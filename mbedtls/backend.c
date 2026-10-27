/*
 * backend.c --
 *
 *	tlsb.h on top of Mbed TLS 3.6.
 *
 *	System trust store loading and the Windows chain verification are
 *	ported from tclmtls: Copyright (c) Konstantin Kushnir <chpock@gmail.com>,
 *	under its license, mbedtls/license.terms.
 */

#include <mbedtls/build_info.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_ciphersuites.h>
#include <mbedtls/ssl_ticket.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/gcm.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/error.h>
#include <mbedtls/version.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/psa_util.h>
#include <psa/crypto.h>

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#endif
#ifdef __APPLE__
#include <TargetConditionals.h>
#if TARGET_OS_OSX
#include <Security/Security.h>
#define MAC_KEYCHAIN
#endif
#endif
#ifdef __HAIKU__
#include <FindDirectory.h>
#endif

#include "tlsb.h"

#if !defined(MBEDTLS_SSL_TLS_C) || !defined(MBEDTLS_X509_CRT_PARSE_C) \
	|| !defined(MBEDTLS_PSA_CRYPTO_C)
#error "Mbed TLS needs TLS, X.509 and PSA crypto"
#endif

#if defined(MBEDTLS_SSL_TICKET_C) && defined(MBEDTLS_SSL_SESSION_TICKETS) \
	&& defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_GCM_C)
#define TICKETS
#endif

#ifdef _MSC_VER
#define THREAD_LOCAL __declspec(thread)
#else
#define THREAD_LOCAL _Thread_local
#endif

#define MAXCHAIN	MBEDTLS_X509_MAX_VERIFY_CHAIN_SIZE
#define NCACHE		32		/* client sessions kept per conf */
#define HELLOMAX	(5 + 16384)	/* one record */

/*
 * Without MBEDTLS_THREADING_C the PSA key store and RNG are not thread safe:
 * one process-wide lock, released around the I/O and verify callbacks.
 */
#if defined(MBEDTLS_THREADING_C)
#define Lock()
#define Unlock()
#elif defined(_WIN32)
static SRWLOCK lock = SRWLOCK_INIT;
#define Lock()		AcquireSRWLockExclusive(&lock)
#define Unlock()	ReleaseSRWLockExclusive(&lock)
#else
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
#define Lock()		pthread_mutex_lock(&lock)
#define Unlock()	pthread_mutex_unlock(&lock)
#endif

/* Guards the client session caches; held briefly, never across callbacks. */
#ifdef _WIN32
static SRWLOCK cacheLock = SRWLOCK_INIT;
#define CacheLock()	AcquireSRWLockExclusive(&cacheLock)
#define CacheUnlock()	ReleaseSRWLockExclusive(&cacheLock)
#else
static pthread_mutex_t cacheLock = PTHREAD_MUTEX_INITIALIZER;
#define CacheLock()	pthread_mutex_lock(&cacheLock)
#define CacheUnlock()	pthread_mutex_unlock(&cacheLock)
#endif

#ifdef _WIN32
typedef INIT_ONCE Once;
#define ONCE_INIT	INIT_ONCE_STATIC_INIT

static BOOL CALLBACK
OnceCb(PINIT_ONCE once, PVOID fn, PVOID *ctx)
{
    (void) once; (void) ctx;
    ((void (*)(void)) fn)();
    return TRUE;
}
#define RunOnce(o, fn)	InitOnceExecuteOnce((o), OnceCb, (PVOID) (fn), NULL)
#else
typedef pthread_once_t Once;
#define ONCE_INIT	PTHREAD_ONCE_INIT
#define RunOnce(o, fn)	pthread_once((o), (fn))
#endif

struct tlsb_conf {
    mbedtls_ssl_config cfg;
    mbedtls_ssl_config noalpn;	/* server with ALPN: cfg without it */
    mbedtls_x509_crt ca;	/* -cafile/-cadir */
    mbedtls_x509_crt own;	/* our chain */
    mbedtls_pk_context key;
    int server;
    int request;
    int require;
    int sys;			/* trusts the system store */
    int *suites;		/* 0 terminated, NULL for the default */
    const char **alpn;		/* NULL terminated, strings in the same block */
    int ncache;
    struct {
	char *name;
	mbedtls_ssl_session *sess;
    } cache[NCACHE];		/* client: last session per servername, oldest first */
#ifdef TICKETS
    mbedtls_ssl_ticket_context tickets;
#endif
};

struct tlsb_sess {
    tlsb_conf *conf;
    mbedtls_ssl_context ssl;
    tlsb_io io;
    char *servername;
    uint8_t ip[16];		/* servername as an IP literal */
    size_t iplen;
    int done;			/* handshake complete */
    int eof;			/* transport EOF */
    int dry;			/* recv returned 0 in this call */
    int resumed;
    int cache;			/* client session may be cached and resumed */
    int offered;		/* client offered a cached session */
    int verified;		/* the verify callback ran */
    uint8_t *hello;		/* server: ClientHello record read ahead */
    size_t hlen, hoff;		/* its length, and how much RecvCb gave out */
    int peeked;			/* no (more) read ahead needed */
    int vtop;			/* highest depth of the chain being verified */
    mbedtls_x509_crt *vcrt[MAXCHAIN];
    uint32_t vflags[MAXCHAIN];
    char sni[256];		/* server: name the client asked for */
    char cipher[64];
    char verr[192];		/* why verification failed */
    char err[256];
};

static void
Msg(char *buf, size_t len, const char *fmt, ...)
{
    va_list ap;

    if (buf == NULL || len == 0) {
	return;
    }
    va_start(ap, fmt);
    vsnprintf(buf, len, fmt, ap);
    va_end(ap);
}

static int
IsPem(const uint8_t *buf, size_t len)
{
    static const char tag[] = "-----BEGIN";
    size_t i;

    for (i = 0; i + sizeof(tag) - 1 <= len; i++) {
	if (memcmp(buf + i, tag, sizeof(tag) - 1) == 0) {
	    return 1;
	}
    }
    return 0;
}

/* Mbed TLS wants PEM NUL terminated, the NUL counted in *zlen. */
static uint8_t *
Dup0(const uint8_t *buf, size_t len, size_t *zlen)
{
    uint8_t *z = malloc(len + 1);

    if (z) {
	memcpy(z, buf, len);
	z[len] = 0;
	*zlen = len + IsPem(buf, len);
    }
    return z;
}

static const char *
ErrStr(int e, char *buf, size_t len)
{
    const char *p;

#ifdef MBEDTLS_ERROR_C
    mbedtls_strerror(e, buf, len);
#else
    snprintf(buf, len, "error -0x%04x", (unsigned) -e);
#endif
    p = strstr(buf, " - ");		/* drop the "SSL - " module prefix */
    return p && p - buf < 12 ? p + 3 : buf;
}

/*
 * Library.
 */

static int initRet;
static Once initOnce = ONCE_INIT;
static mbedtls_x509_crt sys;		/* system store, read only once loaded */
static Once sysOnce = ONCE_INIT;
#ifdef TICKETS
static THREAD_LOCAL tlsb_sess *handshaking;
#endif

static void
InitOnce(void)
{
    mbedtls_x509_crt_init(&sys);
    initRet = psa_crypto_init();
}

int
tlsb_global_init(char *err, size_t errlen)
{
    RunOnce(&initOnce, InitOnce);
    if (initRet != PSA_SUCCESS) {
	Msg(err, errlen, "PSA crypto initialization failed: %d", initRet);
	return TLSB_ERROR;
    }
    return TLSB_OK;
}

const char *
tlsb_version(void)
{
    return "Mbed TLS " MBEDTLS_VERSION_STRING;
}

unsigned
tlsb_protocols(void)
{
    unsigned p = 0;

#ifdef MBEDTLS_SSL_PROTO_TLS1_2
    p |= TLSB_TLS12;
#endif
#ifdef MBEDTLS_SSL_PROTO_TLS1_3
    p |= TLSB_TLS13;
#endif
    return p;
}

/*
 * System trust store.
 */

#if defined(_WIN32)

static void
LoadStore(mbedtls_x509_crt *crt)
{
    static const DWORD where[] = {
	CERT_SYSTEM_STORE_LOCAL_MACHINE, CERT_SYSTEM_STORE_CURRENT_USER
    };
    static const char *const names[] = {"ROOT", "CA"};
    int i, j;

    for (i = 0; i < 2; i++) {
	for (j = 0; j < 2; j++) {
	    HCERTSTORE st = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
		    CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG
		    | CERT_STORE_SHARE_CONTEXT_FLAG | where[i], names[j]);
	    PCCERT_CONTEXT cert = NULL;

	    if (st == NULL) {
		continue;
	    }
	    while ((cert = CertEnumCertificatesInStore(st, cert)) != NULL) {
		if (cert->dwCertEncodingType & X509_ASN_ENCODING) {
		    mbedtls_x509_crt_parse_der(crt, cert->pbCertEncoded,
			    cert->cbCertEncoded);
		}
	    }
	    CertCloseStore(st, 0);
	}
    }
}

/*
 * Windows ships few roots and fetches the rest when CryptoAPI builds a
 * chain, so with the system store CryptoAPI decides whether the chain is
 * trusted; Mbed TLS still checks signatures, dates and the name.
 */
static int
WinTrusted(tlsb_sess *s, const mbedtls_x509_crt *leaf)
{
    LPSTR usage = s->conf->server ? szOID_PKIX_KP_CLIENT_AUTH
	    : szOID_PKIX_KP_SERVER_AUTH;
    PCCERT_CONTEXT cert = CertCreateCertificateContext(X509_ASN_ENCODING,
	    leaf->raw.p, (DWORD) leaf->raw.len);
    HCERTSTORE extra = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    PCCERT_CHAIN_CONTEXT chain = NULL;
    CERT_CHAIN_PARA para;
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl;
    CERT_CHAIN_POLICY_PARA policy;
    CERT_CHAIN_POLICY_STATUS status;
    const mbedtls_x509_crt *p;
    int ok = 0;

    memset(&para, 0, sizeof(para));
    memset(&ssl, 0, sizeof(ssl));
    memset(&policy, 0, sizeof(policy));
    memset(&status, 0, sizeof(status));
    para.cbSize = sizeof(para);
    para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
    para.RequestedUsage.Usage.cUsageIdentifier = 1;
    para.RequestedUsage.Usage.rgpszUsageIdentifier = &usage;
    ssl.cbSize = sizeof(ssl);
    ssl.dwAuthType = s->conf->server ? AUTHTYPE_CLIENT : AUTHTYPE_SERVER;
    policy.cbSize = sizeof(policy);
    policy.pvExtraPolicyPara = &ssl;
    status.cbSize = sizeof(status);
    if (cert && extra) {
	for (p = leaf->next; p; p = p->next) {
	    CertAddEncodedCertificateToStore(extra, X509_ASN_ENCODING, p->raw.p,
		    (DWORD) p->raw.len, CERT_STORE_ADD_ALWAYS, NULL);
	}
	ok = CertGetCertificateChain(NULL, cert, NULL, extra, &para, 0, NULL,
		&chain) && CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL,
		chain, &policy, &status) && status.dwError == 0;
    }
    if (chain) CertFreeCertificateChain(chain);
    if (extra) CertCloseStore(extra, 0);
    if (cert) CertFreeCertificateContext(cert);
    return ok;
}

#elif defined(MAC_KEYCHAIN)

static void
LoadStore(mbedtls_x509_crt *crt)
{
    static const SecTrustSettingsDomain domains[] = {
	kSecTrustSettingsDomainUser, kSecTrustSettingsDomainAdmin,
	kSecTrustSettingsDomainSystem
    };
    CFIndex i, n;
    int d;

    for (d = 0; d < 3; d++) {
	CFArrayRef certs = NULL;

	if (SecTrustSettingsCopyCertificates(domains[d], &certs)
		!= errSecSuccess) {
	    continue;
	}
	for (i = 0, n = CFArrayGetCount(certs); i < n; i++) {
	    CFDataRef der = NULL;

	    if (SecItemExport(CFArrayGetValueAtIndex(certs, i),
		    kSecFormatX509Cert, 0, NULL, &der) == errSecSuccess && der) {
		mbedtls_x509_crt_parse_der(crt, CFDataGetBytePtr(der),
			(size_t) CFDataGetLength(der));
	    }
	    if (der) CFRelease(der);
	}
	CFRelease(certs);
    }
}

#elif defined(MBEDTLS_FS_IO) && defined(__HAIKU__)

/* The packaged bundle and the user's own, as HaikuPorts' OpenSSL. */
static void
LoadStore(mbedtls_x509_crt *crt)
{
    char path[B_PATH_NAME_LENGTH + 32];

    if (find_directory(B_SYSTEM_DATA_DIRECTORY, -1, false, path,
	    B_PATH_NAME_LENGTH) == B_OK) {
	strcat(path, "/ssl/CARootCertificates.pem");
	mbedtls_x509_crt_parse_file(crt, path);
    }
    if (find_directory(B_SYSTEM_NONPACKAGED_DATA_DIRECTORY, -1, false, path,
	    B_PATH_NAME_LENGTH) == B_OK) {
	strcat(path, "/ssl/certs");
	mbedtls_x509_crt_parse_path(crt, path);
    }
}

#elif defined(MBEDTLS_FS_IO)

/* The first bundle found, else the directory: they hold the same certs. */
static void
LoadStore(mbedtls_x509_crt *crt)
{
    static const char *const bundles[] = {
	"/etc/ssl/certs/ca-certificates.crt",	/* Debian, Arch, Gentoo */
	"/etc/pki/tls/certs/ca-bundle.crt",	/* Fedora, RHEL */
	"/etc/ssl/ca-bundle.pem",		/* openSUSE */
	"/etc/ssl/cert.pem",			/* BSDs, Alpine */
	NULL
    };
    const char *file = getenv("SSL_CERT_FILE"), *dir = getenv("SSL_CERT_DIR");
    int i;

    if (file || dir) {
	if (file) mbedtls_x509_crt_parse_file(crt, file);
	if (dir) mbedtls_x509_crt_parse_path(crt, dir);
	return;
    }
    for (i = 0; bundles[i] && crt->raw.len == 0; i++) {
	mbedtls_x509_crt_parse_file(crt, bundles[i]);
    }
    if (crt->raw.len == 0) {
#ifdef __ANDROID__
	mbedtls_x509_crt_parse_path(crt, "/system/etc/security/cacerts");
#else
	mbedtls_x509_crt_parse_path(crt, "/etc/ssl/certs");
#endif
    }
}

#else

static void
LoadStore(mbedtls_x509_crt *crt)
{
    (void) crt;
}

#endif

static void
SysOnce(void)
{
    LoadStore(&sys);
}

/*
 * Cipher suites. Mbed TLS names them TLS-ECDHE-RSA-WITH-... and
 * TLS1-3-AES-...; we report IANA names and also accept OpenSSL ones.
 */

static int
Fold(int c)
{
    c = (unsigned char) c;
    return c == '-' ? '_' : c >= 'a' && c <= 'z' ? c - 32 : c;
}

/* Case-insensitive, '-' and '_' alike. */
static int
NameEq(const char *a, size_t an, const char *b)
{
    size_t i;

    if (strlen(b) != an) {
	return 0;
    }
    for (i = 0; i < an && Fold(a[i]) == Fold(b[i]); i++) ;
    return i == an;
}

static void
Iana(const char *name, char *out, size_t len)
{
    char *p;

    snprintf(out, len, "TLS_%s", name + (strncmp(name, "TLS1-3-", 7) ? 4 : 7));
    for (p = out; *p; p++) {
	if (*p == '-') *p = '_';
    }
}

/* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA -> ECDHE-RSA-AES128-SHA */
static void
Ossl(const char *iana, char *out, size_t len)
{
    const char *w = strstr(iana, "_WITH_"), *t;
    size_t n = 0;
    int poly = 0;

    if (w == NULL) {
	snprintf(out, len, "%s", iana);		/* TLS 1.3: the same */
	return;
    }
    *out = 0;
    if (strncmp(iana, "TLS_RSA_WITH_", 13) != 0) {
	for (t = iana + 4; t < w && n + 2 < len; t++) {
	    out[n++] = *t == '_' ? '-' : *t;
	}
	out[n++] = '-';
	out[n] = 0;
    }
    for (t = w + 6; *t; ) {
	size_t k = strcspn(t, "_");

	if (n >= len) {
	    break;
	}
	if (!(k == 3 && memcmp(t, "CBC", 3) == 0) && !(poly && k == 6)) {
	    n += (size_t) snprintf(out + n, len - n, "%s%.*s",
		    t == w + 6 || (*t >= '0' && *t <= '9') ? "" : "-", (int) k, t);
	}
	poly = k == 8 && memcmp(t, "POLY1305", 8) == 0;
	t += k + (t[k] == '_');
    }
}

static int
Usable(const char *name)
{
    return !strstr(name, "PSK") && !strstr(name, "ECJPAKE");
}

static unsigned
SuiteProto(const char *name)
{
    return strncmp(name, "TLS1-3-", 7) == 0 ? TLSB_TLS13 : TLSB_TLS12;
}

void
tlsb_ciphers(unsigned protocols, void (*cb)(void *ud, const char *name),
	void *ud)
{
    const int *id;
    char iana[64];

    for (id = mbedtls_ssl_list_ciphersuites(); *id; id++) {
	const char *name = mbedtls_ssl_get_ciphersuite_name(*id);

	if (Usable(name) && (SuiteProto(name) & protocols)) {
	    Iana(name, iana, sizeof(iana));
	    cb(ud, iana);
	}
    }
}

static int
SuiteId(const char *spec, size_t len)
{
    const int *id;
    char iana[64], ossl[64];

    for (id = mbedtls_ssl_list_ciphersuites(); *id; id++) {
	const char *name = mbedtls_ssl_get_ciphersuite_name(*id);

	Iana(name, iana, sizeof(iana));
	Ossl(iana, ossl, sizeof(ossl));
	if (NameEq(spec, len, name) || NameEq(spec, len, iana)
		|| NameEq(spec, len, ossl)) {
	    return *id;
	}
    }
    return 0;
}

static void
AddSuite(int *list, int id)
{
    for (; *list && *list != id; list++) ;
    *list = id;
}

/*
 * Adds the suites named in spec (separated by any of ": ,\t\n"); *named
 * collects their protocols.
 */
static int
AddSuites(int *list, const char *spec, unsigned *named, char *err,
	size_t errlen)
{
    const char *sep = ": ,\t\r\n";

    while (spec && *(spec += strspn(spec, sep))) {
	size_t len = strcspn(spec, sep);
	int id = SuiteId(spec, len);

	if (id == 0) {
	    Msg(err, errlen, "unknown cipher: %.*s", (int) len, spec);
	    return 0;
	}
	AddSuite(list, id);
	*named |= SuiteProto(mbedtls_ssl_get_ciphersuite_name(id));
	spec += len;
    }
    return 1;
}

/*
 * A protocol without named suites keeps its defaults unless its own option
 * was given, which disables it.
 */
static int
SetCiphers(tlsb_conf *c, const tlsb_opts *o, unsigned *p, char *err,
	size_t errlen)
{
    const int *all = mbedtls_ssl_list_ciphersuites(), *id;
    unsigned named = 0, proto;
    size_t n;

    if (o->ciphers == NULL && o->ciphersuites == NULL) {
	return 1;
    }
    for (n = 0; all[n]; n++) ;
    if ((c->suites = calloc(n + 1, sizeof(int))) == NULL) {
	Msg(err, errlen, "out of memory");
	return 0;
    }
    if (!AddSuites(c->suites, o->ciphersuites, &named, err, errlen)
	    || !AddSuites(c->suites, o->ciphers, &named, err, errlen)) {
	return 0;
    }
    if (o->ciphersuites && !(named & TLSB_TLS13)) *p &= ~TLSB_TLS13;
    if (o->ciphers && !(named & TLSB_TLS12)) *p &= ~TLSB_TLS12;
    if (*p == 0) {
	Msg(err, errlen, "no usable cipher suites");
	return 0;
    }
    proto = *p & ~named;
    for (id = all; *id; id++) {
	const char *name = mbedtls_ssl_get_ciphersuite_name(*id);

	if (Usable(name) && (SuiteProto(name) & proto)) {
	    AddSuite(c->suites, *id);
	}
    }
    return 1;
}

/*
 * Configuration.
 */

static int
SniCb(void *ud, mbedtls_ssl_context *ssl, const unsigned char *name,
	size_t len)
{
    tlsb_sess *s = mbedtls_ssl_get_user_data_p(ssl);

    (void) ud;
    if (len < sizeof(s->sni)) {
	memcpy(s->sni, name, len);
	s->sni[len] = 0;
    }
    return 0;
}

#ifdef TICKETS
/*
 * Mbed TLS does not pass the session to the ticket parse callback: it is
 * found through the thread-local handshaking.
 */
static int
TicketParse(void *p, mbedtls_ssl_session *session, unsigned char *buf,
	size_t len)
{
    int r;

    /* A verify callback must see every client chain: no resumption. */
    if (handshaking && handshaking->io.verify) {
	return MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED;
    }
    r = mbedtls_ssl_ticket_parse(p, session, buf, len);

    if (r == 0 && handshaking) {
	handshaking->resumed = 1;
    }
    return r;
}
#endif

/* PEM or DER; > 0 when some certificates of a PEM bundle failed. */
static int
ParseCerts(mbedtls_x509_crt *crt, const uint8_t *buf, size_t len)
{
    size_t n;
    uint8_t *z = Dup0(buf, len, &n);
    int r = z ? mbedtls_x509_crt_parse(crt, z, n)
	    : MBEDTLS_ERR_X509_ALLOC_FAILED;

    free(z);
    return r;
}

static int
LoadCert(tlsb_conf *c, const tlsb_opts *o, char *err, size_t errlen)
{
    if (ParseCerts(&c->own, o->cert, o->cert_len) != 0) {
	Msg(err, errlen, "cannot parse certificate");
	return 0;
    }
    return 1;
}

static int
LoadKey(tlsb_conf *c, const tlsb_opts *o, char *err, size_t errlen)
{
    const char *pw = o->password;
    size_t n;
    uint8_t *z = Dup0(o->key, o->key_len, &n);
    int r = MBEDTLS_ERR_PK_ALLOC_FAILED;

    if (z) {
	r = mbedtls_pk_parse_key(&c->key, z, n, (const unsigned char *) pw,
		pw ? strlen(pw) : 0, mbedtls_psa_get_random,
		MBEDTLS_PSA_RANDOM_STATE);
	mbedtls_platform_zeroize(z, o->key_len);
	free(z);
    }
    if (r == MBEDTLS_ERR_PK_PASSWORD_REQUIRED) {
	Msg(err, errlen, "password required");
	return 0;
    }
    if (r != 0) {
	Msg(err, errlen, r == MBEDTLS_ERR_PK_PASSWORD_MISMATCH || pw
		? "wrong password" : "cannot parse private key");
	return 0;
    }
    if (c->own.raw.len && mbedtls_pk_check_pair(&c->own.pk, &c->key,
	    mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE) != 0) {
	Msg(err, errlen, "private key does not match certificate");
	return 0;
    }
    return 1;
}

static int
LoadTrust(tlsb_conf *c, const tlsb_opts *o, char *err, size_t errlen)
{
    if (o->ca && o->ca_len && ParseCerts(&c->ca, o->ca, o->ca_len) < 0) {
	Msg(err, errlen, "cannot parse CA certificates");
	return 0;
    }
    if (o->cadir) {
#ifdef MBEDTLS_FS_IO
	if (mbedtls_x509_crt_parse_path(&c->ca, o->cadir) < 0)
#endif
	{
	    Msg(err, errlen, "cannot read cadir: %s", o->cadir);
	    return 0;
	}
    }
    c->sys = !(o->ca && o->ca_len) && !o->cadir;
    if (c->sys && (!c->server || c->request)) {
	RunOnce(&sysOnce, SysOnce);
    }
    return 1;
}

static int
SetAlpn(tlsb_conf *c, const tlsb_opts *o, char *err, size_t errlen)
{
#ifdef MBEDTLS_SSL_ALPN
    size_t n = (size_t) (o->alpn_count + 1) * sizeof(char *);
    char *p;
    int i;

    for (i = 0; i < o->alpn_count; i++) {
	size_t l = strlen(o->alpn[i]);

	if (l == 0 || l > 255) {
	    Msg(err, errlen, "invalid ALPN protocol name");
	    return 0;
	}
	n += l + 1;
    }
    if ((c->alpn = malloc(n)) == NULL) {
	Msg(err, errlen, "out of memory");
	return 0;
    }
    p = (char *) (c->alpn + o->alpn_count + 1);
    for (i = 0; i < o->alpn_count; i++) {
	c->alpn[i] = strcpy(p, o->alpn[i]);
	p += strlen(p) + 1;
    }
    c->alpn[i] = NULL;
    if (mbedtls_ssl_conf_alpn_protocols(&c->cfg, c->alpn) != 0) {
	Msg(err, errlen, "cannot set ALPN protocols");
	return 0;
    }
#else
    (void) c; (void) o; (void) err; (void) errlen;	/* never negotiated */
#endif
    return 1;
}

/* Everything but ALPN, for cfg and, on a server with ALPN, for noalpn. */
static int
Apply(tlsb_conf *c, mbedtls_ssl_config *cfg, unsigned p, int has_cert)
{
    if (mbedtls_ssl_config_defaults(cfg, c->server ? MBEDTLS_SSL_IS_SERVER
	    : MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
	    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
	return 0;
    }
    if (c->suites) {
	mbedtls_ssl_conf_ciphersuites(cfg, c->suites);
    }
    mbedtls_ssl_conf_min_tls_version(cfg, p & TLSB_TLS12
	    ? MBEDTLS_SSL_VERSION_TLS1_2 : MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(cfg, p & TLSB_TLS13
	    ? MBEDTLS_SSL_VERSION_TLS1_3 : MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_rng(cfg, mbedtls_psa_get_random,
	    MBEDTLS_PSA_RANDOM_STATE);
    /* Clients verify even with require 0: the callback wants a verdict. */
    mbedtls_ssl_conf_authmode(cfg, c->require ? MBEDTLS_SSL_VERIFY_REQUIRED
	    : c->server && !c->request ? MBEDTLS_SSL_VERIFY_NONE
	    : MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(cfg, c->sys ? &sys : &c->ca, NULL);
    if (c->sys && c->server) {
	mbedtls_ssl_conf_cert_req_ca_list(cfg,
		MBEDTLS_SSL_CERT_REQ_CA_LIST_DISABLED);
    }
    if (has_cert && mbedtls_ssl_conf_own_cert(cfg, &c->own, &c->key)) {
	return 0;
    }
    if (c->server) {
#ifdef MBEDTLS_SSL_SERVER_NAME_INDICATION
	mbedtls_ssl_conf_sni(cfg, SniCb, NULL);
#endif
#ifdef TICKETS
	mbedtls_ssl_conf_session_tickets_cb(cfg, mbedtls_ssl_ticket_write,
		TicketParse, &c->tickets);
#endif
    }
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_PROTO_TLS1_3) \
	&& defined(MBEDTLS_SSL_CLI_C)
    if (!c->server) {
	mbedtls_ssl_conf_tls13_enable_signal_new_session_tickets(cfg,
		MBEDTLS_SSL_TLS1_3_SIGNAL_NEW_SESSION_TICKETS_ENABLED);
    }
#endif
    return 1;
}

static int
Configure(tlsb_conf *c, const tlsb_opts *o, char *err, size_t errlen)
{
    unsigned p = o->protocols ? o->protocols & tlsb_protocols()
	    : tlsb_protocols();
    int has_cert = o->cert && o->cert_len, has_key = o->key && o->key_len;

    if (p == 0) {
	Msg(err, errlen, "no supported protocol version enabled");
	return 0;
    }
    if (!SetCiphers(c, o, &p, err, errlen) || !LoadTrust(c, o, err, errlen)) {
	return 0;
    }
    if (has_cert != has_key) {
	Msg(err, errlen, "certificate and private key go together");
	return 0;
    }
    if (has_cert && (!LoadCert(c, o, err, errlen)
	    || !LoadKey(c, o, err, errlen))) {
	return 0;
    }
    if (c->server && !has_cert) {
	Msg(err, errlen, "server requires a certificate and key");
	return 0;
    }
#ifdef TICKETS
    if (c->server && mbedtls_ssl_ticket_setup(&c->tickets,
	    mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE,
	    MBEDTLS_CIPHER_AES_256_GCM, 86400)) {
	Msg(err, errlen, "cannot set up session tickets");
	return 0;
    }
#endif
    if (!Apply(c, &c->cfg, p, has_cert)
	    || (c->server && o->alpn_count > 0
		&& !Apply(c, &c->noalpn, p, has_cert))) {
	Msg(err, errlen, "cannot set up Mbed TLS configuration");
	return 0;
    }
    return o->alpn_count == 0 || SetAlpn(c, o, err, errlen);
}

tlsb_conf *
tlsb_conf_new(const tlsb_opts *o, char *err, size_t errlen)
{
    tlsb_conf *c = calloc(1, sizeof(*c));
    int ok;

    if (c == NULL) {
	Msg(err, errlen, "out of memory");
	return NULL;
    }
    mbedtls_ssl_config_init(&c->cfg);
    mbedtls_ssl_config_init(&c->noalpn);
    mbedtls_x509_crt_init(&c->ca);
    mbedtls_x509_crt_init(&c->own);
    mbedtls_pk_init(&c->key);
#ifdef TICKETS
    mbedtls_ssl_ticket_init(&c->tickets);
#endif
    c->server = o->server;
    c->request = o->request || o->require;
    c->require = o->require;
    Lock();
    ok = Configure(c, o, err, errlen);
    Unlock();
    if (!ok) {
	tlsb_conf_free(c);
	return NULL;
    }
    return c;
}

void
tlsb_conf_free(tlsb_conf *c)
{
    int i;

    if (c == NULL) {
	return;
    }
    Lock();
    for (i = 0; i < c->ncache; i++) {
	free(c->cache[i].name);
	mbedtls_ssl_session_free(c->cache[i].sess);
	free(c->cache[i].sess);
    }
    mbedtls_ssl_config_free(&c->cfg);
    mbedtls_ssl_config_free(&c->noalpn);
    mbedtls_x509_crt_free(&c->ca);
    mbedtls_x509_crt_free(&c->own);
    mbedtls_pk_free(&c->key);
#ifdef TICKETS
    mbedtls_ssl_ticket_free(&c->tickets);
#endif
    Unlock();
    free(c->suites);
    free(c->alpn);
    free(c);
}

/*
 * Sessions.
 */

static int
RecvCb(void *ud, unsigned char *buf, size_t len)
{
    tlsb_sess *s = ud;
    long n;

    if (s->hoff < s->hlen) {		/* the ClientHello read ahead */
	n = (long) (s->hlen - s->hoff < len ? s->hlen - s->hoff : len);
	memcpy(buf, s->hello + s->hoff, (size_t) n);
	s->hoff += (size_t) n;
	return (int) n;
    }
    if (s->eof) {
	return 0;
    }
    Unlock();
    n = s->io.recv(s->io.ud, buf, len > INT_MAX ? INT_MAX : len);
    Lock();
    if (n > 0) {
	return (int) n;
    }
    if (n == 0) {
	s->dry = 1;
	return MBEDTLS_ERR_SSL_WANT_READ;
    }
    s->eof = 1;
    return 0;
}

static int
SendCb(void *ud, const unsigned char *buf, size_t len)
{
    tlsb_sess *s = ud;

    if (len > INT_MAX) {
	len = INT_MAX;
    }
    Unlock();
    s->io.send(s->io.ud, buf, len);
    Lock();
    return (int) len;
}

static const char *
FlagStr(uint32_t f, const mbedtls_x509_crt *c)
{
    if (f & MBEDTLS_X509_BADCERT_NOT_TRUSTED) {
	return c->issuer_raw.len == c->subject_raw.len && memcmp(c->issuer_raw.p,
		c->subject_raw.p, c->subject_raw.len) == 0
		? "self-signed certificate"
		: "unable to get local issuer certificate";
    }
    if (f & MBEDTLS_X509_BADCERT_EXPIRED) return "certificate has expired";
    if (f & MBEDTLS_X509_BADCERT_FUTURE) return "certificate is not yet valid";
    if (f & MBEDTLS_X509_BADCERT_REVOKED) return "certificate revoked";
    if (f & MBEDTLS_X509_BADCERT_CN_MISMATCH) return "hostname mismatch";
    if (f & (MBEDTLS_X509_BADCERT_KEY_USAGE | MBEDTLS_X509_BADCERT_EXT_KEY_USAGE
	    | MBEDTLS_X509_BADCERT_NS_CERT_TYPE)) {
	return "unsupported certificate purpose";
    }
    if (f & (MBEDTLS_X509_BADCERT_BAD_MD | MBEDTLS_X509_BADCERT_BAD_PK
	    | MBEDTLS_X509_BADCERT_BAD_KEY)) {
	return "certificate algorithm or key not allowed";
    }
    return "certificate not acceptable";
}

/* Whether the peer sent c (as opposed to it coming from our store). */
static int
Sent(const mbedtls_x509_crt *leaf, const mbedtls_x509_crt *c)
{
    for (; leaf; leaf = leaf->next) {
	if (leaf == c || (leaf->raw.len == c->raw.len
		&& memcmp(leaf->raw.p, c->raw.p, c->raw.len) == 0)) {
	    return 1;
	}
    }
    return 0;
}

static int
IpMatch(const mbedtls_x509_crt *c, const uint8_t *ip, size_t len)
{
    const mbedtls_x509_sequence *p;

    for (p = &c->subject_alt_names; p; p = p->next) {
	if (p->buf.tag == (MBEDTLS_ASN1_CONTEXT_SPECIFIC
		| MBEDTLS_X509_SAN_IP_ADDRESS) && p->buf.len == len
		&& memcmp(p->buf.p, ip, len) == 0) {
	    return 1;
	}
    }
    return 0;
}

/*
 * Runs at depth 0, once Mbed TLS has seen the whole chain: reports the
 * certificates the peer sent, highest depth first. A bad certificate
 * makes everything below it bad too.
 */
static int
Decide(tlsb_sess *s, mbedtls_x509_crt *leaf, uint32_t *flags)
{
    const char *above = NULL, *err = NULL;
    uint32_t all = 0;
    int d, accept = 1;

#ifdef _WIN32
    if (s->conf->sys) {
	for (d = 0; d <= s->vtop; d++) {
	    s->vflags[d] &= ~MBEDTLS_X509_BADCERT_NOT_TRUSTED;
	}
	if (!WinTrusted(s, leaf)) {
	    s->vflags[0] |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
	}
    }
#endif
    if (s->iplen && !IpMatch(leaf, s->ip, s->iplen)) {
	s->vflags[0] |= MBEDTLS_X509_BADCERT_CN_MISMATCH;
    }
    for (d = s->vtop; d >= 0 && accept; d--) {
	mbedtls_x509_crt *c = s->vcrt[d];
	uint32_t f = s->vflags[d];
	int ok;

	all |= f;
	err = f ? FlagStr(f, c) : above;
	if (!Sent(leaf, c)) {
	    above = err;		/* our trust anchor */
	    continue;
	}
	ok = err == NULL;
	if (!ok) {
	    above = "issuer certificate not trusted";
	}
	if (s->io.verify) {
	    Unlock();
	    accept = s->io.verify(s->io.ud, d, c->raw.p, c->raw.len, ok, err);
	    Lock();
	} else {
	    accept = ok || !s->conf->require;
	}
    }
    s->vtop = -1;
    if (accept) {
	return 0;
    }
    if (s->io.verify) {
	Msg(s->verr, sizeof(s->verr),
		"certificate rejected by validation callback");
    } else {
	Msg(s->verr, sizeof(s->verr), "certificate verify failed: %s", err);
    }
    /* VERIFY_REQUIRED fails on the flags (and alerts accordingly). */
    *flags = all ? all : MBEDTLS_X509_BADCERT_OTHER;
    return s->conf->require ? 0 : MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
}

/* Called per chain certificate, top first; the verdict waits for depth 0. */
static int
VerifyCb(void *ud, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    tlsb_sess *s = ud;

    s->verified = 1;
    if (depth < 0 || depth >= MAXCHAIN) {
	return MBEDTLS_ERR_X509_FATAL_ERROR;
    }
    if (s->vtop < depth) {
	s->vtop = depth;
    }
    s->vcrt[depth] = crt;
    s->vflags[depth] = *flags;
    *flags = 0;
    return depth ? 0 : Decide(s, crt, flags);
}

/*
 * Client session cache: the last session per servername, oldest dropped.
 * Called with Lock() held.
 */

static void
CacheStore(tlsb_sess *s)
{
    tlsb_conf *c = s->conf;
    mbedtls_ssl_session *sess = malloc(sizeof(*sess));
    char *name = malloc(strlen(s->servername) + 1);
    int i;

    if (sess) {
	mbedtls_ssl_session_init(sess);
    }
    if (!sess || !name || mbedtls_ssl_get_session(&s->ssl, sess) != 0) {
	if (sess) mbedtls_ssl_session_free(sess);
	free(sess);
	free(name);
	return;
    }
    strcpy(name, s->servername);
    CacheLock();
    for (i = 0; i < c->ncache && strcmp(c->cache[i].name, name) != 0; i++) ;
    if (i == NCACHE) {
	i = 0;			/* full: drop the oldest */
    }
    if (i < c->ncache) {
	free(c->cache[i].name);
	mbedtls_ssl_session_free(c->cache[i].sess);
	free(c->cache[i].sess);
	memmove(c->cache + i, c->cache + i + 1,
		(size_t) (c->ncache - i - 1) * sizeof(c->cache[0]));
	c->ncache--;
    }
    c->cache[c->ncache].name = name;
    c->cache[c->ncache++].sess = sess;
    CacheUnlock();
}

static void
CacheUse(tlsb_sess *s)
{
    tlsb_conf *c = s->conf;
    int i;

    CacheLock();
    for (i = 0; i < c->ncache; i++) {
	if (strcmp(c->cache[i].name, s->servername) == 0) {
	    s->offered = mbedtls_ssl_set_session(&s->ssl, c->cache[i].sess) == 0;
	    break;
	}
    }
    CacheUnlock();
}

/* Whether the n bytes at name are one of the NULL terminated list. */
static int
InList(const char **list, const uint8_t *name, size_t n)
{
    for (; *list; list++) {
	if (strlen(*list) == n && memcmp(*list, name, n) == 0) {
	    return 1;
	}
    }
    return 0;
}

/*
 * Whether a ClientHello record offers ALPN, none of it in list. The record
 * is untrusted: every length is checked against what is left before use.
 */
static int
NoCommonAlpn(const uint8_t *p, size_t len, const char **list)
{
    size_t off = 9 + 34, n, end;	/* headers, version, random */

    if (len <= off || p[0] != 22 || p[5] != 1) {
	return 0;			/* not a handshake record with a ClientHello */
    }
    off += 1 + p[off];			/* session id */
    if (off + 2 > len) return 0;
    off += 2 + (size_t) (p[off] << 8 | p[off + 1]);	/* cipher suites */
    if (off + 1 > len) return 0;
    off += 1 + p[off] + 2;		/* compression, extensions length */
    while (off + 4 <= len) {
	unsigned type = p[off] << 8 | p[off + 1];

	n = (size_t) (p[off + 2] << 8 | p[off + 3]);
	off += 4;
	if (n > len - off) {
	    return 0;
	}
	if (type == 16 && n >= 2) {	/* ALPN: list length, then names */
	    for (end = off + n, off += 2; off < end && p[off] < end - off;
		    off += 1 + p[off]) {
		if (InList(list, p + off + 1, p[off])) {
		    return 0;
		}
	    }
	    return 1;
	}
	off += n;
    }
    return 0;
}

/* (Re)binds the session to a configuration before the handshake starts. */
static int
Setup(tlsb_sess *s, const mbedtls_ssl_config *cfg)
{
    int ok;

    Lock();
    mbedtls_ssl_free(&s->ssl);
    mbedtls_ssl_init(&s->ssl);
    ok = mbedtls_ssl_setup(&s->ssl, cfg) == 0;
    Unlock();
    if (ok) {
	mbedtls_ssl_set_user_data_p(&s->ssl, s);
	mbedtls_ssl_set_bio(&s->ssl, s, SendCb, RecvCb, NULL);
	mbedtls_ssl_set_verify(&s->ssl, VerifyCb, s);
    }
    return ok;
}

/*
 * Server with ALPN: reads the ClientHello record ahead and, when there is
 * no protocol in common, rebinds the session to noalpn rather than let
 * Mbed TLS fail the handshake. Returns 0 while more data is needed.
 */
static int
Peek(tlsb_sess *s)
{
    size_t need = 5;
    long n;

    if (s->hello == NULL && (s->hello = malloc(HELLOMAX)) == NULL) {
	s->peeked = 1;
	return 1;
    }
    while (s->hlen < need) {
	n = s->io.recv(s->io.ud, s->hello + s->hlen, need - s->hlen);
	if (n == 0) {
	    s->dry = 1;
	    return 0;
	}
	if (n < 0) {
	    s->eof = 1;
	    break;
	}
	s->hlen += (size_t) n;
	if (s->hlen >= 5 && need == 5) {
	    need += (size_t) (s->hello[3] << 8 | s->hello[4]);
	    if (s->hello[0] != 22 || need > HELLOMAX) {
		break;
	    }
	}
    }
    s->peeked = 1;
    if (s->hlen >= need && need > 5
	    && NoCommonAlpn(s->hello, s->hlen, s->conf->alpn)
	    && !Setup(s, &s->conf->noalpn)) {
	s->eof = 1;			/* fails the handshake */
    }
    return 1;
}

static int
SetServerName(tlsb_sess *s, const char *name, char *err, size_t errlen)
{
    size_t n = strlen(name);

    if ((s->servername = malloc(n + 1)) == NULL) {
	Msg(err, errlen, "out of memory");
	return 0;
    }
    memcpy(s->servername, name, n + 1);
    /* IP literals: no SNI, we match the IP SANs ourselves. */
    if (inet_pton(AF_INET, name, s->ip) == 1) {
	s->iplen = 4;
    } else if (inet_pton(AF_INET6, name, s->ip) == 1) {
	s->iplen = 16;
    }
    if (mbedtls_ssl_set_hostname(&s->ssl, s->iplen ? NULL : name) != 0) {
	Msg(err, errlen, "invalid server name \"%s\"", name);
	return 0;
    }
    return 1;
}

tlsb_sess *
tlsb_sess_new(tlsb_conf *c, const char *servername, const tlsb_io *io,
	char *err, size_t errlen)
{
    tlsb_sess *s = calloc(1, sizeof(*s));

    if (s == NULL) {
	Msg(err, errlen, "out of memory");
	return NULL;
    }
    s->conf = c;
    s->io = *io;
    s->vtop = -1;
    mbedtls_ssl_init(&s->ssl);
    if (!Setup(s, &c->cfg)) {
	Msg(err, errlen, "cannot create Mbed TLS session");
	goto fail;
    }
    if (!c->server) {
	if (servername ? !SetServerName(s, servername, err, errlen)
		: mbedtls_ssl_set_hostname(&s->ssl, NULL) != 0) {
	    goto fail;
	}
	/* No resumption past a verify callback: it must see each handshake. */
	s->cache = servername && io->verify == NULL;
	if (s->cache) {
	    Lock();
	    CacheUse(s);
	    Unlock();
	}
    }
    s->peeked = !c->server || c->alpn == NULL;
    return s;

  fail:
    tlsb_sess_free(s);
    return NULL;
}

void
tlsb_sess_free(tlsb_sess *s)
{
    if (s == NULL) {
	return;
    }
    Lock();
    mbedtls_ssl_free(&s->ssl);
    Unlock();
    free(s->hello);
    free(s->servername);
    free(s);
}

const char *
tlsb_errmsg(tlsb_sess *s)
{
    return s->err[0] ? s->err : "unknown error";
}

/*
 * Records the reason of a failed Mbed TLS call; returns TLSB_ERROR. what is
 * empty for the handshake, which the channel layer names itself.
 */
static int
Fail(tlsb_sess *s, const char *what, int e)
{
    const char *sep = *what ? ": " : "";
    char buf[160];

    if (s->verr[0]) {
	Msg(s->err, sizeof(s->err), "%s", s->verr);
    } else if (e == MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE) {
	Msg(s->err, sizeof(s->err), "peer did not return a certificate");
    } else if (s->eof || e == MBEDTLS_ERR_SSL_CONN_EOF) {
	Msg(s->err, sizeof(s->err), s->done ? "connection closed"
		: "connection closed during handshake");
    } else if (e == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE) {
	/* Mbed TLS 3.6 has no public way to tell which alert. */
	Msg(s->err, sizeof(s->err), "peer sent alert");
    } else {
	Msg(s->err, sizeof(s->err), "%s%s%s", what, sep,
		ErrStr(e, buf, sizeof(buf)));
    }
    return TLSB_ERROR;
}

/* Mbed TLS returns this after a TLS 1.3 NewSessionTicket: call again. */
#define NEW_TICKET(r)	((r) == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)

/* WANT_READ only once recv has run dry in this call. */
#define AGAIN(s, r, n) ((r) == MBEDTLS_ERR_SSL_WANT_READ && !(s)->dry \
	&& !(s)->eof && (n)++ < 16)

/* Caches the session after a NewSessionTicket (TLS 1.3) or handshake (1.2). */
static void
CacheNewSession(tlsb_sess *s, int r)
{
    if (s->cache && (NEW_TICKET(r) || (r == 0 && mbedtls_ssl_get_version_number(
	    &s->ssl) == MBEDTLS_SSL_VERSION_TLS1_2))) {
	CacheStore(s);
    }
}

int
tlsb_handshake(tlsb_sess *s)
{
    int r, n = 0;

    if (s->done) {
	return TLSB_OK;
    }
    s->dry = 0;
    if (!s->peeked && !Peek(s)) {
	return TLSB_WANT_READ;
    }
    Lock();
#ifdef TICKETS
    handshaking = s;
#endif
    do {
	r = mbedtls_ssl_handshake(&s->ssl);
	CacheNewSession(s, r);
    } while (NEW_TICKET(r) || AGAIN(s, r, n));
#ifdef TICKETS
    handshaking = NULL;
#endif
    Unlock();
    if (r == 0) {
	s->done = 1;
	if (!s->conf->server) {
	    s->resumed = s->offered && !s->verified;
	}
	return TLSB_OK;
    }
    if (r == MBEDTLS_ERR_SSL_WANT_READ && !s->eof) {
	return TLSB_WANT_READ;
    }
    return Fail(s, "", r);
}

long
tlsb_read(tlsb_sess *s, uint8_t *buf, size_t len)
{
    int r, n = 0;

    if (!s->done && (r = tlsb_handshake(s)) != TLSB_OK) {
	return r;
    }
    s->dry = 0;
    Lock();
    do {
	r = mbedtls_ssl_read(&s->ssl, buf, len > INT_MAX ? INT_MAX : len);
	CacheNewSession(s, r);
    } while (NEW_TICKET(r) || AGAIN(s, r, n));
    Unlock();
    if (r > 0) {
	return r;
    }
    if (r == MBEDTLS_ERR_SSL_WANT_READ && !s->eof) {
	return TLSB_WANT_READ;
    }
    if (r == 0 || r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || s->eof
	    || r == MBEDTLS_ERR_SSL_CONN_EOF) {
	return 0;
    }
    return Fail(s, "read failed", r);
}

long
tlsb_write(tlsb_sess *s, const uint8_t *buf, size_t len)
{
    size_t done = 0;
    int r = 0;

    if (!s->done) {
	Msg(s->err, sizeof(s->err), "handshake not complete");
	return TLSB_ERROR;
    }
    Lock();
    while (done < len && (r >= 0 || NEW_TICKET(r))) {
	r = mbedtls_ssl_write(&s->ssl, buf + done, len - done);
	done += r > 0 ? (size_t) r : 0;
    }
    Unlock();
    return r < 0 ? Fail(s, "write failed", r) : (long) len;
}

int
tlsb_pending(tlsb_sess *s)
{
    return mbedtls_ssl_get_bytes_avail(&s->ssl) > 0
	    || mbedtls_ssl_check_pending(&s->ssl);
}

void
tlsb_close_notify(tlsb_sess *s)
{
    if (s->done) {
	Lock();
	mbedtls_ssl_close_notify(&s->ssl);
	Unlock();
    }
}

int
tlsb_info_get(tlsb_sess *s, tlsb_info *info)
{
    const mbedtls_ssl_ciphersuite_t *cs;

    if (!s->done) {
	return TLSB_ERROR;
    }
    memset(info, 0, sizeof(*info));
    switch (mbedtls_ssl_get_version_number(&s->ssl)) {
    case MBEDTLS_SSL_VERSION_TLS1_2:	info->protocol = "TLS1.2"; break;
    case MBEDTLS_SSL_VERSION_TLS1_3:	info->protocol = "TLS1.3"; break;
    default:				info->protocol = "unknown";
    }
    cs = mbedtls_ssl_ciphersuite_from_id(
	    mbedtls_ssl_get_ciphersuite_id_from_ssl(&s->ssl));
    if (cs) {
	Iana(mbedtls_ssl_ciphersuite_get_name(cs), s->cipher,
		sizeof(s->cipher));
	info->cipher = s->cipher;
	info->cipher_bits = (int) mbedtls_ssl_ciphersuite_get_cipher_key_bitlen(cs);
    }
#ifdef MBEDTLS_SSL_ALPN
    if ((info->alpn = (const uint8_t *) mbedtls_ssl_get_alpn_protocol(&s->ssl))
	    != NULL) {
	info->alpn_len = strlen((const char *) info->alpn);
    }
#endif
    info->servername = s->conf->server ? (s->sni[0] ? s->sni : NULL)
	    : s->iplen ? NULL : s->servername;
    info->resumed = s->resumed;
    return TLSB_OK;
}

int
tlsb_peer_cert(tlsb_sess *s, int depth, const uint8_t **der, size_t *len)
{
    const mbedtls_x509_crt *c = s->done ? mbedtls_ssl_get_peer_cert(&s->ssl)
	    : NULL;

    for (; c && depth > 0; depth--) {
	c = c->next;
    }
    if (c == NULL || depth < 0 || c->raw.len == 0) {
	return TLSB_ERROR;
    }
    *der = c->raw.p;
    *len = c->raw.len;
    return TLSB_OK;
}

int
tlsb_local_cert(tlsb_sess *s, const uint8_t **der, size_t *len)
{
    if (s->conf->own.raw.len == 0) {
	return TLSB_ERROR;
    }
    *der = s->conf->own.raw.p;
    *len = s->conf->own.raw.len;
    return TLSB_OK;
}

int
tlsb_export(tlsb_sess *s, const char *label, size_t label_len,
	const uint8_t *ctx, size_t ctx_len, int use_ctx, uint8_t *out,
	size_t out_len)
{
#ifdef MBEDTLS_SSL_KEYING_MATERIAL_EXPORT
    int r = -1;

    if (s->done) {
	Lock();
	r = mbedtls_ssl_export_keying_material(&s->ssl, out, out_len, label,
		label_len, use_ctx ? ctx : NULL, use_ctx ? ctx_len : 0, use_ctx);
	Unlock();
    }
    if (r == 0) {
	return TLSB_OK;
    }
    Msg(s->err, sizeof(s->err), "keying material export failed");
#else
    (void) label; (void) label_len; (void) ctx; (void) ctx_len;
    (void) use_ctx; (void) out; (void) out_len;
    Msg(s->err, sizeof(s->err), "keying material export not supported");
#endif
    return TLSB_ERROR;
}

/*
 * Crypto helpers.
 */

int
tlsb_random(uint8_t *buf, size_t len)
{
    psa_status_t r;

    Lock();
    r = psa_generate_random(buf, len);
    Unlock();
    return r == PSA_SUCCESS ? TLSB_OK : TLSB_ERROR;
}

static const mbedtls_md_info_t *
MdInfo(int alg)
{
    switch (alg) {
    case TLSB_SHA1:	return mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    case TLSB_SHA256:	return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    case TLSB_SHA512:	return mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    }
    return NULL;
}

int
tlsb_digest(int alg, const uint8_t *data, size_t len, uint8_t *out)
{
    const mbedtls_md_info_t *md = MdInfo(alg);

    return md && mbedtls_md(md, data, len, out) == 0 ? TLSB_OK : TLSB_ERROR;
}

int
tlsb_pbkdf2(int alg, const uint8_t *pw, size_t pw_len, const uint8_t *salt,
	size_t salt_len, uint32_t iterations, uint8_t *out, size_t out_len)
{
#ifdef MBEDTLS_PKCS5_C
    const mbedtls_md_info_t *md = MdInfo(alg);

    if (md && iterations > 0 && out_len <= UINT32_MAX
	    && mbedtls_pkcs5_pbkdf2_hmac_ext(mbedtls_md_get_type(md), pw, pw_len,
	    salt, salt_len, iterations, (uint32_t) out_len, out) == 0) {
	return TLSB_OK;
    }
#else
    (void) alg; (void) pw; (void) pw_len; (void) salt; (void) salt_len;
    (void) iterations; (void) out; (void) out_len;
#endif
    return TLSB_ERROR;
}

#ifdef MBEDTLS_GCM_C
static int
Gcm(int mode, const uint8_t key[32], const uint8_t nonce[12],
	const uint8_t *in, size_t len, uint8_t *out, uint8_t *tag)
{
    mbedtls_gcm_context gcm;
    int r;

    mbedtls_gcm_init(&gcm);
    r = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (r == 0) {
	r = mode == MBEDTLS_GCM_ENCRYPT
		? mbedtls_gcm_crypt_and_tag(&gcm, mode, len, nonce, 12, NULL, 0,
		in, out, 16, tag)
		: mbedtls_gcm_auth_decrypt(&gcm, len, nonce, 12, NULL, 0, tag, 16,
		in, out);
    }
    mbedtls_gcm_free(&gcm);
    return r == 0 ? TLSB_OK : TLSB_ERROR;
}
#endif

int
tlsb_aes256gcm_seal(const uint8_t key[32], const uint8_t nonce[12],
	const uint8_t *in, size_t len, uint8_t *out)
{
#ifdef MBEDTLS_GCM_C
    return Gcm(MBEDTLS_GCM_ENCRYPT, key, nonce, in, len, out, out + len);
#else
    (void) key; (void) nonce; (void) in; (void) len; (void) out;
    return TLSB_ERROR;
#endif
}

int
tlsb_aes256gcm_open(const uint8_t key[32], const uint8_t nonce[12],
	const uint8_t *in, size_t len, uint8_t *out)
{
#ifdef MBEDTLS_GCM_C
    if (len >= 16) {
	return Gcm(MBEDTLS_GCM_DECRYPT, key, nonce, in, len - 16, out,
		(uint8_t *) in + len - 16);
    }
#endif
    (void) key; (void) nonce; (void) in; (void) out;
    return TLSB_ERROR;
}
