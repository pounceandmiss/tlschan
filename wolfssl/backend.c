/*
 * backend.c --
 *
 *	tlsb.h on top of wolfSSL.
 */

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

#include "tlsb.h"

#define SUITEBUF	16384		/* size of a ':' separated suite list */
#define NCACHE		32		/* client sessions kept per conf */

/* Servers encrypt tickets themselves, under a key of each conf. */
#if defined(HAVE_SESSION_TICKET) && defined(HAVE_CHACHA) \
	&& defined(HAVE_POLY1305)
#define TICKETS
#endif

struct tlsb_conf {
    WOLFSSL_CTX *ctx;
    int server;
    int request;
    int require;
    int trust;			/* CAs given, or the system store tried */
    int sys;			/* trusts the system store */
    wolfSSL_Mutex lock;		/* guards the system store and the cache */
    char *alpn;			/* see JoinAlpn */
    uint8_t *leaf;		/* our certificate, DER */
    size_t leaf_len;
    const char *password;	/* only while loading the key */
    int ncache;
    struct {
	char *name;
	WOLFSSL_SESSION *sess;
    } cache[NCACHE];		/* client: last session per servername, oldest first */
#ifdef TICKETS
    uint8_t ticket_name[WOLFSSL_TICKET_NAME_SZ];
    uint8_t ticket_key[CHACHA20_POLY1305_AEAD_KEYSIZE];
#endif
};

struct tlsb_sess {
    tlsb_conf *conf;
    WOLFSSL *ssl;
    tlsb_io io;
    char *servername;
    int ip;			/* servername is an IP literal */
    int cacheable;		/* client session may be cached and resumed */
    int ticket;			/* a ticket arrived, store the session */
    int done;			/* handshake complete */
    int eof;			/* transport EOF */
    int dry;			/* recv returned 0 in this call */
    int broken;			/* accepted a bad CA, see VerifyCb */
    int verify_depth;		/* depth of the last verify callback */
    char verify_err[192];	/* why verification failed */
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
Fold(int c)
{
    c = (unsigned char) c;
    return c == '-' ? '_' : c >= 'a' && c <= 'z' ? c - 32 : c;
}

/* Case-insensitive, '-' and '_' alike. */
static int
CaseEq(const char *a, size_t an, const char *b, size_t bn)
{
    size_t i;

    if (an != bn) {
	return 0;
    }
    for (i = 0; i < an && Fold(a[i]) == Fold(b[i]); i++) ;
    return i == an;
}

static int
Contains(const uint8_t *buf, size_t len, const char *s)
{
    size_t i, n = strlen(s);

    for (i = 0; i + n <= len; i++) {
	if (memcmp(buf + i, s, n) == 0) {
	    return 1;
	}
    }
    return 0;
}

static int
IsPem(const uint8_t *buf, size_t len)
{
    return Contains(buf, len, "-----BEGIN");
}

static int
IsIpLiteral(const char *s)
{
    int dots = 0;

    if (strchr(s, ':')) {
	return 1;
    }
    for (; *s; s++) {
	if (*s == '.') {
	    dots++;
	} else if (*s < '0' || *s > '9') {
	    return 0;
	}
    }
    return dots == 3;
}

static const char *
ErrStr(int e)
{
    switch (e) {
    case ASN_AFTER_DATE_E:	return "certificate has expired";
    case ASN_BEFORE_DATE_E:	return "certificate is not yet valid";
    case ASN_NO_SIGNER_E:	return "unable to get local issuer certificate";
    case ASN_SELF_SIGNED_E:	return "self-signed certificate";
    case ASN_SIG_CONFIRM_E:
    case ASN_SIG_OID_E:
    case ASN_SIG_KEY_E:
    case ASN_SIG_HASH_E:	return "certificate signature failure";
    case ASN_PATHLEN_INV_E:	return "path length constraint exceeded";
    case DOMAIN_NAME_MISMATCH:
    case IPADDR_MISMATCH:	return "hostname mismatch";
    case NO_PEER_CERT:		return "peer did not return a certificate";
    case SOCKET_PEER_CLOSED_E:	return "connection closed";
    }
    return wolfSSL_ERR_reason_error_string((unsigned long) e);
}

/*
 * Library.
 */

static int initRet;

#ifdef _WIN32
static INIT_ONCE initOnce = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK
InitOnce(PINIT_ONCE once, PVOID p, PVOID *ctx)
{
    (void) once; (void) p; (void) ctx;
    initRet = wolfSSL_Init();
    return TRUE;
}
#else
static pthread_once_t initOnce = PTHREAD_ONCE_INIT;

static void
InitOnce(void)
{
    initRet = wolfSSL_Init();
}
#endif

int
tlsb_global_init(char *err, size_t errlen)
{
#ifdef _WIN32
    InitOnceExecuteOnce(&initOnce, InitOnce, NULL, NULL);
#else
    pthread_once(&initOnce, InitOnce);
#endif
    if (initRet != WOLFSSL_SUCCESS) {
	Msg(err, errlen, "wolfSSL initialization failed: %s", ErrStr(initRet));
	return TLSB_ERROR;
    }
    return TLSB_OK;
}

const char *
tlsb_version(void)
{
    return "wolfSSL " LIBWOLFSSL_VERSION_STRING;
}

unsigned
tlsb_protocols(void)
{
    unsigned p = 0;

#ifndef WOLFSSL_NO_TLS12
    p |= TLSB_TLS12;
#endif
#ifdef WOLFSSL_TLS13
    p |= TLSB_TLS13;
#endif
    return p;
}

/*
 * Cipher suites. wolfSSL_get_ciphers lists every compiled-in suite by its
 * wolfSSL name, aliases included.
 */

#define SuiteProto(c0)	((c0) == 0x13 /* TLS13_BYTE */ ? TLSB_TLS13 : TLSB_TLS12)

static char *
SuiteNames(void)
{
    char *buf = malloc(SUITEBUF);

    if (buf && wolfSSL_get_ciphers(buf, SUITEBUF) != WOLFSSL_SUCCESS) {
	free(buf);
	buf = NULL;
    }
    return buf;
}

/* Next name in a ':' separated list; *n gets its length. */
static const char *
NextName(const char **pp, size_t *n)
{
    const char *p = *pp;

    if (*p == 0) {
	return NULL;
    }
    *n = strcspn(p, ":");
    *pp = p + *n + (p[*n] == ':');
    return p;
}

/* wolfSSL_get_cipher_suite_from_name stops at ':'. */
static int
SuiteCode(const char *name, unsigned char *c0, unsigned char *c1)
{
    int flags;

    return wolfSSL_get_cipher_suite_from_name(name, c0, c1, &flags) == 0;
}

static int
Append(char *out, size_t outlen, const char *s, size_t n)
{
    size_t l = strlen(out);

    if (l + n + 2 > outlen) {
	return 0;
    }
    if (l) {
	out[l++] = ':';
    }
    memcpy(out + l, s, n);
    out[l + n] = 0;
    return 1;
}

void
tlsb_ciphers(unsigned protocols, void (*cb)(void *ud, const char *name),
	void *ud)
{
    char *buf = SuiteNames();
    const char *p = buf, *name;
    unsigned short seen[256];
    int nseen = 0;
    size_t n;

    if (buf == NULL) {
	return;
    }
    while ((name = NextName(&p, &n)) != NULL && nseen < 256) {
	unsigned char c0, c1;
	const char *iana;
	int i;

	if (!SuiteCode(name, &c0, &c1) || !(SuiteProto(c0) & protocols)) {
	    continue;
	}
	for (i = 0; i < nseen && seen[i] != (c0 << 8 | c1); i++) ;
	if (i < nseen) {
	    continue;
	}
	seen[nseen++] = (unsigned short) (c0 << 8 | c1);
	iana = wolfSSL_get_cipher_name_iana_from_suite(c0, c1);
	if (iana && strcmp(iana, "None") != 0) {
	    cb(ud, iana);
	}
    }
    free(buf);
}

/*
 * Sorts the suites named in spec (separated by any of ": ,\t\n") into the
 * TLS 1.2 and 1.3 lists as wolfSSL names. Lookup is case-insensitive over
 * wolfSSL and IANA names.
 */
static int
AddSuites(char *l12, char *l13, const char *spec, char *err, size_t errlen)
{
    char *buf = SuiteNames();
    const char *sep = ": ,\t\r\n";
    int ok = 1;

    if (buf == NULL) {
	Msg(err, errlen, "cannot list cipher suites");
	return 0;
    }
    while (ok && spec && *(spec += strspn(spec, sep))) {
	size_t len = strcspn(spec, sep), n = 0;
	const char *p = buf, *name;
	unsigned char c0, c1;

	while ((name = NextName(&p, &n)) != NULL) {
	    const char *iana;

	    if (!SuiteCode(name, &c0, &c1)) {
		continue;
	    }
	    iana = wolfSSL_get_cipher_name_iana_from_suite(c0, c1);
	    if (CaseEq(spec, len, name, n)
		    || (iana && CaseEq(spec, len, iana, strlen(iana)))) {
		break;
	    }
	}
	if (name == NULL) {
	    Msg(err, errlen, "unknown cipher: %.*s", (int) len, spec);
	    ok = 0;
	} else if (!Append(SuiteProto(c0) == TLSB_TLS13 ? l13 : l12, SUITEBUF,
		name, n)) {
	    Msg(err, errlen, "cipher list too long");
	    ok = 0;
	}
	spec += len;
    }
    free(buf);
    return ok;
}

/* Appends every compiled-in suite of protocol proto. */
static void
AddDefaultSuites(char *out, size_t outlen, unsigned proto)
{
    char *buf = SuiteNames();
    const char *p = buf, *name;
    size_t n;

    if (buf == NULL) {
	return;
    }
    while ((name = NextName(&p, &n)) != NULL) {
	unsigned char c0, c1;

	if (SuiteCode(name, &c0, &c1) && SuiteProto(c0) == proto) {
	    Append(out, outlen, name, n);
	}
    }
    free(buf);
}

/*
 * Builds the suite list into *list (NULL for the defaults). A protocol
 * without named suites keeps its defaults unless its own option was given,
 * which disables it.
 */
static int
SuiteList(const tlsb_opts *o, unsigned *p, char **list, char *err,
	size_t errlen)
{
    char *l12, *l13;
    int ok;

    *list = NULL;
    if (o->ciphers == NULL && o->ciphersuites == NULL) {
	return 1;
    }
    l12 = calloc(1, SUITEBUF), l13 = calloc(1, SUITEBUF);
    if (l12 == NULL || l13 == NULL) {
	Msg(err, errlen, "out of memory");
	ok = 0;
    } else {
	ok = AddSuites(l12, l13, o->ciphersuites, err, errlen)
		&& AddSuites(l12, l13, o->ciphers, err, errlen);
    }
    if (ok && *l13 == 0) {
	if (o->ciphersuites) *p &= ~TLSB_TLS13;
	else AddDefaultSuites(l13, SUITEBUF, TLSB_TLS13);
    }
    if (ok && *l12 == 0) {
	if (o->ciphers) *p &= ~TLSB_TLS12;
	else AddDefaultSuites(l12, SUITEBUF, TLSB_TLS12);
    }
    if (ok && *p == 0) {
	Msg(err, errlen, "no usable cipher suites");
	ok = 0;
    }
    if (ok && *l12 && !Append(l13, SUITEBUF, l12, strlen(l12))) {
	Msg(err, errlen, "cipher list too long");
	ok = 0;
    }
    free(l12);
    if (!ok) {
	free(l13);
	return 0;
    }
    *list = l13;
    return 1;
}

/*
 * Transport.
 */

static int
RecvCb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    tlsb_sess *s = ctx;
    long n = s->io.recv(s->io.ud, (uint8_t *) buf, (size_t) sz);

    (void) ssl;
    if (n > 0) {
	return (int) n;
    }
    if (n == 0) {
	s->dry = 1;
	return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    s->eof = 1;
    return WOLFSSL_CBIO_ERR_CONN_CLOSE;
}

static int
SendCb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    tlsb_sess *s = ctx;

    (void) ssl;
    s->io.send(s->io.ud, (const uint8_t *) buf, (size_t) sz);
    return sz;
}

/*
 * Configuration.
 */

static int
SniCb(WOLFSSL *ssl, int *ret, void *arg)
{
    (void) ssl; (void) ret; (void) arg;
    return 0;		/* only so that wolfSSL keeps the client's SNI */
}

#ifdef WOLFSSL_ENCRYPTED_KEYS
static int
PassCb(char *buf, int size, int rw, void *ud)
{
    const char *pw = ((tlsb_conf *) ud)->password;
    int n = pw ? (int) strlen(pw) : 0;

    (void) rw;
    if (n >= size) {
	n = size - 1;
    }
    memcpy(buf, pw ? pw : "", (size_t) n);
    buf[n] = 0;
    return n;
}
#endif

static int
LoadCert(tlsb_conf *c, const tlsb_opts *o, char *err, size_t errlen)
{
    int pem = IsPem(o->cert, o->cert_len), r;

    if (o->cert_len > INT_MAX) {
	Msg(err, errlen, "cannot parse certificate");
	return 0;
    }
    r = pem ? wolfSSL_CTX_use_certificate_chain_buffer_format(c->ctx,
	    o->cert, (long) o->cert_len, WOLFSSL_FILETYPE_PEM)
	    : wolfSSL_CTX_use_certificate_buffer(c->ctx, o->cert,
	    (long) o->cert_len, WOLFSSL_FILETYPE_ASN1);
    if (r != WOLFSSL_SUCCESS || (c->leaf = malloc(o->cert_len)) == NULL) {
	Msg(err, errlen, "cannot parse certificate");
	return 0;
    }
    if (pem) {
	r = wc_CertPemToDer(o->cert, (int) o->cert_len, c->leaf,
		(int) o->cert_len, CERT_TYPE);
	if (r <= 0) {
	    Msg(err, errlen, "cannot parse certificate");
	    return 0;
	}
	c->leaf_len = (size_t) r;
    } else {
	memcpy(c->leaf, o->cert, o->cert_len);
	c->leaf_len = o->cert_len;
    }
    return 1;
}

static int
LoadKey(tlsb_conf *c, const tlsb_opts *o, char *err, size_t errlen)
{
    int pem = IsPem(o->key, o->key_len), r, e = 0;
    int enc = pem && Contains(o->key, o->key_len, "ENCRYPTED");
    const uint8_t *key = o->key;
    uint8_t *dec = NULL;
    long len = (long) o->key_len;

    if (o->key_len > INT_MAX) {
	Msg(err, errlen, "cannot parse private key");
	return 0;
    }
    if (enc && o->password == NULL) {
	Msg(err, errlen, "password required");
	return 0;
    }
#ifdef WOLFSSL_ENCRYPTED_KEYS
    if (!pem && o->password && (dec = malloc(o->key_len)) != NULL) {
	/* Encrypted DER PKCS#8: decrypt ourselves, else load as is. */
	memcpy(dec, o->key, o->key_len);
	r = e = wc_DecryptPKCS8Key(dec, (word32) o->key_len, o->password,
		(int) strlen(o->password));
	if (r > 0) {
	    key = dec, len = r;
	}
    }
    c->password = o->password;
    wolfSSL_CTX_set_default_passwd_cb(c->ctx, PassCb);
    wolfSSL_CTX_set_default_passwd_cb_userdata(c->ctx, c);
#endif
    r = wolfSSL_CTX_use_PrivateKey_buffer(c->ctx, key, len,
	    pem ? WOLFSSL_FILETYPE_PEM : WOLFSSL_FILETYPE_ASN1);
#ifdef WOLFSSL_ENCRYPTED_KEYS
    wolfSSL_CTX_set_default_passwd_cb(c->ctx, NULL);
    wolfSSL_CTX_set_default_passwd_cb_userdata(c->ctx, NULL);
    c->password = NULL;
    if (r != WOLFSSL_SUCCESS && enc && (dec = malloc(o->key_len)) != NULL) {
	/* Again for the reason: a wrong password or an unknown cipher. */
	e = wc_KeyPemToDer(o->key, (int) o->key_len, dec, (int) o->key_len,
		o->password);
    }
#endif
    if (dec) {
	wc_ForceZero(dec, o->key_len);
	free(dec);
    }
    if (r != WOLFSSL_SUCCESS) {
	Msg(err, errlen, e == ALGO_ID_E || e == NOT_COMPILED_IN
		? "unsupported key encryption" : enc || o->password
		? "wrong password" : "cannot parse private key");
	return 0;
    }
    if (c->leaf && wolfSSL_CTX_check_private_key(c->ctx) != WOLFSSL_SUCCESS) {
	Msg(err, errlen, "private key does not match certificate");
	return 0;
    }
    return 1;
}

#ifdef TICKETS
/*
 * Session tickets under a key fixed at conf creation. wolfSSL's default
 * callback sets up and rotates its key without locking out other threads.
 */
static int
TicketCb(WOLFSSL *ssl, unsigned char name[WOLFSSL_TICKET_NAME_SZ],
	unsigned char iv[WOLFSSL_TICKET_IV_SZ],
	unsigned char mac[WOLFSSL_TICKET_MAC_SZ], int enc,
	unsigned char *ticket, int len, int *outlen, void *ud)
{
    tlsb_conf *c = ud;
    uint8_t aad[WOLFSSL_TICKET_NAME_SZ + WOLFSSL_TICKET_IV_SZ + 2];
    int r;

    if (enc) {
	memcpy(name, c->ticket_name, sizeof(c->ticket_name));
	if (tlsb_random(iv, WOLFSSL_TICKET_IV_SZ) != TLSB_OK) {
	    return WOLFSSL_TICKET_RET_FATAL;
	}
    } else if (memcmp(name, c->ticket_name, sizeof(c->ticket_name)) != 0
	    || ((tlsb_sess *) wolfSSL_GetIOReadCtx(ssl))->io.verify) {
	/* A verify callback must see every client chain: no resumption. */
	return WOLFSSL_TICKET_RET_REJECT;
    }
    memcpy(aad, name, WOLFSSL_TICKET_NAME_SZ);
    memcpy(aad + WOLFSSL_TICKET_NAME_SZ, iv, WOLFSSL_TICKET_IV_SZ);
    aad[sizeof(aad) - 2] = (uint8_t) (len >> 8);
    aad[sizeof(aad) - 1] = (uint8_t) len;
    r = enc ? wc_ChaCha20Poly1305_Encrypt(c->ticket_key, iv, aad, sizeof(aad),
	    ticket, (word32) len, ticket, mac)
	    : wc_ChaCha20Poly1305_Decrypt(c->ticket_key, iv, aad, sizeof(aad),
	    ticket, (word32) len, mac, ticket);
    if (r != 0) {
	return enc ? WOLFSSL_TICKET_RET_FATAL : WOLFSSL_TICKET_RET_REJECT;
    }
    *outlen = len;
    return WOLFSSL_TICKET_RET_OK;
}
#endif

static void
LoadSystemStore(tlsb_conf *c)
{
#ifdef WOLFSSL_SYS_CA_CERTS
    if (wc_LockMutex(&c->lock) == 0) {
	if (!c->trust) {
	    c->sys = 1;
	    if (wolfSSL_CTX_load_system_CA_certs(c->ctx) != WOLFSSL_SUCCESS) {
#if !defined(_WIN32) && !defined(__APPLE__)
		/* wolfSSL only looks for directories; OpenBSD and Haiku
		 * have a bundle. */
		wolfSSL_CTX_load_verify_locations_ex(c->ctx,
#ifdef __HAIKU__
			"/boot/system/data/ssl/CARootCertificates.pem",
#else
			"/etc/ssl/cert.pem",
#endif
			NULL, WOLFSSL_LOAD_FLAG_IGNORE_ERR);
#endif
	    }
	    c->trust = 1;	/* tried; failure only makes verification fail */
	}
	wc_UnLockMutex(&c->lock);
    }
#else
    (void) c;
#endif
}

static int
LoadTrust(tlsb_conf *c, const tlsb_opts *o, char *err, size_t errlen)
{
    if (o->ca && o->ca_len) {
	if (o->ca_len > LONG_MAX || wolfSSL_CTX_load_verify_buffer(c->ctx,
		o->ca, (long) o->ca_len, IsPem(o->ca, o->ca_len)
		? WOLFSSL_FILETYPE_PEM : WOLFSSL_FILETYPE_ASN1)
		!= WOLFSSL_SUCCESS) {
	    Msg(err, errlen, "cannot parse CA certificates");
	    return 0;
	}
	c->trust = 1;
    }
    if (o->cadir) {
	if (wolfSSL_CTX_load_verify_locations_ex(c->ctx, NULL, o->cadir,
		WOLFSSL_LOAD_FLAG_IGNORE_ERR) != WOLFSSL_SUCCESS) {
	    Msg(err, errlen, "cannot read cadir: %s", o->cadir);
	    return 0;
	}
	c->trust = 1;
    }
    if (c->require || c->request) {
	LoadSystemStore(c);
    }
    return 1;
}

/* The ALPN protocols joined with ',', as wolfSSL_UseALPN wants them. */
static int
JoinAlpn(tlsb_conf *c, const tlsb_opts *o, char *err, size_t errlen)
{
#ifdef HAVE_ALPN
    size_t n = 1;
    int i;

    if (o->alpn_count <= 0) {
	return 1;
    }
    for (i = 0; i < o->alpn_count; i++) {
	size_t l = strlen(o->alpn[i]);

	if (l == 0 || l > 255 || strchr(o->alpn[i], ',')) {
	    Msg(err, errlen, "invalid ALPN protocol name");
	    return 0;
	}
	n += l + 1;
    }
    if ((c->alpn = malloc(n)) == NULL) {
	Msg(err, errlen, "out of memory");
	return 0;
    }
    *c->alpn = 0;
    for (i = 0; i < o->alpn_count; i++) {
	if (i) strcat(c->alpn, ",");
	strcat(c->alpn, o->alpn[i]);
    }
#else
    (void) c; (void) o; (void) err; (void) errlen;	/* never negotiated */
#endif
    return 1;
}

static WOLFSSL_METHOD *
Method(unsigned protocols, int server)
{
    if (protocols == TLSB_TLS12) {
	return server ? wolfTLSv1_2_server_method() : wolfTLSv1_2_client_method();
    }
#ifdef WOLFSSL_TLS13
    if (protocols == TLSB_TLS13) {
	return server ? wolfTLSv1_3_server_method() : wolfTLSv1_3_client_method();
    }
#endif
    return server ? wolfSSLv23_server_method() : wolfSSLv23_client_method();
}

tlsb_conf *
tlsb_conf_new(const tlsb_opts *o, char *err, size_t errlen)
{
    tlsb_conf *c = calloc(1, sizeof(*c));
    unsigned p = o->protocols ? o->protocols & tlsb_protocols()
	    : tlsb_protocols();
    char *list = NULL;

    if (c == NULL) {
	Msg(err, errlen, "out of memory");
	return NULL;
    }
    c->server = o->server;
    c->request = o->request || o->require;
    c->require = o->require;
    if (wc_InitMutex(&c->lock) != 0) {
	free(c);
	Msg(err, errlen, "cannot create mutex");
	return NULL;
    }
    if (p == 0) {
	Msg(err, errlen, "no supported protocol version enabled");
	goto fail;
    }
    if (!SuiteList(o, &p, &list, err, errlen)) {
	goto fail;
    }
    if ((c->ctx = wolfSSL_CTX_new(Method(p, o->server))) == NULL) {
	Msg(err, errlen, "cannot create wolfSSL context");
	goto fail;
    }
    if (p == (TLSB_TLS12 | TLSB_TLS13)) {
	wolfSSL_CTX_SetMinVersion(c->ctx, WOLFSSL_TLSV1_2);
    }
    wolfSSL_CTX_SetIORecv(c->ctx, RecvCb);
    wolfSSL_CTX_SetIOSend(c->ctx, SendCb);
#ifndef NO_SESSION_CACHE
    /* The cache is process-wide: never resume across confs. */
    wolfSSL_CTX_set_session_cache_mode(c->ctx, WOLFSSL_SESS_CACHE_OFF);
#endif
    if (o->server) {
	wolfSSL_CTX_set_servername_callback(c->ctx, SniCb);
#ifdef TICKETS
	if (tlsb_random(c->ticket_name, sizeof(c->ticket_name)) != TLSB_OK
		|| tlsb_random(c->ticket_key, sizeof(c->ticket_key)) != TLSB_OK) {
	    Msg(err, errlen, "cannot generate session ticket key");
	    goto fail;
	}
	wolfSSL_CTX_set_TicketEncCtx(c->ctx, c);
	wolfSSL_CTX_set_TicketEncCb(c->ctx, TicketCb);
	wolfSSL_CTX_UseSessionTicket(c->ctx);	/* also after a rejected one */
#endif
    }
    if (list && wolfSSL_CTX_set_cipher_list(c->ctx, list) != WOLFSSL_SUCCESS) {
	Msg(err, errlen, "cannot set cipher list");
	goto fail;
    }
    free(list);
    list = NULL;

    if (!LoadTrust(c, o, err, errlen)) {
	goto fail;
    }
    if (!(o->cert && o->cert_len) != !(o->key && o->key_len)) {
	Msg(err, errlen, "certificate and private key go together");
	goto fail;
    }
    if (o->cert && o->cert_len && !LoadCert(c, o, err, errlen)) {
	goto fail;
    }
    if (o->key && o->key_len && !LoadKey(c, o, err, errlen)) {
	goto fail;
    }
    if (o->server && c->leaf == NULL) {
	Msg(err, errlen, "server requires a certificate and key");
	goto fail;
    }
    if (!JoinAlpn(c, o, err, errlen)) {
	goto fail;
    }
    return c;

  fail:
    free(list);
    tlsb_conf_free(c);
    return NULL;
}

void
tlsb_conf_free(tlsb_conf *c)
{
    int i;

    if (c == NULL) {
	return;
    }
    if (c->ctx) {
	wolfSSL_CTX_free(c->ctx);
    }
    wc_FreeMutex(&c->lock);
    for (i = 0; i < c->ncache; i++) {
	free(c->cache[i].name);
	wolfSSL_SESSION_free(c->cache[i].sess);
    }
#ifdef TICKETS
    wc_ForceZero(c->ticket_key, sizeof(c->ticket_key));
#endif
    free(c->alpn);
    free(c->leaf);
    free(c);
}

/*
 * Client session cache: the last session per servername, oldest dropped.
 */

static void
CachePut(tlsb_conf *c, const char *name, WOLFSSL_SESSION *sess)
{
    char *dup = malloc(strlen(name) + 1);
    int i;

    if (dup == NULL || wc_LockMutex(&c->lock) != 0) {
	free(dup);
	wolfSSL_SESSION_free(sess);
	return;
    }
    strcpy(dup, name);
    for (i = 0; i < c->ncache && strcmp(c->cache[i].name, name) != 0; i++) ;
    if (i == NCACHE) {
	i = 0;			/* full: drop the oldest */
    }
    if (i < c->ncache) {
	free(c->cache[i].name);
	wolfSSL_SESSION_free(c->cache[i].sess);
	memmove(c->cache + i, c->cache + i + 1,
		(size_t) (c->ncache - i - 1) * sizeof(c->cache[0]));
	c->ncache--;
    }
    c->cache[c->ncache].name = dup;
    c->cache[c->ncache++].sess = sess;
    wc_UnLockMutex(&c->lock);
}

static void
CacheUse(tlsb_sess *s)
{
    tlsb_conf *c = s->conf;
    int i;

    if (wc_LockMutex(&c->lock) == 0) {
	for (i = 0; i < c->ncache; i++) {
	    if (strcmp(c->cache[i].name, s->servername) == 0) {
		wolfSSL_set_session(s->ssl, c->cache[i].sess);
		break;
	    }
	}
	wc_UnLockMutex(&c->lock);
    }
}

/* Keeps the session once it can be resumed: TLS 1.3 after a ticket. */
static void
CacheStore(tlsb_sess *s)
{
    WOLFSSL_SESSION *sess;

    if (!s->cacheable || !s->done || (!s->ticket
	    && wolfSSL_GetVersion(s->ssl) == WOLFSSL_TLSV1_3)) {
	return;
    }
#ifdef HAVE_SESSION_TICKET
    /* A full handshake without a new ticket must not keep the old one. */
    if (!s->ticket && !wolfSSL_session_reused(s->ssl)) {
	wolfSSL_set_SessionTicket(s->ssl, NULL, 0);
    }
#endif
    if ((sess = wolfSSL_get1_session(s->ssl)) != NULL) {
	CachePut(s->conf, s->servername, sess);
    }
    s->ticket = 0;
}

#ifdef HAVE_SESSION_TICKET
static int
TicketRecvCb(WOLFSSL *ssl, const unsigned char *t, int len, void *ud)
{
    (void) ssl; (void) t; (void) len;
    ((tlsb_sess *) ud)->ticket = 1;
    return 0;
}
#endif

/*
 * Verification.
 */

/*
 * DER element at *p: returns its total length and sets *in to its
 * contents and *inlen to their length; 0 if malformed.
 */
static size_t
Element(const uint8_t *p, size_t len, const uint8_t **in, size_t *inlen)
{
    size_t h = 2, n;

    if (len < 2) {
	return 0;
    }
    n = p[1];
    if (n & 0x80) {
	int k = n & 0x7f;

	if (k < 1 || k > 3 || len < 2 + (size_t) k) {
	    return 0;
	}
	for (n = 0; k; k--) {
	    n = n << 8 | p[h++];
	}
    }
    if (n > len - h) {
	return 0;
    }
    *in = p + h;
    *inlen = n;
    return h + n;
}

/* Whether DER is a self-issued certificate: issuer and subject equal. */
static int
SelfIssued(const uint8_t *der, size_t len)
{
    const uint8_t *tbs, *f, *issuer = NULL;
    size_t tlen, n, step, ilen = 0;
    int i;

    if (!Element(der, len, &tbs, &tlen) || !Element(tbs, tlen, &tbs, &tlen)) {
	return 0;
    }
    /* [0] version, serial, signature, issuer, validity, subject */
    for (i = tbs[0] == 0xa0 ? 0 : 1; i < 6; i++) {
	if ((step = Element(tbs, tlen, &f, &n)) == 0) {
	    return 0;
	}
	if (i == 3) {
	    issuer = tbs, ilen = step;
	} else if (i == 5) {
	    return step == ilen && memcmp(tbs, issuer, ilen) == 0;
	}
	tbs += step, tlen -= step;
    }
    return 0;
}

/*
 * Builds with OPENSSL_COMPATIBLE_DEFAULTS (e.g. FreeBSD's) hand the verify
 * callback X509_V_ERR codes instead of wolfSSL's: map them back.
 */
static int
VerifyError(int e)
{
#ifdef OPENSSL_COMPATIBLE_DEFAULTS
    switch (e) {
    case WOLFSSL_X509_V_ERR_CERT_NOT_YET_VALID:	return ASN_BEFORE_DATE_E;
    case WOLFSSL_X509_V_ERR_CERT_HAS_EXPIRED:	return ASN_AFTER_DATE_E;
    case WOLFSSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
						return ASN_NO_SIGNER_E;
    case WOLFSSL_X509_V_ERR_HOSTNAME_MISMATCH:	return DOMAIN_NAME_MISMATCH;
    case WOLFSSL_X509_V_ERR_IP_ADDRESS_MISMATCH: return IPADDR_MISMATCH;
    case WOLFSSL_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
						return ASN_SELF_SIGNED_E;
    case WOLFSSL_X509_V_ERR_PATH_LENGTH_EXCEEDED: return ASN_PATHLEN_INV_E;
    case WOLFSSL_X509_V_ERR_CERT_SIGNATURE_FAILURE: return ASN_SIG_CONFIRM_E;
    }
#endif
    return e;
}

/* Whether the certificate at depth, or one the peer sent below it, is trusted. */
static int
Anchored(tlsb_sess *s, WOLFSSL_X509_STORE_CTX *st, int depth)
{
    WOLFSSL_CERT_MANAGER *cm = wolfSSL_CTX_GetCertManager(s->conf->ctx);

    for (; depth >= 0; depth--) {
	if (wolfSSL_CertManagerVerifyBuffer(cm, st->certs[depth].buffer,
		st->certs[depth].length, WOLFSSL_FILETYPE_ASN1)
		== WOLFSSL_SUCCESS) {
	    return 1;
	}
    }
    return 0;
}

#ifdef _WIN32
/*
 * Windows fetches most roots only on demand (see generic/winroot.c): adds
 * the certificates Windows trusts the peer chain through to the system
 * store, then the peer's own CAs. wolfSSL has no per-chain untrusted set and
 * caches every CA it accepts anyway, so intermediates are loaded too, but
 * only once Windows has verified them up to a trusted root.
 */
static void
WinAdd(void *ud, const uint8_t *der, size_t len, int root)
{
    (void) root;

    if (len <= LONG_MAX) {
	wolfSSL_CTX_load_verify_buffer((WOLFSSL_CTX *) ud, der, (long) len,
		WOLFSSL_FILETYPE_ASN1);
    }
}

static int
WinFetch(tlsb_sess *s, WOLFSSL_X509_STORE_CTX *st)
{
    const uint8_t *der[16];
    size_t len[16];
    int i, n = 0;

    if (!s->conf->sys || st->certs == NULL) {
	return 0;
    }
    for (i = 0; i < st->totalCerts && n < 16; i++) {
	der[n] = st->certs[i].buffer;
	len[n++] = st->certs[i].length;
    }
    if (tlsb_win_chain(der, len, n, s->conf->server, WinAdd,
	    s->conf->ctx) == 0) {
	return 0;
    }
    for (i = n - 1; i > 0; i--) {
	WinAdd(s->conf->ctx, der[i], len[i], 0);
    }
    return 1;
}
#endif

/*
 * Runs for every peer certificate, highest depth first. wolfSSL adds each
 * chain CA it accepts to the shared certificate manager, so once a bad CA is
 * let through we switch the session to VERIFY_NONE: nothing below it gets
 * cached, and our own verdict for the rest of the chain stays negative.
 */
static int
VerifyCb(int preverify, WOLFSSL_X509_STORE_CTX *st)
{
    tlsb_sess *s = st->userCtx;
    int depth = st->error_depth, ok = preverify, accept;
    int e = VerifyError(st->error);
    const char *err = ok ? NULL : ErrStr(e);
    const uint8_t *der = NULL;
    size_t len = 0;

    if (depth == s->verify_depth) {
	return 1;	/* leaf again after an override: already decided */
    }
    s->verify_depth = depth;
    if (st->certs && depth >= 0 && depth < st->totalCerts) {
	der = st->certs[depth].buffer;
	len = st->certs[depth].length;
    }
    if (s->broken && (ok || e == ASN_NO_SIGNER_E)) {
	ok = 0;
	err = "issuer certificate not trusted";
    } else if (der && (ok ? depth > 0 : e == ASN_NO_SIGNER_E)
	    && SelfIssued(der, len) && !Anchored(s, st, depth)) {
	ok = 0;		/* WOLFSSL_ALT_CERT_CHAINS passes an untrusted root */
	err = "self-signed certificate";
    }
#ifdef _WIN32
    if (!ok && !s->broken && der && (preverify || e == ASN_NO_SIGNER_E)
	    && WinFetch(s, st) && Anchored(s, st, depth)) {
	ok = 1;
	err = NULL;
    }
#endif
    if (s->io.verify) {
	accept = s->io.verify(s->io.ud, depth, der, len, ok, err);
    } else {
	accept = ok || !s->conf->require;
    }
    if (!accept) {
	if (s->io.verify) {
	    Msg(s->verify_err, sizeof(s->verify_err),
		    "certificate rejected by validation callback");
	} else {
	    Msg(s->verify_err, sizeof(s->verify_err), "certificate verify failed: %s", err);
	}
	return 0;
    }
    if (!ok && depth > 0 && !s->broken) {
	s->broken = 1;
	wolfSSL_set_verify(s->ssl, WOLFSSL_VERIFY_NONE, VerifyCb);
    }
    return 1;
}

/*
 * Sessions.
 */

tlsb_sess *
tlsb_sess_new(tlsb_conf *c, const char *servername, const tlsb_io *io,
	char *err, size_t errlen)
{
    tlsb_sess *s = calloc(1, sizeof(*s));
    int verify, mode;

    if (s == NULL) {
	Msg(err, errlen, "out of memory");
	return NULL;
    }
    s->conf = c;
    s->io = *io;
    s->verify_depth = -1;
    if ((s->ssl = wolfSSL_new(c->ctx)) == NULL) {
	Msg(err, errlen, "cannot create wolfSSL session");
	goto fail;
    }
    wolfSSL_SetIOReadCtx(s->ssl, s);
    wolfSSL_SetIOWriteCtx(s->ssl, s);
    wolfSSL_SetCertCbCtx(s->ssl, s);
#ifdef HAVE_KEYING_MATERIAL
    wolfSSL_KeepArrays(s->ssl);		/* the exporter needs the secrets */
#endif

    if (c->server) {
	verify = c->request;
	mode = !verify ? WOLFSSL_VERIFY_NONE : c->require
		? WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT
		: WOLFSSL_VERIFY_PEER;
    } else {
	verify = c->require || io->verify;
	mode = verify ? WOLFSSL_VERIFY_PEER : WOLFSSL_VERIFY_NONE;
    }
    if (verify && io->verify) {
	LoadSystemStore(c);
    }
    wolfSSL_set_verify(s->ssl, mode, verify ? VerifyCb : NULL);

    if (!c->server && servername) {
	size_t n = strlen(servername);
	int ip = IsIpLiteral(servername);

	if ((s->servername = malloc(n + 1)) == NULL) {
	    Msg(err, errlen, "out of memory");
	    goto fail;
	}
	memcpy(s->servername, servername, n + 1);
	s->ip = ip;
	if (!ip && n <= 0xffff && wolfSSL_UseSNI(s->ssl, WOLFSSL_SNI_HOST_NAME,
		servername, (unsigned short) n) != WOLFSSL_SUCCESS) {
	    Msg(err, errlen, "cannot set server name \"%s\"", servername);
	    goto fail;
	}
	if (verify && (ip ? wolfSSL_check_ip_address(s->ssl, servername)
		: wolfSSL_check_domain_name(s->ssl, servername))
		!= WOLFSSL_SUCCESS) {
	    Msg(err, errlen, "invalid server name \"%s\"", servername);
	    goto fail;
	}
	/* No resumption past a verify callback: it must see each handshake. */
	s->cacheable = io->verify == NULL;
#ifdef HAVE_SESSION_TICKET
	wolfSSL_UseSessionTicket(s->ssl);
	wolfSSL_set_SessionTicket_cb(s->ssl, TicketRecvCb, s);
#endif
	if (s->cacheable) {
	    CacheUse(s);
	}
    }
#ifdef HAVE_ALPN
    if (c->alpn && wolfSSL_UseALPN(s->ssl, c->alpn,
	    (unsigned) strlen(c->alpn), WOLFSSL_ALPN_CONTINUE_ON_MISMATCH)
	    != WOLFSSL_SUCCESS) {
	Msg(err, errlen, "cannot set ALPN protocols");
	goto fail;
    }
#endif
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
    if (s->ssl) {
	wolfSSL_free(s->ssl);
    }
    free(s->servername);
    free(s);
}

const char *
tlsb_errmsg(tlsb_sess *s)
{
    return s->err[0] ? s->err : "unknown error";
}

static const char *
AlertStr(int a)
{
    switch (a) {
    case 10:	return "unexpected message";
    case 20:	return "bad record mac";
    case 40:	return "handshake failure";
    case 41:	return "no certificate";
    case 42:	return "bad certificate";
    case 43:	return "unsupported certificate";
    case 44:	return "certificate revoked";
    case 45:	return "certificate expired";
    case 46:	return "certificate unknown";
    case 47:	return "illegal parameter";
    case 48:	return "unknown CA";
    case 50:	return "decode error";
    case 51:	return "decrypt error";
    case 70:	return "protocol version";
    case 71:	return "insufficient security";
    case 80:	return "internal error";
    case 109:	return "missing extension";
    case 112:	return "unrecognized name";
    case 116:	return "certificate required";
    case 120:	return "no application protocol";
    }
    return NULL;
}

/*
 * Records the reason of a failed wolfSSL call; returns TLSB_ERROR. what is
 * empty for the handshake, which the channel layer names itself.
 */
static int
Fail(tlsb_sess *s, const char *what, int e)
{
    const char *sep = *what ? ": " : "";
    WOLFSSL_ALERT_HISTORY h;
    const char *a;

    if (s->verify_err[0]) {
	Msg(s->err, sizeof(s->err), "%s", s->verify_err);
    } else if (s->eof || e == SOCKET_PEER_CLOSED_E) {
	Msg(s->err, sizeof(s->err), s->done ? "connection closed"
		: "connection closed during handshake");
    } else if (e == FATAL_ERROR && wolfSSL_get_alert_history(s->ssl, &h)
	    == WOLFSSL_SUCCESS && h.last_rx.level == alert_fatal
	    && (a = AlertStr(h.last_rx.code)) != NULL) {
	Msg(s->err, sizeof(s->err), "peer sent alert: %s", a);
    } else {
	Msg(s->err, sizeof(s->err), "%s%s%s", what, sep, ErrStr(e));
    }
    return TLSB_ERROR;
}

/*
 * Retry a WANT_READ while recv still has data: the caller only sees
 * WANT_READ once recv has run dry in this call. Bounded, to be safe.
 */
#define AGAIN(s, e, n) ((e) == WOLFSSL_ERROR_WANT_READ && !(s)->dry \
	&& !(s)->eof && (n)++ < 16)

int
tlsb_handshake(tlsb_sess *s)
{
    int r, e, n = 0;

    if (s->done) {
	return TLSB_OK;
    }
    s->dry = 0;
    do {
	r = s->conf->server ? wolfSSL_accept(s->ssl) : wolfSSL_connect(s->ssl);
	e = r == WOLFSSL_SUCCESS ? 0 : wolfSSL_get_error(s->ssl, r);
    } while (AGAIN(s, e, n));
    if (r == WOLFSSL_SUCCESS) {
	s->done = 1;
	CacheStore(s);
	return TLSB_OK;
    }
    if (e == WOLFSSL_ERROR_WANT_READ && !s->eof) {
	return TLSB_WANT_READ;
    }
    return Fail(s, "", e);
}

long
tlsb_read(tlsb_sess *s, uint8_t *buf, size_t len)
{
    int r, e, n = 0;

    if (!s->done && (r = tlsb_handshake(s)) != TLSB_OK) {
	return r;
    }
    s->dry = 0;
    do {
	r = wolfSSL_read(s->ssl, buf, len > INT_MAX ? INT_MAX : (int) len);
	e = r > 0 ? 0 : wolfSSL_get_error(s->ssl, r);
    } while (AGAIN(s, e, n));
    if (s->ticket) {
	CacheStore(s);
    }
    if (r > 0) {
	return r;
    }
    if (e == WOLFSSL_ERROR_WANT_READ && !s->eof) {
	return TLSB_WANT_READ;
    }
    if (e == WOLFSSL_ERROR_ZERO_RETURN || s->eof || e == SOCKET_PEER_CLOSED_E) {
	return 0;
    }
    return Fail(s, "read failed", e);
}

long
tlsb_write(tlsb_sess *s, const uint8_t *buf, size_t len)
{
    size_t done = 0;

    if (!s->done) {
	Msg(s->err, sizeof(s->err), "handshake not complete");
	return TLSB_ERROR;
    }
    while (done < len) {
	int n = len - done > INT_MAX ? INT_MAX : (int) (len - done);
	int r = wolfSSL_write(s->ssl, buf + done, n);

	if (r <= 0) {
	    return Fail(s, "write failed", wolfSSL_get_error(s->ssl, r));
	}
	done += (size_t) r;
    }
    return (long) len;
}

int
tlsb_pending(tlsb_sess *s)
{
    return wolfSSL_pending(s->ssl) > 0 || wolfSSL_has_pending(s->ssl);
}

void
tlsb_close_notify(tlsb_sess *s)
{
    if (s->done) {
	wolfSSL_shutdown(s->ssl);
    }
}

int
tlsb_info_get(tlsb_sess *s, tlsb_info *info)
{
    int cs, bits = 0;
    const char *c;

    if (!s->done) {
	return TLSB_ERROR;
    }
    memset(info, 0, sizeof(*info));
    switch (wolfSSL_GetVersion(s->ssl)) {
    case WOLFSSL_TLSV1_2:	info->protocol = "TLS1.2"; break;
    case WOLFSSL_TLSV1_3:	info->protocol = "TLS1.3"; break;
    default:			info->protocol = "unknown";
    }
    cs = wolfSSL_get_current_cipher_suite(s->ssl);
    c = wolfSSL_get_cipher_name_iana_from_suite((unsigned char) (cs >> 8),
	    (unsigned char) cs);
    if (c) {
	bits = strstr(c, "_128_") ? 128 : strstr(c, "_256_") ? 256
		: strstr(c, "CHACHA20") ? 256 : 0;
    }
    info->cipher = c;
    info->cipher_bits = bits;
#ifdef HAVE_ALPN
    {
	char *p;
	unsigned short n;

	if (wolfSSL_ALPN_GetProtocol(s->ssl, &p, &n) == WOLFSSL_SUCCESS && n) {
	    info->alpn = (const uint8_t *) p;
	    info->alpn_len = n;
	}
    }
#endif
    if (s->conf->server) {
	void *p = NULL;

	if (wolfSSL_SNI_GetRequest(s->ssl, WOLFSSL_SNI_HOST_NAME, &p) && p) {
	    info->servername = p;
	}
    } else {
	info->servername = s->ip ? NULL : s->servername;
    }
    info->resumed = wolfSSL_session_reused(s->ssl) > 0;
    return TLSB_OK;
}

int
tlsb_peer_cert(tlsb_sess *s, int depth, const uint8_t **der, size_t *len)
{
#ifdef SESSION_CERTS
    WOLFSSL_X509_CHAIN *ch = s->done ? wolfSSL_get_peer_chain(s->ssl) : NULL;

    if (ch && depth >= 0 && depth < wolfSSL_get_chain_count(ch)) {
	*der = wolfSSL_get_chain_cert(ch, depth);
	*len = (size_t) wolfSSL_get_chain_length(ch, depth);
	return *der ? TLSB_OK : TLSB_ERROR;
    }
#else
    (void) s; (void) depth; (void) der; (void) len;
#endif
    return TLSB_ERROR;
}

int
tlsb_local_cert(tlsb_sess *s, const uint8_t **der, size_t *len)
{
    if (s->conf->leaf == NULL) {
	return TLSB_ERROR;
    }
    *der = s->conf->leaf;
    *len = s->conf->leaf_len;
    return TLSB_OK;
}

int
tlsb_export(tlsb_sess *s, const char *label, size_t label_len,
	const uint8_t *ctx, size_t ctx_len, int use_ctx, uint8_t *out,
	size_t out_len)
{
#ifdef HAVE_KEYING_MATERIAL
    if (s->done && wolfSSL_export_keying_material(s->ssl, out, out_len,
	    label, label_len, use_ctx ? ctx : NULL, use_ctx ? ctx_len : 0,
	    use_ctx) == WOLFSSL_SUCCESS) {
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
    WC_RNG rng;
    int ok;

    if (wc_InitRng(&rng) != 0) {
	return TLSB_ERROR;
    }
    for (ok = 1; ok && len > 0; ) {
	word32 n = len > 0x10000 ? 0x10000 : (word32) len;

	ok = wc_RNG_GenerateBlock(&rng, buf, n) == 0;
	buf += n, len -= n;
    }
    wc_FreeRng(&rng);
    return ok ? TLSB_OK : TLSB_ERROR;
}

static enum wc_HashType
HashType(int alg)
{
    switch (alg) {
    case TLSB_SHA1:	return WC_HASH_TYPE_SHA;
    case TLSB_SHA256:	return WC_HASH_TYPE_SHA256;
    case TLSB_SHA512:	return WC_HASH_TYPE_SHA512;
    }
    return WC_HASH_TYPE_NONE;
}

int
tlsb_digest(int alg, const uint8_t *data, size_t len, uint8_t *out)
{
    enum wc_HashType t = HashType(alg);
    wc_HashAlg h;
    int ok;

    if (t == WC_HASH_TYPE_NONE || wc_HashInit(&h, t) != 0) {
	return TLSB_ERROR;
    }
    for (ok = 1; ok && len > 0; ) {
	word32 n = len > 0x40000000 ? 0x40000000 : (word32) len;

	ok = wc_HashUpdate(&h, t, data, n) == 0;
	data += n, len -= n;
    }
    ok = ok && wc_HashFinal(&h, t, out) == 0;
    wc_HashFree(&h, t);
    return ok ? TLSB_OK : TLSB_ERROR;
}

int
tlsb_pbkdf2(int alg, const uint8_t *pw, size_t pw_len, const uint8_t *salt,
	size_t salt_len, uint32_t iterations, uint8_t *out, size_t out_len)
{
    enum wc_HashType t = HashType(alg);

    if (t == WC_HASH_TYPE_NONE || pw_len > INT_MAX || salt_len > INT_MAX
	    || out_len > INT_MAX || iterations == 0 || iterations > INT_MAX) {
	return TLSB_ERROR;
    }
    return wc_PBKDF2(out, pw, (int) pw_len, salt, (int) salt_len,
	    (int) iterations, (int) out_len, (int) t) == 0
	    ? TLSB_OK : TLSB_ERROR;
}

int
tlsb_aes256gcm_seal(const uint8_t key[32], const uint8_t nonce[12],
	const uint8_t *in, size_t len, uint8_t *out)
{
    Aes aes;
    int r;

    if (len > 0xffffffe0u || wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
	return TLSB_ERROR;
    }
    r = wc_AesGcmSetKey(&aes, key, 32) == 0
	    && wc_AesGcmEncrypt(&aes, out, in, (word32) len, nonce, 12,
	    out + len, 16, NULL, 0) == 0;
    wc_AesFree(&aes);
    return r ? TLSB_OK : TLSB_ERROR;
}

int
tlsb_aes256gcm_open(const uint8_t key[32], const uint8_t nonce[12],
	const uint8_t *in, size_t len, uint8_t *out)
{
    Aes aes;
    int r;

    if (len < 16 || len - 16 > 0xffffffe0u
	    || wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
	return TLSB_ERROR;
    }
    len -= 16;
    r = wc_AesGcmSetKey(&aes, key, 32) == 0
	    && wc_AesGcmDecrypt(&aes, out, in, (word32) len, nonce, 12,
	    in + len, 16, NULL, 0) == 0;
    wc_AesFree(&aes);
    if (!r) {
	memset(out, 0, len);
    }
    return r ? TLSB_OK : TLSB_ERROR;
}
