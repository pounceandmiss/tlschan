/*
 * backend.c --
 *
 *	tlsb.h on top of OpenSSL 3.
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L	/* S_ISDIR under -std=c11 */
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/decoder.h>
#include <openssl/crypto.h>

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

#include "tlsb.h"

#if !defined(S_ISDIR) && defined(_S_IFDIR)
#define S_ISDIR(m)	(((m) & _S_IFMT) == _S_IFDIR)
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "OpenSSL 3.0 or later required"
#endif

#define MAXCHAIN	16
#define NCACHE		32		/* client sessions kept per conf */
#define TLS13_ALL	"TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:" \
			"TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:" \
			"TLS_AES_128_CCM_8_SHA256"

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
    SSL_CTX *ctx;
    int server;
    int request;
    int require;
    uint8_t *alpn;		/* wire format */
    size_t alpn_len;
    uint8_t *leaf;		/* our certificate, DER */
    size_t leaf_len;
    CRYPTO_RWLOCK *lock;	/* guards the cache */
    int ncache;
    struct {
	char *name;
	SSL_SESSION *sess;
    } cache[NCACHE];		/* client: last session per servername, oldest first */
};

struct tlsb_sess {
    tlsb_conf *conf;
    SSL *ssl;
    tlsb_io io;
    char *servername;
    int ip;			/* servername is an IP literal */
    int cache;			/* client session may be cached and resumed */
    uint8_t *der[MAXCHAIN];	/* tlsb_peer_cert results, kept */
    size_t derlen[MAXCHAIN];
    int done;			/* handshake complete */
    int eof;			/* transport EOF */
    int dry;			/* recv returned 0 in this call */
    int vcode[MAXCHAIN];	/* first verify error per depth */
    char sni[256];		/* server: name the client asked for */
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

static BIO *
MemBio(const uint8_t *buf, size_t len)
{
    return len > INT_MAX ? NULL : BIO_new_mem_buf(buf, (int) len);
}

/*
 * Library.
 */

static Once initOnce = ONCE_INIT;
static BIO_METHOD *bioMethod;
static char version[48];

static int BioWrite(BIO *b, const char *buf, int len);
static int BioRead(BIO *b, char *buf, int len);
static long BioCtrl(BIO *b, int cmd, long num, void *ptr);

static void
InitOnce(void)
{
    BIO_METHOD *m;

    snprintf(version, sizeof(version), "OpenSSL %s",
	    OpenSSL_version(OPENSSL_VERSION_STRING));
    if (OPENSSL_init_ssl(0, NULL) != 1 || (m = BIO_meth_new(
	    BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "tlsb")) == NULL) {
	return;
    }
    if (!BIO_meth_set_write(m, BioWrite) || !BIO_meth_set_read(m, BioRead)
	    || !BIO_meth_set_ctrl(m, BioCtrl)) {
	BIO_meth_free(m);
	return;
    }
    bioMethod = m;
}

int
tlsb_global_init(char *err, size_t errlen)
{
    RunOnce(&initOnce, InitOnce);
    if (bioMethod == NULL) {
	Msg(err, errlen, "OpenSSL initialization failed");
	return TLSB_ERROR;
    }
    return TLSB_OK;
}

const char *
tlsb_version(void)
{
    RunOnce(&initOnce, InitOnce);
    return version;
}

unsigned
tlsb_protocols(void)
{
    unsigned p = 0;

#ifndef OPENSSL_NO_TLS1_2
    p |= TLSB_TLS12;
#endif
#ifndef OPENSSL_NO_TLS1_3
    p |= TLSB_TLS13;
#endif
    return p;
}

/*
 * System trust store: OpenSSL's default paths, plus the usual bundles for
 * builds whose OPENSSLDIR holds none. Loaded on first use, read only after.
 */

static X509_STORE *sysStore;
static Once sysOnce = ONCE_INIT;

static void
SysOnce(void)
{
    static const char *const bundles[] = {
	"/etc/ssl/certs/ca-certificates.crt",	/* Debian, Arch, Gentoo */
	"/etc/pki/tls/certs/ca-bundle.crt",	/* Fedora, RHEL */
	"/etc/ssl/ca-bundle.pem",		/* openSUSE */
	"/etc/ssl/cert.pem",			/* BSDs, Alpine */
	"/boot/system/data/ssl/CARootCertificates.pem",	/* Haiku */
	NULL
    };
    int i;

    if ((sysStore = X509_STORE_new()) == NULL) {
	return;
    }
    X509_STORE_set_default_paths(sysStore);
#if defined(_WIN32) && OPENSSL_VERSION_NUMBER >= 0x30200000L
    X509_STORE_load_store(sysStore, "org.openssl.winstore:");
#endif
    for (i = 0; bundles[i] && !getenv("SSL_CERT_FILE")
	    && sk_X509_OBJECT_num(X509_STORE_get0_objects(sysStore)) == 0; i++) {
	X509_STORE_load_file(sysStore, bundles[i]);
    }
    ERR_clear_error();
}

/*
 * Cipher suites. We report IANA names and accept those and OpenSSL's.
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

    if (b == NULL || strlen(b) != an) {
	return 0;
    }
    for (i = 0; i < an && Fold(a[i]) == Fold(b[i]); i++) ;
    return i == an;
}

static unsigned
SuiteProto(const SSL_CIPHER *c)
{
    return SSL_CIPHER_get_protocol_id(c) >> 8 == 0x13 ? TLSB_TLS13
	    : TLSB_TLS12;
}

/* Certificate based suites. */
static int
Usable(const SSL_CIPHER *c)
{
    int a = SSL_CIPHER_get_auth_nid(c), k = SSL_CIPHER_get_kx_nid(c);

    return (a == NID_auth_rsa || a == NID_auth_ecdsa || a == NID_auth_any)
	    && (k == NID_kx_ecdhe || k == NID_kx_dhe || k == NID_kx_rsa
	    || k == NID_kx_any);
}

/* Every suite OpenSSL knows; free *tmp afterwards. */
static STACK_OF(SSL_CIPHER) *
AllSuites(SSL_CTX **tmp)
{
    if ((*tmp = SSL_CTX_new(TLS_method())) == NULL
	    || !SSL_CTX_set_cipher_list(*tmp, "ALL")
	    || !SSL_CTX_set_ciphersuites(*tmp, TLS13_ALL)) {
	return NULL;
    }
    return SSL_CTX_get_ciphers(*tmp);
}

void
tlsb_ciphers(unsigned protocols, void (*cb)(void *ud, const char *name),
	void *ud)
{
    SSL_CTX *tmp;
    STACK_OF(SSL_CIPHER) *all = AllSuites(&tmp);
    int i;

    for (i = 0; all && i < sk_SSL_CIPHER_num(all); i++) {
	const SSL_CIPHER *c = sk_SSL_CIPHER_value(all, i);

	if (Usable(c) && (SuiteProto(c) & protocols)) {
	    cb(ud, SSL_CIPHER_standard_name(c));
	}
    }
    SSL_CTX_free(tmp);
    ERR_clear_error();
}

static int
Append(char *out, size_t outlen, const char *s)
{
    size_t l = strlen(out), n = strlen(s);

    if (l + n + 2 > outlen) {
	return 0;
    }
    if (l) {
	out[l++] = ':';
    }
    memcpy(out + l, s, n + 1);
    return 1;
}

/*
 * Sorts the suites named in spec (separated by any of ": ,\t\r\n") into the
 * TLS 1.2 and 1.3 lists, as OpenSSL names.
 */
static int
AddSuites(STACK_OF(SSL_CIPHER) *all, const char *spec, char *l12,
	char *l13, size_t len, char *err, size_t errlen)
{
    const char *sep = ": ,\t\r\n";

    while (spec && *(spec += strspn(spec, sep))) {
	size_t n = strcspn(spec, sep);
	const SSL_CIPHER *c = NULL;
	int i;

	for (i = 0; i < sk_SSL_CIPHER_num(all); i++) {
	    c = sk_SSL_CIPHER_value(all, i);
	    if (NameEq(spec, n, SSL_CIPHER_get_name(c))
		    || NameEq(spec, n, SSL_CIPHER_standard_name(c))) {
		break;
	    }
	}
	if (i == sk_SSL_CIPHER_num(all)) {
	    Msg(err, errlen, "unknown cipher: %.*s", (int) n, spec);
	    return 0;
	}
	if (!Append(SuiteProto(c) == TLSB_TLS13 ? l13 : l12, len,
		SSL_CIPHER_get_name(c))) {
	    Msg(err, errlen, "cipher list too long");
	    return 0;
	}
	spec += n;
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
    char l12[4096] = "", l13[4096] = "";
    SSL_CTX *tmp;
    STACK_OF(SSL_CIPHER) *all;
    int ok;

    if (o->ciphers == NULL && o->ciphersuites == NULL) {
	return 1;
    }
    if ((all = AllSuites(&tmp)) == NULL) {
	Msg(err, errlen, "cannot list cipher suites");
	SSL_CTX_free(tmp);
	return 0;
    }
    ok = AddSuites(all, o->ciphersuites, l12, l13, sizeof(l12), err, errlen)
	    && AddSuites(all, o->ciphers, l12, l13, sizeof(l12), err, errlen);
    SSL_CTX_free(tmp);
    if (!ok) {
	return 0;
    }
    if (o->ciphers && *l12 == 0) {
	*p &= ~TLSB_TLS12;
    }
    if (o->ciphersuites && *l13 == 0) {
	*p &= ~TLSB_TLS13;
    }
    if ((*l12 && !SSL_CTX_set_cipher_list(c->ctx, l12))
	    || (*l13 && !SSL_CTX_set_ciphersuites(c->ctx, l13))) {
	Msg(err, errlen, "cannot set cipher list");
	return 0;
    }
    if (*p == 0) {
	Msg(err, errlen, "no usable cipher suites");
	return 0;
    }
    return 1;
}

/*
 * Configuration.
 */

/* Server: remembers the name the client asked for. */
static int
SniCb(SSL *ssl, int *al, void *arg)
{
    tlsb_sess *s = SSL_get_app_data(ssl);
    const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

    (void) al; (void) arg;
    if (name && strlen(name) < sizeof(s->sni)) {
	strcpy(s->sni, name);
    }
    return SSL_TLSEXT_ERR_OK;
}

/* Server preference; no overlap means no ALPN rather than a failure. */
static int
AlpnCb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
	const unsigned char *in, unsigned int inlen, void *arg)
{
    tlsb_conf *c = arg;
    unsigned char *sel;

    (void) ssl;
    if (SSL_select_next_proto(&sel, outlen, c->alpn, (unsigned) c->alpn_len,
	    in, inlen) != OPENSSL_NPN_NEGOTIATED) {
	return SSL_TLSEXT_ERR_NOACK;
    }
    *out = sel;
    return SSL_TLSEXT_ERR_OK;
}

typedef struct Pass {
    const char *pw;
    int asked;
} Pass;

static int
PassCb(char *buf, int size, int rw, void *ud)
{
    Pass *p = ud;
    size_t n;

    (void) rw;
    p->asked = 1;
    if (p->pw == NULL || (n = strlen(p->pw)) > (size_t) size) {
	return -1;
    }
    memcpy(buf, p->pw, n);
    return (int) n;
}

static int
LoadCert(tlsb_conf *c, const tlsb_opts *o, char *err, size_t errlen)
{
    BIO *b = MemBio(o->cert, o->cert_len);
    X509 *x = NULL;
    unsigned char *der = NULL;
    int pem = IsPem(o->cert, o->cert_len), n = 0, ok;

    if (b && pem) {
	x = PEM_read_bio_X509(b, NULL, NULL, NULL);
    } else if (b) {
	x = d2i_X509_bio(b, NULL);
    }
    ok = x && SSL_CTX_use_certificate(c->ctx, x)
	    && (n = i2d_X509(x, &der)) > 0;
    X509_free(x);
    /* PEM: the rest is the chain. */
    while (ok && pem
	    && (x = PEM_read_bio_X509(b, NULL, NULL, NULL)) != NULL) {
	if (!SSL_CTX_add0_chain_cert(c->ctx, x)) {
	    X509_free(x);
	    ok = 0;
	}
    }
    BIO_free(b);
    ERR_clear_error();
    c->leaf = der;
    c->leaf_len = n > 0 ? (size_t) n : 0;
    if (!ok) {
	Msg(err, errlen, "cannot parse certificate");
    }
    return ok;
}

static int
LoadKey(tlsb_conf *c, const tlsb_opts *o, char *err, size_t errlen)
{
    BIO *b = MemBio(o->key, o->key_len);
    Pass pass = {o->password, 0};
    EVP_PKEY *k = NULL;
    X509 *leaf = SSL_CTX_get0_certificate(c->ctx);
    int ok = 0;

    if (b && IsPem(o->key, o->key_len)) {
	k = PEM_read_bio_PrivateKey(b, NULL, PassCb, &pass);
    } else if (b) {
	OSSL_DECODER_CTX *d = OSSL_DECODER_CTX_new_for_pkey(&k, "DER", NULL,
		NULL, EVP_PKEY_KEYPAIR, NULL, NULL);

	if (d && OSSL_DECODER_CTX_set_pem_password_cb(d, PassCb, &pass)) {
	    OSSL_DECODER_from_bio(d, b);
	}
	OSSL_DECODER_CTX_free(d);
    }
    BIO_free(b);
    if (k == NULL) {
	Msg(err, errlen, pass.asked && !pass.pw ? "password required"
		: pass.asked || pass.pw ? "wrong password"
		: "cannot parse private key");
    } else if (leaf && !X509_check_private_key(leaf, k)) {
	Msg(err, errlen, "private key does not match certificate");
    } else if (!SSL_CTX_use_PrivateKey(c->ctx, k)) {
	Msg(err, errlen, "cannot use private key");
    } else {
	ok = 1;
    }
    EVP_PKEY_free(k);
    ERR_clear_error();
    return ok;
}

static int
LoadTrust(tlsb_conf *c, const tlsb_opts *o, char *err, size_t errlen)
{
    X509_STORE *st = SSL_CTX_get_cert_store(c->ctx);
    int has_ca = o->ca && o->ca_len;
    struct stat sb;

    if (has_ca) {
	BIO *b = MemBio(o->ca, o->ca_len);
	X509 *x;
	int n = 0;

	if (b && IsPem(o->ca, o->ca_len)) {
	    while ((x = PEM_read_bio_X509(b, NULL, NULL, NULL)) != NULL) {
		n += X509_STORE_add_cert(st, x);
		X509_free(x);
	    }
	} else if (b && (x = d2i_X509_bio(b, NULL)) != NULL) {
	    n += X509_STORE_add_cert(st, x);
	    X509_free(x);
	}
	BIO_free(b);
	ERR_clear_error();
	if (n == 0) {
	    Msg(err, errlen, "cannot parse CA certificates");
	    return 0;
	}
    }
    if (o->cadir) {
	if (stat(o->cadir, &sb) != 0 || !S_ISDIR(sb.st_mode)
		|| !X509_STORE_load_path(st, o->cadir)) {
	    Msg(err, errlen, "cannot read cadir: %s", o->cadir);
	    return 0;
	}
    }
    if (!has_ca && !o->cadir && (!c->server || c->request)) {
	RunOnce(&sysOnce, SysOnce);
	if (sysStore) {
	    SSL_CTX_set1_cert_store(c->ctx, sysStore);
	}
    }
    return 1;
}

static int
SetAlpn(tlsb_conf *c, const tlsb_opts *o, char *err, size_t errlen)
{
    size_t n = 0;
    uint8_t *p;
    int i;

    for (i = 0; i < o->alpn_count; i++) {
	size_t l = strlen(o->alpn[i]);

	if (l == 0 || l > 255) {
	    Msg(err, errlen, "invalid ALPN protocol name");
	    return 0;
	}
	n += l + 1;
    }
    if (n > 0xffff || (c->alpn = p = malloc(n)) == NULL) {
	Msg(err, errlen, n > 0xffff ? "ALPN list too long" : "out of memory");
	return 0;
    }
    for (i = 0; i < o->alpn_count; i++) {
	*p = (uint8_t) strlen(o->alpn[i]);
	memcpy(p + 1, o->alpn[i], *p);
	p += *p + 1;
    }
    c->alpn_len = n;
    if (c->server) {
	SSL_CTX_set_alpn_select_cb(c->ctx, AlpnCb, c);
    } else if (SSL_CTX_set_alpn_protos(c->ctx, c->alpn, (unsigned) n) != 0) {
	Msg(err, errlen, "cannot set ALPN protocols");
	return 0;
    }
    return 1;
}

/* A verify callback must see every client chain: no resumption. */
static SSL_TICKET_RETURN
TicketCb(SSL *ssl, SSL_SESSION *sess, const unsigned char *name, size_t len,
	SSL_TICKET_STATUS st, void *arg)
{
    tlsb_sess *s = SSL_get_app_data(ssl);

    (void) sess; (void) name; (void) len; (void) arg;
    if (s->io.verify || (st != SSL_TICKET_SUCCESS
	    && st != SSL_TICKET_SUCCESS_RENEW)) {
	return st == SSL_TICKET_NONE ? SSL_TICKET_RETURN_IGNORE
		: SSL_TICKET_RETURN_IGNORE_RENEW;
    }
    return st == SSL_TICKET_SUCCESS ? SSL_TICKET_RETURN_USE
	    : SSL_TICKET_RETURN_USE_RENEW;
}

/*
 * Client session cache: the last session per servername, oldest dropped.
 * OpenSSL hands over each new session: TLS 1.2 after the handshake, TLS 1.3
 * per ticket.
 */
static int
NewSessCb(SSL *ssl, SSL_SESSION *sess)
{
    tlsb_sess *s = SSL_get_app_data(ssl);
    tlsb_conf *c = s->conf;
    char *name;
    int i;

    /*
     * A copy: OpenSSL marks a session unresumable when its connection is
     * freed without close_notify.
     */
    if (!s->cache || !SSL_SESSION_is_resumable(sess)
	    || (sess = SSL_SESSION_dup(sess)) == NULL) {
	return 0;
    }
    if ((name = OPENSSL_strdup(s->servername)) == NULL
	    || !CRYPTO_THREAD_write_lock(c->lock)) {
	OPENSSL_free(name);
	SSL_SESSION_free(sess);
	return 0;
    }
    for (i = 0; i < c->ncache && strcmp(c->cache[i].name, name) != 0; i++) ;
    if (i == NCACHE) {
	i = 0;			/* full: drop the oldest */
    }
    if (i < c->ncache) {
	OPENSSL_free(c->cache[i].name);
	SSL_SESSION_free(c->cache[i].sess);
	memmove(c->cache + i, c->cache + i + 1,
		(size_t) (c->ncache - i - 1) * sizeof(c->cache[0]));
	c->ncache--;
    }
    c->cache[c->ncache].name = name;
    c->cache[c->ncache++].sess = sess;
    CRYPTO_THREAD_unlock(c->lock);
    return 0;
}

/* Client: offers the cached session for s->servername, if any. */
static void
ResumeCached(tlsb_sess *s)
{
    tlsb_conf *c = s->conf;
    int i;

    if (CRYPTO_THREAD_read_lock(c->lock)) {
	for (i = 0; i < c->ncache; i++) {
	    if (strcmp(c->cache[i].name, s->servername) == 0) {
		SSL_SESSION *d = SSL_SESSION_dup(c->cache[i].sess);

		if (d) {		/* a copy, see NewSessCb */
		    SSL_set_session(s->ssl, d);
		    SSL_SESSION_free(d);
		}
		break;
	    }
	}
	CRYPTO_THREAD_unlock(c->lock);
    }
}

static int CertVerify(X509_STORE_CTX *x, void *arg);

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
    c->ctx = SSL_CTX_new(c->server ? TLS_server_method() : TLS_client_method());
    if (c->ctx == NULL) {
	Msg(err, errlen, "cannot create OpenSSL context");
	return 0;
    }
    if (!SetCiphers(c, o, &p, err, errlen)) {
	return 0;
    }
    SSL_CTX_set_min_proto_version(c->ctx, p & TLSB_TLS12 ? TLS1_2_VERSION
	    : TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(c->ctx, p & TLSB_TLS13 ? TLS1_3_VERSION
	    : TLS1_2_VERSION);
    SSL_CTX_set_options(c->ctx, SSL_OP_NO_RENEGOTIATION
	    | SSL_OP_IGNORE_UNEXPECTED_EOF);
    SSL_CTX_set_mode(c->ctx, SSL_MODE_NO_AUTO_CHAIN);	/* send what we got */
    SSL_CTX_set_verify_depth(c->ctx, MAXCHAIN - 2);
    /* Any trusted certificate anchors a chain, as with the other backends. */
    X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(c->ctx),
	    X509_V_FLAG_PARTIAL_CHAIN);
    SSL_CTX_set_cert_verify_callback(c->ctx, CertVerify, NULL);
    if (!LoadTrust(c, o, err, errlen)) {
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

    if (c->server) {
	SSL_CTX_set_tlsext_servername_callback(c->ctx, SniCb);
	SSL_CTX_set_dh_auto(c->ctx, 1);
	/* Without it, resuming a session that verified a client fails. */
	SSL_CTX_set_session_id_context(c->ctx, (const unsigned char *) "tlsb", 4);
	/* Tickets only, so that TicketCb sees every resumption. */
	SSL_CTX_set_session_cache_mode(c->ctx, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_session_ticket_cb(c->ctx, NULL, TicketCb, NULL);
    } else {
	SSL_CTX_set_session_cache_mode(c->ctx, SSL_SESS_CACHE_CLIENT
		| SSL_SESS_CACHE_NO_INTERNAL_STORE);
	SSL_CTX_sess_set_new_cb(c->ctx, NewSessCb);
    }
    return o->alpn_count <= 0 || SetAlpn(c, o, err, errlen);
}

tlsb_conf *
tlsb_conf_new(const tlsb_opts *o, char *err, size_t errlen)
{
    tlsb_conf *c = calloc(1, sizeof(*c));

    if (c == NULL) {
	Msg(err, errlen, "out of memory");
	return NULL;
    }
    c->server = o->server;
    c->request = o->request || o->require;
    c->require = o->require;
    if ((c->lock = CRYPTO_THREAD_lock_new()) == NULL) {
	Msg(err, errlen, "out of memory");
	free(c);
	return NULL;
    }
    if (!Configure(c, o, err, errlen)) {
	tlsb_conf_free(c);
	c = NULL;
    }
    ERR_clear_error();
    return c;
}

void
tlsb_conf_free(tlsb_conf *c)
{
    int i;

    if (c == NULL) {
	return;
    }
    SSL_CTX_free(c->ctx);
    for (i = 0; i < c->ncache; i++) {
	OPENSSL_free(c->cache[i].name);
	SSL_SESSION_free(c->cache[i].sess);
    }
    CRYPTO_THREAD_lock_free(c->lock);
    OPENSSL_free(c->leaf);
    free(c->alpn);
    free(c);
}

/*
 * Transport.
 */

static int
BioWrite(BIO *b, const char *buf, int len)
{
    tlsb_sess *s = BIO_get_data(b);

    s->io.send(s->io.ud, (const uint8_t *) buf, (size_t) len);
    return len;
}

static int
BioRead(BIO *b, char *buf, int len)
{
    tlsb_sess *s = BIO_get_data(b);
    long n = s->io.recv(s->io.ud, (uint8_t *) buf, (size_t) len);

    BIO_clear_retry_flags(b);
    if (n > 0) {
	return (int) n;
    }
    if (n == 0) {
	s->dry = 1;
	BIO_set_retry_read(b);
	return -1;
    }
    s->eof = 1;
    return 0;
}

static long
BioCtrl(BIO *b, int cmd, long num, void *ptr)
{
    (void) num; (void) ptr;
    switch (cmd) {
    case BIO_CTRL_FLUSH:	return 1;
    case BIO_CTRL_EOF:		return ((tlsb_sess *) BIO_get_data(b))->eof;
    }
    return 0;
}

/*
 * Verification.
 */

/* OpenSSL's wording, except where the other backends say it shorter. */
static const char *
VerifyStr(int e)
{
    switch (e) {
    case X509_V_ERR_HOSTNAME_MISMATCH:
    case X509_V_ERR_IP_ADDRESS_MISMATCH:	return "hostname mismatch";
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:	return "self-signed certificate";
    }
    return X509_verify_cert_error_string(e);
}

static tlsb_sess *
StoreSess(X509_STORE_CTX *x)
{
    return SSL_get_app_data((SSL *) X509_STORE_CTX_get_ex_data(x,
	    SSL_get_ex_data_X509_STORE_CTX_idx()));
}

/* Records the first error per depth and lets verification go on. */
static int
VerifyCb(int ok, X509_STORE_CTX *x)
{
    tlsb_sess *s = StoreSess(x);
    int d = X509_STORE_CTX_get_error_depth(x);

    if (!ok) {
	d = d < 0 ? 0 : d < MAXCHAIN ? d : MAXCHAIN - 1;
	if (s->vcode[d] == 0) {
	    s->vcode[d] = X509_STORE_CTX_get_error(x);
	}
    }
    return 1;
}

/* Whether the peer sent c (as opposed to it coming from our store). */
static int
Sent(STACK_OF(X509) *sent, X509 *c)
{
    int i;

    for (i = 0; i < sk_X509_num(sent); i++) {
	if (X509_cmp(sk_X509_value(sent, i), c) == 0) {
	    return 1;
	}
    }
    return 0;
}

#ifdef _WIN32
/*
 * Windows fetches most roots only on demand (see generic/winroot.c): when
 * the system store has no issuer for the peer chain, trust the root Windows
 * found, and verify with the intermediates it fetched added to what the peer
 * sent. Returns that larger untrusted set, or NULL.
 */
static void
WinAdd(void *ud, const uint8_t *der, size_t len, int root)
{
    X509 *c = len <= LONG_MAX ? d2i_X509(NULL, &der, (long) len) : NULL;

    if (c == NULL) {
	return;
    }
    if (root) {
	X509_STORE_add_cert(sysStore, c);
	X509_free(c);
    } else if (!sk_X509_push((STACK_OF(X509) *) ud, c)) {
	X509_free(c);
    }
}

static STACK_OF(X509) *
WinFetch(X509_STORE_CTX *x, int server)
{
    STACK_OF(X509) *sent = X509_STORE_CTX_get0_untrusted(x), *more = NULL;
    X509 *leaf = X509_STORE_CTX_get0_cert(x);
    X509_STORE_CTX *probe;
    unsigned char *der[MAXCHAIN];
    size_t len[MAXCHAIN];
    int e = 0, i, k, n = 0;

    if (X509_STORE_CTX_get0_store(x) != sysStore || leaf == NULL
	    || (probe = X509_STORE_CTX_new()) == NULL) {
	return NULL;
    }
    if (X509_STORE_CTX_init(probe, sysStore, leaf, sent)) {
	X509_STORE_CTX_set_flags(probe, X509_V_FLAG_PARTIAL_CHAIN);
	if (X509_verify_cert(probe) <= 0) {
	    e = X509_STORE_CTX_get_error(probe);
	}
    }
    X509_STORE_CTX_free(probe);
    if (e == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
	    || e == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
	    || e == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {
	for (i = -1; i < sk_X509_num(sent) && n < MAXCHAIN; i++) {
	    X509 *c = i < 0 ? leaf : sk_X509_value(sent, i);

	    der[n] = NULL;
	    if ((i < 0 || X509_cmp(c, leaf) != 0)
		    && (k = i2d_X509(c, &der[n])) > 0) {
		len[n++] = (size_t) k;
	    }
	}
	more = sent ? X509_chain_up_ref(sent) : sk_X509_new_null();
	if (more && tlsb_win_chain((const uint8_t *const *) der, len, n,
		server, WinAdd, more) == 0) {
	    sk_X509_pop_free(more, X509_free);
	    more = NULL;
	}
	for (i = 0; i < n; i++) {
	    OPENSSL_free(der[i]);
	}
    }
    ERR_clear_error();
    return more;
}
#endif

/*
 * Replaces X509_verify_cert, whose callback order doesn't follow the chain:
 * verifies, then reports the certificates the peer sent, highest depth
 * first. A bad certificate makes everything below it bad too.
 */
static int
CertVerify(X509_STORE_CTX *x, void *arg)
{
    tlsb_sess *s = StoreSess(x);
    STACK_OF(X509) *chain, *sent = X509_STORE_CTX_get0_untrusted(x);
    STACK_OF(X509) *more = NULL;
    const char *above = NULL, *err = NULL;
    int d, worst = 0, accept = 1;

    (void) arg;
    memset(s->vcode, 0, sizeof(s->vcode));
#ifdef _WIN32
    if ((more = WinFetch(x, s->conf->server)) != NULL) {
	X509_STORE_CTX_set0_untrusted(x, more);
    }
#endif
    X509_STORE_CTX_set_verify_cb(x, VerifyCb);
    X509_verify_cert(x);
    if ((chain = X509_STORE_CTX_get0_chain(x)) == NULL) {
	err = "no certificate chain";
	accept = 0;
    }
    for (d = sk_X509_num(chain) - 1; d >= 0 && accept; d--) {
	X509 *c = sk_X509_value(chain, d);
	int e = s->vcode[d < MAXCHAIN ? d : MAXCHAIN - 1], ok;

	worst = e ? e : worst;
	err = e ? VerifyStr(e) : above;
	if (!Sent(sent, c)) {
	    above = err;		/* our trust anchor */
	    continue;
	}
	ok = err == NULL;
	if (!ok) {
	    above = "issuer certificate not trusted";
	}
	if (s->io.verify) {
	    unsigned char *der = NULL;
	    int n = i2d_X509(c, &der);

	    accept = s->io.verify(s->io.ud, d, der, n > 0 ? (size_t) n : 0, ok,
		    err);
	    OPENSSL_free(der);
	} else {
	    accept = ok || !s->conf->require;
	}
    }
    if (more) {
	X509_STORE_CTX_set0_untrusted(x, sent);
	sk_X509_pop_free(more, X509_free);
    }
    if (accept) {
	return 1;
    }
    if (s->io.verify) {
	Msg(s->verr, sizeof(s->verr),
		"certificate rejected by validation callback");
    } else {
	Msg(s->verr, sizeof(s->verr), "certificate verify failed: %s", err);
    }
    X509_STORE_CTX_set_error(x, worst ? worst
	    : X509_V_ERR_APPLICATION_VERIFICATION);
    return 0;
}

/*
 * Sessions.
 */

static int
SetServerName(tlsb_sess *s, const char *name, char *err, size_t errlen)
{
    size_t n = strlen(name);

    if ((s->servername = malloc(n + 1)) == NULL) {
	Msg(err, errlen, "out of memory");
	return 0;
    }
    memcpy(s->servername, name, n + 1);
    /* IP literals: matched against IP SANs, and no SNI. */
    if (X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(s->ssl), name)) {
	s->ip = 1;
	return 1;
    }
    SSL_set_hostflags(s->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (!SSL_set1_host(s->ssl, name)
	    || !SSL_set_tlsext_host_name(s->ssl, name)) {
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
    BIO *b;

    if (s == NULL) {
	Msg(err, errlen, "out of memory");
	return NULL;
    }
    s->conf = c;
    s->io = *io;
    if ((s->ssl = SSL_new(c->ctx)) == NULL
	    || (b = BIO_new(bioMethod)) == NULL) {
	Msg(err, errlen, "cannot create OpenSSL session");
	goto fail;
    }
    BIO_set_data(b, s);
    BIO_set_init(b, 1);
    SSL_set_bio(s->ssl, b, b);
    SSL_set_app_data(s->ssl, s);
    if (c->server) {
	SSL_set_accept_state(s->ssl);
	SSL_set_verify(s->ssl, !c->request ? SSL_VERIFY_NONE : c->require
		? SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
		: SSL_VERIFY_PEER, NULL);
    } else {
	/* CertVerify decides, require or not. */
	SSL_set_connect_state(s->ssl);
	SSL_set_verify(s->ssl, SSL_VERIFY_PEER, NULL);
	if (servername && !SetServerName(s, servername, err, errlen)) {
	    goto fail;
	}
	/* No resumption past a verify callback: it must see each handshake. */
	s->cache = servername && io->verify == NULL;
	if (s->cache) {
	    ResumeCached(s);
	}
    }
    ERR_clear_error();
    return s;

  fail:
    ERR_clear_error();
    tlsb_sess_free(s);
    return NULL;
}

void
tlsb_sess_free(tlsb_sess *s)
{
    int i;

    if (s == NULL) {
	return;
    }
    SSL_free(s->ssl);
    for (i = 0; i < MAXCHAIN; i++) {
	OPENSSL_free(s->der[i]);
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
    case 49:	return "access denied";
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
 * Records the reason of a failed OpenSSL call; returns TLSB_ERROR. what is
 * empty for the handshake, which the channel layer names itself.
 */
static int
Fail(tlsb_sess *s, const char *what, int e)
{
    const char *sep = *what ? ": " : "";
    unsigned long code = ERR_peek_error();
    int reason = ERR_GET_REASON(code);
    const char *alert = NULL;

    if (ERR_GET_LIB(code) == ERR_LIB_SSL && reason > SSL_AD_REASON_OFFSET) {
	alert = AlertStr(reason - SSL_AD_REASON_OFFSET);
    }
    if (s->verr[0]) {
	Msg(s->err, sizeof(s->err), "%s", s->verr);
    } else if (s->eof) {
	Msg(s->err, sizeof(s->err), s->done ? "connection closed"
		: "connection closed during handshake");
    } else if (alert) {
	Msg(s->err, sizeof(s->err), "peer sent alert: %s", alert);
    } else if (code) {
	const char *rs = ERR_reason_error_string(code);
	char buf[128];

	if (rs == NULL) {
	    ERR_error_string_n(code, buf, sizeof(buf));
	}
	Msg(s->err, sizeof(s->err), "%s%s%s", what, sep, rs ? rs : buf);
    } else {
	Msg(s->err, sizeof(s->err), "%s%s%s", what, sep,
		e == SSL_ERROR_SYSCALL ? "I/O error" : "internal error");
    }
    ERR_clear_error();
    return TLSB_ERROR;
}

/*
 * Whether to call OpenSSL again after error e: WANT_READ is reported only
 * once recv has run dry in this call. tries bounds the loop.
 */
static int
Again(tlsb_sess *s, int e, int *tries)
{
    return e == SSL_ERROR_WANT_READ && !s->dry && !s->eof && (*tries)++ < 16;
}

int
tlsb_handshake(tlsb_sess *s)
{
    int r, e, n = 0;

    if (s->done) {
	return TLSB_OK;
    }
    s->dry = 0;
    do {
	ERR_clear_error();
	r = SSL_do_handshake(s->ssl);
	e = r == 1 ? 0 : SSL_get_error(s->ssl, r);
    } while (Again(s, e, &n));
    if (r == 1) {
	s->done = 1;
	return TLSB_OK;
    }
    if (e == SSL_ERROR_WANT_READ && !s->eof) {
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
	ERR_clear_error();
	r = SSL_read(s->ssl, buf, len > INT_MAX ? INT_MAX : (int) len);
	e = r > 0 ? 0 : SSL_get_error(s->ssl, r);
    } while (Again(s, e, &n));
    if (r > 0) {
	return r;
    }
    if (e == SSL_ERROR_WANT_READ && !s->eof) {
	return TLSB_WANT_READ;
    }
    if (e == SSL_ERROR_ZERO_RETURN || s->eof) {
	ERR_clear_error();
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
    ERR_clear_error();
    while (done < len) {
	int n = len - done > INT_MAX ? INT_MAX : (int) (len - done);
	int r = SSL_write(s->ssl, buf + done, n);

	if (r <= 0) {
	    return Fail(s, "write failed", SSL_get_error(s->ssl, r));
	}
	done += (size_t) r;
    }
    return (long) len;
}

int
tlsb_pending(tlsb_sess *s)
{
    return SSL_pending(s->ssl) > 0 || SSL_has_pending(s->ssl);
}

void
tlsb_close_notify(tlsb_sess *s)
{
    if (s->done) {
	SSL_shutdown(s->ssl);
	ERR_clear_error();
    }
}

int
tlsb_info_get(tlsb_sess *s, tlsb_info *info)
{
    const SSL_CIPHER *c;
    const unsigned char *alpn;
    unsigned n;

    if (!s->done) {
	return TLSB_ERROR;
    }
    memset(info, 0, sizeof(*info));
    switch (SSL_version(s->ssl)) {
    case TLS1_2_VERSION:	info->protocol = "TLS1.2"; break;
    case TLS1_3_VERSION:	info->protocol = "TLS1.3"; break;
    default:			info->protocol = "unknown";
    }
    if ((c = SSL_get_current_cipher(s->ssl)) != NULL) {
	info->cipher = SSL_CIPHER_standard_name(c);
	info->cipher_bits = SSL_CIPHER_get_bits(c, NULL);
    }
    SSL_get0_alpn_selected(s->ssl, &alpn, &n);
    if (alpn && n) {
	info->alpn = alpn;
	info->alpn_len = n;
    }
    info->servername = s->conf->server ? (s->sni[0] ? s->sni : NULL)
	    : s->ip ? NULL : s->servername;
    info->resumed = SSL_session_reused(s->ssl) > 0;
    return TLSB_OK;
}

int
tlsb_peer_cert(tlsb_sess *s, int depth, const uint8_t **der, size_t *len)
{
    STACK_OF(X509) *chain;
    X509 *c = NULL;
    unsigned char *p = NULL;
    int n;

    if (!s->done || depth < 0 || depth >= MAXCHAIN) {
	return TLSB_ERROR;
    }
    if (s->der[depth]) {		/* kept until the session goes */
	*der = s->der[depth];
	*len = s->derlen[depth];
	return TLSB_OK;
    }
    if (depth == 0) {
	c = SSL_get0_peer_certificate(s->ssl);
    } else if ((chain = SSL_get_peer_cert_chain(s->ssl)) != NULL) {
	int i = depth - s->conf->server;	/* a server's lacks the leaf */

	c = i < sk_X509_num(chain) ? sk_X509_value(chain, i) : NULL;
    }
    if (c == NULL || (n = i2d_X509(c, &p)) <= 0) {
	return TLSB_ERROR;
    }
    *der = s->der[depth] = p;
    *len = s->derlen[depth] = (size_t) n;
    return TLSB_OK;
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
    if (s->done && SSL_export_keying_material(s->ssl, out, out_len, label,
	    label_len, use_ctx ? ctx : NULL, use_ctx ? ctx_len : 0, use_ctx)
	    == 1) {
	return TLSB_OK;
    }
    ERR_clear_error();
    Msg(s->err, sizeof(s->err), "keying material export failed");
    return TLSB_ERROR;
}

/*
 * Crypto helpers.
 */

int
tlsb_random(uint8_t *buf, size_t len)
{
    while (len > 0) {
	int n = len > INT_MAX ? INT_MAX : (int) len;

	if (RAND_bytes(buf, n) != 1) {
	    return TLSB_ERROR;
	}
	buf += n, len -= (size_t) n;
    }
    return TLSB_OK;
}

static const EVP_MD *
Md(int alg)
{
    switch (alg) {
    case TLSB_SHA1:	return EVP_sha1();
    case TLSB_SHA256:	return EVP_sha256();
    case TLSB_SHA512:	return EVP_sha512();
    }
    return NULL;
}

int
tlsb_digest(int alg, const uint8_t *data, size_t len, uint8_t *out)
{
    const EVP_MD *md = Md(alg);

    return md && EVP_Digest(data, len, out, NULL, md, NULL) == 1
	    ? TLSB_OK : TLSB_ERROR;
}

int
tlsb_pbkdf2(int alg, const uint8_t *pw, size_t pw_len, const uint8_t *salt,
	size_t salt_len, uint32_t iterations, uint8_t *out, size_t out_len)
{
    const EVP_MD *md = Md(alg);

    if (md == NULL || pw_len > INT_MAX || salt_len > INT_MAX
	    || out_len > INT_MAX || iterations == 0 || iterations > INT_MAX) {
	return TLSB_ERROR;
    }
    return PKCS5_PBKDF2_HMAC((const char *) pw, (int) pw_len, salt,
	    (int) salt_len, (int) iterations, md, (int) out_len, out) == 1
	    ? TLSB_OK : TLSB_ERROR;
}

static int
Gcm(int enc, const uint8_t key[32], const uint8_t nonce[12],
	const uint8_t *in, size_t len, uint8_t *out, uint8_t *tag)
{
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    int n, ok = x && EVP_CipherInit_ex(x, EVP_aes_256_gcm(), NULL, key,
	    nonce, enc) == 1;

    while (ok && len > 0) {
	int k = len > 0x40000000 ? 0x40000000 : (int) len;	/* int sized */

	ok = EVP_CipherUpdate(x, out, &n, in, k) == 1;
	in += k, out += n, len -= (size_t) k;
    }
    ok = ok && (enc || EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_SET_TAG, 16, tag))
	    && EVP_CipherFinal_ex(x, out, &n) == 1
	    && (!enc || EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_GET_TAG, 16, tag));
    EVP_CIPHER_CTX_free(x);
    return ok ? TLSB_OK : TLSB_ERROR;
}

int
tlsb_aes256gcm_seal(const uint8_t key[32], const uint8_t nonce[12],
	const uint8_t *in, size_t len, uint8_t *out)
{
    return Gcm(1, key, nonce, in, len, out, out + len);
}

int
tlsb_aes256gcm_open(const uint8_t key[32], const uint8_t nonce[12],
	const uint8_t *in, size_t len, uint8_t *out)
{
    if (len < 16) {
	return TLSB_ERROR;
    }
    if (Gcm(0, key, nonce, in, len - 16, out, (uint8_t *) in + len - 16)
	    != TLSB_OK) {
	memset(out, 0, len - 16);	/* no unauthenticated plaintext */
	return TLSB_ERROR;
    }
    return TLSB_OK;
}
