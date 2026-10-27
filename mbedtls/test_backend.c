/*
 * test_backend.c --
 *
 *	Standalone tlsb harness for the Mbed TLS backend: client and server
 *	sessions in one process, joined by memory pipes.
 *	Usage: test_backend certdir [pkidir] [-nonet] [-host name]...
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <mbedtls/build_info.h>

#include "tlsb.h"

static _Atomic int fails, checks;
static const char *certdir, *pkidir;

/* What a trimmed Mbed TLS configuration may lack. */
#if defined(MBEDTLS_SSL_ALPN) && defined(MBEDTLS_SSL_KEYING_MATERIAL_EXPORT) \
	&& defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
static const int full = 1;
#else
static const int full = 0;
#endif

#define FCHECK(c, ...) CHECK(!full || (c), __VA_ARGS__)
#define CHECK(c, ...) do { checks++; if (!(c)) { fails++; \
	printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); \
	printf("\n"); } } while (0)

/*
 * Memory transport.
 */

typedef struct Pipe {
    uint8_t *buf;
    size_t len, off, cap;
    int closed;
    int dry;			/* times recv found it empty */
} Pipe;

typedef struct VLog {
    int n, depth[8], ok[8];
    char err[8][96];
} VLog;

typedef struct End {
    Pipe *in, *out;
    int mode;			/* verify: 0 pass verdict, 1 reject, 2 accept */
    VLog log;
} End;

static long
PipeRecv(void *ud, uint8_t *buf, size_t len)
{
    Pipe *p = ((End *) ud)->in;
    size_t n = p->len - p->off;

    if (n == 0) {
	p->dry += !p->closed;
	return p->closed ? -1 : 0;
    }
    if (n > len) {
	n = len;
    }
    memcpy(buf, p->buf + p->off, n);
    p->off += n;
    return (long) n;
}

static void
PipeSend(void *ud, const uint8_t *buf, size_t len)
{
    Pipe *p = ((End *) ud)->out;

    if (p->len + len > p->cap) {
	p->cap = (p->len + len) * 2;
	p->buf = realloc(p->buf, p->cap);
    }
    memcpy(p->buf + p->len, buf, len);
    p->len += len;
}

static int
Verify(void *ud, int depth, const uint8_t *der, size_t len, int ok,
	const char *err)
{
    End *e = ud;
    VLog *l = &e->log;

    (void) der;
    if (l->n < 8) {
	l->depth[l->n] = depth;
	l->ok[l->n] = ok;
	snprintf(l->err[l->n], sizeof(l->err[0]), "%s", err ? err : "");
	l->n++;
    }
    CHECK(der != NULL && len > 0, "verify callback without DER");
    return e->mode == 0 ? ok : e->mode == 2;
}

/*
 * Fixtures.
 */

typedef struct Buf {
    uint8_t *p;
    size_t n;
} Buf;

static Buf
Load(const char *name)
{
    char path[512];
    Buf b = {NULL, 0};
    FILE *f;
    long n;

    snprintf(path, sizeof(path), "%s/%s", certdir, name);
    if ((f = fopen(path, "rb")) == NULL) {
	printf("cannot open %s\n", path);
	exit(2);
    }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    rewind(f);
    b.p = malloc((size_t) n + 1);
    b.n = fread(b.p, 1, (size_t) n, f);
    b.p[b.n] = 0;
    fclose(f);
    return b;
}

static Buf
Cat(Buf a, Buf b)
{
    Buf c = {malloc(a.n + b.n + 1), a.n + b.n};

    memcpy(c.p, a.p, a.n);
    memcpy(c.p + a.n, b.p, b.n);
    c.p[c.n] = 0;
    return c;
}

static Buf ca, srvCert, srvKey, srvKeyEnc, srvCertDer, srvKeyDer, cliCert,
	cliKey, ssCert, ssKey, srvChain;

static tlsb_opts
Server(void)
{
    tlsb_opts o;

    memset(&o, 0, sizeof(o));
    o.server = 1;
    o.cert = srvCert.p, o.cert_len = srvCert.n;
    o.key = srvKey.p, o.key_len = srvKey.n;
    return o;
}

static tlsb_opts
Client(void)
{
    tlsb_opts o;

    memset(&o, 0, sizeof(o));
    o.require = 1;
    o.ca = ca.p, o.ca_len = ca.n;
    return o;
}

typedef struct Pair {
    Pipe c2s, s2c;
    End ce, se;
    tlsb_conf *cc, *sc;
    tlsb_sess *c, *s;
    int cr, sr;			/* handshake results */
    int own;			/* confs are ours to free */
} Pair;

static int
Attach(Pair *p, tlsb_conf *cc, tlsb_conf *sc, const char *name,
	int cverify, int sverify)
{
    char err[256];
    tlsb_io cio, sio;

    if (!p->own) {
	memset(p, 0, sizeof(*p));
    }
    p->ce.in = &p->s2c, p->ce.out = &p->c2s;
    p->se.in = &p->c2s, p->se.out = &p->s2c;
    p->cc = cc, p->sc = sc;
    if (!cc || !sc) {
	return 0;
    }
    cio = (tlsb_io) {&p->ce, PipeRecv, PipeSend, cverify ? Verify : NULL};
    sio = (tlsb_io) {&p->se, PipeRecv, PipeSend, sverify ? Verify : NULL};
    p->c = tlsb_sess_new(p->cc, name, &cio, err, sizeof(err));
    CHECK(p->c, "client session: %s", err);
    p->s = tlsb_sess_new(p->sc, NULL, &sio, err, sizeof(err));
    CHECK(p->s, "server session: %s", err);
    return p->c && p->s;
}

static int
Setup(Pair *p, const tlsb_opts *co, const tlsb_opts *so, const char *name,
	int cverify, int sverify)
{
    char err[256];
    tlsb_conf *cc, *sc;

    memset(p, 0, sizeof(*p));
    p->own = 1;
    cc = tlsb_conf_new(co, err, sizeof(err));
    CHECK(cc, "client conf: %s", err);
    sc = tlsb_conf_new(so, err, sizeof(err));
    CHECK(sc, "server conf: %s", err);
    return Attach(p, cc, sc, name, cverify, sverify);
}

/* Runs both handshakes; returns 1 if both completed. */
static int
Shake(Pair *p)
{
    int i;

    p->cr = p->sr = TLSB_WANT_READ;
    for (i = 0; i < 20; i++) {
	if (p->cr == TLSB_WANT_READ) p->cr = tlsb_handshake(p->c);
	if (p->sr == TLSB_WANT_READ) p->sr = tlsb_handshake(p->s);
	if (p->cr != TLSB_WANT_READ && p->sr != TLSB_WANT_READ) break;
	if (p->cr == TLSB_ERROR) p->c2s.closed = 1;
	if (p->sr == TLSB_ERROR) p->s2c.closed = 1;
    }
    return p->cr == TLSB_OK && p->sr == TLSB_OK;
}

static void
Teardown(Pair *p)
{
    tlsb_sess_free(p->c);
    tlsb_sess_free(p->s);
    if (p->own) {
	tlsb_conf_free(p->cc);
	tlsb_conf_free(p->sc);
    }
    free(p->c2s.buf);
    free(p->s2c.buf);
}

static const char *
Err(tlsb_sess *s, int r)
{
    return r == TLSB_ERROR ? tlsb_errmsg(s) : "-";
}

/* Expects the handshake to fail with msg in the error of side c or s. */
static void
ExpectFail(Pair *p, const char *msg, int line)
{
    int ok = Shake(p);
    const char *ce = Err(p->c, p->cr), *se = Err(p->s, p->sr);

    CHECK(!ok && (strstr(ce, msg) || strstr(se, msg)),
	    "line %d: expected \"%s\", client: %s, server: %s", line, msg, ce, se);
}

/* Moves len bytes from a to b; returns 1 on success. */
static int
Transfer(tlsb_sess *a, tlsb_sess *b, size_t len)
{
    uint8_t *src = malloc(len), *dst = malloc(len);
    size_t got = 0;
    int ok;

    tlsb_random(src, len);
    CHECK(tlsb_write(a, src, len) == (long) len, "write %zu", len);
    while (got < len) {
	long n = tlsb_read(b, dst + got, len - got);

	if (n <= 0) {
	    break;
	}
	got += (size_t) n;
    }
    ok = got == len && memcmp(src, dst, len) == 0;
    free(src);
    free(dst);
    return ok;
}

static int
SameDer(tlsb_sess *s, int depth, const uint8_t *der, size_t len)
{
    const uint8_t *d;
    size_t n;

    return tlsb_peer_cert(s, depth, &d, &n) == TLSB_OK && n == len
	    && memcmp(d, der, n) == 0;
}

/*
 * Tests.
 */

typedef struct Names {
    int n, tls13, ecdhe;
} Names;

static void
CipherCb(void *ud, const char *name)
{
    Names *c = ud;

    c->n++;
    c->tls13 += strcmp(name, "TLS_AES_128_GCM_SHA256") == 0;
    c->ecdhe += strcmp(name, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256") == 0;
}

static void
TestLibrary(void)
{
    Names all = {0, 0, 0}, t12 = {0, 0, 0};

    printf("version: %s\n", tlsb_version());
    CHECK(strncmp(tlsb_version(), "Mbed TLS ", 9) == 0, "version");
    CHECK(tlsb_protocols() == (TLSB_TLS12 | TLSB_TLS13), "protocols %u",
	    tlsb_protocols());
    tlsb_ciphers(TLSB_TLS12 | TLSB_TLS13, CipherCb, &all);
    tlsb_ciphers(TLSB_TLS12, CipherCb, &t12);
    printf("ciphers: %d (%d TLS 1.2)\n", all.n, t12.n);
    CHECK(all.tls13 == 1 && all.ecdhe == 1, "cipher list");
    CHECK(t12.tls13 == 0 && t12.ecdhe == 1 && t12.n < all.n, "TLS 1.2 list");
}

static void
TestBasic(unsigned proto)
{
    static const char *salpn[] = {"h2", "http/1.1"}, *calpn[] = {"http/1.1"};
    tlsb_opts so = Server(), co = Client();
    tlsb_info ci, si;
    uint8_t k1[48], k2[48], k3[48];
    const uint8_t *d;
    size_t n;
    uint8_t buf[16];
    Pair p;

    so.alpn = salpn, so.alpn_count = 2;
    co.alpn = calpn, co.alpn_count = 1;
    co.protocols = proto;
    if (!Setup(&p, &co, &so, "localhost", 0, 0)) {
	return;
    }
    CHECK(tlsb_info_get(p.c, &ci) == TLSB_ERROR, "info before handshake");
    CHECK(Shake(&p), "handshake: %s / %s", Err(p.c, p.cr), Err(p.s, p.sr));
    CHECK(tlsb_info_get(p.c, &ci) == TLSB_OK, "client info");
    CHECK(tlsb_info_get(p.s, &si) == TLSB_OK, "server info");
    printf("%s %s %d bits, alpn %.*s, sni %s\n", ci.protocol, ci.cipher,
	    ci.cipher_bits, (int) ci.alpn_len, ci.alpn, si.servername);
    CHECK(strcmp(ci.protocol, proto == TLSB_TLS12 ? "TLS1.2" : "TLS1.3") == 0
	    && strcmp(si.protocol, ci.protocol) == 0, "protocol %s", ci.protocol);
    CHECK(ci.cipher && strncmp(ci.cipher, "TLS_", 4) == 0
	    && strcmp(ci.cipher, si.cipher) == 0, "cipher");
    CHECK(ci.cipher_bits == 128 || ci.cipher_bits == 256, "bits");
    FCHECK(ci.alpn_len == 8 && memcmp(ci.alpn, "http/1.1", 8) == 0, "client alpn");
    FCHECK(si.alpn_len == 8 && memcmp(si.alpn, "http/1.1", 8) == 0, "server alpn");
    CHECK(si.servername && strcmp(si.servername, "localhost") == 0, "sni");
    CHECK(ci.servername && strcmp(ci.servername, "localhost") == 0, "sni sent");
    CHECK(!ci.resumed && !si.resumed, "resumed");

    FCHECK(SameDer(p.c, 0, srvCertDer.p, srvCertDer.n), "peer cert depth 0");
    CHECK(tlsb_peer_cert(p.c, 1, &d, &n) == TLSB_ERROR, "peer cert depth 1");
    CHECK(tlsb_peer_cert(p.s, 0, &d, &n) == TLSB_ERROR, "no client cert");
    CHECK(tlsb_local_cert(p.s, &d, &n) == TLSB_OK && n == srvCertDer.n
	    && memcmp(d, srvCertDer.p, n) == 0, "local cert");
    CHECK(tlsb_local_cert(p.c, &d, &n) == TLSB_ERROR, "no local cert");

    FCHECK(tlsb_export(p.c, "EXPERIMENTAL x", 14, (const uint8_t *) "ctx", 3,
	    1, k1, 48) == TLSB_OK, "export client");
    FCHECK(tlsb_export(p.s, "EXPERIMENTAL x", 14, (const uint8_t *) "ctx", 3,
	    1, k2, 48) == TLSB_OK, "export server");
    FCHECK(memcmp(k1, k2, 48) == 0, "export equal");
    FCHECK(tlsb_export(p.s, "EXPERIMENTAL x", 14, NULL, 0, 0, k3, 48)
	    == TLSB_OK && memcmp(k1, k3, 48) != 0, "export without context");

    CHECK(tlsb_read(p.s, buf, sizeof(buf)) == TLSB_WANT_READ, "want read");
    CHECK(Transfer(p.c, p.s, 100000), "client -> server 100000");
    CHECK(Transfer(p.s, p.c, 70000), "server -> client 70000");
    CHECK(Transfer(p.c, p.s, 1), "client -> server 1");
    CHECK(!tlsb_pending(p.s), "nothing pending");

    /* Rest of a record must show up as pending. */
    tlsb_write(p.c, (const uint8_t *) "helloworld", 10);
    CHECK(tlsb_read(p.s, buf, 5) == 5 && tlsb_pending(p.s), "pending");
    CHECK(tlsb_read(p.s, buf, 5) == 5 && memcmp(buf, "world", 5) == 0,
	    "pending data");

    tlsb_close_notify(p.c);
    CHECK(tlsb_read(p.s, buf, sizeof(buf)) == 0, "close_notify -> EOF");
    p.s2c.closed = 1;
    CHECK(tlsb_read(p.c, buf, sizeof(buf)) == 0, "transport EOF -> EOF");
    Teardown(&p);
}

static void
TestVerify(void)
{
    tlsb_opts so = Server(), co = Client();
    const uint8_t *d;
    size_t n;
    Pair p;

    /* IP literal against the IP SAN, and no SNI for it. */
    if (Setup(&p, &co, &so, "127.0.0.1", 0, 0)) {
	tlsb_info si;

	CHECK(Shake(&p), "ip: %s", Err(p.c, p.cr));
	CHECK(tlsb_info_get(p.s, &si) == TLSB_OK && si.servername == NULL,
		"no SNI for an IP literal");
    }
    Teardown(&p);
    if (Setup(&p, &co, &so, "::1", 0, 0)) {
	ExpectFail(&p, "hostname mismatch", __LINE__);
    }
    Teardown(&p);

    if (Setup(&p, &co, &so, "127.0.0.2", 0, 0)) {
	ExpectFail(&p, "hostname mismatch", __LINE__);
    }
    Teardown(&p);

    if (Setup(&p, &co, &so, "example.com", 0, 0)) {
	ExpectFail(&p, "certificate verify failed: hostname mismatch", __LINE__);
    }
    Teardown(&p);

    /* Untrusted self-signed server. */
    so.cert = ssCert.p, so.cert_len = ssCert.n;
    so.key = ssKey.p, so.key_len = ssKey.n;
    if (Setup(&p, &co, &so, "localhost", 0, 0)) {
	ExpectFail(&p, "certificate verify failed: self-signed certificate",
		__LINE__);
	printf("untrusted: %s\n", tlsb_errmsg(p.c));
    }
    Teardown(&p);

    /* require=0 accepts it, and still reports the real verdict. */
    co.require = 0;
    if (Setup(&p, &co, &so, "localhost", 0, 0)) {
	CHECK(Shake(&p), "require 0: %s", Err(p.c, p.cr));
    }
    Teardown(&p);
    if (Setup(&p, &co, &so, "example.com", 1, 0)) {
	p.ce.mode = 2;
	CHECK(Shake(&p), "require 0 + callback: %s", Err(p.c, p.cr));
	CHECK(p.ce.log.n == 1 && p.ce.log.depth[0] == 0 && !p.ce.log.ok[0]
		&& p.ce.log.err[0][0], "require 0 verdict");
	printf("require 0 callback: depth %d ok %d err %s\n",
		p.ce.log.depth[0], p.ce.log.ok[0], p.ce.log.err[0]);
    }
    Teardown(&p);
    co.require = 1;

    /* Chain of two: callback runs depth 1 then 0. */
    so = Server();
    so.cert = srvChain.p, so.cert_len = srvChain.n;
    if (!full) {
	return;		/* the callback only runs on errors there */
    }
    if (Setup(&p, &co, &so, "localhost", 1, 0)) {
	CHECK(Shake(&p), "chain: %s", Err(p.c, p.cr));
	CHECK(p.ce.log.n == 2 && p.ce.log.depth[0] == 1 && p.ce.log.depth[1] == 0
		&& p.ce.log.ok[0] && p.ce.log.ok[1], "callback order: n=%d",
		p.ce.log.n);
	CHECK(SameDer(p.c, 0, srvCertDer.p, srvCertDer.n), "chain depth 0");
	CHECK(tlsb_peer_cert(p.c, 1, &d, &n) == TLSB_OK && n > 0, "depth 1");
	CHECK(tlsb_peer_cert(p.c, 2, &d, &n) == TLSB_ERROR, "depth 2");
    }
    Teardown(&p);

    /* Callback rejecting a valid chain. */
    if (Setup(&p, &co, &so, "localhost", 1, 0)) {
	p.ce.mode = 1;
	ExpectFail(&p, "certificate rejected by validation callback", __LINE__);
	CHECK(p.ce.log.n == 1 && p.ce.log.depth[0] == 1, "rejected at depth 1");
    }
    Teardown(&p);

    /* Callback accepting an invalid one, require=1. */
    if (Setup(&p, &co, &so, "example.com", 1, 0)) {
	p.ce.mode = 2;
	CHECK(Shake(&p), "accept invalid: %s", Err(p.c, p.cr));
	CHECK(p.ce.log.n == 2 && p.ce.log.ok[0] && !p.ce.log.ok[1]
		&& strcmp(p.ce.log.err[1], "hostname mismatch") == 0,
		"accept invalid log");
    }
    Teardown(&p);

    /* Untrusted chain accepted by callback. */
    co.ca = ssCert.p, co.ca_len = ssCert.n;
    if (Setup(&p, &co, &so, "localhost", 1, 0)) {
	p.ce.mode = 2;
	CHECK(Shake(&p), "accept untrusted: %s", Err(p.c, p.cr));
	CHECK(p.ce.log.n == 2 && !p.ce.log.ok[1], "untrusted chain verdict");
	printf("untrusted chain: [%s] [%s]\n", p.ce.log.err[0], p.ce.log.err[1]);
    }
    Teardown(&p);
    /* ... and the same conf afterwards still rejects it. */
    if (Setup(&p, &co, &so, "localhost", 0, 0)) {
	ExpectFail(&p, "certificate verify failed", __LINE__);
    }
    Teardown(&p);
}

static void
TestMutual(void)
{
    tlsb_opts so = Server(), co = Client();
    const uint8_t *d;
    size_t n;
    Pair p;

    so.request = so.require = 1;
    so.ca = ca.p, so.ca_len = ca.n;
    co.cert = cliCert.p, co.cert_len = cliCert.n;
    co.key = cliKey.p, co.key_len = cliKey.n;
    for (unsigned proto = TLSB_TLS12; proto <= TLSB_TLS13; proto <<= 1) {
	co.protocols = proto;
	if (Setup(&p, &co, &so, "localhost", 0, 1)) {
	    CHECK(Shake(&p), "mtls: %s / %s", Err(p.c, p.cr), Err(p.s, p.sr));
	    FCHECK(tlsb_local_cert(p.c, &d, &n) == TLSB_OK
		    && SameDer(p.s, 0, d, n), "client cert on server");
	    FCHECK(p.se.log.n == 1 && p.se.log.ok[0], "server callback");
	    CHECK(Transfer(p.c, p.s, 1000) && Transfer(p.s, p.c, 1000), "data");
	}
	Teardown(&p);
    }
    co.protocols = 0;

    /* No client certificate. */
    co.cert = co.key = NULL;
    if (Setup(&p, &co, &so, "localhost", 0, 0)) {
	ExpectFail(&p, "", __LINE__);
	printf("no client cert: server: %s; client: %s\n", Err(p.s, p.sr),
		Err(p.c, p.cr));
    }
    Teardown(&p);
    so.require = 0;
    if (Setup(&p, &co, &so, "localhost", 0, 0)) {
	CHECK(Shake(&p), "request only: %s", Err(p.s, p.sr));
	CHECK(tlsb_peer_cert(p.s, 0, &d, &n) == TLSB_ERROR, "no peer cert");
    }
    Teardown(&p);

    /* Untrusted client certificate: fine when only requested. */
    co.cert = ssCert.p, co.cert_len = ssCert.n;
    co.key = ssKey.p, co.key_len = ssKey.n;
    if (Setup(&p, &co, &so, "localhost", 0, 0)) {
	CHECK(Shake(&p), "request, untrusted: %s", Err(p.s, p.sr));
    }
    Teardown(&p);
    so.require = 1;
    if (Setup(&p, &co, &so, "localhost", 0, 0)) {
	ExpectFail(&p, "certificate verify failed", __LINE__);
    }
    Teardown(&p);

    /* Neither request nor require: no CertificateRequest. */
    so.request = so.require = 0;
    co.cert = cliCert.p, co.cert_len = cliCert.n;
    co.key = cliKey.p, co.key_len = cliKey.n;
    if (Setup(&p, &co, &so, "localhost", 0, 0)) {
	CHECK(Shake(&p), "no request: %s", Err(p.s, p.sr));
	CHECK(tlsb_peer_cert(p.s, 0, &d, &n) == TLSB_ERROR, "cert not sent");
    }
    Teardown(&p);
}

static void
TestConf(void)
{
    tlsb_opts so = Server(), co = Client();
    char err[256];
    tlsb_conf *c;
    tlsb_info ci;
    const uint8_t *d;
    size_t n;
    Pair p;

    /* Encrypted key. */
    so.key = srvKeyEnc.p, so.key_len = srvKeyEnc.n, so.password = "secret";
    if (full && Setup(&p, &co, &so, "localhost", 0, 0)) {
	CHECK(Shake(&p), "encrypted key: %s", Err(p.s, p.sr));
    }
    Teardown(&p);
    so.password = "wrong";
    c = tlsb_conf_new(&so, err, sizeof(err));
    CHECK(!c && strstr(err, "wrong password"), "wrong password: %s", err);
    tlsb_conf_free(c);
    so.password = NULL;
    c = tlsb_conf_new(&so, err, sizeof(err));
    CHECK(!c && strstr(err, "password"), "no password: %s", err);
    tlsb_conf_free(c);

    /* DER certificate and key. */
    so = Server();
    so.cert = srvCertDer.p, so.cert_len = srvCertDer.n;
    so.key = srvKeyDer.p, so.key_len = srvKeyDer.n;
    if (Setup(&p, &co, &so, "localhost", 0, 0)) {
	CHECK(Shake(&p), "DER: %s", Err(p.s, p.sr));
	CHECK(tlsb_local_cert(p.s, &d, &n) == TLSB_OK && n == srvCertDer.n
		&& memcmp(d, srvCertDer.p, n) == 0, "DER local cert");
    }
    Teardown(&p);

    /* Bad inputs. */
    so = Server();
    so.key = cliKey.p, so.key_len = cliKey.n;
    c = tlsb_conf_new(&so, err, sizeof(err));
    FCHECK(!c && strcmp(err, "private key does not match certificate") == 0,
	    "mismatch: %s", err);
    tlsb_conf_free(c);
    so = Server();
    so.cert = (const uint8_t *) "garbage", so.cert_len = 7;
    c = tlsb_conf_new(&so, err, sizeof(err));
    CHECK(!c && strcmp(err, "cannot parse certificate") == 0, "garbage: %s", err);
    tlsb_conf_free(c);
    so = Server();
    so.ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256 FOO";
    c = tlsb_conf_new(&so, err, sizeof(err));
    CHECK(!c && strcmp(err, "unknown cipher: FOO") == 0, "cipher: %s", err);
    tlsb_conf_free(c);

    /* Cipher selection by OpenSSL and IANA names, any case. */
    so = Server();
    co.ciphers = "ecdhe-ecdsa-aes256-gcm-sha384,ECDHE-ECDSA-AES128-GCM-SHA256";
    co.protocols = TLSB_TLS12;
    if (Setup(&p, &co, &so, "localhost", 0, 0)) {
	CHECK(Shake(&p) && tlsb_info_get(p.c, &ci) == TLSB_OK
		&& strcmp(ci.cipher, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
		== 0 && ci.cipher_bits == 256, "TLS 1.2 cipher");
    }
    Teardown(&p);
    co.ciphersuites = "tls_chacha20_poly1305_sha256";
    co.protocols = 0;
    if (Setup(&p, &co, &so, "localhost", 0, 0)) {
	CHECK(Shake(&p) && tlsb_info_get(p.c, &ci) == TLSB_OK
		&& strcmp(ci.cipher, "TLS_CHACHA20_POLY1305_SHA256") == 0
		&& ci.cipher_bits == 256, "TLS 1.3 cipher");
    }
    Teardown(&p);
    co.ciphersuites = NULL;
    co.ciphers = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
    co.protocols = TLSB_TLS12;
    if (Setup(&p, &co, &so, "localhost", 0, 0)) {
	CHECK(Shake(&p) && tlsb_info_get(p.c, &ci) == TLSB_OK
		&& strcmp(ci.cipher, co.ciphers) == 0, "IANA TLS 1.2 cipher");
    }
    Teardown(&p);

    /* Version mismatch. */
    co = Client();
    co.protocols = TLSB_TLS12;
    so.protocols = TLSB_TLS13;
    if (Setup(&p, &co, &so, "localhost", 0, 0)) {
	ExpectFail(&p, "protocol", __LINE__);
	printf("version mismatch: %s / %s\n", Err(p.c, p.cr), Err(p.s, p.sr));
    }
    Teardown(&p);

    /* Peer closing mid-handshake. */
    so.protocols = 0;
    if (Setup(&p, &co, &so, "localhost", 0, 0)) {
	CHECK(tlsb_handshake(p.c) == TLSB_WANT_READ, "client hello");
	p.s2c.closed = 1;
	CHECK(tlsb_handshake(p.c) == TLSB_ERROR && strcmp(tlsb_errmsg(p.c),
		"connection closed during handshake") == 0, "closed: %s",
		tlsb_errmsg(p.c));
    }
    Teardown(&p);
}

/*
 * Behaviour every backend shares (doc/backend.md).
 */

static const char *
Alpn(const tlsb_info *i, char *buf)
{
    if (i->alpn == NULL) {
	return "(none)";
    }
    snprintf(buf, 64, "%.*s", (int) i->alpn_len, i->alpn);
    return buf;
}

/* No common protocol means no ALPN, never a failure. */
static void
TestAlpn(void)
{
    static const char *h2[] = {"h2"}, *foo[] = {"foo", "bar"};
    tlsb_opts so = Server(), co = Client();
    tlsb_info ci, si;
    char b1[64], b2[64];
    int i;
    Pair p;

    for (i = 0; i < 6; i++) {
	co.protocols = i & 1 ? TLSB_TLS13 : TLSB_TLS12;
	so.alpn = i < 4 ? h2 : NULL, so.alpn_count = i < 4;
	co.alpn = i < 2 || i >= 4 ? foo : NULL, co.alpn_count = i < 2 || i >= 4 ? 2 : 0;
	if (Setup(&p, &co, &so, "localhost", 0, 0)) {
	    CHECK(Shake(&p) && tlsb_info_get(p.c, &ci) == TLSB_OK
		    && tlsb_info_get(p.s, &si) == TLSB_OK && !ci.alpn && !si.alpn,
		    "alpn case %d: %s / %s, alpn %s / %s", i, Err(p.c, p.cr),
		    Err(p.s, p.sr), p.cr ? "-" : Alpn(&ci, b1), p.sr ? "-" : Alpn(&si, b2));
	}
	Teardown(&p);
    }
}

/* Cipher names and how they are sorted into protocols. */
static void
TestCipherNames(void)
{
    static const struct {
	const char *ciphers, *suites, *expect;
	unsigned proto;
    } t[] = {
	{"TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256", NULL,
	    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", TLSB_TLS12},
	{"\ttls_ecdhe_ecdsa_with_aes_256_gcm_sha384,\n", NULL,
	    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", TLSB_TLS12},
	{NULL, "tls-aes-256-gcm-sha384", "TLS_AES_256_GCM_SHA384", 0},
	/* A TLS 1.2 name in ciphersuites: TLS 1.3 has none left. */
	{NULL, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 0},
	{NULL, "ECDHE-ECDSA-CHACHA20-POLY1305 TLS_AES_128_GCM_SHA256",
	    "TLS_AES_128_GCM_SHA256", 0},
	{NULL, "ECDHE-ECDSA-CHACHA20-POLY1305 TLS_AES_128_GCM_SHA256",
	    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", TLSB_TLS12},
	/* A TLS 1.3 name in ciphers: TLS 1.2 has none left. */
	{"TLS_AES_256_GCM_SHA384", NULL, "TLS_AES_256_GCM_SHA384", 0},
	{"TLS_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	    "TLS_AES_256_GCM_SHA384", 0},
	{"TLS_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", TLSB_TLS12},
    };
    tlsb_opts so = Server(), co = Client();
    tlsb_info ci;
    char err[256];
    tlsb_conf *c;
    size_t i;
    Pair p;

    for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
	co.ciphers = t[i].ciphers, co.ciphersuites = t[i].suites;
	co.protocols = t[i].proto;
	if (Setup(&p, &co, &so, "localhost", 0, 0)) {
	    int ok = Shake(&p) && tlsb_info_get(p.c, &ci) == TLSB_OK;

	    CHECK(ok && strcmp(ci.cipher, t[i].expect) == 0,
		    "cipher case %zu: %s / %s, got %s", i, Err(p.c, p.cr),
		    Err(p.s, p.sr), ok ? ci.cipher : "-");
	}
	Teardown(&p);
	/* The same on the server side. */
	co = Client();
	so.ciphers = t[i].ciphers, so.ciphersuites = t[i].suites;
	so.protocols = t[i].proto;
	if (Setup(&p, &co, &so, "localhost", 0, 0)) {
	    int ok = Shake(&p) && tlsb_info_get(p.s, &ci) == TLSB_OK;

	    CHECK(ok && strcmp(ci.cipher, t[i].expect) == 0,
		    "server cipher case %zu: %s / %s, got %s", i, Err(p.c, p.cr),
		    Err(p.s, p.sr), ok ? ci.cipher : "-");
	}
	Teardown(&p);
	so = Server();
    }

    so.ciphers = "TLS_AES_128_GCM_SHA256", so.protocols = TLSB_TLS12;
    c = tlsb_conf_new(&so, err, sizeof(err));
    CHECK(!c && strcmp(err, "no usable cipher suites") == 0, "no suites: %s",
	    c ? "-" : err);
    tlsb_conf_free(c);
    so = Server();
    so.ciphersuites = "ECDHE-ECDSA-AES128-GCM-SHA256", so.protocols = TLSB_TLS13;
    c = tlsb_conf_new(&so, err, sizeof(err));
    CHECK(!c && strcmp(err, "no usable cipher suites") == 0, "no suites 1.3: %s",
	    c ? "-" : err);
    tlsb_conf_free(c);
    so = Server();
    so.ciphersuites = "tls_aes_128_gcm_sha256:NOPE";
    c = tlsb_conf_new(&so, err, sizeof(err));
    CHECK(!c && strcmp(err, "unknown cipher: NOPE") == 0, "unknown: %s",
	    c ? "-" : err);
    tlsb_conf_free(c);
}

/* Configuration error messages. */
static void
TestMessages(void)
{
    static const char *bad[] = {"h2", ""};
    tlsb_opts so = Server(), co = Client();
    char err[256];
    tlsb_conf *c;
    tlsb_sess *s;
    tlsb_io io = {NULL, PipeRecv, PipeSend, NULL};

    so.key = srvKeyEnc.p, so.key_len = srvKeyEnc.n, so.password = "wrong";
    c = tlsb_conf_new(&so, err, sizeof(err));
    CHECK(!c && strcmp(err, "wrong password") == 0, "wrong password: %s", err);
    tlsb_conf_free(c);
    so.password = NULL;
    c = tlsb_conf_new(&so, err, sizeof(err));
    CHECK(!c && strcmp(err, "password required") == 0, "password required: %s",
	    err);
    tlsb_conf_free(c);
    so = Server();
    so.cert = so.key = NULL, so.cert_len = so.key_len = 0;
    c = tlsb_conf_new(&so, err, sizeof(err));
    CHECK(!c && strcmp(err, "server requires a certificate and key") == 0,
	    "no server cert: %s", err);
    tlsb_conf_free(c);
    co.cadir = "/nonexistent";
    c = tlsb_conf_new(&co, err, sizeof(err));
    CHECK(!c && strcmp(err, "cannot read cadir: /nonexistent") == 0, "cadir: %s",
	    err);
    tlsb_conf_free(c);
    co = Client();
    co.alpn = bad, co.alpn_count = 2;
    c = tlsb_conf_new(&co, err, sizeof(err));
    FCHECK(!c && strcmp(err, "invalid ALPN protocol name") == 0, "alpn: %s", err);
    tlsb_conf_free(c);
    co = Client();
    c = tlsb_conf_new(&co, err, sizeof(err));
    s = c ? tlsb_sess_new(c, "localhost", &io, err, sizeof(err)) : NULL;
    CHECK(s && strcmp(tlsb_errmsg(s), "unknown error") == 0, "no error yet");
    tlsb_sess_free(s);
    tlsb_conf_free(c);
}

/* The servername reported, and how long certificates stay valid. */
static void
TestNames(void)
{
    static const char *names[] = {"localhost", "127.0.0.1", NULL};
    tlsb_opts so = Server(), co = Client();
    const uint8_t *d0, *d1, *d0b, *l;
    size_t n0, n1, n0b, ln;
    tlsb_info ci, si;
    uint8_t *copy;
    int i;
    Pair p;

    for (i = 0; i < 3; i++) {
	if (Setup(&p, &co, &so, names[i], 0, 0)) {
	    int ok = Shake(&p) && tlsb_info_get(p.c, &ci) == TLSB_OK
		    && tlsb_info_get(p.s, &si) == TLSB_OK;

	    CHECK(ok, "servername %s: %s", names[i] ? names[i] : "NULL",
		    Err(p.c, p.cr));
	    if (ok && i == 0) {
		CHECK(ci.servername && strcmp(ci.servername, "localhost") == 0
			&& si.servername && strcmp(si.servername, "localhost") == 0,
			"servername localhost");
	    } else if (ok) {
		FCHECK(ci.servername == NULL && si.servername == NULL,
			"servername %s: client %s, server %s", names[i] ? names[i]
			: "NULL", ci.servername ? ci.servername : "NULL",
			si.servername ? si.servername : "NULL");
	    }
	}
	Teardown(&p);
    }

    /* Peer certificates live as long as the session. */
    so.cert = srvChain.p, so.cert_len = srvChain.n;
    if (Setup(&p, &co, &so, "localhost", 0, 0) && Shake(&p)
	    && tlsb_peer_cert(p.c, 0, &d0, &n0) == TLSB_OK) {
	copy = malloc(n0);
	memcpy(copy, d0, n0);
	FCHECK(tlsb_peer_cert(p.c, 1, &d1, &n1) == TLSB_OK, "depth 1");
	CHECK(tlsb_peer_cert(p.c, 0, &d0b, &n0b) == TLSB_OK && n0b == n0
		&& memcmp(d0b, copy, n0) == 0, "depth 0 again");
	CHECK(tlsb_local_cert(p.s, &l, &ln) == TLSB_OK && tlsb_info_get(p.c, &ci)
		== TLSB_OK && Transfer(p.c, p.s, 100) && Transfer(p.s, p.c, 100),
		"other calls");
	CHECK(memcmp(d0, copy, n0) == 0, "depth 0 still valid");
	free(copy);
    }
    Teardown(&p);
}

/*
 * One session of client conf cc against server conf sc. Returns 1 if both
 * ends report resumption, 0 if neither does, 2 if they disagree, -1 on
 * failure.
 */
static int
Session(tlsb_conf *cc, tlsb_conf *sc, const char *name, int cverify,
	int sverify)
{
    tlsb_info ci, si;
    int r = -1;
    Pair p;

    p.own = 0;
    if (Attach(&p, cc, sc, name, cverify, sverify)) {
	p.ce.mode = 2;
	if (Shake(&p) && Transfer(p.s, p.c, 100) && Transfer(p.c, p.s, 100)
		&& tlsb_info_get(p.c, &ci) == TLSB_OK
		&& tlsb_info_get(p.s, &si) == TLSB_OK) {
	    r = ci.resumed && si.resumed ? 1 : !ci.resumed && !si.resumed ? 0 : 2;
	} else {
	    printf("session: %s / %s\n", Err(p.c, p.cr), Err(p.s, p.sr));
	}
    }
    Teardown(&p);
    return r;
}

/*
 * Server handshake on len bytes from a client that then closes; returns
 * the result.
 */
static int
FeedServer(tlsb_conf *sc, const uint8_t *buf, size_t len)
{
    Pipe in = {NULL, len, 0, len, 1, 0}, out = {NULL, 0, 0, 0, 0, 0};
    End e = {&in, &out, 0, {0, {0}, {0}, {{0}}}};
    tlsb_io io = {&e, PipeRecv, PipeSend, NULL};
    char err[256];
    tlsb_sess *s = tlsb_sess_new(sc, NULL, &io, err, sizeof(err));
    int r = TLSB_ERROR, i;

    CHECK(s, "server session: %s", err);
    in.buf = malloc(len + 1);
    memcpy(in.buf, buf, len);
    for (i = 0; s && i < 4 && (r = tlsb_handshake(s)) == TLSB_WANT_READ; i++) ;
    tlsb_sess_free(s);
    free(in.buf);
    free(out.buf);
    return r;
}

/*
 * Truncated and corrupted ClientHellos through the server's ALPN read-ahead:
 * all must fail cleanly.
 */
static void
TestBadHello(void)
{
    static const char *h2[] = {"h2"}, *foo[] = {"foo", "bar"};
    tlsb_opts so = Server(), co = Client();
    uint8_t *hello, *buf;
    size_t len, i;
    int ok = 0, cases = 0, v;
    Pair p;

    so.alpn = h2, so.alpn_count = 1;
    co.alpn = foo, co.alpn_count = 2;
    if (!Setup(&p, &co, &so, "localhost", 0, 0)
	    || tlsb_handshake(p.c) != TLSB_WANT_READ || p.c2s.len < 6) {
	CHECK(0, "client hello: %s", p.c ? tlsb_errmsg(p.c) : "-");
	Teardown(&p);
	return;
    }
    hello = p.c2s.buf, len = p.c2s.len;
    buf = malloc(len);
    for (i = 0; i <= len; i++) {
	/* Each prefix as it is, and as a whole record of its own. */
	ok += FeedServer(p.sc, hello, i) == TLSB_ERROR;
	cases++;
	if (i >= 5) {
	    memcpy(buf, hello, i);
	    buf[3] = (uint8_t) ((i - 5) >> 8), buf[4] = (uint8_t) (i - 5);
	    ok += FeedServer(p.sc, buf, i) == TLSB_ERROR;
	    cases++;
	}
    }
    for (i = 0; i < len; i++) {
	/* Every byte, length fields included, set to 0 and to 0xff. */
	for (v = 0; v <= 0xff; v += 0xff) {
	    memcpy(buf, hello, len);
	    buf[i] = (uint8_t) v;
	    ok += FeedServer(p.sc, buf, len) == TLSB_ERROR;
	    cases++;
	}
    }
    CHECK(ok == cases, "bad hellos: %d of %d failed cleanly", ok, cases);
    printf("bad hellos: %d cases\n", cases);
    free(buf);
    Teardown(&p);
}

/* Session resumption. */
static void
TestResume(void)
{
    tlsb_opts so = Server(), co = Client();
    tlsb_conf *cc, *sc, *sc2;
    char err[256];
    int m, r1, r2, r3;

    for (m = 0; m < 4; m++) {
	co = Client(), so = Server();
	co.protocols = m & 1 ? TLSB_TLS13 : TLSB_TLS12;
	if (m & 2) {		/* mutual */
	    so.request = so.require = 1;
	    so.ca = ca.p, so.ca_len = ca.n;
	    co.cert = cliCert.p, co.cert_len = cliCert.n;
	    co.key = cliKey.p, co.key_len = cliKey.n;
	}
	cc = tlsb_conf_new(&co, err, sizeof(err));
	sc = tlsb_conf_new(&so, err, sizeof(err));
	sc2 = tlsb_conf_new(&so, err, sizeof(err));
	if (!cc || !sc || !sc2) {
	    CHECK(0, "resume confs: %s", err);
	} else {
	    r1 = Session(cc, sc, "localhost", 0, 0);
	    r2 = Session(cc, sc, "localhost", 0, 0);
	    r3 = Session(cc, sc, "localhost", 0, 0);
	    CHECK(r1 == 0 && r2 == 1 && r3 == 1, "resume %s%s: %d %d %d",
		    m & 1 ? "TLS1.3" : "TLS1.2", m & 2 ? " mutual" : "", r1, r2,
		    r3);
	    CHECK(Session(cc, sc, "localhost", 1, 0) == 0, "no resume with callback");
	    FCHECK(Session(cc, sc, "localhost", 0, 1) == 0
		    && Session(cc, sc, "localhost", 0, 0) == 1,
		    "no resume with a server callback");
	    CHECK(Session(cc, sc, NULL, 0, 0) == 0, "no resume without servername");
	    CHECK(Session(cc, sc2, "localhost", 0, 0) == 0, "other server conf");
	    CHECK(Session(cc, sc2, "localhost", 0, 0) == 1, "other server conf again");
	    CHECK(Session(cc, sc, "localhost", 0, 0) == 0, "first server conf again");
	}
	tlsb_conf_free(cc);
	tlsb_conf_free(sc);
	tlsb_conf_free(sc2);
    }
}

/*
 * A TLS 1.3 server refusing the client's certificate. Mbed TLS encrypts its
 * alert with the handshake keys the client no longer reads with, so the
 * client sees a failure, just not the refusal.
 */
static void
TestRefused(void)
{
    tlsb_opts so = Server(), co = Client();
    uint8_t buf[16];
    int i;
    Pair p;

    so.request = so.require = 1;
    so.ca = ca.p, so.ca_len = ca.n;
    co.protocols = TLSB_TLS13;
    for (i = 0; i < 2; i++) {
	if (i) {		/* untrusted certificate */
	    co.cert = ssCert.p, co.cert_len = ssCert.n;
	    co.key = ssKey.p, co.key_len = ssKey.n;
	}
	if (Setup(&p, &co, &so, "localhost", 0, 0)) {
	    const char *e;

	    Shake(&p);
	    CHECK(p.sr == TLSB_ERROR, "server refuses");
	    if (p.cr == TLSB_OK) {
		p.cr = (int) tlsb_read(p.c, buf, sizeof(buf));
	    }
	    e = Err(p.c, p.cr);
	    CHECK(p.cr == TLSB_ERROR, "refused %d: client %s; server %s",
		    i, e, Err(p.s, p.sr));
	    if (i == 0) {
		CHECK(strcmp(Err(p.s, p.sr), "peer did not return a certificate")
			== 0, "server: %s", Err(p.s, p.sr));
	    }
	}
	Teardown(&p);
    }
}

/* WANT_READ only once recv has run dry. */
static void
TestWantRead(void)
{
    tlsb_opts so = Server(), co = Client();
    uint8_t buf[16];
    unsigned proto;
    Pair p;

    for (proto = TLSB_TLS12; proto <= TLSB_TLS13; proto <<= 1) {
	co.protocols = proto;
	if (Setup(&p, &co, &so, "localhost", 0, 0) && Shake(&p)) {
	    int dry = p.s2c.dry;

	    /* TLS 1.3: only tickets are waiting. */
	    CHECK(tlsb_read(p.c, buf, sizeof(buf)) == TLSB_WANT_READ
		    && p.s2c.off == p.s2c.len && p.s2c.dry > dry, "client dry");
	    dry = p.c2s.dry;
	    CHECK(tlsb_read(p.s, buf, sizeof(buf)) == TLSB_WANT_READ
		    && p.c2s.off == p.c2s.len && p.c2s.dry > dry, "server dry");
	    tlsb_write(p.s, (const uint8_t *) "x", 1);
	    CHECK(tlsb_read(p.c, buf, sizeof(buf)) == 1, "one byte");
	    dry = p.s2c.dry;
	    CHECK(tlsb_read(p.c, buf, sizeof(buf)) == TLSB_WANT_READ
		    && p.s2c.dry > dry, "dry again");
	}
	Teardown(&p);
    }
}

static void
Hex(const char *hex, uint8_t *out)
{
    for (; hex[0] && hex[1]; hex += 2) {
	unsigned v;

	sscanf(hex, "%2x", &v);
	*out++ = (uint8_t) v;
    }
}

static int
HexEq(const uint8_t *b, const char *hex)
{
    uint8_t x[128];

    Hex(hex, x);
    return memcmp(b, x, strlen(hex) / 2) == 0;
}

static void
TestCrypto(void)
{
    uint8_t out[64], key[32], nonce[12], pt[100], ct[116], back[100];
    const uint8_t *abc = (const uint8_t *) "abc";

    CHECK(tlsb_digest(TLSB_SHA1, abc, 3, out) == TLSB_OK && HexEq(out,
	    "a9993e364706816aba3e25717850c26c9cd0d89d"), "sha1");
    CHECK(tlsb_digest(TLSB_SHA256, abc, 3, out) == TLSB_OK && HexEq(out,
	    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
	    "sha256");
    CHECK(tlsb_digest(TLSB_SHA512, abc, 3, out) == TLSB_OK && HexEq(out,
	    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
	    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
	    "sha512");
    CHECK(tlsb_digest(7, abc, 3, out) == TLSB_ERROR, "bad digest");

    /* RFC 7914 section 11. */
    CHECK(tlsb_pbkdf2(TLSB_SHA256, (const uint8_t *) "passwd", 6,
	    (const uint8_t *) "salt", 4, 1, out, 64) == TLSB_OK && HexEq(out,
	    "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
	    "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"),
	    "pbkdf2 sha256");
    /* RFC 6070. */
    CHECK(tlsb_pbkdf2(TLSB_SHA1, (const uint8_t *) "password", 8,
	    (const uint8_t *) "salt", 4, 1, out, 20) == TLSB_OK && HexEq(out,
	    "0c60c80f961f0e71f3a9b524af6012062fe037a6"), "pbkdf2 sha1 c=1");
    CHECK(tlsb_pbkdf2(TLSB_SHA1, (const uint8_t *) "password", 8,
	    (const uint8_t *) "salt", 4, 4096, out, 20) == TLSB_OK && HexEq(out,
	    "4b007901b765489abead49d926f721d065a429c1"), "pbkdf2 sha1 c=4096");
    CHECK(tlsb_pbkdf2(TLSB_SHA1, (const uint8_t *) "passwordPASSWORDpassword",
	    24, (const uint8_t *) "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
	    4096, out, 25) == TLSB_OK && HexEq(out,
	    "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"), "pbkdf2 sha1 25");

    /* GCM spec test case 14 (zero key, IV, 16 zero bytes). */
    memset(key, 0, 32), memset(nonce, 0, 12), memset(pt, 0, 16);
    CHECK(tlsb_aes256gcm_seal(key, nonce, pt, 16, ct) == TLSB_OK && HexEq(ct,
	    "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"),
	    "gcm vector");
    CHECK(tlsb_aes256gcm_seal(key, nonce, pt, 0, ct) == TLSB_OK
	    && HexEq(ct, "530f8afbc74536b9a963b4f1c4cb738b"), "gcm empty");
    tlsb_random(key, 32), tlsb_random(nonce, 12), tlsb_random(pt, 100);
    CHECK(tlsb_aes256gcm_seal(key, nonce, pt, 100, ct) == TLSB_OK, "seal");
    CHECK(tlsb_aes256gcm_open(key, nonce, ct, 116, back) == TLSB_OK
	    && memcmp(pt, back, 100) == 0, "open");
    ct[50] ^= 1;
    CHECK(tlsb_aes256gcm_open(key, nonce, ct, 116, back) == TLSB_ERROR,
	    "tampered ciphertext");
    ct[50] ^= 1, ct[115] ^= 0x80;
    CHECK(tlsb_aes256gcm_open(key, nonce, ct, 116, back) == TLSB_ERROR,
	    "tampered tag");
    CHECK(tlsb_aes256gcm_open(key, nonce, ct, 15, back) == TLSB_ERROR,
	    "short input");

    {
	uint8_t a[32], b[32], *big = malloc(200000);

	CHECK(tlsb_random(a, 32) == TLSB_OK && tlsb_random(b, 32) == TLSB_OK
		&& memcmp(a, b, 32) != 0, "random");
	CHECK(tlsb_random(big, 200000) == TLSB_OK, "random big");
	free(big);
    }
}

/* Expired certificates (tests/certs/gen.sh). */
static void
TestExpired(void)
{
    tlsb_opts so = Server(), co = Client();
    char err[256];
    Buf exp, expKey, below, belowKey, inter, chain;
    tlsb_conf *cc, *sc;
    Pair p;

    certdir = pkidir;
    exp = Load("expired-cert.pem"), expKey = Load("expired-key.pem");
    below = Load("below-cert.pem"), belowKey = Load("below-key.pem");
    inter = Load("inter-cert.pem");
    chain = Cat(below, inter);

    so.cert = exp.p, so.cert_len = exp.n, so.key = expKey.p, so.key_len = expKey.n;
    if (Setup(&p, &co, &so, "localhost", 0, 0)) {
	ExpectFail(&p, "certificate verify failed: certificate has expired",
		__LINE__);
    }
    Teardown(&p);

    so.cert = chain.p, so.cert_len = chain.n;
    so.key = belowKey.p, so.key_len = belowKey.n;
    if (Setup(&p, &co, &so, "localhost", 0, 0)) {
	ExpectFail(&p, "certificate verify failed: certificate has expired",
		__LINE__);
    }
    Teardown(&p);

    /*
     * A callback accepting the expired CA must not make the shared conf
     * trust it for later sessions.
     */
    cc = tlsb_conf_new(&co, err, sizeof(err));
    sc = tlsb_conf_new(&so, err, sizeof(err));
    p.own = 0;
    if (Attach(&p, cc, sc, "localhost", 1, 0)) {
	p.ce.mode = 2;
	CHECK(Shake(&p), "accept expired CA: %s", Err(p.c, p.cr));
	FCHECK(p.ce.log.n == 2 && !p.ce.log.ok[0] && !p.ce.log.ok[1]
		&& strcmp(p.ce.log.err[0], "certificate has expired") == 0,
		"expired CA log");
	printf("expired CA: [%s] [%s]\n", p.ce.log.err[0], p.ce.log.err[1]);
	Teardown(&p);
	tlsb_conf_free(sc);
	so.cert = below.p, so.cert_len = below.n;	/* leaf only */
	sc = tlsb_conf_new(&so, err, sizeof(err));
	if (Attach(&p, cc, sc, "localhost", 0, 0)) {
	    ExpectFail(&p, "certificate verify failed", __LINE__);
	}
    }
    Teardown(&p);
    tlsb_conf_free(sc);
    tlsb_conf_free(cc);
    certdir = NULL;
    free(exp.p), free(expKey.p), free(below.p), free(belowKey.p);
    free(inter.p), free(chain.p);
}

/* One pair of confs, many sessions on several threads. */
static tlsb_conf *tcc, *tsc;

static void *
Worker(void *arg)
{
    int i, id = (int) (size_t) arg;

    for (i = 0; i < 8; i++) {
	Pair p;

	p.own = 0;
	if (Attach(&p, tcc, tsc, "localhost", (i + id) & 1, 0)) {
	    p.ce.mode = 2;
	    CHECK(Shake(&p), "thread %d: %s / %s", id, Err(p.c, p.cr),
		    Err(p.s, p.sr));
	    CHECK(Transfer(p.c, p.s, 20000) && Transfer(p.s, p.c, 20000),
		    "thread data");
	}
	Teardown(&p);
    }
    return NULL;
}

static void
TestThreads(void)
{
    tlsb_opts so = Server(), co = Client();
    char err[256];
    pthread_t t[6];
    int i;

    co.ca = NULL, co.ca_len = 0, co.require = 0;	/* lazy system store */
    so.ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256";
    tcc = tlsb_conf_new(&co, err, sizeof(err));
    tsc = tlsb_conf_new(&so, err, sizeof(err));
    CHECK(tcc && tsc, "thread confs: %s", err);
    for (i = 0; i < 6; i++) {
	pthread_create(&t[i], NULL, Worker, (void *) (size_t) i);
    }
    for (i = 0; i < 6; i++) {
	pthread_join(t[i], NULL);
    }
    tlsb_conf_free(tcc);
    tlsb_conf_free(tsc);
}

/*
 * Real host over a blocking socket, trusting the system store.
 */

static long
SockRecv(void *ud, uint8_t *buf, size_t len)
{
    long n = recv(*(int *) ud, buf, len, 0);

    return n > 0 ? n : -1;
}

static void
SockSend(void *ud, const uint8_t *buf, size_t len)
{
    while (len > 0) {
	long n = send(*(int *) ud, buf, len, 0);

	if (n <= 0) {
	    return;
	}
	buf += n, len -= (size_t) n;
    }
}

static void
TestNetwork(const char *host)
{
    struct addrinfo hints, *ai, *a;
    tlsb_opts co;
    tlsb_conf *c;
    tlsb_sess *s;
    tlsb_info info;
    tlsb_io io;
    char err[256], req[256], buf[64];
    int fd = -1, r;
    long n;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, "443", &hints, &ai) != 0) {
	printf("SKIP network: cannot resolve %s\n", host);
	return;
    }
    for (a = ai; a && fd < 0; a = a->ai_next) {
	if ((fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol)) >= 0
		&& connect(fd, a->ai_addr, a->ai_addrlen) != 0) {
	    close(fd);
	    fd = -1;
	}
    }
    freeaddrinfo(ai);
    if (fd < 0) {
	printf("SKIP network: cannot connect to %s\n", host);
	return;
    }
    memset(&co, 0, sizeof(co));
    co.require = 1;
    c = tlsb_conf_new(&co, err, sizeof(err));
    CHECK(c, "network conf: %s", err);
    io = (tlsb_io) {&fd, SockRecv, SockSend, NULL};
    s = c ? tlsb_sess_new(c, host, &io, err, sizeof(err)) : NULL;
    CHECK(s, "network session: %s", err);
    if (s) {
	while ((r = tlsb_handshake(s)) == TLSB_WANT_READ) ;
	FCHECK(r == TLSB_OK, "%s: %s", host, Err(s, r));
	if (r == TLSB_OK) {
	    const uint8_t *d;
	    size_t len;

	    tlsb_info_get(s, &info);
	    printf("%s: %s %s\n", host, info.protocol, info.cipher);
	    CHECK(tlsb_peer_cert(s, 1, &d, &len) == TLSB_OK, "network chain");
	    snprintf(req, sizeof(req), "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n",
		    host);
	    tlsb_write(s, (const uint8_t *) req, strlen(req));
	    while ((n = tlsb_read(s, (uint8_t *) buf, 12)) == TLSB_WANT_READ) ;
	    CHECK(n >= 7 && memcmp(buf, "HTTP/1.", 7) == 0, "http response");
	    tlsb_close_notify(s);
	}
    }
    tlsb_sess_free(s);
    tlsb_conf_free(c);
    close(fd);
}

int
main(int argc, char **argv)
{
    char err[256];
    const char *hosts[16] = {"www.google.com"};
    int i, net = 1, nhosts = 0;

    for (i = 2; i < argc; i++) {
	if (strcmp(argv[i], "-nonet") == 0) {
	    net = 0;
	} else if (strcmp(argv[i], "-host") == 0 && i + 1 < argc && nhosts < 16) {
	    hosts[nhosts++] = argv[++i];
	} else {
	    pkidir = argv[i];
	}
    }
    if (argc < 2) {
	fprintf(stderr, "usage: %s certdir [pkidir] [-nonet] [-host name]...\n",
		argv[0]);
	return 2;
    }
    certdir = argv[1];
    CHECK(tlsb_global_init(err, sizeof(err)) == TLSB_OK, "init: %s", err);
    CHECK(tlsb_global_init(err, sizeof(err)) == TLSB_OK, "init again");

    ca = Load("ca-cert.pem");
    srvCert = Load("server-cert.pem");
    srvKey = Load("server-key.pem");
    srvKeyEnc = Load("server-key-enc.pem");
    srvCertDer = Load("server-cert.der");
    srvKeyDer = Load("server-key.der");
    cliCert = Load("client-cert.pem");
    cliKey = Load("client-key.pem");
    ssCert = Load("selfsigned-cert.pem");
    ssKey = Load("selfsigned-key.pem");
    srvChain = Cat(srvCert, ca);

    TestLibrary();
    TestBasic(TLSB_TLS12);
    TestBasic(TLSB_TLS13);
    TestVerify();
    TestMutual();
    TestConf();
    TestAlpn();
    TestCipherNames();
    TestMessages();
    TestNames();
    TestBadHello();
    TestResume();
    TestRefused();
    TestWantRead();
    TestCrypto();
    TestThreads();
    if (pkidir) {
	TestExpired();
    }
    if (net) {
	for (i = 0; i < (nhosts ? nhosts : 1); i++) {
	    TestNetwork(hosts[i]);
	}
    }

    free(ca.p), free(srvCert.p), free(srvKey.p), free(srvKeyEnc.p);
    free(srvCertDer.p), free(srvKeyDer.p), free(cliCert.p), free(cliKey.p);
    free(ssCert.p), free(ssKey.p), free(srvChain.p);
    printf("%d checks, %d failures\n", checks, fails);
    return fails != 0;
}
