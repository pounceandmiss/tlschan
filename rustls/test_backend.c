/*
 * test_backend.c --
 *
 *	Exercises a tlsb backend through generic/tlsb.h only: client and
 *	server sessions talk over in-memory pipes.
 *	Usage: test_backend certdir [pkidir] [-nonet] [-host name]...
 */

#include <netdb.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../generic/tlsb.h"

static _Atomic int passed, failed;
static const char *certdir = ".", *pkidir, *dir = ".";

#define CHECK(cond, ...) check(!!(cond), __LINE__, #cond, __VA_ARGS__)
static int
check(int ok, int line, const char *expr, const char *fmt, ...)
{
    va_list ap;
    if (ok) {
	passed++;
	return 1;
    }
    failed++;
    fprintf(stderr, "FAIL line %d: %s: ", line, expr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    return 0;
}

/*
 * Files.
 */

typedef struct { uint8_t *d; size_t len; } blob_t;

static blob_t
slurp(const char *path)
{
    blob_t b = {NULL, 0};
    char full[1024];
    FILE *f;
    long n;
    if (!path) {
	return b;
    }
    snprintf(full, sizeof full, "%s/%s", dir, path);
    if (!(f = fopen(full, "rb"))) {
	fprintf(stderr, "cannot open %s\n", full);
	exit(2);
    }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    rewind(f);
    b.d = malloc(n + 1);
    b.len = fread(b.d, 1, n, f);
    fclose(f);
    return b;
}

/*
 * Memory pipes.
 */

typedef struct { uint8_t *d; size_t len, off, cap; int closed; } pipe_t;

#define PASS 2

typedef struct {
    pipe_t *in, *out;
    int verdict;		/* callback result; PASS: the backend's verdict */
    int calls, depth[8], ok[8];
    char err0[256], err[8][96];
    long last;			/* last recv result */
} end_t;

static long
p_recv(void *ud, uint8_t *buf, size_t len)
{
    pipe_t *p = ((end_t *)ud)->in;
    size_t n = p->len - p->off;
    if (n == 0) {
	return ((end_t *)ud)->last = p->closed ? -1 : 0;
    }
    if (n > len) {
	n = len;
    }
    memcpy(buf, p->d + p->off, n);
    p->off += n;
    return ((end_t *)ud)->last = (long)n;
}

static void
p_send(void *ud, const uint8_t *buf, size_t len)
{
    pipe_t *p = ((end_t *)ud)->out;
    if (p->len + len > p->cap) {
	p->cap = (p->len + len) * 2;
	p->d = realloc(p->d, p->cap);
    }
    memcpy(p->d + p->len, buf, len);
    p->len += len;
}

static int
p_verify(void *ud, int depth, const uint8_t *der, size_t len, int ok,
	const char *err)
{
    end_t *e = ud;
    (void)der;
    if (e->calls < 8) {
	e->depth[e->calls] = depth;
	e->ok[e->calls] = ok && len > 0;
	snprintf(e->err[e->calls], sizeof e->err[0], "%s", err ? err : "");
    }
    e->calls++;
    if (depth == 0) {
	snprintf(e->err0, sizeof e->err0, "%s", err ? err : "");
    }
    return e->verdict == PASS ? ok : e->verdict;
}

/*
 * Configurations.
 */

typedef struct {
    int server, request, require;
    unsigned protocols;
    const char *ca, *cadir, *cert, *chain, *key, *password, *ciphers, *ciphersuites;
    const char *const *alpn;
    int alpn_count;
} spec_t;

static char conf_err[256];

static tlsb_conf *
mkconf(spec_t sp)
{
    blob_t ca = slurp(sp.ca), cert = slurp(sp.cert), key = slurp(sp.key);
    blob_t chain = slurp(sp.chain);
    tlsb_opts o = {
	sp.server, sp.request, sp.require, sp.protocols,
	ca.d, ca.len, sp.cadir, cert.d, cert.len, key.d, key.len,
	sp.password, sp.ciphers, sp.ciphersuites, sp.alpn, sp.alpn_count
    };
    tlsb_conf *c;
    if (chain.d) {
	o.cert = cert.d = realloc(cert.d, cert.len + chain.len);
	memcpy(cert.d + cert.len, chain.d, chain.len);
	o.cert_len = cert.len + chain.len;
	free(chain.d);
    }
    conf_err[0] = 0;
    c = tlsb_conf_new(&o, conf_err, sizeof conf_err);
    /* The backend must have copied everything. */
    free(ca.d);
    free(cert.d);
    free(key.d);
    return c;
}

#define SERVER(...) mkconf((spec_t){.server = 1, .cert = "server-cert.pem", \
	.key = "server-key.pem", __VA_ARGS__})
#define CLIENT(...) mkconf((spec_t){.server = 0, __VA_ARGS__})

/*
 * Connected pairs.
 */

typedef struct {
    pipe_t c2s, s2c;
    end_t ce, se;
    tlsb_sess *c, *s;
    int rc, rs;
} conn_t;

/* cverify/sverify: -1 no callback, else the callback's verdict (or PASS). */
static conn_t *
conn_open(tlsb_conf *cc, tlsb_conf *sc, const char *sni, int cverify,
	int sverify)
{
    conn_t *k = calloc(1, sizeof *k);
    char err[256];
    tlsb_io cio = {&k->ce, p_recv, p_send, cverify >= 0 ? p_verify : NULL};
    tlsb_io sio = {&k->se, p_recv, p_send, sverify >= 0 ? p_verify : NULL};
    k->ce = (end_t){.in = &k->s2c, .out = &k->c2s, .verdict = cverify};
    k->se = (end_t){.in = &k->c2s, .out = &k->s2c, .verdict = sverify};
    k->c = tlsb_sess_new(cc, sni, &cio, err, sizeof err);
    CHECK(k->c, "client sess: %s", err);
    k->s = tlsb_sess_new(sc, NULL, &sio, err, sizeof err);
    CHECK(k->s, "server sess: %s", err);
    k->rc = k->rs = TLSB_WANT_READ;
    for (int i = 0; i < 20 && k->c && k->s
	    && (k->rc == TLSB_WANT_READ || k->rs == TLSB_WANT_READ); i++) {
	if (k->rc == TLSB_WANT_READ) {
	    k->rc = tlsb_handshake(k->c);
	}
	if (k->rs == TLSB_WANT_READ) {
	    k->rs = tlsb_handshake(k->s);
	}
	if (k->rc == TLSB_ERROR) {
	    k->c2s.closed = 1;
	}
	if (k->rs == TLSB_ERROR) {
	    k->s2c.closed = 1;
	}
    }
    return k;
}

static void
conn_close(conn_t *k)
{
    tlsb_sess_free(k->c);
    tlsb_sess_free(k->s);
    free(k->c2s.d);
    free(k->s2c.d);
    free(k);
}

static int
hs_ok(conn_t *k)
{
    return CHECK(k->rc == TLSB_OK && k->rs == TLSB_OK,
	    "handshake rc=%d rs=%d client: %s server: %s", k->rc, k->rs,
	    k->c ? tlsb_errmsg(k->c) : "-", k->s ? tlsb_errmsg(k->s) : "-");
}

/* Fails the handshake on the client; returns the client's message. */
static const char *
hs_fail(conn_t *k)
{
    CHECK(k->rc == TLSB_ERROR, "client handshake should fail, rc=%d", k->rc);
    return k->c ? tlsb_errmsg(k->c) : "";
}

static int
xfer(tlsb_sess *a, tlsb_sess *b, size_t n)
{
    uint8_t *src = calloc(n, 1), *dst = calloc(n, 1);
    size_t got = 0;
    int ok;
    for (size_t i = 0; i < n; i++) {
	src[i] = (uint8_t)(i * 31 + (i >> 8));
    }
    ok = CHECK(tlsb_write(a, src, n) == (long)n, "write %zu", n);
    while (ok && got < n) {
	long r = tlsb_read(b, dst + got, n - got);
	if (!CHECK(r > 0, "read returned %ld: %s", r, tlsb_errmsg(b))) {
	    break;
	}
	got += r;
    }
    ok = CHECK(got == n && memcmp(src, dst, n) == 0, "data mismatch");
    free(src);
    free(dst);
    return ok;
}

static int
contains(const char *s, const char *sub)
{
    return s && strstr(s, sub) != NULL;
}

/*
 * Tests.
 */

static const char *const ALPN_C[] = {"h2", "http/1.1"};
static const char *const ALPN_S[] = {"http/1.1", "spdy/3"};

static void
test_basic(unsigned proto, const char *pname)
{
    tlsb_conf *sc = SERVER(.protocols = proto, .alpn = ALPN_S, .alpn_count = 2);
    tlsb_conf *cc = CLIENT(.require = 1, .ca = "ca-cert.pem",
	    .alpn = ALPN_C, .alpn_count = 2);
    conn_t *k;
    tlsb_info ci, si;
    const uint8_t *der, *der2;
    size_t len, len2;
    uint8_t e1[32], e2[32], e3[32];
    blob_t leaf = slurp("server-cert.der");
    uint8_t buf[16];

    printf("-- basic %s\n", pname);
    CHECK(sc && cc, "conf: %s", conf_err);
    k = conn_open(cc, sc, "localhost", -1, -1);
    if (hs_ok(k)) {
	CHECK(tlsb_handshake(k->c) == TLSB_OK, "handshake again");
	CHECK(xfer(k->c, k->s, 200000), "c->s");
	CHECK(xfer(k->s, k->c, 100000), "s->c");
	CHECK(xfer(k->c, k->s, 1), "c->s 1 byte");

	CHECK(tlsb_info_get(k->c, &ci) == TLSB_OK, "info");
	CHECK(tlsb_info_get(k->s, &si) == TLSB_OK, "info");
	CHECK(!strcmp(ci.protocol, pname), "protocol %s", ci.protocol);
	CHECK(!strcmp(ci.cipher, si.cipher), "cipher %s", ci.cipher);
	CHECK(!strncmp(ci.cipher, "TLS_", 4), "IANA name %s", ci.cipher);
	CHECK(ci.cipher_bits == 128 || ci.cipher_bits == 256, "bits %d", ci.cipher_bits);
	CHECK(ci.alpn && ci.alpn_len == 8 && !memcmp(ci.alpn, "http/1.1", 8), "client alpn");
	CHECK(si.alpn && si.alpn_len == 8 && !memcmp(si.alpn, "http/1.1", 8), "server alpn");
	CHECK(ci.servername && !strcmp(ci.servername, "localhost"), "client sni");
	CHECK(si.servername && !strcmp(si.servername, "localhost"), "server sni %s",
		si.servername ? si.servername : "(null)");
	CHECK(!ci.resumed && !si.resumed, "not resumed");
	printf("   %s %s %d bits\n", ci.protocol, ci.cipher, ci.cipher_bits);

	CHECK(tlsb_peer_cert(k->c, 0, &der, &len) == TLSB_OK
		&& len == leaf.len && !memcmp(der, leaf.d, len), "peer leaf");
	CHECK(tlsb_peer_cert(k->c, 1, &der, &len) == TLSB_ERROR, "no depth 1");
	CHECK(tlsb_peer_cert(k->c, -1, &der, &len) == TLSB_ERROR, "no depth -1");
	CHECK(tlsb_peer_cert(k->s, 0, &der, &len) == TLSB_ERROR, "no client cert");
	CHECK(tlsb_local_cert(k->s, &der, &len) == TLSB_OK
		&& tlsb_peer_cert(k->c, 0, &der2, &len2) == TLSB_OK
		&& len == len2 && !memcmp(der, der2, len), "local == peer");
	CHECK(tlsb_local_cert(k->c, &der, &len) == TLSB_ERROR, "client has no cert");

	CHECK(tlsb_export(k->c, "EXPERIMENTAL-x", 14, (const uint8_t *)"ctx", 3, 1, e1, 32) == TLSB_OK
		&& tlsb_export(k->s, "EXPERIMENTAL-x", 14, (const uint8_t *)"ctx", 3, 1, e2, 32) == TLSB_OK
		&& !memcmp(e1, e2, 32), "export with ctx");
	CHECK(tlsb_export(k->c, "EXPERIMENTAL-x", 14, NULL, 0, 0, e3, 32) == TLSB_OK
		&& tlsb_export(k->s, "EXPERIMENTAL-x", 14, NULL, 0, 0, e2, 32) == TLSB_OK
		&& !memcmp(e3, e2, 32) && memcmp(e1, e3, 32), "export without ctx");

	/* close_notify: pending reports it, then read returns EOF. */
	CHECK(!tlsb_pending(k->s), "nothing pending");
	tlsb_close_notify(k->c);
	CHECK(tlsb_read(k->s, buf, sizeof buf) == 0, "EOF after close_notify");
	CHECK(tlsb_read(k->s, buf, sizeof buf) == 0, "EOF again");
	CHECK(!tlsb_pending(k->s), "EOF delivered");
    }
    conn_close(k);

    /* Resumption on a second connection with the same confs. */
    k = conn_open(cc, sc, "localhost", -1, -1);
    if (hs_ok(k)) {
	xfer(k->s, k->c, 10);
	CHECK(tlsb_info_get(k->c, &ci) == TLSB_OK && ci.resumed, "client resumed");
	CHECK(tlsb_info_get(k->s, &si) == TLSB_OK && si.resumed, "server resumed");
	CHECK(tlsb_peer_cert(k->c, 0, &der, &len) == TLSB_OK, "peer cert on resumption");
    }
    conn_close(k);
    free(leaf.d);
    tlsb_conf_free(cc);
    tlsb_conf_free(sc);
}

static void
test_io_edges(void)
{
    tlsb_conf *sc = SERVER(0), *cc = CLIENT(0);
    conn_t *k;
    uint8_t buf[64];
    char err[256];
    tlsb_io io = {NULL, p_recv, p_send, NULL};
    end_t e = {0};
    pipe_t in = {0}, out = {0};
    tlsb_sess *s;

    printf("-- io edges\n");
    /* Write before the handshake is an error. */
    e.in = &in, e.out = &out, io.ud = &e;
    s = tlsb_sess_new(cc, "localhost", &io, err, sizeof err);
    CHECK(s && tlsb_write(s, buf, 1) == TLSB_ERROR, "early write");
    CHECK(s && tlsb_handshake(s) == TLSB_ERROR, "sticky error");
    tlsb_sess_free(s);
    free(out.d);

    /* Transport EOF during the handshake. */
    memset(&out, 0, sizeof out);
    in.closed = 1;
    s = tlsb_sess_new(cc, "localhost", &io, err, sizeof err);
    CHECK(s && tlsb_handshake(s) == TLSB_ERROR
	    && contains(tlsb_errmsg(s), "closed during handshake"), "eof in handshake: %s",
	    s ? tlsb_errmsg(s) : "");
    tlsb_sess_free(s);
    free(out.d);

    /* Unclean transport EOF after the handshake reads as EOF. */
    k = conn_open(cc, sc, "localhost", -1, -1);
    if (hs_ok(k)) {
	CHECK(tlsb_write(k->s, (const uint8_t *)"hello", 5) == 5, "write");
	k->s2c.closed = 1;
	CHECK(tlsb_read(k->c, buf, 3) == 3, "partial read");
	CHECK(tlsb_pending(k->c), "pending buffered plaintext");
	CHECK(tlsb_read(k->c, buf, sizeof buf) == 2, "rest");
	CHECK(tlsb_read(k->c, buf, sizeof buf) == 0, "EOF");
	CHECK(!tlsb_pending(k->c), "EOF delivered");
    }
    conn_close(k);

    /* No data yet: WANT_READ. */
    k = conn_open(cc, sc, "localhost", -1, -1);
    if (hs_ok(k)) {
	CHECK(tlsb_read(k->s, buf, sizeof buf) == TLSB_WANT_READ, "want read");
    }
    conn_close(k);
    tlsb_conf_free(cc);
    tlsb_conf_free(sc);
}

static void
test_verify(void)
{
    tlsb_conf *sc = SERVER(0);
    tlsb_conf *ss = SERVER(.cert = "selfsigned-cert.pem", .key = "selfsigned-key.pem");
    tlsb_conf *cv = CLIENT(.require = 1, .ca = "ca-cert.pem");
    tlsb_conf *cdir = CLIENT(.require = 1, .cadir = certdir);
    tlsb_conf *cany = CLIENT(.require = 0);
    tlsb_conf *csys = CLIENT(.require = 1);
    conn_t *k;
    const char *m;
    tlsb_info ci;

    printf("-- verification\n");
    CHECK(sc && ss && cv && cdir && cany && csys, "confs: %s", conf_err);

    k = conn_open(cv, sc, "localhost", -1, -1);
    hs_ok(k);
    conn_close(k);

    k = conn_open(cv, sc, "127.0.0.1", -1, -1);
    if (hs_ok(k)) {
	CHECK(tlsb_info_get(k->c, &ci) == TLSB_OK && !ci.servername, "no SNI for IP");
    }
    conn_close(k);

    k = conn_open(cdir, sc, "localhost", -1, -1);
    hs_ok(k);
    conn_close(k);

    k = conn_open(cv, sc, "example.com", -1, -1);
    m = hs_fail(k);
    CHECK(!strcmp(m, "certificate verify failed: hostname mismatch"), "msg: %s", m);
    CHECK(k->rs == TLSB_ERROR, "server sees the alert");
    printf("   client: %s | server: %s\n", m, tlsb_errmsg(k->s));
    conn_close(k);

    k = conn_open(cv, ss, "localhost", -1, -1);
    m = hs_fail(k);
    CHECK(!strcmp(m, "certificate verify failed: self-signed certificate"), "msg: %s", m);
    conn_close(k);

    k = conn_open(csys, sc, "localhost", -1, -1);
    m = hs_fail(k);
    CHECK(!strcmp(m, "certificate verify failed: unable to get local issuer certificate"),
	    "system store rejects test CA: %s", m);
    conn_close(k);

    /* require=0 accepts anything. */
    k = conn_open(cany, ss, "example.com", -1, -1);
    hs_ok(k);
    conn_close(k);

    /* No servername: chain only. */
    k = conn_open(cv, sc, NULL, -1, -1);
    if (hs_ok(k)) {
	CHECK(tlsb_info_get(k->s, &ci) == TLSB_OK && !ci.servername, "no SNI sent");
    }
    conn_close(k);
    k = conn_open(cv, ss, NULL, -1, -1);
    m = hs_fail(k);
    CHECK(contains(m, "self-signed"), "nameless untrusted: %s", m);
    conn_close(k);

    tlsb_conf_free(sc);
    tlsb_conf_free(ss);
    tlsb_conf_free(cv);
    tlsb_conf_free(cdir);
    tlsb_conf_free(cany);
    tlsb_conf_free(csys);
}

static void
test_callback(void)
{
    tlsb_conf *sc, *cv, *cany, *smtls, *ccert;
    conn_t *k;
    const char *m;

    printf("-- verify callback\n");
    /* Server sends leaf + CA so the callback sees depths 1 and 0. */
    sc = SERVER(.chain = "ca-cert.pem");
    cv = CLIENT(.require = 1, .ca = "ca-cert.pem");
    cany = CLIENT(.require = 0, .ca = "ca-cert.pem");
    CHECK(sc && cv && cany, "confs: %s", conf_err);

    k = conn_open(cv, sc, "localhost", PASS, -1);
    if (hs_ok(k)) {
	CHECK(k->ce.calls == 2 && k->ce.depth[0] == 1 && k->ce.depth[1] == 0,
		"depths: calls=%d", k->ce.calls);
	CHECK(k->ce.ok[0] && k->ce.ok[1] && !k->ce.err0[0], "both ok");
    }
    conn_close(k);

    /* Passing the bad verdict through rejects; the callback stops there. */
    k = conn_open(cv, sc, "example.com", PASS, -1);
    m = hs_fail(k);
    CHECK(!strcmp(m, "certificate rejected by validation callback")
	    && !strcmp(k->ce.err0, "hostname mismatch"), "msg: %s / %s", m, k->ce.err0);
    conn_close(k);

    k = conn_open(cv, sc, "localhost", 1, -1);
    if (hs_ok(k)) {
	CHECK(k->ce.calls == 2 && k->ce.depth[0] == 1 && k->ce.depth[1] == 0,
		"depths: calls=%d", k->ce.calls);
	CHECK(k->ce.ok[0] && k->ce.ok[1], "both ok");
    }
    conn_close(k);

    /* Callback rejects a valid chain. */
    k = conn_open(cv, sc, "localhost", 0, -1);
    m = hs_fail(k);
    CHECK(!strcmp(m, "certificate rejected by validation callback"), "msg: %s", m);
    CHECK(k->ce.calls == 1 && k->ce.depth[0] == 1, "stops at depth 1: calls=%d", k->ce.calls);
    conn_close(k);

    /* Callback accepts an invalid chain (wrong name) and sees the reason. */
    k = conn_open(cv, sc, "example.com", 1, -1);
    if (hs_ok(k)) {
	CHECK(k->ce.calls == 2 && k->ce.ok[0] && !k->ce.ok[1], "leaf not ok");
	CHECK(!strcmp(k->ce.err0, "hostname mismatch"), "err: %s", k->ce.err0);
    }
    conn_close(k);

    /* require=0: callback still gets the real verdict; returning it rejects. */
    k = conn_open(cany, sc, "example.com", PASS, -1);
    m = hs_fail(k);
    CHECK(!strcmp(m, "certificate rejected by validation callback"), "msg: %s", m);
    CHECK(k->ce.calls == 2 && !strcmp(k->ce.err0, "hostname mismatch"), "called");
    conn_close(k);

    /* Server side: callback on the client chain. */
    smtls = SERVER(.request = 1, .ca = "ca-cert.pem");
    ccert = CLIENT(.cert = "client-cert.pem", .key = "client-key.pem");
    CHECK(smtls && ccert, "confs: %s", conf_err);
    k = conn_open(ccert, smtls, "localhost", -1, 1);
    if (hs_ok(k)) {
	CHECK(k->se.calls == 1 && k->se.depth[0] == 0 && k->se.ok[0], "server cb");
    }
    conn_close(k);
    k = conn_open(ccert, smtls, "localhost", -1, 0);
    CHECK(k->rs == TLSB_ERROR && !strcmp(tlsb_errmsg(k->s),
	    "certificate rejected by validation callback"), "server reject: %s", tlsb_errmsg(k->s));
    conn_close(k);

    tlsb_conf_free(sc);
    tlsb_conf_free(cv);
    tlsb_conf_free(cany);
    tlsb_conf_free(smtls);
    tlsb_conf_free(ccert);
}

static void
test_mtls(void)
{
    tlsb_conf *sreq = SERVER(.require = 1, .ca = "ca-cert.pem");
    tlsb_conf *sopt = SERVER(.request = 1, .ca = "ca-cert.pem");
    tlsb_conf *ccert = CLIENT(.require = 1, .ca = "ca-cert.pem",
	    .cert = "client-cert.pem", .key = "client-key.pem");
    tlsb_conf *cbad = CLIENT(.cert = "selfsigned-cert.pem", .key = "selfsigned-key.pem");
    tlsb_conf *cnone = CLIENT(0);
    const uint8_t *der;
    size_t len;
    uint8_t buf[8];
    conn_t *k;

    printf("-- mutual TLS\n");
    CHECK(sreq && sopt && ccert && cbad && cnone, "confs: %s", conf_err);
    k = conn_open(ccert, sreq, "localhost", -1, -1);
    if (hs_ok(k)) {
	CHECK(tlsb_peer_cert(k->s, 0, &der, &len) == TLSB_OK && len > 300, "client cert seen");
	CHECK(tlsb_local_cert(k->c, &der, &len) == TLSB_OK, "client local cert");
	xfer(k->c, k->s, 1000);
    }
    conn_close(k);

    /* TLS 1.3: the client finishes first and learns of rejection on read. */
    k = conn_open(cnone, sreq, "localhost", -1, -1);
    CHECK(k->rs == TLSB_ERROR && contains(tlsb_errmsg(k->s), "did not return a certificate"),
	    "no client cert: %s", tlsb_errmsg(k->s));
    CHECK(k->rc == TLSB_ERROR || tlsb_read(k->c, buf, sizeof buf) == TLSB_ERROR,
	    "client sees alert");
    printf("   server: %s | client: %s\n", tlsb_errmsg(k->s), tlsb_errmsg(k->c));
    conn_close(k);

    k = conn_open(cbad, sreq, "localhost", -1, -1);
    CHECK(k->rs == TLSB_ERROR && contains(tlsb_errmsg(k->s), "self-signed"),
	    "untrusted client cert: %s", tlsb_errmsg(k->s));
    conn_close(k);

    /* request without require: optional, anything goes. */
    k = conn_open(cnone, sopt, "localhost", -1, -1);
    hs_ok(k);
    conn_close(k);
    k = conn_open(cbad, sopt, "localhost", -1, -1);
    if (hs_ok(k)) {
	CHECK(tlsb_peer_cert(k->s, 0, &der, &len) == TLSB_OK, "unverified cert kept");
    }
    conn_close(k);

    tlsb_conf_free(sreq);
    tlsb_conf_free(sopt);
    tlsb_conf_free(ccert);
    tlsb_conf_free(cbad);
    tlsb_conf_free(cnone);
}

static void
test_credentials(void)
{
    tlsb_conf *c, *cc = CLIENT(.require = 1, .ca = "ca-cert.pem");
    conn_t *k;

    printf("-- credentials\n");
    c = SERVER(.key = "server-key-enc.pem", .password = "secret");
    CHECK(c, "encrypted key: %s", conf_err);
    if (c) {
	k = conn_open(cc, c, "localhost", -1, -1);
	hs_ok(k);
	conn_close(k);
	tlsb_conf_free(c);
    }
    c = SERVER(.key = "server-key-enc.pem");
    CHECK(!c && !strcmp(conf_err, "password required"), "no password: %s", conf_err);
    c = SERVER(.key = "server-key-enc.pem", .password = "wrong");
    CHECK(!c && !strcmp(conf_err, "wrong password"), "bad password: %s", conf_err);

    c = SERVER(.cert = "server-cert.der", .key = "server-key.der");
    CHECK(c, "DER: %s", conf_err);
    if (c) {
	k = conn_open(cc, c, "localhost", -1, -1);
	hs_ok(k);
	conn_close(k);
	tlsb_conf_free(c);
    }

    c = SERVER(.key = "client-key.pem");
    CHECK(!c && !strcmp(conf_err, "private key does not match certificate"), "%s", conf_err);
    c = SERVER(.key = NULL);
    CHECK(!c && !strcmp(conf_err, "certificate and private key go together"), "%s", conf_err);
    c = SERVER(.cert = NULL);
    CHECK(!c && !strcmp(conf_err, "certificate and private key go together"), "%s", conf_err);
    c = CLIENT(.key = "client-key.pem");
    CHECK(!c && !strcmp(conf_err, "certificate and private key go together"), "%s", conf_err);
    c = CLIENT(.ca = "gen.sh");
    CHECK(!c && !strcmp(conf_err, "cannot parse CA certificates"), "%s", conf_err);
    c = CLIENT(.ca = "server-key.pem");
    CHECK(!c && !strcmp(conf_err, "cannot parse CA certificates"), "%s", conf_err);
    c = SERVER(.cert = NULL, .key = NULL);
    CHECK(!c && !strcmp(conf_err, "server requires a certificate and key"), "%s", conf_err);
    c = SERVER(.cert = "gen.sh");
    CHECK(!c && contains(conf_err, "cannot parse certificate"), "%s", conf_err);
    c = CLIENT(.cadir = "/nonexistent");
    CHECK(!c && !strcmp(conf_err, "cannot read cadir: /nonexistent"), "%s", conf_err);
    c = SERVER(.alpn = (const char *const[]){"h2", ""}, .alpn_count = 2);
    CHECK(!c && !strcmp(conf_err, "invalid ALPN protocol name"), "%s", conf_err);
    tlsb_conf_free(cc);
}

static void
test_ciphers(void)
{
    tlsb_conf *sc, *cc;
    conn_t *k;
    tlsb_info i;

    printf("-- ciphers\n");
    sc = SERVER(.protocols = TLSB_TLS12, .ciphers = "ecdhe-ecdsa-aes256-gcm-sha384");
    cc = CLIENT(0);
    CHECK(sc && cc, "conf: %s", conf_err);
    k = conn_open(cc, sc, "localhost", -1, -1);
    if (hs_ok(k) && CHECK(tlsb_info_get(k->c, &i) == TLSB_OK, "info")) {
	CHECK(!strcmp(i.cipher, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
		&& i.cipher_bits == 256 && !strcmp(i.protocol, "TLS1.2"), "%s", i.cipher);
    }
    conn_close(k);
    tlsb_conf_free(sc);

    sc = SERVER(.ciphersuites = " tls-chacha20-poly1305-sha256,");
    k = conn_open(cc, sc, "localhost", -1, -1);
    if (hs_ok(k) && CHECK(tlsb_info_get(k->s, &i) == TLSB_OK, "info")) {
	CHECK(!strcmp(i.cipher, "TLS_CHACHA20_POLY1305_SHA256") && i.cipher_bits == 256
		&& !strcmp(i.protocol, "TLS1.3"), "%s", i.cipher);
    }
    conn_close(k);
    tlsb_conf_free(sc);

    sc = SERVER(.ciphersuites = "TLS_AES_128_GCM_SHA256");
    k = conn_open(cc, sc, "localhost", -1, -1);
    if (hs_ok(k) && CHECK(tlsb_info_get(k->s, &i) == TLSB_OK, "info")) {
	CHECK(i.cipher_bits == 128, "%s %d", i.cipher, i.cipher_bits);
    }
    conn_close(k);
    tlsb_conf_free(sc);

    /* Disjoint suites fail. */
    sc = SERVER(.protocols = TLSB_TLS12, .ciphers = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    tlsb_conf_free(cc);
    cc = CLIENT(.protocols = TLSB_TLS12, .ciphers = "ECDHE-ECDSA-CHACHA20-POLY1305");
    k = conn_open(cc, sc, "localhost", -1, -1);
    CHECK(k->rc == TLSB_ERROR, "no common cipher");
    printf("   %s | %s\n", tlsb_errmsg(k->c), tlsb_errmsg(k->s));
    conn_close(k);
    tlsb_conf_free(sc);
    tlsb_conf_free(cc);

    sc = SERVER(.ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:FOO");
    CHECK(!sc && !strcmp(conf_err, "unknown cipher: FOO"), "%s", conf_err);
    sc = SERVER(.protocols = 4);
    CHECK(!sc, "bad protocols: %s", conf_err);
}

static void
cipher_cb(void *ud, const char *name)
{
    int *n = ud;
    (*n)++;
    printf("   %s\n", name);
}

static void
test_library(void)
{
    char err[64];
    int n12 = 0, n13 = 0;
    printf("-- library: %s\n", tlsb_version());
    CHECK(tlsb_global_init(err, sizeof err) == TLSB_OK, "init");
    CHECK(!strncmp(tlsb_version(), "rustls 0.", 9), "%s", tlsb_version());
    CHECK(tlsb_protocols() == (TLSB_TLS12 | TLSB_TLS13), "protocols");
    tlsb_ciphers(TLSB_TLS12, cipher_cb, &n12);
    tlsb_ciphers(TLSB_TLS13, cipher_cb, &n13);
    CHECK(n12 == 6 && n13 == 3, "ciphers %d %d", n12, n13);
}

static int
hexeq(const uint8_t *b, const char *hex)
{
    char s[3];
    for (size_t i = 0; hex[2 * i]; i++) {
	snprintf(s, sizeof s, "%02x", b[i]);
	if (memcmp(s, hex + 2 * i, 2)) {
	    return 0;
	}
    }
    return 1;
}

static void
test_crypto(void)
{
    uint8_t out[64], key[32], nonce[12] = {0}, ct[64 + 16], pt[64], r1[32], r2[32];
    const uint8_t *pw = (const uint8_t *)"password", *salt = (const uint8_t *)"salt";
    const char *msg = "the quick brown fox";
    size_t mlen = strlen(msg);

    printf("-- crypto\n");
    CHECK(tlsb_digest(TLSB_SHA256, (const uint8_t *)"abc", 3, out) == TLSB_OK
	    && hexeq(out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "sha256");
    CHECK(tlsb_digest(TLSB_SHA1, (const uint8_t *)"abc", 3, out) == TLSB_OK
	    && hexeq(out, "a9993e364706816aba3e25717850c26c9cd0d89d"), "sha1");
    CHECK(tlsb_digest(TLSB_SHA512, (const uint8_t *)"abc", 3, out) == TLSB_OK
	    && hexeq(out, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
		"2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"), "sha512");
    CHECK(tlsb_digest(7, (const uint8_t *)"abc", 3, out) == TLSB_ERROR, "bad alg");

    /* RFC 6070 */
    CHECK(tlsb_pbkdf2(TLSB_SHA1, pw, 8, salt, 4, 1, out, 20) == TLSB_OK
	    && hexeq(out, "0c60c80f961f0e71f3a9b524af6012062fe037a6"), "pbkdf2 sha1 c=1");
    CHECK(tlsb_pbkdf2(TLSB_SHA1, pw, 8, salt, 4, 4096, out, 20) == TLSB_OK
	    && hexeq(out, "4b007901b765489abead49d926f721d065a429c1"), "pbkdf2 sha1 c=4096");
    CHECK(tlsb_pbkdf2(TLSB_SHA1, (const uint8_t *)"pass\0word", 9,
	    (const uint8_t *)"sa\0lt", 5, 4096, out, 16) == TLSB_OK
	    && hexeq(out, "56fa6aa75548099dcc37d7f03425e0c3"), "pbkdf2 sha1 NUL");
    CHECK(tlsb_pbkdf2(TLSB_SHA256, pw, 8, salt, 4, 1, out, 32) == TLSB_OK
	    && hexeq(out, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"), "pbkdf2 sha256");
    CHECK(tlsb_pbkdf2(TLSB_SHA256, pw, 8, salt, 4, 4096, out, 32) == TLSB_OK
	    && hexeq(out, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"), "pbkdf2 sha256 4096");
    CHECK(tlsb_pbkdf2(TLSB_SHA256, pw, 8, salt, 4, 0, out, 32) == TLSB_ERROR, "0 iterations");

    /* AES-256-GCM: zero key/nonce/empty message tag, then a roundtrip. */
    memset(key, 0, sizeof key);
    CHECK(tlsb_aes256gcm_seal(key, nonce, NULL, 0, ct) == TLSB_OK
	    && hexeq(ct, "530f8afbc74536b9a963b4f1c4cb738b"), "gcm empty tag");
    CHECK(tlsb_aes256gcm_open(key, nonce, ct, 16, pt) == TLSB_OK, "gcm empty open");
    CHECK(tlsb_random(key, sizeof key) == TLSB_OK && tlsb_random(r1, 32) == TLSB_OK
	    && tlsb_random(r2, 32) == TLSB_OK && memcmp(r1, r2, 32), "random");
    CHECK(tlsb_aes256gcm_seal(key, nonce, (const uint8_t *)msg, mlen, ct) == TLSB_OK, "seal");
    CHECK(tlsb_aes256gcm_open(key, nonce, ct, mlen + 16, pt) == TLSB_OK
	    && !memcmp(pt, msg, mlen), "open");
    ct[3] ^= 1;
    CHECK(tlsb_aes256gcm_open(key, nonce, ct, mlen + 16, pt) == TLSB_ERROR, "tamper");
    ct[3] ^= 1;
    ct[mlen + 15] ^= 0x80;
    CHECK(tlsb_aes256gcm_open(key, nonce, ct, mlen + 16, pt) == TLSB_ERROR, "tamper tag");
    CHECK(tlsb_aes256gcm_open(key, nonce, ct, 15, pt) == TLSB_ERROR, "short");
    /* In place. */
    memcpy(pt, msg, mlen);
    CHECK(tlsb_aes256gcm_seal(key, nonce, pt, mlen, pt) == TLSB_OK
	    && tlsb_aes256gcm_open(key, nonce, pt, mlen + 16, pt) == TLSB_OK
	    && !memcmp(pt, msg, mlen), "in place");
}

/* Expired certificates (tests/certs/gen.sh), read from pkidir. */
static void
test_expired(void)
{
    tlsb_conf *cv = CLIENT(.require = 1, .ca = "ca-cert.pem"), *sc, *sleaf;
    conn_t *k;
    const char *m;

    printf("-- expired\n");
    dir = pkidir;
    sc = SERVER(.cert = "expired-cert.pem", .key = "expired-key.pem");
    k = conn_open(cv, sc, "localhost", -1, -1);
    m = hs_fail(k);
    CHECK(!strcmp(m, "certificate verify failed: certificate has expired"), "leaf: %s", m);
    conn_close(k);
    tlsb_conf_free(sc);

    /* Valid leaf below an expired intermediate. */
    sc = SERVER(.cert = "below-cert.pem", .chain = "inter-cert.pem", .key = "below-key.pem");
    CHECK(sc, "conf: %s", conf_err);
    k = conn_open(cv, sc, "localhost", -1, -1);
    m = hs_fail(k);
    CHECK(!strcmp(m, "certificate verify failed: certificate has expired"), "inter: %s", m);
    conn_close(k);

    k = conn_open(cv, sc, "localhost", 1, -1);
    if (hs_ok(k)) {
	CHECK(k->ce.calls == 2 && k->ce.depth[0] == 1 && !k->ce.ok[0] && !k->ce.ok[1]
		&& !strcmp(k->ce.err[0], "certificate has expired")
		&& !strcmp(k->ce.err[1], "issuer certificate not trusted"),
		"log: %d [%s] [%s]", k->ce.calls, k->ce.err[0], k->ce.err[1]);
    }
    conn_close(k);

    k = conn_open(cv, sc, "localhost", 0, -1);
    m = hs_fail(k);
    CHECK(!strcmp(m, "certificate rejected by validation callback") && k->ce.calls == 1
	    && k->ce.depth[0] == 1, "reject at depth 1: %s, calls=%d", m, k->ce.calls);
    conn_close(k);

    /* Accepting it once does not make the conf trust it. */
    sleaf = SERVER(.cert = "below-cert.pem", .key = "below-key.pem");
    k = conn_open(cv, sleaf, "localhost", -1, -1);
    m = hs_fail(k);
    CHECK(!strcmp(m, "certificate verify failed: unable to get local issuer certificate"),
	    "leaf alone: %s", m);
    conn_close(k);
    dir = certdir;
    tlsb_conf_free(sc);
    tlsb_conf_free(sleaf);
    tlsb_conf_free(cv);
}

/* Which depth a failure is reported at, and its wording. */
static void
test_depths(void)
{
    tlsb_conf *sc = SERVER(.chain = "ca-cert.pem");
    tlsb_conf *cother = CLIENT(.require = 1, .ca = "selfsigned-cert.pem");
    tlsb_conf *ss = SERVER(.cert = "selfsigned-cert.pem", .key = "selfsigned-key.pem");
    tlsb_conf *cv = CLIENT(.require = 1, .ca = "ca-cert.pem");
    conn_t *k;
    const char *m;

    printf("-- depths\n");
    /* Untrusted root sent by the peer: blamed at depth 1. */
    k = conn_open(cother, sc, "localhost", 1, -1);
    if (hs_ok(k)) {
	CHECK(k->ce.calls == 2 && !strcmp(k->ce.err[0], "self-signed certificate")
		&& !strcmp(k->ce.err[1], "issuer certificate not trusted"),
		"untrusted root: [%s] [%s]", k->ce.err[0], k->ce.err[1]);
    }
    conn_close(k);
    k = conn_open(cother, sc, "localhost", -1, -1);
    m = hs_fail(k);
    CHECK(!strcmp(m, "certificate verify failed: self-signed certificate"), "%s", m);
    conn_close(k);

    /* Self-signed leaf, accepted by the callback, reported once. */
    k = conn_open(cv, ss, "localhost", 1, -1);
    if (hs_ok(k)) {
	CHECK(k->ce.calls == 1 && !k->ce.ok[0]
		&& !strcmp(k->ce.err[0], "self-signed certificate"), "self-signed: %s", k->ce.err[0]);
    }
    conn_close(k);

    /* Unknown issuer and a name mismatch: own errors win over inherited ones. */
    k = conn_open(cother, sc, "example.com", 1, -1);
    if (hs_ok(k)) {
	CHECK(k->ce.calls == 2 && !strcmp(k->ce.err[1], "hostname mismatch"),
		"[%s] [%s]", k->ce.err[0], k->ce.err[1]);
    }
    conn_close(k);

    /* errmsg with nothing recorded; read and write failures. */
    k = conn_open(cv, sc, "localhost", -1, -1);
    if (hs_ok(k)) {
	static const uint8_t junk[] = {0x17, 3, 3, 0, 20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
	    11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
	uint8_t buf[8];
	CHECK(!strcmp(tlsb_errmsg(k->c), "unknown error"), "%s", tlsb_errmsg(k->c));
	p_send(&k->se, junk, sizeof junk);
	CHECK(tlsb_read(k->c, buf, sizeof buf) == TLSB_ERROR
		&& !strncmp(tlsb_errmsg(k->c), "read failed: ", 13), "read: %s", tlsb_errmsg(k->c));
	CHECK(tlsb_read(k->s, buf, sizeof buf) == TLSB_ERROR
		&& contains(tlsb_errmsg(k->s), "peer sent alert: "), "alert: %s", tlsb_errmsg(k->s));
	printf("   %s | %s\n", tlsb_errmsg(k->c), tlsb_errmsg(k->s));
    }
    conn_close(k);
    tlsb_conf_free(sc);
    tlsb_conf_free(ss);
    tlsb_conf_free(cv);
    tlsb_conf_free(cother);
}

static int
alpn_is(tlsb_sess *s, const char *p)
{
    tlsb_info i;
    if (tlsb_info_get(s, &i) != TLSB_OK) {
	return 0;
    }
    return p ? i.alpn && i.alpn_len == strlen(p) && !memcmp(i.alpn, p, i.alpn_len) : !i.alpn;
}

/* No ALPN overlap continues without ALPN. */
static void
test_alpn(void)
{
    static const char *const s2[] = {"h2", "http/1.1"}, *c2[] = {"foo", "http/1.1"},
	*cfoo[] = {"foo"};
    tlsb_conf *sc = SERVER(.alpn = s2, .alpn_count = 2), *snone = SERVER(0);
    tlsb_conf *cc = CLIENT(.alpn = c2, .alpn_count = 2), *cfo = CLIENT(.alpn = cfoo, .alpn_count = 1);
    tlsb_conf *cnone = CLIENT(0), *cv = CLIENT(.require = 1, .ca = "ca-cert.pem",
	.alpn = cfoo, .alpn_count = 1);
    tlsb_conf *smtls = SERVER(.require = 1, .ca = "ca-cert.pem", .alpn = s2, .alpn_count = 2);
    tlsb_conf *ccert = CLIENT(.cert = "client-cert.pem", .key = "client-key.pem",
	.alpn = cfoo, .alpn_count = 1);
    conn_t *k;

    printf("-- alpn\n");
    k = conn_open(cc, sc, "localhost", -1, -1);
    if (hs_ok(k)) {
	CHECK(alpn_is(k->c, "http/1.1") && alpn_is(k->s, "http/1.1"), "server preference");
    }
    conn_close(k);
    for (int proto = TLSB_TLS12; proto <= TLSB_TLS13; proto <<= 1) {
	tlsb_conf *sp = SERVER(.protocols = proto, .alpn = s2, .alpn_count = 2);
	k = conn_open(cfo, sp, "localhost", -1, -1);
	if (hs_ok(k)) {
	    CHECK(alpn_is(k->c, NULL) && alpn_is(k->s, NULL), "no overlap");
	}
	conn_close(k);
	tlsb_conf_free(sp);
    }
    k = conn_open(cnone, sc, "localhost", -1, -1);
    if (hs_ok(k)) {
	CHECK(alpn_is(k->c, NULL) && alpn_is(k->s, NULL), "client offers none");
    }
    conn_close(k);
    k = conn_open(cfo, snone, "localhost", -1, -1);
    if (hs_ok(k)) {
	CHECK(alpn_is(k->c, NULL) && alpn_is(k->s, NULL), "server has none");
    }
    conn_close(k);
    /* With a verify callback on either side. */
    k = conn_open(cv, sc, "localhost", 1, -1);
    if (hs_ok(k)) {
	CHECK(alpn_is(k->c, NULL) && k->ce.calls == 1, "no overlap, client callback");
    }
    conn_close(k);
    k = conn_open(ccert, smtls, "localhost", -1, 1);
    if (hs_ok(k)) {
	CHECK(alpn_is(k->s, NULL) && k->se.calls == 1, "no overlap, server callback");
    }
    conn_close(k);
    tlsb_conf_free(sc);
    tlsb_conf_free(snone);
    tlsb_conf_free(cc);
    tlsb_conf_free(cfo);
    tlsb_conf_free(cnone);
    tlsb_conf_free(cv);
    tlsb_conf_free(smtls);
    tlsb_conf_free(ccert);
}

/* Cipher names and which option they may appear in. */
static void
test_cipher_rules(void)
{
    tlsb_conf *sc = SERVER(0), *cc;
    conn_t *k;
    tlsb_info i;

    printf("-- cipher rules\n");
    /* A TLS 1.2 name in ciphersuites disables TLS 1.3 only. */
    cc = CLIENT(.ciphersuites = "ECDHE-ECDSA-AES128-GCM-SHA256");
    CHECK(cc, "%s", conf_err);
    k = conn_open(cc, sc, "localhost", -1, -1);
    if (hs_ok(k)) {
	CHECK(tlsb_info_get(k->c, &i) == TLSB_OK && !strcmp(i.protocol, "TLS1.2"), "%s", i.protocol);
    }
    conn_close(k);
    tlsb_conf_free(cc);
    /* A TLS 1.3 name in ciphers disables TLS 1.2 only. */
    cc = CLIENT(.ciphers = "tls13_aes_256_gcm_sha384");
    k = conn_open(cc, sc, "localhost", -1, -1);
    if (hs_ok(k)) {
	CHECK(tlsb_info_get(k->c, &i) == TLSB_OK && !strcmp(i.protocol, "TLS1.3"), "%s", i.protocol);
    }
    conn_close(k);
    tlsb_conf_free(cc);
    /* Both kinds in one option, every separator, IANA with dashes. */
    cc = CLIENT(.ciphers = "TLS-AES-128-GCM-SHA256\ttls_ecdhe_ecdsa_with_aes_128_gcm_sha256\n"
	    "ECDHE-ECDSA-AES256-GCM-SHA384, ", .ciphersuites = "TLS_CHACHA20_POLY1305_SHA256");
    k = conn_open(cc, sc, "localhost", -1, -1);
    if (hs_ok(k)) {
	CHECK(tlsb_info_get(k->c, &i) == TLSB_OK
		&& !strcmp(i.cipher, "TLS_CHACHA20_POLY1305_SHA256"), "%s", i.cipher);
    }
    conn_close(k);
    tlsb_conf_free(cc);
    cc = CLIENT(.ciphers = "TLS_AES_128_GCM_SHA256", .protocols = TLSB_TLS12);
    CHECK(!cc && !strcmp(conf_err, "no usable cipher suites"), "%s", conf_err);
    cc = CLIENT(.ciphers = "", .ciphersuites = " ");
    CHECK(!cc && !strcmp(conf_err, "no usable cipher suites"), "%s", conf_err);
    cc = CLIENT(.ciphersuites = "TLS_AES_128_GCM_SHA256:NO-SUCH");
    CHECK(!cc && !strcmp(conf_err, "unknown cipher: NO-SUCH"), "%s", conf_err);
    tlsb_conf_free(sc);
}

/* Servername as seen on both ends. */
static void
test_servername(void)
{
    tlsb_conf *sc = SERVER(0), *cc = CLIENT(0);
    const char *names[] = {"localhost", "127.0.0.1", "::1", NULL};
    const char *want[] = {"localhost", NULL, NULL, NULL};
    tlsb_info ci, si;

    printf("-- servername\n");
    for (int n = 0; n < 4; n++) {
	conn_t *k = conn_open(cc, sc, names[n], -1, -1);
	if (hs_ok(k) && tlsb_info_get(k->c, &ci) == TLSB_OK && tlsb_info_get(k->s, &si) == TLSB_OK) {
	    CHECK((want[n] ? ci.servername && !strcmp(ci.servername, want[n]) : !ci.servername)
		    && (want[n] ? si.servername && !strcmp(si.servername, want[n]) : !si.servername),
		    "%s: %s / %s", names[n] ? names[n] : "NULL", ci.servername ? ci.servername : "NULL",
		    si.servername ? si.servername : "NULL");
	}
	conn_close(k);
    }
    tlsb_conf_free(sc);
    tlsb_conf_free(cc);
}

static int
resumed(tlsb_conf *cc, tlsb_conf *sc, const char *name, int cverify)
{
    tlsb_info ci, si;
    int r = -1;
    conn_t *k = conn_open(cc, sc, name, cverify, -1);
    if (hs_ok(k)) {
	xfer(k->s, k->c, 10);	/* TLS 1.3 tickets arrive after the handshake */
	xfer(k->c, k->s, 10);
	tlsb_info_get(k->c, &ci);
	tlsb_info_get(k->s, &si);
	CHECK(ci.resumed == si.resumed, "both ends agree");
	r = ci.resumed != 0;
    }
    conn_close(k);
    return r;
}

/* Tickets belong to the server conf; the client caches per servername. */
static void
test_resumption(void)
{
    for (int proto = TLSB_TLS12; proto <= TLSB_TLS13; proto <<= 1) {
	tlsb_conf *sc = SERVER(.protocols = proto), *sc2 = SERVER(.protocols = proto);
	tlsb_conf *cc = CLIENT(.require = 1, .ca = "ca-cert.pem");

	printf("-- resumption %s\n", proto == TLSB_TLS12 ? "TLS1.2" : "TLS1.3");
	CHECK(resumed(cc, sc, "localhost", -1) == 0, "first");
	CHECK(resumed(cc, sc, "localhost", -1) == 1, "second");
	CHECK(resumed(cc, sc, "127.0.0.1", -1) == 0, "other name");
	CHECK(resumed(cc, sc, NULL, -1) == 0, "no name");
	CHECK(resumed(cc, sc, NULL, -1) == 0, "no name again");
	CHECK(resumed(cc, sc, "localhost", 1) == 0, "verify callback");
	CHECK(resumed(cc, sc2, "localhost", -1) == 0, "other server conf");
	CHECK(resumed(cc, sc2, "localhost", -1) == 1, "other server conf again");
	tlsb_conf_free(sc);
	tlsb_conf_free(sc2);
	tlsb_conf_free(cc);
    }
}

/* WANT_READ only after recv returned 0. */
static void
test_want_read(void)
{
    tlsb_conf *sc = SERVER(0), *cc = CLIENT(0);
    conn_t *k;
    uint8_t buf[16];
    tlsb_io io = {NULL, p_recv, p_send, NULL};
    end_t e = {0};
    pipe_t in = {0}, out = {0};
    char err[256];
    tlsb_sess *s;

    printf("-- want read\n");
    e.in = &in, e.out = &out, io.ud = &e;
    s = tlsb_sess_new(sc, NULL, &io, err, sizeof err);
    e.last = 1;
    CHECK(s && tlsb_handshake(s) == TLSB_WANT_READ && e.last == 0, "server waits for hello");
    tlsb_sess_free(s);
    free(out.d);
    k = conn_open(cc, sc, "localhost", -1, -1);
    if (hs_ok(k)) {
	k->se.last = 1;
	CHECK(tlsb_read(k->s, buf, sizeof buf) == TLSB_WANT_READ && k->se.last == 0, "idle");
	/* Half a record buffered: pending may say yes, read must recv. */
	tlsb_write(k->c, (const uint8_t *)"helloworld", 10);
	k->c2s.len -= 10;
	k->se.last = 1;
	CHECK(tlsb_read(k->s, buf, sizeof buf) == TLSB_WANT_READ && k->se.last == 0, "partial");
	k->c2s.len += 10;
	CHECK(tlsb_read(k->s, buf, 5) == 5 && tlsb_pending(k->s), "pending after partial read");
	CHECK(tlsb_read(k->s, buf, sizeof buf) == 5 && !memcmp(buf, "world", 5), "rest");
    }
    conn_close(k);
    tlsb_conf_free(sc);
    tlsb_conf_free(cc);
}

/* One pair of confs, many sessions on several threads. */
static tlsb_conf *tcc, *tsc;

static void *
worker(void *arg)
{
    int id = (int)(size_t)arg;
    for (int i = 0; i < 8; i++) {
	conn_t *k = conn_open(tcc, tsc, (i + id) % 3 ? "localhost" : NULL,
		(i + id) & 1 ? 1 : -1, -1);
	if (hs_ok(k)) {
	    CHECK(xfer(k->c, k->s, 20000) && xfer(k->s, k->c, 20000), "thread data");
	}
	conn_close(k);
    }
    return NULL;
}

static void
test_threads(void)
{
    pthread_t t[6];

    printf("-- threads\n");
    tcc = CLIENT(.require = 0);		/* lazy system store */
    tsc = SERVER(.ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256");
    CHECK(tcc && tsc, "%s", conf_err);
    for (int i = 0; i < 6; i++) {
	pthread_create(&t[i], NULL, worker, (void *)(size_t)i);
    }
    for (int i = 0; i < 6; i++) {
	pthread_join(t[i], NULL);
    }
    tlsb_conf_free(tcc);
    tlsb_conf_free(tsc);
}

/*
 * A real server over a blocking socket.
 */

static long
s_recv(void *ud, uint8_t *buf, size_t len)
{
    ssize_t n = recv(*(int *)ud, buf, len, 0);
    return n > 0 ? n : -1;
}

static void
s_send(void *ud, const uint8_t *buf, size_t len)
{
    while (len) {
	ssize_t n = send(*(int *)ud, buf, len, 0);
	if (n <= 0) {
	    return;
	}
	buf += n, len -= n;
    }
}

static void
test_network(const char *host)
{
    struct addrinfo hints = {.ai_socktype = SOCK_STREAM}, *ai;
    int fd = -1;
    tlsb_conf *cc;
    tlsb_sess *s;
    tlsb_io io = {&fd, s_recv, s_send, NULL};
    tlsb_info i;
    char err[256], req[256], buf[4096];
    long n, total = 0;

    printf("-- network %s\n", host);
    if (getaddrinfo(host, "443", &hints, &ai)) {
	printf("   SKIP: cannot resolve %s\n", host);
	return;
    }
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (connect(fd, ai->ai_addr, ai->ai_addrlen)) {
	printf("   SKIP: cannot connect\n");
	close(fd);
	freeaddrinfo(ai);
	return;
    }
    freeaddrinfo(ai);
    cc = CLIENT(.require = 1, .alpn = ALPN_C + 1, .alpn_count = 1);
    s = tlsb_sess_new(cc, host, &io, err, sizeof err);
    if (CHECK(s, "%s", err) && CHECK(tlsb_handshake(s) == TLSB_OK, "%s", tlsb_errmsg(s))) {
	tlsb_info_get(s, &i);
	printf("   %s %s\n", i.protocol, i.cipher);
	snprintf(req, sizeof req, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
	CHECK(tlsb_write(s, (const uint8_t *)req, strlen(req)) == (long)strlen(req), "write");
	n = tlsb_read(s, (uint8_t *)buf, sizeof buf - 1);
	CHECK(n > 12 && !memcmp(buf, "HTTP/1.1 ", 9), "response");
	while (n > 0) {
	    total += n;
	    n = tlsb_read(s, (uint8_t *)buf, sizeof buf);
	}
	CHECK(n == 0, "clean EOF, got %ld: %s", n, tlsb_errmsg(s));
	printf("   %ld bytes\n", total);
    }
    tlsb_sess_free(s);
    tlsb_conf_free(cc);
    close(fd);
}

int
main(int argc, char **argv)
{
    const char *hosts[16] = {"www.google.com"};
    int net = 1, nhosts = 0;

    if (argc < 2) {
	fprintf(stderr, "usage: %s certdir [pkidir] [-nonet] [-host name]...\n", argv[0]);
	return 2;
    }
    dir = certdir = argv[1];
    for (int i = 2; i < argc; i++) {
	if (!strcmp(argv[i], "-nonet")) {
	    net = 0;
	} else if (!strcmp(argv[i], "-host") && i + 1 < argc && nhosts < 16) {
	    hosts[nhosts++] = argv[++i];
	} else {
	    pkidir = argv[i];
	}
    }
    test_library();
    test_basic(TLSB_TLS13, "TLS1.3");
    test_basic(TLSB_TLS12, "TLS1.2");
    test_io_edges();
    test_verify();
    test_callback();
    test_depths();
    test_mtls();
    test_credentials();
    test_ciphers();
    test_cipher_rules();
    test_alpn();
    test_servername();
    test_resumption();
    test_want_read();
    test_crypto();
    test_threads();
    if (pkidir) {
	test_expired();
    }
    for (int i = 0; net && i < (nhosts ? nhosts : 1); i++) {
	test_network(hosts[i]);
    }
    printf("%d passed, %d failed\n", passed, failed);
    return failed != 0;
}
