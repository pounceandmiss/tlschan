/*
 * tlsb.h --
 *
 *	Interface between the Tcl channel layer and a TLS backend.
 *	Backends know nothing about Tcl: all transport goes through tlsb_io,
 *	all configuration arrives as plain memory in tlsb_opts.
 */

#ifndef TLSB_H
#define TLSB_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes. Operations returning a byte count use these when < 0. */
#define TLSB_OK		0
#define TLSB_ERROR	(-1)
#define TLSB_WANT_READ	(-2)

/* Protocol bits. */
#define TLSB_TLS12	(1 << 0)
#define TLSB_TLS13	(1 << 1)

/* Digest algorithms. */
#define TLSB_SHA1	0
#define TLSB_SHA256	1
#define TLSB_SHA512	2

typedef struct tlsb_conf tlsb_conf;
typedef struct tlsb_sess tlsb_sess;

typedef struct tlsb_opts {
    int server;
    int request;		/* server: ask for a client certificate */
    int require;		/* fail unless the peer chain verifies */
    unsigned protocols;		/* TLSB_TLS12 | TLSB_TLS13; 0 means both */

    /* Blobs with length 0 count as absent. */
    const uint8_t *ca;		/* PEM bundle or one DER cert, may be NULL */
    size_t ca_len;
    const char *cadir;		/* directory of PEM certs, may be NULL */

    const uint8_t *cert;	/* PEM chain or one DER cert, may be NULL */
    size_t cert_len;
    const uint8_t *key;		/* PEM or DER private key, may be NULL */
    size_t key_len;
    const char *password;	/* for an encrypted key, may be NULL */

    /*
     * Suite names, IANA (also with '-' for '_'), OpenSSL or the library's,
     * separated by ':' ',' or white space; either protocol's names may
     * appear in either field. A field that leaves a protocol no suites
     * disables it.
     */
    const char *ciphers;	/* meant for TLS 1.2 */
    const char *ciphersuites;	/* meant for TLS 1.3 */
    const char *const *alpn;	/* protocols in preference order */
    int alpn_count;
} tlsb_opts;

/*
 * Transport and policy hooks supplied by the channel layer.
 * Without ca/cadir the backend trusts the system store.
 */
typedef struct tlsb_io {
    void *ud;
    /* > 0 bytes read, 0 nothing available now, -1 EOF or error. */
    long (*recv)(void *ud, uint8_t *buf, size_t len);
    /* Takes all of buf; the caller buffers what the transport refuses. */
    void (*send)(void *ud, const uint8_t *buf, size_t len);
    /*
     * Optional. Called for each certificate the peer sent, from the highest
     * depth down to 0, with the backend's verdict; returns the final one.
     * Sessions with a verify hook are never resumed.
     */
    int (*verify)(void *ud, int depth, const uint8_t *der, size_t len,
	    int ok, const char *err);
} tlsb_io;

typedef struct tlsb_info {
    const char *protocol;	/* "TLS1.2", "TLS1.3" */
    const char *cipher;		/* IANA suite name */
    int cipher_bits;
    const uint8_t *alpn;	/* negotiated, NULL if none */
    size_t alpn_len;
    const char *servername;	/* SNI sent (client) or received (server),
				 * NULL if none */
    int resumed;
} tlsb_info;

/* Library. Error buffers receive a NUL terminated message. */
int		tlsb_global_init(char *err, size_t errlen);
const char *	tlsb_version(void);		/* e.g. "wolfSSL 5.9.4" */
unsigned	tlsb_protocols(void);
void		tlsb_ciphers(unsigned protocols,
		    void (*cb)(void *ud, const char *name), void *ud);

/* Configuration, shared by sessions; the conf must outlive them. */
tlsb_conf *	tlsb_conf_new(const tlsb_opts *opts, char *err, size_t errlen);
void		tlsb_conf_free(tlsb_conf *conf);

/* Sessions. servername (client) is the SNI and verified name, or NULL. */
tlsb_sess *	tlsb_sess_new(tlsb_conf *conf, const char *servername,
		    const tlsb_io *io, char *err, size_t errlen);
void		tlsb_sess_free(tlsb_sess *s);
const char *	tlsb_errmsg(tlsb_sess *s);	/* after TLSB_ERROR */

/*
 * TLSB_WANT_READ from handshake and read only once recv has returned 0 in
 * that call: the layer then waits for the socket to become readable.
 */
int		tlsb_handshake(tlsb_sess *s);	/* OK, WANT_READ, ERROR */
/*
 * > 0 bytes, 0 EOF (close_notify or transport EOF), WANT_READ, ERROR.
 * A TLS 1.3 client learns that the server refused its certificate here.
 */
long		tlsb_read(tlsb_sess *s, uint8_t *buf, size_t len);
/* Bytes accepted (all of them) or ERROR. Handshake must be done. */
long		tlsb_write(tlsb_sess *s, const uint8_t *buf, size_t len);
/* Nonzero if tlsb_read may make progress without recv; it may still
 * return WANT_READ when only part of a record is buffered. */
int		tlsb_pending(tlsb_sess *s);
void		tlsb_close_notify(tlsb_sess *s);

/* Valid after the handshake; its pointers live as long as the session. */
int		tlsb_info_get(tlsb_sess *s, tlsb_info *info);
/* depth 0 is the leaf. TLSB_OK or TLSB_ERROR if absent; the DER lives as
 * long as the session. */
int		tlsb_peer_cert(tlsb_sess *s, int depth, const uint8_t **der,
		    size_t *len);
int		tlsb_local_cert(tlsb_sess *s, const uint8_t **der, size_t *len);
/* RFC 5705 / RFC 8446 7.5 exporter. */
int		tlsb_export(tlsb_sess *s, const char *label, size_t label_len,
		    const uint8_t *ctx, size_t ctx_len, int use_ctx,
		    uint8_t *out, size_t out_len);

/* Crypto helpers. Return TLSB_OK or TLSB_ERROR. */
int		tlsb_random(uint8_t *buf, size_t len);
int		tlsb_digest(int alg, const uint8_t *data, size_t len,
		    uint8_t *out);	/* out holds 64 bytes */
int		tlsb_pbkdf2(int alg, const uint8_t *pw, size_t pw_len,
		    const uint8_t *salt, size_t salt_len, uint32_t iterations,
		    uint8_t *out, size_t out_len);
/* out: len + 16 bytes (ciphertext || tag). */
int		tlsb_aes256gcm_seal(const uint8_t key[32],
		    const uint8_t nonce[12], const uint8_t *in, size_t len,
		    uint8_t *out);
/* in: ciphertext || tag, len >= 16; out: len - 16 bytes. */
int		tlsb_aes256gcm_open(const uint8_t key[32],
		    const uint8_t nonce[12], const uint8_t *in, size_t len,
		    uint8_t *out);

#ifdef _WIN32
/*
 * Provided for the backends (generic/winroot.c): if Windows trusts the peer
 * chain (leaf first), fetching certificates if need be, calls add with its
 * root (root 1), then each intermediate the peer did not send (root 0), top
 * down. Only the root is to be trusted; intermediates only help build this
 * chain. Returns the count.
 */
int		tlsb_win_chain(const uint8_t *const *der, const size_t *len,
		    int n, int server,
		    void (*add)(void *ud, const uint8_t *der, size_t len,
			int root),
		    void *ud);
#endif

#ifdef __cplusplus
}
#endif

#endif /* TLSB_H */
