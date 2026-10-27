/*
 * test_x509.c --
 *
 *	Standalone driver for TlsX509Info.
 *
 *	test_x509 dump FILE...		print the dict
 *	test_x509 compat FILE		print fields in `openssl x509` style
 *	test_x509 fuzz N FILE...	N mutations per file (run under ASan)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "x509.h"
#include "tlsb.h"

int
tlsb_digest(
    int alg,
    const uint8_t *data,
    size_t len,
    uint8_t *out)
{
    const EVP_MD *md = alg == TLSB_SHA1 ? EVP_sha1()
	    : alg == TLSB_SHA256 ? EVP_sha256() : EVP_sha512();

    return EVP_Digest(data, len, out, NULL, md, NULL) ? TLSB_OK : TLSB_ERROR;
}

/* Reads FILE; PEM is converted to DER (first certificate only). */

static unsigned char *
Load(
    const char *path,
    size_t *lenPtr)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf, *der;
    char *b, *e;
    long n;
    int k;

    if (!f) {
	perror(path);
	exit(2);
    }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    rewind(f);
    buf = malloc(n + 1);
    if (fread(buf, 1, n, f) != (size_t) n) {
	exit(2);
    }
    fclose(f);
    buf[n] = 0;
    if (!(b = strstr((char *) buf, "-----BEGIN CERTIFICATE-----"))) {
	*lenPtr = n;
	return buf;
    }
    b = strchr(b, '\n') + 1;
    e = strstr(b, "-----END");
    der = malloc(e - b);
    {
	EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
	int m;

	EVP_DecodeInit(ctx);
	EVP_DecodeUpdate(ctx, der, &k, (unsigned char *) b, (int) (e - b));
	EVP_DecodeFinal(ctx, der + k, &m);
	EVP_ENCODE_CTX_free(ctx);
	k += m;
    }
    free(buf);
    *lenPtr = k;
    return der;
}

static const char *
Get(
    Tcl_Obj *dict,
    const char *key)
{
    Tcl_Obj *k = Tcl_NewStringObj(key, -1), *v = NULL;

    Tcl_IncrRefCount(k);
    Tcl_DictObjGet(NULL, dict, k, &v);
    Tcl_DecrRefCount(k);
    return v ? Tcl_GetString(v) : NULL;
}

static void
List(
    Tcl_Obj *dict,
    const char *key,
    const char *label,
    const char *sep)
{
    Tcl_Obj *k = Tcl_NewStringObj(key, -1), *v = NULL, **elv;
    Tcl_Size i, elc;

    Tcl_DictObjGet(NULL, dict, k, &v);
    Tcl_DecrRefCount(k);
    if (!v || Tcl_ListObjGetElements(NULL, v, &elc, &elv) != TCL_OK) {
	return;
    }
    printf("%s", label);
    for (i = 0; i < elc; i++) {
	printf("%s%s", i ? sep : "", Tcl_GetString(elv[i]));
    }
    printf("\n");
}

static void
Compat(
    Tcl_Obj *d)
{
    const char *s;

    printf("subject=%s\nissuer=%s\nnotBefore=%s\nnotAfter=%s\nserial=%s\n",
	    Get(d, "subject"), Get(d, "issuer"), Get(d, "notBefore"),
	    Get(d, "notAfter"), Get(d, "serialNumber"));
    printf("sha1=%s\nsha256=%s\n", Get(d, "sha1_hash"), Get(d, "sha256_hash"));
    printf("sigalg=%s\nkeyalg=%s\n", Get(d, "signatureAlgorithm"),
	    Get(d, "publicKeyAlgorithm"));
    if ((s = Get(d, "bits"))) {
	printf("bits=%s\n", s);
    }
    List(d, "subjectAltName", "san=", ", ");
    if ((s = Get(d, "subjectKeyIdentifier"))) {
	printf("ski=%s\n", s);
    }
    if ((s = Get(d, "authorityKeyIdentifier"))) {
	printf("aki=%s\n", s);
    }
    List(d, "ocsp", "ocsp=", " ");
    printf("ca=%s\n", strcmp(Get(d, "ca"), "1") == 0 ? "TRUE" : "FALSE");
    printf("pem=%s", Get(d, "certificate"));
}

/* xorshift64 */
static unsigned long long rs = 88172645463325252ULL;

static unsigned
Rand(void)
{
    rs ^= rs << 13;
    rs ^= rs >> 7;
    rs ^= rs << 17;
    return (unsigned) (rs >> 11);
}

static void
Fuzz(
    const unsigned char *der,
    size_t len,
    long iters)
{
    unsigned char *buf;
    long i;
    size_t n, j, k;

    for (i = 0; i < iters; i++) {
	Tcl_Obj *d = Tcl_NewDictObj();

	n = len;
	switch (i % 4) {
	case 0:				/* truncation, exact copy */
	    n = i / 4 < (long) len ? (size_t) (i / 4) : Rand() % (len + 1);
	    break;
	case 1: case 2:			/* byte flips */
	    break;
	case 3:				/* splice: drop a random range */
	    break;
	}
	buf = malloc(n ? n : 1);
	memcpy(buf, der, n);
	if (i % 4 == 1 || i % 4 == 2) {
	    for (k = 1 + Rand() % (i % 4 == 1 ? 2 : 16); k--; ) {
		j = Rand() % len;
		buf[j] = Rand() % 3 ? (unsigned char) Rand()
			: (unsigned char) (buf[j] ^ (1u << (Rand() % 8)));
	    }
	} else if (i % 4 == 3 && len > 2) {
	    size_t a = Rand() % len, b = a + Rand() % (len - a);

	    memmove(buf + a, buf + b, len - b);
	    n = len - (b - a);
	    buf = realloc(buf, n ? n : 1);
	}
	Tcl_IncrRefCount(d);
	TlsX509Info(NULL, buf, n, d);
	Tcl_GetString(d);		/* exercise the string reps */
	Tcl_DecrRefCount(d);
	free(buf);
    }
}

int
main(
    int argc,
    char **argv)
{
    Tcl_Interp *interp;
    unsigned char *der;
    size_t len;
    int i, rc = 0;

    Tcl_FindExecutable(argv[0]);
    interp = Tcl_CreateInterp();
    if (argc < 3) {
	fprintf(stderr, "usage: %s dump|compat|fuzz ...\n", argv[0]);
	return 2;
    }
    if (strcmp(argv[1], "fuzz") == 0) {
	long n = atol(argv[2]);

	for (i = 3; i < argc; i++) {
	    der = Load(argv[i], &len);
	    Fuzz(der, len, n);
	    free(der);
	}
	printf("fuzz: %d files x %ld iterations ok\n", argc - 3, n);
	return 0;
    }
    for (i = 2; i < argc; i++) {
	Tcl_Obj *d = Tcl_NewDictObj();

	Tcl_IncrRefCount(d);
	der = Load(argv[i], &len);
	if (TlsX509Info(interp, der, len, d) != TCL_OK) {
	    printf("%s: error: %s\n", argv[i], Tcl_GetStringResult(interp));
	    rc = 1;
	} else if (strcmp(argv[1], "compat") == 0) {
	    Compat(d);
	} else {
	    Tcl_Obj *k, *v;
	    Tcl_DictSearch s;
	    int done;

	    printf("== %s\n", argv[i]);
	    Tcl_DictObjFirst(NULL, d, &s, &k, &v, &done);
	    for (; !done; Tcl_DictObjNext(&s, &k, &v, &done)) {
		printf("%-24s %s\n", Tcl_GetString(k), Tcl_GetString(v));
	    }
	}
	Tcl_DecrRefCount(d);
	free(der);
    }
    Tcl_DeleteInterp(interp);
    return rc;
}
