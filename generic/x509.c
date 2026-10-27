/*
 * x509.c --
 *
 *	Minimal X.509 DER decoder. The input is untrusted: every read is
 *	bounds checked, there is no recursion, and fields that fail to
 *	decode are omitted rather than reported.
 */

#include <string.h>
#include "x509.h"
#include "tlsb.h"

/* Universal tags. */
#define T_BOOL		0x01
#define T_INT		0x02
#define T_BITS		0x03
#define T_OCTETS	0x04
#define T_OID		0x06
#define T_UTF8		0x0c
#define T_NUMERIC	0x12
#define T_PRINTABLE	0x13
#define T_TELETEX	0x14
#define T_IA5		0x16
#define T_UTCTIME	0x17
#define T_GENTIME	0x18
#define T_VISIBLE	0x1a
#define T_UNIVERSAL	0x1c
#define T_BMP		0x1e
#define T_SEQ		0x30
#define T_SET		0x31
#define T_CTX(n)	(0x80 | (n))	/* context, primitive */
#define T_CTXC(n)	(0xa0 | (n))	/* context, constructed */

#define OIDBUF		128

static const char hex[] = "0123456789ABCDEF";

typedef struct {
    const unsigned char *p, *end;
} Der;

/*
 * Reads the next TLV of d into v (contents) and tlv (whole element, may be
 * NULL). Returns the tag, or -1 without consuming anything on error.
 */

static int
DerGet(
    Der *d,
    Der *v,
    Der *tlv)
{
    const unsigned char *p = d->p;
    size_t n, k;
    int tag;

    if (d->end - p < 2 || (p[0] & 0x1f) == 0x1f) {
	return -1;
    }
    tag = *p++;
    n = *p++;
    if (n & 0x80) {
	k = n & 0x7f;
	if (k == 0 || k > 4 || (size_t)(d->end - p) < k) {
	    return -1;			/* indefinite or absurd length */
	}
	for (n = 0; k--; ) {
	    n = (n << 8) | *p++;
	}
    }
    if (n > (size_t)(d->end - p)) {
	return -1;
    }
    v->p = p;
    v->end = p + n;
    if (tlv) {
	tlv->p = d->p;
	tlv->end = v->end;
    }
    d->p = v->end;
    return tag;
}

/* Like DerGet but only consumes an element with the given tag. */

static int
DerTake(
    Der *d,
    int tag,
    Der *v,
    Der *tlv)
{
    Der save = *d;

    if (DerGet(d, v, tlv) == tag) {
	return 1;
    }
    *d = save;
    return 0;
}

static inline size_t
DerLen(
    const Der *d)
{
    return (size_t)(d->end - d->p);
}

/*
 * Object identifiers.
 */

static const struct {
    const char *oid, *name;
    int bits;			/* curve size for EC curves */
} oids[] = {
    /* Attribute types. */
    {"2.5.4.3", "CN", 0}, {"2.5.4.4", "SN", 0},
    {"2.5.4.5", "serialNumber", 0}, {"2.5.4.6", "C", 0},
    {"2.5.4.7", "L", 0}, {"2.5.4.8", "ST", 0}, {"2.5.4.9", "street", 0},
    {"2.5.4.10", "O", 0}, {"2.5.4.11", "OU", 0}, {"2.5.4.12", "title", 0},
    {"2.5.4.13", "description", 0}, {"2.5.4.15", "businessCategory", 0},
    {"2.5.4.17", "postalCode", 0}, {"2.5.4.42", "GN", 0},
    {"2.5.4.43", "initials", 0}, {"2.5.4.44", "generationQualifier", 0},
    {"2.5.4.46", "dnQualifier", 0}, {"2.5.4.65", "pseudonym", 0},
    {"2.5.4.97", "organizationIdentifier", 0},
    {"1.2.840.113549.1.9.1", "emailAddress", 0},
    {"0.9.2342.19200300.100.1.1", "UID", 0},
    {"0.9.2342.19200300.100.1.25", "DC", 0},
    {"1.3.6.1.4.1.311.60.2.1.1", "jurisdictionL", 0},
    {"1.3.6.1.4.1.311.60.2.1.2", "jurisdictionST", 0},
    {"1.3.6.1.4.1.311.60.2.1.3", "jurisdictionC", 0},
    /* Public key and signature algorithms. */
    {"1.2.840.113549.1.1.1", "rsaEncryption", 0},
    {"1.2.840.113549.1.1.2", "md2WithRSAEncryption", 0},
    {"1.2.840.113549.1.1.4", "md5WithRSAEncryption", 0},
    {"1.2.840.113549.1.1.5", "sha1WithRSAEncryption", 0},
    {"1.2.840.113549.1.1.10", "rsassaPss", 0},
    {"1.2.840.113549.1.1.11", "sha256WithRSAEncryption", 0},
    {"1.2.840.113549.1.1.12", "sha384WithRSAEncryption", 0},
    {"1.2.840.113549.1.1.13", "sha512WithRSAEncryption", 0},
    {"1.2.840.113549.1.1.14", "sha224WithRSAEncryption", 0},
    {"1.2.840.10040.4.1", "dsaEncryption", 0},
    {"1.2.840.10040.4.3", "dsaWithSHA1", 0},
    {"2.16.840.1.101.3.4.3.1", "dsa_with_SHA224", 0},
    {"2.16.840.1.101.3.4.3.2", "dsa_with_SHA256", 0},
    {"1.2.840.10045.2.1", "id-ecPublicKey", 0},
    {"1.2.840.10045.4.1", "ecdsa-with-SHA1", 0},
    {"1.2.840.10045.4.3.1", "ecdsa-with-SHA224", 0},
    {"1.2.840.10045.4.3.2", "ecdsa-with-SHA256", 0},
    {"1.2.840.10045.4.3.3", "ecdsa-with-SHA384", 0},
    {"1.2.840.10045.4.3.4", "ecdsa-with-SHA512", 0},
    {"1.3.101.110", "X25519", 253}, {"1.3.101.111", "X448", 448},
    {"1.3.101.112", "ED25519", 256}, {"1.3.101.113", "ED448", 456},
    {"2.16.840.1.101.3.4.3.17", "ML-DSA-44", 0},
    {"2.16.840.1.101.3.4.3.18", "ML-DSA-65", 0},
    {"2.16.840.1.101.3.4.3.19", "ML-DSA-87", 0},
    /* Named curves. */
    {"1.2.840.10045.3.1.1", "prime192v1", 192},
    {"1.2.840.10045.3.1.7", "prime256v1", 256},
    {"1.3.132.0.10", "secp256k1", 256}, {"1.3.132.0.33", "secp224r1", 224},
    {"1.3.132.0.34", "secp384r1", 384}, {"1.3.132.0.35", "secp521r1", 521},
    {"1.3.36.3.3.2.8.1.1.7", "brainpoolP256r1", 256},
    {"1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1", 384},
    {"1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1", 512},
    /* Extensions. */
    {"2.5.29.9", "subjectDirectoryAttributes", 0},
    {"2.5.29.14", "subjectKeyIdentifier", 0}, {"2.5.29.15", "keyUsage", 0},
    {"2.5.29.16", "privateKeyUsagePeriod", 0},
    {"2.5.29.17", "subjectAltName", 0}, {"2.5.29.18", "issuerAltName", 0},
    {"2.5.29.19", "basicConstraints", 0},
    {"2.5.29.30", "nameConstraints", 0},
    {"2.5.29.31", "crlDistributionPoints", 0},
    {"2.5.29.32", "certificatePolicies", 0},
    {"2.5.29.33", "policyMappings", 0},
    {"2.5.29.35", "authorityKeyIdentifier", 0},
    {"2.5.29.36", "policyConstraints", 0},
    {"2.5.29.37", "extendedKeyUsage", 0}, {"2.5.29.46", "freshestCRL", 0},
    {"2.5.29.54", "inhibitAnyPolicy", 0},
    {"1.3.6.1.5.5.7.1.1", "authorityInfoAccess", 0},
    {"1.3.6.1.5.5.7.1.11", "subjectInfoAccess", 0},
    {"1.3.6.1.5.5.7.1.24", "tlsfeature", 0},
    {"1.3.6.1.4.1.11129.2.4.2", "ct_precert_scts", 0},
    {"1.3.6.1.4.1.11129.2.4.3", "ct_precert_poison", 0},
    {"2.16.840.1.113730.1.1", "nsCertType", 0},
    {"2.16.840.1.113730.1.13", "nsComment", 0},
    {NULL, NULL, 0}
};

#define OID_OCSP	"1.3.6.1.5.5.7.48.1"

/* Dotted form of an OID's contents into buf, or NULL if malformed. */

static const char *
OidText(
    const Der *o,
    char *buf)
{
    const unsigned char *p = o->p;
    char *q = buf, tmp[24];
    unsigned long long v = 0;
    int first = 1, n;

    if (p >= o->end || (o->end[-1] & 0x80)) {
	return NULL;
    }
    for (; p < o->end; p++) {
	if (v > (~0ULL >> 7) || (v == 0 && *p == 0x80)) {
	    return NULL;		/* overflow or non-minimal */
	}
	v = (v << 7) | (*p & 0x7f);
	if (*p & 0x80) {
	    continue;
	}
	if (first) {
	    int a = v < 40 ? 0 : v < 80 ? 1 : 2;

	    n = snprintf(tmp, sizeof(tmp), "%d.%llu", a, v - 40ULL * a);
	    first = 0;
	} else {
	    n = snprintf(tmp, sizeof(tmp), ".%llu", v);
	}
	if (n >= OIDBUF - (q - buf)) {
	    return NULL;
	}
	memcpy(q, tmp, n + 1);
	q += n;
	v = 0;
    }
    return buf;
}

static int
OidFind(
    const char *dotted)
{
    int i;

    for (i = 0; dotted && oids[i].oid; i++) {
	if (strcmp(oids[i].oid, dotted) == 0) {
	    return i;
	}
    }
    return -1;
}

/* Name for an OID, dotted if unknown, NULL if malformed. */

static const char *
OidName(
    const Der *o,
    char *buf)
{
    const char *t = OidText(o, buf);
    int i = OidFind(t);

    return i >= 0 ? oids[i].name : t;
}

/*
 * Strings.
 */

static int
IsString(
    int tag)
{
    switch (tag) {
    case T_UTF8: case T_NUMERIC: case T_PRINTABLE: case T_TELETEX:
    case T_IA5: case T_VISIBLE: case T_UNIVERSAL: case T_BMP:
	return 1;
    }
    return 0;
}

/* Decodes one character of a string of the given type; 0 at the end. */

static int
NextChar(
    int tag,
    Der *s,
    int *cp)
{
    const unsigned char *p = s->p;
    size_t left = DerLen(s);
    int c, n, min;

    if (left == 0) {
	return 0;
    }
    switch (tag) {
    case T_BMP:
	if (left < 2) {
	    s->p = s->end;
	    *cp = 0xfffd;
	    return 1;
	}
	c = p[0] << 8 | p[1];
	p += 2;
	if (c >= 0xd800 && c < 0xdc00 && left >= 4
		&& p[0] >= 0xdc && p[0] < 0xe0) {
	    c = 0x10000 + ((c - 0xd800) << 10) + ((p[0] << 8 | p[1]) - 0xdc00);
	    p += 2;
	} else if (c >= 0xd800 && c < 0xe000) {
	    c = 0xfffd;
	}
	break;
    case T_UNIVERSAL:
	if (left < 4) {
	    s->p = s->end;
	    *cp = 0xfffd;
	    return 1;
	}
	c = p[0] ? 0x110000 : (p[1] << 16 | p[2] << 8 | p[3]);
	p += 4;
	if (c > 0x10ffff || (c >= 0xd800 && c < 0xe000)) {
	    c = 0xfffd;
	}
	break;
    case T_UTF8:
	c = *p++;
	if (c < 0x80) {
	    break;
	}
	n = c >= 0xf0 ? 3 : c >= 0xe0 ? 2 : c >= 0xc0 ? 1 : 0;
	min = n == 3 ? 0x10000 : n == 2 ? 0x800 : 0x80;
	if (n == 0 || c >= 0xf8 || (size_t) n >= left) {
	    c = 0xfffd;
	    break;
	}
	c &= 0x3f >> n;
	for (; n; n--, p++) {
	    if ((*p & 0xc0) != 0x80) {
		break;
	    }
	    c = (c << 6) | (*p & 0x3f);
	}
	if (n || c < min || c > 0x10ffff || (c >= 0xd800 && c < 0xe000)) {
	    p = s->p + 1;
	    c = 0xfffd;
	}
	break;
    default:			/* ASCII subsets and T.61 as Latin-1 */
	c = *p++;
	break;
    }
    s->p = p;
    *cp = c;
    return 1;
}

/* Appends cp as (Tcl internal) UTF-8: NUL becomes C0 80. */

static void
PutChar(
    Tcl_DString *ds,
    int c)
{
    char b[4];
    int n;

    if (c > 0 && c < 0x80) {
	b[0] = (char) c;
	n = 1;
    } else if (c < 0x800) {
	b[0] = (char) (0xc0 | c >> 6);
	b[1] = (char) (0x80 | (c & 0x3f));
	n = 2;
    } else if (c < 0x10000) {
	b[0] = (char) (0xe0 | c >> 12);
	b[1] = (char) (0x80 | ((c >> 6) & 0x3f));
	b[2] = (char) (0x80 | (c & 0x3f));
	n = 3;
    } else {
	b[0] = (char) (0xf0 | c >> 18);
	b[1] = (char) (0x80 | ((c >> 12) & 0x3f));
	b[2] = (char) (0x80 | ((c >> 6) & 0x3f));
	b[3] = (char) (0x80 | (c & 0x3f));
	n = 4;
    }
    Tcl_DStringAppend(ds, b, n);
}

static void
PutHex(
    Tcl_DString *ds,
    const unsigned char *p,
    size_t n)
{
    char b[2];

    for (; n; n--, p++) {
	b[0] = hex[*p >> 4];
	b[1] = hex[*p & 15];
	Tcl_DStringAppend(ds, b, 2);
    }
}

/* Appends a string value; esc applies RFC 4514 escaping. */

static void
PutString(
    Tcl_DString *ds,
    int tag,
    const Der *v,
    int esc)
{
    Der s = *v;
    int c, first = 1;
    unsigned char b;

    while (NextChar(tag, &s, &c)) {
	if (esc) {
	    if (c > 0 && c < 0x80 && strchr(",+\"\\<>;", c)) {
		Tcl_DStringAppend(ds, "\\", 1);
	    } else if ((c == '#' && first)
		    || (c == ' ' && (first || s.p == s.end))) {
		Tcl_DStringAppend(ds, "\\", 1);
	    } else if (c < 0x20 || c == 0x7f) {
		b = (unsigned char) c;
		Tcl_DStringAppend(ds, "\\", 1);
		PutHex(ds, &b, 1);
		first = 0;
		continue;
	    }
	}
	PutChar(ds, c);
	first = 0;
    }
}

static Tcl_Obj *
HexObj(
    const unsigned char *p,
    size_t n)
{
    Tcl_DString ds;

    Tcl_DStringInit(&ds);
    PutHex(&ds, p, n);
    return Tcl_DStringToObj(&ds);
}

/*
 * Names.
 */

/*
 * Formats a Name in OpenSSL's RFC 2253 style: AVAs in reverse order, RDNs
 * separated by ',' and multi-valued RDN members by '+'. With oneline, the
 * X509_NAME_oneline style instead: "/CN=a/O=b", forward, unescaped.
 */

static Tcl_Obj *
NameObj(
    const Der *name,
    int oneline)
{
    Der d = *name, rdn, ava, oid, val, tlv;
    Tcl_Obj *avas = Tcl_NewListObj(0, NULL), **elv;
    Tcl_DString ds;
    Tcl_Size i, elc;
    char buf[OIDBUF];
    const char *type;
    int tag;
    char sep;

    Tcl_IncrRefCount(avas);
    while (DerTake(&d, T_SET, &rdn, NULL)) {
	sep = oneline ? '/' : ',';
	for (; DerTake(&rdn, T_SEQ, &ava, NULL); sep = '+') {
	    if (!DerTake(&ava, T_OID, &oid, NULL)
		    || (tag = DerGet(&ava, &val, &tlv)) < 0
		    || !(type = OidName(&oid, buf))) {
		continue;
	    }
	    /* Leading byte is the separator used before this AVA. */
	    Tcl_DStringInit(&ds);
	    Tcl_DStringAppend(&ds, &sep, 1);
	    Tcl_DStringAppend(&ds, type, -1);
	    Tcl_DStringAppend(&ds, "=", 1);
	    if (type != buf && IsString(tag)) {
		PutString(&ds, tag, &val, !oneline);
	    } else {			/* unknown: hex dump of the DER */
		Tcl_DStringAppend(&ds, "#", 1);
		PutHex(&ds, tlv.p, DerLen(&tlv));
	    }
	    Tcl_ListObjAppendElement(NULL, avas, Tcl_DStringToObj(&ds));
	}
    }
    Tcl_DStringInit(&ds);
    Tcl_ListObjGetElements(NULL, avas, &elc, &elv);
    for (i = 0; oneline && i < elc; i++) {
	Tcl_DStringAppend(&ds, Tcl_GetString(elv[i]), -1);
    }
    for (i = elc - 1; !oneline && i >= 0; i--) {
	Tcl_Size n;
	const char *s = Tcl_GetStringFromObj(elv[i], &n);

	Tcl_DStringAppend(&ds, s + 1, n - 1);
	if (i > 0) {
	    Tcl_DStringAppend(&ds, s, 1);
	}
    }
    Tcl_DecrRefCount(avas);
    return Tcl_DStringToObj(&ds);
}

/*
 * Field decoders.
 */

static int
Digits(
    const unsigned char *p,
    int n)
{
    int v = 0;

    while (n--) {
	if (*p < '0' || *p > '9') {
	    return -1;
	}
	v = v * 10 + (*p++ - '0');
    }
    return v;
}

/* UTCTime or GeneralizedTime as "Mon DD HH:MM:SS[.f] YYYY GMT". */

static Tcl_Obj *
TimeObj(
    int tag,
    const Der *t)
{
    static const char mon[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    const unsigned char *p = t->p;
    size_t n = DerLen(t), fl = 0;
    int y, m, d, hh, mm, ss;
    char buf[64];

    if (tag == T_UTCTIME && n == 13) {
	y = Digits(p, 2);
	y += y < 0 ? 0 : y < 50 ? 2000 : 1900;
	p += 2;
    } else if (tag == T_GENTIME && n >= 15) {
	y = Digits(p, 4);
	p += 4;
	if (n > 15) {			/* fraction: ".d+" */
	    if (p[10] != '.' || n == 16 || n - 16 > 9
		    || Digits(p + 11, (int) (n - 16)) < 0) {
		return NULL;
	    }
	    fl = n - 15;
	}
    } else {
	return NULL;
    }
    m = Digits(p, 2);
    d = Digits(p + 2, 2);
    hh = Digits(p + 4, 2);
    mm = Digits(p + 6, 2);
    ss = Digits(p + 8, 2);
    if (y < 0 || m < 1 || m > 12 || d < 1 || d > 31 || hh < 0 || hh > 23
	    || mm < 0 || mm > 59 || ss < 0 || ss > 60
	    || p[10 + fl] != 'Z') {
	return NULL;
    }
    snprintf(buf, sizeof(buf), "%.3s %2d %02d:%02d:%02d%.*s %d GMT",
	    mon + 3 * (m - 1), d, hh, mm, ss, (int) fl, (const char *) p + 10,
	    y);
    return Tcl_NewStringObj(buf, -1);
}

/* INTEGER as uppercase hex magnitude, "-" prefixed when negative. */

static Tcl_Obj *
IntHexObj(
    const Der *v)
{
    const unsigned char *p = v->p;
    size_t n = DerLen(v), i;
    Tcl_DString ds, neg;
    unsigned c, carry = 1;
    char *h;

    if (n == 0) {
	return NULL;
    }
    Tcl_DStringInit(&ds);
    if (!(p[0] & 0x80)) {
	while (n > 1 && p[0] == 0) {
	    p++, n--;
	}
	PutHex(&ds, p, n);
	return Tcl_DStringToObj(&ds);
    }
    Tcl_DStringSetLength(&ds, 2 * n);	/* two's complement magnitude */
    h = Tcl_DStringValue(&ds);
    for (i = n; i-- > 0; ) {
	c = (~p[i] & 0xffu) + carry;
	carry = c >> 8;
	h[2 * i] = hex[(c >> 4) & 15];
	h[2 * i + 1] = hex[c & 15];
    }
    for (i = 0; i + 2 < 2 * n && h[i] == '0' && h[i + 1] == '0'; i += 2) {
    }
    Tcl_DStringInit(&neg);
    Tcl_DStringAppend(&neg, "-", 1);
    Tcl_DStringAppend(&neg, h + i, 2 * n - i);
    Tcl_DStringFree(&ds);
    return Tcl_DStringToObj(&neg);
}

/* Bit length of a non-negative INTEGER. */

static Tcl_WideInt
IntBits(
    const Der *v)
{
    const unsigned char *p = v->p;
    size_t n = DerLen(v);
    Tcl_WideInt bits;
    int c;

    while (n && *p == 0) {
	p++, n--;
    }
    if (n == 0) {
	return 0;
    }
    bits = (Tcl_WideInt) (n - 1) * 8;
    for (c = *p; c; c >>= 1) {
	bits++;
    }
    return bits;
}

/* GeneralName in OpenSSL's "TYPE:value" form, or NULL to skip. */

static Tcl_Obj *
GeneralNameObj(
    int tag,
    const Der *v)
{
    const unsigned char *p = v->p;
    size_t n = DerLen(v), i;
    Tcl_DString ds;
    char buf[OIDBUF];
    const char *s;

    Tcl_DStringInit(&ds);
    switch (tag) {
    case T_CTXC(0):
	Tcl_DStringAppend(&ds, "othername:<unsupported>", -1);
	break;
    case T_CTX(1):
	Tcl_DStringAppend(&ds, "email:", -1);
	PutString(&ds, T_IA5, v, 0);
	break;
    case T_CTX(2):
	Tcl_DStringAppend(&ds, "DNS:", -1);
	PutString(&ds, T_IA5, v, 0);
	break;
    case T_CTXC(3):
	Tcl_DStringAppend(&ds, "X400Name:<unsupported>", -1);
	break;
    case T_CTXC(4): {
	Der d = *v, name;
	Tcl_Obj *o;

	if (!DerTake(&d, T_SEQ, &name, NULL)) {
	    return NULL;
	}
	o = NameObj(&name, 1);
	Tcl_DStringAppend(&ds, "DirName:", -1);
	Tcl_DStringAppend(&ds, Tcl_GetString(o), -1);
	Tcl_DecrRefCount(o);
	break;
    }
    case T_CTXC(5):
	Tcl_DStringAppend(&ds, "EdiPartyName:<unsupported>", -1);
	break;
    case T_CTX(6):
	Tcl_DStringAppend(&ds, "URI:", -1);
	PutString(&ds, T_IA5, v, 0);
	break;
    case T_CTX(7):
	Tcl_DStringAppend(&ds, "IP Address:", -1);
	if (n == 4) {
	    snprintf(buf, sizeof(buf), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	    Tcl_DStringAppend(&ds, buf, -1);
	} else if (n == 16) {
	    for (i = 0; i < 16; i += 2) {
		snprintf(buf, sizeof(buf), "%s%X", i ? ":" : "",
			p[i] << 8 | p[i + 1]);
		Tcl_DStringAppend(&ds, buf, -1);
	    }
	} else {
	    Tcl_DStringAppend(&ds, "<invalid>", -1);
	}
	break;
    case T_CTX(8):
	if (!(s = OidName(v, buf))) {
	    return NULL;
	}
	Tcl_DStringAppend(&ds, "Registered ID:", -1);
	Tcl_DStringAppend(&ds, s, -1);
	break;
    default:
	return NULL;
    }
    return Tcl_DStringToObj(&ds);
}

/*
 * Extensions.
 */

static void
Put(
    Tcl_Obj *dict,
    const char *key,
    Tcl_Obj *val)
{
    if (val) {
	Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj(key, -1), val);
    }
}

typedef struct {
    Tcl_Obj *names, *san, *ocsp, *ski, *aki;
    int ca;
} ExtInfo;

/* Sets *slot to val, freeing an unshared value from a repeated extension. */

static void
Replace(
    Tcl_Obj **slot,
    Tcl_Obj *val)
{
    if (*slot) {
	Tcl_IncrRefCount(*slot);
	Tcl_DecrRefCount(*slot);
    }
    *slot = val;
}

static void
Extension(
    ExtInfo *x,
    const char *name,
    const Der *val)
{
    Der d = *val, s, e, f, v, g;
    Tcl_Obj *o;
    char buf[OIDBUF];
    const char *t;
    int tag;

    if (strcmp(name, "subjectAltName") == 0) {
	if (!DerTake(&d, T_SEQ, &s, NULL)) {
	    return;
	}
	if (!x->san) {
	    x->san = Tcl_NewListObj(0, NULL);
	}
	while ((tag = DerGet(&s, &v, NULL)) >= 0) {
	    if ((o = GeneralNameObj(tag, &v))) {
		Tcl_ListObjAppendElement(NULL, x->san, o);
	    }
	}
    } else if (strcmp(name, "basicConstraints") == 0) {
	if (DerTake(&d, T_SEQ, &s, NULL) && DerTake(&s, T_BOOL, &v, NULL)
		&& DerLen(&v) == 1) {
	    x->ca = v.p[0] != 0;
	}
    } else if (strcmp(name, "subjectKeyIdentifier") == 0) {
	if (DerTake(&d, T_OCTETS, &v, NULL)) {
	    Replace(&x->ski, HexObj(v.p, DerLen(&v)));
	}
    } else if (strcmp(name, "authorityKeyIdentifier") == 0) {
	if (DerTake(&d, T_SEQ, &s, NULL) && DerTake(&s, T_CTX(0), &v, NULL)) {
	    Replace(&x->aki, HexObj(v.p, DerLen(&v)));
	}
    } else if (strcmp(name, "authorityInfoAccess") == 0) {
	if (!DerTake(&d, T_SEQ, &s, NULL)) {
	    return;
	}
	while (DerTake(&s, T_SEQ, &e, NULL)) {
	    if (DerTake(&e, T_OID, &f, NULL) && (t = OidText(&f, buf))
		    && strcmp(t, OID_OCSP) == 0
		    && DerTake(&e, T_CTX(6), &g, NULL)) {
		Tcl_DString ds;

		if (!x->ocsp) {
		    x->ocsp = Tcl_NewListObj(0, NULL);
		}
		Tcl_DStringInit(&ds);
		PutString(&ds, T_IA5, &g, 0);
		Tcl_ListObjAppendElement(NULL, x->ocsp, Tcl_DStringToObj(&ds));
	    }
	}
    }
}

/* Extensions ::= SEQUENCE OF SEQUENCE { OID, BOOLEAN DEFAULT FALSE, OCTETS } */

static void
Extensions(
    ExtInfo *x,
    const Der *exts)
{
    Der d = *exts, e, oid, v;
    char buf[OIDBUF];
    const char *name;

    while (DerTake(&d, T_SEQ, &e, NULL)) {
	if (!DerTake(&e, T_OID, &oid, NULL)
		|| !(name = OidName(&oid, buf))) {
	    continue;
	}
	DerTake(&e, T_BOOL, &v, NULL);
	Tcl_ListObjAppendElement(NULL, x->names, Tcl_NewStringObj(name, -1));
	if (DerTake(&e, T_OCTETS, &v, NULL)) {
	    Extension(x, name, &v);
	}
    }
}

/* Public key: algorithm name and size. */

static void
PublicKey(
    Tcl_Obj *dict,
    const Der *spki)
{
    Der d = *spki, alg, oid, par, key, k, n;
    char buf[OIDBUF], pbuf[OIDBUF];
    const char *name;
    Tcl_WideInt bits = 0;
    int i;

    if (!DerTake(&d, T_SEQ, &alg, NULL) || !DerTake(&alg, T_OID, &oid, NULL)
	    || !(name = OidName(&oid, buf))) {
	return;
    }
    Put(dict, "publicKeyAlgorithm", Tcl_NewStringObj(name, -1));
    if (strcmp(name, "rsaEncryption") == 0 || strcmp(name, "rsassaPss") == 0) {
	if (DerTake(&d, T_BITS, &key, NULL) && DerLen(&key) > 1
		&& key.p[0] == 0) {
	    key.p++;
	    if (DerTake(&key, T_SEQ, &k, NULL) && DerTake(&k, T_INT, &n, NULL)) {
		bits = IntBits(&n);
	    }
	}
    } else if (strcmp(name, "id-ecPublicKey") == 0) {
	if (DerTake(&alg, T_OID, &par, NULL)
		&& (i = OidFind(OidText(&par, pbuf))) >= 0) {
	    bits = oids[i].bits;
	}
    } else if (strcmp(name, "dsaEncryption") == 0) {
	if (DerTake(&alg, T_SEQ, &par, NULL) && DerTake(&par, T_INT, &n, NULL)) {
	    bits = IntBits(&n);
	}
    } else if ((i = OidFind(OidText(&oid, pbuf))) >= 0) {
	bits = oids[i].bits;
    }
    if (bits > 0) {
	Put(dict, "bits", Tcl_NewWideIntObj(bits));
    }
}

static Tcl_Obj *
AlgObj(
    const Der *algid)
{
    Der d = *algid, oid;
    char buf[OIDBUF];
    const char *name;

    if (!DerTake(&d, T_OID, &oid, NULL) || !(name = OidName(&oid, buf))) {
	return NULL;
    }
    return Tcl_NewStringObj(name, -1);
}

static Tcl_Obj *
PemObj(
    const unsigned char *p,
    size_t n)
{
    static const char b64[] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    Tcl_DString ds;
    char q[4];
    size_t i, col = 0;
    unsigned v;

    Tcl_DStringInit(&ds);
    Tcl_DStringAppend(&ds, "-----BEGIN CERTIFICATE-----\n", -1);
    for (i = 0; i < n; i += 3) {
	v = p[i] << 16 | (i + 1 < n ? p[i + 1] << 8 : 0)
		| (i + 2 < n ? p[i + 2] : 0);
	q[0] = b64[v >> 18];
	q[1] = b64[(v >> 12) & 63];
	q[2] = i + 1 < n ? b64[(v >> 6) & 63] : '=';
	q[3] = i + 2 < n ? b64[v & 63] : '=';
	Tcl_DStringAppend(&ds, q, 4);
	if ((col += 4) == 64 && i + 3 < n) {
	    Tcl_DStringAppend(&ds, "\n", 1);
	    col = 0;
	}
    }
    Tcl_DStringAppend(&ds, "\n-----END CERTIFICATE-----\n", -1);
    return Tcl_DStringToObj(&ds);
}

static Tcl_Obj *
DigestObj(
    int alg,
    const unsigned char *p,
    size_t n)
{
    uint8_t md[64];

    if (tlsb_digest(alg, p, n, md) != TLSB_OK) {
	return NULL;
    }
    return HexObj(md, alg == TLSB_SHA1 ? 20 : 32);
}

/*
 * Entry point (see x509.h).
 */

int
TlsX509Info(
    Tcl_Interp *interp,
    const unsigned char *der,
    size_t len,
    Tcl_Obj *dict)
{
    Der in, cert, all, tbs, alg, sig, d, v, w, issuer, subject;
    ExtInfo x;
    Tcl_Obj *o;
    int tag, version = 1;

    in.p = der;
    in.end = der + len;
    if (!der || !DerTake(&in, T_SEQ, &cert, &all)
	    || !DerTake(&cert, T_SEQ, &tbs, NULL)
	    || !DerTake(&cert, T_SEQ, &alg, NULL)
	    || !DerTake(&cert, T_BITS, &sig, NULL)) {
	if (interp) {
	    Tcl_SetObjResult(interp,
		    Tcl_NewStringObj("cannot parse certificate", -1));
	    Tcl_SetErrorCode(interp, "TLS", "X509", "PARSE", (char *) NULL);
	}
	return TCL_ERROR;
    }
    memset(&x, 0, sizeof(x));
    x.names = Tcl_NewListObj(0, NULL);
    Tcl_IncrRefCount(x.names);

    Put(dict, "signatureAlgorithm", AlgObj(&alg));
    Put(dict, "sha1_hash", DigestObj(TLSB_SHA1, all.p, DerLen(&all)));
    Put(dict, "sha256_hash", DigestObj(TLSB_SHA256, all.p, DerLen(&all)));
    Put(dict, "certificate", PemObj(all.p, DerLen(&all)));

    /* Fields are positional: stop at the first one that does not fit. */
    d = tbs;
    if (DerTake(&d, T_CTXC(0), &v, NULL)) {
	if (DerTake(&v, T_INT, &w, NULL) && DerLen(&w) == 1 && w.p[0] < 3) {
	    version = w.p[0] + 1;
	} else {
	    version = 0;
	}
    }
    if (version) {
	Put(dict, "version", Tcl_NewWideIntObj(version));
    }
    if (!DerTake(&d, T_INT, &v, NULL)) {
	goto done;
    }
    if ((o = IntHexObj(&v))) {
	Put(dict, "serialNumber", o);
	Put(dict, "serial", o);
    }
    if (!DerTake(&d, T_SEQ, &v, NULL)) {
	goto done;
    }
    Put(dict, "signature", AlgObj(&v));
    if (!DerTake(&d, T_SEQ, &v, &issuer)) {
	goto done;
    }
    Put(dict, "issuer", NameObj(&v, 0));
    if (!DerTake(&d, T_SEQ, &v, NULL)) {
	goto done;
    }
    if ((tag = DerGet(&v, &w, NULL)) >= 0) {
	Put(dict, "notBefore", TimeObj(tag, &w));
	if ((tag = DerGet(&v, &w, NULL)) >= 0) {
	    Put(dict, "notAfter", TimeObj(tag, &w));
	}
    }
    if (!DerTake(&d, T_SEQ, &v, &subject)) {
	goto done;
    }
    Put(dict, "subject", NameObj(&v, 0));
    Put(dict, "self_signed", Tcl_NewBooleanObj(
	    DerLen(&issuer) == DerLen(&subject)
	    && memcmp(issuer.p, subject.p, DerLen(&subject)) == 0));
    if (!DerTake(&d, T_SEQ, &v, NULL)) {
	goto done;
    }
    PublicKey(dict, &v);
    DerTake(&d, T_CTX(1), &v, NULL);
    DerTake(&d, T_CTX(2), &v, NULL);
    if (DerTake(&d, T_CTXC(3), &v, NULL) && DerTake(&v, T_SEQ, &w, NULL)) {
	Extensions(&x, &w);
    }

  done:
    {
	Tcl_Size n;

	Tcl_ListObjLength(NULL, x.names, &n);
	Put(dict, "extensions", x.names);
	Put(dict, "num_extensions", Tcl_NewWideIntObj(n));
    }
    Put(dict, "subjectAltName", x.san);
    Put(dict, "subjectKeyIdentifier", x.ski);
    Put(dict, "authorityKeyIdentifier", x.aki);
    Put(dict, "ocsp", x.ocsp);
    Put(dict, "ca", Tcl_NewBooleanObj(x.ca));
    Tcl_DecrRefCount(x.names);
    return TCL_OK;
}
