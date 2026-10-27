/*
 * tls.c --
 *
 *	Tcl commands of the TLS packages, compatible with tcltls.
 */

#include "tlsInt.h"
#include "tlsScript.h"
#include <string.h>

#ifndef PACKAGE_VERSION
#   define PACKAGE_VERSION "0.0"
#endif

#define CRYPTO_MAX_RANDOM	(1024 * 1024)
#define CRYPTO_MAX_ITER		10000000
#define CRYPTO_MAX_DERIVED	64
#define EXPORT_MAX		8160

static const char *const protocolNames[] = {
    "ssl2", "ssl3", "tls1", "tls1.1", "tls1.2", "tls1.3", NULL
};
enum { P_SSL2, P_SSL3, P_TLS1, P_TLS1_1, P_TLS1_2, P_TLS1_3 };

static const char *const importOptions[] = {
    "-alpn", "-autoservername", "-cadir", "-cafile", "-castore", "-cert",
    "-certfile", "-cipher", "-ciphersuites", "-command", "-dhparams", "-key",
    "-keyfile", "-model", "-password", "-post_handshake", "-request",
    "-require", "-security_level", "-server", "-servername", "-session_id",
    "-ssl2", "-ssl3", "-tls1", "-tls1.1", "-tls1.2", "-tls1.3",
    "-validatecommand", "-vcmd", NULL
};
enum {
    O_ALPN, O_AUTOSERVERNAME, O_CADIR, O_CAFILE, O_CASTORE, O_CERT,
    O_CERTFILE, O_CIPHER, O_CIPHERSUITES, O_COMMAND, O_DHPARAMS, O_KEY,
    O_KEYFILE, O_MODEL, O_PASSWORD, O_POST_HANDSHAKE, O_REQUEST,
    O_REQUIRE, O_SECURITY_LEVEL, O_SERVER, O_SERVERNAME, O_SESSION_ID,
    O_SSL2, O_SSL3, O_TLS1, O_TLS1_1, O_TLS1_2, O_TLS1_3,
    O_VALIDATECOMMAND, O_VCMD, O_COUNT
};

static int
Error(
    Tcl_Interp *interp,
    const char *code,
    Tcl_Obj *msg)
{
    Tcl_SetObjResult(interp, msg);
    Tcl_SetErrorCode(interp, "TLS", code, NULL);
    return TCL_ERROR;
}

/*
 * Callbacks into the script level. Errors go to the background handler and
 * never disturb the interpreter result of whatever triggered the I/O.
 */

static int
Callback(
    TlsState *s,
    Tcl_Obj *prefix,
    Tcl_Size objc,
    Tcl_Obj *const objv[],
    Tcl_Obj **resultPtr)
{
    Tcl_Interp *interp = s->interp;
    Tcl_InterpState saved;
    Tcl_Obj *cmd;
    Tcl_Size i;
    int code;

    cmd = Tcl_DuplicateObj(prefix);
    Tcl_IncrRefCount(cmd);
    for (i = 0; i < objc; i++) {
	Tcl_ListObjAppendElement(NULL, cmd, objv[i]);
    }
    if (Tcl_InterpDeleted(interp)) {
	Tcl_DecrRefCount(cmd);
	return TCL_ERROR;
    }
    Tcl_Preserve(interp);
    saved = Tcl_SaveInterpState(interp, TCL_OK);
    code = Tcl_EvalObjEx(interp, cmd, TCL_EVAL_GLOBAL);
    if (code == TCL_OK && resultPtr) {
	*resultPtr = Tcl_GetObjResult(interp);
	Tcl_IncrRefCount(*resultPtr);
    } else if (code != TCL_OK) {
	Tcl_BackgroundException(interp, code);
    }
    Tcl_RestoreInterpState(interp, saved);
    Tcl_Release(interp);
    Tcl_DecrRefCount(cmd);
    return code;
}

void
TlsInvokeCommand(
    TlsState *s,
    Tcl_Size objc,
    Tcl_Obj *const objv[])
{
    if (s->command) {
	Callback(s, s->command, objc, objv, NULL);
    } else {
	/* Free the unused arguments. */
	for (Tcl_Size i = 0; i < objc; i++) {
	    Tcl_IncrRefCount(objv[i]);
	    Tcl_DecrRefCount(objv[i]);
	}
    }
}

int
TlsVerify(
    void *ud,
    int depth,
    const uint8_t *der,
    size_t len,
    int ok,
    const char *err)
{
    TlsState *s = (TlsState *) ud;
    Tcl_Obj *objv[6], *result = NULL;
    int accept = 0;

    objv[0] = Tcl_NewStringObj("verify", -1);
    objv[1] = Tcl_NewStringObj(Tcl_GetChannelName(s->self), -1);
    objv[2] = Tcl_NewIntObj(depth);
    objv[3] = Tcl_NewDictObj();
    TlsX509Info(NULL, der, len, objv[3]);
    objv[4] = Tcl_NewBooleanObj(ok);
    objv[5] = Tcl_NewStringObj(err ? err : "", -1);
    if (Callback(s, s->vcmd, 6, objv, &result) == TCL_OK) {
	if (Tcl_GetBooleanFromObj(NULL, result, &accept) != TCL_OK) {
	    Tcl_GetIntFromObj(NULL, result, &accept);
	}
	Tcl_DecrRefCount(result);
    }
    return accept != 0;
}

/*
 * Configuration.
 */

static Tcl_Obj *
ReadFile(
    Tcl_Interp *interp,
    Tcl_Obj *path)
{
    Tcl_Channel chan = Tcl_FSOpenFileChannel(interp, path, "rb", 0);
    Tcl_Obj *data;

    if (chan == NULL) {
	return NULL;
    }
    data = Tcl_NewObj();
    if (Tcl_ReadChars(chan, data, -1, 0) < 0) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("error reading \"%s\": %s",
		Tcl_GetString(path), Tcl_PosixError(interp)));
	Tcl_DecrRefCount(data);
	data = NULL;
    }
    Tcl_Close(NULL, chan);
    return data;
}

/* An option given as the empty string counts as not given. */
static Tcl_Obj *
NonEmpty(
    Tcl_Obj *obj)
{
    return obj && Tcl_GetCharLength(obj) > 0 ? obj : NULL;
}

/*
 * Content of an inline option, else of a file option, else NULL. The
 * caller releases the reference it gets.
 */
static int
GetBlob(
    Tcl_Interp *interp,
    Tcl_Obj *value,
    Tcl_Obj *file,
    Tcl_Obj **blobPtr)
{
    *blobPtr = NonEmpty(value);
    if (*blobPtr == NULL && NonEmpty(file)) {
	*blobPtr = ReadFile(interp, file);
	if (*blobPtr == NULL) {
	    return TCL_ERROR;
	}
    }
    if (*blobPtr) {
	Tcl_IncrRefCount(*blobPtr);
    }
    return TCL_OK;
}

static int
GetBool(
    Tcl_Interp *interp,
    Tcl_Obj *obj,
    int dflt,
    int *boolPtr)
{
    *boolPtr = dflt;
    return obj ? Tcl_GetBooleanFromObj(interp, obj, boolPtr) : TCL_OK;
}

static TlsConf *
ConfNew(
    Tcl_Interp *interp,
    Tcl_Obj *opt[],
    int server)
{
    tlsb_opts o;
    Tcl_Obj *ca = NULL, *cert = NULL, *key = NULL, *password = NULL;
    Tcl_Obj **alpnv = NULL;
    const char **alpn = NULL;
    Tcl_Size alpnc = 0, i, len;
    int tls12, tls13;
    TlsConf *conf = NULL;
    tlsb_conf *bconf;
    char err[256];

    memset(&o, 0, sizeof(o));
    o.server = server;
    if (GetBool(interp, opt[O_REQUIRE], !server, &o.require) != TCL_OK
	    || GetBool(interp, opt[O_REQUEST], !server, &o.request) != TCL_OK
	    || GetBool(interp, opt[O_TLS1_2], 1, &tls12) != TCL_OK
	    || GetBool(interp, opt[O_TLS1_3], 1, &tls13) != TCL_OK) {
	return NULL;
    }
    o.request |= o.require;
    o.protocols = tlsb_protocols()
	    & ((tls12 ? TLSB_TLS12 : 0) | (tls13 ? TLSB_TLS13 : 0));
    if (o.protocols == 0) {
	Error(interp, "PROTOCOL", Tcl_NewStringObj("no protocols enabled", -1));
	return NULL;
    }

    if (GetBlob(interp, NULL, opt[O_CAFILE], &ca) != TCL_OK
	    || GetBlob(interp, opt[O_CERT], opt[O_CERTFILE], &cert) != TCL_OK
	    || GetBlob(interp, opt[O_KEY],
		opt[O_KEYFILE] ? opt[O_KEYFILE] : opt[O_CERTFILE], &key)
		!= TCL_OK) {
	goto done;
    }
    if (ca) {
	if ((o.ca = Tcl_GetBytesFromObj(interp, ca, &len)) == NULL) {
	    goto done;
	}
	o.ca_len = len;
    }
    if (NonEmpty(opt[O_CADIR])) {
	o.cadir = Tcl_GetString(opt[O_CADIR]);
    }
    if (cert) {
	if ((o.cert = Tcl_GetBytesFromObj(interp, cert, &len)) == NULL) {
	    goto done;
	}
	o.cert_len = len;
    }
    if (key) {
	if ((o.key = Tcl_GetBytesFromObj(interp, key, &len)) == NULL) {
	    goto done;
	}
	o.key_len = len;
    }
    if (key && NonEmpty(opt[O_PASSWORD])) {
	int code = Tcl_EvalObjEx(interp, opt[O_PASSWORD], TCL_EVAL_GLOBAL);

	if (code != TCL_OK && code != TCL_RETURN) {
	    Tcl_AddErrorInfo(interp, "\n    (-password callback)");
	    goto done;
	}
	password = Tcl_GetObjResult(interp);
	Tcl_IncrRefCount(password);
	Tcl_ResetResult(interp);
	o.password = Tcl_GetString(password);
    }
    if (NonEmpty(opt[O_CIPHER])) {
	o.ciphers = Tcl_GetString(opt[O_CIPHER]);
    }
    if (NonEmpty(opt[O_CIPHERSUITES])) {
	o.ciphersuites = Tcl_GetString(opt[O_CIPHERSUITES]);
    }
    if (opt[O_ALPN]) {
	if (Tcl_ListObjGetElements(interp, opt[O_ALPN], &alpnc, &alpnv)
		!= TCL_OK) {
	    goto done;
	}
	alpn = (const char **) Tcl_Alloc(sizeof(char *) * (alpnc + 1));
	for (i = 0; i < alpnc; i++) {
	    alpn[i] = Tcl_GetStringFromObj(alpnv[i], &len);
	    if (len == 0 || len > 255) {
		Error(interp, "CONFIG", Tcl_ObjPrintf(
			"invalid ALPN protocol name \"%s\"", alpn[i]));
		goto done;
	    }
	}
	o.alpn = alpn;
	o.alpn_count = (int) alpnc;
    }

    bconf = tlsb_conf_new(&o, err, sizeof(err));
    if (bconf == NULL) {
	Error(interp, "CONFIG", Tcl_NewStringObj(err, -1));
	goto done;
    }
    conf = (TlsConf *) Tcl_Alloc(sizeof(TlsConf));
    conf->refCount = 1;
    conf->conf = bconf;
    conf->server = server;

  done:
    if (password) {
	Tcl_DecrRefCount(password);
    }
    Tcl_Free((void *) alpn);
    if (ca) {
	Tcl_DecrRefCount(ca);
    }
    if (cert) {
	Tcl_DecrRefCount(cert);
    }
    if (key) {
	Tcl_DecrRefCount(key);
    }
    return conf;
}

/*
 * -model: a TLS channel lends its configuration. Any other channel anchors
 * one: the first import naming it creates the configuration, later ones
 * share it, and it goes when the channel closes. socket -server passes its
 * listening socket, so its connections share one (and its session tickets).
 */

#define ANCHORS "tlschan::" TLS_BACKEND "::anchors"

static void
AnchorClosed(
    void *clientData)
{
    Tcl_HashEntry *e = (Tcl_HashEntry *) clientData;

    TlsConfRelease((TlsConf *) Tcl_GetHashValue(e));
    Tcl_DeleteHashEntry(e);
}

static void
AnchorsFree(
    void *clientData,
    Tcl_Interp *interp)
{
    Tcl_HashTable *t = (Tcl_HashTable *) clientData;
    Tcl_HashSearch search;
    Tcl_HashEntry *e;

    (void) interp;
    for (e = Tcl_FirstHashEntry(t, &search); e; e = Tcl_NextHashEntry(&search)) {
	Tcl_DeleteCloseHandler((Tcl_Channel) Tcl_GetHashKey(t, e),
		AnchorClosed, e);
	TlsConfRelease((TlsConf *) Tcl_GetHashValue(e));
    }
    Tcl_DeleteHashTable(t);
    Tcl_Free(t);
}

static TlsConf *
ModelConf(
    Tcl_Interp *interp,
    Tcl_Obj *opt[],
    int server)
{
    Tcl_Channel chan = Tcl_GetChannel(interp, Tcl_GetString(opt[O_MODEL]),
	    NULL);
    Tcl_HashTable *t;
    Tcl_HashEntry *e;
    TlsConf *conf;
    int isNew;

    if (chan == NULL) {
	return NULL;
    }
    if (Tcl_GetChannelType(Tcl_GetTopChannel(chan)) == TlsChannelType()) {
	conf = ((TlsState *) Tcl_GetChannelInstanceData(
		Tcl_GetTopChannel(chan)))->conf;
    } else {
	t = (Tcl_HashTable *) Tcl_GetAssocData(interp, ANCHORS, NULL);
	if (t == NULL) {
	    t = (Tcl_HashTable *) Tcl_Alloc(sizeof(Tcl_HashTable));
	    Tcl_InitHashTable(t, TCL_ONE_WORD_KEYS);
	    Tcl_SetAssocData(interp, ANCHORS, AnchorsFree, t);
	}
	e = Tcl_CreateHashEntry(t, (char *) chan, &isNew);
	if (isNew) {
	    if ((conf = ConfNew(interp, opt, server)) == NULL) {
		Tcl_DeleteHashEntry(e);
		return NULL;
	    }
	    Tcl_SetHashValue(e, conf);
	    Tcl_CreateCloseHandler(chan, AnchorClosed, e);
	}
	conf = (TlsConf *) Tcl_GetHashValue(e);
    }
    if (conf->server != server) {
	Error(interp, "MODEL", Tcl_ObjPrintf("-model %s is configured as a %s",
		Tcl_GetString(opt[O_MODEL]), conf->server ? "server" : "client"));
	return NULL;
    }
    TlsConfRetain(conf);
    return conf;
}

/*
 * Channel commands.
 */

/*
 * A host name (letters, digits, '-', '_', labels of 1 to 63 between dots,
 * 253 at most) or an IPv4/IPv6 literal.
 */

static int
ValidServername(
    const char *name)
{
    size_t n = strlen(name), label = 0;
    const char *p;

    if (n == 0 || n > 253) {
	return 0;
    }
    if (strchr(name, ':')) {
	return strspn(name, "0123456789abcdefABCDEF:.") == n;
    }
    for (p = name; *p; p++) {
	if (*p == '.') {
	    if (label == 0) {
		return 0;
	    }
	    label = 0;
	} else if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')
		|| (*p >= '0' && *p <= '9') || *p == '-' || *p == '_') {
	    if (++label > 63) {
		return 0;
	    }
	} else {
	    return 0;
	}
    }
    return 1;
}

/*
 * import channel ?-option value ...?
 */

static int
ImportCmd(
    void *dummy,
    Tcl_Interp *interp,
    Tcl_Size objc,
    Tcl_Obj *const objv[])
{
    Tcl_Obj *opt[O_COUNT];
    Tcl_Channel chan;
    TlsConf *conf;
    TlsState *s;
    int server, idx;
    Tcl_Size i;

    (void) dummy;
    if (objc < 2 || (objc % 2) != 0) {
	Tcl_WrongNumArgs(interp, 1, objv, "channel ?-option value ...?");
	return TCL_ERROR;
    }
    if ((chan = Tcl_GetChannel(interp, Tcl_GetString(objv[1]), NULL))
	    == NULL) {
	return TCL_ERROR;
    }
    memset(opt, 0, sizeof(opt));
    for (i = 2; i < objc; i += 2) {
	if (Tcl_GetIndexFromObj(interp, objv[i], importOptions, "option", 0,
		&idx) != TCL_OK) {
	    return TCL_ERROR;
	}
	opt[idx] = objv[i + 1];
    }
    if (GetBool(interp, opt[O_SERVER], 0, &server) != TCL_OK) {
	return TCL_ERROR;
    }
    if (!server && NonEmpty(opt[O_SERVERNAME])
	    && !ValidServername(Tcl_GetString(opt[O_SERVERNAME]))) {
	return Error(interp, "CONFIG", Tcl_ObjPrintf("invalid server name \"%s\"",
		Tcl_GetString(opt[O_SERVERNAME])));
    }

    conf = NonEmpty(opt[O_MODEL]) ? ModelConf(interp, opt, server)
	    : ConfNew(interp, opt, server);
    if (conf == NULL) {
	return TCL_ERROR;
    }

    s = TlsStateNew(interp, chan, conf,
	    opt[O_SERVERNAME] ? Tcl_GetString(opt[O_SERVERNAME]) : NULL,
	    NonEmpty(opt[O_COMMAND]),
	    NonEmpty(opt[O_VALIDATECOMMAND]
		    ? opt[O_VALIDATECOMMAND] : opt[O_VCMD]));
    TlsConfRelease(conf);
    if (s == NULL) {
	return TCL_ERROR;
    }
    Tcl_SetObjResult(interp,
	    Tcl_NewStringObj(Tcl_GetChannelName(s->self), -1));
    return TCL_OK;
}

static int
UnimportCmd(
    void *dummy,
    Tcl_Interp *interp,
    Tcl_Size objc,
    Tcl_Obj *const objv[])
{
    TlsState *s;

    (void) dummy;
    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "channel");
	return TCL_ERROR;
    }
    if ((s = TlsGetState(interp, objv[1])) == NULL) {
	return TCL_ERROR;
    }
    return Tcl_UnstackChannel(interp, s->self);
}

static int
HandshakeCmd(
    void *dummy,
    Tcl_Interp *interp,
    Tcl_Size objc,
    Tcl_Obj *const objv[])
{
    TlsState *s;
    int e, code = TCL_OK;

    (void) dummy;
    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "channel");
	return TCL_ERROR;
    }
    if ((s = TlsGetState(interp, objv[1])) == NULL) {
	return TCL_ERROR;
    }
    Tcl_Preserve(s);		/* a callback may close the channel */
    e = TlsHandshake(s);
    if (e != 0 && e != EAGAIN) {
	Tcl_SetErrno(e);
	code = Error(interp, "HANDSHAKE", s->error
		? s->error : Tcl_NewStringObj(Tcl_ErrnoMsg(e), -1));
    } else {
	Tcl_SetObjResult(interp, Tcl_NewBooleanObj(e == 0));
    }
    Tcl_Release(s);
    return code;
}

/*
 * Introspection.
 */

static void
PutStr(
    Tcl_Obj *dict,
    const char *key,
    const char *value)
{
    Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj(key, -1),
	    Tcl_NewStringObj(value ? value : "", -1));
}

static void
PutInt(
    Tcl_Obj *dict,
    const char *key,
    Tcl_WideInt value)
{
    Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj(key, -1),
	    Tcl_NewWideIntObj(value));
}

static void
PutSession(
    TlsState *s,
    Tcl_Obj *dict,
    const tlsb_info *info)
{
    Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj("protocol", -1),
	    Tcl_ObjPrintf("TLSv%s", info->protocol + 3));	/* as tcltls */
    PutStr(dict, "cipher", info->cipher);
    PutInt(dict, "sbits", info->cipher_bits);
    Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj("alpn", -1),
	    Tcl_NewStringObj((const char *) info->alpn,
		info->alpn ? (Tcl_Size) info->alpn_len : 0));
    PutStr(dict, "servername", info->servername ? info->servername
	    : s->servername);
}

static int
StatusCmd(
    void *dummy,
    Tcl_Interp *interp,
    Tcl_Size objc,
    Tcl_Obj *const objv[])
{
    TlsState *s;
    Tcl_Obj *dict;
    const uint8_t *der;
    size_t len;
    tlsb_info info;
    int local = 0;

    (void) dummy;
    if (objc == 3 && strcmp(Tcl_GetString(objv[1]), "-local") == 0) {
	local = 1;
    } else if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "?-local? channel");
	return TCL_ERROR;
    }
    if ((s = TlsGetState(interp, objv[objc - 1])) == NULL) {
	return TCL_ERROR;
    }
    dict = Tcl_NewDictObj();
    if (s->phase == TLS_OPEN) {
	if ((local ? tlsb_local_cert(s->sess, &der, &len)
		: tlsb_peer_cert(s->sess, 0, &der, &len)) == TLSB_OK) {
	    TlsX509Info(NULL, der, len, dict);
	}
	if (tlsb_info_get(s->sess, &info) == TLSB_OK) {
	    PutSession(s, dict, &info);
	}
    }
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
}

static int
ConnectionCmd(
    void *dummy,
    Tcl_Interp *interp,
    Tcl_Size objc,
    Tcl_Obj *const objv[])
{
    static const char *const phases[] = { "handshake", "open", "failed" };
    TlsState *s;
    Tcl_Obj *dict;
    tlsb_info info;

    (void) dummy;
    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "channel");
	return TCL_ERROR;
    }
    if ((s = TlsGetState(interp, objv[1])) == NULL) {
	return TCL_ERROR;
    }
    dict = Tcl_NewDictObj();
    PutStr(dict, "state", phases[s->phase]);
    Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj("is_server", -1),
	    Tcl_NewBooleanObj(s->conf->server));
    if (s->phase == TLS_FAILED) {
	Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj("error", -1), s->error);
    } else if (s->phase == TLS_OPEN
	    && tlsb_info_get(s->sess, &info) == TLSB_OK) {
	PutSession(s, dict, &info);
	Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj("session_reused", -1),
		Tcl_NewBooleanObj(info.resumed));
    } else {
	PutStr(dict, "servername", s->servername);
    }
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
}

static void
AppendName(
    void *ud,
    const char *name)
{
    Tcl_ListObjAppendElement(NULL, (Tcl_Obj *) ud,
	    Tcl_NewStringObj(name, -1));
}

static int
CiphersCmd(
    void *dummy,
    Tcl_Interp *interp,
    Tcl_Size objc,
    Tcl_Obj *const objv[])
{
    Tcl_Obj *list = Tcl_NewListObj(0, NULL);
    unsigned protocols = tlsb_protocols();
    int idx;

    (void) dummy;
    if (objc > 4) {
	Tcl_WrongNumArgs(interp, 1, objv, "?protocol? ?verbose? ?supported?");
	return TCL_ERROR;
    }
    if (objc > 1) {
	if (Tcl_GetIndexFromObj(interp, objv[1], protocolNames, "protocol",
		0, &idx) != TCL_OK) {
	    Tcl_DecrRefCount(list);
	    return TCL_ERROR;
	}
	protocols &= idx == P_TLS1_2 ? TLSB_TLS12
		: idx == P_TLS1_3 ? TLSB_TLS13 : 0;
    }
    if (protocols) {
	tlsb_ciphers(protocols, AppendName, list);
    }
    Tcl_SetObjResult(interp, list);
    return TCL_OK;
}

static int
ProtocolsCmd(
    void *dummy,
    Tcl_Interp *interp,
    Tcl_Size objc,
    Tcl_Obj *const objv[])
{
    Tcl_Obj *list = Tcl_NewListObj(0, NULL);
    unsigned protocols = tlsb_protocols();

    (void) dummy;
    if (objc != 1) {
	Tcl_WrongNumArgs(interp, 1, objv, NULL);
	return TCL_ERROR;
    }
    if (protocols & TLSB_TLS12) {
	AppendName(list, protocolNames[P_TLS1_2]);
    }
    if (protocols & TLSB_TLS13) {
	AppendName(list, protocolNames[P_TLS1_3]);
    }
    Tcl_SetObjResult(interp, list);
    return TCL_OK;
}

static int
VersionCmd(
    void *dummy,
    Tcl_Interp *interp,
    Tcl_Size objc,
    Tcl_Obj *const objv[])
{
    (void) dummy;
    if (objc != 1) {
	Tcl_WrongNumArgs(interp, 1, objv, NULL);
	return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, Tcl_NewStringObj(tlsb_version(), -1));
    return TCL_OK;
}

/*
 * exporter channel label length ?context?
 */

static int
ExporterCmd(
    void *dummy,
    Tcl_Interp *interp,
    Tcl_Size objc,
    Tcl_Obj *const objv[])
{
    TlsState *s;
    Tcl_WideInt length;
    const unsigned char *ctx = NULL;
    Tcl_Size labelLen, ctxLen = 0;
    const char *label;
    Tcl_Obj *out;

    (void) dummy;
    if (objc != 4 && objc != 5) {
	Tcl_WrongNumArgs(interp, 1, objv, "channel label length ?context?");
	return TCL_ERROR;
    }
    if ((s = TlsGetState(interp, objv[1])) == NULL) {
	return TCL_ERROR;
    }
    if (s->phase != TLS_OPEN) {
	return Error(interp, "WRONGSTATE",
		Tcl_NewStringObj("the TLS handshake has not completed", -1));
    }
    label = Tcl_GetStringFromObj(objv[2], &labelLen);
    if (Tcl_GetWideIntFromObj(interp, objv[3], &length) != TCL_OK) {
	return TCL_ERROR;
    }
    if (length < 1 || length > EXPORT_MAX) {
	return Error(interp, "WRONGARGS", Tcl_ObjPrintf(
		"length must be between 1 and %d", EXPORT_MAX));
    }
    if (objc == 5 && (ctx = Tcl_GetBytesFromObj(interp, objv[4], &ctxLen))
	    == NULL) {
	return TCL_ERROR;
    }
    out = Tcl_NewByteArrayObj(NULL, (Tcl_Size) length);
    if (tlsb_export(s->sess, label, labelLen, ctx, ctxLen, objc == 5,
	    Tcl_GetBytesFromObj(NULL, out, NULL), length) != TLSB_OK) {
	Tcl_DecrRefCount(out);
	return Error(interp, "EXPORT",
		Tcl_NewStringObj("keying material export failed", -1));
    }
    Tcl_SetObjResult(interp, out);
    return TCL_OK;
}

/*
 * Crypto helpers, with the formats of tclmtls.
 */

static int
RandomBytesCmd(
    void *dummy,
    Tcl_Interp *interp,
    Tcl_Size objc,
    Tcl_Obj *const objv[])
{
    Tcl_WideInt count;
    Tcl_Obj *out;

    (void) dummy;
    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "count");
	return TCL_ERROR;
    }
    if (Tcl_GetWideIntFromObj(interp, objv[1], &count) != TCL_OK) {
	return TCL_ERROR;
    }
    if (count < 0 || count > CRYPTO_MAX_RANDOM) {
	return Error(interp, "CRYPTO", Tcl_ObjPrintf(
		"count must be between 0 and %d", CRYPTO_MAX_RANDOM));
    }
    out = Tcl_NewByteArrayObj(NULL, (Tcl_Size) count);
    if (count && tlsb_random(Tcl_GetBytesFromObj(NULL, out, NULL), count)
	    != TLSB_OK) {
	Tcl_DecrRefCount(out);
	return Error(interp, "CRYPTO",
		Tcl_NewStringObj("failed to generate random bytes", -1));
    }
    Tcl_SetObjResult(interp, out);
    return TCL_OK;
}

static unsigned char *
GetKey(
    Tcl_Interp *interp,
    Tcl_Obj *obj)
{
    Tcl_Size len;
    unsigned char *key = Tcl_GetBytesFromObj(interp, obj, &len);

    if (key && len != 32) {
	Error(interp, "CRYPTO", Tcl_NewStringObj("key must be 32 bytes", -1));
	return NULL;
    }
    return key;
}

static int
AesGcmEncryptCmd(
    void *dummy,
    Tcl_Interp *interp,
    Tcl_Size objc,
    Tcl_Obj *const objv[])
{
    unsigned char *key, *pt, *out;
    Tcl_Size len;
    Tcl_Obj *obj;

    (void) dummy;
    if (objc != 3) {
	Tcl_WrongNumArgs(interp, 1, objv, "key plaintext");
	return TCL_ERROR;
    }
    if ((key = GetKey(interp, objv[1])) == NULL
	    || (pt = Tcl_GetBytesFromObj(interp, objv[2], &len)) == NULL) {
	return TCL_ERROR;
    }
    obj = Tcl_NewByteArrayObj(NULL, 12 + len + 16);
    out = Tcl_GetBytesFromObj(NULL, obj, NULL);
    if (tlsb_random(out, 12) != TLSB_OK
	    || tlsb_aes256gcm_seal(key, out, pt, len, out + 12) != TLSB_OK) {
	Tcl_DecrRefCount(obj);
	return Error(interp, "CRYPTO",
		Tcl_NewStringObj("AES-GCM encryption failed", -1));
    }
    Tcl_SetObjResult(interp, obj);
    return TCL_OK;
}

static int
AesGcmDecryptCmd(
    void *dummy,
    Tcl_Interp *interp,
    Tcl_Size objc,
    Tcl_Obj *const objv[])
{
    unsigned char *key, *in;
    Tcl_Size len;
    Tcl_Obj *obj;

    (void) dummy;
    if (objc != 3) {
	Tcl_WrongNumArgs(interp, 1, objv, "key ciphertext");
	return TCL_ERROR;
    }
    if ((key = GetKey(interp, objv[1])) == NULL
	    || (in = Tcl_GetBytesFromObj(interp, objv[2], &len)) == NULL) {
	return TCL_ERROR;
    }
    if (len < 12 + 16) {
	return Error(interp, "CRYPTO",
		Tcl_NewStringObj("ciphertext too short", -1));
    }
    obj = Tcl_NewByteArrayObj(NULL, len - 12 - 16);
    if (tlsb_aes256gcm_open(key, in, in + 12, len - 12,
	    Tcl_GetBytesFromObj(NULL, obj, NULL)) != TLSB_OK) {
	Tcl_DecrRefCount(obj);
	return Error(interp, "CRYPTO",
		Tcl_NewStringObj("AES-GCM authentication failed", -1));
    }
    Tcl_SetObjResult(interp, obj);
    return TCL_OK;
}

static int
Pbkdf2Cmd(
    void *dummy,
    Tcl_Interp *interp,
    Tcl_Size objc,
    Tcl_Obj *const objv[])
{
    static const char *const digests[] = { "sha1", "sha256", "sha512", NULL };
    static const int algs[] = { TLSB_SHA1, TLSB_SHA256, TLSB_SHA512 };
    unsigned char *pw, *salt, out[CRYPTO_MAX_DERIVED];
    Tcl_Size pwLen, saltLen;
    Tcl_WideInt iter, length;
    int idx;

    (void) dummy;
    if (objc != 6) {
	Tcl_WrongNumArgs(interp, 1, objv,
		"digest password salt iterations length");
	return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], digests, "digest", 0, &idx)
	    != TCL_OK
	    || (pw = Tcl_GetBytesFromObj(interp, objv[2], &pwLen)) == NULL
	    || (salt = Tcl_GetBytesFromObj(interp, objv[3], &saltLen)) == NULL
	    || Tcl_GetWideIntFromObj(interp, objv[4], &iter) != TCL_OK
	    || Tcl_GetWideIntFromObj(interp, objv[5], &length) != TCL_OK) {
	return TCL_ERROR;
    }
    if (iter < 1 || iter > CRYPTO_MAX_ITER) {
	return Error(interp, "CRYPTO", Tcl_ObjPrintf(
		"iterations must be between 1 and %d", CRYPTO_MAX_ITER));
    }
    if (length < 1 || length > CRYPTO_MAX_DERIVED) {
	return Error(interp, "CRYPTO", Tcl_ObjPrintf(
		"length must be between 1 and %d", CRYPTO_MAX_DERIVED));
    }
    if (tlsb_pbkdf2(algs[idx], pw, pwLen, salt, saltLen, (uint32_t) iter,
	    out, length) != TLSB_OK) {
	return Error(interp, "CRYPTO", Tcl_NewStringObj("PBKDF2 failed", -1));
    }
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(out, (Tcl_Size) length));
    memset(out, 0, sizeof(out));
    return TCL_OK;
}

/*
 * Package initialisation.
 */

static const struct {
    const char *name;
    Tcl_ObjCmdProc2 *proc;
} commands[] = {
    { "import",		ImportCmd },
    { "unimport",	UnimportCmd },
    { "handshake",	HandshakeCmd },
    { "status",		StatusCmd },
    { "connection",	ConnectionCmd },
    { "ciphers",	CiphersCmd },
    { "protocols",	ProtocolsCmd },
    { "version",	VersionCmd },
    { "exporter",	ExporterCmd },
    { "randombytes",	RandomBytesCmd },
    { "aesgcm-encrypt",	AesGcmEncryptCmd },
    { "aesgcm-decrypt",	AesGcmDecryptCmd },
    { "pbkdf2",		Pbkdf2Cmd },
    { NULL, NULL }
};

static Tcl_Config pkgConfig[] = {
    { "version",	PACKAGE_VERSION },
    { "backend",	TLS_BACKEND },
    { NULL, NULL }
};

DLLEXPORT int
TLS_INIT(
    Tcl_Interp *interp)
{
    char err[256];
    Tcl_Obj *script[4];
    int i, code;

    if (Tcl_InitStubs(interp, "9.0", 0) == NULL) {
	return TCL_ERROR;
    }
    if (tlsb_global_init(err, sizeof(err)) != TLSB_OK) {
	return Error(interp, "INIT", Tcl_NewStringObj(err, -1));
    }
    for (i = 0; commands[i].name; i++) {
	Tcl_CreateObjCommand2(interp, Tcl_GetString(Tcl_ObjPrintf("%s::%s",
		TLS_NS, commands[i].name)), commands[i].proc, NULL, NULL);
    }
    Tcl_RegisterConfig(interp, TLS_PKG, pkgConfig, "utf-8");

    script[0] = Tcl_NewStringObj("namespace", -1);
    script[1] = Tcl_NewStringObj("eval", -1);
    script[2] = Tcl_NewStringObj(TLS_NS, -1);
    script[3] = Tcl_NewStringObj(tlsScript, -1);
    for (i = 0; i < 4; i++) {
	Tcl_IncrRefCount(script[i]);
    }
    code = Tcl_EvalObjv(interp, 4, script, TCL_EVAL_GLOBAL);
    for (i = 0; i < 4; i++) {
	Tcl_DecrRefCount(script[i]);
    }
    if (code != TCL_OK) {
	return code;
    }
    return Tcl_PkgProvideEx(interp, TLS_PKG, PACKAGE_VERSION, NULL);
}
