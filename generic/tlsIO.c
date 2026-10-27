/*
 * tlsIO.c --
 *
 *	Stacked channel driver. Ciphertext moves between the backend and the
 *	channel below through RecvProc/SendProc; plaintext moves between the
 *	backend and the generic I/O layer through TlsInput/TlsOutput.
 *
 *	Output: ciphertext the channel below refuses is queued, and holds back
 *	further plaintext until it has gone out. Input: RecvProc calls the
 *	driver below directly, so its EOF flag doesn't hide a handshake error.
 *	A nonblocking read gathers every complete record; an EOF or error met
 *	after data is held back and returned by the next read.
 *
 *	Event model: we own the watch mask of the channel below. While the
 *	handshake runs in nonblocking mode it is driven from TlsNotify; once
 *	open, interest is passed through. A timer announces what no event
 *	below would: plaintext already buffered in the backend, a held EOF or
 *	error, and a failed channel, which stays ready so the script sees the
 *	error.
 *
 *	The channel below may notify from inside our own calls to it (a
 *	completing async connect does), so events arriving while TLS_BUSY are
 *	dropped; readiness is level triggered and the watch is renewed after.
 *
 *	Closing sends close_notify and drains the queue, blocking if need be;
 *	a half close is passed down and keeps the state.
 */

#include "tlsInt.h"
#include <string.h>
#include <limits.h>

static Tcl_DriverBlockModeProc	TlsBlockMode;
static Tcl_DriverClose2Proc	TlsClose;
static Tcl_DriverInputProc	TlsInput;
static Tcl_DriverOutputProc	TlsOutput;
static Tcl_DriverSetOptionProc	TlsSetOption;
static Tcl_DriverGetOptionProc	TlsGetOption;
static Tcl_DriverWatchProc	TlsWatch;
static Tcl_DriverGetHandleProc	TlsGetHandle;
static Tcl_DriverHandlerProc	TlsNotify;
static Tcl_DriverThreadActionProc TlsThreadAction;

static const Tcl_ChannelType tlsChannelType = {
    "tls",
    TCL_CHANNEL_VERSION_5,
    NULL,			/* close, unused */
    TlsInput,
    TlsOutput,
    NULL,			/* seek, unused */
    TlsSetOption,
    TlsGetOption,
    TlsWatch,
    TlsGetHandle,
    TlsClose,
    TlsBlockMode,
    NULL,			/* flush, reserved */
    TlsNotify,
    NULL,			/* wideSeek */
    TlsThreadAction,
    NULL			/* truncate */
};

const Tcl_ChannelType *
TlsChannelType(void)
{
    return &tlsChannelType;
}

/*
 * TLS_BUSY is set while we are inside the backend or the channel below.
 * Enter returns the previous state for Leave to restore, so calls nest.
 */

static inline int
Enter(
    TlsState *s)
{
    int busy = s->flags & TLS_BUSY;

    s->flags |= TLS_BUSY;
    return busy;
}

static inline void
Leave(
    TlsState *s,
    int busy)
{
    s->flags = (s->flags & ~TLS_BUSY) | busy;
}

/*
 * Transport for the backend. Flush sends queued ciphertext and returns 0
 * once drained, EAGAIN if the channel below is full, or an errno.
 */

static int
Flush(
    TlsState *s)
{
    int busy = Enter(s), e = 0;

    while (s->outStart < s->outEnd) {
	size_t left = s->outEnd - s->outStart;
	Tcl_Size n = Tcl_WriteRaw(s->parent, (char *) s->out + s->outStart,
		left > INT_MAX ? INT_MAX : (Tcl_Size) left);

	if (n <= 0) {
	    e = n ? Tcl_GetErrno() : EAGAIN;
	    e = (e == EAGAIN || e == EWOULDBLOCK) ? EAGAIN : (e ? e : EIO);
	    break;
	}
	s->outStart += n;
    }
    if (s->outStart == s->outEnd) {
	s->outStart = s->outEnd = 0;
    }
    Leave(s, busy);
    return e;
}

static void
SendProc(
    void *ud,
    const uint8_t *buf,
    size_t len)
{
    TlsState *s = (TlsState *) ud;

    if (s->outEnd + len > s->outSize && s->outStart) {
	memmove(s->out, s->out + s->outStart, s->outEnd - s->outStart);
	s->outEnd -= s->outStart;
	s->outStart = 0;
    }
    if (s->outEnd + len > s->outSize) {
	size_t size = s->outSize ? s->outSize : 16384;

	while (size < s->outEnd + len) {
	    size *= 2;
	}
	s->out = (unsigned char *) Tcl_Realloc(s->out, size);
	s->outSize = size;
    }
    memcpy(s->out + s->outEnd, buf, len);
    s->outEnd += len;
}

static long
RecvProc(
    void *ud,
    uint8_t *buf,
    size_t len)
{
    TlsState *s = (TlsState *) ud;
    int n, e;

    /* The peer may be waiting for what we queued, e.g. a ClientHello. */
    e = Flush(s);
    if (e && e != EAGAIN) {
	s->errorCode = e;
	return -1;
    }
    len = len > INT_MAX ? INT_MAX : len;
    if (Tcl_ChannelBuffered(s->parent) > 0) {
	/* Input the channel below had buffered before we were stacked. */
	n = (int) Tcl_ReadRaw(s->parent, (char *) buf, (Tcl_Size) len);
	e = Tcl_GetErrno();
    } else {
	/*
	 * Straight to the driver: Tcl_ReadRaw would leave its EOF flag in
	 * the state we share, hiding a handshake error behind a plain EOF.
	 */
	n = Tcl_ChannelInputProc(Tcl_GetChannelType(s->parent))(
		Tcl_GetChannelInstanceData(s->parent), (char *) buf,
		(int) len, &e);
    }
    if (n > 0) {
	s->flags &= ~TLS_STARVED;
	return n;
    }
    if (n == 0) {
	return -1;
    }
    if (e == EAGAIN || e == EWOULDBLOCK) {
	s->flags |= TLS_STARVED;
	return 0;
    }
    s->errorCode = e;
    return -1;
}

/*
 * Watch mask.
 */

static void
TimerRun(
    void *clientData)
{
    TlsState *s = (TlsState *) clientData;

    s->timer = NULL;
    Tcl_NotifyChannel(s->self,
	    s->phase == TLS_FAILED ? s->want : (s->want & TCL_READABLE));
}

/*
 * Sets the watch below from the phase and the script's interest, and arms
 * the timer for events only we know about.
 */

static void
UpdateWatch(
    TlsState *s)
{
    int mask = 0, synthetic = 0;

    if (s->outStart < s->outEnd) {
	mask |= TCL_WRITABLE;
    }
    switch (s->phase) {
    case TLS_HANDSHAKE:
	if (s->flags & TLS_NONBLOCK) {
	    /* Writable once kicks off a client's first flight. */
	    mask |= TCL_READABLE
		    | ((s->flags & TLS_STARTED) ? 0 : TCL_WRITABLE);
	} else {
	    mask |= s->want;
	}
	break;
    case TLS_OPEN:
	mask |= s->want;
	synthetic = (s->want & TCL_READABLE) && (s->held != TLSB_WANT_READ
		|| (!(s->flags & TLS_STARVED) && tlsb_pending(s->sess)));
	break;
    case TLS_FAILED:
	synthetic = s->want;
	break;
    }

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) \
	|| defined(__DragonFly__)
    /*
     * Tcl's kqueue notifier keeps the write filter when a mask loses
     * TCL_WRITABLE, and the stale event then keeps update from returning:
     * drop the watch first.
     */
    if ((s->below & ~mask) && mask) {
	Tcl_ChannelWatchProc(Tcl_GetChannelType(s->parent))(
		Tcl_GetChannelInstanceData(s->parent), 0);
    }
#endif
    Tcl_ChannelWatchProc(Tcl_GetChannelType(s->parent))(
	    Tcl_GetChannelInstanceData(s->parent), mask);
    s->below = mask;

    if (!synthetic) {
	if (s->timer) {
	    Tcl_DeleteTimerHandler(s->timer);
	    s->timer = NULL;
	}
    } else if (!s->timer) {
	s->timer = Tcl_CreateTimerHandler(0, TimerRun, s);
    }
}

/*
 * Failure. Fail moves the channel into TLS_FAILED, once, and returns the
 * POSIX error to report.
 */

static int
Fail(
    TlsState *s,
    int code,
    const char *msg)
{
    Tcl_Obj *objv[3];
    Tcl_DString ds;

    if (s->phase == TLS_FAILED) {
	return s->errorCode;
    }
    if (s->errorCode) {
	code = s->errorCode;		/* I/O error below wins */
	msg = NULL;
    }
    Tcl_DStringInit(&ds);
    if (msg == NULL && Tcl_GetChannelOption(NULL, s->parent, "-error", &ds)
	    == TCL_OK && Tcl_DStringLength(&ds) > 0) {
	msg = Tcl_DStringValue(&ds);	/* e.g. why an -async connect failed */
    }
    s->errorCode = code;
    s->error = Tcl_ObjPrintf("%s%s",
	    s->phase == TLS_HANDSHAKE ? "handshake failed: " : "",
	    msg ? msg : Tcl_ErrnoMsg(code));
    Tcl_IncrRefCount(s->error);
    Tcl_DStringFree(&ds);
    s->phase = TLS_FAILED;
    s->outStart = s->outEnd = 0;	/* nothing more goes out */

    objv[0] = Tcl_NewStringObj("error", -1);
    objv[1] = Tcl_NewStringObj(Tcl_GetChannelName(s->self), -1);
    objv[2] = s->error;
    TlsInvokeCommand(s, 3, objv);
    if (s->self) {
	UpdateWatch(s);			/* the failure is an event of its own */
    }
    return code;
}

static int
BackendFail(
    TlsState *s)
{
    return Fail(s, ECONNABORTED, tlsb_errmsg(s->sess));
}

static void
SetChannelError(
    TlsState *s)
{
    Tcl_SetChannelError(s->self, Tcl_NewListObj(1, &s->error));
}

/*
 * Handshake. TlsHandshake advances it and returns 0 once open, EAGAIN if it
 * would block, or the error that failed it.
 */

int
TlsHandshake(
    TlsState *s)
{
    int rc, e, busy;

    if (s->phase != TLS_HANDSHAKE) {
	return s->phase == TLS_OPEN ? 0 : s->errorCode;
    }
    if (s->flags & TLS_BUSY) {
	return EAGAIN;		/* a callback from inside the handshake */
    }
    s->flags |= TLS_STARTED;
    Tcl_Preserve(s);
    busy = Enter(s);
    rc = tlsb_handshake(s->sess);
    e = Flush(s);
    Leave(s, busy);
    if (rc == TLSB_ERROR) {
	rc = BackendFail(s);
    } else if (e && e != EAGAIN) {
	rc = Fail(s, e, NULL);
    } else if (rc == TLSB_WANT_READ) {
	rc = EAGAIN;
	UpdateWatch(s);
    } else {
	Tcl_Obj *objv[6];

	s->phase = TLS_OPEN;
	objv[0] = Tcl_NewStringObj("info", -1);
	objv[1] = Tcl_NewStringObj(Tcl_GetChannelName(s->self), -1);
	objv[2] = Tcl_NewStringObj("handshake", -1);
	objv[3] = Tcl_NewStringObj("done", -1);
	objv[4] = Tcl_NewStringObj("SSL negotiation finished successfully",
		-1);
	objv[5] = Tcl_NewStringObj("info", -1);
	TlsInvokeCommand(s, 6, objv);
	rc = s->phase == TLS_OPEN ? 0 : s->errorCode;
    }
    Tcl_Release(s);
    return rc;
}

/*
 * Events.
 */

static void
TlsWatch(
    void *instanceData,
    int mask)
{
    TlsState *s = (TlsState *) instanceData;

    s->want = mask & (TCL_READABLE | TCL_WRITABLE);
    UpdateWatch(s);
}

static int
TlsNotify(
    void *instanceData,
    int mask)
{
    TlsState *s = (TlsState *) instanceData;

    if (s->flags & TLS_BUSY) {
	return 0;
    }
    if (s->timer) {
	Tcl_DeleteTimerHandler(s->timer);
	s->timer = NULL;
    }
    Tcl_Preserve(s);
    if (mask & TCL_READABLE) {
	s->flags &= ~TLS_STARVED;
    }
    if ((mask & TCL_WRITABLE) && s->outStart < s->outEnd) {
	int e = Flush(s);

	if (e && e != EAGAIN) {
	    Fail(s, e, NULL);
	}
    }

    if (s->phase == TLS_HANDSHAKE && (s->flags & TLS_NONBLOCK)) {
	/* Nothing to report unless this completes or fails it. */
	mask = (TlsHandshake(s) == EAGAIN) ? 0 : s->want;
    }
    if (s->self == NULL) {
	mask = 0;			/* a callback closed us */
    } else {
	if (s->phase == TLS_FAILED) {
	    mask = s->want;
	} else if (s->outStart < s->outEnd) {
	    mask &= ~TCL_WRITABLE;
	}
	UpdateWatch(s);
	mask &= s->want;
    }
    Tcl_Release(s);
    return mask;
}

/*
 * Data transfer.
 */

/*
 * Nonblocking reads gather every record that has arrived rather than one
 * per event; an EOF or error that ends the run after data is held for the
 * next call.
 */

static long
Read(
    TlsState *s,
    char *buf,
    int size)
{
    long n, m;

    if (s->held != TLSB_WANT_READ) {
	n = s->held;
	s->held = TLSB_WANT_READ;
	return n;
    }
    n = tlsb_read(s->sess, (uint8_t *) buf, (size_t) size);
    while (n > 0 && n < size && (s->flags & TLS_NONBLOCK)) {
	m = tlsb_read(s->sess, (uint8_t *) buf + n, (size_t) (size - n));
	if (m <= 0) {
	    s->held = m;		/* nothing held if it is WANT_READ */
	    break;
	}
	n += m;
    }
    return n;
}

static int
TlsInput(
    void *instanceData,
    char *buf,
    int bufSize,
    int *errorCodePtr)
{
    TlsState *s = (TlsState *) instanceData;
    long n;
    int e, busy;

    *errorCodePtr = 0;
    e = TlsHandshake(s);
    if (e == 0) {
	busy = Enter(s);
	n = Read(s, buf, bufSize);
	Leave(s, busy);
	if (Flush(s) == EAGAIN) {
	    UpdateWatch(s);		/* e.g. a KeyUpdate reply is queued */
	}
	if (n >= 0) {
	    return (int) n;
	}
	e = (n == TLSB_WANT_READ) ? EAGAIN : BackendFail(s);
    }
    if (e != EAGAIN) {
	SetChannelError(s);
    }
    *errorCodePtr = e;
    return -1;
}

static int
TlsOutput(
    void *instanceData,
    const char *buf,
    int toWrite,
    int *errorCodePtr)
{
    TlsState *s = (TlsState *) instanceData;
    long n;
    int e, busy;

    *errorCodePtr = 0;
    e = TlsHandshake(s);
    if (e == 0) {
	/* Hold back plaintext while ciphertext is still queued. */
	e = Flush(s);
    }
    if (e == 0) {
	busy = Enter(s);
	n = tlsb_write(s->sess, (const uint8_t *) buf, (size_t) toWrite);
	Leave(s, busy);
	if (n < 0) {
	    e = BackendFail(s);
	} else if ((e = Flush(s)) == 0 || e == EAGAIN) {
	    if (e == EAGAIN) {
		UpdateWatch(s);		/* the rest goes out when writable */
	    }
	    return (int) n;
	} else {
	    e = Fail(s, e, NULL);
	}
    }
    if (e == EAGAIN) {
	UpdateWatch(s);
    } else {
	SetChannelError(s);
    }
    *errorCodePtr = e;
    return -1;
}

static int
TlsBlockMode(
    void *instanceData,
    int mode)
{
    TlsState *s = (TlsState *) instanceData;

    if (mode == TCL_MODE_NONBLOCKING) {
	s->flags |= TLS_NONBLOCK;
    } else {
	s->flags &= ~TLS_NONBLOCK;
    }
    return 0;
}

/*
 * Options and handles belong to the channel below.
 */

static int
TlsSetOption(
    void *instanceData,
    Tcl_Interp *interp,
    const char *optionName,
    const char *newValue)
{
    TlsState *s = (TlsState *) instanceData;
    Tcl_DriverSetOptionProc *proc =
	    Tcl_ChannelSetOptionProc(Tcl_GetChannelType(s->parent));

    if (proc == NULL) {
	return Tcl_BadChannelOption(interp, optionName, NULL);
    }
    return proc(Tcl_GetChannelInstanceData(s->parent), interp, optionName,
	    newValue);
}

static int
TlsGetOption(
    void *instanceData,
    Tcl_Interp *interp,
    const char *optionName,
    Tcl_DString *dsPtr)
{
    TlsState *s = (TlsState *) instanceData;
    Tcl_DriverGetOptionProc *proc =
	    Tcl_ChannelGetOptionProc(Tcl_GetChannelType(s->parent));

    if (proc == NULL) {
	return optionName ? Tcl_BadChannelOption(interp, optionName, NULL)
		: TCL_OK;
    }
    return proc(Tcl_GetChannelInstanceData(s->parent), interp, optionName,
	    dsPtr);
}

static int
TlsGetHandle(
    void *instanceData,
    int direction,
    void **handlePtr)
{
    TlsState *s = (TlsState *) instanceData;

    return Tcl_GetChannelHandle(s->parent, direction, handlePtr);
}

static void
TlsThreadAction(
    void *instanceData,
    int action)
{
    TlsState *s = (TlsState *) instanceData;

    if (action == TCL_CHANNEL_THREAD_REMOVE && s->timer) {
	Tcl_DeleteTimerHandler(s->timer);
	s->timer = NULL;
    }
}

/*
 * Shared configurations. Channels sharing a conf may live in different
 * threads.
 */

TCL_DECLARE_MUTEX(confMutex)

void
TlsConfRetain(
    TlsConf *conf)
{
    Tcl_MutexLock(&confMutex);
    conf->refCount++;
    Tcl_MutexUnlock(&confMutex);
}

void
TlsConfRelease(
    TlsConf *conf)
{
    Tcl_Size left;

    Tcl_MutexLock(&confMutex);
    left = --conf->refCount;
    Tcl_MutexUnlock(&confMutex);
    if (left <= 0) {
	tlsb_conf_free(conf->conf);
	Tcl_Free(conf);
    }
}

/*
 * Teardown.
 */

static void
FreeState(
    void *blockPtr)
{
    TlsState *s = (TlsState *) blockPtr;

    if (s->sess) {
	tlsb_sess_free(s->sess);
    }
    TlsConfRelease(s->conf);
    if (s->command) {
	Tcl_DecrRefCount(s->command);
    }
    if (s->vcmd) {
	Tcl_DecrRefCount(s->vcmd);
    }
    if (s->error) {
	Tcl_DecrRefCount(s->error);
    }
    Tcl_Release(s->interp);
    Tcl_Free(s->servername);
    Tcl_Free(s->out);
    Tcl_Free(s);
}

/* Pushes out what is queued, blocking if need be: the caller is closing. */
static void
Drain(
    TlsState *s)
{
    Tcl_DriverBlockModeProc *blockMode =
	    Tcl_ChannelBlockModeProc(Tcl_GetChannelType(s->parent));
    void *parentData = Tcl_GetChannelInstanceData(s->parent);

    if (Flush(s) != EAGAIN || blockMode == NULL) {
	return;
    }
    blockMode(parentData, TCL_MODE_BLOCKING);
    Flush(s);
    if (s->flags & TLS_NONBLOCK) {
	blockMode(parentData, TCL_MODE_NONBLOCKING);
    }
}

static int
TlsClose(
    void *instanceData,
    Tcl_Interp *interp,
    int flags)
{
    TlsState *s = (TlsState *) instanceData;
    Tcl_DriverClose2Proc *parentClose =
	    Tcl_ChannelClose2Proc(Tcl_GetChannelType(s->parent));

    if (flags == TCL_CLOSE_READ && s->phase == TLS_HANDSHAKE) {
	/* Tcl closes reads before flushing; the handshake still needs them. */
	return 0;
    }
    if (s->phase == TLS_OPEN && flags != TCL_CLOSE_READ) {
	tlsb_close_notify(s->sess);
    }
    Drain(s);
    if (flags) {
	/* Half close: shut the matching side below, keep our state. */
	return parentClose(Tcl_GetChannelInstanceData(s->parent), interp,
		flags);
    }
    if (s->timer) {
	Tcl_DeleteTimerHandler(s->timer);
	s->timer = NULL;
    }
    Tcl_ChannelWatchProc(Tcl_GetChannelType(s->parent))(
	    Tcl_GetChannelInstanceData(s->parent), 0);
    s->self = NULL;
    Tcl_EventuallyFree(s, FreeState);
    return 0;
}

/*
 * Construction.
 */

TlsState *
TlsStateNew(
    Tcl_Interp *interp,
    Tcl_Channel parent,
    TlsConf *conf,
    const char *servername,
    Tcl_Obj *command,
    Tcl_Obj *vcmd)
{
    TlsState *s = (TlsState *) Tcl_Alloc(sizeof(TlsState));
    tlsb_io io;
    char err[256];
    int nonblocking = 0;
    Tcl_DString ds;

    memset(s, 0, sizeof(*s));
    s->held = TLSB_WANT_READ;
    s->interp = interp;
    Tcl_Preserve(interp);
    s->conf = conf;
    TlsConfRetain(conf);
    if ((s->command = command) != NULL) {
	Tcl_IncrRefCount(command);
    }
    if ((s->vcmd = vcmd) != NULL) {
	Tcl_IncrRefCount(vcmd);
    }
    if (servername && *servername) {
	s->servername = (char *) Tcl_Alloc(strlen(servername) + 1);
	strcpy(s->servername, servername);
    }

    io.ud = s;
    io.recv = RecvProc;
    io.send = SendProc;
    io.verify = vcmd ? TlsVerify : NULL;
    s->sess = tlsb_sess_new(conf->conf, s->servername, &io, err, sizeof(err));
    if (s->sess == NULL) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj(err, -1));
	Tcl_SetErrorCode(interp, "TLS", "IMPORT", NULL);
	FreeState(s);
	return NULL;
    }

    Tcl_DStringInit(&ds);
    if (Tcl_GetChannelOption(NULL, parent, "-blocking", &ds) == TCL_OK) {
	Tcl_GetBoolean(NULL, Tcl_DStringValue(&ds), &nonblocking);
	nonblocking = !nonblocking;
    }
    Tcl_DStringFree(&ds);
    if (nonblocking) {
	s->flags |= TLS_NONBLOCK;
    }

    s->self = Tcl_StackChannel(interp, &tlsChannelType, s,
	    Tcl_GetChannelMode(parent), parent);
    if (s->self == NULL) {
	FreeState(s);
	return NULL;
    }
    s->parent = Tcl_GetStackedChannel(s->self);
    UpdateWatch(s);
    return s;
}

TlsState *
TlsGetState(
    Tcl_Interp *interp,
    Tcl_Obj *chanObj)
{
    Tcl_Channel chan = Tcl_GetChannel(interp, Tcl_GetString(chanObj), NULL);

    if (chan == NULL) {
	return NULL;
    }
    chan = Tcl_GetTopChannel(chan);
    if (Tcl_GetChannelType(chan) != &tlsChannelType) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf(
		"bad channel \"%s\": not a TLS channel",
		Tcl_GetString(chanObj)));
	Tcl_SetErrorCode(interp, "TLS", "CHANNEL", NULL);
	return NULL;
    }
    return (TlsState *) Tcl_GetChannelInstanceData(chan);
}
