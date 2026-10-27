/*
 * tlsInt.h --
 *
 *	Declarations shared by the Tcl side of the TLS packages.
 */

#ifndef TLSINT_H
#define TLSINT_H

#include <tcl.h>
#include <errno.h>
#include "tlsb.h"
#include "x509.h"

#ifndef TLS_PKG
#   error "TLS_PKG must name the package, e.g. -DTLS_PKG=\"tlschan::wolfssl\""
#endif
#define TLS_NS		"::" TLS_PKG

#ifndef ECONNABORTED
#   define ECONNABORTED ECONNRESET
#endif

/* Configuration shared between channels through -model. */
typedef struct TlsConf {
    Tcl_Size refCount;
    tlsb_conf *conf;
    int server;
} TlsConf;

typedef enum {
    TLS_HANDSHAKE,
    TLS_OPEN,
    TLS_FAILED
} TlsPhase;

#define TLS_NONBLOCK	(1 << 0)	/* channel is in nonblocking mode */
#define TLS_STARVED	(1 << 1)	/* last read from below would block */
#define TLS_STARTED	(1 << 2)	/* handshake has been kicked off */
#define TLS_BUSY	(1 << 3)	/* inside the backend or below */

typedef struct TlsState {
    Tcl_Channel self;		/* the TLS channel */
    Tcl_Channel parent;		/* channel below us */
    Tcl_Interp *interp;		/* for callbacks */
    Tcl_Obj *command;		/* -command */
    Tcl_Obj *vcmd;		/* -validatecommand */
    TlsConf *conf;		/* counted reference */
    tlsb_sess *sess;
    char *servername;		/* -servername, NULL if none */
    TlsPhase phase;
    int flags;			/* TLS_NONBLOCK ... TLS_BUSY */
    int want;			/* interest set by the generic layer */
    int below;			/* watch mask last set on the parent */
    Tcl_TimerToken timer;
    long held;			/* EOF or error kept behind data returned,
				 * TLSB_WANT_READ if none */
    int errorCode;		/* POSIX error once phase is TLS_FAILED */
    Tcl_Obj *error;		/* message once phase is TLS_FAILED */
    unsigned char *out;		/* ciphertext the parent didn't take yet */
    size_t outStart, outEnd, outSize;
} TlsState;

/* tlsIO.c */
const Tcl_ChannelType *	TlsChannelType(void);
TlsState *	TlsGetState(Tcl_Interp *interp, Tcl_Obj *chanObj);
TlsState *	TlsStateNew(Tcl_Interp *interp, Tcl_Channel parent,
		    TlsConf *conf, const char *servername, Tcl_Obj *command,
		    Tcl_Obj *vcmd);
int		TlsHandshake(TlsState *s);
void		TlsConfRetain(TlsConf *conf);
void		TlsConfRelease(TlsConf *conf);

/* tls.c */
void		TlsInvokeCommand(TlsState *s, Tcl_Size objc,
		    Tcl_Obj *const objv[]);
int		TlsVerify(void *ud, int depth, const uint8_t *der, size_t len,
		    int ok, const char *err);

#endif /* TLSINT_H */
