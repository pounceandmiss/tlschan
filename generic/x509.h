/*
 * x509.h --
 *
 *	Minimal X.509 DER decoder producing the dicts of status.
 */

#ifndef X509_H
#define X509_H

#include <stddef.h>
#include <tcl.h>

/*
 * Appends key/value pairs describing the certificate to dict (unshared).
 * Returns TCL_ERROR with a message in interp (may be NULL) if der is not
 * a certificate; malformed inner fields are skipped.
 */
MODULE_SCOPE int	TlsX509Info(Tcl_Interp *interp,
			    const unsigned char *der, size_t len,
			    Tcl_Obj *dict);

#endif /* X509_H */
