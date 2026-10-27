/*
 * tclsh.c --
 *
 *	A tclsh with the static packages of this build linked in, for running
 *	the test suite against them. packages.h lists PKG("name", Prefix);
 *	LIBDIR is where the umbrella package tlschan lives.
 */

#include <tcl.h>

#define PKG(name, prefix) extern Tcl_PackageInitProc prefix##_Init;
#include "packages.h"
#undef PKG

static int
AppInit(
    Tcl_Interp *interp)
{
    if (Tcl_Init(interp) != TCL_OK) {
	return TCL_ERROR;
    }
#define PKG(name, prefix) \
    Tcl_StaticLibrary(NULL, #prefix, prefix##_Init, NULL); \
    Tcl_EvalEx(interp, "package ifneeded " name " " VERSION \
	    " {load {} " #prefix "}", -1, TCL_EVAL_GLOBAL);
#include "packages.h"
#undef PKG
    /* The umbrella package tlschan is a script in the build's lib dir. */
    Tcl_EvalEx(interp, "lappend ::auto_path {" LIBDIR "}", -1,
	    TCL_EVAL_GLOBAL);
    return TCL_OK;
}

int
main(
    int argc,
    char **argv)
{
    Tcl_Main(argc, argv, AppInit);
    return 0;
}
