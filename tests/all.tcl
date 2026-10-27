# all.tcl --
#
#	Runs the test suite against the package named by $env(TLS_PACKAGE).

package require tcltest 2.5
namespace import ::tcltest::*

configure -testdir [file dirname [file normalize [info script]]] {*}$argv
puts "Testing [package require $env(TLS_PACKAGE)] ($env(TLS_PACKAGE))\
	with [$env(TLS_PACKAGE)::version]"
exit [runAllTests]
