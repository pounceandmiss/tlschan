# helpers.tcl --
#
#	Shared setup for the test files.

package require tcltest 2.5
namespace import -force ::tcltest::*

set pkg $env(TLS_PACKAGE)
package require $pkg
set T ::$pkg
set certs [file join [file dirname [file normalize [info script]]] certs]
foreach f {ca-cert server-cert server-key client-cert client-key
	selfsigned-cert selfsigned-key server-key-enc expired-cert expired-key
	inter-cert below-cert below-key} {
    set $f [file join $certs $f.pem]
}

testConstraint linux [file readable /proc/self/stat]
testConstraint network [expr {[info exists env(TLS_NETWORK)]
	&& $env(TLS_NETWORK)}]

proc readfile {name} {
    set f [open $name rb]
    try {read $f} finally {close $f}
}

# Waits for a variable to be set, failing after ms milliseconds.
proc await {varName {ms 5000}} {
    upvar #0 $varName var
    if {![info exists var]} {
	set id [after $ms [list set $varName timeout]]
	vwait $varName
	after cancel $id
    }
    return $var
}

# In-process echo server; returns the port. Peers land in ::srv(chan).
proc echo_server {args} {
    global T server-cert server-key srv
    array unset srv
    set srv(listen) [${T}::socket -server echo_accept \
	    -certfile ${server-cert} -keyfile ${server-key} \
	    {*}$args -myaddr 127.0.0.1 0]
    lindex [chan configure $srv(listen) -sockname] 2
}

proc echo_accept {chan addr port} {
    set ::srv(chan) $chan
    chan configure $chan -blocking 0 -buffering line -translation lf
    chan event $chan readable [list echo_readable $chan]
}

proc echo_readable {chan} {
    global T
    if {[catch {gets $chan line} n]} {
	set ::srv(error) $n
	close $chan
	return
    }
    if {$n >= 0} {
	set ::srv(status) [${T}::status $chan]
	puts $chan $line
    } elseif {[eof $chan]} {
	set ::srv(eof) 1
	close $chan
    }
}

proc stop_server {} {
    global srv
    foreach k {chan listen} {
	if {[info exists srv($k)]} {
	    catch {close $srv($k)}
	}
    }
    array unset srv
}

# Nonblocking client: sends line, waits for the echo. Returns the reply or
# the error raised on the way.
proc roundtrip {chan line} {
    global rt
    unset -nocomplain rt
    chan configure $chan -blocking 0 -buffering line -translation lf
    chan event $chan readable [list apply {{chan} {
	if {[catch {gets $chan line} n]} {
	    set ::rt [list error $n]
	} elseif {$n >= 0} {
	    set ::rt [list ok $line]
	} elseif {[eof $chan]} {
	    set ::rt [list error eof]
	} else {
	    return
	}
	chan event $chan readable {}
    }} $chan]
    if {[catch {puts $chan $line} err]} {
	return [list error $err]
    }
    await rt
}

# TLS server in a child process, for blocking clients: accept is the body
# of its accept {chan addr port} proc, which sets ::done when the child may
# exit. Returns {pipe port}.
proc child_server {cert key accept} {
    global pkg
    set f [makeFile [string map [list @PKG@ $pkg @ACCEPT@ [list $accept]] {
	package require @PKG@
	set T ::@PKG@
	after 20000 exit		;# a failing test must not hang the run
	lassign $argv cert key
	proc accept {c a p} @ACCEPT@
	set s [${T}::socket -server accept -certfile $cert -keyfile $key \
	    -myaddr 127.0.0.1 0]
	puts [lindex [chan configure $s -sockname] 2]
	flush stdout
	vwait done
    }] child.tcl]
    set pipe [open |[list [interpreter] $f $cert $key] r]
    gets $pipe port
    list $pipe $port
}

# A connected pair of plain sockets.
proc socketpair {} {
    set l [socket -server {apply {{s a p} {set ::peer $s}}} -myaddr 127.0.0.1 0]
    set c [socket 127.0.0.1 [lindex [chan configure $l -sockname] 2]]
    await ::peer
    close $l
    list $c $::peer[unset ::peer]
}

# CPU seconds consumed by this process so far.
proc cputime {} {
    set stat [readfile /proc/self/stat]
    set stat [string range $stat [string last ) $stat]+2 end]
    expr {([lindex $stat 11] + [lindex $stat 12]) / 100.0}
}
