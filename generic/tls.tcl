# tls.tcl --
#
#	Script level of the TLS packages, evaluated in the package namespace.

variable defaults {}
variable listeners	;# id -> listening socket, the -model of its connections
variable nextId 0

# Default options for socket. As in tcltls, each call replaces them.
proc init {args} {
    variable defaults
    if {[llength $args] % 2} {
	return -code error "wrong # args: should be\
		\"[lindex [info level 0] 0] ?-option value ...?\""
    }
    set defaults [dict remove $args -model -server -servername]
}

proc socket {args} {
    variable defaults
    set args [list {*}$defaults {*}$args]
    set sopts {}
    set iopts {}
    set auto 1
    for {set i 0} {$i < [llength $args]} {incr i} {
	set opt [lindex $args $i]
	if {![string match -* $opt]} break
	if {$opt eq "-async"} {
	    lappend sopts -async
	    continue
	}
	if {$i + 1 >= [llength $args]} {
	    return -code error "value for \"$opt\" missing"
	}
	set val [lindex $args [incr i]]
	switch -- $opt {
	    -myaddr - -myport - -reuseaddr - -reuseport {lappend sopts $opt $val}
	    -server {set callback $val}
	    -autoservername {set auto $val}
	    default {lappend iopts $opt $val}
	}
    }
    set args [lrange $args $i end]
    set self [namespace current]

    if {[info exists callback]} {
	if {[llength $args] != 1} {
	    return -code error "wrong # args: should be\
		    \"${self}::socket -server command ?options? port\""
	}
	variable listeners
	variable nextId
	# Forget servers closed since; their Accept can't run any more.
	foreach {id chan} [array get listeners] {
	    if {$chan ni [chan names]} {
		unset listeners($id)
	    }
	}
	set id [incr nextId]
	set listeners($id) [::socket -server \
		[list ${self}::Accept $id $iopts $callback] {*}$sopts {*}$args]
	return $listeners($id)
    }

    if {[llength $args] != 2} {
	return -code error "wrong # args: should be\
		\"${self}::socket ?options? host port\""
    }
    lassign $args host port
    if {$auto && ![dict exists $iopts -servername]} {
	lappend iopts -servername $host
    }
    set chan [::socket {*}$sopts $host $port]
    try {
	import $chan {*}$iopts
    } on error {msg opts} {
	catch {close $chan}
	return -options $opts $msg
    }
}

proc Accept {id iopts callback chan addr port} {
    variable listeners
    try {
	import $chan -server 1 -model $listeners($id) {*}$iopts
    } on error {msg opts} {
	catch {close $chan}
	return -options $opts $msg
    }
    uplevel #0 [list {*}$callback $chan $addr $port]
}

# tcltls 2 names.
interp alias {} [namespace current]::starttls {} [namespace current]::import
interp alias {} [namespace current]::unstack {} [namespace current]::unimport
