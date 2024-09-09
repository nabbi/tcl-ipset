#!/bin/sh
# the next line restarts using tclsh \
exec tclsh "$0" "$@"

## Copyright (C) 2021-2024 nic@boet.cc
#set debug 1
#set trace 1

set path [file dirname [file normalize [info script]]]

source $path/common.tcl
source $path/dns.tcl

proc help {} {
    puts "FQDN hostname input to ipset"
    puts "Usage:     $::argv0 <setname> <file> (retry default:1)"
    puts "Example:   $::argv0 admin lists/local.admin-hosts 5"
    exit 64
}

if { [llength $argv] < 2 || [llength $argv] > 3 } {
    puts "Incorrect number of arguments"
    [help]
}

set setname [lindex $argv 0]
set file_hosts [lindex $argv 1]

if { [llength $argv] == 3 } {
    set retry [lindex $argv 2]
} else {
    set retry 1
}


append raw_hosts [import $file_hosts]
if {$trace} { puts "# raw_hosts: $raw_hosts" }

append raw_ips [host2ip_loop $raw_hosts $retry]
# if {$trace} { puts "# raw_ips $raw_ips" }

main $setname $raw_ips

