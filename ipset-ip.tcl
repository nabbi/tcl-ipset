#!/bin/sh
# the next line restarts using tclsh \
exec tclsh "$0" "$@"

## Copyright (C) 2021-2024 nic@boet.cc

set path [file dirname [file normalize [info script]]]

source $path/common.tcl

proc help {} {
    puts "ip address input to ipset"
    puts "Usage:     $::argv0 <setname> <file>"
    puts "Example:   $::argv0 private lists/private"
    exit 64
}

if { [llength $argv] != 2 } {
    puts "Incorrect number of arguments"
    [help]
}

set setname [lindex $argv 0]
set file_ips [lindex $argv 1]

main $setname [import $file_ips]

