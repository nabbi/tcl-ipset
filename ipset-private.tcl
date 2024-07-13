#!/bin/sh
# the next line restarts using tclsh \
exec tclsh "$0" "$@"

## Copyright (C) 2021-2023 nic@boet.cc

puts "# Deprecated script. Consider ipset-ip.tcl instead"

set path [file dirname [file normalize [info script]]]

source $path/common.tcl

main "private" [import $path/lists/private]

