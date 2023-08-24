#!/bin/sh
# the next line restarts using tclsh \
exec tclsh "$0" "$@"

## Copyright (C) 2021-2023 nic@boet.cc
# populate ipset from web url containing IOC to be blocked within iptable rules

set path [file dirname [file normalize [info script]]]

source $path/common.tcl

#FireHOL IP List
lappend urls "https://iplists.firehol.org/files/firehol_level1.netset"
lappend urls "https://iplists.firehol.org/files/firehol_level2.netset"
lappend urls "https://iplists.firehol.org/files/firehol_level3.netset"

# ignore these values
# firehol contains RFC1918 as bogons
lappend exclude "10.0.0.0/8"
lappend exclude "192.168.0.0/16"
lappend exclude "172.16.0.0/12"
#github.com
lappend exclude "140.82.112.4"
lappend exclude "140.82.112.3"
lappend exclude "140.82.114.3"
lappend exclude "185.199.108.133"
lappend exclude "185.199.110.133"
lappend exclude "185.199.111.133"

append rawlist [fetch_all $urls]
append rawlist [import $path/lists/local.deny]

main "denylist" $rawlist

