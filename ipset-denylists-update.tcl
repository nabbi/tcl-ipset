#!/bin/sh
# the next line restarts using tclsh \
exec tclsh "$0" "$@"

## Copyright (C) 2021 nic@boet.cc
# populate ipset from web url containing IOC to be blocked within iptable rules

package require ip

set debug 0
set trace 0

set path [file dirname [file normalize [info script]]]
if { [catch { source $path/config.tcl }] } {
    puts "config.tcl does not exist, please create it from config.tcl.example"
    exit 1
}


# run our url fetch with curl
proc curl {url} {
    #ca; force the tls validation against our own PKI, this adds a retry fetch condition and confirms that the traffic is inspected
    #max-time; prevent sites (ie www.accuweather.com) from hanging connection open caveat is exit code 28
    #location; follows redirects to initiate new tls connection if domain name changes
    try {
        set results [exec /usr/bin/curl --fail --silent --show-error --location --max-time 15 --capath /usr/local/share/ca-certificates/ "${url}"]
        set status 0
    } trap CHILDSTATUS {results options} {
        set status [lindex [dict get $options -errorcode] 2]
    }

    if { $status } {
        # we want to continue and skip if one of the feeds is not functional
        # this could purge out a previously successful update as there is no offline caches
        puts "curl $status $url"
        return
    }

    return -code $status $results
    
}

# populates ip set
proc ipset {setname type values} {

    # normally this temp set should not exist
    try {
        exec ipset destroy temp
    } trap {} {result options} {
        #if {$trace} { puts "# temp $result" }
    }

    # the real set might not exist if this is the first exec
    try {
        exec ipset create $setname $type
    } trap {} {result options} {
        #if {$trace} { puts "# temp $result" }
    }

    exec ipset create temp $type

    foreach v $values {
        try {
            exec ipset add temp $v
        } trap {} {result options} {
            puts "# $v $result"
            continue
        }
    }

    exec ipset swap temp $setname
    exec ipset destroy temp

}


# url fetch each ip list
foreach u $urls {
    append results [curl $u]
    #add a tailing newline as some lists omit it on the last file line causing merge issues of the last and first elements
    append results "\n"
}

#initialize empty lists to store our validated results
set haship {}
set hashnet {}

# process the combined url results
# split inputs into ip vs net lists as ipset hashes these differently
foreach r [split $results "\n"] {

    # ignore comments and empty lines
    if { [string index $r 0] == "#" || [string length $r] == 0 } {
        if {$debug} { puts "# ignore line $r" }
        continue
    }

    # ignore lines which do not validate the tcllib ip package
    # I find that this does not perform detailed validations so I pair with additional regex checks
    if {! [ip::is 4 $r] } {
        if {$debug} { puts "# invalid ipv4 $r" }
        continue
    }

    # ignore entry if it's on our exclusion list
    if { [lsearch $exclude $r] >= 0 } {
        if {$debug} { puts "# excluding $r" }
        continue
    }

    # see if we have a netmask included
    if { [regexp {^\d+\.\d+\.\d+\.\d+/\d+$} $r] } {
        set ip [lindex [split $r "/"] 0]
        set mask [lindex [split $r "/"] 1]

        # convert /32 into hosts
        if { $mask == 32 } {
            if {$trace} { puts "host $ip" }
            lappend haship $ip
            continue
        }

        # validate mask bits
        if { [expr {$mask > 0}] && [expr {$mask <= 31}] } {
            if {$trace} { puts "network $ip $mask" }
            lappend hashnet $ip/$mask
            continue
        } else {
            if {$debug} { puts "# invalid netmask $r" }
            continue
        }

    # see if we just have an ipv4 address
    } elseif { [regexp {^\d+\.\d+\.\d+\.\d+$} $r] } {
        if {$trace} { puts "ip $r" }
        lappend haship $r
        continue

    # ignore any non-conforming lines
    } else {
        if {$debug} { puts "# ignore line $r" }
        continue
    }

}

# de-duplicate our sources
# there is error handling in ipset proc routine to continue so this sort is not required
set haship [lsort -unique $haship]
set hashnet [lsort -unique $hashnet]

# populate our sets
ipset "denylist-host" "iphash" $haship
ipset "denylist-net" "nethash" $hashnet


exit 0
