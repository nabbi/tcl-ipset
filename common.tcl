
package require ip
package require sha256

if { ! [info exists debug] } { set debug 0 }
if { ! [info exists trace] } { set trace 0 }

proc check_root {} {
    if { [exec id -u] eq 0 } {
        return
    } else {
        puts "ipset commands requires root permissions"
        exit 1
    }
}

# fetch url lists using, curl with local cache checks
proc curl {url} {
    
    set hash [sha2::sha256 $url]

    if { [cache_valid $hash] } {
        puts "# using recent cache file for $url"
        return [cache_r $hash]
    }

    #ca; force the tls validation against our own PKI, this adds a retry fetch condition and confirms that the traffic is inspected
    #max-time; prevent sites (ie www.accuweather.com) from hanging connection open caveat is exit code 28
    #location; follows redirects to initiate new tls connection if domain name changes
    try {
        set results [exec curl --fail --silent --show-error --location --max-time 15 --capath /usr/local/share/ca-certificates/ "${url}"]
        set status 0
    } trap CHILDSTATUS {results options} {
        set status [lindex [dict get $options -errorcode] 2]
    }

    if { $status } {
        puts "# curl error $status $url"
        puts "# falling back to cache file, if it exists"
        return [cache_r $hash]
    }

    cache_w $hash $results
    return -code $status $results
}

# Curl fetch each url ip list
proc fetch_all {urls} {
   foreach u $urls {
        append r [curl $u]
        #add a tailing newline as some lists omit it on the last file line causing merge issues of the last and first elements
        append r "\n"
    }
    return $r
}

# write results to disk cache
proc cache_w {hash results} {
    global path

    file mkdir $path/cache
    set fh [open $path/cache/$hash {w}]

    puts $fh "# [clock seconds]"
    puts $fh $results

    close $fh
}

# read (attempt) results from disk cache
proc cache_r {hash} {
    global path
    global debug

    if { ! [file exists $path/cache/$hash] } {
        if ($debug) { puts "# no cache file found for $url" }
        return "# empty"
    }

    set fh [open $path/cache/$hash {r}]
    set data [read $fh]
    close $fh

    return $data
}

# check age of cache file
proc cache_valid {hash} {
    global path
    global debug

    if { ! [file exists $path/cache/$hash] } {
        if ($debug) { puts "# no cache file found for $hash" }
        return false
    }

    if { [expr [clock seconds] - [file mtime $path/cache/$hash] > 3600] } {
        if ($debug) { puts "# cache file state" }
        return false
    }

    return true
}

proc import {filename} {
    global debug
    global trace

    if { ! [file exists $filename] } {
        puts "File not found, skipping $filename"
        return
    }

    set r ""
    set fh [open $filename {r}]
    set lines [split [read $fh] "\n"]
    close $fh

    foreach l $lines {
        # ignore comments and empty lines
        if { [string index $l 0] == "#" || [string length $l] == 0 } {
            if {$trace} { puts "# ignore line $l" }
            continue
        }
        
        if {$trace} { puts "# importing $l" }
        append r "$l\n"
    }

    return $r
}

# check for https://github.com/nabbi/route-summarization
# does nothing if not found in system path
proc cidr_summarize {r} {
    global debug

    try {
        set cmd [exec which aggregateCIDR.pl]
        set status 0
    } trap CHILDSTATUS {cmd options} {
        set status [lindex [dict get $options -errorcode] 2]
    }

    if { $status } {
        # do nothing but pass it back
        return $r
    } else {
        if ($debug) { puts "# summarizing using Perl Net::CIDR::Lite" }
        return [exec aggregateCIDR.pl -q << $r]
    }
}

# Sorts the fetched url results into hosts and network lists
proc process_results {results} {
    global debug
    global trace
    global exclude

    #initialize empty lists to store our validated results
    set haship {}
    set hashnet {}
    set hashnet6 {}

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
        #if {!  ( [ip::is 4 $r] || [ip::is 6 $r] ) } {
        #    if {$debug} { puts "# invalid ip address $r" }
        #    continue
        #}

        # skip entry if on globalvar exclusion list
        if { [info exists exclude] } {
            if { [lsearch $exclude $r] >= 0 } {
                if {$debug} { puts "# excluding $r" }
                continue
            }
        }

        if { [ip::is 4 $r] } {
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
            }
            unset ip
            unset mask

        # TODO expand ipv6 checks
        } elseif { [ip::is 6 $r] } {
            if {$trace} { puts "ipv6 $r" }
            lappend hashnet6 $r
            continue
        # ignore any non-conforming lines
        } else {
            if {$debug} { puts "# ignore unparsed  $r" }
            continue
        }

    }

    # de-duplicate our sources
    # there is error handling in ipset proc routine to continue so this sort is not required
    set haship [lsort -unique $haship]
    set hashnet [lsort -unique $hashnet]
    set hashnet6 [lsort -unique $hashnet6]

    return [list $haship $hashnet $hashnet6]
}


# populates ipset
proc ipset_populate {setname type values family} {

    set temp "${setname}-temp"
    # normally this temp set should not exist
    try {
        exec ipset destroy $temp
    } trap {} {result options} {
        #if {$trace} { puts "# temp $result" }
    }

    # the real set might not exist if this is the inital exec
    try {
        exec ipset create $setname $type family $family
    } trap {} {result options} {
        #if {$trace} { puts "# temp $result" }
    }

    exec ipset create $temp $type family $family

    foreach v $values {
        try {
            exec ipset add $temp $v
        } trap {} {result options} {
            puts "# $v $result"
            continue
        }
    }

    exec ipset swap $temp $setname
    exec ipset destroy $temp
}

# creats an empty ipset
proc ipset_empty {setname type family} {
    # the real set might not exist if this is the inital exec
    try {
        exec ipset create $setname $type family $family
    } trap {} {result options} {
        #if {$trace} { puts "# temp $result" }
    }

    exec ipset flush $setname
}

proc main {prefix rawlist} {
    global debug
    global trace

    check_root

    if {$trace} { puts "# rawlist:\n$rawlist" }
    
    set summarized [cidr_summarize $rawlist]
    if {$trace} { puts "# summarized:\n$summarized" }
    
    set sorted [process_results $summarized]
    if {$trace} { puts "# sorted:\n$sorted" }


    if {$debug} { puts "# ipset; creating and populating" }
    if { [llength [lindex $sorted 0]] > 0 } {
        ipset_populate "${prefix}-host" "iphash" [lindex $sorted 0] "ipv4"
    } else {
        if {$debug} { puts "# ipset; flushing ${prefix}-host no values" }
        ipset_empty "${prefix}-host" "iphash" "ipv4"
    }
  
    if { [llength [lindex $sorted 1]] > 0 } {
        ipset_populate "${prefix}-net" "nethash" [lindex $sorted 1] "ipv4"
    } else {
        if {$debug} { puts "# ipset; flushing ${prefix}-net no values" }
        ipset_empty "${prefix}-net" "nethash" "ipv4"
    }

    if { [llength [lindex $sorted 2]] > 0 } {
        ipset_populate "${prefix}-net6" "nethash" [lindex $sorted 2] "ipv6"
    } else {
        if {$debug} { puts "# ipset; flushing ${prefix}-net6 no values" }
        ipset_empty "${prefix}-net6" "nethash" "ipv6"
    }
}


