
# provides dns hostname functions for ipset

proc unique {data} {
    set d {}
    foreach l $data {
        lappend d $l
    }
    set u [join [lsort -unique $d] "\n"] 
    return $u
}

# normally, firewall fqdn resolution to ip address process;
# requires all addresses to be returned in a single A or AAAA lookup,
# have a reasonably high TTL (several minutes not a few seconds),
# i.e. less frequent changes in the query answer section
#
# This loop attempts to compile a list of address for hostnames which
# have low TTL with round robin results return
#
# This likely will not catch silliness of overly aggressive
# address changes or large randomness in the number of addresses
# configured behind the hostname.
proc host2ip_loop {hostnames retry} {
    global debug
    global trace

    for {set i 0} {$i < $retry} {incr i} {
        append results [host2ip $hostnames]
        if {$trace} {
            set u [unique $results]
            puts "# results (str:[string length $results] uniq:[llength $u]):\n$u"
        }

        # do not sleep if last interation
        if { [expr $i + 1 != $retry] } {
            if {$debug} { puts "# sleep #$i" }
            after 30000
        }
    }

    return [unique $results]
}

proc host2ip {hosts} {
    # TODO the results contains an echo of the hosetname
    # append newlines to force line wrap
    set dig "\n"
    foreach hostname $hosts {
        append dig [mydig $hostname "a"] 
        append dig "\n"
        append dig [mydig $hostname "aaaa"]
        append dig "\n"
    }

    return $dig
}

proc mydig {hostname type} {
    set status 0
    if {[catch {exec dig -t $type $hostname +short} stdout options]} {
        set details [dict get $options -errorcode]
        if {[lindex $details 0] eq "CHILDSTATUS"} {
            set status [lindex $details 2]
        } else {
            set status 70
        }
    }

    # exit if error non-zero
    if { $status } {
        puts "## Error $status ##"
        puts $stdout
        exit 1
    }

    return $stdout
}
