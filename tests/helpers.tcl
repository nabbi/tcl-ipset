# shared setup for the test files: a scratch directory, fake commands on a
# controlled PATH, and constraints for the real summarizers

package require tcltest 2.5
namespace import ::tcltest::*

set ::repo [file normalize [file join [file dirname [info script]] ..]]

# locate the real tools before PATH is replaced
# AGGREGATE_CIDR / PERL_AGGREGATE override the PATH lookup
proc find_real {envvar name} {
    if { [info exists ::env($envvar)] } {
        set f [file normalize $::env($envvar)]
        if { [file executable $f] && ! [file isdirectory $f] } { return $f }
        return ""
    }
    set p [auto_execok $name]
    if { [llength $p] } { return [lindex $p 0] }
    return ""
}
set ::real(aggregate-cidr) [find_real AGGREGATE_CIDR aggregate-cidr]
set ::real(aggregateCIDR.pl) [find_real PERL_AGGREGATE aggregateCIDR.pl]
set ::real(perl) [find_real PERL perl]

testConstraint aggregateCidr [expr {$::real(aggregate-cidr) ne ""}]
testConstraint perlAggregate [expr {
    $::real(aggregateCIDR.pl) ne "" && $::real(perl) ne ""
    && ![catch {exec $::real(perl) -MNet::CIDR::Lite -e 1}]
}]

# CI sets REQUIRE_TOOLS so missing tools fail the run instead of skipping
if { [info exists ::env(REQUIRE_TOOLS)] && $::env(REQUIRE_TOOLS) } {
    foreach c {aggregateCidr perlAggregate} {
        if { ! [testConstraint $c] } {
            error "REQUIRE_TOOLS is set but constraint $c is not met"
        }
    }
}

# scratch space under the repo rather than /tmp: fake commands must be
# executable, and /tmp is often mounted noexec
set ::work [file join $::repo tests .work [pid]]
file delete -force $::work
file mkdir $::work
set ::bin [file join $::work bin]
set ::log [file join $::work log]

# empty bin directory as the whole PATH: only the commands a test installs
# can be found. fakes use absolute paths for anything they run themselves
proc bin_reset {} {
    file delete -force $::bin $::log
    file mkdir $::bin $::log
    set ::env(PATH) $::bin
    # auto_execok caches lookups across PATH changes
    unset -nocomplain ::auto_execs
}

# install a fake command running the given sh script body
proc fake {name body} {
    set f [file join $::bin $name]
    set fh [open $f w]
    puts $fh "#!/bin/sh\n$body"
    close $fh
    file attributes $f -permissions 0755
    unset -nocomplain ::auto_execs
    return $f
}

# fake that records its arguments, one call per line, then echoes stdin
proc fake_logged {name {after {exec /bin/cat}}} {
    fake $name "printf '%s\\n' \"\$*\" >> [file join $::log $name]\n$after"
}

# lines recorded by fake_logged, {} if never called
proc calls {name} {
    set f [file join $::log $name]
    if { ! [file exists $f] } { return {} }
    set fh [open $f r]
    set data [read -nonewline $fh]
    close $fh
    return [split $data "\n"]
}

# make a real tool available on the test PATH
proc install_real {name} {
    file link -symbolic [file join $::bin $name] $::real($name)
    if { $name eq "aggregateCIDR.pl" } {
        file link -symbolic [file join $::bin perl] $::real(perl)
    }
    unset -nocomplain ::auto_execs
}

proc write_file {f data} {
    file mkdir [file dirname $f]
    set fh [open $f w]
    puts -nonewline $fh $data
    close $fh
}

proc read_file {f} {
    set fh [open $f r]
    set data [read $fh]
    close $fh
    return $data
}

# non-empty, non-comment lines, sorted
proc lines {text} {
    set r {}
    foreach l [split $text "\n"] {
        if { $l eq "" || [string index $l 0] eq "#" } { continue }
        lappend r $l
    }
    return [lsort $r]
}

# IPv4 helpers for checking results address by address
proc ip2int {a} {
    lassign [split $a .] o1 o2 o3 o4
    return [expr {($o1 << 24) | ($o2 << 16) | ($o3 << 8) | $o4}]
}

proc int2ip {n} {
    return [join [list [expr {($n >> 24) & 255}] [expr {($n >> 16) & 255}] \
        [expr {($n >> 8) & 255}] [expr {$n & 255}]] .]
}

# addresses covered by an IPv4 host or prefix, as integers
proc expand4 {entry} {
    if { [string first / $entry] < 0 } { set entry $entry/32 }
    lassign [split $entry /] a len
    set base [ip2int $a]
    set size [expr {1 << (32 - $len)}]
    set r {}
    for {set i 0} {$i < $size} {incr i} { lappend r [expr {$base + $i}] }
    return $r
}

# run a script in a separate tclsh, for code that calls exit
# returns {exitcode output}
proc run_tcl {script args} {
    set f [file join $::work child-[incr ::child].tcl]
    write_file $f $script
    set code 0
    if { [catch {exec [info nameofexecutable] $f {*}$args 2>@1} out opts] } {
        set ec [dict get $opts -errorcode]
        if { [lindex $ec 0] eq "CHILDSTATUS" } {
            set code [lindex $ec 2]
        } else {
            set code -1
        }
    }
    return [list $code $out]
}

# load the code under test into this interpreter
proc load_common {} {
    set ::debug 0
    set ::trace 0
    uplevel #0 [list source [file join $::repo common.tcl]]
}

# end of a test file
proc finish {} {
    file delete -force $::work
    catch {file delete [file dirname $::work]}
    cleanupTests
}
