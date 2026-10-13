# run every tests/*.test file, each in its own tclsh
#   tclsh tests/all.tcl [-verbose bpe] [-file summarize.test] [-match name*]
#
# tests needing aggregate-cidr or aggregateCIDR.pl (with perl and
# Net::CIDR::Lite) are skipped when those are not on PATH; set
# AGGREGATE_CIDR / PERL_AGGREGATE to point at them, or REQUIRE_TOOLS=1 to
# fail instead of skipping

package require tcltest 2.5
namespace import ::tcltest::*

configure -testdir [file dirname [file normalize [info script]]] {*}$argv
exit [runAllTests]
