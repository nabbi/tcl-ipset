## TCL IPSet

TCL scripts for managing ipset (iptables address sets)

* Integrates with [CIDR Route Summarization](https://github.com/nabbi/route-summarization-rs) (`aggregate-cidr`), falling back to the [Perl version](https://github.com/nabbi/route-summarization) (`aggregateCIDR.pl`)
* IPv4 and IPv6 support
* FQDN hostname lookups to IP addresses
* source from url or local files
* Exclusion of false positives (see [Exclusions](#exclusions))

## Summarizing and exclusions

Fetched entries are summarized into the fewest prefixes by the first tool
found on `PATH`:

1. `aggregate-cidr` from [route-summarization-rs](https://github.com/nabbi/route-summarization-rs)
2. `aggregateCIDR.pl` from [route-summarization](https://github.com/nabbi/route-summarization) (Perl)

With neither, entries are loaded as listed. Run with `debug` set to see which
tool was used.

### Exclusions

A script's `exclude` list (see `ipset-denylists.tcl`) keeps addresses out of
the sets. Entries can be hosts or prefixes, IPv4 or IPv6.

With `aggregate-cidr`, the list is passed as `--exclude`: the excluded
addresses are removed exactly, and any entry containing one is split around
it. Excluding `140.82.112.3` from `140.82.112.0/24` leaves the other 255
addresses blocked. An invalid exclusion stops the run before any set is
changed.

Without `aggregate-cidr`, only entries identical to an exclusion are dropped,
so an excluded address inside a larger entry (`140.82.112.0/24`, or a `/31`
produced by summarizing) is still blocked. The script prints a warning when
it falls back to this.

## FireHol Deny lists

* [FireHOL](https://iplists.firehol.org/) levels 1-3

## Private Bogon list

* [local private networks](./lists/private)

## Usage

```shell
sudo ./ipset-denylists.tcl
sudo ./ipset-ip.tcl private lists/private
sudo ./ipset-fqdn.tcl app1 lists/local.app1-hostnames
sudo ./ipset-fqdn.tcl app2 lists/local.app2-hostnames 5
```

### iptables

YMMV

```iptables
-N DROP-DENYLIST
-A DROP-DENYLIST -m limit --limit 1/second --limit-burst 100 -j LOG --log-prefix "iptables[denylist]: "
-A DROP-DENYLIST -j DROP

-N DENYLIST-SRC
-A DENYLIST-SRC -4 -p ALL -m set --match-set denylist-host src -j DROP-DENYLIST
-A DENYLIST-SRC -4 -p ALL -m set --match-set denylist-net src -j DROP-DENYLIST
-A DENYLIST-SRC -6 -p ALL -m set --match-set denylist-net6 src -j DROP-DENYLIST

-A INPUT -p tcp -m multiport --dports 22,443 -m conntrack --ctstate NEW -j DENYLIST-SRC

```

### cron

```crontab
0 1 * * *       root    /opt/tcl-ipset/ipset-denylists.tcl && /etc/init.d/ipset save >  /var/log/ipset-denylist.log 2>&1
```


## Testing

```shell
tclsh tests/all.tcl
```

Needs Tcl 8.6 and tcllib. No root or ipset is required: fake `ipset`, `id`,
`curl` and `dig` commands record what the scripts would have run, and each
script runs from a scratch copy so its url cache stays out of the checkout.

Tests that need the real summarizers run when `aggregate-cidr`, or
`aggregateCIDR.pl` with perl and Net::CIDR::Lite, are on `PATH`, and are
skipped otherwise. Point at other copies with `AGGREGATE_CIDR=/path` or
`PERL_AGGREGATE=/path`; set `REQUIRE_TOOLS=1` (as CI does) to fail instead
of skipping. `SEED` and `ITERATIONS` control the randomized exclusion test.

Useful options: `-file exclude.test`, `-match 'rust-*'`, `-verbose bpe`.
