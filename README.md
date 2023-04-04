## TCL IPSet

TCL scripts for managing ipset (iptables sets)

* Intergrates with [CIDR Route Summarizaion](https://github.com/nabbi/route-summarization)
* IPv4 and IPv6 support
* source from url or local files
* Exclusion of false positives

## FireHol Deny lists

* [FireHOL](https://iplists.firehol.org/) levels 1-3

## Private Bogon list

* [local private networks](./lists/private)

## Usage

```shell
sudo ./ipset-denylists.tcl
sudo ./ipset-private.tcl
```

### iptables

YMMV

```iptables
-N DROP-DENYLIST
-A DROP-DENYLIST -m limit --limit 1/second --limit-burst 100 -j LOG --log-prefix "iptables[denylist]: "
-A DROP-DENYLIST -j DROP

-N DENYLIST-SRC
-A DENYLIST-SRC -p ALL -m set --match-set denylist-host src -j DROP-DENYLIST
-A DENYLIST-SRC -p ALL -m set --match-set denylist-net src -j DROP-DENYLIST

-A INPUT -p tcp -m multiport --dports 22,443 -m conntrack --ctstate NEW -j DENYLIST-SRC

```

### cron

```crontab
0 1 * * *       root    /opt/ipset-denylists/ipset-denylists-update.tcl && /etc/init.d/ipset save >  /var/log/ipset-denylist.log 2>&1
```

