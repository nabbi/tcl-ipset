## TCL IPSet

TCL scripts for managing ipset (iptables address sets)

* Intergrates with [CIDR Route Summarizaion](https://github.com/nabbi/route-summarization)
* IPv4 and IPv6 support
* FQDN hostname lookups to IP addresses
* source from url or local files
* Exclusion of false positives

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

