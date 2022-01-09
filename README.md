TCL script to refresh ipset deny lists.

Creates denylist-host and denylist-net which can be used in iptable rules

## lists
[FireHOL](https://iplists.firehol.org/) levels 1-3

## ipset
YMMV, you might need to initialize the ipset names prior in your iptables scripts
```
ipset -q create denylist-host iphash
ipset -q create denylist-net nethash
```

## iptables
```
iptables -A DENYLIST -p ALL -m set --match-set denylist-host src -j DROP-DENYLIST
iptables -A DENYLIST -p ALL -m set --match-set denylist-net src -j DROP-DENYLIST
iptables -A DENYLIST -p ALL -m set --match-set denylist-host dst -j DROP-DENYLIST
iptables -A DENYLIST -p ALL -m set --match-set denylist-net dst -j DROP-DENYLIST

iptables -I INPUT 1 -i $wan -j DENYLIST
iptables -I OUTPUT 1 -o $wan -j DENYLIST

```
