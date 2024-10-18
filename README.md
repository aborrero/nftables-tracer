# nftables-tracer
helper tool to trace packets traversing nftables rulesets

Basically:
 * automate all the steps in https://wiki.nftables.org/wiki-nftables/index.php/Ruleset_debug/tracing
 * add some colors to the output

![Screenshot](https://raw.githubusercontent.com/aborrero/nftables-tracer/main/screenshot.png)

Examples:

```
# show traces for all traffic, the default
$ sudo ./nftables-tracer.py

# show traces for all icmp packets
$ sudo ./nftables-tracer.py "ip protocol icmp"

# show traces for all UDP packets
$ sudo ./nftables-tracer.py "meta nfproto udp"

# show traces for a specific source address and source UDP port
$ sudo ./nftables-tracer.py "ip saddr 8.8.8.8 udp sport 53"

# show traces for all IPv4 packets
$ sudo ./nftables-tracer.py "meta nfproto ipv4"

# show traces for all IPv6 packets
$ sudo ./nftables-tracer.py "meta nfproto ipv6"

# show traces for packets with destination TCP port 22, in the output path
$ sudo ./nftables-tracer.py --output "tcp dport 22"

# show traces for all packets in the prerouting path (forward and local input)
$ sudo ./nftables-tracer.py --prerouting
```

Usage:

```
$ sudo ./nftables-tracer.py  --help
usage: nftables-tracer.py [-h] [-a] [-c] [-p | -o] [nftables_rule_match]

a helper tool to trace nftables rulesets

positional arguments:
  nftables_rule_match  nftables rule match to filter trace events

options:
  -h, --help           show this help message and exit
  -a, --all            show all trace events, including the ones by this very tool
  -c, --no-colors      disable colors
  -p, --prerouting     only trace from prerouting hook
  -o, --output         only trace from output hook
```

By default it uses no match, meaning it will show traces for all traffic.

Hopefully, this single file, self contained script will not have many python dependencies, so it should be fairly
easy to wget/curl and just run it when you need it.

See also:
 * https://github.com/aojea/nftrace
