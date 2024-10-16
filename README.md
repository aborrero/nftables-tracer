# nftables-tracer
helper tool to trace packets traversing nftables rulesets

![Screenshot](https://raw.githubusercontent.com/aborrero/nftables-tracer/main/screenshot.png)

Examples:

```
$ sudo ./nftables-tracer.py "ip protocol icmp"
$ sudo ./nftables-tracer.py "meta nfproto udp"
$ sudo ./nftables-tracer.py "tcp dport 22"
$ sudo ./nftables-tracer.py "ip saddr 8.8.8.8 udp sport 53"
```

Usage:

```
$ sudo ./nftables-tracer.py  --help
usage: nftables-tracer.py [-h] [-a] [-c] [nftables_rule_match]

a helper tool to trace nftables rulesets

positional arguments:
  nftables_rule_match  nftables rule match to filter trace events

options:
  -h, --help           show this help message and exit
  -a, --all            show all trace events, including the ones by this very tool
  -c, --no-colors      disable colors
```

By default it uses `meta nfproto ipv6`, meaning it will show traces for all IPv6 traffic.

Hopefully, this single file, self contained script will not have many python dependencies, so it should be fairly
easy to wget/curl and just run it when you need it.
