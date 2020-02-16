# icmpv6-test
A tool to test if a specific host responds correctly to various IPv6/ICMPv6 packets.

```$ icmpv6-test.sh <iface> <dstmac> <dstip6> <retries>```

* iface: The interface to send requests to and expect replies from
* dstmac: The MAC address of the target host to query
* dstip6: The link-local IPv6 address of the target host to query
* retries: Number of requests to send per test

## Requirements:

* ipv6calc
* ipv6toolkit from [here](https://github.com/T-X/ipv6toolkit), branch [fixes+mldq6-tool](https://github.com/T-X/ipv6toolkit/tree/fixes%2Bmldq6-tool) (until things are merged [upstream](https://github.com/fgont/ipv6toolkit))
* tcpdump
* iproute2 (for "ip" command)
* grep, sed, cut, pgrep, timeout

You might need to run this script as root for the tcpdump, ip and ipv6toolkit (ns6, icmp6, mldq6) commands.

## What it does

This small script small currently tests if a response from the specified host to the following ICMPv6 packets are received:

* MLDv1 Query -> MLD Report?
* Neighbor Solicitation -> Neighbor Advertisement?
* ICMPv6 Echo Request -> ICMPv6 Echo Reply?

It displays the requests send and responses received and displays a summary of packets send vs. responses received. It also creates a pcap log icmpv6_\<icmp6-type\>-\<unix-timestamp\>.pcapng.
