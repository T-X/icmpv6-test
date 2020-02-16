#!/bin/bash
# SPDX-License-Identifier: CC0-1.0
# Copyright (C) 2020: Linus Lüssing <linus.luessing@c0d3.blue>

usage() {
	echo "Usage:"
	echo "  $0 <iface> <dstmac> <dstip6> <retries>"
}

check_params() {
	[ -z "$SRCMAC" ] && {
		echo "Error: Could not determine SRCMAC" >&2
		return 1
	}
	[ -z "$DSTMAC" ] && {
		echo "Error: Could not determine DSTMAC" >&2
		return 1
	}
	[ -z "$SRCIP6" ] && {
		echo "Error: Could not determine SRCIP6" >&2
		return 1
	}
	[ -z "$DSTIP6" ] && {
		echo "Error: Could not determine DSTIP6" >&2
		return 1
	}
	[ -z "$MCGRP" ] && {
		echo "Error: Could not determine MCGRP" >&2
		return 1
	}
	[ -z "$MCASTDSTMAC" ] && {
		echo "Error: Could not determine MCASTDSTMAC" >&2
		return 2
	}
	[ -z "$MCASTDSTIP6" ] && {
		echo "Error: Could not determine MCASTDSTIP6" >&2
		return 2
	}
	[ -z "$RETRIES" ] && {
		echo "Error: Could not determine MCASTDSTIP6" >&2
		return 2
	}
	case "$RETRIES" in
	''|*[!0-9]*)
		echo "Error: Retries argument is not a number" >&2
		return 2
		;;
	esac

	for p in grep pgrep cut sed ipv6calc tcpdump ip timeout icmp6 ns6 mldq6; do
		command -v $p > /dev/null || {
			echo "Error: $p not installed." >&2
			return 2
		}
	done

	return 0
}

RETRIES="$4"

kill_subprocs() {
	local pid="$1"
	local and_self="${2:-false}"
	if procs="$(pgrep -P "$pid")"; then
		for p in $procs; do
			kill_subprocs "$p" true
		done
	fi
	if [[ "$and_self" == true ]]; then
		kill "$pid" 2> /dev/null
	fi
}

get_iface_mac() {
	ip link show dev "$1" | \
		grep "link/ether" | sed "s%.*link/ether \([a-f0-9:]*\) .*%\1%"
}

CAPDATE="`date +%s`"
IFACE="$1"

# SRCMAC: Fetch MAC from interface, we need to use the associated MAC if
# we are an STA connected to an AP
SRCMAC="$(get_iface_mac "$IFACE")"
SRCIP6="fe80::$(ipv6calc -A geneui64 --mac_to_eui64 "$SRCMAC")"

DSTMAC="$2"
DSTIP6="$3"

# Calculate IPv6 solicited multicast address (+ multicast MAC)
MCGRP="$(ipv6calc --addr2fulluncompaddr "$DSTIP6" | sed "s/://g" | cut -c 27-)"
MCASTDSTMAC="33:33:ff:${MCGRP:0:2}:${MCGRP:2:2}:${MCGRP:4:2}"
MCASTDSTIP6="ff02::1:ff${MCGRP:0:2}:${MCGRP:2:4}"


xmit_icmp6_mldq_v1() {
	mldq6 \
		--link-src-addr "$SRCMAC" \
		--link-dst-addr "$1" \
		--src-addr "$SRCIP6" \
		--dst-addr "$2" \
		--mld-addr "::" \
		--mld-resp-delay 3000 \
		-i "$IFACE"
}

xmit_icmp6_nsol() {
	ns6 \
		--link-src-addr "$SRCMAC" \
		--link-dst-addr "$1" \
		--src-addr "$SRCIP6" \
		--dst-addr "$2" \
		--target-address "$DSTIP6" \
		-E "$SRCMAC" \
		-i "$IFACE"
}

xmit_icmp6_echoreq() {
	icmp6 \
		--icmp6 128:0 \
		--link-src-addr "$SRCMAC" \
		--link-dst-addr "$1" \
		--src-addr "$SRCIP6" \
		--dst-addr "$2" \
		-i "$IFACE"
}

CAPFILTER_mldq_v1="$(echo \
	"greater 86 and ip6 and ip6 proto 0 and ip6 protochain 58 and " \
	"(ip6[48] = 130 or ip6[48] = 131) and ip6[49] = 0 and " \
	"(ether src $SRCMAC or ether src $DSTMAC)")"
CAPCNTFILTER_mldq_v1="$(echo \
	"ether src $DSTMAC and ip6[48] = 131 and ip6 dst $MCASTDSTIP6")"

CAPFILTER_nsol="$(echo \
	"ip6 and ip6 proto 58 and " \
	"((icmp6[icmp6type] = icmp6-neighborsolicit and " \
	"  ether src $SRCMAC and ether dst $MCASTDSTMAC)" \
	" or " \
	" (icmp6[icmp6type] = icmp6-neighborsolicit and " \
	"  ether src $SRCMAC and ether dst $DSTMAC)" \
	" or " \
	" (icmp6[icmp6type] = icmp6-neighborsolicit and " \
	"  ether src $SRCMAC and ether dst 33:33:00:00:00:01)" \
	" or " \
	" (icmp6[icmp6type] = icmp6-neighboradvert and " \
	"  ether src $DSTMAC and ether dst $SRCMAC and " \
	"  dst host $SRCIP6))")"
CAPCNTFILTER_nsol="$(echo \
	"icmp6[icmp6type] = icmp6-neighboradvert and " \
	"ether src $DSTMAC and ether dst $SRCMAC")"

CAPFILTER_echoreq="$(echo \
	"ip6 and ip6 proto 58 and " \
	"((icmp6[icmp6type] = icmp6-echo and " \
	"  ether src $SRCMAC and ether dst $MCASTDSTMAC)" \
	" or " \
	" (icmp6[icmp6type] = icmp6-echo and " \
	"  ether src $SRCMAC and ether dst $DSTMAC)" \
	" or " \
	" (icmp6[icmp6type] = icmp6-echo and " \
	"  ether src $SRCMAC and ether dst 33:33:00:00:00:01)" \
	" or " \
	" (icmp6[icmp6type] = icmp6-echoreply and " \
	"  ether src $DSTMAC and ether dst $SRCMAC and " \
	"  dst host $SRCIP6))")"
CAPCNTFILTER_echoreq="$(echo \
	"icmp6[icmp6type] = icmp6-echoreply and " \
	"ether src $DSTMAC and ether dst $SRCMAC")"

cap_icmp6() {
	local capfilter="CAPFILTER_$1"
	timeout $(($RETRIES*8)) tcpdump -q -i "$IFACE" "${!capfilter}" \
		-w - 2> /dev/null | base64
}

cap_icmp6_num_rx() {
	local capcntfilter="CAPCNTFILTER_$1"
	local num_rx="$(echo "$2" | base64 -d | tcpdump -r - \
		"${!capcntfilter}" 2> /dev/null | wc -l)"

	([ -n "$num_rx" ] && echo "$num_rx") || echo 0
}

test_icmp6_exec() {
	local description="$1"
	local sign="$2"
	local ethdst="$3"
	local ip6dst="$4"
	local capture

	(for i in `seq 1 $RETRIES`; do
		sleep 2 && xmit_icmp6_${sign} "$ethdst" "$ip6dst" && sleep 5
	done) &
	capture="$(cap_icmp6 $sign)"

	echo "# $description (Dest.-MAC: $ethdst, dest.-IP6: $ip6dst):"
	echo "-----"
	echo "$capture" | base64 -d | tcpdump -r - 2> /dev/null
	echo "-----"
	echo "Replies received: $(cap_icmp6_num_rx $sign "$capture")/$RETRIES"
	echo ""
	echo "$capture" | base64 -d > ./icmpv6_$sign-"$CAPDATE".pcapng
}

[ $# -ne 4 ] && {
	usage
	exit 1
}

check_params || exit 2

trap 'kill_subprocs $$' EXIT

# Tests:

# Standard:
test_icmp6_exec "MLD Test" "mldq_v1" "33:33:00:00:00:01" "ff02::1"
test_icmp6_exec "Neighbor Discovery Test" "nsol" "$MCASTDSTMAC" "$MCASTDSTIP6"
test_icmp6_exec "ICMPv6 Echo Test" "echoreq" "$DSTMAC" "$DSTIP6"

# Modified:
test_icmp6_exec "MLD Test, modified dest." "mldq_v1" "$DSTMAC" "ff02::1"
test_icmp6_exec "MLD Test, modified dest." "mldq_v1" "$DSTMAC" "$MCASTDSTIP6"
test_icmp6_exec "MLD Test, modified dest." "mldq_v1" "$DSTMAC" "$DSTIP6"

test_icmp6_exec "Neighbor Discovery Test, modified dest." "nsol" "$DSTMAC" "$MCASTDSTIP6"
test_icmp6_exec "Neighbor Discovery Test, modified dest." "nsol" "$DSTMAC" "$DSTIP6"

test_icmp6_exec "ICMPv6 Echo Test, modified dest." "echoreq" "$MCASTDSTMAC" "$DSTIP6"
test_icmp6_exec "ICMPv6 Echo Test, modified dest." "echoreq" "$MCASTDSTMAC" "$MCASTDSTIP6"
test_icmp6_exec "ICMPv6 Echo Test, modified dest." "echoreq" "$MCASTDSTMAC" "ff02::1"
test_icmp6_exec "ICMPv6 Echo Test, modified dest." "echoreq" "33:33:00:00:00:01" "ff02::1"
