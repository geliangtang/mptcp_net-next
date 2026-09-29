#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

. "$(dirname "${0}")/mptcp_lib.sh"

ret=0
ns1=""
ns2=""
capfile=""
capout=""
sin=""
cin=""

cleanup()
{
	[ -n "$sin" ] && rm -f "$sin"
	[ -n "$cin" ] && rm -f "$cin"
	[ -n "$capfile" ] && rm -f "$capfile"
	[ -n "$capout" ] && rm -f "$capout"
	mptcp_lib_ns_exit "$ns1" "$ns2"
}

mptcp_lib_check_mptcp
mptcp_lib_check_tools ip tcpdump

sin=$(mktemp)
cin=$(mktemp)
capfile=$(mktemp /tmp/dsn64_XXXXXX.pcap)
capout=$(mktemp /tmp/dsn64_XXXXXX.txt)

dd if=/dev/urandom of="$cin" bs=1024 count=64 2>/dev/null

trap cleanup EXIT

mptcp_lib_ns_init ns1 ns2

ip link add ns1eth netns "$ns1" type veth peer name ns2eth netns "$ns2"

ip -net "$ns1" addr add 10.0.1.1/24 dev ns1eth
ip -net "$ns1" addr add dead:beef:1::1/64 dev ns1eth nodad
ip -net "$ns1" link set ns1eth up

ip -net "$ns2" addr add 10.0.1.2/24 dev ns2eth
ip -net "$ns2" addr add dead:beef:1::2/64 dev ns2eth nodad
ip -net "$ns2" link set ns2eth up

# $1: "0" or "1" (dsn64 value), $2: "4" or "6" (address family)
run_test()
{
	local dsn64_val="$1"
	local af="$2"
	local connect_addr
	local mptcp_opt=""
	local label

	if [ "$dsn64_val" = "0" ]; then
		label="32-bit DSN (dsn64=0)"
	else
		label="64-bit DSN (dsn64=1)"
	fi

	if [ "$af" = "6" ]; then
		connect_addr="dead:beef:1::2"
		mptcp_opt="-6"
		label="$label IPv6"
	else
		connect_addr="10.0.1.2"
		label="$label IPv4"
	fi

	mptcp_lib_print_info "Testing $label"

	ip netns exec "$ns1" sysctl -q net.mptcp.dsn64="$dsn64_val"
	ip netns exec "$ns2" sysctl -q net.mptcp.dsn64="$dsn64_val"

	# flush old capture
	:>"$capfile"

	# -Z root: prevent privilege drop in containers; -B 128: small ring buffer
	ip netns exec "$ns1" tcpdump -i any -s 256 -B 128 \
		-n -Z root -w "$capfile" -c 50 tcp \
		>> "$capout" 2>&1 &
	local tcpdump_pid=$!

	sleep 1

	ip netns exec "$ns2" ./mptcp_connect $mptcp_opt -s MPTCP -l -p 12345 \
		"$connect_addr" < "$sin" > /dev/null &
	local server_pid=$!

	mptcp_lib_wait_local_port_listen "$ns2" 12345

	ip netns exec "$ns1" ./mptcp_connect $mptcp_opt -s MPTCP -p 12345 \
		"$connect_addr" < "$cin" > /dev/null 2>&1
	local client_ret=$?

	wait "$server_pid" 2>/dev/null

	# sleep before SIGINT so tcpdump drains ring buffer to pcap
	sleep 2
	kill -SIGINT "$tcpdump_pid" 2>/dev/null
	wait "$tcpdump_pid" 2>/dev/null

	if [ "$client_ret" -ne 0 ]; then
		mptcp_lib_pr_fail "$label: mptcp_connect failed (rc=$client_ret)"
		mptcp_lib_result_fail "$label: connection"
		ret=1
		return
	fi

	local pkt_count
	pkt_count=$(tcpdump -r "$capfile" -n 2>/dev/null | wc -l)
	echo "DEBUG ($label): $pkt_count packets in pcap, size=$(stat -c%s "$capfile" 2>/dev/null)"

	# DSS: kind=0x1e, len=0x12(32-bit,18B)=1e122 or len=0x1a(64-bit,26B)=1e1a2
	local dss32_count dss64_count hexdump
	hexdump=$(tcpdump -r "$capfile" -n -xx 2>/dev/null | tr -d ' \n\t')
	dss32_count=$(echo "$hexdump" | grep -o -i "1e122" | wc -l)
	dss64_count=$(echo "$hexdump" | grep -o -i "1e1a2" | wc -l)

	local mptcp_opt_count
	mptcp_opt_count=$(echo "$hexdump" | grep -o -i "1e" | wc -l)
	echo "DEBUG ($label): dss32=$dss32_count dss64=$dss64_count mptcp_opts=$mptcp_opt_count"

	if [ "$dsn64_val" = "1" ]; then
		if [ "$dss64_count" -gt 0 ] && [ "$dss32_count" -eq 0 ]; then
			mptcp_lib_pr_ok "$label: $dss64_count packets with 64-bit DSS"
			mptcp_lib_result_pass "$label"
		else
			mptcp_lib_pr_fail "$label: expected 64-bit DSS, got dss64=$dss64_count dss32=$dss32_count"
			mptcp_lib_result_fail "$label"
			ret=1
		fi
	else
		if [ "$dss32_count" -gt 0 ] && [ "$dss64_count" -eq 0 ]; then
			mptcp_lib_pr_ok "$label: $dss32_count packets with 32-bit DSS"
			mptcp_lib_result_pass "$label"
		else
			mptcp_lib_pr_fail "$label: expected 32-bit DSS, got dss32=$dss32_count dss64=$dss64_count"
			mptcp_lib_result_fail "$label"
			ret=1
		fi
	fi
}

# Test 64-bit then 32-bit, for both IPv4 and IPv6
run_test 1 4
run_test 0 4
run_test 1 6
run_test 0 6

mptcp_lib_result_print_all_tap
exit $ret
