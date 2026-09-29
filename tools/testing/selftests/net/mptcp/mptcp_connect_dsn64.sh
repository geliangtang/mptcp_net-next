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

	# Use tcpdump decoded output to identify DSS MAP by option length.
	# Without checksum (default):
	#   dsn64=0 → "mptcp 18 dss" (ACK32+MAP32, 4+4+4+4+2=18)
	#   dsn64=1 → "mptcp 26 dss" (ACK64+MAP64, 4+8+8+4+2=26)
	#   "mptcp 22 dss" can occur in transition (ACK32+MAP64 before use_64bit_ack is set)
	# Count ACK sizes from decoded DSS output
	count_ack() {
		echo "$1" | grep "$2" | \
			awk -v max32="4294967295" -v want="$3" \
			'{for(i=1;i<=NF;i++) if($i=="ack") {
				v=$(i+1)+0
				if (want=="32" && v<=max32) c++
				if (want=="64" && v>max32) c++
			}} END{print c+0}'
	}

	local decoded dss18 dss22 dss26
	decoded=$(tcpdump -r "$capfile" -n 2>/dev/null)
	dss18=$(echo "$decoded" | grep -c "mptcp 18 dss")
	dss22=$(echo "$decoded" | grep -c "mptcp 22 dss")
	dss26=$(echo "$decoded" | grep -c "mptcp 26 dss")

	local ack32 ack64 out_ack32 out_ack64 in_ack32 in_ack64
	ack32=$(count_ack "$decoded" "dss.*ack" 32)
	ack64=$(count_ack "$decoded" "dss.*ack" 64)
	out_ack32=$(count_ack "$decoded" "Out.*dss.*ack" 32)
	out_ack64=$(count_ack "$decoded" "Out.*dss.*ack" 64)
	in_ack32=$(count_ack "$decoded" "In.*dss.*ack" 32)
	in_ack64=$(count_ack "$decoded" "In.*dss.*ack" 64)
	local ack_info
	ack_info="Out ACK32:$out_ack32 ACK64:$out_ack64"
	ack_info="$ack_info | In ACK32:$in_ack32 ACK64:$in_ack64"
	mptcp_lib_print_info "$label: $ack_info"

	if [ "$dsn64_val" = "1" ]; then
		if [ "$dss26" -gt 0 ] && [ "$dss18" -eq 0 ]; then
			mptcp_lib_pr_ok "$label: $dss26 pkts, 64-bit DSN ($ack_info)"
			mptcp_lib_result_pass "$label"
		else
			mptcp_lib_pr_fail "$label: dss26=$dss26 dss22=$dss22 dss18=$dss18"
			mptcp_lib_result_fail "$label"
			ret=1
		fi
	else
		if [ "$dss18" -gt 0 ] && [ "$dss26" -eq 0 ]; then
			mptcp_lib_pr_ok "$label: $dss18 pkts, 32-bit DSN ($ack_info)"
			mptcp_lib_result_pass "$label"
		else
			mptcp_lib_pr_fail "$label: dss18=$dss18 dss22=$dss22 dss26=$dss26"
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
