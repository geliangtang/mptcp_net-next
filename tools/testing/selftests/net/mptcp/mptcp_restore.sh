#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

. "$(dirname "${0}")/mptcp_lib.sh"

ret=0
ns1=""
pid=""

# This function is used in the cleanup trap
#shellcheck disable=SC2317,SC2329
cleanup()
{
	if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
	fi

	mptcp_lib_ns_exit "$ns1"
}

init()
{
	local max="${1:-4}"

	mptcp_lib_ns_init ns1

	mptcp_lib_pm_nl_set_limits "$ns1" "$max" "$max"

	local i
	for i in $(seq 1 "$max"); do
		mptcp_lib_pm_nl_add_endpoint "$ns1" \
			"127.0.0.1" flags signal port 1000"$i"
	done
}

mptcp_lib_check_mptcp

trap cleanup EXIT

init
ip -n "${ns1}" mptcp limits
mptcp_lib_pm_nl_show_endpoints "$ns1"

ip netns exec "$ns1" ./restore_mptcp_ipv4 &
pid=$!
wait $pid
if [ $? -ne 0 ]; then
	mptcp_lib_pr_fail "restore_mptcp_ipv4 failed"
	mptcp_lib_result_fail "restore_mptcp_ipv4"
	ret=${KSFT_FAIL}

	mptcp_lib_result_print_all_tap
	exit $ret
fi

ip netns exec "$ns1" ./restore_mptcp_ipv6 &
pid=$!
wait $pid
if [ $? -ne 0 ]; then
	mptcp_lib_pr_fail "restore_mptcp_ipv6 failed"
	mptcp_lib_result_fail "restore_mptcp_ipv6"
	ret=${KSFT_FAIL}
fi

mptcp_lib_result_print_all_tap
exit $ret
