#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

. "$(dirname "${0}")/mptcp_lib.sh"

ret=0
pid=""

# This function is used in the cleanup trap
#shellcheck disable=SC2317,SC2329
cleanup()
{
	if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
	fi
}

mptcp_lib_check_mptcp

trap cleanup EXIT

run_test()
{
	local name="$1"
	local rc

	mptcp_lib_print_info "run $name"

	"./$name"
	rc=$?
	mptcp_lib_result_code "$rc" "$name"
	if [ "$rc" -ne 0 ] && [ "$rc" -ne "${KSFT_SKIP}" ]; then
		ret=${KSFT_FAIL}
	fi
}

for name in restore_ipv4 restore_ipv6 \
	    restore_mptcp_ipv4 restore_mptcp_ipv6; do
	run_test "$name"
done

mptcp_lib_result_print_all_tap
exit $ret
