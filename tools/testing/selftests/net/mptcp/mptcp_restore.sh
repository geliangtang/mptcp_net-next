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

# Parse arguments: -t or --trace to enable ftrace
do_ftrace=0
for arg in "$@"; do
	case "$arg" in
	-t|--trace) do_ftrace=1 ;;
	esac
done

TRACEFS=""
ftrace_setup()
{
	[ "$do_ftrace" -eq 1 ] || return 0
	for d in /sys/kernel/tracing /sys/kernel/debug/tracing; do
		if [ -d "$d/events" ]; then
			TRACEFS="$d"
			break
		fi
	done
	[ -n "$TRACEFS" ] || return 0

	# Enable the new tracepoint with counter
	echo 1 > "$TRACEFS/events/tcp/tcp_ao_good_with_counter/enable" 2>/dev/null || return 0
	echo 0 > "$TRACEFS/trace"
	echo 1 > "$TRACEFS/tracing_on"
}

ftrace_teardown()
{
	[ "$do_ftrace" -eq 1 ] || return 0
	[ -n "$TRACEFS" ] || return 0
	echo 0 > "$TRACEFS/tracing_on"
	echo 0 > "$TRACEFS/events/tcp/tcp_ao_good_with_counter/enable"
	echo "# === ftrace log ==="
	cat "$TRACEFS/trace" 2>/dev/null | while IFS= read -r line; do
		echo "# $line"
	done
	echo "# === end ftrace log ==="
	echo '-:ao_good' > "$TRACEFS/kprobe_events" 2>/dev/null
}

trap cleanup EXIT

run_test()
{
	local name="$1"

	mptcp_lib_print_info "run $name"

	ip netns exec "$ns1" "./$name" &
	pid=$!
	wait $pid
	if [ $? -ne 0 ]; then
		mptcp_lib_pr_fail "$name failed"
		mptcp_lib_result_fail "$name"
		ret=${KSFT_FAIL}
	fi
}

init
ip -n "${ns1}" mptcp limits
mptcp_lib_pm_nl_show_endpoints "$ns1"

# TCP tests
for name in restore_ipv4 restore_ipv6; do
	run_test "$name"
done

# MPTCP tests with ftrace
ftrace_setup
for name in restore_mptcp_ipv4 restore_mptcp_ipv6; do
	run_test "$name"
done
ftrace_teardown

mptcp_lib_result_print_all_tap
exit $ret
