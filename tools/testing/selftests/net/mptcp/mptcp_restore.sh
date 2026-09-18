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
	local rc

	mptcp_lib_print_info "run $name"

	"./$name"
	rc=$?
	mptcp_lib_result_code "$rc" "$name"
	if [ "$rc" -ne 0 ] && [ "$rc" -ne "${KSFT_SKIP}" ]; then
		ret=${KSFT_FAIL}
	fi
}

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
