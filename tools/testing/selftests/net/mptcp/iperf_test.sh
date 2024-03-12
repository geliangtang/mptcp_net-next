#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# shellcheck disable=SC2086

. "$(dirname "${0}")/mptcp_lib.sh"

init=0
declare -A failed_tests
MPTCP_LIB_TEST_FORMAT="%02u %s\n"
TEST_NAME=""
ns1=""
ns2=""
last_test_failed=0
last_test_skipped=0
last_test_ignored=1

cleanup()
{
	cleanup_all_ns
}

init()
{
	init=1

	mptcp_lib_check_mptcp
	mptcp_lib_check_tools ip tc iperf

	trap cleanup EXIT
}

init_partial()
{
	mptcp_lib_ns_init ns1 ns2

	local netns
	for netns in "$ns1" "$ns2"; do
		ip netns exec $netns sysctl -q net.mptcp.pm_type=0 2>/dev/null || true
	done

	#  ns1         ns2
	# ns1eth1    ns2eth1
	# ns1eth2    ns2eth2
	# ns1eth3    ns2eth3
	# ns1eth4    ns2eth4

	local i
	for i in $(seq 1 4); do
		ip link add ns1eth$i netns "$ns1" type veth peer name ns2eth$i netns "$ns2"
		ip -net "$ns1" addr add 10.0.$i.1/24 dev ns1eth$i
		ip -net "$ns1" addr add dead:beef:$i::1/64 dev ns1eth$i nodad
		ip -net "$ns1" link set ns1eth$i up

		ip -net "$ns2" addr add 10.0.$i.2/24 dev ns2eth$i
		ip -net "$ns2" addr add dead:beef:$i::2/64 dev ns2eth$i nodad
		ip -net "$ns2" link set ns2eth$i up

		# let $ns2 reach any $ns1 address from any interface
		ip -net "$ns2" route add default via 10.0.$i.1 dev ns2eth$i metric 10$i
		ip -net "$ns2" route add default via dead:beef:$i::1 dev ns2eth$i metric 10$i
	done
}

append_prev_results()
{
	if [ ${last_test_failed} -eq 1 ]; then
		mptcp_lib_result_fail "${TEST_NAME}"
	elif [ ${last_test_skipped} -eq 1 ]; then
		mptcp_lib_result_skip "${TEST_NAME}"
	elif [ ${last_test_ignored} -ne 1 ]; then
		mptcp_lib_result_pass "${TEST_NAME}"
	fi

	last_test_failed=0
	last_test_skipped=0
	last_test_ignored=0
}

# $1: test name
reset()
{
	append_prev_results
	TEST_NAME="${1}"

	mptcp_lib_print_title "${TEST_NAME}"

	if [ "${init}" != "1" ]; then
		init
	else
		cleanup
	fi

	init_partial

	return 0
}

print_check()
{
	printf "%-50s" "${*}"
}

dump_stats()
{
	echo Server ns stats
	ip netns exec $ns1 nstat -as | grep Tcp
	echo Client ns stats
	ip netns exec $ns2 nstat -as | grep Tcp
}

# $1: err msg
fail_test()
{
	ret=${KSFT_FAIL}

	mptcp_lib_pr_fail "${@}"

	# just in case a test is marked twice as failed
	if [ ${last_test_failed} -eq 0 ]; then
		# shellcheck disable=SC2034
		failed_tests[${MPTCP_LIB_TEST_COUNTER}]="${TEST_NAME}"
		dump_stats
		last_test_failed=1
	fi
}

chk_join_nr()
{
	local syn_nr=$1
	local syn_ack_nr=$2
	local ack_nr=$3
	local count

	print_check "syn"
	count=$(mptcp_lib_get_counter ${ns1} "MPTcpExtMPJoinSynRx")
	if [ -z "$count" ]; then
		mptcp_lib_pr_skip
	elif [ "$count" != "$syn_nr" ]; then
		fail_test "got $count JOIN[s] syn expected $syn_nr"
	else
		mptcp_lib_pr_ok
	fi

	print_check "synack"
	count=$(mptcp_lib_get_counter ${ns2} "MPTcpExtMPJoinSynAckRx")
	if [ -z "$count" ]; then
		mptcp_lib_pr_skip
	elif [ "$count" != "$syn_ack_nr" ]; then
		fail_test "got $count JOIN[s] synack expected $syn_ack_nr"
	else
		mptcp_lib_pr_ok
	fi

	print_check "ack"
	count=$(mptcp_lib_get_counter ${ns1} "MPTcpExtMPJoinAckRx")
	if [ -z "$count" ]; then
		mptcp_lib_pr_skip
	elif [ "$count" != "$ack_nr" ]; then
		fail_test "got $count JOIN[s] ack expected $ack_nr"
	else
		mptcp_lib_pr_ok
	fi
}

iperf_tests()
{
	if reset "iperf tcp test, rate 100mbit"; then
		tc -n $ns2 qdisc add dev ns2eth1 root netem rate 100mbit
		tc -n $ns2 qdisc add dev ns2eth2 root netem rate 100mbit
		tc -n $ns2 qdisc add dev ns2eth3 root netem rate 100mbit
		tc -n $ns2 qdisc add dev ns2eth4 root netem rate 100mbit
		ip netns exec $ns1 iperf3 -s &
		local tests_pid=$!
		sleep 1
		ip netns exec $ns2 iperf3 -c 10.0.1.1
		mptcp_lib_kill_wait $tests_pid
		chk_join_nr 0 0 0
	fi

	if reset "iperf mptcp test, rate 100mbit"; then
		tc -n $ns2 qdisc add dev ns2eth1 root netem rate 100mbit
		tc -n $ns2 qdisc add dev ns2eth2 root netem rate 100mbit
		tc -n $ns2 qdisc add dev ns2eth3 root netem rate 100mbit
		tc -n $ns2 qdisc add dev ns2eth4 root netem rate 100mbit
		mptcp_lib_pm_nl_set_limits $ns1 8 8
		mptcp_lib_pm_nl_set_limits $ns2 8 8
		mptcp_lib_pm_nl_add_endpoint $ns2 10.0.2.2 dev ns2eth2 flags subflow
		mptcp_lib_pm_nl_add_endpoint $ns2 10.0.3.2 dev ns2eth3 flags subflow
		mptcp_lib_pm_nl_add_endpoint $ns2 10.0.4.2 dev ns2eth4 flags subflow
		ip netns exec $ns1 iperf3 -m -s &
		local tests_pid=$!
		sleep 1
		ip netns exec $ns2 iperf3 -m -c 10.0.1.1
		mptcp_lib_kill_wait $tests_pid
		chk_join_nr 3 3 3
	fi

	if reset "iperf tcp test, delay 1ms"; then
		tc -n $ns2 qdisc add dev ns2eth1 root netem rate 1mbit delay 1ms
		ip netns exec $ns1 iperf3 -s &
		local tests_pid=$!
		sleep 1
		ip netns exec $ns2 iperf3 -c 10.0.1.1
		mptcp_lib_kill_wait $tests_pid
		chk_join_nr 0 0 0
	fi

	if reset "iperf mptcp test, delay 1ms"; then
		tc -n $ns2 qdisc add dev ns2eth1 root netem rate 1mbit delay 1ms
		mptcp_lib_pm_nl_set_limits $ns1 8 8
		mptcp_lib_pm_nl_set_limits $ns2 8 8
		mptcp_lib_pm_nl_add_endpoint $ns2 10.0.2.2 dev ns2eth2 flags subflow
		mptcp_lib_pm_nl_add_endpoint $ns2 10.0.3.2 dev ns2eth3 flags subflow
		ip netns exec $ns1 iperf3 -m -s &
		local tests_pid=$!
		sleep 1
		ip netns exec $ns2 iperf3 -m -c 10.0.1.1
		mptcp_lib_kill_wait $tests_pid
		chk_join_nr 2 2 2
	fi

	if reset "iperf tcp test, loss 1%"; then
		tc -n $ns2 qdisc add dev ns2eth1 root netem rate 1mbit loss 1%
		ip netns exec $ns1 iperf3 -s &
		local tests_pid=$!
		sleep 1
		ip netns exec $ns2 iperf3 -c 10.0.1.1
		mptcp_lib_kill_wait $tests_pid
		chk_join_nr 0 0 0
	fi

	if reset "iperf mptcp test, loss %1"; then
		tc -n $ns2 qdisc add dev ns2eth1 root netem rate 1mbit loss 1%
		mptcp_lib_pm_nl_set_limits $ns1 8 8
		mptcp_lib_pm_nl_set_limits $ns2 8 8
		mptcp_lib_pm_nl_add_endpoint $ns2 10.0.2.2 dev ns2eth2 flags subflow
		mptcp_lib_pm_nl_add_endpoint $ns2 10.0.3.2 dev ns2eth3 flags subflow
		ip netns exec $ns1 iperf3 -m -s &
		local tests_pid=$!
		sleep 1
		ip netns exec $ns2 iperf3 -m -c 10.0.1.1
		mptcp_lib_kill_wait $tests_pid
		chk_join_nr 2 2 2
	fi
}

iperf_tests

append_prev_results
mptcp_lib_result_print_all_tap
exit $ret
