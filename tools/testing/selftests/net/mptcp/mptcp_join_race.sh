#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# Reproducer for the MPTCP join_list vs close() race:
#
# A passive MP_JOIN subflow completing its 3WHS while the msk
# socket lock is held by the closing thread is parked in
# msk->join_list. msk destruction only walks conn_list, the
# parked subflow is flushed too late (at release_sock() time)
# onto a dying msk and its msk reference is never released:
# struct sock + mptcp_subflow_context leak (and the PM
# extra_subflows accounting for it is lost).
#
# The race is driven statistically: the server closes each
# connection after a random microsecond delay (phase scan across
# the MP_JOIN 3rd ACK arrival time), for ITERATIONS rounds.
#
# Not wired into the default CI run (TEST_PROGS): it is a
# probabilistic stress reproducer, run it manually:
#
#   make -C tools/testing/selftests/net/mptcp genall
#   ./mptcp_join_race.sh
#
# Knobs (environment):
#   ITERATIONS=20000   number of race rounds
#   MAX_DELAY_US=3000  server close delay scan range in us
#   PAYLOAD=2048       unread data left on the server side
#   PORT=50010
#   SRV_LIMITS="0 1"   server pm_nl_ctl limits (rcv_addrs subflows)
#   CLI_LIMITS="0 1"   client pm_nl_ctl limits
#                       ('x 0' on the server would reject the
#                        passive MP_JOIN: no park, no race)
#
# Leak detection, in order of reliability:
#   1. kmemleak (needs CONFIG_DEBUG_KMEMLEAK): scanned at the
#      end if /sys/kernel/debug/kmemleak is accessible
#   2. TCP slab objects growth (/sys/kernel/slab/TCPv4/objects),
#      global counter: meaningful on an otherwise quiet machine
#   3. MPTcpExtJoin* MIB counters, ns1 = server side

. "$(dirname "${0}")/mptcp_lib.sh"

mptcp_lib_check_mptcp
mptcp_lib_check_tools ip

ITERATIONS=${ITERATIONS:-100000}
MAX_DELAY_US=${MAX_DELAY_US:-3000}
PAYLOAD=${PAYLOAD:-2048}
PORT=${PORT:-50010}
SRV_LIMITS=${SRV_LIMITS:-"8 8"}
CLI_LIMITS=${CLI_LIMITS:-"0 1"}

ns1=""
ns2=""
ret=0

cleanup()
{
	mptcp_lib_ns_exit "${ns1}" "${ns2}"
}
trap cleanup EXIT

setup()
{
	mptcp_lib_ns_init ns1 ns2

	# ns1: server; ns2: client with a secondary source address
	# used by the extra MP_JOIN subflow created by the in-kernel
	# path manager. The secondary subnet must exist on both sides:
	# the MP_JOIN keeps the original destination (10.0.1.1) but
	# uses 10.0.2.2 as source, and the server needs a route to it
	# or the SYN is dropped by rp_filter and the SYN/ACK is
	# unroutable
	ip link add ns1eth1 netns "$ns1" type veth peer name ns2eth1 netns "$ns2"
	ip -net "$ns1" addr add 10.0.1.1/24 dev ns1eth1
	ip -net "$ns1" addr add 10.0.2.1/24 dev ns1eth1
	ip -net "$ns1" link set ns1eth1 up
	ip -net "$ns2" addr add 10.0.1.2/24 dev ns2eth1
	ip -net "$ns2" addr add 10.0.2.2/24 dev ns2eth1
	ip -net "$ns2" link set ns2eth1 up
	ip -net "$ns2" route add default via 10.0.1.1 dev ns2eth1 metric 1001

	# server: the subflows limit is only an admission gate for the
	# passive MP_JOIN (>= 1 required), see mptcp_pm_kernel_init()
	mptcp_lib_pm_nl_set_limits "${ns1}" ${SRV_LIMITS}
	# client: exactly one extra subflow per msk
	mptcp_lib_pm_nl_set_limits "${ns2}" ${CLI_LIMITS}
	mptcp_lib_pm_nl_add_endpoint "${ns2}" 10.0.2.2 flags subflow
}

tcp_slab_objects()
{
	local objects

	# the per-cache sysfs attributes need CONFIG_SLUB_DEBUG,
	# /proc/slabinfo is root-only
	if [ -r /sys/kernel/slab/TCPv4/objects ]; then
		read -r objects < /sys/kernel/slab/TCPv4/objects
		echo "${objects%% *}"
	elif [ -r /proc/slabinfo ]; then
		awk '/^TCPv4 /{print $2}' /proc/slabinfo
	else
		echo ""
	fi
}

report()
{
	local slab_before="$1"
	local slab_after delta

	echo "--- server (${ns1}) MPTCP MIB"
	ip netns exec "${ns1}" nstat -az 2>/dev/null | grep -E 'MPTcp.*Join' || true
	echo "--- client (${ns2}) MPTCP MIB"
	ip netns exec "${ns2}" nstat -az 2>/dev/null | grep -E 'MPTcp.*Join' || true

	sleep 5	# let the RST/timer driven cleanup settle

	slab_after=$(tcp_slab_objects)
	if [ -n "${slab_before}" ] && [ -n "${slab_after}" ]; then
		delta=$((slab_after - slab_before))
		echo "--- TCP slab objects: ${slab_before} -> ${slab_after} (delta ${delta})"
		if [ "${delta}" -gt "$((ITERATIONS / 100))" ]; then
			echo "SUSPECT: TCP slab grew by ${delta} objects, possible sock leak"
		fi
	else
		echo "--- TCP slab counters not available"
	fi

	if [ -w /sys/kernel/debug/kmemleak ]; then
		echo scan > /sys/kernel/debug/kmemleak
		sleep 2
		echo "--- kmemleak"
		if grep -q 'mptcp' /sys/kernel/debug/kmemleak; then
			echo "LEAK: mptcp objects reported by kmemleak:"
			grep -B1 -A12 'mptcp' /sys/kernel/debug/kmemleak | head -100
			ret=1
		else
			echo "no mptcp leaks reported"
		fi
	else
		echo "--- kmemleak not available (CONFIG_DEBUG_KMEMLEAK?)"
	fi

	if dmesg &>/dev/null; then
		echo "--- recent mptcp warnings in dmesg"
		dmesg | grep -E 'WARNING.*(mptcp|protocol\.h:1267)' | tail -20 || true
	fi
}

main()
{
	local slab_before spid sret cret

	setup

	slab_before=$(tcp_slab_objects)

	ip netns exec "${ns1}" ./mptcp_join_race -l -p "${PORT}" \
		-n "${ITERATIONS}" -d "${MAX_DELAY_US}" &
	spid=$!

	mptcp_lib_wait_local_port_listen "${ns1}" "${PORT}"

	ip netns exec "${ns2}" ./mptcp_join_race -p "${PORT}" \
		-n "${ITERATIONS}" -s "${PAYLOAD}" 10.0.1.1
	cret=$?

	wait "${spid}"
	sret=$?

	echo "--- program exit codes: client ${cret}, server ${sret}"
	[ "${cret}" -ne 0 ] || [ "${sret}" -ne 0 ] && ret=1

	report "${slab_before}"

	return "${ret}"
}

main "${@}"
