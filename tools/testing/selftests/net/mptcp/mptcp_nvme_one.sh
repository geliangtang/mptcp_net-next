#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

. "$(dirname "$0")/mptcp_lib.sh"

ret=0
trtype="${1:-mptcp}"
iopolicy=${2:-"numa"} # round-robin, queue-depth
tls=${3:-""}
nqn="nqn.2014-08.org.nvmexpress.${trtype}dev.$$.${RANDOM}"
ns=1
port=$((RANDOM % 10000 + 20000))
trsvcid=$((RANDOM % 64512 + 1024))
ns1=""
ns2=""
temp_file=$(mktemp /tmp/test.XXXXXX.raw)
loop_dev=""

ns1_cleanup()
{
	mount -t configfs none /sys/kernel/config

	pushd /sys/kernel/config/nvmet || exit 1
	rm -rf ports/"${port}"/subsystems/"${trtype}"subsys
	rmdir ports/"${port}"
	echo 0 > subsystems/"${nqn}"/namespaces/"${ns}"/enable
	echo -n 0 > subsystems/"${nqn}"/namespaces/"${ns}"/device_path
	rmdir subsystems/"${nqn}"/namespaces/"${ns}"
	rmdir subsystems/"${nqn}"
	popd || exit 1
}

ns2_cleanup()
{
	nvme disconnect -n "${nqn}" || true

	sleep 1
}

check_error()
{
	ss -N "$ns1" -Mtia > ns1_"${1}".log
	ss -N "$ns2" -Mtia > ns2_"${1}".log
	#if dmesg | grep -E -q "starting error recovery|Buffer I/O error|fatal error occurred|failed nvme_keep_alive_end_io"; then
	if dmesg | grep -E -q "starting error recovery|Buffer I/O error|fatal error occurred"; then
		echo "Test error at ${1}"
		ret="${KSFT_FAIL}"
	fi
	rm -rf ns1_"${1}".log ns2_"${1}".log
	echo "${1} done"
}

# This function is used in the cleanup trap
#shellcheck disable=SC2317,SC2329
cleanup()
{
	ip netns exec "$ns2" bash <<- EOF
		$(declare -f ns2_cleanup)
		ns2_cleanup
	EOF

	sleep 1

	ip netns exec "$ns1" bash <<- EOF
		$(declare -f ns1_cleanup)
		ns1_cleanup
	EOF

	sleep 1

	if [ -n "${loop_dev}" ] && [ -b "${loop_dev}" ]; then
		losetup -d "${loop_dev}" 2>/dev/null || true
	fi
	rm -rf "${temp_file}"

	#check_error "cleanup"

	mptcp_lib_ns_exit "$ns1" "$ns2"

	#kill "$monitor_pid_ns1" 2>/dev/null
	#wait "$monitor_pid_ns1" 2>/dev/null

	#kill "$monitor_pid_ns2" 2>/dev/null
	#wait "$monitor_pid_ns2" 2>/dev/null

	if [ -n "$tls" ]; then
		kill "$tlshd_pid_ns1" 2>/dev/null
		wait "$tlshd_pid_ns1" 2>/dev/null

		kill "$tlshd_pid_ns2" 2>/dev/null
		wait "$tlshd_pid_ns2" 2>/dev/null

		for keyid in $(keyctl list %:.nvme 2>/dev/null |
			       grep "psk:.*$nqn" |
			       awk -F: '{print $1}' |
			       tr -d ' '); do
			keyctl unlink "$keyid" %:.nvme 2>/dev/null &&
			echo "remove key $keyid for $nqn"
		done
		for keyid in $(keyctl list %:.nvme 2>/dev/null |
			       grep "psk:.*discovery" |
			       awk -F: '{print $1}' |
			       tr -d ' '); do
			keyctl unlink "$keyid" %:.nvme 2>/dev/null &&
			echo "remove key $keyid for discovery"
		done
	fi

	unset -v trtype nqn ns port trsvcid
	unset iopolicy tls
}

init()
{
	dmesg -C

	mptcp_lib_ns_init ns1 ns2

	# ns1		ns2
	# 10.1.1.1	10.1.1.2
	# 10.1.2.1	10.1.2.2
	# 10.1.3.1	10.1.3.2
	# 10.1.4.1	10.1.4.2
	for i in {1..4}; do
		ip link add ns1eth"$i" netns "$ns1" type veth peer \
					name ns2eth"$i" netns "$ns2"
		ip -net "$ns1" addr add 10.1."$i".1/24 dev ns1eth"$i"
		ip -net "$ns1" addr add dead:beef:"$i"::1/64 \
					dev ns1eth"$i" nodad
		ip -net "$ns1" link set ns1eth"$i" up
		ip -net "$ns2" addr add 10.1."$i".2/24 dev ns2eth"$i"
		ip -net "$ns2" addr add dead:beef:"$i"::2/64 \
					dev ns2eth"$i" nodad
		ip -net "$ns2" link set ns2eth"$i" up
		ip -net "$ns2" route add default via 10.1."$i".1 \
					dev ns2eth"$i" metric 10"$i"
		ip -net "$ns2" route add default via dead:beef:"$i"::1 \
					dev ns2eth"$i" metric 10"$i"

		# Add tc qdisc to both namespaces for bandwidth limiting
		tc -n "$ns1" qdisc add dev ns1eth"$i" root netem rate 1000mbit
		tc -n "$ns2" qdisc add dev ns2eth"$i" root netem rate 1000mbit
	done

	mptcp_lib_pm_nl_set_limits "${ns1}" 8 8

	mptcp_lib_pm_nl_add_endpoint "$ns1" 10.1.2.1 flags signal
	mptcp_lib_pm_nl_add_endpoint "$ns1" 10.1.3.1 flags signal
	mptcp_lib_pm_nl_add_endpoint "$ns1" 10.1.4.1 flags signal

	mptcp_lib_pm_nl_set_limits "${ns2}" 8 8

	mptcp_lib_pm_nl_add_endpoint "$ns2" 10.1.2.2 flags subflow
	mptcp_lib_pm_nl_add_endpoint "$ns2" 10.1.3.2 flags subflow
	mptcp_lib_pm_nl_add_endpoint "$ns2" 10.1.4.2 flags subflow

	#ip -n "${ns1}" mptcp monitor &
	#monitor_pid_ns1=$!
	#ip -n "${ns2}" mptcp monitor &
	#monitor_pid_ns2=$!

	if [ -n "$tls" ]; then
		local key=$(nvme gen-tls-key)

		keyctl clear @s
		nvme check-tls-key --subsysnqn=${nqn} -i -d ${key}
		nvme check-tls-key --subsysnqn=nqn.2014-08.org.nvmexpress.discovery -i -d ${key}
		keyctl list %:.nvme
		keyctl show

		ip netns exec "$ns1" /usr/sbin/tlshd & #-c ./tlshd.conf -s &
		tlshd_pid_ns1=$!
		ip netns exec "$ns2" /usr/sbin/tlshd & #-c ./tlshd.conf -s &
		tlshd_pid_ns2=$!
	fi
}

run_target()
{
	mount -t configfs none /sys/kernel/config

	cd /sys/kernel/config/nvmet/subsystems || exit
	mkdir -p "${nqn}"
	cd "${nqn}" || exit
	echo 1 > attr_allow_any_host
	mkdir -p namespaces/"${ns}"
	echo "${loop_dev}" > namespaces/"${ns}"/device_path
	echo 1 > namespaces/"${ns}"/enable

	cd /sys/kernel/config/nvmet/ports || exit
	mkdir -p "${port}"
	cd "${port}" || exit
	echo "${trtype}" > addr_trtype
	echo ipv4 > addr_adrfam
	echo 0.0.0.0 > addr_traddr
	echo "${trsvcid}" > addr_trsvcid

	if [ -n "$tls" ]; then
		echo "tls1.3" > addr_tsas
	fi

	cd subsystems || exit
	ln -sf ../../../subsystems/"${nqn}" "${trtype}"subsys
}

run_host()
{
	local traddr=10.1.1.1
	local output
	local devname
	local subname
	local extra=""

	if [ -n "$tls" ]; then
		extra="--tls"
	fi

	echo "nvme discover -a ${traddr} ${extra}"
	nvme discover -t "${trtype}" -a "${traddr}" -s "${trsvcid}" "${extra}"
	if [ $? -ne 0 ]; then
		return 1
	fi

	echo "nvme connect ${extra}"
	output=$(nvme connect -t "${trtype}" -a "${traddr}" \
			      -s "${trsvcid}" -n "${nqn}" \
			      "${extra}" 2>&1)
	if [ $? -ne 0 ]; then
		echo "nvme connect failed: $output" >&2
		return 1
	fi

	devname=$(echo "$output" | awk '{print $NF}')
	if [ -z "$devname" ]; then
		echo "Failed to parse device name from output: $output" >&2
		return 1
	fi

	sleep 1

	echo "nvme list"
	nvme list

	subname=$(nvme list-subsys /dev/"${devname}"n1 |
		  grep -o 'nvme-subsys[0-9]*' | head -1)

	echo "${iopolicy}" > /sys/class/nvme-subsystem/"${subname}"/iopolicy
	cat /sys/class/nvme-subsystem/"${subname}"/iopolicy

	sleep 1

	echo "fio randread /dev/${devname}n1"
	fio --name=global --direct=1 --norandommap --randrepeat=0 \
	    --ioengine=libaio --thread=1 --blocksize=128k --runtime=10 \
	    --time_based --rw=randread --numjobs=4 --iodepth=256 \
	    --group_reporting --size=100% --name=libaio_4_256_4k_randread \
	    --filename=/dev/"${devname}"n1
	if [ $? -ne 0 ]; then
		return 1
	fi

	nvme flush /dev/"${devname}"n1

	sleep 1

	echo "fio randwrite /dev/${devname}n1"
	fio --name=global --direct=1 --norandommap --randrepeat=0 \
	    --ioengine=libaio --thread=1 --blocksize=128k --runtime=10 \
	    --time_based --rw=randwrite --numjobs=4 --iodepth=256 \
	    --group_reporting --size=100% --name=libaio_4_256_4k_randwrite \
	    --filename=/dev/"${devname}"n1
	if [ $? -ne 0 ]; then
		return 1
	fi

	nvme flush /dev/"${devname}"n1
}

mptcp_lib_check_tools nvme fio

init
trap cleanup EXIT

dd if=/dev/zero of="${temp_file}" bs=1M count=0 seek=512
loop_dev=$(losetup -f --show "${temp_file}")

run_test()
{
	export trtype nqn ns port trsvcid
	export loop_dev temp_file
	export iopolicy tls

	if ! ip netns exec "$ns1" bash <<- EOF
		$(declare -f run_target)
		run_target
		exit \$?
	EOF
	then
		ret="${KSFT_FAIL}"
	fi

	sleep 1

	if ! ip netns exec "$ns2" bash <<- EOF
		$(declare -f run_host)
		run_host
		exit \$?
	EOF
	then
		ret="${KSFT_FAIL}"
	fi

	sleep 1
}

run_test "$@"
check_error "run_test"

mptcp_lib_result_print_all_tap
exit "$ret"
