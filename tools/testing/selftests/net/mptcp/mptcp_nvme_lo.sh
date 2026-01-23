#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

trtype="${1:-mptcp}"
tls=${2:-""}
traddr="127.0.0.1"
ns=1
port=1234
trsvcid=4420
nqn=nqn.2014-08.org.nvmexpress.${trtype}dev
final_ret=0
extra=""

cleanup()
{
	rm -rf /sys/kernel/config/nvmet/ports/${port}/subsystems/${trtype}subsys
	rmdir /sys/kernel/config/nvmet/ports/${port}
	echo 0 > /sys/kernel/config/nvmet/subsystems/${nqn}/namespaces/${ns}/enable
	echo -n 0 > /sys/kernel/config/nvmet/subsystems/${nqn}/namespaces/${ns}/device_path
	rmdir /sys/kernel/config/nvmet/subsystems/${nqn}/namespaces/${ns}
	rmdir /sys/kernel/config/nvmet/subsystems/${nqn}
	losetup -d /dev/loop100
	rm -rf /tmp/test.raw
	if [ -n "$tls" ]; then
		kill "$tlshd_pid" 2>/dev/null
		wait "$tlshd_pid" 2>/dev/null
	fi
}

check_error()
{
	if dmesg | grep -E -q "starting error recovery|Buffer I/O error"; then
		cleanup
		echo "Test error at ${1}"
		exit 1
	fi
}

dd if=/dev/zero of=/tmp/test.raw bs=1M count=0 seek=512
losetup /dev/loop100 /tmp/test.raw
cd /sys/kernel/config/nvmet/subsystems
mkdir ${nqn}
cd ${nqn}
echo 1 > attr_allow_any_host
cd namespaces
mkdir ${ns}
cd ${ns}
echo /dev/loop100 > device_path
echo 1 > enable
cd /sys/kernel/config/nvmet/ports
mkdir ${port}
cd ${port}
echo ${trtype} > addr_trtype
echo ipv4 > addr_adrfam
echo 0.0.0.0 > addr_traddr
echo ${trsvcid} > addr_trsvcid

if [ -n "$tls" ]; then
	echo "tls1.3" > addr_tsas

	keyctl clear @s
	key=$(nvme gen-tls-key --subsysnqn=${nqn})

	nvme check-tls-key --subsysnqn=${nqn} -i -d ${key}
	nvme check-tls-key --subsysnqn=nqn.2014-08.org.nvmexpress.discovery -i -d ${key}

	/usr/sbin/tlshd &
	tlshd_pid=$!

	keyctl list %:.nvme
	keyctl show

	extra="--tls"
fi

cd subsystems
ln -s ../../../subsystems/${nqn} ${trtype}subsys

echo "nvme discover ${extra}"
nvme discover -t ${trtype} -a ${traddr} -s ${trsvcid} ${extra}

echo "nvme connect ${extra}"
devname=$(nvme connect -t ${trtype} -a ${traddr} -s ${trsvcid} -n ${nqn} ${extra} | awk '{print $NF}')
lret=$?
if [ $lret -ne 0 ]; then
	final_ret=${lret}
fi
check_error "nvme connect"
echo "devname=${devname}"

sleep 1
echo "nvme list"
nvme list
lret=$?
if [ $lret -ne 0 ]; then
	final_ret=${lret}
fi
check_error "nvme list"

echo "fio randread /dev/${devname}n1"
fio --name=global --direct=1 --norandommap --randrepeat=0 --ioengine=libaio \
    --thread=1 --blocksize=4k --runtime=10 --time_based --rw=randread --numjobs=4 \
    --iodepth=256 --group_reporting --size=100% --name=libaio_4_256_4k_randread \
    --size=4m \
    --filename=/dev/${devname}n1
lret=$?
if [ $lret -ne 0 ]; then
	final_ret=${lret}
fi
check_error "fio randread"

echo "fio randwrite /dev/${devname}n1"
fio --name=global --direct=1 --norandommap --randrepeat=0 --ioengine=libaio \
    --thread=1 --blocksize=4k --runtime=10 --time_based --rw=randwrite --numjobs=4 \
    --iodepth=256 --group_reporting --size=100% --name=libaio_4_256_4k_randwrite \
    --size=4m \
    --filename=/dev/${devname}n1
lret=$?
if [ $lret -ne 0 ]; then
	final_ret=${lret}
fi
check_error "fio randwrite"

sleep 1
echo "nvme disconnect"
nvme disconnect -n ${nqn}
lret=$?
if [ $lret -ne 0 ]; then
	final_ret=${lret}
fi
check_error "nvme disconnect"

cleanup
exit ${final_ret}
