#!/bin/bash

trtype="${1:-mptcp}"
port=10
ns=1
nqn=nqn.test

cleanup()
{
        rm -rf /sys/kernel/config/nvmet/ports/${port}/subsystems/${nqn}
        rmdir /sys/kernel/config/nvmet/ports/${port}
        echo 0 > /sys/kernel/config/nvmet/subsystems/${nqn}/namespaces/${ns}/enable
        echo -n 0 > /sys/kernel/config/nvmet/subsystems/${nqn}/namespaces/${ns}/device_path
        rmdir /sys/kernel/config/nvmet/subsystems/${nqn}/namespaces/${ns}
        rmdir /sys/kernel/config/nvmet/subsystems/${nqn}
        losetup -d /dev/loop100
        rm -rf /tmp/test.raw

	KEYRING_ID=$(sudo keyctl search @s keyring "_ses")
	keyctl clear $KEYRING_ID
	keyctl show @s
}

dd if=/dev/zero of=/tmp/test.raw bs=1M count=0 seek=512
losetup /dev/loop100 /tmp/test.raw
mkdir /sys/kernel/config/nvmet/ports/10
echo -n "127.0.0.1" > /sys/kernel/config/nvmet/ports/10/addr_traddr
echo -n ipv4 > /sys/kernel/config/nvmet/ports/10/addr_adrfam
echo -n ${trtype} > /sys/kernel/config/nvmet/ports/10/addr_trtype
echo -n 4420 > /sys/kernel/config/nvmet/ports/10/addr_trsvcid
echo -n "tls1.3" > /sys/kernel/config/nvmet/ports/10/addr_tsas
mkdir /sys/kernel/config/nvmet/subsystems/nqn.test
echo 1 > /sys/kernel/config/nvmet/subsystems/nqn.test/attr_allow_any_host
mkdir /sys/kernel/config/nvmet/subsystems/nqn.test/namespaces/1
echo "/dev/loop100" > /sys/kernel/config/nvmet/subsystems/nqn.test/namespaces/1/device_path
echo 1 > /sys/kernel/config/nvmet/subsystems/nqn.test/namespaces/1/enable
ln -s /sys/kernel/config/nvmet/subsystems/nqn.test /sys/kernel/config/nvmet/ports/10/subsystems/

key1=$(nvme gen-tls-key --subsysnqn=nqn.test)
key2=$(nvme gen-tls-key --subsysnqn=nqn.2014-08.org.nvmexpress.discovery)

nvme check-tls-key --subsysnqn=nqn.test -i -d ${key1}
nvme check-tls-key --subsysnqn=nqn.2014-08.org.nvmexpress.discovery -i -d ${key2}

#systemctl start tlshd.service
keyctl show

nvme discover -t ${trtype} -a 127.0.0.1 -s 4420 --tls
devname=$(nvme connect -t ${trtype} -a 127.0.0.1 -s 4420 -n nqn.test --tls | awk '{print $4}')

echo "fio randread"
fio --name=global --direct=1 --norandommap --randrepeat=0 --ioengine=libaio \
    --thread=1 --blocksize=4k --runtime=10 --time_based --rw=randread --numjobs=4 \
    --iodepth=256 --group_reporting --size=100% --name=libaio_4_256_4k_randread \
    --filename=/dev/${devname}n1

nvme disconnect -n nqn.test
cleanup
