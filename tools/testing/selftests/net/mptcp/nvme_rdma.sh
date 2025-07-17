#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

#modprobe nvme_core nvme-fabrics nvme_tcp
#modprobe nvmet nvmet_tcp

rdma link add rxe_0 type rxe netdev eth0
ls /dev/infiniband/
ibv_devinfo

./mptcp_nvme.sh rdma 10.0.2.15

rdma link del rxe_0
