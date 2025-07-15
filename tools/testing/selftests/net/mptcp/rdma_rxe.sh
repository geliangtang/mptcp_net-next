#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# modprobe rdma_rxe rdma_cm ib_umad
rdma link add rxe_0 type rxe netdev eth0
ls /dev/infiniband/
ibv_devinfo
ib_write_bw --report_gbits &
sleep 0.1
ib_write_bw 10.0.2.15 --report_gbits
rdma link del rxe_0
