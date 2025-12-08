#!/bin/python3

import ctypes
import socket

from bcc import lib, BPF

b = BPF(
  text="""\
struct sock_key {
  u64 cookie;
};

BPF_SOCKHASH(my_hash, struct sock_key, 65535);
"""
)

map_fd = lib.bpf_table_fd(b.module, b"my_hash")

# Fairly arbitrary for this example.
class sock_key(ctypes.Structure):
  _fields_ = [("cookie", ctypes.c_uint64)]

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_MPTCP)

sock.bind(('127.0.0.0',7890))
sock.listen(20)

# Returns -95, in part due to the missing psock_update_sk_prot implementation.
res=lib.bpf_update_elem(map_fd, ctypes.byref(sock_key(0)), ctypes.byref(ctypes.c_int(sock.fileno())), 0)
print(res)
