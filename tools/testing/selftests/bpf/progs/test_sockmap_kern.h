/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2017-2018 Covalent IO, Inc. http://covalent.io */
#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_misc.h"

/* Sockmap sample program connects a client and a backend together
 * using cgroups.
 *
 *    client:X <---> frontend:80 client:X <---> backend:80
 *
 * For simplicity we hard code values here and bind 1:1. The hard
 * coded values are part of the setup in sockmap.sh script that
 * is associated with this BPF program.
 *
 * The bpf_printk is verbose and prints information as connections
 * are established and verdicts are decided.
 */

struct {
	__uint(type, TEST_MAP_TYPE);
	__uint(max_entries, 20);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} sock_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, int);
} sock_skb_opts SEC(".maps");

struct {
	__uint(type, TEST_MAP_TYPE);
	__uint(max_entries, 20);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} tls_sock_map SEC(".maps");

char fmt[] = "%s %d\n";

SEC("sk_skb/stream_parser")
int bpf_prog1(struct __sk_buff *skb)
{
	return SK_PASS;
}

SEC("sk_skb/stream_verdict")
int bpf_prog2(struct __sk_buff *skb)
{
	__u32 lport = skb->local_port;
	int ret;

	if (lport == 10000)
		ret = 10;
	else
		ret = 1;

	return bpf_sk_redirect_map(skb, &sock_map, ret, 0);
}

static inline void bpf_write_pass(struct __sk_buff *skb, int offset)
{
	int err = bpf_skb_pull_data(skb, 6 + offset);
	void *data_end;
	char *c;

	if (err)
		return;

	c = (char *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;

	if (c + 5 + offset < data_end)
		memcpy(c + offset, "PASS", 4);
}

SEC("sk_skb/stream_verdict")
int bpf_prog3(struct __sk_buff *skb)
{
	int err, *f, ret = SK_PASS;
	const int one = 1;

	f = bpf_map_lookup_elem(&sock_skb_opts, &one);
	if (f && *f) {
		__u64 flags = 0;

		bpf_trace_printk(fmt, sizeof(fmt), "prog3: in f=", *f);
		ret = 0;
		flags = *f;

		err = bpf_skb_adjust_room(skb, -13, 0, 0);
		if (err)
			return SK_DROP;
		err = bpf_skb_adjust_room(skb, 4, 0, 0);
		if (err)
			return SK_DROP;
		bpf_write_pass(skb, 0);
		return bpf_sk_redirect_map(skb, &tls_sock_map, ret, flags);
	}
	bpf_trace_printk(fmt, sizeof(fmt), "prog3: f is null ", 0);
	err = bpf_skb_adjust_room(skb, 4, 0, 0);
	if (err)
		return SK_DROP;
	bpf_write_pass(skb, 13);
	return ret;
}

SEC("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
	__u32 lport, rport;
	int op, ret;

	op = (int) skops->op;

	switch (op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		lport = skops->local_port;
		rport = skops->remote_port;

		if (lport == 10000) {
			ret = 1;
			bpf_sock_map_update(skops, &sock_map, &ret,
						  BPF_NOEXIST);
		}
		break;
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		lport = skops->local_port;
		rport = skops->remote_port;

		if (bpf_ntohl(rport) == 10001) {
			ret = 10;
			bpf_sock_map_update(skops, &sock_map, &ret,
						  BPF_NOEXIST);
		}
		break;
	default:
		break;
	}

	return 1;
}

char _license[] SEC("license") = "GPL";
