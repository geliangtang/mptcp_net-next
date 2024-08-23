// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024, Kylin Software */

/* vmlinux.h, bpf_helpers.h and other 'define' */
#include "bpf_tracing_net.h"
#include "mptcp_bpf.h"

char _license[] SEC("license") = "GPL";

static int mptcp_setsockopt_mark(struct bpf_sock *sk, struct bpf_sockopt *ctx)
{
	struct mptcp_subflow_context *subflow;
	int *optval = ctx->optval;
	struct mptcp_sock *msk;
	__u32 mark;
	int i = 0;

	if (ctx->optval + sizeof(mark) > ctx->optval_end)
		return 1;

	mark = *optval;

	msk = bpf_mptcp_sock_acquire(bpf_mptcp_sk((struct sock *)sk));
	if (!msk)
		return 1;

	bpf_for_each(mptcp_subflow, subflow, msk) {
		struct sock *ssk = bpf_mptcp_subflow_tcp_sock(subflow);
		int err;

		bpf_spin_lock_bh(&ssk->sk_lock.slock);
		err = bpf_setsockopt(ssk, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
		bpf_spin_unlock_bh(&ssk->sk_lock.slock);
		if (err < 0)
			break;

		bpf_printk("setsockopt i=%d mark=%u", i++, mark);
	}
	bpf_mptcp_sock_release(msk);

	return 1;
}

static int mptcp_setsockopt_cc(struct bpf_sock *sk, struct bpf_sockopt *ctx)
{
	struct mptcp_subflow_context *subflow;
	char *optval = ctx->optval;
	char cc[TCP_CA_NAME_MAX];
	struct mptcp_sock *msk;
	int i = 0;

	if (ctx->optval + TCP_CA_NAME_MAX > ctx->optval_end)
		return 1;

	__builtin_memcpy(cc, optval, TCP_CA_NAME_MAX);

	msk = bpf_mptcp_sock_acquire(bpf_mptcp_sk((struct sock *)sk));
	if (!msk)
		return 1;

	bpf_for_each(mptcp_subflow, subflow, msk) {
		struct sock *ssk = bpf_mptcp_subflow_tcp_sock(subflow);
		int err;

		bpf_spin_lock_bh(&ssk->sk_lock.slock);
		err = bpf_setsockopt(ssk, SOL_TCP, TCP_CONGESTION, cc, TCP_CA_NAME_MAX);
		bpf_spin_unlock_bh(&ssk->sk_lock.slock);
		if (err < 0)
			break;

		bpf_printk("setsockopt i=%d cc=%s", i++, cc);
	}
	bpf_mptcp_sock_release(msk);

	return 1;
}

SEC("cgroup/setsockopt")
int mptcp_setsockopt(struct bpf_sockopt *ctx)
{
	struct bpf_sock *sk = ctx->sk;

	if (!sk || sk->protocol != IPPROTO_MPTCP)
		return 1;

	if (ctx->level == SOL_SOCKET && ctx->optname == SO_MARK)
		return mptcp_setsockopt_mark(sk, ctx);
	if (ctx->level == SOL_TCP && ctx->optname == TCP_CONGESTION)
		return mptcp_setsockopt_cc(sk, ctx);
	return 1;
}

static int mptcp_getsockopt_mark(struct bpf_sock *sk, struct bpf_sockopt *ctx)
{
	struct mptcp_subflow_context *subflow;
	struct mptcp_sock *msk;
	int i = 0;

	msk = bpf_mptcp_sock_acquire(bpf_mptcp_sk((struct sock *)sk));
	if (!msk)
		return 1;

	bpf_for_each(mptcp_subflow, subflow, msk) {
		struct sock *ssk = bpf_mptcp_subflow_tcp_sock(subflow);

		if (ssk->sk_mark != 1) {
			ctx->retval = -1;
			break;
		}

		bpf_printk("i=%d mark=%u", i++, ssk->sk_mark);
	}
	bpf_mptcp_sock_release(msk);

	return 1;
}

static int mptcp_getsockopt_cc(struct bpf_sock *sk, struct bpf_sockopt *ctx)
{
	struct mptcp_subflow_context *subflow;
	struct mptcp_sock *msk;
	int i = 0;

	msk = bpf_mptcp_sock_acquire(bpf_mptcp_sk((struct sock *)sk));
	if (!msk)
		return 1;

	bpf_for_each(mptcp_subflow, subflow, msk) {
		struct sock *ssk = bpf_mptcp_subflow_tcp_sock(subflow);
		struct inet_connection_sock *icsk;

		icsk = bpf_core_cast(ssk, struct inet_connection_sock);

		if (__builtin_memcmp(icsk->icsk_ca_ops->name, "reno", TCP_CA_NAME_MAX)) {
			ctx->retval = -1;
			break;
		}

		bpf_printk("i=%d cc=%s", i++, icsk->icsk_ca_ops->name);
	}
	bpf_mptcp_sock_release(msk);

	return 1;
}

SEC("cgroup/getsockopt")
int mptcp_getsockopt(struct bpf_sockopt *ctx)
{
	struct bpf_sock *sk = ctx->sk;

	if (!sk || sk->protocol != IPPROTO_MPTCP)
		return 1;

	if (ctx->level == SOL_SOCKET && ctx->optname == SO_MARK)
		return mptcp_getsockopt_mark(sk, ctx);
	if (ctx->level == SOL_TCP && ctx->optname == TCP_CONGESTION)
		return mptcp_getsockopt_cc(sk, ctx);
	return 1;
}
