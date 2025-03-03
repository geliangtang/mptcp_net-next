// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024, Kylin Software */

/* vmlinux.h, bpf_helpers.h and other 'define' */
#include "bpf_tracing_net.h"
#include "mptcp_bpf.h"

char _license[] SEC("license") = "GPL";
int ids;

#ifndef TCP_IS_MPTCP
#define TCP_IS_MPTCP		43	/* Is MPTCP being used? */
#endif

SEC("cgroup/getsockopt")
int iters_subflow(struct bpf_sockopt *ctx)
{
	struct mptcp_subflow_context *subflow;
	struct bpf_sock *sk = ctx->sk;
	struct sock *ssk = NULL;
	struct mptcp_sock *msk;
	int local_ids = 0;

	if (ctx->level != SOL_TCP || ctx->optname != TCP_IS_MPTCP)
		return 1;

	msk = bpf_skc_to_mptcp_sock(sk);
	if (!msk || msk->pm.server_side || !msk->pm.extra_subflows)
		return 1;

	bpf_for_each(mptcp_subflow, subflow, (struct sock *)sk) {
		/* Here MPTCP-specific packet scheduler kfunc can be called:
		 * this test is not doing anything really useful, only to
		 * verify the iteration works.
		 */

		local_ids += subflow->subflow_id;

		/* only to check the following helper works */
		ssk = mptcp_subflow_tcp_sock(subflow);
	}

	if (!ssk)
		goto out;

	/* assert: if not OK, something wrong on the kernel side */
	if (ssk->sk_dport != ((struct sock *)msk)->sk_dport)
		goto out;

	/* only to check the following kfunc works */
	subflow = bpf_mptcp_subflow_ctx(ssk);
	if (!subflow || subflow->token != msk->token)
		goto out;

	ids = local_ids;

out:
	return 1;
}

static int pm_get_local_ids(struct sock *sk, enum mptcp_pm_type pm_type)
{
	struct mptcp_pm_addr_entry *entry;
	int local_ids = 0;

	bpf_for_each(mptcp_pm_addr, entry, sk, pm_type) {
		/* Here MPTCP-specific path manager kfunc can be called:
		 * this test is not doing anything really useful, only to
		 * verify the iteration works.
		 */

		if (!bpf_ipv4_is_private_10(entry->addr.addr.s_addr))
			break;

		local_ids += entry->addr.id;
	}

	return local_ids;
}

SEC("cgroup/getsockopt")
int netlink_addr(struct bpf_sockopt *ctx)
{
	struct bpf_sock *sk = ctx->sk;
	struct mptcp_sock *msk;

	if (ctx->level != SOL_TCP || ctx->optname != TCP_IS_MPTCP)
		return 1;

	msk = bpf_skc_to_mptcp_sock(sk);
	if (!msk || msk->pm.server_side)
		return 1;

	bpf_rcu_read_lock();
	ids = pm_get_local_ids((struct sock *)sk, MPTCP_PM_TYPE_KERNEL);
	bpf_rcu_read_unlock();

	return 1;
}

SEC("cgroup/getsockopt")
int userspace_addr(struct bpf_sockopt *ctx)
{
	struct bpf_sock *sk = ctx->sk;
	struct mptcp_sock *msk;

	if (ctx->level != SOL_TCP || ctx->optname != TCP_IS_MPTCP)
		return 1;

	msk = bpf_skc_to_mptcp_sock(sk);
	if (!msk || msk->pm.server_side)
		return 1;

	bpf_spin_lock_bh(&msk->pm.lock);
	ids = pm_get_local_ids((struct sock *)sk, MPTCP_PM_TYPE_USERSPACE);
	bpf_spin_unlock_bh(&msk->pm.lock);

	return 1;
}

/* tools/testing/selftests/bpf/tools/include/vmlinux.h */
SEC("tracepoint/mptcp/mptcp_subflow_get_send")
int trace_get_send(struct trace_event_raw_mptcp_subflow_get_send *ctx)
{
	struct mptcp_sock *msk = bpf_core_cast(ctx->msk, struct mptcp_sock);
	struct mptcp_subflow_context *subflow;
	int i = 0;

	mptcp_for_each_subflow(msk, subflow) {
		bpf_printk("bpf_iter tracepoint i=%d subflows=%u", i++, msk->pm.subflows);
	}

	bpf_printk("trace_get_send snd_wnd=%u token=%u", ctx->snd_wnd, msk->token);
	return 0;
}
