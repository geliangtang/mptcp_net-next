// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025, Kylin Software */

#include "mptcp_bpf.h"
#include "mptcp_bpf_pm.h"

char _license[] SEC("license") = "GPL";

extern bool CONFIG_MPTCP_IPV6 __kconfig __weak;

extern void
mptcp_userspace_pm_free_local_addr_list(struct mptcp_sock *msk) __ksym;
extern int mptcp_userspace_pm_append_new_local_addr(struct mptcp_sock *msk,
						    struct mptcp_pm_addr_entry *entry,
						    bool needs_id) __ksym;
extern struct mptcp_pm_addr_entry *
mptcp_userspace_pm_lookup_addr(struct mptcp_sock *msk,
			       const struct mptcp_addr_info *addr) __ksym;

SEC("struct_ops")
int BPF_PROG(mptcp_pm_hashmap_get_local_id, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *skc)
{
	__be16 msk_sport = bpf_core_cast(inet_sk((struct sock *)msk),
					 struct inet_sock)->inet_sport;
	struct mptcp_pm_addr_entry *entry;

	bpf_spin_lock_bh(&msk->pm.lock);
	entry = mptcp_userspace_pm_lookup_addr(msk, &skc->addr);
	bpf_spin_unlock_bh(&msk->pm.lock);
	if (entry)
		return entry->addr.id;

	if (skc->addr.port == msk_sport)
		skc->addr.port = 0;

	return mptcp_userspace_pm_append_new_local_addr(msk, skc, true);
}

SEC("struct_ops")
bool BPF_PROG(mptcp_pm_hashmap_get_priority, struct mptcp_sock *msk,
	      struct mptcp_addr_info *skc)
{
	struct mptcp_pm_addr_entry *entry;
	bool backup;

	bpf_spin_lock_bh(&msk->pm.lock);
	entry = mptcp_userspace_pm_lookup_addr(msk, skc);
	backup = entry && !!(entry->flags & MPTCP_PM_ADDR_FLAG_BACKUP);
	bpf_spin_unlock_bh(&msk->pm.lock);

	return backup;
}

SEC("struct_ops")
bool BPF_PROG(mptcp_pm_hashmap_accept_new_subflow, struct mptcp_sock *msk,
	      bool allow)
{
	return mptcp_userspace_pm_active(msk);
}

SEC("struct_ops")
bool BPF_PROG(mptcp_pm_hashmap_accept_new_address, struct mptcp_sock *msk,
	      const struct mptcp_addr_info *addr)
{
	return mptcp_userspace_pm_active(msk);
}

SEC("struct_ops")
void BPF_PROG(mptcp_pm_hashmap_init, struct mptcp_sock *msk)
{
	bpf_printk("BPF hashmap PM (%s)",
		   CONFIG_MPTCP_IPV6 ? "IPv6" : "IPv4");
}

SEC("struct_ops")
void BPF_PROG(mptcp_pm_hashmap_release, struct mptcp_sock *msk)
{
	mptcp_userspace_pm_free_local_addr_list(msk);
}

SEC(".struct_ops.link")
struct mptcp_pm_ops bpf_hashmap = {
	.get_local_id		= (void *)mptcp_pm_hashmap_get_local_id,
	.get_priority		= (void *)mptcp_pm_hashmap_get_priority,
	.accept_new_subflow	= (void *)mptcp_pm_hashmap_accept_new_subflow,
	.accept_new_address	= (void *)mptcp_pm_hashmap_accept_new_address,
	.init			= (void *)mptcp_pm_hashmap_init,
	.release		= (void *)mptcp_pm_hashmap_release,
	.name			= "bpf_hashmap",
};
