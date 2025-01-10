// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025, Kylin Software */

#include "mptcp_bpf.h"
#include "mptcp_bpf_pm.h"

char _license[] SEC("license") = "GPL";

extern bool CONFIG_MPTCP_IPV6 __kconfig __weak;

extern void bpf_list_del_rcu(struct list_head *entry) __ksym;
extern void
mptcp_userspace_pm_free_local_addr_list(struct mptcp_sock *msk) __ksym;
extern int mptcp_userspace_pm_append_new_local_addr(struct mptcp_sock *msk,
						    struct mptcp_pm_addr_entry *entry,
						    bool needs_id) __ksym;
extern struct mptcp_pm_addr_entry *
mptcp_userspace_pm_lookup_addr(struct mptcp_sock *msk,
			       const struct mptcp_addr_info *addr) __ksym;

static struct mptcp_pm_addr_entry *
mptcp_pm_hashmap_lookup_addr_by_id(struct mptcp_sock *msk, unsigned int id)
{
	struct mptcp_pm_addr_entry *entry;

	bpf_for_each(mptcp_pm_addr, entry, (struct sock *)msk, MPTCP_PM_TYPE_USERSPACE) {
		if (entry->addr.id == id)
			return entry;
	}
	return NULL;
}

static struct mptcp_pm_addr_entry *
mptcp_pm_hashmap_lookup_addr(struct mptcp_sock *msk, const struct mptcp_addr_info *addr)
{
	struct mptcp_pm_addr_entry *entry;

	bpf_for_each(mptcp_pm_addr, entry, (struct sock *)msk, MPTCP_PM_TYPE_USERSPACE) {
		if (mptcp_addresses_equal(&entry->addr, addr, false))
			return entry;
	}
	return NULL;
}

static void mptcp_pm_hashmap_delete_entry(struct mptcp_pm_addr_entry *entry)
{
	bpf_list_del_rcu(&entry->list);
}

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
	entry = mptcp_pm_hashmap_lookup_addr(msk, skc);
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
int BPF_PROG(mptcp_pm_hashmap_address_announce, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *local)
{
	int err;

	err = mptcp_userspace_pm_append_new_local_addr(msk, local, false);
	if (err < 0)
		return err;

	bpf_spin_lock_bh(&msk->pm.lock);

	if (mptcp_pm_alloc_anno_list(msk, &local->addr, true)) {
		msk->pm.add_addr_signaled++;
		mptcp_pm_announce_addr(msk, &local->addr, false);
		mptcp_pm_addr_send_ack(msk);
	}

	bpf_spin_unlock_bh(&msk->pm.lock);

	return 0;
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_hashmap_address_remove, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *local)
{
	struct mptcp_pm_addr_entry *entry;
	u8 id = local->addr.id;

	if (id == 0)
		return mptcp_pm_remove_id_zero_address(msk);

	bpf_spin_lock_bh(&msk->pm.lock);
	entry = mptcp_pm_hashmap_lookup_addr_by_id(msk, id);
	if (!entry) {
		bpf_spin_unlock_bh(&msk->pm.lock);
		return -EINVAL;
	}

	mptcp_pm_hashmap_delete_entry(entry);
	bpf_spin_unlock_bh(&msk->pm.lock);

	mptcp_pm_remove_addr_entry(msk, entry);

	bpf_sock_kfree_entry((struct sock *)msk, entry, sizeof(*entry));

	return 0;
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_hashmap_subflow_create, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *local, struct mptcp_addr_info *remote)
{
	struct sock *sk = (struct sock *)msk;
	int err;

	err = mptcp_userspace_pm_append_new_local_addr(msk, local, false);
	if (err < 0)
		return err;

	return bpf_mptcp_subflow_connect(sk, local, remote);
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_hashmap_subflow_destroy, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *local, struct mptcp_addr_info *remote)
{
	struct sock *ssk, *sk = (struct sock *)msk;
	struct mptcp_subflow_context *subflow;

	ssk = mptcp_pm_find_ssk(msk, &local->addr, remote);
	if (!ssk)
		return -ESRCH;

	subflow = bpf_mptcp_subflow_ctx(ssk);
	if (!subflow)
		return -EINVAL;

	mptcp_subflow_shutdown(sk, ssk, RCV_SHUTDOWN | SEND_SHUTDOWN);
	mptcp_close_ssk(sk, ssk, subflow);
	BPF_MPTCP_INC_STATS(bpf_sock_net(sk), MPTCP_MIB_RMSUBFLOW);

	return 0;
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_hashmap_set_priority, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *local, struct mptcp_pm_addr_entry *remote)
{
	struct mptcp_pm_addr_entry *entry;
	u8 lookup_by_id = 0;
	u8 bkup = 0;

	if (local->addr.family == AF_UNSPEC)
		lookup_by_id = 1;

	if (local->flags & MPTCP_PM_ADDR_FLAG_BACKUP)
		bkup = 1;

	bpf_spin_lock_bh(&msk->pm.lock);
	entry = lookup_by_id ? mptcp_pm_hashmap_lookup_addr_by_id(msk, local->addr.id) :
			       mptcp_pm_hashmap_lookup_addr(msk, &local->addr);
	if (entry) {
		if (bkup)
			entry->flags |= MPTCP_PM_ADDR_FLAG_BACKUP;
		else
			entry->flags &= ~MPTCP_PM_ADDR_FLAG_BACKUP;
	}
	bpf_spin_unlock_bh(&msk->pm.lock);

	return mptcp_pm_mp_prio_send_ack(msk, entry ? &entry->addr : &local->addr,
					 &remote->addr, bkup);
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
	.address_announce	= (void *)mptcp_pm_hashmap_address_announce,
	.address_remove		= (void *)mptcp_pm_hashmap_address_remove,
	.subflow_create		= (void *)mptcp_pm_hashmap_subflow_create,
	.subflow_destroy	= (void *)mptcp_pm_hashmap_subflow_destroy,
	.set_priority		= (void *)mptcp_pm_hashmap_set_priority,
	.init			= (void *)mptcp_pm_hashmap_init,
	.release		= (void *)mptcp_pm_hashmap_release,
	.name			= "bpf_hashmap",
};
