// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025, Kylin Software */

#include "mptcp_bpf.h"
#include "mptcp_bpf_pm.h"

char _license[] SEC("license") = "GPL";

#define BPF_NETLINK_MAX		8

extern bool CONFIG_MPTCP_IPV6 __kconfig __weak;

extern void bpf_bitmap_fill(unsigned long *dst__ign, unsigned int nbits) __ksym;

extern bool mptcp_pm_is_init_remote_addr(struct mptcp_sock *msk,
					 const struct mptcp_addr_info *remote) __ksym;
extern void bpf_mptcp_pm_create_subflow_or_signal_addr(struct mptcp_sock *msk) __ksym;
extern int mptcp_pm_nl_append_new_local_addr_msk(struct mptcp_sock *msk,
						 struct mptcp_pm_addr_entry *entry,
						 bool needs_id, bool replace) __ksym;
extern struct mptcp_pm_addr_entry *
mptcp_pm_nl_lookup_addr(struct mptcp_sock *msk,
			const struct mptcp_addr_info *info) __ksym;
extern void mptcp_local_address(const struct sock_common *skc,
				struct mptcp_addr_info *addr) __ksym;
extern bool mptcp_lookup_subflow_by_saddr(const struct list_head *list,
					  const struct mptcp_addr_info *saddr) __ksym;
extern void mptcp_pm_rm_subflow(struct mptcp_sock *msk,
				const struct mptcp_rm_list *rm_list) __ksym;
extern bool mptcp_remove_anno_list_by_saddr(struct mptcp_sock *msk,
					    const struct mptcp_addr_info *addr) __ksym;
extern void mptcp_pm_flush_addrs_and_subflows(struct mptcp_sock *msk,
					      struct list_head *rm_list) __ksym;

extern struct mptcp_pm_addr_entry *
bpf_kmemdup_entry(struct mptcp_pm_addr_entry *entry,
		  int size, gfp_t priority) __ksym;
extern void
bpf_kfree_entry(struct mptcp_pm_addr_entry *entry) __ksym;

extern bool lookup_subflow_by_daddr(const struct list_head *list,
				    const struct mptcp_addr_info *daddr) __ksym;
extern bool mptcp_subflow_connect(struct mptcp_sock *msk,
				  struct mptcp_addr_info *remote) __ksym;
extern bool bpf_mptcp_pm_accept_subflow(struct mptcp_sock *msk) __ksym;
extern bool bpf_mptcp_pm_accept_address(struct mptcp_sock *msk,
					const struct mptcp_addr_info *addr) __ksym;

static unsigned int mptcp_pm_get_add_addr_signal_max(const struct mptcp_sock *msk)
{
	return BPF_NETLINK_MAX;
}

static unsigned int mptcp_pm_get_add_addr_accept_max(const struct mptcp_sock *msk)
{
	return BPF_NETLINK_MAX;
}

static unsigned int mptcp_pm_get_subflows_max(const struct mptcp_sock *msk)
{
	return BPF_NETLINK_MAX;
}

static unsigned int mptcp_pm_get_local_addr_max(const struct mptcp_sock *msk)
{
	return BPF_NETLINK_MAX;
}

static struct mptcp_pm_addr_entry *
__lookup_addr(struct mptcp_sock *msk, const struct mptcp_addr_info *addr)
{
	struct mptcp_pm_addr_entry *entry;

	bpf_for_each(mptcp_pm_addr, entry, (struct sock *)msk, MPTCP_PM_TYPE_KERNEL) {
		if (mptcp_addresses_equal(&entry->addr, addr, entry->addr.port))
			return entry;
	}
	return NULL;
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_netlink_get_local_id, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *skc)
{
	struct mptcp_pm_addr_entry *entry;
	int ret;

	bpf_printk("1 mptcp_pm_netlink_get_local_id");

	bpf_rcu_read_lock();
	entry = mptcp_pm_nl_lookup_addr(msk, &skc->addr);
	ret = entry ? entry->addr.id : -1;
	bpf_rcu_read_unlock();
	if (ret >= 0)
		return ret;

	entry = bpf_kmemdup_entry(skc, sizeof(*skc), GFP_ATOMIC);
	if (!entry)
		return -ENOMEM;

	entry->addr.port = 0;
	ret = mptcp_pm_nl_append_new_local_addr_msk(msk, entry, true, false);
	if (ret < 0)
		bpf_kfree_entry(entry);

	return 0;
}

SEC("struct_ops")
bool BPF_PROG(mptcp_pm_netlink_get_priority, struct mptcp_sock *msk,
	      struct mptcp_addr_info *skc)
{
	struct mptcp_pm_addr_entry *entry;
	bool backup;

	bpf_printk("2 mptcp_pm_netlink_get_priority");

	bpf_rcu_read_lock();
	entry = __lookup_addr(msk, skc);
	backup = entry && !!(entry->flags & MPTCP_PM_ADDR_FLAG_BACKUP);
	bpf_rcu_read_unlock();

	return backup;
}

SEC("struct_ops")
bool BPF_PROG(mptcp_pm_netlink_accept_new_subflow, struct mptcp_sock *msk,
	      bool allow)
{
	bool ret = false;

	bpf_printk("4 mptcp_pm_netlink_accept_new_subflow");

	if (READ_ONCE(msk->pm.accept_subflow)) {
		if (allow)
			return true;

		ret = bpf_mptcp_pm_accept_subflow(msk);
	}

	return ret;
}

SEC("struct_ops")
void BPF_PROG(mptcp_pm_netlink_established, struct mptcp_sock *msk)
{
	bpf_mptcp_pm_create_subflow_or_signal_addr(msk);
}

SEC("struct_ops")
void BPF_PROG(mptcp_pm_netlink_subflow_established, struct mptcp_sock *msk)
{
	bpf_mptcp_pm_create_subflow_or_signal_addr(msk);
}

SEC("struct_ops")
void BPF_PROG(mptcp_pm_netlink_add_addr_received, struct mptcp_sock *msk)
{
	struct sock *sk = (struct sock *)msk;
	unsigned int add_addr_accept_max;
	struct mptcp_addr_info remote;
	unsigned int subflows_max;

	add_addr_accept_max = mptcp_pm_get_add_addr_accept_max(msk);
	subflows_max = mptcp_pm_get_subflows_max(msk);

	bpf_spin_lock_bh(&msk->pm.lock);
	mptcp_pm_copy_addr(&remote, &msk->pm.remote);
	mptcp_pm_announce_addr(msk, &remote, true);
	mptcp_pm_addr_send_ack(msk);

	if (lookup_subflow_by_daddr(&msk->conn_list, &remote))
		goto out;

	/* pick id 0 port, if none is provided the remote address */
	if (!remote.port)
		remote.port = sk->sk_dport;

	if (mptcp_subflow_connect(msk, &remote)) {
		/* add_addr_accepted is not decr for ID 0 */
		if (remote.id)
			msk->pm.add_addr_accepted++;
		if (msk->pm.add_addr_accepted >= add_addr_accept_max ||
		    msk->pm.extra_subflows >= subflows_max)
			WRITE_ONCE(msk->pm.accept_addr, false);
	}
out:
	bpf_spin_unlock_bh(&msk->pm.lock);
}

SEC("struct_ops")
void BPF_PROG(mptcp_pm_netlink_rm_addr_received, struct mptcp_sock *msk, u8 rm_id)
{
	if (rm_id && msk->pm.add_addr_accepted == 0) {
		/* Note: if the subflow has been closed before, this
		 * add_addr_accepted counter will not be decremented.
		 */
		if (--msk->pm.add_addr_accepted < mptcp_pm_get_add_addr_accept_max(msk))
			WRITE_ONCE(msk->pm.accept_addr, true);
	}
}

SEC("struct_ops")
bool BPF_PROG(mptcp_pm_netlink_accept_new_address, struct mptcp_sock *msk,
	      const struct mptcp_addr_info *addr)
{
	return !(bpf_mptcp_pm_accept_address(msk, addr) &&
		 msk->pm.status & BIT(MPTCP_PM_ADD_ADDR_RECEIVED));
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_netlink_add_addr, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *entry)
{
	struct mptcp_addr_info *addr = &entry->addr;
	struct mptcp_addr_info mpc_addr;

	/* if the endp linked to the init sf is re-added with a != ID */
	mptcp_local_address((struct sock_common *)msk, &mpc_addr);

	bpf_spin_lock_bh(&msk->pm.lock);
	if (mptcp_addresses_equal(addr, &mpc_addr, addr->port))
		msk->mpc_endpoint_id = addr->id;
	bpf_spin_unlock_bh(&msk->pm.lock);
	bpf_mptcp_pm_create_subflow_or_signal_addr(msk);

	return 0;
}

static u8 mptcp_endp_get_local_id(struct mptcp_sock *msk,
				  const struct mptcp_addr_info *addr)
{
	return msk->mpc_endpoint_id == addr->id ? 0 : addr->id;
}

static bool mptcp_pm_remove_anno_addr(struct mptcp_sock *msk,
				      const struct mptcp_addr_info *addr,
				      bool force)
{
	struct mptcp_rm_list list = { .nr = 0 };
	bool ret;

	list.ids[list.nr++] = mptcp_endp_get_local_id(msk, addr);

	ret = mptcp_remove_anno_list_by_saddr(msk, addr);
	if (ret || force) {
		bpf_spin_lock_bh(&msk->pm.lock);
		if (ret) {
			bpf_set_bit(addr->id, msk->pm.id_avail_bitmap);
			msk->pm.add_addr_signaled--;
		}
		mptcp_pm_remove_addr(msk, &list);
		bpf_spin_unlock_bh(&msk->pm.lock);
	}
	return ret;
}

static void __mark_subflow_endp_available(struct mptcp_sock *msk, u8 id)
{
	/* If it was marked as used, and not ID 0, decrement local_addr_used */
	if (!bpf_test_and_set_bit(id ? : msk->mpc_endpoint_id, msk->pm.id_avail_bitmap) &&
	    id && !(msk->pm.local_addr_used == 0))
		msk->pm.local_addr_used--;
}

static void mptcp_pm_netlink_remove_id_zero_address(struct mptcp_sock *msk,
						    const struct mptcp_addr_info *addr)
{
	struct mptcp_rm_list list = { .nr = 0 };
	struct mptcp_addr_info msk_local;

	if (list_empty(&msk->conn_list))
		return;

	mptcp_local_address((struct sock_common *)msk, &msk_local);
	if (!mptcp_addresses_equal(&msk_local, addr, addr->port))
		return;

	list.ids[list.nr++] = 0;

	bpf_spin_lock_bh(&msk->pm.lock);
	mptcp_pm_remove_addr(msk, &list);
	mptcp_pm_rm_subflow(msk, &list);
	__mark_subflow_endp_available(msk, 0);
	bpf_spin_unlock_bh(&msk->pm.lock);
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_netlink_del_addr, struct mptcp_sock *msk,
	     const struct mptcp_pm_addr_entry *entry)
{
	const struct mptcp_addr_info *addr = &entry->addr;
	struct mptcp_rm_list list = { .nr = 1 };
	bool remove_subflow;

	if (addr->id == 0) {
		mptcp_pm_netlink_remove_id_zero_address(msk, addr);
		return 0;
	}

	remove_subflow = mptcp_lookup_subflow_by_saddr(&msk->conn_list, addr);
	mptcp_pm_remove_anno_addr(msk, addr, remove_subflow &&
				  !(entry->flags & MPTCP_PM_ADDR_FLAG_IMPLICIT));

	list.ids[0] = mptcp_endp_get_local_id(msk, addr);
	if (remove_subflow) {
		bpf_spin_lock_bh(&msk->pm.lock);
		mptcp_pm_rm_subflow(msk, &list);
		bpf_spin_unlock_bh(&msk->pm.lock);
	}

	if (entry->flags & MPTCP_PM_ADDR_FLAG_SUBFLOW) {
		bpf_spin_lock_bh(&msk->pm.lock);
		__mark_subflow_endp_available(msk, list.ids[0]);
		bpf_spin_unlock_bh(&msk->pm.lock);
	}

	if (msk->mpc_endpoint_id == addr->id)
		msk->mpc_endpoint_id = 0;

	return 0;
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_netlink_flush_addrs, struct mptcp_sock *msk,
	     struct list_head *rm_list)
{
	mptcp_pm_flush_addrs_and_subflows(msk, rm_list);

	return 0;
}

SEC("struct_ops")
void BPF_PROG(mptcp_pm_netlink_init, struct mptcp_sock *msk)
{
	bool subflows_allowed = !!mptcp_pm_get_subflows_max(msk);
	struct mptcp_pm_data *pm = &msk->pm;

	bpf_printk("BPF netlink PM (%s)",
		   CONFIG_MPTCP_IPV6 ? "IPv6" : "IPv4");

	WRITE_ONCE(pm->work_pending,
		   (!!mptcp_pm_get_local_addr_max(msk) &&
		    subflows_allowed) ||
		   !!mptcp_pm_get_add_addr_signal_max(msk));
	WRITE_ONCE(pm->accept_addr,
		   !!mptcp_pm_get_add_addr_accept_max(msk) &&
		   subflows_allowed);
	WRITE_ONCE(pm->accept_subflow, subflows_allowed);

	bpf_bitmap_fill(pm->id_avail_bitmap, MPTCP_PM_MAX_ADDR_ID + 1);
}

SEC(".struct_ops.link")
struct mptcp_pm_ops bpf_netlink = {
	.get_local_id		= (void *)mptcp_pm_netlink_get_local_id,
	.get_priority		= (void *)mptcp_pm_netlink_get_priority,
	.accept_new_subflow	= (void *)mptcp_pm_netlink_accept_new_subflow,
	.established		= (void *)mptcp_pm_netlink_established,
	.subflow_established	= (void *)mptcp_pm_netlink_subflow_established,
	.add_addr_received	= (void *)mptcp_pm_netlink_add_addr_received,
	.rm_addr_received	= (void *)mptcp_pm_netlink_rm_addr_received,
	.accept_new_address	= (void *)mptcp_pm_netlink_accept_new_address,
	.add_addr		= (void *)mptcp_pm_netlink_add_addr,
	.del_addr		= (void *)mptcp_pm_netlink_del_addr,
	.flush_addrs		= (void *)mptcp_pm_netlink_flush_addrs,
	.init			= (void *)mptcp_pm_netlink_init,
	.name			= "bpf_netlink",
};
