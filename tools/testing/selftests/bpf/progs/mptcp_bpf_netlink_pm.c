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
extern bool bpf_test_and_set_bit(unsigned long nr, unsigned long *addr) __ksym;
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

SEC("struct_ops")
int BPF_PROG(mptcp_pm_netlink_get_local_id, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *skc)
{
	struct mptcp_pm_addr_entry *entry;
	int ret;

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

	bpf_rcu_read_lock();
	entry = mptcp_pm_nl_lookup_addr(msk, skc);
	backup = entry && !!(entry->flags & MPTCP_PM_ADDR_FLAG_BACKUP);
	bpf_rcu_read_unlock();

	return backup;
}

SEC("struct_ops")
bool BPF_PROG(mptcp_pm_netlink_accept_new_subflow, struct mptcp_sock *msk,
	      bool allow)
{
	bool ret = false;

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
}

static void mptcp_pm_netlink_rm_addr(struct mptcp_sock *msk, u8 rm_id)
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
void BPF_PROG(mptcp_pm_netlink_rm_addr_received, struct mptcp_sock *msk, u8 id)
{
	mptcp_pm_netlink_rm_addr(msk, id);
}

SEC("struct_ops")
bool BPF_PROG(mptcp_pm_netlink_accept_new_address, struct mptcp_sock *msk,
	      const struct mptcp_addr_info *addr)
{
	return !(bpf_mptcp_pm_accept_address(msk, addr) &&
		 msk->pm.status & BIT(MPTCP_PM_ADD_ADDR_RECEIVED));
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
	.init			= (void *)mptcp_pm_netlink_init,
	.name			= "bpf_netlink",
};
