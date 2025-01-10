// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025, Kylin Software */

#include "mptcp_bpf.h"
#include "mptcp_bpf_pm.h"

char _license[] SEC("license") = "GPL";

extern bool CONFIG_MPTCP_IPV6 __kconfig __weak;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MPTCP_PM_MAX_ADDR_ID);
	__type(key, __u32);
	__type(value, struct mptcp_pm_addr_entry);
} mptcp_pm_addr_map SEC(".maps");

struct callback_ctx {
	struct mptcp_sock *msk;
	struct sk_buff *msg;
	struct netlink_callback *cb;
	unsigned long *bitmap;
};

extern u8 bpf_find_next_zero_bit(const unsigned long *addr,
				 unsigned long size, unsigned long offset) __ksym;

extern int mptcp_userspace_pm_delete_local_addr(struct mptcp_sock *msk,
						struct mptcp_pm_addr_entry *addr) __ksym;

static struct mptcp_pm_addr_entry *
mptcp_pm_userspace_lookup_addr_by_id(struct mptcp_sock *msk, unsigned int id)
{
	struct mptcp_pm_addr_entry *entry;

	entry = bpf_map_lookup_elem(&mptcp_pm_addr_map, &id);
	if (entry)
		return bpf_core_cast(entry, struct mptcp_pm_addr_entry);
	return NULL;
}

static struct mptcp_pm_addr_entry *
mptcp_pm_userspace_lookup_addr(struct mptcp_sock *msk, const struct mptcp_addr_info *addr)
{
	struct mptcp_pm_addr_entry *entry;
	unsigned int id;

	bpf_for(id, 0, MPTCP_PM_MAX_ADDR_ID) {
		entry = mptcp_pm_userspace_lookup_addr_by_id(msk, id++);
		if (entry && mptcp_addresses_equal(&entry->addr, addr, false))
			return entry;
	}
	return NULL;
}

static void mptcp_pm_userspace_delete_entry(struct mptcp_pm_addr_entry *entry)
{
	__u32 key = entry->addr.id;

	bpf_map_delete_elem(&mptcp_pm_addr_map, &key);
}

static void mptcp_pm_userspace_add_entry(struct mptcp_sock *msk,
					 struct mptcp_pm_addr_entry *entry)
{
	__u32 key = entry->addr.id;

	bpf_map_update_elem(&mptcp_pm_addr_map, &key, entry, BPF_ANY);
}

static int mptcp_pm_userspace_append_new_local_addr(struct mptcp_sock *msk,
						    struct mptcp_pm_addr_entry *entry,
						    bool needs_id)
{
	unsigned long id_bitmap[4] = { 0 };
	struct mptcp_pm_addr_entry *e;
	bool addr_match = false;
	bool id_match = false;
	int ret = -EINVAL;
	unsigned int id;

	bpf_spin_lock_bh(&msk->pm.lock);
	bpf_for(id, 0, MPTCP_PM_MAX_ADDR_ID) {
		e = mptcp_pm_userspace_lookup_addr_by_id(msk, id++);
		if (e) {
			addr_match = mptcp_addresses_equal(&e->addr, &entry->addr, true);
			if (addr_match && entry->addr.id == 0 && needs_id)
				entry->addr.id = e->addr.id;
			id_match = (e->addr.id == entry->addr.id);
			if (addr_match || id_match)
				break;
			bpf_set_bit(e->addr.id, id_bitmap);
		}
	}

	if (!addr_match && !id_match) {
		struct mptcp_pm_addr_entry new_entry;

		mptcp_pm_copy_entry(&new_entry, entry);
		if (!new_entry.addr.id && needs_id)
			new_entry.addr.id = bpf_find_next_zero_bit(id_bitmap,
								   MPTCP_PM_MAX_ADDR_ID + 1,
								   1);
		mptcp_pm_userspace_add_entry(msk, &new_entry);
		msk->pm.local_addr_used++;
		ret = new_entry.addr.id;
	} else if (addr_match && id_match) {
		ret = entry->addr.id;
	}

	bpf_spin_unlock_bh(&msk->pm.lock);
	return ret;
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_userspace_get_local_id, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *skc)
{
	__be16 msk_sport = bpf_core_cast(inet_sk((struct sock *)msk),
					 struct inet_sock)->inet_sport;
	struct mptcp_pm_addr_entry *entry;

	bpf_printk("5 mptcp_pm_get_local_id");

	bpf_spin_lock_bh(&msk->pm.lock);
	entry = mptcp_pm_userspace_lookup_addr(msk, &skc->addr);
	bpf_spin_unlock_bh(&msk->pm.lock);
	if (entry)
		return entry->addr.id;

	if (skc->addr.port == msk_sport)
		skc->addr.port = 0;

	return mptcp_pm_userspace_append_new_local_addr(msk, skc, true);
}

SEC("struct_ops")
bool BPF_PROG(mptcp_pm_userspace_get_priority, struct mptcp_sock *msk,
	      struct mptcp_addr_info *skc)
{
	struct mptcp_pm_addr_entry *entry;
	bool backup;

	bpf_spin_lock_bh(&msk->pm.lock);
	entry = mptcp_pm_userspace_lookup_addr(msk, skc);
	backup = entry && !!(entry->flags & MPTCP_PM_ADDR_FLAG_BACKUP);
	bpf_spin_unlock_bh(&msk->pm.lock);

	bpf_printk("6 mptcp_pm_get_priority done");

	return backup;
}

SEC("struct_ops")
bool BPF_PROG(mptcp_pm_userspace_accept_new_subflow, const struct mptcp_sock *msk,
	      bool allow)
{
	return mptcp_userspace_pm_active(msk);
}

SEC("struct_ops")
bool BPF_PROG(mptcp_pm_userspace_accept_new_address, struct mptcp_sock *msk,
	      const struct mptcp_addr_info *addr)
{
	return mptcp_userspace_pm_active(msk);
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_userspace_address_announce, struct mptcp_sock *msk,
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

	bpf_printk("1 mptcp_pm_address_announced done");

	return 0;
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_userspace_address_remove, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *local)
{
	struct mptcp_pm_addr_entry *entry;
	u8 id = local->addr.id;

	if (id == 0)
		return mptcp_pm_remove_id_zero_address(msk);

	bpf_spin_lock_bh(&msk->pm.lock);
	entry = mptcp_pm_userspace_lookup_addr_by_id(msk, id);
	if (!entry) {
		bpf_spin_unlock_bh(&msk->pm.lock);
		return -EINVAL;
	}

	mptcp_pm_userspace_delete_entry(entry);
	bpf_spin_unlock_bh(&msk->pm.lock);

	mptcp_pm_remove_addr_entry(msk, entry);

	bpf_sock_kfree_entry((struct sock *)msk, entry, sizeof(*entry));

	bpf_printk("2 mptcp_pm_address_removed done");

	return 0;
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_userspace_subflow_create, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *local, struct mptcp_addr_info *remote)
{
	struct sock *sk = (struct sock *)msk;
	int err;

	err = mptcp_userspace_pm_append_new_local_addr(msk, local, false);
	if (err < 0)
		return err;

	err = bpf_mptcp_subflow_connect(sk, local, remote);
	bpf_spin_lock_bh(&msk->pm.lock);
	if (err)
		mptcp_userspace_pm_delete_local_addr(msk, local);
	else
		msk->pm.extra_subflows++;
	bpf_spin_unlock_bh(&msk->pm.lock);

	bpf_printk("3 mptcp_pm_subflow_established err=%d", err);

	return err;
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_userspace_subflow_destroy, struct mptcp_sock *msk,
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

	bpf_spin_lock_bh(&msk->pm.lock);
	mptcp_userspace_pm_delete_local_addr(msk, local);
	bpf_spin_unlock_bh(&msk->pm.lock);
	mptcp_subflow_shutdown(sk, ssk, RCV_SHUTDOWN | SEND_SHUTDOWN);
	mptcp_close_ssk(sk, ssk, subflow);
	BPF_MPTCP_INC_STATS(bpf_sock_net(sk), MPTCP_MIB_RMSUBFLOW);

	bpf_printk("4 mptcp_pm_subflow_closed done");

	return 0;
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_userspace_set_priority, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *local, struct mptcp_pm_addr_entry *remote)
{
	struct mptcp_pm_addr_entry *entry;
	u8 lookup_by_id = 0;
	u8 bkup = 0;

	bpf_printk("7 mptcp_pm_set_priority");

	if (local->addr.family == AF_UNSPEC)
		lookup_by_id = 1;

	if (local->flags & MPTCP_PM_ADDR_FLAG_BACKUP)
		bkup = 1;

	bpf_spin_lock_bh(&msk->pm.lock);
	entry = lookup_by_id ? mptcp_pm_userspace_lookup_addr_by_id(msk, local->addr.id) :
			       mptcp_pm_userspace_lookup_addr(msk, &local->addr);
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
void BPF_PROG(mptcp_pm_userspace_init, struct mptcp_sock *msk)
{
	bpf_printk("BPF userspace PM (%s)",
		   CONFIG_MPTCP_IPV6 ? "IPv6" : "IPv4");
}

static int release_callback(struct bpf_map *map, __u32 *key, void *val,
			    struct callback_ctx *data)
{
	struct mptcp_pm_addr_entry *entry;

	entry = mptcp_pm_userspace_lookup_addr_by_id(data->msk, *key);
	if (entry)
		mptcp_pm_userspace_delete_entry(entry);

	return 0;
}

SEC("struct_ops")
void BPF_PROG(mptcp_pm_userspace_release, struct mptcp_sock *msk)
{
	struct callback_ctx data;

	data.msk = msk;

	bpf_spin_lock_bh(&msk->pm.lock);
	bpf_for_each_map_elem(&mptcp_pm_addr_map,
			      release_callback, &data, 0);
	bpf_spin_unlock_bh(&msk->pm.lock);
}

SEC(".struct_ops.link")
struct mptcp_pm_ops bpf_userspace = {
	.get_local_id		= (void *)mptcp_pm_userspace_get_local_id,
	.get_priority		= (void *)mptcp_pm_userspace_get_priority,
	.accept_new_subflow	= (void *)mptcp_pm_userspace_accept_new_subflow,
	.accept_new_address	= (void *)mptcp_pm_userspace_accept_new_address,
	.address_announce	= (void *)mptcp_pm_userspace_address_announce,
	.address_remove		= (void *)mptcp_pm_userspace_address_remove,
	.subflow_create		= (void *)mptcp_pm_userspace_subflow_create,
	.subflow_destroy	= (void *)mptcp_pm_userspace_subflow_destroy,
	.set_priority		= (void *)mptcp_pm_userspace_set_priority,
	.init			= (void *)mptcp_pm_userspace_init,
	.release		= (void *)mptcp_pm_userspace_release,
	.name			= "bpf_userspace",
};

extern void bpf_pm_copy_entry(struct mptcp_pm_addr_entry *dst,
			      struct mptcp_pm_addr_entry *src) __ksym;

SEC("fexit/mptcp_pm_userspace_get_addr_msk")
int BPF_PROG(mptcp_pm_hashmap_get_addr, struct mptcp_sock *msk, u8 id,
	     struct mptcp_pm_addr_entry *addr)
{
	struct mptcp_pm_addr_entry *entry;

	bpf_spin_lock_bh(&msk->pm.lock);
	entry = mptcp_pm_hashmap_lookup_addr_by_id(msk, id);
	if (entry)
		bpf_pm_copy_entry(addr, entry);
	bpf_spin_unlock_bh(&msk->pm.lock);

	return 0;
}

extern bool bpf_test_bit(unsigned long nr, const unsigned long *addr) __ksym;
extern int mptcp_pm_genl_fill_addr(struct sk_buff *msg,
				   struct netlink_callback *cb,
				   struct mptcp_pm_addr_entry *entry) __ksym;

static int dump_addr_callback(struct bpf_map *map, __u32 *key, void *val,
			      struct callback_ctx *data)
{
	struct mptcp_pm_addr_entry *entry;

	entry = mptcp_pm_hashmap_lookup_addr_by_id(data->msk, *key);
	if (entry) {
		if (bpf_test_bit(entry->addr.id, data->bitmap))
			return 0;

		if (mptcp_pm_genl_fill_addr(data->msg, data->cb, entry) < 0)
			return 1;

		bpf_set_bit(entry->addr.id, data->bitmap);
	}

	return 0;
}

SEC("fmod_ret/mptcp_pm_userspace_dump_addr_msk")
int BPF_PROG(mptcp_pm_hashmap_dump_addr, struct mptcp_sock *msk,
	     struct sk_buff *msg, struct netlink_callback *cb)
{
	unsigned long bitmap[4] = { 0 };
	struct callback_ctx data;

	data.msk = msk;
	data.msg = msg;
	data.cb = cb;
	data.bitmap = bitmap;

	bpf_spin_lock_bh(&msk->pm.lock);
	bpf_for_each_map_elem(&mptcp_pm_addr_map,
			      dump_addr_callback, &data, 0);
	bpf_spin_unlock_bh(&msk->pm.lock);

	return msg->len;
}
