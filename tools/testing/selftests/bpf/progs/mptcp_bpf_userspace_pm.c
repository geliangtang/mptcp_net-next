// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025, Kylin Software */

#include "mptcp_bpf.h"
#include "mptcp_bpf_pm.h"

char _license[] SEC("license") = "GPL";

extern bool CONFIG_MPTCP_IPV6 __kconfig __weak;

#define private(name) SEC(".bss." #name) __hidden __attribute__((aligned(8)))

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MPTCP_PM_MAX_ADDR_ID);
	__type(key, __u32);
	__type(value, struct mptcp_pm_addr_entry);
} mptcp_pm_addr_map SEC(".maps");

private(A) struct bpf_spin_lock mptcp_pm_addr_lock;

struct callback_ctx {
	struct mptcp_sock *msk;
};

extern u8 bpf_find_next_zero_bit(const unsigned long *addr,
				 unsigned long size, unsigned long offset) __ksym;

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

		bpf_spin_lock(&mptcp_pm_addr_lock);
		mptcp_pm_copy_entry(&new_entry, entry);
		bpf_spin_unlock(&mptcp_pm_addr_lock);
		if (!new_entry.addr.id && needs_id)
			new_entry.addr.id = bpf_find_next_zero_bit(id_bitmap,
								   MPTCP_PM_MAX_ADDR_ID + 1,
								   1);
		mptcp_pm_userspace_add_entry(msk, &new_entry);
		bpf_spin_lock(&mptcp_pm_addr_lock);
		msk->pm.local_addr_used++;
		bpf_spin_unlock(&mptcp_pm_addr_lock);
		ret = new_entry.addr.id;
	} else if (addr_match && id_match) {
		ret = entry->addr.id;
	}

	return ret;
}

SEC("struct_ops")
int BPF_PROG(mptcp_pm_userspace_get_local_id, struct mptcp_sock *msk,
	     struct mptcp_pm_addr_entry *skc)
{
	__be16 msk_sport = bpf_core_cast(inet_sk((struct sock *)msk),
					 struct inet_sock)->inet_sport;
	struct mptcp_pm_addr_entry *entry;

	entry = mptcp_pm_userspace_lookup_addr(msk, &skc->addr);
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

	entry = mptcp_pm_userspace_lookup_addr(msk, skc);
	backup = entry && !!(entry->flags & MPTCP_PM_ADDR_FLAG_BACKUP);

	return backup;
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

	bpf_for_each_map_elem(&mptcp_pm_addr_map,
			      release_callback, &data, 0);
}

SEC(".struct_ops.link")
struct mptcp_pm_ops bpf_userspace = {
	.get_local_id		= (void *)mptcp_pm_userspace_get_local_id,
	.get_priority		= (void *)mptcp_pm_userspace_get_priority,
	.init			= (void *)mptcp_pm_userspace_init,
	.release		= (void *)mptcp_pm_userspace_release,
	.name			= "bpf_userspace",
};
