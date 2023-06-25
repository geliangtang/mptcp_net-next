// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023, SUSE. */
/* Copyright (c) 2024, Kylin Software */

#include "mptcp_bpf.h"
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct mptcp_stale_storage {
	__u8 nr;
	__u32 ids[MPTCP_SUBFLOWS_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct mptcp_stale_storage);
} mptcp_stale_map SEC(".maps");

static void mptcp_subflow_set_stale(struct mptcp_stale_storage *storage,
				    __u32 subflow_id)
{
	if (!subflow_id)
		return;

	for (int i = 0; i < storage->nr && i < MPTCP_SUBFLOWS_MAX; i++) {
		if (storage->ids[i] == subflow_id)
			return;
	}

	if (storage->nr < MPTCP_SUBFLOWS_MAX - 1)
		storage->ids[storage->nr++] = subflow_id;
}

static void mptcp_subflow_clear_stale(struct mptcp_stale_storage *storage,
				      __u32 subflow_id)
{
	if (!subflow_id)
		return;

	for (int i = 0; i < storage->nr && i < MPTCP_SUBFLOWS_MAX; i++) {
		if (storage->ids[i] == subflow_id) {
			for (int j = i; j < MPTCP_SUBFLOWS_MAX - 1; j++) {
				if (!storage->ids[j + 1])
					break;
				storage->ids[j] = storage->ids[j + 1];
				storage->ids[j + 1] = 0;
			}
			storage->nr--;
			return;
		}
	}
}

static bool mptcp_subflow_is_stale(struct mptcp_stale_storage *storage,
				   __u32 subflow_id)
{
	for (int i = 0; i < storage->nr && i < MPTCP_SUBFLOWS_MAX; i++) {
		if (storage->ids[i] == subflow_id)
			return true;
	}

	return false;
}

static bool mptcp_subflow_is_active(struct mptcp_sock *msk,
				    __u32 subflow_id)
{
	struct mptcp_subflow_context *subflow;

	bpf_for_each(mptcp_subflow, subflow, msk) {
		if (subflow->subflow_id == subflow_id)
			return true;
	}

	return false;
}

SEC("struct_ops")
void BPF_PROG(mptcp_sched_stale_init, struct mptcp_sock *msk)
{
	struct mptcp_stale_storage *storage;

	storage = bpf_sk_storage_get(&mptcp_stale_map, msk, 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!storage)
		return;

	for (int i = 0; i < MPTCP_SUBFLOWS_MAX; i++)
		storage->ids[i] = 0;
	storage->nr = 0;

	mptcp_subflow_set_stale(storage, 2);
	mptcp_subflow_set_stale(storage, 3);
}

SEC("struct_ops")
void BPF_PROG(mptcp_sched_stale_release, struct mptcp_sock *msk)
{
	bpf_sk_storage_delete(&mptcp_stale_map, msk);
}

SEC("struct_ops")
int BPF_PROG(bpf_stale_get_subflow, struct mptcp_sock *msk,
	     struct mptcp_sched_data *data)
{
	struct mptcp_subflow_context *subflow;
	struct mptcp_stale_storage *storage;
	int i;

	if (!msk->pm.subflows) {
		mptcp_subflow_set_scheduled(bpf_mptcp_subflow_ctx(msk->first), true);
		return 0;
	}

	storage = bpf_sk_storage_get(&mptcp_stale_map, msk, 0, 0);
	if (!storage)
		return -1;

	/* Handle invalid subflow ids for subflows that have been closed */
	if (msk->pm.subflows < storage->nr) {
		for (i = 0; i < storage->nr && i < MPTCP_SUBFLOWS_MAX; i++) {
			if (!mptcp_subflow_is_active(msk, storage->ids[i]))
				mptcp_subflow_clear_stale(storage, storage->ids[i]);
		}
	}

	bpf_for_each(mptcp_subflow, subflow, msk) {
		if (mptcp_subflow_is_stale(storage, subflow->subflow_id))
			continue;

		mptcp_subflow_set_scheduled(subflow, true);
		break;
	}

	return 0;
}

SEC(".struct_ops.link")
struct mptcp_sched_ops stale = {
	.init		= (void *)mptcp_sched_stale_init,
	.release	= (void *)mptcp_sched_stale_release,
	.get_subflow	= (void *)bpf_stale_get_subflow,
	.name		= "bpf_stale",
};
