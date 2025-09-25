// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2020, Tessares SA.
 * Copyright (c) 2022, SUSE.
 *
 * Author: Nicolas Rybowski <nicolas.rybowski@tessares.net>
 */

#define pr_fmt(fmt) "MPTCP: " fmt

#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <net/bpf_sk_storage.h>
#include "protocol.h"

#ifdef CONFIG_BPF_JIT
static struct bpf_struct_ops bpf_mptcp_pm_ops;

static u32 mptcp_sock_id,
	   mptcp_entry_id;

/* MPTCP BPF path manager */

static const struct bpf_func_proto *
bpf_mptcp_pm_get_func_proto(enum bpf_func_id func_id,
			    const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_sk_storage_get:
		return &bpf_sk_storage_get_proto;
	case BPF_FUNC_sk_storage_delete:
		return &bpf_sk_storage_delete_proto;
	default:
		return bpf_base_func_proto(func_id, prog);
	}
}

static int bpf_mptcp_pm_btf_struct_access(struct bpf_verifier_log *log,
					  const struct bpf_reg_state *reg,
					  int off, int size)
{
	u32 id = reg->btf_id;
	size_t end;

	if (id == mptcp_sock_id) {
		switch (off) {
		case offsetof(struct mptcp_sock, pm.remote.id):
			end = offsetofend(struct mptcp_sock, pm.remote.id);
			break;
		case offsetof(struct mptcp_sock, pm.remote.family):
			end = offsetofend(struct mptcp_sock, pm.remote.family);
			break;
		case offsetof(struct mptcp_sock, pm.remote.port):
			end = offsetofend(struct mptcp_sock, pm.remote.port);
			break;
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
		case offsetof(struct mptcp_sock, pm.remote.addr6.s6_addr32[0]):
			end = offsetofend(struct mptcp_sock, pm.remote.addr6.s6_addr32[0]);
			break;
		case offsetof(struct mptcp_sock, pm.remote.addr6.s6_addr32[1]):
			end = offsetofend(struct mptcp_sock, pm.remote.addr6.s6_addr32[1]);
			break;
		case offsetof(struct mptcp_sock, pm.remote.addr6.s6_addr32[2]):
			end = offsetofend(struct mptcp_sock, pm.remote.addr6.s6_addr32[2]);
			break;
		case offsetof(struct mptcp_sock, pm.remote.addr6.s6_addr32[3]):
			end = offsetofend(struct mptcp_sock, pm.remote.addr6.s6_addr32[3]);
			break;
#else
		case offsetof(struct mptcp_sock, pm.remote.addr.s_addr):
			end = offsetofend(struct mptcp_sock, pm.remote.addr.s_addr);
			break;
#endif
		case offsetof(struct mptcp_sock, pm.work_pending):
			end = offsetofend(struct mptcp_sock, pm.work_pending);
			break;
		case offsetof(struct mptcp_sock, pm.accept_addr):
			end = offsetofend(struct mptcp_sock, pm.accept_addr);
			break;
		case offsetof(struct mptcp_sock, pm.accept_subflow):
			end = offsetofend(struct mptcp_sock, pm.accept_subflow);
			break;
		case offsetof(struct mptcp_sock, pm.add_addr_signaled):
			end = offsetofend(struct mptcp_sock, pm.add_addr_signaled);
			break;
		case offsetof(struct mptcp_sock, pm.add_addr_accepted):
			end = offsetofend(struct mptcp_sock, pm.add_addr_accepted);
			break;
		case offsetof(struct mptcp_sock, pm.local_addr_used):
			end = offsetofend(struct mptcp_sock, pm.local_addr_used);
			break;
		case offsetof(struct mptcp_sock, pm.subflows):
			end = offsetofend(struct mptcp_sock, pm.subflows);
			break;
		default:
			bpf_log(log, "no write support to mptcp_sock at off %d\n",
				off);
			return -EACCES;
		}
	} else if (id == mptcp_entry_id) {
		switch (off) {
		case offsetof(struct mptcp_pm_addr_entry, addr.id):
			end = offsetofend(struct mptcp_pm_addr_entry, addr.id);
			break;
		case offsetof(struct mptcp_pm_addr_entry, addr.port):
			end = offsetofend(struct mptcp_pm_addr_entry, addr.port);
			break;
		default:
			bpf_log(log, "no write support to mptcp_pm_addr_entry at off %d\n",
				off);
			return -EACCES;
		}
	} else {
		bpf_log(log, "only access to mptcp sock or addr or entry is supported\n");
		return -EACCES;
	}

	if (off + size > end) {
		bpf_log(log, "access beyond %s at off %u size %u ended at %zu",
			id == mptcp_sock_id ? "mptcp_sock" :
			(id == mptcp_entry_id ? "mptcp_pm_addr_entry" : "mptcp_addr_info"),
			off, size, end);
		return -EACCES;
	}

	return NOT_INIT;
}

static const struct bpf_verifier_ops bpf_mptcp_pm_verifier_ops = {
	.get_func_proto		= bpf_mptcp_pm_get_func_proto,
	.is_valid_access	= bpf_tracing_btf_ctx_access,
	.btf_struct_access	= bpf_mptcp_pm_btf_struct_access,
};

static int bpf_mptcp_pm_reg(void *kdata, struct bpf_link *link)
{
	return mptcp_pm_register(kdata);
}

static void bpf_mptcp_pm_unreg(void *kdata, struct bpf_link *link)
{
	mptcp_pm_unregister(kdata);
}

static int bpf_mptcp_pm_check_member(const struct btf_type *t,
				     const struct btf_member *member,
				     const struct bpf_prog *prog)
{
	return 0;
}

static int bpf_mptcp_pm_init_member(const struct btf_type *t,
				    const struct btf_member *member,
				    void *kdata, const void *udata)
{
	const struct mptcp_pm_ops *upm;
	struct mptcp_pm_ops *pm;
	u32 moff;

	upm = (const struct mptcp_pm_ops *)udata;
	pm = (struct mptcp_pm_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct mptcp_pm_ops, name):
		if (bpf_obj_name_cpy(pm->name, upm->name,
				     sizeof(pm->name)) <= 0)
			return -EINVAL;
		return 1;
	}

	return 0;
}

static int bpf_mptcp_pm_init(struct btf *btf)
{
	s32 type_id;

	type_id = btf_find_by_name_kind(btf, "mptcp_sock",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	mptcp_sock_id = type_id;

	type_id = btf_find_by_name_kind(btf, "mptcp_pm_addr_entry",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	mptcp_entry_id = type_id;

	return 0;
}

static int bpf_mptcp_pm_validate(void *kdata)
{
	return mptcp_pm_validate(kdata);
}

static int __bpf_mptcp_pm_get_local_id(struct mptcp_sock *msk,
				       struct mptcp_pm_addr_entry *skc)
{
	return 0;
}

static bool __bpf_mptcp_pm_get_priority(struct mptcp_sock *msk,
					struct mptcp_addr_info *skc)
{
	return false;
}

static void __bpf_mptcp_pm_init(struct mptcp_sock *msk)
{
}

static void __bpf_mptcp_pm_release(struct mptcp_sock *msk)
{
}

static struct mptcp_pm_ops __bpf_mptcp_pm_ops = {
	.get_local_id		= __bpf_mptcp_pm_get_local_id,
	.get_priority		= __bpf_mptcp_pm_get_priority,
	.init			= __bpf_mptcp_pm_init,
	.release		= __bpf_mptcp_pm_release,
};

static struct bpf_struct_ops bpf_mptcp_pm_ops = {
	.verifier_ops	= &bpf_mptcp_pm_verifier_ops,
	.reg		= bpf_mptcp_pm_reg,
	.unreg		= bpf_mptcp_pm_unreg,
	.check_member	= bpf_mptcp_pm_check_member,
	.init_member	= bpf_mptcp_pm_init_member,
	.init		= bpf_mptcp_pm_init,
	.validate	= bpf_mptcp_pm_validate,
	.name		= "mptcp_pm_ops",
	.cfi_stubs	= &__bpf_mptcp_pm_ops,
};
#endif

struct mptcp_sock *bpf_mptcp_sock_from_subflow(struct sock *sk)
{
	if (sk && sk_fullsock(sk) && sk->sk_protocol == IPPROTO_TCP && sk_is_mptcp(sk))
		return mptcp_sk(mptcp_subflow_ctx(sk)->conn);

	return NULL;
}

BTF_SET8_START(bpf_mptcp_fmodret_ids)
BTF_ID_FLAGS(func, update_socket_protocol)
BTF_SET8_END(bpf_mptcp_fmodret_ids)

static const struct btf_kfunc_id_set bpf_mptcp_fmodret_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_mptcp_fmodret_ids,
};

__bpf_kfunc static void bpf_set_bit(unsigned long nr, unsigned long *addr__ign)
{
	__set_bit(nr, addr__ign);
}

__bpf_kfunc static __u8 bpf_find_next_zero_bit(const unsigned long *addr__ign,
					       unsigned long size__sz,
					       unsigned long offset)
{
	return find_next_zero_bit(addr__ign, size__sz, offset);
}

BTF_KFUNCS_START(bpf_mptcp_common_kfunc_ids)
BTF_ID_FLAGS(func, bpf_set_bit)
BTF_ID_FLAGS(func, bpf_find_next_zero_bit)
BTF_KFUNCS_END(bpf_mptcp_common_kfunc_ids)

static int bpf_mptcp_common_kfunc_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	if (!btf_id_set8_contains(&bpf_mptcp_common_kfunc_ids, kfunc_id))
		return 0;

	if (prog->type != BPF_PROG_TYPE_STRUCT_OPS)
		return -EACCES;

#ifdef CONFIG_BPF_JIT
	if (prog->aux->st_ops == &bpf_mptcp_pm_ops)
		return 0;
#endif
	return -EACCES;
}

static const struct btf_kfunc_id_set bpf_mptcp_common_kfunc_set = {
	.owner	= THIS_MODULE,
	.set	= &bpf_mptcp_common_kfunc_ids,
	.filter	= bpf_mptcp_common_kfunc_filter,
};

static int __init bpf_mptcp_kfunc_init(void)
{
	int ret;

	ret = register_btf_fmodret_id_set(&bpf_mptcp_fmodret_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					       &bpf_mptcp_common_kfunc_set);
#ifdef CONFIG_BPF_JIT
	ret = ret ?: register_bpf_struct_ops(&bpf_mptcp_pm_ops, mptcp_pm_ops);
#endif

	return ret;
}
late_initcall(bpf_mptcp_kfunc_init);
