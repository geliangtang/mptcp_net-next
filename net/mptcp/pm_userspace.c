// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2022, Intel Corporation.
 */

#include "protocol.h"
#include "mib.h"
#include "mptcp_pm_gen.h"

#define mptcp_for_each_userspace_pm_addr(__msk, __entry)			\
	list_for_each_entry(__entry,						\
			    &((__msk)->pm.userspace_pm_local_addr_list), list)

void mptcp_userspace_pm_free_local_addr_list(struct mptcp_sock *msk)
{
	struct mptcp_pm_addr_entry *entry, *tmp;
	struct sock *sk = (struct sock *)msk;
	LIST_HEAD(free_list);

	spin_lock_bh(&msk->pm.lock);
	list_splice_init(&msk->pm.userspace_pm_local_addr_list, &free_list);
	spin_unlock_bh(&msk->pm.lock);

	list_for_each_entry_safe(entry, tmp, &free_list, list) {
		sock_kfree_s(sk, entry, sizeof(*entry));
	}
}

__bpf_kfunc_start_defs();

__bpf_kfunc
static struct mptcp_pm_addr_entry *
mptcp_userspace_pm_lookup_addr(struct mptcp_sock *msk,
			       const struct mptcp_addr_info *addr)
{
	struct mptcp_pm_addr_entry *entry;

	mptcp_for_each_userspace_pm_addr(msk, entry) {
		if (mptcp_addresses_equal(&entry->addr, addr, false))
			return entry;
	}
	return NULL;
}

__bpf_kfunc
static int mptcp_userspace_pm_append_new_local_addr(struct mptcp_sock *msk,
						    struct mptcp_pm_addr_entry *entry,
						    bool needs_id)
{
	DECLARE_BITMAP(id_bitmap, MPTCP_PM_MAX_ADDR_ID + 1);
	struct sock *sk = (struct sock *)msk;
	struct mptcp_pm_addr_entry *e;
	bool addr_match = false;
	bool id_match = false;
	int ret = -EINVAL;

	bitmap_zero(id_bitmap, MPTCP_PM_MAX_ADDR_ID + 1);

	spin_lock_bh(&msk->pm.lock);
	mptcp_for_each_userspace_pm_addr(msk, e) {
		addr_match = mptcp_addresses_equal(&e->addr, &entry->addr, true);
		if (addr_match && entry->addr.id == 0 && needs_id)
			entry->addr.id = e->addr.id;
		id_match = (e->addr.id == entry->addr.id);
		if (addr_match || id_match)
			break;
		__set_bit(e->addr.id, id_bitmap);
	}

	if (!addr_match && !id_match) {
		/* Memory for the entry is allocated from the
		 * sock option buffer.
		 */
		e = sock_kmemdup(sk, entry, sizeof(*entry), GFP_ATOMIC);
		if (!e) {
			ret = -ENOMEM;
			goto append_err;
		}

		if (!e->addr.id && needs_id)
			e->addr.id = find_next_zero_bit(id_bitmap,
							MPTCP_PM_MAX_ADDR_ID + 1,
							1);
		list_add_tail_rcu(&e->list, &msk->pm.userspace_pm_local_addr_list);
		msk->pm.local_addr_used++;
		ret = e->addr.id;
	} else if (addr_match && id_match) {
		ret = entry->addr.id;
	}

append_err:
	spin_unlock_bh(&msk->pm.lock);
	return ret;
}

__bpf_kfunc_end_defs();

static struct mptcp_pm_addr_entry *
mptcp_userspace_pm_lookup_addr_by_id(struct mptcp_sock *msk, unsigned int id)
{
	struct mptcp_pm_addr_entry *entry;

	mptcp_for_each_userspace_pm_addr(msk, entry) {
		if (entry->addr.id == id)
			return entry;
	}
	return NULL;
}

static int mptcp_pm_userspace_get_local_id(struct mptcp_sock *msk,
					   struct mptcp_pm_addr_entry *skc)
{
	__be16 msk_sport =  ((struct inet_sock *)
			     inet_sk((struct sock *)msk))->inet_sport;
	struct mptcp_pm_addr_entry *entry;

	spin_lock_bh(&msk->pm.lock);
	entry = mptcp_userspace_pm_lookup_addr(msk, &skc->addr);
	spin_unlock_bh(&msk->pm.lock);
	if (entry)
		return entry->addr.id;

	if (skc->addr.port == msk_sport)
		skc->addr.port = 0;

	return mptcp_userspace_pm_append_new_local_addr(msk, skc, true);
}

static bool mptcp_pm_userspace_get_priority(struct mptcp_sock *msk,
					    struct mptcp_addr_info *skc)
{
	struct mptcp_pm_addr_entry *entry;
	bool backup;

	spin_lock_bh(&msk->pm.lock);
	entry = mptcp_userspace_pm_lookup_addr(msk, skc);
	backup = entry && !!(entry->flags & MPTCP_PM_ADDR_FLAG_BACKUP);
	spin_unlock_bh(&msk->pm.lock);

	return backup;
}

static struct mptcp_sock *mptcp_userspace_pm_get_sock(const struct genl_info *info)
{
	struct mptcp_sock *msk;
	struct nlattr *token;

	if (GENL_REQ_ATTR_CHECK(info, MPTCP_PM_ATTR_TOKEN))
		return NULL;

	token = info->attrs[MPTCP_PM_ATTR_TOKEN];
	msk = mptcp_token_get_sock(genl_info_net(info), nla_get_u32(token));
	if (!msk) {
		NL_SET_ERR_MSG_ATTR(info->extack, token, "invalid token");
		return NULL;
	}

	if (!mptcp_pm_is_userspace(msk)) {
		NL_SET_ERR_MSG_ATTR(info->extack, token,
				    "userspace PM not selected");
		sock_put((struct sock *)msk);
		return NULL;
	}

	return msk;
}

int mptcp_pm_nl_announce_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct mptcp_pm_addr_entry addr_val;
	struct mptcp_sock *msk;
	struct nlattr *addr;
	int err = -EINVAL;
	struct sock *sk;

	if (GENL_REQ_ATTR_CHECK(info, MPTCP_PM_ATTR_ADDR))
		return err;

	msk = mptcp_userspace_pm_get_sock(info);
	if (!msk)
		return err;

	sk = (struct sock *)msk;

	addr = info->attrs[MPTCP_PM_ATTR_ADDR];
	err = mptcp_pm_parse_entry(addr, info, true, &addr_val);
	if (err < 0)
		goto announce_err;

	if (addr_val.addr.id == 0) {
		NL_SET_ERR_MSG_ATTR(info->extack, addr, "invalid addr id");
		err = -EINVAL;
		goto announce_err;
	}

	if (!(addr_val.flags & MPTCP_PM_ADDR_FLAG_SIGNAL)) {
		NL_SET_ERR_MSG_ATTR(info->extack, addr, "invalid addr flags");
		err = -EINVAL;
		goto announce_err;
	}

	lock_sock(sk);
	if (msk->pm.ops->address_announce)
		err = msk->pm.ops->address_announce(msk, &addr_val);
	release_sock(sk);
	if (err)
		NL_SET_ERR_MSG_ATTR(info->extack, addr,
				    "did not match address and id");

 announce_err:
	sock_put(sk);
	return err;
}

static int mptcp_userspace_pm_remove_id_zero_address(struct mptcp_sock *msk)
{
	struct mptcp_rm_list list = { .nr = 0 };
	struct mptcp_subflow_context *subflow;
	bool has_id_0 = false;

	mptcp_for_each_subflow(msk, subflow) {
		if (READ_ONCE(subflow->local_id) == 0) {
			has_id_0 = true;
			break;
		}
	}
	if (!has_id_0)
		return -EINVAL;

	list.ids[list.nr++] = 0;

	spin_lock_bh(&msk->pm.lock);
	mptcp_pm_remove_addr(msk, &list);
	spin_unlock_bh(&msk->pm.lock);

	return 0;
}

void mptcp_pm_remove_addr_entry(struct mptcp_sock *msk,
				struct mptcp_pm_addr_entry *entry__ign)
{
	struct mptcp_pm_addr_entry *entry = entry__ign;
	struct mptcp_rm_list alist = { .nr = 0 };
	int anno_nr = 0;

	/* only delete if either announced or matching a subflow */
	if (mptcp_remove_anno_list_by_saddr(msk, &entry->addr))
		anno_nr++;
	else if (!mptcp_lookup_subflow_by_saddr(&msk->conn_list, &entry->addr))
		return;

	alist.ids[alist.nr++] = entry->addr.id;

	spin_lock_bh(&msk->pm.lock);
	msk->pm.add_addr_signaled -= anno_nr;
	mptcp_pm_remove_addr(msk, &alist);
	spin_unlock_bh(&msk->pm.lock);
}

int mptcp_pm_nl_remove_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct mptcp_pm_addr_entry local;
	struct mptcp_sock *msk;
	struct nlattr *id;
	int err = -EINVAL;
	struct sock *sk;

	if (GENL_REQ_ATTR_CHECK(info, MPTCP_PM_ATTR_LOC_ID))
		return err;

	id = info->attrs[MPTCP_PM_ATTR_LOC_ID];
	local.addr.id = nla_get_u8(id);

	msk = mptcp_userspace_pm_get_sock(info);
	if (!msk)
		return err;

	sk = (struct sock *)msk;

	lock_sock(sk);
	if (msk->pm.ops->address_remove)
		err = msk->pm.ops->address_remove(msk, &local);
	release_sock(sk);
	if (err)
		NL_SET_ERR_MSG_ATTR_FMT(info->extack, id,
					"address with id %u not found",
					local.addr.id);

	sock_put(sk);
	return err;
}

int mptcp_pm_nl_subflow_create_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct mptcp_pm_addr_entry entry = { 0 };
	struct mptcp_addr_info addr_r;
	struct nlattr *raddr, *laddr;
	struct mptcp_sock *msk;
	int err = -EINVAL;
	struct sock *sk;

	if (GENL_REQ_ATTR_CHECK(info, MPTCP_PM_ATTR_ADDR) ||
	    GENL_REQ_ATTR_CHECK(info, MPTCP_PM_ATTR_ADDR_REMOTE))
		return err;

	msk = mptcp_userspace_pm_get_sock(info);
	if (!msk)
		return err;

	sk = (struct sock *)msk;

	laddr = info->attrs[MPTCP_PM_ATTR_ADDR];
	err = mptcp_pm_parse_entry(laddr, info, true, &entry);
	if (err < 0)
		goto create_err;

	if (entry.flags & MPTCP_PM_ADDR_FLAG_SIGNAL) {
		NL_SET_ERR_MSG_ATTR(info->extack, laddr, "invalid addr flags");
		err = -EINVAL;
		goto create_err;
	}
	entry.flags |= MPTCP_PM_ADDR_FLAG_SUBFLOW;

	raddr = info->attrs[MPTCP_PM_ATTR_ADDR_REMOTE];
	err = mptcp_pm_parse_addr(raddr, info, &addr_r);
	if (err < 0)
		goto create_err;

	if (!mptcp_pm_addr_families_match(sk, &entry.addr, &addr_r)) {
		GENL_SET_ERR_MSG(info, "families mismatch");
		err = -EINVAL;
		goto create_err;
	}

	lock_sock(sk);
	if (msk->pm.ops->subflow_create)
		err = msk->pm.ops->subflow_create(msk, &entry, &addr_r);
	release_sock(sk);

	if (err) {
		GENL_SET_ERR_MSG_FMT(info, "connect error: %d", err);
		goto create_err;
	}

	spin_lock_bh(&msk->pm.lock);
	msk->pm.subflows++;
	spin_unlock_bh(&msk->pm.lock);

 create_err:
	sock_put(sk);
	return err;
}

static struct sock *mptcp_nl_find_ssk(struct mptcp_sock *msk,
				      const struct mptcp_addr_info *local,
				      const struct mptcp_addr_info *remote)
{
	struct mptcp_subflow_context *subflow;

	if (local->family != remote->family)
		return NULL;

	mptcp_for_each_subflow(msk, subflow) {
		const struct inet_sock *issk;
		struct sock *ssk;

		ssk = mptcp_subflow_tcp_sock(subflow);

		if (local->family != ssk->sk_family)
			continue;

		issk = inet_sk(ssk);

		switch (ssk->sk_family) {
		case AF_INET:
			if (issk->inet_saddr != local->addr.s_addr ||
			    issk->inet_daddr != remote->addr.s_addr)
				continue;
			break;
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
		case AF_INET6: {
			if (!ipv6_addr_equal(&local->addr6, &issk->pinet6->saddr) ||
			    !ipv6_addr_equal(&remote->addr6, &ssk->sk_v6_daddr))
				continue;
			break;
		}
#endif
		default:
			continue;
		}

		if (issk->inet_sport == local->port &&
		    issk->inet_dport == remote->port)
			return ssk;
	}

	return NULL;
}

int mptcp_pm_nl_subflow_destroy_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct mptcp_pm_addr_entry addr_l;
	struct mptcp_addr_info addr_r;
	struct nlattr *raddr, *laddr;
	struct mptcp_sock *msk;
	int err = -EINVAL;
	struct sock *sk;

	if (GENL_REQ_ATTR_CHECK(info, MPTCP_PM_ATTR_ADDR) ||
	    GENL_REQ_ATTR_CHECK(info, MPTCP_PM_ATTR_ADDR_REMOTE))
		return err;

	msk = mptcp_userspace_pm_get_sock(info);
	if (!msk)
		return err;

	sk = (struct sock *)msk;

	laddr = info->attrs[MPTCP_PM_ATTR_ADDR];
	err = mptcp_pm_parse_entry(laddr, info, true, &addr_l);
	if (err < 0)
		goto destroy_err;

	raddr = info->attrs[MPTCP_PM_ATTR_ADDR_REMOTE];
	err = mptcp_pm_parse_addr(raddr, info, &addr_r);
	if (err < 0)
		goto destroy_err;

#if IS_ENABLED(CONFIG_MPTCP_IPV6)
	if (addr_l.addr.family == AF_INET && ipv6_addr_v4mapped(&addr_r.addr6)) {
		ipv6_addr_set_v4mapped(addr_l.addr.addr.s_addr, &addr_l.addr.addr6);
		addr_l.addr.family = AF_INET6;
	}
	if (addr_r.family == AF_INET && ipv6_addr_v4mapped(&addr_l.addr.addr6)) {
		ipv6_addr_set_v4mapped(addr_r.addr.s_addr, &addr_r.addr6);
		addr_r.family = AF_INET6;
	}
#endif
	if (addr_l.addr.family != addr_r.family) {
		GENL_SET_ERR_MSG(info, "address families do not match");
		err = -EINVAL;
		goto destroy_err;
	}

	if (!addr_l.addr.port) {
		NL_SET_ERR_MSG_ATTR(info->extack, laddr, "missing local port");
		err = -EINVAL;
		goto destroy_err;
	}

	if (!addr_r.port) {
		NL_SET_ERR_MSG_ATTR(info->extack, raddr, "missing remote port");
		err = -EINVAL;
		goto destroy_err;
	}

	lock_sock(sk);
	if (msk->pm.ops->subflow_destroy)
		err = msk->pm.ops->subflow_destroy(msk, &addr_l, &addr_r);
	release_sock(sk);
	if (err)
		GENL_SET_ERR_MSG(info, "subflow not found");

destroy_err:
	sock_put(sk);
	return err;
}

int mptcp_userspace_pm_set_flags(struct mptcp_pm_addr_entry *local,
				 struct mptcp_pm_addr_entry *remote,
				 struct genl_info *info)
{
	struct mptcp_sock *msk;
	int ret = -EINVAL;
	struct sock *sk;

	msk = mptcp_userspace_pm_get_sock(info);
	if (!msk)
		return ret;

	sk = (struct sock *)msk;

	lock_sock(sk);
	if (msk->pm.ops->set_priority)
	      ret = msk->pm.ops->set_priority(msk, local, remote);
	release_sock(sk);

	/* mptcp_pm_mp_prio_send_ack() only fails in one case */
	if (ret < 0)
		GENL_SET_ERR_MSG(info, "subflow not found");

	sock_put(sk);
	return ret;
}

int mptcp_userspace_pm_dump_addr(struct sk_buff *msg,
				 struct netlink_callback *cb)
{
	struct id_bitmap {
		DECLARE_BITMAP(map, MPTCP_PM_MAX_ADDR_ID + 1);
	} *bitmap;
	const struct genl_info *info = genl_info_dump(cb);
	struct mptcp_pm_addr_entry *entry;
	struct mptcp_sock *msk;
	int ret = -EINVAL;
	struct sock *sk;

	BUILD_BUG_ON(sizeof(struct id_bitmap) > sizeof(cb->ctx));

	bitmap = (struct id_bitmap *)cb->ctx;

	msk = mptcp_userspace_pm_get_sock(info);
	if (!msk)
		return ret;

	sk = (struct sock *)msk;

	lock_sock(sk);
	spin_lock_bh(&msk->pm.lock);
	mptcp_for_each_userspace_pm_addr(msk, entry) {
		if (test_bit(entry->addr.id, bitmap->map))
			continue;

		if (mptcp_pm_genl_fill_addr(msg, cb, entry) < 0)
			break;

		__set_bit(entry->addr.id, bitmap->map);
	}
	spin_unlock_bh(&msk->pm.lock);
	release_sock(sk);
	ret = msg->len;

	sock_put(sk);
	return ret;
}

int mptcp_userspace_pm_get_addr(u8 id, struct mptcp_pm_addr_entry *addr,
				struct genl_info *info)
{
	struct mptcp_pm_addr_entry *entry;
	struct mptcp_sock *msk;
	int ret = -EINVAL;
	struct sock *sk;

	msk = mptcp_userspace_pm_get_sock(info);
	if (!msk)
		return ret;

	sk = (struct sock *)msk;

	lock_sock(sk);
	spin_lock_bh(&msk->pm.lock);
	entry = mptcp_userspace_pm_lookup_addr_by_id(msk, id);
	if (entry) {
		*addr = *entry;
		ret = 0;
	}
	spin_unlock_bh(&msk->pm.lock);
	release_sock(sk);

	sock_put(sk);
	return ret;
}

static bool mptcp_pm_userspace_accept_new_subflow(struct mptcp_sock *msk,
						  bool allow)
{
	return mptcp_userspace_pm_active(msk);
}

static bool mptcp_pm_userspace_accept_new_address(struct mptcp_sock *msk,
						  const struct mptcp_addr_info *addr)
{
	return mptcp_userspace_pm_active(msk);
}

static int mptcp_pm_userspace_address_announce(struct mptcp_sock *msk,
					       struct mptcp_pm_addr_entry *local)
{
	int err;

	err = mptcp_userspace_pm_append_new_local_addr(msk, local, false);
	if (err < 0)
		return err;

	spin_lock_bh(&msk->pm.lock);

	if (mptcp_pm_alloc_anno_list(msk, &local->addr)) {
		msk->pm.add_addr_signaled++;
		mptcp_pm_announce_addr(msk, &local->addr, false);
		mptcp_pm_addr_send_ack(msk);
	}

	spin_unlock_bh(&msk->pm.lock);

	return 0;
}

static int mptcp_pm_userspace_address_remove(struct mptcp_sock *msk,
					     struct mptcp_pm_addr_entry *local)
{
	struct sock *sk = (struct sock *)msk;
	struct mptcp_pm_addr_entry *entry;
	u8 id = local->addr.id;

	if (id == 0)
		return mptcp_userspace_pm_remove_id_zero_address(msk);

	spin_lock_bh(&msk->pm.lock);
	entry = mptcp_userspace_pm_lookup_addr_by_id(msk, id);
	if (!entry) {
		spin_unlock_bh(&msk->pm.lock);
		return -EINVAL;
	}

	list_del_rcu(&entry->list);
	msk->pm.local_addr_used--;
	spin_unlock_bh(&msk->pm.lock);

	mptcp_pm_remove_addr_entry(msk, entry);

	/* Adjust sk_omem_alloc like sock_kfree_s() does, to match
	 * with allocation of this memory by sock_kmemdup()
	 */
	sock_krfree_s(sk, entry, sizeof(*entry));

	return 0;
}

static int mptcp_pm_userspace_subflow_create(struct mptcp_sock *msk,
					     struct mptcp_pm_addr_entry *entry,
					     struct mptcp_addr_info *remote)
{
	struct sock *sk = (struct sock *)msk;
	struct mptcp_pm_local local;
	int err;

	err = mptcp_userspace_pm_append_new_local_addr(msk, entry, false);
	if (err < 0)
		return err;

	local.addr = entry->addr;
	local.flags = entry->flags;
	local.ifindex = entry->ifindex;

	return __mptcp_subflow_connect(sk, &local, remote);
}

static int mptcp_pm_userspace_subflow_destroy(struct mptcp_sock *msk,
					      struct mptcp_pm_addr_entry *local,
					      struct mptcp_addr_info *remote)
{
	struct sock *ssk, *sk = (struct sock *)msk;

	ssk = mptcp_nl_find_ssk(msk, &local->addr, remote);
	if (!ssk)
		return -ESRCH;

	mptcp_subflow_shutdown(sk, ssk, RCV_SHUTDOWN | SEND_SHUTDOWN);
	mptcp_close_ssk(sk, ssk, mptcp_subflow_ctx(ssk));
	MPTCP_INC_STATS(sock_net(sk), MPTCP_MIB_RMSUBFLOW);

	return 0;
}

static int mptcp_pm_userspace_set_priority(struct mptcp_sock *msk,
					   struct mptcp_pm_addr_entry *local,
					   struct mptcp_pm_addr_entry *remote)
{
	struct mptcp_pm_addr_entry *entry;
	u8 bkup = 0;

	if (local->addr.family == AF_UNSPEC)
		return -EINVAL;

	if (local->flags & MPTCP_PM_ADDR_FLAG_BACKUP)
		bkup = 1;

	spin_lock_bh(&msk->pm.lock);
	entry = mptcp_userspace_pm_lookup_addr(msk, &local->addr);
	if (entry) {
		if (bkup)
			entry->flags |= MPTCP_PM_ADDR_FLAG_BACKUP;
		else
			entry->flags &= ~MPTCP_PM_ADDR_FLAG_BACKUP;
	}
	spin_unlock_bh(&msk->pm.lock);

	return mptcp_pm_mp_prio_send_ack(msk, &local->addr, &remote->addr, bkup);
}

static void mptcp_pm_userspace_release(struct mptcp_sock *msk)
{
	mptcp_userspace_pm_free_local_addr_list(msk);
}

static struct mptcp_pm_ops mptcp_pm_userspace = {
	.get_local_id		= mptcp_pm_userspace_get_local_id,
	.get_priority		= mptcp_pm_userspace_get_priority,
	.accept_new_subflow	= mptcp_pm_userspace_accept_new_subflow,
	.accept_new_address	= mptcp_pm_userspace_accept_new_address,
	.address_announce	= mptcp_pm_userspace_address_announce,
	.address_remove		= mptcp_pm_userspace_address_remove,
	.subflow_create		= mptcp_pm_userspace_subflow_create,
	.subflow_destroy	= mptcp_pm_userspace_subflow_destroy,
	.set_priority		= mptcp_pm_userspace_set_priority,
	.release		= mptcp_pm_userspace_release,
	.name			= "userspace",
	.owner			= THIS_MODULE,
};

void __init mptcp_pm_userspace_register(void)
{
	mptcp_pm_register(&mptcp_pm_userspace);
}
