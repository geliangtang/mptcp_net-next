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
#include <linux/skmsg.h>
#include <net/bpf_sk_storage.h>
#include <net/strparser.h>
#include <net/inet_common.h>
#include "protocol.h"

#ifdef CONFIG_BPF_JIT
static struct bpf_struct_ops bpf_mptcp_sched_ops;
static u32 mptcp_sock_id,
	   mptcp_subflow_id;

/* MPTCP BPF packet scheduler */

static const struct bpf_func_proto *
bpf_mptcp_sched_get_func_proto(enum bpf_func_id func_id,
			       const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_sk_storage_get:
		return &bpf_sk_storage_get_proto;
	case BPF_FUNC_sk_storage_delete:
		return &bpf_sk_storage_delete_proto;
	case BPF_FUNC_skc_to_tcp6_sock:
		return &bpf_skc_to_tcp6_sock_proto;
	case BPF_FUNC_skc_to_tcp_sock:
		return &bpf_skc_to_tcp_sock_proto;
	default:
		return bpf_base_func_proto(func_id, prog);
	}
}

static int bpf_mptcp_sched_btf_struct_access(struct bpf_verifier_log *log,
					     const struct bpf_reg_state *reg,
					     int off, int size)
{
	u32 id = reg->btf_id;
	size_t end;

	if (id == mptcp_sock_id) {
		switch (off) {
		case offsetof(struct mptcp_sock, snd_burst):
			end = offsetofend(struct mptcp_sock, snd_burst);
			break;
		default:
			bpf_log(log, "no write support to mptcp_sock at off %d\n",
				off);
			return -EACCES;
		}
	} else if (id == mptcp_subflow_id) {
		switch (off) {
		case offsetof(struct mptcp_subflow_context, avg_pacing_rate):
			end = offsetofend(struct mptcp_subflow_context, avg_pacing_rate);
			break;
		default:
			bpf_log(log, "no write support to mptcp_subflow_context at off %d\n",
				off);
			return -EACCES;
		}
	} else {
		bpf_log(log, "only access to mptcp sock or subflow is supported\n");
		return -EACCES;
	}

	if (off + size > end) {
		bpf_log(log, "access beyond %s at off %u size %u ended at %zu",
			id == mptcp_sock_id ? "mptcp_sock" : "mptcp_subflow_context",
			off, size, end);
		return -EACCES;
	}

	return NOT_INIT;
}

static const struct bpf_verifier_ops bpf_mptcp_sched_verifier_ops = {
	.get_func_proto		= bpf_mptcp_sched_get_func_proto,
	.is_valid_access	= bpf_tracing_btf_ctx_access,
	.btf_struct_access	= bpf_mptcp_sched_btf_struct_access,
};

static int bpf_mptcp_sched_reg(void *kdata, struct bpf_link *link)
{
	return mptcp_register_scheduler(kdata);
}

static void bpf_mptcp_sched_unreg(void *kdata, struct bpf_link *link)
{
	mptcp_unregister_scheduler(kdata);
}

static int bpf_mptcp_sched_check_member(const struct btf_type *t,
					const struct btf_member *member,
					const struct bpf_prog *prog)
{
	return 0;
}

static int bpf_mptcp_sched_init_member(const struct btf_type *t,
				       const struct btf_member *member,
				       void *kdata, const void *udata)
{
	const struct mptcp_sched_ops *usched;
	struct mptcp_sched_ops *sched;
	u32 moff;

	usched = (const struct mptcp_sched_ops *)udata;
	sched = (struct mptcp_sched_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct mptcp_sched_ops, name):
		if (bpf_obj_name_cpy(sched->name, usched->name,
				     sizeof(sched->name)) <= 0)
			return -EINVAL;
		return 1;
	}

	return 0;
}

static int bpf_mptcp_sched_init(struct btf *btf)
{
	s32 type_id;

	type_id = btf_find_by_name_kind(btf, "mptcp_sock",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	mptcp_sock_id = type_id;

	type_id = btf_find_by_name_kind(btf, "mptcp_subflow_context",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	mptcp_subflow_id = type_id;

	return 0;
}

static int bpf_mptcp_sched_validate(void *kdata)
{
	return mptcp_validate_scheduler(kdata);
}

static int __bpf_mptcp_sched_get_send(struct mptcp_sock *msk)
{
	return 0;
}

static int __bpf_mptcp_sched_get_retrans(struct mptcp_sock *msk)
{
	return 0;
}

static void __bpf_mptcp_sched_init(struct mptcp_sock *msk)
{
}

static void __bpf_mptcp_sched_release(struct mptcp_sock *msk)
{
}

static struct mptcp_sched_ops __bpf_mptcp_sched_ops = {
	.get_send	= __bpf_mptcp_sched_get_send,
	.get_retrans	= __bpf_mptcp_sched_get_retrans,
	.init		= __bpf_mptcp_sched_init,
	.release	= __bpf_mptcp_sched_release,
};

static struct bpf_struct_ops bpf_mptcp_sched_ops = {
	.verifier_ops	= &bpf_mptcp_sched_verifier_ops,
	.reg		= bpf_mptcp_sched_reg,
	.unreg		= bpf_mptcp_sched_unreg,
	.check_member	= bpf_mptcp_sched_check_member,
	.init_member	= bpf_mptcp_sched_init_member,
	.init		= bpf_mptcp_sched_init,
	.validate	= bpf_mptcp_sched_validate,
	.name		= "mptcp_sched_ops",
	.cfi_stubs	= &__bpf_mptcp_sched_ops,
};

static struct proto *mptcpv6_prot_saved __read_mostly;
static DEFINE_SPINLOCK(mptcpv6_prot_lock);
static struct proto mptcp_bpf_prots[TCP_BPF_NUM_PROTS][TCP_BPF_NUM_CFGS];

static int mptcp_bpf_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			     int flags, int *addr_len)
{
	struct sk_psock *psock;
	int copied, ret;

	if (unlikely(flags & MSG_ERRQUEUE))
		return inet_recv_error(sk, msg, len, addr_len);

	if (!len)
		return 0;

	psock = sk_psock_get(sk);
	if (unlikely(!psock))
		return mptcp_recvmsg(sk, msg, len, flags, addr_len);
	if (!skb_queue_empty(&sk->sk_receive_queue) &&
	    sk_psock_queue_empty(psock)) {
		sk_psock_put(sk, psock);
		return mptcp_recvmsg(sk, msg, len, flags, addr_len);
	}
	lock_sock(sk);
msg_bytes_ready:
	copied = sk_msg_recvmsg(sk, psock, msg, len, flags);
	if (!copied) {
		long timeo;
		int data;

		timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
		data = tcp_msg_wait_data(sk, psock, timeo);
		if (data < 0) {
			ret = data;
			goto unlock;
		}
		if (data) {
			if (!sk_psock_queue_empty(psock))
				goto msg_bytes_ready;
			release_sock(sk);
			sk_psock_put(sk, psock);
			return mptcp_recvmsg(sk, msg, len, flags, addr_len);
		}
		copied = -EAGAIN;
	}
	ret = copied;

unlock:
	release_sock(sk);
	sk_psock_put(sk, psock);
	return ret;
}

static int mptcp_bpf_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct sk_msg tmp, *msg_tx = NULL;
	int copied = 0, err = 0, ret = 0;
	struct sk_psock *psock;
	long timeo;
	int flags;

	/* Don't let internal flags through */
	flags = (msg->msg_flags & ~MSG_SENDPAGE_DECRYPTED);
	flags |= MSG_NO_SHARED_FRAGS;

	psock = sk_psock_get(sk);
	if (unlikely(!psock))
		return mptcp_sendmsg(sk, msg, size);

	lock_sock(sk);
	timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	while (msg_data_left(msg)) {
		bool enospc = false;
		u32 copy, osize;

		if (sk->sk_err) {
			err = -sk->sk_err;
			goto out_err;
		}

		copy = msg_data_left(msg);
		if (!sk_stream_memory_free(sk))
			goto wait_for_sndbuf;
		if (psock->cork) {
			msg_tx = psock->cork;
		} else {
			msg_tx = &tmp;
			sk_msg_init(msg_tx);
		}

		osize = msg_tx->sg.size;
		err = sk_msg_alloc(sk, msg_tx, msg_tx->sg.size + copy, msg_tx->sg.end - 1);
		if (err) {
			if (err != -ENOSPC)
				goto wait_for_memory;
			enospc = true;
			copy = msg_tx->sg.size - osize;
		}

		ret = sk_msg_memcopy_from_iter(sk, &msg->msg_iter, msg_tx,
					       copy);
		if (ret < 0) {
			sk_msg_trim(sk, msg_tx, osize);
			goto out_err;
		}

		copied += ret;
		if (psock->cork_bytes) {
			if (size > psock->cork_bytes)
				psock->cork_bytes = 0;
			else
				psock->cork_bytes -= size;
			if (psock->cork_bytes && !enospc)
				goto out_err;
			/* All cork bytes are accounted, rerun the prog. */
			psock->eval = __SK_NONE;
			psock->cork_bytes = 0;
		}

		err = tcp_bpf_send_verdict(sk, psock, msg_tx, &copied, flags);
		if (unlikely(err < 0))
			goto out_err;
		continue;
wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
		err = sk_stream_wait_memory(sk, &timeo);
		if (err) {
			if (msg_tx && msg_tx != psock->cork)
				sk_msg_free(sk, msg_tx);
			goto out_err;
		}
	}
out_err:
	if (err < 0)
		err = sk_stream_error(sk, msg->msg_flags, err);
	release_sock(sk);
	sk_psock_put(sk, psock);
	return copied > 0 ? copied : err;
}

static bool is_next_msg_fin(struct sk_psock *psock)
{
	struct scatterlist *sge;
	struct sk_msg *msg_rx;
	int i;

	msg_rx = sk_psock_peek_msg(psock);
	i = msg_rx->sg.start;
	sge = sk_msg_elem(msg_rx, i);
	if (!sge->length) {
		struct sk_buff *skb = msg_rx->skb;

		if (skb && TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
			return true;
	}
	return false;
}

static int mptcp_bpf_recvmsg_parser(struct sock *sk,
				    struct msghdr *msg,
				    size_t len,
				    int flags,
				    int *addr_len)
{
	//int peek = flags & MSG_PEEK;
	struct sk_psock *psock;
	struct mptcp_sock *msk;
	//struct tcp_sock *tcp;
	int copied = 0;
	u32 seq;

	if (unlikely(flags & MSG_ERRQUEUE))
		return inet_recv_error(sk, msg, len, addr_len);

	if (!len)
		return 0;

	psock = sk_psock_get(sk);
	if (unlikely(!psock))
		return mptcp_recvmsg(sk, msg, len, flags, addr_len);

	lock_sock(sk);
	//tcp = tcp_sk(sk);
	msk = mptcp_sk(sk);
	//seq = tcp->copied_seq;
	/* We may have received data on the sk_receive_queue pre-accept and
	 * then we can not use read_skb in this context because we haven't
	 * assigned a sk_socket yet so have no link to the ops. The work-around
	 * is to check the sk_receive_queue and in these cases read skbs off
	 * queue again. The read_skb hook is not running at this point because
	 * of lock_sock so we avoid having multiple runners in read_skb.
	 */
	if (unlikely(!skb_queue_empty(&sk->sk_receive_queue))) {
		tcp_data_ready(sk);
		/* This handles the ENOMEM errors if we both receive data
		 * pre accept and are already under memory pressure. At least
		 * let user know to retry.
		 */
		if (unlikely(!skb_queue_empty(&sk->sk_receive_queue))) {
			copied = -EAGAIN;
			goto out;
		}
	}

msg_bytes_ready:
	copied = sk_msg_recvmsg(sk, psock, msg, len, flags);
	/* The typical case for EFAULT is the socket was gracefully
	 * shutdown with a FIN pkt. So check here the other case is
	 * some error on copy_page_to_iter which would be unexpected.
	 * On fin return correct return code to zero.
	 */
	if (copied == -EFAULT) {
		bool is_fin = is_next_msg_fin(psock);

		if (is_fin) {
			copied = 0;
			seq++;
			goto out;
		}
	}
	seq += copied;
	if (!copied) {
		long timeo;
		int data;
		int err;

		if (sock_flag(sk, SOCK_DONE))
			goto out;

		if (sk->sk_err) {
			copied = sock_error(sk);
			goto out;
		}

		timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);

		err = tcp_recv_should_stop(sk, timeo);
		if (err < 0) {
			if (err != -ESHUTDOWN)
				copied = err;
			goto out;
		}

		data = tcp_msg_wait_data(sk, psock, timeo);
		if (data < 0) {
			copied = data;
			goto unlock;
		}
		if (data && !sk_psock_queue_empty(psock))
			goto msg_bytes_ready;
		copied = -EAGAIN;
	}
out:
	//if (!peek)
	//	WRITE_ONCE(tcp->copied_seq, seq);
	mptcp_rcv_space_adjust(msk, copied);
	if (copied > 0)
		__mptcp_cleanup_rbuf(msk, copied, false);

unlock:
	release_sock(sk);
	sk_psock_put(sk, psock);
	return copied;
}

static void mptcp_bpf_rebuild_protos(struct proto prot[TCP_BPF_NUM_CFGS],
				     struct proto *base)
{
	prot[TCP_BPF_BASE]			= *base;
	prot[TCP_BPF_BASE].destroy		= sock_map_destroy;
	prot[TCP_BPF_BASE].close		= sock_map_close;
	prot[TCP_BPF_BASE].recvmsg		= mptcp_bpf_recvmsg;
	prot[TCP_BPF_BASE].sock_is_readable	= sk_msg_is_readable;

	prot[TCP_BPF_TX]			= prot[TCP_BPF_BASE];
	prot[TCP_BPF_TX].sendmsg		= mptcp_bpf_sendmsg;

	prot[TCP_BPF_RX]			= prot[TCP_BPF_BASE];
	prot[TCP_BPF_RX].recvmsg		= mptcp_bpf_recvmsg_parser;

	prot[TCP_BPF_TXRX]			= prot[TCP_BPF_TX];
	prot[TCP_BPF_TXRX].recvmsg		= mptcp_bpf_recvmsg_parser;
}

static void mptcp_bpf_check_v6_needs_rebuild(struct proto *ops)
{
	if (unlikely(ops != smp_load_acquire(&mptcpv6_prot_saved))) {
		spin_lock_bh(&mptcpv6_prot_lock);
		if (likely(ops != mptcpv6_prot_saved)) {
			mptcp_bpf_rebuild_protos(mptcp_bpf_prots[TCP_BPF_IPV6], ops);
			smp_store_release(&mptcpv6_prot_saved, ops);
		}
		spin_unlock_bh(&mptcpv6_prot_lock);
	}
}

static int __init mptcp_bpf_v4_build_proto(void)
{
	mptcp_bpf_rebuild_protos(mptcp_bpf_prots[TCP_BPF_IPV4], &mptcp_prot);
	return 0;
}
late_initcall(mptcp_bpf_v4_build_proto);

static int mptcp_bpf_assert_proto_ops(struct proto *ops)
{
	/* In order to avoid retpoline, we make assumptions when we call
	 * into ops if e.g. a psock is not present. Make sure they are
	 * indeed valid assumptions.
	 */
	return ops->recvmsg  == mptcp_recvmsg &&
	       ops->sendmsg  == mptcp_sendmsg ? 0 : -ENOTSUPP;
}

#if IS_ENABLED(CONFIG_BPF_STREAM_PARSER)
int mptcp_bpf_strp_read_sock(struct strparser *strp, read_descriptor_t *desc,
			     sk_read_actor_t recv_actor)
{
	struct sock *sk = strp->sk;
	struct sk_psock *psock;
	struct mptcp_sock *msk;
	//struct tcp_sock *tp;
	int copied = 0;

	msk = mptcp_sk(sk);
	//tp = tcp_sk(sk);
	rcu_read_lock();
	psock = sk_psock(sk);
	if (WARN_ON_ONCE(!psock)) {
		desc->error = -EINVAL;
		goto out;
	}

	psock->ingress_bytes = 0;
	pr_info("%s call mptcp_read_sock_noack sk_protocol=%d\n", __func__, sk->sk_protocol);
	copied = mptcp_read_sock_noack(sk, desc, recv_actor);
	if (copied < 0)
		goto out;
	/* recv_actor may redirect skb to another socket (SK_REDIRECT) or
	 * just put skb into ingress queue of current socket (SK_PASS).
	 * For SK_REDIRECT, we need to ack the frame immediately but for
	 * SK_PASS, we want to delay the ack until tcp_bpf_recvmsg_parser().
	 */
	//tp->copied_seq = psock->copied_seq - psock->ingress_bytes;
	mptcp_rcv_space_adjust(msk, copied);
	if (copied > 0)
		__mptcp_cleanup_rbuf(msk, copied - psock->ingress_bytes, false);
out:
	rcu_read_unlock();
	return copied;
}
#endif /* CONFIG_BPF_STREAM_PARSER */

int mptcp_bpf_update_proto(struct sock *sk, struct sk_psock *psock, bool restore)
{
	int family = sk->sk_family == AF_INET6 ? TCP_BPF_IPV6 : TCP_BPF_IPV4;
	int config = psock->progs.msg_parser   ? TCP_BPF_TX   : TCP_BPF_BASE;

	if (psock->progs.stream_verdict || psock->progs.skb_verdict) {
		config = (config == TCP_BPF_TX) ? TCP_BPF_TXRX : TCP_BPF_RX;
	}

	if (restore) {
		if (inet_csk_has_ulp(sk)) {
			/* TLS does not have an unhash proto in SW cases,
			 * but we need to ensure we stop using the sock_map
			 * unhash routine because the associated psock is being
			 * removed. So use the original unhash handler.
			 */
			WRITE_ONCE(sk->sk_prot->unhash, psock->saved_unhash);
			tcp_update_ulp(sk, psock->sk_proto, psock->saved_write_space);
		} else {
			sk->sk_write_space = psock->saved_write_space;
			/* Pairs with lockless read in sk_clone_lock() */
			sock_replace_proto(sk, psock->sk_proto);
		}
		return 0;
	}

	if (sk->sk_family == AF_INET6) {
		if (mptcp_bpf_assert_proto_ops(psock->sk_proto))
			return -EINVAL;

		mptcp_bpf_check_v6_needs_rebuild(psock->sk_proto);
	}

	/* Pairs with lockless read in sk_clone_lock() */
	sock_replace_proto(sk, &mptcp_bpf_prots[family][config]);
	return 0;
}
EXPORT_SYMBOL_GPL(mptcp_bpf_update_proto);

#endif /* CONFIG_BPF_JIT */

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

struct bpf_iter_mptcp_subflow {
	__u64 __opaque[2];
} __aligned(8);

struct bpf_iter_mptcp_subflow_kern {
	struct mptcp_sock *msk;
	struct list_head *pos;
} __aligned(8);

__bpf_kfunc_start_defs();

__bpf_kfunc static struct mptcp_subflow_context *
bpf_mptcp_subflow_ctx(const struct sock *sk__ign)
{
	const struct sock *sk = sk__ign;

	if (sk && sk_fullsock(sk) &&
	    sk->sk_protocol == IPPROTO_TCP && sk_is_mptcp(sk))
		return mptcp_subflow_ctx(sk);

	return NULL;
}

__bpf_kfunc static struct sock *
bpf_mptcp_subflow_tcp_sock(const struct mptcp_subflow_context *subflow)
{
	if (!subflow)
		return NULL;

	return mptcp_subflow_tcp_sock(subflow);
}

__bpf_kfunc static int
bpf_iter_mptcp_subflow_new(struct bpf_iter_mptcp_subflow *it,
			   struct sock *sk)
{
	struct bpf_iter_mptcp_subflow_kern *kit = (void *)it;
	struct mptcp_sock *msk;

	BUILD_BUG_ON(sizeof(struct bpf_iter_mptcp_subflow_kern) >
		     sizeof(struct bpf_iter_mptcp_subflow));
	BUILD_BUG_ON(__alignof__(struct bpf_iter_mptcp_subflow_kern) !=
		     __alignof__(struct bpf_iter_mptcp_subflow));

	if (unlikely(!sk || !sk_fullsock(sk)))
		return -EINVAL;

	if (sk->sk_protocol != IPPROTO_MPTCP)
		return -EINVAL;

	msk = mptcp_sk(sk);

	msk_owned_by_me(msk);

	kit->msk = msk;
	kit->pos = &msk->conn_list;
	return 0;
}

__bpf_kfunc static struct mptcp_subflow_context *
bpf_iter_mptcp_subflow_next(struct bpf_iter_mptcp_subflow *it)
{
	struct bpf_iter_mptcp_subflow_kern *kit = (void *)it;

	if (!kit->msk || list_is_last(kit->pos, &kit->msk->conn_list))
		return NULL;

	kit->pos = kit->pos->next;
	return list_entry(kit->pos, struct mptcp_subflow_context, node);
}

__bpf_kfunc static void
bpf_iter_mptcp_subflow_destroy(struct bpf_iter_mptcp_subflow *it)
{
}

__bpf_kfunc static bool bpf_mptcp_subflow_queues_empty(struct sock *sk)
{
	return tcp_rtx_queue_empty(sk);
}

__bpf_kfunc static bool bpf_sk_stream_memory_free(const struct sock *sk__ign)
{
	const struct sock *sk = sk__ign;

	if (sk && sk_fullsock(sk) &&
	    sk->sk_protocol == IPPROTO_TCP && sk_is_mptcp(sk))
		return sk_stream_memory_free(sk);

	return NULL;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_mptcp_iter_kfunc_ids)
BTF_ID_FLAGS(func, bpf_iter_mptcp_subflow_new, KF_ITER_NEW | KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_iter_mptcp_subflow_next, KF_ITER_NEXT | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_mptcp_subflow_destroy, KF_ITER_DESTROY)
BTF_KFUNCS_END(bpf_mptcp_iter_kfunc_ids)

static const struct btf_kfunc_id_set bpf_mptcp_iter_kfunc_set = {
	.owner	= THIS_MODULE,
	.set	= &bpf_mptcp_iter_kfunc_ids,
};

BTF_KFUNCS_START(bpf_mptcp_common_kfunc_ids)
BTF_ID_FLAGS(func, bpf_mptcp_subflow_ctx, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_mptcp_subflow_tcp_sock, KF_RET_NULL)
BTF_ID_FLAGS(func, mptcp_subflow_set_scheduled)
BTF_ID_FLAGS(func, mptcp_subflow_active)
BTF_ID_FLAGS(func, mptcp_set_timeout)
BTF_ID_FLAGS(func, mptcp_wnd_end)
BTF_ID_FLAGS(func, bpf_sk_stream_memory_free, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_mptcp_subflow_queues_empty)
BTF_ID_FLAGS(func, mptcp_pm_subflow_chk_stale, KF_SLEEPABLE)
BTF_KFUNCS_END(bpf_mptcp_common_kfunc_ids)

static int bpf_mptcp_common_kfunc_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	if (!btf_id_set8_contains(&bpf_mptcp_common_kfunc_ids, kfunc_id))
		return 0;

	if (prog->type != BPF_PROG_TYPE_STRUCT_OPS)
		return -EACCES;

#ifdef CONFIG_BPF_JIT
	if (prog->aux->st_ops == &bpf_mptcp_sched_ops)
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
					       &bpf_mptcp_iter_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					       &bpf_mptcp_common_kfunc_set);
#ifdef CONFIG_BPF_JIT
	ret = ret ?: register_bpf_struct_ops(&bpf_mptcp_sched_ops, mptcp_sched_ops);
#endif

	return ret;
}
late_initcall(bpf_mptcp_kfunc_init);
