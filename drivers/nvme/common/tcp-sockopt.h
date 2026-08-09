/* SPDX-License-Identifier: GPL-2.0 */
/*
 * NVMe TCP socket option helpers
 *
 * Shared between NVMe host and NVMe target TCP drivers.
 */
#ifndef NVME_TCP_SOCKOPT_H
#define NVME_TCP_SOCKOPT_H

#include <linux/net.h>

static inline void nvme_tcp_sock_no_linger(struct sock *sk)
{
	struct linger ling = { .l_onoff = 1, .l_linger = 0 };
	int ret;

	ret = do_sock_setsockopt(sk->sk_socket, true, SOL_SOCKET, SO_LINGER,
				 KERNEL_SOCKPTR(&ling), sizeof(ling));
	if (ret)
		pr_warn("failed to set SO_LINGER: %d\n", ret);
}

static inline void nvme_tcp_sock_set_priority(struct sock *sk, u32 priority)
{
	int ret;

	ret = do_sock_setsockopt(sk->sk_socket, true, SOL_SOCKET, SO_PRIORITY,
				 KERNEL_SOCKPTR(&priority), sizeof(priority));
	if (ret)
		pr_warn("failed to set SO_PRIORITY: %d\n", ret);
}

static inline void nvme_tcp_sock_set_reuseaddr(struct sock *sk)
{
	int val = SK_CAN_REUSE;
	int ret;

	ret = do_sock_setsockopt(sk->sk_socket, true, SOL_SOCKET,
				 SO_REUSEADDR, KERNEL_SOCKPTR(&val),
				 sizeof(val));
	if (ret)
		pr_warn("failed to set SO_REUSEADDR: %d\n", ret);
}

static inline void nvme_tcp_sock_set_nodelay(struct sock *sk)
{
	int val = 1;
	int ret;

	ret = do_sock_setsockopt(sk->sk_socket, true, SOL_TCP, TCP_NODELAY,
				 KERNEL_SOCKPTR(&val), sizeof(val));
	if (ret)
		pr_warn("failed to set TCP_NODELAY: %d\n", ret);
}

static inline void nvme_tcp_sock_set_tos(struct sock *sk, int tos)
{
	int ret;

	ret = do_sock_setsockopt(sk->sk_socket, true, SOL_IP, IP_TOS,
				 KERNEL_SOCKPTR(&tos), sizeof(tos));
	if (ret)
		pr_warn("failed to set IP_TOS: %d\n", ret);
}

#endif /* NVME_TCP_SOCKOPT_H */
