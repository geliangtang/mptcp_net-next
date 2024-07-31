/*
 * $ gcc mptcp_eagain_reproducer.c
 * $ sudo ./a.out <times> <totol_size>
 * The default values are 100 times, 10 M totol size.
 * 
 * Normal output:
 *
 * 100
 * create_netns:PASS:ip netns add mptcp_ns 0 nsec
 * create_netns:PASS:ip -net mptcp_ns link set dev lo up 0 nsec
 * test_default:PASS:create_netns 0 nsec
 * endpoint_init:PASS:ip -net mptcp_ns link add veth1 type veth peer name veth2 0 nsec
 * endpoint_init:PASS:ip -net mptcp_ns addr add 10.0.1.1/24 dev veth1 0 nsec
 * endpoint_init:PASS:ip -net mptcp_ns link set dev veth1 up 0 nsec
 * endpoint_init:PASS:ip -net mptcp_ns addr add 10.0.1.2/24 dev veth2 0 nsec
 * endpoint_init:PASS:ip -net mptcp_ns link set dev veth2 up 0 nsec
 * endpoint_init:PASS:ip -net mptcp_ns mptcp endpoint add 10.0.1.2 subflow 0 nsec
 * test_default:PASS:endpoint_init 0 nsec
 * send_data_and_verify:PASS:default 0 nsec
 * send_data_and_verify:PASS:default 0 nsec
 * send_data_and_verify:PASS:send_recv_data 0 nsec
 * default: 329 ms
 *
 * EAGAIN output:
 *
 * 38
 * create_netns:PASS:ip netns add mptcp_ns 0 nsec
 * create_netns:PASS:ip -net mptcp_ns link set dev lo up 0 nsec
 * test_default:PASS:create_netns 0 nsec
 * endpoint_init:PASS:ip -net mptcp_ns link add veth1 type veth peer name veth2 0 nsec
 * endpoint_init:PASS:ip -net mptcp_ns addr add 10.0.1.1/24 dev veth1 0 nsec
 * endpoint_init:PASS:ip -net mptcp_ns link set dev veth1 up 0 nsec
 * endpoint_init:PASS:ip -net mptcp_ns addr add 10.0.1.2/24 dev veth2 0 nsec
 * endpoint_init:PASS:ip -net mptcp_ns link set dev veth2 up 0 nsec
 * endpoint_init:PASS:ip -net mptcp_ns mptcp endpoint add 10.0.1.2 subflow 0 nsec
 * test_default:PASS:endpoint_init 0 nsec
 * send_data_and_verify:PASS:default 0 nsec
 * send_data_and_verify:PASS:default 0 nsec
 * (mptcp_eagain_reproducer.c:324: errno: Resource temporarily unavailable) send 5949000 expected 10485760
 * (mptcp_eagain_reproducer.c:372: errno: Resource temporarily unavailable) recv 840000 expected 10485760
 * (mptcp_eagain_reproducer.c:380: errno: Resource temporarily unavailable) Failed in thread_ret -11
 * send_data_and_verify:FAIL:send_recv_data unexpected error: -11 (errno 11)
 */

#define _GNU_SOURCE
#include <sys/param.h>
#include <sys/un.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <pthread.h>

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

#ifndef SOL_TCP
#define SOL_TCP 6
#endif

#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) (unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO

static inline long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

static bool IS_ERR(const void* ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static void *ERR_PTR(long error)
{
	return (void *) error;
}

struct network_helper_opts {
	int timeout_ms;
	int proto;
};

static const struct network_helper_opts default_opts;

int settimeo(int fd, int timeout_ms)
{
	struct timeval timeout = { .tv_sec = 3 };

	if (timeout_ms > 0) {
		timeout.tv_sec = timeout_ms / 1000;
		timeout.tv_usec = (timeout_ms % 1000) * 1000;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		       sizeof(timeout))) {
		printf("Failed to set SO_RCVTIMEO");
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
		       sizeof(timeout))) {
		printf("Failed to set SO_SNDTIMEO");
		return -1;
	}

	return 0;
}

#define save_errno_close(fd) ({ int __save = errno; close(fd); errno = __save; })

struct send_recv_arg {
	int		fd;
	uint32_t	bytes;
	int		stop;
};

static void *send_recv_server(void *arg)
{
	struct send_recv_arg *a = (struct send_recv_arg *)arg;
	ssize_t nr_sent = 0, bytes = 0;
	char batch[1500];
	int err = 0, fd;

	fd = accept(a->fd, NULL, NULL);
	while (fd == -1) {
		if (errno == EINTR)
			continue;
		err = -errno;
		goto done;
	}

	if (settimeo(fd, 10000)) {
		err = -errno;
		goto done;
	}

	while (bytes < a->bytes && !a->stop) {
		nr_sent = send(fd, &batch,
			       MIN(a->bytes - bytes, sizeof(batch)), 0);
		if (nr_sent == -1 && errno == EINTR)
			continue;
		if (nr_sent == -1) {
			err = -errno;
			break;
		}
		bytes += nr_sent;
	}

	if (bytes != a->bytes) {
		printf("send %zd expected %u", bytes, a->bytes);
		if (!err)
			err = bytes > a->bytes ? -E2BIG : -EINTR;
	}

done:
	if (fd >= 0)
		close(fd);
	if (err) {
		a->stop = 1;
		return ERR_PTR(err);
	}
	return NULL;
}

int send_recv_data(int lfd, int fd, uint32_t total_bytes)
{
	ssize_t nr_recv = 0, bytes = 0;
	struct send_recv_arg arg = {
		.fd	= lfd,
		.bytes	= total_bytes,
		.stop	= 0,
	};
	pthread_t srv_thread;
	void *thread_ret;
	char batch[1500];
	int err = 0;

	err = pthread_create(&srv_thread, NULL, send_recv_server, (void *)&arg);
	if (err) {
		printf("Failed to pthread_create");
		return err;
	}

	/* recv total_bytes */
	while (bytes < total_bytes && !arg.stop) {
		nr_recv = recv(fd, &batch,
			       MIN(total_bytes - bytes, sizeof(batch)), 0);
		if (nr_recv == -1 && errno == EINTR)
			continue;
		if (nr_recv == -1) {
			err = -errno;
			break;
		}
		bytes += nr_recv;
	}

	if (bytes != total_bytes) {
		printf("recv %zd expected %u", bytes, total_bytes);
		if (!err)
			err = bytes > total_bytes ? -E2BIG : -EINTR;
	}

	arg.stop = 1;
	pthread_join(srv_thread, &thread_ret);
	if (IS_ERR(thread_ret)) {
		printf("Failed in thread_ret %ld", PTR_ERR(thread_ret));
		err = err ? : PTR_ERR(thread_ret);
	}

	return err;
}

int start_server_addr(int type, const struct sockaddr_storage *addr, socklen_t addrlen,
		      const struct network_helper_opts *opts)
{
	int on = 1;
	int fd;

	if (!opts)
		opts = &default_opts;

	fd = socket(addr->ss_family, type, opts->proto);
	if (fd < 0) {
		printf("Failed to create server socket");
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
		goto error_close;

	if (settimeo(fd, opts->timeout_ms))
		goto error_close;

	if (bind(fd, (struct sockaddr *)addr, addrlen) < 0) {
		printf("Failed to bind socket");
		goto error_close;
	}

	if (type == SOCK_STREAM) {
		if (listen(fd, 1) < 0) {
			printf("Failed to listed on socket");
			goto error_close;
		}
	}

	return fd;

error_close:
	save_errno_close(fd);
	return -1;
}

int connect_to_fd_opts(int server_fd, const struct network_helper_opts *opts)
{
	struct sockaddr_storage addr;
	struct sockaddr_in *addr_in;
	socklen_t addrlen, optlen;
	int fd, type, protocol;

	if (!opts)
		opts = &default_opts;

	optlen = sizeof(type);
	if (getsockopt(server_fd, SOL_SOCKET, SO_TYPE, &type, &optlen)) {
		printf("getsockopt(SOL_TYPE)");
		return -1;
	}

	if (getsockopt(server_fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &optlen)) {
		printf("getsockopt(SOL_PROTOCOL)");
		return -1;
	}

	addrlen = sizeof(addr);
	if (getsockname(server_fd, (struct sockaddr *)&addr, &addrlen)) {
		printf("Failed to get server addr");
		return -1;
	}

	addr_in = (struct sockaddr_in *)&addr;
	fd = socket(addr_in->sin_family, type, protocol);
	if (fd < 0) {
		printf("Failed to create client socket");
		return -1;
	}

	if (settimeo(fd, opts->timeout_ms))
		goto error_close;

	if (connect(fd, (const struct sockaddr *)&addr, addrlen))
		goto error_close;

	return fd;

error_close:
	save_errno_close(fd);
	return -1;
}

int connect_to_fd(int server_fd, int timeout_ms)
{
	struct network_helper_opts opts = {
		.timeout_ms = timeout_ms,
	};

	return connect_to_fd_opts(server_fd, &opts);
}

int make_sockaddr(int family, const char *addr_str, __u16 port,
		  struct sockaddr_storage *addr, socklen_t *len)
{
	if (family == AF_INET) {
		struct sockaddr_in *sin = (void *)addr;

		memset(addr, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		sin->sin_port = htons(port);
		if (addr_str &&
		    inet_pton(AF_INET, addr_str, &sin->sin_addr) != 1) {
			printf("inet_pton(AF_INET, %s)", addr_str);
			return -1;
		}
		if (len)
			*len = sizeof(*sin);
		return 0;
	}
	return -1;
}

#define ADDR_1	"10.0.1.1"
#define PORT_1	10001

static unsigned int total_bytes = 10 * 1024 * 1024;

static int start_mptcp_server(int family, const char *addr_str, __u16 port,
			      int timeout_ms)
{
	struct network_helper_opts opts = {
		.timeout_ms	= timeout_ms,
		.proto		= IPPROTO_MPTCP,
	};
	struct sockaddr_storage addr;
	socklen_t addrlen;

	if (make_sockaddr(family, addr_str, port, &addr, &addrlen))
		return -1;

	return start_server_addr(SOCK_STREAM, &addr, addrlen, &opts);
}

static int send_data_and_verify(void)
{
	struct timespec start, end;
	int server_fd, client_fd;
	unsigned int delta_ms;
	int err = 0;

	server_fd = start_mptcp_server(AF_INET, ADDR_1, PORT_1, 0);
	if (server_fd < 0)
		return server_fd;

	client_fd = connect_to_fd(server_fd, 0);
	if (client_fd < 0) {
		err = client_fd;
		goto fail;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &start) < 0) {
		err = -1;
		goto fail;
	}

	err = send_recv_data(server_fd, client_fd, total_bytes);
	if (err)
		goto fail;

	if (clock_gettime(CLOCK_MONOTONIC, &end) < 0) {
		err = -1;
		goto fail;
	}

	delta_ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
	printf("delta_ms: %u ms\n", delta_ms);

	close(client_fd);
fail:
	close(server_fd);
	return err;
}

int main(int argc, char *argv[])
{
	int err = 0, i = 0;
	int max = 100;

	if (argc == 3) {
		max = atoi(argv[1]);
		total_bytes = atoi(argv[2]) * 1024 * 1024;
	}

	while (!err && !errno && i++ < max) {
		printf("\n%d\n", i);
		err = send_data_and_verify();
	}

	return err;
}
