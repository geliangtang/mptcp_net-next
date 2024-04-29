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

static inline int IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

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

static long libbpf_get_error(const void *ptr)
{
	if (!IS_ERR_OR_NULL(ptr))
		return 0;

	if (IS_ERR(ptr))
		errno = -PTR_ERR(ptr);

	return -errno;
}

typedef __u8  __attribute__((__may_alias__))  __u8_alias_t;
typedef __u16 __attribute__((__may_alias__)) __u16_alias_t;
typedef __u32 __attribute__((__may_alias__)) __u32_alias_t;
typedef __u64 __attribute__((__may_alias__)) __u64_alias_t;

static __always_inline void __read_once_size(const volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(__u8_alias_t  *) res = *(volatile __u8_alias_t  *) p; break;
	case 2: *(__u16_alias_t *) res = *(volatile __u16_alias_t *) p; break;
	case 4: *(__u32_alias_t *) res = *(volatile __u32_alias_t *) p; break;
	case 8: *(__u64_alias_t *) res = *(volatile __u64_alias_t *) p; break;
	default:
		__builtin_memcpy((void *)res, (const void *)p, size);
	}
}

static __always_inline void __write_once_size(volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(volatile  __u8_alias_t *) p = *(__u8_alias_t  *) res; break;
	case 2: *(volatile __u16_alias_t *) p = *(__u16_alias_t *) res; break;
	case 4: *(volatile __u32_alias_t *) p = *(__u32_alias_t *) res; break;
	case 8: *(volatile __u64_alias_t *) p = *(__u64_alias_t *) res; break;
	default:
		__builtin_memcpy((void *)p, (const void *)res, size);
	}
}

#define READ_ONCE(x)					\
({							\
	union { typeof(x) __val; char __c[1]; } __u =	\
		{ .__c = { 0 } };			\
	__read_once_size(&(x), __u.__c, sizeof(x));	\
	__u.__val;					\
})

#define WRITE_ONCE(x, val)				\
({							\
	union { typeof(x) __val; char __c[1]; } __u =	\
		{ .__val = (val) }; 			\
	__write_once_size(&(x), __u.__c, sizeof(x));	\
	__u.__val;					\
})

#define _CHECK(condition, tag, duration, format...) ({			\
	int __ret = !!(condition);					\
	int __save_errno = errno;					\
	if (__ret) {							\
		fprintf(stdout, "%s:FAIL:%s ", __func__, tag);		\
		fprintf(stdout, ##format);				\
	} else {							\
		fprintf(stdout, "%s:PASS:%s %d nsec\n",			\
		       __func__, tag, duration);			\
	}								\
	errno = __save_errno;						\
	__ret;								\
})

#define CHECK(condition, tag, format...) \
	_CHECK(condition, tag, duration, format)

#define ASSERT_OK(res, name) ({						\
	static int duration = 0;					\
	long long ___res = (res);					\
	bool ___ok = ___res == 0;					\
	CHECK(!___ok, (name), "unexpected error: %lld (errno %d)\n",	\
	      ___res, errno);						\
	___ok;								\
})

#define ASSERT_OK_PTR(ptr, name) ({					\
	static int duration = 0;					\
	const void *___res = (ptr);					\
	int ___err = libbpf_get_error(___res);				\
	bool ___ok = ___err == 0;					\
	CHECK(!___ok, (name), "unexpected error: %d\n", ___err);	\
	___ok;								\
})

#define SYS(goto_label, fmt, ...)					\
	({								\
		char cmd[1024];						\
		snprintf(cmd, sizeof(cmd), fmt, ##__VA_ARGS__);		\
		if (!ASSERT_OK(system(cmd), cmd))			\
			goto goto_label;				\
	})

#define ALL_TO_DEV_NULL " >/dev/null 2>&1"

#define SYS_NOFAIL(fmt, ...)						\
	({								\
		char cmd[1024];						\
		int n;							\
		n = snprintf(cmd, sizeof(cmd), fmt, ##__VA_ARGS__);	\
		if (n < sizeof(cmd) && sizeof(cmd) - n >= sizeof(ALL_TO_DEV_NULL)) \
			strcat(cmd, ALL_TO_DEV_NULL);			\
		system(cmd);						\
	})

#define clean_errno() (errno == 0 ? "None" : strerror(errno))
#define log_err(MSG, ...) ({						\
			int __save = errno;				\
			fprintf(stderr, "(%s:%d: errno: %s) " MSG "\n", \
				__FILE__, __LINE__, clean_errno(),	\
				##__VA_ARGS__);				\
			errno = __save;					\
})

struct network_helper_opts {
	const char *cc;
	int timeout_ms;
	bool must_fail;
	bool noconnect;
	int type;
	int proto;
	int (*setsockopt)(int fd, const void *optval, socklen_t optlen);
	const void *optval;
	socklen_t optlen;
};

static const struct network_helper_opts default_opts;

struct nstoken {
	int orig_netns_fd;
};

struct nstoken *open_netns(const char *name)
{
	int nsfd;
	char nspath[PATH_MAX];
	int err;
	struct nstoken *token;

	token = calloc(1, sizeof(struct nstoken));
	if (!token) {
		log_err("Failed to malloc token");
		return NULL;
	}

	token->orig_netns_fd = open("/proc/self/ns/net", O_RDONLY);
	if (token->orig_netns_fd == -1) {
		log_err("Failed to open /proc/self/ns/net");
		goto fail;
	}

	snprintf(nspath, sizeof(nspath), "%s/%s", "/var/run/netns", name);
	nsfd = open(nspath, O_RDONLY | O_CLOEXEC);
	if (nsfd == -1) {
		log_err("Failed to open netns fd");
		goto fail;
	}

	err = setns(nsfd, CLONE_NEWNET);
	close(nsfd);
	if (err) {
		log_err("Failed to setns");
		goto fail;
	}

	return token;
fail:
	close(token->orig_netns_fd);
	free(token);
	return NULL;
}

void close_netns(struct nstoken *token)
{
	if (!token)
		return;

	if (setns(token->orig_netns_fd, CLONE_NEWNET))
		log_err("Failed to setns");
	close(token->orig_netns_fd);
	free(token);
}

int settimeo(int fd, int timeout_ms)
{
	struct timeval timeout = { .tv_sec = 3 };

	if (timeout_ms > 0) {
		timeout.tv_sec = timeout_ms / 1000;
		timeout.tv_usec = (timeout_ms % 1000) * 1000;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		       sizeof(timeout))) {
		log_err("Failed to set SO_RCVTIMEO");
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
		       sizeof(timeout))) {
		log_err("Failed to set SO_SNDTIMEO");
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

	if (settimeo(fd, 0)) {
		err = -errno;
		goto done;
	}

	while (bytes < a->bytes && !READ_ONCE(a->stop)) {
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
		log_err("send %zd expected %u", bytes, a->bytes);
		if (!err)
			err = bytes > a->bytes ? -E2BIG : -EINTR;
	}

done:
	if (fd >= 0)
		close(fd);
	if (err) {
		WRITE_ONCE(a->stop, 1);
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
		log_err("Failed to pthread_create");
		return err;
	}

	/* recv total_bytes */
	while (bytes < total_bytes && !READ_ONCE(arg.stop)) {
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
		log_err("recv %zd expected %u", bytes, total_bytes);
		if (!err)
			err = bytes > total_bytes ? -E2BIG : -EINTR;
	}

	WRITE_ONCE(arg.stop, 1);
	pthread_join(srv_thread, &thread_ret);
	if (IS_ERR(thread_ret)) {
		log_err("Failed in thread_ret %ld", PTR_ERR(thread_ret));
		err = err ? : PTR_ERR(thread_ret);
	}

	return err;
}

static int __start_server(int type, const struct sockaddr *addr, socklen_t addrlen,
			  const struct network_helper_opts *opts)
{
	int fd;

	fd = socket(addr->sa_family, type, opts->proto);
	if (fd < 0) {
		log_err("Failed to create server socket");
		return -1;
	}

	if (settimeo(fd, opts->timeout_ms))
		goto error_close;

	if (opts->setsockopt &&
	    opts->setsockopt(fd, opts->optval, opts->optlen)) {
		log_err("Failed to set sockopt");
		goto error_close;
	}

	if (bind(fd, addr, addrlen) < 0) {
		log_err("Failed to bind socket");
		goto error_close;
	}

	if (type == SOCK_STREAM) {
		if (listen(fd, 1) < 0) {
			log_err("Failed to listed on socket");
			goto error_close;
		}
	}

	return fd;

error_close:
	save_errno_close(fd);
	return -1;
}

int start_server_addr(int type, const struct sockaddr_storage *addr, socklen_t len,
		      const struct network_helper_opts *opts)
{
	if (!opts)
		opts = &default_opts;

	return __start_server(type, (struct sockaddr *)addr, len, opts);
}

static int connect_fd_to_addr(int fd,
			      const struct sockaddr_storage *addr,
			      socklen_t addrlen, const bool must_fail)
{
	int ret;

	errno = 0;
	ret = connect(fd, (const struct sockaddr *)addr, addrlen);
	if (must_fail) {
		if (!ret) {
			log_err("Unexpected success to connect to server");
			return -1;
		}
		if (errno != EPERM) {
			log_err("Unexpected error from connect to server");
			return -1;
		}
	} else {
		if (ret) {
			log_err("Failed to connect to server");
			return -1;
		}
	}

	return 0;
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

	if (opts->type) {
		type = opts->type;
	} else {
		if (getsockopt(server_fd, SOL_SOCKET, SO_TYPE, &type, &optlen)) {
			log_err("getsockopt(SOL_TYPE)");
			return -1;
		}
	}

	if (opts->proto) {
		protocol = opts->proto;
	} else {
		if (getsockopt(server_fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &optlen)) {
			log_err("getsockopt(SOL_PROTOCOL)");
			return -1;
		}
	}

	addrlen = sizeof(addr);
	if (getsockname(server_fd, (struct sockaddr *)&addr, &addrlen)) {
		log_err("Failed to get server addr");
		return -1;
	}

	addr_in = (struct sockaddr_in *)&addr;
	fd = socket(addr_in->sin_family, type, protocol);
	if (fd < 0) {
		log_err("Failed to create client socket");
		return -1;
	}

	if (settimeo(fd, opts->timeout_ms))
		goto error_close;

	if (opts->cc && opts->cc[0] &&
	    setsockopt(fd, SOL_TCP, TCP_CONGESTION, opts->cc,
		       strlen(opts->cc) + 1))
		goto error_close;

	if (!opts->noconnect)
		if (connect_fd_to_addr(fd, &addr, addrlen, opts->must_fail))
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
			log_err("inet_pton(AF_INET, %s)", addr_str);
			return -1;
		}
		if (len)
			*len = sizeof(*sin);
		return 0;
	} else if (family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (void *)addr;

		memset(addr, 0, sizeof(*sin6));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(port);
		if (addr_str &&
		    inet_pton(AF_INET6, addr_str, &sin6->sin6_addr) != 1) {
			log_err("inet_pton(AF_INET6, %s)", addr_str);
			return -1;
		}
		if (len)
			*len = sizeof(*sin6);
		return 0;
	} else if (family == AF_UNIX) {
		/* Note that we always use abstract unix sockets to avoid having
		 * to clean up leftover files.
		 */
		struct sockaddr_un *sun = (void *)addr;

		memset(addr, 0, sizeof(*sun));
		sun->sun_family = family;
		sun->sun_path[0] = 0;
		strcpy(sun->sun_path + 1, addr_str);
		if (len)
			*len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(addr_str);
		return 0;
	}
	return -1;
}

#define NS_TEST "mptcp_ns"
#define ADDR_1	"10.0.1.1"
#define ADDR_2	"10.0.1.2"
#define PORT_1	10001
#define WITH_DATA	true
#define WITHOUT_DATA	false

static unsigned int total_bytes = 10 * 1024 * 1024;
static int duration;

static void sig_int(int sig)
{
	signal(sig, SIG_IGN);
	SYS_NOFAIL("ip netns del %s", NS_TEST);
}

static struct nstoken *create_netns(void)
{
	SYS(fail, "ip netns add %s", NS_TEST);
	SYS(fail, "ip -net %s link set dev lo up", NS_TEST);

	signal(SIGINT, sig_int);
	return open_netns(NS_TEST);
fail:
	return NULL;
}

static void cleanup_netns(struct nstoken *nstoken)
{
	if (nstoken)
		close_netns(nstoken);

	SYS_NOFAIL("ip netns del %s", NS_TEST);
}

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

static int endpoint_init(char *flags)
{
	SYS(fail, "ip -net %s link add veth1 type veth peer name veth2", NS_TEST);
	SYS(fail, "ip -net %s addr add %s/24 dev veth1", NS_TEST, ADDR_1);
	SYS(fail, "ip -net %s link set dev veth1 up", NS_TEST);
	SYS(fail, "ip -net %s addr add %s/24 dev veth2", NS_TEST, ADDR_2);
	SYS(fail, "ip -net %s link set dev veth2 up", NS_TEST);
	SYS(fail, "ip -net %s mptcp endpoint add %s %s", NS_TEST, ADDR_2, flags);

	return 0;
fail:
	return -1;
}

static int send_data_and_verify(char *sched, bool addr1, bool addr2)
{
	struct timespec start, end;
	int server_fd, client_fd;
	unsigned int delta_ms;
	int err = 0;

	server_fd = start_mptcp_server(AF_INET, ADDR_1, PORT_1, 0);
	if (CHECK(server_fd < 0, sched, "start_mptcp_server: %d\n", errno))
		return server_fd;

	client_fd = connect_to_fd(server_fd, 0);
	if (CHECK(client_fd < 0, sched, "connect_to_fd: %d\n", errno)) {
		err = client_fd;
		goto fail;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &start) < 0) {
		err = -1;
		goto fail;
	}

	err = send_recv_data(server_fd, client_fd, total_bytes);
	if (!ASSERT_OK(err, "send_recv_data"))
		goto fail;

	if (clock_gettime(CLOCK_MONOTONIC, &end) < 0) {
		err = -1;
		goto fail;
	}

	delta_ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
	printf("%s: %u ms\n", sched, delta_ms);


	close(client_fd);
fail:
	close(server_fd);
	return err;
}

static int test_default(void)
{
	struct nstoken *nstoken;
	int err;

	nstoken = create_netns();
	if (!ASSERT_OK_PTR(nstoken, "create_netns"))
		goto fail;

	if (!ASSERT_OK(endpoint_init("subflow"), "endpoint_init"))
		goto fail;

	err = send_data_and_verify("default", WITH_DATA, WITH_DATA);

fail:
	cleanup_netns(nstoken);
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
		err = test_default();
	}

	return 0;
}
