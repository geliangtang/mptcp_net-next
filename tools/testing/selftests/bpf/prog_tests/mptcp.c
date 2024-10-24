// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020, Tessares SA. */
/* Copyright (c) 2022, SUSE. */

#include <linux/const.h>
#include <netinet/in.h>
#include <test_progs.h>
#include <unistd.h>
#include "cgroup_helpers.h"
#include "network_helpers.h"
#include "mptcp_sock.skel.h"
#include "mptcpify.skel.h"
#include "mptcp_subflow.skel.h"
#include "mptcp_bpf_iters.skel.h"
#include "mptcp_bpf_userspace_pm.skel.h"
#include "mptcp_bpf_sockopt.skel.h"
#include "mptcp_bpf_bytes.skel.h"
#include "mptcp_bpf_first.skel.h"
#include "mptcp_bpf_bkup.skel.h"
#include "mptcp_bpf_rr.skel.h"
#include "mptcp_bpf_red.skel.h"
#include "mptcp_bpf_burst.skel.h"
#include "mptcp_bpf_stale.skel.h"

#define NS_TEST "mptcp_ns"
#define ADDR_1	"10.0.1.1"
#define ADDR_2	"10.0.2.1"
#define ADDR_3	"10.0.3.1"
#define ADDR_4	"10.0.4.1"
#define ADDR6_1	"dead:beef:1::1"
#define ADDR6_2	"dead:beef:2::1"
#define ADDR6_3	"dead:beef:3::1"
#define ADDR6_4	"dead:beef:4::1"
#define PORT_1	10001
#define PM_CTL		"./mptcp_pm_nl_ctl"
#define PM_EVENTS	"/tmp/bpf_userspace_pm_events"
#define WITH_DATA	true
#define WITHOUT_DATA	false

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

#ifndef SOL_MPTCP
#define SOL_MPTCP 284
#endif
#ifndef MPTCP_INFO
#define MPTCP_INFO		1
#endif
#ifndef TCP_IS_MPTCP
#define TCP_IS_MPTCP		43	/* Is MPTCP being used? */
#endif
#ifndef MPTCP_INFO_FLAG_FALLBACK
#define MPTCP_INFO_FLAG_FALLBACK		_BITUL(0)
#endif
#ifndef MPTCP_INFO_FLAG_REMOTE_KEY_RECEIVED
#define MPTCP_INFO_FLAG_REMOTE_KEY_RECEIVED	_BITUL(1)
#endif

#ifndef TCP_CA_NAME_MAX
#define TCP_CA_NAME_MAX	16
#endif
#define MPTCP_SCHED_NAME_MAX	16

enum mptcp_pm_type {
	MPTCP_PM_TYPE_KERNEL = 0,
	MPTCP_PM_TYPE_USERSPACE,
	MPTCP_PM_TYPE_BPF,

	__MPTCP_PM_TYPE_NR,
	__MPTCP_PM_TYPE_MAX = __MPTCP_PM_TYPE_NR - 1,
};

enum mptcp_pm_family {
	IPV4 = 0,
	IPV6,
	IPV4MAPPED,
};

static const unsigned int total_bytes = 10 * 1024 * 1024;
static int duration;

struct __mptcp_info {
	__u8	mptcpi_subflows;
	__u8	mptcpi_add_addr_signal;
	__u8	mptcpi_add_addr_accepted;
	__u8	mptcpi_subflows_max;
	__u8	mptcpi_add_addr_signal_max;
	__u8	mptcpi_add_addr_accepted_max;
	__u32	mptcpi_flags;
	__u32	mptcpi_token;
	__u64	mptcpi_write_seq;
	__u64	mptcpi_snd_una;
	__u64	mptcpi_rcv_nxt;
	__u8	mptcpi_local_addr_used;
	__u8	mptcpi_local_addr_max;
	__u8	mptcpi_csum_enabled;
	__u32	mptcpi_retransmits;
	__u64	mptcpi_bytes_retrans;
	__u64	mptcpi_bytes_sent;
	__u64	mptcpi_bytes_received;
	__u64	mptcpi_bytes_acked;
};

struct mptcp_storage {
	__u32 invoked;
	__u32 is_mptcp;
	struct sock *sk;
	__u32 token;
	struct sock *first;
	char ca_name[TCP_CA_NAME_MAX];
};

static struct nstoken *create_netns(void)
{
	struct nstoken *nstoken = NULL;

	if (make_netns(NS_TEST))
		goto fail;

	nstoken = open_netns(NS_TEST);
	if (!nstoken) {
		log_err("open netns %s failed", NS_TEST);
		remove_netns(NS_TEST);
	}

fail:
	return nstoken;
}

static void cleanup_netns(struct nstoken *nstoken)
{
	if (nstoken)
		close_netns(nstoken);

	remove_netns(NS_TEST);
}

static int start_mptcp_server(int family, const char *addr_str, __u16 port,
			      int timeout_ms)
{
	struct network_helper_opts opts = {
		.timeout_ms	= timeout_ms,
		.proto		= IPPROTO_MPTCP,
	};

	return start_server_str(family, SOCK_STREAM, addr_str, port, &opts);
}

static int verify_tsk(int map_fd, int client_fd)
{
	int err, cfd = client_fd;
	struct mptcp_storage val;

	err = bpf_map_lookup_elem(map_fd, &cfd, &val);
	if (!ASSERT_OK(err, "bpf_map_lookup_elem"))
		return err;

	if (!ASSERT_EQ(val.invoked, 1, "unexpected invoked count"))
		err++;

	if (!ASSERT_EQ(val.is_mptcp, 0, "unexpected is_mptcp"))
		err++;

	return err;
}

static void get_msk_ca_name(char ca_name[])
{
	size_t len;
	int fd;

	fd = open("/proc/sys/net/ipv4/tcp_congestion_control", O_RDONLY);
	if (!ASSERT_GE(fd, 0, "failed to open tcp_congestion_control"))
		return;

	len = read(fd, ca_name, TCP_CA_NAME_MAX);
	if (!ASSERT_GT(len, 0, "failed to read ca_name"))
		goto err;

	if (len > 0 && ca_name[len - 1] == '\n')
		ca_name[len - 1] = '\0';

err:
	close(fd);
}

static int verify_msk(int map_fd, int client_fd, __u32 token)
{
	char ca_name[TCP_CA_NAME_MAX];
	int err, cfd = client_fd;
	struct mptcp_storage val;

	if (!ASSERT_GT(token, 0, "invalid token"))
		return -1;

	get_msk_ca_name(ca_name);

	err = bpf_map_lookup_elem(map_fd, &cfd, &val);
	if (!ASSERT_OK(err, "bpf_map_lookup_elem"))
		return err;

	if (!ASSERT_EQ(val.invoked, 1, "unexpected invoked count"))
		err++;

	if (!ASSERT_EQ(val.is_mptcp, 1, "unexpected is_mptcp"))
		err++;

	if (!ASSERT_EQ(val.token, token, "unexpected token"))
		err++;

	if (!ASSERT_EQ(val.first, val.sk, "unexpected first"))
		err++;

	if (!ASSERT_STRNEQ(val.ca_name, ca_name, TCP_CA_NAME_MAX, "unexpected ca_name"))
		err++;

	return err;
}

static int run_test(int cgroup_fd, int server_fd, bool is_mptcp)
{
	int client_fd, prog_fd, map_fd, err;
	struct mptcp_sock *sock_skel;

	sock_skel = mptcp_sock__open_and_load();
	if (!ASSERT_OK_PTR(sock_skel, "skel_open_load"))
		return libbpf_get_error(sock_skel);

	err = mptcp_sock__attach(sock_skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto out;

	prog_fd = bpf_program__fd(sock_skel->progs._sockops);
	map_fd = bpf_map__fd(sock_skel->maps.socket_storage_map);
	err = bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0);
	if (!ASSERT_OK(err, "bpf_prog_attach"))
		goto out;

	client_fd = connect_to_fd(server_fd, 0);
	if (!ASSERT_GE(client_fd, 0, "connect to fd")) {
		err = -EIO;
		goto out;
	}

	err += is_mptcp ? verify_msk(map_fd, client_fd, sock_skel->bss->token) :
			  verify_tsk(map_fd, client_fd);

	close(client_fd);

out:
	mptcp_sock__destroy(sock_skel);
	return err;
}

static void test_base(void)
{
	struct nstoken *nstoken = NULL;
	int server_fd, cgroup_fd;

	cgroup_fd = test__join_cgroup("/mptcp");
	if (!ASSERT_GE(cgroup_fd, 0, "test__join_cgroup"))
		return;

	nstoken = create_netns();
	if (!ASSERT_OK_PTR(nstoken, "create_netns"))
		goto fail;

	/* without MPTCP */
	server_fd = start_server(AF_INET, SOCK_STREAM, NULL, 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_server"))
		goto with_mptcp;

	ASSERT_OK(run_test(cgroup_fd, server_fd, false), "run_test tcp");

	close(server_fd);

with_mptcp:
	/* with MPTCP */
	server_fd = start_mptcp_server(AF_INET, NULL, 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_mptcp_server"))
		goto fail;

	ASSERT_OK(run_test(cgroup_fd, server_fd, true), "run_test mptcp");

	close(server_fd);

fail:
	cleanup_netns(nstoken);
	close(cgroup_fd);
}

static void send_byte(int fd)
{
	char b = 0x55;

	ASSERT_EQ(write(fd, &b, sizeof(b)), 1, "send single byte");
}

static int recv_byte(int fd)
{
	char buf[1];
	ssize_t n;

	n = recv(fd, buf, sizeof(buf), 0);
	if (CHECK(n <= 0, "recv_byte", "recv")) {
		log_err("failed/partial recv");
		return -1;
	}
	return 0;
}

static int verify_mptcpify(int server_fd, int client_fd)
{
	struct __mptcp_info info;
	socklen_t optlen;
	int protocol;
	int err = 0;

	optlen = sizeof(protocol);
	if (!ASSERT_OK(getsockopt(server_fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &optlen),
		       "getsockopt(SOL_PROTOCOL)"))
		return -1;

	if (!ASSERT_EQ(protocol, IPPROTO_MPTCP, "protocol isn't MPTCP"))
		err++;

	optlen = sizeof(info);
	if (!ASSERT_OK(getsockopt(client_fd, SOL_MPTCP, MPTCP_INFO, &info, &optlen),
		       "getsockopt(MPTCP_INFO)"))
		return -1;

	if (!ASSERT_GE(info.mptcpi_flags, 0, "unexpected mptcpi_flags"))
		err++;
	if (!ASSERT_FALSE(info.mptcpi_flags & MPTCP_INFO_FLAG_FALLBACK,
			  "MPTCP fallback"))
		err++;
	if (!ASSERT_TRUE(info.mptcpi_flags & MPTCP_INFO_FLAG_REMOTE_KEY_RECEIVED,
			 "no remote key received"))
		err++;

	return err;
}

static int run_mptcpify(int cgroup_fd)
{
	int server_fd, client_fd, err = 0;
	struct mptcpify *mptcpify_skel;

	mptcpify_skel = mptcpify__open_and_load();
	if (!ASSERT_OK_PTR(mptcpify_skel, "skel_open_load"))
		return libbpf_get_error(mptcpify_skel);

	mptcpify_skel->bss->pid = getpid();

	err = mptcpify__attach(mptcpify_skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto out;

	/* without MPTCP */
	server_fd = start_server(AF_INET, SOCK_STREAM, NULL, 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_server")) {
		err = -EIO;
		goto out;
	}

	client_fd = connect_to_fd(server_fd, 0);
	if (!ASSERT_GE(client_fd, 0, "connect to fd")) {
		err = -EIO;
		goto close_server;
	}

	send_byte(client_fd);

	err = verify_mptcpify(server_fd, client_fd);

	close(client_fd);
close_server:
	close(server_fd);
out:
	mptcpify__destroy(mptcpify_skel);
	return err;
}

static void test_mptcpify(void)
{
	struct nstoken *nstoken = NULL;
	int cgroup_fd;

	cgroup_fd = test__join_cgroup("/mptcpify");
	if (!ASSERT_GE(cgroup_fd, 0, "test__join_cgroup"))
		return;

	nstoken = create_netns();
	if (!ASSERT_OK_PTR(nstoken, "create_netns"))
		goto fail;

	ASSERT_OK(run_mptcpify(cgroup_fd), "run_mptcpify");

fail:
	cleanup_netns(nstoken);
	close(cgroup_fd);
}

static int address_init(void)
{
	SYS(fail, "ip -net %s link add veth1 type veth peer name veth2", NS_TEST);
	SYS(fail, "ip -net %s addr add %s/24 dev veth1", NS_TEST, ADDR_1);
	SYS(fail, "ip -net %s addr add %s/64 dev veth1 nodad", NS_TEST, ADDR6_1);
	SYS(fail, "ip -net %s link set dev veth1 up", NS_TEST);
	SYS(fail, "ip -net %s addr add %s/24 dev veth2", NS_TEST, ADDR_2);
	SYS(fail, "ip -net %s addr add %s/64 dev veth2 nodad", NS_TEST, ADDR6_2);
	SYS(fail, "ip -net %s link set dev veth2 up", NS_TEST);

	SYS(fail, "ip -net %s link add veth3 type veth peer name veth4", NS_TEST);
	SYS(fail, "ip -net %s addr add %s/24 dev veth3", NS_TEST, ADDR_3);
	SYS(fail, "ip -net %s addr add %s/64 dev veth3 nodad", NS_TEST, ADDR6_3);
	SYS(fail, "ip -net %s link set dev veth3 up", NS_TEST);
	SYS(fail, "ip -net %s addr add %s/24 dev veth4", NS_TEST, ADDR_4);
	SYS(fail, "ip -net %s addr add %s/64 dev veth4 nodad", NS_TEST, ADDR6_4);
	SYS(fail, "ip -net %s link set dev veth4 up", NS_TEST);

	return 0;
fail:
	return -1;
}

static int endpoint_add(char *addr, char *flags, bool ip_mptcp)
{
	if (ip_mptcp)
		return SYS_NOFAIL("ip -net %s mptcp endpoint add %s %s",
				  NS_TEST, addr, flags);
	return SYS_NOFAIL("ip netns exec %s %s add %s flags %s",
			  NS_TEST, PM_CTL, addr, flags);
}

static int endpoint_init(char *flags, u8 endpoints)
{
	bool ip_mptcp = true;
	int ret = -1;

	if (!endpoints || endpoints > 4)
		goto fail;

	if (address_init())
		goto fail;

	if (SYS_NOFAIL("ip -net %s mptcp limits set add_addr_accepted 4 subflows 4",
		       NS_TEST)) {
		SYS(fail, "ip netns exec %s %s limits 4 4", NS_TEST, PM_CTL);
		ip_mptcp = false;
	}

	if (endpoints > 1)
		ret = endpoint_add(ADDR_2, flags, ip_mptcp);
	if (endpoints > 2)
		ret = ret ?: endpoint_add(ADDR_3, flags, ip_mptcp);
	if (endpoints > 3)
		ret = ret ?: endpoint_add(ADDR_4, flags, ip_mptcp);

fail:
	return ret;
}

static void wait_for_new_subflows(int fd)
{
	socklen_t len;
	u8 subflows;
	int err, i;

	len = sizeof(subflows);
	/* Wait max 5 sec for new subflows to be created */
	for (i = 0; i < 50; i++) {
		err = getsockopt(fd, SOL_MPTCP, MPTCP_INFO, &subflows, &len);
		if (!err && subflows > 0)
			break;

		usleep(100000); /* 0.1s */
	}
}

static void run_subflow(void)
{
	int server_fd, client_fd, err;
	char new[TCP_CA_NAME_MAX];
	char cc[TCP_CA_NAME_MAX];
	unsigned int mark;
	socklen_t len;

	server_fd = start_mptcp_server(AF_INET, ADDR_1, PORT_1, 0);
	if (!ASSERT_OK_FD(server_fd, "start_mptcp_server"))
		return;

	client_fd = connect_to_fd(server_fd, 0);
	if (!ASSERT_OK_FD(client_fd, "connect_to_fd"))
		goto close_server;

	send_byte(client_fd);
	wait_for_new_subflows(client_fd);

	len = sizeof(mark);
	err = getsockopt(client_fd, SOL_SOCKET, SO_MARK, &mark, &len);
	if (ASSERT_OK(err, "getsockopt(client_fd, SO_MARK)"))
		ASSERT_EQ(mark, 0, "mark");

	len = sizeof(new);
	err = getsockopt(client_fd, SOL_TCP, TCP_CONGESTION, new, &len);
	if (ASSERT_OK(err, "getsockopt(client_fd, TCP_CONGESTION)")) {
		get_msk_ca_name(cc);
		ASSERT_STREQ(new, cc, "cc");
	}

	close(client_fd);
close_server:
	close(server_fd);
}

static void test_subflow(void)
{
	struct mptcp_subflow *skel;
	struct nstoken *nstoken;
	int cgroup_fd;

	cgroup_fd = test__join_cgroup("/mptcp_subflow");
	if (!ASSERT_OK_FD(cgroup_fd, "join_cgroup: mptcp_subflow"))
		return;

	skel = mptcp_subflow__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_load: mptcp_subflow"))
		goto close_cgroup;

	skel->bss->pid = getpid();

	skel->links.mptcp_subflow =
		bpf_program__attach_cgroup(skel->progs.mptcp_subflow, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.mptcp_subflow, "attach mptcp_subflow"))
		goto skel_destroy;

	skel->links._getsockopt_subflow =
		bpf_program__attach_cgroup(skel->progs._getsockopt_subflow, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links._getsockopt_subflow, "attach _getsockopt_subflow"))
		goto skel_destroy;

	nstoken = create_netns();
	if (!ASSERT_OK_PTR(nstoken, "create_netns: mptcp_subflow"))
		goto skel_destroy;

	if (endpoint_init("subflow", 2) < 0)
		goto close_netns;

	run_subflow();

close_netns:
	cleanup_netns(nstoken);
skel_destroy:
	mptcp_subflow__destroy(skel);
close_cgroup:
	close(cgroup_fd);
}

static void run_iters_subflow(void)
{
	int server_fd, client_fd;
	int is_mptcp, err;
	socklen_t len;

	server_fd = start_mptcp_server(AF_INET, ADDR_1, PORT_1, 0);
	if (!ASSERT_OK_FD(server_fd, "start_mptcp_server"))
		return;

	client_fd = connect_to_fd(server_fd, 0);
	if (!ASSERT_OK_FD(client_fd, "connect_to_fd"))
		goto close_server;

	send_byte(client_fd);
	wait_for_new_subflows(client_fd);

	len = sizeof(is_mptcp);
	/* mainly to trigger the BPF program */
	err = getsockopt(client_fd, SOL_TCP, TCP_IS_MPTCP, &is_mptcp, &len);
	if (ASSERT_OK(err, "getsockopt(client_fd, TCP_IS_MPTCP)"))
		ASSERT_EQ(is_mptcp, 1, "is_mptcp");

	close(client_fd);
close_server:
	close(server_fd);
}

static void test_iters_subflow(void)
{
	struct mptcp_bpf_iters *skel;
	struct nstoken *nstoken;
	int cgroup_fd;

	cgroup_fd = test__join_cgroup("/iters_subflow");
	if (!ASSERT_OK_FD(cgroup_fd, "join_cgroup: iters_subflow"))
		return;

	skel = mptcp_bpf_iters__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_load: iters_subflow"))
		goto close_cgroup;

	skel->links.iters_subflow = bpf_program__attach_cgroup(skel->progs.iters_subflow,
							       cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.iters_subflow, "attach getsockopt"))
		goto skel_destroy;

	nstoken = create_netns();
	if (!ASSERT_OK_PTR(nstoken, "create_netns: iters_subflow"))
		goto skel_destroy;

	if (endpoint_init("subflow", 4) < 0)
		goto close_netns;

	run_iters_subflow();

	/* 1 + 2 + 3 + 4 = 10 */
	ASSERT_EQ(skel->bss->ids, 10, "subflow ids");

close_netns:
	cleanup_netns(nstoken);
skel_destroy:
	mptcp_bpf_iters__destroy(skel);
close_cgroup:
	close(cgroup_fd);
}

static int userspace_pm_init(enum mptcp_pm_type pm_type)
{
	if (address_init())
		goto fail;

	SYS(fail, "ip netns exec %s sysctl -qw net.mptcp.pm_type=%u",
	    NS_TEST, pm_type);
	SYS(fail, "ip netns exec %s %s limits 4 4",
	    NS_TEST, PM_CTL);
	SYS(fail, "ip netns exec %s %s events >> %s 2>&1 &",
	    NS_TEST, PM_CTL, PM_EVENTS);

	return 0;
fail:
	return -1;
}

static void userspace_pm_cleanup(void)
{
	//SYS(fail, "ip netns exec %s cat %s", NS_TEST, PM_EVENTS);

	SYS_NOFAIL("ip netns exec %s killall %s > /dev/null 2>&1",
		   NS_TEST, PM_CTL);
	SYS_NOFAIL("ip netns exec %s rm -rf %s", NS_TEST, PM_EVENTS);
//fail:
	;
}

static int userspace_pm_get_events_line(char *type, char *line)
{
	char buf[BUFSIZ], *str;
	size_t len;
	int fd;

	fd = open(PM_EVENTS, O_RDONLY);
	if (fd < 0) {
		log_err("failed to open pm events\n");
		return -1;
	}

	len = read(fd, buf, sizeof(buf));
	close(fd);
	if (len <= 0) {
		log_err("failed to read pm events\n");
		return -1;
	}

	str = strstr(buf, type);
	if (!str) {
		log_err("failed to get type %s pm event\n", type);
		return -1;
	}

	strcpy(line, str);
	return 0;
}

static int userspace_pm_get_token(int fd)
{
	char line[1024], *str;
	__u32 token;
	int i;

	/* Wait max 2 sec for the connection to be established */
	for (i = 0; i < 10; i++) {
		//SYS(fail, "ip netns exec %s echo sleep 0.2 s", NS_TEST);
		usleep(200000); /* 0.2s */
		send_byte(fd);

		sync();
		if (userspace_pm_get_events_line("type:2", line))
			continue;
		str = strstr(line, "token");
		if (!str)
			continue;
		if (sscanf(str, "token:%u,", &token) != 1)
			continue;
		return token;
	}

//fail:
	return 0;
}

static int userspace_pm_add_subflow(__u32 token, char *addr, __u8 id)
{
	bool ipv6 = strstr(addr, ":");
	char line[1024], *str;
	__u32 sport, dport;

	if (userspace_pm_get_events_line("type:2", line))
		return -1;

	str = strstr(line, "sport");
	if (!str || sscanf(str, "sport:%u,dport:%u,", &sport, &dport) != 2) {
		log_err("add_subflow error, str=%s\n", str);
		return -1;
	}

	str = ipv6 ? (strstr(addr, ".") ? "::ffff:"ADDR_1 : ADDR6_1) : ADDR_1;
	SYS_NOFAIL("ip netns exec %s %s csf lip %s lid %u rip %s rport %u token %u",
		   NS_TEST, PM_CTL, addr, id, str, dport, token);

	return 0;
}

static void run_iters_address(void)
{
	int server_fd, client_fd, accept_fd;
	int is_mptcp, err;
	socklen_t len;
	__u32 token;

	server_fd = start_mptcp_server(AF_INET6, "::ffff:"ADDR_1, PORT_1, 0);
	if (!ASSERT_OK_FD(server_fd, "start_mptcp_server"))
		return;

	client_fd = connect_to_fd(server_fd, 0);
	if (!ASSERT_OK_FD(client_fd, "connect_to_fd"))
		goto close_server;

	accept_fd = accept(server_fd, NULL, NULL);
	if (!ASSERT_OK_FD(accept_fd, "accept"))
		goto close_client;

	token = userspace_pm_get_token(client_fd);
	if (!token)
		goto close_client;
	recv_byte(accept_fd);
	usleep(200000); /* 0.2s */

	err = userspace_pm_add_subflow(token, "::ffff:"ADDR_2, 10);
	err = err ?: userspace_pm_add_subflow(token, "::ffff:"ADDR_3, 20);
	err = err ?: userspace_pm_add_subflow(token, "::ffff:"ADDR_4, 30);
	if (!ASSERT_OK(err, "userspace_pm_add_subflow"))
		goto close_accept;

	send_byte(accept_fd);
	recv_byte(client_fd);

	len = sizeof(is_mptcp);
	/* mainly to trigger the BPF program */
	err = getsockopt(client_fd, SOL_TCP, TCP_IS_MPTCP, &is_mptcp, &len);
	if (ASSERT_OK(err, "getsockopt(client_fd, TCP_IS_MPTCP)"))
		ASSERT_EQ(is_mptcp, 1, "is_mptcp");

close_accept:
	close(accept_fd);
close_client:
	close(client_fd);
close_server:
	close(server_fd);
}

static void test_iters_address(void)
{
	struct mptcp_bpf_iters *skel;
	struct nstoken *nstoken;
	int cgroup_fd;
	int err;

	cgroup_fd = test__join_cgroup("/iters_address");
	if (!ASSERT_OK_FD(cgroup_fd, "join_cgroup: iters_address"))
		return;

	skel = mptcp_bpf_iters__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_load: iters_address"))
		goto close_cgroup;

	skel->links.iters_address = bpf_program__attach_cgroup(skel->progs.iters_address,
							       cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.iters_address, "attach getsockopt"))
		goto skel_destroy;

	nstoken = create_netns();
	if (!ASSERT_OK_PTR(nstoken, "create_netns"))
		goto skel_destroy;

	err = userspace_pm_init(MPTCP_PM_TYPE_USERSPACE);
	if (!ASSERT_OK(err, "userspace_pm_init: iters_address"))
		goto close_netns;

	run_iters_address();

	/* 10 + 20 + 30 = 60 */
	ASSERT_EQ(skel->bss->ids, 60, "address ids");

	userspace_pm_cleanup();
close_netns:
	cleanup_netns(nstoken);
skel_destroy:
	mptcp_bpf_iters__destroy(skel);
close_cgroup:
	close(cgroup_fd);
}

static int userspace_pm_add_addr(__u32 token, char *addr, __u8 id)
{
	return SYS_NOFAIL("ip netns exec %s %s ann %s id %u token %u",
			  NS_TEST, PM_CTL, addr, id, token);
}

static int userspace_pm_get_addr(__u32 token, __u8 id, char *output)
{
	char cmd[1024];
	FILE *fp;

	sprintf(cmd, "ip netns exec %s %s get %u token %u",
		NS_TEST, PM_CTL, id, token);
	fp = popen(cmd, "r");
	if (!fp)
		return -1;

	bzero(output, BUFSIZ);
	fread(output, 1, BUFSIZ, fp);
	pclose(fp);

	return 0;
}

static int userspace_pm_dump_addr(__u32 token, char *output)
{
	char cmd[1024];
	FILE *fp;

	sprintf(cmd, "ip netns exec %s %s dump token %u",
		NS_TEST, PM_CTL, token);
	fp = popen(cmd, "r");
	if (!fp)
		return -1;

	bzero(output, BUFSIZ);
	fread(output, 1, BUFSIZ, fp);
	pclose(fp);

	return 0;
}

static int userspace_pm_set_flags(__u32 token, char *addr, char *flags)
{
	bool ipv6 = strstr(addr, ":");
	char line[1024], *str;
	__u32 sport, dport;

	if (userspace_pm_get_events_line("type:10", line))
		return -1;

	str = strstr(line, "sport");
	if (!str || sscanf(str, "sport:%u,dport:%u,", &sport, &dport) != 2) {
		log_err("set_flags error, str=%s\n", str);
		return -1;
	}

	str = ipv6 ? (strstr(addr, ".") ? "::ffff:"ADDR_1 : ADDR6_1) : ADDR_1;
	return SYS_NOFAIL("ip netns exec %s %s set %s port %u rip %s rport %u flags %s token %u",
			  NS_TEST, PM_CTL, addr, sport, str, dport, flags, token);
}

static int userspace_pm_rm_subflow(__u32 token, char *addr, __u8 id)
{
	bool ipv6 = strstr(addr, ":");
	char line[1024], *str;
	__u32 sport, dport;

	if (userspace_pm_get_events_line("type:10", line))
		return -1;

	str = strstr(line, "sport");
	if (!str || sscanf(str, "sport:%u,dport:%u,", &sport, &dport) != 2) {
		log_err("rm_subflow error, str=%s\n", str);
		return -1;
	}

	str = ipv6 ? (strstr(addr, ".") ? "::ffff:"ADDR_1 : ADDR6_1) : ADDR_1;
	return SYS_NOFAIL("ip netns exec %s %s dsf lip %s lport %u rip %s rport %u token %u",
			  NS_TEST, PM_CTL, addr, sport, str, dport, token);
}

static int userspace_pm_rm_addr(__u32 token, __u8 id)
{
	return SYS_NOFAIL("ip netns exec %s %s rem id %u token %u",
			  NS_TEST, PM_CTL, id, token);
}

static void run_userspace_pm(enum mptcp_pm_family family)
{
	bool ipv6 = (family == IPV6 || family == IPV4MAPPED);
	bool ipv4mapped = (family == IPV4MAPPED);
	int server_fd, client_fd, accept_fd;
	char output[BUFSIZ], expect[1024];
	__u32 token;
	char *addr;
	int err;

	addr = ipv6 ? (ipv4mapped ? "::ffff:"ADDR_1 : ADDR6_1) : ADDR_1;
	server_fd = start_mptcp_server(ipv6 ? AF_INET6 : AF_INET, addr, PORT_1, 0);
	if (!ASSERT_OK_FD(server_fd, "start_mptcp_server"))
		return;

	client_fd = connect_to_fd(server_fd, 0);
	if (!ASSERT_OK_FD(client_fd, "connect_to_fd"))
		goto close_server;

	accept_fd = accept(server_fd, NULL, NULL);
	if (!ASSERT_OK_FD(accept_fd, "accept"))
		goto close_client;

	token = userspace_pm_get_token(client_fd);
	if (!token)
		goto close_client;
	recv_byte(accept_fd);
	usleep(200000); /* 0.2s */

	addr = ipv6 ? (ipv4mapped ? "::ffff:"ADDR_2 : ADDR6_2) : ADDR_2;
	err = userspace_pm_add_subflow(token, addr, 100);
	if (!ASSERT_OK(err, "userspace_pm_add_subflow 100"))
		goto close_accept;

	send_byte(accept_fd);
	recv_byte(client_fd);

	sprintf(expect, "id 100 flags subflow %s\n", addr);
	err = userspace_pm_get_addr(token, 100, output);
	if (!ASSERT_OK(err, "userspace_pm_get_addr 100") ||
	    !ASSERT_STRNEQ(output, expect, sizeof(expect), "get_addr"))
		goto close_accept;

	send_byte(client_fd);
	recv_byte(accept_fd);

	err = userspace_pm_set_flags(token, addr, "backup");
	if (!ASSERT_OK(err, "userspace_pm_set_flags backup"))
		goto close_accept;

	send_byte(accept_fd);
	recv_byte(client_fd);

	sprintf(expect, "id 100 flags subflow,backup %s\n", addr);
	err = userspace_pm_get_addr(token, 100, output);
	if (!ASSERT_OK(err, "userspace_pm_get_addr 100") ||
	    !ASSERT_STRNEQ(output, expect, sizeof(expect), "get_addr"))
		goto close_accept;

	send_byte(client_fd);
	recv_byte(accept_fd);

	err = userspace_pm_set_flags(token, addr, "nobackup");
	if (!ASSERT_OK(err, "userspace_pm_set_flags nobackup"))
		goto close_accept;

	send_byte(accept_fd);
	recv_byte(client_fd);

	sprintf(expect, "id 100 flags subflow %s\n", addr);
	err = userspace_pm_get_addr(token, 100, output);
	if (!ASSERT_OK(err, "userspace_pm_get_addr 100") ||
	    !ASSERT_STRNEQ(output, expect, sizeof(expect), "get_addr"))
		goto close_accept;

	send_byte(client_fd);
	recv_byte(accept_fd);

	err = userspace_pm_rm_subflow(token, addr, 100);
	if (!ASSERT_OK(err, "userspace_pm_rm_subflow 100"))
		goto close_accept;

	send_byte(accept_fd);
	recv_byte(client_fd);

	err = userspace_pm_dump_addr(token, output);
	if (!ASSERT_OK(err, "userspace_pm_dump_addr") ||
	    !ASSERT_STRNEQ(output, "", sizeof(output), "dump_addr"))
		goto close_accept;

	send_byte(client_fd);
	recv_byte(accept_fd);

	addr = ipv6 ? (ipv4mapped ? "::ffff:"ADDR_3 : ADDR6_3) : ADDR_3;
	err = userspace_pm_add_addr(token, addr, 200);
	if (!ASSERT_OK(err, "userspace_pm_add_addr 200"))
		goto close_accept;

	send_byte(accept_fd);
	recv_byte(client_fd);

	sprintf(expect, "id 200 flags signal %s\n", addr);
	err = userspace_pm_dump_addr(token, output);
	if (!ASSERT_OK(err, "userspace_pm_dump_addr") ||
	    !ASSERT_STRNEQ(output, expect, sizeof(expect), "dump_addr"))
		goto close_accept;

	send_byte(client_fd);
	recv_byte(accept_fd);

	err = userspace_pm_rm_addr(token, 200);
	if (!ASSERT_OK(err, "userspace_pm_rm_addr 200"))
		goto close_accept;

	send_byte(accept_fd);
	recv_byte(client_fd);

	err = userspace_pm_rm_addr(token, 0);
	ASSERT_OK(err, "userspace_pm_rm_addr 0");

close_accept:
	close(accept_fd);
close_client:
	close(client_fd);
close_server:
	close(server_fd);
}

static void test_userspace_pm(void)
{
	struct nstoken *nstoken;
	int err;

	nstoken = create_netns();
	if (!ASSERT_OK_PTR(nstoken, "create_netns"))
		return;

	err = userspace_pm_init(MPTCP_PM_TYPE_USERSPACE);
	if (!ASSERT_OK(err, "userspace_pm_init: userspace pm"))
		goto fail;

	run_userspace_pm(IPV4);

	userspace_pm_cleanup();
fail:
	cleanup_netns(nstoken);
}

static void test_bpf_pm(void)
{
	struct mptcp_bpf_userspace_pm *skel;
	struct nstoken *nstoken;
	struct bpf_link *link;
	int err;

	skel = mptcp_bpf_userspace_pm__open();
	if (!ASSERT_OK_PTR(skel, "open: userspace_pm"))
		return;

	err = bpf_program__set_flags(skel->progs.mptcp_pm_address_announce,
				     BPF_F_SLEEPABLE);
	err = err ?: bpf_program__set_flags(skel->progs.mptcp_pm_address_remove,
					    BPF_F_SLEEPABLE);
	err = err ?: bpf_program__set_flags(skel->progs.mptcp_pm_subflow_create,
					    BPF_F_SLEEPABLE);
	err = err ?: bpf_program__set_flags(skel->progs.mptcp_pm_subflow_destroy,
					    BPF_F_SLEEPABLE);
	err = err ?: bpf_program__set_flags(skel->progs.mptcp_pm_set_flags,
					    BPF_F_SLEEPABLE);
	if (!ASSERT_OK(err, "set sleepable flags"))
		goto skel_destroy;

	if (!ASSERT_OK(mptcp_bpf_userspace_pm__load(skel), "load: userspace_pm"))
		goto skel_destroy;

	link = bpf_map__attach_struct_ops(skel->maps.userspace_pm);
	if (!ASSERT_OK_PTR(link, "attach_struct_ops"))
		goto skel_destroy;

	nstoken = create_netns();
	if (!ASSERT_OK_PTR(nstoken, "create_netns"))
		goto link_destroy;

	err = userspace_pm_init(MPTCP_PM_TYPE_BPF);
	if (!ASSERT_OK(err, "userspace_pm_init: bpf pm"))
		goto close_netns;

	run_userspace_pm(skel->kconfig->CONFIG_MPTCP_IPV6 ? IPV6 : IPV4);

	userspace_pm_cleanup();
close_netns:
	cleanup_netns(nstoken);
link_destroy:
	bpf_link__destroy(link);
skel_destroy:
	mptcp_bpf_userspace_pm__destroy(skel);
}

static void run_sockopt(void)
{
	char cc[TCP_CA_NAME_MAX] = "reno";
	int server_fd, client_fd, err;
	unsigned int mark = 1;
	socklen_t len;

	server_fd = start_mptcp_server(AF_INET, ADDR_1, PORT_1, 0);
	if (!ASSERT_OK_FD(server_fd, "start_mptcp_server"))
		return;

	client_fd = connect_to_fd(server_fd, 0);
	if (!ASSERT_OK_FD(client_fd, "connect_to_fd"))
		goto close_server;

	send_byte(client_fd);
	wait_for_new_subflows(client_fd);

	len = sizeof(mark);
	err = setsockopt(client_fd, SOL_SOCKET, SO_MARK, &mark, len);
	if (!ASSERT_OK(err, "setsockopt(client_fd, SO_MARK)"))
		goto close_client;

	len = sizeof(cc);
	err = setsockopt(client_fd, SOL_TCP, TCP_CONGESTION, cc, len);
	if (!ASSERT_OK(err, "setsockopt(client_fd, TCP_CONGESTION)"))
		goto close_client;

	len = sizeof(mark);
	err = getsockopt(client_fd, SOL_SOCKET, SO_MARK, &mark, &len);
	if (ASSERT_OK(err, "getsockopt(client_fd, SO_MARK)"))
		ASSERT_EQ(mark, 1, "mark");

	len = sizeof(cc);
	err = getsockopt(client_fd, SOL_TCP, TCP_CONGESTION, cc, &len);
	if (ASSERT_OK(err, "getsockopt(client_fd, TCP_CONGESTION)"))
		ASSERT_STREQ(cc, "reno", "cc");

close_client:
	close(client_fd);
close_server:
	close(server_fd);
}

static void test_sockopt(void)
{
	struct mptcp_bpf_sockopt *skel;
	struct nstoken *nstoken;
	int cgroup_fd;

	cgroup_fd = test__join_cgroup("/bpf_sockopt");
	if (!ASSERT_OK_FD(cgroup_fd, "join_cgroup: bpf_sockopt"))
		return;

	skel = mptcp_bpf_sockopt__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_load: bpf_sockopt"))
		goto close_cgroup;

	skel->links.mptcp_setsockopt = bpf_program__attach_cgroup(skel->progs.mptcp_setsockopt,
								  cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.mptcp_setsockopt, "attach setsockopt"))
		goto skel_destroy;

	skel->links.mptcp_getsockopt = bpf_program__attach_cgroup(skel->progs.mptcp_getsockopt,
								  cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.mptcp_getsockopt, "attach getsockopt"))
		goto skel_destroy;

	nstoken = create_netns();
	if (!ASSERT_OK_PTR(nstoken, "create_netns"))
		goto skel_destroy;

	if (endpoint_init("subflow", 3) < 0)
		goto close_netns;

	run_sockopt();

close_netns:
	cleanup_netns(nstoken);
skel_destroy:
	mptcp_bpf_sockopt__destroy(skel);
close_cgroup:
	close(cgroup_fd);
}

static int sched_init(char *flags, char *sched)
{
	if (endpoint_init(flags, 4) < 0)
		goto fail;

	SYS(fail, "ip netns exec %s sysctl -qw net.mptcp.scheduler=%s", NS_TEST, sched);

	return 0;
fail:
	return -1;
}

static void send_data_and_verify(char *sched, bool addr1, bool addr2)
{
	int server_fd, client_fd, err;
	struct mptcp_bpf_bytes *skel;
	struct timespec start, end;
	unsigned int delta_ms;

	skel = mptcp_bpf_bytes__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load: bytes"))
		return;

	skel->bss->pid = getpid();

	err = mptcp_bpf_bytes__attach(skel);
	if (!ASSERT_OK(err, "skel_attach: bytes"))
		goto skel_destroy;

	server_fd = start_mptcp_server(AF_INET, ADDR_1, PORT_1, 0);
	if (!ASSERT_OK_FD(server_fd, "start_mptcp_server"))
		goto skel_destroy;

	client_fd = connect_to_fd(server_fd, 0);
	if (!ASSERT_OK_FD(client_fd, "connect_to_fd"))
		goto close_server;

	if (clock_gettime(CLOCK_MONOTONIC, &start) < 0)
		goto close_client;

	if (!ASSERT_OK(send_recv_data(server_fd, client_fd, total_bytes, NULL),
		       "send_recv_data"))
		goto close_client;

	if (clock_gettime(CLOCK_MONOTONIC, &end) < 0)
		goto close_client;

	delta_ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
	printf("%s: %u ms\n", sched, delta_ms);

	if (addr1)
		ASSERT_GT(skel->bss->bytes_sent_1, 0, "should have bytes_sent on addr1");
	else
		ASSERT_EQ(skel->bss->bytes_sent_1, 0, "shouldn't have bytes_sent on addr1");
	if (addr2)
		ASSERT_GT(skel->bss->bytes_sent_2, 0, "should have bytes_sent on addr2");
	else
		ASSERT_EQ(skel->bss->bytes_sent_2, 0, "shouldn't have bytes_sent on addr2");

close_client:
	close(client_fd);
close_server:
	close(server_fd);
skel_destroy:
	mptcp_bpf_bytes__destroy(skel);
}

static void test_default(void)
{
	struct nstoken *nstoken;
	int err;

	nstoken = create_netns();
	if (!nstoken)
		goto fail;

	err = sched_init("subflow", "default");
	if (!ASSERT_OK(err, "sched_init"))
		goto fail;

	send_data_and_verify("default", WITH_DATA, WITH_DATA);

fail:
	cleanup_netns(nstoken);
}

#define NS1		NS_TEST"_1"
#define NS2		NS_TEST"_2"
#define ADDR_1_NS2	"10.0.1.2"
#define ADDR_2_NS2	"10.0.2.2"
#define ADDR_3_NS2	"10.0.3.2"
#define ADDR_3_NS4	"10.0.4.2"
#define ADDR6_1_NS2	"dead:beef:1::2"
#define ADDR6_2_NS2	"dead:beef:2::2"
#define ADDR6_3_NS2	"dead:beef:3::2"
#define ADDR6_4_NS2	"dead:beef:4::2"

static int address_init_1(void)
{
	SYS(fail, "ip link add ns1eth1 netns %s type veth peer name ns2eth1 netns %s", NS1, NS2);
	SYS(fail, "ip -net %s addr add %s/24 dev ns1eth1", NS1, ADDR_1);
	SYS(fail, "ip -net %s addr add %s/64 dev ns1eth1 nodad", NS1, ADDR6_1);
	SYS(fail, "ip -net %s link set dev ns1eth1 up", NS1);
	SYS(fail, "ip -net %s addr add %s/24 dev ns2eth1", NS2, ADDR_1_NS2);
	SYS(fail, "ip -net %s addr add %s/64 dev ns2eth1 nodad", NS2, ADDR6_1_NS2);
	SYS(fail, "ip -net %s link set dev ns2eth1 up", NS2);
	SYS(fail, "ip -net %s route add default via %s dev ns2eth1 metric 101", NS2, ADDR_1);
	SYS(fail, "ip -net %s route add default via %s dev ns2eth1 metric 101", NS2, ADDR6_1);

	SYS(fail, "ip link add ns1eth2 netns %s type veth peer name ns2eth2 netns %s", NS1, NS2);
	SYS(fail, "ip -net %s addr add %s/24 dev ns1eth2", NS1, ADDR_2);
	SYS(fail, "ip -net %s addr add %s/64 dev ns1eth2 nodad", NS1, ADDR6_2);
	SYS(fail, "ip -net %s link set dev ns1eth2 up", NS1);
	SYS(fail, "ip -net %s addr add %s/24 dev ns2eth2", NS2, ADDR_2_NS2);
	SYS(fail, "ip -net %s addr add %s/64 dev ns2eth2 nodad", NS2, ADDR6_2_NS2);
	SYS(fail, "ip -net %s link set dev ns2eth2 up", NS2);
	SYS(fail, "ip -net %s route add default via %s dev ns2eth2 metric 102", NS2, ADDR_2);
	SYS(fail, "ip -net %s route add default via %s dev ns2eth2 metric 102", NS2, ADDR6_2);

	SYS(fail, "ip link add ns1eth3 netns %s type veth peer name ns2eth3 netns %s", NS1, NS2);
	SYS(fail, "ip -net %s addr add %s/24 dev ns1eth3", NS1, ADDR_3);
	SYS(fail, "ip -net %s addr add %s/64 dev ns1eth3 nodad", NS1, ADDR6_3);
	SYS(fail, "ip -net %s link set dev ns1eth3 up", NS1);
	SYS(fail, "ip -net %s addr add %s/24 dev ns2eth3", NS2, ADDR_3_NS2);
	SYS(fail, "ip -net %s addr add %s/64 dev ns2eth3 nodad", NS2, ADDR6_3_NS2);
	SYS(fail, "ip -net %s link set dev ns2eth3 up", NS2);
	SYS(fail, "ip -net %s route add default via %s dev ns2eth3 metric 103", NS2, ADDR_3);
	SYS(fail, "ip -net %s route add default via %s dev ns2eth3 metric 103", NS2, ADDR6_3);

	SYS(fail, "ip link add ns1eth4 netns %s type veth peer name ns2eth4 netns %s", NS1, NS2);
	SYS(fail, "ip -net %s addr add %s/24 dev ns1eth4", NS1, ADDR_4);
	SYS(fail, "ip -net %s addr add %s/64 dev ns1eth4 nodad", NS1, ADDR6_4);
	SYS(fail, "ip -net %s link set dev ns1eth4 up", NS1);
	SYS(fail, "ip -net %s addr add %s/24 dev ns2eth4", NS2, ADDR_3_NS4);
	SYS(fail, "ip -net %s addr add %s/64 dev ns2eth4 nodad", NS2, ADDR6_4_NS2);
	SYS(fail, "ip -net %s link set dev ns2eth4 up", NS2);
	SYS(fail, "ip -net %s route add default via %s dev ns2eth4 metric 104", NS2, ADDR_4);
	SYS(fail, "ip -net %s route add default via %s dev ns2eth4 metric 104", NS2, ADDR6_4);

	return 0;
fail:
	return -1;
}

static int endpoint_add_1(char *netns, char *addr, char *flags, bool ip_mptcp)
{
	if (ip_mptcp)
		return SYS_NOFAIL("ip -net %s mptcp endpoint add %s %s",
				  netns, addr, flags);
	return SYS_NOFAIL("ip netns exec %s %s add %s flags %s",
			  netns, PM_CTL, addr, flags);
}

static int endpoint_init_1(char *flags, u8 endpoints)
{
	bool ip_mptcp = true;
	int ret = -1;

	if (!endpoints || endpoints > 4)
		goto fail;

	if (address_init_1())
		goto fail;

	if (SYS_NOFAIL("ip -net %s mptcp limits set add_addr_accepted 4 subflows 4",
		       NS1)) {
		SYS(fail, "ip netns exec %s %s limits 4 4", NS1, PM_CTL);
		ip_mptcp = false;
	}

	if (endpoints > 1)
		ret = endpoint_add_1(NS2, ADDR_2_NS2, flags, ip_mptcp);
	if (endpoints > 2)
		ret = ret ?: endpoint_add_1(NS2, ADDR_3, flags, ip_mptcp);
	if (endpoints > 3)
		ret = ret ?: endpoint_add_1(NS2, ADDR_4, flags, ip_mptcp);

fail:
	return ret;
}

static int sched_init_1(char *flags, char *sched)
{
	if (endpoint_init_1(flags, 2) < 0)
		goto fail;

	SYS(fail, "ip netns exec %s sysctl -qw net.mptcp.scheduler=%s", NS1, sched);

	return 0;
fail:
	return -1;
}

static void do_verify(struct mptcp_bpf_bytes *skel, bool addr1, bool addr2)
{
	if (addr1)
		ASSERT_GT(skel->bss->bytes_sent_1, 0, "should have bytes_sent on addr1");
	else
		ASSERT_EQ(skel->bss->bytes_sent_1, 0, "shouldn't have bytes_sent on addr1");
	if (addr2)
		;//ASSERT_GT(skel->bss->bytes_sent_2, 0, "should have bytes_sent on addr2");
	else
		ASSERT_EQ(skel->bss->bytes_sent_2, 0, "shouldn't have bytes_sent on addr2");
}

static char *sin = "/tmp/sin";
static char *cin = "/tmp/cin";
static char *sout = "/tmp/sout";
static char *cout = "/tmp/cout";

static void test_connect(void)
{
	struct mptcp_bpf_bytes *skel;
	int err;

	SYS_NOFAIL("ip netns del %s", NS1);
	SYS_NOFAIL("ip netns del %s", NS2);
	SYS(close_netns, "ip netns add %s", NS1);
	SYS(close_netns, "ip netns add %s", NS2);

	err = sched_init_1("subflow", "default");
	if (!ASSERT_OK(err, "sched_init"))
		goto close_netns;

	skel = mptcp_bpf_bytes__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load: bytes"))
		return;

	skel->bss->pid = getpid();

	err = mptcp_bpf_bytes__attach(skel);
	if (!ASSERT_OK(err, "skel_attach: bytes"))
		goto skel_destroy;

	SYS(close_netns, "ip netns exec %s dd if=/dev/urandom of=%s bs=1M count=10 2> /dev/null", NS1, sin);
	SYS(close_netns, "ip netns exec %s dd if=/dev/urandom of=%s bs=1M count=10 2> /dev/null", NS2, cin);
	//SYS(close_netns, "ip netns exec %s echo hello > %s", NS1, sin);
	//SYS(close_netns, "ip netns exec %s echo world > %s", NS2, cin);

	SYS(close_netns, "ip netns exec %s ./mptcp_connect -l :: < %s > %s &", NS1, sin, sout);
	usleep(100000); /* 0.1s */
	SYS(close_netns, "ip netns exec %s ./mptcp_connect %s < %s > %s", NS2, ADDR_1, cin, cout);

	//usleep(100000); /* 0.1s */

	SYS_NOFAIL("ip netns exec %s killall ./mptcp_connect > /dev/null 2>&1", NS1);
	//SYS_NOFAIL("ip netns exec %s killall ./mptcp_connect > /dev/null 2>&1", NS2);

	//SYS(close_netns, "ip netns exec %s cat %s", NS1, sin);
	//SYS(close_netns, "ip netns exec %s cat %s", NS2, cin);

	do_verify(skel, WITH_DATA, WITH_DATA);
	SYS_NOFAIL("ip netns exec %s rm -rf %s %s", NS1, sin, sout);
	SYS_NOFAIL("ip netns exec %s rm -rf %s %s", NS2, cin, cout);
	SYS(close_netns, "ip netns del %s", NS1);
	SYS(close_netns, "ip netns del %s", NS2);

skel_destroy:
	mptcp_bpf_bytes__destroy(skel);
close_netns:
	;
}

static void test_bpf_sched(struct bpf_map *map, char *sched,
			   bool addr1, bool addr2)
{
	char bpf_sched[MPTCP_SCHED_NAME_MAX] = "bpf_";
	struct nstoken *nstoken;
	struct bpf_link *link;
	int err;

	if (!ASSERT_LT(strlen(bpf_sched) + strlen(sched),
		       MPTCP_SCHED_NAME_MAX, "Scheduler name too long"))
		return;

	link = bpf_map__attach_struct_ops(map);
	if (!ASSERT_OK_PTR(link, "attach_struct_ops"))
		return;

	nstoken = create_netns();
	if (!nstoken)
		goto fail;

	err = sched_init("subflow", strcat(bpf_sched, sched));
	if (!ASSERT_OK(err, "sched_init"))
		goto fail;

	send_data_and_verify(sched, addr1, addr2);

fail:
	cleanup_netns(nstoken);
	bpf_link__destroy(link);
}

static void test_first(void)
{
	struct mptcp_bpf_first *skel;

	skel = mptcp_bpf_first__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load: first"))
		return;

	test_bpf_sched(skel->maps.first, "first", WITH_DATA, WITHOUT_DATA);
	mptcp_bpf_first__destroy(skel);
}

static void test_bkup(void)
{
	struct mptcp_bpf_bkup *skel;

	skel = mptcp_bpf_bkup__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load: bkup"))
		return;

	test_bpf_sched(skel->maps.bkup, "bkup", WITH_DATA, WITHOUT_DATA);
	mptcp_bpf_bkup__destroy(skel);
}

static void test_rr(void)
{
	struct mptcp_bpf_rr *skel;

	skel = mptcp_bpf_rr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load: rr"))
		return;

	test_bpf_sched(skel->maps.rr, "rr", WITH_DATA, WITH_DATA);
	mptcp_bpf_rr__destroy(skel);
}

static void test_red(void)
{
	struct mptcp_bpf_red *skel;

	skel = mptcp_bpf_red__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load: red"))
		return;

	test_bpf_sched(skel->maps.red, "red", WITH_DATA, WITH_DATA);
	mptcp_bpf_red__destroy(skel);
}

static void test_burst(void)
{
	struct mptcp_bpf_burst *skel;

	skel = mptcp_bpf_burst__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load: burst"))
		return;

	test_bpf_sched(skel->maps.burst, "burst", WITH_DATA, WITH_DATA);
	mptcp_bpf_burst__destroy(skel);
}

static void test_stale(void)
{
	struct mptcp_bpf_stale *skel;

	skel = mptcp_bpf_stale__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load: stale"))
		return;

	test_bpf_sched(skel->maps.stale, "stale", WITH_DATA, WITHOUT_DATA);
	mptcp_bpf_stale__destroy(skel);
}

void test_mptcp(void)
{
	if (test__start_subtest("connect"))
		test_connect();
#if 1
	if (test__start_subtest("base"))
		test_base();
	if (test__start_subtest("mptcpify"))
		test_mptcpify();
	if (test__start_subtest("subflow"))
		test_subflow();
	if (test__start_subtest("iters_subflow"))
		test_iters_subflow();
	if (test__start_subtest("iters_address"))
		test_iters_address();
	if (test__start_subtest("userspace_pm"))
		test_userspace_pm();
	if (test__start_subtest("bpf_pm"))
		test_bpf_pm();
	if (test__start_subtest("sockopt"))
		test_sockopt();
	if (test__start_subtest("default"))
		test_default();
	if (test__start_subtest("first"))
		test_first();
	if (test__start_subtest("bkup"))
		test_bkup();
	if (test__start_subtest("rr"))
		test_rr();
	if (test__start_subtest("red"))
		test_red();
	if (test__start_subtest("burst"))
		test_burst();
	if (test__start_subtest("stale"))
		test_stale();
#endif
}
