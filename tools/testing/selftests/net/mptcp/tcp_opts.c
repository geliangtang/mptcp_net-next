#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>

#ifndef TCP_CA_NAME_MAX
#define TCP_CA_NAME_MAX 16
#endif
#ifndef TCP_ULP_NAME_MAX
#define TCP_ULP_NAME_MAX 16
#endif
#ifndef TCP_CC_INFO
#define TCP_CC_INFO 28
#endif
#ifndef TCP_ULP
#define TCP_ULP 31
#endif

union tcp_cc_info {
	char dummy[256];
};

static void die(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

static void get_congestion_control(int fd)
{
	char name[TCP_CA_NAME_MAX];
	socklen_t len = sizeof(name);

	if (getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, name, &len) < 0)
		die("getsockopt TCP_CONGESTION");
	printf("Current CC: %s\n", name);
}

static void set_congestion_control(int fd, const char *algo)
{
	if (setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, algo, strlen(algo) + 1) < 0)
		die("setsockopt TCP_CONGESTION");
	printf("Set CC to: %s\n", algo);
}

static void try_get_cc_info(int fd)
{
	union tcp_cc_info info;
	socklen_t len = sizeof(info);

	if (getsockopt(fd, IPPROTO_TCP, TCP_CC_INFO, &info, &len) < 0) {
		printf("TCP_CC_INFO not available: %s\n", strerror(errno));
		return;
	}
	printf("TCP_CC_INFO retrieved (%u bytes)\n", len);
}

static void get_ulp(int fd)
{
	char name[TCP_ULP_NAME_MAX];
	socklen_t len = sizeof(name);

	if (getsockopt(fd, IPPROTO_TCP, TCP_ULP, name, &len) < 0) {
		printf("ULP not set: %s\n", strerror(errno));
		return;
	}
	printf("Current ULP: %s\n", name);
}

static void set_ulp(int fd, const char *ulp)
{
	if (setsockopt(fd, IPPROTO_TCP, TCP_ULP, ulp, strlen(ulp) + 1) < 0)
		die("setsockopt TCP_ULP");
	printf("Set ULP to: %s\n", ulp);
}

static void run_echo_server(int port)
{
	struct sockaddr_in addr;
	int listen_fd, conn_fd;
	int opt = 1;

	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0)
		die("server socket");

	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	memset(&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
		die("server bind");
	if (listen(listen_fd, 1) < 0)
		die("server listen");

	conn_fd = accept(listen_fd, NULL, NULL);
	if (conn_fd < 0)
		die("server accept");
	pause();
	close(conn_fd);
	close(listen_fd);
}

int main()
{
	struct sockaddr_in srv_addr;
	int port = 12345;
	pid_t pid;
	int fd;

	pid = fork();
	if (pid == -1)
		die("fork");
	if (pid == 0) {
		run_echo_server(port);
		exit(0);
	}

	sleep(1);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		die("socket");

	printf("\n=== TCP_CONGESTION ===\n");
	get_congestion_control(fd);
	set_congestion_control(fd, "reno");
	get_congestion_control(fd);

	printf("\n=== TCP_CC_INFO ===\n");
	try_get_cc_info(fd);

	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(port);
	inet_pton(AF_INET, "127.0.0.1", &srv_addr.sin_addr);
	if (connect(fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0)
		die("connect");
	printf("Connected to 127.0.0.1:%d\n", port);

	printf("\n=== TCP_ULP (after connection) ===\n");
	get_ulp(fd);
	set_ulp(fd, "tls");
	get_ulp(fd);

	close(fd);
	kill(pid, SIGTERM);
	wait(NULL);
	return 0;
}
