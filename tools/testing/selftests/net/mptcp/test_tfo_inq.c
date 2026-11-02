// SPDX-License-Identifier: GPL-2.0
/*
 * Test MPTCP TFO SIOCINQ: verify it returns correct byte count, not INT_MAX
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/wait.h>
#include <limits.h>

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

#define PORT 18080
#define TFO_DATA "TFO test"
#define TFO_LEN 8

static int server(void)
{
	int srv, cli, avail, i;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(PORT),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	int qlen = 5;
	char buf[64];

	srv = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (srv < 0) {
		perror("socket");
		return 1;
	}

	i = 1;
	setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));
	setsockopt(srv, SOL_SOCKET, SO_REUSEPORT, &i, sizeof(i));
	setsockopt(srv, IPPROTO_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen));

	bind(srv, (struct sockaddr *)&addr, sizeof(addr));
	listen(srv, 5);

	/* First connection: cookie exchange */
	cli = accept(srv, NULL, NULL);
	if (cli < 0) {
		perror("accept");
		return 1;
	}
	printf("Server: first connection accepted (cookie exchange)\n");

	/* Read cookie data */
	ssize_t n = recv(cli, buf, sizeof(buf), 0);
	printf("Server: received %zd bytes in first connection\n", n);
	close(cli);

	usleep(100000);

	/* Second connection: TFO data */
	cli = accept(srv, NULL, NULL);
	if (cli < 0) {
		perror("accept");
		return 1;
	}
	printf("Server: second connection accepted (TFO data)\n");

	usleep(100000);  /* Wait for TFO data to arrive */

	/* Debug: try to read data to see if it arrived */
	n = recv(cli, buf, sizeof(buf), MSG_PEEK | MSG_DONTWAIT);
	printf("Server: recv PEEK returned %zd\n", n);

	ioctl(cli, SIOCINQ, &avail);
	printf("Server: SIOCINQ=%d (expect %d)\n", avail, TFO_LEN);

	if (avail == INT_MAX) {
		printf("FAIL: INT_MAX overflow\n");
		return 1;
	}
	if (avail != TFO_LEN) {
		printf("FAIL: should have %d bytes, got %d\n", TFO_LEN, avail);
		return 1;
	}

	if (n > 0) {
		ssize_t r = read(cli, buf, sizeof(buf));
		(void)r;
	}
	close(cli);

	close(srv);
	return 0;
}

static int client(void)
{
	int sock;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(PORT),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	char buf[64];

	usleep(100000);

	/* First connection: establish TFO cookie */
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (sock < 0) {
		perror("socket");
		return 1;
	}

	/* Enable TFO on client side for first connection to request cookie */
	int qlen = 5;
	if (setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen)) < 0) {
		perror("setsockopt TCP_FASTOPEN first");
		close(sock);
		return 1;
	}

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		close(sock);
		return 1;
	}
	printf("Client: first connection established (cookie exchange)\n");

	/* Send and receive to complete cookie exchange */
	send(sock, "cookie", 6, 0);
	recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
	close(sock);

	usleep(100000);

	/* Second connection: use TFO */
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (sock < 0) {
		perror("socket");
		return 1;
	}

	/* Enable TFO on client side */
	if (setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen)) < 0) {
		perror("setsockopt TCP_FASTOPEN");
		close(sock);
		return 1;
	}

	errno = 0;
	ssize_t ret = sendto(sock, TFO_DATA, TFO_LEN, MSG_FASTOPEN,
	       (struct sockaddr *)&addr, sizeof(addr));
	printf("Client: sendto(MSG_FASTOPEN) returned %zd, errno=%d\n", ret, errno);

	if (ret == -1 && errno == EINPROGRESS) {
		printf("Client: TFO in progress, waiting...\n");
		usleep(200000);
		/* Send remaining data */
		ret = send(sock, TFO_DATA, TFO_LEN, 0);
		printf("Client: send remaining data returned %zd\n", ret);
	} else if (ret > 0 && ret < TFO_LEN) {
		printf("Client: TFO sent %zd bytes in SYN, sending remaining %zd\n",
		       ret, TFO_LEN - ret);
		/* Send remaining data */
		ssize_t remaining = send(sock, TFO_DATA + ret, TFO_LEN - ret, 0);
		printf("Client: send remaining data returned %zd\n", remaining);
	} else if (ret == 0) {
		printf("Client: TFO returned 0, sending all data via send()\n");
		/* TFO didn't work, send all data normally */
		ret = send(sock, TFO_DATA, TFO_LEN, 0);
		printf("Client: send returned %zd\n", ret);
	} else if (ret > 0) {
		printf("Client: TFO sent all %zd bytes in SYN\n", ret);
	}

	sleep(1);
	close(sock);

	return 0;
}

int main(void)
{
	pid_t pid;
	int ret;

	pid = fork();
	if (pid == 0)
		return client();

	ret = server();
	waitpid(pid, NULL, 0);

	printf(ret == 0 ? "PASS\n" : "FAIL\n");
	return ret;
}
