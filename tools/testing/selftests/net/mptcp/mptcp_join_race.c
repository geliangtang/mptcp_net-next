// SPDX-License-Identifier: GPL-2.0

/* MPTCP join_list vs close() race reproducer.
 *
 * Race being exercised (server side, passive MP_JOIN):
 *
 *  - the client in-kernel path manager creates one additional
 *    MP_JOIN subflow right after the MPC handshake completes;
 *  - if the 3rd ACK of that MP_JOIN is processed in softirq while
 *    the server application thread holds the msk socket lock,
 *    mptcp_finish_join() parks the subflow in msk->join_list
 *    (net/mptcp/protocol.c, "sock_owned_by_user(parent)" branch)
 *    and the path manager accounts it (+1 extra_subflows);
 *  - the server closes the msk while leaving unread data in the
 *    receive queue: close() takes the MPTCP fastclose path, sets
 *    TCP_CLOSE and destroys the msk inside the same socket-lock
 *    critical section, walking only msk->conn_list: the parked
 *    subflow is missed by mptcp_destroy_common();
 *  - at release_sock() time __mptcp_flush_join_list() moves it
 *    onto the conn_list of the dying msk and resets it, but
 *    nothing will ever drop the msk reference taken at park time:
 *    the subflow and its mptcp_subflow_context leak.
 *
 * Server mode (-l): accept(), sleep a random number of
 * microseconds (phase scan across the MP_JOIN arrival time), then
 * close() without ever reading, so that unread data is always
 * pending.
 *
 * Client mode: connect(), write a small payload (to leave unread
 * data server side), wait for the fastclose reset, close().
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

static void usage(const char *prog)
{
	fprintf(stderr,
		"%s [-l] -p PORT [-n ITERATIONS] [-d MAX_DELAY_US] [-s PAYLOAD] [-b BIND] [CONNECT_ADDR]\n"
		"  -l            listener (server) mode\n"
		"  -p PORT       port to listen on / connect to\n"
		"  -n ITER       iterations, default 10000\n"
		"  -d MAX_US     max random close delay in us, server only, default 3000\n"
		"  -s PAYLOAD    payload size in bytes, client only, default 2048\n"
		"  -b BIND       server bind address, default 10.0.1.1\n"
		"  CONNECT_ADDR  server address, client only, default 10.0.1.1\n",
		prog);
	exit(1);
}

static int run_server(int port, int iterations, int max_delay_us,
		      const char *bind_addr)
{
	struct sockaddr_in addr;
	const int backlog = 16;
	int err_cnt = 0;
	int listen_fd;
	int i, one = 1;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
		fprintf(stderr, "invalid bind address: %s\n", bind_addr);
		return 1;
	}

	listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (listen_fd < 0) {
		perror("socket");
		return 2;
	}
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		return 2;
	}
	if (listen(listen_fd, backlog) < 0) {
		perror("listen");
		return 2;
	}

	for (i = 0; i < iterations; i++) {
		int fd = accept(listen_fd, NULL, NULL);

		if (fd < 0) {
			err_cnt++;
			continue;
		}

		/* phase scan: spread the close() across the MP_JOIN
		 * 3rd ACK arrival time (PM worker latency + RTT)
		 */
		usleep(rand() % max_delay_us);

		/* close() with unread data: forces the MPTCP
		 * fastclose path, the msk is destroyed inside the
		 * close() socket-lock critical section
		 */
		close(fd);
	}

	close(listen_fd);
	printf("server: %d iterations, %d accept errors\n", i, err_cnt);

	/* a high error rate means the setup is broken, not raced */
	return err_cnt > iterations / 10 ? 2 : 0;
}

static int run_client(const char *dst_addr, int port, int iterations,
		      int payload)
{
	struct sockaddr_in addr;
	struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
	char *payload_buf, read_buf[4096];
	int err_cnt = 0;
	int i;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (inet_pton(AF_INET, dst_addr, &addr.sin_addr) != 1) {
		fprintf(stderr, "invalid connect address: %s\n", dst_addr);
		return 1;
	}

	payload_buf = malloc(payload);
	if (!payload_buf)
		return 2;
	memset(payload_buf, 'x', payload);

	for (i = 0; i < iterations; i++) {
		int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
		int ret;

		if (fd < 0) {
			err_cnt++;
			continue;
		}
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

		if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			err_cnt++;
			close(fd);
			continue;
		}

		/* leave unread data on the server side */
		if (write(fd, payload_buf, payload) < 0) {
			err_cnt++;
			close(fd);
			continue;
		}

		/* keep the msk - and the client side MP_JOIN alive -
		 * until the server fastclose reset arrives
		 */
		do {
			ret = read(fd, read_buf, sizeof(read_buf));
		} while (ret > 0);

		close(fd);
	}

	free(payload_buf);
	printf("client: %d iterations, %d errors\n", i, err_cnt);

	return err_cnt > iterations / 10 ? 2 : 0;
}

int main(int argc, char *argv[])
{
	bool listener = false;
	const char *bind_addr = "10.0.1.1";
	const char *dst_addr = "10.0.1.1";
	int iterations = 10000;
	int max_delay_us = 3000;
	int payload = 2048;
	int port = 50010;
	int opt;

	while ((opt = getopt(argc, argv, "lp:n:d:s:b:")) != -1) {
		switch (opt) {
		case 'l':
			listener = true;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'n':
			iterations = atoi(optarg);
			break;
		case 'd':
			max_delay_us = atoi(optarg);
			break;
		case 's':
			payload = atoi(optarg);
			break;
		case 'b':
			bind_addr = optarg;
			break;
		default:
			usage(argv[0]);
		}
	}
	if (optind < argc)
		dst_addr = argv[optind];

	if (port <= 0 || iterations <= 0 || max_delay_us <= 0 || payload <= 0)
		usage(argv[0]);

	srand(time(NULL) ^ getpid());

	if (listener)
		return run_server(port, iterations, max_delay_us, bind_addr);

	return run_client(dst_addr, port, iterations, payload);
}
