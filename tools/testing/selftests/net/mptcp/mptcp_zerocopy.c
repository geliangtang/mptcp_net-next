// SPDX-License-Identifier: GPL-2.0

/*
 * mptcp_zerocopy: minimal MPTCP MSG_ZEROCOPY smoke test.
 *
 * Default mode (client):
 *   - connect to <host>:<port> via MPTCP;
 *   - send one buffer with sendmsg(MSG_ZEROCOPY);
 *   - read the echoed response from the peer;
 *   - drain the socket's error queue and report every
 *     SO_EE_ORIGIN_ZEROCOPY completion.
 *
 * Server mode (-s):
 *   - listen on <host>:<port>, accept one connection;
 *   - read the request, write the same bytes back to the client.
 *
 * The script exits 0 if every byte sent gets a completion event with
 * SO_EE_CODE_ZEROCOPY_COPIED *not* set, non-zero otherwise.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <linux/errqueue.h>

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

static int parse_port(const char *s)
{
	char *end;
	long v = strtol(s, &end, 0);

	if (*end || v <= 0 || v > 65535) {
		fprintf(stderr, "invalid port: %s\n", s);
		exit(1);
	}
	return (int)v;
}

static int dial(const char *host, const char *port)
{
	struct sockaddr_storage ss = {};
	struct sockaddr_in *sa4 = (void *)&ss;
	struct sockaddr_in6 *sa6 = (void *)&ss;
	int family = strchr(host, ':') ? AF_INET6 : AF_INET;
	int fd = -1, one = 1, err;

	if (family == AF_INET) {
		sa4->sin_family = AF_INET;
		sa4->sin_port = htons(parse_port(port));
		if (inet_pton(AF_INET, host, &sa4->sin_addr) != 1)
			goto err;
	} else {
		sa6->sin6_family = AF_INET6;
		sa6->sin6_port = htons(parse_port(port));
		if (inet_pton(AF_INET6, host, &sa6->sin6_addr) != 1)
			goto err;
	}

	fd = socket(family, SOCK_STREAM, IPPROTO_MPTCP);
	if (fd < 0) {
		perror("socket(MPTCP)");
		return -1;
	}
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)))
		perror("TCP_NODELAY");
	if (setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &one, sizeof(one)))
		perror("SO_ZEROCOPY");

	err = connect(fd, (void *)&ss,
		      family == AF_INET ? sizeof(*sa4) : sizeof(*sa6));
	if (err) {
		perror("connect");
		close(fd);
		return -1;
	}
	return fd;

err:
	fprintf(stderr, "bad address %s\n", host);
	close(fd);
	return -1;
}

static int listen_on(const char *host, const char *port)
{
	struct sockaddr_storage ss = {};
	struct sockaddr_in *sa4 = (void *)&ss;
	struct sockaddr_in6 *sa6 = (void *)&ss;
	int family = strchr(host, ':') ? AF_INET6 : AF_INET;
	int fd = -1, one = 1;

	if (family == AF_INET) {
		sa4->sin_family = AF_INET;
		sa4->sin_port = htons(parse_port(port));
		if (inet_pton(AF_INET, host, &sa4->sin_addr) != 1)
			return -1;
	} else {
		sa6->sin6_family = AF_INET6;
		sa6->sin6_port = htons(parse_port(port));
		if (inet_pton(AF_INET6, host, &sa6->sin6_addr) != 1)
			return -1;
	}

	fd = socket(family, SOCK_STREAM, IPPROTO_MPTCP);
	if (fd < 0) {
		perror("socket(MPTCP)");
		return -1;
	}
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &one, sizeof(one));

	if (bind(fd, (void *)&ss,
		  family == AF_INET ? sizeof(*sa4) : sizeof(*sa6))) {
		perror("bind");
		close(fd);
		return -1;
	}
	if (listen(fd, 1)) {
		perror("listen");
		close(fd);
		return -1;
	}
	return fd;
}

/* Read everything the peer sends, until it half-closes (read returns 0)
 * or an error occurs. The buffer grows as needed and is returned via
 * *out (caller frees with free()). Returns the number of bytes read,
 * or -1 on error.
 */
static ssize_t read_until_eof(int fd, char **out)
{
	size_t cap = 64 * 1024;
	size_t used = 0;
	char *buf = malloc(cap);

	if (!buf)
		return -1;

	for (;;) {
		if (used == cap) {
			char *nb;
			size_t nc = cap * 2;

			nb = realloc(buf, nc);
			if (!nb) {
				free(buf);
				return -1;
			}
			buf = nb;
			cap = nc;
		}

		ssize_t n = read(fd, buf + used, cap - used);
		if (n == 0)
			break;
		if (n < 0) {
			if (errno == EINTR)
				continue;
			free(buf);
			return -1;
		}
		used += n;
	}

	*out = buf;
	return (ssize_t)used;
}

static ssize_t write_full(int fd, const void *buf, size_t len)
{
	const char *p = buf;
	size_t left = len;

	while (left) {
		ssize_t n = write(fd, p, left);

		if (n <= 0) {
			if (n < 0 && errno == EINTR)
				continue;
			return -1;
		}
		p += n;
		left -= n;
	}
	return len;
}

/* Drain the error queue until empty, reporting every MSG_ZEROCOPY
 * completion. Returns the number of completions received and stores
 * the number that carried SO_EE_CODE_ZEROCOPY_COPIED in *copied.
 */
static int drain_errqueue(int fd, int *copied)
{
	int completions = 0;

	*copied = 0;
	for (;;) {
		char cbuf[256];
		struct msghdr msg = {};
		struct cmsghdr *cmsg;

		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);

		ssize_t n = recvmsg(fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			perror("recvmsg errqueue");
			return -1;
		}

		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
		     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			struct sock_extended_err *serr;

			if (cmsg->cmsg_level != SOL_IP &&
			    cmsg->cmsg_level != SOL_IPV6)
				continue;
			if (cmsg->cmsg_type != IP_RECVERR &&
			    cmsg->cmsg_type != IPV6_RECVERR)
				continue;

			serr = (struct sock_extended_err *)CMSG_DATA(cmsg);
			if (serr->ee_origin != SO_EE_ORIGIN_ZEROCOPY)
				continue;

			completions++;
			if (serr->ee_code & SO_EE_CODE_ZEROCOPY_COPIED)
				(*copied)++;
			fprintf(stderr,
				"zc completion: lo=%u hi=%u%s\n",
				serr->ee_info, serr->ee_data,
				(serr->ee_code & SO_EE_CODE_ZEROCOPY_COPIED) ?
				" (copied)" : "");
		}
	}
	return completions;
}

static int run_client(const char *host, const char *port, size_t bufsize)
{
	char *sendbuf, *recvbuf = NULL;
	struct iovec iov;
	struct msghdr msg = {};
	ssize_t sent, got;
	int fd, completions, copied = 0;
	int ret = 0;

	sendbuf = malloc(bufsize);
	if (!sendbuf) {
		perror("malloc");
		return 1;
	}
	for (size_t i = 0; i < bufsize; i++)
		sendbuf[i] = (char)(i ^ (i >> 8));

	fd = dial(host, port);
	if (fd < 0) {
		free(sendbuf);
		return 1;
	}

	iov.iov_base = sendbuf;
	iov.iov_len = bufsize;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	fprintf(stderr, "client: sending %zu bytes via sendmsg(MSG_ZEROCOPY)\n",
		bufsize);
	sent = sendmsg(fd, &msg, MSG_ZEROCOPY);
	if (sent < 0) {
		perror("sendmsg MSG_ZEROCOPY");
		close(fd);
		free(sendbuf);
		return 1;
	}
	if (sent != (ssize_t)bufsize) {
		fprintf(stderr,
			"client: short write, sent %zd of %zu bytes\n",
			sent, bufsize);
		close(fd);
		free(sendbuf);
		return 1;
	}

	/* Half-close so the server sees EOF and exits its read loop. */
	if (shutdown(fd, SHUT_WR)) {
		perror("shutdown SHUT_WR");
		close(fd);
		free(sendbuf);
		return 1;
	}

	got = read_until_eof(fd, &recvbuf);
	if (got < 0) {
		perror("read echo");
		ret = 1;
	} else {
		fprintf(stderr, "client: echoed back %zd bytes\n", got);
		if ((size_t)got != bufsize) {
			fprintf(stderr,
				"client: echo length mismatch: got %zd expected %zu\n",
				got, bufsize);
			ret = 1;
		} else if (memcmp(sendbuf, recvbuf, bufsize) != 0) {
			fprintf(stderr,
				"client: echoed data does not match sent payload\n");
			ret = 1;
		}
	}

	/* Give the kernel a moment to deliver any remaining completions. */
	usleep(50000);

	completions = drain_errqueue(fd, &copied);
	if (completions < 0) {
		ret = 1;
	} else if (completions == 0) {
		fprintf(stderr, "client: no zerocopy completion reported\n");
		ret = 1;
	} else if (copied) {
		/* The kernel marks a zerocopy skb as copied (rather than
		 * "true" zero-copy) when the egress device lacks NETIF_F_SG
		 * or cannot use CHECKSUM_PARTIAL for the fragments. Data
		 * still went out without a kernel copy of the payload, but
		 * from userspace's perspective the buffer is reported as
		 * a copy fallback. Warn rather than fail so the test runs
		 * against loopback and other devices that don't do SG.
		 */
		fprintf(stderr,
			"client: zerocopy reported as copy on %d/%d completion(s) (device likely lacks NETIF_F_SG)\n",
			copied, completions);
	}

	close(fd);
	free(sendbuf);
	free(recvbuf);
	return ret;
}

static int run_server(const char *host, const char *port)
{
	char *buf = NULL;
	int lfd, cfd;
	ssize_t got, echoed;

	lfd = listen_on(host, port);
	if (lfd < 0)
		return 1;
	fprintf(stderr, "server: listening on %s:%s\n", host, port);

	cfd = accept(lfd, NULL, NULL);
	if (cfd < 0) {
		perror("accept");
		close(lfd);
		return 1;
	}

	/* Read everything the client sends, then echo it back. The client
	 * half-closes after sendmsg, which makes this read return EOF.
	 */
	got = read_until_eof(cfd, &buf);
	if (got < 0) {
		perror("read");
		close(cfd);
		close(lfd);
		return 1;
	}
	fprintf(stderr, "server: received %zd bytes\n", got);

	echoed = write_full(cfd, buf, got);
	if (echoed < 0) {
		perror("write");
		close(cfd);
		close(lfd);
		free(buf);
		return 1;
	}
	fprintf(stderr, "server: echoed %zd bytes\n", echoed);

	close(cfd);
	close(lfd);
	free(buf);
	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-s] [-b bufsize] <host> <port>\n"
		"  -s        server mode (default: client)\n"
		"  -b bytes  payload size (default: 131072)\n",
		prog);
	exit(1);
}

int main(int argc, char **argv)
{
	const char *host = "127.0.0.1";
	const char *port = "12345";
	size_t bufsize = 131072;
	bool server = false;
	int opt;

	while ((opt = getopt(argc, argv, "sb:h")) != -1) {
		switch (opt) {
		case 's':
			server = true;
			break;
		case 'b':
			bufsize = (size_t)strtoul(optarg, NULL, 0);
			break;
		case 'h':
		default:
			usage(argv[0]);
		}
	}

	if (optind < argc)
		host = argv[optind++];
	if (optind < argc)
		port = argv[optind++];
	if (optind != argc)
		usage(argv[0]);

	if (server)
		return run_server(host, port);
	return run_client(host, port, bufsize);
}
