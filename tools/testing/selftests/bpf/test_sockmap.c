// SPDX-License-Identifier: GPL-2.0
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <linux/tls.h>
#include <assert.h>
#include <bpf/bpf.h>

#include "bpf_util.h"
#include "cgroup_helpers.h"

# define TCP_ULP 31

/* randomly selected ports for testing on lo */
#define S1_PORT 10000
#define S2_PORT 10001

/* global sockets */
int s1, s2, c1, c2, p1, p2;
int map_fd[3];
struct bpf_map *maps[3];
struct bpf_program *progs[4];
struct bpf_link *links[4];

char *map_names[] = {
	"sock_map",
	"sock_skb_opts",
	"tls_sock_map",
};

static int sockmap_init_ktls(int s)
{
	struct tls12_crypto_info_aes_gcm_128 tls_tx = {
		.info = {
			.version     = TLS_1_2_VERSION,
			.cipher_type = TLS_CIPHER_AES_GCM_128,
		},
	};
	struct tls12_crypto_info_aes_gcm_128 tls_rx = {
		.info = {
			.version     = TLS_1_2_VERSION,
			.cipher_type = TLS_CIPHER_AES_GCM_128,
		},
	};
	int so_buf = 6553500;
	int err;

	err = setsockopt(s, 6, TCP_ULP, "tls", sizeof("tls"));
	if (err)
		return -EINVAL;
	err = setsockopt(s, SOL_TLS, TLS_TX, (void *)&tls_tx, sizeof(tls_tx));
	if (err)
		return -EINVAL;
	err = setsockopt(s, SOL_TLS, TLS_RX, (void *)&tls_rx, sizeof(tls_rx));
	if (err)
		return -EINVAL;
	err = setsockopt(s, SOL_SOCKET, SO_SNDBUF, &so_buf, sizeof(so_buf));
	if (err)
		return -EINVAL;
	err = setsockopt(s, SOL_SOCKET, SO_RCVBUF, &so_buf, sizeof(so_buf));
	if (err)
		return -EINVAL;

	return 0;
}

static int sockmap_init_sockets(void)
{
	int i, err, one = 1;
	struct sockaddr_in addr;
	int *fds[4] = {&s1, &s2, &c1, &c2};

	s1 = s2 = p1 = p2 = c1 = c2 = 0;

	/* Init sockets */
	for (i = 0; i < 4; i++) {
		*fds[i] = socket(AF_INET, SOCK_STREAM, 0);
		if (*fds[i] < 0) {
			perror("socket s1 failed()");
			return errno;
		}
	}

	/* Allow reuse */
	for (i = 0; i < 2; i++) {
		err = setsockopt(*fds[i], SOL_SOCKET, SO_REUSEADDR,
				 (char *)&one, sizeof(one));
		if (err) {
			perror("setsockopt failed()");
			return errno;
		}
	}

	/* Non-blocking sockets */
	for (i = 0; i < 2; i++) {
		err = ioctl(*fds[i], FIONBIO, (char *)&one);
		if (err < 0) {
			perror("ioctl s1 failed()");
			return errno;
		}
	}

	/* Bind server sockets */
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	addr.sin_port = htons(S1_PORT);
	err = bind(s1, (struct sockaddr *)&addr, sizeof(addr));
	if (err < 0) {
		perror("bind s1 failed()");
		return errno;
	}

	addr.sin_port = htons(S2_PORT);
	err = bind(s2, (struct sockaddr *)&addr, sizeof(addr));
	if (err < 0) {
		perror("bind s2 failed()");
		return errno;
	}

	/* Listen server sockets */
	addr.sin_port = htons(S1_PORT);
	err = listen(s1, 32);
	if (err < 0) {
		perror("listen s1 failed()");
		return errno;
	}

	addr.sin_port = htons(S2_PORT);
	err = listen(s2, 32);
	if (err < 0) {
		perror("listen s1 failed()");
		return errno;
	}

	/* Initiate Connect */
	addr.sin_port = htons(S1_PORT);
	err = connect(c1, (struct sockaddr *)&addr, sizeof(addr));
	if (err < 0 && errno != EINPROGRESS) {
		perror("connect c1 failed()");
		return errno;
	}

	addr.sin_port = htons(S2_PORT);
	err = connect(c2, (struct sockaddr *)&addr, sizeof(addr));
	if (err < 0 && errno != EINPROGRESS) {
		perror("connect c2 failed()");
		return errno;
	} else if (err < 0) {
		err = 0;
	}

	/* Accept Connecrtions */
	p1 = accept(s1, NULL, NULL);
	if (p1 < 0) {
		perror("accept s1 failed()");
		return errno;
	}

	p2 = accept(s2, NULL, NULL);
	if (p2 < 0) {
		perror("accept s1 failed()");
		return errno;
	}

	return 0;
}

struct msg_stats {
	size_t bytes_sent;
	size_t bytes_recvd;
};

static void msg_free_iov(struct msghdr *msg)
{
	int i;

	for (i = 0; i < msg->msg_iovlen; i++)
		free(msg->msg_iov[i].iov_base);
	free(msg->msg_iov);
	msg->msg_iov = NULL;
	msg->msg_iovlen = 0;
}

static int msg_alloc_iov(struct msghdr *msg, bool xmit)
{
	unsigned char k = 0;
	struct iovec *iov;
	int iov_count = 1;
	int i, j;

	iov = calloc(iov_count, sizeof(struct iovec));
	if (!iov)
		return errno;

	for (i = 0; i < iov_count; i++) {
		unsigned char *d = calloc(100, sizeof(char));

		if (!d) {
			fprintf(stderr, "iov_count %i/%i OOM\n", i, iov_count);
			goto unwind_iov;
		}
		iov[i].iov_base = d;
		iov[i].iov_len = 100;

		if (xmit) {
			for (j = 0; j < 100; j++)
				d[j] = k++;
		}
	}

	msg->msg_iov = iov;
	msg->msg_iovlen = iov_count;

	return 0;
unwind_iov:
	for (i--; i >= 0 ; i--)
		free(msg->msg_iov[i].iov_base);
	return -ENOMEM;
}

static int msg_verify_data(struct msghdr *msg, int size, int chunk_sz)
{
	int i, j = 0, bytes_cnt = 0;
	unsigned char k = 0;

	for (i = 0; i < msg->msg_iovlen; i++) {
		unsigned char *d = msg->msg_iov[i].iov_base;

		/* Special case test for skb ingress + ktls */
		if (i == 0) {
			if (msg->msg_iov[i].iov_len < 4)
				return -EIO;
			if (memcmp(d, "PASS", 4) != 0) {
				fprintf(stderr,
					"detected skb data error with skb ingress update @iov[%i]:%i \"%02x %02x %02x %02x\" != \"PASS\"\n",
					i, 0, d[0], d[1], d[2], d[3]);
				return -EIO;
			}
			j = 4; /* advance index past PASS header */
		}

		for (; j < msg->msg_iov[i].iov_len && size; j++) {
			if (d[j] != k++) {
				fprintf(stderr,
					"detected data corruption @iov[%i]:%i %02x != %02x, %02x ?= %02x\n",
					i, j, d[j], k - 1, d[j+1], k);
				return -EIO;
			}
			bytes_cnt++;
			if (bytes_cnt == chunk_sz) {
				k = 0;
				bytes_cnt = 0;
			}
			size--;
		}
	}
	return 0;
}

static int msg_loop(struct msg_stats *s, bool tx, bool nonblock)
{
	struct msghdr msg = {0};
	int err;

	err = msg_alloc_iov(&msg, tx);
	if (err)
		goto out_errno;

	if (tx) {
		int sent;

		sent = sendmsg(c1, &msg, MSG_NOSIGNAL);
		if (sent > 0)
			s->bytes_sent += sent;
	} else {
		int slct, recv, max_fd = p2;
		struct timeval timeout = { .tv_sec = 3 };
		fd_set r;

		if (nonblock && fcntl(p2, F_SETFL, O_NONBLOCK))
			goto out_errno;

		/* FD sets */
		FD_ZERO(&r);
		FD_SET(p2, &r);

		while (s->bytes_recvd < 100) {
			slct = select(max_fd + 1, &r, NULL, NULL, &timeout);
			if (slct == -1) {
				perror("select()");
				goto out_errno;
			} else if (!slct) {
				errno = -EIO;
				goto out_errno;
			}

			errno = 0;

			recv = recvmsg(p2, &msg, MSG_NOSIGNAL);
			fprintf(stderr, "recv=%d errno=%d\n", recv, errno);
			if (recv < 0) {
				if (errno != EWOULDBLOCK) {
					perror("recv failed()");
					goto out_errno;
				}
			}

			if (recv > 0)
				s->bytes_recvd += recv;

			if (recv > 0) {
				errno = msg_verify_data(&msg, recv, 100);
				if (errno) {
					perror("data verify msg failed");
					goto out_errno;
				}
			}
		}
	}

	msg_free_iov(&msg);
	return err;
out_errno:
	msg_free_iov(&msg);
	return errno;
}

static int sendmsg_test(bool nonblock)
{
	int txpid, rxpid, err = 0;
	struct msg_stats s = {0};
	int rx_status, tx_status;

	/* Redirecting into non-TLS socket which sends into a TLS
	 * socket is not a valid test. So in this case lets not
	 * enable kTLS but still run the test.
	 */
	err = sockmap_init_ktls(p2);
	if (err)
		return err;
	err = sockmap_init_ktls(c1);
	if (err)
		return err;

	rxpid = fork();
	if (rxpid == 0) {
		err = msg_loop(&s, false, nonblock);
		exit(err ? 1 : 0);
	} else if (rxpid == -1) {
		return errno;
	}

	txpid = fork();
	if (txpid == 0) {
		err = msg_loop(&s, true, nonblock);
		exit(err ? 1 : 0);
	} else if (txpid == -1) {
		return errno;
	}

	assert(waitpid(rxpid, &rx_status, 0) == rxpid);
	assert(waitpid(txpid, &tx_status, 0) == txpid);
	if (WIFEXITED(rx_status)) {
		err = WEXITSTATUS(rx_status);
		if (err)
			goto out;
	}
	if (WIFEXITED(tx_status)) {
		err = WEXITSTATUS(tx_status);
	}
out:
	return err;
}

static int prog_attach(int prog_fd_id, int map_fd_id)
{
	links[map_fd_id] = bpf_program__attach_sockmap(progs[prog_fd_id], map_fd[map_fd_id]);
	if (!links[map_fd_id]) {
		fprintf(stderr,
			"ERROR: bpf_prog_attach (%s %i->%i): (%s)\n",
			map_names[map_fd_id], bpf_program__fd(progs[prog_fd_id]),
			map_fd[map_fd_id], strerror(errno));
		return -1;
	}
	return 0;
}

static int map_update_elem(int map_fd_id, const int key, const int value)
{
	int err;

	err = bpf_map_update_elem(map_fd[map_fd_id], &key, &value, BPF_ANY);
	if (err) {
		fprintf(stderr,
			"ERROR: bpf_map_update_elem (%s): %d (%s)\n",
			map_names[map_fd_id], err, strerror(errno));
	}
	return err;
}

static int run_options(int cg_fd, bool nonblock, bool ingress)
{
	int i, key, next_key, err, zero = 0;

	err = prog_attach(1, 0);
	if (err)
		return err;

	/* Attach programs to TLS sockmap */
	err = prog_attach(0, 2);
	if (err)
		return err;

	err = prog_attach(2, 2);
	if (err)
		return err;

	/* Attach to cgroups */
	err = bpf_prog_attach(bpf_program__fd(progs[3]), cg_fd, BPF_CGROUP_SOCK_OPS, 0);
	if (err) {
		fprintf(stderr, "ERROR: bpf_prog_attach (groups): %d (%s)\n",
			err, strerror(errno));
		return err;
	}

	err = sockmap_init_sockets();
	if (err)
		goto out;

	err = map_update_elem(2, 0, p2);
	if (ingress)
		err = map_update_elem(1, 1, BPF_F_INGRESS);

	err = sendmsg_test(nonblock);
out:
	/* Detatch and zero all the maps */
	bpf_prog_detach2(bpf_program__fd(progs[3]), cg_fd, BPF_CGROUP_SOCK_OPS);

	for (i = 0; i < ARRAY_SIZE(links); i++) {
		if (links[i])
			bpf_link__detach(links[i]);
	}

	for (i = 0; i < ARRAY_SIZE(map_fd); i++) {
		key = next_key = 0;
		bpf_map_update_elem(map_fd[i], &key, &zero, BPF_ANY);
		while (bpf_map_get_next_key(map_fd[i], &key, &next_key) == 0) {
			bpf_map_update_elem(map_fd[i], &key, &zero, BPF_ANY);
			key = next_key;
		}
	}

	close(s1);
	close(s2);
	close(p1);
	close(p2);
	close(c1);
	close(c2);
	return err;
}

static int populate_progs(void)
{
	struct bpf_program *prog;
	struct bpf_object *obj;
	int i = 0;

	obj = bpf_object__open("test_sockmap_kern.bpf.o");
	bpf_object__load(obj);
	i = 0;
	bpf_object__for_each_program(prog, obj) {
		progs[i] = prog;
		i++;
	}

	for (i = 0; i < ARRAY_SIZE(map_fd); i++) {
		maps[i] = bpf_object__find_map_by_name(obj, map_names[i]);
		map_fd[i] = bpf_map__fd(maps[i]);
		if (map_fd[i] < 0)
			return -1;
	}

	for (i = 0; i < ARRAY_SIZE(links); i++)
		links[i] = NULL;

	return 0;
}

int main(int argc, char **argv)
{
	bool nonblock = true;
	bool ingress=true;
	int err, cg_fd = 0;

	if (argc == 2 && !strcmp(argv[1], "block"))
		nonblock = false;
	if (argc == 2 && !strcmp(argv[1], "noingress"))
		ingress = false;

	cg_fd = cgroup_setup_and_join("/sockmap");
	if (cg_fd < 0)
		return cg_fd;
	err = populate_progs();
	if (err < 0)
		return err;
	run_options(cg_fd, nonblock, ingress);
	close(cg_fd);
	cleanup_cgroup_environment();
	return err;
}
