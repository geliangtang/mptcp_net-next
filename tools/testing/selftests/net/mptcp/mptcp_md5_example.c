#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>  // For TCP_MD5SIG
#include <arpa/inet.h>
#include <errno.h>

// 类型定义
typedef unsigned short __u16;
typedef unsigned char __u8;
typedef unsigned int __u32;

// 常量定义
#ifndef TCP_MD5SIG_EXT
#define TCP_MD5SIG_EXT 34
#endif

#ifndef TCP_MD5SIG_MAXKEYLEN
#define TCP_MD5SIG_MAXKEYLEN 160
#endif

#ifndef TCP_MD5SIG_FLAG_IFINDEX
#define TCP_MD5SIG_FLAG_IFINDEX (1 << 0)
#endif

// 地址存储结构
struct __kernel_sockaddr_storage {
	unsigned short ss_family;
	char __data[128 - sizeof(unsigned short)];
};

// 扩展MD5签名结构
struct tcp_md5sig_ext {
	struct __kernel_sockaddr_storage tcpm_addr;
	__u16   __tcpm_pad1;
	__u16   tcpm_keylen;
	__u8    tcpm_key[TCP_MD5SIG_MAXKEYLEN];
	__u32   tcpm_flags;
	__u32   tcpm_ifindex;
};

// 设置传统TCP_MD5SIG
int set_tcp_md5sig(int sockfd, const char *peer_ip, const char *key) {
	struct tcp_md5sig md5sig;
	memset(&md5sig, 0, sizeof(md5sig));

	// 设置目标地址
	struct sockaddr_in *addr = (struct sockaddr_in *)&md5sig.tcpm_addr;
	addr->sin_family = AF_INET;
	if (inet_pton(AF_INET, peer_ip, &addr->sin_addr) != 1) {
		perror("inet_pton failed");
		return -1;
	}

	// 设置密钥
	size_t key_len = strlen(key);
	if (key_len > sizeof(md5sig.tcpm_key)) {
		fprintf(stderr, "Key too long (max %zu bytes)\n", sizeof(md5sig.tcpm_key));
		return -1;
	}
	memcpy(md5sig.tcpm_key, key, key_len);
	md5sig.tcpm_keylen = key_len;

	// 设置套接字选项
	if (setsockopt(sockfd, IPPROTO_TCP, TCP_MD5SIG, &md5sig, sizeof(md5sig))) {
		perror("setsockopt(TCP_MD5SIG) failed");
		return -1;
	}

	printf("Successfully set TCP_MD5SIG for %s\n", peer_ip);
	return 0;
}

// 设置扩展TCP_MD5SIG_EXT
int set_tcp_md5sig_ext(int sockfd, const char *peer_ip, const char *key, int ifindex) {
	struct tcp_md5sig_ext md5ext;
	memset(&md5ext, 0, sizeof(md5ext));

	// 设置目标地址
	struct sockaddr_in *addr = (struct sockaddr_in *)&md5ext.tcpm_addr;
	addr->sin_family = AF_INET;
	if (inet_pton(AF_INET, peer_ip, &addr->sin_addr) != 1) {
		perror("inet_pton failed");
		return -1;
	}

	// 设置密钥
	size_t key_len = strlen(key);
	if (key_len > TCP_MD5SIG_MAXKEYLEN) {
		fprintf(stderr, "Key too long (max %d bytes)\n", TCP_MD5SIG_MAXKEYLEN);
		return -1;
	}
	memcpy(md5ext.tcpm_key, key, key_len);
	md5ext.tcpm_keylen = key_len;

	// 设置接口索引
	md5ext.tcpm_ifindex = ifindex;
	md5ext.tcpm_flags = TCP_MD5SIG_FLAG_IFINDEX;

	// 设置套接字选项
	if (setsockopt(sockfd, IPPROTO_TCP, TCP_MD5SIG_EXT, &md5ext, sizeof(md5ext))) {
		perror("setsockopt(TCP_MD5SIG_EXT) failed");
		return -1;
	}

	printf("Successfully set TCP_MD5SIG_EXT for %s (ifindex %d)\n", peer_ip, ifindex);
	return 0;
}

int main() {
	int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (sockfd < 0) {
		perror("Socket creation failed");
		return EXIT_FAILURE;
	}

	const char *peer_ip = "127.0.0.1";  // 替换为目标IP
	const char *key = "MySecretKey123";
	int ifindex = 2;  // 替换为实际接口索引

	// 设置传统TCP_MD5SIG
	if (set_tcp_md5sig(sockfd, peer_ip, key) != 0) {
		fprintf(stderr, "Traditional TCP_MD5SIG setup failed\n");
	}

	// 设置扩展TCP_MD5SIG_EXT
	if (set_tcp_md5sig_ext(sockfd, peer_ip, key, ifindex) != 0) {
		fprintf(stderr, "Extended TCP_MD5SIG_EXT setup failed\n");
	}

	close(sockfd);
	return EXIT_SUCCESS;
}
