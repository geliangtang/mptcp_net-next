#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>        /* For IP_TOS */
#include <netinet/ip6.h>       /* For IPV6_TCLASS */
#include <arpa/inet.h>

// 显示 DSCP 值的名称（简化版）
const char *dscp_name(int value) {
	switch (value) {
		case 0x00: return "BE (Best Effort)";
		case 0x28: return "AF11 (Assured Forwarding)";
		case 0xb8: return "EF (Expedited Forwarding)";
		case 0xc0: return "CS6 (Network Control)";
		default:   return "Unknown";
	}
}

int ipv4_example() {
	int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (sockfd < 0) {
		perror("IPv4 socket creation failed");
		return -1;
	}

	// 获取默认 TOS 值
	int tos_value;
	socklen_t len = sizeof(tos_value);
	if (getsockopt(sockfd, IPPROTO_IP, IP_TOS, &tos_value, &len) < 0) {
		perror("getsockopt(IP_TOS) failed");
		close(sockfd);
		return -1;
	}
	printf("IPv4 Default TOS: 0x%02x (%s)\n", tos_value, dscp_name(tos_value));

	// 设置新的 TOS 值 (EF: Expedited Forwarding)
	int new_tos = 0xb8;  // EF DSCP (0x2e << 2 = 0xb8)
	if (setsockopt(sockfd, IPPROTO_IP, IP_TOS, &new_tos, sizeof(new_tos)) < 0) {
		perror("setsockopt(IP_TOS) failed");
		close(sockfd);
		return -1;
	}
	printf("Set IPv4 TOS to: 0x%02x (EF)\n", new_tos);

	// 验证设置
	if (getsockopt(sockfd, IPPROTO_IP, IP_TOS, &tos_value, &len) < 0) {
		perror("getsockopt(IP_TOS) failed");
		close(sockfd);
		return -1;
	}
	printf("IPv4 Current TOS: 0x%02x (%s)\n\n", tos_value, dscp_name(tos_value));

	close(sockfd);
	return 0;
}

int ipv6_example() {
	int sockfd = socket(AF_INET6, SOCK_STREAM, IPPROTO_MPTCP);
	if (sockfd < 0) {
		perror("IPv6 socket creation failed");
		return -1;
	}

	// 获取默认 Traffic Class
	int tclass_value;
	socklen_t len = sizeof(tclass_value);
	if (getsockopt(sockfd, IPPROTO_IPV6, IPV6_TCLASS, &tclass_value, &len) < 0) {
		perror("getsockopt(IPV6_TCLASS) failed");
		close(sockfd);
		return -1;
	}
	printf("IPv6 Default Traffic Class: 0x%02x (%s)\n", tclass_value, dscp_name(tclass_value));

	// 设置新的 Traffic Class (CS6: Network Control)
	int new_tclass = 0xc0;  // CS6 DSCP (0x30 << 2 = 0xc0)
	if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_TCLASS, &new_tclass, sizeof(new_tclass)) < 0) {
		perror("setsockopt(IPV6_TCLASS) failed");
		close(sockfd);
		return -1;
	}
	printf("Set IPv6 Traffic Class to: 0x%02x (CS6)\n", new_tclass);

	// 验证设置
	if (getsockopt(sockfd, IPPROTO_IPV6, IPV6_TCLASS, &tclass_value, &len) < 0) {
		perror("getsockopt(IPV6_TCLASS) failed");
		close(sockfd);
		return -1;
	}
	printf("IPv6 Current Traffic Class: 0x%02x (%s)\n\n", tclass_value, dscp_name(tclass_value));

	close(sockfd);
	return 0;
}

int main() {
	printf("=== IPv4 Example (IP_TOS) ===\n");
	if (ipv4_example() != 0) {
		fprintf(stderr, "IPv4 example failed\n");
	}

	printf("=== IPv6 Example (IPV6_TCLASS) ===\n");
	if (ipv6_example() != 0) {
		fprintf(stderr, "IPv6 example failed\n");
	}

	return 0;
}
