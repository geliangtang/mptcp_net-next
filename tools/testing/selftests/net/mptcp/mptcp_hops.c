#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main()
{
	int sockfd;
	int hop_limit;
	socklen_t len = sizeof(hop_limit);

	// 创建IPv6 UDP套接字
	if ((sockfd = socket(AF_INET6, SOCK_STREAM, IPPROTO_MPTCP)) < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}
	printf("IPv6 socket created successfully\n");

	// 获取当前单播跳数限制
	if (getsockopt(sockfd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
				&hop_limit, &len) < 0) {
		perror("getsockopt failed");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	printf("Default unicast hop limit: %d\n", hop_limit);

	// 设置新的跳数限制
	int new_hop_limit = 42;
	if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
				&new_hop_limit, sizeof(new_hop_limit)) < 0) {
		perror("setsockopt failed");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	printf("Unicast hop limit set to: %d\n", new_hop_limit);

	// 验证新设置
	if (getsockopt(sockfd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
				&hop_limit, &len) < 0) {
		perror("getsockopt failed");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	printf("Verified unicast hop limit: %d\n", hop_limit);

	close(sockfd);
	return 0;
}
