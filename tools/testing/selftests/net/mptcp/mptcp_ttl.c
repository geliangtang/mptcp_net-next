#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main()
{
	int sockfd;
	int ttl_val;
	socklen_t len = sizeof(ttl_val);

	// 创建UDP套接字
	if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP)) < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	printf("Socket created successfully\n");

	// 获取当前TTL值
	if (getsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl_val, &len) < 0) {
		perror("getsockopt failed");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	printf("Default TTL: %d\n", ttl_val);

	// 设置新TTL值
	int new_ttl = 65;
	if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &new_ttl, sizeof(new_ttl)) < 0) {
		perror("setsockopt failed");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	printf("TTL set to: %d\n", new_ttl);

	// 验证新TTL值
	if (getsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl_val, &len) < 0) {
		perror("getsockopt failed");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	printf("Verified TTL: %d\n", ttl_val);

	close(sockfd);
	return 0;
}
