#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>

// 类型定义
typedef unsigned short __u16;
typedef unsigned char __u8;
typedef unsigned int __u32;

// 常量定义
#ifndef TCP_MD5SIG
#define TCP_MD5SIG 14
#endif

#ifndef TCP_MD5SIG_MAXKEYLEN
#define TCP_MD5SIG_MAXKEYLEN 80
#endif

// 设置 TCP MD5 签名
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

	printf("Set TCP_MD5SIG for %s\n", peer_ip);
	return 0;
}

// 服务端函数
void run_server(const char *bind_ip, int port, const char *client_ip, const char *key) {
	int server_fd, client_fd;
	struct sockaddr_in server_addr, client_addr;
	socklen_t client_len = sizeof(client_addr);
	char buffer[1024];

	// 创建套接字
	if ((server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP)) < 0) {
		perror("Server socket creation failed");
		exit(EXIT_FAILURE);
	}

	// 设置 SO_REUSEADDR 选项
	int opt = 1;
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
		perror("setsockopt(SO_REUSEADDR) failed");
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	// 设置 TCP MD5 签名（针对特定客户端）
	if (set_tcp_md5sig(server_fd, client_ip, key) != 0) {
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	// 配置服务器地址
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	inet_pton(AF_INET, bind_ip, &server_addr.sin_addr);

	// 绑定套接字
	if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("Server bind failed");
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	// 开始监听
	if (listen(server_fd, 5) < 0) {
		perror("Server listen failed");
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	printf("Server listening on %s:%d, waiting for client %s...\n", bind_ip, port, client_ip);

	// 接受客户端连接
	if ((client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len)) < 0) {
		perror("Server accept failed");
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	char client_ip_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_str, INET_ADDRSTRLEN);
	printf("Accepted connection from %s\n", client_ip_str);

	// 接收客户端消息
	ssize_t bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
	if (bytes_received < 0) {
		perror("Server recv failed");
	} else {
		buffer[bytes_received] = '\0';
		printf("Received from client: %s\n", buffer);
	}

	// 发送回复
	const char *response = "Hello from server!";
	if (send(client_fd, response, strlen(response), 0) < 0) {
		perror("Server send failed");
	} else {
		printf("Sent response to client\n");
	}

	// 清理
	close(client_fd);
	close(server_fd);
}

// 客户端函数
void run_client(const char *server_ip, int port, const char *key) {
	int sockfd;
	struct sockaddr_in server_addr;
	char buffer[1024];

	// 创建套接字
	if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP)) < 0) {
		perror("Client socket creation failed");
		exit(EXIT_FAILURE);
	}

	// 设置 TCP MD5 签名
	if (set_tcp_md5sig(sockfd, server_ip, key) != 0) {
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	// 配置服务器地址
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	inet_pton(AF_INET, server_ip, &server_addr.sin_addr);

	// 连接到服务器
	printf("Connecting to server %s:%d...\n", server_ip, port);
	if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("Client connect failed");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	printf("Connected to server\n");

	// 发送消息
	const char *message = "Hello from client!";
	if (send(sockfd, message, strlen(message), 0) < 0) {
		perror("Client send failed");
	} else {
		printf("Sent message to server\n");
	}

	// 接收回复
	ssize_t bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
	if (bytes_received < 0) {
		perror("Client recv failed");
	} else {
		buffer[bytes_received] = '\0';
		printf("Received from server: %s\n", buffer);
	}

	// 清理
	close(sockfd);
}

// 打印用法信息
void print_usage(const char *prog_name) {
	printf("Usage:\n");
	printf("  Server: %s server <bind_ip> <port> <client_ip> <key>\n", prog_name);
	printf("  Client: %s client <server_ip> <port> <key>\n", prog_name);
	printf("\nExample:\n");
	printf("  Terminal 1: %s server 0.0.0.0 12345 127.0.0.1 MySecretKey\n", prog_name);
	printf("  Terminal 2: %s client 127.0.0.1 12345 MySecretKey\n", prog_name);
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	// 忽略 SIGPIPE 信号
	signal(SIGPIPE, SIG_IGN);

	if (strcmp(argv[1], "server") == 0) {
		if (argc != 6) {
			print_usage(argv[0]);
			return EXIT_FAILURE;
		}
		const char *bind_ip = argv[2];
		int port = atoi(argv[3]);
		const char *client_ip = argv[4];
		const char *key = argv[5];

		run_server(bind_ip, port, client_ip, key);
	} 
	else if (strcmp(argv[1], "client") == 0) {
		if (argc != 5) {
			print_usage(argv[0]);
			return EXIT_FAILURE;
		}
		const char *server_ip = argv[2];
		int port = atoi(argv[3]);
		const char *key = argv[4];

		run_client(server_ip, port, key);
	} 
	else {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
