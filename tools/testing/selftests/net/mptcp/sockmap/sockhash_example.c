#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <sys/syscall.h>

// 定义与Python脚本中相同的sock_key结构
struct sock_key {
	__u64 cookie;
};

// bpf系统调用包装函数
static int bpf_syscall(int cmd, union bpf_attr *attr, unsigned int size) {
	return syscall(SYS_bpf, cmd, attr, size);
}

// 创建BPF映射
static int bpf_create_map(enum bpf_map_type map_type, int key_size, 
		int value_size, int max_entries, int map_flags) {
	union bpf_attr attr = {
		.map_type = map_type,
		.key_size = key_size,
		.value_size = value_size,
		.max_entries = max_entries,
		.map_flags = map_flags,
	};

	return bpf_syscall(BPF_MAP_CREATE, &attr, sizeof(attr));
}

// 更新BPF映射元素
static int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags) {
	union bpf_attr attr = {
		.map_fd = fd,
		.key = (__u64)(unsigned long)key,
		.value = (__u64)(unsigned long)value,
		.flags = flags,
	};

	return bpf_syscall(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int main(int argc, char **argv) {
	int sock_fd, res;
	struct sock_key key = {0};
	int sock_fd_value;
	int map_fd;

	printf("Creating BPF SOCKHASH map...\n");

	// 创建BPF SOCKHASH映射
	map_fd = bpf_create_map(BPF_MAP_TYPE_SOCKHASH, sizeof(struct sock_key), 
			sizeof(int), 65535, 0);

	if (map_fd < 0) {
		fprintf(stderr, "Failed to create BPF SOCKHASH map: %s\n", strerror(errno));
		return 1;
	}

	printf("BPF map created with fd: %d\n", map_fd);

	// 创建socket（与Python脚本中相同）
	sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (sock_fd < 0) {
		if (errno == EPROTONOSUPPORT) {
			printf("MPTCP not supported, trying regular TCP...\n");
			sock_fd = socket(AF_INET, SOCK_STREAM, 0);
		}
		if (sock_fd < 0) {
			perror("socket");
			close(map_fd);
			return 1;
		}
	}

	// 设置SO_REUSEADDR选项，允许多次绑定
	int opt = 1;
	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		perror("setsockopt SO_REUSEADDR");
		// 继续执行，这不是致命错误
	}

	// 绑定socket到地址 - 与Python脚本完全一样使用127.0.0.0:7890
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(7890);

	// 注意：127.0.0.0可能有问题，我们先用127.0.0.0尝试，不行再用127.0.0.1
	if (inet_pton(AF_INET, "127.0.0.0", &addr.sin_addr) <= 0) {
		perror("inet_pton for 127.0.0.0");
		// 如果失败，尝试INADDR_ANY
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
	}

	if (bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		printf("bind failed, trying with INADDR_ANY...\n");

		// 尝试使用INADDR_ANY
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
		if (bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			perror("bind with INADDR_ANY");

			// 尝试其他端口
			printf("Trying port 7891...\n");
			addr.sin_port = htons(7891);
			if (bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
				perror("bind port 7891");
				close(sock_fd);
				close(map_fd);
				return 1;
			}
		}
	}

	// 监听socket
	if (listen(sock_fd, 20) < 0) {
		perror("listen");
		close(sock_fd);
		close(map_fd);
		return 1;
	}

	printf("Socket created and listening, fd: %d\n", sock_fd);

	// 更新BPF映射
	sock_fd_value = sock_fd;

	printf("Attempting to update BPF map with key.cookie=0, value=%d...\n", sock_fd_value);

	// 更新BPF映射元素
	res = bpf_map_update_elem(map_fd, &key, &sock_fd_value, 0);
	if (res < 0) {
		printf("bpf_map_update_elem failed: %d (errno: %d - %s)\n", 
				res, errno, strerror(errno));

		// 检查是否是预期的-95错误
		if (errno == EOPNOTSUPP || res == -95) {
			printf("SUCCESS: Got expected error -95 (EOPNOTSUPP) due to missing psock_update_sk_prot implementation\n");
			printf("This matches the Python script's behavior\n");
		} else if (errno == ENOTSUP) {
			printf("SUCCESS: Got expected error -95 (ENOTSUP) due to missing psock_update_sk_prot implementation\n");
			printf("This matches the Python script's behavior\n");
		} else {
			printf("Got unexpected error\n");
		}
	} else {
		printf("Update successful: %d (unexpected - Python script expects failure)\n", res);
	}

	// 保持socket打开一段时间以便观察
	printf("Keeping socket open for 5 seconds...\n");
	sleep(5);

	// 清理资源
	printf("Cleaning up...\n");
	close(sock_fd);
	close(map_fd);

	return 0;
}
