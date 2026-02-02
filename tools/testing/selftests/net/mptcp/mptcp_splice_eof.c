#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/sendfile.h>

#define PORT 9999
#define TEST_FILE "test_splice.bin"

// 创建测试文件
static int create_test_file(size_t size)
{
    FILE *fp = fopen(TEST_FILE, "wb");
    if (!fp) {
        perror("fopen");
        return -1;
    }
    
    for (size_t i = 0; i < size; i++) {
        fputc('A' + (i % 26), fp);
    }
    
    fclose(fp);
    
    struct stat st;
    if (stat(TEST_FILE, &st) == 0) {
        printf("Created file: %s (%ld bytes)\n", TEST_FILE, st.st_size);
    }
    
    return 0;
}

// 最简化的MPTCP splice_eof测试
void test_mptcp_splice_eof_simple(void)
{
    printf("=== Simple MPTCP splice_eof test ===\n");
    
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    // 创建MPTCP server socket
    server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
    if (server_fd < 0) {
        perror("socket(MPTCP)");
        return;
    }
    
    // 设置SO_REUSEADDR
    int reuse = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    
    // 绑定地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        return;
    }
    
    if (listen(server_fd, 5) < 0) {
        perror("listen");
        close(server_fd);
        return;
    }
    
    printf("MPTCP Server listening on port %d\n", PORT);
    
    // 创建512字节的测试文件
    if (create_test_file(512) < 0) {
        close(server_fd);
        return;
    }
    
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        close(server_fd);
        unlink(TEST_FILE);
        return;
    }
    
    if (pid == 0) {
        // 客户端
        sleep(1);
        
        int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
        if (sockfd < 0) {
            perror("client socket(MPTCP)");
            exit(EXIT_FAILURE);
        }
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(PORT);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        
        if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("connect");
            close(sockfd);
            exit(EXIT_FAILURE);
        }
        
        printf("Client: Connected\n");
        
        // 接收数据
        char buffer[1024];
        ssize_t total = 0;
        while (1) {
            ssize_t n = read(sockfd, buffer, sizeof(buffer));
            if (n > 0) {
                total += n;
            } else if (n == 0) {
                printf("Client: Received total %zd bytes\n", total);
                break;
            } else {
                perror("read");
                break;
            }
        }
        
        close(sockfd);
        exit(EXIT_SUCCESS);
        
    } else {
        // 服务器
        printf("Server: Waiting for connection...\n");
        
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) {
            perror("accept");
            close(server_fd);
            waitpid(pid, NULL, 0);
            unlink(TEST_FILE);
            return;
        }
        
        printf("Server: Accepted connection\n");
        
        // 打开测试文件
        int file_fd = open(TEST_FILE, O_RDONLY);
        if (file_fd < 0) {
            perror("open test file");
            close(client_fd);
            close(server_fd);
            waitpid(pid, NULL, 0);
            unlink(TEST_FILE);
            return;
        }
        
        struct stat st;
        fstat(file_fd, &st);
        printf("Server: File size = %ld bytes\n", st.st_size);
        
        off_t offset = 0;
        
        // 关键：请求1024字节（大于文件大小512字节）
        printf("Server: sendfile with count=1024 (2x file size)\n");
        printf("Server: This should trigger mptcp_splice_eof!\n");
        
        ssize_t sent = sendfile(client_fd, file_fd, &offset, 1024);
        printf("Server: sendfile returned %zd bytes\n", sent);
        
        close(file_fd);
        
        // 等待客户端接收
        sleep(1);
        
        shutdown(client_fd, SHUT_WR);
        close(client_fd);
        close(server_fd);
        
        waitpid(pid, NULL, 0);
        unlink(TEST_FILE);
        
        printf("Server: Test completed\n");
    }
}

int main(void)
{
    printf("========================================\n");
    printf("Simple MPTCP splice_eof trigger test\n");
    printf("========================================\n");
    
    test_mptcp_splice_eof_simple();
    
    printf("\n========================================\n");
    printf("Check kernel logs for:\n");
    printf("  - splice_direct_to_actor\n");
    printf("  - do_splice_read ret=512 then ret=0\n");
    printf("  - read_failure ret=0 more=0 len=512 bytes=512\n");
    printf("  - call do_splice_eof\n");
    printf("  - MPTCP: mptcp_splice_eof  <-- SUCCESS!\n");
    printf("========================================\n");
    
    return 0;
}
