gcc -o mptcp_md5_comm mptcp_md5_comm.c
./mptcp_md5_comm server 0.0.0.0 12345 127.0.0.1 MySecretKey &
./mptcp_md5_comm client 127.0.0.1 12345 MySecretKey
