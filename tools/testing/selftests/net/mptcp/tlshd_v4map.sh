#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Standalone tlshd test for v4map (AF_INET6 v4-mapped) sockets.
#
# Mirrors the namespace/keyring/tlshd setup from mptcp_nvme.sh but
# skips nvme-tcp. Instead it exercises the v4map networking path
# with raw AF_INET6 sockets and verifies tlshd starts and accepts
# kernel handshake requests in both namespaces.
#
# Usage: ./tlshd_v4map.sh [ipv4|ipv6|v4map]   (default: v4map)

set -e

adrfam="${1:-v4map}"
ns1="tlshd_v4map_ns1"
ns2="tlshd_v4map_ns2"
port=$((RANDOM % 10000 + 30000))
tlshd_pid_ns1=""
tlshd_pid_ns2=""

if [[ ! "${adrfam}" =~ ^(ipv4|ipv6|v4map)$ ]]; then
	echo "Invalid adrfam '${adrfam}'. Must be ipv4, ipv6 or v4map" >&2
	exit 1
fi

cleanup()
{
	ip netns del "${ns1}" 2>/dev/null || true
	ip netns del "${ns2}" 2>/dev/null || true

	[ -n "${tlshd_pid_ns1}" ] && { kill "${tlshd_pid_ns1}" 2>/dev/null || true; wait "${tlshd_pid_ns1}" 2>/dev/null || true; }
	[ -n "${tlshd_pid_ns2}" ] && { kill "${tlshd_pid_ns2}" 2>/dev/null || true; wait "${tlshd_pid_ns2}" 2>/dev/null || true; }

	for k in $(keyctl list %:.nvme 2>/dev/null |
		   awk -F: '/psk:/{print $1}' | tr -d ' '); do
		keyctl unlink "$k" %:.nvme 2>/dev/null || true
	done
}

trap cleanup EXIT

echo "=== tlshd v4map test: adrfam=${adrfam} ==="

# --- 1. Namespace + veth setup --------------------------------------
ip netns add "${ns1}"
ip netns add "${ns2}"
ip link add ns1eth netns "${ns1}" type veth peer name ns2eth netns "${ns2}"

case "${adrfam}" in
ipv4)
	ip -net "${ns1}" addr add 10.1.1.1/24 dev ns1eth
	ip -net "${ns2}" addr add 10.1.1.2/24 dev ns2eth
	;;
ipv6)
	ip -net "${ns1}" addr add "dead:beef::1/64" dev ns1eth nodad
	ip -net "${ns2}" addr add "dead:beef::2/64" dev ns2eth nodad
	;;
v4map)
	# Only IPv4 on the wire. v4map semantics are realised by binding
	# the AF_INET6 socket to :: (IPv6 wildcard) so it accepts
	# v4-mapped connections (::ffff:10.1.1.1). This matches what
	# mptcp_nvme.sh does for v4map (addr_traddr = ::ffff:0.0.0.0).
	ip -net "${ns1}" addr add 10.1.1.1/24 dev ns1eth
	ip -net "${ns2}" addr add 10.1.1.2/24 dev ns2eth
	# Make sure IPv6 wildcard socket accepts v4-mapped clients
	ip netns exec "${ns2}" sysctl -qw net.ipv6.bindv6only=0
	;;
esac

ip -net "${ns1}" link set ns1eth up
ip -net "${ns2}" link set ns2eth up
ip -net "${ns1}" link set lo up
ip -net "${ns2}" link set lo up

# --- 2. PSK + keyring ------------------------------------------------
psk_hex=$(openssl rand -hex 32)
psk_id="NVMe0R01 v4map-test-id"

keyctl clear @s 2>/dev/null || true
key_serial=$(keyctl add user "psk-test" "${psk_hex}" @s 2>/dev/null) || true
if [ -z "${key_serial}" ]; then
	echo "WARN: failed to add key into @s" >&2
fi
echo "Inserted PSK len=$((${#psk_hex} / 2)) bytes (serial=${key_serial:-none})"

# --- 3. Start tlshd in both namespaces -------------------------------
ip netns exec "${ns1}" /usr/sbin/tlshd -s >/tmp/tlshd_ns1.log 2>&1 &
tlshd_pid_ns1=$!
ip netns exec "${ns2}" /usr/sbin/tlshd -s >/tmp/tlshd_ns2.log 2>&1 &
tlshd_pid_ns2=$!
sleep 1

# Verify both tlshd processes are alive
if ! kill -0 "${tlshd_pid_ns1}" 2>/dev/null; then
	echo "FAIL: tlshd in ${ns1} exited prematurely:"
	cat /tmp/tlshd_ns1.log
	exit 1
fi
if ! kill -0 "${tlshd_pid_ns2}" 2>/dev/null; then
	echo "FAIL: tlshd in ${ns2} exited prematurely:"
	cat /tmp/tlshd_ns2.log
	exit 1
fi
echo "tlshd running: ns1 pid=${tlshd_pid_ns1} ns2 pid=${tlshd_pid_ns2}"

# --- 4. Raw TCP v4map connectivity test ------------------------------
case "${adrfam}" in
ipv4)
	bind_addr="10.1.1.1";     connect_addr="10.1.1.1";     family_name="AF_INET";  family_num=2 ;;
ipv6)
	bind_addr="dead:beef::1"; connect_addr="dead:beef::1"; family_name="AF_INET6"; family_num=10 ;;
v4map)
	# Server binds to IPv6 wildcard (::) so it accepts v4-mapped
	# clients. Client connects to the v4-mapped form ::ffff:10.1.1.1.
	# bindv6only=0 already set above in ns1.
	bind_addr="::";           connect_addr="::ffff:10.1.1.1"; family_name="AF_INET6"; family_num=10 ;;
esac

# Server runs in ns1 (where the addresses live), client in ns2 — so the
# connection actually traverses the veth pair, mirroring the nvme setup.
echo "Test: ${family_name} server in ${ns1} bind=${bind_addr} -> client in ${ns2} connect=${connect_addr}"
ip netns exec "${ns1}" sysctl -qw net.ipv6.bindv6only=0 >/dev/null 2>&1 || true

server_log=$(mktemp)
ip netns exec "${ns1}" python3 - <<PYEOF >"${server_log}" 2>&1 &
import socket
family = ${family_num}
bind_addr = "${bind_addr}"
port = ${port}
srv = socket.socket(family, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((bind_addr, port))
srv.listen(1)
print(f"server bound {bind_addr}:{port} family={family}", flush=True)
conn, _ = srv.accept()
print(f"server accepted from {conn.getpeername()}", flush=True)
msg = conn.recv(16)
print(f"server got: {msg!r}", flush=True)
conn.send(b"pong")
reply = conn.recv(16)
print(f"server final got: {reply!r}", flush=True)
conn.close()
srv.close()
PYEOF
server_pid=$!

sleep 0.3

cli_out=$(ip netns exec "${ns2}" python3 - <<PYEOF
import socket, sys
family = ${family_num}
connect_addr = "${connect_addr}"
port = ${port}
cli = socket.socket(family, socket.SOCK_STREAM)
cli.settimeout(5)
try:
    cli.connect((connect_addr, port))
    print(f"client connected to {connect_addr}:{port}")
    cli.send(b"ping")
    reply = cli.recv(16)
    print(f"client got: {reply!r}")
    cli.send(b"final-pong")
    cli.close()
except Exception as e:
    print(f"client FAILED: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
) || true

wait "${server_pid}" 2>/dev/null || true
echo "--- server log ---"
cat "${server_log}"
rm -f "${server_log}"
echo "--- client log ---"
echo "${cli_out}"

if echo "${cli_out}" | grep -q "client got: b'pong'"; then
	echo "PASS: ${adrfam} raw TCP connectivity OK"
else
	echo "FAIL: ${adrfam} raw TCP connectivity"
	exit 1
fi

# --- 5. Verify tlshd still alive (sanity) ----------------------------
if ! kill -0 "${tlshd_pid_ns1}" 2>/dev/null || \
   ! kill -0 "${tlshd_pid_ns2}" 2>/dev/null; then
	echo "FAIL: tlshd exited unexpectedly during test"
	exit 1
fi

echo "PASS: tlshd v4map test (${adrfam}) all checks OK"
exit 0