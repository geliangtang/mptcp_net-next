#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Test MPTCP TFO SIOCINQ overflow bug

set -e

TEST_DIR="$(dirname "$0")"
TEST_PROG="$TEST_DIR/test_tfo_inq"

# Build test program
if [ ! -f "$TEST_PROG" ] || [ "$TEST_PROG.c" -nt "$TEST_PROG" ]; then
	echo "Building test program..."
	gcc -o "$TEST_PROG" "$TEST_PROG.c" -Wall
fi

# Check and enable TCP Fast Open
echo "=== TCP Fast Open 状态 ==="
tfo_val=$(cat /proc/sys/net/ipv4/tcp_fastopen)
echo "tcp_fastopen: $tfo_val"

if [ "$tfo_val" != "3" ]; then
	echo "Enabling full TFO support (client + server)..."
	echo 3 | sudo tee /proc/sys/net/ipv4/tcp_fastopen >/dev/null
	echo "tcp_fastopen is now: $(cat /proc/sys/net/ipv4/tcp_fastopen)"
fi

# Check MPTCP status
echo ""
echo "=== MPTCP 状态 ==="
if [ -f /proc/sys/net/mptcp/enabled ]; then
	echo "mptcp enabled: $(cat /proc/sys/net/mptcp/enabled)"
else
	echo "mptcp enabled: N/A"
fi

echo ""
echo "=================================="

# Run test
echo "Running MPTCP TFO SIOCINQ test..."
echo "=================================="
"$TEST_PROG"
exit_code=$?

exit $exit_code
