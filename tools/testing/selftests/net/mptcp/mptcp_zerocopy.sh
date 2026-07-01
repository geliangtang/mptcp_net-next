#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# mptcp_zerocopy.sh: drive the standalone mptcp_zerocopy binary in a
# loopback-style smoke test. Spawns the server in the background,
# waits for it to be ready, runs the client and reports the result.
#
# Usage:
#   ./mptcp_zerocopy.sh                # default 1MB payload
#   ./mptcp_zerocopy.sh -b 1048576     # explicit payload size
#   ./mptcp_zerocopy.sh -b 65536 127.0.0.1 12346
#
# Defaults match the example in the selftest header:
#   ./mptcp_zerocopy -s 127.0.0.1 12345
#   ./mptcp_zerocopy -b 1048576 127.0.0.1 12345

set -u

KSFT_PASS=0
KSFT_FAIL=1

mptcp_zerocopy_bin="$(dirname "${0}")/mptcp_zerocopy"
if [ ! -x "${mptcp_zerocopy_bin}" ]; then
	echo "FAIL: ${mptcp_zerocopy_bin} not built"
	exit ${KSFT_FAIL}
fi

host="127.0.0.1"
port="12345"
bufsize="1048576"

usage() {
	echo "Usage: $0 [-h] [-b bufsize] [host] [port]"
	echo "  -h        this help"
	echo "  -b bytes  payload size (default: 1048576)"
	echo "  host      server address (default: 127.0.0.1)"
	echo "  port      server port    (default: 12345)"
}

while getopts "hb:" opt; do
	case "${opt}" in
		h) usage; exit ${KSFT_PASS} ;;
		b) bufsize="${OPTARG}" ;;
		?) usage; exit ${KSFT_FAIL} ;;
	esac
done
shift $((OPTIND - 1))

if [ $# -ge 1 ]; then host="$1"; fi
if [ $# -ge 2 ]; then port="$2"; fi
if [ $# -gt 2 ]; then usage; exit ${KSFT_FAIL}; fi

server_pid=
cleanup() {
	if [ -n "${server_pid}" ]; then
		kill "${server_pid}" 2>/dev/null
		wait "${server_pid}" 2>/dev/null
	fi
}
trap cleanup EXIT

echo "INFO: starting mptcp_zerocopy server on ${host}:${port}"
"${mptcp_zerocopy_bin}" -s "${host}" "${port}" &
server_pid=$!

# Give the server a moment to bind+listen; loop until /proc shows it
# listening, or fail after ~2s.
ready=0
for _ in $(seq 1 20); do
	if ss -lnt 2>/dev/null | grep -qE "[\" ]${host}:${port}[[:space:]]"; then
		ready=1
		break
	fi
	sleep 0.1
done

if [ "${ready}" -ne 1 ]; then
	echo "FAIL: server did not become ready on ${host}:${port}"
	exit ${KSFT_FAIL}
fi

echo "INFO: running mptcp_zerocopy client with -b ${bufsize}"
"${mptcp_zerocopy_bin}" -b "${bufsize}" "${host}" "${port}"
rc=$?

if [ "${rc}" -ne 0 ]; then
	echo "FAIL: mptcp_zerocopy client exited with ${rc}"
	exit ${KSFT_FAIL}
fi

echo "PASS: mptcp_zerocopy completed successfully"
exit ${KSFT_PASS}