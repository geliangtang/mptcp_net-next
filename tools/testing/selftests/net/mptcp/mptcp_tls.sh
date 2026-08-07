#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

. "$(dirname "${0}")/mptcp_lib.sh"

ret=0
ns1=""
pid=""
PERF_DATA="/tmp/mptcp_tls_perf.data"

# This function is used in the cleanup trap
#shellcheck disable=SC2317,SC2329
cleanup()
{
	if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
	fi

	mptcp_lib_ns_exit "$ns1"
}

init()
{
	local max="${1:-4}"

	mptcp_lib_ns_init ns1

	mptcp_lib_pm_nl_set_limits "$ns1" "$max" "$max"

	local i
	for i in $(seq 1 "$max"); do
		mptcp_lib_pm_nl_add_endpoint "$ns1" \
			"127.0.0.1" flags signal port 1000"$i"
	done

	rm -f "$PERF_DATA"
}

mptcp_lib_check_mptcp

trap cleanup EXIT

init
ip -n "${ns1}" mptcp limits
mptcp_lib_pm_nl_show_endpoints "$ns1"

#ip netns exec "$ns1" ./tls -t tls_v4map &
#ip netns exec "$ns1" ./tls -t nonblocking &
#ip netns exec "$ns1" ./tls -t shutdown_reuse &
#ip netns exec "$ns1" ./tls -t multi_chunk_sendfile &
#ip netns exec "$ns1" ./tls -t mutliproc_even \
#			 -t mutliproc_readers \
#			 -t mutliproc_writers \
#			 -t mutliproc_sendpage_even \
#			 -t mutliproc_sendpage_readers \
#			 -t mutliproc_sendpage_writers &
#ip netns exec "$ns1" ./tls \
#-r tls.12_aes_gcm_mptcp.mutliproc_even \
#-r tls.12_aes_gcm_mptcp.mutliproc_readers \
#-r tls.12_aes_gcm_mptcp.mutliproc_writers \
#-r tls.12_aes_gcm_mptcp.mutliproc_sendpage_even \
#-r tls.12_aes_gcm_mptcp.mutliproc_sendpage_readers \
#-r tls.12_aes_gcm_mptcp.mutliproc_sendpage_writers \
#-r tls.13_aes_gcm_mptcp.mutliproc_even \
#-r tls.13_aes_gcm_mptcp.mutliproc_readers \
#-r tls.13_aes_gcm_mptcp.mutliproc_writers \
#-r tls.13_aes_gcm_mptcp.mutliproc_sendpage_even \
#-r tls.13_aes_gcm_mptcp.mutliproc_sendpage_readers \
#-r tls.13_aes_gcm_mptcp.mutliproc_sendpage_writers \
#-r tls.12_chacha_mptcp.mutliproc_even \
#-r tls.12_chacha_mptcp.mutliproc_readers \
#-r tls.12_chacha_mptcp.mutliproc_writers \
#-r tls.12_chacha_mptcp.mutliproc_sendpage_even \
#-r tls.12_chacha_mptcp.mutliproc_sendpage_readers \
#-r tls.12_chacha_mptcp.mutliproc_sendpage_writers \
#-r tls.13_chacha_mptcp.mutliproc_even \
#-r tls.13_chacha_mptcp.mutliproc_readers \
#-r tls.13_chacha_mptcp.mutliproc_writers \
#-r tls.13_chacha_mptcp.mutliproc_sendpage_even \
#-r tls.13_chacha_mptcp.mutliproc_sendpage_readers \
#-r tls.13_chacha_mptcp.mutliproc_sendpage_writers \
#-r tls.13_sm4_gcm_mptcp.mutliproc_even \
#-r tls.13_sm4_gcm_mptcp.mutliproc_readers \
#-r tls.13_sm4_gcm_mptcp.mutliproc_writers \
#-r tls.13_sm4_gcm_mptcp.mutliproc_sendpage_even \
#-r tls.13_sm4_gcm_mptcp.mutliproc_sendpage_readers \
#-r tls.13_sm4_gcm_mptcp.mutliproc_sendpage_writers \
#-r tls.13_sm4_ccm_mptcp.mutliproc_even \
#-r tls.13_sm4_ccm_mptcp.mutliproc_readers \
#-r tls.13_sm4_ccm_mptcp.mutliproc_writers \
#-r tls.13_sm4_ccm_mptcp.mutliproc_sendpage_even \
#-r tls.13_sm4_ccm_mptcp.mutliproc_sendpage_readers \
#-r tls.13_sm4_ccm_mptcp.mutliproc_sendpage_writers \
#-r tls.12_aes_ccm_mptcp.mutliproc_even \
#-r tls.12_aes_ccm_mptcp.mutliproc_readers \
#-r tls.12_aes_ccm_mptcp.mutliproc_writers \
#-r tls.12_aes_ccm_mptcp.mutliproc_sendpage_even \
#-r tls.12_aes_ccm_mptcp.mutliproc_sendpage_readers \
#-r tls.12_aes_ccm_mptcp.mutliproc_sendpage_writers \
#-r tls.13_aes_ccm_mptcp.mutliproc_even \
#-r tls.13_aes_ccm_mptcp.mutliproc_readers \
#-r tls.13_aes_ccm_mptcp.mutliproc_writers \
#-r tls.13_aes_ccm_mptcp.mutliproc_sendpage_even \
#-r tls.13_aes_ccm_mptcp.mutliproc_sendpage_readers \
#-r tls.13_aes_ccm_mptcp.mutliproc_sendpage_writers \
#-r tls.12_aes_gcm_256_mptcp.mutliproc_even \
#-r tls.12_aes_gcm_256_mptcp.mutliproc_readers \
#-r tls.12_aes_gcm_256_mptcp.mutliproc_writers \
#-r tls.12_aes_gcm_256_mptcp.mutliproc_sendpage_even \
#-r tls.12_aes_gcm_256_mptcp.mutliproc_sendpage_readers \
#-r tls.12_aes_gcm_256_mptcp.mutliproc_sendpage_writers \
#-r tls.13_aes_gcm_256_mptcp.mutliproc_even \
#-r tls.13_aes_gcm_256_mptcp.mutliproc_readers \
#-r tls.13_aes_gcm_256_mptcp.mutliproc_writers \
#-r tls.13_aes_gcm_256_mptcp.mutliproc_sendpage_even \
#-r tls.13_aes_gcm_256_mptcp.mutliproc_sendpage_readers \
#-r tls.13_aes_gcm_256_mptcp.mutliproc_sendpage_writers \
#-r tls.13_nopad_mptcp.mutliproc_even \
#-r tls.13_nopad_mptcp.mutliproc_readers \
#-r tls.13_nopad_mptcp.mutliproc_writers \
#-r tls.13_nopad_mptcp.mutliproc_sendpage_even \
#-r tls.13_nopad_mptcp.mutliproc_sendpage_readers \
#-r tls.13_nopad_mptcp.mutliproc_sendpage_writers \
#-r tls.12_aria_gcm_mptcp.mutliproc_even \
#-r tls.12_aria_gcm_mptcp.mutliproc_readers \
#-r tls.12_aria_gcm_mptcp.mutliproc_writers \
#-r tls.12_aria_gcm_mptcp.mutliproc_sendpage_even \
#-r tls.12_aria_gcm_mptcp.mutliproc_sendpage_readers \
#-r tls.12_aria_gcm_mptcp.mutliproc_sendpage_writers \
#-r tls.12_aria_gcm_256_mptcp.mutliproc_even \
#-r tls.12_aria_gcm_256_mptcp.mutliproc_readers \
#-r tls.12_aria_gcm_256_mptcp.mutliproc_writers \
#-r tls.12_aria_gcm_256_mptcp.mutliproc_sendpage_even \
#-r tls.12_aria_gcm_256_mptcp.mutliproc_sendpage_readers \
#-r tls.12_aria_gcm_256_mptcp.mutliproc_sendpage_writers &
ip netns exec "$ns1" ./tls &
#ip netns exec "$ns1" ./tls -v 12_aes_gcm_mptcp \
#			   -v 13_aes_gcm_mptcp \
#			   -v 12_chacha_mptcp \
#			   -v 13_chacha_mptcp \
#			   -v 13_sm4_gcm_mptcp \
#			   -v 13_sm4_ccm_mptcp \
#			   -v 12_aes_ccm_mptcp \
#			   -v 13_aes_ccm_mptcp \
#			   -v 12_aes_gcm_256_mptcp \
#			   -v 13_aes_gcm_256_mptcp \
#			   -v 13_nopad_mptcp \
#			   -v 12_aria_gcm_mptcp \
#			   -v 12_aria_gcm_256_mptcp &
#ip netns exec "$ns1" ./tls -v 12_aes_gcm_mptcp \
#			   -v 13_aes_gcm \
#			   -v 12_chacha_mptcp \
#			   -v 13_chacha \
#			   -v 13_sm4_gcm_mptcp \
#			   -v 13_sm4_ccm \
#			   -v 12_aes_ccm_mptcp \
#			   -v 13_aes_ccm \
#			   -v 12_aes_gcm_256_mptcp \
#			   -v 13_aes_gcm_256 \
#			   -v 13_nopad_mptcp \
#			   -v 12_aria_gcm \
#			   -v 12_aria_gcm_256_mptcp &
perf record -g -e cycles -F 999 -o "$PERF_DATA" --all-cpus \
    -- ip netns exec "$ns1" ./tls -t multi_chunk_sendfile 2>&1 &
pid=$!
wait $pid
ret=$?

echo "============================================================"
echo "perf report (active kernel symbols - idle filtered):"
echo "============================================================"
# Keep only non-idle lines (kernel functions that actually do work)
perf report -i "$PERF_DATA" --children --sort=sym --stdio 2>/dev/null | \
    grep -E '__mptcp_|^[a-z].*sk_|t c p|tcp_|t l s|tls_|crypto_|sock_|inet_connection|mptcp_|skb_|inet_|net_|dev_queue|xmit|fastopen|sendmsg|recvmsg|sendpage|sk_data|sk_buff' | head -30 || \
	perf report -i "$PERF_DATA" --sort=sym --stdio 2>/dev/null | \
    grep -E '__mptcp_|^[a-z].*sk_|t c p|tcp_|t l s|tls_|crypto_|sock_|inet_connection|mptcp_|skb_|inet_|net_|dev_queue|xmit|fastopen|sendmsg|recvmsg|sendpage|sk_data|sk_buff' | head -30
echo "============================================================"
echo "perf report (all symbols, first 30 lines after header):"
echo "============================================================"
perf report -i "$PERF_DATA" --sort=sym --stdio 2>/dev/null | head -40

mptcp_lib_result_print_all_tap
exit $ret
