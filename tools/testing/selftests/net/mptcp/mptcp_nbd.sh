#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

. "$(dirname "$0")/mptcp_lib.sh"

ret=0
adrfam="${1:-ipv4}"
trtype="${2:-mptcp}"
path="${3:-1}"
loss=${4:-0}
tls="${5:-""}"  # any non-empty value (e.g. "tls") enables TLS
ns=1
port=$((RANDOM % 10000 + 20000))
ns1=""
ns2=""
temp_file=""
conf_file=""
pid_file=""
server_pid=""
cert_dir=""

export adrfam trtype path port
export temp_file conf_file pid_file server_pid cert_dir
export loss tls

usage()
{
	cat << EOF

Usage:

	$(basename "$0") [adrfam] [trtype] [path] [loss] [tls]

	adrfam   Address family (ipv4|ipv6|v4map) - default: ipv4
	trtype   Transport type (tcp|mptcp) - default: mptcp
	path     Number of NBD connections via -C (1-4) - default: 1
	loss     Enable packet loss (0|1) - default: 0
	tls      Enable TLS (any non-empty value, e.g. "tls") - default: ""

EOF
exit ${KSFT_FAIL}
}

validate_params()
{
	if [[ ! "${adrfam}" =~ ^(ipv4|ipv6|v4map)$ ]]; then
		echo "Invalid adrfam ${adrfam}. Must be ipv4, ipv6 or v4map"
		usage
	fi

	if [[ ! "${trtype}" =~ ^(tcp|mptcp)$ ]]; then
		echo "Invalid trtype ${trtype}. Must be tcp or mptcp"
		usage
	fi

	if [[ ! "${path}" =~ ^[1-4]$ ]]; then
		echo "Invalid path count ${path}. Must be between 1 and 4"
		usage
	fi

	if [[ ! "${loss}" =~ ^[01]$ ]]; then
		echo "Invalid loss value ${loss}. Must be 0 or 1"
		usage
	fi
}

get_server_addr()
{
	local idx="${1:-1}"

	if [ "${adrfam}" = "ipv6" ]; then
		if [ "${path}" -eq 1 ]; then
			echo "dead:beef:1::1"
		else
			echo "dead:beef:${idx}::1"
		fi
	elif [ "${adrfam}" = "v4map" ]; then
		if [ "${path}" -eq 1 ]; then
			echo "::ffff:10.1.1.1"
		else
			echo "::ffff:10.1.${idx}.1"
		fi
	else
		if [ "${path}" -eq 1 ]; then
			echo "10.1.1.1"
		else
			echo "10.1.${idx}.1"
		fi
	fi
}

get_listen_addr()
{
	if [ "${adrfam}" = "ipv6" ] || [ "${adrfam}" = "v4map" ]; then
		echo "::"
	else
		echo "0.0.0.0"
	fi
}

# Generate self-signed TLS certificates
#shellcheck disable=SC2317,SC2329
generate_certs()
{
	cert_dir=$(mktemp -d /tmp/nbd_certs.XXXXXX)

	# CA key and certificate
	openssl req -x509 -newkey rsa:2048 -keyout "${cert_dir}/ca-key.pem" \
		-out "${cert_dir}/ca-cert.pem" -days 1 -nodes \
		-subj "/CN=NBD Test CA" 2>/dev/null

	# Server key and certificate
	openssl req -newkey rsa:2048 -keyout "${cert_dir}/server-key.pem" \
		-out "${cert_dir}/server-csr.pem" -nodes \
		-subj "/CN=localhost" 2>/dev/null
	openssl x509 -req -in "${cert_dir}/server-csr.pem" \
		-CA "${cert_dir}/ca-cert.pem" -CAkey "${cert_dir}/ca-key.pem" \
		-CAcreateserial -out "${cert_dir}/server-cert.pem" \
		-days 1 2>/dev/null

	# Client key and certificate
	openssl req -newkey rsa:2048 -keyout "${cert_dir}/client-key.pem" \
		-out "${cert_dir}/client-csr.pem" -nodes \
		-subj "/CN=nbd-client" 2>/dev/null
	openssl x509 -req -in "${cert_dir}/client-csr.pem" \
		-CA "${cert_dir}/ca-cert.pem" -CAkey "${cert_dir}/ca-key.pem" \
		-CAcreateserial -out "${cert_dir}/client-cert.pem" \
		-days 1 2>/dev/null

	# Create combined cert+key files (nbd-server uses keyfile for both
	# when certfile option is not available). Cert first, then key.
	cat "${cert_dir}/server-cert.pem" "${cert_dir}/server-key.pem" \
		> "${cert_dir}/server-combined.pem"
	cat "${cert_dir}/client-cert.pem" "${cert_dir}/client-key.pem" \
		> "${cert_dir}/client-combined.pem"

	# Copy certs to both namespaces
	for ns in "$ns1" "$ns2"; do
		ip netns exec "$ns" mkdir -p /tmp/nbd_certs
		for f in "${cert_dir}"/*.pem; do
			local dest="/tmp/nbd_certs/$(basename "$f")"
			ip netns exec "$ns" tee "$dest" < "$f" > /dev/null
		done
	done
}

# This function is used in the cleanup trap
#shellcheck disable=SC2317,SC2329
cleanup()
{
	# Disconnect nbd device in ns2
	ip netns exec "$ns2" nbd-client -d /dev/nbd0 2>/dev/null || true

	sleep 1

	# Kill nbd-server in ns1
	if [ -n "${server_pid}" ]; then
		ip netns exec "$ns1" kill "${server_pid}" 2>/dev/null || true
		ip netns exec "$ns1" kill -9 "${server_pid}" 2>/dev/null || true
	fi

	# Clean up temp files
	if [ -n "${temp_file}" ]; then
		ip netns exec "$ns1" rm -f "${temp_file}" 2>/dev/null || true
	fi
	if [ -n "${conf_file}" ]; then
		ip netns exec "$ns1" rm -f "${conf_file}" 2>/dev/null || true
	fi
	if [ -n "${pid_file}" ]; then
		ip netns exec "$ns1" rm -f "${pid_file}" 2>/dev/null || true
	fi

	# Clean up certificates
	if [ -n "${cert_dir}" ]; then
		rm -rf "${cert_dir}"
		for ns in "$ns1" "$ns2"; do
			ip netns exec "$ns" rm -rf /tmp/nbd_certs \
				2>/dev/null || true
		done
	fi

	mptcp_lib_ns_exit "$ns1" "$ns2"

	unset -v trtype path port
	unset -v temp_file server_pid cert_dir
	unset -v loss tls
}

# $tc_args needs word splitting to pass multiple arguments to netem
# shellcheck disable=SC2086
init()
{
	local tc_args="rate 1000mbit"

	if [ "${loss}" -eq 1 ]; then
		tc_args+=" delay 5ms loss 0.5%"
	fi

	mptcp_lib_ns_init ns1 ns2

	ip netns exec "$ns1" sysctl -qw net.ipv4.tcp_reflect_tos=1

	# ns1		ns2
	# 10.1.1.1	10.1.1.2
	# 10.1.2.1	10.1.2.2
	# 10.1.3.1	10.1.3.2
	# 10.1.4.1	10.1.4.2
	for i in {1..4}; do
		ip link add ns1eth"$i" netns "$ns1" type veth peer \
					name ns2eth"$i" netns "$ns2"
		ip -net "$ns1" addr add 10.1."$i".1/24 dev ns1eth"$i"
		ip -net "$ns1" addr add dead:beef:"$i"::1/64 \
					dev ns1eth"$i" nodad
		ip -net "$ns1" link set ns1eth"$i" up
		ip -net "$ns2" addr add 10.1."$i".2/24 dev ns2eth"$i"
		ip -net "$ns2" addr add dead:beef:"$i"::2/64 \
					dev ns2eth"$i" nodad
		ip -net "$ns2" link set ns2eth"$i" up
		ip -net "$ns2" route add default via 10.1."$i".1 \
					dev ns2eth"$i" metric 10"$i"
		ip -net "$ns2" route add default via dead:beef:"$i"::1 \
					dev ns2eth"$i" metric 10"$i"

		tc -n "$ns1" qdisc add dev ns1eth"$i" root netem $tc_args
		tc -n "$ns2" qdisc add dev ns2eth"$i" root netem $tc_args
	done

	mptcp_lib_pm_nl_set_limits "${ns1}" 8 8

	if [ "${adrfam}" = "ipv6" ]; then
		mptcp_lib_pm_nl_add_endpoint "$ns1" dead:beef:1::1 flags signal
		mptcp_lib_pm_nl_add_endpoint "$ns1" dead:beef:2::1 flags signal
		mptcp_lib_pm_nl_add_endpoint "$ns1" dead:beef:3::1 flags signal
		mptcp_lib_pm_nl_add_endpoint "$ns1" dead:beef:4::1 flags signal
	elif [ "${adrfam}" = "v4map" ]; then
		mptcp_lib_pm_nl_add_endpoint "$ns1" "::ffff:10.1.1.1" \
			flags signal
		mptcp_lib_pm_nl_add_endpoint "$ns1" "::ffff:10.1.2.1" \
			flags signal
		mptcp_lib_pm_nl_add_endpoint "$ns1" "::ffff:10.1.3.1" \
			flags signal
		mptcp_lib_pm_nl_add_endpoint "$ns1" "::ffff:10.1.4.1" \
			flags signal
	else
		mptcp_lib_pm_nl_add_endpoint "$ns1" 10.1.1.1 flags signal
		mptcp_lib_pm_nl_add_endpoint "$ns1" 10.1.2.1 flags signal
		mptcp_lib_pm_nl_add_endpoint "$ns1" 10.1.3.1 flags signal
		mptcp_lib_pm_nl_add_endpoint "$ns1" 10.1.4.1 flags signal
	fi

	mptcp_lib_pm_nl_set_limits "${ns2}" 8 8

	if [ "${adrfam}" = "ipv6" ]; then
		mptcp_lib_pm_nl_add_endpoint "$ns2" dead:beef:1::2 flags subflow
		mptcp_lib_pm_nl_add_endpoint "$ns2" dead:beef:2::2 flags subflow
		mptcp_lib_pm_nl_add_endpoint "$ns2" dead:beef:3::2 flags subflow
		mptcp_lib_pm_nl_add_endpoint "$ns2" dead:beef:4::2 flags subflow
	elif [ "${adrfam}" = "v4map" ]; then
		mptcp_lib_pm_nl_add_endpoint "$ns2" "::ffff:10.1.1.2" \
			flags subflow
		mptcp_lib_pm_nl_add_endpoint "$ns2" "::ffff:10.1.2.2" \
			flags subflow
		mptcp_lib_pm_nl_add_endpoint "$ns2" "::ffff:10.1.3.2" \
			flags subflow
		mptcp_lib_pm_nl_add_endpoint "$ns2" "::ffff:10.1.4.2" \
			flags subflow
	else
		mptcp_lib_pm_nl_add_endpoint "$ns2" 10.1.1.2 flags subflow
		mptcp_lib_pm_nl_add_endpoint "$ns2" 10.1.2.2 flags subflow
		mptcp_lib_pm_nl_add_endpoint "$ns2" 10.1.3.2 flags subflow
		mptcp_lib_pm_nl_add_endpoint "$ns2" 10.1.4.2 flags subflow
	fi

	if [ -n "$tls" ]; then
		generate_certs
	fi

	# Create temp files using mktemp for security
	temp_file=$(mktemp /tmp/nbd_backing_XXXXXX.raw)
	conf_file=$(mktemp /tmp/nbd_server_XXXXXX.conf)
	pid_file=$(mktemp /tmp/nbd_server_XXXXXX.pid)
}

# This function is invoked indirectly
#shellcheck disable=SC2317,SC2329
run_server()
{
	local listen_addr
	local conf_file="/tmp/nbd-server.conf"

	listen_addr=$(get_listen_addr)

	# Create backing file
	dd if=/dev/zero of="${temp_file}" bs=1M count=0 seek=256 2>/dev/null

	# Detect MPTCP support: native config or mptcpize fallback
	local use_mptcpize=""
	local mptcp_opt=""
	if [ "${trtype}" = "mptcp" ]; then
		if ! grep -q '"mptcp"' /usr/bin/nbd-server 2>/dev/null && \
		   ! nbd-server --help 2>&1 | grep -qi mptcp; then
			if command -v mptcpize &> /dev/null; then
				use_mptcpize="mptcpize run -d"
				echo "nbd-server lacks native MPTCP, using mptcpize"
			else
				echo "no MPTCP support in nbd-server"
				return 1
			fi
		else
			mptcp_opt="mptcp = true"
			echo "nbd-server has native MPTCP support"
		fi
	fi

	if [ -n "$tls" ]; then
		# Create allowlist file
		echo "10.1.0.0/16" > /tmp/nbd-allowlist

		cat > "${conf_file}" << CONF
[generic]
	port = ${port}
	listenaddr = ${listen_addr}
	${mptcp_opt}
	force_tls = true
	certfile = /tmp/nbd_certs/server-cert.pem
	keyfile = /tmp/nbd_certs/server-key.pem
	cacertfile = /tmp/nbd_certs/ca-cert.pem
	tlsprio = NORMAL

[test]
	exportname = ${temp_file}
	allowlist = /tmp/nbd-allowlist
CONF
	else
		cat > "${conf_file}" << CONF
[generic]
	port = ${port}
	listenaddr = ${listen_addr}
	${mptcp_opt}

[test]
	exportname = ${temp_file}
CONF
	fi

	# Verify cert files exist before starting server
	if [ -n "$tls" ]; then
		local cert_files="/tmp/nbd_certs/server-combined.pem
		                 /tmp/nbd_certs/ca-cert.pem"
		for f in $cert_files; do
			if [ ! -f "$f" ]; then
				echo "ERROR: TLS cert file missing: $f"
				return 1
			fi
		done
	fi

	# Capture server log for TLS verification
	local server_log="/tmp/nbd-server.log"
	> "${server_log}"

	# Enable GnuTLS debug logging for TLS tests to capture cipher suite info
	local env_prefix=""
	if [ -n "$tls" ]; then
		env_prefix="env GNUTLS_DEBUG_LEVEL=3"
	fi

	# Use -n (nodaemon) and background manually for better control
	${env_prefix} ${use_mptcpize} nbd-server \
		-C "${conf_file}" -n > "${server_log}" 2>&1 &
	server_pid=$!

	# Write PID to file for parent process to read
	echo "${server_pid}" > "${pid_file}"

	# Verify server is running
	if ! kill -0 "${server_pid}" 2>/dev/null; then
		echo "nbd-server failed to start"
		return 1
	fi
}

# This function is invoked indirectly
#shellcheck disable=SC2317,SC2329
run_client()
{
	local server_addr
	local extra_args=()
	local nbd_dev="/dev/nbd0"

	server_addr=$(get_server_addr 1)

	local use_mptcpize=""
	if [ "${trtype}" = "mptcp" ]; then
		if nbd-client 2>&1 | grep -qE "\-M|\-\-mptcp"; then
			extra_args+=("-M")
			echo "nbd-client has native MPTCP support (-M)"
		elif command -v mptcpize &> /dev/null; then
			use_mptcpize="mptcpize run -d"
			echo "nbd-client lacks native MPTCP, using mptcpize"
		else
			echo "no MPTCP support in nbd-client"
			return 1
		fi
	fi

	if [ -n "$tls" ]; then
		extra_args+=("-x")
		extra_args+=("--certfile" "/tmp/nbd_certs/client-cert.pem")
		extra_args+=("--keyfile" "/tmp/nbd_certs/client-key.pem")
		extra_args+=("--cacertfile" "/tmp/nbd_certs/ca-cert.pem")
		extra_args+=("--tlshostname" "localhost")
	fi

	# -C sets the number of connections (multipath equivalent)
	# Only use -C if nbd-client supports it
	if [ "${path}" -gt 1 ]; then
		if nbd-client 2>&1 | grep -qE "\-C|\-\-connections"; then
			extra_args+=("-C" "${path}")
		else
			echo "WARNING: no -C support, using single connection"
		fi
	fi

	# Options before positional args: -N name host port device
	if ! ${use_mptcpize} nbd-client -N test "${extra_args[@]}" \
			"${server_addr}" "${port}" "${nbd_dev}"; then
		echo "Failed to connect ${nbd_dev} to ${server_addr}"
		return 1
	fi

	sleep 1

	# Verify connection
	if ! nbd-client -c /dev/nbd0; then
		echo "nbd-client check failed"
		return 1
	fi

	return 0
}

# This function is invoked indirectly
#shellcheck disable=SC2317,SC2329
run_io_test()
{
	local nbd_dev="/dev/nbd0"
	local test_data
	local read_data

	# Create temp files for data integrity test
	test_data=$(mktemp /tmp/nbd_test_XXXXXX.bin)
	read_data=$(mktemp /tmp/nbd_read_XXXXXX.bin)

	# Data integrity test: write and verify
	dd if=/dev/urandom of="${test_data}" bs=1M count=10 2>/dev/null
	if ! dd if="${test_data}" of="${nbd_dev}" bs=1M \
			conv=fdatasync 2>/dev/null; then
		echo "dd write failed"
		rm -f "${test_data}" "${read_data}"
		return 1
	fi

	if ! dd if="${nbd_dev}" of="${read_data}" bs=1M count=10 \
			2>/dev/null; then
		echo "dd read failed"
		rm -f "${test_data}" "${read_data}"
		return 1
	fi

	if ! cmp -s "${test_data}" "${read_data}"; then
		echo "FAIL: Data integrity check failed"
		rm -f "${test_data}" "${read_data}"
		return 1
	fi
	echo "PASS: Data integrity verified"
	rm -f "${test_data}" "${read_data}"

	# dd write test (larger, for performance measurement)
	if ! dd if=/dev/urandom of="${nbd_dev}" bs=4k count=1000 \
			conv=fdatasync 2>/dev/null; then
		echo "dd write failed"
		return 1
	fi

	# dd read test
	if ! dd if="${nbd_dev}" of=/dev/null bs=4k count=1000 2>/dev/null; then
		echo "dd read failed"
		return 1
	fi

	# fio random read test
	if ! fio --name=randread --direct=1 --ioengine=libaio \
		 --blocksize=4k --runtime=10 --time_based \
		 --rw=randread --numjobs=1 --iodepth=32 \
		 --group_reporting --size=128M \
		 --filename="${nbd_dev}"; then
		echo "fio randread failed"
		return 1
	fi

	# fio random write test
	if ! fio --name=randwrite --direct=1 --ioengine=libaio \
		 --blocksize=4k --runtime=10 --time_based \
		 --rw=randwrite --numjobs=1 --iodepth=32 \
		 --group_reporting --size=128M \
		 --filename="${nbd_dev}"; then
		echo "fio randwrite failed"
		return 1
	fi

	# Verify MPTCP subflows if trtype is mptcp
	if [ "${trtype}" = "mptcp" ]; then
		local sf_total sf_max tcp_conns is_fallback
		sf_total=$(ss -Mia | grep -oP "subflows_total:\K[0-9]+" | head -1)
		sf_max=$(ss -Mia | grep -oP "subflows_max:\K[0-9]+" | head -1)
		tcp_conns=$(ss -tia | grep -c "tcp-ulp-mptcp" || true)
		is_fallback=$(ss -Mia | grep -c "fallback" || true)
		if [ "${is_fallback}" -gt 0 ]; then
			echo "FAIL: MPTCP fell back to TCP!" \
				"subflows_total:${sf_total}" \
				"tcp_subflows:${tcp_conns}"
			return 1
		elif [ -n "${sf_total}" ]; then
			echo "PASS: MPTCP subflows_total:${sf_total} subflows_max:${sf_max} tcp_subflows:${tcp_conns}"
		else
			echo "FAIL: No MPTCP subflows info found"
			return 1
		fi
	fi

	return 0
}

# Check MPTCP support in kernel
mptcp_lib_check_mptcp

# Check for required tools
mptcp_lib_check_tools ip tc ss nbd fio

# Check for /dev/nbd0
if [ ! -b /dev/nbd0 ]; then
	mptcp_lib_pr_skip "/dev/nbd0 not found"
	exit ${KSFT_SKIP}
fi

validate_params

# Check for mptcpize if using MPTCP transport
if [ "${trtype}" = "mptcp" ]; then
	if ! command -v mptcpize &> /dev/null; then
		mptcp_lib_pr_skip "mptcpize tool not found"
		exit ${KSFT_SKIP}
	fi
fi

trap cleanup EXIT

init

run_test()
{
	if ! ip netns exec "$ns1" bash <<- EOF
		$(declare -f get_listen_addr get_server_addr)
		$(declare -f run_server)
		export adrfam trtype path port tls
		run_server
		exit \$?
	EOF
	then
		ret="${KSFT_FAIL}"
		return
	fi

	# Get server pid for cleanup from file
	server_pid=$(ip netns exec "$ns1" cat "${pid_file}" 2>/dev/null)
	server_pid="${server_pid:-}"

	# Wait for server to be ready instead of fixed sleep
	mptcp_lib_wait_local_port_listen "$ns1" "$port"

	if ! ip netns exec "$ns2" bash <<- EOF
		$(declare -f get_server_addr)
		$(declare -f run_client run_io_test)
		export adrfam trtype path port tls
		run_client || exit 1
		run_io_test || exit 1
		exit \$?
	EOF
	then
		ret="${KSFT_FAIL}"
	fi

	# Verify TLS: check server log for cert verification and cipher
	if [ -n "$tls" ]; then
		local server_log_content
		server_log_content=$(ip netns exec "$ns1" \
			cat /tmp/nbd-server.log 2>/dev/null)
		if echo "${server_log_content}" | \
		   grep -q "certificate verification successful"; then
			echo "INFO: TLS verified (certificate check passed)"

			# Extract negotiated cipher suite from GnuTLS debug log
			local cipher_suite
			cipher_suite=$(echo "${server_log_content}" | \
				grep -oP 'ciphersuite [0-9a-f.]+: \K[A-Z0-9_]+' | \
				head -1)

			if [ -n "$cipher_suite" ]; then
				echo "INFO: Cipher: $cipher_suite"
				# Parse cipher suite components
				if echo "$cipher_suite" | \
				   grep -q "AES_256_GCM"; then
					echo "INFO: Encrypt: AES-256-GCM"
				elif echo "$cipher_suite" | \
				     grep -q "AES_128_GCM"; then
					echo "INFO: Encrypt: AES-128-GCM"
				elif echo "$cipher_suite" | \
				     grep -q "CHACHA20"; then
					echo "INFO: Encrypt: ChaCha20"
				fi
				if echo "$cipher_suite" | grep -q "ECDHE"; then
					echo "INFO: Key xchg: ECDHE (PFS)"
				fi
			fi
		else
			echo "FAIL: TLS requested but no TLS handshake detected"
			echo "Server log:"
			echo "${server_log_content}"
			ret="${KSFT_FAIL}"
		fi
	fi

	sleep 1
}

run_test "$@"

if [ "${ret}" -eq 0 ]; then
	mptcp_lib_result_pass "nbd over ${trtype} test"
else
	mptcp_lib_result_fail "nbd over ${trtype} test"
fi

mptcp_lib_result_print_all_tap
exit "$ret"
