# SPDX-License-Identifier: GPL-2.0

top_srcdir = ../../../../..

.DEFAULT_GOAL := all

CFLAGS += -Wall -Wl,--no-as-needed -O2 -g -I$(top_srcdir)/usr/include $(KHDR_INCLUDES)
CFLAGS += -I$(top_srcdir)/tools/include

TEST_PROGS := \
	diag.sh \
	mptcp_connect.sh \
	mptcp_connect_checksum.sh \
	mptcp_connect_mmap.sh \
	mptcp_connect_sendfile.sh \
	mptcp_connect_splice.sh \
	mptcp_connect_zerocopy.sh \
	mptcp_join.sh \
	mptcp_nvme.sh \
	mptcp_restore.sh \
	mptcp_sockopt.sh \
	mptcp_tls.sh \
	pm_netlink.sh \
	simult_flows.sh \
	tlshd_v4map.sh \
	userspace_pm.sh \
# end of TEST_PROGS

TEST_GEN_FILES := \
	mptcp_connect \
	mptcp_diag \
	mptcp_sockopt \
	multi_chunk \
	pm_nl_ctl \
	restore_ipv4 \
	restore_ipv6 \
	restore_mptcp_ipv4 \
	restore_mptcp_ipv6 \
	tls \
# end of TEST_GEN_FILES

TEST_FILES := \
	mptcp_lib.sh \
	settings \
# end of TEST_FILES

TEST_INCLUDES := ../lib.sh $(wildcard ../lib/sh/*.sh)

EXTRA_CLEAN := *.pcap ksft-ftrace-*

include ../../lib.mk

# tcp_ao library for restore test
HOSTAR ?= ar
TCP_AO_LIBDIR := tcp_ao_lib
TCP_AO_LIB := $(TCP_AO_LIBDIR)/libaotst.a
TCP_AO_CFLAGS := -Wall -O2 -g -fno-strict-aliasing
TCP_AO_CFLAGS += -isystem $(top_srcdir)/usr/include
TCP_AO_CFLAGS += -I$(top_srcdir)/tools/testing/selftests
TCP_AO_CFLAGS += -iquote ../tcp_ao/lib/ -I ../../../../include/
TCP_AO_LDLIBS := $(TCP_AO_LIB) -pthread

ifneq ($(V),1)
QUIET_CC   = @echo '  CC      ' $@;
QUIET_AR   = @echo '  AR      ' $@;
endif

# tcp_ao library build rules
TCP_AO_LIBSRC := ftrace.c ftrace-tcp.c kconfig.c netlink.c proc.c repair.c setup.c sock.c utils.c
TCP_AO_LIBOBJ := $(TCP_AO_LIBSRC:%.c=$(TCP_AO_LIBDIR)/%.o)
EXTRA_CLEAN += $(TCP_AO_LIBOBJ) $(TCP_AO_LIB)

$(TCP_AO_LIB): $(TCP_AO_LIBOBJ)
	$(QUIET_AR)$(HOSTAR) rcs $@ $^

$(TCP_AO_LIBDIR)/%.o: ../tcp_ao/lib/%.c ../tcp_ao/lib/aolib.h Makefile
	@mkdir -p $(TCP_AO_LIBDIR)
	$(QUIET_CC)$(CC) $< -D_GNU_SOURCE $(TCP_AO_CFLAGS) -o $@ -c

$(OUTPUT)/restore_ipv4: ../tcp_ao/restore.c $(TCP_AO_LIB)
	$(QUIET_CC)$(CC) $< -D_GNU_SOURCE $(TCP_AO_CFLAGS) $(TCP_AO_LDLIBS) -o $@

$(OUTPUT)/restore_ipv6: ../tcp_ao/restore.c $(TCP_AO_LIB)
	$(QUIET_CC)$(CC) $< -D_GNU_SOURCE $(TCP_AO_CFLAGS) -DIPV6_TEST $(TCP_AO_LDLIBS) -o $@

$(OUTPUT)/restore_mptcp_ipv4: ../tcp_ao/restore.c $(TCP_AO_LIB)
	$(QUIET_CC)$(CC) $< -D_GNU_SOURCE $(TCP_AO_CFLAGS) -DMPTCP_TEST $(TCP_AO_LDLIBS) -o $@

$(OUTPUT)/restore_mptcp_ipv6: ../tcp_ao/restore.c $(TCP_AO_LIB)
	$(QUIET_CC)$(CC) $< -D_GNU_SOURCE $(TCP_AO_CFLAGS) -DMPTCP_TEST -DIPV6_TEST $(TCP_AO_LDLIBS) -o $@

$(OUTPUT)/tls: ../tls.c
	$(QUIET_CC)$(CC) $< $(CFLAGS) $(CPPFLAGS) -o $@
