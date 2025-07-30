// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "bpf_nvme_simple.skel.h"

static void test_simple_select(void)
{
	struct bpf_nvme_simple *skel;
	struct bpf_link *link;

	skel = bpf_nvme_simple__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open: bpf_nvme_simple"))
		return;

	link = bpf_map__attach_struct_ops(skel->maps.bpf_nvme_simple);
	if (!ASSERT_OK_PTR(link, "attach_struct_ops: bpf_nvme_simple"))
		goto skel_destroy;

skel_destroy:
	bpf_nvme_simple__destroy(skel);
}

void test_nvme(void)
{
	if (test__start_subtest("simple_select"))
		test_simple_select();
}
