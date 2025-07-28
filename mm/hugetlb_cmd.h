// SPDX-License-Identifier: GPL-2.0

#ifndef _LINUX_HUGETLB_CMD_H
#define _LINUX_HUGETLB_CMD_H

/* for command line parsing */
static struct hstate * __initdata parsed_hstate;
static unsigned long __initdata default_hstate_max_huge_pages;
static bool __initdata parsed_default_hugepagesz;
static unsigned int default_hugepages_in_node[MAX_NUMNODES] __initdata;
static unsigned long hugepage_allocation_threads __initdata;

__init int hugetlb_add_param(char *s, int (*setup)(char *val));
__init void hugetlb_parse_params(void);

#endif /* _LINUX_HUGETLB_CMD_H */
