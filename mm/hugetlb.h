// SPDX-License-Identifier: GPL-2.0
/*
 * Internal HugeTLB definitions.
 *
 * Copyright (c) 2022, ByteDance. All rights reserved.
 *
 *     Author: Muchun Song <songmuchun@bytedance.com>
 */
#ifndef _LINUX_HUGETLB_INTERNAL_H
#define _LINUX_HUGETLB_INTERNAL_H
#include <linux/hugetlb.h>

int hugetlb_set_max_huge_pages(struct hstate *h, unsigned long count, int nid,
			       nodemask_t *nodes_allowed);
int hugetlb_demote_pool_page(struct hstate *h, nodemask_t *nodes_allowed);

#endif /* _LINUX_HUGETLB_INTERNAL_H */

