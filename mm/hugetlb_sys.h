// SPDX-License-Identifier: GPL-2.0

#ifndef _LINUX_HUGETLB_SYS_H
#define _LINUX_HUGETLB_SYS_H

int hstate_next_node_to_alloc(int *next_node,
			      nodemask_t *nodes_allowed);

#define for_each_node_mask_to_alloc(next_node, nr_nodes, node, mask)		\
	for (nr_nodes = nodes_weight(*mask);				\
		nr_nodes > 0 &&						\
		((node = hstate_next_node_to_alloc(next_node, mask)) || 1);	\
		nr_nodes--)

int hstate_next_node_to_free(struct hstate *h, nodemask_t *nodes_allowed);

#define for_each_node_mask_to_free(hs, nr_nodes, node, mask)		\
	for (nr_nodes = nodes_weight(*mask);				\
		nr_nodes > 0 &&						\
		((node = hstate_next_node_to_free(hs, mask)) || 1);	\
		nr_nodes--)

void __init hugetlb_sysfs_init(void);

#ifdef CONFIG_SYSCTL
void hugetlb_sysctl_init(void);
#else
static inline void hugetlb_sysctl_init(void) { }
#endif

void update_and_free_pages_bulk(struct hstate *h,
				struct list_head *folio_list);
void flush_free_hpage_work(struct hstate *h);

#endif /* _LINUX_HUGETLB_SYS_H */
