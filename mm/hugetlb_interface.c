// SPDX-License-Identifier: GPL-2.0-only
/*
 * HugeTLB interfaces (e.g. sysfs) creation and removal.
 *
 * Copyright (c) 2025, ByteDance. All rights reserved.
 *
 *     Author: Muchun Song <songmuchun@bytedance.com>
 *
 * Add the per-page-size control/query attributes to the per-node devices
 * or mm:
 *
 * 1) /sys/devices/system/node/node<ID>/hugepages/hugepages-<size>/
 * 2) /sys/kernel/mm/hugepages/hugepages-<size>/
 */

#include <linux/sysfs.h>
#include <linux/kobject.h>

static struct kobject *hugepages_kobj;
static struct kobject *hstate_kobjs[HUGE_MAX_HSTATE];

static struct attribute *hstate_attrs[] = {
	NULL,
};

static const struct attribute_group hstate_attr_group = {
	.attrs = hstate_attrs,
};

static struct attribute *hstate_demote_attrs[] = {
	NULL,
};

static const struct attribute_group hstate_demote_attr_group = {
	.attrs = hstate_demote_attrs,
};

static int hugetlb_sysfs_add_hstate(struct hstate *h, struct kobject *parent,
				    struct kobject **hstate_kobjs,
				    const struct attribute_group *hstate_attr_group)
{
	int retval;
	int hi = hstate_index(h);

	hstate_kobjs[hi] = kobject_create_and_add(h->name, parent);
	if (!hstate_kobjs[hi])
		return -ENOMEM;

	retval = sysfs_create_group(hstate_kobjs[hi], hstate_attr_group);
	if (retval) {
		kobject_put(hstate_kobjs[hi]);
		hstate_kobjs[hi] = NULL;
		return retval;
	}

	if (h->demote_order) {
		retval = sysfs_create_group(hstate_kobjs[hi],
					    &hstate_demote_attr_group);
		if (retval) {
			pr_warn("HugeTLB unable to create demote interfaces for %s\n", h->name);
			sysfs_remove_group(hstate_kobjs[hi], hstate_attr_group);
			kobject_put(hstate_kobjs[hi]);
			hstate_kobjs[hi] = NULL;
			return retval;
		}
	}

	return 0;
}

#ifdef CONFIG_NUMA
static bool hugetlb_sysfs_initialized __ro_after_init;

/*
 * node_hstate/s - associate per node hstate attributes, via their kobjects,
 * with node devices in node_devices[] using a parallel array.  The array
 * index of a node device or _hstate == node id.
 * This is here to avoid any static dependency of the node device driver, in
 * the base kernel, on the hugetlb module.
 */
struct node_hstate {
	struct kobject		*hugepages_kobj;
	struct kobject		*hstate_kobjs[HUGE_MAX_HSTATE];
};
static struct node_hstate node_hstates[MAX_NUMNODES];

/*
 * A subset of global hstate attributes for node devices
 */
static struct attribute *per_node_hstate_attrs[] = {
	NULL,
};

static const struct attribute_group per_node_hstate_attr_group = {
	.attrs = per_node_hstate_attrs,
};

/*
 * Unregister hstate attributes from a single node device.
 * No-op if no hstate attributes attached.
 */
void hugetlb_unregister_node(struct node *node)
{
	struct hstate *h;
	struct node_hstate *nhs = &node_hstates[node->dev.id];

	if (!nhs->hugepages_kobj)
		return;		/* no hstate attributes */

	for_each_hstate(h) {
		int idx = hstate_index(h);
		struct kobject *hstate_kobj = nhs->hstate_kobjs[idx];

		if (!hstate_kobj)
			continue;
		if (h->demote_order)
			sysfs_remove_group(hstate_kobj, &hstate_demote_attr_group);
		sysfs_remove_group(hstate_kobj, &per_node_hstate_attr_group);
		kobject_put(hstate_kobj);
		nhs->hstate_kobjs[idx] = NULL;
	}

	kobject_put(nhs->hugepages_kobj);
	nhs->hugepages_kobj = NULL;
}

/*
 * Register hstate attributes for a single node device.
 * No-op if attributes already registered.
 */
void hugetlb_register_node(struct node *node)
{
	struct hstate *h;
	struct node_hstate *nhs = &node_hstates[node->dev.id];
	int err;

	if (!hugetlb_sysfs_initialized)
		return;

	if (nhs->hugepages_kobj)
		return;		/* already allocated */

	nhs->hugepages_kobj = kobject_create_and_add("hugepages",
							&node->dev.kobj);
	if (!nhs->hugepages_kobj)
		return;

	for_each_hstate(h) {
		err = hugetlb_sysfs_add_hstate(h, nhs->hugepages_kobj,
						nhs->hstate_kobjs,
						&per_node_hstate_attr_group);
		if (err) {
			pr_err("HugeTLB: Unable to add hstate %s for node %d\n",
				h->name, node->dev.id);
			hugetlb_unregister_node(node);
			break;
		}
	}
}

/*
 * hugetlb init time:  register hstate attributes for all registered node
 * devices of nodes that have memory.  All on-line nodes should have
 * registered their associated device by this time.
 */
static void __init hugetlb_register_all_nodes(void)
{
	int nid;

	for_each_online_node(nid)
		hugetlb_register_node(node_devices[nid]);
}
#else	/* !CONFIG_NUMA */

static void hugetlb_register_all_nodes(void) { }

#endif

void __init hugetlb_sysfs_init(void)
{
	struct hstate *h;
	int err;

	hugepages_kobj = kobject_create_and_add("hugepages", mm_kobj);
	if (!hugepages_kobj)
		return;

	for_each_hstate(h) {
		err = hugetlb_sysfs_add_hstate(h, hugepages_kobj,
					 hstate_kobjs, &hstate_attr_group);
		if (err)
			pr_err("HugeTLB: Unable to add hstate %s\n", h->name);
	}

#ifdef CONFIG_NUMA
	hugetlb_sysfs_initialized = true;
#endif
	hugetlb_register_all_nodes();
}
