// SPDX-License-Identifier: GPL-2.0
/*
 * HugeTLB interfaces (e.g. sysfs) creation and removal.
 *
 * Copyright (c) 2022, ByteDance. All rights reserved.
 *
 *     Author: Muchun Song <songmuchun@bytedance.com>
 *
 * Add the per-page-size control/query attributes to the per-node devices
 * or mm:
 *
 * 1) /sys/devices/system/node/node<ID>/hugepages/hugepages-<size>/
 * 2) /sys/kernel/mm/hugepages/hugepages-<size>/
 */
#define pr_fmt(fmt)	"HugeTLB: " fmt

#include <linux/hugetlb.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/memory.h>

struct hugetlb_sysfs {
	struct kobject *hugepages_kobj;			/* "hugepages" */
	struct kobject *hstate_kobjs[HUGE_MAX_HSTATE];	/* "hugepages-<size>kB" */
};

static struct hugetlb_sysfs *sysfs_node[MAX_NUMNODES];

static struct attribute *hugetlb_attrs[] = {
	NULL,
};

static const struct attribute_group hugetlb_group = {
	.attrs = hugetlb_attrs,
};

static struct attribute *hugetlb_node_attrs[] = {
	NULL,
};

static const struct attribute_group hugetlb_node_group = {
	.attrs = hugetlb_node_attrs,
};

static struct kobject *hugetlb_create_group(struct hstate *hstate,
					    struct kobject *hugepages_kobj,
					    const struct attribute_group *group)
{
	struct kobject *hstate_kobj;

	hstate_kobj = kobject_create_and_add(hstate->name, hugepages_kobj);
	if (!hstate_kobj)
		return NULL;
	if (sysfs_create_group(hstate_kobj, group))
		goto put_kobj;
	return hstate_kobj;
put_kobj:
	kobject_put(hstate_kobj);
	return NULL;
}

static void hugetlb_remove_group(struct hstate *hstate,
				 struct kobject *hstate_kobj,
				 const struct attribute_group *group)
{
	sysfs_remove_group(hstate_kobj, group);
	kobject_put(hstate_kobj);
}

static int hugetlb_create_sysfs(struct kobject *root,
				const struct attribute_group *group,
				struct hugetlb_sysfs *sysfs)
{
	struct kobject *hugepages_kobj;
	struct hstate *hstate, *stop;

	hugepages_kobj = kobject_create_and_add("hugepages", root);
	if (!hugepages_kobj)
		return -ENOMEM;

	for_each_hstate(hstate) {
		struct kobject *hstate_kobj;

		hstate_kobj = hugetlb_create_group(hstate, hugepages_kobj, group);
		if (!hstate_kobj) {
			stop = hstate;
			goto err;
		}
		sysfs->hstate_kobjs[hstate_index(hstate)] = hstate_kobj;
	}
	sysfs->hugepages_kobj = hugepages_kobj;
	return 0;
err:
	for_each_hstate(hstate) {
		struct kobject *hstate_kobj;

		if (hstate == stop)
			break;
		hstate_kobj = sysfs->hstate_kobjs[hstate_index(hstate)];
		hugetlb_remove_group(hstate, hstate_kobj, group);
		sysfs->hstate_kobjs[hstate_index(hstate)] = NULL;
	}
	kobject_put(hugepages_kobj);
	return -ENOMEM;
}

static int hugetlb_create_node_sysfs(struct node *node)
{
	struct hugetlb_sysfs *sysfs = sysfs_node[node->dev.id];

	if (sysfs)
		return 0;

	sysfs = kzalloc(sizeof(*sysfs), GFP_KERNEL);
	if (!sysfs)
		return -ENOMEM;

	if (hugetlb_create_sysfs(&node->dev.kobj, &hugetlb_node_group, sysfs))
		goto out;

	sysfs_node[node->dev.id] = sysfs;
	return 0;
out:
	kfree(sysfs);
	return -ENOMEM;
}

static void hugetlb_remove_node_sysfs(struct node *node)
{
	struct hstate *hstate;
	struct hugetlb_sysfs *sysfs = sysfs_node[node->dev.id];

	if (!sysfs)
		return;

	for_each_hstate(hstate) {
		struct kobject *hstate_kobj;

		hstate_kobj = sysfs->hstate_kobjs[hstate_index(hstate)];
		hugetlb_remove_group(hstate, hstate_kobj, &hugetlb_node_group);
		sysfs->hstate_kobjs[hstate_index(hstate)] = NULL;
	}
	kobject_put(sysfs->hugepages_kobj);
	kfree(sysfs);
	sysfs_node[node->dev.id] = NULL;
}

static int __meminit hugetlb_memory_callback(struct notifier_block *self,
					     unsigned long action, void *arg)
{
	int ret = 0;
	struct memory_notify *mnb = arg;
	int nid = mnb->status_change_nid;

	if (nid == NUMA_NO_NODE)
		return NOTIFY_DONE;

	if (action == MEM_GOING_ONLINE)
		ret = hugetlb_create_node_sysfs(node_devices[nid]);
	else if (action == MEM_CANCEL_ONLINE || action == MEM_OFFLINE)
		hugetlb_remove_node_sysfs(node_devices[nid]);

	return notifier_from_errno(ret);
}

static int __init hugetlb_sysfs_init(void)
{
	struct hugetlb_sysfs sysfs;

	if (!hugepages_supported())
		return 0;

	if (hugetlb_create_sysfs(mm_kobj, &hugetlb_group, &sysfs))
		return -ENOMEM;

	if (IS_ENABLED(CONFIG_NUMA)) {
		int nid;

		get_online_mems();
		hotplug_memory_notifier(hugetlb_memory_callback, 0);
		for_each_node_state(nid, N_MEMORY)
			hugetlb_create_node_sysfs(node_devices[nid]);
		put_online_mems();
	}
	return 0;
}
late_initcall(hugetlb_sysfs_init);
