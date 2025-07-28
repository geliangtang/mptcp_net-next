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

#include "hugetlb.h"

struct hugetlb_sysfs {
	struct kobject *hugepages_kobj;			/* "hugepages" */
	struct kobject *hstate_kobjs[HUGE_MAX_HSTATE];	/* "hugepages-<size>kB" */
};

static struct hugetlb_sysfs *sysfs_node[MAX_NUMNODES];

#define HUGETLB_ATTR_RO(_name)	\
	static struct kobj_attribute _name##_attr = __ATTR_RO(_name)
#define HUGETLB_ATTR_WO(_name)	\
	static struct kobj_attribute _name##_attr = __ATTR_WO(_name)
#define HUGETLB_ATTR_RW(_name)	\
	static struct kobj_attribute _name##_attr = __ATTR_RW(_name)

#define HUGETLB_DEFINE_METADATA_NODE_SHOW(_name, member)		\
	static ssize_t _name##_show(struct kobject *kobj,		\
				    struct kobj_attribute *attr,	\
				    char *buf)				\
	{								\
		int nid = hstate_kobject_to_nid(kobj);			\
		struct hstate *hstate = hstate_kobject_to_hstate(kobj);	\
		unsigned long nr_pages;					\
									\
		if (nid == NUMA_NO_NODE)				\
			nr_pages = hstate->member;			\
		else							\
			nr_pages = hstate->member##_node[nid];		\
		return sysfs_emit(buf, "%lu\n", nr_pages);		\
	}

#define HUGETLB_METADATA_NODE_ATTR_RO(_name, member)			\
	HUGETLB_DEFINE_METADATA_NODE_SHOW(_name, member)		\
	HUGETLB_ATTR_RO(_name)

#define HUGETLB_METADATA_NODE_ATTR_RW(_name, member)			\
	HUGETLB_DEFINE_METADATA_NODE_SHOW(_name, member)		\
	HUGETLB_ATTR_RW(_name)

#define HUGETLB_DEFINE_METADATA_SHOW(_name, member)			\
	static ssize_t _name##_show(struct kobject *kobj,		\
				    struct kobj_attribute *attr,	\
				    char *buf)				\
	{								\
		struct hstate *hstate = hstate_kobject_to_hstate(kobj);	\
									\
		return sysfs_emit(buf, "%lu\n", hstate->member);	\
	}

#define HUGETLB_METADATA_ATTR_RO(_name, member)				\
	HUGETLB_DEFINE_METADATA_SHOW(_name, member)			\
	HUGETLB_ATTR_RO(_name)

#define HUGETLB_METADATA_ATTR_RW(_name, member)				\
	HUGETLB_DEFINE_METADATA_SHOW(_name, member)			\
	HUGETLB_ATTR_RW(_name)

static struct hstate *hstate_kobject_to_hstate(struct kobject *hstate_kobj)
{
	struct hstate *hstate;

	for_each_hstate(hstate) {
		int offset = sizeof("hugepages-");
		const char *name = kobject_name(hstate_kobj);

		/*
		 * It is more efficient to start the comparison from the @offset
		 * of the hstate name since hstate name is always prefixed with
		 * "hugepages-".
		 */
		if (!strcmp(hstate->name + offset, name + offset))
			return hstate;
	}
	return NULL;
}

static inline int hstate_kobject_to_nid(struct kobject *hstate_kobj)
{
	struct kobject *root = hstate_kobj->parent->parent;

	/*
	 * The hugepages-<size>kB represented by @hstate_kobj directory could
	 * be found in the following two different types of path.
	 *
	 *	1) /sys/kernel/mm/hugepages
	 *	2) /sys/devices/system/node/node<ID>/hugepages
	 *
	 * So @root represents "mm" or "node<ID>" kobject. Note that 2) only
	 * exists when CONFIG_NUMA is configured.
	 */
	if (!IS_ENABLED(CONFIG_NUMA) || root == mm_kobj)
		return NUMA_NO_NODE;

	/* @root represents "node<ID>" kobject if the code reaches here. */
	return kobj_to_dev(root)->id;
}

static ssize_t nr_hugepages_store_policy(struct hstate *hstate,
					 const char *buf, size_t len,
					 int nid, nodemask_t *allowed)
{
	int ret;
	unsigned long nr;

	if (hstate_is_gigantic(hstate) && !gigantic_page_runtime_supported())
		return -EPERM;

	if (kstrtoul(buf, 10, &nr))
		return -EINVAL;

	ret = hugetlb_set_max_huge_pages(hstate, nr, nid, allowed);

	return ret < 0 ? ret : len;
}

static ssize_t nr_hugepages_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t len)
{
	int nid = hstate_kobject_to_nid(kobj);
	struct hstate *hstate = hstate_kobject_to_hstate(kobj);
	nodemask_t *allowed = &node_states[N_MEMORY], nodes;

	if (nid != NUMA_NO_NODE) {
		init_nodemask_of_node(&nodes, nid);
		allowed = &nodes;
	}

	return nr_hugepages_store_policy(hstate, buf, len, nid, allowed);
}
HUGETLB_METADATA_NODE_ATTR_RW(nr_hugepages, nr_huge_pages);

static ssize_t nr_overcommit_hugepages_store(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     const char *buf, size_t len)
{
	unsigned long nr_pages;
	struct hstate *hstate = hstate_kobject_to_hstate(kobj);

	if (hstate_is_gigantic(hstate))
		return -EPERM;

	if (kstrtoul(buf, 10, &nr_pages))
		return -EINVAL;

	spin_lock_irq(&hugetlb_lock);
	hstate->nr_overcommit_huge_pages = nr_pages;
	spin_unlock_irq(&hugetlb_lock);

	return len;
}
HUGETLB_METADATA_ATTR_RW(nr_overcommit_hugepages, nr_overcommit_huge_pages);

#ifdef CONFIG_NUMA
static ssize_t nr_hugepages_mempolicy_show(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	return nr_hugepages_show(kobj, attr, buf);
}

static ssize_t nr_hugepages_mempolicy_store(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    const char *buf, size_t len)
{
	struct hstate *hstate = hstate_kobject_to_hstate(kobj);
	nodemask_t *allowed = &node_states[N_MEMORY], nodes;

	if (init_nodemask_of_mempolicy(&nodes))
		allowed = &nodes;

	return nr_hugepages_store_policy(hstate, buf, len, NUMA_NO_NODE, allowed);
}
HUGETLB_ATTR_RW(nr_hugepages_mempolicy);
#endif

HUGETLB_METADATA_ATTR_RO(resv_hugepages, resv_huge_pages);
HUGETLB_METADATA_NODE_ATTR_RO(free_hugepages, free_huge_pages);

static struct attribute *hugetlb_attrs[] = {
	&nr_hugepages_attr.attr,
	&nr_overcommit_hugepages_attr.attr,
#ifdef CONFIG_NUMA
	&nr_hugepages_mempolicy_attr.attr,
#endif
	&resv_hugepages_attr.attr,
	&free_hugepages_attr.attr,
	NULL,
};

static const struct attribute_group hugetlb_group = {
	.attrs = hugetlb_attrs,
};

static struct attribute *hugetlb_node_attrs[] = {
	&nr_hugepages_attr.attr,
	&free_hugepages_attr.attr,
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
