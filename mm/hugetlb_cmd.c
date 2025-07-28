// SPDX-License-Identifier: GPL-2.0-only

#include <linux/init.h>
#include <asm/setup.h>
#include <linux/hugetlb.h>

#include "hugetlb_cma.h"
#include "hugetlb_cmd.h"

/*
 * Due to ordering constraints across the init code for various
 * architectures, hugetlb hstate cmdline parameters can't simply
 * be early_param. early_param might call the setup function
 * before valid hugetlb page sizes are determined, leading to
 * incorrect rejection of valid hugepagesz= options.
 *
 * So, record the parameters early and consume them whenever the
 * init code is ready for them, by calling hugetlb_parse_params().
 */

/* one (hugepagesz=,hugepages=) pair per hstate, one default_hugepagesz */
#define HUGE_MAX_CMDLINE_ARGS	(2 * HUGE_MAX_HSTATE + 1)
struct hugetlb_cmdline {
	char *val;
	int (*setup)(char *val);
};

static bool __initdata parsed_valid_hugepagesz = true;
static char hstate_cmdline_buf[COMMAND_LINE_SIZE] __initdata;
static int hstate_cmdline_index __initdata;
static struct hugetlb_cmdline hugetlb_params[HUGE_MAX_CMDLINE_ARGS] __initdata;
static int hugetlb_param_index __initdata;

#define hugetlb_early_param(str, func) \
static __init int func##args(char *s) \
{ \
	return hugetlb_add_param(s, func); \
} \
early_param(str, func##args)

static void __init hugepages_clear_pages_in_node(void)
{
	if (!hugetlb_max_hstate) {
		default_hstate_max_huge_pages = 0;
		memset(default_hugepages_in_node, 0,
			sizeof(default_hugepages_in_node));
	} else {
		parsed_hstate->max_huge_pages = 0;
		memset(parsed_hstate->max_huge_pages_node, 0,
			sizeof(parsed_hstate->max_huge_pages_node));
	}
}

__init int hugetlb_add_param(char *s, int (*setup)(char *))
{
	size_t len;
	char *p;

	if (hugetlb_param_index >= HUGE_MAX_CMDLINE_ARGS)
		return -EINVAL;

	len = strlen(s) + 1;
	if (len + hstate_cmdline_index > sizeof(hstate_cmdline_buf))
		return -EINVAL;

	p = &hstate_cmdline_buf[hstate_cmdline_index];
	memcpy(p, s, len);
	hstate_cmdline_index += len;

	hugetlb_params[hugetlb_param_index].val = p;
	hugetlb_params[hugetlb_param_index].setup = setup;

	hugetlb_param_index++;

	return 0;
}

__init void hugetlb_parse_params(void)
{
	int i;
	struct hugetlb_cmdline *hcp;

	for (i = 0; i < hugetlb_param_index; i++) {
		hcp = &hugetlb_params[i];

		hcp->setup(hcp->val);
	}

	hugetlb_cma_validate_params();
}

/*
 * hugepages command line processing
 * hugepages normally follows a valid hugepagsz or default_hugepagsz
 * specification.  If not, ignore the hugepages value.  hugepages can also
 * be the first huge page command line  option in which case it implicitly
 * specifies the number of huge pages for the default size.
 */
static int __init hugepages_setup(char *s)
{
	unsigned long *mhp;
	static unsigned long *last_mhp;
	int node = NUMA_NO_NODE;
	int count;
	unsigned long tmp;
	char *p = s;

	if (!parsed_valid_hugepagesz) {
		pr_warn("HugeTLB: hugepages=%s does not follow a valid hugepagesz, ignoring\n", s);
		parsed_valid_hugepagesz = true;
		return -EINVAL;
	}

	/*
	 * !hugetlb_max_hstate means we haven't parsed a hugepagesz= parameter
	 * yet, so this hugepages= parameter goes to the "default hstate".
	 * Otherwise, it goes with the previously parsed hugepagesz or
	 * default_hugepagesz.
	 */
	else if (!hugetlb_max_hstate)
		mhp = &default_hstate_max_huge_pages;
	else
		mhp = &parsed_hstate->max_huge_pages;

	if (mhp == last_mhp) {
		pr_warn("HugeTLB: hugepages= specified twice without interleaving hugepagesz=, ignoring hugepages=%s\n", s);
		return 1;
	}

	while (*p) {
		count = 0;
		if (sscanf(p, "%lu%n", &tmp, &count) != 1)
			goto invalid;
		/* Parameter is node format */
		if (p[count] == ':') {
			if (!hugetlb_node_alloc_supported()) {
				pr_warn("HugeTLB: architecture can't support node specific alloc, ignoring!\n");
				return 1;
			}
			if (tmp >= MAX_NUMNODES || !node_online(tmp))
				goto invalid;
			node = array_index_nospec(tmp, MAX_NUMNODES);
			p += count + 1;
			/* Parse hugepages */
			if (sscanf(p, "%lu%n", &tmp, &count) != 1)
				goto invalid;
			if (!hugetlb_max_hstate)
				default_hugepages_in_node[node] = tmp;
			else
				parsed_hstate->max_huge_pages_node[node] = tmp;
			*mhp += tmp;
			/* Go to parse next node*/
			if (p[count] == ',')
				p += count + 1;
			else
				break;
		} else {
			if (p != s)
				goto invalid;
			*mhp = tmp;
			break;
		}
	}

	last_mhp = mhp;

	return 0;

invalid:
	pr_warn("HugeTLB: Invalid hugepages parameter %s\n", p);
	hugepages_clear_pages_in_node();
	return -EINVAL;
}
hugetlb_early_param("hugepages", hugepages_setup);

/*
 * hugepagesz command line processing
 * A specific huge page size can only be specified once with hugepagesz.
 * hugepagesz is followed by hugepages on the command line.  The global
 * variable 'parsed_valid_hugepagesz' is used to determine if prior
 * hugepagesz argument was valid.
 */
static int __init hugepagesz_setup(char *s)
{
	unsigned long size;
	struct hstate *h;

	parsed_valid_hugepagesz = false;
	size = (unsigned long)memparse(s, NULL);

	if (!arch_hugetlb_valid_size(size)) {
		pr_err("HugeTLB: unsupported hugepagesz=%s\n", s);
		return -EINVAL;
	}

	h = size_to_hstate(size);
	if (h) {
		/*
		 * hstate for this size already exists.  This is normally
		 * an error, but is allowed if the existing hstate is the
		 * default hstate.  More specifically, it is only allowed if
		 * the number of huge pages for the default hstate was not
		 * previously specified.
		 */
		if (!parsed_default_hugepagesz ||  h != &default_hstate ||
		    default_hstate.max_huge_pages) {
			pr_warn("HugeTLB: hugepagesz=%s specified twice, ignoring\n", s);
			return -EINVAL;
		}

		/*
		 * No need to call hugetlb_add_hstate() as hstate already
		 * exists.  But, do set parsed_hstate so that a following
		 * hugepages= parameter will be applied to this hstate.
		 */
		parsed_hstate = h;
		parsed_valid_hugepagesz = true;
		return 0;
	}

	hugetlb_add_hstate(ilog2(size) - PAGE_SHIFT);
	parsed_valid_hugepagesz = true;
	return 0;
}
hugetlb_early_param("hugepagesz", hugepagesz_setup);

/*
 * default_hugepagesz command line input
 * Only one instance of default_hugepagesz allowed on command line.
 */
static int __init default_hugepagesz_setup(char *s)
{
	unsigned long size;
	int i;

	parsed_valid_hugepagesz = false;
	if (parsed_default_hugepagesz) {
		pr_err("HugeTLB: default_hugepagesz previously specified, ignoring %s\n", s);
		return -EINVAL;
	}

	size = (unsigned long)memparse(s, NULL);

	if (!arch_hugetlb_valid_size(size)) {
		pr_err("HugeTLB: unsupported default_hugepagesz=%s\n", s);
		return -EINVAL;
	}

	hugetlb_add_hstate(ilog2(size) - PAGE_SHIFT);
	parsed_valid_hugepagesz = true;
	parsed_default_hugepagesz = true;
	default_hstate_idx = hstate_index(size_to_hstate(size));

	/*
	 * The number of default huge pages (for this size) could have been
	 * specified as the first hugetlb parameter: hugepages=X.  If so,
	 * then default_hstate_max_huge_pages is set.  If the default huge
	 * page size is gigantic (> MAX_PAGE_ORDER), then the pages must be
	 * allocated here from bootmem allocator.
	 */
	if (default_hstate_max_huge_pages) {
		default_hstate.max_huge_pages = default_hstate_max_huge_pages;
		/*
		 * Since this is an early parameter, we can't check
		 * NUMA node state yet, so loop through MAX_NUMNODES.
		 */
		for (i = 0; i < MAX_NUMNODES; i++) {
			if (default_hugepages_in_node[i] != 0)
				default_hstate.max_huge_pages_node[i] =
					default_hugepages_in_node[i];
		}
		default_hstate_max_huge_pages = 0;
	}

	return 0;
}
hugetlb_early_param("default_hugepagesz", default_hugepagesz_setup);

/*
 * hugepage_alloc_threads command line parsing.
 *
 * When set, use this specific number of threads for the boot
 * allocation of hugepages.
 */
static int __init hugepage_alloc_threads_setup(char *s)
{
	unsigned long allocation_threads;

	if (kstrtoul(s, 0, &allocation_threads) != 0)
		return 1;

	if (allocation_threads == 0)
		return 1;

	hugepage_allocation_threads = allocation_threads;

	return 1;
}
__setup("hugepage_alloc_threads=", hugepage_alloc_threads_setup);
