// SPDX-License-Identifier: GPL-2.0

/*
 * MMU-generic set_memory implementation for powerpc
 *
 * Copyright 2019, IBM Corporation.
 */

#include <linux/mm.h>
#include <linux/set_memory.h>

#include <asm/mmu.h>
#include <asm/page.h>
#include <asm/pgtable.h>


/*
 * Updates the attributes of a page in three steps:
 *
 * 1. invalidate the page table entry
 * 2. flush the TLB
 * 3. install the new entry with the updated attributes
 *
 * This is unsafe if the caller is attempting to change the mapping of the
 * page it is executing from, or if another CPU is concurrently using the
 * page being altered.
 *
 * TODO make the implementation resistant to this.
 *
 * NOTE: can be dangerous to call without STRICT_KERNEL_RWX
 */
static int change_page_attr(pte_t *ptep, unsigned long addr, void *data)
{
	long action = (long)data;
	pte_t pte;

	spin_lock(&init_mm.page_table_lock);

	/* invalidate the PTE so it's safe to modify */
	pte = ptep_get_and_clear(&init_mm, addr, ptep);
	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);

	/* modify the PTE bits as desired, then apply */
	switch (action) {
	case SET_MEMORY_RO:
		pte = pte_wrprotect(pte);
		break;
	case SET_MEMORY_RW:
		pte = pte_mkwrite(pte);
		break;
	case SET_MEMORY_NX:
		pte = pte_exprotect(pte);
		break;
	case SET_MEMORY_X:
		pte = pte_mkexec(pte);
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}

	set_pte_at(&init_mm, addr, ptep, pte);
	spin_unlock(&init_mm.page_table_lock);

	return 0;
}

int change_memory_attr(unsigned long addr, int numpages, long action)
{
	unsigned long start = ALIGN_DOWN(addr, PAGE_SIZE);
	unsigned long sz = numpages * PAGE_SIZE;

	if (!IS_ENABLED(CONFIG_STRICT_KERNEL_RWX))
		return 0;

	if (numpages <= 0)
		return 0;

	return apply_to_existing_page_range(&init_mm, start, sz,
					    change_page_attr, (void *)action);
}

/*
 * Set the attributes of a page:
 *
 * This function is used by PPC32 at the end of init to set final kernel memory
 * protection. It includes changing the maping of the page it is executing from
 * and data pages it is using.
 */
static int set_page_attr(pte_t *ptep, unsigned long addr, void *data)
{
	pgprot_t prot = __pgprot((unsigned long)data);

	spin_lock(&init_mm.page_table_lock);

	set_pte_at(&init_mm, addr, ptep, pte_modify(*ptep, prot));
	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);

	spin_unlock(&init_mm.page_table_lock);

	return 0;
}

int set_memory_attr(unsigned long addr, int numpages, pgprot_t prot)
{
	unsigned long start = ALIGN_DOWN(addr, PAGE_SIZE);
	unsigned long sz = numpages * PAGE_SIZE;

	if (numpages <= 0)
		return 0;

	return apply_to_existing_page_range(&init_mm, start, sz, set_page_attr,
					    (void *)pgprot_val(prot));
}
