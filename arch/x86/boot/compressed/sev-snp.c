// SPDX-License-Identifier: GPL-2.0
/*
 * AMD SEV SNP support
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 */

#include "misc.h"
#include "error.h"

#include <asm/e820/types.h>
#include <asm/msr-index.h>
#include <asm/sev-snp.h>
#include <asm/sev-es.h>

#include "sev-snp.h"

static bool sev_snp_enabled(void)
{
	unsigned long low, high;
	u64 val;

	asm volatile("rdmsr\n" : "=a" (low), "=d" (high) :
			"c" (MSR_AMD64_SEV));

	val = (high << 32) | low;

	if (val & MSR_AMD64_SEV_SNP_ENABLED)
		return true;

	return false;
}

/* Provides sev_snp_{wr,rd}_ghcb_msr() */
#include "sev-common.c"

/* Provides sev_es_terminate() */
#include "../../kernel/sev-common-shared.c"

static void sev_snp_pages_state_change(unsigned long paddr, int op)
{
	u64 pfn = paddr >> PAGE_SHIFT;
	u64 old, val;

	/* save the old GHCB MSR */
	old = sev_es_rd_ghcb_msr();

	/* Issue VMGEXIT to change the page state */
	sev_es_wr_ghcb_msr(GHCB_SNP_PAGE_STATE_REQ_GFN(pfn, op));
	VMGEXIT();

	/* Read the response of the VMGEXIT */
	val = sev_es_rd_ghcb_msr();
	if ((GHCB_SEV_GHCB_RESP_CODE(val) != GHCB_SNP_PAGE_STATE_CHANGE_RESP) ||
	    (GHCB_SNP_PAGE_STATE_RESP_VAL(val) != 0))
		sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);

	/* Restore the GHCB MSR value */
	sev_es_wr_ghcb_msr(old);
}

static void sev_snp_issue_pvalidate_page(unsigned long paddr, bool validate)
{
	unsigned long eflags;
	int rc;

	rc = __pvalidate(paddr, RMP_PG_SIZE_4K, validate, &eflags);
	if (rc) {
		error("Failed to validate address");
		goto e_fail;
	}

	/* Check for the double validation and assert on failure */
	if (eflags & X86_EFLAGS_CF) {
		error("Double validation detected");
		goto e_fail;
	}

	return;
e_fail:
	sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);
}

static void sev_snp_set_page_private_shared(unsigned long paddr, int op)
{
	if (!sev_snp_enabled())
		return;

	/*
	 * We are change the page state from private to shared, invalidate the pages before
	 * making the page state change in the RMP table.
	 */
	if (op == SNP_PAGE_STATE_SHARED)
		sev_snp_issue_pvalidate_page(paddr, false);

	/* Request the page state change in the RMP table. */
	sev_snp_pages_state_change(paddr, op);

	/*
	 * Now that pages are added in the RMP table as a private memory, validate the
	 * memory range so that it is consistent with the RMP entry.
	 */
	if (op == SNP_PAGE_STATE_PRIVATE)
		sev_snp_issue_pvalidate_page(paddr, true);
}

void sev_snp_set_page_private(unsigned long paddr)
{
	sev_snp_set_page_private_shared(paddr, SNP_PAGE_STATE_PRIVATE);
}

void sev_snp_set_page_shared(unsigned long paddr)
{
	sev_snp_set_page_private_shared(paddr, SNP_PAGE_STATE_SHARED);
}

void sev_snp_register_ghcb(unsigned long paddr)
{
	u64 pfn = paddr >> PAGE_SHIFT;
	u64 old, val;

	if (!sev_snp_enabled())
		return;

	/* save the old GHCB MSR */
	old = sev_es_rd_ghcb_msr();

	/* Issue VMGEXIT */
	sev_es_wr_ghcb_msr(GHCB_REGISTER_GPA_REQ_VAL(pfn));
	VMGEXIT();

	val = sev_es_rd_ghcb_msr();

	/* If the response GPA is not ours then abort the guest */
	if ((GHCB_SEV_GHCB_RESP_CODE(val) != GHCB_REGISTER_GPA_RESP) ||
	    (GHCB_REGISTER_GPA_RESP_VAL(val) != pfn))
		sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);

	/* Restore the GHCB MSR value */
	sev_es_wr_ghcb_msr(old);
}

static void extend_e820_on_demand(struct boot_e820_entry *e820_entry,
				  u64 needed_ram_end)
{
	u64 end, paddr;
	if (!e820_entry) {
		return;
	}
	end = e820_entry->addr + e820_entry->size;
	if (needed_ram_end > end && e820_entry->type == E820_TYPE_RAM) {
		for (paddr = end; paddr < needed_ram_end; paddr += PAGE_SIZE) {
			sev_snp_issue_pvalidate_page(paddr, true);
		}
		e820_entry->size = needed_ram_end - e820_entry->addr;
	}
}

/*
 * Explictly pvalidate needed pages for decompressing the kernel.
 * The E820_TYPE_RAM entry includes only validated memory. The kernel
 * expects that the RAM entry's addr is fixed while the entry size is to be
 * extended to cover addresses to the start of next entry.
 * The function increases the RAM entry size to cover all possilble memory
 * addresses until init_size.
 * For example,  init_end = 0x4000000,
 * [RAM: 0x0 - 0x0],                       M[RAM: 0x0 - 0xa0000]
 * [RSVD: 0xa0000 - 0x10000]                [RSVD: 0xa0000 - 0x10000]
 * [ACPI: 0x10000 - 0x20000]      ==>       [ACPI: 0x10000 - 0x20000]
 * [RSVD: 0x800000 - 0x900000]              [RSVD: 0x800000 - 0x900000]
 * [RAM: 0x1000000 - 0x2000000]            M[RAM: 0x1000000 - 0x2001000]
 * [RAM: 0x2001000 - 0x2007000]            M[RAM: 0x2001000 - 0x4000000]

 Other RAM memory after init_end is pvalidated by ms_hyperv_init_platform
 */
__visible void pvalidate_for_startup_64(struct boot_params *boot_params)
{
	struct boot_e820_entry *e820_entry;
	u64 init_end =
		boot_params->hdr.pref_address + boot_params->hdr.init_size;
	u64 needed_end;
	u8 i, nr_entries = boot_params->e820_entries;
	if (!sev_snp_enabled()) {
		return;
	}
	for (i = 0; i < nr_entries; ++i) {
		/* Pvalidate memory holes in e820 RAM entries. */
		e820_entry = &boot_params->e820_table[i];
		if (i < nr_entries - 1) {
			needed_end = boot_params->e820_table[i + 1].addr;
			BUG_ON(needed_end <
			       e820_entry->addr + e820_entry->size);
		}else{
			needed_end = init_end;
		}
		extend_e820_on_demand(e820_entry, needed_end);
	}
}
