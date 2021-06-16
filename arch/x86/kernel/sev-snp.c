// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2021 Advanced Micro Devices
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 */

#define pr_fmt(fmt)	"SEV-SNP: " fmt

#include <linux/mem_encrypt.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/memblock.h>

#include <asm/sev-es.h>
#include <asm/sev-snp.h>
#include <asm/svm.h>
#include <asm/smp.h>
#include <asm/cpu.h>
#include <asm/apic.h>
#include <asm/traps.h>

struct sev_hv_doorbell_page {
	union {
		u16 pending_events;
		struct {
			u8 vector;
			u8 nmi : 1;
			u8 mc : 1;
			u8 reserved1 : 5;
			u8 no_further_signal : 1;
		};
	};
	u8 no_eoi_required;
	u8 reserved2[61];
	u8 padding[4032];
};

struct sev_snp_runtime_data {
	struct sev_hv_doorbell_page hv_doorbell_page;
};

static DEFINE_PER_CPU(struct sev_snp_runtime_data*, snp_runtime_data);

struct sev_hv_doorbell_page *sev_snp_current_doorbell_page(void)
{
	return &this_cpu_read(snp_runtime_data)->hv_doorbell_page;
}

void sev_snp_setup_hv_doorbell_page(struct ghcb *ghcb)
{
	u64 pa;
	struct sev_hv_doorbell_page *hv_doorbell_page = sev_snp_current_doorbell_page();
	enum es_result ret;

	pa = __pa(hv_doorbell_page);
	vc_ghcb_invalidate(ghcb);
	ret = vmgexit_hv_doorbell_page(ghcb, SVM_VMGEXIT_SET_HV_DOORBELL_PAGE, pa);
	if (ret != ES_OK)
		panic("SEV-SNP: failed to set up #HV doorbell page");
}

static void hv_doorbell_apic_eoi_write(u32 reg, u32 val)
{
	struct sev_hv_doorbell_page *hv_doorbell_page = sev_snp_current_doorbell_page();;

	if (xchg(&hv_doorbell_page->no_eoi_required, 0) & 0x1)
		return;

	BUG_ON(reg != APIC_EOI);
	apic->write(reg, val);
}

void __init sev_snp_init_hv_handling(void)
{
	struct sev_snp_runtime_data *snp_data;
	int cpu;
	int err;
	struct ghcb_state state;
	struct ghcb *ghcb;

	BUILD_BUG_ON(offsetof(struct sev_snp_runtime_data, hv_doorbell_page) % PAGE_SIZE);

	if (!sev_snp_active() || !sev_restricted_injection_enabled())
		return;

	/* Allocate per-cpu doorbell pages */
	for_each_possible_cpu(cpu) {
		snp_data = memblock_alloc(sizeof(*snp_data), PAGE_SIZE);
		if (!snp_data)
			panic("Can't allocate SEV-SNP runtime data");

		err = early_set_memory_decrypted((unsigned long)&snp_data->hv_doorbell_page,
						 sizeof(snp_data->hv_doorbell_page));
		if (err)
			panic("Can't map #HV doorbell pages unencrypted");

		memset(&snp_data->hv_doorbell_page, 0, sizeof(snp_data->hv_doorbell_page));

		per_cpu(snp_runtime_data, cpu) = snp_data;
	}

	ghcb = sev_es_get_ghcb(&state);
	sev_snp_setup_hv_doorbell_page(ghcb);
	sev_es_put_ghcb(&state);
	apic_set_eoi_write(hv_doorbell_apic_eoi_write);
}

static DEFINE_PER_CPU(u8, hv_pending);

static void do_exc_hv(struct pt_regs *regs)
{
	struct sev_hv_doorbell_page *hvp = sev_snp_current_doorbell_page();
	u8 vector;

	BUG_ON((native_save_fl() & X86_EFLAGS_IF) == 0);

	while (this_cpu_read(hv_pending)) {
		asm volatile("cli": : :"memory");
		this_cpu_write(hv_pending, 0);
		vector = xchg(&hvp->vector, 0);

		switch (vector) {
#if IS_ENABLED(CONFIG_HYPERV)
		case HYPERV_STIMER0_VECTOR:
			sysvec_hyperv_stimer0(regs);
			break;
		case HYPERVISOR_CALLBACK_VECTOR:
			sysvec_hyperv_callback(regs);
			break;
#endif
#ifdef CONFIG_SMP
		case RESCHEDULE_VECTOR:
			sysvec_reschedule_ipi(regs);
			break;
		case IRQ_MOVE_CLEANUP_VECTOR:
			sysvec_irq_move_cleanup(regs);
			break;
		case REBOOT_VECTOR:
			sysvec_reboot(regs);
			break;
		case CALL_FUNCTION_SINGLE_VECTOR:
			sysvec_call_function_single(regs);
			break;
		case CALL_FUNCTION_VECTOR:
			sysvec_call_function(regs);
			break;
#endif
#ifdef CONFIG_X86_LOCAL_APIC
		case ERROR_APIC_VECTOR:
			sysvec_error_interrupt(regs);
			break;
		case SPURIOUS_APIC_VECTOR:
			sysvec_spurious_apic_interrupt(regs);
			break;
		case LOCAL_TIMER_VECTOR:
			sysvec_apic_timer_interrupt(regs);
			break;
		case X86_PLATFORM_IPI_VECTOR:
			sysvec_x86_platform_ipi(regs);
			break;
#endif
		case 0x0:
			break;
		default:
			panic("Unexpected vector %d\n", vector);
			unreachable();
		}

		asm volatile("sti": : :"memory");
	}
}

void check_hv_pending(struct pt_regs *regs)
{
	if (!sev_snp_active())
		return;

	if (regs) {
		if ((regs->flags & X86_EFLAGS_IF) == 0)
			return;

		asm volatile("sti": : :"memory");

		if (!this_cpu_read(hv_pending))
			return;

		do_exc_hv(regs);
	} else {
		/* Reached from STI/POPF */
		if (this_cpu_read(hv_pending))
			asm volatile("int %0" :: "i" (X86_TRAP_HV));
	}
}
EXPORT_SYMBOL_GPL(check_hv_pending);

DEFINE_IDTENTRY_RAW(exc_hv)
{
	struct sev_hv_doorbell_page *hvp = sev_snp_current_doorbell_page();

	this_cpu_write(hv_pending, 1);

	/* Clear the no_further_signal bit */
	hvp->pending_events &= 0x7fff;

	/* TODO: handle NMI and MC? */

	check_hv_pending(regs);
}

static inline u64 sev_es_rd_ghcb_msr(void)
{
	return __rdmsr(MSR_AMD64_SEV_ES_GHCB);
}

static inline void sev_es_wr_ghcb_msr(u64 val)
{
	u32 low, high;

	low  = (u32)(val);
	high = (u32)(val >> 32);

	native_wrmsr(MSR_AMD64_SEV_ES_GHCB, low, high);
}

static inline u64 vmgexit_ghcb_msr(u64 val) {
	u64 old;
	unsigned long flags;

	local_irq_save(flags);
	old = sev_es_rd_ghcb_msr();
	sev_es_wr_ghcb_msr(val);
	VMGEXIT();
	val = sev_es_rd_ghcb_msr();
	sev_es_wr_ghcb_msr(old);
	local_irq_restore(flags);

	return val;
}

/* Provides sev_es_terminate() */
#include "sev-common-shared.c"

void sev_snp_register_ghcb(unsigned long paddr)
{
	u64 pfn = paddr >> PAGE_SHIFT;
	u64 val;

	/* Issue VMGEXIT */
	val = vmgexit_ghcb_msr(GHCB_REGISTER_GPA_REQ_VAL(pfn));

	/* If the response GPA is not ours then abort the guest */
	if ((GHCB_SEV_GHCB_RESP_CODE(val) != GHCB_REGISTER_GPA_RESP) ||
	    (GHCB_REGISTER_GPA_RESP_VAL(val) != pfn))
		sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);

	sev_es_wr_ghcb_msr(pfn << PAGE_SHIFT);
}

void sev_snp_issue_pvalidate(unsigned long vaddr, unsigned int npages, bool validate)
{
	unsigned long eflags, vaddr_end, vaddr_next;
	int rc;

	vaddr = vaddr & PAGE_MASK;
	vaddr_end = vaddr + (npages << PAGE_SHIFT);

	for (; vaddr < vaddr_end; vaddr = vaddr_next) {
		rc = __pvalidate(vaddr, RMP_PG_SIZE_4K, validate, &eflags);

		if (rc) {
			pr_err("Failed to validate address 0x%lx ret %d\n", vaddr, rc);
			goto e_fail;
		}

		/* Check for the double validation condition */
		if (eflags & X86_EFLAGS_CF) {
			pr_err("Double %salidation detected (address 0x%lx)\n",
					validate ? "v" : "inv", vaddr);
			goto e_fail;
		}

		vaddr_next = vaddr + PAGE_SIZE;
	}

	return;

e_fail:
	/* Dump stack for the debugging purpose */
	dump_stack();

	/* Ask to terminate the guest */
	sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);
}

static void early_snp_set_page_state(unsigned long paddr, unsigned int npages, int op)
{
	unsigned long paddr_end, paddr_next;
	u64 val;

	paddr = paddr & PAGE_MASK;
	paddr_end = paddr + (npages << PAGE_SHIFT);

	for (; paddr < paddr_end; paddr = paddr_next) {

		/*
		 * Use the MSR protocol VMGEXIT to request the page state change. We use the MSR
		 * protocol VMGEXIT because in early boot we may not have the full GHCB setup
		 * yet.
		 */
		val = vmgexit_ghcb_msr(GHCB_SNP_PAGE_STATE_REQ_GFN(paddr >> PAGE_SHIFT, op));

		/* Read the response, if the page state change failed then terminate the guest. */
		if (GHCB_SEV_GHCB_RESP_CODE(val) != GHCB_SNP_PAGE_STATE_CHANGE_RESP)
			sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);

		if (GHCB_SNP_PAGE_STATE_RESP_VAL(val) != 0) {
			pr_err("Failed to change page state to '%s' paddr 0x%lx error 0x%llx\n",
					op == SNP_PAGE_STATE_PRIVATE ? "private" : "shared",
					paddr, GHCB_SNP_PAGE_STATE_RESP_VAL(val));

			/* Dump stack for the debugging purpose */
			dump_stack();

			/* Ask to terminate the guest */
			sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);
		}

		paddr_next = paddr + PAGE_SIZE;
	}
}

void __init early_snp_set_memory_private(unsigned long vaddr, unsigned long paddr,
					 unsigned int npages)
{
	 /* Ask hypervisor to add the memory in RMP table as a 'private'. */
	early_snp_set_page_state(paddr, npages, SNP_PAGE_STATE_PRIVATE);

	/* Validate the memory region after its added in the RMP table. */
	sev_snp_issue_pvalidate(vaddr, npages, true);
}

void __init early_snp_set_memory_shared(unsigned long vaddr, unsigned long paddr,
					unsigned int npages)
{
	/*
	 * We are chaning the memory from private to shared, invalidate the memory region
	 * before making it shared in the RMP table.
	 */
	sev_snp_issue_pvalidate(vaddr, npages, false);

	 /* Ask hypervisor to make the memory shared in the RMP table. */
	early_snp_set_page_state(paddr, npages, SNP_PAGE_STATE_SHARED);
}

static int snp_page_state_vmgexit(struct ghcb *ghcb, struct snp_page_state_change *data)
{
	struct snp_page_state_header *hdr;
	int ret = 0;

	hdr = &data->header;

	/*
	 * The hypervisor can return before processing all the entries, the loop below retries
	 * until all the entries are processed.
	 */
	while (hdr->cur_entry <= hdr->end_entry) {
		ghcb_set_sw_scratch(ghcb, (u64)__pa(data));
		ret = vmgexit_page_state_change(ghcb, data);
		/* Page State Change VMGEXIT can pass error code through exit_info_2. */
		if (ret || ghcb->save.sw_exit_info_2)
			break;
	}

	return ret;
}

static void snp_set_page_state(unsigned long paddr, unsigned int npages, int op)
{
	unsigned long paddr_end, paddr_next;
	struct snp_page_state_change *data;
	struct snp_page_state_header *hdr;
	struct snp_page_state_entry *e;
	struct ghcb_state state;
	struct ghcb *ghcb;
	int ret, idx;

	paddr = paddr & PAGE_MASK;
	paddr_end = paddr + (npages << PAGE_SHIFT);

	ghcb = sev_es_get_ghcb(&state);

	data = (struct snp_page_state_change *)ghcb->shared_buffer;
	hdr = &data->header;
	e = &(data->entry[0]);
	memset(data, 0, sizeof (*data));

	for (idx = 0; paddr < paddr_end; paddr = paddr_next) {
		int level = PG_LEVEL_4K;

		/* If we cannot fit more request then issue VMGEXIT before going further.  */
		if (hdr->end_entry == (SNP_PAGE_STATE_CHANGE_MAX_ENTRY - 1)) {
			ret = snp_page_state_vmgexit(ghcb, data);
			if (ret)
				goto e_fail;

			idx = 0;
			memset(data, 0, sizeof (*data));
			e = &(data->entry[0]);
		}

		hdr->end_entry = idx;
		e->gfn = paddr >> PAGE_SHIFT;
		e->operation = op;
		e->pagesize = X86_RMP_PG_LEVEL(level);
		e++;
		idx++;
		paddr_next = paddr + page_level_size(level);
	}

	/*
	 * We can exit the above loop before issuing the VMGEXIT, if we exited before calling the
	 * the VMGEXIT, then issue the VMGEXIT now.
	 */
	if (idx)
		ret = snp_page_state_vmgexit(ghcb, data);

	sev_es_put_ghcb(&state);
	return;

e_fail:
	/* Dump stack for the debugging purpose */
	dump_stack();

	/* Ask to terminate the guest */
	sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);
}

int snp_set_memory_shared(unsigned long vaddr, unsigned long paddr, unsigned int npages)
{
	/* Invalidate the memory before changing the page state in the RMP table. */
	sev_snp_issue_pvalidate(vaddr, npages, false);

	/* Change the page state in the RMP table. */
	early_snp_set_page_state(paddr, npages, SNP_PAGE_STATE_SHARED);

	return 0;
}

int snp_set_memory_private(unsigned long vaddr, unsigned long paddr, unsigned int npages)
{
	/* Change the page state in the RMP table. */
	early_snp_set_page_state(paddr, npages, SNP_PAGE_STATE_PRIVATE);

	/* Validate the memory after the memory is made private in the RMP table. */
	sev_snp_issue_pvalidate(vaddr, npages, true);

	return 0;
}
