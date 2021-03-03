// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD SEV-SNP Support
 *
 * Authors:
 *   Weidong Cui <Weidong.Cui@microsoft.com>
 *   Xinyang Ge <xing@microsoft.com>
 */

#define pr_fmt(fmt)	"SEV-SNP: " fmt

#include <linux/sched/debug.h>	/* For show_regs() */
#include <linux/percpu-defs.h>
#include <linux/mem_encrypt.h>
#include <linux/lockdep.h>
#include <linux/printk.h>
#include <linux/mm_types.h>
#include <linux/set_memory.h>
#include <linux/memblock.h>
#include <linux/kernel.h>
#include <linux/mm.h>

#include <asm/cpu_entry_area.h>
#include <asm/stacktrace.h>
#include <asm/sev-es.h>
#include <asm/insn-eval.h>
#include <asm/fpu/internal.h>
#include <asm/processor.h>
#include <asm/realmode.h>
#include <asm/traps.h>
#include <asm/svm.h>
#include <asm/smp.h>
#include <asm/cpu.h>
#include <asm/apic.h>

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

void sev_snp_setup_hv_doorbell_page(void)
{
	u64 pa;
	unsigned long flags;
	struct ghcb *ghcb;
	struct sev_hv_doorbell_page *hv_doorbell_page = sev_snp_current_doorbell_page();
	enum es_result ret;

	pa = __pa(hv_doorbell_page);
	if (sev_vtom_enabled())
		pa = sev_vtom_get_alias(pa, false);

	local_irq_save(flags);
	ghcb = sev_es_current_ghcb();
	vc_ghcb_invalidate(ghcb);
	ret = sev_es_ghcb_hv_call(ghcb, NULL, SVM_VMGEXIT_HV_DOORBELL_PAGE,
				SVM_VMGEXIT_SET_HV_DOORBELL_PAGE, pa);
	VMGEXIT();
	local_irq_restore(flags);

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

	sev_snp_setup_hv_doorbell_page();
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

DEFINE_IDTENTRY_RAW(exc_hv)
{
	struct sev_hv_doorbell_page *hvp = sev_snp_current_doorbell_page();

	this_cpu_write(hv_pending, 1);

	/* Clear the no_further_signal bit */
	hvp->pending_events &= 0x7fff;

	/* TODO: handle NMI and MC? */

	check_hv_pending(regs);
}

static inline u64 sev_snp_rd_ghcb_msr(void)
{
	unsigned long low, high;

	asm volatile("rdmsr\n" : "=a" (low), "=d" (high) :
			"c" (MSR_AMD64_SEV_ES_GHCB));

	return ((high << 32) | low);
}

static inline void sev_snp_wr_ghcb_msr(u64 val)
{
	u32 low, high;

	low  = val & 0xffffffffUL;
	high = val >> 32;

	asm volatile("wrmsr\n" : : "c" (MSR_AMD64_SEV_ES_GHCB),
			"a"(low), "d" (high) : "memory");
}

void sev_snp_setup_ghcb(struct ghcb *ghcb)
{
	u64 ghcbmsr;
	u64 ghcb_gpa;

	BUG_ON(!sev_snp_active());

	ghcb_gpa = __pa(ghcb);
	if (sev_vtom_enabled())
		ghcb_gpa = sev_vtom_get_alias(ghcb_gpa, false);

	sev_snp_wr_ghcb_msr(GHCB_GPA_REGISTER_REQ_MSR(ghcb_gpa >> PAGE_SHIFT));
	VMGEXIT();

	ghcbmsr = sev_snp_rd_ghcb_msr();
	if (GHCB_SEV_GHCB_RESP_CODE(ghcbmsr) != GHCB_GPA_REGISTER_RESP ||
		GHCB_SNP_GPA_REGISTER_RESP_GFN(ghcbmsr) != (ghcb_gpa >> PAGE_SHIFT))
		sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);

	sev_snp_wr_ghcb_msr(GHCB_GPA_REGISTER_REQ_VAL(ghcbmsr));
}

void sev_snp_change_page_state(u64 gpa, bool enc)
{
	u64 ghcbmsr;
	u64 backup = sev_snp_rd_ghcb_msr();
	unsigned long flags;
	u8 state = enc ? SNP_PAGE_STATE_PRIVATE : SNP_PAGE_STATE_SHARED;
	int ret;

	local_irq_save(flags);
	sev_snp_wr_ghcb_msr(GHCB_SNP_PAGE_STATE_CHANGE_REQ_MSR(gpa >> PAGE_SHIFT, state));
	VMGEXIT();
	ghcbmsr = sev_snp_rd_ghcb_msr();
	sev_snp_wr_ghcb_msr(backup);
	local_irq_restore(flags);

	if (ghcbmsr != GHCB_SNP_PAGE_STATE_CHANGE_RESP)
		panic("Failed to change the page state (gpa=%llx, enc=%d)\n", gpa, enc);

	if (enc) {
		PVALIDATE(__va(gpa), 0, 1, ret);
		if (ret != 0)
			panic("Failed to PVALIDATE GPA=%llx\n", gpa);
	}
}
