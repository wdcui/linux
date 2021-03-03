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

