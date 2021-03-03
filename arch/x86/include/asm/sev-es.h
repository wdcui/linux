/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AMD Encrypted Register State Support
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#ifndef __ASM_ENCRYPTED_STATE_H
#define __ASM_ENCRYPTED_STATE_H

#include <linux/types.h>
#include <asm/insn.h>

#define GHCB_SEV_INFO		0x001UL
#define GHCB_SEV_INFO_REQ	0x002UL
#define		GHCB_INFO(v)		((v) & 0xfffUL)
#define		GHCB_PROTO_MAX(v)	(((v) >> 48) & 0xffffUL)
#define		GHCB_PROTO_MIN(v)	(((v) >> 32) & 0xffffUL)
#define		GHCB_PROTO_OUR		0x0001UL
#define GHCB_SEV_CPUID_REQ	0x004UL
#define		GHCB_CPUID_REQ_EAX	0
#define		GHCB_CPUID_REQ_EBX	1
#define		GHCB_CPUID_REQ_ECX	2
#define		GHCB_CPUID_REQ_EDX	3
#define		GHCB_CPUID_REQ(fn, reg) (GHCB_SEV_CPUID_REQ | \
					(((unsigned long)reg & 3) << 30) | \
					(((unsigned long)fn) << 32))

#define	GHCB_PROTOCOL_MAX	0x0001UL
#define GHCB_DEFAULT_USAGE	0x0000UL

#define GHCB_SEV_CPUID_RESP	0x005UL

#define GHCB_GPA_REGISTER_REQ	0x012UL
#define 	GHCB_GPA_REGISTER_REQ_VAL(v)		((v) & ~0xfff)
#define		GHCB_GPA_REGISTER_REQ_MSR(gfn) (GHCB_GPA_REGISTER_REQ | ((u64)(gfn)) << 12)

#define GHCB_GPA_REGISTER_RESP	0x013UL
#define 	GHCB_GPA_REGISTER_RESP_VAL(reg, val)	((reg) | (v))
#define		GHCB_SNP_GPA_REGISTER_RESP_GFN(v)	((v) >> 12)

#define GHCB_SNP_PAGE_STATE_CHANGE_REQ	0x0014
#define		GHCB_SNP_PAGE_STATE_CHANGE_REQ_MSR(gfn, op) \
			(GHCB_SNP_PAGE_STATE_CHANGE_REQ | \
			(((u64)(gfn)) << 12) | \
			(((u64)(op)) << 52))

#define		GHCB_SNP_PAGE_STATE_REQ_GFN(v)	(((v) >> 12) & 0xffffffffff)
#define		GHCB_SNP_PAGE_STATE_REQ_OP(v)	((((unsigned long)(v)) >> 52) & 0xf)
#define		SNP_PAGE_STATE_PRIVATE		1
#define		SNP_PAGE_STATE_SHARED		2
#define		SNP_PAGE_STATE_PSMASH		3
#define		SNP_PAGE_STATE_UNSMASH		4

#define GHCB_SNP_PAGE_STATE_CHANGE_RESP	0x0015
#define		GHCB_SNP_PAGE_STATE_RESP_VAL(reg, val)	\
			(((reg) & 0xFFF) | ((val) << 32))

#define GHCB_SEV_TERMINATE	0x100UL
#define		GHCB_SEV_TERMINATE_REASON(reason_set, reason_val)	\
			(((((u64)reason_set) &  0x7) << 12) |		\
			 ((((u64)reason_val) & 0xff) << 16))
#define		GHCB_SEV_ES_REASON_GENERAL_REQUEST	0
#define		GHCB_SEV_ES_REASON_PROTOCOL_UNSUPPORTED	1

#define	GHCB_SEV_GHCB_RESP_CODE(v)	((v) & 0xfff)
#define	VMGEXIT()			{ asm volatile("rep; vmmcall\n\r"); }

enum es_result {
	ES_OK,			/* All good */
	ES_UNSUPPORTED,		/* Requested operation not supported */
	ES_VMM_ERROR,		/* Unexpected state from the VMM */
	ES_DECODE_FAILED,	/* Instruction decoding failed */
	ES_EXCEPTION,		/* Instruction caused exception */
	ES_RETRY,		/* Retry instruction emulation */
};

struct es_fault_info {
	unsigned long vector;
	unsigned long error_code;
	unsigned long cr2;
};

struct pt_regs;

/* ES instruction emulation context */
struct es_em_ctxt {
	struct pt_regs *regs;
	struct insn insn;
	struct es_fault_info fi;
};

void do_vc_no_ghcb(struct pt_regs *regs, unsigned long exit_code);

static inline u64 lower_bits(u64 val, unsigned int bits)
{
	u64 mask = (1ULL << bits) - 1;

	return (val & mask);
}

struct real_mode_header;
enum stack_type;

/* Early IDT entry points for #VC handler */
extern void vc_no_ghcb(void);
extern void vc_boot_ghcb(void);
extern bool handle_vc_boot_ghcb(struct pt_regs *regs);

#ifdef CONFIG_AMD_MEM_ENCRYPT
extern struct static_key_false sev_es_enable_key;
extern void __sev_es_ist_enter(struct pt_regs *regs);
extern void __sev_es_ist_exit(void);
static __always_inline void sev_es_ist_enter(struct pt_regs *regs)
{
	if (static_branch_unlikely(&sev_es_enable_key))
		__sev_es_ist_enter(regs);
}
static __always_inline void sev_es_ist_exit(void)
{
	if (static_branch_unlikely(&sev_es_enable_key))
		__sev_es_ist_exit();
}
extern int sev_es_setup_ap_jump_table(struct real_mode_header *rmh);
extern void __sev_es_nmi_complete(void);
static __always_inline void sev_es_nmi_complete(void)
{
	if (static_branch_unlikely(&sev_es_enable_key))
		__sev_es_nmi_complete();
}
extern int __init sev_es_efi_map_ghcbs(pgd_t *pgd);
#else
static inline void sev_es_ist_enter(struct pt_regs *regs) { }
static inline void sev_es_ist_exit(void) { }
static inline int sev_es_setup_ap_jump_table(struct real_mode_header *rmh) { return 0; }
static inline void sev_es_nmi_complete(void) { }
static inline int sev_es_efi_map_ghcbs(pgd_t *pgd) { return 0; }
#endif

#define SEV_GHCB_FORMAT_BASE        0
#define SEV_GHCB_FORMAT_HYPERCALL   1
#define SEV_GHCB_FORMAT_VTL_RETURN  2

union sev_rmp_adjust
{
    u64 as_uint64;
    struct
    {
        u64 target_vmpl : 8;
        u64 enable_read : 1;
        u64 enable_write : 1;
        u64 enable_user_execute : 1;
        u64 enable_kernel_execute : 1;
        u64 reserved1 : 4;
        u64 vmsa : 1;
    };
};

#define RMPADJUST(addr, size, flags, ret) \
	asm volatile ("movq %1, %%rax\n\t" \
		      "mov %2, %%ecx\n\t" \
		      "movq %3, %%rdx\n\t" \
		      ".byte 0xf3, 0x0f, 0x01, 0xfe\n\t" \
		      "movq %%rax, %0" \
			: "=r" (ret) \
			: "r" (addr), "r" (size), "r" (flags) \
			: "rax", "rcx", "rdx")

#define PVALIDATE(addr, largepage, validate, ret) \
	asm volatile ("movq %1, %%rax\n\t" \
		      "mov %2, %%ecx\n\t" \
		      "mov %3, %%edx\n\t" \
		      ".byte 0xf2, 0x0f, 0x01, 0xff\n\t" \
		      "mov %%eax, %0" \
			: "=r" (ret) \
			: "r" (addr), "r" (largepage), "r" (validate) \
			: "cc", "rax", "rcx", "rdx")

struct ghcb *sev_es_current_ghcb(void);
void sev_es_terminate(unsigned int reason);
void sev_snp_setup_ghcb(struct ghcb *ghcb);
void sev_snp_change_page_state(u64 gpa, bool enc);

#endif
