/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AMD SEV Secure Nested Paging Support
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 */

#ifndef __COMPRESSED_SECURE_NESTED_PAGING_H
#define __COMPRESSED_SECURE_NESTED_PAGING_H

#ifdef CONFIG_AMD_MEM_ENCRYPT

void sev_snp_set_page_private(unsigned long paddr);
void sev_snp_set_page_shared(unsigned long paddr);

#else

static inline void sev_snp_set_page_private(unsigned long paddr) { }
static inline void sev_snp_set_page_shared(unsigned long paddr) { }

/* Transition Guest-Invalid pages to Guest-Valid for kernel booting.
   The startup_64 code needs extra memory
    * to use uninitialized symbols (startup_32)
    * to decompress vmlinux.bin to memory
   This step is used to avoid unnecessary LAUNCH_UPDATE via PSP command.
*/
int pvalidate_for_startup_64(void *rmode);
#endif /* CONFIG_AMD_MEM_ENCRYPT */

#endif /* __COMPRESSED_SECURE_NESTED_PAGING_H */
