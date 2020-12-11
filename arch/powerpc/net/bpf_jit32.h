/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * bpf_jit32.h: BPF JIT compiler for PPC32
 *
 * Copyright 2016 Naveen N. Rao <naveen.n.rao@linux.vnet.ibm.com>
 *		  IBM Corporation
 */
#ifndef _BPF_JIT32_H
#define _BPF_JIT32_H

#include "bpf_jit.h"

/*
 * Stack layout:
 *
 *		[	prev sp		] <-------------
 *		[   nv gpr save area	] 6*8		|
 *		[    tail_call_cnt	] 8		|
 *		[    local_tmp_var	] 8		|
 * fp (r31) -->	[   ebpf stack space	] upto 512	|
 *		[     frame header	] 32/112	|
 * sp (r1) --->	[    stack pointer	] --------------
 */

/* for gpr non volatile registers BPG_REG_6 to 10 */
#define BPF_PPC_STACK_SAVE	((17+3)*4)
/* for bpf JIT code internal usage */
#define BPF_PPC_STACK_LOCALS	16
/* stack frame excluding BPF stack, ensure this is quadword aligned */
#define BPF_PPC_STACKFRAME	(STACK_FRAME_MIN_SIZE + \
				 BPF_PPC_STACK_LOCALS + BPF_PPC_STACK_SAVE)

#ifndef __ASSEMBLY__

/* BPF register usage */
#define TMP_REG	(MAX_BPF_JIT_REG + 0)

/* BPF to ppc register mappings */
static const int b2p[] = {
	/* function return value */
	[BPF_REG_0] = 22,
	/* function arguments */
	[BPF_REG_1] = 4,
	[BPF_REG_2] = 6,
	[BPF_REG_3] = 8,
	[BPF_REG_4] = 10,
	[BPF_REG_5] = 12,
	/* non volatile registers */
	[BPF_REG_6] = 24,
	[BPF_REG_7] = 26,
	[BPF_REG_8] = 28,
	[BPF_REG_9] = 30,
	/* frame pointer aka BPF_REG_10 */
	[BPF_REG_FP] = 31,
	/* eBPF jit internal registers */
	[BPF_REG_AX] = 20,
	[TMP_REG] = 18,
};

/* PPC NVR range -- update this if we ever use NVRs below r27 */
#define BPF_PPC_NVR_MIN		18

#define SEEN_FUNC	0x20000000 /* might call external helpers */
#define SEEN_STACK	0x40000000 /* uses BPF stack */
#define SEEN_TAILCALL	0x80000000 /* uses tail calls */

struct codegen_context {
	/*
	 * This is used to track register usage as well
	 * as calls to external helpers.
	 * - register usage is tracked with corresponding
	 *   bits (r3-r10 and r27-r31)
	 * - rest of the bits can be used to track other
	 *   things -- for now, we use bits 16 to 23
	 *   encoded in SEEN_* macros above
	 */
	unsigned int seen;
	unsigned int idx;
	unsigned int stack_size;
};

#endif /* !__ASSEMBLY__ */

#endif
