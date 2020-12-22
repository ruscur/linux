/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __HEAD_40x_H__
#define __HEAD_40x_H__

#include <asm/ptrace.h>	/* for STACK_FRAME_REGS_MARKER */

/*
 * Exception entry code.  This code runs with address translation
 * turned off, i.e. using physical addresses.
 * We assume sprg3 has the physical address of the current
 * task's thread_struct.
 */
.macro EXCEPTION_PROLOG
	mtspr	SPRN_SPRG_SCRATCH0,r10
	mtspr	SPRN_SPRG_SCRATCH1,r11
	mfspr	r11, SPRN_SRR1		/* check whether user or kernel */
	mfcr	r10
	andi.	r11, r11, MSR_PR
	subi	r11, r1, INT_FRAME_SIZE		/* use r1 if kernel */
	beq	1f
	mfspr	r11,SPRN_SPRG_THREAD
	lwz	r11,TASK_STACK-THREAD(r11)
	addi	r11, r11, THREAD_SIZE - INT_FRAME_SIZE
1:	tophys(r11, r11)
	stw	r1,GPR1(r11)
	stw	r1,0(r11)
	tovirt(r1, r11)		/* set new kernel sp */
	stw	r10,_CCR(r11)		/* save registers */
	stw	r12,GPR12(r11)
	stw	r9,GPR9(r11)
	mfspr	r10,SPRN_SPRG_SCRATCH0
	mfspr	r12,SPRN_SPRG_SCRATCH1
	stw	r10,GPR10(r11)
	stw	r12,GPR11(r11)
	mflr	r10
	stw	r10,_LINK(r11)
	mfspr	r12,SPRN_SRR0
	mfspr	r9,SPRN_SRR1
	rlwinm	r9,r9,0,14,12		/* clear MSR_WE (necessary?) */
	stw	r0,GPR0(r11)
	lis	r10,STACK_FRAME_REGS_MARKER@ha /* exception frame marker */
	addi	r10,r10,STACK_FRAME_REGS_MARKER@l
	stw	r10,8(r11)
	SAVE_4GPRS(3, r11)
	SAVE_2GPRS(7, r11)
.endm

.macro SYSCALL_ENTRY trapno
	mfspr	r12,SPRN_SPRG_THREAD
	mfspr	r9, SPRN_SRR1
	andi.	r11, r9, MSR_PR
	lwz	r11,TASK_STACK-THREAD(r12)
	beq-	99f
	addi	r11, r11, THREAD_SIZE - INT_FRAME_SIZE
	tophys(r11, r11)
	stw	r1,GPR1(r11)
	stw	r1,0(r11)
	tovirt(r1, r11)		/* set new kernel sp */
	mflr	r10
	stw	r10, _LINK(r11)
	mfspr	r10,SPRN_SRR0
	stw	r10,_NIP(r11)
	mfcr	r10
	rlwinm	r10,r10,0,4,2	/* Clear SO bit in CR */
	stw	r10,_CCR(r11)		/* save registers */
	rlwinm	r9,r9,0,14,12		/* clear MSR_WE (necessary?) */
	lis	r10,STACK_FRAME_REGS_MARKER@ha /* exception frame marker */
	stw	r2,GPR2(r11)
	addi	r10,r10,STACK_FRAME_REGS_MARKER@l
	stw	r9,_MSR(r11)
	li	r2, \trapno + 1
	stw	r10,8(r11)
	stw	r2,_TRAP(r11)
	SAVE_GPR(0, r11)
	SAVE_4GPRS(3, r11)
	SAVE_2GPRS(7, r11)
	addi	r11,r1,STACK_FRAME_OVERHEAD
	addi	r2,r12,-THREAD
	stw	r11,PT_REGS(r12)
	/* Check to see if the dbcr0 register is set up to debug.  Use the
	   internal debug mode bit to do this. */
	lwz	r12,THREAD_DBCR0(r12)
	andis.	r12,r12,DBCR0_IDM@h
	ACCOUNT_CPU_USER_ENTRY(r2, r11, r12)
	beq+	3f
	/* From user and task is ptraced - load up global dbcr0 */
	li	r12,-1			/* clear all pending debug events */
	mtspr	SPRN_DBSR,r12
	lis	r11,global_dbcr0@ha
	tophys(r11,r11)
	addi	r11,r11,global_dbcr0@l
	lwz	r12,0(r11)
	mtspr	SPRN_DBCR0,r12
	lwz	r12,4(r11)
	addi	r12,r12,-1
	stw	r12,4(r11)

3:
	tovirt(r2, r2)	 	/* set r2 to current */
	lis	r11, transfer_to_syscall@h
	ori	r11, r11, transfer_to_syscall@l
#ifdef CONFIG_TRACE_IRQFLAGS
	/*
	 * If MSR is changing we need to keep interrupts disabled at this point
	 * otherwise we might risk taking an interrupt before we tell lockdep
	 * they are enabled.
	 */
	LOAD_REG_IMMEDIATE(r10, MSR_KERNEL)
	rlwimi	r10, r9, 0, MSR_EE
#else
	LOAD_REG_IMMEDIATE(r10, MSR_KERNEL | MSR_EE)
#endif
	mtspr	SPRN_SRR1,r10
	mtspr	SPRN_SRR0,r11
	rfi				/* jump to handler, enable MMU */
	b .	/* Prevent prefetch past rfi */
99:	b	ret_from_kernel_syscall
.endm

.macro tovirt_vmstack dst, src
	.ifnc	\dst, \src
	mr	\dst, \src
	.endif
.endm

.macro tovirt_novmstack dst, src
	tovirt(\dst, \src)
.endm

.macro tophys_novmstack dst, src
	tophys(\dst, \src)
.endm

/*
 * Note: code which follows this uses cr0.eq (set if from kernel),
 * r11, r12 (SRR0), and r9 (SRR1).
 *
 * Note2: once we have set r1 we are in a position to take exceptions
 * again, and we could thus set MSR:RI at that point.
 */

/*
 * Exception vectors.
 */
#define	START_EXCEPTION(n, label)		\
	. = n;					\
label:


#define EXCEPTION(n, label, hdlr, xfer)		\
	START_EXCEPTION(n, label)		\
	EXCEPTION_PROLOG;			\
	addi	r3,r1,STACK_FRAME_OVERHEAD;	\
	xfer(n, hdlr)

#define EXC_XFER_TEMPLATE(hdlr, trap, msr, tfer, ret)		\
	li	r10,trap;					\
	stw	r10,_TRAP(r11);					\
	LOAD_REG_IMMEDIATE(r10, msr);				\
	bl	tfer;						\
	.long	hdlr;						\
	.long	ret

#define EXC_XFER_STD(n, hdlr)		\
	EXC_XFER_TEMPLATE(hdlr, n, MSR_KERNEL, transfer_to_handler_full,	\
			  ret_from_except_full)

#define EXC_XFER_LITE(n, hdlr)		\
	EXC_XFER_TEMPLATE(hdlr, n+1, MSR_KERNEL, transfer_to_handler, \
			  ret_from_except)
#endif /* __HEAD_40x_H__ */
