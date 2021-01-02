/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _ASM_POWERPC_INTERRUPT_H
#define _ASM_POWERPC_INTERRUPT_H

#include <linux/context_tracking.h>
#include <asm/ftrace.h>

/**
 * DECLARE_INTERRUPT_HANDLER_RAW - Declare raw interrupt handler function
 * @func:	Function name of the entry point
 * @returns:	Returns a value back to asm caller
 */
#define DECLARE_INTERRUPT_HANDLER_RAW(func)				\
	__visible long func(struct pt_regs *regs)

/**
 * DEFINE_INTERRUPT_HANDLER_RAW - Define raw interrupt handler function
 * @func:	Function name of the entry point
 * @returns:	Returns a value back to asm caller
 *
 * @func is called from ASM entry code.
 *
 * This is a plain function which does no tracing, reconciling, etc.
 * The macro is written so it acts as function definition. Append the
 * body with a pair of curly brackets.
 *
 * raw interrupt handlers must not enable or disable interrupts, or
 * schedule, tracing and instrumentation (ftrace, lockdep, etc) would
 * not be advisable either, although may be possible in a pinch, the
 * trace will look odd at least.
 *
 * A raw handler may call one of the other interrupt handler functions
 * to be converted into that interrupt context without these restrictions.
 *
 * On PPC64, _RAW handlers may return with fast_interrupt_return.
 *
 * Specific handlers may have additional restrictions.
 */
#define DEFINE_INTERRUPT_HANDLER_RAW(func)				\
static __always_inline long ____##func(struct pt_regs *regs);		\
									\
__visible noinstr long func(struct pt_regs *regs)			\
{									\
	long ret;							\
									\
	ret = ____##func (regs);					\
									\
	return ret;							\
}									\
									\
static __always_inline long ____##func(struct pt_regs *regs)

/**
 * DECLARE_INTERRUPT_HANDLER - Declare synchronous interrupt handler function
 * @func:	Function name of the entry point
 */
#define DECLARE_INTERRUPT_HANDLER(func)					\
	__visible void func(struct pt_regs *regs)

/**
 * DEFINE_INTERRUPT_HANDLER - Define synchronous interrupt handler function
 * @func:	Function name of the entry point
 *
 * @func is called from ASM entry code.
 *
 * The macro is written so it acts as function definition. Append the
 * body with a pair of curly brackets.
 */
#define DEFINE_INTERRUPT_HANDLER(func)					\
static __always_inline void ____##func(struct pt_regs *regs);		\
									\
__visible noinstr void func(struct pt_regs *regs)			\
{									\
	____##func (regs);						\
}									\
									\
static __always_inline void ____##func(struct pt_regs *regs)

/**
 * DECLARE_INTERRUPT_HANDLER_RET - Declare synchronous interrupt handler function
 * @func:	Function name of the entry point
 * @returns:	Returns a value back to asm caller
 */
#define DECLARE_INTERRUPT_HANDLER_RET(func)				\
	__visible long func(struct pt_regs *regs)

/**
 * DEFINE_INTERRUPT_HANDLER_RET - Define synchronous interrupt handler function
 * @func:	Function name of the entry point
 * @returns:	Returns a value back to asm caller
 *
 * @func is called from ASM entry code.
 *
 * The macro is written so it acts as function definition. Append the
 * body with a pair of curly brackets.
 */
#define DEFINE_INTERRUPT_HANDLER_RET(func)				\
static __always_inline long ____##func(struct pt_regs *regs);		\
									\
__visible noinstr long func(struct pt_regs *regs)			\
{									\
	long ret;							\
									\
	ret = ____##func (regs);					\
									\
	return ret;							\
}									\
									\
static __always_inline long ____##func(struct pt_regs *regs)

/**
 * DECLARE_INTERRUPT_HANDLER_ASYNC - Declare asynchronous interrupt handler function
 * @func:	Function name of the entry point
 */
#define DECLARE_INTERRUPT_HANDLER_ASYNC(func)				\
	__visible void func(struct pt_regs *regs)

/**
 * DEFINE_INTERRUPT_HANDLER_ASYNC - Define asynchronous interrupt handler function
 * @func:	Function name of the entry point
 *
 * @func is called from ASM entry code.
 *
 * The macro is written so it acts as function definition. Append the
 * body with a pair of curly brackets.
 */
#define DEFINE_INTERRUPT_HANDLER_ASYNC(func)				\
static __always_inline void ____##func(struct pt_regs *regs);		\
									\
__visible noinstr void func(struct pt_regs *regs)			\
{									\
	____##func (regs);						\
}									\
									\
static __always_inline void ____##func(struct pt_regs *regs)

/**
 * DECLARE_INTERRUPT_HANDLER_NMI - Declare NMI interrupt handler function
 * @func:	Function name of the entry point
 * @returns:	Returns a value back to asm caller
 */
#define DECLARE_INTERRUPT_HANDLER_NMI(func)				\
	__visible long func(struct pt_regs *regs)

/**
 * DEFINE_INTERRUPT_HANDLER_NMI - Define NMI interrupt handler function
 * @func:	Function name of the entry point
 * @returns:	Returns a value back to asm caller
 *
 * @func is called from ASM entry code.
 *
 * The macro is written so it acts as function definition. Append the
 * body with a pair of curly brackets.
 */
#define DEFINE_INTERRUPT_HANDLER_NMI(func)				\
static __always_inline long ____##func(struct pt_regs *regs);		\
									\
__visible noinstr long func(struct pt_regs *regs)			\
{									\
	long ret;							\
									\
	ret = ____##func (regs);					\
									\
	return ret;							\
}									\
									\
static __always_inline long ____##func(struct pt_regs *regs)


/* Interrupt handlers */
DECLARE_INTERRUPT_HANDLER_NMI(machine_check_early);
DECLARE_INTERRUPT_HANDLER_NMI(hmi_exception_realmode);
DECLARE_INTERRUPT_HANDLER(SMIException);
DECLARE_INTERRUPT_HANDLER(handle_hmi_exception);
DECLARE_INTERRUPT_HANDLER(instruction_breakpoint_exception);
DECLARE_INTERRUPT_HANDLER(RunModeException);
DECLARE_INTERRUPT_HANDLER(single_step_exception);
DECLARE_INTERRUPT_HANDLER(program_check_exception);
DECLARE_INTERRUPT_HANDLER(alignment_exception);
DECLARE_INTERRUPT_HANDLER(StackOverflow);
DECLARE_INTERRUPT_HANDLER(stack_overflow_exception);
DECLARE_INTERRUPT_HANDLER(kernel_fp_unavailable_exception);
DECLARE_INTERRUPT_HANDLER(altivec_unavailable_exception);
DECLARE_INTERRUPT_HANDLER(vsx_unavailable_exception);
DECLARE_INTERRUPT_HANDLER(fp_unavailable_tm);
DECLARE_INTERRUPT_HANDLER(altivec_unavailable_tm);
DECLARE_INTERRUPT_HANDLER(vsx_unavailable_tm);
DECLARE_INTERRUPT_HANDLER(facility_unavailable_exception);
DECLARE_INTERRUPT_HANDLER_ASYNC(TAUException);
DECLARE_INTERRUPT_HANDLER(altivec_assist_exception);
DECLARE_INTERRUPT_HANDLER(unrecoverable_exception);
DECLARE_INTERRUPT_HANDLER(kernel_bad_stack);
DECLARE_INTERRUPT_HANDLER_NMI(system_reset_exception);
#ifdef CONFIG_PPC_BOOK3S_64
DECLARE_INTERRUPT_HANDLER_ASYNC(machine_check_exception);
#else
DECLARE_INTERRUPT_HANDLER_NMI(machine_check_exception);
#endif
DECLARE_INTERRUPT_HANDLER(emulation_assist_interrupt);
DECLARE_INTERRUPT_HANDLER_RAW(do_slb_fault);
DECLARE_INTERRUPT_HANDLER(do_bad_slb_fault);
DECLARE_INTERRUPT_HANDLER_RAW(do_hash_fault);
DECLARE_INTERRUPT_HANDLER_RET(do_page_fault);
DECLARE_INTERRUPT_HANDLER(__do_bad_page_fault);
DECLARE_INTERRUPT_HANDLER(do_bad_page_fault);

DECLARE_INTERRUPT_HANDLER_ASYNC(timer_interrupt);
DECLARE_INTERRUPT_HANDLER_NMI(performance_monitor_exception_nmi);
DECLARE_INTERRUPT_HANDLER_ASYNC(performance_monitor_exception_async);
DECLARE_INTERRUPT_HANDLER_RAW(performance_monitor_exception);
DECLARE_INTERRUPT_HANDLER(WatchdogException);
DECLARE_INTERRUPT_HANDLER(unknown_exception);
DECLARE_INTERRUPT_HANDLER_ASYNC(unknown_async_exception);

void replay_system_reset(void);
void replay_soft_interrupts(void);

#endif /* _ASM_POWERPC_INTERRUPT_H */
