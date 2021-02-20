/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1995 - 2000 by Ralf Baechle
 */
#include <linux/context_tracking.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/ratelimit.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/kprobes.h>
#include <linux/perf_event.h>
#include <linux/uaccess.h>

#include <asm/branch.h>
#include <asm/mmu_context.h>
#include <asm/ptrace.h>
#include <asm/highmem.h>		/* For VMALLOC_END */
#include <linux/kdebug.h>

int show_unhandled_signals = 1;

static inline void no_context(struct pt_regs *regs, unsigned long address)
{
	const int field = sizeof(unsigned long) * 2;

	/* Are we prepared to handle this kernel fault?	 */
	if (likely(fixup_exception(regs))) {
		current->thread.cp0_baduaddr = address;
		return;
	}

	/*
	 * Oops. The kernel tried to access some bad page. We'll have to
	 * terminate things with extreme prejudice.
	 */
	bust_spinlocks(1);

	printk(KERN_ALERT "CPU %d Unable to handle kernel paging request at virtual address %0*lx, epc == %0*lx, ra == %0*lx\n",
	       raw_smp_processor_id(), field, address, field, regs->cp0_epc,
	       field,  regs->regs[31]);
	die("Oops", regs);
}

static inline int access_error(unsigned long write, struct pt_regs *regs,
					unsigned long address, struct vm_area_struct *vma)
{
	if (write) {
		if (unlikely(!(vma->vm_flags & VM_WRITE)))
			return true;
	} else {
		if (cpu_has_rixi) {
			if (unlikely(address == regs->cp0_epc && !(vma->vm_flags & VM_EXEC)))
				return true;
			if (unlikely(!(vma->vm_flags & VM_READ) &&
				exception_epc(regs) != address)) {
				return true;
			}
		} else {
			if (unlikely(!vma_is_accessible(vma)))
				return true;
		}
	}

	return false;
}

static inline void bad_area_nosemaphore(struct pt_regs *regs, int si_code,
					unsigned long write, unsigned long address)
{
	struct task_struct *tsk = current;
	const int field = sizeof(unsigned long) * 2;

	static DEFINE_RATELIMIT_STATE(ratelimit_state, 5 * HZ, 10);

	/* User mode accesses just cause a SIGSEGV */
	if (user_mode(regs)) {
		tsk->thread.cp0_badvaddr = address;
		tsk->thread.error_code = write;
		if (show_unhandled_signals &&
		    unhandled_signal(tsk, SIGSEGV) &&
		    __ratelimit(&ratelimit_state)) {
			pr_info("do_page_fault(): sending SIGSEGV to %s for invalid %s %0*lx\n",
				tsk->comm,
				write ? "write access to" : "read access from",
				field, address);
			pr_info("epc = %0*lx in", field,
				(unsigned long) regs->cp0_epc);
			print_vma_addr(KERN_CONT " ", regs->cp0_epc);
			pr_cont("\n");
			pr_info("ra  = %0*lx in", field,
				(unsigned long) regs->regs[31]);
			print_vma_addr(KERN_CONT " ", regs->regs[31]);
			pr_cont("\n");
		}
		tsk->thread.trap_nr = (regs->cp0_cause >> 2) & 0x1f;
		force_sig_fault(SIGSEGV, si_code, (void __user *)address);
		return;
	}

	no_context(regs, address);
}


/*
 * Something tried to access memory that isn't in our memory map..
 * Fix it, but check if it's kernel or user first..
 */
static inline void bad_area(struct pt_regs *regs, int si_code, unsigned long write,
					unsigned long address)
{
	mmap_read_unlock(current->mm);
	bad_area_nosemaphore(regs, si_code, write, address);
}


#ifndef CONFIG_64BIT
static inline void vmalloc_fault(struct pt_regs *regs, unsigned long address)
{
	/*
	 * Synchronize this task's top level page-table
	 * with the 'reference' page table.
	 *
	 * Do _not_ use "tsk" here. We might be inside
	 * an interrupt in the middle of a task switch..
	 */
	int offset = pgd_index(address);
	pgd_t *pgd, *pgd_k;
	p4d_t *p4d, *p4d_k;
	pud_t *pud, *pud_k;
	pmd_t *pmd, *pmd_k;
	pte_t *pte_k;

	pgd = (pgd_t *) pgd_current[raw_smp_processor_id()] + offset;
	pgd_k = init_mm.pgd + offset;

	if (!pgd_present(*pgd_k)) {
		no_context(regs, address);
		return;
	}

	set_pgd(pgd, *pgd_k);

	p4d = p4d_offset(pgd, address);
	p4d_k = p4d_offset(pgd_k, address);
	if (!p4d_present(*p4d_k)) {
		no_context(regs, address);
		return;
	}
	pud = pud_offset(p4d, address);
	pud_k = pud_offset(p4d_k, address);
	if (!pud_present(*pud_k)) {
		no_context(regs, address);
		return;
	}
	pmd = pmd_offset(pud, address);
	pmd_k = pmd_offset(pud_k, address);
	if (!pmd_present(*pmd_k)) {
		no_context(regs, address);
		return;
	}
	set_pmd(pmd, *pmd_k);

	pte_k = pte_offset_kernel(pmd_k, address);
	if (!pte_present(*pte_k)) {
		no_context(regs, address);
		return;
	}
}
#endif


static void
do_sigbus(struct pt_regs *regs, unsigned long address)
{
	struct task_struct *tsk = current;
	struct mm_struct *mm = tsk->mm;

	mmap_read_unlock(mm);


	/* Kernel mode? Handle exceptions or die */
	if (!user_mode(regs)) {
		no_context(regs, address);
		return;
	}

	/*
	 * Send a sigbus, regardless of whether we were in kernel
	 * or user mode.
	 */
	current->thread.trap_nr = (regs->cp0_cause >> 2) & 0x1f;
	current->thread.cp0_badvaddr = address;
	force_sig_fault(SIGBUS, BUS_ADRERR, (void __user *)address);
}


static noinline void
mm_fault_error(struct pt_regs *regs, unsigned long si_code,
	       unsigned long write, unsigned long address, vm_fault_t fault)
{
	if (fault & VM_FAULT_OOM) {
		/*
		 * We ran out of memory, call the OOM killer, and return the userspace
		 * (which will retry the fault, or kill us if we got oom-killed).
		 */
		mmap_read_unlock(current->mm);
		if (!user_mode(regs)) {
			no_context(regs, address);
			return;
		}
		pagefault_out_of_memory();
		return;
	} else if (fault & VM_FAULT_SIGSEGV) {
		bad_area(regs, si_code, write, address);
		return;
	} else if (fault & VM_FAULT_SIGBUS) {
		do_sigbus(regs, address);
		return;
	}
	BUG();

}

/*
 * This routine handles page faults.  It determines the address,
 * and the problem, and then passes it off to one of the appropriate
 * routines.
 */
static void __kprobes __do_page_fault(struct pt_regs *regs, unsigned long write,
	unsigned long address)
{
	struct vm_area_struct * vma = NULL;
	struct task_struct *tsk = current;
	struct mm_struct *mm = tsk->mm;
	int si_code = SEGV_MAPERR;
	vm_fault_t fault;
	unsigned int flags = FAULT_FLAG_DEFAULT;

#ifdef CONFIG_KPROBES
	/*
	 * This is to notify the fault handler of the kprobes.
	 */
	if (notify_die(DIE_PAGE_FAULT, "page fault", regs, -1,
		       tsk->thread.trap_nr, SIGSEGV) == NOTIFY_STOP)
		return;
#endif

	/*
	 * We fault-in kernel-space virtual memory on-demand. The
	 * 'reference' page table is init_mm.pgd.
	 *
	 * NOTE! We MUST NOT take any locks for this case. We may
	 * be in an interrupt or a critical region, and should
	 * only copy the information from the master page table,
	 * nothing more.
	 */
#ifdef CONFIG_64BIT
# define VMALLOC_FAULT_TARGET no_context
#else
# define VMALLOC_FAULT_TARGET vmalloc_fault
#endif

	if (unlikely(address >= VMALLOC_START && address <= VMALLOC_END)) {
		VMALLOC_FAULT_TARGET(regs, address);
		return;
	}

#ifdef MODULE_START
	if (unlikely(address >= MODULE_START && address < MODULE_END)) {
		VMALLOC_FAULT_TARGET(regs, address);
		return;
	}
#endif

	/*
	 * If we're in an interrupt or have no user
	 * context, we must not take the fault..
	 */
	if (unlikely(faulthandler_disabled() || !mm)) {
		bad_area_nosemaphore(regs, si_code, write, address);
		return;
	}

	if (user_mode(regs))
		flags |= FAULT_FLAG_USER;

	if (write)
		flags |= FAULT_FLAG_WRITE;

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, address);

retry:
	mmap_read_lock(mm);
	vma = find_vma(mm, address);
	if (unlikely(!vma)) {
		bad_area(regs, si_code, write, address);
		return;
	}

	if (likely(vma->vm_start <= address))
		goto good_area;

	if (unlikely(!(vma->vm_flags & VM_GROWSDOWN))) {
		bad_area(regs, si_code, write, address);
		return;

	}

	if (unlikely(expand_stack(vma, address))) {
		bad_area(regs, si_code, write, address);
		return;
	}

/*
 * Ok, we have a good vm_area for this memory access, so
 * we can handle it..
 */
good_area:
	si_code = SEGV_ACCERR;

	if (access_error(write, regs, address, vma)) {
		bad_area(regs, si_code, write, address);
		return;
	}

	/*
	 * If for any reason at all we couldn't handle the fault,
	 * make sure we exit gracefully rather than endlessly redo
	 * the fault.
	 */
	fault = handle_mm_fault(vma, address, flags, regs);

	if (fault_signal_pending(fault, regs))
		return;

	if (unlikely(fault & VM_FAULT_ERROR)) {
		mm_fault_error(regs, si_code, write, address, fault);
		return;
	}

	if (flags & FAULT_FLAG_ALLOW_RETRY) {
		if (fault & VM_FAULT_RETRY) {
			flags |= FAULT_FLAG_TRIED;

			/*
			 * No need to mmap_read_unlock(mm) as we would
			 * have already released it in __lock_page_or_retry
			 * in mm/filemap.c.
			 */

			goto retry;
		}
	}
	mmap_read_unlock(mm);
	return;

}

asmlinkage void __kprobes do_page_fault(struct pt_regs *regs,
	unsigned long write, unsigned long address)
{
	enum ctx_state prev_state;

	prev_state = exception_enter();
	__do_page_fault(regs, write, address);
	exception_exit(prev_state);
}
