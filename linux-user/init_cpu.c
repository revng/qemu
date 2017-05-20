#include <stdio.h>

#include "qemu.h"
#include "qemu-common.h"
#include "cpu.h"
#include "tcg.h"
#include "trace.h"
#include "disas/disas.h"

#include "ptc.h"
#include "elf.h"

#include "exec/exec-all.h"

/* Code copy/pasted from main.c */

/* Beware of the XXXs */
void initialize_cpu_state(CPUArchState *env) {
    struct target_pt_regs regs1, *regs = &regs1;
    /* Zero out regs */
    memset(regs, 0, sizeof(struct target_pt_regs));

#if defined(TARGET_I386)
    env->cr[0] = CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK;
    env->hflags |= HF_PE_MASK | HF_CPL_MASK;
    if (env->features[FEAT_1_EDX] & CPUID_SSE) {
        env->cr[4] |= CR4_OSFXSR_MASK;
        env->hflags |= HF_OSFXSR_MASK;
    }
#ifndef TARGET_ABI32
    /* enable 64 bit mode if possible */
    if (!(env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM)) {
        fprintf(stderr, "The selected x86 CPU does not support 64 bit mode\n");
        exit(1);
    }
    env->cr[4] |= CR4_PAE_MASK;
    env->efer |= MSR_EFER_LMA | MSR_EFER_LME;
    env->hflags |= HF_LMA_MASK;
#endif

    /* flags setup : we activate the IRQs by default as in user mode */
    env->eflags |= IF_MASK;

    /* linux register setup */
#ifndef TARGET_ABI32
    env->regs[R_EAX] = regs->rax;
    env->regs[R_EBX] = regs->rbx;
    env->regs[R_ECX] = regs->rcx;
    env->regs[R_EDX] = regs->rdx;
    env->regs[R_ESI] = regs->rsi;
    env->regs[R_EDI] = regs->rdi;
    env->regs[R_EBP] = regs->rbp;
    env->regs[R_ESP] = regs->rsp;
    env->eip = regs->rip;
#else
    env->regs[R_EAX] = regs->eax;
    env->regs[R_EBX] = regs->ebx;
    env->regs[R_ECX] = regs->ecx;
    env->regs[R_EDX] = regs->edx;
    env->regs[R_ESI] = regs->esi;
    env->regs[R_EDI] = regs->edi;
    env->regs[R_EBP] = regs->ebp;
    env->regs[R_ESP] = regs->esp;
    env->eip = regs->eip;
#endif

    /* XXX: disabled */
/*     /\* linux interrupt setup *\/ */
/* #ifndef TARGET_ABI32 */
/*     env->idt.limit = 511; */
/* #else */
/*     env->idt.limit = 255; */
/* #endif */
/*     env->idt.base = target_mmap(0, sizeof(uint64_t) * (env->idt.limit + 1), */
/*                                 PROT_READ|PROT_WRITE, */
/*                                 MAP_ANONYMOUS|MAP_PRIVATE, -1, 0); */
/*     idt_table = g2h(env->idt.base); */
/*     set_idt(0, 0); */
/*     set_idt(1, 0); */
/*     set_idt(2, 0); */
/*     set_idt(3, 3); */
/*     set_idt(4, 3); */
/*     set_idt(5, 0); */
/*     set_idt(6, 0); */
/*     set_idt(7, 0); */
/*     set_idt(8, 0); */
/*     set_idt(9, 0); */
/*     set_idt(10, 0); */
/*     set_idt(11, 0); */
/*     set_idt(12, 0); */
/*     set_idt(13, 0); */
/*     set_idt(14, 0); */
/*     set_idt(15, 0); */
/*     set_idt(16, 0); */
/*     set_idt(17, 0); */
/*     set_idt(18, 0); */
/*     set_idt(19, 0); */
/*     set_idt(0x80, 3); */

    /* linux segment setup */
    setup_segmentation(env);

#elif defined(TARGET_AARCH64)
    {
        int i;

        if (!(arm_feature(env, ARM_FEATURE_AARCH64))) {
            fprintf(stderr,
                    "The selected ARM CPU does not support 64 bit mode\n");
            exit(1);
        }

        for (i = 0; i < 31; i++) {
            env->xregs[i] = regs->regs[i];
        }
        env->pc = regs->pc;
        env->xregs[31] = regs->sp;
    }
#elif defined(TARGET_ARM)
    {
        int i;
        cpsr_write(env, regs->uregs[16], 0xffffffff);
        for(i = 0; i < 16; i++) {
            env->regs[i] = regs->uregs[i];
        }
        /* XXX: disabled */
        /* /\* Enable BE8.  *\/ */
        /* if (EF_ARM_EABI_VERSION(info->elf_flags) >= EF_ARM_EABI_VER4 */
        /*     && (info->elf_flags & EF_ARM_BE8)) { */
        /*     env->bswap_code = 1; */
        /* } */
    }
#elif defined(TARGET_UNICORE32)
    {
        int i;
        cpu_asr_write(env, regs->uregs[32], 0xffffffff);
        for (i = 0; i < 32; i++) {
            env->regs[i] = regs->uregs[i];
        }
    }
#elif defined(TARGET_SPARC)
    {
        int i;
	env->pc = regs->pc;
	env->npc = regs->npc;
        env->y = regs->y;
        for(i = 0; i < 8; i++)
            env->gregs[i] = regs->u_regs[i];
        for(i = 0; i < 8; i++)
            env->regwptr[i] = regs->u_regs[i + 8];
    }
#elif defined(TARGET_PPC)
    {
        int i;

#if defined(TARGET_PPC64)
#if defined(TARGET_ABI32)
        env->msr &= ~((target_ulong)1 << MSR_SF);
#else
        env->msr |= (target_ulong)1 << MSR_SF;
#endif
#endif
        env->nip = regs->nip;
        for(i = 0; i < 32; i++) {
            env->gpr[i] = regs->gpr[i];
        }
    }
#elif defined(TARGET_M68K)
    {
        env->pc = regs->pc;
        env->dregs[0] = regs->d0;
        env->dregs[1] = regs->d1;
        env->dregs[2] = regs->d2;
        env->dregs[3] = regs->d3;
        env->dregs[4] = regs->d4;
        env->dregs[5] = regs->d5;
        env->dregs[6] = regs->d6;
        env->dregs[7] = regs->d7;
        env->aregs[0] = regs->a0;
        env->aregs[1] = regs->a1;
        env->aregs[2] = regs->a2;
        env->aregs[3] = regs->a3;
        env->aregs[4] = regs->a4;
        env->aregs[5] = regs->a5;
        env->aregs[6] = regs->a6;
        env->aregs[7] = regs->usp;
        env->sr = regs->sr;
        ts->sim_syscalls = 1;
    }
#elif defined(TARGET_MICROBLAZE)
    {
        env->regs[0] = regs->r0;
        env->regs[1] = regs->r1;
        env->regs[2] = regs->r2;
        env->regs[3] = regs->r3;
        env->regs[4] = regs->r4;
        env->regs[5] = regs->r5;
        env->regs[6] = regs->r6;
        env->regs[7] = regs->r7;
        env->regs[8] = regs->r8;
        env->regs[9] = regs->r9;
        env->regs[10] = regs->r10;
        env->regs[11] = regs->r11;
        env->regs[12] = regs->r12;
        env->regs[13] = regs->r13;
        env->regs[14] = regs->r14;
        env->regs[15] = regs->r15;
        env->regs[16] = regs->r16;
        env->regs[17] = regs->r17;
        env->regs[18] = regs->r18;
        env->regs[19] = regs->r19;
        env->regs[20] = regs->r20;
        env->regs[21] = regs->r21;
        env->regs[22] = regs->r22;
        env->regs[23] = regs->r23;
        env->regs[24] = regs->r24;
        env->regs[25] = regs->r25;
        env->regs[26] = regs->r26;
        env->regs[27] = regs->r27;
        env->regs[28] = regs->r28;
        env->regs[29] = regs->r29;
        env->regs[30] = regs->r30;
        env->regs[31] = regs->r31;
        env->sregs[SR_PC] = regs->pc;
    }
#elif defined(TARGET_MIPS)
    {
        int i;

        for(i = 0; i < 32; i++) {
            env->active_tc.gpr[i] = regs->regs[i];
        }
        env->active_tc.PC = regs->cp0_epc & ~(target_ulong)1;
        if (regs->cp0_epc & 1) {
            env->hflags |= MIPS_HFLAG_M16;
        }
    }
#elif defined(TARGET_OPENRISC)
    {
        int i;

        for (i = 0; i < 32; i++) {
            env->gpr[i] = regs->gpr[i];
        }

        env->sr = regs->sr;
        env->pc = regs->pc;
    }
#elif defined(TARGET_SH4)
    {
        int i;

        for(i = 0; i < 16; i++) {
            env->gregs[i] = regs->regs[i];
        }
        env->pc = regs->pc;
    }
#elif defined(TARGET_ALPHA)
    {
        int i;

        for(i = 0; i < 28; i++) {
            env->ir[i] = ((abi_ulong *)regs)[i];
        }
        env->ir[IR_SP] = regs->usp;
        env->pc = regs->pc;
    }
#elif defined(TARGET_CRIS)
    {
	    env->regs[0] = regs->r0;
	    env->regs[1] = regs->r1;
	    env->regs[2] = regs->r2;
	    env->regs[3] = regs->r3;
	    env->regs[4] = regs->r4;
	    env->regs[5] = regs->r5;
	    env->regs[6] = regs->r6;
	    env->regs[7] = regs->r7;
	    env->regs[8] = regs->r8;
	    env->regs[9] = regs->r9;
	    env->regs[10] = regs->r10;
	    env->regs[11] = regs->r11;
	    env->regs[12] = regs->r12;
	    env->regs[13] = regs->r13;
	    env->regs[14] = info->start_stack;
	    env->regs[15] = regs->acr;
	    env->pc = regs->erp;
    }
#elif defined(TARGET_S390X)
    {
            int i;
            for (i = 0; i < 16; i++) {
                env->regs[i] = regs->gprs[i];
            }
            env->psw.mask = regs->psw.mask;
            env->psw.addr = regs->psw.addr;
    }
#else
#error unsupported target CPU
#endif
}
