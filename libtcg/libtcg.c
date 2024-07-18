/* TODO(anjo): Can we cut down on these includes? */
#include <stdint.h>
#include <stdbool.h>

#include "qemu/osdep.h"
#include "qemu/help-texts.h"
#include "qemu/units.h"
#include "qemu/accel.h"
#include "qemu-version.h"
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <linux/binfmts.h>

#include "qapi/error.h"

#include "qemu.h"
#include "qemu/osdep.h"
#include "cpu.h"
#include "cpu-param.h"
#include "tcg/insn-start-words.h"
#include "disas/disas.h"
#include "exec/exec-all.h"
#include "exec/translator.h"
#include "tcg/tcg-op.h"
#include "tcg/tcg-internal.h"
#include "tcg/tcg.h"
#include "tcg/startup.h"
#include "qemu/accel.h"
#include "elf.h"
#include "target_elf.h"
#include "target_syscall.h" /* for struct target_pt_regs */
#include "cpu_loop-common.h" /* for target_cpu_copy_regs */

/*
 * Including our header last, otherwise we run into trouble with
 * TCG_TARGET_MAYBE_vec being doubly deinfed. We define it to 0 to
 * avoid exposing target dependent vector instructions in `libtcg.h`.
 */
#include "libtcg/libtcg.h"

typedef struct LibTcgContext {
    LibTcgDesc desc;
    CPUState *cpu;
} LibTcgContext;

/*
 * Here we hold some information about the bytecode we're going
 * to translate. This struct will be passed via CPUState->opaque
 * to the memory access functions below.
 */
typedef struct BytecodeRegion {
    const unsigned char *buffer;
    size_t size;
    uint64_t virtual_address;
} BytecodeRegion;

/*
 * Here we have the functions to replace QEMUs memory access functions in
 * accel/tcg/user-exec.c. We override them to read bytecode from the
 * BytecodeRegion struct passed by via CPUState->opaque instead.
 */
#define CPU_MEMORY_ACCESS_FUNC(return_type, read_type, name)            \
    return_type name(CPUArchState *env, abi_ptr ptr) {                  \
        CPUState *cpu = env_cpu(env);                                   \
        BytecodeRegion *region = cpu->opaque;                           \
        uint64_t offset = (uintptr_t)ptr - region->virtual_address;     \
        assert(offset + sizeof(read_type) <= region->size);             \
        return *(read_type *) ((uintptr_t) region->buffer + offset);    \
    }

CPU_MEMORY_ACCESS_FUNC(uint32_t, uint8_t,  cpu_ldub_code)
CPU_MEMORY_ACCESS_FUNC(uint32_t, uint16_t, cpu_lduw_code)
CPU_MEMORY_ACCESS_FUNC(uint32_t, uint32_t, cpu_ldl_code )
CPU_MEMORY_ACCESS_FUNC(uint64_t, uint64_t, cpu_ldq_code )

#undef CPU_MEMORY_ACCESS_FUNC

//static inline bool instruction_has_label_argument(TCGOpcode opc)
//{
//    return (opc == INDEX_op_set_label  ||
//            opc == INDEX_op_br         ||
//            opc == INDEX_op_brcond_i32 ||
//            opc == INDEX_op_brcond_i64 ||
//            opc == INDEX_op_brcond2_i32);
//}

const char *libtcg_get_instruction_name(LibTcgOpcode opcode)
{
    TCGOpDef def = tcg_op_defs[(TCGOpcode) opcode];
    return def.name;
}

LibTcgHelperInfo libtcg_get_helper_info(LibTcgInstruction *insn)
{
    /*
     * For a call instruction, the first constant argument holds
     * a pointer to a TCGHelperInfo struct allocated in a static
     * hash table g_helper_table.
     *
     * NOTE(anjo): This function needs to be kept up to date with
     *             tcg_call_info(op), since we effectively
     *             reimplement it here.
     *
     */
    assert(insn->opcode == LIBTCG_op_call);
    uintptr_t ptr_to_helper_info = insn->constant_args[1].constant;
    TCGHelperInfo *info = (void *) ptr_to_helper_info;
    return (LibTcgHelperInfo) {
        .func_name = info->name,
        .func_flags = info->flags,
    };
}

LibTcgContext *libtcg_context_create(LibTcgDesc *desc)
{
    assert(desc);

    /* Default initialize desc */
    if (!desc->mem_alloc) {
        desc->mem_alloc = malloc;
    }

    if (!desc->mem_free) {
        desc->mem_free = free;
    }

    /* Initialize context */
    LibTcgContext *context = desc->mem_alloc(sizeof(LibTcgContext));
    if (context == NULL)
        return NULL;
    context->desc = *desc;

    qemu_init_cpu_list();
    module_call_init(MODULE_INIT_QOM);
#if defined(TARGET_HEXAGON)
    uint32_t elf_flags = 0x73;
#else
    uint32_t elf_flags = 0;
#endif
    const char *cpu_model = cpu_get_model(elf_flags);
    const char *cpu_type = parse_cpu_option(cpu_model);
    /* Initializes accel/tcg */
    {
        AccelClass *ac = ACCEL_GET_CLASS(current_accel());

        accel_init_interfaces(ac);
        ac->init_machine(NULL);
    }

    context->cpu = cpu_create(cpu_type);
    cpu_reset(context->cpu);
    tcg_prologue_init();
    struct target_pt_regs regs = {0};

    struct image_info info = {0};
    TaskState *ts = malloc(sizeof(TaskState));
    ts->info = &info;
    context->cpu->opaque = ts;

    target_cpu_copy_regs(cpu_env(context->cpu), &regs);

    free(ts);

    return context;
}

void libtcg_context_destroy(LibTcgContext *context)
{
    context->desc.mem_free(context);
}

LibTcgInstructionList libtcg_translate(LibTcgContext *context,
                                       const unsigned char *buffer,
                                       uint64_t start_address,
                                       size_t size,
                                       uint64_t virtual_address,
                                       uint32_t translate_flags)
{
    BytecodeRegion region = {
        .buffer = buffer,
        .size = size,
        .virtual_address = start_address,
    };
    context->cpu->opaque = &region;

    vaddr pc;
    uint64_t cs_base;
    uint32_t flags;
    /*
     * We're using this call to setup `flags` and `cs_base` correctly.
     * We then override `pc`.
     */
    cpu_get_tb_cpu_state(cpu_env(context->cpu), &pc, &cs_base, &flags);
    pc = virtual_address;

    /* Set flags */
#ifdef TARGET_ARM
    if (translate_flags & LIBTCG_TRANSLATE_ARM_THUMB) {
        CPUARMTBFlags arm_flags = {};
        /* flags |= THUMB; */
        DP_TBFLAG_AM32(arm_flags, THUMB, 1);
        flags = arm_flags.flags;
    }
#endif

    /* Set cflags */
    uint32_t cflags = context->cpu->cflags_next_tb;
    if (cflags == -1) {
        cflags = curr_cflags(context->cpu);
    } else {
        context->cpu->cflags_next_tb = -1;
    }
    cflags |= CF_NO_GOTO_TB;
    cflags |= CF_NO_GOTO_PTR;
    cflags &= ~CF_USE_ICOUNT;
    cflags |= CF_NOIRQ;

    /* 
     * Initialize backend fields to avoid 
     * triggering asserts in tcg_func_start
     * */
    tcg_ctx->addr_type = TARGET_LONG_BITS == 32 ? TCG_TYPE_I32 : TCG_TYPE_I64;
    tcg_ctx->insn_start_words = TARGET_INSN_START_WORDS;
    /* Needed to initialize fields in `tcg_ctx` */
    tcg_func_start(tcg_ctx);

    /*
     * Set `max_insns` to the number of bytes in the buffer
     * so we don't have to worry about it being too small.
     */
    int max_insns = size;

    TranslationBlock *tb = tcg_tb_alloc(tcg_ctx);
    tb->pc = pc;
    tb->cs_base = cs_base;
    tb->max_pc = virtual_address + size;
    tb->flags = flags;
    tb->cflags = cflags;

    void *host_pc = NULL;
    gen_intermediate_code(context->cpu, tb, &max_insns, pc, host_pc);

    LibTcgInstructionList instruction_list = {
        .list = context->desc.mem_alloc(sizeof(LibTcgInstruction) * tcg_ctx->nb_ops),
        .instruction_count = 0,

        /* Note: tcg_ctx->nb_temps includes tcg_ctx->nb_globals */
        .temps = context->desc.mem_alloc(sizeof(LibTcgTemp) * tcg_ctx->nb_temps),
        .temp_count = 0,

        .labels = context->desc.mem_alloc(sizeof(LibTcgLabel) * (tcg_ctx->nb_labels)),
        .label_count = 0,

        .size_in_bytes = tb->size,
    };

    assert(instruction_list.list   != NULL &&
           instruction_list.temps  != NULL &&
           instruction_list.labels != NULL);

    /*
     * Loop over each TCG op and translate it to our format that we expose.
     */
    TCGOp *op = NULL;
    QTAILQ_FOREACH(op, &tcg_ctx->ops, link) {
        TCGOpcode opc = op->opc;
        TCGOpDef def = tcg_op_defs[opc];

        assert(def.nb_oargs <= LIBTCG_INSN_MAX_ARGS);
        assert(def.nb_iargs <= LIBTCG_INSN_MAX_ARGS);
        assert(def.nb_cargs <= LIBTCG_INSN_MAX_ARGS);
        LibTcgInstruction insn = {
            .opcode = (LibTcgOpcode) opc,
            .flags = def.flags,
            .nb_oargs = def.nb_oargs,
            .nb_iargs = def.nb_iargs,
            .nb_cargs = def.nb_cargs,
            .nb_args = def.nb_args,
        };

        if (opc == INDEX_op_call) {
            const TCGHelperInfo *info = tcg_call_info(op);

            insn.nb_oargs = TCGOP_CALLO(op);
            insn.nb_iargs = TCGOP_CALLI(op);
            insn.nb_args = insn.nb_oargs + insn.nb_iargs + insn.nb_cargs;

            void *func = tcg_call_func(op);
            assert(func == info->func);
        }

        /*
         * Here we handle `temp` arguments so output and input args.
         * Note: `insn.args[i]` and `op->args[i]` may have different
         * integer sizes.
         */
        for (uint32_t i = 0; i < insn.nb_oargs; ++i) {
            TCGTemp *ts = arg_temp(op->args[i]);
            int idx = temp_idx(ts);
            /*
             * TODO(anjo): Here we are casting between TCG's enums and ours.
             * This can of course cause problems. I am here assuming that the
             * TCG enums are stable.
             */
            assert(instruction_list.temp_count < LIBTCG_MAX_TEMPS);
            assert(idx < LIBTCG_MAX_TEMPS);
            LibTcgTemp *temp = &instruction_list.temps[idx];
            temp->kind = (LibTcgTempKind) ts->kind;
            temp->type = (LibTcgTempType) ts->type;
            temp->val = ts->val;
            temp->index = idx;
            temp->mem_offset = ts->mem_offset;
            tcg_get_arg_str(tcg_ctx, temp->name, LIBTCG_MAX_NAME_LEN, op->args[i]);

            insn.output_args[i] = (LibTcgArgument) {
                .kind = LIBTCG_ARG_TEMP,
                .temp = temp,
            };
        }

        for (uint32_t i = 0; i < insn.nb_iargs; ++i) {
            TCGTemp *ts = arg_temp(op->args[insn.nb_oargs + i]);
            int idx = temp_idx(ts);
            /*
             * TODO(anjo): Here we are casting between TCG's enums and ours.
             * This can of course cause problems. I am here assuming that the
             * TCG enums are stable.
             */
            assert(instruction_list.temp_count < LIBTCG_MAX_TEMPS);
            assert(idx < LIBTCG_MAX_TEMPS);
            LibTcgTemp *temp = &instruction_list.temps[idx];
            temp->kind = (LibTcgTempKind) ts->kind;
            temp->type = (LibTcgTempType) ts->type;
            temp->val = ts->val;
            temp->index = idx;
            temp->mem_offset = ts->mem_offset;
            tcg_get_arg_str(tcg_ctx, temp->name, LIBTCG_MAX_NAME_LEN, op->args[insn.nb_oargs + i]);

            insn.input_args[i] = (LibTcgArgument) {
                .kind = LIBTCG_ARG_TEMP,
                .temp = temp,
            };
        }

        /*
         * Here we handle constant args.
         */
        /*
         * Constant arguments are weird.
         *     - 1st arg: {constant, mmu id, cond, bswap flag, label},
         *     - 2nd arg: {constant, label}
         *     - nth arg: constant
         */
        //printf("%ld - %ld - %ld\n", insn.nb_oargs, insn.nb_iargs, insn.nb_cargs);
        //for (uint32_t i = 0; i < insn.nb_cargs; ++i) {
        //    if (false && i == 0 && instruction_has_label_argument(opc)) {
        //        TCGLabel *label =
        //            arg_label(op->args[insn.nb_oargs + insn.nb_iargs + i]);
        //        LibTcgLabel *our_label = &instruction_list.labels[label->id];
        //        our_label->id = label->id;
        //        insn.constant_args[i] = (LibTcgArgument) {
        //            .kind = LIBTCG_ARG_LABEL,
        //            .label = our_label
        //        };
        //    } else {
        //        /*
        //         * If we get to here the constant arg was actually a
        //         * constant
        //         */
        //        insn.constant_args[i] = (LibTcgArgument) {
        //            .kind = LIBTCG_ARG_CONSTANT,
        //            .constant = op->args[insn.nb_oargs + insn.nb_iargs + i],
        //        };
        //    }
        //}

        uint32_t start_index = 0;

        switch (opc) {
        case INDEX_op_brcond_i32:
        case INDEX_op_setcond_i32:
        case INDEX_op_movcond_i32:
        case INDEX_op_brcond2_i32:
        case INDEX_op_setcond2_i32:
        case INDEX_op_brcond_i64:
        case INDEX_op_setcond_i64:
        case INDEX_op_movcond_i64:
        case INDEX_op_cmp_vec:
        case INDEX_op_cmpsel_vec:
            insn.constant_args[start_index] = (LibTcgArgument) {
                .kind = LIBTCG_ARG_COND,
                .cond = op->args[insn.nb_oargs + insn.nb_iargs + start_index],
            };
            start_index++;
            break;
       case INDEX_op_qemu_ld_a32_i32:
       case INDEX_op_qemu_ld_a64_i32:
       case INDEX_op_qemu_st_a32_i32:
       case INDEX_op_qemu_st_a64_i32:
       case INDEX_op_qemu_st8_a32_i32:
       case INDEX_op_qemu_st8_a64_i32:
       case INDEX_op_qemu_ld_a32_i64:
       case INDEX_op_qemu_ld_a64_i64:
       case INDEX_op_qemu_st_a32_i64:
       case INDEX_op_qemu_st_a64_i64:
       case INDEX_op_qemu_ld_a32_i128:
       case INDEX_op_qemu_ld_a64_i128:
       case INDEX_op_qemu_st_a32_i128:
       case INDEX_op_qemu_st_a64_i128:
            {
                MemOpIdx oi = op->args[insn.nb_oargs + insn.nb_iargs + start_index];
                insn.constant_args[start_index] = (LibTcgArgument) {
                    .kind = LIBTCG_ARG_MEM_OP_INDEX,
                    .mem_op_index = {
                        .op = libtcg_get_memop(oi),
                        .mmu_index = libtcg_get_mmuidx(oi),
                    },
                };
                start_index++;
            }
            break;
        case INDEX_op_bswap16_i32:
        case INDEX_op_bswap16_i64:
        case INDEX_op_bswap32_i32:
        case INDEX_op_bswap32_i64:
        case INDEX_op_bswap64_i64:
            {
                insn.constant_args[start_index] = (LibTcgArgument) {
                    .kind = LIBTCG_ARG_BSWAP,
                    .bswap_flag = op->args[insn.nb_oargs + insn.nb_iargs + start_index],
                };
                start_index++;
            }
            break;
        default:
            break;
        }

        switch (opc) {
        case INDEX_op_set_label:
        case INDEX_op_br:
        case INDEX_op_brcond_i32:
        case INDEX_op_brcond_i64:
        case INDEX_op_brcond2_i32:
            {
                TCGLabel *label =
                    arg_label(op->args[insn.nb_oargs + insn.nb_iargs + start_index]);
                LibTcgLabel *our_label = &instruction_list.labels[label->id];
                our_label->id = label->id;
                insn.constant_args[start_index] = (LibTcgArgument) {
                    .kind = LIBTCG_ARG_LABEL,
                    .label = our_label
                };
            }
            start_index++;
            break;
        default:
            break;
        }

        for (uint32_t i = start_index; i < insn.nb_cargs; ++i) {
            insn.constant_args[i] = (LibTcgArgument) {
                .kind = LIBTCG_ARG_CONSTANT,
                .constant = op->args[insn.nb_oargs + insn.nb_iargs + i],
            };
        }

        instruction_list.list[instruction_list.instruction_count++] = insn;
    }

    return instruction_list;
}

void libtcg_instruction_list_destroy(LibTcgContext *context,
                                     LibTcgInstructionList instruction_list)
{
    context->desc.mem_free(instruction_list.list);
    context->desc.mem_free(instruction_list.temps);
    context->desc.mem_free(instruction_list.labels);
}

uint8_t *libtcg_env_ptr(LibTcgContext *context)
{
    return (uint8_t *) cpu_env(context->cpu);
}

LibTcgInterface libtcg_load(void) {
    return (LibTcgInterface) {
        /* Functions */
        .get_instruction_name       = libtcg_get_instruction_name,
        .get_helper_info            = libtcg_get_helper_info,
        .context_create             = libtcg_context_create,
        .context_destroy            = libtcg_context_destroy,
        .translate                  = libtcg_translate,
        .instruction_list_destroy   = libtcg_instruction_list_destroy,
        .env_ptr                    = libtcg_env_ptr,
        .dump_instruction_to_buffer = libtcg_dump_instruction_to_buffer,

        /* CPUState variables */
        .exception_index = offsetof(ArchCPU, parent_obj)
                           + offsetof(CPUState, exception_index),

        .env_offset = offsetof(ArchCPU, env),

        /* Target specific CPU state */
#if defined(TARGET_ALPHA)
        .pc = offsetof(CPUArchState, pc),
        .sp = 0, /* TODO(anjo) */
        .arch_cpu_name = "AlphaCPU",
#elif defined(TARGET_ARM)
    #if defined(TARGET_AARCH64)
        .pc = offsetof(CPUArchState, pc),
        .sp = offsetof(CPUArchState, xregs[31]), /* NOTE(anjo): UNCHECKED */
    #else
        .pc = offsetof(CPUArchState, regs[15]), /* NOTE(anjo): UNCHECKED */
        .sp = offsetof(CPUArchState, xregs[31]), /* NOTE(anjo): UNCHECKED */
        .is_thumb = offsetof(CPUArchState, thumb),
    #endif
        .arch_cpu_name = "ARMCPU",
#elif defined(TARGET_AVR)
        .pc = offsetof(CPUArchState, pc_w),
        .sp = offsetof(CPUArchState, sp),
        .arch_cpu_name = "AVRCPU",
#elif defined(TARGET_CRIS)
        .pc = 0, /* NOTE(anjo): UNCHECKED */
        .sp = 0, /* NOTE(anjo): UNCHECKED */
        .arch_cpu_name = "CRISCPU",
#elif defined(TARGET_HEXAGON)
        .pc = 0, /* NOTE(anjo): UNCHECKED */
        .sp = 0, /* NOTE(anjo): UNCHECKED */
        .arch_cpu_name = "HexagonCPU",
#elif defined(TARGET_HPPA)
        .pc = 0, /* NOTE(anjo): UNCHECKED */
        .sp = 0, /* NOTE(anjo): UNCHECKED */
        .arch_cpu_name = "HPPACPU",
#elif defined(TARGET_I386)
    #if defined(TARGET_X86_64)
        .pc = offsetof(CPUArchState, eip), /* NOTE(anjo): UNCHECKED */
        .sp = offsetof(CPUArchState, regs[R_ESP]), /* NOTE(anjo): UNCHECKED */
    #else
        .pc = offsetof(CPUArchState, eip), /* NOTE(anjo): UNCHECKED */
        .sp = offsetof(CPUArchState, regs[R_ESP]), /* NOTE(anjo): UNCHECKED */
    #endif
        .arch_cpu_name = "X86CPU",
#elif defined(TARGET_M68K)
        .pc = 0, /* NOTE(anjo): UNCHECKED */
        .sp = 0, /* NOTE(anjo): UNCHECKED */
        .arch_cpu_name = "M68kCPU",
#elif defined(TARGET_MICROBLAZE)
        .pc = 0, /* NOTE(anjo): UNCHECKED */
        .sp = 0, /* NOTE(anjo): UNCHECKED */
        .arch_cpu_name = "MicroBlazeCPU",
#elif defined(TARGET_MIPS)
    #if defined(TARGET_MIPS64)
        .pc = 0, /* NOTE(anjo): UNCHECKED */
        .sp = 0, /* NOTE(anjo): UNCHECKED */
    #else
        .pc = offsetof(CPUArchState, active_tc.PC), /* NOTE(anjo): UNCHECKED */
        .sp = offsetof(CPUArchState, active_tc.gpr[29]), /* NOTE(anjo): UNCHECKED */
    #endif
        .arch_cpu_name = "MIPSCPU",
#elif defined(TARGET_NIOS2)
        .pc = 0, /* NOTE(anjo): UNCHECKED */
        .sp = 0, /* NOTE(anjo): UNCHECKED */
        .arch_cpu_name = "Nios2CPU",
#elif defined(TARGET_OPENRISC)
        .pc = 0, /* NOTE(anjo): UNCHECKED */
        .sp = 0, /* NOTE(anjo): UNCHECKED */
        .arch_cpu_name = "OpenRISCCPU",
#elif defined(TARGET_PPC)
    #if defined(TARGET_PPC64)
        .pc = 0, /* NOTE(anjo): UNCHECKED */
        .sp = 0, /* NOTE(anjo): UNCHECKED */
    #else
        .pc = 0, /* NOTE(anjo): UNCHECKED */
        .sp = 0, /* NOTE(anjo): UNCHECKED */
    #endif
        .arch_cpu_name = "PowerPCCPU",
#elif defined(TARGET_RISCV32)
        .pc = 0, /* NOTE(anjo): UNCHECKED */
        .sp = 0, /* NOTE(anjo): UNCHECKED */
        .arch_cpu_name = "RISCVCPU",
#elif defined(TARGET_RISCV64)
        /*
         * NOTE(anjo): TARGET_RISCV64 is the only 64-bit arch not defined
         *             alongside the 32-bit variant (TARGET_RISCV32).
         */
        .pc = 0, /* NOTE(anjo): UNCHECKED */
        .sp = 0, /* NOTE(anjo): UNCHECKED */
        .arch_cpu_name = "RISCVCPU",
#elif defined(TARGET_RX)
        .pc = 0, /* NOTE(anjo): UNCHECKED */
        .sp = 0, /* NOTE(anjo): UNCHECKED */
        .arch_cpu_name = "RXCPU",
#elif defined(TARGET_S390X)
        .pc = offsetof(CPUArchState, psw.addr), /* NOTE(anjo): UNCHECKED */
        .sp = offsetof(CPUArchState, regs[15]), /* NOTE(anjo): UNCHECKED */
        .arch_cpu_name = "S390CPU",
#elif defined(TARGET_SH4)
        .pc = 0, /* NOTE(anjo): UNCHECKED */
        .sp = 0, /* NOTE(anjo): UNCHECKED */
        .arch_cpu_name = "SuperHCPU",
#elif defined(TARGET_SPARC)
    #if defined(TARGET_SPARC64)
        .pc = 0, /* NOTE(anjo): UNCHECKED */
        .sp = 0, /* NOTE(anjo): UNCHECKED */
    #else
        .pc = 0, /* NOTE(anjo): UNCHECKED */
        .sp = 0, /* NOTE(anjo): UNCHECKED */
    #endif
        .arch_cpu_name = "SPARCCPU",
#elif defined(TARGET_TRICORE)
        .pc = 0, /* NOTE(anjo): UNCHECKED */
        .sp = 0, /* NOTE(anjo): UNCHECKED */
        .arch_cpu_name = "TriCoreCPU",
#elif defined(TARGET_XTENSA)
        .pc = 0, /* NOTE(anjo): UNCHECKED */
        .sp = 0, /* NOTE(anjo): UNCHECKED */
        .arch_cpu_name = "XtensaCPU",
#endif
    };
}
