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
#include "disas/disas.h"
#include "exec/exec-all.h"
#include "tcg/tcg-op.h"
#include "tcg/tcg-internal.h"
#include "tcg/tcg.h"
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

typedef struct LibTinyCodeContext {
    LibTinyCodeDesc desc;
    CPUState *cpu;
} LibTinyCodeContext;

/*
 * Here we hold some information about the bytecode we're going
 * to translate. This struct will be passed via CPUState->opaque
 * to the memory access functions below.
 */
typedef struct BytecodeRegion {
    char *buffer;
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

static inline bool instruction_has_label_argument(TCGOpcode opc)
{
    return (opc == INDEX_op_set_label  ||
            opc == INDEX_op_br         ||
            opc == INDEX_op_brcond_i32 ||
            opc == INDEX_op_brcond_i64 ||
            opc == INDEX_op_brcond2_i32);
}

const char *libtcg_get_instruction_name(LibTinyCodeOpcode opcode)
{
    TCGOpDef def = tcg_op_defs[(TCGOpcode) opcode];
    return def.name;
}

LibTinyCodeCallInfo libtcg_get_call_info(LibTinyCodeInstruction *insn)
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
    return (LibTinyCodeCallInfo) {
        .func_name = info->name,
        .func_flags = info->flags,
    };
}

LibTinyCodeContext *libtcg_context_create(LibTinyCodeDesc *desc)
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
    LibTinyCodeContext *context = desc->mem_alloc(sizeof(LibTinyCodeContext));
    context->desc = *desc;

    qemu_init_cpu_list();
    module_call_init(MODULE_INIT_QOM);
    uint32_t elf_flags = 0;
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
    tcg_prologue_init(tcg_ctx);
    struct target_pt_regs regs = {0};

    struct image_info info = {0};
    TaskState *ts = malloc(sizeof(TaskState));
    ts->info = &info;
    context->cpu->opaque = ts;

    target_cpu_copy_regs(context->cpu->env_ptr, &regs);

    free(ts);

    return context;
}

void libtcg_context_destroy(LibTinyCodeContext *context)
{
    context->desc.mem_free(context);
}

LibTinyCodeInstructionList libtcg_translate(LibTinyCodeContext *context,
                                            char *buffer, size_t size,
                                            uint64_t virtual_address)
{
    BytecodeRegion region = {
        .buffer = buffer,
        .size = size,
        .virtual_address = virtual_address,
    };
    context->cpu->opaque = &region;

    /* Needed to initialize fields in `tcg_ctx` */
    tcg_func_start(tcg_ctx);

    target_ulong cs_base, pc;
    uint32_t flags;
    /*
     * We're using this call to setup `flags` and `cs_base` correctly.
     * We then override `pc`.
     */
    cpu_get_tb_cpu_state(context->cpu->env_ptr, &pc, &cs_base, &flags);
    pc = virtual_address;

    uint32_t cflags = context->cpu->cflags_next_tb;
    if (cflags == -1) {
        cflags = curr_cflags(context->cpu);
    } else {
        context->cpu->cflags_next_tb = -1;
    }

    /*
     * Set `max_insns` to the number of bytes in the buffer
     * so we don't have to worry about it being too small.
     */
    int max_insns = size;

    TranslationBlock tb = {
        .pc = pc,
        .cs_base = cs_base,
        .flags = flags,
        .cflags = cflags,
    };
    gen_intermediate_code(context->cpu, &tb, max_insns);

    LibTinyCodeInstructionList instruction_list = {
        .list = context->desc.mem_alloc(sizeof(LibTinyCodeInstruction) * LIBTCG_MAX_INSTRUCTIONS),
        .instruction_count = 0,

        .temps = context->desc.mem_alloc(sizeof(LibTinyCodeTemp) * LIBTCG_MAX_TEMPS),
        .temp_count = 0,

        .labels = context->desc.mem_alloc(sizeof(LibTinyCodeLabel) * LIBTCG_MAX_LABELS),
        .label_count = 0,
    };

    /*
     * Loop over each TCG op and translate it to our format that we expose.
     */
    TCGOp *op = NULL;
    QTAILQ_FOREACH(op, &tcg_ctx->ops, link) {
        TCGOpcode opc = op->opc;
        TCGOpDef def = tcg_op_defs[opc];

        LibTinyCodeInstruction insn = {
            .opcode = (LibTinyCodeOpcode) opc,
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
            LibTinyCodeTemp *temp = &instruction_list.temps[instruction_list.temp_count++];
            temp->kind = (LibTinyCodeTempKind) ts->kind;
            temp->type = (LibTinyCodeTempType) ts->type;
            temp->val = ts->val;
            temp->num = idx - tcg_ctx->nb_globals;
            tcg_get_arg_str(tcg_ctx, temp->name, LIBTCG_MAX_NAME_LEN, op->args[i]);

            insn.output_args[i] = (LibTinyCodeArgument) {
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
            LibTinyCodeTemp *temp = &instruction_list.temps[instruction_list.temp_count++];
            temp->kind = (LibTinyCodeTempKind) ts->kind;
            temp->type = (LibTinyCodeTempType) ts->type;
            temp->val = ts->val;
            temp->num = idx - tcg_ctx->nb_globals;
            tcg_get_arg_str(tcg_ctx, temp->name, LIBTCG_MAX_NAME_LEN, op->args[insn.nb_oargs + i]);

            insn.input_args[i] = (LibTinyCodeArgument) {
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
        //        LibTinyCodeLabel *our_label = &instruction_list.labels[label->id];
        //        our_label->id = label->id;
        //        insn.constant_args[i] = (LibTinyCodeArgument) {
        //            .kind = LIBTCG_ARG_LABEL,
        //            .label = our_label
        //        };
        //    } else {
        //        /*
        //         * If we get to here the constant arg was actually a
        //         * constant
        //         */
        //        insn.constant_args[i] = (LibTinyCodeArgument) {
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
            insn.constant_args[start_index] = (LibTinyCodeArgument) {
                .kind = LIBTCG_ARG_COND,
                .cond = op->args[insn.nb_oargs + insn.nb_iargs + start_index],
            };
            start_index++;
            break;
        case INDEX_op_qemu_ld_i32:
        case INDEX_op_qemu_st_i32:
        case INDEX_op_qemu_st8_i32:
        case INDEX_op_qemu_ld_i64:
        case INDEX_op_qemu_st_i64:
            {
                MemOpIdx oi = op->args[insn.nb_oargs + insn.nb_iargs + start_index];
                insn.constant_args[start_index] = (LibTinyCodeArgument) {
                    .kind = LIBTCG_ARG_MEM_OP_INDEX,
                    .mem_op_index = {
                        .op = get_memop(oi),
                        .mmu_index = get_mmuidx(oi),
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
                insn.constant_args[start_index] = (LibTinyCodeArgument) {
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
                LibTinyCodeLabel *our_label = &instruction_list.labels[label->id];
                our_label->id = label->id;
                insn.constant_args[start_index] = (LibTinyCodeArgument) {
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
            insn.constant_args[i] = (LibTinyCodeArgument) {
                .kind = LIBTCG_ARG_CONSTANT,
                .constant = op->args[insn.nb_oargs + insn.nb_iargs + i],
            };
        }

        instruction_list.list[instruction_list.instruction_count++] = insn;
    }

    return instruction_list;
}

void libtcg_instruction_list_destroy(LibTinyCodeContext *context,
                                     LibTinyCodeInstructionList instruction_list)
{
    context->desc.mem_free(instruction_list.list);
    context->desc.mem_free(instruction_list.temps);
    context->desc.mem_free(instruction_list.labels);
}
