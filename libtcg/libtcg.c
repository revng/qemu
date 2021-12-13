/* TODO(anjo): Can we cut down on these includes? */
#include "qemu/osdep.h"
#include "cpu.h"
#include "disas/disas.h"
#include "exec/exec-all.h"
#include "tcg/tcg-op.h"
#include "tcg/tcg-internal.h"
#include "qemu/accel.h"
#include "target_elf.h"
#include "target_syscall.h" /* for struct target_pt_regs */
#include "cpu_loop-common.h" /* for target_cpu_copy_regs */

/*
 * Including our header last, otherwise we run into trouble with
 * TCG_TARGET_MAYBE_vec being doubly deinfed. We define it to 0 to
 * avoid exposing target dependent vector instructions in `libtcg.h`.
 */
#include "libtcg/libtcg.h"

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

/*
 * Temporaries in TCG don't usually have names, however it's nice to have,
 * especially when printing. Here we assign them names in accordance to what is
 * printed in `tcg_dump_ops`.
 */
static inline void tinycode_temp_create_name(TinyCodeTemp *temp)
{
    switch (temp->kind) {
    case LIBTCG_TEMP_FIXED:
    case LIBTCG_TEMP_GLOBAL: {
        /* Here's the exception. Globals to have names */
        /* fallthrough */
        return;
    }
    case LIBTCG_TEMP_LOCAL: {
        snprintf(temp->name, LIBTCG_MAX_NAME_LEN-1, "loc%d", temp->num);
        return;
    }
    case LIBTCG_TEMP_NORMAL: {
        snprintf(temp->name, LIBTCG_MAX_NAME_LEN-1, "tmp%d", temp->num);
        return;
    }
    case LIBTCG_TEMP_CONST: {
        switch (temp->type) {
        case LIBTCG_TYPE_I32: {
            snprintf(temp->name, LIBTCG_MAX_NAME_LEN-1, "$0x%x",
                     (int32_t) temp->val);
            return;
        }
        case LIBTCG_TYPE_I64: {
            snprintf(temp->name, LIBTCG_MAX_NAME_LEN-1, "$0x%lx", temp->val);
            return;
        }
        case LIBTCG_TYPE_V64:
        case LIBTCG_TYPE_V128:
        case LIBTCG_TYPE_V256: {
            snprintf(temp->name, LIBTCG_MAX_NAME_LEN-1, "v%d$0x%lx",
                     64 << (temp->type - LIBTCG_TYPE_V64), temp->val);
            return;
        }
        default:
            assert(0);
        }
        break;
    }
    }
}

static inline bool instruction_has_label_argument(TCGOpcode opc)
{
    return (opc == INDEX_op_set_label  ||
            opc == INDEX_op_br         ||
            opc == INDEX_op_brcond_i32 ||
            opc == INDEX_op_brcond_i64 ||
            opc == INDEX_op_brcond2_i32);
}

const char *get_instruction_name(TinyCodeOpcode opcode)
{
    TCGOpDef def = tcg_op_defs[(TCGOpcode) opcode];
    return def.name;
}

TinyCodeCallInfo get_call_info(TinyCodeInstruction *insn)
{
    /*
     * For a call instruction, the first constant argument holds
     * a pointer to a TCGHelperInfo struct allocated in a static
     * hash table g_helper_table.
     *
     * NOTE(anjo): This function needs to be kept up to date with
                   tcg_call_info(op), since we effectively
                   reimplement it here.
     *
     */
    assert(insn->opcode == LIBTCG_op_call);
    uintptr_t ptr_to_helper_info = insn->constant_args[1].constant;
    TCGHelperInfo *info = (void *) ptr_to_helper_info;
    return (TinyCodeCallInfo) {
        .func_name = info->name,
        .func_flags = info->flags,
    };
}

TinyCodeInstructionList translate(char *buffer, size_t size, uint64_t virtual_address)
{
    BytecodeRegion region = {
        .buffer = buffer,
        .size = size,
        .virtual_address = virtual_address,
    };

    qemu_init_cpu_list() ;
    module_call_init(MODULE_INIT_QOM);
    uint32_t elf_flags = 0;
    const char *cpu_model = cpu_get_model(elf_flags);
    const char *cpu_type = parse_cpu_option(cpu_model);
    /* Initializes accel/tcg */ { AccelClass *ac = ACCEL_GET_CLASS(current_accel());

        accel_init_interfaces(ac);
        ac->init_machine(NULL);
    }

    CPUState *cpu = cpu_create(cpu_type);
    cpu_reset(cpu);
    tcg_prologue_init(tcg_ctx);
    struct target_pt_regs regs1, *regs = &regs1;
    memset(regs, 0, sizeof(struct target_pt_regs));
    target_cpu_copy_regs(cpu->env_ptr, regs);
    cpu->opaque = &region;

    /* Needed to initialize fields in `tcg_ctx` */
    tcg_func_start(tcg_ctx);

    target_ulong cs_base, pc;
    uint32_t flags;
    /*
     * We're using this call to setup `flags` and `cs_base` correctly.
     * We then override `pc`.
     */
    cpu_get_tb_cpu_state(cpu->env_ptr, &pc, &cs_base, &flags);
    pc = virtual_address;

    uint32_t cflags = cpu->cflags_next_tb;
    if (cflags == -1) {
        cflags = curr_cflags(cpu);
    } else {
        cpu->cflags_next_tb = -1;
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
    gen_intermediate_code(cpu, &tb, max_insns);

    TinyCodeInstructionList instruction_list = {
        .list = malloc(sizeof(TinyCodeInstruction) * tcg_ctx->nb_ops),
        .instruction_count = tcg_ctx->nb_ops,
        .temps = malloc(sizeof(TinyCodeTemp) * tcg_ctx->nb_temps),
        .temp_count = tcg_ctx->nb_temps,
        .labels = malloc(sizeof(TinyCodeLabel) * tcg_ctx->nb_labels),
        .label_count = tcg_ctx->nb_labels,
    };

    /*
     * Loop over each TCG op and translate it to our format that we expose.
     */
    uint32_t index = 0;
    TCGOp *op = NULL;
    QTAILQ_FOREACH(op, &tcg_ctx->ops, link) {
        TCGOpcode opc = op->opc;
        TCGOpDef def = tcg_op_defs[opc];

        TinyCodeInstruction insn = {
            .opcode = (TinyCodeOpcode) opc,
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
             * This can ofcourse cause problems. I am here assuming that the
             * TCG enums are stable.
             */
            TinyCodeTemp *temp = &instruction_list.temps[idx];
            temp->kind = (TinyCodeTempKind) ts->kind;
            temp->type = (TinyCodeTempType) ts->type;
            temp->val = ts->val;
            temp->num = idx - tcg_ctx->nb_globals;
            if (ts->name) {
                strncpy(temp->name, ts->name, LIBTCG_MAX_NAME_LEN-1);
            } else {
                tinycode_temp_create_name(temp);
            }

            insn.output_args[i] = (TinyCodeArgument) {
                .kind = LIBTCG_ARG_TEMP,
                .temp = temp,
            };
        }

        for (uint32_t i = 0; i < insn.nb_iargs; ++i) {
            TCGTemp *ts = arg_temp(op->args[insn.nb_oargs + i]);
            int idx = temp_idx(ts);
            /*
             * TODO(anjo): Here we are casting between TCG's enums and ours.
             * This can ofcourse cause problems. I am here assuming that the
             * TCG enums are stable.
             */
            TinyCodeTemp *temp = &instruction_list.temps[idx];
            temp->kind = (TinyCodeTempKind) ts->kind;
            temp->type = (TinyCodeTempType) ts->type;
            temp->val = ts->val;
            temp->num = idx - tcg_ctx->nb_globals;
            if (ts->name) {
                strncpy(temp->name, ts->name, LIBTCG_MAX_NAME_LEN-1);
            } else {
                tinycode_temp_create_name(temp);
            }

            insn.input_args[i] = (TinyCodeArgument) {
                .kind = LIBTCG_ARG_TEMP,
                .temp = temp,
            };
        }

        /*
         * Here we handle constant args.
         */
        for (uint32_t i = 0; i < insn.nb_cargs; ++i) {
            if (i == 0 && instruction_has_label_argument(opc)) {
                TCGLabel *label = arg_label(op->args[insn.nb_oargs + insn.nb_iargs + i]);
                TinyCodeLabel *our_label = &instruction_list.labels[label->id];
                our_label->id = label->id;
                insn.constant_args[i] = (TinyCodeArgument) {
                    .kind = LIBTCG_ARG_LABEL,
                    .label = our_label
                };
            } else {
                /*
                 * If we get to here the constant arg was actually a
                 * constant
                 */
                insn.constant_args[i] = (TinyCodeArgument) {
                    .kind = LIBTCG_ARG_CONSTANT,
                    .constant = op->args[insn.nb_oargs + insn.nb_iargs + i],
                };
            }
        }

        instruction_list.list[index] = insn;
        index++;
    }

    return instruction_list;
}
