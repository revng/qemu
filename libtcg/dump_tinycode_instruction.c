#include "libtcg/libtcg.h"
#include <stdarg.h>
#include <stdio.h> /* for vsnprintf */
#include <assert.h>

#define ARRAY_LEN(arr) \
    sizeof(arr)/sizeof(arr[0])

/* Taken from `tcg/tcg.c` */
static const char * const cond_name[] = {
    [LIBTCG_COND_NEVER] = "never",
    [LIBTCG_COND_ALWAYS] = "always",
    [LIBTCG_COND_EQ] = "eq",
    [LIBTCG_COND_NE] = "ne",
    [LIBTCG_COND_LT] = "lt",
    [LIBTCG_COND_GE] = "ge",
    [LIBTCG_COND_LE] = "le",
    [LIBTCG_COND_GT] = "gt",
    [LIBTCG_COND_LTU] = "ltu",
    [LIBTCG_COND_GEU] = "geu",
    [LIBTCG_COND_LEU] = "leu",
    [LIBTCG_COND_GTU] = "gtu"
};

/* Taken from `tcg/tcg.c` */
static const char * const ldst_name[] = {
    [LIBTCG_MO_UB]   = "ub",
    [LIBTCG_MO_SB]   = "sb",
    //[LIBTCG_MO_LEUW] = "leuw",
    //[LIBTCG_MO_LESW] = "lesw",
    //[LIBTCG_MO_LEUL] = "leul",
    //[LIBTCG_MO_LESL] = "lesl",
    //[LIBTCG_MO_LEUQ] = "leq",
    //[LIBTCG_MO_BEUW] = "beuw",
    //[LIBTCG_MO_BESW] = "besw",
    //[LIBTCG_MO_BEUL] = "beul",
    //[LIBTCG_MO_BESL] = "besl",
    //[LIBTCG_MO_BEUQ] = "beq",
    //[LIBTCG_MO_128 + LIBTCG_MO_BE] = "beo",
    //[LIBTCG_MO_128 + LIBTCG_MO_LE] = "leo",
};

/* Taken from `tcg/tcg.c` */
static
const char * const alignment_name[(LIBTCG_MO_AMASK >> LIBTCG_MO_ASHIFT) + 1] = {
#ifdef TARGET_ALIGNED_ONLY
    [LIBTCG_MO_UNALN >> LIBTCG_MO_ASHIFT]    = "un+",
    [LIBTCG_MO_ALIGN >> LIBTCG_MO_ASHIFT]    = "",
#else
    [LIBTCG_MO_UNALN >> LIBTCG_MO_ASHIFT]    = "",
    [LIBTCG_MO_ALIGN >> LIBTCG_MO_ASHIFT]    = "al+",
#endif
    [LIBTCG_MO_ALIGN_2 >> LIBTCG_MO_ASHIFT]  = "al2+",
    [LIBTCG_MO_ALIGN_4 >> LIBTCG_MO_ASHIFT]  = "al4+",
    [LIBTCG_MO_ALIGN_8 >> LIBTCG_MO_ASHIFT]  = "al8+",
    [LIBTCG_MO_ALIGN_16 >> LIBTCG_MO_ASHIFT] = "al16+",
    [LIBTCG_MO_ALIGN_32 >> LIBTCG_MO_ASHIFT] = "al32+",
    [LIBTCG_MO_ALIGN_64 >> LIBTCG_MO_ASHIFT] = "al64+",
};

/* Taken from `tcg/tcg.c` */
static const char bswap_flag_name[][6] = {
    [LIBTCG_BSWAP_IZ] = "iz",
    [LIBTCG_BSWAP_OZ] = "oz",
    [LIBTCG_BSWAP_OS] = "os",
    [LIBTCG_BSWAP_IZ | LIBTCG_BSWAP_OZ] = "iz,oz",
    [LIBTCG_BSWAP_IZ | LIBTCG_BSWAP_OS] = "iz,os",
};

typedef struct StringBuffer {
    char *data;
    size_t at;
    size_t size;
} StringBuffer;

static inline void fmt_append_to_stringbuffer(StringBuffer *buffer,
                                              const char *fmt, ...)
{
    if (buffer->at >= buffer->size) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    size_t size_left = buffer->size - buffer->at;
    size_t bytes_written = vsnprintf(buffer->data+buffer->at, size_left, fmt,
                                     args);
    va_end(args);

    if (bytes_written > size_left) {
        /* Truncation happened */
        buffer->at = buffer->size;
    } else {
        buffer->at += bytes_written;
    }
}

void libtcg_dump_constant_arg_to_buffer(LibTcgArgument *arg,
                                        char *buf,
                                        size_t size)
{
    StringBuffer buffer = {
        .data = buf,
        .at   = 0,
        .size = size,
    };

    (void) bswap_flag_name;
    (void) alignment_name;
    (void) ldst_name;
    (void) cond_name;

    switch(arg->kind) {
        case LIBTCG_ARG_CONSTANT:
            fmt_append_to_stringbuffer(&buffer, "$0x%lx", arg->constant);
            break;
        case LIBTCG_ARG_MEM_OP_INDEX:
            {
                LibTcgMemOp op = arg->mem_op_index.op;
                unsigned ix = arg->mem_op_index.mmu_index;
                if (op & ~(LIBTCG_MO_AMASK | LIBTCG_MO_BSWAP | LIBTCG_MO_SSIZE)) {
                    fmt_append_to_stringbuffer(&buffer, "$0x%x,%u", op, ix);
                } else {
                    const char *s_al, *s_op;
                    s_al = alignment_name[(op & LIBTCG_MO_AMASK) >> LIBTCG_MO_ASHIFT];
                    s_op = ldst_name[op & (LIBTCG_MO_BSWAP | LIBTCG_MO_SSIZE)];
                    fmt_append_to_stringbuffer(&buffer, "%s%s,%u", s_al, s_op, ix);
                }
            }
            break;
        case LIBTCG_ARG_COND:
            {
                uint64_t constant = arg->cond;
                if (constant < ARRAY_LEN(cond_name)
                    && cond_name[constant]) {
                    fmt_append_to_stringbuffer(&buffer, "%s", cond_name[constant]);
                } else {
                    fmt_append_to_stringbuffer(&buffer, "$0x%lx", constant);
                }
            }
            break;
        case LIBTCG_ARG_BSWAP:
            {
                uint64_t flags = arg->bswap_flag;
                const char *name = NULL;

                if (flags < ARRAY_LEN(bswap_flag_name)) {
                    name = bswap_flag_name[flags];
                }
                if (name) {
                    fmt_append_to_stringbuffer(&buffer, "%s", name);
                } else {
                    fmt_append_to_stringbuffer(&buffer, "$0x%lx", flags);
                }
            }
            break;
        case LIBTCG_ARG_TEMP:
            assert(0);
            break;
        case LIBTCG_ARG_LABEL:
            fmt_append_to_stringbuffer(&buffer, "$L%d", arg->label->id);
            break;
        default:
            assert(0);
            break;
    };
}

void libtcg_dump_instruction_name_to_buffer(LibTcgInstruction *insn, char *buf,
                                            size_t size)
{
    LibTcgOpcode c = insn->opcode;

    StringBuffer buffer = {
        .data = buf,
        .at   = 0,
        .size = size,
    };

    const char *insn_name = libtcg_get_instruction_name(insn->opcode);
    if (c == LIBTCG_op_insn_start) {
        fmt_append_to_stringbuffer(&buffer, " ----");

        for (uint32_t i = 0; i < insn->nb_cargs; ++i) {
            fmt_append_to_stringbuffer(&buffer, " %016x",
                                       insn->constant_args[i].constant);
        }
    } else {
        fmt_append_to_stringbuffer(&buffer, "%s", insn_name);
    }

    fmt_append_to_stringbuffer(&buffer, "\0");
}

/*
 * TODO(anjo): Adapted from `tcg_dump_ops` in `tcg/tcg.c`.
 *      This print function doesnt handle:
 *              - plugins
 *              - lifetime
 *              - output preferences
 *      This functions is quite shit. It has inherited a distinc C-89 vibe
 *      from `tcg_dump_ops`. Refactor.
 */
void libtcg_dump_instruction_to_buffer(LibTcgInstruction *insn, char *buf,
                                       size_t size)
{
    LibTcgOpcode c = insn->opcode;

    StringBuffer buffer = {
        .data = buf,
        .at   = 0,
        .size = size,
    };

    const char *insn_name = libtcg_get_instruction_name(insn->opcode);
    if (c == LIBTCG_op_insn_start) {
        fmt_append_to_stringbuffer(&buffer, "\n ----");

        for (uint32_t i = 0; i < insn->nb_cargs; ++i) {
            fmt_append_to_stringbuffer(&buffer, " %016x",
                                       insn->constant_args[i].constant);
        }
    } else if (c == LIBTCG_op_call) {
        LibTcgHelperInfo info = libtcg_get_helper_info(insn);
        fmt_append_to_stringbuffer(&buffer, " %s %s", insn_name,
                                   info.func_name);
        fmt_append_to_stringbuffer(&buffer, ",$0x%x,$%d", info.func_flags,
                                   insn->nb_oargs);
        for (uint32_t i = 0; i < insn->nb_oargs; i++) {
            fmt_append_to_stringbuffer(&buffer, ",%s",
                                       insn->output_args[i].temp->name);
        }
        for (uint32_t i = 0; i < insn->nb_iargs; i++) {
            fmt_append_to_stringbuffer(&buffer, ",%s",
                                       insn->input_args[i].temp->name);
        }
    } else {
        fmt_append_to_stringbuffer(&buffer, " %s ", insn_name);
        /* TODO(anjo): We do not print vector arguments, this is how qemu prints them
         *
         *   if (insn->flags & TCG_OPF_VECTOR) {
         *       // col += qemu_log("v%d,e%d,", 64 << TCGOP_VECL(op),
         *   }
         */

        for (uint32_t i = 0; i < insn->nb_oargs; ++i) {
            if (i > 0) {
                fmt_append_to_stringbuffer(&buffer, ",");
            }
            fmt_append_to_stringbuffer(&buffer, "%s",
                                       insn->output_args[i].temp->name);
        }
        for (uint32_t i = 0; i < insn->nb_iargs; ++i) {
            if (i > 0 || insn->nb_oargs > 0) {
                fmt_append_to_stringbuffer(&buffer, ",");
            }
            fmt_append_to_stringbuffer(&buffer, "%s",
                                       insn->input_args[i].temp->name);
        }

        (void) bswap_flag_name;
        (void) alignment_name;
        (void) ldst_name;
        (void) cond_name;

        /*
         * The first constant argument might need some special treatment
         * depending on the instruction.
         */

        for (uint32_t i = 0; i < insn->nb_cargs; ++i) {
            if (i > 0 || insn->nb_oargs > 0 || insn->nb_iargs > 0) {
                fmt_append_to_stringbuffer(&buffer, ",");
            }

            LibTcgArgument arg = insn->constant_args[i];
            switch(arg.kind) {
            case LIBTCG_ARG_CONSTANT:
                fmt_append_to_stringbuffer(&buffer, "$0x%lx", arg.constant);
                break;
            case LIBTCG_ARG_MEM_OP_INDEX:
                {
                    //LibTcgMemOp op = tinycode_get_memop(oi);
                    //unsigned ix = tinycode_get_mmuidx(oi);
                    LibTcgMemOp op = arg.mem_op_index.op;
                    unsigned ix = arg.mem_op_index.mmu_index;
                    if (op & ~(LIBTCG_MO_AMASK | LIBTCG_MO_BSWAP | LIBTCG_MO_SSIZE)) {
                        fmt_append_to_stringbuffer(&buffer, ",$0x%x,%u", op, ix);
                    } else {
                        const char *s_al, *s_op;
                        s_al = alignment_name[(op & LIBTCG_MO_AMASK) >> LIBTCG_MO_ASHIFT];
                        s_op = ldst_name[op & (LIBTCG_MO_BSWAP | LIBTCG_MO_SSIZE)];
                        fmt_append_to_stringbuffer(&buffer, ",%s%s,%u", s_al, s_op, ix);
                    }
                }
                break;
            case LIBTCG_ARG_COND:
                {
                    uint64_t constant = arg.cond;
                    if (constant < ARRAY_LEN(cond_name)
                        && cond_name[constant]) {
                        fmt_append_to_stringbuffer(&buffer, ",%s", cond_name[constant]);
                    } else {
                        fmt_append_to_stringbuffer(&buffer, ",$0x%lx", constant);
                    }
                }
                break;
            case LIBTCG_ARG_BSWAP:
                {
                    uint64_t flags = arg.bswap_flag;
                    const char *name = NULL;

                    if (flags < ARRAY_LEN(bswap_flag_name)) {
                        name = bswap_flag_name[flags];
                    }
                    if (name) {
                        fmt_append_to_stringbuffer(&buffer, ",%s", name);
                    } else {
                        fmt_append_to_stringbuffer(&buffer, ",$0x%lx", flags);
                    }
                }
                break;
            case LIBTCG_ARG_TEMP:
                assert(0);
                break;
            case LIBTCG_ARG_LABEL:
                fmt_append_to_stringbuffer(&buffer, "$L%d", arg.label->id);
                break;
            default:
                assert(0);
                break;
            };
        }
    }

    fmt_append_to_stringbuffer(&buffer, "\0");
}
