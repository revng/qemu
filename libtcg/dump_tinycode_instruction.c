#include "libtcg/libtcg.h"
#include <stdarg.h>
#include <stdio.h> /* for vsnprintf */
#include <assert.h>

#define ARRAY_LEN(arr) \
    sizeof(arr)/sizeof(arr[0])

/* Taken from `tcg/tcg.c` */
static const char * const cond_name[] =
{
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
static const char * const ldst_name[] =
{
    [LIBTCG_MO_UB]   = "ub",
    [LIBTCG_MO_SB]   = "sb",
    [LIBTCG_MO_LEUW] = "leuw",
    [LIBTCG_MO_LESW] = "lesw",
    [LIBTCG_MO_LEUL] = "leul",
    [LIBTCG_MO_LESL] = "lesl",
    [LIBTCG_MO_LEQ]  = "leq",
    [LIBTCG_MO_BEUW] = "beuw",
    [LIBTCG_MO_BESW] = "besw",
    [LIBTCG_MO_BEUL] = "beul",
    [LIBTCG_MO_BESL] = "besl",
    [LIBTCG_MO_BEQ]  = "beq",
};

/* Taken from `tcg/tcg.c` */
static const char * const alignment_name[(LIBTCG_MO_AMASK >> LIBTCG_MO_ASHIFT) + 1] = {
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

static inline void fmt_append_to_stringbuffer(StringBuffer *buffer, const char *fmt, ...) {
    if (buffer->at >= buffer->size) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    size_t size_left = buffer->size - buffer->at;
    size_t bytes_written = vsnprintf(buffer->data+buffer->at, size_left, fmt, args);
    va_end(args);

    if (bytes_written > size_left) {
        /* Truncation happened */
        buffer->at = buffer->size;
    } else {
        buffer->at += bytes_written;
    }
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
void dump_instruction_to_buffer(TinyCodeInstruction *insn, char *buf, size_t size) {
    TinyCodeOpcode c = insn->opcode;

    StringBuffer buffer = {
        .data = buf,
        .at   = 0,
        .size = size,
    };

    if (c == LIBTCG_op_insn_start) {
        fmt_append_to_stringbuffer(&buffer, "\n ----");

        for (uint32_t i = 0; i < insn->nb_cargs; ++i) {
            fmt_append_to_stringbuffer(&buffer, " %016x", insn->args[i].constant);
        }
    } else if (c == LIBTCG_op_call) {
        fmt_append_to_stringbuffer(&buffer, " %s %s", insn->name, insn->func_name);
        fmt_append_to_stringbuffer(&buffer, ",$0x%x,$%d", insn->func_flags, insn->nb_oargs);
        for (uint32_t i = 0; i < insn->nb_oargs + insn->nb_iargs; i++) {
            fmt_append_to_stringbuffer(&buffer, ",%s", insn->args[i].temp->name);
        }
        //        for (i = 0; i < nb_iargs; i++) {
        //            TCGArg arg = op->args[nb_oargs + i];
        //            const char *t = "<dummy>";
        //            if (arg != TCG_CALL_DUMMY_ARG) {
        //                t = tcg_get_arg_str(s, buf, sizeof(buf), arg);
        //            }
        //            col += qemu_log(",%s", t);
        //        }
    } else {
        fmt_append_to_stringbuffer(&buffer, " %s ", insn->name);
        /* TODO(anjo): What does this do? */
        /*
        if (insn->flags & TCG_OPF_VECTOR) {
            // col += qemu_log("v%d,e%d,", 64 << TCGOP_VECL(op),
        }
        */

        uint32_t i = 0;
        uint32_t k = 0;
        for (i = 0; i < insn->nb_oargs; ++i) {
            if (k != 0) {
                fmt_append_to_stringbuffer(&buffer, ",");
            }
            fmt_append_to_stringbuffer(&buffer, "%s", insn->args[k++].temp->name);
        }
        for (i = 0; i < insn->nb_iargs; ++i) {
            if (k != 0) {
                fmt_append_to_stringbuffer(&buffer, ",");
            }
            fmt_append_to_stringbuffer(&buffer, "%s", insn->args[k++].temp->name);
        }

        switch (c) {
        case LIBTCG_op_brcond_i32:
        case LIBTCG_op_setcond_i32:
        case LIBTCG_op_movcond_i32:
        case LIBTCG_op_brcond2_i32:
        case LIBTCG_op_setcond2_i32:
        case LIBTCG_op_brcond_i64:
        case LIBTCG_op_setcond_i64:
        case LIBTCG_op_movcond_i64:
        case LIBTCG_op_cmp_vec:
        case LIBTCG_op_cmpsel_vec: {
            if (insn->args[k].constant < ARRAY_LEN(cond_name)
                && cond_name[insn->args[k].constant]) {
                fmt_append_to_stringbuffer(&buffer, ",%s", cond_name[insn->args[k++].constant]);
            } else {
                fmt_append_to_stringbuffer(&buffer, ",$0x%lx", insn->args[k++].constant);
            }
            i = 1;
            break;
        }
        case LIBTCG_op_qemu_ld_i32:
        case LIBTCG_op_qemu_st_i32:
        case LIBTCG_op_qemu_st8_i32:
        case LIBTCG_op_qemu_ld_i64:
        case LIBTCG_op_qemu_st_i64: {
            TinyCodeMemOpIdx oi = insn->args[k++].constant;
            TinyCodeMemOp op = tinycode_get_memop(oi);
            unsigned ix = tinycode_get_mmuidx(oi);

            if (op & ~(LIBTCG_MO_AMASK | LIBTCG_MO_BSWAP | LIBTCG_MO_SSIZE)) {
                fmt_append_to_stringbuffer(&buffer, ",$0x%x,%u", op, ix);
            } else {
                const char *s_al, *s_op;
                s_al = alignment_name[(op & LIBTCG_MO_AMASK) >> LIBTCG_MO_ASHIFT];
                s_op = ldst_name[op & (LIBTCG_MO_BSWAP | LIBTCG_MO_SSIZE)];
                fmt_append_to_stringbuffer(&buffer, ",%s%s,%u", s_al, s_op, ix);
            }
            i = 1;
            break;
        }
        case LIBTCG_op_bswap16_i32:
        case LIBTCG_op_bswap16_i64:
        case LIBTCG_op_bswap32_i32:
        case LIBTCG_op_bswap32_i64:
        case LIBTCG_op_bswap64_i64: {
            uint64_t flags = insn->args[k].constant;
            const char *name = NULL;

            if (flags < ARRAY_LEN(bswap_flag_name)) {
                name = bswap_flag_name[flags];
            }
            if (name) {
                fmt_append_to_stringbuffer(&buffer, ",%s", name);
            } else {
                fmt_append_to_stringbuffer(&buffer, ",$0x%lx", flags);
            }
            i = k = 1;
            break;
        }
        default:
            i = 0;
            break;
        }

        switch (c) {
        case LIBTCG_op_set_label:
        case LIBTCG_op_br:
        case LIBTCG_op_brcond_i32:
        case LIBTCG_op_brcond_i64:
        case LIBTCG_op_brcond2_i32: {
            fmt_append_to_stringbuffer(&buffer, "%s$L%d", k ? "," : "",
                                     insn->args[k].label->id);
            i++, k++;
            break;
        }
        default:
            break;
        }

        for (; i < insn->nb_cargs; i++, k++) {
            fmt_append_to_stringbuffer(&buffer, "%s$0x%lx",
                                            k ? "," : "", insn->args[k].constant);
        }
    }

    fmt_append_to_stringbuffer(&buffer, "\0");
}
