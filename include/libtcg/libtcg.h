#ifndef LIBTCG_H
#define LIBTCG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LIBTCG_INSN_MAX_ARGS 16
#define LIBTCG_MAX_NAME_LEN 32
#define LIBTCG_MAX_TEMPS 128
#define LIBTCG_MAX_LABELS 128
#define LIBTCG_MAX_INSTRUCTIONS 128

/*
 * We start out with a bunch of constants and enums taken from
 * various `tcg/...` files.
 */

/*
 * Taken from `tcg/tcg.h`
 * Needed by `tcg/tcg-opc.h`
 */
#ifndef TCG_TARGET_REG_BITS
# if UINTPTR_MAX == UINT32_MAX
#  define TCG_TARGET_REG_BITS 32
# elif UINTPTR_MAX == UINT64_MAX
#  define TCG_TARGET_REG_BITS 64
# else
#  error Unknown pointer size for tcg target
# endif
#endif

/*
 * TODO(anjo): I explicitly exclude vector instructions here
 * as they are very target dependent. Is this what we wanna do?
 * Needed by `tcg/tcg-opc.h`
 */
#ifndef TCG_TARGET_MAYBE_vec
#define TCG_TARGET_MAYBE_vec 0
#endif

/* Taken from `tcg/tcg.h` */
typedef enum LibTinyCodeOpcode {
#define DEF(name, oargs, iargs, cargs, flags) LIBTCG_op_ ## name,
#include "tcg/tcg-opc.h"
#undef DEF
    LIBTCG_NB_OPS,
} LibTinyCodeOpcode;

/* Taken from exec/memop.h */
typedef enum LibTinyCodeMemOp {
    LIBTCG_MO_8     = 0,
    LIBTCG_MO_16    = 1,
    LIBTCG_MO_32    = 2,
    LIBTCG_MO_64    = 3,
    LIBTCG_MO_SIZE  = 3,   /* Mask for the above.  */

    LIBTCG_MO_SIGN  = 4,   /* Sign-extended, otherwise zero-extended.  */

    LIBTCG_MO_BSWAP = 8,   /* Host reverse endian.  */
#ifdef HOST_BIG_ENDIAN
    LIBTCG_MO_LE    = LIBTCG_MO_BSWAP,
    LIBTCG_MO_BE    = 0,
#else
    LIBTCG_MO_LE    = 0,
    LIBTCG_MO_BE    = LIBTCG_MO_BSWAP,
#endif
#ifdef TARGET_BIG_ENDIAN
    LIBTCG_MO_TE    = LIBTCG_MO_BE,
#else
    LIBTCG_MO_TE    = LIBTCG_MO_LE,
#endif

    /*
     * LIBTCG_MO_UNALN accesses are never checked for alignment.
     * LIBTCG_MO_ALIGN accesses will result in a call to the CPU's
     * do_unaligned_access hook if the guest address is not aligned.
     * The default depends on whether the target CPU defines
     * TARGET_ALIGNED_ONLY.
     *
     * Some architectures (e.g. ARMv8) need the address which is aligned
     * to a size more than the size of the memory access.
     * Some architectures (e.g. SPARCv9) need an address which is aligned,
     * but less strictly than the natural alignment.
     *
     * LIBTCG_MO_ALIGN supposes the alignment size is the size of a memory access.
     *
     * There are three options:
     * - unaligned access permitted (LIBTCG_MO_UNALN).
     * - an alignment to the size of an access (LIBTCG_MO_ALIGN);
     * - an alignment to a specified size, which may be more or less than
     *   the access size (LIBTCG_MO_ALIGN_x where 'x' is a size in bytes);
     */
    LIBTCG_MO_ASHIFT = 4,
    LIBTCG_MO_AMASK = 7 << LIBTCG_MO_ASHIFT,
#ifdef TARGET_ALIGNED_ONLY
    LIBTCG_MO_ALIGN = 0,
    LIBTCG_MO_UNALN = LIBTCG_MO_AMASK,
#else
    LIBTCG_MO_ALIGN = LIBTCG_MO_AMASK,
    LIBTCG_MO_UNALN = 0,
#endif
    LIBTCG_MO_ALIGN_2  = 1 << LIBTCG_MO_ASHIFT,
    LIBTCG_MO_ALIGN_4  = 2 << LIBTCG_MO_ASHIFT,
    LIBTCG_MO_ALIGN_8  = 3 << LIBTCG_MO_ASHIFT,
    LIBTCG_MO_ALIGN_16 = 4 << LIBTCG_MO_ASHIFT,
    LIBTCG_MO_ALIGN_32 = 5 << LIBTCG_MO_ASHIFT,
    LIBTCG_MO_ALIGN_64 = 6 << LIBTCG_MO_ASHIFT,

    /* Combinations of the above, for ease of use.  */
    LIBTCG_MO_UB    = LIBTCG_MO_8,
    LIBTCG_MO_UW    = LIBTCG_MO_16,
    LIBTCG_MO_UL    = LIBTCG_MO_32,
    LIBTCG_MO_SB    = LIBTCG_MO_SIGN | LIBTCG_MO_8,
    LIBTCG_MO_SW    = LIBTCG_MO_SIGN | LIBTCG_MO_16,
    LIBTCG_MO_SL    = LIBTCG_MO_SIGN | LIBTCG_MO_32,
    LIBTCG_MO_Q     = LIBTCG_MO_64,

    LIBTCG_MO_LEUW  = LIBTCG_MO_LE | LIBTCG_MO_UW,
    LIBTCG_MO_LEUL  = LIBTCG_MO_LE | LIBTCG_MO_UL,
    LIBTCG_MO_LESW  = LIBTCG_MO_LE | LIBTCG_MO_SW,
    LIBTCG_MO_LESL  = LIBTCG_MO_LE | LIBTCG_MO_SL,
    LIBTCG_MO_LEQ   = LIBTCG_MO_LE | LIBTCG_MO_Q,

    LIBTCG_MO_BEUW  = LIBTCG_MO_BE | LIBTCG_MO_UW,
    LIBTCG_MO_BEUL  = LIBTCG_MO_BE | LIBTCG_MO_UL,
    LIBTCG_MO_BESW  = LIBTCG_MO_BE | LIBTCG_MO_SW,
    LIBTCG_MO_BESL  = LIBTCG_MO_BE | LIBTCG_MO_SL,
    LIBTCG_MO_BEQ   = LIBTCG_MO_BE | LIBTCG_MO_Q,

    LIBTCG_MO_TEUW  = LIBTCG_MO_TE | LIBTCG_MO_UW,
    LIBTCG_MO_TEUL  = LIBTCG_MO_TE | LIBTCG_MO_UL,
    LIBTCG_MO_TESW  = LIBTCG_MO_TE | LIBTCG_MO_SW,
    LIBTCG_MO_TESL  = LIBTCG_MO_TE | LIBTCG_MO_SL,
    LIBTCG_MO_TEQ   = LIBTCG_MO_TE | LIBTCG_MO_Q,

    LIBTCG_MO_SSIZE = LIBTCG_MO_SIZE | LIBTCG_MO_SIGN,
} LibTinyCodeMemOp;

/* More MemOp stuff taken from `tcg/tcg.h` */

typedef uint32_t LibTinyCodeMemOpIdx;

inline LibTinyCodeMemOp tinycode_get_memop(LibTinyCodeMemOpIdx oi)
{
    return (LibTinyCodeMemOp) (oi >> 4);
}

inline unsigned tinycode_get_mmuidx(LibTinyCodeMemOpIdx oi)
{
    return oi & 15;
}

/* Taken from tcg/tcg.h */
typedef enum LibTinyCodeBSwap{
    LIBTCG_BSWAP_IZ = 1,
    LIBTCG_BSWAP_OZ = 2,
    LIBTCG_BSWAP_OS = 4,
} LibTinyCodeBSwap;

/* Taken from tcg/tcg-cond.h */
typedef enum LibTinyCodeCond {
    /* non-signed */
    LIBTCG_COND_NEVER  = 0 | 0 | 0 | 0,
    LIBTCG_COND_ALWAYS = 0 | 0 | 0 | 1,
    LIBTCG_COND_EQ     = 8 | 0 | 0 | 0,
    LIBTCG_COND_NE     = 8 | 0 | 0 | 1,
    /* signed */
    LIBTCG_COND_LT     = 0 | 0 | 2 | 0,
    LIBTCG_COND_GE     = 0 | 0 | 2 | 1,
    LIBTCG_COND_LE     = 8 | 0 | 2 | 0,
    LIBTCG_COND_GT     = 8 | 0 | 2 | 1,
    /* unsigned */
    LIBTCG_COND_LTU    = 0 | 4 | 0 | 0,
    LIBTCG_COND_GEU    = 0 | 4 | 0 | 1,
    LIBTCG_COND_LEU    = 8 | 4 | 0 | 0,
    LIBTCG_COND_GTU    = 8 | 4 | 0 | 1,
} LibTinyCodeCond;

/* From `TCGTempKind` in `tcg/tcg.c` */
typedef enum LibTinyCodeTempKind {
    /* Temp is dead at the end of all basic blocks. */
    LIBTCG_TEMP_NORMAL,
    /* Temp is saved across basic blocks but dead at the end of TBs. */
    LIBTCG_TEMP_LOCAL,
    /* Temp is saved across both basic blocks and translation blocks. */
    LIBTCG_TEMP_GLOBAL,
      /* Temp is in a fixed register. */
    LIBTCG_TEMP_FIXED,
    /* Temp is a fixed constant. */
    LIBTCG_TEMP_CONST,
} LibTinyCodeTempKind;

/* From `TCGType` in `tcg/tcg.c` */
typedef enum LibTinyCodeTempType {
    LIBTCG_TYPE_I32,
    LIBTCG_TYPE_I64,

    /* TODO(anjo): Remove vector types? */
    LIBTCG_TYPE_V64,
    LIBTCG_TYPE_V128,
    LIBTCG_TYPE_V256,

    /* number of different types */
    LIBTCG_TYPE_COUNT,
} LibTinyCodeTempType;

/*
 * Now we finally get into our adapted versions of the various
 * TCG structs needed to represent our TCG op data.
 */

typedef struct LibTinyCodeTemp {
    LibTinyCodeTempKind kind;
    LibTinyCodeTempType type;
    int64_t val;
    uint32_t num;
    char name[LIBTCG_MAX_NAME_LEN];
} LibTinyCodeTemp;

typedef struct LibTinyCodeLabel {
    /*
     * Currently `id` is the only field of the label used in
     * dumping the tinycode instruction. There are more goodies
     * in `tcg/tcg.h` tho.
     */
    uint32_t id;
} LibTinyCodeLabel;

typedef struct LibTinyCodeMemOpIndex {
    LibTinyCodeMemOp op;
    unsigned mmu_index;
} LibTinyCodeMemOpIndex;

typedef enum LibTinyCodeArgumentKind {
    LIBTCG_ARG_CONSTANT,
    LIBTCG_ARG_MEM_OP_INDEX,
    LIBTCG_ARG_COND,
    LIBTCG_ARG_BSWAP,
    LIBTCG_ARG_TEMP,
    LIBTCG_ARG_LABEL,
} LibTinyCodeArgumentKind;

/*
 * Note that LIBTCG_ARG_CONSTANT, as in QEMU, can
 * be a bit of whatever depending on context:
 *    - If it's an arg to a ld/st op then it usually contains MemOp flags;
 *    - If it's an arg to a bswap op is usually holds bswap flags;
 *
 * TODO(anjo): separate out arguments that are flags aswell, such as
 *             MemOp, Bswap. This will aid a lot in simpliyfing the dump
 *             function for instructions.
 */
typedef struct LibTinyCodeArgument {
    LibTinyCodeArgumentKind kind;
    union {
        uint64_t constant;
        LibTinyCodeMemOpIndex mem_op_index;
        LibTinyCodeCond cond;
        uint32_t bswap_flag;
        LibTinyCodeTemp *temp;
        LibTinyCodeLabel *label;
    };
} LibTinyCodeArgument;

typedef struct LibTinyCodeCallInfo {
    const char *func_name;
    /*
     * TODO(anjo): Does the func_flags replace def.flags?
     *             In that case move func_flags -> insn.flags
     */
    uint32_t func_flags;
} LibTinyCodeCallInfo;

typedef struct LibTinyCodeInstruction {
    LibTinyCodeOpcode opcode;
    uint32_t flags;
    /*
     * Arguments are handled in the same way as in QEMU,
     * so output args first, followed by input, followed
     * by constants. Output and input arguments are temps.
     */
    uint8_t nb_oargs;
    uint8_t nb_iargs;
    uint8_t nb_cargs;
    uint8_t nb_args;
    LibTinyCodeArgument output_args[LIBTCG_INSN_MAX_ARGS];
    LibTinyCodeArgument input_args[LIBTCG_INSN_MAX_ARGS];
    LibTinyCodeArgument constant_args[LIBTCG_INSN_MAX_ARGS];
} LibTinyCodeInstruction;

typedef struct LibTinyCodeInstructionList {
    LibTinyCodeInstruction *list;
    size_t instruction_count;

    /* Keeps track of all temporaries */
    LibTinyCodeTemp *temps;
    size_t temp_count;

    /* Keeps track of all labels */
    LibTinyCodeLabel *labels;
    size_t label_count;

    size_t size_in_bytes;
} LibTinyCodeInstructionList;

/*
 * Lastly we have the functions we expose.
 */

void libtcg_dump_instruction_to_buffer(LibTinyCodeInstruction *insn, char *buf,
                                       size_t size);

const char *libtcg_get_instruction_name(LibTinyCodeOpcode opcode);
LibTinyCodeCallInfo libtcg_get_call_info(LibTinyCodeInstruction *insn);

/*
 * Description struct used in the creation of
 * LibTinyCodeContext. Allows specifying
 * functions used for allocation/freeing
 * memory.
 *
 * Zero-initialize to use default values
 * (malloc/free).
 */
typedef struct LibTinyCodeDesc {
    void *(*mem_alloc)(size_t);
    void (*mem_free)(void *);
} LibTinyCodeDesc;

struct LibTinyCodeContext;
typedef struct LibTinyCodeContext LibTinyCodeContext;

LibTinyCodeContext *libtcg_context_create(LibTinyCodeDesc *desc);
void libtcg_context_destroy(LibTinyCodeContext *context);

LibTinyCodeInstructionList libtcg_translate(LibTinyCodeContext *context,
                                            char *buffer, size_t size,
                                            uint64_t virtual_address);

void libtcg_instruction_list_destroy(LibTinyCodeContext *context,
                                     LibTinyCodeInstructionList instruction_list);

#ifdef __cplusplus
}
#endif

#endif /* LIBTCG_H */
