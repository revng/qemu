#ifndef LIBTCG_H
#define LIBTCG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LIBTCG_INSN_MAX_ARGS 16
#define LIBTCG_MAX_NAME_LEN 32
#define LIBTCG_MAX_TEMPS 512
#define LIBTCG_MAX_LABELS 512
#define LIBTCG_MAX_INSTRUCTIONS 1024

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
typedef enum LibTcgOpcode {
#define DEF(name, oargs, iargs, cargs, flags) LIBTCG_op_ ## name,
#include "tcg/tcg-opc.h"
#undef DEF
    LIBTCG_NB_OPS,
} LibTcgOpcode;

/* Taken from exec/memop.h */
typedef enum LibTcgMemOp {
    LIBTCG_MO_8     = 0,
    LIBTCG_MO_16    = 1,
    LIBTCG_MO_32    = 2,
    LIBTCG_MO_64    = 3,
    LIBTCG_MO_128   = 4,
    LIBTCG_MO_256   = 5,
    LIBTCG_MO_512   = 6,
    LIBTCG_MO_1024  = 7,
    LIBTCG_MO_SIZE  = 0x07,   /* Mask for the above.  */

    LIBTCG_MO_SIGN  = 0x08,   /* Sign-extended, otherwise zero-extended.  */

    LIBTCG_MO_BSWAP = 0x10,   /* Host reverse endian.  */
//#if HOST_BIG_ENDIAN
//    LIBTCG_MO_LE    = LIBTCG_MO_BSWAP,
//    LIBTCG_MO_BE    = 0,
//#else
//    LIBTCG_MO_LE    = 0,
//    LIBTCG_MO_BE    = LIBTCG_MO_BSWAP,
//#endif

    /*
     * MO_UNALN accesses are never checked for alignment.
     * MO_ALIGN accesses will result in a call to the CPU's
     * do_unaligned_access hook if the guest address is not aligned.
     *
     * Some architectures (e.g. ARMv8) need the address which is aligned
     * to a size more than the size of the memory access.
     * Some architectures (e.g. SPARCv9) need an address which is aligned,
     * but less strictly than the natural alignment.
     *
     * MO_ALIGN supposes the alignment size is the size of a memory access.
     *
     * There are three options:
     * - unaligned access permitted (MO_UNALN).
     * - an alignment to the size of an access (MO_ALIGN);
     * - an alignment to a specified size, which may be more or less than
     *   the access size (MO_ALIGN_x where 'x' is a size in bytes);
     */
    LIBTCG_MO_ASHIFT = 5,
    LIBTCG_MO_AMASK = 0x7 << LIBTCG_MO_ASHIFT,
    LIBTCG_MO_UNALN    = 0,
    LIBTCG_MO_ALIGN_2  = 1 << LIBTCG_MO_ASHIFT,
    LIBTCG_MO_ALIGN_4  = 2 << LIBTCG_MO_ASHIFT,
    LIBTCG_MO_ALIGN_8  = 3 << LIBTCG_MO_ASHIFT,
    LIBTCG_MO_ALIGN_16 = 4 << LIBTCG_MO_ASHIFT,
    LIBTCG_MO_ALIGN_32 = 5 << LIBTCG_MO_ASHIFT,
    LIBTCG_MO_ALIGN_64 = 6 << LIBTCG_MO_ASHIFT,
    LIBTCG_MO_ALIGN    = LIBTCG_MO_AMASK,

    /*
     * MO_ATOM_* describes the atomicity requirements of the operation:
     * MO_ATOM_IFALIGN: the operation must be single-copy atomic if it
     *    is aligned; if unaligned there is no atomicity.
     * MO_ATOM_IFALIGN_PAIR: the entire operation may be considered to
     *    be a pair of half-sized operations which are packed together
     *    for convenience, with single-copy atomicity on each half if
     *    the half is aligned.
     *    This is the atomicity e.g. of Arm pre-FEAT_LSE2 LDP.
     * MO_ATOM_WITHIN16: the operation is single-copy atomic, even if it
     *    is unaligned, so long as it does not cross a 16-byte boundary;
     *    if it crosses a 16-byte boundary there is no atomicity.
     *    This is the atomicity e.g. of Arm FEAT_LSE2 LDR.
     * MO_ATOM_WITHIN16_PAIR: the entire operation is single-copy atomic,
     *    if it happens to be within a 16-byte boundary, otherwise it
     *    devolves to a pair of half-sized MO_ATOM_WITHIN16 operations.
     *    Depending on alignment, one or both will be single-copy atomic.
     *    This is the atomicity e.g. of Arm FEAT_LSE2 LDP.
     * MO_ATOM_SUBALIGN: the operation is single-copy atomic by parts
     *    by the alignment.  E.g. if the address is 0 mod 4, then each
     *    4-byte subobject is single-copy atomic.
     *    This is the atomicity e.g. of IBM Power.
     * MO_ATOM_NONE: the operation has no atomicity requirements.
     *
     * Note the default (i.e. 0) value is single-copy atomic to the
     * size of the operation, if aligned.  This retains the behaviour
     * from before this field was introduced.
     */
    LIBTCG_MO_ATOM_SHIFT         = 8,
    LIBTCG_MO_ATOM_IFALIGN       = 0 << LIBTCG_MO_ATOM_SHIFT,
    LIBTCG_MO_ATOM_IFALIGN_PAIR  = 1 << LIBTCG_MO_ATOM_SHIFT,
    LIBTCG_MO_ATOM_WITHIN16      = 2 << LIBTCG_MO_ATOM_SHIFT,
    LIBTCG_MO_ATOM_WITHIN16_PAIR = 3 << LIBTCG_MO_ATOM_SHIFT,
    LIBTCG_MO_ATOM_SUBALIGN      = 4 << LIBTCG_MO_ATOM_SHIFT,
    LIBTCG_MO_ATOM_NONE          = 5 << LIBTCG_MO_ATOM_SHIFT,
    LIBTCG_MO_ATOM_MASK          = 7 << LIBTCG_MO_ATOM_SHIFT,

    /* Combinations of the above, for ease of use.  */
    LIBTCG_MO_UB    = LIBTCG_MO_8,
    LIBTCG_MO_UW    = LIBTCG_MO_16,
    LIBTCG_MO_UL    = LIBTCG_MO_32,
    LIBTCG_MO_UQ    = LIBTCG_MO_64,
    LIBTCG_MO_UO    = LIBTCG_MO_128,
    LIBTCG_MO_SB    = LIBTCG_MO_SIGN | LIBTCG_MO_8,
    LIBTCG_MO_SW    = LIBTCG_MO_SIGN | LIBTCG_MO_16,
    LIBTCG_MO_SL    = LIBTCG_MO_SIGN | LIBTCG_MO_32,
    LIBTCG_MO_SQ    = LIBTCG_MO_SIGN | LIBTCG_MO_64,
    LIBTCG_MO_SO    = LIBTCG_MO_SIGN | LIBTCG_MO_128,

//    LIBTCG_MO_LEUW  = LIBTCG_MO_LE | LIBTCG_MO_UW,
//    LIBTCG_MO_LEUL  = LIBTCG_MO_LE | LIBTCG_MO_UL,
//    LIBTCG_MO_LEUQ  = LIBTCG_MO_LE | LIBTCG_MO_UQ,
//    LIBTCG_MO_LESW  = LIBTCG_MO_LE | LIBTCG_MO_SW,
//    LIBTCG_MO_LESL  = LIBTCG_MO_LE | LIBTCG_MO_SL,
//    LIBTCG_MO_LESQ  = LIBTCG_MO_LE | LIBTCG_MO_SQ,
//
//    LIBTCG_MO_BEUW  = LIBTCG_MO_BE | LIBTCG_MO_UW,
//    LIBTCG_MO_BEUL  = LIBTCG_MO_BE | LIBTCG_MO_UL,
//    LIBTCG_MO_BEUQ  = LIBTCG_MO_BE | LIBTCG_MO_UQ,
//    LIBTCG_MO_BESW  = LIBTCG_MO_BE | LIBTCG_MO_SW,
//    LIBTCG_MO_BESL  = LIBTCG_MO_BE | LIBTCG_MO_SL,
//    LIBTCG_MO_BESQ  = LIBTCG_MO_BE | LIBTCG_MO_SQ,

    LIBTCG_MO_SSIZE = LIBTCG_MO_SIZE | LIBTCG_MO_SIGN,
} LibTcgMemOp;

/* More MemOp stuff taken from `tcg/tcg.h` */

typedef uint32_t LibTcgMemOpIdx;

inline LibTcgMemOp libtcg_get_memop(LibTcgMemOpIdx oi)
{
    return (LibTcgMemOp) (oi >> 4);
}

inline unsigned libtcg_get_mmuidx(LibTcgMemOpIdx oi)
{
    return oi & 15;
}

/* Taken from tcg/tcg.h */
typedef enum LibTcgBSwap{
    LIBTCG_BSWAP_IZ = 1,
    LIBTCG_BSWAP_OZ = 2,
    LIBTCG_BSWAP_OS = 4,
} LibTcgBSwap;

/* Taken from tcg/tcg-cond.h */
typedef enum LibTcgCond {
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
} LibTcgCond;

/* From `TCGTempKind` in `tcg/tcg.c` */
typedef enum LibTcgTempKind {
    /*
     * Temp is dead at the end of the extended basic block (EBB),
     * the single-entry multiple-exit region that falls through
     * conditional branches.
     */
    LIBTCG_TEMP_EBB,
    /* Temp is live across the entire translation block, but dead at end. */
    LIBTCG_TEMP_TB,
    /* Temp is live across the entire translation block, and between them. */
    LIBTCG_TEMP_GLOBAL,
    /* Temp is in a fixed register. */
    LIBTCG_TEMP_FIXED,
    /* Temp is a fixed constant. */
    LIBTCG_TEMP_CONST,
} LibTcgTempKind;

/* From `TCGType` in `tcg/tcg.c` */
typedef enum LibTcgTempType {
    LIBTCG_TYPE_I32,
    LIBTCG_TYPE_I64,
    LIBTCG_TYPE_I128,

    /* TODO(anjo): Remove vector types? */
    LIBTCG_TYPE_V64,
    LIBTCG_TYPE_V128,
    LIBTCG_TYPE_V256,

    /* number of different types */
    LIBTCG_TYPE_COUNT,
} LibTcgTempType;

/* From tcg/tcg.h */
/* call flags */
/* Helper does not read globals (either directly or through an exception). It
   implies LIBTCG_TCG_CALL_NO_WRITE_GLOBALS. */
#define LIBTCG_CALL_NO_READ_GLOBALS    0x0001
/* Helper does not write globals */
#define LIBTCG_CALL_NO_WRITE_GLOBALS   0x0002
/* Helper can be safely suppressed if the return value is not used. */
#define LIBTCG_CALL_NO_SIDE_EFFECTS    0x0004
/* Helper is G_NORETURN.  */
#define LIBTCG_CALL_NO_RETURN          0x0008
/* Helper is part of Plugins.  */
#define LIBTCG_CALL_PLUGIN             0x0010

/*
 * Now we finally get into our adapted versions of the various
 * TCG structs needed to represent our TCG op data.
 */

typedef struct LibTcgTemp {
    LibTcgTempKind kind;
    LibTcgTempType type;
    int64_t val;
    uint32_t index;
    intptr_t mem_offset; /* Only used by globals */
    char name[LIBTCG_MAX_NAME_LEN];
} LibTcgTemp;

typedef struct LibTcgLabel {
    /*
     * Currently `id` is the only field of the label used in
     * dumping the tinycode instruction. There are more goodies
     * in `tcg/tcg.h` tho.
     */
    uint32_t id;
} LibTcgLabel;

typedef struct LibTcgMemOpIndex {
    LibTcgMemOp op;
    unsigned mmu_index;
} LibTcgMemOpIndex;

typedef enum LibTcgArgumentKind {
    LIBTCG_ARG_CONSTANT,
    LIBTCG_ARG_MEM_OP_INDEX,
    LIBTCG_ARG_COND,
    LIBTCG_ARG_BSWAP,
    LIBTCG_ARG_TEMP,
    LIBTCG_ARG_LABEL,
} LibTcgArgumentKind;

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
typedef struct LibTcgArgument {
    LibTcgArgumentKind kind;
    union {
        uint64_t constant;
        LibTcgMemOpIndex mem_op_index;
        LibTcgCond cond;
        uint32_t bswap_flag;
        LibTcgTemp *temp;
        LibTcgLabel *label;
    };
} LibTcgArgument;

typedef struct LibTcgHelperInfo {
    const char *func_name;
    /*
     * TODO(anjo): Does the func_flags replace def.flags?
     *             In that case move func_flags -> insn.flags
     */
    uint32_t func_flags;
} LibTcgHelperInfo;

typedef struct LibTcgArchInfo {
    uint16_t num_globals;
    const char *arch_cpu_name;
    intptr_t env_offset;
    intptr_t exception_index;
    intptr_t is_thumb;
    intptr_t pc;
    intptr_t sp;
    intptr_t bp;
} LibTcgArchInfo;

typedef struct LibTcgInstruction {
    LibTcgOpcode opcode;
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
    LibTcgArgument output_args[LIBTCG_INSN_MAX_ARGS];
    LibTcgArgument input_args[LIBTCG_INSN_MAX_ARGS];
    LibTcgArgument constant_args[LIBTCG_INSN_MAX_ARGS];
} LibTcgInstruction;

typedef struct LibTcgTranslationBlock {
    LibTcgInstruction *list;
    size_t instruction_count;

    /* Keeps track of all temporaries */
    LibTcgTemp *temps;
    size_t temp_count;

    /* Keeps track of all labels */
    LibTcgLabel *labels;
    size_t label_count;

    size_t size_in_bytes;
} LibTcgTranslationBlock;

typedef enum LibTcgTranslateFlags {
    LIBTCG_TRANSLATE_ARM_THUMB = 1,
} LibTcgTranslateFlags;

/*
 * Lastly we have the functions we expose.
 */

/*
 * Description struct used in the creation of
 * LibTcgContext. Allows specifying
 * functions used for allocation/freeing
 * memory.
 *
 * Zero-initialize to use default values
 * (malloc/free).
 */
typedef struct LibTcgDesc {
    void *(*mem_alloc)(size_t);
    void (*mem_free)(void *);
} LibTcgDesc;

struct LibTcgContext;
typedef struct LibTcgContext LibTcgContext;

/*
 * Following are a bunch of macros that help in defining a function prototype
 * along with a typedef of the function type.
 *
 * NOTE(anjo): Not really a fan of this, but it does reduce the amount of
 * function prototypes you need to keep in sync. :/
 */

/* Returns the name of the function's typedef */
#define LIBTCG_FUNC_TYPE(name) \
    name ## _func

/* Declares and typedefs a function */
#define LIBTCG_EXPORT(ret, name, params)                                 \
    ret name params;                          /* Function declaration */ \
    typedef ret LIBTCG_FUNC_TYPE(name) params /* Funciton typedef     */

LIBTCG_EXPORT(const char *,           libtcg_get_instruction_name,       (LibTcgOpcode opcode));
LIBTCG_EXPORT(LibTcgHelperInfo,       libtcg_get_helper_info,            (LibTcgInstruction *insn));
LIBTCG_EXPORT(LibTcgArchInfo,         libtcg_get_arch_info,              (void));
LIBTCG_EXPORT(LibTcgContext *,        libtcg_context_create,             (LibTcgDesc *desc));
LIBTCG_EXPORT(void,                   libtcg_context_destroy,            (LibTcgContext *context));
LIBTCG_EXPORT(LibTcgTranslationBlock, libtcg_translate_block,            (LibTcgContext *context, const unsigned char *buffer, size_t size, uint64_t virtual_address, uint32_t translate_flags));
LIBTCG_EXPORT(void,                   libtcg_translation_block_destroy,  (LibTcgContext *context, LibTcgTranslationBlock));
LIBTCG_EXPORT(uint8_t *,              libtcg_env_ptr,                    (LibTcgContext *context));
LIBTCG_EXPORT(void,                   libtcg_dump_instruction_to_buffer, (LibTcgInstruction *insn, char *buf, size_t size));
LIBTCG_EXPORT(void,                   libtcg_dump_instruction_name_to_buffer, (LibTcgInstruction *insn, char *buf, size_t size));
LIBTCG_EXPORT(void,                   libtcg_dump_constant_arg_to_buffer, (LibTcgArgument *arg, char *buf, size_t size));

/*
 * struct to help load functions we expose,
 * useful when `dlopen`ing.
 */
typedef struct LibTcgInterface {
    LIBTCG_FUNC_TYPE(libtcg_get_instruction_name)       *get_instruction_name;
    LIBTCG_FUNC_TYPE(libtcg_get_helper_info)            *get_helper_info;
    LIBTCG_FUNC_TYPE(libtcg_get_arch_info)              *get_arch_info;
    LIBTCG_FUNC_TYPE(libtcg_context_create)             *context_create;
    LIBTCG_FUNC_TYPE(libtcg_context_destroy)            *context_destroy;
    LIBTCG_FUNC_TYPE(libtcg_translate_block)            *translate_block;
    LIBTCG_FUNC_TYPE(libtcg_translation_block_destroy)  *translation_block_destroy;
    LIBTCG_FUNC_TYPE(libtcg_env_ptr)                    *env_ptr;
    LIBTCG_FUNC_TYPE(libtcg_dump_instruction_to_buffer) *dump_instruction_to_buffer;
} LibTcgInterface;

/*
 * Last function we export takes care of creating/populating a LibTcgInterface.
 * This is the only funciton needing to be manually loaded using `dlsym`.
 */
LIBTCG_EXPORT(LibTcgInterface, libtcg_load, (void));

#undef LIBTCG_EXPORT
/*
 * NOTE(anjo): LIBTCG_FUNC_TYPE remains defined, so it can be used
 * to get the typedef'd function types.
 */

#ifdef __cplusplus
}
#endif

#endif /* LIBTCG_H */
