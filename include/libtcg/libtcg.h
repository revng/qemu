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
 * Disable vector instructions.
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
    LIBTCG_MO_SIZE  = 0x07,
    LIBTCG_MO_SIGN  = 0x08,
    LIBTCG_MO_BSWAP = 0x10,
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
    LIBTCG_MO_ATOM_SHIFT         = 8,
    LIBTCG_MO_ATOM_IFALIGN       = 0 << LIBTCG_MO_ATOM_SHIFT,
    LIBTCG_MO_ATOM_IFALIGN_PAIR  = 1 << LIBTCG_MO_ATOM_SHIFT,
    LIBTCG_MO_ATOM_WITHIN16      = 2 << LIBTCG_MO_ATOM_SHIFT,
    LIBTCG_MO_ATOM_WITHIN16_PAIR = 3 << LIBTCG_MO_ATOM_SHIFT,
    LIBTCG_MO_ATOM_SUBALIGN      = 4 << LIBTCG_MO_ATOM_SHIFT,
    LIBTCG_MO_ATOM_NONE          = 5 << LIBTCG_MO_ATOM_SHIFT,
    LIBTCG_MO_ATOM_MASK          = 7 << LIBTCG_MO_ATOM_SHIFT,
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
    LIBTCG_MO_SSIZE = LIBTCG_MO_SIZE | LIBTCG_MO_SIGN,
} LibTcgMemOp;

/* More MemOp stuff taken from `tcg/tcg.h` */

typedef uint32_t LibTcgMemOpIdx;

static inline LibTcgMemOp libtcg_get_memop(LibTcgMemOpIdx oi)
{
    return (LibTcgMemOp) (oi >> 4);
}

static inline unsigned libtcg_get_mmuidx(LibTcgMemOpIdx oi)
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
    LIBTCG_COND_NEVER  = 0 | 0 | 0 | 0,
    LIBTCG_COND_ALWAYS = 0 | 0 | 0 | 1,
    LIBTCG_COND_EQ     = 8 | 0 | 0 | 0,
    LIBTCG_COND_NE     = 8 | 0 | 0 | 1,
    LIBTCG_COND_LT     = 0 | 0 | 2 | 0,
    LIBTCG_COND_GE     = 0 | 0 | 2 | 1,
    LIBTCG_COND_LE     = 8 | 0 | 2 | 0,
    LIBTCG_COND_GT     = 8 | 0 | 2 | 1,
    LIBTCG_COND_LTU    = 0 | 4 | 0 | 0,
    LIBTCG_COND_GEU    = 0 | 4 | 0 | 1,
    LIBTCG_COND_LEU    = 8 | 4 | 0 | 0,
    LIBTCG_COND_GTU    = 8 | 4 | 0 | 1,
} LibTcgCond;

/* From `TCGTempKind` in `tcg/tcg.c` */
typedef enum LibTcgTempKind {
    LIBTCG_TEMP_EBB,
    LIBTCG_TEMP_TB,
    LIBTCG_TEMP_GLOBAL,
    LIBTCG_TEMP_FIXED,
    LIBTCG_TEMP_CONST,
} LibTcgTempKind;

/* From `TCGType` in `tcg/tcg.c` */
typedef enum LibTcgTempType {
    LIBTCG_TYPE_I32,
    LIBTCG_TYPE_I64,
    LIBTCG_TYPE_I128,
    LIBTCG_TYPE_V64,
    LIBTCG_TYPE_V128,
    LIBTCG_TYPE_V256,
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
     * Currently `id` is the only field of the label used in dumping the
     * tinycode instruction. There are more goodies in `tcg/tcg.h` tho.
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
 * Note that LIBTCG_ARG_CONSTANT, as in QEMU, can be a bit of whatever depending
 * on context:
 *    - If it's an arg to a ld/st op then it usually contains MemOp flags;
 *    - If it's an arg to a bswap op is usually holds bswap flags;
 *
 * TODO: separate out arguments that are flags aswell, such as MemOp,
 *       Bswap. This will aid a lot in simpliyfing the dump function for
 *       instructions.
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
     * TODO: Does the func_flags replace def.flags?  In that case move
     *       func_flags -> insn.flags
     */
    uint32_t func_flags;
} LibTcgHelperInfo;

typedef struct LibTcgGlobal {
    intptr_t offset;
    const char *name;
} LibTcgGlobal;

typedef struct LibTcgArchInfo {
    uint16_t num_globals;
    const char *arch_cpu_name;
    // TODO: can we drop all of these in favor of globals?
    intptr_t env_offset;
    intptr_t exception_index;
    intptr_t is_thumb;
    intptr_t pc;
    intptr_t sp;
    intptr_t bp;
    LibTcgGlobal *globals;
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

struct LibTcgContext;
typedef struct LibTcgContext LibTcgContext;

/*
 * Following are a bunch of macros that help in defining a function prototype
 * along with a typedef of the function type.
 */

/* Returns the name of the function's typedef */
#define LIBTCG_FUNC_TYPE(name) \
    name ## _func

/* Declares and typedefs a function */
#define LIBTCG_EXPORT(ret, name, params)                                 \
    ret name params;                          /* Function declaration */ \
    typedef ret LIBTCG_FUNC_TYPE(name) params /* Funciton typedef     */

LIBTCG_EXPORT(const char *, libtcg_get_instruction_name, (LibTcgOpcode opcode));
LIBTCG_EXPORT(LibTcgHelperInfo, libtcg_get_helper_info, (LibTcgInstruction *insn));
LIBTCG_EXPORT(LibTcgArchInfo, libtcg_get_arch_info, (void));
LIBTCG_EXPORT(LibTcgContext *, libtcg_context_create, (void));
LIBTCG_EXPORT(void, libtcg_context_destroy, (LibTcgContext *context));
LIBTCG_EXPORT(LibTcgTranslationBlock, libtcg_translate_block, (LibTcgContext *context, const unsigned char *buffer, size_t size, uint64_t virtual_address, uint32_t translate_flags));
LIBTCG_EXPORT(void, libtcg_translation_block_destroy, (LibTcgContext *context, LibTcgTranslationBlock));
LIBTCG_EXPORT(uint8_t *, libtcg_env_ptr, (LibTcgContext *context));
LIBTCG_EXPORT(void, libtcg_dump_instruction_to_buffer, (LibTcgInstruction *insn, char *buf, size_t size));
LIBTCG_EXPORT(void, libtcg_dump_instruction_name_to_buffer, (LibTcgInstruction *insn, char *buf, size_t size));
LIBTCG_EXPORT(void, libtcg_dump_constant_arg_to_buffer, (LibTcgArgument *arg, char *buf, size_t size));

/*
 * struct to help load functions we expose, useful when `dlopen`ing.
 */
typedef struct LibTcgInterface {
    LIBTCG_FUNC_TYPE(libtcg_get_instruction_name) *get_instruction_name;
    LIBTCG_FUNC_TYPE(libtcg_get_helper_info) *get_helper_info;
    LIBTCG_FUNC_TYPE(libtcg_get_arch_info) *get_arch_info;
    LIBTCG_FUNC_TYPE(libtcg_context_create) *context_create;
    LIBTCG_FUNC_TYPE(libtcg_context_destroy) *context_destroy;
    LIBTCG_FUNC_TYPE(libtcg_translate_block) *translate_block;
    LIBTCG_FUNC_TYPE(libtcg_translation_block_destroy) *translation_block_destroy;
    LIBTCG_FUNC_TYPE(libtcg_env_ptr) *env_ptr;
    LIBTCG_FUNC_TYPE(libtcg_dump_instruction_to_buffer) *dump_instruction_to_buffer;
    LIBTCG_FUNC_TYPE(libtcg_dump_instruction_name_to_buffer) *dump_instruction_name_to_buffer;
    LIBTCG_FUNC_TYPE(libtcg_dump_constant_arg_to_buffer) *dump_constant_arg_to_buffer;
} LibTcgInterface;

/*
 * Last function we export takes care of creating/populating a LibTcgInterface.
 * This is the only funciton needing to be manually loaded using `dlsym`.
 */
LIBTCG_EXPORT(LibTcgInterface, libtcg_load, (void));

#undef LIBTCG_EXPORT

/*
 * NOTE: LIBTCG_FUNC_TYPE remains defined, so it can be used to get the
 *       typedef'd function types.
 */

#ifdef __cplusplus
}
#endif

#endif /* LIBTCG_H */
