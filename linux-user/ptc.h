#ifndef _PTC_H
#define _PTC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#ifdef USE_DYNAMIC_PTC
# include <dlfcn.h>
#endif

/* Exported data structures */

/* This corresponds to TCGArg, whose size is target-dependent. We always use a 64-bit value. */
typedef uint64_t PTCInstructionArg;

typedef enum {
#define DEF(name, oargs, iargs, cargs, flags) PTC_INSTRUCTION_op_ ## name,
#include "tcg-opc.h"
#undef DEF
    PTC_INSTRUCTION_NB_OPS,
} PTCOpcode;

typedef struct {
  PTCOpcode opc   : 8;

  /* The number of out and in parameter for a call.  */
  unsigned callo  : 2;
  unsigned calli  : 6;

  PTCInstructionArg *args;
} PTCInstruction;

typedef enum {
  PTC_TEMP_VAL_DEAD,
  PTC_TEMP_VAL_REG,
  PTC_TEMP_VAL_MEM,
  PTC_TEMP_VAL_CONST,
} PTCTempType;

typedef enum {
  PTC_TYPE_I32,
  PTC_TYPE_I64,
  PTC_TYPE_COUNT, /* number of different types */
} PTCType;

typedef struct {
  /* For PTC_TEMP_VAL_REG */
  uint8_t reg;
  /* For PTC_TEMP_VAL_MEM */
  uint8_t mem_reg;
  intptr_t mem_offset;
  /* For PTC_TEMP_VAL_CONST */
  uint64_t val;

  /* Common */
  const char *name;
  PTCTempType val_type:8;
  PTCType base_type:8;
  PTCType type:8;
  unsigned int fixed_reg:1;
  unsigned int mem_coherent:1;
  unsigned int mem_allocated:1;
  unsigned int temp_local:1; /* If true, the temp is saved across
                                basic blocks. Otherwise, it is not
                                preserved across basic blocks. */
  unsigned int temp_allocated:1; /* never used for code gen */
} PTCTemp;

typedef struct {
  PTCInstruction *instructions;
  unsigned instruction_count;

  /* Additional data, do not access this directly */
  PTCInstructionArg *arguments;
  PTCTemp *temps;
  unsigned global_temps;
  unsigned total_temps;
} PTCInstructionList;

typedef struct {
  const char *name;
  uint8_t nb_oargs, nb_iargs, nb_cargs, nb_args;
  /* TODO: add missing fields (see TCGOpDef) */
} PTCOpcodeDef;

static inline int ptc_temp_is_global(PTCInstructionList *instructions, unsigned int temp_id) {
  assert(temp_id < instructions->total_temps);
  return temp_id < instructions->global_temps;
}

static inline PTCTemp *ptc_temp_get(PTCInstructionList *instructions, unsigned int temp_id) {
  assert(temp_id < instructions->total_temps);
  return &instructions->temps[temp_id];
}

static inline int ptc_temp_get_by_mem_offset(PTCInstructionList *instructions, intptr_t mem_offset) {
  unsigned i = 0;
  for (i = 0; i < instructions->total_temps; i++)
    if (instructions->temps[i].mem_offset == mem_offset)
      return i;

  return -1;
}

/* Taken from TCGCond */
typedef enum {
    /* non-signed */
    PTC_COND_NEVER  = 0 | 0 | 0 | 0,
    PTC_COND_ALWAYS = 0 | 0 | 0 | 1,
    PTC_COND_EQ     = 8 | 0 | 0 | 0,
    PTC_COND_NE     = 8 | 0 | 0 | 1,
    /* signed */
    PTC_COND_LT     = 0 | 0 | 2 | 0,
    PTC_COND_GE     = 0 | 0 | 2 | 1,
    PTC_COND_LE     = 8 | 0 | 2 | 0,
    PTC_COND_GT     = 8 | 0 | 2 | 1,
    /* unsigned */
    PTC_COND_LTU    = 0 | 4 | 0 | 0,
    PTC_COND_GEU    = 0 | 4 | 0 | 1,
    PTC_COND_LEU    = 8 | 4 | 0 | 0,
    PTC_COND_GTU    = 8 | 4 | 0 | 1,
} PTCCondition;

#ifndef HOST_WORDS_BIGENDIAN
/* TODO: Check for host endianess, #error if not possible */
#endif

/* Taken from TCGMemOp */
typedef enum {
  PTC_MO_8     = 0,
  PTC_MO_16    = 1,
  PTC_MO_32    = 2,
  PTC_MO_64    = 3,
  PTC_MO_SIZE  = 3,   /* Mask for the above.  */

  PTC_MO_SIGN  = 4,   /* Sign-extended, otherwise zero-extended.  */

  PTC_MO_BSWAP = 8,   /* Host reverse endian.  */

#ifdef HOST_WORDS_BIGENDIAN
  PTC_MO_LE    = PTC_MO_BSWAP,
  PTC_MO_BE    = 0,
#else
  PTC_MO_LE    = 0,
  PTC_MO_BE    = PTC_MO_BSWAP,
#endif
#ifdef TARGET_WORDS_BIGENDIAN
  PTC_MO_TE    = PTC_MO_BE,
#else
  PTC_MO_TE    = PTC_MO_LE,
#endif

  /* Combinations of the above, for ease of use.  */
  PTC_MO_UB    = PTC_MO_8,
  PTC_MO_UW    = PTC_MO_16,
  PTC_MO_UL    = PTC_MO_32,
  PTC_MO_SB    = PTC_MO_SIGN | PTC_MO_8,
  PTC_MO_SW    = PTC_MO_SIGN | PTC_MO_16,
  PTC_MO_SL    = PTC_MO_SIGN | PTC_MO_32,
  PTC_MO_Q     = PTC_MO_64,

  PTC_MO_LEUW  = PTC_MO_LE | PTC_MO_UW,
  PTC_MO_LEUL  = PTC_MO_LE | PTC_MO_UL,
  PTC_MO_LESW  = PTC_MO_LE | PTC_MO_SW,
  PTC_MO_LESL  = PTC_MO_LE | PTC_MO_SL,
  PTC_MO_LEQ   = PTC_MO_LE | PTC_MO_Q,

  PTC_MO_BEUW  = PTC_MO_BE | PTC_MO_UW,
  PTC_MO_BEUL  = PTC_MO_BE | PTC_MO_UL,
  PTC_MO_BESW  = PTC_MO_BE | PTC_MO_SW,
  PTC_MO_BESL  = PTC_MO_BE | PTC_MO_SL,
  PTC_MO_BEQ   = PTC_MO_BE | PTC_MO_Q,

  PTC_MO_TEUW  = PTC_MO_TE | PTC_MO_UW,
  PTC_MO_TEUL  = PTC_MO_TE | PTC_MO_UL,
  PTC_MO_TESW  = PTC_MO_TE | PTC_MO_SW,
  PTC_MO_TESL  = PTC_MO_TE | PTC_MO_SL,
  PTC_MO_TEQ   = PTC_MO_TE | PTC_MO_Q,

  PTC_MO_SSIZE = PTC_MO_SIZE | PTC_MO_SIGN,
} PTCLoadStoreType;

inline static PTCLoadStoreType ptc_get_memory_access_size(PTCLoadStoreType type) {
  return (PTCLoadStoreType) (type & PTC_MO_SIZE);
}

inline static int ptc_is_sign_extended_load(PTCLoadStoreType type) {
  return (type & PTC_MO_SIGN) != 0;
}

typedef enum {
  PTC_MEMORY_ACCESS_UNKNOWN,
  PTC_MEMORY_ACCESS_NORMAL,
  PTC_MEMORY_ACCESS_ALIGNED,
  PTC_MEMORY_ACCESS_UNALIGNED
} PTCMemoryAccessType;

typedef struct {
  PTCMemoryAccessType access_type : 2;
  PTCLoadStoreType type : 6;
  unsigned raw_op;
  unsigned mmu_index;
} PTCLoadStoreArg;

/* Taken from TCGHelperInfo */
typedef struct PTCHelperDef {
  void *func;
  const char *name;
  unsigned flags;
  /* For now we ignore sizemask */
  /* unsigned sizemask; */
} PTCHelperDef;

/* Code types */
typedef enum {
  PTC_CODE_REGULAR = 0,
  PTC_CODE_ARM_THUMB = 1
} PTCCodeType;

/* Exported functions */

#define FUNC_PTR(ret, name, params) typedef ret (*name ## _ptr_t) params
#define PROTOTYPE(ret, name, params) ret name params
#define BOTH(ret, name, params)                \
  FUNC_PTR(ret, name, params);                 \
  PROTOTYPE(ret, name, params)

#ifndef USE_DYNAMIC_PTC

/* Exported global variables */

extern PTCOpcodeDef *ptc_opcode_defs;
extern PTCHelperDef *ptc_helper_defs;
extern unsigned ptc_helper_defs_size;

#define EXPORTED(ret, name, params) BOTH(ret, name, params)
#else
#define EXPORTED(ret, name, params) FUNC_PTR(ret, name, params)
#endif

EXPORTED(void, ptc_init, (void));
EXPORTED(void, ptc_disassemble, (FILE *output, uint32_t buffer, size_t buffer_size, int max));
EXPORTED(const char *, ptc_get_condition_name, (PTCCondition condition));
EXPORTED(const char *, ptc_get_load_store_name, (PTCLoadStoreType condition));
EXPORTED(PTCLoadStoreArg, ptc_parse_load_store_arg, (PTCInstructionArg arg));
EXPORTED(unsigned, ptc_get_arg_label_id, (PTCInstructionArg arg));
EXPORTED(void, ptc_mmap, (uint64_t virtual_address, const void *code, size_t code_size));
EXPORTED(size_t, ptc_translate, (uint64_t virtual_address, PTCCodeType type, PTCInstructionList *instructions));

#undef EXPORTED

typedef struct {
  ptc_get_condition_name_ptr_t get_condition_name;
  ptc_get_load_store_name_ptr_t get_load_store_name;
  ptc_parse_load_store_arg_ptr_t parse_load_store_arg;
  ptc_get_arg_label_id_ptr_t get_arg_label_id;
  ptc_mmap_ptr_t mmap;
  ptc_translate_ptr_t translate;
  ptc_disassemble_ptr_t disassemble;

  PTCOpcodeDef *opcode_defs;
  PTCHelperDef *helper_defs;
  unsigned helper_defs_size;

  intptr_t pc;
  intptr_t sp;
  intptr_t is_thumb;
  intptr_t exception_index;
  uint8_t *initialized_env;

} PTCInterface;

BOTH(int, ptc_load, (void *handle, PTCInterface *output));

/* Helper inline functions */

static inline void ptc_instruction_list_free(PTCInstructionList *to_free) {
  if (to_free) {
    free(to_free->arguments);
    free(to_free->instructions);
    free(to_free->temps);
  }
}

static inline PTCHelperDef *ptc_find_helper(PTCInterface *ptc, PTCInstructionArg id) {
  unsigned i = 0;

  for (i = 0; i < ptc->helper_defs_size; i++) {
    if (ptc->helper_defs[i].func == (void *) id) {
      return &ptc->helper_defs[i];
    }
  }

  return NULL;
}

static inline PTCOpcodeDef *ptc_instruction_opcode_def(PTCInterface *ptc, PTCInstruction *instruction) {
  return &ptc->opcode_defs[instruction->opc];
}

/* PTCInstruction accessors */

#define PTC_CALL_NO_READ_GLOBALS 0x0010
#define PTC_CALL_NO_WRITE_GLOBALS 0x0020
#define PTC_CALL_NO_SIDE_EFFECTS 0x0040

#define PTC_CALL_NO_RWG PTC_CALL_NO_READ_GLOBALS
#define PTC_CALL_NO_WG PTC_CALL_NO_WRITE_GLOBALS
#define PTC_CALL_NO_SE PTC_CALL_NO_SIDE_EFFECTS
#define PTC_CALL_NO_RWG_SE (PTC_CALL_NO_RWG | PTC_CALL_NO_SE)
#define PTC_CALL_NO_WG_SE (PTC_CALL_NO_WG | PTC_CALL_NO_SE)

#define PTC_CALL_DUMMY_ARG ((PTCInstructionArg) -1)

#define ptc_call_instruction_opcode_def ptc_instruction_opcode_def

static inline unsigned ptc_instruction_out_arg_count(PTCInterface *ptc, PTCInstruction *instruction) {
  assert(instruction->opc != PTC_INSTRUCTION_op_call);
  return ptc_instruction_opcode_def(ptc, instruction)->nb_oargs;
}

static inline PTCInstructionArg ptc_instruction_out_arg(PTCInterface *ptc, PTCInstruction *instruction, unsigned index) {
  assert(instruction->opc != PTC_INSTRUCTION_op_call);
  assert(index < ptc_instruction_out_arg_count(ptc, instruction));
  return instruction->args[index];
}

static inline unsigned ptc_instruction_in_arg_count(PTCInterface *ptc, PTCInstruction *instruction) {
  assert(instruction->opc != PTC_INSTRUCTION_op_call);
  return ptc_instruction_opcode_def(ptc, instruction)->nb_iargs;
}

static inline PTCInstructionArg ptc_instruction_in_arg(PTCInterface *ptc, PTCInstruction *instruction, unsigned index) {
  assert(instruction->opc != PTC_INSTRUCTION_op_call);
  assert(index < ptc_instruction_in_arg_count(ptc, instruction));
  return instruction->args[ptc_instruction_opcode_def(ptc, instruction)->nb_oargs + index];
}

static inline unsigned ptc_instruction_const_arg_count(PTCInterface *ptc, PTCInstruction *instruction) {
  assert(instruction->opc != PTC_INSTRUCTION_op_call);
  return ptc_instruction_opcode_def(ptc, instruction)->nb_cargs;
}

static inline PTCInstructionArg ptc_instruction_const_arg(PTCInterface *ptc, PTCInstruction *instruction, unsigned index) {
  assert(instruction->opc != PTC_INSTRUCTION_op_call);
  assert(index < ptc_instruction_const_arg_count(ptc, instruction));
  return instruction->args[ptc_instruction_opcode_def(ptc, instruction)->nb_oargs +
                           ptc_instruction_opcode_def(ptc, instruction)->nb_iargs +
                           index];
}


static inline unsigned ptc_call_instruction_out_arg_count(PTCInterface *ptc, PTCInstruction *instruction) {
  assert(instruction->opc == PTC_INSTRUCTION_op_call);
  return instruction->callo;
}

static inline PTCInstructionArg ptc_call_instruction_out_arg(PTCInterface *ptc, PTCInstruction *instruction, unsigned index) {
  assert(instruction->opc == PTC_INSTRUCTION_op_call);
  assert(index < ptc_call_instruction_out_arg_count(ptc, instruction));
  return instruction->args[index];
}

static inline unsigned ptc_call_instruction_in_arg_count(PTCInterface *ptc, PTCInstruction *instruction) {
  assert(instruction->opc == PTC_INSTRUCTION_op_call);
  return instruction->calli;
}

static inline PTCInstructionArg ptc_call_instruction_in_arg(PTCInterface *ptc, PTCInstruction *instruction, unsigned index) {
  assert(instruction->opc == PTC_INSTRUCTION_op_call);
  assert(index < ptc_call_instruction_in_arg_count(ptc, instruction));
  return instruction->args[instruction->callo + index];
}

static inline unsigned ptc_call_instruction_const_arg_count(PTCInterface *ptc, PTCInstruction *instruction) {
  assert(instruction->opc == PTC_INSTRUCTION_op_call);
  return ptc_instruction_opcode_def(ptc, instruction)->nb_cargs;
}

static inline PTCInstructionArg ptc_call_instruction_const_arg(PTCInterface *ptc, PTCInstruction *instruction, unsigned index) {
  assert(instruction->opc == PTC_INSTRUCTION_op_call);
  assert(index < ptc_instruction_opcode_def(ptc, instruction)->nb_cargs);
  return instruction->args[instruction->callo + instruction->calli + index];
}

#ifdef __cplusplus
}
#endif

#endif /* !_PTC_H */
