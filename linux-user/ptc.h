#ifndef _PTC_H

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

/* TODO: import TCG_CALL_* flags */

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
  size_t instruction_count;

  /* Additional data, do not access this directly */
  PTCInstructionArg *arguments;
  PTCTemp *temps;
  size_t global_temps;
  size_t total_temps;
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

/* Exported global variables */

extern PTCOpcodeDef *ptc_opcode_defs;
extern PTCHelperDef *ptc_helper_defs;
extern size_t ptc_helper_defs_size;

/* Exported functions */

void ptc_init(void);

const char *ptc_get_condition_name(PTCCondition condition);
const char *ptc_get_load_store_name(PTCLoadStoreType condition);
PTCLoadStoreArg ptc_parse_load_store_arg(PTCInstructionArg arg);
unsigned ptc_get_arg_label_id(PTCInstructionArg arg);

void ptc_translate(void *code, size_t code_size, PTCInstructionList *instructions);

/* Helper inline functions */

static inline void ptc_instruction_list_free(PTCInstructionList *to_free) {
  if (to_free) {
    free(to_free->arguments);
    free(to_free->instructions);
    free(to_free->temps);
  }
}

static inline PTCHelperDef *ptc_find_helper(PTCInstructionArg id) {
  unsigned i = 0;

  for (i = 0; i < ptc_helper_defs_size; i++) {
    if (ptc_helper_defs[i].func == (void *) id) {
      return &ptc_helper_defs[i];
    }
  }

  return NULL;
}

/* PTCInstruction accessors */

/* TODO: use unsigned int instead of size_t */

#define PTC_CALL_DUMMY_ARG ((PTCInstructionArg) -1)

#define ptc_call_instruction_opcode_def ptc_instruction_opcode_def
#define ptc_call_instruction_const_arg_count ptc_instruction_const_arg_count

static inline PTCOpcodeDef *ptc_instruction_opcode_def(PTCInstruction *instruction) {
  return &ptc_opcode_defs[instruction->opc];
}


static inline size_t ptc_instruction_out_arg_count(PTCInstruction *instruction) {
  assert(instruction->opc != PTC_INSTRUCTION_op_call);
  return ptc_instruction_opcode_def(instruction)->nb_oargs;
}

static inline PTCInstructionArg ptc_instruction_out_arg(PTCInstruction *instruction, size_t index) {
  assert(instruction->opc != PTC_INSTRUCTION_op_call);
  assert(index < ptc_instruction_out_arg_count(instruction));
  return instruction->args[index];
}

static inline size_t ptc_instruction_in_arg_count(PTCInstruction *instruction) {
  assert(instruction->opc != PTC_INSTRUCTION_op_call);
  return ptc_instruction_opcode_def(instruction)->nb_iargs;
}

static inline PTCInstructionArg ptc_instruction_in_arg(PTCInstruction *instruction, size_t index) {
  assert(instruction->opc != PTC_INSTRUCTION_op_call);
  assert(index < ptc_instruction_in_arg_count(instruction));
  return instruction->args[ptc_instruction_opcode_def(instruction)->nb_oargs + index];
}

static inline size_t ptc_instruction_const_arg_count(PTCInstruction *instruction) {
  assert(instruction->opc != PTC_INSTRUCTION_op_call);
  return ptc_instruction_opcode_def(instruction)->nb_cargs;
}

static inline PTCInstructionArg ptc_instruction_const_arg(PTCInstruction *instruction, size_t index) {
  assert(instruction->opc != PTC_INSTRUCTION_op_call);
  assert(index < ptc_instruction_const_arg_count(instruction));
  return instruction->args[ptc_instruction_opcode_def(instruction)->nb_oargs + ptc_instruction_opcode_def(instruction)->nb_iargs + index];
}


static inline size_t ptc_call_instruction_out_arg_count(PTCInstruction *instruction) {
  assert(instruction->opc == PTC_INSTRUCTION_op_call);
  return instruction->callo;
}

static inline PTCInstructionArg ptc_call_instruction_out_arg(PTCInstruction *instruction, size_t index) {
  assert(instruction->opc == PTC_INSTRUCTION_op_call);
  assert(index < ptc_call_instruction_out_arg_count(instruction));
  return instruction->args[index];
}

static inline size_t ptc_call_instruction_in_arg_count(PTCInstruction *instruction) {
  assert(instruction->opc == PTC_INSTRUCTION_op_call);
  return instruction->calli;
}

static inline PTCInstructionArg ptc_call_instruction_in_arg(PTCInstruction *instruction, size_t index) {
  assert(instruction->opc == PTC_INSTRUCTION_op_call);
  assert(index < ptc_call_instruction_in_arg_count(instruction));
  return instruction->args[instruction->callo + index];
}

static inline PTCInstructionArg ptc_call_instruction_const_arg(PTCInstruction *instruction, size_t index) {
  assert(instruction->opc == PTC_INSTRUCTION_op_call);
  assert(index < ptc_instruction_opcode_def(instruction)->nb_cargs);
  return instruction->args[instruction->callo + instruction->calli + index];
}

#endif /* !_PTC_H */
