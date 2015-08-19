#ifndef _PTC_H

#include <stdint.h>
#include <stdlib.h>

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

typedef struct {
  PTCInstruction *instructions;
  size_t instruction_count;
  PTCInstructionArg *arguments;
} PTCInstructionList;

typedef struct {
  const char *name;
  uint8_t nb_oargs, nb_iargs, nb_cargs, nb_args;
  /* TODO: add missing fields (see TCGOpDef) */
} PTCOpcodeDef;

/* Exported global variables */

extern PTCOpcodeDef *ptc_opcode_defs;

/* Exported functions */

void ptc_init(void);
void ptc_translate(void *code, size_t code_size, PTCInstructionList *instructions);

/* Helper inline functions */

static inline void ptc_instruction_list_free(PTCInstructionList *to_free) {
  if (to_free) {
    free(to_free->arguments);
    free(to_free->instructions);
  }
}

/* PTCInstruction accessors */

#define ptc_call_instruction_opcode_def ptc_instruction_opcode_def
#define ptc_call_instruction_const_arg_count ptc_instruction_const_arg_count

static inline PTCOpcodeDef *ptc_instruction_opcode_def(PTCInstruction *instruction) {
  return &ptc_opcode_defs[instruction->opc];
}


static inline size_t ptc_instruction_out_arg_count(PTCInstruction *instruction) {
  assert(instruction->opc != PTC_INSTRUCTION_op_call);
  return ptc_instruction_opcode_def(instruction)->nb_oargs;
}

static inline PTCInstructionArg *ptc_instruction_out_arg(PTCInstruction *instruction, size_t index) {
  assert(instruction->opc != PTC_INSTRUCTION_op_call);
  assert(index < ptc_instruction_out_arg_count(instruction));
  return &instruction->args[index];
}

static inline size_t ptc_instruction_in_arg_count(PTCInstruction *instruction) {
  assert(instruction->opc != PTC_INSTRUCTION_op_call);
  return ptc_instruction_opcode_def(instruction)->nb_iargs;
}

static inline PTCInstructionArg *ptc_instruction_in_arg(PTCInstruction *instruction, size_t index) {
  assert(instruction->opc != PTC_INSTRUCTION_op_call);
  assert(index < ptc_instruction_in_arg_count(instruction));
  return &instruction->args[ptc_instruction_opcode_def(instruction)->nb_oargs + index];
}

static inline size_t ptc_instruction_const_arg_count(PTCInstruction *instruction) {
  assert(instruction->opc != PTC_INSTRUCTION_op_call);
  return ptc_instruction_opcode_def(instruction)->nb_cargs;
}

static inline PTCInstructionArg *ptc_instruction_const_arg(PTCInstruction *instruction, size_t index) {
  assert(instruction->opc != PTC_INSTRUCTION_op_call);
  assert(index < ptc_instruction_const_arg_count(instruction));
  return &instruction->args[ptc_instruction_opcode_def(instruction)->nb_oargs + ptc_instruction_opcode_def(instruction)->nb_iargs + index];
}


static inline size_t ptc_call_instruction_out_arg_count(PTCInstruction *instruction) {
  assert(instruction->opc == PTC_INSTRUCTION_op_call);
  return instruction->callo;
}

static inline PTCInstructionArg *ptc_call_instruction_out_arg(PTCInstruction *instruction, size_t index) {
  assert(instruction->opc == PTC_INSTRUCTION_op_call);
  assert(index < ptc_call_instruction_out_arg_count(instruction));
  return &instruction->args[index];
}

static inline size_t ptc_call_instruction_in_arg_count(PTCInstruction *instruction) {
  assert(instruction->opc == PTC_INSTRUCTION_op_call);
  return instruction->calli;
}

static inline PTCInstructionArg *ptc_call_instruction_in_arg(PTCInstruction *instruction, size_t index) {
  assert(instruction->opc == PTC_INSTRUCTION_op_call);
  assert(index < ptc_call_instruction_in_arg_count(instruction));
  return &instruction->args[instruction->callo + index];
}

static inline PTCInstructionArg *ptc_call_instruction_const_arg(PTCInstruction *instruction, size_t index) {
  assert(instruction->opc == PTC_INSTRUCTION_op_call);
  assert(index < ptc_instruction_opcode_def(instruction)->nb_cargs);
  return &instruction->args[instruction->callo + instruction->calli + index];
}

#endif /* !_PTC_H */
