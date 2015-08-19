#include <stdio.h>
#include <sys/mman.h>

#include "qemu.h"
#include "qemu-common.h"
#include "cpu.h"
#include "tcg.h"
#include "trace.h"

#include "ptc.h"

#include "exec/exec-all.h"

unsigned long reserved_va = 0;
int singlestep = 0;
unsigned long guest_base = 0;

abi_long do_brk(abi_ulong new_brk) { exit(-1); }

void cpu_list_unlock(void) { /* exit(-1); */ }
void cpu_list_lock(void) { /* exit(-1); */ }

void mmap_unlock(void) { /* exit(-1); */ }
void mmap_lock(void) { /* exit(-1); */ }

static void dump_tinycode(TCGContext *s, PTCInstructionList *instructions);

PTCOpcodeDef *ptc_opcode_defs;
static unsigned long cs_base = 0;
static CPUState *cpu = NULL;

void ptc_init(void) {
  int i = 0;

  if (ptc_opcode_defs == NULL) {
    ptc_opcode_defs = (PTCOpcodeDef *) calloc(sizeof(PTCOpcodeDef), tcg_op_defs_max);

    for (i = 0; i < tcg_op_defs_max; i++) {
      ptc_opcode_defs[i].name = tcg_op_defs[i].name;
      ptc_opcode_defs[i].nb_oargs = tcg_op_defs[i].nb_oargs;
      ptc_opcode_defs[i].nb_iargs = tcg_op_defs[i].nb_iargs;
      ptc_opcode_defs[i].nb_cargs = tcg_op_defs[i].nb_cargs;
      ptc_opcode_defs[i].nb_args = tcg_op_defs[i].nb_args;
    }
  }

  if (cpu == NULL) {
    /* init guest base */
    guest_base = (unsigned long) mmap((void *)0xb0000000, 0x8000, PROT_EXEC|PROT_READ|PROT_WRITE,
            MAP_FIXED|MAP_PRIVATE|MAP_ANON, -1, 0x0);

    /* init TCGContext */
    tcg_exec_init(0);

    /* init QOM */
    module_call_init(MODULE_INIT_QOM);

    /* init env and cpu */
    cpu = cpu_init("any");

    /* Reset CPU */
    cpu_reset(cpu);

    /* set logging for tiny code dumping */
    qemu_set_log(CPU_LOG_TB_OP | CPU_LOG_TB_OP_OPT);
  }

}

static TranslationBlock *tb_alloc2(target_ulong pc)
{
    TranslationBlock *tb;

    if (tcg_ctx.tb_ctx.nb_tbs >= tcg_ctx.code_gen_max_blocks ||
        (tcg_ctx.code_gen_ptr - tcg_ctx.code_gen_buffer) >=
         tcg_ctx.code_gen_buffer_max_size) {
        return NULL;
    }
    tb = &tcg_ctx.tb_ctx.tbs[tcg_ctx.tb_ctx.nb_tbs++];
    tb->pc = pc;
    tb->cflags = 0;
    return tb;
}

static void dump_tinycode(TCGContext *s, PTCInstructionList *instructions) {
    TCGOp *op;
    int oi;

    PTCInstructionList result = { 0 };

    size_t arguments_count = 0;

    PTCInstruction *current_instruction = NULL;
    TCGOpcode c;
    const TCGOpDef *def;

    for (oi = s->gen_first_op_idx; oi >= 0; oi = op->next) {
      result.instruction_count++;

      op = &s->gen_op_buf[oi];
      c = op->opc;
      def = &tcg_op_defs[c];

      if (c == INDEX_op_debug_insn_start) {
        arguments_count += 2;
      } else if (c == INDEX_op_call){
        arguments_count += op->callo + op->calli + def->nb_cargs;
      } else {
        arguments_count += def->nb_oargs + def->nb_iargs + def->nb_cargs;
      }
    }

    result.instructions = (PTCInstruction *) calloc(sizeof(PTCInstruction), result.instruction_count);
    result.arguments = (PTCInstructionArg *) calloc(sizeof(PTCInstructionArg), arguments_count);

    result.instruction_count = 0;
    arguments_count = 0;
    for (oi = s->gen_first_op_idx; oi >= 0; oi = op->next) {
      current_instruction = &result.instructions[result.instruction_count];
      result.instruction_count++;

      op = &s->gen_op_buf[oi];

      current_instruction->opc = (PTCOpcode) s->gen_op_buf[oi].opc;
      current_instruction->callo = s->gen_op_buf[oi].callo;
      current_instruction->calli = s->gen_op_buf[oi].calli;

      c = current_instruction->opc;
      def = &tcg_op_defs[c];

      if (c == INDEX_op_debug_insn_start) {
        current_instruction->args = &result.arguments[arguments_count];
        arguments_count += 2;
      } else if (c == INDEX_op_call){
        current_instruction->args = &result.arguments[arguments_count];
        arguments_count += current_instruction->callo + current_instruction->calli + def->nb_cargs;
      } else {
        current_instruction->args = &result.arguments[arguments_count];
        arguments_count += def->nb_oargs + def->nb_iargs + def->nb_cargs;
      }
    }

    *instructions = result;
}

static TranslationBlock *tb_gen_code2(TCGContext *s, CPUState *cpu,
                                     target_ulong pc, target_ulong cs_base,
                                     int flags, int cflags)
{
    CPUArchState *env = cpu->env_ptr;
    TranslationBlock *tb;

    if (use_icount) {
        cflags |= CF_USE_ICOUNT;
    }

    tb = tb_alloc2(pc);
    if (!tb) {
        /* flush must be done */
        tb_flush(cpu);
        /* cannot fail at this point */
        tb = tb_alloc2(pc);
        /* Don't forget to invalidate previous TB info.  */
        tcg_ctx.tb_ctx.tb_invalidated_flag = 1;
    }

    tb->tc_ptr = tcg_ctx.code_gen_ptr;
    tb->cs_base = cs_base;
    tb->flags = flags;
    tb->cflags = cflags;

    // From cpu_gen_code
    tcg_func_start(s);

    gen_intermediate_code(env, tb);

    return tb;
}

void ptc_translate(void *code, size_t code_size, PTCInstructionList *instructions) {
    TCGContext *s = &tcg_ctx;

    /* copy code over */
    memcpy((void *) guest_base, code, code_size);

    tb_gen_code2(s, cpu, (target_ulong) 0, cs_base, 0, 0);

    // tcg_dump_ops(s);

    dump_tinycode(s, instructions);
}
