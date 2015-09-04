#include <stdio.h>
#include <sys/mman.h>

#include "qemu.h"
#include "qemu-common.h"
#include "cpu.h"
#include "tcg.h"
#include "trace.h"

#include "ptc.h"

#include "exec/exec-all.h"

/* Check coherence of the values of the constants between TCG_* and
   PTC_*. Sadly we have to use this dirty division by zero trick to
   trigger an error from the compiler, in fact, due to using enums and
   not defines, we cannot check the values with a preprocessor
   conditional block. */

#define EQUALS(x, y) (1 / ((int) (x) == (int) (y)))
#define MATCH(pref, x) EQUALS(PTC_ ## x, pref ## x)
#define MATCH2(pref, prefix, a, b) MATCH(pref, prefix ## _ ## a) + MATCH(pref, prefix ## _ ## b)
#define MATCH3(pref, prefix, a, b, c) MATCH(pref, prefix ## _ ## a) + MATCH2(pref, prefix, b, c)
#define MATCH4(pref, prefix, a, b, c, d) MATCH2(pref, prefix, a, b) + MATCH2(pref, prefix, c, d)
#define MATCH5(pref, prefix, a, b, c, d, e) MATCH3(pref, prefix, a, b, e) + MATCH2(pref, prefix, c, d)
#define MATCH7(pref, prefix, a, b, c, d, e, f, g) MATCH4(pref, prefix, a, b, c, d) + MATCH3(pref, prefix, e, f, g)

static int constants_checks =
  MATCH3(TCG_, TYPE, I32, I64, COUNT) +

  MATCH4(TCG_, COND, NEVER, ALWAYS, EQ, NE) +
  MATCH4(TCG_, COND, LT, GE, LE, GT) +
  MATCH4(TCG_, COND, NEVER, ALWAYS, EQ, NE) +
  MATCH4(TCG_, COND, LTU, GEU, LEU, GTU) +

  MATCH5(, MO, 8, 16, 32, 64, SIZE) +
  MATCH2(, MO, SIGN, BSWAP) + MATCH3(, MO, LE, BE, TE) +
  MATCH7(, MO, UB, UW, UL, SB, SW, SL, Q) +
  MATCH5(, MO, LEUW, LEUL, LESW, LESL, LEQ) +
  MATCH5(, MO, BEUW, BEUL, BESW, BESL, BEQ) +
  MATCH5(, MO, TEUW, TEUL, TESW, TESL, TEQ) +
  MATCH(, MO_SSIZE) +

  MATCH4(, TEMP_VAL, DEAD, REG, MEM, CONST) +

  MATCH(TCG_, CALL_DUMMY_ARG);

#undef EQUALS
#undef MATCH

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
PTCHelperDef *ptc_helper_defs;
size_t ptc_helper_defs_size;

static unsigned long cs_base = 0;
static CPUState *cpu = NULL;


static void add_helper(gpointer key, gpointer value, gpointer user_data) {
  TCGHelperInfo *helper = value;
  size_t *count = user_data;
  size_t index = --(*count);

  ptc_helper_defs[index].func = helper->func;
  ptc_helper_defs[index].name = helper->name;
  ptc_helper_defs[index].flags = helper->flags;
}

void ptc_init(void) {
  int i = 0;

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

  if (ptc_helper_defs == NULL) {
    TCGContext *s = &tcg_ctx;
    GHashTable *helper_table = s->helpers;
    size_t helper_table_size = g_hash_table_size(helper_table);

    ptc_helper_defs_size = helper_table_size;
    ptc_helper_defs = (PTCHelperDef *) calloc(sizeof(PTCHelperDef), helper_table_size);

    g_hash_table_foreach(helper_table, add_helper, &helper_table_size);
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
    TCGOp *op = NULL;
    int oi = 0;
    int j = 0;

    PTCInstructionList result = { 0 };

    size_t arguments_count = 0;

    PTCInstruction *current_instruction = NULL;
    TCGOpcode c;
    const TCGOpDef *def = NULL;
    const TCGArg *args = NULL;

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

    /* Copy the temp values */
    result.total_temps = s->nb_temps;
    result.global_temps = s->nb_globals;
    result.temps = (PTCTemp *) calloc(sizeof(PTCTemp), result.total_temps);

    for (oi = 0; oi < s->nb_temps; oi++) {
      result.temps[oi].reg = s->temps[oi].reg;
      result.temps[oi].mem_reg = s->temps[oi].mem_reg;
      result.temps[oi].val_type = s->temps[oi].val_type;
      result.temps[oi].base_type = s->temps[oi].base_type;
      result.temps[oi].type = s->temps[oi].type;
      result.temps[oi].fixed_reg = s->temps[oi].fixed_reg;
      result.temps[oi].mem_coherent = s->temps[oi].mem_coherent;
      result.temps[oi].mem_allocated = s->temps[oi].mem_allocated;
      result.temps[oi].temp_local = s->temps[oi].temp_local;
      result.temps[oi].temp_allocated = s->temps[oi].temp_allocated;
      result.temps[oi].val = s->temps[oi].val;
      result.temps[oi].mem_offset = s->temps[oi].mem_offset;
      result.temps[oi].name = s->temps[oi].name;
    }

    /* Go through all the instructions again and collect the information */

    result.instruction_count = 0;
    arguments_count = 0;
    for (oi = s->gen_first_op_idx; oi >= 0; oi = op->next) {
      unsigned int total_new = 0;

      current_instruction = &result.instructions[result.instruction_count];
      result.instruction_count++;

      op = &s->gen_op_buf[oi];
      args = &s->gen_opparam_buf[op->args];

      current_instruction->opc = (PTCOpcode) s->gen_op_buf[oi].opc;
      current_instruction->callo = s->gen_op_buf[oi].callo;
      current_instruction->calli = s->gen_op_buf[oi].calli;

      c = current_instruction->opc;
      def = &tcg_op_defs[c];

      current_instruction->args = &result.arguments[arguments_count];

      if (c == INDEX_op_debug_insn_start)
        total_new = 2;
      else if (c == INDEX_op_call)
        total_new = current_instruction->callo + current_instruction->calli + def->nb_cargs;
      else
        total_new = def->nb_oargs + def->nb_iargs + def->nb_cargs;

      for (j = 0; j < total_new; j++)
        result.arguments[arguments_count + j] = args[j];

      arguments_count += total_new;
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

const char *ptc_get_condition_name(PTCCondition condition) {
  switch (condition) {
  case PTC_COND_NEVER: return "never";
  case PTC_COND_ALWAYS: return "always";
  case PTC_COND_EQ: return "eq";
  case PTC_COND_NE: return "ne";
  case PTC_COND_LT: return "lt";
  case PTC_COND_GE: return "ge";
  case PTC_COND_LE: return "le";
  case PTC_COND_GT: return "gt";
  case PTC_COND_LTU: return "ltu";
  case PTC_COND_GEU: return "geu";
  case PTC_COND_LEU: return "leu";
  case PTC_COND_GTU: return "gtu";
  default: return NULL;
  }
}

const char *ptc_get_load_store_name(PTCLoadStoreType type) {
  switch (type) {
  case PTC_MO_UB: return "ub";
  case PTC_MO_SB: return "sb";
  case PTC_MO_LEUW: return "leuw";
  case PTC_MO_LESW: return "lesw";
  case PTC_MO_LEUL: return "leul";
  case PTC_MO_LESL: return "lesl";
  case PTC_MO_LEQ: return "leq";
  case PTC_MO_BEUW: return "beuw";
  case PTC_MO_BESW: return "besw";
  case PTC_MO_BEUL: return "beul";
  case PTC_MO_BESL: return "besl";
  case PTC_MO_BEQ: return "beq";
  default: return NULL;
  }
}

PTCLoadStoreArg ptc_parse_load_store_arg(PTCInstructionArg arg) {
  PTCLoadStoreArg result = { 0 };

  result.raw_op = get_memop((TCGMemOpIdx) arg);
  if (result.raw_op & ~(MO_AMASK | MO_BSWAP | MO_SSIZE)) {
    result.access_type = PTC_MEMORY_ACCESS_UNKNOWN;
  } else {
    if (result.raw_op & MO_AMASK) {
      if ((result.raw_op & MO_AMASK) == MO_ALIGN) {
        result.access_type = PTC_MEMORY_ACCESS_ALIGNED;
      } else {
        result.access_type = PTC_MEMORY_ACCESS_UNALIGNED;
      }
    } else {
      result.access_type = PTC_MEMORY_ACCESS_NORMAL;
    }
  }

  result.type = result.raw_op & (MO_BSWAP | MO_SSIZE);
  result.mmu_index = get_mmuidx((TCGMemOpIdx) arg);
  return result;
}

unsigned ptc_get_arg_label_id(PTCInstructionArg arg) {
  TCGLabel *label = arg_label((TCGArg) arg);
  return label->id;
}
