#include <stdio.h>
#include <sys/mman.h>

#include "qemu.h"
#include "qemu-common.h"
#include "cpu.h"
#include "tcg.h"
#include "trace.h"
#include "disas/disas.h"

#include "ptc.h"
#include "elf.h"

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

static int constants_checks __attribute__((unused)) =
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

  MATCH3(TCG_, CALL, NO_READ_GLOBALS, NO_WRITE_GLOBALS, NO_SIDE_EFFECTS) +
  MATCH5(TCG_, CALL, NO_RWG, NO_WG, NO_SE, NO_RWG_SE, NO_WG_SE) +
  MATCH(TCG_, CALL_DUMMY_ARG);

#undef EQUALS
#undef MATCH

unsigned long reserved_va = 0;
int singlestep = 0;
unsigned long guest_base = 0;
unsigned long mmap_min_addr = 4096;

abi_long do_brk(abi_ulong new_brk) { exit(-1); }

void cpu_list_unlock(void) { /* exit(-1); */ }
void cpu_list_lock(void) { /* exit(-1); */ }

#ifdef TARGET_I386
uint64_t cpu_get_tsc(CPUX86State *env) {
    return 0;
}

int cpu_get_pic_interrupt(CPUX86State *env)
{
    return -1;
}

#endif

static void dump_tinycode(TCGContext *s, PTCInstructionList *instructions);

PTCOpcodeDef *ptc_opcode_defs;
PTCHelperDef *ptc_helper_defs;
unsigned ptc_helper_defs_size;

static unsigned long cs_base = 0;
static CPUState *cpu = NULL;

#if defined(TARGET_X86_64) || defined(TARGET_I386)
# define CPU_STRUCT X86CPU
#elif defined(TARGET_ARM) || defined(TARGET_AARCH64)
# define CPU_STRUCT ARMCPU
#elif defined(TARGET_MIPS)
# define CPU_STRUCT MIPSCPU
#elif defined(TARGET_S390X)
# define CPU_STRUCT S390CPU
#endif

typedef struct {
  target_ulong start;
  target_ulong end;
} AddressRange;

#define MAX_RANGES 10
static AddressRange ranges[MAX_RANGES];

static CPU_STRUCT initialized_state;

int ptc_load(void *handle, PTCInterface *output) {

  PTCInterface result = { 0 };

  ptc_init();

#if defined(TARGET_X86_64) || defined(TARGET_I386)
  result.pc = offsetof(CPUX86State, eip);
  result.sp = offsetof(CPUX86State, regs[R_ESP]);
#elif defined(TARGET_ARM)
#if defined(TARGET_AARCH64)
  result.pc = offsetof(CPUARMState, pc);
  result.sp = offsetof(CPUARMState, xregs[31]);
#else
  result.pc = offsetof(CPUARMState, regs[15]);
  result.sp = offsetof(CPUARMState, regs[13]);
  result.is_thumb = offsetof(CPUARMState, thumb);
#endif
#elif defined(TARGET_MIPS)
  result.pc = offsetof(CPUMIPSState, active_tc.PC);
  result.sp = offsetof(CPUMIPSState, active_tc.gpr[29]);
#elif defined(TARGET_S390X)
  result.pc = offsetof(CPUS390XState, psw.addr);
  result.sp = offsetof(CPUS390XState, regs[15]);
#endif

  result.exception_index = (offsetof(CPU_STRUCT, parent_obj)
                            + offsetof(CPUState, exception_index));

  result.get_condition_name = &ptc_get_condition_name;
  result.get_load_store_name = &ptc_get_load_store_name;
  result.parse_load_store_arg = &ptc_parse_load_store_arg;
  result.get_arg_label_id = &ptc_get_arg_label_id;
  result.mmap = &ptc_mmap;
  result.translate = &ptc_translate;
  result.disassemble = &ptc_disassemble;

  result.opcode_defs = ptc_opcode_defs;
  result.helper_defs = ptc_helper_defs;
  result.helper_defs_size = ptc_helper_defs_size;
  result.initialized_env = (uint8_t *) &initialized_state.env;

  *output = result;

  return 0;
}

static void add_helper(gpointer key, gpointer value, gpointer user_data) {
  TCGHelperInfo *helper = value;
  unsigned *count = user_data;
  unsigned index = --(*count);

  ptc_helper_defs[index].func = helper->func;
  ptc_helper_defs[index].name = helper->name;
  ptc_helper_defs[index].flags = helper->flags;
}

void ptc_init(void) {
  int i = 0;

  if (cpu == NULL) {
    /* init guest base */
    guest_base = 0x40000000;

    /* init TCGContext */
    tcg_exec_init(0);

    /* init QOM */
    module_call_init(MODULE_INIT_QOM);

    /* init env and cpu */
#if defined(TARGET_I386)

#if defined(TARGET_X86_64)
    cpu = cpu_init("qemu64");
#else
    cpu = cpu_init("qemu32");
#endif

#elif defined(TARGET_MIPS)
#if defined(TARGET_ABI_MIPSN32) || defined(TARGET_ABI_MIPSN64)
    cpu = cpu_init("5KEf");
#else
    cpu = cpu_init("24Kf");
#endif
#else
    cpu = cpu_init("any");
#endif

    assert(cpu != NULL);

    /* Reset CPU */
    cpu_reset(cpu);

    initialize_cpu_state(cpu->env_ptr);

    /* set logging for tiny code dumping */
    qemu_set_log(CPU_LOG_TB_OP | CPU_LOG_TB_OP_OPT);

    initialized_state = *(container_of(cpu->env_ptr, CPU_STRUCT, env));
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
    unsigned helper_table_size = g_hash_table_size(helper_table);

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

static PTCTemp copy_temp(TCGTemp original) {
  PTCTemp result = { 0 };

  result.reg = original.reg;
  result.mem_reg = original.mem_reg;
  result.val_type = original.val_type;
  result.base_type = original.base_type;
  result.type = original.type;
  result.fixed_reg = original.fixed_reg;
  result.mem_coherent = original.mem_coherent;
  result.mem_allocated = original.mem_allocated;
  result.temp_local = original.temp_local;
  result.temp_allocated = original.temp_allocated;
  result.val = original.val;
  result.mem_offset = original.mem_offset;
  result.name = original.name;

  return result;
}

static void dump_tinycode(TCGContext *s, PTCInstructionList *instructions) {
    TCGOp *op = NULL;
    int oi = 0;
    int j = 0;

    PTCInstructionList result = { 0 };

    unsigned arguments_count = 0;

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
      } else if (c == INDEX_op_call) {
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

    for (oi = 0; oi < s->nb_temps; oi++)
      result.temps[oi] = copy_temp(s->temps[oi]);

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

extern void tb_link_page(TranslationBlock *tb, tb_page_addr_t phys_pc,
                         tb_page_addr_t phys_page2);

static TranslationBlock *tb_gen_code2(TCGContext *s, CPUState *cpu,
                                     target_ulong pc, target_ulong cs_base,
                                     int flags, int cflags)
{
    CPUArchState *env = cpu->env_ptr;
    TranslationBlock *tb;
    tb_page_addr_t phys_pc;
    int i = 0;

    phys_pc = get_page_addr_code(env, pc);

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

    for (i = 0; i < MAX_RANGES; i++)
      if (ranges[i].start <= pc && pc < ranges[i].end)
        break;
    assert(i != MAX_RANGES);
    tb->max_pc = ranges[i].end;

    // From cpu_gen_code
    tcg_func_start(s);

    gen_intermediate_code(env, tb);

    tb_link_page(tb, phys_pc, -1);

    return tb;
}

void ptc_mmap(uint64_t virtual_address, const void *code, size_t code_size) {
  abi_long mmapd_address;
  unsigned i;

  mmapd_address = target_mmap((abi_ulong) virtual_address,
                              (abi_ulong) code_size,
                              PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                              -1,
                              0);
  memcpy((void *) g2h(virtual_address), code, code_size);

  assert(mmapd_address == (abi_ulong) virtual_address);

  for (i = 0; i < MAX_RANGES; i++) {
    if (ranges[i].start == ranges[i].end
        && ranges[i].end == 0) {
      ranges[i].start = virtual_address;
      ranges[i].end = virtual_address + code_size;
      return;
    }
  }

  assert(false);
}

/* TODO: error management */
size_t ptc_translate(uint64_t virtual_address, PTCCodeType type, PTCInstructionList *instructions) {
    TCGContext *s = &tcg_ctx;
    TranslationBlock *tb = NULL;

    target_ulong temp;
    int flags = 0;
    cpu_get_tb_cpu_state(cpu->env_ptr, &temp, &temp, &flags);

#if defined(TARGET_S390X)
    flags |= FLAG_MASK_32 | FLAG_MASK_64;
#endif

  bool is_thumb = (type & PTC_CODE_ARM_THUMB) != 0;
#ifdef TARGET_ARM
  if (is_thumb)
    flags |= (1 << ARM_TBFLAG_THUMB_SHIFT);
#else
  assert(!is_thumb);
#endif

    tb = tb_gen_code2(s, cpu, (target_ulong) virtual_address, cs_base, flags, 0);

    // tcg_dump_ops(s);

    dump_tinycode(s, instructions);

    return (size_t) tb->size;
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

void ptc_disassemble(FILE *output, uint32_t buffer, size_t buffer_size, int max) {
  int flags = 0;
#ifdef TARGET_X86_64
  /* Force 64-bit decoding */
  flags = 2;
#endif

  target_disas_max(output, cpu, /* GUEST_BASE + */ buffer, buffer_size, flags, max);
}
