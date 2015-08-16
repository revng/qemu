#include <stdio.h>
#include <sys/mman.h>

#include "qemu.h"
#include "qemu-common.h"
#include "cpu.h"
#include "tcg.h"

#include "exec/exec-all.h"

unsigned long reserved_va = 0;
unsigned long mmap_min_addr = 4096;
int singlestep = 0;
unsigned long guest_base = 0;

abi_long do_brk(abi_ulong new_brk) { exit(-1); }

void cpu_list_unlock(void) { /* exit(-1); */ }
void cpu_list_lock(void) { /* exit(-1); */ }

void mmap_unlock(void) { /* exit(-1); */ }
void mmap_lock(void) { /* exit(-1); */ }

static target_ulong code[6] = { 0xe28f1014, 0xe3a00001, 0xe3a0200c, 0xe3a07004, 0xef000000, 0x0 };

TranslationBlock *tb_alloc(target_ulong p);

int test_translation(void);

int test_translation(void) {

    unsigned long cs_base = 0;
    int i;

    /* init guest base */
    guest_base = (unsigned long) mmap((void *)0xb0000000, 0x8000, PROT_EXEC|PROT_READ|PROT_WRITE,
            MAP_FIXED|MAP_PRIVATE|MAP_ANON, -1, 0x0);

    fprintf(stderr, "Guest Base: %lu\n", guest_base);

    /* init TCGContext */
    tcg_exec_init(0);

    /* init QOM */
    module_call_init(MODULE_INIT_QOM);

    /* init env and cpu */
    CPUState *cpu = cpu_init("any");

    /* Reset CPU */
    cpu_reset(cpu);

    /* copy code over */
    memcpy((void *)guest_base, code, sizeof(code));

    /* set logging for tiny code dumping */
    qemu_set_log(CPU_LOG_TB_OP | CPU_LOG_TB_OP_OPT);

    /* program counter */
    fprintf(stderr, "Generating Tiny Code\n");

    for(i = 0; i < sizeof(code); i += 4)
        tb_gen_code(cpu, (target_ulong)i, cs_base, 0x0, 1);

    return 0;
}
