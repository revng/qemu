#include "libtcg/libtcg.h"
#include "qemu/osdep.h"
#include "cpu.h"
#include "disas/disas.h"
#include "exec/exec-all.h"
#include "tcg/tcg-op.h"
#include "tcg/tcg-internal.h"
#include "qemu/accel.h"
#include "target_elf.h"
#include "target_syscall.h" /* for struct target_pt_regs */
#include "cpu_loop-common.h" /* for target_cpu_copy_regs */

void translate(void) {
    qemu_init_cpu_list() ;
    module_call_init(MODULE_INIT_QOM);
    uint32_t elf_flags = 0;
    const char *cpu_model = cpu_get_model(elf_flags);
    const char *cpu_type = parse_cpu_option(cpu_model);
    /* Initializes accel/tcg */
    {
        AccelClass *ac = ACCEL_GET_CLASS(current_accel());

        accel_init_interfaces(ac);
        ac->init_machine(NULL);
    }

    CPUState *cpu = cpu_create(cpu_type);
    cpu_reset(cpu);
    tcg_prologue_init(tcg_ctx);
    struct target_pt_regs regs1, *regs = &regs1;
    memset(regs, 0, sizeof(struct target_pt_regs));
    target_cpu_copy_regs(cpu->env_ptr, regs);

    /* Needed to initialize fields in `tcg_ctx` */
    tcg_func_start(tcg_ctx);

    target_ulong cs_base, pc;
    uint32_t flags;
    cpu_get_tb_cpu_state(cpu->env_ptr, &pc, &cs_base, &flags);

    uint32_t cflags = cpu->cflags_next_tb;
    if (cflags == -1) {
        cflags = curr_cflags(cpu);
    } else {
        cpu->cflags_next_tb = -1;
    }

    int max_insns = 16;

    TranslationBlock tb = {
        .pc = pc,
        .cs_base = cs_base,
        .flags = flags,
        .cflags = cflags,
    };
    gen_intermediate_code(cpu, &tb, max_insns);
}
