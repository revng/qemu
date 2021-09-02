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

static char *global_buffer = NULL;
static size_t global_size = 0;
static uint64_t global_virtual_address = 0;

/*
 * Here we have the functions to replace QEMUs memory access functions in
 * accel/tcg/user-exec.c. We override them to read bytecode from a buffer
 * instead.
 */

#define CPU_MEMORY_ACCESS_FUNC(return_type, read_type, name)            \
    return_type name(CPUArchState *env, abi_ptr ptr) {                  \
        uint64_t offset = (uintptr_t)ptr - global_virtual_address;      \
        assert(offset + sizeof(read_type) <= global_size);              \
        return *(read_type *) ((uintptr_t) global_buffer + offset);     \
    }

CPU_MEMORY_ACCESS_FUNC(uint32_t,  uint8_t, cpu_ldub_code)
CPU_MEMORY_ACCESS_FUNC(uint32_t, uint16_t, cpu_lduw_code)
CPU_MEMORY_ACCESS_FUNC(uint32_t, uint32_t, cpu_ldl_code )
CPU_MEMORY_ACCESS_FUNC(uint64_t, uint64_t, cpu_ldq_code )

#undef CPU_MEMORY_ACCESS_FUNC

void translate(char *buffer, size_t size, uint64_t virtual_address) {
    global_buffer = buffer;
    global_size = size;
    global_virtual_address = virtual_address;

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
    /*
     * We're using this call to setup `flags` and `cs_base` correctly.
     * We then override `pc`.
     */
    cpu_get_tb_cpu_state(cpu->env_ptr, &pc, &cs_base, &flags);
    pc = virtual_address;

    uint32_t cflags = cpu->cflags_next_tb;
    if (cflags == -1) {
        cflags = curr_cflags(cpu);
    } else {
        cpu->cflags_next_tb = -1;
    }

    /*
     * Set `max_insns` to the number of bytes in the buffer
     * so we don't have to worry about it being too small.
     */
    int max_insns = size;

    TranslationBlock tb = {
        .pc = pc,
        .cs_base = cs_base,
        .flags = flags,
        .cflags = cflags,
    };
    gen_intermediate_code(cpu, &tb, max_insns);
}
