#include "libtcg/libtcg_loader.h"
#include "libtcg/libtcg.h"
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#define ARRLEN(arr) (sizeof(arr) / sizeof(arr[0]))

typedef struct LibTcgLibraryInfo {
    void *handle;
    LibTcgContext *context;
    LibTcgInterface libtcg;
} LibTcgLibraryInfo;

static LibTcgLibraryInfo library_info[LIBTCG_ARCH_COUNT] = {0};

static const char *arch_names[] = {
    [LIBTCG_ARCH_AARCH64_BE]   = "aarch64_be",
    [LIBTCG_ARCH_AARCH64]      = "aarch64",
    [LIBTCG_ARCH_ALPHA]        = "alpha",
    [LIBTCG_ARCH_ARMEB]        = "armeb",
    [LIBTCG_ARCH_ARM]          = "arm",
    [LIBTCG_ARCH_CRIS]         = "cris",
    [LIBTCG_ARCH_HEXAGON]      = "hexagon",
    [LIBTCG_ARCH_HPPA]         = "hppa",
    [LIBTCG_ARCH_I386]         = "i386",
    [LIBTCG_ARCH_LOONGARCH64]  = "loongarch64",
    [LIBTCG_ARCH_M68K]         = "m68k",
    [LIBTCG_ARCH_MICROBLAZEEL] = "microblazeel",
    [LIBTCG_ARCH_MICROBLAZE]   = "microblaze",
    [LIBTCG_ARCH_MIPS64EL]     = "mips64el",
    [LIBTCG_ARCH_MIPS64]       = "mips64",
    [LIBTCG_ARCH_MIPSEL]       = "mipsel",
    [LIBTCG_ARCH_MIPS]         = "mipsn32el",
    [LIBTCG_ARCH_MIPSN32EL]    = "mipsn32",
    [LIBTCG_ARCH_MIPSN32]      = "mips",
    [LIBTCG_ARCH_NIOS2]        = "nios2",
    [LIBTCG_ARCH_OR1K]         = "or1k",
    [LIBTCG_ARCH_PPC64LE]      = "ppc64le",
    [LIBTCG_ARCH_PPC64]        = "ppc64",
    [LIBTCG_ARCH_PPC]          = "ppc",
    [LIBTCG_ARCH_RISCV32]      = "riscv32",
    [LIBTCG_ARCH_RISCV64]      = "riscv64",
    [LIBTCG_ARCH_S390X]        = "s390x",
    [LIBTCG_ARCH_SH4EB]        = "sh4eb",
    [LIBTCG_ARCH_SH4]          = "sh4",
    [LIBTCG_ARCH_SPARC32PLUS]  = "sparc32plus",
    [LIBTCG_ARCH_SPARC64]      = "sparc64",
    [LIBTCG_ARCH_SPARC]        = "sparc",
    [LIBTCG_ARCH_X86_64]       = "x86_64",
    [LIBTCG_ARCH_XTENSAEB]     = "xtensaeb",
    [LIBTCG_ARCH_XTENSA]       = "xtensa",
};

const char *libtcg_arch_name(LibTcgArch arch) {
    return arch_names[arch];
}

const char *libtcg_arch_file(LibTcgArch arch) {
    static char buf[64] = {0};
    const char *name = arch_names[arch];
    snprintf(buf, ARRLEN(buf)-1, "libtcg-%s.so", name);
    return buf;
}

LibTcgArch libtcg_arch_from_str(const char *str) {
    for (int i = 0; i < ARRLEN(arch_names); ++i) {
        if (i == LIBTCG_ARCH_NONE) {
            continue;
        }
        if (strcmp(arch_names[i], str) == 0) {
            return i;
        }
    }
    return LIBTCG_ARCH_NONE;
}

void libtcg_open(LibTcgArch arch,
                 LibTcgDesc *desc,
                 LibTcgInterface *libtcg,
                 LibTcgContext **context) {
    if (arch == LIBTCG_ARCH_NONE) {
        fprintf(stderr, "[error]: libtcg invalid architecture \"%d\"", arch);
        return;
    }

    LibTcgLibraryInfo *info = &library_info[arch];
    if (info->handle != NULL) {
        *libtcg = info->libtcg;
        *context = info->context;
        return;
    }

    const char *arch_file = libtcg_arch_file(arch);
    void *handle = dlopen(arch_file, RTLD_LAZY);
    if (handle == NULL) {
        fprintf(stderr, "[error]: libtcg failed to dlopen \"%s\"", arch_file);
        return;
    }

    LIBTCG_FUNC_TYPE(libtcg_load) *libtcg_load = dlsym(handle, "libtcg_load");
    *libtcg = libtcg_load();
    *context = libtcg->context_create(desc);

    info->handle = handle;
    info->libtcg = *libtcg;
    info->context = *context;
}

void libtcg_close(LibTcgArch arch) {
    if (arch == LIBTCG_ARCH_NONE) {
        fprintf(stderr, "[error]: libtcg invalid architecture \"%d\"", arch);
        return;
    }

    LibTcgLibraryInfo *info = &library_info[arch];
    if (info->handle != NULL) {
        info->libtcg.context_destroy(info->context);
        dlclose(info->handle);
    }
}

void libtcg_close_all(void) {
    for (int i = 0; i < LIBTCG_ARCH_COUNT; ++i) {
        if (i == LIBTCG_ARCH_NONE) {
            continue;
        }
        libtcg_close(i);
    }
}
