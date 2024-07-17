#ifndef LIBTCG_LOADER_H
#define LIBTCG_LOADER_H

typedef enum LibTcgArch {
    LIBTCG_ARCH_NONE = 0,
    LIBTCG_ARCH_AARCH64_BE,
    LIBTCG_ARCH_AARCH64,
    LIBTCG_ARCH_ALPHA,
    LIBTCG_ARCH_ARMEB,
    LIBTCG_ARCH_ARM,
    LIBTCG_ARCH_CRIS,
    LIBTCG_ARCH_HEXAGON,
    LIBTCG_ARCH_HPPA,
    LIBTCG_ARCH_I386,
    LIBTCG_ARCH_LOONGARCH64,
    LIBTCG_ARCH_M68K,
    LIBTCG_ARCH_MICROBLAZEEL,
    LIBTCG_ARCH_MICROBLAZE,
    LIBTCG_ARCH_MIPS64EL,
    LIBTCG_ARCH_MIPS64,
    LIBTCG_ARCH_MIPSEL,
    LIBTCG_ARCH_MIPS,
    LIBTCG_ARCH_MIPSN32EL,
    LIBTCG_ARCH_MIPSN32,
    LIBTCG_ARCH_NIOS2,
    LIBTCG_ARCH_OR1K,
    LIBTCG_ARCH_PPC64LE,
    LIBTCG_ARCH_PPC64,
    LIBTCG_ARCH_PPC,
    LIBTCG_ARCH_RISCV32,
    LIBTCG_ARCH_RISCV64,
    LIBTCG_ARCH_S390X,
    LIBTCG_ARCH_SH4EB,
    LIBTCG_ARCH_SH4,
    LIBTCG_ARCH_SPARC32PLUS,
    LIBTCG_ARCH_SPARC64,
    LIBTCG_ARCH_SPARC,
    LIBTCG_ARCH_X86_64,
    LIBTCG_ARCH_XTENSAEB,
    LIBTCG_ARCH_XTENSA,
    LIBTCG_ARCH_COUNT,
} LibTcgArch;

const char *libtcg_arch_name(LibTcgArch arch);
const char *libtcg_arch_file(LibTcgArch arch);
LibTcgArch libtcg_arch_from_str(const char *str);

typedef struct LibTcgContext LibTcgContext;
typedef struct LibTcgInterface LibTcgInterface;
typedef struct LibTcgDesc LibTcgDesc;

/*
 * For a given LibTcgArch , return the LibTcgInterface into litcg , and
 * create and return a LibTcgContext if needed .
 */
void libtcg_open(LibTcgArch arch,
                 LibTcgDesc *desc,
                 LibTcgInterface *libtcg,
                 LibTcgContext **context);

/* Close a given libtcg library */
void libtcg_close(LibTcgArch arch);
/* Close all open libtcg libraries */
void libtcg_close_all(void);

#endif /* LIBTCG_LOADER_H */
