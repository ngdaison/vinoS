#ifndef KOS_ELF_H
#define KOS_ELF_H

#include <stdbool.h>
#include <stdint.h>

/* Standard ELF data types */
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef int32_t  Elf64_Sword;
typedef uint64_t Elf64_Xword;
typedef int64_t  Elf64_Sxword;

/* ELF Identification constants */
#define EI_MAG0         0
#define EI_MAG1         1
#define EI_MAG2         2
#define EI_MAG3         3
#define EI_CLASS        4
#define EI_DATA         5
#define EI_VERSION      6
#define EI_OSABI        7
#define EI_ABIVERSION   8
#define EI_PAD          9
#define EI_NIDENT       16

#define ELFMAG0         0x7f
#define ELFMAG1         'E'
#define ELFMAG2         'L'
#define ELFMAG3         'F'

#define ELFCLASSNONE    0
#define ELFCLASS32      1
#define ELFCLASS64      2

#define ELFDATANONE     0
#define ELFDATA2LSB     1
#define ELFDATA2MSB     2

#define EV_NONE         0
#define EV_CURRENT      1

/* ELF Object File Types */
#define ET_NONE         0
#define ET_REL          1
#define ET_EXEC         2
#define ET_DYN          3
#define ET_CORE         4

/* ELF Target Architecture Machines */
#define EM_NONE         0
#define EM_386          3
#define EM_X86_64       62

/* ELF Segment Types */
#define PT_NULL         0
#define PT_LOAD         1
#define PT_DYNAMIC      2
#define PT_INTERP       3
#define PT_NOTE         4
#define PT_SHLIB        5
#define PT_PHDR         6
#define PT_TLS          7
#define PT_GNU_EH_FRAME 0x6474e550
#define PT_GNU_STACK    0x6474e551
#define PT_GNU_RELRO    0x6474e552

/* ELF Segment Flags */
#define PF_X            (1u << 0)
#define PF_W            (1u << 1)
#define PF_R            (1u << 2)
#define PF_MASKOS       0x0ff00000
#define PF_MASKPROC     0xf0000000

/* Standard ELF64 File Header */
typedef struct {
    unsigned char e_ident[EI_NIDENT];
    Elf64_Half    e_type;
    Elf64_Half    e_machine;
    Elf64_Word    e_version;
    Elf64_Addr    e_entry;
    Elf64_Off     e_phoff;
    Elf64_Off     e_shoff;
    Elf64_Word    e_flags;
    Elf64_Half    e_ehsize;
    Elf64_Half    e_phentsize;
    Elf64_Half    e_phnum;
    Elf64_Half    e_shentsize;
    Elf64_Half    e_shnum;
    Elf64_Half    e_shstrndx;
} Elf64_Ehdr;

/* Standard ELF64 Program (Segment) Header */
typedef struct {
    Elf64_Word    p_type;
    Elf64_Word    p_flags;
    Elf64_Off     p_offset;
    Elf64_Addr    p_vaddr;
    Elf64_Addr    p_paddr;
    Elf64_Xword   p_filesz;
    Elf64_Xword   p_memsz;
    Elf64_Xword   p_align;
} Elf64_Phdr;

_Static_assert(sizeof(Elf64_Ehdr) == 64, "Elf64_Ehdr size must be 64 bytes");
_Static_assert(sizeof(Elf64_Phdr) == 56, "Elf64_Phdr size must be 56 bytes");

/* Loaded binary representation for userspace execution */
struct elf_binary_image {
    uint64_t entry_point;
    uint64_t user_stack_top;
    uint64_t user_stack_bottom;
    uint64_t user_rsp;
};

struct elf_image_info {
    uint64_t entry_point;
    uint16_t program_header_count;
    uint16_t loadable_segment_count;
};

/* User stack parameters */
#define USER_STACK_TOP        0x00007FFFFFFFE000ull
#define USER_STACK_SIZE       (64 * 1024ull) /* 64 KiB = 16 pages */
#define USER_STACK_BOTTOM     (USER_STACK_TOP - USER_STACK_SIZE) /* 0x00007FFFFFFEE000ull */
#define USER_STACK_GUARD_PAGE (USER_STACK_BOTTOM - 4096ull)      /* 0x00007FFFFFFED000ull */

bool elf_inspect_image(const uint8_t *image, uint64_t image_size, struct elf_image_info *info);
bool elf_load_binary(const char *path, uint64_t pml4_phys, struct elf_binary_image *out_image);
bool process_setup_user_stack(uint64_t pml4_phys, int argc, char *const argv[], uint64_t *out_user_rsp);
bool elf_self_test(void);

#endif
