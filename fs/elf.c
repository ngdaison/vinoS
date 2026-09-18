#include <stdbool.h>
#include <stdint.h>

#include <kos/elf.h>
#include <kos/log.h>
#include <kos/memory.h>
#include <kos/pmm.h>
#include <kos/vfs.h>
#include <kos/vmm.h>

void *memset(void *destination, int value, uint64_t size);
void *memcpy(void *destination, const void *source, uint64_t size);
int memcmp(const void *left, const void *right, uint64_t size);

static uint64_t str_len(const char *str) {
    uint64_t len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}

static uint16_t read_u16(const uint8_t *address) {
    return (uint16_t)address[0] | ((uint16_t)address[1] << 8);
}

static uint32_t read_u32(const uint8_t *address) {
    return (uint32_t)address[0] | ((uint32_t)address[1] << 8) | ((uint32_t)address[2] << 16)
        | ((uint32_t)address[3] << 24);
}

static uint64_t read_u64(const uint8_t *address) {
    uint64_t value = 0;
    for (uint64_t index = 0; index < 8; ++index) {
        value |= (uint64_t)address[index] << (index * 8);
    }
    return value;
}

static bool range_is_valid(uint64_t offset, uint64_t length, uint64_t total_size) {
    return offset <= total_size && length <= total_size - offset;
}

static bool is_power_of_two(uint64_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

static bool stack_write_bytes(uint64_t *stack_frames, uint64_t user_vaddr, const void *src, uint64_t len) {
    if (user_vaddr < USER_STACK_BOTTOM || user_vaddr + len > USER_STACK_TOP) {
        return false;
    }
    const uint8_t *src_bytes = (const uint8_t *)src;
    while (len > 0) {
        uint64_t page_idx = (user_vaddr - USER_STACK_BOTTOM) / KOS_PAGE_SIZE;
        uint64_t page_off = (user_vaddr - USER_STACK_BOTTOM) % KOS_PAGE_SIZE;
        uint64_t chunk = KOS_PAGE_SIZE - page_off;
        if (chunk > len) {
            chunk = len;
        }
        uint8_t *dest = (uint8_t *)vmm_physical_to_virtual(stack_frames[page_idx]) + page_off;
        memcpy(dest, src_bytes, chunk);
        user_vaddr += chunk;
        src_bytes += chunk;
        len -= chunk;
    }
    return true;
}

bool process_setup_user_stack(uint64_t pml4_phys, int argc, char *const argv[], uint64_t *out_user_rsp) {
    if (pml4_phys == 0 || (pml4_phys % KOS_PAGE_SIZE) != 0 || out_user_rsp == 0) {
        return false;
    }
    if (argc < 0 || argc > 64) {
        return false;
    }
    if (argc > 0 && argv == 0) {
        return false;
    }

    /* Ensure guard page directly beneath stack bottom is strictly unmapped */
    if (vmm_query_page_in(pml4_phys, USER_STACK_GUARD_PAGE, 0, 0)) {
        vmm_unmap_page_in(pml4_phys, USER_STACK_GUARD_PAGE);
    }

    /* Map 16 user stack pages (64 KiB) ending at USER_STACK_TOP */
    uint64_t stack_frames[16];
    bool newly_allocated[16];
    for (uint64_t i = 0; i < 16; ++i) {
        newly_allocated[i] = false;
    }

    for (uint64_t i = 0; i < 16; ++i) {
        uint64_t page_vaddr = USER_STACK_BOTTOM + i * KOS_PAGE_SIZE;
        uint64_t frame = 0;
        if (vmm_query_page_in(pml4_phys, page_vaddr, &frame, 0)) {
            stack_frames[i] = frame;
        } else {
            frame = pmm_allocate_frame();
            if (frame == 0) {
                goto unwind_stack;
            }
            if (!vmm_map_page_in(pml4_phys, page_vaddr, frame,
                    VMM_PAGE_USER | VMM_PAGE_WRITABLE | VMM_PAGE_NO_EXECUTE)) {
                pmm_free_frame(frame);
                goto unwind_stack;
            }
            stack_frames[i] = frame;
            newly_allocated[i] = true;
        }
        memset(vmm_physical_to_virtual(stack_frames[i]), 0, KOS_PAGE_SIZE);
    }

    /* Validate argv strings and compute total length */
    uint64_t total_str_bytes = 0;
    for (int i = 0; i < argc; ++i) {
        if (argv[i] == 0) {
            goto unwind_stack;
        }
        uint64_t slen = str_len(argv[i]);
        if (slen > 4096) {
            goto unwind_stack;
        }
        total_str_bytes += slen + 1;
    }

    /*
     * System V AMD64 ABI initial stack layout:
     * High address (USER_STACK_TOP):
     *   - argv string data
     * Lower address (down to %rsp):
     *   - padding to ensure %rsp % 16 == 0
     *   - auxv[0]: a_type = AT_NULL (0), a_val = 0
     *   - envp[0] = NULL
     *   - argv[argc] = NULL
     *   - argv[argc-1] .. argv[0]
     *   - argc
     */
    uint64_t table_quadwords = 1 + (uint64_t)argc + 1 + 1 + 2;
    uint64_t table_bytes = table_quadwords * sizeof(uint64_t);

    if (total_str_bytes + table_bytes + 64 > USER_STACK_SIZE) {
        goto unwind_stack;
    }

    uint64_t curr_sp = USER_STACK_TOP;
    uint64_t argv_ptrs[64];
    for (int i = 0; i < argc; ++i) {
        uint64_t slen = str_len(argv[i]) + 1;
        curr_sp -= slen;
        if (!stack_write_bytes(stack_frames, curr_sp, argv[i], slen)) {
            goto unwind_stack;
        }
        argv_ptrs[i] = curr_sp;
    }

    if (curr_sp < table_bytes) {
        goto unwind_stack;
    }
    uint64_t target_rsp = (curr_sp - table_bytes) & ~0xFull;
    if (target_rsp < USER_STACK_BOTTOM) {
        goto unwind_stack;
    }

    uint64_t table[72];
    table[0] = (uint64_t)argc;
    for (int i = 0; i < argc; ++i) {
        table[1 + i] = argv_ptrs[i];
    }
    table[1 + argc] = 0; /* argv NULL terminator */
    table[2 + argc] = 0; /* envp NULL terminator (envp[0] = NULL) */
    table[3 + argc] = 0; /* auxv[0].a_type = AT_NULL */
    table[4 + argc] = 0; /* auxv[0].a_val = 0 */

    if (!stack_write_bytes(stack_frames, target_rsp, table, table_bytes)) {
        goto unwind_stack;
    }

    *out_user_rsp = target_rsp;
    return true;

unwind_stack:
    for (uint64_t i = 0; i < 16; ++i) {
        if (newly_allocated[i]) {
            vmm_unmap_page_in(pml4_phys, USER_STACK_BOTTOM + i * KOS_PAGE_SIZE);
            pmm_free_frame(stack_frames[i]);
        }
    }
    return false;
}

bool elf_load_binary(const char *path, uint64_t pml4_phys, struct elf_binary_image *out_image) {
    if (path == 0 || pml4_phys == 0 || (pml4_phys % KOS_PAGE_SIZE) != 0) {
        return false;
    }

    const uint8_t *data = 0;
    uint64_t file_size = 0;
    if (!vfs_read_file(path, &data, &file_size) || data == 0 || file_size < sizeof(Elf64_Ehdr)) {
        return false;
    }

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data;

    /* Strict verification of ELF64 header fields */
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 || ehdr->e_ident[EI_MAG1] != ELFMAG1
        || ehdr->e_ident[EI_MAG2] != ELFMAG2 || ehdr->e_ident[EI_MAG3] != ELFMAG3
        || ehdr->e_ident[EI_CLASS] != ELFCLASS64
        || ehdr->e_ident[EI_DATA] != ELFDATA2LSB
        || ehdr->e_ident[EI_VERSION] != EV_CURRENT
        || ehdr->e_type != ET_EXEC
        || ehdr->e_machine != EM_X86_64
        || ehdr->e_version != EV_CURRENT
        || ehdr->e_ehsize != sizeof(Elf64_Ehdr)
        || ehdr->e_phentsize != sizeof(Elf64_Phdr)
        || ehdr->e_phnum == 0 || ehdr->e_phnum > 64) {
        return false;
    }

    /* Program header table boundary check */
    uint64_t ph_table_bytes = (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr);
    if (!range_is_valid(ehdr->e_phoff, ph_table_bytes, file_size)) {
        return false;
    }

    /* Entry point must be in canonical user space and >= 2 MiB */
    if (ehdr->e_entry < 0x00200000ull || ehdr->e_entry >= 0x0000800000000000ull) {
        return false;
    }

    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(data + ehdr->e_phoff);
    uint32_t loadable_count = 0;
    const Elf64_Phdr *loadable[64];

    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
        const Elf64_Phdr *phdr = &phdrs[i];
        if (phdr->p_type == PT_INTERP) {
            /* Dynamic shared library interpreter not supported for static binaries */
            return false;
        }
        if (phdr->p_type == PT_LOAD) {
            if (phdr->p_memsz < phdr->p_filesz) {
                return false;
            }
            if (!range_is_valid(phdr->p_offset, phdr->p_filesz, file_size)) {
                return false;
            }
            if (phdr->p_vaddr < 0x00200000ull) {
                return false;
            }
            if (phdr->p_memsz > 0) {
                uint64_t end_va = phdr->p_vaddr + phdr->p_memsz;
                if (end_va < phdr->p_vaddr || end_va >= 0x0000800000000000ull) {
                    return false;
                }
            }
            if (phdr->p_align > 1) {
                if (!is_power_of_two(phdr->p_align)
                    || (phdr->p_vaddr % phdr->p_align) != (phdr->p_offset % phdr->p_align)) {
                    return false;
                }
            }
            loadable[loadable_count++] = phdr;
        }
    }

    if (loadable_count == 0) {
        return false;
    }

    /* Verify non-overlapping PT_LOAD segments */
    for (uint32_t i = 0; i < loadable_count; ++i) {
        uint64_t start_i = loadable[i]->p_vaddr;
        uint64_t end_i = loadable[i]->p_vaddr + loadable[i]->p_memsz;
        for (uint32_t j = i + 1; j < loadable_count; ++j) {
            uint64_t start_j = loadable[j]->p_vaddr;
            uint64_t end_j = loadable[j]->p_vaddr + loadable[j]->p_memsz;
            uint64_t max_start = start_i > start_j ? start_i : start_j;
            uint64_t min_end = end_i < end_j ? end_i : end_j;
            if (max_start < min_end) {
                return false;
            }
        }
    }

    /* Verify entry point resides within an executable PT_LOAD segment */
    bool entry_valid = false;
    for (uint32_t i = 0; i < loadable_count; ++i) {
        if ((loadable[i]->p_flags & PF_X) != 0
            && ehdr->e_entry >= loadable[i]->p_vaddr
            && ehdr->e_entry < loadable[i]->p_vaddr + loadable[i]->p_memsz) {
            entry_valid = true;
            break;
        }
    }
    if (!entry_valid) {
        return false;
    }

    /* Map and populate all PT_LOAD segments */
    for (uint32_t i = 0; i < loadable_count; ++i) {
        const Elf64_Phdr *phdr = loadable[i];
        if (phdr->p_memsz == 0) {
            continue;
        }

        uint64_t vmm_flags = VMM_PAGE_USER;
        if ((phdr->p_flags & PF_W) != 0) {
            vmm_flags |= VMM_PAGE_WRITABLE;
        }
        if ((phdr->p_flags & PF_X) == 0) {
            vmm_flags |= VMM_PAGE_NO_EXECUTE;
        }

        uint64_t seg_start_va = phdr->p_vaddr & ~(KOS_PAGE_SIZE - 1);
        uint64_t seg_end_va = (phdr->p_vaddr + phdr->p_memsz + KOS_PAGE_SIZE - 1) & ~(KOS_PAGE_SIZE - 1);

        for (uint64_t va = seg_start_va; va < seg_end_va; va += KOS_PAGE_SIZE) {
            uint64_t frame = 0;
            if (vmm_query_page_in(pml4_phys, va, &frame, 0)) {
                /* Page already mapped in target address space */
            } else {
                frame = pmm_allocate_frame();
                if (frame == 0) {
                    goto load_error;
                }
                if (!vmm_map_page_in(pml4_phys, va, frame, vmm_flags)) {
                    pmm_free_frame(frame);
                    goto load_error;
                }
                memset(vmm_physical_to_virtual(frame), 0, KOS_PAGE_SIZE);
            }

            /* Copy intersecting segment file content */
            uint64_t file_start = phdr->p_vaddr;
            uint64_t file_end = phdr->p_vaddr + phdr->p_filesz;
            uint64_t page_start = va;
            uint64_t page_end = va + KOS_PAGE_SIZE;
            uint64_t isect_start = file_start > page_start ? file_start : page_start;
            uint64_t isect_end = file_end < page_end ? file_end : page_end;

            if (isect_start < isect_end) {
                uint64_t copy_len = isect_end - isect_start;
                uint64_t dest_off = isect_start - page_start;
                uint64_t src_off = phdr->p_offset + (isect_start - file_start);
                uint8_t *dest = (uint8_t *)vmm_physical_to_virtual(frame) + dest_off;
                memcpy(dest, data + src_off, copy_len);
            }
        }
    }

    /* Initialize user stack */
    uint64_t default_user_rsp = 0;
    if (!process_setup_user_stack(pml4_phys, 0, 0, &default_user_rsp)) {
        goto load_error;
    }

    if (out_image != 0) {
        out_image->entry_point = ehdr->e_entry;
        out_image->user_stack_top = USER_STACK_TOP;
        out_image->user_stack_bottom = USER_STACK_BOTTOM;
        out_image->user_rsp = default_user_rsp;
    }

    return true;

load_error:
    vmm_clear_user_address_space(pml4_phys);
    return false;
}

bool elf_inspect_image(const uint8_t *image, uint64_t image_size, struct elf_image_info *info) {
    if (image == 0 || info == 0 || image_size < sizeof(Elf64_Ehdr) || image[0] != ELFMAG0
        || image[1] != ELFMAG1 || image[2] != ELFMAG2 || image[3] != ELFMAG3
        || image[4] != ELFCLASS64 || image[5] != ELFDATA2LSB || image[6] != EV_CURRENT
        || (read_u16(image + 16) != ET_EXEC && read_u16(image + 16) != ET_DYN)
        || read_u16(image + 18) != EM_X86_64 || read_u32(image + 20) != EV_CURRENT) {
        return false;
    }
    uint64_t program_header_offset = read_u64(image + 32);
    uint16_t program_header_size = read_u16(image + 54);
    uint16_t program_header_count = read_u16(image + 56);
    if (program_header_size < sizeof(Elf64_Phdr) || program_header_count == 0
        || !range_is_valid(program_header_offset,
            (uint64_t)program_header_count * (uint64_t)program_header_size, image_size)) {
        return false;
    }
    uint16_t loadable_segments = 0;
    for (uint16_t index = 0; index < program_header_count; ++index) {
        const uint8_t *program_header = image + program_header_offset + (uint64_t)index * program_header_size;
        if (read_u32(program_header) == PT_LOAD) {
            uint64_t file_offset = read_u64(program_header + 8);
            uint64_t file_size = read_u64(program_header + 32);
            uint64_t memory_size = read_u64(program_header + 40);
            uint64_t alignment = read_u64(program_header + 48);
            if (memory_size < file_size || !range_is_valid(file_offset, file_size, image_size)
                || (alignment != 0 && !is_power_of_two(alignment))) {
                return false;
            }
            ++loadable_segments;
        }
    }
    if (loadable_segments == 0) {
        return false;
    }
    *info = (struct elf_image_info){
        .entry_point = read_u64(image + 24),
        .program_header_count = program_header_count,
        .loadable_segment_count = loadable_segments,
    };
    return true;
}

bool elf_self_test(void) {
    /* 1. Validate rejection of bad ELF image */
    uint8_t corrupt_hdr[64];
    memset(corrupt_hdr, 0, sizeof(corrupt_hdr));
    struct elf_image_info info;
    if (elf_inspect_image(corrupt_hdr, sizeof(corrupt_hdr), &info)) {
        return false;
    }

    /* 2. Validate rejection of bad arguments to elf_load_binary */
    if (elf_load_binary(0, 0, 0)) {
        return false;
    }

    /* 3. Validate user stack setup and ABI layout */
    uint64_t initial_free = pmm_free_frame_count();
    uint64_t test_pml4 = vmm_create_address_space();
    if (test_pml4 == 0) {
        return false;
    }

    char arg0[] = "test_bin";
    char arg1[] = "param1";
    char *test_argv[] = { arg0, arg1 };
    uint64_t user_rsp = 0;
    if (!process_setup_user_stack(test_pml4, 2, test_argv, &user_rsp)) {
        vmm_destroy_address_space(test_pml4);
        return false;
    }

    /* Verify 16-byte alignment of initial RSP */
    if ((user_rsp & 0xFull) != 0) {
        vmm_destroy_address_space(test_pml4);
        return false;
    }

    /* Verify guard page is unmapped */
    if (vmm_query_page_in(test_pml4, USER_STACK_GUARD_PAGE, 0, 0)) {
        vmm_destroy_address_space(test_pml4);
        return false;
    }

    /* Verify stack pages are mapped with user permissions */
    uint64_t q_phys = 0;
    uint64_t q_flags = 0;
    if (!vmm_query_page_in(test_pml4, USER_STACK_TOP - KOS_PAGE_SIZE, &q_phys, &q_flags)) {
        vmm_destroy_address_space(test_pml4);
        return false;
    }
    if ((q_flags & VMM_PAGE_USER) == 0 || (q_flags & VMM_PAGE_WRITABLE) == 0) {
        vmm_destroy_address_space(test_pml4);
        return false;
    }

    /* Destroy test address space and verify zero frame leaks */
    vmm_destroy_address_space(test_pml4);
    uint64_t final_free = pmm_free_frame_count();
    if (final_free != initial_free) {
        return false;
    }

    log_info("ELF loader & user stack self-test passed (0 frame leaks).");
    return true;
}
