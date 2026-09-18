/*
 * KOS host development tool.
 *
 * This is deliberately ordinary hosted C: it builds the freestanding KOS
 * kernel, prepares its UEFI ESP, bootstraps dependencies, and starts QEMU.
 * Run it from the repository root on Windows.
 */
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COMMAND_CAPACITY 16384
#define PATH_CAPACITY MAX_PATH
#define ARRAY_COUNT(items) (sizeof(items) / sizeof((items)[0]))

static const char *const c_sources[] = {
    "boot/limine_requests.c", "arch/x86_64/acpi.c", "arch/x86_64/apic.c", "arch/x86_64/cpu_control.c",
    "arch/x86_64/descriptors.c", "arch/x86_64/interrupts.c", "arch/x86_64/ioapic.c", "arch/x86_64/pci.c",
    "arch/x86_64/pic.c", "arch/x86_64/security.c", "arch/x86_64/smp.c", "arch/x86_64/syscall_init.c",
    "drivers/ahci.c", "drivers/block.c", "drivers/driver.c", "drivers/e1000.c", "drivers/framebuffer.c",
    "drivers/keyboard.c", "drivers/nvme.c", "drivers/ramdisk.c", "drivers/serial.c", "drivers/timer.c",
    "drivers/virtio_blk.c", "drivers/usb/xhci.c", "drivers/usb/usb_hid.c",
    "fs/block_cache.c", "fs/elf.c", "fs/fat32.c", "fs/initramfs.c", "fs/partition.c", "fs/ramfs.c", "fs/vfs.c", "fs/volume.c",
    "kernel/command.c", "kernel/console.c", "kernel/log.c", "kernel/main.c", "kernel/mutex.c",
    "kernel/panic.c", "kernel/spinlock.c", "kernel/symbol.c", "kernel/syscall.c", "kernel/system.c",
    "kernel/process.c", "kernel/task.c", "kernel/object.c", "kernel/handle.c", "kernel/uaccess.c", "kernel/wait.c",
    "lib/asn1.c", "lib/crypto.c", "lib/kpkg.c", "lib/memory.c", "lib/x509.c",
    "kernel/pkg_db.c", "kernel/installer.c",
    "kernel/qa_framework.c", "kernel/qa_fuzz.c", "kernel/qa_stress.c", "kernel/fault_injection.c",
    "net/arp.c", "net/dhcp.c", "net/dns.c", "net/ethernet.c", "net/http.c", "net/httpd.c", "net/icmp.c",
    "net/ipv4.c", "net/net_device.c", "net/socket.c", "net/socket_subsystem.c", "net/tcp.c", "net/tls.c",
    "kernel/terminal.c", "mm/heap.c", "mm/pmm.c", "mm/vmm.c",
};

static const char *const asm_sources[] = {
    "boot/entry.asm", "arch/x86_64/cpu.asm", "arch/x86_64/interrupt_stubs.asm",
    "arch/x86_64/syscall_entry.asm", "arch/x86_64/task_switch.asm",
};

static int fail(const char *message) {
    fprintf(stderr, "KOS tool error: %s\n", message);
    return 1;
}

static bool file_exists(const char *path) {
    DWORD attributes = GetFileAttributesA(path);
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

static bool directory_exists(const char *path) {
    DWORD attributes = GetFileAttributesA(path);
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY);
}

static bool ensure_directory(const char *path) {
    if (directory_exists(path)) {
        return true;
    }
    if (CreateDirectoryA(path, NULL)) {
        return true;
    }
    fprintf(stderr, "Cannot create directory: %s (error %lu)\n", path, GetLastError());
    return false;
}

static bool ensure_directories(void) {
    return ensure_directory("build") && ensure_directory("build/obj") &&
           ensure_directory("build/esp") && ensure_directory("build/esp/EFI") &&
           ensure_directory("build/esp/EFI/BOOT") && ensure_directory("build/esp/boot") &&
           ensure_directory("third_party") && ensure_directory("third_party/tools");
}

static int execute(const char *command) {
    int status;
    printf("+ %s\n", command);
    status = system(command);
    if (status != 0) {
        fprintf(stderr, "Command failed with status %d.\n", status);
        return 1;
    }
    return 0;
}

static int execute_format(const char *format, ...) {
    char command[COMMAND_CAPACITY];
    va_list arguments;
    int written;
    va_start(arguments, format);
    written = vsnprintf(command, sizeof(command), format, arguments);
    va_end(arguments);
    if (written < 0 || (size_t)written >= sizeof(command)) {
        return fail("host command exceeds the command buffer");
    }
    return execute(command);
}

static bool command_exists(const char *name) {
    char command[256];
    int written = snprintf(command, sizeof(command), "where %s >nul 2>nul", name);
    return written > 0 && (size_t)written < sizeof(command) && system(command) == 0;
}

static const char *nasm_command(void) {
    if (file_exists("third_party/tools/nasm-3.02/nasm.exe")) {
        return "third_party\\tools\\nasm-3.02\\nasm.exe";
    }
    return "nasm";
}

static const char *clang_command(void) {
    if (file_exists("C:/Program Files/LLVM/bin/clang.exe")) {
        return "C:/Program Files/LLVM/bin/clang.exe";
    }
    return "clang";
}

static const char *lld_command(void) {
    if (file_exists("C:/Program Files/LLVM/bin/ld.lld.exe")) {
        return "C:/Program Files/LLVM/bin/ld.lld.exe";
    }
    return "ld.lld";
}


static const char *nm_command(void) {
    if (file_exists("C:/Program Files/LLVM/bin/llvm-nm.exe")) {
        return "C:/Program Files/LLVM/bin/llvm-nm.exe";
    }
    return "llvm-nm";
}

static const char *qemu_command(void) {
    if (file_exists("C:/Program Files/qemu/qemu-system-x86_64.exe")) {
        return "C:/Program Files/qemu/qemu-system-x86_64.exe";
    }
    return "qemu-system-x86_64";
}

static void object_path(const char *source, char *output, size_t output_size) {
    size_t index;
    int written = snprintf(output, output_size, "build/obj/%s", source);
    if (written < 0 || (size_t)written >= output_size) {
        output[0] = '\0';
        return;
    }
    for (index = strlen("build/obj/"); output[index] != '\0'; ++index) {
        if (output[index] == '/' || output[index] == '\\') {
            output[index] = '_';
        }
    }
    {
        char *extension = strrchr(output, '.');
        if (extension != NULL) {
            strcpy_s(extension, output_size - (size_t)(extension - output), ".o");
        }
    }
}

static bool copy_file(const char *source, const char *destination) {
    if (!CopyFileA(source, destination, FALSE)) {
        fprintf(stderr, "Cannot copy %s to %s (error %lu)\n", source, destination, GetLastError());
        return false;
    }
    return true;
}

static bool read_file(const char *path, unsigned char **contents, size_t *size) {
    FILE *file;
    long length;
    unsigned char *buffer;
    if (fopen_s(&file, path, "rb") != 0 || file == NULL) {
        fprintf(stderr, "Cannot open %s\n", path);
        return false;
    }
    if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return false;
    }
    buffer = malloc((size_t)length + 1U);
    if (buffer == NULL || fread(buffer, 1, (size_t)length, file) != (size_t)length) {
        free(buffer);
        fclose(file);
        return false;
    }
    fclose(file);
    *contents = buffer;
    *size = (size_t)length;
    return true;
}

static bool cpio_padding(FILE *archive, size_t *offset) {
    static const unsigned char zeroes[4] = {0, 0, 0, 0};
    size_t amount = (4U - (*offset % 4U)) % 4U;
    if (amount != 0U && fwrite(zeroes, 1, amount, archive) != amount) {
        return false;
    }
    *offset += amount;
    return true;
}

static bool cpio_entry(FILE *archive, size_t *offset, const char *name,
                       const unsigned char *contents, size_t contents_size, unsigned int mode) {
    char header[111];
    size_t name_size = strlen(name) + 1U;
    int length = snprintf(header, sizeof(header),
        "070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
        1U, mode, 0U, 0U, 1U, 0U, (unsigned int)contents_size, 0U, 0U, 0U, 0U,
        (unsigned int)name_size, 0U);
    if (length != 110 || fwrite(header, 1, 110, archive) != 110 ||
        fwrite(name, 1, name_size, archive) != name_size) {
        return false;
    }
    *offset += 110U + name_size;
    if (!cpio_padding(archive, offset)) {
        return false;
    }
    if (contents_size != 0U && fwrite(contents, 1, contents_size, archive) != contents_size) {
        return false;
    }
    *offset += contents_size;
    return cpio_padding(archive, offset);
}

static int make_initramfs(void) {
    unsigned char *readme = NULL;
    unsigned char *kernel = NULL;
    size_t readme_size = 0;
    size_t kernel_size = 0;
    size_t offset = 0;
    FILE *archive;
    int result = 1;
    if (!read_file("assets/initramfs/README.TXT", &readme, &readme_size) ||
        !read_file("build/kos.elf", &kernel, &kernel_size)) {
        goto cleanup;
    }
    if (fopen_s(&archive, "build/initramfs.cpio", "wb") != 0 || archive == NULL) {
        goto cleanup;
    }
    if (!cpio_entry(archive, &offset, "README.TXT", readme, readme_size, 0100644U) ||
        !cpio_entry(archive, &offset, "KOS.ELF", kernel, kernel_size, 0100644U) ||
        !cpio_entry(archive, &offset, "TRAILER!!!", NULL, 0U, 0U)) {
        fclose(archive);
        goto cleanup;
    }
    fclose(archive);
    result = 0;
cleanup:
    free(readme);
    free(kernel);
    if (result != 0) {
        return fail("could not create build/initramfs.cpio");
    }
    return 0;
}

static int write_stub_symbols(const char *path) {
    FILE *file;
    if (fopen_s(&file, path, "w") != 0 || file == NULL) {
        return fail("cannot write stub symbol table");
    }
    fputs("/* Auto-generated stub symbol table by kos-tool */\n", file);
    fputs("#include <stdint.h>\n", file);
    fputs("#include <stddef.h>\n", file);
    fputs("#include <kos/symbol.h>\n\n", file);
    fputs("const struct kernel_symbol kernel_symbols[1] = {\n", file);
    fputs("    { 0, \"<none>\" }\n", file);
    fputs("};\n\n", file);
    fputs("const size_t kernel_symbol_count = 0;\n", file);
    fclose(file);
    return 0;
}

static int generate_symbol_table(const char *elf_path, const char *c_output_path, size_t *out_count) {
    char cmd[COMMAND_CAPACITY];
    char temp_map[PATH_CAPACITY];
    FILE *in = NULL;
    FILE *out = NULL;
    char line[512];
    unsigned long long prev_addr = 0;
    bool has_prev = false;
    size_t count = 0;

    snprintf(temp_map, sizeof(temp_map), "build/kernel_symbols.tmp");
    snprintf(cmd, sizeof(cmd), "call \"%s\" -n \"%s\" > \"%s\"", nm_command(), elf_path, temp_map);
    if (execute(cmd) != 0) {
        return fail("failed to extract symbols using llvm-nm");
    }

    if (fopen_s(&in, temp_map, "r") != 0 || in == NULL) {
        return fail("failed to open extracted symbol list");
    }

    if (fopen_s(&out, c_output_path, "w") != 0 || out == NULL) {
        fclose(in);
        return fail("failed to create symbol C source file");
    }

    fputs("/* Auto-generated by kos-tool. Do not edit. */\n", out);
    fputs("#include <stdint.h>\n", out);
    fputs("#include <stddef.h>\n", out);
    fputs("#include <kos/symbol.h>\n\n", out);
    fputs("const struct kernel_symbol kernel_symbols[] = {\n", out);

    while (fgets(line, sizeof(line), in) != NULL) {
        unsigned long long addr = 0;
        char type = '\0';
        char name[256];
        if (sscanf_s(line, "%llx %c %255s", &addr, &type, 1U, name, (unsigned int)sizeof(name)) == 3) {
            if (type == 'T' || type == 't') {
                /* Filter out section boundary markers */
                if (strcmp(name, "__kernel_text_start") == 0 ||
                    strcmp(name, "__kernel_text_end") == 0) {
                    continue;
                }
                /* Deduplicate identical consecutive addresses */
                if (has_prev && addr == prev_addr) {
                    continue;
                }
                fprintf(out, "    { 0x%016llxULL, \"%s\" },\n", addr, name);
                prev_addr = addr;
                has_prev = true;
                count++;
            }
        }
    }

    if (count == 0) {
        fputs("    { 0, \"<none>\" }\n", out);
    }
    fputs("};\n\n", out);
    fprintf(out, "const size_t kernel_symbol_count = sizeof(kernel_symbols) / sizeof(kernel_symbols[0]);\n");

    fclose(out);
    fclose(in);
    remove(temp_map);

    if (out_count != NULL) {
        *out_count = count;
    }
    return 0;
}

static int build_kernel(bool kernel_only, bool panic_test) {
    char object[PATH_CAPACITY];
    char link[COMMAND_CAPACITY];
    size_t index;
    int written;
    size_t symbol_count = 0;
    const char *panic_define = panic_test ? " -DKOS_PANIC_TEST" : "";
    const char *const flags =
        "--target=x86_64-unknown-none-elf -std=c17 -ffreestanding -fno-stack-protector "
        "-fno-pic -fno-pie -mno-red-zone -mcmodel=kernel -mno-mmx -mno-sse -mno-80387 "
        "-ffunction-sections -fdata-sections -fno-common -fno-asynchronous-unwind-tables "
        "-fno-unwind-tables -Wall -Wextra -Werror -O2 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer "
        "-g -I include -I third_party/limine-protocol/include -I third_party/font8x8";

    if (!file_exists("third_party/limine-protocol/include/limine.h")) {
        return fail("Limine protocol header is absent; run bootstrap-limine");
    }
    if (!file_exists("third_party/font8x8/font8x8_basic.h")) {
        return fail("font asset is absent; run bootstrap-assets");
    }
    if (!ensure_directories()) {
        return 1;
    }

    /* Compile all C sources */
    for (index = 0; index < ARRAY_COUNT(c_sources); ++index) {
        object_path(c_sources[index], object, sizeof(object));
        if (object[0] == '\0' || execute_format("call \"%s\" %s%s -c \"%s\" -o \"%s\"",
             clang_command(), flags, panic_define, c_sources[index], object) != 0) {
            return 1;
        }
    }

    /* Compile all Assembly sources */
    for (index = 0; index < ARRAY_COUNT(asm_sources); ++index) {
        object_path(asm_sources[index], object, sizeof(object));
        if (object[0] == '\0' || execute_format("call \"%s\" -f elf64 \"%s\" -o \"%s\"",
             nasm_command(), asm_sources[index], object) != 0) {
            return 1;
        }
    }

    /* Build linker command */
    written = snprintf(link, sizeof(link), "call \"%s\" -m elf_x86_64 -nostdlib -static -z max-page-size=0x1000 "
        "--gc-sections --build-id=none --fatal-warnings -T boot/linker.ld -o build/kos.elf", lld_command());
    if (written < 0 || (size_t)written >= sizeof(link)) {
        return fail("link command is too long");
    }
    for (index = 0; index < ARRAY_COUNT(c_sources) + ARRAY_COUNT(asm_sources); ++index) {
        const char *source = index < ARRAY_COUNT(c_sources) ? c_sources[index] : asm_sources[index - ARRAY_COUNT(c_sources)];
        object_path(source, object, sizeof(object));
        written += snprintf(link + written, sizeof(link) - (size_t)written, " \"%s\"", object);
        if (written < 0 || (size_t)written >= sizeof(link)) {
            return fail("link command is too long");
        }
    }
    written += snprintf(link + written, sizeof(link) - (size_t)written, " \"build/obj/kernel_symbols.o\"");
    if (written < 0 || (size_t)written >= sizeof(link)) {
        return fail("link command is too long");
    }

    /* PASS 1: Initialize stub symbols if build/kernel_symbols.c does not exist */
    if (!file_exists("build/kernel_symbols.c")) {
        if (write_stub_symbols("build/kernel_symbols.c") != 0) {
            return 1;
        }
    }

    /* Compile symbol table for Pass 1 */
    if (execute_format("call \"%s\" %s -c \"build/kernel_symbols.c\" -o \"build/obj/kernel_symbols.o\"",
         clang_command(), flags) != 0) {
        return 1;
    }

    /* Pass 1 Link: create intermediate ELF */
    if (execute(link) != 0 || !file_exists("build/kos.elf")) {
        return 1;
    }

    /* SYMBOL EXTRACTION: extract sorted symbols and generate build/kernel_symbols.c */
    if (generate_symbol_table("build/kos.elf", "build/kernel_symbols.c", &symbol_count) != 0) {
        return 1;
    }

    /* PASS 2: Recompile generated symbol table */
    if (execute_format("call \"%s\" %s -c \"build/kernel_symbols.c\" -o \"build/obj/kernel_symbols.o\"",
         clang_command(), flags) != 0) {
        return 1;
    }

    /* Pass 2 Final Link */
    if (execute(link) != 0 || !file_exists("build/kos.elf")) {
        return 1;
    }

    printf("Kernel ELF built with %zu embedded symbols: build/kos.elf\n", symbol_count);

    if (kernel_only) {
        return 0;
    }
    if (!file_exists("third_party/limine-binary/BOOTX64.EFI")) {
        return fail("Limine UEFI binary is absent; run bootstrap-limine");
    }
    if (make_initramfs() != 0 ||
        !copy_file("third_party/limine-binary/BOOTX64.EFI", "build/esp/EFI/BOOT/BOOTX64.EFI") ||
        !copy_file("boot/limine.conf", "build/esp/EFI/BOOT/limine.conf") ||
        !copy_file("build/kos.elf", "build/esp/boot/kos.elf") ||
        !copy_file("build/initramfs.cpio", "build/esp/boot/initramfs.cpio")) {
        return 1;
    }
    printf("UEFI ESP staged: build/esp\n");
    return 0;
}

static int check_environment(void) {
    int missing = 0;
    if (command_exists("git")) printf("[OK] git\n"); else { puts("[MISSING] git"); missing = 1; }
    if (command_exists("clang") || file_exists("C:/Program Files/LLVM/bin/clang.exe")) printf("[OK] clang\n"); else { puts("[MISSING] clang"); missing = 1; }
    if (command_exists("ld.lld") || file_exists("C:/Program Files/LLVM/bin/ld.lld.exe")) printf("[OK] ld.lld\n"); else { puts("[MISSING] ld.lld"); missing = 1; }
    if (command_exists("llvm-readobj") || file_exists("C:/Program Files/LLVM/bin/llvm-readobj.exe")) printf("[OK] llvm-readobj\n"); else { puts("[MISSING] llvm-readobj"); missing = 1; }
    if (command_exists("llvm-nm") || file_exists("C:/Program Files/LLVM/bin/llvm-nm.exe")) printf("[OK] llvm-nm\n"); else { puts("[MISSING] llvm-nm"); missing = 1; }
    if (command_exists("qemu-system-x86_64") || file_exists("C:/Program Files/qemu/qemu-system-x86_64.exe")) printf("[OK] qemu-system-x86_64\n"); else { puts("[MISSING] qemu-system-x86_64"); missing = 1; }
    if (command_exists("nasm") || file_exists("third_party/tools/nasm-3.02/nasm.exe")) {
        printf("[OK] nasm\n");
    } else {
        printf("[MISSING] nasm\n");
        missing = 1;
    }
    return missing ? fail("install the missing host tools, then rerun check") : 0;
}

static int bootstrap_limine(bool skip_binary) {
    if (!directory_exists("third_party/limine") &&
        execute("git clone --depth 1 --branch v12.9.0 https://github.com/limine-bootloader/limine.git third_party/limine") != 0) {
        return 1;
    }
    if (!directory_exists("third_party/limine-protocol") &&
        execute("git clone --depth 1 https://github.com/limine-bootloader/limine-protocol.git third_party/limine-protocol") != 0) {
        return 1;
    }
    if (skip_binary || directory_exists("third_party/limine-binary")) {
        return 0;
    }
    return fail("download Limine's BOOTX64.EFI release into third_party/limine-binary, then rerun build");
}

static int bootstrap_assets(void) {
    if (!directory_exists("third_party/font8x8") &&
        execute("git clone --depth 1 https://github.com/dhepper/font8x8.git third_party/font8x8") != 0) {
        return 1;
    }
    return file_exists("third_party/font8x8/font8x8_basic.h") ? 0 : fail("font8x8_basic.h is absent");
}

static int bootstrap_nasm(void) {
    return file_exists("third_party/tools/nasm-3.02/nasm.exe") || command_exists("nasm") ? 0 :
        fail("install NASM 3.02+ and add it to PATH");
}

static int run_qemu(int memory_mb, int host_port, bool display, bool gdb_wait) {
    const char *firmware = "C:/Program Files/qemu/share/edk2-x86_64-code.fd";
    const char *variables_template = "C:/Program Files/qemu/share/edk2-i386-vars.fd";
    if (!file_exists("build/esp/boot/kos.elf")) {
        return fail("UEFI ESP is absent; run build");
    }
    if (!file_exists(firmware) || !file_exists(variables_template)) {
        return fail("QEMU UEFI firmware is absent");
    }
    if (!file_exists("build/edk2-vars.fd") && !copy_file(variables_template, "build/edk2-vars.fd")) {
        return 1;
    }
    return execute_format("call \"%s\" -machine q35 -cpu max -m %d "
        "-drive if=pflash,format=raw,readonly=on,file=\"%s\" "
        "-drive if=pflash,format=raw,file=build/edk2-vars.fd "
        "-drive format=raw,file=fat:rw:build/esp -serial stdio -monitor none -no-reboot "
        "-netdev user,id=kosnet,ipv4=on,ipv6=off,hostfwd=tcp::%d-:80 -device e1000,netdev=kosnet,mac=52:54:00:12:34:56 "
        "-display %s%s", qemu_command(), memory_mb, firmware, host_port,
        display ? "default" : "none", gdb_wait ? " -S -s" : "");
}

static void print_usage(void) {
    puts("KOS C development tool");
    puts("Usage: kos-tool <check|bootstrap-limine|bootstrap-assets|bootstrap-nasm|build|run> [options]");
    puts("build options: --kernel-only, --panic-test");
    puts("run options: --display, --gdb-wait, --memory-mb <128..4096>, --host-port <1024..65535>");
}

int main(int argc, char **argv) {
    bool kernel_only = false;
    bool panic_test = false;
    bool display = false;
    bool gdb_wait = false;
    bool skip_binary = false;
    int memory_mb = 256;
    int host_port = 8080;
    int index;
    if (argc < 2) {
        print_usage();
        return 1;
    }
    for (index = 2; index < argc; ++index) {
        if (strcmp(argv[index], "--kernel-only") == 0) kernel_only = true;
        else if (strcmp(argv[index], "--panic-test") == 0) panic_test = true;
        else if (strcmp(argv[index], "--display") == 0) display = true;
        else if (strcmp(argv[index], "--gdb-wait") == 0) gdb_wait = true;
        else if (strcmp(argv[index], "--skip-binary") == 0) skip_binary = true;
        else if (strcmp(argv[index], "--memory-mb") == 0 && index + 1 < argc) memory_mb = atoi(argv[++index]);
        else if (strcmp(argv[index], "--host-port") == 0 && index + 1 < argc) host_port = atoi(argv[++index]);
        else return fail("unknown option");
    }
    if (strcmp(argv[1], "check") == 0) return check_environment();
    if (strcmp(argv[1], "bootstrap-limine") == 0) return bootstrap_limine(skip_binary);
    if (strcmp(argv[1], "bootstrap-assets") == 0) return bootstrap_assets();
    if (strcmp(argv[1], "bootstrap-nasm") == 0) return bootstrap_nasm();
    if (strcmp(argv[1], "build") == 0) return build_kernel(kernel_only, panic_test);
    if (strcmp(argv[1], "run") == 0) {
        if (memory_mb < 128 || memory_mb > 4096) return fail("memory must be between 128 and 4096 MB");
        if (host_port < 1024 || host_port > 65535) return fail("host port must be between 1024 and 65535");
        return run_qemu(memory_mb, host_port, display, gdb_wait);
    }
    print_usage();
    return 1;
}
