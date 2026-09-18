#include <stdint.h>

#include <kos/boot_protocol.h>
#include <kos/command.h>
#include <kos/console.h>
#include <kos/compiler.h>
#include <kos/cpu.h>
#include <kos/driver.h>
#include <kos/e1000.h>
#include <kos/framebuffer.h>
#include <kos/heap.h>
#include <kos/initramfs.h>
#include <kos/interrupts.h>
#include <kos/keyboard.h>
#include <kos/log.h>
#include <kos/net.h>
#include <kos/socket.h>
#include <kos/crypto.h>
#include <kos/x509.h>
#include <kos/tls.h>
#include <kos/pmm.h>
#include <kos/pic.h>
#include <kos/pci.h>
#include <kos/ramfs.h>
#include <kos/serial.h>
#include <kos/timer.h>
#include <kos/terminal.h>
#include <kos/task.h>
#include <kos/vmm.h>
#include <kos/vfs.h>
#include <kos/block.h>
#include <kos/ramdisk.h>
#include <kos/virtio_blk.h>
#include <kos/ahci.h>
#include <kos/block_cache.h>
#include <kos/partition.h>
#include <kos/fat32.h>
#include <kos/volume.h>
#include <kos/acpi.h>
#include <kos/apic.h>
#include <kos/smp.h>
#include <kos/security.h>
#include <kos/syscall.h>
#include <kos/xhci.h>
#include <kos/nvme.h>
#include <kos/installer.h>
#include <kos/qa.h>
#include <kos/fault_injection.h>
#include <limine.h>

static KOS_NORETURN void kernel_halt(void) {
    cpu_halt();
}

static uint64_t virtual_memory_probe;
extern uint8_t kos_boot_stack_bottom[];
extern uint8_t kos_boot_stack_top[];
extern uint8_t __kernel_text_start[];
extern uint8_t __kernel_data_start[];

static void timer_irq_handler(uint8_t irq, void *context) {
    (void)irq;
    (void)context;
    timer_interrupt();
    task_timer_tick();
}

static void keyboard_irq_handler(uint8_t irq, void *context) {
    (void)irq;
    (void)context;
    keyboard_interrupt();
}

static bool serial_driver_ready(void) { return serial_is_initialized(); }
static bool framebuffer_driver_ready(void) { return framebuffer_is_initialized(); }
static bool timer_driver_ready(void) { return timer_is_initialized(); }
static bool keyboard_driver_ready(void) { return keyboard_is_initialized(); }
static bool pci_driver_initialize(void) { return pci_enumerate(); }

static struct driver builtin_drivers[] = {
    { .name = "serial", .init = serial_driver_ready },
    { .name = "framebuffer", .init = framebuffer_driver_ready },
    { .name = "pit", .init = timer_driver_ready, .irq_handler = timer_irq_handler },
    { .name = "ps2-keyboard", .init = keyboard_driver_ready, .irq_handler = keyboard_irq_handler },
    { .name = "pci", .init = pci_driver_initialize },
    { .name = "e1000", .init = e1000_initialize },
};

static bool strings_equal(const char *left, const char *right) {
    if (left == 0 || right == 0) {
        return false;
    }
    while (*left != '\0' && *right != '\0') {
        if (*left != *right) {
            return false;
        }
        ++left;
        ++right;
    }
    return *left == *right;
}

static const struct limine_file *find_initramfs_module(void) {
    if (kos_module_request.response == 0 || kos_module_request.response->modules == 0) {
        return 0;
    }
    for (uint64_t index = 0; index < kos_module_request.response->module_count; ++index) {
        const struct limine_file *module = kos_module_request.response->modules[index];
        if (module != 0 && strings_equal(module->string, "kos-initramfs")) {
            return module;
        }
    }
    return 0;
}

static bool virtual_page_has_permissions(uint64_t virtual_address, uint64_t required_flags,
        uint64_t forbidden_flags) {
    uint64_t flags;
    return vmm_query_page(virtual_address, 0, &flags)
        && (flags & required_flags) == required_flags
        && (flags & forbidden_flags) == 0;
}

static bool mapping_has_permissions(const char *label, uint64_t virtual_address, uint64_t required_flags,
        uint64_t forbidden_flags) {
    uint64_t flags;
    if (!vmm_query_page(virtual_address, 0, &flags)) {
        return false;
    }
    log_info_hex(label, flags);
    return (flags & required_flags) == required_flags && (flags & forbidden_flags) == 0;
}

static bool heap_self_test(void) {
    uint64_t mapped_pages_before = heap_mapped_page_count();
    uint64_t free_frames_before = pmm_free_frame_count();
    volatile uint8_t *small = kmalloc(64);
    volatile uint8_t *large = kmalloc(9000);
    if (small == 0 || large == 0) {
        return false;
    }

    small[0] = 0x4b;
    small[63] = 0x53;
    large[0] = 0x11;
    large[4095] = 0x22;
    large[8191] = 0x33;
    large[8999] = 0x44;
    bool valid = small[0] == 0x4b && small[63] == 0x53
        && large[0] == 0x11 && large[4095] == 0x22
        && large[8191] == 0x33 && large[8999] == 0x44;
    bool heap_permissions_are_safe = virtual_page_has_permissions((uint64_t)small,
            VMM_PAGE_WRITABLE | VMM_PAGE_NO_EXECUTE, 0)
        && virtual_page_has_permissions((uint64_t)large,
                VMM_PAGE_WRITABLE | VMM_PAGE_NO_EXECUTE, 0)
        && virtual_page_has_permissions((uint64_t)(large + 8999),
                VMM_PAGE_WRITABLE | VMM_PAGE_NO_EXECUTE, 0);

    return valid && heap_permissions_are_safe && kfree((void *)small) && kfree((void *)large)
        && heap_active_allocation_count() == 0
        && heap_mapped_page_count() == mapped_pages_before
        && pmm_free_frame_count() == free_frames_before;
}

static bool pmm_self_test(void) {
    enum { PMM_SELF_TEST_FRAME_COUNT = 65 };
    uint64_t frames[PMM_SELF_TEST_FRAME_COUNT];
    uint64_t free_frames_before = pmm_free_frame_count();
    uint64_t allocated_count = 0;
    bool unique = true;

    for (; allocated_count < PMM_SELF_TEST_FRAME_COUNT; ++allocated_count) {
        frames[allocated_count] = pmm_allocate_frame();
        if (frames[allocated_count] == 0) {
            break;
        }
        for (uint64_t previous = 0; previous < allocated_count; ++previous) {
            if (frames[previous] == frames[allocated_count]) {
                unique = false;
                break;
            }
        }
        if (!unique) {
            ++allocated_count;
            break;
        }
    }
    if (!unique || allocated_count != PMM_SELF_TEST_FRAME_COUNT) {
        for (uint64_t index = 0; index < allocated_count; ++index) {
            pmm_free_frame(frames[index]);
        }
        return false;
    }

    if (!pmm_free_frame(frames[0])) {
        for (uint64_t index = 0; index < allocated_count; ++index) {
            pmm_free_frame(frames[index]);
        }
        return false;
    }
    if (pmm_free_frame(frames[0])) {
        for (uint64_t index = 1; index < allocated_count; ++index) {
            pmm_free_frame(frames[index]);
        }
        return false;
    }
    for (uint64_t index = 1; index < allocated_count; ++index) {
        if (!pmm_free_frame(frames[index])) {
            return false;
        }
    }
    return pmm_free_frame_count() == free_frames_before;
}

static bool vfs_volume_self_test(void) {
    const uint8_t *system_data;
    const uint8_t *data_volume_data;
    uint64_t system_size;
    uint64_t data_volume_size;
    return vfs_volume_count() == 2
        && vfs_read_file("C:\\README.TXT", &system_data, &system_size)
        && system_size != 0
        && system_data[0] != '\0'
        && vfs_read_file("D:\\README.TXT", &data_volume_data, &data_volume_size)
        && data_volume_size != 0
        && data_volume_data[0] == 'K';
}

KOS_NORETURN void kernel_main(void) {
    serial_initialize();
    serial_write("KOS: kernel started\n");

    if (!LIMINE_BASE_REVISION_SUPPORTED(kos_limine_base_revision)) {
        serial_write("KOS: unsupported Limine base revision\n");
        kernel_halt();
    }

    if (kos_framebuffer_request.response == 0
        || kos_framebuffer_request.response->framebuffer_count == 0
        || kos_framebuffer_request.response->framebuffers == 0
        || kos_framebuffer_request.response->framebuffers[0] == 0) {
        serial_write("KOS: no usable framebuffer\n");
        kernel_halt();
    }
    if (!framebuffer_initialize(kos_framebuffer_request.response->framebuffers[0])) {
        serial_write("KOS: unsupported framebuffer format\n");
        kernel_halt();
    }
    if (!console_initialize()) {
        serial_write("KOS: console initialization failed\n");
        kernel_halt();
    }

    log_info("KOS booting...");
    log_info("Framebuffer initialized.");
    log_info("Serial COM1 online.");
    gdt_initialize();
    idt_initialize();
    log_info("CPU descriptor tables initialized.");

#ifdef KOS_PANIC_TEST
    log_info("Panic test: triggering divide-by-zero.");
    cpu_trigger_divide_by_zero();
#endif

    if (kos_memmap_request.response == 0 || !pmm_initialize(kos_memmap_request.response)) {
        log_error("Physical memory manager initialization failed.");
        kernel_halt();
    }

    if (!pmm_self_test()) {
        log_error("Physical memory manager self-test failed.");
        kernel_halt();
    }

    log_info("Physical memory manager initialized.");
    if (kos_hhdm_request.response == 0 || !vmm_initialize(kos_hhdm_request.response->offset)) {
        log_error("Virtual memory manager initialization failed.");
        kernel_halt();
    }
    if (!vmm_is_mapped((uint64_t)kernel_main)
        || !vmm_is_mapped((uint64_t)&virtual_memory_probe)
        || !vmm_is_mapped((uint64_t)kos_boot_stack_bottom)
        || !vmm_is_mapped((uint64_t)(kos_boot_stack_top - 1))
        || !vmm_is_mapped(framebuffer_virtual_address())) {
        log_error("Required Limine boot mapping is absent.");
        kernel_halt();
    }
    if (!vmm_set_page_permissions(framebuffer_virtual_address(),
            VMM_PAGE_WRITABLE | VMM_PAGE_NO_EXECUTE)) {
        log_error("Framebuffer mapping permission update failed.");
        kernel_halt();
    }
    if (!mapping_has_permissions("  Text mapping flags: ", (uint64_t)__kernel_text_start,
                0, VMM_PAGE_WRITABLE | VMM_PAGE_NO_EXECUTE)
        || !mapping_has_permissions("  Data mapping flags: ", (uint64_t)__kernel_data_start,
                VMM_PAGE_WRITABLE | VMM_PAGE_NO_EXECUTE, 0)
        || !mapping_has_permissions("  BSS mapping flags: ", (uint64_t)&virtual_memory_probe,
                VMM_PAGE_WRITABLE | VMM_PAGE_NO_EXECUTE, 0)
        || !mapping_has_permissions("  Stack mapping flags: ", (uint64_t)kos_boot_stack_bottom,
                VMM_PAGE_WRITABLE | VMM_PAGE_NO_EXECUTE, 0)
        || !mapping_has_permissions("  Framebuffer mapping flags: ", framebuffer_virtual_address(),
                VMM_PAGE_WRITABLE | VMM_PAGE_NO_EXECUTE, 0)) {
        log_error("Unsafe Limine boot mapping permissions.");
        kernel_halt();
    }
    if (!heap_initialize() || !heap_self_test()) {
        log_error("Kernel heap self-test failed.");
        kernel_halt();
    }
    log_info("Four-level virtual memory manager initialized.");
    log_info("Kernel heap self-test and page reclamation passed.");
    log_info("Running bootstrap meminfo command.");
    if (!kernel_command_execute("meminfo")) {
        log_error("meminfo command registry failure.");
        kernel_halt();
    }
    log_info("Phase 6 virtual memory and kernel heap complete.");

    if (!pic_initialize() || !timer_initialize(100)
        || !irq_register_handler(KOS_PIC_IRQ_TIMER, timer_irq_handler)
        || !pic_unmask_irq(KOS_PIC_IRQ_TIMER)) {
        log_error("PIT/PIC timer initialization failed.");
        kernel_halt();
    }
    cpu_enable_interrupts();
    timer_wait_ticks(timer_frequency_hz());
    if (!timer_is_initialized() || timer_ticks() < timer_frequency_hz()
        || timer_uptime_seconds() == 0) {
        log_error("PIT timer self-test failed.");
        kernel_halt();
    }
    log_info("PIT timer interrupts initialized at 100 Hz.");
    log_info("Timer self-test passed; monotonic uptime is running.");
    log_info("Phase 7 timer and hardware interrupt foundation complete.");
    if (!keyboard_initialize()
        || !irq_register_handler(KOS_PIC_IRQ_KEYBOARD, keyboard_irq_handler)
        || !pic_unmask_irq(KOS_PIC_IRQ_KEYBOARD)) {
        log_error("PS/2 keyboard initialization failed.");
        kernel_halt();
    }
    log_info("PS/2 keyboard driver initialized.");
    for (uint64_t index = 0; index < sizeof(builtin_drivers) / sizeof(builtin_drivers[0]); ++index) {
        if (!driver_register(&builtin_drivers[index])) {
            log_error("Builtin driver registration failed.");
            kernel_halt();
        }
    }
    if (!driver_initialize_all()) {
        log_error("Builtin driver initialization failed.");
        kernel_halt();
    }
    log_info_u64("Driver framework initialized; registered drivers: ", driver_count());
    log_info_u64("PCI devices discovered: ", pci_device_count());
    log_info(e1000_is_initialized()
        ? "Intel e1000 built-in driver: RX/TX DMA rings initialized."
        : "Intel e1000 built-in driver: no compatible PCI adapter.");

    /* Initialize storage and block device subsystem */
    block_subsystem_init();
    ramdisk_init();
    virtio_blk_initialize();
    ahci_initialize();
    nvme_initialize();
    block_cache_init();

    /* Initialize ACPI, Local APIC, IOAPIC and SMP */
    acpi_initialize();
    lapic_initialize();
    ioapic_initialize();
    pic_disable();
    smp_initialize();

    /* Initialize Kernel Security (NX, SMEP, SMAP, Canary) and Fast Syscalls */
    security_init_bsp();
    syscall_subsystem_init();

    /* Initialize USB Subsystem */
    xhci_initialize();

    const struct limine_file *initramfs_module = find_initramfs_module();
    if (initramfs_module == 0 || !initramfs_initialize(initramfs_module->address,
            initramfs_module->size)
        || !vfs_mount_root(&initramfs_vfs_backend)
        || !ramfs_initialize()
        || !vfs_mount_volume('D', "Data RAM", &ramfs_vfs_backend)) {
        log_error("Initramfs/VFS initialization failed.");
        kernel_halt();
    }
    log_info_u64("VFS mounted volumes: ", vfs_volume_count());
    log_info_u64("C: initramfs files: ", vfs_file_count_on_volume('C'));
    log_info_u64("D: RAM volume files: ", vfs_file_count_on_volume('D'));

    /* Initialize volume manager to auto-discover and mount storage partitions */
    volume_manager_init();

    /* Initialize Application Package Database and Installer */
    installer_subsystem_init();

    if (!vfs_volume_self_test()) {
        log_error("VFS multi-volume self-test failed.");
        kernel_halt();
    }
    log_info("VFS multi-volume path self-test passed.");
    if (!net_initialize() || !net_udp_loopback_self_test()) {
        log_error("Network loopback socket self-test failed.");
        kernel_halt();
    }
    log_info("UDP loopback socket self-test passed.");
    socket_subsystem_init();
    if (!socket_self_test()) {
        log_error("Socket subsystem self-test failed.");
        kernel_halt();
    }
    log_info("Socket subsystem self-test passed.");
    kos_entropy_initialize();
    if (!kos_crypto_self_test()) {
        log_error("Cryptographic primitives self-test failed.");
        kernel_halt();
    }
    log_info("Cryptographic primitives self-test passed: SHA-256, SHA-384, HMAC, HKDF, X25519, AES-GCM, ChaCha20-Poly1305 OK.");
    if (!net_icmp_self_test()) {
        log_error("ICMP checksum self-test failed.");
        kernel_halt();
    }
    log_info("ICMP checksum self-test passed.");
    if (net_has_external_interface()) {
        uint8_t gateway_mac[NET_ETHERNET_ADDRESS_SIZE];
        if (net_arp_resolve(NET_QEMU_GATEWAY_ADDRESS, gateway_mac, NET_ARP_DEFAULT_TIMEOUT_TICKS)) {
            log_info("ARP self-test passed: QEMU gateway resolved.");
            uint64_t round_trip_ticks;
            if (net_icmp_ping(NET_QEMU_GATEWAY_ADDRESS, 1, timer_frequency_hz(), &round_trip_ticks)) {
                log_info("ICMP ping self-test passed: QEMU gateway replied.");
            }
            else {
                log_error("ICMP ping self-test timed out: use ping 10.0.2.2 for diagnosis.");
            }
        }
        else {
            log_error("ARP self-test timed out: link remains available for manual diagnosis.");
        }
        if (net_dhcp_acquire(timer_frequency_hz() * 5)) {
            log_info("DHCP self-test passed: QEMU DHCP lease acquired.");
        }
        else {
            log_error("DHCP self-test timed out: use dhcp for diagnosis.");
        }
    }
    if (!task_initialize()) {
        log_error("Kernel task scheduler initialization failed.");
        kernel_halt();
    }
    log_info("Kernel task scheduler initialized in cooperative mode.");
    log_info("Running bootstrap commands.");
    if (!kernel_command_execute("sysinfo") || !kernel_command_execute("dhcp")
        || !kernel_command_execute("netinfo")) {
        log_error("Bootstrap command execution failure.");
        kernel_halt();
    }
    /* Initialize Fault Injection Subsystem */
    fault_injection_init();

    (void)kernel_command_execute("sockettest");
    (void)kernel_command_execute("cryptotest");
    (void)kernel_command_execute("x509test");
    (void)kernel_command_execute("tlstest");
    (void)kernel_command_execute("acpi");
    (void)kernel_command_execute("smp");
    (void)kernel_command_execute("smptest");
    (void)kernel_command_execute("usbinfo");
    (void)kernel_command_execute("nvmeinfo");
    (void)kernel_command_execute("sectest");
    (void)kernel_command_execute("syscalltest");
    (void)kernel_command_execute("pkgtest");
    (void)kernel_command_execute("qatest");
    (void)kernel_command_execute("tcptest 1.1.1.1 80");
    (void)kernel_command_execute("nslookup example.com");
    (void)kernel_command_execute("curl http://example.com/");
    (void)kernel_command_execute("httpd start 80");
    (void)kernel_command_execute("netstat");
    (void)kernel_command_execute("curl -i http://10.0.2.15/");
    (void)kernel_command_execute("curl http://10.0.2.15/sysinfo");
    (void)kernel_command_execute("netstat");
    (void)kernel_command_execute("netinfo");
    (void)kernel_command_execute("handletest");
    (void)kernel_command_execute("waittest");
    (void)kernel_command_execute("synctest");
    (void)kernel_command_execute("atomictest");
    (void)kernel_command_execute("locktest");
    (void)kernel_command_execute("mutextest");
    (void)kernel_command_execute("timertest");
    (void)kernel_command_execute("sleeptest");
    (void)kernel_command_execute("preempttest");
    (void)kernel_command_execute("processtest");
    (void)kernel_command_execute("stacktest");
    (void)kernel_command_execute("pftest");
    (void)kernel_command_execute("panictest");
    (void)kernel_command_execute("kstress");
    (void)kernel_command_execute("blocktest");
    (void)kernel_command_execute("mbrtest");
    (void)kernel_command_execute("gpttest");
    (void)kernel_command_execute("cachetest");
    (void)kernel_command_execute("fattest");
    (void)kernel_command_execute("fdisk");
    if (!terminal_initialize()) {
        log_error("Kernel terminal initialization failed.");
        kernel_halt();
    }
    terminal_run();
}
