#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/acpi.h>
#include <kos/apic.h>
#include <kos/boot_protocol.h>
#include <kos/cpu.h>
#include <kos/descriptors.h>
#include <kos/interrupts.h>
#include <kos/log.h>
#include <kos/security.h>
#include <kos/smp.h>
#include <kos/spinlock.h>
#include <kos/syscall.h>
#include <kos/task.h>
#include <kos/timer.h>
#include <kos/vmm.h>

#define IA32_GS_BASE 0xC0000101
#define IA32_KERNEL_GS_BASE 0xC0000102

extern void gdt_load(const struct descriptor_table_pointer *pointer);
extern void tss_load(uint16_t selector);


static struct percpu_data g_percpu_table[SMP_MAX_CPUS];
static uint32_t g_discovered_cpu_count = 1;
static uint32_t g_online_cpu_count = 1;
static bool g_smp_initialized = false;

/* TLB Shootdown Synchronization State */
static kos_spinlock_t g_tlb_lock = SPINLOCK_INIT;
static volatile uint64_t g_tlb_shootdown_vaddr = 0;
static volatile uint64_t g_tlb_shootdown_pages = 0;
static volatile uint32_t g_tlb_shootdown_acks = 0;

static inline void wrmsr(uint32_t msr, uint64_t value) {
    uint32_t low = (uint32_t)value;
    uint32_t high = (uint32_t)(value >> 32);
    __asm__ volatile ("wrmsr" : : "a"(low), "d"(high), "c"(msr) : "memory");
}

static inline uint64_t rdmsr(uint32_t msr) {
    uint32_t low, high;
    __asm__ volatile ("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((uint64_t)high << 32) | low;
}

static void configure_cpu_gdt(struct percpu_data *cpu) {
    cpu->gdt_entries[0] = 0x0000000000000000ull; /* Null */
    cpu->gdt_entries[1] = 0x00af9a000000ffffull; /* Kernel Code (0x08) */
    cpu->gdt_entries[2] = 0x00cf92000000ffffull; /* Kernel Data (0x10) */

    /* Configure TSS Descriptor (0x18) */
    uint64_t base = (uint64_t)&cpu->tss;
    uint64_t limit = sizeof(struct task_state_segment) - 1;
    cpu->gdt_entries[3] = (limit & 0xffff)
        | ((base & 0xffffff) << 16)
        | (0x89ull << 40)
        | ((limit & 0xf0000) << 32)
        | (((base >> 24) & 0xff) << 56);
    cpu->gdt_entries[4] = base >> 32;

    cpu->gdt_entries[5] = 0x00cff2000000ffffull; /* User Data (0x28 | 3 = 0x2B) */
    cpu->gdt_entries[6] = 0x00affa000000ffffull; /* User Code (0x30 | 3 = 0x33) */
}

struct percpu_data *smp_get_percpu(uint32_t cpu_id) {
    if (cpu_id < SMP_MAX_CPUS) {
        return &g_percpu_table[cpu_id];
    }
    return &g_percpu_table[0];
}

uint32_t smp_get_cpu_count(void) {
    return g_discovered_cpu_count;
}

uint32_t smp_get_online_cpu_count(void) {
    return g_online_cpu_count;
}

struct percpu_data *smp_get_current_cpu(void) {
    uint64_t gs_val = rdmsr(IA32_GS_BASE);
    if (gs_val != 0) {
        struct percpu_data *cpu = (struct percpu_data *)gs_val;
        if (cpu->self == cpu) {
            return cpu;
        }
    }

    /* Fallback: Match current LAPIC ID */
    uint32_t lapic_id = lapic_get_id();
    for (uint32_t i = 0; i < g_discovered_cpu_count; ++i) {
        if (g_percpu_table[i].lapic_id == lapic_id) {
            return &g_percpu_table[i];
        }
    }
    return &g_percpu_table[0];
}

uint32_t smp_get_cpu_id(void) {
    struct percpu_data *cpu = smp_get_current_cpu();
    return cpu != 0 ? cpu->cpu_id : 0;
}

void smp_send_reschedule(uint32_t target_cpu_id) {
    if (target_cpu_id < g_discovered_cpu_count) {
        struct percpu_data *target = &g_percpu_table[target_cpu_id];
        if (target->state == CPU_ONLINE) {
            lapic_send_ipi(target->lapic_id, KOS_IPI_RESCHEDULE_VECTOR);
            target->ipi_reschedule_count++;
        }
    }
}

void smp_tlb_shootdown(uint64_t virtual_address, uint64_t page_count) {
    if (g_online_cpu_count <= 1) {
        for (uint64_t i = 0; i < page_count; ++i) {
            cpu_invalidate_page(virtual_address + i * 4096);
        }
        return;
    }

    uint64_t flags = spinlock_lock_irqsave(&g_tlb_lock);
    g_tlb_shootdown_vaddr = virtual_address;
    g_tlb_shootdown_pages = page_count;
    g_tlb_shootdown_acks = 0;

    /* Invalidate locally on current core */
    for (uint64_t i = 0; i < page_count; ++i) {
        cpu_invalidate_page(virtual_address + i * 4096);
    }

    /* Broadcast TLB Shootdown IPI to all other cores */
    lapic_send_ipi_all_excluding_self(KOS_IPI_TLB_SHOOTDOWN_VECTOR);

    /* Wait for acknowledgement from all other online cores */
    uint32_t expected_acks = g_online_cpu_count - 1;
    uint64_t timeout = 100000;
    while (__atomic_load_n(&g_tlb_shootdown_acks, __ATOMIC_ACQUIRE) < expected_acks && timeout > 0) {
        cpu_pause();
        --timeout;
    }

    spinlock_unlock_irqrestore(&g_tlb_lock, flags);
}

void smp_handle_tlb_shootdown_ipi(void) {
    uint64_t vaddr = g_tlb_shootdown_vaddr;
    uint64_t pages = g_tlb_shootdown_pages;
    for (uint64_t i = 0; i < pages; ++i) {
        cpu_invalidate_page(vaddr + i * 4096);
    }
    struct percpu_data *cpu = smp_get_current_cpu();
    if (cpu != 0) {
        cpu->ipi_tlb_count++;
    }
    __atomic_add_fetch(&g_tlb_shootdown_acks, 1, __ATOMIC_RELEASE);
}

/* Entry point executed by Application Processors (APs) */
static void ap_entry_point(struct limine_mp_info *info) {
    struct percpu_data *cpu = (struct percpu_data *)info->extra_argument;
    if (cpu == 0) {
        cpu_halt();
    }

    /* 1. Setup per-CPU GS Base MSRs */
    wrmsr(IA32_GS_BASE, (uint64_t)cpu);
    wrmsr(IA32_KERNEL_GS_BASE, (uint64_t)cpu);

    /* 2. Load Per-CPU GDT and TSS */
    const struct descriptor_table_pointer gdt_pointer = {
        .limit = sizeof(cpu->gdt_entries) - 1,
        .base = (uint64_t)cpu->gdt_entries,
    };
    gdt_load(&gdt_pointer);
    tss_load(KOS_KERNEL_TSS_SELECTOR);

    /* 3. Load IDT on AP */
    idt_reload();

    /* 4. Initialize Local APIC on this core */
    lapic_init_ap();

    /* 5. Initialize Security (SMEP, SMAP, NX) & Syscall on this AP */
    security_init_ap();
    syscall_init_core();

    /* 6. Mark AP online */
    __atomic_store_n(&cpu->state, CPU_ONLINE, __ATOMIC_RELEASE);
    __atomic_add_fetch(&g_online_cpu_count, 1, __ATOMIC_SEQ_CST);

    /* 7. Enable Interrupts and run idle loop */
    cpu_enable_interrupts();

    while (1) {
        cpu_wait_for_interrupt();
    }
}

bool smp_initialize(void) {
    /* 1. Initialize BSP (CPU 0) */
    struct percpu_data *bsp = &g_percpu_table[0];
    bsp->kernel_rsp = (uint64_t)(bsp->kernel_stack + KOS_TASK_KERNEL_STACK_SIZE);
    bsp->user_rsp = 0;
    bsp->cpu_id = 0;
    bsp->lapic_id = lapic_get_id();
    bsp->state = CPU_ONLINE;
    bsp->self = bsp;

    bsp->tss.rsp0 = (uint64_t)(bsp->kernel_stack + KOS_TASK_KERNEL_STACK_SIZE);
    bsp->tss.ist1 = (uint64_t)(bsp->double_fault_stack + sizeof(bsp->double_fault_stack));
    bsp->tss.io_map_base = sizeof(bsp->tss);

    configure_cpu_gdt(bsp);

    const struct descriptor_table_pointer bsp_gdt_ptr = {
        .limit = sizeof(bsp->gdt_entries) - 1,
        .base = (uint64_t)bsp->gdt_entries,
    };
    gdt_load(&bsp_gdt_ptr);
    tss_load(KOS_KERNEL_TSS_SELECTOR);

    wrmsr(IA32_GS_BASE, (uint64_t)bsp);
    wrmsr(IA32_KERNEL_GS_BASE, (uint64_t)bsp);

    g_discovered_cpu_count = 1;
    g_online_cpu_count = 1;

    /* 2. Boot Application Processors via Limine MP Protocol */
    if (kos_mp_request.response != 0 && kos_mp_request.response->cpu_count > 1) {
        uint64_t total_cpus = kos_mp_request.response->cpu_count;
        if (total_cpus > SMP_MAX_CPUS) total_cpus = SMP_MAX_CPUS;

        g_discovered_cpu_count = (uint32_t)total_cpus;
        log_infof("SMP: Bootloader reported %u logical CPU cores.", (unsigned)total_cpus);

        for (uint64_t i = 1; i < total_cpus; ++i) {
            struct limine_mp_info *info = kos_mp_request.response->cpus[i];
            if (info == 0) continue;

            struct percpu_data *ap = &g_percpu_table[i];
            ap->kernel_rsp = (uint64_t)(ap->kernel_stack + KOS_TASK_KERNEL_STACK_SIZE);
            ap->user_rsp = 0;
            ap->cpu_id = (uint32_t)i;
            ap->lapic_id = info->lapic_id;
            ap->state = CPU_STARTING;
            ap->self = ap;

            ap->tss.rsp0 = (uint64_t)(ap->kernel_stack + KOS_TASK_KERNEL_STACK_SIZE);
            ap->tss.ist1 = (uint64_t)(ap->double_fault_stack + sizeof(ap->double_fault_stack));
            ap->tss.io_map_base = sizeof(ap->tss);
            configure_cpu_gdt(ap);

            info->extra_argument = (uint64_t)ap;
            __atomic_store_n(&info->goto_address, ap_entry_point, __ATOMIC_RELEASE);

            /* Wait up to 100ms for AP to come online */
            uint64_t start_tick = timer_ticks();
            while (__atomic_load_n(&ap->state, __ATOMIC_ACQUIRE) != CPU_ONLINE) {
                if (timer_ticks() - start_tick > (timer_frequency_hz() / 10)) {
                    log_warnf("SMP: Timed out waiting for AP core %u (LAPIC %u) to boot.", (unsigned)i, (unsigned)info->lapic_id);
                    break;
                }
                cpu_pause();
            }
        }
    } else if (acpi_get_cpu_count() > 1) {
        /* ACPI reported multiple cores */
        uint32_t acpi_cpus = acpi_get_cpu_count();
        if (acpi_cpus > SMP_MAX_CPUS) acpi_cpus = SMP_MAX_CPUS;
        g_discovered_cpu_count = acpi_cpus;
        log_infof("SMP: ACPI MADT reported %u logical CPUs (Limine MP inactive).", (unsigned)acpi_cpus);
    }

    g_smp_initialized = true;
    log_infof("SMP: Initialization complete. Online cores: %u / %u (BSP Core: 0)",
              (unsigned)g_online_cpu_count, (unsigned)g_discovered_cpu_count);

    return true;
}
