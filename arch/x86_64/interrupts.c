#include <stdbool.h>
#include <stdint.h>

#include <kos/compiler.h>
#include <kos/console.h>
#include <kos/cpu.h>
#include <kos/descriptors.h>
#include <kos/interrupts.h>
#include <kos/log.h>
#include <kos/page_fault.h>
#include <kos/panic.h>
#include <kos/pic.h>
#include <kos/process.h>
#include <kos/serial.h>
#include <kos/syscall.h>
#include <kos/task.h>

enum {
    IDT_ENTRY_COUNT = 256,
    IDT_INTERRUPT_GATE = 0x8e,
    KOS_SYSCALL_VECTOR = 0x80,
};

struct idt_entry {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t ist;
    uint8_t type_attributes;
    uint16_t offset_middle;
    uint32_t offset_high;
    uint32_t reserved;
} __attribute__((packed));

struct idt_pointer {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

extern void idt_load(const struct idt_pointer *pointer);
extern void (*isr_stub_table[])(void);

static struct idt_entry idt_entries[IDT_ENTRY_COUNT] KOS_ALIGNED(16);
static irq_handler irq_handlers[16];
static volatile uint64_t irq_counts[16];
static volatile uint64_t irq_unhandled_counts[16];

static exception_handler_t exception_handlers[KOS_EXCEPTION_VECTOR_COUNT];
static volatile uint64_t exception_counts[KOS_EXCEPTION_VECTOR_COUNT];

static volatile uint32_t s_pf_recursion = 0;
static volatile uint64_t s_last_page_fault_cr2 = 0;
static struct page_fault_record s_last_page_fault_record;

KOS_NOINLINE KOS_USED uint64_t page_fault_get_last_cr2(void) {
    return s_last_page_fault_cr2;
}

KOS_NOINLINE KOS_USED const struct page_fault_record *page_fault_get_last_record(void) {
    return &s_last_page_fault_record;
}

static void idt_set_gate(uint8_t vector, void (*handler)(void), uint8_t ist) {
    uint64_t address = (uint64_t)handler;
    idt_entries[vector] = (struct idt_entry){
        .offset_low = (uint16_t)address,
        .selector = KOS_KERNEL_CODE_SELECTOR,
        .ist = (uint8_t)(ist & 0x07),
        .type_attributes = IDT_INTERRUPT_GATE,
        .offset_middle = (uint16_t)(address >> 16),
        .offset_high = (uint32_t)(address >> 32),
        .reserved = 0,
    };
}

KOS_NOINLINE uint8_t idt_get_gate_ist(uint8_t vector) {
    return (uint8_t)(idt_entries[vector].ist & 0x07);
}

static const char *exception_name(uint64_t vector) {
    switch (vector) {
        case 0: return "Divide-by-zero (#DE)";
        case 1: return "Debug exception (#DB)";
        case 2: return "NMI interrupt";
        case 3: return "Breakpoint (#BP)";
        case 4: return "Overflow (#OF)";
        case 5: return "BOUND range exceeded (#BR)";
        case 6: return "Invalid opcode (#UD)";
        case 7: return "Device not available (#NM)";
        case 8: return "Double fault (#DF)";
        case 9: return "Coprocessor segment overrun";
        case 10: return "Invalid TSS (#TS)";
        case 11: return "Segment not present (#NP)";
        case 12: return "Stack-segment fault (#SS)";
        case 13: return "General protection fault (#GP)";
        case 14: return "Page fault (#PF)";
        case 16: return "x87 FPU error (#MF)";
        case 17: return "Alignment check (#AC)";
        case 18: return "Machine check (#MC)";
        case 19: return "SIMD floating-point (#XM)";
        case 20: return "Virtualization exception (#VE)";
        case 21: return "Control protection (#CP)";
        case 29: return "VMM communication (#VC)";
        case 30: return "Security exception (#SX)";
        default: return "Unhandled CPU exception";
    }
}

KOS_NOINLINE KOS_USED void page_fault_decode(uint64_t error_code, struct page_fault_record *record) {
    if (record == 0) {
        return;
    }
    record->error_code = error_code;
    record->present = (error_code & PF_ERROR_PRESENT) != 0;
    record->write = (error_code & PF_ERROR_WRITE) != 0;
    record->user = (error_code & PF_ERROR_USER) != 0;
    record->reserved_bit = (error_code & PF_ERROR_RESERVED) != 0;
    record->instruction_fetch = (error_code & PF_ERROR_INSTRUCTION) != 0;
    record->protection_key = (error_code & PF_ERROR_PROTECTION_KEY) != 0;
    record->shadow_stack = (error_code & PF_ERROR_SHADOW_STACK) != 0;
    record->sgx = (error_code & PF_ERROR_SGX) != 0;

    if (record->instruction_fetch) {
        record->access_operation = "instruction-fetch";
        record->access_target = "code";
    } else if (record->write) {
        record->access_operation = "write";
        record->access_target = "data";
    } else {
        record->access_operation = "read";
        record->access_target = "data";
    }

    if (record->user) {
        record->cpu_mode = "user";
    } else {
        record->cpu_mode = "kernel";
    }

    if (record->reserved_bit) {
        record->violation_cause = "reserved bit violation in page table";
    } else if (record->instruction_fetch) {
        record->violation_cause = "execution of non-executable (NX) page";
    } else if (record->protection_key) {
        record->violation_cause = "protection-key (PKRU) violation";
    } else if (record->shadow_stack) {
        record->violation_cause = "shadow-stack access violation";
    } else if (record->sgx) {
        record->violation_cause = "SGX enclave violation";
    } else if (record->present) {
        record->violation_cause = "page protection violation (write to read-only or supervisor page)";
    } else {
        record->violation_cause = "non-present page (unmapped virtual address)";
    }
}

static void log_page_fault_panic(const struct interrupt_context *context, const struct page_fault_record *rec) {
    log_enter_emergency_mode();
    log_emergency_puts("\r\n==================== KERNEL PANIC: PAGE FAULT (#PF) ====================\r\n");
    log_error("KERNEL PANIC: Fatal Page Fault in Kernel Mode!");

    char summary[256];
    ksnprintf(summary, sizeof(summary),
              "[PAGE FAULT] Address: 0x%016lX | Access: %s %s from %s mode | Violation: %s",
              (unsigned long)rec->fault_address,
              rec->access_operation,
              rec->access_target,
              rec->cpu_mode,
              rec->violation_cause);
    log_error(summary);

    /* Decoded Error Flags Breakdown */
    log_error("--- Decoded Error Flags ---");
    log_error(rec->present ?
        "  [P=1] Cause:  Page-protection violation (page is present)" :
        "  [P=0] Cause:  Non-present page (page translation not present)");

    log_error(rec->write ?
        "  [W/R=1] Access: Write operation" :
        "  [W/R=0] Access: Read operation");

    log_error(rec->user ?
        "  [U/S=1] Mode:   User mode (Ring 3)" :
        "  [U/S=0] Mode:   Supervisor / Kernel mode (Ring 0)");

    if (rec->reserved_bit) {
        log_error("  [RSVD=1] Violation: Reserved bit set to 1 in page table hierarchy");
    }
    if (rec->instruction_fetch) {
        log_error("  [I/D=1] Violation: Instruction fetch from non-executable page (NX)");
    }
    if (rec->protection_key) {
        log_error("  [PK=1] Violation: Protection key rights violation");
    }
    if (rec->shadow_stack) {
        log_error("  [SS=1] Violation: Shadow stack access fault");
    }
    if (rec->sgx) {
        log_error("  [SGX=1] Violation: Software Guard Extensions violation");
    }

    /* Address Space Classification */
    log_error("--- Address Classification ---");
    if (rec->fault_address == 0) {
        log_error("  Fault Category: NULL Pointer Dereference (0x0000000000000000)");
    } else if (rec->fault_address < 0x1000) {
        log_error("  Fault Category: Near-NULL Pointer Dereference (< 4 KiB)");
    } else if (rec->fault_address < 0x0000800000000000ULL) {
        log_error("  Fault Category: Canonical User Address Range (0x0 - 0x00007FFFFFFFFFFF)");
    } else if (rec->fault_address < 0xFFFF800000000000ULL) {
        log_error("  Fault Category: Non-Canonical Address Range (Hole)");
    } else {
        log_error("  Fault Category: Higher-Half Kernel Address Range (>= 0xFFFF800000000000)");
    }

    panic_with_context(context,
        "Fatal Page Fault: %s %s at address 0x%016lX (%s mode, %s)",
        rec->access_operation, rec->access_target,
        (unsigned long)rec->fault_address, rec->cpu_mode, rec->violation_cause);
}

void page_fault_handler(struct interrupt_context *context) {
    /* 1. CR2 MUST be captured immediately as the VERY FIRST instruction */
    const uint64_t cr2 = cpu_read_cr2();
    s_last_page_fault_cr2 = cr2;

    /* 2. Atomic recursion guard */
    uint32_t recursion = __atomic_add_fetch(&s_pf_recursion, 1, __ATOMIC_SEQ_CST);
    if (recursion > 1) {
        serial_emergency_puts("\r\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\r\n");
        serial_emergency_puts("FATAL: RECURSIVE PAGE FAULT INSIDE PAGE FAULT HANDLER!\r\n");
        serial_emergency_puts("Faulting CR2: ");
        serial_emergency_put_hex(cr2);
        serial_emergency_puts("\r\nFaulting RIP: ");
        serial_emergency_put_hex(context->rip);
        serial_emergency_puts("\r\nRecursion Count: ");
        serial_emergency_put_dec(recursion);
        serial_emergency_puts("\r\nSystem halted immediately to prevent triple fault.\r\n");
        serial_emergency_puts("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\r\n");
        cpu_halt();
    }

    /* 3. Decode page fault context into record */
    struct page_fault_record record;
    record.fault_address = cr2;
    record.rip = context->rip;
    record.rsp = context->rsp;
    record.cs = context->cs;
    record.ss = context->ss;
    record.rflags = context->rflags;
    record.cr3 = cpu_read_cr3();

    page_fault_decode(context->error_code, &record);
    s_last_page_fault_record = record;

    /* 4. Fault discrimination: Kernel mode vs User mode */
    bool is_user = ((context->cs & 3) == 3) || ((context->error_code & 4) != 0);
    if (!is_user) {
        /* Kernel mode page fault is unrecoverable -> Panic & Halt */
        log_page_fault_panic(context, &record);
    } else {
        /* User mode page fault (Ring 3) */
        __atomic_sub_fetch(&s_pf_recursion, 1, __ATOMIC_SEQ_CST);

        log_warnf("User process page fault: CR2=0x%016lX, RIP=0x%016lX, RSP=0x%016lX, error=0x%lX [P=%u W=%u U=%u R=%u I=%u] (%s)",
                  (unsigned long)cr2,
                  (unsigned long)context->rip,
                  (unsigned long)context->rsp,
                  (unsigned long)context->error_code,
                  (unsigned int)(record.present ? 1 : 0),
                  (unsigned int)(record.write ? 1 : 0),
                  (unsigned int)(record.user ? 1 : 0),
                  (unsigned int)(record.reserved_bit ? 1 : 0),
                  (unsigned int)(record.instruction_fetch ? 1 : 0),
                  record.violation_cause ? record.violation_cause : "access violation");

        struct process *cur = process_get_current();
        if (cur != NULL) {
            log_warnf("Terminating user process PID %lu (%s) due to page fault (SIGSEGV -11)",
                      (unsigned long)cur->pid, cur->name);
            process_exit(cur, -11);
            schedule();
        }
        schedule();
    }
}

static void report_page_fault(uint64_t error_code) {
    const uint64_t cr2 = cpu_read_cr2();
    struct page_fault_record record;
    record.fault_address = cr2;
    page_fault_decode(error_code, &record);

    char summary[256];
    ksnprintf(summary, sizeof(summary),
              "[PAGE FAULT] Address: 0x%016lX | Access: %s %s from %s mode | Violation: %s",
              (unsigned long)cr2,
              record.access_operation,
              record.access_target,
              record.cpu_mode,
              record.violation_cause);
    log_error(summary);
}

static bool vector_is_pic_irq(uint64_t vector) {
    return vector >= KOS_PIC_MASTER_VECTOR && vector < KOS_PIC_MASTER_VECTOR + 16;
}

bool irq_register_handler(uint8_t irq, irq_handler handler) {
    if (irq >= 16 || handler == 0 || irq_handlers[irq] != 0) {
        return false;
    }
    irq_handlers[irq] = handler;
    return true;
}

bool irq_unregister_handler(uint8_t irq, irq_handler handler) {
    if (irq >= 16 || handler == 0 || irq_handlers[irq] != handler) {
        return false;
    }
    irq_handlers[irq] = 0;
    return true;
}

uint64_t irq_dispatch_count(uint8_t irq) {
    return irq < 16 ? irq_counts[irq] : 0;
}

uint64_t irq_unhandled_count(uint8_t irq) {
    return irq < 16 ? irq_unhandled_counts[irq] : 0;
}

KOS_NOINLINE int exception_register_handler(uint8_t vector, exception_handler_t handler) {
    if (vector >= KOS_EXCEPTION_VECTOR_COUNT || handler == 0 || exception_handlers[vector] != 0) {
        return 0;
    }
    exception_handlers[vector] = handler;
    return 1;
}

KOS_NOINLINE int exception_unregister_handler(uint8_t vector, exception_handler_t handler) {
    if (vector >= KOS_EXCEPTION_VECTOR_COUNT || handler == 0 || exception_handlers[vector] != handler) {
        return 0;
    }
    exception_handlers[vector] = 0;
    return 1;
}

KOS_NOINLINE exception_handler_t exception_get_handler(uint8_t vector) {
    return vector < KOS_EXCEPTION_VECTOR_COUNT ? exception_handlers[vector] : 0;
}

KOS_NOINLINE uint64_t exception_dispatch_count(uint8_t vector) {
    return vector < KOS_EXCEPTION_VECTOR_COUNT ? exception_counts[vector] : 0;
}

static void handle_user_exception(const struct interrupt_context *context) {
    log_warnf("Unhandled user exception: vector=0x%02lX (%s), error_code=0x%lX, RIP=0x%016lX",
              (unsigned long)context->vector,
              exception_name(context->vector),
              (unsigned long)context->error_code,
              (unsigned long)context->rip);
    struct process *cur = process_get_current();
    log_warnf("User process exception details: PID %lu (%s)",
              (unsigned long)(cur ? cur->pid : 0),
              cur ? cur->name : "unknown");
    log_warnf("  RIP: 0x%016lX  RSP: 0x%016lX  RFLAGS: 0x%016lX",
              (unsigned long)context->rip,
              (unsigned long)context->rsp,
              (unsigned long)context->rflags);
    log_warnf("  RAX: 0x%016lX  RBX: 0x%016lX  RCX: 0x%016lX  RDX: 0x%016lX",
              (unsigned long)context->rax,
              (unsigned long)context->rbx,
              (unsigned long)context->rcx,
              (unsigned long)context->rdx);
    log_warnf("  RSI: 0x%016lX  RDI: 0x%016lX  RBP: 0x%016lX",
              (unsigned long)context->rsi,
              (unsigned long)context->rdi,
              (unsigned long)context->rbp);
    log_warnf("  R8 : 0x%016lX  R9 : 0x%016lX  R10: 0x%016lX  R11: 0x%016lX",
              (unsigned long)context->r8,
              (unsigned long)context->r9,
              (unsigned long)context->r10,
              (unsigned long)context->r11);
    log_warnf("  R12: 0x%016lX  R13: 0x%016lX  R14: 0x%016lX  R15: 0x%016lX",
              (unsigned long)context->r12,
              (unsigned long)context->r13,
              (unsigned long)context->r14,
              (unsigned long)context->r15);
    log_warnf("  CS : 0x%04lX  SS : 0x%04lX",
              (unsigned long)context->cs,
              (unsigned long)context->ss);
    if (cur != NULL) {
        log_warnf("Terminating user process PID %lu (%s) due to unhandled exception",
                  (unsigned long)cur->pid, cur->name);
        process_exit(cur, -1);
        schedule();
    }
    schedule();
}

static void default_exception_panic(const struct interrupt_context *context) {
    if ((context->cs & 3) == 3) {
        log_warnf("Unhandled user exception: vector=0x%02lX (%s), error_code=0x%lX, RIP=0x%016lX",
                  (unsigned long)context->vector,
                  exception_name(context->vector),
                  (unsigned long)context->error_code,
                  (unsigned long)context->rip);
        struct process *cur = process_get_current();
        if (cur != NULL) {
            log_warnf("Terminating user process PID %lu (%s) due to unhandled exception",
                      (unsigned long)cur->pid, cur->name);
            process_exit(cur, -1);
            schedule();
        }
        schedule();
        return;
    }

    if (context->vector == 14) {
        report_page_fault(context->error_code);
    }
    panic_with_context(context, "Unhandled CPU Exception: %s (Vector 0x%02lX)",
                       exception_name(context->vector), (unsigned long)context->vector);
}

#include <kos/apic.h>

extern void smp_handle_tlb_shootdown_ipi(void);

void interrupt_dispatch(const struct interrupt_context *context) {
    /* Stage 1: Syscall (vector 0x80) */
    if (context->vector == KOS_SYSCALL_VECTOR) {
        struct interrupt_context *mutable_context = (struct interrupt_context *)context;
        mutable_context->rax = kos_syscall_dispatch(context->rax, context->rdi,
            context->rsi, context->rdx, context->r10, context->r8, context->r9);
        return;
    }

    /* Stage 1.5: APIC Special Vectors & IPIs */
    if (context->vector == KOS_APIC_SPURIOUS_VECTOR) {
        return; /* Spurious interrupt: no EOI */
    }
    if (context->vector == KOS_IPI_RESCHEDULE_VECTOR) {
        lapic_eoi();
        if (task_is_multitasking_active()) {
            task_reschedule_if_needed();
        }
        return;
    }
    if (context->vector == KOS_IPI_TLB_SHOOTDOWN_VECTOR) {
        smp_handle_tlb_shootdown_ipi();
        lapic_eoi();
        return;
    }
    if (context->vector == KOS_IPI_GENERIC_VECTOR) {
        lapic_eoi();
        return;
    }

    /* Stage 2: Hardware IRQs (vectors 32 to 47) */
    if (vector_is_pic_irq(context->vector)) {
        uint8_t irq = (uint8_t)(context->vector - 32);
        if (irq < 16 && !lapic_is_enabled() && pic_is_spurious_irq(irq)) {
            pic_send_spurious_eoi(irq);
            return;
        }
        if (irq < 16) {
            ++irq_counts[irq];
            irq_handler handler = irq_handlers[irq];
            if (handler != 0) {
                handler(irq, (void *)context);
            }
            else {
                ++irq_unhandled_counts[irq];
            }
        }
        if (lapic_is_enabled()) {
            lapic_eoi();
        } else if (irq < 16) {
            pic_send_eoi(irq);
        }

        /* Preemptive reschedule hook upon return from hardware interrupt */
        if (task_is_multitasking_active() && (context->rflags & (1ull << 9))) {
            task_reschedule_if_needed();
        }
        return;
    }

    /* Stage 3: Dynamic CPU Exceptions (vectors 0 to 31) */
    if (context->vector < KOS_EXCEPTION_VECTOR_COUNT) {
        ++exception_counts[context->vector];
        exception_handler_t handler = exception_handlers[context->vector];
        if (handler != 0) {
            handler((struct interrupt_context *)context);
            return;
        }
        if ((context->cs & 3) == 3) {
            handle_user_exception(context);
            return;
        }
    }

    /* Stage 4: Default Panic for unhandled exceptions or unexpected vectors */
    default_exception_panic(context);
}

static volatile bool s_int3_test_triggered = false;
static volatile uint64_t s_int3_observed_vector = 0;
static volatile uint64_t s_int3_observed_rip = 0;
static volatile uint64_t s_int3_observed_rsp = 0;

static void test_int3_handler(struct interrupt_context *context) {
    s_int3_test_triggered = true;
    s_int3_observed_vector = context->vector;
    s_int3_observed_rip = context->rip;
    s_int3_observed_rsp = context->rsp;
}

KOS_NOINLINE bool exception_self_test(void) {
    if (exception_register_handler(KOS_EXCEPTION_VECTOR_COUNT, test_int3_handler) != 0) {
        return false;
    }
    if (exception_register_handler(3, 0) != 0) {
        return false;
    }
    if (exception_register_handler(3, test_int3_handler) == 0) {
        return false;
    }
    if (exception_get_handler(3) != test_int3_handler) {
        return false;
    }
    if (exception_register_handler(3, test_int3_handler) != 0) {
        return false;
    }

    s_int3_test_triggered = false;
    s_int3_observed_vector = 0;
    s_int3_observed_rip = 0;
    s_int3_observed_rsp = 0;

    __asm__ volatile ("int3" : : : "memory");

    if (!s_int3_test_triggered) {
        return false;
    }
    if (s_int3_observed_vector != 3) {
        return false;
    }
    if (s_int3_observed_rip == 0 || s_int3_observed_rsp == 0) {
        return false;
    }
    if (exception_dispatch_count(3) == 0) {
        return false;
    }

    if (exception_unregister_handler(3, test_int3_handler) == 0) {
        return false;
    }
    if (exception_get_handler(3) != 0) {
        return false;
    }

    return true;
}

void idt_initialize(void) {
    for (uint16_t vector = 0; vector < IDT_ENTRY_COUNT; ++vector) {
        uint8_t ist = vector == 8 ? 1 : 0;
        idt_set_gate((uint8_t)vector, isr_stub_table[vector], ist);
    }
    /* User mode may enter only through the deliberately narrow syscall gate. */
    idt_entries[KOS_SYSCALL_VECTOR].type_attributes = 0xee;

    const struct idt_pointer pointer = {
        .limit = sizeof(idt_entries) - 1,
        .base = (uint64_t)idt_entries,
    };
    idt_load(&pointer);

    if (idt_get_gate_ist(8) != 1) {
        log_error("IDT gate 8 IST configuration verification failed.");
        cpu_halt();
    }

    if (!exception_self_test()) {
        log_error("Exception frame and dynamic dispatch self-test failed.");
        cpu_halt();
    }
    log_info("Exception frame and dynamic handler dispatch initialized (K12.1 passed).");

    /* Formally register vector 14 (#PF - Page Fault) handler (K12.2) */
    if (exception_register_handler(14, page_fault_handler) == 0) {
        log_error("Failed to register page fault handler (vector 14).");
        cpu_halt();
    }
    if (exception_get_handler(14) != page_fault_handler) {
        log_error("Page fault handler registration verification failed.");
        cpu_halt();
    }
    log_info("Page fault handler registered at vector 14 (K12.2 passed).");
}

void idt_reload(void) {
    const struct idt_pointer pointer = {
        .limit = sizeof(idt_entries) - 1,
        .base = (uint64_t)idt_entries,
    };
    idt_load(&pointer);
}

