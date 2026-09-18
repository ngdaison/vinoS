#ifndef KOS_PAGE_FAULT_H
#define KOS_PAGE_FAULT_H

#include <stdbool.h>
#include <stdint.h>
#include <kos/interrupts.h>

/*
 * x86_64 Page Fault Error Code Bitmasks (Intel SDM Vol 3A §4.7)
 */
#define PF_ERROR_PRESENT        (1ull << 0)  /* Bit 0: 0 = Non-present, 1 = Protection violation */
#define PF_ERROR_WRITE          (1ull << 1)  /* Bit 1: 0 = Read access, 1 = Write access */
#define PF_ERROR_USER           (1ull << 2)  /* Bit 2: 0 = Supervisor/Kernel mode, 1 = User mode */
#define PF_ERROR_RESERVED       (1ull << 3)  /* Bit 3: 1 = Reserved bit set in page tables */
#define PF_ERROR_INSTRUCTION    (1ull << 4)  /* Bit 4: 1 = Instruction fetch (NX violation) */
#define PF_ERROR_PROTECTION_KEY (1ull << 5)  /* Bit 5: 1 = Protection-key violation */
#define PF_ERROR_SHADOW_STACK   (1ull << 6)  /* Bit 6: 1 = Shadow stack access */
#define PF_ERROR_SGX            (1ull << 15) /* Bit 15: 1 = SGX enclave violation */

struct page_fault_record {
    /* Raw hardware context */
    uint64_t fault_address;          /* CR2 register value captured at handler entry */
    uint64_t error_code;             /* Raw CPU error code from interrupt context */
    uint64_t rip;                    /* Instruction pointer at fault */
    uint64_t rsp;                    /* Stack pointer at fault */
    uint64_t cs;                     /* Code segment selector */
    uint64_t ss;                     /* Stack segment selector */
    uint64_t rflags;                 /* CPU flags */
    uint64_t cr3;                    /* Page directory base register (PML4) */

    /* Decoded boolean flags */
    bool present;                    /* true = protection violation, false = unmapped page */
    bool write;                      /* true = write access, false = read access */
    bool user;                       /* true = user mode (Ring 3), false = kernel mode (Ring 0) */
    bool reserved_bit;               /* true = reserved bit violation in paging structure */
    bool instruction_fetch;          /* true = instruction fetch on non-executable page */
    bool protection_key;             /* true = protection-key violation */
    bool shadow_stack;               /* true = shadow stack access fault */
    bool sgx;                        /* true = SGX enclave violation */

    /* High-level human-readable descriptive strings */
    const char *access_operation;    /* "read", "write", or "instruction-fetch" */
    const char *access_target;       /* "data" or "code" */
    const char *cpu_mode;            /* "kernel" or "user" */
    const char *violation_cause;     /* Concise summary of the violation cause */
};

/* Core Page Fault APIs */
void page_fault_decode(uint64_t error_code, struct page_fault_record *record);
void page_fault_handler(struct interrupt_context *context);
uint64_t page_fault_get_last_cr2(void);
const struct page_fault_record *page_fault_get_last_record(void);

#endif /* KOS_PAGE_FAULT_H */
