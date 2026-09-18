#ifndef KOS_ACPI_H
#define KOS_ACPI_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/compiler.h>

#define ACPI_MAX_CPUS 64
#define ACPI_MAX_IOAPICS 8
#define ACPI_MAX_ISOS 32

/* ACPI 1.0 RSDP Structure */
struct acpi_rsdp_descriptor {
    char signature[8];        /* "RSD PTR " */
    uint8_t checksum;
    char oem_id[6];
    uint8_t revision;         /* 0 for ACPI 1.0, 2 for ACPI 2.0+ */
    uint32_t rsdt_address;
} __attribute__((packed));

/* ACPI 2.0+ Extended RSDP Structure */
struct acpi_rsdp_descriptor20 {
    struct acpi_rsdp_descriptor first_part;
    uint32_t length;
    uint64_t xsdt_address;
    uint8_t extended_checksum;
    uint8_t reserved[3];
} __attribute__((packed));

/* Standard ACPI SDT Header */
struct acpi_sdt_header {
    char signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oem_id[6];
    char oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
} __attribute__((packed));

/* MADT (APIC) Header */
struct acpi_madt {
    struct acpi_sdt_header header;
    uint32_t local_apic_address;
    uint32_t flags;           /* 1 = Dual 8259 PICs installed (PCAT_COMPAT) */
} __attribute__((packed));

/* MADT Entry Types */
enum acpi_madt_type {
    ACPI_MADT_TYPE_LOCAL_APIC           = 0,
    ACPI_MADT_TYPE_IO_APIC              = 1,
    ACPI_MADT_TYPE_INTERRUPT_OVERRIDE   = 2,
    ACPI_MADT_TYPE_NMI_SOURCE           = 3,
    ACPI_MADT_TYPE_LOCAL_APIC_NMI       = 4,
    ACPI_MADT_TYPE_LOCAL_APIC_OVERRIDE  = 5,
    ACPI_MADT_TYPE_LOCAL_X2APIC         = 9,
};

struct acpi_madt_entry_header {
    uint8_t type;
    uint8_t length;
} __attribute__((packed));

/* Type 0: Processor Local APIC */
struct acpi_madt_local_apic {
    struct acpi_madt_entry_header header;
    uint8_t acpi_processor_id;
    uint8_t apic_id;
    uint32_t flags;           /* Bit 0 = Enabled, Bit 1 = Online Capable */
} __attribute__((packed));

/* Type 1: I/O APIC */
struct acpi_madt_io_apic {
    struct acpi_madt_entry_header header;
    uint8_t io_apic_id;
    uint8_t reserved;
    uint32_t io_apic_address;
    uint32_t global_system_interrupt_base;
} __attribute__((packed));

/* Type 2: Interrupt Source Override (ISO) */
struct acpi_madt_iso {
    struct acpi_madt_entry_header header;
    uint8_t bus;              /* 0 = ISA */
    uint8_t source_irq;       /* ISA IRQ */
    uint32_t global_system_interrupt; /* GSI */
    uint16_t flags;           /* Polarity & Trigger mode */
} __attribute__((packed));

/* Type 4: Local APIC NMI */
struct acpi_madt_nmi {
    struct acpi_madt_entry_header header;
    uint8_t acpi_processor_id; /* 0xFF = All processors */
    uint16_t flags;
    uint8_t lint;             /* LINT0 or LINT1 */
} __attribute__((packed));

/* Type 5: 64-bit Local APIC Address Override */
struct acpi_madt_lapic64 {
    struct acpi_madt_entry_header header;
    uint16_t reserved;
    uint64_t local_apic_address;
} __attribute__((packed));

/* Parsed Information Structures */
struct acpi_cpu_entry {
    uint8_t acpi_id;
    uint8_t lapic_id;
    bool enabled;
};

struct acpi_ioapic_entry {
    uint8_t id;
    uint32_t address;
    uint32_t gsi_base;
    uint32_t max_redirections;
};

struct acpi_iso_entry {
    uint8_t bus;
    uint8_t source_irq;
    uint32_t gsi;
    uint16_t flags;
};

/* Core ACPI API */
bool acpi_initialize(void);
const struct acpi_sdt_header *acpi_find_table(const char *signature);
bool acpi_verify_table_checksum(const struct acpi_sdt_header *header);

uint64_t acpi_get_lapic_address(void);
bool acpi_has_pcat_dual_pic(void);

uint32_t acpi_get_cpu_count(void);
const struct acpi_cpu_entry *acpi_get_cpu(uint32_t index);

uint32_t acpi_get_ioapic_count(void);
const struct acpi_ioapic_entry *acpi_get_ioapic(uint32_t index);

uint32_t acpi_get_iso_count(void);
const struct acpi_iso_entry *acpi_get_iso(uint32_t index);
const struct acpi_iso_entry *acpi_find_iso_for_irq(uint8_t source_irq);

#endif /* KOS_ACPI_H */
