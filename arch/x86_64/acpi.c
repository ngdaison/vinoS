#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/acpi.h>
#include <kos/boot_protocol.h>
#include <kos/log.h>
#include <kos/vmm.h>

static const struct acpi_sdt_header *acpi_tables[64];
static uint32_t acpi_table_count = 0;

static uint64_t g_lapic_phys_address = 0xFEE00000;
static bool g_pcat_dual_pic = true;

static struct acpi_cpu_entry g_cpus[ACPI_MAX_CPUS];
static uint32_t g_cpu_count = 0;

static struct acpi_ioapic_entry g_ioapics[ACPI_MAX_IOAPICS];
static uint32_t g_ioapic_count = 0;

static struct acpi_iso_entry g_isos[ACPI_MAX_ISOS];
static uint32_t g_iso_count = 0;

static bool signature_matches(const char *sig1, const char *sig2, uint64_t len) {
    for (uint64_t i = 0; i < len; ++i) {
        if (sig1[i] != sig2[i]) return false;
    }
    return true;
}

bool acpi_verify_table_checksum(const struct acpi_sdt_header *header) {
    if (header == 0 || header->length < sizeof(struct acpi_sdt_header)) {
        return false;
    }
    const uint8_t *bytes = (const uint8_t *)header;
    uint8_t sum = 0;
    for (uint32_t i = 0; i < header->length; ++i) {
        sum = (uint8_t)(sum + bytes[i]);
    }
    return sum == 0;
}

static bool verify_rsdp_checksum(const struct acpi_rsdp_descriptor *rsdp) {
    const uint8_t *bytes = (const uint8_t *)rsdp;
    uint8_t sum = 0;
    for (uint32_t i = 0; i < sizeof(struct acpi_rsdp_descriptor); ++i) {
        sum = (uint8_t)(sum + bytes[i]);
    }
    if (sum != 0) return false;

    if (rsdp->revision >= 2) {
        const struct acpi_rsdp_descriptor20 *rsdp20 = (const struct acpi_rsdp_descriptor20 *)rsdp;
        const uint8_t *bytes20 = (const uint8_t *)rsdp20;
        sum = 0;
        for (uint32_t i = 0; i < rsdp20->length && i < sizeof(struct acpi_rsdp_descriptor20); ++i) {
            sum = (uint8_t)(sum + bytes20[i]);
        }
        return sum == 0;
    }
    return true;
}

static const struct acpi_rsdp_descriptor *find_rsdp(void) {
    /* 1. Check Limine Bootloader RSDP Response */
    if (kos_rsdp_request.response != 0 && kos_rsdp_request.response->address != 0) {
        uint64_t rsdp_addr = (uint64_t)kos_rsdp_request.response->address;
        const struct acpi_rsdp_descriptor *rsdp = (const struct acpi_rsdp_descriptor *)(
            rsdp_addr < 0xFFFF800000000000ull ? vmm_map_mmio(rsdp_addr, sizeof(struct acpi_rsdp_descriptor20))
                                              : (void *)rsdp_addr);
        if (rsdp != 0 && signature_matches(rsdp->signature, "RSD PTR ", 8) && verify_rsdp_checksum(rsdp)) {
            return rsdp;
        }
    }

    /* 2. Fallback: Scan Extended BIOS Data Area (EBDA) */
    uint16_t ebda_segment = *(const uint16_t *)vmm_physical_to_virtual(0x40E);
    uint64_t ebda_address = ((uint64_t)ebda_segment) << 4;
    if (ebda_address >= 0x80000 && ebda_address < 0xA0000) {
        const uint8_t *ebda_virt = (const uint8_t *)vmm_physical_to_virtual(ebda_address);
        for (uint64_t offset = 0; offset < 1024; offset += 16) {
            const struct acpi_rsdp_descriptor *rsdp = (const struct acpi_rsdp_descriptor *)(ebda_virt + offset);
            if (signature_matches(rsdp->signature, "RSD PTR ", 8) && verify_rsdp_checksum(rsdp)) {
                return rsdp;
            }
        }
    }

    /* 3. Fallback: Scan Main BIOS ROM Area 0x000E0000 - 0x000FFFFF */
    const uint8_t *bios_virt = (const uint8_t *)vmm_physical_to_virtual(0xE0000);
    for (uint64_t offset = 0; offset < (0x100000 - 0xE0000); offset += 16) {
        const struct acpi_rsdp_descriptor *rsdp = (const struct acpi_rsdp_descriptor *)(bios_virt + offset);
        if (signature_matches(rsdp->signature, "RSD PTR ", 8) && verify_rsdp_checksum(rsdp)) {
            return rsdp;
        }
    }

    return 0;
}

static void parse_madt(const struct acpi_madt *madt) {
    if (madt == 0) return;

    g_lapic_phys_address = madt->local_apic_address;
    g_pcat_dual_pic = (madt->flags & 1) != 0;

    const uint8_t *ptr = (const uint8_t *)madt + sizeof(struct acpi_madt);
    const uint8_t *end = (const uint8_t *)madt + madt->header.length;

    g_cpu_count = 0;
    g_ioapic_count = 0;
    g_iso_count = 0;

    while (ptr + sizeof(struct acpi_madt_entry_header) <= end) {
        const struct acpi_madt_entry_header *entry = (const struct acpi_madt_entry_header *)ptr;
        if (entry->length < sizeof(struct acpi_madt_entry_header) || ptr + entry->length > end) {
            break;
        }

        switch (entry->type) {
            case ACPI_MADT_TYPE_LOCAL_APIC: {
                if (entry->length >= sizeof(struct acpi_madt_local_apic) && g_cpu_count < ACPI_MAX_CPUS) {
                    const struct acpi_madt_local_apic *lapic = (const struct acpi_madt_local_apic *)entry;
                    bool enabled = (lapic->flags & 1) != 0 || (lapic->flags & 2) != 0;
                    g_cpus[g_cpu_count].acpi_id = lapic->acpi_processor_id;
                    g_cpus[g_cpu_count].lapic_id = lapic->apic_id;
                    g_cpus[g_cpu_count].enabled = enabled;
                    g_cpu_count++;
                }
                break;
            }
            case ACPI_MADT_TYPE_IO_APIC: {
                if (entry->length >= sizeof(struct acpi_madt_io_apic) && g_ioapic_count < ACPI_MAX_IOAPICS) {
                    const struct acpi_madt_io_apic *ioapic = (const struct acpi_madt_io_apic *)entry;
                    g_ioapics[g_ioapic_count].id = ioapic->io_apic_id;
                    g_ioapics[g_ioapic_count].address = ioapic->io_apic_address;
                    g_ioapics[g_ioapic_count].gsi_base = ioapic->global_system_interrupt_base;
                    g_ioapics[g_ioapic_count].max_redirections = 24; /* Default fallback */
                    g_ioapic_count++;
                }
                break;
            }
            case ACPI_MADT_TYPE_INTERRUPT_OVERRIDE: {
                if (entry->length >= sizeof(struct acpi_madt_iso) && g_iso_count < ACPI_MAX_ISOS) {
                    const struct acpi_madt_iso *iso = (const struct acpi_madt_iso *)entry;
                    g_isos[g_iso_count].bus = iso->bus;
                    g_isos[g_iso_count].source_irq = iso->source_irq;
                    g_isos[g_iso_count].gsi = iso->global_system_interrupt;
                    g_isos[g_iso_count].flags = iso->flags;
                    g_iso_count++;
                }
                break;
            }
            case ACPI_MADT_TYPE_LOCAL_APIC_OVERRIDE: {
                if (entry->length >= sizeof(struct acpi_madt_lapic64)) {
                    const struct acpi_madt_lapic64 *lapic64 = (const struct acpi_madt_lapic64 *)entry;
                    g_lapic_phys_address = lapic64->local_apic_address;
                }
                break;
            }
            default:
                break;
        }
        ptr += entry->length;
    }
}

bool acpi_initialize(void) {
    const struct acpi_rsdp_descriptor *rsdp = find_rsdp();
    if (rsdp == 0) {
        log_warn("ACPI: RSDP table not found; system may not support ACPI.");
        return false;
    }

    char oem_str[7] = {0};
    for (int i = 0; i < 6; ++i) oem_str[i] = rsdp->oem_id[i];
    log_infof("ACPI: RSDP found (OEM: %s, Revision: %u)", oem_str, (unsigned)rsdp->revision);

    acpi_table_count = 0;

    if (rsdp->revision >= 2) {
        const struct acpi_rsdp_descriptor20 *rsdp20 = (const struct acpi_rsdp_descriptor20 *)rsdp;
        if (rsdp20->xsdt_address != 0) {
            const struct acpi_sdt_header *xsdt = (const struct acpi_sdt_header *)vmm_map_mmio(rsdp20->xsdt_address, sizeof(struct acpi_sdt_header));
            if (xsdt != 0 && signature_matches(xsdt->signature, "XSDT", 4)) {
                xsdt = (const struct acpi_sdt_header *)vmm_map_mmio(rsdp20->xsdt_address, xsdt->length);
                if (xsdt != 0 && acpi_verify_table_checksum(xsdt)) {
                    uint32_t entries = (xsdt->length - sizeof(struct acpi_sdt_header)) / 8;
                    const uint64_t *pointers = (const uint64_t *)((const uint8_t *)xsdt + sizeof(struct acpi_sdt_header));
                    for (uint32_t i = 0; i < entries && acpi_table_count < 64; ++i) {
                        if (pointers[i] != 0) {
                            const struct acpi_sdt_header *tbl_hdr = (const struct acpi_sdt_header *)vmm_map_mmio(pointers[i], sizeof(struct acpi_sdt_header));
                            if (tbl_hdr != 0) {
                                const struct acpi_sdt_header *tbl = (const struct acpi_sdt_header *)vmm_map_mmio(pointers[i], tbl_hdr->length);
                                if (tbl != 0 && acpi_verify_table_checksum(tbl)) {
                                    acpi_tables[acpi_table_count++] = tbl;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /* Fallback to RSDT if XSDT produced no valid tables */
    if (acpi_table_count == 0 && rsdp->rsdt_address != 0) {
        const struct acpi_sdt_header *rsdt = (const struct acpi_sdt_header *)vmm_map_mmio(rsdp->rsdt_address, sizeof(struct acpi_sdt_header));
        if (rsdt != 0 && signature_matches(rsdt->signature, "RSDT", 4)) {
            rsdt = (const struct acpi_sdt_header *)vmm_map_mmio(rsdp->rsdt_address, rsdt->length);
            if (rsdt != 0 && acpi_verify_table_checksum(rsdt)) {
                uint32_t entries = (rsdt->length - sizeof(struct acpi_sdt_header)) / 4;
                const uint32_t *pointers = (const uint32_t *)((const uint8_t *)rsdt + sizeof(struct acpi_sdt_header));
                for (uint32_t i = 0; i < entries && acpi_table_count < 64; ++i) {
                    if (pointers[i] != 0) {
                        const struct acpi_sdt_header *tbl_hdr = (const struct acpi_sdt_header *)vmm_map_mmio((uint64_t)pointers[i], sizeof(struct acpi_sdt_header));
                        if (tbl_hdr != 0) {
                            const struct acpi_sdt_header *tbl = (const struct acpi_sdt_header *)vmm_map_mmio((uint64_t)pointers[i], tbl_hdr->length);
                            if (tbl != 0 && acpi_verify_table_checksum(tbl)) {
                                acpi_tables[acpi_table_count++] = tbl;
                            }
                        }
                    }
                }
            }
        }
    }

    log_infof("ACPI: Discovered %u verified system description tables.", (unsigned)acpi_table_count);

    /* Parse Multiple APIC Description Table (MADT / "APIC") */
    const struct acpi_madt *madt = (const struct acpi_madt *)acpi_find_table("APIC");
    if (madt != 0) {
        parse_madt(madt);
        log_infof("ACPI: MADT parsed -> LAPIC Base: 0x%lX, CPUs: %u, IOAPICs: %u, ISOs: %u",
                  (unsigned long)g_lapic_phys_address, (unsigned)g_cpu_count,
                  (unsigned)g_ioapic_count, (unsigned)g_iso_count);
    } else {
        log_warn("ACPI: MADT table not found.");
    }

    return true;
}

const struct acpi_sdt_header *acpi_find_table(const char *signature) {
    if (signature == 0) return 0;
    for (uint32_t i = 0; i < acpi_table_count; ++i) {
        if (acpi_tables[i] != 0 && signature_matches(acpi_tables[i]->signature, signature, 4)) {
            return acpi_tables[i];
        }
    }
    return 0;
}

uint64_t acpi_get_lapic_address(void) { return g_lapic_phys_address; }
bool acpi_has_pcat_dual_pic(void) { return g_pcat_dual_pic; }

uint32_t acpi_get_cpu_count(void) { return g_cpu_count; }
const struct acpi_cpu_entry *acpi_get_cpu(uint32_t index) {
    return index < g_cpu_count ? &g_cpus[index] : 0;
}

uint32_t acpi_get_ioapic_count(void) { return g_ioapic_count; }
const struct acpi_ioapic_entry *acpi_get_ioapic(uint32_t index) {
    return index < g_ioapic_count ? &g_ioapics[index] : 0;
}

uint32_t acpi_get_iso_count(void) { return g_iso_count; }
const struct acpi_iso_entry *acpi_get_iso(uint32_t index) {
    return index < g_iso_count ? &g_isos[index] : 0;
}

const struct acpi_iso_entry *acpi_find_iso_for_irq(uint8_t source_irq) {
    for (uint32_t i = 0; i < g_iso_count; ++i) {
        if (g_isos[i].source_irq == source_irq) {
            return &g_isos[i];
        }
    }
    return 0;
}
