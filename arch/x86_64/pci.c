#include <stdbool.h>
#include <stdint.h>

#include <kos/io.h>
#include <kos/pci.h>

enum {
    PCI_CONFIGURATION_ADDRESS = 0xcf8,
    PCI_CONFIGURATION_DATA = 0xcfc,
    PCI_VENDOR_ID_OFFSET = 0x00,
    PCI_CLASS_OFFSET = 0x08,
    PCI_HEADER_TYPE_OFFSET = 0x0c,
    PCI_BAR0_OFFSET = 0x10,
    PCI_INTERRUPT_OFFSET = 0x3c,
    PCI_HEADER_MULTIFUNCTION = 0x80,
    PCI_HEADER_TYPE_MASK = 0x7f,
    PCI_CLASS_BRIDGE = 0x06,
    PCI_SUBCLASS_PCI_TO_PCI_BRIDGE = 0x04,
    PCI_SECONDARY_BUS_OFFSET = 0x19,
};

static struct pci_device devices[PCI_MAX_DISCOVERED_DEVICES];
static uint64_t discovered_device_count;
static bool visited_bus[256];

static uint32_t pci_configuration_address(uint8_t bus, uint8_t device, uint8_t function,
        uint8_t offset) {
    return 0x80000000u | ((uint32_t)bus << 16) | ((uint32_t)device << 11)
        | ((uint32_t)function << 8) | (offset & 0xfcu);
}

static uint32_t pci_read32(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset) {
    io_out32(PCI_CONFIGURATION_ADDRESS, pci_configuration_address(bus, device, function, offset));
    return io_in32(PCI_CONFIGURATION_DATA);
}

static void pci_write32(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset, uint32_t value) {
    io_out32(PCI_CONFIGURATION_ADDRESS, pci_configuration_address(bus, device, function, offset));
    io_out32(PCI_CONFIGURATION_DATA, value);
}

static uint16_t pci_read16(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset) {
    uint32_t value = pci_read32(bus, device, function, offset);
    return (uint16_t)(value >> ((offset & 2u) * 8u));
}

static uint8_t pci_read8(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset) {
    uint32_t value = pci_read32(bus, device, function, offset);
    return (uint8_t)(value >> ((offset & 3u) * 8u));
}

static void pci_scan_bus(uint8_t bus) {
    if (visited_bus[bus]) {
        return;
    }
    visited_bus[bus] = true;
    for (uint8_t device = 0; device < 32; ++device) {
        uint16_t vendor = pci_read16(bus, device, 0, PCI_VENDOR_ID_OFFSET);
        if (vendor == 0xffff) {
            continue;
        }
        uint8_t header = pci_read8(bus, device, 0, PCI_HEADER_TYPE_OFFSET);
        uint8_t function_count = (header & PCI_HEADER_MULTIFUNCTION) != 0 ? 8 : 1;
        for (uint8_t function = 0; function < function_count; ++function) {
            vendor = pci_read16(bus, device, function, PCI_VENDOR_ID_OFFSET);
            if (vendor == 0xffff) {
                continue;
            }
            uint32_t class_data = pci_read32(bus, device, function, PCI_CLASS_OFFSET);
            uint8_t class_code = (uint8_t)(class_data >> 24);
            uint8_t subclass = (uint8_t)(class_data >> 16);
            uint8_t header_type = (uint8_t)(pci_read8(bus, device, function,
                PCI_HEADER_TYPE_OFFSET) & PCI_HEADER_TYPE_MASK);
            if (discovered_device_count < PCI_MAX_DISCOVERED_DEVICES) {
                struct pci_device *found = &devices[discovered_device_count];
                *found = (struct pci_device){
                    .bus = bus, .device = device, .function = function,
                    .vendor_id = vendor,
                    .device_id = pci_read16(bus, device, function, 0x02),
                    .class_code = class_code, .subclass = subclass,
                    .programming_interface = (uint8_t)(class_data >> 8),
                    .header_type = header_type,
                    .interrupt_line = pci_read8(bus, device, function, PCI_INTERRUPT_OFFSET),
                    .interrupt_pin = pci_read8(bus, device, function, PCI_INTERRUPT_OFFSET + 1),
                };
                if (header_type == 0) {
                    for (uint8_t bar = 0; bar < 6; ++bar) {
                        found->bars[bar] = pci_read32(bus, device, function,
                            (uint8_t)(PCI_BAR0_OFFSET + bar * 4));
                    }
                }
                ++discovered_device_count;
            }
            if (class_code == PCI_CLASS_BRIDGE && subclass == PCI_SUBCLASS_PCI_TO_PCI_BRIDGE) {
                pci_scan_bus(pci_read8(bus, device, function, PCI_SECONDARY_BUS_OFFSET));
            }
        }
    }
}

bool pci_enumerate(void) {
    discovered_device_count = 0;
    for (uint16_t bus = 0; bus < 256; ++bus) {
        visited_bus[bus] = false;
    }
    pci_scan_bus(0);
    return true;
}

uint64_t pci_device_count(void) { return discovered_device_count; }

const struct pci_device *pci_device_at(uint64_t index) {
    return index < discovered_device_count ? &devices[index] : 0;
}

const struct pci_device *pci_find_device(uint16_t vendor_id, uint16_t device_id) {
    for (uint64_t index = 0; index < discovered_device_count; ++index) {
        if (devices[index].vendor_id == vendor_id && devices[index].device_id == device_id) {
            return &devices[index];
        }
    }
    return 0;
}

bool pci_enable_memory_bus_mastering(const struct pci_device *device) {
    if (device == 0 || pci_read16(device->bus, device->device, device->function,
            PCI_VENDOR_ID_OFFSET) != device->vendor_id) {
        return false;
    }
    uint32_t command_status = pci_read32(device->bus, device->device, device->function, 0x04);
    command_status |= (1u << 1) | (1u << 2);
    pci_write32(device->bus, device->device, device->function, 0x04, command_status);
    uint16_t command = pci_read16(device->bus, device->device, device->function, 0x04);
    return (command & ((1u << 1) | (1u << 2))) == ((1u << 1) | (1u << 2));
}
