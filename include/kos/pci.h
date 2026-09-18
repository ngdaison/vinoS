#ifndef KOS_PCI_H
#define KOS_PCI_H

#include <stdbool.h>
#include <stdint.h>

enum {
    PCI_MAX_DISCOVERED_DEVICES = 128,
};

struct pci_device {
    uint8_t bus;
    uint8_t device;
    uint8_t function;
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t class_code;
    uint8_t subclass;
    uint8_t programming_interface;
    uint8_t header_type;
    uint8_t interrupt_line;
    uint8_t interrupt_pin;
    uint32_t bars[6];
};

bool pci_enumerate(void);
uint64_t pci_device_count(void);
const struct pci_device *pci_device_at(uint64_t index);
const struct pci_device *pci_find_device(uint16_t vendor_id, uint16_t device_id);
bool pci_enable_memory_bus_mastering(const struct pci_device *device);

#endif
