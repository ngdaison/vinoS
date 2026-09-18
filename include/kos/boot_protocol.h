#ifndef KOS_BOOT_PROTOCOL_H
#define KOS_BOOT_PROTOCOL_H

#include <stdint.h>
#include <limine.h>

/* Written by Limine when it accepts the requested base revision. */
extern volatile uint64_t kos_limine_base_revision[3];
extern volatile struct limine_framebuffer_request kos_framebuffer_request;
extern volatile struct limine_memmap_request kos_memmap_request;
extern volatile struct limine_hhdm_request kos_hhdm_request;
extern volatile struct limine_module_request kos_module_request;
extern volatile struct limine_rsdp_request kos_rsdp_request;
extern volatile struct limine_mp_request kos_mp_request;

#endif
