#include <stdint.h>

#include <kos/boot_protocol.h>
#include <kos/compiler.h>
#include <limine.h>

/*
 * Keep all protocol requests in their own sections. The linker script orders
 * the start marker, requests, and end marker in one loadable read-only segment.
 */
KOS_USED KOS_SECTION(".limine_requests_start")
static volatile uint64_t limine_requests_start_marker[4] = LIMINE_REQUESTS_START_MARKER;

KOS_USED KOS_SECTION(".limine_requests")
volatile uint64_t kos_limine_base_revision[3] = LIMINE_BASE_REVISION(3);

KOS_USED KOS_SECTION(".limine_requests")
static volatile struct limine_bootloader_info_request limine_bootloader_info_request = {
    .id = LIMINE_BOOTLOADER_INFO_REQUEST_ID,
    .revision = 0,
    .response = 0,
};

KOS_USED KOS_SECTION(".limine_requests")
volatile struct limine_framebuffer_request kos_framebuffer_request = {
    .id = LIMINE_FRAMEBUFFER_REQUEST_ID,
    .revision = 0,
    .response = 0,
};

KOS_USED KOS_SECTION(".limine_requests")
volatile struct limine_memmap_request kos_memmap_request = {
    .id = LIMINE_MEMMAP_REQUEST_ID,
    .revision = 0,
    .response = 0,
};

KOS_USED KOS_SECTION(".limine_requests")
volatile struct limine_hhdm_request kos_hhdm_request = {
    .id = LIMINE_HHDM_REQUEST_ID,
    .revision = 0,
    .response = 0,
};

KOS_USED KOS_SECTION(".limine_requests")
volatile struct limine_module_request kos_module_request = {
    .id = LIMINE_MODULE_REQUEST_ID,
    .revision = 0,
    .response = 0,
};

KOS_USED KOS_SECTION(".limine_requests")
volatile struct limine_rsdp_request kos_rsdp_request = {
    .id = LIMINE_RSDP_REQUEST_ID,
    .revision = 0,
    .response = 0,
};

KOS_USED KOS_SECTION(".limine_requests")
volatile struct limine_mp_request kos_mp_request = {
    .id = LIMINE_MP_REQUEST_ID,
    .revision = 0,
    .response = 0,
    .flags = 0,
};

KOS_USED KOS_SECTION(".limine_requests_end")
static volatile uint64_t limine_requests_end_marker[2] = LIMINE_REQUESTS_END_MARKER;
