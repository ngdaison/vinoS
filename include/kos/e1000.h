#ifndef KOS_E1000_H
#define KOS_E1000_H

#include <stdbool.h>
#include <stdint.h>

/* Intel 82540EM (the NIC exposed by QEMU's "-device e1000"). */
struct e1000_info {
    bool initialized;
    bool link_up;
    bool tx_pending;
    uint64_t transmitted_frames;
    uint64_t received_frames;
    uint64_t transmit_timeouts;
    uint64_t receive_errors;
    uint64_t resets;
    uint64_t recovery_failures;
    uint64_t link_changes;
    uint64_t last_activity_tick;
};

bool e1000_initialize(void);
bool e1000_is_initialized(void);
bool e1000_link_is_up(void);
void e1000_service(void);
bool e1000_get_info(struct e1000_info *info);
bool e1000_get_mac_address(uint8_t address[6]);
bool e1000_send_frame(const uint8_t *frame, uint64_t size);
bool e1000_wait_for_transmit(uint64_t timeout_ticks);
bool e1000_receive_frame(uint8_t *frame, uint64_t capacity, uint64_t *size);
uint64_t e1000_transmitted_frame_count(void);
uint64_t e1000_received_frame_count(void);
uint64_t e1000_transmit_timeout_count(void);

#endif
