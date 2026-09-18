#ifndef KOS_DRIVER_H
#define KOS_DRIVER_H

#include <stdbool.h>
#include <stdint.h>

#include <kos/interrupts.h>

enum driver_state {
    DRIVER_STATE_REGISTERED,
    DRIVER_STATE_READY,
    DRIVER_STATE_FAILED,
};

struct driver {
    const char *name;
    bool (*init)(void);
    void (*shutdown)(void);
    irq_handler irq_handler;
    enum driver_state state;
};

bool driver_register(struct driver *driver);
bool driver_initialize_all(void);
void driver_shutdown_all(void);
uint64_t driver_count(void);
const struct driver *driver_at(uint64_t index);

#endif
