#include <stdbool.h>
#include <stdint.h>

#include <kos/driver.h>

enum {
    DRIVER_MAX_COUNT = 32,
};

static struct driver *registered_drivers[DRIVER_MAX_COUNT];
static uint64_t registered_driver_count;

static bool strings_equal(const char *left, const char *right) {
    while (*left != '\0' && *right != '\0') {
        if (*left != *right) {
            return false;
        }
        ++left;
        ++right;
    }
    return *left == *right;
}

bool driver_register(struct driver *driver) {
    if (driver == 0 || driver->name == 0 || driver->init == 0
        || registered_driver_count >= DRIVER_MAX_COUNT) {
        return false;
    }
    for (uint64_t index = 0; index < registered_driver_count; ++index) {
        if (registered_drivers[index] == driver
            || strings_equal(registered_drivers[index]->name, driver->name)) {
            return false;
        }
    }
    driver->state = DRIVER_STATE_REGISTERED;
    registered_drivers[registered_driver_count] = driver;
    ++registered_driver_count;
    return true;
}

void driver_shutdown_all(void) {
    for (uint64_t index = registered_driver_count; index > 0; --index) {
        struct driver *driver = registered_drivers[index - 1];
        if (driver->state == DRIVER_STATE_READY && driver->shutdown != 0) {
            driver->shutdown();
        }
        if (driver->state != DRIVER_STATE_FAILED) {
            driver->state = DRIVER_STATE_REGISTERED;
        }
    }
}

bool driver_initialize_all(void) {
    for (uint64_t index = 0; index < registered_driver_count; ++index) {
        struct driver *driver = registered_drivers[index];
        if (driver->state == DRIVER_STATE_READY) {
            continue;
        }
        if (!driver->init()) {
            driver->state = DRIVER_STATE_FAILED;
            return false;
        }
        driver->state = DRIVER_STATE_READY;
    }
    return true;
}

uint64_t driver_count(void) {
    return registered_driver_count;
}

const struct driver *driver_at(uint64_t index) {
    return index < registered_driver_count ? registered_drivers[index] : 0;
}
