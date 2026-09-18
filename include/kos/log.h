#ifndef KOS_LOG_H
#define KOS_LOG_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kos/compiler.h>

/* Standard log levels (K12.0) */
typedef enum log_level {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO  = 1,
    LOG_LEVEL_WARN  = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_PANIC = 4,
} log_level_t;

/* Subsystem initialization and filter level control */
void log_init(void);
void log_set_level(log_level_t level);
log_level_t log_get_level(void);

/* Central formatted logging APIs */
void log_write(log_level_t level, const char *fmt, ...)
    __attribute__((__format__(__printf__, 2, 3)));
void log_vwrite(log_level_t level, const char *fmt, va_list args);

static inline void log_write_valist(log_level_t level, const char *fmt, va_list args) {
    log_vwrite(level, fmt, args);
}

/* Helper to construct standard prefix: [ sssss.mmm] [TID tid] [LEVEL] */
size_t log_format_prefix(char *buf, size_t size, log_level_t level);

/* 64 KiB Ring buffer query interfaces (for dmesg and diagnostics) */
size_t log_read_ring_buffer(char *buf, size_t max_len);
size_t log_read_from_offset(uint64_t *cursor, char *buf, size_t max_len);

/* Ring buffer statistics */
uint64_t log_get_dropped_bytes(void);
uint64_t log_get_dropped_records(void);
uint64_t log_get_total_records(void);
uint64_t log_get_total_written(void);
void log_clear_ring_buffer(void);

/*
 * Freestanding Non-Allocating String Formatter (Safe for kernel space)
 * Supports: %s, %c, %d, %i, %u, %x, %X, %p, %ld, %lu, %lx, %lX, %lld, %llu, %llx, %zd, %zu, width, flags 0, -, and precision
 */
int kvsnprintf(char *buffer, size_t size, const char *format, va_list args);
int ksnprintf(char *buffer, size_t size, const char *format, ...)
    __attribute__((__format__(__printf__, 3, 4)));

#ifndef vsnprintf
#define vsnprintf kvsnprintf
#endif
#ifndef snprintf
#define snprintf ksnprintf
#endif

/* Emergency Polling Serial Bypass interfaces (Panic / NMI path) */
void log_emergency_putc(char c);
void log_emergency_puts(const char *str);
void log_enter_emergency_mode(void);
bool log_is_in_emergency_mode(void);

/* Convenient formatted logging macros */
#define log_debugf(fmt, ...) log_write(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)
#define log_infof(fmt, ...)  log_write(LOG_LEVEL_INFO,  fmt, ##__VA_ARGS__)
#define log_warnf(fmt, ...)  log_write(LOG_LEVEL_WARN,  fmt, ##__VA_ARGS__)
#define log_errorf(fmt, ...) log_write(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)
#define log_panicf(fmt, ...) log_write(LOG_LEVEL_PANIC, fmt, ##__VA_ARGS__)

/* Backward-compatible legacy log functions */
void log_info(const char *message);
void log_warn(const char *message);
void log_error(const char *message);
void log_debug(const char *message);
void log_panic(const char *message);
void log_serial(const char *message);
void log_info_u64(const char *label, uint64_t value);
void log_info_u64_suffix(const char *label, uint64_t value, const char *suffix);
void log_info_hex(const char *label, uint64_t value);

#endif /* KOS_LOG_H */
