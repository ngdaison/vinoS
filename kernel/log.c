#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kos/console.h>
#include <kos/cpu.h>
#include <kos/log.h>
#include <kos/serial.h>
#include <kos/sync.h>
#include <kos/timer.h>

/* Weak linkage declarations for forward compatibility with Task and Panic subsystems */
extern uint64_t task_current_id(void) __attribute__((weak));
extern uint64_t task_get_current_tid(void) __attribute__((weak));
extern uint64_t task_get_current_id(void) __attribute__((weak));
extern bool panic_is_active(void) __attribute__((weak));

/* Circular ring buffer configuration: 64 KiB power-of-two buffer */
#define LOG_BUFFER_SIZE  65536ULL
#define LOG_BUFFER_MASK  (LOG_BUFFER_SIZE - 1ULL)
#define LOG_LINE_MAX     512

struct log_ring_buffer {
    char data[LOG_BUFFER_SIZE];
    uint64_t head;            /* Monotonic write counter */
    uint64_t tail;            /* Monotonic read pointer */
    uint64_t dropped_bytes;   /* Bytes overwritten by wrap-around */
    uint64_t dropped_records; /* Lines truncated/discarded on wrap */
    uint64_t total_records;   /* Total log entries submitted */
};

/* Static state located in BSS */
static struct log_ring_buffer ring_buffer;
static struct kos_spinlock log_lock = KOS_SPINLOCK_INITIALIZER;
static log_level_t active_log_level = LOG_LEVEL_INFO;
static volatile bool log_emergency_mode = false;
static bool log_initialized = false;

static const char * const log_level_tags[] = {
    [LOG_LEVEL_DEBUG] = "[DEBUG]",
    [LOG_LEVEL_INFO]  = "[INFO ]",
    [LOG_LEVEL_WARN]  = "[WARN ]",
    [LOG_LEVEL_ERROR] = "[ERROR]",
    [LOG_LEVEL_PANIC] = "[PANIC]",
};

/* Safe task query with fallback to 0 for early-boot context */
static uint64_t log_query_current_tid(void) {
    if (task_current_id) {
        return task_current_id();
    }
    if (task_get_current_tid) {
        return task_get_current_tid();
    }
    if (task_get_current_id) {
        return task_get_current_id();
    }
    return 0;
}

/* =========================================================================
 * SECTION 1: FREESTANDING NON-ALLOCATING STRING FORMATTER
 * ========================================================================= */

struct format_output {
    char *buf;
    size_t size;
    size_t written;
};

static inline void format_putc(struct format_output *out, char c) {
    if (out->buf && out->size > 0) {
        if (out->written + 1 < out->size) {
            out->buf[out->written] = c;
        }
    }
    out->written++;
}

int kvsnprintf(char *buffer, size_t size, const char *format, va_list args) {
    if (!format) {
        if (buffer && size > 0) {
            buffer[0] = '\0';
        }
        return 0;
    }

    struct format_output out;
    out.buf = buffer;
    out.size = size;
    out.written = 0;

    for (const char *p = format; *p != '\0'; p++) {
        if (*p != '%') {
            format_putc(&out, *p);
            continue;
        }

        p++; /* Skip '%' */
        if (*p == '\0') {
            format_putc(&out, '%');
            break;
        }
        if (*p == '%') {
            format_putc(&out, '%');
            continue;
        }

        /* 1. Flags */
        bool left_align = false;
        bool zero_pad = false;
        while (*p == '-' || *p == '0') {
            if (*p == '-') {
                left_align = true;
            } else if (*p == '0') {
                zero_pad = true;
            }
            p++;
        }
        if (left_align) {
            zero_pad = false; /* '-' overrides '0' */
        }

        /* 2. Width */
        int width = 0;
        while (*p >= '0' && *p <= '9') {
            width = width * 10 + (*p - '0');
            p++;
        }

        /* 3. Precision */
        int precision = -1;
        if (*p == '.') {
            p++;
            precision = 0;
            while (*p >= '0' && *p <= '9') {
                precision = precision * 10 + (*p - '0');
                p++;
            }
        }

        /* 4. Length Modifiers */
        int is_long = 0; /* 0 = 32-bit int, 1 = 64-bit long / size_t, 2 = 64-bit long long */
        if (*p == 'l') {
            is_long = 1;
            p++;
            if (*p == 'l') {
                is_long = 2;
                p++;
            }
        } else if (*p == 'z') {
            is_long = 1;
            p++;
        } else if (*p == 'h') {
            p++;
            if (*p == 'h') {
                p++;
            }
        }

        /* 5. Conversion Specifiers */
        char spec = *p;

        if (spec == 'c') {
            char c = (char)va_arg(args, int);
            if (!left_align && width > 1) {
                for (int i = 0; i < width - 1; i++) {
                    format_putc(&out, ' ');
                }
            }
            format_putc(&out, c);
            if (left_align && width > 1) {
                for (int i = 0; i < width - 1; i++) {
                    format_putc(&out, ' ');
                }
            }
        } else if (spec == 's') {
            const char *str = va_arg(args, const char *);
            if (!str) {
                str = "(null)";
            }
            int len = 0;
            while (str[len] != '\0') {
                len++;
            }
            if (precision >= 0 && len > precision) {
                len = precision;
            }
            if (!left_align && width > len) {
                for (int i = 0; i < width - len; i++) {
                    format_putc(&out, ' ');
                }
            }
            for (int i = 0; i < len; i++) {
                format_putc(&out, str[i]);
            }
            if (left_align && width > len) {
                for (int i = 0; i < width - len; i++) {
                    format_putc(&out, ' ');
                }
            }
        } else if (spec == 'd' || spec == 'i') {
            int64_t val = (is_long > 0) ? va_arg(args, int64_t) : (int64_t)va_arg(args, int);
            bool negative = false;
            uint64_t uval;
            if (val < 0) {
                negative = true;
                uval = (uint64_t)(-(val + 1)) + 1ULL; /* Overflow-safe for INT64_MIN */
            } else {
                uval = (uint64_t)val;
            }

            char digits[32];
            int dlen = 0;
            if (uval == 0) {
                digits[dlen++] = '0';
            } else {
                while (uval > 0) {
                    digits[dlen++] = (char)('0' + (uval % 10));
                    uval /= 10;
                }
            }

            int total_len = dlen + (negative ? 1 : 0);
            if (!left_align) {
                if (zero_pad) {
                    if (negative) {
                        format_putc(&out, '-');
                    }
                    for (int i = 0; i < width - total_len; i++) {
                        format_putc(&out, '0');
                    }
                } else {
                    for (int i = 0; i < width - total_len; i++) {
                        format_putc(&out, ' ');
                    }
                    if (negative) {
                        format_putc(&out, '-');
                    }
                }
            } else {
                if (negative) {
                    format_putc(&out, '-');
                }
            }
            for (int i = dlen - 1; i >= 0; i--) {
                format_putc(&out, digits[i]);
            }
            if (left_align && width > total_len) {
                for (int i = 0; i < width - total_len; i++) {
                    format_putc(&out, ' ');
                }
            }
        } else if (spec == 'u') {
            uint64_t uval = (is_long > 0) ? va_arg(args, uint64_t) : (uint64_t)va_arg(args, unsigned int);
            char digits[32];
            int dlen = 0;
            if (uval == 0) {
                digits[dlen++] = '0';
            } else {
                while (uval > 0) {
                    digits[dlen++] = (char)('0' + (uval % 10));
                    uval /= 10;
                }
            }
            int total_len = dlen;
            if (!left_align) {
                char pad = zero_pad ? '0' : ' ';
                for (int i = 0; i < width - total_len; i++) {
                    format_putc(&out, pad);
                }
            }
            for (int i = dlen - 1; i >= 0; i--) {
                format_putc(&out, digits[i]);
            }
            if (left_align && width > total_len) {
                for (int i = 0; i < width - total_len; i++) {
                    format_putc(&out, ' ');
                }
            }
        } else if (spec == 'x' || spec == 'X') {
            uint64_t uval = (is_long > 0) ? va_arg(args, uint64_t) : (uint64_t)va_arg(args, unsigned int);
            const char *hex_chars = (spec == 'X') ? "0123456789ABCDEF" : "0123456789abcdef";
            char digits[32];
            int dlen = 0;
            if (uval == 0) {
                digits[dlen++] = '0';
            } else {
                while (uval > 0) {
                    digits[dlen++] = hex_chars[uval & 0x0f];
                    uval >>= 4;
                }
            }
            int total_len = dlen;
            if (!left_align) {
                char pad = zero_pad ? '0' : ' ';
                for (int i = 0; i < width - total_len; i++) {
                    format_putc(&out, pad);
                }
            }
            for (int i = dlen - 1; i >= 0; i--) {
                format_putc(&out, digits[i]);
            }
            if (left_align && width > total_len) {
                for (int i = 0; i < width - total_len; i++) {
                    format_putc(&out, ' ');
                }
            }
        } else if (spec == 'p') {
            void *ptr = va_arg(args, void *);
            uint64_t uval = (uint64_t)ptr;
            const char *hex_chars = "0123456789abcdef";
            char digits[16];
            int dlen = 0;
            if (uval == 0) {
                digits[dlen++] = '0';
            } else {
                while (uval > 0) {
                    digits[dlen++] = hex_chars[uval & 0x0f];
                    uval >>= 4;
                }
            }
            int total_len = dlen + 2; /* for "0x" prefix */
            if (!left_align && !zero_pad && width > total_len) {
                for (int i = 0; i < width - total_len; i++) {
                    format_putc(&out, ' ');
                }
            }
            format_putc(&out, '0');
            format_putc(&out, 'x');
            if (!left_align && zero_pad && width > total_len) {
                for (int i = 0; i < width - total_len; i++) {
                    format_putc(&out, '0');
                }
            }
            for (int i = dlen - 1; i >= 0; i--) {
                format_putc(&out, digits[i]);
            }
            if (left_align && width > total_len) {
                for (int i = 0; i < width - total_len; i++) {
                    format_putc(&out, ' ');
                }
            }
        } else {
            format_putc(&out, '%');
            format_putc(&out, spec);
        }
    }

    if (buffer && size > 0) {
        if (out.written < size) {
            buffer[out.written] = '\0';
        } else {
            buffer[size - 1] = '\0';
        }
    }

    return (int)out.written;
}

int ksnprintf(char *buffer, size_t size, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int written = kvsnprintf(buffer, size, format, args);
    va_end(args);
    return written;
}

/* =========================================================================
 * SECTION 2: PREFIX FORMATTING & RING BUFFER OPERATIONS
 * ========================================================================= */

size_t log_format_prefix(char *buf, size_t size, log_level_t level) {
    if (!buf || size == 0) {
        return 0;
    }

    /* 1. Monotonic uptime from timer */
    uint64_t sec = 0;
    uint64_t ms = 0;
    if (timer_is_initialized()) {
        uint64_t hz = timer_frequency_hz();
        uint64_t ticks = timer_ticks();
        if (hz > 0) {
            sec = ticks / hz;
            ms = (ticks % hz) * 1000ULL / hz;
        }
    }

    /* 2. Safe Thread ID */
    uint64_t tid = log_query_current_tid();

    /* 3. Level tag */
    const char *lvl_tag = "[UNKN ]";
    if ((unsigned int)level <= LOG_LEVEL_PANIC) {
        lvl_tag = log_level_tags[level];
    }

    /* 4. Format standardized prefix: [ sssss.mmm] [TID tid] [LEVEL] */
    int len = ksnprintf(buf, size, "[%5lu.%03lu] [TID %lu] %s ", sec, ms, tid, lvl_tag);
    if (len < 0) {
        buf[0] = '\0';
        return 0;
    }
    return (size_t)len < size ? (size_t)len : (size - 1);
}

void log_init(void) {
    uint64_t flags = spinlock_lock_irqsave(&log_lock);
    ring_buffer.head = 0;
    ring_buffer.tail = 0;
    ring_buffer.dropped_bytes = 0;
    ring_buffer.dropped_records = 0;
    ring_buffer.total_records = 0;
    ring_buffer.data[0] = '\0';
    active_log_level = LOG_LEVEL_INFO;
    log_emergency_mode = false;
    log_initialized = true;
    spinlock_unlock_irqrestore(&log_lock, flags);
}

void log_set_level(log_level_t level) {
    active_log_level = level;
}

log_level_t log_get_level(void) {
    return active_log_level;
}

static void log_ring_buffer_write_locked(const char *data, size_t len) {
    if (len == 0 || data == 0) {
        return;
    }

    if (len > LOG_BUFFER_SIZE) {
        data += (len - LOG_BUFFER_SIZE);
        len = LOG_BUFFER_SIZE;
    }

    for (size_t i = 0; i < len; i++) {
        ring_buffer.data[(ring_buffer.head + i) & LOG_BUFFER_MASK] = data[i];
    }
    ring_buffer.head += len;
    ring_buffer.total_records++;

    /* Manage circular wrap-around and line alignment */
    if (ring_buffer.head - ring_buffer.tail > LOG_BUFFER_SIZE) {
        uint64_t overflow = (ring_buffer.head - ring_buffer.tail) - LOG_BUFFER_SIZE;
        ring_buffer.tail += overflow;
        ring_buffer.dropped_bytes += overflow;

        /* Advance tail to next line boundary for clean dmesg output */
        while (ring_buffer.tail < ring_buffer.head &&
               ring_buffer.data[ring_buffer.tail & LOG_BUFFER_MASK] != '\n') {
            ring_buffer.tail++;
            ring_buffer.dropped_bytes++;
        }
        if (ring_buffer.tail < ring_buffer.head &&
            ring_buffer.data[ring_buffer.tail & LOG_BUFFER_MASK] == '\n') {
            ring_buffer.tail++;
            ring_buffer.dropped_bytes++;
            ring_buffer.dropped_records++;
        }
    }
}

size_t log_read_ring_buffer(char *buf, size_t max_len) {
    if (!buf || max_len == 0) {
        return 0;
    }

    uint64_t flags = spinlock_lock_irqsave(&log_lock);
    uint64_t head = ring_buffer.head;
    uint64_t tail = ring_buffer.tail;
    uint64_t available = head - tail;

    if (available == 0) {
        buf[0] = '\0';
        spinlock_unlock_irqrestore(&log_lock, flags);
        return 0;
    }

    size_t to_copy = (available < (max_len - 1)) ? (size_t)available : (max_len - 1);
    for (size_t i = 0; i < to_copy; i++) {
        buf[i] = ring_buffer.data[(tail + i) & LOG_BUFFER_MASK];
    }
    buf[to_copy] = '\0';

    spinlock_unlock_irqrestore(&log_lock, flags);
    return to_copy;
}

size_t log_read_from_offset(uint64_t *cursor, char *buf, size_t max_len) {
    if (!cursor || !buf || max_len == 0) {
        return 0;
    }

    uint64_t flags = spinlock_lock_irqsave(&log_lock);
    uint64_t head = ring_buffer.head;
    uint64_t tail = ring_buffer.tail;

    if (*cursor < tail) {
        *cursor = tail;
    }

    if (*cursor >= head) {
        buf[0] = '\0';
        spinlock_unlock_irqrestore(&log_lock, flags);
        return 0;
    }

    uint64_t available = head - *cursor;
    size_t to_copy = (available < (max_len - 1)) ? (size_t)available : (max_len - 1);
    for (size_t i = 0; i < to_copy; i++) {
        buf[i] = ring_buffer.data[(*cursor + i) & LOG_BUFFER_MASK];
    }
    buf[to_copy] = '\0';
    *cursor += to_copy;

    spinlock_unlock_irqrestore(&log_lock, flags);
    return to_copy;
}

uint64_t log_get_dropped_bytes(void) {
    uint64_t flags = spinlock_lock_irqsave(&log_lock);
    uint64_t val = ring_buffer.dropped_bytes;
    spinlock_unlock_irqrestore(&log_lock, flags);
    return val;
}

uint64_t log_get_dropped_records(void) {
    uint64_t flags = spinlock_lock_irqsave(&log_lock);
    uint64_t val = ring_buffer.dropped_records;
    spinlock_unlock_irqrestore(&log_lock, flags);
    return val;
}

uint64_t log_get_total_records(void) {
    uint64_t flags = spinlock_lock_irqsave(&log_lock);
    uint64_t val = ring_buffer.total_records;
    spinlock_unlock_irqrestore(&log_lock, flags);
    return val;
}

uint64_t log_get_total_written(void) {
    uint64_t flags = spinlock_lock_irqsave(&log_lock);
    uint64_t val = ring_buffer.head;
    spinlock_unlock_irqrestore(&log_lock, flags);
    return val;
}

void log_clear_ring_buffer(void) {
    uint64_t flags = spinlock_lock_irqsave(&log_lock);
    ring_buffer.tail = ring_buffer.head;
    spinlock_unlock_irqrestore(&log_lock, flags);
}

/* =========================================================================
 * SECTION 3: DUAL-PATH LOGGING (NORMAL & PANIC BYPASS)
 * ========================================================================= */

void log_emergency_putc(char c) {
    serial_emergency_putc(c);
}

void log_emergency_puts(const char *str) {
    serial_emergency_puts(str);
}

void log_enter_emergency_mode(void) {
    log_emergency_mode = true;
}

bool log_is_in_emergency_mode(void) {
    return log_emergency_mode;
}

void log_vwrite(log_level_t level, const char *fmt, va_list args) {
    if (!log_initialized) {
        log_init();
    }

    bool emergency = (level == LOG_LEVEL_PANIC) || log_emergency_mode;
    if (panic_is_active && panic_is_active()) {
        emergency = true;
    }

    if (level < active_log_level && !emergency) {
        return;
    }

    char line[LOG_LINE_MAX];
    size_t prefix_len = log_format_prefix(line, sizeof(line), level);
    size_t offset = prefix_len;

    int msg_len = kvsnprintf(line + offset, sizeof(line) - offset, fmt, args);
    if (msg_len > 0) {
        offset += (size_t)msg_len;
        if (offset >= sizeof(line)) {
            offset = sizeof(line) - 1;
        }
    }

    /* Ensure line concludes with newline */
    if (offset + 1 < sizeof(line)) {
        if (offset == 0 || line[offset - 1] != '\n') {
            line[offset++] = '\n';
            line[offset] = '\0';
        }
    } else {
        line[sizeof(line) - 2] = '\n';
        line[sizeof(line) - 1] = '\0';
        offset = sizeof(line) - 1;
    }

    /* Emergency / Panic Bypass Path: Non-blocking, zero locks */
    if (emergency) {
        if (spinlock_try_lock(&log_lock)) {
            log_ring_buffer_write_locked(line, offset);
            spinlock_unlock(&log_lock);
        }
        serial_emergency_puts(line);
        if (console_is_initialized()) {
            console_write(line);
        }
        return;
    }

    /* Normal Path: Protected RAM copy, serial/console written outside lock */
    uint64_t flags = spinlock_lock_irqsave(&log_lock);
    log_ring_buffer_write_locked(line, offset);
    spinlock_unlock_irqrestore(&log_lock, flags);

    serial_write(line);
    if (console_is_initialized()) {
        console_write(line);
    }
}

void log_write(log_level_t level, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_vwrite(level, fmt, args);
    va_end(args);
}

/* =========================================================================
 * SECTION 4: BACKWARD-COMPATIBILITY ADAPTERS
 * ========================================================================= */

void log_info(const char *message) {
    log_write(LOG_LEVEL_INFO, "%s", message);
}

void log_warn(const char *message) {
    log_write(LOG_LEVEL_WARN, "%s", message);
}

void log_error(const char *message) {
    log_write(LOG_LEVEL_ERROR, "%s", message);
}

void log_debug(const char *message) {
    log_write(LOG_LEVEL_DEBUG, "%s", message);
}

void log_panic(const char *message) {
    log_write(LOG_LEVEL_PANIC, "%s", message);
}

void log_serial(const char *message) {
    serial_write(message);
}

void log_info_u64(const char *label, uint64_t value) {
    log_write(LOG_LEVEL_INFO, "%s%lu", label, value);
}

void log_info_u64_suffix(const char *label, uint64_t value, const char *suffix) {
    log_write(LOG_LEVEL_INFO, "%s%lu%s", label, value, suffix);
}

void log_info_hex(const char *label, uint64_t value) {
    log_write(LOG_LEVEL_INFO, "%s0x%016lX", label, value);
}
