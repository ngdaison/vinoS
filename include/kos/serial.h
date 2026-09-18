#ifndef KOS_SERIAL_H
#define KOS_SERIAL_H

#include <stdbool.h>
#include <stdint.h>

/* Normal serial driver interfaces */
void serial_initialize(void);
bool serial_is_initialized(void);
void serial_write(const char *text);
void serial_write_char(char character);

/* 
 * Emergency Polling Serial Bypass (K12.0 - Milestone 2)
 * Guarantees:
 * - Zero spinlocks/mutexes (cannot deadlock)
 * - Zero dynamic memory allocations (cannot run out of memory)
 * - Zero interrupt dependency (works with IF=0 or broken IDT)
 * - Auto-initializes hardware if called early or uninitialized
 * - Translates '\n' to '\r\n' (CRLF) automatically
 */
void serial_emergency_init(void);
void serial_emergency_putc(char c);
void serial_emergency_puts(const char *s);
void serial_emergency_put_hex(uint64_t value);
void serial_emergency_put_dec(uint64_t value);

#endif /* KOS_SERIAL_H */
