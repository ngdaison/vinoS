#ifndef KOS_CONSOLE_H
#define KOS_CONSOLE_H

#include <stdbool.h>
#include <stdint.h>

bool console_initialize(void);
bool console_is_initialized(void);
uint64_t console_columns(void);
uint64_t console_rows(void);
void console_clear(void);
void console_write_char(char character);
void console_write(const char *text);

#endif
