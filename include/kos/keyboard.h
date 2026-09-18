#ifndef KOS_KEYBOARD_H
#define KOS_KEYBOARD_H

#include <stdbool.h>
#include <stdint.h>

bool keyboard_initialize(void);
bool keyboard_is_initialized(void);
void keyboard_interrupt(void);
bool keyboard_read_char(char *character);
void keyboard_push_char(char character);
uint16_t keyboard_pending_count(void);
uint64_t keyboard_dropped_char_count(void);

#endif
