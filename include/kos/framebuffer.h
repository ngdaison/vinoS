#ifndef KOS_FRAMEBUFFER_H
#define KOS_FRAMEBUFFER_H

#include <stdbool.h>
#include <stdint.h>

#include <limine.h>

bool framebuffer_initialize(const struct limine_framebuffer *framebuffer);
bool framebuffer_is_initialized(void);
uint32_t framebuffer_make_color(uint8_t red, uint8_t green, uint8_t blue);
uint64_t framebuffer_width(void);
uint64_t framebuffer_height(void);
uint64_t framebuffer_virtual_address(void);
void framebuffer_fill(uint32_t color);
void framebuffer_fill_rect(uint64_t x, uint64_t y, uint64_t width, uint64_t height, uint32_t color);
void framebuffer_scroll_up(uint64_t pixel_rows, uint32_t fill_color);

#endif
