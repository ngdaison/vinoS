#include <stdbool.h>
#include <stdint.h>

#include <kos/framebuffer.h>

struct kos_framebuffer {
    volatile uint8_t *address;
    uint64_t width;
    uint64_t height;
    uint64_t pitch;
    uint8_t red_mask_shift;
    uint8_t green_mask_shift;
    uint8_t blue_mask_shift;
    bool initialized;
};

static struct kos_framebuffer framebuffer;

static bool channel_mask_is_valid(uint8_t shift, uint8_t size) {
    return size == 8 && shift <= 24;
}

bool framebuffer_initialize(const struct limine_framebuffer *source) {
    if (source == 0 || source->address == 0 || source->width == 0 || source->height == 0) {
        return false;
    }
    if (source->memory_model != LIMINE_FRAMEBUFFER_RGB || source->bpp != 32) {
        return false;
    }
    if (source->width > UINT64_MAX / sizeof(uint32_t)
        || source->pitch < source->width * sizeof(uint32_t)
        || source->pitch % sizeof(uint32_t) != 0) {
        return false;
    }
    if (!channel_mask_is_valid(source->red_mask_shift, source->red_mask_size)
        || !channel_mask_is_valid(source->green_mask_shift, source->green_mask_size)
        || !channel_mask_is_valid(source->blue_mask_shift, source->blue_mask_size)) {
        return false;
    }
    uint32_t red_mask = 0xffu << source->red_mask_shift;
    uint32_t green_mask = 0xffu << source->green_mask_shift;
    uint32_t blue_mask = 0xffu << source->blue_mask_shift;
    if ((red_mask & green_mask) != 0 || (red_mask & blue_mask) != 0 || (green_mask & blue_mask) != 0) {
        return false;
    }

    framebuffer.address = (volatile uint8_t *)source->address;
    framebuffer.width = source->width;
    framebuffer.height = source->height;
    framebuffer.pitch = source->pitch;
    framebuffer.red_mask_shift = source->red_mask_shift;
    framebuffer.green_mask_shift = source->green_mask_shift;
    framebuffer.blue_mask_shift = source->blue_mask_shift;
    framebuffer.initialized = true;
    return true;
}

bool framebuffer_is_initialized(void) {
    return framebuffer.initialized;
}

uint32_t framebuffer_make_color(uint8_t red, uint8_t green, uint8_t blue) {
    if (!framebuffer.initialized) {
        return 0;
    }
    return ((uint32_t)red << framebuffer.red_mask_shift)
        | ((uint32_t)green << framebuffer.green_mask_shift)
        | ((uint32_t)blue << framebuffer.blue_mask_shift);
}

uint64_t framebuffer_width(void) {
    return framebuffer.width;
}

uint64_t framebuffer_height(void) {
    return framebuffer.height;
}

uint64_t framebuffer_virtual_address(void) {
    return (uint64_t)framebuffer.address;
}

static volatile uint32_t *framebuffer_row(uint64_t row) {
    return (volatile uint32_t *)(framebuffer.address + row * framebuffer.pitch);
}

void framebuffer_fill_rect(uint64_t x, uint64_t y, uint64_t width, uint64_t height, uint32_t color) {
    if (!framebuffer.initialized || x >= framebuffer.width || y >= framebuffer.height) {
        return;
    }

    uint64_t end_x = x + width;
    uint64_t end_y = y + height;
    if (end_x > framebuffer.width || end_x < x) {
        end_x = framebuffer.width;
    }
    if (end_y > framebuffer.height || end_y < y) {
        end_y = framebuffer.height;
    }

    for (uint64_t row = y; row < end_y; ++row) {
        volatile uint32_t *destination = framebuffer_row(row) + x;
        for (uint64_t column = x; column < end_x; ++column) {
            *destination = color;
            ++destination;
        }
    }
}

void framebuffer_fill(uint32_t color) {
    framebuffer_fill_rect(0, 0, framebuffer.width, framebuffer.height, color);
}

void framebuffer_scroll_up(uint64_t pixel_rows, uint32_t fill_color) {
    if (!framebuffer.initialized || pixel_rows == 0) {
        return;
    }
    if (pixel_rows >= framebuffer.height) {
        framebuffer_fill(fill_color);
        return;
    }

    uint64_t remaining_rows = framebuffer.height - pixel_rows;
    for (uint64_t row = 0; row < remaining_rows; ++row) {
        volatile uint32_t *destination = framebuffer_row(row);
        volatile uint32_t *source = framebuffer_row(row + pixel_rows);
        for (uint64_t column = 0; column < framebuffer.width; ++column) {
            *destination = *source;
            ++destination;
            ++source;
        }
    }
    framebuffer_fill_rect(0, remaining_rows, framebuffer.width, pixel_rows, fill_color);
}
