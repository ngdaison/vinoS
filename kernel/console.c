#include <stdint.h>

#include <font8x8_basic.h>

#include <kos/console.h>
#include <kos/framebuffer.h>

enum {
    FONT_SOURCE_WIDTH = 8,
    FONT_SOURCE_HEIGHT = 8,
    FONT_SCALE_X = 2,
    FONT_SCALE_Y = 2,
    FONT_WIDTH = FONT_SOURCE_WIDTH * FONT_SCALE_X,
    FONT_HEIGHT = FONT_SOURCE_HEIGHT * FONT_SCALE_Y,
    TAB_WIDTH = 4,
    CURSOR_HEIGHT = 2,
};

struct kos_console {
    uint64_t columns;
    uint64_t rows;
    uint64_t column;
    uint64_t row;
    uint32_t foreground;
    uint32_t background;
    uint8_t initialized;
};

static struct kos_console console;

static void draw_glyph_row(uint64_t x, uint64_t y, uint8_t bits) {
    uint64_t run_start = 0;
    bool run_is_foreground = (bits & 1u) != 0;
    for (uint64_t glyph_column = 1; glyph_column <= FONT_SOURCE_WIDTH; ++glyph_column) {
        bool next_is_foreground = glyph_column < FONT_SOURCE_WIDTH
            && ((bits >> glyph_column) & 1u) != 0;
        if (glyph_column == FONT_SOURCE_WIDTH || next_is_foreground != run_is_foreground) {
            uint32_t color = run_is_foreground ? console.foreground : console.background;
            framebuffer_fill_rect(x + run_start * FONT_SCALE_X, y,
                (glyph_column - run_start) * FONT_SCALE_X, FONT_SCALE_Y, color);
            run_start = glyph_column;
            run_is_foreground = next_is_foreground;
        }
    }
}

static void draw_character(uint64_t column, uint64_t row, unsigned char character) {
    uint64_t x = column * FONT_WIDTH;
    uint64_t y = row * FONT_HEIGHT;
    unsigned char glyph = character;
    if (glyph < 32 || glyph > 126) {
        glyph = '?';
    }

    for (uint64_t glyph_row = 0; glyph_row < FONT_SOURCE_HEIGHT; ++glyph_row) {
        uint8_t bits = (uint8_t)font8x8_basic[glyph][glyph_row];
        draw_glyph_row(x, y + glyph_row * FONT_SCALE_Y, bits);
    }
}

static void erase_cursor(void) {
    draw_character(console.column, console.row, ' ');
}

static void draw_cursor(void) {
    uint64_t x = console.column * FONT_WIDTH;
    uint64_t y = console.row * FONT_HEIGHT + FONT_HEIGHT - CURSOR_HEIGHT;
    framebuffer_fill_rect(x, y, FONT_WIDTH, CURSOR_HEIGHT, console.foreground);
}

static void advance_line(void) {
    console.column = 0;
    ++console.row;
    if (console.row >= console.rows) {
        framebuffer_scroll_up(FONT_HEIGHT, console.background);
        console.row = console.rows - 1;
    }
}

bool console_initialize(void) {
    if (!framebuffer_is_initialized()) {
        return false;
    }

    console.columns = framebuffer_width() / FONT_WIDTH;
    console.rows = framebuffer_height() / FONT_HEIGHT;
    if (console.columns == 0 || console.rows == 0) {
        return false;
    }

    console.foreground = framebuffer_make_color(0xe8, 0xea, 0xed);
    console.background = framebuffer_make_color(0x18, 0x1b, 0x20);
    console.column = 0;
    console.row = 0;
    console.initialized = 1;
    framebuffer_fill(console.background);
    draw_cursor();
    return true;
}

bool console_is_initialized(void) {
    return console.initialized != 0;
}

uint64_t console_columns(void) {
    return console.columns;
}

uint64_t console_rows(void) {
    return console.rows;
}

void console_clear(void) {
    if (!console_is_initialized()) {
        return;
    }
    console.column = 0;
    console.row = 0;
    framebuffer_fill(console.background);
    draw_cursor();
}

void console_write_char(char character) {
    if (!console_is_initialized()) {
        return;
    }

    erase_cursor();
    if (character == '\n') {
        advance_line();
    }
    else if (character == '\r') {
        console.column = 0;
    }
    else if (character == '\t') {
        uint64_t spaces = TAB_WIDTH - (console.column % TAB_WIDTH);
        for (uint64_t index = 0; index < spaces; ++index) {
            console_write_char(' ');
        }
        return;
    }
    else if (character == '\b') {
        if (console.column > 0) {
            --console.column;
        }
        else if (console.row > 0) {
            --console.row;
            console.column = console.columns - 1;
        }
        draw_character(console.column, console.row, ' ');
    }
    else {
        draw_character(console.column, console.row, (unsigned char)character);
        ++console.column;
        if (console.column >= console.columns) {
            advance_line();
        }
    }
    draw_cursor();
}

void console_write(const char *text) {
    if (text == 0) {
        return;
    }
    while (*text != '\0') {
        console_write_char(*text);
        ++text;
    }
}
