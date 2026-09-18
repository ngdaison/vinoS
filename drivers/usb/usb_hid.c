#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/keyboard.h>
#include <kos/log.h>
#include <kos/usb.h>

static uint8_t prev_keycodes[6] = {0};
static int32_t mouse_x = 0;
static int32_t mouse_y = 0;
static uint8_t prev_mouse_buttons = 0;

static const char hid_ascii_table[128] = {
    0, 0, 0, 0,
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
    '\n', '\x1B', '\b', '\t', ' ', '-', '=', '[', ']', '\\', '#', ';', '\'',
    '`', ',', '.', '/',
};

static const char hid_ascii_shift_table[128] = {
    0, 0, 0, 0,
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    '!', '@', '#', '$', '%', '^', '&', '*', '(', ')',
    '\n', '\x1B', '\b', '\t', ' ', '_', '+', '{', '}', '|', '~', ':', '"',
    '~', '<', '>', '?',
};

void usb_hid_keyboard_handle_report(const struct usb_hid_keyboard_report *report) {
    if (report == 0) return;

    bool shift = (report->modifiers & 0x22) != 0; /* Left Shift (0x02) or Right Shift (0x20) */

    for (int i = 0; i < 6; ++i) {
        uint8_t kc = report->keycodes[i];
        if (kc == 0) continue;

        /* Check if this key was already pressed in the previous report */
        bool already_pressed = false;
        for (int j = 0; j < 6; ++j) {
            if (prev_keycodes[j] == kc) {
                already_pressed = true;
                break;
            }
        }

        if (!already_pressed && kc < sizeof(hid_ascii_table)) {
            char c = shift ? hid_ascii_shift_table[kc] : hid_ascii_table[kc];
            if (c != '\0') {
                keyboard_push_char(c);
            }
        }
    }

    for (int i = 0; i < 6; ++i) {
        prev_keycodes[i] = report->keycodes[i];
    }
}

void usb_hid_mouse_handle_report(const struct usb_hid_mouse_report *report) {
    if (report == 0) return;

    mouse_x += report->delta_x;
    mouse_y += report->delta_y;

    if (mouse_x < 0) mouse_x = 0;
    if (mouse_y < 0) mouse_y = 0;

    if (report->buttons != prev_mouse_buttons) {
        prev_mouse_buttons = report->buttons;
    }
}
