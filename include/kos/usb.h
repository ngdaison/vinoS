#ifndef KOS_USB_H
#define KOS_USB_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/compiler.h>

/* USB Standard Descriptor Types */
#define USB_DESC_TYPE_DEVICE        0x01
#define USB_DESC_TYPE_CONFIG        0x02
#define USB_DESC_TYPE_STRING        0x03
#define USB_DESC_TYPE_INTERFACE     0x04
#define USB_DESC_TYPE_ENDPOINT      0x05
#define USB_DESC_TYPE_HID           0x21
#define USB_DESC_TYPE_REPORT        0x22

/* USB Class Codes */
#define USB_CLASS_PER_INTERFACE     0x00
#define USB_CLASS_AUDIO             0x01
#define USB_CLASS_COMMUNICATION     0x02
#define USB_CLASS_HID               0x03
#define USB_CLASS_MASS_STORAGE      0x08
#define USB_CLASS_HUB               0x09

/* USB HID Subclasses & Protocols */
#define USB_HID_SUBCLASS_BOOT       0x01
#define USB_HID_PROTOCOL_KEYBOARD   0x01
#define USB_HID_PROTOCOL_MOUSE      0x02

struct usb_device_descriptor {
    uint8_t length;
    uint8_t descriptor_type;
    uint16_t bcd_usb;
    uint8_t device_class;
    uint8_t device_subclass;
    uint8_t device_protocol;
    uint8_t max_packet_size0;
    uint16_t vendor_id;
    uint16_t product_id;
    uint16_t bcd_device;
    uint8_t manufacturer_index;
    uint8_t product_index;
    uint8_t serial_index;
    uint8_t num_configurations;
} __attribute__((packed));

struct usb_configuration_descriptor {
    uint8_t length;
    uint8_t descriptor_type;
    uint16_t total_length;
    uint8_t num_interfaces;
    uint8_t configuration_value;
    uint8_t configuration_index;
    uint8_t attributes;
    uint8_t max_power;
} __attribute__((packed));

struct usb_interface_descriptor {
    uint8_t length;
    uint8_t descriptor_type;
    uint8_t interface_number;
    uint8_t alternate_setting;
    uint8_t num_endpoints;
    uint8_t interface_class;
    uint8_t interface_subclass;
    uint8_t interface_protocol;
    uint8_t interface_index;
} __attribute__((packed));

struct usb_endpoint_descriptor {
    uint8_t length;
    uint8_t descriptor_type;
    uint8_t endpoint_address;
    uint8_t attributes;
    uint16_t max_packet_size;
    uint8_t interval;
} __attribute__((packed));

struct usb_hid_descriptor {
    uint8_t length;
    uint8_t descriptor_type;
    uint16_t bcd_hid;
    uint8_t country_code;
    uint8_t num_descriptors;
    uint8_t report_descriptor_type;
    uint16_t report_descriptor_length;
} __attribute__((packed));

/* USB HID Boot Protocol Reports */
struct usb_hid_keyboard_report {
    uint8_t modifiers;
    uint8_t reserved;
    uint8_t keycodes[6];
} __attribute__((packed));

struct usb_hid_mouse_report {
    uint8_t buttons;
    int8_t delta_x;
    int8_t delta_y;
    int8_t wheel;
} __attribute__((packed));

/* USB HID Handlers */
void usb_hid_keyboard_handle_report(const struct usb_hid_keyboard_report *report);
void usb_hid_mouse_handle_report(const struct usb_hid_mouse_report *report);

#endif /* KOS_USB_H */
