#ifndef KOS_PIC_H
#define KOS_PIC_H

#include <stdbool.h>
#include <stdint.h>

enum {
    KOS_PIC_MASTER_VECTOR = 32,
    KOS_PIC_SLAVE_VECTOR = 40,
    KOS_PIC_IRQ_TIMER = 0,
    KOS_PIC_IRQ_KEYBOARD = 1,
};

bool pic_initialize(void);
bool pic_unmask_irq(uint8_t irq);
bool pic_is_spurious_irq(uint8_t irq);
void pic_send_spurious_eoi(uint8_t irq);
void pic_send_eoi(uint8_t irq);
void pic_disable(void);

#endif
