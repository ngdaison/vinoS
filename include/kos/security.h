#ifndef KOS_SECURITY_H
#define KOS_SECURITY_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/compiler.h>

bool security_has_smep(void);
bool security_has_smap(void);
bool security_has_nx(void);

void security_init_bsp(void);
void security_init_ap(void);

bool security_verify_wx_policy(void);

extern uintptr_t __stack_chk_guard;
KOS_NORETURN void __stack_chk_fail(void);

#endif
