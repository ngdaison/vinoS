#ifndef KOS_OBJECT_H
#define KOS_OBJECT_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/atomic.h>
#include <kos/compiler.h>
#include <kos/spinlock.h>

/*
 * Kernel Object Types (K12.14)
 */
enum kos_object_type {
    KOS_OBJ_NONE = 0,
    KOS_OBJ_THREAD,
    KOS_OBJ_PROCESS,
    KOS_OBJ_MUTEX,
    KOS_OBJ_SEMAPHORE,
    KOS_OBJ_EVENT,
    KOS_OBJ_FILE,
    KOS_OBJ_SOCKET,
    KOS_OBJ_WAIT_QUEUE,
    KOS_OBJ_MAX
};

/* Custom Destructor Callback Type */
typedef void (*kos_object_destructor_t)(void *object);

/*
 * Kernel Object Header (K12.14):
 * Embedded in all refcounted kernel objects.
 */
struct kos_object_header {
    enum kos_object_type type;
    atomic_t refcount;
    kos_object_destructor_t destructor;
    kos_spinlock_t lock;
};

/* Core Kernel Object APIs */
void kos_object_init(struct kos_object_header *hdr, enum kos_object_type type, kos_object_destructor_t destructor);
void kos_object_ref(struct kos_object_header *hdr);
void kos_object_unref(struct kos_object_header *hdr);
int32_t kos_object_get_refcount(const struct kos_object_header *hdr);
const char *kos_object_type_name(enum kos_object_type type);

#endif /* KOS_OBJECT_H */
