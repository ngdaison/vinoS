#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/atomic.h>
#include <kos/compiler.h>
#include <kos/spinlock.h>
#include <kos/object.h>

void kos_object_init(struct kos_object_header *hdr, enum kos_object_type type, kos_object_destructor_t destructor) {
    if (hdr == NULL) {
        return;
    }
    hdr->type = type;
    atomic_set(&hdr->refcount, 1);
    hdr->destructor = destructor;
    spinlock_init(&hdr->lock);
}

void kos_object_ref(struct kos_object_header *hdr) {
    if (hdr == NULL) {
        return;
    }
    atomic_inc(&hdr->refcount);
}

void kos_object_unref(struct kos_object_header *hdr) {
    if (hdr == NULL) {
        return;
    }
    if (atomic_dec_and_test(&hdr->refcount)) {
        if (hdr->destructor != NULL) {
            hdr->destructor(hdr);
        }
    }
}

int32_t kos_object_get_refcount(const struct kos_object_header *hdr) {
    if (hdr == NULL) {
        return 0;
    }
    return atomic_read(&hdr->refcount);
}

const char *kos_object_type_name(enum kos_object_type type) {
    switch (type) {
        case KOS_OBJ_NONE:       return "NONE";
        case KOS_OBJ_THREAD:     return "THREAD";
        case KOS_OBJ_PROCESS:    return "PROCESS";
        case KOS_OBJ_MUTEX:      return "MUTEX";
        case KOS_OBJ_SEMAPHORE:  return "SEMAPHORE";
        case KOS_OBJ_EVENT:      return "EVENT";
        case KOS_OBJ_FILE:       return "FILE";
        case KOS_OBJ_SOCKET:     return "SOCKET";
        case KOS_OBJ_WAIT_QUEUE: return "WAIT_QUEUE";
        default:                 return "UNKNOWN";
    }
}
