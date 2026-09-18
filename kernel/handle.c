#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/compiler.h>
#include <kos/heap.h>
#include <kos/spinlock.h>
#include <kos/object.h>
#include <kos/handle.h>
#include <kos/process.h>

struct handle_table *handle_table_create(void) {
    struct handle_table *table = (struct handle_table *)kmalloc(sizeof(struct handle_table));
    if (table == NULL) {
        return NULL;
    }

    spinlock_init(&table->lock);
    table->count = 0;
    for (uint32_t i = 0; i < KOS_HANDLE_TABLE_CAPACITY; i++) {
        table->entries[i].object = NULL;
        table->entries[i].rights = KOS_RIGHT_NONE;
        table->entries[i].generation = 1;
        table->entries[i].in_use = false;
    }

    return table;
}

void handle_table_destroy(struct handle_table *table) {
    if (table == NULL) {
        return;
    }

    struct kos_object_header *objs_to_unref[KOS_HANDLE_TABLE_CAPACITY];
    uint32_t unref_count = 0;

    uint64_t flags = spinlock_lock_irqsave(&table->lock);
    for (uint32_t i = 0; i < KOS_HANDLE_TABLE_CAPACITY; i++) {
        if (table->entries[i].in_use && table->entries[i].object != NULL) {
            objs_to_unref[unref_count++] = table->entries[i].object;
            table->entries[i].in_use = false;
            table->entries[i].object = NULL;
            table->entries[i].rights = KOS_RIGHT_NONE;
            table->entries[i].generation++;
            if (table->entries[i].generation == 0) {
                table->entries[i].generation = 1;
            }
        }
    }
    table->count = 0;
    spinlock_unlock_irqrestore(&table->lock, flags);

    /* Unref objects outside of table spinlock to avoid lock inversions in destructors */
    for (uint32_t i = 0; i < unref_count; i++) {
        kos_object_unref(objs_to_unref[i]);
    }

    (void)kfree(table);
}

handle_t handle_create(struct process *proc, void *object, uint32_t rights) {
    if (proc == NULL || object == NULL) {
        return KOS_INVALID_HANDLE;
    }

    struct handle_table *table = proc->handles;
    if (table == NULL) {
        return KOS_INVALID_HANDLE;
    }

    struct kos_object_header *hdr = (struct kos_object_header *)object;

    uint64_t flags = spinlock_lock_irqsave(&table->lock);

    for (uint32_t i = 0; i < KOS_HANDLE_TABLE_CAPACITY; i++) {
        if (!table->entries[i].in_use) {
            table->entries[i].in_use = true;
            table->entries[i].object = hdr;
            table->entries[i].rights = rights;
            if (table->entries[i].generation == 0) {
                table->entries[i].generation = 1;
            }
            uint16_t gen = table->entries[i].generation;
            table->count++;

            kos_object_ref(hdr);

            spinlock_unlock_irqrestore(&table->lock, flags);
            return KOS_MAKE_HANDLE(i, gen);
        }
    }

    spinlock_unlock_irqrestore(&table->lock, flags);
    return KOS_INVALID_HANDLE;
}

void *handle_lookup(struct process *proc, handle_t handle, uint32_t required_rights) {
    if (proc == NULL || handle == KOS_INVALID_HANDLE) {
        return NULL;
    }

    struct handle_table *table = proc->handles;
    if (table == NULL) {
        return NULL;
    }

    uint16_t index = KOS_HANDLE_INDEX(handle);
    uint16_t gen = KOS_HANDLE_GEN(handle);

    if (index >= KOS_HANDLE_TABLE_CAPACITY) {
        return NULL;
    }

    uint64_t flags = spinlock_lock_irqsave(&table->lock);

    if (!table->entries[index].in_use || table->entries[index].generation != gen) {
        spinlock_unlock_irqrestore(&table->lock, flags);
        return NULL;
    }

    if ((table->entries[index].rights & required_rights) != required_rights) {
        spinlock_unlock_irqrestore(&table->lock, flags);
        return NULL;
    }

    void *obj = (void *)table->entries[index].object;

    spinlock_unlock_irqrestore(&table->lock, flags);
    return obj;
}

void *handle_lookup_type(struct process *proc, handle_t handle, enum kos_object_type type, uint32_t required_rights) {
    void *obj = handle_lookup(proc, handle, required_rights);
    if (obj == NULL) {
        return NULL;
    }

    struct kos_object_header *hdr = (struct kos_object_header *)obj;
    if (hdr->type != type) {
        return NULL;
    }

    return obj;
}

bool handle_close(struct process *proc, handle_t handle) {
    if (proc == NULL || handle == KOS_INVALID_HANDLE) {
        return false;
    }

    struct handle_table *table = proc->handles;
    if (table == NULL) {
        return false;
    }

    uint16_t index = KOS_HANDLE_INDEX(handle);
    uint16_t gen = KOS_HANDLE_GEN(handle);

    if (index >= KOS_HANDLE_TABLE_CAPACITY) {
        return false;
    }

    struct kos_object_header *obj_to_unref = NULL;

    uint64_t flags = spinlock_lock_irqsave(&table->lock);

    if (!table->entries[index].in_use || table->entries[index].generation != gen) {
        spinlock_unlock_irqrestore(&table->lock, flags);
        return false;
    }

    obj_to_unref = table->entries[index].object;
    table->entries[index].in_use = false;
    table->entries[index].object = NULL;
    table->entries[index].rights = KOS_RIGHT_NONE;
    table->entries[index].generation++;
    if (table->entries[index].generation == 0) {
        table->entries[index].generation = 1;
    }
    if (table->count > 0) {
        table->count--;
    }

    spinlock_unlock_irqrestore(&table->lock, flags);

    if (obj_to_unref != NULL) {
        kos_object_unref(obj_to_unref);
    }

    return true;
}

handle_t handle_duplicate(struct process *src_proc, struct process *dst_proc, handle_t handle, uint32_t new_rights) {
    if (src_proc == NULL || dst_proc == NULL || handle == KOS_INVALID_HANDLE) {
        return KOS_INVALID_HANDLE;
    }

    struct handle_table *src_table = src_proc->handles;
    struct handle_table *dst_table = dst_proc->handles;
    if (src_table == NULL || dst_table == NULL) {
        return KOS_INVALID_HANDLE;
    }

    uint16_t index = KOS_HANDLE_INDEX(handle);
    uint16_t gen = KOS_HANDLE_GEN(handle);

    if (index >= KOS_HANDLE_TABLE_CAPACITY) {
        return KOS_INVALID_HANDLE;
    }

    uint64_t src_flags = spinlock_lock_irqsave(&src_table->lock);

    if (!src_table->entries[index].in_use || src_table->entries[index].generation != gen) {
        spinlock_unlock_irqrestore(&src_table->lock, src_flags);
        return KOS_INVALID_HANDLE;
    }

    /* Duplication requires KOS_RIGHT_DUPLICATE */
    if ((src_table->entries[index].rights & KOS_RIGHT_DUPLICATE) == 0) {
        spinlock_unlock_irqrestore(&src_table->lock, src_flags);
        return KOS_INVALID_HANDLE;
    }

    /* If new_rights is 0, preserve source handle rights; otherwise attenuate (cannot amplify) */
    uint32_t target_rights = (new_rights != 0) ? new_rights : src_table->entries[index].rights;
    if ((target_rights & ~src_table->entries[index].rights) != 0) {
        spinlock_unlock_irqrestore(&src_table->lock, src_flags);
        return KOS_INVALID_HANDLE;
    }

    struct kos_object_header *obj = src_table->entries[index].object;
    if (obj == NULL) {
        spinlock_unlock_irqrestore(&src_table->lock, src_flags);
        return KOS_INVALID_HANDLE;
    }

    /* Temporary reference to prevent object destruction between unlock and creation */
    kos_object_ref(obj);

    spinlock_unlock_irqrestore(&src_table->lock, src_flags);

    /* Allocate handle in destination process */
    handle_t dst_handle = handle_create(dst_proc, obj, target_rights);

    /* Drop temporary reference */
    kos_object_unref(obj);

    return dst_handle;
}
