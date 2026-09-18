#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kos/block.h>
#include <kos/heap.h>
#include <kos/log.h>
#include <kos/memory.h>
#include <kos/partition.h>

/* IEEE 802.3 CRC32 Implementation */
uint32_t partition_crc32(const void *data, size_t length) {
    if (data == NULL || length == 0) {
        return 0;
    }
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFU;
    for (size_t i = 0; i < length; i++) {
        crc ^= (uint32_t)bytes[i];
        for (int b = 0; b < 8; b++) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320U & mask);
        }
    }
    return ~crc;
}

static const char hex_digits[] = "0123456789ABCDEF";

void partition_format_guid(const uint8_t guid[16], char buffer[37]) {
    if (guid == NULL || buffer == NULL) return;
    /* Format: {3-2-1-0}-{5-4}-{7-6}-{8-9}-{10-11-12-13-14-15} (mixed-endian GPT standard) */
    size_t pos = 0;
    /* Data1 (uint32_t little-endian: bytes 3,2,1,0) */
    for (int i = 3; i >= 0; i--) {
        buffer[pos++] = hex_digits[(guid[i] >> 4) & 0xF];
        buffer[pos++] = hex_digits[guid[i] & 0xF];
    }
    buffer[pos++] = '-';
    /* Data2 (uint16_t little-endian: bytes 5,4) */
    for (int i = 5; i >= 4; i--) {
        buffer[pos++] = hex_digits[(guid[i] >> 4) & 0xF];
        buffer[pos++] = hex_digits[guid[i] & 0xF];
    }
    buffer[pos++] = '-';
    /* Data3 (uint16_t little-endian: bytes 7,6) */
    for (int i = 7; i >= 6; i--) {
        buffer[pos++] = hex_digits[(guid[i] >> 4) & 0xF];
        buffer[pos++] = hex_digits[guid[i] & 0xF];
    }
    buffer[pos++] = '-';
    /* Data4 (bytes 8,9) */
    for (int i = 8; i <= 9; i++) {
        buffer[pos++] = hex_digits[(guid[i] >> 4) & 0xF];
        buffer[pos++] = hex_digits[guid[i] & 0xF];
    }
    buffer[pos++] = '-';
    /* Data5 (bytes 10..15) */
    for (int i = 10; i <= 15; i++) {
        buffer[pos++] = hex_digits[(guid[i] >> 4) & 0xF];
        buffer[pos++] = hex_digits[guid[i] & 0xF];
    }
    buffer[pos] = '\0';
}

static bool guid_is_zero(const uint8_t guid[16]) {
    for (int i = 0; i < 16; i++) {
        if (guid[i] != 0) return false;
    }
    return true;
}

/* Parse GPT Partition Table */
static uint32_t partition_scan_gpt(struct block_device *dev) {
    if (dev->total_blocks < 34) {
        return 0;
    }

    uint8_t sector_buf[512];
    if (!block_read(dev, 1, 1, sector_buf)) {
        log_errorf("[partition] Failed to read GPT header (LBA 1) from %s", dev->name);
        return 0;
    }

    struct gpt_header *hdr = (struct gpt_header *)sector_buf;

    /* Check "EFI PART" signature */
    if (hdr->signature[0] != 'E' || hdr->signature[1] != 'F' ||
        hdr->signature[2] != 'I' || hdr->signature[3] != ' ' ||
        hdr->signature[4] != 'P' || hdr->signature[5] != 'A' ||
        hdr->signature[6] != 'R' || hdr->signature[7] != 'T') {
        return 0;
    }

    if (hdr->header_size < 92 || hdr->header_size > 512) {
        log_errorf("[partition] Invalid GPT header size: %u", hdr->header_size);
        return 0;
    }

    /* Verify Header CRC32 */
    uint32_t orig_crc = hdr->header_crc32;
    hdr->header_crc32 = 0;
    uint32_t calc_crc = partition_crc32(hdr, hdr->header_size);
    hdr->header_crc32 = orig_crc;

    if (calc_crc != orig_crc) {
        log_errorf("[partition] GPT Header CRC32 mismatch on %s (expected 0x%08X, calculated 0x%08X)",
                   dev->name, orig_crc, calc_crc);
        return 0;
    }

    char disk_guid_str[37];
    partition_format_guid(hdr->disk_guid, disk_guid_str);
    log_infof("[partition] Found valid GPT on %s (Disk GUID: %s, entries=%u)",
              dev->name, disk_guid_str, hdr->num_partition_entries);

    uint32_t num_entries = hdr->num_partition_entries;
    uint32_t entry_size = hdr->size_partition_entry;
    if (entry_size < sizeof(struct gpt_partition_entry)) {
        entry_size = sizeof(struct gpt_partition_entry);
    }
    if (num_entries > 128) {
        num_entries = 128;
    }

    uint64_t entries_lba = hdr->partition_entries_lba;
    uint32_t entries_bytes = num_entries * entry_size;
    uint32_t entries_sectors = (entries_bytes + (uint32_t)dev->block_size - 1) / (uint32_t)dev->block_size;

    uint8_t *entries_buf = (uint8_t *)kmalloc(entries_sectors * dev->block_size);
    if (entries_buf == NULL) {
        log_error("[partition] Out of memory allocating GPT entries buffer!");
        return 0;
    }

    if (!block_read(dev, entries_lba, entries_sectors, entries_buf)) {
        log_errorf("[partition] Failed to read GPT partition entries from %s", dev->name);
        kfree(entries_buf);
        return 0;
    }

    /* Verify Partition Array CRC32 */
    uint32_t array_crc = partition_crc32(entries_buf, entries_bytes);
    if (hdr->partition_array_crc32 != 0 && array_crc != hdr->partition_array_crc32) {
        log_warnf("[partition] GPT Partition Array CRC32 mismatch (0x%08X != 0x%08X), proceeding with caution",
                  array_crc, hdr->partition_array_crc32);
    }

    uint32_t valid_parts = 0;
    for (uint32_t i = 0; i < num_entries; i++) {
        struct gpt_partition_entry *e = (struct gpt_partition_entry *)(entries_buf + (i * entry_size));
        if (guid_is_zero(e->type_guid)) {
            continue;
        }
        if (e->starting_lba > e->ending_lba || e->ending_lba >= dev->total_blocks) {
            log_warnf("[partition] Skipping invalid GPT partition %u bounds (%llu..%llu)",
                      i + 1, (unsigned long long)e->starting_lba, (unsigned long long)e->ending_lba);
            continue;
        }

        uint64_t count = (e->ending_lba - e->starting_lba) + 1;
        valid_parts++;
        (void)block_partition_register(dev, valid_parts, e->starting_lba, count, 0xEE, e->unique_partition_guid);
    }

    kfree(entries_buf);
    return valid_parts;
}

/* Parse MBR Partition Table */
static uint32_t partition_scan_mbr(struct block_device *dev) {
    uint8_t sector_buf[512];
    if (!block_read(dev, 0, 1, sector_buf)) {
        log_errorf("[partition] Failed to read MBR sector 0 from %s", dev->name);
        return 0;
    }

    struct mbr_sector *mbr = (struct mbr_sector *)sector_buf;
    if (mbr->signature != MBR_BOOT_SIGNATURE) {
        log_debugf("[partition] No valid MBR signature on %s (got 0x%04X, expect 0x%04X)",
                   dev->name, mbr->signature, MBR_BOOT_SIGNATURE);
        return 0;
    }

    /* Check if this is a GPT protective MBR (Type 0xEE on partition 0) */
    if (mbr->partitions[0].partition_type == MBR_GPT_PROTECTIVE_TYPE) {
        uint32_t gpt_count = partition_scan_gpt(dev);
        if (gpt_count > 0) {
            return gpt_count;
        }
    }

    uint32_t valid_parts = 0;
    for (uint32_t i = 0; i < MBR_PARTITION_COUNT; i++) {
        struct mbr_partition_entry *p = &mbr->partitions[i];
        if (p->partition_type == MBR_TYPE_EMPTY || p->sector_count == 0) {
            continue;
        }
        if ((uint64_t)p->start_lba + p->sector_count > dev->total_blocks) {
            log_warnf("[partition] Skipping out-of-bounds MBR partition %u on %s (LBA %u + %u > %llu)",
                      i + 1, dev->name, p->start_lba, p->sector_count, (unsigned long long)dev->total_blocks);
            continue;
        }

        valid_parts++;
        (void)block_partition_register(dev, valid_parts, p->start_lba, p->sector_count, p->partition_type, NULL);
    }

    if (valid_parts > 0) {
        log_infof("[partition] Found MBR with %u valid partitions on %s", valid_parts, dev->name);
    }
    return valid_parts;
}

uint32_t partition_scan(struct block_device *dev) {
    if (dev == NULL || dev->state != BLOCK_DEVICE_ONLINE || dev->type == BLOCK_TYPE_PARTITION) {
        return 0;
    }
    log_infof("[partition] Scanning partition table on %s (%llu blocks)...",
              dev->name, (unsigned long long)dev->total_blocks);
    return partition_scan_mbr(dev);
}
