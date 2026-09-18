#ifndef KOS_PARTITION_H
#define KOS_PARTITION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kos/block.h>

#define MBR_BOOT_SIGNATURE 0xAA55
#define MBR_PARTITION_COUNT 4
#define MBR_GPT_PROTECTIVE_TYPE 0xEE

/* Standard MBR Partition Types */
#define MBR_TYPE_EMPTY       0x00
#define MBR_TYPE_FAT12       0x01
#define MBR_TYPE_FAT16_32MB  0x04
#define MBR_TYPE_EXTENDED    0x05
#define MBR_TYPE_FAT16       0x06
#define MBR_TYPE_NTFS_EXFAT  0x07
#define MBR_TYPE_FAT32_CHS   0x0B
#define MBR_TYPE_FAT32_LBA   0x0C
#define MBR_TYPE_FAT16_LBA   0x0E
#define MBR_TYPE_LINUX       0x83
#define MBR_TYPE_LINUX_SWAP  0x82
#define MBR_TYPE_EFI_SYSTEM  0xEF

/* MBR Partition Entry (16 bytes packed) */
struct mbr_partition_entry {
    uint8_t boot_indicator;     /* 0x80 = active/bootable, 0x00 = inactive */
    uint8_t start_chs[3];
    uint8_t partition_type;
    uint8_t end_chs[3];
    uint32_t start_lba;
    uint32_t sector_count;
} KOS_PACKED;

/* MBR Sector Layout (512 bytes) */
struct mbr_sector {
    uint8_t bootstrap_code[446];
    struct mbr_partition_entry partitions[MBR_PARTITION_COUNT];
    uint16_t signature;         /* 0xAA55 */
} KOS_PACKED;

/* GPT Header (92 bytes + padding to 512) */
struct gpt_header {
    char signature[8];          /* "EFI PART" (0x5452415020494645ULL) */
    uint32_t revision;          /* 0x00010000 for version 1.0 */
    uint32_t header_size;       /* usually 92 */
    uint32_t header_crc32;
    uint32_t reserved;
    uint64_t current_lba;
    uint64_t backup_lba;
    uint64_t first_usable_lba;
    uint64_t last_usable_lba;
    uint8_t disk_guid[16];
    uint64_t partition_entries_lba;
    uint32_t num_partition_entries;
    uint32_t size_partition_entry;
    uint32_t partition_array_crc32;
} KOS_PACKED;

/* GPT Partition Entry (128 bytes) */
struct gpt_partition_entry {
    uint8_t type_guid[16];
    uint8_t unique_partition_guid[16];
    uint64_t starting_lba;
    uint64_t ending_lba;
    uint64_t attributes;
    uint16_t name[36];          /* UTF-16LE partition name */
} KOS_PACKED;

/* CRC32 Utility Function */
uint32_t partition_crc32(const void *data, size_t length);

/* Scan a block device for MBR or GPT partitions and register child block devices */
uint32_t partition_scan(struct block_device *dev);

/* Format helper for GUID string */
void partition_format_guid(const uint8_t guid[16], char buffer[37]);

#endif /* KOS_PARTITION_H */
