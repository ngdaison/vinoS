#ifndef KOS_FAT32_H
#define KOS_FAT32_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kos/block.h>
#include <kos/compiler.h>
#include <kos/vfs.h>

/* FAT32 Boot Sector (BPB + Extended BPB) */
struct fat32_bpb {
    uint8_t  jmp_boot[3];
    uint8_t  oem_name[8];
    uint16_t bytes_per_sector;
    uint8_t  sectors_per_cluster;
    uint16_t reserved_sector_count;
    uint8_t  num_fats;
    uint16_t root_entry_count;
    uint16_t total_sectors_16;
    uint8_t  media;
    uint16_t fat_size_16;
    uint16_t sectors_per_track;
    uint16_t num_heads;
    uint32_t hidden_sectors;
    uint32_t total_sectors_32;

    /* FAT32 Extended fields */
    uint32_t fat_size_32;
    uint16_t ext_flags;
    uint16_t fs_version;
    uint32_t root_cluster;
    uint16_t fs_info_sector;
    uint16_t backup_boot_sector;
    uint8_t  reserved[12];
    uint8_t  drive_number;
    uint8_t  reserved1;
    uint8_t  boot_signature;
    uint32_t volume_id;
    uint8_t  volume_label[11];
    uint8_t  fs_type[8];
} KOS_PACKED;

/* FAT32 Standard Directory Entry (32 bytes) */
#define FAT_ATTR_READ_ONLY 0x01
#define FAT_ATTR_HIDDEN    0x02
#define FAT_ATTR_SYSTEM    0x04
#define FAT_ATTR_VOLUME_ID 0x08
#define FAT_ATTR_DIRECTORY 0x10
#define FAT_ATTR_ARCHIVE   0x20
#define FAT_ATTR_LFN       (FAT_ATTR_READ_ONLY | FAT_ATTR_HIDDEN | FAT_ATTR_SYSTEM | FAT_ATTR_VOLUME_ID)

struct fat32_dir_entry {
    uint8_t  name[11];           /* Short 8.3 name */
    uint8_t  attr;               /* File attributes */
    uint8_t  nt_reserved;
    uint8_t  creation_time_tenth;
    uint16_t creation_time;
    uint16_t creation_date;
    uint16_t last_access_date;
    uint16_t first_cluster_high; /* High 16 bits of cluster */
    uint16_t write_time;
    uint16_t write_date;
    uint16_t first_cluster_low;  /* Low 16 bits of cluster */
    uint32_t file_size;          /* Size in bytes */
} KOS_PACKED;

/* FAT32 Long File Name Entry (32 bytes) */
struct fat32_lfn_entry {
    uint8_t  sequence;           /* Sequence number (with 0x40 flag for last LFN) */
    uint16_t name0_4[5];         /* Chars 1-5 (UTF-16LE) */
    uint8_t  attr;               /* Always 0x0F */
    uint8_t  type;               /* Always 0 */
    uint8_t  checksum;           /* Short name checksum */
    uint16_t name5_10[6];        /* Chars 6-11 (UTF-16LE) */
    uint16_t first_cluster_low;  /* Always 0 */
    uint16_t name11_12[2];       /* Chars 12-13 (UTF-16LE) */
} KOS_PACKED;

/* FSInfo Sector */
struct fat32_fsinfo {
    uint32_t lead_sig;           /* 0x41615252 */
    uint8_t  reserved1[480];
    uint32_t struct_sig;         /* 0x61417272 */
    uint32_t free_count;         /* Free cluster count (-1 if unknown) */
    uint32_t next_free;          /* Most recently allocated cluster */
    uint8_t  reserved2[12];
    uint32_t trail_sig;          /* 0xAA550000 */
} KOS_PACKED;

/* Cluster Constants */
#define FAT32_CLUSTER_FREE     0x00000000
#define FAT32_CLUSTER_RESERVED 0x0FFFFFF0
#define FAT32_CLUSTER_BAD      0x0FFFFFF7
#define FAT32_CLUSTER_END_MIN  0x0FFFFFF8
#define FAT32_CLUSTER_END      0x0FFFFFFF

struct fat32_volume;

/* Volume Management & Lifecycle */
bool fat32_probe(struct block_device *dev);
struct fat32_volume *fat32_mount(struct block_device *dev);
bool fat32_unmount(struct fat32_volume *vol);

/* File System Operations */
bool fat32_read_file(struct fat32_volume *vol, const char *path, const uint8_t **data_out, uint64_t *size_out);
bool fat32_write_file(struct fat32_volume *vol, const char *path, const uint8_t *data, uint64_t size);
bool fat32_unlink_file(struct fat32_volume *vol, const char *path);
bool fat32_mkdir(struct fat32_volume *vol, const char *path);
bool fat32_rmdir(struct fat32_volume *vol, const char *path);
bool fat32_rename(struct fat32_volume *vol, const char *old_path, const char *new_path);

/* Directory Enumeration */
typedef void (*fat32_readdir_cb)(const char *name, uint64_t size, uint8_t attr, void *user_arg);
bool fat32_readdir(struct fat32_volume *vol, const char *dir_path, fat32_readdir_cb callback, void *user_arg);

/* VFS Backend Adapter */
const struct vfs_backend *fat32_get_vfs_backend(struct fat32_volume *vol);

#endif /* KOS_FAT32_H */
