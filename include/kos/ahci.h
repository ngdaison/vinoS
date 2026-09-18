#ifndef KOS_AHCI_H
#define KOS_AHCI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kos/block.h>
#include <kos/compiler.h>

#define AHCI_MAX_PORTS 32
#define AHCI_MAX_DEVICES 8

/* AHCI FIS Types */
#define FIS_TYPE_REG_H2D   0x27 /* Register FIS - host to device */
#define FIS_TYPE_REG_D2H   0x34 /* Register FIS - device to host */
#define FIS_TYPE_DMA_ACT   0x39 /* DMA activate FIS - device to host */
#define FIS_TYPE_DMA_SETUP 0x41 /* DMA setup FIS - bidirectional */
#define FIS_TYPE_DATA      0x46 /* Data FIS - bidirectional */
#define FIS_TYPE_BIST      0x58 /* BIST activate FIS - bidirectional */
#define FIS_TYPE_PIO_SETUP 0x5F /* PIO setup FIS - device to host */
#define FIS_TYPE_DEV_BITS  0xA1 /* Set device bits FIS - device to host */

/* ATA Commands */
#define ATA_CMD_READ_DMA_EX     0x25
#define ATA_CMD_WRITE_DMA_EX    0x35
#define ATA_CMD_IDENTIFY        0xEC
#define ATA_CMD_FLUSH_CACHE_EX  0xE7

/* SATA Device Signatures */
#define SATA_SIG_ATA    0x00000101 /* SATA drive */
#define SATA_SIG_ATAPI  0xEB140101 /* SATAPI drive (e.g. CD/DVD) */
#define SATA_SIG_SEMB   0xC33C0101 /* Enclosure management bridge */
#define SATA_SIG_PM     0x96690101 /* Port multiplier */

/* HBA Port Command / Status Bits */
#define HBA_PORT_CMD_ST  (1U << 0)  /* Start processing command list */
#define HBA_PORT_CMD_SUD (1U << 1)  /* Spin-Up Device */
#define HBA_PORT_CMD_POD (1U << 2)  /* Power On Device */
#define HBA_PORT_CMD_FRE (1U << 4)  /* FIS Receive Enable */
#define HBA_PORT_CMD_FR  (1U << 14) /* FIS Receive Running */
#define HBA_PORT_CMD_CR  (1U << 15) /* Command List Running */

/* HBA Port Interrupt Status Bits */
#define HBA_PORT_IS_TFES (1U << 30) /* Task File Error Status */

/* Host to Device Register FIS */
struct fis_reg_h2d {
    uint8_t fis_type;    /* FIS_TYPE_REG_H2D */
    uint8_t pmport_c;    /* Port multiplier (bits 0-3), C=1 for command (bit 7) */
    uint8_t command;     /* ATA command */
    uint8_t featurel;    /* Feature register low */

    uint8_t lba0;        /* LBA 7:0 */
    uint8_t lba1;        /* LBA 15:8 */
    uint8_t lba2;        /* LBA 23:16 */
    uint8_t device;      /* Device register (1<<6 for LBA) */

    uint8_t lba3;        /* LBA 31:24 */
    uint8_t lba4;        /* LBA 39:32 */
    uint8_t lba5;        /* LBA 47:40 */
    uint8_t featureh;    /* Feature register high */

    uint8_t countl;      /* Count register 7:0 */
    uint8_t counth;      /* Count register 15:8 */
    uint8_t icc;         /* Isochronous command completion */
    uint8_t control;     /* Control register */

    uint8_t rsv1[4];     /* Reserved */
} KOS_PACKED;

/* Physical Region Descriptor Table Entry */
struct ahci_prdt_entry {
    uint32_t dba;        /* Data Base Address low 32 bits */
    uint32_t dbau;       /* Data Base Address upper 32 bits */
    uint32_t rsv0;       /* Reserved */
    uint32_t dbc_i;      /* Byte count (bits 0-21: size-1), Interrupt bit (bit 31) */
} KOS_PACKED;

/* AHCI Command Header */
struct ahci_cmd_header {
    uint8_t cfl_a_w;     /* CFL (bits 0-4), ATAPI (bit 5), Write (bit 6), Prefetch (bit 7) */
    uint8_t p_r_b_c;     /* Reset, BIST, Clear, etc. */
    uint16_t prdtl;      /* PRDT length in entries */
    volatile uint32_t prdbc; /* PRD byte count transferred */
    uint32_t ctba;       /* Command Table Base Address low */
    uint32_t ctbau;      /* Command Table Base Address upper */
    uint32_t rsv1[4];    /* Reserved */
} KOS_PACKED;

/* AHCI Command Table */
struct ahci_cmd_table {
    uint8_t cfis[64];    /* Command FIS */
    uint8_t acmd[16];    /* ATAPI Command */
    uint8_t rsv[48];     /* Reserved */
    struct ahci_prdt_entry prdt_entry[8]; /* PRDT entries */
} KOS_PACKED;

/* AHCI Port Registers */
struct ahci_port {
    volatile uint32_t clb;   /* Command List Base Address low */
    volatile uint32_t clbu;  /* Command List Base Address upper */
    volatile uint32_t fb;    /* FIS Base Address low */
    volatile uint32_t fbu;   /* FIS Base Address upper */
    volatile uint32_t is;    /* Interrupt Status */
    volatile uint32_t ie;    /* Interrupt Enable */
    volatile uint32_t cmd;   /* Command and Status */
    volatile uint32_t rsv0;
    volatile uint32_t tfd;   /* Task File Data */
    volatile uint32_t sig;   /* Signature */
    volatile uint32_t ssts;  /* SATA Status (SCR0:SStatus) */
    volatile uint32_t sctl;  /* SATA Control (SCR2:SControl) */
    volatile uint32_t serr;  /* SATA Error (SCR1:SError) */
    volatile uint32_t sact;  /* SATA Active (SCR3:SActive) */
    volatile uint32_t ci;    /* Command Issue */
    volatile uint32_t sntf;  /* SATA Notification */
    volatile uint32_t fbs;   /* FIS-based Switching Control */
    volatile uint32_t rsv1[11];
    volatile uint32_t vendor[4];
} KOS_PACKED;

/* AHCI Generic Host Control Registers */
struct ahci_hba_mem {
    volatile uint32_t cap;     /* Host Capability */
    volatile uint32_t ghc;     /* Global Host Control */
    volatile uint32_t is;      /* Interrupt Status */
    volatile uint32_t pi;      /* Ports Implemented bitmask */
    volatile uint32_t vs;      /* Version */
    volatile uint32_t ccc_ctl; /* Command Completion Coalescing Control */
    volatile uint32_t ccc_pts; /* Command Completion Coalescing Ports */
    volatile uint32_t em_loc;  /* Enclosure Management Location */
    volatile uint32_t em_ctl;  /* Enclosure Management Control */
    volatile uint32_t cap2;    /* Host Capabilities Extended */
    volatile uint32_t bohc;    /* BIOS/OS Handoff Control and Status */
    volatile uint8_t  rsv[0xA0 - 0x2C];
    volatile uint8_t  vendor[0x100 - 0xA0];
    struct ahci_port  ports[AHCI_MAX_PORTS];
} KOS_PACKED;

/* Public AHCI API */
bool ahci_initialize(void);
uint32_t ahci_device_count(void);

#endif /* KOS_AHCI_H */
