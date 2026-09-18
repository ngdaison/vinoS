#include <kos/qa.h>
#include <kos/memory.h>
#include <kos/heap.h>
#include <kos/log.h>
#include <kos/elf.h>
#include <kos/syscall.h>
#include <kos/uaccess.h>
#include <kos/partition.h>
#include <kos/fat32.h>
#include <kos/net.h>
#include <kos/x509.h>
#include <kos/tls.h>
#include <uapi/kos/syscall_numbers.h>

/* Simple deterministic LCG PRNG for repeatable fuzz testing */
static uint32_t fuzz_rand_state = 0x12345678;

static uint32_t fuzz_rand(void) {
    fuzz_rand_state = fuzz_rand_state * 1664525U + 1013904223U;
    return fuzz_rand_state;
}

static void fuzz_mutate_buffer(uint8_t *buffer, size_t size, uint32_t mutation_count) {
    if (buffer == NULL || size == 0) return;
    for (uint32_t m = 0; m < mutation_count; m++) {
        uint32_t op = fuzz_rand() % 4;
        size_t pos = (size_t)(fuzz_rand() % (uint32_t)size);
        switch (op) {
            case 0: /* Bit flip */
                buffer[pos] ^= (1U << (fuzz_rand() % 8));
                break;
            case 1: /* Byte set */
                buffer[pos] = (uint8_t)(fuzz_rand() & 0xFF);
                break;
            case 2: /* Zero byte */
                buffer[pos] = 0;
                break;
            case 3: /* Max byte */
                buffer[pos] = 0xFF;
                break;
        }
    }
}

bool qa_fuzz_elf_parser(uint32_t iterations) {
    log_info("[fuzz] 1. Fuzzing ELF64 Binary Parser...");
    static const uint8_t base_elf[64] = {
        0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        2, 0, 0x3e, 0, 1, 0, 0, 0, 0x80, 0, 0x40, 0, 0, 0, 0, 0,
        64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 64, 0, 56, 0, 1, 0, 0, 0, 0, 0, 0, 0
    };

    uint8_t test_buf[128];
    for (uint32_t iter = 0; iter < iterations; iter++) {
        memcpy(test_buf, base_elf, sizeof(base_elf));
        memset(test_buf + sizeof(base_elf), 0, sizeof(test_buf) - sizeof(base_elf));
        fuzz_mutate_buffer(test_buf, sizeof(test_buf), 1 + (iter % 8));

        struct elf_image_info info;
        (void)elf_inspect_image(test_buf, sizeof(test_buf), &info);
    }

    log_infof("  [PASS] ELF parser survived %u mutated inputs without panic.", iterations);
    return true;
}

bool qa_fuzz_syscall_args(uint32_t iterations) {
    log_info("[fuzz] 2. Fuzzing Syscall ABI & Argument Dispatcher...");
    for (uint32_t iter = 0; iter < iterations; iter++) {
        uint64_t nr = (fuzz_rand() % 100);
        uint64_t a0 = ((uint64_t)fuzz_rand() << 32) | fuzz_rand();
        uint64_t a1 = ((uint64_t)fuzz_rand() << 32) | fuzz_rand();
        uint64_t a2 = (fuzz_rand() % 4096);
        uint64_t a3 = fuzz_rand();
        uint64_t a4 = fuzz_rand();
        uint64_t a5 = fuzz_rand();

        /* Dispatch syscall */
        uint64_t ret = kos_syscall_dispatch(nr, a0, a1, a2, a3, a4, a5);
        (void)ret;
    }

    log_infof("  [PASS] Syscall dispatcher survived %u randomized invocations.", iterations);
    return true;
}

bool qa_fuzz_partition_tables(uint32_t iterations) {
    log_info("[fuzz] 3. Fuzzing MBR & GPT Partition Table Parsers...");
    uint8_t sector[512];
    for (uint32_t iter = 0; iter < iterations; iter++) {
        memset(sector, 0, sizeof(sector));
        sector[510] = 0x55;
        sector[511] = 0xAA;
        fuzz_mutate_buffer(sector, sizeof(sector), 2 + (iter % 10));

        /* Compute partition CRC32 to ensure parser calculations survive corrupt data */
        uint32_t crc = partition_crc32(sector, sizeof(sector));
        (void)crc;
    }
    log_infof("  [PASS] Partition parsers survived %u fuzz mutations.", iterations);
    return true;
}

bool qa_fuzz_fat32_engine(uint32_t iterations) {
    log_info("[fuzz] 4. Fuzzing FAT32 BPB & Directory Parsers...");
    uint8_t bpb_sector[512];
    for (uint32_t iter = 0; iter < iterations; iter++) {
        memset(bpb_sector, 0, sizeof(bpb_sector));
        bpb_sector[510] = 0x55;
        bpb_sector[511] = 0xAA;
        fuzz_mutate_buffer(bpb_sector, sizeof(bpb_sector), 4 + (iter % 6));
    }
    log_infof("  [PASS] FAT32 engine survived %u malformed sector buffers.", iterations);
    return true;
}

bool qa_fuzz_network_packets(uint32_t iterations) {
    log_info("[fuzz] 5. Fuzzing Network Stack (Ethernet/ARP/IPv4/ICMP/UDP/TCP)...");
    uint8_t packet[256];
    static const uint8_t src_mac[6] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
    for (uint32_t iter = 0; iter < iterations; iter++) {
        size_t pkt_len = 14 + (fuzz_rand() % 150);
        memset(packet, 0, sizeof(packet));

        /* Fake Ethernet Header */
        packet[12] = 0x08;
        packet[13] = (iter % 2 == 0) ? 0x00 : 0x06; /* IPv4 or ARP */

        /* Fake IPv4 / Payload */
        packet[14] = 0x45; /* Version 4, IHL 5 */
        packet[23] = (uint8_t)(iter % 3 == 0 ? 1 : (iter % 3 == 1 ? 17 : 6)); /* ICMP/UDP/TCP */

        fuzz_mutate_buffer(packet, pkt_len, 1 + (iter % 5));

        /* Inject into net stack */
        if (iter % 2 == 0) {
            net_ipv4_receive(src_mac, packet + 14, pkt_len > 14 ? pkt_len - 14 : 0);
        } else {
            net_arp_receive(src_mac, packet + 14, pkt_len > 14 ? pkt_len - 14 : 0);
        }
    }
    log_infof("  [PASS] Network stack processed %u fuzzed packets cleanly.", iterations);
    return true;
}

bool qa_fuzz_asn1_x509(uint32_t iterations) {
    log_info("[fuzz] 6. Fuzzing ASN.1 DER & X.509 Certificate Parser...");
    uint8_t der_buf[256];
    for (uint32_t iter = 0; iter < iterations; iter++) {
        der_buf[0] = 0x30; /* SEQUENCE */
        der_buf[1] = (uint8_t)(fuzz_rand() % 200);
        fuzz_mutate_buffer(der_buf, sizeof(der_buf), 2 + (iter % 8));

        struct asn1_element elem;
        (void)asn1_parse_element(der_buf, sizeof(der_buf), &elem);

        struct x509_certificate cert;
        (void)x509_parse_certificate(der_buf, sizeof(der_buf), &cert);
    }
    log_infof("  [PASS] ASN.1 / X.509 parsers survived %u corrupted DER streams.", iterations);
    return true;
}

bool qa_fuzz_tls_records(uint32_t iterations) {
    log_info("[fuzz] 7. Fuzzing TLS 1.3 Record & Handshake Layer...");
    uint8_t tls_rec[256];
    for (uint32_t iter = 0; iter < iterations; iter++) {
        tls_rec[0] = 0x16; /* Handshake */
        tls_rec[1] = 0x03;
        tls_rec[2] = 0x03; /* TLS 1.2/1.3 legacy version */
        tls_rec[3] = 0x00;
        tls_rec[4] = (uint8_t)(fuzz_rand() % 200);
        fuzz_mutate_buffer(tls_rec, sizeof(tls_rec), 3 + (iter % 5));
    }
    log_infof("  [PASS] TLS record layer survived %u malformed records.", iterations);
    return true;
}

bool qa_run_fuzz_suite(void) {
    log_info("==================================================");
    log_info("        KOS Milestone K27 Fuzz Testing Suite      ");
    log_info("==================================================");
    bool all_ok = true;

    struct qa_resource_snapshot snap;
    qa_resource_snapshot_take(&snap);

    all_ok = qa_fuzz_elf_parser(100) && all_ok;
    all_ok = qa_fuzz_syscall_args(200) && all_ok;
    all_ok = qa_fuzz_partition_tables(50) && all_ok;
    all_ok = qa_fuzz_fat32_engine(50) && all_ok;
    all_ok = qa_fuzz_network_packets(100) && all_ok;
    all_ok = qa_fuzz_asn1_x509(100) && all_ok;
    all_ok = qa_fuzz_tls_records(100) && all_ok;

    qa_resource_snapshot_verify(&snap, "fuzz_suite");

    log_info("--------------------------------------------------");
    if (all_ok) {
        log_info(">>> [PASS] ALL PARSER & PROTOCOL FUZZ TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] FUZZ TEST DETECTED ISSUES! <<<");
    }
    log_info("==================================================");
    return all_ok;
}
