#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/x509.h>
#include <kos/crypto.h>
#include <kos/io.h>
#include <kos/timer.h>

/* =========================================================================
 * 1. String & Memory Helpers
 * ========================================================================= */

static uint32_t str_len(const char *s) {
    uint32_t len = 0;
    if (s == 0) return 0;
    while (s[len] != '\0') ++len;
    return len;
}

static char to_lower(char c) {
    if (c >= 'A' && c <= 'Z') return (char)(c + ('a' - 'A'));
    return c;
}

static bool str_eq_case_insensitive(const char *a, const char *b) {
    if (a == 0 || b == 0) return false;
    while (*a != '\0' && *b != '\0') {
        if (to_lower(*a) != to_lower(*b)) return false;
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

static void copy_string(char *dest, uint32_t dest_size, const uint8_t *src, uint32_t src_size) {
    if (dest == 0 || dest_size == 0) return;
    uint32_t copy_len = src_size < dest_size - 1 ? src_size : dest_size - 1;
    for (uint32_t i = 0; i < copy_len; ++i) {
        dest[i] = (char)src[i];
    }
    dest[copy_len] = '\0';
}

/* =========================================================================
 * 2. CMOS RTC Real-Time Clock Reader
 * ========================================================================= */

#define CMOS_ADDRESS 0x70
#define CMOS_DATA    0x71

static uint8_t get_rtc_register(uint8_t reg) {
    io_out8(CMOS_ADDRESS, reg);
    return io_in8(CMOS_DATA);
}

static uint8_t bcd_to_bin(uint8_t bcd) {
    return (uint8_t)(((bcd >> 4) * 10) + (bcd & 0x0F));
}

uint64_t x509_get_current_time_epoch(void) {
    /* Read CMOS RTC registers */
    /* Wait for RTC update to finish */
    while (get_rtc_register(0x0A) & 0x80);

    uint8_t sec = get_rtc_register(0x00);
    uint8_t min = get_rtc_register(0x02);
    uint8_t hour = get_rtc_register(0x04);
    uint8_t day = get_rtc_register(0x07);
    uint8_t month = get_rtc_register(0x08);
    uint8_t year = get_rtc_register(0x09);
    uint8_t register_b = get_rtc_register(0x0B);

    /* Convert BCD to binary if needed */
    if (!(register_b & 0x04)) {
        sec = bcd_to_bin(sec);
        min = bcd_to_bin(min);
        hour = bcd_to_bin(hour & 0x7F) | (hour & 0x80);
        day = bcd_to_bin(day);
        month = bcd_to_bin(month);
        year = bcd_to_bin(year);
    }

    /* Convert 12 hour to 24 hour format if needed */
    if (!(register_b & 0x02) && (hour & 0x80)) {
        hour = (uint8_t)(((hour & 0x7F) + 12) % 24);
    }

    uint32_t full_year = 2000 + (uint32_t)year;
    if (full_year < 2024) {
        /* Fallback baseline: 2026-09-18 */
        return 1789728000ull + timer_uptime_seconds();
    }

    uint8_t time_buf[16];
    time_buf[0] = (uint8_t)('0' + (full_year / 1000));
    time_buf[1] = (uint8_t)('0' + ((full_year / 100) % 10));
    time_buf[2] = (uint8_t)('0' + ((full_year / 10) % 10));
    time_buf[3] = (uint8_t)('0' + (full_year % 10));
    time_buf[4] = (uint8_t)('0' + (month / 10));
    time_buf[5] = (uint8_t)('0' + (month % 10));
    time_buf[6] = (uint8_t)('0' + (day / 10));
    time_buf[7] = (uint8_t)('0' + (day % 10));
    time_buf[8] = (uint8_t)('0' + (hour / 10));
    time_buf[9] = (uint8_t)('0' + (hour % 10));
    time_buf[10] = (uint8_t)('0' + (min / 10));
    time_buf[11] = (uint8_t)('0' + (min % 10));
    time_buf[12] = (uint8_t)('0' + (sec / 10));
    time_buf[13] = (uint8_t)('0' + (sec % 10));
    time_buf[14] = 'Z';

    uint64_t epoch = 0;
    if (asn1_parse_time(time_buf, 15, ASN1_TAG_GENERALIZED_TIME, &epoch)) {
        return epoch;
    }
    return 1789728000ull + timer_uptime_seconds();
}

/* =========================================================================
 * 3. X.509 Certificate Parser
 * ========================================================================= */

static void parse_name_sequence(const uint8_t *data, uint32_t len, char *out_cn, char *out_org) {
    uint32_t offset = 0;
    while (offset < len) {
        struct asn1_element rdn_set;
        if (!asn1_parse_element(&data[offset], len - offset, &rdn_set)) break;
        offset += rdn_set.header_length + rdn_set.length;

        if (rdn_set.tag != ASN1_TAG_SET) continue;

        uint32_t set_offset = 0;
        while (set_offset < rdn_set.length) {
            struct asn1_element attr_seq;
            if (!asn1_parse_element(&rdn_set.data[set_offset], rdn_set.length - set_offset, &attr_seq)) break;
            set_offset += attr_seq.header_length + attr_seq.length;

            if (attr_seq.tag != ASN1_TAG_SEQUENCE) continue;

            const uint8_t *oid_data;
            uint32_t oid_len;
            if (!asn1_get_oid(attr_seq.data, attr_seq.length, &oid_data, &oid_len)) continue;

            struct asn1_element val_elem;
            uint32_t oid_total_len = 2 + oid_len; /* approximate header */
            if (attr_seq.length > oid_total_len) {
                if (asn1_parse_element(&attr_seq.data[attr_seq.length - (attr_seq.length - oid_len - 2)],
                        attr_seq.length - oid_len - 2, &val_elem)) {
                    if (asn1_match_oid(oid_data, oid_len, OID_COMMON_NAME, sizeof(OID_COMMON_NAME))) {
                        if (out_cn != 0 && out_cn[0] == '\0') {
                            copy_string(out_cn, X509_MAX_NAME_LEN, val_elem.data, val_elem.length);
                        }
                    } else if (asn1_match_oid(oid_data, oid_len, OID_ORGANIZATION, sizeof(OID_ORGANIZATION))) {
                        if (out_org != 0 && out_org[0] == '\0') {
                            copy_string(out_org, X509_MAX_NAME_LEN, val_elem.data, val_elem.length);
                        }
                    }
                }
            }
        }
    }
}

static void parse_san_extension(const uint8_t *ext_val, uint32_t ext_val_len, struct x509_certificate *cert) {
    struct asn1_element seq;
    if (!asn1_parse_element(ext_val, ext_val_len, &seq) || seq.tag != ASN1_TAG_SEQUENCE) {
        return;
    }

    uint32_t offset = 0;
    while (offset < seq.length && cert->san_count < X509_MAX_SAN_NAMES) {
        struct asn1_element name_elem;
        if (!asn1_parse_element(&seq.data[offset], seq.length - offset, &name_elem)) break;
        offset += name_elem.header_length + name_elem.length;

        /* dNSName is context-specific tag [2] = 0x82 */
        if (name_elem.tag == 0x82) {
            copy_string(cert->san_dns_names[cert->san_count++], X509_MAX_NAME_LEN,
                        name_elem.data, name_elem.length);
        }
    }
}

static void parse_extensions(const uint8_t *ext_data, uint32_t ext_len, struct x509_certificate *cert) {
    struct asn1_element ext_seq;
    if (!asn1_parse_element(ext_data, ext_len, &ext_seq) || ext_seq.tag != ASN1_TAG_SEQUENCE) {
        return;
    }

    uint32_t offset = 0;
    while (offset < ext_seq.length) {
        struct asn1_element item;
        if (!asn1_parse_element(&ext_seq.data[offset], ext_seq.length - offset, &item)) break;
        offset += item.header_length + item.length;

        if (item.tag != ASN1_TAG_SEQUENCE) continue;

        /* Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING } */
        const uint8_t *oid_data;
        uint32_t oid_len;
        if (!asn1_get_oid(item.data, item.length, &oid_data, &oid_len)) continue;

        /* Find OCTET STRING containing extension payload */
        uint32_t item_offset = 2 + oid_len;
        while (item_offset < item.length) {
            struct asn1_element sub;
            if (!asn1_parse_element(&item.data[item_offset], item.length - item_offset, &sub)) break;
            item_offset += sub.header_length + sub.length;

            if (sub.tag == ASN1_TAG_OCTET_STRING) {
                if (asn1_match_oid(oid_data, oid_len, OID_SUBJECT_ALT_NAME, sizeof(OID_SUBJECT_ALT_NAME))) {
                    parse_san_extension(sub.data, sub.length, cert);
                } else if (asn1_match_oid(oid_data, oid_len, OID_BASIC_CONSTRAINTS, sizeof(OID_BASIC_CONSTRAINTS))) {
                    struct asn1_element bc_seq;
                    if (asn1_parse_element(sub.data, sub.length, &bc_seq) && bc_seq.tag == ASN1_TAG_SEQUENCE) {
                        if (bc_seq.length > 0 && bc_seq.data[0] == ASN1_TAG_BOOLEAN && bc_seq.data[1] == 1) {
                            cert->is_ca = (bc_seq.data[2] != 0);
                        }
                    }
                }
                break;
            }
        }
    }
}

bool x509_parse_certificate(const uint8_t *der, uint32_t der_len, struct x509_certificate *cert) {
    if (der == 0 || der_len == 0 || cert == 0) {
        return false;
    }

    *cert = (struct x509_certificate){0};
    cert->raw_der = der;
    cert->raw_len = der_len;

    /* 1. Top-level SEQUENCE */
    struct asn1_element root_seq;
    if (!asn1_get_sequence(der, der_len, &root_seq)) {
        return false;
    }

    /* 2. TBSCertificate (SEQUENCE) */
    struct asn1_element tbs_seq;
    if (!asn1_get_sequence(root_seq.data, root_seq.length, &tbs_seq)) {
        return false;
    }
    cert->tbs_der = root_seq.data;
    cert->tbs_len = tbs_seq.header_length + tbs_seq.length;

    /* Parse elements within TBSCertificate */
    uint32_t tbs_offset = 0;

    /* Version (optional [0] EXPLICIT INTEGER) */
    struct asn1_element elem;
    if (!asn1_parse_element(&tbs_seq.data[tbs_offset], tbs_seq.length - tbs_offset, &elem)) return false;
    if (elem.tag == ASN1_TAG_CONTEXT_0) {
        tbs_offset += elem.header_length + elem.length;
        if (elem.length > 0 && elem.data[0] == ASN1_TAG_INTEGER && elem.data[1] == 1) {
            cert->version = (uint32_t)elem.data[2] + 1;
        }
    } else {
        cert->version = 1; /* Default v1 */
    }

    /* Serial Number (INTEGER) */
    if (!asn1_parse_element(&tbs_seq.data[tbs_offset], tbs_seq.length - tbs_offset, &elem) || elem.tag != ASN1_TAG_INTEGER) {
        return false;
    }
    cert->serial = elem.data;
    cert->serial_len = elem.length;
    tbs_offset += elem.header_length + elem.length;

    /* Signature Algorithm Identifier (SEQUENCE) */
    if (!asn1_parse_element(&tbs_seq.data[tbs_offset], tbs_seq.length - tbs_offset, &elem) || elem.tag != ASN1_TAG_SEQUENCE) {
        return false;
    }
    const uint8_t *sig_oid;
    uint32_t sig_oid_len;
    if (asn1_get_oid(elem.data, elem.length, &sig_oid, &sig_oid_len)) {
        if (asn1_match_oid(sig_oid, sig_oid_len, OID_SHA256_WITH_RSA, sizeof(OID_SHA256_WITH_RSA))) {
            cert->signature_algo = X509_SIG_RSA_SHA256;
        } else if (asn1_match_oid(sig_oid, sig_oid_len, OID_RSA_PSS, sizeof(OID_RSA_PSS))) {
            cert->signature_algo = X509_SIG_RSA_PSS_SHA256;
        } else if (asn1_match_oid(sig_oid, sig_oid_len, OID_ECDSA_WITH_SHA256, sizeof(OID_ECDSA_WITH_SHA256))) {
            cert->signature_algo = X509_SIG_ECDSA_SHA256;
        }
    }
    tbs_offset += elem.header_length + elem.length;

    /* Issuer Name (SEQUENCE) */
    if (!asn1_parse_element(&tbs_seq.data[tbs_offset], tbs_seq.length - tbs_offset, &elem) || elem.tag != ASN1_TAG_SEQUENCE) {
        return false;
    }
    cert->issuer_raw = &tbs_seq.data[tbs_offset];
    cert->issuer_raw_len = elem.header_length + elem.length;
    parse_name_sequence(elem.data, elem.length, cert->issuer_cn, cert->issuer_org);
    tbs_offset += elem.header_length + elem.length;

    /* Validity (SEQUENCE: notBefore, notAfter) */
    if (!asn1_parse_element(&tbs_seq.data[tbs_offset], tbs_seq.length - tbs_offset, &elem) || elem.tag != ASN1_TAG_SEQUENCE) {
        return false;
    }
    uint32_t val_offset = 0;
    struct asn1_element time_elem;
    if (asn1_parse_element(&elem.data[val_offset], elem.length - val_offset, &time_elem)) {
        asn1_parse_time(time_elem.data, time_elem.length, time_elem.tag, &cert->not_before);
        val_offset += time_elem.header_length + time_elem.length;
    }
    if (val_offset < elem.length && asn1_parse_element(&elem.data[val_offset], elem.length - val_offset, &time_elem)) {
        asn1_parse_time(time_elem.data, time_elem.length, time_elem.tag, &cert->not_after);
    }
    tbs_offset += elem.header_length + elem.length;

    /* Subject Name (SEQUENCE) */
    if (!asn1_parse_element(&tbs_seq.data[tbs_offset], tbs_seq.length - tbs_offset, &elem) || elem.tag != ASN1_TAG_SEQUENCE) {
        return false;
    }
    cert->subject_raw = &tbs_seq.data[tbs_offset];
    cert->subject_raw_len = elem.header_length + elem.length;
    parse_name_sequence(elem.data, elem.length, cert->subject_cn, cert->subject_org);
    tbs_offset += elem.header_length + elem.length;

    /* SubjectPublicKeyInfo (SEQUENCE) */
    if (!asn1_parse_element(&tbs_seq.data[tbs_offset], tbs_seq.length - tbs_offset, &elem) || elem.tag != ASN1_TAG_SEQUENCE) {
        return false;
    }
    uint32_t spki_offset = 0;
    struct asn1_element alg_id;
    if (asn1_parse_element(&elem.data[spki_offset], elem.length - spki_offset, &alg_id) && alg_id.tag == ASN1_TAG_SEQUENCE) {
        spki_offset += alg_id.header_length + alg_id.length;
        const uint8_t *key_oid;
        uint32_t key_oid_len;
        if (asn1_get_oid(alg_id.data, alg_id.length, &key_oid, &key_oid_len)) {
            if (asn1_match_oid(key_oid, key_oid_len, OID_RSA_ENCRYPTION, sizeof(OID_RSA_ENCRYPTION))) {
                cert->pubkey_type = X509_KEY_RSA;
            } else if (asn1_match_oid(key_oid, key_oid_len, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY))) {
                cert->pubkey_type = X509_KEY_ECDSA_P256;
            }
        }
    }

    struct asn1_element pub_bits;
    if (spki_offset < elem.length && asn1_parse_element(&elem.data[spki_offset], elem.length - spki_offset, &pub_bits) && pub_bits.tag == ASN1_TAG_BIT_STRING) {
        const uint8_t *key_bytes = pub_bits.data + 1; /* Skip unused bits byte */
        uint32_t key_len = pub_bits.length - 1;

        if (cert->pubkey_type == X509_KEY_RSA) {
            /* Parse RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER } */
            struct asn1_element rsa_seq;
            if (asn1_get_sequence(key_bytes, key_len, &rsa_seq)) {
                uint32_t rsa_off = 0;
                struct asn1_element mod_elem;
                if (asn1_parse_element(&rsa_seq.data[rsa_off], rsa_seq.length - rsa_off, &mod_elem) && mod_elem.tag == ASN1_TAG_INTEGER) {
                    cert->rsa_modulus = mod_elem.data;
                    cert->rsa_modulus_len = mod_elem.length;
                    /* Strip leading zero if present in ASN.1 positive integer */
                    if (cert->rsa_modulus_len > 0 && cert->rsa_modulus[0] == 0x00) {
                        cert->rsa_modulus += 1;
                        cert->rsa_modulus_len -= 1;
                    }
                    rsa_off += mod_elem.header_length + mod_elem.length;
                }
                struct asn1_element exp_elem;
                if (rsa_off < rsa_seq.length && asn1_parse_element(&rsa_seq.data[rsa_off], rsa_seq.length - rsa_off, &exp_elem) && exp_elem.tag == ASN1_TAG_INTEGER) {
                    cert->rsa_exponent = exp_elem.data;
                    cert->rsa_exponent_len = exp_elem.length;
                }
            }
        } else if (cert->pubkey_type == X509_KEY_ECDSA_P256) {
            /* Uncompressed EC point: 0x04 || X (32 bytes) || Y (32 bytes) */
            if (key_len >= 65 && key_bytes[0] == 0x04) {
                for (int i = 0; i < 32; ++i) {
                    cert->ec_pubkey_x[i] = key_bytes[1 + i];
                    cert->ec_pubkey_y[i] = key_bytes[33 + i];
                }
            }
        }
    }
    tbs_offset += elem.header_length + elem.length;

    /* Extensions (optional [3] EXPLICIT Extensions) */
    while (tbs_offset < tbs_seq.length) {
        if (!asn1_parse_element(&tbs_seq.data[tbs_offset], tbs_seq.length - tbs_offset, &elem)) break;
        tbs_offset += elem.header_length + elem.length;
        if (elem.tag == ASN1_TAG_CONTEXT_3) {
            parse_extensions(elem.data, elem.length, cert);
        }
    }

    /* 3. Outer Signature Algorithm Identifier (SEQUENCE) */
    uint32_t root_offset = tbs_seq.header_length + tbs_seq.length;
    if (root_offset < root_seq.length) {
        if (asn1_parse_element(&root_seq.data[root_offset], root_seq.length - root_offset, &elem)) {
            root_offset += elem.header_length + elem.length;
        }
    }

    /* 4. Signature Value (BIT STRING) */
    if (root_offset < root_seq.length) {
        if (asn1_parse_element(&root_seq.data[root_offset], root_seq.length - root_offset, &elem) && elem.tag == ASN1_TAG_BIT_STRING && elem.length > 1) {
            cert->signature = elem.data + 1;
            cert->signature_len = elem.length - 1;
        }
    }

    return true;
}

/* =========================================================================
 * 4. Hostname Verification
 * ========================================================================= */

static bool match_domain_pattern(const char *pattern, const char *hostname) {
    if (pattern == 0 || hostname == 0) return false;

    /* Exact match */
    if (str_eq_case_insensitive(pattern, hostname)) {
        return true;
    }

    /* Wildcard match: *.example.com matches foo.example.com */
    if (pattern[0] == '*' && pattern[1] == '.') {
        const char *suffix = pattern + 1; /* .example.com */
        uint32_t s_len = str_len(suffix);
        uint32_t h_len = str_len(hostname);

        if (h_len > s_len && str_eq_case_insensitive(&hostname[h_len - s_len], suffix)) {
            /* Verify no extra dots in left prefix: bar.foo.example.com does not match *.example.com */
            for (uint32_t i = 0; i < h_len - s_len; ++i) {
                if (hostname[i] == '.') return false;
            }
            return true;
        }
    }

    return false;
}

bool x509_verify_hostname(const struct x509_certificate *cert, const char *hostname) {
    if (cert == 0 || hostname == 0) return false;

    /* 1. Check Subject Alternative Names (SAN) */
    if (cert->san_count > 0) {
        for (uint32_t i = 0; i < cert->san_count; ++i) {
            if (match_domain_pattern(cert->san_dns_names[i], hostname)) {
                return true;
            }
        }
        return false;
    }

    /* 2. Fallback to Common Name (CN) */
    if (cert->subject_cn[0] != '\0') {
        return match_domain_pattern(cert->subject_cn, hostname);
    }

    return false;
}

/* =========================================================================
 * 5. Signature Verification
 * ========================================================================= */

enum x509_verify_result x509_verify_cert_signature(const struct x509_certificate *cert, const struct x509_certificate *issuer_cert) {
    if (cert == 0 || issuer_cert == 0 || cert->tbs_der == 0 || cert->tbs_len == 0 || cert->signature == 0) {
        return X509_V_ERR_SIGNATURE_INVALID;
    }

    /* Hash the TBS Certificate */
    uint8_t hash[32];
    kos_sha256(cert->tbs_der, cert->tbs_len, hash);

    if (issuer_cert->pubkey_type == X509_KEY_RSA) {
        if (cert->signature_algo == X509_SIG_RSA_PSS_SHA256) {
            if (!kos_rsa_pss_verify_sha256(issuer_cert->rsa_modulus, issuer_cert->rsa_modulus_len,
                    issuer_cert->rsa_exponent, issuer_cert->rsa_exponent_len,
                    hash, cert->signature, cert->signature_len)) {
                return X509_V_ERR_SIGNATURE_INVALID;
            }
        } else {
            if (!kos_rsa_pkcs1_verify_sha256(issuer_cert->rsa_modulus, issuer_cert->rsa_modulus_len,
                    issuer_cert->rsa_exponent, issuer_cert->rsa_exponent_len,
                    hash, cert->signature, cert->signature_len)) {
                return X509_V_ERR_SIGNATURE_INVALID;
            }
        }
    } else if (issuer_cert->pubkey_type == X509_KEY_ECDSA_P256) {
        /* Parse ECDSA signature: SEQUENCE { r INTEGER, s INTEGER } */
        struct asn1_element sig_seq;
        if (asn1_get_sequence(cert->signature, cert->signature_len, &sig_seq)) {
            const uint8_t *r_data = 0, *s_data = 0;
            uint32_t r_len = 0, s_len = 0;
            uint32_t off = 0;
            struct asn1_element r_elem;
            if (asn1_parse_element(&sig_seq.data[off], sig_seq.length - off, &r_elem) && r_elem.tag == ASN1_TAG_INTEGER) {
                r_data = r_elem.data; r_len = r_elem.length;
                off += r_elem.header_length + r_elem.length;
            }
            struct asn1_element s_elem;
            if (off < sig_seq.length && asn1_parse_element(&sig_seq.data[off], sig_seq.length - off, &s_elem) && s_elem.tag == ASN1_TAG_INTEGER) {
                s_data = s_elem.data; s_len = s_elem.length;
            }
            if (r_data && s_data) {
                uint8_t r32[32] = {0}, s32[32] = {0};
                if (r_len > 0 && r_data[0] == 0x00) { r_data++; r_len--; }
                if (s_len > 0 && s_data[0] == 0x00) { s_data++; s_len--; }
                if (r_len <= 32 && s_len <= 32) {
                    for (uint32_t i = 0; i < r_len; ++i) r32[32 - r_len + i] = r_data[i];
                    for (uint32_t i = 0; i < s_len; ++i) s32[32 - s_len + i] = s_data[i];
                    if (!kos_ecdsa_p256_verify(issuer_cert->ec_pubkey_x, issuer_cert->ec_pubkey_y, hash, r32, s32)) {
                        return X509_V_ERR_SIGNATURE_INVALID;
                    }
                }
            }
        }
    }

    return X509_V_OK;
}

/* =========================================================================
 * 6. Chain Verification against Trust Store
 * ========================================================================= */

enum x509_verify_result x509_verify_chain(const struct x509_chain *chain, const char *hostname, uint64_t current_time_sec) {
    if (chain == 0 || chain->count == 0) {
        return X509_V_ERR_INVALID_CHAIN;
    }

    /* 1. Verify Leaf Certificate Hostname */
    if (hostname != 0 && !x509_verify_hostname(&chain->certs[0], hostname)) {
        return X509_V_ERR_HOSTNAME_MISMATCH;
    }

    /* 2. Verify Time Validity for all certs in chain */
    for (uint32_t i = 0; i < chain->count; ++i) {
        const struct x509_certificate *c = &chain->certs[i];
        if (current_time_sec > 0) {
            if (c->not_before > 0 && current_time_sec < c->not_before) {
                return X509_V_ERR_NOT_YET_VALID;
            }
            if (c->not_after > 0 && current_time_sec > c->not_after) {
                return X509_V_ERR_EXPIRED;
            }
        }
    }

    /* 3. Verify Signature Linkage along the chain */
    for (uint32_t i = 0; i < chain->count - 1; ++i) {
        enum x509_verify_result res = x509_verify_cert_signature(&chain->certs[i], &chain->certs[i + 1]);
        if (res != X509_V_OK) {
            return res;
        }
    }

    return X509_V_OK;
}
