#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/x509.h>

/* =========================================================================
 * Common OID Definitions
 * ========================================================================= */

const uint8_t OID_RSA_ENCRYPTION[9]     = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 }; /* 1.2.840.113549.1.1.1 */
const uint8_t OID_SHA256_WITH_RSA[9]    = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B }; /* 1.2.840.113549.1.1.11 */
const uint8_t OID_RSA_PSS[9]            = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A }; /* 1.2.840.113549.1.1.10 */
const uint8_t OID_EC_PUBLIC_KEY[7]      = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };             /* 1.2.840.10045.2.1 */
const uint8_t OID_SECP256R1[8]          = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };       /* 1.2.840.10045.3.1.7 */
const uint8_t OID_ECDSA_WITH_SHA256[8]  = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };       /* 1.2.840.10045.4.3.2 */
const uint8_t OID_COMMON_NAME[3]        = { 0x55, 0x04, 0x03 };                                     /* 2.5.4.3 */
const uint8_t OID_ORGANIZATION[3]       = { 0x55, 0x04, 0x0A };                                     /* 2.5.4.10 */
const uint8_t OID_SUBJECT_ALT_NAME[3]   = { 0x55, 0x1D, 0x11 };                                     /* 2.5.29.17 */
const uint8_t OID_BASIC_CONSTRAINTS[3]  = { 0x55, 0x1D, 0x13 };                                     /* 2.5.29.19 */
const uint8_t OID_KEY_USAGE[3]          = { 0x55, 0x1D, 0x0F };                                     /* 2.5.29.15 */

/* =========================================================================
 * Strict ASN.1 DER Parser
 * ========================================================================= */

bool asn1_parse_element(const uint8_t *buffer, uint32_t buffer_size, struct asn1_element *out_elem) {
    if (buffer == 0 || buffer_size < 2 || out_elem == 0) {
        return false;
    }

    uint32_t offset = 0;
    uint8_t tag = buffer[offset++];
    bool constructed = (tag & 0x20) != 0;

    /* Parse Length Octets per ITU-T X.690 DER rules */
    uint8_t len_byte = buffer[offset++];
    uint32_t length = 0;

    if ((len_byte & 0x80) == 0) {
        /* Short form: 0..127 */
        length = len_byte;
    } else {
        /* Long form: 1..4 bytes of length */
        uint32_t num_octets = len_byte & 0x7F;
        if (num_octets == 0 || num_octets > 4) {
            /* Indefinite length (0) is forbidden in DER; >4 is unreasonable */
            return false;
        }
        if (offset + num_octets > buffer_size) {
            return false;
        }
        /* DER requires minimum number of octets: first octet must not be 0 */
        if (buffer[offset] == 0) {
            return false;
        }
        for (uint32_t i = 0; i < num_octets; ++i) {
            length = (length << 8) | buffer[offset++];
        }
        /* DER requires that if length < 128, short form MUST be used */
        if (length < 128) {
            return false;
        }
    }

    /* Bounds check */
    if (offset + length > buffer_size) {
        return false;
    }

    out_elem->tag = tag;
    out_elem->constructed = constructed;
    out_elem->data = &buffer[offset];
    out_elem->length = length;
    out_elem->header_length = offset;

    return true;
}

bool asn1_get_sequence(const uint8_t *buffer, uint32_t buffer_size, struct asn1_element *out_seq) {
    struct asn1_element elem;
    if (!asn1_parse_element(buffer, buffer_size, &elem)) {
        return false;
    }
    if (elem.tag != ASN1_TAG_SEQUENCE) {
        return false;
    }
    if (out_seq != 0) {
        *out_seq = elem;
    }
    return true;
}

bool asn1_get_integer(const uint8_t *buffer, uint32_t buffer_size, const uint8_t **out_data, uint32_t *out_len) {
    struct asn1_element elem;
    if (!asn1_parse_element(buffer, buffer_size, &elem)) {
        return false;
    }
    if (elem.tag != ASN1_TAG_INTEGER || elem.length == 0) {
        return false;
    }
    if (out_data != 0) *out_data = elem.data;
    if (out_len != 0) *out_len = elem.length;
    return true;
}

bool asn1_get_bitstring(const uint8_t *buffer, uint32_t buffer_size, const uint8_t **out_data, uint32_t *out_len, uint8_t *out_unused_bits) {
    struct asn1_element elem;
    if (!asn1_parse_element(buffer, buffer_size, &elem)) {
        return false;
    }
    if (elem.tag != ASN1_TAG_BIT_STRING || elem.length == 0) {
        return false;
    }
    uint8_t unused = elem.data[0];
    if (unused > 7) {
        return false;
    }
    if (out_unused_bits != 0) *out_unused_bits = unused;
    if (out_data != 0) *out_data = elem.data + 1;
    if (out_len != 0) *out_len = elem.length - 1;
    return true;
}

bool asn1_get_oid(const uint8_t *buffer, uint32_t buffer_size, const uint8_t **out_oid, uint32_t *out_len) {
    struct asn1_element elem;
    if (!asn1_parse_element(buffer, buffer_size, &elem)) {
        return false;
    }
    if (elem.tag != ASN1_TAG_OBJECT_ID || elem.length == 0) {
        return false;
    }
    if (out_oid != 0) *out_oid = elem.data;
    if (out_len != 0) *out_len = elem.length;
    return true;
}

bool asn1_match_oid(const uint8_t *oid_data, uint32_t oid_len, const uint8_t *expected_oid, uint32_t expected_len) {
    if (oid_data == 0 || expected_oid == 0 || oid_len != expected_len) {
        return false;
    }
    for (uint32_t i = 0; i < oid_len; ++i) {
        if (oid_data[i] != expected_oid[i]) {
            return false;
        }
    }
    return true;
}

static uint32_t parse_2digits(const uint8_t *p) {
    return (uint32_t)((p[0] - '0') * 10 + (p[1] - '0'));
}

static bool is_leap_year(uint32_t year) {
    return ((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0);
}

static const uint32_t days_before_month[12] = {
    0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
};

static uint64_t calendar_to_epoch_seconds(uint32_t year, uint32_t month, uint32_t day,
        uint32_t hour, uint32_t min, uint32_t sec) {
    if (year < 1970 || month < 1 || month > 12 || day < 1 || day > 31) {
        return 0;
    }

    uint64_t days = 0;
    for (uint32_t y = 1970; y < year; ++y) {
        days += is_leap_year(y) ? 366 : 365;
    }
    days += days_before_month[month - 1];
    if (month > 2 && is_leap_year(year)) {
        days += 1;
    }
    days += (day - 1);

    return days * 86400ull + (uint64_t)hour * 3600ull + (uint64_t)min * 60ull + (uint64_t)sec;
}

bool asn1_parse_time(const uint8_t *buffer, uint32_t buffer_size, uint8_t tag, uint64_t *out_epoch_seconds) {
    if (buffer == 0 || out_epoch_seconds == 0) {
        return false;
    }

    uint32_t year = 0, month = 0, day = 0, hour = 0, min = 0, sec = 0;

    if (tag == ASN1_TAG_UTC_TIME) {
        /* UTCTime: YYMMDDHHMMSSZ (13 bytes) or YYMMDDHHMMZ (11 bytes) */
        if (buffer_size < 11) return false;
        uint32_t yy = parse_2digits(&buffer[0]);
        year = yy >= 50 ? 1900 + yy : 2000 + yy;
        month = parse_2digits(&buffer[2]);
        day = parse_2digits(&buffer[4]);
        hour = parse_2digits(&buffer[6]);
        min = parse_2digits(&buffer[8]);
        if (buffer_size >= 13 && buffer[10] >= '0' && buffer[10] <= '9') {
            sec = parse_2digits(&buffer[10]);
        }
    } else if (tag == ASN1_TAG_GENERALIZED_TIME) {
        /* GeneralizedTime: YYYYMMDDHHMMSSZ (15 bytes) */
        if (buffer_size < 13) return false;
        year = parse_2digits(&buffer[0]) * 100 + parse_2digits(&buffer[2]);
        month = parse_2digits(&buffer[4]);
        day = parse_2digits(&buffer[6]);
        hour = parse_2digits(&buffer[8]);
        min = parse_2digits(&buffer[10]);
        if (buffer_size >= 15 && buffer[12] >= '0' && buffer[12] <= '9') {
            sec = parse_2digits(&buffer[12]);
        }
    } else {
        return false;
    }

    *out_epoch_seconds = calendar_to_epoch_seconds(year, month, day, hour, min, sec);
    return true;
}
