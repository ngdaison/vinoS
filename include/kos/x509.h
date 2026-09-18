#ifndef KOS_X509_H
#define KOS_X509_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* =========================================================================
 * 1. ASN.1 DER Definitions
 * ========================================================================= */

enum asn1_tag {
    ASN1_TAG_BOOLEAN          = 0x01,
    ASN1_TAG_INTEGER          = 0x02,
    ASN1_TAG_BIT_STRING       = 0x03,
    ASN1_TAG_OCTET_STRING     = 0x04,
    ASN1_TAG_NULL             = 0x05,
    ASN1_TAG_OBJECT_ID        = 0x06,
    ASN1_TAG_UTF8_STRING      = 0x0C,
    ASN1_TAG_PRINTABLE_STRING = 0x13,
    ASN1_TAG_TELETEX_STRING   = 0x14,
    ASN1_TAG_IA5_STRING       = 0x16,
    ASN1_TAG_UTC_TIME         = 0x17,
    ASN1_TAG_GENERALIZED_TIME = 0x18,
    ASN1_TAG_SEQUENCE         = 0x30,
    ASN1_TAG_SET              = 0x31,
    ASN1_TAG_CONTEXT_0        = 0xA0,
    ASN1_TAG_CONTEXT_1        = 0xA1,
    ASN1_TAG_CONTEXT_2        = 0xA2,
    ASN1_TAG_CONTEXT_3        = 0xA3,
};

struct asn1_element {
    uint8_t tag;
    bool constructed;
    const uint8_t *data;
    uint32_t length;
    uint32_t header_length;
};

/* Strict bounds-checked ASN.1 DER Parser */
bool asn1_parse_element(const uint8_t *buffer, uint32_t buffer_size, struct asn1_element *out_elem);
bool asn1_get_sequence(const uint8_t *buffer, uint32_t buffer_size, struct asn1_element *out_seq);
bool asn1_get_integer(const uint8_t *buffer, uint32_t buffer_size, const uint8_t **out_data, uint32_t *out_len);
bool asn1_get_bitstring(const uint8_t *buffer, uint32_t buffer_size, const uint8_t **out_data, uint32_t *out_len, uint8_t *out_unused_bits);
bool asn1_get_oid(const uint8_t *buffer, uint32_t buffer_size, const uint8_t **out_oid, uint32_t *out_len);
bool asn1_match_oid(const uint8_t *oid_data, uint32_t oid_len, const uint8_t *expected_oid, uint32_t expected_len);
bool asn1_parse_time(const uint8_t *buffer, uint32_t buffer_size, uint8_t tag, uint64_t *out_epoch_seconds);

/* Common OID Byte Arrays */
extern const uint8_t OID_RSA_ENCRYPTION[9];       /* 1.2.840.113549.1.1.1 */
extern const uint8_t OID_SHA256_WITH_RSA[9];     /* 1.2.840.113549.1.1.11 */
extern const uint8_t OID_RSA_PSS[9];             /* 1.2.840.113549.1.1.10 */
extern const uint8_t OID_EC_PUBLIC_KEY[7];       /* 1.2.840.10045.2.1 */
extern const uint8_t OID_SECP256R1[8];           /* 1.2.840.10045.3.1.7 */
extern const uint8_t OID_ECDSA_WITH_SHA256[8];   /* 1.2.840.10045.4.3.2 */
extern const uint8_t OID_COMMON_NAME[3];         /* 2.5.4.3 */
extern const uint8_t OID_ORGANIZATION[3];        /* 2.5.4.10 */
extern const uint8_t OID_SUBJECT_ALT_NAME[3];    /* 2.5.29.17 */
extern const uint8_t OID_BASIC_CONSTRAINTS[3];   /* 2.5.29.19 */
extern const uint8_t OID_KEY_USAGE[3];           /* 2.5.29.15 */

/* =========================================================================
 * 2. X.509 Certificate Representation
 * ========================================================================= */

enum x509_pubkey_type {
    X509_KEY_UNKNOWN = 0,
    X509_KEY_RSA,
    X509_KEY_ECDSA_P256,
};

enum x509_sig_algo {
    X509_SIG_UNKNOWN = 0,
    X509_SIG_RSA_SHA256,
    X509_SIG_RSA_PSS_SHA256,
    X509_SIG_ECDSA_SHA256,
};

#define X509_MAX_SAN_NAMES 16
#define X509_MAX_NAME_LEN  128

struct x509_certificate {
    const uint8_t *raw_der;
    uint32_t raw_len;

    /* TBS (To-Be-Signed) slice for signature verification */
    const uint8_t *tbs_der;
    uint32_t tbs_len;

    uint32_t version;
    const uint8_t *serial;
    uint32_t serial_len;

    enum x509_sig_algo signature_algo;

    /* Issuer and Subject */
    char issuer_cn[X509_MAX_NAME_LEN];
    char issuer_org[X509_MAX_NAME_LEN];
    const uint8_t *issuer_raw;
    uint32_t issuer_raw_len;

    char subject_cn[X509_MAX_NAME_LEN];
    char subject_org[X509_MAX_NAME_LEN];
    const uint8_t *subject_raw;
    uint32_t subject_raw_len;

    /* Validity (UNIX timestamps) */
    uint64_t not_before;
    uint64_t not_after;

    /* Public Key */
    enum x509_pubkey_type pubkey_type;
    const uint8_t *rsa_modulus;
    uint32_t rsa_modulus_len;
    const uint8_t *rsa_exponent;
    uint32_t rsa_exponent_len;
    uint8_t ec_pubkey_x[32];
    uint8_t ec_pubkey_y[32];

    /* Extensions */
    bool is_ca;
    uint32_t san_count;
    char san_dns_names[X509_MAX_SAN_NAMES][X509_MAX_NAME_LEN];

    /* Signature */
    const uint8_t *signature;
    uint32_t signature_len;
};

#define X509_MAX_CHAIN_DEPTH 8

struct x509_chain {
    struct x509_certificate certs[X509_MAX_CHAIN_DEPTH];
    uint32_t count;
};

/* =========================================================================
 * 3. Trust Store & Verification APIs
 * ========================================================================= */

enum x509_verify_result {
    X509_V_OK = 0,
    X509_V_ERR_PARSE_FAILED,
    X509_V_ERR_EXPIRED,
    X509_V_ERR_NOT_YET_VALID,
    X509_V_ERR_SIGNATURE_INVALID,
    X509_V_ERR_UNTRUSTED_ROOT,
    X509_V_ERR_HOSTNAME_MISMATCH,
    X509_V_ERR_INVALID_CHAIN,
};

bool x509_parse_certificate(const uint8_t *der, uint32_t der_len, struct x509_certificate *out_cert);
bool x509_verify_hostname(const struct x509_certificate *cert, const char *hostname);
enum x509_verify_result x509_verify_cert_signature(const struct x509_certificate *cert, const struct x509_certificate *issuer_cert);
enum x509_verify_result x509_verify_chain(const struct x509_chain *chain, const char *hostname, uint64_t current_time_sec);

/* Get current real time from RTC */
uint64_t x509_get_current_time_epoch(void);

#endif /* KOS_X509_H */
