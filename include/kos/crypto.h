#ifndef KOS_CRYPTO_H
#define KOS_CRYPTO_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* SHA-256 Context (32-byte digest, 64-byte block) */
struct kos_sha256_context {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t buffer[64];
    uint64_t buffer_size;
};

void kos_sha256_initialize(struct kos_sha256_context *context);
void kos_sha256_update(struct kos_sha256_context *context, const uint8_t *data, uint64_t size);
void kos_sha256_finalize(struct kos_sha256_context *context, uint8_t digest[32]);
void kos_sha256(const uint8_t *data, uint64_t size, uint8_t digest[32]);

/* SHA-384 Context (48-byte digest, 128-byte block) */
struct kos_sha384_context {
    uint64_t state[8];
    uint64_t bit_count_high;
    uint64_t bit_count_low;
    uint8_t buffer[128];
    uint64_t buffer_size;
};

void kos_sha384_initialize(struct kos_sha384_context *context);
void kos_sha384_update(struct kos_sha384_context *context, const uint8_t *data, uint64_t size);
void kos_sha384_finalize(struct kos_sha384_context *context, uint8_t digest[48]);
void kos_sha384(const uint8_t *data, uint64_t size, uint8_t digest[48]);

/* HMAC */
void kos_hmac_sha256(const uint8_t *key, uint64_t key_size, const uint8_t *data, uint64_t data_size,
    uint8_t digest[32]);
void kos_hmac_sha384(const uint8_t *key, uint64_t key_size, const uint8_t *data, uint64_t data_size,
    uint8_t digest[48]);

/* HKDF (RFC 5869 & RFC 8446) */
bool kos_hkdf_sha256(const uint8_t *salt, uint64_t salt_size, const uint8_t *ikm,
    uint64_t ikm_size, const uint8_t *info, uint64_t info_size, uint8_t *output, uint64_t output_size);
bool kos_hkdf_extract_sha256(const uint8_t *salt, uint64_t salt_size, const uint8_t *ikm,
    uint64_t ikm_size, uint8_t prk[32]);
bool kos_hkdf_expand_sha256(const uint8_t prk[32], const uint8_t *info, uint64_t info_size,
    uint8_t *output, uint64_t output_size);
bool kos_hkdf_expand_label_sha256(const uint8_t secret[32], const char *label,
    const uint8_t *context, uint64_t context_size, uint8_t *output, uint16_t length);

/* X25519 ECDH (RFC 7748) */
bool kos_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t base[32]);
bool kos_x25519_base(uint8_t out[32], const uint8_t scalar[32]);

/* AES-GCM (NIST SP 800-38D) */
bool kos_aes128_gcm_encrypt(const uint8_t key[16], const uint8_t nonce[12],
    const uint8_t *aad, uint64_t aad_size, const uint8_t *plaintext, uint64_t size,
    uint8_t *ciphertext, uint8_t tag[16]);
bool kos_aes128_gcm_decrypt(const uint8_t key[16], const uint8_t nonce[12],
    const uint8_t *aad, uint64_t aad_size, const uint8_t *ciphertext, uint64_t size,
    const uint8_t tag[16], uint8_t *plaintext);
bool kos_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *aad, uint64_t aad_size, const uint8_t *plaintext, uint64_t size,
    uint8_t *ciphertext, uint8_t tag[16]);
bool kos_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *aad, uint64_t aad_size, const uint8_t *ciphertext, uint64_t size,
    const uint8_t tag[16], uint8_t *plaintext);

/* ChaCha20-Poly1305 AEAD (RFC 8439) */
bool kos_chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *aad, uint64_t aad_size, const uint8_t *plaintext, uint64_t size,
    uint8_t *ciphertext, uint8_t tag[16]);
bool kos_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *aad, uint64_t aad_size, const uint8_t *ciphertext, uint64_t size,
    const uint8_t tag[16], uint8_t *plaintext);

/* Signature Verification */
bool kos_ecdsa_p256_verify(const uint8_t pubkey_x[32], const uint8_t pubkey_y[32],
    const uint8_t hash[32], const uint8_t r[32], const uint8_t s[32]);
bool kos_rsa_pkcs1_verify_sha256(const uint8_t *modulus, uint32_t mod_len,
    const uint8_t *exponent, uint32_t exp_len,
    const uint8_t hash[32], const uint8_t *sig, uint32_t sig_len);
bool kos_rsa_pss_verify_sha256(const uint8_t *modulus, uint32_t mod_len,
    const uint8_t *exponent, uint32_t exp_len,
    const uint8_t hash[32], const uint8_t *sig, uint32_t sig_len);

/* Self-test */
bool kos_crypto_self_test(void);

/* Entropy / Hardware RNG */
struct kos_entropy_status {
    bool initialized;
    bool hardware_source;
    uint64_t samples;
};

bool kos_entropy_initialize(void);
bool kos_entropy_status(struct kos_entropy_status *status);
bool kos_entropy_fill(uint8_t *output, uint64_t size);

#endif /* KOS_CRYPTO_H */
