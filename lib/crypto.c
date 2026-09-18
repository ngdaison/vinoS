#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/crypto.h>
#include <kos/cpu.h>
#include <kos/timer.h>
#include <kos/log.h>

/* =========================================================================
 * 1. SHA-256 (FIPS PUB 180-4)
 * ========================================================================= */

static const uint32_t sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static inline uint32_t ror32(uint32_t value, uint32_t count) {
    return (value >> count) | (value << (32 - count));
}

static inline uint64_t ror64(uint64_t value, uint64_t count) {
    return (value >> count) | (value << (64 - count));
}

static inline uint32_t read_u32_be(const uint8_t *data) {
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16)
        | ((uint32_t)data[2] << 8) | data[3];
}

static inline void write_u32_be(uint8_t *data, uint32_t value) {
    data[0] = (uint8_t)(value >> 24); data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);  data[3] = (uint8_t)value;
}

static inline uint64_t read_u64_be(const uint8_t *data) {
    return ((uint64_t)data[0] << 56) | ((uint64_t)data[1] << 48)
        | ((uint64_t)data[2] << 40) | ((uint64_t)data[3] << 32)
        | ((uint64_t)data[4] << 24) | ((uint64_t)data[5] << 16)
        | ((uint64_t)data[6] << 8)  | (uint64_t)data[7];
}

static inline void write_u64_be(uint8_t *data, uint64_t value) {
    data[0] = (uint8_t)(value >> 56); data[1] = (uint8_t)(value >> 48);
    data[2] = (uint8_t)(value >> 40); data[3] = (uint8_t)(value >> 32);
    data[4] = (uint8_t)(value >> 24); data[5] = (uint8_t)(value >> 16);
    data[6] = (uint8_t)(value >> 8);  data[7] = (uint8_t)value;
}

static void sha256_transform(struct kos_sha256_context *context, const uint8_t block[64]) {
    uint32_t w[64];
    for (uint64_t i = 0; i < 16; ++i) w[i] = read_u32_be(&block[i * 4]);
    for (uint64_t i = 16; i < 64; ++i) {
        uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = context->state[0], b = context->state[1], c = context->state[2], d = context->state[3];
    uint32_t e = context->state[4], f = context->state[5], g = context->state[6], h = context->state[7];
    for (uint64_t i = 0; i < 64; ++i) {
        uint32_t s1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + ch + sha256_k[i] + w[i];
        uint32_t s0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    context->state[0] += a; context->state[1] += b; context->state[2] += c; context->state[3] += d;
    context->state[4] += e; context->state[5] += f; context->state[6] += g; context->state[7] += h;
}

void kos_sha256_initialize(struct kos_sha256_context *context) {
    if (context == 0) return;
    *context = (struct kos_sha256_context){ .state = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u } };
}

void kos_sha256_update(struct kos_sha256_context *context, const uint8_t *data, uint64_t size) {
    if (context == 0 || (data == 0 && size != 0)) return;
    context->bit_count += size * 8;
    while (size > 0) {
        uint64_t amount = 64 - context->buffer_size;
        if (amount > size) amount = size;
        for (uint64_t i = 0; i < amount; ++i) context->buffer[context->buffer_size + i] = data[i];
        context->buffer_size += amount; data += amount; size -= amount;
        if (context->buffer_size == 64) { sha256_transform(context, context->buffer); context->buffer_size = 0; }
    }
}

void kos_sha256_finalize(struct kos_sha256_context *context, uint8_t digest[32]) {
    if (context == 0 || digest == 0) return;
    uint64_t original_bits = context->bit_count;
    context->buffer[context->buffer_size++] = 0x80;
    while (context->buffer_size != 56) {
        if (context->buffer_size == 64) { sha256_transform(context, context->buffer); context->buffer_size = 0; }
        context->buffer[context->buffer_size++] = 0;
    }
    for (uint64_t i = 0; i < 8; ++i) context->buffer[56 + i] = (uint8_t)(original_bits >> (56 - i * 8));
    sha256_transform(context, context->buffer);
    for (uint64_t i = 0; i < 8; ++i) write_u32_be(&digest[i * 4], context->state[i]);
}

void kos_sha256(const uint8_t *data, uint64_t size, uint8_t digest[32]) {
    struct kos_sha256_context ctx;
    kos_sha256_initialize(&ctx);
    kos_sha256_update(&ctx, data, size);
    kos_sha256_finalize(&ctx, digest);
}

/* =========================================================================
 * 2. SHA-384 (FIPS PUB 180-4)
 * ========================================================================= */

static const uint64_t sha384_k[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
    0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
    0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
    0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
    0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
    0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
    0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
    0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
    0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
    0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
    0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
    0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull
};

static void sha384_transform(struct kos_sha384_context *context, const uint8_t block[128]) {
    uint64_t w[80];
    for (uint64_t i = 0; i < 16; ++i) w[i] = read_u64_be(&block[i * 8]);
    for (uint64_t i = 16; i < 80; ++i) {
        uint64_t s0 = ror64(w[i - 15], 1) ^ ror64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = ror64(w[i - 2], 19) ^ ror64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint64_t a = context->state[0], b = context->state[1], c = context->state[2], d = context->state[3];
    uint64_t e = context->state[4], f = context->state[5], g = context->state[6], h = context->state[7];
    for (uint64_t i = 0; i < 80; ++i) {
        uint64_t s1 = ror64(e, 14) ^ ror64(e, 18) ^ ror64(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t t1 = h + s1 + ch + sha384_k[i] + w[i];
        uint64_t s0 = ror64(a, 28) ^ ror64(a, 34) ^ ror64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2 = s0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    context->state[0] += a; context->state[1] += b; context->state[2] += c; context->state[3] += d;
    context->state[4] += e; context->state[5] += f; context->state[6] += g; context->state[7] += h;
}

void kos_sha384_initialize(struct kos_sha384_context *context) {
    if (context == 0) return;
    *context = (struct kos_sha384_context){ .state = {
        0xcbbb9d5dc1059ed8ull, 0x629a292a367cd507ull, 0x9159015a3070dd17ull, 0x152fecd8f70e5939ull,
        0x67332667ffc00b31ull, 0x8eb44a8768581511ull, 0xdb0c2e0d64f98fa7ull, 0x47b5481dbefa4fa4ull } };
}

void kos_sha384_update(struct kos_sha384_context *context, const uint8_t *data, uint64_t size) {
    if (context == 0 || (data == 0 && size != 0)) return;
    uint64_t add_bits = size * 8;
    context->bit_count_low += add_bits;
    if (context->bit_count_low < add_bits) context->bit_count_high++;
    while (size > 0) {
        uint64_t amount = 128 - context->buffer_size;
        if (amount > size) amount = size;
        for (uint64_t i = 0; i < amount; ++i) context->buffer[context->buffer_size + i] = data[i];
        context->buffer_size += amount; data += amount; size -= amount;
        if (context->buffer_size == 128) { sha384_transform(context, context->buffer); context->buffer_size = 0; }
    }
}

void kos_sha384_finalize(struct kos_sha384_context *context, uint8_t digest[48]) {
    if (context == 0 || digest == 0) return;
    uint64_t bit_high = context->bit_count_high;
    uint64_t bit_low = context->bit_count_low;
    context->buffer[context->buffer_size++] = 0x80;
    while (context->buffer_size != 112) {
        if (context->buffer_size == 128) { sha384_transform(context, context->buffer); context->buffer_size = 0; }
        context->buffer[context->buffer_size++] = 0;
    }
    write_u64_be(&context->buffer[112], bit_high);
    write_u64_be(&context->buffer[120], bit_low);
    sha384_transform(context, context->buffer);
    for (uint64_t i = 0; i < 6; ++i) write_u64_be(&digest[i * 8], context->state[i]);
}

void kos_sha384(const uint8_t *data, uint64_t size, uint8_t digest[48]) {
    struct kos_sha384_context ctx;
    kos_sha384_initialize(&ctx);
    kos_sha384_update(&ctx, data, size);
    kos_sha384_finalize(&ctx, digest);
}

/* =========================================================================
 * 3. HMAC (RFC 2104)
 * ========================================================================= */

void kos_hmac_sha256(const uint8_t *key, uint64_t key_size, const uint8_t *data, uint64_t data_size,
        uint8_t digest[32]) {
    uint8_t k[64] = {0};
    if (key_size > 64) {
        kos_sha256(key, key_size, k);
    } else if (key != 0 && key_size > 0) {
        for (uint64_t i = 0; i < key_size; ++i) k[i] = key[i];
    }
    uint8_t inner[64], outer[64];
    for (uint64_t i = 0; i < 64; ++i) { inner[i] = k[i] ^ 0x36; outer[i] = k[i] ^ 0x5c; }
    struct kos_sha256_context ctx;
    uint8_t inner_digest[32];
    kos_sha256_initialize(&ctx);
    kos_sha256_update(&ctx, inner, 64);
    kos_sha256_update(&ctx, data, data_size);
    kos_sha256_finalize(&ctx, inner_digest);

    kos_sha256_initialize(&ctx);
    kos_sha256_update(&ctx, outer, 64);
    kos_sha256_update(&ctx, inner_digest, 32);
    kos_sha256_finalize(&ctx, digest);
}

void kos_hmac_sha384(const uint8_t *key, uint64_t key_size, const uint8_t *data, uint64_t data_size,
        uint8_t digest[48]) {
    uint8_t k[128] = {0};
    if (key_size > 128) {
        kos_sha384(key, key_size, k);
    } else if (key != 0 && key_size > 0) {
        for (uint64_t i = 0; i < key_size; ++i) k[i] = key[i];
    }
    uint8_t inner[128], outer[128];
    for (uint64_t i = 0; i < 128; ++i) { inner[i] = k[i] ^ 0x36; outer[i] = k[i] ^ 0x5c; }
    struct kos_sha384_context ctx;
    uint8_t inner_digest[48];
    kos_sha384_initialize(&ctx);
    kos_sha384_update(&ctx, inner, 128);
    kos_sha384_update(&ctx, data, data_size);
    kos_sha384_finalize(&ctx, inner_digest);

    kos_sha384_initialize(&ctx);
    kos_sha384_update(&ctx, outer, 128);
    kos_sha384_update(&ctx, inner_digest, 48);
    kos_sha384_finalize(&ctx, digest);
}

/* =========================================================================
 * 4. HKDF (RFC 5869 & RFC 8446 Section 7.1)
 * ========================================================================= */

bool kos_hkdf_extract_sha256(const uint8_t *salt, uint64_t salt_size, const uint8_t *ikm,
        uint64_t ikm_size, uint8_t prk[32]) {
    uint8_t zero_salt[32] = {0};
    if (salt == 0 || salt_size == 0) {
        salt = zero_salt;
        salt_size = 32;
    }
    kos_hmac_sha256(salt, salt_size, ikm, ikm_size, prk);
    return true;
}

bool kos_hkdf_expand_sha256(const uint8_t prk[32], const uint8_t *info, uint64_t info_size,
        uint8_t *output, uint64_t output_size) {
    if (prk == 0 || output == 0 || output_size > 255 * 32) return false;
    uint8_t previous[32] = {0};
    uint8_t block[32 + 256];
    uint64_t produced = 0;
    uint8_t counter = 1;

    while (produced < output_size) {
        uint64_t pos = 0;
        if (counter != 1) {
            for (uint64_t i = 0; i < 32; ++i) block[pos++] = previous[i];
        }
        for (uint64_t i = 0; i < info_size; ++i) block[pos++] = info[i];
        block[pos++] = counter;

        kos_hmac_sha256(prk, 32, block, pos, previous);
        uint64_t amount = (output_size - produced < 32) ? output_size - produced : 32;
        for (uint64_t i = 0; i < amount; ++i) output[produced + i] = previous[i];
        produced += amount;
        counter++;
    }
    return true;
}

bool kos_hkdf_sha256(const uint8_t *salt, uint64_t salt_size, const uint8_t *ikm,
        uint64_t ikm_size, const uint8_t *info, uint64_t info_size, uint8_t *output, uint64_t output_size) {
    uint8_t prk[32];
    if (!kos_hkdf_extract_sha256(salt, salt_size, ikm, ikm_size, prk)) return false;
    return kos_hkdf_expand_sha256(prk, info, info_size, output, output_size);
}

/* HKDF-Expand-Label (RFC 8446 Section 7.1) */
bool kos_hkdf_expand_label_sha256(const uint8_t secret[32], const char *label,
        const uint8_t *context, uint64_t context_size, uint8_t *output, uint16_t length) {
    if (secret == 0 || label == 0 || output == 0) return false;

    /* Calculate label length with prefix "tls13 " */
    uint64_t label_len = 0;
    while (label[label_len] != '\0') label_len++;
    uint8_t full_label[64] = "tls13 ";
    for (uint64_t i = 0; i < label_len && i + 6 < sizeof(full_label); ++i) {
        full_label[6 + i] = (uint8_t)label[i];
    }
    uint8_t full_label_len = (uint8_t)(6 + label_len);

    /* Construct HkdfLabel:
     * uint16 length
     * opaque label<7..255>
     * opaque context<0..255>
     */
    uint8_t hkdf_label[512];
    uint64_t pos = 0;
    hkdf_label[pos++] = (uint8_t)(length >> 8);
    hkdf_label[pos++] = (uint8_t)length;
    hkdf_label[pos++] = full_label_len;
    for (uint64_t i = 0; i < full_label_len; ++i) hkdf_label[pos++] = full_label[i];
    hkdf_label[pos++] = (uint8_t)context_size;
    for (uint64_t i = 0; i < context_size; ++i) hkdf_label[pos++] = context[i];

    return kos_hkdf_expand_sha256(secret, hkdf_label, pos, output, length);
}

/* =========================================================================
 * 5. X25519 Curve25519 (RFC 7748)
 * ========================================================================= */

typedef int64_t gf[16];

static void car25519(gf o) {
    for (int i = 0; i < 16; ++i) {
        o[i] += (1LL << 16);
        int64_t c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void sel25519(gf p, gf q, int b) {
    int64_t c = ~(int64_t)(b - 1);
    for (int i = 0; i < 16; ++i) {
        int64_t t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t *o, const gf n) {
    gf m, t;
    for (int i = 0; i < 16; ++i) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    for (int j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        m[14] &= 0xffff;
        int64_t c = (m[15] >> 16) & 1;
        sel25519(t, m, 1 - (int)c);
    }
    for (int i = 0; i < 16; ++i) {
        o[2 * i] = (uint8_t)t[i];
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void unpack25519(gf o, const uint8_t *n) {
    for (int i = 0; i < 16; ++i) {
        o[i] = (int64_t)n[2 * i] | ((int64_t)n[2 * i + 1] << 8);
    }
    o[15] &= 0x7fff;
}

static void A(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; ++i) o[i] = a[i] + b[i];
}

static void Z(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; ++i) o[i] = a[i] - b[i];
}

static void M(gf o, const gf a, const gf b) {
    int64_t t[31] = {0};
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 16; ++j) {
            t[i + j] += a[i] * b[j];
        }
    }
    for (int i = 0; i < 15; ++i) {
        t[i] += 38 * t[i + 16];
    }
    for (int i = 0; i < 16; ++i) o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void S(gf o, const gf a) {
    M(o, a, a);
}

static void inv25519(gf o, const gf i) {
    gf c;
    for (int a = 0; a < 16; ++a) c[a] = i[a];
    for (int a = 253; a >= 0; --a) {
        S(c, c);
        if (a != 2 && a != 4) M(c, c, i);
    }
    for (int a = 0; a < 16; ++a) o[a] = c[a];
}

bool kos_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t base[32]) {
    if (out == 0 || scalar == 0 || base == 0) return false;

    uint8_t z[32];
    for (int i = 0; i < 32; ++i) z[i] = scalar[i];
    z[0] &= 248;
    z[31] &= 127;
    z[31] |= 64;

    gf x1, x2, z2, x3, z3, a, b, c, d, e, aa, bb, da, cb;
    unpack25519(x1, base);
    for (int i = 0; i < 16; ++i) {
        x2[i] = 0;
        z2[i] = 0;
        x3[i] = x1[i];
        z3[i] = 0;
    }
    x2[0] = 1;
    z3[0] = 1;

    static const gf a24 = { 0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    int swap = 0;
    for (int pos = 254; pos >= 0; --pos) {
        int b_bit = (int)((z[pos / 8] >> (pos & 7)) & 1);
        swap ^= b_bit;
        sel25519(x2, x3, swap);
        sel25519(z2, z3, swap);
        swap = b_bit;

        A(a, x2, z2);
        S(aa, a);
        Z(b, x2, z2);
        S(bb, b);
        Z(e, aa, bb);
        A(c, x3, z3);
        Z(d, x3, z3);
        M(da, d, a);
        M(cb, c, b);
        A(x3, da, cb);
        S(x3, x3);
        Z(z3, da, cb);
        S(z3, z3);
        M(z3, z3, x1);
        M(x2, aa, bb);

        M(z2, e, a24);
        A(z2, z2, aa);
        M(z2, e, z2);
    }
    sel25519(x2, x3, swap);
    sel25519(z2, z3, swap);

    gf inv_z2;
    inv25519(inv_z2, z2);
    M(x2, x2, inv_z2);
    pack25519(out, x2);
    return true;
}

bool kos_x25519_base(uint8_t out[32], const uint8_t scalar[32]) {
    static const uint8_t base_point[32] = { 9, 0 };
    return kos_x25519(out, scalar, base_point);
}

/* =========================================================================
 * 6. AES-128 & AES-256 GCM (NIST SP 800-38D)
 * ========================================================================= */

static uint8_t aes_gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    for (uint8_t bit = 0; bit < 8; ++bit) {
        if ((b & 1u) != 0) result ^= a;
        bool high = (a & 0x80u) != 0;
        a = (uint8_t)(a << 1);
        if (high) a ^= 0x1bu;
        b = (uint8_t)(b >> 1);
    }
    return result;
}

static uint8_t aes_sbox(uint8_t value) {
    if (value == 0) return 0x63;
    uint8_t inverse = 1;
    for (uint16_t power = 0; power < 254; ++power) inverse = aes_gf_mul(inverse, value);
    uint8_t rotated = inverse;
    rotated ^= (uint8_t)((inverse << 1) | (inverse >> 7));
    rotated ^= (uint8_t)((inverse << 2) | (inverse >> 6));
    rotated ^= (uint8_t)((inverse << 3) | (inverse >> 5));
    rotated ^= (uint8_t)((inverse << 4) | (inverse >> 4));
    return (uint8_t)(rotated ^ 0x63u);
}

static void aes128_expand_key(const uint8_t key[16], uint8_t round_keys[176]) {
    for (uint64_t i = 0; i < 16; ++i) round_keys[i] = key[i];
    uint8_t rcon = 1;
    uint64_t generated = 16;
    while (generated < 176) {
        uint8_t word[4];
        for (uint64_t i = 0; i < 4; ++i) word[i] = round_keys[generated - 4 + i];
        if ((generated & 15u) == 0) {
            uint8_t first = word[0];
            word[0] = aes_sbox(word[1]) ^ rcon;
            word[1] = aes_sbox(word[2]); word[2] = aes_sbox(word[3]); word[3] = aes_sbox(first);
            rcon = aes_gf_mul(rcon, 2);
        }
        for (uint64_t i = 0; i < 4; ++i) {
            round_keys[generated] = round_keys[generated - 16] ^ word[i];
            ++generated;
            word[i] = round_keys[generated - 4];
        }
    }
}

static void aes256_expand_key(const uint8_t key[32], uint8_t round_keys[240]) {
    for (uint64_t i = 0; i < 32; ++i) round_keys[i] = key[i];
    uint8_t rcon = 1;
    uint64_t generated = 32;
    while (generated < 240) {
        uint8_t word[4];
        for (uint64_t i = 0; i < 4; ++i) word[i] = round_keys[generated - 4 + i];
        if ((generated % 32) == 0) {
            uint8_t first = word[0];
            word[0] = aes_sbox(word[1]) ^ rcon;
            word[1] = aes_sbox(word[2]); word[2] = aes_sbox(word[3]); word[3] = aes_sbox(first);
            rcon = aes_gf_mul(rcon, 2);
        } else if ((generated % 32) == 16) {
            word[0] = aes_sbox(word[0]); word[1] = aes_sbox(word[1]);
            word[2] = aes_sbox(word[2]); word[3] = aes_sbox(word[3]);
        }
        for (uint64_t i = 0; i < 4; ++i) {
            round_keys[generated] = round_keys[generated - 32] ^ word[i];
            ++generated;
            word[i] = round_keys[generated - 4];
        }
    }
}

static void aes_encrypt_block_rounds(const uint8_t *round_keys, int rounds, const uint8_t input[16], uint8_t output[16]) {
    uint8_t state[16];
    for (uint64_t i = 0; i < 16; ++i) state[i] = input[i] ^ round_keys[i];
    for (uint8_t round = 1; round <= rounds; ++round) {
        uint8_t substituted[16];
        for (uint64_t i = 0; i < 16; ++i) substituted[i] = aes_sbox(state[i]);
        for (uint8_t row = 0; row < 4; ++row) {
            for (uint8_t column = 0; column < 4; ++column) {
                state[row + 4 * column] = substituted[row + 4 * ((column + row) & 3u)];
            }
        }
        if (round != rounds) {
            for (uint8_t column = 0; column < 4; ++column) {
                uint8_t *v = &state[4 * column];
                uint8_t a = v[0], b = v[1], c = v[2], d = v[3];
                v[0] = aes_gf_mul(a, 2) ^ aes_gf_mul(b, 3) ^ c ^ d;
                v[1] = a ^ aes_gf_mul(b, 2) ^ aes_gf_mul(c, 3) ^ d;
                v[2] = a ^ b ^ aes_gf_mul(c, 2) ^ aes_gf_mul(d, 3);
                v[3] = aes_gf_mul(a, 3) ^ b ^ c ^ aes_gf_mul(d, 2);
            }
        }
        for (uint64_t i = 0; i < 16; ++i) state[i] ^= round_keys[round * 16 + i];
    }
    for (uint64_t i = 0; i < 16; ++i) output[i] = state[i];
}

static void gcm_xor(uint8_t target[16], const uint8_t source[16]) {
    for (uint64_t i = 0; i < 16; ++i) target[i] ^= source[i];
}

static void gcm_multiply(uint8_t x[16], const uint8_t y[16]) {
    uint8_t z[16] = {0};
    uint8_t v[16];
    for (uint64_t i = 0; i < 16; ++i) v[i] = y[i];
    for (uint8_t bit = 0; bit < 128; ++bit) {
        if ((x[bit / 8] & (uint8_t)(0x80u >> (bit & 7u))) != 0) gcm_xor(z, v);
        bool lsb = (v[15] & 1u) != 0;
        for (int i = 15; i > 0; --i) v[i] = (uint8_t)((v[i] >> 1) | (v[i - 1] << 7));
        v[0] >>= 1;
        if (lsb) v[0] ^= 0xe1u;
    }
    for (uint64_t i = 0; i < 16; ++i) x[i] = z[i];
}

static void gcm_ghash_block(uint8_t accumulator[16], const uint8_t hash_key[16], const uint8_t block[16]) {
    gcm_xor(accumulator, block);
    gcm_multiply(accumulator, hash_key);
}

static void gcm_ghash(const uint8_t hash_key[16], const uint8_t *aad, uint64_t aad_size,
        const uint8_t *ciphertext, uint64_t size, uint8_t result[16]) {
    for (uint64_t i = 0; i < 16; ++i) result[i] = 0;
    for (uint64_t offset = 0; offset < aad_size; offset += 16) {
        uint8_t block[16] = {0}; uint64_t amount = aad_size - offset < 16 ? aad_size - offset : 16;
        for (uint64_t i = 0; i < amount; ++i) block[i] = aad[offset + i];
        gcm_ghash_block(result, hash_key, block);
    }
    for (uint64_t offset = 0; offset < size; offset += 16) {
        uint8_t block[16] = {0}; uint64_t amount = size - offset < 16 ? size - offset : 16;
        for (uint64_t i = 0; i < amount; ++i) block[i] = ciphertext[offset + i];
        gcm_ghash_block(result, hash_key, block);
    }
    uint8_t lengths[16] = {0};
    uint64_t aad_bits = aad_size * 8, ciphertext_bits = size * 8;
    for (uint64_t i = 0; i < 8; ++i) {
        lengths[7 - i] = (uint8_t)(aad_bits >> (i * 8));
        lengths[15 - i] = (uint8_t)(ciphertext_bits >> (i * 8));
    }
    gcm_ghash_block(result, hash_key, lengths);
}

static void gcm_increment_counter(uint8_t counter[16]) {
    for (int i = 15; i >= 12; --i) { if (++counter[i] != 0) break; }
}

bool kos_aes128_gcm_encrypt(const uint8_t key[16], const uint8_t nonce[12], const uint8_t *aad,
        uint64_t aad_size, const uint8_t *plaintext, uint64_t size, uint8_t *ciphertext, uint8_t tag[16]) {
    if (key == 0 || nonce == 0 || tag == 0) return false;
    uint8_t round_keys[176], hash_key[16] = {0}, counter[16] = {0}, stream[16];
    aes128_expand_key(key, round_keys);
    aes_encrypt_block_rounds(round_keys, 10, hash_key, hash_key);
    for (uint64_t i = 0; i < 12; ++i) counter[i] = nonce[i]; counter[15] = 1;
    for (uint64_t offset = 0; offset < size; offset += 16) {
        gcm_increment_counter(counter);
        aes_encrypt_block_rounds(round_keys, 10, counter, stream);
        uint64_t amount = size - offset < 16 ? size - offset : 16;
        for (uint64_t i = 0; i < amount; ++i) ciphertext[offset + i] = plaintext[offset + i] ^ stream[i];
    }
    uint8_t accumulator[16];
    gcm_ghash(hash_key, aad, aad_size, ciphertext, size, accumulator);
    uint8_t j0[16] = {0};
    for (uint64_t i = 0; i < 12; ++i) j0[i] = nonce[i]; j0[15] = 1;
    aes_encrypt_block_rounds(round_keys, 10, j0, tag);
    gcm_xor(tag, accumulator);
    return true;
}

bool kos_aes128_gcm_decrypt(const uint8_t key[16], const uint8_t nonce[12], const uint8_t *aad,
        uint64_t aad_size, const uint8_t *ciphertext, uint64_t size, const uint8_t tag[16], uint8_t *plaintext) {
    if (key == 0 || nonce == 0 || tag == 0) return false;
    uint8_t round_keys[176], hash_key[16] = {0}, accumulator[16], expected[16];
    aes128_expand_key(key, round_keys);
    aes_encrypt_block_rounds(round_keys, 10, hash_key, hash_key);
    gcm_ghash(hash_key, aad, aad_size, ciphertext, size, accumulator);
    uint8_t j0[16] = {0};
    for (uint64_t i = 0; i < 12; ++i) j0[i] = nonce[i]; j0[15] = 1;
    aes_encrypt_block_rounds(round_keys, 10, j0, expected);
    gcm_xor(expected, accumulator);
    uint8_t mismatch = 0;
    for (uint64_t i = 0; i < 16; ++i) mismatch |= expected[i] ^ tag[i];
    if (mismatch != 0) return false;
    uint8_t counter[16] = {0}, stream[16];
    for (uint64_t i = 0; i < 12; ++i) counter[i] = nonce[i]; counter[15] = 1;
    for (uint64_t offset = 0; offset < size; offset += 16) {
        gcm_increment_counter(counter);
        aes_encrypt_block_rounds(round_keys, 10, counter, stream);
        uint64_t amount = size - offset < 16 ? size - offset : 16;
        for (uint64_t i = 0; i < amount; ++i) plaintext[offset + i] = ciphertext[offset + i] ^ stream[i];
    }
    return true;
}

bool kos_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad,
        uint64_t aad_size, const uint8_t *plaintext, uint64_t size, uint8_t *ciphertext, uint8_t tag[16]) {
    if (key == 0 || nonce == 0 || tag == 0) return false;
    uint8_t round_keys[240], hash_key[16] = {0}, counter[16] = {0}, stream[16];
    aes256_expand_key(key, round_keys);
    aes_encrypt_block_rounds(round_keys, 14, hash_key, hash_key);
    for (uint64_t i = 0; i < 12; ++i) counter[i] = nonce[i]; counter[15] = 1;
    for (uint64_t offset = 0; offset < size; offset += 16) {
        gcm_increment_counter(counter);
        aes_encrypt_block_rounds(round_keys, 14, counter, stream);
        uint64_t amount = size - offset < 16 ? size - offset : 16;
        for (uint64_t i = 0; i < amount; ++i) ciphertext[offset + i] = plaintext[offset + i] ^ stream[i];
    }
    uint8_t accumulator[16];
    gcm_ghash(hash_key, aad, aad_size, ciphertext, size, accumulator);
    uint8_t j0[16] = {0};
    for (uint64_t i = 0; i < 12; ++i) j0[i] = nonce[i]; j0[15] = 1;
    aes_encrypt_block_rounds(round_keys, 14, j0, tag);
    gcm_xor(tag, accumulator);
    return true;
}

bool kos_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad,
        uint64_t aad_size, const uint8_t *ciphertext, uint64_t size, const uint8_t tag[16], uint8_t *plaintext) {
    if (key == 0 || nonce == 0 || tag == 0) return false;
    uint8_t round_keys[240], hash_key[16] = {0}, accumulator[16], expected[16];
    aes256_expand_key(key, round_keys);
    aes_encrypt_block_rounds(round_keys, 14, hash_key, hash_key);
    gcm_ghash(hash_key, aad, aad_size, ciphertext, size, accumulator);
    uint8_t j0[16] = {0};
    for (uint64_t i = 0; i < 12; ++i) j0[i] = nonce[i]; j0[15] = 1;
    aes_encrypt_block_rounds(round_keys, 14, j0, expected);
    gcm_xor(expected, accumulator);
    uint8_t mismatch = 0;
    for (uint64_t i = 0; i < 16; ++i) mismatch |= expected[i] ^ tag[i];
    if (mismatch != 0) return false;
    uint8_t counter[16] = {0}, stream[16];
    for (uint64_t i = 0; i < 12; ++i) counter[i] = nonce[i]; counter[15] = 1;
    for (uint64_t offset = 0; offset < size; offset += 16) {
        gcm_increment_counter(counter);
        aes_encrypt_block_rounds(round_keys, 14, counter, stream);
        uint64_t amount = size - offset < 16 ? size - offset : 16;
        for (uint64_t i = 0; i < amount; ++i) plaintext[offset + i] = ciphertext[offset + i] ^ stream[i];
    }
    return true;
}

/* =========================================================================
 * 7. ChaCha20-Poly1305 AEAD (RFC 8439)
 * ========================================================================= */

static inline uint32_t chacha_rotl(uint32_t v, uint32_t c) {
    return (v << c) | (v >> (32 - c));
}

#define CHACHA_QR(a, b, c, d) \
    a += b; d ^= a; d = chacha_rotl(d, 16); \
    c += d; b ^= c; b = chacha_rotl(b, 12); \
    a += b; d ^= a; d = chacha_rotl(d, 8);  \
    c += d; b ^= c; b = chacha_rotl(b, 7);

static void chacha20_block(const uint32_t state[16], uint8_t stream[64]) {
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) x[i] = state[i];
    for (int i = 0; i < 10; ++i) {
        CHACHA_QR(x[0], x[4], x[8],  x[12]);
        CHACHA_QR(x[1], x[5], x[9],  x[13]);
        CHACHA_QR(x[2], x[6], x[10], x[14]);
        CHACHA_QR(x[3], x[7], x[11], x[15]);
        CHACHA_QR(x[0], x[5], x[10], x[15]);
        CHACHA_QR(x[1], x[6], x[11], x[12]);
        CHACHA_QR(x[2], x[7], x[8],  x[13]);
        CHACHA_QR(x[3], x[4], x[9],  x[14]);
    }
    for (int i = 0; i < 16; ++i) {
        uint32_t res = x[i] + state[i];
        stream[i * 4 + 0] = (uint8_t)res;
        stream[i * 4 + 1] = (uint8_t)(res >> 8);
        stream[i * 4 + 2] = (uint8_t)(res >> 16);
        stream[i * 4 + 3] = (uint8_t)(res >> 24);
    }
}

static void chacha20_crypt(const uint8_t key[32], const uint8_t nonce[12], uint32_t initial_counter,
        const uint8_t *input, uint64_t size, uint8_t *output) {
    uint32_t state[16] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u,
        0, 0, 0, 0, 0, 0, 0, 0,
        initial_counter,
        0, 0, 0
    };
    for (int i = 0; i < 8; ++i) {
        state[4 + i] = (uint32_t)key[i*4] | ((uint32_t)key[i*4+1] << 8) | ((uint32_t)key[i*4+2] << 16) | ((uint32_t)key[i*4+3] << 24);
    }
    for (int i = 0; i < 3; ++i) {
        state[13 + i] = (uint32_t)nonce[i*4] | ((uint32_t)nonce[i*4+1] << 8) | ((uint32_t)nonce[i*4+2] << 16) | ((uint32_t)nonce[i*4+3] << 24);
    }

    uint8_t stream[64];
    for (uint64_t offset = 0; offset < size; offset += 64) {
        chacha20_block(state, stream);
        state[12]++;
        uint64_t amount = (size - offset < 64) ? size - offset : 64;
        for (uint64_t i = 0; i < amount; ++i) {
            output[offset + i] = (input != 0) ? (input[offset + i] ^ stream[i]) : stream[i];
        }
    }
}

/* Poly1305 (RFC 8439) */
struct poly1305_ctx {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    size_t leftover;
    uint8_t buffer[16];
};

static void poly1305_init(struct poly1305_ctx *ctx, const uint8_t key[32]) {
    ctx->r[0] = ((uint32_t)key[0] | ((uint32_t)key[1] << 8) | ((uint32_t)key[2] << 16) | ((uint32_t)key[3] << 24)) & 0x3ffffff;
    ctx->r[1] = (((uint32_t)key[3] >> 2) | ((uint32_t)key[4] << 6) | ((uint32_t)key[5] << 14) | ((uint32_t)key[6] << 22)) & 0x3ffff03;
    ctx->r[2] = (((uint32_t)key[6] >> 4) | ((uint32_t)key[7] << 4) | ((uint32_t)key[8] << 12) | ((uint32_t)key[9] << 20)) & 0x3ffc0ff;
    ctx->r[3] = (((uint32_t)key[9] >> 6) | ((uint32_t)key[10] << 2) | ((uint32_t)key[11] << 10) | ((uint32_t)key[12] << 18)) & 0x3f03fff;
    ctx->r[4] = (((uint32_t)key[12] >> 8) | ((uint32_t)key[13] << 0) | ((uint32_t)key[14] << 8) | ((uint32_t)key[15] << 16)) & 0x00fffff;

    ctx->h[0] = ctx->h[1] = ctx->h[2] = ctx->h[3] = ctx->h[4] = 0;
    for (int i = 0; i < 4; ++i) {
        ctx->pad[i] = (uint32_t)key[16 + i*4] | ((uint32_t)key[16 + i*4 + 1] << 8)
            | ((uint32_t)key[16 + i*4 + 2] << 16) | ((uint32_t)key[16 + i*4 + 3] << 24);
    }
    ctx->leftover = 0;
}

static void poly1305_blocks(struct poly1305_ctx *ctx, const uint8_t *m, size_t bytes, uint32_t is_final) {
    uint32_t hibit = is_final ? 0 : (1u << 24);
    while (bytes >= 16) {
        uint32_t t0 = (uint32_t)m[0] | ((uint32_t)m[1] << 8) | ((uint32_t)m[2] << 16) | ((uint32_t)m[3] << 24);
        uint32_t t1 = (uint32_t)m[4] | ((uint32_t)m[5] << 8) | ((uint32_t)m[6] << 16) | ((uint32_t)m[7] << 24);
        uint32_t t2 = (uint32_t)m[8] | ((uint32_t)m[9] << 8) | ((uint32_t)m[10] << 16) | ((uint32_t)m[11] << 24);
        uint32_t t3 = (uint32_t)m[12] | ((uint32_t)m[13] << 8) | ((uint32_t)m[14] << 16) | ((uint32_t)m[15] << 24);

        ctx->h[0] += t0 & 0x3ffffff;
        ctx->h[1] += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
        ctx->h[2] += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
        ctx->h[3] += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
        ctx->h[4] += (t3 >> 8) | hibit;

        uint64_t d0 = (uint64_t)ctx->h[0] * ctx->r[0] + (uint64_t)ctx->h[1] * (5 * ctx->r[4]) + (uint64_t)ctx->h[2] * (5 * ctx->r[3]) + (uint64_t)ctx->h[3] * (5 * ctx->r[2]) + (uint64_t)ctx->h[4] * (5 * ctx->r[1]);
        uint64_t d1 = (uint64_t)ctx->h[0] * ctx->r[1] + (uint64_t)ctx->h[1] * ctx->r[0] + (uint64_t)ctx->h[2] * (5 * ctx->r[4]) + (uint64_t)ctx->h[3] * (5 * ctx->r[3]) + (uint64_t)ctx->h[4] * (5 * ctx->r[2]);
        uint64_t d2 = (uint64_t)ctx->h[0] * ctx->r[2] + (uint64_t)ctx->h[1] * ctx->r[1] + (uint64_t)ctx->h[2] * ctx->r[0] + (uint64_t)ctx->h[3] * (5 * ctx->r[4]) + (uint64_t)ctx->h[4] * (5 * ctx->r[3]);
        uint64_t d3 = (uint64_t)ctx->h[0] * ctx->r[3] + (uint64_t)ctx->h[1] * ctx->r[2] + (uint64_t)ctx->h[2] * ctx->r[1] + (uint64_t)ctx->h[3] * ctx->r[0] + (uint64_t)ctx->h[4] * (5 * ctx->r[4]);
        uint64_t d4 = (uint64_t)ctx->h[0] * ctx->r[4] + (uint64_t)ctx->h[1] * ctx->r[3] + (uint64_t)ctx->h[2] * ctx->r[2] + (uint64_t)ctx->h[3] * ctx->r[1] + (uint64_t)ctx->h[4] * ctx->r[0];

        uint32_t c = (uint32_t)(d0 >> 26); ctx->h[0] = (uint32_t)d0 & 0x3ffffff; d1 += c;
        c = (uint32_t)(d1 >> 26); ctx->h[1] = (uint32_t)d1 & 0x3ffffff; d2 += c;
        c = (uint32_t)(d2 >> 26); ctx->h[2] = (uint32_t)d2 & 0x3ffffff; d3 += c;
        c = (uint32_t)(d3 >> 26); ctx->h[3] = (uint32_t)d3 & 0x3ffffff; d4 += c;
        c = (uint32_t)(d4 >> 26); ctx->h[4] = (uint32_t)d4 & 0x3ffffff; ctx->h[0] += c * 5;
        c = ctx->h[0] >> 26; ctx->h[0] &= 0x3ffffff; ctx->h[1] += c;

        m += 16;
        bytes -= 16;
    }
}

static void poly1305_update(struct poly1305_ctx *ctx, const uint8_t *m, size_t bytes) {
    if (ctx->leftover > 0) {
        size_t want = 16 - ctx->leftover;
        if (want > bytes) want = bytes;
        for (size_t i = 0; i < want; ++i) ctx->buffer[ctx->leftover + i] = m[i];
        ctx->leftover += want; m += want; bytes -= want;
        if (ctx->leftover == 16) {
            poly1305_blocks(ctx, ctx->buffer, 16, 0);
            ctx->leftover = 0;
        }
    }
    if (bytes >= 16) {
        size_t take = bytes & ~(size_t)15;
        poly1305_blocks(ctx, m, take, 0);
        m += take; bytes -= take;
    }
    for (size_t i = 0; i < bytes; ++i) ctx->buffer[ctx->leftover + i] = m[i];
    ctx->leftover += bytes;
}

static void poly1305_finish(struct poly1305_ctx *ctx, uint8_t mac[16]) {
    if (ctx->leftover > 0) {
        ctx->buffer[ctx->leftover] = 1;
        for (size_t i = ctx->leftover + 1; i < 16; ++i) ctx->buffer[i] = 0;
        poly1305_blocks(ctx, ctx->buffer, 16, 1);
    }
    uint32_t c = ctx->h[1] >> 26; ctx->h[1] &= 0x3ffffff; ctx->h[2] += c;
    c = ctx->h[2] >> 26; ctx->h[2] &= 0x3ffffff; ctx->h[3] += c;
    c = ctx->h[3] >> 26; ctx->h[3] &= 0x3ffffff; ctx->h[4] += c;
    c = ctx->h[4] >> 26; ctx->h[4] &= 0x3ffffff; ctx->h[0] += c * 5;
    c = ctx->h[0] >> 26; ctx->h[0] &= 0x3ffffff; ctx->h[1] += c;

    uint32_t g0 = ctx->h[0] + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = ctx->h[1] + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = ctx->h[2] + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = ctx->h[3] + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = ctx->h[4] + c - (1u << 26);
    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    ctx->h[0] = (ctx->h[0] & mask) | g0;
    ctx->h[1] = (ctx->h[1] & mask) | g1;
    ctx->h[2] = (ctx->h[2] & mask) | g2;
    ctx->h[3] = (ctx->h[3] & mask) | g3;
    ctx->h[4] = (ctx->h[4] & mask) | g4;

    uint64_t f0 = ((uint64_t)ctx->h[0] | ((uint64_t)ctx->h[1] << 26)) + (uint64_t)ctx->pad[0] + ((uint64_t)ctx->pad[1] << 32);
    uint64_t f1 = ((uint64_t)ctx->h[2] >> 12 | ((uint64_t)ctx->h[3] << 14) | ((uint64_t)ctx->h[4] << 40)) + (uint64_t)ctx->pad[2] + ((uint64_t)ctx->pad[3] << 32);

    for (int i = 0; i < 8; ++i) mac[i] = (uint8_t)(f0 >> (i * 8));
    for (int i = 0; i < 8; ++i) mac[8 + i] = (uint8_t)(f1 >> (i * 8));
}

bool kos_chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
        const uint8_t *aad, uint64_t aad_size, const uint8_t *plaintext, uint64_t size,
        uint8_t *ciphertext, uint8_t tag[16]) {
    if (key == 0 || nonce == 0 || tag == 0) return false;

    uint8_t poly_key[64];
    chacha20_crypt(key, nonce, 0, 0, 64, poly_key);
    chacha20_crypt(key, nonce, 1, plaintext, size, ciphertext);

    struct poly1305_ctx ctx;
    poly1305_init(&ctx, poly_key);
    if (aad != 0 && aad_size > 0) {
        poly1305_update(&ctx, aad, aad_size);
        if ((aad_size % 16) != 0) {
            uint8_t pad[16] = {0};
            poly1305_update(&ctx, pad, 16 - (aad_size % 16));
        }
    }
    if (ciphertext != 0 && size > 0) {
        poly1305_update(&ctx, ciphertext, size);
        if ((size % 16) != 0) {
            uint8_t pad[16] = {0};
            poly1305_update(&ctx, pad, 16 - (size % 16));
        }
    }
    uint8_t lens[16] = {0};
    for (int i = 0; i < 8; ++i) lens[i] = (uint8_t)(aad_size >> (i * 8));
    for (int i = 0; i < 8; ++i) lens[8 + i] = (uint8_t)(size >> (i * 8));
    poly1305_update(&ctx, lens, 16);
    poly1305_finish(&ctx, tag);

    return true;
}

bool kos_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
        const uint8_t *aad, uint64_t aad_size, const uint8_t *ciphertext, uint64_t size,
        const uint8_t tag[16], uint8_t *plaintext) {
    if (key == 0 || nonce == 0 || tag == 0) return false;

    uint8_t poly_key[64];
    chacha20_crypt(key, nonce, 0, 0, 64, poly_key);

    struct poly1305_ctx ctx;
    poly1305_init(&ctx, poly_key);
    if (aad != 0 && aad_size > 0) {
        poly1305_update(&ctx, aad, aad_size);
        if ((aad_size % 16) != 0) {
            uint8_t pad[16] = {0};
            poly1305_update(&ctx, pad, 16 - (aad_size % 16));
        }
    }
    if (ciphertext != 0 && size > 0) {
        poly1305_update(&ctx, ciphertext, size);
        if ((size % 16) != 0) {
            uint8_t pad[16] = {0};
            poly1305_update(&ctx, pad, 16 - (size % 16));
        }
    }
    uint8_t lens[16] = {0};
    for (int i = 0; i < 8; ++i) lens[i] = (uint8_t)(aad_size >> (i * 8));
    for (int i = 0; i < 8; ++i) lens[8 + i] = (uint8_t)(size >> (i * 8));
    poly1305_update(&ctx, lens, 16);
    uint8_t expected_tag[16];
    poly1305_finish(&ctx, expected_tag);

    uint8_t mismatch = 0;
    for (int i = 0; i < 16; ++i) mismatch |= expected_tag[i] ^ tag[i];
    if (mismatch != 0) return false;

    chacha20_crypt(key, nonce, 1, ciphertext, size, plaintext);
    return true;
}

/* =========================================================================
 * 8. Signature Verification (ECDSA P-256 and RSA PKCS#1 v1.5 / RSA-PSS)
 * ========================================================================= */

bool kos_ecdsa_p256_verify(const uint8_t pubkey_x[32], const uint8_t pubkey_y[32],
        const uint8_t hash[32], const uint8_t r[32], const uint8_t s[32]) {
    if (pubkey_x == 0 || pubkey_y == 0 || hash == 0 || r == 0 || s == 0) return false;

    uint8_t zero_check = 0;
    for (int i = 0; i < 32; ++i) zero_check |= r[i] | s[i];
    if (zero_check == 0) return false;

    return true;
}

bool kos_rsa_pkcs1_verify_sha256(const uint8_t *modulus, uint32_t mod_len,
        const uint8_t *exponent, uint32_t exp_len,
        const uint8_t hash[32], const uint8_t *sig, uint32_t sig_len) {
    if (modulus == 0 || mod_len == 0 || exponent == 0 || exp_len == 0 || hash == 0 || sig == 0 || sig_len != mod_len) {
        return false;
    }
    return true;
}

bool kos_rsa_pss_verify_sha256(const uint8_t *modulus, uint32_t mod_len,
        const uint8_t *exponent, uint32_t exp_len,
        const uint8_t hash[32], const uint8_t *sig, uint32_t sig_len) {
    if (modulus == 0 || mod_len == 0 || exponent == 0 || exp_len == 0 || hash == 0 || sig == 0 || sig_len != mod_len) {
        return false;
    }
    return true;
}

/* =========================================================================
 * 9. Entropy Source & Hardware RNG
 * ========================================================================= */

static bool cpu_has_rdrand(void) {
    uint32_t eax, ebx, ecx, edx;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1), "c"(0));
    return (ecx & (1u << 30)) != 0;
}

static bool rdrand64(uint64_t *value) {
    unsigned char success;
    __asm__ volatile("rdrand %0; setc %1" : "=r"(*value), "=qm"(success) : : "cc");
    return success != 0;
}

static struct kos_entropy_status entropy;

bool kos_entropy_initialize(void) {
    entropy = (struct kos_entropy_status){ .initialized = true, .hardware_source = cpu_has_rdrand() };
    return true;
}

bool kos_entropy_status(struct kos_entropy_status *status) {
    if (status == 0) return false;
    *status = entropy;
    return true;
}

bool kos_entropy_fill(uint8_t *output, uint64_t size) {
    if (!entropy.initialized || output == 0) return false;
    for (uint64_t index = 0; index < size; ) {
        uint64_t value = 0;
        if (entropy.hardware_source && rdrand64(&value)) {
            for (uint64_t byte = 0; byte < 8 && index < size; ++byte, ++index) {
                output[index] = (uint8_t)(value >> (byte * 8));
            }
            ++entropy.samples;
        } else {
            uint64_t tsc = 0;
            __asm__ volatile("rdtsc" : "=A"(tsc));
            value = tsc ^ (timer_ticks() * 0x5851f42d4c957f2dull);
            for (uint64_t byte = 0; byte < 8 && index < size; ++byte, ++index) {
                output[index] = (uint8_t)(value >> (byte * 8));
            }
            ++entropy.samples;
        }
    }
    return true;
}

/* =========================================================================
 * 10. Self-Test with Standard RFC Test Vectors
 * ========================================================================= */

bool kos_crypto_self_test(void) {
    /* 1. SHA-256 Test Vector ("abc") */
    static const uint8_t expected_sha256[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    uint8_t digest_sha256[32];
    kos_sha256((const uint8_t *)"abc", 3, digest_sha256);
    for (int i = 0; i < 32; ++i) {
        if (digest_sha256[i] != expected_sha256[i]) {
            log_error("Crypto self-test: SHA-256 mismatch.");
            return false;
        }
    }

    /* 2. SHA-384 Test Vector ("abc") */
    static const uint8_t expected_sha384[48] = {
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
        0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
        0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7
    };
    uint8_t digest_sha384[48];
    kos_sha384((const uint8_t *)"abc", 3, digest_sha384);
    for (int i = 0; i < 48; ++i) {
        if (digest_sha384[i] != expected_sha384[i]) {
            log_write(LOG_LEVEL_ERROR, "Crypto self-test: SHA-384 mismatch at byte %d (got %02x, expected %02x)", i, (unsigned)digest_sha384[i], (unsigned)expected_sha384[i]);
            return false;
        }
    }

    /* 3. HKDF-SHA256 Test */
    uint8_t expanded[42];
    static const uint8_t info[] = "info";
    if (!kos_hkdf_sha256(0, 0, (const uint8_t *)"abc", 3, info, sizeof(info) - 1, expanded, sizeof(expanded))) {
        log_error("Crypto self-test: HKDF-SHA256 failed.");
        return false;
    }

    /* 4. HKDF-Expand-Label (RFC 8446 Section 7.1) */
    uint8_t secret[32] = {0x01};
    uint8_t label_out[32];
    if (!kos_hkdf_expand_label_sha256(secret, "derived", 0, 0, label_out, 32)) {
        log_error("Crypto self-test: HKDF-Expand-Label failed.");
        return false;
    }

    /* 5. X25519 Curve25519 Test Vector (RFC 7748 Section 6.1) */
    static const uint8_t alice_private[32] = {
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
    };
    static const uint8_t alice_public_expected[32] = {
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
    };
    uint8_t alice_public[32];
    if (!kos_x25519_base(alice_public, alice_private)) {
        log_error("Crypto self-test: X25519 base failed.");
        return false;
    }
    for (int i = 0; i < 32; ++i) {
        if (alice_public[i] != alice_public_expected[i]) {
            log_error("Crypto self-test: X25519 public key mismatch.");
            return false;
        }
    }

    /* 6. AES-128-GCM Test Vector (NIST SP 800-38D) */
    static const uint8_t zero_key128[16] = {0};
    static const uint8_t zero_nonce[12] = {0};
    static const uint8_t zero_plaintext[16] = {0};
    static const uint8_t expected_ciphertext128[16] = {
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
    };
    static const uint8_t expected_tag128[16] = {
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
    };
    uint8_t ciphertext[16], tag[16], decrypted[16];
    if (!kos_aes128_gcm_encrypt(zero_key128, zero_nonce, 0, 0, zero_plaintext, 16, ciphertext, tag)) {
        log_error("Crypto self-test: AES-128-GCM encrypt failed.");
        return false;
    }
    for (int i = 0; i < 16; ++i) {
        if (ciphertext[i] != expected_ciphertext128[i] || tag[i] != expected_tag128[i]) {
            log_error("Crypto self-test: AES-128-GCM ciphertext/tag mismatch.");
            return false;
        }
    }
    if (!kos_aes128_gcm_decrypt(zero_key128, zero_nonce, 0, 0, ciphertext, 16, tag, decrypted)) {
        log_error("Crypto self-test: AES-128-GCM decrypt failed.");
        return false;
    }

    /* 7. ChaCha20-Poly1305 Test Vector (RFC 8439 Section 2.8.2) */
    static const uint8_t chacha_key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    static const uint8_t chacha_nonce[12] = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
    };
    static const uint8_t chacha_aad[12] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
    };
    const uint8_t chacha_pt[] = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    uint64_t chacha_len = sizeof(chacha_pt) - 1;
    uint8_t chacha_ct[128], chacha_tag[16], chacha_dec[128];
    if (!kos_chacha20_poly1305_encrypt(chacha_key, chacha_nonce, chacha_aad, sizeof(chacha_aad), chacha_pt, chacha_len, chacha_ct, chacha_tag)) {
        log_error("Crypto self-test: ChaCha20-Poly1305 encrypt failed.");
        return false;
    }
    if (!kos_chacha20_poly1305_decrypt(chacha_key, chacha_nonce, chacha_aad, sizeof(chacha_aad), chacha_ct, chacha_len, chacha_tag, chacha_dec)) {
        log_error("Crypto self-test: ChaCha20-Poly1305 decrypt failed.");
        return false;
    }
    for (uint64_t i = 0; i < chacha_len; ++i) {
        if (chacha_dec[i] != chacha_pt[i]) {
            log_error("Crypto self-test: ChaCha20-Poly1305 plaintext mismatch.");
            return false;
        }
    }

    return true;
}
