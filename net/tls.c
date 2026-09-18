#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/crypto.h>
#include <kos/tls.h>
#include <kos/net.h>
#include <kos/timer.h>
#include <kos/x509.h>

static enum net_tls_error last_error;

/* =========================================================================
 * 1. String & Buffer Helpers
 * ========================================================================= */

static uint64_t str_len(const char *text) {
    uint64_t length = 0;
    if (text == 0) return 0;
    while (text[length] != '\0') ++length;
    return length;
}

static void mem_cpy(void *dest, const void *src, uint64_t size) {
    uint8_t *d = (uint8_t *)dest;
    const uint8_t *s = (const uint8_t *)src;
    for (uint64_t i = 0; i < size; ++i) d[i] = s[i];
}

/* =========================================================================
 * 2. Socket Transport Helpers
 * ========================================================================= */

static bool socket_read_exact(int sock, uint8_t *buf, uint64_t len, uint64_t timeout_ticks) {
    uint64_t total = 0;
    uint64_t start = timer_ticks();
    while (total < len) {
        if (timer_ticks() - start > timeout_ticks) {
            return false;
        }
        int r = tcp_receive(sock, &buf[total], len - total);
        if (r > 0) {
            total += (uint64_t)r;
        } else if (r < 0) {
            return false;
        } else {
            timer_delay_ms(1);
        }
    }
    return true;
}

static bool socket_write_exact(int sock, const uint8_t *buf, uint64_t len) {
    uint64_t total = 0;
    while (total < len) {
        int w = tcp_send(sock, &buf[total], len - total);
        if (w > 0) {
            total += (uint64_t)w;
        } else {
            return false;
        }
    }
    return true;
}

/* =========================================================================
 * 3. TLS 1.3 Record Layer Cryptography
 * ========================================================================= */

static void construct_nonce(const uint8_t iv[12], uint64_t seq, uint8_t nonce_out[12]) {
    for (int i = 0; i < 12; ++i) {
        nonce_out[i] = iv[i];
    }
    for (int i = 0; i < 8; ++i) {
        nonce_out[11 - i] ^= (uint8_t)(seq >> (i * 8));
    }
}

static bool encrypt_record(uint16_t cipher_suite, const uint8_t *key, const uint8_t *iv,
        uint64_t seq, uint8_t inner_type, const uint8_t *plaintext, uint64_t pt_len,
        uint8_t *out_record, uint64_t *out_record_len) {
    uint64_t payload_len = pt_len + 1; /* Plaintext + 1 byte content type */
    uint64_t ct_len = payload_len;
    uint64_t total_record_len = 5 + ct_len + 16; /* 5-byte header + ciphertext + 16-byte tag */

    /* 5-byte Outer Record Header: Type 0x17 (Application Data), Version 0x0303 (Legacy), Length */
    out_record[0] = TLS_RECORD_APPLICATION_DATA;
    out_record[1] = 0x03;
    out_record[2] = 0x03;
    uint16_t enc_len = (uint16_t)(ct_len + 16);
    out_record[3] = (uint8_t)(enc_len >> 8);
    out_record[4] = (uint8_t)(enc_len & 0xFF);

    uint8_t nonce[12];
    construct_nonce(iv, seq, nonce);

    uint8_t temp_buf[4096];
    if (payload_len > sizeof(temp_buf)) return false;
    mem_cpy(temp_buf, plaintext, pt_len);
    temp_buf[pt_len] = inner_type;

    uint8_t tag[16];
    bool ok = false;
    if (cipher_suite == TLS_AES_128_GCM_SHA256) {
        ok = kos_aes128_gcm_encrypt(key, nonce, out_record, 5, temp_buf, payload_len, &out_record[5], tag);
    } else if (cipher_suite == TLS_CHACHA20_POLY1305_SHA256) {
        ok = kos_chacha20_poly1305_encrypt(key, nonce, out_record, 5, temp_buf, payload_len, &out_record[5], tag);
    } else if (cipher_suite == TLS_AES_256_GCM_SHA384) {
        ok = kos_aes256_gcm_encrypt(key, nonce, out_record, 5, temp_buf, payload_len, &out_record[5], tag);
    }

    if (!ok) return false;
    mem_cpy(&out_record[5 + ct_len], tag, 16);
    *out_record_len = total_record_len;
    return true;
}

static bool decrypt_record(uint16_t cipher_suite, const uint8_t *key, const uint8_t *iv,
        uint64_t seq, const uint8_t *record, uint64_t record_len,
        uint8_t *out_plaintext, uint64_t *out_pt_len, uint8_t *out_inner_type) {
    if (record_len < 5 + 16 + 1) return false;

    uint16_t enc_len = ((uint16_t)record[3] << 8) | record[4];
    if (record_len != (uint64_t)(5 + enc_len)) return false;

    uint64_t ct_len = enc_len - 16;
    const uint8_t *tag = &record[5 + ct_len];

    uint8_t nonce[12];
    construct_nonce(iv, seq, nonce);

    uint8_t temp_buf[4096];
    if (ct_len > sizeof(temp_buf)) return false;

    bool ok = false;
    if (cipher_suite == TLS_AES_128_GCM_SHA256) {
        ok = kos_aes128_gcm_decrypt(key, nonce, record, 5, &record[5], ct_len, tag, temp_buf);
    } else if (cipher_suite == TLS_CHACHA20_POLY1305_SHA256) {
        ok = kos_chacha20_poly1305_decrypt(key, nonce, record, 5, &record[5], ct_len, tag, temp_buf);
    } else if (cipher_suite == TLS_AES_256_GCM_SHA384) {
        ok = kos_aes256_gcm_decrypt(key, nonce, record, 5, &record[5], ct_len, tag, temp_buf);
    }

    if (!ok) return false;

    /* Find inner content type (last non-zero byte) */
    int64_t idx = (int64_t)ct_len - 1;
    while (idx >= 0 && temp_buf[idx] == 0) {
        --idx;
    }
    if (idx < 0) return false;

    *out_inner_type = temp_buf[idx];
    *out_pt_len = (uint64_t)idx;
    mem_cpy(out_plaintext, temp_buf, *out_pt_len);
    return true;
}

/* =========================================================================
 * 4. TLS 1.3 Key Schedule Derivations
 * ========================================================================= */

static void derive_handshake_secrets(struct net_tls_session *s) {
    uint8_t early_secret[32];
    static const uint8_t zero_salt[32] = {0};
    kos_hkdf_extract_sha256(zero_salt, 32, zero_salt, 32, early_secret);

    uint8_t empty_hash[32];
    kos_sha256(0, 0, empty_hash);

    uint8_t derived[32];
    kos_hkdf_expand_label_sha256(early_secret, "derived", empty_hash, 32, derived, 32);

    uint8_t handshake_secret[32];
    kos_hkdf_extract_sha256(derived, 32, s->shared_secret, 32, handshake_secret);

    /* Get current Transcript Hash up to ServerHello */
    struct kos_sha256_context ctx_copy = s->transcript_sha256;
    uint8_t thash[32];
    kos_sha256_finalize(&ctx_copy, thash);

    kos_hkdf_expand_label_sha256(handshake_secret, "c hs traffic", thash, 32, s->client_handshake_traffic_secret, 32);
    kos_hkdf_expand_label_sha256(handshake_secret, "s hs traffic", thash, 32, s->server_handshake_traffic_secret, 32);

    /* Derive Keys and IVs */
    uint16_t key_len = (s->cipher_suite == TLS_AES_128_GCM_SHA256) ? 16 : 32;
    kos_hkdf_expand_label_sha256(s->client_handshake_traffic_secret, "key", 0, 0, s->client_handshake_key, key_len);
    kos_hkdf_expand_label_sha256(s->client_handshake_traffic_secret, "iv", 0, 0, s->client_handshake_iv, 12);
    kos_hkdf_expand_label_sha256(s->server_handshake_traffic_secret, "key", 0, 0, s->server_handshake_key, key_len);
    kos_hkdf_expand_label_sha256(s->server_handshake_traffic_secret, "iv", 0, 0, s->server_handshake_iv, 12);
}

static void derive_application_secrets(struct net_tls_session *s) {
    uint8_t empty_hash[32];
    kos_sha256(0, 0, empty_hash);

    uint8_t early_secret[32];
    static const uint8_t zero_salt[32] = {0};
    kos_hkdf_extract_sha256(zero_salt, 32, zero_salt, 32, early_secret);

    uint8_t derived[32];
    kos_hkdf_expand_label_sha256(early_secret, "derived", empty_hash, 32, derived, 32);

    uint8_t handshake_secret[32];
    kos_hkdf_extract_sha256(derived, 32, s->shared_secret, 32, handshake_secret);

    uint8_t derived2[32];
    kos_hkdf_expand_label_sha256(handshake_secret, "derived", empty_hash, 32, derived2, 32);

    kos_hkdf_extract_sha256(derived2, 32, zero_salt, 32, s->master_secret);

    /* Get Transcript Hash up to Server Finished */
    struct kos_sha256_context ctx_copy = s->transcript_sha256;
    uint8_t thash[32];
    kos_sha256_finalize(&ctx_copy, thash);

    kos_hkdf_expand_label_sha256(s->master_secret, "c ap traffic", thash, 32, s->client_app_traffic_secret, 32);
    kos_hkdf_expand_label_sha256(s->master_secret, "s ap traffic", thash, 32, s->server_app_traffic_secret, 32);

    uint16_t key_len = (s->cipher_suite == TLS_AES_128_GCM_SHA256) ? 16 : 32;
    kos_hkdf_expand_label_sha256(s->client_app_traffic_secret, "key", 0, 0, s->client_app_key, key_len);
    kos_hkdf_expand_label_sha256(s->client_app_traffic_secret, "iv", 0, 0, s->client_app_iv, 12);
    kos_hkdf_expand_label_sha256(s->server_app_traffic_secret, "key", 0, 0, s->server_app_key, key_len);
    kos_hkdf_expand_label_sha256(s->server_app_traffic_secret, "iv", 0, 0, s->server_app_iv, 12);
}

/* =========================================================================
 * 5. Handshake Message Construction & Parsing
 * ========================================================================= */

static uint32_t build_client_hello(struct net_tls_session *s, uint8_t *buf, uint32_t max_len) {
    if (max_len < 512) return 0;

    uint8_t *p = buf;

    /* 1. Generate Client Random */
    uint8_t client_random[32];
    kos_entropy_fill(client_random, 32);

    /* 2. Generate Client X25519 Key Pair */
    kos_entropy_fill(s->client_private_key, 32);
    kos_x25519_base(s->client_public_key, s->client_private_key);

    /* Handshake Header placeholder: Type (1), Length (3) */
    p[0] = TLS_HS_CLIENT_HELLO;
    p += 4;

    /* Legacy Client Version: 0x0303 */
    *p++ = 0x03; *p++ = 0x03;

    /* Random (32 bytes) */
    mem_cpy(p, client_random, 32); p += 32;

    /* Legacy Session ID (32 bytes) */
    *p++ = 32;
    kos_entropy_fill(p, 32); p += 32;

    /* Cipher Suites (TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384) */
    *p++ = 0x00; *p++ = 0x06;
    *p++ = 0x13; *p++ = 0x01;
    *p++ = 0x13; *p++ = 0x03;
    *p++ = 0x13; *p++ = 0x02;

    /* Legacy Compression Methods: null only */
    *p++ = 0x01; *p++ = 0x00;

    /* Extensions Length placeholder */
    uint8_t *ext_len_ptr = p;
    p += 2;

    /* Extension: server_name (SNI) */
    uint64_t sni_len = str_len(s->server_name);
    if (sni_len > 0) {
        *p++ = 0x00; *p++ = 0x00; /* type = 0 */
        uint16_t sni_ext_size = (uint16_t)(sni_len + 5);
        *p++ = (uint8_t)(sni_ext_size >> 8); *p++ = (uint8_t)(sni_ext_size & 0xFF);
        uint16_t list_len = (uint16_t)(sni_len + 3);
        *p++ = (uint8_t)(list_len >> 8); *p++ = (uint8_t)(list_len & 0xFF);
        *p++ = 0x00; /* host_name type */
        *p++ = (uint8_t)(sni_len >> 8); *p++ = (uint8_t)(sni_len & 0xFF);
        for (uint64_t i = 0; i < sni_len; ++i) *p++ = (uint8_t)s->server_name[i];
    }

    /* Extension: supported_versions (TLS 1.3 = 0x0304) */
    *p++ = 0x00; *p++ = 0x2B; /* type = 43 */
    *p++ = 0x00; *p++ = 0x03; /* length = 3 */
    *p++ = 0x02;              /* versions length = 2 */
    *p++ = 0x03; *p++ = 0x04; /* TLS 1.3 */

    /* Extension: supported_groups (x25519 = 0x001d, secp256r1 = 0x0017) */
    *p++ = 0x00; *p++ = 0x0A; /* type = 10 */
    *p++ = 0x00; *p++ = 0x06; /* length = 6 */
    *p++ = 0x00; *p++ = 0x04; /* groups list length = 4 */
    *p++ = 0x00; *p++ = 0x1D; /* X25519 */
    *p++ = 0x00; *p++ = 0x17; /* secp256r1 */

    /* Extension: signature_algorithms */
    *p++ = 0x00; *p++ = 0x0D; /* type = 13 */
    *p++ = 0x00; *p++ = 0x08; /* length = 8 */
    *p++ = 0x00; *p++ = 0x06; /* list length = 6 */
    *p++ = 0x08; *p++ = 0x04; /* rsa_pss_rsae_sha256 */
    *p++ = 0x04; *p++ = 0x03; /* ecdsa_secp256r1_sha256 */
    *p++ = 0x04; *p++ = 0x01; /* rsa_pkcs1_sha256 */

    /* Extension: key_share (X25519 public key) */
    *p++ = 0x00; *p++ = 0x33; /* type = 51 */
    *p++ = 0x00; *p++ = 0x26; /* length = 38 (2 + 2 + 2 + 32) */
    *p++ = 0x00; *p++ = 0x24; /* client_shares length = 36 */
    *p++ = 0x00; *p++ = 0x1D; /* group = X25519 */
    *p++ = 0x00; *p++ = 0x20; /* key_exchange length = 32 */
    mem_cpy(p, s->client_public_key, 32); p += 32;

    /* Fill Extensions Length */
    uint16_t total_ext_len = (uint16_t)(p - (ext_len_ptr + 2));
    ext_len_ptr[0] = (uint8_t)(total_ext_len >> 8);
    ext_len_ptr[1] = (uint8_t)(total_ext_len & 0xFF);

    /* Fill Handshake Length */
    uint32_t hs_len = (uint32_t)(p - buf - 4);
    buf[1] = (uint8_t)(hs_len >> 16);
    buf[2] = (uint8_t)(hs_len >> 8);
    buf[3] = (uint8_t)(hs_len & 0xFF);

    return (uint32_t)(p - buf);
}

/* =========================================================================
 * 6. TLS 1.3 Client Handshake Execution
 * ========================================================================= */

void net_tls_session_initialize(struct net_tls_session *session, const char *server_name, bool insecure) {
    if (session == 0) return;
    *session = (struct net_tls_session){ .state = NET_TLS_STATE_IDLE, .insecure = insecure };
    if (server_name != 0) {
        uint64_t len = str_len(server_name);
        if (len >= sizeof(session->server_name)) len = sizeof(session->server_name) - 1;
        for (uint64_t i = 0; i < len; ++i) session->server_name[i] = server_name[i];
        session->server_name[len] = '\0';
    }
    kos_sha256_initialize(&session->transcript_sha256);
    last_error = NET_TLS_ERROR_NONE;
}

enum net_tls_error net_tls_client_handshake(struct net_tls_session *s, int sock, uint64_t timeout_ticks) {
    if (s == 0) { last_error = NET_TLS_ERROR_UNSUPPORTED_PROTOCOL; return last_error; }

    s->state = NET_TLS_STATE_CLIENT_HELLO;
    s->error = NET_TLS_ERROR_NONE;

    if (!kos_crypto_self_test()) {
        s->state = NET_TLS_STATE_FAILED; s->error = NET_TLS_ERROR_UNSUPPORTED_CIPHER;
        last_error = s->error; return last_error;
    }

    /* 1. Build and Send ClientHello */
    uint8_t hs_buf[1024];
    uint32_t hs_len = build_client_hello(s, hs_buf, sizeof(hs_buf));
    if (hs_len == 0) {
        s->state = NET_TLS_STATE_FAILED; s->error = NET_TLS_ERROR_NO_ENTROPY;
        last_error = s->error; return last_error;
    }

    /* Wrap in TLS Plaintext Record: Type 22 (Handshake), Version 0x0301, Length */
    uint8_t rec_buf[1024 + 5];
    rec_buf[0] = TLS_RECORD_HANDSHAKE;
    rec_buf[1] = 0x03; rec_buf[2] = 0x01;
    rec_buf[3] = (uint8_t)(hs_len >> 8);
    rec_buf[4] = (uint8_t)(hs_len & 0xFF);
    mem_cpy(&rec_buf[5], hs_buf, hs_len);

    /* Update transcript hash with ClientHello handshake bytes */
    kos_sha256_update(&s->transcript_sha256, hs_buf, hs_len);

    if (!socket_write_exact(sock, rec_buf, 5 + hs_len)) {
        s->state = NET_TLS_STATE_FAILED; s->error = NET_TLS_ERROR_IO_FAILURE;
        last_error = s->error; return last_error;
    }

    /* 2. Receive ServerHello */
    s->state = NET_TLS_STATE_SERVER_HELLO;
    uint8_t s_rec_hdr[5];
    if (!socket_read_exact(sock, s_rec_hdr, 5, timeout_ticks)) {
        s->state = NET_TLS_STATE_FAILED; s->error = NET_TLS_ERROR_HANDSHAKE_TIMEOUT;
        last_error = s->error; return last_error;
    }

    uint16_t s_rec_len = ((uint16_t)s_rec_hdr[3] << 8) | s_rec_hdr[4];
    if (s_rec_len > sizeof(hs_buf)) {
        s->state = NET_TLS_STATE_FAILED; s->error = NET_TLS_ERROR_RECORD_OVERFLOW;
        last_error = s->error; return last_error;
    }

    if (!socket_read_exact(sock, hs_buf, s_rec_len, timeout_ticks)) {
        s->state = NET_TLS_STATE_FAILED; s->error = NET_TLS_ERROR_IO_FAILURE;
        last_error = s->error; return last_error;
    }

    /* Parse ServerHello */
    if (hs_buf[0] != TLS_HS_SERVER_HELLO) {
        s->state = NET_TLS_STATE_FAILED; s->error = NET_TLS_ERROR_UNSUPPORTED_PROTOCOL;
        last_error = s->error; return last_error;
    }

    uint32_t s_hs_len = ((uint32_t)hs_buf[1] << 16) | ((uint32_t)hs_buf[2] << 8) | hs_buf[3];
    kos_sha256_update(&s->transcript_sha256, hs_buf, s_hs_len + 4);

    /* Parse cipher suite and key share from ServerHello */
    uint32_t off = 4 + 2 + 32; /* skip header, version, random */
    uint8_t sess_id_len = hs_buf[off++];
    off += sess_id_len;
    s->cipher_suite = ((uint16_t)hs_buf[off] << 8) | hs_buf[off + 1];
    off += 2 + 1; /* skip cipher suite and legacy compression */

    uint16_t ext_len = ((uint16_t)hs_buf[off] << 8) | hs_buf[off + 1];
    off += 2;
    uint32_t ext_end = off + ext_len;

    bool found_key_share = false;
    while (off + 4 <= ext_end) {
        uint16_t e_type = ((uint16_t)hs_buf[off] << 8) | hs_buf[off + 1];
        uint16_t e_len = ((uint16_t)hs_buf[off + 2] << 8) | hs_buf[off + 3];
        off += 4;
        if (e_type == 0x0033 && e_len >= 36) { /* key_share */
            uint16_t group = ((uint16_t)hs_buf[off] << 8) | hs_buf[off + 1];
            if (group == TLS_GROUP_X25519) {
                mem_cpy(s->server_public_key, &hs_buf[off + 4], 32);
                found_key_share = true;
            }
        }
        off += e_len;
    }

    if (!found_key_share) {
        s->state = NET_TLS_STATE_FAILED; s->error = NET_TLS_ERROR_UNSUPPORTED_CIPHER;
        last_error = s->error; return last_error;
    }

    /* Compute ECDH shared secret */
    kos_x25519(s->shared_secret, s->client_private_key, s->server_public_key);

    /* Derive Handshake traffic secrets */
    derive_handshake_secrets(s);

    /* 3. Receive Encrypted Handshake Records */
    s->server_record_seq = 0;
    s->client_record_seq = 0;

    bool handshake_done = false;
    while (!handshake_done) {
        uint8_t rec_hdr[5];
        if (!socket_read_exact(sock, rec_hdr, 5, timeout_ticks)) {
            s->state = NET_TLS_STATE_FAILED; s->error = NET_TLS_ERROR_HANDSHAKE_TIMEOUT;
            last_error = s->error; return last_error;
        }

        /* If ChangeCipherSpec (type 20), skip it */
        if (rec_hdr[0] == TLS_RECORD_CHANGE_CIPHER_SPEC) {
            uint16_t ccs_len = ((uint16_t)rec_hdr[3] << 8) | rec_hdr[4];
            uint8_t ccs_buf[16];
            socket_read_exact(sock, ccs_buf, ccs_len, timeout_ticks);
            continue;
        }

        uint16_t rec_len = ((uint16_t)rec_hdr[3] << 8) | rec_hdr[4];
        uint8_t encrypted_rec[4096];
        mem_cpy(encrypted_rec, rec_hdr, 5);
        if (!socket_read_exact(sock, &encrypted_rec[5], rec_len, timeout_ticks)) {
            s->state = NET_TLS_STATE_FAILED; s->error = NET_TLS_ERROR_IO_FAILURE;
            last_error = s->error; return last_error;
        }

        uint8_t decrypted_buf[4096];
        uint64_t pt_len = 0;
        uint8_t inner_type = 0;
        if (!decrypt_record(s->cipher_suite, s->server_handshake_key, s->server_handshake_iv,
                s->server_record_seq++, encrypted_rec, 5 + rec_len,
                decrypted_buf, &pt_len, &inner_type)) {
            s->state = NET_TLS_STATE_FAILED; s->error = NET_TLS_ERROR_DECRYPT_FAILED;
            last_error = s->error; return last_error;
        }

        /* Parse Handshake messages inside decrypted payload */
        uint32_t hs_offset = 0;
        while (hs_offset < pt_len) {
            uint8_t m_type = decrypted_buf[hs_offset];
            uint32_t m_len = ((uint32_t)decrypted_buf[hs_offset + 1] << 16) |
                             ((uint32_t)decrypted_buf[hs_offset + 2] << 8) |
                             decrypted_buf[hs_offset + 3];

            if (m_type == TLS_HS_ENCRYPTED_EXTENSIONS) {
                s->state = NET_TLS_STATE_ENCRYPTED_EXTENSIONS;
                kos_sha256_update(&s->transcript_sha256, &decrypted_buf[hs_offset], 4 + m_len);
            } else if (m_type == TLS_HS_CERTIFICATE) {
                s->state = NET_TLS_STATE_CERTIFICATE;
                kos_sha256_update(&s->transcript_sha256, &decrypted_buf[hs_offset], 4 + m_len);

                /* Parse Certificate List */
                uint32_t c_off = hs_offset + 4;
                uint8_t req_ctx_len = decrypted_buf[c_off++];
                c_off += req_ctx_len;
                uint32_t cert_list_len = ((uint32_t)decrypted_buf[c_off] << 16) |
                                         ((uint32_t)decrypted_buf[c_off + 1] << 8) |
                                         decrypted_buf[c_off + 2];
                c_off += 3;
                uint32_t cert_list_end = c_off + cert_list_len;

                s->peer_chain.count = 0;
                while (c_off + 3 < cert_list_end && s->peer_chain.count < X509_MAX_CHAIN_DEPTH) {
                    uint32_t single_cert_len = ((uint32_t)decrypted_buf[c_off] << 16) |
                                               ((uint32_t)decrypted_buf[c_off + 1] << 8) |
                                               decrypted_buf[c_off + 2];
                    c_off += 3;
                    x509_parse_certificate(&decrypted_buf[c_off], single_cert_len,
                                           &s->peer_chain.certs[s->peer_chain.count++]);
                    c_off += single_cert_len;
                    uint16_t c_ext_len = ((uint16_t)decrypted_buf[c_off] << 8) | decrypted_buf[c_off + 1];
                    c_off += 2 + c_ext_len;
                }
            } else if (m_type == TLS_HS_CERTIFICATE_VERIFY) {
                s->state = NET_TLS_STATE_CERTIFICATE_VERIFY;
                kos_sha256_update(&s->transcript_sha256, &decrypted_buf[hs_offset], 4 + m_len);
            } else if (m_type == TLS_HS_FINISHED) {
                s->state = NET_TLS_STATE_FINISHED;
                /* Verify Server Finished HMAC */
                uint8_t server_finished_key[32];
                kos_hkdf_expand_label_sha256(s->server_handshake_traffic_secret, "finished", 0, 0, server_finished_key, 32);

                struct kos_sha256_context ctx_c = s->transcript_sha256;
                uint8_t thash[32];
                kos_sha256_finalize(&ctx_c, thash);

                uint8_t expected_mac[32];
                kos_hmac_sha256(server_finished_key, 32, thash, 32, expected_mac);

                for (int i = 0; i < 32; ++i) {
                    if (decrypted_buf[hs_offset + 4 + i] != expected_mac[i]) {
                        s->state = NET_TLS_STATE_FAILED; s->error = NET_TLS_ERROR_BAD_FINISHED;
                        last_error = s->error; return last_error;
                    }
                }

                kos_sha256_update(&s->transcript_sha256, &decrypted_buf[hs_offset], 4 + m_len);
                handshake_done = true;
            }
            hs_offset += 4 + m_len;
        }
    }

    /* 4. Validate Certificate Chain if secure */
    if (!s->insecure && s->peer_chain.count > 0) {
        enum x509_verify_result vres = x509_verify_chain(&s->peer_chain, s->server_name, x509_get_current_time_epoch());
        if (vres != X509_V_OK) {
            s->state = NET_TLS_STATE_FAILED;
            s->error = (vres == X509_V_ERR_HOSTNAME_MISMATCH) ? NET_TLS_ERROR_HOSTNAME_MISMATCH : NET_TLS_ERROR_INVALID_CERTIFICATE_CHAIN;
            last_error = s->error;
            return last_error;
        }
    }

    /* 5. Derive Application Secrets */
    derive_application_secrets(s);

    /* 6. Send Client Finished */
    uint8_t client_finished_key[32];
    kos_hkdf_expand_label_sha256(s->client_handshake_traffic_secret, "finished", 0, 0, client_finished_key, 32);

    struct kos_sha256_context ctx_fin = s->transcript_sha256;
    uint8_t fin_thash[32];
    kos_sha256_finalize(&ctx_fin, fin_thash);

    uint8_t client_finished_msg[36];
    client_finished_msg[0] = TLS_HS_FINISHED;
    client_finished_msg[1] = 0x00; client_finished_msg[2] = 0x00; client_finished_msg[3] = 32;
    kos_hmac_sha256(client_finished_key, 32, fin_thash, 32, &client_finished_msg[4]);

    uint8_t fin_record[128];
    uint64_t fin_rec_len = 0;
    if (!encrypt_record(s->cipher_suite, s->client_handshake_key, s->client_handshake_iv,
            s->client_record_seq++, TLS_RECORD_HANDSHAKE, client_finished_msg, 36,
            fin_record, &fin_rec_len)) {
        s->state = NET_TLS_STATE_FAILED; s->error = NET_TLS_ERROR_DECRYPT_FAILED;
        last_error = s->error; return last_error;
    }

    if (!socket_write_exact(sock, fin_record, fin_rec_len)) {
        s->state = NET_TLS_STATE_FAILED; s->error = NET_TLS_ERROR_IO_FAILURE;
        last_error = s->error; return last_error;
    }

    /* Reset sequence numbers for Application Data keys */
    s->client_record_seq = 0;
    s->server_record_seq = 0;

    s->state = NET_TLS_STATE_ESTABLISHED;
    s->error = NET_TLS_ERROR_NONE;
    last_error = NET_TLS_ERROR_NONE;
    return NET_TLS_ERROR_NONE;
}

/* =========================================================================
 * 7. Application Data Transmission & Reception
 * ========================================================================= */

int net_tls_send(struct net_tls_session *s, int sock, const uint8_t *data, uint64_t length) {
    if (s == 0 || s->state != NET_TLS_STATE_ESTABLISHED || data == 0) {
        return -1;
    }

    uint8_t rec_buf[4096];
    uint64_t total_sent = 0;

    while (total_sent < length) {
        uint64_t chunk = length - total_sent;
        if (chunk > 1400) chunk = 1400;

        uint64_t rec_len = 0;
        if (!encrypt_record(s->cipher_suite, s->client_app_key, s->client_app_iv,
                s->client_record_seq++, TLS_RECORD_APPLICATION_DATA, &data[total_sent], chunk,
                rec_buf, &rec_len)) {
            return -1;
        }

        if (!socket_write_exact(sock, rec_buf, rec_len)) {
            return -1;
        }
        total_sent += chunk;
    }

    return (int)total_sent;
}

int net_tls_recv(struct net_tls_session *s, int sock, uint8_t *buffer, uint64_t capacity) {
    if (s == 0 || s->state != NET_TLS_STATE_ESTABLISHED || buffer == 0 || capacity == 0) {
        return -1;
    }

    uint8_t rec_hdr[5];
    if (!socket_read_exact(sock, rec_hdr, 5, timer_frequency_hz() * 5)) {
        return 0;
    }

    uint16_t rec_len = ((uint16_t)rec_hdr[3] << 8) | rec_hdr[4];
    uint8_t enc_rec[4096];
    mem_cpy(enc_rec, rec_hdr, 5);
    if (!socket_read_exact(sock, &enc_rec[5], rec_len, timer_frequency_hz() * 5)) {
        return -1;
    }

    uint8_t dec_buf[4096];
    uint64_t pt_len = 0;
    uint8_t inner_type = 0;
    if (!decrypt_record(s->cipher_suite, s->server_app_key, s->server_app_iv,
            s->server_record_seq++, enc_rec, 5 + rec_len,
            dec_buf, &pt_len, &inner_type)) {
        return -1;
    }

    if (inner_type == TLS_RECORD_ALERT) {
        s->state = NET_TLS_STATE_CLOSED;
        return 0;
    }

    uint64_t copy_bytes = pt_len < capacity ? pt_len : capacity;
    mem_cpy(buffer, dec_buf, copy_bytes);
    return (int)copy_bytes;
}

void net_tls_close(struct net_tls_session *s, int sock) {
    if (s == 0 || s->state != NET_TLS_STATE_ESTABLISHED) return;

    /* Send encrypted close_notify alert: Level 1 (warning), Description 0 (close_notify) */
    uint8_t alert_msg[2] = { 0x01, 0x00 };
    uint8_t rec_buf[128];
    uint64_t rec_len = 0;
    if (encrypt_record(s->cipher_suite, s->client_app_key, s->client_app_iv,
            s->client_record_seq++, TLS_RECORD_ALERT, alert_msg, 2, rec_buf, &rec_len)) {
        socket_write_exact(sock, rec_buf, rec_len);
    }
    s->state = NET_TLS_STATE_CLOSED;
}

enum net_tls_error net_tls_last_error(void) { return last_error; }

const char *net_tls_error_string(enum net_tls_error error) {
    switch (error) {
        case NET_TLS_ERROR_NONE: return "none";
        case NET_TLS_ERROR_UNSUPPORTED_CIPHER: return "unsupported cipher suite";
        case NET_TLS_ERROR_INVALID_CERTIFICATE_CHAIN: return "invalid certificate chain";
        case NET_TLS_ERROR_HOSTNAME_MISMATCH: return "hostname mismatch";
        case NET_TLS_ERROR_HANDSHAKE_TIMEOUT: return "handshake timed out";
        case NET_TLS_ERROR_UNSUPPORTED_PROTOCOL: return "server requires unsupported protocol";
        case NET_TLS_ERROR_NO_ENTROPY: return "secure entropy unavailable";
        case NET_TLS_ERROR_NOT_IMPLEMENTED: return "TLS 1.3 handshake not implemented";
        case NET_TLS_ERROR_RECORD_OVERFLOW: return "record payload exceeds capacity";
        case NET_TLS_ERROR_DECRYPT_FAILED: return "record decryption / AEAD tag verification failed";
        case NET_TLS_ERROR_BAD_FINISHED: return "server finished HMAC verification failed";
        case NET_TLS_ERROR_IO_FAILURE: return "network I/O failure during TLS handshake";
        case NET_TLS_ERROR_PEER_CLOSED: return "connection closed by remote peer";
        default: return "unknown TLS error";
    }
}

const char *net_tls_state_string(enum net_tls_state state) {
    switch (state) {
        case NET_TLS_STATE_IDLE: return "IDLE";
        case NET_TLS_STATE_CLIENT_HELLO: return "CLIENT_HELLO";
        case NET_TLS_STATE_SERVER_HELLO: return "SERVER_HELLO";
        case NET_TLS_STATE_ENCRYPTED_EXTENSIONS: return "ENCRYPTED_EXTENSIONS";
        case NET_TLS_STATE_CERTIFICATE: return "CERTIFICATE";
        case NET_TLS_STATE_CERTIFICATE_VERIFY: return "CERTIFICATE_VERIFY";
        case NET_TLS_STATE_FINISHED: return "FINISHED";
        case NET_TLS_STATE_ESTABLISHED: return "ESTABLISHED";
        case NET_TLS_STATE_FAILED: return "FAILED";
        case NET_TLS_STATE_CLOSED: return "CLOSED";
        default: return "UNKNOWN";
    }
}
