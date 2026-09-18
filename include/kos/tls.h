#ifndef KOS_TLS_H
#define KOS_TLS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <kos/crypto.h>
#include <kos/x509.h>

/* TLS 1.3 Protocol Constants (RFC 8446) */
#define TLS_VERSION_1_3                  0x0304
#define TLS_VERSION_1_2_LEGACY           0x0303

/* Cipher Suites */
#define TLS_AES_128_GCM_SHA256           0x1301
#define TLS_AES_256_GCM_SHA384           0x1302
#define TLS_CHACHA20_POLY1305_SHA256     0x1303

/* Named Groups */
#define TLS_GROUP_X25519                 0x001D
#define TLS_GROUP_SECP256R1              0x0017

/* Signature Schemes */
#define TLS_SIG_RSA_PSS_RSAE_SHA256      0x0804
#define TLS_SIG_ECDSA_SECP256R1_SHA256   0x0403
#define TLS_SIG_RSA_PKCS1_SHA256         0x0401

/* Record Types */
#define TLS_RECORD_INVALID               0
#define TLS_RECORD_CHANGE_CIPHER_SPEC    20
#define TLS_RECORD_ALERT                 21
#define TLS_RECORD_HANDSHAKE             22
#define TLS_RECORD_APPLICATION_DATA      23

/* Handshake Message Types */
#define TLS_HS_CLIENT_HELLO              1
#define TLS_HS_SERVER_HELLO              2
#define TLS_HS_ENCRYPTED_EXTENSIONS      8
#define TLS_HS_CERTIFICATE               11
#define TLS_HS_CERTIFICATE_VERIFY        15
#define TLS_HS_FINISHED                  20

enum net_tls_error {
    NET_TLS_ERROR_NONE = 0,
    NET_TLS_ERROR_UNSUPPORTED_CIPHER,
    NET_TLS_ERROR_INVALID_CERTIFICATE_CHAIN,
    NET_TLS_ERROR_HOSTNAME_MISMATCH,
    NET_TLS_ERROR_HANDSHAKE_TIMEOUT,
    NET_TLS_ERROR_UNSUPPORTED_PROTOCOL,
    NET_TLS_ERROR_NO_ENTROPY,
    NET_TLS_ERROR_NOT_IMPLEMENTED,
    NET_TLS_ERROR_RECORD_OVERFLOW,
    NET_TLS_ERROR_DECRYPT_FAILED,
    NET_TLS_ERROR_BAD_FINISHED,
    NET_TLS_ERROR_IO_FAILURE,
    NET_TLS_ERROR_PEER_CLOSED,
};

enum net_tls_state {
    NET_TLS_STATE_IDLE,
    NET_TLS_STATE_CLIENT_HELLO,
    NET_TLS_STATE_SERVER_HELLO,
    NET_TLS_STATE_ENCRYPTED_EXTENSIONS,
    NET_TLS_STATE_CERTIFICATE,
    NET_TLS_STATE_CERTIFICATE_VERIFY,
    NET_TLS_STATE_FINISHED,
    NET_TLS_STATE_ESTABLISHED,
    NET_TLS_STATE_FAILED,
    NET_TLS_STATE_CLOSED,
};

struct net_tls_session {
    enum net_tls_state state;
    enum net_tls_error error;
    bool insecure;
    char server_name[128];
    uint16_t cipher_suite;

    /* X25519 Key Share */
    uint8_t client_private_key[32];
    uint8_t client_public_key[32];
    uint8_t server_public_key[32];
    uint8_t shared_secret[32];

    /* Handshake Transcript Context */
    struct kos_sha256_context transcript_sha256;
    struct kos_sha384_context transcript_sha384;

    /* Handshake Keys & IVs */
    uint8_t client_handshake_key[32];
    uint8_t client_handshake_iv[12];
    uint8_t server_handshake_key[32];
    uint8_t server_handshake_iv[12];
    uint8_t client_handshake_traffic_secret[48];
    uint8_t server_handshake_traffic_secret[48];

    /* Application Keys & IVs */
    uint8_t client_app_key[32];
    uint8_t client_app_iv[12];
    uint8_t server_app_key[32];
    uint8_t server_app_iv[12];
    uint8_t master_secret[48];
    uint8_t client_app_traffic_secret[48];
    uint8_t server_app_traffic_secret[48];

    /* 64-bit Sequence Numbers */
    uint64_t client_record_seq;
    uint64_t server_record_seq;

    /* Peer Certificate Chain */
    struct x509_chain peer_chain;
};

void net_tls_session_initialize(struct net_tls_session *session, const char *server_name, bool insecure);
enum net_tls_error net_tls_client_handshake(struct net_tls_session *session, int tcp_socket, uint64_t timeout_ticks);
int net_tls_send(struct net_tls_session *session, int tcp_socket, const uint8_t *data, uint64_t length);
int net_tls_recv(struct net_tls_session *session, int tcp_socket, uint8_t *buffer, uint64_t capacity);
void net_tls_close(struct net_tls_session *session, int tcp_socket);

enum net_tls_error net_tls_last_error(void);
const char *net_tls_error_string(enum net_tls_error error);
const char *net_tls_state_string(enum net_tls_state state);

#endif /* KOS_TLS_H */
