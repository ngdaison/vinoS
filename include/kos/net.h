#ifndef KOS_NET_H
#define KOS_NET_H

#include <stdbool.h>
#include <stdint.h>

enum {
    NET_SOCKET_MAX = 8,
    NET_UDP_PAYLOAD_MAX = 1472,
    NET_IPV4_LOOPBACK = 0x7f000001u,
    NET_ETHERNET_ADDRESS_SIZE = 6,
    NET_ETHERNET_FRAME_MAX = 1514,
    NET_ARP_CACHE_MAX = 16,
    /* Allow QEMU's user-mode network backend time to come up after boot. */
    NET_ARP_DEFAULT_TIMEOUT_TICKS = 300,
    NET_QEMU_STATIC_ADDRESS = 0x0a00020fu,
    NET_QEMU_GATEWAY_ADDRESS = 0x0a000202u,
    NET_QEMU_DNS_ADDRESS = 0x0a000203u,
    NET_TCP_SOCKET_MAX = 8,
    NET_TCP_DEFAULT_MSS = 1460,
    NET_TCP_DEFAULT_WINDOW = 8192,
    NET_TCP_RTO_TICKS = 200,
    NET_DNS_PORT = 53,
    NET_DNS_CACHE_MAX = 8,
    NET_HTTP_PORT = 80,
    NET_HTTP_BUFFER_MAX = 8192,
};

enum tcp_state {
    TCP_STATE_CLOSED,
    TCP_STATE_LISTEN,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECEIVED,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_LAST_ACK,
    TCP_STATE_TIME_WAIT,
};

enum net_configuration_source {
    NET_CONFIGURATION_STATIC,
    NET_CONFIGURATION_DHCP,
};

enum net_dhcp_state {
    NET_DHCP_IDLE,
    NET_DHCP_DISCOVERING,
    NET_DHCP_REQUESTING,
    NET_DHCP_BOUND,
    NET_DHCP_FAILED,
};

struct net_ipv4_endpoint {
    uint32_t address;
    uint16_t port;
};

struct net_interface_info {
    bool available;
    uint8_t mac_address[NET_ETHERNET_ADDRESS_SIZE];
    uint32_t ipv4_address;
    uint32_t subnet_mask;
    uint32_t gateway;
    uint32_t dns_server;
    enum net_configuration_source configuration_source;
    enum net_dhcp_state dhcp_state;
    uint64_t dhcp_lease_seconds;
    uint64_t ipv4_packets_received;
    uint64_t ipv4_packets_dropped;
};

struct net_arp_cache_entry {
    bool valid;
    uint32_t ipv4_address;
    uint8_t mac_address[NET_ETHERNET_ADDRESS_SIZE];
    uint64_t learned_at_tick;
    uint64_t expires_at_tick;
};

void net_arp_cache_prune(void);
void net_arp_receive(const uint8_t source[NET_ETHERNET_ADDRESS_SIZE], const uint8_t *payload, uint64_t size);
void net_ipv4_receive(const uint8_t source[NET_ETHERNET_ADDRESS_SIZE], const uint8_t *packet, uint64_t size);
bool net_icmp_send_dest_unreachable(uint32_t destination, uint8_t code,
    const uint8_t *original_ipv4_and_payload, uint64_t original_len);
bool net_icmp_send_time_exceeded(uint32_t destination, uint8_t code,
    const uint8_t *original_ipv4_and_payload, uint64_t original_len);
void net_icmp_receive(uint32_t source, const uint8_t *packet, uint64_t size);

bool net_initialize(void);
bool net_is_initialized(void);
bool net_e1000_detected(void);
bool net_has_external_interface(void);
bool net_interface_info(struct net_interface_info *info);
bool net_ipv4_initialize_interface(const uint8_t mac_address[NET_ETHERNET_ADDRESS_SIZE]);
bool net_ipv4_configure_dhcp(uint32_t address, uint32_t subnet_mask, uint32_t gateway,
    uint32_t dns_server, uint64_t lease_seconds);
void net_ipv4_set_dhcp_state(enum net_dhcp_state state);
bool net_ipv4_send_from(uint8_t protocol, uint32_t source, uint32_t destination,
    const uint8_t *payload, uint64_t payload_size);
void net_poll(void);
bool net_ethernet_send(const uint8_t destination[NET_ETHERNET_ADDRESS_SIZE], uint16_t ether_type,
    const uint8_t *payload, uint64_t payload_size);
bool net_ethernet_wait_for_transmit(uint64_t timeout_ticks);
uint64_t net_ethernet_frames_sent(void);
uint64_t net_ethernet_frames_received(void);
uint64_t net_ethernet_frames_dropped(void);
bool net_arp_resolve(uint32_t ipv4_address, uint8_t mac_address[NET_ETHERNET_ADDRESS_SIZE],
    uint64_t timeout_ticks);
uint64_t net_arp_cache_count(void);
bool net_arp_cache_at(uint64_t index, struct net_arp_cache_entry *entry);
uint64_t net_arp_requests_sent(void);
uint64_t net_arp_replies_received(void);
bool net_ipv4_send(uint8_t protocol, uint32_t destination, const uint8_t *payload,
    uint64_t payload_size);
bool net_icmp_ping(uint32_t destination, uint16_t sequence, uint64_t timeout_ticks,
    uint64_t *round_trip_ticks);
uint64_t net_icmp_echo_requests_sent(void);
uint64_t net_icmp_echo_replies_received(void);
bool net_icmp_self_test(void);
void net_format_ipv4(uint32_t address, char text[16]);
void net_format_mac(const uint8_t address[NET_ETHERNET_ADDRESS_SIZE], char text[18]);
uint64_t net_udp_datagrams_sent(void);
uint64_t net_udp_datagrams_received(void);
bool net_udp_open(uint16_t *socket_id);
bool net_udp_close(uint16_t socket_id);
bool net_udp_bind(uint16_t socket_id, struct net_ipv4_endpoint endpoint);
bool net_udp_sendto(uint16_t socket_id, struct net_ipv4_endpoint destination,
        const uint8_t *data, uint64_t size);
bool net_udp_recvfrom(uint16_t socket_id, struct net_ipv4_endpoint *source,
        uint8_t *data, uint64_t capacity, uint64_t *size);
bool net_udp_recvfrom_timeout(uint16_t socket_id, struct net_ipv4_endpoint *source,
        uint8_t *data, uint64_t capacity, uint64_t *size, uint64_t timeout_ms);
bool net_udp_loopback_self_test(void);
uint64_t net_udp_datagrams_dropped(void);
void net_udp_receive(uint32_t source, uint32_t destination, const uint8_t *packet, uint64_t size);
bool net_dhcp_acquire(uint64_t timeout_ticks);
bool net_dhcp_renew(uint64_t timeout_ticks);
enum net_dhcp_state net_dhcp_current_state(void);
uint64_t net_dhcp_discovers_sent(void);
uint64_t net_dhcp_offers_received(void);
uint64_t net_dhcp_requests_sent(void);
uint64_t net_dhcp_acks_received(void);

int tcp_connect(uint32_t address, uint16_t port);
int tcp_send(int socket, const uint8_t *data, uint64_t size);
int tcp_receive(int socket, uint8_t *data, uint64_t capacity);
void tcp_close(int socket);
int tcp_listen(uint16_t port, uint16_t backlog);
int tcp_accept(int listen_socket, struct net_ipv4_endpoint *remote_endpoint);

struct net_tcp_socket_info {
    bool in_use;
    enum tcp_state state;
    uint32_t local_ip;
    uint16_t local_port;
    uint32_t remote_ip;
    uint16_t remote_port;
    uint64_t rx_buffered_bytes;
    uint64_t tx_buffered_bytes;
};
uint64_t net_tcp_get_sockets(struct net_tcp_socket_info *out_sockets, uint64_t max_count);

void net_tcp_receive(uint32_t source, uint32_t destination, const uint8_t *packet, uint64_t size);
void net_tcp_poll(void);
uint64_t net_tcp_segments_sent(void);
uint64_t net_tcp_segments_received(void);
uint64_t net_tcp_retransmissions(void);

bool net_dns_resolve(const char *hostname, uint32_t *out_address, uint64_t timeout_ticks);
uint64_t net_dns_queries_sent(void);
uint64_t net_dns_responses_received(void);

bool net_http_get(const char *url, char *response_buffer, uint64_t capacity, uint64_t *out_size);

bool httpd_start(uint16_t port);
void httpd_stop(void);
void httpd_poll(void);
bool httpd_is_running(void);
uint64_t httpd_requests_served(void);
uint16_t httpd_listen_port(void);

#endif
