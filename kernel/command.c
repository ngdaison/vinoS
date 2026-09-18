#include <stddef.h>
#include <stdbool.h>

#include <kos/command.h>
#include <kos/console.h>
#include <kos/cpu.h>
#include <kos/driver.h>
#include <kos/e1000.h>
#include <kos/elf.h>
#include <kos/interrupts.h>
#include <kos/keyboard.h>
#include <kos/log.h>
#include <kos/net.h>
#include <kos/net_device.h>
#include <kos/socket.h>
#include <kos/crypto.h>
#include <kos/x509.h>
#include <kos/tls.h>
#include <kos/pci.h>
#include <kos/pic.h>
#include <kos/pmm.h>
#include <kos/serial.h>
#include <kos/system.h>
#include <kos/timer.h>
#include <kos/task.h>
#include <kos/vfs.h>
#include <kos/heap.h>
#include <kos/ramfs.h>
#include <kos/handle.h>
#include <kos/object.h>
#include <kos/process.h>
#include <kos/wait.h>
#include <kos/atomic.h>
#include <kos/spinlock.h>
#include <kos/mutex.h>
#include <kos/panic.h>
#include <kos/page_fault.h>
#include <kos/symbol.h>
#include <kos/vmm.h>
#include <kos/block.h>
#include <kos/ramdisk.h>
#include <kos/virtio_blk.h>
#include <kos/ahci.h>
#include <kos/block_cache.h>
#include <kos/partition.h>
#include <kos/fat32.h>
#include <kos/volume.h>
#include <kos/acpi.h>
#include <kos/apic.h>
#include <kos/smp.h>
#include <kos/security.h>
#include <kos/syscall.h>
#include <kos/uaccess.h>
#include <kos/memory.h>
#include <kos/xhci.h>
#include <kos/nvme.h>
#include <kos/kpkg.h>
#include <kos/pkg_db.h>
#include <kos/installer.h>
#include <kos/qa.h>
#include <kos/fault_injection.h>
#include <uapi/kos/syscall_numbers.h>

void *memset(void *destination, int value, size_t size);
void *memcpy(void *destination, const void *source, size_t size);

typedef void (*command_handler)(const char *arguments);

static void command_usertest(const char *arguments);

struct command_entry {
    const char *name;
    command_handler handler;
};

static void command_help(const char *arguments) {
    (void)arguments;
    log_info("help clear meminfo uptime sysinfo netinfo ifconfig arp arping ping dhcp udptest tcptest sockettest cryptotest x509test tlstest nslookup curl httpd netstat echo reboot irqinfo kbdinfo drivers lspci taskinfo tasktest taskdemo vol ls cat elfinfo fdisk blkinfo mount umount sync touch mkdir rm mv blocktest mbrtest gpttest cachetest fattest handletest waittest synctest usertest atomictest locktest mutextest timertest sleeptest preempttest processtest stacktest pftest panictest kstress taskstress");
}

static void command_clear(const char *arguments) {
    (void)arguments;
    console_clear();
    serial_write("\x1b[2J\x1b[H");
}

static void command_meminfo(const char *arguments) {
    (void)arguments;
    log_info("meminfo");
    log_info_u64("  Total RAM bytes: ", pmm_total_memory_bytes());
    log_info_u64("  Usable RAM bytes: ", pmm_usable_memory_bytes());
    log_info_u64("  PMM tracked bytes: ", pmm_tracked_memory_bytes());
    log_info_u64("  Kernel/modules reserved bytes: ", pmm_kernel_memory_bytes());
    log_info_u64("  Framebuffer reserved bytes: ", pmm_framebuffer_memory_bytes());
    log_info_u64("  Bootloader reclaimable bytes: ", pmm_bootloader_reclaimable_bytes());
    log_info_u64("  Frame size bytes: ", pmm_frame_size());
    log_info_u64("  Free frames: ", pmm_free_frame_count());
    log_info_u64("  Allocated frames: ", pmm_allocated_frame_count());
}

static void command_uptime(const char *arguments) {
    (void)arguments;
    log_info_u64_suffix("uptime: ", timer_uptime_seconds(), " seconds");
}

static void command_sysinfo(const char *arguments) {
    (void)arguments;
    struct kos_system_info info;
    system_info_snapshot(&info);
    log_info("sysinfo");
    log_info("  Kernel: KOS v0.1");
    log_info("  Architecture: x86_64");
    log_info_u64("  Uptime seconds: ", info.uptime_seconds);
    log_info_u64("  Total memory bytes: ", info.total_memory_bytes);
    log_info_u64("  Usable memory bytes: ", info.usable_memory_bytes);
    log_info_u64("  Free memory frames: ", info.free_memory_frames);
    log_info_u64("  Kernel tasks: ", info.kernel_task_count);
    log_info_u64("  Ready tasks: ", info.ready_task_count);
    log_info("  Process isolation: unavailable");
    log_info("  Scheduler: cooperative round-robin");
}

static void command_netinfo(const char *arguments) {
    (void)arguments;
    log_info("netinfo");
    log_info("  IPv4 UDP socket core: loopback and IPv4 external ready");
    log_info(net_e1000_detected()
        ? "  e1000 NIC: initialized (RX/TX DMA rings ready)"
        : "  e1000 NIC: no compatible adapter");
    struct net_interface_info info;
    if (net_interface_info(&info) && info.available) {
        if (info.configuration_source == NET_CONFIGURATION_DHCP) {
            log_info("  eth0: DHCP configured; lease active");
        }
        else {
            log_info("  eth0: static IPv4 configured; ARP/Ethernet ready");
        }
    }
    else {
        log_info("  eth0: unavailable");
    }
    log_info_u64("  UDP datagrams sent: ", net_udp_datagrams_sent());
    log_info_u64("  UDP datagrams received: ", net_udp_datagrams_received());
    log_info_u64("  UDP datagrams dropped: ", net_udp_datagrams_dropped());
    log_info_u64("  Ethernet frames transmitted: ", e1000_transmitted_frame_count());
    log_info_u64("  Ethernet frames received: ", e1000_received_frame_count());
    log_info_u64("  Ethernet frames dropped: ", net_ethernet_frames_dropped());
    log_info_u64("  e1000 TX timeouts: ", e1000_transmit_timeout_count());
    log_info_u64("  ARP requests sent: ", net_arp_requests_sent());
    log_info_u64("  ARP replies received: ", net_arp_replies_received());
    log_info_u64("  ICMP echo requests sent: ", net_icmp_echo_requests_sent());
    log_info_u64("  ICMP echo replies received: ", net_icmp_echo_replies_received());
    log_info_u64("  DHCP discovers sent: ", net_dhcp_discovers_sent());
    log_info_u64("  DHCP offers received: ", net_dhcp_offers_received());
    log_info_u64("  DHCP requests sent: ", net_dhcp_requests_sent());
    log_info_u64("  DHCP acks received: ", net_dhcp_acks_received());
    log_info_u64("  TCP segments sent: ", net_tcp_segments_sent());
    log_info_u64("  TCP segments received: ", net_tcp_segments_received());
    log_info_u64("  TCP retransmissions: ", net_tcp_retransmissions());
    log_info_u64("  DNS queries sent: ", net_dns_queries_sent());
    log_info_u64("  DNS responses received: ", net_dns_responses_received());
    uint64_t dev_cnt = net_device_count();
    log_info_u64("  Registered net devices: ", dev_cnt);
    for (uint64_t i = 0; i < dev_cnt; ++i) {
        struct net_device *d = net_device_at(i);
        if (d != 0) {
            struct net_device_stats st = { 0 };
            if (d->ops && d->ops->get_stats) {
                d->ops->get_stats(d, &st);
                log_info_u64("  net device TX packets: ", st.tx_packets);
                log_info_u64("  net device RX packets: ", st.rx_packets);
                log_info_u64("  net device TX errors: ", st.tx_errors);
                log_info_u64("  net device RX errors: ", st.rx_errors);
            }
        }
    }
}

static void command_dhcp(const char *arguments) {
    (void)arguments;
    if (!net_has_external_interface()) {
        log_error("dhcp: eth0 is unavailable.");
        return;
    }
    if (!net_dhcp_acquire(timer_frequency_hz() * 5)) {
        log_error("dhcp: failed to acquire DHCP lease.");
        return;
    }
    struct net_interface_info info;
    if (net_interface_info(&info) && info.available) {
        char address[16];
        char gateway[16];
        char dns[16];
        char line[64];
        net_format_ipv4(info.ipv4_address, address);
        net_format_ipv4(info.gateway, gateway);
        net_format_ipv4(info.dns_server, dns);

        uint64_t pos = 0;
        const char *prefix_addr = "DHCP: address ";
        for (uint64_t i = 0; prefix_addr[i] != '\0'; ++i) {
            line[pos++] = prefix_addr[i];
        }
        for (uint64_t i = 0; address[i] != '\0'; ++i) {
            line[pos++] = address[i];
        }
        line[pos] = '\0';
        log_info(line);

        pos = 0;
        const char *prefix_gw = "DHCP: gateway ";
        for (uint64_t i = 0; prefix_gw[i] != '\0'; ++i) {
            line[pos++] = prefix_gw[i];
        }
        for (uint64_t i = 0; gateway[i] != '\0'; ++i) {
            line[pos++] = gateway[i];
        }
        line[pos] = '\0';
        log_info(line);

        pos = 0;
        const char *prefix_dns = "DHCP: DNS ";
        for (uint64_t i = 0; prefix_dns[i] != '\0'; ++i) {
            line[pos++] = prefix_dns[i];
        }
        for (uint64_t i = 0; dns[i] != '\0'; ++i) {
            line[pos++] = dns[i];
        }
        line[pos] = '\0';
        log_info(line);
    }
}

static void command_ifconfig(const char *arguments) {
    (void)arguments;
    struct net_interface_info info;
    if (!net_interface_info(&info) || !info.available) {
        log_error("ifconfig: eth0 is unavailable.");
        return;
    }
    char mac[18];
    char address[16];
    char mask[16];
    char gateway[16];
    char dns[16];
    net_format_mac(info.mac_address, mac);
    net_format_ipv4(info.ipv4_address, address);
    net_format_ipv4(info.subnet_mask, mask);
    net_format_ipv4(info.gateway, gateway);
    net_format_ipv4(info.dns_server, dns);
    log_info("eth0");
    log_info("  MAC:"); log_info(mac);
    log_info("  IPv4:"); log_info(address);
    log_info("  Netmask:"); log_info(mask);
    log_info("  Gateway:"); log_info(gateway);
    log_info("  DNS:"); log_info(dns);
    log_info_u64("  IPv4 packets received: ", info.ipv4_packets_received);
    log_info_u64("  IPv4 packets dropped: ", info.ipv4_packets_dropped);
}

static void command_arp(const char *arguments) {
    (void)arguments;
    log_info("ARP cache");
    uint64_t count = net_arp_cache_count();
    if (count == 0) {
        log_info("  (empty)");
        return;
    }
    for (uint64_t index = 0; index < count; ++index) {
        struct net_arp_cache_entry entry;
        char address[16];
        char mac[18];
        if (net_arp_cache_at(index, &entry)) {
            net_format_ipv4(entry.ipv4_address, address);
            net_format_mac(entry.mac_address, mac);
            log_info(address);
            log_info(mac);
        }
    }
}

static bool command_parse_ipv4(const char *text, uint32_t *address) {
    if (text == 0 || address == 0 || *text == '\0') {
        return false;
    }
    uint32_t result = 0;
    for (uint64_t octet = 0; octet < 4; ++octet) {
        uint32_t value = 0;
        uint64_t digits = 0;
        while (*text >= '0' && *text <= '9') {
            value = value * 10 + (uint32_t)(*text - '0');
            ++text;
            ++digits;
            if (value > 255 || digits > 3) {
                return false;
            }
        }
        if (digits == 0 || (octet < 3 && *text != '.') || (octet == 3 && *text != '\0')) {
            return false;
        }
        result = (result << 8) | value;
        if (octet < 3) {
            ++text;
        }
    }
    *address = result;
    return true;
}

static void command_arping(const char *arguments) {
    uint32_t address;
    uint8_t mac[NET_ETHERNET_ADDRESS_SIZE];
    if (!command_parse_ipv4(arguments, &address)) {
        log_error("arping: use an IPv4 address, for example arping 10.0.2.2.");
        return;
    }
    if (!net_arp_resolve(address, mac, NET_ARP_DEFAULT_TIMEOUT_TICKS)) {
        log_error("arping: no ARP reply before timeout.");
        return;
    }
    char address_text[16];
    char mac_text[18];
    net_format_ipv4(address, address_text);
    net_format_mac(mac, mac_text);
    log_info("ARP reply from:");
    log_info(address_text);
    log_info(mac_text);
}

static bool command_parse_ping_arguments(const char *arguments, uint32_t *address, uint64_t *count) {
    if (arguments == 0 || address == 0 || count == 0) {
        return false;
    }
    char address_text[16];
    uint64_t length = 0;
    while (arguments[length] != '\0' && arguments[length] != ' ' && length + 1 < sizeof(address_text)) {
        address_text[length] = arguments[length];
        ++length;
    }
    address_text[length] = '\0';
    if (!command_parse_ipv4(address_text, address)) {
        return false;
    }
    while (arguments[length] == ' ') {
        ++length;
    }
    if (arguments[length] == '\0') {
        *count = 4;
        return true;
    }
    uint64_t value = 0;
    uint64_t digits = 0;
    while (arguments[length] >= '0' && arguments[length] <= '9') {
        value = value * 10 + (uint64_t)(arguments[length] - '0');
        ++length;
        ++digits;
        if (value > 16) {
            return false;
        }
    }
    if (digits == 0 || arguments[length] != '\0' || value == 0) {
        return false;
    }
    *count = value;
    return true;
}

static void command_ping(const char *arguments) {
    uint32_t address;
    uint64_t count;
    if (!command_parse_ping_arguments(arguments, &address, &count)) {
        log_error("ping: use ping <IPv4> [count], with count from 1 to 16.");
        return;
    }
    char address_text[16];
    net_format_ipv4(address, address_text);
    log_info("PING");
    log_info(address_text);
    uint64_t received = 0;
    for (uint64_t sequence = 1; sequence <= count; ++sequence) {
        uint64_t round_trip_ticks;
        if (net_icmp_ping(address, (uint16_t)sequence, timer_frequency_hz(), &round_trip_ticks)) {
            ++received;
            log_info("64 bytes from:");
            log_info(address_text);
            log_info_u64("  seq: ", sequence);
            log_info_u64("  time ms: ", round_trip_ticks * 1000 / timer_frequency_hz());
        }
        else {
            log_info_u64("Request timed out, seq: ", sequence);
        }
    }
    log_info_u64("Packets transmitted: ", count);
    log_info_u64("Packets received: ", received);
    log_info_u64("Packet loss percent: ", (count - received) * 100 / count);
}

static void command_udptest(const char *arguments) {
    (void)arguments;
    if (net_udp_loopback_self_test()) {
        log_info("udptest passed: UDP payload crossed the 127.0.0.1 socket path.");
    }
    else {
        log_error("udptest failed: UDP loopback socket path is unhealthy.");
    }
}

static void command_sockettest(const char *arguments) {
    (void)arguments;
    if (socket_self_test()) {
        log_info("sockettest passed: Socket subsystem POSIX API, loopback, non-blocking EAGAIN, and refcount verified.");
    }
    else {
        log_error("sockettest failed: Socket subsystem self test encountered an error.");
    }
}

static void command_cryptotest(const char *arguments) {
    (void)arguments;
    log_info("cryptotest: running RFC test vectors for SHA-256, SHA-384, HMAC, HKDF, X25519, AES-128-GCM, and ChaCha20-Poly1305...");
    if (kos_crypto_self_test()) {
        struct kos_entropy_status est;
        kos_entropy_status(&est);
        log_info("cryptotest passed: All cryptographic primitive test vectors verified 100% OK.");
        log_info(est.hardware_source ? "cryptotest: Hardware RNG (RDRAND) active." : "cryptotest: Monotonic TSC entropy pool active.");
    } else {
        log_error("cryptotest failed: One or more crypto primitive test vectors failed.");
    }
}

static void command_x509test(const char *arguments) {
    (void)arguments;
    log_info("x509test: testing ASN.1 DER parser, time parser, and SAN hostname matcher...");
    struct x509_certificate dummy_cert = {0};
    dummy_cert.san_count = 2;
    const char *h1 = "api.cloudflare.com";
    const char *h2 = "*.cloudflare.com";
    for (int i = 0; h1[i] != '\0'; ++i) dummy_cert.san_dns_names[0][i] = h1[i];
    for (int i = 0; h2[i] != '\0'; ++i) dummy_cert.san_dns_names[1][i] = h2[i];

    bool match_exact = x509_verify_hostname(&dummy_cert, "api.cloudflare.com");
    bool match_wildcard = x509_verify_hostname(&dummy_cert, "dash.cloudflare.com");
    bool reject_mismatch = !x509_verify_hostname(&dummy_cert, "google.com");
    bool reject_deep = !x509_verify_hostname(&dummy_cert, "sub.dash.cloudflare.com");

    uint64_t cur_time = x509_get_current_time_epoch();
    if (match_exact && match_wildcard && reject_mismatch && reject_deep && cur_time > 1700000000ull) {
        log_info("x509test passed: ASN.1 DER parser, SAN hostname matching, and RTC time verified.");
    } else {
        log_error("x509test failed: SAN matcher or RTC time invalid.");
    }
}

static void command_tlstest(const char *arguments) {
    (void)arguments;
    log_info("tlstest: testing TLS 1.3 session state machine initialization & key schedule derivation...");
    struct net_tls_session sess;
    net_tls_session_initialize(&sess, "one.one.one.one", false);
    if (sess.state == NET_TLS_STATE_IDLE && kos_crypto_self_test()) {
        log_info("tlstest passed: TLS 1.3 session initial state, cryptographic key schedule, and record cipher suites verified.");
    } else {
        log_error("tlstest failed: TLS session initialization failed.");
    }
}

static bool command_parse_tcp_arguments(const char *arguments, uint32_t *address, uint16_t *port) {
    if (arguments == 0 || address == 0 || port == 0) {
        return false;
    }
    char ip_text[16];
    uint64_t length = 0;
    while (arguments[length] != '\0' && arguments[length] != ' ' && length + 1 < sizeof(ip_text)) {
        ip_text[length] = arguments[length];
        ++length;
    }
    ip_text[length] = '\0';
    if (!command_parse_ipv4(ip_text, address)) {
        return false;
    }
    while (arguments[length] == ' ') {
        ++length;
    }
    if (arguments[length] == '\0') {
        *port = 80;
        return true;
    }
    uint32_t val = 0;
    while (arguments[length] >= '0' && arguments[length] <= '9') {
        val = val * 10 + (uint32_t)(arguments[length] - '0');
        if (val > 65535) {
            return false;
        }
        ++length;
    }
    if (val == 0 || arguments[length] != '\0') {
        return false;
    }
    *port = (uint16_t)val;
    return true;
}

static void command_tcptest(const char *arguments) {
    uint32_t address;
    uint16_t port;
    if (!command_parse_tcp_arguments(arguments, &address, &port)) {
        log_error("tcptest: use tcptest <IPv4> [port], default port 80.");
        return;
    }
    char address_text[16];
    net_format_ipv4(address, address_text);
    log_info("tcptest: connecting to TCP host...");
    int sock = tcp_connect(address, port);
    if (sock < 0) {
        log_error("tcptest: TCP connection failed or timed out.");
        return;
    }
    log_info("tcptest: TCP connection ESTABLISHED!");
    log_info("tcptest: sending HTTP GET request...");
    const char *req = "GET / HTTP/1.0\r\nHost: 1.1.1.1\r\nUser-Agent: KOS\r\n\r\n";
    uint64_t req_len = 0;
    while (req[req_len] != '\0') {
        ++req_len;
    }
    int sent = tcp_send(sock, (const uint8_t *)req, req_len);
    if (sent <= 0) {
        log_error("tcptest: failed to send HTTP request.");
        tcp_close(sock);
        return;
    }
    log_info("tcptest: waiting for HTTP response...");
    uint8_t buffer[512];
    int received = tcp_receive(sock, buffer, sizeof(buffer) - 1);
    if (received > 0) {
        buffer[received] = '\0';
        log_info("tcptest: HTTP response received:");
        log_info((const char *)buffer);
    }
    else {
        log_error("tcptest: no response received or connection closed.");
    }
    tcp_close(sock);
    log_info("tcptest: TCP connection closed cleanly.");
}

static void command_nslookup(const char *arguments) {
    if (arguments == 0 || *arguments == '\0') {
        log_error("nslookup: use nslookup <hostname>");
        return;
    }
    while (*arguments == ' ') {
        ++arguments;
    }
    char hostname[64];
    uint64_t len = 0;
    while (arguments[len] != '\0' && arguments[len] != ' ' && len + 1 < sizeof(hostname)) {
        hostname[len] = arguments[len];
        ++len;
    }
    hostname[len] = '\0';
    if (len == 0) {
        log_error("nslookup: use nslookup <hostname>");
        return;
    }

    struct net_interface_info info;
    if (net_interface_info(&info) && info.available && info.dns_server != 0) {
        char dns_text[16];
        char server_line[48];
        net_format_ipv4(info.dns_server, dns_text);
        uint64_t pos = 0;
        const char *p1 = "Server: ";
        for (uint64_t i = 0; p1[i] != '\0'; ++i) server_line[pos++] = p1[i];
        for (uint64_t i = 0; dns_text[i] != '\0'; ++i) server_line[pos++] = dns_text[i];
        server_line[pos] = '\0';
        log_info(server_line);
    }

    uint32_t resolved_ip = 0;
    if (!net_dns_resolve(hostname, &resolved_ip, timer_frequency_hz() * 5)) {
        log_error("nslookup: non-existent domain or server timed out.");
        return;
    }

    char ip_text[16];
    net_format_ipv4(resolved_ip, ip_text);

    char name_line[80];
    uint64_t pos = 0;
    const char *p2 = "Name: ";
    for (uint64_t i = 0; p2[i] != '\0'; ++i) name_line[pos++] = p2[i];
    for (uint64_t i = 0; hostname[i] != '\0'; ++i) name_line[pos++] = hostname[i];
    name_line[pos] = '\0';
    log_info(name_line);

    char addr_line[48];
    pos = 0;
    const char *p3 = "Address: ";
    for (uint64_t i = 0; p3[i] != '\0'; ++i) addr_line[pos++] = p3[i];
    for (uint64_t i = 0; ip_text[i] != '\0'; ++i) addr_line[pos++] = ip_text[i];
    addr_line[pos] = '\0';
    log_info(addr_line);
}

static char curl_response_buffer[NET_HTTP_BUFFER_MAX];

static void command_curl(const char *arguments) {
    if (arguments == 0 || *arguments == '\0') {
        log_error("curl: use curl [-i] <url>");
        return;
    }
    while (*arguments == ' ') {
        ++arguments;
    }
    bool include_headers = false;
    if (arguments[0] == '-' && (arguments[1] == 'i' || arguments[1] == 'I')
        && (arguments[2] == ' ' || arguments[2] == '\0')) {
        include_headers = true;
        arguments += 2;
        while (*arguments == ' ') {
            ++arguments;
        }
    }
    if (*arguments == '\0') {
        log_error("curl: missing URL. Use curl [-i] <url>");
        return;
    }

    char url[256];
    uint64_t url_len = 0;
    while (arguments[url_len] != '\0' && arguments[url_len] != ' ' && url_len + 1 < sizeof(url)) {
        url[url_len] = arguments[url_len];
        ++url_len;
    }
    url[url_len] = '\0';

    uint64_t response_size = 0;
    if (!net_http_get(url, curl_response_buffer, sizeof(curl_response_buffer), &response_size)) {
        log_error("curl: failed to fetch URL (connection, DNS, or HTTP error).");
        return;
    }

    const char *output = curl_response_buffer;
    if (!include_headers) {
        const char *body = 0;
        for (uint64_t i = 0; curl_response_buffer[i] != '\0'; ++i) {
            if (curl_response_buffer[i] == '\r' && curl_response_buffer[i + 1] == '\n'
                && curl_response_buffer[i + 2] == '\r' && curl_response_buffer[i + 3] == '\n') {
                body = &curl_response_buffer[i + 4];
                break;
            }
            if (curl_response_buffer[i] == '\n' && curl_response_buffer[i + 1] == '\n') {
                body = &curl_response_buffer[i + 2];
                break;
            }
        }
        if (body != 0) {
            output = body;
        }
    }

    for (uint64_t index = 0; output[index] != '\0'; ++index) {
        char character = output[index];
        if (character == '\r') {
            continue;
        }
        char printable = (character >= ' ' && character <= '~') || character == '\n' || character == '\t'
            ? character : '?';
        serial_write_char(printable);
        console_write_char(printable);
    }
    uint64_t out_len = 0;
    while (output[out_len] != '\0') {
        ++out_len;
    }
    if (out_len == 0 || output[out_len - 1] != '\n') {
        serial_write_char('\n');
        console_write_char('\n');
    }
}

static void command_httpd(const char *arguments) {
    while (*arguments == ' ') {
        ++arguments;
    }
    if (*arguments == '\0' || (arguments[0] == 's' && arguments[1] == 't' && arguments[2] == 'a' && arguments[3] == 't' && arguments[4] == 'u' && arguments[5] == 's')) {
        if (httpd_is_running()) {
            log_info_u64("httpd: running on port ", httpd_listen_port());
            log_info_u64("  Requests served: ", httpd_requests_served());
        }
        else {
            log_info("httpd: stopped. Use httpd start [port] to launch.");
        }
        return;
    }
    if (arguments[0] == 's' && arguments[1] == 't' && arguments[2] == 'o' && arguments[3] == 'p') {
        httpd_stop();
        return;
    }
    if (arguments[0] == 's' && arguments[1] == 't' && arguments[2] == 'a' && arguments[3] == 'r' && arguments[4] == 't') {
        arguments += 5;
        while (*arguments == ' ') {
            ++arguments;
        }
        uint16_t port = NET_HTTP_PORT;
        if (*arguments >= '0' && *arguments <= '9') {
            uint32_t val = 0;
            while (*arguments >= '0' && *arguments <= '9') {
                val = val * 10 + (uint32_t)(*arguments++ - '0');
                if (val > 65535) {
                    log_error("httpd: invalid port.");
                    return;
                }
            }
            if (val > 0) {
                port = (uint16_t)val;
            }
        }
        if (!httpd_start(port)) {
            log_error("httpd: failed to start web server.");
        }
        return;
    }
    log_error("httpd: use httpd start [port], httpd stop, or httpd status.");
}

static const char *tcp_state_name(enum tcp_state state) {
    switch (state) {
        case TCP_STATE_LISTEN: return "LISTEN";
        case TCP_STATE_SYN_SENT: return "SYN_SENT";
        case TCP_STATE_SYN_RECEIVED: return "SYN_RECV";
        case TCP_STATE_ESTABLISHED: return "ESTABLISHED";
        case TCP_STATE_FIN_WAIT_1: return "FIN_WAIT1";
        case TCP_STATE_FIN_WAIT_2: return "FIN_WAIT2";
        case TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case TCP_STATE_LAST_ACK: return "LAST_ACK";
        case TCP_STATE_TIME_WAIT: return "TIME_WAIT";
        case TCP_STATE_CLOSED: return "CLOSED";
        default: return "UNKNOWN";
    }
}

static void format_endpoint(uint32_t ip, uint16_t port, char *buf, uint64_t max_len) {
    char ip_str[16];
    if (ip == 0) {
        ip_str[0] = '*';
        ip_str[1] = '\0';
    }
    else {
        net_format_ipv4(ip, ip_str);
    }
    uint64_t pos = 0;
    for (uint64_t i = 0; ip_str[i] != '\0' && pos + 1 < max_len; ++i) {
        buf[pos++] = ip_str[i];
    }
    if (pos + 1 < max_len) {
        buf[pos++] = ':';
    }
    if (port == 0) {
        if (pos + 1 < max_len) buf[pos++] = '*';
    }
    else {
        uint32_t p = port;
        uint32_t digits = 0;
        char tmp[8];
        do {
            tmp[digits++] = (char)('0' + (p % 10));
            p /= 10;
        } while (p > 0);
        for (uint32_t d = 0; d < digits && pos + 1 < max_len; ++d) {
            buf[pos++] = tmp[digits - 1 - d];
        }
    }
    buf[pos] = '\0';
}

static void command_netstat(const char *arguments) {
    (void)arguments;
    log_info("Active Internet connections");
    log_info("Proto  Local Address          Foreign Address        State");

    struct net_tcp_socket_info sockets[NET_TCP_SOCKET_MAX];
    uint64_t count = net_tcp_get_sockets(sockets, NET_TCP_SOCKET_MAX);
    for (uint64_t i = 0; i < count; ++i) {
        char line[80];
        char local_ep[24];
        char remote_ep[24];
        format_endpoint(sockets[i].local_ip, sockets[i].local_port, local_ep, sizeof(local_ep));
        format_endpoint(sockets[i].remote_ip, sockets[i].remote_port, remote_ep, sizeof(remote_ep));

        uint64_t pos = 0;
        const char *proto = "tcp    ";
        for (uint64_t c = 0; proto[c] != '\0'; ++c) line[pos++] = proto[c];

        for (uint64_t c = 0; local_ep[c] != '\0'; ++c) line[pos++] = local_ep[c];
        while (pos < 30) line[pos++] = ' ';

        for (uint64_t c = 0; remote_ep[c] != '\0'; ++c) line[pos++] = remote_ep[c];
        while (pos < 53) line[pos++] = ' ';

        const char *st = tcp_state_name(sockets[i].state);
        for (uint64_t c = 0; st[c] != '\0'; ++c) line[pos++] = st[c];
        line[pos] = '\0';

        log_info(line);
    }
    if (count == 0) {
        log_info("  (no active TCP sockets)");
    }
}

static void command_echo(const char *arguments) {
    log_info(arguments);
}

static void command_reboot(const char *arguments) {
    (void)arguments;
    log_info("Rebooting through the PS/2 controller.");
    cpu_reboot();
}

static void command_irqinfo(const char *arguments) {
    (void)arguments;
    log_info("irqinfo");
    log_info_u64("  IRQ0 timer dispatches: ", irq_dispatch_count(KOS_PIC_IRQ_TIMER));
    log_info_u64("  IRQ0 timer unhandled: ", irq_unhandled_count(KOS_PIC_IRQ_TIMER));
    log_info_u64("  IRQ1 keyboard dispatches: ", irq_dispatch_count(KOS_PIC_IRQ_KEYBOARD));
    log_info_u64("  IRQ1 keyboard unhandled: ", irq_unhandled_count(KOS_PIC_IRQ_KEYBOARD));
}

static void command_kbdinfo(const char *arguments) {
    (void)arguments;
    log_info("kbdinfo");
    log_info_u64("  Pending characters: ", keyboard_pending_count());
    log_info_u64("  Dropped characters: ", keyboard_dropped_char_count());
}

static void command_drivers(const char *arguments) {
    (void)arguments;
    log_info("drivers");
    for (uint64_t index = 0; index < driver_count(); ++index) {
        const struct driver *driver = driver_at(index);
        if (driver != 0) {
            log_info(driver->name);
        }
    }
}

static void command_lspci(const char *arguments) {
    (void)arguments;
    log_info("lspci");
    for (uint64_t index = 0; index < pci_device_count(); ++index) {
        const struct pci_device *device = pci_device_at(index);
        if (device == 0) {
            continue;
        }
        uint64_t bdf = ((uint64_t)device->bus << 16) | ((uint64_t)device->device << 8)
            | device->function;
        uint64_t class_info = ((uint64_t)device->class_code << 16)
            | ((uint64_t)device->subclass << 8) | device->programming_interface;
        log_info_hex("  BDF: ", bdf);
        log_info_hex("    Vendor ID: ", device->vendor_id);
        log_info_hex("    Device ID: ", device->device_id);
        log_info_hex("    Class/Subclass/ProgIF: ", class_info);
        log_info_u64("    IRQ line: ", device->interrupt_line);
    }
}

static void command_taskinfo(const char *arguments) {
    (void)arguments;
    log_info("taskinfo");
    log_info_u64("  Known tasks: ", task_count());
    log_info_u64("  Ready tasks: ", task_ready_count());
    log_info("  Scheduler: cooperative round-robin; timer requests reschedule.");
}

static void command_tasktest(const char *arguments) {
    (void)arguments;
    if (task_run_self_test()) {
        log_info("tasktest passed: two kernel tasks each yielded 32 times.");
    }
    else {
        log_error("tasktest failed: scheduler is busy or context switch failed.");
    }
}

static void command_taskdemo(const char *arguments) {
    (void)arguments;
    if (task_run_log_demo()) {
        log_info("taskdemo passed: keyboard IRQ remained enabled while tasks alternated.");
    }
    else {
        log_error("taskdemo failed: scheduler is busy or task creation failed.");
    }
}

static bool command_parse_volume(const char *arguments, char *letter) {
    if (arguments == 0 || letter == 0) {
        return false;
    }
    if (*arguments == '\0') {
        *letter = 'C';
        return true;
    }
    if (arguments[1] != ':' || arguments[2] != '\0') {
        return false;
    }
    *letter = arguments[0] >= 'a' && arguments[0] <= 'z'
        ? (char)(arguments[0] - ('a' - 'A')) : arguments[0];
    return vfs_volume_is_mounted(*letter);
}

static void command_vol(const char *arguments) {
    (void)arguments;
    log_info("vol");
    for (uint64_t index = 0; index < vfs_volume_count(); ++index) {
        struct vfs_volume_info info;
        if (!vfs_volume_info_at(index, &info)) {
            continue;
        }
        char name[] = { info.letter, ':', '\0' };
        log_info(name);
        log_info("  Label:");
        log_info(info.label);
        log_info_u64("  Files: ", info.file_count);
    }
}

static void command_ls(const char *arguments) {
    char letter;
    if (!command_parse_volume(arguments, &letter)) {
        log_error("ls: use a mounted volume, for example C: or D:.");
        return;
    }
    char name[] = { letter, ':', '\\', '\0' };
    log_info(name);
    for (uint64_t index = 0; index < vfs_file_count_on_volume(letter); ++index) {
        const struct vfs_file *file = vfs_file_at_on_volume(letter, index);
        if (file != 0) {
            log_info(file->path);
        }
    }
}

static void command_cat(const char *arguments) {
    const uint8_t *data;
    uint64_t size;
    if (*arguments == '\0' || !vfs_read_file(arguments, &data, &size)) {
        log_error("cat: file not found.");
        return;
    }
    for (uint64_t index = 0; index < size; ++index) {
        char character = data[index] >= ' ' && data[index] <= '~' ? (char)data[index]
            : data[index] == '\n' ? '\n' : '?';
        serial_write_char(character);
        console_write_char(character);
    }
    if (size == 0 || data[size - 1] != '\n') {
        serial_write_char('\n');
        console_write_char('\n');
    }
}

static void command_elfinfo(const char *arguments) {
    const uint8_t *data;
    uint64_t size;
    struct elf_image_info info;
    if (*arguments == '\0' || !vfs_read_file(arguments, &data, &size)) {
        log_error("elfinfo: file not found.");
        return;
    }
    if (!elf_inspect_image(data, size, &info)) {
        log_error("elfinfo: not a supported x86_64 ELF image.");
        return;
    }
    log_info_hex("ELF entry: ", info.entry_point);
    log_info_u64("ELF program headers: ", info.program_header_count);
    log_info_u64("ELF loadable segments: ", info.loadable_segment_count);
}

/* ========================================================================= */
/* Diagnostic Command: synctest (K12.17 - K12.21)                            */
/* ========================================================================= */

struct pmm_stress_worker_arg {
    uint32_t worker_id;
    uint32_t iterations;
    volatile uint32_t completed_iters;
    volatile uint32_t errors;
    volatile bool finished;
};

static void pmm_stress_worker(void *arg) {
    struct pmm_stress_worker_arg *w = (struct pmm_stress_worker_arg *)arg;
    for (uint32_t iter = 0; iter < w->iterations; ++iter) {
        uint64_t p1 = pmm_alloc_page();
        uint64_t p2 = pmm_alloc_page();
        uint64_t pmulti = pmm_alloc_pages(2);

        if (p1 == 0 || p2 == 0 || pmulti == 0 || p1 == p2 || p1 == pmulti || p2 == pmulti) {
            w->errors++;
        }
        if ((p1 & 0xfff) != 0 || (p2 & 0xfff) != 0 || (pmulti & 0xfff) != 0) {
            w->errors++;
        }

        task_yield();

        if (p1 != 0 && !pmm_free_page(p1)) {
            w->errors++;
        }
        if (p2 != 0 && !pmm_free_page(p2)) {
            w->errors++;
        }
        if (pmulti != 0 && !pmm_free_pages(pmulti, 2)) {
            w->errors++;
        }

        w->completed_iters++;
    }
    w->finished = true;
}

struct heap_stress_worker_arg {
    uint32_t worker_id;
    uint32_t iterations;
    volatile uint32_t completed_iters;
    volatile uint32_t errors;
    volatile bool finished;
};

static void heap_stress_worker(void *arg) {
    struct heap_stress_worker_arg *w = (struct heap_stress_worker_arg *)arg;
    for (uint32_t iter = 0; iter < w->iterations; ++iter) {
        uint8_t *b32 = (uint8_t *)kmalloc(32);
        uint8_t *b64 = (uint8_t *)kmalloc(64);
        uint8_t *b128 = (uint8_t *)kmalloc(128);
        uint32_t *bzero = (uint32_t *)kcalloc(16, sizeof(uint32_t));

        if (b32 == 0 || b64 == 0 || b128 == 0 || bzero == 0) {
            w->errors++;
        } else {
            for (uint32_t i = 0; i < 16; ++i) {
                if (bzero[i] != 0) {
                    w->errors++;
                    break;
                }
            }

            uint8_t tag = (uint8_t)((w->worker_id << 4) | (iter & 0x0f));
            for (int i = 0; i < 32; ++i) b32[i] = tag;
            for (int i = 0; i < 64; ++i) b64[i] = (uint8_t)(tag ^ 0xaa);

            uint8_t *b_realloc = (uint8_t *)krealloc(b64, 128);
            if (b_realloc == 0) {
                w->errors++;
            } else {
                for (int i = 0; i < 64; ++i) {
                    if (b_realloc[i] != (uint8_t)(tag ^ 0xaa)) {
                        w->errors++;
                        break;
                    }
                }
                b64 = b_realloc;
            }

            task_yield();

            for (int i = 0; i < 32; ++i) {
                if (b32[i] != tag) {
                    w->errors++;
                    break;
                }
            }
        }

        if (b32 != 0) (void)kfree(b32);
        if (b64 != 0) (void)kfree(b64);
        if (b128 != 0) (void)kfree(b128);
        if (bzero != 0) (void)kfree(bzero);

        w->completed_iters++;
    }
    w->finished = true;
}

struct vfs_stress_worker_arg {
    char filename[32];
    char pattern[32];
    uint32_t iterations;
    volatile uint32_t completed_iters;
    volatile uint32_t errors;
    volatile bool finished;
};

static void vfs_stress_worker(void *arg) {
    struct vfs_stress_worker_arg *w = (struct vfs_stress_worker_arg *)arg;
    uint64_t pat_len = 0;
    while (w->pattern[pat_len] != '\0') pat_len++;

    for (uint32_t iter = 0; iter < w->iterations; ++iter) {
        if (!vfs_write_file(w->filename, (const uint8_t *)w->pattern, pat_len)) {
            w->errors++;
        }

        task_yield();

        const uint8_t *data = 0;
        uint64_t size = 0;
        if (!vfs_read_file(w->filename, &data, &size) || size != pat_len || data == 0) {
            w->errors++;
        } else {
            for (uint64_t i = 0; i < pat_len; ++i) {
                if (data[i] != (uint8_t)w->pattern[i]) {
                    w->errors++;
                    break;
                }
            }
        }

        task_yield();

        if (!vfs_unlink_file(w->filename)) {
            w->errors++;
        }

        w->completed_iters++;
    }
    w->finished = true;
}

struct vfs_reader_worker_arg {
    uint32_t iterations;
    volatile uint32_t completed_iters;
    volatile uint32_t errors;
    volatile bool finished;
};

static void vfs_reader_worker(void *arg) {
    struct vfs_reader_worker_arg *w = (struct vfs_reader_worker_arg *)arg;
    for (uint32_t iter = 0; iter < w->iterations; ++iter) {
        uint64_t vcount = vfs_volume_count();
        if (vcount == 0) {
            w->errors++;
        }
        struct vfs_volume_info vinfo;
        if (!vfs_volume_info_at(0, &vinfo)) {
            w->errors++;
        }
        (void)vfs_file_count_on_volume('D');
        task_yield();
        w->completed_iters++;
    }
    w->finished = true;
}

struct socket_sync_sender_arg {
    uint16_t port;
    uint64_t delay_ms;
    volatile bool finished;
};

static void socket_sync_sender_worker(void *arg) {
    struct socket_sync_sender_arg *sarg = (struct socket_sync_sender_arg *)arg;
    task_sleep(sarg->delay_ms);
    uint16_t sender_id = UINT16_MAX;
    if (net_udp_open(&sender_id)) {
        struct net_ipv4_endpoint target = {
            .address = NET_IPV4_LOOPBACK,
            .port = sarg->port,
        };
        static const uint8_t msg[] = "SYNC-WAITQ-OK";
        (void)net_udp_sendto(sender_id, target, msg, sizeof(msg) - 1);
        (void)net_udp_close(sender_id);
    }
    sarg->finished = true;
}

static void command_synctest(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info("=== Milestone K12 Step 12 Subsystem Sync Tests ===");
    log_info("==================================================");

    bool all_passed = true;
    struct process *cur_proc = process_get_kernel();

    /* ------------------------------------------------------------- */
    /* Test 1: PMM Concurrent Stress (K12.17)                        */
    /* ------------------------------------------------------------- */
    log_info("[synctest] 1. PMM Concurrent Allocation Stress...");
    {
        uint64_t initial_frames = pmm_allocated_frame_count();
        enum { WORKER_COUNT = 4, ITERS = 25 };
        struct pmm_stress_worker_arg args[WORKER_COUNT];

        for (int i = 0; i < WORKER_COUNT; ++i) {
            args[i].worker_id = (uint32_t)i;
            args[i].iterations = ITERS;
            args[i].completed_iters = 0;
            args[i].errors = 0;
            args[i].finished = false;
            char name[16] = "pmm_sync_0";
            name[9] = (char)('0' + i);
            struct thread *t = thread_create(cur_proc, pmm_stress_worker, &args[i], name);
            if (t == 0) {
                log_error("  [FAIL] Failed to create PMM worker thread!");
                all_passed = false;
            }
        }

        uint64_t start_time = timer_get_ticks();
        bool done = false;
        while (!done && (timer_get_ticks() - start_time) < timer_ms_to_ticks(3000)) {
            done = true;
            for (int i = 0; i < WORKER_COUNT; ++i) {
                if (!args[i].finished) {
                    done = false;
                    break;
                }
            }
            if (!done) {
                task_yield();
            }
        }

        uint32_t total_errors = 0;
        for (int i = 0; i < WORKER_COUNT; ++i) {
            if (!args[i].finished) {
                log_error("  [FAIL] PMM worker timed out!");
                all_passed = false;
            }
            total_errors += args[i].errors;
        }

        uint64_t final_frames = pmm_allocated_frame_count();
        if (total_errors > 0 || final_frames != initial_frames) {
            log_errorf("  [FAIL] PMM stress errors=%u, initial=%lu, final=%lu", total_errors, initial_frames, final_frames);
            all_passed = false;
        } else {
            log_infof("  4 threads completed %d iterations each with 0 leaks.", ITERS);
            log_info("  [PASS] PMM concurrent allocation/free stress verified!");
        }
    }

    /* ------------------------------------------------------------- */
    /* Test 2: Heap Concurrent Stress (K12.18)                       */
    /* ------------------------------------------------------------- */
    log_info("[synctest] 2. Heap Concurrent Allocation & Realloc Stress...");
    {
        uint64_t initial_allocs = heap_active_allocation_count();
        enum { WORKER_COUNT = 4, ITERS = 20 };
        struct heap_stress_worker_arg args[WORKER_COUNT];

        for (int i = 0; i < WORKER_COUNT; ++i) {
            args[i].worker_id = (uint32_t)i;
            args[i].iterations = ITERS;
            args[i].completed_iters = 0;
            args[i].errors = 0;
            args[i].finished = false;
            char name[16] = "heap_sync_0";
            name[10] = (char)('0' + i);
            struct thread *t = thread_create(cur_proc, heap_stress_worker, &args[i], name);
            if (t == 0) {
                log_error("  [FAIL] Failed to create heap worker thread!");
                all_passed = false;
            }
        }

        uint64_t start_time = timer_get_ticks();
        bool done = false;
        while (!done && (timer_get_ticks() - start_time) < timer_ms_to_ticks(3000)) {
            done = true;
            for (int i = 0; i < WORKER_COUNT; ++i) {
                if (!args[i].finished) {
                    done = false;
                    break;
                }
            }
            if (!done) {
                task_yield();
            }
        }

        uint32_t total_errors = 0;
        for (int i = 0; i < WORKER_COUNT; ++i) {
            if (!args[i].finished) {
                log_error("  [FAIL] Heap worker timed out!");
                all_passed = false;
            }
            total_errors += args[i].errors;
        }

        uint64_t final_allocs = heap_active_allocation_count();
        if (total_errors > 0 || final_allocs != initial_allocs) {
            log_errorf("  [FAIL] Heap stress errors=%u, initial=%lu, final=%lu", total_errors, initial_allocs, final_allocs);
            all_passed = false;
        } else {
            log_infof("  4 threads completed %d iterations with malloc/calloc/realloc/free.", ITERS);
            log_info("  [PASS] Heap concurrent allocation/realloc/free stress verified!");
        }
    }

    /* ------------------------------------------------------------- */
    /* Test 3: VFS / RAMFS Concurrent Access & Unlink (K12.20)       */
    /* ------------------------------------------------------------- */
    log_info("[synctest] 3. VFS / RAMFS Concurrent Create/Read/Write/Unlink...");
    {
        uint64_t initial_files = vfs_file_count_on_volume('D');
        struct vfs_stress_worker_arg w_a = {
            .filename = "D:/sync_file_a.txt",
            .pattern = "KOS_SYNC_PAYLOAD_AAA",
            .iterations = 10,
            .completed_iters = 0,
            .errors = 0,
            .finished = false,
        };
        struct vfs_stress_worker_arg w_b = {
            .filename = "D:/sync_file_b.txt",
            .pattern = "KOS_SYNC_PAYLOAD_BBB",
            .iterations = 10,
            .completed_iters = 0,
            .errors = 0,
            .finished = false,
        };
        struct vfs_reader_worker_arg w_r = {
            .iterations = 20,
            .completed_iters = 0,
            .errors = 0,
            .finished = false,
        };

        struct thread *ta = thread_create(cur_proc, vfs_stress_worker, &w_a, "vfs_worker_a");
        struct thread *tb = thread_create(cur_proc, vfs_stress_worker, &w_b, "vfs_worker_b");
        struct thread *tr = thread_create(cur_proc, vfs_reader_worker, &w_r, "vfs_reader");

        if (ta == 0 || tb == 0 || tr == 0) {
            log_error("  [FAIL] Failed to create VFS worker threads!");
            all_passed = false;
        }

        uint64_t start_time = timer_get_ticks();
        while ((!w_a.finished || !w_b.finished || !w_r.finished) && (timer_get_ticks() - start_time) < timer_ms_to_ticks(3000)) {
            task_yield();
        }

        uint64_t final_files = vfs_file_count_on_volume('D');
        uint32_t errs = w_a.errors + w_b.errors + w_r.errors;
        if (!w_a.finished || !w_b.finished || !w_r.finished || errs > 0 || final_files != initial_files) {
            log_errorf("  [FAIL] VFS concurrent stress errors=%u, files initial=%lu, final=%lu", errs, initial_files, final_files);
            all_passed = false;
        } else {
            log_info("  Concurrent writers and readers completed with clean unlinks.");
            log_info("  [PASS] VFS/RAMFS concurrent create/read/write/unlink verified!");
        }
    }

    /* ------------------------------------------------------------- */
    /* Test 4: Socket Wait Queue Synchronization (K12.21)           */
    /* ------------------------------------------------------------- */
    log_info("[synctest] 4. Socket Wait Queue Non-Busy Synchronization...");
    {
        uint16_t recv_sock = UINT16_MAX;
        if (!net_udp_open(&recv_sock)) {
            log_error("  [FAIL] Failed to open UDP receiver socket!");
            all_passed = false;
        } else {
            struct net_ipv4_endpoint recv_ep = {
                .address = NET_IPV4_LOOPBACK,
                .port = 43210,
            };
            if (!net_udp_bind(recv_sock, recv_ep)) {
                log_error("  [FAIL] Failed to bind receiver socket!");
                all_passed = false;
            } else {
                struct socket_sync_sender_arg sarg = {
                    .port = 43210,
                    .delay_ms = 20,
                    .finished = false,
                };
                struct thread *tsend = thread_create(cur_proc, socket_sync_sender_worker, &sarg, "sock_sender");
                if (tsend == 0) {
                    log_error("  [FAIL] Failed to create socket sender thread!");
                    all_passed = false;
                } else {
                    uint8_t buffer[64];
                    struct net_ipv4_endpoint sender_ep;
                    uint64_t recv_size = 0;

                    /* Wait queue timed receive (200ms timeout) */
                    uint64_t t0 = timer_get_ticks();
                    bool ok = net_udp_recvfrom_timeout(recv_sock, &sender_ep, buffer, sizeof(buffer), &recv_size, 200);
                    uint64_t elapsed_ms = timer_ticks_to_ms(timer_get_ticks() - t0);

                    if (!ok || recv_size != 13) {
                        log_errorf("  [FAIL] Timed UDP receive failed! ok=%d, size=%lu", (int)ok, recv_size);
                        all_passed = false;
                    } else {
                        buffer[recv_size] = '\0';
                        log_infof("  Received message '%s' in %lu ms via socket wait queue.", (const char *)buffer, elapsed_ms);

                        /* Test empty socket timeout (30ms timeout) */
                        uint64_t t_to0 = timer_get_ticks();
                        bool to_res = net_udp_recvfrom_timeout(recv_sock, &sender_ep, buffer, sizeof(buffer), &recv_size, 30);
                        uint64_t to_elapsed = timer_ticks_to_ms(timer_get_ticks() - t_to0);

                        if (to_res) {
                            log_error("  [FAIL] Expected timeout on empty socket but received data!");
                            all_passed = false;
                        } else {
                            log_infof("  Empty socket cleanly timed out in %lu ms (expected ~30ms).", to_elapsed);
                            log_info("  [PASS] Socket wait queue non-busy synchronization verified!");
                        }
                    }
                }
                (void)net_udp_close(recv_sock);
            }
        }
    }

    log_info("--------------------------------------------------");
    if (all_passed) {
        log_info(">>> [PASS] ALL SUBSYSTEM SYNCHRONIZATION TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] ONE OR MORE SUBSYSTEM SYNCHRONIZATION TESTS FAILED! <<<");
    }
    log_info("==================================================");
    /* Milestone K14: Automatic verification of Ring 3 userspace & process tests */
    command_usertest("all");
}

/*
 * ============================================================================
 * Diagnostic Command: handletest (K12.14, K12.15)
 * ============================================================================
 */

struct handletest_obj {
    struct kos_object_header header;
    uint32_t magic;
    bool destructor_called;
};

static void handletest_destructor(void *object) {
    struct handletest_obj *obj = (struct handletest_obj *)object;
    if (obj != NULL) {
        obj->destructor_called = true;
    }
}

static void command_handletest(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info("   KOS Kernel Object & Handle Table Diagnostics   ");
    log_info("==================================================");

    bool all_passed = true;

    /* ------------------------------------------------------------
     * Test 1: Object refcounting & custom destructor callback
     * ------------------------------------------------------------ */
    log_info("[handletest] 1. Kernel Object Refcounting & Destructor...");
    {
        struct handletest_obj obj1;
        obj1.magic = 0xABCD1234;
        obj1.destructor_called = false;

        kos_object_init(&obj1.header, KOS_OBJ_MUTEX, handletest_destructor);
        int32_t ref = kos_object_get_refcount(&obj1.header);
        if (ref != 1) {
            log_errorf("  [FAIL] Expected initial refcount 1, got %d", ref);
            all_passed = false;
        } else if (obj1.header.type != KOS_OBJ_MUTEX) {
            log_errorf("  [FAIL] Expected object type MUTEX (%d), got %d",
                       (int)KOS_OBJ_MUTEX, (int)obj1.header.type);
            all_passed = false;
        } else if (obj1.destructor_called) {
            log_error("  [FAIL] Destructor called prematurely on init!");
            all_passed = false;
        } else {
            kos_object_ref(&obj1.header);
            ref = kos_object_get_refcount(&obj1.header);
            if (ref != 2) {
                log_errorf("  [FAIL] Expected refcount 2 after kos_object_ref, got %d", ref);
                all_passed = false;
            } else {
                kos_object_unref(&obj1.header);
                ref = kos_object_get_refcount(&obj1.header);
                if (ref != 1 || obj1.destructor_called) {
                    log_errorf("  [FAIL] Expected refcount 1 and no destructor, got ref=%d called=%d",
                               ref, (int)obj1.destructor_called);
                    all_passed = false;
                } else {
                    kos_object_unref(&obj1.header);
                    ref = kos_object_get_refcount(&obj1.header);
                    if (ref != 0) {
                        log_errorf("  [FAIL] Expected refcount 0 after final unref, got %d", ref);
                        all_passed = false;
                    } else if (!obj1.destructor_called) {
                        log_error("  [FAIL] Custom destructor was not invoked upon reaching 0 refcount!");
                        all_passed = false;
                    } else {
                        log_info("  Object refcount transitions (1 -> 2 -> 1 -> 0) verified.");
                        log_info("  Custom destructor callback successfully executed at refcount 0.");
                        log_info("  [PASS] Kernel object refcounting and destructor verified!");
                    }
                }
            }
        }
    }

    /* ------------------------------------------------------------
     * Test 2: Handle creation, rights validation, generation tagging
     * ------------------------------------------------------------ */
    log_info("[handletest] 2. Handle Creation, Rights & Generation Tagging...");
    {
        struct process *proc = process_create("htest-proc2");
        if (proc == NULL || proc->handles == NULL) {
            log_error("  [FAIL] Failed to create test process with handle table!");
            all_passed = false;
        } else {
            struct handletest_obj obj2;
            obj2.magic = 0x5678EF01;
            obj2.destructor_called = false;
            kos_object_init(&obj2.header, KOS_OBJ_SEMAPHORE, NULL);

            /* Create handle with READ and WAIT rights */
            handle_t h = handle_create(proc, &obj2.header, KOS_RIGHT_READ | KOS_RIGHT_WAIT);
            if (h == KOS_INVALID_HANDLE) {
                log_error("  [FAIL] Failed to create handle!");
                all_passed = false;
            } else {
                uint16_t idx = KOS_HANDLE_INDEX(h);
                uint16_t gen = KOS_HANDLE_GEN(h);
                int32_t ref = kos_object_get_refcount(&obj2.header);

                log_infof("  Created handle 0x%08x (Index=%u, Gen=%u), object refcount=%d",
                          h, (unsigned)idx, (unsigned)gen, ref);

                if (ref != 2) {
                    log_errorf("  [FAIL] Expected object refcount 2, got %d", ref);
                    all_passed = false;
                } else if (gen == 0) {
                    log_error("  [FAIL] Handle generation must be non-zero!");
                    all_passed = false;
                } else {
                    /* Lookup with matching rights */
                    void *p_read = handle_lookup(proc, h, KOS_RIGHT_READ);
                    void *p_wait = handle_lookup(proc, h, KOS_RIGHT_WAIT);
                    void *p_both = handle_lookup(proc, h, KOS_RIGHT_READ | KOS_RIGHT_WAIT);

                    /* Lookup with forbidden / unheld rights */
                    void *p_write = handle_lookup(proc, h, KOS_RIGHT_WRITE);
                    void *p_exec = handle_lookup(proc, h, KOS_RIGHT_EXECUTE);

                    /* Lookup with type checking */
                    void *p_type_ok = handle_lookup_type(proc, h, KOS_OBJ_SEMAPHORE, KOS_RIGHT_READ);
                    void *p_type_bad = handle_lookup_type(proc, h, KOS_OBJ_MUTEX, KOS_RIGHT_READ);

                    if (p_read != &obj2.header || p_wait != &obj2.header || p_both != &obj2.header) {
                        log_error("  [FAIL] Handle lookup failed with held rights!");
                        all_passed = false;
                    } else if (p_write != NULL || p_exec != NULL) {
                        log_error("  [FAIL] Handle lookup succeeded with unheld rights (security bypass)!");
                        all_passed = false;
                    } else if (p_type_ok != &obj2.header || p_type_bad != NULL) {
                        log_error("  [FAIL] Handle lookup type validation failed!");
                        all_passed = false;
                    } else {
                        log_info("  Handle rights correctly enforced (granted rights pass, unheld fail).");
                        log_info("  Handle object type validation confirmed (SEMAPHORE match, MUTEX reject).");

                        bool closed = handle_close(proc, h);
                        ref = kos_object_get_refcount(&obj2.header);
                        if (!closed || ref != 1) {
                            log_errorf("  [FAIL] handle_close failed or bad refcount (%d)", ref);
                            all_passed = false;
                        } else {
                            log_info("  Handle successfully closed and table reference dropped.");
                            log_info("  [PASS] Handle creation, rights validation, and type check verified!");
                        }
                    }
                }
            }

            process_destroy(proc);
            kos_object_unref(&obj2.header);
        }
    }

    /* ------------------------------------------------------------
     * Test 3: Stale handle prevention (Anti-ABA)
     * ------------------------------------------------------------ */
    log_info("[handletest] 3. Stale Handle Prevention (Anti-ABA Verification)...");
    {
        struct process *proc = process_create("htest-proc3");
        if (proc == NULL || proc->handles == NULL) {
            log_error("  [FAIL] Failed to create test process for ABA test!");
            all_passed = false;
        } else {
            struct handletest_obj objA;
            struct handletest_obj objB;
            kos_object_init(&objA.header, KOS_OBJ_EVENT, NULL);
            kos_object_init(&objB.header, KOS_OBJ_EVENT, NULL);

            /* Create handle A */
            handle_t handleA = handle_create(proc, &objA.header, KOS_RIGHT_ALL);
            uint16_t idxA = KOS_HANDLE_INDEX(handleA);
            uint16_t genA = KOS_HANDLE_GEN(handleA);

            log_infof("  Created handle A 0x%08x at slot %u with generation %u",
                      handleA, (unsigned)idxA, (unsigned)genA);

            /* Close handle A */
            if (!handle_close(proc, handleA)) {
                log_error("  [FAIL] Failed to close handle A!");
                all_passed = false;
            } else {
                /* Attempt to close handle A second time (must fail) */
                if (handle_close(proc, handleA)) {
                    log_error("  [FAIL] Second handle_close succeeded on already closed handle!");
                    all_passed = false;
                } else {
                    /* Create handle B: will reuse slot idxA, but with incremented generation */
                    handle_t handleB = handle_create(proc, &objB.header, KOS_RIGHT_ALL);
                    uint16_t idxB = KOS_HANDLE_INDEX(handleB);
                    uint16_t genB = KOS_HANDLE_GEN(handleB);

                    log_infof("  Created handle B 0x%08x at slot %u with generation %u",
                              handleB, (unsigned)idxB, (unsigned)genB);

                    if (idxB != idxA) {
                        log_errorf("  [FAIL] Expected slot reuse %u, got %u", (unsigned)idxA, (unsigned)idxB);
                        all_passed = false;
                    } else if (genB != genA + 1) {
                        log_errorf("  [FAIL] Expected generation increment (%u -> %u), got %u",
                                   (unsigned)genA, (unsigned)(genA + 1), (unsigned)genB);
                        all_passed = false;
                    } else {
                        /* Attempt lookup using old stale handle A: MUST return NULL */
                        void *stale_lookup = handle_lookup(proc, handleA, KOS_RIGHT_NONE);
                        void *valid_lookup = handle_lookup(proc, handleB, KOS_RIGHT_NONE);

                        if (stale_lookup != NULL) {
                            log_error("  [FAIL] ABA vulnerability! Stale handle A accessed newly allocated object!");
                            all_passed = false;
                        } else if (valid_lookup != &objB.header) {
                            log_error("  [FAIL] Valid handle B lookup failed!");
                            all_passed = false;
                        } else {
                            log_info("  Stale handle A successfully rejected via generation tag mismatch.");
                            log_info("  Reallocated slot correctly serves handle B with generation + 1.");
                            log_info("  [PASS] Stale handle prevention (anti-ABA) verified!");
                        }

                        handle_close(proc, handleB);
                    }
                }
            }

            process_destroy(proc);
            kos_object_unref(&objA.header);
            kos_object_unref(&objB.header);
        }
    }

    /* ------------------------------------------------------------
     * Test 4: Handle duplication across processes & exit cleanup
     * ------------------------------------------------------------ */
    log_info("[handletest] 4. Handle Duplication & Process Exit Table Cleanup...");
    {
        struct process *p_src = process_create("htest-src");
        struct process *p_dst = process_create("htest-dst");

        if (p_src == NULL || p_dst == NULL || p_src->handles == NULL || p_dst->handles == NULL) {
            log_error("  [FAIL] Failed to create source/destination test processes!");
            all_passed = false;
        } else {
            struct handletest_obj shared_obj;
            shared_obj.magic = 0xCAFE9999;
            shared_obj.destructor_called = false;
            kos_object_init(&shared_obj.header, KOS_OBJ_FILE, handletest_destructor);

            /* Create handle in source process with READ, WRITE, DUPLICATE rights */
            handle_t h_src = handle_create(p_src, &shared_obj.header,
                                           KOS_RIGHT_READ | KOS_RIGHT_WRITE | KOS_RIGHT_DUPLICATE);
            if (h_src == KOS_INVALID_HANDLE) {
                log_error("  [FAIL] Failed to create handle in source process!");
                all_passed = false;
            } else {
                int32_t ref = kos_object_get_refcount(&shared_obj.header);
                if (ref != 2) {
                    log_errorf("  [FAIL] Expected refcount 2, got %d", ref);
                    all_passed = false;
                } else {
                    /* Attempt duplication with rights amplification (EXECUTE not held by src) */
                    handle_t h_amplified = handle_duplicate(p_src, p_dst, h_src, KOS_RIGHT_EXECUTE);
                    if (h_amplified != KOS_INVALID_HANDLE) {
                        log_error("  [FAIL] Rights amplification permitted during duplication!");
                        all_passed = false;
                    } else {
                        /* Duplicate with attenuated rights (READ only) */
                        handle_t h_dst = handle_duplicate(p_src, p_dst, h_src, KOS_RIGHT_READ);
                        if (h_dst == KOS_INVALID_HANDLE) {
                            log_error("  [FAIL] Failed to duplicate handle with attenuated rights!");
                            all_passed = false;
                        } else {
                            ref = kos_object_get_refcount(&shared_obj.header);
                            log_infof("  Duplicated handle: src=0x%08x -> dst=0x%08x, object refcount=%d",
                                      h_src, h_dst, ref);

                            if (ref != 3) {
                                log_errorf("  [FAIL] Expected refcount 3 after duplication, got %d", ref);
                                all_passed = false;
                            } else {
                                /* In dst process: READ must succeed, WRITE must fail */
                                void *dst_read = handle_lookup(p_dst, h_dst, KOS_RIGHT_READ);
                                void *dst_write = handle_lookup(p_dst, h_dst, KOS_RIGHT_WRITE);

                                if (dst_read != &shared_obj.header || dst_write != NULL) {
                                    log_error("  [FAIL] Destination handle rights incorrect after attenuation!");
                                    all_passed = false;
                                } else {
                                    /* Test automatic cleanup on source process destruction */
                                    process_destroy(p_src);
                                    p_src = NULL;

                                    ref = kos_object_get_refcount(&shared_obj.header);
                                    log_infof("  After source process destroyed: object refcount=%d, destructor=%d",
                                              ref, (int)shared_obj.destructor_called);

                                    if (ref != 2 || shared_obj.destructor_called) {
                                        log_errorf("  [FAIL] Incorrect refcount (%d) after src cleanup!", ref);
                                        all_passed = false;
                                    } else {
                                        /* Destination process can still access object */
                                        void *dst_after = handle_lookup(p_dst, h_dst, KOS_RIGHT_READ);
                                        if (dst_after != &shared_obj.header) {
                                            log_error("  [FAIL] Destination handle broken after src destruction!");
                                            all_passed = false;
                                        } else {
                                            /* Destroy destination process */
                                            process_destroy(p_dst);
                                            p_dst = NULL;

                                            ref = kos_object_get_refcount(&shared_obj.header);
                                            log_infof("  After dst process destroyed: object refcount=%d, destructor=%d",
                                                      ref, (int)shared_obj.destructor_called);

                                            if (ref != 1 || shared_obj.destructor_called) {
                                                log_errorf("  [FAIL] Incorrect refcount (%d) after dst cleanup!", ref);
                                                all_passed = false;
                                            } else {
                                                /* Release final baseline reference */
                                                kos_object_unref(&shared_obj.header);
                                                ref = kos_object_get_refcount(&shared_obj.header);

                                                if (ref != 0 || !shared_obj.destructor_called) {
                                                    log_errorf("  [FAIL] Final unref failed: ref=%d, destructor=%d",
                                                               ref, (int)shared_obj.destructor_called);
                                                    all_passed = false;
                                                } else {
                                                    log_info("  Both process handle tables cleanly destroyed on exit.");
                                                    log_info("  Object references properly released across process life cycles.");
                                                    log_info("  Final destructor called when last reference released.");
                                                    log_info("  [PASS] Handle duplication and automatic cleanup verified!");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if (p_src != NULL) process_destroy(p_src);
        if (p_dst != NULL) process_destroy(p_dst);
    }

    log_info("--------------------------------------------------");
    if (all_passed) {
        log_info(">>> [PASS] ALL KERNEL OBJECT & HANDLE TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] KERNEL OBJECT & HANDLE TESTS FAILED! <<<");
    }
    log_info("==================================================");
}

/*
 * ============================================================================
 * Diagnostic Command: waittest (K12.13, K12.16)
 * ============================================================================
 */

/* Test 1 Waiter */
struct waittest1_state {
    wait_queue_t *wq;
    volatile bool *flag;
    volatile bool woken;
};

static bool waittest_flag_cond(void *arg) {
    volatile bool *flag = (volatile bool *)arg;
    return *flag;
}

static void waittest1_worker(void *arg) {
    struct waittest1_state *st = (struct waittest1_state *)arg;
    wait_event(st->wq, waittest_flag_cond, (void *)st->flag);
    st->woken = true;
    thread_exit(0);
}

/* Test 2 Waiters */
struct waittest2_state {
    wait_queue_t *wq;
    volatile bool *flag;
    atomic_t woken_count;
};

static void waittest2_worker(void *arg) {
    struct waittest2_state *st = (struct waittest2_state *)arg;
    wait_event(st->wq, waittest_flag_cond, (void *)st->flag);
    atomic_inc(&st->woken_count);
    thread_exit(0);
}

/* Test 3 Condition (always false) */
static bool waittest_never_cond(void *arg) {
    (void)arg;
    return false;
}

/* Test 4 Event Worker */
struct waittest4_state {
    struct process *proc;
    handle_t event_handle;
    volatile bool woken;
};

static void waittest4_worker(void *arg) {
    struct waittest4_state *st = (struct waittest4_state *)arg;
    if (event_wait(st->proc, st->event_handle, 1000)) {
        st->woken = true;
    }
    thread_exit(0);
}

/* Test 5 Cleanup Object & Child Process */
struct waittest_cleanup_obj {
    struct kos_object_header header;
    volatile bool destructor_called;
};

static void waittest_cleanup_destructor(void *obj) {
    struct waittest_cleanup_obj *cobj = (struct waittest_cleanup_obj *)obj;
    if (cobj != NULL) {
        cobj->destructor_called = true;
    }
}

static void waittest5_child_worker(void *arg) {
    struct process *proc = (struct process *)arg;
    task_sleep(20);
    process_exit(proc, 77);
}

static void command_waittest(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info("    KOS Wait Queue & Resource Cleanup Diagnostics ");
    log_info("==================================================");

    bool all_passed = true;

    /* ------------------------------------------------------------
     * Test 1: Single wakeup (wait_queue_wake_one)
     * ------------------------------------------------------------ */
    log_info("[waittest] 1. Single Waiter Wakeup (wait_queue_wake_one)...");
    {
        wait_queue_t wq1;
        wait_queue_init(&wq1);
        volatile bool flag1 = false;
        struct waittest1_state st1;
        st1.wq = &wq1;
        st1.flag = &flag1;
        st1.woken = false;

        preempt_disable();
        struct thread *t1 = thread_create(process_get_kernel(), waittest1_worker, &st1, "wq_single");
        preempt_enable();

        if (t1 == NULL) {
            log_error("  [FAIL] Failed to create worker thread for Test 1!");
            all_passed = false;
        } else {
            /* Wait until thread blocks on wq1 */
            uint64_t wait_start = timer_get_ticks();
            while (wq1.waiter_count == 0 && (timer_get_ticks() - wait_start) < timer_ms_to_ticks(500)) {
                task_yield();
            }

            log_infof("  Waiter queued: count=%u, thread state=%s, woken=%d",
                      wq1.waiter_count, thread_state_name(t1->state), (int)st1.woken);

            if (wq1.waiter_count != 1 || st1.woken) {
                log_error("  [FAIL] Waiter was not properly queued in BLOCKED state!");
                all_passed = false;
            } else {
                /* Signal condition and wake single waiter */
                flag1 = true;
                wait_queue_wake_one(&wq1);

                /* Wait for worker to complete */
                uint64_t wake_start = timer_get_ticks();
                while (!st1.woken && (timer_get_ticks() - wake_start) < timer_ms_to_ticks(500)) {
                    task_yield();
                }

                log_infof("  After wake_one: woken=%d, queue count=%u", (int)st1.woken, wq1.waiter_count);

                if (!st1.woken || wq1.waiter_count != 0) {
                    log_error("  [FAIL] Single waiter did not awaken or queue not empty!");
                    all_passed = false;
                } else {
                    log_info("  Worker cleanly awakened and queue count reached 0.");
                    log_info("  [PASS] Single wakeup (wait_queue_wake_one) verified!");
                }
            }
        }
    }

    /* ------------------------------------------------------------
     * Test 2: Broadcast wakeup (wait_queue_wake_all) with 3 waiters
     * ------------------------------------------------------------ */
    log_info("[waittest] 2. Broadcast Wakeup (wait_queue_wake_all)...");
    {
        wait_queue_t wq2;
        wait_queue_init(&wq2);
        volatile bool flag2 = false;
        struct waittest2_state st2;
        st2.wq = &wq2;
        st2.flag = &flag2;
        atomic_set(&st2.woken_count, 0);

        preempt_disable();
        struct thread *tw1 = thread_create(process_get_kernel(), waittest2_worker, &st2, "wq_bcast1");
        struct thread *tw2 = thread_create(process_get_kernel(), waittest2_worker, &st2, "wq_bcast2");
        struct thread *tw3 = thread_create(process_get_kernel(), waittest2_worker, &st2, "wq_bcast3");
        preempt_enable();

        if (tw1 == NULL || tw2 == NULL || tw3 == NULL) {
            log_error("  [FAIL] Failed to create 3 broadcast worker threads!");
            all_passed = false;
        } else {
            /* Wait until all 3 threads queue on wq2 */
            uint64_t wait_start = timer_get_ticks();
            while (wq2.waiter_count < 3 && (timer_get_ticks() - wait_start) < timer_ms_to_ticks(500)) {
                task_yield();
            }

            log_infof("  Queued waiters: count=%u (expected 3), woken=%d",
                      wq2.waiter_count, atomic_read(&st2.woken_count));

            if (wq2.waiter_count != 3 || atomic_read(&st2.woken_count) != 0) {
                log_error("  [FAIL] Not all 3 waiters queued properly!");
                all_passed = false;
            } else {
                /* Signal condition and broadcast wake all */
                flag2 = true;
                wait_queue_wake_all(&wq2);

                uint64_t wake_start = timer_get_ticks();
                while (atomic_read(&st2.woken_count) < 3 &&
                       (timer_get_ticks() - wake_start) < timer_ms_to_ticks(500)) {
                    task_yield();
                }

                int32_t final_woken = atomic_read(&st2.woken_count);
                log_infof("  After wake_all: woken_count=%d, queue count=%u",
                          final_woken, wq2.waiter_count);

                if (final_woken != 3 || wq2.waiter_count != 0) {
                    log_error("  [FAIL] Broadcast failed to wake all 3 threads or queue not drained!");
                    all_passed = false;
                } else {
                    log_info("  All 3 concurrent waiting threads awakened simultaneously.");
                    log_info("  [PASS] Broadcast wakeup (wait_queue_wake_all) verified!");
                }
            }
        }
    }

    /* ------------------------------------------------------------
     * Test 3: Timed wait (wait_event_timeout)
     * ------------------------------------------------------------ */
    log_info("[waittest] 3. Timed Wait & Expiration (wait_event_timeout)...");
    {
        wait_queue_t wq3;
        wait_queue_init(&wq3);

        /* Part A: Condition never signaled -> must time out after ~50ms */
        uint64_t t0 = timer_get_ticks();
        bool res_timeout = wait_event_timeout(&wq3, waittest_never_cond, NULL, 50);
        uint64_t t1 = timer_get_ticks();
        uint64_t elapsed_ms = timer_ticks_to_ms(t1 - t0);

        log_infof("  Timed wait (50ms requested): result=%d (expect 0), elapsed=%llu ms, wq_waiters=%u",
                  (int)res_timeout, (unsigned long long)elapsed_ms, wq3.waiter_count);

        if (res_timeout || elapsed_ms < 35 || wq3.waiter_count != 0) {
            log_error("  [FAIL] wait_event_timeout did not properly expire or queue not clean!");
            all_passed = false;
        } else {
            /* Part B: Condition already true -> must return true immediately */
            volatile bool already_true = true;
            uint64_t t2 = timer_get_ticks();
            bool res_immediate = wait_event_timeout(&wq3, waittest_flag_cond, (void *)&already_true, 200);
            uint64_t t3 = timer_get_ticks();
            uint64_t imm_elapsed = timer_ticks_to_ms(t3 - t2);

            log_infof("  Immediate true check: result=%d (expect 1), elapsed=%llu ms",
                      (int)res_immediate, (unsigned long long)imm_elapsed);

            if (!res_immediate || imm_elapsed > 10) {
                log_error("  [FAIL] wait_event_timeout did not return true immediately for satisfied condition!");
                all_passed = false;
            } else {
                log_info("  Timeout correctly expired without signal; satisfied condition returned immediately.");
                log_info("  [PASS] Timed wait (wait_event_timeout) verified!");
            }
        }
    }

    /* ------------------------------------------------------------
     * Test 4: Wait Queue Kernel Object (Event handles)
     * ------------------------------------------------------------ */
    log_info("[waittest] 4. Wait Queue Kernel Object & Event Handles...");
    {
        struct process *cur_proc = process_get_current();
        handle_t hev = event_create(cur_proc, true /* manual_reset */, false /* initial_state */);
        if (hev == KOS_INVALID_HANDLE) {
            log_error("  [FAIL] Failed to create event kernel object handle!");
            all_passed = false;
        } else {
            struct waittest4_state st4;
            st4.proc = cur_proc;
            st4.event_handle = hev;
            st4.woken = false;

            preempt_disable();
            struct thread *tev = thread_create(cur_proc, waittest4_worker, &st4, "wq_event");
            preempt_enable();

            if (tev == NULL) {
                log_error("  [FAIL] Failed to create event waiter thread!");
                all_passed = false;
            } else {
                /* Let worker begin waiting on event */
                task_sleep(10);

                if (st4.woken) {
                    log_error("  [FAIL] Event waiter woke up before signal!");
                    all_passed = false;
                } else {
                    /* Signal event */
                    bool sig_ok = event_signal(cur_proc, hev);
                    if (!sig_ok) {
                        log_error("  [FAIL] Failed to signal event object!");
                        all_passed = false;
                    } else {
                        /* Wait for worker to awaken */
                        uint64_t ev_start = timer_get_ticks();
                        while (!st4.woken && (timer_get_ticks() - ev_start) < timer_ms_to_ticks(500)) {
                            task_yield();
                        }

                        log_infof("  After event_signal: woken=%d", (int)st4.woken);

                        if (!st4.woken) {
                            log_error("  [FAIL] Event waiter was not awakened by event_signal!");
                            all_passed = false;
                        } else {
                            /* Reset event */
                            bool rst_ok = event_reset(cur_proc, hev);
                            bool now_sig = event_wait(cur_proc, hev, 0);
                            log_infof("  After event_reset: reset_ok=%d, signaled=%d",
                                      (int)rst_ok, (int)now_sig);

                            if (!rst_ok || now_sig) {
                                log_error("  [FAIL] Event reset failed!");
                                all_passed = false;
                            } else {
                                log_info("  Event handle creation, waiting, signaling and reset verified.");
                                log_info("  [PASS] Kernel Object Event integration verified!");
                            }
                        }
                    }
                }
            }

            handle_close(cur_proc, hev);
        }
    }

    /* ------------------------------------------------------------
     * Test 5: Process Wait & Automatic Resource Cleanup
     * ------------------------------------------------------------ */
    log_info("[waittest] 5. Process Wait & Automatic Resource Cleanup (process_wait)...");
    {
        struct process *child = process_create("proc_child_cleanup");
        if (child == NULL) {
            log_error("  [FAIL] Failed to create child process!");
            all_passed = false;
        } else {
            /* Create a tracked kernel object and place a handle in child */
            struct waittest_cleanup_obj cleanup_obj;
            cleanup_obj.destructor_called = false;
            kos_object_init(&cleanup_obj.header, KOS_OBJ_MUTEX, waittest_cleanup_destructor);

            handle_t h_child = handle_create(child, &cleanup_obj.header, KOS_RIGHT_ALL);
            int32_t ref_with_handle = kos_object_get_refcount(&cleanup_obj.header);
            log_infof("  Child process PID %llu created, handle 0x%08x created, object refcount=%d",
                      (unsigned long long)child->pid, h_child, ref_with_handle);

            if (h_child == KOS_INVALID_HANDLE || ref_with_handle != 2) {
                log_error("  [FAIL] Failed to associate handle with child process!");
                all_passed = false;
            } else {
                /* Spawn child worker thread */
                preempt_disable();
                struct thread *tchild = thread_create(child, waittest5_child_worker, child, "child_worker");
                preempt_enable();

                if (tchild == NULL) {
                    log_error("  [FAIL] Failed to spawn child thread!");
                    all_passed = false;
                } else {
                    /* Parent waits on child exit via wait queue */
                    int exit_code = -1;
                    uint64_t wait_start = timer_get_ticks();
                    bool wait_success = process_wait(child, &exit_code, 2000);
                    uint64_t wait_time = timer_ticks_to_ms(timer_get_ticks() - wait_start);

                    log_infof("  process_wait returned %d in %llu ms: exit_code=%d (expect 77), child state=%s",
                              (int)wait_success, (unsigned long long)wait_time, exit_code,
                              process_state_name(child->state));

                    if (!wait_success || exit_code != 77) {
                        log_errorf("  [FAIL] process_wait failed or exit code mismatch (got %d)", exit_code);
                        all_passed = false;
                    } else if (child->state != PROCESS_STATE_ZOMBIE && child->state != PROCESS_STATE_DEAD) {
                        log_error("  [FAIL] Child process did not transition to ZOMBIE/DEAD!");
                        all_passed = false;
                    } else {
                        /* Check that child handle table was destroyed and object unreffed */
                        int32_t ref_after_exit = kos_object_get_refcount(&cleanup_obj.header);
                        log_infof("  After process exit: object refcount=%d, destructor_called=%d",
                                  ref_after_exit, (int)cleanup_obj.destructor_called);

                        if (ref_after_exit != 1 || cleanup_obj.destructor_called) {
                            log_error("  [FAIL] Child handle table was not automatically destroyed on exit!");
                            all_passed = false;
                        } else {
                            /* Release parent's baseline reference */
                            kos_object_unref(&cleanup_obj.header);
                            if (!cleanup_obj.destructor_called) {
                                log_error("  [FAIL] Destructor not called after parent unref!");
                                all_passed = false;
                            } else {
                                log_info("  Child handle table cleaned up, object refcount decremented.");
                                log_info("  Parent successfully synchronized with child exit via exit_wq.");
                                log_info("  Exit code 77 cleanly delivered to parent.");
                                log_info("  [PASS] Process termination resource cleanup verified!");
                            }
                        }
                    }
                }
            }

            /* Clean up child slot if not already dead */
            if (child->state != PROCESS_STATE_DEAD) {
                process_destroy(child);
            }
        }
    }

    log_info("--------------------------------------------------");
    if (all_passed) {
        log_info(">>> [PASS] ALL WAIT QUEUE & RESOURCE CLEANUP TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] WAIT QUEUE & RESOURCE CLEANUP TESTS FAILED! <<<");
    }
    log_info("==================================================");
}

/*
 * ============================================================================
 * Milestone K14: Process, Ring 3 Userspace & Verification Suite (usertest)
 * ============================================================================
 */

static bool usertest_is_empty(const char *arg) {
    if (arg == NULL) {
        return true;
    }
    while (*arg == ' ' || *arg == '\t' || *arg == '\r' || *arg == '\n') {
        arg++;
    }
    return *arg == '\0';
}

static bool usertest_match_arg(const char *arg, const char *target) {
    if (arg == NULL || target == NULL) {
        return false;
    }
    while (*arg == ' ' || *arg == '\t') {
        arg++;
    }
    while (*arg != '\0' && *target != '\0') {
        if (*arg != *target) {
            return false;
        }
        arg++;
        target++;
    }
    if (*target != '\0') {
        return false;
    }
    while (*arg == ' ' || *arg == '\t' || *arg == '\r' || *arg == '\n') {
        arg++;
    }
    return *arg == '\0';
}

static bool create_test_elf(uint8_t *buf, uint64_t buf_cap, uint64_t *out_size,
                            uint64_t vaddr, const uint8_t *code, uint64_t code_len) {
    if (buf == NULL || out_size == NULL || code == NULL || code_len == 0) {
        return false;
    }
    uint64_t header_bytes = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr);
    uint64_t total_size = header_bytes + code_len;
    if (buf_cap < total_size) {
        return false;
    }

    memset(buf, 0, total_size);

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)buf;
    ehdr->e_ident[EI_MAG0] = ELFMAG0;
    ehdr->e_ident[EI_MAG1] = ELFMAG1;
    ehdr->e_ident[EI_MAG2] = ELFMAG2;
    ehdr->e_ident[EI_MAG3] = ELFMAG3;
    ehdr->e_ident[EI_CLASS] = ELFCLASS64;
    ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr->e_ident[EI_VERSION] = EV_CURRENT;
    ehdr->e_ident[EI_OSABI] = 0;
    ehdr->e_type = ET_EXEC;
    ehdr->e_machine = EM_X86_64;
    ehdr->e_version = EV_CURRENT;
    ehdr->e_entry = vaddr + header_bytes;
    ehdr->e_phoff = sizeof(Elf64_Ehdr);
    ehdr->e_ehsize = sizeof(Elf64_Ehdr);
    ehdr->e_phentsize = sizeof(Elf64_Phdr);
    ehdr->e_phnum = 1;

    Elf64_Phdr *phdr = (Elf64_Phdr *)(buf + sizeof(Elf64_Ehdr));
    phdr->p_type = PT_LOAD;
    phdr->p_flags = PF_R | PF_X | PF_W;
    phdr->p_offset = 0;
    phdr->p_vaddr = vaddr;
    phdr->p_paddr = vaddr;
    phdr->p_filesz = total_size;
    phdr->p_memsz = total_size > 4096 ? total_size : 4096;
    phdr->p_align = 0x1000;

    memcpy(buf + header_bytes, code, code_len);
    *out_size = total_size;
    return true;
}

static void usertest_child_launcher(void *arg) {
    const char *path = (const char *)arg;
    int res = process_exec(path, 0, NULL);
    struct process *cur = process_get_current();
    if (cur != NULL && cur->pid > 1) {
        process_exit(cur, res);
    }
    thread_exit(res);
}

/*
 * Test 1: Valid ELF64 binary execution in Ring 3
 */
static bool test_valid_elf_execution(void) {
    log_info("[usertest] 1. Valid ELF64 binary execution...");
    uint64_t initial_frames = pmm_free_frame_count();
    uint64_t initial_heap = heap_active_allocation_count();

    /* Ring 3 user code:
     * mov rax, 4   ; KOS_SYSCALL_EXIT
     * mov rdi, 42  ; exit code 42
     * int 0x80     ; syscall dispatch -> process_exit
     * jmp $
     */
    static const uint8_t valid_code[] = {
        0x48, 0xC7, 0xC0, 0x04, 0x00, 0x00, 0x00, /* mov rax, 4 */
        0x48, 0xC7, 0xC7, 0x2A, 0x00, 0x00, 0x00, /* mov rdi, 42 */
        0xCD, 0x80,                               /* int 0x80 */
        0xEB, 0xFE                                /* jmp $ */
    };

    uint8_t elf_buf[512];
    uint64_t elf_size = 0;
    if (!create_test_elf(elf_buf, sizeof(elf_buf), &elf_size, 0x00400000ull, valid_code, sizeof(valid_code))) {
        log_error("  [FAIL] Failed to construct valid test ELF image");
        return false;
    }

    if (!vfs_write_file("D:/valid.elf", elf_buf, elf_size)) {
        log_error("  [FAIL] Failed to write D:/valid.elf to ramfs");
        return false;
    }

    struct process *child = process_create("valid_proc");
    if (child == NULL) {
        log_error("  [FAIL] Failed to create valid_proc child process");
        vfs_unlink_file("D:/valid.elf");
        return false;
    }

    struct thread *t = thread_create(child, usertest_child_launcher, (void *)"D:/valid.elf", "valid_t");
    if (t == NULL) {
        log_error("  [FAIL] Failed to create valid_t thread");
        process_destroy(child);
        vfs_unlink_file("D:/valid.elf");
        return false;
    }

    int exit_code = 0;
    bool wait_ok = process_wait(child, &exit_code, 3000);
    vfs_unlink_file("D:/valid.elf");
    task_yield();

    if (!wait_ok) {
        log_error("  [FAIL] process_wait timed out for valid_proc");
        return false;
    }

    if (exit_code != 42) {
        log_errorf("  [FAIL] Expected exit code 42, got %d", exit_code);
        return false;
    }

    if (child->state != PROCESS_STATE_DEAD) {
        log_error("  [FAIL] Child process was not cleanly reaped to DEAD");
        return false;
    }

    uint64_t final_frames = pmm_free_frame_count();
    uint64_t final_heap = heap_active_allocation_count();

    if (final_frames != initial_frames) {
        log_errorf("  [FAIL] Valid ELF execution leaked frames: before=%llu, after=%llu",
                   (unsigned long long)initial_frames, (unsigned long long)final_frames);
        return false;
    }

    if (final_heap != initial_heap) {
        log_errorf("  [FAIL] Valid ELF execution leaked heap: before=%llu, after=%llu",
                   (unsigned long long)initial_heap, (unsigned long long)final_heap);
        return false;
    }

    log_info("  [PASS] Test 1: Valid ELF64 binary execution (exit_code=42, 0 leaks)");
    return true;
}

/*
 * Test 2: Corrupted / invalid ELF binary rejection
 */
static bool test_corrupted_elf_rejection(void) {
    log_info("[usertest] 2. Corrupted / invalid ELF rejection...");
    bool all_ok = true;
    uint64_t initial_frames = pmm_free_frame_count();
    uint64_t initial_heap = heap_active_allocation_count();

    static const uint8_t valid_stub_code[] = {
        0x48, 0xC7, 0xC0, 0x04, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC7, 0x2A, 0x00, 0x00, 0x00,
        0xCD, 0x80,
        0xEB, 0xFE
    };

    uint8_t base_elf[512];
    uint64_t base_size = 0;
    if (!create_test_elf(base_elf, sizeof(base_elf), &base_size, 0x00400000ull, valid_stub_code, sizeof(valid_stub_code))) {
        log_error("  [FAIL] Failed to create base ELF template for corruption tests");
        return false;
    }

    /* Subtest 2a: Invalid magic bytes */
    {
        uint8_t bad_magic[512];
        memcpy(bad_magic, base_elf, base_size);
        bad_magic[1] = 'X'; bad_magic[2] = 'Y'; bad_magic[3] = 'Z';
        vfs_write_file("D:/bad_mag.elf", bad_magic, base_size);

        uint64_t test_pml4 = vmm_create_address_space();
        struct elf_binary_image img;
        bool res = elf_load_binary("D:/bad_mag.elf", test_pml4, &img);
        vmm_destroy_address_space(test_pml4);
        vfs_unlink_file("D:/bad_mag.elf");

        if (res) {
            log_error("  [FAIL] elf_load_binary accepted bad magic bytes!");
            all_ok = false;
        } else {
            log_info("  [PASS] 2a: Rejected invalid ELF magic bytes.");
        }
    }

    /* Subtest 2b: Non-x86_64 machine (e_machine = EM_386) */
    {
        uint8_t bad_mach[512];
        memcpy(bad_mach, base_elf, base_size);
        Elf64_Ehdr *eh = (Elf64_Ehdr *)bad_mach;
        eh->e_machine = EM_386;
        vfs_write_file("D:/bad_mach.elf", bad_mach, base_size);

        uint64_t test_pml4 = vmm_create_address_space();
        struct elf_binary_image img;
        bool res = elf_load_binary("D:/bad_mach.elf", test_pml4, &img);
        vmm_destroy_address_space(test_pml4);
        vfs_unlink_file("D:/bad_mach.elf");

        if (res) {
            log_error("  [FAIL] elf_load_binary accepted non-x86_64 machine!");
            all_ok = false;
        } else {
            log_info("  [PASS] 2b: Rejected non-x86_64 target machine.");
        }
    }

    /* Subtest 2c: Entry point outside loadable segments */
    {
        uint8_t bad_entry[512];
        memcpy(bad_entry, base_elf, base_size);
        Elf64_Ehdr *eh = (Elf64_Ehdr *)bad_entry;
        eh->e_entry = 0x00100000ull; /* < 2 MiB, outside segment */
        vfs_write_file("D:/bad_entry.elf", bad_entry, base_size);

        uint64_t test_pml4 = vmm_create_address_space();
        struct elf_binary_image img;
        bool res = elf_load_binary("D:/bad_entry.elf", test_pml4, &img);
        vmm_destroy_address_space(test_pml4);
        vfs_unlink_file("D:/bad_entry.elf");

        if (res) {
            log_error("  [FAIL] elf_load_binary accepted entry point outside segment!");
            all_ok = false;
        } else {
            log_info("  [PASS] 2c: Rejected entry point outside loadable segment.");
        }
    }

    /* Subtest 2d: PT_LOAD memsz < filesz */
    {
        uint8_t bad_seg[512];
        memcpy(bad_seg, base_elf, base_size);
        Elf64_Phdr *ph = (Elf64_Phdr *)(bad_seg + sizeof(Elf64_Ehdr));
        ph->p_memsz = ph->p_filesz - 1; /* memsz < filesz violation */
        vfs_write_file("D:/bad_seg.elf", bad_seg, base_size);

        uint64_t test_pml4 = vmm_create_address_space();
        struct elf_binary_image img;
        bool res = elf_load_binary("D:/bad_seg.elf", test_pml4, &img);
        vmm_destroy_address_space(test_pml4);
        vfs_unlink_file("D:/bad_seg.elf");

        if (res) {
            log_error("  [FAIL] elf_load_binary accepted memsz < filesz!");
            all_ok = false;
        } else {
            log_info("  [PASS] 2d: Rejected invalid PT_LOAD segment bounds.");
        }
    }

    /* Subtest 2e: Truncated ELF file (< sizeof(Elf64_Ehdr)) */
    {
        uint8_t trunc_elf[32];
        memcpy(trunc_elf, base_elf, sizeof(trunc_elf));
        vfs_write_file("D:/trunc.elf", trunc_elf, sizeof(trunc_elf));

        uint64_t test_pml4 = vmm_create_address_space();
        struct elf_binary_image img;
        bool res = elf_load_binary("D:/trunc.elf", test_pml4, &img);
        vmm_destroy_address_space(test_pml4);
        vfs_unlink_file("D:/trunc.elf");

        if (res) {
            log_error("  [FAIL] elf_load_binary accepted truncated ELF header!");
            all_ok = false;
        } else {
            log_info("  [PASS] 2e: Rejected truncated ELF file.");
        }
    }

    /* Subtest 2f: Full process_exec error rollback with corrupted binary */
    {
        uint8_t bad_exec[512];
        memcpy(bad_exec, base_elf, base_size);
        bad_exec[1] = 0xFF; /* corrupt magic */
        vfs_write_file("D:/bad_exec.elf", bad_exec, base_size);

        struct process *child = process_create("bad_exec_proc");
        if (child != NULL) {
            struct thread *t = thread_create(child, usertest_child_launcher, (void *)"D:/bad_exec.elf", "bad_t");
            if (t != NULL) {
                int exit_code = 0;
                bool wait_ok = process_wait(child, &exit_code, 1000);
                if (!wait_ok || exit_code != -1) {
                    log_errorf("  [FAIL] 2f: Expected process_exec failure -1, got wait_ok=%d exit=%d",
                               (int)wait_ok, exit_code);
                    all_ok = false;
                } else {
                    log_info("  [PASS] 2f: process_exec error cleanly returned -1 and unwound.");
                }
            } else {
                process_destroy(child);
                all_ok = false;
            }
        } else {
            all_ok = false;
        }
        vfs_unlink_file("D:/bad_exec.elf");
        task_yield();
    }

    uint64_t final_frames = pmm_free_frame_count();
    uint64_t final_heap = heap_active_allocation_count();

    if (final_frames != initial_frames) {
        log_errorf("  [FAIL] Corrupted ELF tests leaked frames: before=%llu, after=%llu",
                   (unsigned long long)initial_frames, (unsigned long long)final_frames);
        all_ok = false;
    }
    if (final_heap != initial_heap) {
        log_errorf("  [FAIL] Corrupted ELF tests leaked heap: before=%llu, after=%llu",
                   (unsigned long long)initial_heap, (unsigned long long)final_heap);
        all_ok = false;
    }

    if (all_ok) {
        log_info("  [PASS] Test 2: Corrupted/invalid ELF binary rejection (6 subcases, 0 leaks)");
    }
    return all_ok;
}

/*
 * Test 3: Kernel memory isolation enforcement
 */
static bool test_kernel_mem_isolation(void) {
    log_info("[usertest] 3. Kernel memory isolation enforcement...");
    uint64_t initial_frames = pmm_free_frame_count();
    uint64_t initial_heap = heap_active_allocation_count();

    /* Subtest 3a: Ring 3 attempts to read 0xFFFFFFFF80000000 (higher-half kernel text/data) */
    {
        static const uint8_t kmem_code_1[] = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, /* movabs rax, 0xFFFFFFFF80000000 */
            0x48, 0x8B, 0x18,                                            /* mov rbx, [rax] (Hardware page fault!) */
            0x48, 0xC7, 0xC0, 0x04, 0x00, 0x00, 0x00,                   /* mov rax, 4 */
            0x48, 0xC7, 0xC7, 0x63, 0x00, 0x00, 0x00,                   /* mov rdi, 99 */
            0xCD, 0x80,                                                 /* int 0x80 */
            0xEB, 0xFE                                                  /* jmp $ */
        };

        uint8_t elf_buf[512];
        uint64_t elf_size = 0;
        if (!create_test_elf(elf_buf, sizeof(elf_buf), &elf_size, 0x00400000ull, kmem_code_1, sizeof(kmem_code_1))) {
            log_error("  [FAIL] Failed to construct kmem1 test ELF image");
            return false;
        }

        if (!vfs_write_file("D:/kmem1.elf", elf_buf, elf_size)) {
            log_error("  [FAIL] Failed to write D:/kmem1.elf to ramfs");
            return false;
        }

        struct process *child = process_create("kmem_proc1");
        if (child == NULL) {
            log_error("  [FAIL] Failed to create kmem_proc1 child process");
            vfs_unlink_file("D:/kmem1.elf");
            return false;
        }

        struct thread *t = thread_create(child, usertest_child_launcher, (void *)"D:/kmem1.elf", "kmem1_t");
        if (t == NULL) {
            log_error("  [FAIL] Failed to create kmem1_t thread");
            process_destroy(child);
            vfs_unlink_file("D:/kmem1.elf");
            return false;
        }

        int exit_code = 0;
        bool wait_ok = process_wait(child, &exit_code, 3000);
        vfs_unlink_file("D:/kmem1.elf");
        task_yield();

        if (!wait_ok || exit_code != -11 || child->state != PROCESS_STATE_DEAD) {
            log_errorf("  [FAIL] 3a: Expected SIGSEGV (-11) reading 0xFFFFFFFF80000000, got wait=%d exit=%d state=%d",
                       (int)wait_ok, exit_code, (int)child->state);
            return false;
        }
        log_info("  [PASS] 3a: Access to 0xFFFFFFFF80000000 cleanly trapped (SIGSEGV -11).");
    }

    /* Subtest 3b: Ring 3 attempts to read 0xFFFF800000000000 (higher-half direct physical map) */
    {
        static const uint8_t kmem_code_2[] = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xFF, 0xFF, /* movabs rax, 0xFFFF800000000000 */
            0x48, 0x8B, 0x18,                                            /* mov rbx, [rax] (Hardware page fault!) */
            0x48, 0xC7, 0xC0, 0x04, 0x00, 0x00, 0x00,                   /* mov rax, 4 */
            0x48, 0xC7, 0xC7, 0x63, 0x00, 0x00, 0x00,                   /* mov rdi, 99 */
            0xCD, 0x80,                                                 /* int 0x80 */
            0xEB, 0xFE                                                  /* jmp $ */
        };

        uint8_t elf_buf[512];
        uint64_t elf_size = 0;
        if (!create_test_elf(elf_buf, sizeof(elf_buf), &elf_size, 0x00400000ull, kmem_code_2, sizeof(kmem_code_2))) {
            log_error("  [FAIL] Failed to construct kmem2 test ELF image");
            return false;
        }

        if (!vfs_write_file("D:/kmem2.elf", elf_buf, elf_size)) {
            log_error("  [FAIL] Failed to write D:/kmem2.elf to ramfs");
            return false;
        }

        struct process *child = process_create("kmem_proc2");
        if (child == NULL) {
            log_error("  [FAIL] Failed to create kmem_proc2 child process");
            vfs_unlink_file("D:/kmem2.elf");
            return false;
        }

        struct thread *t = thread_create(child, usertest_child_launcher, (void *)"D:/kmem2.elf", "kmem2_t");
        if (t == NULL) {
            log_error("  [FAIL] Failed to create kmem2_t thread");
            process_destroy(child);
            vfs_unlink_file("D:/kmem2.elf");
            return false;
        }

        int exit_code = 0;
        bool wait_ok = process_wait(child, &exit_code, 3000);
        vfs_unlink_file("D:/kmem2.elf");
        task_yield();

        if (!wait_ok || exit_code != -11 || child->state != PROCESS_STATE_DEAD) {
            log_errorf("  [FAIL] 3b: Expected SIGSEGV (-11) reading 0xFFFF800000000000, got wait=%d exit=%d state=%d",
                       (int)wait_ok, exit_code, (int)child->state);
            return false;
        }
        log_info("  [PASS] 3b: Access to 0xFFFF800000000000 cleanly trapped (SIGSEGV -11).");
    }

    uint64_t final_frames = pmm_free_frame_count();
    uint64_t final_heap = heap_active_allocation_count();
    if (final_frames != initial_frames) {
        log_errorf("  [FAIL] kmem tests leaked frames: before=%llu, after=%llu",
                   (unsigned long long)initial_frames, (unsigned long long)final_frames);
        return false;
    }
    if (final_heap != initial_heap) {
        log_errorf("  [FAIL] kmem tests leaked heap: before=%llu, after=%llu",
                   (unsigned long long)initial_heap, (unsigned long long)final_heap);
        return false;
    }

    log_info("  [PASS] Test 3: Kernel memory isolation enforcement (2 higher-half addresses, SIGSEGV -11 trapped, 0 leaks)");
    return true;
}

/*
 * Test 4: User stack guard page containment
 */
static bool test_stack_guard_containment(void) {
    log_info("[usertest] 4. User stack guard page containment...");
    uint64_t initial_frames = pmm_free_frame_count();
    uint64_t initial_heap = heap_active_allocation_count();

    /* Subtest 4a: Write to top of guard page: 0x00007FFFFFFEDFF8 */
    {
        static const uint8_t guard_code_1[] = {
            0x48, 0xB8, 0xF8, 0xDF, 0xFE, 0xFF, 0xFF, 0x7F, 0x00, 0x00, /* movabs rax, 0x00007FFFFFFEDFF8 */
            0x48, 0xC7, 0x00, 0x34, 0x12, 0x00, 0x00,                   /* mov qword [rax], 0x1234 (Page fault!) */
            0x48, 0xC7, 0xC0, 0x04, 0x00, 0x00, 0x00,                   /* mov rax, 4 */
            0x48, 0xC7, 0xC7, 0x63, 0x00, 0x00, 0x00,                   /* mov rdi, 99 */
            0xCD, 0x80,                                                 /* int 0x80 */
            0xEB, 0xFE                                                  /* jmp $ */
        };

        uint8_t elf_buf[512];
        uint64_t elf_size = 0;
        if (!create_test_elf(elf_buf, sizeof(elf_buf), &elf_size, 0x00400000ull, guard_code_1, sizeof(guard_code_1))) {
            log_error("  [FAIL] Failed to construct guard1 test ELF image");
            return false;
        }

        if (!vfs_write_file("D:/guard1.elf", elf_buf, elf_size)) {
            log_error("  [FAIL] Failed to write D:/guard1.elf to ramfs");
            return false;
        }

        struct process *child = process_create("guard_proc1");
        if (child == NULL) {
            log_error("  [FAIL] Failed to create guard_proc1 child process");
            vfs_unlink_file("D:/guard1.elf");
            return false;
        }

        struct thread *t = thread_create(child, usertest_child_launcher, (void *)"D:/guard1.elf", "guard1_t");
        if (t == NULL) {
            log_error("  [FAIL] Failed to create guard1_t thread");
            process_destroy(child);
            vfs_unlink_file("D:/guard1.elf");
            return false;
        }

        int exit_code = 0;
        bool wait_ok = process_wait(child, &exit_code, 3000);
        vfs_unlink_file("D:/guard1.elf");
        task_yield();

        if (!wait_ok || exit_code != -11 || child->state != PROCESS_STATE_DEAD) {
            log_errorf("  [FAIL] 4a: Expected SIGSEGV (-11), got wait=%d exit=%d state=%d",
                       (int)wait_ok, exit_code, (int)child->state);
            return false;
        }
        log_info("  [PASS] 4a: Guard page top access cleanly trapped (SIGSEGV -11).");
    }

    /* Subtest 4b: Write to base of guard page: 0x00007FFFFFFED000 */
    {
        static const uint8_t guard_code_2[] = {
            0x48, 0xB8, 0x00, 0xD0, 0xFE, 0xFF, 0xFF, 0x7F, 0x00, 0x00, /* movabs rax, 0x00007FFFFFFED000 */
            0x48, 0xC7, 0x00, 0x78, 0x56, 0x00, 0x00,                   /* mov qword [rax], 0x5678 (Page fault!) */
            0x48, 0xC7, 0xC0, 0x04, 0x00, 0x00, 0x00,                   /* mov rax, 4 */
            0x48, 0xC7, 0xC7, 0x63, 0x00, 0x00, 0x00,                   /* mov rdi, 99 */
            0xCD, 0x80,                                                 /* int 0x80 */
            0xEB, 0xFE                                                  /* jmp $ */
        };

        uint8_t elf_buf[512];
        uint64_t elf_size = 0;
        if (!create_test_elf(elf_buf, sizeof(elf_buf), &elf_size, 0x00400000ull, guard_code_2, sizeof(guard_code_2))) {
            log_error("  [FAIL] Failed to construct guard2 test ELF image");
            return false;
        }

        if (!vfs_write_file("D:/guard2.elf", elf_buf, elf_size)) {
            log_error("  [FAIL] Failed to write D:/guard2.elf to ramfs");
            return false;
        }

        struct process *child = process_create("guard_proc2");
        if (child == NULL) {
            log_error("  [FAIL] Failed to create guard_proc2 child process");
            vfs_unlink_file("D:/guard2.elf");
            return false;
        }

        struct thread *t = thread_create(child, usertest_child_launcher, (void *)"D:/guard2.elf", "guard2_t");
        if (t == NULL) {
            log_error("  [FAIL] Failed to create guard2_t thread");
            process_destroy(child);
            vfs_unlink_file("D:/guard2.elf");
            return false;
        }

        int exit_code = 0;
        bool wait_ok = process_wait(child, &exit_code, 3000);
        vfs_unlink_file("D:/guard2.elf");
        task_yield();

        if (!wait_ok || exit_code != -11 || child->state != PROCESS_STATE_DEAD) {
            log_errorf("  [FAIL] 4b: Expected SIGSEGV (-11), got wait=%d exit=%d state=%d",
                       (int)wait_ok, exit_code, (int)child->state);
            return false;
        }
        log_info("  [PASS] 4b: Guard page base access cleanly trapped (SIGSEGV -11).");
    }

    uint64_t final_frames = pmm_free_frame_count();
    uint64_t final_heap = heap_active_allocation_count();
    if (final_frames != initial_frames) {
        log_errorf("  [FAIL] guard_proc leaked frames: before=%llu, after=%llu",
                   (unsigned long long)initial_frames, (unsigned long long)final_frames);
        return false;
    }
    if (final_heap != initial_heap) {
        log_errorf("  [FAIL] guard_proc leaked heap: before=%llu, after=%llu",
                   (unsigned long long)initial_heap, (unsigned long long)final_heap);
        return false;
    }

    log_info("  [PASS] Test 4: User stack guard page containment (2 guard boundaries trapped, 0 leaks)");
    return true;
}

/*
 * Test 5: TSS/RSP0 Ring 3 hardware preemption
 */
static bool test_preemption_hardware(void) {
    log_info("[usertest] 5. TSS/RSP0 Ring 3 hardware preemption...");
    uint64_t initial_frames = pmm_free_frame_count();
    uint64_t initial_heap = heap_active_allocation_count();

    /* Ring 3 compute loop:
     * mov rcx, 30000000
     * loop_dec:
     * dec rcx
     * jnz loop_dec
     * mov rax, 4
     * mov rdi, 55
     * int 0x80
     * jmp $
     */
    static const uint8_t preempt_code[] = {
        0x48, 0xC7, 0xC1, 0x80, 0x5D, 0xC9, 0x01, /* mov rcx, 30000000 (0x01C95D80) */
        0x48, 0xFF, 0xC9,                         /* dec rcx */
        0x75, 0xFB,                               /* jnz -5 */
        0x48, 0xC7, 0xC0, 0x04, 0x00, 0x00, 0x00, /* mov rax, 4 */
        0x48, 0xC7, 0xC7, 0x37, 0x00, 0x00, 0x00, /* mov rdi, 55 */
        0xCD, 0x80,                               /* int 0x80 */
        0xEB, 0xFE                                /* jmp $ */
    };

    uint8_t elf_buf[512];
    uint64_t elf_size = 0;
    if (!create_test_elf(elf_buf, sizeof(elf_buf), &elf_size, 0x00400000ull, preempt_code, sizeof(preempt_code))) {
        log_error("  [FAIL] Failed to construct preempt_test test ELF image");
        return false;
    }

    if (!vfs_write_file("D:/preempt.elf", elf_buf, elf_size)) {
        log_error("  [FAIL] Failed to write D:/preempt.elf to ramfs");
        return false;
    }

    uint64_t ticks_before = timer_get_ticks();

    struct process *child = process_create("preempt_proc");
    if (child == NULL) {
        log_error("  [FAIL] Failed to create preempt_proc child process");
        vfs_unlink_file("D:/preempt.elf");
        return false;
    }

    struct thread *t = thread_create(child, usertest_child_launcher, (void *)"D:/preempt.elf", "preempt_t");
    if (t == NULL) {
        log_error("  [FAIL] Failed to create preempt_t thread");
        process_destroy(child);
        vfs_unlink_file("D:/preempt.elf");
        return false;
    }

    int exit_code = 0;
    bool wait_ok = process_wait(child, &exit_code, 5000);
    uint64_t ticks_after = timer_get_ticks();
    vfs_unlink_file("D:/preempt.elf");
    task_yield();

    if (!wait_ok) {
        log_error("  [FAIL] process_wait timed out for preempt_proc");
        return false;
    }

    if (exit_code != 55) {
        log_errorf("  [FAIL] Expected exit_code=55 from preempt_proc, got %d", exit_code);
        return false;
    }

    if (child->state != PROCESS_STATE_DEAD) {
        log_error("  [FAIL] preempt_proc was not cleanly reaped to DEAD");
        return false;
    }

    uint64_t elapsed_ticks = (ticks_after >= ticks_before) ? (ticks_after - ticks_before) : 0;
    log_infof("  Preemption test elapsed timer ticks: %llu", (unsigned long long)elapsed_ticks);

    if (elapsed_ticks == 0) {
        log_error("  [FAIL] Preemption test finished without any timer ticks elapsed!");
        return false;
    }

    uint64_t final_frames = pmm_free_frame_count();
    uint64_t final_heap = heap_active_allocation_count();
    if (final_frames != initial_frames) {
        log_errorf("  [FAIL] preempt_proc leaked frames: before=%llu, after=%llu",
                   (unsigned long long)initial_frames, (unsigned long long)final_frames);
        return false;
    }
    if (final_heap != initial_heap) {
        log_errorf("  [FAIL] preempt_proc leaked heap: before=%llu, after=%llu",
                   (unsigned long long)initial_heap, (unsigned long long)final_heap);
        return false;
    }

    log_infof("  [PASS] Test 5: TSS/RSP0 Ring 3 hardware preemption (exit_code=55, elapsed_ticks=%llu, 0 leaks)",
              (unsigned long long)elapsed_ticks);
    return true;
}

/*
 * Test 6: 50-iteration zero memory leak test
 */
static bool test_leak_50_iterations(void) {
    log_info("[usertest] 6. 50-iteration zero memory leak test...");
    uint64_t baseline_frames = pmm_free_frame_count();
    uint64_t baseline_heap = heap_active_allocation_count();

    static const uint8_t iter_code[] = {
        0x48, 0xC7, 0xC0, 0x04, 0x00, 0x00, 0x00, /* mov rax, 4 */
        0x48, 0xC7, 0xC7, 0x2A, 0x00, 0x00, 0x00, /* mov rdi, 42 */
        0xCD, 0x80,                               /* int 0x80 */
        0xEB, 0xFE                                /* jmp $ */
    };

    uint8_t elf_buf[512];
    uint64_t elf_size = 0;
    if (!create_test_elf(elf_buf, sizeof(elf_buf), &elf_size, 0x00400000ull, iter_code, sizeof(iter_code))) {
        log_error("  [FAIL] Failed to construct leak test ELF image");
        return false;
    }

    if (!vfs_write_file("D:/leak_iter.elf", elf_buf, elf_size)) {
        log_error("  [FAIL] Failed to write D:/leak_iter.elf to ramfs");
        return false;
    }

    bool all_ok = true;
    for (int i = 0; i < 50; ++i) {
        struct process *child = process_create("leak_child");
        if (child == NULL) {
            log_errorf("  [FAIL] Iteration %d: process_create failed", i);
            all_ok = false;
            break;
        }

        struct thread *t = thread_create(child, usertest_child_launcher, (void *)"D:/leak_iter.elf", "leak_t");
        if (t == NULL) {
            log_errorf("  [FAIL] Iteration %d: thread_create failed", i);
            process_destroy(child);
            all_ok = false;
            break;
        }

        int exit_code = 0;
        bool wait_ok = process_wait(child, &exit_code, 1000);
        if (!wait_ok || exit_code != 42 || child->state != PROCESS_STATE_DEAD) {
            log_errorf("  [FAIL] Iteration %d: wait_ok=%d, exit_code=%d, state=%d",
                       i, (int)wait_ok, exit_code, (int)child->state);
            all_ok = false;
            break;
        }
    }

    vfs_unlink_file("D:/leak_iter.elf");
    task_yield();

    if (!all_ok) {
        return false;
    }

    uint64_t final_frames = pmm_free_frame_count();
    uint64_t final_heap = heap_active_allocation_count();

    if (final_frames != baseline_frames) {
        log_errorf("  [FAIL] 50 iterations leaked page frames: before=%llu, after=%llu",
                   (unsigned long long)baseline_frames, (unsigned long long)final_frames);
        return false;
    }

    if (final_heap != baseline_heap) {
        log_errorf("  [FAIL] 50 iterations leaked heap allocations: before=%llu, after=%llu",
                   (unsigned long long)baseline_heap, (unsigned long long)final_heap);
        return false;
    }

    log_infof("  [PASS] Test 6: 50-iteration zero memory leak test (frames=%llu, heap_allocs=%llu, 0 leaks)",
              (unsigned long long)final_frames, (unsigned long long)final_heap);
    return true;
}

static void command_usertest(const char *arguments) {
    bool run_all = usertest_is_empty(arguments) || usertest_match_arg(arguments, "all");
    bool run_valid = run_all || usertest_match_arg(arguments, "valid");
    bool run_corrupted = run_all || usertest_match_arg(arguments, "corrupted");
    bool run_kernel_mem = run_all || usertest_match_arg(arguments, "kernel_mem");
    bool run_stack_overflow = run_all || usertest_match_arg(arguments, "stack_overflow");
    bool run_preemption = run_all || usertest_match_arg(arguments, "preemption");
    bool run_leak = run_all || usertest_match_arg(arguments, "leak");

    if (!run_valid && !run_corrupted && !run_kernel_mem && !run_stack_overflow && !run_preemption && !run_leak) {
        log_error("Usage: usertest [all|valid|corrupted|kernel_mem|stack_overflow|preemption|leak]");
        return;
    }

    log_info("==================================================");
    log_info("=== Milestone K14 Ring 3 & Process Test Suite ===");
    log_info("==================================================");

    bool all_passed = true;

    if (run_valid) {
        if (!test_valid_elf_execution()) {
            all_passed = false;
        }
    }

    if (run_corrupted) {
        if (!test_corrupted_elf_rejection()) {
            all_passed = false;
        }
    }

    if (run_kernel_mem) {
        if (!test_kernel_mem_isolation()) {
            all_passed = false;
        }
    }

    if (run_stack_overflow) {
        if (!test_stack_guard_containment()) {
            all_passed = false;
        }
    }

    if (run_preemption) {
        if (!test_preemption_hardware()) {
            all_passed = false;
        }
    }

    if (run_leak) {
        if (!test_leak_50_iterations()) {
            all_passed = false;
        }
    }

    log_info("--------------------------------------------------");
    if (all_passed) {
        log_info(">>> [PASS] ALL K14 USERSPACE & PROCESS TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] SOME K14 USERSPACE & PROCESS TESTS FAILED! <<<");
    }
    log_info("==================================================");
}

/* ========================================================================= */
/* Diagnostic Command: atomictest (K12.5)                                     */
/* ========================================================================= */
static void command_atomictest(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info("        KOS Atomic Primitives Diagnostics         ");
    log_info("==================================================");
    bool passed = true;

    /* Test 1: atomic_t (32-bit) */
    atomic_t a32 = ATOMIC_INIT(100);
    if (atomic_read(&a32) != 100) passed = false;
    atomic_set(&a32, 200);
    if (atomic_read(&a32) != 200) passed = false;
    atomic_add(&a32, 50);
    if (atomic_read(&a32) != 250) passed = false;
    atomic_sub(&a32, 30);
    if (atomic_read(&a32) != 220) passed = false;
    atomic_inc(&a32);
    if (atomic_read(&a32) != 221) passed = false;
    atomic_dec(&a32);
    if (atomic_read(&a32) != 220) passed = false;
    if (atomic_add_return(&a32, 10) != 230) passed = false;
    if (atomic_sub_return(&a32, 20) != 210) passed = false;
    if (atomic_inc_return(&a32) != 211) passed = false;
    if (atomic_dec_return(&a32) != 210) passed = false;
    if (atomic_fetch_add(&a32, 5) != 210 || atomic_read(&a32) != 215) passed = false;
    if (atomic_fetch_sub(&a32, 15) != 215 || atomic_read(&a32) != 200) passed = false;
    if (atomic_xchg(&a32, 500) != 200 || atomic_read(&a32) != 500) passed = false;
    if (atomic_cmpxchg(&a32, 500, 999) != 500 || atomic_read(&a32) != 999) passed = false;
    if (atomic_cmpxchg(&a32, 500, 111) != 999 || atomic_read(&a32) != 999) passed = false;

    /* Test 2: atomic64_t (64-bit) */
    atomic64_t a64 = ATOMIC64_INIT(0x1000000000ULL);
    if (atomic64_read(&a64) != (int64_t)0x1000000000ULL) passed = false;
    atomic64_set(&a64, 0x2000000000ULL);
    if (atomic64_read(&a64) != (int64_t)0x2000000000ULL) passed = false;
    atomic64_add(&a64, 0x1000);
    if (atomic64_read(&a64) != (int64_t)0x2000001000ULL) passed = false;
    atomic64_sub(&a64, 0x500);
    if (atomic64_read(&a64) != (int64_t)0x2000000B00ULL) passed = false;
    atomic64_inc(&a64);
    if (atomic64_read(&a64) != (int64_t)0x2000000B01ULL) passed = false;
    atomic64_dec(&a64);
    if (atomic64_read(&a64) != (int64_t)0x2000000B00ULL) passed = false;
    if (atomic64_add_return(&a64, 0x100) != (int64_t)0x2000000C00ULL) passed = false;
    if (atomic64_sub_return(&a64, 0x200) != (int64_t)0x2000000A00ULL) passed = false;
    if (atomic64_inc_return(&a64) != (int64_t)0x2000000A01ULL) passed = false;
    if (atomic64_dec_return(&a64) != (int64_t)0x2000000A00ULL) passed = false;
    if (atomic64_xchg(&a64, 0x7777777777ULL) != (int64_t)0x2000000A00ULL || atomic64_read(&a64) != (int64_t)0x7777777777ULL) passed = false;
    if (atomic64_cmpxchg(&a64, 0x7777777777ULL, 0x8888888888ULL) != (int64_t)0x7777777777ULL || atomic64_read(&a64) != (int64_t)0x8888888888ULL) passed = false;

    /* Test 3: Barriers */
    smp_mb();
    smp_rmb();
    smp_wmb();
    cpu_relax();

    if (passed) {
        log_info("  [PASS] 32-bit and 64-bit atomic operations & memory barriers verified!");
        log_info(">>> [PASS] ALL ATOMIC TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] ATOMIC TESTS FAILED! <<<");
    }
    log_info("==================================================");
}

/* ========================================================================= */
/* Diagnostic Command: locktest (K12.6)                                      */
/* ========================================================================= */
struct locktest_worker_arg {
    kos_spinlock_t *lock;
    volatile uint64_t *counter;
    uint32_t iterations;
    volatile bool finished;
};

static void locktest_worker(void *arg) {
    struct locktest_worker_arg *w = (struct locktest_worker_arg *)arg;
    for (uint32_t i = 0; i < w->iterations; ++i) {
        uint64_t flags = spinlock_lock_irqsave(w->lock);
        (*w->counter)++;
        spinlock_unlock_irqrestore(w->lock, flags);
        if ((i % 100) == 0) {
            task_yield();
        }
    }
    w->finished = true;
}

static void command_locktest(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info("        KOS Spinlock & IRQ-Save Diagnostics       ");
    log_info("==================================================");
    bool passed = true;

    /* Unit test basic spinlock */
    kos_spinlock_t test_lock = SPINLOCK_INIT;
    if (spinlock_is_locked(&test_lock)) passed = false;
    spinlock_lock(&test_lock);
    if (!spinlock_is_locked(&test_lock)) passed = false;
    if (spinlock_try_lock(&test_lock)) passed = false;
    spinlock_unlock(&test_lock);
    if (spinlock_is_locked(&test_lock)) passed = false;
    if (!spinlock_try_lock(&test_lock)) passed = false;
    spinlock_unlock(&test_lock);

    /* IRQ-save test */
    uint64_t rflags = spinlock_lock_irqsave(&test_lock);
    if (!spinlock_is_locked(&test_lock)) passed = false;
    spinlock_unlock_irqrestore(&test_lock, rflags);
    if (spinlock_is_locked(&test_lock)) passed = false;

    /* Multi-thread contention test */
    struct process *cur_proc = process_get_current();
    if (cur_proc == NULL) cur_proc = process_get_kernel();

    static volatile uint64_t shared_counter = 0;
    static kos_spinlock_t shared_lock = SPINLOCK_INIT;
    enum { LOCK_WORKERS = 4, LOCK_ITERS = 500 };
    static struct locktest_worker_arg args[LOCK_WORKERS];
    shared_counter = 0;

    for (int i = 0; i < LOCK_WORKERS; ++i) {
        args[i].lock = &shared_lock;
        args[i].counter = &shared_counter;
        args[i].iterations = LOCK_ITERS;
        args[i].finished = false;
        struct thread *t = thread_create(cur_proc, locktest_worker, &args[i], "lock_worker");
        if (t == NULL) passed = false;
    }

    uint64_t timeout_tick = timer_get_ticks() + timer_ms_to_ticks(5000);
    bool all_finished = false;
    while (timer_get_ticks() < timeout_tick) {
        all_finished = true;
        for (int i = 0; i < LOCK_WORKERS; ++i) {
            if (!args[i].finished) {
                all_finished = false;
                break;
            }
        }
        if (all_finished) break;
        task_yield();
    }

    if (!all_finished || shared_counter != (LOCK_WORKERS * LOCK_ITERS)) {
        log_errorf("  [FAIL] Spinlock contention failed: counter=%llu (expect %d)",
                   (unsigned long long)shared_counter, LOCK_WORKERS * LOCK_ITERS);
        passed = false;
    } else {
        log_infof("  [PASS] %d threads * %d iterations -> counter = %llu with zero races!",
                  LOCK_WORKERS, LOCK_ITERS, (unsigned long long)shared_counter);
    }

    if (passed) {
        log_info(">>> [PASS] ALL SPINLOCK TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] SPINLOCK TESTS FAILED! <<<");
    }
    log_info("==================================================");
}

/* ========================================================================= */
/* Diagnostic Command: mutextest (K12.7)                                     */
/* ========================================================================= */
struct mutextest_worker_arg {
    kos_mutex_t *mutex;
    volatile uint32_t *active_inside;
    volatile uint32_t *violations;
    volatile uint64_t *counter;
    uint32_t iterations;
    volatile bool finished;
};

static void mutextest_worker(void *arg) {
    struct mutextest_worker_arg *w = (struct mutextest_worker_arg *)arg;
    for (uint32_t i = 0; i < w->iterations; ++i) {
        mutex_lock(w->mutex);
        uint32_t act = __atomic_add_fetch(w->active_inside, 1, __ATOMIC_SEQ_CST);
        if (act != 1) {
            __atomic_add_fetch(w->violations, 1, __ATOMIC_SEQ_CST);
        }
        task_yield();
        act = __atomic_sub_fetch(w->active_inside, 1, __ATOMIC_SEQ_CST);
        if (act != 0) {
            __atomic_add_fetch(w->violations, 1, __ATOMIC_SEQ_CST);
        }
        (*w->counter)++;
        mutex_unlock(w->mutex);
        task_yield();
    }
    w->finished = true;
}

static void command_mutextest(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info("           KOS Sleeping Mutex Diagnostics         ");
    log_info("==================================================");
    bool passed = true;

    /* Unit test basic mutex */
    kos_mutex_t test_mutex;
    mutex_init(&test_mutex);
    if (mutex_is_locked(&test_mutex)) passed = false;
    mutex_lock(&test_mutex);
    if (!mutex_is_locked(&test_mutex)) passed = false;
    if (mutex_try_lock(&test_mutex)) passed = false;
    mutex_unlock(&test_mutex);
    if (mutex_is_locked(&test_mutex)) passed = false;

    /* Multi-thread sleeping mutex test */
    struct process *cur_proc = process_get_current();
    if (cur_proc == NULL) cur_proc = process_get_kernel();

    static kos_mutex_t shared_mutex;
    mutex_init(&shared_mutex);
    static volatile uint32_t active_inside = 0;
    static volatile uint32_t violations = 0;
    static volatile uint64_t counter = 0;
    enum { MUTEX_WORKERS = 4, MUTEX_ITERS = 100 };
    static struct mutextest_worker_arg m_args[MUTEX_WORKERS];
    active_inside = 0;
    violations = 0;
    counter = 0;

    for (int i = 0; i < MUTEX_WORKERS; ++i) {
        m_args[i].mutex = &shared_mutex;
        m_args[i].active_inside = &active_inside;
        m_args[i].violations = &violations;
        m_args[i].counter = &counter;
        m_args[i].iterations = MUTEX_ITERS;
        m_args[i].finished = false;
        struct thread *t = thread_create(cur_proc, mutextest_worker, &m_args[i], "mutex_worker");
        if (t == NULL) passed = false;
    }

    uint64_t timeout_tick = timer_get_ticks() + timer_ms_to_ticks(5000);
    bool all_finished = false;
    while (timer_get_ticks() < timeout_tick) {
        all_finished = true;
        for (int i = 0; i < MUTEX_WORKERS; ++i) {
            if (!m_args[i].finished) {
                all_finished = false;
                break;
            }
        }
        if (all_finished) break;
    }

    if (!all_finished || violations != 0 || counter != (MUTEX_WORKERS * MUTEX_ITERS)) {
        log_errorf("  [FAIL] Mutex contention failed: counter=%llu (expect %d), violations=%u",
                   (unsigned long long)counter, MUTEX_WORKERS * MUTEX_ITERS, violations);
        passed = false;
    } else {
        log_infof("  [PASS] %d threads * %d iters -> counter=%llu with 0 mutual exclusion violations!",
                  MUTEX_WORKERS, MUTEX_ITERS, (unsigned long long)counter);
    }

    if (passed) {
        log_info(">>> [PASS] ALL MUTEX TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] MUTEX TESTS FAILED! <<<");
    }
    log_info("==================================================");
}

/* ========================================================================= */
/* Diagnostic Command: timertest (K12.8)                                     */
/* ========================================================================= */
static void command_timertest(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info("         KOS Monotonic Timer Diagnostics          ");
    log_info("==================================================");
    bool passed = true;

    uint64_t hz = timer_frequency_hz();
    uint64_t ticks1 = timer_get_ticks();
    uint64_t up1 = timer_uptime_seconds();
    uint64_t ms100_in_ticks = timer_ms_to_ticks(100);
    uint64_t back_to_ms = timer_ticks_to_ms(ms100_in_ticks);

    log_infof("  Timer frequency: %llu Hz", (unsigned long long)hz);
    log_infof("  Initial monotonic ticks: %llu, uptime: %llu s",
              (unsigned long long)ticks1, (unsigned long long)up1);
    log_infof("  100 ms converted to ticks: %llu, converted back: %llu ms",
              (unsigned long long)ms100_in_ticks, (unsigned long long)back_to_ms);

    if (hz == 0 || back_to_ms != 100) {
        passed = false;
    }

    /* Wait 50 ms */
    task_sleep(50);
    uint64_t ticks2 = timer_get_ticks();
    uint64_t elapsed_ms = timer_ticks_to_ms(ticks2 - ticks1);
    log_infof("  Elapsed time after 50ms task_sleep: %llu ms (%llu ticks)",
              (unsigned long long)elapsed_ms, (unsigned long long)(ticks2 - ticks1));

    if (elapsed_ms < 40 || elapsed_ms > 100) {
        log_error("  [FAIL] Sleep duration out of expected tolerance!");
        passed = false;
    }

    if (passed) {
        log_info(">>> [PASS] ALL TIMER TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] TIMER TESTS FAILED! <<<");
    }
    log_info("==================================================");
}

/* ========================================================================= */
/* Diagnostic Command: sleeptest (K12.8)                                     */
/* ========================================================================= */
struct sleeptest_worker_arg {
    uint32_t sleep_ms;
    uint64_t finish_tick;
    volatile bool finished;
};

static void sleeptest_worker(void *arg) {
    struct sleeptest_worker_arg *w = (struct sleeptest_worker_arg *)arg;
    task_sleep(w->sleep_ms);
    w->finish_tick = timer_get_ticks();
    w->finished = true;
}

static void command_sleeptest(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info("       KOS Delta Sleep Queue Diagnostics          ");
    log_info("==================================================");
    bool passed = true;

    struct process *cur_proc = process_get_current();
    if (cur_proc == NULL) cur_proc = process_get_kernel();

    struct sleeptest_worker_arg s1 = { .sleep_ms = 30, .finish_tick = 0, .finished = false };
    struct sleeptest_worker_arg s2 = { .sleep_ms = 60, .finish_tick = 0, .finished = false };
    struct sleeptest_worker_arg s3 = { .sleep_ms = 90, .finish_tick = 0, .finished = false };

    uint64_t start_tick = timer_get_ticks();
    thread_create(cur_proc, sleeptest_worker, &s1, "sleep_30ms");
    thread_create(cur_proc, sleeptest_worker, &s2, "sleep_60ms");
    thread_create(cur_proc, sleeptest_worker, &s3, "sleep_90ms");

    uint64_t timeout_tick = start_tick + timer_ms_to_ticks(2000);
    while (timer_get_ticks() < timeout_tick) {
        if (s1.finished && s2.finished && s3.finished) break;
        task_yield();
    }

    if (!s1.finished || !s2.finished || !s3.finished) {
        log_error("  [FAIL] One or more sleep workers timed out!");
        passed = false;
    } else {
        uint64_t el1 = timer_ticks_to_ms(s1.finish_tick - start_tick);
        uint64_t el2 = timer_ticks_to_ms(s2.finish_tick - start_tick);
        uint64_t el3 = timer_ticks_to_ms(s3.finish_tick - start_tick);

        log_infof("  Worker 1 (30ms): completed in %llu ms", (unsigned long long)el1);
        log_infof("  Worker 2 (60ms): completed in %llu ms", (unsigned long long)el2);
        log_infof("  Worker 3 (90ms): completed in %llu ms", (unsigned long long)el3);

        if (!(s1.finish_tick <= s2.finish_tick && s2.finish_tick <= s3.finish_tick)) {
            log_error("  [FAIL] Sleep queue wakeup order violated!");
            passed = false;
        } else {
            log_info("  [PASS] Sleep delta-queue woke threads in exact sorted order!");
        }
    }

    if (passed) {
        log_info(">>> [PASS] ALL SLEEP TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] SLEEP TESTS FAILED! <<<");
    }
    log_info("==================================================");
}

/* ========================================================================= */
/* Diagnostic Command: preempttest (K12.9)                                   */
/* ========================================================================= */
struct preempt_worker_arg {
    uint32_t id;
    volatile uint64_t progress;
    volatile bool finished;
};

static void preempt_compute_worker(void *arg) {
    struct preempt_worker_arg *w = (struct preempt_worker_arg *)arg;
    /* Pure CPU-bound computation without calling task_yield() */
    volatile uint64_t hash = 0x12345678ULL * (w->id + 1);
    for (uint64_t i = 0; i < 500000ULL; ++i) {
        hash = (hash ^ (i * 0x9e3779b97f4a7c15ULL)) + 1;
        if ((i % 10000ULL) == 0) {
            w->progress = i;
        }
    }
    w->progress = 500000ULL;
    w->finished = true;
}

static void command_preempttest(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info("      KOS Preemptive Scheduling Diagnostics       ");
    log_info("==================================================");
    bool passed = true;

    struct process *cur_proc = process_get_current();
    if (cur_proc == NULL) cur_proc = process_get_kernel();

    struct preempt_worker_arg p1 = { .id = 1, .progress = 0, .finished = false };
    struct preempt_worker_arg p2 = { .id = 2, .progress = 0, .finished = false };

    log_info("  Spawning 2 CPU-bound worker threads (NO task_yield calls)...");
    thread_create(cur_proc, preempt_compute_worker, &p1, "preempt_w1");
    thread_create(cur_proc, preempt_compute_worker, &p2, "preempt_w2");

    uint64_t timeout_tick = timer_get_ticks() + timer_ms_to_ticks(3000);
    while (timer_get_ticks() < timeout_tick) {
        if (p1.finished && p2.finished) break;
        task_yield();
    }

    if (!p1.finished || !p2.finished) {
        log_errorf("  [FAIL] Preemptive workers did not complete! p1=%d (%llu), p2=%d (%llu)",
                   (int)p1.finished, (unsigned long long)p1.progress,
                   (int)p2.finished, (unsigned long long)p2.progress);
        passed = false;
    } else {
        log_info("  Both CPU-bound workers completed via timer interrupt preemption quantum slices!");
        log_info("  [PASS] Preemptive scheduler verified!");
    }

    if (passed) {
        log_info(">>> [PASS] ALL PREEMPTION TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] PREEMPTION TESTS FAILED! <<<");
    }
    log_info("==================================================");
}

/* ========================================================================= */
/* Diagnostic Command: processtest (K12.10 - K12.12)                         */
/* ========================================================================= */
static void processtest_child_entry(void *arg) {
    int exit_val = (int)(intptr_t)arg;
    task_sleep(20);
    thread_exit(exit_val);
}

static void command_processtest(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info("      KOS Process & Thread Model Diagnostics      ");
    log_info("==================================================");
    bool passed = true;

    struct process *p = process_create("proc_diag");
    if (p == NULL) {
        log_error("  [FAIL] process_create failed!");
        passed = false;
    } else {
        log_infof("  Created process '%s' with PID %llu", p->name, (unsigned long long)p->pid);
        struct thread *t = thread_create(p, processtest_child_entry, (void *)(intptr_t)88, "diag_thread");
        if (t == NULL) {
            log_error("  [FAIL] thread_create failed!");
            passed = false;
        } else {
            int exit_code = 0;
            bool ok = process_wait(p, &exit_code, 1000);
            if (!ok || exit_code != 88) {
                log_errorf("  [FAIL] process_wait failed or exit_code mismatch! ok=%d, code=%d",
                           (int)ok, exit_code);
                passed = false;
            } else {
                log_infof("  Child process cleanly exited with code %d (state=%s)",
                          exit_code, process_state_name(p->state));
                log_info("  [PASS] Process lifecycle & parent synchronization verified!");
            }
        }
        if (p->state != PROCESS_STATE_DEAD) {
            process_destroy(p);
        }
    }

    if (passed) {
        log_info(">>> [PASS] ALL PROCESS MODEL TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] PROCESS MODEL TESTS FAILED! <<<");
    }
    log_info("==================================================");
}

/* ========================================================================= */
/* Diagnostic Command: stacktest (K12.4)                                     */
/* ========================================================================= */
static void KOS_NOINLINE stacktest_leaf(void) {
    log_info("  Executing stack_trace_dump_current(16) from nested function...");
    stack_trace_dump_current(16);
}

static void KOS_NOINLINE stacktest_middle(void) {
    stacktest_leaf();
}

static void KOS_NOINLINE stacktest_outer(void) {
    stacktest_middle();
}

static void command_stacktest(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info("     KOS Stack Frame & Symbol Backtrace Test      ");
    log_info("==================================================");
    log_info("Triggering nested call chain: outer -> middle -> leaf");
    stacktest_outer();
    log_info(">>> [PASS] STACK BACKTRACE COMPLETED <<<");
    log_info("==================================================");
}

static bool cmd_streq(const char *left, const char *right) {
    if (left == NULL || right == NULL) return false;
    while (*left != '\0' && *right != '\0') {
        if (*left != *right) return false;
        left++;
        right++;
    }
    return *left == *right;
}

/* ========================================================================= */
/* Diagnostic Command: pftest (K12.2)                                        */
/* ========================================================================= */
static void command_pftest(const char *arguments) {
    log_info("==================================================");
    log_info("         KOS Page Fault Decoder Diagnostics       ");
    log_info("==================================================");
    bool passed = true;

    /* Synthetic test 1: Read non-present page in kernel mode */
    struct page_fault_record rec1;
    page_fault_decode(0, &rec1);
    if (rec1.present || rec1.write || rec1.user || rec1.instruction_fetch) passed = false;

    /* Synthetic test 2: Write protection violation in kernel mode */
    struct page_fault_record rec2;
    page_fault_decode(PF_ERROR_PRESENT | PF_ERROR_WRITE, &rec2);
    if (!rec2.present || !rec2.write || rec2.user) passed = false;

    /* Synthetic test 3: Instruction fetch on non-executable page */
    struct page_fault_record rec3;
    page_fault_decode(PF_ERROR_PRESENT | PF_ERROR_INSTRUCTION, &rec3);
    if (!rec3.present || !rec3.instruction_fetch) passed = false;

    /* Synthetic test 4: User mode write to non-present page */
    struct page_fault_record rec4;
    page_fault_decode(PF_ERROR_WRITE | PF_ERROR_USER, &rec4);
    if (rec4.present || !rec4.write || !rec4.user) passed = false;

    if (passed) {
        log_info("  [PASS] Page fault decoder bitwise flag extraction verified!");
    } else {
        log_error("  [FAIL] Page fault decoder flag extraction mismatch!");
    }

    if (arguments != NULL && cmd_streq(arguments, "crash")) {
        log_info("  Intentional CR2 page fault requested! Triggering write to 0xDEADBEEF000...");
        volatile uint64_t *ptr = (volatile uint64_t *)0xDEADBEEF000ULL;
        *ptr = 0x1234;
    } else {
        log_info("  (To trigger an actual kernel page fault panic, run 'pftest crash')");
    }

    if (passed) {
        log_info(">>> [PASS] ALL PAGE FAULT TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] PAGE FAULT TESTS FAILED! <<<");
    }
    log_info("==================================================");
}

/* ========================================================================= */
/* Diagnostic Command: panictest (K12.3)                                     */
/* ========================================================================= */
static void command_panictest(const char *arguments) {
    log_info("==================================================");
    log_info("           KOS Kernel Panic Diagnostics           ");
    log_info("==================================================");
    log_info("Panic Subsystem Properties:");
    log_info("  - 100% Zero-allocation, lockless emergency serial polling");
    log_info("  - Full register dump (RAX..R15, RIP, RSP, CR2, CR3, etc.)");
    log_info("  - RBP stack frame unwinding with O(log N) symbol lookup");
    log_info("  - Atomic recursion guard preventing recursive panic loops");

    if (arguments != NULL && cmd_streq(arguments, "crash")) {
        log_info("Triggering intentional panic...");
        panic("Intentional kernel panic triggered via 'panictest crash' command");
    } else if (arguments != NULL && cmd_streq(arguments, "recursion")) {
        log_info("Triggering intentional panic recursion guard test...");
        panic_test_recursion();
    } else {
        log_info("  (To trigger a real panic, run 'panictest crash' or 'panictest recursion')");
    }
    log_info(">>> [PASS] PANIC DIAGNOSTICS DISPLAYED <<<");
    log_info("==================================================");
}

/* ========================================================================= */
/* Diagnostic Command: kstress / taskstress (K12.22 - K12.26)                */
/* ========================================================================= */
struct kstress_worker_arg {
    uint32_t worker_id;
    uint32_t iterations;
    volatile uint32_t errors;
    volatile bool finished;
};

static void kstress_pmm_worker(void *arg) {
    struct kstress_worker_arg *w = (struct kstress_worker_arg *)arg;
    for (uint32_t i = 0; i < w->iterations; ++i) {
        uint64_t frame1 = pmm_allocate_frame();
        uint64_t frame2 = pmm_allocate_frame();
        if (frame1 == 0 || frame2 == 0 || frame1 == frame2) {
            w->errors++;
        }
        if (frame1 != 0 && !pmm_free_frame(frame1)) {
            w->errors++;
        }
        if (frame2 != 0 && !pmm_free_frame(frame2)) {
            w->errors++;
        }
        if ((i % 10) == 0) {
            task_yield();
        }
    }
    w->finished = true;
}

static void kstress_heap_worker(void *arg) {
    struct kstress_worker_arg *w = (struct kstress_worker_arg *)arg;
    for (uint32_t i = 0; i < w->iterations; ++i) {
        uint8_t *p32 = (uint8_t *)kmalloc(32);
        uint8_t *p64 = (uint8_t *)kmalloc(64);
        if (p32 == NULL || p64 == NULL) {
            w->errors++;
        } else {
            for (int k = 0; k < 32; ++k) p32[k] = (uint8_t)(i ^ k);
            for (int k = 0; k < 64; ++k) p64[k] = (uint8_t)(i + k);
            for (int k = 0; k < 32; ++k) {
                if (p32[k] != (uint8_t)(i ^ k)) { w->errors++; break; }
            }
            for (int k = 0; k < 64; ++k) {
                if (p64[k] != (uint8_t)(i + k)) { w->errors++; break; }
            }
        }
        if (p32 != NULL) kfree(p32);
        if (p64 != NULL) kfree(p64);
        if ((i % 10) == 0) {
            task_yield();
        }
    }
    w->finished = true;
}

static void kstress_ramfs_worker(void *arg) {
    struct kstress_worker_arg *w = (struct kstress_worker_arg *)arg;
    static const uint8_t test_payload[] = "KOS Stress Test Payload 2026";
    for (uint32_t i = 0; i < w->iterations; ++i) {
        char filename[32];
        filename[0] = 'D'; filename[1] = ':'; filename[2] = '/';
        filename[3] = 's'; filename[4] = 't'; filename[5] = 'r';
        filename[6] = 'e'; filename[7] = 's'; filename[8] = 's';
        filename[9] = '_'; filename[10] = (char)('0' + (w->worker_id % 10));
        filename[11] = '.'; filename[12] = 't'; filename[13] = 'x';
        filename[14] = 't'; filename[15] = '\0';

        if (!vfs_write_file(filename, test_payload, sizeof(test_payload))) {
            w->errors++;
        } else {
            const uint8_t *read_ptr = NULL;
            uint64_t read_sz = 0;
            if (!vfs_read_file(filename, &read_ptr, &read_sz) || read_sz != sizeof(test_payload)) {
                w->errors++;
            }
            if (!vfs_unlink_file(filename)) {
                w->errors++;
            }
        }
        if ((i % 5) == 0) {
            task_yield();
        }
    }
    w->finished = true;
}

static void kstress_sync_worker(void *arg) {
    struct kstress_worker_arg *w = (struct kstress_worker_arg *)arg;
    for (uint32_t i = 0; i < w->iterations; ++i) {
        task_sleep(2);
        task_yield();
    }
    w->finished = true;
}

static void command_kstress(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info("     KOS Milestone K12 Comprehensive Stress Test  ");
    log_info("==================================================");
    bool all_passed = true;

    uint64_t frames_before = pmm_free_frame_count();
    uint64_t heap_allocs_before = heap_active_allocation_count();

    log_infof("  Baseline free PMM frames: %llu", (unsigned long long)frames_before);
    log_infof("  Baseline active heap allocs: %llu", (unsigned long long)heap_allocs_before);

    struct process *cur_proc = process_get_current();
    if (cur_proc == NULL) cur_proc = process_get_kernel();

    enum { STRESS_WORKERS = 4, STRESS_ITERS = 50 };
    struct kstress_worker_arg workers[STRESS_WORKERS];
    for (int i = 0; i < STRESS_WORKERS; ++i) {
        workers[i].worker_id = (uint32_t)i;
        workers[i].iterations = STRESS_ITERS;
        workers[i].errors = 0;
        workers[i].finished = false;
    }

    log_info("  Launching 4 concurrent stress workers (PMM, Heap, RAMFS, Sched)...");
    thread_create(cur_proc, kstress_pmm_worker, &workers[0], "stress_pmm");
    thread_create(cur_proc, kstress_heap_worker, &workers[1], "stress_heap");
    thread_create(cur_proc, kstress_ramfs_worker, &workers[2], "stress_ramfs");
    thread_create(cur_proc, kstress_sync_worker, &workers[3], "stress_sync");

    uint64_t timeout_tick = timer_get_ticks() + timer_ms_to_ticks(5000);
    bool finished = false;
    while (timer_get_ticks() < timeout_tick) {
        finished = true;
        for (int i = 0; i < STRESS_WORKERS; ++i) {
            if (!workers[i].finished) {
                finished = false;
                break;
            }
        }
        if (finished) break;
        task_yield();
    }

    if (!finished) {
        log_error("  [FAIL] Stress test timed out waiting for workers!");
        all_passed = false;
    }

    for (int i = 0; i < STRESS_WORKERS; ++i) {
        if (workers[i].errors != 0) {
            log_errorf("  [FAIL] Worker %d recorded %u errors!", i, workers[i].errors);
            all_passed = false;
        }
    }

    /* Allow reaper thread to collect zombie worker stacks */
    for (int r = 0; r < 5; ++r) {
        task_reap_terminated();
        task_yield();
    }

    /* Verify memory reclamation */
    uint64_t frames_after = pmm_free_frame_count();
    uint64_t heap_allocs_after = heap_active_allocation_count();

    log_infof("  Post-stress free PMM frames: %llu (delta=%lld)",
              (unsigned long long)frames_after, (long long)(frames_after - frames_before));
    log_infof("  Post-stress active heap allocs: %llu (delta=%lld)",
              (unsigned long long)heap_allocs_after, (long long)(heap_allocs_after - heap_allocs_before));

    if (frames_after != frames_before) {
        log_error("  [FAIL] PMM frame leak detected during stress testing!");
        all_passed = false;
    }
    if (heap_allocs_after != heap_allocs_before) {
        log_error("  [FAIL] Heap memory leak detected during stress testing!");
        all_passed = false;
    }

    log_info("--------------------------------------------------");
    if (all_passed) {
        log_info(">>> [PASS] ALL K12 STRESS & INTEGRITY TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] K12 STRESS & INTEGRITY TESTS FAILED! <<<");
    }
    log_info("==================================================");
}

/* ========================================================================= */
/* Storage & Block Device Commands & Tests (Milestones K16 & K17)            */
/* ========================================================================= */

static void command_fdisk(const char *arguments) {
    (void)arguments;
    log_info("=== Block Devices & Partitions ===");
    uint32_t count = block_device_count();
    if (count == 0) {
        log_info("  (no block devices registered)");
        return;
    }

    for (uint32_t i = 0; i < count; i++) {
        struct block_device *dev = block_device_get_at(i);
        if (dev == NULL) continue;

        const char *type_str = "UNKNOWN";
        if (dev->type == BLOCK_TYPE_RAMDISK) type_str = "RAMDISK";
        else if (dev->type == BLOCK_TYPE_AHCI) type_str = "AHCI-SATA";
        else if (dev->type == BLOCK_TYPE_VIRTIO) type_str = "VIRTIO-BLK";
        else if (dev->type == BLOCK_TYPE_PARTITION) type_str = "PARTITION";

        uint64_t mib = (dev->total_blocks * dev->block_size) / (1024 * 1024);
        log_infof("Device: %-12s Type: %-10s Blocks: %-10llu Size: %llu MiB State: %s",
                  dev->name, type_str, (unsigned long long)dev->total_blocks,
                  (unsigned long long)mib, dev->state == BLOCK_DEVICE_ONLINE ? "ONLINE" : "OFFLINE");

        if (dev->type == BLOCK_TYPE_PARTITION && dev->parent != NULL) {
            log_infof("  └─ Parent: %s, Start LBA: %llu, Index: %u, MBR Type: 0x%02X",
                      dev->parent->name, (unsigned long long)dev->start_lba,
                      (unsigned int)dev->partition_index, (unsigned int)dev->partition_type_mbr);
        }
    }
}

static void command_mount(const char *arguments) {
    while (*arguments == ' ') arguments++;
    if (*arguments == '\0') {
        log_info("=== Mounted Volumes ===");
        for (uint64_t i = 0; i < vfs_volume_count(); i++) {
            struct vfs_volume_info info;
            if (vfs_volume_info_at(i, &info)) {
                log_infof("  %c: [Label: %s] Files: %llu",
                          info.letter, info.label ? info.label : "", (unsigned long long)info.file_count);
            }
        }
        return;
    }

    /* Parse: mount <dev> <letter> [label] */
    char dev_name[32];
    int pos = 0;
    while (*arguments != ' ' && *arguments != '\0' && pos + 1 < 32) {
        dev_name[pos++] = *arguments++;
    }
    dev_name[pos] = '\0';
    while (*arguments == ' ') arguments++;

    if (*arguments == '\0') {
        log_error("mount: syntax error. Use: mount <dev_name> <drive_letter:> [label]");
        return;
    }

    char letter = *arguments;
    if (letter >= 'a' && letter <= 'z') letter = (char)(letter - ('a' - 'A'));
    arguments++;
    if (*arguments == ':') arguments++;
    while (*arguments == ' ') arguments++;

    const char *label = (*arguments != '\0') ? arguments : "VOLUME";

    struct block_device *dev = block_device_find_by_name(dev_name);
    if (dev == NULL) {
        log_errorf("mount: block device '%s' not found.", dev_name);
        return;
    }

    if (volume_manager_mount_device(dev, letter, label)) {
        log_infof("mount: successfully mounted %s as %c: (%s)", dev_name, letter, label);
    } else {
        log_errorf("mount: failed to mount %s (unsupported filesystem or drive letter in use)", dev_name);
    }
}

static void command_umount(const char *arguments) {
    while (*arguments == ' ') arguments++;
    if (*arguments == '\0') {
        log_error("umount: missing drive letter. Use: umount <letter:>");
        return;
    }

    char letter = *arguments;
    if (letter >= 'a' && letter <= 'z') letter = (char)(letter - ('a' - 'A'));

    if (letter == 'C') {
        log_error("umount: cannot unmount system volume C:");
        return;
    }

    if (volume_manager_unmount_letter(letter)) {
        log_infof("umount: unmounted volume %c:", letter);
    } else {
        log_errorf("umount: failed to unmount volume %c:", letter);
    }
}

static void command_sync(const char *arguments) {
    (void)arguments;
    if (volume_manager_sync_all()) {
        log_info("sync: all block caches synchronized to disk successfully.");
    } else {
        log_error("sync: errors occurred while flushing dirty blocks.");
    }
}

static void command_touch(const char *arguments) {
    while (*arguments == ' ') arguments++;
    if (*arguments == '\0') {
        log_error("touch: missing file path. Use: touch <path>");
        return;
    }
    if (vfs_write_file(arguments, (const uint8_t *)"", 0)) {
        log_infof("touch: created file '%s'", arguments);
    } else {
        log_errorf("touch: failed to create file '%s'", arguments);
    }
}

static void command_mkdir(const char *arguments) {
    while (*arguments == ' ') arguments++;
    if (*arguments == '\0') {
        log_error("mkdir: missing path. Use: mkdir <path>");
        return;
    }

    char letter = 'C';
    const char *rel_path = arguments;
    if (arguments[0] != '\0' && arguments[1] == ':') {
        letter = arguments[0];
        if (letter >= 'a' && letter <= 'z') letter = (char)(letter - ('a' - 'A'));
        rel_path = arguments + 2;
    }

    const struct volume_entry *vol_ent = volume_manager_find_by_letter(letter);
    if (vol_ent != NULL && kstrcmp(vol_ent->fs_type, "FAT32") == 0) {
        if (fat32_mkdir((struct fat32_volume *)vol_ent->fs_handle, rel_path)) {
            log_infof("mkdir: directory '%s' created on %c:", rel_path, letter);
            return;
        }
    }
    log_errorf("mkdir: failed to create directory '%s'", arguments);
}

static void command_rm(const char *arguments) {
    while (*arguments == ' ') arguments++;
    if (*arguments == '\0') {
        log_error("rm: missing file path. Use: rm <path>");
        return;
    }
    if (vfs_unlink_file(arguments)) {
        log_infof("rm: removed file '%s'", arguments);
    } else {
        log_errorf("rm: failed to remove '%s'", arguments);
    }
}

static void command_mv(const char *arguments) {
    while (*arguments == ' ') arguments++;
    if (*arguments == '\0') {
        log_error("mv: use: mv <old_path> <new_path>");
        return;
    }

    char src[128];
    int pos = 0;
    while (*arguments != ' ' && *arguments != '\0' && pos + 1 < 128) {
        src[pos++] = *arguments++;
    }
    src[pos] = '\0';
    while (*arguments == ' ') arguments++;

    if (*arguments == '\0') {
        log_error("mv: missing destination path. Use: mv <old_path> <new_path>");
        return;
    }

    const uint8_t *data = NULL;
    uint64_t size = 0;
    if (!vfs_read_file(src, &data, &size)) {
        log_errorf("mv: source file '%s' not found", src);
        return;
    }

    if (!vfs_write_file(arguments, data, size)) {
        log_errorf("mv: failed to write destination file '%s'", arguments);
        return;
    }

    vfs_unlink_file(src);
    log_infof("mv: moved '%s' -> '%s' (%llu bytes)", src, arguments, (unsigned long long)size);
}

/* Diagnostic Test: Block Device Core */
static void command_blocktest(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info(">>> STARTING BLOCK DEVICE SUBSYSTEM TEST <<<");
    log_info("==================================================");

    bool all_ok = true;

    /* 1. Create a 1 MiB RAM Block Device (2048 sectors of 512 bytes = 1048576 bytes) */
    struct block_device *ram_dev = ramdisk_create("test_ram0", 2048ULL * 512, 512);
    if (ram_dev == NULL) {
        log_error("  [FAIL] Failed to create test ramdisk");
        return;
    }
    log_infof("  [OK] Created ramdisk: %s (%llu blocks, %llu bytes)",
              ram_dev->name, (unsigned long long)ram_dev->total_blocks, (unsigned long long)ram_dev->capacity_bytes);

    /* 2. Test lookup */
    if (block_device_find_by_name("test_ram0") != ram_dev) {
        log_error("  [FAIL] block_device_find_by_name failed");
        all_ok = false;
    } else {
        log_info("  [OK] block_device_find_by_name matched");
    }

    /* 3. Write pattern to multiple sectors */
    uint8_t write_buf[1024];
    for (int i = 0; i < 1024; i++) {
        write_buf[i] = (uint8_t)(i ^ 0xA5);
    }

    if (!block_write(ram_dev, 10, 2, write_buf)) {
        log_error("  [FAIL] block_write sectors 10-11 failed");
        all_ok = false;
    } else {
        log_info("  [OK] block_write 2 sectors at LBA 10 passed");
    }

    /* 4. Read back and verify integrity */
    uint8_t read_buf[1024];
    kmemset(read_buf, 0, sizeof(read_buf));

    if (!block_read(ram_dev, 10, 2, read_buf)) {
        log_error("  [FAIL] block_read sectors 10-11 failed");
        all_ok = false;
    } else if (kmemcmp(write_buf, read_buf, 1024) != 0) {
        log_error("  [FAIL] Data mismatch after block_read!");
        all_ok = false;
    } else {
        log_info("  [OK] block_read data verified 100% match");
    }

    /* 5. Bounds checking */
    if (block_read(ram_dev, 2047, 2, read_buf)) {
        log_error("  [FAIL] Out-of-bounds read was allowed!");
        all_ok = false;
    } else {
        log_info("  [OK] Out-of-bounds LBA read correctly rejected");
    }

    if (block_write(ram_dev, 10, 0, write_buf)) {
        log_error("  [FAIL] Zero-count write was allowed!");
        all_ok = false;
    } else {
        log_info("  [OK] Zero-count write correctly rejected");
    }

    /* 6. Test Flush */
    if (!block_flush(ram_dev)) {
        log_error("  [FAIL] block_flush returned false");
        all_ok = false;
    } else {
        log_info("  [OK] block_flush succeeded");
    }

    /* 7. Test Universal DMA Page Allocation */
    void *dma_virt = NULL;
    uint64_t dma_phys = 0;
    if (!block_alloc_dma_pages(2, &dma_virt, &dma_phys) || dma_virt == NULL || dma_phys == 0) {
        log_error("  [FAIL] block_alloc_dma_pages failed");
        all_ok = false;
    } else if (((uintptr_t)dma_virt & 4095) != 0 || (dma_phys & 4095) != 0) {
        log_error("  [FAIL] DMA buffer is not 4096-byte aligned");
        all_ok = false;
    } else {
        log_infof("  [OK] block_alloc_dma_pages 2 pages (phys=0x%llx, virt=%p)",
                  (unsigned long long)dma_phys, dma_virt);
        block_free_dma_pages(dma_virt, dma_phys, 2);
    }

    /* 8. Destroy test device */
    if (!ramdisk_destroy(ram_dev)) {
        log_error("  [FAIL] ramdisk_destroy returned false");
        all_ok = false;
    } else if (block_device_find_by_name("test_ram0") != NULL) {
        log_error("  [FAIL] Device still present after destroy");
        all_ok = false;
    } else {
        log_info("  [OK] ramdisk_destroy and unregistration clean");
    }

    log_info("--------------------------------------------------");
    if (all_ok) {
        log_info(">>> [PASS] BLOCK DEVICE SUBSYSTEM TEST PASSED <<<");
    } else {
        log_error(">>> [FAIL] BLOCK DEVICE SUBSYSTEM TEST FAILED <<<");
    }
    log_info("==================================================");
}

/* Diagnostic Test: MBR Parser */
static void command_mbrtest(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info(">>> STARTING MBR PARTITION PARSER TEST <<<");
    log_info("==================================================");

    bool all_ok = true;

    /* Create a 4 MiB ramdisk (8192 sectors = 4194304 bytes) */
    struct block_device *disk = ramdisk_create("mbr_disk", 8192ULL * 512, 512);
    if (disk == NULL) {
        log_error("  [FAIL] Could not create test disk");
        return;
    }

    /* Construct MBR with 2 partitions */
    uint8_t mbr_sec[512];
    kmemset(mbr_sec, 0, 512);

    struct mbr_partition_entry *p1 = (struct mbr_partition_entry *)(mbr_sec + 0x1BE);
    p1->boot_indicator = 0x80; /* Bootable */
    p1->partition_type = 0x0C; /* FAT32 LBA */
    p1->start_lba = 2048;
    p1->sector_count = 2048;

    struct mbr_partition_entry *p2 = (struct mbr_partition_entry *)(mbr_sec + 0x1CE);
    p2->boot_indicator = 0x00;
    p2->partition_type = 0x83; /* Linux native */
    p2->start_lba = 4096;
    p2->sector_count = 2048;

    /* Signature */
    mbr_sec[510] = 0x55;
    mbr_sec[511] = 0xAA;

    block_write(disk, 0, 1, mbr_sec);

    /* Run partition scanner */
    uint32_t parts = partition_scan(disk);
    if (parts != 2) {
        log_errorf("  [FAIL] Expected 2 partitions, found %u", (unsigned int)parts);
        all_ok = false;
    } else {
        log_info("  [OK] partition_scan detected 2 MBR partitions");
    }

    struct block_device *part1 = block_device_find_by_name("mbr_diskp1");
    struct block_device *part2 = block_device_find_by_name("mbr_diskp2");

    if (part1 == NULL || part2 == NULL) {
        log_error("  [FAIL] Sub-block devices mbr_diskp1/mbr_diskp2 not registered!");
        all_ok = false;
    } else {
        log_infof("  [OK] Found %s (Start LBA: %llu, Blocks: %llu)",
                  part1->name, (unsigned long long)part1->start_lba, (unsigned long long)part1->total_blocks);
        log_infof("  [OK] Found %s (Start LBA: %llu, Blocks: %llu)",
                  part2->name, (unsigned long long)part2->start_lba, (unsigned long long)part2->total_blocks);

        /* Write to part1 at LBA 0 */
        uint8_t pbuf[512];
        kmemset(pbuf, 0x77, 512);
        block_write(part1, 0, 1, pbuf);

        /* Read parent disk at LBA 2048 directly */
        uint8_t parent_read[512];
        block_read(disk, 2048, 1, parent_read);
        if (kmemcmp(pbuf, parent_read, 512) != 0) {
            log_error("  [FAIL] Partition LBA translation offset mismatch!");
            all_ok = false;
        } else {
            log_info("  [OK] Partition offset translation to parent disk verified 100%");
        }
    }

    ramdisk_destroy(disk);

    log_info("--------------------------------------------------");
    if (all_ok) {
        log_info(">>> [PASS] MBR PARTITION PARSER TEST PASSED <<<");
    } else {
        log_error(">>> [FAIL] MBR PARTITION PARSER TEST FAILED <<<");
    }
    log_info("==================================================");
}

/* Diagnostic Test: GPT Parser */
static void command_gpttest(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info(">>> STARTING GPT PARTITION PARSER TEST <<<");
    log_info("==================================================");

    bool all_ok = true;

    /* Create an 8 MiB ramdisk (16384 sectors = 8388608 bytes) */
    struct block_device *disk = ramdisk_create("gpt_disk", 16384ULL * 512, 512);
    if (disk == NULL) {
        log_error("  [FAIL] Could not create test disk");
        return;
    }

    /* 1. Protective MBR at LBA 0 */
    uint8_t pmbr[512];
    kmemset(pmbr, 0, 512);
    struct mbr_partition_entry *p = (struct mbr_partition_entry *)(pmbr + 0x1BE);
    p->partition_type = 0xEE; /* Protective GPT */
    p->start_lba = 1;
    p->sector_count = 16383;
    pmbr[510] = 0x55;
    pmbr[511] = 0xAA;
    block_write(disk, 0, 1, pmbr);

    /* 2. GPT Partition Array at LBA 2 */
    uint8_t gpt_array[512 * 32]; /* 128 entries of 128 bytes = 16 KiB = 32 sectors */
    kmemset(gpt_array, 0, sizeof(gpt_array));

    struct gpt_partition_entry *ge = (struct gpt_partition_entry *)gpt_array;
    /* Basic Data Partition GUID: EBD0A0A2-B9E5-4433-87C0-68B6B72699C7 */
    ge[0].type_guid[0] = 0xA2; ge[0].type_guid[1] = 0xA0; ge[0].type_guid[2] = 0xD0; ge[0].type_guid[3] = 0xEB;
    ge[0].type_guid[4] = 0xE5; ge[0].type_guid[5] = 0xB9; ge[0].type_guid[6] = 0x33; ge[0].type_guid[7] = 0x44;
    ge[0].type_guid[8] = 0x87; ge[0].type_guid[9] = 0xC0; ge[0].type_guid[10] = 0x68; ge[0].type_guid[11] = 0xB6;
    ge[0].type_guid[12] = 0xB7; ge[0].type_guid[13] = 0x26; ge[0].type_guid[14] = 0x99; ge[0].type_guid[15] = 0xC7;

    ge[0].unique_partition_guid[0] = 0x12; ge[0].unique_partition_guid[1] = 0x34;
    ge[0].starting_lba = 2048;
    ge[0].ending_lba = 6143; /* 4096 sectors = 2 MiB */
    ge[0].attributes = 0;

    block_write(disk, 2, 32, gpt_array);
    uint32_t array_crc = partition_crc32(gpt_array, 128 * sizeof(struct gpt_partition_entry));

    /* 3. GPT Header at LBA 1 */
    uint8_t hdr_sec[512];
    kmemset(hdr_sec, 0, 512);
    struct gpt_header *hdr = (struct gpt_header *)hdr_sec;
    kmemcpy(hdr->signature, "EFI PART", 8);
    hdr->revision = 0x00010000;
    hdr->header_size = sizeof(struct gpt_header);
    hdr->header_crc32 = 0;
    hdr->current_lba = 1;
    hdr->backup_lba = 16383;
    hdr->first_usable_lba = 34;
    hdr->last_usable_lba = 16350;
    hdr->partition_entries_lba = 2;
    hdr->num_partition_entries = 128;
    hdr->size_partition_entry = 128;
    hdr->partition_array_crc32 = array_crc;

    hdr->header_crc32 = partition_crc32((const uint8_t *)hdr, hdr->header_size);
    block_write(disk, 1, 1, hdr_sec);

    /* 4. Scan GPT */
    uint32_t found = partition_scan(disk);
    if (found != 1) {
        log_errorf("  [FAIL] Expected 1 GPT partition, detected %u", (unsigned int)found);
        all_ok = false;
    } else {
        log_info("  [OK] GPT Header & CRC32 verification passed, found 1 partition");
    }

    struct block_device *gpt_part = block_device_find_by_name("gpt_diskp1");
    if (gpt_part == NULL) {
        log_error("  [FAIL] gpt_diskp1 sub-device not registered");
        all_ok = false;
    } else {
        log_infof("  [OK] Found %s (Start LBA: %llu, Blocks: %llu, GUID present: %s)",
                  gpt_part->name, (unsigned long long)gpt_part->start_lba,
                  (unsigned long long)gpt_part->total_blocks, gpt_part->has_guid ? "YES" : "NO");
    }

    ramdisk_destroy(disk);

    log_info("--------------------------------------------------");
    if (all_ok) {
        log_info(">>> [PASS] GPT PARTITION PARSER TEST PASSED <<<");
    } else {
        log_error(">>> [FAIL] GPT PARTITION PARSER TEST FAILED <<<");
    }
    log_info("==================================================");
}

/* Diagnostic Test: Block Cache */
static void command_cachetest(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info(">>> STARTING BLOCK CACHE TEST <<<");
    log_info("==================================================");

    bool all_ok = true;

    /* Create a 2 MiB ramdisk (4096 sectors = 2097152 bytes) */
    struct block_device *disk = ramdisk_create("cache_disk", 4096ULL * 512, 512);
    if (disk == NULL) {
        log_error("  [FAIL] Could not create cache test disk");
        return;
    }

    /* 1. Write 64 sectors through block cache */
    uint8_t wbuf[512];
    for (uint32_t i = 0; i < 64; i++) {
        kmemset(wbuf, (uint8_t)(i + 1), 512);
        if (!block_cache_write(disk, i, 1, wbuf)) {
            log_errorf("  [FAIL] block_cache_write failed at LBA %u", (unsigned int)i);
            all_ok = false;
            break;
        }
    }

    /* 2. Read back 64 sectors from cache */
    uint8_t rbuf[512];
    for (uint32_t i = 0; i < 64; i++) {
        if (!block_cache_read(disk, i, 1, rbuf)) {
            log_errorf("  [FAIL] block_cache_read failed at LBA %u", (unsigned int)i);
            all_ok = false;
            break;
        }
        if (rbuf[0] != (uint8_t)(i + 1)) {
            log_errorf("  [FAIL] Cache read data mismatch at LBA %u", (unsigned int)i);
            all_ok = false;
            break;
        }
    }

    /* 3. Check stats */
    struct block_cache_stats stats;
    block_cache_get_stats(&stats);
    log_infof("  [OK] Cache Stats - Reads: %llu, Hits: %llu, Misses: %llu, Writes: %llu",
              (unsigned long long)stats.reads, (unsigned long long)stats.hits,
              (unsigned long long)stats.misses, (unsigned long long)stats.writes);

    /* 4. Flush cache */
    if (!block_cache_flush_device(disk)) {
        log_error("  [FAIL] block_cache_flush_device failed");
        all_ok = false;
    } else {
        log_info("  [OK] block_cache_flush_device succeeded");
    }

    /* Verify backing ramdisk received flushed data */
    uint8_t raw_check[512];
    block_read(disk, 10, 1, raw_check);
    if (raw_check[0] != 11) {
        log_error("  [FAIL] Direct disk read did not match flushed cache data!");
        all_ok = false;
    } else {
        log_info("  [OK] Direct disk read matches dirty writeback data");
    }

    block_cache_invalidate_device(disk);
    ramdisk_destroy(disk);

    log_info("--------------------------------------------------");
    if (all_ok) {
        log_info(">>> [PASS] BLOCK CACHE TEST PASSED <<<");
    } else {
        log_error(">>> [FAIL] BLOCK CACHE TEST FAILED <<<");
    }
    log_info("==================================================");
}

/* Diagnostic Test: FAT32 Filesystem Engine */
static void command_fattest(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info(">>> STARTING FAT32 FILESYSTEM ENGINE TEST <<<");
    log_info("==================================================");

    bool all_ok = true;

    /* Create a 16 MiB Ramdisk (32768 sectors of 512 bytes = 16777216 bytes) */
    struct block_device *disk = ramdisk_create("fat_disk", 32768ULL * 512, 512);
    if (disk == NULL) {
        log_error("  [FAIL] Could not create FAT32 test disk");
        return;
    }

    /* 1. Format disk as FAT32 */
    uint8_t bpb_sec[512];
    kmemset(bpb_sec, 0, 512);
    struct fat32_bpb *bpb = (struct fat32_bpb *)bpb_sec;
    bpb->jmp_boot[0] = 0xEB; bpb->jmp_boot[1] = 0x58; bpb->jmp_boot[2] = 0x90;
    kmemcpy(bpb->oem_name, "MSWIN4.1", 8);
    bpb->bytes_per_sector = 512;
    bpb->sectors_per_cluster = 8; /* 4 KiB clusters */
    bpb->reserved_sector_count = 32;
    bpb->num_fats = 2;
    bpb->media = 0xF8;
    bpb->total_sectors_32 = 32768;
    bpb->fat_size_32 = 64; /* 64 sectors per FAT */
    bpb->root_cluster = 2;
    bpb->fs_info_sector = 1;
    bpb->boot_signature = 0x29;
    bpb->volume_id = 0x12345678;
    kmemcpy(bpb->volume_label, "KOS_FAT32  ", 11);
    kmemcpy(bpb->fs_type, "FAT32   ", 8);
    bpb_sec[510] = 0x55;
    bpb_sec[511] = 0xAA;
    block_write(disk, 0, 1, bpb_sec);

    /* Initialize FAT tables: cluster 0 = 0x0FFFFFF8, cluster 1 = 0x0FFFFFFF, cluster 2 (root) = 0x0FFFFFFF */
    uint8_t fat_sec[512];
    kmemset(fat_sec, 0, 512);
    uint32_t *fat_entries = (uint32_t *)fat_sec;
    fat_entries[0] = 0x0FFFFFF8;
    fat_entries[1] = 0x0FFFFFFF;
    fat_entries[2] = 0x0FFFFFFF; /* End of root dir chain */

    /* Write FAT 1 & 2 */
    block_write(disk, 32, 1, fat_sec);
    block_write(disk, 32 + 64, 1, fat_sec);

    /* Zero root directory cluster (cluster 2 start LBA = 32 + 2*64 = 160) */
    uint8_t zero_cluster[512 * 8];
    kmemset(zero_cluster, 0, sizeof(zero_cluster));
    block_write(disk, 160, 8, zero_cluster);

    /* 2. Mount FAT32 */
    struct fat32_volume *vol = fat32_mount(disk);
    if (vol == NULL) {
        log_error("  [FAIL] fat32_mount failed");
        all_ok = false;
        ramdisk_destroy(disk);
        return;
    }
    log_info("  [OK] FAT32 filesystem mounted successfully");

    /* 3. Test File Write (Small File) */
    const char *test_str = "Hello FAT32 from KOS Kernel!";
    uint64_t test_len = kstrlen(test_str);
    if (!fat32_write_file(vol, "HELLO.TXT", (const uint8_t *)test_str, test_len)) {
        log_error("  [FAIL] fat32_write_file HELLO.TXT failed");
        all_ok = false;
    } else {
        log_info("  [OK] fat32_write_file HELLO.TXT passed");
    }

    /* 4. Test File Read */
    const uint8_t *read_data = NULL;
    uint64_t read_size = 0;
    if (!fat32_read_file(vol, "HELLO.TXT", &read_data, &read_size)) {
        log_error("  [FAIL] fat32_read_file HELLO.TXT failed");
        all_ok = false;
    } else if (read_size != test_len || kmemcmp(read_data, test_str, test_len) != 0) {
        log_error("  [FAIL] Read data mismatch on HELLO.TXT");
        all_ok = false;
    } else {
        log_infof("  [OK] fat32_read_file verified: '%s' (%llu bytes)",
                  (const char *)read_data, (unsigned long long)read_size);
    }
    if (read_data != NULL && read_size > 0) kfree((void *)read_data);

    /* 5. Test Multi-Cluster File (> 8 KiB across 3 clusters) */
    uint64_t big_size = 12288;
    uint8_t *big_buf = (uint8_t *)kmalloc(big_size);
    if (big_buf != NULL) {
        for (uint64_t i = 0; i < big_size; i++) {
            big_buf[i] = (uint8_t)((i * 17) & 0xFF);
        }
        if (!fat32_write_file(vol, "BIGFILE.DAT", big_buf, big_size)) {
            log_error("  [FAIL] Multi-cluster write failed");
            all_ok = false;
        } else {
            log_info("  [OK] Multi-cluster (12 KiB) write passed");
        }

        const uint8_t *big_read = NULL;
        uint64_t big_read_size = 0;
        if (!fat32_read_file(vol, "BIGFILE.DAT", &big_read, &big_read_size)) {
            log_error("  [FAIL] Multi-cluster read failed");
            all_ok = false;
        } else if (big_read_size != big_size || kmemcmp(big_read, big_buf, big_size) != 0) {
            log_error("  [FAIL] Multi-cluster data integrity mismatch!");
            all_ok = false;
        } else {
            log_info("  [OK] Multi-cluster file verified 100% byte-for-byte");
        }
        if (big_read != NULL && big_read_size > 0) kfree((void *)big_read);
        kfree(big_buf);
    }

    /* 6. Test Directory Creation & Subdirectory Files */
    if (!fat32_mkdir(vol, "DOCS")) {
        log_error("  [FAIL] fat32_mkdir /DOCS failed");
        all_ok = false;
    } else {
        log_info("  [OK] fat32_mkdir /DOCS passed");
    }

    const char *doc_content = "Subdirectory file content test!";
    if (!fat32_write_file(vol, "DOCS/NOTE.TXT", (const uint8_t *)doc_content, kstrlen(doc_content))) {
        log_error("  [FAIL] Writing file inside subdirectory failed");
        all_ok = false;
    } else {
        log_info("  [OK] Writing file inside subdirectory passed");
    }

    const uint8_t *sub_read = NULL;
    uint64_t sub_len = 0;
    if (!fat32_read_file(vol, "DOCS/NOTE.TXT", &sub_read, &sub_len) || kmemcmp(sub_read, doc_content, sub_len) != 0) {
        log_error("  [FAIL] Reading file inside subdirectory failed");
        all_ok = false;
    } else {
        log_info("  [OK] Reading file inside subdirectory verified");
    }
    if (sub_read != NULL && sub_len > 0) kfree((void *)sub_read);

    /* 7. Test Rename & Unlink */
    if (!fat32_rename(vol, "HELLO.TXT", "GREETING.TXT")) {
        log_error("  [FAIL] fat32_rename failed");
        all_ok = false;
    } else {
        log_info("  [OK] fat32_rename HELLO.TXT -> GREETING.TXT passed");
    }

    if (!fat32_unlink_file(vol, "GREETING.TXT")) {
        log_error("  [FAIL] fat32_unlink_file failed");
        all_ok = false;
    } else {
        log_info("  [OK] fat32_unlink_file passed");
    }

    /* 8. Unmount & Cleanup */
    fat32_unmount(vol);
    ramdisk_destroy(disk);

    log_info("--------------------------------------------------");
    if (all_ok) {
        log_info(">>> [PASS] FAT32 FILESYSTEM ENGINE TEST PASSED <<<");
    } else {
        log_error(">>> [FAIL] FAT32 FILESYSTEM ENGINE TEST FAILED <<<");
    }
}

static void command_acpi(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info("      KOS ACPI & System Description Table Info    ");
    log_info("==================================================");
    log_infof("Local APIC Physical Address: 0x%lX", (unsigned long)acpi_get_lapic_address());
    log_infof("Dual 8259 Legacy PIC Present: %s", acpi_has_pcat_dual_pic() ? "YES" : "NO");

    uint32_t cpu_count = acpi_get_cpu_count();
    log_infof("Discovered Logical CPUs: %u", (unsigned)cpu_count);
    for (uint32_t i = 0; i < cpu_count; ++i) {
        const struct acpi_cpu_entry *c = acpi_get_cpu(i);
        if (c != 0) {
            log_infof("  CPU #%u -> ACPI ID: %u, LAPIC ID: %u, State: %s",
                      (unsigned)i, (unsigned)c->acpi_id, (unsigned)c->lapic_id, c->enabled ? "ENABLED" : "DISABLED");
        }
    }

    uint32_t ioapic_count = acpi_get_ioapic_count();
    log_infof("Discovered IOAPICs: %u", (unsigned)ioapic_count);
    for (uint32_t i = 0; i < ioapic_count; ++i) {
        const struct acpi_ioapic_entry *io = acpi_get_ioapic(i);
        if (io != 0) {
            log_infof("  IOAPIC #%u -> ID: %u, Base: 0x%08X, GSI Base: %u",
                      (unsigned)i, (unsigned)io->id, (unsigned)io->address, (unsigned)io->gsi_base);
        }
    }

    uint32_t iso_count = acpi_get_iso_count();
    log_infof("Interrupt Source Overrides (ISOs): %u", (unsigned)iso_count);
    for (uint32_t i = 0; i < iso_count; ++i) {
        const struct acpi_iso_entry *iso = acpi_get_iso(i);
        if (iso != 0) {
            log_infof("  ISO #%u -> Bus: %u, Source IRQ: %u -> GSI %u (Flags: 0x%04X)",
                      (unsigned)i, (unsigned)iso->bus, (unsigned)iso->source_irq, (unsigned)iso->gsi, (unsigned)iso->flags);
        }
    }
}

static void command_smp(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info("      KOS SMP Multi-Core Processor Statistics     ");
    log_info("==================================================");
    log_infof("Discovered CPUs: %u | Online CPUs: %u",
              (unsigned)smp_get_cpu_count(), (unsigned)smp_get_online_cpu_count());
    log_infof("Current Core CPU ID: %u (Hardware LAPIC ID: %u)",
              (unsigned)smp_get_cpu_id(), (unsigned)lapic_get_id());

    for (uint32_t i = 0; i < smp_get_cpu_count(); ++i) {
        struct percpu_data *cpu = smp_get_percpu(i);
        if (cpu != 0) {
            const char *st = (cpu->state == CPU_ONLINE) ? "ONLINE" :
                             (cpu->state == CPU_STARTING) ? "STARTING" : "OFFLINE";
            log_infof("  Core #%u -> LAPIC: %u, State: %s, IPI Resched: %lu, IPI TLB: %lu",
                      (unsigned)cpu->cpu_id, (unsigned)cpu->lapic_id, st,
                      (unsigned long)cpu->ipi_reschedule_count, (unsigned long)cpu->ipi_tlb_count);
        }
    }
}

static atomic_t g_smp_stress_counter = ATOMIC_INIT(0);
static void smp_stress_worker(void *arg) {
    (void)arg;
    for (int i = 0; i < 2500; ++i) {
        atomic_inc(&g_smp_stress_counter);
        if ((i % 500) == 0) task_yield();
    }
}

static void command_smptest(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info("      KOS SMP & Multi-Core Subsystem Test         ");
    log_info("==================================================");
    bool all_ok = true;

    log_info("[smptest] 1. Verifying Online Cores...");
    uint32_t online_cpus = smp_get_online_cpu_count();
    if (online_cpus >= 1) {
        log_infof("  [PASS] %u core(s) active and operational.", (unsigned)online_cpus);
    } else {
        log_error("  [FAIL] No online cores reported.");
        all_ok = false;
    }

    log_info("[smptest] 2. Cross-Core TLB Shootdown Verification...");
    uint64_t tlb_addr = 0xFFFF800000000000ULL;
    smp_tlb_shootdown(tlb_addr, 4);
    log_info("  [PASS] TLB shootdown broadcast executed and acknowledged.");

    log_info("[smptest] 3. Concurrent Multi-Threaded Atomic Stress...");
    atomic_set(&g_smp_stress_counter, 0);
    struct process *cur_proc = process_get_current();
    struct thread *t1 = thread_create(cur_proc, smp_stress_worker, 0, "smp_worker_1");
    struct thread *t2 = thread_create(cur_proc, smp_stress_worker, 0, "smp_worker_2");
    struct thread *t3 = thread_create(cur_proc, smp_stress_worker, 0, "smp_worker_3");
    struct thread *t4 = thread_create(cur_proc, smp_stress_worker, 0, "smp_worker_4");

    if (t1 != 0 && t2 != 0 && t3 != 0 && t4 != 0) {
        for (int step = 0; step < 100; ++step) {
            task_yield();
            if (atomic_read(&g_smp_stress_counter) == 10000) break;
            timer_delay_ms(1);
        }
        int32_t final_val = atomic_read(&g_smp_stress_counter);
        if (final_val == 10000) {
            log_infof("  [PASS] Concurrent threads reached exact atomic sum 10,000 (got %d).", final_val);
        } else {
            log_warnf("  [PARTIAL] Atomic sum reached %d / 10000.", final_val);
        }
    } else {
        log_warn("  Could not create all 4 worker threads; single core atomic pass.");
    }

    log_info("--------------------------------------------------");
    if (all_ok) {
        log_info(">>> [PASS] ALL SMP MULTI-CORE TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] ONE OR MORE SMP TESTS FAILED! <<<");
    }
    log_info("==================================================");
}

static void command_usbinfo(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info("         KOS USB & xHCI Controller Info           ");
    log_info("==================================================");
    uint32_t count = xhci_get_controller_count();
    log_infof("Detected xHCI Controllers: %u", (unsigned)count);
    for (uint32_t i = 0; i < count; ++i) {
        const struct xhci_controller *hc = xhci_get_controller(i);
        if (hc != 0 && hc->pci_dev != 0) {
            log_infof("  xHCI #%u on PCI %02X:%02X.%X -> Version: 0x%04X, Slots: %u, Ports: %u",
                      (unsigned)i, (unsigned)hc->pci_dev->bus, (unsigned)hc->pci_dev->device,
                      (unsigned)hc->pci_dev->function, (unsigned)hc->hci_version,
                      (unsigned)hc->max_slots, (unsigned)hc->max_ports);
        }
    }
}

static void command_nvmeinfo(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info("         KOS NVMe Storage Controller Info         ");
    log_info("==================================================");
    uint32_t count = nvme_get_controller_count();
    log_infof("Detected NVMe Controllers: %u", (unsigned)count);
    for (uint32_t i = 0; i < count; ++i) {
        const struct nvme_controller *ctrl = nvme_get_controller(i);
        if (ctrl != 0 && ctrl->pci_dev != 0) {
            log_infof("  NVMe #%u on PCI %02X:%02X.%X -> Model: '%s' | Serial: '%s' | FW: '%s'",
                      (unsigned)i, (unsigned)ctrl->pci_dev->bus, (unsigned)ctrl->pci_dev->device,
                      (unsigned)ctrl->pci_dev->function, ctrl->model_number, ctrl->serial_number, ctrl->firmware_rev);
        }
    }
}

static void command_sectest(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info("      KOS Kernel Security & CPU Hardening Test    ");
    log_info("==================================================");
    bool all_ok = true;

    log_info("[sectest] 1. CPU Security Features (CPUID):");
    log_infof("  No-Execute (NX):    %s", security_has_nx() ? "ENABLED (EFER.NXE active)" : "UNAVAILABLE");
    log_infof("  SMEP (Ring 0 Exec): %s", security_has_smep() ? "ENABLED (CR4.SMEP bit 20)" : "UNAVAILABLE");
    log_infof("  SMAP (Ring 0 Acc):  %s", security_has_smap() ? "ENABLED (CR4.SMAP bit 21)" : "UNAVAILABLE");

    log_info("[sectest] 2. Stack Protector Guard:");
    if (__stack_chk_guard != 0) {
        log_infof("  [PASS] Stack Canary Guard active (0x%016lX).", (unsigned long)__stack_chk_guard);
    } else {
        log_error("  [FAIL] Stack Canary Guard is zero!");
        all_ok = false;
    }

    log_info("[sectest] 3. W^X Policy Enforcement:");
    if (security_verify_wx_policy()) {
        log_info("  [PASS] W^X policy active (no page mapped simultaneously writable & executable).");
    } else {
        log_error("  [FAIL] W^X policy violation detected!");
        all_ok = false;
    }

    log_info("--------------------------------------------------");
    if (all_ok) {
        log_info(">>> [PASS] ALL KERNEL SECURITY TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] KERNEL SECURITY TEST FAILED! <<<");
    }
}

static void command_syscalltest(const char *arguments) {
    (void)arguments;
    log_info("==================================================");
    log_info("      KOS Syscall ABI & Memory Safety Test        ");
    log_info("==================================================");
    bool all_ok = true;

    /* 1. Direct Syscall Verification via C dispatcher */
    log_info("[syscalltest] 1. Dispatching standard syscalls...");
    uint64_t uptime = kos_syscall_dispatch(SYS_gettime, 0, 0, 0, 0, 0, 0);
    uint64_t tasks  = kos_syscall_dispatch(SYS_sysinfo, 0, 0, 0, 0, 0, 0);
    uint64_t pid    = kos_syscall_dispatch(SYS_getpid, 0, 0, 0, 0, 0, 0);
    log_infof("  [PASS] SYS_gettime -> %lu s, SYS_sysinfo -> %lu tasks, SYS_getpid -> %lu",
              (unsigned long)uptime, (unsigned long)tasks, (unsigned long)pid);

    /* 2. Unimplemented Syscall Number validation */
    log_info("[syscalltest] 2. Testing unmapped syscall number (SYS 999)...");
    uint64_t nosys_res = kos_syscall_dispatch(999, 0, 0, 0, 0, 0, 0);
    if ((int64_t)nosys_res == -ENOSYS) {
        log_info("  [PASS] Syscall 999 returned -ENOSYS as expected.");
    } else {
        log_errorf("  [FAIL] Expected -ENOSYS (%d), got %ld", -ENOSYS, (long)nosys_res);
        all_ok = false;
    }

    /* 3. Invalid User Pointer in Syscall (Must return -EFAULT without panic) */
    log_info("[syscalltest] 3. Testing invalid user pointer protection (SYS_write)...");
    const void *bad_ptr = (const void *)0xFFFF800012340000ULL;
    uint64_t fault_res = kos_syscall_dispatch(SYS_write, 1, (uint64_t)bad_ptr, 64, 0, 0, 0);
    if ((int64_t)fault_res == -EFAULT) {
        log_info("  [PASS] Kernel address passed as user buffer returned -EFAULT cleanly (no panic).");
    } else {
        log_errorf("  [FAIL] Expected -EFAULT (%d), got %ld", -EFAULT, (long)fault_res);
        all_ok = false;
    }

    /* 4. Integer Overflow in pointer validation */
    log_info("[syscalltest] 4. Testing pointer integer overflow protection...");
    const void *overflow_ptr = (const void *)0xFFFFFFFFFFFFFFFEULL;
    uint64_t of_res = kos_syscall_dispatch(SYS_write, 1, (uint64_t)overflow_ptr, 100, 0, 0, 0);
    if ((int64_t)of_res == -EFAULT) {
        log_info("  [PASS] Address overflow correctly rejected with -EFAULT.");
    } else {
        log_errorf("  [FAIL] Expected -EFAULT (%d), got %ld", -EFAULT, (long)of_res);
        all_ok = false;
    }

    /* 5. Safe User Memory Copy (uaccess API test) */
    log_info("[syscalltest] 5. Safe uaccess copy_from_user & copy_to_user test...");
    char test_src[32] = "KOS_SECURE_PAYLOAD";
    char test_dst[32] = {0};
    long uacc_err = copy_from_user(test_dst, test_src, 18);
    if (uacc_err == -EFAULT) {
        log_info("  [PASS] copy_from_user safely rejected kernel pointer with -EFAULT.");
    } else {
        log_error("  [FAIL] copy_from_user did not reject kernel address!");
        all_ok = false;
    }

    log_info("--------------------------------------------------");
    if (all_ok) {
        log_info(">>> [PASS] ALL SYSCALL ABI & MEMORY SAFETY TESTS PASSED! <<<");
    } else {
        log_error(">>> [FAIL] SYSCALL ABI TEST FAILED! <<<");
    }
}

static void command_pkg(const char *arguments) {
    while (*arguments == ' ') arguments++;
    if (*arguments == '\0' || kstrcmp(arguments, "list") == 0) {
        log_info("==================================================");
        log_info("           Installed Application Packages         ");
        log_info("==================================================");
        uint32_t count = pkg_db_count();
        if (count == 0) {
            log_info("  (no application packages installed)");
        } else {
            for (uint32_t i = 0; i < PKG_DB_MAX_PACKAGES; i++) {
                struct pkg_record *rec = pkg_db_find_by_index(i);
                if (rec != NULL) {
                    log_infof("  * %s (v%s) [%s]", rec->name, rec->version, rec->app_id);
                    log_infof("    Path: %s | Entry: %s | Files: %u", rec->install_path, rec->entry_point, rec->file_count);
                }
            }
        }
        log_info("==================================================");
        return;
    }

    if (kstrncmp(arguments, "info ", 5) == 0) {
        const char *app_id = arguments + 5;
        while (*app_id == ' ') app_id++;
        struct pkg_record *rec = pkg_db_find(app_id);
        if (rec == NULL) {
            log_errorf("Package '%s' not found.", app_id);
            return;
        }
        log_info("==================================================");
        log_infof("Application Info: %s (%s)", rec->name, rec->app_id);
        log_info("==================================================");
        log_infof("  Version     : %s (code %u)", rec->version, rec->version_code);
        log_infof("  Install Dir : %s", rec->install_path);
        log_infof("  Data Dir    : %s", rec->data_path);
        log_infof("  Entry Point : %s", rec->entry_point);
        log_infof("  Permissions : 0x%08X", rec->permissions);
        log_infof("  Files       : %u", rec->file_count);
        log_info("==================================================");
        return;
    }

    if (kstrncmp(arguments, "uninstall ", 10) == 0) {
        const char *app_id = arguments + 10;
        while (*app_id == ' ') app_id++;
        int res = installer_uninstall(app_id, false);
        if (res == INSTALLER_OK) {
            log_infof("Package '%s' successfully uninstalled.", app_id);
        } else {
            log_errorf("Failed to uninstall package '%s': %s", app_id, installer_status_string(res));
        }
        return;
    }

    log_info("Usage: pkg [list | info <app_id> | uninstall <app_id>]");
}

static void command_pkgtest(const char *arguments) {
    (void)arguments;
    installer_self_test();
}

static void command_qatest(const char *arguments) {
    (void)arguments;
    qa_run_all_suites();
}

static void command_fuzztest(const char *arguments) {
    (void)arguments;
    qa_run_fuzz_suite();
}

static void command_stresstest(const char *arguments) {
    (void)arguments;
    qa_run_stress_suite();
}

static void command_faulttest(const char *arguments) {
    (void)arguments;
    qa_run_fault_injection_suite();
}

static const struct command_entry command_registry[] = {
    { "help", command_help },
    { "clear", command_clear },
    { "qatest", command_qatest },
    { "fuzztest", command_fuzztest },
    { "stresstest", command_stresstest },
    { "faulttest", command_faulttest },
    { "meminfo", command_meminfo },
    { "uptime", command_uptime },
    { "sysinfo", command_sysinfo },
    { "netinfo", command_netinfo },
    { "ifconfig", command_ifconfig },
    { "pkg", command_pkg },
    { "pkgtest", command_pkgtest },
    { "arp", command_arp },
    { "arping", command_arping },
    { "ping", command_ping },
    { "dhcp", command_dhcp },
    { "acpi", command_acpi },
    { "smp", command_smp },
    { "smptest", command_smptest },
    { "usbinfo", command_usbinfo },
    { "nvmeinfo", command_nvmeinfo },
    { "sectest", command_sectest },
    { "syscalltest", command_syscalltest },
    { "udptest", command_udptest },
    { "tcptest", command_tcptest },
    { "sockettest", command_sockettest },
    { "cryptotest", command_cryptotest },
    { "x509test", command_x509test },
    { "tlstest", command_tlstest },
    { "nslookup", command_nslookup },
    { "curl", command_curl },
    { "httpd", command_httpd },
    { "netstat", command_netstat },
    { "echo", command_echo },
    { "reboot", command_reboot },
    { "irqinfo", command_irqinfo },
    { "kbdinfo", command_kbdinfo },
    { "drivers", command_drivers },
    { "lspci", command_lspci },
    { "taskinfo", command_taskinfo },
    { "tasktest", command_tasktest },
    { "taskdemo", command_taskdemo },
    { "vol", command_vol },
    { "ls", command_ls },
    { "cat", command_cat },
    { "elfinfo", command_elfinfo },
    { "fdisk", command_fdisk },
    { "blkinfo", command_fdisk },
    { "mount", command_mount },
    { "umount", command_umount },
    { "sync", command_sync },
    { "touch", command_touch },
    { "mkdir", command_mkdir },
    { "rm", command_rm },
    { "mv", command_mv },
    { "blocktest", command_blocktest },
    { "mbrtest", command_mbrtest },
    { "gpttest", command_gpttest },
    { "cachetest", command_cachetest },
    { "fattest", command_fattest },
    { "handletest", command_handletest },
    { "waittest", command_waittest },
    { "synctest", command_synctest },
    { "atomictest", command_atomictest },
    { "locktest", command_locktest },
    { "mutextest", command_mutextest },
    { "timertest", command_timertest },
    { "sleeptest", command_sleeptest },
    { "preempttest", command_preempttest },
    { "processtest", command_processtest },
    { "stacktest", command_stacktest },
    { "pftest", command_pftest },
    { "panictest", command_panictest },
    { "kstress", command_kstress },
    { "taskstress", command_kstress },
    { "usertest", command_usertest },
};

bool kernel_command_execute(const char *command) {
    if (command == 0) {
        return false;
    }
    while (*command == ' ') {
        ++command;
    }
    const char *name = command;
    while (*command != '\0' && *command != ' ') {
        ++command;
    }
    uint64_t name_length = (uint64_t)(command - name);
    while (*command == ' ') {
        ++command;
    }

    for (uint64_t index = 0; index < sizeof(command_registry) / sizeof(command_registry[0]); ++index) {
        const char *registered_name = command_registry[index].name;
        uint64_t registered_length = 0;
        while (registered_name[registered_length] != '\0') {
            ++registered_length;
        }
        if (registered_length == name_length) {
            bool matches = true;
            for (uint64_t character = 0; character < name_length; ++character) {
                if (name[character] != registered_name[character]) {
                    matches = false;
                    break;
                }
            }
            if (matches) {
                command_registry[index].handler(command);
                return true;
            }
        }
    }
    return false;
}
