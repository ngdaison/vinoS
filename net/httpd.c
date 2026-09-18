#include <stdbool.h>
#include <stdint.h>

#include <kos/log.h>
#include <kos/net.h>
#include <kos/pmm.h>
#include <kos/system.h>
#include <kos/timer.h>

static int httpd_listen_sock = -1;
static bool httpd_running;
static uint16_t httpd_port = NET_HTTP_PORT;
static uint64_t httpd_requests_count;

static uint64_t u64_to_str(uint64_t val, char *buf) {
    char tmp[24];
    uint64_t digits = 0;
    do {
        tmp[digits++] = (char)('0' + (val % 10));
        val /= 10;
    } while (val > 0);
    for (uint64_t i = 0; i < digits; ++i) {
        buf[i] = tmp[digits - 1 - i];
    }
    buf[digits] = '\0';
    return digits;
}

static uint64_t append_str(char *dest, uint64_t pos, const char *src) {
    if (src == 0) {
        return pos;
    }
    while (*src != '\0') {
        dest[pos++] = *src++;
    }
    dest[pos] = '\0';
    return pos;
}

static uint64_t append_u64(char *dest, uint64_t pos, uint64_t val) {
    char num[24];
    (void)u64_to_str(val, num);
    return append_str(dest, pos, num);
}

bool httpd_start(uint16_t port) {
    if (httpd_running) {
        if (httpd_port == port) {
            return true;
        }
        httpd_stop();
    }

    uint16_t target_port = port > 0 ? port : NET_HTTP_PORT;
    int sock = tcp_listen(target_port, 4);
    if (sock < 0) {
        log_error("httpd: failed to listen on port.");
        return false;
    }

    httpd_listen_sock = sock;
    httpd_running = true;
    httpd_port = target_port;
    log_info_u64("httpd: web server listening on port ", target_port);
    return true;
}

void httpd_stop(void) {
    if (!httpd_running) {
        return;
    }
    if (httpd_listen_sock >= 0) {
        tcp_close(httpd_listen_sock);
        httpd_listen_sock = -1;
    }
    httpd_running = false;
    log_info("httpd: web server stopped.");
}

bool httpd_is_running(void) {
    return httpd_running;
}

uint64_t httpd_requests_served(void) {
    return __atomic_load_n(&httpd_requests_count, __ATOMIC_RELAXED);
}

uint16_t httpd_listen_port(void) {
    return httpd_port;
}

static void send_404_response(int client_sock) {
    const char *resp =
        "HTTP/1.1 404 Not Found\r\n"
        "Server: KOS-httpd/0.1\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 67\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<html><body><h1>404 Not Found</h1><p>KOS Web Server</p></body></html>";
    uint64_t len = 0;
    while (resp[len] != '\0') ++len;
    (void)tcp_send(client_sock, (const uint8_t *)resp, len);
}

static void send_204_response(int client_sock) {
    const char *resp =
        "HTTP/1.1 204 No Content\r\n"
        "Server: KOS-httpd/0.1\r\n"
        "Connection: close\r\n"
        "\r\n";
    uint64_t len = 0;
    while (resp[len] != '\0') ++len;
    (void)tcp_send(client_sock, (const uint8_t *)resp, len);
}

static void send_dashboard_response(int client_sock) {
    static char body[2048];
    uint64_t b_pos = 0;

    struct net_interface_info net_info;
    char ip_str[16] = "10.0.2.15";
    if (net_interface_info(&net_info) && net_info.available) {
        net_format_ipv4(net_info.ipv4_address, ip_str);
    }

    uint64_t uptime = timer_uptime_seconds();
    uint64_t ram_mb = pmm_total_memory_bytes() / (1024 * 1024);
    uint64_t free_frames = pmm_free_frame_count();
    uint64_t req_count = __atomic_load_n(&httpd_requests_count, __ATOMIC_RELAXED) + 1;

    b_pos = append_str(body, b_pos,
        "<!doctype html><html><head><title>KOS Web Dashboard</title>"
        "<style>body{background:#1a1a2e;color:#e0e0e0;font-family:sans-serif;max-width:680px;margin:30px auto;padding:20px;}"
        "h1{color:#4ecca3;border-bottom:2px solid #4ecca3;padding-bottom:6px;}"
        ".card{background:#162447;padding:14px;margin:10px 0;border-radius:6px;border-left:4px solid #e94560;}"
        ".label{color:#a0a0c0;font-weight:bold;} .val{color:#fff;}"
        "</style></head><body><h1>KOS Operating System</h1>"
        "<div class=\"card\"><div><span class=\"label\">Kernel:</span> <span class=\"val\">KOS v0.1 (x86_64)</span></div>"
        "<div><span class=\"label\">Uptime:</span> <span class=\"val\">");
    b_pos = append_u64(body, b_pos, uptime);
    b_pos = append_str(body, b_pos, " seconds</span></div></div>"
        "<div class=\"card\"><div><span class=\"label\">Total RAM:</span> <span class=\"val\">");
    b_pos = append_u64(body, b_pos, ram_mb);
    b_pos = append_str(body, b_pos, " MB</span></div>"
        "<div><span class=\"label\">Free Frames:</span> <span class=\"val\">");
    b_pos = append_u64(body, b_pos, free_frames);
    b_pos = append_str(body, b_pos, "</span></div></div>"
        "<div class=\"card\"><div><span class=\"label\">Network IP:</span> <span class=\"val\">");
    b_pos = append_str(body, b_pos, ip_str);
    b_pos = append_str(body, b_pos, "</span></div>"
        "<div><span class=\"label\">HTTP Server:</span> <span class=\"val\">KOS-httpd/0.1 on port ");
    b_pos = append_u64(body, b_pos, (uint64_t)httpd_port);
    b_pos = append_str(body, b_pos, "</span></div>"
        "<div><span class=\"label\">Requests Served:</span> <span class=\"val\">");
    b_pos = append_u64(body, b_pos, req_count);
    b_pos = append_str(body, b_pos, "</span></div></div>"
        "<p style=\"text-align:center;color:#777;font-size:12px;\">Powered by KOS Bare-Metal Network Stack</p>"
        "</body></html>\n");

    /* Build headers */
    char hdr[256];
    uint64_t h_pos = 0;
    h_pos = append_str(hdr, h_pos,
        "HTTP/1.1 200 OK\r\n"
        "Server: KOS-httpd/0.1\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: ");
    h_pos = append_u64(hdr, h_pos, b_pos);
    h_pos = append_str(hdr, h_pos, "\r\nConnection: close\r\n\r\n");

    (void)tcp_send(client_sock, (const uint8_t *)hdr, h_pos);
    (void)tcp_send(client_sock, (const uint8_t *)body, b_pos);
}

static void send_sysinfo_response(int client_sock) {
    char body[512];
    uint64_t b_pos = 0;

    b_pos = append_str(body, b_pos, "Kernel: KOS v0.1\nArch: x86_64\nUptime: ");
    b_pos = append_u64(body, b_pos, timer_uptime_seconds());
    b_pos = append_str(body, b_pos, " seconds\nTotal Memory: ");
    b_pos = append_u64(body, b_pos, pmm_total_memory_bytes());
    b_pos = append_str(body, b_pos, " bytes\nFree Frames: ");
    b_pos = append_u64(body, b_pos, pmm_free_frame_count());
    b_pos = append_str(body, b_pos, "\n");

    char hdr[256];
    uint64_t h_pos = 0;
    h_pos = append_str(hdr, h_pos,
        "HTTP/1.1 200 OK\r\n"
        "Server: KOS-httpd/0.1\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: ");
    h_pos = append_u64(hdr, h_pos, b_pos);
    h_pos = append_str(hdr, h_pos, "\r\nConnection: close\r\n\r\n");

    (void)tcp_send(client_sock, (const uint8_t *)hdr, h_pos);
    (void)tcp_send(client_sock, (const uint8_t *)body, b_pos);
}

static void send_netinfo_response(int client_sock) {
    char body[512];
    uint64_t b_pos = 0;

    b_pos = append_str(body, b_pos, "TCP Segments Sent: ");
    b_pos = append_u64(body, b_pos, net_tcp_segments_sent());
    b_pos = append_str(body, b_pos, "\nTCP Segments Received: ");
    b_pos = append_u64(body, b_pos, net_tcp_segments_received());
    b_pos = append_str(body, b_pos, "\nDNS Queries Sent: ");
    b_pos = append_u64(body, b_pos, net_dns_queries_sent());
    b_pos = append_str(body, b_pos, "\nDNS Responses Received: ");
    b_pos = append_u64(body, b_pos, net_dns_responses_received());
    b_pos = append_str(body, b_pos, "\nHTTP Requests Served: ");
    b_pos = append_u64(body, b_pos, __atomic_load_n(&httpd_requests_count, __ATOMIC_RELAXED) + 1);
    b_pos = append_str(body, b_pos, "\n");

    char hdr[256];
    uint64_t h_pos = 0;
    h_pos = append_str(hdr, h_pos,
        "HTTP/1.1 200 OK\r\n"
        "Server: KOS-httpd/0.1\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: ");
    h_pos = append_u64(hdr, h_pos, b_pos);
    h_pos = append_str(hdr, h_pos, "\r\nConnection: close\r\n\r\n");

    (void)tcp_send(client_sock, (const uint8_t *)hdr, h_pos);
    (void)tcp_send(client_sock, (const uint8_t *)body, b_pos);
}

void httpd_poll(void) {
    if (!httpd_running || httpd_listen_sock < 0) {
        return;
    }

    struct net_ipv4_endpoint client_ep;
    int client = tcp_accept(httpd_listen_sock, &client_ep);
    if (client < 0) {
        return;
    }

    char req[512];
    int r = tcp_receive(client, (uint8_t *)req, sizeof(req) - 1);
    if (r <= 0) {
        tcp_close(client);
        return;
    }
    req[r] = '\0';

    /* Parse request line: e.g. "GET /path HTTP/1.1" */
    const char *p = req;
    while (*p == ' ') ++p;
    if (p[0] == 'G' && p[1] == 'E' && p[2] == 'T' && p[3] == ' ') {
        p += 4;
        while (*p == ' ') ++p;

        char path[64];
        uint64_t path_len = 0;
        while (*p != ' ' && *p != '\r' && *p != '\n' && *p != '\0' && path_len + 1 < sizeof(path)) {
            path[path_len++] = *p++;
        }
        path[path_len] = '\0';

        if (path_len == 0 || (path[0] == '/' && path[1] == '\0')
            || (path[0] == '/' && path[1] == 'i' && path[2] == 'n' && path[3] == 'd'
                && path[4] == 'e' && path[5] == 'x')) {
            send_dashboard_response(client);
        }
        else if (path[0] == '/' && path[1] == 's' && path[2] == 'y' && path[3] == 's') {
            send_sysinfo_response(client);
        }
        else if (path[0] == '/' && path[1] == 'n' && path[2] == 'e' && path[3] == 't') {
            send_netinfo_response(client);
        }
        else if (path[0] == '/' && path[1] == 'f' && path[2] == 'a' && path[3] == 'v') {
            send_204_response(client);
        }
        else {
            send_404_response(client);
        }
    }
    else {
        send_404_response(client);
    }

    (void)__atomic_add_fetch(&httpd_requests_count, 1, __ATOMIC_RELAXED);
    tcp_close(client);
}
