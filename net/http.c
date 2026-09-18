#include <stdbool.h>
#include <stdint.h>

#include <kos/cpu.h>
#include <kos/log.h>
#include <kos/net.h>
#include <kos/timer.h>
#include <kos/tls.h>

enum {
    HTTP_MAX_REDIRECTS = 3,
    HTTP_DEFAULT_PORT = 80,
    HTTPS_DEFAULT_PORT = 443,
    HTTP_MAX_HOST = 64,
    HTTP_MAX_PATH = 256,
};

struct parsed_url {
    bool is_https;
    char host[HTTP_MAX_HOST];
    uint16_t port;
    char path[HTTP_MAX_PATH];
};

static uint64_t str_length(const char *s) {
    if (s == 0) {
        return 0;
    }
    uint64_t len = 0;
    while (s[len] != '\0') {
        ++len;
    }
    return len;
}

static char to_lower_char(char c) {
    if (c >= 'A' && c <= 'Z') {
        return (char)(c + ('a' - 'A'));
    }
    return c;
}

static bool str_starts_with_case_insensitive(const char *str, const char *prefix) {
    if (str == 0 || prefix == 0) {
        return false;
    }
    while (*prefix != '\0') {
        if (to_lower_char(*str) != to_lower_char(*prefix)) {
            return false;
        }
        ++str;
        ++prefix;
    }
    return true;
}

static bool parse_ipv4_literal(const char *text, uint32_t *address) {
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

static bool parse_http_url(const char *url, struct parsed_url *parsed) {
    if (url == 0 || parsed == 0 || *url == '\0') {
        return false;
    }

    parsed->is_https = false;
    const char *p = url;
    if (str_starts_with_case_insensitive(p, "https://")) {
        parsed->is_https = true;
        p += 8;
    } else if (str_starts_with_case_insensitive(p, "http://")) {
        parsed->is_https = false;
        p += 7;
    }

    uint64_t h_idx = 0;
    while (*p != '\0' && *p != ':' && *p != '/' && h_idx + 1 < sizeof(parsed->host)) {
        parsed->host[h_idx++] = *p++;
    }
    parsed->host[h_idx] = '\0';
    if (h_idx == 0) {
        return false;
    }

    parsed->port = parsed->is_https ? HTTPS_DEFAULT_PORT : HTTP_DEFAULT_PORT;
    if (*p == ':') {
        ++p;
        uint32_t port_val = 0;
        while (*p >= '0' && *p <= '9') {
            port_val = port_val * 10 + (uint32_t)(*p++ - '0');
            if (port_val > 65535) {
                return false;
            }
        }
        if (port_val == 0) {
            return false;
        }
        parsed->port = (uint16_t)port_val;
    }

    if (*p == '/') {
        uint64_t path_idx = 0;
        while (*p != '\0' && path_idx + 1 < sizeof(parsed->path)) {
            parsed->path[path_idx++] = *p++;
        }
        parsed->path[path_idx] = '\0';
    }
    else {
        parsed->path[0] = '/';
        parsed->path[1] = '\0';
    }

    return true;
}

static const char *find_substring_case_insensitive(const char *haystack, const char *needle) {
    if (haystack == 0 || needle == 0 || *needle == '\0') {
        return 0;
    }
    uint64_t needle_len = str_length(needle);
    for (uint64_t i = 0; haystack[i] != '\0'; ++i) {
        bool match = true;
        for (uint64_t j = 0; j < needle_len; ++j) {
            if (haystack[i + j] == '\0' || to_lower_char(haystack[i + j]) != to_lower_char(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) {
            return &haystack[i];
        }
    }
    return 0;
}

static uint64_t decode_hex_size(const char *str, uint64_t *consumed) {
    uint64_t val = 0;
    uint64_t idx = 0;
    while (str[idx] == ' ' || str[idx] == '\t') {
        ++idx;
    }
    while (str[idx] != '\0') {
        char c = str[idx];
        if (c >= '0' && c <= '9') {
            val = (val << 4) | (uint64_t)(c - '0');
        }
        else if (c >= 'a' && c <= 'f') {
            val = (val << 4) | (uint64_t)(c - 'a' + 10);
        }
        else if (c >= 'A' && c <= 'F') {
            val = (val << 4) | (uint64_t)(c - 'A' + 10);
        }
        else {
            break;
        }
        ++idx;
    }
    while (str[idx] != '\0' && str[idx] != '\r' && str[idx] != '\n') {
        ++idx;
    }
    if (str[idx] == '\r') {
        ++idx;
    }
    if (str[idx] == '\n') {
        ++idx;
    }
    *consumed = idx;
    return val;
}

static void unchunk_http_body(char *body_start, uint64_t body_len) {
    if (body_start == 0 || body_len == 0) {
        return;
    }
    char *read_ptr = body_start;
    char *write_ptr = body_start;
    uint64_t remaining = body_len;

    while (remaining > 0) {
        uint64_t header_consumed = 0;
        uint64_t chunk_size = decode_hex_size(read_ptr, &header_consumed);
        if (header_consumed == 0 || header_consumed > remaining) {
            break;
        }
        read_ptr += header_consumed;
        remaining -= header_consumed;

        if (chunk_size == 0) {
            break;
        }

        uint64_t copy_bytes = chunk_size < remaining ? chunk_size : remaining;
        for (uint64_t i = 0; i < copy_bytes; ++i) {
            *write_ptr++ = *read_ptr++;
        }
        remaining -= copy_bytes;

        /* Skip trailing \r\n after chunk data */
        if (remaining > 0 && *read_ptr == '\r') {
            ++read_ptr;
            --remaining;
        }
        if (remaining > 0 && *read_ptr == '\n') {
            ++read_ptr;
            --remaining;
        }
    }
    *write_ptr = '\0';
}

static bool execute_http_request(const struct parsed_url *parsed, char *response_buffer,
        uint64_t capacity, uint64_t *out_size, char *out_redirect_location,
        uint64_t redirect_capacity, uint16_t *out_status_code) {
    uint32_t ip_address = 0;
    if (!parse_ipv4_literal(parsed->host, &ip_address)) {
        if (!net_dns_resolve(parsed->host, &ip_address, timer_frequency_hz() * 5)) {
            return false;
        }
    }

    int sock = tcp_connect(ip_address, parsed->port);
    if (sock < 0) {
        return false;
    }

    struct net_tls_session tls;
    bool use_tls = parsed->is_https || parsed->port == HTTPS_DEFAULT_PORT;
    if (use_tls) {
        net_tls_session_initialize(&tls, parsed->host, false);
        enum net_tls_error terr = net_tls_client_handshake(&tls, sock, timer_frequency_hz() * 5);
        if (terr != NET_TLS_ERROR_NONE) {
            tcp_close(sock);
            return false;
        }
    }

    /* Build HTTP/1.1 request */
    char req[512];
    uint64_t r_pos = 0;
    const char *part1 = "GET ";
    for (uint64_t i = 0; part1[i] != '\0'; ++i) req[r_pos++] = part1[i];
    for (uint64_t i = 0; parsed->path[i] != '\0'; ++i) req[r_pos++] = parsed->path[i];
    const char *part2 = " HTTP/1.1\r\nHost: ";
    for (uint64_t i = 0; part2[i] != '\0'; ++i) req[r_pos++] = part2[i];
    for (uint64_t i = 0; parsed->host[i] != '\0'; ++i) req[r_pos++] = parsed->host[i];

    uint16_t default_port = use_tls ? HTTPS_DEFAULT_PORT : HTTP_DEFAULT_PORT;
    if (parsed->port != default_port) {
        req[r_pos++] = ':';
        uint32_t p_val = parsed->port;
        uint32_t p_digits = 0;
        char tmp[8];
        do {
            tmp[p_digits++] = (char)('0' + (p_val % 10));
            p_val /= 10;
        } while (p_val > 0);
        for (uint32_t d = 0; d < p_digits; ++d) {
            req[r_pos++] = tmp[p_digits - 1 - d];
        }
    }
    const char *part3 = "\r\nUser-Agent: KOS-curl/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    for (uint64_t i = 0; part3[i] != '\0'; ++i) req[r_pos++] = part3[i];
    req[r_pos] = '\0';

    int sent = 0;
    if (use_tls) {
        sent = net_tls_send(&tls, sock, (const uint8_t *)req, r_pos);
    } else {
        sent = tcp_send(sock, (const uint8_t *)req, r_pos);
    }

    if (sent <= 0) {
        if (use_tls) net_tls_close(&tls, sock);
        tcp_close(sock);
        return false;
    }

    /* Receive full response */
    uint64_t total_read = 0;
    while (total_read + 1 < capacity) {
        int r = 0;
        if (use_tls) {
            r = net_tls_recv(&tls, sock, (uint8_t *)&response_buffer[total_read], capacity - total_read - 1);
        } else {
            r = tcp_receive(sock, (uint8_t *)&response_buffer[total_read], capacity - total_read - 1);
        }

        if (r <= 0) {
            break;
        }
        total_read += (uint64_t)r;
        response_buffer[total_read] = '\0';

        /* Early completion check if full payload has arrived */
        const char *hdr_end = find_substring_case_insensitive(response_buffer, "\r\n\r\n");
        if (hdr_end != 0) {
            uint64_t body_offset = (uint64_t)(hdr_end + 4 - response_buffer);
            uint64_t cur_body_len = total_read >= body_offset ? total_read - body_offset : 0;

            const char *cl = find_substring_case_insensitive(response_buffer, "Content-Length:");
            if (cl != 0 && cl < hdr_end) {
                while (*cl != ':') ++cl;
                ++cl;
                while (*cl == ' ' || *cl == '\t') ++cl;
                uint64_t cl_val = 0;
                while (*cl >= '0' && *cl <= '9') {
                    cl_val = cl_val * 10 + (uint64_t)(*cl++ - '0');
                }
                if (cur_body_len >= cl_val) {
                    break;
                }
            }

            const char *te = find_substring_case_insensitive(response_buffer, "Transfer-Encoding:");
            if (te != 0 && te < hdr_end) {
                if (find_substring_case_insensitive(hdr_end, "\r\n0\r\n\r\n") != 0
                    || find_substring_case_insensitive(hdr_end, "0\r\n\r\n") == hdr_end + 4) {
                    break;
                }
            }
        }
    }
    response_buffer[total_read] = '\0';

    if (use_tls) {
        net_tls_close(&tls, sock);
    }
    tcp_close(sock);

    if (total_read == 0) {
        return false;
    }
    *out_size = total_read;

    /* Parse Status Code */
    uint16_t status_code = 0;
    if (str_starts_with_case_insensitive(response_buffer, "HTTP/")) {
        const char *sp = response_buffer;
        while (*sp != '\0' && *sp != ' ') {
            ++sp;
        }
        if (*sp == ' ') {
            ++sp;
            while (*sp >= '0' && *sp <= '9') {
                status_code = status_code * 10 + (uint16_t)(*sp++ - '0');
            }
        }
    }
    *out_status_code = status_code;

    /* Check Location header on redirect status */
    if (status_code == 301 || status_code == 302 || status_code == 303
        || status_code == 307 || status_code == 308) {
        const char *loc = find_substring_case_insensitive(response_buffer, "\r\nLocation:");
        if (loc == 0) {
            loc = find_substring_case_insensitive(response_buffer, "\nLocation:");
        }
        if (loc != 0) {
            while (*loc != ':') {
                ++loc;
            }
            ++loc;
            while (*loc == ' ' || *loc == '\t') {
                ++loc;
            }
            uint64_t l_idx = 0;
            while (*loc != '\r' && *loc != '\n' && *loc != '\0' && l_idx + 1 < redirect_capacity) {
                out_redirect_location[l_idx++] = *loc++;
            }
            out_redirect_location[l_idx] = '\0';
        }
    }

    /* If chunked transfer encoding, decode body */
    const char *te = find_substring_case_insensitive(response_buffer, "Transfer-Encoding:");
    if (te != 0) {
        const char *chk = find_substring_case_insensitive(te, "chunked");
        const char *hdr_end = find_substring_case_insensitive(response_buffer, "\r\n\r\n");
        if (chk != 0 && hdr_end != 0 && chk < hdr_end) {
            char *body_start = (char *)(hdr_end + 4);
            uint64_t body_len = (uint64_t)(&response_buffer[total_read] - body_start);
            unchunk_http_body(body_start, body_len);
            *out_size = (uint64_t)(str_length(response_buffer));
        }
    }

    return true;
}

bool net_http_get(const char *url, char *response_buffer, uint64_t capacity, uint64_t *out_size) {
    if (url == 0 || response_buffer == 0 || capacity == 0 || out_size == 0) {
        return false;
    }

    char current_url[512];
    uint64_t u_len = str_length(url);
    if (u_len >= sizeof(current_url)) {
        return false;
    }
    for (uint64_t i = 0; i <= u_len; ++i) {
        current_url[i] = url[i];
    }

    for (uint32_t redirect = 0; redirect < HTTP_MAX_REDIRECTS; ++redirect) {
        struct parsed_url parsed;
        if (!parse_http_url(current_url, &parsed)) {
            return false;
        }

        char redirect_location[512] = { 0 };
        uint16_t status_code = 0;
        if (!execute_http_request(&parsed, response_buffer, capacity, out_size,
                redirect_location, sizeof(redirect_location), &status_code)) {
            return false;
        }

        if ((status_code == 301 || status_code == 302 || status_code == 303
             || status_code == 307 || status_code == 308) && redirect_location[0] != '\0') {
            /* If redirect target is relative path, prepend host */
            if (redirect_location[0] == '/') {
                uint64_t p_len = 0;
                const char *prefix = parsed.is_https ? "https://" : "http://";
                for (uint64_t i = 0; prefix[i] != '\0'; ++i) current_url[p_len++] = prefix[i];
                for (uint64_t i = 0; parsed.host[i] != '\0'; ++i) current_url[p_len++] = parsed.host[i];
                for (uint64_t i = 0; redirect_location[i] != '\0'; ++i) current_url[p_len++] = redirect_location[i];
                current_url[p_len] = '\0';
            }
            else {
                uint64_t l_len = str_length(redirect_location);
                for (uint64_t i = 0; i <= l_len; ++i) {
                    current_url[i] = redirect_location[i];
                }
            }
            continue;
        }

        return true;
    }

    return true;
}
