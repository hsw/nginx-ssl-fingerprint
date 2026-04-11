#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>
#include <ngx_http_v2.h>
#include <ngx_md5.h>
#include <openssl/sha.h>

#include <nginx_ssl_fingerprint.h>

#define IS_GREASE_CODE(code) (((code)&0x0f0f) == 0x0a0a && ((code)&0xff) == ((code)>>8))

/* Stack buffer size for JA4 SHA-256 hex string computation.
 * Must be >= max(NGX_SSL_JA4_MAX_CIPHERS, NGX_SSL_JA4_MAX_EXTENSIONS +
 * NGX_SSL_JA4_MAX_SIGALGS) * 5.  Current worst case: 200*5-1+1+128*5-1 = 1639 */
#define NGX_SSL_JA4_HASH_BUF_SIZE  2048

/* JA4 _a section: t(1) + ver(2) + sni(1) + cc(2) + ec(2) + alpn(2) = 10 chars */
#define NGX_SSL_JA4_A_LEN          10

/* TLS extension type codes used in JA4 hash exclusion */
#define NGX_SSL_EXT_SNI            0x0000
#define NGX_SSL_EXT_ALPN           0x0010

static const u_char hex[] = "0123456789abcdef";

static inline
unsigned char *append_uint8(unsigned char* dst, uint8_t n)
{
    if (n < 10) {
        dst[0] = n + '0';
        dst++;
    } else if (n < 100) {
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 2;
    } else {
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 3;
    }

    return dst;
}

static inline
unsigned char *append_uint16(unsigned char* dst, uint16_t n)
{
    if (n < 10) {
        dst[0] = n + '0';
        dst++;
    } else if (n < 100) {
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 2;
    } else if (n < 1000) {
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 3;
    }  else if (n < 10000) {
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 4;
    } else {
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 5;
    }

    return dst;
}

static inline
unsigned char *append_uint32(unsigned char* dst, uint32_t n)
{
    if (n < 10) {
        dst[0] = n + '0';
        dst++;
    } else if (n < 100) {
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 2;
    } else if (n < 1000) {
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 3;
    } else if (n < 10000) {
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 4;
    } else if (n < 100000) {
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 5;
    } else if (n < 1000000) {
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 6;
    } else if (n < 10000000) {
        dst[6] = n % 10 + '0';
        n /= 10;
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 7;
    } else if (n < 100000000) {
        dst[7] = n % 10 + '0';
        n /= 10;
        dst[6] = n % 10 + '0';
        n /= 10;
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 8;
    } else if (n < 1000000000) {
        dst[8] = n % 10 + '0';
        n /= 10;
        dst[7] = n % 10 + '0';
        n /= 10;
        dst[6] = n % 10 + '0';
        n /= 10;
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 9;
    } else {
        dst[9] = n % 10 + '0';
        n /= 10;
        dst[8] = n % 10 + '0';
        n /= 10;
        dst[7] = n % 10 + '0';
        n /= 10;
        dst[6] = n % 10 + '0';
        n /= 10;
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 10;
    }

    return dst;
}


/**
 * Params:
 *      c and c->ssl should be valid pointers
 *
 * Returns:
 *      NGX_OK - c->ssl->fp_ja3_str is already set
 *      NGX_ERROR - something went wrong
 */
int ngx_ssl_ja3(ngx_connection_t *c)
{
    u_char *ptr = NULL, *data = NULL, *end;
    size_t num = 0, i;
    uint16_t n, greased = 0;

    data = c->ssl->fp_ja3_data.data;
    if (data == NULL) {
        /**
         *  NOTE:
         *  If we can't set it in OpenSSL,
         *  then something defenetly something went wrong.
         *  Typical production configuration has log level set to error,
         *  this would help to debug this case, if it happened.
         */
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja3: fp_ja_data == NULL");
        return NGX_ERROR;
    }

    if (c->ssl->fp_ja3_str.data != NULL) {
        return NGX_OK;
    }

    end = data + c->ssl->fp_ja3_data.len;

    /* *4: formats section has 1-byte entries, max 3 digits + separator = 4 chars */
    c->ssl->fp_ja3_str.len = c->ssl->fp_ja3_data.len * 4;
    c->ssl->fp_ja3_str.data = ngx_pnalloc(c->pool, c->ssl->fp_ja3_str.len);
    if (c->ssl->fp_ja3_str.data == NULL) {
        /** Else we break a data stream */
        c->ssl->fp_ja3_str.len = 0;
        return NGX_ERROR;
    }

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_ssl_ja3: alloc bytes: [%d]\n", c->ssl->fp_ja3_str.len);

    /* version */
    ptr = c->ssl->fp_ja3_str.data;
    if (data + 2 > end) {
        goto error;
    }
    ptr = append_uint16(ptr, *(uint16_t*)data);
    *ptr++ = ',';
    data += 2;

    /* ciphers */
    if (data + 2 > end) {
        goto error;
    }
    num = *(uint16_t*)data;
    if (data + 2 + num > end) {
        goto error;
    }
    for (i = 2; i + 1 <= num; i += 2) {
        n = ((uint16_t)data[i]) << 8 | ((uint16_t)data[i+1]);
        if (!IS_GREASE_CODE(n)) {
            /* if (data[i] == 0x13) {
                c->ssl->fp_ja3_str.data[2] = '2'; // fixup tls1.3 version
            } */
            ptr = append_uint16(ptr, n);
            *ptr++ = '-';
        } else if (greased == 0) {
            greased = n;
        }
    }
    *(ptr-1) = ',';
    data += 2 + num;

    /* extensions */
    if (data + 2 > end) {
        goto error;
    }
    num = *(uint16_t*)data;
    if (data + 2 + num > end) {
        goto error;
    }
    for (i = 2; i <= num; i += 2) {
        n = *(uint16_t*)(data+i);
        if (!IS_GREASE_CODE(n)) {
            ptr = append_uint16(ptr, n);
            *ptr++ = '-';
        }
    }
    if (num != 0) {
        *(ptr-1) = ',';
        data += 2 + num;
    } else {
        *(ptr++) = ',';
    }


    /* groups */
    if (data + 2 > end) {
        goto error;
    }
    num = *(uint16_t*)data;
    if (data + num > end) {
        goto error;
    }
    for (i = 2; i + 1 < num; i += 2) {
        n = ((uint16_t)data[i]) << 8 | ((uint16_t)data[i+1]);
        if (!IS_GREASE_CODE(n)) {
            ptr = append_uint16(ptr, n);
            *ptr++ = '-';
        }
    }
    if (num != 0) {
        *(ptr-1) = ',';
        data += num;
    } else {
        *(ptr++) = ',';
    }

    /* formats */
    if (data + 1 > end) {
        goto error;
    }
    num = *(uint8_t*)data;
    if (data + num > end) {
        goto error;
    }
    for (i = 1; i < num; i++) {
        ptr = append_uint16(ptr, (uint16_t)data[i]);
        *ptr++ = '-';
    }
    if (num != 0) {
        data += num;
        *(ptr-1) = ',';
        *ptr-- = 0;
    }

    /* end */
    c->ssl->fp_ja3_str.len = ptr - c->ssl->fp_ja3_str.data;

    /* greased */
    c->ssl->fp_tls_greased = greased;

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_ssl_ja3: ja3 str=[%V], len=[%d]", &c->ssl->fp_ja3_str, c->ssl->fp_ja3_str.len);

    return NGX_OK;

error:
    c->ssl->fp_ja3_str.data = NULL;
    c->ssl->fp_ja3_str.len = 0;
    return NGX_ERROR;
}

/**
 * Params:
 *      c and c->ssl should be valid pointers and tested before.
 *
 * Returns:
 *      NGX_OK - c->ssl->fp_ja3_hash is alread set
 *      NGX_ERROR - something went wrong
 */
int ngx_ssl_ja3_hash(ngx_connection_t *c)
{
    ngx_md5_t ctx;
    u_char hash_buf[16];

    if (c->ssl->fp_ja3_hash.len > 0) {
        return NGX_OK;
    }

    if (ngx_ssl_ja3(c) != NGX_OK) {
        return NGX_ERROR;
    }

    c->ssl->fp_ja3_hash.len = 32;
    c->ssl->fp_ja3_hash.data = ngx_pnalloc(c->pool, c->ssl->fp_ja3_hash.len);
    if (c->ssl->fp_ja3_hash.data == NULL) {
        /** Else we can break a stream */
        c->ssl->fp_ja3_hash.len = 0;
        return NGX_ERROR;
    }

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_ssl_ja3_hash: alloc bytes: [%d]\n", c->ssl->fp_ja3_hash.len);

    ngx_md5_init(&ctx);
    ngx_md5_update(&ctx, c->ssl->fp_ja3_str.data, c->ssl->fp_ja3_str.len);
    ngx_md5_final(hash_buf, &ctx);
    ngx_hex_dump(c->ssl->fp_ja3_hash.data, hash_buf, 16);

    return NGX_OK;
}

static void
ngx_ssl_ja4_sort_uint16(uint16_t *arr, size_t n)
{
    size_t    i, j;
    uint16_t  tmp;

    for (i = 1; i < n; i++) {
        tmp = arr[i];
        j = i;
        while (j > 0 && arr[j - 1] > tmp) {
            arr[j] = arr[j - 1];
            j--;
        }
        arr[j] = tmp;
    }
}

static void
ngx_ssl_ja4_sha256_hex12(u_char *data, size_t len, u_char *out)
{
    SHA256_CTX  ctx;
    u_char      hash[SHA256_DIGEST_LENGTH];

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(hash, &ctx);

    ngx_hex_dump(out, hash, 6);
}

static u_char *
ngx_ssl_ja4_hex_list(u_char *p, const uint16_t *arr, size_t count)
{
    size_t  i;

    for (i = 0; i < count; i++) {
        if (i > 0) {
            *p++ = ',';
        }
        *p++ = hex[(arr[i] >> 12) & 0x0F];
        *p++ = hex[(arr[i] >> 8) & 0x0F];
        *p++ = hex[(arr[i] >> 4) & 0x0F];
        *p++ = hex[arr[i] & 0x0F];
    }

    return p;
}

/* Like ngx_ssl_ja4_hex_list but skips SNI and ALPN entries */
static u_char *
ngx_ssl_ja4_hex_list_no_sni_alpn(u_char *p, const uint16_t *arr, size_t count)
{
    size_t     i;
    ngx_uint_t first;

    first = 1;
    for (i = 0; i < count; i++) {
        if (arr[i] == NGX_SSL_EXT_SNI || arr[i] == NGX_SSL_EXT_ALPN) {
            continue;
        }
        if (!first) {
            *p++ = ',';
        }
        *p++ = hex[(arr[i] >> 12) & 0x0F];
        *p++ = hex[(arr[i] >> 8) & 0x0F];
        *p++ = hex[(arr[i] >> 4) & 0x0F];
        *p++ = hex[arr[i] & 0x0F];
        first = 0;
    }

    return p;
}

static inline ngx_uint_t
ngx_ssl_ja4_is_alnum(u_char c)
{
    return ((c >= '0' && c <= '9') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z'));
}

/**
 * Params:
 *      c and c->ssl should be valid pointers
 *
 * Returns:
 *      NGX_OK - c->ssl->fp_ja4_r is set (raw JA4 string, no SHA-256)
 *      NGX_ERROR - something went wrong
 *      NGX_DECLINED - data unavailable (QUIC or callback didn't fire)
 */
int ngx_ssl_ja4_raw(ngx_connection_t *c)
{
    size_t       i;
    size_t       cc, ec, ec_for_hash;
    size_t       cc_display, ec_display;
    size_t       sa_sz;
    uint16_t    *ciphers, *extensions;
    size_t       ciphers_sz, extensions_sz;
    u_char      *p;
    const char  *ver;
    u_char       a_buf[NGX_SSL_JA4_A_LEN];

    /* cache check */
    if (c->ssl->fp_ja4_r.data != NULL) {
        return NGX_OK;
    }

    /* QUIC guard: callback didn't fire */
    if (c->ssl->fp_ja4_ciphers == NULL) {
        return NGX_DECLINED;
    }

    /*
     * Step 1: Process ciphers - in-place GREASE filter, count, sort
     */
    cc = 0;
    for (i = 0; i < c->ssl->fp_ja4_ciphers_sz; i++) {
        if (!IS_GREASE_CODE(c->ssl->fp_ja4_ciphers[i])) {
            if (cc != i)
                c->ssl->fp_ja4_ciphers[cc] = c->ssl->fp_ja4_ciphers[i];
            cc++;
        }
    }
    c->ssl->fp_ja4_ciphers_sz = cc;

    ciphers = c->ssl->fp_ja4_ciphers;
    ciphers_sz = cc;

    /* display count capped at 99 per spec; hash uses full list */
    cc_display = (ciphers_sz > 99) ? 99 : ciphers_sz;

    if (ciphers_sz > 1) {
        ngx_ssl_ja4_sort_uint16(ciphers, ciphers_sz);
    }

    /*
     * Step 2: Process extensions - in-place GREASE filter, count (with SNI/ALPN),
     *         sort, then count excluding SNI/ALPN for hashing
     */
    ec = 0;
    for (i = 0; i < c->ssl->fp_ja4_extensions_sz; i++) {
        if (!IS_GREASE_CODE(c->ssl->fp_ja4_extensions[i])) {
            if (ec != i)
                c->ssl->fp_ja4_extensions[ec] = c->ssl->fp_ja4_extensions[i];
            ec++;
        }
    }
    c->ssl->fp_ja4_extensions_sz = ec;

    extensions = c->ssl->fp_ja4_extensions;
    extensions_sz = ec;

    /* display count capped at 99 per spec; hash uses full list */
    ec_display = (extensions_sz > 99) ? 99 : extensions_sz;

    if (extensions_sz > 1) {
        ngx_ssl_ja4_sort_uint16(extensions, extensions_sz);
    }

    /* Count extensions excluding SNI and ALPN for hashing.
     * Do NOT compact in-place: the original array must survive retries
     * after pool exhaustion so ec_display stays correct. */
    ec_for_hash = 0;
    for (i = 0; i < extensions_sz; i++) {
        if (extensions[i] != NGX_SSL_EXT_SNI && extensions[i] != NGX_SSL_EXT_ALPN) {
            ec_for_hash++;
        }
    }

    /*
     * Step 3: sigalgs (kept in original order)
     */
    sa_sz = c->ssl->fp_ja4_sigalgs_sz;

    /*
     * Step 4: Build _a section: t{ver}{sni}{cc}{ec}{alpn}
     */

    /* version mapping */
    switch (c->ssl->fp_ja4_version) {
    case 0x0304:
        ver = "13";
        break;
    case 0x0303:
        ver = "12";
        break;
    case 0x0302:
        ver = "11";
        break;
    case 0x0301:
        ver = "10";
        break;
    case 0x0300:
        ver = "s3";
        break;
    default:
        ver = "00";
        break;
    }

    /* _a section: t + ver(2) + sni(1) + cc(2) + ec(2) + alpn(2) */
    p = a_buf;

    *p++ = 't';                                    /* transport */
    *p++ = ver[0];                                 /* version char 1 */
    *p++ = ver[1];                                 /* version char 2 */
    *p++ = c->ssl->fp_ja4_has_sni ? 'd' : 'i';    /* SNI */
    *p++ = (u_char)('0' + (cc_display / 10));      /* cc tens */
    *p++ = (u_char)('0' + (cc_display % 10));      /* cc ones */
    *p++ = (u_char)('0' + (ec_display / 10));      /* ec tens */
    *p++ = (u_char)('0' + (ec_display % 10));      /* ec ones */

    /* ALPN first/last character */
    {
        const u_char *alpn = c->ssl->fp_first_alpn;

        if (alpn == NULL || alpn[0] == '\0') {
            *p++ = '0';
            *p++ = '0';
        } else {
            size_t  alen;
            u_char  first_byte, last_byte;

            alen = ngx_strlen(alpn);
            first_byte = (u_char) alpn[0];
            last_byte = (u_char) alpn[alen - 1];

            if (ngx_ssl_ja4_is_alnum(first_byte)
                && ngx_ssl_ja4_is_alnum(last_byte))
            {
                *p++ = first_byte;
                *p++ = last_byte;
            } else {
                /* hex mode: first nibble of hex(first_byte),
                 *           last nibble of hex(last_byte) */
                *p++ = hex[(first_byte >> 4) & 0x0F];
                *p++ = hex[last_byte & 0x0F];
            }
        }
    }

    /*
     * Step 8: Build fp_ja4_r: "{_a}_{cipher_list}_{ext_list}[_{sigalg_list}]"
     */
    {
        size_t  raw_len;
        size_t  cipher_list_len, ext_list_len, sigalg_list_len;

        /* cipher list: each cipher 4 hex + comma, minus trailing comma */
        cipher_list_len = (ciphers_sz > 0) ? ciphers_sz * 5 - 1 : 0;

        /* ext list: excludes SNI/ALPN, same as hash */
        ext_list_len = (ec_for_hash > 0) ? ec_for_hash * 5 - 1 : 0;

        /* sigalg list: same pattern */
        sigalg_list_len = (sa_sz > 0) ? sa_sz * 5 - 1 : 0;

        /* total: _a + _ + cipher_list + _ + ext_list [+ _ + sigalg_list] */
        raw_len = NGX_SSL_JA4_A_LEN + 1 + cipher_list_len + 1 + ext_list_len;
        if (sa_sz > 0) {
            raw_len += 1 + sigalg_list_len;
        }

        c->ssl->fp_ja4_r.len = raw_len;
        c->ssl->fp_ja4_r.data = ngx_pnalloc(c->pool, raw_len);
        if (c->ssl->fp_ja4_r.data == NULL) {
            c->ssl->fp_ja4_r.len = 0;
            return NGX_ERROR;
        }

        p = c->ssl->fp_ja4_r.data;
        ngx_memcpy(p, a_buf, NGX_SSL_JA4_A_LEN);  p += NGX_SSL_JA4_A_LEN;
        *p++ = '_';

        p = ngx_ssl_ja4_hex_list(p, ciphers, ciphers_sz);

        *p++ = '_';

        p = ngx_ssl_ja4_hex_list_no_sni_alpn(p, extensions, extensions_sz);

        if (sa_sz > 0) {
            *p++ = '_';
            p = ngx_ssl_ja4_hex_list(p, c->ssl->fp_ja4_sigalgs, sa_sz);
        }
    }

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0,
                  "ngx_ssl_ja4_raw: ja4_r=[%V]",
                  &c->ssl->fp_ja4_r);

    return NGX_OK;
}

/**
 * Params:
 *      c and c->ssl should be valid pointers
 *
 * Returns:
 *      NGX_OK - c->ssl->fp_ja4 and c->ssl->fp_ja4_r are set
 *      NGX_ERROR - something went wrong
 *      NGX_DECLINED - data unavailable (QUIC or callback didn't fire)
 */
int ngx_ssl_ja4(ngx_connection_t *c)
{
    int          rc;
    size_t       i;
    size_t       ec_for_hash;
    size_t       sa_sz;
    uint16_t    *ciphers, *extensions;
    size_t       ciphers_sz, extensions_sz;
    u_char      *p, *buf;
    size_t       buf_len;
    u_char       a_buf[NGX_SSL_JA4_A_LEN];
    u_char       cipher_hash[12];
    u_char       ext_hash[12];

    /* cache check */
    if (c->ssl->fp_ja4.data != NULL) {
        return NGX_OK;
    }

    /* delegate common work (GREASE filter, sort, build fp_ja4_r) to _raw */
    rc = ngx_ssl_ja4_raw(c);
    if (rc != NGX_OK) {
        return rc;  /* handles NGX_DECLINED and NGX_ERROR */
    }

    /* copy _a section from fp_ja4_r (built by _raw) */
    ngx_memcpy(a_buf, c->ssl->fp_ja4_r.data, NGX_SSL_JA4_A_LEN);

    /* Recompute ec_for_hash: extensions already GREASE-filtered and sorted
     * by _raw, only need to exclude SNI and ALPN */
    extensions = c->ssl->fp_ja4_extensions;
    extensions_sz = c->ssl->fp_ja4_extensions_sz;

    ec_for_hash = 0;
    for (i = 0; i < extensions_sz; i++) {
        if (extensions[i] != NGX_SSL_EXT_SNI && extensions[i] != NGX_SSL_EXT_ALPN) {
            ec_for_hash++;
        }
    }

    /* get ciphers and sigalgs info for hash computation */
    ciphers = c->ssl->fp_ja4_ciphers;
    ciphers_sz = c->ssl->fp_ja4_ciphers_sz;
    sa_sz = c->ssl->fp_ja4_sigalgs_sz;

    /*
     * Step 5: Compute cipher_hash
     */
    if (ciphers_sz == 0) {
        ngx_memcpy(cipher_hash, "000000000000", 12);
    } else {
        u_char  cipher_stack[NGX_SSL_JA4_HASH_BUF_SIZE];

        /* each cipher is 4 hex chars, separated by commas:
         * total = ciphers_sz * 4 + (ciphers_sz - 1)
         * max with NGX_SSL_JA4_MAX_CIPHERS=200: 200*5-1 = 999 */
        buf_len = ciphers_sz * 5 - 1;
        buf = (buf_len <= sizeof(cipher_stack)) ? cipher_stack
                                                : ngx_pnalloc(c->pool, buf_len);
        if (buf == NULL) {
            return NGX_ERROR;
        }

        p = buf;
        p = ngx_ssl_ja4_hex_list(p, ciphers, ciphers_sz);

        ngx_ssl_ja4_sha256_hex12(buf, buf_len, cipher_hash);
    }

    /*
     * Step 6: Compute ext_hash (uses ec_for_hash: excludes SNI/ALPN)
     */
    if (ec_for_hash == 0) {
        ngx_memcpy(ext_hash, "000000000000", 12);
    } else {
        u_char  ext_stack[NGX_SSL_JA4_HASH_BUF_SIZE];

        /* extensions: ec_for_hash * 5 - 1
         * if sigalgs: + 1 (underscore) + sa_sz * 5 - 1
         * max: 200*5-1 + 1 + 128*5-1 = 1639 */
        buf_len = ec_for_hash * 5 - 1;
        if (sa_sz > 0) {
            buf_len += 1 + sa_sz * 5 - 1;
        }

        buf = (buf_len <= sizeof(ext_stack)) ? ext_stack
                                             : ngx_pnalloc(c->pool, buf_len);
        if (buf == NULL) {
            return NGX_ERROR;
        }

        p = buf;
        p = ngx_ssl_ja4_hex_list_no_sni_alpn(p, extensions, extensions_sz);

        if (sa_sz > 0) {
            *p++ = '_';
            p = ngx_ssl_ja4_hex_list(p, c->ssl->fp_ja4_sigalgs, sa_sz);
        }

        ngx_ssl_ja4_sha256_hex12(buf, buf_len, ext_hash);
    }

    /*
     * Step 7: Build fp_ja4: "{_a}_{cipher_hash}_{ext_hash}"
     * Length: NGX_SSL_JA4_A_LEN + 1 + 12 + 1 + 12 = 36
     */
    c->ssl->fp_ja4.len = NGX_SSL_JA4_A_LEN + 1 + 12 + 1 + 12;
    c->ssl->fp_ja4.data = ngx_pnalloc(c->pool, c->ssl->fp_ja4.len);
    if (c->ssl->fp_ja4.data == NULL) {
        c->ssl->fp_ja4.len = 0;
        return NGX_ERROR;
    }

    p = c->ssl->fp_ja4.data;
    ngx_memcpy(p, a_buf, NGX_SSL_JA4_A_LEN);  p += NGX_SSL_JA4_A_LEN;
    *p++ = '_';
    ngx_memcpy(p, cipher_hash, 12);  p += 12;
    *p++ = '_';
    ngx_memcpy(p, ext_hash, 12);

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0,
                  "ngx_ssl_ja4: ja4=[%V], ja4_r=[%V]",
                  &c->ssl->fp_ja4, &c->ssl->fp_ja4_r);

    return NGX_OK;
}

/**
 * Params:
 *      c and h2c should be a valid pointers
 *
 * Returns:
 *      NGX_OK -- h2c->fp_str is set
 *      NGX_ERROR -- something went wrong
 */
int ngx_http2_fingerprint(ngx_connection_t *c, ngx_http_v2_connection_t *h2c)
{
    unsigned char *pstr = NULL;
    unsigned short n = 0;
    size_t i;

    if (h2c->fp_str.len > 0) {
        return NGX_OK;
    }

    n = 4 + h2c->fp_settings.len * 3
        + 10 + h2c->fp_priorities.len * 4
        + h2c->fp_pseudoheaders.len * 2;

    h2c->fp_str.data = ngx_pnalloc(c->pool, n);
    if (h2c->fp_str.data == NULL) {
        /** Else we break a stream */
        return NGX_ERROR;
    }
    pstr = h2c->fp_str.data;

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_http2_fingerprint: alloc bytes: [%d]\n", n);

    /* setting */
    for (i = 0; i < h2c->fp_settings.len; i+=5) {
        pstr = append_uint8(pstr, h2c->fp_settings.data[i]);
        *pstr++ = ':';
        pstr = append_uint32(pstr, *(uint32_t*)(h2c->fp_settings.data+i+1));
        *pstr++ = ';';
    }
    if (h2c->fp_settings.len > 0) {
        *(pstr-1) = '|';
    } else {
        *pstr++ = '|';
    }

    /* windows update */
    pstr = append_uint32(pstr, h2c->fp_windowupdate);
    *pstr++ = '|';

    /* priorities */
    for (i = 0; i < h2c->fp_priorities.len; i+=4) {
        pstr = append_uint8(pstr, h2c->fp_priorities.data[i]);
        *pstr++ = ':';
        pstr = append_uint8(pstr, h2c->fp_priorities.data[i+1]);
        *pstr++ = ':';
        pstr = append_uint8(pstr, h2c->fp_priorities.data[i+2]);
        *pstr++ = ':';
        pstr = append_uint16(pstr, (uint16_t)h2c->fp_priorities.data[i+3]+1);
        *pstr++ = ',';
    }
    if (h2c->fp_priorities.len > 0) {
        *(pstr-1) = '|';
    } else {
        *pstr++ = '|';
    }

    /* fp_pseudoheaders */
    for (i = 0; i < h2c->fp_pseudoheaders.len; i++) {
        *pstr++ = h2c->fp_pseudoheaders.data[i];
        *pstr++ = ',';
    }

    /* null terminator */
    if (h2c->fp_pseudoheaders.len > 0) {
        *--pstr = 0;
    } else {
        *pstr = 0;
    }

    h2c->fp_str.len = pstr - h2c->fp_str.data;

    h2c->fp_fingerprinted = 1;

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_http2_fingerprint: http2 fingerprint: [%V], len=[%d]\n", &h2c->fp_str, h2c->fp_str.len);

    return NGX_OK;
}
