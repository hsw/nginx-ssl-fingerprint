
/*
 * JA4 TLS fingerprint computation.
 *
 * Reads pre-captured cipher/extension/sigalg arrays from c->ssl->fp_ja4_*
 * fields (populated by the nginx JA4 patch callback) and builds the JA4
 * fingerprint string per the FoxIO JA4 specification.
 *
 * Four variants are exposed, all sharing the same _a section
 * (transport/version/sni/cc/ec/alpn) but differing in the cipher/extension
 * list content used for the hash / raw output:
 *
 *   ja4     - sorted ciphers, sorted extensions (minus SNI/ALPN), hashed
 *   ja4_r   - sorted ciphers, sorted extensions (minus SNI/ALPN), raw
 *   ja4_o   - original-order ciphers and extensions (keeps SNI/ALPN), hashed
 *   ja4_ro  - original-order ciphers and extensions (keeps SNI/ALPN), raw
 *
 * The GREASE filter is applied in-place on the shared arrays (idempotent
 * after first pass). Sorted copies live in fp_ja4_ciphers_sorted /
 * fp_ja4_extensions_sorted, allocated lazily on first sorted-variant call.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#ifdef OPENSSL_NO_DEPRECATED_3_0
#include <openssl/evp.h>
#else
#include <openssl/sha.h>
#endif

#include <nginx_ssl_fingerprint.h>


/* Stack buffer size for JA4 SHA-256 hex string computation.
 * Must be >= max(NGX_SSL_JA4_MAX_CIPHERS, NGX_SSL_JA4_MAX_EXTENSIONS +
 * NGX_SSL_JA4_MAX_SIGALGS) * 5.  Current worst case (original-order path,
 * includes SNI+ALPN): 200*5 + 1 + 128*5-1 = 1640 */
#define NGX_SSL_JA4_HASH_BUF_SIZE  2048

/* JA4 _a section: t(1) + ver(2) + sni(1) + cc(2) + ec(2) + alpn(2) = 10 chars */
#define NGX_SSL_JA4_A_LEN          10

/* TLS extension type codes used in JA4 hash exclusion */
#define NGX_SSL_EXT_SNI            0x0000
#define NGX_SSL_EXT_ALPN           0x0010

static const u_char hex[] = "0123456789abcdef";


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
#ifdef OPENSSL_NO_DEPRECATED_3_0
    EVP_MD_CTX  *ctx;
    u_char       hash[EVP_MAX_MD_SIZE];

    ctx = EVP_MD_CTX_new();
    if (ctx != NULL) {
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(ctx, data, len);
        EVP_DigestFinal_ex(ctx, hash, NULL);
        EVP_MD_CTX_free(ctx);
    } else {
        ngx_memzero(hash, EVP_MAX_MD_SIZE);
    }
#else
    SHA256_CTX  ctx;
    u_char      hash[SHA256_DIGEST_LENGTH];

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(hash, &ctx);
#endif

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


static ngx_inline ngx_uint_t
ngx_ssl_ja4_is_alnum(u_char c)
{
    return ((c >= '0' && c <= '9') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z'));
}


/*
 * GREASE-filter fp_ja4_ciphers / fp_ja4_extensions in place.
 * Idempotent: after the first pass IS_GREASE_CODE returns false for every
 * surviving element. Safe to call from any of the 4 entry points.
 */
static void
ngx_ssl_ja4_grease_filter(ngx_connection_t *c)
{
    size_t  i, n;

    n = 0;
    for (i = 0; i < c->ssl->fp_ja4_ciphers_sz; i++) {
        if (!IS_GREASE_CODE(c->ssl->fp_ja4_ciphers[i])) {
            if (n != i) {
                c->ssl->fp_ja4_ciphers[n] = c->ssl->fp_ja4_ciphers[i];
            }
            n++;
        }
    }
    c->ssl->fp_ja4_ciphers_sz = n;

    n = 0;
    for (i = 0; i < c->ssl->fp_ja4_extensions_sz; i++) {
        if (!IS_GREASE_CODE(c->ssl->fp_ja4_extensions[i])) {
            if (n != i) {
                c->ssl->fp_ja4_extensions[n] = c->ssl->fp_ja4_extensions[i];
            }
            n++;
        }
    }
    c->ssl->fp_ja4_extensions_sz = n;
}


/*
 * Lazy-alloc sorted copies of fp_ja4_ciphers / fp_ja4_extensions into
 * fp_ja4_ciphers_sorted / fp_ja4_extensions_sorted. Only called on the
 * sorted-variant code path (original == 0).
 *
 * Returns NGX_OK on success; NGX_ERROR on pool exhaustion (sorted pointers
 * cleared so the next call may retry).
 */
static int
ngx_ssl_ja4_build_sorted(ngx_connection_t *c)
{
    size_t  n_c, n_e;

    n_c = c->ssl->fp_ja4_ciphers_sz;
    n_e = c->ssl->fp_ja4_extensions_sz;

    if (c->ssl->fp_ja4_ciphers_sorted == NULL && n_c > 0) {
        c->ssl->fp_ja4_ciphers_sorted = ngx_pnalloc(c->pool,
                                                    n_c * sizeof(uint16_t));
        if (c->ssl->fp_ja4_ciphers_sorted == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(c->ssl->fp_ja4_ciphers_sorted, c->ssl->fp_ja4_ciphers,
                   n_c * sizeof(uint16_t));
        if (n_c > 1) {
            ngx_ssl_ja4_sort_uint16(c->ssl->fp_ja4_ciphers_sorted, n_c);
        }
    }

    if (c->ssl->fp_ja4_extensions_sorted == NULL && n_e > 0) {
        c->ssl->fp_ja4_extensions_sorted = ngx_pnalloc(c->pool,
                                                       n_e * sizeof(uint16_t));
        if (c->ssl->fp_ja4_extensions_sorted == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(c->ssl->fp_ja4_extensions_sorted, c->ssl->fp_ja4_extensions,
                   n_e * sizeof(uint16_t));
        if (n_e > 1) {
            ngx_ssl_ja4_sort_uint16(c->ssl->fp_ja4_extensions_sorted, n_e);
        }
    }

    return NGX_OK;
}


/*
 * Core raw-JA4 builder.
 *
 * Parameters:
 *   c        - connection (c, c->ssl, c->pool all valid)
 *   dst      - output ngx_str_t (fp_ja4_r for sorted, fp_ja4_ro for original)
 *   original - 0 = sorted path (ja4/ja4_r), 1 = original-order path (ja4_o/ja4_ro)
 *
 * Returns:
 *   NGX_OK       - *dst populated
 *   NGX_ERROR    - pool allocation failed
 *   NGX_DECLINED - capture data unavailable (callback didn't fire)
 */
static int
ngx_ssl_ja4_raw_impl(ngx_connection_t *c, ngx_str_t *dst, ngx_uint_t original)
{
    size_t       i;
    size_t       cc_display, ec_display, ec_for_hash;
    size_t       sa_sz;
    uint16_t    *ciphers, *extensions;
    size_t       ciphers_sz, extensions_sz;
    u_char      *p;
    const char  *ver;
    u_char       a_buf[NGX_SSL_JA4_A_LEN];

    /* per-variant cache check */
    if (dst->data != NULL) {
        return NGX_OK;
    }

    /* no capture data: callback didn't fire or allocation failed */
    if (c->ssl->fp_ja4_ciphers == NULL) {
        return NGX_DECLINED;
    }

    /* Step 1: GREASE-filter shared arrays (idempotent) */
    ngx_ssl_ja4_grease_filter(c);

    /* Step 2: select cipher / extension source by flag */
    if (original) {
        ciphers       = c->ssl->fp_ja4_ciphers;
        extensions    = c->ssl->fp_ja4_extensions;
    } else {
        if (ngx_ssl_ja4_build_sorted(c) != NGX_OK) {
            return NGX_ERROR;
        }
        ciphers       = c->ssl->fp_ja4_ciphers_sorted;
        extensions    = c->ssl->fp_ja4_extensions_sorted;
    }
    ciphers_sz    = c->ssl->fp_ja4_ciphers_sz;
    extensions_sz = c->ssl->fp_ja4_extensions_sz;

    /* display counts capped at 99 per spec; same for all 4 variants */
    cc_display = (ciphers_sz > 99) ? 99 : ciphers_sz;
    ec_display = (extensions_sz > 99) ? 99 : extensions_sz;

    /* Count extensions excluding SNI and ALPN for sorted-variant hash. */
    ec_for_hash = 0;
    if (!original) {
        for (i = 0; i < extensions_sz; i++) {
            if (extensions[i] != NGX_SSL_EXT_SNI
                && extensions[i] != NGX_SSL_EXT_ALPN)
            {
                ec_for_hash++;
            }
        }
    }

    /* Step 3: sigalgs (always original order, shared across variants) */
    sa_sz = c->ssl->fp_ja4_sigalgs_sz;

    /* Step 4: Build _a section: t{ver}{sni}{cc}{ec}{alpn} */

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

    p = a_buf;

#if (NGX_QUIC || NGX_COMPAT)
    *p++ = c->quic ? 'q' : 't';                    /* transport */
#else
    *p++ = 't';                                     /* transport */
#endif
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

    /* Step 5: Build *dst: "{_a}_{cipher_list}_{ext_list}[_{sigalg_list}]" */
    {
        size_t  raw_len;
        size_t  cipher_list_len, ext_list_len, sigalg_list_len;
        size_t  ext_entries;

        /* cipher list: each cipher 4 hex + comma, minus trailing comma */
        cipher_list_len = (ciphers_sz > 0) ? ciphers_sz * 5 - 1 : 0;

        /* ext list size depends on variant:
         *   sorted  -> excludes SNI/ALPN, uses ec_for_hash
         *   original -> keeps everything, uses extensions_sz */
        ext_entries = original ? extensions_sz : ec_for_hash;
        ext_list_len = (ext_entries > 0) ? ext_entries * 5 - 1 : 0;

        /* sigalg list: same pattern */
        sigalg_list_len = (sa_sz > 0) ? sa_sz * 5 - 1 : 0;

        /* total: _a + _ + cipher_list + _ + ext_list [+ _ + sigalg_list] */
        raw_len = NGX_SSL_JA4_A_LEN + 1 + cipher_list_len + 1 + ext_list_len;
        if (sa_sz > 0) {
            raw_len += 1 + sigalg_list_len;
        }

        dst->len = raw_len;
        dst->data = ngx_pnalloc(c->pool, raw_len);
        if (dst->data == NULL) {
            dst->len = 0;
            return NGX_ERROR;
        }

        p = dst->data;
        ngx_memcpy(p, a_buf, NGX_SSL_JA4_A_LEN);  p += NGX_SSL_JA4_A_LEN;
        *p++ = '_';

        p = ngx_ssl_ja4_hex_list(p, ciphers, ciphers_sz);

        *p++ = '_';

        if (original) {
            p = ngx_ssl_ja4_hex_list(p, extensions, extensions_sz);
        } else {
            p = ngx_ssl_ja4_hex_list_no_sni_alpn(p, extensions, extensions_sz);
        }

        if (sa_sz > 0) {
            *p++ = '_';
            p = ngx_ssl_ja4_hex_list(p, c->ssl->fp_ja4_sigalgs, sa_sz);
        }
    }

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0,
                  "ngx_ssl_ja4_raw_impl(original=%ui): [%V]",
                  original, dst);

    return NGX_OK;
}


/*
 * Core hashed-JA4 builder.
 *
 * Parameters:
 *   c        - connection
 *   raw      - raw-variant dst to delegate to (fp_ja4_r or fp_ja4_ro)
 *   dst      - hashed output (fp_ja4 or fp_ja4_o)
 *   original - 0 = sorted path, 1 = original-order path
 *
 * Returns NGX_OK / NGX_ERROR / NGX_DECLINED (see *_raw_impl).
 */
static int
ngx_ssl_ja4_impl(ngx_connection_t *c, ngx_str_t *raw, ngx_str_t *dst,
    ngx_uint_t original)
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

    /* per-variant cache check */
    if (dst->data != NULL) {
        return NGX_OK;
    }

    /* delegate common work (GREASE filter, sort, build raw string) */
    rc = ngx_ssl_ja4_raw_impl(c, raw, original);
    if (rc != NGX_OK) {
        return rc;
    }

    /* copy _a section from raw (they share the same _a section) */
    ngx_memcpy(a_buf, raw->data, NGX_SSL_JA4_A_LEN);

    /* select cipher / extension source matching the raw path */
    if (original) {
        ciphers    = c->ssl->fp_ja4_ciphers;
        extensions = c->ssl->fp_ja4_extensions;
    } else {
        ciphers    = c->ssl->fp_ja4_ciphers_sorted;
        extensions = c->ssl->fp_ja4_extensions_sorted;
    }
    ciphers_sz    = c->ssl->fp_ja4_ciphers_sz;
    extensions_sz = c->ssl->fp_ja4_extensions_sz;
    sa_sz = c->ssl->fp_ja4_sigalgs_sz;

    /* sorted-variant extension hash list excludes SNI/ALPN */
    ec_for_hash = 0;
    if (!original) {
        for (i = 0; i < extensions_sz; i++) {
            if (extensions[i] != NGX_SSL_EXT_SNI
                && extensions[i] != NGX_SSL_EXT_ALPN)
            {
                ec_for_hash++;
            }
        }
    }

    /* Step 6: Compute cipher_hash */
    if (ciphers_sz == 0) {
        ngx_memcpy(cipher_hash, "000000000000", 12);
    } else {
        u_char  cipher_stack[NGX_SSL_JA4_HASH_BUF_SIZE];

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

    /* Step 7: Compute ext_hash
     *   sorted  -> list excludes SNI/ALPN (ec_for_hash entries)
     *   original -> list includes everything (extensions_sz entries) */
    {
        size_t  ext_entries;

        ext_entries = original ? extensions_sz : ec_for_hash;

        if (ext_entries == 0) {
            ngx_memcpy(ext_hash, "000000000000", 12);
        } else {
            u_char  ext_stack[NGX_SSL_JA4_HASH_BUF_SIZE];

            buf_len = ext_entries * 5 - 1;
            if (sa_sz > 0) {
                buf_len += 1 + sa_sz * 5 - 1;
            }

            buf = (buf_len <= sizeof(ext_stack)) ? ext_stack
                                                 : ngx_pnalloc(c->pool, buf_len);
            if (buf == NULL) {
                return NGX_ERROR;
            }

            p = buf;
            if (original) {
                p = ngx_ssl_ja4_hex_list(p, extensions, extensions_sz);
            } else {
                p = ngx_ssl_ja4_hex_list_no_sni_alpn(p, extensions,
                                                     extensions_sz);
            }

            if (sa_sz > 0) {
                *p++ = '_';
                p = ngx_ssl_ja4_hex_list(p, c->ssl->fp_ja4_sigalgs, sa_sz);
            }

            ngx_ssl_ja4_sha256_hex12(buf, buf_len, ext_hash);
        }
    }

    /* Step 8: Build dst: "{_a}_{cipher_hash}_{ext_hash}" (36 bytes) */
    dst->len = NGX_SSL_JA4_A_LEN + 1 + 12 + 1 + 12;
    dst->data = ngx_pnalloc(c->pool, dst->len);
    if (dst->data == NULL) {
        dst->len = 0;
        return NGX_ERROR;
    }

    p = dst->data;
    ngx_memcpy(p, a_buf, NGX_SSL_JA4_A_LEN);  p += NGX_SSL_JA4_A_LEN;
    *p++ = '_';
    ngx_memcpy(p, cipher_hash, 12);  p += 12;
    *p++ = '_';
    ngx_memcpy(p, ext_hash, 12);

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0,
                  "ngx_ssl_ja4_impl(original=%ui): [%V], raw=[%V]",
                  original, dst, raw);

    return NGX_OK;
}


/*
 * Public wrappers. Each entry point may be called first; cache lives in
 * its own dst->data field, so lazy-init is independent across variants.
 */

int
ngx_ssl_ja4_raw(ngx_connection_t *c)
{
    return ngx_ssl_ja4_raw_impl(c, &c->ssl->fp_ja4_r, 0);
}


int
ngx_ssl_ja4(ngx_connection_t *c)
{
    return ngx_ssl_ja4_impl(c, &c->ssl->fp_ja4_r, &c->ssl->fp_ja4, 0);
}


int
ngx_ssl_ja4_raw_o(ngx_connection_t *c)
{
    return ngx_ssl_ja4_raw_impl(c, &c->ssl->fp_ja4_ro, 1);
}


int
ngx_ssl_ja4_o(ngx_connection_t *c)
{
    return ngx_ssl_ja4_impl(c, &c->ssl->fp_ja4_ro, &c->ssl->fp_ja4_o, 1);
}
