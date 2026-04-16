
/*
 * Obj: nginx_ssl_fingerprint.c
 */

#ifndef NGINX_SSL_FINGERPRINT_H_
#define NGINX_SSL_FINGERPRINT_H_ 1


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define IS_GREASE_CODE(code) \
    (((code) & 0x0f0f) == 0x0a0a && ((code) & 0xff) == ((code) >> 8))

int ngx_ssl_ja3(ngx_connection_t *c);
int ngx_ssl_ja3_hash(ngx_connection_t *c);
int ngx_http2_fingerprint(ngx_connection_t *c, ngx_http_v2_connection_t *h2c);

#if (NGX_SSL_JA4)
int ngx_ssl_ja4_raw(ngx_connection_t *c);
int ngx_ssl_ja4(ngx_connection_t *c);
int ngx_ssl_ja4_raw_o(ngx_connection_t *c);
int ngx_ssl_ja4_o(ngx_connection_t *c);
#endif /* NGX_SSL_JA4 */

#endif /** NGINX_SSL_FINGERPRINT_H_ */
