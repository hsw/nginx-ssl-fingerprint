
/*
 * Please make sure that you have been incuded --with-streams_ssl_moduke
 * before --add-module Else this module won't be compiled
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_md5.h>

extern int ngx_ssl_ja3(ngx_connection_t *c);
extern int ngx_ssl_ja3_hash(ngx_connection_t *c);
extern int ngx_ssl_ja4(ngx_connection_t *c);

static ngx_int_t ngx_stream_ssl_fingerprint_preread_init(ngx_conf_t *cf);

static ngx_stream_module_t  ngx_stream_ssl_fingerprint_preread_module_ctx = {
    ngx_stream_ssl_fingerprint_preread_init,  /* preconfiguration */
    NULL,                                     /* postconfiguration */
    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */
    NULL,                                     /* create server configuration */
    NULL                                      /* merge server configuration */
};

ngx_module_t  ngx_stream_ssl_fingerprint_preread_module = {
    NGX_MODULE_V1,
    &ngx_stream_ssl_fingerprint_preread_module_ctx,      /* module context */
    NULL,                                                /* module directives */
    NGX_STREAM_MODULE,                                   /* module type */
    NULL,                                                /* init master */
    NULL,                                                /* init module */
    NULL,                                                /* init process */
    NULL,                                                /* init thread */
    NULL,                                                /* exit thread */
    NULL,                                                /* exit process */
    NULL,                                                /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_stream_ssl_greased(ngx_stream_session_t *s,
                 ngx_stream_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;

    if (s->connection == NULL)
    {
        return NGX_OK;
    }

    if (s->connection->ssl == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja3(s->connection) != NGX_OK)
    {
        return NGX_OK;
    }

    v->len = 1;
    v->data = (u_char*)(s->connection->ssl->fp_tls_greased ? "1" : "0");

    v->valid = 1;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_ssl_ja3(ngx_stream_session_t *s,
                 ngx_stream_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;

    if (s->connection == NULL)
    {
        return NGX_OK;
    }

    if (s->connection->ssl == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja3(s->connection) != NGX_OK)
    {
        return NGX_OK;
    }

    v->data = s->connection->ssl->fp_ja3_str.data;
    v->len = s->connection->ssl->fp_ja3_str.len;
    v->valid = 1;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_ssl_ja3_hash(ngx_stream_session_t *s,
                 ngx_stream_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;

    if (s->connection == NULL)
    {
        return NGX_OK;
    }

    if (s->connection->ssl == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja3_hash(s->connection) != NGX_OK)
    {
        return NGX_OK;
    }

    v->data = s->connection->ssl->fp_ja3_hash.data;
    v->len = s->connection->ssl->fp_ja3_hash.len;
    v->valid = 1;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_ssl_ja4(ngx_stream_session_t *s,
                 ngx_stream_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;

    if (s->connection == NULL)
    {
        return NGX_OK;
    }

    if (s->connection->ssl == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja4(s->connection) != NGX_OK)
    {
        return NGX_OK;
    }

    v->data = s->connection->ssl->fp_ja4_str.data;
    v->len = s->connection->ssl->fp_ja4_str.len;
    v->valid = 1;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_stream_variable_t  ngx_stream_ssl_fingerprint_variables_list[] = {

    {   ngx_string("stream_ssl_greased"),
        NULL,
        ngx_stream_ssl_greased,
        0, 0, 0
    },

    {   ngx_string("stream_ssl_ja3"),
        NULL,
        ngx_stream_ssl_ja3,
        0, 0, 0
    },

    {   ngx_string("stream_ssl_ja3_hash"),
        NULL,
        ngx_stream_ssl_ja3_hash,
        0, 0, 0
    },

    {   ngx_string("stream_ssl_ja4"),
        NULL,
        ngx_stream_ssl_ja4,
        0, 0, 0
    },

    ngx_stream_null_variable
};

static ngx_int_t
ngx_stream_ssl_fingerprint_preread_init(ngx_conf_t *cf)
{
    ngx_stream_variable_t  *var, *v;

    for (v = ngx_stream_ssl_fingerprint_variables_list; v->name.len; v++) {

        var = ngx_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }
        /** NOTE: update it, if set_handler will be needed */
        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

