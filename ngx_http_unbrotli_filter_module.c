
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <brotli/decode.h>
//#include <zlib.h>
#define Z_NO_FLUSH      0
#define Z_SYNC_FLUSH    2
#define Z_FINISH        4


typedef struct {
    ngx_flag_t           enable;
    ngx_bufs_t           bufs;
} ngx_http_unbrotli_conf_t;


typedef struct {
    ngx_chain_t         *in;
    ngx_chain_t         *free;
    ngx_chain_t         *busy;
    ngx_chain_t         *out;
    ngx_chain_t        **last_out;

    ngx_buf_t           *in_buf;
    ngx_buf_t           *out_buf;
    ngx_int_t            bufs;

    unsigned             started:1;
    unsigned             flush:4;
    unsigned             redo:1;
    unsigned             done:1;
    unsigned             nomem:1;

    BrotliDecoderState  *brotli_decoder;
    ngx_http_request_t  *request;
} ngx_http_unbrotli_ctx_t;


static ngx_int_t ngx_http_unbrotli_check_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_unbrotli_filter_inflate_start(ngx_http_request_t *r,
    ngx_http_unbrotli_ctx_t *ctx);
static ngx_int_t ngx_http_unbrotli_filter_add_data(ngx_http_request_t *r,
    ngx_http_unbrotli_ctx_t *ctx);
static ngx_int_t ngx_http_unbrotli_filter_get_buf(ngx_http_request_t *r,
    ngx_http_unbrotli_ctx_t *ctx);
static ngx_int_t ngx_http_unbrotli_filter_inflate(ngx_http_request_t *r,
    ngx_http_unbrotli_ctx_t *ctx);
static ngx_int_t ngx_http_unbrotli_filter_inflate_end(ngx_http_request_t *r,
    ngx_http_unbrotli_ctx_t *ctx);

static void *ngx_http_unbrotli_filter_alloc(void *opaque, size_t size);
static void ngx_http_unbrotli_filter_free(void *opaque, void *address);

static ngx_int_t ngx_http_unbrotli_filter_init(ngx_conf_t *cf);
static void *ngx_http_unbrotli_create_conf(ngx_conf_t *cf);
static char *ngx_http_unbrotli_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_command_t  ngx_http_unbrotli_filter_commands[] = {

    { ngx_string("unbrotli"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_unbrotli_conf_t, enable),
      NULL },

    { ngx_string("unbrotli_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_unbrotli_conf_t, bufs),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_unbrotli_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_unbrotli_filter_init,           /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_unbrotli_create_conf,           /* create location configuration */
    ngx_http_unbrotli_merge_conf             /* merge location configuration */
};


ngx_module_t  ngx_http_unbrotli_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_unbrotli_filter_module_ctx,    /* module context */
    ngx_http_unbrotli_filter_commands,       /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_unbrotli_header_filter(ngx_http_request_t *r)
{
    ngx_http_unbrotli_ctx_t   *ctx;
    ngx_http_unbrotli_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_unbrotli_filter_module);

    /* TODO support multiple content-codings */
    /* TODO always unbrotli - due to configuration or module request */
    /* TODO ignore content encoding? */

    if (!conf->enable
        || r->headers_out.content_encoding == NULL
        || r->headers_out.content_encoding->value.len != 2
        || ngx_strncasecmp(r->headers_out.content_encoding->value.data,
                           (u_char *) "br", 2) != 0)
    {
        return ngx_http_next_header_filter(r);
    }

    r->gzip_vary = 1;

    if (ngx_http_unbrotli_check_request(r) == NGX_OK) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_unbrotli_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_unbrotli_filter_module);

    ctx->request = r;

    r->filter_need_in_memory = 1;

    r->headers_out.content_encoding->hash = 0;
    r->headers_out.content_encoding = NULL;

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_unbrotli_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int                     rc;
    ngx_uint_t              flush;
    ngx_chain_t            *cl;
    ngx_http_unbrotli_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_unbrotli_filter_module);

    if (ctx == NULL || ctx->done) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http unbrotli filter");

    if (!ctx->started) {
        if (ngx_http_unbrotli_filter_inflate_start(r, ctx) != NGX_OK) {
            goto failed;
        }
    }

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            goto failed;
        }
    }

    if (ctx->nomem) {

        /* flush busy buffers */

        if (ngx_http_next_body_filter(r, NULL) == NGX_ERROR) {
            goto failed;
        }

        cl = NULL;

        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
                                (ngx_buf_tag_t) &ngx_http_unbrotli_filter_module);
        ctx->nomem = 0;
        flush = 0;

    } else {
        flush = ctx->busy ? 1 : 0;
    }

    for ( ;; ) {

        /* cycle while we can write to a client */

        for ( ;; ) {

            /* cycle while there is data to feed brotli and ... */

            rc = ngx_http_unbrotli_filter_add_data(r, ctx);

            if (rc == NGX_DECLINED) {
                break;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }


            /* ... there are buffers to write brotli output */

            rc = ngx_http_unbrotli_filter_get_buf(r, ctx);

            if (rc == NGX_DECLINED) {
                break;
            }

            if (rc == NGX_ERROR) {
                goto failed;
            }

            rc = ngx_http_unbrotli_filter_inflate(r, ctx);

            if (rc == NGX_OK) {
                break;
            }

            if (rc == NGX_ERROR) {
                goto failed;
            }

            /* rc == NGX_AGAIN */
        }

        if (ctx->out == NULL && !flush) {
            return ctx->busy ? NGX_AGAIN : NGX_OK;
        }

        rc = ngx_http_next_body_filter(r, ctx->out);

        if (rc == NGX_ERROR) {
            goto failed;
        }

        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                                (ngx_buf_tag_t) &ngx_http_unbrotli_filter_module);
        ctx->last_out = &ctx->out;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "unbrotli out: %p", ctx->out);

        ctx->nomem = 0;
        flush = 0;

        if (ctx->done) {
            return rc;
        }
    }

    /* unreachable */

failed:

    ctx->done = 1;

    return NGX_ERROR;
}


static /* const */ char kEncoding[] = "br";
static const size_t kEncodingLen = 2;

static ngx_int_t check_accept_encoding(ngx_http_request_t* req) {
  ngx_table_elt_t* accept_encoding_entry;
  ngx_str_t* accept_encoding;
  u_char* cursor;
  u_char* end;
  u_char before;
  u_char after;

  accept_encoding_entry = req->headers_in.accept_encoding;
  if (accept_encoding_entry == NULL) return NGX_DECLINED;
  accept_encoding = &accept_encoding_entry->value;

  cursor = accept_encoding->data;
  end = cursor + accept_encoding->len;
  while (1) {
    u_char digit;
    /* It would be an idiotic idea to rely on compiler to produce performant
       binary, that is why we just do -1 at every call site. */
    cursor = ngx_strcasestrn(cursor, kEncoding, kEncodingLen - 1);
    if (cursor == NULL) return NGX_DECLINED;
    before = (cursor == accept_encoding->data) ? ' ' : cursor[-1];
    cursor += kEncodingLen;
    after = (cursor >= end) ? ' ' : *cursor;
    if (before != ',' && before != ' ') continue;
    if (after != ',' && after != ' ' && after != ';') continue;

    /* Check for ";q=0[.[0[0[0]]]]" */
    while (*cursor == ' ') cursor++;
    if (*(cursor++) != ';') break;
    while (*cursor == ' ') cursor++;
    if (*(cursor++) != 'q') break;
    while (*cursor == ' ') cursor++;
    if (*(cursor++) != '=') break;
    while (*cursor == ' ') cursor++;
    if (*(cursor++) != '0') break;
    if (*(cursor++) != '.') return NGX_DECLINED; /* ;q=0, */
    digit = *(cursor++);
    if (digit < '0' || digit > '9') return NGX_DECLINED; /* ;q=0., */
    if (digit > '0') break;
    digit = *(cursor++);
    if (digit < '0' || digit > '9') return NGX_DECLINED; /* ;q=0.0, */
    if (digit > '0') break;
    digit = *(cursor++);
    if (digit < '0' || digit > '9') return NGX_DECLINED; /* ;q=0.00, */
    if (digit > '0') break;
    return NGX_DECLINED; /* ;q=0.000 */
  }
  return NGX_OK;
}


static ngx_int_t
ngx_http_unbrotli_check_request(ngx_http_request_t* req) {
  if (req != req->main) return NGX_DECLINED;
  if (check_accept_encoding(req) != NGX_OK) return NGX_DECLINED;
  return NGX_OK;
}


static ngx_int_t
ngx_http_unbrotli_filter_inflate_start(ngx_http_request_t *r,
    ngx_http_unbrotli_ctx_t *ctx)
{
    if ((ctx->brotli_decoder = BrotliDecoderCreateInstance(
        ngx_http_unbrotli_filter_alloc,
        ngx_http_unbrotli_filter_free,
        ctx
    )) == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "BrotliDecoderCreateInstance failed");
        return NGX_ERROR;
    }

    ctx->started = 1;

    ctx->last_out = &ctx->out;
    ctx->flush = Z_NO_FLUSH;

    return NGX_OK;
}


static ngx_int_t
ngx_http_unbrotli_filter_add_data(ngx_http_request_t *r,
    ngx_http_unbrotli_ctx_t *ctx)
{
    size_t avail_in;
    if ((ctx->in_buf && ngx_buf_size(ctx->in_buf)) || ctx->flush != Z_NO_FLUSH || ctx->redo) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "unbrotli in: %p", ctx->in);

    if (ctx->in == NULL) {
        return NGX_DECLINED;
    }

    ctx->in_buf = ctx->in->buf;
    ctx->in = ctx->in->next;
    avail_in = ngx_buf_size(ctx->in_buf);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "unbrotli in_buf:%p ni:%p ai:%ud",
                   ctx->in_buf,
                   ctx->in_buf->pos, avail_in);

    if (ctx->in_buf->last_buf || ctx->in_buf->last_in_chain) {
        ctx->flush = Z_FINISH;

    } else if (ctx->in_buf->flush) {
        ctx->flush = Z_SYNC_FLUSH;

    } else if (avail_in == 0) {
        /* ctx->flush == Z_NO_FLUSH */
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_unbrotli_filter_get_buf(ngx_http_request_t *r,
    ngx_http_unbrotli_ctx_t *ctx)
{
    ngx_http_unbrotli_conf_t  *conf;

    if (ctx->out_buf && ctx->out_buf->end > ctx->out_buf->last) {
        return NGX_OK;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_unbrotli_filter_module);

    if (ctx->free) {
        ctx->out_buf = ctx->free->buf;
        ctx->free = ctx->free->next;

        ctx->out_buf->flush = 0;

    } else if (ctx->bufs < conf->bufs.num) {

        ctx->out_buf = ngx_create_temp_buf(r->pool, conf->bufs.size);
        if (ctx->out_buf == NULL) {
            return NGX_ERROR;
        }

        ctx->out_buf->tag = (ngx_buf_tag_t) &ngx_http_unbrotli_filter_module;
        ctx->out_buf->recycled = 1;
        ctx->bufs++;

    } else {
        ctx->nomem = 1;
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_unbrotli_filter_inflate(ngx_http_request_t *r,
    ngx_http_unbrotli_ctx_t *ctx)
{
    int           rc;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;
    uint8_t      *next_in, *next_out;
    size_t        avail_in, avail_out;

    next_in = ctx->in_buf->pos;
    avail_in = ngx_buf_size(ctx->in_buf);
    next_out = ctx->out_buf->last;
    avail_out = ctx->out_buf->end - ctx->out_buf->last;

    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "inflate in: ni:%p no:%p ai:%ud ao:%ud fl:%d redo:%d",
                   next_in, next_out,
                   avail_in, avail_out,
                   ctx->flush, ctx->redo);

    rc = BrotliDecoderDecompressStream(
        ctx->brotli_decoder,
        &avail_in,
        (const uint8_t **)&next_in,
        &avail_out,
        &next_out,
        NULL
    );

    if (rc == BROTLI_DECODER_RESULT_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "BrotliDecoderDecompressStream() failed: %d, %d", ctx->flush, rc);
        return NGX_ERROR;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "inflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                   next_in, next_out,
                   avail_in, avail_out,
                   rc);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "unbrotli in_buf:%p pos:%p",
                   ctx->in_buf, ctx->in_buf->pos);

    ctx->in_buf->pos = next_in;
    ctx->out_buf->last = avail_out ? next_out : ctx->out_buf->end;

    if (avail_out == 0) {

        /* brotli wants to output some more data */

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = ctx->out_buf;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;
        ctx->out_buf = NULL;

        ctx->redo = 1;

        return NGX_AGAIN;
    }

    ctx->redo = 0;

    if (ctx->flush == Z_SYNC_FLUSH) {

        ctx->flush = Z_NO_FLUSH;

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        b = ctx->out_buf;

        if (ngx_buf_size(b) == 0) {

            b = ngx_calloc_buf(ctx->request->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

        } else {
            ctx->out_buf = NULL;
        }

        b->flush = 1;

        cl->buf = b;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        return NGX_OK;
    }

    if (ctx->flush == Z_FINISH && avail_in == 0) {

        if (rc != BROTLI_DECODER_RESULT_SUCCESS) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "BrotliDecoderDecompressStream() returned %d on response end", rc);
            return NGX_ERROR;
        }

        if (ngx_http_unbrotli_filter_inflate_end(r, ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    if (ctx->in == NULL) {

        b = ctx->out_buf;

        if (ngx_buf_size(b) == 0) {
            return NGX_OK;
        }

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        ctx->out_buf = NULL;

        cl->buf = b;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        return NGX_OK;
    }

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_unbrotli_filter_inflate_end(ngx_http_request_t *r,
    ngx_http_unbrotli_ctx_t *ctx)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "unbrotli inflate end");

    BrotliDecoderDestroyInstance(ctx->brotli_decoder);

    b = ctx->out_buf;

    if (ngx_buf_size(b) == 0) {

        b = ngx_calloc_buf(ctx->request->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;
    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;
    b->sync = 1;

    ctx->done = 1;

    return NGX_OK;
}


static void *
ngx_http_unbrotli_filter_alloc(void *opaque, size_t size)
{
    ngx_http_unbrotli_ctx_t *ctx = opaque;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "unbrotli alloc: size:%zu",
                   size);

    return ngx_palloc(ctx->request->pool, size);
}


static void
ngx_http_unbrotli_filter_free(void *opaque, void *address)
{
#if 0
    ngx_http_unbrotli_ctx_t *ctx = opaque;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "unbrotli free: %p", address);
#endif
}


static void *
ngx_http_unbrotli_create_conf(ngx_conf_t *cf)
{
    ngx_http_unbrotli_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_unbrotli_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->bufs.num = 0;
     */

    conf->enable = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_unbrotli_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_unbrotli_conf_t *prev = parent;
    ngx_http_unbrotli_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              (128 * 1024) / ngx_pagesize, ngx_pagesize);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_unbrotli_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_unbrotli_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_unbrotli_body_filter;

    return NGX_OK;
}
