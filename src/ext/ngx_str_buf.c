//
// Created by tursom on 2021/6/22.
//

#include "ngx_str_buf.h"

ngx_str_buf_t *ngx_new_str_buf(ngx_pool_t *pool, size_t init_buf_size) {
    if (pool == NULL) {
        pool = ngx_create_pool(1024, NULL);
    }

    if (init_buf_size <= 0) {
        init_buf_size = 64;
    }

    ngx_str_buf_t *buf = ngx_palloc(pool, sizeof(ngx_str_buf_t));
    if (buf == NULL) {
        return NULL;
    }

    buf->pool = pool;
    buf->buf = ngx_palloc(pool, init_buf_size);
    if (buf->buf == NULL) {
        ngx_pfree(pool, buf);
        return NULL;
    }
    buf->buf_size = init_buf_size;
    buf->used = 0;

    return buf;
}

ngx_str_buf_t *new_ngx_str_buf_without_pool(size_t init_buf_size, ngx_log_t *log) {
    ngx_str_buf_t *buf = ngx_alloc(sizeof(ngx_str_buf_t), log);
    if (buf == NULL) {
        return NULL;
    }

    buf->log = log;
    buf->pool = NULL;
    buf->buf = ngx_alloc(init_buf_size, log);
    if (buf->buf == NULL) {
        ngx_free(buf);
        return NULL;
    }
    buf->buf_size = init_buf_size;
    buf->used = 0;

    return buf;
}

ngx_uint_t ngx_str_buf_append(ngx_str_buf_t *str_buf, const void *buf, size_t size) {
    u_char *target = ngx_str_buf_append_ptr(str_buf, size);
    if (target == NULL) {
        return 0;
    }

    memcpy(target, buf, size);
    str_buf->used += size;
    str_buf->buf[str_buf->used] = 0;
    return 1;
}

void *ngx_str_buf_append_ptr(ngx_str_buf_t *str_buf, size_t size) {
    if (str_buf->buf_size - str_buf->used - 1 < size) {
        size_t new_buf_size = str_buf->buf_size << 1;
        if (new_buf_size <= 0) new_buf_size = 16;
        while (new_buf_size < size + 1)new_buf_size <<= 1;

        u_char *old_buf = str_buf->buf;
        if (str_buf->pool != NULL) {
            str_buf->buf = ngx_palloc(str_buf->pool, new_buf_size);
        } else {
            str_buf->buf = ngx_alloc(new_buf_size, str_buf->log);
        }
        if (str_buf->buf == NULL) {
            str_buf->buf = old_buf;
            return NULL;
        }

        if (old_buf != NULL) {
            memcpy(str_buf->buf, old_buf, str_buf->used);
        }
        str_buf->buf_size = new_buf_size;
    }

    return str_buf->buf + str_buf->used;
}

ngx_str_t *ngx_str_buf_to_str(ngx_str_buf_t *str_buf) {
    ngx_str_t *str;
    if (str_buf->pool != NULL) {
        str = ngx_palloc(str_buf->pool, sizeof(ngx_str_t));
    } else {
        str = ngx_alloc(sizeof(ngx_str_t), str_buf->log);
    }
    if (str == NULL) {
        return NULL;
    }
    str->data = str_buf->buf;
    str->len = str_buf->used;
    return str;
}

ngx_str_t *ngx_str_buf_to_str_cpy(ngx_str_buf_t *str_buf) {
    return ngx_str_buf_to_str_pool(str_buf, str_buf->pool);
}

ngx_str_t *ngx_str_buf_to_str_pool(ngx_str_buf_t *str_buf, ngx_pool_t *pool) {
    ngx_str_t *str;
    if (pool != NULL) {
        str = ngx_palloc(pool, sizeof(ngx_str_t));
    } else {
        str = ngx_alloc(sizeof(ngx_str_t), str_buf->log);
    }
    if (str == NULL) {
        return NULL;
    }

    str->data = ngx_palloc(pool, str_buf->used);
    if (pool != NULL) {
        str->data = ngx_palloc(pool, str_buf->used + 1);
    } else {
        str->data = ngx_alloc(str_buf->used + 1, str_buf->log);
    }
    if (str->data == NULL) {
        if (pool != NULL) {
            ngx_pfree(pool, str);
        } else {
            ngx_free(str);
        }
        return NULL;
    }
    memcpy(str->data, str_buf->buf, str_buf->used + 1);

    str->len = str_buf->used;
    return str;
}

void ngx_finish_str_buf(ngx_str_buf_t *str_buf) {
    ngx_destroy_pool(str_buf->pool);
}
