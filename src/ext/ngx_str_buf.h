//
// Created by tursom on 2021/6/22.
//

#ifndef NGINX_NGX_STR_BUF_H
#define NGINX_NGX_STR_BUF_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_string.h>

typedef struct ngx_str_buf_s ngx_str_buf_t;

/**
* create an new nginx string buffer
* @param pool to store string buffer
*        if NULL then will alloc new one by str_buf
* @param init_buf_size
* @return
*/
ngx_str_buf_t *ngx_new_str_buf(ngx_pool_t *pool, size_t init_buf_size);

void ngx_finish_str_buf(ngx_str_buf_t *str_buf);

void ngx_reset_str_buf(ngx_str_buf_t *str_buf);

ngx_uint_t ngx_str_buf_append(ngx_str_buf_t *str_buf, const ngx_str_t *str);

extern ngx_str_t NGX_STR_BUF_APPEND_END;

#define ngx_str_buf_append_multi(str_buf, ...) ngx_str_buf_append_multi__(str_buf, __VA_ARGS__, NGX_STR_BUF_APPEND_END)

ngx_uint_t ngx_str_buf_append_multi__(ngx_str_buf_t *str_buf, ...);

void *ngx_str_buf_alloc(ngx_str_buf_t *str_buf, size_t size);

ngx_uint_t ngx_str_buf_used(ngx_str_buf_t *str_buf, size_t size);

ngx_str_t *ngx_str_buf_to_str(ngx_str_buf_t *str_buf, ngx_pool_t *pool);

ngx_str_t *ngx_str_buf_to_str_snap(ngx_str_buf_t *str_buf);

ngx_str_t *ngx_str_buf_to_str_cpy(ngx_str_buf_t *str_buf);

size_t ngx_str_buf_get_buf_size(ngx_str_buf_t *str_buf);

size_t ngx_str_buf_get_used(ngx_str_buf_t *str_buf);

#define ngx_build_string(builder) ngx_str_buf_t * builder = ngx_new_str_buf(NULL, 0)
#define ngx_build_end(builder) ngx_finish_str_buf(builder)

#endif //NGINX_NGX_STR_BUF_H
