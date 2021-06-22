//
// Created by tursom on 2021/6/22.
//

#ifndef NGINX_NGX_STR_BUF_H
#define NGINX_NGX_STR_BUF_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_string.h>

typedef struct {
    u_char *buf;
    size_t used;
    size_t buf_size;
    ngx_pool_t *pool;
    ngx_log_t *log;
} ngx_str_buf_t;

ngx_str_buf_t *ngx_new_str_buf(ngx_pool_t *pool, size_t init_buf_size);

ngx_str_buf_t *new_ngx_str_buf_without_pool(size_t init_buf_size, ngx_log_t *log);

void ngx_finish_str_buf(ngx_str_buf_t *str_buf);

ngx_uint_t ngx_str_buf_append(ngx_str_buf_t *str_buf, const void *buf, size_t size);

void *ngx_str_buf_append_ptr(ngx_str_buf_t *str_buf, size_t size);

ngx_str_t *ngx_str_buf_to_str(ngx_str_buf_t *str_buf);

ngx_str_t *ngx_str_buf_to_str_cpy(ngx_str_buf_t *str_buf);

ngx_str_t *ngx_str_buf_to_str_pool(ngx_str_buf_t *str_buf, ngx_pool_t *pool);

#endif //NGINX_NGX_STR_BUF_H
