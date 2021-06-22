//
// Created by tursom on 2021/6/18.
//

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_str_buf.h>


int main(int argc, char **argv) {
    ngx_pool_t *pool = ngx_create_pool(4096, NULL);
    ngx_str_buf_t *str_buf = ngx_new_str_buf(NULL, 0);

    for (int i = 0; i < 10; ++i) {
        char *buf = ngx_str_buf_append_ptr(str_buf, 32);
        sprintf(buf, "hello %d\n", i);
        str_buf->used += strlen(buf);
    }

    ngx_str_t *str = ngx_str_buf_to_str_pool(str_buf, pool);
    printf("%s\n", str->data);
    printf("buf size: %ld, used: %ld\n", str_buf->buf_size, str_buf->used);

    ngx_finish_str_buf(str_buf);
    ngx_destroy_pool(pool);
}
