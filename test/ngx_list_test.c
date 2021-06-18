//
// Created by tursom on 2021/6/18.
//

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_list.h"


int main(int argc, char **argv) {
    ngx_pool_t *pool = ngx_create_pool(4096, NULL);
    ngx_list_t *list = ngx_list_create(pool, 10, sizeof(ngx_str_t));

    for (int i = 0; i < 32; i++) {
        ngx_str_t *str = ngx_list_push(list);
        char *buf = ngx_palloc(pool, 32);
        sprintf(buf, "hello %d", i);
        str->len = strlen(buf);
        str->data = (u_char *) buf;
    }

    ngx_list_iter_t iter = ngx_list_iter(list);
    while (ngx_list_iter_has_next(&iter)) {
        ngx_str_t *str = ngx_list_iter_next(&iter);
        printf("%s\n", str->data);
    }

    ngx_destroy_pool(pool);
}
