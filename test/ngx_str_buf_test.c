//
// Created by tursom on 2021/6/18.
//

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_str_buf.h>

int main(int argc, char **argv) {
    ngx_pool_t *pool = ngx_create_pool(1024, NULL);
    ngx_build_string(str_buf);

    //ngx_str_t buf, split = ngx_string("-");
    //buf.len = 1;
    //buf.data = ngx_alloc(2, NULL);
    for (int i = 0; i < 30; ++i) {
        //*buf.data = i % 10 + '0';
        //ngx_str_buf_append_multi(str_buf, buf, buf, buf, buf, buf, buf, buf, buf, split);
        char *buf = ngx_str_buf_alloc(str_buf, 32);
        sprintf(buf, "num %d\n", i + 1);
        if (!ngx_str_buf_used(str_buf, strlen(buf))) {
            break;
        }
    }
    ngx_str_buf_used(str_buf, -1);

    ngx_str_t *str = ngx_str_buf_to_str(str_buf, pool);
    printf("%s\n", str->data);
    printf("buf size: %ld, used: %ld\n",
           ngx_str_buf_get_buf_size(str_buf),
           ngx_str_buf_get_used(str_buf));

    ngx_build_end(str_buf);
    ngx_destroy_pool(pool);
}
