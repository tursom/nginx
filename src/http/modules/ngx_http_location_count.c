

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static void *ngx_http_location_count_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_location_count_create_cmd_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_location_count_shm_zone_init(ngx_shm_zone_t *zone, void *data);

static ngx_int_t ngx_http_location_count_handler(ngx_http_request_t *r);


typedef struct {

    ssize_t shmsize;
    ngx_slab_pool_t *pool;

    //ngx_uint_t interval;
    //ngx_uint_t client_count;

} ngx_http_location_conf_t;


ngx_command_t ngx_http_location_count_cmd[] = {

        {
                ngx_string("count"),
                NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
                ngx_http_location_count_create_cmd_set,
                NGX_HTTP_LOC_CONF_OFFSET,
                0, NULL
        },
        ngx_null_command
};


static ngx_http_module_t ngx_http_location_count_ctx = {

        NULL, //preconfigure
        NULL, //postconfigure

        NULL, //ngx_http_location_count_create_main_conf, // create main
        NULL, // init main

        NULL, //ngx_http_location_count_create_server_conf, //create server
        NULL, //init server

        ngx_http_location_count_create_loc_conf,
        NULL,

};


ngx_module_t ngx_http_location_count_module = {

        NGX_MODULE_V1,
        &ngx_http_location_count_ctx,
        ngx_http_location_count_cmd,
        NGX_HTTP_MODULE,

        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,

        NGX_MODULE_V1_PADDING

};

ngx_int_t ngx_http_location_count_shm_zone_init(ngx_shm_zone_t *zone, void *data) {


    return NGX_OK;
}


ngx_int_t ngx_http_location_count_handler(ngx_http_request_t *r) {


    struct sockaddr_in *client_addr = (struct sockaddr_in *) r->connection->sockaddr;

    // key , value

    //
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, ngx_errno, "ngx_http_location_count_handler");

    return NGX_OK;

}


static void *ngx_http_location_count_create_loc_conf(ngx_conf_t *cf) {

    ngx_http_location_conf_t *conf = ngx_palloc(cf->pool, sizeof(ngx_http_location_conf_t));
    if (conf == NULL) {

        return NULL;

    }
    ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno, "ngx_http_location_count_create_loc_conf");


    return conf;

}

// nginx.conf --> count
// curl -I http://localhost/test
static char *ngx_http_location_count_create_cmd_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {


    ngx_http_location_conf_t *lconf = (ngx_http_location_conf_t *) conf;
    ngx_str_t name = ngx_string("location_count_slab");

    lconf->shmsize = 128 * 1024;

    ngx_shm_zone_t *zone = ngx_shared_memory_add(cf, &name, lconf->shmsize, &ngx_http_location_count_module);
    if (zone == NULL) {
        return NGX_CONF_ERROR;
    }

    zone->init = ngx_http_location_count_shm_zone_init;
    zone->data = lconf;

    ngx_http_core_loc_conf_t *corecf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    corecf->handler = ngx_http_location_count_handler;

    ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno, "ngx_http_location_count_create_cmd_set");


    return NULL;

}

