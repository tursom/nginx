
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_list_t *
ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    ngx_list_t  *list;

    list = ngx_palloc(pool, sizeof(ngx_list_t));
    if (list == NULL) {
        return NULL;
    }

    if (ngx_list_init(list, pool, n, size) != NGX_OK) {
        return NULL;
    }

    return list;
}


void *
ngx_list_push(ngx_list_t *l)
{
    void             *elt;
    ngx_list_part_t  *last;

    last = l->last;

    if (last->nelts == l->nalloc) {

        /* the last part is full, allocate a new list part */

        last = ngx_palloc(l->pool, sizeof(ngx_list_part_t));
        if (last == NULL) {
            return NULL;
        }

        last->elts = ngx_palloc(l->pool, l->nalloc * l->size);
        if (last->elts == NULL) {
            return NULL;
        }

        last->nelts = 0;
        last->next = NULL;

        l->last->next = last;
        l->last = last;
    }

    elt = (char *) last->elts + l->size * last->nelts;
    last->nelts++;

    return elt;
}

ngx_list_iter_t ngx_list_iter(ngx_list_t *list) {
    ngx_list_iter_t iter = {&list->part, list->size, 0};
    return iter;
}

ngx_int_t ngx_list_iter_has_next(const ngx_list_iter_t *iter) {
    return iter->i < iter->part->nelts || iter->part->next != NULL;
}

void *ngx_list_iter_next(ngx_list_iter_t *iter) {
    void *data = NULL;
    if (iter->i >= iter->part->nelts) {
        if (iter->part->next != NULL) {
            iter->part = iter->part->next;
            iter->i = 0;
        } else {
            return NULL;
        }
    }
    data = (void *) ((ngx_int_t) iter->part->elts + iter->i * iter->size);
    iter->i++;
    return data;
}
