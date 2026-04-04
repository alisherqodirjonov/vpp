/* Imported API files */
#ifndef included_http_static_api_fromjson_h
#define included_http_static_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_http_static_enable_v4_t *vl_api_http_static_enable_v4_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_http_static_enable_v4_t);
    vl_api_http_static_enable_v4_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "fifo_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->fifo_size);

    item = cJSON_GetObjectItem(o, "cache_size_limit");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cache_size_limit);

    item = cJSON_GetObjectItem(o, "max_age");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->max_age);

    item = cJSON_GetObjectItem(o, "keepalive_timeout");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->keepalive_timeout);

    item = cJSON_GetObjectItem(o, "max_body_size");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->max_body_size);

    item = cJSON_GetObjectItem(o, "prealloc_fifos");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->prealloc_fifos);

    item = cJSON_GetObjectItem(o, "private_segment_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->private_segment_size);

    item = cJSON_GetObjectItem(o, "www_root");
    if (!item) goto error;
    strncpy_s((char *)a->www_root, sizeof(a->www_root), cJSON_GetStringValue(item), sizeof(a->www_root) - 1);

    item = cJSON_GetObjectItem(o, "uri");
    if (!item) goto error;
    strncpy_s((char *)a->uri, sizeof(a->uri), cJSON_GetStringValue(item), sizeof(a->uri) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_http_static_enable_v4_reply_t *vl_api_http_static_enable_v4_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_http_static_enable_v4_reply_t);
    vl_api_http_static_enable_v4_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_http_static_enable_v5_t *vl_api_http_static_enable_v5_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_http_static_enable_v5_t);
    vl_api_http_static_enable_v5_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "fifo_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->fifo_size);

    item = cJSON_GetObjectItem(o, "cache_size_limit");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cache_size_limit);

    item = cJSON_GetObjectItem(o, "max_age");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->max_age);

    item = cJSON_GetObjectItem(o, "keepalive_timeout");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->keepalive_timeout);

    item = cJSON_GetObjectItem(o, "max_body_size");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->max_body_size);

    item = cJSON_GetObjectItem(o, "rx_buff_thresh");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->rx_buff_thresh);

    item = cJSON_GetObjectItem(o, "prealloc_fifos");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->prealloc_fifos);

    item = cJSON_GetObjectItem(o, "private_segment_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->private_segment_size);

    item = cJSON_GetObjectItem(o, "www_root");
    if (!item) goto error;
    strncpy_s((char *)a->www_root, sizeof(a->www_root), cJSON_GetStringValue(item), sizeof(a->www_root) - 1);

    item = cJSON_GetObjectItem(o, "uri");
    if (!item) goto error;
    strncpy_s((char *)a->uri, sizeof(a->uri), cJSON_GetStringValue(item), sizeof(a->uri) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_http_static_enable_v5_reply_t *vl_api_http_static_enable_v5_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_http_static_enable_v5_reply_t);
    vl_api_http_static_enable_v5_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
