/* Imported API files */
#ifndef included_http_static_api_tojson_h
#define included_http_static_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_http_static_enable_v4_t_tojson (vl_api_http_static_enable_v4_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "http_static_enable_v4");
    cJSON_AddStringToObject(o, "_crc", "37540bfc");
    cJSON_AddNumberToObject(o, "fifo_size", a->fifo_size);
    cJSON_AddNumberToObject(o, "cache_size_limit", a->cache_size_limit);
    cJSON_AddNumberToObject(o, "max_age", a->max_age);
    cJSON_AddNumberToObject(o, "keepalive_timeout", a->keepalive_timeout);
    cJSON_AddNumberToObject(o, "max_body_size", a->max_body_size);
    cJSON_AddNumberToObject(o, "prealloc_fifos", a->prealloc_fifos);
    cJSON_AddNumberToObject(o, "private_segment_size", a->private_segment_size);
    cJSON_AddStringToObject(o, "www_root", (char *)a->www_root);
    cJSON_AddStringToObject(o, "uri", (char *)a->uri);
    return o;
}
static inline cJSON *vl_api_http_static_enable_v4_reply_t_tojson (vl_api_http_static_enable_v4_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "http_static_enable_v4_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_http_static_enable_v5_t_tojson (vl_api_http_static_enable_v5_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "http_static_enable_v5");
    cJSON_AddStringToObject(o, "_crc", "8bf84069");
    cJSON_AddNumberToObject(o, "fifo_size", a->fifo_size);
    cJSON_AddNumberToObject(o, "cache_size_limit", a->cache_size_limit);
    cJSON_AddNumberToObject(o, "max_age", a->max_age);
    cJSON_AddNumberToObject(o, "keepalive_timeout", a->keepalive_timeout);
    cJSON_AddNumberToObject(o, "max_body_size", a->max_body_size);
    cJSON_AddNumberToObject(o, "rx_buff_thresh", a->rx_buff_thresh);
    cJSON_AddNumberToObject(o, "prealloc_fifos", a->prealloc_fifos);
    cJSON_AddNumberToObject(o, "private_segment_size", a->private_segment_size);
    cJSON_AddStringToObject(o, "www_root", (char *)a->www_root);
    cJSON_AddStringToObject(o, "uri", (char *)a->uri);
    return o;
}
static inline cJSON *vl_api_http_static_enable_v5_reply_t_tojson (vl_api_http_static_enable_v5_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "http_static_enable_v5_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
