/* Imported API files */
#ifndef included_ioam_cache_api_fromjson_h
#define included_ioam_cache_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_ioam_cache_ip6_enable_disable_t *vl_api_ioam_cache_ip6_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ioam_cache_ip6_enable_disable_t);
    vl_api_ioam_cache_ip6_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_disable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_disable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ioam_cache_ip6_enable_disable_reply_t *vl_api_ioam_cache_ip6_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ioam_cache_ip6_enable_disable_reply_t);
    vl_api_ioam_cache_ip6_enable_disable_reply_t *a = cJSON_malloc(l);

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
