/* Imported API files */
#ifndef included_ioam_cache_api_tojson_h
#define included_ioam_cache_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_ioam_cache_ip6_enable_disable_t_tojson (vl_api_ioam_cache_ip6_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ioam_cache_ip6_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "47705c03");
    cJSON_AddBoolToObject(o, "is_disable", a->is_disable);
    return o;
}
static inline cJSON *vl_api_ioam_cache_ip6_enable_disable_reply_t_tojson (vl_api_ioam_cache_ip6_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ioam_cache_ip6_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
