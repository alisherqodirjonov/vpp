/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#ifndef included_mss_clamp_api_tojson_h
#define included_mss_clamp_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_mss_clamp_dir_t_tojson (vl_api_mss_clamp_dir_t a) {
    cJSON *array = cJSON_CreateArray();
    if (a & MSS_CLAMP_DIR_RX)
       cJSON_AddItemToArray(array, cJSON_CreateString("MSS_CLAMP_DIR_RX"));
    if (a & MSS_CLAMP_DIR_TX)
       cJSON_AddItemToArray(array, cJSON_CreateString("MSS_CLAMP_DIR_TX"));
    return array;
}
static inline cJSON *vl_api_mss_clamp_enable_disable_t_tojson (vl_api_mss_clamp_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mss_clamp_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "d31b44e3");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "ipv4_mss", a->ipv4_mss);
    cJSON_AddNumberToObject(o, "ipv6_mss", a->ipv6_mss);
    cJSON_AddItemToObject(o, "ipv4_direction", vl_api_mss_clamp_dir_t_tojson(a->ipv4_direction));
    cJSON_AddItemToObject(o, "ipv6_direction", vl_api_mss_clamp_dir_t_tojson(a->ipv6_direction));
    return o;
}
static inline cJSON *vl_api_mss_clamp_enable_disable_reply_t_tojson (vl_api_mss_clamp_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mss_clamp_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_mss_clamp_get_t_tojson (vl_api_mss_clamp_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mss_clamp_get");
    cJSON_AddStringToObject(o, "_crc", "47250981");
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_mss_clamp_get_reply_t_tojson (vl_api_mss_clamp_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mss_clamp_get_reply");
    cJSON_AddStringToObject(o, "_crc", "53b48f5d");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_mss_clamp_details_t_tojson (vl_api_mss_clamp_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "mss_clamp_details");
    cJSON_AddStringToObject(o, "_crc", "d3a4de61");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "ipv4_mss", a->ipv4_mss);
    cJSON_AddNumberToObject(o, "ipv6_mss", a->ipv6_mss);
    cJSON_AddItemToObject(o, "ipv4_direction", vl_api_mss_clamp_dir_t_tojson(a->ipv4_direction));
    cJSON_AddItemToObject(o, "ipv6_direction", vl_api_mss_clamp_dir_t_tojson(a->ipv6_direction));
    return o;
}
#endif
