/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#ifndef included_ct6_api_tojson_h
#define included_ct6_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_ct6_enable_disable_t_tojson (vl_api_ct6_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ct6_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "5d02ac02");
    cJSON_AddBoolToObject(o, "enable_disable", a->enable_disable);
    cJSON_AddBoolToObject(o, "is_inside", a->is_inside);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_ct6_enable_disable_reply_t_tojson (vl_api_ct6_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ct6_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
