/* Imported API files */
#ifndef included_cdp_api_tojson_h
#define included_cdp_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_cdp_enable_disable_t_tojson (vl_api_cdp_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cdp_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "2e7b47df");
    cJSON_AddBoolToObject(o, "enable_disable", a->enable_disable);
    return o;
}
static inline cJSON *vl_api_cdp_enable_disable_reply_t_tojson (vl_api_cdp_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cdp_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
