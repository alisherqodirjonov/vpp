/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#ifndef included_feature_api_tojson_h
#define included_feature_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_feature_enable_disable_t_tojson (vl_api_feature_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "feature_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "7531c862");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    cJSON_AddStringToObject(o, "arc_name", (char *)a->arc_name);
    cJSON_AddStringToObject(o, "feature_name", (char *)a->feature_name);
    return o;
}
static inline cJSON *vl_api_feature_enable_disable_reply_t_tojson (vl_api_feature_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "feature_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_feature_is_enabled_t_tojson (vl_api_feature_is_enabled_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "feature_is_enabled");
    cJSON_AddStringToObject(o, "_crc", "55db09e2");
    cJSON_AddStringToObject(o, "arc_name", (char *)a->arc_name);
    cJSON_AddStringToObject(o, "feature_name", (char *)a->feature_name);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_feature_is_enabled_reply_t_tojson (vl_api_feature_is_enabled_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "feature_is_enabled_reply");
    cJSON_AddStringToObject(o, "_crc", "03f284b5");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddBoolToObject(o, "is_enabled", a->is_enabled);
    return o;
}
#endif
