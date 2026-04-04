/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/flow/flow_types.api_tojson.h>
#ifndef included_flow_api_tojson_h
#define included_flow_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_flow_add_t_tojson (vl_api_flow_add_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flow_add");
    cJSON_AddStringToObject(o, "_crc", "f946ed84");
    cJSON_AddItemToObject(o, "flow", vl_api_flow_rule_t_tojson(&a->flow));
    return o;
}
static inline cJSON *vl_api_flow_add_v2_t_tojson (vl_api_flow_add_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flow_add_v2");
    cJSON_AddStringToObject(o, "_crc", "5b757558");
    cJSON_AddItemToObject(o, "flow", vl_api_flow_rule_v2_t_tojson(&a->flow));
    return o;
}
static inline cJSON *vl_api_flow_add_reply_t_tojson (vl_api_flow_add_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flow_add_reply");
    cJSON_AddStringToObject(o, "_crc", "8587dc85");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "flow_index", a->flow_index);
    return o;
}
static inline cJSON *vl_api_flow_add_v2_reply_t_tojson (vl_api_flow_add_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flow_add_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "8587dc85");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "flow_index", a->flow_index);
    return o;
}
static inline cJSON *vl_api_flow_del_t_tojson (vl_api_flow_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flow_del");
    cJSON_AddStringToObject(o, "_crc", "b6b9b02c");
    cJSON_AddNumberToObject(o, "flow_index", a->flow_index);
    return o;
}
static inline cJSON *vl_api_flow_del_reply_t_tojson (vl_api_flow_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flow_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_flow_enable_t_tojson (vl_api_flow_enable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flow_enable");
    cJSON_AddStringToObject(o, "_crc", "2024be69");
    cJSON_AddNumberToObject(o, "flow_index", a->flow_index);
    cJSON_AddNumberToObject(o, "hw_if_index", a->hw_if_index);
    return o;
}
static inline cJSON *vl_api_flow_enable_reply_t_tojson (vl_api_flow_enable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flow_enable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_flow_disable_t_tojson (vl_api_flow_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flow_disable");
    cJSON_AddStringToObject(o, "_crc", "2024be69");
    cJSON_AddNumberToObject(o, "flow_index", a->flow_index);
    cJSON_AddNumberToObject(o, "hw_if_index", a->hw_if_index);
    return o;
}
static inline cJSON *vl_api_flow_disable_reply_t_tojson (vl_api_flow_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flow_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
