/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#ifndef included_span_api_tojson_h
#define included_span_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_span_state_t_tojson (vl_api_span_state_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("SPAN_STATE_API_DISABLED");
    case 1:
        return cJSON_CreateString("SPAN_STATE_API_RX");
    case 2:
        return cJSON_CreateString("SPAN_STATE_API_TX");
    case 3:
        return cJSON_CreateString("SPAN_STATE_API_RX_TX");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_sw_interface_span_enable_disable_t_tojson (vl_api_sw_interface_span_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_span_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "23ddd96b");
    cJSON_AddNumberToObject(o, "sw_if_index_from", a->sw_if_index_from);
    cJSON_AddNumberToObject(o, "sw_if_index_to", a->sw_if_index_to);
    cJSON_AddItemToObject(o, "state", vl_api_span_state_t_tojson(a->state));
    cJSON_AddBoolToObject(o, "is_l2", a->is_l2);
    return o;
}
static inline cJSON *vl_api_sw_interface_span_enable_disable_reply_t_tojson (vl_api_sw_interface_span_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_span_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_span_dump_t_tojson (vl_api_sw_interface_span_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_span_dump");
    cJSON_AddStringToObject(o, "_crc", "d6cf0c3d");
    cJSON_AddBoolToObject(o, "is_l2", a->is_l2);
    return o;
}
static inline cJSON *vl_api_sw_interface_span_details_t_tojson (vl_api_sw_interface_span_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_span_details");
    cJSON_AddStringToObject(o, "_crc", "8a20e79f");
    cJSON_AddNumberToObject(o, "sw_if_index_from", a->sw_if_index_from);
    cJSON_AddNumberToObject(o, "sw_if_index_to", a->sw_if_index_to);
    cJSON_AddItemToObject(o, "state", vl_api_span_state_t_tojson(a->state));
    cJSON_AddBoolToObject(o, "is_l2", a->is_l2);
    return o;
}
#endif
