/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/fib/fib_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_urpf_api_tojson_h
#define included_urpf_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_urpf_mode_t_tojson (vl_api_urpf_mode_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("URPF_API_MODE_OFF");
    case 1:
        return cJSON_CreateString("URPF_API_MODE_LOOSE");
    case 2:
        return cJSON_CreateString("URPF_API_MODE_STRICT");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_urpf_update_t_tojson (vl_api_urpf_update_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "urpf_update");
    cJSON_AddStringToObject(o, "_crc", "cc274cd1");
    cJSON_AddBoolToObject(o, "is_input", a->is_input);
    cJSON_AddItemToObject(o, "mode", vl_api_urpf_mode_t_tojson(a->mode));
    cJSON_AddItemToObject(o, "af", vl_api_address_family_t_tojson(a->af));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_urpf_update_reply_t_tojson (vl_api_urpf_update_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "urpf_update_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_urpf_update_v2_t_tojson (vl_api_urpf_update_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "urpf_update_v2");
    cJSON_AddStringToObject(o, "_crc", "b873d028");
    cJSON_AddBoolToObject(o, "is_input", a->is_input);
    cJSON_AddItemToObject(o, "mode", vl_api_urpf_mode_t_tojson(a->mode));
    cJSON_AddItemToObject(o, "af", vl_api_address_family_t_tojson(a->af));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    return o;
}
static inline cJSON *vl_api_urpf_update_v2_reply_t_tojson (vl_api_urpf_update_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "urpf_update_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_urpf_interface_dump_t_tojson (vl_api_urpf_interface_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "urpf_interface_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_urpf_interface_details_t_tojson (vl_api_urpf_interface_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "urpf_interface_details");
    cJSON_AddStringToObject(o, "_crc", "f94b5374");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_input", a->is_input);
    cJSON_AddItemToObject(o, "mode", vl_api_urpf_mode_t_tojson(a->mode));
    cJSON_AddItemToObject(o, "af", vl_api_address_family_t_tojson(a->af));
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    return o;
}
#endif
