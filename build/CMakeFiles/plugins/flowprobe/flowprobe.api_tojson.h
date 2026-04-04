/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#ifndef included_flowprobe_api_tojson_h
#define included_flowprobe_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_flowprobe_which_flags_t_tojson (vl_api_flowprobe_which_flags_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("FLOWPROBE_WHICH_FLAG_IP4");
    case 2:
        return cJSON_CreateString("FLOWPROBE_WHICH_FLAG_L2");
    case 4:
        return cJSON_CreateString("FLOWPROBE_WHICH_FLAG_IP6");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_flowprobe_which_t_tojson (vl_api_flowprobe_which_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("FLOWPROBE_WHICH_IP4");
    case 1:
        return cJSON_CreateString("FLOWPROBE_WHICH_IP6");
    case 2:
        return cJSON_CreateString("FLOWPROBE_WHICH_L2");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_flowprobe_record_flags_t_tojson (vl_api_flowprobe_record_flags_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("FLOWPROBE_RECORD_FLAG_L2");
    case 2:
        return cJSON_CreateString("FLOWPROBE_RECORD_FLAG_L3");
    case 4:
        return cJSON_CreateString("FLOWPROBE_RECORD_FLAG_L4");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_flowprobe_direction_t_tojson (vl_api_flowprobe_direction_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("FLOWPROBE_DIRECTION_RX");
    case 1:
        return cJSON_CreateString("FLOWPROBE_DIRECTION_TX");
    case 2:
        return cJSON_CreateString("FLOWPROBE_DIRECTION_BOTH");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_flowprobe_tx_interface_add_del_t_tojson (vl_api_flowprobe_tx_interface_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flowprobe_tx_interface_add_del");
    cJSON_AddStringToObject(o, "_crc", "b782c976");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "which", vl_api_flowprobe_which_flags_t_tojson(a->which));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_flowprobe_tx_interface_add_del_reply_t_tojson (vl_api_flowprobe_tx_interface_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flowprobe_tx_interface_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_flowprobe_interface_add_del_t_tojson (vl_api_flowprobe_interface_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flowprobe_interface_add_del");
    cJSON_AddStringToObject(o, "_crc", "3420739c");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "which", vl_api_flowprobe_which_t_tojson(a->which));
    cJSON_AddItemToObject(o, "direction", vl_api_flowprobe_direction_t_tojson(a->direction));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_flowprobe_interface_add_del_reply_t_tojson (vl_api_flowprobe_interface_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flowprobe_interface_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_flowprobe_interface_dump_t_tojson (vl_api_flowprobe_interface_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flowprobe_interface_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_flowprobe_interface_details_t_tojson (vl_api_flowprobe_interface_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flowprobe_interface_details");
    cJSON_AddStringToObject(o, "_crc", "427d77e0");
    cJSON_AddItemToObject(o, "which", vl_api_flowprobe_which_t_tojson(a->which));
    cJSON_AddItemToObject(o, "direction", vl_api_flowprobe_direction_t_tojson(a->direction));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_flowprobe_params_t_tojson (vl_api_flowprobe_params_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flowprobe_params");
    cJSON_AddStringToObject(o, "_crc", "baa46c09");
    cJSON_AddItemToObject(o, "record_flags", vl_api_flowprobe_record_flags_t_tojson(a->record_flags));
    cJSON_AddNumberToObject(o, "active_timer", a->active_timer);
    cJSON_AddNumberToObject(o, "passive_timer", a->passive_timer);
    return o;
}
static inline cJSON *vl_api_flowprobe_params_reply_t_tojson (vl_api_flowprobe_params_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flowprobe_params_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_flowprobe_set_params_t_tojson (vl_api_flowprobe_set_params_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flowprobe_set_params");
    cJSON_AddStringToObject(o, "_crc", "baa46c09");
    cJSON_AddItemToObject(o, "record_flags", vl_api_flowprobe_record_flags_t_tojson(a->record_flags));
    cJSON_AddNumberToObject(o, "active_timer", a->active_timer);
    cJSON_AddNumberToObject(o, "passive_timer", a->passive_timer);
    return o;
}
static inline cJSON *vl_api_flowprobe_set_params_reply_t_tojson (vl_api_flowprobe_set_params_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flowprobe_set_params_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_flowprobe_get_params_t_tojson (vl_api_flowprobe_get_params_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flowprobe_get_params");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_flowprobe_get_params_reply_t_tojson (vl_api_flowprobe_get_params_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "flowprobe_get_params_reply");
    cJSON_AddStringToObject(o, "_crc", "f350d621");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "record_flags", vl_api_flowprobe_record_flags_t_tojson(a->record_flags));
    cJSON_AddNumberToObject(o, "active_timer", a->active_timer);
    cJSON_AddNumberToObject(o, "passive_timer", a->passive_timer);
    return o;
}
#endif
