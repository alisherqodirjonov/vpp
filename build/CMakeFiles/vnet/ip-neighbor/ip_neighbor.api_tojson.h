/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_ip_neighbor_api_tojson_h
#define included_ip_neighbor_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_ip_neighbor_flags_t_tojson (vl_api_ip_neighbor_flags_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("IP_API_NEIGHBOR_FLAG_NONE");
    case 1:
        return cJSON_CreateString("IP_API_NEIGHBOR_FLAG_STATIC");
    case 2:
        return cJSON_CreateString("IP_API_NEIGHBOR_FLAG_NO_FIB_ENTRY");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_ip_neighbor_t_tojson (vl_api_ip_neighbor_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "flags", vl_api_ip_neighbor_flags_t_tojson(a->flags));
    cJSON_AddItemToObject(o, "mac_address", vl_api_mac_address_t_tojson(&a->mac_address));
    cJSON_AddItemToObject(o, "ip_address", vl_api_address_t_tojson(&a->ip_address));
    return o;
}
static inline cJSON *vl_api_ip_neighbor_event_flags_t_tojson (vl_api_ip_neighbor_event_flags_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("IP_NEIGHBOR_API_EVENT_FLAG_ADDED");
    case 2:
        return cJSON_CreateString("IP_NEIGHBOR_API_EVENT_FLAG_REMOVED");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_ip_neighbor_add_del_t_tojson (vl_api_ip_neighbor_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_neighbor_add_del");
    cJSON_AddStringToObject(o, "_crc", "0607c257");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "neighbor", vl_api_ip_neighbor_t_tojson(&a->neighbor));
    return o;
}
static inline cJSON *vl_api_ip_neighbor_add_del_reply_t_tojson (vl_api_ip_neighbor_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_neighbor_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "1992deab");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "stats_index", a->stats_index);
    return o;
}
static inline cJSON *vl_api_ip_neighbor_dump_t_tojson (vl_api_ip_neighbor_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_neighbor_dump");
    cJSON_AddStringToObject(o, "_crc", "d817a484");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "af", vl_api_address_family_t_tojson(a->af));
    return o;
}
static inline cJSON *vl_api_ip_neighbor_details_t_tojson (vl_api_ip_neighbor_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_neighbor_details");
    cJSON_AddStringToObject(o, "_crc", "e29d79f0");
    cJSON_AddNumberToObject(o, "age", a->age);
    cJSON_AddItemToObject(o, "neighbor", vl_api_ip_neighbor_t_tojson(&a->neighbor));
    return o;
}
static inline cJSON *vl_api_ip_neighbor_config_t_tojson (vl_api_ip_neighbor_config_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_neighbor_config");
    cJSON_AddStringToObject(o, "_crc", "f4a5cf44");
    cJSON_AddItemToObject(o, "af", vl_api_address_family_t_tojson(a->af));
    cJSON_AddNumberToObject(o, "max_number", a->max_number);
    cJSON_AddNumberToObject(o, "max_age", a->max_age);
    cJSON_AddBoolToObject(o, "recycle", a->recycle);
    return o;
}
static inline cJSON *vl_api_ip_neighbor_config_reply_t_tojson (vl_api_ip_neighbor_config_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_neighbor_config_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_neighbor_config_get_t_tojson (vl_api_ip_neighbor_config_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_neighbor_config_get");
    cJSON_AddStringToObject(o, "_crc", "a5db7bf7");
    cJSON_AddItemToObject(o, "af", vl_api_address_family_t_tojson(a->af));
    return o;
}
static inline cJSON *vl_api_ip_neighbor_config_get_reply_t_tojson (vl_api_ip_neighbor_config_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_neighbor_config_get_reply");
    cJSON_AddStringToObject(o, "_crc", "798e6fdd");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "af", vl_api_address_family_t_tojson(a->af));
    cJSON_AddNumberToObject(o, "max_number", a->max_number);
    cJSON_AddNumberToObject(o, "max_age", a->max_age);
    cJSON_AddBoolToObject(o, "recycle", a->recycle);
    return o;
}
static inline cJSON *vl_api_ip_neighbor_replace_begin_t_tojson (vl_api_ip_neighbor_replace_begin_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_neighbor_replace_begin");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ip_neighbor_replace_begin_reply_t_tojson (vl_api_ip_neighbor_replace_begin_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_neighbor_replace_begin_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_neighbor_replace_end_t_tojson (vl_api_ip_neighbor_replace_end_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_neighbor_replace_end");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ip_neighbor_replace_end_reply_t_tojson (vl_api_ip_neighbor_replace_end_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_neighbor_replace_end_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_neighbor_flush_t_tojson (vl_api_ip_neighbor_flush_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_neighbor_flush");
    cJSON_AddStringToObject(o, "_crc", "16aa35d2");
    cJSON_AddItemToObject(o, "af", vl_api_address_family_t_tojson(a->af));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_ip_neighbor_flush_reply_t_tojson (vl_api_ip_neighbor_flush_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_neighbor_flush_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_want_ip_neighbor_events_t_tojson (vl_api_want_ip_neighbor_events_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_ip_neighbor_events");
    cJSON_AddStringToObject(o, "_crc", "73e70a86");
    cJSON_AddBoolToObject(o, "enable", a->enable);
    cJSON_AddNumberToObject(o, "pid", a->pid);
    cJSON_AddItemToObject(o, "ip", vl_api_address_t_tojson(&a->ip));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_want_ip_neighbor_events_reply_t_tojson (vl_api_want_ip_neighbor_events_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_ip_neighbor_events_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_neighbor_event_t_tojson (vl_api_ip_neighbor_event_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_neighbor_event");
    cJSON_AddStringToObject(o, "_crc", "bdb092b2");
    cJSON_AddNumberToObject(o, "pid", a->pid);
    cJSON_AddItemToObject(o, "neighbor", vl_api_ip_neighbor_t_tojson(&a->neighbor));
    return o;
}
static inline cJSON *vl_api_want_ip_neighbor_events_v2_t_tojson (vl_api_want_ip_neighbor_events_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_ip_neighbor_events_v2");
    cJSON_AddStringToObject(o, "_crc", "73e70a86");
    cJSON_AddBoolToObject(o, "enable", a->enable);
    cJSON_AddNumberToObject(o, "pid", a->pid);
    cJSON_AddItemToObject(o, "ip", vl_api_address_t_tojson(&a->ip));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_want_ip_neighbor_events_v2_reply_t_tojson (vl_api_want_ip_neighbor_events_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_ip_neighbor_events_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_neighbor_event_v2_t_tojson (vl_api_ip_neighbor_event_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_neighbor_event_v2");
    cJSON_AddStringToObject(o, "_crc", "c1d53dc0");
    cJSON_AddNumberToObject(o, "pid", a->pid);
    cJSON_AddItemToObject(o, "flags", vl_api_ip_neighbor_event_flags_t_tojson(a->flags));
    cJSON_AddItemToObject(o, "neighbor", vl_api_ip_neighbor_t_tojson(&a->neighbor));
    return o;
}
#endif
