/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_igmp_api_tojson_h
#define included_igmp_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_filter_mode_t_tojson (vl_api_filter_mode_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("EXCLUDE");
    case 1:
        return cJSON_CreateString("INCLUDE");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_igmp_group_t_tojson (vl_api_igmp_group_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "filter", vl_api_filter_mode_t_tojson(a->filter));
    cJSON_AddNumberToObject(o, "n_srcs", a->n_srcs);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "gaddr", vl_api_ip4_address_t_tojson(&a->gaddr));
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "saddrs");
        for (i = 0; i < a->n_srcs; i++) {
            cJSON_AddItemToArray(array, vl_api_ip4_address_t_tojson(&a->saddrs[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_group_prefix_type_t_tojson (vl_api_group_prefix_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("ASM");
    case 1:
        return cJSON_CreateString("SSM");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_group_prefix_t_tojson (vl_api_group_prefix_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "type", vl_api_group_prefix_type_t_tojson(a->type));
    cJSON_AddItemToObject(o, "prefix", vl_api_prefix_t_tojson(&a->prefix));
    return o;
}
static inline cJSON *vl_api_igmp_listen_t_tojson (vl_api_igmp_listen_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "igmp_listen");
    cJSON_AddStringToObject(o, "_crc", "19a49f1e");
    cJSON_AddItemToObject(o, "group", vl_api_igmp_group_t_tojson(&a->group));
    return o;
}
static inline cJSON *vl_api_igmp_listen_reply_t_tojson (vl_api_igmp_listen_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "igmp_listen_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_igmp_enable_disable_t_tojson (vl_api_igmp_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "igmp_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "b1edfb96");
    cJSON_AddBoolToObject(o, "enable", a->enable);
    cJSON_AddNumberToObject(o, "mode", a->mode);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_igmp_enable_disable_reply_t_tojson (vl_api_igmp_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "igmp_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_igmp_proxy_device_add_del_t_tojson (vl_api_igmp_proxy_device_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "igmp_proxy_device_add_del");
    cJSON_AddStringToObject(o, "_crc", "0b9be9ce");
    cJSON_AddNumberToObject(o, "add", a->add);
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_igmp_proxy_device_add_del_reply_t_tojson (vl_api_igmp_proxy_device_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "igmp_proxy_device_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_igmp_proxy_device_add_del_interface_t_tojson (vl_api_igmp_proxy_device_add_del_interface_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "igmp_proxy_device_add_del_interface");
    cJSON_AddStringToObject(o, "_crc", "1a9ec24a");
    cJSON_AddBoolToObject(o, "add", a->add);
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_igmp_proxy_device_add_del_interface_reply_t_tojson (vl_api_igmp_proxy_device_add_del_interface_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "igmp_proxy_device_add_del_interface_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_igmp_dump_t_tojson (vl_api_igmp_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "igmp_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_igmp_details_t_tojson (vl_api_igmp_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "igmp_details");
    cJSON_AddStringToObject(o, "_crc", "38f09929");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "saddr", vl_api_ip4_address_t_tojson(&a->saddr));
    cJSON_AddItemToObject(o, "gaddr", vl_api_ip4_address_t_tojson(&a->gaddr));
    return o;
}
static inline cJSON *vl_api_igmp_clear_interface_t_tojson (vl_api_igmp_clear_interface_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "igmp_clear_interface");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_igmp_clear_interface_reply_t_tojson (vl_api_igmp_clear_interface_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "igmp_clear_interface_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_want_igmp_events_t_tojson (vl_api_want_igmp_events_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_igmp_events");
    cJSON_AddStringToObject(o, "_crc", "cfaccc1f");
    cJSON_AddNumberToObject(o, "enable", a->enable);
    cJSON_AddNumberToObject(o, "pid", a->pid);
    return o;
}
static inline cJSON *vl_api_want_igmp_events_reply_t_tojson (vl_api_want_igmp_events_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_igmp_events_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_igmp_event_t_tojson (vl_api_igmp_event_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "igmp_event");
    cJSON_AddStringToObject(o, "_crc", "85fe93ec");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "filter", vl_api_filter_mode_t_tojson(a->filter));
    cJSON_AddItemToObject(o, "saddr", vl_api_ip4_address_t_tojson(&a->saddr));
    cJSON_AddItemToObject(o, "gaddr", vl_api_ip4_address_t_tojson(&a->gaddr));
    return o;
}
static inline cJSON *vl_api_igmp_group_prefix_set_t_tojson (vl_api_igmp_group_prefix_set_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "igmp_group_prefix_set");
    cJSON_AddStringToObject(o, "_crc", "5b14a5ce");
    cJSON_AddItemToObject(o, "gp", vl_api_group_prefix_t_tojson(&a->gp));
    return o;
}
static inline cJSON *vl_api_igmp_group_prefix_set_reply_t_tojson (vl_api_igmp_group_prefix_set_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "igmp_group_prefix_set_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_igmp_group_prefix_dump_t_tojson (vl_api_igmp_group_prefix_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "igmp_group_prefix_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_igmp_group_prefix_details_t_tojson (vl_api_igmp_group_prefix_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "igmp_group_prefix_details");
    cJSON_AddStringToObject(o, "_crc", "259ccd81");
    cJSON_AddItemToObject(o, "gp", vl_api_group_prefix_t_tojson(&a->gp));
    return o;
}
#endif
