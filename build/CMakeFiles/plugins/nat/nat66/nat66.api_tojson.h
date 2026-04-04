/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#include <nat/lib/nat_types.api_tojson.h>
#ifndef included_nat66_api_tojson_h
#define included_nat66_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_nat66_plugin_enable_disable_t_tojson (vl_api_nat66_plugin_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat66_plugin_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "56f2f83b");
    cJSON_AddNumberToObject(o, "outside_vrf", a->outside_vrf);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_nat66_plugin_enable_disable_reply_t_tojson (vl_api_nat66_plugin_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat66_plugin_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat66_add_del_interface_t_tojson (vl_api_nat66_add_del_interface_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat66_add_del_interface");
    cJSON_AddStringToObject(o, "_crc", "f3699b83");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_nat66_add_del_interface_reply_t_tojson (vl_api_nat66_add_del_interface_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat66_add_del_interface_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat66_interface_dump_t_tojson (vl_api_nat66_interface_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat66_interface_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat66_interface_details_t_tojson (vl_api_nat66_interface_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat66_interface_details");
    cJSON_AddStringToObject(o, "_crc", "5d286289");
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_nat66_add_del_static_mapping_t_tojson (vl_api_nat66_add_del_static_mapping_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat66_add_del_static_mapping");
    cJSON_AddStringToObject(o, "_crc", "3ed88f71");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "local_ip_address", vl_api_ip6_address_t_tojson(&a->local_ip_address));
    cJSON_AddItemToObject(o, "external_ip_address", vl_api_ip6_address_t_tojson(&a->external_ip_address));
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    return o;
}
static inline cJSON *vl_api_nat66_add_del_static_mapping_reply_t_tojson (vl_api_nat66_add_del_static_mapping_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat66_add_del_static_mapping_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat66_static_mapping_dump_t_tojson (vl_api_nat66_static_mapping_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat66_static_mapping_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat66_static_mapping_details_t_tojson (vl_api_nat66_static_mapping_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat66_static_mapping_details");
    cJSON_AddStringToObject(o, "_crc", "df39654b");
    cJSON_AddItemToObject(o, "local_ip_address", vl_api_ip6_address_t_tojson(&a->local_ip_address));
    cJSON_AddItemToObject(o, "external_ip_address", vl_api_ip6_address_t_tojson(&a->external_ip_address));
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddNumberToObject(o, "total_bytes", a->total_bytes);
    cJSON_AddNumberToObject(o, "total_pkts", a->total_pkts);
    return o;
}
#endif
