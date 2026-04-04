/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_vxlan_gpe_ioam_export_api_tojson_h
#define included_vxlan_gpe_ioam_export_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_vxlan_gpe_ioam_export_enable_disable_t_tojson (vl_api_vxlan_gpe_ioam_export_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_ioam_export_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "d4c76d3a");
    cJSON_AddBoolToObject(o, "is_disable", a->is_disable);
    cJSON_AddItemToObject(o, "collector_address", vl_api_ip4_address_t_tojson(&a->collector_address));
    cJSON_AddItemToObject(o, "src_address", vl_api_ip4_address_t_tojson(&a->src_address));
    return o;
}
static inline cJSON *vl_api_vxlan_gpe_ioam_export_enable_disable_reply_t_tojson (vl_api_vxlan_gpe_ioam_export_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_ioam_export_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
