/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_ioam_vxlan_gpe_api_tojson_h
#define included_ioam_vxlan_gpe_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_vxlan_gpe_ioam_enable_t_tojson (vl_api_vxlan_gpe_ioam_enable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_ioam_enable");
    cJSON_AddStringToObject(o, "_crc", "2481bef7");
    cJSON_AddNumberToObject(o, "id", a->id);
    cJSON_AddNumberToObject(o, "trace_ppc", a->trace_ppc);
    cJSON_AddBoolToObject(o, "pow_enable", a->pow_enable);
    cJSON_AddBoolToObject(o, "trace_enable", a->trace_enable);
    return o;
}
static inline cJSON *vl_api_vxlan_gpe_ioam_enable_reply_t_tojson (vl_api_vxlan_gpe_ioam_enable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_ioam_enable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_vxlan_gpe_ioam_disable_t_tojson (vl_api_vxlan_gpe_ioam_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_ioam_disable");
    cJSON_AddStringToObject(o, "_crc", "6b16a45e");
    cJSON_AddNumberToObject(o, "id", a->id);
    return o;
}
static inline cJSON *vl_api_vxlan_gpe_ioam_disable_reply_t_tojson (vl_api_vxlan_gpe_ioam_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_ioam_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_vxlan_gpe_ioam_vni_enable_t_tojson (vl_api_vxlan_gpe_ioam_vni_enable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_ioam_vni_enable");
    cJSON_AddStringToObject(o, "_crc", "0fbb5fb1");
    cJSON_AddNumberToObject(o, "vni", a->vni);
    cJSON_AddItemToObject(o, "local", vl_api_address_t_tojson(&a->local));
    cJSON_AddItemToObject(o, "remote", vl_api_address_t_tojson(&a->remote));
    return o;
}
static inline cJSON *vl_api_vxlan_gpe_ioam_vni_enable_reply_t_tojson (vl_api_vxlan_gpe_ioam_vni_enable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_ioam_vni_enable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_vxlan_gpe_ioam_vni_disable_t_tojson (vl_api_vxlan_gpe_ioam_vni_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_ioam_vni_disable");
    cJSON_AddStringToObject(o, "_crc", "0fbb5fb1");
    cJSON_AddNumberToObject(o, "vni", a->vni);
    cJSON_AddItemToObject(o, "local", vl_api_address_t_tojson(&a->local));
    cJSON_AddItemToObject(o, "remote", vl_api_address_t_tojson(&a->remote));
    return o;
}
static inline cJSON *vl_api_vxlan_gpe_ioam_vni_disable_reply_t_tojson (vl_api_vxlan_gpe_ioam_vni_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_ioam_vni_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_vxlan_gpe_ioam_transit_enable_t_tojson (vl_api_vxlan_gpe_ioam_transit_enable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_ioam_transit_enable");
    cJSON_AddStringToObject(o, "_crc", "3d3ec657");
    cJSON_AddNumberToObject(o, "outer_fib_index", a->outer_fib_index);
    cJSON_AddItemToObject(o, "dst_addr", vl_api_address_t_tojson(&a->dst_addr));
    return o;
}
static inline cJSON *vl_api_vxlan_gpe_ioam_transit_enable_reply_t_tojson (vl_api_vxlan_gpe_ioam_transit_enable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_ioam_transit_enable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_vxlan_gpe_ioam_transit_disable_t_tojson (vl_api_vxlan_gpe_ioam_transit_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_ioam_transit_disable");
    cJSON_AddStringToObject(o, "_crc", "3d3ec657");
    cJSON_AddNumberToObject(o, "outer_fib_index", a->outer_fib_index);
    cJSON_AddItemToObject(o, "dst_addr", vl_api_address_t_tojson(&a->dst_addr));
    return o;
}
static inline cJSON *vl_api_vxlan_gpe_ioam_transit_disable_reply_t_tojson (vl_api_vxlan_gpe_ioam_transit_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_ioam_transit_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
