/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_vxlan_api_tojson_h
#define included_vxlan_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_vxlan_add_del_tunnel_t_tojson (vl_api_vxlan_add_del_tunnel_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_add_del_tunnel");
    cJSON_AddStringToObject(o, "_crc", "0c09dc80");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "instance", a->instance);
    cJSON_AddItemToObject(o, "src_address", vl_api_address_t_tojson(&a->src_address));
    cJSON_AddItemToObject(o, "dst_address", vl_api_address_t_tojson(&a->dst_address));
    cJSON_AddNumberToObject(o, "mcast_sw_if_index", a->mcast_sw_if_index);
    cJSON_AddNumberToObject(o, "encap_vrf_id", a->encap_vrf_id);
    cJSON_AddNumberToObject(o, "decap_next_index", a->decap_next_index);
    cJSON_AddNumberToObject(o, "vni", a->vni);
    return o;
}
static inline cJSON *vl_api_vxlan_add_del_tunnel_v2_t_tojson (vl_api_vxlan_add_del_tunnel_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_add_del_tunnel_v2");
    cJSON_AddStringToObject(o, "_crc", "4f223f40");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "instance", a->instance);
    cJSON_AddItemToObject(o, "src_address", vl_api_address_t_tojson(&a->src_address));
    cJSON_AddItemToObject(o, "dst_address", vl_api_address_t_tojson(&a->dst_address));
    cJSON_AddNumberToObject(o, "src_port", a->src_port);
    cJSON_AddNumberToObject(o, "dst_port", a->dst_port);
    cJSON_AddNumberToObject(o, "mcast_sw_if_index", a->mcast_sw_if_index);
    cJSON_AddNumberToObject(o, "encap_vrf_id", a->encap_vrf_id);
    cJSON_AddNumberToObject(o, "decap_next_index", a->decap_next_index);
    cJSON_AddNumberToObject(o, "vni", a->vni);
    return o;
}
static inline cJSON *vl_api_vxlan_add_del_tunnel_v3_t_tojson (vl_api_vxlan_add_del_tunnel_v3_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_add_del_tunnel_v3");
    cJSON_AddStringToObject(o, "_crc", "0072b037");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "instance", a->instance);
    cJSON_AddItemToObject(o, "src_address", vl_api_address_t_tojson(&a->src_address));
    cJSON_AddItemToObject(o, "dst_address", vl_api_address_t_tojson(&a->dst_address));
    cJSON_AddNumberToObject(o, "src_port", a->src_port);
    cJSON_AddNumberToObject(o, "dst_port", a->dst_port);
    cJSON_AddNumberToObject(o, "mcast_sw_if_index", a->mcast_sw_if_index);
    cJSON_AddNumberToObject(o, "encap_vrf_id", a->encap_vrf_id);
    cJSON_AddNumberToObject(o, "decap_next_index", a->decap_next_index);
    cJSON_AddNumberToObject(o, "vni", a->vni);
    cJSON_AddBoolToObject(o, "is_l3", a->is_l3);
    return o;
}
static inline cJSON *vl_api_vxlan_add_del_tunnel_reply_t_tojson (vl_api_vxlan_add_del_tunnel_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_add_del_tunnel_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_vxlan_add_del_tunnel_v2_reply_t_tojson (vl_api_vxlan_add_del_tunnel_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_add_del_tunnel_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_vxlan_add_del_tunnel_v3_reply_t_tojson (vl_api_vxlan_add_del_tunnel_v3_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_add_del_tunnel_v3_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_vxlan_tunnel_dump_t_tojson (vl_api_vxlan_tunnel_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_tunnel_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_vxlan_tunnel_v2_dump_t_tojson (vl_api_vxlan_tunnel_v2_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_tunnel_v2_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_vxlan_tunnel_details_t_tojson (vl_api_vxlan_tunnel_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_tunnel_details");
    cJSON_AddStringToObject(o, "_crc", "c3916cb1");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "instance", a->instance);
    cJSON_AddItemToObject(o, "src_address", vl_api_address_t_tojson(&a->src_address));
    cJSON_AddItemToObject(o, "dst_address", vl_api_address_t_tojson(&a->dst_address));
    cJSON_AddNumberToObject(o, "mcast_sw_if_index", a->mcast_sw_if_index);
    cJSON_AddNumberToObject(o, "encap_vrf_id", a->encap_vrf_id);
    cJSON_AddNumberToObject(o, "decap_next_index", a->decap_next_index);
    cJSON_AddNumberToObject(o, "vni", a->vni);
    return o;
}
static inline cJSON *vl_api_vxlan_tunnel_v2_details_t_tojson (vl_api_vxlan_tunnel_v2_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_tunnel_v2_details");
    cJSON_AddStringToObject(o, "_crc", "d3bdd4d9");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "instance", a->instance);
    cJSON_AddItemToObject(o, "src_address", vl_api_address_t_tojson(&a->src_address));
    cJSON_AddItemToObject(o, "dst_address", vl_api_address_t_tojson(&a->dst_address));
    cJSON_AddNumberToObject(o, "src_port", a->src_port);
    cJSON_AddNumberToObject(o, "dst_port", a->dst_port);
    cJSON_AddNumberToObject(o, "mcast_sw_if_index", a->mcast_sw_if_index);
    cJSON_AddNumberToObject(o, "encap_vrf_id", a->encap_vrf_id);
    cJSON_AddNumberToObject(o, "decap_next_index", a->decap_next_index);
    cJSON_AddNumberToObject(o, "vni", a->vni);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_vxlan_bypass_t_tojson (vl_api_sw_interface_set_vxlan_bypass_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_vxlan_bypass");
    cJSON_AddStringToObject(o, "_crc", "65247409");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_ipv6", a->is_ipv6);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_vxlan_bypass_reply_t_tojson (vl_api_sw_interface_set_vxlan_bypass_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_vxlan_bypass_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_vxlan_offload_rx_t_tojson (vl_api_vxlan_offload_rx_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_offload_rx");
    cJSON_AddStringToObject(o, "_crc", "9cc95087");
    cJSON_AddNumberToObject(o, "hw_if_index", a->hw_if_index);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_vxlan_offload_rx_reply_t_tojson (vl_api_vxlan_offload_rx_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_offload_rx_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
