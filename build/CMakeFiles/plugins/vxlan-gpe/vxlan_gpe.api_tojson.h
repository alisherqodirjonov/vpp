/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_vxlan_gpe_api_tojson_h
#define included_vxlan_gpe_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_vxlan_gpe_add_del_tunnel_t_tojson (vl_api_vxlan_gpe_add_del_tunnel_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_add_del_tunnel");
    cJSON_AddStringToObject(o, "_crc", "a645b2b0");
    cJSON_AddItemToObject(o, "local", vl_api_address_t_tojson(&a->local));
    cJSON_AddItemToObject(o, "remote", vl_api_address_t_tojson(&a->remote));
    cJSON_AddNumberToObject(o, "mcast_sw_if_index", a->mcast_sw_if_index);
    cJSON_AddNumberToObject(o, "encap_vrf_id", a->encap_vrf_id);
    cJSON_AddNumberToObject(o, "decap_vrf_id", a->decap_vrf_id);
    cJSON_AddItemToObject(o, "protocol", vl_api_ip_proto_t_tojson(a->protocol));
    cJSON_AddNumberToObject(o, "vni", a->vni);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_vxlan_gpe_add_del_tunnel_v2_t_tojson (vl_api_vxlan_gpe_add_del_tunnel_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_add_del_tunnel_v2");
    cJSON_AddStringToObject(o, "_crc", "d62fdb35");
    cJSON_AddItemToObject(o, "local", vl_api_address_t_tojson(&a->local));
    cJSON_AddItemToObject(o, "remote", vl_api_address_t_tojson(&a->remote));
    cJSON_AddNumberToObject(o, "local_port", a->local_port);
    cJSON_AddNumberToObject(o, "remote_port", a->remote_port);
    cJSON_AddNumberToObject(o, "mcast_sw_if_index", a->mcast_sw_if_index);
    cJSON_AddNumberToObject(o, "encap_vrf_id", a->encap_vrf_id);
    cJSON_AddNumberToObject(o, "decap_vrf_id", a->decap_vrf_id);
    cJSON_AddItemToObject(o, "protocol", vl_api_ip_proto_t_tojson(a->protocol));
    cJSON_AddNumberToObject(o, "vni", a->vni);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_vxlan_gpe_add_del_tunnel_reply_t_tojson (vl_api_vxlan_gpe_add_del_tunnel_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_add_del_tunnel_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_vxlan_gpe_add_del_tunnel_v2_reply_t_tojson (vl_api_vxlan_gpe_add_del_tunnel_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_add_del_tunnel_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_vxlan_gpe_tunnel_dump_t_tojson (vl_api_vxlan_gpe_tunnel_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_tunnel_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_vxlan_gpe_tunnel_v2_dump_t_tojson (vl_api_vxlan_gpe_tunnel_v2_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_tunnel_v2_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_vxlan_gpe_tunnel_details_t_tojson (vl_api_vxlan_gpe_tunnel_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_tunnel_details");
    cJSON_AddStringToObject(o, "_crc", "0968fc8b");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "local", vl_api_address_t_tojson(&a->local));
    cJSON_AddItemToObject(o, "remote", vl_api_address_t_tojson(&a->remote));
    cJSON_AddNumberToObject(o, "vni", a->vni);
    cJSON_AddItemToObject(o, "protocol", vl_api_ip_proto_t_tojson(a->protocol));
    cJSON_AddNumberToObject(o, "mcast_sw_if_index", a->mcast_sw_if_index);
    cJSON_AddNumberToObject(o, "encap_vrf_id", a->encap_vrf_id);
    cJSON_AddNumberToObject(o, "decap_vrf_id", a->decap_vrf_id);
    cJSON_AddBoolToObject(o, "is_ipv6", a->is_ipv6);
    return o;
}
static inline cJSON *vl_api_vxlan_gpe_tunnel_v2_details_t_tojson (vl_api_vxlan_gpe_tunnel_v2_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "vxlan_gpe_tunnel_v2_details");
    cJSON_AddStringToObject(o, "_crc", "06be4870");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "local", vl_api_address_t_tojson(&a->local));
    cJSON_AddItemToObject(o, "remote", vl_api_address_t_tojson(&a->remote));
    cJSON_AddNumberToObject(o, "local_port", a->local_port);
    cJSON_AddNumberToObject(o, "remote_port", a->remote_port);
    cJSON_AddNumberToObject(o, "vni", a->vni);
    cJSON_AddItemToObject(o, "protocol", vl_api_ip_proto_t_tojson(a->protocol));
    cJSON_AddNumberToObject(o, "mcast_sw_if_index", a->mcast_sw_if_index);
    cJSON_AddNumberToObject(o, "encap_vrf_id", a->encap_vrf_id);
    cJSON_AddNumberToObject(o, "decap_vrf_id", a->decap_vrf_id);
    cJSON_AddBoolToObject(o, "is_ipv6", a->is_ipv6);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_vxlan_gpe_bypass_t_tojson (vl_api_sw_interface_set_vxlan_gpe_bypass_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_vxlan_gpe_bypass");
    cJSON_AddStringToObject(o, "_crc", "65247409");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_ipv6", a->is_ipv6);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_vxlan_gpe_bypass_reply_t_tojson (vl_api_sw_interface_set_vxlan_gpe_bypass_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_vxlan_gpe_bypass_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
