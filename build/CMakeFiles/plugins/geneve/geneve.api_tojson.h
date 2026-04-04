/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_geneve_api_tojson_h
#define included_geneve_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_geneve_add_del_tunnel_t_tojson (vl_api_geneve_add_del_tunnel_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "geneve_add_del_tunnel");
    cJSON_AddStringToObject(o, "_crc", "99445831");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "local_address", vl_api_address_t_tojson(&a->local_address));
    cJSON_AddItemToObject(o, "remote_address", vl_api_address_t_tojson(&a->remote_address));
    cJSON_AddNumberToObject(o, "mcast_sw_if_index", a->mcast_sw_if_index);
    cJSON_AddNumberToObject(o, "encap_vrf_id", a->encap_vrf_id);
    cJSON_AddNumberToObject(o, "decap_next_index", a->decap_next_index);
    cJSON_AddNumberToObject(o, "vni", a->vni);
    return o;
}
static inline cJSON *vl_api_geneve_add_del_tunnel_reply_t_tojson (vl_api_geneve_add_del_tunnel_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "geneve_add_del_tunnel_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_geneve_add_del_tunnel2_t_tojson (vl_api_geneve_add_del_tunnel2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "geneve_add_del_tunnel2");
    cJSON_AddStringToObject(o, "_crc", "8c2a9999");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "local_address", vl_api_address_t_tojson(&a->local_address));
    cJSON_AddItemToObject(o, "remote_address", vl_api_address_t_tojson(&a->remote_address));
    cJSON_AddNumberToObject(o, "mcast_sw_if_index", a->mcast_sw_if_index);
    cJSON_AddNumberToObject(o, "encap_vrf_id", a->encap_vrf_id);
    cJSON_AddNumberToObject(o, "decap_next_index", a->decap_next_index);
    cJSON_AddNumberToObject(o, "vni", a->vni);
    cJSON_AddBoolToObject(o, "l3_mode", a->l3_mode);
    return o;
}
static inline cJSON *vl_api_geneve_add_del_tunnel2_reply_t_tojson (vl_api_geneve_add_del_tunnel2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "geneve_add_del_tunnel2_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_geneve_tunnel_dump_t_tojson (vl_api_geneve_tunnel_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "geneve_tunnel_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_geneve_tunnel_details_t_tojson (vl_api_geneve_tunnel_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "geneve_tunnel_details");
    cJSON_AddStringToObject(o, "_crc", "6b16eb24");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "src_address", vl_api_address_t_tojson(&a->src_address));
    cJSON_AddItemToObject(o, "dst_address", vl_api_address_t_tojson(&a->dst_address));
    cJSON_AddNumberToObject(o, "mcast_sw_if_index", a->mcast_sw_if_index);
    cJSON_AddNumberToObject(o, "encap_vrf_id", a->encap_vrf_id);
    cJSON_AddNumberToObject(o, "decap_next_index", a->decap_next_index);
    cJSON_AddNumberToObject(o, "vni", a->vni);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_geneve_bypass_t_tojson (vl_api_sw_interface_set_geneve_bypass_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_geneve_bypass");
    cJSON_AddStringToObject(o, "_crc", "65247409");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_ipv6", a->is_ipv6);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_geneve_bypass_reply_t_tojson (vl_api_sw_interface_set_geneve_bypass_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_geneve_bypass_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
