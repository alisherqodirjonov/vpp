/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/tunnel/tunnel_types.api_tojson.h>
#ifndef included_ipip_api_tojson_h
#define included_ipip_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_ipip_tunnel_t_tojson (vl_api_ipip_tunnel_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "instance", a->instance);
    cJSON_AddItemToObject(o, "src", vl_api_address_t_tojson(&a->src));
    cJSON_AddItemToObject(o, "dst", vl_api_address_t_tojson(&a->dst));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddItemToObject(o, "flags", vl_api_tunnel_encap_decap_flags_t_tojson(a->flags));
    cJSON_AddItemToObject(o, "mode", vl_api_tunnel_mode_t_tojson(a->mode));
    cJSON_AddItemToObject(o, "dscp", vl_api_ip_dscp_t_tojson(a->dscp));
    return o;
}
static inline cJSON *vl_api_ipip_add_tunnel_t_tojson (vl_api_ipip_add_tunnel_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipip_add_tunnel");
    cJSON_AddStringToObject(o, "_crc", "2ac399f5");
    cJSON_AddItemToObject(o, "tunnel", vl_api_ipip_tunnel_t_tojson(&a->tunnel));
    return o;
}
static inline cJSON *vl_api_ipip_add_tunnel_reply_t_tojson (vl_api_ipip_add_tunnel_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipip_add_tunnel_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_ipip_del_tunnel_t_tojson (vl_api_ipip_del_tunnel_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipip_del_tunnel");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_ipip_del_tunnel_reply_t_tojson (vl_api_ipip_del_tunnel_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipip_del_tunnel_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ipip_6rd_add_tunnel_t_tojson (vl_api_ipip_6rd_add_tunnel_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipip_6rd_add_tunnel");
    cJSON_AddStringToObject(o, "_crc", "b9ec1863");
    cJSON_AddNumberToObject(o, "ip6_table_id", a->ip6_table_id);
    cJSON_AddNumberToObject(o, "ip4_table_id", a->ip4_table_id);
    cJSON_AddItemToObject(o, "ip6_prefix", vl_api_ip6_prefix_t_tojson(&a->ip6_prefix));
    cJSON_AddItemToObject(o, "ip4_prefix", vl_api_ip4_prefix_t_tojson(&a->ip4_prefix));
    cJSON_AddItemToObject(o, "ip4_src", vl_api_ip4_address_t_tojson(&a->ip4_src));
    cJSON_AddBoolToObject(o, "security_check", a->security_check);
    cJSON_AddNumberToObject(o, "tc_tos", a->tc_tos);
    return o;
}
static inline cJSON *vl_api_ipip_6rd_add_tunnel_reply_t_tojson (vl_api_ipip_6rd_add_tunnel_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipip_6rd_add_tunnel_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_ipip_6rd_del_tunnel_t_tojson (vl_api_ipip_6rd_del_tunnel_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipip_6rd_del_tunnel");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_ipip_6rd_del_tunnel_reply_t_tojson (vl_api_ipip_6rd_del_tunnel_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipip_6rd_del_tunnel_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ipip_tunnel_dump_t_tojson (vl_api_ipip_tunnel_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipip_tunnel_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_ipip_tunnel_details_t_tojson (vl_api_ipip_tunnel_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipip_tunnel_details");
    cJSON_AddStringToObject(o, "_crc", "d31cb34e");
    cJSON_AddItemToObject(o, "tunnel", vl_api_ipip_tunnel_t_tojson(&a->tunnel));
    return o;
}
#endif
