/* Imported API files */
#include <lb/lb_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_lb_api_tojson_h
#define included_lb_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_lb_conf_t_tojson (vl_api_lb_conf_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lb_conf");
    cJSON_AddStringToObject(o, "_crc", "56cd3261");
    cJSON_AddItemToObject(o, "ip4_src_address", vl_api_ip4_address_t_tojson(&a->ip4_src_address));
    cJSON_AddItemToObject(o, "ip6_src_address", vl_api_ip6_address_t_tojson(&a->ip6_src_address));
    cJSON_AddNumberToObject(o, "sticky_buckets_per_core", a->sticky_buckets_per_core);
    cJSON_AddNumberToObject(o, "flow_timeout", a->flow_timeout);
    return o;
}
static inline cJSON *vl_api_lb_conf_reply_t_tojson (vl_api_lb_conf_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lb_conf_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lb_add_del_vip_t_tojson (vl_api_lb_add_del_vip_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lb_add_del_vip");
    cJSON_AddStringToObject(o, "_crc", "6fa569c7");
    cJSON_AddItemToObject(o, "pfx", vl_api_address_with_prefix_t_tojson(&a->pfx));
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddNumberToObject(o, "port", a->port);
    cJSON_AddItemToObject(o, "encap", vl_api_lb_encap_type_t_tojson(a->encap));
    cJSON_AddNumberToObject(o, "dscp", a->dscp);
    cJSON_AddItemToObject(o, "type", vl_api_lb_srv_type_t_tojson(a->type));
    cJSON_AddNumberToObject(o, "target_port", a->target_port);
    cJSON_AddNumberToObject(o, "node_port", a->node_port);
    cJSON_AddNumberToObject(o, "new_flows_table_length", a->new_flows_table_length);
    cJSON_AddBoolToObject(o, "is_del", a->is_del);
    return o;
}
static inline cJSON *vl_api_lb_add_del_vip_reply_t_tojson (vl_api_lb_add_del_vip_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lb_add_del_vip_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lb_add_del_vip_v2_t_tojson (vl_api_lb_add_del_vip_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lb_add_del_vip_v2");
    cJSON_AddStringToObject(o, "_crc", "7c520e0f");
    cJSON_AddItemToObject(o, "pfx", vl_api_address_with_prefix_t_tojson(&a->pfx));
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddNumberToObject(o, "port", a->port);
    cJSON_AddItemToObject(o, "encap", vl_api_lb_encap_type_t_tojson(a->encap));
    cJSON_AddNumberToObject(o, "dscp", a->dscp);
    cJSON_AddItemToObject(o, "type", vl_api_lb_srv_type_t_tojson(a->type));
    cJSON_AddNumberToObject(o, "target_port", a->target_port);
    cJSON_AddNumberToObject(o, "node_port", a->node_port);
    cJSON_AddNumberToObject(o, "new_flows_table_length", a->new_flows_table_length);
    cJSON_AddBoolToObject(o, "src_ip_sticky", a->src_ip_sticky);
    cJSON_AddBoolToObject(o, "is_del", a->is_del);
    return o;
}
static inline cJSON *vl_api_lb_add_del_vip_v2_reply_t_tojson (vl_api_lb_add_del_vip_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lb_add_del_vip_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lb_add_del_as_t_tojson (vl_api_lb_add_del_as_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lb_add_del_as");
    cJSON_AddStringToObject(o, "_crc", "35d72500");
    cJSON_AddItemToObject(o, "pfx", vl_api_address_with_prefix_t_tojson(&a->pfx));
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddNumberToObject(o, "port", a->port);
    cJSON_AddItemToObject(o, "as_address", vl_api_address_t_tojson(&a->as_address));
    cJSON_AddBoolToObject(o, "is_del", a->is_del);
    cJSON_AddBoolToObject(o, "is_flush", a->is_flush);
    return o;
}
static inline cJSON *vl_api_lb_add_del_as_reply_t_tojson (vl_api_lb_add_del_as_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lb_add_del_as_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lb_flush_vip_t_tojson (vl_api_lb_flush_vip_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lb_flush_vip");
    cJSON_AddStringToObject(o, "_crc", "1063f819");
    cJSON_AddItemToObject(o, "pfx", vl_api_address_with_prefix_t_tojson(&a->pfx));
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddNumberToObject(o, "port", a->port);
    return o;
}
static inline cJSON *vl_api_lb_flush_vip_reply_t_tojson (vl_api_lb_flush_vip_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lb_flush_vip_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lb_vip_dump_t_tojson (vl_api_lb_vip_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lb_vip_dump");
    cJSON_AddStringToObject(o, "_crc", "56110cb7");
    cJSON_AddItemToObject(o, "pfx", vl_api_address_with_prefix_t_tojson(&a->pfx));
    cJSON_AddItemToObject(o, "pfx_matcher", vl_api_prefix_matcher_t_tojson(&a->pfx_matcher));
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddNumberToObject(o, "port", a->port);
    return o;
}
static inline cJSON *vl_api_lb_vip_details_t_tojson (vl_api_lb_vip_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lb_vip_details");
    cJSON_AddStringToObject(o, "_crc", "1329ec9b");
    cJSON_AddItemToObject(o, "vip", vl_api_lb_vip_t_tojson(&a->vip));
    cJSON_AddItemToObject(o, "encap", vl_api_lb_encap_type_t_tojson(a->encap));
    cJSON_AddItemToObject(o, "dscp", vl_api_ip_dscp_t_tojson(a->dscp));
    cJSON_AddItemToObject(o, "srv_type", vl_api_lb_srv_type_t_tojson(a->srv_type));
    cJSON_AddNumberToObject(o, "target_port", a->target_port);
    cJSON_AddNumberToObject(o, "flow_table_length", a->flow_table_length);
    return o;
}
static inline cJSON *vl_api_lb_as_dump_t_tojson (vl_api_lb_as_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lb_as_dump");
    cJSON_AddStringToObject(o, "_crc", "1063f819");
    cJSON_AddItemToObject(o, "pfx", vl_api_address_with_prefix_t_tojson(&a->pfx));
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddNumberToObject(o, "port", a->port);
    return o;
}
static inline cJSON *vl_api_lb_as_details_t_tojson (vl_api_lb_as_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lb_as_details");
    cJSON_AddStringToObject(o, "_crc", "8d24c29e");
    cJSON_AddItemToObject(o, "vip", vl_api_lb_vip_t_tojson(&a->vip));
    cJSON_AddItemToObject(o, "app_srv", vl_api_address_t_tojson(&a->app_srv));
    cJSON_AddNumberToObject(o, "flags", a->flags);
    cJSON_AddNumberToObject(o, "in_use_since", a->in_use_since);
    return o;
}
static inline cJSON *vl_api_lb_add_del_intf_nat4_t_tojson (vl_api_lb_add_del_intf_nat4_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lb_add_del_intf_nat4");
    cJSON_AddStringToObject(o, "_crc", "47d6e753");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_lb_add_del_intf_nat4_reply_t_tojson (vl_api_lb_add_del_intf_nat4_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lb_add_del_intf_nat4_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lb_add_del_intf_nat6_t_tojson (vl_api_lb_add_del_intf_nat6_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lb_add_del_intf_nat6");
    cJSON_AddStringToObject(o, "_crc", "47d6e753");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_lb_add_del_intf_nat6_reply_t_tojson (vl_api_lb_add_del_intf_nat6_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lb_add_del_intf_nat6_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
