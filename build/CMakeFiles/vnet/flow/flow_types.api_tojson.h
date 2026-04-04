/* Imported API files */
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_flow_types_api_tojson_h
#define included_flow_types_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_flow_type_t_tojson (vl_api_flow_type_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("FLOW_TYPE_ETHERNET");
    case 2:
        return cJSON_CreateString("FLOW_TYPE_IP4");
    case 3:
        return cJSON_CreateString("FLOW_TYPE_IP6");
    case 4:
        return cJSON_CreateString("FLOW_TYPE_IP4_L2TPV3OIP");
    case 5:
        return cJSON_CreateString("FLOW_TYPE_IP4_IPSEC_ESP");
    case 6:
        return cJSON_CreateString("FLOW_TYPE_IP4_IPSEC_AH");
    case 7:
        return cJSON_CreateString("FLOW_TYPE_IP4_N_TUPLE");
    case 8:
        return cJSON_CreateString("FLOW_TYPE_IP6_N_TUPLE");
    case 9:
        return cJSON_CreateString("FLOW_TYPE_IP4_N_TUPLE_TAGGED");
    case 10:
        return cJSON_CreateString("FLOW_TYPE_IP6_N_TUPLE_TAGGED");
    case 11:
        return cJSON_CreateString("FLOW_TYPE_IP4_VXLAN");
    case 12:
        return cJSON_CreateString("FLOW_TYPE_IP6_VXLAN");
    case 13:
        return cJSON_CreateString("FLOW_TYPE_IP4_GTPC");
    case 14:
        return cJSON_CreateString("FLOW_TYPE_IP4_GTPU");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_flow_type_v2_t_tojson (vl_api_flow_type_v2_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("FLOW_TYPE_ETHERNET_V2");
    case 2:
        return cJSON_CreateString("FLOW_TYPE_IP4_V2");
    case 3:
        return cJSON_CreateString("FLOW_TYPE_IP6_V2");
    case 4:
        return cJSON_CreateString("FLOW_TYPE_IP4_L2TPV3OIP_V2");
    case 5:
        return cJSON_CreateString("FLOW_TYPE_IP4_IPSEC_ESP_V2");
    case 6:
        return cJSON_CreateString("FLOW_TYPE_IP4_IPSEC_AH_V2");
    case 7:
        return cJSON_CreateString("FLOW_TYPE_IP4_N_TUPLE_V2");
    case 8:
        return cJSON_CreateString("FLOW_TYPE_IP6_N_TUPLE_V2");
    case 9:
        return cJSON_CreateString("FLOW_TYPE_IP4_N_TUPLE_TAGGED_V2");
    case 10:
        return cJSON_CreateString("FLOW_TYPE_IP6_N_TUPLE_TAGGED_V2");
    case 11:
        return cJSON_CreateString("FLOW_TYPE_IP4_VXLAN_V2");
    case 12:
        return cJSON_CreateString("FLOW_TYPE_IP6_VXLAN_V2");
    case 13:
        return cJSON_CreateString("FLOW_TYPE_IP4_GTPC_V2");
    case 14:
        return cJSON_CreateString("FLOW_TYPE_IP4_GTPU_V2");
    case 15:
        return cJSON_CreateString("FLOW_TYPE_GENERIC_V2");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_flow_action_t_tojson (vl_api_flow_action_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("FLOW_ACTION_COUNT");
    case 2:
        return cJSON_CreateString("FLOW_ACTION_MARK");
    case 4:
        return cJSON_CreateString("FLOW_ACTION_BUFFER_ADVANCE");
    case 8:
        return cJSON_CreateString("FLOW_ACTION_REDIRECT_TO_NODE");
    case 16:
        return cJSON_CreateString("FLOW_ACTION_REDIRECT_TO_QUEUE");
    case 64:
        return cJSON_CreateString("FLOW_ACTION_DROP");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_flow_action_v2_t_tojson (vl_api_flow_action_v2_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("FLOW_ACTION_COUNT_V2");
    case 2:
        return cJSON_CreateString("FLOW_ACTION_MARK_V2");
    case 4:
        return cJSON_CreateString("FLOW_ACTION_BUFFER_ADVANCE_V2");
    case 8:
        return cJSON_CreateString("FLOW_ACTION_REDIRECT_TO_NODE_V2");
    case 16:
        return cJSON_CreateString("FLOW_ACTION_REDIRECT_TO_QUEUE_V2");
    case 32:
        return cJSON_CreateString("FLOW_ACTION_RSS_V2");
    case 64:
        return cJSON_CreateString("FLOW_ACTION_DROP_V2");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_rss_function_t_tojson (vl_api_rss_function_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("RSS_FUNC_DEFAULT");
    case 1:
        return cJSON_CreateString("RSS_FUNC_TOEPLITZ");
    case 2:
        return cJSON_CreateString("RSS_FUNC_SIMPLE_XOR");
    case 3:
        return cJSON_CreateString("RSS_FUNC_SYMMETRIC_TOEPLITZ");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_generic_pattern_t_tojson (vl_api_generic_pattern_t *a) {
    cJSON *o = cJSON_CreateObject();
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->spec, 1024);
    cJSON_AddStringToObject(o, "spec", s);
    vec_free(s);
    }
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->mask, 1024);
    cJSON_AddStringToObject(o, "mask", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_ip_port_and_mask_t_tojson (vl_api_ip_port_and_mask_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "port", a->port);
    cJSON_AddNumberToObject(o, "mask", a->mask);
    return o;
}
static inline cJSON *vl_api_ip_prot_and_mask_t_tojson (vl_api_ip_prot_and_mask_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "prot", vl_api_ip_proto_t_tojson(a->prot));
    cJSON_AddNumberToObject(o, "mask", a->mask);
    return o;
}
static inline cJSON *vl_api_flow_ethernet_t_tojson (vl_api_flow_ethernet_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "foo", a->foo);
    cJSON_AddItemToObject(o, "src_addr", vl_api_mac_address_t_tojson(&a->src_addr));
    cJSON_AddItemToObject(o, "dst_addr", vl_api_mac_address_t_tojson(&a->dst_addr));
    cJSON_AddNumberToObject(o, "type", a->type);
    return o;
}
static inline cJSON *vl_api_flow_ip4_t_tojson (vl_api_flow_ip4_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "foo", a->foo);
    cJSON_AddItemToObject(o, "src_addr", vl_api_ip4_address_and_mask_t_tojson(&a->src_addr));
    cJSON_AddItemToObject(o, "dst_addr", vl_api_ip4_address_and_mask_t_tojson(&a->dst_addr));
    cJSON_AddItemToObject(o, "protocol", vl_api_ip_prot_and_mask_t_tojson(&a->protocol));
    return o;
}
static inline cJSON *vl_api_flow_ip6_t_tojson (vl_api_flow_ip6_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "foo", a->foo);
    cJSON_AddItemToObject(o, "src_addr", vl_api_ip6_address_and_mask_t_tojson(&a->src_addr));
    cJSON_AddItemToObject(o, "dst_addr", vl_api_ip6_address_and_mask_t_tojson(&a->dst_addr));
    cJSON_AddItemToObject(o, "protocol", vl_api_ip_prot_and_mask_t_tojson(&a->protocol));
    return o;
}
static inline cJSON *vl_api_flow_ip4_n_tuple_t_tojson (vl_api_flow_ip4_n_tuple_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "foo", a->foo);
    cJSON_AddItemToObject(o, "src_addr", vl_api_ip4_address_and_mask_t_tojson(&a->src_addr));
    cJSON_AddItemToObject(o, "dst_addr", vl_api_ip4_address_and_mask_t_tojson(&a->dst_addr));
    cJSON_AddItemToObject(o, "protocol", vl_api_ip_prot_and_mask_t_tojson(&a->protocol));
    cJSON_AddItemToObject(o, "src_port", vl_api_ip_port_and_mask_t_tojson(&a->src_port));
    cJSON_AddItemToObject(o, "dst_port", vl_api_ip_port_and_mask_t_tojson(&a->dst_port));
    return o;
}
static inline cJSON *vl_api_flow_ip6_n_tuple_t_tojson (vl_api_flow_ip6_n_tuple_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "foo", a->foo);
    cJSON_AddItemToObject(o, "src_addr", vl_api_ip6_address_and_mask_t_tojson(&a->src_addr));
    cJSON_AddItemToObject(o, "dst_addr", vl_api_ip6_address_and_mask_t_tojson(&a->dst_addr));
    cJSON_AddItemToObject(o, "protocol", vl_api_ip_prot_and_mask_t_tojson(&a->protocol));
    cJSON_AddItemToObject(o, "src_port", vl_api_ip_port_and_mask_t_tojson(&a->src_port));
    cJSON_AddItemToObject(o, "dst_port", vl_api_ip_port_and_mask_t_tojson(&a->dst_port));
    return o;
}
static inline cJSON *vl_api_flow_ip4_n_tuple_tagged_t_tojson (vl_api_flow_ip4_n_tuple_tagged_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "foo", a->foo);
    cJSON_AddItemToObject(o, "src_addr", vl_api_ip4_address_and_mask_t_tojson(&a->src_addr));
    cJSON_AddItemToObject(o, "dst_addr", vl_api_ip4_address_and_mask_t_tojson(&a->dst_addr));
    cJSON_AddItemToObject(o, "protocol", vl_api_ip_prot_and_mask_t_tojson(&a->protocol));
    cJSON_AddItemToObject(o, "src_port", vl_api_ip_port_and_mask_t_tojson(&a->src_port));
    cJSON_AddItemToObject(o, "dst_port", vl_api_ip_port_and_mask_t_tojson(&a->dst_port));
    return o;
}
static inline cJSON *vl_api_flow_ip6_n_tuple_tagged_t_tojson (vl_api_flow_ip6_n_tuple_tagged_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "foo", a->foo);
    cJSON_AddItemToObject(o, "src_addr", vl_api_ip6_address_and_mask_t_tojson(&a->src_addr));
    cJSON_AddItemToObject(o, "dst_addr", vl_api_ip6_address_and_mask_t_tojson(&a->dst_addr));
    cJSON_AddItemToObject(o, "protocol", vl_api_ip_prot_and_mask_t_tojson(&a->protocol));
    cJSON_AddItemToObject(o, "src_port", vl_api_ip_port_and_mask_t_tojson(&a->src_port));
    cJSON_AddItemToObject(o, "dst_port", vl_api_ip_port_and_mask_t_tojson(&a->dst_port));
    return o;
}
static inline cJSON *vl_api_flow_ip4_l2tpv3oip_t_tojson (vl_api_flow_ip4_l2tpv3oip_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "foo", a->foo);
    cJSON_AddItemToObject(o, "src_addr", vl_api_ip4_address_and_mask_t_tojson(&a->src_addr));
    cJSON_AddItemToObject(o, "dst_addr", vl_api_ip4_address_and_mask_t_tojson(&a->dst_addr));
    cJSON_AddItemToObject(o, "protocol", vl_api_ip_prot_and_mask_t_tojson(&a->protocol));
    cJSON_AddNumberToObject(o, "session_id", a->session_id);
    return o;
}
static inline cJSON *vl_api_flow_ip4_ipsec_esp_t_tojson (vl_api_flow_ip4_ipsec_esp_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "foo", a->foo);
    cJSON_AddItemToObject(o, "src_addr", vl_api_ip4_address_and_mask_t_tojson(&a->src_addr));
    cJSON_AddItemToObject(o, "dst_addr", vl_api_ip4_address_and_mask_t_tojson(&a->dst_addr));
    cJSON_AddItemToObject(o, "protocol", vl_api_ip_prot_and_mask_t_tojson(&a->protocol));
    cJSON_AddNumberToObject(o, "spi", a->spi);
    return o;
}
static inline cJSON *vl_api_flow_ip4_ipsec_ah_t_tojson (vl_api_flow_ip4_ipsec_ah_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "foo", a->foo);
    cJSON_AddItemToObject(o, "src_addr", vl_api_ip4_address_and_mask_t_tojson(&a->src_addr));
    cJSON_AddItemToObject(o, "dst_addr", vl_api_ip4_address_and_mask_t_tojson(&a->dst_addr));
    cJSON_AddItemToObject(o, "protocol", vl_api_ip_prot_and_mask_t_tojson(&a->protocol));
    cJSON_AddNumberToObject(o, "spi", a->spi);
    return o;
}
static inline cJSON *vl_api_flow_ip4_vxlan_t_tojson (vl_api_flow_ip4_vxlan_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "foo", a->foo);
    cJSON_AddItemToObject(o, "src_addr", vl_api_ip4_address_and_mask_t_tojson(&a->src_addr));
    cJSON_AddItemToObject(o, "dst_addr", vl_api_ip4_address_and_mask_t_tojson(&a->dst_addr));
    cJSON_AddItemToObject(o, "protocol", vl_api_ip_prot_and_mask_t_tojson(&a->protocol));
    cJSON_AddItemToObject(o, "src_port", vl_api_ip_port_and_mask_t_tojson(&a->src_port));
    cJSON_AddItemToObject(o, "dst_port", vl_api_ip_port_and_mask_t_tojson(&a->dst_port));
    cJSON_AddNumberToObject(o, "vni", a->vni);
    return o;
}
static inline cJSON *vl_api_flow_ip6_vxlan_t_tojson (vl_api_flow_ip6_vxlan_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "foo", a->foo);
    cJSON_AddItemToObject(o, "src_addr", vl_api_ip6_address_and_mask_t_tojson(&a->src_addr));
    cJSON_AddItemToObject(o, "dst_addr", vl_api_ip6_address_and_mask_t_tojson(&a->dst_addr));
    cJSON_AddItemToObject(o, "protocol", vl_api_ip_prot_and_mask_t_tojson(&a->protocol));
    cJSON_AddItemToObject(o, "src_port", vl_api_ip_port_and_mask_t_tojson(&a->src_port));
    cJSON_AddItemToObject(o, "dst_port", vl_api_ip_port_and_mask_t_tojson(&a->dst_port));
    cJSON_AddNumberToObject(o, "vni", a->vni);
    return o;
}
static inline cJSON *vl_api_flow_ip4_gtpc_t_tojson (vl_api_flow_ip4_gtpc_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "foo", a->foo);
    cJSON_AddItemToObject(o, "src_addr", vl_api_ip4_address_and_mask_t_tojson(&a->src_addr));
    cJSON_AddItemToObject(o, "dst_addr", vl_api_ip4_address_and_mask_t_tojson(&a->dst_addr));
    cJSON_AddItemToObject(o, "protocol", vl_api_ip_prot_and_mask_t_tojson(&a->protocol));
    cJSON_AddItemToObject(o, "src_port", vl_api_ip_port_and_mask_t_tojson(&a->src_port));
    cJSON_AddItemToObject(o, "dst_port", vl_api_ip_port_and_mask_t_tojson(&a->dst_port));
    cJSON_AddNumberToObject(o, "teid", a->teid);
    return o;
}
static inline cJSON *vl_api_flow_ip4_gtpu_t_tojson (vl_api_flow_ip4_gtpu_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "foo", a->foo);
    cJSON_AddItemToObject(o, "src_addr", vl_api_ip4_address_and_mask_t_tojson(&a->src_addr));
    cJSON_AddItemToObject(o, "dst_addr", vl_api_ip4_address_and_mask_t_tojson(&a->dst_addr));
    cJSON_AddItemToObject(o, "protocol", vl_api_ip_prot_and_mask_t_tojson(&a->protocol));
    cJSON_AddItemToObject(o, "src_port", vl_api_ip_port_and_mask_t_tojson(&a->src_port));
    cJSON_AddItemToObject(o, "dst_port", vl_api_ip_port_and_mask_t_tojson(&a->dst_port));
    cJSON_AddNumberToObject(o, "teid", a->teid);
    return o;
}
static inline cJSON *vl_api_flow_generic_t_tojson (vl_api_flow_generic_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "foo", a->foo);
    cJSON_AddItemToObject(o, "pattern", vl_api_generic_pattern_t_tojson(&a->pattern));
    return o;
}
static inline cJSON *vl_api_flow_t_tojson (vl_api_flow_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "ethernet", vl_api_flow_ethernet_t_tojson(&a->ethernet));
    cJSON_AddItemToObject(o, "ip4", vl_api_flow_ip4_t_tojson(&a->ip4));
    cJSON_AddItemToObject(o, "ip6", vl_api_flow_ip6_t_tojson(&a->ip6));
    cJSON_AddItemToObject(o, "ip4_l2tpv3oip", vl_api_flow_ip4_l2tpv3oip_t_tojson(&a->ip4_l2tpv3oip));
    cJSON_AddItemToObject(o, "ip4_ipsec_esp", vl_api_flow_ip4_ipsec_esp_t_tojson(&a->ip4_ipsec_esp));
    cJSON_AddItemToObject(o, "ip4_ipsec_ah", vl_api_flow_ip4_ipsec_ah_t_tojson(&a->ip4_ipsec_ah));
    cJSON_AddItemToObject(o, "ip4_n_tuple", vl_api_flow_ip4_n_tuple_t_tojson(&a->ip4_n_tuple));
    cJSON_AddItemToObject(o, "ip6_n_tuple", vl_api_flow_ip6_n_tuple_t_tojson(&a->ip6_n_tuple));
    cJSON_AddItemToObject(o, "ip4_n_tuple_tagged", vl_api_flow_ip4_n_tuple_tagged_t_tojson(&a->ip4_n_tuple_tagged));
    cJSON_AddItemToObject(o, "ip6_n_tuple_tagged", vl_api_flow_ip6_n_tuple_tagged_t_tojson(&a->ip6_n_tuple_tagged));
    cJSON_AddItemToObject(o, "ip4_vxlan", vl_api_flow_ip4_vxlan_t_tojson(&a->ip4_vxlan));
    cJSON_AddItemToObject(o, "ip6_vxlan", vl_api_flow_ip6_vxlan_t_tojson(&a->ip6_vxlan));
    cJSON_AddItemToObject(o, "ip4_gtpc", vl_api_flow_ip4_gtpc_t_tojson(&a->ip4_gtpc));
    cJSON_AddItemToObject(o, "ip4_gtpu", vl_api_flow_ip4_gtpu_t_tojson(&a->ip4_gtpu));
    return o;
}
static inline cJSON *vl_api_flow_v2_t_tojson (vl_api_flow_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "ethernet", vl_api_flow_ethernet_t_tojson(&a->ethernet));
    cJSON_AddItemToObject(o, "ip4", vl_api_flow_ip4_t_tojson(&a->ip4));
    cJSON_AddItemToObject(o, "ip6", vl_api_flow_ip6_t_tojson(&a->ip6));
    cJSON_AddItemToObject(o, "ip4_l2tpv3oip", vl_api_flow_ip4_l2tpv3oip_t_tojson(&a->ip4_l2tpv3oip));
    cJSON_AddItemToObject(o, "ip4_ipsec_esp", vl_api_flow_ip4_ipsec_esp_t_tojson(&a->ip4_ipsec_esp));
    cJSON_AddItemToObject(o, "ip4_ipsec_ah", vl_api_flow_ip4_ipsec_ah_t_tojson(&a->ip4_ipsec_ah));
    cJSON_AddItemToObject(o, "ip4_n_tuple", vl_api_flow_ip4_n_tuple_t_tojson(&a->ip4_n_tuple));
    cJSON_AddItemToObject(o, "ip6_n_tuple", vl_api_flow_ip6_n_tuple_t_tojson(&a->ip6_n_tuple));
    cJSON_AddItemToObject(o, "ip4_n_tuple_tagged", vl_api_flow_ip4_n_tuple_tagged_t_tojson(&a->ip4_n_tuple_tagged));
    cJSON_AddItemToObject(o, "ip6_n_tuple_tagged", vl_api_flow_ip6_n_tuple_tagged_t_tojson(&a->ip6_n_tuple_tagged));
    cJSON_AddItemToObject(o, "ip4_vxlan", vl_api_flow_ip4_vxlan_t_tojson(&a->ip4_vxlan));
    cJSON_AddItemToObject(o, "ip6_vxlan", vl_api_flow_ip6_vxlan_t_tojson(&a->ip6_vxlan));
    cJSON_AddItemToObject(o, "ip4_gtpc", vl_api_flow_ip4_gtpc_t_tojson(&a->ip4_gtpc));
    cJSON_AddItemToObject(o, "ip4_gtpu", vl_api_flow_ip4_gtpu_t_tojson(&a->ip4_gtpu));
    cJSON_AddItemToObject(o, "generic", vl_api_flow_generic_t_tojson(&a->generic));
    return o;
}
static inline cJSON *vl_api_flow_rule_t_tojson (vl_api_flow_rule_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "type", vl_api_flow_type_t_tojson(a->type));
    cJSON_AddNumberToObject(o, "index", a->index);
    cJSON_AddItemToObject(o, "actions", vl_api_flow_action_t_tojson(a->actions));
    cJSON_AddNumberToObject(o, "mark_flow_id", a->mark_flow_id);
    cJSON_AddNumberToObject(o, "redirect_node_index", a->redirect_node_index);
    cJSON_AddNumberToObject(o, "redirect_device_input_next_index", a->redirect_device_input_next_index);
    cJSON_AddNumberToObject(o, "redirect_queue", a->redirect_queue);
    cJSON_AddNumberToObject(o, "buffer_advance", a->buffer_advance);
    cJSON_AddItemToObject(o, "flow", vl_api_flow_t_tojson(&a->flow));
    return o;
}
static inline cJSON *vl_api_flow_rule_v2_t_tojson (vl_api_flow_rule_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "type", vl_api_flow_type_v2_t_tojson(a->type));
    cJSON_AddNumberToObject(o, "index", a->index);
    cJSON_AddItemToObject(o, "actions", vl_api_flow_action_v2_t_tojson(a->actions));
    cJSON_AddNumberToObject(o, "mark_flow_id", a->mark_flow_id);
    cJSON_AddNumberToObject(o, "redirect_node_index", a->redirect_node_index);
    cJSON_AddNumberToObject(o, "redirect_device_input_next_index", a->redirect_device_input_next_index);
    cJSON_AddNumberToObject(o, "redirect_queue", a->redirect_queue);
    cJSON_AddNumberToObject(o, "queue_index", a->queue_index);
    cJSON_AddNumberToObject(o, "queue_num", a->queue_num);
    cJSON_AddNumberToObject(o, "buffer_advance", a->buffer_advance);
    cJSON_AddNumberToObject(o, "rss_types", a->rss_types);
    cJSON_AddItemToObject(o, "rss_fun", vl_api_rss_function_t_tojson(a->rss_fun));
    cJSON_AddItemToObject(o, "flow", vl_api_flow_v2_t_tojson(&a->flow));
    return o;
}
#endif
