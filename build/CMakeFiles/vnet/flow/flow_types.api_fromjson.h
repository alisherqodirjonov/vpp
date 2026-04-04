/* Imported API files */
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_flow_types_api_fromjson_h
#define included_flow_types_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_flow_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_flow_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "FLOW_TYPE_ETHERNET") == 0) {*a = 1; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP4") == 0) {*a = 2; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP6") == 0) {*a = 3; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP4_L2TPV3OIP") == 0) {*a = 4; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP4_IPSEC_ESP") == 0) {*a = 5; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP4_IPSEC_AH") == 0) {*a = 6; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP4_N_TUPLE") == 0) {*a = 7; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP6_N_TUPLE") == 0) {*a = 8; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP4_N_TUPLE_TAGGED") == 0) {*a = 9; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP6_N_TUPLE_TAGGED") == 0) {*a = 10; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP4_VXLAN") == 0) {*a = 11; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP6_VXLAN") == 0) {*a = 12; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP4_GTPC") == 0) {*a = 13; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP4_GTPU") == 0) {*a = 14; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_flow_type_v2_t_fromjson(void **mp, int *len, cJSON *o, vl_api_flow_type_v2_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "FLOW_TYPE_ETHERNET_V2") == 0) {*a = 1; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP4_V2") == 0) {*a = 2; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP6_V2") == 0) {*a = 3; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP4_L2TPV3OIP_V2") == 0) {*a = 4; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP4_IPSEC_ESP_V2") == 0) {*a = 5; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP4_IPSEC_AH_V2") == 0) {*a = 6; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP4_N_TUPLE_V2") == 0) {*a = 7; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP6_N_TUPLE_V2") == 0) {*a = 8; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP4_N_TUPLE_TAGGED_V2") == 0) {*a = 9; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP6_N_TUPLE_TAGGED_V2") == 0) {*a = 10; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP4_VXLAN_V2") == 0) {*a = 11; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP6_VXLAN_V2") == 0) {*a = 12; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP4_GTPC_V2") == 0) {*a = 13; return 0;}
    if (strcmp(p, "FLOW_TYPE_IP4_GTPU_V2") == 0) {*a = 14; return 0;}
    if (strcmp(p, "FLOW_TYPE_GENERIC_V2") == 0) {*a = 15; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_flow_action_t_fromjson(void **mp, int *len, cJSON *o, vl_api_flow_action_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "FLOW_ACTION_COUNT") == 0) {*a = 1; return 0;}
    if (strcmp(p, "FLOW_ACTION_MARK") == 0) {*a = 2; return 0;}
    if (strcmp(p, "FLOW_ACTION_BUFFER_ADVANCE") == 0) {*a = 4; return 0;}
    if (strcmp(p, "FLOW_ACTION_REDIRECT_TO_NODE") == 0) {*a = 8; return 0;}
    if (strcmp(p, "FLOW_ACTION_REDIRECT_TO_QUEUE") == 0) {*a = 16; return 0;}
    if (strcmp(p, "FLOW_ACTION_DROP") == 0) {*a = 64; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_flow_action_v2_t_fromjson(void **mp, int *len, cJSON *o, vl_api_flow_action_v2_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "FLOW_ACTION_COUNT_V2") == 0) {*a = 1; return 0;}
    if (strcmp(p, "FLOW_ACTION_MARK_V2") == 0) {*a = 2; return 0;}
    if (strcmp(p, "FLOW_ACTION_BUFFER_ADVANCE_V2") == 0) {*a = 4; return 0;}
    if (strcmp(p, "FLOW_ACTION_REDIRECT_TO_NODE_V2") == 0) {*a = 8; return 0;}
    if (strcmp(p, "FLOW_ACTION_REDIRECT_TO_QUEUE_V2") == 0) {*a = 16; return 0;}
    if (strcmp(p, "FLOW_ACTION_RSS_V2") == 0) {*a = 32; return 0;}
    if (strcmp(p, "FLOW_ACTION_DROP_V2") == 0) {*a = 64; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_rss_function_t_fromjson(void **mp, int *len, cJSON *o, vl_api_rss_function_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "RSS_FUNC_DEFAULT") == 0) {*a = 0; return 0;}
    if (strcmp(p, "RSS_FUNC_TOEPLITZ") == 0) {*a = 1; return 0;}
    if (strcmp(p, "RSS_FUNC_SIMPLE_XOR") == 0) {*a = 2; return 0;}
    if (strcmp(p, "RSS_FUNC_SYMMETRIC_TOEPLITZ") == 0) {*a = 3; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_generic_pattern_t_fromjson (void **mp, int *len, cJSON *o, vl_api_generic_pattern_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "spec");
    if (!item) goto error;
    if (u8string_fromjson2(o, "spec", a->spec) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mask");
    if (!item) goto error;
    if (u8string_fromjson2(o, "mask", a->mask) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_ip_port_and_mask_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ip_port_and_mask_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->port);

    item = cJSON_GetObjectItem(o, "mask");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->mask);

    return 0;

  error:
    return -1;
}
static inline int vl_api_ip_prot_and_mask_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ip_prot_and_mask_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "prot");
    if (!item) goto error;
    if (vl_api_ip_proto_t_fromjson(mp, len, item, &a->prot) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mask");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->mask);

    return 0;

  error:
    return -1;
}
static inline int vl_api_flow_ethernet_t_fromjson (void **mp, int *len, cJSON *o, vl_api_flow_ethernet_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "foo");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->foo);

    item = cJSON_GetObjectItem(o, "src_addr");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson(mp, len, item, &a->src_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_addr");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson(mp, len, item, &a->dst_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->type);

    return 0;

  error:
    return -1;
}
static inline int vl_api_flow_ip4_t_fromjson (void **mp, int *len, cJSON *o, vl_api_flow_ip4_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "foo");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->foo);

    item = cJSON_GetObjectItem(o, "src_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_and_mask_t_fromjson(mp, len, item, &a->src_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_and_mask_t_fromjson(mp, len, item, &a->dst_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ip_prot_and_mask_t_fromjson(mp, len, item, &a->protocol) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_flow_ip6_t_fromjson (void **mp, int *len, cJSON *o, vl_api_flow_ip6_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "foo");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->foo);

    item = cJSON_GetObjectItem(o, "src_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_and_mask_t_fromjson(mp, len, item, &a->src_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_and_mask_t_fromjson(mp, len, item, &a->dst_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ip_prot_and_mask_t_fromjson(mp, len, item, &a->protocol) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_flow_ip4_n_tuple_t_fromjson (void **mp, int *len, cJSON *o, vl_api_flow_ip4_n_tuple_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "foo");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->foo);

    item = cJSON_GetObjectItem(o, "src_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_and_mask_t_fromjson(mp, len, item, &a->src_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_and_mask_t_fromjson(mp, len, item, &a->dst_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ip_prot_and_mask_t_fromjson(mp, len, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "src_port");
    if (!item) goto error;
    if (vl_api_ip_port_and_mask_t_fromjson(mp, len, item, &a->src_port) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_port");
    if (!item) goto error;
    if (vl_api_ip_port_and_mask_t_fromjson(mp, len, item, &a->dst_port) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_flow_ip6_n_tuple_t_fromjson (void **mp, int *len, cJSON *o, vl_api_flow_ip6_n_tuple_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "foo");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->foo);

    item = cJSON_GetObjectItem(o, "src_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_and_mask_t_fromjson(mp, len, item, &a->src_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_and_mask_t_fromjson(mp, len, item, &a->dst_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ip_prot_and_mask_t_fromjson(mp, len, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "src_port");
    if (!item) goto error;
    if (vl_api_ip_port_and_mask_t_fromjson(mp, len, item, &a->src_port) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_port");
    if (!item) goto error;
    if (vl_api_ip_port_and_mask_t_fromjson(mp, len, item, &a->dst_port) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_flow_ip4_n_tuple_tagged_t_fromjson (void **mp, int *len, cJSON *o, vl_api_flow_ip4_n_tuple_tagged_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "foo");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->foo);

    item = cJSON_GetObjectItem(o, "src_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_and_mask_t_fromjson(mp, len, item, &a->src_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_and_mask_t_fromjson(mp, len, item, &a->dst_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ip_prot_and_mask_t_fromjson(mp, len, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "src_port");
    if (!item) goto error;
    if (vl_api_ip_port_and_mask_t_fromjson(mp, len, item, &a->src_port) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_port");
    if (!item) goto error;
    if (vl_api_ip_port_and_mask_t_fromjson(mp, len, item, &a->dst_port) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_flow_ip6_n_tuple_tagged_t_fromjson (void **mp, int *len, cJSON *o, vl_api_flow_ip6_n_tuple_tagged_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "foo");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->foo);

    item = cJSON_GetObjectItem(o, "src_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_and_mask_t_fromjson(mp, len, item, &a->src_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_and_mask_t_fromjson(mp, len, item, &a->dst_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ip_prot_and_mask_t_fromjson(mp, len, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "src_port");
    if (!item) goto error;
    if (vl_api_ip_port_and_mask_t_fromjson(mp, len, item, &a->src_port) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_port");
    if (!item) goto error;
    if (vl_api_ip_port_and_mask_t_fromjson(mp, len, item, &a->dst_port) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_flow_ip4_l2tpv3oip_t_fromjson (void **mp, int *len, cJSON *o, vl_api_flow_ip4_l2tpv3oip_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "foo");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->foo);

    item = cJSON_GetObjectItem(o, "src_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_and_mask_t_fromjson(mp, len, item, &a->src_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_and_mask_t_fromjson(mp, len, item, &a->dst_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ip_prot_and_mask_t_fromjson(mp, len, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "session_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->session_id);

    return 0;

  error:
    return -1;
}
static inline int vl_api_flow_ip4_ipsec_esp_t_fromjson (void **mp, int *len, cJSON *o, vl_api_flow_ip4_ipsec_esp_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "foo");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->foo);

    item = cJSON_GetObjectItem(o, "src_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_and_mask_t_fromjson(mp, len, item, &a->src_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_and_mask_t_fromjson(mp, len, item, &a->dst_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ip_prot_and_mask_t_fromjson(mp, len, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "spi");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->spi);

    return 0;

  error:
    return -1;
}
static inline int vl_api_flow_ip4_ipsec_ah_t_fromjson (void **mp, int *len, cJSON *o, vl_api_flow_ip4_ipsec_ah_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "foo");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->foo);

    item = cJSON_GetObjectItem(o, "src_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_and_mask_t_fromjson(mp, len, item, &a->src_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_and_mask_t_fromjson(mp, len, item, &a->dst_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ip_prot_and_mask_t_fromjson(mp, len, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "spi");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->spi);

    return 0;

  error:
    return -1;
}
static inline int vl_api_flow_ip4_vxlan_t_fromjson (void **mp, int *len, cJSON *o, vl_api_flow_ip4_vxlan_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "foo");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->foo);

    item = cJSON_GetObjectItem(o, "src_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_and_mask_t_fromjson(mp, len, item, &a->src_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_and_mask_t_fromjson(mp, len, item, &a->dst_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ip_prot_and_mask_t_fromjson(mp, len, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "src_port");
    if (!item) goto error;
    if (vl_api_ip_port_and_mask_t_fromjson(mp, len, item, &a->src_port) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_port");
    if (!item) goto error;
    if (vl_api_ip_port_and_mask_t_fromjson(mp, len, item, &a->dst_port) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    return 0;

  error:
    return -1;
}
static inline int vl_api_flow_ip6_vxlan_t_fromjson (void **mp, int *len, cJSON *o, vl_api_flow_ip6_vxlan_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "foo");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->foo);

    item = cJSON_GetObjectItem(o, "src_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_and_mask_t_fromjson(mp, len, item, &a->src_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_and_mask_t_fromjson(mp, len, item, &a->dst_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ip_prot_and_mask_t_fromjson(mp, len, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "src_port");
    if (!item) goto error;
    if (vl_api_ip_port_and_mask_t_fromjson(mp, len, item, &a->src_port) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_port");
    if (!item) goto error;
    if (vl_api_ip_port_and_mask_t_fromjson(mp, len, item, &a->dst_port) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    return 0;

  error:
    return -1;
}
static inline int vl_api_flow_ip4_gtpc_t_fromjson (void **mp, int *len, cJSON *o, vl_api_flow_ip4_gtpc_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "foo");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->foo);

    item = cJSON_GetObjectItem(o, "src_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_and_mask_t_fromjson(mp, len, item, &a->src_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_and_mask_t_fromjson(mp, len, item, &a->dst_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ip_prot_and_mask_t_fromjson(mp, len, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "src_port");
    if (!item) goto error;
    if (vl_api_ip_port_and_mask_t_fromjson(mp, len, item, &a->src_port) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_port");
    if (!item) goto error;
    if (vl_api_ip_port_and_mask_t_fromjson(mp, len, item, &a->dst_port) < 0) goto error;

    item = cJSON_GetObjectItem(o, "teid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->teid);

    return 0;

  error:
    return -1;
}
static inline int vl_api_flow_ip4_gtpu_t_fromjson (void **mp, int *len, cJSON *o, vl_api_flow_ip4_gtpu_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "foo");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->foo);

    item = cJSON_GetObjectItem(o, "src_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_and_mask_t_fromjson(mp, len, item, &a->src_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_and_mask_t_fromjson(mp, len, item, &a->dst_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ip_prot_and_mask_t_fromjson(mp, len, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "src_port");
    if (!item) goto error;
    if (vl_api_ip_port_and_mask_t_fromjson(mp, len, item, &a->src_port) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_port");
    if (!item) goto error;
    if (vl_api_ip_port_and_mask_t_fromjson(mp, len, item, &a->dst_port) < 0) goto error;

    item = cJSON_GetObjectItem(o, "teid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->teid);

    return 0;

  error:
    return -1;
}
static inline int vl_api_flow_generic_t_fromjson (void **mp, int *len, cJSON *o, vl_api_flow_generic_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "foo");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->foo);

    item = cJSON_GetObjectItem(o, "pattern");
    if (!item) goto error;
    if (vl_api_generic_pattern_t_fromjson(mp, len, item, &a->pattern) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_flow_t_fromjson (void **mp, int *len, cJSON *o, vl_api_flow_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    item = cJSON_GetObjectItem(o, "ethernet");
    if (item) {
    if (vl_api_flow_ethernet_t_fromjson(mp, len, item, &a->ethernet) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip4");
    if (item) {
    if (vl_api_flow_ip4_t_fromjson(mp, len, item, &a->ip4) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip6");
    if (item) {
    if (vl_api_flow_ip6_t_fromjson(mp, len, item, &a->ip6) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip4_l2tpv3oip");
    if (item) {
    if (vl_api_flow_ip4_l2tpv3oip_t_fromjson(mp, len, item, &a->ip4_l2tpv3oip) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip4_ipsec_esp");
    if (item) {
    if (vl_api_flow_ip4_ipsec_esp_t_fromjson(mp, len, item, &a->ip4_ipsec_esp) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip4_ipsec_ah");
    if (item) {
    if (vl_api_flow_ip4_ipsec_ah_t_fromjson(mp, len, item, &a->ip4_ipsec_ah) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip4_n_tuple");
    if (item) {
    if (vl_api_flow_ip4_n_tuple_t_fromjson(mp, len, item, &a->ip4_n_tuple) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip6_n_tuple");
    if (item) {
    if (vl_api_flow_ip6_n_tuple_t_fromjson(mp, len, item, &a->ip6_n_tuple) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip4_n_tuple_tagged");
    if (item) {
    if (vl_api_flow_ip4_n_tuple_tagged_t_fromjson(mp, len, item, &a->ip4_n_tuple_tagged) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip6_n_tuple_tagged");
    if (item) {
    if (vl_api_flow_ip6_n_tuple_tagged_t_fromjson(mp, len, item, &a->ip6_n_tuple_tagged) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip4_vxlan");
    if (item) {
    if (vl_api_flow_ip4_vxlan_t_fromjson(mp, len, item, &a->ip4_vxlan) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip6_vxlan");
    if (item) {
    if (vl_api_flow_ip6_vxlan_t_fromjson(mp, len, item, &a->ip6_vxlan) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip4_gtpc");
    if (item) {
    if (vl_api_flow_ip4_gtpc_t_fromjson(mp, len, item, &a->ip4_gtpc) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip4_gtpu");
    if (item) {
    if (vl_api_flow_ip4_gtpu_t_fromjson(mp, len, item, &a->ip4_gtpu) < 0) goto error;
    };

    return 0;

  error:
    return -1;
}
static inline int vl_api_flow_v2_t_fromjson (void **mp, int *len, cJSON *o, vl_api_flow_v2_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    item = cJSON_GetObjectItem(o, "ethernet");
    if (item) {
    if (vl_api_flow_ethernet_t_fromjson(mp, len, item, &a->ethernet) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip4");
    if (item) {
    if (vl_api_flow_ip4_t_fromjson(mp, len, item, &a->ip4) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip6");
    if (item) {
    if (vl_api_flow_ip6_t_fromjson(mp, len, item, &a->ip6) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip4_l2tpv3oip");
    if (item) {
    if (vl_api_flow_ip4_l2tpv3oip_t_fromjson(mp, len, item, &a->ip4_l2tpv3oip) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip4_ipsec_esp");
    if (item) {
    if (vl_api_flow_ip4_ipsec_esp_t_fromjson(mp, len, item, &a->ip4_ipsec_esp) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip4_ipsec_ah");
    if (item) {
    if (vl_api_flow_ip4_ipsec_ah_t_fromjson(mp, len, item, &a->ip4_ipsec_ah) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip4_n_tuple");
    if (item) {
    if (vl_api_flow_ip4_n_tuple_t_fromjson(mp, len, item, &a->ip4_n_tuple) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip6_n_tuple");
    if (item) {
    if (vl_api_flow_ip6_n_tuple_t_fromjson(mp, len, item, &a->ip6_n_tuple) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip4_n_tuple_tagged");
    if (item) {
    if (vl_api_flow_ip4_n_tuple_tagged_t_fromjson(mp, len, item, &a->ip4_n_tuple_tagged) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip6_n_tuple_tagged");
    if (item) {
    if (vl_api_flow_ip6_n_tuple_tagged_t_fromjson(mp, len, item, &a->ip6_n_tuple_tagged) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip4_vxlan");
    if (item) {
    if (vl_api_flow_ip4_vxlan_t_fromjson(mp, len, item, &a->ip4_vxlan) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip6_vxlan");
    if (item) {
    if (vl_api_flow_ip6_vxlan_t_fromjson(mp, len, item, &a->ip6_vxlan) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip4_gtpc");
    if (item) {
    if (vl_api_flow_ip4_gtpc_t_fromjson(mp, len, item, &a->ip4_gtpc) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip4_gtpu");
    if (item) {
    if (vl_api_flow_ip4_gtpu_t_fromjson(mp, len, item, &a->ip4_gtpu) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "generic");
    if (item) {
    if (vl_api_flow_generic_t_fromjson(mp, len, item, &a->generic) < 0) goto error;
    };

    return 0;

  error:
    return -1;
}
static inline int vl_api_flow_rule_t_fromjson (void **mp, int *len, cJSON *o, vl_api_flow_rule_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_flow_type_t_fromjson(mp, len, item, &a->type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->index);

    item = cJSON_GetObjectItem(o, "actions");
    if (!item) goto error;
    if (vl_api_flow_action_t_fromjson(mp, len, item, &a->actions) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mark_flow_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mark_flow_id);

    item = cJSON_GetObjectItem(o, "redirect_node_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->redirect_node_index);

    item = cJSON_GetObjectItem(o, "redirect_device_input_next_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->redirect_device_input_next_index);

    item = cJSON_GetObjectItem(o, "redirect_queue");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->redirect_queue);

    item = cJSON_GetObjectItem(o, "buffer_advance");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->buffer_advance);

    item = cJSON_GetObjectItem(o, "flow");
    if (!item) goto error;
    if (vl_api_flow_t_fromjson(mp, len, item, &a->flow) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_flow_rule_v2_t_fromjson (void **mp, int *len, cJSON *o, vl_api_flow_rule_v2_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_flow_type_v2_t_fromjson(mp, len, item, &a->type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->index);

    item = cJSON_GetObjectItem(o, "actions");
    if (!item) goto error;
    if (vl_api_flow_action_v2_t_fromjson(mp, len, item, &a->actions) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mark_flow_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mark_flow_id);

    item = cJSON_GetObjectItem(o, "redirect_node_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->redirect_node_index);

    item = cJSON_GetObjectItem(o, "redirect_device_input_next_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->redirect_device_input_next_index);

    item = cJSON_GetObjectItem(o, "redirect_queue");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->redirect_queue);

    item = cJSON_GetObjectItem(o, "queue_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->queue_index);

    item = cJSON_GetObjectItem(o, "queue_num");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->queue_num);

    item = cJSON_GetObjectItem(o, "buffer_advance");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->buffer_advance);

    item = cJSON_GetObjectItem(o, "rss_types");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->rss_types);

    item = cJSON_GetObjectItem(o, "rss_fun");
    if (!item) goto error;
    if (vl_api_rss_function_t_fromjson(mp, len, item, &a->rss_fun) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flow");
    if (!item) goto error;
    if (vl_api_flow_v2_t_fromjson(mp, len, item, &a->flow) < 0) goto error;

    return 0;

  error:
    return -1;
}
#endif
