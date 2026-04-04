/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_tapv2_api_fromjson_h
#define included_tapv2_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_tap_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_tap_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "TAP_API_FLAG_GSO") == 0) {*a = 1; return 0;}
    if (strcmp(p, "TAP_API_FLAG_CSUM_OFFLOAD") == 0) {*a = 2; return 0;}
    if (strcmp(p, "TAP_API_FLAG_PERSIST") == 0) {*a = 4; return 0;}
    if (strcmp(p, "TAP_API_FLAG_ATTACH") == 0) {*a = 8; return 0;}
    if (strcmp(p, "TAP_API_FLAG_TUN") == 0) {*a = 16; return 0;}
    if (strcmp(p, "TAP_API_FLAG_GRO_COALESCE") == 0) {*a = 32; return 0;}
    if (strcmp(p, "TAP_API_FLAG_PACKED") == 0) {*a = 64; return 0;}
    if (strcmp(p, "TAP_API_FLAG_IN_ORDER") == 0) {*a = 128; return 0;}
    if (strcmp(p, "TAP_API_FLAG_CONSISTENT_QP") == 0) {*a = 256; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_tap_create_v3_t *vl_api_tap_create_v3_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_tap_create_v3_t);
    vl_api_tap_create_v3_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "use_random_mac");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->use_random_mac);

    item = cJSON_GetObjectItem(o, "mac_address");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->mac_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "num_rx_queues");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->num_rx_queues);

    item = cJSON_GetObjectItem(o, "num_tx_queues");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->num_tx_queues);

    item = cJSON_GetObjectItem(o, "tx_ring_sz");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->tx_ring_sz);

    item = cJSON_GetObjectItem(o, "rx_ring_sz");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->rx_ring_sz);

    item = cJSON_GetObjectItem(o, "host_mtu_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->host_mtu_set);

    item = cJSON_GetObjectItem(o, "host_mtu_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->host_mtu_size);

    item = cJSON_GetObjectItem(o, "host_mac_addr_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->host_mac_addr_set);

    item = cJSON_GetObjectItem(o, "host_mac_addr");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->host_mac_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "host_ip4_prefix_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->host_ip4_prefix_set);

    item = cJSON_GetObjectItem(o, "host_ip4_prefix");
    if (!item) goto error;
    if (vl_api_ip4_address_with_prefix_t_fromjson((void **)&a, &l, item, &a->host_ip4_prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "host_ip6_prefix_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->host_ip6_prefix_set);

    item = cJSON_GetObjectItem(o, "host_ip6_prefix");
    if (!item) goto error;
    if (vl_api_ip6_address_with_prefix_t_fromjson((void **)&a, &l, item, &a->host_ip6_prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "host_ip4_gw_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->host_ip4_gw_set);

    item = cJSON_GetObjectItem(o, "host_ip4_gw");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->host_ip4_gw) < 0) goto error;

    item = cJSON_GetObjectItem(o, "host_ip6_gw_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->host_ip6_gw_set);

    item = cJSON_GetObjectItem(o, "host_ip6_gw");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->host_ip6_gw) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tap_flags");
    if (!item) goto error;
    if (vl_api_tap_flags_t_fromjson((void **)&a, &l, item, &a->tap_flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "host_namespace_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->host_namespace_set);

    item = cJSON_GetObjectItem(o, "host_namespace");
    if (!item) goto error;
    strncpy_s((char *)a->host_namespace, sizeof(a->host_namespace), cJSON_GetStringValue(item), sizeof(a->host_namespace) - 1);

    item = cJSON_GetObjectItem(o, "host_if_name_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->host_if_name_set);

    item = cJSON_GetObjectItem(o, "host_if_name");
    if (!item) goto error;
    strncpy_s((char *)a->host_if_name, sizeof(a->host_if_name), cJSON_GetStringValue(item), sizeof(a->host_if_name) - 1);

    item = cJSON_GetObjectItem(o, "host_bridge_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->host_bridge_set);

    item = cJSON_GetObjectItem(o, "host_bridge");
    if (!item) goto error;
    strncpy_s((char *)a->host_bridge, sizeof(a->host_bridge), cJSON_GetStringValue(item), sizeof(a->host_bridge) - 1);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    char *p = cJSON_GetStringValue(item);
    size_t plen = strlen(p);
    a = cJSON_realloc(a, l + plen);
    if (a == 0) goto error;
    vl_api_c_string_to_api_string(p, (void *)a + l - sizeof(vl_api_string_t));
    l += plen;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_tap_create_v3_reply_t *vl_api_tap_create_v3_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_tap_create_v3_reply_t);
    vl_api_tap_create_v3_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_tap_create_v2_t *vl_api_tap_create_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_tap_create_v2_t);
    vl_api_tap_create_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "use_random_mac");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->use_random_mac);

    item = cJSON_GetObjectItem(o, "mac_address");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->mac_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "num_rx_queues");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->num_rx_queues);

    item = cJSON_GetObjectItem(o, "tx_ring_sz");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->tx_ring_sz);

    item = cJSON_GetObjectItem(o, "rx_ring_sz");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->rx_ring_sz);

    item = cJSON_GetObjectItem(o, "host_mtu_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->host_mtu_set);

    item = cJSON_GetObjectItem(o, "host_mtu_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->host_mtu_size);

    item = cJSON_GetObjectItem(o, "host_mac_addr_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->host_mac_addr_set);

    item = cJSON_GetObjectItem(o, "host_mac_addr");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->host_mac_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "host_ip4_prefix_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->host_ip4_prefix_set);

    item = cJSON_GetObjectItem(o, "host_ip4_prefix");
    if (!item) goto error;
    if (vl_api_ip4_address_with_prefix_t_fromjson((void **)&a, &l, item, &a->host_ip4_prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "host_ip6_prefix_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->host_ip6_prefix_set);

    item = cJSON_GetObjectItem(o, "host_ip6_prefix");
    if (!item) goto error;
    if (vl_api_ip6_address_with_prefix_t_fromjson((void **)&a, &l, item, &a->host_ip6_prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "host_ip4_gw_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->host_ip4_gw_set);

    item = cJSON_GetObjectItem(o, "host_ip4_gw");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->host_ip4_gw) < 0) goto error;

    item = cJSON_GetObjectItem(o, "host_ip6_gw_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->host_ip6_gw_set);

    item = cJSON_GetObjectItem(o, "host_ip6_gw");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->host_ip6_gw) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tap_flags");
    if (!item) goto error;
    if (vl_api_tap_flags_t_fromjson((void **)&a, &l, item, &a->tap_flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "host_namespace_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->host_namespace_set);

    item = cJSON_GetObjectItem(o, "host_namespace");
    if (!item) goto error;
    strncpy_s((char *)a->host_namespace, sizeof(a->host_namespace), cJSON_GetStringValue(item), sizeof(a->host_namespace) - 1);

    item = cJSON_GetObjectItem(o, "host_if_name_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->host_if_name_set);

    item = cJSON_GetObjectItem(o, "host_if_name");
    if (!item) goto error;
    strncpy_s((char *)a->host_if_name, sizeof(a->host_if_name), cJSON_GetStringValue(item), sizeof(a->host_if_name) - 1);

    item = cJSON_GetObjectItem(o, "host_bridge_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->host_bridge_set);

    item = cJSON_GetObjectItem(o, "host_bridge");
    if (!item) goto error;
    strncpy_s((char *)a->host_bridge, sizeof(a->host_bridge), cJSON_GetStringValue(item), sizeof(a->host_bridge) - 1);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    char *p = cJSON_GetStringValue(item);
    size_t plen = strlen(p);
    a = cJSON_realloc(a, l + plen);
    if (a == 0) goto error;
    vl_api_c_string_to_api_string(p, (void *)a + l - sizeof(vl_api_string_t));
    l += plen;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_tap_create_v2_reply_t *vl_api_tap_create_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_tap_create_v2_reply_t);
    vl_api_tap_create_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_tap_delete_v2_t *vl_api_tap_delete_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_tap_delete_v2_t);
    vl_api_tap_delete_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_tap_delete_v2_reply_t *vl_api_tap_delete_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_tap_delete_v2_reply_t);
    vl_api_tap_delete_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_tap_v2_dump_t *vl_api_sw_interface_tap_v2_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_tap_v2_dump_t);
    vl_api_sw_interface_tap_v2_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_tap_v2_details_t *vl_api_sw_interface_tap_v2_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_tap_v2_details_t);
    vl_api_sw_interface_tap_v2_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sw_if_index);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "tx_ring_sz");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->tx_ring_sz);

    item = cJSON_GetObjectItem(o, "rx_ring_sz");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->rx_ring_sz);

    item = cJSON_GetObjectItem(o, "host_mtu_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->host_mtu_size);

    item = cJSON_GetObjectItem(o, "host_mac_addr");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->host_mac_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "host_ip4_prefix");
    if (!item) goto error;
    if (vl_api_ip4_address_with_prefix_t_fromjson((void **)&a, &l, item, &a->host_ip4_prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "host_ip6_prefix");
    if (!item) goto error;
    if (vl_api_ip6_address_with_prefix_t_fromjson((void **)&a, &l, item, &a->host_ip6_prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tap_flags");
    if (!item) goto error;
    if (vl_api_tap_flags_t_fromjson((void **)&a, &l, item, &a->tap_flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dev_name");
    if (!item) goto error;
    strncpy_s((char *)a->dev_name, sizeof(a->dev_name), cJSON_GetStringValue(item), sizeof(a->dev_name) - 1);

    item = cJSON_GetObjectItem(o, "host_if_name");
    if (!item) goto error;
    strncpy_s((char *)a->host_if_name, sizeof(a->host_if_name), cJSON_GetStringValue(item), sizeof(a->host_if_name) - 1);

    item = cJSON_GetObjectItem(o, "host_namespace");
    if (!item) goto error;
    strncpy_s((char *)a->host_namespace, sizeof(a->host_namespace), cJSON_GetStringValue(item), sizeof(a->host_namespace) - 1);

    item = cJSON_GetObjectItem(o, "host_bridge");
    if (!item) goto error;
    strncpy_s((char *)a->host_bridge, sizeof(a->host_bridge), cJSON_GetStringValue(item), sizeof(a->host_bridge) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
