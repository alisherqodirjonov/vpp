/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_tapv2_api_tojson_h
#define included_tapv2_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_tap_flags_t_tojson (vl_api_tap_flags_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("TAP_API_FLAG_GSO");
    case 2:
        return cJSON_CreateString("TAP_API_FLAG_CSUM_OFFLOAD");
    case 4:
        return cJSON_CreateString("TAP_API_FLAG_PERSIST");
    case 8:
        return cJSON_CreateString("TAP_API_FLAG_ATTACH");
    case 16:
        return cJSON_CreateString("TAP_API_FLAG_TUN");
    case 32:
        return cJSON_CreateString("TAP_API_FLAG_GRO_COALESCE");
    case 64:
        return cJSON_CreateString("TAP_API_FLAG_PACKED");
    case 128:
        return cJSON_CreateString("TAP_API_FLAG_IN_ORDER");
    case 256:
        return cJSON_CreateString("TAP_API_FLAG_CONSISTENT_QP");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_tap_create_v3_t_tojson (vl_api_tap_create_v3_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "tap_create_v3");
    cJSON_AddStringToObject(o, "_crc", "3f3fd1df");
    cJSON_AddNumberToObject(o, "id", a->id);
    cJSON_AddBoolToObject(o, "use_random_mac", a->use_random_mac);
    cJSON_AddItemToObject(o, "mac_address", vl_api_mac_address_t_tojson(&a->mac_address));
    cJSON_AddNumberToObject(o, "num_rx_queues", a->num_rx_queues);
    cJSON_AddNumberToObject(o, "num_tx_queues", a->num_tx_queues);
    cJSON_AddNumberToObject(o, "tx_ring_sz", a->tx_ring_sz);
    cJSON_AddNumberToObject(o, "rx_ring_sz", a->rx_ring_sz);
    cJSON_AddBoolToObject(o, "host_mtu_set", a->host_mtu_set);
    cJSON_AddNumberToObject(o, "host_mtu_size", a->host_mtu_size);
    cJSON_AddBoolToObject(o, "host_mac_addr_set", a->host_mac_addr_set);
    cJSON_AddItemToObject(o, "host_mac_addr", vl_api_mac_address_t_tojson(&a->host_mac_addr));
    cJSON_AddBoolToObject(o, "host_ip4_prefix_set", a->host_ip4_prefix_set);
    cJSON_AddItemToObject(o, "host_ip4_prefix", vl_api_ip4_address_with_prefix_t_tojson(&a->host_ip4_prefix));
    cJSON_AddBoolToObject(o, "host_ip6_prefix_set", a->host_ip6_prefix_set);
    cJSON_AddItemToObject(o, "host_ip6_prefix", vl_api_ip6_address_with_prefix_t_tojson(&a->host_ip6_prefix));
    cJSON_AddBoolToObject(o, "host_ip4_gw_set", a->host_ip4_gw_set);
    cJSON_AddItemToObject(o, "host_ip4_gw", vl_api_ip4_address_t_tojson(&a->host_ip4_gw));
    cJSON_AddBoolToObject(o, "host_ip6_gw_set", a->host_ip6_gw_set);
    cJSON_AddItemToObject(o, "host_ip6_gw", vl_api_ip6_address_t_tojson(&a->host_ip6_gw));
    cJSON_AddItemToObject(o, "tap_flags", vl_api_tap_flags_t_tojson(a->tap_flags));
    cJSON_AddBoolToObject(o, "host_namespace_set", a->host_namespace_set);
    cJSON_AddStringToObject(o, "host_namespace", (char *)a->host_namespace);
    cJSON_AddBoolToObject(o, "host_if_name_set", a->host_if_name_set);
    cJSON_AddStringToObject(o, "host_if_name", (char *)a->host_if_name);
    cJSON_AddBoolToObject(o, "host_bridge_set", a->host_bridge_set);
    cJSON_AddStringToObject(o, "host_bridge", (char *)a->host_bridge);
    vl_api_string_cJSON_AddToObject(o, "tag", &a->tag);
    return o;
}
static inline cJSON *vl_api_tap_create_v3_reply_t_tojson (vl_api_tap_create_v3_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "tap_create_v3_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_tap_create_v2_t_tojson (vl_api_tap_create_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "tap_create_v2");
    cJSON_AddStringToObject(o, "_crc", "2d0d6570");
    cJSON_AddNumberToObject(o, "id", a->id);
    cJSON_AddBoolToObject(o, "use_random_mac", a->use_random_mac);
    cJSON_AddItemToObject(o, "mac_address", vl_api_mac_address_t_tojson(&a->mac_address));
    cJSON_AddNumberToObject(o, "num_rx_queues", a->num_rx_queues);
    cJSON_AddNumberToObject(o, "tx_ring_sz", a->tx_ring_sz);
    cJSON_AddNumberToObject(o, "rx_ring_sz", a->rx_ring_sz);
    cJSON_AddBoolToObject(o, "host_mtu_set", a->host_mtu_set);
    cJSON_AddNumberToObject(o, "host_mtu_size", a->host_mtu_size);
    cJSON_AddBoolToObject(o, "host_mac_addr_set", a->host_mac_addr_set);
    cJSON_AddItemToObject(o, "host_mac_addr", vl_api_mac_address_t_tojson(&a->host_mac_addr));
    cJSON_AddBoolToObject(o, "host_ip4_prefix_set", a->host_ip4_prefix_set);
    cJSON_AddItemToObject(o, "host_ip4_prefix", vl_api_ip4_address_with_prefix_t_tojson(&a->host_ip4_prefix));
    cJSON_AddBoolToObject(o, "host_ip6_prefix_set", a->host_ip6_prefix_set);
    cJSON_AddItemToObject(o, "host_ip6_prefix", vl_api_ip6_address_with_prefix_t_tojson(&a->host_ip6_prefix));
    cJSON_AddBoolToObject(o, "host_ip4_gw_set", a->host_ip4_gw_set);
    cJSON_AddItemToObject(o, "host_ip4_gw", vl_api_ip4_address_t_tojson(&a->host_ip4_gw));
    cJSON_AddBoolToObject(o, "host_ip6_gw_set", a->host_ip6_gw_set);
    cJSON_AddItemToObject(o, "host_ip6_gw", vl_api_ip6_address_t_tojson(&a->host_ip6_gw));
    cJSON_AddItemToObject(o, "tap_flags", vl_api_tap_flags_t_tojson(a->tap_flags));
    cJSON_AddBoolToObject(o, "host_namespace_set", a->host_namespace_set);
    cJSON_AddStringToObject(o, "host_namespace", (char *)a->host_namespace);
    cJSON_AddBoolToObject(o, "host_if_name_set", a->host_if_name_set);
    cJSON_AddStringToObject(o, "host_if_name", (char *)a->host_if_name);
    cJSON_AddBoolToObject(o, "host_bridge_set", a->host_bridge_set);
    cJSON_AddStringToObject(o, "host_bridge", (char *)a->host_bridge);
    vl_api_string_cJSON_AddToObject(o, "tag", &a->tag);
    return o;
}
static inline cJSON *vl_api_tap_create_v2_reply_t_tojson (vl_api_tap_create_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "tap_create_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_tap_delete_v2_t_tojson (vl_api_tap_delete_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "tap_delete_v2");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_tap_delete_v2_reply_t_tojson (vl_api_tap_delete_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "tap_delete_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_tap_v2_dump_t_tojson (vl_api_sw_interface_tap_v2_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_tap_v2_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_sw_interface_tap_v2_details_t_tojson (vl_api_sw_interface_tap_v2_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_tap_v2_details");
    cJSON_AddStringToObject(o, "_crc", "1e2b2a47");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "id", a->id);
    cJSON_AddNumberToObject(o, "tx_ring_sz", a->tx_ring_sz);
    cJSON_AddNumberToObject(o, "rx_ring_sz", a->rx_ring_sz);
    cJSON_AddNumberToObject(o, "host_mtu_size", a->host_mtu_size);
    cJSON_AddItemToObject(o, "host_mac_addr", vl_api_mac_address_t_tojson(&a->host_mac_addr));
    cJSON_AddItemToObject(o, "host_ip4_prefix", vl_api_ip4_address_with_prefix_t_tojson(&a->host_ip4_prefix));
    cJSON_AddItemToObject(o, "host_ip6_prefix", vl_api_ip6_address_with_prefix_t_tojson(&a->host_ip6_prefix));
    cJSON_AddItemToObject(o, "tap_flags", vl_api_tap_flags_t_tojson(a->tap_flags));
    cJSON_AddStringToObject(o, "dev_name", (char *)a->dev_name);
    cJSON_AddStringToObject(o, "host_if_name", (char *)a->host_if_name);
    cJSON_AddStringToObject(o, "host_namespace", (char *)a->host_namespace);
    cJSON_AddStringToObject(o, "host_bridge", (char *)a->host_bridge);
    return o;
}
#endif
