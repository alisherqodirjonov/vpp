/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_gtpu_api_tojson_h
#define included_gtpu_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_gtpu_forwarding_type_t_tojson (vl_api_gtpu_forwarding_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("GTPU_API_FORWARDING_NONE");
    case 1:
        return cJSON_CreateString("GTPU_API_FORWARDING_BAD_HEADER");
    case 2:
        return cJSON_CreateString("GTPU_API_FORWARDING_UNKNOWN_TEID");
    case 4:
        return cJSON_CreateString("GTPU_API_FORWARDING_UNKNOWN_TYPE");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_gtpu_decap_next_type_t_tojson (vl_api_gtpu_decap_next_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("GTPU_API_DECAP_NEXT_DROP");
    case 1:
        return cJSON_CreateString("GTPU_API_DECAP_NEXT_L2");
    case 2:
        return cJSON_CreateString("GTPU_API_DECAP_NEXT_IP4");
    case 3:
        return cJSON_CreateString("GTPU_API_DECAP_NEXT_IP6");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_sw_if_counters_t_tojson (vl_api_sw_if_counters_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "packets_rx", a->packets_rx);
    cJSON_AddNumberToObject(o, "packets_tx", a->packets_tx);
    cJSON_AddNumberToObject(o, "bytes_rx", a->bytes_rx);
    cJSON_AddNumberToObject(o, "bytes_tx", a->bytes_tx);
    return o;
}
static inline cJSON *vl_api_tunnel_metrics_t_tojson (vl_api_tunnel_metrics_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "reserved", a->reserved);
    cJSON_AddItemToObject(o, "counters", vl_api_sw_if_counters_t_tojson(&a->counters));
    return o;
}
static inline cJSON *vl_api_gtpu_add_del_tunnel_t_tojson (vl_api_gtpu_add_del_tunnel_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gtpu_add_del_tunnel");
    cJSON_AddStringToObject(o, "_crc", "ca983a2b");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "src_address", vl_api_address_t_tojson(&a->src_address));
    cJSON_AddItemToObject(o, "dst_address", vl_api_address_t_tojson(&a->dst_address));
    cJSON_AddNumberToObject(o, "mcast_sw_if_index", a->mcast_sw_if_index);
    cJSON_AddNumberToObject(o, "encap_vrf_id", a->encap_vrf_id);
    cJSON_AddNumberToObject(o, "decap_next_index", a->decap_next_index);
    cJSON_AddNumberToObject(o, "teid", a->teid);
    cJSON_AddNumberToObject(o, "tteid", a->tteid);
    return o;
}
static inline cJSON *vl_api_gtpu_add_del_tunnel_reply_t_tojson (vl_api_gtpu_add_del_tunnel_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gtpu_add_del_tunnel_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_gtpu_add_del_tunnel_v2_t_tojson (vl_api_gtpu_add_del_tunnel_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gtpu_add_del_tunnel_v2");
    cJSON_AddStringToObject(o, "_crc", "a0c30713");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "src_address", vl_api_address_t_tojson(&a->src_address));
    cJSON_AddItemToObject(o, "dst_address", vl_api_address_t_tojson(&a->dst_address));
    cJSON_AddNumberToObject(o, "mcast_sw_if_index", a->mcast_sw_if_index);
    cJSON_AddNumberToObject(o, "encap_vrf_id", a->encap_vrf_id);
    cJSON_AddItemToObject(o, "decap_next_index", vl_api_gtpu_decap_next_type_t_tojson(a->decap_next_index));
    cJSON_AddNumberToObject(o, "teid", a->teid);
    cJSON_AddNumberToObject(o, "tteid", a->tteid);
    cJSON_AddBoolToObject(o, "pdu_extension", a->pdu_extension);
    cJSON_AddNumberToObject(o, "qfi", a->qfi);
    return o;
}
static inline cJSON *vl_api_gtpu_add_del_tunnel_v2_reply_t_tojson (vl_api_gtpu_add_del_tunnel_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gtpu_add_del_tunnel_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "62b41304");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "counters", vl_api_sw_if_counters_t_tojson(&a->counters));
    return o;
}
static inline cJSON *vl_api_gtpu_tunnel_update_tteid_t_tojson (vl_api_gtpu_tunnel_update_tteid_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gtpu_tunnel_update_tteid");
    cJSON_AddStringToObject(o, "_crc", "79f33816");
    cJSON_AddItemToObject(o, "dst_address", vl_api_address_t_tojson(&a->dst_address));
    cJSON_AddNumberToObject(o, "encap_vrf_id", a->encap_vrf_id);
    cJSON_AddNumberToObject(o, "teid", a->teid);
    cJSON_AddNumberToObject(o, "tteid", a->tteid);
    return o;
}
static inline cJSON *vl_api_gtpu_tunnel_update_tteid_reply_t_tojson (vl_api_gtpu_tunnel_update_tteid_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gtpu_tunnel_update_tteid_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_gtpu_tunnel_dump_t_tojson (vl_api_gtpu_tunnel_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gtpu_tunnel_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_gtpu_tunnel_details_t_tojson (vl_api_gtpu_tunnel_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gtpu_tunnel_details");
    cJSON_AddStringToObject(o, "_crc", "27f434ae");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "src_address", vl_api_address_t_tojson(&a->src_address));
    cJSON_AddItemToObject(o, "dst_address", vl_api_address_t_tojson(&a->dst_address));
    cJSON_AddNumberToObject(o, "mcast_sw_if_index", a->mcast_sw_if_index);
    cJSON_AddNumberToObject(o, "encap_vrf_id", a->encap_vrf_id);
    cJSON_AddNumberToObject(o, "decap_next_index", a->decap_next_index);
    cJSON_AddNumberToObject(o, "teid", a->teid);
    cJSON_AddNumberToObject(o, "tteid", a->tteid);
    return o;
}
static inline cJSON *vl_api_gtpu_tunnel_v2_dump_t_tojson (vl_api_gtpu_tunnel_v2_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gtpu_tunnel_v2_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_gtpu_tunnel_v2_details_t_tojson (vl_api_gtpu_tunnel_v2_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gtpu_tunnel_v2_details");
    cJSON_AddStringToObject(o, "_crc", "8bf4ba92");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "src_address", vl_api_address_t_tojson(&a->src_address));
    cJSON_AddItemToObject(o, "dst_address", vl_api_address_t_tojson(&a->dst_address));
    cJSON_AddNumberToObject(o, "mcast_sw_if_index", a->mcast_sw_if_index);
    cJSON_AddNumberToObject(o, "encap_vrf_id", a->encap_vrf_id);
    cJSON_AddItemToObject(o, "decap_next_index", vl_api_gtpu_decap_next_type_t_tojson(a->decap_next_index));
    cJSON_AddNumberToObject(o, "teid", a->teid);
    cJSON_AddNumberToObject(o, "tteid", a->tteid);
    cJSON_AddBoolToObject(o, "pdu_extension", a->pdu_extension);
    cJSON_AddNumberToObject(o, "qfi", a->qfi);
    cJSON_AddBoolToObject(o, "is_forwarding", a->is_forwarding);
    cJSON_AddItemToObject(o, "forwarding_type", vl_api_gtpu_forwarding_type_t_tojson(a->forwarding_type));
    cJSON_AddItemToObject(o, "counters", vl_api_sw_if_counters_t_tojson(&a->counters));
    return o;
}
static inline cJSON *vl_api_sw_interface_set_gtpu_bypass_t_tojson (vl_api_sw_interface_set_gtpu_bypass_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_gtpu_bypass");
    cJSON_AddStringToObject(o, "_crc", "65247409");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_ipv6", a->is_ipv6);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_gtpu_bypass_reply_t_tojson (vl_api_sw_interface_set_gtpu_bypass_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_gtpu_bypass_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_gtpu_offload_rx_t_tojson (vl_api_gtpu_offload_rx_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gtpu_offload_rx");
    cJSON_AddStringToObject(o, "_crc", "f0b08786");
    cJSON_AddNumberToObject(o, "hw_if_index", a->hw_if_index);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_gtpu_offload_rx_reply_t_tojson (vl_api_gtpu_offload_rx_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gtpu_offload_rx_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_gtpu_add_del_forward_t_tojson (vl_api_gtpu_add_del_forward_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gtpu_add_del_forward");
    cJSON_AddStringToObject(o, "_crc", "c6ccce13");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "dst_address", vl_api_address_t_tojson(&a->dst_address));
    cJSON_AddItemToObject(o, "forwarding_type", vl_api_gtpu_forwarding_type_t_tojson(a->forwarding_type));
    cJSON_AddNumberToObject(o, "encap_vrf_id", a->encap_vrf_id);
    cJSON_AddItemToObject(o, "decap_next_index", vl_api_gtpu_decap_next_type_t_tojson(a->decap_next_index));
    return o;
}
static inline cJSON *vl_api_gtpu_add_del_forward_reply_t_tojson (vl_api_gtpu_add_del_forward_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gtpu_add_del_forward_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_gtpu_get_transfer_counts_t_tojson (vl_api_gtpu_get_transfer_counts_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gtpu_get_transfer_counts");
    cJSON_AddStringToObject(o, "_crc", "61410788");
    cJSON_AddNumberToObject(o, "sw_if_index_start", a->sw_if_index_start);
    cJSON_AddNumberToObject(o, "capacity", a->capacity);
    return o;
}
static inline cJSON *vl_api_gtpu_get_transfer_counts_reply_t_tojson (vl_api_gtpu_get_transfer_counts_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gtpu_get_transfer_counts_reply");
    cJSON_AddStringToObject(o, "_crc", "e35f04bc");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "tunnels");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, vl_api_tunnel_metrics_t_tojson(&a->tunnels[i]));
        }
    }
    return o;
}
#endif
