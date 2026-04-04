/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#ifndef included_af_packet_api_tojson_h
#define included_af_packet_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_af_packet_mode_t_tojson (vl_api_af_packet_mode_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("AF_PACKET_API_MODE_ETHERNET");
    case 2:
        return cJSON_CreateString("AF_PACKET_API_MODE_IP");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_af_packet_flags_t_tojson (vl_api_af_packet_flags_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("AF_PACKET_API_FLAG_QDISC_BYPASS");
    case 2:
        return cJSON_CreateString("AF_PACKET_API_FLAG_CKSUM_GSO");
    case 8:
        return cJSON_CreateString("AF_PACKET_API_FLAG_VERSION_2");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_af_packet_create_t_tojson (vl_api_af_packet_create_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "af_packet_create");
    cJSON_AddStringToObject(o, "_crc", "a190415f");
    cJSON_AddItemToObject(o, "hw_addr", vl_api_mac_address_t_tojson(&a->hw_addr));
    cJSON_AddBoolToObject(o, "use_random_hw_addr", a->use_random_hw_addr);
    cJSON_AddStringToObject(o, "host_if_name", (char *)a->host_if_name);
    return o;
}
static inline cJSON *vl_api_af_packet_create_reply_t_tojson (vl_api_af_packet_create_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "af_packet_create_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_af_packet_create_v2_t_tojson (vl_api_af_packet_create_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "af_packet_create_v2");
    cJSON_AddStringToObject(o, "_crc", "4aff0436");
    cJSON_AddItemToObject(o, "hw_addr", vl_api_mac_address_t_tojson(&a->hw_addr));
    cJSON_AddBoolToObject(o, "use_random_hw_addr", a->use_random_hw_addr);
    cJSON_AddStringToObject(o, "host_if_name", (char *)a->host_if_name);
    cJSON_AddNumberToObject(o, "rx_frame_size", a->rx_frame_size);
    cJSON_AddNumberToObject(o, "tx_frame_size", a->tx_frame_size);
    cJSON_AddNumberToObject(o, "rx_frames_per_block", a->rx_frames_per_block);
    cJSON_AddNumberToObject(o, "tx_frames_per_block", a->tx_frames_per_block);
    cJSON_AddNumberToObject(o, "flags", a->flags);
    cJSON_AddNumberToObject(o, "num_rx_queues", a->num_rx_queues);
    return o;
}
static inline cJSON *vl_api_af_packet_create_v2_reply_t_tojson (vl_api_af_packet_create_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "af_packet_create_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_af_packet_create_v3_t_tojson (vl_api_af_packet_create_v3_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "af_packet_create_v3");
    cJSON_AddStringToObject(o, "_crc", "b3a809d4");
    cJSON_AddItemToObject(o, "mode", vl_api_af_packet_mode_t_tojson(a->mode));
    cJSON_AddItemToObject(o, "hw_addr", vl_api_mac_address_t_tojson(&a->hw_addr));
    cJSON_AddBoolToObject(o, "use_random_hw_addr", a->use_random_hw_addr);
    cJSON_AddStringToObject(o, "host_if_name", (char *)a->host_if_name);
    cJSON_AddNumberToObject(o, "rx_frame_size", a->rx_frame_size);
    cJSON_AddNumberToObject(o, "tx_frame_size", a->tx_frame_size);
    cJSON_AddNumberToObject(o, "rx_frames_per_block", a->rx_frames_per_block);
    cJSON_AddNumberToObject(o, "tx_frames_per_block", a->tx_frames_per_block);
    cJSON_AddItemToObject(o, "flags", vl_api_af_packet_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "num_rx_queues", a->num_rx_queues);
    cJSON_AddNumberToObject(o, "num_tx_queues", a->num_tx_queues);
    return o;
}
static inline cJSON *vl_api_af_packet_create_v3_reply_t_tojson (vl_api_af_packet_create_v3_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "af_packet_create_v3_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_af_packet_delete_t_tojson (vl_api_af_packet_delete_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "af_packet_delete");
    cJSON_AddStringToObject(o, "_crc", "863fa648");
    cJSON_AddStringToObject(o, "host_if_name", (char *)a->host_if_name);
    return o;
}
static inline cJSON *vl_api_af_packet_delete_reply_t_tojson (vl_api_af_packet_delete_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "af_packet_delete_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_af_packet_set_l4_cksum_offload_t_tojson (vl_api_af_packet_set_l4_cksum_offload_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "af_packet_set_l4_cksum_offload");
    cJSON_AddStringToObject(o, "_crc", "319cd5c8");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "set", a->set);
    return o;
}
static inline cJSON *vl_api_af_packet_set_l4_cksum_offload_reply_t_tojson (vl_api_af_packet_set_l4_cksum_offload_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "af_packet_set_l4_cksum_offload_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_af_packet_dump_t_tojson (vl_api_af_packet_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "af_packet_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_af_packet_details_t_tojson (vl_api_af_packet_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "af_packet_details");
    cJSON_AddStringToObject(o, "_crc", "58c7c042");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddStringToObject(o, "host_if_name", (char *)a->host_if_name);
    return o;
}
#endif
