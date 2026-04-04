/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#ifndef included_af_packet_api_fromjson_h
#define included_af_packet_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_af_packet_mode_t_fromjson(void **mp, int *len, cJSON *o, vl_api_af_packet_mode_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "AF_PACKET_API_MODE_ETHERNET") == 0) {*a = 1; return 0;}
    if (strcmp(p, "AF_PACKET_API_MODE_IP") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_af_packet_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_af_packet_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "AF_PACKET_API_FLAG_QDISC_BYPASS") == 0) {*a = 1; return 0;}
    if (strcmp(p, "AF_PACKET_API_FLAG_CKSUM_GSO") == 0) {*a = 2; return 0;}
    if (strcmp(p, "AF_PACKET_API_FLAG_VERSION_2") == 0) {*a = 8; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_af_packet_create_t *vl_api_af_packet_create_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_af_packet_create_t);
    vl_api_af_packet_create_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "hw_addr");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->hw_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "use_random_hw_addr");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->use_random_hw_addr);

    item = cJSON_GetObjectItem(o, "host_if_name");
    if (!item) goto error;
    strncpy_s((char *)a->host_if_name, sizeof(a->host_if_name), cJSON_GetStringValue(item), sizeof(a->host_if_name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_af_packet_create_reply_t *vl_api_af_packet_create_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_af_packet_create_reply_t);
    vl_api_af_packet_create_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_af_packet_create_v2_t *vl_api_af_packet_create_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_af_packet_create_v2_t);
    vl_api_af_packet_create_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "hw_addr");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->hw_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "use_random_hw_addr");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->use_random_hw_addr);

    item = cJSON_GetObjectItem(o, "host_if_name");
    if (!item) goto error;
    strncpy_s((char *)a->host_if_name, sizeof(a->host_if_name), cJSON_GetStringValue(item), sizeof(a->host_if_name) - 1);

    item = cJSON_GetObjectItem(o, "rx_frame_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->rx_frame_size);

    item = cJSON_GetObjectItem(o, "tx_frame_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tx_frame_size);

    item = cJSON_GetObjectItem(o, "rx_frames_per_block");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->rx_frames_per_block);

    item = cJSON_GetObjectItem(o, "tx_frames_per_block");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tx_frames_per_block);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->flags);

    item = cJSON_GetObjectItem(o, "num_rx_queues");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->num_rx_queues);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_af_packet_create_v2_reply_t *vl_api_af_packet_create_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_af_packet_create_v2_reply_t);
    vl_api_af_packet_create_v2_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_af_packet_create_v3_t *vl_api_af_packet_create_v3_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_af_packet_create_v3_t);
    vl_api_af_packet_create_v3_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_af_packet_mode_t_fromjson((void **)&a, &l, item, &a->mode) < 0) goto error;

    item = cJSON_GetObjectItem(o, "hw_addr");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->hw_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "use_random_hw_addr");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->use_random_hw_addr);

    item = cJSON_GetObjectItem(o, "host_if_name");
    if (!item) goto error;
    strncpy_s((char *)a->host_if_name, sizeof(a->host_if_name), cJSON_GetStringValue(item), sizeof(a->host_if_name) - 1);

    item = cJSON_GetObjectItem(o, "rx_frame_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->rx_frame_size);

    item = cJSON_GetObjectItem(o, "tx_frame_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tx_frame_size);

    item = cJSON_GetObjectItem(o, "rx_frames_per_block");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->rx_frames_per_block);

    item = cJSON_GetObjectItem(o, "tx_frames_per_block");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tx_frames_per_block);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_af_packet_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "num_rx_queues");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->num_rx_queues);

    item = cJSON_GetObjectItem(o, "num_tx_queues");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->num_tx_queues);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_af_packet_create_v3_reply_t *vl_api_af_packet_create_v3_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_af_packet_create_v3_reply_t);
    vl_api_af_packet_create_v3_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_af_packet_delete_t *vl_api_af_packet_delete_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_af_packet_delete_t);
    vl_api_af_packet_delete_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "host_if_name");
    if (!item) goto error;
    strncpy_s((char *)a->host_if_name, sizeof(a->host_if_name), cJSON_GetStringValue(item), sizeof(a->host_if_name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_af_packet_delete_reply_t *vl_api_af_packet_delete_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_af_packet_delete_reply_t);
    vl_api_af_packet_delete_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_af_packet_set_l4_cksum_offload_t *vl_api_af_packet_set_l4_cksum_offload_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_af_packet_set_l4_cksum_offload_t);
    vl_api_af_packet_set_l4_cksum_offload_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->set);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_af_packet_set_l4_cksum_offload_reply_t *vl_api_af_packet_set_l4_cksum_offload_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_af_packet_set_l4_cksum_offload_reply_t);
    vl_api_af_packet_set_l4_cksum_offload_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_af_packet_dump_t *vl_api_af_packet_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_af_packet_dump_t);
    vl_api_af_packet_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_af_packet_details_t *vl_api_af_packet_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_af_packet_details_t);
    vl_api_af_packet_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "host_if_name");
    if (!item) goto error;
    strncpy_s((char *)a->host_if_name, sizeof(a->host_if_name), cJSON_GetStringValue(item), sizeof(a->host_if_name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
