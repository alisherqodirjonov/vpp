/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_gtpu_api_fromjson_h
#define included_gtpu_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_gtpu_forwarding_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_gtpu_forwarding_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "GTPU_API_FORWARDING_NONE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "GTPU_API_FORWARDING_BAD_HEADER") == 0) {*a = 1; return 0;}
    if (strcmp(p, "GTPU_API_FORWARDING_UNKNOWN_TEID") == 0) {*a = 2; return 0;}
    if (strcmp(p, "GTPU_API_FORWARDING_UNKNOWN_TYPE") == 0) {*a = 4; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_gtpu_decap_next_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_gtpu_decap_next_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "GTPU_API_DECAP_NEXT_DROP") == 0) {*a = 0; return 0;}
    if (strcmp(p, "GTPU_API_DECAP_NEXT_L2") == 0) {*a = 1; return 0;}
    if (strcmp(p, "GTPU_API_DECAP_NEXT_IP4") == 0) {*a = 2; return 0;}
    if (strcmp(p, "GTPU_API_DECAP_NEXT_IP6") == 0) {*a = 3; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_sw_if_counters_t_fromjson (void **mp, int *len, cJSON *o, vl_api_sw_if_counters_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "packets_rx");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->packets_rx);

    item = cJSON_GetObjectItem(o, "packets_tx");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->packets_tx);

    item = cJSON_GetObjectItem(o, "bytes_rx");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->bytes_rx);

    item = cJSON_GetObjectItem(o, "bytes_tx");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->bytes_tx);

    return 0;

  error:
    return -1;
}
static inline int vl_api_tunnel_metrics_t_fromjson (void **mp, int *len, cJSON *o, vl_api_tunnel_metrics_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "reserved");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->reserved);

    item = cJSON_GetObjectItem(o, "counters");
    if (!item) goto error;
    if (vl_api_sw_if_counters_t_fromjson(mp, len, item, &a->counters) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline vl_api_gtpu_add_del_tunnel_t *vl_api_gtpu_add_del_tunnel_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gtpu_add_del_tunnel_t);
    vl_api_gtpu_add_del_tunnel_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "src_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->src_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->dst_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mcast_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->mcast_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "encap_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->encap_vrf_id);

    item = cJSON_GetObjectItem(o, "decap_next_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->decap_next_index);

    item = cJSON_GetObjectItem(o, "teid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->teid);

    item = cJSON_GetObjectItem(o, "tteid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tteid);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gtpu_add_del_tunnel_reply_t *vl_api_gtpu_add_del_tunnel_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gtpu_add_del_tunnel_reply_t);
    vl_api_gtpu_add_del_tunnel_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_gtpu_add_del_tunnel_v2_t *vl_api_gtpu_add_del_tunnel_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gtpu_add_del_tunnel_v2_t);
    vl_api_gtpu_add_del_tunnel_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "src_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->src_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->dst_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mcast_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->mcast_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "encap_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->encap_vrf_id);

    item = cJSON_GetObjectItem(o, "decap_next_index");
    if (!item) goto error;
    if (vl_api_gtpu_decap_next_type_t_fromjson((void **)&a, &l, item, &a->decap_next_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "teid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->teid);

    item = cJSON_GetObjectItem(o, "tteid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tteid);

    item = cJSON_GetObjectItem(o, "pdu_extension");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->pdu_extension);

    item = cJSON_GetObjectItem(o, "qfi");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->qfi);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gtpu_add_del_tunnel_v2_reply_t *vl_api_gtpu_add_del_tunnel_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gtpu_add_del_tunnel_v2_reply_t);
    vl_api_gtpu_add_del_tunnel_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "counters");
    if (!item) goto error;
    if (vl_api_sw_if_counters_t_fromjson((void **)&a, &l, item, &a->counters) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gtpu_tunnel_update_tteid_t *vl_api_gtpu_tunnel_update_tteid_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gtpu_tunnel_update_tteid_t);
    vl_api_gtpu_tunnel_update_tteid_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "dst_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->dst_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "encap_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->encap_vrf_id);

    item = cJSON_GetObjectItem(o, "teid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->teid);

    item = cJSON_GetObjectItem(o, "tteid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tteid);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gtpu_tunnel_update_tteid_reply_t *vl_api_gtpu_tunnel_update_tteid_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gtpu_tunnel_update_tteid_reply_t);
    vl_api_gtpu_tunnel_update_tteid_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gtpu_tunnel_dump_t *vl_api_gtpu_tunnel_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gtpu_tunnel_dump_t);
    vl_api_gtpu_tunnel_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gtpu_tunnel_details_t *vl_api_gtpu_tunnel_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gtpu_tunnel_details_t);
    vl_api_gtpu_tunnel_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "src_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->src_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->dst_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mcast_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->mcast_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "encap_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->encap_vrf_id);

    item = cJSON_GetObjectItem(o, "decap_next_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->decap_next_index);

    item = cJSON_GetObjectItem(o, "teid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->teid);

    item = cJSON_GetObjectItem(o, "tteid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tteid);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gtpu_tunnel_v2_dump_t *vl_api_gtpu_tunnel_v2_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gtpu_tunnel_v2_dump_t);
    vl_api_gtpu_tunnel_v2_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gtpu_tunnel_v2_details_t *vl_api_gtpu_tunnel_v2_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gtpu_tunnel_v2_details_t);
    vl_api_gtpu_tunnel_v2_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "src_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->src_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->dst_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mcast_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->mcast_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "encap_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->encap_vrf_id);

    item = cJSON_GetObjectItem(o, "decap_next_index");
    if (!item) goto error;
    if (vl_api_gtpu_decap_next_type_t_fromjson((void **)&a, &l, item, &a->decap_next_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "teid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->teid);

    item = cJSON_GetObjectItem(o, "tteid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tteid);

    item = cJSON_GetObjectItem(o, "pdu_extension");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->pdu_extension);

    item = cJSON_GetObjectItem(o, "qfi");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->qfi);

    item = cJSON_GetObjectItem(o, "is_forwarding");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_forwarding);

    item = cJSON_GetObjectItem(o, "forwarding_type");
    if (!item) goto error;
    if (vl_api_gtpu_forwarding_type_t_fromjson((void **)&a, &l, item, &a->forwarding_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "counters");
    if (!item) goto error;
    if (vl_api_sw_if_counters_t_fromjson((void **)&a, &l, item, &a->counters) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_gtpu_bypass_t *vl_api_sw_interface_set_gtpu_bypass_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_gtpu_bypass_t);
    vl_api_sw_interface_set_gtpu_bypass_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ipv6);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_gtpu_bypass_reply_t *vl_api_sw_interface_set_gtpu_bypass_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_gtpu_bypass_reply_t);
    vl_api_sw_interface_set_gtpu_bypass_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gtpu_offload_rx_t *vl_api_gtpu_offload_rx_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gtpu_offload_rx_t);
    vl_api_gtpu_offload_rx_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "hw_if_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->hw_if_index);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sw_if_index);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gtpu_offload_rx_reply_t *vl_api_gtpu_offload_rx_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gtpu_offload_rx_reply_t);
    vl_api_gtpu_offload_rx_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gtpu_add_del_forward_t *vl_api_gtpu_add_del_forward_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gtpu_add_del_forward_t);
    vl_api_gtpu_add_del_forward_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "dst_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->dst_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "forwarding_type");
    if (!item) goto error;
    if (vl_api_gtpu_forwarding_type_t_fromjson((void **)&a, &l, item, &a->forwarding_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "encap_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->encap_vrf_id);

    item = cJSON_GetObjectItem(o, "decap_next_index");
    if (!item) goto error;
    if (vl_api_gtpu_decap_next_type_t_fromjson((void **)&a, &l, item, &a->decap_next_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gtpu_add_del_forward_reply_t *vl_api_gtpu_add_del_forward_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gtpu_add_del_forward_reply_t);
    vl_api_gtpu_add_del_forward_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_gtpu_get_transfer_counts_t *vl_api_gtpu_get_transfer_counts_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gtpu_get_transfer_counts_t);
    vl_api_gtpu_get_transfer_counts_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index_start");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index_start) < 0) goto error;

    item = cJSON_GetObjectItem(o, "capacity");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->capacity);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_gtpu_get_transfer_counts_reply_t *vl_api_gtpu_get_transfer_counts_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_gtpu_get_transfer_counts_reply_t);
    vl_api_gtpu_get_transfer_counts_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "tunnels");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "tunnels");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_tunnel_metrics_t) * size);
        vl_api_tunnel_metrics_t *d = (void *)a + l;
        l += sizeof(vl_api_tunnel_metrics_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_tunnel_metrics_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
