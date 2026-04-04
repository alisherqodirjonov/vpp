/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#include <nat/lib/nat_types.api_fromjson.h>
#ifndef included_det44_api_fromjson_h
#define included_det44_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_det44_plugin_enable_disable_t *vl_api_det44_plugin_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_plugin_enable_disable_t);
    vl_api_det44_plugin_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "inside_vrf");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->inside_vrf);

    item = cJSON_GetObjectItem(o, "outside_vrf");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->outside_vrf);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_det44_plugin_enable_disable_reply_t *vl_api_det44_plugin_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_plugin_enable_disable_reply_t);
    vl_api_det44_plugin_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_det44_interface_add_del_feature_t *vl_api_det44_interface_add_del_feature_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_interface_add_del_feature_t);
    vl_api_det44_interface_add_del_feature_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "is_inside");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_inside);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_det44_interface_add_del_feature_reply_t *vl_api_det44_interface_add_del_feature_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_interface_add_del_feature_reply_t);
    vl_api_det44_interface_add_del_feature_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_det44_interface_dump_t *vl_api_det44_interface_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_interface_dump_t);
    vl_api_det44_interface_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_det44_interface_details_t *vl_api_det44_interface_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_interface_details_t);
    vl_api_det44_interface_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_inside");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_inside);

    item = cJSON_GetObjectItem(o, "is_outside");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_outside);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_det44_add_del_map_t *vl_api_det44_add_del_map_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_add_del_map_t);
    vl_api_det44_add_del_map_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "in_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->in_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "in_plen");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->in_plen);

    item = cJSON_GetObjectItem(o, "out_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->out_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "out_plen");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->out_plen);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_det44_add_del_map_reply_t *vl_api_det44_add_del_map_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_add_del_map_reply_t);
    vl_api_det44_add_del_map_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_det44_forward_t *vl_api_det44_forward_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_forward_t);
    vl_api_det44_forward_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "in_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->in_addr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_det44_forward_reply_t *vl_api_det44_forward_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_forward_reply_t);
    vl_api_det44_forward_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "out_port_lo");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->out_port_lo);

    item = cJSON_GetObjectItem(o, "out_port_hi");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->out_port_hi);

    item = cJSON_GetObjectItem(o, "out_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->out_addr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_det44_reverse_t *vl_api_det44_reverse_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_reverse_t);
    vl_api_det44_reverse_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "out_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->out_port);

    item = cJSON_GetObjectItem(o, "out_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->out_addr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_det44_reverse_reply_t *vl_api_det44_reverse_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_reverse_reply_t);
    vl_api_det44_reverse_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "in_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->in_addr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_det44_map_dump_t *vl_api_det44_map_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_map_dump_t);
    vl_api_det44_map_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_det44_map_details_t *vl_api_det44_map_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_map_details_t);
    vl_api_det44_map_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "in_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->in_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "in_plen");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->in_plen);

    item = cJSON_GetObjectItem(o, "out_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->out_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "out_plen");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->out_plen);

    item = cJSON_GetObjectItem(o, "sharing_ratio");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sharing_ratio);

    item = cJSON_GetObjectItem(o, "ports_per_host");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ports_per_host);

    item = cJSON_GetObjectItem(o, "ses_num");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ses_num);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_det44_close_session_out_t *vl_api_det44_close_session_out_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_close_session_out_t);
    vl_api_det44_close_session_out_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "out_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->out_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "out_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->out_port);

    item = cJSON_GetObjectItem(o, "ext_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ext_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ext_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ext_port);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_det44_close_session_out_reply_t *vl_api_det44_close_session_out_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_close_session_out_reply_t);
    vl_api_det44_close_session_out_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_det44_close_session_in_t *vl_api_det44_close_session_in_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_close_session_in_t);
    vl_api_det44_close_session_in_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "in_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->in_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "in_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->in_port);

    item = cJSON_GetObjectItem(o, "ext_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ext_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ext_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ext_port);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_det44_close_session_in_reply_t *vl_api_det44_close_session_in_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_close_session_in_reply_t);
    vl_api_det44_close_session_in_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_det44_session_dump_t *vl_api_det44_session_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_session_dump_t);
    vl_api_det44_session_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "user_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->user_addr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_det44_session_details_t *vl_api_det44_session_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_session_details_t);
    vl_api_det44_session_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "in_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->in_port);

    item = cJSON_GetObjectItem(o, "ext_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ext_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ext_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ext_port);

    item = cJSON_GetObjectItem(o, "out_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->out_port);

    item = cJSON_GetObjectItem(o, "state");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->state);

    item = cJSON_GetObjectItem(o, "expire");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->expire);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_det44_set_timeouts_t *vl_api_det44_set_timeouts_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_set_timeouts_t);
    vl_api_det44_set_timeouts_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "udp");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->udp);

    item = cJSON_GetObjectItem(o, "tcp_established");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tcp_established);

    item = cJSON_GetObjectItem(o, "tcp_transitory");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tcp_transitory);

    item = cJSON_GetObjectItem(o, "icmp");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->icmp);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_det44_set_timeouts_reply_t *vl_api_det44_set_timeouts_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_set_timeouts_reply_t);
    vl_api_det44_set_timeouts_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_det44_get_timeouts_t *vl_api_det44_get_timeouts_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_get_timeouts_t);
    vl_api_det44_get_timeouts_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_det44_get_timeouts_reply_t *vl_api_det44_get_timeouts_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_det44_get_timeouts_reply_t);
    vl_api_det44_get_timeouts_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "udp");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->udp);

    item = cJSON_GetObjectItem(o, "tcp_established");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tcp_established);

    item = cJSON_GetObjectItem(o, "tcp_transitory");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tcp_transitory);

    item = cJSON_GetObjectItem(o, "icmp");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->icmp);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_det_add_del_map_t *vl_api_nat_det_add_del_map_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_det_add_del_map_t);
    vl_api_nat_det_add_del_map_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "in_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->in_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "in_plen");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->in_plen);

    item = cJSON_GetObjectItem(o, "out_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->out_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "out_plen");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->out_plen);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_det_add_del_map_reply_t *vl_api_nat_det_add_del_map_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_det_add_del_map_reply_t);
    vl_api_nat_det_add_del_map_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_det_forward_t *vl_api_nat_det_forward_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_det_forward_t);
    vl_api_nat_det_forward_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "in_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->in_addr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_det_forward_reply_t *vl_api_nat_det_forward_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_det_forward_reply_t);
    vl_api_nat_det_forward_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "out_port_lo");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->out_port_lo);

    item = cJSON_GetObjectItem(o, "out_port_hi");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->out_port_hi);

    item = cJSON_GetObjectItem(o, "out_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->out_addr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_det_reverse_t *vl_api_nat_det_reverse_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_det_reverse_t);
    vl_api_nat_det_reverse_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "out_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->out_port);

    item = cJSON_GetObjectItem(o, "out_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->out_addr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_det_reverse_reply_t *vl_api_nat_det_reverse_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_det_reverse_reply_t);
    vl_api_nat_det_reverse_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "in_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->in_addr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_det_map_dump_t *vl_api_nat_det_map_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_det_map_dump_t);
    vl_api_nat_det_map_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_nat_det_map_details_t *vl_api_nat_det_map_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_det_map_details_t);
    vl_api_nat_det_map_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "in_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->in_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "in_plen");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->in_plen);

    item = cJSON_GetObjectItem(o, "out_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->out_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "out_plen");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->out_plen);

    item = cJSON_GetObjectItem(o, "sharing_ratio");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sharing_ratio);

    item = cJSON_GetObjectItem(o, "ports_per_host");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ports_per_host);

    item = cJSON_GetObjectItem(o, "ses_num");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ses_num);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_det_close_session_out_t *vl_api_nat_det_close_session_out_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_det_close_session_out_t);
    vl_api_nat_det_close_session_out_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "out_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->out_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "out_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->out_port);

    item = cJSON_GetObjectItem(o, "ext_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ext_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ext_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ext_port);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_det_close_session_out_reply_t *vl_api_nat_det_close_session_out_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_det_close_session_out_reply_t);
    vl_api_nat_det_close_session_out_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_det_close_session_in_t *vl_api_nat_det_close_session_in_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_det_close_session_in_t);
    vl_api_nat_det_close_session_in_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "in_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->in_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "in_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->in_port);

    item = cJSON_GetObjectItem(o, "ext_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ext_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ext_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ext_port);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_det_close_session_in_reply_t *vl_api_nat_det_close_session_in_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_det_close_session_in_reply_t);
    vl_api_nat_det_close_session_in_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_det_session_dump_t *vl_api_nat_det_session_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_det_session_dump_t);
    vl_api_nat_det_session_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "user_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->user_addr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_det_session_details_t *vl_api_nat_det_session_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_det_session_details_t);
    vl_api_nat_det_session_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "in_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->in_port);

    item = cJSON_GetObjectItem(o, "ext_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ext_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ext_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ext_port);

    item = cJSON_GetObjectItem(o, "out_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->out_port);

    item = cJSON_GetObjectItem(o, "state");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->state);

    item = cJSON_GetObjectItem(o, "expire");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->expire);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
