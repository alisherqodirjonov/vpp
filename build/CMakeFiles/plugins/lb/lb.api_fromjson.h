/* Imported API files */
#include <lb/lb_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_lb_api_fromjson_h
#define included_lb_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_lb_conf_t *vl_api_lb_conf_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lb_conf_t);
    vl_api_lb_conf_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ip4_src_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ip4_src_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip6_src_address");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->ip6_src_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sticky_buckets_per_core");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sticky_buckets_per_core);

    item = cJSON_GetObjectItem(o, "flow_timeout");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->flow_timeout);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lb_conf_reply_t *vl_api_lb_conf_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lb_conf_reply_t);
    vl_api_lb_conf_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lb_add_del_vip_t *vl_api_lb_add_del_vip_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lb_add_del_vip_t);
    vl_api_lb_add_del_vip_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pfx");
    if (!item) goto error;
    if (vl_api_address_with_prefix_t_fromjson((void **)&a, &l, item, &a->pfx) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->protocol);

    item = cJSON_GetObjectItem(o, "port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->port);

    item = cJSON_GetObjectItem(o, "encap");
    if (!item) goto error;
    if (vl_api_lb_encap_type_t_fromjson((void **)&a, &l, item, &a->encap) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dscp");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->dscp);

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_lb_srv_type_t_fromjson((void **)&a, &l, item, &a->type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "target_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->target_port);

    item = cJSON_GetObjectItem(o, "node_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->node_port);

    item = cJSON_GetObjectItem(o, "new_flows_table_length");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->new_flows_table_length);

    item = cJSON_GetObjectItem(o, "is_del");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_del);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lb_add_del_vip_reply_t *vl_api_lb_add_del_vip_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lb_add_del_vip_reply_t);
    vl_api_lb_add_del_vip_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lb_add_del_vip_v2_t *vl_api_lb_add_del_vip_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lb_add_del_vip_v2_t);
    vl_api_lb_add_del_vip_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pfx");
    if (!item) goto error;
    if (vl_api_address_with_prefix_t_fromjson((void **)&a, &l, item, &a->pfx) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->protocol);

    item = cJSON_GetObjectItem(o, "port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->port);

    item = cJSON_GetObjectItem(o, "encap");
    if (!item) goto error;
    if (vl_api_lb_encap_type_t_fromjson((void **)&a, &l, item, &a->encap) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dscp");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->dscp);

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_lb_srv_type_t_fromjson((void **)&a, &l, item, &a->type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "target_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->target_port);

    item = cJSON_GetObjectItem(o, "node_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->node_port);

    item = cJSON_GetObjectItem(o, "new_flows_table_length");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->new_flows_table_length);

    item = cJSON_GetObjectItem(o, "src_ip_sticky");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->src_ip_sticky);

    item = cJSON_GetObjectItem(o, "is_del");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_del);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lb_add_del_vip_v2_reply_t *vl_api_lb_add_del_vip_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lb_add_del_vip_v2_reply_t);
    vl_api_lb_add_del_vip_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lb_add_del_as_t *vl_api_lb_add_del_as_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lb_add_del_as_t);
    vl_api_lb_add_del_as_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pfx");
    if (!item) goto error;
    if (vl_api_address_with_prefix_t_fromjson((void **)&a, &l, item, &a->pfx) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->protocol);

    item = cJSON_GetObjectItem(o, "port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->port);

    item = cJSON_GetObjectItem(o, "as_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->as_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_del");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_del);

    item = cJSON_GetObjectItem(o, "is_flush");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_flush);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lb_add_del_as_reply_t *vl_api_lb_add_del_as_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lb_add_del_as_reply_t);
    vl_api_lb_add_del_as_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lb_flush_vip_t *vl_api_lb_flush_vip_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lb_flush_vip_t);
    vl_api_lb_flush_vip_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pfx");
    if (!item) goto error;
    if (vl_api_address_with_prefix_t_fromjson((void **)&a, &l, item, &a->pfx) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->protocol);

    item = cJSON_GetObjectItem(o, "port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->port);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lb_flush_vip_reply_t *vl_api_lb_flush_vip_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lb_flush_vip_reply_t);
    vl_api_lb_flush_vip_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lb_vip_dump_t *vl_api_lb_vip_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lb_vip_dump_t);
    vl_api_lb_vip_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pfx");
    if (!item) goto error;
    if (vl_api_address_with_prefix_t_fromjson((void **)&a, &l, item, &a->pfx) < 0) goto error;

    item = cJSON_GetObjectItem(o, "pfx_matcher");
    if (!item) goto error;
    if (vl_api_prefix_matcher_t_fromjson((void **)&a, &l, item, &a->pfx_matcher) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->protocol);

    item = cJSON_GetObjectItem(o, "port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->port);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lb_vip_details_t *vl_api_lb_vip_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lb_vip_details_t);
    vl_api_lb_vip_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "vip");
    if (!item) goto error;
    if (vl_api_lb_vip_t_fromjson((void **)&a, &l, item, &a->vip) < 0) goto error;

    item = cJSON_GetObjectItem(o, "encap");
    if (!item) goto error;
    if (vl_api_lb_encap_type_t_fromjson((void **)&a, &l, item, &a->encap) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dscp");
    if (!item) goto error;
    if (vl_api_ip_dscp_t_fromjson((void **)&a, &l, item, &a->dscp) < 0) goto error;

    item = cJSON_GetObjectItem(o, "srv_type");
    if (!item) goto error;
    if (vl_api_lb_srv_type_t_fromjson((void **)&a, &l, item, &a->srv_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "target_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->target_port);

    item = cJSON_GetObjectItem(o, "flow_table_length");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->flow_table_length);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lb_as_dump_t *vl_api_lb_as_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lb_as_dump_t);
    vl_api_lb_as_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pfx");
    if (!item) goto error;
    if (vl_api_address_with_prefix_t_fromjson((void **)&a, &l, item, &a->pfx) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->protocol);

    item = cJSON_GetObjectItem(o, "port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->port);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lb_as_details_t *vl_api_lb_as_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lb_as_details_t);
    vl_api_lb_as_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "vip");
    if (!item) goto error;
    if (vl_api_lb_vip_t_fromjson((void **)&a, &l, item, &a->vip) < 0) goto error;

    item = cJSON_GetObjectItem(o, "app_srv");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->app_srv) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->flags);

    item = cJSON_GetObjectItem(o, "in_use_since");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->in_use_since);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lb_add_del_intf_nat4_t *vl_api_lb_add_del_intf_nat4_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lb_add_del_intf_nat4_t);
    vl_api_lb_add_del_intf_nat4_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lb_add_del_intf_nat4_reply_t *vl_api_lb_add_del_intf_nat4_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lb_add_del_intf_nat4_reply_t);
    vl_api_lb_add_del_intf_nat4_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lb_add_del_intf_nat6_t *vl_api_lb_add_del_intf_nat6_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lb_add_del_intf_nat6_t);
    vl_api_lb_add_del_intf_nat6_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lb_add_del_intf_nat6_reply_t *vl_api_lb_add_del_intf_nat6_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lb_add_del_intf_nat6_reply_t);
    vl_api_lb_add_del_intf_nat6_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
