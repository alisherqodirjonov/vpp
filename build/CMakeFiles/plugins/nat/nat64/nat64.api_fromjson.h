/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#include <nat/lib/nat_types.api_fromjson.h>
#ifndef included_nat64_api_fromjson_h
#define included_nat64_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_nat64_plugin_enable_disable_t *vl_api_nat64_plugin_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_plugin_enable_disable_t);
    vl_api_nat64_plugin_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bib_buckets");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bib_buckets);

    item = cJSON_GetObjectItem(o, "bib_memory_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bib_memory_size);

    item = cJSON_GetObjectItem(o, "st_buckets");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->st_buckets);

    item = cJSON_GetObjectItem(o, "st_memory_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->st_memory_size);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat64_plugin_enable_disable_reply_t *vl_api_nat64_plugin_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_plugin_enable_disable_reply_t);
    vl_api_nat64_plugin_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat64_set_timeouts_t *vl_api_nat64_set_timeouts_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_set_timeouts_t);
    vl_api_nat64_set_timeouts_t *a = cJSON_malloc(l);

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
static inline vl_api_nat64_set_timeouts_reply_t *vl_api_nat64_set_timeouts_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_set_timeouts_reply_t);
    vl_api_nat64_set_timeouts_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat64_get_timeouts_t *vl_api_nat64_get_timeouts_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_get_timeouts_t);
    vl_api_nat64_get_timeouts_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_nat64_get_timeouts_reply_t *vl_api_nat64_get_timeouts_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_get_timeouts_reply_t);
    vl_api_nat64_get_timeouts_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_nat64_add_del_pool_addr_range_t *vl_api_nat64_add_del_pool_addr_range_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_add_del_pool_addr_range_t);
    vl_api_nat64_add_del_pool_addr_range_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "start_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->start_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "end_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->end_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat64_add_del_pool_addr_range_reply_t *vl_api_nat64_add_del_pool_addr_range_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_add_del_pool_addr_range_reply_t);
    vl_api_nat64_add_del_pool_addr_range_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat64_pool_addr_dump_t *vl_api_nat64_pool_addr_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_pool_addr_dump_t);
    vl_api_nat64_pool_addr_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_nat64_pool_addr_details_t *vl_api_nat64_pool_addr_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_pool_addr_details_t);
    vl_api_nat64_pool_addr_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat64_add_del_interface_t *vl_api_nat64_add_del_interface_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_add_del_interface_t);
    vl_api_nat64_add_del_interface_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat64_add_del_interface_reply_t *vl_api_nat64_add_del_interface_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_add_del_interface_reply_t);
    vl_api_nat64_add_del_interface_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat64_interface_dump_t *vl_api_nat64_interface_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_interface_dump_t);
    vl_api_nat64_interface_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_nat64_interface_details_t *vl_api_nat64_interface_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_interface_details_t);
    vl_api_nat64_interface_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat64_add_del_static_bib_t *vl_api_nat64_add_del_static_bib_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_add_del_static_bib_t);
    vl_api_nat64_add_del_static_bib_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "i_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->i_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "o_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->o_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "i_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->i_port);

    item = cJSON_GetObjectItem(o, "o_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->o_port);

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "proto");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->proto);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat64_add_del_static_bib_reply_t *vl_api_nat64_add_del_static_bib_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_add_del_static_bib_reply_t);
    vl_api_nat64_add_del_static_bib_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat64_bib_dump_t *vl_api_nat64_bib_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_bib_dump_t);
    vl_api_nat64_bib_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "proto");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->proto);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat64_bib_details_t *vl_api_nat64_bib_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_bib_details_t);
    vl_api_nat64_bib_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "i_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->i_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "o_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->o_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "i_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->i_port);

    item = cJSON_GetObjectItem(o, "o_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->o_port);

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "proto");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->proto);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ses_num");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ses_num);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat64_st_dump_t *vl_api_nat64_st_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_st_dump_t);
    vl_api_nat64_st_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "proto");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->proto);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat64_st_details_t *vl_api_nat64_st_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_st_details_t);
    vl_api_nat64_st_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "il_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->il_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ol_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ol_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "il_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->il_port);

    item = cJSON_GetObjectItem(o, "ol_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ol_port);

    item = cJSON_GetObjectItem(o, "ir_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->ir_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "or_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->or_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "r_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->r_port);

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "proto");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->proto);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat64_add_del_prefix_t *vl_api_nat64_add_del_prefix_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_add_del_prefix_t);
    vl_api_nat64_add_del_prefix_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_ip6_prefix_t_fromjson((void **)&a, &l, item, &a->prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat64_add_del_prefix_reply_t *vl_api_nat64_add_del_prefix_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_add_del_prefix_reply_t);
    vl_api_nat64_add_del_prefix_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat64_prefix_dump_t *vl_api_nat64_prefix_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_prefix_dump_t);
    vl_api_nat64_prefix_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_nat64_prefix_details_t *vl_api_nat64_prefix_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_prefix_details_t);
    vl_api_nat64_prefix_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_ip6_prefix_t_fromjson((void **)&a, &l, item, &a->prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat64_add_del_interface_addr_t *vl_api_nat64_add_del_interface_addr_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_add_del_interface_addr_t);
    vl_api_nat64_add_del_interface_addr_t *a = cJSON_malloc(l);

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
static inline vl_api_nat64_add_del_interface_addr_reply_t *vl_api_nat64_add_del_interface_addr_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat64_add_del_interface_addr_reply_t);
    vl_api_nat64_add_del_interface_addr_reply_t *a = cJSON_malloc(l);

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
