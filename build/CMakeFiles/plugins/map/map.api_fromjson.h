/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_map_api_fromjson_h
#define included_map_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_map_add_domain_t *vl_api_map_add_domain_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_add_domain_t);
    vl_api_map_add_domain_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ip6_prefix");
    if (!item) goto error;
    if (vl_api_ip6_prefix_t_fromjson((void **)&a, &l, item, &a->ip6_prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip4_prefix");
    if (!item) goto error;
    if (vl_api_ip4_prefix_t_fromjson((void **)&a, &l, item, &a->ip4_prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip6_src");
    if (!item) goto error;
    if (vl_api_ip6_prefix_t_fromjson((void **)&a, &l, item, &a->ip6_src) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ea_bits_len");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->ea_bits_len);

    item = cJSON_GetObjectItem(o, "psid_offset");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->psid_offset);

    item = cJSON_GetObjectItem(o, "psid_length");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->psid_length);

    item = cJSON_GetObjectItem(o, "mtu");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->mtu);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_add_domain_reply_t *vl_api_map_add_domain_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_add_domain_reply_t);
    vl_api_map_add_domain_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->index);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_del_domain_t *vl_api_map_del_domain_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_del_domain_t);
    vl_api_map_del_domain_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_del_domain_reply_t *vl_api_map_del_domain_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_del_domain_reply_t);
    vl_api_map_del_domain_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_add_del_rule_t *vl_api_map_add_del_rule_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_add_del_rule_t);
    vl_api_map_add_del_rule_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->index);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "ip6_dst");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->ip6_dst) < 0) goto error;

    item = cJSON_GetObjectItem(o, "psid");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->psid);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_add_del_rule_reply_t *vl_api_map_add_del_rule_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_add_del_rule_reply_t);
    vl_api_map_add_del_rule_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_domains_get_t *vl_api_map_domains_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_domains_get_t);
    vl_api_map_domains_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_domains_get_reply_t *vl_api_map_domains_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_domains_get_reply_t);
    vl_api_map_domains_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_domain_dump_t *vl_api_map_domain_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_domain_dump_t);
    vl_api_map_domain_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_map_domain_details_t *vl_api_map_domain_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_domain_details_t);
    vl_api_map_domain_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "domain_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->domain_index);

    item = cJSON_GetObjectItem(o, "ip6_prefix");
    if (!item) goto error;
    if (vl_api_ip6_prefix_t_fromjson((void **)&a, &l, item, &a->ip6_prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip4_prefix");
    if (!item) goto error;
    if (vl_api_ip4_prefix_t_fromjson((void **)&a, &l, item, &a->ip4_prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip6_src");
    if (!item) goto error;
    if (vl_api_ip6_prefix_t_fromjson((void **)&a, &l, item, &a->ip6_src) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ea_bits_len");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->ea_bits_len);

    item = cJSON_GetObjectItem(o, "psid_offset");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->psid_offset);

    item = cJSON_GetObjectItem(o, "psid_length");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->psid_length);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->flags);

    item = cJSON_GetObjectItem(o, "mtu");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->mtu);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_rule_dump_t *vl_api_map_rule_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_rule_dump_t);
    vl_api_map_rule_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "domain_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->domain_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_rule_details_t *vl_api_map_rule_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_rule_details_t);
    vl_api_map_rule_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ip6_dst");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->ip6_dst) < 0) goto error;

    item = cJSON_GetObjectItem(o, "psid");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->psid);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_if_enable_disable_t *vl_api_map_if_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_if_enable_disable_t);
    vl_api_map_if_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    item = cJSON_GetObjectItem(o, "is_translation");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_translation);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_if_enable_disable_reply_t *vl_api_map_if_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_if_enable_disable_reply_t);
    vl_api_map_if_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_summary_stats_t *vl_api_map_summary_stats_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_summary_stats_t);
    vl_api_map_summary_stats_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_map_summary_stats_reply_t *vl_api_map_summary_stats_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_summary_stats_reply_t);
    vl_api_map_summary_stats_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "total_bindings");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->total_bindings);

    item = cJSON_GetObjectItem(o, "total_pkts");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "total_pkts");
        int size = cJSON_GetArraySize(array);
        if (size != 2) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u64_fromjson(e, &a->total_pkts[i]);
        }
    }

    item = cJSON_GetObjectItem(o, "total_bytes");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "total_bytes");
        int size = cJSON_GetArraySize(array);
        if (size != 2) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u64_fromjson(e, &a->total_bytes[i]);
        }
    }

    item = cJSON_GetObjectItem(o, "total_ip4_fragments");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->total_ip4_fragments);

    item = cJSON_GetObjectItem(o, "total_security_check");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "total_security_check");
        int size = cJSON_GetArraySize(array);
        if (size != 2) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u64_fromjson(e, &a->total_security_check[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_param_set_fragmentation_t *vl_api_map_param_set_fragmentation_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_param_set_fragmentation_t);
    vl_api_map_param_set_fragmentation_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "inner");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->inner);

    item = cJSON_GetObjectItem(o, "ignore_df");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->ignore_df);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_param_set_fragmentation_reply_t *vl_api_map_param_set_fragmentation_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_param_set_fragmentation_reply_t);
    vl_api_map_param_set_fragmentation_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_param_set_icmp_t *vl_api_map_param_set_icmp_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_param_set_icmp_t);
    vl_api_map_param_set_icmp_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ip4_err_relay_src");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ip4_err_relay_src) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_param_set_icmp_reply_t *vl_api_map_param_set_icmp_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_param_set_icmp_reply_t);
    vl_api_map_param_set_icmp_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_param_set_icmp6_t *vl_api_map_param_set_icmp6_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_param_set_icmp6_t);
    vl_api_map_param_set_icmp6_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable_unreachable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_unreachable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_param_set_icmp6_reply_t *vl_api_map_param_set_icmp6_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_param_set_icmp6_reply_t);
    vl_api_map_param_set_icmp6_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_param_add_del_pre_resolve_t *vl_api_map_param_add_del_pre_resolve_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_param_add_del_pre_resolve_t);
    vl_api_map_param_add_del_pre_resolve_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "ip4_nh_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ip4_nh_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip6_nh_address");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->ip6_nh_address) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_param_add_del_pre_resolve_reply_t *vl_api_map_param_add_del_pre_resolve_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_param_add_del_pre_resolve_reply_t);
    vl_api_map_param_add_del_pre_resolve_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_param_set_security_check_t *vl_api_map_param_set_security_check_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_param_set_security_check_t);
    vl_api_map_param_set_security_check_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    item = cJSON_GetObjectItem(o, "fragments");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->fragments);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_param_set_security_check_reply_t *vl_api_map_param_set_security_check_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_param_set_security_check_reply_t);
    vl_api_map_param_set_security_check_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_param_set_traffic_class_t *vl_api_map_param_set_traffic_class_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_param_set_traffic_class_t);
    vl_api_map_param_set_traffic_class_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "copy");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->copy);

    item = cJSON_GetObjectItem(o, "tc_class");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->tc_class);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_param_set_traffic_class_reply_t *vl_api_map_param_set_traffic_class_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_param_set_traffic_class_reply_t);
    vl_api_map_param_set_traffic_class_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_param_set_tcp_t *vl_api_map_param_set_tcp_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_param_set_tcp_t);
    vl_api_map_param_set_tcp_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "tcp_mss");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->tcp_mss);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_param_set_tcp_reply_t *vl_api_map_param_set_tcp_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_param_set_tcp_reply_t);
    vl_api_map_param_set_tcp_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_map_param_get_t *vl_api_map_param_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_param_get_t);
    vl_api_map_param_get_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_map_param_get_reply_t *vl_api_map_param_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_map_param_get_reply_t);
    vl_api_map_param_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "frag_inner");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->frag_inner);

    item = cJSON_GetObjectItem(o, "frag_ignore_df");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->frag_ignore_df);

    item = cJSON_GetObjectItem(o, "icmp_ip4_err_relay_src");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->icmp_ip4_err_relay_src) < 0) goto error;

    item = cJSON_GetObjectItem(o, "icmp6_enable_unreachable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->icmp6_enable_unreachable);

    item = cJSON_GetObjectItem(o, "ip4_nh_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ip4_nh_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip6_nh_address");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->ip6_nh_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip4_lifetime_ms");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ip4_lifetime_ms);

    item = cJSON_GetObjectItem(o, "ip4_pool_size");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ip4_pool_size);

    item = cJSON_GetObjectItem(o, "ip4_buffers");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip4_buffers);

    item = cJSON_GetObjectItem(o, "ip4_ht_ratio");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->ip4_ht_ratio);

    item = cJSON_GetObjectItem(o, "sec_check_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->sec_check_enable);

    item = cJSON_GetObjectItem(o, "sec_check_fragments");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->sec_check_fragments);

    item = cJSON_GetObjectItem(o, "tc_copy");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->tc_copy);

    item = cJSON_GetObjectItem(o, "tc_class");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->tc_class);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
