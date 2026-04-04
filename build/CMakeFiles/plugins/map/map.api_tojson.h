/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_map_api_tojson_h
#define included_map_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_map_add_domain_t_tojson (vl_api_map_add_domain_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_add_domain");
    cJSON_AddStringToObject(o, "_crc", "249f195c");
    cJSON_AddItemToObject(o, "ip6_prefix", vl_api_ip6_prefix_t_tojson(&a->ip6_prefix));
    cJSON_AddItemToObject(o, "ip4_prefix", vl_api_ip4_prefix_t_tojson(&a->ip4_prefix));
    cJSON_AddItemToObject(o, "ip6_src", vl_api_ip6_prefix_t_tojson(&a->ip6_src));
    cJSON_AddNumberToObject(o, "ea_bits_len", a->ea_bits_len);
    cJSON_AddNumberToObject(o, "psid_offset", a->psid_offset);
    cJSON_AddNumberToObject(o, "psid_length", a->psid_length);
    cJSON_AddNumberToObject(o, "mtu", a->mtu);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    return o;
}
static inline cJSON *vl_api_map_add_domain_reply_t_tojson (vl_api_map_add_domain_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_add_domain_reply");
    cJSON_AddStringToObject(o, "_crc", "3e6d4e2c");
    cJSON_AddNumberToObject(o, "index", a->index);
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_map_del_domain_t_tojson (vl_api_map_del_domain_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_del_domain");
    cJSON_AddStringToObject(o, "_crc", "8ac76db6");
    cJSON_AddNumberToObject(o, "index", a->index);
    return o;
}
static inline cJSON *vl_api_map_del_domain_reply_t_tojson (vl_api_map_del_domain_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_del_domain_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_map_add_del_rule_t_tojson (vl_api_map_add_del_rule_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_add_del_rule");
    cJSON_AddStringToObject(o, "_crc", "c65b32f7");
    cJSON_AddNumberToObject(o, "index", a->index);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "ip6_dst", vl_api_ip6_address_t_tojson(&a->ip6_dst));
    cJSON_AddNumberToObject(o, "psid", a->psid);
    return o;
}
static inline cJSON *vl_api_map_add_del_rule_reply_t_tojson (vl_api_map_add_del_rule_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_add_del_rule_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_map_domains_get_t_tojson (vl_api_map_domains_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_domains_get");
    cJSON_AddStringToObject(o, "_crc", "f75ba505");
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_map_domains_get_reply_t_tojson (vl_api_map_domains_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_domains_get_reply");
    cJSON_AddStringToObject(o, "_crc", "53b48f5d");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_map_domain_dump_t_tojson (vl_api_map_domain_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_domain_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_map_domain_details_t_tojson (vl_api_map_domain_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_domain_details");
    cJSON_AddStringToObject(o, "_crc", "796edb50");
    cJSON_AddNumberToObject(o, "domain_index", a->domain_index);
    cJSON_AddItemToObject(o, "ip6_prefix", vl_api_ip6_prefix_t_tojson(&a->ip6_prefix));
    cJSON_AddItemToObject(o, "ip4_prefix", vl_api_ip4_prefix_t_tojson(&a->ip4_prefix));
    cJSON_AddItemToObject(o, "ip6_src", vl_api_ip6_prefix_t_tojson(&a->ip6_src));
    cJSON_AddNumberToObject(o, "ea_bits_len", a->ea_bits_len);
    cJSON_AddNumberToObject(o, "psid_offset", a->psid_offset);
    cJSON_AddNumberToObject(o, "psid_length", a->psid_length);
    cJSON_AddNumberToObject(o, "flags", a->flags);
    cJSON_AddNumberToObject(o, "mtu", a->mtu);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    return o;
}
static inline cJSON *vl_api_map_rule_dump_t_tojson (vl_api_map_rule_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_rule_dump");
    cJSON_AddStringToObject(o, "_crc", "e43e6ff6");
    cJSON_AddNumberToObject(o, "domain_index", a->domain_index);
    return o;
}
static inline cJSON *vl_api_map_rule_details_t_tojson (vl_api_map_rule_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_rule_details");
    cJSON_AddStringToObject(o, "_crc", "c7cbeea5");
    cJSON_AddItemToObject(o, "ip6_dst", vl_api_ip6_address_t_tojson(&a->ip6_dst));
    cJSON_AddNumberToObject(o, "psid", a->psid);
    return o;
}
static inline cJSON *vl_api_map_if_enable_disable_t_tojson (vl_api_map_if_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_if_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "59bb32f4");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_enable", a->is_enable);
    cJSON_AddBoolToObject(o, "is_translation", a->is_translation);
    return o;
}
static inline cJSON *vl_api_map_if_enable_disable_reply_t_tojson (vl_api_map_if_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_if_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_map_summary_stats_t_tojson (vl_api_map_summary_stats_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_summary_stats");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_map_summary_stats_reply_t_tojson (vl_api_map_summary_stats_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_summary_stats_reply");
    cJSON_AddStringToObject(o, "_crc", "0e4ace0e");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "total_bindings", a->total_bindings);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "total_pkts");
        for (i = 0; i < 2; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->total_pkts[i]));
        }
    }
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "total_bytes");
        for (i = 0; i < 2; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->total_bytes[i]));
        }
    }
    cJSON_AddNumberToObject(o, "total_ip4_fragments", a->total_ip4_fragments);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "total_security_check");
        for (i = 0; i < 2; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->total_security_check[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_map_param_set_fragmentation_t_tojson (vl_api_map_param_set_fragmentation_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_param_set_fragmentation");
    cJSON_AddStringToObject(o, "_crc", "9ff54d90");
    cJSON_AddBoolToObject(o, "inner", a->inner);
    cJSON_AddBoolToObject(o, "ignore_df", a->ignore_df);
    return o;
}
static inline cJSON *vl_api_map_param_set_fragmentation_reply_t_tojson (vl_api_map_param_set_fragmentation_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_param_set_fragmentation_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_map_param_set_icmp_t_tojson (vl_api_map_param_set_icmp_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_param_set_icmp");
    cJSON_AddStringToObject(o, "_crc", "58210cbf");
    cJSON_AddItemToObject(o, "ip4_err_relay_src", vl_api_ip4_address_t_tojson(&a->ip4_err_relay_src));
    return o;
}
static inline cJSON *vl_api_map_param_set_icmp_reply_t_tojson (vl_api_map_param_set_icmp_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_param_set_icmp_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_map_param_set_icmp6_t_tojson (vl_api_map_param_set_icmp6_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_param_set_icmp6");
    cJSON_AddStringToObject(o, "_crc", "5d01f8c1");
    cJSON_AddBoolToObject(o, "enable_unreachable", a->enable_unreachable);
    return o;
}
static inline cJSON *vl_api_map_param_set_icmp6_reply_t_tojson (vl_api_map_param_set_icmp6_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_param_set_icmp6_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_map_param_add_del_pre_resolve_t_tojson (vl_api_map_param_add_del_pre_resolve_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_param_add_del_pre_resolve");
    cJSON_AddStringToObject(o, "_crc", "dae5af03");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "ip4_nh_address", vl_api_ip4_address_t_tojson(&a->ip4_nh_address));
    cJSON_AddItemToObject(o, "ip6_nh_address", vl_api_ip6_address_t_tojson(&a->ip6_nh_address));
    return o;
}
static inline cJSON *vl_api_map_param_add_del_pre_resolve_reply_t_tojson (vl_api_map_param_add_del_pre_resolve_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_param_add_del_pre_resolve_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_map_param_set_security_check_t_tojson (vl_api_map_param_set_security_check_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_param_set_security_check");
    cJSON_AddStringToObject(o, "_crc", "6abe9836");
    cJSON_AddBoolToObject(o, "enable", a->enable);
    cJSON_AddBoolToObject(o, "fragments", a->fragments);
    return o;
}
static inline cJSON *vl_api_map_param_set_security_check_reply_t_tojson (vl_api_map_param_set_security_check_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_param_set_security_check_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_map_param_set_traffic_class_t_tojson (vl_api_map_param_set_traffic_class_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_param_set_traffic_class");
    cJSON_AddStringToObject(o, "_crc", "9cac455c");
    cJSON_AddBoolToObject(o, "copy", a->copy);
    cJSON_AddNumberToObject(o, "tc_class", a->tc_class);
    return o;
}
static inline cJSON *vl_api_map_param_set_traffic_class_reply_t_tojson (vl_api_map_param_set_traffic_class_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_param_set_traffic_class_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_map_param_set_tcp_t_tojson (vl_api_map_param_set_tcp_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_param_set_tcp");
    cJSON_AddStringToObject(o, "_crc", "87a825d9");
    cJSON_AddNumberToObject(o, "tcp_mss", a->tcp_mss);
    return o;
}
static inline cJSON *vl_api_map_param_set_tcp_reply_t_tojson (vl_api_map_param_set_tcp_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_param_set_tcp_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_map_param_get_t_tojson (vl_api_map_param_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_param_get");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_map_param_get_reply_t_tojson (vl_api_map_param_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "map_param_get_reply");
    cJSON_AddStringToObject(o, "_crc", "26272c90");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "frag_inner", a->frag_inner);
    cJSON_AddNumberToObject(o, "frag_ignore_df", a->frag_ignore_df);
    cJSON_AddItemToObject(o, "icmp_ip4_err_relay_src", vl_api_ip4_address_t_tojson(&a->icmp_ip4_err_relay_src));
    cJSON_AddBoolToObject(o, "icmp6_enable_unreachable", a->icmp6_enable_unreachable);
    cJSON_AddItemToObject(o, "ip4_nh_address", vl_api_ip4_address_t_tojson(&a->ip4_nh_address));
    cJSON_AddItemToObject(o, "ip6_nh_address", vl_api_ip6_address_t_tojson(&a->ip6_nh_address));
    cJSON_AddNumberToObject(o, "ip4_lifetime_ms", a->ip4_lifetime_ms);
    cJSON_AddNumberToObject(o, "ip4_pool_size", a->ip4_pool_size);
    cJSON_AddNumberToObject(o, "ip4_buffers", a->ip4_buffers);
    cJSON_AddNumberToObject(o, "ip4_ht_ratio", a->ip4_ht_ratio);
    cJSON_AddBoolToObject(o, "sec_check_enable", a->sec_check_enable);
    cJSON_AddBoolToObject(o, "sec_check_fragments", a->sec_check_fragments);
    cJSON_AddBoolToObject(o, "tc_copy", a->tc_copy);
    cJSON_AddNumberToObject(o, "tc_class", a->tc_class);
    return o;
}
#endif
