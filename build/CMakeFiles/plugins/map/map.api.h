/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: map.api
 * Automatically generated: please edit the input file NOT this file!
 */

#include <stdbool.h>
#if defined(vl_msg_id)||defined(vl_union_id) \
    || defined(vl_printfun) ||defined(vl_endianfun) \
    || defined(vl_api_version)||defined(vl_typedefs) \
    || defined(vl_msg_name)||defined(vl_msg_name_crc_list) \
    || defined(vl_api_version_tuple) || defined(vl_calcsizefun)
/* ok, something was selected */
#else
#warning no content included from map.api
#endif

#define VL_API_PACKED(x) x __attribute__ ((packed))

/*
 * Note: VL_API_MAX_ARRAY_SIZE is set to an arbitrarily large limit.
 *
 * However, any message with a ~2 billion element array is likely to break the
 * api handling long before this limit causes array element endian issues.
 *
 * Applications should be written to create reasonable api messages.
 */
#define VL_API_MAX_ARRAY_SIZE 0x7fffffff

/* Imported API files */
#ifndef vl_api_version
#include <vnet/ip/ip_types.api.h>
#include <vnet/interface_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_MAP_ADD_DOMAIN, vl_api_map_add_domain_t_handler)
vl_msg_id(VL_API_MAP_ADD_DOMAIN_REPLY, vl_api_map_add_domain_reply_t_handler)
vl_msg_id(VL_API_MAP_DEL_DOMAIN, vl_api_map_del_domain_t_handler)
vl_msg_id(VL_API_MAP_DEL_DOMAIN_REPLY, vl_api_map_del_domain_reply_t_handler)
vl_msg_id(VL_API_MAP_ADD_DEL_RULE, vl_api_map_add_del_rule_t_handler)
vl_msg_id(VL_API_MAP_ADD_DEL_RULE_REPLY, vl_api_map_add_del_rule_reply_t_handler)
vl_msg_id(VL_API_MAP_DOMAINS_GET, vl_api_map_domains_get_t_handler)
vl_msg_id(VL_API_MAP_DOMAINS_GET_REPLY, vl_api_map_domains_get_reply_t_handler)
vl_msg_id(VL_API_MAP_DOMAIN_DUMP, vl_api_map_domain_dump_t_handler)
vl_msg_id(VL_API_MAP_DOMAIN_DETAILS, vl_api_map_domain_details_t_handler)
vl_msg_id(VL_API_MAP_RULE_DUMP, vl_api_map_rule_dump_t_handler)
vl_msg_id(VL_API_MAP_RULE_DETAILS, vl_api_map_rule_details_t_handler)
vl_msg_id(VL_API_MAP_IF_ENABLE_DISABLE, vl_api_map_if_enable_disable_t_handler)
vl_msg_id(VL_API_MAP_IF_ENABLE_DISABLE_REPLY, vl_api_map_if_enable_disable_reply_t_handler)
vl_msg_id(VL_API_MAP_SUMMARY_STATS, vl_api_map_summary_stats_t_handler)
vl_msg_id(VL_API_MAP_SUMMARY_STATS_REPLY, vl_api_map_summary_stats_reply_t_handler)
vl_msg_id(VL_API_MAP_PARAM_SET_FRAGMENTATION, vl_api_map_param_set_fragmentation_t_handler)
vl_msg_id(VL_API_MAP_PARAM_SET_FRAGMENTATION_REPLY, vl_api_map_param_set_fragmentation_reply_t_handler)
vl_msg_id(VL_API_MAP_PARAM_SET_ICMP, vl_api_map_param_set_icmp_t_handler)
vl_msg_id(VL_API_MAP_PARAM_SET_ICMP_REPLY, vl_api_map_param_set_icmp_reply_t_handler)
vl_msg_id(VL_API_MAP_PARAM_SET_ICMP6, vl_api_map_param_set_icmp6_t_handler)
vl_msg_id(VL_API_MAP_PARAM_SET_ICMP6_REPLY, vl_api_map_param_set_icmp6_reply_t_handler)
vl_msg_id(VL_API_MAP_PARAM_ADD_DEL_PRE_RESOLVE, vl_api_map_param_add_del_pre_resolve_t_handler)
vl_msg_id(VL_API_MAP_PARAM_ADD_DEL_PRE_RESOLVE_REPLY, vl_api_map_param_add_del_pre_resolve_reply_t_handler)
vl_msg_id(VL_API_MAP_PARAM_SET_SECURITY_CHECK, vl_api_map_param_set_security_check_t_handler)
vl_msg_id(VL_API_MAP_PARAM_SET_SECURITY_CHECK_REPLY, vl_api_map_param_set_security_check_reply_t_handler)
vl_msg_id(VL_API_MAP_PARAM_SET_TRAFFIC_CLASS, vl_api_map_param_set_traffic_class_t_handler)
vl_msg_id(VL_API_MAP_PARAM_SET_TRAFFIC_CLASS_REPLY, vl_api_map_param_set_traffic_class_reply_t_handler)
vl_msg_id(VL_API_MAP_PARAM_SET_TCP, vl_api_map_param_set_tcp_t_handler)
vl_msg_id(VL_API_MAP_PARAM_SET_TCP_REPLY, vl_api_map_param_set_tcp_reply_t_handler)
vl_msg_id(VL_API_MAP_PARAM_GET, vl_api_map_param_get_t_handler)
vl_msg_id(VL_API_MAP_PARAM_GET_REPLY, vl_api_map_param_get_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_map_add_domain_t, 1)
vl_msg_name(vl_api_map_add_domain_reply_t, 1)
vl_msg_name(vl_api_map_del_domain_t, 1)
vl_msg_name(vl_api_map_del_domain_reply_t, 1)
vl_msg_name(vl_api_map_add_del_rule_t, 1)
vl_msg_name(vl_api_map_add_del_rule_reply_t, 1)
vl_msg_name(vl_api_map_domains_get_t, 1)
vl_msg_name(vl_api_map_domains_get_reply_t, 1)
vl_msg_name(vl_api_map_domain_dump_t, 1)
vl_msg_name(vl_api_map_domain_details_t, 1)
vl_msg_name(vl_api_map_rule_dump_t, 1)
vl_msg_name(vl_api_map_rule_details_t, 1)
vl_msg_name(vl_api_map_if_enable_disable_t, 1)
vl_msg_name(vl_api_map_if_enable_disable_reply_t, 1)
vl_msg_name(vl_api_map_summary_stats_t, 1)
vl_msg_name(vl_api_map_summary_stats_reply_t, 1)
vl_msg_name(vl_api_map_param_set_fragmentation_t, 1)
vl_msg_name(vl_api_map_param_set_fragmentation_reply_t, 1)
vl_msg_name(vl_api_map_param_set_icmp_t, 1)
vl_msg_name(vl_api_map_param_set_icmp_reply_t, 1)
vl_msg_name(vl_api_map_param_set_icmp6_t, 1)
vl_msg_name(vl_api_map_param_set_icmp6_reply_t, 1)
vl_msg_name(vl_api_map_param_add_del_pre_resolve_t, 1)
vl_msg_name(vl_api_map_param_add_del_pre_resolve_reply_t, 1)
vl_msg_name(vl_api_map_param_set_security_check_t, 1)
vl_msg_name(vl_api_map_param_set_security_check_reply_t, 1)
vl_msg_name(vl_api_map_param_set_traffic_class_t, 1)
vl_msg_name(vl_api_map_param_set_traffic_class_reply_t, 1)
vl_msg_name(vl_api_map_param_set_tcp_t, 1)
vl_msg_name(vl_api_map_param_set_tcp_reply_t, 1)
vl_msg_name(vl_api_map_param_get_t, 1)
vl_msg_name(vl_api_map_param_get_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_map \
_(VL_API_MAP_ADD_DOMAIN, map_add_domain, 249f195c) \
_(VL_API_MAP_ADD_DOMAIN_REPLY, map_add_domain_reply, 3e6d4e2c) \
_(VL_API_MAP_DEL_DOMAIN, map_del_domain, 8ac76db6) \
_(VL_API_MAP_DEL_DOMAIN_REPLY, map_del_domain_reply, e8d4e804) \
_(VL_API_MAP_ADD_DEL_RULE, map_add_del_rule, c65b32f7) \
_(VL_API_MAP_ADD_DEL_RULE_REPLY, map_add_del_rule_reply, e8d4e804) \
_(VL_API_MAP_DOMAINS_GET, map_domains_get, f75ba505) \
_(VL_API_MAP_DOMAINS_GET_REPLY, map_domains_get_reply, 53b48f5d) \
_(VL_API_MAP_DOMAIN_DUMP, map_domain_dump, 51077d14) \
_(VL_API_MAP_DOMAIN_DETAILS, map_domain_details, 796edb50) \
_(VL_API_MAP_RULE_DUMP, map_rule_dump, e43e6ff6) \
_(VL_API_MAP_RULE_DETAILS, map_rule_details, c7cbeea5) \
_(VL_API_MAP_IF_ENABLE_DISABLE, map_if_enable_disable, 59bb32f4) \
_(VL_API_MAP_IF_ENABLE_DISABLE_REPLY, map_if_enable_disable_reply, e8d4e804) \
_(VL_API_MAP_SUMMARY_STATS, map_summary_stats, 51077d14) \
_(VL_API_MAP_SUMMARY_STATS_REPLY, map_summary_stats_reply, 0e4ace0e) \
_(VL_API_MAP_PARAM_SET_FRAGMENTATION, map_param_set_fragmentation, 9ff54d90) \
_(VL_API_MAP_PARAM_SET_FRAGMENTATION_REPLY, map_param_set_fragmentation_reply, e8d4e804) \
_(VL_API_MAP_PARAM_SET_ICMP, map_param_set_icmp, 58210cbf) \
_(VL_API_MAP_PARAM_SET_ICMP_REPLY, map_param_set_icmp_reply, e8d4e804) \
_(VL_API_MAP_PARAM_SET_ICMP6, map_param_set_icmp6, 5d01f8c1) \
_(VL_API_MAP_PARAM_SET_ICMP6_REPLY, map_param_set_icmp6_reply, e8d4e804) \
_(VL_API_MAP_PARAM_ADD_DEL_PRE_RESOLVE, map_param_add_del_pre_resolve, dae5af03) \
_(VL_API_MAP_PARAM_ADD_DEL_PRE_RESOLVE_REPLY, map_param_add_del_pre_resolve_reply, e8d4e804) \
_(VL_API_MAP_PARAM_SET_SECURITY_CHECK, map_param_set_security_check, 6abe9836) \
_(VL_API_MAP_PARAM_SET_SECURITY_CHECK_REPLY, map_param_set_security_check_reply, e8d4e804) \
_(VL_API_MAP_PARAM_SET_TRAFFIC_CLASS, map_param_set_traffic_class, 9cac455c) \
_(VL_API_MAP_PARAM_SET_TRAFFIC_CLASS_REPLY, map_param_set_traffic_class_reply, e8d4e804) \
_(VL_API_MAP_PARAM_SET_TCP, map_param_set_tcp, 87a825d9) \
_(VL_API_MAP_PARAM_SET_TCP_REPLY, map_param_set_tcp_reply, e8d4e804) \
_(VL_API_MAP_PARAM_GET, map_param_get, 51077d14) \
_(VL_API_MAP_PARAM_GET_REPLY, map_param_get_reply, 26272c90) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "map.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_map_printfun_types
#define included_map_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_map_printfun
#define included_map_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "map.api_tojson.h"
#include "map.api_fromjson.h"

static inline u8 *vl_api_map_add_domain_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_add_domain_t *a = va_arg (*args, vl_api_map_add_domain_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_add_domain_t: */
    s = format(s, "vl_api_map_add_domain_t:");
    s = format(s, "\n%Uip6_prefix: %U", format_white_space, indent, format_vl_api_ip6_prefix_t, &a->ip6_prefix, indent);
    s = format(s, "\n%Uip4_prefix: %U", format_white_space, indent, format_vl_api_ip4_prefix_t, &a->ip4_prefix, indent);
    s = format(s, "\n%Uip6_src: %U", format_white_space, indent, format_vl_api_ip6_prefix_t, &a->ip6_src, indent);
    s = format(s, "\n%Uea_bits_len: %u", format_white_space, indent, a->ea_bits_len);
    s = format(s, "\n%Upsid_offset: %u", format_white_space, indent, a->psid_offset);
    s = format(s, "\n%Upsid_length: %u", format_white_space, indent, a->psid_length);
    s = format(s, "\n%Umtu: %u", format_white_space, indent, a->mtu);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    return s;
}

static inline u8 *vl_api_map_add_domain_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_add_domain_reply_t *a = va_arg (*args, vl_api_map_add_domain_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_add_domain_reply_t: */
    s = format(s, "vl_api_map_add_domain_reply_t:");
    s = format(s, "\n%Uindex: %u", format_white_space, indent, a->index);
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_map_del_domain_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_del_domain_t *a = va_arg (*args, vl_api_map_del_domain_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_del_domain_t: */
    s = format(s, "vl_api_map_del_domain_t:");
    s = format(s, "\n%Uindex: %u", format_white_space, indent, a->index);
    return s;
}

static inline u8 *vl_api_map_del_domain_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_del_domain_reply_t *a = va_arg (*args, vl_api_map_del_domain_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_del_domain_reply_t: */
    s = format(s, "vl_api_map_del_domain_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_map_add_del_rule_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_add_del_rule_t *a = va_arg (*args, vl_api_map_add_del_rule_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_add_del_rule_t: */
    s = format(s, "vl_api_map_add_del_rule_t:");
    s = format(s, "\n%Uindex: %u", format_white_space, indent, a->index);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uip6_dst: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->ip6_dst, indent);
    s = format(s, "\n%Upsid: %u", format_white_space, indent, a->psid);
    return s;
}

static inline u8 *vl_api_map_add_del_rule_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_add_del_rule_reply_t *a = va_arg (*args, vl_api_map_add_del_rule_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_add_del_rule_reply_t: */
    s = format(s, "vl_api_map_add_del_rule_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_map_domains_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_domains_get_t *a = va_arg (*args, vl_api_map_domains_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_domains_get_t: */
    s = format(s, "vl_api_map_domains_get_t:");
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_map_domains_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_domains_get_reply_t *a = va_arg (*args, vl_api_map_domains_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_domains_get_reply_t: */
    s = format(s, "vl_api_map_domains_get_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_map_domain_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_domain_dump_t *a = va_arg (*args, vl_api_map_domain_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_domain_dump_t: */
    s = format(s, "vl_api_map_domain_dump_t:");
    return s;
}

static inline u8 *vl_api_map_domain_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_domain_details_t *a = va_arg (*args, vl_api_map_domain_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_domain_details_t: */
    s = format(s, "vl_api_map_domain_details_t:");
    s = format(s, "\n%Udomain_index: %u", format_white_space, indent, a->domain_index);
    s = format(s, "\n%Uip6_prefix: %U", format_white_space, indent, format_vl_api_ip6_prefix_t, &a->ip6_prefix, indent);
    s = format(s, "\n%Uip4_prefix: %U", format_white_space, indent, format_vl_api_ip4_prefix_t, &a->ip4_prefix, indent);
    s = format(s, "\n%Uip6_src: %U", format_white_space, indent, format_vl_api_ip6_prefix_t, &a->ip6_src, indent);
    s = format(s, "\n%Uea_bits_len: %u", format_white_space, indent, a->ea_bits_len);
    s = format(s, "\n%Upsid_offset: %u", format_white_space, indent, a->psid_offset);
    s = format(s, "\n%Upsid_length: %u", format_white_space, indent, a->psid_length);
    s = format(s, "\n%Uflags: %u", format_white_space, indent, a->flags);
    s = format(s, "\n%Umtu: %u", format_white_space, indent, a->mtu);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    return s;
}

static inline u8 *vl_api_map_rule_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_rule_dump_t *a = va_arg (*args, vl_api_map_rule_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_rule_dump_t: */
    s = format(s, "vl_api_map_rule_dump_t:");
    s = format(s, "\n%Udomain_index: %u", format_white_space, indent, a->domain_index);
    return s;
}

static inline u8 *vl_api_map_rule_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_rule_details_t *a = va_arg (*args, vl_api_map_rule_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_rule_details_t: */
    s = format(s, "vl_api_map_rule_details_t:");
    s = format(s, "\n%Uip6_dst: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->ip6_dst, indent);
    s = format(s, "\n%Upsid: %u", format_white_space, indent, a->psid);
    return s;
}

static inline u8 *vl_api_map_if_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_if_enable_disable_t *a = va_arg (*args, vl_api_map_if_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_if_enable_disable_t: */
    s = format(s, "vl_api_map_if_enable_disable_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uis_enable: %u", format_white_space, indent, a->is_enable);
    s = format(s, "\n%Uis_translation: %u", format_white_space, indent, a->is_translation);
    return s;
}

static inline u8 *vl_api_map_if_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_if_enable_disable_reply_t *a = va_arg (*args, vl_api_map_if_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_if_enable_disable_reply_t: */
    s = format(s, "vl_api_map_if_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_map_summary_stats_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_summary_stats_t *a = va_arg (*args, vl_api_map_summary_stats_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_summary_stats_t: */
    s = format(s, "vl_api_map_summary_stats_t:");
    return s;
}

static inline u8 *vl_api_map_summary_stats_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_summary_stats_reply_t *a = va_arg (*args, vl_api_map_summary_stats_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_summary_stats_reply_t: */
    s = format(s, "vl_api_map_summary_stats_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Utotal_bindings: %llu", format_white_space, indent, a->total_bindings);
    for (i = 0; i < 2; i++) {
        s = format(s, "\n%Utotal_pkts: %llu",
                   format_white_space, indent, a->total_pkts[i]);
    }
    for (i = 0; i < 2; i++) {
        s = format(s, "\n%Utotal_bytes: %llu",
                   format_white_space, indent, a->total_bytes[i]);
    }
    s = format(s, "\n%Utotal_ip4_fragments: %llu", format_white_space, indent, a->total_ip4_fragments);
    for (i = 0; i < 2; i++) {
        s = format(s, "\n%Utotal_security_check: %llu",
                   format_white_space, indent, a->total_security_check[i]);
    }
    return s;
}

static inline u8 *vl_api_map_param_set_fragmentation_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_param_set_fragmentation_t *a = va_arg (*args, vl_api_map_param_set_fragmentation_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_param_set_fragmentation_t: */
    s = format(s, "vl_api_map_param_set_fragmentation_t:");
    s = format(s, "\n%Uinner: %u", format_white_space, indent, a->inner);
    s = format(s, "\n%Uignore_df: %u", format_white_space, indent, a->ignore_df);
    return s;
}

static inline u8 *vl_api_map_param_set_fragmentation_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_param_set_fragmentation_reply_t *a = va_arg (*args, vl_api_map_param_set_fragmentation_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_param_set_fragmentation_reply_t: */
    s = format(s, "vl_api_map_param_set_fragmentation_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_map_param_set_icmp_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_param_set_icmp_t *a = va_arg (*args, vl_api_map_param_set_icmp_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_param_set_icmp_t: */
    s = format(s, "vl_api_map_param_set_icmp_t:");
    s = format(s, "\n%Uip4_err_relay_src: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip4_err_relay_src, indent);
    return s;
}

static inline u8 *vl_api_map_param_set_icmp_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_param_set_icmp_reply_t *a = va_arg (*args, vl_api_map_param_set_icmp_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_param_set_icmp_reply_t: */
    s = format(s, "vl_api_map_param_set_icmp_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_map_param_set_icmp6_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_param_set_icmp6_t *a = va_arg (*args, vl_api_map_param_set_icmp6_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_param_set_icmp6_t: */
    s = format(s, "vl_api_map_param_set_icmp6_t:");
    s = format(s, "\n%Uenable_unreachable: %u", format_white_space, indent, a->enable_unreachable);
    return s;
}

static inline u8 *vl_api_map_param_set_icmp6_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_param_set_icmp6_reply_t *a = va_arg (*args, vl_api_map_param_set_icmp6_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_param_set_icmp6_reply_t: */
    s = format(s, "vl_api_map_param_set_icmp6_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_map_param_add_del_pre_resolve_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_param_add_del_pre_resolve_t *a = va_arg (*args, vl_api_map_param_add_del_pre_resolve_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_param_add_del_pre_resolve_t: */
    s = format(s, "vl_api_map_param_add_del_pre_resolve_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uip4_nh_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip4_nh_address, indent);
    s = format(s, "\n%Uip6_nh_address: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->ip6_nh_address, indent);
    return s;
}

static inline u8 *vl_api_map_param_add_del_pre_resolve_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_param_add_del_pre_resolve_reply_t *a = va_arg (*args, vl_api_map_param_add_del_pre_resolve_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_param_add_del_pre_resolve_reply_t: */
    s = format(s, "vl_api_map_param_add_del_pre_resolve_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_map_param_set_security_check_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_param_set_security_check_t *a = va_arg (*args, vl_api_map_param_set_security_check_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_param_set_security_check_t: */
    s = format(s, "vl_api_map_param_set_security_check_t:");
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    s = format(s, "\n%Ufragments: %u", format_white_space, indent, a->fragments);
    return s;
}

static inline u8 *vl_api_map_param_set_security_check_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_param_set_security_check_reply_t *a = va_arg (*args, vl_api_map_param_set_security_check_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_param_set_security_check_reply_t: */
    s = format(s, "vl_api_map_param_set_security_check_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_map_param_set_traffic_class_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_param_set_traffic_class_t *a = va_arg (*args, vl_api_map_param_set_traffic_class_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_param_set_traffic_class_t: */
    s = format(s, "vl_api_map_param_set_traffic_class_t:");
    s = format(s, "\n%Ucopy: %u", format_white_space, indent, a->copy);
    s = format(s, "\n%Utc_class: %u", format_white_space, indent, a->tc_class);
    return s;
}

static inline u8 *vl_api_map_param_set_traffic_class_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_param_set_traffic_class_reply_t *a = va_arg (*args, vl_api_map_param_set_traffic_class_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_param_set_traffic_class_reply_t: */
    s = format(s, "vl_api_map_param_set_traffic_class_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_map_param_set_tcp_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_param_set_tcp_t *a = va_arg (*args, vl_api_map_param_set_tcp_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_param_set_tcp_t: */
    s = format(s, "vl_api_map_param_set_tcp_t:");
    s = format(s, "\n%Utcp_mss: %u", format_white_space, indent, a->tcp_mss);
    return s;
}

static inline u8 *vl_api_map_param_set_tcp_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_param_set_tcp_reply_t *a = va_arg (*args, vl_api_map_param_set_tcp_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_param_set_tcp_reply_t: */
    s = format(s, "vl_api_map_param_set_tcp_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_map_param_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_param_get_t *a = va_arg (*args, vl_api_map_param_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_param_get_t: */
    s = format(s, "vl_api_map_param_get_t:");
    return s;
}

static inline u8 *vl_api_map_param_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_map_param_get_reply_t *a = va_arg (*args, vl_api_map_param_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_map_param_get_reply_t: */
    s = format(s, "vl_api_map_param_get_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ufrag_inner: %u", format_white_space, indent, a->frag_inner);
    s = format(s, "\n%Ufrag_ignore_df: %u", format_white_space, indent, a->frag_ignore_df);
    s = format(s, "\n%Uicmp_ip4_err_relay_src: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->icmp_ip4_err_relay_src, indent);
    s = format(s, "\n%Uicmp6_enable_unreachable: %u", format_white_space, indent, a->icmp6_enable_unreachable);
    s = format(s, "\n%Uip4_nh_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip4_nh_address, indent);
    s = format(s, "\n%Uip6_nh_address: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->ip6_nh_address, indent);
    s = format(s, "\n%Uip4_lifetime_ms: %u", format_white_space, indent, a->ip4_lifetime_ms);
    s = format(s, "\n%Uip4_pool_size: %u", format_white_space, indent, a->ip4_pool_size);
    s = format(s, "\n%Uip4_buffers: %u", format_white_space, indent, a->ip4_buffers);
    s = format(s, "\n%Uip4_ht_ratio: %.2f", format_white_space, indent, a->ip4_ht_ratio);
    s = format(s, "\n%Usec_check_enable: %u", format_white_space, indent, a->sec_check_enable);
    s = format(s, "\n%Usec_check_fragments: %u", format_white_space, indent, a->sec_check_fragments);
    s = format(s, "\n%Utc_copy: %u", format_white_space, indent, a->tc_copy);
    s = format(s, "\n%Utc_class: %u", format_white_space, indent, a->tc_class);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_map_endianfun
#define included_map_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_map_add_domain_t_endian (vl_api_map_add_domain_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip6_prefix_t_endian(&a->ip6_prefix, to_net);
    vl_api_ip4_prefix_t_endian(&a->ip4_prefix, to_net);
    vl_api_ip6_prefix_t_endian(&a->ip6_src, to_net);
    /* a->ea_bits_len = a->ea_bits_len (no-op) */
    /* a->psid_offset = a->psid_offset (no-op) */
    /* a->psid_length = a->psid_length (no-op) */
    a->mtu = clib_net_to_host_u16(a->mtu);
    /* a->tag = a->tag (no-op) */
}

static inline void vl_api_map_add_domain_reply_t_endian (vl_api_map_add_domain_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->index = clib_net_to_host_u32(a->index);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_map_del_domain_t_endian (vl_api_map_del_domain_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->index = clib_net_to_host_u32(a->index);
}

static inline void vl_api_map_del_domain_reply_t_endian (vl_api_map_del_domain_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_map_add_del_rule_t_endian (vl_api_map_add_del_rule_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->index = clib_net_to_host_u32(a->index);
    /* a->is_add = a->is_add (no-op) */
    vl_api_ip6_address_t_endian(&a->ip6_dst, to_net);
    a->psid = clib_net_to_host_u16(a->psid);
}

static inline void vl_api_map_add_del_rule_reply_t_endian (vl_api_map_add_del_rule_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_map_domains_get_t_endian (vl_api_map_domains_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_map_domains_get_reply_t_endian (vl_api_map_domains_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_map_domain_dump_t_endian (vl_api_map_domain_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_map_domain_details_t_endian (vl_api_map_domain_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->domain_index = clib_net_to_host_u32(a->domain_index);
    vl_api_ip6_prefix_t_endian(&a->ip6_prefix, to_net);
    vl_api_ip4_prefix_t_endian(&a->ip4_prefix, to_net);
    vl_api_ip6_prefix_t_endian(&a->ip6_src, to_net);
    /* a->ea_bits_len = a->ea_bits_len (no-op) */
    /* a->psid_offset = a->psid_offset (no-op) */
    /* a->psid_length = a->psid_length (no-op) */
    /* a->flags = a->flags (no-op) */
    a->mtu = clib_net_to_host_u16(a->mtu);
    /* a->tag = a->tag (no-op) */
}

static inline void vl_api_map_rule_dump_t_endian (vl_api_map_rule_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->domain_index = clib_net_to_host_u32(a->domain_index);
}

static inline void vl_api_map_rule_details_t_endian (vl_api_map_rule_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip6_address_t_endian(&a->ip6_dst, to_net);
    a->psid = clib_net_to_host_u16(a->psid);
}

static inline void vl_api_map_if_enable_disable_t_endian (vl_api_map_if_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->is_enable = a->is_enable (no-op) */
    /* a->is_translation = a->is_translation (no-op) */
}

static inline void vl_api_map_if_enable_disable_reply_t_endian (vl_api_map_if_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_map_summary_stats_t_endian (vl_api_map_summary_stats_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_map_summary_stats_reply_t_endian (vl_api_map_summary_stats_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->total_bindings = clib_net_to_host_u64(a->total_bindings);
    ASSERT((u32)2 <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < 2; i++) {
        a->total_pkts[i] = clib_net_to_host_u64(a->total_pkts[i]);
    }
    ASSERT((u32)2 <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < 2; i++) {
        a->total_bytes[i] = clib_net_to_host_u64(a->total_bytes[i]);
    }
    a->total_ip4_fragments = clib_net_to_host_u64(a->total_ip4_fragments);
    ASSERT((u32)2 <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < 2; i++) {
        a->total_security_check[i] = clib_net_to_host_u64(a->total_security_check[i]);
    }
}

static inline void vl_api_map_param_set_fragmentation_t_endian (vl_api_map_param_set_fragmentation_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->inner = a->inner (no-op) */
    /* a->ignore_df = a->ignore_df (no-op) */
}

static inline void vl_api_map_param_set_fragmentation_reply_t_endian (vl_api_map_param_set_fragmentation_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_map_param_set_icmp_t_endian (vl_api_map_param_set_icmp_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->ip4_err_relay_src, to_net);
}

static inline void vl_api_map_param_set_icmp_reply_t_endian (vl_api_map_param_set_icmp_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_map_param_set_icmp6_t_endian (vl_api_map_param_set_icmp6_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->enable_unreachable = a->enable_unreachable (no-op) */
}

static inline void vl_api_map_param_set_icmp6_reply_t_endian (vl_api_map_param_set_icmp6_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_map_param_add_del_pre_resolve_t_endian (vl_api_map_param_add_del_pre_resolve_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_ip4_address_t_endian(&a->ip4_nh_address, to_net);
    vl_api_ip6_address_t_endian(&a->ip6_nh_address, to_net);
}

static inline void vl_api_map_param_add_del_pre_resolve_reply_t_endian (vl_api_map_param_add_del_pre_resolve_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_map_param_set_security_check_t_endian (vl_api_map_param_set_security_check_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->enable = a->enable (no-op) */
    /* a->fragments = a->fragments (no-op) */
}

static inline void vl_api_map_param_set_security_check_reply_t_endian (vl_api_map_param_set_security_check_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_map_param_set_traffic_class_t_endian (vl_api_map_param_set_traffic_class_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->copy = a->copy (no-op) */
    /* a->tc_class = a->tc_class (no-op) */
}

static inline void vl_api_map_param_set_traffic_class_reply_t_endian (vl_api_map_param_set_traffic_class_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_map_param_set_tcp_t_endian (vl_api_map_param_set_tcp_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->tcp_mss = clib_net_to_host_u16(a->tcp_mss);
}

static inline void vl_api_map_param_set_tcp_reply_t_endian (vl_api_map_param_set_tcp_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_map_param_get_t_endian (vl_api_map_param_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_map_param_get_reply_t_endian (vl_api_map_param_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->frag_inner = a->frag_inner (no-op) */
    /* a->frag_ignore_df = a->frag_ignore_df (no-op) */
    vl_api_ip4_address_t_endian(&a->icmp_ip4_err_relay_src, to_net);
    /* a->icmp6_enable_unreachable = a->icmp6_enable_unreachable (no-op) */
    vl_api_ip4_address_t_endian(&a->ip4_nh_address, to_net);
    vl_api_ip6_address_t_endian(&a->ip6_nh_address, to_net);
    a->ip4_lifetime_ms = clib_net_to_host_u16(a->ip4_lifetime_ms);
    a->ip4_pool_size = clib_net_to_host_u16(a->ip4_pool_size);
    a->ip4_buffers = clib_net_to_host_u32(a->ip4_buffers);
    a->ip4_ht_ratio = clib_net_to_host_f64(a->ip4_ht_ratio);
    /* a->sec_check_enable = a->sec_check_enable (no-op) */
    /* a->sec_check_fragments = a->sec_check_fragments (no-op) */
    /* a->tc_copy = a->tc_copy (no-op) */
    /* a->tc_class = a->tc_class (no-op) */
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_map_calcsizefun
#define included_map_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_map_add_domain_t_calc_size (vl_api_map_add_domain_t *a)
{
      return sizeof(*a) - sizeof(a->ip6_prefix) + vl_api_ip6_prefix_t_calc_size(&a->ip6_prefix) - sizeof(a->ip4_prefix) + vl_api_ip4_prefix_t_calc_size(&a->ip4_prefix) - sizeof(a->ip6_src) + vl_api_ip6_prefix_t_calc_size(&a->ip6_src);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_add_domain_reply_t_calc_size (vl_api_map_add_domain_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_del_domain_t_calc_size (vl_api_map_del_domain_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_del_domain_reply_t_calc_size (vl_api_map_del_domain_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_add_del_rule_t_calc_size (vl_api_map_add_del_rule_t *a)
{
      return sizeof(*a) - sizeof(a->ip6_dst) + vl_api_ip6_address_t_calc_size(&a->ip6_dst);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_add_del_rule_reply_t_calc_size (vl_api_map_add_del_rule_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_domains_get_t_calc_size (vl_api_map_domains_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_domains_get_reply_t_calc_size (vl_api_map_domains_get_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_domain_dump_t_calc_size (vl_api_map_domain_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_domain_details_t_calc_size (vl_api_map_domain_details_t *a)
{
      return sizeof(*a) - sizeof(a->ip6_prefix) + vl_api_ip6_prefix_t_calc_size(&a->ip6_prefix) - sizeof(a->ip4_prefix) + vl_api_ip4_prefix_t_calc_size(&a->ip4_prefix) - sizeof(a->ip6_src) + vl_api_ip6_prefix_t_calc_size(&a->ip6_src);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_rule_dump_t_calc_size (vl_api_map_rule_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_rule_details_t_calc_size (vl_api_map_rule_details_t *a)
{
      return sizeof(*a) - sizeof(a->ip6_dst) + vl_api_ip6_address_t_calc_size(&a->ip6_dst);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_if_enable_disable_t_calc_size (vl_api_map_if_enable_disable_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_if_enable_disable_reply_t_calc_size (vl_api_map_if_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_summary_stats_t_calc_size (vl_api_map_summary_stats_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_summary_stats_reply_t_calc_size (vl_api_map_summary_stats_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_param_set_fragmentation_t_calc_size (vl_api_map_param_set_fragmentation_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_param_set_fragmentation_reply_t_calc_size (vl_api_map_param_set_fragmentation_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_param_set_icmp_t_calc_size (vl_api_map_param_set_icmp_t *a)
{
      return sizeof(*a) - sizeof(a->ip4_err_relay_src) + vl_api_ip4_address_t_calc_size(&a->ip4_err_relay_src);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_param_set_icmp_reply_t_calc_size (vl_api_map_param_set_icmp_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_param_set_icmp6_t_calc_size (vl_api_map_param_set_icmp6_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_param_set_icmp6_reply_t_calc_size (vl_api_map_param_set_icmp6_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_param_add_del_pre_resolve_t_calc_size (vl_api_map_param_add_del_pre_resolve_t *a)
{
      return sizeof(*a) - sizeof(a->ip4_nh_address) + vl_api_ip4_address_t_calc_size(&a->ip4_nh_address) - sizeof(a->ip6_nh_address) + vl_api_ip6_address_t_calc_size(&a->ip6_nh_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_param_add_del_pre_resolve_reply_t_calc_size (vl_api_map_param_add_del_pre_resolve_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_param_set_security_check_t_calc_size (vl_api_map_param_set_security_check_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_param_set_security_check_reply_t_calc_size (vl_api_map_param_set_security_check_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_param_set_traffic_class_t_calc_size (vl_api_map_param_set_traffic_class_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_param_set_traffic_class_reply_t_calc_size (vl_api_map_param_set_traffic_class_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_param_set_tcp_t_calc_size (vl_api_map_param_set_tcp_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_param_set_tcp_reply_t_calc_size (vl_api_map_param_set_tcp_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_param_get_t_calc_size (vl_api_map_param_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_map_param_get_reply_t_calc_size (vl_api_map_param_get_reply_t *a)
{
      return sizeof(*a) - sizeof(a->icmp_ip4_err_relay_src) + vl_api_ip4_address_t_calc_size(&a->icmp_ip4_err_relay_src) - sizeof(a->ip4_nh_address) + vl_api_ip4_address_t_calc_size(&a->ip4_nh_address) - sizeof(a->ip6_nh_address) + vl_api_ip6_address_t_calc_size(&a->ip6_nh_address);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(map.api, 4, 2, 1)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(map.api, 0x8bf7a18a)

#endif

