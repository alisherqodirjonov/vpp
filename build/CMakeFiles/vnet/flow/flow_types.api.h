/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: flow_types.api
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
#warning no content included from flow_types.api
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
#include <vnet/ethernet/ethernet_types.api.h>
#include <vnet/ip/ip_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
#endif
/****** Message names ******/

#ifdef vl_msg_name
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_flow_types 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "flow_types.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_flow_types_printfun_types
#define included_flow_types_printfun_types

static inline u8 *format_vl_api_flow_type_t (u8 *s, va_list * args)
{
    vl_api_flow_type_t *a = va_arg (*args, vl_api_flow_type_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "FLOW_TYPE_ETHERNET");
    case 2:
        return format(s, "FLOW_TYPE_IP4");
    case 3:
        return format(s, "FLOW_TYPE_IP6");
    case 4:
        return format(s, "FLOW_TYPE_IP4_L2TPV3OIP");
    case 5:
        return format(s, "FLOW_TYPE_IP4_IPSEC_ESP");
    case 6:
        return format(s, "FLOW_TYPE_IP4_IPSEC_AH");
    case 7:
        return format(s, "FLOW_TYPE_IP4_N_TUPLE");
    case 8:
        return format(s, "FLOW_TYPE_IP6_N_TUPLE");
    case 9:
        return format(s, "FLOW_TYPE_IP4_N_TUPLE_TAGGED");
    case 10:
        return format(s, "FLOW_TYPE_IP6_N_TUPLE_TAGGED");
    case 11:
        return format(s, "FLOW_TYPE_IP4_VXLAN");
    case 12:
        return format(s, "FLOW_TYPE_IP6_VXLAN");
    case 13:
        return format(s, "FLOW_TYPE_IP4_GTPC");
    case 14:
        return format(s, "FLOW_TYPE_IP4_GTPU");
    }
    return s;
}

static inline u8 *format_vl_api_flow_type_v2_t (u8 *s, va_list * args)
{
    vl_api_flow_type_v2_t *a = va_arg (*args, vl_api_flow_type_v2_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "FLOW_TYPE_ETHERNET_V2");
    case 2:
        return format(s, "FLOW_TYPE_IP4_V2");
    case 3:
        return format(s, "FLOW_TYPE_IP6_V2");
    case 4:
        return format(s, "FLOW_TYPE_IP4_L2TPV3OIP_V2");
    case 5:
        return format(s, "FLOW_TYPE_IP4_IPSEC_ESP_V2");
    case 6:
        return format(s, "FLOW_TYPE_IP4_IPSEC_AH_V2");
    case 7:
        return format(s, "FLOW_TYPE_IP4_N_TUPLE_V2");
    case 8:
        return format(s, "FLOW_TYPE_IP6_N_TUPLE_V2");
    case 9:
        return format(s, "FLOW_TYPE_IP4_N_TUPLE_TAGGED_V2");
    case 10:
        return format(s, "FLOW_TYPE_IP6_N_TUPLE_TAGGED_V2");
    case 11:
        return format(s, "FLOW_TYPE_IP4_VXLAN_V2");
    case 12:
        return format(s, "FLOW_TYPE_IP6_VXLAN_V2");
    case 13:
        return format(s, "FLOW_TYPE_IP4_GTPC_V2");
    case 14:
        return format(s, "FLOW_TYPE_IP4_GTPU_V2");
    case 15:
        return format(s, "FLOW_TYPE_GENERIC_V2");
    }
    return s;
}

static inline u8 *format_vl_api_flow_action_t (u8 *s, va_list * args)
{
    vl_api_flow_action_t *a = va_arg (*args, vl_api_flow_action_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "FLOW_ACTION_COUNT");
    case 2:
        return format(s, "FLOW_ACTION_MARK");
    case 4:
        return format(s, "FLOW_ACTION_BUFFER_ADVANCE");
    case 8:
        return format(s, "FLOW_ACTION_REDIRECT_TO_NODE");
    case 16:
        return format(s, "FLOW_ACTION_REDIRECT_TO_QUEUE");
    case 64:
        return format(s, "FLOW_ACTION_DROP");
    }
    return s;
}

static inline u8 *format_vl_api_flow_action_v2_t (u8 *s, va_list * args)
{
    vl_api_flow_action_v2_t *a = va_arg (*args, vl_api_flow_action_v2_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "FLOW_ACTION_COUNT_V2");
    case 2:
        return format(s, "FLOW_ACTION_MARK_V2");
    case 4:
        return format(s, "FLOW_ACTION_BUFFER_ADVANCE_V2");
    case 8:
        return format(s, "FLOW_ACTION_REDIRECT_TO_NODE_V2");
    case 16:
        return format(s, "FLOW_ACTION_REDIRECT_TO_QUEUE_V2");
    case 32:
        return format(s, "FLOW_ACTION_RSS_V2");
    case 64:
        return format(s, "FLOW_ACTION_DROP_V2");
    }
    return s;
}

static inline u8 *format_vl_api_rss_function_t (u8 *s, va_list * args)
{
    vl_api_rss_function_t *a = va_arg (*args, vl_api_rss_function_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "RSS_FUNC_DEFAULT");
    case 1:
        return format(s, "RSS_FUNC_TOEPLITZ");
    case 2:
        return format(s, "RSS_FUNC_SIMPLE_XOR");
    case 3:
        return format(s, "RSS_FUNC_SYMMETRIC_TOEPLITZ");
    }
    return s;
}

static inline u8 *format_vl_api_generic_pattern_t (u8 *s, va_list * args)
{
    vl_api_generic_pattern_t *a = va_arg (*args, vl_api_generic_pattern_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uspec: %U", format_white_space, indent, format_hex_bytes, a, 1024);
    s = format(s, "\n%Umask: %U", format_white_space, indent, format_hex_bytes, a, 1024);
    return s;
}

static inline u8 *format_vl_api_ip_port_and_mask_t (u8 *s, va_list * args)
{
    vl_api_ip_port_and_mask_t *a = va_arg (*args, vl_api_ip_port_and_mask_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    s = format(s, "\n%Umask: %u", format_white_space, indent, a->mask);
    return s;
}

static inline u8 *format_vl_api_ip_prot_and_mask_t (u8 *s, va_list * args)
{
    vl_api_ip_prot_and_mask_t *a = va_arg (*args, vl_api_ip_prot_and_mask_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uprot: %U", format_white_space, indent, format_vl_api_ip_proto_t, &a->prot, indent);
    s = format(s, "\n%Umask: %u", format_white_space, indent, a->mask);
    return s;
}

static inline u8 *format_vl_api_flow_ethernet_t (u8 *s, va_list * args)
{
    vl_api_flow_ethernet_t *a = va_arg (*args, vl_api_flow_ethernet_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ufoo: %ld", format_white_space, indent, a->foo);
    s = format(s, "\n%Usrc_addr: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->src_addr, indent);
    s = format(s, "\n%Udst_addr: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->dst_addr, indent);
    s = format(s, "\n%Utype: %u", format_white_space, indent, a->type);
    return s;
}

static inline u8 *format_vl_api_flow_ip4_t (u8 *s, va_list * args)
{
    vl_api_flow_ip4_t *a = va_arg (*args, vl_api_flow_ip4_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ufoo: %ld", format_white_space, indent, a->foo);
    s = format(s, "\n%Usrc_addr: %U", format_white_space, indent, format_vl_api_ip4_address_and_mask_t, &a->src_addr, indent);
    s = format(s, "\n%Udst_addr: %U", format_white_space, indent, format_vl_api_ip4_address_and_mask_t, &a->dst_addr, indent);
    s = format(s, "\n%Uprotocol: %U", format_white_space, indent, format_vl_api_ip_prot_and_mask_t, &a->protocol, indent);
    return s;
}

static inline u8 *format_vl_api_flow_ip6_t (u8 *s, va_list * args)
{
    vl_api_flow_ip6_t *a = va_arg (*args, vl_api_flow_ip6_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ufoo: %ld", format_white_space, indent, a->foo);
    s = format(s, "\n%Usrc_addr: %U", format_white_space, indent, format_vl_api_ip6_address_and_mask_t, &a->src_addr, indent);
    s = format(s, "\n%Udst_addr: %U", format_white_space, indent, format_vl_api_ip6_address_and_mask_t, &a->dst_addr, indent);
    s = format(s, "\n%Uprotocol: %U", format_white_space, indent, format_vl_api_ip_prot_and_mask_t, &a->protocol, indent);
    return s;
}

static inline u8 *format_vl_api_flow_ip4_n_tuple_t (u8 *s, va_list * args)
{
    vl_api_flow_ip4_n_tuple_t *a = va_arg (*args, vl_api_flow_ip4_n_tuple_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ufoo: %ld", format_white_space, indent, a->foo);
    s = format(s, "\n%Usrc_addr: %U", format_white_space, indent, format_vl_api_ip4_address_and_mask_t, &a->src_addr, indent);
    s = format(s, "\n%Udst_addr: %U", format_white_space, indent, format_vl_api_ip4_address_and_mask_t, &a->dst_addr, indent);
    s = format(s, "\n%Uprotocol: %U", format_white_space, indent, format_vl_api_ip_prot_and_mask_t, &a->protocol, indent);
    s = format(s, "\n%Usrc_port: %U", format_white_space, indent, format_vl_api_ip_port_and_mask_t, &a->src_port, indent);
    s = format(s, "\n%Udst_port: %U", format_white_space, indent, format_vl_api_ip_port_and_mask_t, &a->dst_port, indent);
    return s;
}

static inline u8 *format_vl_api_flow_ip6_n_tuple_t (u8 *s, va_list * args)
{
    vl_api_flow_ip6_n_tuple_t *a = va_arg (*args, vl_api_flow_ip6_n_tuple_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ufoo: %ld", format_white_space, indent, a->foo);
    s = format(s, "\n%Usrc_addr: %U", format_white_space, indent, format_vl_api_ip6_address_and_mask_t, &a->src_addr, indent);
    s = format(s, "\n%Udst_addr: %U", format_white_space, indent, format_vl_api_ip6_address_and_mask_t, &a->dst_addr, indent);
    s = format(s, "\n%Uprotocol: %U", format_white_space, indent, format_vl_api_ip_prot_and_mask_t, &a->protocol, indent);
    s = format(s, "\n%Usrc_port: %U", format_white_space, indent, format_vl_api_ip_port_and_mask_t, &a->src_port, indent);
    s = format(s, "\n%Udst_port: %U", format_white_space, indent, format_vl_api_ip_port_and_mask_t, &a->dst_port, indent);
    return s;
}

static inline u8 *format_vl_api_flow_ip4_n_tuple_tagged_t (u8 *s, va_list * args)
{
    vl_api_flow_ip4_n_tuple_tagged_t *a = va_arg (*args, vl_api_flow_ip4_n_tuple_tagged_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ufoo: %ld", format_white_space, indent, a->foo);
    s = format(s, "\n%Usrc_addr: %U", format_white_space, indent, format_vl_api_ip4_address_and_mask_t, &a->src_addr, indent);
    s = format(s, "\n%Udst_addr: %U", format_white_space, indent, format_vl_api_ip4_address_and_mask_t, &a->dst_addr, indent);
    s = format(s, "\n%Uprotocol: %U", format_white_space, indent, format_vl_api_ip_prot_and_mask_t, &a->protocol, indent);
    s = format(s, "\n%Usrc_port: %U", format_white_space, indent, format_vl_api_ip_port_and_mask_t, &a->src_port, indent);
    s = format(s, "\n%Udst_port: %U", format_white_space, indent, format_vl_api_ip_port_and_mask_t, &a->dst_port, indent);
    return s;
}

static inline u8 *format_vl_api_flow_ip6_n_tuple_tagged_t (u8 *s, va_list * args)
{
    vl_api_flow_ip6_n_tuple_tagged_t *a = va_arg (*args, vl_api_flow_ip6_n_tuple_tagged_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ufoo: %ld", format_white_space, indent, a->foo);
    s = format(s, "\n%Usrc_addr: %U", format_white_space, indent, format_vl_api_ip6_address_and_mask_t, &a->src_addr, indent);
    s = format(s, "\n%Udst_addr: %U", format_white_space, indent, format_vl_api_ip6_address_and_mask_t, &a->dst_addr, indent);
    s = format(s, "\n%Uprotocol: %U", format_white_space, indent, format_vl_api_ip_prot_and_mask_t, &a->protocol, indent);
    s = format(s, "\n%Usrc_port: %U", format_white_space, indent, format_vl_api_ip_port_and_mask_t, &a->src_port, indent);
    s = format(s, "\n%Udst_port: %U", format_white_space, indent, format_vl_api_ip_port_and_mask_t, &a->dst_port, indent);
    return s;
}

static inline u8 *format_vl_api_flow_ip4_l2tpv3oip_t (u8 *s, va_list * args)
{
    vl_api_flow_ip4_l2tpv3oip_t *a = va_arg (*args, vl_api_flow_ip4_l2tpv3oip_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ufoo: %ld", format_white_space, indent, a->foo);
    s = format(s, "\n%Usrc_addr: %U", format_white_space, indent, format_vl_api_ip4_address_and_mask_t, &a->src_addr, indent);
    s = format(s, "\n%Udst_addr: %U", format_white_space, indent, format_vl_api_ip4_address_and_mask_t, &a->dst_addr, indent);
    s = format(s, "\n%Uprotocol: %U", format_white_space, indent, format_vl_api_ip_prot_and_mask_t, &a->protocol, indent);
    s = format(s, "\n%Usession_id: %u", format_white_space, indent, a->session_id);
    return s;
}

static inline u8 *format_vl_api_flow_ip4_ipsec_esp_t (u8 *s, va_list * args)
{
    vl_api_flow_ip4_ipsec_esp_t *a = va_arg (*args, vl_api_flow_ip4_ipsec_esp_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ufoo: %ld", format_white_space, indent, a->foo);
    s = format(s, "\n%Usrc_addr: %U", format_white_space, indent, format_vl_api_ip4_address_and_mask_t, &a->src_addr, indent);
    s = format(s, "\n%Udst_addr: %U", format_white_space, indent, format_vl_api_ip4_address_and_mask_t, &a->dst_addr, indent);
    s = format(s, "\n%Uprotocol: %U", format_white_space, indent, format_vl_api_ip_prot_and_mask_t, &a->protocol, indent);
    s = format(s, "\n%Uspi: %u", format_white_space, indent, a->spi);
    return s;
}

static inline u8 *format_vl_api_flow_ip4_ipsec_ah_t (u8 *s, va_list * args)
{
    vl_api_flow_ip4_ipsec_ah_t *a = va_arg (*args, vl_api_flow_ip4_ipsec_ah_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ufoo: %ld", format_white_space, indent, a->foo);
    s = format(s, "\n%Usrc_addr: %U", format_white_space, indent, format_vl_api_ip4_address_and_mask_t, &a->src_addr, indent);
    s = format(s, "\n%Udst_addr: %U", format_white_space, indent, format_vl_api_ip4_address_and_mask_t, &a->dst_addr, indent);
    s = format(s, "\n%Uprotocol: %U", format_white_space, indent, format_vl_api_ip_prot_and_mask_t, &a->protocol, indent);
    s = format(s, "\n%Uspi: %u", format_white_space, indent, a->spi);
    return s;
}

static inline u8 *format_vl_api_flow_ip4_vxlan_t (u8 *s, va_list * args)
{
    vl_api_flow_ip4_vxlan_t *a = va_arg (*args, vl_api_flow_ip4_vxlan_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ufoo: %ld", format_white_space, indent, a->foo);
    s = format(s, "\n%Usrc_addr: %U", format_white_space, indent, format_vl_api_ip4_address_and_mask_t, &a->src_addr, indent);
    s = format(s, "\n%Udst_addr: %U", format_white_space, indent, format_vl_api_ip4_address_and_mask_t, &a->dst_addr, indent);
    s = format(s, "\n%Uprotocol: %U", format_white_space, indent, format_vl_api_ip_prot_and_mask_t, &a->protocol, indent);
    s = format(s, "\n%Usrc_port: %U", format_white_space, indent, format_vl_api_ip_port_and_mask_t, &a->src_port, indent);
    s = format(s, "\n%Udst_port: %U", format_white_space, indent, format_vl_api_ip_port_and_mask_t, &a->dst_port, indent);
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    return s;
}

static inline u8 *format_vl_api_flow_ip6_vxlan_t (u8 *s, va_list * args)
{
    vl_api_flow_ip6_vxlan_t *a = va_arg (*args, vl_api_flow_ip6_vxlan_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ufoo: %ld", format_white_space, indent, a->foo);
    s = format(s, "\n%Usrc_addr: %U", format_white_space, indent, format_vl_api_ip6_address_and_mask_t, &a->src_addr, indent);
    s = format(s, "\n%Udst_addr: %U", format_white_space, indent, format_vl_api_ip6_address_and_mask_t, &a->dst_addr, indent);
    s = format(s, "\n%Uprotocol: %U", format_white_space, indent, format_vl_api_ip_prot_and_mask_t, &a->protocol, indent);
    s = format(s, "\n%Usrc_port: %U", format_white_space, indent, format_vl_api_ip_port_and_mask_t, &a->src_port, indent);
    s = format(s, "\n%Udst_port: %U", format_white_space, indent, format_vl_api_ip_port_and_mask_t, &a->dst_port, indent);
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    return s;
}

static inline u8 *format_vl_api_flow_ip4_gtpc_t (u8 *s, va_list * args)
{
    vl_api_flow_ip4_gtpc_t *a = va_arg (*args, vl_api_flow_ip4_gtpc_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ufoo: %ld", format_white_space, indent, a->foo);
    s = format(s, "\n%Usrc_addr: %U", format_white_space, indent, format_vl_api_ip4_address_and_mask_t, &a->src_addr, indent);
    s = format(s, "\n%Udst_addr: %U", format_white_space, indent, format_vl_api_ip4_address_and_mask_t, &a->dst_addr, indent);
    s = format(s, "\n%Uprotocol: %U", format_white_space, indent, format_vl_api_ip_prot_and_mask_t, &a->protocol, indent);
    s = format(s, "\n%Usrc_port: %U", format_white_space, indent, format_vl_api_ip_port_and_mask_t, &a->src_port, indent);
    s = format(s, "\n%Udst_port: %U", format_white_space, indent, format_vl_api_ip_port_and_mask_t, &a->dst_port, indent);
    s = format(s, "\n%Uteid: %u", format_white_space, indent, a->teid);
    return s;
}

static inline u8 *format_vl_api_flow_ip4_gtpu_t (u8 *s, va_list * args)
{
    vl_api_flow_ip4_gtpu_t *a = va_arg (*args, vl_api_flow_ip4_gtpu_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ufoo: %ld", format_white_space, indent, a->foo);
    s = format(s, "\n%Usrc_addr: %U", format_white_space, indent, format_vl_api_ip4_address_and_mask_t, &a->src_addr, indent);
    s = format(s, "\n%Udst_addr: %U", format_white_space, indent, format_vl_api_ip4_address_and_mask_t, &a->dst_addr, indent);
    s = format(s, "\n%Uprotocol: %U", format_white_space, indent, format_vl_api_ip_prot_and_mask_t, &a->protocol, indent);
    s = format(s, "\n%Usrc_port: %U", format_white_space, indent, format_vl_api_ip_port_and_mask_t, &a->src_port, indent);
    s = format(s, "\n%Udst_port: %U", format_white_space, indent, format_vl_api_ip_port_and_mask_t, &a->dst_port, indent);
    s = format(s, "\n%Uteid: %u", format_white_space, indent, a->teid);
    return s;
}

static inline u8 *format_vl_api_flow_generic_t (u8 *s, va_list * args)
{
    vl_api_flow_generic_t *a = va_arg (*args, vl_api_flow_generic_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ufoo: %ld", format_white_space, indent, a->foo);
    s = format(s, "\n%Upattern: %U", format_white_space, indent, format_vl_api_generic_pattern_t, &a->pattern, indent);
    return s;
}

static inline u8 *format_vl_api_flow_t (u8 *s, va_list * args)
{
    vl_api_flow_t *a = va_arg (*args, vl_api_flow_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uethernet: %U", format_white_space, indent, format_vl_api_flow_ethernet_t, &a->ethernet, indent);
    s = format(s, "\n%Uip4: %U", format_white_space, indent, format_vl_api_flow_ip4_t, &a->ip4, indent);
    s = format(s, "\n%Uip6: %U", format_white_space, indent, format_vl_api_flow_ip6_t, &a->ip6, indent);
    s = format(s, "\n%Uip4_l2tpv3oip: %U", format_white_space, indent, format_vl_api_flow_ip4_l2tpv3oip_t, &a->ip4_l2tpv3oip, indent);
    s = format(s, "\n%Uip4_ipsec_esp: %U", format_white_space, indent, format_vl_api_flow_ip4_ipsec_esp_t, &a->ip4_ipsec_esp, indent);
    s = format(s, "\n%Uip4_ipsec_ah: %U", format_white_space, indent, format_vl_api_flow_ip4_ipsec_ah_t, &a->ip4_ipsec_ah, indent);
    s = format(s, "\n%Uip4_n_tuple: %U", format_white_space, indent, format_vl_api_flow_ip4_n_tuple_t, &a->ip4_n_tuple, indent);
    s = format(s, "\n%Uip6_n_tuple: %U", format_white_space, indent, format_vl_api_flow_ip6_n_tuple_t, &a->ip6_n_tuple, indent);
    s = format(s, "\n%Uip4_n_tuple_tagged: %U", format_white_space, indent, format_vl_api_flow_ip4_n_tuple_tagged_t, &a->ip4_n_tuple_tagged, indent);
    s = format(s, "\n%Uip6_n_tuple_tagged: %U", format_white_space, indent, format_vl_api_flow_ip6_n_tuple_tagged_t, &a->ip6_n_tuple_tagged, indent);
    s = format(s, "\n%Uip4_vxlan: %U", format_white_space, indent, format_vl_api_flow_ip4_vxlan_t, &a->ip4_vxlan, indent);
    s = format(s, "\n%Uip6_vxlan: %U", format_white_space, indent, format_vl_api_flow_ip6_vxlan_t, &a->ip6_vxlan, indent);
    s = format(s, "\n%Uip4_gtpc: %U", format_white_space, indent, format_vl_api_flow_ip4_gtpc_t, &a->ip4_gtpc, indent);
    s = format(s, "\n%Uip4_gtpu: %U", format_white_space, indent, format_vl_api_flow_ip4_gtpu_t, &a->ip4_gtpu, indent);
    return s;
}

static inline u8 *format_vl_api_flow_v2_t (u8 *s, va_list * args)
{
    vl_api_flow_v2_t *a = va_arg (*args, vl_api_flow_v2_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uethernet: %U", format_white_space, indent, format_vl_api_flow_ethernet_t, &a->ethernet, indent);
    s = format(s, "\n%Uip4: %U", format_white_space, indent, format_vl_api_flow_ip4_t, &a->ip4, indent);
    s = format(s, "\n%Uip6: %U", format_white_space, indent, format_vl_api_flow_ip6_t, &a->ip6, indent);
    s = format(s, "\n%Uip4_l2tpv3oip: %U", format_white_space, indent, format_vl_api_flow_ip4_l2tpv3oip_t, &a->ip4_l2tpv3oip, indent);
    s = format(s, "\n%Uip4_ipsec_esp: %U", format_white_space, indent, format_vl_api_flow_ip4_ipsec_esp_t, &a->ip4_ipsec_esp, indent);
    s = format(s, "\n%Uip4_ipsec_ah: %U", format_white_space, indent, format_vl_api_flow_ip4_ipsec_ah_t, &a->ip4_ipsec_ah, indent);
    s = format(s, "\n%Uip4_n_tuple: %U", format_white_space, indent, format_vl_api_flow_ip4_n_tuple_t, &a->ip4_n_tuple, indent);
    s = format(s, "\n%Uip6_n_tuple: %U", format_white_space, indent, format_vl_api_flow_ip6_n_tuple_t, &a->ip6_n_tuple, indent);
    s = format(s, "\n%Uip4_n_tuple_tagged: %U", format_white_space, indent, format_vl_api_flow_ip4_n_tuple_tagged_t, &a->ip4_n_tuple_tagged, indent);
    s = format(s, "\n%Uip6_n_tuple_tagged: %U", format_white_space, indent, format_vl_api_flow_ip6_n_tuple_tagged_t, &a->ip6_n_tuple_tagged, indent);
    s = format(s, "\n%Uip4_vxlan: %U", format_white_space, indent, format_vl_api_flow_ip4_vxlan_t, &a->ip4_vxlan, indent);
    s = format(s, "\n%Uip6_vxlan: %U", format_white_space, indent, format_vl_api_flow_ip6_vxlan_t, &a->ip6_vxlan, indent);
    s = format(s, "\n%Uip4_gtpc: %U", format_white_space, indent, format_vl_api_flow_ip4_gtpc_t, &a->ip4_gtpc, indent);
    s = format(s, "\n%Uip4_gtpu: %U", format_white_space, indent, format_vl_api_flow_ip4_gtpu_t, &a->ip4_gtpu, indent);
    s = format(s, "\n%Ugeneric: %U", format_white_space, indent, format_vl_api_flow_generic_t, &a->generic, indent);
    return s;
}

static inline u8 *format_vl_api_flow_rule_t (u8 *s, va_list * args)
{
    vl_api_flow_rule_t *a = va_arg (*args, vl_api_flow_rule_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Utype: %U", format_white_space, indent, format_vl_api_flow_type_t, &a->type, indent);
    s = format(s, "\n%Uindex: %u", format_white_space, indent, a->index);
    s = format(s, "\n%Uactions: %U", format_white_space, indent, format_vl_api_flow_action_t, &a->actions, indent);
    s = format(s, "\n%Umark_flow_id: %u", format_white_space, indent, a->mark_flow_id);
    s = format(s, "\n%Uredirect_node_index: %u", format_white_space, indent, a->redirect_node_index);
    s = format(s, "\n%Uredirect_device_input_next_index: %u", format_white_space, indent, a->redirect_device_input_next_index);
    s = format(s, "\n%Uredirect_queue: %u", format_white_space, indent, a->redirect_queue);
    s = format(s, "\n%Ubuffer_advance: %ld", format_white_space, indent, a->buffer_advance);
    s = format(s, "\n%Uflow: %U", format_white_space, indent, format_vl_api_flow_t, &a->flow, indent);
    return s;
}

static inline u8 *format_vl_api_flow_rule_v2_t (u8 *s, va_list * args)
{
    vl_api_flow_rule_v2_t *a = va_arg (*args, vl_api_flow_rule_v2_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Utype: %U", format_white_space, indent, format_vl_api_flow_type_v2_t, &a->type, indent);
    s = format(s, "\n%Uindex: %u", format_white_space, indent, a->index);
    s = format(s, "\n%Uactions: %U", format_white_space, indent, format_vl_api_flow_action_v2_t, &a->actions, indent);
    s = format(s, "\n%Umark_flow_id: %u", format_white_space, indent, a->mark_flow_id);
    s = format(s, "\n%Uredirect_node_index: %u", format_white_space, indent, a->redirect_node_index);
    s = format(s, "\n%Uredirect_device_input_next_index: %u", format_white_space, indent, a->redirect_device_input_next_index);
    s = format(s, "\n%Uredirect_queue: %u", format_white_space, indent, a->redirect_queue);
    s = format(s, "\n%Uqueue_index: %u", format_white_space, indent, a->queue_index);
    s = format(s, "\n%Uqueue_num: %u", format_white_space, indent, a->queue_num);
    s = format(s, "\n%Ubuffer_advance: %ld", format_white_space, indent, a->buffer_advance);
    s = format(s, "\n%Urss_types: %llu", format_white_space, indent, a->rss_types);
    s = format(s, "\n%Urss_fun: %U", format_white_space, indent, format_vl_api_rss_function_t, &a->rss_fun, indent);
    s = format(s, "\n%Uflow: %U", format_white_space, indent, format_vl_api_flow_v2_t, &a->flow, indent);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_flow_types_printfun
#define included_flow_types_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "flow_types.api_tojson.h"
#include "flow_types.api_fromjson.h"


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_flow_types_endianfun
#define included_flow_types_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_flow_type_t_endian (vl_api_flow_type_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_flow_type_v2_t_endian (vl_api_flow_type_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_flow_action_t_endian (vl_api_flow_action_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_flow_action_v2_t_endian (vl_api_flow_action_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_rss_function_t_endian (vl_api_rss_function_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_generic_pattern_t_endian (vl_api_generic_pattern_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->spec = a->spec (no-op) */
    /* a->mask = a->mask (no-op) */
}

static inline void vl_api_ip_port_and_mask_t_endian (vl_api_ip_port_and_mask_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->port = clib_net_to_host_u16(a->port);
    a->mask = clib_net_to_host_u16(a->mask);
}

static inline void vl_api_ip_prot_and_mask_t_endian (vl_api_ip_prot_and_mask_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_ip_proto_t_endian(&a->prot, to_net);
    /* a->mask = a->mask (no-op) */
}

static inline void vl_api_flow_ethernet_t_endian (vl_api_flow_ethernet_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->foo = clib_net_to_host_i32(a->foo);
    vl_api_mac_address_t_endian(&a->src_addr, to_net);
    vl_api_mac_address_t_endian(&a->dst_addr, to_net);
    a->type = clib_net_to_host_u16(a->type);
}

static inline void vl_api_flow_ip4_t_endian (vl_api_flow_ip4_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->foo = clib_net_to_host_i32(a->foo);
    vl_api_ip4_address_and_mask_t_endian(&a->src_addr, to_net);
    vl_api_ip4_address_and_mask_t_endian(&a->dst_addr, to_net);
    vl_api_ip_prot_and_mask_t_endian(&a->protocol, to_net);
}

static inline void vl_api_flow_ip6_t_endian (vl_api_flow_ip6_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->foo = clib_net_to_host_i32(a->foo);
    vl_api_ip6_address_and_mask_t_endian(&a->src_addr, to_net);
    vl_api_ip6_address_and_mask_t_endian(&a->dst_addr, to_net);
    vl_api_ip_prot_and_mask_t_endian(&a->protocol, to_net);
}

static inline void vl_api_flow_ip4_n_tuple_t_endian (vl_api_flow_ip4_n_tuple_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->foo = clib_net_to_host_i32(a->foo);
    vl_api_ip4_address_and_mask_t_endian(&a->src_addr, to_net);
    vl_api_ip4_address_and_mask_t_endian(&a->dst_addr, to_net);
    vl_api_ip_prot_and_mask_t_endian(&a->protocol, to_net);
    vl_api_ip_port_and_mask_t_endian(&a->src_port, to_net);
    vl_api_ip_port_and_mask_t_endian(&a->dst_port, to_net);
}

static inline void vl_api_flow_ip6_n_tuple_t_endian (vl_api_flow_ip6_n_tuple_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->foo = clib_net_to_host_i32(a->foo);
    vl_api_ip6_address_and_mask_t_endian(&a->src_addr, to_net);
    vl_api_ip6_address_and_mask_t_endian(&a->dst_addr, to_net);
    vl_api_ip_prot_and_mask_t_endian(&a->protocol, to_net);
    vl_api_ip_port_and_mask_t_endian(&a->src_port, to_net);
    vl_api_ip_port_and_mask_t_endian(&a->dst_port, to_net);
}

static inline void vl_api_flow_ip4_n_tuple_tagged_t_endian (vl_api_flow_ip4_n_tuple_tagged_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->foo = clib_net_to_host_i32(a->foo);
    vl_api_ip4_address_and_mask_t_endian(&a->src_addr, to_net);
    vl_api_ip4_address_and_mask_t_endian(&a->dst_addr, to_net);
    vl_api_ip_prot_and_mask_t_endian(&a->protocol, to_net);
    vl_api_ip_port_and_mask_t_endian(&a->src_port, to_net);
    vl_api_ip_port_and_mask_t_endian(&a->dst_port, to_net);
}

static inline void vl_api_flow_ip6_n_tuple_tagged_t_endian (vl_api_flow_ip6_n_tuple_tagged_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->foo = clib_net_to_host_i32(a->foo);
    vl_api_ip6_address_and_mask_t_endian(&a->src_addr, to_net);
    vl_api_ip6_address_and_mask_t_endian(&a->dst_addr, to_net);
    vl_api_ip_prot_and_mask_t_endian(&a->protocol, to_net);
    vl_api_ip_port_and_mask_t_endian(&a->src_port, to_net);
    vl_api_ip_port_and_mask_t_endian(&a->dst_port, to_net);
}

static inline void vl_api_flow_ip4_l2tpv3oip_t_endian (vl_api_flow_ip4_l2tpv3oip_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->foo = clib_net_to_host_i32(a->foo);
    vl_api_ip4_address_and_mask_t_endian(&a->src_addr, to_net);
    vl_api_ip4_address_and_mask_t_endian(&a->dst_addr, to_net);
    vl_api_ip_prot_and_mask_t_endian(&a->protocol, to_net);
    a->session_id = clib_net_to_host_u32(a->session_id);
}

static inline void vl_api_flow_ip4_ipsec_esp_t_endian (vl_api_flow_ip4_ipsec_esp_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->foo = clib_net_to_host_i32(a->foo);
    vl_api_ip4_address_and_mask_t_endian(&a->src_addr, to_net);
    vl_api_ip4_address_and_mask_t_endian(&a->dst_addr, to_net);
    vl_api_ip_prot_and_mask_t_endian(&a->protocol, to_net);
    a->spi = clib_net_to_host_u32(a->spi);
}

static inline void vl_api_flow_ip4_ipsec_ah_t_endian (vl_api_flow_ip4_ipsec_ah_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->foo = clib_net_to_host_i32(a->foo);
    vl_api_ip4_address_and_mask_t_endian(&a->src_addr, to_net);
    vl_api_ip4_address_and_mask_t_endian(&a->dst_addr, to_net);
    vl_api_ip_prot_and_mask_t_endian(&a->protocol, to_net);
    a->spi = clib_net_to_host_u32(a->spi);
}

static inline void vl_api_flow_ip4_vxlan_t_endian (vl_api_flow_ip4_vxlan_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->foo = clib_net_to_host_i32(a->foo);
    vl_api_ip4_address_and_mask_t_endian(&a->src_addr, to_net);
    vl_api_ip4_address_and_mask_t_endian(&a->dst_addr, to_net);
    vl_api_ip_prot_and_mask_t_endian(&a->protocol, to_net);
    vl_api_ip_port_and_mask_t_endian(&a->src_port, to_net);
    vl_api_ip_port_and_mask_t_endian(&a->dst_port, to_net);
    a->vni = clib_net_to_host_u32(a->vni);
}

static inline void vl_api_flow_ip6_vxlan_t_endian (vl_api_flow_ip6_vxlan_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->foo = clib_net_to_host_i32(a->foo);
    vl_api_ip6_address_and_mask_t_endian(&a->src_addr, to_net);
    vl_api_ip6_address_and_mask_t_endian(&a->dst_addr, to_net);
    vl_api_ip_prot_and_mask_t_endian(&a->protocol, to_net);
    vl_api_ip_port_and_mask_t_endian(&a->src_port, to_net);
    vl_api_ip_port_and_mask_t_endian(&a->dst_port, to_net);
    a->vni = clib_net_to_host_u32(a->vni);
}

static inline void vl_api_flow_ip4_gtpc_t_endian (vl_api_flow_ip4_gtpc_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->foo = clib_net_to_host_i32(a->foo);
    vl_api_ip4_address_and_mask_t_endian(&a->src_addr, to_net);
    vl_api_ip4_address_and_mask_t_endian(&a->dst_addr, to_net);
    vl_api_ip_prot_and_mask_t_endian(&a->protocol, to_net);
    vl_api_ip_port_and_mask_t_endian(&a->src_port, to_net);
    vl_api_ip_port_and_mask_t_endian(&a->dst_port, to_net);
    a->teid = clib_net_to_host_u32(a->teid);
}

static inline void vl_api_flow_ip4_gtpu_t_endian (vl_api_flow_ip4_gtpu_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->foo = clib_net_to_host_i32(a->foo);
    vl_api_ip4_address_and_mask_t_endian(&a->src_addr, to_net);
    vl_api_ip4_address_and_mask_t_endian(&a->dst_addr, to_net);
    vl_api_ip_prot_and_mask_t_endian(&a->protocol, to_net);
    vl_api_ip_port_and_mask_t_endian(&a->src_port, to_net);
    vl_api_ip_port_and_mask_t_endian(&a->dst_port, to_net);
    a->teid = clib_net_to_host_u32(a->teid);
}

static inline void vl_api_flow_generic_t_endian (vl_api_flow_generic_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->foo = clib_net_to_host_i32(a->foo);
    vl_api_generic_pattern_t_endian(&a->pattern, to_net);
}

static inline void vl_api_flow_t_endian (vl_api_flow_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_flow_ethernet_t_endian(&a->ethernet, to_net);
    vl_api_flow_ip4_t_endian(&a->ip4, to_net);
    vl_api_flow_ip6_t_endian(&a->ip6, to_net);
    vl_api_flow_ip4_l2tpv3oip_t_endian(&a->ip4_l2tpv3oip, to_net);
    vl_api_flow_ip4_ipsec_esp_t_endian(&a->ip4_ipsec_esp, to_net);
    vl_api_flow_ip4_ipsec_ah_t_endian(&a->ip4_ipsec_ah, to_net);
    vl_api_flow_ip4_n_tuple_t_endian(&a->ip4_n_tuple, to_net);
    vl_api_flow_ip6_n_tuple_t_endian(&a->ip6_n_tuple, to_net);
    vl_api_flow_ip4_n_tuple_tagged_t_endian(&a->ip4_n_tuple_tagged, to_net);
    vl_api_flow_ip6_n_tuple_tagged_t_endian(&a->ip6_n_tuple_tagged, to_net);
    vl_api_flow_ip4_vxlan_t_endian(&a->ip4_vxlan, to_net);
    vl_api_flow_ip6_vxlan_t_endian(&a->ip6_vxlan, to_net);
    vl_api_flow_ip4_gtpc_t_endian(&a->ip4_gtpc, to_net);
    vl_api_flow_ip4_gtpu_t_endian(&a->ip4_gtpu, to_net);
}

static inline void vl_api_flow_v2_t_endian (vl_api_flow_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_flow_ethernet_t_endian(&a->ethernet, to_net);
    vl_api_flow_ip4_t_endian(&a->ip4, to_net);
    vl_api_flow_ip6_t_endian(&a->ip6, to_net);
    vl_api_flow_ip4_l2tpv3oip_t_endian(&a->ip4_l2tpv3oip, to_net);
    vl_api_flow_ip4_ipsec_esp_t_endian(&a->ip4_ipsec_esp, to_net);
    vl_api_flow_ip4_ipsec_ah_t_endian(&a->ip4_ipsec_ah, to_net);
    vl_api_flow_ip4_n_tuple_t_endian(&a->ip4_n_tuple, to_net);
    vl_api_flow_ip6_n_tuple_t_endian(&a->ip6_n_tuple, to_net);
    vl_api_flow_ip4_n_tuple_tagged_t_endian(&a->ip4_n_tuple_tagged, to_net);
    vl_api_flow_ip6_n_tuple_tagged_t_endian(&a->ip6_n_tuple_tagged, to_net);
    vl_api_flow_ip4_vxlan_t_endian(&a->ip4_vxlan, to_net);
    vl_api_flow_ip6_vxlan_t_endian(&a->ip6_vxlan, to_net);
    vl_api_flow_ip4_gtpc_t_endian(&a->ip4_gtpc, to_net);
    vl_api_flow_ip4_gtpu_t_endian(&a->ip4_gtpu, to_net);
    vl_api_flow_generic_t_endian(&a->generic, to_net);
}

static inline void vl_api_flow_rule_t_endian (vl_api_flow_rule_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_flow_type_t_endian(&a->type, to_net);
    a->index = clib_net_to_host_u32(a->index);
    vl_api_flow_action_t_endian(&a->actions, to_net);
    a->mark_flow_id = clib_net_to_host_u32(a->mark_flow_id);
    a->redirect_node_index = clib_net_to_host_u32(a->redirect_node_index);
    a->redirect_device_input_next_index = clib_net_to_host_u32(a->redirect_device_input_next_index);
    a->redirect_queue = clib_net_to_host_u32(a->redirect_queue);
    a->buffer_advance = clib_net_to_host_i32(a->buffer_advance);
    vl_api_flow_t_endian(&a->flow, to_net);
}

static inline void vl_api_flow_rule_v2_t_endian (vl_api_flow_rule_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_flow_type_v2_t_endian(&a->type, to_net);
    a->index = clib_net_to_host_u32(a->index);
    vl_api_flow_action_v2_t_endian(&a->actions, to_net);
    a->mark_flow_id = clib_net_to_host_u32(a->mark_flow_id);
    a->redirect_node_index = clib_net_to_host_u32(a->redirect_node_index);
    a->redirect_device_input_next_index = clib_net_to_host_u32(a->redirect_device_input_next_index);
    a->redirect_queue = clib_net_to_host_u32(a->redirect_queue);
    a->queue_index = clib_net_to_host_u32(a->queue_index);
    a->queue_num = clib_net_to_host_u32(a->queue_num);
    a->buffer_advance = clib_net_to_host_i32(a->buffer_advance);
    a->rss_types = clib_net_to_host_u64(a->rss_types);
    vl_api_rss_function_t_endian(&a->rss_fun, to_net);
    vl_api_flow_v2_t_endian(&a->flow, to_net);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_flow_types_calcsizefun
#define included_flow_types_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_type_t_calc_size (vl_api_flow_type_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_type_v2_t_calc_size (vl_api_flow_type_v2_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_action_t_calc_size (vl_api_flow_action_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_action_v2_t_calc_size (vl_api_flow_action_v2_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_rss_function_t_calc_size (vl_api_rss_function_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_generic_pattern_t_calc_size (vl_api_generic_pattern_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_port_and_mask_t_calc_size (vl_api_ip_port_and_mask_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_prot_and_mask_t_calc_size (vl_api_ip_prot_and_mask_t *a)
{
      return sizeof(*a) - sizeof(a->prot) + vl_api_ip_proto_t_calc_size(&a->prot);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_ethernet_t_calc_size (vl_api_flow_ethernet_t *a)
{
      return sizeof(*a) - sizeof(a->src_addr) + vl_api_mac_address_t_calc_size(&a->src_addr) - sizeof(a->dst_addr) + vl_api_mac_address_t_calc_size(&a->dst_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_ip4_t_calc_size (vl_api_flow_ip4_t *a)
{
      return sizeof(*a) - sizeof(a->src_addr) + vl_api_ip4_address_and_mask_t_calc_size(&a->src_addr) - sizeof(a->dst_addr) + vl_api_ip4_address_and_mask_t_calc_size(&a->dst_addr) - sizeof(a->protocol) + vl_api_ip_prot_and_mask_t_calc_size(&a->protocol);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_ip6_t_calc_size (vl_api_flow_ip6_t *a)
{
      return sizeof(*a) - sizeof(a->src_addr) + vl_api_ip6_address_and_mask_t_calc_size(&a->src_addr) - sizeof(a->dst_addr) + vl_api_ip6_address_and_mask_t_calc_size(&a->dst_addr) - sizeof(a->protocol) + vl_api_ip_prot_and_mask_t_calc_size(&a->protocol);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_ip4_n_tuple_t_calc_size (vl_api_flow_ip4_n_tuple_t *a)
{
      return sizeof(*a) - sizeof(a->src_addr) + vl_api_ip4_address_and_mask_t_calc_size(&a->src_addr) - sizeof(a->dst_addr) + vl_api_ip4_address_and_mask_t_calc_size(&a->dst_addr) - sizeof(a->protocol) + vl_api_ip_prot_and_mask_t_calc_size(&a->protocol) - sizeof(a->src_port) + vl_api_ip_port_and_mask_t_calc_size(&a->src_port) - sizeof(a->dst_port) + vl_api_ip_port_and_mask_t_calc_size(&a->dst_port);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_ip6_n_tuple_t_calc_size (vl_api_flow_ip6_n_tuple_t *a)
{
      return sizeof(*a) - sizeof(a->src_addr) + vl_api_ip6_address_and_mask_t_calc_size(&a->src_addr) - sizeof(a->dst_addr) + vl_api_ip6_address_and_mask_t_calc_size(&a->dst_addr) - sizeof(a->protocol) + vl_api_ip_prot_and_mask_t_calc_size(&a->protocol) - sizeof(a->src_port) + vl_api_ip_port_and_mask_t_calc_size(&a->src_port) - sizeof(a->dst_port) + vl_api_ip_port_and_mask_t_calc_size(&a->dst_port);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_ip4_n_tuple_tagged_t_calc_size (vl_api_flow_ip4_n_tuple_tagged_t *a)
{
      return sizeof(*a) - sizeof(a->src_addr) + vl_api_ip4_address_and_mask_t_calc_size(&a->src_addr) - sizeof(a->dst_addr) + vl_api_ip4_address_and_mask_t_calc_size(&a->dst_addr) - sizeof(a->protocol) + vl_api_ip_prot_and_mask_t_calc_size(&a->protocol) - sizeof(a->src_port) + vl_api_ip_port_and_mask_t_calc_size(&a->src_port) - sizeof(a->dst_port) + vl_api_ip_port_and_mask_t_calc_size(&a->dst_port);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_ip6_n_tuple_tagged_t_calc_size (vl_api_flow_ip6_n_tuple_tagged_t *a)
{
      return sizeof(*a) - sizeof(a->src_addr) + vl_api_ip6_address_and_mask_t_calc_size(&a->src_addr) - sizeof(a->dst_addr) + vl_api_ip6_address_and_mask_t_calc_size(&a->dst_addr) - sizeof(a->protocol) + vl_api_ip_prot_and_mask_t_calc_size(&a->protocol) - sizeof(a->src_port) + vl_api_ip_port_and_mask_t_calc_size(&a->src_port) - sizeof(a->dst_port) + vl_api_ip_port_and_mask_t_calc_size(&a->dst_port);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_ip4_l2tpv3oip_t_calc_size (vl_api_flow_ip4_l2tpv3oip_t *a)
{
      return sizeof(*a) - sizeof(a->src_addr) + vl_api_ip4_address_and_mask_t_calc_size(&a->src_addr) - sizeof(a->dst_addr) + vl_api_ip4_address_and_mask_t_calc_size(&a->dst_addr) - sizeof(a->protocol) + vl_api_ip_prot_and_mask_t_calc_size(&a->protocol);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_ip4_ipsec_esp_t_calc_size (vl_api_flow_ip4_ipsec_esp_t *a)
{
      return sizeof(*a) - sizeof(a->src_addr) + vl_api_ip4_address_and_mask_t_calc_size(&a->src_addr) - sizeof(a->dst_addr) + vl_api_ip4_address_and_mask_t_calc_size(&a->dst_addr) - sizeof(a->protocol) + vl_api_ip_prot_and_mask_t_calc_size(&a->protocol);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_ip4_ipsec_ah_t_calc_size (vl_api_flow_ip4_ipsec_ah_t *a)
{
      return sizeof(*a) - sizeof(a->src_addr) + vl_api_ip4_address_and_mask_t_calc_size(&a->src_addr) - sizeof(a->dst_addr) + vl_api_ip4_address_and_mask_t_calc_size(&a->dst_addr) - sizeof(a->protocol) + vl_api_ip_prot_and_mask_t_calc_size(&a->protocol);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_ip4_vxlan_t_calc_size (vl_api_flow_ip4_vxlan_t *a)
{
      return sizeof(*a) - sizeof(a->src_addr) + vl_api_ip4_address_and_mask_t_calc_size(&a->src_addr) - sizeof(a->dst_addr) + vl_api_ip4_address_and_mask_t_calc_size(&a->dst_addr) - sizeof(a->protocol) + vl_api_ip_prot_and_mask_t_calc_size(&a->protocol) - sizeof(a->src_port) + vl_api_ip_port_and_mask_t_calc_size(&a->src_port) - sizeof(a->dst_port) + vl_api_ip_port_and_mask_t_calc_size(&a->dst_port);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_ip6_vxlan_t_calc_size (vl_api_flow_ip6_vxlan_t *a)
{
      return sizeof(*a) - sizeof(a->src_addr) + vl_api_ip6_address_and_mask_t_calc_size(&a->src_addr) - sizeof(a->dst_addr) + vl_api_ip6_address_and_mask_t_calc_size(&a->dst_addr) - sizeof(a->protocol) + vl_api_ip_prot_and_mask_t_calc_size(&a->protocol) - sizeof(a->src_port) + vl_api_ip_port_and_mask_t_calc_size(&a->src_port) - sizeof(a->dst_port) + vl_api_ip_port_and_mask_t_calc_size(&a->dst_port);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_ip4_gtpc_t_calc_size (vl_api_flow_ip4_gtpc_t *a)
{
      return sizeof(*a) - sizeof(a->src_addr) + vl_api_ip4_address_and_mask_t_calc_size(&a->src_addr) - sizeof(a->dst_addr) + vl_api_ip4_address_and_mask_t_calc_size(&a->dst_addr) - sizeof(a->protocol) + vl_api_ip_prot_and_mask_t_calc_size(&a->protocol) - sizeof(a->src_port) + vl_api_ip_port_and_mask_t_calc_size(&a->src_port) - sizeof(a->dst_port) + vl_api_ip_port_and_mask_t_calc_size(&a->dst_port);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_ip4_gtpu_t_calc_size (vl_api_flow_ip4_gtpu_t *a)
{
      return sizeof(*a) - sizeof(a->src_addr) + vl_api_ip4_address_and_mask_t_calc_size(&a->src_addr) - sizeof(a->dst_addr) + vl_api_ip4_address_and_mask_t_calc_size(&a->dst_addr) - sizeof(a->protocol) + vl_api_ip_prot_and_mask_t_calc_size(&a->protocol) - sizeof(a->src_port) + vl_api_ip_port_and_mask_t_calc_size(&a->src_port) - sizeof(a->dst_port) + vl_api_ip_port_and_mask_t_calc_size(&a->dst_port);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_generic_t_calc_size (vl_api_flow_generic_t *a)
{
      return sizeof(*a) - sizeof(a->pattern) + vl_api_generic_pattern_t_calc_size(&a->pattern);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_t_calc_size (vl_api_flow_t *a)
{
      return sizeof(*a) - sizeof(a->ethernet) + vl_api_flow_ethernet_t_calc_size(&a->ethernet) - sizeof(a->ip4) + vl_api_flow_ip4_t_calc_size(&a->ip4) - sizeof(a->ip6) + vl_api_flow_ip6_t_calc_size(&a->ip6) - sizeof(a->ip4_l2tpv3oip) + vl_api_flow_ip4_l2tpv3oip_t_calc_size(&a->ip4_l2tpv3oip) - sizeof(a->ip4_ipsec_esp) + vl_api_flow_ip4_ipsec_esp_t_calc_size(&a->ip4_ipsec_esp) - sizeof(a->ip4_ipsec_ah) + vl_api_flow_ip4_ipsec_ah_t_calc_size(&a->ip4_ipsec_ah) - sizeof(a->ip4_n_tuple) + vl_api_flow_ip4_n_tuple_t_calc_size(&a->ip4_n_tuple) - sizeof(a->ip6_n_tuple) + vl_api_flow_ip6_n_tuple_t_calc_size(&a->ip6_n_tuple) - sizeof(a->ip4_n_tuple_tagged) + vl_api_flow_ip4_n_tuple_tagged_t_calc_size(&a->ip4_n_tuple_tagged) - sizeof(a->ip6_n_tuple_tagged) + vl_api_flow_ip6_n_tuple_tagged_t_calc_size(&a->ip6_n_tuple_tagged) - sizeof(a->ip4_vxlan) + vl_api_flow_ip4_vxlan_t_calc_size(&a->ip4_vxlan) - sizeof(a->ip6_vxlan) + vl_api_flow_ip6_vxlan_t_calc_size(&a->ip6_vxlan) - sizeof(a->ip4_gtpc) + vl_api_flow_ip4_gtpc_t_calc_size(&a->ip4_gtpc) - sizeof(a->ip4_gtpu) + vl_api_flow_ip4_gtpu_t_calc_size(&a->ip4_gtpu);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_v2_t_calc_size (vl_api_flow_v2_t *a)
{
      return sizeof(*a) - sizeof(a->ethernet) + vl_api_flow_ethernet_t_calc_size(&a->ethernet) - sizeof(a->ip4) + vl_api_flow_ip4_t_calc_size(&a->ip4) - sizeof(a->ip6) + vl_api_flow_ip6_t_calc_size(&a->ip6) - sizeof(a->ip4_l2tpv3oip) + vl_api_flow_ip4_l2tpv3oip_t_calc_size(&a->ip4_l2tpv3oip) - sizeof(a->ip4_ipsec_esp) + vl_api_flow_ip4_ipsec_esp_t_calc_size(&a->ip4_ipsec_esp) - sizeof(a->ip4_ipsec_ah) + vl_api_flow_ip4_ipsec_ah_t_calc_size(&a->ip4_ipsec_ah) - sizeof(a->ip4_n_tuple) + vl_api_flow_ip4_n_tuple_t_calc_size(&a->ip4_n_tuple) - sizeof(a->ip6_n_tuple) + vl_api_flow_ip6_n_tuple_t_calc_size(&a->ip6_n_tuple) - sizeof(a->ip4_n_tuple_tagged) + vl_api_flow_ip4_n_tuple_tagged_t_calc_size(&a->ip4_n_tuple_tagged) - sizeof(a->ip6_n_tuple_tagged) + vl_api_flow_ip6_n_tuple_tagged_t_calc_size(&a->ip6_n_tuple_tagged) - sizeof(a->ip4_vxlan) + vl_api_flow_ip4_vxlan_t_calc_size(&a->ip4_vxlan) - sizeof(a->ip6_vxlan) + vl_api_flow_ip6_vxlan_t_calc_size(&a->ip6_vxlan) - sizeof(a->ip4_gtpc) + vl_api_flow_ip4_gtpc_t_calc_size(&a->ip4_gtpc) - sizeof(a->ip4_gtpu) + vl_api_flow_ip4_gtpu_t_calc_size(&a->ip4_gtpu) - sizeof(a->generic) + vl_api_flow_generic_t_calc_size(&a->generic);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_rule_t_calc_size (vl_api_flow_rule_t *a)
{
      return sizeof(*a) - sizeof(a->type) + vl_api_flow_type_t_calc_size(&a->type) - sizeof(a->actions) + vl_api_flow_action_t_calc_size(&a->actions) - sizeof(a->flow) + vl_api_flow_t_calc_size(&a->flow);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flow_rule_v2_t_calc_size (vl_api_flow_rule_v2_t *a)
{
      return sizeof(*a) - sizeof(a->type) + vl_api_flow_type_v2_t_calc_size(&a->type) - sizeof(a->actions) + vl_api_flow_action_v2_t_calc_size(&a->actions) - sizeof(a->rss_fun) + vl_api_rss_function_t_calc_size(&a->rss_fun) - sizeof(a->flow) + vl_api_flow_v2_t_calc_size(&a->flow);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(flow_types.api, 0, 0, 4)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(flow_types.api, 0xe5fe0905)

#endif

