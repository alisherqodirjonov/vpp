/*
 * VLIB API definitions 2026-04-04 08:31:59
 * Input file: lb.api
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
#warning no content included from lb.api
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
#include <lb/lb_types.api.h>
#include <vnet/interface_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_LB_CONF, vl_api_lb_conf_t_handler)
vl_msg_id(VL_API_LB_CONF_REPLY, vl_api_lb_conf_reply_t_handler)
vl_msg_id(VL_API_LB_ADD_DEL_VIP, vl_api_lb_add_del_vip_t_handler)
vl_msg_id(VL_API_LB_ADD_DEL_VIP_REPLY, vl_api_lb_add_del_vip_reply_t_handler)
vl_msg_id(VL_API_LB_ADD_DEL_VIP_V2, vl_api_lb_add_del_vip_v2_t_handler)
vl_msg_id(VL_API_LB_ADD_DEL_VIP_V2_REPLY, vl_api_lb_add_del_vip_v2_reply_t_handler)
vl_msg_id(VL_API_LB_ADD_DEL_AS, vl_api_lb_add_del_as_t_handler)
vl_msg_id(VL_API_LB_ADD_DEL_AS_REPLY, vl_api_lb_add_del_as_reply_t_handler)
vl_msg_id(VL_API_LB_FLUSH_VIP, vl_api_lb_flush_vip_t_handler)
vl_msg_id(VL_API_LB_FLUSH_VIP_REPLY, vl_api_lb_flush_vip_reply_t_handler)
vl_msg_id(VL_API_LB_VIP_DUMP, vl_api_lb_vip_dump_t_handler)
vl_msg_id(VL_API_LB_VIP_DETAILS, vl_api_lb_vip_details_t_handler)
vl_msg_id(VL_API_LB_AS_DUMP, vl_api_lb_as_dump_t_handler)
vl_msg_id(VL_API_LB_AS_DETAILS, vl_api_lb_as_details_t_handler)
vl_msg_id(VL_API_LB_ADD_DEL_INTF_NAT4, vl_api_lb_add_del_intf_nat4_t_handler)
vl_msg_id(VL_API_LB_ADD_DEL_INTF_NAT4_REPLY, vl_api_lb_add_del_intf_nat4_reply_t_handler)
vl_msg_id(VL_API_LB_ADD_DEL_INTF_NAT6, vl_api_lb_add_del_intf_nat6_t_handler)
vl_msg_id(VL_API_LB_ADD_DEL_INTF_NAT6_REPLY, vl_api_lb_add_del_intf_nat6_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_lb_conf_t, 1)
vl_msg_name(vl_api_lb_conf_reply_t, 1)
vl_msg_name(vl_api_lb_add_del_vip_t, 1)
vl_msg_name(vl_api_lb_add_del_vip_reply_t, 1)
vl_msg_name(vl_api_lb_add_del_vip_v2_t, 1)
vl_msg_name(vl_api_lb_add_del_vip_v2_reply_t, 1)
vl_msg_name(vl_api_lb_add_del_as_t, 1)
vl_msg_name(vl_api_lb_add_del_as_reply_t, 1)
vl_msg_name(vl_api_lb_flush_vip_t, 1)
vl_msg_name(vl_api_lb_flush_vip_reply_t, 1)
vl_msg_name(vl_api_lb_vip_dump_t, 1)
vl_msg_name(vl_api_lb_vip_details_t, 1)
vl_msg_name(vl_api_lb_as_dump_t, 1)
vl_msg_name(vl_api_lb_as_details_t, 1)
vl_msg_name(vl_api_lb_add_del_intf_nat4_t, 1)
vl_msg_name(vl_api_lb_add_del_intf_nat4_reply_t, 1)
vl_msg_name(vl_api_lb_add_del_intf_nat6_t, 1)
vl_msg_name(vl_api_lb_add_del_intf_nat6_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_lb \
_(VL_API_LB_CONF, lb_conf, 56cd3261) \
_(VL_API_LB_CONF_REPLY, lb_conf_reply, e8d4e804) \
_(VL_API_LB_ADD_DEL_VIP, lb_add_del_vip, 6fa569c7) \
_(VL_API_LB_ADD_DEL_VIP_REPLY, lb_add_del_vip_reply, e8d4e804) \
_(VL_API_LB_ADD_DEL_VIP_V2, lb_add_del_vip_v2, 7c520e0f) \
_(VL_API_LB_ADD_DEL_VIP_V2_REPLY, lb_add_del_vip_v2_reply, e8d4e804) \
_(VL_API_LB_ADD_DEL_AS, lb_add_del_as, 35d72500) \
_(VL_API_LB_ADD_DEL_AS_REPLY, lb_add_del_as_reply, e8d4e804) \
_(VL_API_LB_FLUSH_VIP, lb_flush_vip, 1063f819) \
_(VL_API_LB_FLUSH_VIP_REPLY, lb_flush_vip_reply, e8d4e804) \
_(VL_API_LB_VIP_DUMP, lb_vip_dump, 56110cb7) \
_(VL_API_LB_VIP_DETAILS, lb_vip_details, 1329ec9b) \
_(VL_API_LB_AS_DUMP, lb_as_dump, 1063f819) \
_(VL_API_LB_AS_DETAILS, lb_as_details, 8d24c29e) \
_(VL_API_LB_ADD_DEL_INTF_NAT4, lb_add_del_intf_nat4, 47d6e753) \
_(VL_API_LB_ADD_DEL_INTF_NAT4_REPLY, lb_add_del_intf_nat4_reply, e8d4e804) \
_(VL_API_LB_ADD_DEL_INTF_NAT6, lb_add_del_intf_nat6, 47d6e753) \
_(VL_API_LB_ADD_DEL_INTF_NAT6_REPLY, lb_add_del_intf_nat6_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "lb.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_lb_printfun_types
#define included_lb_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_lb_printfun
#define included_lb_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "lb.api_tojson.h"
#include "lb.api_fromjson.h"

static inline u8 *vl_api_lb_conf_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lb_conf_t *a = va_arg (*args, vl_api_lb_conf_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lb_conf_t: */
    s = format(s, "vl_api_lb_conf_t:");
    s = format(s, "\n%Uip4_src_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip4_src_address, indent);
    s = format(s, "\n%Uip6_src_address: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->ip6_src_address, indent);
    s = format(s, "\n%Usticky_buckets_per_core: %u", format_white_space, indent, a->sticky_buckets_per_core);
    s = format(s, "\n%Uflow_timeout: %u", format_white_space, indent, a->flow_timeout);
    return s;
}

static inline u8 *vl_api_lb_conf_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lb_conf_reply_t *a = va_arg (*args, vl_api_lb_conf_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lb_conf_reply_t: */
    s = format(s, "vl_api_lb_conf_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lb_add_del_vip_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lb_add_del_vip_t *a = va_arg (*args, vl_api_lb_add_del_vip_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lb_add_del_vip_t: */
    s = format(s, "vl_api_lb_add_del_vip_t:");
    s = format(s, "\n%Upfx: %U", format_white_space, indent, format_vl_api_address_with_prefix_t, &a->pfx, indent);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    s = format(s, "\n%Uencap: %U", format_white_space, indent, format_vl_api_lb_encap_type_t, &a->encap, indent);
    s = format(s, "\n%Udscp: %u", format_white_space, indent, a->dscp);
    s = format(s, "\n%Utype: %U", format_white_space, indent, format_vl_api_lb_srv_type_t, &a->type, indent);
    s = format(s, "\n%Utarget_port: %u", format_white_space, indent, a->target_port);
    s = format(s, "\n%Unode_port: %u", format_white_space, indent, a->node_port);
    s = format(s, "\n%Unew_flows_table_length: %u", format_white_space, indent, a->new_flows_table_length);
    s = format(s, "\n%Uis_del: %u", format_white_space, indent, a->is_del);
    return s;
}

static inline u8 *vl_api_lb_add_del_vip_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lb_add_del_vip_reply_t *a = va_arg (*args, vl_api_lb_add_del_vip_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lb_add_del_vip_reply_t: */
    s = format(s, "vl_api_lb_add_del_vip_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lb_add_del_vip_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lb_add_del_vip_v2_t *a = va_arg (*args, vl_api_lb_add_del_vip_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lb_add_del_vip_v2_t: */
    s = format(s, "vl_api_lb_add_del_vip_v2_t:");
    s = format(s, "\n%Upfx: %U", format_white_space, indent, format_vl_api_address_with_prefix_t, &a->pfx, indent);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    s = format(s, "\n%Uencap: %U", format_white_space, indent, format_vl_api_lb_encap_type_t, &a->encap, indent);
    s = format(s, "\n%Udscp: %u", format_white_space, indent, a->dscp);
    s = format(s, "\n%Utype: %U", format_white_space, indent, format_vl_api_lb_srv_type_t, &a->type, indent);
    s = format(s, "\n%Utarget_port: %u", format_white_space, indent, a->target_port);
    s = format(s, "\n%Unode_port: %u", format_white_space, indent, a->node_port);
    s = format(s, "\n%Unew_flows_table_length: %u", format_white_space, indent, a->new_flows_table_length);
    s = format(s, "\n%Usrc_ip_sticky: %u", format_white_space, indent, a->src_ip_sticky);
    s = format(s, "\n%Uis_del: %u", format_white_space, indent, a->is_del);
    return s;
}

static inline u8 *vl_api_lb_add_del_vip_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lb_add_del_vip_v2_reply_t *a = va_arg (*args, vl_api_lb_add_del_vip_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lb_add_del_vip_v2_reply_t: */
    s = format(s, "vl_api_lb_add_del_vip_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lb_add_del_as_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lb_add_del_as_t *a = va_arg (*args, vl_api_lb_add_del_as_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lb_add_del_as_t: */
    s = format(s, "vl_api_lb_add_del_as_t:");
    s = format(s, "\n%Upfx: %U", format_white_space, indent, format_vl_api_address_with_prefix_t, &a->pfx, indent);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    s = format(s, "\n%Uas_address: %U", format_white_space, indent, format_vl_api_address_t, &a->as_address, indent);
    s = format(s, "\n%Uis_del: %u", format_white_space, indent, a->is_del);
    s = format(s, "\n%Uis_flush: %u", format_white_space, indent, a->is_flush);
    return s;
}

static inline u8 *vl_api_lb_add_del_as_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lb_add_del_as_reply_t *a = va_arg (*args, vl_api_lb_add_del_as_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lb_add_del_as_reply_t: */
    s = format(s, "vl_api_lb_add_del_as_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lb_flush_vip_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lb_flush_vip_t *a = va_arg (*args, vl_api_lb_flush_vip_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lb_flush_vip_t: */
    s = format(s, "vl_api_lb_flush_vip_t:");
    s = format(s, "\n%Upfx: %U", format_white_space, indent, format_vl_api_address_with_prefix_t, &a->pfx, indent);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    return s;
}

static inline u8 *vl_api_lb_flush_vip_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lb_flush_vip_reply_t *a = va_arg (*args, vl_api_lb_flush_vip_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lb_flush_vip_reply_t: */
    s = format(s, "vl_api_lb_flush_vip_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lb_vip_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lb_vip_dump_t *a = va_arg (*args, vl_api_lb_vip_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lb_vip_dump_t: */
    s = format(s, "vl_api_lb_vip_dump_t:");
    s = format(s, "\n%Upfx: %U", format_white_space, indent, format_vl_api_address_with_prefix_t, &a->pfx, indent);
    s = format(s, "\n%Upfx_matcher: %U", format_white_space, indent, format_vl_api_prefix_matcher_t, &a->pfx_matcher, indent);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    return s;
}

static inline u8 *vl_api_lb_vip_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lb_vip_details_t *a = va_arg (*args, vl_api_lb_vip_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lb_vip_details_t: */
    s = format(s, "vl_api_lb_vip_details_t:");
    s = format(s, "\n%Uvip: %U", format_white_space, indent, format_vl_api_lb_vip_t, &a->vip, indent);
    s = format(s, "\n%Uencap: %U", format_white_space, indent, format_vl_api_lb_encap_type_t, &a->encap, indent);
    s = format(s, "\n%Udscp: %U", format_white_space, indent, format_vl_api_ip_dscp_t, &a->dscp, indent);
    s = format(s, "\n%Usrv_type: %U", format_white_space, indent, format_vl_api_lb_srv_type_t, &a->srv_type, indent);
    s = format(s, "\n%Utarget_port: %u", format_white_space, indent, a->target_port);
    s = format(s, "\n%Uflow_table_length: %u", format_white_space, indent, a->flow_table_length);
    return s;
}

static inline u8 *vl_api_lb_as_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lb_as_dump_t *a = va_arg (*args, vl_api_lb_as_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lb_as_dump_t: */
    s = format(s, "vl_api_lb_as_dump_t:");
    s = format(s, "\n%Upfx: %U", format_white_space, indent, format_vl_api_address_with_prefix_t, &a->pfx, indent);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    return s;
}

static inline u8 *vl_api_lb_as_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lb_as_details_t *a = va_arg (*args, vl_api_lb_as_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lb_as_details_t: */
    s = format(s, "vl_api_lb_as_details_t:");
    s = format(s, "\n%Uvip: %U", format_white_space, indent, format_vl_api_lb_vip_t, &a->vip, indent);
    s = format(s, "\n%Uapp_srv: %U", format_white_space, indent, format_vl_api_address_t, &a->app_srv, indent);
    s = format(s, "\n%Uflags: %u", format_white_space, indent, a->flags);
    s = format(s, "\n%Uin_use_since: %u", format_white_space, indent, a->in_use_since);
    return s;
}

static inline u8 *vl_api_lb_add_del_intf_nat4_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lb_add_del_intf_nat4_t *a = va_arg (*args, vl_api_lb_add_del_intf_nat4_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lb_add_del_intf_nat4_t: */
    s = format(s, "vl_api_lb_add_del_intf_nat4_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_lb_add_del_intf_nat4_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lb_add_del_intf_nat4_reply_t *a = va_arg (*args, vl_api_lb_add_del_intf_nat4_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lb_add_del_intf_nat4_reply_t: */
    s = format(s, "vl_api_lb_add_del_intf_nat4_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lb_add_del_intf_nat6_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lb_add_del_intf_nat6_t *a = va_arg (*args, vl_api_lb_add_del_intf_nat6_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lb_add_del_intf_nat6_t: */
    s = format(s, "vl_api_lb_add_del_intf_nat6_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_lb_add_del_intf_nat6_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lb_add_del_intf_nat6_reply_t *a = va_arg (*args, vl_api_lb_add_del_intf_nat6_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lb_add_del_intf_nat6_reply_t: */
    s = format(s, "vl_api_lb_add_del_intf_nat6_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_lb_endianfun
#define included_lb_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_lb_conf_t_endian (vl_api_lb_conf_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->ip4_src_address, to_net);
    vl_api_ip6_address_t_endian(&a->ip6_src_address, to_net);
    a->sticky_buckets_per_core = clib_net_to_host_u32(a->sticky_buckets_per_core);
    a->flow_timeout = clib_net_to_host_u32(a->flow_timeout);
}

static inline void vl_api_lb_conf_reply_t_endian (vl_api_lb_conf_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lb_add_del_vip_t_endian (vl_api_lb_add_del_vip_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_address_with_prefix_t_endian(&a->pfx, to_net);
    /* a->protocol = a->protocol (no-op) */
    a->port = clib_net_to_host_u16(a->port);
    vl_api_lb_encap_type_t_endian(&a->encap, to_net);
    /* a->dscp = a->dscp (no-op) */
    vl_api_lb_srv_type_t_endian(&a->type, to_net);
    a->target_port = clib_net_to_host_u16(a->target_port);
    a->node_port = clib_net_to_host_u16(a->node_port);
    a->new_flows_table_length = clib_net_to_host_u32(a->new_flows_table_length);
    /* a->is_del = a->is_del (no-op) */
}

static inline void vl_api_lb_add_del_vip_reply_t_endian (vl_api_lb_add_del_vip_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lb_add_del_vip_v2_t_endian (vl_api_lb_add_del_vip_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_address_with_prefix_t_endian(&a->pfx, to_net);
    /* a->protocol = a->protocol (no-op) */
    a->port = clib_net_to_host_u16(a->port);
    vl_api_lb_encap_type_t_endian(&a->encap, to_net);
    /* a->dscp = a->dscp (no-op) */
    vl_api_lb_srv_type_t_endian(&a->type, to_net);
    a->target_port = clib_net_to_host_u16(a->target_port);
    a->node_port = clib_net_to_host_u16(a->node_port);
    a->new_flows_table_length = clib_net_to_host_u32(a->new_flows_table_length);
    /* a->src_ip_sticky = a->src_ip_sticky (no-op) */
    /* a->is_del = a->is_del (no-op) */
}

static inline void vl_api_lb_add_del_vip_v2_reply_t_endian (vl_api_lb_add_del_vip_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lb_add_del_as_t_endian (vl_api_lb_add_del_as_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_address_with_prefix_t_endian(&a->pfx, to_net);
    /* a->protocol = a->protocol (no-op) */
    a->port = clib_net_to_host_u16(a->port);
    vl_api_address_t_endian(&a->as_address, to_net);
    /* a->is_del = a->is_del (no-op) */
    /* a->is_flush = a->is_flush (no-op) */
}

static inline void vl_api_lb_add_del_as_reply_t_endian (vl_api_lb_add_del_as_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lb_flush_vip_t_endian (vl_api_lb_flush_vip_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_address_with_prefix_t_endian(&a->pfx, to_net);
    /* a->protocol = a->protocol (no-op) */
    a->port = clib_net_to_host_u16(a->port);
}

static inline void vl_api_lb_flush_vip_reply_t_endian (vl_api_lb_flush_vip_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lb_vip_dump_t_endian (vl_api_lb_vip_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_address_with_prefix_t_endian(&a->pfx, to_net);
    vl_api_prefix_matcher_t_endian(&a->pfx_matcher, to_net);
    /* a->protocol = a->protocol (no-op) */
    a->port = clib_net_to_host_u16(a->port);
}

static inline void vl_api_lb_vip_details_t_endian (vl_api_lb_vip_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_lb_vip_t_endian(&a->vip, to_net);
    vl_api_lb_encap_type_t_endian(&a->encap, to_net);
    vl_api_ip_dscp_t_endian(&a->dscp, to_net);
    vl_api_lb_srv_type_t_endian(&a->srv_type, to_net);
    a->target_port = clib_net_to_host_u16(a->target_port);
    a->flow_table_length = clib_net_to_host_u16(a->flow_table_length);
}

static inline void vl_api_lb_as_dump_t_endian (vl_api_lb_as_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_address_with_prefix_t_endian(&a->pfx, to_net);
    /* a->protocol = a->protocol (no-op) */
    a->port = clib_net_to_host_u16(a->port);
}

static inline void vl_api_lb_as_details_t_endian (vl_api_lb_as_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_lb_vip_t_endian(&a->vip, to_net);
    vl_api_address_t_endian(&a->app_srv, to_net);
    /* a->flags = a->flags (no-op) */
    a->in_use_since = clib_net_to_host_u32(a->in_use_since);
}

static inline void vl_api_lb_add_del_intf_nat4_t_endian (vl_api_lb_add_del_intf_nat4_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_lb_add_del_intf_nat4_reply_t_endian (vl_api_lb_add_del_intf_nat4_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lb_add_del_intf_nat6_t_endian (vl_api_lb_add_del_intf_nat6_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_lb_add_del_intf_nat6_reply_t_endian (vl_api_lb_add_del_intf_nat6_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_lb_calcsizefun
#define included_lb_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_conf_t_calc_size (vl_api_lb_conf_t *a)
{
      return sizeof(*a) - sizeof(a->ip4_src_address) + vl_api_ip4_address_t_calc_size(&a->ip4_src_address) - sizeof(a->ip6_src_address) + vl_api_ip6_address_t_calc_size(&a->ip6_src_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_conf_reply_t_calc_size (vl_api_lb_conf_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_add_del_vip_t_calc_size (vl_api_lb_add_del_vip_t *a)
{
      return sizeof(*a) - sizeof(a->pfx) + vl_api_address_with_prefix_t_calc_size(&a->pfx) - sizeof(a->encap) + vl_api_lb_encap_type_t_calc_size(&a->encap) - sizeof(a->type) + vl_api_lb_srv_type_t_calc_size(&a->type);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_add_del_vip_reply_t_calc_size (vl_api_lb_add_del_vip_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_add_del_vip_v2_t_calc_size (vl_api_lb_add_del_vip_v2_t *a)
{
      return sizeof(*a) - sizeof(a->pfx) + vl_api_address_with_prefix_t_calc_size(&a->pfx) - sizeof(a->encap) + vl_api_lb_encap_type_t_calc_size(&a->encap) - sizeof(a->type) + vl_api_lb_srv_type_t_calc_size(&a->type);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_add_del_vip_v2_reply_t_calc_size (vl_api_lb_add_del_vip_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_add_del_as_t_calc_size (vl_api_lb_add_del_as_t *a)
{
      return sizeof(*a) - sizeof(a->pfx) + vl_api_address_with_prefix_t_calc_size(&a->pfx) - sizeof(a->as_address) + vl_api_address_t_calc_size(&a->as_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_add_del_as_reply_t_calc_size (vl_api_lb_add_del_as_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_flush_vip_t_calc_size (vl_api_lb_flush_vip_t *a)
{
      return sizeof(*a) - sizeof(a->pfx) + vl_api_address_with_prefix_t_calc_size(&a->pfx);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_flush_vip_reply_t_calc_size (vl_api_lb_flush_vip_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_vip_dump_t_calc_size (vl_api_lb_vip_dump_t *a)
{
      return sizeof(*a) - sizeof(a->pfx) + vl_api_address_with_prefix_t_calc_size(&a->pfx) - sizeof(a->pfx_matcher) + vl_api_prefix_matcher_t_calc_size(&a->pfx_matcher);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_vip_details_t_calc_size (vl_api_lb_vip_details_t *a)
{
      return sizeof(*a) - sizeof(a->vip) + vl_api_lb_vip_t_calc_size(&a->vip) - sizeof(a->encap) + vl_api_lb_encap_type_t_calc_size(&a->encap) - sizeof(a->dscp) + vl_api_ip_dscp_t_calc_size(&a->dscp) - sizeof(a->srv_type) + vl_api_lb_srv_type_t_calc_size(&a->srv_type);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_as_dump_t_calc_size (vl_api_lb_as_dump_t *a)
{
      return sizeof(*a) - sizeof(a->pfx) + vl_api_address_with_prefix_t_calc_size(&a->pfx);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_as_details_t_calc_size (vl_api_lb_as_details_t *a)
{
      return sizeof(*a) - sizeof(a->vip) + vl_api_lb_vip_t_calc_size(&a->vip) - sizeof(a->app_srv) + vl_api_address_t_calc_size(&a->app_srv);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_add_del_intf_nat4_t_calc_size (vl_api_lb_add_del_intf_nat4_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_add_del_intf_nat4_reply_t_calc_size (vl_api_lb_add_del_intf_nat4_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_add_del_intf_nat6_t_calc_size (vl_api_lb_add_del_intf_nat6_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_add_del_intf_nat6_reply_t_calc_size (vl_api_lb_add_del_intf_nat6_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(lb.api, 1, 1, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(lb.api, 0x31818767)

#endif

