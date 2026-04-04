/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: mpls.api
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
#warning no content included from mpls.api
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
#include <vnet/fib/fib_types.api.h>
#include <vnet/ip/ip_types.api.h>
#include <vnet/interface_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_MPLS_IP_BIND_UNBIND, vl_api_mpls_ip_bind_unbind_t_handler)
vl_msg_id(VL_API_MPLS_IP_BIND_UNBIND_REPLY, vl_api_mpls_ip_bind_unbind_reply_t_handler)
vl_msg_id(VL_API_MPLS_TUNNEL_ADD_DEL, vl_api_mpls_tunnel_add_del_t_handler)
vl_msg_id(VL_API_MPLS_TUNNEL_ADD_DEL_REPLY, vl_api_mpls_tunnel_add_del_reply_t_handler)
vl_msg_id(VL_API_MPLS_TUNNEL_DUMP, vl_api_mpls_tunnel_dump_t_handler)
vl_msg_id(VL_API_MPLS_TUNNEL_DETAILS, vl_api_mpls_tunnel_details_t_handler)
vl_msg_id(VL_API_MPLS_INTERFACE_DUMP, vl_api_mpls_interface_dump_t_handler)
vl_msg_id(VL_API_MPLS_INTERFACE_DETAILS, vl_api_mpls_interface_details_t_handler)
vl_msg_id(VL_API_MPLS_TABLE_ADD_DEL, vl_api_mpls_table_add_del_t_handler)
vl_msg_id(VL_API_MPLS_TABLE_ADD_DEL_REPLY, vl_api_mpls_table_add_del_reply_t_handler)
vl_msg_id(VL_API_MPLS_TABLE_DUMP, vl_api_mpls_table_dump_t_handler)
vl_msg_id(VL_API_MPLS_TABLE_DETAILS, vl_api_mpls_table_details_t_handler)
vl_msg_id(VL_API_MPLS_ROUTE_ADD_DEL, vl_api_mpls_route_add_del_t_handler)
vl_msg_id(VL_API_MPLS_ROUTE_ADD_DEL_REPLY, vl_api_mpls_route_add_del_reply_t_handler)
vl_msg_id(VL_API_MPLS_ROUTE_DUMP, vl_api_mpls_route_dump_t_handler)
vl_msg_id(VL_API_MPLS_ROUTE_DETAILS, vl_api_mpls_route_details_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_SET_MPLS_ENABLE, vl_api_sw_interface_set_mpls_enable_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_SET_MPLS_ENABLE_REPLY, vl_api_sw_interface_set_mpls_enable_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_mpls_ip_bind_unbind_t, 1)
vl_msg_name(vl_api_mpls_ip_bind_unbind_reply_t, 1)
vl_msg_name(vl_api_mpls_tunnel_add_del_t, 1)
vl_msg_name(vl_api_mpls_tunnel_add_del_reply_t, 1)
vl_msg_name(vl_api_mpls_tunnel_dump_t, 1)
vl_msg_name(vl_api_mpls_tunnel_details_t, 1)
vl_msg_name(vl_api_mpls_interface_dump_t, 1)
vl_msg_name(vl_api_mpls_interface_details_t, 1)
vl_msg_name(vl_api_mpls_table_add_del_t, 1)
vl_msg_name(vl_api_mpls_table_add_del_reply_t, 1)
vl_msg_name(vl_api_mpls_table_dump_t, 1)
vl_msg_name(vl_api_mpls_table_details_t, 1)
vl_msg_name(vl_api_mpls_route_add_del_t, 1)
vl_msg_name(vl_api_mpls_route_add_del_reply_t, 1)
vl_msg_name(vl_api_mpls_route_dump_t, 1)
vl_msg_name(vl_api_mpls_route_details_t, 1)
vl_msg_name(vl_api_sw_interface_set_mpls_enable_t, 1)
vl_msg_name(vl_api_sw_interface_set_mpls_enable_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_mpls \
_(VL_API_MPLS_IP_BIND_UNBIND, mpls_ip_bind_unbind, c7533b32) \
_(VL_API_MPLS_IP_BIND_UNBIND_REPLY, mpls_ip_bind_unbind_reply, e8d4e804) \
_(VL_API_MPLS_TUNNEL_ADD_DEL, mpls_tunnel_add_del, 44350ac1) \
_(VL_API_MPLS_TUNNEL_ADD_DEL_REPLY, mpls_tunnel_add_del_reply, afb01472) \
_(VL_API_MPLS_TUNNEL_DUMP, mpls_tunnel_dump, f9e6675e) \
_(VL_API_MPLS_TUNNEL_DETAILS, mpls_tunnel_details, 57118ae3) \
_(VL_API_MPLS_INTERFACE_DUMP, mpls_interface_dump, f9e6675e) \
_(VL_API_MPLS_INTERFACE_DETAILS, mpls_interface_details, 0b45011c) \
_(VL_API_MPLS_TABLE_ADD_DEL, mpls_table_add_del, 57817512) \
_(VL_API_MPLS_TABLE_ADD_DEL_REPLY, mpls_table_add_del_reply, e8d4e804) \
_(VL_API_MPLS_TABLE_DUMP, mpls_table_dump, 51077d14) \
_(VL_API_MPLS_TABLE_DETAILS, mpls_table_details, f03ecdc8) \
_(VL_API_MPLS_ROUTE_ADD_DEL, mpls_route_add_del, 8e1d1e07) \
_(VL_API_MPLS_ROUTE_ADD_DEL_REPLY, mpls_route_add_del_reply, 1992deab) \
_(VL_API_MPLS_ROUTE_DUMP, mpls_route_dump, 935fdefa) \
_(VL_API_MPLS_ROUTE_DETAILS, mpls_route_details, 9b5043dc) \
_(VL_API_SW_INTERFACE_SET_MPLS_ENABLE, sw_interface_set_mpls_enable, ae6cfcfb) \
_(VL_API_SW_INTERFACE_SET_MPLS_ENABLE_REPLY, sw_interface_set_mpls_enable_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "mpls.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_mpls_printfun_types
#define included_mpls_printfun_types

static inline u8 *format_vl_api_mpls_tunnel_t (u8 *s, va_list * args)
{
    vl_api_mpls_tunnel_t *a = va_arg (*args, vl_api_mpls_tunnel_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Umt_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->mt_sw_if_index, indent);
    s = format(s, "\n%Umt_tunnel_index: %u", format_white_space, indent, a->mt_tunnel_index);
    s = format(s, "\n%Umt_l2_only: %u", format_white_space, indent, a->mt_l2_only);
    s = format(s, "\n%Umt_is_multicast: %u", format_white_space, indent, a->mt_is_multicast);
    s = format(s, "\n%Umt_tag: %s", format_white_space, indent, a->mt_tag);
    s = format(s, "\n%Umt_n_paths: %u", format_white_space, indent, a->mt_n_paths);
    for (i = 0; i < a->mt_n_paths; i++) {
        s = format(s, "\n%Umt_paths: %U",
                   format_white_space, indent, format_vl_api_fib_path_t, &a->mt_paths[i], indent);
    }
    return s;
}

static inline u8 *format_vl_api_mpls_table_t (u8 *s, va_list * args)
{
    vl_api_mpls_table_t *a = va_arg (*args, vl_api_mpls_table_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Umt_table_id: %u", format_white_space, indent, a->mt_table_id);
    s = format(s, "\n%Umt_name: %s", format_white_space, indent, a->mt_name);
    return s;
}

static inline u8 *format_vl_api_mpls_route_t (u8 *s, va_list * args)
{
    vl_api_mpls_route_t *a = va_arg (*args, vl_api_mpls_route_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Umr_table_id: %u", format_white_space, indent, a->mr_table_id);
    s = format(s, "\n%Umr_label: %u", format_white_space, indent, a->mr_label);
    s = format(s, "\n%Umr_eos: %u", format_white_space, indent, a->mr_eos);
    s = format(s, "\n%Umr_eos_proto: %u", format_white_space, indent, a->mr_eos_proto);
    s = format(s, "\n%Umr_is_multicast: %u", format_white_space, indent, a->mr_is_multicast);
    s = format(s, "\n%Umr_n_paths: %u", format_white_space, indent, a->mr_n_paths);
    for (i = 0; i < a->mr_n_paths; i++) {
        s = format(s, "\n%Umr_paths: %U",
                   format_white_space, indent, format_vl_api_fib_path_t, &a->mr_paths[i], indent);
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_mpls_printfun
#define included_mpls_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "mpls.api_tojson.h"
#include "mpls.api_fromjson.h"

static inline u8 *vl_api_mpls_ip_bind_unbind_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mpls_ip_bind_unbind_t *a = va_arg (*args, vl_api_mpls_ip_bind_unbind_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mpls_ip_bind_unbind_t: */
    s = format(s, "vl_api_mpls_ip_bind_unbind_t:");
    s = format(s, "\n%Umb_mpls_table_id: %u", format_white_space, indent, a->mb_mpls_table_id);
    s = format(s, "\n%Umb_label: %u", format_white_space, indent, a->mb_label);
    s = format(s, "\n%Umb_ip_table_id: %u", format_white_space, indent, a->mb_ip_table_id);
    s = format(s, "\n%Umb_is_bind: %u", format_white_space, indent, a->mb_is_bind);
    s = format(s, "\n%Umb_prefix: %U", format_white_space, indent, format_vl_api_prefix_t, &a->mb_prefix, indent);
    return s;
}

static inline u8 *vl_api_mpls_ip_bind_unbind_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mpls_ip_bind_unbind_reply_t *a = va_arg (*args, vl_api_mpls_ip_bind_unbind_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mpls_ip_bind_unbind_reply_t: */
    s = format(s, "vl_api_mpls_ip_bind_unbind_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_mpls_tunnel_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mpls_tunnel_add_del_t *a = va_arg (*args, vl_api_mpls_tunnel_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mpls_tunnel_add_del_t: */
    s = format(s, "vl_api_mpls_tunnel_add_del_t:");
    s = format(s, "\n%Umt_is_add: %u", format_white_space, indent, a->mt_is_add);
    s = format(s, "\n%Umt_tunnel: %U", format_white_space, indent, format_vl_api_mpls_tunnel_t, &a->mt_tunnel, indent);
    return s;
}

static inline u8 *vl_api_mpls_tunnel_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mpls_tunnel_add_del_reply_t *a = va_arg (*args, vl_api_mpls_tunnel_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mpls_tunnel_add_del_reply_t: */
    s = format(s, "vl_api_mpls_tunnel_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Utunnel_index: %u", format_white_space, indent, a->tunnel_index);
    return s;
}

static inline u8 *vl_api_mpls_tunnel_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mpls_tunnel_dump_t *a = va_arg (*args, vl_api_mpls_tunnel_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mpls_tunnel_dump_t: */
    s = format(s, "vl_api_mpls_tunnel_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_mpls_tunnel_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mpls_tunnel_details_t *a = va_arg (*args, vl_api_mpls_tunnel_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mpls_tunnel_details_t: */
    s = format(s, "vl_api_mpls_tunnel_details_t:");
    s = format(s, "\n%Umt_tunnel: %U", format_white_space, indent, format_vl_api_mpls_tunnel_t, &a->mt_tunnel, indent);
    return s;
}

static inline u8 *vl_api_mpls_interface_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mpls_interface_dump_t *a = va_arg (*args, vl_api_mpls_interface_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mpls_interface_dump_t: */
    s = format(s, "vl_api_mpls_interface_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_mpls_interface_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mpls_interface_details_t *a = va_arg (*args, vl_api_mpls_interface_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mpls_interface_details_t: */
    s = format(s, "vl_api_mpls_interface_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_mpls_table_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mpls_table_add_del_t *a = va_arg (*args, vl_api_mpls_table_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mpls_table_add_del_t: */
    s = format(s, "vl_api_mpls_table_add_del_t:");
    s = format(s, "\n%Umt_is_add: %u", format_white_space, indent, a->mt_is_add);
    s = format(s, "\n%Umt_table: %U", format_white_space, indent, format_vl_api_mpls_table_t, &a->mt_table, indent);
    return s;
}

static inline u8 *vl_api_mpls_table_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mpls_table_add_del_reply_t *a = va_arg (*args, vl_api_mpls_table_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mpls_table_add_del_reply_t: */
    s = format(s, "vl_api_mpls_table_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_mpls_table_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mpls_table_dump_t *a = va_arg (*args, vl_api_mpls_table_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mpls_table_dump_t: */
    s = format(s, "vl_api_mpls_table_dump_t:");
    return s;
}

static inline u8 *vl_api_mpls_table_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mpls_table_details_t *a = va_arg (*args, vl_api_mpls_table_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mpls_table_details_t: */
    s = format(s, "vl_api_mpls_table_details_t:");
    s = format(s, "\n%Umt_table: %U", format_white_space, indent, format_vl_api_mpls_table_t, &a->mt_table, indent);
    return s;
}

static inline u8 *vl_api_mpls_route_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mpls_route_add_del_t *a = va_arg (*args, vl_api_mpls_route_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mpls_route_add_del_t: */
    s = format(s, "vl_api_mpls_route_add_del_t:");
    s = format(s, "\n%Umr_is_add: %u", format_white_space, indent, a->mr_is_add);
    s = format(s, "\n%Umr_is_multipath: %u", format_white_space, indent, a->mr_is_multipath);
    s = format(s, "\n%Umr_route: %U", format_white_space, indent, format_vl_api_mpls_route_t, &a->mr_route, indent);
    return s;
}

static inline u8 *vl_api_mpls_route_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mpls_route_add_del_reply_t *a = va_arg (*args, vl_api_mpls_route_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mpls_route_add_del_reply_t: */
    s = format(s, "vl_api_mpls_route_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ustats_index: %u", format_white_space, indent, a->stats_index);
    return s;
}

static inline u8 *vl_api_mpls_route_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mpls_route_dump_t *a = va_arg (*args, vl_api_mpls_route_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mpls_route_dump_t: */
    s = format(s, "vl_api_mpls_route_dump_t:");
    s = format(s, "\n%Utable: %U", format_white_space, indent, format_vl_api_mpls_table_t, &a->table, indent);
    return s;
}

static inline u8 *vl_api_mpls_route_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mpls_route_details_t *a = va_arg (*args, vl_api_mpls_route_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mpls_route_details_t: */
    s = format(s, "vl_api_mpls_route_details_t:");
    s = format(s, "\n%Umr_route: %U", format_white_space, indent, format_vl_api_mpls_route_t, &a->mr_route, indent);
    return s;
}

static inline u8 *vl_api_sw_interface_set_mpls_enable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_set_mpls_enable_t *a = va_arg (*args, vl_api_sw_interface_set_mpls_enable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_set_mpls_enable_t: */
    s = format(s, "vl_api_sw_interface_set_mpls_enable_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}

static inline u8 *vl_api_sw_interface_set_mpls_enable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_set_mpls_enable_reply_t *a = va_arg (*args, vl_api_sw_interface_set_mpls_enable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_set_mpls_enable_reply_t: */
    s = format(s, "vl_api_sw_interface_set_mpls_enable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_mpls_endianfun
#define included_mpls_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_mpls_tunnel_t_endian (vl_api_mpls_tunnel_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_interface_index_t_endian(&a->mt_sw_if_index, to_net);
    a->mt_tunnel_index = clib_net_to_host_u32(a->mt_tunnel_index);
    /* a->mt_l2_only = a->mt_l2_only (no-op) */
    /* a->mt_is_multicast = a->mt_is_multicast (no-op) */
    /* a->mt_tag = a->mt_tag (no-op) */
    /* a->mt_n_paths = a->mt_n_paths (no-op) */
    u32 count = a->mt_n_paths;
    for (i = 0; i < count; i++) {
        vl_api_fib_path_t_endian(&a->mt_paths[i], to_net);
    }
}

static inline void vl_api_mpls_table_t_endian (vl_api_mpls_table_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->mt_table_id = clib_net_to_host_u32(a->mt_table_id);
    /* a->mt_name = a->mt_name (no-op) */
}

static inline void vl_api_mpls_route_t_endian (vl_api_mpls_route_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->mr_table_id = clib_net_to_host_u32(a->mr_table_id);
    a->mr_label = clib_net_to_host_u32(a->mr_label);
    /* a->mr_eos = a->mr_eos (no-op) */
    /* a->mr_eos_proto = a->mr_eos_proto (no-op) */
    /* a->mr_is_multicast = a->mr_is_multicast (no-op) */
    /* a->mr_n_paths = a->mr_n_paths (no-op) */
    u32 count = a->mr_n_paths;
    for (i = 0; i < count; i++) {
        vl_api_fib_path_t_endian(&a->mr_paths[i], to_net);
    }
}

static inline void vl_api_mpls_ip_bind_unbind_t_endian (vl_api_mpls_ip_bind_unbind_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->mb_mpls_table_id = clib_net_to_host_u32(a->mb_mpls_table_id);
    a->mb_label = clib_net_to_host_u32(a->mb_label);
    a->mb_ip_table_id = clib_net_to_host_u32(a->mb_ip_table_id);
    /* a->mb_is_bind = a->mb_is_bind (no-op) */
    vl_api_prefix_t_endian(&a->mb_prefix, to_net);
}

static inline void vl_api_mpls_ip_bind_unbind_reply_t_endian (vl_api_mpls_ip_bind_unbind_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_mpls_tunnel_add_del_t_endian (vl_api_mpls_tunnel_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->mt_is_add = a->mt_is_add (no-op) */
    vl_api_mpls_tunnel_t_endian(&a->mt_tunnel, to_net);
}

static inline void vl_api_mpls_tunnel_add_del_reply_t_endian (vl_api_mpls_tunnel_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->tunnel_index = clib_net_to_host_u32(a->tunnel_index);
}

static inline void vl_api_mpls_tunnel_dump_t_endian (vl_api_mpls_tunnel_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_mpls_tunnel_details_t_endian (vl_api_mpls_tunnel_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_mpls_tunnel_t_endian(&a->mt_tunnel, to_net);
}

static inline void vl_api_mpls_interface_dump_t_endian (vl_api_mpls_interface_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_mpls_interface_details_t_endian (vl_api_mpls_interface_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_mpls_table_add_del_t_endian (vl_api_mpls_table_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->mt_is_add = a->mt_is_add (no-op) */
    vl_api_mpls_table_t_endian(&a->mt_table, to_net);
}

static inline void vl_api_mpls_table_add_del_reply_t_endian (vl_api_mpls_table_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_mpls_table_dump_t_endian (vl_api_mpls_table_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_mpls_table_details_t_endian (vl_api_mpls_table_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_mpls_table_t_endian(&a->mt_table, to_net);
}

static inline void vl_api_mpls_route_add_del_t_endian (vl_api_mpls_route_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->mr_is_add = a->mr_is_add (no-op) */
    /* a->mr_is_multipath = a->mr_is_multipath (no-op) */
    vl_api_mpls_route_t_endian(&a->mr_route, to_net);
}

static inline void vl_api_mpls_route_add_del_reply_t_endian (vl_api_mpls_route_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->stats_index = clib_net_to_host_u32(a->stats_index);
}

static inline void vl_api_mpls_route_dump_t_endian (vl_api_mpls_route_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_mpls_table_t_endian(&a->table, to_net);
}

static inline void vl_api_mpls_route_details_t_endian (vl_api_mpls_route_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_mpls_route_t_endian(&a->mr_route, to_net);
}

static inline void vl_api_sw_interface_set_mpls_enable_t_endian (vl_api_sw_interface_set_mpls_enable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->enable = a->enable (no-op) */
}

static inline void vl_api_sw_interface_set_mpls_enable_reply_t_endian (vl_api_sw_interface_set_mpls_enable_reply_t *a, bool to_net)
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
#ifndef included_mpls_calcsizefun
#define included_mpls_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_mpls_tunnel_t_calc_size (vl_api_mpls_tunnel_t *a)
{
      return sizeof(*a) - sizeof(a->mt_sw_if_index) + vl_api_interface_index_t_calc_size(&a->mt_sw_if_index) + a->mt_n_paths * sizeof(a->mt_paths[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mpls_table_t_calc_size (vl_api_mpls_table_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mpls_route_t_calc_size (vl_api_mpls_route_t *a)
{
      return sizeof(*a) + a->mr_n_paths * sizeof(a->mr_paths[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mpls_ip_bind_unbind_t_calc_size (vl_api_mpls_ip_bind_unbind_t *a)
{
      return sizeof(*a) - sizeof(a->mb_prefix) + vl_api_prefix_t_calc_size(&a->mb_prefix);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mpls_ip_bind_unbind_reply_t_calc_size (vl_api_mpls_ip_bind_unbind_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mpls_tunnel_add_del_t_calc_size (vl_api_mpls_tunnel_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->mt_tunnel) + vl_api_mpls_tunnel_t_calc_size(&a->mt_tunnel);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mpls_tunnel_add_del_reply_t_calc_size (vl_api_mpls_tunnel_add_del_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mpls_tunnel_dump_t_calc_size (vl_api_mpls_tunnel_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mpls_tunnel_details_t_calc_size (vl_api_mpls_tunnel_details_t *a)
{
      return sizeof(*a) - sizeof(a->mt_tunnel) + vl_api_mpls_tunnel_t_calc_size(&a->mt_tunnel);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mpls_interface_dump_t_calc_size (vl_api_mpls_interface_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mpls_interface_details_t_calc_size (vl_api_mpls_interface_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mpls_table_add_del_t_calc_size (vl_api_mpls_table_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->mt_table) + vl_api_mpls_table_t_calc_size(&a->mt_table);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mpls_table_add_del_reply_t_calc_size (vl_api_mpls_table_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mpls_table_dump_t_calc_size (vl_api_mpls_table_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mpls_table_details_t_calc_size (vl_api_mpls_table_details_t *a)
{
      return sizeof(*a) - sizeof(a->mt_table) + vl_api_mpls_table_t_calc_size(&a->mt_table);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mpls_route_add_del_t_calc_size (vl_api_mpls_route_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->mr_route) + vl_api_mpls_route_t_calc_size(&a->mr_route);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mpls_route_add_del_reply_t_calc_size (vl_api_mpls_route_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mpls_route_dump_t_calc_size (vl_api_mpls_route_dump_t *a)
{
      return sizeof(*a) - sizeof(a->table) + vl_api_mpls_table_t_calc_size(&a->table);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mpls_route_details_t_calc_size (vl_api_mpls_route_details_t *a)
{
      return sizeof(*a) - sizeof(a->mr_route) + vl_api_mpls_route_t_calc_size(&a->mr_route);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_set_mpls_enable_t_calc_size (vl_api_sw_interface_set_mpls_enable_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_set_mpls_enable_reply_t_calc_size (vl_api_sw_interface_set_mpls_enable_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(mpls.api, 1, 1, 1)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(mpls.api, 0x85e5987f)

#endif

