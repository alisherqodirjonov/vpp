/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: vxlan.api
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
#warning no content included from vxlan.api
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
#include <vnet/interface_types.api.h>
#include <vnet/ip/ip_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_VXLAN_ADD_DEL_TUNNEL, vl_api_vxlan_add_del_tunnel_t_handler)
vl_msg_id(VL_API_VXLAN_ADD_DEL_TUNNEL_V2, vl_api_vxlan_add_del_tunnel_v2_t_handler)
vl_msg_id(VL_API_VXLAN_ADD_DEL_TUNNEL_V3, vl_api_vxlan_add_del_tunnel_v3_t_handler)
vl_msg_id(VL_API_VXLAN_ADD_DEL_TUNNEL_REPLY, vl_api_vxlan_add_del_tunnel_reply_t_handler)
vl_msg_id(VL_API_VXLAN_ADD_DEL_TUNNEL_V2_REPLY, vl_api_vxlan_add_del_tunnel_v2_reply_t_handler)
vl_msg_id(VL_API_VXLAN_ADD_DEL_TUNNEL_V3_REPLY, vl_api_vxlan_add_del_tunnel_v3_reply_t_handler)
vl_msg_id(VL_API_VXLAN_TUNNEL_DUMP, vl_api_vxlan_tunnel_dump_t_handler)
vl_msg_id(VL_API_VXLAN_TUNNEL_V2_DUMP, vl_api_vxlan_tunnel_v2_dump_t_handler)
vl_msg_id(VL_API_VXLAN_TUNNEL_DETAILS, vl_api_vxlan_tunnel_details_t_handler)
vl_msg_id(VL_API_VXLAN_TUNNEL_V2_DETAILS, vl_api_vxlan_tunnel_v2_details_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_SET_VXLAN_BYPASS, vl_api_sw_interface_set_vxlan_bypass_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_SET_VXLAN_BYPASS_REPLY, vl_api_sw_interface_set_vxlan_bypass_reply_t_handler)
vl_msg_id(VL_API_VXLAN_OFFLOAD_RX, vl_api_vxlan_offload_rx_t_handler)
vl_msg_id(VL_API_VXLAN_OFFLOAD_RX_REPLY, vl_api_vxlan_offload_rx_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_vxlan_add_del_tunnel_t, 1)
vl_msg_name(vl_api_vxlan_add_del_tunnel_v2_t, 1)
vl_msg_name(vl_api_vxlan_add_del_tunnel_v3_t, 1)
vl_msg_name(vl_api_vxlan_add_del_tunnel_reply_t, 1)
vl_msg_name(vl_api_vxlan_add_del_tunnel_v2_reply_t, 1)
vl_msg_name(vl_api_vxlan_add_del_tunnel_v3_reply_t, 1)
vl_msg_name(vl_api_vxlan_tunnel_dump_t, 1)
vl_msg_name(vl_api_vxlan_tunnel_v2_dump_t, 1)
vl_msg_name(vl_api_vxlan_tunnel_details_t, 1)
vl_msg_name(vl_api_vxlan_tunnel_v2_details_t, 1)
vl_msg_name(vl_api_sw_interface_set_vxlan_bypass_t, 1)
vl_msg_name(vl_api_sw_interface_set_vxlan_bypass_reply_t, 1)
vl_msg_name(vl_api_vxlan_offload_rx_t, 1)
vl_msg_name(vl_api_vxlan_offload_rx_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_vxlan \
_(VL_API_VXLAN_ADD_DEL_TUNNEL, vxlan_add_del_tunnel, 0c09dc80) \
_(VL_API_VXLAN_ADD_DEL_TUNNEL_V2, vxlan_add_del_tunnel_v2, 4f223f40) \
_(VL_API_VXLAN_ADD_DEL_TUNNEL_V3, vxlan_add_del_tunnel_v3, 0072b037) \
_(VL_API_VXLAN_ADD_DEL_TUNNEL_REPLY, vxlan_add_del_tunnel_reply, 5383d31f) \
_(VL_API_VXLAN_ADD_DEL_TUNNEL_V2_REPLY, vxlan_add_del_tunnel_v2_reply, 5383d31f) \
_(VL_API_VXLAN_ADD_DEL_TUNNEL_V3_REPLY, vxlan_add_del_tunnel_v3_reply, 5383d31f) \
_(VL_API_VXLAN_TUNNEL_DUMP, vxlan_tunnel_dump, f9e6675e) \
_(VL_API_VXLAN_TUNNEL_V2_DUMP, vxlan_tunnel_v2_dump, f9e6675e) \
_(VL_API_VXLAN_TUNNEL_DETAILS, vxlan_tunnel_details, c3916cb1) \
_(VL_API_VXLAN_TUNNEL_V2_DETAILS, vxlan_tunnel_v2_details, d3bdd4d9) \
_(VL_API_SW_INTERFACE_SET_VXLAN_BYPASS, sw_interface_set_vxlan_bypass, 65247409) \
_(VL_API_SW_INTERFACE_SET_VXLAN_BYPASS_REPLY, sw_interface_set_vxlan_bypass_reply, e8d4e804) \
_(VL_API_VXLAN_OFFLOAD_RX, vxlan_offload_rx, 9cc95087) \
_(VL_API_VXLAN_OFFLOAD_RX_REPLY, vxlan_offload_rx_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "vxlan.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_vxlan_printfun_types
#define included_vxlan_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_vxlan_printfun
#define included_vxlan_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "vxlan.api_tojson.h"
#include "vxlan.api_fromjson.h"

static inline u8 *vl_api_vxlan_add_del_tunnel_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_add_del_tunnel_t *a = va_arg (*args, vl_api_vxlan_add_del_tunnel_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_add_del_tunnel_t: */
    s = format(s, "vl_api_vxlan_add_del_tunnel_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uinstance: %u", format_white_space, indent, a->instance);
    s = format(s, "\n%Usrc_address: %U", format_white_space, indent, format_vl_api_address_t, &a->src_address, indent);
    s = format(s, "\n%Udst_address: %U", format_white_space, indent, format_vl_api_address_t, &a->dst_address, indent);
    s = format(s, "\n%Umcast_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->mcast_sw_if_index, indent);
    s = format(s, "\n%Uencap_vrf_id: %u", format_white_space, indent, a->encap_vrf_id);
    s = format(s, "\n%Udecap_next_index: %u", format_white_space, indent, a->decap_next_index);
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    return s;
}

static inline u8 *vl_api_vxlan_add_del_tunnel_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_add_del_tunnel_v2_t *a = va_arg (*args, vl_api_vxlan_add_del_tunnel_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_add_del_tunnel_v2_t: */
    s = format(s, "vl_api_vxlan_add_del_tunnel_v2_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uinstance: %u", format_white_space, indent, a->instance);
    s = format(s, "\n%Usrc_address: %U", format_white_space, indent, format_vl_api_address_t, &a->src_address, indent);
    s = format(s, "\n%Udst_address: %U", format_white_space, indent, format_vl_api_address_t, &a->dst_address, indent);
    s = format(s, "\n%Usrc_port: %u", format_white_space, indent, a->src_port);
    s = format(s, "\n%Udst_port: %u", format_white_space, indent, a->dst_port);
    s = format(s, "\n%Umcast_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->mcast_sw_if_index, indent);
    s = format(s, "\n%Uencap_vrf_id: %u", format_white_space, indent, a->encap_vrf_id);
    s = format(s, "\n%Udecap_next_index: %u", format_white_space, indent, a->decap_next_index);
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    return s;
}

static inline u8 *vl_api_vxlan_add_del_tunnel_v3_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_add_del_tunnel_v3_t *a = va_arg (*args, vl_api_vxlan_add_del_tunnel_v3_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_add_del_tunnel_v3_t: */
    s = format(s, "vl_api_vxlan_add_del_tunnel_v3_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uinstance: %u", format_white_space, indent, a->instance);
    s = format(s, "\n%Usrc_address: %U", format_white_space, indent, format_vl_api_address_t, &a->src_address, indent);
    s = format(s, "\n%Udst_address: %U", format_white_space, indent, format_vl_api_address_t, &a->dst_address, indent);
    s = format(s, "\n%Usrc_port: %u", format_white_space, indent, a->src_port);
    s = format(s, "\n%Udst_port: %u", format_white_space, indent, a->dst_port);
    s = format(s, "\n%Umcast_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->mcast_sw_if_index, indent);
    s = format(s, "\n%Uencap_vrf_id: %u", format_white_space, indent, a->encap_vrf_id);
    s = format(s, "\n%Udecap_next_index: %u", format_white_space, indent, a->decap_next_index);
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    s = format(s, "\n%Uis_l3: %u", format_white_space, indent, a->is_l3);
    return s;
}

static inline u8 *vl_api_vxlan_add_del_tunnel_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_add_del_tunnel_reply_t *a = va_arg (*args, vl_api_vxlan_add_del_tunnel_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_add_del_tunnel_reply_t: */
    s = format(s, "vl_api_vxlan_add_del_tunnel_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_vxlan_add_del_tunnel_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_add_del_tunnel_v2_reply_t *a = va_arg (*args, vl_api_vxlan_add_del_tunnel_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_add_del_tunnel_v2_reply_t: */
    s = format(s, "vl_api_vxlan_add_del_tunnel_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_vxlan_add_del_tunnel_v3_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_add_del_tunnel_v3_reply_t *a = va_arg (*args, vl_api_vxlan_add_del_tunnel_v3_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_add_del_tunnel_v3_reply_t: */
    s = format(s, "vl_api_vxlan_add_del_tunnel_v3_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_vxlan_tunnel_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_tunnel_dump_t *a = va_arg (*args, vl_api_vxlan_tunnel_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_tunnel_dump_t: */
    s = format(s, "vl_api_vxlan_tunnel_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_vxlan_tunnel_v2_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_tunnel_v2_dump_t *a = va_arg (*args, vl_api_vxlan_tunnel_v2_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_tunnel_v2_dump_t: */
    s = format(s, "vl_api_vxlan_tunnel_v2_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_vxlan_tunnel_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_tunnel_details_t *a = va_arg (*args, vl_api_vxlan_tunnel_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_tunnel_details_t: */
    s = format(s, "vl_api_vxlan_tunnel_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uinstance: %u", format_white_space, indent, a->instance);
    s = format(s, "\n%Usrc_address: %U", format_white_space, indent, format_vl_api_address_t, &a->src_address, indent);
    s = format(s, "\n%Udst_address: %U", format_white_space, indent, format_vl_api_address_t, &a->dst_address, indent);
    s = format(s, "\n%Umcast_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->mcast_sw_if_index, indent);
    s = format(s, "\n%Uencap_vrf_id: %u", format_white_space, indent, a->encap_vrf_id);
    s = format(s, "\n%Udecap_next_index: %u", format_white_space, indent, a->decap_next_index);
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    return s;
}

static inline u8 *vl_api_vxlan_tunnel_v2_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_tunnel_v2_details_t *a = va_arg (*args, vl_api_vxlan_tunnel_v2_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_tunnel_v2_details_t: */
    s = format(s, "vl_api_vxlan_tunnel_v2_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uinstance: %u", format_white_space, indent, a->instance);
    s = format(s, "\n%Usrc_address: %U", format_white_space, indent, format_vl_api_address_t, &a->src_address, indent);
    s = format(s, "\n%Udst_address: %U", format_white_space, indent, format_vl_api_address_t, &a->dst_address, indent);
    s = format(s, "\n%Usrc_port: %u", format_white_space, indent, a->src_port);
    s = format(s, "\n%Udst_port: %u", format_white_space, indent, a->dst_port);
    s = format(s, "\n%Umcast_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->mcast_sw_if_index, indent);
    s = format(s, "\n%Uencap_vrf_id: %u", format_white_space, indent, a->encap_vrf_id);
    s = format(s, "\n%Udecap_next_index: %u", format_white_space, indent, a->decap_next_index);
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    return s;
}

static inline u8 *vl_api_sw_interface_set_vxlan_bypass_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_set_vxlan_bypass_t *a = va_arg (*args, vl_api_sw_interface_set_vxlan_bypass_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_set_vxlan_bypass_t: */
    s = format(s, "vl_api_sw_interface_set_vxlan_bypass_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uis_ipv6: %u", format_white_space, indent, a->is_ipv6);
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}

static inline u8 *vl_api_sw_interface_set_vxlan_bypass_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_set_vxlan_bypass_reply_t *a = va_arg (*args, vl_api_sw_interface_set_vxlan_bypass_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_set_vxlan_bypass_reply_t: */
    s = format(s, "vl_api_sw_interface_set_vxlan_bypass_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_vxlan_offload_rx_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_offload_rx_t *a = va_arg (*args, vl_api_vxlan_offload_rx_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_offload_rx_t: */
    s = format(s, "vl_api_vxlan_offload_rx_t:");
    s = format(s, "\n%Uhw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->hw_if_index, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}

static inline u8 *vl_api_vxlan_offload_rx_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vxlan_offload_rx_reply_t *a = va_arg (*args, vl_api_vxlan_offload_rx_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vxlan_offload_rx_reply_t: */
    s = format(s, "vl_api_vxlan_offload_rx_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_vxlan_endianfun
#define included_vxlan_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_vxlan_add_del_tunnel_t_endian (vl_api_vxlan_add_del_tunnel_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    a->instance = clib_net_to_host_u32(a->instance);
    vl_api_address_t_endian(&a->src_address, to_net);
    vl_api_address_t_endian(&a->dst_address, to_net);
    vl_api_interface_index_t_endian(&a->mcast_sw_if_index, to_net);
    a->encap_vrf_id = clib_net_to_host_u32(a->encap_vrf_id);
    a->decap_next_index = clib_net_to_host_u32(a->decap_next_index);
    a->vni = clib_net_to_host_u32(a->vni);
}

static inline void vl_api_vxlan_add_del_tunnel_v2_t_endian (vl_api_vxlan_add_del_tunnel_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    a->instance = clib_net_to_host_u32(a->instance);
    vl_api_address_t_endian(&a->src_address, to_net);
    vl_api_address_t_endian(&a->dst_address, to_net);
    a->src_port = clib_net_to_host_u16(a->src_port);
    a->dst_port = clib_net_to_host_u16(a->dst_port);
    vl_api_interface_index_t_endian(&a->mcast_sw_if_index, to_net);
    a->encap_vrf_id = clib_net_to_host_u32(a->encap_vrf_id);
    a->decap_next_index = clib_net_to_host_u32(a->decap_next_index);
    a->vni = clib_net_to_host_u32(a->vni);
}

static inline void vl_api_vxlan_add_del_tunnel_v3_t_endian (vl_api_vxlan_add_del_tunnel_v3_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    a->instance = clib_net_to_host_u32(a->instance);
    vl_api_address_t_endian(&a->src_address, to_net);
    vl_api_address_t_endian(&a->dst_address, to_net);
    a->src_port = clib_net_to_host_u16(a->src_port);
    a->dst_port = clib_net_to_host_u16(a->dst_port);
    vl_api_interface_index_t_endian(&a->mcast_sw_if_index, to_net);
    a->encap_vrf_id = clib_net_to_host_u32(a->encap_vrf_id);
    a->decap_next_index = clib_net_to_host_u32(a->decap_next_index);
    a->vni = clib_net_to_host_u32(a->vni);
    /* a->is_l3 = a->is_l3 (no-op) */
}

static inline void vl_api_vxlan_add_del_tunnel_reply_t_endian (vl_api_vxlan_add_del_tunnel_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_vxlan_add_del_tunnel_v2_reply_t_endian (vl_api_vxlan_add_del_tunnel_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_vxlan_add_del_tunnel_v3_reply_t_endian (vl_api_vxlan_add_del_tunnel_v3_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_vxlan_tunnel_dump_t_endian (vl_api_vxlan_tunnel_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_vxlan_tunnel_v2_dump_t_endian (vl_api_vxlan_tunnel_v2_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_vxlan_tunnel_details_t_endian (vl_api_vxlan_tunnel_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->instance = clib_net_to_host_u32(a->instance);
    vl_api_address_t_endian(&a->src_address, to_net);
    vl_api_address_t_endian(&a->dst_address, to_net);
    vl_api_interface_index_t_endian(&a->mcast_sw_if_index, to_net);
    a->encap_vrf_id = clib_net_to_host_u32(a->encap_vrf_id);
    a->decap_next_index = clib_net_to_host_u32(a->decap_next_index);
    a->vni = clib_net_to_host_u32(a->vni);
}

static inline void vl_api_vxlan_tunnel_v2_details_t_endian (vl_api_vxlan_tunnel_v2_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->instance = clib_net_to_host_u32(a->instance);
    vl_api_address_t_endian(&a->src_address, to_net);
    vl_api_address_t_endian(&a->dst_address, to_net);
    a->src_port = clib_net_to_host_u16(a->src_port);
    a->dst_port = clib_net_to_host_u16(a->dst_port);
    vl_api_interface_index_t_endian(&a->mcast_sw_if_index, to_net);
    a->encap_vrf_id = clib_net_to_host_u32(a->encap_vrf_id);
    a->decap_next_index = clib_net_to_host_u32(a->decap_next_index);
    a->vni = clib_net_to_host_u32(a->vni);
}

static inline void vl_api_sw_interface_set_vxlan_bypass_t_endian (vl_api_sw_interface_set_vxlan_bypass_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->is_ipv6 = a->is_ipv6 (no-op) */
    /* a->enable = a->enable (no-op) */
}

static inline void vl_api_sw_interface_set_vxlan_bypass_reply_t_endian (vl_api_sw_interface_set_vxlan_bypass_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_vxlan_offload_rx_t_endian (vl_api_vxlan_offload_rx_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->hw_if_index, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->enable = a->enable (no-op) */
}

static inline void vl_api_vxlan_offload_rx_reply_t_endian (vl_api_vxlan_offload_rx_reply_t *a, bool to_net)
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
#ifndef included_vxlan_calcsizefun
#define included_vxlan_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_add_del_tunnel_t_calc_size (vl_api_vxlan_add_del_tunnel_t *a)
{
      return sizeof(*a) - sizeof(a->src_address) + vl_api_address_t_calc_size(&a->src_address) - sizeof(a->dst_address) + vl_api_address_t_calc_size(&a->dst_address) - sizeof(a->mcast_sw_if_index) + vl_api_interface_index_t_calc_size(&a->mcast_sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_add_del_tunnel_v2_t_calc_size (vl_api_vxlan_add_del_tunnel_v2_t *a)
{
      return sizeof(*a) - sizeof(a->src_address) + vl_api_address_t_calc_size(&a->src_address) - sizeof(a->dst_address) + vl_api_address_t_calc_size(&a->dst_address) - sizeof(a->mcast_sw_if_index) + vl_api_interface_index_t_calc_size(&a->mcast_sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_add_del_tunnel_v3_t_calc_size (vl_api_vxlan_add_del_tunnel_v3_t *a)
{
      return sizeof(*a) - sizeof(a->src_address) + vl_api_address_t_calc_size(&a->src_address) - sizeof(a->dst_address) + vl_api_address_t_calc_size(&a->dst_address) - sizeof(a->mcast_sw_if_index) + vl_api_interface_index_t_calc_size(&a->mcast_sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_add_del_tunnel_reply_t_calc_size (vl_api_vxlan_add_del_tunnel_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_add_del_tunnel_v2_reply_t_calc_size (vl_api_vxlan_add_del_tunnel_v2_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_add_del_tunnel_v3_reply_t_calc_size (vl_api_vxlan_add_del_tunnel_v3_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_tunnel_dump_t_calc_size (vl_api_vxlan_tunnel_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_tunnel_v2_dump_t_calc_size (vl_api_vxlan_tunnel_v2_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_tunnel_details_t_calc_size (vl_api_vxlan_tunnel_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->src_address) + vl_api_address_t_calc_size(&a->src_address) - sizeof(a->dst_address) + vl_api_address_t_calc_size(&a->dst_address) - sizeof(a->mcast_sw_if_index) + vl_api_interface_index_t_calc_size(&a->mcast_sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_tunnel_v2_details_t_calc_size (vl_api_vxlan_tunnel_v2_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->src_address) + vl_api_address_t_calc_size(&a->src_address) - sizeof(a->dst_address) + vl_api_address_t_calc_size(&a->dst_address) - sizeof(a->mcast_sw_if_index) + vl_api_interface_index_t_calc_size(&a->mcast_sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_set_vxlan_bypass_t_calc_size (vl_api_sw_interface_set_vxlan_bypass_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_set_vxlan_bypass_reply_t_calc_size (vl_api_sw_interface_set_vxlan_bypass_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_offload_rx_t_calc_size (vl_api_vxlan_offload_rx_t *a)
{
      return sizeof(*a) - sizeof(a->hw_if_index) + vl_api_interface_index_t_calc_size(&a->hw_if_index) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vxlan_offload_rx_reply_t_calc_size (vl_api_vxlan_offload_rx_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(vxlan.api, 2, 1, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(vxlan.api, 0x4d9cc2b3)

#endif

