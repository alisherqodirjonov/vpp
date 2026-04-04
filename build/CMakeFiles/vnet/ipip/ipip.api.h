/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: ipip.api
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
#warning no content included from ipip.api
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
#include <vnet/tunnel/tunnel_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_IPIP_ADD_TUNNEL, vl_api_ipip_add_tunnel_t_handler)
vl_msg_id(VL_API_IPIP_ADD_TUNNEL_REPLY, vl_api_ipip_add_tunnel_reply_t_handler)
vl_msg_id(VL_API_IPIP_DEL_TUNNEL, vl_api_ipip_del_tunnel_t_handler)
vl_msg_id(VL_API_IPIP_DEL_TUNNEL_REPLY, vl_api_ipip_del_tunnel_reply_t_handler)
vl_msg_id(VL_API_IPIP_6RD_ADD_TUNNEL, vl_api_ipip_6rd_add_tunnel_t_handler)
vl_msg_id(VL_API_IPIP_6RD_ADD_TUNNEL_REPLY, vl_api_ipip_6rd_add_tunnel_reply_t_handler)
vl_msg_id(VL_API_IPIP_6RD_DEL_TUNNEL, vl_api_ipip_6rd_del_tunnel_t_handler)
vl_msg_id(VL_API_IPIP_6RD_DEL_TUNNEL_REPLY, vl_api_ipip_6rd_del_tunnel_reply_t_handler)
vl_msg_id(VL_API_IPIP_TUNNEL_DUMP, vl_api_ipip_tunnel_dump_t_handler)
vl_msg_id(VL_API_IPIP_TUNNEL_DETAILS, vl_api_ipip_tunnel_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_ipip_add_tunnel_t, 1)
vl_msg_name(vl_api_ipip_add_tunnel_reply_t, 1)
vl_msg_name(vl_api_ipip_del_tunnel_t, 1)
vl_msg_name(vl_api_ipip_del_tunnel_reply_t, 1)
vl_msg_name(vl_api_ipip_6rd_add_tunnel_t, 1)
vl_msg_name(vl_api_ipip_6rd_add_tunnel_reply_t, 1)
vl_msg_name(vl_api_ipip_6rd_del_tunnel_t, 1)
vl_msg_name(vl_api_ipip_6rd_del_tunnel_reply_t, 1)
vl_msg_name(vl_api_ipip_tunnel_dump_t, 1)
vl_msg_name(vl_api_ipip_tunnel_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_ipip \
_(VL_API_IPIP_ADD_TUNNEL, ipip_add_tunnel, 2ac399f5) \
_(VL_API_IPIP_ADD_TUNNEL_REPLY, ipip_add_tunnel_reply, 5383d31f) \
_(VL_API_IPIP_DEL_TUNNEL, ipip_del_tunnel, f9e6675e) \
_(VL_API_IPIP_DEL_TUNNEL_REPLY, ipip_del_tunnel_reply, e8d4e804) \
_(VL_API_IPIP_6RD_ADD_TUNNEL, ipip_6rd_add_tunnel, b9ec1863) \
_(VL_API_IPIP_6RD_ADD_TUNNEL_REPLY, ipip_6rd_add_tunnel_reply, 5383d31f) \
_(VL_API_IPIP_6RD_DEL_TUNNEL, ipip_6rd_del_tunnel, f9e6675e) \
_(VL_API_IPIP_6RD_DEL_TUNNEL_REPLY, ipip_6rd_del_tunnel_reply, e8d4e804) \
_(VL_API_IPIP_TUNNEL_DUMP, ipip_tunnel_dump, f9e6675e) \
_(VL_API_IPIP_TUNNEL_DETAILS, ipip_tunnel_details, d31cb34e) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "ipip.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_ipip_printfun_types
#define included_ipip_printfun_types

static inline u8 *format_vl_api_ipip_tunnel_t (u8 *s, va_list * args)
{
    vl_api_ipip_tunnel_t *a = va_arg (*args, vl_api_ipip_tunnel_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uinstance: %u", format_white_space, indent, a->instance);
    s = format(s, "\n%Usrc: %U", format_white_space, indent, format_vl_api_address_t, &a->src, indent);
    s = format(s, "\n%Udst: %U", format_white_space, indent, format_vl_api_address_t, &a->dst, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Utable_id: %u", format_white_space, indent, a->table_id);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_tunnel_encap_decap_flags_t, &a->flags, indent);
    s = format(s, "\n%Umode: %U", format_white_space, indent, format_vl_api_tunnel_mode_t, &a->mode, indent);
    s = format(s, "\n%Udscp: %U", format_white_space, indent, format_vl_api_ip_dscp_t, &a->dscp, indent);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_ipip_printfun
#define included_ipip_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "ipip.api_tojson.h"
#include "ipip.api_fromjson.h"

static inline u8 *vl_api_ipip_add_tunnel_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipip_add_tunnel_t *a = va_arg (*args, vl_api_ipip_add_tunnel_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipip_add_tunnel_t: */
    s = format(s, "vl_api_ipip_add_tunnel_t:");
    s = format(s, "\n%Utunnel: %U", format_white_space, indent, format_vl_api_ipip_tunnel_t, &a->tunnel, indent);
    return s;
}

static inline u8 *vl_api_ipip_add_tunnel_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipip_add_tunnel_reply_t *a = va_arg (*args, vl_api_ipip_add_tunnel_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipip_add_tunnel_reply_t: */
    s = format(s, "vl_api_ipip_add_tunnel_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_ipip_del_tunnel_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipip_del_tunnel_t *a = va_arg (*args, vl_api_ipip_del_tunnel_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipip_del_tunnel_t: */
    s = format(s, "vl_api_ipip_del_tunnel_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_ipip_del_tunnel_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipip_del_tunnel_reply_t *a = va_arg (*args, vl_api_ipip_del_tunnel_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipip_del_tunnel_reply_t: */
    s = format(s, "vl_api_ipip_del_tunnel_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ipip_6rd_add_tunnel_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipip_6rd_add_tunnel_t *a = va_arg (*args, vl_api_ipip_6rd_add_tunnel_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipip_6rd_add_tunnel_t: */
    s = format(s, "vl_api_ipip_6rd_add_tunnel_t:");
    s = format(s, "\n%Uip6_table_id: %u", format_white_space, indent, a->ip6_table_id);
    s = format(s, "\n%Uip4_table_id: %u", format_white_space, indent, a->ip4_table_id);
    s = format(s, "\n%Uip6_prefix: %U", format_white_space, indent, format_vl_api_ip6_prefix_t, &a->ip6_prefix, indent);
    s = format(s, "\n%Uip4_prefix: %U", format_white_space, indent, format_vl_api_ip4_prefix_t, &a->ip4_prefix, indent);
    s = format(s, "\n%Uip4_src: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip4_src, indent);
    s = format(s, "\n%Usecurity_check: %u", format_white_space, indent, a->security_check);
    s = format(s, "\n%Utc_tos: %u", format_white_space, indent, a->tc_tos);
    return s;
}

static inline u8 *vl_api_ipip_6rd_add_tunnel_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipip_6rd_add_tunnel_reply_t *a = va_arg (*args, vl_api_ipip_6rd_add_tunnel_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipip_6rd_add_tunnel_reply_t: */
    s = format(s, "vl_api_ipip_6rd_add_tunnel_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_ipip_6rd_del_tunnel_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipip_6rd_del_tunnel_t *a = va_arg (*args, vl_api_ipip_6rd_del_tunnel_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipip_6rd_del_tunnel_t: */
    s = format(s, "vl_api_ipip_6rd_del_tunnel_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_ipip_6rd_del_tunnel_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipip_6rd_del_tunnel_reply_t *a = va_arg (*args, vl_api_ipip_6rd_del_tunnel_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipip_6rd_del_tunnel_reply_t: */
    s = format(s, "vl_api_ipip_6rd_del_tunnel_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ipip_tunnel_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipip_tunnel_dump_t *a = va_arg (*args, vl_api_ipip_tunnel_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipip_tunnel_dump_t: */
    s = format(s, "vl_api_ipip_tunnel_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_ipip_tunnel_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipip_tunnel_details_t *a = va_arg (*args, vl_api_ipip_tunnel_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipip_tunnel_details_t: */
    s = format(s, "vl_api_ipip_tunnel_details_t:");
    s = format(s, "\n%Utunnel: %U", format_white_space, indent, format_vl_api_ipip_tunnel_t, &a->tunnel, indent);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_ipip_endianfun
#define included_ipip_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_ipip_tunnel_t_endian (vl_api_ipip_tunnel_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->instance = clib_net_to_host_u32(a->instance);
    vl_api_address_t_endian(&a->src, to_net);
    vl_api_address_t_endian(&a->dst, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->table_id = clib_net_to_host_u32(a->table_id);
    vl_api_tunnel_encap_decap_flags_t_endian(&a->flags, to_net);
    vl_api_tunnel_mode_t_endian(&a->mode, to_net);
    vl_api_ip_dscp_t_endian(&a->dscp, to_net);
}

static inline void vl_api_ipip_add_tunnel_t_endian (vl_api_ipip_add_tunnel_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ipip_tunnel_t_endian(&a->tunnel, to_net);
}

static inline void vl_api_ipip_add_tunnel_reply_t_endian (vl_api_ipip_add_tunnel_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_ipip_del_tunnel_t_endian (vl_api_ipip_del_tunnel_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_ipip_del_tunnel_reply_t_endian (vl_api_ipip_del_tunnel_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ipip_6rd_add_tunnel_t_endian (vl_api_ipip_6rd_add_tunnel_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->ip6_table_id = clib_net_to_host_u32(a->ip6_table_id);
    a->ip4_table_id = clib_net_to_host_u32(a->ip4_table_id);
    vl_api_ip6_prefix_t_endian(&a->ip6_prefix, to_net);
    vl_api_ip4_prefix_t_endian(&a->ip4_prefix, to_net);
    vl_api_ip4_address_t_endian(&a->ip4_src, to_net);
    /* a->security_check = a->security_check (no-op) */
    /* a->tc_tos = a->tc_tos (no-op) */
}

static inline void vl_api_ipip_6rd_add_tunnel_reply_t_endian (vl_api_ipip_6rd_add_tunnel_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_ipip_6rd_del_tunnel_t_endian (vl_api_ipip_6rd_del_tunnel_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_ipip_6rd_del_tunnel_reply_t_endian (vl_api_ipip_6rd_del_tunnel_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ipip_tunnel_dump_t_endian (vl_api_ipip_tunnel_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_ipip_tunnel_details_t_endian (vl_api_ipip_tunnel_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ipip_tunnel_t_endian(&a->tunnel, to_net);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_ipip_calcsizefun
#define included_ipip_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_ipip_tunnel_t_calc_size (vl_api_ipip_tunnel_t *a)
{
      return sizeof(*a) - sizeof(a->src) + vl_api_address_t_calc_size(&a->src) - sizeof(a->dst) + vl_api_address_t_calc_size(&a->dst) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->flags) + vl_api_tunnel_encap_decap_flags_t_calc_size(&a->flags) - sizeof(a->mode) + vl_api_tunnel_mode_t_calc_size(&a->mode) - sizeof(a->dscp) + vl_api_ip_dscp_t_calc_size(&a->dscp);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipip_add_tunnel_t_calc_size (vl_api_ipip_add_tunnel_t *a)
{
      return sizeof(*a) - sizeof(a->tunnel) + vl_api_ipip_tunnel_t_calc_size(&a->tunnel);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipip_add_tunnel_reply_t_calc_size (vl_api_ipip_add_tunnel_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipip_del_tunnel_t_calc_size (vl_api_ipip_del_tunnel_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipip_del_tunnel_reply_t_calc_size (vl_api_ipip_del_tunnel_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipip_6rd_add_tunnel_t_calc_size (vl_api_ipip_6rd_add_tunnel_t *a)
{
      return sizeof(*a) - sizeof(a->ip6_prefix) + vl_api_ip6_prefix_t_calc_size(&a->ip6_prefix) - sizeof(a->ip4_prefix) + vl_api_ip4_prefix_t_calc_size(&a->ip4_prefix) - sizeof(a->ip4_src) + vl_api_ip4_address_t_calc_size(&a->ip4_src);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipip_6rd_add_tunnel_reply_t_calc_size (vl_api_ipip_6rd_add_tunnel_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipip_6rd_del_tunnel_t_calc_size (vl_api_ipip_6rd_del_tunnel_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipip_6rd_del_tunnel_reply_t_calc_size (vl_api_ipip_6rd_del_tunnel_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipip_tunnel_dump_t_calc_size (vl_api_ipip_tunnel_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipip_tunnel_details_t_calc_size (vl_api_ipip_tunnel_details_t *a)
{
      return sizeof(*a) - sizeof(a->tunnel) + vl_api_ipip_tunnel_t_calc_size(&a->tunnel);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(ipip.api, 2, 0, 2)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(ipip.api, 0x3c9c667)

#endif

