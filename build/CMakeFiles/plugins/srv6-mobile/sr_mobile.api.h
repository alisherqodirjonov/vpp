/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: sr_mobile.api
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
#warning no content included from sr_mobile.api
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
#include <vnet/srv6/sr_types.api.h>
#include <vnet/srv6/sr.api.h>
#include <srv6-mobile/sr_mobile_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_SR_MOBILE_LOCALSID_ADD_DEL, vl_api_sr_mobile_localsid_add_del_t_handler)
vl_msg_id(VL_API_SR_MOBILE_LOCALSID_ADD_DEL_REPLY, vl_api_sr_mobile_localsid_add_del_reply_t_handler)
vl_msg_id(VL_API_SR_MOBILE_POLICY_ADD, vl_api_sr_mobile_policy_add_t_handler)
vl_msg_id(VL_API_SR_MOBILE_POLICY_ADD_REPLY, vl_api_sr_mobile_policy_add_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_sr_mobile_localsid_add_del_t, 1)
vl_msg_name(vl_api_sr_mobile_localsid_add_del_reply_t, 1)
vl_msg_name(vl_api_sr_mobile_policy_add_t, 1)
vl_msg_name(vl_api_sr_mobile_policy_add_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_sr_mobile \
_(VL_API_SR_MOBILE_LOCALSID_ADD_DEL, sr_mobile_localsid_add_del, b85a7ed7) \
_(VL_API_SR_MOBILE_LOCALSID_ADD_DEL_REPLY, sr_mobile_localsid_add_del_reply, e8d4e804) \
_(VL_API_SR_MOBILE_POLICY_ADD, sr_mobile_policy_add, 8f051658) \
_(VL_API_SR_MOBILE_POLICY_ADD_REPLY, sr_mobile_policy_add_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "sr_mobile.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_sr_mobile_printfun_types
#define included_sr_mobile_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_sr_mobile_printfun
#define included_sr_mobile_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "sr_mobile.api_tojson.h"
#include "sr_mobile.api_fromjson.h"

static inline u8 *vl_api_sr_mobile_localsid_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_mobile_localsid_add_del_t *a = va_arg (*args, vl_api_sr_mobile_localsid_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_mobile_localsid_add_del_t: */
    s = format(s, "vl_api_sr_mobile_localsid_add_del_t:");
    s = format(s, "\n%Uis_del: %u", format_white_space, indent, a->is_del);
    s = format(s, "\n%Ulocalsid_prefix: %U", format_white_space, indent, format_vl_api_ip6_prefix_t, &a->localsid_prefix, indent);
    s = format(s, "\n%Ubehavior: %s", format_white_space, indent, a->behavior);
    s = format(s, "\n%Ufib_table: %u", format_white_space, indent, a->fib_table);
    s = format(s, "\n%Ulocal_fib_table: %u", format_white_space, indent, a->local_fib_table);
    s = format(s, "\n%Udrop_in: %u", format_white_space, indent, a->drop_in);
    s = format(s, "\n%Unhtype: %U", format_white_space, indent, format_vl_api_sr_mobile_nhtype_t, &a->nhtype, indent);
    s = format(s, "\n%Usr_prefix: %U", format_white_space, indent, format_vl_api_ip6_prefix_t, &a->sr_prefix, indent);
    s = format(s, "\n%Uv4src_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->v4src_addr, indent);
    s = format(s, "\n%Uv4src_position: %u", format_white_space, indent, a->v4src_position);
    return s;
}

static inline u8 *vl_api_sr_mobile_localsid_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_mobile_localsid_add_del_reply_t *a = va_arg (*args, vl_api_sr_mobile_localsid_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_mobile_localsid_add_del_reply_t: */
    s = format(s, "vl_api_sr_mobile_localsid_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sr_mobile_policy_add_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_mobile_policy_add_t *a = va_arg (*args, vl_api_sr_mobile_policy_add_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_mobile_policy_add_t: */
    s = format(s, "vl_api_sr_mobile_policy_add_t:");
    s = format(s, "\n%Ubsid_addr: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->bsid_addr, indent);
    s = format(s, "\n%Usr_prefix: %U", format_white_space, indent, format_vl_api_ip6_prefix_t, &a->sr_prefix, indent);
    s = format(s, "\n%Uv6src_prefix: %U", format_white_space, indent, format_vl_api_ip6_prefix_t, &a->v6src_prefix, indent);
    s = format(s, "\n%Ubehavior: %s", format_white_space, indent, a->behavior);
    s = format(s, "\n%Ufib_table: %u", format_white_space, indent, a->fib_table);
    s = format(s, "\n%Ulocal_fib_table: %u", format_white_space, indent, a->local_fib_table);
    s = format(s, "\n%Uencap_src: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->encap_src, indent);
    s = format(s, "\n%Udrop_in: %u", format_white_space, indent, a->drop_in);
    s = format(s, "\n%Unhtype: %U", format_white_space, indent, format_vl_api_sr_mobile_nhtype_t, &a->nhtype, indent);
    return s;
}

static inline u8 *vl_api_sr_mobile_policy_add_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sr_mobile_policy_add_reply_t *a = va_arg (*args, vl_api_sr_mobile_policy_add_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sr_mobile_policy_add_reply_t: */
    s = format(s, "vl_api_sr_mobile_policy_add_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_sr_mobile_endianfun
#define included_sr_mobile_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_sr_mobile_localsid_add_del_t_endian (vl_api_sr_mobile_localsid_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_del = a->is_del (no-op) */
    vl_api_ip6_prefix_t_endian(&a->localsid_prefix, to_net);
    /* a->behavior = a->behavior (no-op) */
    a->fib_table = clib_net_to_host_u32(a->fib_table);
    a->local_fib_table = clib_net_to_host_u32(a->local_fib_table);
    /* a->drop_in = a->drop_in (no-op) */
    vl_api_sr_mobile_nhtype_t_endian(&a->nhtype, to_net);
    vl_api_ip6_prefix_t_endian(&a->sr_prefix, to_net);
    vl_api_ip4_address_t_endian(&a->v4src_addr, to_net);
    a->v4src_position = clib_net_to_host_u32(a->v4src_position);
}

static inline void vl_api_sr_mobile_localsid_add_del_reply_t_endian (vl_api_sr_mobile_localsid_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sr_mobile_policy_add_t_endian (vl_api_sr_mobile_policy_add_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip6_address_t_endian(&a->bsid_addr, to_net);
    vl_api_ip6_prefix_t_endian(&a->sr_prefix, to_net);
    vl_api_ip6_prefix_t_endian(&a->v6src_prefix, to_net);
    /* a->behavior = a->behavior (no-op) */
    a->fib_table = clib_net_to_host_u32(a->fib_table);
    a->local_fib_table = clib_net_to_host_u32(a->local_fib_table);
    vl_api_ip6_address_t_endian(&a->encap_src, to_net);
    /* a->drop_in = a->drop_in (no-op) */
    vl_api_sr_mobile_nhtype_t_endian(&a->nhtype, to_net);
}

static inline void vl_api_sr_mobile_policy_add_reply_t_endian (vl_api_sr_mobile_policy_add_reply_t *a, bool to_net)
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
#ifndef included_sr_mobile_calcsizefun
#define included_sr_mobile_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_mobile_localsid_add_del_t_calc_size (vl_api_sr_mobile_localsid_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->localsid_prefix) + vl_api_ip6_prefix_t_calc_size(&a->localsid_prefix) - sizeof(a->nhtype) + vl_api_sr_mobile_nhtype_t_calc_size(&a->nhtype) - sizeof(a->sr_prefix) + vl_api_ip6_prefix_t_calc_size(&a->sr_prefix) - sizeof(a->v4src_addr) + vl_api_ip4_address_t_calc_size(&a->v4src_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_mobile_localsid_add_del_reply_t_calc_size (vl_api_sr_mobile_localsid_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_mobile_policy_add_t_calc_size (vl_api_sr_mobile_policy_add_t *a)
{
      return sizeof(*a) - sizeof(a->bsid_addr) + vl_api_ip6_address_t_calc_size(&a->bsid_addr) - sizeof(a->sr_prefix) + vl_api_ip6_prefix_t_calc_size(&a->sr_prefix) - sizeof(a->v6src_prefix) + vl_api_ip6_prefix_t_calc_size(&a->v6src_prefix) - sizeof(a->encap_src) + vl_api_ip6_address_t_calc_size(&a->encap_src) - sizeof(a->nhtype) + vl_api_sr_mobile_nhtype_t_calc_size(&a->nhtype);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_mobile_policy_add_reply_t_calc_size (vl_api_sr_mobile_policy_add_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(sr_mobile.api, 0, 1, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(sr_mobile.api, 0xdfd0b506)

#endif

