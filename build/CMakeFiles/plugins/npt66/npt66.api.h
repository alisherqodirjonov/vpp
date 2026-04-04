/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: npt66.api
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
#warning no content included from npt66.api
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
vl_msg_id(VL_API_NPT66_BINDING_ADD_DEL, vl_api_npt66_binding_add_del_t_handler)
vl_msg_id(VL_API_NPT66_BINDING_ADD_DEL_REPLY, vl_api_npt66_binding_add_del_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_npt66_binding_add_del_t, 1)
vl_msg_name(vl_api_npt66_binding_add_del_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_npt66 \
_(VL_API_NPT66_BINDING_ADD_DEL, npt66_binding_add_del, 8aa10a52) \
_(VL_API_NPT66_BINDING_ADD_DEL_REPLY, npt66_binding_add_del_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "npt66.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_npt66_printfun_types
#define included_npt66_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_npt66_printfun
#define included_npt66_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "npt66.api_tojson.h"
#include "npt66.api_fromjson.h"

static inline u8 *vl_api_npt66_binding_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_npt66_binding_add_del_t *a = va_arg (*args, vl_api_npt66_binding_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_npt66_binding_add_del_t: */
    s = format(s, "vl_api_npt66_binding_add_del_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uinternal: %U", format_white_space, indent, format_vl_api_ip6_prefix_t, &a->internal, indent);
    s = format(s, "\n%Uexternal: %U", format_white_space, indent, format_vl_api_ip6_prefix_t, &a->external, indent);
    return s;
}

static inline u8 *vl_api_npt66_binding_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_npt66_binding_add_del_reply_t *a = va_arg (*args, vl_api_npt66_binding_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_npt66_binding_add_del_reply_t: */
    s = format(s, "vl_api_npt66_binding_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_npt66_endianfun
#define included_npt66_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_npt66_binding_add_del_t_endian (vl_api_npt66_binding_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_ip6_prefix_t_endian(&a->internal, to_net);
    vl_api_ip6_prefix_t_endian(&a->external, to_net);
}

static inline void vl_api_npt66_binding_add_del_reply_t_endian (vl_api_npt66_binding_add_del_reply_t *a, bool to_net)
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
#ifndef included_npt66_calcsizefun
#define included_npt66_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_npt66_binding_add_del_t_calc_size (vl_api_npt66_binding_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->internal) + vl_api_ip6_prefix_t_calc_size(&a->internal) - sizeof(a->external) + vl_api_ip6_prefix_t_calc_size(&a->external);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_npt66_binding_add_del_reply_t_calc_size (vl_api_npt66_binding_add_del_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(npt66.api, 0, 0, 1)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(npt66.api, 0x41148766)

#endif

