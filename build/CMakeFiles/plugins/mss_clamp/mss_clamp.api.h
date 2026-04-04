/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: mss_clamp.api
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
#warning no content included from mss_clamp.api
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
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_MSS_CLAMP_ENABLE_DISABLE, vl_api_mss_clamp_enable_disable_t_handler)
vl_msg_id(VL_API_MSS_CLAMP_ENABLE_DISABLE_REPLY, vl_api_mss_clamp_enable_disable_reply_t_handler)
vl_msg_id(VL_API_MSS_CLAMP_GET, vl_api_mss_clamp_get_t_handler)
vl_msg_id(VL_API_MSS_CLAMP_GET_REPLY, vl_api_mss_clamp_get_reply_t_handler)
vl_msg_id(VL_API_MSS_CLAMP_DETAILS, vl_api_mss_clamp_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_mss_clamp_enable_disable_t, 1)
vl_msg_name(vl_api_mss_clamp_enable_disable_reply_t, 1)
vl_msg_name(vl_api_mss_clamp_get_t, 1)
vl_msg_name(vl_api_mss_clamp_get_reply_t, 1)
vl_msg_name(vl_api_mss_clamp_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_mss_clamp \
_(VL_API_MSS_CLAMP_ENABLE_DISABLE, mss_clamp_enable_disable, d31b44e3) \
_(VL_API_MSS_CLAMP_ENABLE_DISABLE_REPLY, mss_clamp_enable_disable_reply, e8d4e804) \
_(VL_API_MSS_CLAMP_GET, mss_clamp_get, 47250981) \
_(VL_API_MSS_CLAMP_GET_REPLY, mss_clamp_get_reply, 53b48f5d) \
_(VL_API_MSS_CLAMP_DETAILS, mss_clamp_details, d3a4de61) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "mss_clamp.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_mss_clamp_printfun_types
#define included_mss_clamp_printfun_types

static inline u8 *format_vl_api_mss_clamp_dir_t (u8 *s, va_list * args)
{
    vl_api_mss_clamp_dir_t *a = va_arg (*args, vl_api_mss_clamp_dir_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "MSS_CLAMP_DIR_NONE");
    case 1:
        return format(s, "MSS_CLAMP_DIR_RX");
    case 2:
        return format(s, "MSS_CLAMP_DIR_TX");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_mss_clamp_printfun
#define included_mss_clamp_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "mss_clamp.api_tojson.h"
#include "mss_clamp.api_fromjson.h"

static inline u8 *vl_api_mss_clamp_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mss_clamp_enable_disable_t *a = va_arg (*args, vl_api_mss_clamp_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mss_clamp_enable_disable_t: */
    s = format(s, "vl_api_mss_clamp_enable_disable_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uipv4_mss: %u", format_white_space, indent, a->ipv4_mss);
    s = format(s, "\n%Uipv6_mss: %u", format_white_space, indent, a->ipv6_mss);
    s = format(s, "\n%Uipv4_direction: %U", format_white_space, indent, format_vl_api_mss_clamp_dir_t, &a->ipv4_direction, indent);
    s = format(s, "\n%Uipv6_direction: %U", format_white_space, indent, format_vl_api_mss_clamp_dir_t, &a->ipv6_direction, indent);
    return s;
}

static inline u8 *vl_api_mss_clamp_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mss_clamp_enable_disable_reply_t *a = va_arg (*args, vl_api_mss_clamp_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mss_clamp_enable_disable_reply_t: */
    s = format(s, "vl_api_mss_clamp_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_mss_clamp_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mss_clamp_get_t *a = va_arg (*args, vl_api_mss_clamp_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mss_clamp_get_t: */
    s = format(s, "vl_api_mss_clamp_get_t:");
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_mss_clamp_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mss_clamp_get_reply_t *a = va_arg (*args, vl_api_mss_clamp_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mss_clamp_get_reply_t: */
    s = format(s, "vl_api_mss_clamp_get_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_mss_clamp_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mss_clamp_details_t *a = va_arg (*args, vl_api_mss_clamp_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mss_clamp_details_t: */
    s = format(s, "vl_api_mss_clamp_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uipv4_mss: %u", format_white_space, indent, a->ipv4_mss);
    s = format(s, "\n%Uipv6_mss: %u", format_white_space, indent, a->ipv6_mss);
    s = format(s, "\n%Uipv4_direction: %U", format_white_space, indent, format_vl_api_mss_clamp_dir_t, &a->ipv4_direction, indent);
    s = format(s, "\n%Uipv6_direction: %U", format_white_space, indent, format_vl_api_mss_clamp_dir_t, &a->ipv6_direction, indent);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_mss_clamp_endianfun
#define included_mss_clamp_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_mss_clamp_dir_t_endian (vl_api_mss_clamp_dir_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->mss_clamp_dir = a->mss_clamp_dir (no-op) */
}

static inline void vl_api_mss_clamp_enable_disable_t_endian (vl_api_mss_clamp_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->ipv4_mss = clib_net_to_host_u16(a->ipv4_mss);
    a->ipv6_mss = clib_net_to_host_u16(a->ipv6_mss);
    vl_api_mss_clamp_dir_t_endian(&a->ipv4_direction, to_net);
    vl_api_mss_clamp_dir_t_endian(&a->ipv6_direction, to_net);
}

static inline void vl_api_mss_clamp_enable_disable_reply_t_endian (vl_api_mss_clamp_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_mss_clamp_get_t_endian (vl_api_mss_clamp_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->cursor = clib_net_to_host_u32(a->cursor);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_mss_clamp_get_reply_t_endian (vl_api_mss_clamp_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_mss_clamp_details_t_endian (vl_api_mss_clamp_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->ipv4_mss = clib_net_to_host_u16(a->ipv4_mss);
    a->ipv6_mss = clib_net_to_host_u16(a->ipv6_mss);
    vl_api_mss_clamp_dir_t_endian(&a->ipv4_direction, to_net);
    vl_api_mss_clamp_dir_t_endian(&a->ipv6_direction, to_net);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_mss_clamp_calcsizefun
#define included_mss_clamp_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_mss_clamp_dir_t_calc_size (vl_api_mss_clamp_dir_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mss_clamp_enable_disable_t_calc_size (vl_api_mss_clamp_enable_disable_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->ipv4_direction) + vl_api_mss_clamp_dir_t_calc_size(&a->ipv4_direction) - sizeof(a->ipv6_direction) + vl_api_mss_clamp_dir_t_calc_size(&a->ipv6_direction);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mss_clamp_enable_disable_reply_t_calc_size (vl_api_mss_clamp_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mss_clamp_get_t_calc_size (vl_api_mss_clamp_get_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mss_clamp_get_reply_t_calc_size (vl_api_mss_clamp_get_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mss_clamp_details_t_calc_size (vl_api_mss_clamp_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->ipv4_direction) + vl_api_mss_clamp_dir_t_calc_size(&a->ipv4_direction) - sizeof(a->ipv6_direction) + vl_api_mss_clamp_dir_t_calc_size(&a->ipv6_direction);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(mss_clamp.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(mss_clamp.api, 0x74a0c674)

#endif

