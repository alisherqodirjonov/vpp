/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: feature.api
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
#warning no content included from feature.api
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
vl_msg_id(VL_API_FEATURE_ENABLE_DISABLE, vl_api_feature_enable_disable_t_handler)
vl_msg_id(VL_API_FEATURE_ENABLE_DISABLE_REPLY, vl_api_feature_enable_disable_reply_t_handler)
vl_msg_id(VL_API_FEATURE_IS_ENABLED, vl_api_feature_is_enabled_t_handler)
vl_msg_id(VL_API_FEATURE_IS_ENABLED_REPLY, vl_api_feature_is_enabled_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_feature_enable_disable_t, 1)
vl_msg_name(vl_api_feature_enable_disable_reply_t, 1)
vl_msg_name(vl_api_feature_is_enabled_t, 1)
vl_msg_name(vl_api_feature_is_enabled_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_feature \
_(VL_API_FEATURE_ENABLE_DISABLE, feature_enable_disable, 7531c862) \
_(VL_API_FEATURE_ENABLE_DISABLE_REPLY, feature_enable_disable_reply, e8d4e804) \
_(VL_API_FEATURE_IS_ENABLED, feature_is_enabled, 55db09e2) \
_(VL_API_FEATURE_IS_ENABLED_REPLY, feature_is_enabled_reply, 03f284b5) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "feature.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_feature_printfun_types
#define included_feature_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_feature_printfun
#define included_feature_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "feature.api_tojson.h"
#include "feature.api_fromjson.h"

static inline u8 *vl_api_feature_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_feature_enable_disable_t *a = va_arg (*args, vl_api_feature_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_feature_enable_disable_t: */
    s = format(s, "vl_api_feature_enable_disable_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    s = format(s, "\n%Uarc_name: %s", format_white_space, indent, a->arc_name);
    s = format(s, "\n%Ufeature_name: %s", format_white_space, indent, a->feature_name);
    return s;
}

static inline u8 *vl_api_feature_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_feature_enable_disable_reply_t *a = va_arg (*args, vl_api_feature_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_feature_enable_disable_reply_t: */
    s = format(s, "vl_api_feature_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_feature_is_enabled_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_feature_is_enabled_t *a = va_arg (*args, vl_api_feature_is_enabled_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_feature_is_enabled_t: */
    s = format(s, "vl_api_feature_is_enabled_t:");
    s = format(s, "\n%Uarc_name: %s", format_white_space, indent, a->arc_name);
    s = format(s, "\n%Ufeature_name: %s", format_white_space, indent, a->feature_name);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_feature_is_enabled_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_feature_is_enabled_reply_t *a = va_arg (*args, vl_api_feature_is_enabled_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_feature_is_enabled_reply_t: */
    s = format(s, "vl_api_feature_is_enabled_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uis_enabled: %u", format_white_space, indent, a->is_enabled);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_feature_endianfun
#define included_feature_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_feature_enable_disable_t_endian (vl_api_feature_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->enable = a->enable (no-op) */
    /* a->arc_name = a->arc_name (no-op) */
    /* a->feature_name = a->feature_name (no-op) */
}

static inline void vl_api_feature_enable_disable_reply_t_endian (vl_api_feature_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_feature_is_enabled_t_endian (vl_api_feature_is_enabled_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->arc_name = a->arc_name (no-op) */
    /* a->feature_name = a->feature_name (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_feature_is_enabled_reply_t_endian (vl_api_feature_is_enabled_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->is_enabled = a->is_enabled (no-op) */
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_feature_calcsizefun
#define included_feature_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_feature_enable_disable_t_calc_size (vl_api_feature_enable_disable_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_feature_enable_disable_reply_t_calc_size (vl_api_feature_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_feature_is_enabled_t_calc_size (vl_api_feature_is_enabled_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_feature_is_enabled_reply_t_calc_size (vl_api_feature_is_enabled_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(feature.api, 1, 0, 2)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(feature.api, 0xea1b6429)

#endif

