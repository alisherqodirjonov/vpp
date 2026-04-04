/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: mdata.api
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
#warning no content included from mdata.api
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
vl_msg_id(VL_API_MDATA_ENABLE_DISABLE, vl_api_mdata_enable_disable_t_handler)
vl_msg_id(VL_API_MDATA_ENABLE_DISABLE_REPLY, vl_api_mdata_enable_disable_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_mdata_enable_disable_t, 1)
vl_msg_name(vl_api_mdata_enable_disable_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_mdata \
_(VL_API_MDATA_ENABLE_DISABLE, mdata_enable_disable, 2e7b47df) \
_(VL_API_MDATA_ENABLE_DISABLE_REPLY, mdata_enable_disable_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "mdata.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_mdata_printfun_types
#define included_mdata_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_mdata_printfun
#define included_mdata_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "mdata.api_tojson.h"
#include "mdata.api_fromjson.h"

static inline u8 *vl_api_mdata_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mdata_enable_disable_t *a = va_arg (*args, vl_api_mdata_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mdata_enable_disable_t: */
    s = format(s, "vl_api_mdata_enable_disable_t:");
    s = format(s, "\n%Uenable_disable: %u", format_white_space, indent, a->enable_disable);
    return s;
}

static inline u8 *vl_api_mdata_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_mdata_enable_disable_reply_t *a = va_arg (*args, vl_api_mdata_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_mdata_enable_disable_reply_t: */
    s = format(s, "vl_api_mdata_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_mdata_endianfun
#define included_mdata_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_mdata_enable_disable_t_endian (vl_api_mdata_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->enable_disable = a->enable_disable (no-op) */
}

static inline void vl_api_mdata_enable_disable_reply_t_endian (vl_api_mdata_enable_disable_reply_t *a, bool to_net)
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
#ifndef included_mdata_calcsizefun
#define included_mdata_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_mdata_enable_disable_t_calc_size (vl_api_mdata_enable_disable_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mdata_enable_disable_reply_t_calc_size (vl_api_mdata_enable_disable_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(mdata.api, 0, 1, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(mdata.api, 0x8cfa825e)

#endif

