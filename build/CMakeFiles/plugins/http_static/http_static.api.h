/*
 * VLIB API definitions 2026-04-04 08:31:59
 * Input file: http_static.api
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
#warning no content included from http_static.api
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
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_HTTP_STATIC_ENABLE_V4, vl_api_http_static_enable_v4_t_handler)
vl_msg_id(VL_API_HTTP_STATIC_ENABLE_V4_REPLY, vl_api_http_static_enable_v4_reply_t_handler)
vl_msg_id(VL_API_HTTP_STATIC_ENABLE_V5, vl_api_http_static_enable_v5_t_handler)
vl_msg_id(VL_API_HTTP_STATIC_ENABLE_V5_REPLY, vl_api_http_static_enable_v5_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_http_static_enable_v4_t, 1)
vl_msg_name(vl_api_http_static_enable_v4_reply_t, 1)
vl_msg_name(vl_api_http_static_enable_v5_t, 1)
vl_msg_name(vl_api_http_static_enable_v5_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_http_static \
_(VL_API_HTTP_STATIC_ENABLE_V4, http_static_enable_v4, 37540bfc) \
_(VL_API_HTTP_STATIC_ENABLE_V4_REPLY, http_static_enable_v4_reply, e8d4e804) \
_(VL_API_HTTP_STATIC_ENABLE_V5, http_static_enable_v5, 8bf84069) \
_(VL_API_HTTP_STATIC_ENABLE_V5_REPLY, http_static_enable_v5_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "http_static.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_http_static_printfun_types
#define included_http_static_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_http_static_printfun
#define included_http_static_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "http_static.api_tojson.h"
#include "http_static.api_fromjson.h"

static inline u8 *vl_api_http_static_enable_v4_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_http_static_enable_v4_t *a = va_arg (*args, vl_api_http_static_enable_v4_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_http_static_enable_v4_t: */
    s = format(s, "vl_api_http_static_enable_v4_t:");
    s = format(s, "\n%Ufifo_size: %u", format_white_space, indent, a->fifo_size);
    s = format(s, "\n%Ucache_size_limit: %u", format_white_space, indent, a->cache_size_limit);
    s = format(s, "\n%Umax_age: %u", format_white_space, indent, a->max_age);
    s = format(s, "\n%Ukeepalive_timeout: %u", format_white_space, indent, a->keepalive_timeout);
    s = format(s, "\n%Umax_body_size: %llu", format_white_space, indent, a->max_body_size);
    s = format(s, "\n%Uprealloc_fifos: %u", format_white_space, indent, a->prealloc_fifos);
    s = format(s, "\n%Uprivate_segment_size: %u", format_white_space, indent, a->private_segment_size);
    s = format(s, "\n%Uwww_root: %s", format_white_space, indent, a->www_root);
    s = format(s, "\n%Uuri: %s", format_white_space, indent, a->uri);
    return s;
}

static inline u8 *vl_api_http_static_enable_v4_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_http_static_enable_v4_reply_t *a = va_arg (*args, vl_api_http_static_enable_v4_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_http_static_enable_v4_reply_t: */
    s = format(s, "vl_api_http_static_enable_v4_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_http_static_enable_v5_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_http_static_enable_v5_t *a = va_arg (*args, vl_api_http_static_enable_v5_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_http_static_enable_v5_t: */
    s = format(s, "vl_api_http_static_enable_v5_t:");
    s = format(s, "\n%Ufifo_size: %u", format_white_space, indent, a->fifo_size);
    s = format(s, "\n%Ucache_size_limit: %u", format_white_space, indent, a->cache_size_limit);
    s = format(s, "\n%Umax_age: %u", format_white_space, indent, a->max_age);
    s = format(s, "\n%Ukeepalive_timeout: %u", format_white_space, indent, a->keepalive_timeout);
    s = format(s, "\n%Umax_body_size: %llu", format_white_space, indent, a->max_body_size);
    s = format(s, "\n%Urx_buff_thresh: %u", format_white_space, indent, a->rx_buff_thresh);
    s = format(s, "\n%Uprealloc_fifos: %u", format_white_space, indent, a->prealloc_fifos);
    s = format(s, "\n%Uprivate_segment_size: %u", format_white_space, indent, a->private_segment_size);
    s = format(s, "\n%Uwww_root: %s", format_white_space, indent, a->www_root);
    s = format(s, "\n%Uuri: %s", format_white_space, indent, a->uri);
    return s;
}

static inline u8 *vl_api_http_static_enable_v5_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_http_static_enable_v5_reply_t *a = va_arg (*args, vl_api_http_static_enable_v5_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_http_static_enable_v5_reply_t: */
    s = format(s, "vl_api_http_static_enable_v5_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_http_static_endianfun
#define included_http_static_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_http_static_enable_v4_t_endian (vl_api_http_static_enable_v4_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->fifo_size = clib_net_to_host_u32(a->fifo_size);
    a->cache_size_limit = clib_net_to_host_u32(a->cache_size_limit);
    a->max_age = clib_net_to_host_u32(a->max_age);
    a->keepalive_timeout = clib_net_to_host_u32(a->keepalive_timeout);
    a->max_body_size = clib_net_to_host_u64(a->max_body_size);
    a->prealloc_fifos = clib_net_to_host_u32(a->prealloc_fifos);
    a->private_segment_size = clib_net_to_host_u32(a->private_segment_size);
    /* a->www_root = a->www_root (no-op) */
    /* a->uri = a->uri (no-op) */
}

static inline void vl_api_http_static_enable_v4_reply_t_endian (vl_api_http_static_enable_v4_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_http_static_enable_v5_t_endian (vl_api_http_static_enable_v5_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->fifo_size = clib_net_to_host_u32(a->fifo_size);
    a->cache_size_limit = clib_net_to_host_u32(a->cache_size_limit);
    a->max_age = clib_net_to_host_u32(a->max_age);
    a->keepalive_timeout = clib_net_to_host_u32(a->keepalive_timeout);
    a->max_body_size = clib_net_to_host_u64(a->max_body_size);
    a->rx_buff_thresh = clib_net_to_host_u32(a->rx_buff_thresh);
    a->prealloc_fifos = clib_net_to_host_u32(a->prealloc_fifos);
    a->private_segment_size = clib_net_to_host_u32(a->private_segment_size);
    /* a->www_root = a->www_root (no-op) */
    /* a->uri = a->uri (no-op) */
}

static inline void vl_api_http_static_enable_v5_reply_t_endian (vl_api_http_static_enable_v5_reply_t *a, bool to_net)
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
#ifndef included_http_static_calcsizefun
#define included_http_static_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_http_static_enable_v4_t_calc_size (vl_api_http_static_enable_v4_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_http_static_enable_v4_reply_t_calc_size (vl_api_http_static_enable_v4_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_http_static_enable_v5_t_calc_size (vl_api_http_static_enable_v5_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_http_static_enable_v5_reply_t_calc_size (vl_api_http_static_enable_v5_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(http_static.api, 2, 5, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(http_static.api, 0xa4be530f)

#endif

