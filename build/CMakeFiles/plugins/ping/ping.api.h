/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: ping.api
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
#warning no content included from ping.api
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
vl_msg_id(VL_API_WANT_PING_FINISHED_EVENTS, vl_api_want_ping_finished_events_t_handler)
vl_msg_id(VL_API_WANT_PING_FINISHED_EVENTS_REPLY, vl_api_want_ping_finished_events_reply_t_handler)
vl_msg_id(VL_API_PING_FINISHED_EVENT, vl_api_ping_finished_event_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_want_ping_finished_events_t, 1)
vl_msg_name(vl_api_want_ping_finished_events_reply_t, 1)
vl_msg_name(vl_api_ping_finished_event_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_ping \
_(VL_API_WANT_PING_FINISHED_EVENTS, want_ping_finished_events, e79ee58b) \
_(VL_API_WANT_PING_FINISHED_EVENTS_REPLY, want_ping_finished_events_reply, e8d4e804) \
_(VL_API_PING_FINISHED_EVENT, ping_finished_event, 397ccf72) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "ping.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_ping_printfun_types
#define included_ping_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_ping_printfun
#define included_ping_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "ping.api_tojson.h"
#include "ping.api_fromjson.h"

static inline u8 *vl_api_want_ping_finished_events_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_want_ping_finished_events_t *a = va_arg (*args, vl_api_want_ping_finished_events_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_want_ping_finished_events_t: */
    s = format(s, "vl_api_want_ping_finished_events_t:");
    s = format(s, "\n%Uaddress: %U", format_white_space, indent, format_vl_api_address_t, &a->address, indent);
    s = format(s, "\n%Urepeat: %u", format_white_space, indent, a->repeat);
    s = format(s, "\n%Uinterval: %.2f", format_white_space, indent, a->interval);
    return s;
}

static inline u8 *vl_api_want_ping_finished_events_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_want_ping_finished_events_reply_t *a = va_arg (*args, vl_api_want_ping_finished_events_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_want_ping_finished_events_reply_t: */
    s = format(s, "vl_api_want_ping_finished_events_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ping_finished_event_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ping_finished_event_t *a = va_arg (*args, vl_api_ping_finished_event_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ping_finished_event_t: */
    s = format(s, "vl_api_ping_finished_event_t:");
    s = format(s, "\n%Urequest_count: %u", format_white_space, indent, a->request_count);
    s = format(s, "\n%Ureply_count: %u", format_white_space, indent, a->reply_count);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_ping_endianfun
#define included_ping_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_want_ping_finished_events_t_endian (vl_api_want_ping_finished_events_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_address_t_endian(&a->address, to_net);
    a->repeat = clib_net_to_host_u32(a->repeat);
    a->interval = clib_net_to_host_f64(a->interval);
}

static inline void vl_api_want_ping_finished_events_reply_t_endian (vl_api_want_ping_finished_events_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ping_finished_event_t_endian (vl_api_ping_finished_event_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->request_count = clib_net_to_host_u32(a->request_count);
    a->reply_count = clib_net_to_host_u32(a->reply_count);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_ping_calcsizefun
#define included_ping_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_want_ping_finished_events_t_calc_size (vl_api_want_ping_finished_events_t *a)
{
      return sizeof(*a) - sizeof(a->address) + vl_api_address_t_calc_size(&a->address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_want_ping_finished_events_reply_t_calc_size (vl_api_want_ping_finished_events_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ping_finished_event_t_calc_size (vl_api_ping_finished_event_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(ping.api, 0, 1, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(ping.api, 0xbdcc118)

#endif

