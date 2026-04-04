/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: nat_types.api
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
#warning no content included from nat_types.api
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
#endif
/****** Message names ******/

#ifdef vl_msg_name
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_nat_types 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "nat_types.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_nat_types_printfun_types
#define included_nat_types_printfun_types

static inline u8 *format_vl_api_nat_timeouts_t (u8 *s, va_list * args)
{
    vl_api_nat_timeouts_t *a = va_arg (*args, vl_api_nat_timeouts_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uudp: %u", format_white_space, indent, a->udp);
    s = format(s, "\n%Utcp_established: %u", format_white_space, indent, a->tcp_established);
    s = format(s, "\n%Utcp_transitory: %u", format_white_space, indent, a->tcp_transitory);
    s = format(s, "\n%Uicmp: %u", format_white_space, indent, a->icmp);
    return s;
}

static inline u8 *format_vl_api_nat_log_level_t (u8 *s, va_list * args)
{
    vl_api_nat_log_level_t *a = va_arg (*args, vl_api_nat_log_level_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "NAT_LOG_NONE");
    case 1:
        return format(s, "NAT_LOG_ERROR");
    case 2:
        return format(s, "NAT_LOG_WARNING");
    case 3:
        return format(s, "NAT_LOG_NOTICE");
    case 4:
        return format(s, "NAT_LOG_INFO");
    case 5:
        return format(s, "NAT_LOG_DEBUG");
    }
    return s;
}

static inline u8 *format_vl_api_nat_config_flags_t (u8 *s, va_list * args)
{
    vl_api_nat_config_flags_t *a = va_arg (*args, vl_api_nat_config_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "NAT_IS_NONE");
    case 1:
        return format(s, "NAT_IS_TWICE_NAT");
    case 2:
        return format(s, "NAT_IS_SELF_TWICE_NAT");
    case 4:
        return format(s, "NAT_IS_OUT2IN_ONLY");
    case 8:
        return format(s, "NAT_IS_ADDR_ONLY");
    case 16:
        return format(s, "NAT_IS_OUTSIDE");
    case 32:
        return format(s, "NAT_IS_INSIDE");
    case 64:
        return format(s, "NAT_IS_STATIC");
    case 128:
        return format(s, "NAT_IS_EXT_HOST_VALID");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_nat_types_printfun
#define included_nat_types_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "nat_types.api_tojson.h"
#include "nat_types.api_fromjson.h"


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_nat_types_endianfun
#define included_nat_types_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_nat_timeouts_t_endian (vl_api_nat_timeouts_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->udp = clib_net_to_host_u32(a->udp);
    a->tcp_established = clib_net_to_host_u32(a->tcp_established);
    a->tcp_transitory = clib_net_to_host_u32(a->tcp_transitory);
    a->icmp = clib_net_to_host_u32(a->icmp);
}

static inline void vl_api_nat_log_level_t_endian (vl_api_nat_log_level_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->nat_log_level = a->nat_log_level (no-op) */
}

static inline void vl_api_nat_config_flags_t_endian (vl_api_nat_config_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->nat_config_flags = a->nat_config_flags (no-op) */
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_nat_types_calcsizefun
#define included_nat_types_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_timeouts_t_calc_size (vl_api_nat_timeouts_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_log_level_t_calc_size (vl_api_nat_log_level_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_config_flags_t_calc_size (vl_api_nat_config_flags_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(nat_types.api, 0, 0, 1)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(nat_types.api, 0x2ca9110f)

#endif

