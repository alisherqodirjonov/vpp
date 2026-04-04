/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: sr_types.api
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
#warning no content included from sr_types.api
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
#define foreach_vl_msg_name_crc_sr_types 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "sr_types.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_sr_types_printfun_types
#define included_sr_types_printfun_types

static inline u8 *format_vl_api_sr_policy_op_t (u8 *s, va_list * args)
{
    vl_api_sr_policy_op_t *a = va_arg (*args, vl_api_sr_policy_op_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "SR_POLICY_OP_API_NONE");
    case 1:
        return format(s, "SR_POLICY_OP_API_ADD");
    case 2:
        return format(s, "SR_POLICY_OP_API_DEL");
    case 3:
        return format(s, "SR_POLICY_OP_API_MOD");
    }
    return s;
}

static inline u8 *format_vl_api_sr_behavior_t (u8 *s, va_list * args)
{
    vl_api_sr_behavior_t *a = va_arg (*args, vl_api_sr_behavior_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "SR_BEHAVIOR_API_END");
    case 2:
        return format(s, "SR_BEHAVIOR_API_X");
    case 3:
        return format(s, "SR_BEHAVIOR_API_T");
    case 4:
        return format(s, "SR_BEHAVIOR_API_D_FIRST");
    case 5:
        return format(s, "SR_BEHAVIOR_API_DX2");
    case 6:
        return format(s, "SR_BEHAVIOR_API_DX6");
    case 7:
        return format(s, "SR_BEHAVIOR_API_DX4");
    case 8:
        return format(s, "SR_BEHAVIOR_API_DT6");
    case 9:
        return format(s, "SR_BEHAVIOR_API_DT4");
    case 10:
        return format(s, "SR_BEHAVIOR_API_LAST");
    case 11:
        return format(s, "SR_BEHAVIOR_API_END_UN_PERF");
    case 12:
        return format(s, "SR_BEHAVIOR_API_END_UN");
    case 13:
        return format(s, "SR_BEHAVIOR_API_UA");
    }
    return s;
}

static inline u8 *format_vl_api_sr_steer_t (u8 *s, va_list * args)
{
    vl_api_sr_steer_t *a = va_arg (*args, vl_api_sr_steer_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 2:
        return format(s, "SR_STEER_API_L2");
    case 4:
        return format(s, "SR_STEER_API_IPV4");
    case 6:
        return format(s, "SR_STEER_API_IPV6");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_sr_types_printfun
#define included_sr_types_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "sr_types.api_tojson.h"
#include "sr_types.api_fromjson.h"


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_sr_types_endianfun
#define included_sr_types_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_sr_policy_op_t_endian (vl_api_sr_policy_op_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->sr_policy_op = a->sr_policy_op (no-op) */
}

static inline void vl_api_sr_behavior_t_endian (vl_api_sr_behavior_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->sr_behavior = a->sr_behavior (no-op) */
}

static inline void vl_api_sr_steer_t_endian (vl_api_sr_steer_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->sr_steer = a->sr_steer (no-op) */
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_sr_types_calcsizefun
#define included_sr_types_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_policy_op_t_calc_size (vl_api_sr_policy_op_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_behavior_t_calc_size (vl_api_sr_behavior_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sr_steer_t_calc_size (vl_api_sr_steer_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(sr_types.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(sr_types.api, 0x7955bd50)

#endif

