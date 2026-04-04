/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: mfib_types.api
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
#warning no content included from mfib_types.api
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
#include <vnet/fib/fib_types.api.h>
#include <vnet/ip/ip_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
#endif
/****** Message names ******/

#ifdef vl_msg_name
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_mfib_types 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "mfib_types.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_mfib_types_printfun_types
#define included_mfib_types_printfun_types

static inline u8 *format_vl_api_mfib_entry_flags_t (u8 *s, va_list * args)
{
    vl_api_mfib_entry_flags_t *a = va_arg (*args, vl_api_mfib_entry_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "MFIB_API_ENTRY_FLAG_NONE");
    case 1:
        return format(s, "MFIB_API_ENTRY_FLAG_SIGNAL");
    case 2:
        return format(s, "MFIB_API_ENTRY_FLAG_DROP");
    case 4:
        return format(s, "MFIB_API_ENTRY_FLAG_CONNECTED");
    case 8:
        return format(s, "MFIB_API_ENTRY_FLAG_ACCEPT_ALL_ITF");
    }
    return s;
}

static inline u8 *format_vl_api_mfib_itf_flags_t (u8 *s, va_list * args)
{
    vl_api_mfib_itf_flags_t *a = va_arg (*args, vl_api_mfib_itf_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "MFIB_API_ITF_FLAG_NONE");
    case 1:
        return format(s, "MFIB_API_ITF_FLAG_NEGATE_SIGNAL");
    case 2:
        return format(s, "MFIB_API_ITF_FLAG_ACCEPT");
    case 4:
        return format(s, "MFIB_API_ITF_FLAG_FORWARD");
    case 8:
        return format(s, "MFIB_API_ITF_FLAG_SIGNAL_PRESENT");
    case 16:
        return format(s, "MFIB_API_ITF_FLAG_DONT_PRESERVE");
    }
    return s;
}

static inline u8 *format_vl_api_mfib_path_t (u8 *s, va_list * args)
{
    vl_api_mfib_path_t *a = va_arg (*args, vl_api_mfib_path_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uitf_flags: %U", format_white_space, indent, format_vl_api_mfib_itf_flags_t, &a->itf_flags, indent);
    s = format(s, "\n%Upath: %U", format_white_space, indent, format_vl_api_fib_path_t, &a->path, indent);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_mfib_types_printfun
#define included_mfib_types_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "mfib_types.api_tojson.h"
#include "mfib_types.api_fromjson.h"


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_mfib_types_endianfun
#define included_mfib_types_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_mfib_entry_flags_t_endian (vl_api_mfib_entry_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_mfib_itf_flags_t_endian (vl_api_mfib_itf_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_mfib_path_t_endian (vl_api_mfib_path_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_mfib_itf_flags_t_endian(&a->itf_flags, to_net);
    vl_api_fib_path_t_endian(&a->path, to_net);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_mfib_types_calcsizefun
#define included_mfib_types_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_mfib_entry_flags_t_calc_size (vl_api_mfib_entry_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mfib_itf_flags_t_calc_size (vl_api_mfib_itf_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mfib_path_t_calc_size (vl_api_mfib_path_t *a)
{
      return sizeof(*a) - sizeof(a->itf_flags) + vl_api_mfib_itf_flags_t_calc_size(&a->itf_flags) - sizeof(a->path) + vl_api_fib_path_t_calc_size(&a->path);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(mfib_types.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(mfib_types.api, 0xa172b91e)

#endif

