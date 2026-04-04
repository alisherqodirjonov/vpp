/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: virtio_types.api
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
#warning no content included from virtio_types.api
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
#define foreach_vl_msg_name_crc_virtio_types 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "virtio_types.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_virtio_types_printfun_types
#define included_virtio_types_printfun_types

static inline u8 *format_vl_api_virtio_net_features_first_32_t (u8 *s, va_list * args)
{
    vl_api_virtio_net_features_first_32_t *a = va_arg (*args, vl_api_virtio_net_features_first_32_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "VIRTIO_NET_F_API_CSUM");
    case 2:
        return format(s, "VIRTIO_NET_F_API_GUEST_CSUM");
    case 128:
        return format(s, "VIRTIO_NET_F_API_GUEST_TSO4");
    case 256:
        return format(s, "VIRTIO_NET_F_API_GUEST_TSO6");
    case 1024:
        return format(s, "VIRTIO_NET_F_API_GUEST_UFO");
    case 2048:
        return format(s, "VIRTIO_NET_F_API_HOST_TSO4");
    case 4096:
        return format(s, "VIRTIO_NET_F_API_HOST_TSO6");
    case 16384:
        return format(s, "VIRTIO_NET_F_API_HOST_UFO");
    case 32768:
        return format(s, "VIRTIO_NET_F_API_MRG_RXBUF");
    case 131072:
        return format(s, "VIRTIO_NET_F_API_CTRL_VQ");
    case 2097152:
        return format(s, "VIRTIO_NET_F_API_GUEST_ANNOUNCE");
    case 4194304:
        return format(s, "VIRTIO_NET_F_API_MQ");
    case 67108864:
        return format(s, "VHOST_F_API_LOG_ALL");
    case 134217728:
        return format(s, "VIRTIO_F_API_ANY_LAYOUT");
    case 268435456:
        return format(s, "VIRTIO_F_API_INDIRECT_DESC");
    case 1073741824:
        return format(s, "VHOST_USER_F_API_PROTOCOL_FEATURES");
    }
    return s;
}

static inline u8 *format_vl_api_virtio_net_features_last_32_t (u8 *s, va_list * args)
{
    vl_api_virtio_net_features_last_32_t *a = va_arg (*args, vl_api_virtio_net_features_last_32_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "VIRTIO_F_API_VERSION_1");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_virtio_types_printfun
#define included_virtio_types_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "virtio_types.api_tojson.h"
#include "virtio_types.api_fromjson.h"


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_virtio_types_endianfun
#define included_virtio_types_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_virtio_net_features_first_32_t_endian (vl_api_virtio_net_features_first_32_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_virtio_net_features_last_32_t_endian (vl_api_virtio_net_features_last_32_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_virtio_types_calcsizefun
#define included_virtio_types_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_virtio_net_features_first_32_t_calc_size (vl_api_virtio_net_features_first_32_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_virtio_net_features_last_32_t_calc_size (vl_api_virtio_net_features_last_32_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(virtio_types.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(virtio_types.api, 0x7a70a44e)

#endif

