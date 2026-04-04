/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: tunnel_types.api
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
#warning no content included from tunnel_types.api
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
#endif
/****** Message names ******/

#ifdef vl_msg_name
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_tunnel_types 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "tunnel_types.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_tunnel_types_printfun_types
#define included_tunnel_types_printfun_types

static inline u8 *format_vl_api_tunnel_encap_decap_flags_t (u8 *s, va_list * args)
{
    vl_api_tunnel_encap_decap_flags_t *a = va_arg (*args, vl_api_tunnel_encap_decap_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "TUNNEL_API_ENCAP_DECAP_FLAG_NONE");
    case 1:
        return format(s, "TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DF");
    case 2:
        return format(s, "TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_SET_DF");
    case 4:
        return format(s, "TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP");
    case 8:
        return format(s, "TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN");
    case 16:
        return format(s, "TUNNEL_API_ENCAP_DECAP_FLAG_DECAP_COPY_ECN");
    case 32:
        return format(s, "TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_INNER_HASH");
    case 64:
        return format(s, "TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_HOP_LIMIT");
    case 128:
        return format(s, "TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_FLOW_LABEL");
    }
    return s;
}

static inline u8 *format_vl_api_tunnel_mode_t (u8 *s, va_list * args)
{
    vl_api_tunnel_mode_t *a = va_arg (*args, vl_api_tunnel_mode_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "TUNNEL_API_MODE_P2P");
    case 1:
        return format(s, "TUNNEL_API_MODE_MP");
    }
    return s;
}

static inline u8 *format_vl_api_tunnel_flags_t (u8 *s, va_list * args)
{
    vl_api_tunnel_flags_t *a = va_arg (*args, vl_api_tunnel_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "TUNNEL_API_FLAG_TRACK_MTU");
    }
    return s;
}

static inline u8 *format_vl_api_tunnel_t (u8 *s, va_list * args)
{
    vl_api_tunnel_t *a = va_arg (*args, vl_api_tunnel_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uinstance: %u", format_white_space, indent, a->instance);
    s = format(s, "\n%Usrc: %U", format_white_space, indent, format_vl_api_address_t, &a->src, indent);
    s = format(s, "\n%Udst: %U", format_white_space, indent, format_vl_api_address_t, &a->dst, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Utable_id: %u", format_white_space, indent, a->table_id);
    s = format(s, "\n%Uencap_decap_flags: %U", format_white_space, indent, format_vl_api_tunnel_encap_decap_flags_t, &a->encap_decap_flags, indent);
    s = format(s, "\n%Umode: %U", format_white_space, indent, format_vl_api_tunnel_mode_t, &a->mode, indent);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_tunnel_flags_t, &a->flags, indent);
    s = format(s, "\n%Udscp: %U", format_white_space, indent, format_vl_api_ip_dscp_t, &a->dscp, indent);
    s = format(s, "\n%Uhop_limit: %u", format_white_space, indent, a->hop_limit);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_tunnel_types_printfun
#define included_tunnel_types_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "tunnel_types.api_tojson.h"
#include "tunnel_types.api_fromjson.h"


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_tunnel_types_endianfun
#define included_tunnel_types_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_tunnel_encap_decap_flags_t_endian (vl_api_tunnel_encap_decap_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->tunnel_encap_decap_flags = a->tunnel_encap_decap_flags (no-op) */
}

static inline void vl_api_tunnel_mode_t_endian (vl_api_tunnel_mode_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->tunnel_mode = a->tunnel_mode (no-op) */
}

static inline void vl_api_tunnel_flags_t_endian (vl_api_tunnel_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->tunnel_flags = a->tunnel_flags (no-op) */
}

static inline void vl_api_tunnel_t_endian (vl_api_tunnel_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->instance = clib_net_to_host_u32(a->instance);
    vl_api_address_t_endian(&a->src, to_net);
    vl_api_address_t_endian(&a->dst, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->table_id = clib_net_to_host_u32(a->table_id);
    vl_api_tunnel_encap_decap_flags_t_endian(&a->encap_decap_flags, to_net);
    vl_api_tunnel_mode_t_endian(&a->mode, to_net);
    vl_api_tunnel_flags_t_endian(&a->flags, to_net);
    vl_api_ip_dscp_t_endian(&a->dscp, to_net);
    /* a->hop_limit = a->hop_limit (no-op) */
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_tunnel_types_calcsizefun
#define included_tunnel_types_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_tunnel_encap_decap_flags_t_calc_size (vl_api_tunnel_encap_decap_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_tunnel_mode_t_calc_size (vl_api_tunnel_mode_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_tunnel_flags_t_calc_size (vl_api_tunnel_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_tunnel_t_calc_size (vl_api_tunnel_t *a)
{
      return sizeof(*a) - sizeof(a->src) + vl_api_address_t_calc_size(&a->src) - sizeof(a->dst) + vl_api_address_t_calc_size(&a->dst) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->encap_decap_flags) + vl_api_tunnel_encap_decap_flags_t_calc_size(&a->encap_decap_flags) - sizeof(a->mode) + vl_api_tunnel_mode_t_calc_size(&a->mode) - sizeof(a->flags) + vl_api_tunnel_flags_t_calc_size(&a->flags) - sizeof(a->dscp) + vl_api_ip_dscp_t_calc_size(&a->dscp);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(tunnel_types.api, 1, 0, 1)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(tunnel_types.api, 0xcd783d74)

#endif

