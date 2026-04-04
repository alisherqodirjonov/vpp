/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: lb_types.api
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
#warning no content included from lb_types.api
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
#define foreach_vl_msg_name_crc_lb_types 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "lb_types.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_lb_types_printfun_types
#define included_lb_types_printfun_types

static inline u8 *format_vl_api_lb_srv_type_t (u8 *s, va_list * args)
{
    vl_api_lb_srv_type_t *a = va_arg (*args, vl_api_lb_srv_type_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "LB_API_SRV_TYPE_CLUSTERIP");
    case 1:
        return format(s, "LB_API_SRV_TYPE_NODEPORT");
    case 2:
        return format(s, "LB_API_SRV_N_TYPES");
    }
    return s;
}

static inline u8 *format_vl_api_lb_encap_type_t (u8 *s, va_list * args)
{
    vl_api_lb_encap_type_t *a = va_arg (*args, vl_api_lb_encap_type_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "LB_API_ENCAP_TYPE_GRE4");
    case 1:
        return format(s, "LB_API_ENCAP_TYPE_GRE6");
    case 2:
        return format(s, "LB_API_ENCAP_TYPE_L3DSR");
    case 3:
        return format(s, "LB_API_ENCAP_TYPE_NAT4");
    case 4:
        return format(s, "LB_API_ENCAP_TYPE_NAT6");
    case 5:
        return format(s, "LB_API_ENCAP_N_TYPES");
    }
    return s;
}

static inline u8 *format_vl_api_lb_lkp_type_t_t (u8 *s, va_list * args)
{
    vl_api_lb_lkp_type_t_t *a = va_arg (*args, vl_api_lb_lkp_type_t_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "LB_API_LKP_SAME_IP_PORT");
    case 1:
        return format(s, "LB_API_LKP_DIFF_IP_PORT");
    case 2:
        return format(s, "LB_API_LKP_ALL_PORT_IP");
    case 3:
        return format(s, "LB_API_LKP_N_TYPES");
    }
    return s;
}

static inline u8 *format_vl_api_lb_vip_type_t (u8 *s, va_list * args)
{
    vl_api_lb_vip_type_t *a = va_arg (*args, vl_api_lb_vip_type_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "LB_API_VIP_TYPE_IP6_GRE6");
    case 1:
        return format(s, "LB_API_VIP_TYPE_IP6_GRE4");
    case 2:
        return format(s, "LB_API_VIP_TYPE_IP4_GRE6");
    case 3:
        return format(s, "LB_API_VIP_TYPE_IP4_GRE4");
    case 4:
        return format(s, "LB_API_VIP_TYPE_IP4_L3DSR");
    case 5:
        return format(s, "LB_API_VIP_TYPE_IP4_NAT4");
    case 6:
        return format(s, "LB_API_VIP_TYPE_IP6_NAT6");
    case 7:
        return format(s, "LB_API_VIP_N_TYPES");
    }
    return s;
}

static inline u8 *format_vl_api_lb_nat_protocol_t (u8 *s, va_list * args)
{
    vl_api_lb_nat_protocol_t *a = va_arg (*args, vl_api_lb_nat_protocol_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 6:
        return format(s, "LB_API_NAT_PROTOCOL_UDP");
    case 23:
        return format(s, "LB_API_NAT_PROTOCOL_TCP");
    case 4294967295:
        return format(s, "LB_API_NAT_PROTOCOL_ANY");
    }
    return s;
}

static inline u8 *format_vl_api_lb_vip_t (u8 *s, va_list * args)
{
    vl_api_lb_vip_t *a = va_arg (*args, vl_api_lb_vip_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Upfx: %U", format_white_space, indent, format_vl_api_address_with_prefix_t, &a->pfx, indent);
    s = format(s, "\n%Uprotocol: %U", format_white_space, indent, format_vl_api_ip_proto_t, &a->protocol, indent);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_lb_types_printfun
#define included_lb_types_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "lb_types.api_tojson.h"
#include "lb_types.api_fromjson.h"


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_lb_types_endianfun
#define included_lb_types_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_lb_srv_type_t_endian (vl_api_lb_srv_type_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_lb_encap_type_t_endian (vl_api_lb_encap_type_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_lb_lkp_type_t_t_endian (vl_api_lb_lkp_type_t_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_lb_vip_type_t_endian (vl_api_lb_vip_type_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_lb_nat_protocol_t_endian (vl_api_lb_nat_protocol_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_lb_vip_t_endian (vl_api_lb_vip_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_address_with_prefix_t_endian(&a->pfx, to_net);
    vl_api_ip_proto_t_endian(&a->protocol, to_net);
    a->port = clib_net_to_host_u16(a->port);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_lb_types_calcsizefun
#define included_lb_types_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_srv_type_t_calc_size (vl_api_lb_srv_type_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_encap_type_t_calc_size (vl_api_lb_encap_type_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_lkp_type_t_t_calc_size (vl_api_lb_lkp_type_t_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_vip_type_t_calc_size (vl_api_lb_vip_type_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_nat_protocol_t_calc_size (vl_api_lb_nat_protocol_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lb_vip_t_calc_size (vl_api_lb_vip_t *a)
{
      return sizeof(*a) - sizeof(a->pfx) + vl_api_address_with_prefix_t_calc_size(&a->pfx) - sizeof(a->protocol) + vl_api_ip_proto_t_calc_size(&a->protocol);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(lb_types.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(lb_types.api, 0xd972a17f)

#endif

