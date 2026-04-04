/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: pvti.api
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
#warning no content included from pvti.api
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
vl_msg_id(VL_API_PVTI_INTERFACE_CREATE, vl_api_pvti_interface_create_t_handler)
vl_msg_id(VL_API_PVTI_INTERFACE_CREATE_REPLY, vl_api_pvti_interface_create_reply_t_handler)
vl_msg_id(VL_API_PVTI_INTERFACE_DELETE, vl_api_pvti_interface_delete_t_handler)
vl_msg_id(VL_API_PVTI_INTERFACE_DELETE_REPLY, vl_api_pvti_interface_delete_reply_t_handler)
vl_msg_id(VL_API_PVTI_INTERFACE_DUMP, vl_api_pvti_interface_dump_t_handler)
vl_msg_id(VL_API_PVTI_INTERFACE_DETAILS, vl_api_pvti_interface_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_pvti_interface_create_t, 1)
vl_msg_name(vl_api_pvti_interface_create_reply_t, 1)
vl_msg_name(vl_api_pvti_interface_delete_t, 1)
vl_msg_name(vl_api_pvti_interface_delete_reply_t, 1)
vl_msg_name(vl_api_pvti_interface_dump_t, 1)
vl_msg_name(vl_api_pvti_interface_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_pvti \
_(VL_API_PVTI_INTERFACE_CREATE, pvti_interface_create, a1e95595) \
_(VL_API_PVTI_INTERFACE_CREATE_REPLY, pvti_interface_create_reply, 5383d31f) \
_(VL_API_PVTI_INTERFACE_DELETE, pvti_interface_delete, f9e6675e) \
_(VL_API_PVTI_INTERFACE_DELETE_REPLY, pvti_interface_delete_reply, e8d4e804) \
_(VL_API_PVTI_INTERFACE_DUMP, pvti_interface_dump, f9e6675e) \
_(VL_API_PVTI_INTERFACE_DETAILS, pvti_interface_details, a26072b7) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "pvti.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_pvti_printfun_types
#define included_pvti_printfun_types

static inline u8 *format_vl_api_pvti_tunnel_t (u8 *s, va_list * args)
{
    vl_api_pvti_tunnel_t *a = va_arg (*args, vl_api_pvti_tunnel_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Ulocal_ip: %U", format_white_space, indent, format_vl_api_address_t, &a->local_ip, indent);
    s = format(s, "\n%Ulocal_port: %u", format_white_space, indent, a->local_port);
    s = format(s, "\n%Uremote_ip: %U", format_white_space, indent, format_vl_api_address_t, &a->remote_ip, indent);
    s = format(s, "\n%Upeer_address_from_payload: %u", format_white_space, indent, a->peer_address_from_payload);
    s = format(s, "\n%Uremote_port: %u", format_white_space, indent, a->remote_port);
    s = format(s, "\n%Uunderlay_mtu: %u", format_white_space, indent, a->underlay_mtu);
    s = format(s, "\n%Uunderlay_fib_index: %u", format_white_space, indent, a->underlay_fib_index);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_pvti_printfun
#define included_pvti_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "pvti.api_tojson.h"
#include "pvti.api_fromjson.h"

static inline u8 *vl_api_pvti_interface_create_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pvti_interface_create_t *a = va_arg (*args, vl_api_pvti_interface_create_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pvti_interface_create_t: */
    s = format(s, "vl_api_pvti_interface_create_t:");
    s = format(s, "\n%Uinterface: %U", format_white_space, indent, format_vl_api_pvti_tunnel_t, &a->interface, indent);
    return s;
}

static inline u8 *vl_api_pvti_interface_create_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pvti_interface_create_reply_t *a = va_arg (*args, vl_api_pvti_interface_create_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pvti_interface_create_reply_t: */
    s = format(s, "vl_api_pvti_interface_create_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_pvti_interface_delete_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pvti_interface_delete_t *a = va_arg (*args, vl_api_pvti_interface_delete_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pvti_interface_delete_t: */
    s = format(s, "vl_api_pvti_interface_delete_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_pvti_interface_delete_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pvti_interface_delete_reply_t *a = va_arg (*args, vl_api_pvti_interface_delete_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pvti_interface_delete_reply_t: */
    s = format(s, "vl_api_pvti_interface_delete_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_pvti_interface_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pvti_interface_dump_t *a = va_arg (*args, vl_api_pvti_interface_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pvti_interface_dump_t: */
    s = format(s, "vl_api_pvti_interface_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_pvti_interface_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pvti_interface_details_t *a = va_arg (*args, vl_api_pvti_interface_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pvti_interface_details_t: */
    s = format(s, "vl_api_pvti_interface_details_t:");
    s = format(s, "\n%Uinterface: %U", format_white_space, indent, format_vl_api_pvti_tunnel_t, &a->interface, indent);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_pvti_endianfun
#define included_pvti_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_pvti_tunnel_t_endian (vl_api_pvti_tunnel_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_address_t_endian(&a->local_ip, to_net);
    a->local_port = clib_net_to_host_u16(a->local_port);
    vl_api_address_t_endian(&a->remote_ip, to_net);
    /* a->peer_address_from_payload = a->peer_address_from_payload (no-op) */
    a->remote_port = clib_net_to_host_u16(a->remote_port);
    a->underlay_mtu = clib_net_to_host_u16(a->underlay_mtu);
    a->underlay_fib_index = clib_net_to_host_u32(a->underlay_fib_index);
}

static inline void vl_api_pvti_interface_create_t_endian (vl_api_pvti_interface_create_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_pvti_tunnel_t_endian(&a->interface, to_net);
}

static inline void vl_api_pvti_interface_create_reply_t_endian (vl_api_pvti_interface_create_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_pvti_interface_delete_t_endian (vl_api_pvti_interface_delete_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_pvti_interface_delete_reply_t_endian (vl_api_pvti_interface_delete_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_pvti_interface_dump_t_endian (vl_api_pvti_interface_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_pvti_interface_details_t_endian (vl_api_pvti_interface_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_pvti_tunnel_t_endian(&a->interface, to_net);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_pvti_calcsizefun
#define included_pvti_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_pvti_tunnel_t_calc_size (vl_api_pvti_tunnel_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->local_ip) + vl_api_address_t_calc_size(&a->local_ip) - sizeof(a->remote_ip) + vl_api_address_t_calc_size(&a->remote_ip);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pvti_interface_create_t_calc_size (vl_api_pvti_interface_create_t *a)
{
      return sizeof(*a) - sizeof(a->interface) + vl_api_pvti_tunnel_t_calc_size(&a->interface);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pvti_interface_create_reply_t_calc_size (vl_api_pvti_interface_create_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pvti_interface_delete_t_calc_size (vl_api_pvti_interface_delete_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pvti_interface_delete_reply_t_calc_size (vl_api_pvti_interface_delete_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pvti_interface_dump_t_calc_size (vl_api_pvti_interface_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pvti_interface_details_t_calc_size (vl_api_pvti_interface_details_t *a)
{
      return sizeof(*a) - sizeof(a->interface) + vl_api_pvti_tunnel_t_calc_size(&a->interface);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(pvti.api, 0, 0, 1)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(pvti.api, 0xf0486cba)

#endif

