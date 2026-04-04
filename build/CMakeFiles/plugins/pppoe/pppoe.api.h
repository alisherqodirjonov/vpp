/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: pppoe.api
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
#warning no content included from pppoe.api
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
#include <vnet/ethernet/ethernet_types.api.h>
#include <vnet/ip/ip_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_PPPOE_ADD_DEL_SESSION, vl_api_pppoe_add_del_session_t_handler)
vl_msg_id(VL_API_PPPOE_ADD_DEL_SESSION_REPLY, vl_api_pppoe_add_del_session_reply_t_handler)
vl_msg_id(VL_API_PPPOE_SESSION_DUMP, vl_api_pppoe_session_dump_t_handler)
vl_msg_id(VL_API_PPPOE_SESSION_DETAILS, vl_api_pppoe_session_details_t_handler)
vl_msg_id(VL_API_PPPOE_ADD_DEL_CP, vl_api_pppoe_add_del_cp_t_handler)
vl_msg_id(VL_API_PPPOE_ADD_DEL_CP_REPLY, vl_api_pppoe_add_del_cp_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_pppoe_add_del_session_t, 1)
vl_msg_name(vl_api_pppoe_add_del_session_reply_t, 1)
vl_msg_name(vl_api_pppoe_session_dump_t, 1)
vl_msg_name(vl_api_pppoe_session_details_t, 1)
vl_msg_name(vl_api_pppoe_add_del_cp_t, 1)
vl_msg_name(vl_api_pppoe_add_del_cp_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_pppoe \
_(VL_API_PPPOE_ADD_DEL_SESSION, pppoe_add_del_session, f6fd759e) \
_(VL_API_PPPOE_ADD_DEL_SESSION_REPLY, pppoe_add_del_session_reply, 5383d31f) \
_(VL_API_PPPOE_SESSION_DUMP, pppoe_session_dump, f9e6675e) \
_(VL_API_PPPOE_SESSION_DETAILS, pppoe_session_details, 4b8e8a4a) \
_(VL_API_PPPOE_ADD_DEL_CP, pppoe_add_del_cp, eacd9aaa) \
_(VL_API_PPPOE_ADD_DEL_CP_REPLY, pppoe_add_del_cp_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "pppoe.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_pppoe_printfun_types
#define included_pppoe_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_pppoe_printfun
#define included_pppoe_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "pppoe.api_tojson.h"
#include "pppoe.api_fromjson.h"

static inline u8 *vl_api_pppoe_add_del_session_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pppoe_add_del_session_t *a = va_arg (*args, vl_api_pppoe_add_del_session_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pppoe_add_del_session_t: */
    s = format(s, "vl_api_pppoe_add_del_session_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Usession_id: %u", format_white_space, indent, a->session_id);
    s = format(s, "\n%Uclient_ip: %U", format_white_space, indent, format_vl_api_address_t, &a->client_ip, indent);
    s = format(s, "\n%Udecap_vrf_id: %u", format_white_space, indent, a->decap_vrf_id);
    s = format(s, "\n%Uclient_mac: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->client_mac, indent);
    return s;
}

static inline u8 *vl_api_pppoe_add_del_session_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pppoe_add_del_session_reply_t *a = va_arg (*args, vl_api_pppoe_add_del_session_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pppoe_add_del_session_reply_t: */
    s = format(s, "vl_api_pppoe_add_del_session_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_pppoe_session_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pppoe_session_dump_t *a = va_arg (*args, vl_api_pppoe_session_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pppoe_session_dump_t: */
    s = format(s, "vl_api_pppoe_session_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_pppoe_session_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pppoe_session_details_t *a = va_arg (*args, vl_api_pppoe_session_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pppoe_session_details_t: */
    s = format(s, "vl_api_pppoe_session_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Usession_id: %u", format_white_space, indent, a->session_id);
    s = format(s, "\n%Uclient_ip: %U", format_white_space, indent, format_vl_api_address_t, &a->client_ip, indent);
    s = format(s, "\n%Uencap_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->encap_if_index, indent);
    s = format(s, "\n%Udecap_vrf_id: %u", format_white_space, indent, a->decap_vrf_id);
    s = format(s, "\n%Ulocal_mac: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->local_mac, indent);
    s = format(s, "\n%Uclient_mac: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->client_mac, indent);
    return s;
}

static inline u8 *vl_api_pppoe_add_del_cp_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pppoe_add_del_cp_t *a = va_arg (*args, vl_api_pppoe_add_del_cp_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pppoe_add_del_cp_t: */
    s = format(s, "vl_api_pppoe_add_del_cp_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    return s;
}

static inline u8 *vl_api_pppoe_add_del_cp_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_pppoe_add_del_cp_reply_t *a = va_arg (*args, vl_api_pppoe_add_del_cp_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_pppoe_add_del_cp_reply_t: */
    s = format(s, "vl_api_pppoe_add_del_cp_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_pppoe_endianfun
#define included_pppoe_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_pppoe_add_del_session_t_endian (vl_api_pppoe_add_del_session_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    a->session_id = clib_net_to_host_u16(a->session_id);
    vl_api_address_t_endian(&a->client_ip, to_net);
    a->decap_vrf_id = clib_net_to_host_u32(a->decap_vrf_id);
    vl_api_mac_address_t_endian(&a->client_mac, to_net);
}

static inline void vl_api_pppoe_add_del_session_reply_t_endian (vl_api_pppoe_add_del_session_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_pppoe_session_dump_t_endian (vl_api_pppoe_session_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_pppoe_session_details_t_endian (vl_api_pppoe_session_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->session_id = clib_net_to_host_u16(a->session_id);
    vl_api_address_t_endian(&a->client_ip, to_net);
    vl_api_interface_index_t_endian(&a->encap_if_index, to_net);
    a->decap_vrf_id = clib_net_to_host_u32(a->decap_vrf_id);
    vl_api_mac_address_t_endian(&a->local_mac, to_net);
    vl_api_mac_address_t_endian(&a->client_mac, to_net);
}

static inline void vl_api_pppoe_add_del_cp_t_endian (vl_api_pppoe_add_del_cp_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->is_add = a->is_add (no-op) */
}

static inline void vl_api_pppoe_add_del_cp_reply_t_endian (vl_api_pppoe_add_del_cp_reply_t *a, bool to_net)
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
#ifndef included_pppoe_calcsizefun
#define included_pppoe_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_pppoe_add_del_session_t_calc_size (vl_api_pppoe_add_del_session_t *a)
{
      return sizeof(*a) - sizeof(a->client_ip) + vl_api_address_t_calc_size(&a->client_ip) - sizeof(a->client_mac) + vl_api_mac_address_t_calc_size(&a->client_mac);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pppoe_add_del_session_reply_t_calc_size (vl_api_pppoe_add_del_session_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pppoe_session_dump_t_calc_size (vl_api_pppoe_session_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pppoe_session_details_t_calc_size (vl_api_pppoe_session_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->client_ip) + vl_api_address_t_calc_size(&a->client_ip) - sizeof(a->encap_if_index) + vl_api_interface_index_t_calc_size(&a->encap_if_index) - sizeof(a->local_mac) + vl_api_mac_address_t_calc_size(&a->local_mac) - sizeof(a->client_mac) + vl_api_mac_address_t_calc_size(&a->client_mac);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pppoe_add_del_cp_t_calc_size (vl_api_pppoe_add_del_cp_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_pppoe_add_del_cp_reply_t_calc_size (vl_api_pppoe_add_del_cp_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(pppoe.api, 2, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(pppoe.api, 0x57db3239)

#endif

