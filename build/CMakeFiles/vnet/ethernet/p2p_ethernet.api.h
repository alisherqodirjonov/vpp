/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: p2p_ethernet.api
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
#warning no content included from p2p_ethernet.api
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
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_P2P_ETHERNET_ADD, vl_api_p2p_ethernet_add_t_handler)
vl_msg_id(VL_API_P2P_ETHERNET_ADD_REPLY, vl_api_p2p_ethernet_add_reply_t_handler)
vl_msg_id(VL_API_P2P_ETHERNET_DEL, vl_api_p2p_ethernet_del_t_handler)
vl_msg_id(VL_API_P2P_ETHERNET_DEL_REPLY, vl_api_p2p_ethernet_del_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_p2p_ethernet_add_t, 1)
vl_msg_name(vl_api_p2p_ethernet_add_reply_t, 1)
vl_msg_name(vl_api_p2p_ethernet_del_t, 1)
vl_msg_name(vl_api_p2p_ethernet_del_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_p2p_ethernet \
_(VL_API_P2P_ETHERNET_ADD, p2p_ethernet_add, 36a1a6dc) \
_(VL_API_P2P_ETHERNET_ADD_REPLY, p2p_ethernet_add_reply, 5383d31f) \
_(VL_API_P2P_ETHERNET_DEL, p2p_ethernet_del, 62f81c8c) \
_(VL_API_P2P_ETHERNET_DEL_REPLY, p2p_ethernet_del_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "p2p_ethernet.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_p2p_ethernet_printfun_types
#define included_p2p_ethernet_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_p2p_ethernet_printfun
#define included_p2p_ethernet_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "p2p_ethernet.api_tojson.h"
#include "p2p_ethernet.api_fromjson.h"

static inline u8 *vl_api_p2p_ethernet_add_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_p2p_ethernet_add_t *a = va_arg (*args, vl_api_p2p_ethernet_add_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_p2p_ethernet_add_t: */
    s = format(s, "vl_api_p2p_ethernet_add_t:");
    s = format(s, "\n%Uparent_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->parent_if_index, indent);
    s = format(s, "\n%Usubif_id: %u", format_white_space, indent, a->subif_id);
    s = format(s, "\n%Uremote_mac: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->remote_mac, indent);
    return s;
}

static inline u8 *vl_api_p2p_ethernet_add_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_p2p_ethernet_add_reply_t *a = va_arg (*args, vl_api_p2p_ethernet_add_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_p2p_ethernet_add_reply_t: */
    s = format(s, "vl_api_p2p_ethernet_add_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_p2p_ethernet_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_p2p_ethernet_del_t *a = va_arg (*args, vl_api_p2p_ethernet_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_p2p_ethernet_del_t: */
    s = format(s, "vl_api_p2p_ethernet_del_t:");
    s = format(s, "\n%Uparent_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->parent_if_index, indent);
    s = format(s, "\n%Uremote_mac: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->remote_mac, indent);
    return s;
}

static inline u8 *vl_api_p2p_ethernet_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_p2p_ethernet_del_reply_t *a = va_arg (*args, vl_api_p2p_ethernet_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_p2p_ethernet_del_reply_t: */
    s = format(s, "vl_api_p2p_ethernet_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_p2p_ethernet_endianfun
#define included_p2p_ethernet_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_p2p_ethernet_add_t_endian (vl_api_p2p_ethernet_add_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->parent_if_index, to_net);
    a->subif_id = clib_net_to_host_u32(a->subif_id);
    vl_api_mac_address_t_endian(&a->remote_mac, to_net);
}

static inline void vl_api_p2p_ethernet_add_reply_t_endian (vl_api_p2p_ethernet_add_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_p2p_ethernet_del_t_endian (vl_api_p2p_ethernet_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->parent_if_index, to_net);
    vl_api_mac_address_t_endian(&a->remote_mac, to_net);
}

static inline void vl_api_p2p_ethernet_del_reply_t_endian (vl_api_p2p_ethernet_del_reply_t *a, bool to_net)
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
#ifndef included_p2p_ethernet_calcsizefun
#define included_p2p_ethernet_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_p2p_ethernet_add_t_calc_size (vl_api_p2p_ethernet_add_t *a)
{
      return sizeof(*a) - sizeof(a->parent_if_index) + vl_api_interface_index_t_calc_size(&a->parent_if_index) - sizeof(a->remote_mac) + vl_api_mac_address_t_calc_size(&a->remote_mac);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_p2p_ethernet_add_reply_t_calc_size (vl_api_p2p_ethernet_add_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_p2p_ethernet_del_t_calc_size (vl_api_p2p_ethernet_del_t *a)
{
      return sizeof(*a) - sizeof(a->parent_if_index) + vl_api_interface_index_t_calc_size(&a->parent_if_index) - sizeof(a->remote_mac) + vl_api_mac_address_t_calc_size(&a->remote_mac);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_p2p_ethernet_del_reply_t_calc_size (vl_api_p2p_ethernet_del_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(p2p_ethernet.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(p2p_ethernet.api, 0x339e3d84)

#endif

