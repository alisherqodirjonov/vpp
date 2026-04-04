/*
 * VLIB API definitions 2026-04-04 08:31:59
 * Input file: lacp.api
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
#warning no content included from lacp.api
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
#include <vnet/ethernet/ethernet_types.api.h>
#include <vnet/interface_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_SW_INTERFACE_LACP_DUMP, vl_api_sw_interface_lacp_dump_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_LACP_DETAILS, vl_api_sw_interface_lacp_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_sw_interface_lacp_dump_t, 1)
vl_msg_name(vl_api_sw_interface_lacp_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_lacp \
_(VL_API_SW_INTERFACE_LACP_DUMP, sw_interface_lacp_dump, 51077d14) \
_(VL_API_SW_INTERFACE_LACP_DETAILS, sw_interface_lacp_details, d9a83d2f) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "lacp.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_lacp_printfun_types
#define included_lacp_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_lacp_printfun
#define included_lacp_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "lacp.api_tojson.h"
#include "lacp.api_fromjson.h"

static inline u8 *vl_api_sw_interface_lacp_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_lacp_dump_t *a = va_arg (*args, vl_api_sw_interface_lacp_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_lacp_dump_t: */
    s = format(s, "vl_api_sw_interface_lacp_dump_t:");
    return s;
}

static inline u8 *vl_api_sw_interface_lacp_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_lacp_details_t *a = va_arg (*args, vl_api_sw_interface_lacp_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_lacp_details_t: */
    s = format(s, "vl_api_sw_interface_lacp_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uinterface_name: %s", format_white_space, indent, a->interface_name);
    s = format(s, "\n%Urx_state: %u", format_white_space, indent, a->rx_state);
    s = format(s, "\n%Utx_state: %u", format_white_space, indent, a->tx_state);
    s = format(s, "\n%Umux_state: %u", format_white_space, indent, a->mux_state);
    s = format(s, "\n%Uptx_state: %u", format_white_space, indent, a->ptx_state);
    s = format(s, "\n%Ubond_interface_name: %s", format_white_space, indent, a->bond_interface_name);
    s = format(s, "\n%Uactor_system_priority: %u", format_white_space, indent, a->actor_system_priority);
    s = format(s, "\n%Uactor_system: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->actor_system, indent);
    s = format(s, "\n%Uactor_key: %u", format_white_space, indent, a->actor_key);
    s = format(s, "\n%Uactor_port_priority: %u", format_white_space, indent, a->actor_port_priority);
    s = format(s, "\n%Uactor_port_number: %u", format_white_space, indent, a->actor_port_number);
    s = format(s, "\n%Uactor_state: %u", format_white_space, indent, a->actor_state);
    s = format(s, "\n%Upartner_system_priority: %u", format_white_space, indent, a->partner_system_priority);
    s = format(s, "\n%Upartner_system: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->partner_system, indent);
    s = format(s, "\n%Upartner_key: %u", format_white_space, indent, a->partner_key);
    s = format(s, "\n%Upartner_port_priority: %u", format_white_space, indent, a->partner_port_priority);
    s = format(s, "\n%Upartner_port_number: %u", format_white_space, indent, a->partner_port_number);
    s = format(s, "\n%Upartner_state: %u", format_white_space, indent, a->partner_state);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_lacp_endianfun
#define included_lacp_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_sw_interface_lacp_dump_t_endian (vl_api_sw_interface_lacp_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_sw_interface_lacp_details_t_endian (vl_api_sw_interface_lacp_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->interface_name = a->interface_name (no-op) */
    a->rx_state = clib_net_to_host_u32(a->rx_state);
    a->tx_state = clib_net_to_host_u32(a->tx_state);
    a->mux_state = clib_net_to_host_u32(a->mux_state);
    a->ptx_state = clib_net_to_host_u32(a->ptx_state);
    /* a->bond_interface_name = a->bond_interface_name (no-op) */
    a->actor_system_priority = clib_net_to_host_u16(a->actor_system_priority);
    vl_api_mac_address_t_endian(&a->actor_system, to_net);
    a->actor_key = clib_net_to_host_u16(a->actor_key);
    a->actor_port_priority = clib_net_to_host_u16(a->actor_port_priority);
    a->actor_port_number = clib_net_to_host_u16(a->actor_port_number);
    /* a->actor_state = a->actor_state (no-op) */
    a->partner_system_priority = clib_net_to_host_u16(a->partner_system_priority);
    vl_api_mac_address_t_endian(&a->partner_system, to_net);
    a->partner_key = clib_net_to_host_u16(a->partner_key);
    a->partner_port_priority = clib_net_to_host_u16(a->partner_port_priority);
    a->partner_port_number = clib_net_to_host_u16(a->partner_port_number);
    /* a->partner_state = a->partner_state (no-op) */
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_lacp_calcsizefun
#define included_lacp_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_lacp_dump_t_calc_size (vl_api_sw_interface_lacp_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_lacp_details_t_calc_size (vl_api_sw_interface_lacp_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->actor_system) + vl_api_mac_address_t_calc_size(&a->actor_system) - sizeof(a->partner_system) + vl_api_mac_address_t_calc_size(&a->partner_system);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(lacp.api, 2, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(lacp.api, 0x8975258e)

#endif

