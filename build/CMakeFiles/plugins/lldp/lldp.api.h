/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: lldp.api
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
#warning no content included from lldp.api
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
vl_msg_id(VL_API_LLDP_CONFIG, vl_api_lldp_config_t_handler)
vl_msg_id(VL_API_LLDP_CONFIG_REPLY, vl_api_lldp_config_reply_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_SET_LLDP, vl_api_sw_interface_set_lldp_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_SET_LLDP_REPLY, vl_api_sw_interface_set_lldp_reply_t_handler)
vl_msg_id(VL_API_LLDP_DUMP, vl_api_lldp_dump_t_handler)
vl_msg_id(VL_API_LLDP_DUMP_REPLY, vl_api_lldp_dump_reply_t_handler)
vl_msg_id(VL_API_LLDP_DETAILS, vl_api_lldp_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_lldp_config_t, 1)
vl_msg_name(vl_api_lldp_config_reply_t, 1)
vl_msg_name(vl_api_sw_interface_set_lldp_t, 1)
vl_msg_name(vl_api_sw_interface_set_lldp_reply_t, 1)
vl_msg_name(vl_api_lldp_dump_t, 1)
vl_msg_name(vl_api_lldp_dump_reply_t, 1)
vl_msg_name(vl_api_lldp_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_lldp \
_(VL_API_LLDP_CONFIG, lldp_config, c14445df) \
_(VL_API_LLDP_CONFIG_REPLY, lldp_config_reply, e8d4e804) \
_(VL_API_SW_INTERFACE_SET_LLDP, sw_interface_set_lldp, 57afbcd4) \
_(VL_API_SW_INTERFACE_SET_LLDP_REPLY, sw_interface_set_lldp_reply, e8d4e804) \
_(VL_API_LLDP_DUMP, lldp_dump, f75ba505) \
_(VL_API_LLDP_DUMP_REPLY, lldp_dump_reply, 53b48f5d) \
_(VL_API_LLDP_DETAILS, lldp_details, c2d226cd) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "lldp.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_lldp_printfun_types
#define included_lldp_printfun_types

static inline u8 *format_vl_api_port_id_subtype_t (u8 *s, va_list * args)
{
    vl_api_port_id_subtype_t *a = va_arg (*args, vl_api_port_id_subtype_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "PORT_ID_SUBTYPE_RESERVED");
    case 1:
        return format(s, "PORT_ID_SUBTYPE_INTF_ALIAS");
    case 2:
        return format(s, "PORT_ID_SUBTYPE_PORT_COMP");
    case 3:
        return format(s, "PORT_ID_SUBTYPE_MAC_ADDR");
    case 4:
        return format(s, "PORT_ID_SUBTYPE_NET_ADDR");
    case 5:
        return format(s, "PORT_ID_SUBTYPE_INTF_NAME");
    case 6:
        return format(s, "PORT_ID_SUBTYPE_AGENT_CIRCUIT_ID");
    case 7:
        return format(s, "PORT_ID_SUBTYPE_LOCAL");
    }
    return s;
}

static inline u8 *format_vl_api_chassis_id_subtype_t (u8 *s, va_list * args)
{
    vl_api_chassis_id_subtype_t *a = va_arg (*args, vl_api_chassis_id_subtype_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "CHASSIS_ID_SUBTYPE_RESERVED");
    case 1:
        return format(s, "CHASSIS_ID_SUBTYPE_CHASSIS_COMP");
    case 2:
        return format(s, "CHASSIS_ID_SUBTYPE_INTF_ALIAS");
    case 3:
        return format(s, "CHASSIS_ID_SUBTYPE_PORT_COMP");
    case 4:
        return format(s, "CHASSIS_ID_SUBTYPE_MAC_ADDR");
    case 5:
        return format(s, "CHASSIS_ID_SUBTYPE_NET_ADDR");
    case 6:
        return format(s, "CHASSIS_ID_SUBTYPE_INTF_NAME");
    case 7:
        return format(s, "CHASSIS_ID_SUBTYPE_LOCAL");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_lldp_printfun
#define included_lldp_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "lldp.api_tojson.h"
#include "lldp.api_fromjson.h"

static inline u8 *vl_api_lldp_config_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lldp_config_t *a = va_arg (*args, vl_api_lldp_config_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lldp_config_t: */
    s = format(s, "vl_api_lldp_config_t:");
    s = format(s, "\n%Utx_hold: %u", format_white_space, indent, a->tx_hold);
    s = format(s, "\n%Utx_interval: %u", format_white_space, indent, a->tx_interval);
    if (vl_api_string_len(&a->system_name) > 0) {
        s = format(s, "\n%Usystem_name: %U", format_white_space, indent, vl_api_format_string, (&a->system_name));
    } else {
        s = format(s, "\n%Usystem_name:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_lldp_config_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lldp_config_reply_t *a = va_arg (*args, vl_api_lldp_config_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lldp_config_reply_t: */
    s = format(s, "vl_api_lldp_config_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sw_interface_set_lldp_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_set_lldp_t *a = va_arg (*args, vl_api_sw_interface_set_lldp_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_set_lldp_t: */
    s = format(s, "vl_api_sw_interface_set_lldp_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Umgmt_ip4: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->mgmt_ip4, indent);
    s = format(s, "\n%Umgmt_ip6: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->mgmt_ip6, indent);
    s = format(s, "\n%Umgmt_oid: %U", format_white_space, indent, format_hex_bytes, a, 128);
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    if (vl_api_string_len(&a->port_desc) > 0) {
        s = format(s, "\n%Uport_desc: %U", format_white_space, indent, vl_api_format_string, (&a->port_desc));
    } else {
        s = format(s, "\n%Uport_desc:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_sw_interface_set_lldp_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_set_lldp_reply_t *a = va_arg (*args, vl_api_sw_interface_set_lldp_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_set_lldp_reply_t: */
    s = format(s, "vl_api_sw_interface_set_lldp_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_lldp_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lldp_dump_t *a = va_arg (*args, vl_api_lldp_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lldp_dump_t: */
    s = format(s, "vl_api_lldp_dump_t:");
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_lldp_dump_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lldp_dump_reply_t *a = va_arg (*args, vl_api_lldp_dump_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lldp_dump_reply_t: */
    s = format(s, "vl_api_lldp_dump_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_lldp_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_lldp_details_t *a = va_arg (*args, vl_api_lldp_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_lldp_details_t: */
    s = format(s, "vl_api_lldp_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Ulast_heard: %.2f", format_white_space, indent, a->last_heard);
    s = format(s, "\n%Ulast_sent: %.2f", format_white_space, indent, a->last_sent);
    s = format(s, "\n%Uchassis_id: %U", format_white_space, indent, format_hex_bytes, a, 64);
    s = format(s, "\n%Uchassis_id_len: %u", format_white_space, indent, a->chassis_id_len);
    s = format(s, "\n%Uport_id: %U", format_white_space, indent, format_hex_bytes, a, 64);
    s = format(s, "\n%Uport_id_len: %u", format_white_space, indent, a->port_id_len);
    s = format(s, "\n%Uttl: %u", format_white_space, indent, a->ttl);
    s = format(s, "\n%Uport_id_subtype: %U", format_white_space, indent, format_vl_api_port_id_subtype_t, &a->port_id_subtype, indent);
    s = format(s, "\n%Uchassis_id_subtype: %U", format_white_space, indent, format_vl_api_chassis_id_subtype_t, &a->chassis_id_subtype, indent);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_lldp_endianfun
#define included_lldp_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_port_id_subtype_t_endian (vl_api_port_id_subtype_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_chassis_id_subtype_t_endian (vl_api_chassis_id_subtype_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_lldp_config_t_endian (vl_api_lldp_config_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->tx_hold = clib_net_to_host_u32(a->tx_hold);
    a->tx_interval = clib_net_to_host_u32(a->tx_interval);
    /* a->system_name = a->system_name (no-op) */
}

static inline void vl_api_lldp_config_reply_t_endian (vl_api_lldp_config_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sw_interface_set_lldp_t_endian (vl_api_sw_interface_set_lldp_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_ip4_address_t_endian(&a->mgmt_ip4, to_net);
    vl_api_ip6_address_t_endian(&a->mgmt_ip6, to_net);
    /* a->mgmt_oid = a->mgmt_oid (no-op) */
    /* a->enable = a->enable (no-op) */
    /* a->port_desc = a->port_desc (no-op) */
}

static inline void vl_api_sw_interface_set_lldp_reply_t_endian (vl_api_sw_interface_set_lldp_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_lldp_dump_t_endian (vl_api_lldp_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_lldp_dump_reply_t_endian (vl_api_lldp_dump_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_lldp_details_t_endian (vl_api_lldp_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->last_heard = clib_net_to_host_f64(a->last_heard);
    a->last_sent = clib_net_to_host_f64(a->last_sent);
    /* a->chassis_id = a->chassis_id (no-op) */
    /* a->chassis_id_len = a->chassis_id_len (no-op) */
    /* a->port_id = a->port_id (no-op) */
    /* a->port_id_len = a->port_id_len (no-op) */
    a->ttl = clib_net_to_host_u16(a->ttl);
    vl_api_port_id_subtype_t_endian(&a->port_id_subtype, to_net);
    vl_api_chassis_id_subtype_t_endian(&a->chassis_id_subtype, to_net);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_lldp_calcsizefun
#define included_lldp_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_port_id_subtype_t_calc_size (vl_api_port_id_subtype_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_chassis_id_subtype_t_calc_size (vl_api_chassis_id_subtype_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lldp_config_t_calc_size (vl_api_lldp_config_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->system_name);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lldp_config_reply_t_calc_size (vl_api_lldp_config_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_set_lldp_t_calc_size (vl_api_sw_interface_set_lldp_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->mgmt_ip4) + vl_api_ip4_address_t_calc_size(&a->mgmt_ip4) - sizeof(a->mgmt_ip6) + vl_api_ip6_address_t_calc_size(&a->mgmt_ip6) + vl_api_string_len(&a->port_desc);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_set_lldp_reply_t_calc_size (vl_api_sw_interface_set_lldp_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lldp_dump_t_calc_size (vl_api_lldp_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lldp_dump_reply_t_calc_size (vl_api_lldp_dump_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_lldp_details_t_calc_size (vl_api_lldp_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->port_id_subtype) + vl_api_port_id_subtype_t_calc_size(&a->port_id_subtype) - sizeof(a->chassis_id_subtype) + vl_api_chassis_id_subtype_t_calc_size(&a->chassis_id_subtype);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(lldp.api, 2, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(lldp.api, 0x85a9ebb2)

#endif

