/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: det44.api
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
#warning no content included from det44.api
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
#include <vnet/interface_types.api.h>
#include <nat/lib/nat_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_DET44_PLUGIN_ENABLE_DISABLE, vl_api_det44_plugin_enable_disable_t_handler)
vl_msg_id(VL_API_DET44_PLUGIN_ENABLE_DISABLE_REPLY, vl_api_det44_plugin_enable_disable_reply_t_handler)
vl_msg_id(VL_API_DET44_INTERFACE_ADD_DEL_FEATURE, vl_api_det44_interface_add_del_feature_t_handler)
vl_msg_id(VL_API_DET44_INTERFACE_ADD_DEL_FEATURE_REPLY, vl_api_det44_interface_add_del_feature_reply_t_handler)
vl_msg_id(VL_API_DET44_INTERFACE_DUMP, vl_api_det44_interface_dump_t_handler)
vl_msg_id(VL_API_DET44_INTERFACE_DETAILS, vl_api_det44_interface_details_t_handler)
vl_msg_id(VL_API_DET44_ADD_DEL_MAP, vl_api_det44_add_del_map_t_handler)
vl_msg_id(VL_API_DET44_ADD_DEL_MAP_REPLY, vl_api_det44_add_del_map_reply_t_handler)
vl_msg_id(VL_API_DET44_FORWARD, vl_api_det44_forward_t_handler)
vl_msg_id(VL_API_DET44_FORWARD_REPLY, vl_api_det44_forward_reply_t_handler)
vl_msg_id(VL_API_DET44_REVERSE, vl_api_det44_reverse_t_handler)
vl_msg_id(VL_API_DET44_REVERSE_REPLY, vl_api_det44_reverse_reply_t_handler)
vl_msg_id(VL_API_DET44_MAP_DUMP, vl_api_det44_map_dump_t_handler)
vl_msg_id(VL_API_DET44_MAP_DETAILS, vl_api_det44_map_details_t_handler)
vl_msg_id(VL_API_DET44_CLOSE_SESSION_OUT, vl_api_det44_close_session_out_t_handler)
vl_msg_id(VL_API_DET44_CLOSE_SESSION_OUT_REPLY, vl_api_det44_close_session_out_reply_t_handler)
vl_msg_id(VL_API_DET44_CLOSE_SESSION_IN, vl_api_det44_close_session_in_t_handler)
vl_msg_id(VL_API_DET44_CLOSE_SESSION_IN_REPLY, vl_api_det44_close_session_in_reply_t_handler)
vl_msg_id(VL_API_DET44_SESSION_DUMP, vl_api_det44_session_dump_t_handler)
vl_msg_id(VL_API_DET44_SESSION_DETAILS, vl_api_det44_session_details_t_handler)
vl_msg_id(VL_API_DET44_SET_TIMEOUTS, vl_api_det44_set_timeouts_t_handler)
vl_msg_id(VL_API_DET44_SET_TIMEOUTS_REPLY, vl_api_det44_set_timeouts_reply_t_handler)
vl_msg_id(VL_API_DET44_GET_TIMEOUTS, vl_api_det44_get_timeouts_t_handler)
vl_msg_id(VL_API_DET44_GET_TIMEOUTS_REPLY, vl_api_det44_get_timeouts_reply_t_handler)
vl_msg_id(VL_API_NAT_DET_ADD_DEL_MAP, vl_api_nat_det_add_del_map_t_handler)
vl_msg_id(VL_API_NAT_DET_ADD_DEL_MAP_REPLY, vl_api_nat_det_add_del_map_reply_t_handler)
vl_msg_id(VL_API_NAT_DET_FORWARD, vl_api_nat_det_forward_t_handler)
vl_msg_id(VL_API_NAT_DET_FORWARD_REPLY, vl_api_nat_det_forward_reply_t_handler)
vl_msg_id(VL_API_NAT_DET_REVERSE, vl_api_nat_det_reverse_t_handler)
vl_msg_id(VL_API_NAT_DET_REVERSE_REPLY, vl_api_nat_det_reverse_reply_t_handler)
vl_msg_id(VL_API_NAT_DET_MAP_DUMP, vl_api_nat_det_map_dump_t_handler)
vl_msg_id(VL_API_NAT_DET_MAP_DETAILS, vl_api_nat_det_map_details_t_handler)
vl_msg_id(VL_API_NAT_DET_CLOSE_SESSION_OUT, vl_api_nat_det_close_session_out_t_handler)
vl_msg_id(VL_API_NAT_DET_CLOSE_SESSION_OUT_REPLY, vl_api_nat_det_close_session_out_reply_t_handler)
vl_msg_id(VL_API_NAT_DET_CLOSE_SESSION_IN, vl_api_nat_det_close_session_in_t_handler)
vl_msg_id(VL_API_NAT_DET_CLOSE_SESSION_IN_REPLY, vl_api_nat_det_close_session_in_reply_t_handler)
vl_msg_id(VL_API_NAT_DET_SESSION_DUMP, vl_api_nat_det_session_dump_t_handler)
vl_msg_id(VL_API_NAT_DET_SESSION_DETAILS, vl_api_nat_det_session_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_det44_plugin_enable_disable_t, 1)
vl_msg_name(vl_api_det44_plugin_enable_disable_reply_t, 1)
vl_msg_name(vl_api_det44_interface_add_del_feature_t, 1)
vl_msg_name(vl_api_det44_interface_add_del_feature_reply_t, 1)
vl_msg_name(vl_api_det44_interface_dump_t, 1)
vl_msg_name(vl_api_det44_interface_details_t, 1)
vl_msg_name(vl_api_det44_add_del_map_t, 1)
vl_msg_name(vl_api_det44_add_del_map_reply_t, 1)
vl_msg_name(vl_api_det44_forward_t, 1)
vl_msg_name(vl_api_det44_forward_reply_t, 1)
vl_msg_name(vl_api_det44_reverse_t, 1)
vl_msg_name(vl_api_det44_reverse_reply_t, 1)
vl_msg_name(vl_api_det44_map_dump_t, 1)
vl_msg_name(vl_api_det44_map_details_t, 1)
vl_msg_name(vl_api_det44_close_session_out_t, 1)
vl_msg_name(vl_api_det44_close_session_out_reply_t, 1)
vl_msg_name(vl_api_det44_close_session_in_t, 1)
vl_msg_name(vl_api_det44_close_session_in_reply_t, 1)
vl_msg_name(vl_api_det44_session_dump_t, 1)
vl_msg_name(vl_api_det44_session_details_t, 1)
vl_msg_name(vl_api_det44_set_timeouts_t, 1)
vl_msg_name(vl_api_det44_set_timeouts_reply_t, 1)
vl_msg_name(vl_api_det44_get_timeouts_t, 1)
vl_msg_name(vl_api_det44_get_timeouts_reply_t, 1)
vl_msg_name(vl_api_nat_det_add_del_map_t, 1)
vl_msg_name(vl_api_nat_det_add_del_map_reply_t, 1)
vl_msg_name(vl_api_nat_det_forward_t, 1)
vl_msg_name(vl_api_nat_det_forward_reply_t, 1)
vl_msg_name(vl_api_nat_det_reverse_t, 1)
vl_msg_name(vl_api_nat_det_reverse_reply_t, 1)
vl_msg_name(vl_api_nat_det_map_dump_t, 1)
vl_msg_name(vl_api_nat_det_map_details_t, 1)
vl_msg_name(vl_api_nat_det_close_session_out_t, 1)
vl_msg_name(vl_api_nat_det_close_session_out_reply_t, 1)
vl_msg_name(vl_api_nat_det_close_session_in_t, 1)
vl_msg_name(vl_api_nat_det_close_session_in_reply_t, 1)
vl_msg_name(vl_api_nat_det_session_dump_t, 1)
vl_msg_name(vl_api_nat_det_session_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_det44 \
_(VL_API_DET44_PLUGIN_ENABLE_DISABLE, det44_plugin_enable_disable, 617b6bf8) \
_(VL_API_DET44_PLUGIN_ENABLE_DISABLE_REPLY, det44_plugin_enable_disable_reply, e8d4e804) \
_(VL_API_DET44_INTERFACE_ADD_DEL_FEATURE, det44_interface_add_del_feature, dc17a836) \
_(VL_API_DET44_INTERFACE_ADD_DEL_FEATURE_REPLY, det44_interface_add_del_feature_reply, e8d4e804) \
_(VL_API_DET44_INTERFACE_DUMP, det44_interface_dump, 51077d14) \
_(VL_API_DET44_INTERFACE_DETAILS, det44_interface_details, e60cc5be) \
_(VL_API_DET44_ADD_DEL_MAP, det44_add_del_map, 1150a190) \
_(VL_API_DET44_ADD_DEL_MAP_REPLY, det44_add_del_map_reply, e8d4e804) \
_(VL_API_DET44_FORWARD, det44_forward, 7f8a89cd) \
_(VL_API_DET44_FORWARD_REPLY, det44_forward_reply, a8ccbdc0) \
_(VL_API_DET44_REVERSE, det44_reverse, a7573fe1) \
_(VL_API_DET44_REVERSE_REPLY, det44_reverse_reply, 34066d48) \
_(VL_API_DET44_MAP_DUMP, det44_map_dump, 51077d14) \
_(VL_API_DET44_MAP_DETAILS, det44_map_details, ad91dc83) \
_(VL_API_DET44_CLOSE_SESSION_OUT, det44_close_session_out, f6b259d1) \
_(VL_API_DET44_CLOSE_SESSION_OUT_REPLY, det44_close_session_out_reply, e8d4e804) \
_(VL_API_DET44_CLOSE_SESSION_IN, det44_close_session_in, 3c68e073) \
_(VL_API_DET44_CLOSE_SESSION_IN_REPLY, det44_close_session_in_reply, e8d4e804) \
_(VL_API_DET44_SESSION_DUMP, det44_session_dump, e45a3af7) \
_(VL_API_DET44_SESSION_DETAILS, det44_session_details, 27f3c171) \
_(VL_API_DET44_SET_TIMEOUTS, det44_set_timeouts, d4746b16) \
_(VL_API_DET44_SET_TIMEOUTS_REPLY, det44_set_timeouts_reply, e8d4e804) \
_(VL_API_DET44_GET_TIMEOUTS, det44_get_timeouts, 51077d14) \
_(VL_API_DET44_GET_TIMEOUTS_REPLY, det44_get_timeouts_reply, 3c4df4e1) \
_(VL_API_NAT_DET_ADD_DEL_MAP, nat_det_add_del_map, 1150a190) \
_(VL_API_NAT_DET_ADD_DEL_MAP_REPLY, nat_det_add_del_map_reply, e8d4e804) \
_(VL_API_NAT_DET_FORWARD, nat_det_forward, 7f8a89cd) \
_(VL_API_NAT_DET_FORWARD_REPLY, nat_det_forward_reply, a8ccbdc0) \
_(VL_API_NAT_DET_REVERSE, nat_det_reverse, a7573fe1) \
_(VL_API_NAT_DET_REVERSE_REPLY, nat_det_reverse_reply, 34066d48) \
_(VL_API_NAT_DET_MAP_DUMP, nat_det_map_dump, 51077d14) \
_(VL_API_NAT_DET_MAP_DETAILS, nat_det_map_details, ad91dc83) \
_(VL_API_NAT_DET_CLOSE_SESSION_OUT, nat_det_close_session_out, f6b259d1) \
_(VL_API_NAT_DET_CLOSE_SESSION_OUT_REPLY, nat_det_close_session_out_reply, e8d4e804) \
_(VL_API_NAT_DET_CLOSE_SESSION_IN, nat_det_close_session_in, 3c68e073) \
_(VL_API_NAT_DET_CLOSE_SESSION_IN_REPLY, nat_det_close_session_in_reply, e8d4e804) \
_(VL_API_NAT_DET_SESSION_DUMP, nat_det_session_dump, e45a3af7) \
_(VL_API_NAT_DET_SESSION_DETAILS, nat_det_session_details, 27f3c171) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "det44.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_det44_printfun_types
#define included_det44_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_det44_printfun
#define included_det44_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "det44.api_tojson.h"
#include "det44.api_fromjson.h"

static inline u8 *vl_api_det44_plugin_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_plugin_enable_disable_t *a = va_arg (*args, vl_api_det44_plugin_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_plugin_enable_disable_t: */
    s = format(s, "vl_api_det44_plugin_enable_disable_t:");
    s = format(s, "\n%Uinside_vrf: %u", format_white_space, indent, a->inside_vrf);
    s = format(s, "\n%Uoutside_vrf: %u", format_white_space, indent, a->outside_vrf);
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}

static inline u8 *vl_api_det44_plugin_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_plugin_enable_disable_reply_t *a = va_arg (*args, vl_api_det44_plugin_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_plugin_enable_disable_reply_t: */
    s = format(s, "vl_api_det44_plugin_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_det44_interface_add_del_feature_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_interface_add_del_feature_t *a = va_arg (*args, vl_api_det44_interface_add_del_feature_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_interface_add_del_feature_t: */
    s = format(s, "vl_api_det44_interface_add_del_feature_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uis_inside: %u", format_white_space, indent, a->is_inside);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_det44_interface_add_del_feature_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_interface_add_del_feature_reply_t *a = va_arg (*args, vl_api_det44_interface_add_del_feature_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_interface_add_del_feature_reply_t: */
    s = format(s, "vl_api_det44_interface_add_del_feature_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_det44_interface_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_interface_dump_t *a = va_arg (*args, vl_api_det44_interface_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_interface_dump_t: */
    s = format(s, "vl_api_det44_interface_dump_t:");
    return s;
}

static inline u8 *vl_api_det44_interface_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_interface_details_t *a = va_arg (*args, vl_api_det44_interface_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_interface_details_t: */
    s = format(s, "vl_api_det44_interface_details_t:");
    s = format(s, "\n%Uis_inside: %u", format_white_space, indent, a->is_inside);
    s = format(s, "\n%Uis_outside: %u", format_white_space, indent, a->is_outside);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_det44_add_del_map_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_add_del_map_t *a = va_arg (*args, vl_api_det44_add_del_map_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_add_del_map_t: */
    s = format(s, "vl_api_det44_add_del_map_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uin_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->in_addr, indent);
    s = format(s, "\n%Uin_plen: %u", format_white_space, indent, a->in_plen);
    s = format(s, "\n%Uout_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->out_addr, indent);
    s = format(s, "\n%Uout_plen: %u", format_white_space, indent, a->out_plen);
    return s;
}

static inline u8 *vl_api_det44_add_del_map_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_add_del_map_reply_t *a = va_arg (*args, vl_api_det44_add_del_map_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_add_del_map_reply_t: */
    s = format(s, "vl_api_det44_add_del_map_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_det44_forward_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_forward_t *a = va_arg (*args, vl_api_det44_forward_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_forward_t: */
    s = format(s, "vl_api_det44_forward_t:");
    s = format(s, "\n%Uin_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->in_addr, indent);
    return s;
}

static inline u8 *vl_api_det44_forward_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_forward_reply_t *a = va_arg (*args, vl_api_det44_forward_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_forward_reply_t: */
    s = format(s, "vl_api_det44_forward_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uout_port_lo: %u", format_white_space, indent, a->out_port_lo);
    s = format(s, "\n%Uout_port_hi: %u", format_white_space, indent, a->out_port_hi);
    s = format(s, "\n%Uout_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->out_addr, indent);
    return s;
}

static inline u8 *vl_api_det44_reverse_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_reverse_t *a = va_arg (*args, vl_api_det44_reverse_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_reverse_t: */
    s = format(s, "vl_api_det44_reverse_t:");
    s = format(s, "\n%Uout_port: %u", format_white_space, indent, a->out_port);
    s = format(s, "\n%Uout_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->out_addr, indent);
    return s;
}

static inline u8 *vl_api_det44_reverse_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_reverse_reply_t *a = va_arg (*args, vl_api_det44_reverse_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_reverse_reply_t: */
    s = format(s, "vl_api_det44_reverse_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uin_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->in_addr, indent);
    return s;
}

static inline u8 *vl_api_det44_map_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_map_dump_t *a = va_arg (*args, vl_api_det44_map_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_map_dump_t: */
    s = format(s, "vl_api_det44_map_dump_t:");
    return s;
}

static inline u8 *vl_api_det44_map_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_map_details_t *a = va_arg (*args, vl_api_det44_map_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_map_details_t: */
    s = format(s, "vl_api_det44_map_details_t:");
    s = format(s, "\n%Uin_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->in_addr, indent);
    s = format(s, "\n%Uin_plen: %u", format_white_space, indent, a->in_plen);
    s = format(s, "\n%Uout_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->out_addr, indent);
    s = format(s, "\n%Uout_plen: %u", format_white_space, indent, a->out_plen);
    s = format(s, "\n%Usharing_ratio: %u", format_white_space, indent, a->sharing_ratio);
    s = format(s, "\n%Uports_per_host: %u", format_white_space, indent, a->ports_per_host);
    s = format(s, "\n%Uses_num: %u", format_white_space, indent, a->ses_num);
    return s;
}

static inline u8 *vl_api_det44_close_session_out_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_close_session_out_t *a = va_arg (*args, vl_api_det44_close_session_out_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_close_session_out_t: */
    s = format(s, "vl_api_det44_close_session_out_t:");
    s = format(s, "\n%Uout_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->out_addr, indent);
    s = format(s, "\n%Uout_port: %u", format_white_space, indent, a->out_port);
    s = format(s, "\n%Uext_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ext_addr, indent);
    s = format(s, "\n%Uext_port: %u", format_white_space, indent, a->ext_port);
    return s;
}

static inline u8 *vl_api_det44_close_session_out_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_close_session_out_reply_t *a = va_arg (*args, vl_api_det44_close_session_out_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_close_session_out_reply_t: */
    s = format(s, "vl_api_det44_close_session_out_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_det44_close_session_in_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_close_session_in_t *a = va_arg (*args, vl_api_det44_close_session_in_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_close_session_in_t: */
    s = format(s, "vl_api_det44_close_session_in_t:");
    s = format(s, "\n%Uin_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->in_addr, indent);
    s = format(s, "\n%Uin_port: %u", format_white_space, indent, a->in_port);
    s = format(s, "\n%Uext_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ext_addr, indent);
    s = format(s, "\n%Uext_port: %u", format_white_space, indent, a->ext_port);
    return s;
}

static inline u8 *vl_api_det44_close_session_in_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_close_session_in_reply_t *a = va_arg (*args, vl_api_det44_close_session_in_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_close_session_in_reply_t: */
    s = format(s, "vl_api_det44_close_session_in_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_det44_session_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_session_dump_t *a = va_arg (*args, vl_api_det44_session_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_session_dump_t: */
    s = format(s, "vl_api_det44_session_dump_t:");
    s = format(s, "\n%Uuser_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->user_addr, indent);
    return s;
}

static inline u8 *vl_api_det44_session_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_session_details_t *a = va_arg (*args, vl_api_det44_session_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_session_details_t: */
    s = format(s, "vl_api_det44_session_details_t:");
    s = format(s, "\n%Uin_port: %u", format_white_space, indent, a->in_port);
    s = format(s, "\n%Uext_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ext_addr, indent);
    s = format(s, "\n%Uext_port: %u", format_white_space, indent, a->ext_port);
    s = format(s, "\n%Uout_port: %u", format_white_space, indent, a->out_port);
    s = format(s, "\n%Ustate: %u", format_white_space, indent, a->state);
    s = format(s, "\n%Uexpire: %u", format_white_space, indent, a->expire);
    return s;
}

static inline u8 *vl_api_det44_set_timeouts_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_set_timeouts_t *a = va_arg (*args, vl_api_det44_set_timeouts_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_set_timeouts_t: */
    s = format(s, "vl_api_det44_set_timeouts_t:");
    s = format(s, "\n%Uudp: %u", format_white_space, indent, a->udp);
    s = format(s, "\n%Utcp_established: %u", format_white_space, indent, a->tcp_established);
    s = format(s, "\n%Utcp_transitory: %u", format_white_space, indent, a->tcp_transitory);
    s = format(s, "\n%Uicmp: %u", format_white_space, indent, a->icmp);
    return s;
}

static inline u8 *vl_api_det44_set_timeouts_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_set_timeouts_reply_t *a = va_arg (*args, vl_api_det44_set_timeouts_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_set_timeouts_reply_t: */
    s = format(s, "vl_api_det44_set_timeouts_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_det44_get_timeouts_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_get_timeouts_t *a = va_arg (*args, vl_api_det44_get_timeouts_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_get_timeouts_t: */
    s = format(s, "vl_api_det44_get_timeouts_t:");
    return s;
}

static inline u8 *vl_api_det44_get_timeouts_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_det44_get_timeouts_reply_t *a = va_arg (*args, vl_api_det44_get_timeouts_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_det44_get_timeouts_reply_t: */
    s = format(s, "vl_api_det44_get_timeouts_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uudp: %u", format_white_space, indent, a->udp);
    s = format(s, "\n%Utcp_established: %u", format_white_space, indent, a->tcp_established);
    s = format(s, "\n%Utcp_transitory: %u", format_white_space, indent, a->tcp_transitory);
    s = format(s, "\n%Uicmp: %u", format_white_space, indent, a->icmp);
    return s;
}

static inline u8 *vl_api_nat_det_add_del_map_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_det_add_del_map_t *a = va_arg (*args, vl_api_nat_det_add_del_map_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_det_add_del_map_t: */
    s = format(s, "vl_api_nat_det_add_del_map_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uin_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->in_addr, indent);
    s = format(s, "\n%Uin_plen: %u", format_white_space, indent, a->in_plen);
    s = format(s, "\n%Uout_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->out_addr, indent);
    s = format(s, "\n%Uout_plen: %u", format_white_space, indent, a->out_plen);
    return s;
}

static inline u8 *vl_api_nat_det_add_del_map_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_det_add_del_map_reply_t *a = va_arg (*args, vl_api_nat_det_add_del_map_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_det_add_del_map_reply_t: */
    s = format(s, "vl_api_nat_det_add_del_map_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat_det_forward_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_det_forward_t *a = va_arg (*args, vl_api_nat_det_forward_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_det_forward_t: */
    s = format(s, "vl_api_nat_det_forward_t:");
    s = format(s, "\n%Uin_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->in_addr, indent);
    return s;
}

static inline u8 *vl_api_nat_det_forward_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_det_forward_reply_t *a = va_arg (*args, vl_api_nat_det_forward_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_det_forward_reply_t: */
    s = format(s, "vl_api_nat_det_forward_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uout_port_lo: %u", format_white_space, indent, a->out_port_lo);
    s = format(s, "\n%Uout_port_hi: %u", format_white_space, indent, a->out_port_hi);
    s = format(s, "\n%Uout_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->out_addr, indent);
    return s;
}

static inline u8 *vl_api_nat_det_reverse_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_det_reverse_t *a = va_arg (*args, vl_api_nat_det_reverse_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_det_reverse_t: */
    s = format(s, "vl_api_nat_det_reverse_t:");
    s = format(s, "\n%Uout_port: %u", format_white_space, indent, a->out_port);
    s = format(s, "\n%Uout_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->out_addr, indent);
    return s;
}

static inline u8 *vl_api_nat_det_reverse_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_det_reverse_reply_t *a = va_arg (*args, vl_api_nat_det_reverse_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_det_reverse_reply_t: */
    s = format(s, "vl_api_nat_det_reverse_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uin_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->in_addr, indent);
    return s;
}

static inline u8 *vl_api_nat_det_map_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_det_map_dump_t *a = va_arg (*args, vl_api_nat_det_map_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_det_map_dump_t: */
    s = format(s, "vl_api_nat_det_map_dump_t:");
    return s;
}

static inline u8 *vl_api_nat_det_map_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_det_map_details_t *a = va_arg (*args, vl_api_nat_det_map_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_det_map_details_t: */
    s = format(s, "vl_api_nat_det_map_details_t:");
    s = format(s, "\n%Uin_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->in_addr, indent);
    s = format(s, "\n%Uin_plen: %u", format_white_space, indent, a->in_plen);
    s = format(s, "\n%Uout_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->out_addr, indent);
    s = format(s, "\n%Uout_plen: %u", format_white_space, indent, a->out_plen);
    s = format(s, "\n%Usharing_ratio: %u", format_white_space, indent, a->sharing_ratio);
    s = format(s, "\n%Uports_per_host: %u", format_white_space, indent, a->ports_per_host);
    s = format(s, "\n%Uses_num: %u", format_white_space, indent, a->ses_num);
    return s;
}

static inline u8 *vl_api_nat_det_close_session_out_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_det_close_session_out_t *a = va_arg (*args, vl_api_nat_det_close_session_out_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_det_close_session_out_t: */
    s = format(s, "vl_api_nat_det_close_session_out_t:");
    s = format(s, "\n%Uout_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->out_addr, indent);
    s = format(s, "\n%Uout_port: %u", format_white_space, indent, a->out_port);
    s = format(s, "\n%Uext_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ext_addr, indent);
    s = format(s, "\n%Uext_port: %u", format_white_space, indent, a->ext_port);
    return s;
}

static inline u8 *vl_api_nat_det_close_session_out_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_det_close_session_out_reply_t *a = va_arg (*args, vl_api_nat_det_close_session_out_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_det_close_session_out_reply_t: */
    s = format(s, "vl_api_nat_det_close_session_out_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat_det_close_session_in_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_det_close_session_in_t *a = va_arg (*args, vl_api_nat_det_close_session_in_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_det_close_session_in_t: */
    s = format(s, "vl_api_nat_det_close_session_in_t:");
    s = format(s, "\n%Uin_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->in_addr, indent);
    s = format(s, "\n%Uin_port: %u", format_white_space, indent, a->in_port);
    s = format(s, "\n%Uext_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ext_addr, indent);
    s = format(s, "\n%Uext_port: %u", format_white_space, indent, a->ext_port);
    return s;
}

static inline u8 *vl_api_nat_det_close_session_in_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_det_close_session_in_reply_t *a = va_arg (*args, vl_api_nat_det_close_session_in_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_det_close_session_in_reply_t: */
    s = format(s, "vl_api_nat_det_close_session_in_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat_det_session_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_det_session_dump_t *a = va_arg (*args, vl_api_nat_det_session_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_det_session_dump_t: */
    s = format(s, "vl_api_nat_det_session_dump_t:");
    s = format(s, "\n%Uuser_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->user_addr, indent);
    return s;
}

static inline u8 *vl_api_nat_det_session_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_det_session_details_t *a = va_arg (*args, vl_api_nat_det_session_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_det_session_details_t: */
    s = format(s, "vl_api_nat_det_session_details_t:");
    s = format(s, "\n%Uin_port: %u", format_white_space, indent, a->in_port);
    s = format(s, "\n%Uext_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ext_addr, indent);
    s = format(s, "\n%Uext_port: %u", format_white_space, indent, a->ext_port);
    s = format(s, "\n%Uout_port: %u", format_white_space, indent, a->out_port);
    s = format(s, "\n%Ustate: %u", format_white_space, indent, a->state);
    s = format(s, "\n%Uexpire: %u", format_white_space, indent, a->expire);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_det44_endianfun
#define included_det44_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_det44_plugin_enable_disable_t_endian (vl_api_det44_plugin_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->inside_vrf = clib_net_to_host_u32(a->inside_vrf);
    a->outside_vrf = clib_net_to_host_u32(a->outside_vrf);
    /* a->enable = a->enable (no-op) */
}

static inline void vl_api_det44_plugin_enable_disable_reply_t_endian (vl_api_det44_plugin_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_det44_interface_add_del_feature_t_endian (vl_api_det44_interface_add_del_feature_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    /* a->is_inside = a->is_inside (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_det44_interface_add_del_feature_reply_t_endian (vl_api_det44_interface_add_del_feature_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_det44_interface_dump_t_endian (vl_api_det44_interface_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_det44_interface_details_t_endian (vl_api_det44_interface_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_inside = a->is_inside (no-op) */
    /* a->is_outside = a->is_outside (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_det44_add_del_map_t_endian (vl_api_det44_add_del_map_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_ip4_address_t_endian(&a->in_addr, to_net);
    /* a->in_plen = a->in_plen (no-op) */
    vl_api_ip4_address_t_endian(&a->out_addr, to_net);
    /* a->out_plen = a->out_plen (no-op) */
}

static inline void vl_api_det44_add_del_map_reply_t_endian (vl_api_det44_add_del_map_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_det44_forward_t_endian (vl_api_det44_forward_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->in_addr, to_net);
}

static inline void vl_api_det44_forward_reply_t_endian (vl_api_det44_forward_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->out_port_lo = clib_net_to_host_u16(a->out_port_lo);
    a->out_port_hi = clib_net_to_host_u16(a->out_port_hi);
    vl_api_ip4_address_t_endian(&a->out_addr, to_net);
}

static inline void vl_api_det44_reverse_t_endian (vl_api_det44_reverse_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->out_port = clib_net_to_host_u16(a->out_port);
    vl_api_ip4_address_t_endian(&a->out_addr, to_net);
}

static inline void vl_api_det44_reverse_reply_t_endian (vl_api_det44_reverse_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_ip4_address_t_endian(&a->in_addr, to_net);
}

static inline void vl_api_det44_map_dump_t_endian (vl_api_det44_map_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_det44_map_details_t_endian (vl_api_det44_map_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->in_addr, to_net);
    /* a->in_plen = a->in_plen (no-op) */
    vl_api_ip4_address_t_endian(&a->out_addr, to_net);
    /* a->out_plen = a->out_plen (no-op) */
    a->sharing_ratio = clib_net_to_host_u32(a->sharing_ratio);
    a->ports_per_host = clib_net_to_host_u16(a->ports_per_host);
    a->ses_num = clib_net_to_host_u32(a->ses_num);
}

static inline void vl_api_det44_close_session_out_t_endian (vl_api_det44_close_session_out_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->out_addr, to_net);
    a->out_port = clib_net_to_host_u16(a->out_port);
    vl_api_ip4_address_t_endian(&a->ext_addr, to_net);
    a->ext_port = clib_net_to_host_u16(a->ext_port);
}

static inline void vl_api_det44_close_session_out_reply_t_endian (vl_api_det44_close_session_out_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_det44_close_session_in_t_endian (vl_api_det44_close_session_in_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->in_addr, to_net);
    a->in_port = clib_net_to_host_u16(a->in_port);
    vl_api_ip4_address_t_endian(&a->ext_addr, to_net);
    a->ext_port = clib_net_to_host_u16(a->ext_port);
}

static inline void vl_api_det44_close_session_in_reply_t_endian (vl_api_det44_close_session_in_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_det44_session_dump_t_endian (vl_api_det44_session_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->user_addr, to_net);
}

static inline void vl_api_det44_session_details_t_endian (vl_api_det44_session_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->in_port = clib_net_to_host_u16(a->in_port);
    vl_api_ip4_address_t_endian(&a->ext_addr, to_net);
    a->ext_port = clib_net_to_host_u16(a->ext_port);
    a->out_port = clib_net_to_host_u16(a->out_port);
    /* a->state = a->state (no-op) */
    a->expire = clib_net_to_host_u32(a->expire);
}

static inline void vl_api_det44_set_timeouts_t_endian (vl_api_det44_set_timeouts_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->udp = clib_net_to_host_u32(a->udp);
    a->tcp_established = clib_net_to_host_u32(a->tcp_established);
    a->tcp_transitory = clib_net_to_host_u32(a->tcp_transitory);
    a->icmp = clib_net_to_host_u32(a->icmp);
}

static inline void vl_api_det44_set_timeouts_reply_t_endian (vl_api_det44_set_timeouts_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_det44_get_timeouts_t_endian (vl_api_det44_get_timeouts_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_det44_get_timeouts_reply_t_endian (vl_api_det44_get_timeouts_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->udp = clib_net_to_host_u32(a->udp);
    a->tcp_established = clib_net_to_host_u32(a->tcp_established);
    a->tcp_transitory = clib_net_to_host_u32(a->tcp_transitory);
    a->icmp = clib_net_to_host_u32(a->icmp);
}

static inline void vl_api_nat_det_add_del_map_t_endian (vl_api_nat_det_add_del_map_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_ip4_address_t_endian(&a->in_addr, to_net);
    /* a->in_plen = a->in_plen (no-op) */
    vl_api_ip4_address_t_endian(&a->out_addr, to_net);
    /* a->out_plen = a->out_plen (no-op) */
}

static inline void vl_api_nat_det_add_del_map_reply_t_endian (vl_api_nat_det_add_del_map_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat_det_forward_t_endian (vl_api_nat_det_forward_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->in_addr, to_net);
}

static inline void vl_api_nat_det_forward_reply_t_endian (vl_api_nat_det_forward_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->out_port_lo = clib_net_to_host_u16(a->out_port_lo);
    a->out_port_hi = clib_net_to_host_u16(a->out_port_hi);
    vl_api_ip4_address_t_endian(&a->out_addr, to_net);
}

static inline void vl_api_nat_det_reverse_t_endian (vl_api_nat_det_reverse_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->out_port = clib_net_to_host_u16(a->out_port);
    vl_api_ip4_address_t_endian(&a->out_addr, to_net);
}

static inline void vl_api_nat_det_reverse_reply_t_endian (vl_api_nat_det_reverse_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_ip4_address_t_endian(&a->in_addr, to_net);
}

static inline void vl_api_nat_det_map_dump_t_endian (vl_api_nat_det_map_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat_det_map_details_t_endian (vl_api_nat_det_map_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->in_addr, to_net);
    /* a->in_plen = a->in_plen (no-op) */
    vl_api_ip4_address_t_endian(&a->out_addr, to_net);
    /* a->out_plen = a->out_plen (no-op) */
    a->sharing_ratio = clib_net_to_host_u32(a->sharing_ratio);
    a->ports_per_host = clib_net_to_host_u16(a->ports_per_host);
    a->ses_num = clib_net_to_host_u32(a->ses_num);
}

static inline void vl_api_nat_det_close_session_out_t_endian (vl_api_nat_det_close_session_out_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->out_addr, to_net);
    a->out_port = clib_net_to_host_u16(a->out_port);
    vl_api_ip4_address_t_endian(&a->ext_addr, to_net);
    a->ext_port = clib_net_to_host_u16(a->ext_port);
}

static inline void vl_api_nat_det_close_session_out_reply_t_endian (vl_api_nat_det_close_session_out_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat_det_close_session_in_t_endian (vl_api_nat_det_close_session_in_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->in_addr, to_net);
    a->in_port = clib_net_to_host_u16(a->in_port);
    vl_api_ip4_address_t_endian(&a->ext_addr, to_net);
    a->ext_port = clib_net_to_host_u16(a->ext_port);
}

static inline void vl_api_nat_det_close_session_in_reply_t_endian (vl_api_nat_det_close_session_in_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat_det_session_dump_t_endian (vl_api_nat_det_session_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->user_addr, to_net);
}

static inline void vl_api_nat_det_session_details_t_endian (vl_api_nat_det_session_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->in_port = clib_net_to_host_u16(a->in_port);
    vl_api_ip4_address_t_endian(&a->ext_addr, to_net);
    a->ext_port = clib_net_to_host_u16(a->ext_port);
    a->out_port = clib_net_to_host_u16(a->out_port);
    /* a->state = a->state (no-op) */
    a->expire = clib_net_to_host_u32(a->expire);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_det44_calcsizefun
#define included_det44_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_plugin_enable_disable_t_calc_size (vl_api_det44_plugin_enable_disable_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_plugin_enable_disable_reply_t_calc_size (vl_api_det44_plugin_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_interface_add_del_feature_t_calc_size (vl_api_det44_interface_add_del_feature_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_interface_add_del_feature_reply_t_calc_size (vl_api_det44_interface_add_del_feature_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_interface_dump_t_calc_size (vl_api_det44_interface_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_interface_details_t_calc_size (vl_api_det44_interface_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_add_del_map_t_calc_size (vl_api_det44_add_del_map_t *a)
{
      return sizeof(*a) - sizeof(a->in_addr) + vl_api_ip4_address_t_calc_size(&a->in_addr) - sizeof(a->out_addr) + vl_api_ip4_address_t_calc_size(&a->out_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_add_del_map_reply_t_calc_size (vl_api_det44_add_del_map_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_forward_t_calc_size (vl_api_det44_forward_t *a)
{
      return sizeof(*a) - sizeof(a->in_addr) + vl_api_ip4_address_t_calc_size(&a->in_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_forward_reply_t_calc_size (vl_api_det44_forward_reply_t *a)
{
      return sizeof(*a) - sizeof(a->out_addr) + vl_api_ip4_address_t_calc_size(&a->out_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_reverse_t_calc_size (vl_api_det44_reverse_t *a)
{
      return sizeof(*a) - sizeof(a->out_addr) + vl_api_ip4_address_t_calc_size(&a->out_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_reverse_reply_t_calc_size (vl_api_det44_reverse_reply_t *a)
{
      return sizeof(*a) - sizeof(a->in_addr) + vl_api_ip4_address_t_calc_size(&a->in_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_map_dump_t_calc_size (vl_api_det44_map_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_map_details_t_calc_size (vl_api_det44_map_details_t *a)
{
      return sizeof(*a) - sizeof(a->in_addr) + vl_api_ip4_address_t_calc_size(&a->in_addr) - sizeof(a->out_addr) + vl_api_ip4_address_t_calc_size(&a->out_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_close_session_out_t_calc_size (vl_api_det44_close_session_out_t *a)
{
      return sizeof(*a) - sizeof(a->out_addr) + vl_api_ip4_address_t_calc_size(&a->out_addr) - sizeof(a->ext_addr) + vl_api_ip4_address_t_calc_size(&a->ext_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_close_session_out_reply_t_calc_size (vl_api_det44_close_session_out_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_close_session_in_t_calc_size (vl_api_det44_close_session_in_t *a)
{
      return sizeof(*a) - sizeof(a->in_addr) + vl_api_ip4_address_t_calc_size(&a->in_addr) - sizeof(a->ext_addr) + vl_api_ip4_address_t_calc_size(&a->ext_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_close_session_in_reply_t_calc_size (vl_api_det44_close_session_in_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_session_dump_t_calc_size (vl_api_det44_session_dump_t *a)
{
      return sizeof(*a) - sizeof(a->user_addr) + vl_api_ip4_address_t_calc_size(&a->user_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_session_details_t_calc_size (vl_api_det44_session_details_t *a)
{
      return sizeof(*a) - sizeof(a->ext_addr) + vl_api_ip4_address_t_calc_size(&a->ext_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_set_timeouts_t_calc_size (vl_api_det44_set_timeouts_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_set_timeouts_reply_t_calc_size (vl_api_det44_set_timeouts_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_get_timeouts_t_calc_size (vl_api_det44_get_timeouts_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_det44_get_timeouts_reply_t_calc_size (vl_api_det44_get_timeouts_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_det_add_del_map_t_calc_size (vl_api_nat_det_add_del_map_t *a)
{
      return sizeof(*a) - sizeof(a->in_addr) + vl_api_ip4_address_t_calc_size(&a->in_addr) - sizeof(a->out_addr) + vl_api_ip4_address_t_calc_size(&a->out_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_det_add_del_map_reply_t_calc_size (vl_api_nat_det_add_del_map_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_det_forward_t_calc_size (vl_api_nat_det_forward_t *a)
{
      return sizeof(*a) - sizeof(a->in_addr) + vl_api_ip4_address_t_calc_size(&a->in_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_det_forward_reply_t_calc_size (vl_api_nat_det_forward_reply_t *a)
{
      return sizeof(*a) - sizeof(a->out_addr) + vl_api_ip4_address_t_calc_size(&a->out_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_det_reverse_t_calc_size (vl_api_nat_det_reverse_t *a)
{
      return sizeof(*a) - sizeof(a->out_addr) + vl_api_ip4_address_t_calc_size(&a->out_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_det_reverse_reply_t_calc_size (vl_api_nat_det_reverse_reply_t *a)
{
      return sizeof(*a) - sizeof(a->in_addr) + vl_api_ip4_address_t_calc_size(&a->in_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_det_map_dump_t_calc_size (vl_api_nat_det_map_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_det_map_details_t_calc_size (vl_api_nat_det_map_details_t *a)
{
      return sizeof(*a) - sizeof(a->in_addr) + vl_api_ip4_address_t_calc_size(&a->in_addr) - sizeof(a->out_addr) + vl_api_ip4_address_t_calc_size(&a->out_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_det_close_session_out_t_calc_size (vl_api_nat_det_close_session_out_t *a)
{
      return sizeof(*a) - sizeof(a->out_addr) + vl_api_ip4_address_t_calc_size(&a->out_addr) - sizeof(a->ext_addr) + vl_api_ip4_address_t_calc_size(&a->ext_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_det_close_session_out_reply_t_calc_size (vl_api_nat_det_close_session_out_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_det_close_session_in_t_calc_size (vl_api_nat_det_close_session_in_t *a)
{
      return sizeof(*a) - sizeof(a->in_addr) + vl_api_ip4_address_t_calc_size(&a->in_addr) - sizeof(a->ext_addr) + vl_api_ip4_address_t_calc_size(&a->ext_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_det_close_session_in_reply_t_calc_size (vl_api_nat_det_close_session_in_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_det_session_dump_t_calc_size (vl_api_nat_det_session_dump_t *a)
{
      return sizeof(*a) - sizeof(a->user_addr) + vl_api_ip4_address_t_calc_size(&a->user_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_det_session_details_t_calc_size (vl_api_nat_det_session_details_t *a)
{
      return sizeof(*a) - sizeof(a->ext_addr) + vl_api_ip4_address_t_calc_size(&a->ext_addr);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(det44.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(det44.api, 0xee5882b1)

#endif

