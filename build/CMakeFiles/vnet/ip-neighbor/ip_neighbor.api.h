/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: ip_neighbor.api
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
#warning no content included from ip_neighbor.api
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
#include <vnet/ethernet/ethernet_types.api.h>
#include <vnet/interface_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_IP_NEIGHBOR_ADD_DEL, vl_api_ip_neighbor_add_del_t_handler)
vl_msg_id(VL_API_IP_NEIGHBOR_ADD_DEL_REPLY, vl_api_ip_neighbor_add_del_reply_t_handler)
vl_msg_id(VL_API_IP_NEIGHBOR_DUMP, vl_api_ip_neighbor_dump_t_handler)
vl_msg_id(VL_API_IP_NEIGHBOR_DETAILS, vl_api_ip_neighbor_details_t_handler)
vl_msg_id(VL_API_IP_NEIGHBOR_CONFIG, vl_api_ip_neighbor_config_t_handler)
vl_msg_id(VL_API_IP_NEIGHBOR_CONFIG_REPLY, vl_api_ip_neighbor_config_reply_t_handler)
vl_msg_id(VL_API_IP_NEIGHBOR_CONFIG_GET, vl_api_ip_neighbor_config_get_t_handler)
vl_msg_id(VL_API_IP_NEIGHBOR_CONFIG_GET_REPLY, vl_api_ip_neighbor_config_get_reply_t_handler)
vl_msg_id(VL_API_IP_NEIGHBOR_REPLACE_BEGIN, vl_api_ip_neighbor_replace_begin_t_handler)
vl_msg_id(VL_API_IP_NEIGHBOR_REPLACE_BEGIN_REPLY, vl_api_ip_neighbor_replace_begin_reply_t_handler)
vl_msg_id(VL_API_IP_NEIGHBOR_REPLACE_END, vl_api_ip_neighbor_replace_end_t_handler)
vl_msg_id(VL_API_IP_NEIGHBOR_REPLACE_END_REPLY, vl_api_ip_neighbor_replace_end_reply_t_handler)
vl_msg_id(VL_API_IP_NEIGHBOR_FLUSH, vl_api_ip_neighbor_flush_t_handler)
vl_msg_id(VL_API_IP_NEIGHBOR_FLUSH_REPLY, vl_api_ip_neighbor_flush_reply_t_handler)
vl_msg_id(VL_API_WANT_IP_NEIGHBOR_EVENTS, vl_api_want_ip_neighbor_events_t_handler)
vl_msg_id(VL_API_WANT_IP_NEIGHBOR_EVENTS_REPLY, vl_api_want_ip_neighbor_events_reply_t_handler)
vl_msg_id(VL_API_IP_NEIGHBOR_EVENT, vl_api_ip_neighbor_event_t_handler)
vl_msg_id(VL_API_WANT_IP_NEIGHBOR_EVENTS_V2, vl_api_want_ip_neighbor_events_v2_t_handler)
vl_msg_id(VL_API_WANT_IP_NEIGHBOR_EVENTS_V2_REPLY, vl_api_want_ip_neighbor_events_v2_reply_t_handler)
vl_msg_id(VL_API_IP_NEIGHBOR_EVENT_V2, vl_api_ip_neighbor_event_v2_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_ip_neighbor_add_del_t, 1)
vl_msg_name(vl_api_ip_neighbor_add_del_reply_t, 1)
vl_msg_name(vl_api_ip_neighbor_dump_t, 1)
vl_msg_name(vl_api_ip_neighbor_details_t, 1)
vl_msg_name(vl_api_ip_neighbor_config_t, 1)
vl_msg_name(vl_api_ip_neighbor_config_reply_t, 1)
vl_msg_name(vl_api_ip_neighbor_config_get_t, 1)
vl_msg_name(vl_api_ip_neighbor_config_get_reply_t, 1)
vl_msg_name(vl_api_ip_neighbor_replace_begin_t, 1)
vl_msg_name(vl_api_ip_neighbor_replace_begin_reply_t, 1)
vl_msg_name(vl_api_ip_neighbor_replace_end_t, 1)
vl_msg_name(vl_api_ip_neighbor_replace_end_reply_t, 1)
vl_msg_name(vl_api_ip_neighbor_flush_t, 1)
vl_msg_name(vl_api_ip_neighbor_flush_reply_t, 1)
vl_msg_name(vl_api_want_ip_neighbor_events_t, 1)
vl_msg_name(vl_api_want_ip_neighbor_events_reply_t, 1)
vl_msg_name(vl_api_ip_neighbor_event_t, 1)
vl_msg_name(vl_api_want_ip_neighbor_events_v2_t, 1)
vl_msg_name(vl_api_want_ip_neighbor_events_v2_reply_t, 1)
vl_msg_name(vl_api_ip_neighbor_event_v2_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_ip_neighbor \
_(VL_API_IP_NEIGHBOR_ADD_DEL, ip_neighbor_add_del, 0607c257) \
_(VL_API_IP_NEIGHBOR_ADD_DEL_REPLY, ip_neighbor_add_del_reply, 1992deab) \
_(VL_API_IP_NEIGHBOR_DUMP, ip_neighbor_dump, d817a484) \
_(VL_API_IP_NEIGHBOR_DETAILS, ip_neighbor_details, e29d79f0) \
_(VL_API_IP_NEIGHBOR_CONFIG, ip_neighbor_config, f4a5cf44) \
_(VL_API_IP_NEIGHBOR_CONFIG_REPLY, ip_neighbor_config_reply, e8d4e804) \
_(VL_API_IP_NEIGHBOR_CONFIG_GET, ip_neighbor_config_get, a5db7bf7) \
_(VL_API_IP_NEIGHBOR_CONFIG_GET_REPLY, ip_neighbor_config_get_reply, 798e6fdd) \
_(VL_API_IP_NEIGHBOR_REPLACE_BEGIN, ip_neighbor_replace_begin, 51077d14) \
_(VL_API_IP_NEIGHBOR_REPLACE_BEGIN_REPLY, ip_neighbor_replace_begin_reply, e8d4e804) \
_(VL_API_IP_NEIGHBOR_REPLACE_END, ip_neighbor_replace_end, 51077d14) \
_(VL_API_IP_NEIGHBOR_REPLACE_END_REPLY, ip_neighbor_replace_end_reply, e8d4e804) \
_(VL_API_IP_NEIGHBOR_FLUSH, ip_neighbor_flush, 16aa35d2) \
_(VL_API_IP_NEIGHBOR_FLUSH_REPLY, ip_neighbor_flush_reply, e8d4e804) \
_(VL_API_WANT_IP_NEIGHBOR_EVENTS, want_ip_neighbor_events, 73e70a86) \
_(VL_API_WANT_IP_NEIGHBOR_EVENTS_REPLY, want_ip_neighbor_events_reply, e8d4e804) \
_(VL_API_IP_NEIGHBOR_EVENT, ip_neighbor_event, bdb092b2) \
_(VL_API_WANT_IP_NEIGHBOR_EVENTS_V2, want_ip_neighbor_events_v2, 73e70a86) \
_(VL_API_WANT_IP_NEIGHBOR_EVENTS_V2_REPLY, want_ip_neighbor_events_v2_reply, e8d4e804) \
_(VL_API_IP_NEIGHBOR_EVENT_V2, ip_neighbor_event_v2, c1d53dc0) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "ip_neighbor.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_ip_neighbor_printfun_types
#define included_ip_neighbor_printfun_types

static inline u8 *format_vl_api_ip_neighbor_flags_t (u8 *s, va_list * args)
{
    vl_api_ip_neighbor_flags_t *a = va_arg (*args, vl_api_ip_neighbor_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "IP_API_NEIGHBOR_FLAG_NONE");
    case 1:
        return format(s, "IP_API_NEIGHBOR_FLAG_STATIC");
    case 2:
        return format(s, "IP_API_NEIGHBOR_FLAG_NO_FIB_ENTRY");
    }
    return s;
}

static inline u8 *format_vl_api_ip_neighbor_t (u8 *s, va_list * args)
{
    vl_api_ip_neighbor_t *a = va_arg (*args, vl_api_ip_neighbor_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_ip_neighbor_flags_t, &a->flags, indent);
    s = format(s, "\n%Umac_address: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->mac_address, indent);
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_address_t, &a->ip_address, indent);
    return s;
}

static inline u8 *format_vl_api_ip_neighbor_event_flags_t (u8 *s, va_list * args)
{
    vl_api_ip_neighbor_event_flags_t *a = va_arg (*args, vl_api_ip_neighbor_event_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "IP_NEIGHBOR_API_EVENT_FLAG_ADDED");
    case 2:
        return format(s, "IP_NEIGHBOR_API_EVENT_FLAG_REMOVED");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_ip_neighbor_printfun
#define included_ip_neighbor_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "ip_neighbor.api_tojson.h"
#include "ip_neighbor.api_fromjson.h"

static inline u8 *vl_api_ip_neighbor_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_neighbor_add_del_t *a = va_arg (*args, vl_api_ip_neighbor_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_neighbor_add_del_t: */
    s = format(s, "vl_api_ip_neighbor_add_del_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uneighbor: %U", format_white_space, indent, format_vl_api_ip_neighbor_t, &a->neighbor, indent);
    return s;
}

static inline u8 *vl_api_ip_neighbor_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_neighbor_add_del_reply_t *a = va_arg (*args, vl_api_ip_neighbor_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_neighbor_add_del_reply_t: */
    s = format(s, "vl_api_ip_neighbor_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ustats_index: %u", format_white_space, indent, a->stats_index);
    return s;
}

static inline u8 *vl_api_ip_neighbor_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_neighbor_dump_t *a = va_arg (*args, vl_api_ip_neighbor_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_neighbor_dump_t: */
    s = format(s, "vl_api_ip_neighbor_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uaf: %U", format_white_space, indent, format_vl_api_address_family_t, &a->af, indent);
    return s;
}

static inline u8 *vl_api_ip_neighbor_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_neighbor_details_t *a = va_arg (*args, vl_api_ip_neighbor_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_neighbor_details_t: */
    s = format(s, "vl_api_ip_neighbor_details_t:");
    s = format(s, "\n%Uage: %.2f", format_white_space, indent, a->age);
    s = format(s, "\n%Uneighbor: %U", format_white_space, indent, format_vl_api_ip_neighbor_t, &a->neighbor, indent);
    return s;
}

static inline u8 *vl_api_ip_neighbor_config_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_neighbor_config_t *a = va_arg (*args, vl_api_ip_neighbor_config_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_neighbor_config_t: */
    s = format(s, "vl_api_ip_neighbor_config_t:");
    s = format(s, "\n%Uaf: %U", format_white_space, indent, format_vl_api_address_family_t, &a->af, indent);
    s = format(s, "\n%Umax_number: %u", format_white_space, indent, a->max_number);
    s = format(s, "\n%Umax_age: %u", format_white_space, indent, a->max_age);
    s = format(s, "\n%Urecycle: %u", format_white_space, indent, a->recycle);
    return s;
}

static inline u8 *vl_api_ip_neighbor_config_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_neighbor_config_reply_t *a = va_arg (*args, vl_api_ip_neighbor_config_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_neighbor_config_reply_t: */
    s = format(s, "vl_api_ip_neighbor_config_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ip_neighbor_config_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_neighbor_config_get_t *a = va_arg (*args, vl_api_ip_neighbor_config_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_neighbor_config_get_t: */
    s = format(s, "vl_api_ip_neighbor_config_get_t:");
    s = format(s, "\n%Uaf: %U", format_white_space, indent, format_vl_api_address_family_t, &a->af, indent);
    return s;
}

static inline u8 *vl_api_ip_neighbor_config_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_neighbor_config_get_reply_t *a = va_arg (*args, vl_api_ip_neighbor_config_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_neighbor_config_get_reply_t: */
    s = format(s, "vl_api_ip_neighbor_config_get_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uaf: %U", format_white_space, indent, format_vl_api_address_family_t, &a->af, indent);
    s = format(s, "\n%Umax_number: %u", format_white_space, indent, a->max_number);
    s = format(s, "\n%Umax_age: %u", format_white_space, indent, a->max_age);
    s = format(s, "\n%Urecycle: %u", format_white_space, indent, a->recycle);
    return s;
}

static inline u8 *vl_api_ip_neighbor_replace_begin_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_neighbor_replace_begin_t *a = va_arg (*args, vl_api_ip_neighbor_replace_begin_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_neighbor_replace_begin_t: */
    s = format(s, "vl_api_ip_neighbor_replace_begin_t:");
    return s;
}

static inline u8 *vl_api_ip_neighbor_replace_begin_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_neighbor_replace_begin_reply_t *a = va_arg (*args, vl_api_ip_neighbor_replace_begin_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_neighbor_replace_begin_reply_t: */
    s = format(s, "vl_api_ip_neighbor_replace_begin_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ip_neighbor_replace_end_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_neighbor_replace_end_t *a = va_arg (*args, vl_api_ip_neighbor_replace_end_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_neighbor_replace_end_t: */
    s = format(s, "vl_api_ip_neighbor_replace_end_t:");
    return s;
}

static inline u8 *vl_api_ip_neighbor_replace_end_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_neighbor_replace_end_reply_t *a = va_arg (*args, vl_api_ip_neighbor_replace_end_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_neighbor_replace_end_reply_t: */
    s = format(s, "vl_api_ip_neighbor_replace_end_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ip_neighbor_flush_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_neighbor_flush_t *a = va_arg (*args, vl_api_ip_neighbor_flush_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_neighbor_flush_t: */
    s = format(s, "vl_api_ip_neighbor_flush_t:");
    s = format(s, "\n%Uaf: %U", format_white_space, indent, format_vl_api_address_family_t, &a->af, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_ip_neighbor_flush_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_neighbor_flush_reply_t *a = va_arg (*args, vl_api_ip_neighbor_flush_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_neighbor_flush_reply_t: */
    s = format(s, "vl_api_ip_neighbor_flush_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_want_ip_neighbor_events_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_want_ip_neighbor_events_t *a = va_arg (*args, vl_api_want_ip_neighbor_events_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_want_ip_neighbor_events_t: */
    s = format(s, "vl_api_want_ip_neighbor_events_t:");
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    s = format(s, "\n%Upid: %u", format_white_space, indent, a->pid);
    s = format(s, "\n%Uip: %U", format_white_space, indent, format_vl_api_address_t, &a->ip, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_want_ip_neighbor_events_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_want_ip_neighbor_events_reply_t *a = va_arg (*args, vl_api_want_ip_neighbor_events_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_want_ip_neighbor_events_reply_t: */
    s = format(s, "vl_api_want_ip_neighbor_events_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ip_neighbor_event_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_neighbor_event_t *a = va_arg (*args, vl_api_ip_neighbor_event_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_neighbor_event_t: */
    s = format(s, "vl_api_ip_neighbor_event_t:");
    s = format(s, "\n%Upid: %u", format_white_space, indent, a->pid);
    s = format(s, "\n%Uneighbor: %U", format_white_space, indent, format_vl_api_ip_neighbor_t, &a->neighbor, indent);
    return s;
}

static inline u8 *vl_api_want_ip_neighbor_events_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_want_ip_neighbor_events_v2_t *a = va_arg (*args, vl_api_want_ip_neighbor_events_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_want_ip_neighbor_events_v2_t: */
    s = format(s, "vl_api_want_ip_neighbor_events_v2_t:");
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    s = format(s, "\n%Upid: %u", format_white_space, indent, a->pid);
    s = format(s, "\n%Uip: %U", format_white_space, indent, format_vl_api_address_t, &a->ip, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_want_ip_neighbor_events_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_want_ip_neighbor_events_v2_reply_t *a = va_arg (*args, vl_api_want_ip_neighbor_events_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_want_ip_neighbor_events_v2_reply_t: */
    s = format(s, "vl_api_want_ip_neighbor_events_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ip_neighbor_event_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip_neighbor_event_v2_t *a = va_arg (*args, vl_api_ip_neighbor_event_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip_neighbor_event_v2_t: */
    s = format(s, "vl_api_ip_neighbor_event_v2_t:");
    s = format(s, "\n%Upid: %u", format_white_space, indent, a->pid);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_ip_neighbor_event_flags_t, &a->flags, indent);
    s = format(s, "\n%Uneighbor: %U", format_white_space, indent, format_vl_api_ip_neighbor_t, &a->neighbor, indent);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_ip_neighbor_endianfun
#define included_ip_neighbor_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_ip_neighbor_flags_t_endian (vl_api_ip_neighbor_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->ip_neighbor_flags = a->ip_neighbor_flags (no-op) */
}

static inline void vl_api_ip_neighbor_t_endian (vl_api_ip_neighbor_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_ip_neighbor_flags_t_endian(&a->flags, to_net);
    vl_api_mac_address_t_endian(&a->mac_address, to_net);
    vl_api_address_t_endian(&a->ip_address, to_net);
}

static inline void vl_api_ip_neighbor_event_flags_t_endian (vl_api_ip_neighbor_event_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_ip_neighbor_add_del_t_endian (vl_api_ip_neighbor_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_ip_neighbor_t_endian(&a->neighbor, to_net);
}

static inline void vl_api_ip_neighbor_add_del_reply_t_endian (vl_api_ip_neighbor_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->stats_index = clib_net_to_host_u32(a->stats_index);
}

static inline void vl_api_ip_neighbor_dump_t_endian (vl_api_ip_neighbor_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_address_family_t_endian(&a->af, to_net);
}

static inline void vl_api_ip_neighbor_details_t_endian (vl_api_ip_neighbor_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->age = clib_net_to_host_f64(a->age);
    vl_api_ip_neighbor_t_endian(&a->neighbor, to_net);
}

static inline void vl_api_ip_neighbor_config_t_endian (vl_api_ip_neighbor_config_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_address_family_t_endian(&a->af, to_net);
    a->max_number = clib_net_to_host_u32(a->max_number);
    a->max_age = clib_net_to_host_u32(a->max_age);
    /* a->recycle = a->recycle (no-op) */
}

static inline void vl_api_ip_neighbor_config_reply_t_endian (vl_api_ip_neighbor_config_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ip_neighbor_config_get_t_endian (vl_api_ip_neighbor_config_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_address_family_t_endian(&a->af, to_net);
}

static inline void vl_api_ip_neighbor_config_get_reply_t_endian (vl_api_ip_neighbor_config_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_address_family_t_endian(&a->af, to_net);
    a->max_number = clib_net_to_host_u32(a->max_number);
    a->max_age = clib_net_to_host_u32(a->max_age);
    /* a->recycle = a->recycle (no-op) */
}

static inline void vl_api_ip_neighbor_replace_begin_t_endian (vl_api_ip_neighbor_replace_begin_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_ip_neighbor_replace_begin_reply_t_endian (vl_api_ip_neighbor_replace_begin_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ip_neighbor_replace_end_t_endian (vl_api_ip_neighbor_replace_end_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_ip_neighbor_replace_end_reply_t_endian (vl_api_ip_neighbor_replace_end_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ip_neighbor_flush_t_endian (vl_api_ip_neighbor_flush_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_address_family_t_endian(&a->af, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_ip_neighbor_flush_reply_t_endian (vl_api_ip_neighbor_flush_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_want_ip_neighbor_events_t_endian (vl_api_want_ip_neighbor_events_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->enable = a->enable (no-op) */
    a->pid = clib_net_to_host_u32(a->pid);
    vl_api_address_t_endian(&a->ip, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_want_ip_neighbor_events_reply_t_endian (vl_api_want_ip_neighbor_events_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ip_neighbor_event_t_endian (vl_api_ip_neighbor_event_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->pid = clib_net_to_host_u32(a->pid);
    vl_api_ip_neighbor_t_endian(&a->neighbor, to_net);
}

static inline void vl_api_want_ip_neighbor_events_v2_t_endian (vl_api_want_ip_neighbor_events_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->enable = a->enable (no-op) */
    a->pid = clib_net_to_host_u32(a->pid);
    vl_api_address_t_endian(&a->ip, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_want_ip_neighbor_events_v2_reply_t_endian (vl_api_want_ip_neighbor_events_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ip_neighbor_event_v2_t_endian (vl_api_ip_neighbor_event_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->pid = clib_net_to_host_u32(a->pid);
    vl_api_ip_neighbor_event_flags_t_endian(&a->flags, to_net);
    vl_api_ip_neighbor_t_endian(&a->neighbor, to_net);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_ip_neighbor_calcsizefun
#define included_ip_neighbor_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_neighbor_flags_t_calc_size (vl_api_ip_neighbor_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_neighbor_t_calc_size (vl_api_ip_neighbor_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->flags) + vl_api_ip_neighbor_flags_t_calc_size(&a->flags) - sizeof(a->mac_address) + vl_api_mac_address_t_calc_size(&a->mac_address) - sizeof(a->ip_address) + vl_api_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_neighbor_event_flags_t_calc_size (vl_api_ip_neighbor_event_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_neighbor_add_del_t_calc_size (vl_api_ip_neighbor_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->neighbor) + vl_api_ip_neighbor_t_calc_size(&a->neighbor);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_neighbor_add_del_reply_t_calc_size (vl_api_ip_neighbor_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_neighbor_dump_t_calc_size (vl_api_ip_neighbor_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->af) + vl_api_address_family_t_calc_size(&a->af);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_neighbor_details_t_calc_size (vl_api_ip_neighbor_details_t *a)
{
      return sizeof(*a) - sizeof(a->neighbor) + vl_api_ip_neighbor_t_calc_size(&a->neighbor);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_neighbor_config_t_calc_size (vl_api_ip_neighbor_config_t *a)
{
      return sizeof(*a) - sizeof(a->af) + vl_api_address_family_t_calc_size(&a->af);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_neighbor_config_reply_t_calc_size (vl_api_ip_neighbor_config_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_neighbor_config_get_t_calc_size (vl_api_ip_neighbor_config_get_t *a)
{
      return sizeof(*a) - sizeof(a->af) + vl_api_address_family_t_calc_size(&a->af);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_neighbor_config_get_reply_t_calc_size (vl_api_ip_neighbor_config_get_reply_t *a)
{
      return sizeof(*a) - sizeof(a->af) + vl_api_address_family_t_calc_size(&a->af);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_neighbor_replace_begin_t_calc_size (vl_api_ip_neighbor_replace_begin_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_neighbor_replace_begin_reply_t_calc_size (vl_api_ip_neighbor_replace_begin_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_neighbor_replace_end_t_calc_size (vl_api_ip_neighbor_replace_end_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_neighbor_replace_end_reply_t_calc_size (vl_api_ip_neighbor_replace_end_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_neighbor_flush_t_calc_size (vl_api_ip_neighbor_flush_t *a)
{
      return sizeof(*a) - sizeof(a->af) + vl_api_address_family_t_calc_size(&a->af) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_neighbor_flush_reply_t_calc_size (vl_api_ip_neighbor_flush_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_want_ip_neighbor_events_t_calc_size (vl_api_want_ip_neighbor_events_t *a)
{
      return sizeof(*a) - sizeof(a->ip) + vl_api_address_t_calc_size(&a->ip) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_want_ip_neighbor_events_reply_t_calc_size (vl_api_want_ip_neighbor_events_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_neighbor_event_t_calc_size (vl_api_ip_neighbor_event_t *a)
{
      return sizeof(*a) - sizeof(a->neighbor) + vl_api_ip_neighbor_t_calc_size(&a->neighbor);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_want_ip_neighbor_events_v2_t_calc_size (vl_api_want_ip_neighbor_events_v2_t *a)
{
      return sizeof(*a) - sizeof(a->ip) + vl_api_address_t_calc_size(&a->ip) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_want_ip_neighbor_events_v2_reply_t_calc_size (vl_api_want_ip_neighbor_events_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip_neighbor_event_v2_t_calc_size (vl_api_ip_neighbor_event_v2_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_ip_neighbor_event_flags_t_calc_size(&a->flags) - sizeof(a->neighbor) + vl_api_ip_neighbor_t_calc_size(&a->neighbor);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(ip_neighbor.api, 1, 0, 1)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(ip_neighbor.api, 0x8bbbad7c)

#endif

