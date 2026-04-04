/*
 * VLIB API definitions 2026-04-04 08:31:59
 * Input file: igmp.api
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
#warning no content included from igmp.api
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
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_IGMP_LISTEN, vl_api_igmp_listen_t_handler)
vl_msg_id(VL_API_IGMP_LISTEN_REPLY, vl_api_igmp_listen_reply_t_handler)
vl_msg_id(VL_API_IGMP_ENABLE_DISABLE, vl_api_igmp_enable_disable_t_handler)
vl_msg_id(VL_API_IGMP_ENABLE_DISABLE_REPLY, vl_api_igmp_enable_disable_reply_t_handler)
vl_msg_id(VL_API_IGMP_PROXY_DEVICE_ADD_DEL, vl_api_igmp_proxy_device_add_del_t_handler)
vl_msg_id(VL_API_IGMP_PROXY_DEVICE_ADD_DEL_REPLY, vl_api_igmp_proxy_device_add_del_reply_t_handler)
vl_msg_id(VL_API_IGMP_PROXY_DEVICE_ADD_DEL_INTERFACE, vl_api_igmp_proxy_device_add_del_interface_t_handler)
vl_msg_id(VL_API_IGMP_PROXY_DEVICE_ADD_DEL_INTERFACE_REPLY, vl_api_igmp_proxy_device_add_del_interface_reply_t_handler)
vl_msg_id(VL_API_IGMP_DUMP, vl_api_igmp_dump_t_handler)
vl_msg_id(VL_API_IGMP_DETAILS, vl_api_igmp_details_t_handler)
vl_msg_id(VL_API_IGMP_CLEAR_INTERFACE, vl_api_igmp_clear_interface_t_handler)
vl_msg_id(VL_API_IGMP_CLEAR_INTERFACE_REPLY, vl_api_igmp_clear_interface_reply_t_handler)
vl_msg_id(VL_API_WANT_IGMP_EVENTS, vl_api_want_igmp_events_t_handler)
vl_msg_id(VL_API_WANT_IGMP_EVENTS_REPLY, vl_api_want_igmp_events_reply_t_handler)
vl_msg_id(VL_API_IGMP_EVENT, vl_api_igmp_event_t_handler)
vl_msg_id(VL_API_IGMP_GROUP_PREFIX_SET, vl_api_igmp_group_prefix_set_t_handler)
vl_msg_id(VL_API_IGMP_GROUP_PREFIX_SET_REPLY, vl_api_igmp_group_prefix_set_reply_t_handler)
vl_msg_id(VL_API_IGMP_GROUP_PREFIX_DUMP, vl_api_igmp_group_prefix_dump_t_handler)
vl_msg_id(VL_API_IGMP_GROUP_PREFIX_DETAILS, vl_api_igmp_group_prefix_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_igmp_listen_t, 1)
vl_msg_name(vl_api_igmp_listen_reply_t, 1)
vl_msg_name(vl_api_igmp_enable_disable_t, 1)
vl_msg_name(vl_api_igmp_enable_disable_reply_t, 1)
vl_msg_name(vl_api_igmp_proxy_device_add_del_t, 1)
vl_msg_name(vl_api_igmp_proxy_device_add_del_reply_t, 1)
vl_msg_name(vl_api_igmp_proxy_device_add_del_interface_t, 1)
vl_msg_name(vl_api_igmp_proxy_device_add_del_interface_reply_t, 1)
vl_msg_name(vl_api_igmp_dump_t, 1)
vl_msg_name(vl_api_igmp_details_t, 1)
vl_msg_name(vl_api_igmp_clear_interface_t, 1)
vl_msg_name(vl_api_igmp_clear_interface_reply_t, 1)
vl_msg_name(vl_api_want_igmp_events_t, 1)
vl_msg_name(vl_api_want_igmp_events_reply_t, 1)
vl_msg_name(vl_api_igmp_event_t, 1)
vl_msg_name(vl_api_igmp_group_prefix_set_t, 1)
vl_msg_name(vl_api_igmp_group_prefix_set_reply_t, 1)
vl_msg_name(vl_api_igmp_group_prefix_dump_t, 1)
vl_msg_name(vl_api_igmp_group_prefix_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_igmp \
_(VL_API_IGMP_LISTEN, igmp_listen, 19a49f1e) \
_(VL_API_IGMP_LISTEN_REPLY, igmp_listen_reply, e8d4e804) \
_(VL_API_IGMP_ENABLE_DISABLE, igmp_enable_disable, b1edfb96) \
_(VL_API_IGMP_ENABLE_DISABLE_REPLY, igmp_enable_disable_reply, e8d4e804) \
_(VL_API_IGMP_PROXY_DEVICE_ADD_DEL, igmp_proxy_device_add_del, 0b9be9ce) \
_(VL_API_IGMP_PROXY_DEVICE_ADD_DEL_REPLY, igmp_proxy_device_add_del_reply, e8d4e804) \
_(VL_API_IGMP_PROXY_DEVICE_ADD_DEL_INTERFACE, igmp_proxy_device_add_del_interface, 1a9ec24a) \
_(VL_API_IGMP_PROXY_DEVICE_ADD_DEL_INTERFACE_REPLY, igmp_proxy_device_add_del_interface_reply, e8d4e804) \
_(VL_API_IGMP_DUMP, igmp_dump, f9e6675e) \
_(VL_API_IGMP_DETAILS, igmp_details, 38f09929) \
_(VL_API_IGMP_CLEAR_INTERFACE, igmp_clear_interface, f9e6675e) \
_(VL_API_IGMP_CLEAR_INTERFACE_REPLY, igmp_clear_interface_reply, e8d4e804) \
_(VL_API_WANT_IGMP_EVENTS, want_igmp_events, cfaccc1f) \
_(VL_API_WANT_IGMP_EVENTS_REPLY, want_igmp_events_reply, e8d4e804) \
_(VL_API_IGMP_EVENT, igmp_event, 85fe93ec) \
_(VL_API_IGMP_GROUP_PREFIX_SET, igmp_group_prefix_set, 5b14a5ce) \
_(VL_API_IGMP_GROUP_PREFIX_SET_REPLY, igmp_group_prefix_set_reply, e8d4e804) \
_(VL_API_IGMP_GROUP_PREFIX_DUMP, igmp_group_prefix_dump, 51077d14) \
_(VL_API_IGMP_GROUP_PREFIX_DETAILS, igmp_group_prefix_details, 259ccd81) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "igmp.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_igmp_printfun_types
#define included_igmp_printfun_types

static inline u8 *format_vl_api_filter_mode_t (u8 *s, va_list * args)
{
    vl_api_filter_mode_t *a = va_arg (*args, vl_api_filter_mode_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "EXCLUDE");
    case 1:
        return format(s, "INCLUDE");
    }
    return s;
}

static inline u8 *format_vl_api_igmp_group_t (u8 *s, va_list * args)
{
    vl_api_igmp_group_t *a = va_arg (*args, vl_api_igmp_group_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ufilter: %U", format_white_space, indent, format_vl_api_filter_mode_t, &a->filter, indent);
    s = format(s, "\n%Un_srcs: %u", format_white_space, indent, a->n_srcs);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Ugaddr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->gaddr, indent);
    for (i = 0; i < a->n_srcs; i++) {
        s = format(s, "\n%Usaddrs: %U",
                   format_white_space, indent, format_vl_api_ip4_address_t, &a->saddrs[i], indent);
    }
    return s;
}

static inline u8 *format_vl_api_group_prefix_type_t (u8 *s, va_list * args)
{
    vl_api_group_prefix_type_t *a = va_arg (*args, vl_api_group_prefix_type_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "ASM");
    case 1:
        return format(s, "SSM");
    }
    return s;
}

static inline u8 *format_vl_api_group_prefix_t (u8 *s, va_list * args)
{
    vl_api_group_prefix_t *a = va_arg (*args, vl_api_group_prefix_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Utype: %U", format_white_space, indent, format_vl_api_group_prefix_type_t, &a->type, indent);
    s = format(s, "\n%Uprefix: %U", format_white_space, indent, format_vl_api_prefix_t, &a->prefix, indent);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_igmp_printfun
#define included_igmp_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "igmp.api_tojson.h"
#include "igmp.api_fromjson.h"

static inline u8 *vl_api_igmp_listen_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_igmp_listen_t *a = va_arg (*args, vl_api_igmp_listen_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_igmp_listen_t: */
    s = format(s, "vl_api_igmp_listen_t:");
    s = format(s, "\n%Ugroup: %U", format_white_space, indent, format_vl_api_igmp_group_t, &a->group, indent);
    return s;
}

static inline u8 *vl_api_igmp_listen_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_igmp_listen_reply_t *a = va_arg (*args, vl_api_igmp_listen_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_igmp_listen_reply_t: */
    s = format(s, "vl_api_igmp_listen_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_igmp_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_igmp_enable_disable_t *a = va_arg (*args, vl_api_igmp_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_igmp_enable_disable_t: */
    s = format(s, "vl_api_igmp_enable_disable_t:");
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    s = format(s, "\n%Umode: %u", format_white_space, indent, a->mode);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_igmp_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_igmp_enable_disable_reply_t *a = va_arg (*args, vl_api_igmp_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_igmp_enable_disable_reply_t: */
    s = format(s, "vl_api_igmp_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_igmp_proxy_device_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_igmp_proxy_device_add_del_t *a = va_arg (*args, vl_api_igmp_proxy_device_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_igmp_proxy_device_add_del_t: */
    s = format(s, "vl_api_igmp_proxy_device_add_del_t:");
    s = format(s, "\n%Uadd: %u", format_white_space, indent, a->add);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_igmp_proxy_device_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_igmp_proxy_device_add_del_reply_t *a = va_arg (*args, vl_api_igmp_proxy_device_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_igmp_proxy_device_add_del_reply_t: */
    s = format(s, "vl_api_igmp_proxy_device_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_igmp_proxy_device_add_del_interface_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_igmp_proxy_device_add_del_interface_t *a = va_arg (*args, vl_api_igmp_proxy_device_add_del_interface_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_igmp_proxy_device_add_del_interface_t: */
    s = format(s, "vl_api_igmp_proxy_device_add_del_interface_t:");
    s = format(s, "\n%Uadd: %u", format_white_space, indent, a->add);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_igmp_proxy_device_add_del_interface_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_igmp_proxy_device_add_del_interface_reply_t *a = va_arg (*args, vl_api_igmp_proxy_device_add_del_interface_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_igmp_proxy_device_add_del_interface_reply_t: */
    s = format(s, "vl_api_igmp_proxy_device_add_del_interface_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_igmp_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_igmp_dump_t *a = va_arg (*args, vl_api_igmp_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_igmp_dump_t: */
    s = format(s, "vl_api_igmp_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_igmp_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_igmp_details_t *a = va_arg (*args, vl_api_igmp_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_igmp_details_t: */
    s = format(s, "vl_api_igmp_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Usaddr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->saddr, indent);
    s = format(s, "\n%Ugaddr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->gaddr, indent);
    return s;
}

static inline u8 *vl_api_igmp_clear_interface_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_igmp_clear_interface_t *a = va_arg (*args, vl_api_igmp_clear_interface_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_igmp_clear_interface_t: */
    s = format(s, "vl_api_igmp_clear_interface_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_igmp_clear_interface_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_igmp_clear_interface_reply_t *a = va_arg (*args, vl_api_igmp_clear_interface_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_igmp_clear_interface_reply_t: */
    s = format(s, "vl_api_igmp_clear_interface_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_want_igmp_events_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_want_igmp_events_t *a = va_arg (*args, vl_api_want_igmp_events_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_want_igmp_events_t: */
    s = format(s, "vl_api_want_igmp_events_t:");
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    s = format(s, "\n%Upid: %u", format_white_space, indent, a->pid);
    return s;
}

static inline u8 *vl_api_want_igmp_events_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_want_igmp_events_reply_t *a = va_arg (*args, vl_api_want_igmp_events_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_want_igmp_events_reply_t: */
    s = format(s, "vl_api_want_igmp_events_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_igmp_event_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_igmp_event_t *a = va_arg (*args, vl_api_igmp_event_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_igmp_event_t: */
    s = format(s, "vl_api_igmp_event_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Ufilter: %U", format_white_space, indent, format_vl_api_filter_mode_t, &a->filter, indent);
    s = format(s, "\n%Usaddr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->saddr, indent);
    s = format(s, "\n%Ugaddr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->gaddr, indent);
    return s;
}

static inline u8 *vl_api_igmp_group_prefix_set_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_igmp_group_prefix_set_t *a = va_arg (*args, vl_api_igmp_group_prefix_set_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_igmp_group_prefix_set_t: */
    s = format(s, "vl_api_igmp_group_prefix_set_t:");
    s = format(s, "\n%Ugp: %U", format_white_space, indent, format_vl_api_group_prefix_t, &a->gp, indent);
    return s;
}

static inline u8 *vl_api_igmp_group_prefix_set_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_igmp_group_prefix_set_reply_t *a = va_arg (*args, vl_api_igmp_group_prefix_set_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_igmp_group_prefix_set_reply_t: */
    s = format(s, "vl_api_igmp_group_prefix_set_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_igmp_group_prefix_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_igmp_group_prefix_dump_t *a = va_arg (*args, vl_api_igmp_group_prefix_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_igmp_group_prefix_dump_t: */
    s = format(s, "vl_api_igmp_group_prefix_dump_t:");
    return s;
}

static inline u8 *vl_api_igmp_group_prefix_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_igmp_group_prefix_details_t *a = va_arg (*args, vl_api_igmp_group_prefix_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_igmp_group_prefix_details_t: */
    s = format(s, "vl_api_igmp_group_prefix_details_t:");
    s = format(s, "\n%Ugp: %U", format_white_space, indent, format_vl_api_group_prefix_t, &a->gp, indent);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_igmp_endianfun
#define included_igmp_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_filter_mode_t_endian (vl_api_filter_mode_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_igmp_group_t_endian (vl_api_igmp_group_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_filter_mode_t_endian(&a->filter, to_net);
    /* a->n_srcs = a->n_srcs (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_ip4_address_t_endian(&a->gaddr, to_net);
    u32 count = a->n_srcs;
    for (i = 0; i < count; i++) {
        vl_api_ip4_address_t_endian(&a->saddrs[i], to_net);
    }
}

static inline void vl_api_group_prefix_type_t_endian (vl_api_group_prefix_type_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_group_prefix_t_endian (vl_api_group_prefix_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_group_prefix_type_t_endian(&a->type, to_net);
    vl_api_prefix_t_endian(&a->prefix, to_net);
}

static inline void vl_api_igmp_listen_t_endian (vl_api_igmp_listen_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_igmp_group_t_endian(&a->group, to_net);
}

static inline void vl_api_igmp_listen_reply_t_endian (vl_api_igmp_listen_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_igmp_enable_disable_t_endian (vl_api_igmp_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->enable = a->enable (no-op) */
    /* a->mode = a->mode (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_igmp_enable_disable_reply_t_endian (vl_api_igmp_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_igmp_proxy_device_add_del_t_endian (vl_api_igmp_proxy_device_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->add = a->add (no-op) */
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_igmp_proxy_device_add_del_reply_t_endian (vl_api_igmp_proxy_device_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_igmp_proxy_device_add_del_interface_t_endian (vl_api_igmp_proxy_device_add_del_interface_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->add = a->add (no-op) */
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_igmp_proxy_device_add_del_interface_reply_t_endian (vl_api_igmp_proxy_device_add_del_interface_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_igmp_dump_t_endian (vl_api_igmp_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_igmp_details_t_endian (vl_api_igmp_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_ip4_address_t_endian(&a->saddr, to_net);
    vl_api_ip4_address_t_endian(&a->gaddr, to_net);
}

static inline void vl_api_igmp_clear_interface_t_endian (vl_api_igmp_clear_interface_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_igmp_clear_interface_reply_t_endian (vl_api_igmp_clear_interface_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_want_igmp_events_t_endian (vl_api_want_igmp_events_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->enable = clib_net_to_host_u32(a->enable);
    a->pid = clib_net_to_host_u32(a->pid);
}

static inline void vl_api_want_igmp_events_reply_t_endian (vl_api_want_igmp_events_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_igmp_event_t_endian (vl_api_igmp_event_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_filter_mode_t_endian(&a->filter, to_net);
    vl_api_ip4_address_t_endian(&a->saddr, to_net);
    vl_api_ip4_address_t_endian(&a->gaddr, to_net);
}

static inline void vl_api_igmp_group_prefix_set_t_endian (vl_api_igmp_group_prefix_set_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_group_prefix_t_endian(&a->gp, to_net);
}

static inline void vl_api_igmp_group_prefix_set_reply_t_endian (vl_api_igmp_group_prefix_set_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_igmp_group_prefix_dump_t_endian (vl_api_igmp_group_prefix_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_igmp_group_prefix_details_t_endian (vl_api_igmp_group_prefix_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_group_prefix_t_endian(&a->gp, to_net);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_igmp_calcsizefun
#define included_igmp_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_filter_mode_t_calc_size (vl_api_filter_mode_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_igmp_group_t_calc_size (vl_api_igmp_group_t *a)
{
      return sizeof(*a) - sizeof(a->filter) + vl_api_filter_mode_t_calc_size(&a->filter) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->gaddr) + vl_api_ip4_address_t_calc_size(&a->gaddr) + a->n_srcs * sizeof(a->saddrs[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_group_prefix_type_t_calc_size (vl_api_group_prefix_type_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_group_prefix_t_calc_size (vl_api_group_prefix_t *a)
{
      return sizeof(*a) - sizeof(a->type) + vl_api_group_prefix_type_t_calc_size(&a->type) - sizeof(a->prefix) + vl_api_prefix_t_calc_size(&a->prefix);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_igmp_listen_t_calc_size (vl_api_igmp_listen_t *a)
{
      return sizeof(*a) - sizeof(a->group) + vl_api_igmp_group_t_calc_size(&a->group);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_igmp_listen_reply_t_calc_size (vl_api_igmp_listen_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_igmp_enable_disable_t_calc_size (vl_api_igmp_enable_disable_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_igmp_enable_disable_reply_t_calc_size (vl_api_igmp_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_igmp_proxy_device_add_del_t_calc_size (vl_api_igmp_proxy_device_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_igmp_proxy_device_add_del_reply_t_calc_size (vl_api_igmp_proxy_device_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_igmp_proxy_device_add_del_interface_t_calc_size (vl_api_igmp_proxy_device_add_del_interface_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_igmp_proxy_device_add_del_interface_reply_t_calc_size (vl_api_igmp_proxy_device_add_del_interface_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_igmp_dump_t_calc_size (vl_api_igmp_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_igmp_details_t_calc_size (vl_api_igmp_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->saddr) + vl_api_ip4_address_t_calc_size(&a->saddr) - sizeof(a->gaddr) + vl_api_ip4_address_t_calc_size(&a->gaddr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_igmp_clear_interface_t_calc_size (vl_api_igmp_clear_interface_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_igmp_clear_interface_reply_t_calc_size (vl_api_igmp_clear_interface_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_want_igmp_events_t_calc_size (vl_api_want_igmp_events_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_want_igmp_events_reply_t_calc_size (vl_api_want_igmp_events_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_igmp_event_t_calc_size (vl_api_igmp_event_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->filter) + vl_api_filter_mode_t_calc_size(&a->filter) - sizeof(a->saddr) + vl_api_ip4_address_t_calc_size(&a->saddr) - sizeof(a->gaddr) + vl_api_ip4_address_t_calc_size(&a->gaddr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_igmp_group_prefix_set_t_calc_size (vl_api_igmp_group_prefix_set_t *a)
{
      return sizeof(*a) - sizeof(a->gp) + vl_api_group_prefix_t_calc_size(&a->gp);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_igmp_group_prefix_set_reply_t_calc_size (vl_api_igmp_group_prefix_set_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_igmp_group_prefix_dump_t_calc_size (vl_api_igmp_group_prefix_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_igmp_group_prefix_details_t_calc_size (vl_api_igmp_group_prefix_details_t *a)
{
      return sizeof(*a) - sizeof(a->gp) + vl_api_group_prefix_t_calc_size(&a->gp);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(igmp.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(igmp.api, 0x2fd2bd5e)

#endif

