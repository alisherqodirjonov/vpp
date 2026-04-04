/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: vrrp.api
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
#warning no content included from vrrp.api
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
#include <vnet/ethernet/ethernet_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_VRRP_VR_ADD_DEL, vl_api_vrrp_vr_add_del_t_handler)
vl_msg_id(VL_API_VRRP_VR_ADD_DEL_REPLY, vl_api_vrrp_vr_add_del_reply_t_handler)
vl_msg_id(VL_API_VRRP_VR_UPDATE, vl_api_vrrp_vr_update_t_handler)
vl_msg_id(VL_API_VRRP_VR_UPDATE_REPLY, vl_api_vrrp_vr_update_reply_t_handler)
vl_msg_id(VL_API_VRRP_VR_DEL, vl_api_vrrp_vr_del_t_handler)
vl_msg_id(VL_API_VRRP_VR_DEL_REPLY, vl_api_vrrp_vr_del_reply_t_handler)
vl_msg_id(VL_API_VRRP_VR_DUMP, vl_api_vrrp_vr_dump_t_handler)
vl_msg_id(VL_API_VRRP_VR_DETAILS, vl_api_vrrp_vr_details_t_handler)
vl_msg_id(VL_API_VRRP_VR_START_STOP, vl_api_vrrp_vr_start_stop_t_handler)
vl_msg_id(VL_API_VRRP_VR_START_STOP_REPLY, vl_api_vrrp_vr_start_stop_reply_t_handler)
vl_msg_id(VL_API_VRRP_VR_SET_PEERS, vl_api_vrrp_vr_set_peers_t_handler)
vl_msg_id(VL_API_VRRP_VR_SET_PEERS_REPLY, vl_api_vrrp_vr_set_peers_reply_t_handler)
vl_msg_id(VL_API_VRRP_VR_PEER_DUMP, vl_api_vrrp_vr_peer_dump_t_handler)
vl_msg_id(VL_API_VRRP_VR_PEER_DETAILS, vl_api_vrrp_vr_peer_details_t_handler)
vl_msg_id(VL_API_VRRP_VR_TRACK_IF_ADD_DEL, vl_api_vrrp_vr_track_if_add_del_t_handler)
vl_msg_id(VL_API_VRRP_VR_TRACK_IF_ADD_DEL_REPLY, vl_api_vrrp_vr_track_if_add_del_reply_t_handler)
vl_msg_id(VL_API_VRRP_VR_TRACK_IF_DUMP, vl_api_vrrp_vr_track_if_dump_t_handler)
vl_msg_id(VL_API_VRRP_VR_TRACK_IF_DETAILS, vl_api_vrrp_vr_track_if_details_t_handler)
vl_msg_id(VL_API_VRRP_VR_EVENT, vl_api_vrrp_vr_event_t_handler)
vl_msg_id(VL_API_WANT_VRRP_VR_EVENTS, vl_api_want_vrrp_vr_events_t_handler)
vl_msg_id(VL_API_WANT_VRRP_VR_EVENTS_REPLY, vl_api_want_vrrp_vr_events_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_vrrp_vr_add_del_t, 1)
vl_msg_name(vl_api_vrrp_vr_add_del_reply_t, 1)
vl_msg_name(vl_api_vrrp_vr_update_t, 1)
vl_msg_name(vl_api_vrrp_vr_update_reply_t, 1)
vl_msg_name(vl_api_vrrp_vr_del_t, 1)
vl_msg_name(vl_api_vrrp_vr_del_reply_t, 1)
vl_msg_name(vl_api_vrrp_vr_dump_t, 1)
vl_msg_name(vl_api_vrrp_vr_details_t, 1)
vl_msg_name(vl_api_vrrp_vr_start_stop_t, 1)
vl_msg_name(vl_api_vrrp_vr_start_stop_reply_t, 1)
vl_msg_name(vl_api_vrrp_vr_set_peers_t, 1)
vl_msg_name(vl_api_vrrp_vr_set_peers_reply_t, 1)
vl_msg_name(vl_api_vrrp_vr_peer_dump_t, 1)
vl_msg_name(vl_api_vrrp_vr_peer_details_t, 1)
vl_msg_name(vl_api_vrrp_vr_track_if_add_del_t, 1)
vl_msg_name(vl_api_vrrp_vr_track_if_add_del_reply_t, 1)
vl_msg_name(vl_api_vrrp_vr_track_if_dump_t, 1)
vl_msg_name(vl_api_vrrp_vr_track_if_details_t, 1)
vl_msg_name(vl_api_vrrp_vr_event_t, 1)
vl_msg_name(vl_api_want_vrrp_vr_events_t, 1)
vl_msg_name(vl_api_want_vrrp_vr_events_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_vrrp \
_(VL_API_VRRP_VR_ADD_DEL, vrrp_vr_add_del, c5cf15aa) \
_(VL_API_VRRP_VR_ADD_DEL_REPLY, vrrp_vr_add_del_reply, e8d4e804) \
_(VL_API_VRRP_VR_UPDATE, vrrp_vr_update, 0b51e2f4) \
_(VL_API_VRRP_VR_UPDATE_REPLY, vrrp_vr_update_reply, 5317d608) \
_(VL_API_VRRP_VR_DEL, vrrp_vr_del, 6029baa1) \
_(VL_API_VRRP_VR_DEL_REPLY, vrrp_vr_del_reply, e8d4e804) \
_(VL_API_VRRP_VR_DUMP, vrrp_vr_dump, f9e6675e) \
_(VL_API_VRRP_VR_DETAILS, vrrp_vr_details, 46edcebd) \
_(VL_API_VRRP_VR_START_STOP, vrrp_vr_start_stop, 0662a3b7) \
_(VL_API_VRRP_VR_START_STOP_REPLY, vrrp_vr_start_stop_reply, e8d4e804) \
_(VL_API_VRRP_VR_SET_PEERS, vrrp_vr_set_peers, 20bec71f) \
_(VL_API_VRRP_VR_SET_PEERS_REPLY, vrrp_vr_set_peers_reply, e8d4e804) \
_(VL_API_VRRP_VR_PEER_DUMP, vrrp_vr_peer_dump, 6fa3f7c4) \
_(VL_API_VRRP_VR_PEER_DETAILS, vrrp_vr_peer_details, 3d99c108) \
_(VL_API_VRRP_VR_TRACK_IF_ADD_DEL, vrrp_vr_track_if_add_del, d67df299) \
_(VL_API_VRRP_VR_TRACK_IF_ADD_DEL_REPLY, vrrp_vr_track_if_add_del_reply, e8d4e804) \
_(VL_API_VRRP_VR_TRACK_IF_DUMP, vrrp_vr_track_if_dump, a34dfc6d) \
_(VL_API_VRRP_VR_TRACK_IF_DETAILS, vrrp_vr_track_if_details, 73c36f81) \
_(VL_API_VRRP_VR_EVENT, vrrp_vr_event, c1fea6a5) \
_(VL_API_WANT_VRRP_VR_EVENTS, want_vrrp_vr_events, c5e2af94) \
_(VL_API_WANT_VRRP_VR_EVENTS_REPLY, want_vrrp_vr_events_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "vrrp.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_vrrp_printfun_types
#define included_vrrp_printfun_types

static inline u8 *format_vl_api_vrrp_vr_key_t (u8 *s, va_list * args)
{
    vl_api_vrrp_vr_key_t *a = va_arg (*args, vl_api_vrrp_vr_key_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uvr_id: %u", format_white_space, indent, a->vr_id);
    s = format(s, "\n%Uis_ipv6: %u", format_white_space, indent, a->is_ipv6);
    return s;
}

static inline u8 *format_vl_api_vrrp_vr_flags_t (u8 *s, va_list * args)
{
    vl_api_vrrp_vr_flags_t *a = va_arg (*args, vl_api_vrrp_vr_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "VRRP_API_VR_PREEMPT");
    case 2:
        return format(s, "VRRP_API_VR_ACCEPT");
    case 4:
        return format(s, "VRRP_API_VR_UNICAST");
    case 8:
        return format(s, "VRRP_API_VR_IPV6");
    }
    return s;
}

static inline u8 *format_vl_api_vrrp_vr_conf_t (u8 *s, va_list * args)
{
    vl_api_vrrp_vr_conf_t *a = va_arg (*args, vl_api_vrrp_vr_conf_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uvr_id: %u", format_white_space, indent, a->vr_id);
    s = format(s, "\n%Upriority: %u", format_white_space, indent, a->priority);
    s = format(s, "\n%Uinterval: %u", format_white_space, indent, a->interval);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_vrrp_vr_flags_t, &a->flags, indent);
    return s;
}

static inline u8 *format_vl_api_vrrp_vr_state_t (u8 *s, va_list * args)
{
    vl_api_vrrp_vr_state_t *a = va_arg (*args, vl_api_vrrp_vr_state_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "VRRP_API_VR_STATE_INIT");
    case 1:
        return format(s, "VRRP_API_VR_STATE_BACKUP");
    case 2:
        return format(s, "VRRP_API_VR_STATE_MASTER");
    case 3:
        return format(s, "VRRP_API_VR_STATE_INTF_DOWN");
    }
    return s;
}

static inline u8 *format_vl_api_vrrp_vr_tracking_t (u8 *s, va_list * args)
{
    vl_api_vrrp_vr_tracking_t *a = va_arg (*args, vl_api_vrrp_vr_tracking_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uinterfaces_dec: %u", format_white_space, indent, a->interfaces_dec);
    s = format(s, "\n%Upriority: %u", format_white_space, indent, a->priority);
    return s;
}

static inline u8 *format_vl_api_vrrp_vr_runtime_t (u8 *s, va_list * args)
{
    vl_api_vrrp_vr_runtime_t *a = va_arg (*args, vl_api_vrrp_vr_runtime_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ustate: %U", format_white_space, indent, format_vl_api_vrrp_vr_state_t, &a->state, indent);
    s = format(s, "\n%Umaster_adv_int: %u", format_white_space, indent, a->master_adv_int);
    s = format(s, "\n%Uskew: %u", format_white_space, indent, a->skew);
    s = format(s, "\n%Umaster_down_int: %u", format_white_space, indent, a->master_down_int);
    s = format(s, "\n%Umac: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->mac, indent);
    s = format(s, "\n%Utracking: %U", format_white_space, indent, format_vl_api_vrrp_vr_tracking_t, &a->tracking, indent);
    return s;
}

static inline u8 *format_vl_api_vrrp_vr_track_if_t (u8 *s, va_list * args)
{
    vl_api_vrrp_vr_track_if_t *a = va_arg (*args, vl_api_vrrp_vr_track_if_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Upriority: %u", format_white_space, indent, a->priority);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_vrrp_printfun
#define included_vrrp_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "vrrp.api_tojson.h"
#include "vrrp.api_fromjson.h"

static inline u8 *vl_api_vrrp_vr_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vrrp_vr_add_del_t *a = va_arg (*args, vl_api_vrrp_vr_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vrrp_vr_add_del_t: */
    s = format(s, "vl_api_vrrp_vr_add_del_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uvr_id: %u", format_white_space, indent, a->vr_id);
    s = format(s, "\n%Upriority: %u", format_white_space, indent, a->priority);
    s = format(s, "\n%Uinterval: %u", format_white_space, indent, a->interval);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_vrrp_vr_flags_t, &a->flags, indent);
    s = format(s, "\n%Un_addrs: %u", format_white_space, indent, a->n_addrs);
    for (i = 0; i < a->n_addrs; i++) {
        s = format(s, "\n%Uaddrs: %U",
                   format_white_space, indent, format_vl_api_address_t, &a->addrs[i], indent);
    }
    return s;
}

static inline u8 *vl_api_vrrp_vr_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vrrp_vr_add_del_reply_t *a = va_arg (*args, vl_api_vrrp_vr_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vrrp_vr_add_del_reply_t: */
    s = format(s, "vl_api_vrrp_vr_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_vrrp_vr_update_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vrrp_vr_update_t *a = va_arg (*args, vl_api_vrrp_vr_update_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vrrp_vr_update_t: */
    s = format(s, "vl_api_vrrp_vr_update_t:");
    s = format(s, "\n%Uvrrp_index: %u", format_white_space, indent, a->vrrp_index);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uvr_id: %u", format_white_space, indent, a->vr_id);
    s = format(s, "\n%Upriority: %u", format_white_space, indent, a->priority);
    s = format(s, "\n%Uinterval: %u", format_white_space, indent, a->interval);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_vrrp_vr_flags_t, &a->flags, indent);
    s = format(s, "\n%Un_addrs: %u", format_white_space, indent, a->n_addrs);
    for (i = 0; i < a->n_addrs; i++) {
        s = format(s, "\n%Uaddrs: %U",
                   format_white_space, indent, format_vl_api_address_t, &a->addrs[i], indent);
    }
    return s;
}

static inline u8 *vl_api_vrrp_vr_update_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vrrp_vr_update_reply_t *a = va_arg (*args, vl_api_vrrp_vr_update_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vrrp_vr_update_reply_t: */
    s = format(s, "vl_api_vrrp_vr_update_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uvrrp_index: %u", format_white_space, indent, a->vrrp_index);
    return s;
}

static inline u8 *vl_api_vrrp_vr_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vrrp_vr_del_t *a = va_arg (*args, vl_api_vrrp_vr_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vrrp_vr_del_t: */
    s = format(s, "vl_api_vrrp_vr_del_t:");
    s = format(s, "\n%Uvrrp_index: %u", format_white_space, indent, a->vrrp_index);
    return s;
}

static inline u8 *vl_api_vrrp_vr_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vrrp_vr_del_reply_t *a = va_arg (*args, vl_api_vrrp_vr_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vrrp_vr_del_reply_t: */
    s = format(s, "vl_api_vrrp_vr_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_vrrp_vr_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vrrp_vr_dump_t *a = va_arg (*args, vl_api_vrrp_vr_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vrrp_vr_dump_t: */
    s = format(s, "vl_api_vrrp_vr_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_vrrp_vr_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vrrp_vr_details_t *a = va_arg (*args, vl_api_vrrp_vr_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vrrp_vr_details_t: */
    s = format(s, "vl_api_vrrp_vr_details_t:");
    s = format(s, "\n%Uconfig: %U", format_white_space, indent, format_vl_api_vrrp_vr_conf_t, &a->config, indent);
    s = format(s, "\n%Uruntime: %U", format_white_space, indent, format_vl_api_vrrp_vr_runtime_t, &a->runtime, indent);
    s = format(s, "\n%Un_addrs: %u", format_white_space, indent, a->n_addrs);
    for (i = 0; i < a->n_addrs; i++) {
        s = format(s, "\n%Uaddrs: %U",
                   format_white_space, indent, format_vl_api_address_t, &a->addrs[i], indent);
    }
    return s;
}

static inline u8 *vl_api_vrrp_vr_start_stop_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vrrp_vr_start_stop_t *a = va_arg (*args, vl_api_vrrp_vr_start_stop_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vrrp_vr_start_stop_t: */
    s = format(s, "vl_api_vrrp_vr_start_stop_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uvr_id: %u", format_white_space, indent, a->vr_id);
    s = format(s, "\n%Uis_ipv6: %u", format_white_space, indent, a->is_ipv6);
    s = format(s, "\n%Uis_start: %u", format_white_space, indent, a->is_start);
    return s;
}

static inline u8 *vl_api_vrrp_vr_start_stop_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vrrp_vr_start_stop_reply_t *a = va_arg (*args, vl_api_vrrp_vr_start_stop_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vrrp_vr_start_stop_reply_t: */
    s = format(s, "vl_api_vrrp_vr_start_stop_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_vrrp_vr_set_peers_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vrrp_vr_set_peers_t *a = va_arg (*args, vl_api_vrrp_vr_set_peers_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vrrp_vr_set_peers_t: */
    s = format(s, "vl_api_vrrp_vr_set_peers_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uvr_id: %u", format_white_space, indent, a->vr_id);
    s = format(s, "\n%Uis_ipv6: %u", format_white_space, indent, a->is_ipv6);
    s = format(s, "\n%Un_addrs: %u", format_white_space, indent, a->n_addrs);
    for (i = 0; i < a->n_addrs; i++) {
        s = format(s, "\n%Uaddrs: %U",
                   format_white_space, indent, format_vl_api_address_t, &a->addrs[i], indent);
    }
    return s;
}

static inline u8 *vl_api_vrrp_vr_set_peers_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vrrp_vr_set_peers_reply_t *a = va_arg (*args, vl_api_vrrp_vr_set_peers_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vrrp_vr_set_peers_reply_t: */
    s = format(s, "vl_api_vrrp_vr_set_peers_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_vrrp_vr_peer_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vrrp_vr_peer_dump_t *a = va_arg (*args, vl_api_vrrp_vr_peer_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vrrp_vr_peer_dump_t: */
    s = format(s, "vl_api_vrrp_vr_peer_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uis_ipv6: %u", format_white_space, indent, a->is_ipv6);
    s = format(s, "\n%Uvr_id: %u", format_white_space, indent, a->vr_id);
    return s;
}

static inline u8 *vl_api_vrrp_vr_peer_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vrrp_vr_peer_details_t *a = va_arg (*args, vl_api_vrrp_vr_peer_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vrrp_vr_peer_details_t: */
    s = format(s, "vl_api_vrrp_vr_peer_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uvr_id: %u", format_white_space, indent, a->vr_id);
    s = format(s, "\n%Uis_ipv6: %u", format_white_space, indent, a->is_ipv6);
    s = format(s, "\n%Un_peer_addrs: %u", format_white_space, indent, a->n_peer_addrs);
    for (i = 0; i < a->n_peer_addrs; i++) {
        s = format(s, "\n%Upeer_addrs: %U",
                   format_white_space, indent, format_vl_api_address_t, &a->peer_addrs[i], indent);
    }
    return s;
}

static inline u8 *vl_api_vrrp_vr_track_if_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vrrp_vr_track_if_add_del_t *a = va_arg (*args, vl_api_vrrp_vr_track_if_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vrrp_vr_track_if_add_del_t: */
    s = format(s, "vl_api_vrrp_vr_track_if_add_del_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uis_ipv6: %u", format_white_space, indent, a->is_ipv6);
    s = format(s, "\n%Uvr_id: %u", format_white_space, indent, a->vr_id);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Un_ifs: %u", format_white_space, indent, a->n_ifs);
    for (i = 0; i < a->n_ifs; i++) {
        s = format(s, "\n%Uifs: %U",
                   format_white_space, indent, format_vl_api_vrrp_vr_track_if_t, &a->ifs[i], indent);
    }
    return s;
}

static inline u8 *vl_api_vrrp_vr_track_if_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vrrp_vr_track_if_add_del_reply_t *a = va_arg (*args, vl_api_vrrp_vr_track_if_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vrrp_vr_track_if_add_del_reply_t: */
    s = format(s, "vl_api_vrrp_vr_track_if_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_vrrp_vr_track_if_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vrrp_vr_track_if_dump_t *a = va_arg (*args, vl_api_vrrp_vr_track_if_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vrrp_vr_track_if_dump_t: */
    s = format(s, "vl_api_vrrp_vr_track_if_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uis_ipv6: %u", format_white_space, indent, a->is_ipv6);
    s = format(s, "\n%Uvr_id: %u", format_white_space, indent, a->vr_id);
    s = format(s, "\n%Udump_all: %u", format_white_space, indent, a->dump_all);
    return s;
}

static inline u8 *vl_api_vrrp_vr_track_if_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vrrp_vr_track_if_details_t *a = va_arg (*args, vl_api_vrrp_vr_track_if_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vrrp_vr_track_if_details_t: */
    s = format(s, "vl_api_vrrp_vr_track_if_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uvr_id: %u", format_white_space, indent, a->vr_id);
    s = format(s, "\n%Uis_ipv6: %u", format_white_space, indent, a->is_ipv6);
    s = format(s, "\n%Un_ifs: %u", format_white_space, indent, a->n_ifs);
    for (i = 0; i < a->n_ifs; i++) {
        s = format(s, "\n%Uifs: %U",
                   format_white_space, indent, format_vl_api_vrrp_vr_track_if_t, &a->ifs[i], indent);
    }
    return s;
}

static inline u8 *vl_api_vrrp_vr_event_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_vrrp_vr_event_t *a = va_arg (*args, vl_api_vrrp_vr_event_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_vrrp_vr_event_t: */
    s = format(s, "vl_api_vrrp_vr_event_t:");
    s = format(s, "\n%Upid: %u", format_white_space, indent, a->pid);
    s = format(s, "\n%Uvr: %U", format_white_space, indent, format_vl_api_vrrp_vr_key_t, &a->vr, indent);
    s = format(s, "\n%Uold_state: %U", format_white_space, indent, format_vl_api_vrrp_vr_state_t, &a->old_state, indent);
    s = format(s, "\n%Unew_state: %U", format_white_space, indent, format_vl_api_vrrp_vr_state_t, &a->new_state, indent);
    return s;
}

static inline u8 *vl_api_want_vrrp_vr_events_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_want_vrrp_vr_events_t *a = va_arg (*args, vl_api_want_vrrp_vr_events_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_want_vrrp_vr_events_t: */
    s = format(s, "vl_api_want_vrrp_vr_events_t:");
    s = format(s, "\n%Uenable_disable: %u", format_white_space, indent, a->enable_disable);
    s = format(s, "\n%Upid: %u", format_white_space, indent, a->pid);
    return s;
}

static inline u8 *vl_api_want_vrrp_vr_events_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_want_vrrp_vr_events_reply_t *a = va_arg (*args, vl_api_want_vrrp_vr_events_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_want_vrrp_vr_events_reply_t: */
    s = format(s, "vl_api_want_vrrp_vr_events_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_vrrp_endianfun
#define included_vrrp_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_vrrp_vr_key_t_endian (vl_api_vrrp_vr_key_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->vr_id = a->vr_id (no-op) */
    /* a->is_ipv6 = a->is_ipv6 (no-op) */
}

static inline void vl_api_vrrp_vr_flags_t_endian (vl_api_vrrp_vr_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_vrrp_vr_conf_t_endian (vl_api_vrrp_vr_conf_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->vr_id = a->vr_id (no-op) */
    /* a->priority = a->priority (no-op) */
    a->interval = clib_net_to_host_u16(a->interval);
    vl_api_vrrp_vr_flags_t_endian(&a->flags, to_net);
}

static inline void vl_api_vrrp_vr_state_t_endian (vl_api_vrrp_vr_state_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_vrrp_vr_tracking_t_endian (vl_api_vrrp_vr_tracking_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->interfaces_dec = clib_net_to_host_u32(a->interfaces_dec);
    /* a->priority = a->priority (no-op) */
}

static inline void vl_api_vrrp_vr_runtime_t_endian (vl_api_vrrp_vr_runtime_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_vrrp_vr_state_t_endian(&a->state, to_net);
    a->master_adv_int = clib_net_to_host_u16(a->master_adv_int);
    a->skew = clib_net_to_host_u16(a->skew);
    a->master_down_int = clib_net_to_host_u16(a->master_down_int);
    vl_api_mac_address_t_endian(&a->mac, to_net);
    vl_api_vrrp_vr_tracking_t_endian(&a->tracking, to_net);
}

static inline void vl_api_vrrp_vr_track_if_t_endian (vl_api_vrrp_vr_track_if_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->priority = a->priority (no-op) */
}

static inline void vl_api_vrrp_vr_add_del_t_endian (vl_api_vrrp_vr_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->vr_id = a->vr_id (no-op) */
    /* a->priority = a->priority (no-op) */
    a->interval = clib_net_to_host_u16(a->interval);
    vl_api_vrrp_vr_flags_t_endian(&a->flags, to_net);
    /* a->n_addrs = a->n_addrs (no-op) */
    u32 count = a->n_addrs;
    for (i = 0; i < count; i++) {
        vl_api_address_t_endian(&a->addrs[i], to_net);
    }
}

static inline void vl_api_vrrp_vr_add_del_reply_t_endian (vl_api_vrrp_vr_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_vrrp_vr_update_t_endian (vl_api_vrrp_vr_update_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->vrrp_index = clib_net_to_host_u32(a->vrrp_index);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->vr_id = a->vr_id (no-op) */
    /* a->priority = a->priority (no-op) */
    a->interval = clib_net_to_host_u16(a->interval);
    vl_api_vrrp_vr_flags_t_endian(&a->flags, to_net);
    /* a->n_addrs = a->n_addrs (no-op) */
    u32 count = a->n_addrs;
    for (i = 0; i < count; i++) {
        vl_api_address_t_endian(&a->addrs[i], to_net);
    }
}

static inline void vl_api_vrrp_vr_update_reply_t_endian (vl_api_vrrp_vr_update_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->vrrp_index = clib_net_to_host_u32(a->vrrp_index);
}

static inline void vl_api_vrrp_vr_del_t_endian (vl_api_vrrp_vr_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->vrrp_index = clib_net_to_host_u32(a->vrrp_index);
}

static inline void vl_api_vrrp_vr_del_reply_t_endian (vl_api_vrrp_vr_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_vrrp_vr_dump_t_endian (vl_api_vrrp_vr_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_vrrp_vr_details_t_endian (vl_api_vrrp_vr_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_vrrp_vr_conf_t_endian(&a->config, to_net);
    vl_api_vrrp_vr_runtime_t_endian(&a->runtime, to_net);
    /* a->n_addrs = a->n_addrs (no-op) */
    u32 count = a->n_addrs;
    for (i = 0; i < count; i++) {
        vl_api_address_t_endian(&a->addrs[i], to_net);
    }
}

static inline void vl_api_vrrp_vr_start_stop_t_endian (vl_api_vrrp_vr_start_stop_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->vr_id = a->vr_id (no-op) */
    /* a->is_ipv6 = a->is_ipv6 (no-op) */
    /* a->is_start = a->is_start (no-op) */
}

static inline void vl_api_vrrp_vr_start_stop_reply_t_endian (vl_api_vrrp_vr_start_stop_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_vrrp_vr_set_peers_t_endian (vl_api_vrrp_vr_set_peers_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->vr_id = a->vr_id (no-op) */
    /* a->is_ipv6 = a->is_ipv6 (no-op) */
    /* a->n_addrs = a->n_addrs (no-op) */
    u32 count = a->n_addrs;
    for (i = 0; i < count; i++) {
        vl_api_address_t_endian(&a->addrs[i], to_net);
    }
}

static inline void vl_api_vrrp_vr_set_peers_reply_t_endian (vl_api_vrrp_vr_set_peers_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_vrrp_vr_peer_dump_t_endian (vl_api_vrrp_vr_peer_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->is_ipv6 = a->is_ipv6 (no-op) */
    /* a->vr_id = a->vr_id (no-op) */
}

static inline void vl_api_vrrp_vr_peer_details_t_endian (vl_api_vrrp_vr_peer_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->vr_id = a->vr_id (no-op) */
    /* a->is_ipv6 = a->is_ipv6 (no-op) */
    /* a->n_peer_addrs = a->n_peer_addrs (no-op) */
    u32 count = a->n_peer_addrs;
    for (i = 0; i < count; i++) {
        vl_api_address_t_endian(&a->peer_addrs[i], to_net);
    }
}

static inline void vl_api_vrrp_vr_track_if_add_del_t_endian (vl_api_vrrp_vr_track_if_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->is_ipv6 = a->is_ipv6 (no-op) */
    /* a->vr_id = a->vr_id (no-op) */
    /* a->is_add = a->is_add (no-op) */
    /* a->n_ifs = a->n_ifs (no-op) */
    u32 count = a->n_ifs;
    for (i = 0; i < count; i++) {
        vl_api_vrrp_vr_track_if_t_endian(&a->ifs[i], to_net);
    }
}

static inline void vl_api_vrrp_vr_track_if_add_del_reply_t_endian (vl_api_vrrp_vr_track_if_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_vrrp_vr_track_if_dump_t_endian (vl_api_vrrp_vr_track_if_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->is_ipv6 = a->is_ipv6 (no-op) */
    /* a->vr_id = a->vr_id (no-op) */
    /* a->dump_all = a->dump_all (no-op) */
}

static inline void vl_api_vrrp_vr_track_if_details_t_endian (vl_api_vrrp_vr_track_if_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->vr_id = a->vr_id (no-op) */
    /* a->is_ipv6 = a->is_ipv6 (no-op) */
    /* a->n_ifs = a->n_ifs (no-op) */
    u32 count = a->n_ifs;
    for (i = 0; i < count; i++) {
        vl_api_vrrp_vr_track_if_t_endian(&a->ifs[i], to_net);
    }
}

static inline void vl_api_vrrp_vr_event_t_endian (vl_api_vrrp_vr_event_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->pid = clib_net_to_host_u32(a->pid);
    vl_api_vrrp_vr_key_t_endian(&a->vr, to_net);
    vl_api_vrrp_vr_state_t_endian(&a->old_state, to_net);
    vl_api_vrrp_vr_state_t_endian(&a->new_state, to_net);
}

static inline void vl_api_want_vrrp_vr_events_t_endian (vl_api_want_vrrp_vr_events_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->enable_disable = a->enable_disable (no-op) */
    a->pid = clib_net_to_host_u32(a->pid);
}

static inline void vl_api_want_vrrp_vr_events_reply_t_endian (vl_api_want_vrrp_vr_events_reply_t *a, bool to_net)
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
#ifndef included_vrrp_calcsizefun
#define included_vrrp_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_key_t_calc_size (vl_api_vrrp_vr_key_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_flags_t_calc_size (vl_api_vrrp_vr_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_conf_t_calc_size (vl_api_vrrp_vr_conf_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->flags) + vl_api_vrrp_vr_flags_t_calc_size(&a->flags);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_state_t_calc_size (vl_api_vrrp_vr_state_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_tracking_t_calc_size (vl_api_vrrp_vr_tracking_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_runtime_t_calc_size (vl_api_vrrp_vr_runtime_t *a)
{
      return sizeof(*a) - sizeof(a->state) + vl_api_vrrp_vr_state_t_calc_size(&a->state) - sizeof(a->mac) + vl_api_mac_address_t_calc_size(&a->mac) - sizeof(a->tracking) + vl_api_vrrp_vr_tracking_t_calc_size(&a->tracking);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_track_if_t_calc_size (vl_api_vrrp_vr_track_if_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_add_del_t_calc_size (vl_api_vrrp_vr_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->flags) + vl_api_vrrp_vr_flags_t_calc_size(&a->flags) + a->n_addrs * sizeof(a->addrs[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_add_del_reply_t_calc_size (vl_api_vrrp_vr_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_update_t_calc_size (vl_api_vrrp_vr_update_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->flags) + vl_api_vrrp_vr_flags_t_calc_size(&a->flags) + a->n_addrs * sizeof(a->addrs[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_update_reply_t_calc_size (vl_api_vrrp_vr_update_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_del_t_calc_size (vl_api_vrrp_vr_del_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_del_reply_t_calc_size (vl_api_vrrp_vr_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_dump_t_calc_size (vl_api_vrrp_vr_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_details_t_calc_size (vl_api_vrrp_vr_details_t *a)
{
      return sizeof(*a) - sizeof(a->config) + vl_api_vrrp_vr_conf_t_calc_size(&a->config) - sizeof(a->runtime) + vl_api_vrrp_vr_runtime_t_calc_size(&a->runtime) + a->n_addrs * sizeof(a->addrs[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_start_stop_t_calc_size (vl_api_vrrp_vr_start_stop_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_start_stop_reply_t_calc_size (vl_api_vrrp_vr_start_stop_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_set_peers_t_calc_size (vl_api_vrrp_vr_set_peers_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) + a->n_addrs * sizeof(a->addrs[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_set_peers_reply_t_calc_size (vl_api_vrrp_vr_set_peers_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_peer_dump_t_calc_size (vl_api_vrrp_vr_peer_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_peer_details_t_calc_size (vl_api_vrrp_vr_peer_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) + a->n_peer_addrs * sizeof(a->peer_addrs[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_track_if_add_del_t_calc_size (vl_api_vrrp_vr_track_if_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) + a->n_ifs * sizeof(a->ifs[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_track_if_add_del_reply_t_calc_size (vl_api_vrrp_vr_track_if_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_track_if_dump_t_calc_size (vl_api_vrrp_vr_track_if_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_track_if_details_t_calc_size (vl_api_vrrp_vr_track_if_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) + a->n_ifs * sizeof(a->ifs[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_vrrp_vr_event_t_calc_size (vl_api_vrrp_vr_event_t *a)
{
      return sizeof(*a) - sizeof(a->vr) + vl_api_vrrp_vr_key_t_calc_size(&a->vr) - sizeof(a->old_state) + vl_api_vrrp_vr_state_t_calc_size(&a->old_state) - sizeof(a->new_state) + vl_api_vrrp_vr_state_t_calc_size(&a->new_state);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_want_vrrp_vr_events_t_calc_size (vl_api_want_vrrp_vr_events_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_want_vrrp_vr_events_reply_t_calc_size (vl_api_want_vrrp_vr_events_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(vrrp.api, 1, 1, 1)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(vrrp.api, 0x488c32da)

#endif

