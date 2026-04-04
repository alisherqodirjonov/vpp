/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: wireguard.api
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
#warning no content included from wireguard.api
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
vl_msg_id(VL_API_WIREGUARD_INTERFACE_CREATE, vl_api_wireguard_interface_create_t_handler)
vl_msg_id(VL_API_WIREGUARD_INTERFACE_CREATE_REPLY, vl_api_wireguard_interface_create_reply_t_handler)
vl_msg_id(VL_API_WIREGUARD_INTERFACE_DELETE, vl_api_wireguard_interface_delete_t_handler)
vl_msg_id(VL_API_WIREGUARD_INTERFACE_DELETE_REPLY, vl_api_wireguard_interface_delete_reply_t_handler)
vl_msg_id(VL_API_WIREGUARD_INTERFACE_DUMP, vl_api_wireguard_interface_dump_t_handler)
vl_msg_id(VL_API_WIREGUARD_INTERFACE_DETAILS, vl_api_wireguard_interface_details_t_handler)
vl_msg_id(VL_API_WANT_WIREGUARD_PEER_EVENTS, vl_api_want_wireguard_peer_events_t_handler)
vl_msg_id(VL_API_WANT_WIREGUARD_PEER_EVENTS_REPLY, vl_api_want_wireguard_peer_events_reply_t_handler)
vl_msg_id(VL_API_WIREGUARD_PEER_EVENT, vl_api_wireguard_peer_event_t_handler)
vl_msg_id(VL_API_WIREGUARD_PEER_ADD, vl_api_wireguard_peer_add_t_handler)
vl_msg_id(VL_API_WIREGUARD_PEER_ADD_REPLY, vl_api_wireguard_peer_add_reply_t_handler)
vl_msg_id(VL_API_WIREGUARD_PEER_REMOVE, vl_api_wireguard_peer_remove_t_handler)
vl_msg_id(VL_API_WIREGUARD_PEER_REMOVE_REPLY, vl_api_wireguard_peer_remove_reply_t_handler)
vl_msg_id(VL_API_WIREGUARD_PEERS_DUMP, vl_api_wireguard_peers_dump_t_handler)
vl_msg_id(VL_API_WIREGUARD_PEERS_DETAILS, vl_api_wireguard_peers_details_t_handler)
vl_msg_id(VL_API_WG_SET_ASYNC_MODE, vl_api_wg_set_async_mode_t_handler)
vl_msg_id(VL_API_WG_SET_ASYNC_MODE_REPLY, vl_api_wg_set_async_mode_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_wireguard_interface_create_t, 1)
vl_msg_name(vl_api_wireguard_interface_create_reply_t, 1)
vl_msg_name(vl_api_wireguard_interface_delete_t, 1)
vl_msg_name(vl_api_wireguard_interface_delete_reply_t, 1)
vl_msg_name(vl_api_wireguard_interface_dump_t, 1)
vl_msg_name(vl_api_wireguard_interface_details_t, 1)
vl_msg_name(vl_api_want_wireguard_peer_events_t, 1)
vl_msg_name(vl_api_want_wireguard_peer_events_reply_t, 1)
vl_msg_name(vl_api_wireguard_peer_event_t, 1)
vl_msg_name(vl_api_wireguard_peer_add_t, 1)
vl_msg_name(vl_api_wireguard_peer_add_reply_t, 1)
vl_msg_name(vl_api_wireguard_peer_remove_t, 1)
vl_msg_name(vl_api_wireguard_peer_remove_reply_t, 1)
vl_msg_name(vl_api_wireguard_peers_dump_t, 1)
vl_msg_name(vl_api_wireguard_peers_details_t, 1)
vl_msg_name(vl_api_wg_set_async_mode_t, 1)
vl_msg_name(vl_api_wg_set_async_mode_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_wireguard \
_(VL_API_WIREGUARD_INTERFACE_CREATE, wireguard_interface_create, a530137e) \
_(VL_API_WIREGUARD_INTERFACE_CREATE_REPLY, wireguard_interface_create_reply, 5383d31f) \
_(VL_API_WIREGUARD_INTERFACE_DELETE, wireguard_interface_delete, f9e6675e) \
_(VL_API_WIREGUARD_INTERFACE_DELETE_REPLY, wireguard_interface_delete_reply, e8d4e804) \
_(VL_API_WIREGUARD_INTERFACE_DUMP, wireguard_interface_dump, 2c954158) \
_(VL_API_WIREGUARD_INTERFACE_DETAILS, wireguard_interface_details, 0dd4865d) \
_(VL_API_WANT_WIREGUARD_PEER_EVENTS, want_wireguard_peer_events, 3bc666c8) \
_(VL_API_WANT_WIREGUARD_PEER_EVENTS_REPLY, want_wireguard_peer_events_reply, e8d4e804) \
_(VL_API_WIREGUARD_PEER_EVENT, wireguard_peer_event, 4e1b5d67) \
_(VL_API_WIREGUARD_PEER_ADD, wireguard_peer_add, 9b8aad61) \
_(VL_API_WIREGUARD_PEER_ADD_REPLY, wireguard_peer_add_reply, 084a0cd3) \
_(VL_API_WIREGUARD_PEER_REMOVE, wireguard_peer_remove, 3b74607a) \
_(VL_API_WIREGUARD_PEER_REMOVE_REPLY, wireguard_peer_remove_reply, e8d4e804) \
_(VL_API_WIREGUARD_PEERS_DUMP, wireguard_peers_dump, 3b74607a) \
_(VL_API_WIREGUARD_PEERS_DETAILS, wireguard_peers_details, 6a9f6bc3) \
_(VL_API_WG_SET_ASYNC_MODE, wg_set_async_mode, a6465f7c) \
_(VL_API_WG_SET_ASYNC_MODE_REPLY, wg_set_async_mode_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "wireguard.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_wireguard_printfun_types
#define included_wireguard_printfun_types

static inline u8 *format_vl_api_wireguard_interface_t (u8 *s, va_list * args)
{
    vl_api_wireguard_interface_t *a = va_arg (*args, vl_api_wireguard_interface_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uuser_instance: %u", format_white_space, indent, a->user_instance);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uprivate_key: %U", format_white_space, indent, format_hex_bytes, a, 32);
    s = format(s, "\n%Upublic_key: %U", format_white_space, indent, format_hex_bytes, a, 32);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    s = format(s, "\n%Usrc_ip: %U", format_white_space, indent, format_vl_api_address_t, &a->src_ip, indent);
    return s;
}

static inline u8 *format_vl_api_wireguard_peer_flags_t (u8 *s, va_list * args)
{
    vl_api_wireguard_peer_flags_t *a = va_arg (*args, vl_api_wireguard_peer_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "WIREGUARD_PEER_STATUS_DEAD");
    case 2:
        return format(s, "WIREGUARD_PEER_ESTABLISHED");
    }
    return s;
}

static inline u8 *format_vl_api_wireguard_peer_t (u8 *s, va_list * args)
{
    vl_api_wireguard_peer_t *a = va_arg (*args, vl_api_wireguard_peer_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Upeer_index: %u", format_white_space, indent, a->peer_index);
    s = format(s, "\n%Upublic_key: %U", format_white_space, indent, format_hex_bytes, a, 32);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    s = format(s, "\n%Upersistent_keepalive: %u", format_white_space, indent, a->persistent_keepalive);
    s = format(s, "\n%Utable_id: %u", format_white_space, indent, a->table_id);
    s = format(s, "\n%Uendpoint: %U", format_white_space, indent, format_vl_api_address_t, &a->endpoint, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_wireguard_peer_flags_t, &a->flags, indent);
    s = format(s, "\n%Un_allowed_ips: %u", format_white_space, indent, a->n_allowed_ips);
    for (i = 0; i < a->n_allowed_ips; i++) {
        s = format(s, "\n%Uallowed_ips: %U",
                   format_white_space, indent, format_vl_api_prefix_t, &a->allowed_ips[i], indent);
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_wireguard_printfun
#define included_wireguard_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "wireguard.api_tojson.h"
#include "wireguard.api_fromjson.h"

static inline u8 *vl_api_wireguard_interface_create_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_wireguard_interface_create_t *a = va_arg (*args, vl_api_wireguard_interface_create_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_wireguard_interface_create_t: */
    s = format(s, "vl_api_wireguard_interface_create_t:");
    s = format(s, "\n%Uinterface: %U", format_white_space, indent, format_vl_api_wireguard_interface_t, &a->interface, indent);
    s = format(s, "\n%Ugenerate_key: %u", format_white_space, indent, a->generate_key);
    return s;
}

static inline u8 *vl_api_wireguard_interface_create_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_wireguard_interface_create_reply_t *a = va_arg (*args, vl_api_wireguard_interface_create_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_wireguard_interface_create_reply_t: */
    s = format(s, "vl_api_wireguard_interface_create_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_wireguard_interface_delete_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_wireguard_interface_delete_t *a = va_arg (*args, vl_api_wireguard_interface_delete_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_wireguard_interface_delete_t: */
    s = format(s, "vl_api_wireguard_interface_delete_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_wireguard_interface_delete_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_wireguard_interface_delete_reply_t *a = va_arg (*args, vl_api_wireguard_interface_delete_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_wireguard_interface_delete_reply_t: */
    s = format(s, "vl_api_wireguard_interface_delete_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_wireguard_interface_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_wireguard_interface_dump_t *a = va_arg (*args, vl_api_wireguard_interface_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_wireguard_interface_dump_t: */
    s = format(s, "vl_api_wireguard_interface_dump_t:");
    s = format(s, "\n%Ushow_private_key: %u", format_white_space, indent, a->show_private_key);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_wireguard_interface_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_wireguard_interface_details_t *a = va_arg (*args, vl_api_wireguard_interface_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_wireguard_interface_details_t: */
    s = format(s, "vl_api_wireguard_interface_details_t:");
    s = format(s, "\n%Uinterface: %U", format_white_space, indent, format_vl_api_wireguard_interface_t, &a->interface, indent);
    return s;
}

static inline u8 *vl_api_want_wireguard_peer_events_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_want_wireguard_peer_events_t *a = va_arg (*args, vl_api_want_wireguard_peer_events_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_want_wireguard_peer_events_t: */
    s = format(s, "vl_api_want_wireguard_peer_events_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Upeer_index: %u", format_white_space, indent, a->peer_index);
    s = format(s, "\n%Uenable_disable: %u", format_white_space, indent, a->enable_disable);
    s = format(s, "\n%Upid: %u", format_white_space, indent, a->pid);
    return s;
}

static inline u8 *vl_api_want_wireguard_peer_events_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_want_wireguard_peer_events_reply_t *a = va_arg (*args, vl_api_want_wireguard_peer_events_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_want_wireguard_peer_events_reply_t: */
    s = format(s, "vl_api_want_wireguard_peer_events_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_wireguard_peer_event_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_wireguard_peer_event_t *a = va_arg (*args, vl_api_wireguard_peer_event_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_wireguard_peer_event_t: */
    s = format(s, "vl_api_wireguard_peer_event_t:");
    s = format(s, "\n%Upid: %u", format_white_space, indent, a->pid);
    s = format(s, "\n%Upeer_index: %u", format_white_space, indent, a->peer_index);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_wireguard_peer_flags_t, &a->flags, indent);
    return s;
}

static inline u8 *vl_api_wireguard_peer_add_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_wireguard_peer_add_t *a = va_arg (*args, vl_api_wireguard_peer_add_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_wireguard_peer_add_t: */
    s = format(s, "vl_api_wireguard_peer_add_t:");
    s = format(s, "\n%Upeer: %U", format_white_space, indent, format_vl_api_wireguard_peer_t, &a->peer, indent);
    return s;
}

static inline u8 *vl_api_wireguard_peer_add_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_wireguard_peer_add_reply_t *a = va_arg (*args, vl_api_wireguard_peer_add_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_wireguard_peer_add_reply_t: */
    s = format(s, "vl_api_wireguard_peer_add_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Upeer_index: %u", format_white_space, indent, a->peer_index);
    return s;
}

static inline u8 *vl_api_wireguard_peer_remove_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_wireguard_peer_remove_t *a = va_arg (*args, vl_api_wireguard_peer_remove_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_wireguard_peer_remove_t: */
    s = format(s, "vl_api_wireguard_peer_remove_t:");
    s = format(s, "\n%Upeer_index: %u", format_white_space, indent, a->peer_index);
    return s;
}

static inline u8 *vl_api_wireguard_peer_remove_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_wireguard_peer_remove_reply_t *a = va_arg (*args, vl_api_wireguard_peer_remove_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_wireguard_peer_remove_reply_t: */
    s = format(s, "vl_api_wireguard_peer_remove_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_wireguard_peers_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_wireguard_peers_dump_t *a = va_arg (*args, vl_api_wireguard_peers_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_wireguard_peers_dump_t: */
    s = format(s, "vl_api_wireguard_peers_dump_t:");
    s = format(s, "\n%Upeer_index: %u", format_white_space, indent, a->peer_index);
    return s;
}

static inline u8 *vl_api_wireguard_peers_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_wireguard_peers_details_t *a = va_arg (*args, vl_api_wireguard_peers_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_wireguard_peers_details_t: */
    s = format(s, "vl_api_wireguard_peers_details_t:");
    s = format(s, "\n%Upeer: %U", format_white_space, indent, format_vl_api_wireguard_peer_t, &a->peer, indent);
    return s;
}

static inline u8 *vl_api_wg_set_async_mode_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_wg_set_async_mode_t *a = va_arg (*args, vl_api_wg_set_async_mode_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_wg_set_async_mode_t: */
    s = format(s, "vl_api_wg_set_async_mode_t:");
    s = format(s, "\n%Uasync_enable: %u", format_white_space, indent, a->async_enable);
    return s;
}

static inline u8 *vl_api_wg_set_async_mode_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_wg_set_async_mode_reply_t *a = va_arg (*args, vl_api_wg_set_async_mode_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_wg_set_async_mode_reply_t: */
    s = format(s, "vl_api_wg_set_async_mode_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_wireguard_endianfun
#define included_wireguard_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_wireguard_interface_t_endian (vl_api_wireguard_interface_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->user_instance = clib_net_to_host_u32(a->user_instance);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->private_key = a->private_key (no-op) */
    /* a->public_key = a->public_key (no-op) */
    a->port = clib_net_to_host_u16(a->port);
    vl_api_address_t_endian(&a->src_ip, to_net);
}

static inline void vl_api_wireguard_peer_flags_t_endian (vl_api_wireguard_peer_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->wireguard_peer_flags = a->wireguard_peer_flags (no-op) */
}

static inline void vl_api_wireguard_peer_t_endian (vl_api_wireguard_peer_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->peer_index = clib_net_to_host_u32(a->peer_index);
    /* a->public_key = a->public_key (no-op) */
    a->port = clib_net_to_host_u16(a->port);
    a->persistent_keepalive = clib_net_to_host_u16(a->persistent_keepalive);
    a->table_id = clib_net_to_host_u32(a->table_id);
    vl_api_address_t_endian(&a->endpoint, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_wireguard_peer_flags_t_endian(&a->flags, to_net);
    /* a->n_allowed_ips = a->n_allowed_ips (no-op) */
    u32 count = a->n_allowed_ips;
    for (i = 0; i < count; i++) {
        vl_api_prefix_t_endian(&a->allowed_ips[i], to_net);
    }
}

static inline void vl_api_wireguard_interface_create_t_endian (vl_api_wireguard_interface_create_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_wireguard_interface_t_endian(&a->interface, to_net);
    /* a->generate_key = a->generate_key (no-op) */
}

static inline void vl_api_wireguard_interface_create_reply_t_endian (vl_api_wireguard_interface_create_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_wireguard_interface_delete_t_endian (vl_api_wireguard_interface_delete_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_wireguard_interface_delete_reply_t_endian (vl_api_wireguard_interface_delete_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_wireguard_interface_dump_t_endian (vl_api_wireguard_interface_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->show_private_key = a->show_private_key (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_wireguard_interface_details_t_endian (vl_api_wireguard_interface_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_wireguard_interface_t_endian(&a->interface, to_net);
}

static inline void vl_api_want_wireguard_peer_events_t_endian (vl_api_want_wireguard_peer_events_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->peer_index = clib_net_to_host_u32(a->peer_index);
    a->enable_disable = clib_net_to_host_u32(a->enable_disable);
    a->pid = clib_net_to_host_u32(a->pid);
}

static inline void vl_api_want_wireguard_peer_events_reply_t_endian (vl_api_want_wireguard_peer_events_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_wireguard_peer_event_t_endian (vl_api_wireguard_peer_event_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->pid = clib_net_to_host_u32(a->pid);
    a->peer_index = clib_net_to_host_u32(a->peer_index);
    vl_api_wireguard_peer_flags_t_endian(&a->flags, to_net);
}

static inline void vl_api_wireguard_peer_add_t_endian (vl_api_wireguard_peer_add_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_wireguard_peer_t_endian(&a->peer, to_net);
}

static inline void vl_api_wireguard_peer_add_reply_t_endian (vl_api_wireguard_peer_add_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->peer_index = clib_net_to_host_u32(a->peer_index);
}

static inline void vl_api_wireguard_peer_remove_t_endian (vl_api_wireguard_peer_remove_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->peer_index = clib_net_to_host_u32(a->peer_index);
}

static inline void vl_api_wireguard_peer_remove_reply_t_endian (vl_api_wireguard_peer_remove_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_wireguard_peers_dump_t_endian (vl_api_wireguard_peers_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->peer_index = clib_net_to_host_u32(a->peer_index);
}

static inline void vl_api_wireguard_peers_details_t_endian (vl_api_wireguard_peers_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_wireguard_peer_t_endian(&a->peer, to_net);
}

static inline void vl_api_wg_set_async_mode_t_endian (vl_api_wg_set_async_mode_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->async_enable = a->async_enable (no-op) */
}

static inline void vl_api_wg_set_async_mode_reply_t_endian (vl_api_wg_set_async_mode_reply_t *a, bool to_net)
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
#ifndef included_wireguard_calcsizefun
#define included_wireguard_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_wireguard_interface_t_calc_size (vl_api_wireguard_interface_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->src_ip) + vl_api_address_t_calc_size(&a->src_ip);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_wireguard_peer_flags_t_calc_size (vl_api_wireguard_peer_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_wireguard_peer_t_calc_size (vl_api_wireguard_peer_t *a)
{
      return sizeof(*a) - sizeof(a->endpoint) + vl_api_address_t_calc_size(&a->endpoint) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->flags) + vl_api_wireguard_peer_flags_t_calc_size(&a->flags) + a->n_allowed_ips * sizeof(a->allowed_ips[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_wireguard_interface_create_t_calc_size (vl_api_wireguard_interface_create_t *a)
{
      return sizeof(*a) - sizeof(a->interface) + vl_api_wireguard_interface_t_calc_size(&a->interface);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_wireguard_interface_create_reply_t_calc_size (vl_api_wireguard_interface_create_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_wireguard_interface_delete_t_calc_size (vl_api_wireguard_interface_delete_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_wireguard_interface_delete_reply_t_calc_size (vl_api_wireguard_interface_delete_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_wireguard_interface_dump_t_calc_size (vl_api_wireguard_interface_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_wireguard_interface_details_t_calc_size (vl_api_wireguard_interface_details_t *a)
{
      return sizeof(*a) - sizeof(a->interface) + vl_api_wireguard_interface_t_calc_size(&a->interface);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_want_wireguard_peer_events_t_calc_size (vl_api_want_wireguard_peer_events_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_want_wireguard_peer_events_reply_t_calc_size (vl_api_want_wireguard_peer_events_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_wireguard_peer_event_t_calc_size (vl_api_wireguard_peer_event_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_wireguard_peer_flags_t_calc_size(&a->flags);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_wireguard_peer_add_t_calc_size (vl_api_wireguard_peer_add_t *a)
{
      return sizeof(*a) - sizeof(a->peer) + vl_api_wireguard_peer_t_calc_size(&a->peer);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_wireguard_peer_add_reply_t_calc_size (vl_api_wireguard_peer_add_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_wireguard_peer_remove_t_calc_size (vl_api_wireguard_peer_remove_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_wireguard_peer_remove_reply_t_calc_size (vl_api_wireguard_peer_remove_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_wireguard_peers_dump_t_calc_size (vl_api_wireguard_peers_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_wireguard_peers_details_t_calc_size (vl_api_wireguard_peers_details_t *a)
{
      return sizeof(*a) - sizeof(a->peer) + vl_api_wireguard_peer_t_calc_size(&a->peer);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_wg_set_async_mode_t_calc_size (vl_api_wg_set_async_mode_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_wg_set_async_mode_reply_t_calc_size (vl_api_wg_set_async_mode_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(wireguard.api, 1, 3, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(wireguard.api, 0x4f5c87aa)

#endif

