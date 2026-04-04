/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: ip6_nd.api
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
#warning no content included from ip6_nd.api
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
vl_msg_id(VL_API_SW_INTERFACE_IP6ND_RA_CONFIG, vl_api_sw_interface_ip6nd_ra_config_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_IP6ND_RA_CONFIG_REPLY, vl_api_sw_interface_ip6nd_ra_config_reply_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_IP6ND_RA_PREFIX, vl_api_sw_interface_ip6nd_ra_prefix_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_IP6ND_RA_PREFIX_REPLY, vl_api_sw_interface_ip6nd_ra_prefix_reply_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_IP6ND_RA_DUMP, vl_api_sw_interface_ip6nd_ra_dump_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_IP6ND_RA_DETAILS, vl_api_sw_interface_ip6nd_ra_details_t_handler)
vl_msg_id(VL_API_IP6ND_PROXY_ENABLE_DISABLE, vl_api_ip6nd_proxy_enable_disable_t_handler)
vl_msg_id(VL_API_IP6ND_PROXY_ENABLE_DISABLE_REPLY, vl_api_ip6nd_proxy_enable_disable_reply_t_handler)
vl_msg_id(VL_API_IP6ND_PROXY_ADD_DEL, vl_api_ip6nd_proxy_add_del_t_handler)
vl_msg_id(VL_API_IP6ND_PROXY_ADD_DEL_REPLY, vl_api_ip6nd_proxy_add_del_reply_t_handler)
vl_msg_id(VL_API_IP6ND_PROXY_DETAILS, vl_api_ip6nd_proxy_details_t_handler)
vl_msg_id(VL_API_IP6ND_PROXY_DUMP, vl_api_ip6nd_proxy_dump_t_handler)
vl_msg_id(VL_API_IP6ND_SEND_ROUTER_SOLICITATION, vl_api_ip6nd_send_router_solicitation_t_handler)
vl_msg_id(VL_API_IP6ND_SEND_ROUTER_SOLICITATION_REPLY, vl_api_ip6nd_send_router_solicitation_reply_t_handler)
vl_msg_id(VL_API_WANT_IP6_RA_EVENTS, vl_api_want_ip6_ra_events_t_handler)
vl_msg_id(VL_API_WANT_IP6_RA_EVENTS_REPLY, vl_api_want_ip6_ra_events_reply_t_handler)
vl_msg_id(VL_API_IP6_RA_EVENT, vl_api_ip6_ra_event_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_sw_interface_ip6nd_ra_config_t, 1)
vl_msg_name(vl_api_sw_interface_ip6nd_ra_config_reply_t, 1)
vl_msg_name(vl_api_sw_interface_ip6nd_ra_prefix_t, 1)
vl_msg_name(vl_api_sw_interface_ip6nd_ra_prefix_reply_t, 1)
vl_msg_name(vl_api_sw_interface_ip6nd_ra_dump_t, 1)
vl_msg_name(vl_api_sw_interface_ip6nd_ra_details_t, 1)
vl_msg_name(vl_api_ip6nd_proxy_enable_disable_t, 1)
vl_msg_name(vl_api_ip6nd_proxy_enable_disable_reply_t, 1)
vl_msg_name(vl_api_ip6nd_proxy_add_del_t, 1)
vl_msg_name(vl_api_ip6nd_proxy_add_del_reply_t, 1)
vl_msg_name(vl_api_ip6nd_proxy_details_t, 1)
vl_msg_name(vl_api_ip6nd_proxy_dump_t, 1)
vl_msg_name(vl_api_ip6nd_send_router_solicitation_t, 1)
vl_msg_name(vl_api_ip6nd_send_router_solicitation_reply_t, 1)
vl_msg_name(vl_api_want_ip6_ra_events_t, 1)
vl_msg_name(vl_api_want_ip6_ra_events_reply_t, 1)
vl_msg_name(vl_api_ip6_ra_event_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_ip6_nd \
_(VL_API_SW_INTERFACE_IP6ND_RA_CONFIG, sw_interface_ip6nd_ra_config, 3eb00b1c) \
_(VL_API_SW_INTERFACE_IP6ND_RA_CONFIG_REPLY, sw_interface_ip6nd_ra_config_reply, e8d4e804) \
_(VL_API_SW_INTERFACE_IP6ND_RA_PREFIX, sw_interface_ip6nd_ra_prefix, 82cc1b28) \
_(VL_API_SW_INTERFACE_IP6ND_RA_PREFIX_REPLY, sw_interface_ip6nd_ra_prefix_reply, e8d4e804) \
_(VL_API_SW_INTERFACE_IP6ND_RA_DUMP, sw_interface_ip6nd_ra_dump, f9e6675e) \
_(VL_API_SW_INTERFACE_IP6ND_RA_DETAILS, sw_interface_ip6nd_ra_details, d3198de5) \
_(VL_API_IP6ND_PROXY_ENABLE_DISABLE, ip6nd_proxy_enable_disable, 7daa1e3a) \
_(VL_API_IP6ND_PROXY_ENABLE_DISABLE_REPLY, ip6nd_proxy_enable_disable_reply, e8d4e804) \
_(VL_API_IP6ND_PROXY_ADD_DEL, ip6nd_proxy_add_del, c2e4a686) \
_(VL_API_IP6ND_PROXY_ADD_DEL_REPLY, ip6nd_proxy_add_del_reply, e8d4e804) \
_(VL_API_IP6ND_PROXY_DETAILS, ip6nd_proxy_details, 30b9ff4a) \
_(VL_API_IP6ND_PROXY_DUMP, ip6nd_proxy_dump, 51077d14) \
_(VL_API_IP6ND_SEND_ROUTER_SOLICITATION, ip6nd_send_router_solicitation, e5de609c) \
_(VL_API_IP6ND_SEND_ROUTER_SOLICITATION_REPLY, ip6nd_send_router_solicitation_reply, e8d4e804) \
_(VL_API_WANT_IP6_RA_EVENTS, want_ip6_ra_events, 3ec6d6c2) \
_(VL_API_WANT_IP6_RA_EVENTS_REPLY, want_ip6_ra_events_reply, e8d4e804) \
_(VL_API_IP6_RA_EVENT, ip6_ra_event, 0364c1c5) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "ip6_nd.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_ip6_nd_printfun_types
#define included_ip6_nd_printfun_types

static inline u8 *format_vl_api_ip6nd_ra_prefix_t (u8 *s, va_list * args)
{
    vl_api_ip6nd_ra_prefix_t *a = va_arg (*args, vl_api_ip6nd_ra_prefix_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uprefix: %U", format_white_space, indent, format_vl_api_prefix_t, &a->prefix, indent);
    s = format(s, "\n%Uonlink_flag: %u", format_white_space, indent, a->onlink_flag);
    s = format(s, "\n%Uautonomous_flag: %u", format_white_space, indent, a->autonomous_flag);
    s = format(s, "\n%Uval_lifetime: %u", format_white_space, indent, a->val_lifetime);
    s = format(s, "\n%Upref_lifetime: %u", format_white_space, indent, a->pref_lifetime);
    s = format(s, "\n%Uvalid_lifetime_expires: %.2f", format_white_space, indent, a->valid_lifetime_expires);
    s = format(s, "\n%Upref_lifetime_expires: %.2f", format_white_space, indent, a->pref_lifetime_expires);
    s = format(s, "\n%Udecrement_lifetime_flag: %u", format_white_space, indent, a->decrement_lifetime_flag);
    s = format(s, "\n%Uno_advertise: %u", format_white_space, indent, a->no_advertise);
    return s;
}

static inline u8 *format_vl_api_ip6_ra_prefix_info_t (u8 *s, va_list * args)
{
    vl_api_ip6_ra_prefix_info_t *a = va_arg (*args, vl_api_ip6_ra_prefix_info_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uprefix: %U", format_white_space, indent, format_vl_api_prefix_t, &a->prefix, indent);
    s = format(s, "\n%Uflags: %u", format_white_space, indent, a->flags);
    s = format(s, "\n%Uvalid_time: %u", format_white_space, indent, a->valid_time);
    s = format(s, "\n%Upreferred_time: %u", format_white_space, indent, a->preferred_time);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_ip6_nd_printfun
#define included_ip6_nd_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "ip6_nd.api_tojson.h"
#include "ip6_nd.api_fromjson.h"

static inline u8 *vl_api_sw_interface_ip6nd_ra_config_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_ip6nd_ra_config_t *a = va_arg (*args, vl_api_sw_interface_ip6nd_ra_config_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_ip6nd_ra_config_t: */
    s = format(s, "vl_api_sw_interface_ip6nd_ra_config_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Usuppress: %u", format_white_space, indent, a->suppress);
    s = format(s, "\n%Umanaged: %u", format_white_space, indent, a->managed);
    s = format(s, "\n%Uother: %u", format_white_space, indent, a->other);
    s = format(s, "\n%Ull_option: %u", format_white_space, indent, a->ll_option);
    s = format(s, "\n%Usend_unicast: %u", format_white_space, indent, a->send_unicast);
    s = format(s, "\n%Ucease: %u", format_white_space, indent, a->cease);
    s = format(s, "\n%Uis_no: %u", format_white_space, indent, a->is_no);
    s = format(s, "\n%Udefault_router: %u", format_white_space, indent, a->default_router);
    s = format(s, "\n%Umax_interval: %u", format_white_space, indent, a->max_interval);
    s = format(s, "\n%Umin_interval: %u", format_white_space, indent, a->min_interval);
    s = format(s, "\n%Ulifetime: %u", format_white_space, indent, a->lifetime);
    s = format(s, "\n%Uinitial_count: %u", format_white_space, indent, a->initial_count);
    s = format(s, "\n%Uinitial_interval: %u", format_white_space, indent, a->initial_interval);
    return s;
}

static inline u8 *vl_api_sw_interface_ip6nd_ra_config_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_ip6nd_ra_config_reply_t *a = va_arg (*args, vl_api_sw_interface_ip6nd_ra_config_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_ip6nd_ra_config_reply_t: */
    s = format(s, "vl_api_sw_interface_ip6nd_ra_config_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sw_interface_ip6nd_ra_prefix_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_ip6nd_ra_prefix_t *a = va_arg (*args, vl_api_sw_interface_ip6nd_ra_prefix_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_ip6nd_ra_prefix_t: */
    s = format(s, "vl_api_sw_interface_ip6nd_ra_prefix_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uprefix: %U", format_white_space, indent, format_vl_api_prefix_t, &a->prefix, indent);
    s = format(s, "\n%Uuse_default: %u", format_white_space, indent, a->use_default);
    s = format(s, "\n%Uno_advertise: %u", format_white_space, indent, a->no_advertise);
    s = format(s, "\n%Uoff_link: %u", format_white_space, indent, a->off_link);
    s = format(s, "\n%Uno_autoconfig: %u", format_white_space, indent, a->no_autoconfig);
    s = format(s, "\n%Uno_onlink: %u", format_white_space, indent, a->no_onlink);
    s = format(s, "\n%Uis_no: %u", format_white_space, indent, a->is_no);
    s = format(s, "\n%Uval_lifetime: %u", format_white_space, indent, a->val_lifetime);
    s = format(s, "\n%Upref_lifetime: %u", format_white_space, indent, a->pref_lifetime);
    return s;
}

static inline u8 *vl_api_sw_interface_ip6nd_ra_prefix_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_ip6nd_ra_prefix_reply_t *a = va_arg (*args, vl_api_sw_interface_ip6nd_ra_prefix_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_ip6nd_ra_prefix_reply_t: */
    s = format(s, "vl_api_sw_interface_ip6nd_ra_prefix_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sw_interface_ip6nd_ra_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_ip6nd_ra_dump_t *a = va_arg (*args, vl_api_sw_interface_ip6nd_ra_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_ip6nd_ra_dump_t: */
    s = format(s, "vl_api_sw_interface_ip6nd_ra_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_sw_interface_ip6nd_ra_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_ip6nd_ra_details_t *a = va_arg (*args, vl_api_sw_interface_ip6nd_ra_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_ip6nd_ra_details_t: */
    s = format(s, "vl_api_sw_interface_ip6nd_ra_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Ucur_hop_limit: %u", format_white_space, indent, a->cur_hop_limit);
    s = format(s, "\n%Uadv_managed_flag: %u", format_white_space, indent, a->adv_managed_flag);
    s = format(s, "\n%Uadv_other_flag: %u", format_white_space, indent, a->adv_other_flag);
    s = format(s, "\n%Uadv_router_lifetime: %u", format_white_space, indent, a->adv_router_lifetime);
    s = format(s, "\n%Uadv_neighbor_reachable_time: %u", format_white_space, indent, a->adv_neighbor_reachable_time);
    s = format(s, "\n%Uadv_retransmit_interval: %u", format_white_space, indent, a->adv_retransmit_interval);
    s = format(s, "\n%Uadv_link_mtu: %u", format_white_space, indent, a->adv_link_mtu);
    s = format(s, "\n%Usend_radv: %u", format_white_space, indent, a->send_radv);
    s = format(s, "\n%Ucease_radv: %u", format_white_space, indent, a->cease_radv);
    s = format(s, "\n%Usend_unicast: %u", format_white_space, indent, a->send_unicast);
    s = format(s, "\n%Uadv_link_layer_address: %u", format_white_space, indent, a->adv_link_layer_address);
    s = format(s, "\n%Umax_radv_interval: %.2f", format_white_space, indent, a->max_radv_interval);
    s = format(s, "\n%Umin_radv_interval: %.2f", format_white_space, indent, a->min_radv_interval);
    s = format(s, "\n%Ulast_radv_time: %.2f", format_white_space, indent, a->last_radv_time);
    s = format(s, "\n%Ulast_multicast_time: %.2f", format_white_space, indent, a->last_multicast_time);
    s = format(s, "\n%Unext_multicast_time: %.2f", format_white_space, indent, a->next_multicast_time);
    s = format(s, "\n%Uinitial_adverts_count: %u", format_white_space, indent, a->initial_adverts_count);
    s = format(s, "\n%Uinitial_adverts_interval: %.2f", format_white_space, indent, a->initial_adverts_interval);
    s = format(s, "\n%Uinitial_adverts_sent: %u", format_white_space, indent, a->initial_adverts_sent);
    s = format(s, "\n%Un_advertisements_sent: %u", format_white_space, indent, a->n_advertisements_sent);
    s = format(s, "\n%Un_solicitations_rcvd: %u", format_white_space, indent, a->n_solicitations_rcvd);
    s = format(s, "\n%Un_solicitations_dropped: %u", format_white_space, indent, a->n_solicitations_dropped);
    s = format(s, "\n%Un_prefixes: %u", format_white_space, indent, a->n_prefixes);
    for (i = 0; i < a->n_prefixes; i++) {
        s = format(s, "\n%Uprefixes: %U",
                   format_white_space, indent, format_vl_api_ip6nd_ra_prefix_t, &a->prefixes[i], indent);
    }
    return s;
}

static inline u8 *vl_api_ip6nd_proxy_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip6nd_proxy_enable_disable_t *a = va_arg (*args, vl_api_ip6nd_proxy_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip6nd_proxy_enable_disable_t: */
    s = format(s, "vl_api_ip6nd_proxy_enable_disable_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uis_enable: %u", format_white_space, indent, a->is_enable);
    return s;
}

static inline u8 *vl_api_ip6nd_proxy_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip6nd_proxy_enable_disable_reply_t *a = va_arg (*args, vl_api_ip6nd_proxy_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip6nd_proxy_enable_disable_reply_t: */
    s = format(s, "vl_api_ip6nd_proxy_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ip6nd_proxy_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip6nd_proxy_add_del_t *a = va_arg (*args, vl_api_ip6nd_proxy_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip6nd_proxy_add_del_t: */
    s = format(s, "vl_api_ip6nd_proxy_add_del_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uip: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->ip, indent);
    return s;
}

static inline u8 *vl_api_ip6nd_proxy_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip6nd_proxy_add_del_reply_t *a = va_arg (*args, vl_api_ip6nd_proxy_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip6nd_proxy_add_del_reply_t: */
    s = format(s, "vl_api_ip6nd_proxy_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ip6nd_proxy_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip6nd_proxy_details_t *a = va_arg (*args, vl_api_ip6nd_proxy_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip6nd_proxy_details_t: */
    s = format(s, "vl_api_ip6nd_proxy_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uip: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->ip, indent);
    return s;
}

static inline u8 *vl_api_ip6nd_proxy_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip6nd_proxy_dump_t *a = va_arg (*args, vl_api_ip6nd_proxy_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip6nd_proxy_dump_t: */
    s = format(s, "vl_api_ip6nd_proxy_dump_t:");
    return s;
}

static inline u8 *vl_api_ip6nd_send_router_solicitation_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip6nd_send_router_solicitation_t *a = va_arg (*args, vl_api_ip6nd_send_router_solicitation_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip6nd_send_router_solicitation_t: */
    s = format(s, "vl_api_ip6nd_send_router_solicitation_t:");
    s = format(s, "\n%Uirt: %u", format_white_space, indent, a->irt);
    s = format(s, "\n%Umrt: %u", format_white_space, indent, a->mrt);
    s = format(s, "\n%Umrc: %u", format_white_space, indent, a->mrc);
    s = format(s, "\n%Umrd: %u", format_white_space, indent, a->mrd);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Ustop: %u", format_white_space, indent, a->stop);
    return s;
}

static inline u8 *vl_api_ip6nd_send_router_solicitation_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip6nd_send_router_solicitation_reply_t *a = va_arg (*args, vl_api_ip6nd_send_router_solicitation_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip6nd_send_router_solicitation_reply_t: */
    s = format(s, "vl_api_ip6nd_send_router_solicitation_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_want_ip6_ra_events_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_want_ip6_ra_events_t *a = va_arg (*args, vl_api_want_ip6_ra_events_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_want_ip6_ra_events_t: */
    s = format(s, "vl_api_want_ip6_ra_events_t:");
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    s = format(s, "\n%Upid: %u", format_white_space, indent, a->pid);
    return s;
}

static inline u8 *vl_api_want_ip6_ra_events_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_want_ip6_ra_events_reply_t *a = va_arg (*args, vl_api_want_ip6_ra_events_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_want_ip6_ra_events_reply_t: */
    s = format(s, "vl_api_want_ip6_ra_events_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ip6_ra_event_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ip6_ra_event_t *a = va_arg (*args, vl_api_ip6_ra_event_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ip6_ra_event_t: */
    s = format(s, "vl_api_ip6_ra_event_t:");
    s = format(s, "\n%Upid: %u", format_white_space, indent, a->pid);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Urouter_addr: %U", format_white_space, indent, format_vl_api_ip6_address_t, &a->router_addr, indent);
    s = format(s, "\n%Ucurrent_hop_limit: %u", format_white_space, indent, a->current_hop_limit);
    s = format(s, "\n%Uflags: %u", format_white_space, indent, a->flags);
    s = format(s, "\n%Urouter_lifetime_in_sec: %u", format_white_space, indent, a->router_lifetime_in_sec);
    s = format(s, "\n%Uneighbor_reachable_time_in_msec: %u", format_white_space, indent, a->neighbor_reachable_time_in_msec);
    s = format(s, "\n%Utime_in_msec_between_retransmitted_neighbor_solicitations: %u", format_white_space, indent, a->time_in_msec_between_retransmitted_neighbor_solicitations);
    s = format(s, "\n%Un_prefixes: %u", format_white_space, indent, a->n_prefixes);
    for (i = 0; i < a->n_prefixes; i++) {
        s = format(s, "\n%Uprefixes: %U",
                   format_white_space, indent, format_vl_api_ip6_ra_prefix_info_t, &a->prefixes[i], indent);
    }
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_ip6_nd_endianfun
#define included_ip6_nd_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_ip6nd_ra_prefix_t_endian (vl_api_ip6nd_ra_prefix_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_prefix_t_endian(&a->prefix, to_net);
    /* a->onlink_flag = a->onlink_flag (no-op) */
    /* a->autonomous_flag = a->autonomous_flag (no-op) */
    a->val_lifetime = clib_net_to_host_u32(a->val_lifetime);
    a->pref_lifetime = clib_net_to_host_u32(a->pref_lifetime);
    a->valid_lifetime_expires = clib_net_to_host_f64(a->valid_lifetime_expires);
    a->pref_lifetime_expires = clib_net_to_host_f64(a->pref_lifetime_expires);
    /* a->decrement_lifetime_flag = a->decrement_lifetime_flag (no-op) */
    /* a->no_advertise = a->no_advertise (no-op) */
}

static inline void vl_api_ip6_ra_prefix_info_t_endian (vl_api_ip6_ra_prefix_info_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_prefix_t_endian(&a->prefix, to_net);
    /* a->flags = a->flags (no-op) */
    a->valid_time = clib_net_to_host_u32(a->valid_time);
    a->preferred_time = clib_net_to_host_u32(a->preferred_time);
}

static inline void vl_api_sw_interface_ip6nd_ra_config_t_endian (vl_api_sw_interface_ip6nd_ra_config_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->suppress = a->suppress (no-op) */
    /* a->managed = a->managed (no-op) */
    /* a->other = a->other (no-op) */
    /* a->ll_option = a->ll_option (no-op) */
    /* a->send_unicast = a->send_unicast (no-op) */
    /* a->cease = a->cease (no-op) */
    /* a->is_no = a->is_no (no-op) */
    /* a->default_router = a->default_router (no-op) */
    a->max_interval = clib_net_to_host_u32(a->max_interval);
    a->min_interval = clib_net_to_host_u32(a->min_interval);
    a->lifetime = clib_net_to_host_u32(a->lifetime);
    a->initial_count = clib_net_to_host_u32(a->initial_count);
    a->initial_interval = clib_net_to_host_u32(a->initial_interval);
}

static inline void vl_api_sw_interface_ip6nd_ra_config_reply_t_endian (vl_api_sw_interface_ip6nd_ra_config_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sw_interface_ip6nd_ra_prefix_t_endian (vl_api_sw_interface_ip6nd_ra_prefix_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_prefix_t_endian(&a->prefix, to_net);
    /* a->use_default = a->use_default (no-op) */
    /* a->no_advertise = a->no_advertise (no-op) */
    /* a->off_link = a->off_link (no-op) */
    /* a->no_autoconfig = a->no_autoconfig (no-op) */
    /* a->no_onlink = a->no_onlink (no-op) */
    /* a->is_no = a->is_no (no-op) */
    a->val_lifetime = clib_net_to_host_u32(a->val_lifetime);
    a->pref_lifetime = clib_net_to_host_u32(a->pref_lifetime);
}

static inline void vl_api_sw_interface_ip6nd_ra_prefix_reply_t_endian (vl_api_sw_interface_ip6nd_ra_prefix_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sw_interface_ip6nd_ra_dump_t_endian (vl_api_sw_interface_ip6nd_ra_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_sw_interface_ip6nd_ra_details_t_endian (vl_api_sw_interface_ip6nd_ra_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->cur_hop_limit = a->cur_hop_limit (no-op) */
    /* a->adv_managed_flag = a->adv_managed_flag (no-op) */
    /* a->adv_other_flag = a->adv_other_flag (no-op) */
    a->adv_router_lifetime = clib_net_to_host_u16(a->adv_router_lifetime);
    a->adv_neighbor_reachable_time = clib_net_to_host_u32(a->adv_neighbor_reachable_time);
    a->adv_retransmit_interval = clib_net_to_host_u32(a->adv_retransmit_interval);
    a->adv_link_mtu = clib_net_to_host_u32(a->adv_link_mtu);
    /* a->send_radv = a->send_radv (no-op) */
    /* a->cease_radv = a->cease_radv (no-op) */
    /* a->send_unicast = a->send_unicast (no-op) */
    /* a->adv_link_layer_address = a->adv_link_layer_address (no-op) */
    a->max_radv_interval = clib_net_to_host_f64(a->max_radv_interval);
    a->min_radv_interval = clib_net_to_host_f64(a->min_radv_interval);
    a->last_radv_time = clib_net_to_host_f64(a->last_radv_time);
    a->last_multicast_time = clib_net_to_host_f64(a->last_multicast_time);
    a->next_multicast_time = clib_net_to_host_f64(a->next_multicast_time);
    a->initial_adverts_count = clib_net_to_host_u32(a->initial_adverts_count);
    a->initial_adverts_interval = clib_net_to_host_f64(a->initial_adverts_interval);
    /* a->initial_adverts_sent = a->initial_adverts_sent (no-op) */
    a->n_advertisements_sent = clib_net_to_host_u32(a->n_advertisements_sent);
    a->n_solicitations_rcvd = clib_net_to_host_u32(a->n_solicitations_rcvd);
    a->n_solicitations_dropped = clib_net_to_host_u32(a->n_solicitations_dropped);
    a->n_prefixes = clib_net_to_host_u32(a->n_prefixes);
    u32 count = to_net ? clib_net_to_host_u32(a->n_prefixes) : a->n_prefixes;
    for (i = 0; i < count; i++) {
        vl_api_ip6nd_ra_prefix_t_endian(&a->prefixes[i], to_net);
    }
}

static inline void vl_api_ip6nd_proxy_enable_disable_t_endian (vl_api_ip6nd_proxy_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->is_enable = a->is_enable (no-op) */
}

static inline void vl_api_ip6nd_proxy_enable_disable_reply_t_endian (vl_api_ip6nd_proxy_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ip6nd_proxy_add_del_t_endian (vl_api_ip6nd_proxy_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->is_add = a->is_add (no-op) */
    vl_api_ip6_address_t_endian(&a->ip, to_net);
}

static inline void vl_api_ip6nd_proxy_add_del_reply_t_endian (vl_api_ip6nd_proxy_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ip6nd_proxy_details_t_endian (vl_api_ip6nd_proxy_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_ip6_address_t_endian(&a->ip, to_net);
}

static inline void vl_api_ip6nd_proxy_dump_t_endian (vl_api_ip6nd_proxy_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_ip6nd_send_router_solicitation_t_endian (vl_api_ip6nd_send_router_solicitation_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->irt = clib_net_to_host_u32(a->irt);
    a->mrt = clib_net_to_host_u32(a->mrt);
    a->mrc = clib_net_to_host_u32(a->mrc);
    a->mrd = clib_net_to_host_u32(a->mrd);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->stop = a->stop (no-op) */
}

static inline void vl_api_ip6nd_send_router_solicitation_reply_t_endian (vl_api_ip6nd_send_router_solicitation_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_want_ip6_ra_events_t_endian (vl_api_want_ip6_ra_events_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->enable = a->enable (no-op) */
    a->pid = clib_net_to_host_u32(a->pid);
}

static inline void vl_api_want_ip6_ra_events_reply_t_endian (vl_api_want_ip6_ra_events_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ip6_ra_event_t_endian (vl_api_ip6_ra_event_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->pid = clib_net_to_host_u32(a->pid);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_ip6_address_t_endian(&a->router_addr, to_net);
    /* a->current_hop_limit = a->current_hop_limit (no-op) */
    /* a->flags = a->flags (no-op) */
    a->router_lifetime_in_sec = clib_net_to_host_u16(a->router_lifetime_in_sec);
    a->neighbor_reachable_time_in_msec = clib_net_to_host_u32(a->neighbor_reachable_time_in_msec);
    a->time_in_msec_between_retransmitted_neighbor_solicitations = clib_net_to_host_u32(a->time_in_msec_between_retransmitted_neighbor_solicitations);
    a->n_prefixes = clib_net_to_host_u32(a->n_prefixes);
    u32 count = to_net ? clib_net_to_host_u32(a->n_prefixes) : a->n_prefixes;
    for (i = 0; i < count; i++) {
        vl_api_ip6_ra_prefix_info_t_endian(&a->prefixes[i], to_net);
    }
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_ip6_nd_calcsizefun
#define included_ip6_nd_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_ip6nd_ra_prefix_t_calc_size (vl_api_ip6nd_ra_prefix_t *a)
{
      return sizeof(*a) - sizeof(a->prefix) + vl_api_prefix_t_calc_size(&a->prefix);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip6_ra_prefix_info_t_calc_size (vl_api_ip6_ra_prefix_info_t *a)
{
      return sizeof(*a) - sizeof(a->prefix) + vl_api_prefix_t_calc_size(&a->prefix);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_ip6nd_ra_config_t_calc_size (vl_api_sw_interface_ip6nd_ra_config_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_ip6nd_ra_config_reply_t_calc_size (vl_api_sw_interface_ip6nd_ra_config_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_ip6nd_ra_prefix_t_calc_size (vl_api_sw_interface_ip6nd_ra_prefix_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->prefix) + vl_api_prefix_t_calc_size(&a->prefix);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_ip6nd_ra_prefix_reply_t_calc_size (vl_api_sw_interface_ip6nd_ra_prefix_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_ip6nd_ra_dump_t_calc_size (vl_api_sw_interface_ip6nd_ra_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_ip6nd_ra_details_t_calc_size (vl_api_sw_interface_ip6nd_ra_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) + clib_net_to_host_u32(a->n_prefixes) * sizeof(a->prefixes[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip6nd_proxy_enable_disable_t_calc_size (vl_api_ip6nd_proxy_enable_disable_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip6nd_proxy_enable_disable_reply_t_calc_size (vl_api_ip6nd_proxy_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip6nd_proxy_add_del_t_calc_size (vl_api_ip6nd_proxy_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->ip) + vl_api_ip6_address_t_calc_size(&a->ip);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip6nd_proxy_add_del_reply_t_calc_size (vl_api_ip6nd_proxy_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip6nd_proxy_details_t_calc_size (vl_api_ip6nd_proxy_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->ip) + vl_api_ip6_address_t_calc_size(&a->ip);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip6nd_proxy_dump_t_calc_size (vl_api_ip6nd_proxy_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip6nd_send_router_solicitation_t_calc_size (vl_api_ip6nd_send_router_solicitation_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip6nd_send_router_solicitation_reply_t_calc_size (vl_api_ip6nd_send_router_solicitation_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_want_ip6_ra_events_t_calc_size (vl_api_want_ip6_ra_events_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_want_ip6_ra_events_reply_t_calc_size (vl_api_want_ip6_ra_events_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ip6_ra_event_t_calc_size (vl_api_ip6_ra_event_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->router_addr) + vl_api_ip6_address_t_calc_size(&a->router_addr) + clib_net_to_host_u32(a->n_prefixes) * sizeof(a->prefixes[0]);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(ip6_nd.api, 1, 1, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(ip6_nd.api, 0xdeae73c7)

#endif

