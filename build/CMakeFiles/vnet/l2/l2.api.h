/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: l2.api
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
#warning no content included from l2.api
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
vl_msg_id(VL_API_L2_XCONNECT_DETAILS, vl_api_l2_xconnect_details_t_handler)
vl_msg_id(VL_API_L2_XCONNECT_DUMP, vl_api_l2_xconnect_dump_t_handler)
vl_msg_id(VL_API_L2_FIB_TABLE_DETAILS, vl_api_l2_fib_table_details_t_handler)
vl_msg_id(VL_API_L2_FIB_TABLE_DUMP, vl_api_l2_fib_table_dump_t_handler)
vl_msg_id(VL_API_L2_FIB_CLEAR_TABLE, vl_api_l2_fib_clear_table_t_handler)
vl_msg_id(VL_API_L2_FIB_CLEAR_TABLE_REPLY, vl_api_l2_fib_clear_table_reply_t_handler)
vl_msg_id(VL_API_L2FIB_FLUSH_ALL, vl_api_l2fib_flush_all_t_handler)
vl_msg_id(VL_API_L2FIB_FLUSH_ALL_REPLY, vl_api_l2fib_flush_all_reply_t_handler)
vl_msg_id(VL_API_L2FIB_FLUSH_BD, vl_api_l2fib_flush_bd_t_handler)
vl_msg_id(VL_API_L2FIB_FLUSH_BD_REPLY, vl_api_l2fib_flush_bd_reply_t_handler)
vl_msg_id(VL_API_L2FIB_FLUSH_INT, vl_api_l2fib_flush_int_t_handler)
vl_msg_id(VL_API_L2FIB_FLUSH_INT_REPLY, vl_api_l2fib_flush_int_reply_t_handler)
vl_msg_id(VL_API_L2FIB_ADD_DEL, vl_api_l2fib_add_del_t_handler)
vl_msg_id(VL_API_L2FIB_ADD_DEL_REPLY, vl_api_l2fib_add_del_reply_t_handler)
vl_msg_id(VL_API_WANT_L2_MACS_EVENTS, vl_api_want_l2_macs_events_t_handler)
vl_msg_id(VL_API_WANT_L2_MACS_EVENTS_REPLY, vl_api_want_l2_macs_events_reply_t_handler)
vl_msg_id(VL_API_WANT_L2_MACS_EVENTS2, vl_api_want_l2_macs_events2_t_handler)
vl_msg_id(VL_API_WANT_L2_MACS_EVENTS2_REPLY, vl_api_want_l2_macs_events2_reply_t_handler)
vl_msg_id(VL_API_L2FIB_SET_SCAN_DELAY, vl_api_l2fib_set_scan_delay_t_handler)
vl_msg_id(VL_API_L2FIB_SET_SCAN_DELAY_REPLY, vl_api_l2fib_set_scan_delay_reply_t_handler)
vl_msg_id(VL_API_L2_MACS_EVENT, vl_api_l2_macs_event_t_handler)
vl_msg_id(VL_API_L2_FLAGS, vl_api_l2_flags_t_handler)
vl_msg_id(VL_API_L2_FLAGS_REPLY, vl_api_l2_flags_reply_t_handler)
vl_msg_id(VL_API_BRIDGE_DOMAIN_SET_MAC_AGE, vl_api_bridge_domain_set_mac_age_t_handler)
vl_msg_id(VL_API_BRIDGE_DOMAIN_SET_MAC_AGE_REPLY, vl_api_bridge_domain_set_mac_age_reply_t_handler)
vl_msg_id(VL_API_BRIDGE_DOMAIN_SET_DEFAULT_LEARN_LIMIT, vl_api_bridge_domain_set_default_learn_limit_t_handler)
vl_msg_id(VL_API_BRIDGE_DOMAIN_SET_DEFAULT_LEARN_LIMIT_REPLY, vl_api_bridge_domain_set_default_learn_limit_reply_t_handler)
vl_msg_id(VL_API_BRIDGE_DOMAIN_SET_LEARN_LIMIT, vl_api_bridge_domain_set_learn_limit_t_handler)
vl_msg_id(VL_API_BRIDGE_DOMAIN_SET_LEARN_LIMIT_REPLY, vl_api_bridge_domain_set_learn_limit_reply_t_handler)
vl_msg_id(VL_API_BRIDGE_DOMAIN_ADD_DEL, vl_api_bridge_domain_add_del_t_handler)
vl_msg_id(VL_API_BRIDGE_DOMAIN_ADD_DEL_REPLY, vl_api_bridge_domain_add_del_reply_t_handler)
vl_msg_id(VL_API_BRIDGE_DOMAIN_ADD_DEL_V2, vl_api_bridge_domain_add_del_v2_t_handler)
vl_msg_id(VL_API_BRIDGE_DOMAIN_ADD_DEL_V2_REPLY, vl_api_bridge_domain_add_del_v2_reply_t_handler)
vl_msg_id(VL_API_BRIDGE_DOMAIN_DUMP, vl_api_bridge_domain_dump_t_handler)
vl_msg_id(VL_API_BRIDGE_DOMAIN_DETAILS, vl_api_bridge_domain_details_t_handler)
vl_msg_id(VL_API_BRIDGE_FLAGS, vl_api_bridge_flags_t_handler)
vl_msg_id(VL_API_BRIDGE_FLAGS_REPLY, vl_api_bridge_flags_reply_t_handler)
vl_msg_id(VL_API_L2_INTERFACE_VLAN_TAG_REWRITE, vl_api_l2_interface_vlan_tag_rewrite_t_handler)
vl_msg_id(VL_API_L2_INTERFACE_VLAN_TAG_REWRITE_REPLY, vl_api_l2_interface_vlan_tag_rewrite_reply_t_handler)
vl_msg_id(VL_API_L2_INTERFACE_PBB_TAG_REWRITE, vl_api_l2_interface_pbb_tag_rewrite_t_handler)
vl_msg_id(VL_API_L2_INTERFACE_PBB_TAG_REWRITE_REPLY, vl_api_l2_interface_pbb_tag_rewrite_reply_t_handler)
vl_msg_id(VL_API_L2_PATCH_ADD_DEL, vl_api_l2_patch_add_del_t_handler)
vl_msg_id(VL_API_L2_PATCH_ADD_DEL_REPLY, vl_api_l2_patch_add_del_reply_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_SET_L2_XCONNECT, vl_api_sw_interface_set_l2_xconnect_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_SET_L2_XCONNECT_REPLY, vl_api_sw_interface_set_l2_xconnect_reply_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_SET_L2_BRIDGE, vl_api_sw_interface_set_l2_bridge_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_SET_L2_BRIDGE_REPLY, vl_api_sw_interface_set_l2_bridge_reply_t_handler)
vl_msg_id(VL_API_BD_IP_MAC_ADD_DEL, vl_api_bd_ip_mac_add_del_t_handler)
vl_msg_id(VL_API_BD_IP_MAC_ADD_DEL_REPLY, vl_api_bd_ip_mac_add_del_reply_t_handler)
vl_msg_id(VL_API_BD_IP_MAC_FLUSH, vl_api_bd_ip_mac_flush_t_handler)
vl_msg_id(VL_API_BD_IP_MAC_FLUSH_REPLY, vl_api_bd_ip_mac_flush_reply_t_handler)
vl_msg_id(VL_API_BD_IP_MAC_DETAILS, vl_api_bd_ip_mac_details_t_handler)
vl_msg_id(VL_API_BD_IP_MAC_DUMP, vl_api_bd_ip_mac_dump_t_handler)
vl_msg_id(VL_API_L2_INTERFACE_EFP_FILTER, vl_api_l2_interface_efp_filter_t_handler)
vl_msg_id(VL_API_L2_INTERFACE_EFP_FILTER_REPLY, vl_api_l2_interface_efp_filter_reply_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_SET_VPATH, vl_api_sw_interface_set_vpath_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_SET_VPATH_REPLY, vl_api_sw_interface_set_vpath_reply_t_handler)
vl_msg_id(VL_API_BVI_CREATE, vl_api_bvi_create_t_handler)
vl_msg_id(VL_API_BVI_CREATE_REPLY, vl_api_bvi_create_reply_t_handler)
vl_msg_id(VL_API_BVI_DELETE, vl_api_bvi_delete_t_handler)
vl_msg_id(VL_API_BVI_DELETE_REPLY, vl_api_bvi_delete_reply_t_handler)
vl_msg_id(VL_API_WANT_L2_ARP_TERM_EVENTS, vl_api_want_l2_arp_term_events_t_handler)
vl_msg_id(VL_API_WANT_L2_ARP_TERM_EVENTS_REPLY, vl_api_want_l2_arp_term_events_reply_t_handler)
vl_msg_id(VL_API_L2_ARP_TERM_EVENT, vl_api_l2_arp_term_event_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_l2_xconnect_details_t, 1)
vl_msg_name(vl_api_l2_xconnect_dump_t, 1)
vl_msg_name(vl_api_l2_fib_table_details_t, 1)
vl_msg_name(vl_api_l2_fib_table_dump_t, 1)
vl_msg_name(vl_api_l2_fib_clear_table_t, 1)
vl_msg_name(vl_api_l2_fib_clear_table_reply_t, 1)
vl_msg_name(vl_api_l2fib_flush_all_t, 1)
vl_msg_name(vl_api_l2fib_flush_all_reply_t, 1)
vl_msg_name(vl_api_l2fib_flush_bd_t, 1)
vl_msg_name(vl_api_l2fib_flush_bd_reply_t, 1)
vl_msg_name(vl_api_l2fib_flush_int_t, 1)
vl_msg_name(vl_api_l2fib_flush_int_reply_t, 1)
vl_msg_name(vl_api_l2fib_add_del_t, 1)
vl_msg_name(vl_api_l2fib_add_del_reply_t, 1)
vl_msg_name(vl_api_want_l2_macs_events_t, 1)
vl_msg_name(vl_api_want_l2_macs_events_reply_t, 1)
vl_msg_name(vl_api_want_l2_macs_events2_t, 1)
vl_msg_name(vl_api_want_l2_macs_events2_reply_t, 1)
vl_msg_name(vl_api_l2fib_set_scan_delay_t, 1)
vl_msg_name(vl_api_l2fib_set_scan_delay_reply_t, 1)
vl_msg_name(vl_api_l2_macs_event_t, 1)
vl_msg_name(vl_api_l2_flags_t, 1)
vl_msg_name(vl_api_l2_flags_reply_t, 1)
vl_msg_name(vl_api_bridge_domain_set_mac_age_t, 1)
vl_msg_name(vl_api_bridge_domain_set_mac_age_reply_t, 1)
vl_msg_name(vl_api_bridge_domain_set_default_learn_limit_t, 1)
vl_msg_name(vl_api_bridge_domain_set_default_learn_limit_reply_t, 1)
vl_msg_name(vl_api_bridge_domain_set_learn_limit_t, 1)
vl_msg_name(vl_api_bridge_domain_set_learn_limit_reply_t, 1)
vl_msg_name(vl_api_bridge_domain_add_del_t, 1)
vl_msg_name(vl_api_bridge_domain_add_del_reply_t, 1)
vl_msg_name(vl_api_bridge_domain_add_del_v2_t, 1)
vl_msg_name(vl_api_bridge_domain_add_del_v2_reply_t, 1)
vl_msg_name(vl_api_bridge_domain_dump_t, 1)
vl_msg_name(vl_api_bridge_domain_details_t, 1)
vl_msg_name(vl_api_bridge_flags_t, 1)
vl_msg_name(vl_api_bridge_flags_reply_t, 1)
vl_msg_name(vl_api_l2_interface_vlan_tag_rewrite_t, 1)
vl_msg_name(vl_api_l2_interface_vlan_tag_rewrite_reply_t, 1)
vl_msg_name(vl_api_l2_interface_pbb_tag_rewrite_t, 1)
vl_msg_name(vl_api_l2_interface_pbb_tag_rewrite_reply_t, 1)
vl_msg_name(vl_api_l2_patch_add_del_t, 1)
vl_msg_name(vl_api_l2_patch_add_del_reply_t, 1)
vl_msg_name(vl_api_sw_interface_set_l2_xconnect_t, 1)
vl_msg_name(vl_api_sw_interface_set_l2_xconnect_reply_t, 1)
vl_msg_name(vl_api_sw_interface_set_l2_bridge_t, 1)
vl_msg_name(vl_api_sw_interface_set_l2_bridge_reply_t, 1)
vl_msg_name(vl_api_bd_ip_mac_add_del_t, 1)
vl_msg_name(vl_api_bd_ip_mac_add_del_reply_t, 1)
vl_msg_name(vl_api_bd_ip_mac_flush_t, 1)
vl_msg_name(vl_api_bd_ip_mac_flush_reply_t, 1)
vl_msg_name(vl_api_bd_ip_mac_details_t, 1)
vl_msg_name(vl_api_bd_ip_mac_dump_t, 1)
vl_msg_name(vl_api_l2_interface_efp_filter_t, 1)
vl_msg_name(vl_api_l2_interface_efp_filter_reply_t, 1)
vl_msg_name(vl_api_sw_interface_set_vpath_t, 1)
vl_msg_name(vl_api_sw_interface_set_vpath_reply_t, 1)
vl_msg_name(vl_api_bvi_create_t, 1)
vl_msg_name(vl_api_bvi_create_reply_t, 1)
vl_msg_name(vl_api_bvi_delete_t, 1)
vl_msg_name(vl_api_bvi_delete_reply_t, 1)
vl_msg_name(vl_api_want_l2_arp_term_events_t, 1)
vl_msg_name(vl_api_want_l2_arp_term_events_reply_t, 1)
vl_msg_name(vl_api_l2_arp_term_event_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_l2 \
_(VL_API_L2_XCONNECT_DETAILS, l2_xconnect_details, 472b6b67) \
_(VL_API_L2_XCONNECT_DUMP, l2_xconnect_dump, 51077d14) \
_(VL_API_L2_FIB_TABLE_DETAILS, l2_fib_table_details, a44ef6b8) \
_(VL_API_L2_FIB_TABLE_DUMP, l2_fib_table_dump, c25fdce6) \
_(VL_API_L2_FIB_CLEAR_TABLE, l2_fib_clear_table, 51077d14) \
_(VL_API_L2_FIB_CLEAR_TABLE_REPLY, l2_fib_clear_table_reply, e8d4e804) \
_(VL_API_L2FIB_FLUSH_ALL, l2fib_flush_all, 51077d14) \
_(VL_API_L2FIB_FLUSH_ALL_REPLY, l2fib_flush_all_reply, e8d4e804) \
_(VL_API_L2FIB_FLUSH_BD, l2fib_flush_bd, c25fdce6) \
_(VL_API_L2FIB_FLUSH_BD_REPLY, l2fib_flush_bd_reply, e8d4e804) \
_(VL_API_L2FIB_FLUSH_INT, l2fib_flush_int, f9e6675e) \
_(VL_API_L2FIB_FLUSH_INT_REPLY, l2fib_flush_int_reply, e8d4e804) \
_(VL_API_L2FIB_ADD_DEL, l2fib_add_del, eddda487) \
_(VL_API_L2FIB_ADD_DEL_REPLY, l2fib_add_del_reply, e8d4e804) \
_(VL_API_WANT_L2_MACS_EVENTS, want_l2_macs_events, 9aabdfde) \
_(VL_API_WANT_L2_MACS_EVENTS_REPLY, want_l2_macs_events_reply, e8d4e804) \
_(VL_API_WANT_L2_MACS_EVENTS2, want_l2_macs_events2, cc1377b0) \
_(VL_API_WANT_L2_MACS_EVENTS2_REPLY, want_l2_macs_events2_reply, e8d4e804) \
_(VL_API_L2FIB_SET_SCAN_DELAY, l2fib_set_scan_delay, a3b968a4) \
_(VL_API_L2FIB_SET_SCAN_DELAY_REPLY, l2fib_set_scan_delay_reply, e8d4e804) \
_(VL_API_L2_MACS_EVENT, l2_macs_event, 44b8fd64) \
_(VL_API_L2_FLAGS, l2_flags, fc41cfe8) \
_(VL_API_L2_FLAGS_REPLY, l2_flags_reply, 29b2a2b3) \
_(VL_API_BRIDGE_DOMAIN_SET_MAC_AGE, bridge_domain_set_mac_age, b537ad7b) \
_(VL_API_BRIDGE_DOMAIN_SET_MAC_AGE_REPLY, bridge_domain_set_mac_age_reply, e8d4e804) \
_(VL_API_BRIDGE_DOMAIN_SET_DEFAULT_LEARN_LIMIT, bridge_domain_set_default_learn_limit, f097ffce) \
_(VL_API_BRIDGE_DOMAIN_SET_DEFAULT_LEARN_LIMIT_REPLY, bridge_domain_set_default_learn_limit_reply, e8d4e804) \
_(VL_API_BRIDGE_DOMAIN_SET_LEARN_LIMIT, bridge_domain_set_learn_limit, 89c52b5f) \
_(VL_API_BRIDGE_DOMAIN_SET_LEARN_LIMIT_REPLY, bridge_domain_set_learn_limit_reply, e8d4e804) \
_(VL_API_BRIDGE_DOMAIN_ADD_DEL, bridge_domain_add_del, 600b7170) \
_(VL_API_BRIDGE_DOMAIN_ADD_DEL_REPLY, bridge_domain_add_del_reply, e8d4e804) \
_(VL_API_BRIDGE_DOMAIN_ADD_DEL_V2, bridge_domain_add_del_v2, 600b7170) \
_(VL_API_BRIDGE_DOMAIN_ADD_DEL_V2_REPLY, bridge_domain_add_del_v2_reply, fcb1e980) \
_(VL_API_BRIDGE_DOMAIN_DUMP, bridge_domain_dump, 74396a43) \
_(VL_API_BRIDGE_DOMAIN_DETAILS, bridge_domain_details, 0fa506fd) \
_(VL_API_BRIDGE_FLAGS, bridge_flags, 1b0c5fbd) \
_(VL_API_BRIDGE_FLAGS_REPLY, bridge_flags_reply, 29b2a2b3) \
_(VL_API_L2_INTERFACE_VLAN_TAG_REWRITE, l2_interface_vlan_tag_rewrite, 62cc0bbc) \
_(VL_API_L2_INTERFACE_VLAN_TAG_REWRITE_REPLY, l2_interface_vlan_tag_rewrite_reply, e8d4e804) \
_(VL_API_L2_INTERFACE_PBB_TAG_REWRITE, l2_interface_pbb_tag_rewrite, 38e802a8) \
_(VL_API_L2_INTERFACE_PBB_TAG_REWRITE_REPLY, l2_interface_pbb_tag_rewrite_reply, e8d4e804) \
_(VL_API_L2_PATCH_ADD_DEL, l2_patch_add_del, a1f6a6f3) \
_(VL_API_L2_PATCH_ADD_DEL_REPLY, l2_patch_add_del_reply, e8d4e804) \
_(VL_API_SW_INTERFACE_SET_L2_XCONNECT, sw_interface_set_l2_xconnect, 4fa28a85) \
_(VL_API_SW_INTERFACE_SET_L2_XCONNECT_REPLY, sw_interface_set_l2_xconnect_reply, e8d4e804) \
_(VL_API_SW_INTERFACE_SET_L2_BRIDGE, sw_interface_set_l2_bridge, d0678b13) \
_(VL_API_SW_INTERFACE_SET_L2_BRIDGE_REPLY, sw_interface_set_l2_bridge_reply, e8d4e804) \
_(VL_API_BD_IP_MAC_ADD_DEL, bd_ip_mac_add_del, 0257c869) \
_(VL_API_BD_IP_MAC_ADD_DEL_REPLY, bd_ip_mac_add_del_reply, e8d4e804) \
_(VL_API_BD_IP_MAC_FLUSH, bd_ip_mac_flush, c25fdce6) \
_(VL_API_BD_IP_MAC_FLUSH_REPLY, bd_ip_mac_flush_reply, e8d4e804) \
_(VL_API_BD_IP_MAC_DETAILS, bd_ip_mac_details, 545af86a) \
_(VL_API_BD_IP_MAC_DUMP, bd_ip_mac_dump, c25fdce6) \
_(VL_API_L2_INTERFACE_EFP_FILTER, l2_interface_efp_filter, 5501adee) \
_(VL_API_L2_INTERFACE_EFP_FILTER_REPLY, l2_interface_efp_filter_reply, e8d4e804) \
_(VL_API_SW_INTERFACE_SET_VPATH, sw_interface_set_vpath, ae6cfcfb) \
_(VL_API_SW_INTERFACE_SET_VPATH_REPLY, sw_interface_set_vpath_reply, e8d4e804) \
_(VL_API_BVI_CREATE, bvi_create, f5398559) \
_(VL_API_BVI_CREATE_REPLY, bvi_create_reply, 5383d31f) \
_(VL_API_BVI_DELETE, bvi_delete, f9e6675e) \
_(VL_API_BVI_DELETE_REPLY, bvi_delete_reply, e8d4e804) \
_(VL_API_WANT_L2_ARP_TERM_EVENTS, want_l2_arp_term_events, 3ec6d6c2) \
_(VL_API_WANT_L2_ARP_TERM_EVENTS_REPLY, want_l2_arp_term_events_reply, e8d4e804) \
_(VL_API_L2_ARP_TERM_EVENT, l2_arp_term_event, 6963e07a) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "l2.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_l2_printfun_types
#define included_l2_printfun_types

static inline u8 *format_vl_api_mac_event_action_t (u8 *s, va_list * args)
{
    vl_api_mac_event_action_t *a = va_arg (*args, vl_api_mac_event_action_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "MAC_EVENT_ACTION_API_ADD");
    case 1:
        return format(s, "MAC_EVENT_ACTION_API_DELETE");
    case 2:
        return format(s, "MAC_EVENT_ACTION_API_MOVE");
    }
    return s;
}

static inline u8 *format_vl_api_mac_entry_t (u8 *s, va_list * args)
{
    vl_api_mac_entry_t *a = va_arg (*args, vl_api_mac_entry_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Umac_addr: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->mac_addr, indent);
    s = format(s, "\n%Uaction: %U", format_white_space, indent, format_vl_api_mac_event_action_t, &a->action, indent);
    s = format(s, "\n%Uflags: %u", format_white_space, indent, a->flags);
    return s;
}

static inline u8 *format_vl_api_bridge_domain_sw_if_t (u8 *s, va_list * args)
{
    vl_api_bridge_domain_sw_if_t *a = va_arg (*args, vl_api_bridge_domain_sw_if_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Ushg: %u", format_white_space, indent, a->shg);
    return s;
}

static inline u8 *format_vl_api_bd_flags_t (u8 *s, va_list * args)
{
    vl_api_bd_flags_t *a = va_arg (*args, vl_api_bd_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "BRIDGE_API_FLAG_NONE");
    case 1:
        return format(s, "BRIDGE_API_FLAG_LEARN");
    case 2:
        return format(s, "BRIDGE_API_FLAG_FWD");
    case 4:
        return format(s, "BRIDGE_API_FLAG_FLOOD");
    case 8:
        return format(s, "BRIDGE_API_FLAG_UU_FLOOD");
    case 16:
        return format(s, "BRIDGE_API_FLAG_ARP_TERM");
    case 32:
        return format(s, "BRIDGE_API_FLAG_ARP_UFWD");
    }
    return s;
}

static inline u8 *format_vl_api_l2_port_type_t (u8 *s, va_list * args)
{
    vl_api_l2_port_type_t *a = va_arg (*args, vl_api_l2_port_type_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "L2_API_PORT_TYPE_NORMAL");
    case 1:
        return format(s, "L2_API_PORT_TYPE_BVI");
    case 2:
        return format(s, "L2_API_PORT_TYPE_UU_FWD");
    }
    return s;
}

static inline u8 *format_vl_api_bd_ip_mac_t (u8 *s, va_list * args)
{
    vl_api_bd_ip_mac_t *a = va_arg (*args, vl_api_bd_ip_mac_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ubd_id: %u", format_white_space, indent, a->bd_id);
    s = format(s, "\n%Uip: %U", format_white_space, indent, format_vl_api_address_t, &a->ip, indent);
    s = format(s, "\n%Umac: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->mac, indent);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_l2_printfun
#define included_l2_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "l2.api_tojson.h"
#include "l2.api_fromjson.h"

static inline u8 *vl_api_l2_xconnect_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2_xconnect_details_t *a = va_arg (*args, vl_api_l2_xconnect_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2_xconnect_details_t: */
    s = format(s, "vl_api_l2_xconnect_details_t:");
    s = format(s, "\n%Urx_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->rx_sw_if_index, indent);
    s = format(s, "\n%Utx_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->tx_sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_l2_xconnect_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2_xconnect_dump_t *a = va_arg (*args, vl_api_l2_xconnect_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2_xconnect_dump_t: */
    s = format(s, "vl_api_l2_xconnect_dump_t:");
    return s;
}

static inline u8 *vl_api_l2_fib_table_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2_fib_table_details_t *a = va_arg (*args, vl_api_l2_fib_table_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2_fib_table_details_t: */
    s = format(s, "vl_api_l2_fib_table_details_t:");
    s = format(s, "\n%Ubd_id: %u", format_white_space, indent, a->bd_id);
    s = format(s, "\n%Umac: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->mac, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Ustatic_mac: %u", format_white_space, indent, a->static_mac);
    s = format(s, "\n%Ufilter_mac: %u", format_white_space, indent, a->filter_mac);
    s = format(s, "\n%Ubvi_mac: %u", format_white_space, indent, a->bvi_mac);
    return s;
}

static inline u8 *vl_api_l2_fib_table_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2_fib_table_dump_t *a = va_arg (*args, vl_api_l2_fib_table_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2_fib_table_dump_t: */
    s = format(s, "vl_api_l2_fib_table_dump_t:");
    s = format(s, "\n%Ubd_id: %u", format_white_space, indent, a->bd_id);
    return s;
}

static inline u8 *vl_api_l2_fib_clear_table_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2_fib_clear_table_t *a = va_arg (*args, vl_api_l2_fib_clear_table_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2_fib_clear_table_t: */
    s = format(s, "vl_api_l2_fib_clear_table_t:");
    return s;
}

static inline u8 *vl_api_l2_fib_clear_table_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2_fib_clear_table_reply_t *a = va_arg (*args, vl_api_l2_fib_clear_table_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2_fib_clear_table_reply_t: */
    s = format(s, "vl_api_l2_fib_clear_table_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_l2fib_flush_all_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2fib_flush_all_t *a = va_arg (*args, vl_api_l2fib_flush_all_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2fib_flush_all_t: */
    s = format(s, "vl_api_l2fib_flush_all_t:");
    return s;
}

static inline u8 *vl_api_l2fib_flush_all_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2fib_flush_all_reply_t *a = va_arg (*args, vl_api_l2fib_flush_all_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2fib_flush_all_reply_t: */
    s = format(s, "vl_api_l2fib_flush_all_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_l2fib_flush_bd_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2fib_flush_bd_t *a = va_arg (*args, vl_api_l2fib_flush_bd_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2fib_flush_bd_t: */
    s = format(s, "vl_api_l2fib_flush_bd_t:");
    s = format(s, "\n%Ubd_id: %u", format_white_space, indent, a->bd_id);
    return s;
}

static inline u8 *vl_api_l2fib_flush_bd_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2fib_flush_bd_reply_t *a = va_arg (*args, vl_api_l2fib_flush_bd_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2fib_flush_bd_reply_t: */
    s = format(s, "vl_api_l2fib_flush_bd_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_l2fib_flush_int_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2fib_flush_int_t *a = va_arg (*args, vl_api_l2fib_flush_int_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2fib_flush_int_t: */
    s = format(s, "vl_api_l2fib_flush_int_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_l2fib_flush_int_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2fib_flush_int_reply_t *a = va_arg (*args, vl_api_l2fib_flush_int_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2fib_flush_int_reply_t: */
    s = format(s, "vl_api_l2fib_flush_int_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_l2fib_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2fib_add_del_t *a = va_arg (*args, vl_api_l2fib_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2fib_add_del_t: */
    s = format(s, "vl_api_l2fib_add_del_t:");
    s = format(s, "\n%Umac: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->mac, indent);
    s = format(s, "\n%Ubd_id: %u", format_white_space, indent, a->bd_id);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Ustatic_mac: %u", format_white_space, indent, a->static_mac);
    s = format(s, "\n%Ufilter_mac: %u", format_white_space, indent, a->filter_mac);
    s = format(s, "\n%Ubvi_mac: %u", format_white_space, indent, a->bvi_mac);
    return s;
}

static inline u8 *vl_api_l2fib_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2fib_add_del_reply_t *a = va_arg (*args, vl_api_l2fib_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2fib_add_del_reply_t: */
    s = format(s, "vl_api_l2fib_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_want_l2_macs_events_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_want_l2_macs_events_t *a = va_arg (*args, vl_api_want_l2_macs_events_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_want_l2_macs_events_t: */
    s = format(s, "vl_api_want_l2_macs_events_t:");
    s = format(s, "\n%Ulearn_limit: %u", format_white_space, indent, a->learn_limit);
    s = format(s, "\n%Uscan_delay: %u", format_white_space, indent, a->scan_delay);
    s = format(s, "\n%Umax_macs_in_event: %u", format_white_space, indent, a->max_macs_in_event);
    s = format(s, "\n%Uenable_disable: %u", format_white_space, indent, a->enable_disable);
    s = format(s, "\n%Upid: %u", format_white_space, indent, a->pid);
    return s;
}

static inline u8 *vl_api_want_l2_macs_events_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_want_l2_macs_events_reply_t *a = va_arg (*args, vl_api_want_l2_macs_events_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_want_l2_macs_events_reply_t: */
    s = format(s, "vl_api_want_l2_macs_events_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_want_l2_macs_events2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_want_l2_macs_events2_t *a = va_arg (*args, vl_api_want_l2_macs_events2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_want_l2_macs_events2_t: */
    s = format(s, "vl_api_want_l2_macs_events2_t:");
    s = format(s, "\n%Umax_macs_in_event: %u", format_white_space, indent, a->max_macs_in_event);
    s = format(s, "\n%Uenable_disable: %u", format_white_space, indent, a->enable_disable);
    s = format(s, "\n%Upid: %u", format_white_space, indent, a->pid);
    return s;
}

static inline u8 *vl_api_want_l2_macs_events2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_want_l2_macs_events2_reply_t *a = va_arg (*args, vl_api_want_l2_macs_events2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_want_l2_macs_events2_reply_t: */
    s = format(s, "vl_api_want_l2_macs_events2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_l2fib_set_scan_delay_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2fib_set_scan_delay_t *a = va_arg (*args, vl_api_l2fib_set_scan_delay_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2fib_set_scan_delay_t: */
    s = format(s, "vl_api_l2fib_set_scan_delay_t:");
    s = format(s, "\n%Uscan_delay: %u", format_white_space, indent, a->scan_delay);
    return s;
}

static inline u8 *vl_api_l2fib_set_scan_delay_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2fib_set_scan_delay_reply_t *a = va_arg (*args, vl_api_l2fib_set_scan_delay_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2fib_set_scan_delay_reply_t: */
    s = format(s, "vl_api_l2fib_set_scan_delay_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_l2_macs_event_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2_macs_event_t *a = va_arg (*args, vl_api_l2_macs_event_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2_macs_event_t: */
    s = format(s, "vl_api_l2_macs_event_t:");
    s = format(s, "\n%Upid: %u", format_white_space, indent, a->pid);
    s = format(s, "\n%Un_macs: %u", format_white_space, indent, a->n_macs);
    for (i = 0; i < a->n_macs; i++) {
        s = format(s, "\n%Umac: %U",
                   format_white_space, indent, format_vl_api_mac_entry_t, &a->mac[i], indent);
    }
    return s;
}

static inline u8 *vl_api_l2_flags_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2_flags_t *a = va_arg (*args, vl_api_l2_flags_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2_flags_t: */
    s = format(s, "vl_api_l2_flags_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uis_set: %u", format_white_space, indent, a->is_set);
    s = format(s, "\n%Ufeature_bitmap: %u", format_white_space, indent, a->feature_bitmap);
    return s;
}

static inline u8 *vl_api_l2_flags_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2_flags_reply_t *a = va_arg (*args, vl_api_l2_flags_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2_flags_reply_t: */
    s = format(s, "vl_api_l2_flags_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uresulting_feature_bitmap: %u", format_white_space, indent, a->resulting_feature_bitmap);
    return s;
}

static inline u8 *vl_api_bridge_domain_set_mac_age_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bridge_domain_set_mac_age_t *a = va_arg (*args, vl_api_bridge_domain_set_mac_age_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bridge_domain_set_mac_age_t: */
    s = format(s, "vl_api_bridge_domain_set_mac_age_t:");
    s = format(s, "\n%Ubd_id: %u", format_white_space, indent, a->bd_id);
    s = format(s, "\n%Umac_age: %u", format_white_space, indent, a->mac_age);
    return s;
}

static inline u8 *vl_api_bridge_domain_set_mac_age_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bridge_domain_set_mac_age_reply_t *a = va_arg (*args, vl_api_bridge_domain_set_mac_age_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bridge_domain_set_mac_age_reply_t: */
    s = format(s, "vl_api_bridge_domain_set_mac_age_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_bridge_domain_set_default_learn_limit_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bridge_domain_set_default_learn_limit_t *a = va_arg (*args, vl_api_bridge_domain_set_default_learn_limit_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bridge_domain_set_default_learn_limit_t: */
    s = format(s, "vl_api_bridge_domain_set_default_learn_limit_t:");
    s = format(s, "\n%Ulearn_limit: %u", format_white_space, indent, a->learn_limit);
    return s;
}

static inline u8 *vl_api_bridge_domain_set_default_learn_limit_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bridge_domain_set_default_learn_limit_reply_t *a = va_arg (*args, vl_api_bridge_domain_set_default_learn_limit_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bridge_domain_set_default_learn_limit_reply_t: */
    s = format(s, "vl_api_bridge_domain_set_default_learn_limit_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_bridge_domain_set_learn_limit_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bridge_domain_set_learn_limit_t *a = va_arg (*args, vl_api_bridge_domain_set_learn_limit_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bridge_domain_set_learn_limit_t: */
    s = format(s, "vl_api_bridge_domain_set_learn_limit_t:");
    s = format(s, "\n%Ubd_id: %u", format_white_space, indent, a->bd_id);
    s = format(s, "\n%Ulearn_limit: %u", format_white_space, indent, a->learn_limit);
    return s;
}

static inline u8 *vl_api_bridge_domain_set_learn_limit_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bridge_domain_set_learn_limit_reply_t *a = va_arg (*args, vl_api_bridge_domain_set_learn_limit_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bridge_domain_set_learn_limit_reply_t: */
    s = format(s, "vl_api_bridge_domain_set_learn_limit_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_bridge_domain_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bridge_domain_add_del_t *a = va_arg (*args, vl_api_bridge_domain_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bridge_domain_add_del_t: */
    s = format(s, "vl_api_bridge_domain_add_del_t:");
    s = format(s, "\n%Ubd_id: %u", format_white_space, indent, a->bd_id);
    s = format(s, "\n%Uflood: %u", format_white_space, indent, a->flood);
    s = format(s, "\n%Uuu_flood: %u", format_white_space, indent, a->uu_flood);
    s = format(s, "\n%Uforward: %u", format_white_space, indent, a->forward);
    s = format(s, "\n%Ulearn: %u", format_white_space, indent, a->learn);
    s = format(s, "\n%Uarp_term: %u", format_white_space, indent, a->arp_term);
    s = format(s, "\n%Uarp_ufwd: %u", format_white_space, indent, a->arp_ufwd);
    s = format(s, "\n%Umac_age: %u", format_white_space, indent, a->mac_age);
    s = format(s, "\n%Ubd_tag: %s", format_white_space, indent, a->bd_tag);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    return s;
}

static inline u8 *vl_api_bridge_domain_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bridge_domain_add_del_reply_t *a = va_arg (*args, vl_api_bridge_domain_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bridge_domain_add_del_reply_t: */
    s = format(s, "vl_api_bridge_domain_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_bridge_domain_add_del_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bridge_domain_add_del_v2_t *a = va_arg (*args, vl_api_bridge_domain_add_del_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bridge_domain_add_del_v2_t: */
    s = format(s, "vl_api_bridge_domain_add_del_v2_t:");
    s = format(s, "\n%Ubd_id: %u", format_white_space, indent, a->bd_id);
    s = format(s, "\n%Uflood: %u", format_white_space, indent, a->flood);
    s = format(s, "\n%Uuu_flood: %u", format_white_space, indent, a->uu_flood);
    s = format(s, "\n%Uforward: %u", format_white_space, indent, a->forward);
    s = format(s, "\n%Ulearn: %u", format_white_space, indent, a->learn);
    s = format(s, "\n%Uarp_term: %u", format_white_space, indent, a->arp_term);
    s = format(s, "\n%Uarp_ufwd: %u", format_white_space, indent, a->arp_ufwd);
    s = format(s, "\n%Umac_age: %u", format_white_space, indent, a->mac_age);
    s = format(s, "\n%Ubd_tag: %s", format_white_space, indent, a->bd_tag);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    return s;
}

static inline u8 *vl_api_bridge_domain_add_del_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bridge_domain_add_del_v2_reply_t *a = va_arg (*args, vl_api_bridge_domain_add_del_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bridge_domain_add_del_v2_reply_t: */
    s = format(s, "vl_api_bridge_domain_add_del_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ubd_id: %u", format_white_space, indent, a->bd_id);
    return s;
}

static inline u8 *vl_api_bridge_domain_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bridge_domain_dump_t *a = va_arg (*args, vl_api_bridge_domain_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bridge_domain_dump_t: */
    s = format(s, "vl_api_bridge_domain_dump_t:");
    s = format(s, "\n%Ubd_id: %u", format_white_space, indent, a->bd_id);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_bridge_domain_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bridge_domain_details_t *a = va_arg (*args, vl_api_bridge_domain_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bridge_domain_details_t: */
    s = format(s, "vl_api_bridge_domain_details_t:");
    s = format(s, "\n%Ubd_id: %u", format_white_space, indent, a->bd_id);
    s = format(s, "\n%Uflood: %u", format_white_space, indent, a->flood);
    s = format(s, "\n%Uuu_flood: %u", format_white_space, indent, a->uu_flood);
    s = format(s, "\n%Uforward: %u", format_white_space, indent, a->forward);
    s = format(s, "\n%Ulearn: %u", format_white_space, indent, a->learn);
    s = format(s, "\n%Uarp_term: %u", format_white_space, indent, a->arp_term);
    s = format(s, "\n%Uarp_ufwd: %u", format_white_space, indent, a->arp_ufwd);
    s = format(s, "\n%Umac_age: %u", format_white_space, indent, a->mac_age);
    s = format(s, "\n%Ubd_tag: %s", format_white_space, indent, a->bd_tag);
    s = format(s, "\n%Ubvi_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->bvi_sw_if_index, indent);
    s = format(s, "\n%Uuu_fwd_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->uu_fwd_sw_if_index, indent);
    s = format(s, "\n%Un_sw_ifs: %u", format_white_space, indent, a->n_sw_ifs);
    for (i = 0; i < a->n_sw_ifs; i++) {
        s = format(s, "\n%Usw_if_details: %U",
                   format_white_space, indent, format_vl_api_bridge_domain_sw_if_t, &a->sw_if_details[i], indent);
    }
    return s;
}

static inline u8 *vl_api_bridge_flags_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bridge_flags_t *a = va_arg (*args, vl_api_bridge_flags_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bridge_flags_t: */
    s = format(s, "vl_api_bridge_flags_t:");
    s = format(s, "\n%Ubd_id: %u", format_white_space, indent, a->bd_id);
    s = format(s, "\n%Uis_set: %u", format_white_space, indent, a->is_set);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_bd_flags_t, &a->flags, indent);
    return s;
}

static inline u8 *vl_api_bridge_flags_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bridge_flags_reply_t *a = va_arg (*args, vl_api_bridge_flags_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bridge_flags_reply_t: */
    s = format(s, "vl_api_bridge_flags_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uresulting_feature_bitmap: %u", format_white_space, indent, a->resulting_feature_bitmap);
    return s;
}

static inline u8 *vl_api_l2_interface_vlan_tag_rewrite_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2_interface_vlan_tag_rewrite_t *a = va_arg (*args, vl_api_l2_interface_vlan_tag_rewrite_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2_interface_vlan_tag_rewrite_t: */
    s = format(s, "vl_api_l2_interface_vlan_tag_rewrite_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uvtr_op: %u", format_white_space, indent, a->vtr_op);
    s = format(s, "\n%Upush_dot1q: %u", format_white_space, indent, a->push_dot1q);
    s = format(s, "\n%Utag1: %u", format_white_space, indent, a->tag1);
    s = format(s, "\n%Utag2: %u", format_white_space, indent, a->tag2);
    return s;
}

static inline u8 *vl_api_l2_interface_vlan_tag_rewrite_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2_interface_vlan_tag_rewrite_reply_t *a = va_arg (*args, vl_api_l2_interface_vlan_tag_rewrite_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2_interface_vlan_tag_rewrite_reply_t: */
    s = format(s, "vl_api_l2_interface_vlan_tag_rewrite_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_l2_interface_pbb_tag_rewrite_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2_interface_pbb_tag_rewrite_t *a = va_arg (*args, vl_api_l2_interface_pbb_tag_rewrite_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2_interface_pbb_tag_rewrite_t: */
    s = format(s, "vl_api_l2_interface_pbb_tag_rewrite_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uvtr_op: %u", format_white_space, indent, a->vtr_op);
    s = format(s, "\n%Uouter_tag: %u", format_white_space, indent, a->outer_tag);
    s = format(s, "\n%Ub_dmac: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->b_dmac, indent);
    s = format(s, "\n%Ub_smac: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->b_smac, indent);
    s = format(s, "\n%Ub_vlanid: %u", format_white_space, indent, a->b_vlanid);
    s = format(s, "\n%Ui_sid: %u", format_white_space, indent, a->i_sid);
    return s;
}

static inline u8 *vl_api_l2_interface_pbb_tag_rewrite_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2_interface_pbb_tag_rewrite_reply_t *a = va_arg (*args, vl_api_l2_interface_pbb_tag_rewrite_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2_interface_pbb_tag_rewrite_reply_t: */
    s = format(s, "vl_api_l2_interface_pbb_tag_rewrite_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_l2_patch_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2_patch_add_del_t *a = va_arg (*args, vl_api_l2_patch_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2_patch_add_del_t: */
    s = format(s, "vl_api_l2_patch_add_del_t:");
    s = format(s, "\n%Urx_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->rx_sw_if_index, indent);
    s = format(s, "\n%Utx_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->tx_sw_if_index, indent);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    return s;
}

static inline u8 *vl_api_l2_patch_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2_patch_add_del_reply_t *a = va_arg (*args, vl_api_l2_patch_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2_patch_add_del_reply_t: */
    s = format(s, "vl_api_l2_patch_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sw_interface_set_l2_xconnect_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_set_l2_xconnect_t *a = va_arg (*args, vl_api_sw_interface_set_l2_xconnect_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_set_l2_xconnect_t: */
    s = format(s, "vl_api_sw_interface_set_l2_xconnect_t:");
    s = format(s, "\n%Urx_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->rx_sw_if_index, indent);
    s = format(s, "\n%Utx_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->tx_sw_if_index, indent);
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}

static inline u8 *vl_api_sw_interface_set_l2_xconnect_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_set_l2_xconnect_reply_t *a = va_arg (*args, vl_api_sw_interface_set_l2_xconnect_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_set_l2_xconnect_reply_t: */
    s = format(s, "vl_api_sw_interface_set_l2_xconnect_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sw_interface_set_l2_bridge_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_set_l2_bridge_t *a = va_arg (*args, vl_api_sw_interface_set_l2_bridge_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_set_l2_bridge_t: */
    s = format(s, "vl_api_sw_interface_set_l2_bridge_t:");
    s = format(s, "\n%Urx_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->rx_sw_if_index, indent);
    s = format(s, "\n%Ubd_id: %u", format_white_space, indent, a->bd_id);
    s = format(s, "\n%Uport_type: %U", format_white_space, indent, format_vl_api_l2_port_type_t, &a->port_type, indent);
    s = format(s, "\n%Ushg: %u", format_white_space, indent, a->shg);
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}

static inline u8 *vl_api_sw_interface_set_l2_bridge_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_set_l2_bridge_reply_t *a = va_arg (*args, vl_api_sw_interface_set_l2_bridge_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_set_l2_bridge_reply_t: */
    s = format(s, "vl_api_sw_interface_set_l2_bridge_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_bd_ip_mac_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bd_ip_mac_add_del_t *a = va_arg (*args, vl_api_bd_ip_mac_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bd_ip_mac_add_del_t: */
    s = format(s, "vl_api_bd_ip_mac_add_del_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uentry: %U", format_white_space, indent, format_vl_api_bd_ip_mac_t, &a->entry, indent);
    return s;
}

static inline u8 *vl_api_bd_ip_mac_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bd_ip_mac_add_del_reply_t *a = va_arg (*args, vl_api_bd_ip_mac_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bd_ip_mac_add_del_reply_t: */
    s = format(s, "vl_api_bd_ip_mac_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_bd_ip_mac_flush_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bd_ip_mac_flush_t *a = va_arg (*args, vl_api_bd_ip_mac_flush_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bd_ip_mac_flush_t: */
    s = format(s, "vl_api_bd_ip_mac_flush_t:");
    s = format(s, "\n%Ubd_id: %u", format_white_space, indent, a->bd_id);
    return s;
}

static inline u8 *vl_api_bd_ip_mac_flush_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bd_ip_mac_flush_reply_t *a = va_arg (*args, vl_api_bd_ip_mac_flush_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bd_ip_mac_flush_reply_t: */
    s = format(s, "vl_api_bd_ip_mac_flush_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_bd_ip_mac_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bd_ip_mac_details_t *a = va_arg (*args, vl_api_bd_ip_mac_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bd_ip_mac_details_t: */
    s = format(s, "vl_api_bd_ip_mac_details_t:");
    s = format(s, "\n%Uentry: %U", format_white_space, indent, format_vl_api_bd_ip_mac_t, &a->entry, indent);
    return s;
}

static inline u8 *vl_api_bd_ip_mac_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bd_ip_mac_dump_t *a = va_arg (*args, vl_api_bd_ip_mac_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bd_ip_mac_dump_t: */
    s = format(s, "vl_api_bd_ip_mac_dump_t:");
    s = format(s, "\n%Ubd_id: %u", format_white_space, indent, a->bd_id);
    return s;
}

static inline u8 *vl_api_l2_interface_efp_filter_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2_interface_efp_filter_t *a = va_arg (*args, vl_api_l2_interface_efp_filter_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2_interface_efp_filter_t: */
    s = format(s, "vl_api_l2_interface_efp_filter_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uenable_disable: %u", format_white_space, indent, a->enable_disable);
    return s;
}

static inline u8 *vl_api_l2_interface_efp_filter_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2_interface_efp_filter_reply_t *a = va_arg (*args, vl_api_l2_interface_efp_filter_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2_interface_efp_filter_reply_t: */
    s = format(s, "vl_api_l2_interface_efp_filter_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sw_interface_set_vpath_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_set_vpath_t *a = va_arg (*args, vl_api_sw_interface_set_vpath_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_set_vpath_t: */
    s = format(s, "vl_api_sw_interface_set_vpath_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}

static inline u8 *vl_api_sw_interface_set_vpath_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_set_vpath_reply_t *a = va_arg (*args, vl_api_sw_interface_set_vpath_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_set_vpath_reply_t: */
    s = format(s, "vl_api_sw_interface_set_vpath_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_bvi_create_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bvi_create_t *a = va_arg (*args, vl_api_bvi_create_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bvi_create_t: */
    s = format(s, "vl_api_bvi_create_t:");
    s = format(s, "\n%Umac: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->mac, indent);
    s = format(s, "\n%Uuser_instance: %u", format_white_space, indent, a->user_instance);
    return s;
}

static inline u8 *vl_api_bvi_create_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bvi_create_reply_t *a = va_arg (*args, vl_api_bvi_create_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bvi_create_reply_t: */
    s = format(s, "vl_api_bvi_create_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_bvi_delete_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bvi_delete_t *a = va_arg (*args, vl_api_bvi_delete_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bvi_delete_t: */
    s = format(s, "vl_api_bvi_delete_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_bvi_delete_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bvi_delete_reply_t *a = va_arg (*args, vl_api_bvi_delete_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bvi_delete_reply_t: */
    s = format(s, "vl_api_bvi_delete_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_want_l2_arp_term_events_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_want_l2_arp_term_events_t *a = va_arg (*args, vl_api_want_l2_arp_term_events_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_want_l2_arp_term_events_t: */
    s = format(s, "vl_api_want_l2_arp_term_events_t:");
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    s = format(s, "\n%Upid: %u", format_white_space, indent, a->pid);
    return s;
}

static inline u8 *vl_api_want_l2_arp_term_events_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_want_l2_arp_term_events_reply_t *a = va_arg (*args, vl_api_want_l2_arp_term_events_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_want_l2_arp_term_events_reply_t: */
    s = format(s, "vl_api_want_l2_arp_term_events_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_l2_arp_term_event_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2_arp_term_event_t *a = va_arg (*args, vl_api_l2_arp_term_event_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2_arp_term_event_t: */
    s = format(s, "vl_api_l2_arp_term_event_t:");
    s = format(s, "\n%Upid: %u", format_white_space, indent, a->pid);
    s = format(s, "\n%Uip: %U", format_white_space, indent, format_vl_api_address_t, &a->ip, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Umac: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->mac, indent);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_l2_endianfun
#define included_l2_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_mac_event_action_t_endian (vl_api_mac_event_action_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_mac_entry_t_endian (vl_api_mac_entry_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_mac_address_t_endian(&a->mac_addr, to_net);
    vl_api_mac_event_action_t_endian(&a->action, to_net);
    /* a->flags = a->flags (no-op) */
}

static inline void vl_api_bridge_domain_sw_if_t_endian (vl_api_bridge_domain_sw_if_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->shg = a->shg (no-op) */
}

static inline void vl_api_bd_flags_t_endian (vl_api_bd_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_l2_port_type_t_endian (vl_api_l2_port_type_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_bd_ip_mac_t_endian (vl_api_bd_ip_mac_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->bd_id = clib_net_to_host_u32(a->bd_id);
    vl_api_address_t_endian(&a->ip, to_net);
    vl_api_mac_address_t_endian(&a->mac, to_net);
}

static inline void vl_api_l2_xconnect_details_t_endian (vl_api_l2_xconnect_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->rx_sw_if_index, to_net);
    vl_api_interface_index_t_endian(&a->tx_sw_if_index, to_net);
}

static inline void vl_api_l2_xconnect_dump_t_endian (vl_api_l2_xconnect_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_l2_fib_table_details_t_endian (vl_api_l2_fib_table_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->bd_id = clib_net_to_host_u32(a->bd_id);
    vl_api_mac_address_t_endian(&a->mac, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->static_mac = a->static_mac (no-op) */
    /* a->filter_mac = a->filter_mac (no-op) */
    /* a->bvi_mac = a->bvi_mac (no-op) */
}

static inline void vl_api_l2_fib_table_dump_t_endian (vl_api_l2_fib_table_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->bd_id = clib_net_to_host_u32(a->bd_id);
}

static inline void vl_api_l2_fib_clear_table_t_endian (vl_api_l2_fib_clear_table_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_l2_fib_clear_table_reply_t_endian (vl_api_l2_fib_clear_table_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_l2fib_flush_all_t_endian (vl_api_l2fib_flush_all_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_l2fib_flush_all_reply_t_endian (vl_api_l2fib_flush_all_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_l2fib_flush_bd_t_endian (vl_api_l2fib_flush_bd_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->bd_id = clib_net_to_host_u32(a->bd_id);
}

static inline void vl_api_l2fib_flush_bd_reply_t_endian (vl_api_l2fib_flush_bd_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_l2fib_flush_int_t_endian (vl_api_l2fib_flush_int_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_l2fib_flush_int_reply_t_endian (vl_api_l2fib_flush_int_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_l2fib_add_del_t_endian (vl_api_l2fib_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_mac_address_t_endian(&a->mac, to_net);
    a->bd_id = clib_net_to_host_u32(a->bd_id);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->is_add = a->is_add (no-op) */
    /* a->static_mac = a->static_mac (no-op) */
    /* a->filter_mac = a->filter_mac (no-op) */
    /* a->bvi_mac = a->bvi_mac (no-op) */
}

static inline void vl_api_l2fib_add_del_reply_t_endian (vl_api_l2fib_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_want_l2_macs_events_t_endian (vl_api_want_l2_macs_events_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->learn_limit = clib_net_to_host_u32(a->learn_limit);
    /* a->scan_delay = a->scan_delay (no-op) */
    /* a->max_macs_in_event = a->max_macs_in_event (no-op) */
    /* a->enable_disable = a->enable_disable (no-op) */
    a->pid = clib_net_to_host_u32(a->pid);
}

static inline void vl_api_want_l2_macs_events_reply_t_endian (vl_api_want_l2_macs_events_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_want_l2_macs_events2_t_endian (vl_api_want_l2_macs_events2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->max_macs_in_event = a->max_macs_in_event (no-op) */
    /* a->enable_disable = a->enable_disable (no-op) */
    a->pid = clib_net_to_host_u32(a->pid);
}

static inline void vl_api_want_l2_macs_events2_reply_t_endian (vl_api_want_l2_macs_events2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_l2fib_set_scan_delay_t_endian (vl_api_l2fib_set_scan_delay_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->scan_delay = clib_net_to_host_u16(a->scan_delay);
}

static inline void vl_api_l2fib_set_scan_delay_reply_t_endian (vl_api_l2fib_set_scan_delay_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_l2_macs_event_t_endian (vl_api_l2_macs_event_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->pid = clib_net_to_host_u32(a->pid);
    a->n_macs = clib_net_to_host_u32(a->n_macs);
    u32 count = to_net ? clib_net_to_host_u32(a->n_macs) : a->n_macs;
    for (i = 0; i < count; i++) {
        vl_api_mac_entry_t_endian(&a->mac[i], to_net);
    }
}

static inline void vl_api_l2_flags_t_endian (vl_api_l2_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->is_set = a->is_set (no-op) */
    a->feature_bitmap = clib_net_to_host_u32(a->feature_bitmap);
}

static inline void vl_api_l2_flags_reply_t_endian (vl_api_l2_flags_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->resulting_feature_bitmap = clib_net_to_host_u32(a->resulting_feature_bitmap);
}

static inline void vl_api_bridge_domain_set_mac_age_t_endian (vl_api_bridge_domain_set_mac_age_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->bd_id = clib_net_to_host_u32(a->bd_id);
    /* a->mac_age = a->mac_age (no-op) */
}

static inline void vl_api_bridge_domain_set_mac_age_reply_t_endian (vl_api_bridge_domain_set_mac_age_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_bridge_domain_set_default_learn_limit_t_endian (vl_api_bridge_domain_set_default_learn_limit_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->learn_limit = clib_net_to_host_u32(a->learn_limit);
}

static inline void vl_api_bridge_domain_set_default_learn_limit_reply_t_endian (vl_api_bridge_domain_set_default_learn_limit_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_bridge_domain_set_learn_limit_t_endian (vl_api_bridge_domain_set_learn_limit_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->bd_id = clib_net_to_host_u32(a->bd_id);
    a->learn_limit = clib_net_to_host_u32(a->learn_limit);
}

static inline void vl_api_bridge_domain_set_learn_limit_reply_t_endian (vl_api_bridge_domain_set_learn_limit_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_bridge_domain_add_del_t_endian (vl_api_bridge_domain_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->bd_id = clib_net_to_host_u32(a->bd_id);
    /* a->flood = a->flood (no-op) */
    /* a->uu_flood = a->uu_flood (no-op) */
    /* a->forward = a->forward (no-op) */
    /* a->learn = a->learn (no-op) */
    /* a->arp_term = a->arp_term (no-op) */
    /* a->arp_ufwd = a->arp_ufwd (no-op) */
    /* a->mac_age = a->mac_age (no-op) */
    /* a->bd_tag = a->bd_tag (no-op) */
    /* a->is_add = a->is_add (no-op) */
}

static inline void vl_api_bridge_domain_add_del_reply_t_endian (vl_api_bridge_domain_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_bridge_domain_add_del_v2_t_endian (vl_api_bridge_domain_add_del_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->bd_id = clib_net_to_host_u32(a->bd_id);
    /* a->flood = a->flood (no-op) */
    /* a->uu_flood = a->uu_flood (no-op) */
    /* a->forward = a->forward (no-op) */
    /* a->learn = a->learn (no-op) */
    /* a->arp_term = a->arp_term (no-op) */
    /* a->arp_ufwd = a->arp_ufwd (no-op) */
    /* a->mac_age = a->mac_age (no-op) */
    /* a->bd_tag = a->bd_tag (no-op) */
    /* a->is_add = a->is_add (no-op) */
}

static inline void vl_api_bridge_domain_add_del_v2_reply_t_endian (vl_api_bridge_domain_add_del_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->bd_id = clib_net_to_host_u32(a->bd_id);
}

static inline void vl_api_bridge_domain_dump_t_endian (vl_api_bridge_domain_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->bd_id = clib_net_to_host_u32(a->bd_id);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_bridge_domain_details_t_endian (vl_api_bridge_domain_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->bd_id = clib_net_to_host_u32(a->bd_id);
    /* a->flood = a->flood (no-op) */
    /* a->uu_flood = a->uu_flood (no-op) */
    /* a->forward = a->forward (no-op) */
    /* a->learn = a->learn (no-op) */
    /* a->arp_term = a->arp_term (no-op) */
    /* a->arp_ufwd = a->arp_ufwd (no-op) */
    /* a->mac_age = a->mac_age (no-op) */
    /* a->bd_tag = a->bd_tag (no-op) */
    vl_api_interface_index_t_endian(&a->bvi_sw_if_index, to_net);
    vl_api_interface_index_t_endian(&a->uu_fwd_sw_if_index, to_net);
    a->n_sw_ifs = clib_net_to_host_u32(a->n_sw_ifs);
    u32 count = to_net ? clib_net_to_host_u32(a->n_sw_ifs) : a->n_sw_ifs;
    for (i = 0; i < count; i++) {
        vl_api_bridge_domain_sw_if_t_endian(&a->sw_if_details[i], to_net);
    }
}

static inline void vl_api_bridge_flags_t_endian (vl_api_bridge_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->bd_id = clib_net_to_host_u32(a->bd_id);
    /* a->is_set = a->is_set (no-op) */
    vl_api_bd_flags_t_endian(&a->flags, to_net);
}

static inline void vl_api_bridge_flags_reply_t_endian (vl_api_bridge_flags_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->resulting_feature_bitmap = clib_net_to_host_u32(a->resulting_feature_bitmap);
}

static inline void vl_api_l2_interface_vlan_tag_rewrite_t_endian (vl_api_l2_interface_vlan_tag_rewrite_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->vtr_op = clib_net_to_host_u32(a->vtr_op);
    a->push_dot1q = clib_net_to_host_u32(a->push_dot1q);
    a->tag1 = clib_net_to_host_u32(a->tag1);
    a->tag2 = clib_net_to_host_u32(a->tag2);
}

static inline void vl_api_l2_interface_vlan_tag_rewrite_reply_t_endian (vl_api_l2_interface_vlan_tag_rewrite_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_l2_interface_pbb_tag_rewrite_t_endian (vl_api_l2_interface_pbb_tag_rewrite_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->vtr_op = clib_net_to_host_u32(a->vtr_op);
    a->outer_tag = clib_net_to_host_u16(a->outer_tag);
    vl_api_mac_address_t_endian(&a->b_dmac, to_net);
    vl_api_mac_address_t_endian(&a->b_smac, to_net);
    a->b_vlanid = clib_net_to_host_u16(a->b_vlanid);
    a->i_sid = clib_net_to_host_u32(a->i_sid);
}

static inline void vl_api_l2_interface_pbb_tag_rewrite_reply_t_endian (vl_api_l2_interface_pbb_tag_rewrite_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_l2_patch_add_del_t_endian (vl_api_l2_patch_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->rx_sw_if_index, to_net);
    vl_api_interface_index_t_endian(&a->tx_sw_if_index, to_net);
    /* a->is_add = a->is_add (no-op) */
}

static inline void vl_api_l2_patch_add_del_reply_t_endian (vl_api_l2_patch_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sw_interface_set_l2_xconnect_t_endian (vl_api_sw_interface_set_l2_xconnect_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->rx_sw_if_index, to_net);
    vl_api_interface_index_t_endian(&a->tx_sw_if_index, to_net);
    /* a->enable = a->enable (no-op) */
}

static inline void vl_api_sw_interface_set_l2_xconnect_reply_t_endian (vl_api_sw_interface_set_l2_xconnect_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sw_interface_set_l2_bridge_t_endian (vl_api_sw_interface_set_l2_bridge_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->rx_sw_if_index, to_net);
    a->bd_id = clib_net_to_host_u32(a->bd_id);
    vl_api_l2_port_type_t_endian(&a->port_type, to_net);
    /* a->shg = a->shg (no-op) */
    /* a->enable = a->enable (no-op) */
}

static inline void vl_api_sw_interface_set_l2_bridge_reply_t_endian (vl_api_sw_interface_set_l2_bridge_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_bd_ip_mac_add_del_t_endian (vl_api_bd_ip_mac_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_bd_ip_mac_t_endian(&a->entry, to_net);
}

static inline void vl_api_bd_ip_mac_add_del_reply_t_endian (vl_api_bd_ip_mac_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_bd_ip_mac_flush_t_endian (vl_api_bd_ip_mac_flush_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->bd_id = clib_net_to_host_u32(a->bd_id);
}

static inline void vl_api_bd_ip_mac_flush_reply_t_endian (vl_api_bd_ip_mac_flush_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_bd_ip_mac_details_t_endian (vl_api_bd_ip_mac_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_bd_ip_mac_t_endian(&a->entry, to_net);
}

static inline void vl_api_bd_ip_mac_dump_t_endian (vl_api_bd_ip_mac_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->bd_id = clib_net_to_host_u32(a->bd_id);
}

static inline void vl_api_l2_interface_efp_filter_t_endian (vl_api_l2_interface_efp_filter_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->enable_disable = a->enable_disable (no-op) */
}

static inline void vl_api_l2_interface_efp_filter_reply_t_endian (vl_api_l2_interface_efp_filter_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sw_interface_set_vpath_t_endian (vl_api_sw_interface_set_vpath_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->enable = a->enable (no-op) */
}

static inline void vl_api_sw_interface_set_vpath_reply_t_endian (vl_api_sw_interface_set_vpath_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_bvi_create_t_endian (vl_api_bvi_create_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_mac_address_t_endian(&a->mac, to_net);
    a->user_instance = clib_net_to_host_u32(a->user_instance);
}

static inline void vl_api_bvi_create_reply_t_endian (vl_api_bvi_create_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_bvi_delete_t_endian (vl_api_bvi_delete_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_bvi_delete_reply_t_endian (vl_api_bvi_delete_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_want_l2_arp_term_events_t_endian (vl_api_want_l2_arp_term_events_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->enable = a->enable (no-op) */
    a->pid = clib_net_to_host_u32(a->pid);
}

static inline void vl_api_want_l2_arp_term_events_reply_t_endian (vl_api_want_l2_arp_term_events_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_l2_arp_term_event_t_endian (vl_api_l2_arp_term_event_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->pid = clib_net_to_host_u32(a->pid);
    vl_api_address_t_endian(&a->ip, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_mac_address_t_endian(&a->mac, to_net);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_l2_calcsizefun
#define included_l2_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_mac_event_action_t_calc_size (vl_api_mac_event_action_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_mac_entry_t_calc_size (vl_api_mac_entry_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->mac_addr) + vl_api_mac_address_t_calc_size(&a->mac_addr) - sizeof(a->action) + vl_api_mac_event_action_t_calc_size(&a->action);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bridge_domain_sw_if_t_calc_size (vl_api_bridge_domain_sw_if_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bd_flags_t_calc_size (vl_api_bd_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2_port_type_t_calc_size (vl_api_l2_port_type_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bd_ip_mac_t_calc_size (vl_api_bd_ip_mac_t *a)
{
      return sizeof(*a) - sizeof(a->ip) + vl_api_address_t_calc_size(&a->ip) - sizeof(a->mac) + vl_api_mac_address_t_calc_size(&a->mac);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2_xconnect_details_t_calc_size (vl_api_l2_xconnect_details_t *a)
{
      return sizeof(*a) - sizeof(a->rx_sw_if_index) + vl_api_interface_index_t_calc_size(&a->rx_sw_if_index) - sizeof(a->tx_sw_if_index) + vl_api_interface_index_t_calc_size(&a->tx_sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2_xconnect_dump_t_calc_size (vl_api_l2_xconnect_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2_fib_table_details_t_calc_size (vl_api_l2_fib_table_details_t *a)
{
      return sizeof(*a) - sizeof(a->mac) + vl_api_mac_address_t_calc_size(&a->mac) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2_fib_table_dump_t_calc_size (vl_api_l2_fib_table_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2_fib_clear_table_t_calc_size (vl_api_l2_fib_clear_table_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2_fib_clear_table_reply_t_calc_size (vl_api_l2_fib_clear_table_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2fib_flush_all_t_calc_size (vl_api_l2fib_flush_all_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2fib_flush_all_reply_t_calc_size (vl_api_l2fib_flush_all_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2fib_flush_bd_t_calc_size (vl_api_l2fib_flush_bd_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2fib_flush_bd_reply_t_calc_size (vl_api_l2fib_flush_bd_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2fib_flush_int_t_calc_size (vl_api_l2fib_flush_int_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2fib_flush_int_reply_t_calc_size (vl_api_l2fib_flush_int_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2fib_add_del_t_calc_size (vl_api_l2fib_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->mac) + vl_api_mac_address_t_calc_size(&a->mac) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2fib_add_del_reply_t_calc_size (vl_api_l2fib_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_want_l2_macs_events_t_calc_size (vl_api_want_l2_macs_events_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_want_l2_macs_events_reply_t_calc_size (vl_api_want_l2_macs_events_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_want_l2_macs_events2_t_calc_size (vl_api_want_l2_macs_events2_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_want_l2_macs_events2_reply_t_calc_size (vl_api_want_l2_macs_events2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2fib_set_scan_delay_t_calc_size (vl_api_l2fib_set_scan_delay_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2fib_set_scan_delay_reply_t_calc_size (vl_api_l2fib_set_scan_delay_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2_macs_event_t_calc_size (vl_api_l2_macs_event_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->n_macs) * sizeof(a->mac[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2_flags_t_calc_size (vl_api_l2_flags_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2_flags_reply_t_calc_size (vl_api_l2_flags_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bridge_domain_set_mac_age_t_calc_size (vl_api_bridge_domain_set_mac_age_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bridge_domain_set_mac_age_reply_t_calc_size (vl_api_bridge_domain_set_mac_age_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bridge_domain_set_default_learn_limit_t_calc_size (vl_api_bridge_domain_set_default_learn_limit_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bridge_domain_set_default_learn_limit_reply_t_calc_size (vl_api_bridge_domain_set_default_learn_limit_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bridge_domain_set_learn_limit_t_calc_size (vl_api_bridge_domain_set_learn_limit_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bridge_domain_set_learn_limit_reply_t_calc_size (vl_api_bridge_domain_set_learn_limit_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bridge_domain_add_del_t_calc_size (vl_api_bridge_domain_add_del_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bridge_domain_add_del_reply_t_calc_size (vl_api_bridge_domain_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bridge_domain_add_del_v2_t_calc_size (vl_api_bridge_domain_add_del_v2_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bridge_domain_add_del_v2_reply_t_calc_size (vl_api_bridge_domain_add_del_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bridge_domain_dump_t_calc_size (vl_api_bridge_domain_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bridge_domain_details_t_calc_size (vl_api_bridge_domain_details_t *a)
{
      return sizeof(*a) - sizeof(a->bvi_sw_if_index) + vl_api_interface_index_t_calc_size(&a->bvi_sw_if_index) - sizeof(a->uu_fwd_sw_if_index) + vl_api_interface_index_t_calc_size(&a->uu_fwd_sw_if_index) + clib_net_to_host_u32(a->n_sw_ifs) * sizeof(a->sw_if_details[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bridge_flags_t_calc_size (vl_api_bridge_flags_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_bd_flags_t_calc_size(&a->flags);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bridge_flags_reply_t_calc_size (vl_api_bridge_flags_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2_interface_vlan_tag_rewrite_t_calc_size (vl_api_l2_interface_vlan_tag_rewrite_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2_interface_vlan_tag_rewrite_reply_t_calc_size (vl_api_l2_interface_vlan_tag_rewrite_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2_interface_pbb_tag_rewrite_t_calc_size (vl_api_l2_interface_pbb_tag_rewrite_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->b_dmac) + vl_api_mac_address_t_calc_size(&a->b_dmac) - sizeof(a->b_smac) + vl_api_mac_address_t_calc_size(&a->b_smac);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2_interface_pbb_tag_rewrite_reply_t_calc_size (vl_api_l2_interface_pbb_tag_rewrite_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2_patch_add_del_t_calc_size (vl_api_l2_patch_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->rx_sw_if_index) + vl_api_interface_index_t_calc_size(&a->rx_sw_if_index) - sizeof(a->tx_sw_if_index) + vl_api_interface_index_t_calc_size(&a->tx_sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2_patch_add_del_reply_t_calc_size (vl_api_l2_patch_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_set_l2_xconnect_t_calc_size (vl_api_sw_interface_set_l2_xconnect_t *a)
{
      return sizeof(*a) - sizeof(a->rx_sw_if_index) + vl_api_interface_index_t_calc_size(&a->rx_sw_if_index) - sizeof(a->tx_sw_if_index) + vl_api_interface_index_t_calc_size(&a->tx_sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_set_l2_xconnect_reply_t_calc_size (vl_api_sw_interface_set_l2_xconnect_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_set_l2_bridge_t_calc_size (vl_api_sw_interface_set_l2_bridge_t *a)
{
      return sizeof(*a) - sizeof(a->rx_sw_if_index) + vl_api_interface_index_t_calc_size(&a->rx_sw_if_index) - sizeof(a->port_type) + vl_api_l2_port_type_t_calc_size(&a->port_type);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_set_l2_bridge_reply_t_calc_size (vl_api_sw_interface_set_l2_bridge_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bd_ip_mac_add_del_t_calc_size (vl_api_bd_ip_mac_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->entry) + vl_api_bd_ip_mac_t_calc_size(&a->entry);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bd_ip_mac_add_del_reply_t_calc_size (vl_api_bd_ip_mac_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bd_ip_mac_flush_t_calc_size (vl_api_bd_ip_mac_flush_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bd_ip_mac_flush_reply_t_calc_size (vl_api_bd_ip_mac_flush_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bd_ip_mac_details_t_calc_size (vl_api_bd_ip_mac_details_t *a)
{
      return sizeof(*a) - sizeof(a->entry) + vl_api_bd_ip_mac_t_calc_size(&a->entry);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bd_ip_mac_dump_t_calc_size (vl_api_bd_ip_mac_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2_interface_efp_filter_t_calc_size (vl_api_l2_interface_efp_filter_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2_interface_efp_filter_reply_t_calc_size (vl_api_l2_interface_efp_filter_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_set_vpath_t_calc_size (vl_api_sw_interface_set_vpath_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_set_vpath_reply_t_calc_size (vl_api_sw_interface_set_vpath_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bvi_create_t_calc_size (vl_api_bvi_create_t *a)
{
      return sizeof(*a) - sizeof(a->mac) + vl_api_mac_address_t_calc_size(&a->mac);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bvi_create_reply_t_calc_size (vl_api_bvi_create_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bvi_delete_t_calc_size (vl_api_bvi_delete_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bvi_delete_reply_t_calc_size (vl_api_bvi_delete_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_want_l2_arp_term_events_t_calc_size (vl_api_want_l2_arp_term_events_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_want_l2_arp_term_events_reply_t_calc_size (vl_api_want_l2_arp_term_events_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2_arp_term_event_t_calc_size (vl_api_l2_arp_term_event_t *a)
{
      return sizeof(*a) - sizeof(a->ip) + vl_api_address_t_calc_size(&a->ip) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->mac) + vl_api_mac_address_t_calc_size(&a->mac);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(l2.api, 3, 2, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(l2.api, 0x90ecafc3)

#endif

