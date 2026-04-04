#define vl_endianfun		/* define message structures */
#include "l2.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "l2.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "l2.api.h"
#undef vl_printfun

#include "l2.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("l2_90ecafc3", VL_MSG_L2_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_l2);
   vl_msg_api_add_msg_name_crc (am, "l2_xconnect_details_472b6b67",
                                VL_API_L2_XCONNECT_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2_xconnect_dump_51077d14",
                                VL_API_L2_XCONNECT_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2_fib_table_details_a44ef6b8",
                                VL_API_L2_FIB_TABLE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2_fib_table_dump_c25fdce6",
                                VL_API_L2_FIB_TABLE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2_fib_clear_table_51077d14",
                                VL_API_L2_FIB_CLEAR_TABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2_fib_clear_table_reply_e8d4e804",
                                VL_API_L2_FIB_CLEAR_TABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2fib_flush_all_51077d14",
                                VL_API_L2FIB_FLUSH_ALL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2fib_flush_all_reply_e8d4e804",
                                VL_API_L2FIB_FLUSH_ALL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2fib_flush_bd_c25fdce6",
                                VL_API_L2FIB_FLUSH_BD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2fib_flush_bd_reply_e8d4e804",
                                VL_API_L2FIB_FLUSH_BD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2fib_flush_int_f9e6675e",
                                VL_API_L2FIB_FLUSH_INT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2fib_flush_int_reply_e8d4e804",
                                VL_API_L2FIB_FLUSH_INT_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2fib_add_del_eddda487",
                                VL_API_L2FIB_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2fib_add_del_reply_e8d4e804",
                                VL_API_L2FIB_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_l2_macs_events_9aabdfde",
                                VL_API_WANT_L2_MACS_EVENTS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_l2_macs_events_reply_e8d4e804",
                                VL_API_WANT_L2_MACS_EVENTS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_l2_macs_events2_cc1377b0",
                                VL_API_WANT_L2_MACS_EVENTS2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_l2_macs_events2_reply_e8d4e804",
                                VL_API_WANT_L2_MACS_EVENTS2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2fib_set_scan_delay_a3b968a4",
                                VL_API_L2FIB_SET_SCAN_DELAY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2fib_set_scan_delay_reply_e8d4e804",
                                VL_API_L2FIB_SET_SCAN_DELAY_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2_macs_event_44b8fd64",
                                VL_API_L2_MACS_EVENT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2_flags_fc41cfe8",
                                VL_API_L2_FLAGS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2_flags_reply_29b2a2b3",
                                VL_API_L2_FLAGS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bridge_domain_set_mac_age_b537ad7b",
                                VL_API_BRIDGE_DOMAIN_SET_MAC_AGE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bridge_domain_set_mac_age_reply_e8d4e804",
                                VL_API_BRIDGE_DOMAIN_SET_MAC_AGE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bridge_domain_set_default_learn_limit_f097ffce",
                                VL_API_BRIDGE_DOMAIN_SET_DEFAULT_LEARN_LIMIT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bridge_domain_set_default_learn_limit_reply_e8d4e804",
                                VL_API_BRIDGE_DOMAIN_SET_DEFAULT_LEARN_LIMIT_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bridge_domain_set_learn_limit_89c52b5f",
                                VL_API_BRIDGE_DOMAIN_SET_LEARN_LIMIT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bridge_domain_set_learn_limit_reply_e8d4e804",
                                VL_API_BRIDGE_DOMAIN_SET_LEARN_LIMIT_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bridge_domain_add_del_600b7170",
                                VL_API_BRIDGE_DOMAIN_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bridge_domain_add_del_reply_e8d4e804",
                                VL_API_BRIDGE_DOMAIN_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bridge_domain_add_del_v2_600b7170",
                                VL_API_BRIDGE_DOMAIN_ADD_DEL_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bridge_domain_add_del_v2_reply_fcb1e980",
                                VL_API_BRIDGE_DOMAIN_ADD_DEL_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bridge_domain_dump_74396a43",
                                VL_API_BRIDGE_DOMAIN_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bridge_domain_details_0fa506fd",
                                VL_API_BRIDGE_DOMAIN_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bridge_flags_1b0c5fbd",
                                VL_API_BRIDGE_FLAGS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bridge_flags_reply_29b2a2b3",
                                VL_API_BRIDGE_FLAGS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2_interface_vlan_tag_rewrite_62cc0bbc",
                                VL_API_L2_INTERFACE_VLAN_TAG_REWRITE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2_interface_vlan_tag_rewrite_reply_e8d4e804",
                                VL_API_L2_INTERFACE_VLAN_TAG_REWRITE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2_interface_pbb_tag_rewrite_38e802a8",
                                VL_API_L2_INTERFACE_PBB_TAG_REWRITE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2_interface_pbb_tag_rewrite_reply_e8d4e804",
                                VL_API_L2_INTERFACE_PBB_TAG_REWRITE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2_patch_add_del_a1f6a6f3",
                                VL_API_L2_PATCH_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2_patch_add_del_reply_e8d4e804",
                                VL_API_L2_PATCH_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_l2_xconnect_4fa28a85",
                                VL_API_SW_INTERFACE_SET_L2_XCONNECT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_l2_xconnect_reply_e8d4e804",
                                VL_API_SW_INTERFACE_SET_L2_XCONNECT_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_l2_bridge_d0678b13",
                                VL_API_SW_INTERFACE_SET_L2_BRIDGE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_l2_bridge_reply_e8d4e804",
                                VL_API_SW_INTERFACE_SET_L2_BRIDGE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bd_ip_mac_add_del_0257c869",
                                VL_API_BD_IP_MAC_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bd_ip_mac_add_del_reply_e8d4e804",
                                VL_API_BD_IP_MAC_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bd_ip_mac_flush_c25fdce6",
                                VL_API_BD_IP_MAC_FLUSH + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bd_ip_mac_flush_reply_e8d4e804",
                                VL_API_BD_IP_MAC_FLUSH_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bd_ip_mac_details_545af86a",
                                VL_API_BD_IP_MAC_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bd_ip_mac_dump_c25fdce6",
                                VL_API_BD_IP_MAC_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2_interface_efp_filter_5501adee",
                                VL_API_L2_INTERFACE_EFP_FILTER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2_interface_efp_filter_reply_e8d4e804",
                                VL_API_L2_INTERFACE_EFP_FILTER_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_vpath_ae6cfcfb",
                                VL_API_SW_INTERFACE_SET_VPATH + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_vpath_reply_e8d4e804",
                                VL_API_SW_INTERFACE_SET_VPATH_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bvi_create_f5398559",
                                VL_API_BVI_CREATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bvi_create_reply_5383d31f",
                                VL_API_BVI_CREATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bvi_delete_f9e6675e",
                                VL_API_BVI_DELETE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bvi_delete_reply_e8d4e804",
                                VL_API_BVI_DELETE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_l2_arp_term_events_3ec6d6c2",
                                VL_API_WANT_L2_ARP_TERM_EVENTS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_l2_arp_term_events_reply_e8d4e804",
                                VL_API_WANT_L2_ARP_TERM_EVENTS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2_arp_term_event_6963e07a",
                                VL_API_L2_ARP_TERM_EVENT + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_WANT_L2_MACS_EVENTS + msg_id_base,
   .name = "want_l2_macs_events",
   .handler = vl_api_want_l2_macs_events_t_handler,
   .endian = vl_api_want_l2_macs_events_t_endian,
   .format_fn = vl_api_want_l2_macs_events_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_want_l2_macs_events_t_tojson,
   .fromjson = vl_api_want_l2_macs_events_t_fromjson,
   .calc_size = vl_api_want_l2_macs_events_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_WANT_L2_MACS_EVENTS_REPLY + msg_id_base,
  .name = "want_l2_macs_events_reply",
  .handler = 0,
  .endian = vl_api_want_l2_macs_events_reply_t_endian,
  .format_fn = vl_api_want_l2_macs_events_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_want_l2_macs_events_reply_t_tojson,
  .fromjson = vl_api_want_l2_macs_events_reply_t_fromjson,
  .calc_size = vl_api_want_l2_macs_events_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_WANT_L2_ARP_TERM_EVENTS + msg_id_base,
   .name = "want_l2_arp_term_events",
   .handler = vl_api_want_l2_arp_term_events_t_handler,
   .endian = vl_api_want_l2_arp_term_events_t_endian,
   .format_fn = vl_api_want_l2_arp_term_events_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_want_l2_arp_term_events_t_tojson,
   .fromjson = vl_api_want_l2_arp_term_events_t_fromjson,
   .calc_size = vl_api_want_l2_arp_term_events_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_WANT_L2_ARP_TERM_EVENTS_REPLY + msg_id_base,
  .name = "want_l2_arp_term_events_reply",
  .handler = 0,
  .endian = vl_api_want_l2_arp_term_events_reply_t_endian,
  .format_fn = vl_api_want_l2_arp_term_events_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_want_l2_arp_term_events_reply_t_tojson,
  .fromjson = vl_api_want_l2_arp_term_events_reply_t_fromjson,
  .calc_size = vl_api_want_l2_arp_term_events_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L2_XCONNECT_DUMP + msg_id_base,
   .name = "l2_xconnect_dump",
   .handler = vl_api_l2_xconnect_dump_t_handler,
   .endian = vl_api_l2_xconnect_dump_t_endian,
   .format_fn = vl_api_l2_xconnect_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l2_xconnect_dump_t_tojson,
   .fromjson = vl_api_l2_xconnect_dump_t_fromjson,
   .calc_size = vl_api_l2_xconnect_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L2_XCONNECT_DETAILS + msg_id_base,
  .name = "l2_xconnect_details",
  .handler = 0,
  .endian = vl_api_l2_xconnect_details_t_endian,
  .format_fn = vl_api_l2_xconnect_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l2_xconnect_details_t_tojson,
  .fromjson = vl_api_l2_xconnect_details_t_fromjson,
  .calc_size = vl_api_l2_xconnect_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L2_FIB_TABLE_DUMP + msg_id_base,
   .name = "l2_fib_table_dump",
   .handler = vl_api_l2_fib_table_dump_t_handler,
   .endian = vl_api_l2_fib_table_dump_t_endian,
   .format_fn = vl_api_l2_fib_table_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l2_fib_table_dump_t_tojson,
   .fromjson = vl_api_l2_fib_table_dump_t_fromjson,
   .calc_size = vl_api_l2_fib_table_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L2_FIB_TABLE_DETAILS + msg_id_base,
  .name = "l2_fib_table_details",
  .handler = 0,
  .endian = vl_api_l2_fib_table_details_t_endian,
  .format_fn = vl_api_l2_fib_table_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l2_fib_table_details_t_tojson,
  .fromjson = vl_api_l2_fib_table_details_t_fromjson,
  .calc_size = vl_api_l2_fib_table_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L2_FIB_CLEAR_TABLE + msg_id_base,
   .name = "l2_fib_clear_table",
   .handler = vl_api_l2_fib_clear_table_t_handler,
   .endian = vl_api_l2_fib_clear_table_t_endian,
   .format_fn = vl_api_l2_fib_clear_table_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l2_fib_clear_table_t_tojson,
   .fromjson = vl_api_l2_fib_clear_table_t_fromjson,
   .calc_size = vl_api_l2_fib_clear_table_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L2_FIB_CLEAR_TABLE_REPLY + msg_id_base,
  .name = "l2_fib_clear_table_reply",
  .handler = 0,
  .endian = vl_api_l2_fib_clear_table_reply_t_endian,
  .format_fn = vl_api_l2_fib_clear_table_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l2_fib_clear_table_reply_t_tojson,
  .fromjson = vl_api_l2_fib_clear_table_reply_t_fromjson,
  .calc_size = vl_api_l2_fib_clear_table_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L2FIB_FLUSH_ALL + msg_id_base,
   .name = "l2fib_flush_all",
   .handler = vl_api_l2fib_flush_all_t_handler,
   .endian = vl_api_l2fib_flush_all_t_endian,
   .format_fn = vl_api_l2fib_flush_all_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l2fib_flush_all_t_tojson,
   .fromjson = vl_api_l2fib_flush_all_t_fromjson,
   .calc_size = vl_api_l2fib_flush_all_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L2FIB_FLUSH_ALL_REPLY + msg_id_base,
  .name = "l2fib_flush_all_reply",
  .handler = 0,
  .endian = vl_api_l2fib_flush_all_reply_t_endian,
  .format_fn = vl_api_l2fib_flush_all_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l2fib_flush_all_reply_t_tojson,
  .fromjson = vl_api_l2fib_flush_all_reply_t_fromjson,
  .calc_size = vl_api_l2fib_flush_all_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L2FIB_FLUSH_BD + msg_id_base,
   .name = "l2fib_flush_bd",
   .handler = vl_api_l2fib_flush_bd_t_handler,
   .endian = vl_api_l2fib_flush_bd_t_endian,
   .format_fn = vl_api_l2fib_flush_bd_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l2fib_flush_bd_t_tojson,
   .fromjson = vl_api_l2fib_flush_bd_t_fromjson,
   .calc_size = vl_api_l2fib_flush_bd_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L2FIB_FLUSH_BD_REPLY + msg_id_base,
  .name = "l2fib_flush_bd_reply",
  .handler = 0,
  .endian = vl_api_l2fib_flush_bd_reply_t_endian,
  .format_fn = vl_api_l2fib_flush_bd_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l2fib_flush_bd_reply_t_tojson,
  .fromjson = vl_api_l2fib_flush_bd_reply_t_fromjson,
  .calc_size = vl_api_l2fib_flush_bd_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L2FIB_FLUSH_INT + msg_id_base,
   .name = "l2fib_flush_int",
   .handler = vl_api_l2fib_flush_int_t_handler,
   .endian = vl_api_l2fib_flush_int_t_endian,
   .format_fn = vl_api_l2fib_flush_int_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l2fib_flush_int_t_tojson,
   .fromjson = vl_api_l2fib_flush_int_t_fromjson,
   .calc_size = vl_api_l2fib_flush_int_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L2FIB_FLUSH_INT_REPLY + msg_id_base,
  .name = "l2fib_flush_int_reply",
  .handler = 0,
  .endian = vl_api_l2fib_flush_int_reply_t_endian,
  .format_fn = vl_api_l2fib_flush_int_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l2fib_flush_int_reply_t_tojson,
  .fromjson = vl_api_l2fib_flush_int_reply_t_fromjson,
  .calc_size = vl_api_l2fib_flush_int_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L2FIB_ADD_DEL + msg_id_base,
   .name = "l2fib_add_del",
   .handler = vl_api_l2fib_add_del_t_handler,
   .endian = vl_api_l2fib_add_del_t_endian,
   .format_fn = vl_api_l2fib_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l2fib_add_del_t_tojson,
   .fromjson = vl_api_l2fib_add_del_t_fromjson,
   .calc_size = vl_api_l2fib_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L2FIB_ADD_DEL_REPLY + msg_id_base,
  .name = "l2fib_add_del_reply",
  .handler = 0,
  .endian = vl_api_l2fib_add_del_reply_t_endian,
  .format_fn = vl_api_l2fib_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l2fib_add_del_reply_t_tojson,
  .fromjson = vl_api_l2fib_add_del_reply_t_fromjson,
  .calc_size = vl_api_l2fib_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_WANT_L2_MACS_EVENTS2 + msg_id_base,
   .name = "want_l2_macs_events2",
   .handler = vl_api_want_l2_macs_events2_t_handler,
   .endian = vl_api_want_l2_macs_events2_t_endian,
   .format_fn = vl_api_want_l2_macs_events2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_want_l2_macs_events2_t_tojson,
   .fromjson = vl_api_want_l2_macs_events2_t_fromjson,
   .calc_size = vl_api_want_l2_macs_events2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_WANT_L2_MACS_EVENTS2_REPLY + msg_id_base,
  .name = "want_l2_macs_events2_reply",
  .handler = 0,
  .endian = vl_api_want_l2_macs_events2_reply_t_endian,
  .format_fn = vl_api_want_l2_macs_events2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_want_l2_macs_events2_reply_t_tojson,
  .fromjson = vl_api_want_l2_macs_events2_reply_t_fromjson,
  .calc_size = vl_api_want_l2_macs_events2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L2FIB_SET_SCAN_DELAY + msg_id_base,
   .name = "l2fib_set_scan_delay",
   .handler = vl_api_l2fib_set_scan_delay_t_handler,
   .endian = vl_api_l2fib_set_scan_delay_t_endian,
   .format_fn = vl_api_l2fib_set_scan_delay_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l2fib_set_scan_delay_t_tojson,
   .fromjson = vl_api_l2fib_set_scan_delay_t_fromjson,
   .calc_size = vl_api_l2fib_set_scan_delay_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L2FIB_SET_SCAN_DELAY_REPLY + msg_id_base,
  .name = "l2fib_set_scan_delay_reply",
  .handler = 0,
  .endian = vl_api_l2fib_set_scan_delay_reply_t_endian,
  .format_fn = vl_api_l2fib_set_scan_delay_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l2fib_set_scan_delay_reply_t_tojson,
  .fromjson = vl_api_l2fib_set_scan_delay_reply_t_fromjson,
  .calc_size = vl_api_l2fib_set_scan_delay_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L2_FLAGS + msg_id_base,
   .name = "l2_flags",
   .handler = vl_api_l2_flags_t_handler,
   .endian = vl_api_l2_flags_t_endian,
   .format_fn = vl_api_l2_flags_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l2_flags_t_tojson,
   .fromjson = vl_api_l2_flags_t_fromjson,
   .calc_size = vl_api_l2_flags_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L2_FLAGS_REPLY + msg_id_base,
  .name = "l2_flags_reply",
  .handler = 0,
  .endian = vl_api_l2_flags_reply_t_endian,
  .format_fn = vl_api_l2_flags_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l2_flags_reply_t_tojson,
  .fromjson = vl_api_l2_flags_reply_t_fromjson,
  .calc_size = vl_api_l2_flags_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BRIDGE_DOMAIN_SET_MAC_AGE + msg_id_base,
   .name = "bridge_domain_set_mac_age",
   .handler = vl_api_bridge_domain_set_mac_age_t_handler,
   .endian = vl_api_bridge_domain_set_mac_age_t_endian,
   .format_fn = vl_api_bridge_domain_set_mac_age_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bridge_domain_set_mac_age_t_tojson,
   .fromjson = vl_api_bridge_domain_set_mac_age_t_fromjson,
   .calc_size = vl_api_bridge_domain_set_mac_age_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BRIDGE_DOMAIN_SET_MAC_AGE_REPLY + msg_id_base,
  .name = "bridge_domain_set_mac_age_reply",
  .handler = 0,
  .endian = vl_api_bridge_domain_set_mac_age_reply_t_endian,
  .format_fn = vl_api_bridge_domain_set_mac_age_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bridge_domain_set_mac_age_reply_t_tojson,
  .fromjson = vl_api_bridge_domain_set_mac_age_reply_t_fromjson,
  .calc_size = vl_api_bridge_domain_set_mac_age_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BRIDGE_DOMAIN_SET_DEFAULT_LEARN_LIMIT + msg_id_base,
   .name = "bridge_domain_set_default_learn_limit",
   .handler = vl_api_bridge_domain_set_default_learn_limit_t_handler,
   .endian = vl_api_bridge_domain_set_default_learn_limit_t_endian,
   .format_fn = vl_api_bridge_domain_set_default_learn_limit_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bridge_domain_set_default_learn_limit_t_tojson,
   .fromjson = vl_api_bridge_domain_set_default_learn_limit_t_fromjson,
   .calc_size = vl_api_bridge_domain_set_default_learn_limit_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BRIDGE_DOMAIN_SET_DEFAULT_LEARN_LIMIT_REPLY + msg_id_base,
  .name = "bridge_domain_set_default_learn_limit_reply",
  .handler = 0,
  .endian = vl_api_bridge_domain_set_default_learn_limit_reply_t_endian,
  .format_fn = vl_api_bridge_domain_set_default_learn_limit_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bridge_domain_set_default_learn_limit_reply_t_tojson,
  .fromjson = vl_api_bridge_domain_set_default_learn_limit_reply_t_fromjson,
  .calc_size = vl_api_bridge_domain_set_default_learn_limit_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BRIDGE_DOMAIN_SET_LEARN_LIMIT + msg_id_base,
   .name = "bridge_domain_set_learn_limit",
   .handler = vl_api_bridge_domain_set_learn_limit_t_handler,
   .endian = vl_api_bridge_domain_set_learn_limit_t_endian,
   .format_fn = vl_api_bridge_domain_set_learn_limit_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bridge_domain_set_learn_limit_t_tojson,
   .fromjson = vl_api_bridge_domain_set_learn_limit_t_fromjson,
   .calc_size = vl_api_bridge_domain_set_learn_limit_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BRIDGE_DOMAIN_SET_LEARN_LIMIT_REPLY + msg_id_base,
  .name = "bridge_domain_set_learn_limit_reply",
  .handler = 0,
  .endian = vl_api_bridge_domain_set_learn_limit_reply_t_endian,
  .format_fn = vl_api_bridge_domain_set_learn_limit_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bridge_domain_set_learn_limit_reply_t_tojson,
  .fromjson = vl_api_bridge_domain_set_learn_limit_reply_t_fromjson,
  .calc_size = vl_api_bridge_domain_set_learn_limit_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BRIDGE_DOMAIN_ADD_DEL + msg_id_base,
   .name = "bridge_domain_add_del",
   .handler = vl_api_bridge_domain_add_del_t_handler,
   .endian = vl_api_bridge_domain_add_del_t_endian,
   .format_fn = vl_api_bridge_domain_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bridge_domain_add_del_t_tojson,
   .fromjson = vl_api_bridge_domain_add_del_t_fromjson,
   .calc_size = vl_api_bridge_domain_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BRIDGE_DOMAIN_ADD_DEL_REPLY + msg_id_base,
  .name = "bridge_domain_add_del_reply",
  .handler = 0,
  .endian = vl_api_bridge_domain_add_del_reply_t_endian,
  .format_fn = vl_api_bridge_domain_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bridge_domain_add_del_reply_t_tojson,
  .fromjson = vl_api_bridge_domain_add_del_reply_t_fromjson,
  .calc_size = vl_api_bridge_domain_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BRIDGE_DOMAIN_ADD_DEL_V2 + msg_id_base,
   .name = "bridge_domain_add_del_v2",
   .handler = vl_api_bridge_domain_add_del_v2_t_handler,
   .endian = vl_api_bridge_domain_add_del_v2_t_endian,
   .format_fn = vl_api_bridge_domain_add_del_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bridge_domain_add_del_v2_t_tojson,
   .fromjson = vl_api_bridge_domain_add_del_v2_t_fromjson,
   .calc_size = vl_api_bridge_domain_add_del_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BRIDGE_DOMAIN_ADD_DEL_V2_REPLY + msg_id_base,
  .name = "bridge_domain_add_del_v2_reply",
  .handler = 0,
  .endian = vl_api_bridge_domain_add_del_v2_reply_t_endian,
  .format_fn = vl_api_bridge_domain_add_del_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bridge_domain_add_del_v2_reply_t_tojson,
  .fromjson = vl_api_bridge_domain_add_del_v2_reply_t_fromjson,
  .calc_size = vl_api_bridge_domain_add_del_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BRIDGE_DOMAIN_DUMP + msg_id_base,
   .name = "bridge_domain_dump",
   .handler = vl_api_bridge_domain_dump_t_handler,
   .endian = vl_api_bridge_domain_dump_t_endian,
   .format_fn = vl_api_bridge_domain_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bridge_domain_dump_t_tojson,
   .fromjson = vl_api_bridge_domain_dump_t_fromjson,
   .calc_size = vl_api_bridge_domain_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BRIDGE_DOMAIN_DETAILS + msg_id_base,
  .name = "bridge_domain_details",
  .handler = 0,
  .endian = vl_api_bridge_domain_details_t_endian,
  .format_fn = vl_api_bridge_domain_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bridge_domain_details_t_tojson,
  .fromjson = vl_api_bridge_domain_details_t_fromjson,
  .calc_size = vl_api_bridge_domain_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BRIDGE_FLAGS + msg_id_base,
   .name = "bridge_flags",
   .handler = vl_api_bridge_flags_t_handler,
   .endian = vl_api_bridge_flags_t_endian,
   .format_fn = vl_api_bridge_flags_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bridge_flags_t_tojson,
   .fromjson = vl_api_bridge_flags_t_fromjson,
   .calc_size = vl_api_bridge_flags_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BRIDGE_FLAGS_REPLY + msg_id_base,
  .name = "bridge_flags_reply",
  .handler = 0,
  .endian = vl_api_bridge_flags_reply_t_endian,
  .format_fn = vl_api_bridge_flags_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bridge_flags_reply_t_tojson,
  .fromjson = vl_api_bridge_flags_reply_t_fromjson,
  .calc_size = vl_api_bridge_flags_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L2_INTERFACE_VLAN_TAG_REWRITE + msg_id_base,
   .name = "l2_interface_vlan_tag_rewrite",
   .handler = vl_api_l2_interface_vlan_tag_rewrite_t_handler,
   .endian = vl_api_l2_interface_vlan_tag_rewrite_t_endian,
   .format_fn = vl_api_l2_interface_vlan_tag_rewrite_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l2_interface_vlan_tag_rewrite_t_tojson,
   .fromjson = vl_api_l2_interface_vlan_tag_rewrite_t_fromjson,
   .calc_size = vl_api_l2_interface_vlan_tag_rewrite_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L2_INTERFACE_VLAN_TAG_REWRITE_REPLY + msg_id_base,
  .name = "l2_interface_vlan_tag_rewrite_reply",
  .handler = 0,
  .endian = vl_api_l2_interface_vlan_tag_rewrite_reply_t_endian,
  .format_fn = vl_api_l2_interface_vlan_tag_rewrite_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l2_interface_vlan_tag_rewrite_reply_t_tojson,
  .fromjson = vl_api_l2_interface_vlan_tag_rewrite_reply_t_fromjson,
  .calc_size = vl_api_l2_interface_vlan_tag_rewrite_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L2_INTERFACE_PBB_TAG_REWRITE + msg_id_base,
   .name = "l2_interface_pbb_tag_rewrite",
   .handler = vl_api_l2_interface_pbb_tag_rewrite_t_handler,
   .endian = vl_api_l2_interface_pbb_tag_rewrite_t_endian,
   .format_fn = vl_api_l2_interface_pbb_tag_rewrite_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l2_interface_pbb_tag_rewrite_t_tojson,
   .fromjson = vl_api_l2_interface_pbb_tag_rewrite_t_fromjson,
   .calc_size = vl_api_l2_interface_pbb_tag_rewrite_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L2_INTERFACE_PBB_TAG_REWRITE_REPLY + msg_id_base,
  .name = "l2_interface_pbb_tag_rewrite_reply",
  .handler = 0,
  .endian = vl_api_l2_interface_pbb_tag_rewrite_reply_t_endian,
  .format_fn = vl_api_l2_interface_pbb_tag_rewrite_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l2_interface_pbb_tag_rewrite_reply_t_tojson,
  .fromjson = vl_api_l2_interface_pbb_tag_rewrite_reply_t_fromjson,
  .calc_size = vl_api_l2_interface_pbb_tag_rewrite_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L2_PATCH_ADD_DEL + msg_id_base,
   .name = "l2_patch_add_del",
   .handler = vl_api_l2_patch_add_del_t_handler,
   .endian = vl_api_l2_patch_add_del_t_endian,
   .format_fn = vl_api_l2_patch_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l2_patch_add_del_t_tojson,
   .fromjson = vl_api_l2_patch_add_del_t_fromjson,
   .calc_size = vl_api_l2_patch_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L2_PATCH_ADD_DEL_REPLY + msg_id_base,
  .name = "l2_patch_add_del_reply",
  .handler = 0,
  .endian = vl_api_l2_patch_add_del_reply_t_endian,
  .format_fn = vl_api_l2_patch_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l2_patch_add_del_reply_t_tojson,
  .fromjson = vl_api_l2_patch_add_del_reply_t_fromjson,
  .calc_size = vl_api_l2_patch_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SET_L2_XCONNECT + msg_id_base,
   .name = "sw_interface_set_l2_xconnect",
   .handler = vl_api_sw_interface_set_l2_xconnect_t_handler,
   .endian = vl_api_sw_interface_set_l2_xconnect_t_endian,
   .format_fn = vl_api_sw_interface_set_l2_xconnect_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_set_l2_xconnect_t_tojson,
   .fromjson = vl_api_sw_interface_set_l2_xconnect_t_fromjson,
   .calc_size = vl_api_sw_interface_set_l2_xconnect_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SET_L2_XCONNECT_REPLY + msg_id_base,
  .name = "sw_interface_set_l2_xconnect_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_set_l2_xconnect_reply_t_endian,
  .format_fn = vl_api_sw_interface_set_l2_xconnect_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_set_l2_xconnect_reply_t_tojson,
  .fromjson = vl_api_sw_interface_set_l2_xconnect_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_set_l2_xconnect_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SET_L2_BRIDGE + msg_id_base,
   .name = "sw_interface_set_l2_bridge",
   .handler = vl_api_sw_interface_set_l2_bridge_t_handler,
   .endian = vl_api_sw_interface_set_l2_bridge_t_endian,
   .format_fn = vl_api_sw_interface_set_l2_bridge_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_set_l2_bridge_t_tojson,
   .fromjson = vl_api_sw_interface_set_l2_bridge_t_fromjson,
   .calc_size = vl_api_sw_interface_set_l2_bridge_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SET_L2_BRIDGE_REPLY + msg_id_base,
  .name = "sw_interface_set_l2_bridge_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_set_l2_bridge_reply_t_endian,
  .format_fn = vl_api_sw_interface_set_l2_bridge_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_set_l2_bridge_reply_t_tojson,
  .fromjson = vl_api_sw_interface_set_l2_bridge_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_set_l2_bridge_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BD_IP_MAC_ADD_DEL + msg_id_base,
   .name = "bd_ip_mac_add_del",
   .handler = vl_api_bd_ip_mac_add_del_t_handler,
   .endian = vl_api_bd_ip_mac_add_del_t_endian,
   .format_fn = vl_api_bd_ip_mac_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bd_ip_mac_add_del_t_tojson,
   .fromjson = vl_api_bd_ip_mac_add_del_t_fromjson,
   .calc_size = vl_api_bd_ip_mac_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BD_IP_MAC_ADD_DEL_REPLY + msg_id_base,
  .name = "bd_ip_mac_add_del_reply",
  .handler = 0,
  .endian = vl_api_bd_ip_mac_add_del_reply_t_endian,
  .format_fn = vl_api_bd_ip_mac_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bd_ip_mac_add_del_reply_t_tojson,
  .fromjson = vl_api_bd_ip_mac_add_del_reply_t_fromjson,
  .calc_size = vl_api_bd_ip_mac_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BD_IP_MAC_FLUSH + msg_id_base,
   .name = "bd_ip_mac_flush",
   .handler = vl_api_bd_ip_mac_flush_t_handler,
   .endian = vl_api_bd_ip_mac_flush_t_endian,
   .format_fn = vl_api_bd_ip_mac_flush_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bd_ip_mac_flush_t_tojson,
   .fromjson = vl_api_bd_ip_mac_flush_t_fromjson,
   .calc_size = vl_api_bd_ip_mac_flush_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BD_IP_MAC_FLUSH_REPLY + msg_id_base,
  .name = "bd_ip_mac_flush_reply",
  .handler = 0,
  .endian = vl_api_bd_ip_mac_flush_reply_t_endian,
  .format_fn = vl_api_bd_ip_mac_flush_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bd_ip_mac_flush_reply_t_tojson,
  .fromjson = vl_api_bd_ip_mac_flush_reply_t_fromjson,
  .calc_size = vl_api_bd_ip_mac_flush_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BD_IP_MAC_DUMP + msg_id_base,
   .name = "bd_ip_mac_dump",
   .handler = vl_api_bd_ip_mac_dump_t_handler,
   .endian = vl_api_bd_ip_mac_dump_t_endian,
   .format_fn = vl_api_bd_ip_mac_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bd_ip_mac_dump_t_tojson,
   .fromjson = vl_api_bd_ip_mac_dump_t_fromjson,
   .calc_size = vl_api_bd_ip_mac_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BD_IP_MAC_DETAILS + msg_id_base,
  .name = "bd_ip_mac_details",
  .handler = 0,
  .endian = vl_api_bd_ip_mac_details_t_endian,
  .format_fn = vl_api_bd_ip_mac_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bd_ip_mac_details_t_tojson,
  .fromjson = vl_api_bd_ip_mac_details_t_fromjson,
  .calc_size = vl_api_bd_ip_mac_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L2_INTERFACE_EFP_FILTER + msg_id_base,
   .name = "l2_interface_efp_filter",
   .handler = vl_api_l2_interface_efp_filter_t_handler,
   .endian = vl_api_l2_interface_efp_filter_t_endian,
   .format_fn = vl_api_l2_interface_efp_filter_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l2_interface_efp_filter_t_tojson,
   .fromjson = vl_api_l2_interface_efp_filter_t_fromjson,
   .calc_size = vl_api_l2_interface_efp_filter_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L2_INTERFACE_EFP_FILTER_REPLY + msg_id_base,
  .name = "l2_interface_efp_filter_reply",
  .handler = 0,
  .endian = vl_api_l2_interface_efp_filter_reply_t_endian,
  .format_fn = vl_api_l2_interface_efp_filter_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l2_interface_efp_filter_reply_t_tojson,
  .fromjson = vl_api_l2_interface_efp_filter_reply_t_fromjson,
  .calc_size = vl_api_l2_interface_efp_filter_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SET_VPATH + msg_id_base,
   .name = "sw_interface_set_vpath",
   .handler = vl_api_sw_interface_set_vpath_t_handler,
   .endian = vl_api_sw_interface_set_vpath_t_endian,
   .format_fn = vl_api_sw_interface_set_vpath_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_set_vpath_t_tojson,
   .fromjson = vl_api_sw_interface_set_vpath_t_fromjson,
   .calc_size = vl_api_sw_interface_set_vpath_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SET_VPATH_REPLY + msg_id_base,
  .name = "sw_interface_set_vpath_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_set_vpath_reply_t_endian,
  .format_fn = vl_api_sw_interface_set_vpath_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_set_vpath_reply_t_tojson,
  .fromjson = vl_api_sw_interface_set_vpath_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_set_vpath_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BVI_CREATE + msg_id_base,
   .name = "bvi_create",
   .handler = vl_api_bvi_create_t_handler,
   .endian = vl_api_bvi_create_t_endian,
   .format_fn = vl_api_bvi_create_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bvi_create_t_tojson,
   .fromjson = vl_api_bvi_create_t_fromjson,
   .calc_size = vl_api_bvi_create_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BVI_CREATE_REPLY + msg_id_base,
  .name = "bvi_create_reply",
  .handler = 0,
  .endian = vl_api_bvi_create_reply_t_endian,
  .format_fn = vl_api_bvi_create_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bvi_create_reply_t_tojson,
  .fromjson = vl_api_bvi_create_reply_t_fromjson,
  .calc_size = vl_api_bvi_create_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BVI_DELETE + msg_id_base,
   .name = "bvi_delete",
   .handler = vl_api_bvi_delete_t_handler,
   .endian = vl_api_bvi_delete_t_endian,
   .format_fn = vl_api_bvi_delete_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bvi_delete_t_tojson,
   .fromjson = vl_api_bvi_delete_t_fromjson,
   .calc_size = vl_api_bvi_delete_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BVI_DELETE_REPLY + msg_id_base,
  .name = "bvi_delete_reply",
  .handler = 0,
  .endian = vl_api_bvi_delete_reply_t_endian,
  .format_fn = vl_api_bvi_delete_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bvi_delete_reply_t_tojson,
  .fromjson = vl_api_bvi_delete_reply_t_fromjson,
  .calc_size = vl_api_bvi_delete_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
