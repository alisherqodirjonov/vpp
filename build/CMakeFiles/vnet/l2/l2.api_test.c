#define vl_endianfun            /* define message structures */
#include "l2.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "l2.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "l2.api.h"
#undef vl_printfun

#ifndef VL_API_WANT_L2_MACS_EVENTS_REPLY_T_HANDLER
static void
vl_api_want_l2_macs_events_reply_t_handler (vl_api_want_l2_macs_events_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
static void
vl_api_l2_macs_event_t_handler (vl_api_l2_macs_event_t * mp) {
    vlib_cli_output(0, "l2_macs_event event called:");
    vlib_cli_output(0, "%U", vl_api_l2_macs_event_t_format, mp);
}
#ifndef VL_API_WANT_L2_ARP_TERM_EVENTS_REPLY_T_HANDLER
static void
vl_api_want_l2_arp_term_events_reply_t_handler (vl_api_want_l2_arp_term_events_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
static void
vl_api_l2_arp_term_event_t_handler (vl_api_l2_arp_term_event_t * mp) {
    vlib_cli_output(0, "l2_arp_term_event event called:");
    vlib_cli_output(0, "%U", vl_api_l2_arp_term_event_t_format, mp);
}
/* Generation not supported (vl_api_l2_xconnect_details_t_handler()) */
/* Generation not supported (vl_api_l2_fib_table_details_t_handler()) */
#ifndef VL_API_L2_FIB_CLEAR_TABLE_REPLY_T_HANDLER
static void
vl_api_l2_fib_clear_table_reply_t_handler (vl_api_l2_fib_clear_table_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_L2FIB_FLUSH_ALL_REPLY_T_HANDLER
static void
vl_api_l2fib_flush_all_reply_t_handler (vl_api_l2fib_flush_all_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_L2FIB_FLUSH_BD_REPLY_T_HANDLER
static void
vl_api_l2fib_flush_bd_reply_t_handler (vl_api_l2fib_flush_bd_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_L2FIB_FLUSH_INT_REPLY_T_HANDLER
static void
vl_api_l2fib_flush_int_reply_t_handler (vl_api_l2fib_flush_int_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_L2FIB_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_l2fib_add_del_reply_t_handler (vl_api_l2fib_add_del_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_WANT_L2_MACS_EVENTS2_REPLY_T_HANDLER
static void
vl_api_want_l2_macs_events2_reply_t_handler (vl_api_want_l2_macs_events2_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_L2FIB_SET_SCAN_DELAY_REPLY_T_HANDLER
static void
vl_api_l2fib_set_scan_delay_reply_t_handler (vl_api_l2fib_set_scan_delay_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_l2_flags_reply_t_handler()) */
#ifndef VL_API_BRIDGE_DOMAIN_SET_MAC_AGE_REPLY_T_HANDLER
static void
vl_api_bridge_domain_set_mac_age_reply_t_handler (vl_api_bridge_domain_set_mac_age_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_BRIDGE_DOMAIN_SET_DEFAULT_LEARN_LIMIT_REPLY_T_HANDLER
static void
vl_api_bridge_domain_set_default_learn_limit_reply_t_handler (vl_api_bridge_domain_set_default_learn_limit_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_BRIDGE_DOMAIN_SET_LEARN_LIMIT_REPLY_T_HANDLER
static void
vl_api_bridge_domain_set_learn_limit_reply_t_handler (vl_api_bridge_domain_set_learn_limit_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_BRIDGE_DOMAIN_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_bridge_domain_add_del_reply_t_handler (vl_api_bridge_domain_add_del_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_bridge_domain_add_del_v2_reply_t_handler()) */
/* Generation not supported (vl_api_bridge_domain_details_t_handler()) */
/* Generation not supported (vl_api_bridge_flags_reply_t_handler()) */
#ifndef VL_API_L2_INTERFACE_VLAN_TAG_REWRITE_REPLY_T_HANDLER
static void
vl_api_l2_interface_vlan_tag_rewrite_reply_t_handler (vl_api_l2_interface_vlan_tag_rewrite_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_L2_INTERFACE_PBB_TAG_REWRITE_REPLY_T_HANDLER
static void
vl_api_l2_interface_pbb_tag_rewrite_reply_t_handler (vl_api_l2_interface_pbb_tag_rewrite_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_L2_PATCH_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_l2_patch_add_del_reply_t_handler (vl_api_l2_patch_add_del_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SW_INTERFACE_SET_L2_XCONNECT_REPLY_T_HANDLER
static void
vl_api_sw_interface_set_l2_xconnect_reply_t_handler (vl_api_sw_interface_set_l2_xconnect_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SW_INTERFACE_SET_L2_BRIDGE_REPLY_T_HANDLER
static void
vl_api_sw_interface_set_l2_bridge_reply_t_handler (vl_api_sw_interface_set_l2_bridge_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_BD_IP_MAC_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_bd_ip_mac_add_del_reply_t_handler (vl_api_bd_ip_mac_add_del_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_BD_IP_MAC_FLUSH_REPLY_T_HANDLER
static void
vl_api_bd_ip_mac_flush_reply_t_handler (vl_api_bd_ip_mac_flush_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_bd_ip_mac_details_t_handler()) */
#ifndef VL_API_L2_INTERFACE_EFP_FILTER_REPLY_T_HANDLER
static void
vl_api_l2_interface_efp_filter_reply_t_handler (vl_api_l2_interface_efp_filter_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SW_INTERFACE_SET_VPATH_REPLY_T_HANDLER
static void
vl_api_sw_interface_set_vpath_reply_t_handler (vl_api_sw_interface_set_vpath_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_bvi_create_reply_t_handler()) */
#ifndef VL_API_BVI_DELETE_REPLY_T_HANDLER
static void
vl_api_bvi_delete_reply_t_handler (vl_api_bvi_delete_reply_t * mp) {
   vat_main_t * vam = l2_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_WANT_L2_MACS_EVENTS_REPLY + msg_id_base,
    .name = "want_l2_macs_events_reply",
    .handler = vl_api_want_l2_macs_events_reply_t_handler,
    .endian = vl_api_want_l2_macs_events_reply_t_endian,
    .format_fn = vl_api_want_l2_macs_events_reply_t_format,
    .size = sizeof(vl_api_want_l2_macs_events_reply_t),
    .traced = 1,
    .tojson = vl_api_want_l2_macs_events_reply_t_tojson,
    .fromjson = vl_api_want_l2_macs_events_reply_t_fromjson,
    .calc_size = vl_api_want_l2_macs_events_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "want_l2_macs_events", api_want_l2_macs_events);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_L2_MACS_EVENT + msg_id_base,
    .name = "l2_macs_event",
    .handler = vl_api_l2_macs_event_t_handler,
    .endian = vl_api_l2_macs_event_t_endian,
    .format_fn = vl_api_l2_macs_event_t_format,
    .size = sizeof(vl_api_l2_macs_event_t),
    .traced = 1,
    .tojson = vl_api_l2_macs_event_t_tojson,
    .fromjson = vl_api_l2_macs_event_t_fromjson,
    .calc_size = vl_api_l2_macs_event_t_calc_size,
   });   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_WANT_L2_ARP_TERM_EVENTS_REPLY + msg_id_base,
    .name = "want_l2_arp_term_events_reply",
    .handler = vl_api_want_l2_arp_term_events_reply_t_handler,
    .endian = vl_api_want_l2_arp_term_events_reply_t_endian,
    .format_fn = vl_api_want_l2_arp_term_events_reply_t_format,
    .size = sizeof(vl_api_want_l2_arp_term_events_reply_t),
    .traced = 1,
    .tojson = vl_api_want_l2_arp_term_events_reply_t_tojson,
    .fromjson = vl_api_want_l2_arp_term_events_reply_t_fromjson,
    .calc_size = vl_api_want_l2_arp_term_events_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "want_l2_arp_term_events", api_want_l2_arp_term_events);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_L2_ARP_TERM_EVENT + msg_id_base,
    .name = "l2_arp_term_event",
    .handler = vl_api_l2_arp_term_event_t_handler,
    .endian = vl_api_l2_arp_term_event_t_endian,
    .format_fn = vl_api_l2_arp_term_event_t_format,
    .size = sizeof(vl_api_l2_arp_term_event_t),
    .traced = 1,
    .tojson = vl_api_l2_arp_term_event_t_tojson,
    .fromjson = vl_api_l2_arp_term_event_t_fromjson,
    .calc_size = vl_api_l2_arp_term_event_t_calc_size,
   });   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_L2_XCONNECT_DETAILS + msg_id_base,
    .name = "l2_xconnect_details",
    .handler = vl_api_l2_xconnect_details_t_handler,
    .endian = vl_api_l2_xconnect_details_t_endian,
    .format_fn = vl_api_l2_xconnect_details_t_format,
    .size = sizeof(vl_api_l2_xconnect_details_t),
    .traced = 1,
    .tojson = vl_api_l2_xconnect_details_t_tojson,
    .fromjson = vl_api_l2_xconnect_details_t_fromjson,
    .calc_size = vl_api_l2_xconnect_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "l2_xconnect_dump", api_l2_xconnect_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_L2_FIB_TABLE_DETAILS + msg_id_base,
    .name = "l2_fib_table_details",
    .handler = vl_api_l2_fib_table_details_t_handler,
    .endian = vl_api_l2_fib_table_details_t_endian,
    .format_fn = vl_api_l2_fib_table_details_t_format,
    .size = sizeof(vl_api_l2_fib_table_details_t),
    .traced = 1,
    .tojson = vl_api_l2_fib_table_details_t_tojson,
    .fromjson = vl_api_l2_fib_table_details_t_fromjson,
    .calc_size = vl_api_l2_fib_table_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "l2_fib_table_dump", api_l2_fib_table_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_L2_FIB_CLEAR_TABLE_REPLY + msg_id_base,
    .name = "l2_fib_clear_table_reply",
    .handler = vl_api_l2_fib_clear_table_reply_t_handler,
    .endian = vl_api_l2_fib_clear_table_reply_t_endian,
    .format_fn = vl_api_l2_fib_clear_table_reply_t_format,
    .size = sizeof(vl_api_l2_fib_clear_table_reply_t),
    .traced = 1,
    .tojson = vl_api_l2_fib_clear_table_reply_t_tojson,
    .fromjson = vl_api_l2_fib_clear_table_reply_t_fromjson,
    .calc_size = vl_api_l2_fib_clear_table_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "l2_fib_clear_table", api_l2_fib_clear_table);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_L2FIB_FLUSH_ALL_REPLY + msg_id_base,
    .name = "l2fib_flush_all_reply",
    .handler = vl_api_l2fib_flush_all_reply_t_handler,
    .endian = vl_api_l2fib_flush_all_reply_t_endian,
    .format_fn = vl_api_l2fib_flush_all_reply_t_format,
    .size = sizeof(vl_api_l2fib_flush_all_reply_t),
    .traced = 1,
    .tojson = vl_api_l2fib_flush_all_reply_t_tojson,
    .fromjson = vl_api_l2fib_flush_all_reply_t_fromjson,
    .calc_size = vl_api_l2fib_flush_all_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "l2fib_flush_all", api_l2fib_flush_all);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_L2FIB_FLUSH_BD_REPLY + msg_id_base,
    .name = "l2fib_flush_bd_reply",
    .handler = vl_api_l2fib_flush_bd_reply_t_handler,
    .endian = vl_api_l2fib_flush_bd_reply_t_endian,
    .format_fn = vl_api_l2fib_flush_bd_reply_t_format,
    .size = sizeof(vl_api_l2fib_flush_bd_reply_t),
    .traced = 1,
    .tojson = vl_api_l2fib_flush_bd_reply_t_tojson,
    .fromjson = vl_api_l2fib_flush_bd_reply_t_fromjson,
    .calc_size = vl_api_l2fib_flush_bd_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "l2fib_flush_bd", api_l2fib_flush_bd);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_L2FIB_FLUSH_INT_REPLY + msg_id_base,
    .name = "l2fib_flush_int_reply",
    .handler = vl_api_l2fib_flush_int_reply_t_handler,
    .endian = vl_api_l2fib_flush_int_reply_t_endian,
    .format_fn = vl_api_l2fib_flush_int_reply_t_format,
    .size = sizeof(vl_api_l2fib_flush_int_reply_t),
    .traced = 1,
    .tojson = vl_api_l2fib_flush_int_reply_t_tojson,
    .fromjson = vl_api_l2fib_flush_int_reply_t_fromjson,
    .calc_size = vl_api_l2fib_flush_int_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "l2fib_flush_int", api_l2fib_flush_int);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_L2FIB_ADD_DEL_REPLY + msg_id_base,
    .name = "l2fib_add_del_reply",
    .handler = vl_api_l2fib_add_del_reply_t_handler,
    .endian = vl_api_l2fib_add_del_reply_t_endian,
    .format_fn = vl_api_l2fib_add_del_reply_t_format,
    .size = sizeof(vl_api_l2fib_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_l2fib_add_del_reply_t_tojson,
    .fromjson = vl_api_l2fib_add_del_reply_t_fromjson,
    .calc_size = vl_api_l2fib_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "l2fib_add_del", api_l2fib_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_WANT_L2_MACS_EVENTS2_REPLY + msg_id_base,
    .name = "want_l2_macs_events2_reply",
    .handler = vl_api_want_l2_macs_events2_reply_t_handler,
    .endian = vl_api_want_l2_macs_events2_reply_t_endian,
    .format_fn = vl_api_want_l2_macs_events2_reply_t_format,
    .size = sizeof(vl_api_want_l2_macs_events2_reply_t),
    .traced = 1,
    .tojson = vl_api_want_l2_macs_events2_reply_t_tojson,
    .fromjson = vl_api_want_l2_macs_events2_reply_t_fromjson,
    .calc_size = vl_api_want_l2_macs_events2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "want_l2_macs_events2", api_want_l2_macs_events2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_L2FIB_SET_SCAN_DELAY_REPLY + msg_id_base,
    .name = "l2fib_set_scan_delay_reply",
    .handler = vl_api_l2fib_set_scan_delay_reply_t_handler,
    .endian = vl_api_l2fib_set_scan_delay_reply_t_endian,
    .format_fn = vl_api_l2fib_set_scan_delay_reply_t_format,
    .size = sizeof(vl_api_l2fib_set_scan_delay_reply_t),
    .traced = 1,
    .tojson = vl_api_l2fib_set_scan_delay_reply_t_tojson,
    .fromjson = vl_api_l2fib_set_scan_delay_reply_t_fromjson,
    .calc_size = vl_api_l2fib_set_scan_delay_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "l2fib_set_scan_delay", api_l2fib_set_scan_delay);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_L2_FLAGS_REPLY + msg_id_base,
    .name = "l2_flags_reply",
    .handler = vl_api_l2_flags_reply_t_handler,
    .endian = vl_api_l2_flags_reply_t_endian,
    .format_fn = vl_api_l2_flags_reply_t_format,
    .size = sizeof(vl_api_l2_flags_reply_t),
    .traced = 1,
    .tojson = vl_api_l2_flags_reply_t_tojson,
    .fromjson = vl_api_l2_flags_reply_t_fromjson,
    .calc_size = vl_api_l2_flags_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "l2_flags", api_l2_flags);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BRIDGE_DOMAIN_SET_MAC_AGE_REPLY + msg_id_base,
    .name = "bridge_domain_set_mac_age_reply",
    .handler = vl_api_bridge_domain_set_mac_age_reply_t_handler,
    .endian = vl_api_bridge_domain_set_mac_age_reply_t_endian,
    .format_fn = vl_api_bridge_domain_set_mac_age_reply_t_format,
    .size = sizeof(vl_api_bridge_domain_set_mac_age_reply_t),
    .traced = 1,
    .tojson = vl_api_bridge_domain_set_mac_age_reply_t_tojson,
    .fromjson = vl_api_bridge_domain_set_mac_age_reply_t_fromjson,
    .calc_size = vl_api_bridge_domain_set_mac_age_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bridge_domain_set_mac_age", api_bridge_domain_set_mac_age);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BRIDGE_DOMAIN_SET_DEFAULT_LEARN_LIMIT_REPLY + msg_id_base,
    .name = "bridge_domain_set_default_learn_limit_reply",
    .handler = vl_api_bridge_domain_set_default_learn_limit_reply_t_handler,
    .endian = vl_api_bridge_domain_set_default_learn_limit_reply_t_endian,
    .format_fn = vl_api_bridge_domain_set_default_learn_limit_reply_t_format,
    .size = sizeof(vl_api_bridge_domain_set_default_learn_limit_reply_t),
    .traced = 1,
    .tojson = vl_api_bridge_domain_set_default_learn_limit_reply_t_tojson,
    .fromjson = vl_api_bridge_domain_set_default_learn_limit_reply_t_fromjson,
    .calc_size = vl_api_bridge_domain_set_default_learn_limit_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bridge_domain_set_default_learn_limit", api_bridge_domain_set_default_learn_limit);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BRIDGE_DOMAIN_SET_LEARN_LIMIT_REPLY + msg_id_base,
    .name = "bridge_domain_set_learn_limit_reply",
    .handler = vl_api_bridge_domain_set_learn_limit_reply_t_handler,
    .endian = vl_api_bridge_domain_set_learn_limit_reply_t_endian,
    .format_fn = vl_api_bridge_domain_set_learn_limit_reply_t_format,
    .size = sizeof(vl_api_bridge_domain_set_learn_limit_reply_t),
    .traced = 1,
    .tojson = vl_api_bridge_domain_set_learn_limit_reply_t_tojson,
    .fromjson = vl_api_bridge_domain_set_learn_limit_reply_t_fromjson,
    .calc_size = vl_api_bridge_domain_set_learn_limit_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bridge_domain_set_learn_limit", api_bridge_domain_set_learn_limit);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BRIDGE_DOMAIN_ADD_DEL_REPLY + msg_id_base,
    .name = "bridge_domain_add_del_reply",
    .handler = vl_api_bridge_domain_add_del_reply_t_handler,
    .endian = vl_api_bridge_domain_add_del_reply_t_endian,
    .format_fn = vl_api_bridge_domain_add_del_reply_t_format,
    .size = sizeof(vl_api_bridge_domain_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_bridge_domain_add_del_reply_t_tojson,
    .fromjson = vl_api_bridge_domain_add_del_reply_t_fromjson,
    .calc_size = vl_api_bridge_domain_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bridge_domain_add_del", api_bridge_domain_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BRIDGE_DOMAIN_ADD_DEL_V2_REPLY + msg_id_base,
    .name = "bridge_domain_add_del_v2_reply",
    .handler = vl_api_bridge_domain_add_del_v2_reply_t_handler,
    .endian = vl_api_bridge_domain_add_del_v2_reply_t_endian,
    .format_fn = vl_api_bridge_domain_add_del_v2_reply_t_format,
    .size = sizeof(vl_api_bridge_domain_add_del_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_bridge_domain_add_del_v2_reply_t_tojson,
    .fromjson = vl_api_bridge_domain_add_del_v2_reply_t_fromjson,
    .calc_size = vl_api_bridge_domain_add_del_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bridge_domain_add_del_v2", api_bridge_domain_add_del_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BRIDGE_DOMAIN_DETAILS + msg_id_base,
    .name = "bridge_domain_details",
    .handler = vl_api_bridge_domain_details_t_handler,
    .endian = vl_api_bridge_domain_details_t_endian,
    .format_fn = vl_api_bridge_domain_details_t_format,
    .size = sizeof(vl_api_bridge_domain_details_t),
    .traced = 1,
    .tojson = vl_api_bridge_domain_details_t_tojson,
    .fromjson = vl_api_bridge_domain_details_t_fromjson,
    .calc_size = vl_api_bridge_domain_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bridge_domain_dump", api_bridge_domain_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BRIDGE_FLAGS_REPLY + msg_id_base,
    .name = "bridge_flags_reply",
    .handler = vl_api_bridge_flags_reply_t_handler,
    .endian = vl_api_bridge_flags_reply_t_endian,
    .format_fn = vl_api_bridge_flags_reply_t_format,
    .size = sizeof(vl_api_bridge_flags_reply_t),
    .traced = 1,
    .tojson = vl_api_bridge_flags_reply_t_tojson,
    .fromjson = vl_api_bridge_flags_reply_t_fromjson,
    .calc_size = vl_api_bridge_flags_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bridge_flags", api_bridge_flags);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_L2_INTERFACE_VLAN_TAG_REWRITE_REPLY + msg_id_base,
    .name = "l2_interface_vlan_tag_rewrite_reply",
    .handler = vl_api_l2_interface_vlan_tag_rewrite_reply_t_handler,
    .endian = vl_api_l2_interface_vlan_tag_rewrite_reply_t_endian,
    .format_fn = vl_api_l2_interface_vlan_tag_rewrite_reply_t_format,
    .size = sizeof(vl_api_l2_interface_vlan_tag_rewrite_reply_t),
    .traced = 1,
    .tojson = vl_api_l2_interface_vlan_tag_rewrite_reply_t_tojson,
    .fromjson = vl_api_l2_interface_vlan_tag_rewrite_reply_t_fromjson,
    .calc_size = vl_api_l2_interface_vlan_tag_rewrite_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "l2_interface_vlan_tag_rewrite", api_l2_interface_vlan_tag_rewrite);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_L2_INTERFACE_PBB_TAG_REWRITE_REPLY + msg_id_base,
    .name = "l2_interface_pbb_tag_rewrite_reply",
    .handler = vl_api_l2_interface_pbb_tag_rewrite_reply_t_handler,
    .endian = vl_api_l2_interface_pbb_tag_rewrite_reply_t_endian,
    .format_fn = vl_api_l2_interface_pbb_tag_rewrite_reply_t_format,
    .size = sizeof(vl_api_l2_interface_pbb_tag_rewrite_reply_t),
    .traced = 1,
    .tojson = vl_api_l2_interface_pbb_tag_rewrite_reply_t_tojson,
    .fromjson = vl_api_l2_interface_pbb_tag_rewrite_reply_t_fromjson,
    .calc_size = vl_api_l2_interface_pbb_tag_rewrite_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "l2_interface_pbb_tag_rewrite", api_l2_interface_pbb_tag_rewrite);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_L2_PATCH_ADD_DEL_REPLY + msg_id_base,
    .name = "l2_patch_add_del_reply",
    .handler = vl_api_l2_patch_add_del_reply_t_handler,
    .endian = vl_api_l2_patch_add_del_reply_t_endian,
    .format_fn = vl_api_l2_patch_add_del_reply_t_format,
    .size = sizeof(vl_api_l2_patch_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_l2_patch_add_del_reply_t_tojson,
    .fromjson = vl_api_l2_patch_add_del_reply_t_fromjson,
    .calc_size = vl_api_l2_patch_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "l2_patch_add_del", api_l2_patch_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_SET_L2_XCONNECT_REPLY + msg_id_base,
    .name = "sw_interface_set_l2_xconnect_reply",
    .handler = vl_api_sw_interface_set_l2_xconnect_reply_t_handler,
    .endian = vl_api_sw_interface_set_l2_xconnect_reply_t_endian,
    .format_fn = vl_api_sw_interface_set_l2_xconnect_reply_t_format,
    .size = sizeof(vl_api_sw_interface_set_l2_xconnect_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_set_l2_xconnect_reply_t_tojson,
    .fromjson = vl_api_sw_interface_set_l2_xconnect_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_set_l2_xconnect_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_set_l2_xconnect", api_sw_interface_set_l2_xconnect);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_SET_L2_BRIDGE_REPLY + msg_id_base,
    .name = "sw_interface_set_l2_bridge_reply",
    .handler = vl_api_sw_interface_set_l2_bridge_reply_t_handler,
    .endian = vl_api_sw_interface_set_l2_bridge_reply_t_endian,
    .format_fn = vl_api_sw_interface_set_l2_bridge_reply_t_format,
    .size = sizeof(vl_api_sw_interface_set_l2_bridge_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_set_l2_bridge_reply_t_tojson,
    .fromjson = vl_api_sw_interface_set_l2_bridge_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_set_l2_bridge_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_set_l2_bridge", api_sw_interface_set_l2_bridge);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BD_IP_MAC_ADD_DEL_REPLY + msg_id_base,
    .name = "bd_ip_mac_add_del_reply",
    .handler = vl_api_bd_ip_mac_add_del_reply_t_handler,
    .endian = vl_api_bd_ip_mac_add_del_reply_t_endian,
    .format_fn = vl_api_bd_ip_mac_add_del_reply_t_format,
    .size = sizeof(vl_api_bd_ip_mac_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_bd_ip_mac_add_del_reply_t_tojson,
    .fromjson = vl_api_bd_ip_mac_add_del_reply_t_fromjson,
    .calc_size = vl_api_bd_ip_mac_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bd_ip_mac_add_del", api_bd_ip_mac_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BD_IP_MAC_FLUSH_REPLY + msg_id_base,
    .name = "bd_ip_mac_flush_reply",
    .handler = vl_api_bd_ip_mac_flush_reply_t_handler,
    .endian = vl_api_bd_ip_mac_flush_reply_t_endian,
    .format_fn = vl_api_bd_ip_mac_flush_reply_t_format,
    .size = sizeof(vl_api_bd_ip_mac_flush_reply_t),
    .traced = 1,
    .tojson = vl_api_bd_ip_mac_flush_reply_t_tojson,
    .fromjson = vl_api_bd_ip_mac_flush_reply_t_fromjson,
    .calc_size = vl_api_bd_ip_mac_flush_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bd_ip_mac_flush", api_bd_ip_mac_flush);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BD_IP_MAC_DETAILS + msg_id_base,
    .name = "bd_ip_mac_details",
    .handler = vl_api_bd_ip_mac_details_t_handler,
    .endian = vl_api_bd_ip_mac_details_t_endian,
    .format_fn = vl_api_bd_ip_mac_details_t_format,
    .size = sizeof(vl_api_bd_ip_mac_details_t),
    .traced = 1,
    .tojson = vl_api_bd_ip_mac_details_t_tojson,
    .fromjson = vl_api_bd_ip_mac_details_t_fromjson,
    .calc_size = vl_api_bd_ip_mac_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bd_ip_mac_dump", api_bd_ip_mac_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_L2_INTERFACE_EFP_FILTER_REPLY + msg_id_base,
    .name = "l2_interface_efp_filter_reply",
    .handler = vl_api_l2_interface_efp_filter_reply_t_handler,
    .endian = vl_api_l2_interface_efp_filter_reply_t_endian,
    .format_fn = vl_api_l2_interface_efp_filter_reply_t_format,
    .size = sizeof(vl_api_l2_interface_efp_filter_reply_t),
    .traced = 1,
    .tojson = vl_api_l2_interface_efp_filter_reply_t_tojson,
    .fromjson = vl_api_l2_interface_efp_filter_reply_t_fromjson,
    .calc_size = vl_api_l2_interface_efp_filter_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "l2_interface_efp_filter", api_l2_interface_efp_filter);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_SET_VPATH_REPLY + msg_id_base,
    .name = "sw_interface_set_vpath_reply",
    .handler = vl_api_sw_interface_set_vpath_reply_t_handler,
    .endian = vl_api_sw_interface_set_vpath_reply_t_endian,
    .format_fn = vl_api_sw_interface_set_vpath_reply_t_format,
    .size = sizeof(vl_api_sw_interface_set_vpath_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_set_vpath_reply_t_tojson,
    .fromjson = vl_api_sw_interface_set_vpath_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_set_vpath_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_set_vpath", api_sw_interface_set_vpath);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BVI_CREATE_REPLY + msg_id_base,
    .name = "bvi_create_reply",
    .handler = vl_api_bvi_create_reply_t_handler,
    .endian = vl_api_bvi_create_reply_t_endian,
    .format_fn = vl_api_bvi_create_reply_t_format,
    .size = sizeof(vl_api_bvi_create_reply_t),
    .traced = 1,
    .tojson = vl_api_bvi_create_reply_t_tojson,
    .fromjson = vl_api_bvi_create_reply_t_fromjson,
    .calc_size = vl_api_bvi_create_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bvi_create", api_bvi_create);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BVI_DELETE_REPLY + msg_id_base,
    .name = "bvi_delete_reply",
    .handler = vl_api_bvi_delete_reply_t_handler,
    .endian = vl_api_bvi_delete_reply_t_endian,
    .format_fn = vl_api_bvi_delete_reply_t_format,
    .size = sizeof(vl_api_bvi_delete_reply_t),
    .traced = 1,
    .tojson = vl_api_bvi_delete_reply_t_tojson,
    .fromjson = vl_api_bvi_delete_reply_t_fromjson,
    .calc_size = vl_api_bvi_delete_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bvi_delete", api_bvi_delete);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   l2_test_main_t * mainp = &l2_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("l2_90ecafc3");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "l2 plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
