#define vl_endianfun            /* define message structures */
#include "interface.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "interface.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "interface.api.h"
#undef vl_printfun

#ifndef VL_API_WANT_INTERFACE_EVENTS_REPLY_T_HANDLER
static void
vl_api_want_interface_events_reply_t_handler (vl_api_want_interface_events_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
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
vl_api_sw_interface_event_t_handler (vl_api_sw_interface_event_t * mp) {
    vlib_cli_output(0, "sw_interface_event event called:");
    vlib_cli_output(0, "%U", vl_api_sw_interface_event_t_format, mp);
}
/* Generation not supported (vl_api_sw_interface_tx_placement_get_reply_t_handler()) */
#ifndef VL_API_SW_INTERFACE_SET_FLAGS_REPLY_T_HANDLER
static void
vl_api_sw_interface_set_flags_reply_t_handler (vl_api_sw_interface_set_flags_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SW_INTERFACE_SET_PROMISC_REPLY_T_HANDLER
static void
vl_api_sw_interface_set_promisc_reply_t_handler (vl_api_sw_interface_set_promisc_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_HW_INTERFACE_SET_MTU_REPLY_T_HANDLER
static void
vl_api_hw_interface_set_mtu_reply_t_handler (vl_api_hw_interface_set_mtu_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SW_INTERFACE_SET_MTU_REPLY_T_HANDLER
static void
vl_api_sw_interface_set_mtu_reply_t_handler (vl_api_sw_interface_set_mtu_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SW_INTERFACE_SET_IP_DIRECTED_BROADCAST_REPLY_T_HANDLER
static void
vl_api_sw_interface_set_ip_directed_broadcast_reply_t_handler (vl_api_sw_interface_set_ip_directed_broadcast_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_sw_interface_details_t_handler()) */
#ifndef VL_API_SW_INTERFACE_ADD_DEL_ADDRESS_REPLY_T_HANDLER
static void
vl_api_sw_interface_add_del_address_reply_t_handler (vl_api_sw_interface_add_del_address_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SW_INTERFACE_ADDRESS_REPLACE_BEGIN_REPLY_T_HANDLER
static void
vl_api_sw_interface_address_replace_begin_reply_t_handler (vl_api_sw_interface_address_replace_begin_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SW_INTERFACE_ADDRESS_REPLACE_END_REPLY_T_HANDLER
static void
vl_api_sw_interface_address_replace_end_reply_t_handler (vl_api_sw_interface_address_replace_end_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SW_INTERFACE_SET_TABLE_REPLY_T_HANDLER
static void
vl_api_sw_interface_set_table_reply_t_handler (vl_api_sw_interface_set_table_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_sw_interface_get_table_reply_t_handler()) */
#ifndef VL_API_SW_INTERFACE_SET_UNNUMBERED_REPLY_T_HANDLER
static void
vl_api_sw_interface_set_unnumbered_reply_t_handler (vl_api_sw_interface_set_unnumbered_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SW_INTERFACE_CLEAR_STATS_REPLY_T_HANDLER
static void
vl_api_sw_interface_clear_stats_reply_t_handler (vl_api_sw_interface_clear_stats_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SW_INTERFACE_TAG_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_sw_interface_tag_add_del_reply_t_handler (vl_api_sw_interface_tag_add_del_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SW_INTERFACE_ADD_DEL_MAC_ADDRESS_REPLY_T_HANDLER
static void
vl_api_sw_interface_add_del_mac_address_reply_t_handler (vl_api_sw_interface_add_del_mac_address_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SW_INTERFACE_SET_MAC_ADDRESS_REPLY_T_HANDLER
static void
vl_api_sw_interface_set_mac_address_reply_t_handler (vl_api_sw_interface_set_mac_address_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_sw_interface_get_mac_address_reply_t_handler()) */
#ifndef VL_API_SW_INTERFACE_SET_RX_MODE_REPLY_T_HANDLER
static void
vl_api_sw_interface_set_rx_mode_reply_t_handler (vl_api_sw_interface_set_rx_mode_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SW_INTERFACE_SET_RX_PLACEMENT_REPLY_T_HANDLER
static void
vl_api_sw_interface_set_rx_placement_reply_t_handler (vl_api_sw_interface_set_rx_placement_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SW_INTERFACE_SET_TX_PLACEMENT_REPLY_T_HANDLER
static void
vl_api_sw_interface_set_tx_placement_reply_t_handler (vl_api_sw_interface_set_tx_placement_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SW_INTERFACE_SET_INTERFACE_NAME_REPLY_T_HANDLER
static void
vl_api_sw_interface_set_interface_name_reply_t_handler (vl_api_sw_interface_set_interface_name_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_sw_interface_rx_placement_details_t_handler()) */
#ifndef VL_API_INTERFACE_NAME_RENUMBER_REPLY_T_HANDLER
static void
vl_api_interface_name_renumber_reply_t_handler (vl_api_interface_name_renumber_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_create_subif_reply_t_handler()) */
/* Generation not supported (vl_api_create_vlan_subif_reply_t_handler()) */
#ifndef VL_API_DELETE_SUBIF_REPLY_T_HANDLER
static void
vl_api_delete_subif_reply_t_handler (vl_api_delete_subif_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_create_loopback_reply_t_handler()) */
/* Generation not supported (vl_api_create_loopback_instance_reply_t_handler()) */
#ifndef VL_API_DELETE_LOOPBACK_REPLY_T_HANDLER
static void
vl_api_delete_loopback_reply_t_handler (vl_api_delete_loopback_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_COLLECT_DETAILED_INTERFACE_STATS_REPLY_T_HANDLER
static void
vl_api_collect_detailed_interface_stats_reply_t_handler (vl_api_collect_detailed_interface_stats_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_PCAP_SET_FILTER_FUNCTION_REPLY_T_HANDLER
static void
vl_api_pcap_set_filter_function_reply_t_handler (vl_api_pcap_set_filter_function_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_PCAP_TRACE_ON_REPLY_T_HANDLER
static void
vl_api_pcap_trace_on_reply_t_handler (vl_api_pcap_trace_on_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_PCAP_TRACE_OFF_REPLY_T_HANDLER
static void
vl_api_pcap_trace_off_reply_t_handler (vl_api_pcap_trace_off_reply_t * mp) {
   vat_main_t * vam = interface_test_main.vat_main;
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
    .id = VL_API_WANT_INTERFACE_EVENTS_REPLY + msg_id_base,
    .name = "want_interface_events_reply",
    .handler = vl_api_want_interface_events_reply_t_handler,
    .endian = vl_api_want_interface_events_reply_t_endian,
    .format_fn = vl_api_want_interface_events_reply_t_format,
    .size = sizeof(vl_api_want_interface_events_reply_t),
    .traced = 1,
    .tojson = vl_api_want_interface_events_reply_t_tojson,
    .fromjson = vl_api_want_interface_events_reply_t_fromjson,
    .calc_size = vl_api_want_interface_events_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "want_interface_events", api_want_interface_events);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_EVENT + msg_id_base,
    .name = "sw_interface_event",
    .handler = vl_api_sw_interface_event_t_handler,
    .endian = vl_api_sw_interface_event_t_endian,
    .format_fn = vl_api_sw_interface_event_t_format,
    .size = sizeof(vl_api_sw_interface_event_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_event_t_tojson,
    .fromjson = vl_api_sw_interface_event_t_fromjson,
    .calc_size = vl_api_sw_interface_event_t_calc_size,
   });   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_TX_PLACEMENT_GET_REPLY + msg_id_base,
    .name = "sw_interface_tx_placement_get_reply",
    .handler = vl_api_sw_interface_tx_placement_get_reply_t_handler,
    .endian = vl_api_sw_interface_tx_placement_get_reply_t_endian,
    .format_fn = vl_api_sw_interface_tx_placement_get_reply_t_format,
    .size = sizeof(vl_api_sw_interface_tx_placement_get_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_tx_placement_get_reply_t_tojson,
    .fromjson = vl_api_sw_interface_tx_placement_get_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_tx_placement_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_tx_placement_get", api_sw_interface_tx_placement_get);
   hash_set_mem (vam->help_by_name, "sw_interface_tx_placement_get", "[interface | sw_if_index <index>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_SET_FLAGS_REPLY + msg_id_base,
    .name = "sw_interface_set_flags_reply",
    .handler = vl_api_sw_interface_set_flags_reply_t_handler,
    .endian = vl_api_sw_interface_set_flags_reply_t_endian,
    .format_fn = vl_api_sw_interface_set_flags_reply_t_format,
    .size = sizeof(vl_api_sw_interface_set_flags_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_set_flags_reply_t_tojson,
    .fromjson = vl_api_sw_interface_set_flags_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_set_flags_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_set_flags", api_sw_interface_set_flags);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_SET_PROMISC_REPLY + msg_id_base,
    .name = "sw_interface_set_promisc_reply",
    .handler = vl_api_sw_interface_set_promisc_reply_t_handler,
    .endian = vl_api_sw_interface_set_promisc_reply_t_endian,
    .format_fn = vl_api_sw_interface_set_promisc_reply_t_format,
    .size = sizeof(vl_api_sw_interface_set_promisc_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_set_promisc_reply_t_tojson,
    .fromjson = vl_api_sw_interface_set_promisc_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_set_promisc_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_set_promisc", api_sw_interface_set_promisc);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_HW_INTERFACE_SET_MTU_REPLY + msg_id_base,
    .name = "hw_interface_set_mtu_reply",
    .handler = vl_api_hw_interface_set_mtu_reply_t_handler,
    .endian = vl_api_hw_interface_set_mtu_reply_t_endian,
    .format_fn = vl_api_hw_interface_set_mtu_reply_t_format,
    .size = sizeof(vl_api_hw_interface_set_mtu_reply_t),
    .traced = 1,
    .tojson = vl_api_hw_interface_set_mtu_reply_t_tojson,
    .fromjson = vl_api_hw_interface_set_mtu_reply_t_fromjson,
    .calc_size = vl_api_hw_interface_set_mtu_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "hw_interface_set_mtu", api_hw_interface_set_mtu);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_SET_MTU_REPLY + msg_id_base,
    .name = "sw_interface_set_mtu_reply",
    .handler = vl_api_sw_interface_set_mtu_reply_t_handler,
    .endian = vl_api_sw_interface_set_mtu_reply_t_endian,
    .format_fn = vl_api_sw_interface_set_mtu_reply_t_format,
    .size = sizeof(vl_api_sw_interface_set_mtu_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_set_mtu_reply_t_tojson,
    .fromjson = vl_api_sw_interface_set_mtu_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_set_mtu_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_set_mtu", api_sw_interface_set_mtu);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_SET_IP_DIRECTED_BROADCAST_REPLY + msg_id_base,
    .name = "sw_interface_set_ip_directed_broadcast_reply",
    .handler = vl_api_sw_interface_set_ip_directed_broadcast_reply_t_handler,
    .endian = vl_api_sw_interface_set_ip_directed_broadcast_reply_t_endian,
    .format_fn = vl_api_sw_interface_set_ip_directed_broadcast_reply_t_format,
    .size = sizeof(vl_api_sw_interface_set_ip_directed_broadcast_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_set_ip_directed_broadcast_reply_t_tojson,
    .fromjson = vl_api_sw_interface_set_ip_directed_broadcast_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_set_ip_directed_broadcast_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_set_ip_directed_broadcast", api_sw_interface_set_ip_directed_broadcast);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_DETAILS + msg_id_base,
    .name = "sw_interface_details",
    .handler = vl_api_sw_interface_details_t_handler,
    .endian = vl_api_sw_interface_details_t_endian,
    .format_fn = vl_api_sw_interface_details_t_format,
    .size = sizeof(vl_api_sw_interface_details_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_details_t_tojson,
    .fromjson = vl_api_sw_interface_details_t_fromjson,
    .calc_size = vl_api_sw_interface_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_dump", api_sw_interface_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_ADD_DEL_ADDRESS_REPLY + msg_id_base,
    .name = "sw_interface_add_del_address_reply",
    .handler = vl_api_sw_interface_add_del_address_reply_t_handler,
    .endian = vl_api_sw_interface_add_del_address_reply_t_endian,
    .format_fn = vl_api_sw_interface_add_del_address_reply_t_format,
    .size = sizeof(vl_api_sw_interface_add_del_address_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_add_del_address_reply_t_tojson,
    .fromjson = vl_api_sw_interface_add_del_address_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_add_del_address_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_add_del_address", api_sw_interface_add_del_address);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_ADDRESS_REPLACE_BEGIN_REPLY + msg_id_base,
    .name = "sw_interface_address_replace_begin_reply",
    .handler = vl_api_sw_interface_address_replace_begin_reply_t_handler,
    .endian = vl_api_sw_interface_address_replace_begin_reply_t_endian,
    .format_fn = vl_api_sw_interface_address_replace_begin_reply_t_format,
    .size = sizeof(vl_api_sw_interface_address_replace_begin_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_address_replace_begin_reply_t_tojson,
    .fromjson = vl_api_sw_interface_address_replace_begin_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_address_replace_begin_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_address_replace_begin", api_sw_interface_address_replace_begin);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_ADDRESS_REPLACE_END_REPLY + msg_id_base,
    .name = "sw_interface_address_replace_end_reply",
    .handler = vl_api_sw_interface_address_replace_end_reply_t_handler,
    .endian = vl_api_sw_interface_address_replace_end_reply_t_endian,
    .format_fn = vl_api_sw_interface_address_replace_end_reply_t_format,
    .size = sizeof(vl_api_sw_interface_address_replace_end_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_address_replace_end_reply_t_tojson,
    .fromjson = vl_api_sw_interface_address_replace_end_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_address_replace_end_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_address_replace_end", api_sw_interface_address_replace_end);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_SET_TABLE_REPLY + msg_id_base,
    .name = "sw_interface_set_table_reply",
    .handler = vl_api_sw_interface_set_table_reply_t_handler,
    .endian = vl_api_sw_interface_set_table_reply_t_endian,
    .format_fn = vl_api_sw_interface_set_table_reply_t_format,
    .size = sizeof(vl_api_sw_interface_set_table_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_set_table_reply_t_tojson,
    .fromjson = vl_api_sw_interface_set_table_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_set_table_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_set_table", api_sw_interface_set_table);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_GET_TABLE_REPLY + msg_id_base,
    .name = "sw_interface_get_table_reply",
    .handler = vl_api_sw_interface_get_table_reply_t_handler,
    .endian = vl_api_sw_interface_get_table_reply_t_endian,
    .format_fn = vl_api_sw_interface_get_table_reply_t_format,
    .size = sizeof(vl_api_sw_interface_get_table_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_get_table_reply_t_tojson,
    .fromjson = vl_api_sw_interface_get_table_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_get_table_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_get_table", api_sw_interface_get_table);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_SET_UNNUMBERED_REPLY + msg_id_base,
    .name = "sw_interface_set_unnumbered_reply",
    .handler = vl_api_sw_interface_set_unnumbered_reply_t_handler,
    .endian = vl_api_sw_interface_set_unnumbered_reply_t_endian,
    .format_fn = vl_api_sw_interface_set_unnumbered_reply_t_format,
    .size = sizeof(vl_api_sw_interface_set_unnumbered_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_set_unnumbered_reply_t_tojson,
    .fromjson = vl_api_sw_interface_set_unnumbered_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_set_unnumbered_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_set_unnumbered", api_sw_interface_set_unnumbered);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_CLEAR_STATS_REPLY + msg_id_base,
    .name = "sw_interface_clear_stats_reply",
    .handler = vl_api_sw_interface_clear_stats_reply_t_handler,
    .endian = vl_api_sw_interface_clear_stats_reply_t_endian,
    .format_fn = vl_api_sw_interface_clear_stats_reply_t_format,
    .size = sizeof(vl_api_sw_interface_clear_stats_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_clear_stats_reply_t_tojson,
    .fromjson = vl_api_sw_interface_clear_stats_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_clear_stats_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_clear_stats", api_sw_interface_clear_stats);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_TAG_ADD_DEL_REPLY + msg_id_base,
    .name = "sw_interface_tag_add_del_reply",
    .handler = vl_api_sw_interface_tag_add_del_reply_t_handler,
    .endian = vl_api_sw_interface_tag_add_del_reply_t_endian,
    .format_fn = vl_api_sw_interface_tag_add_del_reply_t_format,
    .size = sizeof(vl_api_sw_interface_tag_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_tag_add_del_reply_t_tojson,
    .fromjson = vl_api_sw_interface_tag_add_del_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_tag_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_tag_add_del", api_sw_interface_tag_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_ADD_DEL_MAC_ADDRESS_REPLY + msg_id_base,
    .name = "sw_interface_add_del_mac_address_reply",
    .handler = vl_api_sw_interface_add_del_mac_address_reply_t_handler,
    .endian = vl_api_sw_interface_add_del_mac_address_reply_t_endian,
    .format_fn = vl_api_sw_interface_add_del_mac_address_reply_t_format,
    .size = sizeof(vl_api_sw_interface_add_del_mac_address_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_add_del_mac_address_reply_t_tojson,
    .fromjson = vl_api_sw_interface_add_del_mac_address_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_add_del_mac_address_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_add_del_mac_address", api_sw_interface_add_del_mac_address);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_SET_MAC_ADDRESS_REPLY + msg_id_base,
    .name = "sw_interface_set_mac_address_reply",
    .handler = vl_api_sw_interface_set_mac_address_reply_t_handler,
    .endian = vl_api_sw_interface_set_mac_address_reply_t_endian,
    .format_fn = vl_api_sw_interface_set_mac_address_reply_t_format,
    .size = sizeof(vl_api_sw_interface_set_mac_address_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_set_mac_address_reply_t_tojson,
    .fromjson = vl_api_sw_interface_set_mac_address_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_set_mac_address_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_set_mac_address", api_sw_interface_set_mac_address);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_GET_MAC_ADDRESS_REPLY + msg_id_base,
    .name = "sw_interface_get_mac_address_reply",
    .handler = vl_api_sw_interface_get_mac_address_reply_t_handler,
    .endian = vl_api_sw_interface_get_mac_address_reply_t_endian,
    .format_fn = vl_api_sw_interface_get_mac_address_reply_t_format,
    .size = sizeof(vl_api_sw_interface_get_mac_address_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_get_mac_address_reply_t_tojson,
    .fromjson = vl_api_sw_interface_get_mac_address_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_get_mac_address_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_get_mac_address", api_sw_interface_get_mac_address);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_SET_RX_MODE_REPLY + msg_id_base,
    .name = "sw_interface_set_rx_mode_reply",
    .handler = vl_api_sw_interface_set_rx_mode_reply_t_handler,
    .endian = vl_api_sw_interface_set_rx_mode_reply_t_endian,
    .format_fn = vl_api_sw_interface_set_rx_mode_reply_t_format,
    .size = sizeof(vl_api_sw_interface_set_rx_mode_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_set_rx_mode_reply_t_tojson,
    .fromjson = vl_api_sw_interface_set_rx_mode_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_set_rx_mode_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_set_rx_mode", api_sw_interface_set_rx_mode);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_SET_RX_PLACEMENT_REPLY + msg_id_base,
    .name = "sw_interface_set_rx_placement_reply",
    .handler = vl_api_sw_interface_set_rx_placement_reply_t_handler,
    .endian = vl_api_sw_interface_set_rx_placement_reply_t_endian,
    .format_fn = vl_api_sw_interface_set_rx_placement_reply_t_format,
    .size = sizeof(vl_api_sw_interface_set_rx_placement_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_set_rx_placement_reply_t_tojson,
    .fromjson = vl_api_sw_interface_set_rx_placement_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_set_rx_placement_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_set_rx_placement", api_sw_interface_set_rx_placement);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_SET_TX_PLACEMENT_REPLY + msg_id_base,
    .name = "sw_interface_set_tx_placement_reply",
    .handler = vl_api_sw_interface_set_tx_placement_reply_t_handler,
    .endian = vl_api_sw_interface_set_tx_placement_reply_t_endian,
    .format_fn = vl_api_sw_interface_set_tx_placement_reply_t_format,
    .size = sizeof(vl_api_sw_interface_set_tx_placement_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_set_tx_placement_reply_t_tojson,
    .fromjson = vl_api_sw_interface_set_tx_placement_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_set_tx_placement_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_set_tx_placement", api_sw_interface_set_tx_placement);
   hash_set_mem (vam->help_by_name, "sw_interface_set_tx_placement", "<interface | sw_if_index <index>> queue <n> [threads <list> | mask <hex>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_SET_INTERFACE_NAME_REPLY + msg_id_base,
    .name = "sw_interface_set_interface_name_reply",
    .handler = vl_api_sw_interface_set_interface_name_reply_t_handler,
    .endian = vl_api_sw_interface_set_interface_name_reply_t_endian,
    .format_fn = vl_api_sw_interface_set_interface_name_reply_t_format,
    .size = sizeof(vl_api_sw_interface_set_interface_name_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_set_interface_name_reply_t_tojson,
    .fromjson = vl_api_sw_interface_set_interface_name_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_set_interface_name_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_set_interface_name", api_sw_interface_set_interface_name);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_RX_PLACEMENT_DETAILS + msg_id_base,
    .name = "sw_interface_rx_placement_details",
    .handler = vl_api_sw_interface_rx_placement_details_t_handler,
    .endian = vl_api_sw_interface_rx_placement_details_t_endian,
    .format_fn = vl_api_sw_interface_rx_placement_details_t_format,
    .size = sizeof(vl_api_sw_interface_rx_placement_details_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_rx_placement_details_t_tojson,
    .fromjson = vl_api_sw_interface_rx_placement_details_t_fromjson,
    .calc_size = vl_api_sw_interface_rx_placement_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_rx_placement_dump", api_sw_interface_rx_placement_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_INTERFACE_NAME_RENUMBER_REPLY + msg_id_base,
    .name = "interface_name_renumber_reply",
    .handler = vl_api_interface_name_renumber_reply_t_handler,
    .endian = vl_api_interface_name_renumber_reply_t_endian,
    .format_fn = vl_api_interface_name_renumber_reply_t_format,
    .size = sizeof(vl_api_interface_name_renumber_reply_t),
    .traced = 1,
    .tojson = vl_api_interface_name_renumber_reply_t_tojson,
    .fromjson = vl_api_interface_name_renumber_reply_t_fromjson,
    .calc_size = vl_api_interface_name_renumber_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "interface_name_renumber", api_interface_name_renumber);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CREATE_SUBIF_REPLY + msg_id_base,
    .name = "create_subif_reply",
    .handler = vl_api_create_subif_reply_t_handler,
    .endian = vl_api_create_subif_reply_t_endian,
    .format_fn = vl_api_create_subif_reply_t_format,
    .size = sizeof(vl_api_create_subif_reply_t),
    .traced = 1,
    .tojson = vl_api_create_subif_reply_t_tojson,
    .fromjson = vl_api_create_subif_reply_t_fromjson,
    .calc_size = vl_api_create_subif_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "create_subif", api_create_subif);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CREATE_VLAN_SUBIF_REPLY + msg_id_base,
    .name = "create_vlan_subif_reply",
    .handler = vl_api_create_vlan_subif_reply_t_handler,
    .endian = vl_api_create_vlan_subif_reply_t_endian,
    .format_fn = vl_api_create_vlan_subif_reply_t_format,
    .size = sizeof(vl_api_create_vlan_subif_reply_t),
    .traced = 1,
    .tojson = vl_api_create_vlan_subif_reply_t_tojson,
    .fromjson = vl_api_create_vlan_subif_reply_t_fromjson,
    .calc_size = vl_api_create_vlan_subif_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "create_vlan_subif", api_create_vlan_subif);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DELETE_SUBIF_REPLY + msg_id_base,
    .name = "delete_subif_reply",
    .handler = vl_api_delete_subif_reply_t_handler,
    .endian = vl_api_delete_subif_reply_t_endian,
    .format_fn = vl_api_delete_subif_reply_t_format,
    .size = sizeof(vl_api_delete_subif_reply_t),
    .traced = 1,
    .tojson = vl_api_delete_subif_reply_t_tojson,
    .fromjson = vl_api_delete_subif_reply_t_fromjson,
    .calc_size = vl_api_delete_subif_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "delete_subif", api_delete_subif);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CREATE_LOOPBACK_REPLY + msg_id_base,
    .name = "create_loopback_reply",
    .handler = vl_api_create_loopback_reply_t_handler,
    .endian = vl_api_create_loopback_reply_t_endian,
    .format_fn = vl_api_create_loopback_reply_t_format,
    .size = sizeof(vl_api_create_loopback_reply_t),
    .traced = 1,
    .tojson = vl_api_create_loopback_reply_t_tojson,
    .fromjson = vl_api_create_loopback_reply_t_fromjson,
    .calc_size = vl_api_create_loopback_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "create_loopback", api_create_loopback);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CREATE_LOOPBACK_INSTANCE_REPLY + msg_id_base,
    .name = "create_loopback_instance_reply",
    .handler = vl_api_create_loopback_instance_reply_t_handler,
    .endian = vl_api_create_loopback_instance_reply_t_endian,
    .format_fn = vl_api_create_loopback_instance_reply_t_format,
    .size = sizeof(vl_api_create_loopback_instance_reply_t),
    .traced = 1,
    .tojson = vl_api_create_loopback_instance_reply_t_tojson,
    .fromjson = vl_api_create_loopback_instance_reply_t_fromjson,
    .calc_size = vl_api_create_loopback_instance_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "create_loopback_instance", api_create_loopback_instance);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DELETE_LOOPBACK_REPLY + msg_id_base,
    .name = "delete_loopback_reply",
    .handler = vl_api_delete_loopback_reply_t_handler,
    .endian = vl_api_delete_loopback_reply_t_endian,
    .format_fn = vl_api_delete_loopback_reply_t_format,
    .size = sizeof(vl_api_delete_loopback_reply_t),
    .traced = 1,
    .tojson = vl_api_delete_loopback_reply_t_tojson,
    .fromjson = vl_api_delete_loopback_reply_t_fromjson,
    .calc_size = vl_api_delete_loopback_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "delete_loopback", api_delete_loopback);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_COLLECT_DETAILED_INTERFACE_STATS_REPLY + msg_id_base,
    .name = "collect_detailed_interface_stats_reply",
    .handler = vl_api_collect_detailed_interface_stats_reply_t_handler,
    .endian = vl_api_collect_detailed_interface_stats_reply_t_endian,
    .format_fn = vl_api_collect_detailed_interface_stats_reply_t_format,
    .size = sizeof(vl_api_collect_detailed_interface_stats_reply_t),
    .traced = 1,
    .tojson = vl_api_collect_detailed_interface_stats_reply_t_tojson,
    .fromjson = vl_api_collect_detailed_interface_stats_reply_t_fromjson,
    .calc_size = vl_api_collect_detailed_interface_stats_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "collect_detailed_interface_stats", api_collect_detailed_interface_stats);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PCAP_SET_FILTER_FUNCTION_REPLY + msg_id_base,
    .name = "pcap_set_filter_function_reply",
    .handler = vl_api_pcap_set_filter_function_reply_t_handler,
    .endian = vl_api_pcap_set_filter_function_reply_t_endian,
    .format_fn = vl_api_pcap_set_filter_function_reply_t_format,
    .size = sizeof(vl_api_pcap_set_filter_function_reply_t),
    .traced = 1,
    .tojson = vl_api_pcap_set_filter_function_reply_t_tojson,
    .fromjson = vl_api_pcap_set_filter_function_reply_t_fromjson,
    .calc_size = vl_api_pcap_set_filter_function_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "pcap_set_filter_function", api_pcap_set_filter_function);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PCAP_TRACE_ON_REPLY + msg_id_base,
    .name = "pcap_trace_on_reply",
    .handler = vl_api_pcap_trace_on_reply_t_handler,
    .endian = vl_api_pcap_trace_on_reply_t_endian,
    .format_fn = vl_api_pcap_trace_on_reply_t_format,
    .size = sizeof(vl_api_pcap_trace_on_reply_t),
    .traced = 1,
    .tojson = vl_api_pcap_trace_on_reply_t_tojson,
    .fromjson = vl_api_pcap_trace_on_reply_t_fromjson,
    .calc_size = vl_api_pcap_trace_on_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "pcap_trace_on", api_pcap_trace_on);
   hash_set_mem (vam->help_by_name, "pcap_trace_on", "pcap_trace_on [capture_rx] [capture_tx] [capture_drop] [max_packets <nn>] [sw_if_index <sw_if_index>|0 for any] [error <node>.<error>] [filename <name>] [max_bytes_per_packet <nnnn>] [filter] [preallocate_data] [free_data]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PCAP_TRACE_OFF_REPLY + msg_id_base,
    .name = "pcap_trace_off_reply",
    .handler = vl_api_pcap_trace_off_reply_t_handler,
    .endian = vl_api_pcap_trace_off_reply_t_endian,
    .format_fn = vl_api_pcap_trace_off_reply_t_format,
    .size = sizeof(vl_api_pcap_trace_off_reply_t),
    .traced = 1,
    .tojson = vl_api_pcap_trace_off_reply_t_tojson,
    .fromjson = vl_api_pcap_trace_off_reply_t_fromjson,
    .calc_size = vl_api_pcap_trace_off_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "pcap_trace_off", api_pcap_trace_off);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   interface_test_main_t * mainp = &interface_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("interface_4f4d9ac1");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "interface plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
