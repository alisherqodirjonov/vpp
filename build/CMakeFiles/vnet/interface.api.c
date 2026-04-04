#define vl_endianfun		/* define message structures */
#include "interface.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "interface.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "interface.api.h"
#undef vl_printfun

#include "interface.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("interface_4f4d9ac1", VL_MSG_INTERFACE_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_interface);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_flags_f5aec1b8",
                                VL_API_SW_INTERFACE_SET_FLAGS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_flags_reply_e8d4e804",
                                VL_API_SW_INTERFACE_SET_FLAGS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_promisc_d40860d4",
                                VL_API_SW_INTERFACE_SET_PROMISC + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_promisc_reply_e8d4e804",
                                VL_API_SW_INTERFACE_SET_PROMISC_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "hw_interface_set_mtu_e6746899",
                                VL_API_HW_INTERFACE_SET_MTU + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "hw_interface_set_mtu_reply_e8d4e804",
                                VL_API_HW_INTERFACE_SET_MTU_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_mtu_5cbe85e5",
                                VL_API_SW_INTERFACE_SET_MTU + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_mtu_reply_e8d4e804",
                                VL_API_SW_INTERFACE_SET_MTU_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_ip_directed_broadcast_ae6cfcfb",
                                VL_API_SW_INTERFACE_SET_IP_DIRECTED_BROADCAST + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_ip_directed_broadcast_reply_e8d4e804",
                                VL_API_SW_INTERFACE_SET_IP_DIRECTED_BROADCAST_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_event_2d3d95a7",
                                VL_API_SW_INTERFACE_EVENT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_interface_events_476f5a08",
                                VL_API_WANT_INTERFACE_EVENTS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_interface_events_reply_e8d4e804",
                                VL_API_WANT_INTERFACE_EVENTS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_details_6c221fc7",
                                VL_API_SW_INTERFACE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_dump_aa610c27",
                                VL_API_SW_INTERFACE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_add_del_address_5463d73b",
                                VL_API_SW_INTERFACE_ADD_DEL_ADDRESS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_add_del_address_reply_e8d4e804",
                                VL_API_SW_INTERFACE_ADD_DEL_ADDRESS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_address_replace_begin_51077d14",
                                VL_API_SW_INTERFACE_ADDRESS_REPLACE_BEGIN + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_address_replace_begin_reply_e8d4e804",
                                VL_API_SW_INTERFACE_ADDRESS_REPLACE_BEGIN_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_address_replace_end_51077d14",
                                VL_API_SW_INTERFACE_ADDRESS_REPLACE_END + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_address_replace_end_reply_e8d4e804",
                                VL_API_SW_INTERFACE_ADDRESS_REPLACE_END_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_table_df42a577",
                                VL_API_SW_INTERFACE_SET_TABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_table_reply_e8d4e804",
                                VL_API_SW_INTERFACE_SET_TABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_get_table_2d033de4",
                                VL_API_SW_INTERFACE_GET_TABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_get_table_reply_a6eb0109",
                                VL_API_SW_INTERFACE_GET_TABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_unnumbered_154a6439",
                                VL_API_SW_INTERFACE_SET_UNNUMBERED + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_unnumbered_reply_e8d4e804",
                                VL_API_SW_INTERFACE_SET_UNNUMBERED_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_clear_stats_f9e6675e",
                                VL_API_SW_INTERFACE_CLEAR_STATS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_clear_stats_reply_e8d4e804",
                                VL_API_SW_INTERFACE_CLEAR_STATS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_tag_add_del_426f8bc1",
                                VL_API_SW_INTERFACE_TAG_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_tag_add_del_reply_e8d4e804",
                                VL_API_SW_INTERFACE_TAG_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_add_del_mac_address_638bb9f4",
                                VL_API_SW_INTERFACE_ADD_DEL_MAC_ADDRESS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_add_del_mac_address_reply_e8d4e804",
                                VL_API_SW_INTERFACE_ADD_DEL_MAC_ADDRESS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_mac_address_c536e7eb",
                                VL_API_SW_INTERFACE_SET_MAC_ADDRESS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_mac_address_reply_e8d4e804",
                                VL_API_SW_INTERFACE_SET_MAC_ADDRESS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_get_mac_address_f9e6675e",
                                VL_API_SW_INTERFACE_GET_MAC_ADDRESS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_get_mac_address_reply_40ef2c08",
                                VL_API_SW_INTERFACE_GET_MAC_ADDRESS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_rx_mode_b04d1cfe",
                                VL_API_SW_INTERFACE_SET_RX_MODE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_rx_mode_reply_e8d4e804",
                                VL_API_SW_INTERFACE_SET_RX_MODE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_rx_placement_db65f3c9",
                                VL_API_SW_INTERFACE_SET_RX_PLACEMENT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_rx_placement_reply_e8d4e804",
                                VL_API_SW_INTERFACE_SET_RX_PLACEMENT_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_tx_placement_4e0cd5ff",
                                VL_API_SW_INTERFACE_SET_TX_PLACEMENT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_tx_placement_reply_e8d4e804",
                                VL_API_SW_INTERFACE_SET_TX_PLACEMENT_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_interface_name_45a1d548",
                                VL_API_SW_INTERFACE_SET_INTERFACE_NAME + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_interface_name_reply_e8d4e804",
                                VL_API_SW_INTERFACE_SET_INTERFACE_NAME_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_rx_placement_dump_f9e6675e",
                                VL_API_SW_INTERFACE_RX_PLACEMENT_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_rx_placement_details_9e44a7ce",
                                VL_API_SW_INTERFACE_RX_PLACEMENT_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_tx_placement_get_47250981",
                                VL_API_SW_INTERFACE_TX_PLACEMENT_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_tx_placement_get_reply_53b48f5d",
                                VL_API_SW_INTERFACE_TX_PLACEMENT_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_tx_placement_details_00381a2e",
                                VL_API_SW_INTERFACE_TX_PLACEMENT_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "interface_name_renumber_2b8858b8",
                                VL_API_INTERFACE_NAME_RENUMBER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "interface_name_renumber_reply_e8d4e804",
                                VL_API_INTERFACE_NAME_RENUMBER_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "create_subif_790ca755",
                                VL_API_CREATE_SUBIF + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "create_subif_reply_5383d31f",
                                VL_API_CREATE_SUBIF_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "create_vlan_subif_af34ac8b",
                                VL_API_CREATE_VLAN_SUBIF + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "create_vlan_subif_reply_5383d31f",
                                VL_API_CREATE_VLAN_SUBIF_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "delete_subif_f9e6675e",
                                VL_API_DELETE_SUBIF + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "delete_subif_reply_e8d4e804",
                                VL_API_DELETE_SUBIF_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "create_loopback_42bb5d22",
                                VL_API_CREATE_LOOPBACK + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "create_loopback_reply_5383d31f",
                                VL_API_CREATE_LOOPBACK_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "create_loopback_instance_d36a3ee2",
                                VL_API_CREATE_LOOPBACK_INSTANCE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "create_loopback_instance_reply_5383d31f",
                                VL_API_CREATE_LOOPBACK_INSTANCE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "delete_loopback_f9e6675e",
                                VL_API_DELETE_LOOPBACK + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "delete_loopback_reply_e8d4e804",
                                VL_API_DELETE_LOOPBACK_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "collect_detailed_interface_stats_5501adee",
                                VL_API_COLLECT_DETAILED_INTERFACE_STATS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "collect_detailed_interface_stats_reply_e8d4e804",
                                VL_API_COLLECT_DETAILED_INTERFACE_STATS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pcap_set_filter_function_616abb92",
                                VL_API_PCAP_SET_FILTER_FUNCTION + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pcap_set_filter_function_reply_e8d4e804",
                                VL_API_PCAP_SET_FILTER_FUNCTION_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pcap_trace_on_cb39e968",
                                VL_API_PCAP_TRACE_ON + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pcap_trace_on_reply_e8d4e804",
                                VL_API_PCAP_TRACE_ON_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pcap_trace_off_51077d14",
                                VL_API_PCAP_TRACE_OFF + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pcap_trace_off_reply_e8d4e804",
                                VL_API_PCAP_TRACE_OFF_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_WANT_INTERFACE_EVENTS + msg_id_base,
   .name = "want_interface_events",
   .handler = vl_api_want_interface_events_t_handler,
   .endian = vl_api_want_interface_events_t_endian,
   .format_fn = vl_api_want_interface_events_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_want_interface_events_t_tojson,
   .fromjson = vl_api_want_interface_events_t_fromjson,
   .calc_size = vl_api_want_interface_events_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_WANT_INTERFACE_EVENTS_REPLY + msg_id_base,
  .name = "want_interface_events_reply",
  .handler = 0,
  .endian = vl_api_want_interface_events_reply_t_endian,
  .format_fn = vl_api_want_interface_events_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_want_interface_events_reply_t_tojson,
  .fromjson = vl_api_want_interface_events_reply_t_fromjson,
  .calc_size = vl_api_want_interface_events_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_TX_PLACEMENT_GET + msg_id_base,
   .name = "sw_interface_tx_placement_get",
   .handler = vl_api_sw_interface_tx_placement_get_t_handler,
   .endian = vl_api_sw_interface_tx_placement_get_t_endian,
   .format_fn = vl_api_sw_interface_tx_placement_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_tx_placement_get_t_tojson,
   .fromjson = vl_api_sw_interface_tx_placement_get_t_fromjson,
   .calc_size = vl_api_sw_interface_tx_placement_get_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_TX_PLACEMENT_GET_REPLY + msg_id_base,
  .name = "sw_interface_tx_placement_get_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_tx_placement_get_reply_t_endian,
  .format_fn = vl_api_sw_interface_tx_placement_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_tx_placement_get_reply_t_tojson,
  .fromjson = vl_api_sw_interface_tx_placement_get_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_tx_placement_get_reply_t_calc_size,
  .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_TX_PLACEMENT_DETAILS + msg_id_base,
  .name = "sw_interface_tx_placement_details",
  .handler = 0,
  .endian = vl_api_sw_interface_tx_placement_details_t_endian,
  .format_fn = vl_api_sw_interface_tx_placement_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_tx_placement_details_t_tojson,
  .fromjson = vl_api_sw_interface_tx_placement_details_t_fromjson,
  .calc_size = vl_api_sw_interface_tx_placement_details_t_calc_size,
  .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SET_FLAGS + msg_id_base,
   .name = "sw_interface_set_flags",
   .handler = vl_api_sw_interface_set_flags_t_handler,
   .endian = vl_api_sw_interface_set_flags_t_endian,
   .format_fn = vl_api_sw_interface_set_flags_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_set_flags_t_tojson,
   .fromjson = vl_api_sw_interface_set_flags_t_fromjson,
   .calc_size = vl_api_sw_interface_set_flags_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SET_FLAGS_REPLY + msg_id_base,
  .name = "sw_interface_set_flags_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_set_flags_reply_t_endian,
  .format_fn = vl_api_sw_interface_set_flags_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_set_flags_reply_t_tojson,
  .fromjson = vl_api_sw_interface_set_flags_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_set_flags_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SET_PROMISC + msg_id_base,
   .name = "sw_interface_set_promisc",
   .handler = vl_api_sw_interface_set_promisc_t_handler,
   .endian = vl_api_sw_interface_set_promisc_t_endian,
   .format_fn = vl_api_sw_interface_set_promisc_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_set_promisc_t_tojson,
   .fromjson = vl_api_sw_interface_set_promisc_t_fromjson,
   .calc_size = vl_api_sw_interface_set_promisc_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SET_PROMISC_REPLY + msg_id_base,
  .name = "sw_interface_set_promisc_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_set_promisc_reply_t_endian,
  .format_fn = vl_api_sw_interface_set_promisc_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_set_promisc_reply_t_tojson,
  .fromjson = vl_api_sw_interface_set_promisc_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_set_promisc_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_HW_INTERFACE_SET_MTU + msg_id_base,
   .name = "hw_interface_set_mtu",
   .handler = vl_api_hw_interface_set_mtu_t_handler,
   .endian = vl_api_hw_interface_set_mtu_t_endian,
   .format_fn = vl_api_hw_interface_set_mtu_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_hw_interface_set_mtu_t_tojson,
   .fromjson = vl_api_hw_interface_set_mtu_t_fromjson,
   .calc_size = vl_api_hw_interface_set_mtu_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_HW_INTERFACE_SET_MTU_REPLY + msg_id_base,
  .name = "hw_interface_set_mtu_reply",
  .handler = 0,
  .endian = vl_api_hw_interface_set_mtu_reply_t_endian,
  .format_fn = vl_api_hw_interface_set_mtu_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_hw_interface_set_mtu_reply_t_tojson,
  .fromjson = vl_api_hw_interface_set_mtu_reply_t_fromjson,
  .calc_size = vl_api_hw_interface_set_mtu_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SET_MTU + msg_id_base,
   .name = "sw_interface_set_mtu",
   .handler = vl_api_sw_interface_set_mtu_t_handler,
   .endian = vl_api_sw_interface_set_mtu_t_endian,
   .format_fn = vl_api_sw_interface_set_mtu_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_set_mtu_t_tojson,
   .fromjson = vl_api_sw_interface_set_mtu_t_fromjson,
   .calc_size = vl_api_sw_interface_set_mtu_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SET_MTU_REPLY + msg_id_base,
  .name = "sw_interface_set_mtu_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_set_mtu_reply_t_endian,
  .format_fn = vl_api_sw_interface_set_mtu_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_set_mtu_reply_t_tojson,
  .fromjson = vl_api_sw_interface_set_mtu_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_set_mtu_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SET_IP_DIRECTED_BROADCAST + msg_id_base,
   .name = "sw_interface_set_ip_directed_broadcast",
   .handler = vl_api_sw_interface_set_ip_directed_broadcast_t_handler,
   .endian = vl_api_sw_interface_set_ip_directed_broadcast_t_endian,
   .format_fn = vl_api_sw_interface_set_ip_directed_broadcast_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_set_ip_directed_broadcast_t_tojson,
   .fromjson = vl_api_sw_interface_set_ip_directed_broadcast_t_fromjson,
   .calc_size = vl_api_sw_interface_set_ip_directed_broadcast_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SET_IP_DIRECTED_BROADCAST_REPLY + msg_id_base,
  .name = "sw_interface_set_ip_directed_broadcast_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_set_ip_directed_broadcast_reply_t_endian,
  .format_fn = vl_api_sw_interface_set_ip_directed_broadcast_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_set_ip_directed_broadcast_reply_t_tojson,
  .fromjson = vl_api_sw_interface_set_ip_directed_broadcast_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_set_ip_directed_broadcast_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_DUMP + msg_id_base,
   .name = "sw_interface_dump",
   .handler = vl_api_sw_interface_dump_t_handler,
   .endian = vl_api_sw_interface_dump_t_endian,
   .format_fn = vl_api_sw_interface_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_dump_t_tojson,
   .fromjson = vl_api_sw_interface_dump_t_fromjson,
   .calc_size = vl_api_sw_interface_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_DETAILS + msg_id_base,
  .name = "sw_interface_details",
  .handler = 0,
  .endian = vl_api_sw_interface_details_t_endian,
  .format_fn = vl_api_sw_interface_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_details_t_tojson,
  .fromjson = vl_api_sw_interface_details_t_fromjson,
  .calc_size = vl_api_sw_interface_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_ADD_DEL_ADDRESS + msg_id_base,
   .name = "sw_interface_add_del_address",
   .handler = vl_api_sw_interface_add_del_address_t_handler,
   .endian = vl_api_sw_interface_add_del_address_t_endian,
   .format_fn = vl_api_sw_interface_add_del_address_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_add_del_address_t_tojson,
   .fromjson = vl_api_sw_interface_add_del_address_t_fromjson,
   .calc_size = vl_api_sw_interface_add_del_address_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_ADD_DEL_ADDRESS_REPLY + msg_id_base,
  .name = "sw_interface_add_del_address_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_add_del_address_reply_t_endian,
  .format_fn = vl_api_sw_interface_add_del_address_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_add_del_address_reply_t_tojson,
  .fromjson = vl_api_sw_interface_add_del_address_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_add_del_address_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_ADDRESS_REPLACE_BEGIN + msg_id_base,
   .name = "sw_interface_address_replace_begin",
   .handler = vl_api_sw_interface_address_replace_begin_t_handler,
   .endian = vl_api_sw_interface_address_replace_begin_t_endian,
   .format_fn = vl_api_sw_interface_address_replace_begin_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_address_replace_begin_t_tojson,
   .fromjson = vl_api_sw_interface_address_replace_begin_t_fromjson,
   .calc_size = vl_api_sw_interface_address_replace_begin_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_ADDRESS_REPLACE_BEGIN_REPLY + msg_id_base,
  .name = "sw_interface_address_replace_begin_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_address_replace_begin_reply_t_endian,
  .format_fn = vl_api_sw_interface_address_replace_begin_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_address_replace_begin_reply_t_tojson,
  .fromjson = vl_api_sw_interface_address_replace_begin_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_address_replace_begin_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_ADDRESS_REPLACE_END + msg_id_base,
   .name = "sw_interface_address_replace_end",
   .handler = vl_api_sw_interface_address_replace_end_t_handler,
   .endian = vl_api_sw_interface_address_replace_end_t_endian,
   .format_fn = vl_api_sw_interface_address_replace_end_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_address_replace_end_t_tojson,
   .fromjson = vl_api_sw_interface_address_replace_end_t_fromjson,
   .calc_size = vl_api_sw_interface_address_replace_end_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_ADDRESS_REPLACE_END_REPLY + msg_id_base,
  .name = "sw_interface_address_replace_end_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_address_replace_end_reply_t_endian,
  .format_fn = vl_api_sw_interface_address_replace_end_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_address_replace_end_reply_t_tojson,
  .fromjson = vl_api_sw_interface_address_replace_end_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_address_replace_end_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SET_TABLE + msg_id_base,
   .name = "sw_interface_set_table",
   .handler = vl_api_sw_interface_set_table_t_handler,
   .endian = vl_api_sw_interface_set_table_t_endian,
   .format_fn = vl_api_sw_interface_set_table_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_set_table_t_tojson,
   .fromjson = vl_api_sw_interface_set_table_t_fromjson,
   .calc_size = vl_api_sw_interface_set_table_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SET_TABLE_REPLY + msg_id_base,
  .name = "sw_interface_set_table_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_set_table_reply_t_endian,
  .format_fn = vl_api_sw_interface_set_table_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_set_table_reply_t_tojson,
  .fromjson = vl_api_sw_interface_set_table_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_set_table_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_GET_TABLE + msg_id_base,
   .name = "sw_interface_get_table",
   .handler = vl_api_sw_interface_get_table_t_handler,
   .endian = vl_api_sw_interface_get_table_t_endian,
   .format_fn = vl_api_sw_interface_get_table_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_get_table_t_tojson,
   .fromjson = vl_api_sw_interface_get_table_t_fromjson,
   .calc_size = vl_api_sw_interface_get_table_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_GET_TABLE_REPLY + msg_id_base,
  .name = "sw_interface_get_table_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_get_table_reply_t_endian,
  .format_fn = vl_api_sw_interface_get_table_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_get_table_reply_t_tojson,
  .fromjson = vl_api_sw_interface_get_table_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_get_table_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SET_UNNUMBERED + msg_id_base,
   .name = "sw_interface_set_unnumbered",
   .handler = vl_api_sw_interface_set_unnumbered_t_handler,
   .endian = vl_api_sw_interface_set_unnumbered_t_endian,
   .format_fn = vl_api_sw_interface_set_unnumbered_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_set_unnumbered_t_tojson,
   .fromjson = vl_api_sw_interface_set_unnumbered_t_fromjson,
   .calc_size = vl_api_sw_interface_set_unnumbered_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SET_UNNUMBERED_REPLY + msg_id_base,
  .name = "sw_interface_set_unnumbered_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_set_unnumbered_reply_t_endian,
  .format_fn = vl_api_sw_interface_set_unnumbered_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_set_unnumbered_reply_t_tojson,
  .fromjson = vl_api_sw_interface_set_unnumbered_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_set_unnumbered_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_CLEAR_STATS + msg_id_base,
   .name = "sw_interface_clear_stats",
   .handler = vl_api_sw_interface_clear_stats_t_handler,
   .endian = vl_api_sw_interface_clear_stats_t_endian,
   .format_fn = vl_api_sw_interface_clear_stats_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_clear_stats_t_tojson,
   .fromjson = vl_api_sw_interface_clear_stats_t_fromjson,
   .calc_size = vl_api_sw_interface_clear_stats_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_CLEAR_STATS_REPLY + msg_id_base,
  .name = "sw_interface_clear_stats_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_clear_stats_reply_t_endian,
  .format_fn = vl_api_sw_interface_clear_stats_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_clear_stats_reply_t_tojson,
  .fromjson = vl_api_sw_interface_clear_stats_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_clear_stats_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_TAG_ADD_DEL + msg_id_base,
   .name = "sw_interface_tag_add_del",
   .handler = vl_api_sw_interface_tag_add_del_t_handler,
   .endian = vl_api_sw_interface_tag_add_del_t_endian,
   .format_fn = vl_api_sw_interface_tag_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_tag_add_del_t_tojson,
   .fromjson = vl_api_sw_interface_tag_add_del_t_fromjson,
   .calc_size = vl_api_sw_interface_tag_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_TAG_ADD_DEL_REPLY + msg_id_base,
  .name = "sw_interface_tag_add_del_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_tag_add_del_reply_t_endian,
  .format_fn = vl_api_sw_interface_tag_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_tag_add_del_reply_t_tojson,
  .fromjson = vl_api_sw_interface_tag_add_del_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_tag_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_ADD_DEL_MAC_ADDRESS + msg_id_base,
   .name = "sw_interface_add_del_mac_address",
   .handler = vl_api_sw_interface_add_del_mac_address_t_handler,
   .endian = vl_api_sw_interface_add_del_mac_address_t_endian,
   .format_fn = vl_api_sw_interface_add_del_mac_address_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_add_del_mac_address_t_tojson,
   .fromjson = vl_api_sw_interface_add_del_mac_address_t_fromjson,
   .calc_size = vl_api_sw_interface_add_del_mac_address_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_ADD_DEL_MAC_ADDRESS_REPLY + msg_id_base,
  .name = "sw_interface_add_del_mac_address_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_add_del_mac_address_reply_t_endian,
  .format_fn = vl_api_sw_interface_add_del_mac_address_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_add_del_mac_address_reply_t_tojson,
  .fromjson = vl_api_sw_interface_add_del_mac_address_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_add_del_mac_address_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SET_MAC_ADDRESS + msg_id_base,
   .name = "sw_interface_set_mac_address",
   .handler = vl_api_sw_interface_set_mac_address_t_handler,
   .endian = vl_api_sw_interface_set_mac_address_t_endian,
   .format_fn = vl_api_sw_interface_set_mac_address_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_set_mac_address_t_tojson,
   .fromjson = vl_api_sw_interface_set_mac_address_t_fromjson,
   .calc_size = vl_api_sw_interface_set_mac_address_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SET_MAC_ADDRESS_REPLY + msg_id_base,
  .name = "sw_interface_set_mac_address_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_set_mac_address_reply_t_endian,
  .format_fn = vl_api_sw_interface_set_mac_address_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_set_mac_address_reply_t_tojson,
  .fromjson = vl_api_sw_interface_set_mac_address_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_set_mac_address_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_GET_MAC_ADDRESS + msg_id_base,
   .name = "sw_interface_get_mac_address",
   .handler = vl_api_sw_interface_get_mac_address_t_handler,
   .endian = vl_api_sw_interface_get_mac_address_t_endian,
   .format_fn = vl_api_sw_interface_get_mac_address_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_get_mac_address_t_tojson,
   .fromjson = vl_api_sw_interface_get_mac_address_t_fromjson,
   .calc_size = vl_api_sw_interface_get_mac_address_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_GET_MAC_ADDRESS_REPLY + msg_id_base,
  .name = "sw_interface_get_mac_address_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_get_mac_address_reply_t_endian,
  .format_fn = vl_api_sw_interface_get_mac_address_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_get_mac_address_reply_t_tojson,
  .fromjson = vl_api_sw_interface_get_mac_address_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_get_mac_address_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SET_RX_MODE + msg_id_base,
   .name = "sw_interface_set_rx_mode",
   .handler = vl_api_sw_interface_set_rx_mode_t_handler,
   .endian = vl_api_sw_interface_set_rx_mode_t_endian,
   .format_fn = vl_api_sw_interface_set_rx_mode_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_set_rx_mode_t_tojson,
   .fromjson = vl_api_sw_interface_set_rx_mode_t_fromjson,
   .calc_size = vl_api_sw_interface_set_rx_mode_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SET_RX_MODE_REPLY + msg_id_base,
  .name = "sw_interface_set_rx_mode_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_set_rx_mode_reply_t_endian,
  .format_fn = vl_api_sw_interface_set_rx_mode_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_set_rx_mode_reply_t_tojson,
  .fromjson = vl_api_sw_interface_set_rx_mode_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_set_rx_mode_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SET_RX_PLACEMENT + msg_id_base,
   .name = "sw_interface_set_rx_placement",
   .handler = vl_api_sw_interface_set_rx_placement_t_handler,
   .endian = vl_api_sw_interface_set_rx_placement_t_endian,
   .format_fn = vl_api_sw_interface_set_rx_placement_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_set_rx_placement_t_tojson,
   .fromjson = vl_api_sw_interface_set_rx_placement_t_fromjson,
   .calc_size = vl_api_sw_interface_set_rx_placement_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SET_RX_PLACEMENT_REPLY + msg_id_base,
  .name = "sw_interface_set_rx_placement_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_set_rx_placement_reply_t_endian,
  .format_fn = vl_api_sw_interface_set_rx_placement_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_set_rx_placement_reply_t_tojson,
  .fromjson = vl_api_sw_interface_set_rx_placement_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_set_rx_placement_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SET_TX_PLACEMENT + msg_id_base,
   .name = "sw_interface_set_tx_placement",
   .handler = vl_api_sw_interface_set_tx_placement_t_handler,
   .endian = vl_api_sw_interface_set_tx_placement_t_endian,
   .format_fn = vl_api_sw_interface_set_tx_placement_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_set_tx_placement_t_tojson,
   .fromjson = vl_api_sw_interface_set_tx_placement_t_fromjson,
   .calc_size = vl_api_sw_interface_set_tx_placement_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SET_TX_PLACEMENT_REPLY + msg_id_base,
  .name = "sw_interface_set_tx_placement_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_set_tx_placement_reply_t_endian,
  .format_fn = vl_api_sw_interface_set_tx_placement_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_set_tx_placement_reply_t_tojson,
  .fromjson = vl_api_sw_interface_set_tx_placement_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_set_tx_placement_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SET_INTERFACE_NAME + msg_id_base,
   .name = "sw_interface_set_interface_name",
   .handler = vl_api_sw_interface_set_interface_name_t_handler,
   .endian = vl_api_sw_interface_set_interface_name_t_endian,
   .format_fn = vl_api_sw_interface_set_interface_name_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_set_interface_name_t_tojson,
   .fromjson = vl_api_sw_interface_set_interface_name_t_fromjson,
   .calc_size = vl_api_sw_interface_set_interface_name_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SET_INTERFACE_NAME_REPLY + msg_id_base,
  .name = "sw_interface_set_interface_name_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_set_interface_name_reply_t_endian,
  .format_fn = vl_api_sw_interface_set_interface_name_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_set_interface_name_reply_t_tojson,
  .fromjson = vl_api_sw_interface_set_interface_name_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_set_interface_name_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_RX_PLACEMENT_DUMP + msg_id_base,
   .name = "sw_interface_rx_placement_dump",
   .handler = vl_api_sw_interface_rx_placement_dump_t_handler,
   .endian = vl_api_sw_interface_rx_placement_dump_t_endian,
   .format_fn = vl_api_sw_interface_rx_placement_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_rx_placement_dump_t_tojson,
   .fromjson = vl_api_sw_interface_rx_placement_dump_t_fromjson,
   .calc_size = vl_api_sw_interface_rx_placement_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_RX_PLACEMENT_DETAILS + msg_id_base,
  .name = "sw_interface_rx_placement_details",
  .handler = 0,
  .endian = vl_api_sw_interface_rx_placement_details_t_endian,
  .format_fn = vl_api_sw_interface_rx_placement_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_rx_placement_details_t_tojson,
  .fromjson = vl_api_sw_interface_rx_placement_details_t_fromjson,
  .calc_size = vl_api_sw_interface_rx_placement_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_INTERFACE_NAME_RENUMBER + msg_id_base,
   .name = "interface_name_renumber",
   .handler = vl_api_interface_name_renumber_t_handler,
   .endian = vl_api_interface_name_renumber_t_endian,
   .format_fn = vl_api_interface_name_renumber_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_interface_name_renumber_t_tojson,
   .fromjson = vl_api_interface_name_renumber_t_fromjson,
   .calc_size = vl_api_interface_name_renumber_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_INTERFACE_NAME_RENUMBER_REPLY + msg_id_base,
  .name = "interface_name_renumber_reply",
  .handler = 0,
  .endian = vl_api_interface_name_renumber_reply_t_endian,
  .format_fn = vl_api_interface_name_renumber_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_interface_name_renumber_reply_t_tojson,
  .fromjson = vl_api_interface_name_renumber_reply_t_fromjson,
  .calc_size = vl_api_interface_name_renumber_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CREATE_SUBIF + msg_id_base,
   .name = "create_subif",
   .handler = vl_api_create_subif_t_handler,
   .endian = vl_api_create_subif_t_endian,
   .format_fn = vl_api_create_subif_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_create_subif_t_tojson,
   .fromjson = vl_api_create_subif_t_fromjson,
   .calc_size = vl_api_create_subif_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CREATE_SUBIF_REPLY + msg_id_base,
  .name = "create_subif_reply",
  .handler = 0,
  .endian = vl_api_create_subif_reply_t_endian,
  .format_fn = vl_api_create_subif_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_create_subif_reply_t_tojson,
  .fromjson = vl_api_create_subif_reply_t_fromjson,
  .calc_size = vl_api_create_subif_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CREATE_VLAN_SUBIF + msg_id_base,
   .name = "create_vlan_subif",
   .handler = vl_api_create_vlan_subif_t_handler,
   .endian = vl_api_create_vlan_subif_t_endian,
   .format_fn = vl_api_create_vlan_subif_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_create_vlan_subif_t_tojson,
   .fromjson = vl_api_create_vlan_subif_t_fromjson,
   .calc_size = vl_api_create_vlan_subif_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CREATE_VLAN_SUBIF_REPLY + msg_id_base,
  .name = "create_vlan_subif_reply",
  .handler = 0,
  .endian = vl_api_create_vlan_subif_reply_t_endian,
  .format_fn = vl_api_create_vlan_subif_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_create_vlan_subif_reply_t_tojson,
  .fromjson = vl_api_create_vlan_subif_reply_t_fromjson,
  .calc_size = vl_api_create_vlan_subif_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DELETE_SUBIF + msg_id_base,
   .name = "delete_subif",
   .handler = vl_api_delete_subif_t_handler,
   .endian = vl_api_delete_subif_t_endian,
   .format_fn = vl_api_delete_subif_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_delete_subif_t_tojson,
   .fromjson = vl_api_delete_subif_t_fromjson,
   .calc_size = vl_api_delete_subif_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DELETE_SUBIF_REPLY + msg_id_base,
  .name = "delete_subif_reply",
  .handler = 0,
  .endian = vl_api_delete_subif_reply_t_endian,
  .format_fn = vl_api_delete_subif_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_delete_subif_reply_t_tojson,
  .fromjson = vl_api_delete_subif_reply_t_fromjson,
  .calc_size = vl_api_delete_subif_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CREATE_LOOPBACK + msg_id_base,
   .name = "create_loopback",
   .handler = vl_api_create_loopback_t_handler,
   .endian = vl_api_create_loopback_t_endian,
   .format_fn = vl_api_create_loopback_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_create_loopback_t_tojson,
   .fromjson = vl_api_create_loopback_t_fromjson,
   .calc_size = vl_api_create_loopback_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CREATE_LOOPBACK_REPLY + msg_id_base,
  .name = "create_loopback_reply",
  .handler = 0,
  .endian = vl_api_create_loopback_reply_t_endian,
  .format_fn = vl_api_create_loopback_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_create_loopback_reply_t_tojson,
  .fromjson = vl_api_create_loopback_reply_t_fromjson,
  .calc_size = vl_api_create_loopback_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CREATE_LOOPBACK_INSTANCE + msg_id_base,
   .name = "create_loopback_instance",
   .handler = vl_api_create_loopback_instance_t_handler,
   .endian = vl_api_create_loopback_instance_t_endian,
   .format_fn = vl_api_create_loopback_instance_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_create_loopback_instance_t_tojson,
   .fromjson = vl_api_create_loopback_instance_t_fromjson,
   .calc_size = vl_api_create_loopback_instance_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CREATE_LOOPBACK_INSTANCE_REPLY + msg_id_base,
  .name = "create_loopback_instance_reply",
  .handler = 0,
  .endian = vl_api_create_loopback_instance_reply_t_endian,
  .format_fn = vl_api_create_loopback_instance_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_create_loopback_instance_reply_t_tojson,
  .fromjson = vl_api_create_loopback_instance_reply_t_fromjson,
  .calc_size = vl_api_create_loopback_instance_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DELETE_LOOPBACK + msg_id_base,
   .name = "delete_loopback",
   .handler = vl_api_delete_loopback_t_handler,
   .endian = vl_api_delete_loopback_t_endian,
   .format_fn = vl_api_delete_loopback_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_delete_loopback_t_tojson,
   .fromjson = vl_api_delete_loopback_t_fromjson,
   .calc_size = vl_api_delete_loopback_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DELETE_LOOPBACK_REPLY + msg_id_base,
  .name = "delete_loopback_reply",
  .handler = 0,
  .endian = vl_api_delete_loopback_reply_t_endian,
  .format_fn = vl_api_delete_loopback_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_delete_loopback_reply_t_tojson,
  .fromjson = vl_api_delete_loopback_reply_t_fromjson,
  .calc_size = vl_api_delete_loopback_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_COLLECT_DETAILED_INTERFACE_STATS + msg_id_base,
   .name = "collect_detailed_interface_stats",
   .handler = vl_api_collect_detailed_interface_stats_t_handler,
   .endian = vl_api_collect_detailed_interface_stats_t_endian,
   .format_fn = vl_api_collect_detailed_interface_stats_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_collect_detailed_interface_stats_t_tojson,
   .fromjson = vl_api_collect_detailed_interface_stats_t_fromjson,
   .calc_size = vl_api_collect_detailed_interface_stats_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_COLLECT_DETAILED_INTERFACE_STATS_REPLY + msg_id_base,
  .name = "collect_detailed_interface_stats_reply",
  .handler = 0,
  .endian = vl_api_collect_detailed_interface_stats_reply_t_endian,
  .format_fn = vl_api_collect_detailed_interface_stats_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_collect_detailed_interface_stats_reply_t_tojson,
  .fromjson = vl_api_collect_detailed_interface_stats_reply_t_fromjson,
  .calc_size = vl_api_collect_detailed_interface_stats_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PCAP_SET_FILTER_FUNCTION + msg_id_base,
   .name = "pcap_set_filter_function",
   .handler = vl_api_pcap_set_filter_function_t_handler,
   .endian = vl_api_pcap_set_filter_function_t_endian,
   .format_fn = vl_api_pcap_set_filter_function_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pcap_set_filter_function_t_tojson,
   .fromjson = vl_api_pcap_set_filter_function_t_fromjson,
   .calc_size = vl_api_pcap_set_filter_function_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PCAP_SET_FILTER_FUNCTION_REPLY + msg_id_base,
  .name = "pcap_set_filter_function_reply",
  .handler = 0,
  .endian = vl_api_pcap_set_filter_function_reply_t_endian,
  .format_fn = vl_api_pcap_set_filter_function_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pcap_set_filter_function_reply_t_tojson,
  .fromjson = vl_api_pcap_set_filter_function_reply_t_fromjson,
  .calc_size = vl_api_pcap_set_filter_function_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PCAP_TRACE_ON + msg_id_base,
   .name = "pcap_trace_on",
   .handler = vl_api_pcap_trace_on_t_handler,
   .endian = vl_api_pcap_trace_on_t_endian,
   .format_fn = vl_api_pcap_trace_on_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pcap_trace_on_t_tojson,
   .fromjson = vl_api_pcap_trace_on_t_fromjson,
   .calc_size = vl_api_pcap_trace_on_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PCAP_TRACE_ON_REPLY + msg_id_base,
  .name = "pcap_trace_on_reply",
  .handler = 0,
  .endian = vl_api_pcap_trace_on_reply_t_endian,
  .format_fn = vl_api_pcap_trace_on_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pcap_trace_on_reply_t_tojson,
  .fromjson = vl_api_pcap_trace_on_reply_t_fromjson,
  .calc_size = vl_api_pcap_trace_on_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PCAP_TRACE_OFF + msg_id_base,
   .name = "pcap_trace_off",
   .handler = vl_api_pcap_trace_off_t_handler,
   .endian = vl_api_pcap_trace_off_t_endian,
   .format_fn = vl_api_pcap_trace_off_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pcap_trace_off_t_tojson,
   .fromjson = vl_api_pcap_trace_off_t_fromjson,
   .calc_size = vl_api_pcap_trace_off_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PCAP_TRACE_OFF_REPLY + msg_id_base,
  .name = "pcap_trace_off_reply",
  .handler = 0,
  .endian = vl_api_pcap_trace_off_reply_t_endian,
  .format_fn = vl_api_pcap_trace_off_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pcap_trace_off_reply_t_tojson,
  .fromjson = vl_api_pcap_trace_off_reply_t_fromjson,
  .calc_size = vl_api_pcap_trace_off_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
