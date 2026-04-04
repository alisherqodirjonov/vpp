#define vl_endianfun		/* define message structures */
#include "one.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "one.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "one.api.h"
#undef vl_printfun

#include "one.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("one_a4bbba2c", VL_MSG_ONE_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_one);
   vl_msg_api_add_msg_name_crc (am, "one_add_del_locator_set_6fcd6471",
                                VL_API_ONE_ADD_DEL_LOCATOR_SET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_add_del_locator_set_reply_b6666db4",
                                VL_API_ONE_ADD_DEL_LOCATOR_SET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_add_del_locator_af4d8f13",
                                VL_API_ONE_ADD_DEL_LOCATOR + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_add_del_locator_reply_e8d4e804",
                                VL_API_ONE_ADD_DEL_LOCATOR_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_add_del_local_eid_4e5a83a2",
                                VL_API_ONE_ADD_DEL_LOCAL_EID + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_add_del_local_eid_reply_e8d4e804",
                                VL_API_ONE_ADD_DEL_LOCAL_EID_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_map_register_set_ttl_dd59f1f3",
                                VL_API_ONE_MAP_REGISTER_SET_TTL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_map_register_set_ttl_reply_e8d4e804",
                                VL_API_ONE_MAP_REGISTER_SET_TTL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_one_map_register_ttl_51077d14",
                                VL_API_SHOW_ONE_MAP_REGISTER_TTL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_one_map_register_ttl_reply_fa83dd66",
                                VL_API_SHOW_ONE_MAP_REGISTER_TTL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_add_del_map_server_ce19e32d",
                                VL_API_ONE_ADD_DEL_MAP_SERVER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_add_del_map_server_reply_e8d4e804",
                                VL_API_ONE_ADD_DEL_MAP_SERVER_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_add_del_map_resolver_ce19e32d",
                                VL_API_ONE_ADD_DEL_MAP_RESOLVER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_add_del_map_resolver_reply_e8d4e804",
                                VL_API_ONE_ADD_DEL_MAP_RESOLVER_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_enable_disable_c264d7bf",
                                VL_API_ONE_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_enable_disable_reply_e8d4e804",
                                VL_API_ONE_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_nsh_set_locator_set_486e2b76",
                                VL_API_ONE_NSH_SET_LOCATOR_SET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_nsh_set_locator_set_reply_e8d4e804",
                                VL_API_ONE_NSH_SET_LOCATOR_SET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_pitr_set_locator_set_486e2b76",
                                VL_API_ONE_PITR_SET_LOCATOR_SET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_pitr_set_locator_set_reply_e8d4e804",
                                VL_API_ONE_PITR_SET_LOCATOR_SET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_use_petr_d87dbad9",
                                VL_API_ONE_USE_PETR + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_use_petr_reply_e8d4e804",
                                VL_API_ONE_USE_PETR_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_one_use_petr_51077d14",
                                VL_API_SHOW_ONE_USE_PETR + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_one_use_petr_reply_84a03528",
                                VL_API_SHOW_ONE_USE_PETR_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_one_rloc_probe_state_51077d14",
                                VL_API_SHOW_ONE_RLOC_PROBE_STATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_one_rloc_probe_state_reply_f15abb16",
                                VL_API_SHOW_ONE_RLOC_PROBE_STATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_rloc_probe_enable_disable_c264d7bf",
                                VL_API_ONE_RLOC_PROBE_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_rloc_probe_enable_disable_reply_e8d4e804",
                                VL_API_ONE_RLOC_PROBE_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_map_register_enable_disable_c264d7bf",
                                VL_API_ONE_MAP_REGISTER_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_map_register_enable_disable_reply_e8d4e804",
                                VL_API_ONE_MAP_REGISTER_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_one_map_register_state_51077d14",
                                VL_API_SHOW_ONE_MAP_REGISTER_STATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_one_map_register_state_reply_f15abb16",
                                VL_API_SHOW_ONE_MAP_REGISTER_STATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_map_request_mode_ffa5d2f5",
                                VL_API_ONE_MAP_REQUEST_MODE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_map_request_mode_reply_e8d4e804",
                                VL_API_ONE_MAP_REQUEST_MODE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_one_map_request_mode_51077d14",
                                VL_API_SHOW_ONE_MAP_REQUEST_MODE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_one_map_request_mode_reply_d41f3c1d",
                                VL_API_SHOW_ONE_MAP_REQUEST_MODE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_add_del_remote_mapping_6d5c789e",
                                VL_API_ONE_ADD_DEL_REMOTE_MAPPING + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_add_del_remote_mapping_reply_e8d4e804",
                                VL_API_ONE_ADD_DEL_REMOTE_MAPPING_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_add_del_l2_arp_entry_1aa5e8b3",
                                VL_API_ONE_ADD_DEL_L2_ARP_ENTRY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_add_del_l2_arp_entry_reply_e8d4e804",
                                VL_API_ONE_ADD_DEL_L2_ARP_ENTRY_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_l2_arp_entries_get_4d418cf4",
                                VL_API_ONE_L2_ARP_ENTRIES_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_l2_arp_entries_get_reply_b0dd200f",
                                VL_API_ONE_L2_ARP_ENTRIES_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_add_del_ndp_entry_0f8a287c",
                                VL_API_ONE_ADD_DEL_NDP_ENTRY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_add_del_ndp_entry_reply_e8d4e804",
                                VL_API_ONE_ADD_DEL_NDP_ENTRY_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_ndp_entries_get_4d418cf4",
                                VL_API_ONE_NDP_ENTRIES_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_ndp_entries_get_reply_70719b1a",
                                VL_API_ONE_NDP_ENTRIES_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_set_transport_protocol_07b6b85f",
                                VL_API_ONE_SET_TRANSPORT_PROTOCOL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_set_transport_protocol_reply_e8d4e804",
                                VL_API_ONE_SET_TRANSPORT_PROTOCOL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_get_transport_protocol_51077d14",
                                VL_API_ONE_GET_TRANSPORT_PROTOCOL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_get_transport_protocol_reply_62a28eb3",
                                VL_API_ONE_GET_TRANSPORT_PROTOCOL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_ndp_bd_get_51077d14",
                                VL_API_ONE_NDP_BD_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_ndp_bd_get_reply_221ac888",
                                VL_API_ONE_NDP_BD_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_l2_arp_bd_get_51077d14",
                                VL_API_ONE_L2_ARP_BD_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_l2_arp_bd_get_reply_221ac888",
                                VL_API_ONE_L2_ARP_BD_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_add_del_adjacency_9e830312",
                                VL_API_ONE_ADD_DEL_ADJACENCY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_add_del_adjacency_reply_e8d4e804",
                                VL_API_ONE_ADD_DEL_ADJACENCY_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_add_del_map_request_itr_rlocs_6be88e45",
                                VL_API_ONE_ADD_DEL_MAP_REQUEST_ITR_RLOCS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_add_del_map_request_itr_rlocs_reply_e8d4e804",
                                VL_API_ONE_ADD_DEL_MAP_REQUEST_ITR_RLOCS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_eid_table_add_del_map_9481416b",
                                VL_API_ONE_EID_TABLE_ADD_DEL_MAP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_eid_table_add_del_map_reply_e8d4e804",
                                VL_API_ONE_EID_TABLE_ADD_DEL_MAP_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_locator_dump_9b11076c",
                                VL_API_ONE_LOCATOR_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_locator_details_2c620ffe",
                                VL_API_ONE_LOCATOR_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_locator_set_details_5b33a105",
                                VL_API_ONE_LOCATOR_SET_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_locator_set_dump_71190768",
                                VL_API_ONE_LOCATOR_SET_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_eid_table_details_1c29f792",
                                VL_API_ONE_EID_TABLE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_eid_table_dump_bd190269",
                                VL_API_ONE_EID_TABLE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_adjacencies_get_reply_085bab89",
                                VL_API_ONE_ADJACENCIES_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_adjacencies_get_8d1f2fe9",
                                VL_API_ONE_ADJACENCIES_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_eid_table_map_details_0b6859e2",
                                VL_API_ONE_EID_TABLE_MAP_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_eid_table_map_dump_d6cf0c3d",
                                VL_API_ONE_EID_TABLE_MAP_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_eid_table_vni_dump_51077d14",
                                VL_API_ONE_EID_TABLE_VNI_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_eid_table_vni_details_64abc01e",
                                VL_API_ONE_EID_TABLE_VNI_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_map_resolver_details_3e78fc57",
                                VL_API_ONE_MAP_RESOLVER_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_map_resolver_dump_51077d14",
                                VL_API_ONE_MAP_RESOLVER_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_map_server_details_3e78fc57",
                                VL_API_ONE_MAP_SERVER_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_map_server_dump_51077d14",
                                VL_API_ONE_MAP_SERVER_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_one_status_51077d14",
                                VL_API_SHOW_ONE_STATUS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_one_status_reply_961bb25b",
                                VL_API_SHOW_ONE_STATUS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_get_map_request_itr_rlocs_51077d14",
                                VL_API_ONE_GET_MAP_REQUEST_ITR_RLOCS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_get_map_request_itr_rlocs_reply_76580f3a",
                                VL_API_ONE_GET_MAP_REQUEST_ITR_RLOCS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_one_nsh_mapping_51077d14",
                                VL_API_SHOW_ONE_NSH_MAPPING + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_one_nsh_mapping_reply_46478c02",
                                VL_API_SHOW_ONE_NSH_MAPPING_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_one_pitr_51077d14",
                                VL_API_SHOW_ONE_PITR + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_one_pitr_reply_a2d1a49f",
                                VL_API_SHOW_ONE_PITR_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_stats_dump_51077d14",
                                VL_API_ONE_STATS_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_stats_details_2eb74678",
                                VL_API_ONE_STATS_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_stats_flush_51077d14",
                                VL_API_ONE_STATS_FLUSH + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_stats_flush_reply_e8d4e804",
                                VL_API_ONE_STATS_FLUSH_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_stats_enable_disable_c264d7bf",
                                VL_API_ONE_STATS_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_stats_enable_disable_reply_e8d4e804",
                                VL_API_ONE_STATS_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_one_stats_enable_disable_51077d14",
                                VL_API_SHOW_ONE_STATS_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_one_stats_enable_disable_reply_f15abb16",
                                VL_API_SHOW_ONE_STATS_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_map_register_fallback_threshold_f7d4a475",
                                VL_API_ONE_MAP_REGISTER_FALLBACK_THRESHOLD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_map_register_fallback_threshold_reply_e8d4e804",
                                VL_API_ONE_MAP_REGISTER_FALLBACK_THRESHOLD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_one_map_register_fallback_threshold_51077d14",
                                VL_API_SHOW_ONE_MAP_REGISTER_FALLBACK_THRESHOLD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_one_map_register_fallback_threshold_reply_c93a9113",
                                VL_API_SHOW_ONE_MAP_REGISTER_FALLBACK_THRESHOLD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_enable_disable_xtr_mode_c264d7bf",
                                VL_API_ONE_ENABLE_DISABLE_XTR_MODE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_enable_disable_xtr_mode_reply_e8d4e804",
                                VL_API_ONE_ENABLE_DISABLE_XTR_MODE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_show_xtr_mode_51077d14",
                                VL_API_ONE_SHOW_XTR_MODE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_show_xtr_mode_reply_f15abb16",
                                VL_API_ONE_SHOW_XTR_MODE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_enable_disable_petr_mode_c264d7bf",
                                VL_API_ONE_ENABLE_DISABLE_PETR_MODE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_enable_disable_petr_mode_reply_e8d4e804",
                                VL_API_ONE_ENABLE_DISABLE_PETR_MODE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_show_petr_mode_51077d14",
                                VL_API_ONE_SHOW_PETR_MODE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_show_petr_mode_reply_f15abb16",
                                VL_API_ONE_SHOW_PETR_MODE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_enable_disable_pitr_mode_c264d7bf",
                                VL_API_ONE_ENABLE_DISABLE_PITR_MODE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_enable_disable_pitr_mode_reply_e8d4e804",
                                VL_API_ONE_ENABLE_DISABLE_PITR_MODE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_show_pitr_mode_51077d14",
                                VL_API_ONE_SHOW_PITR_MODE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "one_show_pitr_mode_reply_f15abb16",
                                VL_API_ONE_SHOW_PITR_MODE_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_ADD_DEL_LOCATOR_SET + msg_id_base,
   .name = "one_add_del_locator_set",
   .handler = vl_api_one_add_del_locator_set_t_handler,
   .endian = vl_api_one_add_del_locator_set_t_endian,
   .format_fn = vl_api_one_add_del_locator_set_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_add_del_locator_set_t_tojson,
   .fromjson = vl_api_one_add_del_locator_set_t_fromjson,
   .calc_size = vl_api_one_add_del_locator_set_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_ADD_DEL_LOCATOR_SET_REPLY + msg_id_base,
  .name = "one_add_del_locator_set_reply",
  .handler = 0,
  .endian = vl_api_one_add_del_locator_set_reply_t_endian,
  .format_fn = vl_api_one_add_del_locator_set_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_add_del_locator_set_reply_t_tojson,
  .fromjson = vl_api_one_add_del_locator_set_reply_t_fromjson,
  .calc_size = vl_api_one_add_del_locator_set_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_ADD_DEL_LOCATOR + msg_id_base,
   .name = "one_add_del_locator",
   .handler = vl_api_one_add_del_locator_t_handler,
   .endian = vl_api_one_add_del_locator_t_endian,
   .format_fn = vl_api_one_add_del_locator_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_add_del_locator_t_tojson,
   .fromjson = vl_api_one_add_del_locator_t_fromjson,
   .calc_size = vl_api_one_add_del_locator_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_ADD_DEL_LOCATOR_REPLY + msg_id_base,
  .name = "one_add_del_locator_reply",
  .handler = 0,
  .endian = vl_api_one_add_del_locator_reply_t_endian,
  .format_fn = vl_api_one_add_del_locator_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_add_del_locator_reply_t_tojson,
  .fromjson = vl_api_one_add_del_locator_reply_t_fromjson,
  .calc_size = vl_api_one_add_del_locator_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_ADD_DEL_LOCAL_EID + msg_id_base,
   .name = "one_add_del_local_eid",
   .handler = vl_api_one_add_del_local_eid_t_handler,
   .endian = vl_api_one_add_del_local_eid_t_endian,
   .format_fn = vl_api_one_add_del_local_eid_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_add_del_local_eid_t_tojson,
   .fromjson = vl_api_one_add_del_local_eid_t_fromjson,
   .calc_size = vl_api_one_add_del_local_eid_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_ADD_DEL_LOCAL_EID_REPLY + msg_id_base,
  .name = "one_add_del_local_eid_reply",
  .handler = 0,
  .endian = vl_api_one_add_del_local_eid_reply_t_endian,
  .format_fn = vl_api_one_add_del_local_eid_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_add_del_local_eid_reply_t_tojson,
  .fromjson = vl_api_one_add_del_local_eid_reply_t_fromjson,
  .calc_size = vl_api_one_add_del_local_eid_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_MAP_REGISTER_SET_TTL + msg_id_base,
   .name = "one_map_register_set_ttl",
   .handler = vl_api_one_map_register_set_ttl_t_handler,
   .endian = vl_api_one_map_register_set_ttl_t_endian,
   .format_fn = vl_api_one_map_register_set_ttl_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_map_register_set_ttl_t_tojson,
   .fromjson = vl_api_one_map_register_set_ttl_t_fromjson,
   .calc_size = vl_api_one_map_register_set_ttl_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_MAP_REGISTER_SET_TTL_REPLY + msg_id_base,
  .name = "one_map_register_set_ttl_reply",
  .handler = 0,
  .endian = vl_api_one_map_register_set_ttl_reply_t_endian,
  .format_fn = vl_api_one_map_register_set_ttl_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_map_register_set_ttl_reply_t_tojson,
  .fromjson = vl_api_one_map_register_set_ttl_reply_t_fromjson,
  .calc_size = vl_api_one_map_register_set_ttl_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SHOW_ONE_MAP_REGISTER_TTL + msg_id_base,
   .name = "show_one_map_register_ttl",
   .handler = vl_api_show_one_map_register_ttl_t_handler,
   .endian = vl_api_show_one_map_register_ttl_t_endian,
   .format_fn = vl_api_show_one_map_register_ttl_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_show_one_map_register_ttl_t_tojson,
   .fromjson = vl_api_show_one_map_register_ttl_t_fromjson,
   .calc_size = vl_api_show_one_map_register_ttl_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SHOW_ONE_MAP_REGISTER_TTL_REPLY + msg_id_base,
  .name = "show_one_map_register_ttl_reply",
  .handler = 0,
  .endian = vl_api_show_one_map_register_ttl_reply_t_endian,
  .format_fn = vl_api_show_one_map_register_ttl_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_show_one_map_register_ttl_reply_t_tojson,
  .fromjson = vl_api_show_one_map_register_ttl_reply_t_fromjson,
  .calc_size = vl_api_show_one_map_register_ttl_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_ADD_DEL_MAP_SERVER + msg_id_base,
   .name = "one_add_del_map_server",
   .handler = vl_api_one_add_del_map_server_t_handler,
   .endian = vl_api_one_add_del_map_server_t_endian,
   .format_fn = vl_api_one_add_del_map_server_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_add_del_map_server_t_tojson,
   .fromjson = vl_api_one_add_del_map_server_t_fromjson,
   .calc_size = vl_api_one_add_del_map_server_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_ADD_DEL_MAP_SERVER_REPLY + msg_id_base,
  .name = "one_add_del_map_server_reply",
  .handler = 0,
  .endian = vl_api_one_add_del_map_server_reply_t_endian,
  .format_fn = vl_api_one_add_del_map_server_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_add_del_map_server_reply_t_tojson,
  .fromjson = vl_api_one_add_del_map_server_reply_t_fromjson,
  .calc_size = vl_api_one_add_del_map_server_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_ADD_DEL_MAP_RESOLVER + msg_id_base,
   .name = "one_add_del_map_resolver",
   .handler = vl_api_one_add_del_map_resolver_t_handler,
   .endian = vl_api_one_add_del_map_resolver_t_endian,
   .format_fn = vl_api_one_add_del_map_resolver_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_add_del_map_resolver_t_tojson,
   .fromjson = vl_api_one_add_del_map_resolver_t_fromjson,
   .calc_size = vl_api_one_add_del_map_resolver_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_ADD_DEL_MAP_RESOLVER_REPLY + msg_id_base,
  .name = "one_add_del_map_resolver_reply",
  .handler = 0,
  .endian = vl_api_one_add_del_map_resolver_reply_t_endian,
  .format_fn = vl_api_one_add_del_map_resolver_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_add_del_map_resolver_reply_t_tojson,
  .fromjson = vl_api_one_add_del_map_resolver_reply_t_fromjson,
  .calc_size = vl_api_one_add_del_map_resolver_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_ENABLE_DISABLE + msg_id_base,
   .name = "one_enable_disable",
   .handler = vl_api_one_enable_disable_t_handler,
   .endian = vl_api_one_enable_disable_t_endian,
   .format_fn = vl_api_one_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_enable_disable_t_tojson,
   .fromjson = vl_api_one_enable_disable_t_fromjson,
   .calc_size = vl_api_one_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "one_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_one_enable_disable_reply_t_endian,
  .format_fn = vl_api_one_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_enable_disable_reply_t_tojson,
  .fromjson = vl_api_one_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_one_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_NSH_SET_LOCATOR_SET + msg_id_base,
   .name = "one_nsh_set_locator_set",
   .handler = vl_api_one_nsh_set_locator_set_t_handler,
   .endian = vl_api_one_nsh_set_locator_set_t_endian,
   .format_fn = vl_api_one_nsh_set_locator_set_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_nsh_set_locator_set_t_tojson,
   .fromjson = vl_api_one_nsh_set_locator_set_t_fromjson,
   .calc_size = vl_api_one_nsh_set_locator_set_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_NSH_SET_LOCATOR_SET_REPLY + msg_id_base,
  .name = "one_nsh_set_locator_set_reply",
  .handler = 0,
  .endian = vl_api_one_nsh_set_locator_set_reply_t_endian,
  .format_fn = vl_api_one_nsh_set_locator_set_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_nsh_set_locator_set_reply_t_tojson,
  .fromjson = vl_api_one_nsh_set_locator_set_reply_t_fromjson,
  .calc_size = vl_api_one_nsh_set_locator_set_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_PITR_SET_LOCATOR_SET + msg_id_base,
   .name = "one_pitr_set_locator_set",
   .handler = vl_api_one_pitr_set_locator_set_t_handler,
   .endian = vl_api_one_pitr_set_locator_set_t_endian,
   .format_fn = vl_api_one_pitr_set_locator_set_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_pitr_set_locator_set_t_tojson,
   .fromjson = vl_api_one_pitr_set_locator_set_t_fromjson,
   .calc_size = vl_api_one_pitr_set_locator_set_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_PITR_SET_LOCATOR_SET_REPLY + msg_id_base,
  .name = "one_pitr_set_locator_set_reply",
  .handler = 0,
  .endian = vl_api_one_pitr_set_locator_set_reply_t_endian,
  .format_fn = vl_api_one_pitr_set_locator_set_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_pitr_set_locator_set_reply_t_tojson,
  .fromjson = vl_api_one_pitr_set_locator_set_reply_t_fromjson,
  .calc_size = vl_api_one_pitr_set_locator_set_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_USE_PETR + msg_id_base,
   .name = "one_use_petr",
   .handler = vl_api_one_use_petr_t_handler,
   .endian = vl_api_one_use_petr_t_endian,
   .format_fn = vl_api_one_use_petr_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_use_petr_t_tojson,
   .fromjson = vl_api_one_use_petr_t_fromjson,
   .calc_size = vl_api_one_use_petr_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_USE_PETR_REPLY + msg_id_base,
  .name = "one_use_petr_reply",
  .handler = 0,
  .endian = vl_api_one_use_petr_reply_t_endian,
  .format_fn = vl_api_one_use_petr_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_use_petr_reply_t_tojson,
  .fromjson = vl_api_one_use_petr_reply_t_fromjson,
  .calc_size = vl_api_one_use_petr_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SHOW_ONE_USE_PETR + msg_id_base,
   .name = "show_one_use_petr",
   .handler = vl_api_show_one_use_petr_t_handler,
   .endian = vl_api_show_one_use_petr_t_endian,
   .format_fn = vl_api_show_one_use_petr_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_show_one_use_petr_t_tojson,
   .fromjson = vl_api_show_one_use_petr_t_fromjson,
   .calc_size = vl_api_show_one_use_petr_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SHOW_ONE_USE_PETR_REPLY + msg_id_base,
  .name = "show_one_use_petr_reply",
  .handler = 0,
  .endian = vl_api_show_one_use_petr_reply_t_endian,
  .format_fn = vl_api_show_one_use_petr_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_show_one_use_petr_reply_t_tojson,
  .fromjson = vl_api_show_one_use_petr_reply_t_fromjson,
  .calc_size = vl_api_show_one_use_petr_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SHOW_ONE_RLOC_PROBE_STATE + msg_id_base,
   .name = "show_one_rloc_probe_state",
   .handler = vl_api_show_one_rloc_probe_state_t_handler,
   .endian = vl_api_show_one_rloc_probe_state_t_endian,
   .format_fn = vl_api_show_one_rloc_probe_state_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_show_one_rloc_probe_state_t_tojson,
   .fromjson = vl_api_show_one_rloc_probe_state_t_fromjson,
   .calc_size = vl_api_show_one_rloc_probe_state_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SHOW_ONE_RLOC_PROBE_STATE_REPLY + msg_id_base,
  .name = "show_one_rloc_probe_state_reply",
  .handler = 0,
  .endian = vl_api_show_one_rloc_probe_state_reply_t_endian,
  .format_fn = vl_api_show_one_rloc_probe_state_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_show_one_rloc_probe_state_reply_t_tojson,
  .fromjson = vl_api_show_one_rloc_probe_state_reply_t_fromjson,
  .calc_size = vl_api_show_one_rloc_probe_state_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_RLOC_PROBE_ENABLE_DISABLE + msg_id_base,
   .name = "one_rloc_probe_enable_disable",
   .handler = vl_api_one_rloc_probe_enable_disable_t_handler,
   .endian = vl_api_one_rloc_probe_enable_disable_t_endian,
   .format_fn = vl_api_one_rloc_probe_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_rloc_probe_enable_disable_t_tojson,
   .fromjson = vl_api_one_rloc_probe_enable_disable_t_fromjson,
   .calc_size = vl_api_one_rloc_probe_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_RLOC_PROBE_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "one_rloc_probe_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_one_rloc_probe_enable_disable_reply_t_endian,
  .format_fn = vl_api_one_rloc_probe_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_rloc_probe_enable_disable_reply_t_tojson,
  .fromjson = vl_api_one_rloc_probe_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_one_rloc_probe_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_MAP_REGISTER_ENABLE_DISABLE + msg_id_base,
   .name = "one_map_register_enable_disable",
   .handler = vl_api_one_map_register_enable_disable_t_handler,
   .endian = vl_api_one_map_register_enable_disable_t_endian,
   .format_fn = vl_api_one_map_register_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_map_register_enable_disable_t_tojson,
   .fromjson = vl_api_one_map_register_enable_disable_t_fromjson,
   .calc_size = vl_api_one_map_register_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_MAP_REGISTER_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "one_map_register_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_one_map_register_enable_disable_reply_t_endian,
  .format_fn = vl_api_one_map_register_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_map_register_enable_disable_reply_t_tojson,
  .fromjson = vl_api_one_map_register_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_one_map_register_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SHOW_ONE_MAP_REGISTER_STATE + msg_id_base,
   .name = "show_one_map_register_state",
   .handler = vl_api_show_one_map_register_state_t_handler,
   .endian = vl_api_show_one_map_register_state_t_endian,
   .format_fn = vl_api_show_one_map_register_state_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_show_one_map_register_state_t_tojson,
   .fromjson = vl_api_show_one_map_register_state_t_fromjson,
   .calc_size = vl_api_show_one_map_register_state_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SHOW_ONE_MAP_REGISTER_STATE_REPLY + msg_id_base,
  .name = "show_one_map_register_state_reply",
  .handler = 0,
  .endian = vl_api_show_one_map_register_state_reply_t_endian,
  .format_fn = vl_api_show_one_map_register_state_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_show_one_map_register_state_reply_t_tojson,
  .fromjson = vl_api_show_one_map_register_state_reply_t_fromjson,
  .calc_size = vl_api_show_one_map_register_state_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_MAP_REQUEST_MODE + msg_id_base,
   .name = "one_map_request_mode",
   .handler = vl_api_one_map_request_mode_t_handler,
   .endian = vl_api_one_map_request_mode_t_endian,
   .format_fn = vl_api_one_map_request_mode_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_map_request_mode_t_tojson,
   .fromjson = vl_api_one_map_request_mode_t_fromjson,
   .calc_size = vl_api_one_map_request_mode_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_MAP_REQUEST_MODE_REPLY + msg_id_base,
  .name = "one_map_request_mode_reply",
  .handler = 0,
  .endian = vl_api_one_map_request_mode_reply_t_endian,
  .format_fn = vl_api_one_map_request_mode_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_map_request_mode_reply_t_tojson,
  .fromjson = vl_api_one_map_request_mode_reply_t_fromjson,
  .calc_size = vl_api_one_map_request_mode_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SHOW_ONE_MAP_REQUEST_MODE + msg_id_base,
   .name = "show_one_map_request_mode",
   .handler = vl_api_show_one_map_request_mode_t_handler,
   .endian = vl_api_show_one_map_request_mode_t_endian,
   .format_fn = vl_api_show_one_map_request_mode_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_show_one_map_request_mode_t_tojson,
   .fromjson = vl_api_show_one_map_request_mode_t_fromjson,
   .calc_size = vl_api_show_one_map_request_mode_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SHOW_ONE_MAP_REQUEST_MODE_REPLY + msg_id_base,
  .name = "show_one_map_request_mode_reply",
  .handler = 0,
  .endian = vl_api_show_one_map_request_mode_reply_t_endian,
  .format_fn = vl_api_show_one_map_request_mode_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_show_one_map_request_mode_reply_t_tojson,
  .fromjson = vl_api_show_one_map_request_mode_reply_t_fromjson,
  .calc_size = vl_api_show_one_map_request_mode_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_ADD_DEL_REMOTE_MAPPING + msg_id_base,
   .name = "one_add_del_remote_mapping",
   .handler = vl_api_one_add_del_remote_mapping_t_handler,
   .endian = vl_api_one_add_del_remote_mapping_t_endian,
   .format_fn = vl_api_one_add_del_remote_mapping_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_add_del_remote_mapping_t_tojson,
   .fromjson = vl_api_one_add_del_remote_mapping_t_fromjson,
   .calc_size = vl_api_one_add_del_remote_mapping_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_ADD_DEL_REMOTE_MAPPING_REPLY + msg_id_base,
  .name = "one_add_del_remote_mapping_reply",
  .handler = 0,
  .endian = vl_api_one_add_del_remote_mapping_reply_t_endian,
  .format_fn = vl_api_one_add_del_remote_mapping_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_add_del_remote_mapping_reply_t_tojson,
  .fromjson = vl_api_one_add_del_remote_mapping_reply_t_fromjson,
  .calc_size = vl_api_one_add_del_remote_mapping_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_ADD_DEL_L2_ARP_ENTRY + msg_id_base,
   .name = "one_add_del_l2_arp_entry",
   .handler = vl_api_one_add_del_l2_arp_entry_t_handler,
   .endian = vl_api_one_add_del_l2_arp_entry_t_endian,
   .format_fn = vl_api_one_add_del_l2_arp_entry_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_add_del_l2_arp_entry_t_tojson,
   .fromjson = vl_api_one_add_del_l2_arp_entry_t_fromjson,
   .calc_size = vl_api_one_add_del_l2_arp_entry_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_ADD_DEL_L2_ARP_ENTRY_REPLY + msg_id_base,
  .name = "one_add_del_l2_arp_entry_reply",
  .handler = 0,
  .endian = vl_api_one_add_del_l2_arp_entry_reply_t_endian,
  .format_fn = vl_api_one_add_del_l2_arp_entry_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_add_del_l2_arp_entry_reply_t_tojson,
  .fromjson = vl_api_one_add_del_l2_arp_entry_reply_t_fromjson,
  .calc_size = vl_api_one_add_del_l2_arp_entry_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_L2_ARP_ENTRIES_GET + msg_id_base,
   .name = "one_l2_arp_entries_get",
   .handler = vl_api_one_l2_arp_entries_get_t_handler,
   .endian = vl_api_one_l2_arp_entries_get_t_endian,
   .format_fn = vl_api_one_l2_arp_entries_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_l2_arp_entries_get_t_tojson,
   .fromjson = vl_api_one_l2_arp_entries_get_t_fromjson,
   .calc_size = vl_api_one_l2_arp_entries_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_L2_ARP_ENTRIES_GET_REPLY + msg_id_base,
  .name = "one_l2_arp_entries_get_reply",
  .handler = 0,
  .endian = vl_api_one_l2_arp_entries_get_reply_t_endian,
  .format_fn = vl_api_one_l2_arp_entries_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_l2_arp_entries_get_reply_t_tojson,
  .fromjson = vl_api_one_l2_arp_entries_get_reply_t_fromjson,
  .calc_size = vl_api_one_l2_arp_entries_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_ADD_DEL_NDP_ENTRY + msg_id_base,
   .name = "one_add_del_ndp_entry",
   .handler = vl_api_one_add_del_ndp_entry_t_handler,
   .endian = vl_api_one_add_del_ndp_entry_t_endian,
   .format_fn = vl_api_one_add_del_ndp_entry_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_add_del_ndp_entry_t_tojson,
   .fromjson = vl_api_one_add_del_ndp_entry_t_fromjson,
   .calc_size = vl_api_one_add_del_ndp_entry_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_ADD_DEL_NDP_ENTRY_REPLY + msg_id_base,
  .name = "one_add_del_ndp_entry_reply",
  .handler = 0,
  .endian = vl_api_one_add_del_ndp_entry_reply_t_endian,
  .format_fn = vl_api_one_add_del_ndp_entry_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_add_del_ndp_entry_reply_t_tojson,
  .fromjson = vl_api_one_add_del_ndp_entry_reply_t_fromjson,
  .calc_size = vl_api_one_add_del_ndp_entry_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_NDP_ENTRIES_GET + msg_id_base,
   .name = "one_ndp_entries_get",
   .handler = vl_api_one_ndp_entries_get_t_handler,
   .endian = vl_api_one_ndp_entries_get_t_endian,
   .format_fn = vl_api_one_ndp_entries_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_ndp_entries_get_t_tojson,
   .fromjson = vl_api_one_ndp_entries_get_t_fromjson,
   .calc_size = vl_api_one_ndp_entries_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_NDP_ENTRIES_GET_REPLY + msg_id_base,
  .name = "one_ndp_entries_get_reply",
  .handler = 0,
  .endian = vl_api_one_ndp_entries_get_reply_t_endian,
  .format_fn = vl_api_one_ndp_entries_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_ndp_entries_get_reply_t_tojson,
  .fromjson = vl_api_one_ndp_entries_get_reply_t_fromjson,
  .calc_size = vl_api_one_ndp_entries_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_SET_TRANSPORT_PROTOCOL + msg_id_base,
   .name = "one_set_transport_protocol",
   .handler = vl_api_one_set_transport_protocol_t_handler,
   .endian = vl_api_one_set_transport_protocol_t_endian,
   .format_fn = vl_api_one_set_transport_protocol_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_set_transport_protocol_t_tojson,
   .fromjson = vl_api_one_set_transport_protocol_t_fromjson,
   .calc_size = vl_api_one_set_transport_protocol_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_SET_TRANSPORT_PROTOCOL_REPLY + msg_id_base,
  .name = "one_set_transport_protocol_reply",
  .handler = 0,
  .endian = vl_api_one_set_transport_protocol_reply_t_endian,
  .format_fn = vl_api_one_set_transport_protocol_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_set_transport_protocol_reply_t_tojson,
  .fromjson = vl_api_one_set_transport_protocol_reply_t_fromjson,
  .calc_size = vl_api_one_set_transport_protocol_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_GET_TRANSPORT_PROTOCOL + msg_id_base,
   .name = "one_get_transport_protocol",
   .handler = vl_api_one_get_transport_protocol_t_handler,
   .endian = vl_api_one_get_transport_protocol_t_endian,
   .format_fn = vl_api_one_get_transport_protocol_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_get_transport_protocol_t_tojson,
   .fromjson = vl_api_one_get_transport_protocol_t_fromjson,
   .calc_size = vl_api_one_get_transport_protocol_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_GET_TRANSPORT_PROTOCOL_REPLY + msg_id_base,
  .name = "one_get_transport_protocol_reply",
  .handler = 0,
  .endian = vl_api_one_get_transport_protocol_reply_t_endian,
  .format_fn = vl_api_one_get_transport_protocol_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_get_transport_protocol_reply_t_tojson,
  .fromjson = vl_api_one_get_transport_protocol_reply_t_fromjson,
  .calc_size = vl_api_one_get_transport_protocol_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_NDP_BD_GET + msg_id_base,
   .name = "one_ndp_bd_get",
   .handler = vl_api_one_ndp_bd_get_t_handler,
   .endian = vl_api_one_ndp_bd_get_t_endian,
   .format_fn = vl_api_one_ndp_bd_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_ndp_bd_get_t_tojson,
   .fromjson = vl_api_one_ndp_bd_get_t_fromjson,
   .calc_size = vl_api_one_ndp_bd_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_NDP_BD_GET_REPLY + msg_id_base,
  .name = "one_ndp_bd_get_reply",
  .handler = 0,
  .endian = vl_api_one_ndp_bd_get_reply_t_endian,
  .format_fn = vl_api_one_ndp_bd_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_ndp_bd_get_reply_t_tojson,
  .fromjson = vl_api_one_ndp_bd_get_reply_t_fromjson,
  .calc_size = vl_api_one_ndp_bd_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_L2_ARP_BD_GET + msg_id_base,
   .name = "one_l2_arp_bd_get",
   .handler = vl_api_one_l2_arp_bd_get_t_handler,
   .endian = vl_api_one_l2_arp_bd_get_t_endian,
   .format_fn = vl_api_one_l2_arp_bd_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_l2_arp_bd_get_t_tojson,
   .fromjson = vl_api_one_l2_arp_bd_get_t_fromjson,
   .calc_size = vl_api_one_l2_arp_bd_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_L2_ARP_BD_GET_REPLY + msg_id_base,
  .name = "one_l2_arp_bd_get_reply",
  .handler = 0,
  .endian = vl_api_one_l2_arp_bd_get_reply_t_endian,
  .format_fn = vl_api_one_l2_arp_bd_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_l2_arp_bd_get_reply_t_tojson,
  .fromjson = vl_api_one_l2_arp_bd_get_reply_t_fromjson,
  .calc_size = vl_api_one_l2_arp_bd_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_ADD_DEL_ADJACENCY + msg_id_base,
   .name = "one_add_del_adjacency",
   .handler = vl_api_one_add_del_adjacency_t_handler,
   .endian = vl_api_one_add_del_adjacency_t_endian,
   .format_fn = vl_api_one_add_del_adjacency_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_add_del_adjacency_t_tojson,
   .fromjson = vl_api_one_add_del_adjacency_t_fromjson,
   .calc_size = vl_api_one_add_del_adjacency_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_ADD_DEL_ADJACENCY_REPLY + msg_id_base,
  .name = "one_add_del_adjacency_reply",
  .handler = 0,
  .endian = vl_api_one_add_del_adjacency_reply_t_endian,
  .format_fn = vl_api_one_add_del_adjacency_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_add_del_adjacency_reply_t_tojson,
  .fromjson = vl_api_one_add_del_adjacency_reply_t_fromjson,
  .calc_size = vl_api_one_add_del_adjacency_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_ADD_DEL_MAP_REQUEST_ITR_RLOCS + msg_id_base,
   .name = "one_add_del_map_request_itr_rlocs",
   .handler = vl_api_one_add_del_map_request_itr_rlocs_t_handler,
   .endian = vl_api_one_add_del_map_request_itr_rlocs_t_endian,
   .format_fn = vl_api_one_add_del_map_request_itr_rlocs_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_add_del_map_request_itr_rlocs_t_tojson,
   .fromjson = vl_api_one_add_del_map_request_itr_rlocs_t_fromjson,
   .calc_size = vl_api_one_add_del_map_request_itr_rlocs_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_ADD_DEL_MAP_REQUEST_ITR_RLOCS_REPLY + msg_id_base,
  .name = "one_add_del_map_request_itr_rlocs_reply",
  .handler = 0,
  .endian = vl_api_one_add_del_map_request_itr_rlocs_reply_t_endian,
  .format_fn = vl_api_one_add_del_map_request_itr_rlocs_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_add_del_map_request_itr_rlocs_reply_t_tojson,
  .fromjson = vl_api_one_add_del_map_request_itr_rlocs_reply_t_fromjson,
  .calc_size = vl_api_one_add_del_map_request_itr_rlocs_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_EID_TABLE_ADD_DEL_MAP + msg_id_base,
   .name = "one_eid_table_add_del_map",
   .handler = vl_api_one_eid_table_add_del_map_t_handler,
   .endian = vl_api_one_eid_table_add_del_map_t_endian,
   .format_fn = vl_api_one_eid_table_add_del_map_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_eid_table_add_del_map_t_tojson,
   .fromjson = vl_api_one_eid_table_add_del_map_t_fromjson,
   .calc_size = vl_api_one_eid_table_add_del_map_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_EID_TABLE_ADD_DEL_MAP_REPLY + msg_id_base,
  .name = "one_eid_table_add_del_map_reply",
  .handler = 0,
  .endian = vl_api_one_eid_table_add_del_map_reply_t_endian,
  .format_fn = vl_api_one_eid_table_add_del_map_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_eid_table_add_del_map_reply_t_tojson,
  .fromjson = vl_api_one_eid_table_add_del_map_reply_t_fromjson,
  .calc_size = vl_api_one_eid_table_add_del_map_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_LOCATOR_DUMP + msg_id_base,
   .name = "one_locator_dump",
   .handler = vl_api_one_locator_dump_t_handler,
   .endian = vl_api_one_locator_dump_t_endian,
   .format_fn = vl_api_one_locator_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_locator_dump_t_tojson,
   .fromjson = vl_api_one_locator_dump_t_fromjson,
   .calc_size = vl_api_one_locator_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_LOCATOR_DETAILS + msg_id_base,
  .name = "one_locator_details",
  .handler = 0,
  .endian = vl_api_one_locator_details_t_endian,
  .format_fn = vl_api_one_locator_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_locator_details_t_tojson,
  .fromjson = vl_api_one_locator_details_t_fromjson,
  .calc_size = vl_api_one_locator_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_LOCATOR_SET_DUMP + msg_id_base,
   .name = "one_locator_set_dump",
   .handler = vl_api_one_locator_set_dump_t_handler,
   .endian = vl_api_one_locator_set_dump_t_endian,
   .format_fn = vl_api_one_locator_set_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_locator_set_dump_t_tojson,
   .fromjson = vl_api_one_locator_set_dump_t_fromjson,
   .calc_size = vl_api_one_locator_set_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_LOCATOR_SET_DETAILS + msg_id_base,
  .name = "one_locator_set_details",
  .handler = 0,
  .endian = vl_api_one_locator_set_details_t_endian,
  .format_fn = vl_api_one_locator_set_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_locator_set_details_t_tojson,
  .fromjson = vl_api_one_locator_set_details_t_fromjson,
  .calc_size = vl_api_one_locator_set_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_EID_TABLE_DUMP + msg_id_base,
   .name = "one_eid_table_dump",
   .handler = vl_api_one_eid_table_dump_t_handler,
   .endian = vl_api_one_eid_table_dump_t_endian,
   .format_fn = vl_api_one_eid_table_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_eid_table_dump_t_tojson,
   .fromjson = vl_api_one_eid_table_dump_t_fromjson,
   .calc_size = vl_api_one_eid_table_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_EID_TABLE_DETAILS + msg_id_base,
  .name = "one_eid_table_details",
  .handler = 0,
  .endian = vl_api_one_eid_table_details_t_endian,
  .format_fn = vl_api_one_eid_table_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_eid_table_details_t_tojson,
  .fromjson = vl_api_one_eid_table_details_t_fromjson,
  .calc_size = vl_api_one_eid_table_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_ADJACENCIES_GET + msg_id_base,
   .name = "one_adjacencies_get",
   .handler = vl_api_one_adjacencies_get_t_handler,
   .endian = vl_api_one_adjacencies_get_t_endian,
   .format_fn = vl_api_one_adjacencies_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_adjacencies_get_t_tojson,
   .fromjson = vl_api_one_adjacencies_get_t_fromjson,
   .calc_size = vl_api_one_adjacencies_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_ADJACENCIES_GET_REPLY + msg_id_base,
  .name = "one_adjacencies_get_reply",
  .handler = 0,
  .endian = vl_api_one_adjacencies_get_reply_t_endian,
  .format_fn = vl_api_one_adjacencies_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_adjacencies_get_reply_t_tojson,
  .fromjson = vl_api_one_adjacencies_get_reply_t_fromjson,
  .calc_size = vl_api_one_adjacencies_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_EID_TABLE_MAP_DUMP + msg_id_base,
   .name = "one_eid_table_map_dump",
   .handler = vl_api_one_eid_table_map_dump_t_handler,
   .endian = vl_api_one_eid_table_map_dump_t_endian,
   .format_fn = vl_api_one_eid_table_map_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_eid_table_map_dump_t_tojson,
   .fromjson = vl_api_one_eid_table_map_dump_t_fromjson,
   .calc_size = vl_api_one_eid_table_map_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_EID_TABLE_MAP_DETAILS + msg_id_base,
  .name = "one_eid_table_map_details",
  .handler = 0,
  .endian = vl_api_one_eid_table_map_details_t_endian,
  .format_fn = vl_api_one_eid_table_map_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_eid_table_map_details_t_tojson,
  .fromjson = vl_api_one_eid_table_map_details_t_fromjson,
  .calc_size = vl_api_one_eid_table_map_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_EID_TABLE_VNI_DUMP + msg_id_base,
   .name = "one_eid_table_vni_dump",
   .handler = vl_api_one_eid_table_vni_dump_t_handler,
   .endian = vl_api_one_eid_table_vni_dump_t_endian,
   .format_fn = vl_api_one_eid_table_vni_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_eid_table_vni_dump_t_tojson,
   .fromjson = vl_api_one_eid_table_vni_dump_t_fromjson,
   .calc_size = vl_api_one_eid_table_vni_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_EID_TABLE_VNI_DETAILS + msg_id_base,
  .name = "one_eid_table_vni_details",
  .handler = 0,
  .endian = vl_api_one_eid_table_vni_details_t_endian,
  .format_fn = vl_api_one_eid_table_vni_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_eid_table_vni_details_t_tojson,
  .fromjson = vl_api_one_eid_table_vni_details_t_fromjson,
  .calc_size = vl_api_one_eid_table_vni_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_MAP_RESOLVER_DUMP + msg_id_base,
   .name = "one_map_resolver_dump",
   .handler = vl_api_one_map_resolver_dump_t_handler,
   .endian = vl_api_one_map_resolver_dump_t_endian,
   .format_fn = vl_api_one_map_resolver_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_map_resolver_dump_t_tojson,
   .fromjson = vl_api_one_map_resolver_dump_t_fromjson,
   .calc_size = vl_api_one_map_resolver_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_MAP_RESOLVER_DETAILS + msg_id_base,
  .name = "one_map_resolver_details",
  .handler = 0,
  .endian = vl_api_one_map_resolver_details_t_endian,
  .format_fn = vl_api_one_map_resolver_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_map_resolver_details_t_tojson,
  .fromjson = vl_api_one_map_resolver_details_t_fromjson,
  .calc_size = vl_api_one_map_resolver_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_MAP_SERVER_DUMP + msg_id_base,
   .name = "one_map_server_dump",
   .handler = vl_api_one_map_server_dump_t_handler,
   .endian = vl_api_one_map_server_dump_t_endian,
   .format_fn = vl_api_one_map_server_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_map_server_dump_t_tojson,
   .fromjson = vl_api_one_map_server_dump_t_fromjson,
   .calc_size = vl_api_one_map_server_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_MAP_SERVER_DETAILS + msg_id_base,
  .name = "one_map_server_details",
  .handler = 0,
  .endian = vl_api_one_map_server_details_t_endian,
  .format_fn = vl_api_one_map_server_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_map_server_details_t_tojson,
  .fromjson = vl_api_one_map_server_details_t_fromjson,
  .calc_size = vl_api_one_map_server_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SHOW_ONE_STATUS + msg_id_base,
   .name = "show_one_status",
   .handler = vl_api_show_one_status_t_handler,
   .endian = vl_api_show_one_status_t_endian,
   .format_fn = vl_api_show_one_status_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_show_one_status_t_tojson,
   .fromjson = vl_api_show_one_status_t_fromjson,
   .calc_size = vl_api_show_one_status_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SHOW_ONE_STATUS_REPLY + msg_id_base,
  .name = "show_one_status_reply",
  .handler = 0,
  .endian = vl_api_show_one_status_reply_t_endian,
  .format_fn = vl_api_show_one_status_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_show_one_status_reply_t_tojson,
  .fromjson = vl_api_show_one_status_reply_t_fromjson,
  .calc_size = vl_api_show_one_status_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_GET_MAP_REQUEST_ITR_RLOCS + msg_id_base,
   .name = "one_get_map_request_itr_rlocs",
   .handler = vl_api_one_get_map_request_itr_rlocs_t_handler,
   .endian = vl_api_one_get_map_request_itr_rlocs_t_endian,
   .format_fn = vl_api_one_get_map_request_itr_rlocs_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_get_map_request_itr_rlocs_t_tojson,
   .fromjson = vl_api_one_get_map_request_itr_rlocs_t_fromjson,
   .calc_size = vl_api_one_get_map_request_itr_rlocs_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_GET_MAP_REQUEST_ITR_RLOCS_REPLY + msg_id_base,
  .name = "one_get_map_request_itr_rlocs_reply",
  .handler = 0,
  .endian = vl_api_one_get_map_request_itr_rlocs_reply_t_endian,
  .format_fn = vl_api_one_get_map_request_itr_rlocs_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_get_map_request_itr_rlocs_reply_t_tojson,
  .fromjson = vl_api_one_get_map_request_itr_rlocs_reply_t_fromjson,
  .calc_size = vl_api_one_get_map_request_itr_rlocs_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SHOW_ONE_NSH_MAPPING + msg_id_base,
   .name = "show_one_nsh_mapping",
   .handler = vl_api_show_one_nsh_mapping_t_handler,
   .endian = vl_api_show_one_nsh_mapping_t_endian,
   .format_fn = vl_api_show_one_nsh_mapping_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_show_one_nsh_mapping_t_tojson,
   .fromjson = vl_api_show_one_nsh_mapping_t_fromjson,
   .calc_size = vl_api_show_one_nsh_mapping_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SHOW_ONE_NSH_MAPPING_REPLY + msg_id_base,
  .name = "show_one_nsh_mapping_reply",
  .handler = 0,
  .endian = vl_api_show_one_nsh_mapping_reply_t_endian,
  .format_fn = vl_api_show_one_nsh_mapping_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_show_one_nsh_mapping_reply_t_tojson,
  .fromjson = vl_api_show_one_nsh_mapping_reply_t_fromjson,
  .calc_size = vl_api_show_one_nsh_mapping_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SHOW_ONE_PITR + msg_id_base,
   .name = "show_one_pitr",
   .handler = vl_api_show_one_pitr_t_handler,
   .endian = vl_api_show_one_pitr_t_endian,
   .format_fn = vl_api_show_one_pitr_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_show_one_pitr_t_tojson,
   .fromjson = vl_api_show_one_pitr_t_fromjson,
   .calc_size = vl_api_show_one_pitr_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SHOW_ONE_PITR_REPLY + msg_id_base,
  .name = "show_one_pitr_reply",
  .handler = 0,
  .endian = vl_api_show_one_pitr_reply_t_endian,
  .format_fn = vl_api_show_one_pitr_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_show_one_pitr_reply_t_tojson,
  .fromjson = vl_api_show_one_pitr_reply_t_fromjson,
  .calc_size = vl_api_show_one_pitr_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_STATS_DUMP + msg_id_base,
   .name = "one_stats_dump",
   .handler = vl_api_one_stats_dump_t_handler,
   .endian = vl_api_one_stats_dump_t_endian,
   .format_fn = vl_api_one_stats_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_stats_dump_t_tojson,
   .fromjson = vl_api_one_stats_dump_t_fromjson,
   .calc_size = vl_api_one_stats_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_STATS_DETAILS + msg_id_base,
  .name = "one_stats_details",
  .handler = 0,
  .endian = vl_api_one_stats_details_t_endian,
  .format_fn = vl_api_one_stats_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_stats_details_t_tojson,
  .fromjson = vl_api_one_stats_details_t_fromjson,
  .calc_size = vl_api_one_stats_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_STATS_FLUSH + msg_id_base,
   .name = "one_stats_flush",
   .handler = vl_api_one_stats_flush_t_handler,
   .endian = vl_api_one_stats_flush_t_endian,
   .format_fn = vl_api_one_stats_flush_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_stats_flush_t_tojson,
   .fromjson = vl_api_one_stats_flush_t_fromjson,
   .calc_size = vl_api_one_stats_flush_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_STATS_FLUSH_REPLY + msg_id_base,
  .name = "one_stats_flush_reply",
  .handler = 0,
  .endian = vl_api_one_stats_flush_reply_t_endian,
  .format_fn = vl_api_one_stats_flush_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_stats_flush_reply_t_tojson,
  .fromjson = vl_api_one_stats_flush_reply_t_fromjson,
  .calc_size = vl_api_one_stats_flush_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_STATS_ENABLE_DISABLE + msg_id_base,
   .name = "one_stats_enable_disable",
   .handler = vl_api_one_stats_enable_disable_t_handler,
   .endian = vl_api_one_stats_enable_disable_t_endian,
   .format_fn = vl_api_one_stats_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_stats_enable_disable_t_tojson,
   .fromjson = vl_api_one_stats_enable_disable_t_fromjson,
   .calc_size = vl_api_one_stats_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_STATS_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "one_stats_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_one_stats_enable_disable_reply_t_endian,
  .format_fn = vl_api_one_stats_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_stats_enable_disable_reply_t_tojson,
  .fromjson = vl_api_one_stats_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_one_stats_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SHOW_ONE_STATS_ENABLE_DISABLE + msg_id_base,
   .name = "show_one_stats_enable_disable",
   .handler = vl_api_show_one_stats_enable_disable_t_handler,
   .endian = vl_api_show_one_stats_enable_disable_t_endian,
   .format_fn = vl_api_show_one_stats_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_show_one_stats_enable_disable_t_tojson,
   .fromjson = vl_api_show_one_stats_enable_disable_t_fromjson,
   .calc_size = vl_api_show_one_stats_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SHOW_ONE_STATS_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "show_one_stats_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_show_one_stats_enable_disable_reply_t_endian,
  .format_fn = vl_api_show_one_stats_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_show_one_stats_enable_disable_reply_t_tojson,
  .fromjson = vl_api_show_one_stats_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_show_one_stats_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_MAP_REGISTER_FALLBACK_THRESHOLD + msg_id_base,
   .name = "one_map_register_fallback_threshold",
   .handler = vl_api_one_map_register_fallback_threshold_t_handler,
   .endian = vl_api_one_map_register_fallback_threshold_t_endian,
   .format_fn = vl_api_one_map_register_fallback_threshold_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_map_register_fallback_threshold_t_tojson,
   .fromjson = vl_api_one_map_register_fallback_threshold_t_fromjson,
   .calc_size = vl_api_one_map_register_fallback_threshold_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_MAP_REGISTER_FALLBACK_THRESHOLD_REPLY + msg_id_base,
  .name = "one_map_register_fallback_threshold_reply",
  .handler = 0,
  .endian = vl_api_one_map_register_fallback_threshold_reply_t_endian,
  .format_fn = vl_api_one_map_register_fallback_threshold_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_map_register_fallback_threshold_reply_t_tojson,
  .fromjson = vl_api_one_map_register_fallback_threshold_reply_t_fromjson,
  .calc_size = vl_api_one_map_register_fallback_threshold_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SHOW_ONE_MAP_REGISTER_FALLBACK_THRESHOLD + msg_id_base,
   .name = "show_one_map_register_fallback_threshold",
   .handler = vl_api_show_one_map_register_fallback_threshold_t_handler,
   .endian = vl_api_show_one_map_register_fallback_threshold_t_endian,
   .format_fn = vl_api_show_one_map_register_fallback_threshold_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_show_one_map_register_fallback_threshold_t_tojson,
   .fromjson = vl_api_show_one_map_register_fallback_threshold_t_fromjson,
   .calc_size = vl_api_show_one_map_register_fallback_threshold_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SHOW_ONE_MAP_REGISTER_FALLBACK_THRESHOLD_REPLY + msg_id_base,
  .name = "show_one_map_register_fallback_threshold_reply",
  .handler = 0,
  .endian = vl_api_show_one_map_register_fallback_threshold_reply_t_endian,
  .format_fn = vl_api_show_one_map_register_fallback_threshold_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_show_one_map_register_fallback_threshold_reply_t_tojson,
  .fromjson = vl_api_show_one_map_register_fallback_threshold_reply_t_fromjson,
  .calc_size = vl_api_show_one_map_register_fallback_threshold_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_ENABLE_DISABLE_XTR_MODE + msg_id_base,
   .name = "one_enable_disable_xtr_mode",
   .handler = vl_api_one_enable_disable_xtr_mode_t_handler,
   .endian = vl_api_one_enable_disable_xtr_mode_t_endian,
   .format_fn = vl_api_one_enable_disable_xtr_mode_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_enable_disable_xtr_mode_t_tojson,
   .fromjson = vl_api_one_enable_disable_xtr_mode_t_fromjson,
   .calc_size = vl_api_one_enable_disable_xtr_mode_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_ENABLE_DISABLE_XTR_MODE_REPLY + msg_id_base,
  .name = "one_enable_disable_xtr_mode_reply",
  .handler = 0,
  .endian = vl_api_one_enable_disable_xtr_mode_reply_t_endian,
  .format_fn = vl_api_one_enable_disable_xtr_mode_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_enable_disable_xtr_mode_reply_t_tojson,
  .fromjson = vl_api_one_enable_disable_xtr_mode_reply_t_fromjson,
  .calc_size = vl_api_one_enable_disable_xtr_mode_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_SHOW_XTR_MODE + msg_id_base,
   .name = "one_show_xtr_mode",
   .handler = vl_api_one_show_xtr_mode_t_handler,
   .endian = vl_api_one_show_xtr_mode_t_endian,
   .format_fn = vl_api_one_show_xtr_mode_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_show_xtr_mode_t_tojson,
   .fromjson = vl_api_one_show_xtr_mode_t_fromjson,
   .calc_size = vl_api_one_show_xtr_mode_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_SHOW_XTR_MODE_REPLY + msg_id_base,
  .name = "one_show_xtr_mode_reply",
  .handler = 0,
  .endian = vl_api_one_show_xtr_mode_reply_t_endian,
  .format_fn = vl_api_one_show_xtr_mode_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_show_xtr_mode_reply_t_tojson,
  .fromjson = vl_api_one_show_xtr_mode_reply_t_fromjson,
  .calc_size = vl_api_one_show_xtr_mode_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_ENABLE_DISABLE_PETR_MODE + msg_id_base,
   .name = "one_enable_disable_petr_mode",
   .handler = vl_api_one_enable_disable_petr_mode_t_handler,
   .endian = vl_api_one_enable_disable_petr_mode_t_endian,
   .format_fn = vl_api_one_enable_disable_petr_mode_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_enable_disable_petr_mode_t_tojson,
   .fromjson = vl_api_one_enable_disable_petr_mode_t_fromjson,
   .calc_size = vl_api_one_enable_disable_petr_mode_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_ENABLE_DISABLE_PETR_MODE_REPLY + msg_id_base,
  .name = "one_enable_disable_petr_mode_reply",
  .handler = 0,
  .endian = vl_api_one_enable_disable_petr_mode_reply_t_endian,
  .format_fn = vl_api_one_enable_disable_petr_mode_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_enable_disable_petr_mode_reply_t_tojson,
  .fromjson = vl_api_one_enable_disable_petr_mode_reply_t_fromjson,
  .calc_size = vl_api_one_enable_disable_petr_mode_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_SHOW_PETR_MODE + msg_id_base,
   .name = "one_show_petr_mode",
   .handler = vl_api_one_show_petr_mode_t_handler,
   .endian = vl_api_one_show_petr_mode_t_endian,
   .format_fn = vl_api_one_show_petr_mode_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_show_petr_mode_t_tojson,
   .fromjson = vl_api_one_show_petr_mode_t_fromjson,
   .calc_size = vl_api_one_show_petr_mode_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_SHOW_PETR_MODE_REPLY + msg_id_base,
  .name = "one_show_petr_mode_reply",
  .handler = 0,
  .endian = vl_api_one_show_petr_mode_reply_t_endian,
  .format_fn = vl_api_one_show_petr_mode_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_show_petr_mode_reply_t_tojson,
  .fromjson = vl_api_one_show_petr_mode_reply_t_fromjson,
  .calc_size = vl_api_one_show_petr_mode_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_ENABLE_DISABLE_PITR_MODE + msg_id_base,
   .name = "one_enable_disable_pitr_mode",
   .handler = vl_api_one_enable_disable_pitr_mode_t_handler,
   .endian = vl_api_one_enable_disable_pitr_mode_t_endian,
   .format_fn = vl_api_one_enable_disable_pitr_mode_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_enable_disable_pitr_mode_t_tojson,
   .fromjson = vl_api_one_enable_disable_pitr_mode_t_fromjson,
   .calc_size = vl_api_one_enable_disable_pitr_mode_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_ENABLE_DISABLE_PITR_MODE_REPLY + msg_id_base,
  .name = "one_enable_disable_pitr_mode_reply",
  .handler = 0,
  .endian = vl_api_one_enable_disable_pitr_mode_reply_t_endian,
  .format_fn = vl_api_one_enable_disable_pitr_mode_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_enable_disable_pitr_mode_reply_t_tojson,
  .fromjson = vl_api_one_enable_disable_pitr_mode_reply_t_fromjson,
  .calc_size = vl_api_one_enable_disable_pitr_mode_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ONE_SHOW_PITR_MODE + msg_id_base,
   .name = "one_show_pitr_mode",
   .handler = vl_api_one_show_pitr_mode_t_handler,
   .endian = vl_api_one_show_pitr_mode_t_endian,
   .format_fn = vl_api_one_show_pitr_mode_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_one_show_pitr_mode_t_tojson,
   .fromjson = vl_api_one_show_pitr_mode_t_fromjson,
   .calc_size = vl_api_one_show_pitr_mode_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ONE_SHOW_PITR_MODE_REPLY + msg_id_base,
  .name = "one_show_pitr_mode_reply",
  .handler = 0,
  .endian = vl_api_one_show_pitr_mode_reply_t_endian,
  .format_fn = vl_api_one_show_pitr_mode_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_one_show_pitr_mode_reply_t_tojson,
  .fromjson = vl_api_one_show_pitr_mode_reply_t_fromjson,
  .calc_size = vl_api_one_show_pitr_mode_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
