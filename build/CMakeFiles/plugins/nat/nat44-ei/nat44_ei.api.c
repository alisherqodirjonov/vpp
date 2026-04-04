#define vl_endianfun		/* define message structures */
#include "nat44_ei.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "nat44_ei.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "nat44_ei.api.h"
#undef vl_printfun

#include "nat44_ei.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("nat44_ei_20734fe0", VL_MSG_NAT44_EI_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_nat44_ei);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_plugin_enable_disable_bf692144",
                                VL_API_NAT44_EI_PLUGIN_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_plugin_enable_disable_reply_e8d4e804",
                                VL_API_NAT44_EI_PLUGIN_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_show_running_config_51077d14",
                                VL_API_NAT44_EI_SHOW_RUNNING_CONFIG + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_show_running_config_reply_41b66a81",
                                VL_API_NAT44_EI_SHOW_RUNNING_CONFIG_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_set_log_level_70076bfe",
                                VL_API_NAT44_EI_SET_LOG_LEVEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_set_log_level_reply_e8d4e804",
                                VL_API_NAT44_EI_SET_LOG_LEVEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_set_workers_da926638",
                                VL_API_NAT44_EI_SET_WORKERS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_set_workers_reply_e8d4e804",
                                VL_API_NAT44_EI_SET_WORKERS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_worker_dump_51077d14",
                                VL_API_NAT44_EI_WORKER_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_worker_details_84bf06fc",
                                VL_API_NAT44_EI_WORKER_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_ipfix_enable_disable_9af4a2d2",
                                VL_API_NAT44_EI_IPFIX_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_ipfix_enable_disable_reply_e8d4e804",
                                VL_API_NAT44_EI_IPFIX_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_set_timeouts_d4746b16",
                                VL_API_NAT44_EI_SET_TIMEOUTS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_set_timeouts_reply_e8d4e804",
                                VL_API_NAT44_EI_SET_TIMEOUTS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_set_addr_and_port_alloc_alg_deeb746f",
                                VL_API_NAT44_EI_SET_ADDR_AND_PORT_ALLOC_ALG + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_set_addr_and_port_alloc_alg_reply_e8d4e804",
                                VL_API_NAT44_EI_SET_ADDR_AND_PORT_ALLOC_ALG_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_get_addr_and_port_alloc_alg_51077d14",
                                VL_API_NAT44_EI_GET_ADDR_AND_PORT_ALLOC_ALG + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_get_addr_and_port_alloc_alg_reply_3607a7d0",
                                VL_API_NAT44_EI_GET_ADDR_AND_PORT_ALLOC_ALG_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_set_mss_clamping_25e90abb",
                                VL_API_NAT44_EI_SET_MSS_CLAMPING + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_set_mss_clamping_reply_e8d4e804",
                                VL_API_NAT44_EI_SET_MSS_CLAMPING_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_get_mss_clamping_51077d14",
                                VL_API_NAT44_EI_GET_MSS_CLAMPING + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_get_mss_clamping_reply_1c0b2a78",
                                VL_API_NAT44_EI_GET_MSS_CLAMPING_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_ha_set_listener_e4a8cb4e",
                                VL_API_NAT44_EI_HA_SET_LISTENER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_ha_set_listener_reply_e8d4e804",
                                VL_API_NAT44_EI_HA_SET_LISTENER_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_ha_set_failover_718246af",
                                VL_API_NAT44_EI_HA_SET_FAILOVER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_ha_set_failover_reply_e8d4e804",
                                VL_API_NAT44_EI_HA_SET_FAILOVER_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_ha_get_listener_51077d14",
                                VL_API_NAT44_EI_HA_GET_LISTENER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_ha_get_listener_reply_123ea41f",
                                VL_API_NAT44_EI_HA_GET_LISTENER_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_ha_get_failover_51077d14",
                                VL_API_NAT44_EI_HA_GET_FAILOVER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_ha_get_failover_reply_a67d8752",
                                VL_API_NAT44_EI_HA_GET_FAILOVER_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_ha_flush_51077d14",
                                VL_API_NAT44_EI_HA_FLUSH + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_ha_flush_reply_e8d4e804",
                                VL_API_NAT44_EI_HA_FLUSH_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_ha_resync_c8ab9e03",
                                VL_API_NAT44_EI_HA_RESYNC + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_ha_resync_reply_e8d4e804",
                                VL_API_NAT44_EI_HA_RESYNC_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_ha_resync_completed_event_fdc598fb",
                                VL_API_NAT44_EI_HA_RESYNC_COMPLETED_EVENT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_del_user_99a9f998",
                                VL_API_NAT44_EI_DEL_USER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_del_user_reply_e8d4e804",
                                VL_API_NAT44_EI_DEL_USER_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_add_del_address_range_35f21abc",
                                VL_API_NAT44_EI_ADD_DEL_ADDRESS_RANGE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_add_del_address_range_reply_e8d4e804",
                                VL_API_NAT44_EI_ADD_DEL_ADDRESS_RANGE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_address_dump_51077d14",
                                VL_API_NAT44_EI_ADDRESS_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_address_details_318f1202",
                                VL_API_NAT44_EI_ADDRESS_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_interface_add_del_feature_63a2db8b",
                                VL_API_NAT44_EI_INTERFACE_ADD_DEL_FEATURE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_interface_add_del_feature_reply_e8d4e804",
                                VL_API_NAT44_EI_INTERFACE_ADD_DEL_FEATURE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_interface_dump_51077d14",
                                VL_API_NAT44_EI_INTERFACE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_interface_details_f446e508",
                                VL_API_NAT44_EI_INTERFACE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_interface_add_del_output_feature_63a2db8b",
                                VL_API_NAT44_EI_INTERFACE_ADD_DEL_OUTPUT_FEATURE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_interface_add_del_output_feature_reply_e8d4e804",
                                VL_API_NAT44_EI_INTERFACE_ADD_DEL_OUTPUT_FEATURE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_interface_output_feature_dump_51077d14",
                                VL_API_NAT44_EI_INTERFACE_OUTPUT_FEATURE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_interface_output_feature_details_f446e508",
                                VL_API_NAT44_EI_INTERFACE_OUTPUT_FEATURE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_add_del_output_interface_47d6e753",
                                VL_API_NAT44_EI_ADD_DEL_OUTPUT_INTERFACE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_add_del_output_interface_reply_e8d4e804",
                                VL_API_NAT44_EI_ADD_DEL_OUTPUT_INTERFACE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_output_interface_get_f75ba505",
                                VL_API_NAT44_EI_OUTPUT_INTERFACE_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_output_interface_get_reply_53b48f5d",
                                VL_API_NAT44_EI_OUTPUT_INTERFACE_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_output_interface_details_0b45011c",
                                VL_API_NAT44_EI_OUTPUT_INTERFACE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_add_del_static_mapping_b404b7fe",
                                VL_API_NAT44_EI_ADD_DEL_STATIC_MAPPING + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_add_del_static_mapping_reply_e8d4e804",
                                VL_API_NAT44_EI_ADD_DEL_STATIC_MAPPING_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_static_mapping_dump_51077d14",
                                VL_API_NAT44_EI_STATIC_MAPPING_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_static_mapping_details_6b51ca6e",
                                VL_API_NAT44_EI_STATIC_MAPPING_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_add_del_identity_mapping_cb8606b9",
                                VL_API_NAT44_EI_ADD_DEL_IDENTITY_MAPPING + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_add_del_identity_mapping_reply_e8d4e804",
                                VL_API_NAT44_EI_ADD_DEL_IDENTITY_MAPPING_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_identity_mapping_dump_51077d14",
                                VL_API_NAT44_EI_IDENTITY_MAPPING_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_identity_mapping_details_30d53e26",
                                VL_API_NAT44_EI_IDENTITY_MAPPING_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_add_del_interface_addr_883abbcc",
                                VL_API_NAT44_EI_ADD_DEL_INTERFACE_ADDR + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_add_del_interface_addr_reply_e8d4e804",
                                VL_API_NAT44_EI_ADD_DEL_INTERFACE_ADDR_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_interface_addr_dump_51077d14",
                                VL_API_NAT44_EI_INTERFACE_ADDR_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_interface_addr_details_0b45011c",
                                VL_API_NAT44_EI_INTERFACE_ADDR_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_user_dump_51077d14",
                                VL_API_NAT44_EI_USER_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_user_details_355896c2",
                                VL_API_NAT44_EI_USER_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_user_session_dump_e1899c98",
                                VL_API_NAT44_EI_USER_SESSION_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_user_session_details_19b7c0ac",
                                VL_API_NAT44_EI_USER_SESSION_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_user_session_v2_dump_e1899c98",
                                VL_API_NAT44_EI_USER_SESSION_V2_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_user_session_v2_details_5bd3e9d6",
                                VL_API_NAT44_EI_USER_SESSION_V2_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_del_session_74969ffe",
                                VL_API_NAT44_EI_DEL_SESSION + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_del_session_reply_e8d4e804",
                                VL_API_NAT44_EI_DEL_SESSION_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_forwarding_enable_disable_b3e225d2",
                                VL_API_NAT44_EI_FORWARDING_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_forwarding_enable_disable_reply_e8d4e804",
                                VL_API_NAT44_EI_FORWARDING_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_set_fq_options_2399bd71",
                                VL_API_NAT44_EI_SET_FQ_OPTIONS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_set_fq_options_reply_e8d4e804",
                                VL_API_NAT44_EI_SET_FQ_OPTIONS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_show_fq_options_51077d14",
                                VL_API_NAT44_EI_SHOW_FQ_OPTIONS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ei_show_fq_options_reply_7213b545",
                                VL_API_NAT44_EI_SHOW_FQ_OPTIONS_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_HA_RESYNC + msg_id_base,
   .name = "nat44_ei_ha_resync",
   .handler = vl_api_nat44_ei_ha_resync_t_handler,
   .endian = vl_api_nat44_ei_ha_resync_t_endian,
   .format_fn = vl_api_nat44_ei_ha_resync_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_ha_resync_t_tojson,
   .fromjson = vl_api_nat44_ei_ha_resync_t_fromjson,
   .calc_size = vl_api_nat44_ei_ha_resync_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_HA_RESYNC_REPLY + msg_id_base,
  .name = "nat44_ei_ha_resync_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_ha_resync_reply_t_endian,
  .format_fn = vl_api_nat44_ei_ha_resync_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_ha_resync_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_ha_resync_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_ha_resync_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_OUTPUT_INTERFACE_GET + msg_id_base,
   .name = "nat44_ei_output_interface_get",
   .handler = vl_api_nat44_ei_output_interface_get_t_handler,
   .endian = vl_api_nat44_ei_output_interface_get_t_endian,
   .format_fn = vl_api_nat44_ei_output_interface_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_output_interface_get_t_tojson,
   .fromjson = vl_api_nat44_ei_output_interface_get_t_fromjson,
   .calc_size = vl_api_nat44_ei_output_interface_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_OUTPUT_INTERFACE_GET_REPLY + msg_id_base,
  .name = "nat44_ei_output_interface_get_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_output_interface_get_reply_t_endian,
  .format_fn = vl_api_nat44_ei_output_interface_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_output_interface_get_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_output_interface_get_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_output_interface_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_OUTPUT_INTERFACE_DETAILS + msg_id_base,
  .name = "nat44_ei_output_interface_details",
  .handler = 0,
  .endian = vl_api_nat44_ei_output_interface_details_t_endian,
  .format_fn = vl_api_nat44_ei_output_interface_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_output_interface_details_t_tojson,
  .fromjson = vl_api_nat44_ei_output_interface_details_t_fromjson,
  .calc_size = vl_api_nat44_ei_output_interface_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_PLUGIN_ENABLE_DISABLE + msg_id_base,
   .name = "nat44_ei_plugin_enable_disable",
   .handler = vl_api_nat44_ei_plugin_enable_disable_t_handler,
   .endian = vl_api_nat44_ei_plugin_enable_disable_t_endian,
   .format_fn = vl_api_nat44_ei_plugin_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_plugin_enable_disable_t_tojson,
   .fromjson = vl_api_nat44_ei_plugin_enable_disable_t_fromjson,
   .calc_size = vl_api_nat44_ei_plugin_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_PLUGIN_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "nat44_ei_plugin_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_plugin_enable_disable_reply_t_endian,
  .format_fn = vl_api_nat44_ei_plugin_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_plugin_enable_disable_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_plugin_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_plugin_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_SHOW_RUNNING_CONFIG + msg_id_base,
   .name = "nat44_ei_show_running_config",
   .handler = vl_api_nat44_ei_show_running_config_t_handler,
   .endian = vl_api_nat44_ei_show_running_config_t_endian,
   .format_fn = vl_api_nat44_ei_show_running_config_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_show_running_config_t_tojson,
   .fromjson = vl_api_nat44_ei_show_running_config_t_fromjson,
   .calc_size = vl_api_nat44_ei_show_running_config_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_SHOW_RUNNING_CONFIG_REPLY + msg_id_base,
  .name = "nat44_ei_show_running_config_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_show_running_config_reply_t_endian,
  .format_fn = vl_api_nat44_ei_show_running_config_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_show_running_config_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_show_running_config_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_show_running_config_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_SET_LOG_LEVEL + msg_id_base,
   .name = "nat44_ei_set_log_level",
   .handler = vl_api_nat44_ei_set_log_level_t_handler,
   .endian = vl_api_nat44_ei_set_log_level_t_endian,
   .format_fn = vl_api_nat44_ei_set_log_level_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_set_log_level_t_tojson,
   .fromjson = vl_api_nat44_ei_set_log_level_t_fromjson,
   .calc_size = vl_api_nat44_ei_set_log_level_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_SET_LOG_LEVEL_REPLY + msg_id_base,
  .name = "nat44_ei_set_log_level_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_set_log_level_reply_t_endian,
  .format_fn = vl_api_nat44_ei_set_log_level_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_set_log_level_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_set_log_level_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_set_log_level_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_SET_WORKERS + msg_id_base,
   .name = "nat44_ei_set_workers",
   .handler = vl_api_nat44_ei_set_workers_t_handler,
   .endian = vl_api_nat44_ei_set_workers_t_endian,
   .format_fn = vl_api_nat44_ei_set_workers_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_set_workers_t_tojson,
   .fromjson = vl_api_nat44_ei_set_workers_t_fromjson,
   .calc_size = vl_api_nat44_ei_set_workers_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_SET_WORKERS_REPLY + msg_id_base,
  .name = "nat44_ei_set_workers_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_set_workers_reply_t_endian,
  .format_fn = vl_api_nat44_ei_set_workers_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_set_workers_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_set_workers_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_set_workers_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_WORKER_DUMP + msg_id_base,
   .name = "nat44_ei_worker_dump",
   .handler = vl_api_nat44_ei_worker_dump_t_handler,
   .endian = vl_api_nat44_ei_worker_dump_t_endian,
   .format_fn = vl_api_nat44_ei_worker_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_worker_dump_t_tojson,
   .fromjson = vl_api_nat44_ei_worker_dump_t_fromjson,
   .calc_size = vl_api_nat44_ei_worker_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_WORKER_DETAILS + msg_id_base,
  .name = "nat44_ei_worker_details",
  .handler = 0,
  .endian = vl_api_nat44_ei_worker_details_t_endian,
  .format_fn = vl_api_nat44_ei_worker_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_worker_details_t_tojson,
  .fromjson = vl_api_nat44_ei_worker_details_t_fromjson,
  .calc_size = vl_api_nat44_ei_worker_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_IPFIX_ENABLE_DISABLE + msg_id_base,
   .name = "nat44_ei_ipfix_enable_disable",
   .handler = vl_api_nat44_ei_ipfix_enable_disable_t_handler,
   .endian = vl_api_nat44_ei_ipfix_enable_disable_t_endian,
   .format_fn = vl_api_nat44_ei_ipfix_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_ipfix_enable_disable_t_tojson,
   .fromjson = vl_api_nat44_ei_ipfix_enable_disable_t_fromjson,
   .calc_size = vl_api_nat44_ei_ipfix_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_IPFIX_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "nat44_ei_ipfix_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_ipfix_enable_disable_reply_t_endian,
  .format_fn = vl_api_nat44_ei_ipfix_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_ipfix_enable_disable_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_ipfix_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_ipfix_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_SET_TIMEOUTS + msg_id_base,
   .name = "nat44_ei_set_timeouts",
   .handler = vl_api_nat44_ei_set_timeouts_t_handler,
   .endian = vl_api_nat44_ei_set_timeouts_t_endian,
   .format_fn = vl_api_nat44_ei_set_timeouts_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_set_timeouts_t_tojson,
   .fromjson = vl_api_nat44_ei_set_timeouts_t_fromjson,
   .calc_size = vl_api_nat44_ei_set_timeouts_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_SET_TIMEOUTS_REPLY + msg_id_base,
  .name = "nat44_ei_set_timeouts_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_set_timeouts_reply_t_endian,
  .format_fn = vl_api_nat44_ei_set_timeouts_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_set_timeouts_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_set_timeouts_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_set_timeouts_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_SET_ADDR_AND_PORT_ALLOC_ALG + msg_id_base,
   .name = "nat44_ei_set_addr_and_port_alloc_alg",
   .handler = vl_api_nat44_ei_set_addr_and_port_alloc_alg_t_handler,
   .endian = vl_api_nat44_ei_set_addr_and_port_alloc_alg_t_endian,
   .format_fn = vl_api_nat44_ei_set_addr_and_port_alloc_alg_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_set_addr_and_port_alloc_alg_t_tojson,
   .fromjson = vl_api_nat44_ei_set_addr_and_port_alloc_alg_t_fromjson,
   .calc_size = vl_api_nat44_ei_set_addr_and_port_alloc_alg_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_SET_ADDR_AND_PORT_ALLOC_ALG_REPLY + msg_id_base,
  .name = "nat44_ei_set_addr_and_port_alloc_alg_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t_endian,
  .format_fn = vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_GET_ADDR_AND_PORT_ALLOC_ALG + msg_id_base,
   .name = "nat44_ei_get_addr_and_port_alloc_alg",
   .handler = vl_api_nat44_ei_get_addr_and_port_alloc_alg_t_handler,
   .endian = vl_api_nat44_ei_get_addr_and_port_alloc_alg_t_endian,
   .format_fn = vl_api_nat44_ei_get_addr_and_port_alloc_alg_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_get_addr_and_port_alloc_alg_t_tojson,
   .fromjson = vl_api_nat44_ei_get_addr_and_port_alloc_alg_t_fromjson,
   .calc_size = vl_api_nat44_ei_get_addr_and_port_alloc_alg_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_GET_ADDR_AND_PORT_ALLOC_ALG_REPLY + msg_id_base,
  .name = "nat44_ei_get_addr_and_port_alloc_alg_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t_endian,
  .format_fn = vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_SET_MSS_CLAMPING + msg_id_base,
   .name = "nat44_ei_set_mss_clamping",
   .handler = vl_api_nat44_ei_set_mss_clamping_t_handler,
   .endian = vl_api_nat44_ei_set_mss_clamping_t_endian,
   .format_fn = vl_api_nat44_ei_set_mss_clamping_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_set_mss_clamping_t_tojson,
   .fromjson = vl_api_nat44_ei_set_mss_clamping_t_fromjson,
   .calc_size = vl_api_nat44_ei_set_mss_clamping_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_SET_MSS_CLAMPING_REPLY + msg_id_base,
  .name = "nat44_ei_set_mss_clamping_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_set_mss_clamping_reply_t_endian,
  .format_fn = vl_api_nat44_ei_set_mss_clamping_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_set_mss_clamping_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_set_mss_clamping_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_set_mss_clamping_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_GET_MSS_CLAMPING + msg_id_base,
   .name = "nat44_ei_get_mss_clamping",
   .handler = vl_api_nat44_ei_get_mss_clamping_t_handler,
   .endian = vl_api_nat44_ei_get_mss_clamping_t_endian,
   .format_fn = vl_api_nat44_ei_get_mss_clamping_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_get_mss_clamping_t_tojson,
   .fromjson = vl_api_nat44_ei_get_mss_clamping_t_fromjson,
   .calc_size = vl_api_nat44_ei_get_mss_clamping_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_GET_MSS_CLAMPING_REPLY + msg_id_base,
  .name = "nat44_ei_get_mss_clamping_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_get_mss_clamping_reply_t_endian,
  .format_fn = vl_api_nat44_ei_get_mss_clamping_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_get_mss_clamping_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_get_mss_clamping_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_get_mss_clamping_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_HA_SET_LISTENER + msg_id_base,
   .name = "nat44_ei_ha_set_listener",
   .handler = vl_api_nat44_ei_ha_set_listener_t_handler,
   .endian = vl_api_nat44_ei_ha_set_listener_t_endian,
   .format_fn = vl_api_nat44_ei_ha_set_listener_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_ha_set_listener_t_tojson,
   .fromjson = vl_api_nat44_ei_ha_set_listener_t_fromjson,
   .calc_size = vl_api_nat44_ei_ha_set_listener_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_HA_SET_LISTENER_REPLY + msg_id_base,
  .name = "nat44_ei_ha_set_listener_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_ha_set_listener_reply_t_endian,
  .format_fn = vl_api_nat44_ei_ha_set_listener_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_ha_set_listener_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_ha_set_listener_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_ha_set_listener_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_HA_SET_FAILOVER + msg_id_base,
   .name = "nat44_ei_ha_set_failover",
   .handler = vl_api_nat44_ei_ha_set_failover_t_handler,
   .endian = vl_api_nat44_ei_ha_set_failover_t_endian,
   .format_fn = vl_api_nat44_ei_ha_set_failover_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_ha_set_failover_t_tojson,
   .fromjson = vl_api_nat44_ei_ha_set_failover_t_fromjson,
   .calc_size = vl_api_nat44_ei_ha_set_failover_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_HA_SET_FAILOVER_REPLY + msg_id_base,
  .name = "nat44_ei_ha_set_failover_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_ha_set_failover_reply_t_endian,
  .format_fn = vl_api_nat44_ei_ha_set_failover_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_ha_set_failover_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_ha_set_failover_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_ha_set_failover_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_HA_GET_LISTENER + msg_id_base,
   .name = "nat44_ei_ha_get_listener",
   .handler = vl_api_nat44_ei_ha_get_listener_t_handler,
   .endian = vl_api_nat44_ei_ha_get_listener_t_endian,
   .format_fn = vl_api_nat44_ei_ha_get_listener_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_ha_get_listener_t_tojson,
   .fromjson = vl_api_nat44_ei_ha_get_listener_t_fromjson,
   .calc_size = vl_api_nat44_ei_ha_get_listener_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_HA_GET_LISTENER_REPLY + msg_id_base,
  .name = "nat44_ei_ha_get_listener_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_ha_get_listener_reply_t_endian,
  .format_fn = vl_api_nat44_ei_ha_get_listener_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_ha_get_listener_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_ha_get_listener_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_ha_get_listener_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_HA_GET_FAILOVER + msg_id_base,
   .name = "nat44_ei_ha_get_failover",
   .handler = vl_api_nat44_ei_ha_get_failover_t_handler,
   .endian = vl_api_nat44_ei_ha_get_failover_t_endian,
   .format_fn = vl_api_nat44_ei_ha_get_failover_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_ha_get_failover_t_tojson,
   .fromjson = vl_api_nat44_ei_ha_get_failover_t_fromjson,
   .calc_size = vl_api_nat44_ei_ha_get_failover_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_HA_GET_FAILOVER_REPLY + msg_id_base,
  .name = "nat44_ei_ha_get_failover_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_ha_get_failover_reply_t_endian,
  .format_fn = vl_api_nat44_ei_ha_get_failover_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_ha_get_failover_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_ha_get_failover_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_ha_get_failover_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_HA_FLUSH + msg_id_base,
   .name = "nat44_ei_ha_flush",
   .handler = vl_api_nat44_ei_ha_flush_t_handler,
   .endian = vl_api_nat44_ei_ha_flush_t_endian,
   .format_fn = vl_api_nat44_ei_ha_flush_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_ha_flush_t_tojson,
   .fromjson = vl_api_nat44_ei_ha_flush_t_fromjson,
   .calc_size = vl_api_nat44_ei_ha_flush_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_HA_FLUSH_REPLY + msg_id_base,
  .name = "nat44_ei_ha_flush_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_ha_flush_reply_t_endian,
  .format_fn = vl_api_nat44_ei_ha_flush_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_ha_flush_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_ha_flush_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_ha_flush_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_DEL_USER + msg_id_base,
   .name = "nat44_ei_del_user",
   .handler = vl_api_nat44_ei_del_user_t_handler,
   .endian = vl_api_nat44_ei_del_user_t_endian,
   .format_fn = vl_api_nat44_ei_del_user_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_del_user_t_tojson,
   .fromjson = vl_api_nat44_ei_del_user_t_fromjson,
   .calc_size = vl_api_nat44_ei_del_user_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_DEL_USER_REPLY + msg_id_base,
  .name = "nat44_ei_del_user_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_del_user_reply_t_endian,
  .format_fn = vl_api_nat44_ei_del_user_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_del_user_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_del_user_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_del_user_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_ADD_DEL_ADDRESS_RANGE + msg_id_base,
   .name = "nat44_ei_add_del_address_range",
   .handler = vl_api_nat44_ei_add_del_address_range_t_handler,
   .endian = vl_api_nat44_ei_add_del_address_range_t_endian,
   .format_fn = vl_api_nat44_ei_add_del_address_range_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_add_del_address_range_t_tojson,
   .fromjson = vl_api_nat44_ei_add_del_address_range_t_fromjson,
   .calc_size = vl_api_nat44_ei_add_del_address_range_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_ADD_DEL_ADDRESS_RANGE_REPLY + msg_id_base,
  .name = "nat44_ei_add_del_address_range_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_add_del_address_range_reply_t_endian,
  .format_fn = vl_api_nat44_ei_add_del_address_range_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_add_del_address_range_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_add_del_address_range_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_add_del_address_range_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_ADDRESS_DUMP + msg_id_base,
   .name = "nat44_ei_address_dump",
   .handler = vl_api_nat44_ei_address_dump_t_handler,
   .endian = vl_api_nat44_ei_address_dump_t_endian,
   .format_fn = vl_api_nat44_ei_address_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_address_dump_t_tojson,
   .fromjson = vl_api_nat44_ei_address_dump_t_fromjson,
   .calc_size = vl_api_nat44_ei_address_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_ADDRESS_DETAILS + msg_id_base,
  .name = "nat44_ei_address_details",
  .handler = 0,
  .endian = vl_api_nat44_ei_address_details_t_endian,
  .format_fn = vl_api_nat44_ei_address_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_address_details_t_tojson,
  .fromjson = vl_api_nat44_ei_address_details_t_fromjson,
  .calc_size = vl_api_nat44_ei_address_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_INTERFACE_ADD_DEL_FEATURE + msg_id_base,
   .name = "nat44_ei_interface_add_del_feature",
   .handler = vl_api_nat44_ei_interface_add_del_feature_t_handler,
   .endian = vl_api_nat44_ei_interface_add_del_feature_t_endian,
   .format_fn = vl_api_nat44_ei_interface_add_del_feature_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_interface_add_del_feature_t_tojson,
   .fromjson = vl_api_nat44_ei_interface_add_del_feature_t_fromjson,
   .calc_size = vl_api_nat44_ei_interface_add_del_feature_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_INTERFACE_ADD_DEL_FEATURE_REPLY + msg_id_base,
  .name = "nat44_ei_interface_add_del_feature_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_interface_add_del_feature_reply_t_endian,
  .format_fn = vl_api_nat44_ei_interface_add_del_feature_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_interface_add_del_feature_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_interface_add_del_feature_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_interface_add_del_feature_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_INTERFACE_DUMP + msg_id_base,
   .name = "nat44_ei_interface_dump",
   .handler = vl_api_nat44_ei_interface_dump_t_handler,
   .endian = vl_api_nat44_ei_interface_dump_t_endian,
   .format_fn = vl_api_nat44_ei_interface_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_interface_dump_t_tojson,
   .fromjson = vl_api_nat44_ei_interface_dump_t_fromjson,
   .calc_size = vl_api_nat44_ei_interface_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_INTERFACE_DETAILS + msg_id_base,
  .name = "nat44_ei_interface_details",
  .handler = 0,
  .endian = vl_api_nat44_ei_interface_details_t_endian,
  .format_fn = vl_api_nat44_ei_interface_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_interface_details_t_tojson,
  .fromjson = vl_api_nat44_ei_interface_details_t_fromjson,
  .calc_size = vl_api_nat44_ei_interface_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_INTERFACE_ADD_DEL_OUTPUT_FEATURE + msg_id_base,
   .name = "nat44_ei_interface_add_del_output_feature",
   .handler = vl_api_nat44_ei_interface_add_del_output_feature_t_handler,
   .endian = vl_api_nat44_ei_interface_add_del_output_feature_t_endian,
   .format_fn = vl_api_nat44_ei_interface_add_del_output_feature_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_interface_add_del_output_feature_t_tojson,
   .fromjson = vl_api_nat44_ei_interface_add_del_output_feature_t_fromjson,
   .calc_size = vl_api_nat44_ei_interface_add_del_output_feature_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_INTERFACE_ADD_DEL_OUTPUT_FEATURE_REPLY + msg_id_base,
  .name = "nat44_ei_interface_add_del_output_feature_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_interface_add_del_output_feature_reply_t_endian,
  .format_fn = vl_api_nat44_ei_interface_add_del_output_feature_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_interface_add_del_output_feature_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_interface_add_del_output_feature_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_interface_add_del_output_feature_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_INTERFACE_OUTPUT_FEATURE_DUMP + msg_id_base,
   .name = "nat44_ei_interface_output_feature_dump",
   .handler = vl_api_nat44_ei_interface_output_feature_dump_t_handler,
   .endian = vl_api_nat44_ei_interface_output_feature_dump_t_endian,
   .format_fn = vl_api_nat44_ei_interface_output_feature_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_interface_output_feature_dump_t_tojson,
   .fromjson = vl_api_nat44_ei_interface_output_feature_dump_t_fromjson,
   .calc_size = vl_api_nat44_ei_interface_output_feature_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_INTERFACE_OUTPUT_FEATURE_DETAILS + msg_id_base,
  .name = "nat44_ei_interface_output_feature_details",
  .handler = 0,
  .endian = vl_api_nat44_ei_interface_output_feature_details_t_endian,
  .format_fn = vl_api_nat44_ei_interface_output_feature_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_interface_output_feature_details_t_tojson,
  .fromjson = vl_api_nat44_ei_interface_output_feature_details_t_fromjson,
  .calc_size = vl_api_nat44_ei_interface_output_feature_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_ADD_DEL_OUTPUT_INTERFACE + msg_id_base,
   .name = "nat44_ei_add_del_output_interface",
   .handler = vl_api_nat44_ei_add_del_output_interface_t_handler,
   .endian = vl_api_nat44_ei_add_del_output_interface_t_endian,
   .format_fn = vl_api_nat44_ei_add_del_output_interface_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_add_del_output_interface_t_tojson,
   .fromjson = vl_api_nat44_ei_add_del_output_interface_t_fromjson,
   .calc_size = vl_api_nat44_ei_add_del_output_interface_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_ADD_DEL_OUTPUT_INTERFACE_REPLY + msg_id_base,
  .name = "nat44_ei_add_del_output_interface_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_add_del_output_interface_reply_t_endian,
  .format_fn = vl_api_nat44_ei_add_del_output_interface_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_add_del_output_interface_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_add_del_output_interface_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_add_del_output_interface_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_ADD_DEL_STATIC_MAPPING + msg_id_base,
   .name = "nat44_ei_add_del_static_mapping",
   .handler = vl_api_nat44_ei_add_del_static_mapping_t_handler,
   .endian = vl_api_nat44_ei_add_del_static_mapping_t_endian,
   .format_fn = vl_api_nat44_ei_add_del_static_mapping_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_add_del_static_mapping_t_tojson,
   .fromjson = vl_api_nat44_ei_add_del_static_mapping_t_fromjson,
   .calc_size = vl_api_nat44_ei_add_del_static_mapping_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_ADD_DEL_STATIC_MAPPING_REPLY + msg_id_base,
  .name = "nat44_ei_add_del_static_mapping_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_add_del_static_mapping_reply_t_endian,
  .format_fn = vl_api_nat44_ei_add_del_static_mapping_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_add_del_static_mapping_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_add_del_static_mapping_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_add_del_static_mapping_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_STATIC_MAPPING_DUMP + msg_id_base,
   .name = "nat44_ei_static_mapping_dump",
   .handler = vl_api_nat44_ei_static_mapping_dump_t_handler,
   .endian = vl_api_nat44_ei_static_mapping_dump_t_endian,
   .format_fn = vl_api_nat44_ei_static_mapping_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_static_mapping_dump_t_tojson,
   .fromjson = vl_api_nat44_ei_static_mapping_dump_t_fromjson,
   .calc_size = vl_api_nat44_ei_static_mapping_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_STATIC_MAPPING_DETAILS + msg_id_base,
  .name = "nat44_ei_static_mapping_details",
  .handler = 0,
  .endian = vl_api_nat44_ei_static_mapping_details_t_endian,
  .format_fn = vl_api_nat44_ei_static_mapping_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_static_mapping_details_t_tojson,
  .fromjson = vl_api_nat44_ei_static_mapping_details_t_fromjson,
  .calc_size = vl_api_nat44_ei_static_mapping_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_ADD_DEL_IDENTITY_MAPPING + msg_id_base,
   .name = "nat44_ei_add_del_identity_mapping",
   .handler = vl_api_nat44_ei_add_del_identity_mapping_t_handler,
   .endian = vl_api_nat44_ei_add_del_identity_mapping_t_endian,
   .format_fn = vl_api_nat44_ei_add_del_identity_mapping_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_add_del_identity_mapping_t_tojson,
   .fromjson = vl_api_nat44_ei_add_del_identity_mapping_t_fromjson,
   .calc_size = vl_api_nat44_ei_add_del_identity_mapping_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_ADD_DEL_IDENTITY_MAPPING_REPLY + msg_id_base,
  .name = "nat44_ei_add_del_identity_mapping_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_add_del_identity_mapping_reply_t_endian,
  .format_fn = vl_api_nat44_ei_add_del_identity_mapping_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_add_del_identity_mapping_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_add_del_identity_mapping_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_add_del_identity_mapping_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_IDENTITY_MAPPING_DUMP + msg_id_base,
   .name = "nat44_ei_identity_mapping_dump",
   .handler = vl_api_nat44_ei_identity_mapping_dump_t_handler,
   .endian = vl_api_nat44_ei_identity_mapping_dump_t_endian,
   .format_fn = vl_api_nat44_ei_identity_mapping_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_identity_mapping_dump_t_tojson,
   .fromjson = vl_api_nat44_ei_identity_mapping_dump_t_fromjson,
   .calc_size = vl_api_nat44_ei_identity_mapping_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_IDENTITY_MAPPING_DETAILS + msg_id_base,
  .name = "nat44_ei_identity_mapping_details",
  .handler = 0,
  .endian = vl_api_nat44_ei_identity_mapping_details_t_endian,
  .format_fn = vl_api_nat44_ei_identity_mapping_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_identity_mapping_details_t_tojson,
  .fromjson = vl_api_nat44_ei_identity_mapping_details_t_fromjson,
  .calc_size = vl_api_nat44_ei_identity_mapping_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_ADD_DEL_INTERFACE_ADDR + msg_id_base,
   .name = "nat44_ei_add_del_interface_addr",
   .handler = vl_api_nat44_ei_add_del_interface_addr_t_handler,
   .endian = vl_api_nat44_ei_add_del_interface_addr_t_endian,
   .format_fn = vl_api_nat44_ei_add_del_interface_addr_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_add_del_interface_addr_t_tojson,
   .fromjson = vl_api_nat44_ei_add_del_interface_addr_t_fromjson,
   .calc_size = vl_api_nat44_ei_add_del_interface_addr_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_ADD_DEL_INTERFACE_ADDR_REPLY + msg_id_base,
  .name = "nat44_ei_add_del_interface_addr_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_add_del_interface_addr_reply_t_endian,
  .format_fn = vl_api_nat44_ei_add_del_interface_addr_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_add_del_interface_addr_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_add_del_interface_addr_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_add_del_interface_addr_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_INTERFACE_ADDR_DUMP + msg_id_base,
   .name = "nat44_ei_interface_addr_dump",
   .handler = vl_api_nat44_ei_interface_addr_dump_t_handler,
   .endian = vl_api_nat44_ei_interface_addr_dump_t_endian,
   .format_fn = vl_api_nat44_ei_interface_addr_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_interface_addr_dump_t_tojson,
   .fromjson = vl_api_nat44_ei_interface_addr_dump_t_fromjson,
   .calc_size = vl_api_nat44_ei_interface_addr_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_INTERFACE_ADDR_DETAILS + msg_id_base,
  .name = "nat44_ei_interface_addr_details",
  .handler = 0,
  .endian = vl_api_nat44_ei_interface_addr_details_t_endian,
  .format_fn = vl_api_nat44_ei_interface_addr_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_interface_addr_details_t_tojson,
  .fromjson = vl_api_nat44_ei_interface_addr_details_t_fromjson,
  .calc_size = vl_api_nat44_ei_interface_addr_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_USER_DUMP + msg_id_base,
   .name = "nat44_ei_user_dump",
   .handler = vl_api_nat44_ei_user_dump_t_handler,
   .endian = vl_api_nat44_ei_user_dump_t_endian,
   .format_fn = vl_api_nat44_ei_user_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_user_dump_t_tojson,
   .fromjson = vl_api_nat44_ei_user_dump_t_fromjson,
   .calc_size = vl_api_nat44_ei_user_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_USER_DETAILS + msg_id_base,
  .name = "nat44_ei_user_details",
  .handler = 0,
  .endian = vl_api_nat44_ei_user_details_t_endian,
  .format_fn = vl_api_nat44_ei_user_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_user_details_t_tojson,
  .fromjson = vl_api_nat44_ei_user_details_t_fromjson,
  .calc_size = vl_api_nat44_ei_user_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_USER_SESSION_DUMP + msg_id_base,
   .name = "nat44_ei_user_session_dump",
   .handler = vl_api_nat44_ei_user_session_dump_t_handler,
   .endian = vl_api_nat44_ei_user_session_dump_t_endian,
   .format_fn = vl_api_nat44_ei_user_session_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_user_session_dump_t_tojson,
   .fromjson = vl_api_nat44_ei_user_session_dump_t_fromjson,
   .calc_size = vl_api_nat44_ei_user_session_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_USER_SESSION_DETAILS + msg_id_base,
  .name = "nat44_ei_user_session_details",
  .handler = 0,
  .endian = vl_api_nat44_ei_user_session_details_t_endian,
  .format_fn = vl_api_nat44_ei_user_session_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_user_session_details_t_tojson,
  .fromjson = vl_api_nat44_ei_user_session_details_t_fromjson,
  .calc_size = vl_api_nat44_ei_user_session_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_USER_SESSION_V2_DUMP + msg_id_base,
   .name = "nat44_ei_user_session_v2_dump",
   .handler = vl_api_nat44_ei_user_session_v2_dump_t_handler,
   .endian = vl_api_nat44_ei_user_session_v2_dump_t_endian,
   .format_fn = vl_api_nat44_ei_user_session_v2_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_user_session_v2_dump_t_tojson,
   .fromjson = vl_api_nat44_ei_user_session_v2_dump_t_fromjson,
   .calc_size = vl_api_nat44_ei_user_session_v2_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_USER_SESSION_V2_DETAILS + msg_id_base,
  .name = "nat44_ei_user_session_v2_details",
  .handler = 0,
  .endian = vl_api_nat44_ei_user_session_v2_details_t_endian,
  .format_fn = vl_api_nat44_ei_user_session_v2_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_user_session_v2_details_t_tojson,
  .fromjson = vl_api_nat44_ei_user_session_v2_details_t_fromjson,
  .calc_size = vl_api_nat44_ei_user_session_v2_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_DEL_SESSION + msg_id_base,
   .name = "nat44_ei_del_session",
   .handler = vl_api_nat44_ei_del_session_t_handler,
   .endian = vl_api_nat44_ei_del_session_t_endian,
   .format_fn = vl_api_nat44_ei_del_session_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_del_session_t_tojson,
   .fromjson = vl_api_nat44_ei_del_session_t_fromjson,
   .calc_size = vl_api_nat44_ei_del_session_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_DEL_SESSION_REPLY + msg_id_base,
  .name = "nat44_ei_del_session_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_del_session_reply_t_endian,
  .format_fn = vl_api_nat44_ei_del_session_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_del_session_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_del_session_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_del_session_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_FORWARDING_ENABLE_DISABLE + msg_id_base,
   .name = "nat44_ei_forwarding_enable_disable",
   .handler = vl_api_nat44_ei_forwarding_enable_disable_t_handler,
   .endian = vl_api_nat44_ei_forwarding_enable_disable_t_endian,
   .format_fn = vl_api_nat44_ei_forwarding_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_forwarding_enable_disable_t_tojson,
   .fromjson = vl_api_nat44_ei_forwarding_enable_disable_t_fromjson,
   .calc_size = vl_api_nat44_ei_forwarding_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_FORWARDING_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "nat44_ei_forwarding_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_forwarding_enable_disable_reply_t_endian,
  .format_fn = vl_api_nat44_ei_forwarding_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_forwarding_enable_disable_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_forwarding_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_forwarding_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_SET_FQ_OPTIONS + msg_id_base,
   .name = "nat44_ei_set_fq_options",
   .handler = vl_api_nat44_ei_set_fq_options_t_handler,
   .endian = vl_api_nat44_ei_set_fq_options_t_endian,
   .format_fn = vl_api_nat44_ei_set_fq_options_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_set_fq_options_t_tojson,
   .fromjson = vl_api_nat44_ei_set_fq_options_t_fromjson,
   .calc_size = vl_api_nat44_ei_set_fq_options_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_SET_FQ_OPTIONS_REPLY + msg_id_base,
  .name = "nat44_ei_set_fq_options_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_set_fq_options_reply_t_endian,
  .format_fn = vl_api_nat44_ei_set_fq_options_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_set_fq_options_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_set_fq_options_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_set_fq_options_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_EI_SHOW_FQ_OPTIONS + msg_id_base,
   .name = "nat44_ei_show_fq_options",
   .handler = vl_api_nat44_ei_show_fq_options_t_handler,
   .endian = vl_api_nat44_ei_show_fq_options_t_endian,
   .format_fn = vl_api_nat44_ei_show_fq_options_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ei_show_fq_options_t_tojson,
   .fromjson = vl_api_nat44_ei_show_fq_options_t_fromjson,
   .calc_size = vl_api_nat44_ei_show_fq_options_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_EI_SHOW_FQ_OPTIONS_REPLY + msg_id_base,
  .name = "nat44_ei_show_fq_options_reply",
  .handler = 0,
  .endian = vl_api_nat44_ei_show_fq_options_reply_t_endian,
  .format_fn = vl_api_nat44_ei_show_fq_options_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ei_show_fq_options_reply_t_tojson,
  .fromjson = vl_api_nat44_ei_show_fq_options_reply_t_fromjson,
  .calc_size = vl_api_nat44_ei_show_fq_options_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
