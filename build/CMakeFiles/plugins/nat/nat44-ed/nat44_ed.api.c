#define vl_endianfun		/* define message structures */
#include "nat44_ed.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "nat44_ed.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "nat44_ed.api.h"
#undef vl_printfun

#include "nat44_ed.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("nat44_ed_8c7fcb7f", VL_MSG_NAT44_ED_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_nat44_ed);
   vl_msg_api_add_msg_name_crc (am, "nat44_ed_plugin_enable_disable_be17f8dd",
                                VL_API_NAT44_ED_PLUGIN_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ed_plugin_enable_disable_reply_e8d4e804",
                                VL_API_NAT44_ED_PLUGIN_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_forwarding_enable_disable_b3e225d2",
                                VL_API_NAT44_FORWARDING_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_forwarding_enable_disable_reply_e8d4e804",
                                VL_API_NAT44_FORWARDING_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_ipfix_enable_disable_9af4a2d2",
                                VL_API_NAT_IPFIX_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_ipfix_enable_disable_reply_e8d4e804",
                                VL_API_NAT_IPFIX_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_set_timeouts_d4746b16",
                                VL_API_NAT_SET_TIMEOUTS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_set_timeouts_reply_e8d4e804",
                                VL_API_NAT_SET_TIMEOUTS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_set_session_limit_8899bbb1",
                                VL_API_NAT44_SET_SESSION_LIMIT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_set_session_limit_reply_e8d4e804",
                                VL_API_NAT44_SET_SESSION_LIMIT_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_show_running_config_51077d14",
                                VL_API_NAT44_SHOW_RUNNING_CONFIG + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_show_running_config_reply_93d8e267",
                                VL_API_NAT44_SHOW_RUNNING_CONFIG_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_set_workers_da926638",
                                VL_API_NAT_SET_WORKERS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_set_workers_reply_e8d4e804",
                                VL_API_NAT_SET_WORKERS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_worker_dump_51077d14",
                                VL_API_NAT_WORKER_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_worker_details_84bf06fc",
                                VL_API_NAT_WORKER_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ed_add_del_vrf_table_08330904",
                                VL_API_NAT44_ED_ADD_DEL_VRF_TABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ed_add_del_vrf_table_reply_e8d4e804",
                                VL_API_NAT44_ED_ADD_DEL_VRF_TABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ed_add_del_vrf_route_59187407",
                                VL_API_NAT44_ED_ADD_DEL_VRF_ROUTE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ed_add_del_vrf_route_reply_e8d4e804",
                                VL_API_NAT44_ED_ADD_DEL_VRF_ROUTE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ed_vrf_tables_dump_51077d14",
                                VL_API_NAT44_ED_VRF_TABLES_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ed_vrf_tables_details_7b264e4f",
                                VL_API_NAT44_ED_VRF_TABLES_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ed_vrf_tables_v2_dump_51077d14",
                                VL_API_NAT44_ED_VRF_TABLES_V2_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ed_vrf_tables_v2_details_7b264e4f",
                                VL_API_NAT44_ED_VRF_TABLES_V2_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_set_mss_clamping_25e90abb",
                                VL_API_NAT_SET_MSS_CLAMPING + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_set_mss_clamping_reply_e8d4e804",
                                VL_API_NAT_SET_MSS_CLAMPING_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_get_mss_clamping_51077d14",
                                VL_API_NAT_GET_MSS_CLAMPING + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_get_mss_clamping_reply_1c0b2a78",
                                VL_API_NAT_GET_MSS_CLAMPING_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ed_set_fq_options_2399bd71",
                                VL_API_NAT44_ED_SET_FQ_OPTIONS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ed_set_fq_options_reply_e8d4e804",
                                VL_API_NAT44_ED_SET_FQ_OPTIONS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ed_show_fq_options_51077d14",
                                VL_API_NAT44_ED_SHOW_FQ_OPTIONS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ed_show_fq_options_reply_7213b545",
                                VL_API_NAT44_ED_SHOW_FQ_OPTIONS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_add_del_interface_addr_4aed50c0",
                                VL_API_NAT44_ADD_DEL_INTERFACE_ADDR + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_add_del_interface_addr_reply_e8d4e804",
                                VL_API_NAT44_ADD_DEL_INTERFACE_ADDR_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_interface_addr_dump_51077d14",
                                VL_API_NAT44_INTERFACE_ADDR_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_interface_addr_details_e4aca9ca",
                                VL_API_NAT44_INTERFACE_ADDR_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_add_del_address_range_6f2b8055",
                                VL_API_NAT44_ADD_DEL_ADDRESS_RANGE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_add_del_address_range_reply_e8d4e804",
                                VL_API_NAT44_ADD_DEL_ADDRESS_RANGE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_address_dump_51077d14",
                                VL_API_NAT44_ADDRESS_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_address_details_0d1beac1",
                                VL_API_NAT44_ADDRESS_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_interface_add_del_feature_f3699b83",
                                VL_API_NAT44_INTERFACE_ADD_DEL_FEATURE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_interface_add_del_feature_reply_e8d4e804",
                                VL_API_NAT44_INTERFACE_ADD_DEL_FEATURE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_interface_dump_51077d14",
                                VL_API_NAT44_INTERFACE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_interface_details_5d286289",
                                VL_API_NAT44_INTERFACE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ed_add_del_output_interface_47d6e753",
                                VL_API_NAT44_ED_ADD_DEL_OUTPUT_INTERFACE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ed_add_del_output_interface_reply_e8d4e804",
                                VL_API_NAT44_ED_ADD_DEL_OUTPUT_INTERFACE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ed_output_interface_get_f75ba505",
                                VL_API_NAT44_ED_OUTPUT_INTERFACE_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ed_output_interface_get_reply_53b48f5d",
                                VL_API_NAT44_ED_OUTPUT_INTERFACE_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_ed_output_interface_details_0b45011c",
                                VL_API_NAT44_ED_OUTPUT_INTERFACE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_add_del_static_mapping_5ae5f03e",
                                VL_API_NAT44_ADD_DEL_STATIC_MAPPING + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_add_del_static_mapping_reply_e8d4e804",
                                VL_API_NAT44_ADD_DEL_STATIC_MAPPING_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_add_del_static_mapping_v2_5e205f1a",
                                VL_API_NAT44_ADD_DEL_STATIC_MAPPING_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_add_del_static_mapping_v2_reply_e8d4e804",
                                VL_API_NAT44_ADD_DEL_STATIC_MAPPING_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_static_mapping_dump_51077d14",
                                VL_API_NAT44_STATIC_MAPPING_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_static_mapping_details_06cb40b2",
                                VL_API_NAT44_STATIC_MAPPING_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_add_del_identity_mapping_02faaa22",
                                VL_API_NAT44_ADD_DEL_IDENTITY_MAPPING + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_add_del_identity_mapping_reply_e8d4e804",
                                VL_API_NAT44_ADD_DEL_IDENTITY_MAPPING_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_identity_mapping_dump_51077d14",
                                VL_API_NAT44_IDENTITY_MAPPING_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_identity_mapping_details_2a52a030",
                                VL_API_NAT44_IDENTITY_MAPPING_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_add_del_lb_static_mapping_4f68ee9d",
                                VL_API_NAT44_ADD_DEL_LB_STATIC_MAPPING + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_add_del_lb_static_mapping_reply_e8d4e804",
                                VL_API_NAT44_ADD_DEL_LB_STATIC_MAPPING_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_lb_static_mapping_add_del_local_7ca47547",
                                VL_API_NAT44_LB_STATIC_MAPPING_ADD_DEL_LOCAL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_lb_static_mapping_add_del_local_reply_e8d4e804",
                                VL_API_NAT44_LB_STATIC_MAPPING_ADD_DEL_LOCAL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_lb_static_mapping_dump_51077d14",
                                VL_API_NAT44_LB_STATIC_MAPPING_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_lb_static_mapping_details_ed5ce876",
                                VL_API_NAT44_LB_STATIC_MAPPING_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_del_session_15a5bf8c",
                                VL_API_NAT44_DEL_SESSION + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_del_session_reply_e8d4e804",
                                VL_API_NAT44_DEL_SESSION_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_user_dump_51077d14",
                                VL_API_NAT44_USER_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_user_details_355896c2",
                                VL_API_NAT44_USER_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_user_session_dump_e1899c98",
                                VL_API_NAT44_USER_SESSION_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_user_session_details_2cf6e16d",
                                VL_API_NAT44_USER_SESSION_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_user_session_v2_dump_e1899c98",
                                VL_API_NAT44_USER_SESSION_V2_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_user_session_v2_details_fd42b729",
                                VL_API_NAT44_USER_SESSION_V2_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_user_session_v3_details_edae926e",
                                VL_API_NAT44_USER_SESSION_V3_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat44_user_session_v3_dump_e1899c98",
                                VL_API_NAT44_USER_SESSION_V3_DUMP + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_ED_OUTPUT_INTERFACE_GET + msg_id_base,
   .name = "nat44_ed_output_interface_get",
   .handler = vl_api_nat44_ed_output_interface_get_t_handler,
   .endian = vl_api_nat44_ed_output_interface_get_t_endian,
   .format_fn = vl_api_nat44_ed_output_interface_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ed_output_interface_get_t_tojson,
   .fromjson = vl_api_nat44_ed_output_interface_get_t_fromjson,
   .calc_size = vl_api_nat44_ed_output_interface_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_ED_OUTPUT_INTERFACE_GET_REPLY + msg_id_base,
  .name = "nat44_ed_output_interface_get_reply",
  .handler = 0,
  .endian = vl_api_nat44_ed_output_interface_get_reply_t_endian,
  .format_fn = vl_api_nat44_ed_output_interface_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ed_output_interface_get_reply_t_tojson,
  .fromjson = vl_api_nat44_ed_output_interface_get_reply_t_fromjson,
  .calc_size = vl_api_nat44_ed_output_interface_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_ED_OUTPUT_INTERFACE_DETAILS + msg_id_base,
  .name = "nat44_ed_output_interface_details",
  .handler = 0,
  .endian = vl_api_nat44_ed_output_interface_details_t_endian,
  .format_fn = vl_api_nat44_ed_output_interface_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ed_output_interface_details_t_tojson,
  .fromjson = vl_api_nat44_ed_output_interface_details_t_fromjson,
  .calc_size = vl_api_nat44_ed_output_interface_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_ED_PLUGIN_ENABLE_DISABLE + msg_id_base,
   .name = "nat44_ed_plugin_enable_disable",
   .handler = vl_api_nat44_ed_plugin_enable_disable_t_handler,
   .endian = vl_api_nat44_ed_plugin_enable_disable_t_endian,
   .format_fn = vl_api_nat44_ed_plugin_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ed_plugin_enable_disable_t_tojson,
   .fromjson = vl_api_nat44_ed_plugin_enable_disable_t_fromjson,
   .calc_size = vl_api_nat44_ed_plugin_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_ED_PLUGIN_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "nat44_ed_plugin_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_nat44_ed_plugin_enable_disable_reply_t_endian,
  .format_fn = vl_api_nat44_ed_plugin_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ed_plugin_enable_disable_reply_t_tojson,
  .fromjson = vl_api_nat44_ed_plugin_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_nat44_ed_plugin_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_FORWARDING_ENABLE_DISABLE + msg_id_base,
   .name = "nat44_forwarding_enable_disable",
   .handler = vl_api_nat44_forwarding_enable_disable_t_handler,
   .endian = vl_api_nat44_forwarding_enable_disable_t_endian,
   .format_fn = vl_api_nat44_forwarding_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_forwarding_enable_disable_t_tojson,
   .fromjson = vl_api_nat44_forwarding_enable_disable_t_fromjson,
   .calc_size = vl_api_nat44_forwarding_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_FORWARDING_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "nat44_forwarding_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_nat44_forwarding_enable_disable_reply_t_endian,
  .format_fn = vl_api_nat44_forwarding_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_forwarding_enable_disable_reply_t_tojson,
  .fromjson = vl_api_nat44_forwarding_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_nat44_forwarding_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT_IPFIX_ENABLE_DISABLE + msg_id_base,
   .name = "nat_ipfix_enable_disable",
   .handler = vl_api_nat_ipfix_enable_disable_t_handler,
   .endian = vl_api_nat_ipfix_enable_disable_t_endian,
   .format_fn = vl_api_nat_ipfix_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat_ipfix_enable_disable_t_tojson,
   .fromjson = vl_api_nat_ipfix_enable_disable_t_fromjson,
   .calc_size = vl_api_nat_ipfix_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT_IPFIX_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "nat_ipfix_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_nat_ipfix_enable_disable_reply_t_endian,
  .format_fn = vl_api_nat_ipfix_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat_ipfix_enable_disable_reply_t_tojson,
  .fromjson = vl_api_nat_ipfix_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_nat_ipfix_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT_SET_TIMEOUTS + msg_id_base,
   .name = "nat_set_timeouts",
   .handler = vl_api_nat_set_timeouts_t_handler,
   .endian = vl_api_nat_set_timeouts_t_endian,
   .format_fn = vl_api_nat_set_timeouts_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat_set_timeouts_t_tojson,
   .fromjson = vl_api_nat_set_timeouts_t_fromjson,
   .calc_size = vl_api_nat_set_timeouts_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT_SET_TIMEOUTS_REPLY + msg_id_base,
  .name = "nat_set_timeouts_reply",
  .handler = 0,
  .endian = vl_api_nat_set_timeouts_reply_t_endian,
  .format_fn = vl_api_nat_set_timeouts_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat_set_timeouts_reply_t_tojson,
  .fromjson = vl_api_nat_set_timeouts_reply_t_fromjson,
  .calc_size = vl_api_nat_set_timeouts_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_SET_SESSION_LIMIT + msg_id_base,
   .name = "nat44_set_session_limit",
   .handler = vl_api_nat44_set_session_limit_t_handler,
   .endian = vl_api_nat44_set_session_limit_t_endian,
   .format_fn = vl_api_nat44_set_session_limit_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_set_session_limit_t_tojson,
   .fromjson = vl_api_nat44_set_session_limit_t_fromjson,
   .calc_size = vl_api_nat44_set_session_limit_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_SET_SESSION_LIMIT_REPLY + msg_id_base,
  .name = "nat44_set_session_limit_reply",
  .handler = 0,
  .endian = vl_api_nat44_set_session_limit_reply_t_endian,
  .format_fn = vl_api_nat44_set_session_limit_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_set_session_limit_reply_t_tojson,
  .fromjson = vl_api_nat44_set_session_limit_reply_t_fromjson,
  .calc_size = vl_api_nat44_set_session_limit_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_SHOW_RUNNING_CONFIG + msg_id_base,
   .name = "nat44_show_running_config",
   .handler = vl_api_nat44_show_running_config_t_handler,
   .endian = vl_api_nat44_show_running_config_t_endian,
   .format_fn = vl_api_nat44_show_running_config_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_show_running_config_t_tojson,
   .fromjson = vl_api_nat44_show_running_config_t_fromjson,
   .calc_size = vl_api_nat44_show_running_config_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_SHOW_RUNNING_CONFIG_REPLY + msg_id_base,
  .name = "nat44_show_running_config_reply",
  .handler = 0,
  .endian = vl_api_nat44_show_running_config_reply_t_endian,
  .format_fn = vl_api_nat44_show_running_config_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_show_running_config_reply_t_tojson,
  .fromjson = vl_api_nat44_show_running_config_reply_t_fromjson,
  .calc_size = vl_api_nat44_show_running_config_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT_SET_WORKERS + msg_id_base,
   .name = "nat_set_workers",
   .handler = vl_api_nat_set_workers_t_handler,
   .endian = vl_api_nat_set_workers_t_endian,
   .format_fn = vl_api_nat_set_workers_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat_set_workers_t_tojson,
   .fromjson = vl_api_nat_set_workers_t_fromjson,
   .calc_size = vl_api_nat_set_workers_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT_SET_WORKERS_REPLY + msg_id_base,
  .name = "nat_set_workers_reply",
  .handler = 0,
  .endian = vl_api_nat_set_workers_reply_t_endian,
  .format_fn = vl_api_nat_set_workers_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat_set_workers_reply_t_tojson,
  .fromjson = vl_api_nat_set_workers_reply_t_fromjson,
  .calc_size = vl_api_nat_set_workers_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT_WORKER_DUMP + msg_id_base,
   .name = "nat_worker_dump",
   .handler = vl_api_nat_worker_dump_t_handler,
   .endian = vl_api_nat_worker_dump_t_endian,
   .format_fn = vl_api_nat_worker_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat_worker_dump_t_tojson,
   .fromjson = vl_api_nat_worker_dump_t_fromjson,
   .calc_size = vl_api_nat_worker_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT_WORKER_DETAILS + msg_id_base,
  .name = "nat_worker_details",
  .handler = 0,
  .endian = vl_api_nat_worker_details_t_endian,
  .format_fn = vl_api_nat_worker_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat_worker_details_t_tojson,
  .fromjson = vl_api_nat_worker_details_t_fromjson,
  .calc_size = vl_api_nat_worker_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_ED_ADD_DEL_VRF_TABLE + msg_id_base,
   .name = "nat44_ed_add_del_vrf_table",
   .handler = vl_api_nat44_ed_add_del_vrf_table_t_handler,
   .endian = vl_api_nat44_ed_add_del_vrf_table_t_endian,
   .format_fn = vl_api_nat44_ed_add_del_vrf_table_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ed_add_del_vrf_table_t_tojson,
   .fromjson = vl_api_nat44_ed_add_del_vrf_table_t_fromjson,
   .calc_size = vl_api_nat44_ed_add_del_vrf_table_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_ED_ADD_DEL_VRF_TABLE_REPLY + msg_id_base,
  .name = "nat44_ed_add_del_vrf_table_reply",
  .handler = 0,
  .endian = vl_api_nat44_ed_add_del_vrf_table_reply_t_endian,
  .format_fn = vl_api_nat44_ed_add_del_vrf_table_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ed_add_del_vrf_table_reply_t_tojson,
  .fromjson = vl_api_nat44_ed_add_del_vrf_table_reply_t_fromjson,
  .calc_size = vl_api_nat44_ed_add_del_vrf_table_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_ED_ADD_DEL_VRF_ROUTE + msg_id_base,
   .name = "nat44_ed_add_del_vrf_route",
   .handler = vl_api_nat44_ed_add_del_vrf_route_t_handler,
   .endian = vl_api_nat44_ed_add_del_vrf_route_t_endian,
   .format_fn = vl_api_nat44_ed_add_del_vrf_route_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ed_add_del_vrf_route_t_tojson,
   .fromjson = vl_api_nat44_ed_add_del_vrf_route_t_fromjson,
   .calc_size = vl_api_nat44_ed_add_del_vrf_route_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_ED_ADD_DEL_VRF_ROUTE_REPLY + msg_id_base,
  .name = "nat44_ed_add_del_vrf_route_reply",
  .handler = 0,
  .endian = vl_api_nat44_ed_add_del_vrf_route_reply_t_endian,
  .format_fn = vl_api_nat44_ed_add_del_vrf_route_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ed_add_del_vrf_route_reply_t_tojson,
  .fromjson = vl_api_nat44_ed_add_del_vrf_route_reply_t_fromjson,
  .calc_size = vl_api_nat44_ed_add_del_vrf_route_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_ED_VRF_TABLES_DUMP + msg_id_base,
   .name = "nat44_ed_vrf_tables_dump",
   .handler = vl_api_nat44_ed_vrf_tables_dump_t_handler,
   .endian = vl_api_nat44_ed_vrf_tables_dump_t_endian,
   .format_fn = vl_api_nat44_ed_vrf_tables_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ed_vrf_tables_dump_t_tojson,
   .fromjson = vl_api_nat44_ed_vrf_tables_dump_t_fromjson,
   .calc_size = vl_api_nat44_ed_vrf_tables_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_ED_VRF_TABLES_DETAILS + msg_id_base,
  .name = "nat44_ed_vrf_tables_details",
  .handler = 0,
  .endian = vl_api_nat44_ed_vrf_tables_details_t_endian,
  .format_fn = vl_api_nat44_ed_vrf_tables_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ed_vrf_tables_details_t_tojson,
  .fromjson = vl_api_nat44_ed_vrf_tables_details_t_fromjson,
  .calc_size = vl_api_nat44_ed_vrf_tables_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_ED_VRF_TABLES_V2_DUMP + msg_id_base,
   .name = "nat44_ed_vrf_tables_v2_dump",
   .handler = vl_api_nat44_ed_vrf_tables_v2_dump_t_handler,
   .endian = vl_api_nat44_ed_vrf_tables_v2_dump_t_endian,
   .format_fn = vl_api_nat44_ed_vrf_tables_v2_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ed_vrf_tables_v2_dump_t_tojson,
   .fromjson = vl_api_nat44_ed_vrf_tables_v2_dump_t_fromjson,
   .calc_size = vl_api_nat44_ed_vrf_tables_v2_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_ED_VRF_TABLES_V2_DETAILS + msg_id_base,
  .name = "nat44_ed_vrf_tables_v2_details",
  .handler = 0,
  .endian = vl_api_nat44_ed_vrf_tables_v2_details_t_endian,
  .format_fn = vl_api_nat44_ed_vrf_tables_v2_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ed_vrf_tables_v2_details_t_tojson,
  .fromjson = vl_api_nat44_ed_vrf_tables_v2_details_t_fromjson,
  .calc_size = vl_api_nat44_ed_vrf_tables_v2_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT_SET_MSS_CLAMPING + msg_id_base,
   .name = "nat_set_mss_clamping",
   .handler = vl_api_nat_set_mss_clamping_t_handler,
   .endian = vl_api_nat_set_mss_clamping_t_endian,
   .format_fn = vl_api_nat_set_mss_clamping_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat_set_mss_clamping_t_tojson,
   .fromjson = vl_api_nat_set_mss_clamping_t_fromjson,
   .calc_size = vl_api_nat_set_mss_clamping_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT_SET_MSS_CLAMPING_REPLY + msg_id_base,
  .name = "nat_set_mss_clamping_reply",
  .handler = 0,
  .endian = vl_api_nat_set_mss_clamping_reply_t_endian,
  .format_fn = vl_api_nat_set_mss_clamping_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat_set_mss_clamping_reply_t_tojson,
  .fromjson = vl_api_nat_set_mss_clamping_reply_t_fromjson,
  .calc_size = vl_api_nat_set_mss_clamping_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT_GET_MSS_CLAMPING + msg_id_base,
   .name = "nat_get_mss_clamping",
   .handler = vl_api_nat_get_mss_clamping_t_handler,
   .endian = vl_api_nat_get_mss_clamping_t_endian,
   .format_fn = vl_api_nat_get_mss_clamping_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat_get_mss_clamping_t_tojson,
   .fromjson = vl_api_nat_get_mss_clamping_t_fromjson,
   .calc_size = vl_api_nat_get_mss_clamping_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT_GET_MSS_CLAMPING_REPLY + msg_id_base,
  .name = "nat_get_mss_clamping_reply",
  .handler = 0,
  .endian = vl_api_nat_get_mss_clamping_reply_t_endian,
  .format_fn = vl_api_nat_get_mss_clamping_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat_get_mss_clamping_reply_t_tojson,
  .fromjson = vl_api_nat_get_mss_clamping_reply_t_fromjson,
  .calc_size = vl_api_nat_get_mss_clamping_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_ED_SET_FQ_OPTIONS + msg_id_base,
   .name = "nat44_ed_set_fq_options",
   .handler = vl_api_nat44_ed_set_fq_options_t_handler,
   .endian = vl_api_nat44_ed_set_fq_options_t_endian,
   .format_fn = vl_api_nat44_ed_set_fq_options_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ed_set_fq_options_t_tojson,
   .fromjson = vl_api_nat44_ed_set_fq_options_t_fromjson,
   .calc_size = vl_api_nat44_ed_set_fq_options_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_ED_SET_FQ_OPTIONS_REPLY + msg_id_base,
  .name = "nat44_ed_set_fq_options_reply",
  .handler = 0,
  .endian = vl_api_nat44_ed_set_fq_options_reply_t_endian,
  .format_fn = vl_api_nat44_ed_set_fq_options_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ed_set_fq_options_reply_t_tojson,
  .fromjson = vl_api_nat44_ed_set_fq_options_reply_t_fromjson,
  .calc_size = vl_api_nat44_ed_set_fq_options_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_ED_SHOW_FQ_OPTIONS + msg_id_base,
   .name = "nat44_ed_show_fq_options",
   .handler = vl_api_nat44_ed_show_fq_options_t_handler,
   .endian = vl_api_nat44_ed_show_fq_options_t_endian,
   .format_fn = vl_api_nat44_ed_show_fq_options_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ed_show_fq_options_t_tojson,
   .fromjson = vl_api_nat44_ed_show_fq_options_t_fromjson,
   .calc_size = vl_api_nat44_ed_show_fq_options_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_ED_SHOW_FQ_OPTIONS_REPLY + msg_id_base,
  .name = "nat44_ed_show_fq_options_reply",
  .handler = 0,
  .endian = vl_api_nat44_ed_show_fq_options_reply_t_endian,
  .format_fn = vl_api_nat44_ed_show_fq_options_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ed_show_fq_options_reply_t_tojson,
  .fromjson = vl_api_nat44_ed_show_fq_options_reply_t_fromjson,
  .calc_size = vl_api_nat44_ed_show_fq_options_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_ADD_DEL_INTERFACE_ADDR + msg_id_base,
   .name = "nat44_add_del_interface_addr",
   .handler = vl_api_nat44_add_del_interface_addr_t_handler,
   .endian = vl_api_nat44_add_del_interface_addr_t_endian,
   .format_fn = vl_api_nat44_add_del_interface_addr_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_add_del_interface_addr_t_tojson,
   .fromjson = vl_api_nat44_add_del_interface_addr_t_fromjson,
   .calc_size = vl_api_nat44_add_del_interface_addr_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_ADD_DEL_INTERFACE_ADDR_REPLY + msg_id_base,
  .name = "nat44_add_del_interface_addr_reply",
  .handler = 0,
  .endian = vl_api_nat44_add_del_interface_addr_reply_t_endian,
  .format_fn = vl_api_nat44_add_del_interface_addr_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_add_del_interface_addr_reply_t_tojson,
  .fromjson = vl_api_nat44_add_del_interface_addr_reply_t_fromjson,
  .calc_size = vl_api_nat44_add_del_interface_addr_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_INTERFACE_ADDR_DUMP + msg_id_base,
   .name = "nat44_interface_addr_dump",
   .handler = vl_api_nat44_interface_addr_dump_t_handler,
   .endian = vl_api_nat44_interface_addr_dump_t_endian,
   .format_fn = vl_api_nat44_interface_addr_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_interface_addr_dump_t_tojson,
   .fromjson = vl_api_nat44_interface_addr_dump_t_fromjson,
   .calc_size = vl_api_nat44_interface_addr_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_INTERFACE_ADDR_DETAILS + msg_id_base,
  .name = "nat44_interface_addr_details",
  .handler = 0,
  .endian = vl_api_nat44_interface_addr_details_t_endian,
  .format_fn = vl_api_nat44_interface_addr_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_interface_addr_details_t_tojson,
  .fromjson = vl_api_nat44_interface_addr_details_t_fromjson,
  .calc_size = vl_api_nat44_interface_addr_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_ADD_DEL_ADDRESS_RANGE + msg_id_base,
   .name = "nat44_add_del_address_range",
   .handler = vl_api_nat44_add_del_address_range_t_handler,
   .endian = vl_api_nat44_add_del_address_range_t_endian,
   .format_fn = vl_api_nat44_add_del_address_range_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_add_del_address_range_t_tojson,
   .fromjson = vl_api_nat44_add_del_address_range_t_fromjson,
   .calc_size = vl_api_nat44_add_del_address_range_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_ADD_DEL_ADDRESS_RANGE_REPLY + msg_id_base,
  .name = "nat44_add_del_address_range_reply",
  .handler = 0,
  .endian = vl_api_nat44_add_del_address_range_reply_t_endian,
  .format_fn = vl_api_nat44_add_del_address_range_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_add_del_address_range_reply_t_tojson,
  .fromjson = vl_api_nat44_add_del_address_range_reply_t_fromjson,
  .calc_size = vl_api_nat44_add_del_address_range_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_ADDRESS_DUMP + msg_id_base,
   .name = "nat44_address_dump",
   .handler = vl_api_nat44_address_dump_t_handler,
   .endian = vl_api_nat44_address_dump_t_endian,
   .format_fn = vl_api_nat44_address_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_address_dump_t_tojson,
   .fromjson = vl_api_nat44_address_dump_t_fromjson,
   .calc_size = vl_api_nat44_address_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_ADDRESS_DETAILS + msg_id_base,
  .name = "nat44_address_details",
  .handler = 0,
  .endian = vl_api_nat44_address_details_t_endian,
  .format_fn = vl_api_nat44_address_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_address_details_t_tojson,
  .fromjson = vl_api_nat44_address_details_t_fromjson,
  .calc_size = vl_api_nat44_address_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_INTERFACE_ADD_DEL_FEATURE + msg_id_base,
   .name = "nat44_interface_add_del_feature",
   .handler = vl_api_nat44_interface_add_del_feature_t_handler,
   .endian = vl_api_nat44_interface_add_del_feature_t_endian,
   .format_fn = vl_api_nat44_interface_add_del_feature_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_interface_add_del_feature_t_tojson,
   .fromjson = vl_api_nat44_interface_add_del_feature_t_fromjson,
   .calc_size = vl_api_nat44_interface_add_del_feature_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_INTERFACE_ADD_DEL_FEATURE_REPLY + msg_id_base,
  .name = "nat44_interface_add_del_feature_reply",
  .handler = 0,
  .endian = vl_api_nat44_interface_add_del_feature_reply_t_endian,
  .format_fn = vl_api_nat44_interface_add_del_feature_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_interface_add_del_feature_reply_t_tojson,
  .fromjson = vl_api_nat44_interface_add_del_feature_reply_t_fromjson,
  .calc_size = vl_api_nat44_interface_add_del_feature_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_INTERFACE_DUMP + msg_id_base,
   .name = "nat44_interface_dump",
   .handler = vl_api_nat44_interface_dump_t_handler,
   .endian = vl_api_nat44_interface_dump_t_endian,
   .format_fn = vl_api_nat44_interface_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_interface_dump_t_tojson,
   .fromjson = vl_api_nat44_interface_dump_t_fromjson,
   .calc_size = vl_api_nat44_interface_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_INTERFACE_DETAILS + msg_id_base,
  .name = "nat44_interface_details",
  .handler = 0,
  .endian = vl_api_nat44_interface_details_t_endian,
  .format_fn = vl_api_nat44_interface_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_interface_details_t_tojson,
  .fromjson = vl_api_nat44_interface_details_t_fromjson,
  .calc_size = vl_api_nat44_interface_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_ED_ADD_DEL_OUTPUT_INTERFACE + msg_id_base,
   .name = "nat44_ed_add_del_output_interface",
   .handler = vl_api_nat44_ed_add_del_output_interface_t_handler,
   .endian = vl_api_nat44_ed_add_del_output_interface_t_endian,
   .format_fn = vl_api_nat44_ed_add_del_output_interface_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_ed_add_del_output_interface_t_tojson,
   .fromjson = vl_api_nat44_ed_add_del_output_interface_t_fromjson,
   .calc_size = vl_api_nat44_ed_add_del_output_interface_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_ED_ADD_DEL_OUTPUT_INTERFACE_REPLY + msg_id_base,
  .name = "nat44_ed_add_del_output_interface_reply",
  .handler = 0,
  .endian = vl_api_nat44_ed_add_del_output_interface_reply_t_endian,
  .format_fn = vl_api_nat44_ed_add_del_output_interface_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_ed_add_del_output_interface_reply_t_tojson,
  .fromjson = vl_api_nat44_ed_add_del_output_interface_reply_t_fromjson,
  .calc_size = vl_api_nat44_ed_add_del_output_interface_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_ADD_DEL_STATIC_MAPPING + msg_id_base,
   .name = "nat44_add_del_static_mapping",
   .handler = vl_api_nat44_add_del_static_mapping_t_handler,
   .endian = vl_api_nat44_add_del_static_mapping_t_endian,
   .format_fn = vl_api_nat44_add_del_static_mapping_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_add_del_static_mapping_t_tojson,
   .fromjson = vl_api_nat44_add_del_static_mapping_t_fromjson,
   .calc_size = vl_api_nat44_add_del_static_mapping_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_ADD_DEL_STATIC_MAPPING_REPLY + msg_id_base,
  .name = "nat44_add_del_static_mapping_reply",
  .handler = 0,
  .endian = vl_api_nat44_add_del_static_mapping_reply_t_endian,
  .format_fn = vl_api_nat44_add_del_static_mapping_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_add_del_static_mapping_reply_t_tojson,
  .fromjson = vl_api_nat44_add_del_static_mapping_reply_t_fromjson,
  .calc_size = vl_api_nat44_add_del_static_mapping_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_ADD_DEL_STATIC_MAPPING_V2 + msg_id_base,
   .name = "nat44_add_del_static_mapping_v2",
   .handler = vl_api_nat44_add_del_static_mapping_v2_t_handler,
   .endian = vl_api_nat44_add_del_static_mapping_v2_t_endian,
   .format_fn = vl_api_nat44_add_del_static_mapping_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_add_del_static_mapping_v2_t_tojson,
   .fromjson = vl_api_nat44_add_del_static_mapping_v2_t_fromjson,
   .calc_size = vl_api_nat44_add_del_static_mapping_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_ADD_DEL_STATIC_MAPPING_V2_REPLY + msg_id_base,
  .name = "nat44_add_del_static_mapping_v2_reply",
  .handler = 0,
  .endian = vl_api_nat44_add_del_static_mapping_v2_reply_t_endian,
  .format_fn = vl_api_nat44_add_del_static_mapping_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_add_del_static_mapping_v2_reply_t_tojson,
  .fromjson = vl_api_nat44_add_del_static_mapping_v2_reply_t_fromjson,
  .calc_size = vl_api_nat44_add_del_static_mapping_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_STATIC_MAPPING_DUMP + msg_id_base,
   .name = "nat44_static_mapping_dump",
   .handler = vl_api_nat44_static_mapping_dump_t_handler,
   .endian = vl_api_nat44_static_mapping_dump_t_endian,
   .format_fn = vl_api_nat44_static_mapping_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_static_mapping_dump_t_tojson,
   .fromjson = vl_api_nat44_static_mapping_dump_t_fromjson,
   .calc_size = vl_api_nat44_static_mapping_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_STATIC_MAPPING_DETAILS + msg_id_base,
  .name = "nat44_static_mapping_details",
  .handler = 0,
  .endian = vl_api_nat44_static_mapping_details_t_endian,
  .format_fn = vl_api_nat44_static_mapping_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_static_mapping_details_t_tojson,
  .fromjson = vl_api_nat44_static_mapping_details_t_fromjson,
  .calc_size = vl_api_nat44_static_mapping_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_ADD_DEL_IDENTITY_MAPPING + msg_id_base,
   .name = "nat44_add_del_identity_mapping",
   .handler = vl_api_nat44_add_del_identity_mapping_t_handler,
   .endian = vl_api_nat44_add_del_identity_mapping_t_endian,
   .format_fn = vl_api_nat44_add_del_identity_mapping_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_add_del_identity_mapping_t_tojson,
   .fromjson = vl_api_nat44_add_del_identity_mapping_t_fromjson,
   .calc_size = vl_api_nat44_add_del_identity_mapping_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_ADD_DEL_IDENTITY_MAPPING_REPLY + msg_id_base,
  .name = "nat44_add_del_identity_mapping_reply",
  .handler = 0,
  .endian = vl_api_nat44_add_del_identity_mapping_reply_t_endian,
  .format_fn = vl_api_nat44_add_del_identity_mapping_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_add_del_identity_mapping_reply_t_tojson,
  .fromjson = vl_api_nat44_add_del_identity_mapping_reply_t_fromjson,
  .calc_size = vl_api_nat44_add_del_identity_mapping_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_IDENTITY_MAPPING_DUMP + msg_id_base,
   .name = "nat44_identity_mapping_dump",
   .handler = vl_api_nat44_identity_mapping_dump_t_handler,
   .endian = vl_api_nat44_identity_mapping_dump_t_endian,
   .format_fn = vl_api_nat44_identity_mapping_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_identity_mapping_dump_t_tojson,
   .fromjson = vl_api_nat44_identity_mapping_dump_t_fromjson,
   .calc_size = vl_api_nat44_identity_mapping_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_IDENTITY_MAPPING_DETAILS + msg_id_base,
  .name = "nat44_identity_mapping_details",
  .handler = 0,
  .endian = vl_api_nat44_identity_mapping_details_t_endian,
  .format_fn = vl_api_nat44_identity_mapping_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_identity_mapping_details_t_tojson,
  .fromjson = vl_api_nat44_identity_mapping_details_t_fromjson,
  .calc_size = vl_api_nat44_identity_mapping_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_ADD_DEL_LB_STATIC_MAPPING + msg_id_base,
   .name = "nat44_add_del_lb_static_mapping",
   .handler = vl_api_nat44_add_del_lb_static_mapping_t_handler,
   .endian = vl_api_nat44_add_del_lb_static_mapping_t_endian,
   .format_fn = vl_api_nat44_add_del_lb_static_mapping_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_add_del_lb_static_mapping_t_tojson,
   .fromjson = vl_api_nat44_add_del_lb_static_mapping_t_fromjson,
   .calc_size = vl_api_nat44_add_del_lb_static_mapping_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_ADD_DEL_LB_STATIC_MAPPING_REPLY + msg_id_base,
  .name = "nat44_add_del_lb_static_mapping_reply",
  .handler = 0,
  .endian = vl_api_nat44_add_del_lb_static_mapping_reply_t_endian,
  .format_fn = vl_api_nat44_add_del_lb_static_mapping_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_add_del_lb_static_mapping_reply_t_tojson,
  .fromjson = vl_api_nat44_add_del_lb_static_mapping_reply_t_fromjson,
  .calc_size = vl_api_nat44_add_del_lb_static_mapping_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_LB_STATIC_MAPPING_ADD_DEL_LOCAL + msg_id_base,
   .name = "nat44_lb_static_mapping_add_del_local",
   .handler = vl_api_nat44_lb_static_mapping_add_del_local_t_handler,
   .endian = vl_api_nat44_lb_static_mapping_add_del_local_t_endian,
   .format_fn = vl_api_nat44_lb_static_mapping_add_del_local_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_lb_static_mapping_add_del_local_t_tojson,
   .fromjson = vl_api_nat44_lb_static_mapping_add_del_local_t_fromjson,
   .calc_size = vl_api_nat44_lb_static_mapping_add_del_local_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_LB_STATIC_MAPPING_ADD_DEL_LOCAL_REPLY + msg_id_base,
  .name = "nat44_lb_static_mapping_add_del_local_reply",
  .handler = 0,
  .endian = vl_api_nat44_lb_static_mapping_add_del_local_reply_t_endian,
  .format_fn = vl_api_nat44_lb_static_mapping_add_del_local_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_lb_static_mapping_add_del_local_reply_t_tojson,
  .fromjson = vl_api_nat44_lb_static_mapping_add_del_local_reply_t_fromjson,
  .calc_size = vl_api_nat44_lb_static_mapping_add_del_local_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_LB_STATIC_MAPPING_DUMP + msg_id_base,
   .name = "nat44_lb_static_mapping_dump",
   .handler = vl_api_nat44_lb_static_mapping_dump_t_handler,
   .endian = vl_api_nat44_lb_static_mapping_dump_t_endian,
   .format_fn = vl_api_nat44_lb_static_mapping_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_lb_static_mapping_dump_t_tojson,
   .fromjson = vl_api_nat44_lb_static_mapping_dump_t_fromjson,
   .calc_size = vl_api_nat44_lb_static_mapping_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_LB_STATIC_MAPPING_DETAILS + msg_id_base,
  .name = "nat44_lb_static_mapping_details",
  .handler = 0,
  .endian = vl_api_nat44_lb_static_mapping_details_t_endian,
  .format_fn = vl_api_nat44_lb_static_mapping_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_lb_static_mapping_details_t_tojson,
  .fromjson = vl_api_nat44_lb_static_mapping_details_t_fromjson,
  .calc_size = vl_api_nat44_lb_static_mapping_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_DEL_SESSION + msg_id_base,
   .name = "nat44_del_session",
   .handler = vl_api_nat44_del_session_t_handler,
   .endian = vl_api_nat44_del_session_t_endian,
   .format_fn = vl_api_nat44_del_session_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_del_session_t_tojson,
   .fromjson = vl_api_nat44_del_session_t_fromjson,
   .calc_size = vl_api_nat44_del_session_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_DEL_SESSION_REPLY + msg_id_base,
  .name = "nat44_del_session_reply",
  .handler = 0,
  .endian = vl_api_nat44_del_session_reply_t_endian,
  .format_fn = vl_api_nat44_del_session_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_del_session_reply_t_tojson,
  .fromjson = vl_api_nat44_del_session_reply_t_fromjson,
  .calc_size = vl_api_nat44_del_session_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_USER_DUMP + msg_id_base,
   .name = "nat44_user_dump",
   .handler = vl_api_nat44_user_dump_t_handler,
   .endian = vl_api_nat44_user_dump_t_endian,
   .format_fn = vl_api_nat44_user_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_user_dump_t_tojson,
   .fromjson = vl_api_nat44_user_dump_t_fromjson,
   .calc_size = vl_api_nat44_user_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_USER_DETAILS + msg_id_base,
  .name = "nat44_user_details",
  .handler = 0,
  .endian = vl_api_nat44_user_details_t_endian,
  .format_fn = vl_api_nat44_user_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_user_details_t_tojson,
  .fromjson = vl_api_nat44_user_details_t_fromjson,
  .calc_size = vl_api_nat44_user_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_USER_SESSION_DUMP + msg_id_base,
   .name = "nat44_user_session_dump",
   .handler = vl_api_nat44_user_session_dump_t_handler,
   .endian = vl_api_nat44_user_session_dump_t_endian,
   .format_fn = vl_api_nat44_user_session_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_user_session_dump_t_tojson,
   .fromjson = vl_api_nat44_user_session_dump_t_fromjson,
   .calc_size = vl_api_nat44_user_session_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_USER_SESSION_DETAILS + msg_id_base,
  .name = "nat44_user_session_details",
  .handler = 0,
  .endian = vl_api_nat44_user_session_details_t_endian,
  .format_fn = vl_api_nat44_user_session_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_user_session_details_t_tojson,
  .fromjson = vl_api_nat44_user_session_details_t_fromjson,
  .calc_size = vl_api_nat44_user_session_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_USER_SESSION_V2_DUMP + msg_id_base,
   .name = "nat44_user_session_v2_dump",
   .handler = vl_api_nat44_user_session_v2_dump_t_handler,
   .endian = vl_api_nat44_user_session_v2_dump_t_endian,
   .format_fn = vl_api_nat44_user_session_v2_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_user_session_v2_dump_t_tojson,
   .fromjson = vl_api_nat44_user_session_v2_dump_t_fromjson,
   .calc_size = vl_api_nat44_user_session_v2_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_USER_SESSION_V2_DETAILS + msg_id_base,
  .name = "nat44_user_session_v2_details",
  .handler = 0,
  .endian = vl_api_nat44_user_session_v2_details_t_endian,
  .format_fn = vl_api_nat44_user_session_v2_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_user_session_v2_details_t_tojson,
  .fromjson = vl_api_nat44_user_session_v2_details_t_fromjson,
  .calc_size = vl_api_nat44_user_session_v2_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT44_USER_SESSION_V3_DUMP + msg_id_base,
   .name = "nat44_user_session_v3_dump",
   .handler = vl_api_nat44_user_session_v3_dump_t_handler,
   .endian = vl_api_nat44_user_session_v3_dump_t_endian,
   .format_fn = vl_api_nat44_user_session_v3_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat44_user_session_v3_dump_t_tojson,
   .fromjson = vl_api_nat44_user_session_v3_dump_t_fromjson,
   .calc_size = vl_api_nat44_user_session_v3_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT44_USER_SESSION_V3_DETAILS + msg_id_base,
  .name = "nat44_user_session_v3_details",
  .handler = 0,
  .endian = vl_api_nat44_user_session_v3_details_t_endian,
  .format_fn = vl_api_nat44_user_session_v3_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat44_user_session_v3_details_t_tojson,
  .fromjson = vl_api_nat44_user_session_v3_details_t_fromjson,
  .calc_size = vl_api_nat44_user_session_v3_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
