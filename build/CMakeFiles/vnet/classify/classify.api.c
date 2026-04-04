#define vl_endianfun		/* define message structures */
#include "classify.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "classify.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "classify.api.h"
#undef vl_printfun

#include "classify.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("classify_fdc06ac8", VL_MSG_CLASSIFY_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_classify);
   vl_msg_api_add_msg_name_crc (am, "classify_add_del_table_6849e39e",
                                VL_API_CLASSIFY_ADD_DEL_TABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_add_del_table_reply_05486349",
                                VL_API_CLASSIFY_ADD_DEL_TABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_add_del_session_f20879f0",
                                VL_API_CLASSIFY_ADD_DEL_SESSION + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_add_del_session_reply_e8d4e804",
                                VL_API_CLASSIFY_ADD_DEL_SESSION_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_classify_set_interface_de7ad708",
                                VL_API_POLICER_CLASSIFY_SET_INTERFACE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_classify_set_interface_reply_e8d4e804",
                                VL_API_POLICER_CLASSIFY_SET_INTERFACE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_classify_dump_56cbb5fb",
                                VL_API_POLICER_CLASSIFY_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_classify_details_dfd08765",
                                VL_API_POLICER_CLASSIFY_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_table_ids_51077d14",
                                VL_API_CLASSIFY_TABLE_IDS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_table_ids_reply_d1d20e1d",
                                VL_API_CLASSIFY_TABLE_IDS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_table_by_interface_f9e6675e",
                                VL_API_CLASSIFY_TABLE_BY_INTERFACE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_table_by_interface_reply_ed4197db",
                                VL_API_CLASSIFY_TABLE_BY_INTERFACE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_table_info_0cca2cd9",
                                VL_API_CLASSIFY_TABLE_INFO + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_table_info_reply_4a573c0e",
                                VL_API_CLASSIFY_TABLE_INFO_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_session_dump_0cca2cd9",
                                VL_API_CLASSIFY_SESSION_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_session_details_60e3ef94",
                                VL_API_CLASSIFY_SESSION_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flow_classify_set_interface_b6192f1c",
                                VL_API_FLOW_CLASSIFY_SET_INTERFACE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flow_classify_set_interface_reply_e8d4e804",
                                VL_API_FLOW_CLASSIFY_SET_INTERFACE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flow_classify_dump_25dd3e4c",
                                VL_API_FLOW_CLASSIFY_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flow_classify_details_dfd08765",
                                VL_API_FLOW_CLASSIFY_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_set_interface_ip_table_e0b097c7",
                                VL_API_CLASSIFY_SET_INTERFACE_IP_TABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_set_interface_ip_table_reply_e8d4e804",
                                VL_API_CLASSIFY_SET_INTERFACE_IP_TABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_set_interface_l2_tables_5a6ddf65",
                                VL_API_CLASSIFY_SET_INTERFACE_L2_TABLES + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_set_interface_l2_tables_reply_e8d4e804",
                                VL_API_CLASSIFY_SET_INTERFACE_L2_TABLES_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "input_acl_set_interface_de7ad708",
                                VL_API_INPUT_ACL_SET_INTERFACE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "input_acl_set_interface_reply_e8d4e804",
                                VL_API_INPUT_ACL_SET_INTERFACE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "punt_acl_add_del_a93bf3a0",
                                VL_API_PUNT_ACL_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "punt_acl_add_del_reply_e8d4e804",
                                VL_API_PUNT_ACL_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "punt_acl_get_51077d14",
                                VL_API_PUNT_ACL_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "punt_acl_get_reply_8409b9dd",
                                VL_API_PUNT_ACL_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "output_acl_set_interface_de7ad708",
                                VL_API_OUTPUT_ACL_SET_INTERFACE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "output_acl_set_interface_reply_e8d4e804",
                                VL_API_OUTPUT_ACL_SET_INTERFACE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_pcap_lookup_table_e1b4cc6b",
                                VL_API_CLASSIFY_PCAP_LOOKUP_TABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_pcap_lookup_table_reply_9c6c6773",
                                VL_API_CLASSIFY_PCAP_LOOKUP_TABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_pcap_set_table_006051b3",
                                VL_API_CLASSIFY_PCAP_SET_TABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_pcap_set_table_reply_9c6c6773",
                                VL_API_CLASSIFY_PCAP_SET_TABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_pcap_get_tables_f9e6675e",
                                VL_API_CLASSIFY_PCAP_GET_TABLES + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_pcap_get_tables_reply_5f5bc9e6",
                                VL_API_CLASSIFY_PCAP_GET_TABLES_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_trace_lookup_table_3f7b72e4",
                                VL_API_CLASSIFY_TRACE_LOOKUP_TABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_trace_lookup_table_reply_9c6c6773",
                                VL_API_CLASSIFY_TRACE_LOOKUP_TABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_trace_set_table_3909b55a",
                                VL_API_CLASSIFY_TRACE_SET_TABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_trace_set_table_reply_9c6c6773",
                                VL_API_CLASSIFY_TRACE_SET_TABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_trace_get_tables_51077d14",
                                VL_API_CLASSIFY_TRACE_GET_TABLES + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "classify_trace_get_tables_reply_5f5bc9e6",
                                VL_API_CLASSIFY_TRACE_GET_TABLES_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CLASSIFY_ADD_DEL_TABLE + msg_id_base,
   .name = "classify_add_del_table",
   .handler = vl_api_classify_add_del_table_t_handler,
   .endian = vl_api_classify_add_del_table_t_endian,
   .format_fn = vl_api_classify_add_del_table_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_classify_add_del_table_t_tojson,
   .fromjson = vl_api_classify_add_del_table_t_fromjson,
   .calc_size = vl_api_classify_add_del_table_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CLASSIFY_ADD_DEL_TABLE_REPLY + msg_id_base,
  .name = "classify_add_del_table_reply",
  .handler = 0,
  .endian = vl_api_classify_add_del_table_reply_t_endian,
  .format_fn = vl_api_classify_add_del_table_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_classify_add_del_table_reply_t_tojson,
  .fromjson = vl_api_classify_add_del_table_reply_t_fromjson,
  .calc_size = vl_api_classify_add_del_table_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CLASSIFY_ADD_DEL_SESSION + msg_id_base,
   .name = "classify_add_del_session",
   .handler = vl_api_classify_add_del_session_t_handler,
   .endian = vl_api_classify_add_del_session_t_endian,
   .format_fn = vl_api_classify_add_del_session_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_classify_add_del_session_t_tojson,
   .fromjson = vl_api_classify_add_del_session_t_fromjson,
   .calc_size = vl_api_classify_add_del_session_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CLASSIFY_ADD_DEL_SESSION_REPLY + msg_id_base,
  .name = "classify_add_del_session_reply",
  .handler = 0,
  .endian = vl_api_classify_add_del_session_reply_t_endian,
  .format_fn = vl_api_classify_add_del_session_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_classify_add_del_session_reply_t_tojson,
  .fromjson = vl_api_classify_add_del_session_reply_t_fromjson,
  .calc_size = vl_api_classify_add_del_session_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_POLICER_CLASSIFY_SET_INTERFACE + msg_id_base,
   .name = "policer_classify_set_interface",
   .handler = vl_api_policer_classify_set_interface_t_handler,
   .endian = vl_api_policer_classify_set_interface_t_endian,
   .format_fn = vl_api_policer_classify_set_interface_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_policer_classify_set_interface_t_tojson,
   .fromjson = vl_api_policer_classify_set_interface_t_fromjson,
   .calc_size = vl_api_policer_classify_set_interface_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_POLICER_CLASSIFY_SET_INTERFACE_REPLY + msg_id_base,
  .name = "policer_classify_set_interface_reply",
  .handler = 0,
  .endian = vl_api_policer_classify_set_interface_reply_t_endian,
  .format_fn = vl_api_policer_classify_set_interface_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_policer_classify_set_interface_reply_t_tojson,
  .fromjson = vl_api_policer_classify_set_interface_reply_t_fromjson,
  .calc_size = vl_api_policer_classify_set_interface_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_POLICER_CLASSIFY_DUMP + msg_id_base,
   .name = "policer_classify_dump",
   .handler = vl_api_policer_classify_dump_t_handler,
   .endian = vl_api_policer_classify_dump_t_endian,
   .format_fn = vl_api_policer_classify_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_policer_classify_dump_t_tojson,
   .fromjson = vl_api_policer_classify_dump_t_fromjson,
   .calc_size = vl_api_policer_classify_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_POLICER_CLASSIFY_DETAILS + msg_id_base,
  .name = "policer_classify_details",
  .handler = 0,
  .endian = vl_api_policer_classify_details_t_endian,
  .format_fn = vl_api_policer_classify_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_policer_classify_details_t_tojson,
  .fromjson = vl_api_policer_classify_details_t_fromjson,
  .calc_size = vl_api_policer_classify_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CLASSIFY_TABLE_IDS + msg_id_base,
   .name = "classify_table_ids",
   .handler = vl_api_classify_table_ids_t_handler,
   .endian = vl_api_classify_table_ids_t_endian,
   .format_fn = vl_api_classify_table_ids_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_classify_table_ids_t_tojson,
   .fromjson = vl_api_classify_table_ids_t_fromjson,
   .calc_size = vl_api_classify_table_ids_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CLASSIFY_TABLE_IDS_REPLY + msg_id_base,
  .name = "classify_table_ids_reply",
  .handler = 0,
  .endian = vl_api_classify_table_ids_reply_t_endian,
  .format_fn = vl_api_classify_table_ids_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_classify_table_ids_reply_t_tojson,
  .fromjson = vl_api_classify_table_ids_reply_t_fromjson,
  .calc_size = vl_api_classify_table_ids_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CLASSIFY_TABLE_BY_INTERFACE + msg_id_base,
   .name = "classify_table_by_interface",
   .handler = vl_api_classify_table_by_interface_t_handler,
   .endian = vl_api_classify_table_by_interface_t_endian,
   .format_fn = vl_api_classify_table_by_interface_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_classify_table_by_interface_t_tojson,
   .fromjson = vl_api_classify_table_by_interface_t_fromjson,
   .calc_size = vl_api_classify_table_by_interface_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CLASSIFY_TABLE_BY_INTERFACE_REPLY + msg_id_base,
  .name = "classify_table_by_interface_reply",
  .handler = 0,
  .endian = vl_api_classify_table_by_interface_reply_t_endian,
  .format_fn = vl_api_classify_table_by_interface_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_classify_table_by_interface_reply_t_tojson,
  .fromjson = vl_api_classify_table_by_interface_reply_t_fromjson,
  .calc_size = vl_api_classify_table_by_interface_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CLASSIFY_TABLE_INFO + msg_id_base,
   .name = "classify_table_info",
   .handler = vl_api_classify_table_info_t_handler,
   .endian = vl_api_classify_table_info_t_endian,
   .format_fn = vl_api_classify_table_info_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_classify_table_info_t_tojson,
   .fromjson = vl_api_classify_table_info_t_fromjson,
   .calc_size = vl_api_classify_table_info_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CLASSIFY_TABLE_INFO_REPLY + msg_id_base,
  .name = "classify_table_info_reply",
  .handler = 0,
  .endian = vl_api_classify_table_info_reply_t_endian,
  .format_fn = vl_api_classify_table_info_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_classify_table_info_reply_t_tojson,
  .fromjson = vl_api_classify_table_info_reply_t_fromjson,
  .calc_size = vl_api_classify_table_info_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CLASSIFY_SESSION_DUMP + msg_id_base,
   .name = "classify_session_dump",
   .handler = vl_api_classify_session_dump_t_handler,
   .endian = vl_api_classify_session_dump_t_endian,
   .format_fn = vl_api_classify_session_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_classify_session_dump_t_tojson,
   .fromjson = vl_api_classify_session_dump_t_fromjson,
   .calc_size = vl_api_classify_session_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CLASSIFY_SESSION_DETAILS + msg_id_base,
  .name = "classify_session_details",
  .handler = 0,
  .endian = vl_api_classify_session_details_t_endian,
  .format_fn = vl_api_classify_session_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_classify_session_details_t_tojson,
  .fromjson = vl_api_classify_session_details_t_fromjson,
  .calc_size = vl_api_classify_session_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_FLOW_CLASSIFY_SET_INTERFACE + msg_id_base,
   .name = "flow_classify_set_interface",
   .handler = vl_api_flow_classify_set_interface_t_handler,
   .endian = vl_api_flow_classify_set_interface_t_endian,
   .format_fn = vl_api_flow_classify_set_interface_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_flow_classify_set_interface_t_tojson,
   .fromjson = vl_api_flow_classify_set_interface_t_fromjson,
   .calc_size = vl_api_flow_classify_set_interface_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_FLOW_CLASSIFY_SET_INTERFACE_REPLY + msg_id_base,
  .name = "flow_classify_set_interface_reply",
  .handler = 0,
  .endian = vl_api_flow_classify_set_interface_reply_t_endian,
  .format_fn = vl_api_flow_classify_set_interface_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_flow_classify_set_interface_reply_t_tojson,
  .fromjson = vl_api_flow_classify_set_interface_reply_t_fromjson,
  .calc_size = vl_api_flow_classify_set_interface_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_FLOW_CLASSIFY_DUMP + msg_id_base,
   .name = "flow_classify_dump",
   .handler = vl_api_flow_classify_dump_t_handler,
   .endian = vl_api_flow_classify_dump_t_endian,
   .format_fn = vl_api_flow_classify_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_flow_classify_dump_t_tojson,
   .fromjson = vl_api_flow_classify_dump_t_fromjson,
   .calc_size = vl_api_flow_classify_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_FLOW_CLASSIFY_DETAILS + msg_id_base,
  .name = "flow_classify_details",
  .handler = 0,
  .endian = vl_api_flow_classify_details_t_endian,
  .format_fn = vl_api_flow_classify_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_flow_classify_details_t_tojson,
  .fromjson = vl_api_flow_classify_details_t_fromjson,
  .calc_size = vl_api_flow_classify_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CLASSIFY_SET_INTERFACE_IP_TABLE + msg_id_base,
   .name = "classify_set_interface_ip_table",
   .handler = vl_api_classify_set_interface_ip_table_t_handler,
   .endian = vl_api_classify_set_interface_ip_table_t_endian,
   .format_fn = vl_api_classify_set_interface_ip_table_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_classify_set_interface_ip_table_t_tojson,
   .fromjson = vl_api_classify_set_interface_ip_table_t_fromjson,
   .calc_size = vl_api_classify_set_interface_ip_table_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CLASSIFY_SET_INTERFACE_IP_TABLE_REPLY + msg_id_base,
  .name = "classify_set_interface_ip_table_reply",
  .handler = 0,
  .endian = vl_api_classify_set_interface_ip_table_reply_t_endian,
  .format_fn = vl_api_classify_set_interface_ip_table_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_classify_set_interface_ip_table_reply_t_tojson,
  .fromjson = vl_api_classify_set_interface_ip_table_reply_t_fromjson,
  .calc_size = vl_api_classify_set_interface_ip_table_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CLASSIFY_SET_INTERFACE_L2_TABLES + msg_id_base,
   .name = "classify_set_interface_l2_tables",
   .handler = vl_api_classify_set_interface_l2_tables_t_handler,
   .endian = vl_api_classify_set_interface_l2_tables_t_endian,
   .format_fn = vl_api_classify_set_interface_l2_tables_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_classify_set_interface_l2_tables_t_tojson,
   .fromjson = vl_api_classify_set_interface_l2_tables_t_fromjson,
   .calc_size = vl_api_classify_set_interface_l2_tables_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CLASSIFY_SET_INTERFACE_L2_TABLES_REPLY + msg_id_base,
  .name = "classify_set_interface_l2_tables_reply",
  .handler = 0,
  .endian = vl_api_classify_set_interface_l2_tables_reply_t_endian,
  .format_fn = vl_api_classify_set_interface_l2_tables_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_classify_set_interface_l2_tables_reply_t_tojson,
  .fromjson = vl_api_classify_set_interface_l2_tables_reply_t_fromjson,
  .calc_size = vl_api_classify_set_interface_l2_tables_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_INPUT_ACL_SET_INTERFACE + msg_id_base,
   .name = "input_acl_set_interface",
   .handler = vl_api_input_acl_set_interface_t_handler,
   .endian = vl_api_input_acl_set_interface_t_endian,
   .format_fn = vl_api_input_acl_set_interface_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_input_acl_set_interface_t_tojson,
   .fromjson = vl_api_input_acl_set_interface_t_fromjson,
   .calc_size = vl_api_input_acl_set_interface_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_INPUT_ACL_SET_INTERFACE_REPLY + msg_id_base,
  .name = "input_acl_set_interface_reply",
  .handler = 0,
  .endian = vl_api_input_acl_set_interface_reply_t_endian,
  .format_fn = vl_api_input_acl_set_interface_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_input_acl_set_interface_reply_t_tojson,
  .fromjson = vl_api_input_acl_set_interface_reply_t_fromjson,
  .calc_size = vl_api_input_acl_set_interface_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PUNT_ACL_ADD_DEL + msg_id_base,
   .name = "punt_acl_add_del",
   .handler = vl_api_punt_acl_add_del_t_handler,
   .endian = vl_api_punt_acl_add_del_t_endian,
   .format_fn = vl_api_punt_acl_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_punt_acl_add_del_t_tojson,
   .fromjson = vl_api_punt_acl_add_del_t_fromjson,
   .calc_size = vl_api_punt_acl_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PUNT_ACL_ADD_DEL_REPLY + msg_id_base,
  .name = "punt_acl_add_del_reply",
  .handler = 0,
  .endian = vl_api_punt_acl_add_del_reply_t_endian,
  .format_fn = vl_api_punt_acl_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_punt_acl_add_del_reply_t_tojson,
  .fromjson = vl_api_punt_acl_add_del_reply_t_fromjson,
  .calc_size = vl_api_punt_acl_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PUNT_ACL_GET + msg_id_base,
   .name = "punt_acl_get",
   .handler = vl_api_punt_acl_get_t_handler,
   .endian = vl_api_punt_acl_get_t_endian,
   .format_fn = vl_api_punt_acl_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_punt_acl_get_t_tojson,
   .fromjson = vl_api_punt_acl_get_t_fromjson,
   .calc_size = vl_api_punt_acl_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PUNT_ACL_GET_REPLY + msg_id_base,
  .name = "punt_acl_get_reply",
  .handler = 0,
  .endian = vl_api_punt_acl_get_reply_t_endian,
  .format_fn = vl_api_punt_acl_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_punt_acl_get_reply_t_tojson,
  .fromjson = vl_api_punt_acl_get_reply_t_fromjson,
  .calc_size = vl_api_punt_acl_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_OUTPUT_ACL_SET_INTERFACE + msg_id_base,
   .name = "output_acl_set_interface",
   .handler = vl_api_output_acl_set_interface_t_handler,
   .endian = vl_api_output_acl_set_interface_t_endian,
   .format_fn = vl_api_output_acl_set_interface_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_output_acl_set_interface_t_tojson,
   .fromjson = vl_api_output_acl_set_interface_t_fromjson,
   .calc_size = vl_api_output_acl_set_interface_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_OUTPUT_ACL_SET_INTERFACE_REPLY + msg_id_base,
  .name = "output_acl_set_interface_reply",
  .handler = 0,
  .endian = vl_api_output_acl_set_interface_reply_t_endian,
  .format_fn = vl_api_output_acl_set_interface_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_output_acl_set_interface_reply_t_tojson,
  .fromjson = vl_api_output_acl_set_interface_reply_t_fromjson,
  .calc_size = vl_api_output_acl_set_interface_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CLASSIFY_PCAP_LOOKUP_TABLE + msg_id_base,
   .name = "classify_pcap_lookup_table",
   .handler = vl_api_classify_pcap_lookup_table_t_handler,
   .endian = vl_api_classify_pcap_lookup_table_t_endian,
   .format_fn = vl_api_classify_pcap_lookup_table_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_classify_pcap_lookup_table_t_tojson,
   .fromjson = vl_api_classify_pcap_lookup_table_t_fromjson,
   .calc_size = vl_api_classify_pcap_lookup_table_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CLASSIFY_PCAP_LOOKUP_TABLE_REPLY + msg_id_base,
  .name = "classify_pcap_lookup_table_reply",
  .handler = 0,
  .endian = vl_api_classify_pcap_lookup_table_reply_t_endian,
  .format_fn = vl_api_classify_pcap_lookup_table_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_classify_pcap_lookup_table_reply_t_tojson,
  .fromjson = vl_api_classify_pcap_lookup_table_reply_t_fromjson,
  .calc_size = vl_api_classify_pcap_lookup_table_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CLASSIFY_PCAP_SET_TABLE + msg_id_base,
   .name = "classify_pcap_set_table",
   .handler = vl_api_classify_pcap_set_table_t_handler,
   .endian = vl_api_classify_pcap_set_table_t_endian,
   .format_fn = vl_api_classify_pcap_set_table_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_classify_pcap_set_table_t_tojson,
   .fromjson = vl_api_classify_pcap_set_table_t_fromjson,
   .calc_size = vl_api_classify_pcap_set_table_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CLASSIFY_PCAP_SET_TABLE_REPLY + msg_id_base,
  .name = "classify_pcap_set_table_reply",
  .handler = 0,
  .endian = vl_api_classify_pcap_set_table_reply_t_endian,
  .format_fn = vl_api_classify_pcap_set_table_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_classify_pcap_set_table_reply_t_tojson,
  .fromjson = vl_api_classify_pcap_set_table_reply_t_fromjson,
  .calc_size = vl_api_classify_pcap_set_table_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CLASSIFY_PCAP_GET_TABLES + msg_id_base,
   .name = "classify_pcap_get_tables",
   .handler = vl_api_classify_pcap_get_tables_t_handler,
   .endian = vl_api_classify_pcap_get_tables_t_endian,
   .format_fn = vl_api_classify_pcap_get_tables_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_classify_pcap_get_tables_t_tojson,
   .fromjson = vl_api_classify_pcap_get_tables_t_fromjson,
   .calc_size = vl_api_classify_pcap_get_tables_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CLASSIFY_PCAP_GET_TABLES_REPLY + msg_id_base,
  .name = "classify_pcap_get_tables_reply",
  .handler = 0,
  .endian = vl_api_classify_pcap_get_tables_reply_t_endian,
  .format_fn = vl_api_classify_pcap_get_tables_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_classify_pcap_get_tables_reply_t_tojson,
  .fromjson = vl_api_classify_pcap_get_tables_reply_t_fromjson,
  .calc_size = vl_api_classify_pcap_get_tables_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CLASSIFY_TRACE_LOOKUP_TABLE + msg_id_base,
   .name = "classify_trace_lookup_table",
   .handler = vl_api_classify_trace_lookup_table_t_handler,
   .endian = vl_api_classify_trace_lookup_table_t_endian,
   .format_fn = vl_api_classify_trace_lookup_table_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_classify_trace_lookup_table_t_tojson,
   .fromjson = vl_api_classify_trace_lookup_table_t_fromjson,
   .calc_size = vl_api_classify_trace_lookup_table_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CLASSIFY_TRACE_LOOKUP_TABLE_REPLY + msg_id_base,
  .name = "classify_trace_lookup_table_reply",
  .handler = 0,
  .endian = vl_api_classify_trace_lookup_table_reply_t_endian,
  .format_fn = vl_api_classify_trace_lookup_table_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_classify_trace_lookup_table_reply_t_tojson,
  .fromjson = vl_api_classify_trace_lookup_table_reply_t_fromjson,
  .calc_size = vl_api_classify_trace_lookup_table_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CLASSIFY_TRACE_SET_TABLE + msg_id_base,
   .name = "classify_trace_set_table",
   .handler = vl_api_classify_trace_set_table_t_handler,
   .endian = vl_api_classify_trace_set_table_t_endian,
   .format_fn = vl_api_classify_trace_set_table_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_classify_trace_set_table_t_tojson,
   .fromjson = vl_api_classify_trace_set_table_t_fromjson,
   .calc_size = vl_api_classify_trace_set_table_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CLASSIFY_TRACE_SET_TABLE_REPLY + msg_id_base,
  .name = "classify_trace_set_table_reply",
  .handler = 0,
  .endian = vl_api_classify_trace_set_table_reply_t_endian,
  .format_fn = vl_api_classify_trace_set_table_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_classify_trace_set_table_reply_t_tojson,
  .fromjson = vl_api_classify_trace_set_table_reply_t_fromjson,
  .calc_size = vl_api_classify_trace_set_table_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CLASSIFY_TRACE_GET_TABLES + msg_id_base,
   .name = "classify_trace_get_tables",
   .handler = vl_api_classify_trace_get_tables_t_handler,
   .endian = vl_api_classify_trace_get_tables_t_endian,
   .format_fn = vl_api_classify_trace_get_tables_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_classify_trace_get_tables_t_tojson,
   .fromjson = vl_api_classify_trace_get_tables_t_fromjson,
   .calc_size = vl_api_classify_trace_get_tables_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CLASSIFY_TRACE_GET_TABLES_REPLY + msg_id_base,
  .name = "classify_trace_get_tables_reply",
  .handler = 0,
  .endian = vl_api_classify_trace_get_tables_reply_t_endian,
  .format_fn = vl_api_classify_trace_get_tables_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_classify_trace_get_tables_reply_t_tojson,
  .fromjson = vl_api_classify_trace_get_tables_reply_t_fromjson,
  .calc_size = vl_api_classify_trace_get_tables_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
