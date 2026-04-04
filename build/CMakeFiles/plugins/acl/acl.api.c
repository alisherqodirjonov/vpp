#define vl_endianfun		/* define message structures */
#include "acl.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "acl.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "acl.api.h"
#undef vl_printfun

#include "acl.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("acl_9cde599d", VL_MSG_ACL_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_acl);
   vl_msg_api_add_msg_name_crc (am, "acl_plugin_get_version_51077d14",
                                VL_API_ACL_PLUGIN_GET_VERSION + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_plugin_get_version_reply_9b32cf86",
                                VL_API_ACL_PLUGIN_GET_VERSION_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_plugin_control_ping_51077d14",
                                VL_API_ACL_PLUGIN_CONTROL_PING + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_plugin_control_ping_reply_f6b0b8ca",
                                VL_API_ACL_PLUGIN_CONTROL_PING_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_plugin_get_conn_table_max_entries_51077d14",
                                VL_API_ACL_PLUGIN_GET_CONN_TABLE_MAX_ENTRIES + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_plugin_get_conn_table_max_entries_reply_7a096d3d",
                                VL_API_ACL_PLUGIN_GET_CONN_TABLE_MAX_ENTRIES_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_add_replace_ee5c2f18",
                                VL_API_ACL_ADD_REPLACE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_add_replace_reply_ac407b0c",
                                VL_API_ACL_ADD_REPLACE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_del_ef34fea4",
                                VL_API_ACL_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_del_reply_e8d4e804",
                                VL_API_ACL_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_interface_add_del_4b54bebd",
                                VL_API_ACL_INTERFACE_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_interface_add_del_reply_e8d4e804",
                                VL_API_ACL_INTERFACE_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_interface_set_acl_list_473982bd",
                                VL_API_ACL_INTERFACE_SET_ACL_LIST + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_interface_set_acl_list_reply_e8d4e804",
                                VL_API_ACL_INTERFACE_SET_ACL_LIST_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_dump_ef34fea4",
                                VL_API_ACL_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_details_95babae0",
                                VL_API_ACL_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_interface_list_dump_f9e6675e",
                                VL_API_ACL_INTERFACE_LIST_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_interface_list_details_e695d256",
                                VL_API_ACL_INTERFACE_LIST_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "macip_acl_add_ce6fbad0",
                                VL_API_MACIP_ACL_ADD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "macip_acl_add_reply_ac407b0c",
                                VL_API_MACIP_ACL_ADD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "macip_acl_add_replace_2a461dd4",
                                VL_API_MACIP_ACL_ADD_REPLACE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "macip_acl_add_replace_reply_ac407b0c",
                                VL_API_MACIP_ACL_ADD_REPLACE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "macip_acl_del_ef34fea4",
                                VL_API_MACIP_ACL_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "macip_acl_del_reply_e8d4e804",
                                VL_API_MACIP_ACL_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "macip_acl_interface_add_del_4b8690b1",
                                VL_API_MACIP_ACL_INTERFACE_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "macip_acl_interface_add_del_reply_e8d4e804",
                                VL_API_MACIP_ACL_INTERFACE_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "macip_acl_dump_ef34fea4",
                                VL_API_MACIP_ACL_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "macip_acl_details_27135b59",
                                VL_API_MACIP_ACL_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "macip_acl_interface_get_51077d14",
                                VL_API_MACIP_ACL_INTERFACE_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "macip_acl_interface_get_reply_accf9b05",
                                VL_API_MACIP_ACL_INTERFACE_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "macip_acl_interface_list_dump_f9e6675e",
                                VL_API_MACIP_ACL_INTERFACE_LIST_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "macip_acl_interface_list_details_a0c5d56d",
                                VL_API_MACIP_ACL_INTERFACE_LIST_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_interface_set_etype_whitelist_3f5c2d2d",
                                VL_API_ACL_INTERFACE_SET_ETYPE_WHITELIST + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_interface_set_etype_whitelist_reply_e8d4e804",
                                VL_API_ACL_INTERFACE_SET_ETYPE_WHITELIST_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_interface_etype_whitelist_dump_f9e6675e",
                                VL_API_ACL_INTERFACE_ETYPE_WHITELIST_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_interface_etype_whitelist_details_cc2bfded",
                                VL_API_ACL_INTERFACE_ETYPE_WHITELIST_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_stats_intf_counters_enable_b3e225d2",
                                VL_API_ACL_STATS_INTF_COUNTERS_ENABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_stats_intf_counters_enable_reply_e8d4e804",
                                VL_API_ACL_STATS_INTF_COUNTERS_ENABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_plugin_use_hash_lookup_set_b3e225d2",
                                VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_SET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_plugin_use_hash_lookup_set_reply_e8d4e804",
                                VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_SET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_plugin_use_hash_lookup_get_51077d14",
                                VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "acl_plugin_use_hash_lookup_get_reply_5392ad31",
                                VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_GET_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ACL_PLUGIN_GET_VERSION + msg_id_base,
   .name = "acl_plugin_get_version",
   .handler = vl_api_acl_plugin_get_version_t_handler,
   .endian = vl_api_acl_plugin_get_version_t_endian,
   .format_fn = vl_api_acl_plugin_get_version_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_acl_plugin_get_version_t_tojson,
   .fromjson = vl_api_acl_plugin_get_version_t_fromjson,
   .calc_size = vl_api_acl_plugin_get_version_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ACL_PLUGIN_GET_VERSION_REPLY + msg_id_base,
  .name = "acl_plugin_get_version_reply",
  .handler = 0,
  .endian = vl_api_acl_plugin_get_version_reply_t_endian,
  .format_fn = vl_api_acl_plugin_get_version_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_acl_plugin_get_version_reply_t_tojson,
  .fromjson = vl_api_acl_plugin_get_version_reply_t_fromjson,
  .calc_size = vl_api_acl_plugin_get_version_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ACL_PLUGIN_CONTROL_PING + msg_id_base,
   .name = "acl_plugin_control_ping",
   .handler = vl_api_acl_plugin_control_ping_t_handler,
   .endian = vl_api_acl_plugin_control_ping_t_endian,
   .format_fn = vl_api_acl_plugin_control_ping_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_acl_plugin_control_ping_t_tojson,
   .fromjson = vl_api_acl_plugin_control_ping_t_fromjson,
   .calc_size = vl_api_acl_plugin_control_ping_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ACL_PLUGIN_CONTROL_PING_REPLY + msg_id_base,
  .name = "acl_plugin_control_ping_reply",
  .handler = 0,
  .endian = vl_api_acl_plugin_control_ping_reply_t_endian,
  .format_fn = vl_api_acl_plugin_control_ping_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_acl_plugin_control_ping_reply_t_tojson,
  .fromjson = vl_api_acl_plugin_control_ping_reply_t_fromjson,
  .calc_size = vl_api_acl_plugin_control_ping_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ACL_PLUGIN_GET_CONN_TABLE_MAX_ENTRIES + msg_id_base,
   .name = "acl_plugin_get_conn_table_max_entries",
   .handler = vl_api_acl_plugin_get_conn_table_max_entries_t_handler,
   .endian = vl_api_acl_plugin_get_conn_table_max_entries_t_endian,
   .format_fn = vl_api_acl_plugin_get_conn_table_max_entries_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_acl_plugin_get_conn_table_max_entries_t_tojson,
   .fromjson = vl_api_acl_plugin_get_conn_table_max_entries_t_fromjson,
   .calc_size = vl_api_acl_plugin_get_conn_table_max_entries_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ACL_PLUGIN_GET_CONN_TABLE_MAX_ENTRIES_REPLY + msg_id_base,
  .name = "acl_plugin_get_conn_table_max_entries_reply",
  .handler = 0,
  .endian = vl_api_acl_plugin_get_conn_table_max_entries_reply_t_endian,
  .format_fn = vl_api_acl_plugin_get_conn_table_max_entries_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_acl_plugin_get_conn_table_max_entries_reply_t_tojson,
  .fromjson = vl_api_acl_plugin_get_conn_table_max_entries_reply_t_fromjson,
  .calc_size = vl_api_acl_plugin_get_conn_table_max_entries_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ACL_ADD_REPLACE + msg_id_base,
   .name = "acl_add_replace",
   .handler = vl_api_acl_add_replace_t_handler,
   .endian = vl_api_acl_add_replace_t_endian,
   .format_fn = vl_api_acl_add_replace_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_acl_add_replace_t_tojson,
   .fromjson = vl_api_acl_add_replace_t_fromjson,
   .calc_size = vl_api_acl_add_replace_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ACL_ADD_REPLACE_REPLY + msg_id_base,
  .name = "acl_add_replace_reply",
  .handler = 0,
  .endian = vl_api_acl_add_replace_reply_t_endian,
  .format_fn = vl_api_acl_add_replace_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_acl_add_replace_reply_t_tojson,
  .fromjson = vl_api_acl_add_replace_reply_t_fromjson,
  .calc_size = vl_api_acl_add_replace_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ACL_DEL + msg_id_base,
   .name = "acl_del",
   .handler = vl_api_acl_del_t_handler,
   .endian = vl_api_acl_del_t_endian,
   .format_fn = vl_api_acl_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_acl_del_t_tojson,
   .fromjson = vl_api_acl_del_t_fromjson,
   .calc_size = vl_api_acl_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ACL_DEL_REPLY + msg_id_base,
  .name = "acl_del_reply",
  .handler = 0,
  .endian = vl_api_acl_del_reply_t_endian,
  .format_fn = vl_api_acl_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_acl_del_reply_t_tojson,
  .fromjson = vl_api_acl_del_reply_t_fromjson,
  .calc_size = vl_api_acl_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ACL_INTERFACE_ADD_DEL + msg_id_base,
   .name = "acl_interface_add_del",
   .handler = vl_api_acl_interface_add_del_t_handler,
   .endian = vl_api_acl_interface_add_del_t_endian,
   .format_fn = vl_api_acl_interface_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_acl_interface_add_del_t_tojson,
   .fromjson = vl_api_acl_interface_add_del_t_fromjson,
   .calc_size = vl_api_acl_interface_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ACL_INTERFACE_ADD_DEL_REPLY + msg_id_base,
  .name = "acl_interface_add_del_reply",
  .handler = 0,
  .endian = vl_api_acl_interface_add_del_reply_t_endian,
  .format_fn = vl_api_acl_interface_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_acl_interface_add_del_reply_t_tojson,
  .fromjson = vl_api_acl_interface_add_del_reply_t_fromjson,
  .calc_size = vl_api_acl_interface_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ACL_INTERFACE_SET_ACL_LIST + msg_id_base,
   .name = "acl_interface_set_acl_list",
   .handler = vl_api_acl_interface_set_acl_list_t_handler,
   .endian = vl_api_acl_interface_set_acl_list_t_endian,
   .format_fn = vl_api_acl_interface_set_acl_list_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_acl_interface_set_acl_list_t_tojson,
   .fromjson = vl_api_acl_interface_set_acl_list_t_fromjson,
   .calc_size = vl_api_acl_interface_set_acl_list_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ACL_INTERFACE_SET_ACL_LIST_REPLY + msg_id_base,
  .name = "acl_interface_set_acl_list_reply",
  .handler = 0,
  .endian = vl_api_acl_interface_set_acl_list_reply_t_endian,
  .format_fn = vl_api_acl_interface_set_acl_list_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_acl_interface_set_acl_list_reply_t_tojson,
  .fromjson = vl_api_acl_interface_set_acl_list_reply_t_fromjson,
  .calc_size = vl_api_acl_interface_set_acl_list_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ACL_DUMP + msg_id_base,
   .name = "acl_dump",
   .handler = vl_api_acl_dump_t_handler,
   .endian = vl_api_acl_dump_t_endian,
   .format_fn = vl_api_acl_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_acl_dump_t_tojson,
   .fromjson = vl_api_acl_dump_t_fromjson,
   .calc_size = vl_api_acl_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ACL_DETAILS + msg_id_base,
  .name = "acl_details",
  .handler = 0,
  .endian = vl_api_acl_details_t_endian,
  .format_fn = vl_api_acl_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_acl_details_t_tojson,
  .fromjson = vl_api_acl_details_t_fromjson,
  .calc_size = vl_api_acl_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ACL_INTERFACE_LIST_DUMP + msg_id_base,
   .name = "acl_interface_list_dump",
   .handler = vl_api_acl_interface_list_dump_t_handler,
   .endian = vl_api_acl_interface_list_dump_t_endian,
   .format_fn = vl_api_acl_interface_list_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_acl_interface_list_dump_t_tojson,
   .fromjson = vl_api_acl_interface_list_dump_t_fromjson,
   .calc_size = vl_api_acl_interface_list_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ACL_INTERFACE_LIST_DETAILS + msg_id_base,
  .name = "acl_interface_list_details",
  .handler = 0,
  .endian = vl_api_acl_interface_list_details_t_endian,
  .format_fn = vl_api_acl_interface_list_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_acl_interface_list_details_t_tojson,
  .fromjson = vl_api_acl_interface_list_details_t_fromjson,
  .calc_size = vl_api_acl_interface_list_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MACIP_ACL_ADD + msg_id_base,
   .name = "macip_acl_add",
   .handler = vl_api_macip_acl_add_t_handler,
   .endian = vl_api_macip_acl_add_t_endian,
   .format_fn = vl_api_macip_acl_add_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_macip_acl_add_t_tojson,
   .fromjson = vl_api_macip_acl_add_t_fromjson,
   .calc_size = vl_api_macip_acl_add_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MACIP_ACL_ADD_REPLY + msg_id_base,
  .name = "macip_acl_add_reply",
  .handler = 0,
  .endian = vl_api_macip_acl_add_reply_t_endian,
  .format_fn = vl_api_macip_acl_add_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_macip_acl_add_reply_t_tojson,
  .fromjson = vl_api_macip_acl_add_reply_t_fromjson,
  .calc_size = vl_api_macip_acl_add_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MACIP_ACL_ADD_REPLACE + msg_id_base,
   .name = "macip_acl_add_replace",
   .handler = vl_api_macip_acl_add_replace_t_handler,
   .endian = vl_api_macip_acl_add_replace_t_endian,
   .format_fn = vl_api_macip_acl_add_replace_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_macip_acl_add_replace_t_tojson,
   .fromjson = vl_api_macip_acl_add_replace_t_fromjson,
   .calc_size = vl_api_macip_acl_add_replace_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MACIP_ACL_ADD_REPLACE_REPLY + msg_id_base,
  .name = "macip_acl_add_replace_reply",
  .handler = 0,
  .endian = vl_api_macip_acl_add_replace_reply_t_endian,
  .format_fn = vl_api_macip_acl_add_replace_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_macip_acl_add_replace_reply_t_tojson,
  .fromjson = vl_api_macip_acl_add_replace_reply_t_fromjson,
  .calc_size = vl_api_macip_acl_add_replace_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MACIP_ACL_DEL + msg_id_base,
   .name = "macip_acl_del",
   .handler = vl_api_macip_acl_del_t_handler,
   .endian = vl_api_macip_acl_del_t_endian,
   .format_fn = vl_api_macip_acl_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_macip_acl_del_t_tojson,
   .fromjson = vl_api_macip_acl_del_t_fromjson,
   .calc_size = vl_api_macip_acl_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MACIP_ACL_DEL_REPLY + msg_id_base,
  .name = "macip_acl_del_reply",
  .handler = 0,
  .endian = vl_api_macip_acl_del_reply_t_endian,
  .format_fn = vl_api_macip_acl_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_macip_acl_del_reply_t_tojson,
  .fromjson = vl_api_macip_acl_del_reply_t_fromjson,
  .calc_size = vl_api_macip_acl_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MACIP_ACL_INTERFACE_ADD_DEL + msg_id_base,
   .name = "macip_acl_interface_add_del",
   .handler = vl_api_macip_acl_interface_add_del_t_handler,
   .endian = vl_api_macip_acl_interface_add_del_t_endian,
   .format_fn = vl_api_macip_acl_interface_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_macip_acl_interface_add_del_t_tojson,
   .fromjson = vl_api_macip_acl_interface_add_del_t_fromjson,
   .calc_size = vl_api_macip_acl_interface_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MACIP_ACL_INTERFACE_ADD_DEL_REPLY + msg_id_base,
  .name = "macip_acl_interface_add_del_reply",
  .handler = 0,
  .endian = vl_api_macip_acl_interface_add_del_reply_t_endian,
  .format_fn = vl_api_macip_acl_interface_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_macip_acl_interface_add_del_reply_t_tojson,
  .fromjson = vl_api_macip_acl_interface_add_del_reply_t_fromjson,
  .calc_size = vl_api_macip_acl_interface_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MACIP_ACL_DUMP + msg_id_base,
   .name = "macip_acl_dump",
   .handler = vl_api_macip_acl_dump_t_handler,
   .endian = vl_api_macip_acl_dump_t_endian,
   .format_fn = vl_api_macip_acl_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_macip_acl_dump_t_tojson,
   .fromjson = vl_api_macip_acl_dump_t_fromjson,
   .calc_size = vl_api_macip_acl_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MACIP_ACL_DETAILS + msg_id_base,
  .name = "macip_acl_details",
  .handler = 0,
  .endian = vl_api_macip_acl_details_t_endian,
  .format_fn = vl_api_macip_acl_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_macip_acl_details_t_tojson,
  .fromjson = vl_api_macip_acl_details_t_fromjson,
  .calc_size = vl_api_macip_acl_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MACIP_ACL_INTERFACE_GET + msg_id_base,
   .name = "macip_acl_interface_get",
   .handler = vl_api_macip_acl_interface_get_t_handler,
   .endian = vl_api_macip_acl_interface_get_t_endian,
   .format_fn = vl_api_macip_acl_interface_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_macip_acl_interface_get_t_tojson,
   .fromjson = vl_api_macip_acl_interface_get_t_fromjson,
   .calc_size = vl_api_macip_acl_interface_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MACIP_ACL_INTERFACE_GET_REPLY + msg_id_base,
  .name = "macip_acl_interface_get_reply",
  .handler = 0,
  .endian = vl_api_macip_acl_interface_get_reply_t_endian,
  .format_fn = vl_api_macip_acl_interface_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_macip_acl_interface_get_reply_t_tojson,
  .fromjson = vl_api_macip_acl_interface_get_reply_t_fromjson,
  .calc_size = vl_api_macip_acl_interface_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MACIP_ACL_INTERFACE_LIST_DUMP + msg_id_base,
   .name = "macip_acl_interface_list_dump",
   .handler = vl_api_macip_acl_interface_list_dump_t_handler,
   .endian = vl_api_macip_acl_interface_list_dump_t_endian,
   .format_fn = vl_api_macip_acl_interface_list_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_macip_acl_interface_list_dump_t_tojson,
   .fromjson = vl_api_macip_acl_interface_list_dump_t_fromjson,
   .calc_size = vl_api_macip_acl_interface_list_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MACIP_ACL_INTERFACE_LIST_DETAILS + msg_id_base,
  .name = "macip_acl_interface_list_details",
  .handler = 0,
  .endian = vl_api_macip_acl_interface_list_details_t_endian,
  .format_fn = vl_api_macip_acl_interface_list_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_macip_acl_interface_list_details_t_tojson,
  .fromjson = vl_api_macip_acl_interface_list_details_t_fromjson,
  .calc_size = vl_api_macip_acl_interface_list_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ACL_INTERFACE_SET_ETYPE_WHITELIST + msg_id_base,
   .name = "acl_interface_set_etype_whitelist",
   .handler = vl_api_acl_interface_set_etype_whitelist_t_handler,
   .endian = vl_api_acl_interface_set_etype_whitelist_t_endian,
   .format_fn = vl_api_acl_interface_set_etype_whitelist_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_acl_interface_set_etype_whitelist_t_tojson,
   .fromjson = vl_api_acl_interface_set_etype_whitelist_t_fromjson,
   .calc_size = vl_api_acl_interface_set_etype_whitelist_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ACL_INTERFACE_SET_ETYPE_WHITELIST_REPLY + msg_id_base,
  .name = "acl_interface_set_etype_whitelist_reply",
  .handler = 0,
  .endian = vl_api_acl_interface_set_etype_whitelist_reply_t_endian,
  .format_fn = vl_api_acl_interface_set_etype_whitelist_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_acl_interface_set_etype_whitelist_reply_t_tojson,
  .fromjson = vl_api_acl_interface_set_etype_whitelist_reply_t_fromjson,
  .calc_size = vl_api_acl_interface_set_etype_whitelist_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ACL_INTERFACE_ETYPE_WHITELIST_DUMP + msg_id_base,
   .name = "acl_interface_etype_whitelist_dump",
   .handler = vl_api_acl_interface_etype_whitelist_dump_t_handler,
   .endian = vl_api_acl_interface_etype_whitelist_dump_t_endian,
   .format_fn = vl_api_acl_interface_etype_whitelist_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_acl_interface_etype_whitelist_dump_t_tojson,
   .fromjson = vl_api_acl_interface_etype_whitelist_dump_t_fromjson,
   .calc_size = vl_api_acl_interface_etype_whitelist_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ACL_INTERFACE_ETYPE_WHITELIST_DETAILS + msg_id_base,
  .name = "acl_interface_etype_whitelist_details",
  .handler = 0,
  .endian = vl_api_acl_interface_etype_whitelist_details_t_endian,
  .format_fn = vl_api_acl_interface_etype_whitelist_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_acl_interface_etype_whitelist_details_t_tojson,
  .fromjson = vl_api_acl_interface_etype_whitelist_details_t_fromjson,
  .calc_size = vl_api_acl_interface_etype_whitelist_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ACL_STATS_INTF_COUNTERS_ENABLE + msg_id_base,
   .name = "acl_stats_intf_counters_enable",
   .handler = vl_api_acl_stats_intf_counters_enable_t_handler,
   .endian = vl_api_acl_stats_intf_counters_enable_t_endian,
   .format_fn = vl_api_acl_stats_intf_counters_enable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_acl_stats_intf_counters_enable_t_tojson,
   .fromjson = vl_api_acl_stats_intf_counters_enable_t_fromjson,
   .calc_size = vl_api_acl_stats_intf_counters_enable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ACL_STATS_INTF_COUNTERS_ENABLE_REPLY + msg_id_base,
  .name = "acl_stats_intf_counters_enable_reply",
  .handler = 0,
  .endian = vl_api_acl_stats_intf_counters_enable_reply_t_endian,
  .format_fn = vl_api_acl_stats_intf_counters_enable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_acl_stats_intf_counters_enable_reply_t_tojson,
  .fromjson = vl_api_acl_stats_intf_counters_enable_reply_t_fromjson,
  .calc_size = vl_api_acl_stats_intf_counters_enable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_SET + msg_id_base,
   .name = "acl_plugin_use_hash_lookup_set",
   .handler = vl_api_acl_plugin_use_hash_lookup_set_t_handler,
   .endian = vl_api_acl_plugin_use_hash_lookup_set_t_endian,
   .format_fn = vl_api_acl_plugin_use_hash_lookup_set_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_acl_plugin_use_hash_lookup_set_t_tojson,
   .fromjson = vl_api_acl_plugin_use_hash_lookup_set_t_fromjson,
   .calc_size = vl_api_acl_plugin_use_hash_lookup_set_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_SET_REPLY + msg_id_base,
  .name = "acl_plugin_use_hash_lookup_set_reply",
  .handler = 0,
  .endian = vl_api_acl_plugin_use_hash_lookup_set_reply_t_endian,
  .format_fn = vl_api_acl_plugin_use_hash_lookup_set_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_acl_plugin_use_hash_lookup_set_reply_t_tojson,
  .fromjson = vl_api_acl_plugin_use_hash_lookup_set_reply_t_fromjson,
  .calc_size = vl_api_acl_plugin_use_hash_lookup_set_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_GET + msg_id_base,
   .name = "acl_plugin_use_hash_lookup_get",
   .handler = vl_api_acl_plugin_use_hash_lookup_get_t_handler,
   .endian = vl_api_acl_plugin_use_hash_lookup_get_t_endian,
   .format_fn = vl_api_acl_plugin_use_hash_lookup_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_acl_plugin_use_hash_lookup_get_t_tojson,
   .fromjson = vl_api_acl_plugin_use_hash_lookup_get_t_fromjson,
   .calc_size = vl_api_acl_plugin_use_hash_lookup_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_GET_REPLY + msg_id_base,
  .name = "acl_plugin_use_hash_lookup_get_reply",
  .handler = 0,
  .endian = vl_api_acl_plugin_use_hash_lookup_get_reply_t_endian,
  .format_fn = vl_api_acl_plugin_use_hash_lookup_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_acl_plugin_use_hash_lookup_get_reply_t_tojson,
  .fromjson = vl_api_acl_plugin_use_hash_lookup_get_reply_t_fromjson,
  .calc_size = vl_api_acl_plugin_use_hash_lookup_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
