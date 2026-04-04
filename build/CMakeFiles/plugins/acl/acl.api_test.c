#define vl_endianfun            /* define message structures */
#include "acl.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "acl.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "acl.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_acl_plugin_get_version_reply_t_handler()) */
/* Generation not supported (vl_api_acl_plugin_control_ping_reply_t_handler()) */
/* Generation not supported (vl_api_acl_plugin_get_conn_table_max_entries_reply_t_handler()) */
/* Generation not supported (vl_api_acl_add_replace_reply_t_handler()) */
#ifndef VL_API_ACL_DEL_REPLY_T_HANDLER
static void
vl_api_acl_del_reply_t_handler (vl_api_acl_del_reply_t * mp) {
   vat_main_t * vam = acl_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_ACL_INTERFACE_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_acl_interface_add_del_reply_t_handler (vl_api_acl_interface_add_del_reply_t * mp) {
   vat_main_t * vam = acl_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_ACL_INTERFACE_SET_ACL_LIST_REPLY_T_HANDLER
static void
vl_api_acl_interface_set_acl_list_reply_t_handler (vl_api_acl_interface_set_acl_list_reply_t * mp) {
   vat_main_t * vam = acl_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_acl_details_t_handler()) */
/* Generation not supported (vl_api_acl_interface_list_details_t_handler()) */
/* Generation not supported (vl_api_macip_acl_add_reply_t_handler()) */
/* Generation not supported (vl_api_macip_acl_add_replace_reply_t_handler()) */
#ifndef VL_API_MACIP_ACL_DEL_REPLY_T_HANDLER
static void
vl_api_macip_acl_del_reply_t_handler (vl_api_macip_acl_del_reply_t * mp) {
   vat_main_t * vam = acl_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_MACIP_ACL_INTERFACE_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_macip_acl_interface_add_del_reply_t_handler (vl_api_macip_acl_interface_add_del_reply_t * mp) {
   vat_main_t * vam = acl_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_macip_acl_details_t_handler()) */
/* Generation not supported (vl_api_macip_acl_interface_get_reply_t_handler()) */
/* Generation not supported (vl_api_macip_acl_interface_list_details_t_handler()) */
#ifndef VL_API_ACL_INTERFACE_SET_ETYPE_WHITELIST_REPLY_T_HANDLER
static void
vl_api_acl_interface_set_etype_whitelist_reply_t_handler (vl_api_acl_interface_set_etype_whitelist_reply_t * mp) {
   vat_main_t * vam = acl_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_acl_interface_etype_whitelist_details_t_handler()) */
#ifndef VL_API_ACL_STATS_INTF_COUNTERS_ENABLE_REPLY_T_HANDLER
static void
vl_api_acl_stats_intf_counters_enable_reply_t_handler (vl_api_acl_stats_intf_counters_enable_reply_t * mp) {
   vat_main_t * vam = acl_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_SET_REPLY_T_HANDLER
static void
vl_api_acl_plugin_use_hash_lookup_set_reply_t_handler (vl_api_acl_plugin_use_hash_lookup_set_reply_t * mp) {
   vat_main_t * vam = acl_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_acl_plugin_use_hash_lookup_get_reply_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ACL_PLUGIN_GET_VERSION_REPLY + msg_id_base,
    .name = "acl_plugin_get_version_reply",
    .handler = vl_api_acl_plugin_get_version_reply_t_handler,
    .endian = vl_api_acl_plugin_get_version_reply_t_endian,
    .format_fn = vl_api_acl_plugin_get_version_reply_t_format,
    .size = sizeof(vl_api_acl_plugin_get_version_reply_t),
    .traced = 1,
    .tojson = vl_api_acl_plugin_get_version_reply_t_tojson,
    .fromjson = vl_api_acl_plugin_get_version_reply_t_fromjson,
    .calc_size = vl_api_acl_plugin_get_version_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "acl_plugin_get_version", api_acl_plugin_get_version);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ACL_PLUGIN_CONTROL_PING_REPLY + msg_id_base,
    .name = "acl_plugin_control_ping_reply",
    .handler = vl_api_acl_plugin_control_ping_reply_t_handler,
    .endian = vl_api_acl_plugin_control_ping_reply_t_endian,
    .format_fn = vl_api_acl_plugin_control_ping_reply_t_format,
    .size = sizeof(vl_api_acl_plugin_control_ping_reply_t),
    .traced = 1,
    .tojson = vl_api_acl_plugin_control_ping_reply_t_tojson,
    .fromjson = vl_api_acl_plugin_control_ping_reply_t_fromjson,
    .calc_size = vl_api_acl_plugin_control_ping_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "acl_plugin_control_ping", api_acl_plugin_control_ping);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ACL_PLUGIN_GET_CONN_TABLE_MAX_ENTRIES_REPLY + msg_id_base,
    .name = "acl_plugin_get_conn_table_max_entries_reply",
    .handler = vl_api_acl_plugin_get_conn_table_max_entries_reply_t_handler,
    .endian = vl_api_acl_plugin_get_conn_table_max_entries_reply_t_endian,
    .format_fn = vl_api_acl_plugin_get_conn_table_max_entries_reply_t_format,
    .size = sizeof(vl_api_acl_plugin_get_conn_table_max_entries_reply_t),
    .traced = 1,
    .tojson = vl_api_acl_plugin_get_conn_table_max_entries_reply_t_tojson,
    .fromjson = vl_api_acl_plugin_get_conn_table_max_entries_reply_t_fromjson,
    .calc_size = vl_api_acl_plugin_get_conn_table_max_entries_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "acl_plugin_get_conn_table_max_entries", api_acl_plugin_get_conn_table_max_entries);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ACL_ADD_REPLACE_REPLY + msg_id_base,
    .name = "acl_add_replace_reply",
    .handler = vl_api_acl_add_replace_reply_t_handler,
    .endian = vl_api_acl_add_replace_reply_t_endian,
    .format_fn = vl_api_acl_add_replace_reply_t_format,
    .size = sizeof(vl_api_acl_add_replace_reply_t),
    .traced = 1,
    .tojson = vl_api_acl_add_replace_reply_t_tojson,
    .fromjson = vl_api_acl_add_replace_reply_t_fromjson,
    .calc_size = vl_api_acl_add_replace_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "acl_add_replace", api_acl_add_replace);
   hash_set_mem (vam->help_by_name, "acl_add_replace", "<acl-idx> <permit|permit+reflect|deny|action N> [src IP/plen] [dst IP/plen] [sport X-Y] [dport X-Y] [proto P] [tcpflags FL MASK], ... , ...");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ACL_DEL_REPLY + msg_id_base,
    .name = "acl_del_reply",
    .handler = vl_api_acl_del_reply_t_handler,
    .endian = vl_api_acl_del_reply_t_endian,
    .format_fn = vl_api_acl_del_reply_t_format,
    .size = sizeof(vl_api_acl_del_reply_t),
    .traced = 1,
    .tojson = vl_api_acl_del_reply_t_tojson,
    .fromjson = vl_api_acl_del_reply_t_fromjson,
    .calc_size = vl_api_acl_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "acl_del", api_acl_del);
   hash_set_mem (vam->help_by_name, "acl_del", "<acl-idx>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ACL_INTERFACE_ADD_DEL_REPLY + msg_id_base,
    .name = "acl_interface_add_del_reply",
    .handler = vl_api_acl_interface_add_del_reply_t_handler,
    .endian = vl_api_acl_interface_add_del_reply_t_endian,
    .format_fn = vl_api_acl_interface_add_del_reply_t_format,
    .size = sizeof(vl_api_acl_interface_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_acl_interface_add_del_reply_t_tojson,
    .fromjson = vl_api_acl_interface_add_del_reply_t_fromjson,
    .calc_size = vl_api_acl_interface_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "acl_interface_add_del", api_acl_interface_add_del);
   hash_set_mem (vam->help_by_name, "acl_interface_add_del", "<intfc> | sw_if_index <if-idx> [add|del] [input|output] acl <acl-idx>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ACL_INTERFACE_SET_ACL_LIST_REPLY + msg_id_base,
    .name = "acl_interface_set_acl_list_reply",
    .handler = vl_api_acl_interface_set_acl_list_reply_t_handler,
    .endian = vl_api_acl_interface_set_acl_list_reply_t_endian,
    .format_fn = vl_api_acl_interface_set_acl_list_reply_t_format,
    .size = sizeof(vl_api_acl_interface_set_acl_list_reply_t),
    .traced = 1,
    .tojson = vl_api_acl_interface_set_acl_list_reply_t_tojson,
    .fromjson = vl_api_acl_interface_set_acl_list_reply_t_fromjson,
    .calc_size = vl_api_acl_interface_set_acl_list_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "acl_interface_set_acl_list", api_acl_interface_set_acl_list);
   hash_set_mem (vam->help_by_name, "acl_interface_set_acl_list", "<intfc> | sw_if_index <if-idx> input [acl-idx list] output [acl-idx list]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ACL_DETAILS + msg_id_base,
    .name = "acl_details",
    .handler = vl_api_acl_details_t_handler,
    .endian = vl_api_acl_details_t_endian,
    .format_fn = vl_api_acl_details_t_format,
    .size = sizeof(vl_api_acl_details_t),
    .traced = 1,
    .tojson = vl_api_acl_details_t_tojson,
    .fromjson = vl_api_acl_details_t_fromjson,
    .calc_size = vl_api_acl_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "acl_dump", api_acl_dump);
   hash_set_mem (vam->help_by_name, "acl_dump", "[<acl-idx>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ACL_INTERFACE_LIST_DETAILS + msg_id_base,
    .name = "acl_interface_list_details",
    .handler = vl_api_acl_interface_list_details_t_handler,
    .endian = vl_api_acl_interface_list_details_t_endian,
    .format_fn = vl_api_acl_interface_list_details_t_format,
    .size = sizeof(vl_api_acl_interface_list_details_t),
    .traced = 1,
    .tojson = vl_api_acl_interface_list_details_t_tojson,
    .fromjson = vl_api_acl_interface_list_details_t_fromjson,
    .calc_size = vl_api_acl_interface_list_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "acl_interface_list_dump", api_acl_interface_list_dump);
   hash_set_mem (vam->help_by_name, "acl_interface_list_dump", "[<intfc> | sw_if_index <if-idx>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MACIP_ACL_ADD_REPLY + msg_id_base,
    .name = "macip_acl_add_reply",
    .handler = vl_api_macip_acl_add_reply_t_handler,
    .endian = vl_api_macip_acl_add_reply_t_endian,
    .format_fn = vl_api_macip_acl_add_reply_t_format,
    .size = sizeof(vl_api_macip_acl_add_reply_t),
    .traced = 1,
    .tojson = vl_api_macip_acl_add_reply_t_tojson,
    .fromjson = vl_api_macip_acl_add_reply_t_fromjson,
    .calc_size = vl_api_macip_acl_add_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "macip_acl_add", api_macip_acl_add);
   hash_set_mem (vam->help_by_name, "macip_acl_add", "...");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MACIP_ACL_ADD_REPLACE_REPLY + msg_id_base,
    .name = "macip_acl_add_replace_reply",
    .handler = vl_api_macip_acl_add_replace_reply_t_handler,
    .endian = vl_api_macip_acl_add_replace_reply_t_endian,
    .format_fn = vl_api_macip_acl_add_replace_reply_t_format,
    .size = sizeof(vl_api_macip_acl_add_replace_reply_t),
    .traced = 1,
    .tojson = vl_api_macip_acl_add_replace_reply_t_tojson,
    .fromjson = vl_api_macip_acl_add_replace_reply_t_fromjson,
    .calc_size = vl_api_macip_acl_add_replace_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "macip_acl_add_replace", api_macip_acl_add_replace);
   hash_set_mem (vam->help_by_name, "macip_acl_add_replace", "<acl-idx> <permit|deny|action N> [count <count>] [src] ip <ipaddress/[plen]> mac <mac> mask <mac_mask>, ... , ...");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MACIP_ACL_DEL_REPLY + msg_id_base,
    .name = "macip_acl_del_reply",
    .handler = vl_api_macip_acl_del_reply_t_handler,
    .endian = vl_api_macip_acl_del_reply_t_endian,
    .format_fn = vl_api_macip_acl_del_reply_t_format,
    .size = sizeof(vl_api_macip_acl_del_reply_t),
    .traced = 1,
    .tojson = vl_api_macip_acl_del_reply_t_tojson,
    .fromjson = vl_api_macip_acl_del_reply_t_fromjson,
    .calc_size = vl_api_macip_acl_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "macip_acl_del", api_macip_acl_del);
   hash_set_mem (vam->help_by_name, "macip_acl_del", "<acl-idx>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MACIP_ACL_INTERFACE_ADD_DEL_REPLY + msg_id_base,
    .name = "macip_acl_interface_add_del_reply",
    .handler = vl_api_macip_acl_interface_add_del_reply_t_handler,
    .endian = vl_api_macip_acl_interface_add_del_reply_t_endian,
    .format_fn = vl_api_macip_acl_interface_add_del_reply_t_format,
    .size = sizeof(vl_api_macip_acl_interface_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_macip_acl_interface_add_del_reply_t_tojson,
    .fromjson = vl_api_macip_acl_interface_add_del_reply_t_fromjson,
    .calc_size = vl_api_macip_acl_interface_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "macip_acl_interface_add_del", api_macip_acl_interface_add_del);
   hash_set_mem (vam->help_by_name, "macip_acl_interface_add_del", "<intfc> | sw_if_index <if-idx> [add|del] acl <acl-idx>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MACIP_ACL_DETAILS + msg_id_base,
    .name = "macip_acl_details",
    .handler = vl_api_macip_acl_details_t_handler,
    .endian = vl_api_macip_acl_details_t_endian,
    .format_fn = vl_api_macip_acl_details_t_format,
    .size = sizeof(vl_api_macip_acl_details_t),
    .traced = 1,
    .tojson = vl_api_macip_acl_details_t_tojson,
    .fromjson = vl_api_macip_acl_details_t_fromjson,
    .calc_size = vl_api_macip_acl_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "macip_acl_dump", api_macip_acl_dump);
   hash_set_mem (vam->help_by_name, "macip_acl_dump", "[<acl-idx>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MACIP_ACL_INTERFACE_GET_REPLY + msg_id_base,
    .name = "macip_acl_interface_get_reply",
    .handler = vl_api_macip_acl_interface_get_reply_t_handler,
    .endian = vl_api_macip_acl_interface_get_reply_t_endian,
    .format_fn = vl_api_macip_acl_interface_get_reply_t_format,
    .size = sizeof(vl_api_macip_acl_interface_get_reply_t),
    .traced = 1,
    .tojson = vl_api_macip_acl_interface_get_reply_t_tojson,
    .fromjson = vl_api_macip_acl_interface_get_reply_t_fromjson,
    .calc_size = vl_api_macip_acl_interface_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "macip_acl_interface_get", api_macip_acl_interface_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MACIP_ACL_INTERFACE_LIST_DETAILS + msg_id_base,
    .name = "macip_acl_interface_list_details",
    .handler = vl_api_macip_acl_interface_list_details_t_handler,
    .endian = vl_api_macip_acl_interface_list_details_t_endian,
    .format_fn = vl_api_macip_acl_interface_list_details_t_format,
    .size = sizeof(vl_api_macip_acl_interface_list_details_t),
    .traced = 1,
    .tojson = vl_api_macip_acl_interface_list_details_t_tojson,
    .fromjson = vl_api_macip_acl_interface_list_details_t_fromjson,
    .calc_size = vl_api_macip_acl_interface_list_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "macip_acl_interface_list_dump", api_macip_acl_interface_list_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ACL_INTERFACE_SET_ETYPE_WHITELIST_REPLY + msg_id_base,
    .name = "acl_interface_set_etype_whitelist_reply",
    .handler = vl_api_acl_interface_set_etype_whitelist_reply_t_handler,
    .endian = vl_api_acl_interface_set_etype_whitelist_reply_t_endian,
    .format_fn = vl_api_acl_interface_set_etype_whitelist_reply_t_format,
    .size = sizeof(vl_api_acl_interface_set_etype_whitelist_reply_t),
    .traced = 1,
    .tojson = vl_api_acl_interface_set_etype_whitelist_reply_t_tojson,
    .fromjson = vl_api_acl_interface_set_etype_whitelist_reply_t_fromjson,
    .calc_size = vl_api_acl_interface_set_etype_whitelist_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "acl_interface_set_etype_whitelist", api_acl_interface_set_etype_whitelist);
   hash_set_mem (vam->help_by_name, "acl_interface_set_etype_whitelist", "<intfc> | sw_if_index <if-idx> input [ethertype list] output [ethertype list]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ACL_INTERFACE_ETYPE_WHITELIST_DETAILS + msg_id_base,
    .name = "acl_interface_etype_whitelist_details",
    .handler = vl_api_acl_interface_etype_whitelist_details_t_handler,
    .endian = vl_api_acl_interface_etype_whitelist_details_t_endian,
    .format_fn = vl_api_acl_interface_etype_whitelist_details_t_format,
    .size = sizeof(vl_api_acl_interface_etype_whitelist_details_t),
    .traced = 1,
    .tojson = vl_api_acl_interface_etype_whitelist_details_t_tojson,
    .fromjson = vl_api_acl_interface_etype_whitelist_details_t_fromjson,
    .calc_size = vl_api_acl_interface_etype_whitelist_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "acl_interface_etype_whitelist_dump", api_acl_interface_etype_whitelist_dump);
   hash_set_mem (vam->help_by_name, "acl_interface_etype_whitelist_dump", "[<intfc> | sw_if_index <if-idx>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ACL_STATS_INTF_COUNTERS_ENABLE_REPLY + msg_id_base,
    .name = "acl_stats_intf_counters_enable_reply",
    .handler = vl_api_acl_stats_intf_counters_enable_reply_t_handler,
    .endian = vl_api_acl_stats_intf_counters_enable_reply_t_endian,
    .format_fn = vl_api_acl_stats_intf_counters_enable_reply_t_format,
    .size = sizeof(vl_api_acl_stats_intf_counters_enable_reply_t),
    .traced = 1,
    .tojson = vl_api_acl_stats_intf_counters_enable_reply_t_tojson,
    .fromjson = vl_api_acl_stats_intf_counters_enable_reply_t_fromjson,
    .calc_size = vl_api_acl_stats_intf_counters_enable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "acl_stats_intf_counters_enable", api_acl_stats_intf_counters_enable);
   hash_set_mem (vam->help_by_name, "acl_stats_intf_counters_enable", "[disable]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_SET_REPLY + msg_id_base,
    .name = "acl_plugin_use_hash_lookup_set_reply",
    .handler = vl_api_acl_plugin_use_hash_lookup_set_reply_t_handler,
    .endian = vl_api_acl_plugin_use_hash_lookup_set_reply_t_endian,
    .format_fn = vl_api_acl_plugin_use_hash_lookup_set_reply_t_format,
    .size = sizeof(vl_api_acl_plugin_use_hash_lookup_set_reply_t),
    .traced = 1,
    .tojson = vl_api_acl_plugin_use_hash_lookup_set_reply_t_tojson,
    .fromjson = vl_api_acl_plugin_use_hash_lookup_set_reply_t_fromjson,
    .calc_size = vl_api_acl_plugin_use_hash_lookup_set_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "acl_plugin_use_hash_lookup_set", api_acl_plugin_use_hash_lookup_set);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_GET_REPLY + msg_id_base,
    .name = "acl_plugin_use_hash_lookup_get_reply",
    .handler = vl_api_acl_plugin_use_hash_lookup_get_reply_t_handler,
    .endian = vl_api_acl_plugin_use_hash_lookup_get_reply_t_endian,
    .format_fn = vl_api_acl_plugin_use_hash_lookup_get_reply_t_format,
    .size = sizeof(vl_api_acl_plugin_use_hash_lookup_get_reply_t),
    .traced = 1,
    .tojson = vl_api_acl_plugin_use_hash_lookup_get_reply_t_tojson,
    .fromjson = vl_api_acl_plugin_use_hash_lookup_get_reply_t_fromjson,
    .calc_size = vl_api_acl_plugin_use_hash_lookup_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "acl_plugin_use_hash_lookup_get", api_acl_plugin_use_hash_lookup_get);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   acl_test_main_t * mainp = &acl_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("acl_9cde599d");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "acl plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
