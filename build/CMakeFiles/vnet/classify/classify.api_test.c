#define vl_endianfun            /* define message structures */
#include "classify.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "classify.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "classify.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_classify_add_del_table_reply_t_handler()) */
#ifndef VL_API_CLASSIFY_ADD_DEL_SESSION_REPLY_T_HANDLER
static void
vl_api_classify_add_del_session_reply_t_handler (vl_api_classify_add_del_session_reply_t * mp) {
   vat_main_t * vam = classify_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_POLICER_CLASSIFY_SET_INTERFACE_REPLY_T_HANDLER
static void
vl_api_policer_classify_set_interface_reply_t_handler (vl_api_policer_classify_set_interface_reply_t * mp) {
   vat_main_t * vam = classify_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_policer_classify_details_t_handler()) */
/* Generation not supported (vl_api_classify_table_ids_reply_t_handler()) */
/* Generation not supported (vl_api_classify_table_by_interface_reply_t_handler()) */
/* Generation not supported (vl_api_classify_table_info_reply_t_handler()) */
/* Generation not supported (vl_api_classify_session_details_t_handler()) */
#ifndef VL_API_FLOW_CLASSIFY_SET_INTERFACE_REPLY_T_HANDLER
static void
vl_api_flow_classify_set_interface_reply_t_handler (vl_api_flow_classify_set_interface_reply_t * mp) {
   vat_main_t * vam = classify_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_flow_classify_details_t_handler()) */
#ifndef VL_API_CLASSIFY_SET_INTERFACE_IP_TABLE_REPLY_T_HANDLER
static void
vl_api_classify_set_interface_ip_table_reply_t_handler (vl_api_classify_set_interface_ip_table_reply_t * mp) {
   vat_main_t * vam = classify_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_CLASSIFY_SET_INTERFACE_L2_TABLES_REPLY_T_HANDLER
static void
vl_api_classify_set_interface_l2_tables_reply_t_handler (vl_api_classify_set_interface_l2_tables_reply_t * mp) {
   vat_main_t * vam = classify_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_INPUT_ACL_SET_INTERFACE_REPLY_T_HANDLER
static void
vl_api_input_acl_set_interface_reply_t_handler (vl_api_input_acl_set_interface_reply_t * mp) {
   vat_main_t * vam = classify_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_PUNT_ACL_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_punt_acl_add_del_reply_t_handler (vl_api_punt_acl_add_del_reply_t * mp) {
   vat_main_t * vam = classify_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_punt_acl_get_reply_t_handler()) */
#ifndef VL_API_OUTPUT_ACL_SET_INTERFACE_REPLY_T_HANDLER
static void
vl_api_output_acl_set_interface_reply_t_handler (vl_api_output_acl_set_interface_reply_t * mp) {
   vat_main_t * vam = classify_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_classify_pcap_lookup_table_reply_t_handler()) */
/* Generation not supported (vl_api_classify_pcap_set_table_reply_t_handler()) */
/* Generation not supported (vl_api_classify_pcap_get_tables_reply_t_handler()) */
/* Generation not supported (vl_api_classify_trace_lookup_table_reply_t_handler()) */
/* Generation not supported (vl_api_classify_trace_set_table_reply_t_handler()) */
/* Generation not supported (vl_api_classify_trace_get_tables_reply_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CLASSIFY_ADD_DEL_TABLE_REPLY + msg_id_base,
    .name = "classify_add_del_table_reply",
    .handler = vl_api_classify_add_del_table_reply_t_handler,
    .endian = vl_api_classify_add_del_table_reply_t_endian,
    .format_fn = vl_api_classify_add_del_table_reply_t_format,
    .size = sizeof(vl_api_classify_add_del_table_reply_t),
    .traced = 1,
    .tojson = vl_api_classify_add_del_table_reply_t_tojson,
    .fromjson = vl_api_classify_add_del_table_reply_t_fromjson,
    .calc_size = vl_api_classify_add_del_table_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "classify_add_del_table", api_classify_add_del_table);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CLASSIFY_ADD_DEL_SESSION_REPLY + msg_id_base,
    .name = "classify_add_del_session_reply",
    .handler = vl_api_classify_add_del_session_reply_t_handler,
    .endian = vl_api_classify_add_del_session_reply_t_endian,
    .format_fn = vl_api_classify_add_del_session_reply_t_format,
    .size = sizeof(vl_api_classify_add_del_session_reply_t),
    .traced = 1,
    .tojson = vl_api_classify_add_del_session_reply_t_tojson,
    .fromjson = vl_api_classify_add_del_session_reply_t_fromjson,
    .calc_size = vl_api_classify_add_del_session_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "classify_add_del_session", api_classify_add_del_session);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_POLICER_CLASSIFY_SET_INTERFACE_REPLY + msg_id_base,
    .name = "policer_classify_set_interface_reply",
    .handler = vl_api_policer_classify_set_interface_reply_t_handler,
    .endian = vl_api_policer_classify_set_interface_reply_t_endian,
    .format_fn = vl_api_policer_classify_set_interface_reply_t_format,
    .size = sizeof(vl_api_policer_classify_set_interface_reply_t),
    .traced = 1,
    .tojson = vl_api_policer_classify_set_interface_reply_t_tojson,
    .fromjson = vl_api_policer_classify_set_interface_reply_t_fromjson,
    .calc_size = vl_api_policer_classify_set_interface_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "policer_classify_set_interface", api_policer_classify_set_interface);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_POLICER_CLASSIFY_DETAILS + msg_id_base,
    .name = "policer_classify_details",
    .handler = vl_api_policer_classify_details_t_handler,
    .endian = vl_api_policer_classify_details_t_endian,
    .format_fn = vl_api_policer_classify_details_t_format,
    .size = sizeof(vl_api_policer_classify_details_t),
    .traced = 1,
    .tojson = vl_api_policer_classify_details_t_tojson,
    .fromjson = vl_api_policer_classify_details_t_fromjson,
    .calc_size = vl_api_policer_classify_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "policer_classify_dump", api_policer_classify_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CLASSIFY_TABLE_IDS_REPLY + msg_id_base,
    .name = "classify_table_ids_reply",
    .handler = vl_api_classify_table_ids_reply_t_handler,
    .endian = vl_api_classify_table_ids_reply_t_endian,
    .format_fn = vl_api_classify_table_ids_reply_t_format,
    .size = sizeof(vl_api_classify_table_ids_reply_t),
    .traced = 1,
    .tojson = vl_api_classify_table_ids_reply_t_tojson,
    .fromjson = vl_api_classify_table_ids_reply_t_fromjson,
    .calc_size = vl_api_classify_table_ids_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "classify_table_ids", api_classify_table_ids);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CLASSIFY_TABLE_BY_INTERFACE_REPLY + msg_id_base,
    .name = "classify_table_by_interface_reply",
    .handler = vl_api_classify_table_by_interface_reply_t_handler,
    .endian = vl_api_classify_table_by_interface_reply_t_endian,
    .format_fn = vl_api_classify_table_by_interface_reply_t_format,
    .size = sizeof(vl_api_classify_table_by_interface_reply_t),
    .traced = 1,
    .tojson = vl_api_classify_table_by_interface_reply_t_tojson,
    .fromjson = vl_api_classify_table_by_interface_reply_t_fromjson,
    .calc_size = vl_api_classify_table_by_interface_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "classify_table_by_interface", api_classify_table_by_interface);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CLASSIFY_TABLE_INFO_REPLY + msg_id_base,
    .name = "classify_table_info_reply",
    .handler = vl_api_classify_table_info_reply_t_handler,
    .endian = vl_api_classify_table_info_reply_t_endian,
    .format_fn = vl_api_classify_table_info_reply_t_format,
    .size = sizeof(vl_api_classify_table_info_reply_t),
    .traced = 1,
    .tojson = vl_api_classify_table_info_reply_t_tojson,
    .fromjson = vl_api_classify_table_info_reply_t_fromjson,
    .calc_size = vl_api_classify_table_info_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "classify_table_info", api_classify_table_info);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CLASSIFY_SESSION_DETAILS + msg_id_base,
    .name = "classify_session_details",
    .handler = vl_api_classify_session_details_t_handler,
    .endian = vl_api_classify_session_details_t_endian,
    .format_fn = vl_api_classify_session_details_t_format,
    .size = sizeof(vl_api_classify_session_details_t),
    .traced = 1,
    .tojson = vl_api_classify_session_details_t_tojson,
    .fromjson = vl_api_classify_session_details_t_fromjson,
    .calc_size = vl_api_classify_session_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "classify_session_dump", api_classify_session_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_FLOW_CLASSIFY_SET_INTERFACE_REPLY + msg_id_base,
    .name = "flow_classify_set_interface_reply",
    .handler = vl_api_flow_classify_set_interface_reply_t_handler,
    .endian = vl_api_flow_classify_set_interface_reply_t_endian,
    .format_fn = vl_api_flow_classify_set_interface_reply_t_format,
    .size = sizeof(vl_api_flow_classify_set_interface_reply_t),
    .traced = 1,
    .tojson = vl_api_flow_classify_set_interface_reply_t_tojson,
    .fromjson = vl_api_flow_classify_set_interface_reply_t_fromjson,
    .calc_size = vl_api_flow_classify_set_interface_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "flow_classify_set_interface", api_flow_classify_set_interface);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_FLOW_CLASSIFY_DETAILS + msg_id_base,
    .name = "flow_classify_details",
    .handler = vl_api_flow_classify_details_t_handler,
    .endian = vl_api_flow_classify_details_t_endian,
    .format_fn = vl_api_flow_classify_details_t_format,
    .size = sizeof(vl_api_flow_classify_details_t),
    .traced = 1,
    .tojson = vl_api_flow_classify_details_t_tojson,
    .fromjson = vl_api_flow_classify_details_t_fromjson,
    .calc_size = vl_api_flow_classify_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "flow_classify_dump", api_flow_classify_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CLASSIFY_SET_INTERFACE_IP_TABLE_REPLY + msg_id_base,
    .name = "classify_set_interface_ip_table_reply",
    .handler = vl_api_classify_set_interface_ip_table_reply_t_handler,
    .endian = vl_api_classify_set_interface_ip_table_reply_t_endian,
    .format_fn = vl_api_classify_set_interface_ip_table_reply_t_format,
    .size = sizeof(vl_api_classify_set_interface_ip_table_reply_t),
    .traced = 1,
    .tojson = vl_api_classify_set_interface_ip_table_reply_t_tojson,
    .fromjson = vl_api_classify_set_interface_ip_table_reply_t_fromjson,
    .calc_size = vl_api_classify_set_interface_ip_table_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "classify_set_interface_ip_table", api_classify_set_interface_ip_table);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CLASSIFY_SET_INTERFACE_L2_TABLES_REPLY + msg_id_base,
    .name = "classify_set_interface_l2_tables_reply",
    .handler = vl_api_classify_set_interface_l2_tables_reply_t_handler,
    .endian = vl_api_classify_set_interface_l2_tables_reply_t_endian,
    .format_fn = vl_api_classify_set_interface_l2_tables_reply_t_format,
    .size = sizeof(vl_api_classify_set_interface_l2_tables_reply_t),
    .traced = 1,
    .tojson = vl_api_classify_set_interface_l2_tables_reply_t_tojson,
    .fromjson = vl_api_classify_set_interface_l2_tables_reply_t_fromjson,
    .calc_size = vl_api_classify_set_interface_l2_tables_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "classify_set_interface_l2_tables", api_classify_set_interface_l2_tables);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_INPUT_ACL_SET_INTERFACE_REPLY + msg_id_base,
    .name = "input_acl_set_interface_reply",
    .handler = vl_api_input_acl_set_interface_reply_t_handler,
    .endian = vl_api_input_acl_set_interface_reply_t_endian,
    .format_fn = vl_api_input_acl_set_interface_reply_t_format,
    .size = sizeof(vl_api_input_acl_set_interface_reply_t),
    .traced = 1,
    .tojson = vl_api_input_acl_set_interface_reply_t_tojson,
    .fromjson = vl_api_input_acl_set_interface_reply_t_fromjson,
    .calc_size = vl_api_input_acl_set_interface_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "input_acl_set_interface", api_input_acl_set_interface);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PUNT_ACL_ADD_DEL_REPLY + msg_id_base,
    .name = "punt_acl_add_del_reply",
    .handler = vl_api_punt_acl_add_del_reply_t_handler,
    .endian = vl_api_punt_acl_add_del_reply_t_endian,
    .format_fn = vl_api_punt_acl_add_del_reply_t_format,
    .size = sizeof(vl_api_punt_acl_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_punt_acl_add_del_reply_t_tojson,
    .fromjson = vl_api_punt_acl_add_del_reply_t_fromjson,
    .calc_size = vl_api_punt_acl_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "punt_acl_add_del", api_punt_acl_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PUNT_ACL_GET_REPLY + msg_id_base,
    .name = "punt_acl_get_reply",
    .handler = vl_api_punt_acl_get_reply_t_handler,
    .endian = vl_api_punt_acl_get_reply_t_endian,
    .format_fn = vl_api_punt_acl_get_reply_t_format,
    .size = sizeof(vl_api_punt_acl_get_reply_t),
    .traced = 1,
    .tojson = vl_api_punt_acl_get_reply_t_tojson,
    .fromjson = vl_api_punt_acl_get_reply_t_fromjson,
    .calc_size = vl_api_punt_acl_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "punt_acl_get", api_punt_acl_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_OUTPUT_ACL_SET_INTERFACE_REPLY + msg_id_base,
    .name = "output_acl_set_interface_reply",
    .handler = vl_api_output_acl_set_interface_reply_t_handler,
    .endian = vl_api_output_acl_set_interface_reply_t_endian,
    .format_fn = vl_api_output_acl_set_interface_reply_t_format,
    .size = sizeof(vl_api_output_acl_set_interface_reply_t),
    .traced = 1,
    .tojson = vl_api_output_acl_set_interface_reply_t_tojson,
    .fromjson = vl_api_output_acl_set_interface_reply_t_fromjson,
    .calc_size = vl_api_output_acl_set_interface_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "output_acl_set_interface", api_output_acl_set_interface);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CLASSIFY_PCAP_LOOKUP_TABLE_REPLY + msg_id_base,
    .name = "classify_pcap_lookup_table_reply",
    .handler = vl_api_classify_pcap_lookup_table_reply_t_handler,
    .endian = vl_api_classify_pcap_lookup_table_reply_t_endian,
    .format_fn = vl_api_classify_pcap_lookup_table_reply_t_format,
    .size = sizeof(vl_api_classify_pcap_lookup_table_reply_t),
    .traced = 1,
    .tojson = vl_api_classify_pcap_lookup_table_reply_t_tojson,
    .fromjson = vl_api_classify_pcap_lookup_table_reply_t_fromjson,
    .calc_size = vl_api_classify_pcap_lookup_table_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "classify_pcap_lookup_table", api_classify_pcap_lookup_table);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CLASSIFY_PCAP_SET_TABLE_REPLY + msg_id_base,
    .name = "classify_pcap_set_table_reply",
    .handler = vl_api_classify_pcap_set_table_reply_t_handler,
    .endian = vl_api_classify_pcap_set_table_reply_t_endian,
    .format_fn = vl_api_classify_pcap_set_table_reply_t_format,
    .size = sizeof(vl_api_classify_pcap_set_table_reply_t),
    .traced = 1,
    .tojson = vl_api_classify_pcap_set_table_reply_t_tojson,
    .fromjson = vl_api_classify_pcap_set_table_reply_t_fromjson,
    .calc_size = vl_api_classify_pcap_set_table_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "classify_pcap_set_table", api_classify_pcap_set_table);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CLASSIFY_PCAP_GET_TABLES_REPLY + msg_id_base,
    .name = "classify_pcap_get_tables_reply",
    .handler = vl_api_classify_pcap_get_tables_reply_t_handler,
    .endian = vl_api_classify_pcap_get_tables_reply_t_endian,
    .format_fn = vl_api_classify_pcap_get_tables_reply_t_format,
    .size = sizeof(vl_api_classify_pcap_get_tables_reply_t),
    .traced = 1,
    .tojson = vl_api_classify_pcap_get_tables_reply_t_tojson,
    .fromjson = vl_api_classify_pcap_get_tables_reply_t_fromjson,
    .calc_size = vl_api_classify_pcap_get_tables_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "classify_pcap_get_tables", api_classify_pcap_get_tables);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CLASSIFY_TRACE_LOOKUP_TABLE_REPLY + msg_id_base,
    .name = "classify_trace_lookup_table_reply",
    .handler = vl_api_classify_trace_lookup_table_reply_t_handler,
    .endian = vl_api_classify_trace_lookup_table_reply_t_endian,
    .format_fn = vl_api_classify_trace_lookup_table_reply_t_format,
    .size = sizeof(vl_api_classify_trace_lookup_table_reply_t),
    .traced = 1,
    .tojson = vl_api_classify_trace_lookup_table_reply_t_tojson,
    .fromjson = vl_api_classify_trace_lookup_table_reply_t_fromjson,
    .calc_size = vl_api_classify_trace_lookup_table_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "classify_trace_lookup_table", api_classify_trace_lookup_table);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CLASSIFY_TRACE_SET_TABLE_REPLY + msg_id_base,
    .name = "classify_trace_set_table_reply",
    .handler = vl_api_classify_trace_set_table_reply_t_handler,
    .endian = vl_api_classify_trace_set_table_reply_t_endian,
    .format_fn = vl_api_classify_trace_set_table_reply_t_format,
    .size = sizeof(vl_api_classify_trace_set_table_reply_t),
    .traced = 1,
    .tojson = vl_api_classify_trace_set_table_reply_t_tojson,
    .fromjson = vl_api_classify_trace_set_table_reply_t_fromjson,
    .calc_size = vl_api_classify_trace_set_table_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "classify_trace_set_table", api_classify_trace_set_table);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CLASSIFY_TRACE_GET_TABLES_REPLY + msg_id_base,
    .name = "classify_trace_get_tables_reply",
    .handler = vl_api_classify_trace_get_tables_reply_t_handler,
    .endian = vl_api_classify_trace_get_tables_reply_t_endian,
    .format_fn = vl_api_classify_trace_get_tables_reply_t_format,
    .size = sizeof(vl_api_classify_trace_get_tables_reply_t),
    .traced = 1,
    .tojson = vl_api_classify_trace_get_tables_reply_t_tojson,
    .fromjson = vl_api_classify_trace_get_tables_reply_t_fromjson,
    .calc_size = vl_api_classify_trace_get_tables_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "classify_trace_get_tables", api_classify_trace_get_tables);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   classify_test_main_t * mainp = &classify_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("classify_fdc06ac8");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "classify plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
