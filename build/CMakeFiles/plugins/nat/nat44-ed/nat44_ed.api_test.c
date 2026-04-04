#define vl_endianfun            /* define message structures */
#include "nat44_ed.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "nat44_ed.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "nat44_ed.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_nat44_ed_output_interface_get_reply_t_handler()) */
#ifndef VL_API_NAT44_ED_PLUGIN_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_nat44_ed_plugin_enable_disable_reply_t_handler (vl_api_nat44_ed_plugin_enable_disable_reply_t * mp) {
   vat_main_t * vam = nat44_ed_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NAT44_FORWARDING_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_nat44_forwarding_enable_disable_reply_t_handler (vl_api_nat44_forwarding_enable_disable_reply_t * mp) {
   vat_main_t * vam = nat44_ed_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NAT_IPFIX_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_nat_ipfix_enable_disable_reply_t_handler (vl_api_nat_ipfix_enable_disable_reply_t * mp) {
   vat_main_t * vam = nat44_ed_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NAT_SET_TIMEOUTS_REPLY_T_HANDLER
static void
vl_api_nat_set_timeouts_reply_t_handler (vl_api_nat_set_timeouts_reply_t * mp) {
   vat_main_t * vam = nat44_ed_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NAT44_SET_SESSION_LIMIT_REPLY_T_HANDLER
static void
vl_api_nat44_set_session_limit_reply_t_handler (vl_api_nat44_set_session_limit_reply_t * mp) {
   vat_main_t * vam = nat44_ed_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_show_running_config_reply_t_handler()) */
#ifndef VL_API_NAT_SET_WORKERS_REPLY_T_HANDLER
static void
vl_api_nat_set_workers_reply_t_handler (vl_api_nat_set_workers_reply_t * mp) {
   vat_main_t * vam = nat44_ed_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat_worker_details_t_handler()) */
#ifndef VL_API_NAT44_ED_ADD_DEL_VRF_TABLE_REPLY_T_HANDLER
static void
vl_api_nat44_ed_add_del_vrf_table_reply_t_handler (vl_api_nat44_ed_add_del_vrf_table_reply_t * mp) {
   vat_main_t * vam = nat44_ed_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NAT44_ED_ADD_DEL_VRF_ROUTE_REPLY_T_HANDLER
static void
vl_api_nat44_ed_add_del_vrf_route_reply_t_handler (vl_api_nat44_ed_add_del_vrf_route_reply_t * mp) {
   vat_main_t * vam = nat44_ed_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_ed_vrf_tables_details_t_handler()) */
/* Generation not supported (vl_api_nat44_ed_vrf_tables_v2_details_t_handler()) */
#ifndef VL_API_NAT_SET_MSS_CLAMPING_REPLY_T_HANDLER
static void
vl_api_nat_set_mss_clamping_reply_t_handler (vl_api_nat_set_mss_clamping_reply_t * mp) {
   vat_main_t * vam = nat44_ed_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat_get_mss_clamping_reply_t_handler()) */
#ifndef VL_API_NAT44_ED_SET_FQ_OPTIONS_REPLY_T_HANDLER
static void
vl_api_nat44_ed_set_fq_options_reply_t_handler (vl_api_nat44_ed_set_fq_options_reply_t * mp) {
   vat_main_t * vam = nat44_ed_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_ed_show_fq_options_reply_t_handler()) */
#ifndef VL_API_NAT44_ADD_DEL_INTERFACE_ADDR_REPLY_T_HANDLER
static void
vl_api_nat44_add_del_interface_addr_reply_t_handler (vl_api_nat44_add_del_interface_addr_reply_t * mp) {
   vat_main_t * vam = nat44_ed_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_interface_addr_details_t_handler()) */
#ifndef VL_API_NAT44_ADD_DEL_ADDRESS_RANGE_REPLY_T_HANDLER
static void
vl_api_nat44_add_del_address_range_reply_t_handler (vl_api_nat44_add_del_address_range_reply_t * mp) {
   vat_main_t * vam = nat44_ed_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_address_details_t_handler()) */
#ifndef VL_API_NAT44_INTERFACE_ADD_DEL_FEATURE_REPLY_T_HANDLER
static void
vl_api_nat44_interface_add_del_feature_reply_t_handler (vl_api_nat44_interface_add_del_feature_reply_t * mp) {
   vat_main_t * vam = nat44_ed_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_interface_details_t_handler()) */
#ifndef VL_API_NAT44_ED_ADD_DEL_OUTPUT_INTERFACE_REPLY_T_HANDLER
static void
vl_api_nat44_ed_add_del_output_interface_reply_t_handler (vl_api_nat44_ed_add_del_output_interface_reply_t * mp) {
   vat_main_t * vam = nat44_ed_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NAT44_ADD_DEL_STATIC_MAPPING_REPLY_T_HANDLER
static void
vl_api_nat44_add_del_static_mapping_reply_t_handler (vl_api_nat44_add_del_static_mapping_reply_t * mp) {
   vat_main_t * vam = nat44_ed_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NAT44_ADD_DEL_STATIC_MAPPING_V2_REPLY_T_HANDLER
static void
vl_api_nat44_add_del_static_mapping_v2_reply_t_handler (vl_api_nat44_add_del_static_mapping_v2_reply_t * mp) {
   vat_main_t * vam = nat44_ed_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_static_mapping_details_t_handler()) */
#ifndef VL_API_NAT44_ADD_DEL_IDENTITY_MAPPING_REPLY_T_HANDLER
static void
vl_api_nat44_add_del_identity_mapping_reply_t_handler (vl_api_nat44_add_del_identity_mapping_reply_t * mp) {
   vat_main_t * vam = nat44_ed_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_identity_mapping_details_t_handler()) */
#ifndef VL_API_NAT44_ADD_DEL_LB_STATIC_MAPPING_REPLY_T_HANDLER
static void
vl_api_nat44_add_del_lb_static_mapping_reply_t_handler (vl_api_nat44_add_del_lb_static_mapping_reply_t * mp) {
   vat_main_t * vam = nat44_ed_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NAT44_LB_STATIC_MAPPING_ADD_DEL_LOCAL_REPLY_T_HANDLER
static void
vl_api_nat44_lb_static_mapping_add_del_local_reply_t_handler (vl_api_nat44_lb_static_mapping_add_del_local_reply_t * mp) {
   vat_main_t * vam = nat44_ed_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_lb_static_mapping_details_t_handler()) */
#ifndef VL_API_NAT44_DEL_SESSION_REPLY_T_HANDLER
static void
vl_api_nat44_del_session_reply_t_handler (vl_api_nat44_del_session_reply_t * mp) {
   vat_main_t * vam = nat44_ed_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_user_details_t_handler()) */
/* Generation not supported (vl_api_nat44_user_session_details_t_handler()) */
/* Generation not supported (vl_api_nat44_user_session_v2_details_t_handler()) */
/* Generation not supported (vl_api_nat44_user_session_v3_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_ED_OUTPUT_INTERFACE_GET_REPLY + msg_id_base,
    .name = "nat44_ed_output_interface_get_reply",
    .handler = vl_api_nat44_ed_output_interface_get_reply_t_handler,
    .endian = vl_api_nat44_ed_output_interface_get_reply_t_endian,
    .format_fn = vl_api_nat44_ed_output_interface_get_reply_t_format,
    .size = sizeof(vl_api_nat44_ed_output_interface_get_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ed_output_interface_get_reply_t_tojson,
    .fromjson = vl_api_nat44_ed_output_interface_get_reply_t_fromjson,
    .calc_size = vl_api_nat44_ed_output_interface_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ed_output_interface_get", api_nat44_ed_output_interface_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_ED_PLUGIN_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "nat44_ed_plugin_enable_disable_reply",
    .handler = vl_api_nat44_ed_plugin_enable_disable_reply_t_handler,
    .endian = vl_api_nat44_ed_plugin_enable_disable_reply_t_endian,
    .format_fn = vl_api_nat44_ed_plugin_enable_disable_reply_t_format,
    .size = sizeof(vl_api_nat44_ed_plugin_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ed_plugin_enable_disable_reply_t_tojson,
    .fromjson = vl_api_nat44_ed_plugin_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_nat44_ed_plugin_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ed_plugin_enable_disable", api_nat44_ed_plugin_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_FORWARDING_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "nat44_forwarding_enable_disable_reply",
    .handler = vl_api_nat44_forwarding_enable_disable_reply_t_handler,
    .endian = vl_api_nat44_forwarding_enable_disable_reply_t_endian,
    .format_fn = vl_api_nat44_forwarding_enable_disable_reply_t_format,
    .size = sizeof(vl_api_nat44_forwarding_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_forwarding_enable_disable_reply_t_tojson,
    .fromjson = vl_api_nat44_forwarding_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_nat44_forwarding_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_forwarding_enable_disable", api_nat44_forwarding_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT_IPFIX_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "nat_ipfix_enable_disable_reply",
    .handler = vl_api_nat_ipfix_enable_disable_reply_t_handler,
    .endian = vl_api_nat_ipfix_enable_disable_reply_t_endian,
    .format_fn = vl_api_nat_ipfix_enable_disable_reply_t_format,
    .size = sizeof(vl_api_nat_ipfix_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_nat_ipfix_enable_disable_reply_t_tojson,
    .fromjson = vl_api_nat_ipfix_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_nat_ipfix_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat_ipfix_enable_disable", api_nat_ipfix_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT_SET_TIMEOUTS_REPLY + msg_id_base,
    .name = "nat_set_timeouts_reply",
    .handler = vl_api_nat_set_timeouts_reply_t_handler,
    .endian = vl_api_nat_set_timeouts_reply_t_endian,
    .format_fn = vl_api_nat_set_timeouts_reply_t_format,
    .size = sizeof(vl_api_nat_set_timeouts_reply_t),
    .traced = 1,
    .tojson = vl_api_nat_set_timeouts_reply_t_tojson,
    .fromjson = vl_api_nat_set_timeouts_reply_t_fromjson,
    .calc_size = vl_api_nat_set_timeouts_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat_set_timeouts", api_nat_set_timeouts);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_SET_SESSION_LIMIT_REPLY + msg_id_base,
    .name = "nat44_set_session_limit_reply",
    .handler = vl_api_nat44_set_session_limit_reply_t_handler,
    .endian = vl_api_nat44_set_session_limit_reply_t_endian,
    .format_fn = vl_api_nat44_set_session_limit_reply_t_format,
    .size = sizeof(vl_api_nat44_set_session_limit_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_set_session_limit_reply_t_tojson,
    .fromjson = vl_api_nat44_set_session_limit_reply_t_fromjson,
    .calc_size = vl_api_nat44_set_session_limit_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_set_session_limit", api_nat44_set_session_limit);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_SHOW_RUNNING_CONFIG_REPLY + msg_id_base,
    .name = "nat44_show_running_config_reply",
    .handler = vl_api_nat44_show_running_config_reply_t_handler,
    .endian = vl_api_nat44_show_running_config_reply_t_endian,
    .format_fn = vl_api_nat44_show_running_config_reply_t_format,
    .size = sizeof(vl_api_nat44_show_running_config_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_show_running_config_reply_t_tojson,
    .fromjson = vl_api_nat44_show_running_config_reply_t_fromjson,
    .calc_size = vl_api_nat44_show_running_config_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_show_running_config", api_nat44_show_running_config);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT_SET_WORKERS_REPLY + msg_id_base,
    .name = "nat_set_workers_reply",
    .handler = vl_api_nat_set_workers_reply_t_handler,
    .endian = vl_api_nat_set_workers_reply_t_endian,
    .format_fn = vl_api_nat_set_workers_reply_t_format,
    .size = sizeof(vl_api_nat_set_workers_reply_t),
    .traced = 1,
    .tojson = vl_api_nat_set_workers_reply_t_tojson,
    .fromjson = vl_api_nat_set_workers_reply_t_fromjson,
    .calc_size = vl_api_nat_set_workers_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat_set_workers", api_nat_set_workers);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT_WORKER_DETAILS + msg_id_base,
    .name = "nat_worker_details",
    .handler = vl_api_nat_worker_details_t_handler,
    .endian = vl_api_nat_worker_details_t_endian,
    .format_fn = vl_api_nat_worker_details_t_format,
    .size = sizeof(vl_api_nat_worker_details_t),
    .traced = 1,
    .tojson = vl_api_nat_worker_details_t_tojson,
    .fromjson = vl_api_nat_worker_details_t_fromjson,
    .calc_size = vl_api_nat_worker_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat_worker_dump", api_nat_worker_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_ED_ADD_DEL_VRF_TABLE_REPLY + msg_id_base,
    .name = "nat44_ed_add_del_vrf_table_reply",
    .handler = vl_api_nat44_ed_add_del_vrf_table_reply_t_handler,
    .endian = vl_api_nat44_ed_add_del_vrf_table_reply_t_endian,
    .format_fn = vl_api_nat44_ed_add_del_vrf_table_reply_t_format,
    .size = sizeof(vl_api_nat44_ed_add_del_vrf_table_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ed_add_del_vrf_table_reply_t_tojson,
    .fromjson = vl_api_nat44_ed_add_del_vrf_table_reply_t_fromjson,
    .calc_size = vl_api_nat44_ed_add_del_vrf_table_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ed_add_del_vrf_table", api_nat44_ed_add_del_vrf_table);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_ED_ADD_DEL_VRF_ROUTE_REPLY + msg_id_base,
    .name = "nat44_ed_add_del_vrf_route_reply",
    .handler = vl_api_nat44_ed_add_del_vrf_route_reply_t_handler,
    .endian = vl_api_nat44_ed_add_del_vrf_route_reply_t_endian,
    .format_fn = vl_api_nat44_ed_add_del_vrf_route_reply_t_format,
    .size = sizeof(vl_api_nat44_ed_add_del_vrf_route_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ed_add_del_vrf_route_reply_t_tojson,
    .fromjson = vl_api_nat44_ed_add_del_vrf_route_reply_t_fromjson,
    .calc_size = vl_api_nat44_ed_add_del_vrf_route_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ed_add_del_vrf_route", api_nat44_ed_add_del_vrf_route);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_ED_VRF_TABLES_DETAILS + msg_id_base,
    .name = "nat44_ed_vrf_tables_details",
    .handler = vl_api_nat44_ed_vrf_tables_details_t_handler,
    .endian = vl_api_nat44_ed_vrf_tables_details_t_endian,
    .format_fn = vl_api_nat44_ed_vrf_tables_details_t_format,
    .size = sizeof(vl_api_nat44_ed_vrf_tables_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_ed_vrf_tables_details_t_tojson,
    .fromjson = vl_api_nat44_ed_vrf_tables_details_t_fromjson,
    .calc_size = vl_api_nat44_ed_vrf_tables_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ed_vrf_tables_dump", api_nat44_ed_vrf_tables_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_ED_VRF_TABLES_V2_DETAILS + msg_id_base,
    .name = "nat44_ed_vrf_tables_v2_details",
    .handler = vl_api_nat44_ed_vrf_tables_v2_details_t_handler,
    .endian = vl_api_nat44_ed_vrf_tables_v2_details_t_endian,
    .format_fn = vl_api_nat44_ed_vrf_tables_v2_details_t_format,
    .size = sizeof(vl_api_nat44_ed_vrf_tables_v2_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_ed_vrf_tables_v2_details_t_tojson,
    .fromjson = vl_api_nat44_ed_vrf_tables_v2_details_t_fromjson,
    .calc_size = vl_api_nat44_ed_vrf_tables_v2_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ed_vrf_tables_v2_dump", api_nat44_ed_vrf_tables_v2_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT_SET_MSS_CLAMPING_REPLY + msg_id_base,
    .name = "nat_set_mss_clamping_reply",
    .handler = vl_api_nat_set_mss_clamping_reply_t_handler,
    .endian = vl_api_nat_set_mss_clamping_reply_t_endian,
    .format_fn = vl_api_nat_set_mss_clamping_reply_t_format,
    .size = sizeof(vl_api_nat_set_mss_clamping_reply_t),
    .traced = 1,
    .tojson = vl_api_nat_set_mss_clamping_reply_t_tojson,
    .fromjson = vl_api_nat_set_mss_clamping_reply_t_fromjson,
    .calc_size = vl_api_nat_set_mss_clamping_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat_set_mss_clamping", api_nat_set_mss_clamping);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT_GET_MSS_CLAMPING_REPLY + msg_id_base,
    .name = "nat_get_mss_clamping_reply",
    .handler = vl_api_nat_get_mss_clamping_reply_t_handler,
    .endian = vl_api_nat_get_mss_clamping_reply_t_endian,
    .format_fn = vl_api_nat_get_mss_clamping_reply_t_format,
    .size = sizeof(vl_api_nat_get_mss_clamping_reply_t),
    .traced = 1,
    .tojson = vl_api_nat_get_mss_clamping_reply_t_tojson,
    .fromjson = vl_api_nat_get_mss_clamping_reply_t_fromjson,
    .calc_size = vl_api_nat_get_mss_clamping_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat_get_mss_clamping", api_nat_get_mss_clamping);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_ED_SET_FQ_OPTIONS_REPLY + msg_id_base,
    .name = "nat44_ed_set_fq_options_reply",
    .handler = vl_api_nat44_ed_set_fq_options_reply_t_handler,
    .endian = vl_api_nat44_ed_set_fq_options_reply_t_endian,
    .format_fn = vl_api_nat44_ed_set_fq_options_reply_t_format,
    .size = sizeof(vl_api_nat44_ed_set_fq_options_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ed_set_fq_options_reply_t_tojson,
    .fromjson = vl_api_nat44_ed_set_fq_options_reply_t_fromjson,
    .calc_size = vl_api_nat44_ed_set_fq_options_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ed_set_fq_options", api_nat44_ed_set_fq_options);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_ED_SHOW_FQ_OPTIONS_REPLY + msg_id_base,
    .name = "nat44_ed_show_fq_options_reply",
    .handler = vl_api_nat44_ed_show_fq_options_reply_t_handler,
    .endian = vl_api_nat44_ed_show_fq_options_reply_t_endian,
    .format_fn = vl_api_nat44_ed_show_fq_options_reply_t_format,
    .size = sizeof(vl_api_nat44_ed_show_fq_options_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ed_show_fq_options_reply_t_tojson,
    .fromjson = vl_api_nat44_ed_show_fq_options_reply_t_fromjson,
    .calc_size = vl_api_nat44_ed_show_fq_options_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ed_show_fq_options", api_nat44_ed_show_fq_options);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_ADD_DEL_INTERFACE_ADDR_REPLY + msg_id_base,
    .name = "nat44_add_del_interface_addr_reply",
    .handler = vl_api_nat44_add_del_interface_addr_reply_t_handler,
    .endian = vl_api_nat44_add_del_interface_addr_reply_t_endian,
    .format_fn = vl_api_nat44_add_del_interface_addr_reply_t_format,
    .size = sizeof(vl_api_nat44_add_del_interface_addr_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_add_del_interface_addr_reply_t_tojson,
    .fromjson = vl_api_nat44_add_del_interface_addr_reply_t_fromjson,
    .calc_size = vl_api_nat44_add_del_interface_addr_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_add_del_interface_addr", api_nat44_add_del_interface_addr);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_INTERFACE_ADDR_DETAILS + msg_id_base,
    .name = "nat44_interface_addr_details",
    .handler = vl_api_nat44_interface_addr_details_t_handler,
    .endian = vl_api_nat44_interface_addr_details_t_endian,
    .format_fn = vl_api_nat44_interface_addr_details_t_format,
    .size = sizeof(vl_api_nat44_interface_addr_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_interface_addr_details_t_tojson,
    .fromjson = vl_api_nat44_interface_addr_details_t_fromjson,
    .calc_size = vl_api_nat44_interface_addr_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_interface_addr_dump", api_nat44_interface_addr_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_ADD_DEL_ADDRESS_RANGE_REPLY + msg_id_base,
    .name = "nat44_add_del_address_range_reply",
    .handler = vl_api_nat44_add_del_address_range_reply_t_handler,
    .endian = vl_api_nat44_add_del_address_range_reply_t_endian,
    .format_fn = vl_api_nat44_add_del_address_range_reply_t_format,
    .size = sizeof(vl_api_nat44_add_del_address_range_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_add_del_address_range_reply_t_tojson,
    .fromjson = vl_api_nat44_add_del_address_range_reply_t_fromjson,
    .calc_size = vl_api_nat44_add_del_address_range_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_add_del_address_range", api_nat44_add_del_address_range);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_ADDRESS_DETAILS + msg_id_base,
    .name = "nat44_address_details",
    .handler = vl_api_nat44_address_details_t_handler,
    .endian = vl_api_nat44_address_details_t_endian,
    .format_fn = vl_api_nat44_address_details_t_format,
    .size = sizeof(vl_api_nat44_address_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_address_details_t_tojson,
    .fromjson = vl_api_nat44_address_details_t_fromjson,
    .calc_size = vl_api_nat44_address_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_address_dump", api_nat44_address_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_INTERFACE_ADD_DEL_FEATURE_REPLY + msg_id_base,
    .name = "nat44_interface_add_del_feature_reply",
    .handler = vl_api_nat44_interface_add_del_feature_reply_t_handler,
    .endian = vl_api_nat44_interface_add_del_feature_reply_t_endian,
    .format_fn = vl_api_nat44_interface_add_del_feature_reply_t_format,
    .size = sizeof(vl_api_nat44_interface_add_del_feature_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_interface_add_del_feature_reply_t_tojson,
    .fromjson = vl_api_nat44_interface_add_del_feature_reply_t_fromjson,
    .calc_size = vl_api_nat44_interface_add_del_feature_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_interface_add_del_feature", api_nat44_interface_add_del_feature);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_INTERFACE_DETAILS + msg_id_base,
    .name = "nat44_interface_details",
    .handler = vl_api_nat44_interface_details_t_handler,
    .endian = vl_api_nat44_interface_details_t_endian,
    .format_fn = vl_api_nat44_interface_details_t_format,
    .size = sizeof(vl_api_nat44_interface_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_interface_details_t_tojson,
    .fromjson = vl_api_nat44_interface_details_t_fromjson,
    .calc_size = vl_api_nat44_interface_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_interface_dump", api_nat44_interface_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_ED_ADD_DEL_OUTPUT_INTERFACE_REPLY + msg_id_base,
    .name = "nat44_ed_add_del_output_interface_reply",
    .handler = vl_api_nat44_ed_add_del_output_interface_reply_t_handler,
    .endian = vl_api_nat44_ed_add_del_output_interface_reply_t_endian,
    .format_fn = vl_api_nat44_ed_add_del_output_interface_reply_t_format,
    .size = sizeof(vl_api_nat44_ed_add_del_output_interface_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ed_add_del_output_interface_reply_t_tojson,
    .fromjson = vl_api_nat44_ed_add_del_output_interface_reply_t_fromjson,
    .calc_size = vl_api_nat44_ed_add_del_output_interface_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ed_add_del_output_interface", api_nat44_ed_add_del_output_interface);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_ADD_DEL_STATIC_MAPPING_REPLY + msg_id_base,
    .name = "nat44_add_del_static_mapping_reply",
    .handler = vl_api_nat44_add_del_static_mapping_reply_t_handler,
    .endian = vl_api_nat44_add_del_static_mapping_reply_t_endian,
    .format_fn = vl_api_nat44_add_del_static_mapping_reply_t_format,
    .size = sizeof(vl_api_nat44_add_del_static_mapping_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_add_del_static_mapping_reply_t_tojson,
    .fromjson = vl_api_nat44_add_del_static_mapping_reply_t_fromjson,
    .calc_size = vl_api_nat44_add_del_static_mapping_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_add_del_static_mapping", api_nat44_add_del_static_mapping);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_ADD_DEL_STATIC_MAPPING_V2_REPLY + msg_id_base,
    .name = "nat44_add_del_static_mapping_v2_reply",
    .handler = vl_api_nat44_add_del_static_mapping_v2_reply_t_handler,
    .endian = vl_api_nat44_add_del_static_mapping_v2_reply_t_endian,
    .format_fn = vl_api_nat44_add_del_static_mapping_v2_reply_t_format,
    .size = sizeof(vl_api_nat44_add_del_static_mapping_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_add_del_static_mapping_v2_reply_t_tojson,
    .fromjson = vl_api_nat44_add_del_static_mapping_v2_reply_t_fromjson,
    .calc_size = vl_api_nat44_add_del_static_mapping_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_add_del_static_mapping_v2", api_nat44_add_del_static_mapping_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_STATIC_MAPPING_DETAILS + msg_id_base,
    .name = "nat44_static_mapping_details",
    .handler = vl_api_nat44_static_mapping_details_t_handler,
    .endian = vl_api_nat44_static_mapping_details_t_endian,
    .format_fn = vl_api_nat44_static_mapping_details_t_format,
    .size = sizeof(vl_api_nat44_static_mapping_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_static_mapping_details_t_tojson,
    .fromjson = vl_api_nat44_static_mapping_details_t_fromjson,
    .calc_size = vl_api_nat44_static_mapping_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_static_mapping_dump", api_nat44_static_mapping_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_ADD_DEL_IDENTITY_MAPPING_REPLY + msg_id_base,
    .name = "nat44_add_del_identity_mapping_reply",
    .handler = vl_api_nat44_add_del_identity_mapping_reply_t_handler,
    .endian = vl_api_nat44_add_del_identity_mapping_reply_t_endian,
    .format_fn = vl_api_nat44_add_del_identity_mapping_reply_t_format,
    .size = sizeof(vl_api_nat44_add_del_identity_mapping_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_add_del_identity_mapping_reply_t_tojson,
    .fromjson = vl_api_nat44_add_del_identity_mapping_reply_t_fromjson,
    .calc_size = vl_api_nat44_add_del_identity_mapping_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_add_del_identity_mapping", api_nat44_add_del_identity_mapping);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_IDENTITY_MAPPING_DETAILS + msg_id_base,
    .name = "nat44_identity_mapping_details",
    .handler = vl_api_nat44_identity_mapping_details_t_handler,
    .endian = vl_api_nat44_identity_mapping_details_t_endian,
    .format_fn = vl_api_nat44_identity_mapping_details_t_format,
    .size = sizeof(vl_api_nat44_identity_mapping_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_identity_mapping_details_t_tojson,
    .fromjson = vl_api_nat44_identity_mapping_details_t_fromjson,
    .calc_size = vl_api_nat44_identity_mapping_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_identity_mapping_dump", api_nat44_identity_mapping_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_ADD_DEL_LB_STATIC_MAPPING_REPLY + msg_id_base,
    .name = "nat44_add_del_lb_static_mapping_reply",
    .handler = vl_api_nat44_add_del_lb_static_mapping_reply_t_handler,
    .endian = vl_api_nat44_add_del_lb_static_mapping_reply_t_endian,
    .format_fn = vl_api_nat44_add_del_lb_static_mapping_reply_t_format,
    .size = sizeof(vl_api_nat44_add_del_lb_static_mapping_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_add_del_lb_static_mapping_reply_t_tojson,
    .fromjson = vl_api_nat44_add_del_lb_static_mapping_reply_t_fromjson,
    .calc_size = vl_api_nat44_add_del_lb_static_mapping_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_add_del_lb_static_mapping", api_nat44_add_del_lb_static_mapping);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_LB_STATIC_MAPPING_ADD_DEL_LOCAL_REPLY + msg_id_base,
    .name = "nat44_lb_static_mapping_add_del_local_reply",
    .handler = vl_api_nat44_lb_static_mapping_add_del_local_reply_t_handler,
    .endian = vl_api_nat44_lb_static_mapping_add_del_local_reply_t_endian,
    .format_fn = vl_api_nat44_lb_static_mapping_add_del_local_reply_t_format,
    .size = sizeof(vl_api_nat44_lb_static_mapping_add_del_local_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_lb_static_mapping_add_del_local_reply_t_tojson,
    .fromjson = vl_api_nat44_lb_static_mapping_add_del_local_reply_t_fromjson,
    .calc_size = vl_api_nat44_lb_static_mapping_add_del_local_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_lb_static_mapping_add_del_local", api_nat44_lb_static_mapping_add_del_local);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_LB_STATIC_MAPPING_DETAILS + msg_id_base,
    .name = "nat44_lb_static_mapping_details",
    .handler = vl_api_nat44_lb_static_mapping_details_t_handler,
    .endian = vl_api_nat44_lb_static_mapping_details_t_endian,
    .format_fn = vl_api_nat44_lb_static_mapping_details_t_format,
    .size = sizeof(vl_api_nat44_lb_static_mapping_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_lb_static_mapping_details_t_tojson,
    .fromjson = vl_api_nat44_lb_static_mapping_details_t_fromjson,
    .calc_size = vl_api_nat44_lb_static_mapping_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_lb_static_mapping_dump", api_nat44_lb_static_mapping_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_DEL_SESSION_REPLY + msg_id_base,
    .name = "nat44_del_session_reply",
    .handler = vl_api_nat44_del_session_reply_t_handler,
    .endian = vl_api_nat44_del_session_reply_t_endian,
    .format_fn = vl_api_nat44_del_session_reply_t_format,
    .size = sizeof(vl_api_nat44_del_session_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_del_session_reply_t_tojson,
    .fromjson = vl_api_nat44_del_session_reply_t_fromjson,
    .calc_size = vl_api_nat44_del_session_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_del_session", api_nat44_del_session);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_USER_DETAILS + msg_id_base,
    .name = "nat44_user_details",
    .handler = vl_api_nat44_user_details_t_handler,
    .endian = vl_api_nat44_user_details_t_endian,
    .format_fn = vl_api_nat44_user_details_t_format,
    .size = sizeof(vl_api_nat44_user_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_user_details_t_tojson,
    .fromjson = vl_api_nat44_user_details_t_fromjson,
    .calc_size = vl_api_nat44_user_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_user_dump", api_nat44_user_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_USER_SESSION_DETAILS + msg_id_base,
    .name = "nat44_user_session_details",
    .handler = vl_api_nat44_user_session_details_t_handler,
    .endian = vl_api_nat44_user_session_details_t_endian,
    .format_fn = vl_api_nat44_user_session_details_t_format,
    .size = sizeof(vl_api_nat44_user_session_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_user_session_details_t_tojson,
    .fromjson = vl_api_nat44_user_session_details_t_fromjson,
    .calc_size = vl_api_nat44_user_session_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_user_session_dump", api_nat44_user_session_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_USER_SESSION_V2_DETAILS + msg_id_base,
    .name = "nat44_user_session_v2_details",
    .handler = vl_api_nat44_user_session_v2_details_t_handler,
    .endian = vl_api_nat44_user_session_v2_details_t_endian,
    .format_fn = vl_api_nat44_user_session_v2_details_t_format,
    .size = sizeof(vl_api_nat44_user_session_v2_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_user_session_v2_details_t_tojson,
    .fromjson = vl_api_nat44_user_session_v2_details_t_fromjson,
    .calc_size = vl_api_nat44_user_session_v2_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_user_session_v2_dump", api_nat44_user_session_v2_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_USER_SESSION_V3_DETAILS + msg_id_base,
    .name = "nat44_user_session_v3_details",
    .handler = vl_api_nat44_user_session_v3_details_t_handler,
    .endian = vl_api_nat44_user_session_v3_details_t_endian,
    .format_fn = vl_api_nat44_user_session_v3_details_t_format,
    .size = sizeof(vl_api_nat44_user_session_v3_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_user_session_v3_details_t_tojson,
    .fromjson = vl_api_nat44_user_session_v3_details_t_fromjson,
    .calc_size = vl_api_nat44_user_session_v3_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_user_session_v3_dump", api_nat44_user_session_v3_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   nat44_ed_test_main_t * mainp = &nat44_ed_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("nat44_ed_8c7fcb7f");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "nat44_ed plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
