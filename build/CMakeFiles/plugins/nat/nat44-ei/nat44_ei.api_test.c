#define vl_endianfun            /* define message structures */
#include "nat44_ei.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "nat44_ei.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "nat44_ei.api.h"
#undef vl_printfun

#ifndef VL_API_NAT44_EI_HA_RESYNC_REPLY_T_HANDLER
static void
vl_api_nat44_ei_ha_resync_reply_t_handler (vl_api_nat44_ei_ha_resync_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
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
vl_api_nat44_ei_ha_resync_completed_event_t_handler (vl_api_nat44_ei_ha_resync_completed_event_t * mp) {
    vlib_cli_output(0, "nat44_ei_ha_resync_completed_event event called:");
    vlib_cli_output(0, "%U", vl_api_nat44_ei_ha_resync_completed_event_t_format, mp);
}
/* Generation not supported (vl_api_nat44_ei_output_interface_get_reply_t_handler()) */
#ifndef VL_API_NAT44_EI_PLUGIN_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_nat44_ei_plugin_enable_disable_reply_t_handler (vl_api_nat44_ei_plugin_enable_disable_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_ei_show_running_config_reply_t_handler()) */
#ifndef VL_API_NAT44_EI_SET_LOG_LEVEL_REPLY_T_HANDLER
static void
vl_api_nat44_ei_set_log_level_reply_t_handler (vl_api_nat44_ei_set_log_level_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NAT44_EI_SET_WORKERS_REPLY_T_HANDLER
static void
vl_api_nat44_ei_set_workers_reply_t_handler (vl_api_nat44_ei_set_workers_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_ei_worker_details_t_handler()) */
#ifndef VL_API_NAT44_EI_IPFIX_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_nat44_ei_ipfix_enable_disable_reply_t_handler (vl_api_nat44_ei_ipfix_enable_disable_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NAT44_EI_SET_TIMEOUTS_REPLY_T_HANDLER
static void
vl_api_nat44_ei_set_timeouts_reply_t_handler (vl_api_nat44_ei_set_timeouts_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NAT44_EI_SET_ADDR_AND_PORT_ALLOC_ALG_REPLY_T_HANDLER
static void
vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t_handler (vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t_handler()) */
#ifndef VL_API_NAT44_EI_SET_MSS_CLAMPING_REPLY_T_HANDLER
static void
vl_api_nat44_ei_set_mss_clamping_reply_t_handler (vl_api_nat44_ei_set_mss_clamping_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_ei_get_mss_clamping_reply_t_handler()) */
#ifndef VL_API_NAT44_EI_HA_SET_LISTENER_REPLY_T_HANDLER
static void
vl_api_nat44_ei_ha_set_listener_reply_t_handler (vl_api_nat44_ei_ha_set_listener_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NAT44_EI_HA_SET_FAILOVER_REPLY_T_HANDLER
static void
vl_api_nat44_ei_ha_set_failover_reply_t_handler (vl_api_nat44_ei_ha_set_failover_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_ei_ha_get_listener_reply_t_handler()) */
/* Generation not supported (vl_api_nat44_ei_ha_get_failover_reply_t_handler()) */
#ifndef VL_API_NAT44_EI_HA_FLUSH_REPLY_T_HANDLER
static void
vl_api_nat44_ei_ha_flush_reply_t_handler (vl_api_nat44_ei_ha_flush_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NAT44_EI_DEL_USER_REPLY_T_HANDLER
static void
vl_api_nat44_ei_del_user_reply_t_handler (vl_api_nat44_ei_del_user_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NAT44_EI_ADD_DEL_ADDRESS_RANGE_REPLY_T_HANDLER
static void
vl_api_nat44_ei_add_del_address_range_reply_t_handler (vl_api_nat44_ei_add_del_address_range_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_ei_address_details_t_handler()) */
#ifndef VL_API_NAT44_EI_INTERFACE_ADD_DEL_FEATURE_REPLY_T_HANDLER
static void
vl_api_nat44_ei_interface_add_del_feature_reply_t_handler (vl_api_nat44_ei_interface_add_del_feature_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_ei_interface_details_t_handler()) */
#ifndef VL_API_NAT44_EI_INTERFACE_ADD_DEL_OUTPUT_FEATURE_REPLY_T_HANDLER
static void
vl_api_nat44_ei_interface_add_del_output_feature_reply_t_handler (vl_api_nat44_ei_interface_add_del_output_feature_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_ei_interface_output_feature_details_t_handler()) */
#ifndef VL_API_NAT44_EI_ADD_DEL_OUTPUT_INTERFACE_REPLY_T_HANDLER
static void
vl_api_nat44_ei_add_del_output_interface_reply_t_handler (vl_api_nat44_ei_add_del_output_interface_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NAT44_EI_ADD_DEL_STATIC_MAPPING_REPLY_T_HANDLER
static void
vl_api_nat44_ei_add_del_static_mapping_reply_t_handler (vl_api_nat44_ei_add_del_static_mapping_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_ei_static_mapping_details_t_handler()) */
#ifndef VL_API_NAT44_EI_ADD_DEL_IDENTITY_MAPPING_REPLY_T_HANDLER
static void
vl_api_nat44_ei_add_del_identity_mapping_reply_t_handler (vl_api_nat44_ei_add_del_identity_mapping_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_ei_identity_mapping_details_t_handler()) */
#ifndef VL_API_NAT44_EI_ADD_DEL_INTERFACE_ADDR_REPLY_T_HANDLER
static void
vl_api_nat44_ei_add_del_interface_addr_reply_t_handler (vl_api_nat44_ei_add_del_interface_addr_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_ei_interface_addr_details_t_handler()) */
/* Generation not supported (vl_api_nat44_ei_user_details_t_handler()) */
/* Generation not supported (vl_api_nat44_ei_user_session_details_t_handler()) */
/* Generation not supported (vl_api_nat44_ei_user_session_v2_details_t_handler()) */
#ifndef VL_API_NAT44_EI_DEL_SESSION_REPLY_T_HANDLER
static void
vl_api_nat44_ei_del_session_reply_t_handler (vl_api_nat44_ei_del_session_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NAT44_EI_FORWARDING_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_nat44_ei_forwarding_enable_disable_reply_t_handler (vl_api_nat44_ei_forwarding_enable_disable_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NAT44_EI_SET_FQ_OPTIONS_REPLY_T_HANDLER
static void
vl_api_nat44_ei_set_fq_options_reply_t_handler (vl_api_nat44_ei_set_fq_options_reply_t * mp) {
   vat_main_t * vam = nat44_ei_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat44_ei_show_fq_options_reply_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_HA_RESYNC_REPLY + msg_id_base,
    .name = "nat44_ei_ha_resync_reply",
    .handler = vl_api_nat44_ei_ha_resync_reply_t_handler,
    .endian = vl_api_nat44_ei_ha_resync_reply_t_endian,
    .format_fn = vl_api_nat44_ei_ha_resync_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_ha_resync_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_ha_resync_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_ha_resync_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_ha_resync_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_ha_resync", api_nat44_ei_ha_resync);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_HA_RESYNC_COMPLETED_EVENT + msg_id_base,
    .name = "nat44_ei_ha_resync_completed_event",
    .handler = vl_api_nat44_ei_ha_resync_completed_event_t_handler,
    .endian = vl_api_nat44_ei_ha_resync_completed_event_t_endian,
    .format_fn = vl_api_nat44_ei_ha_resync_completed_event_t_format,
    .size = sizeof(vl_api_nat44_ei_ha_resync_completed_event_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_ha_resync_completed_event_t_tojson,
    .fromjson = vl_api_nat44_ei_ha_resync_completed_event_t_fromjson,
    .calc_size = vl_api_nat44_ei_ha_resync_completed_event_t_calc_size,
   });   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_OUTPUT_INTERFACE_GET_REPLY + msg_id_base,
    .name = "nat44_ei_output_interface_get_reply",
    .handler = vl_api_nat44_ei_output_interface_get_reply_t_handler,
    .endian = vl_api_nat44_ei_output_interface_get_reply_t_endian,
    .format_fn = vl_api_nat44_ei_output_interface_get_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_output_interface_get_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_output_interface_get_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_output_interface_get_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_output_interface_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_output_interface_get", api_nat44_ei_output_interface_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_PLUGIN_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "nat44_ei_plugin_enable_disable_reply",
    .handler = vl_api_nat44_ei_plugin_enable_disable_reply_t_handler,
    .endian = vl_api_nat44_ei_plugin_enable_disable_reply_t_endian,
    .format_fn = vl_api_nat44_ei_plugin_enable_disable_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_plugin_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_plugin_enable_disable_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_plugin_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_plugin_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_plugin_enable_disable", api_nat44_ei_plugin_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_SHOW_RUNNING_CONFIG_REPLY + msg_id_base,
    .name = "nat44_ei_show_running_config_reply",
    .handler = vl_api_nat44_ei_show_running_config_reply_t_handler,
    .endian = vl_api_nat44_ei_show_running_config_reply_t_endian,
    .format_fn = vl_api_nat44_ei_show_running_config_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_show_running_config_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_show_running_config_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_show_running_config_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_show_running_config_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_show_running_config", api_nat44_ei_show_running_config);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_SET_LOG_LEVEL_REPLY + msg_id_base,
    .name = "nat44_ei_set_log_level_reply",
    .handler = vl_api_nat44_ei_set_log_level_reply_t_handler,
    .endian = vl_api_nat44_ei_set_log_level_reply_t_endian,
    .format_fn = vl_api_nat44_ei_set_log_level_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_set_log_level_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_set_log_level_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_set_log_level_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_set_log_level_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_set_log_level", api_nat44_ei_set_log_level);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_SET_WORKERS_REPLY + msg_id_base,
    .name = "nat44_ei_set_workers_reply",
    .handler = vl_api_nat44_ei_set_workers_reply_t_handler,
    .endian = vl_api_nat44_ei_set_workers_reply_t_endian,
    .format_fn = vl_api_nat44_ei_set_workers_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_set_workers_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_set_workers_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_set_workers_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_set_workers_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_set_workers", api_nat44_ei_set_workers);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_WORKER_DETAILS + msg_id_base,
    .name = "nat44_ei_worker_details",
    .handler = vl_api_nat44_ei_worker_details_t_handler,
    .endian = vl_api_nat44_ei_worker_details_t_endian,
    .format_fn = vl_api_nat44_ei_worker_details_t_format,
    .size = sizeof(vl_api_nat44_ei_worker_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_worker_details_t_tojson,
    .fromjson = vl_api_nat44_ei_worker_details_t_fromjson,
    .calc_size = vl_api_nat44_ei_worker_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_worker_dump", api_nat44_ei_worker_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_IPFIX_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "nat44_ei_ipfix_enable_disable_reply",
    .handler = vl_api_nat44_ei_ipfix_enable_disable_reply_t_handler,
    .endian = vl_api_nat44_ei_ipfix_enable_disable_reply_t_endian,
    .format_fn = vl_api_nat44_ei_ipfix_enable_disable_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_ipfix_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_ipfix_enable_disable_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_ipfix_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_ipfix_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_ipfix_enable_disable", api_nat44_ei_ipfix_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_SET_TIMEOUTS_REPLY + msg_id_base,
    .name = "nat44_ei_set_timeouts_reply",
    .handler = vl_api_nat44_ei_set_timeouts_reply_t_handler,
    .endian = vl_api_nat44_ei_set_timeouts_reply_t_endian,
    .format_fn = vl_api_nat44_ei_set_timeouts_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_set_timeouts_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_set_timeouts_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_set_timeouts_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_set_timeouts_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_set_timeouts", api_nat44_ei_set_timeouts);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_SET_ADDR_AND_PORT_ALLOC_ALG_REPLY + msg_id_base,
    .name = "nat44_ei_set_addr_and_port_alloc_alg_reply",
    .handler = vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t_handler,
    .endian = vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t_endian,
    .format_fn = vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_set_addr_and_port_alloc_alg", api_nat44_ei_set_addr_and_port_alloc_alg);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_GET_ADDR_AND_PORT_ALLOC_ALG_REPLY + msg_id_base,
    .name = "nat44_ei_get_addr_and_port_alloc_alg_reply",
    .handler = vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t_handler,
    .endian = vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t_endian,
    .format_fn = vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_get_addr_and_port_alloc_alg", api_nat44_ei_get_addr_and_port_alloc_alg);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_SET_MSS_CLAMPING_REPLY + msg_id_base,
    .name = "nat44_ei_set_mss_clamping_reply",
    .handler = vl_api_nat44_ei_set_mss_clamping_reply_t_handler,
    .endian = vl_api_nat44_ei_set_mss_clamping_reply_t_endian,
    .format_fn = vl_api_nat44_ei_set_mss_clamping_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_set_mss_clamping_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_set_mss_clamping_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_set_mss_clamping_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_set_mss_clamping_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_set_mss_clamping", api_nat44_ei_set_mss_clamping);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_GET_MSS_CLAMPING_REPLY + msg_id_base,
    .name = "nat44_ei_get_mss_clamping_reply",
    .handler = vl_api_nat44_ei_get_mss_clamping_reply_t_handler,
    .endian = vl_api_nat44_ei_get_mss_clamping_reply_t_endian,
    .format_fn = vl_api_nat44_ei_get_mss_clamping_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_get_mss_clamping_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_get_mss_clamping_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_get_mss_clamping_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_get_mss_clamping_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_get_mss_clamping", api_nat44_ei_get_mss_clamping);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_HA_SET_LISTENER_REPLY + msg_id_base,
    .name = "nat44_ei_ha_set_listener_reply",
    .handler = vl_api_nat44_ei_ha_set_listener_reply_t_handler,
    .endian = vl_api_nat44_ei_ha_set_listener_reply_t_endian,
    .format_fn = vl_api_nat44_ei_ha_set_listener_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_ha_set_listener_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_ha_set_listener_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_ha_set_listener_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_ha_set_listener_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_ha_set_listener", api_nat44_ei_ha_set_listener);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_HA_SET_FAILOVER_REPLY + msg_id_base,
    .name = "nat44_ei_ha_set_failover_reply",
    .handler = vl_api_nat44_ei_ha_set_failover_reply_t_handler,
    .endian = vl_api_nat44_ei_ha_set_failover_reply_t_endian,
    .format_fn = vl_api_nat44_ei_ha_set_failover_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_ha_set_failover_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_ha_set_failover_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_ha_set_failover_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_ha_set_failover_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_ha_set_failover", api_nat44_ei_ha_set_failover);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_HA_GET_LISTENER_REPLY + msg_id_base,
    .name = "nat44_ei_ha_get_listener_reply",
    .handler = vl_api_nat44_ei_ha_get_listener_reply_t_handler,
    .endian = vl_api_nat44_ei_ha_get_listener_reply_t_endian,
    .format_fn = vl_api_nat44_ei_ha_get_listener_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_ha_get_listener_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_ha_get_listener_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_ha_get_listener_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_ha_get_listener_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_ha_get_listener", api_nat44_ei_ha_get_listener);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_HA_GET_FAILOVER_REPLY + msg_id_base,
    .name = "nat44_ei_ha_get_failover_reply",
    .handler = vl_api_nat44_ei_ha_get_failover_reply_t_handler,
    .endian = vl_api_nat44_ei_ha_get_failover_reply_t_endian,
    .format_fn = vl_api_nat44_ei_ha_get_failover_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_ha_get_failover_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_ha_get_failover_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_ha_get_failover_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_ha_get_failover_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_ha_get_failover", api_nat44_ei_ha_get_failover);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_HA_FLUSH_REPLY + msg_id_base,
    .name = "nat44_ei_ha_flush_reply",
    .handler = vl_api_nat44_ei_ha_flush_reply_t_handler,
    .endian = vl_api_nat44_ei_ha_flush_reply_t_endian,
    .format_fn = vl_api_nat44_ei_ha_flush_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_ha_flush_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_ha_flush_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_ha_flush_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_ha_flush_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_ha_flush", api_nat44_ei_ha_flush);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_DEL_USER_REPLY + msg_id_base,
    .name = "nat44_ei_del_user_reply",
    .handler = vl_api_nat44_ei_del_user_reply_t_handler,
    .endian = vl_api_nat44_ei_del_user_reply_t_endian,
    .format_fn = vl_api_nat44_ei_del_user_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_del_user_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_del_user_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_del_user_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_del_user_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_del_user", api_nat44_ei_del_user);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_ADD_DEL_ADDRESS_RANGE_REPLY + msg_id_base,
    .name = "nat44_ei_add_del_address_range_reply",
    .handler = vl_api_nat44_ei_add_del_address_range_reply_t_handler,
    .endian = vl_api_nat44_ei_add_del_address_range_reply_t_endian,
    .format_fn = vl_api_nat44_ei_add_del_address_range_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_add_del_address_range_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_add_del_address_range_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_add_del_address_range_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_add_del_address_range_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_add_del_address_range", api_nat44_ei_add_del_address_range);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_ADDRESS_DETAILS + msg_id_base,
    .name = "nat44_ei_address_details",
    .handler = vl_api_nat44_ei_address_details_t_handler,
    .endian = vl_api_nat44_ei_address_details_t_endian,
    .format_fn = vl_api_nat44_ei_address_details_t_format,
    .size = sizeof(vl_api_nat44_ei_address_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_address_details_t_tojson,
    .fromjson = vl_api_nat44_ei_address_details_t_fromjson,
    .calc_size = vl_api_nat44_ei_address_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_address_dump", api_nat44_ei_address_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_INTERFACE_ADD_DEL_FEATURE_REPLY + msg_id_base,
    .name = "nat44_ei_interface_add_del_feature_reply",
    .handler = vl_api_nat44_ei_interface_add_del_feature_reply_t_handler,
    .endian = vl_api_nat44_ei_interface_add_del_feature_reply_t_endian,
    .format_fn = vl_api_nat44_ei_interface_add_del_feature_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_interface_add_del_feature_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_interface_add_del_feature_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_interface_add_del_feature_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_interface_add_del_feature_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_interface_add_del_feature", api_nat44_ei_interface_add_del_feature);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_INTERFACE_DETAILS + msg_id_base,
    .name = "nat44_ei_interface_details",
    .handler = vl_api_nat44_ei_interface_details_t_handler,
    .endian = vl_api_nat44_ei_interface_details_t_endian,
    .format_fn = vl_api_nat44_ei_interface_details_t_format,
    .size = sizeof(vl_api_nat44_ei_interface_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_interface_details_t_tojson,
    .fromjson = vl_api_nat44_ei_interface_details_t_fromjson,
    .calc_size = vl_api_nat44_ei_interface_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_interface_dump", api_nat44_ei_interface_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_INTERFACE_ADD_DEL_OUTPUT_FEATURE_REPLY + msg_id_base,
    .name = "nat44_ei_interface_add_del_output_feature_reply",
    .handler = vl_api_nat44_ei_interface_add_del_output_feature_reply_t_handler,
    .endian = vl_api_nat44_ei_interface_add_del_output_feature_reply_t_endian,
    .format_fn = vl_api_nat44_ei_interface_add_del_output_feature_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_interface_add_del_output_feature_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_interface_add_del_output_feature_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_interface_add_del_output_feature_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_interface_add_del_output_feature_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_interface_add_del_output_feature", api_nat44_ei_interface_add_del_output_feature);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_INTERFACE_OUTPUT_FEATURE_DETAILS + msg_id_base,
    .name = "nat44_ei_interface_output_feature_details",
    .handler = vl_api_nat44_ei_interface_output_feature_details_t_handler,
    .endian = vl_api_nat44_ei_interface_output_feature_details_t_endian,
    .format_fn = vl_api_nat44_ei_interface_output_feature_details_t_format,
    .size = sizeof(vl_api_nat44_ei_interface_output_feature_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_interface_output_feature_details_t_tojson,
    .fromjson = vl_api_nat44_ei_interface_output_feature_details_t_fromjson,
    .calc_size = vl_api_nat44_ei_interface_output_feature_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_interface_output_feature_dump", api_nat44_ei_interface_output_feature_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_ADD_DEL_OUTPUT_INTERFACE_REPLY + msg_id_base,
    .name = "nat44_ei_add_del_output_interface_reply",
    .handler = vl_api_nat44_ei_add_del_output_interface_reply_t_handler,
    .endian = vl_api_nat44_ei_add_del_output_interface_reply_t_endian,
    .format_fn = vl_api_nat44_ei_add_del_output_interface_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_add_del_output_interface_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_add_del_output_interface_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_add_del_output_interface_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_add_del_output_interface_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_add_del_output_interface", api_nat44_ei_add_del_output_interface);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_ADD_DEL_STATIC_MAPPING_REPLY + msg_id_base,
    .name = "nat44_ei_add_del_static_mapping_reply",
    .handler = vl_api_nat44_ei_add_del_static_mapping_reply_t_handler,
    .endian = vl_api_nat44_ei_add_del_static_mapping_reply_t_endian,
    .format_fn = vl_api_nat44_ei_add_del_static_mapping_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_add_del_static_mapping_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_add_del_static_mapping_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_add_del_static_mapping_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_add_del_static_mapping_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_add_del_static_mapping", api_nat44_ei_add_del_static_mapping);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_STATIC_MAPPING_DETAILS + msg_id_base,
    .name = "nat44_ei_static_mapping_details",
    .handler = vl_api_nat44_ei_static_mapping_details_t_handler,
    .endian = vl_api_nat44_ei_static_mapping_details_t_endian,
    .format_fn = vl_api_nat44_ei_static_mapping_details_t_format,
    .size = sizeof(vl_api_nat44_ei_static_mapping_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_static_mapping_details_t_tojson,
    .fromjson = vl_api_nat44_ei_static_mapping_details_t_fromjson,
    .calc_size = vl_api_nat44_ei_static_mapping_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_static_mapping_dump", api_nat44_ei_static_mapping_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_ADD_DEL_IDENTITY_MAPPING_REPLY + msg_id_base,
    .name = "nat44_ei_add_del_identity_mapping_reply",
    .handler = vl_api_nat44_ei_add_del_identity_mapping_reply_t_handler,
    .endian = vl_api_nat44_ei_add_del_identity_mapping_reply_t_endian,
    .format_fn = vl_api_nat44_ei_add_del_identity_mapping_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_add_del_identity_mapping_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_add_del_identity_mapping_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_add_del_identity_mapping_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_add_del_identity_mapping_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_add_del_identity_mapping", api_nat44_ei_add_del_identity_mapping);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_IDENTITY_MAPPING_DETAILS + msg_id_base,
    .name = "nat44_ei_identity_mapping_details",
    .handler = vl_api_nat44_ei_identity_mapping_details_t_handler,
    .endian = vl_api_nat44_ei_identity_mapping_details_t_endian,
    .format_fn = vl_api_nat44_ei_identity_mapping_details_t_format,
    .size = sizeof(vl_api_nat44_ei_identity_mapping_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_identity_mapping_details_t_tojson,
    .fromjson = vl_api_nat44_ei_identity_mapping_details_t_fromjson,
    .calc_size = vl_api_nat44_ei_identity_mapping_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_identity_mapping_dump", api_nat44_ei_identity_mapping_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_ADD_DEL_INTERFACE_ADDR_REPLY + msg_id_base,
    .name = "nat44_ei_add_del_interface_addr_reply",
    .handler = vl_api_nat44_ei_add_del_interface_addr_reply_t_handler,
    .endian = vl_api_nat44_ei_add_del_interface_addr_reply_t_endian,
    .format_fn = vl_api_nat44_ei_add_del_interface_addr_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_add_del_interface_addr_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_add_del_interface_addr_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_add_del_interface_addr_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_add_del_interface_addr_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_add_del_interface_addr", api_nat44_ei_add_del_interface_addr);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_INTERFACE_ADDR_DETAILS + msg_id_base,
    .name = "nat44_ei_interface_addr_details",
    .handler = vl_api_nat44_ei_interface_addr_details_t_handler,
    .endian = vl_api_nat44_ei_interface_addr_details_t_endian,
    .format_fn = vl_api_nat44_ei_interface_addr_details_t_format,
    .size = sizeof(vl_api_nat44_ei_interface_addr_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_interface_addr_details_t_tojson,
    .fromjson = vl_api_nat44_ei_interface_addr_details_t_fromjson,
    .calc_size = vl_api_nat44_ei_interface_addr_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_interface_addr_dump", api_nat44_ei_interface_addr_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_USER_DETAILS + msg_id_base,
    .name = "nat44_ei_user_details",
    .handler = vl_api_nat44_ei_user_details_t_handler,
    .endian = vl_api_nat44_ei_user_details_t_endian,
    .format_fn = vl_api_nat44_ei_user_details_t_format,
    .size = sizeof(vl_api_nat44_ei_user_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_user_details_t_tojson,
    .fromjson = vl_api_nat44_ei_user_details_t_fromjson,
    .calc_size = vl_api_nat44_ei_user_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_user_dump", api_nat44_ei_user_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_USER_SESSION_DETAILS + msg_id_base,
    .name = "nat44_ei_user_session_details",
    .handler = vl_api_nat44_ei_user_session_details_t_handler,
    .endian = vl_api_nat44_ei_user_session_details_t_endian,
    .format_fn = vl_api_nat44_ei_user_session_details_t_format,
    .size = sizeof(vl_api_nat44_ei_user_session_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_user_session_details_t_tojson,
    .fromjson = vl_api_nat44_ei_user_session_details_t_fromjson,
    .calc_size = vl_api_nat44_ei_user_session_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_user_session_dump", api_nat44_ei_user_session_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_USER_SESSION_V2_DETAILS + msg_id_base,
    .name = "nat44_ei_user_session_v2_details",
    .handler = vl_api_nat44_ei_user_session_v2_details_t_handler,
    .endian = vl_api_nat44_ei_user_session_v2_details_t_endian,
    .format_fn = vl_api_nat44_ei_user_session_v2_details_t_format,
    .size = sizeof(vl_api_nat44_ei_user_session_v2_details_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_user_session_v2_details_t_tojson,
    .fromjson = vl_api_nat44_ei_user_session_v2_details_t_fromjson,
    .calc_size = vl_api_nat44_ei_user_session_v2_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_user_session_v2_dump", api_nat44_ei_user_session_v2_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_DEL_SESSION_REPLY + msg_id_base,
    .name = "nat44_ei_del_session_reply",
    .handler = vl_api_nat44_ei_del_session_reply_t_handler,
    .endian = vl_api_nat44_ei_del_session_reply_t_endian,
    .format_fn = vl_api_nat44_ei_del_session_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_del_session_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_del_session_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_del_session_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_del_session_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_del_session", api_nat44_ei_del_session);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_FORWARDING_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "nat44_ei_forwarding_enable_disable_reply",
    .handler = vl_api_nat44_ei_forwarding_enable_disable_reply_t_handler,
    .endian = vl_api_nat44_ei_forwarding_enable_disable_reply_t_endian,
    .format_fn = vl_api_nat44_ei_forwarding_enable_disable_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_forwarding_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_forwarding_enable_disable_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_forwarding_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_forwarding_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_forwarding_enable_disable", api_nat44_ei_forwarding_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_SET_FQ_OPTIONS_REPLY + msg_id_base,
    .name = "nat44_ei_set_fq_options_reply",
    .handler = vl_api_nat44_ei_set_fq_options_reply_t_handler,
    .endian = vl_api_nat44_ei_set_fq_options_reply_t_endian,
    .format_fn = vl_api_nat44_ei_set_fq_options_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_set_fq_options_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_set_fq_options_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_set_fq_options_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_set_fq_options_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_set_fq_options", api_nat44_ei_set_fq_options);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT44_EI_SHOW_FQ_OPTIONS_REPLY + msg_id_base,
    .name = "nat44_ei_show_fq_options_reply",
    .handler = vl_api_nat44_ei_show_fq_options_reply_t_handler,
    .endian = vl_api_nat44_ei_show_fq_options_reply_t_endian,
    .format_fn = vl_api_nat44_ei_show_fq_options_reply_t_format,
    .size = sizeof(vl_api_nat44_ei_show_fq_options_reply_t),
    .traced = 1,
    .tojson = vl_api_nat44_ei_show_fq_options_reply_t_tojson,
    .fromjson = vl_api_nat44_ei_show_fq_options_reply_t_fromjson,
    .calc_size = vl_api_nat44_ei_show_fq_options_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat44_ei_show_fq_options", api_nat44_ei_show_fq_options);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   nat44_ei_test_main_t * mainp = &nat44_ei_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("nat44_ei_20734fe0");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "nat44_ei plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
