#define vl_endianfun            /* define message structures */
#include "dhcp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "dhcp.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "dhcp.api.h"
#undef vl_printfun

#ifndef VL_API_DHCP_CLIENT_CONFIG_REPLY_T_HANDLER
static void
vl_api_dhcp_client_config_reply_t_handler (vl_api_dhcp_client_config_reply_t * mp) {
   vat_main_t * vam = dhcp_test_main.vat_main;
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
vl_api_dhcp_compl_event_t_handler (vl_api_dhcp_compl_event_t * mp) {
    vlib_cli_output(0, "dhcp_compl_event event called:");
    vlib_cli_output(0, "%U", vl_api_dhcp_compl_event_t_format, mp);
}
#ifndef VL_API_WANT_DHCP6_REPLY_EVENTS_REPLY_T_HANDLER
static void
vl_api_want_dhcp6_reply_events_reply_t_handler (vl_api_want_dhcp6_reply_events_reply_t * mp) {
   vat_main_t * vam = dhcp_test_main.vat_main;
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
vl_api_dhcp6_reply_event_t_handler (vl_api_dhcp6_reply_event_t * mp) {
    vlib_cli_output(0, "dhcp6_reply_event event called:");
    vlib_cli_output(0, "%U", vl_api_dhcp6_reply_event_t_format, mp);
}
#ifndef VL_API_WANT_DHCP6_PD_REPLY_EVENTS_REPLY_T_HANDLER
static void
vl_api_want_dhcp6_pd_reply_events_reply_t_handler (vl_api_want_dhcp6_pd_reply_events_reply_t * mp) {
   vat_main_t * vam = dhcp_test_main.vat_main;
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
vl_api_dhcp6_pd_reply_event_t_handler (vl_api_dhcp6_pd_reply_event_t * mp) {
    vlib_cli_output(0, "dhcp6_pd_reply_event event called:");
    vlib_cli_output(0, "%U", vl_api_dhcp6_pd_reply_event_t_format, mp);
}
/* Generation not supported (vl_api_dhcp_plugin_get_version_reply_t_handler()) */
/* Generation not supported (vl_api_dhcp_plugin_control_ping_reply_t_handler()) */
#ifndef VL_API_DHCP_PROXY_CONFIG_REPLY_T_HANDLER
static void
vl_api_dhcp_proxy_config_reply_t_handler (vl_api_dhcp_proxy_config_reply_t * mp) {
   vat_main_t * vam = dhcp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_DHCP_PROXY_SET_VSS_REPLY_T_HANDLER
static void
vl_api_dhcp_proxy_set_vss_reply_t_handler (vl_api_dhcp_proxy_set_vss_reply_t * mp) {
   vat_main_t * vam = dhcp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_dhcp_client_details_t_handler()) */
/* Generation not supported (vl_api_dhcp_proxy_details_t_handler()) */
#ifndef VL_API_DHCP_CLIENT_DETECT_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_dhcp_client_detect_enable_disable_reply_t_handler (vl_api_dhcp_client_detect_enable_disable_reply_t * mp) {
   vat_main_t * vam = dhcp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_DHCP6_DUID_LL_SET_REPLY_T_HANDLER
static void
vl_api_dhcp6_duid_ll_set_reply_t_handler (vl_api_dhcp6_duid_ll_set_reply_t * mp) {
   vat_main_t * vam = dhcp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_DHCP6_CLIENTS_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_dhcp6_clients_enable_disable_reply_t_handler (vl_api_dhcp6_clients_enable_disable_reply_t * mp) {
   vat_main_t * vam = dhcp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_DHCP6_SEND_CLIENT_MESSAGE_REPLY_T_HANDLER
static void
vl_api_dhcp6_send_client_message_reply_t_handler (vl_api_dhcp6_send_client_message_reply_t * mp) {
   vat_main_t * vam = dhcp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_DHCP6_PD_SEND_CLIENT_MESSAGE_REPLY_T_HANDLER
static void
vl_api_dhcp6_pd_send_client_message_reply_t_handler (vl_api_dhcp6_pd_send_client_message_reply_t * mp) {
   vat_main_t * vam = dhcp_test_main.vat_main;
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
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DHCP_CLIENT_CONFIG_REPLY + msg_id_base,
    .name = "dhcp_client_config_reply",
    .handler = vl_api_dhcp_client_config_reply_t_handler,
    .endian = vl_api_dhcp_client_config_reply_t_endian,
    .format_fn = vl_api_dhcp_client_config_reply_t_format,
    .size = sizeof(vl_api_dhcp_client_config_reply_t),
    .traced = 1,
    .tojson = vl_api_dhcp_client_config_reply_t_tojson,
    .fromjson = vl_api_dhcp_client_config_reply_t_fromjson,
    .calc_size = vl_api_dhcp_client_config_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dhcp_client_config", api_dhcp_client_config);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DHCP_COMPL_EVENT + msg_id_base,
    .name = "dhcp_compl_event",
    .handler = vl_api_dhcp_compl_event_t_handler,
    .endian = vl_api_dhcp_compl_event_t_endian,
    .format_fn = vl_api_dhcp_compl_event_t_format,
    .size = sizeof(vl_api_dhcp_compl_event_t),
    .traced = 1,
    .tojson = vl_api_dhcp_compl_event_t_tojson,
    .fromjson = vl_api_dhcp_compl_event_t_fromjson,
    .calc_size = vl_api_dhcp_compl_event_t_calc_size,
   });   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_WANT_DHCP6_REPLY_EVENTS_REPLY + msg_id_base,
    .name = "want_dhcp6_reply_events_reply",
    .handler = vl_api_want_dhcp6_reply_events_reply_t_handler,
    .endian = vl_api_want_dhcp6_reply_events_reply_t_endian,
    .format_fn = vl_api_want_dhcp6_reply_events_reply_t_format,
    .size = sizeof(vl_api_want_dhcp6_reply_events_reply_t),
    .traced = 1,
    .tojson = vl_api_want_dhcp6_reply_events_reply_t_tojson,
    .fromjson = vl_api_want_dhcp6_reply_events_reply_t_fromjson,
    .calc_size = vl_api_want_dhcp6_reply_events_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "want_dhcp6_reply_events", api_want_dhcp6_reply_events);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DHCP6_REPLY_EVENT + msg_id_base,
    .name = "dhcp6_reply_event",
    .handler = vl_api_dhcp6_reply_event_t_handler,
    .endian = vl_api_dhcp6_reply_event_t_endian,
    .format_fn = vl_api_dhcp6_reply_event_t_format,
    .size = sizeof(vl_api_dhcp6_reply_event_t),
    .traced = 1,
    .tojson = vl_api_dhcp6_reply_event_t_tojson,
    .fromjson = vl_api_dhcp6_reply_event_t_fromjson,
    .calc_size = vl_api_dhcp6_reply_event_t_calc_size,
   });   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_WANT_DHCP6_PD_REPLY_EVENTS_REPLY + msg_id_base,
    .name = "want_dhcp6_pd_reply_events_reply",
    .handler = vl_api_want_dhcp6_pd_reply_events_reply_t_handler,
    .endian = vl_api_want_dhcp6_pd_reply_events_reply_t_endian,
    .format_fn = vl_api_want_dhcp6_pd_reply_events_reply_t_format,
    .size = sizeof(vl_api_want_dhcp6_pd_reply_events_reply_t),
    .traced = 1,
    .tojson = vl_api_want_dhcp6_pd_reply_events_reply_t_tojson,
    .fromjson = vl_api_want_dhcp6_pd_reply_events_reply_t_fromjson,
    .calc_size = vl_api_want_dhcp6_pd_reply_events_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "want_dhcp6_pd_reply_events", api_want_dhcp6_pd_reply_events);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DHCP6_PD_REPLY_EVENT + msg_id_base,
    .name = "dhcp6_pd_reply_event",
    .handler = vl_api_dhcp6_pd_reply_event_t_handler,
    .endian = vl_api_dhcp6_pd_reply_event_t_endian,
    .format_fn = vl_api_dhcp6_pd_reply_event_t_format,
    .size = sizeof(vl_api_dhcp6_pd_reply_event_t),
    .traced = 1,
    .tojson = vl_api_dhcp6_pd_reply_event_t_tojson,
    .fromjson = vl_api_dhcp6_pd_reply_event_t_fromjson,
    .calc_size = vl_api_dhcp6_pd_reply_event_t_calc_size,
   });   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DHCP_PLUGIN_GET_VERSION_REPLY + msg_id_base,
    .name = "dhcp_plugin_get_version_reply",
    .handler = vl_api_dhcp_plugin_get_version_reply_t_handler,
    .endian = vl_api_dhcp_plugin_get_version_reply_t_endian,
    .format_fn = vl_api_dhcp_plugin_get_version_reply_t_format,
    .size = sizeof(vl_api_dhcp_plugin_get_version_reply_t),
    .traced = 1,
    .tojson = vl_api_dhcp_plugin_get_version_reply_t_tojson,
    .fromjson = vl_api_dhcp_plugin_get_version_reply_t_fromjson,
    .calc_size = vl_api_dhcp_plugin_get_version_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dhcp_plugin_get_version", api_dhcp_plugin_get_version);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DHCP_PLUGIN_CONTROL_PING_REPLY + msg_id_base,
    .name = "dhcp_plugin_control_ping_reply",
    .handler = vl_api_dhcp_plugin_control_ping_reply_t_handler,
    .endian = vl_api_dhcp_plugin_control_ping_reply_t_endian,
    .format_fn = vl_api_dhcp_plugin_control_ping_reply_t_format,
    .size = sizeof(vl_api_dhcp_plugin_control_ping_reply_t),
    .traced = 1,
    .tojson = vl_api_dhcp_plugin_control_ping_reply_t_tojson,
    .fromjson = vl_api_dhcp_plugin_control_ping_reply_t_fromjson,
    .calc_size = vl_api_dhcp_plugin_control_ping_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dhcp_plugin_control_ping", api_dhcp_plugin_control_ping);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DHCP_PROXY_CONFIG_REPLY + msg_id_base,
    .name = "dhcp_proxy_config_reply",
    .handler = vl_api_dhcp_proxy_config_reply_t_handler,
    .endian = vl_api_dhcp_proxy_config_reply_t_endian,
    .format_fn = vl_api_dhcp_proxy_config_reply_t_format,
    .size = sizeof(vl_api_dhcp_proxy_config_reply_t),
    .traced = 1,
    .tojson = vl_api_dhcp_proxy_config_reply_t_tojson,
    .fromjson = vl_api_dhcp_proxy_config_reply_t_fromjson,
    .calc_size = vl_api_dhcp_proxy_config_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dhcp_proxy_config", api_dhcp_proxy_config);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DHCP_PROXY_SET_VSS_REPLY + msg_id_base,
    .name = "dhcp_proxy_set_vss_reply",
    .handler = vl_api_dhcp_proxy_set_vss_reply_t_handler,
    .endian = vl_api_dhcp_proxy_set_vss_reply_t_endian,
    .format_fn = vl_api_dhcp_proxy_set_vss_reply_t_format,
    .size = sizeof(vl_api_dhcp_proxy_set_vss_reply_t),
    .traced = 1,
    .tojson = vl_api_dhcp_proxy_set_vss_reply_t_tojson,
    .fromjson = vl_api_dhcp_proxy_set_vss_reply_t_fromjson,
    .calc_size = vl_api_dhcp_proxy_set_vss_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dhcp_proxy_set_vss", api_dhcp_proxy_set_vss);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DHCP_CLIENT_DETAILS + msg_id_base,
    .name = "dhcp_client_details",
    .handler = vl_api_dhcp_client_details_t_handler,
    .endian = vl_api_dhcp_client_details_t_endian,
    .format_fn = vl_api_dhcp_client_details_t_format,
    .size = sizeof(vl_api_dhcp_client_details_t),
    .traced = 1,
    .tojson = vl_api_dhcp_client_details_t_tojson,
    .fromjson = vl_api_dhcp_client_details_t_fromjson,
    .calc_size = vl_api_dhcp_client_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dhcp_client_dump", api_dhcp_client_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DHCP_PROXY_DETAILS + msg_id_base,
    .name = "dhcp_proxy_details",
    .handler = vl_api_dhcp_proxy_details_t_handler,
    .endian = vl_api_dhcp_proxy_details_t_endian,
    .format_fn = vl_api_dhcp_proxy_details_t_format,
    .size = sizeof(vl_api_dhcp_proxy_details_t),
    .traced = 1,
    .tojson = vl_api_dhcp_proxy_details_t_tojson,
    .fromjson = vl_api_dhcp_proxy_details_t_fromjson,
    .calc_size = vl_api_dhcp_proxy_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dhcp_proxy_dump", api_dhcp_proxy_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DHCP_CLIENT_DETECT_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "dhcp_client_detect_enable_disable_reply",
    .handler = vl_api_dhcp_client_detect_enable_disable_reply_t_handler,
    .endian = vl_api_dhcp_client_detect_enable_disable_reply_t_endian,
    .format_fn = vl_api_dhcp_client_detect_enable_disable_reply_t_format,
    .size = sizeof(vl_api_dhcp_client_detect_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_dhcp_client_detect_enable_disable_reply_t_tojson,
    .fromjson = vl_api_dhcp_client_detect_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_dhcp_client_detect_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dhcp_client_detect_enable_disable", api_dhcp_client_detect_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DHCP6_DUID_LL_SET_REPLY + msg_id_base,
    .name = "dhcp6_duid_ll_set_reply",
    .handler = vl_api_dhcp6_duid_ll_set_reply_t_handler,
    .endian = vl_api_dhcp6_duid_ll_set_reply_t_endian,
    .format_fn = vl_api_dhcp6_duid_ll_set_reply_t_format,
    .size = sizeof(vl_api_dhcp6_duid_ll_set_reply_t),
    .traced = 1,
    .tojson = vl_api_dhcp6_duid_ll_set_reply_t_tojson,
    .fromjson = vl_api_dhcp6_duid_ll_set_reply_t_fromjson,
    .calc_size = vl_api_dhcp6_duid_ll_set_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dhcp6_duid_ll_set", api_dhcp6_duid_ll_set);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DHCP6_CLIENTS_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "dhcp6_clients_enable_disable_reply",
    .handler = vl_api_dhcp6_clients_enable_disable_reply_t_handler,
    .endian = vl_api_dhcp6_clients_enable_disable_reply_t_endian,
    .format_fn = vl_api_dhcp6_clients_enable_disable_reply_t_format,
    .size = sizeof(vl_api_dhcp6_clients_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_dhcp6_clients_enable_disable_reply_t_tojson,
    .fromjson = vl_api_dhcp6_clients_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_dhcp6_clients_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dhcp6_clients_enable_disable", api_dhcp6_clients_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DHCP6_SEND_CLIENT_MESSAGE_REPLY + msg_id_base,
    .name = "dhcp6_send_client_message_reply",
    .handler = vl_api_dhcp6_send_client_message_reply_t_handler,
    .endian = vl_api_dhcp6_send_client_message_reply_t_endian,
    .format_fn = vl_api_dhcp6_send_client_message_reply_t_format,
    .size = sizeof(vl_api_dhcp6_send_client_message_reply_t),
    .traced = 1,
    .tojson = vl_api_dhcp6_send_client_message_reply_t_tojson,
    .fromjson = vl_api_dhcp6_send_client_message_reply_t_fromjson,
    .calc_size = vl_api_dhcp6_send_client_message_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dhcp6_send_client_message", api_dhcp6_send_client_message);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DHCP6_PD_SEND_CLIENT_MESSAGE_REPLY + msg_id_base,
    .name = "dhcp6_pd_send_client_message_reply",
    .handler = vl_api_dhcp6_pd_send_client_message_reply_t_handler,
    .endian = vl_api_dhcp6_pd_send_client_message_reply_t_endian,
    .format_fn = vl_api_dhcp6_pd_send_client_message_reply_t_format,
    .size = sizeof(vl_api_dhcp6_pd_send_client_message_reply_t),
    .traced = 1,
    .tojson = vl_api_dhcp6_pd_send_client_message_reply_t_tojson,
    .fromjson = vl_api_dhcp6_pd_send_client_message_reply_t_fromjson,
    .calc_size = vl_api_dhcp6_pd_send_client_message_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dhcp6_pd_send_client_message", api_dhcp6_pd_send_client_message);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   dhcp_test_main_t * mainp = &dhcp_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("dhcp_287ada20");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "dhcp plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
