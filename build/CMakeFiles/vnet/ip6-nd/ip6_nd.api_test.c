#define vl_endianfun            /* define message structures */
#include "ip6_nd.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ip6_nd.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "ip6_nd.api.h"
#undef vl_printfun

#ifndef VL_API_WANT_IP6_RA_EVENTS_REPLY_T_HANDLER
static void
vl_api_want_ip6_ra_events_reply_t_handler (vl_api_want_ip6_ra_events_reply_t * mp) {
   vat_main_t * vam = ip6_nd_test_main.vat_main;
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
vl_api_ip6_ra_event_t_handler (vl_api_ip6_ra_event_t * mp) {
    vlib_cli_output(0, "ip6_ra_event event called:");
    vlib_cli_output(0, "%U", vl_api_ip6_ra_event_t_format, mp);
}
#ifndef VL_API_SW_INTERFACE_IP6ND_RA_CONFIG_REPLY_T_HANDLER
static void
vl_api_sw_interface_ip6nd_ra_config_reply_t_handler (vl_api_sw_interface_ip6nd_ra_config_reply_t * mp) {
   vat_main_t * vam = ip6_nd_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SW_INTERFACE_IP6ND_RA_PREFIX_REPLY_T_HANDLER
static void
vl_api_sw_interface_ip6nd_ra_prefix_reply_t_handler (vl_api_sw_interface_ip6nd_ra_prefix_reply_t * mp) {
   vat_main_t * vam = ip6_nd_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_sw_interface_ip6nd_ra_details_t_handler()) */
#ifndef VL_API_IP6ND_PROXY_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_ip6nd_proxy_enable_disable_reply_t_handler (vl_api_ip6nd_proxy_enable_disable_reply_t * mp) {
   vat_main_t * vam = ip6_nd_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IP6ND_PROXY_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_ip6nd_proxy_add_del_reply_t_handler (vl_api_ip6nd_proxy_add_del_reply_t * mp) {
   vat_main_t * vam = ip6_nd_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_ip6nd_proxy_details_t_handler()) */
#ifndef VL_API_IP6ND_SEND_ROUTER_SOLICITATION_REPLY_T_HANDLER
static void
vl_api_ip6nd_send_router_solicitation_reply_t_handler (vl_api_ip6nd_send_router_solicitation_reply_t * mp) {
   vat_main_t * vam = ip6_nd_test_main.vat_main;
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
    .id = VL_API_WANT_IP6_RA_EVENTS_REPLY + msg_id_base,
    .name = "want_ip6_ra_events_reply",
    .handler = vl_api_want_ip6_ra_events_reply_t_handler,
    .endian = vl_api_want_ip6_ra_events_reply_t_endian,
    .format_fn = vl_api_want_ip6_ra_events_reply_t_format,
    .size = sizeof(vl_api_want_ip6_ra_events_reply_t),
    .traced = 1,
    .tojson = vl_api_want_ip6_ra_events_reply_t_tojson,
    .fromjson = vl_api_want_ip6_ra_events_reply_t_fromjson,
    .calc_size = vl_api_want_ip6_ra_events_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "want_ip6_ra_events", api_want_ip6_ra_events);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP6_RA_EVENT + msg_id_base,
    .name = "ip6_ra_event",
    .handler = vl_api_ip6_ra_event_t_handler,
    .endian = vl_api_ip6_ra_event_t_endian,
    .format_fn = vl_api_ip6_ra_event_t_format,
    .size = sizeof(vl_api_ip6_ra_event_t),
    .traced = 1,
    .tojson = vl_api_ip6_ra_event_t_tojson,
    .fromjson = vl_api_ip6_ra_event_t_fromjson,
    .calc_size = vl_api_ip6_ra_event_t_calc_size,
   });   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_IP6ND_RA_CONFIG_REPLY + msg_id_base,
    .name = "sw_interface_ip6nd_ra_config_reply",
    .handler = vl_api_sw_interface_ip6nd_ra_config_reply_t_handler,
    .endian = vl_api_sw_interface_ip6nd_ra_config_reply_t_endian,
    .format_fn = vl_api_sw_interface_ip6nd_ra_config_reply_t_format,
    .size = sizeof(vl_api_sw_interface_ip6nd_ra_config_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_ip6nd_ra_config_reply_t_tojson,
    .fromjson = vl_api_sw_interface_ip6nd_ra_config_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_ip6nd_ra_config_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_ip6nd_ra_config", api_sw_interface_ip6nd_ra_config);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_IP6ND_RA_PREFIX_REPLY + msg_id_base,
    .name = "sw_interface_ip6nd_ra_prefix_reply",
    .handler = vl_api_sw_interface_ip6nd_ra_prefix_reply_t_handler,
    .endian = vl_api_sw_interface_ip6nd_ra_prefix_reply_t_endian,
    .format_fn = vl_api_sw_interface_ip6nd_ra_prefix_reply_t_format,
    .size = sizeof(vl_api_sw_interface_ip6nd_ra_prefix_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_ip6nd_ra_prefix_reply_t_tojson,
    .fromjson = vl_api_sw_interface_ip6nd_ra_prefix_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_ip6nd_ra_prefix_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_ip6nd_ra_prefix", api_sw_interface_ip6nd_ra_prefix);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_IP6ND_RA_DETAILS + msg_id_base,
    .name = "sw_interface_ip6nd_ra_details",
    .handler = vl_api_sw_interface_ip6nd_ra_details_t_handler,
    .endian = vl_api_sw_interface_ip6nd_ra_details_t_endian,
    .format_fn = vl_api_sw_interface_ip6nd_ra_details_t_format,
    .size = sizeof(vl_api_sw_interface_ip6nd_ra_details_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_ip6nd_ra_details_t_tojson,
    .fromjson = vl_api_sw_interface_ip6nd_ra_details_t_fromjson,
    .calc_size = vl_api_sw_interface_ip6nd_ra_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_ip6nd_ra_dump", api_sw_interface_ip6nd_ra_dump);
   hash_set_mem (vam->help_by_name, "sw_interface_ip6nd_ra_dump", "[(<if-name>|sw_if_index <if-idx>)]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP6ND_PROXY_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "ip6nd_proxy_enable_disable_reply",
    .handler = vl_api_ip6nd_proxy_enable_disable_reply_t_handler,
    .endian = vl_api_ip6nd_proxy_enable_disable_reply_t_endian,
    .format_fn = vl_api_ip6nd_proxy_enable_disable_reply_t_format,
    .size = sizeof(vl_api_ip6nd_proxy_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_ip6nd_proxy_enable_disable_reply_t_tojson,
    .fromjson = vl_api_ip6nd_proxy_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_ip6nd_proxy_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip6nd_proxy_enable_disable", api_ip6nd_proxy_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP6ND_PROXY_ADD_DEL_REPLY + msg_id_base,
    .name = "ip6nd_proxy_add_del_reply",
    .handler = vl_api_ip6nd_proxy_add_del_reply_t_handler,
    .endian = vl_api_ip6nd_proxy_add_del_reply_t_endian,
    .format_fn = vl_api_ip6nd_proxy_add_del_reply_t_format,
    .size = sizeof(vl_api_ip6nd_proxy_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_ip6nd_proxy_add_del_reply_t_tojson,
    .fromjson = vl_api_ip6nd_proxy_add_del_reply_t_fromjson,
    .calc_size = vl_api_ip6nd_proxy_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip6nd_proxy_add_del", api_ip6nd_proxy_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP6ND_PROXY_DETAILS + msg_id_base,
    .name = "ip6nd_proxy_details",
    .handler = vl_api_ip6nd_proxy_details_t_handler,
    .endian = vl_api_ip6nd_proxy_details_t_endian,
    .format_fn = vl_api_ip6nd_proxy_details_t_format,
    .size = sizeof(vl_api_ip6nd_proxy_details_t),
    .traced = 1,
    .tojson = vl_api_ip6nd_proxy_details_t_tojson,
    .fromjson = vl_api_ip6nd_proxy_details_t_fromjson,
    .calc_size = vl_api_ip6nd_proxy_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip6nd_proxy_dump", api_ip6nd_proxy_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP6ND_SEND_ROUTER_SOLICITATION_REPLY + msg_id_base,
    .name = "ip6nd_send_router_solicitation_reply",
    .handler = vl_api_ip6nd_send_router_solicitation_reply_t_handler,
    .endian = vl_api_ip6nd_send_router_solicitation_reply_t_endian,
    .format_fn = vl_api_ip6nd_send_router_solicitation_reply_t_format,
    .size = sizeof(vl_api_ip6nd_send_router_solicitation_reply_t),
    .traced = 1,
    .tojson = vl_api_ip6nd_send_router_solicitation_reply_t_tojson,
    .fromjson = vl_api_ip6nd_send_router_solicitation_reply_t_fromjson,
    .calc_size = vl_api_ip6nd_send_router_solicitation_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip6nd_send_router_solicitation", api_ip6nd_send_router_solicitation);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   ip6_nd_test_main_t * mainp = &ip6_nd_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("ip6_nd_deae73c7");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "ip6_nd plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
