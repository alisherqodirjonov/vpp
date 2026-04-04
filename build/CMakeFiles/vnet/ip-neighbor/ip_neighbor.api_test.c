#define vl_endianfun            /* define message structures */
#include "ip_neighbor.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ip_neighbor.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "ip_neighbor.api.h"
#undef vl_printfun

#ifndef VL_API_WANT_IP_NEIGHBOR_EVENTS_REPLY_T_HANDLER
static void
vl_api_want_ip_neighbor_events_reply_t_handler (vl_api_want_ip_neighbor_events_reply_t * mp) {
   vat_main_t * vam = ip_neighbor_test_main.vat_main;
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
vl_api_ip_neighbor_event_t_handler (vl_api_ip_neighbor_event_t * mp) {
    vlib_cli_output(0, "ip_neighbor_event event called:");
    vlib_cli_output(0, "%U", vl_api_ip_neighbor_event_t_format, mp);
}
#ifndef VL_API_WANT_IP_NEIGHBOR_EVENTS_V2_REPLY_T_HANDLER
static void
vl_api_want_ip_neighbor_events_v2_reply_t_handler (vl_api_want_ip_neighbor_events_v2_reply_t * mp) {
   vat_main_t * vam = ip_neighbor_test_main.vat_main;
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
vl_api_ip_neighbor_event_v2_t_handler (vl_api_ip_neighbor_event_v2_t * mp) {
    vlib_cli_output(0, "ip_neighbor_event_v2 event called:");
    vlib_cli_output(0, "%U", vl_api_ip_neighbor_event_v2_t_format, mp);
}
/* Generation not supported (vl_api_ip_neighbor_add_del_reply_t_handler()) */
/* Generation not supported (vl_api_ip_neighbor_details_t_handler()) */
#ifndef VL_API_IP_NEIGHBOR_CONFIG_REPLY_T_HANDLER
static void
vl_api_ip_neighbor_config_reply_t_handler (vl_api_ip_neighbor_config_reply_t * mp) {
   vat_main_t * vam = ip_neighbor_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_ip_neighbor_config_get_reply_t_handler()) */
#ifndef VL_API_IP_NEIGHBOR_REPLACE_BEGIN_REPLY_T_HANDLER
static void
vl_api_ip_neighbor_replace_begin_reply_t_handler (vl_api_ip_neighbor_replace_begin_reply_t * mp) {
   vat_main_t * vam = ip_neighbor_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IP_NEIGHBOR_REPLACE_END_REPLY_T_HANDLER
static void
vl_api_ip_neighbor_replace_end_reply_t_handler (vl_api_ip_neighbor_replace_end_reply_t * mp) {
   vat_main_t * vam = ip_neighbor_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IP_NEIGHBOR_FLUSH_REPLY_T_HANDLER
static void
vl_api_ip_neighbor_flush_reply_t_handler (vl_api_ip_neighbor_flush_reply_t * mp) {
   vat_main_t * vam = ip_neighbor_test_main.vat_main;
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
    .id = VL_API_WANT_IP_NEIGHBOR_EVENTS_REPLY + msg_id_base,
    .name = "want_ip_neighbor_events_reply",
    .handler = vl_api_want_ip_neighbor_events_reply_t_handler,
    .endian = vl_api_want_ip_neighbor_events_reply_t_endian,
    .format_fn = vl_api_want_ip_neighbor_events_reply_t_format,
    .size = sizeof(vl_api_want_ip_neighbor_events_reply_t),
    .traced = 1,
    .tojson = vl_api_want_ip_neighbor_events_reply_t_tojson,
    .fromjson = vl_api_want_ip_neighbor_events_reply_t_fromjson,
    .calc_size = vl_api_want_ip_neighbor_events_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "want_ip_neighbor_events", api_want_ip_neighbor_events);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_NEIGHBOR_EVENT + msg_id_base,
    .name = "ip_neighbor_event",
    .handler = vl_api_ip_neighbor_event_t_handler,
    .endian = vl_api_ip_neighbor_event_t_endian,
    .format_fn = vl_api_ip_neighbor_event_t_format,
    .size = sizeof(vl_api_ip_neighbor_event_t),
    .traced = 1,
    .tojson = vl_api_ip_neighbor_event_t_tojson,
    .fromjson = vl_api_ip_neighbor_event_t_fromjson,
    .calc_size = vl_api_ip_neighbor_event_t_calc_size,
   });   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_WANT_IP_NEIGHBOR_EVENTS_V2_REPLY + msg_id_base,
    .name = "want_ip_neighbor_events_v2_reply",
    .handler = vl_api_want_ip_neighbor_events_v2_reply_t_handler,
    .endian = vl_api_want_ip_neighbor_events_v2_reply_t_endian,
    .format_fn = vl_api_want_ip_neighbor_events_v2_reply_t_format,
    .size = sizeof(vl_api_want_ip_neighbor_events_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_want_ip_neighbor_events_v2_reply_t_tojson,
    .fromjson = vl_api_want_ip_neighbor_events_v2_reply_t_fromjson,
    .calc_size = vl_api_want_ip_neighbor_events_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "want_ip_neighbor_events_v2", api_want_ip_neighbor_events_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_NEIGHBOR_EVENT_V2 + msg_id_base,
    .name = "ip_neighbor_event_v2",
    .handler = vl_api_ip_neighbor_event_v2_t_handler,
    .endian = vl_api_ip_neighbor_event_v2_t_endian,
    .format_fn = vl_api_ip_neighbor_event_v2_t_format,
    .size = sizeof(vl_api_ip_neighbor_event_v2_t),
    .traced = 1,
    .tojson = vl_api_ip_neighbor_event_v2_t_tojson,
    .fromjson = vl_api_ip_neighbor_event_v2_t_fromjson,
    .calc_size = vl_api_ip_neighbor_event_v2_t_calc_size,
   });   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_NEIGHBOR_ADD_DEL_REPLY + msg_id_base,
    .name = "ip_neighbor_add_del_reply",
    .handler = vl_api_ip_neighbor_add_del_reply_t_handler,
    .endian = vl_api_ip_neighbor_add_del_reply_t_endian,
    .format_fn = vl_api_ip_neighbor_add_del_reply_t_format,
    .size = sizeof(vl_api_ip_neighbor_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_neighbor_add_del_reply_t_tojson,
    .fromjson = vl_api_ip_neighbor_add_del_reply_t_fromjson,
    .calc_size = vl_api_ip_neighbor_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_neighbor_add_del", api_ip_neighbor_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_NEIGHBOR_DETAILS + msg_id_base,
    .name = "ip_neighbor_details",
    .handler = vl_api_ip_neighbor_details_t_handler,
    .endian = vl_api_ip_neighbor_details_t_endian,
    .format_fn = vl_api_ip_neighbor_details_t_format,
    .size = sizeof(vl_api_ip_neighbor_details_t),
    .traced = 1,
    .tojson = vl_api_ip_neighbor_details_t_tojson,
    .fromjson = vl_api_ip_neighbor_details_t_fromjson,
    .calc_size = vl_api_ip_neighbor_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_neighbor_dump", api_ip_neighbor_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_NEIGHBOR_CONFIG_REPLY + msg_id_base,
    .name = "ip_neighbor_config_reply",
    .handler = vl_api_ip_neighbor_config_reply_t_handler,
    .endian = vl_api_ip_neighbor_config_reply_t_endian,
    .format_fn = vl_api_ip_neighbor_config_reply_t_format,
    .size = sizeof(vl_api_ip_neighbor_config_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_neighbor_config_reply_t_tojson,
    .fromjson = vl_api_ip_neighbor_config_reply_t_fromjson,
    .calc_size = vl_api_ip_neighbor_config_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_neighbor_config", api_ip_neighbor_config);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_NEIGHBOR_CONFIG_GET_REPLY + msg_id_base,
    .name = "ip_neighbor_config_get_reply",
    .handler = vl_api_ip_neighbor_config_get_reply_t_handler,
    .endian = vl_api_ip_neighbor_config_get_reply_t_endian,
    .format_fn = vl_api_ip_neighbor_config_get_reply_t_format,
    .size = sizeof(vl_api_ip_neighbor_config_get_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_neighbor_config_get_reply_t_tojson,
    .fromjson = vl_api_ip_neighbor_config_get_reply_t_fromjson,
    .calc_size = vl_api_ip_neighbor_config_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_neighbor_config_get", api_ip_neighbor_config_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_NEIGHBOR_REPLACE_BEGIN_REPLY + msg_id_base,
    .name = "ip_neighbor_replace_begin_reply",
    .handler = vl_api_ip_neighbor_replace_begin_reply_t_handler,
    .endian = vl_api_ip_neighbor_replace_begin_reply_t_endian,
    .format_fn = vl_api_ip_neighbor_replace_begin_reply_t_format,
    .size = sizeof(vl_api_ip_neighbor_replace_begin_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_neighbor_replace_begin_reply_t_tojson,
    .fromjson = vl_api_ip_neighbor_replace_begin_reply_t_fromjson,
    .calc_size = vl_api_ip_neighbor_replace_begin_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_neighbor_replace_begin", api_ip_neighbor_replace_begin);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_NEIGHBOR_REPLACE_END_REPLY + msg_id_base,
    .name = "ip_neighbor_replace_end_reply",
    .handler = vl_api_ip_neighbor_replace_end_reply_t_handler,
    .endian = vl_api_ip_neighbor_replace_end_reply_t_endian,
    .format_fn = vl_api_ip_neighbor_replace_end_reply_t_format,
    .size = sizeof(vl_api_ip_neighbor_replace_end_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_neighbor_replace_end_reply_t_tojson,
    .fromjson = vl_api_ip_neighbor_replace_end_reply_t_fromjson,
    .calc_size = vl_api_ip_neighbor_replace_end_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_neighbor_replace_end", api_ip_neighbor_replace_end);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_NEIGHBOR_FLUSH_REPLY + msg_id_base,
    .name = "ip_neighbor_flush_reply",
    .handler = vl_api_ip_neighbor_flush_reply_t_handler,
    .endian = vl_api_ip_neighbor_flush_reply_t_endian,
    .format_fn = vl_api_ip_neighbor_flush_reply_t_format,
    .size = sizeof(vl_api_ip_neighbor_flush_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_neighbor_flush_reply_t_tojson,
    .fromjson = vl_api_ip_neighbor_flush_reply_t_fromjson,
    .calc_size = vl_api_ip_neighbor_flush_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_neighbor_flush", api_ip_neighbor_flush);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   ip_neighbor_test_main_t * mainp = &ip_neighbor_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("ip_neighbor_8bbbad7c");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "ip_neighbor plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
