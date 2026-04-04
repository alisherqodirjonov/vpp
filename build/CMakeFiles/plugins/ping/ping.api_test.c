#define vl_endianfun            /* define message structures */
#include "ping.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ping.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "ping.api.h"
#undef vl_printfun

#ifndef VL_API_WANT_PING_FINISHED_EVENTS_REPLY_T_HANDLER
static void
vl_api_want_ping_finished_events_reply_t_handler (vl_api_want_ping_finished_events_reply_t * mp) {
   vat_main_t * vam = ping_test_main.vat_main;
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
vl_api_ping_finished_event_t_handler (vl_api_ping_finished_event_t * mp) {
    vlib_cli_output(0, "ping_finished_event event called:");
    vlib_cli_output(0, "%U", vl_api_ping_finished_event_t_format, mp);
}
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_WANT_PING_FINISHED_EVENTS_REPLY + msg_id_base,
    .name = "want_ping_finished_events_reply",
    .handler = vl_api_want_ping_finished_events_reply_t_handler,
    .endian = vl_api_want_ping_finished_events_reply_t_endian,
    .format_fn = vl_api_want_ping_finished_events_reply_t_format,
    .size = sizeof(vl_api_want_ping_finished_events_reply_t),
    .traced = 1,
    .tojson = vl_api_want_ping_finished_events_reply_t_tojson,
    .fromjson = vl_api_want_ping_finished_events_reply_t_fromjson,
    .calc_size = vl_api_want_ping_finished_events_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "want_ping_finished_events", api_want_ping_finished_events);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PING_FINISHED_EVENT + msg_id_base,
    .name = "ping_finished_event",
    .handler = vl_api_ping_finished_event_t_handler,
    .endian = vl_api_ping_finished_event_t_endian,
    .format_fn = vl_api_ping_finished_event_t_format,
    .size = sizeof(vl_api_ping_finished_event_t),
    .traced = 1,
    .tojson = vl_api_ping_finished_event_t_tojson,
    .fromjson = vl_api_ping_finished_event_t_fromjson,
    .calc_size = vl_api_ping_finished_event_t_calc_size,
   });}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   ping_test_main_t * mainp = &ping_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("ping_0bdcc118");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "ping plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
