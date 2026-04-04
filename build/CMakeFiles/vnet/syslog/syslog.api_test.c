#define vl_endianfun            /* define message structures */
#include "syslog.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "syslog.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "syslog.api.h"
#undef vl_printfun

#ifndef VL_API_SYSLOG_SET_SENDER_REPLY_T_HANDLER
static void
vl_api_syslog_set_sender_reply_t_handler (vl_api_syslog_set_sender_reply_t * mp) {
   vat_main_t * vam = syslog_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_syslog_get_sender_reply_t_handler()) */
#ifndef VL_API_SYSLOG_SET_FILTER_REPLY_T_HANDLER
static void
vl_api_syslog_set_filter_reply_t_handler (vl_api_syslog_set_filter_reply_t * mp) {
   vat_main_t * vam = syslog_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_syslog_get_filter_reply_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SYSLOG_SET_SENDER_REPLY + msg_id_base,
    .name = "syslog_set_sender_reply",
    .handler = vl_api_syslog_set_sender_reply_t_handler,
    .endian = vl_api_syslog_set_sender_reply_t_endian,
    .format_fn = vl_api_syslog_set_sender_reply_t_format,
    .size = sizeof(vl_api_syslog_set_sender_reply_t),
    .traced = 1,
    .tojson = vl_api_syslog_set_sender_reply_t_tojson,
    .fromjson = vl_api_syslog_set_sender_reply_t_fromjson,
    .calc_size = vl_api_syslog_set_sender_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "syslog_set_sender", api_syslog_set_sender);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SYSLOG_GET_SENDER_REPLY + msg_id_base,
    .name = "syslog_get_sender_reply",
    .handler = vl_api_syslog_get_sender_reply_t_handler,
    .endian = vl_api_syslog_get_sender_reply_t_endian,
    .format_fn = vl_api_syslog_get_sender_reply_t_format,
    .size = sizeof(vl_api_syslog_get_sender_reply_t),
    .traced = 1,
    .tojson = vl_api_syslog_get_sender_reply_t_tojson,
    .fromjson = vl_api_syslog_get_sender_reply_t_fromjson,
    .calc_size = vl_api_syslog_get_sender_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "syslog_get_sender", api_syslog_get_sender);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SYSLOG_SET_FILTER_REPLY + msg_id_base,
    .name = "syslog_set_filter_reply",
    .handler = vl_api_syslog_set_filter_reply_t_handler,
    .endian = vl_api_syslog_set_filter_reply_t_endian,
    .format_fn = vl_api_syslog_set_filter_reply_t_format,
    .size = sizeof(vl_api_syslog_set_filter_reply_t),
    .traced = 1,
    .tojson = vl_api_syslog_set_filter_reply_t_tojson,
    .fromjson = vl_api_syslog_set_filter_reply_t_fromjson,
    .calc_size = vl_api_syslog_set_filter_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "syslog_set_filter", api_syslog_set_filter);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SYSLOG_GET_FILTER_REPLY + msg_id_base,
    .name = "syslog_get_filter_reply",
    .handler = vl_api_syslog_get_filter_reply_t_handler,
    .endian = vl_api_syslog_get_filter_reply_t_endian,
    .format_fn = vl_api_syslog_get_filter_reply_t_format,
    .size = sizeof(vl_api_syslog_get_filter_reply_t),
    .traced = 1,
    .tojson = vl_api_syslog_get_filter_reply_t_tojson,
    .fromjson = vl_api_syslog_get_filter_reply_t_fromjson,
    .calc_size = vl_api_syslog_get_filter_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "syslog_get_filter", api_syslog_get_filter);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   syslog_test_main_t * mainp = &syslog_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("syslog_9229df5b");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "syslog plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
