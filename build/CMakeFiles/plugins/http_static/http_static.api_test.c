#define vl_endianfun            /* define message structures */
#include "http_static.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "http_static.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "http_static.api.h"
#undef vl_printfun

#ifndef VL_API_HTTP_STATIC_ENABLE_V4_REPLY_T_HANDLER
static void
vl_api_http_static_enable_v4_reply_t_handler (vl_api_http_static_enable_v4_reply_t * mp) {
   vat_main_t * vam = http_static_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_HTTP_STATIC_ENABLE_V5_REPLY_T_HANDLER
static void
vl_api_http_static_enable_v5_reply_t_handler (vl_api_http_static_enable_v5_reply_t * mp) {
   vat_main_t * vam = http_static_test_main.vat_main;
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
    .id = VL_API_HTTP_STATIC_ENABLE_V4_REPLY + msg_id_base,
    .name = "http_static_enable_v4_reply",
    .handler = vl_api_http_static_enable_v4_reply_t_handler,
    .endian = vl_api_http_static_enable_v4_reply_t_endian,
    .format_fn = vl_api_http_static_enable_v4_reply_t_format,
    .size = sizeof(vl_api_http_static_enable_v4_reply_t),
    .traced = 1,
    .tojson = vl_api_http_static_enable_v4_reply_t_tojson,
    .fromjson = vl_api_http_static_enable_v4_reply_t_fromjson,
    .calc_size = vl_api_http_static_enable_v4_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "http_static_enable_v4", api_http_static_enable_v4);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_HTTP_STATIC_ENABLE_V5_REPLY + msg_id_base,
    .name = "http_static_enable_v5_reply",
    .handler = vl_api_http_static_enable_v5_reply_t_handler,
    .endian = vl_api_http_static_enable_v5_reply_t_endian,
    .format_fn = vl_api_http_static_enable_v5_reply_t_format,
    .size = sizeof(vl_api_http_static_enable_v5_reply_t),
    .traced = 1,
    .tojson = vl_api_http_static_enable_v5_reply_t_tojson,
    .fromjson = vl_api_http_static_enable_v5_reply_t_fromjson,
    .calc_size = vl_api_http_static_enable_v5_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "http_static_enable_v5", api_http_static_enable_v5);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   http_static_test_main_t * mainp = &http_static_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("http_static_a4be530f");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "http_static plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
