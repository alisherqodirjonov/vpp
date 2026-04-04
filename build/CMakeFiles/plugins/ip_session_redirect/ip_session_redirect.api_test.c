#define vl_endianfun            /* define message structures */
#include "ip_session_redirect.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ip_session_redirect.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "ip_session_redirect.api.h"
#undef vl_printfun

#ifndef VL_API_IP_SESSION_REDIRECT_ADD_REPLY_T_HANDLER
static void
vl_api_ip_session_redirect_add_reply_t_handler (vl_api_ip_session_redirect_add_reply_t * mp) {
   vat_main_t * vam = ip_session_redirect_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IP_SESSION_REDIRECT_ADD_V2_REPLY_T_HANDLER
static void
vl_api_ip_session_redirect_add_v2_reply_t_handler (vl_api_ip_session_redirect_add_v2_reply_t * mp) {
   vat_main_t * vam = ip_session_redirect_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IP_SESSION_REDIRECT_DEL_REPLY_T_HANDLER
static void
vl_api_ip_session_redirect_del_reply_t_handler (vl_api_ip_session_redirect_del_reply_t * mp) {
   vat_main_t * vam = ip_session_redirect_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_ip_session_redirect_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_SESSION_REDIRECT_ADD_REPLY + msg_id_base,
    .name = "ip_session_redirect_add_reply",
    .handler = vl_api_ip_session_redirect_add_reply_t_handler,
    .endian = vl_api_ip_session_redirect_add_reply_t_endian,
    .format_fn = vl_api_ip_session_redirect_add_reply_t_format,
    .size = sizeof(vl_api_ip_session_redirect_add_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_session_redirect_add_reply_t_tojson,
    .fromjson = vl_api_ip_session_redirect_add_reply_t_fromjson,
    .calc_size = vl_api_ip_session_redirect_add_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_session_redirect_add", api_ip_session_redirect_add);
   hash_set_mem (vam->help_by_name, "ip_session_redirect_add", "table <index> match <match> via <path>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_SESSION_REDIRECT_ADD_V2_REPLY + msg_id_base,
    .name = "ip_session_redirect_add_v2_reply",
    .handler = vl_api_ip_session_redirect_add_v2_reply_t_handler,
    .endian = vl_api_ip_session_redirect_add_v2_reply_t_endian,
    .format_fn = vl_api_ip_session_redirect_add_v2_reply_t_format,
    .size = sizeof(vl_api_ip_session_redirect_add_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_session_redirect_add_v2_reply_t_tojson,
    .fromjson = vl_api_ip_session_redirect_add_v2_reply_t_fromjson,
    .calc_size = vl_api_ip_session_redirect_add_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_session_redirect_add_v2", api_ip_session_redirect_add_v2);
   hash_set_mem (vam->help_by_name, "ip_session_redirect_add_v2", "table <index> match <match> via <path>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_SESSION_REDIRECT_DEL_REPLY + msg_id_base,
    .name = "ip_session_redirect_del_reply",
    .handler = vl_api_ip_session_redirect_del_reply_t_handler,
    .endian = vl_api_ip_session_redirect_del_reply_t_endian,
    .format_fn = vl_api_ip_session_redirect_del_reply_t_format,
    .size = sizeof(vl_api_ip_session_redirect_del_reply_t),
    .traced = 1,
    .tojson = vl_api_ip_session_redirect_del_reply_t_tojson,
    .fromjson = vl_api_ip_session_redirect_del_reply_t_fromjson,
    .calc_size = vl_api_ip_session_redirect_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_session_redirect_del", api_ip_session_redirect_del);
   hash_set_mem (vam->help_by_name, "ip_session_redirect_del", "session-index <index> table <index> match <match>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IP_SESSION_REDIRECT_DETAILS + msg_id_base,
    .name = "ip_session_redirect_details",
    .handler = vl_api_ip_session_redirect_details_t_handler,
    .endian = vl_api_ip_session_redirect_details_t_endian,
    .format_fn = vl_api_ip_session_redirect_details_t_format,
    .size = sizeof(vl_api_ip_session_redirect_details_t),
    .traced = 1,
    .tojson = vl_api_ip_session_redirect_details_t_tojson,
    .fromjson = vl_api_ip_session_redirect_details_t_fromjson,
    .calc_size = vl_api_ip_session_redirect_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ip_session_redirect_dump", api_ip_session_redirect_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   ip_session_redirect_test_main_t * mainp = &ip_session_redirect_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("ip_session_redirect_53620f15");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "ip_session_redirect plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
