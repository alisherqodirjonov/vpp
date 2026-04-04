#define vl_endianfun            /* define message structures */
#include "punt.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "punt.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "punt.api.h"
#undef vl_printfun

#ifndef VL_API_SET_PUNT_REPLY_T_HANDLER
static void
vl_api_set_punt_reply_t_handler (vl_api_set_punt_reply_t * mp) {
   vat_main_t * vam = punt_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_punt_socket_register_reply_t_handler()) */
/* Generation not supported (vl_api_punt_socket_details_t_handler()) */
#ifndef VL_API_PUNT_SOCKET_DEREGISTER_REPLY_T_HANDLER
static void
vl_api_punt_socket_deregister_reply_t_handler (vl_api_punt_socket_deregister_reply_t * mp) {
   vat_main_t * vam = punt_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_punt_reason_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SET_PUNT_REPLY + msg_id_base,
    .name = "set_punt_reply",
    .handler = vl_api_set_punt_reply_t_handler,
    .endian = vl_api_set_punt_reply_t_endian,
    .format_fn = vl_api_set_punt_reply_t_format,
    .size = sizeof(vl_api_set_punt_reply_t),
    .traced = 1,
    .tojson = vl_api_set_punt_reply_t_tojson,
    .fromjson = vl_api_set_punt_reply_t_fromjson,
    .calc_size = vl_api_set_punt_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "set_punt", api_set_punt);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PUNT_SOCKET_REGISTER_REPLY + msg_id_base,
    .name = "punt_socket_register_reply",
    .handler = vl_api_punt_socket_register_reply_t_handler,
    .endian = vl_api_punt_socket_register_reply_t_endian,
    .format_fn = vl_api_punt_socket_register_reply_t_format,
    .size = sizeof(vl_api_punt_socket_register_reply_t),
    .traced = 1,
    .tojson = vl_api_punt_socket_register_reply_t_tojson,
    .fromjson = vl_api_punt_socket_register_reply_t_fromjson,
    .calc_size = vl_api_punt_socket_register_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "punt_socket_register", api_punt_socket_register);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PUNT_SOCKET_DETAILS + msg_id_base,
    .name = "punt_socket_details",
    .handler = vl_api_punt_socket_details_t_handler,
    .endian = vl_api_punt_socket_details_t_endian,
    .format_fn = vl_api_punt_socket_details_t_format,
    .size = sizeof(vl_api_punt_socket_details_t),
    .traced = 1,
    .tojson = vl_api_punt_socket_details_t_tojson,
    .fromjson = vl_api_punt_socket_details_t_fromjson,
    .calc_size = vl_api_punt_socket_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "punt_socket_dump", api_punt_socket_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PUNT_SOCKET_DEREGISTER_REPLY + msg_id_base,
    .name = "punt_socket_deregister_reply",
    .handler = vl_api_punt_socket_deregister_reply_t_handler,
    .endian = vl_api_punt_socket_deregister_reply_t_endian,
    .format_fn = vl_api_punt_socket_deregister_reply_t_format,
    .size = sizeof(vl_api_punt_socket_deregister_reply_t),
    .traced = 1,
    .tojson = vl_api_punt_socket_deregister_reply_t_tojson,
    .fromjson = vl_api_punt_socket_deregister_reply_t_fromjson,
    .calc_size = vl_api_punt_socket_deregister_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "punt_socket_deregister", api_punt_socket_deregister);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PUNT_REASON_DETAILS + msg_id_base,
    .name = "punt_reason_details",
    .handler = vl_api_punt_reason_details_t_handler,
    .endian = vl_api_punt_reason_details_t_endian,
    .format_fn = vl_api_punt_reason_details_t_format,
    .size = sizeof(vl_api_punt_reason_details_t),
    .traced = 1,
    .tojson = vl_api_punt_reason_details_t_tojson,
    .fromjson = vl_api_punt_reason_details_t_fromjson,
    .calc_size = vl_api_punt_reason_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "punt_reason_dump", api_punt_reason_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   punt_test_main_t * mainp = &punt_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("punt_692c7d27");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "punt plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
