#define vl_endianfun            /* define message structures */
#include "vhost_user.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "vhost_user.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "vhost_user.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_create_vhost_user_if_reply_t_handler()) */
#ifndef VL_API_MODIFY_VHOST_USER_IF_REPLY_T_HANDLER
static void
vl_api_modify_vhost_user_if_reply_t_handler (vl_api_modify_vhost_user_if_reply_t * mp) {
   vat_main_t * vam = vhost_user_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_create_vhost_user_if_v2_reply_t_handler()) */
#ifndef VL_API_MODIFY_VHOST_USER_IF_V2_REPLY_T_HANDLER
static void
vl_api_modify_vhost_user_if_v2_reply_t_handler (vl_api_modify_vhost_user_if_v2_reply_t * mp) {
   vat_main_t * vam = vhost_user_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_DELETE_VHOST_USER_IF_REPLY_T_HANDLER
static void
vl_api_delete_vhost_user_if_reply_t_handler (vl_api_delete_vhost_user_if_reply_t * mp) {
   vat_main_t * vam = vhost_user_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_sw_interface_vhost_user_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CREATE_VHOST_USER_IF_REPLY + msg_id_base,
    .name = "create_vhost_user_if_reply",
    .handler = vl_api_create_vhost_user_if_reply_t_handler,
    .endian = vl_api_create_vhost_user_if_reply_t_endian,
    .format_fn = vl_api_create_vhost_user_if_reply_t_format,
    .size = sizeof(vl_api_create_vhost_user_if_reply_t),
    .traced = 1,
    .tojson = vl_api_create_vhost_user_if_reply_t_tojson,
    .fromjson = vl_api_create_vhost_user_if_reply_t_fromjson,
    .calc_size = vl_api_create_vhost_user_if_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "create_vhost_user_if", api_create_vhost_user_if);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MODIFY_VHOST_USER_IF_REPLY + msg_id_base,
    .name = "modify_vhost_user_if_reply",
    .handler = vl_api_modify_vhost_user_if_reply_t_handler,
    .endian = vl_api_modify_vhost_user_if_reply_t_endian,
    .format_fn = vl_api_modify_vhost_user_if_reply_t_format,
    .size = sizeof(vl_api_modify_vhost_user_if_reply_t),
    .traced = 1,
    .tojson = vl_api_modify_vhost_user_if_reply_t_tojson,
    .fromjson = vl_api_modify_vhost_user_if_reply_t_fromjson,
    .calc_size = vl_api_modify_vhost_user_if_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "modify_vhost_user_if", api_modify_vhost_user_if);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CREATE_VHOST_USER_IF_V2_REPLY + msg_id_base,
    .name = "create_vhost_user_if_v2_reply",
    .handler = vl_api_create_vhost_user_if_v2_reply_t_handler,
    .endian = vl_api_create_vhost_user_if_v2_reply_t_endian,
    .format_fn = vl_api_create_vhost_user_if_v2_reply_t_format,
    .size = sizeof(vl_api_create_vhost_user_if_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_create_vhost_user_if_v2_reply_t_tojson,
    .fromjson = vl_api_create_vhost_user_if_v2_reply_t_fromjson,
    .calc_size = vl_api_create_vhost_user_if_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "create_vhost_user_if_v2", api_create_vhost_user_if_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MODIFY_VHOST_USER_IF_V2_REPLY + msg_id_base,
    .name = "modify_vhost_user_if_v2_reply",
    .handler = vl_api_modify_vhost_user_if_v2_reply_t_handler,
    .endian = vl_api_modify_vhost_user_if_v2_reply_t_endian,
    .format_fn = vl_api_modify_vhost_user_if_v2_reply_t_format,
    .size = sizeof(vl_api_modify_vhost_user_if_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_modify_vhost_user_if_v2_reply_t_tojson,
    .fromjson = vl_api_modify_vhost_user_if_v2_reply_t_fromjson,
    .calc_size = vl_api_modify_vhost_user_if_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "modify_vhost_user_if_v2", api_modify_vhost_user_if_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DELETE_VHOST_USER_IF_REPLY + msg_id_base,
    .name = "delete_vhost_user_if_reply",
    .handler = vl_api_delete_vhost_user_if_reply_t_handler,
    .endian = vl_api_delete_vhost_user_if_reply_t_endian,
    .format_fn = vl_api_delete_vhost_user_if_reply_t_format,
    .size = sizeof(vl_api_delete_vhost_user_if_reply_t),
    .traced = 1,
    .tojson = vl_api_delete_vhost_user_if_reply_t_tojson,
    .fromjson = vl_api_delete_vhost_user_if_reply_t_fromjson,
    .calc_size = vl_api_delete_vhost_user_if_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "delete_vhost_user_if", api_delete_vhost_user_if);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_VHOST_USER_DETAILS + msg_id_base,
    .name = "sw_interface_vhost_user_details",
    .handler = vl_api_sw_interface_vhost_user_details_t_handler,
    .endian = vl_api_sw_interface_vhost_user_details_t_endian,
    .format_fn = vl_api_sw_interface_vhost_user_details_t_format,
    .size = sizeof(vl_api_sw_interface_vhost_user_details_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_vhost_user_details_t_tojson,
    .fromjson = vl_api_sw_interface_vhost_user_details_t_fromjson,
    .calc_size = vl_api_sw_interface_vhost_user_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_vhost_user_dump", api_sw_interface_vhost_user_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   vhost_user_test_main_t * mainp = &vhost_user_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("vhost_user_30000028");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "vhost_user plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
