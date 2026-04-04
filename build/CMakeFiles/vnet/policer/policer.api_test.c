#define vl_endianfun            /* define message structures */
#include "policer.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "policer.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "policer.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_policer_details_t_handler()) */
#ifndef VL_API_POLICER_BIND_REPLY_T_HANDLER
static void
vl_api_policer_bind_reply_t_handler (vl_api_policer_bind_reply_t * mp) {
   vat_main_t * vam = policer_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_POLICER_BIND_V2_REPLY_T_HANDLER
static void
vl_api_policer_bind_v2_reply_t_handler (vl_api_policer_bind_v2_reply_t * mp) {
   vat_main_t * vam = policer_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_POLICER_INPUT_REPLY_T_HANDLER
static void
vl_api_policer_input_reply_t_handler (vl_api_policer_input_reply_t * mp) {
   vat_main_t * vam = policer_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_POLICER_INPUT_V2_REPLY_T_HANDLER
static void
vl_api_policer_input_v2_reply_t_handler (vl_api_policer_input_v2_reply_t * mp) {
   vat_main_t * vam = policer_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_POLICER_OUTPUT_REPLY_T_HANDLER
static void
vl_api_policer_output_reply_t_handler (vl_api_policer_output_reply_t * mp) {
   vat_main_t * vam = policer_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_POLICER_OUTPUT_V2_REPLY_T_HANDLER
static void
vl_api_policer_output_v2_reply_t_handler (vl_api_policer_output_v2_reply_t * mp) {
   vat_main_t * vam = policer_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_policer_add_del_reply_t_handler()) */
/* Generation not supported (vl_api_policer_add_reply_t_handler()) */
#ifndef VL_API_POLICER_DEL_REPLY_T_HANDLER
static void
vl_api_policer_del_reply_t_handler (vl_api_policer_del_reply_t * mp) {
   vat_main_t * vam = policer_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_POLICER_UPDATE_REPLY_T_HANDLER
static void
vl_api_policer_update_reply_t_handler (vl_api_policer_update_reply_t * mp) {
   vat_main_t * vam = policer_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_POLICER_RESET_REPLY_T_HANDLER
static void
vl_api_policer_reset_reply_t_handler (vl_api_policer_reset_reply_t * mp) {
   vat_main_t * vam = policer_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_policer_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_POLICER_DETAILS + msg_id_base,
    .name = "policer_details",
    .handler = vl_api_policer_details_t_handler,
    .endian = vl_api_policer_details_t_endian,
    .format_fn = vl_api_policer_details_t_format,
    .size = sizeof(vl_api_policer_details_t),
    .traced = 1,
    .tojson = vl_api_policer_details_t_tojson,
    .fromjson = vl_api_policer_details_t_fromjson,
    .calc_size = vl_api_policer_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "policer_dump_v2", api_policer_dump_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_POLICER_BIND_REPLY + msg_id_base,
    .name = "policer_bind_reply",
    .handler = vl_api_policer_bind_reply_t_handler,
    .endian = vl_api_policer_bind_reply_t_endian,
    .format_fn = vl_api_policer_bind_reply_t_format,
    .size = sizeof(vl_api_policer_bind_reply_t),
    .traced = 1,
    .tojson = vl_api_policer_bind_reply_t_tojson,
    .fromjson = vl_api_policer_bind_reply_t_fromjson,
    .calc_size = vl_api_policer_bind_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "policer_bind", api_policer_bind);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_POLICER_BIND_V2_REPLY + msg_id_base,
    .name = "policer_bind_v2_reply",
    .handler = vl_api_policer_bind_v2_reply_t_handler,
    .endian = vl_api_policer_bind_v2_reply_t_endian,
    .format_fn = vl_api_policer_bind_v2_reply_t_format,
    .size = sizeof(vl_api_policer_bind_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_policer_bind_v2_reply_t_tojson,
    .fromjson = vl_api_policer_bind_v2_reply_t_fromjson,
    .calc_size = vl_api_policer_bind_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "policer_bind_v2", api_policer_bind_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_POLICER_INPUT_REPLY + msg_id_base,
    .name = "policer_input_reply",
    .handler = vl_api_policer_input_reply_t_handler,
    .endian = vl_api_policer_input_reply_t_endian,
    .format_fn = vl_api_policer_input_reply_t_format,
    .size = sizeof(vl_api_policer_input_reply_t),
    .traced = 1,
    .tojson = vl_api_policer_input_reply_t_tojson,
    .fromjson = vl_api_policer_input_reply_t_fromjson,
    .calc_size = vl_api_policer_input_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "policer_input", api_policer_input);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_POLICER_INPUT_V2_REPLY + msg_id_base,
    .name = "policer_input_v2_reply",
    .handler = vl_api_policer_input_v2_reply_t_handler,
    .endian = vl_api_policer_input_v2_reply_t_endian,
    .format_fn = vl_api_policer_input_v2_reply_t_format,
    .size = sizeof(vl_api_policer_input_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_policer_input_v2_reply_t_tojson,
    .fromjson = vl_api_policer_input_v2_reply_t_fromjson,
    .calc_size = vl_api_policer_input_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "policer_input_v2", api_policer_input_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_POLICER_OUTPUT_REPLY + msg_id_base,
    .name = "policer_output_reply",
    .handler = vl_api_policer_output_reply_t_handler,
    .endian = vl_api_policer_output_reply_t_endian,
    .format_fn = vl_api_policer_output_reply_t_format,
    .size = sizeof(vl_api_policer_output_reply_t),
    .traced = 1,
    .tojson = vl_api_policer_output_reply_t_tojson,
    .fromjson = vl_api_policer_output_reply_t_fromjson,
    .calc_size = vl_api_policer_output_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "policer_output", api_policer_output);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_POLICER_OUTPUT_V2_REPLY + msg_id_base,
    .name = "policer_output_v2_reply",
    .handler = vl_api_policer_output_v2_reply_t_handler,
    .endian = vl_api_policer_output_v2_reply_t_endian,
    .format_fn = vl_api_policer_output_v2_reply_t_format,
    .size = sizeof(vl_api_policer_output_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_policer_output_v2_reply_t_tojson,
    .fromjson = vl_api_policer_output_v2_reply_t_fromjson,
    .calc_size = vl_api_policer_output_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "policer_output_v2", api_policer_output_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_POLICER_ADD_DEL_REPLY + msg_id_base,
    .name = "policer_add_del_reply",
    .handler = vl_api_policer_add_del_reply_t_handler,
    .endian = vl_api_policer_add_del_reply_t_endian,
    .format_fn = vl_api_policer_add_del_reply_t_format,
    .size = sizeof(vl_api_policer_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_policer_add_del_reply_t_tojson,
    .fromjson = vl_api_policer_add_del_reply_t_fromjson,
    .calc_size = vl_api_policer_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "policer_add_del", api_policer_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_POLICER_ADD_REPLY + msg_id_base,
    .name = "policer_add_reply",
    .handler = vl_api_policer_add_reply_t_handler,
    .endian = vl_api_policer_add_reply_t_endian,
    .format_fn = vl_api_policer_add_reply_t_format,
    .size = sizeof(vl_api_policer_add_reply_t),
    .traced = 1,
    .tojson = vl_api_policer_add_reply_t_tojson,
    .fromjson = vl_api_policer_add_reply_t_fromjson,
    .calc_size = vl_api_policer_add_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "policer_add", api_policer_add);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_POLICER_DEL_REPLY + msg_id_base,
    .name = "policer_del_reply",
    .handler = vl_api_policer_del_reply_t_handler,
    .endian = vl_api_policer_del_reply_t_endian,
    .format_fn = vl_api_policer_del_reply_t_format,
    .size = sizeof(vl_api_policer_del_reply_t),
    .traced = 1,
    .tojson = vl_api_policer_del_reply_t_tojson,
    .fromjson = vl_api_policer_del_reply_t_fromjson,
    .calc_size = vl_api_policer_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "policer_del", api_policer_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_POLICER_UPDATE_REPLY + msg_id_base,
    .name = "policer_update_reply",
    .handler = vl_api_policer_update_reply_t_handler,
    .endian = vl_api_policer_update_reply_t_endian,
    .format_fn = vl_api_policer_update_reply_t_format,
    .size = sizeof(vl_api_policer_update_reply_t),
    .traced = 1,
    .tojson = vl_api_policer_update_reply_t_tojson,
    .fromjson = vl_api_policer_update_reply_t_fromjson,
    .calc_size = vl_api_policer_update_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "policer_update", api_policer_update);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_POLICER_RESET_REPLY + msg_id_base,
    .name = "policer_reset_reply",
    .handler = vl_api_policer_reset_reply_t_handler,
    .endian = vl_api_policer_reset_reply_t_endian,
    .format_fn = vl_api_policer_reset_reply_t_format,
    .size = sizeof(vl_api_policer_reset_reply_t),
    .traced = 1,
    .tojson = vl_api_policer_reset_reply_t_tojson,
    .fromjson = vl_api_policer_reset_reply_t_fromjson,
    .calc_size = vl_api_policer_reset_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "policer_reset", api_policer_reset);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_POLICER_DETAILS + msg_id_base,
    .name = "policer_details",
    .handler = vl_api_policer_details_t_handler,
    .endian = vl_api_policer_details_t_endian,
    .format_fn = vl_api_policer_details_t_format,
    .size = sizeof(vl_api_policer_details_t),
    .traced = 1,
    .tojson = vl_api_policer_details_t_tojson,
    .fromjson = vl_api_policer_details_t_fromjson,
    .calc_size = vl_api_policer_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "policer_dump", api_policer_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   policer_test_main_t * mainp = &policer_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("policer_68c02844");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "policer plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
