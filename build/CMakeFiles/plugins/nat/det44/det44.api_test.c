#define vl_endianfun            /* define message structures */
#include "det44.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "det44.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "det44.api.h"
#undef vl_printfun

#ifndef VL_API_DET44_PLUGIN_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_det44_plugin_enable_disable_reply_t_handler (vl_api_det44_plugin_enable_disable_reply_t * mp) {
   vat_main_t * vam = det44_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_DET44_INTERFACE_ADD_DEL_FEATURE_REPLY_T_HANDLER
static void
vl_api_det44_interface_add_del_feature_reply_t_handler (vl_api_det44_interface_add_del_feature_reply_t * mp) {
   vat_main_t * vam = det44_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_det44_interface_details_t_handler()) */
#ifndef VL_API_DET44_ADD_DEL_MAP_REPLY_T_HANDLER
static void
vl_api_det44_add_del_map_reply_t_handler (vl_api_det44_add_del_map_reply_t * mp) {
   vat_main_t * vam = det44_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_det44_forward_reply_t_handler()) */
/* Generation not supported (vl_api_det44_reverse_reply_t_handler()) */
/* Generation not supported (vl_api_det44_map_details_t_handler()) */
#ifndef VL_API_DET44_CLOSE_SESSION_OUT_REPLY_T_HANDLER
static void
vl_api_det44_close_session_out_reply_t_handler (vl_api_det44_close_session_out_reply_t * mp) {
   vat_main_t * vam = det44_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_DET44_CLOSE_SESSION_IN_REPLY_T_HANDLER
static void
vl_api_det44_close_session_in_reply_t_handler (vl_api_det44_close_session_in_reply_t * mp) {
   vat_main_t * vam = det44_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_det44_session_details_t_handler()) */
#ifndef VL_API_DET44_SET_TIMEOUTS_REPLY_T_HANDLER
static void
vl_api_det44_set_timeouts_reply_t_handler (vl_api_det44_set_timeouts_reply_t * mp) {
   vat_main_t * vam = det44_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_det44_get_timeouts_reply_t_handler()) */
#ifndef VL_API_NAT_DET_ADD_DEL_MAP_REPLY_T_HANDLER
static void
vl_api_nat_det_add_del_map_reply_t_handler (vl_api_nat_det_add_del_map_reply_t * mp) {
   vat_main_t * vam = det44_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat_det_forward_reply_t_handler()) */
/* Generation not supported (vl_api_nat_det_reverse_reply_t_handler()) */
/* Generation not supported (vl_api_nat_det_map_details_t_handler()) */
#ifndef VL_API_NAT_DET_CLOSE_SESSION_OUT_REPLY_T_HANDLER
static void
vl_api_nat_det_close_session_out_reply_t_handler (vl_api_nat_det_close_session_out_reply_t * mp) {
   vat_main_t * vam = det44_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NAT_DET_CLOSE_SESSION_IN_REPLY_T_HANDLER
static void
vl_api_nat_det_close_session_in_reply_t_handler (vl_api_nat_det_close_session_in_reply_t * mp) {
   vat_main_t * vam = det44_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat_det_session_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DET44_PLUGIN_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "det44_plugin_enable_disable_reply",
    .handler = vl_api_det44_plugin_enable_disable_reply_t_handler,
    .endian = vl_api_det44_plugin_enable_disable_reply_t_endian,
    .format_fn = vl_api_det44_plugin_enable_disable_reply_t_format,
    .size = sizeof(vl_api_det44_plugin_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_det44_plugin_enable_disable_reply_t_tojson,
    .fromjson = vl_api_det44_plugin_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_det44_plugin_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "det44_plugin_enable_disable", api_det44_plugin_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DET44_INTERFACE_ADD_DEL_FEATURE_REPLY + msg_id_base,
    .name = "det44_interface_add_del_feature_reply",
    .handler = vl_api_det44_interface_add_del_feature_reply_t_handler,
    .endian = vl_api_det44_interface_add_del_feature_reply_t_endian,
    .format_fn = vl_api_det44_interface_add_del_feature_reply_t_format,
    .size = sizeof(vl_api_det44_interface_add_del_feature_reply_t),
    .traced = 1,
    .tojson = vl_api_det44_interface_add_del_feature_reply_t_tojson,
    .fromjson = vl_api_det44_interface_add_del_feature_reply_t_fromjson,
    .calc_size = vl_api_det44_interface_add_del_feature_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "det44_interface_add_del_feature", api_det44_interface_add_del_feature);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DET44_INTERFACE_DETAILS + msg_id_base,
    .name = "det44_interface_details",
    .handler = vl_api_det44_interface_details_t_handler,
    .endian = vl_api_det44_interface_details_t_endian,
    .format_fn = vl_api_det44_interface_details_t_format,
    .size = sizeof(vl_api_det44_interface_details_t),
    .traced = 1,
    .tojson = vl_api_det44_interface_details_t_tojson,
    .fromjson = vl_api_det44_interface_details_t_fromjson,
    .calc_size = vl_api_det44_interface_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "det44_interface_dump", api_det44_interface_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DET44_ADD_DEL_MAP_REPLY + msg_id_base,
    .name = "det44_add_del_map_reply",
    .handler = vl_api_det44_add_del_map_reply_t_handler,
    .endian = vl_api_det44_add_del_map_reply_t_endian,
    .format_fn = vl_api_det44_add_del_map_reply_t_format,
    .size = sizeof(vl_api_det44_add_del_map_reply_t),
    .traced = 1,
    .tojson = vl_api_det44_add_del_map_reply_t_tojson,
    .fromjson = vl_api_det44_add_del_map_reply_t_fromjson,
    .calc_size = vl_api_det44_add_del_map_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "det44_add_del_map", api_det44_add_del_map);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DET44_FORWARD_REPLY + msg_id_base,
    .name = "det44_forward_reply",
    .handler = vl_api_det44_forward_reply_t_handler,
    .endian = vl_api_det44_forward_reply_t_endian,
    .format_fn = vl_api_det44_forward_reply_t_format,
    .size = sizeof(vl_api_det44_forward_reply_t),
    .traced = 1,
    .tojson = vl_api_det44_forward_reply_t_tojson,
    .fromjson = vl_api_det44_forward_reply_t_fromjson,
    .calc_size = vl_api_det44_forward_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "det44_forward", api_det44_forward);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DET44_REVERSE_REPLY + msg_id_base,
    .name = "det44_reverse_reply",
    .handler = vl_api_det44_reverse_reply_t_handler,
    .endian = vl_api_det44_reverse_reply_t_endian,
    .format_fn = vl_api_det44_reverse_reply_t_format,
    .size = sizeof(vl_api_det44_reverse_reply_t),
    .traced = 1,
    .tojson = vl_api_det44_reverse_reply_t_tojson,
    .fromjson = vl_api_det44_reverse_reply_t_fromjson,
    .calc_size = vl_api_det44_reverse_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "det44_reverse", api_det44_reverse);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DET44_MAP_DETAILS + msg_id_base,
    .name = "det44_map_details",
    .handler = vl_api_det44_map_details_t_handler,
    .endian = vl_api_det44_map_details_t_endian,
    .format_fn = vl_api_det44_map_details_t_format,
    .size = sizeof(vl_api_det44_map_details_t),
    .traced = 1,
    .tojson = vl_api_det44_map_details_t_tojson,
    .fromjson = vl_api_det44_map_details_t_fromjson,
    .calc_size = vl_api_det44_map_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "det44_map_dump", api_det44_map_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DET44_CLOSE_SESSION_OUT_REPLY + msg_id_base,
    .name = "det44_close_session_out_reply",
    .handler = vl_api_det44_close_session_out_reply_t_handler,
    .endian = vl_api_det44_close_session_out_reply_t_endian,
    .format_fn = vl_api_det44_close_session_out_reply_t_format,
    .size = sizeof(vl_api_det44_close_session_out_reply_t),
    .traced = 1,
    .tojson = vl_api_det44_close_session_out_reply_t_tojson,
    .fromjson = vl_api_det44_close_session_out_reply_t_fromjson,
    .calc_size = vl_api_det44_close_session_out_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "det44_close_session_out", api_det44_close_session_out);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DET44_CLOSE_SESSION_IN_REPLY + msg_id_base,
    .name = "det44_close_session_in_reply",
    .handler = vl_api_det44_close_session_in_reply_t_handler,
    .endian = vl_api_det44_close_session_in_reply_t_endian,
    .format_fn = vl_api_det44_close_session_in_reply_t_format,
    .size = sizeof(vl_api_det44_close_session_in_reply_t),
    .traced = 1,
    .tojson = vl_api_det44_close_session_in_reply_t_tojson,
    .fromjson = vl_api_det44_close_session_in_reply_t_fromjson,
    .calc_size = vl_api_det44_close_session_in_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "det44_close_session_in", api_det44_close_session_in);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DET44_SESSION_DETAILS + msg_id_base,
    .name = "det44_session_details",
    .handler = vl_api_det44_session_details_t_handler,
    .endian = vl_api_det44_session_details_t_endian,
    .format_fn = vl_api_det44_session_details_t_format,
    .size = sizeof(vl_api_det44_session_details_t),
    .traced = 1,
    .tojson = vl_api_det44_session_details_t_tojson,
    .fromjson = vl_api_det44_session_details_t_fromjson,
    .calc_size = vl_api_det44_session_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "det44_session_dump", api_det44_session_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DET44_SET_TIMEOUTS_REPLY + msg_id_base,
    .name = "det44_set_timeouts_reply",
    .handler = vl_api_det44_set_timeouts_reply_t_handler,
    .endian = vl_api_det44_set_timeouts_reply_t_endian,
    .format_fn = vl_api_det44_set_timeouts_reply_t_format,
    .size = sizeof(vl_api_det44_set_timeouts_reply_t),
    .traced = 1,
    .tojson = vl_api_det44_set_timeouts_reply_t_tojson,
    .fromjson = vl_api_det44_set_timeouts_reply_t_fromjson,
    .calc_size = vl_api_det44_set_timeouts_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "det44_set_timeouts", api_det44_set_timeouts);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DET44_GET_TIMEOUTS_REPLY + msg_id_base,
    .name = "det44_get_timeouts_reply",
    .handler = vl_api_det44_get_timeouts_reply_t_handler,
    .endian = vl_api_det44_get_timeouts_reply_t_endian,
    .format_fn = vl_api_det44_get_timeouts_reply_t_format,
    .size = sizeof(vl_api_det44_get_timeouts_reply_t),
    .traced = 1,
    .tojson = vl_api_det44_get_timeouts_reply_t_tojson,
    .fromjson = vl_api_det44_get_timeouts_reply_t_fromjson,
    .calc_size = vl_api_det44_get_timeouts_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "det44_get_timeouts", api_det44_get_timeouts);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT_DET_ADD_DEL_MAP_REPLY + msg_id_base,
    .name = "nat_det_add_del_map_reply",
    .handler = vl_api_nat_det_add_del_map_reply_t_handler,
    .endian = vl_api_nat_det_add_del_map_reply_t_endian,
    .format_fn = vl_api_nat_det_add_del_map_reply_t_format,
    .size = sizeof(vl_api_nat_det_add_del_map_reply_t),
    .traced = 1,
    .tojson = vl_api_nat_det_add_del_map_reply_t_tojson,
    .fromjson = vl_api_nat_det_add_del_map_reply_t_fromjson,
    .calc_size = vl_api_nat_det_add_del_map_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat_det_add_del_map", api_nat_det_add_del_map);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT_DET_FORWARD_REPLY + msg_id_base,
    .name = "nat_det_forward_reply",
    .handler = vl_api_nat_det_forward_reply_t_handler,
    .endian = vl_api_nat_det_forward_reply_t_endian,
    .format_fn = vl_api_nat_det_forward_reply_t_format,
    .size = sizeof(vl_api_nat_det_forward_reply_t),
    .traced = 1,
    .tojson = vl_api_nat_det_forward_reply_t_tojson,
    .fromjson = vl_api_nat_det_forward_reply_t_fromjson,
    .calc_size = vl_api_nat_det_forward_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat_det_forward", api_nat_det_forward);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT_DET_REVERSE_REPLY + msg_id_base,
    .name = "nat_det_reverse_reply",
    .handler = vl_api_nat_det_reverse_reply_t_handler,
    .endian = vl_api_nat_det_reverse_reply_t_endian,
    .format_fn = vl_api_nat_det_reverse_reply_t_format,
    .size = sizeof(vl_api_nat_det_reverse_reply_t),
    .traced = 1,
    .tojson = vl_api_nat_det_reverse_reply_t_tojson,
    .fromjson = vl_api_nat_det_reverse_reply_t_fromjson,
    .calc_size = vl_api_nat_det_reverse_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat_det_reverse", api_nat_det_reverse);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT_DET_MAP_DETAILS + msg_id_base,
    .name = "nat_det_map_details",
    .handler = vl_api_nat_det_map_details_t_handler,
    .endian = vl_api_nat_det_map_details_t_endian,
    .format_fn = vl_api_nat_det_map_details_t_format,
    .size = sizeof(vl_api_nat_det_map_details_t),
    .traced = 1,
    .tojson = vl_api_nat_det_map_details_t_tojson,
    .fromjson = vl_api_nat_det_map_details_t_fromjson,
    .calc_size = vl_api_nat_det_map_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat_det_map_dump", api_nat_det_map_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT_DET_CLOSE_SESSION_OUT_REPLY + msg_id_base,
    .name = "nat_det_close_session_out_reply",
    .handler = vl_api_nat_det_close_session_out_reply_t_handler,
    .endian = vl_api_nat_det_close_session_out_reply_t_endian,
    .format_fn = vl_api_nat_det_close_session_out_reply_t_format,
    .size = sizeof(vl_api_nat_det_close_session_out_reply_t),
    .traced = 1,
    .tojson = vl_api_nat_det_close_session_out_reply_t_tojson,
    .fromjson = vl_api_nat_det_close_session_out_reply_t_fromjson,
    .calc_size = vl_api_nat_det_close_session_out_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat_det_close_session_out", api_nat_det_close_session_out);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT_DET_CLOSE_SESSION_IN_REPLY + msg_id_base,
    .name = "nat_det_close_session_in_reply",
    .handler = vl_api_nat_det_close_session_in_reply_t_handler,
    .endian = vl_api_nat_det_close_session_in_reply_t_endian,
    .format_fn = vl_api_nat_det_close_session_in_reply_t_format,
    .size = sizeof(vl_api_nat_det_close_session_in_reply_t),
    .traced = 1,
    .tojson = vl_api_nat_det_close_session_in_reply_t_tojson,
    .fromjson = vl_api_nat_det_close_session_in_reply_t_fromjson,
    .calc_size = vl_api_nat_det_close_session_in_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat_det_close_session_in", api_nat_det_close_session_in);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT_DET_SESSION_DETAILS + msg_id_base,
    .name = "nat_det_session_details",
    .handler = vl_api_nat_det_session_details_t_handler,
    .endian = vl_api_nat_det_session_details_t_endian,
    .format_fn = vl_api_nat_det_session_details_t_format,
    .size = sizeof(vl_api_nat_det_session_details_t),
    .traced = 1,
    .tojson = vl_api_nat_det_session_details_t_tojson,
    .fromjson = vl_api_nat_det_session_details_t_fromjson,
    .calc_size = vl_api_nat_det_session_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat_det_session_dump", api_nat_det_session_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   det44_test_main_t * mainp = &det44_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("det44_ee5882b1");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "det44 plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
