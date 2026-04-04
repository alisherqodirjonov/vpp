#define vl_endianfun            /* define message structures */
#include "qos.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "qos.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "qos.api.h"
#undef vl_printfun

#ifndef VL_API_QOS_STORE_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_qos_store_enable_disable_reply_t_handler (vl_api_qos_store_enable_disable_reply_t * mp) {
   vat_main_t * vam = qos_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_qos_store_details_t_handler()) */
#ifndef VL_API_QOS_RECORD_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_qos_record_enable_disable_reply_t_handler (vl_api_qos_record_enable_disable_reply_t * mp) {
   vat_main_t * vam = qos_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_qos_record_details_t_handler()) */
#ifndef VL_API_QOS_EGRESS_MAP_UPDATE_REPLY_T_HANDLER
static void
vl_api_qos_egress_map_update_reply_t_handler (vl_api_qos_egress_map_update_reply_t * mp) {
   vat_main_t * vam = qos_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_QOS_EGRESS_MAP_DELETE_REPLY_T_HANDLER
static void
vl_api_qos_egress_map_delete_reply_t_handler (vl_api_qos_egress_map_delete_reply_t * mp) {
   vat_main_t * vam = qos_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_qos_egress_map_details_t_handler()) */
#ifndef VL_API_QOS_MARK_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_qos_mark_enable_disable_reply_t_handler (vl_api_qos_mark_enable_disable_reply_t * mp) {
   vat_main_t * vam = qos_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_qos_mark_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_QOS_STORE_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "qos_store_enable_disable_reply",
    .handler = vl_api_qos_store_enable_disable_reply_t_handler,
    .endian = vl_api_qos_store_enable_disable_reply_t_endian,
    .format_fn = vl_api_qos_store_enable_disable_reply_t_format,
    .size = sizeof(vl_api_qos_store_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_qos_store_enable_disable_reply_t_tojson,
    .fromjson = vl_api_qos_store_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_qos_store_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "qos_store_enable_disable", api_qos_store_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_QOS_STORE_DETAILS + msg_id_base,
    .name = "qos_store_details",
    .handler = vl_api_qos_store_details_t_handler,
    .endian = vl_api_qos_store_details_t_endian,
    .format_fn = vl_api_qos_store_details_t_format,
    .size = sizeof(vl_api_qos_store_details_t),
    .traced = 1,
    .tojson = vl_api_qos_store_details_t_tojson,
    .fromjson = vl_api_qos_store_details_t_fromjson,
    .calc_size = vl_api_qos_store_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "qos_store_dump", api_qos_store_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_QOS_RECORD_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "qos_record_enable_disable_reply",
    .handler = vl_api_qos_record_enable_disable_reply_t_handler,
    .endian = vl_api_qos_record_enable_disable_reply_t_endian,
    .format_fn = vl_api_qos_record_enable_disable_reply_t_format,
    .size = sizeof(vl_api_qos_record_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_qos_record_enable_disable_reply_t_tojson,
    .fromjson = vl_api_qos_record_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_qos_record_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "qos_record_enable_disable", api_qos_record_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_QOS_RECORD_DETAILS + msg_id_base,
    .name = "qos_record_details",
    .handler = vl_api_qos_record_details_t_handler,
    .endian = vl_api_qos_record_details_t_endian,
    .format_fn = vl_api_qos_record_details_t_format,
    .size = sizeof(vl_api_qos_record_details_t),
    .traced = 1,
    .tojson = vl_api_qos_record_details_t_tojson,
    .fromjson = vl_api_qos_record_details_t_fromjson,
    .calc_size = vl_api_qos_record_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "qos_record_dump", api_qos_record_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_QOS_EGRESS_MAP_UPDATE_REPLY + msg_id_base,
    .name = "qos_egress_map_update_reply",
    .handler = vl_api_qos_egress_map_update_reply_t_handler,
    .endian = vl_api_qos_egress_map_update_reply_t_endian,
    .format_fn = vl_api_qos_egress_map_update_reply_t_format,
    .size = sizeof(vl_api_qos_egress_map_update_reply_t),
    .traced = 1,
    .tojson = vl_api_qos_egress_map_update_reply_t_tojson,
    .fromjson = vl_api_qos_egress_map_update_reply_t_fromjson,
    .calc_size = vl_api_qos_egress_map_update_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "qos_egress_map_update", api_qos_egress_map_update);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_QOS_EGRESS_MAP_DELETE_REPLY + msg_id_base,
    .name = "qos_egress_map_delete_reply",
    .handler = vl_api_qos_egress_map_delete_reply_t_handler,
    .endian = vl_api_qos_egress_map_delete_reply_t_endian,
    .format_fn = vl_api_qos_egress_map_delete_reply_t_format,
    .size = sizeof(vl_api_qos_egress_map_delete_reply_t),
    .traced = 1,
    .tojson = vl_api_qos_egress_map_delete_reply_t_tojson,
    .fromjson = vl_api_qos_egress_map_delete_reply_t_fromjson,
    .calc_size = vl_api_qos_egress_map_delete_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "qos_egress_map_delete", api_qos_egress_map_delete);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_QOS_EGRESS_MAP_DETAILS + msg_id_base,
    .name = "qos_egress_map_details",
    .handler = vl_api_qos_egress_map_details_t_handler,
    .endian = vl_api_qos_egress_map_details_t_endian,
    .format_fn = vl_api_qos_egress_map_details_t_format,
    .size = sizeof(vl_api_qos_egress_map_details_t),
    .traced = 1,
    .tojson = vl_api_qos_egress_map_details_t_tojson,
    .fromjson = vl_api_qos_egress_map_details_t_fromjson,
    .calc_size = vl_api_qos_egress_map_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "qos_egress_map_dump", api_qos_egress_map_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_QOS_MARK_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "qos_mark_enable_disable_reply",
    .handler = vl_api_qos_mark_enable_disable_reply_t_handler,
    .endian = vl_api_qos_mark_enable_disable_reply_t_endian,
    .format_fn = vl_api_qos_mark_enable_disable_reply_t_format,
    .size = sizeof(vl_api_qos_mark_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_qos_mark_enable_disable_reply_t_tojson,
    .fromjson = vl_api_qos_mark_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_qos_mark_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "qos_mark_enable_disable", api_qos_mark_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_QOS_MARK_DETAILS + msg_id_base,
    .name = "qos_mark_details",
    .handler = vl_api_qos_mark_details_t_handler,
    .endian = vl_api_qos_mark_details_t_endian,
    .format_fn = vl_api_qos_mark_details_t_format,
    .size = sizeof(vl_api_qos_mark_details_t),
    .traced = 1,
    .tojson = vl_api_qos_mark_details_t_tojson,
    .fromjson = vl_api_qos_mark_details_t_fromjson,
    .calc_size = vl_api_qos_mark_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "qos_mark_dump", api_qos_mark_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   qos_test_main_t * mainp = &qos_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("qos_ad857fa4");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "qos plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
