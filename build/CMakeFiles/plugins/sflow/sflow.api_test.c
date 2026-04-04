#define vl_endianfun            /* define message structures */
#include "sflow.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "sflow.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "sflow.api.h"
#undef vl_printfun

#ifndef VL_API_SFLOW_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_sflow_enable_disable_reply_t_handler (vl_api_sflow_enable_disable_reply_t * mp) {
   vat_main_t * vam = sflow_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_sflow_sampling_rate_get_reply_t_handler()) */
#ifndef VL_API_SFLOW_SAMPLING_RATE_SET_REPLY_T_HANDLER
static void
vl_api_sflow_sampling_rate_set_reply_t_handler (vl_api_sflow_sampling_rate_set_reply_t * mp) {
   vat_main_t * vam = sflow_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SFLOW_POLLING_INTERVAL_SET_REPLY_T_HANDLER
static void
vl_api_sflow_polling_interval_set_reply_t_handler (vl_api_sflow_polling_interval_set_reply_t * mp) {
   vat_main_t * vam = sflow_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_sflow_polling_interval_get_reply_t_handler()) */
#ifndef VL_API_SFLOW_HEADER_BYTES_SET_REPLY_T_HANDLER
static void
vl_api_sflow_header_bytes_set_reply_t_handler (vl_api_sflow_header_bytes_set_reply_t * mp) {
   vat_main_t * vam = sflow_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_sflow_header_bytes_get_reply_t_handler()) */
#ifndef VL_API_SFLOW_DIRECTION_SET_REPLY_T_HANDLER
static void
vl_api_sflow_direction_set_reply_t_handler (vl_api_sflow_direction_set_reply_t * mp) {
   vat_main_t * vam = sflow_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_sflow_direction_get_reply_t_handler()) */
#ifndef VL_API_SFLOW_DROP_MONITORING_SET_REPLY_T_HANDLER
static void
vl_api_sflow_drop_monitoring_set_reply_t_handler (vl_api_sflow_drop_monitoring_set_reply_t * mp) {
   vat_main_t * vam = sflow_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_sflow_drop_monitoring_get_reply_t_handler()) */
/* Generation not supported (vl_api_sflow_interface_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SFLOW_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "sflow_enable_disable_reply",
    .handler = vl_api_sflow_enable_disable_reply_t_handler,
    .endian = vl_api_sflow_enable_disable_reply_t_endian,
    .format_fn = vl_api_sflow_enable_disable_reply_t_format,
    .size = sizeof(vl_api_sflow_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_sflow_enable_disable_reply_t_tojson,
    .fromjson = vl_api_sflow_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_sflow_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sflow_enable_disable", api_sflow_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SFLOW_SAMPLING_RATE_GET_REPLY + msg_id_base,
    .name = "sflow_sampling_rate_get_reply",
    .handler = vl_api_sflow_sampling_rate_get_reply_t_handler,
    .endian = vl_api_sflow_sampling_rate_get_reply_t_endian,
    .format_fn = vl_api_sflow_sampling_rate_get_reply_t_format,
    .size = sizeof(vl_api_sflow_sampling_rate_get_reply_t),
    .traced = 1,
    .tojson = vl_api_sflow_sampling_rate_get_reply_t_tojson,
    .fromjson = vl_api_sflow_sampling_rate_get_reply_t_fromjson,
    .calc_size = vl_api_sflow_sampling_rate_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sflow_sampling_rate_get", api_sflow_sampling_rate_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SFLOW_SAMPLING_RATE_SET_REPLY + msg_id_base,
    .name = "sflow_sampling_rate_set_reply",
    .handler = vl_api_sflow_sampling_rate_set_reply_t_handler,
    .endian = vl_api_sflow_sampling_rate_set_reply_t_endian,
    .format_fn = vl_api_sflow_sampling_rate_set_reply_t_format,
    .size = sizeof(vl_api_sflow_sampling_rate_set_reply_t),
    .traced = 1,
    .tojson = vl_api_sflow_sampling_rate_set_reply_t_tojson,
    .fromjson = vl_api_sflow_sampling_rate_set_reply_t_fromjson,
    .calc_size = vl_api_sflow_sampling_rate_set_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sflow_sampling_rate_set", api_sflow_sampling_rate_set);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SFLOW_POLLING_INTERVAL_SET_REPLY + msg_id_base,
    .name = "sflow_polling_interval_set_reply",
    .handler = vl_api_sflow_polling_interval_set_reply_t_handler,
    .endian = vl_api_sflow_polling_interval_set_reply_t_endian,
    .format_fn = vl_api_sflow_polling_interval_set_reply_t_format,
    .size = sizeof(vl_api_sflow_polling_interval_set_reply_t),
    .traced = 1,
    .tojson = vl_api_sflow_polling_interval_set_reply_t_tojson,
    .fromjson = vl_api_sflow_polling_interval_set_reply_t_fromjson,
    .calc_size = vl_api_sflow_polling_interval_set_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sflow_polling_interval_set", api_sflow_polling_interval_set);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SFLOW_POLLING_INTERVAL_GET_REPLY + msg_id_base,
    .name = "sflow_polling_interval_get_reply",
    .handler = vl_api_sflow_polling_interval_get_reply_t_handler,
    .endian = vl_api_sflow_polling_interval_get_reply_t_endian,
    .format_fn = vl_api_sflow_polling_interval_get_reply_t_format,
    .size = sizeof(vl_api_sflow_polling_interval_get_reply_t),
    .traced = 1,
    .tojson = vl_api_sflow_polling_interval_get_reply_t_tojson,
    .fromjson = vl_api_sflow_polling_interval_get_reply_t_fromjson,
    .calc_size = vl_api_sflow_polling_interval_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sflow_polling_interval_get", api_sflow_polling_interval_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SFLOW_HEADER_BYTES_SET_REPLY + msg_id_base,
    .name = "sflow_header_bytes_set_reply",
    .handler = vl_api_sflow_header_bytes_set_reply_t_handler,
    .endian = vl_api_sflow_header_bytes_set_reply_t_endian,
    .format_fn = vl_api_sflow_header_bytes_set_reply_t_format,
    .size = sizeof(vl_api_sflow_header_bytes_set_reply_t),
    .traced = 1,
    .tojson = vl_api_sflow_header_bytes_set_reply_t_tojson,
    .fromjson = vl_api_sflow_header_bytes_set_reply_t_fromjson,
    .calc_size = vl_api_sflow_header_bytes_set_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sflow_header_bytes_set", api_sflow_header_bytes_set);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SFLOW_HEADER_BYTES_GET_REPLY + msg_id_base,
    .name = "sflow_header_bytes_get_reply",
    .handler = vl_api_sflow_header_bytes_get_reply_t_handler,
    .endian = vl_api_sflow_header_bytes_get_reply_t_endian,
    .format_fn = vl_api_sflow_header_bytes_get_reply_t_format,
    .size = sizeof(vl_api_sflow_header_bytes_get_reply_t),
    .traced = 1,
    .tojson = vl_api_sflow_header_bytes_get_reply_t_tojson,
    .fromjson = vl_api_sflow_header_bytes_get_reply_t_fromjson,
    .calc_size = vl_api_sflow_header_bytes_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sflow_header_bytes_get", api_sflow_header_bytes_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SFLOW_DIRECTION_SET_REPLY + msg_id_base,
    .name = "sflow_direction_set_reply",
    .handler = vl_api_sflow_direction_set_reply_t_handler,
    .endian = vl_api_sflow_direction_set_reply_t_endian,
    .format_fn = vl_api_sflow_direction_set_reply_t_format,
    .size = sizeof(vl_api_sflow_direction_set_reply_t),
    .traced = 1,
    .tojson = vl_api_sflow_direction_set_reply_t_tojson,
    .fromjson = vl_api_sflow_direction_set_reply_t_fromjson,
    .calc_size = vl_api_sflow_direction_set_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sflow_direction_set", api_sflow_direction_set);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SFLOW_DIRECTION_GET_REPLY + msg_id_base,
    .name = "sflow_direction_get_reply",
    .handler = vl_api_sflow_direction_get_reply_t_handler,
    .endian = vl_api_sflow_direction_get_reply_t_endian,
    .format_fn = vl_api_sflow_direction_get_reply_t_format,
    .size = sizeof(vl_api_sflow_direction_get_reply_t),
    .traced = 1,
    .tojson = vl_api_sflow_direction_get_reply_t_tojson,
    .fromjson = vl_api_sflow_direction_get_reply_t_fromjson,
    .calc_size = vl_api_sflow_direction_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sflow_direction_get", api_sflow_direction_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SFLOW_DROP_MONITORING_SET_REPLY + msg_id_base,
    .name = "sflow_drop_monitoring_set_reply",
    .handler = vl_api_sflow_drop_monitoring_set_reply_t_handler,
    .endian = vl_api_sflow_drop_monitoring_set_reply_t_endian,
    .format_fn = vl_api_sflow_drop_monitoring_set_reply_t_format,
    .size = sizeof(vl_api_sflow_drop_monitoring_set_reply_t),
    .traced = 1,
    .tojson = vl_api_sflow_drop_monitoring_set_reply_t_tojson,
    .fromjson = vl_api_sflow_drop_monitoring_set_reply_t_fromjson,
    .calc_size = vl_api_sflow_drop_monitoring_set_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sflow_drop_monitoring_set", api_sflow_drop_monitoring_set);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SFLOW_DROP_MONITORING_GET_REPLY + msg_id_base,
    .name = "sflow_drop_monitoring_get_reply",
    .handler = vl_api_sflow_drop_monitoring_get_reply_t_handler,
    .endian = vl_api_sflow_drop_monitoring_get_reply_t_endian,
    .format_fn = vl_api_sflow_drop_monitoring_get_reply_t_format,
    .size = sizeof(vl_api_sflow_drop_monitoring_get_reply_t),
    .traced = 1,
    .tojson = vl_api_sflow_drop_monitoring_get_reply_t_tojson,
    .fromjson = vl_api_sflow_drop_monitoring_get_reply_t_fromjson,
    .calc_size = vl_api_sflow_drop_monitoring_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sflow_drop_monitoring_get", api_sflow_drop_monitoring_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SFLOW_INTERFACE_DETAILS + msg_id_base,
    .name = "sflow_interface_details",
    .handler = vl_api_sflow_interface_details_t_handler,
    .endian = vl_api_sflow_interface_details_t_endian,
    .format_fn = vl_api_sflow_interface_details_t_format,
    .size = sizeof(vl_api_sflow_interface_details_t),
    .traced = 1,
    .tojson = vl_api_sflow_interface_details_t_tojson,
    .fromjson = vl_api_sflow_interface_details_t_fromjson,
    .calc_size = vl_api_sflow_interface_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sflow_interface_dump", api_sflow_interface_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   sflow_test_main_t * mainp = &sflow_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("sflow_ba88ab74");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "sflow plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
