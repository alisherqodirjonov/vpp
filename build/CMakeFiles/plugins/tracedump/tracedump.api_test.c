#define vl_endianfun            /* define message structures */
#include "tracedump.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "tracedump.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "tracedump.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_trace_dump_reply_t_handler()) */
#ifndef VL_API_TRACE_SET_FILTERS_REPLY_T_HANDLER
static void
vl_api_trace_set_filters_reply_t_handler (vl_api_trace_set_filters_reply_t * mp) {
   vat_main_t * vam = tracedump_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_TRACE_CAPTURE_PACKETS_REPLY_T_HANDLER
static void
vl_api_trace_capture_packets_reply_t_handler (vl_api_trace_capture_packets_reply_t * mp) {
   vat_main_t * vam = tracedump_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_TRACE_CLEAR_CAPTURE_REPLY_T_HANDLER
static void
vl_api_trace_clear_capture_reply_t_handler (vl_api_trace_clear_capture_reply_t * mp) {
   vat_main_t * vam = tracedump_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_TRACE_CLEAR_CACHE_REPLY_T_HANDLER
static void
vl_api_trace_clear_cache_reply_t_handler (vl_api_trace_clear_cache_reply_t * mp) {
   vat_main_t * vam = tracedump_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_trace_v2_details_t_handler()) */
#ifndef VL_API_TRACE_SET_FILTER_FUNCTION_REPLY_T_HANDLER
static void
vl_api_trace_set_filter_function_reply_t_handler (vl_api_trace_set_filter_function_reply_t * mp) {
   vat_main_t * vam = tracedump_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_trace_filter_function_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TRACE_DUMP_REPLY + msg_id_base,
    .name = "trace_dump_reply",
    .handler = vl_api_trace_dump_reply_t_handler,
    .endian = vl_api_trace_dump_reply_t_endian,
    .format_fn = vl_api_trace_dump_reply_t_format,
    .size = sizeof(vl_api_trace_dump_reply_t),
    .traced = 1,
    .tojson = vl_api_trace_dump_reply_t_tojson,
    .fromjson = vl_api_trace_dump_reply_t_fromjson,
    .calc_size = vl_api_trace_dump_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "trace_dump", api_trace_dump);
   hash_set_mem (vam->help_by_name, "trace_dump", "trace_dump [thread_id <tid>] [position <pos>] [max <max>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TRACE_SET_FILTERS_REPLY + msg_id_base,
    .name = "trace_set_filters_reply",
    .handler = vl_api_trace_set_filters_reply_t_handler,
    .endian = vl_api_trace_set_filters_reply_t_endian,
    .format_fn = vl_api_trace_set_filters_reply_t_format,
    .size = sizeof(vl_api_trace_set_filters_reply_t),
    .traced = 1,
    .tojson = vl_api_trace_set_filters_reply_t_tojson,
    .fromjson = vl_api_trace_set_filters_reply_t_fromjson,
    .calc_size = vl_api_trace_set_filters_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "trace_set_filters", api_trace_set_filters);
   hash_set_mem (vam->help_by_name, "trace_set_filters", "trace_set_filters [none] | [(include_node|exclude_node) <node-index>] | [(include_classifier|exclude_classifier) <classifier-index>] [count <count>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TRACE_CAPTURE_PACKETS_REPLY + msg_id_base,
    .name = "trace_capture_packets_reply",
    .handler = vl_api_trace_capture_packets_reply_t_handler,
    .endian = vl_api_trace_capture_packets_reply_t_endian,
    .format_fn = vl_api_trace_capture_packets_reply_t_format,
    .size = sizeof(vl_api_trace_capture_packets_reply_t),
    .traced = 1,
    .tojson = vl_api_trace_capture_packets_reply_t_tojson,
    .fromjson = vl_api_trace_capture_packets_reply_t_fromjson,
    .calc_size = vl_api_trace_capture_packets_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "trace_capture_packets", api_trace_capture_packets);
   hash_set_mem (vam->help_by_name, "trace_capture_packets", "trace_capture_packets [node_index <index>] [max <max>] [pre_capture_clear] [use_filter] [verbose]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TRACE_CLEAR_CAPTURE_REPLY + msg_id_base,
    .name = "trace_clear_capture_reply",
    .handler = vl_api_trace_clear_capture_reply_t_handler,
    .endian = vl_api_trace_clear_capture_reply_t_endian,
    .format_fn = vl_api_trace_clear_capture_reply_t_format,
    .size = sizeof(vl_api_trace_clear_capture_reply_t),
    .traced = 1,
    .tojson = vl_api_trace_clear_capture_reply_t_tojson,
    .fromjson = vl_api_trace_clear_capture_reply_t_fromjson,
    .calc_size = vl_api_trace_clear_capture_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "trace_clear_capture", api_trace_clear_capture);
   hash_set_mem (vam->help_by_name, "trace_clear_capture", "trace_clear_capture");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TRACE_CLEAR_CACHE_REPLY + msg_id_base,
    .name = "trace_clear_cache_reply",
    .handler = vl_api_trace_clear_cache_reply_t_handler,
    .endian = vl_api_trace_clear_cache_reply_t_endian,
    .format_fn = vl_api_trace_clear_cache_reply_t_format,
    .size = sizeof(vl_api_trace_clear_cache_reply_t),
    .traced = 1,
    .tojson = vl_api_trace_clear_cache_reply_t_tojson,
    .fromjson = vl_api_trace_clear_cache_reply_t_fromjson,
    .calc_size = vl_api_trace_clear_cache_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "trace_clear_cache", api_trace_clear_cache);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TRACE_V2_DETAILS + msg_id_base,
    .name = "trace_v2_details",
    .handler = vl_api_trace_v2_details_t_handler,
    .endian = vl_api_trace_v2_details_t_endian,
    .format_fn = vl_api_trace_v2_details_t_format,
    .size = sizeof(vl_api_trace_v2_details_t),
    .traced = 1,
    .tojson = vl_api_trace_v2_details_t_tojson,
    .fromjson = vl_api_trace_v2_details_t_fromjson,
    .calc_size = vl_api_trace_v2_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "trace_v2_dump", api_trace_v2_dump);
   hash_set_mem (vam->help_by_name, "trace_v2_dump", "trace_v2_dump [thread_id <tid>] [position <pos>] [max <max>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TRACE_SET_FILTER_FUNCTION_REPLY + msg_id_base,
    .name = "trace_set_filter_function_reply",
    .handler = vl_api_trace_set_filter_function_reply_t_handler,
    .endian = vl_api_trace_set_filter_function_reply_t_endian,
    .format_fn = vl_api_trace_set_filter_function_reply_t_format,
    .size = sizeof(vl_api_trace_set_filter_function_reply_t),
    .traced = 1,
    .tojson = vl_api_trace_set_filter_function_reply_t_tojson,
    .fromjson = vl_api_trace_set_filter_function_reply_t_fromjson,
    .calc_size = vl_api_trace_set_filter_function_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "trace_set_filter_function", api_trace_set_filter_function);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_TRACE_FILTER_FUNCTION_DETAILS + msg_id_base,
    .name = "trace_filter_function_details",
    .handler = vl_api_trace_filter_function_details_t_handler,
    .endian = vl_api_trace_filter_function_details_t_endian,
    .format_fn = vl_api_trace_filter_function_details_t_format,
    .size = sizeof(vl_api_trace_filter_function_details_t),
    .traced = 1,
    .tojson = vl_api_trace_filter_function_details_t_tojson,
    .fromjson = vl_api_trace_filter_function_details_t_fromjson,
    .calc_size = vl_api_trace_filter_function_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "trace_filter_function_dump", api_trace_filter_function_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   tracedump_test_main_t * mainp = &tracedump_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("tracedump_56abf80a");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "tracedump plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
