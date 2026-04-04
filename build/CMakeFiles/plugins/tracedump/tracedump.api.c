#define vl_endianfun		/* define message structures */
#include "tracedump.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "tracedump.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "tracedump.api.h"
#undef vl_printfun

#include "tracedump.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("tracedump_56abf80a", VL_MSG_TRACEDUMP_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_tracedump);
   vl_msg_api_add_msg_name_crc (am, "trace_set_filters_f522b44a",
                                VL_API_TRACE_SET_FILTERS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_set_filters_reply_e8d4e804",
                                VL_API_TRACE_SET_FILTERS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_capture_packets_9e791a9b",
                                VL_API_TRACE_CAPTURE_PACKETS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_capture_packets_reply_e8d4e804",
                                VL_API_TRACE_CAPTURE_PACKETS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_clear_capture_51077d14",
                                VL_API_TRACE_CLEAR_CAPTURE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_clear_capture_reply_e8d4e804",
                                VL_API_TRACE_CLEAR_CAPTURE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_dump_c7d6681f",
                                VL_API_TRACE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_dump_reply_e0e87f9d",
                                VL_API_TRACE_DUMP_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_details_1553e9eb",
                                VL_API_TRACE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_clear_cache_51077d14",
                                VL_API_TRACE_CLEAR_CACHE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_clear_cache_reply_e8d4e804",
                                VL_API_TRACE_CLEAR_CACHE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_v2_dump_83f88d8e",
                                VL_API_TRACE_V2_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_v2_details_91f87d52",
                                VL_API_TRACE_V2_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_set_filter_function_616abb92",
                                VL_API_TRACE_SET_FILTER_FUNCTION + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_set_filter_function_reply_e8d4e804",
                                VL_API_TRACE_SET_FILTER_FUNCTION_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_filter_function_dump_51077d14",
                                VL_API_TRACE_FILTER_FUNCTION_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_filter_function_details_28821359",
                                VL_API_TRACE_FILTER_FUNCTION_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TRACE_DUMP + msg_id_base,
   .name = "trace_dump",
   .handler = vl_api_trace_dump_t_handler,
   .endian = vl_api_trace_dump_t_endian,
   .format_fn = vl_api_trace_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_trace_dump_t_tojson,
   .fromjson = vl_api_trace_dump_t_fromjson,
   .calc_size = vl_api_trace_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TRACE_DUMP_REPLY + msg_id_base,
  .name = "trace_dump_reply",
  .handler = 0,
  .endian = vl_api_trace_dump_reply_t_endian,
  .format_fn = vl_api_trace_dump_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_trace_dump_reply_t_tojson,
  .fromjson = vl_api_trace_dump_reply_t_fromjson,
  .calc_size = vl_api_trace_dump_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TRACE_DETAILS + msg_id_base,
  .name = "trace_details",
  .handler = 0,
  .endian = vl_api_trace_details_t_endian,
  .format_fn = vl_api_trace_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_trace_details_t_tojson,
  .fromjson = vl_api_trace_details_t_fromjson,
  .calc_size = vl_api_trace_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TRACE_SET_FILTERS + msg_id_base,
   .name = "trace_set_filters",
   .handler = vl_api_trace_set_filters_t_handler,
   .endian = vl_api_trace_set_filters_t_endian,
   .format_fn = vl_api_trace_set_filters_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_trace_set_filters_t_tojson,
   .fromjson = vl_api_trace_set_filters_t_fromjson,
   .calc_size = vl_api_trace_set_filters_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TRACE_SET_FILTERS_REPLY + msg_id_base,
  .name = "trace_set_filters_reply",
  .handler = 0,
  .endian = vl_api_trace_set_filters_reply_t_endian,
  .format_fn = vl_api_trace_set_filters_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_trace_set_filters_reply_t_tojson,
  .fromjson = vl_api_trace_set_filters_reply_t_fromjson,
  .calc_size = vl_api_trace_set_filters_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TRACE_CAPTURE_PACKETS + msg_id_base,
   .name = "trace_capture_packets",
   .handler = vl_api_trace_capture_packets_t_handler,
   .endian = vl_api_trace_capture_packets_t_endian,
   .format_fn = vl_api_trace_capture_packets_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_trace_capture_packets_t_tojson,
   .fromjson = vl_api_trace_capture_packets_t_fromjson,
   .calc_size = vl_api_trace_capture_packets_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TRACE_CAPTURE_PACKETS_REPLY + msg_id_base,
  .name = "trace_capture_packets_reply",
  .handler = 0,
  .endian = vl_api_trace_capture_packets_reply_t_endian,
  .format_fn = vl_api_trace_capture_packets_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_trace_capture_packets_reply_t_tojson,
  .fromjson = vl_api_trace_capture_packets_reply_t_fromjson,
  .calc_size = vl_api_trace_capture_packets_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TRACE_CLEAR_CAPTURE + msg_id_base,
   .name = "trace_clear_capture",
   .handler = vl_api_trace_clear_capture_t_handler,
   .endian = vl_api_trace_clear_capture_t_endian,
   .format_fn = vl_api_trace_clear_capture_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_trace_clear_capture_t_tojson,
   .fromjson = vl_api_trace_clear_capture_t_fromjson,
   .calc_size = vl_api_trace_clear_capture_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TRACE_CLEAR_CAPTURE_REPLY + msg_id_base,
  .name = "trace_clear_capture_reply",
  .handler = 0,
  .endian = vl_api_trace_clear_capture_reply_t_endian,
  .format_fn = vl_api_trace_clear_capture_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_trace_clear_capture_reply_t_tojson,
  .fromjson = vl_api_trace_clear_capture_reply_t_fromjson,
  .calc_size = vl_api_trace_clear_capture_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TRACE_CLEAR_CACHE + msg_id_base,
   .name = "trace_clear_cache",
   .handler = vl_api_trace_clear_cache_t_handler,
   .endian = vl_api_trace_clear_cache_t_endian,
   .format_fn = vl_api_trace_clear_cache_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_trace_clear_cache_t_tojson,
   .fromjson = vl_api_trace_clear_cache_t_fromjson,
   .calc_size = vl_api_trace_clear_cache_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TRACE_CLEAR_CACHE_REPLY + msg_id_base,
  .name = "trace_clear_cache_reply",
  .handler = 0,
  .endian = vl_api_trace_clear_cache_reply_t_endian,
  .format_fn = vl_api_trace_clear_cache_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_trace_clear_cache_reply_t_tojson,
  .fromjson = vl_api_trace_clear_cache_reply_t_fromjson,
  .calc_size = vl_api_trace_clear_cache_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TRACE_V2_DUMP + msg_id_base,
   .name = "trace_v2_dump",
   .handler = vl_api_trace_v2_dump_t_handler,
   .endian = vl_api_trace_v2_dump_t_endian,
   .format_fn = vl_api_trace_v2_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_trace_v2_dump_t_tojson,
   .fromjson = vl_api_trace_v2_dump_t_fromjson,
   .calc_size = vl_api_trace_v2_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TRACE_V2_DETAILS + msg_id_base,
  .name = "trace_v2_details",
  .handler = 0,
  .endian = vl_api_trace_v2_details_t_endian,
  .format_fn = vl_api_trace_v2_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_trace_v2_details_t_tojson,
  .fromjson = vl_api_trace_v2_details_t_fromjson,
  .calc_size = vl_api_trace_v2_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TRACE_SET_FILTER_FUNCTION + msg_id_base,
   .name = "trace_set_filter_function",
   .handler = vl_api_trace_set_filter_function_t_handler,
   .endian = vl_api_trace_set_filter_function_t_endian,
   .format_fn = vl_api_trace_set_filter_function_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_trace_set_filter_function_t_tojson,
   .fromjson = vl_api_trace_set_filter_function_t_fromjson,
   .calc_size = vl_api_trace_set_filter_function_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TRACE_SET_FILTER_FUNCTION_REPLY + msg_id_base,
  .name = "trace_set_filter_function_reply",
  .handler = 0,
  .endian = vl_api_trace_set_filter_function_reply_t_endian,
  .format_fn = vl_api_trace_set_filter_function_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_trace_set_filter_function_reply_t_tojson,
  .fromjson = vl_api_trace_set_filter_function_reply_t_fromjson,
  .calc_size = vl_api_trace_set_filter_function_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TRACE_FILTER_FUNCTION_DUMP + msg_id_base,
   .name = "trace_filter_function_dump",
   .handler = vl_api_trace_filter_function_dump_t_handler,
   .endian = vl_api_trace_filter_function_dump_t_endian,
   .format_fn = vl_api_trace_filter_function_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_trace_filter_function_dump_t_tojson,
   .fromjson = vl_api_trace_filter_function_dump_t_fromjson,
   .calc_size = vl_api_trace_filter_function_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TRACE_FILTER_FUNCTION_DETAILS + msg_id_base,
  .name = "trace_filter_function_details",
  .handler = 0,
  .endian = vl_api_trace_filter_function_details_t_endian,
  .format_fn = vl_api_trace_filter_function_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_trace_filter_function_details_t_tojson,
  .fromjson = vl_api_trace_filter_function_details_t_fromjson,
  .calc_size = vl_api_trace_filter_function_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
