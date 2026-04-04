#define vl_endianfun		/* define message structures */
#include "span.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "span.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "span.api.h"
#undef vl_printfun

#include "span.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("span_fe511ce4", VL_MSG_SPAN_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_span);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_span_enable_disable_23ddd96b",
                                VL_API_SW_INTERFACE_SPAN_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_span_enable_disable_reply_e8d4e804",
                                VL_API_SW_INTERFACE_SPAN_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_span_dump_d6cf0c3d",
                                VL_API_SW_INTERFACE_SPAN_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_span_details_8a20e79f",
                                VL_API_SW_INTERFACE_SPAN_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SPAN_ENABLE_DISABLE + msg_id_base,
   .name = "sw_interface_span_enable_disable",
   .handler = vl_api_sw_interface_span_enable_disable_t_handler,
   .endian = vl_api_sw_interface_span_enable_disable_t_endian,
   .format_fn = vl_api_sw_interface_span_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_span_enable_disable_t_tojson,
   .fromjson = vl_api_sw_interface_span_enable_disable_t_fromjson,
   .calc_size = vl_api_sw_interface_span_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SPAN_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "sw_interface_span_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_span_enable_disable_reply_t_endian,
  .format_fn = vl_api_sw_interface_span_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_span_enable_disable_reply_t_tojson,
  .fromjson = vl_api_sw_interface_span_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_span_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SPAN_DUMP + msg_id_base,
   .name = "sw_interface_span_dump",
   .handler = vl_api_sw_interface_span_dump_t_handler,
   .endian = vl_api_sw_interface_span_dump_t_endian,
   .format_fn = vl_api_sw_interface_span_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_span_dump_t_tojson,
   .fromjson = vl_api_sw_interface_span_dump_t_fromjson,
   .calc_size = vl_api_sw_interface_span_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SPAN_DETAILS + msg_id_base,
  .name = "sw_interface_span_details",
  .handler = 0,
  .endian = vl_api_sw_interface_span_details_t_endian,
  .format_fn = vl_api_sw_interface_span_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_span_details_t_tojson,
  .fromjson = vl_api_sw_interface_span_details_t_fromjson,
  .calc_size = vl_api_sw_interface_span_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
