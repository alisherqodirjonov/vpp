#define vl_endianfun		/* define message structures */
#include "tapv2.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "tapv2.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "tapv2.api.h"
#undef vl_printfun

#include "tapv2.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("tapv2_b21cac4e", VL_MSG_TAPV2_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_tapv2);
   vl_msg_api_add_msg_name_crc (am, "tap_create_v3_3f3fd1df",
                                VL_API_TAP_CREATE_V3 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "tap_create_v3_reply_5383d31f",
                                VL_API_TAP_CREATE_V3_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "tap_create_v2_2d0d6570",
                                VL_API_TAP_CREATE_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "tap_create_v2_reply_5383d31f",
                                VL_API_TAP_CREATE_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "tap_delete_v2_f9e6675e",
                                VL_API_TAP_DELETE_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "tap_delete_v2_reply_e8d4e804",
                                VL_API_TAP_DELETE_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_tap_v2_dump_f9e6675e",
                                VL_API_SW_INTERFACE_TAP_V2_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_tap_v2_details_1e2b2a47",
                                VL_API_SW_INTERFACE_TAP_V2_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TAP_CREATE_V3 + msg_id_base,
   .name = "tap_create_v3",
   .handler = vl_api_tap_create_v3_t_handler,
   .endian = vl_api_tap_create_v3_t_endian,
   .format_fn = vl_api_tap_create_v3_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_tap_create_v3_t_tojson,
   .fromjson = vl_api_tap_create_v3_t_fromjson,
   .calc_size = vl_api_tap_create_v3_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TAP_CREATE_V3_REPLY + msg_id_base,
  .name = "tap_create_v3_reply",
  .handler = 0,
  .endian = vl_api_tap_create_v3_reply_t_endian,
  .format_fn = vl_api_tap_create_v3_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_tap_create_v3_reply_t_tojson,
  .fromjson = vl_api_tap_create_v3_reply_t_fromjson,
  .calc_size = vl_api_tap_create_v3_reply_t_calc_size,
  .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TAP_CREATE_V2 + msg_id_base,
   .name = "tap_create_v2",
   .handler = vl_api_tap_create_v2_t_handler,
   .endian = vl_api_tap_create_v2_t_endian,
   .format_fn = vl_api_tap_create_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_tap_create_v2_t_tojson,
   .fromjson = vl_api_tap_create_v2_t_fromjson,
   .calc_size = vl_api_tap_create_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TAP_CREATE_V2_REPLY + msg_id_base,
  .name = "tap_create_v2_reply",
  .handler = 0,
  .endian = vl_api_tap_create_v2_reply_t_endian,
  .format_fn = vl_api_tap_create_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_tap_create_v2_reply_t_tojson,
  .fromjson = vl_api_tap_create_v2_reply_t_fromjson,
  .calc_size = vl_api_tap_create_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TAP_DELETE_V2 + msg_id_base,
   .name = "tap_delete_v2",
   .handler = vl_api_tap_delete_v2_t_handler,
   .endian = vl_api_tap_delete_v2_t_endian,
   .format_fn = vl_api_tap_delete_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_tap_delete_v2_t_tojson,
   .fromjson = vl_api_tap_delete_v2_t_fromjson,
   .calc_size = vl_api_tap_delete_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TAP_DELETE_V2_REPLY + msg_id_base,
  .name = "tap_delete_v2_reply",
  .handler = 0,
  .endian = vl_api_tap_delete_v2_reply_t_endian,
  .format_fn = vl_api_tap_delete_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_tap_delete_v2_reply_t_tojson,
  .fromjson = vl_api_tap_delete_v2_reply_t_fromjson,
  .calc_size = vl_api_tap_delete_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_TAP_V2_DUMP + msg_id_base,
   .name = "sw_interface_tap_v2_dump",
   .handler = vl_api_sw_interface_tap_v2_dump_t_handler,
   .endian = vl_api_sw_interface_tap_v2_dump_t_endian,
   .format_fn = vl_api_sw_interface_tap_v2_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_tap_v2_dump_t_tojson,
   .fromjson = vl_api_sw_interface_tap_v2_dump_t_fromjson,
   .calc_size = vl_api_sw_interface_tap_v2_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_TAP_V2_DETAILS + msg_id_base,
  .name = "sw_interface_tap_v2_details",
  .handler = 0,
  .endian = vl_api_sw_interface_tap_v2_details_t_endian,
  .format_fn = vl_api_sw_interface_tap_v2_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_tap_v2_details_t_tojson,
  .fromjson = vl_api_sw_interface_tap_v2_details_t_fromjson,
  .calc_size = vl_api_sw_interface_tap_v2_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
