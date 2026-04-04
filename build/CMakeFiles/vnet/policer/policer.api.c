#define vl_endianfun		/* define message structures */
#include "policer.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "policer.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "policer.api.h"
#undef vl_printfun

#include "policer.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("policer_68c02844", VL_MSG_POLICER_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_policer);
   vl_msg_api_add_msg_name_crc (am, "policer_bind_dcf516f9",
                                VL_API_POLICER_BIND + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_bind_reply_e8d4e804",
                                VL_API_POLICER_BIND_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_bind_v2_f87bd3c0",
                                VL_API_POLICER_BIND_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_bind_v2_reply_e8d4e804",
                                VL_API_POLICER_BIND_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_input_233f0ef5",
                                VL_API_POLICER_INPUT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_input_reply_e8d4e804",
                                VL_API_POLICER_INPUT_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_input_v2_8388eb84",
                                VL_API_POLICER_INPUT_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_input_v2_reply_e8d4e804",
                                VL_API_POLICER_INPUT_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_output_233f0ef5",
                                VL_API_POLICER_OUTPUT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_output_reply_e8d4e804",
                                VL_API_POLICER_OUTPUT_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_output_v2_8388eb84",
                                VL_API_POLICER_OUTPUT_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_output_v2_reply_e8d4e804",
                                VL_API_POLICER_OUTPUT_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_add_del_2b31dd38",
                                VL_API_POLICER_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_add_4d949e35",
                                VL_API_POLICER_ADD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_del_7ff7912e",
                                VL_API_POLICER_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_del_reply_e8d4e804",
                                VL_API_POLICER_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_update_fd039ef0",
                                VL_API_POLICER_UPDATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_update_reply_e8d4e804",
                                VL_API_POLICER_UPDATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_reset_7ff7912e",
                                VL_API_POLICER_RESET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_reset_reply_e8d4e804",
                                VL_API_POLICER_RESET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_add_del_reply_a177cef2",
                                VL_API_POLICER_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_add_reply_a177cef2",
                                VL_API_POLICER_ADD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_dump_35f1ae0f",
                                VL_API_POLICER_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_dump_v2_7ff7912e",
                                VL_API_POLICER_DUMP_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "policer_details_72d0e248",
                                VL_API_POLICER_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_POLICER_DUMP_V2 + msg_id_base,
   .name = "policer_dump_v2",
   .handler = vl_api_policer_dump_v2_t_handler,
   .endian = vl_api_policer_dump_v2_t_endian,
   .format_fn = vl_api_policer_dump_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_policer_dump_v2_t_tojson,
   .fromjson = vl_api_policer_dump_v2_t_fromjson,
   .calc_size = vl_api_policer_dump_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_POLICER_DETAILS + msg_id_base,
  .name = "policer_details",
  .handler = 0,
  .endian = vl_api_policer_details_t_endian,
  .format_fn = vl_api_policer_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_policer_details_t_tojson,
  .fromjson = vl_api_policer_details_t_fromjson,
  .calc_size = vl_api_policer_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_POLICER_BIND + msg_id_base,
   .name = "policer_bind",
   .handler = vl_api_policer_bind_t_handler,
   .endian = vl_api_policer_bind_t_endian,
   .format_fn = vl_api_policer_bind_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_policer_bind_t_tojson,
   .fromjson = vl_api_policer_bind_t_fromjson,
   .calc_size = vl_api_policer_bind_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_POLICER_BIND_REPLY + msg_id_base,
  .name = "policer_bind_reply",
  .handler = 0,
  .endian = vl_api_policer_bind_reply_t_endian,
  .format_fn = vl_api_policer_bind_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_policer_bind_reply_t_tojson,
  .fromjson = vl_api_policer_bind_reply_t_fromjson,
  .calc_size = vl_api_policer_bind_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_POLICER_BIND_V2 + msg_id_base,
   .name = "policer_bind_v2",
   .handler = vl_api_policer_bind_v2_t_handler,
   .endian = vl_api_policer_bind_v2_t_endian,
   .format_fn = vl_api_policer_bind_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_policer_bind_v2_t_tojson,
   .fromjson = vl_api_policer_bind_v2_t_fromjson,
   .calc_size = vl_api_policer_bind_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_POLICER_BIND_V2_REPLY + msg_id_base,
  .name = "policer_bind_v2_reply",
  .handler = 0,
  .endian = vl_api_policer_bind_v2_reply_t_endian,
  .format_fn = vl_api_policer_bind_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_policer_bind_v2_reply_t_tojson,
  .fromjson = vl_api_policer_bind_v2_reply_t_fromjson,
  .calc_size = vl_api_policer_bind_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_POLICER_INPUT + msg_id_base,
   .name = "policer_input",
   .handler = vl_api_policer_input_t_handler,
   .endian = vl_api_policer_input_t_endian,
   .format_fn = vl_api_policer_input_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_policer_input_t_tojson,
   .fromjson = vl_api_policer_input_t_fromjson,
   .calc_size = vl_api_policer_input_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_POLICER_INPUT_REPLY + msg_id_base,
  .name = "policer_input_reply",
  .handler = 0,
  .endian = vl_api_policer_input_reply_t_endian,
  .format_fn = vl_api_policer_input_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_policer_input_reply_t_tojson,
  .fromjson = vl_api_policer_input_reply_t_fromjson,
  .calc_size = vl_api_policer_input_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_POLICER_INPUT_V2 + msg_id_base,
   .name = "policer_input_v2",
   .handler = vl_api_policer_input_v2_t_handler,
   .endian = vl_api_policer_input_v2_t_endian,
   .format_fn = vl_api_policer_input_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_policer_input_v2_t_tojson,
   .fromjson = vl_api_policer_input_v2_t_fromjson,
   .calc_size = vl_api_policer_input_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_POLICER_INPUT_V2_REPLY + msg_id_base,
  .name = "policer_input_v2_reply",
  .handler = 0,
  .endian = vl_api_policer_input_v2_reply_t_endian,
  .format_fn = vl_api_policer_input_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_policer_input_v2_reply_t_tojson,
  .fromjson = vl_api_policer_input_v2_reply_t_fromjson,
  .calc_size = vl_api_policer_input_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_POLICER_OUTPUT + msg_id_base,
   .name = "policer_output",
   .handler = vl_api_policer_output_t_handler,
   .endian = vl_api_policer_output_t_endian,
   .format_fn = vl_api_policer_output_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_policer_output_t_tojson,
   .fromjson = vl_api_policer_output_t_fromjson,
   .calc_size = vl_api_policer_output_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_POLICER_OUTPUT_REPLY + msg_id_base,
  .name = "policer_output_reply",
  .handler = 0,
  .endian = vl_api_policer_output_reply_t_endian,
  .format_fn = vl_api_policer_output_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_policer_output_reply_t_tojson,
  .fromjson = vl_api_policer_output_reply_t_fromjson,
  .calc_size = vl_api_policer_output_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_POLICER_OUTPUT_V2 + msg_id_base,
   .name = "policer_output_v2",
   .handler = vl_api_policer_output_v2_t_handler,
   .endian = vl_api_policer_output_v2_t_endian,
   .format_fn = vl_api_policer_output_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_policer_output_v2_t_tojson,
   .fromjson = vl_api_policer_output_v2_t_fromjson,
   .calc_size = vl_api_policer_output_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_POLICER_OUTPUT_V2_REPLY + msg_id_base,
  .name = "policer_output_v2_reply",
  .handler = 0,
  .endian = vl_api_policer_output_v2_reply_t_endian,
  .format_fn = vl_api_policer_output_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_policer_output_v2_reply_t_tojson,
  .fromjson = vl_api_policer_output_v2_reply_t_fromjson,
  .calc_size = vl_api_policer_output_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_POLICER_ADD_DEL + msg_id_base,
   .name = "policer_add_del",
   .handler = vl_api_policer_add_del_t_handler,
   .endian = vl_api_policer_add_del_t_endian,
   .format_fn = vl_api_policer_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_policer_add_del_t_tojson,
   .fromjson = vl_api_policer_add_del_t_fromjson,
   .calc_size = vl_api_policer_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_POLICER_ADD_DEL_REPLY + msg_id_base,
  .name = "policer_add_del_reply",
  .handler = 0,
  .endian = vl_api_policer_add_del_reply_t_endian,
  .format_fn = vl_api_policer_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_policer_add_del_reply_t_tojson,
  .fromjson = vl_api_policer_add_del_reply_t_fromjson,
  .calc_size = vl_api_policer_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_POLICER_ADD + msg_id_base,
   .name = "policer_add",
   .handler = vl_api_policer_add_t_handler,
   .endian = vl_api_policer_add_t_endian,
   .format_fn = vl_api_policer_add_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_policer_add_t_tojson,
   .fromjson = vl_api_policer_add_t_fromjson,
   .calc_size = vl_api_policer_add_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_POLICER_ADD_REPLY + msg_id_base,
  .name = "policer_add_reply",
  .handler = 0,
  .endian = vl_api_policer_add_reply_t_endian,
  .format_fn = vl_api_policer_add_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_policer_add_reply_t_tojson,
  .fromjson = vl_api_policer_add_reply_t_fromjson,
  .calc_size = vl_api_policer_add_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_POLICER_DEL + msg_id_base,
   .name = "policer_del",
   .handler = vl_api_policer_del_t_handler,
   .endian = vl_api_policer_del_t_endian,
   .format_fn = vl_api_policer_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_policer_del_t_tojson,
   .fromjson = vl_api_policer_del_t_fromjson,
   .calc_size = vl_api_policer_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_POLICER_DEL_REPLY + msg_id_base,
  .name = "policer_del_reply",
  .handler = 0,
  .endian = vl_api_policer_del_reply_t_endian,
  .format_fn = vl_api_policer_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_policer_del_reply_t_tojson,
  .fromjson = vl_api_policer_del_reply_t_fromjson,
  .calc_size = vl_api_policer_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_POLICER_UPDATE + msg_id_base,
   .name = "policer_update",
   .handler = vl_api_policer_update_t_handler,
   .endian = vl_api_policer_update_t_endian,
   .format_fn = vl_api_policer_update_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_policer_update_t_tojson,
   .fromjson = vl_api_policer_update_t_fromjson,
   .calc_size = vl_api_policer_update_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_POLICER_UPDATE_REPLY + msg_id_base,
  .name = "policer_update_reply",
  .handler = 0,
  .endian = vl_api_policer_update_reply_t_endian,
  .format_fn = vl_api_policer_update_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_policer_update_reply_t_tojson,
  .fromjson = vl_api_policer_update_reply_t_fromjson,
  .calc_size = vl_api_policer_update_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_POLICER_RESET + msg_id_base,
   .name = "policer_reset",
   .handler = vl_api_policer_reset_t_handler,
   .endian = vl_api_policer_reset_t_endian,
   .format_fn = vl_api_policer_reset_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_policer_reset_t_tojson,
   .fromjson = vl_api_policer_reset_t_fromjson,
   .calc_size = vl_api_policer_reset_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_POLICER_RESET_REPLY + msg_id_base,
  .name = "policer_reset_reply",
  .handler = 0,
  .endian = vl_api_policer_reset_reply_t_endian,
  .format_fn = vl_api_policer_reset_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_policer_reset_reply_t_tojson,
  .fromjson = vl_api_policer_reset_reply_t_fromjson,
  .calc_size = vl_api_policer_reset_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_POLICER_DUMP + msg_id_base,
   .name = "policer_dump",
   .handler = vl_api_policer_dump_t_handler,
   .endian = vl_api_policer_dump_t_endian,
   .format_fn = vl_api_policer_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_policer_dump_t_tojson,
   .fromjson = vl_api_policer_dump_t_fromjson,
   .calc_size = vl_api_policer_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_POLICER_DETAILS + msg_id_base,
  .name = "policer_details",
  .handler = 0,
  .endian = vl_api_policer_details_t_endian,
  .format_fn = vl_api_policer_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_policer_details_t_tojson,
  .fromjson = vl_api_policer_details_t_fromjson,
  .calc_size = vl_api_policer_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
