#define vl_endianfun		/* define message structures */
#include "punt.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "punt.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "punt.api.h"
#undef vl_printfun

#include "punt.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("punt_692c7d27", VL_MSG_PUNT_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_punt);
   vl_msg_api_add_msg_name_crc (am, "set_punt_47d0e347",
                                VL_API_SET_PUNT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "set_punt_reply_e8d4e804",
                                VL_API_SET_PUNT_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "punt_socket_register_7875badb",
                                VL_API_PUNT_SOCKET_REGISTER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "punt_socket_register_reply_bd30ae90",
                                VL_API_PUNT_SOCKET_REGISTER_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "punt_socket_dump_916fb004",
                                VL_API_PUNT_SOCKET_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "punt_socket_details_330466e4",
                                VL_API_PUNT_SOCKET_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "punt_socket_deregister_75afa766",
                                VL_API_PUNT_SOCKET_DEREGISTER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "punt_socket_deregister_reply_e8d4e804",
                                VL_API_PUNT_SOCKET_DEREGISTER_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "punt_reason_dump_5c0dd4fe",
                                VL_API_PUNT_REASON_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "punt_reason_details_2c9d4a40",
                                VL_API_PUNT_REASON_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SET_PUNT + msg_id_base,
   .name = "set_punt",
   .handler = vl_api_set_punt_t_handler,
   .endian = vl_api_set_punt_t_endian,
   .format_fn = vl_api_set_punt_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_set_punt_t_tojson,
   .fromjson = vl_api_set_punt_t_fromjson,
   .calc_size = vl_api_set_punt_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SET_PUNT_REPLY + msg_id_base,
  .name = "set_punt_reply",
  .handler = 0,
  .endian = vl_api_set_punt_reply_t_endian,
  .format_fn = vl_api_set_punt_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_set_punt_reply_t_tojson,
  .fromjson = vl_api_set_punt_reply_t_fromjson,
  .calc_size = vl_api_set_punt_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PUNT_SOCKET_REGISTER + msg_id_base,
   .name = "punt_socket_register",
   .handler = vl_api_punt_socket_register_t_handler,
   .endian = vl_api_punt_socket_register_t_endian,
   .format_fn = vl_api_punt_socket_register_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_punt_socket_register_t_tojson,
   .fromjson = vl_api_punt_socket_register_t_fromjson,
   .calc_size = vl_api_punt_socket_register_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PUNT_SOCKET_REGISTER_REPLY + msg_id_base,
  .name = "punt_socket_register_reply",
  .handler = 0,
  .endian = vl_api_punt_socket_register_reply_t_endian,
  .format_fn = vl_api_punt_socket_register_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_punt_socket_register_reply_t_tojson,
  .fromjson = vl_api_punt_socket_register_reply_t_fromjson,
  .calc_size = vl_api_punt_socket_register_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PUNT_SOCKET_DUMP + msg_id_base,
   .name = "punt_socket_dump",
   .handler = vl_api_punt_socket_dump_t_handler,
   .endian = vl_api_punt_socket_dump_t_endian,
   .format_fn = vl_api_punt_socket_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_punt_socket_dump_t_tojson,
   .fromjson = vl_api_punt_socket_dump_t_fromjson,
   .calc_size = vl_api_punt_socket_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PUNT_SOCKET_DETAILS + msg_id_base,
  .name = "punt_socket_details",
  .handler = 0,
  .endian = vl_api_punt_socket_details_t_endian,
  .format_fn = vl_api_punt_socket_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_punt_socket_details_t_tojson,
  .fromjson = vl_api_punt_socket_details_t_fromjson,
  .calc_size = vl_api_punt_socket_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PUNT_SOCKET_DEREGISTER + msg_id_base,
   .name = "punt_socket_deregister",
   .handler = vl_api_punt_socket_deregister_t_handler,
   .endian = vl_api_punt_socket_deregister_t_endian,
   .format_fn = vl_api_punt_socket_deregister_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_punt_socket_deregister_t_tojson,
   .fromjson = vl_api_punt_socket_deregister_t_fromjson,
   .calc_size = vl_api_punt_socket_deregister_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PUNT_SOCKET_DEREGISTER_REPLY + msg_id_base,
  .name = "punt_socket_deregister_reply",
  .handler = 0,
  .endian = vl_api_punt_socket_deregister_reply_t_endian,
  .format_fn = vl_api_punt_socket_deregister_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_punt_socket_deregister_reply_t_tojson,
  .fromjson = vl_api_punt_socket_deregister_reply_t_fromjson,
  .calc_size = vl_api_punt_socket_deregister_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PUNT_REASON_DUMP + msg_id_base,
   .name = "punt_reason_dump",
   .handler = vl_api_punt_reason_dump_t_handler,
   .endian = vl_api_punt_reason_dump_t_endian,
   .format_fn = vl_api_punt_reason_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_punt_reason_dump_t_tojson,
   .fromjson = vl_api_punt_reason_dump_t_fromjson,
   .calc_size = vl_api_punt_reason_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PUNT_REASON_DETAILS + msg_id_base,
  .name = "punt_reason_details",
  .handler = 0,
  .endian = vl_api_punt_reason_details_t_endian,
  .format_fn = vl_api_punt_reason_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_punt_reason_details_t_tojson,
  .fromjson = vl_api_punt_reason_details_t_fromjson,
  .calc_size = vl_api_punt_reason_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
