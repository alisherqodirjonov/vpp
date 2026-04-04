#define vl_endianfun		/* define message structures */
#include "pg.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "pg.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "pg.api.h"
#undef vl_printfun

#include "pg.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("pg_b62765bc", VL_MSG_PG_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_pg);
   vl_msg_api_add_msg_name_crc (am, "pg_create_interface_b7c893d7",
                                VL_API_PG_CREATE_INTERFACE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pg_create_interface_v2_8657466a",
                                VL_API_PG_CREATE_INTERFACE_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pg_create_interface_v3_b2aac653",
                                VL_API_PG_CREATE_INTERFACE_V3 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pg_create_interface_reply_5383d31f",
                                VL_API_PG_CREATE_INTERFACE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pg_create_interface_v2_reply_5383d31f",
                                VL_API_PG_CREATE_INTERFACE_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pg_create_interface_v3_reply_5383d31f",
                                VL_API_PG_CREATE_INTERFACE_V3_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pg_delete_interface_f9e6675e",
                                VL_API_PG_DELETE_INTERFACE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pg_delete_interface_reply_e8d4e804",
                                VL_API_PG_DELETE_INTERFACE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pg_interface_enable_disable_coalesce_a2ef99e7",
                                VL_API_PG_INTERFACE_ENABLE_DISABLE_COALESCE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pg_interface_enable_disable_coalesce_reply_e8d4e804",
                                VL_API_PG_INTERFACE_ENABLE_DISABLE_COALESCE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pg_capture_3712fb6c",
                                VL_API_PG_CAPTURE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pg_capture_reply_e8d4e804",
                                VL_API_PG_CAPTURE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pg_enable_disable_01f94f3a",
                                VL_API_PG_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pg_enable_disable_reply_e8d4e804",
                                VL_API_PG_ENABLE_DISABLE_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PG_CREATE_INTERFACE + msg_id_base,
   .name = "pg_create_interface",
   .handler = vl_api_pg_create_interface_t_handler,
   .endian = vl_api_pg_create_interface_t_endian,
   .format_fn = vl_api_pg_create_interface_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pg_create_interface_t_tojson,
   .fromjson = vl_api_pg_create_interface_t_fromjson,
   .calc_size = vl_api_pg_create_interface_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PG_CREATE_INTERFACE_REPLY + msg_id_base,
  .name = "pg_create_interface_reply",
  .handler = 0,
  .endian = vl_api_pg_create_interface_reply_t_endian,
  .format_fn = vl_api_pg_create_interface_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pg_create_interface_reply_t_tojson,
  .fromjson = vl_api_pg_create_interface_reply_t_fromjson,
  .calc_size = vl_api_pg_create_interface_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PG_CREATE_INTERFACE_V2 + msg_id_base,
   .name = "pg_create_interface_v2",
   .handler = vl_api_pg_create_interface_v2_t_handler,
   .endian = vl_api_pg_create_interface_v2_t_endian,
   .format_fn = vl_api_pg_create_interface_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pg_create_interface_v2_t_tojson,
   .fromjson = vl_api_pg_create_interface_v2_t_fromjson,
   .calc_size = vl_api_pg_create_interface_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PG_CREATE_INTERFACE_V2_REPLY + msg_id_base,
  .name = "pg_create_interface_v2_reply",
  .handler = 0,
  .endian = vl_api_pg_create_interface_v2_reply_t_endian,
  .format_fn = vl_api_pg_create_interface_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pg_create_interface_v2_reply_t_tojson,
  .fromjson = vl_api_pg_create_interface_v2_reply_t_fromjson,
  .calc_size = vl_api_pg_create_interface_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PG_CREATE_INTERFACE_V3 + msg_id_base,
   .name = "pg_create_interface_v3",
   .handler = vl_api_pg_create_interface_v3_t_handler,
   .endian = vl_api_pg_create_interface_v3_t_endian,
   .format_fn = vl_api_pg_create_interface_v3_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pg_create_interface_v3_t_tojson,
   .fromjson = vl_api_pg_create_interface_v3_t_fromjson,
   .calc_size = vl_api_pg_create_interface_v3_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PG_CREATE_INTERFACE_V3_REPLY + msg_id_base,
  .name = "pg_create_interface_v3_reply",
  .handler = 0,
  .endian = vl_api_pg_create_interface_v3_reply_t_endian,
  .format_fn = vl_api_pg_create_interface_v3_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pg_create_interface_v3_reply_t_tojson,
  .fromjson = vl_api_pg_create_interface_v3_reply_t_fromjson,
  .calc_size = vl_api_pg_create_interface_v3_reply_t_calc_size,
  .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PG_DELETE_INTERFACE + msg_id_base,
   .name = "pg_delete_interface",
   .handler = vl_api_pg_delete_interface_t_handler,
   .endian = vl_api_pg_delete_interface_t_endian,
   .format_fn = vl_api_pg_delete_interface_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pg_delete_interface_t_tojson,
   .fromjson = vl_api_pg_delete_interface_t_fromjson,
   .calc_size = vl_api_pg_delete_interface_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PG_DELETE_INTERFACE_REPLY + msg_id_base,
  .name = "pg_delete_interface_reply",
  .handler = 0,
  .endian = vl_api_pg_delete_interface_reply_t_endian,
  .format_fn = vl_api_pg_delete_interface_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pg_delete_interface_reply_t_tojson,
  .fromjson = vl_api_pg_delete_interface_reply_t_fromjson,
  .calc_size = vl_api_pg_delete_interface_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PG_INTERFACE_ENABLE_DISABLE_COALESCE + msg_id_base,
   .name = "pg_interface_enable_disable_coalesce",
   .handler = vl_api_pg_interface_enable_disable_coalesce_t_handler,
   .endian = vl_api_pg_interface_enable_disable_coalesce_t_endian,
   .format_fn = vl_api_pg_interface_enable_disable_coalesce_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pg_interface_enable_disable_coalesce_t_tojson,
   .fromjson = vl_api_pg_interface_enable_disable_coalesce_t_fromjson,
   .calc_size = vl_api_pg_interface_enable_disable_coalesce_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PG_INTERFACE_ENABLE_DISABLE_COALESCE_REPLY + msg_id_base,
  .name = "pg_interface_enable_disable_coalesce_reply",
  .handler = 0,
  .endian = vl_api_pg_interface_enable_disable_coalesce_reply_t_endian,
  .format_fn = vl_api_pg_interface_enable_disable_coalesce_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pg_interface_enable_disable_coalesce_reply_t_tojson,
  .fromjson = vl_api_pg_interface_enable_disable_coalesce_reply_t_fromjson,
  .calc_size = vl_api_pg_interface_enable_disable_coalesce_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PG_CAPTURE + msg_id_base,
   .name = "pg_capture",
   .handler = vl_api_pg_capture_t_handler,
   .endian = vl_api_pg_capture_t_endian,
   .format_fn = vl_api_pg_capture_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pg_capture_t_tojson,
   .fromjson = vl_api_pg_capture_t_fromjson,
   .calc_size = vl_api_pg_capture_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PG_CAPTURE_REPLY + msg_id_base,
  .name = "pg_capture_reply",
  .handler = 0,
  .endian = vl_api_pg_capture_reply_t_endian,
  .format_fn = vl_api_pg_capture_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pg_capture_reply_t_tojson,
  .fromjson = vl_api_pg_capture_reply_t_fromjson,
  .calc_size = vl_api_pg_capture_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PG_ENABLE_DISABLE + msg_id_base,
   .name = "pg_enable_disable",
   .handler = vl_api_pg_enable_disable_t_handler,
   .endian = vl_api_pg_enable_disable_t_endian,
   .format_fn = vl_api_pg_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pg_enable_disable_t_tojson,
   .fromjson = vl_api_pg_enable_disable_t_fromjson,
   .calc_size = vl_api_pg_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PG_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "pg_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_pg_enable_disable_reply_t_endian,
  .format_fn = vl_api_pg_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pg_enable_disable_reply_t_tojson,
  .fromjson = vl_api_pg_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_pg_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
