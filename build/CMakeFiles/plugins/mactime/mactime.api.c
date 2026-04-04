#define vl_endianfun		/* define message structures */
#include "mactime.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "mactime.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "mactime.api.h"
#undef vl_printfun

#include "mactime.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("mactime_f50faf9b", VL_MSG_MACTIME_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_mactime);
   vl_msg_api_add_msg_name_crc (am, "mactime_enable_disable_3865946c",
                                VL_API_MACTIME_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mactime_enable_disable_reply_e8d4e804",
                                VL_API_MACTIME_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mactime_add_del_range_cb56e877",
                                VL_API_MACTIME_ADD_DEL_RANGE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mactime_add_del_range_reply_e8d4e804",
                                VL_API_MACTIME_ADD_DEL_RANGE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mactime_dump_8f454e23",
                                VL_API_MACTIME_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mactime_details_da25b13a",
                                VL_API_MACTIME_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mactime_dump_reply_49bcc753",
                                VL_API_MACTIME_DUMP_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MACTIME_ENABLE_DISABLE + msg_id_base,
   .name = "mactime_enable_disable",
   .handler = vl_api_mactime_enable_disable_t_handler,
   .endian = vl_api_mactime_enable_disable_t_endian,
   .format_fn = vl_api_mactime_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_mactime_enable_disable_t_tojson,
   .fromjson = vl_api_mactime_enable_disable_t_fromjson,
   .calc_size = vl_api_mactime_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MACTIME_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "mactime_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_mactime_enable_disable_reply_t_endian,
  .format_fn = vl_api_mactime_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_mactime_enable_disable_reply_t_tojson,
  .fromjson = vl_api_mactime_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_mactime_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MACTIME_ADD_DEL_RANGE + msg_id_base,
   .name = "mactime_add_del_range",
   .handler = vl_api_mactime_add_del_range_t_handler,
   .endian = vl_api_mactime_add_del_range_t_endian,
   .format_fn = vl_api_mactime_add_del_range_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_mactime_add_del_range_t_tojson,
   .fromjson = vl_api_mactime_add_del_range_t_fromjson,
   .calc_size = vl_api_mactime_add_del_range_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MACTIME_ADD_DEL_RANGE_REPLY + msg_id_base,
  .name = "mactime_add_del_range_reply",
  .handler = 0,
  .endian = vl_api_mactime_add_del_range_reply_t_endian,
  .format_fn = vl_api_mactime_add_del_range_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_mactime_add_del_range_reply_t_tojson,
  .fromjson = vl_api_mactime_add_del_range_reply_t_fromjson,
  .calc_size = vl_api_mactime_add_del_range_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MACTIME_DUMP + msg_id_base,
   .name = "mactime_dump",
   .handler = vl_api_mactime_dump_t_handler,
   .endian = vl_api_mactime_dump_t_endian,
   .format_fn = vl_api_mactime_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_mactime_dump_t_tojson,
   .fromjson = vl_api_mactime_dump_t_fromjson,
   .calc_size = vl_api_mactime_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MACTIME_DETAILS + msg_id_base,
  .name = "mactime_details",
  .handler = 0,
  .endian = vl_api_mactime_details_t_endian,
  .format_fn = vl_api_mactime_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_mactime_details_t_tojson,
  .fromjson = vl_api_mactime_details_t_fromjson,
  .calc_size = vl_api_mactime_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
