#define vl_endianfun		/* define message structures */
#include "syslog.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "syslog.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "syslog.api.h"
#undef vl_printfun

#include "syslog.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("syslog_9229df5b", VL_MSG_SYSLOG_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_syslog);
   vl_msg_api_add_msg_name_crc (am, "syslog_set_sender_b8011d0b",
                                VL_API_SYSLOG_SET_SENDER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "syslog_set_sender_reply_e8d4e804",
                                VL_API_SYSLOG_SET_SENDER_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "syslog_get_sender_51077d14",
                                VL_API_SYSLOG_GET_SENDER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "syslog_get_sender_reply_424cfa4e",
                                VL_API_SYSLOG_GET_SENDER_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "syslog_set_filter_571348c3",
                                VL_API_SYSLOG_SET_FILTER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "syslog_set_filter_reply_e8d4e804",
                                VL_API_SYSLOG_SET_FILTER_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "syslog_get_filter_51077d14",
                                VL_API_SYSLOG_GET_FILTER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "syslog_get_filter_reply_eb1833f8",
                                VL_API_SYSLOG_GET_FILTER_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SYSLOG_SET_SENDER + msg_id_base,
   .name = "syslog_set_sender",
   .handler = vl_api_syslog_set_sender_t_handler,
   .endian = vl_api_syslog_set_sender_t_endian,
   .format_fn = vl_api_syslog_set_sender_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_syslog_set_sender_t_tojson,
   .fromjson = vl_api_syslog_set_sender_t_fromjson,
   .calc_size = vl_api_syslog_set_sender_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SYSLOG_SET_SENDER_REPLY + msg_id_base,
  .name = "syslog_set_sender_reply",
  .handler = 0,
  .endian = vl_api_syslog_set_sender_reply_t_endian,
  .format_fn = vl_api_syslog_set_sender_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_syslog_set_sender_reply_t_tojson,
  .fromjson = vl_api_syslog_set_sender_reply_t_fromjson,
  .calc_size = vl_api_syslog_set_sender_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SYSLOG_GET_SENDER + msg_id_base,
   .name = "syslog_get_sender",
   .handler = vl_api_syslog_get_sender_t_handler,
   .endian = vl_api_syslog_get_sender_t_endian,
   .format_fn = vl_api_syslog_get_sender_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_syslog_get_sender_t_tojson,
   .fromjson = vl_api_syslog_get_sender_t_fromjson,
   .calc_size = vl_api_syslog_get_sender_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SYSLOG_GET_SENDER_REPLY + msg_id_base,
  .name = "syslog_get_sender_reply",
  .handler = 0,
  .endian = vl_api_syslog_get_sender_reply_t_endian,
  .format_fn = vl_api_syslog_get_sender_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_syslog_get_sender_reply_t_tojson,
  .fromjson = vl_api_syslog_get_sender_reply_t_fromjson,
  .calc_size = vl_api_syslog_get_sender_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SYSLOG_SET_FILTER + msg_id_base,
   .name = "syslog_set_filter",
   .handler = vl_api_syslog_set_filter_t_handler,
   .endian = vl_api_syslog_set_filter_t_endian,
   .format_fn = vl_api_syslog_set_filter_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_syslog_set_filter_t_tojson,
   .fromjson = vl_api_syslog_set_filter_t_fromjson,
   .calc_size = vl_api_syslog_set_filter_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SYSLOG_SET_FILTER_REPLY + msg_id_base,
  .name = "syslog_set_filter_reply",
  .handler = 0,
  .endian = vl_api_syslog_set_filter_reply_t_endian,
  .format_fn = vl_api_syslog_set_filter_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_syslog_set_filter_reply_t_tojson,
  .fromjson = vl_api_syslog_set_filter_reply_t_fromjson,
  .calc_size = vl_api_syslog_set_filter_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SYSLOG_GET_FILTER + msg_id_base,
   .name = "syslog_get_filter",
   .handler = vl_api_syslog_get_filter_t_handler,
   .endian = vl_api_syslog_get_filter_t_endian,
   .format_fn = vl_api_syslog_get_filter_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_syslog_get_filter_t_tojson,
   .fromjson = vl_api_syslog_get_filter_t_fromjson,
   .calc_size = vl_api_syslog_get_filter_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SYSLOG_GET_FILTER_REPLY + msg_id_base,
  .name = "syslog_get_filter_reply",
  .handler = 0,
  .endian = vl_api_syslog_get_filter_reply_t_endian,
  .format_fn = vl_api_syslog_get_filter_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_syslog_get_filter_reply_t_tojson,
  .fromjson = vl_api_syslog_get_filter_reply_t_fromjson,
  .calc_size = vl_api_syslog_get_filter_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
