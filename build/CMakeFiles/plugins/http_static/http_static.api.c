#define vl_endianfun		/* define message structures */
#include "http_static.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "http_static.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "http_static.api.h"
#undef vl_printfun

#include "http_static.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("http_static_a4be530f", VL_MSG_HTTP_STATIC_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_http_static);
   vl_msg_api_add_msg_name_crc (am, "http_static_enable_v4_37540bfc",
                                VL_API_HTTP_STATIC_ENABLE_V4 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "http_static_enable_v4_reply_e8d4e804",
                                VL_API_HTTP_STATIC_ENABLE_V4_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "http_static_enable_v5_8bf84069",
                                VL_API_HTTP_STATIC_ENABLE_V5 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "http_static_enable_v5_reply_e8d4e804",
                                VL_API_HTTP_STATIC_ENABLE_V5_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_HTTP_STATIC_ENABLE_V4 + msg_id_base,
   .name = "http_static_enable_v4",
   .handler = vl_api_http_static_enable_v4_t_handler,
   .endian = vl_api_http_static_enable_v4_t_endian,
   .format_fn = vl_api_http_static_enable_v4_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_http_static_enable_v4_t_tojson,
   .fromjson = vl_api_http_static_enable_v4_t_fromjson,
   .calc_size = vl_api_http_static_enable_v4_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_HTTP_STATIC_ENABLE_V4_REPLY + msg_id_base,
  .name = "http_static_enable_v4_reply",
  .handler = 0,
  .endian = vl_api_http_static_enable_v4_reply_t_endian,
  .format_fn = vl_api_http_static_enable_v4_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_http_static_enable_v4_reply_t_tojson,
  .fromjson = vl_api_http_static_enable_v4_reply_t_fromjson,
  .calc_size = vl_api_http_static_enable_v4_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_HTTP_STATIC_ENABLE_V5 + msg_id_base,
   .name = "http_static_enable_v5",
   .handler = vl_api_http_static_enable_v5_t_handler,
   .endian = vl_api_http_static_enable_v5_t_endian,
   .format_fn = vl_api_http_static_enable_v5_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_http_static_enable_v5_t_tojson,
   .fromjson = vl_api_http_static_enable_v5_t_fromjson,
   .calc_size = vl_api_http_static_enable_v5_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_HTTP_STATIC_ENABLE_V5_REPLY + msg_id_base,
  .name = "http_static_enable_v5_reply",
  .handler = 0,
  .endian = vl_api_http_static_enable_v5_reply_t_endian,
  .format_fn = vl_api_http_static_enable_v5_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_http_static_enable_v5_reply_t_tojson,
  .fromjson = vl_api_http_static_enable_v5_reply_t_fromjson,
  .calc_size = vl_api_http_static_enable_v5_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
