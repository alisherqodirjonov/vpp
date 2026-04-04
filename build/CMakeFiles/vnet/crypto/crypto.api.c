#define vl_endianfun		/* define message structures */
#include "crypto.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "crypto.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "crypto.api.h"
#undef vl_printfun

#include "crypto.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("crypto_2a68080c", VL_MSG_CRYPTO_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_crypto);
   vl_msg_api_add_msg_name_crc (am, "crypto_set_async_dispatch_5ca4adc0",
                                VL_API_CRYPTO_SET_ASYNC_DISPATCH + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "crypto_set_async_dispatch_reply_e8d4e804",
                                VL_API_CRYPTO_SET_ASYNC_DISPATCH_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "crypto_set_async_dispatch_v2_667d2d54",
                                VL_API_CRYPTO_SET_ASYNC_DISPATCH_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "crypto_set_async_dispatch_v2_reply_e8d4e804",
                                VL_API_CRYPTO_SET_ASYNC_DISPATCH_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "crypto_set_handler_ce9ad00d",
                                VL_API_CRYPTO_SET_HANDLER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "crypto_set_handler_reply_e8d4e804",
                                VL_API_CRYPTO_SET_HANDLER_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CRYPTO_SET_ASYNC_DISPATCH + msg_id_base,
   .name = "crypto_set_async_dispatch",
   .handler = vl_api_crypto_set_async_dispatch_t_handler,
   .endian = vl_api_crypto_set_async_dispatch_t_endian,
   .format_fn = vl_api_crypto_set_async_dispatch_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_crypto_set_async_dispatch_t_tojson,
   .fromjson = vl_api_crypto_set_async_dispatch_t_fromjson,
   .calc_size = vl_api_crypto_set_async_dispatch_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CRYPTO_SET_ASYNC_DISPATCH_REPLY + msg_id_base,
  .name = "crypto_set_async_dispatch_reply",
  .handler = 0,
  .endian = vl_api_crypto_set_async_dispatch_reply_t_endian,
  .format_fn = vl_api_crypto_set_async_dispatch_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_crypto_set_async_dispatch_reply_t_tojson,
  .fromjson = vl_api_crypto_set_async_dispatch_reply_t_fromjson,
  .calc_size = vl_api_crypto_set_async_dispatch_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CRYPTO_SET_ASYNC_DISPATCH_V2 + msg_id_base,
   .name = "crypto_set_async_dispatch_v2",
   .handler = vl_api_crypto_set_async_dispatch_v2_t_handler,
   .endian = vl_api_crypto_set_async_dispatch_v2_t_endian,
   .format_fn = vl_api_crypto_set_async_dispatch_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_crypto_set_async_dispatch_v2_t_tojson,
   .fromjson = vl_api_crypto_set_async_dispatch_v2_t_fromjson,
   .calc_size = vl_api_crypto_set_async_dispatch_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CRYPTO_SET_ASYNC_DISPATCH_V2_REPLY + msg_id_base,
  .name = "crypto_set_async_dispatch_v2_reply",
  .handler = 0,
  .endian = vl_api_crypto_set_async_dispatch_v2_reply_t_endian,
  .format_fn = vl_api_crypto_set_async_dispatch_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_crypto_set_async_dispatch_v2_reply_t_tojson,
  .fromjson = vl_api_crypto_set_async_dispatch_v2_reply_t_fromjson,
  .calc_size = vl_api_crypto_set_async_dispatch_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CRYPTO_SET_HANDLER + msg_id_base,
   .name = "crypto_set_handler",
   .handler = vl_api_crypto_set_handler_t_handler,
   .endian = vl_api_crypto_set_handler_t_endian,
   .format_fn = vl_api_crypto_set_handler_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_crypto_set_handler_t_tojson,
   .fromjson = vl_api_crypto_set_handler_t_fromjson,
   .calc_size = vl_api_crypto_set_handler_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CRYPTO_SET_HANDLER_REPLY + msg_id_base,
  .name = "crypto_set_handler_reply",
  .handler = 0,
  .endian = vl_api_crypto_set_handler_reply_t_endian,
  .format_fn = vl_api_crypto_set_handler_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_crypto_set_handler_reply_t_tojson,
  .fromjson = vl_api_crypto_set_handler_reply_t_fromjson,
  .calc_size = vl_api_crypto_set_handler_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
