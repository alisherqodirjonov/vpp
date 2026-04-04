#define vl_endianfun		/* define message structures */
#include "tls_openssl.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "tls_openssl.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "tls_openssl.api.h"
#undef vl_printfun

#include "tls_openssl.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("tls_openssl_7386fbcd", VL_MSG_TLS_OPENSSL_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_tls_openssl);
   vl_msg_api_add_msg_name_crc (am, "tls_openssl_set_engine_e34d95c1",
                                VL_API_TLS_OPENSSL_SET_ENGINE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "tls_openssl_set_engine_reply_e8d4e804",
                                VL_API_TLS_OPENSSL_SET_ENGINE_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TLS_OPENSSL_SET_ENGINE + msg_id_base,
   .name = "tls_openssl_set_engine",
   .handler = vl_api_tls_openssl_set_engine_t_handler,
   .endian = vl_api_tls_openssl_set_engine_t_endian,
   .format_fn = vl_api_tls_openssl_set_engine_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_tls_openssl_set_engine_t_tojson,
   .fromjson = vl_api_tls_openssl_set_engine_t_fromjson,
   .calc_size = vl_api_tls_openssl_set_engine_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TLS_OPENSSL_SET_ENGINE_REPLY + msg_id_base,
  .name = "tls_openssl_set_engine_reply",
  .handler = 0,
  .endian = vl_api_tls_openssl_set_engine_reply_t_endian,
  .format_fn = vl_api_tls_openssl_set_engine_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_tls_openssl_set_engine_reply_t_tojson,
  .fromjson = vl_api_tls_openssl_set_engine_reply_t_fromjson,
  .calc_size = vl_api_tls_openssl_set_engine_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
