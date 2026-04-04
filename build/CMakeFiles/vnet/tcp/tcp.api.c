#define vl_endianfun		/* define message structures */
#include "tcp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "tcp.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "tcp.api.h"
#undef vl_printfun

#include "tcp.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("tcp_bd2e9222", VL_MSG_TCP_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_tcp);
   vl_msg_api_add_msg_name_crc (am, "tcp_configure_src_addresses_67eede0d",
                                VL_API_TCP_CONFIGURE_SRC_ADDRESSES + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "tcp_configure_src_addresses_reply_e8d4e804",
                                VL_API_TCP_CONFIGURE_SRC_ADDRESSES_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TCP_CONFIGURE_SRC_ADDRESSES + msg_id_base,
   .name = "tcp_configure_src_addresses",
   .handler = vl_api_tcp_configure_src_addresses_t_handler,
   .endian = vl_api_tcp_configure_src_addresses_t_endian,
   .format_fn = vl_api_tcp_configure_src_addresses_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_tcp_configure_src_addresses_t_tojson,
   .fromjson = vl_api_tcp_configure_src_addresses_t_fromjson,
   .calc_size = vl_api_tcp_configure_src_addresses_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TCP_CONFIGURE_SRC_ADDRESSES_REPLY + msg_id_base,
  .name = "tcp_configure_src_addresses_reply",
  .handler = 0,
  .endian = vl_api_tcp_configure_src_addresses_reply_t_endian,
  .format_fn = vl_api_tcp_configure_src_addresses_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_tcp_configure_src_addresses_reply_t_tojson,
  .fromjson = vl_api_tcp_configure_src_addresses_reply_t_fromjson,
  .calc_size = vl_api_tcp_configure_src_addresses_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
