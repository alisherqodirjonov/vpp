#define vl_endianfun		/* define message structures */
#include "udp_ping.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "udp_ping.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "udp_ping.api.h"
#undef vl_printfun

#include "udp_ping.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("udp_ping_a88fa111", VL_MSG_UDP_PING_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_udp_ping);
   vl_msg_api_add_msg_name_crc (am, "udp_ping_add_del_fa2628fc",
                                VL_API_UDP_PING_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "udp_ping_add_del_reply_e8d4e804",
                                VL_API_UDP_PING_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "udp_ping_export_b3e225d2",
                                VL_API_UDP_PING_EXPORT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "udp_ping_export_reply_e8d4e804",
                                VL_API_UDP_PING_EXPORT_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_UDP_PING_ADD_DEL + msg_id_base,
   .name = "udp_ping_add_del",
   .handler = vl_api_udp_ping_add_del_t_handler,
   .endian = vl_api_udp_ping_add_del_t_endian,
   .format_fn = vl_api_udp_ping_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_udp_ping_add_del_t_tojson,
   .fromjson = vl_api_udp_ping_add_del_t_fromjson,
   .calc_size = vl_api_udp_ping_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_UDP_PING_ADD_DEL_REPLY + msg_id_base,
  .name = "udp_ping_add_del_reply",
  .handler = 0,
  .endian = vl_api_udp_ping_add_del_reply_t_endian,
  .format_fn = vl_api_udp_ping_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_udp_ping_add_del_reply_t_tojson,
  .fromjson = vl_api_udp_ping_add_del_reply_t_fromjson,
  .calc_size = vl_api_udp_ping_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_UDP_PING_EXPORT + msg_id_base,
   .name = "udp_ping_export",
   .handler = vl_api_udp_ping_export_t_handler,
   .endian = vl_api_udp_ping_export_t_endian,
   .format_fn = vl_api_udp_ping_export_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_udp_ping_export_t_tojson,
   .fromjson = vl_api_udp_ping_export_t_fromjson,
   .calc_size = vl_api_udp_ping_export_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_UDP_PING_EXPORT_REPLY + msg_id_base,
  .name = "udp_ping_export_reply",
  .handler = 0,
  .endian = vl_api_udp_ping_export_reply_t_endian,
  .format_fn = vl_api_udp_ping_export_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_udp_ping_export_reply_t_tojson,
  .fromjson = vl_api_udp_ping_export_reply_t_fromjson,
  .calc_size = vl_api_udp_ping_export_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
