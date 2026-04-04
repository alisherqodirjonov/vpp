#define vl_endianfun		/* define message structures */
#include "l2tp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "l2tp.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "l2tp.api.h"
#undef vl_printfun

#include "l2tp.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("l2tp_f73ff6b9", VL_MSG_L2TP_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_l2tp);
   vl_msg_api_add_msg_name_crc (am, "l2tpv3_create_tunnel_15bed0c2",
                                VL_API_L2TPV3_CREATE_TUNNEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2tpv3_create_tunnel_reply_5383d31f",
                                VL_API_L2TPV3_CREATE_TUNNEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2tpv3_set_tunnel_cookies_b3f4faf7",
                                VL_API_L2TPV3_SET_TUNNEL_COOKIES + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2tpv3_set_tunnel_cookies_reply_e8d4e804",
                                VL_API_L2TPV3_SET_TUNNEL_COOKIES_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_if_l2tpv3_tunnel_details_50b88993",
                                VL_API_SW_IF_L2TPV3_TUNNEL_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_if_l2tpv3_tunnel_dump_51077d14",
                                VL_API_SW_IF_L2TPV3_TUNNEL_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2tpv3_interface_enable_disable_3865946c",
                                VL_API_L2TPV3_INTERFACE_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2tpv3_interface_enable_disable_reply_e8d4e804",
                                VL_API_L2TPV3_INTERFACE_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2tpv3_set_lookup_key_c9892c86",
                                VL_API_L2TPV3_SET_LOOKUP_KEY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l2tpv3_set_lookup_key_reply_e8d4e804",
                                VL_API_L2TPV3_SET_LOOKUP_KEY_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L2TPV3_CREATE_TUNNEL + msg_id_base,
   .name = "l2tpv3_create_tunnel",
   .handler = vl_api_l2tpv3_create_tunnel_t_handler,
   .endian = vl_api_l2tpv3_create_tunnel_t_endian,
   .format_fn = vl_api_l2tpv3_create_tunnel_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l2tpv3_create_tunnel_t_tojson,
   .fromjson = vl_api_l2tpv3_create_tunnel_t_fromjson,
   .calc_size = vl_api_l2tpv3_create_tunnel_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L2TPV3_CREATE_TUNNEL_REPLY + msg_id_base,
  .name = "l2tpv3_create_tunnel_reply",
  .handler = 0,
  .endian = vl_api_l2tpv3_create_tunnel_reply_t_endian,
  .format_fn = vl_api_l2tpv3_create_tunnel_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l2tpv3_create_tunnel_reply_t_tojson,
  .fromjson = vl_api_l2tpv3_create_tunnel_reply_t_fromjson,
  .calc_size = vl_api_l2tpv3_create_tunnel_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L2TPV3_SET_TUNNEL_COOKIES + msg_id_base,
   .name = "l2tpv3_set_tunnel_cookies",
   .handler = vl_api_l2tpv3_set_tunnel_cookies_t_handler,
   .endian = vl_api_l2tpv3_set_tunnel_cookies_t_endian,
   .format_fn = vl_api_l2tpv3_set_tunnel_cookies_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l2tpv3_set_tunnel_cookies_t_tojson,
   .fromjson = vl_api_l2tpv3_set_tunnel_cookies_t_fromjson,
   .calc_size = vl_api_l2tpv3_set_tunnel_cookies_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L2TPV3_SET_TUNNEL_COOKIES_REPLY + msg_id_base,
  .name = "l2tpv3_set_tunnel_cookies_reply",
  .handler = 0,
  .endian = vl_api_l2tpv3_set_tunnel_cookies_reply_t_endian,
  .format_fn = vl_api_l2tpv3_set_tunnel_cookies_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l2tpv3_set_tunnel_cookies_reply_t_tojson,
  .fromjson = vl_api_l2tpv3_set_tunnel_cookies_reply_t_fromjson,
  .calc_size = vl_api_l2tpv3_set_tunnel_cookies_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_IF_L2TPV3_TUNNEL_DUMP + msg_id_base,
   .name = "sw_if_l2tpv3_tunnel_dump",
   .handler = vl_api_sw_if_l2tpv3_tunnel_dump_t_handler,
   .endian = vl_api_sw_if_l2tpv3_tunnel_dump_t_endian,
   .format_fn = vl_api_sw_if_l2tpv3_tunnel_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_if_l2tpv3_tunnel_dump_t_tojson,
   .fromjson = vl_api_sw_if_l2tpv3_tunnel_dump_t_fromjson,
   .calc_size = vl_api_sw_if_l2tpv3_tunnel_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_IF_L2TPV3_TUNNEL_DETAILS + msg_id_base,
  .name = "sw_if_l2tpv3_tunnel_details",
  .handler = 0,
  .endian = vl_api_sw_if_l2tpv3_tunnel_details_t_endian,
  .format_fn = vl_api_sw_if_l2tpv3_tunnel_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_if_l2tpv3_tunnel_details_t_tojson,
  .fromjson = vl_api_sw_if_l2tpv3_tunnel_details_t_fromjson,
  .calc_size = vl_api_sw_if_l2tpv3_tunnel_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L2TPV3_INTERFACE_ENABLE_DISABLE + msg_id_base,
   .name = "l2tpv3_interface_enable_disable",
   .handler = vl_api_l2tpv3_interface_enable_disable_t_handler,
   .endian = vl_api_l2tpv3_interface_enable_disable_t_endian,
   .format_fn = vl_api_l2tpv3_interface_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l2tpv3_interface_enable_disable_t_tojson,
   .fromjson = vl_api_l2tpv3_interface_enable_disable_t_fromjson,
   .calc_size = vl_api_l2tpv3_interface_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L2TPV3_INTERFACE_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "l2tpv3_interface_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_l2tpv3_interface_enable_disable_reply_t_endian,
  .format_fn = vl_api_l2tpv3_interface_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l2tpv3_interface_enable_disable_reply_t_tojson,
  .fromjson = vl_api_l2tpv3_interface_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_l2tpv3_interface_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L2TPV3_SET_LOOKUP_KEY + msg_id_base,
   .name = "l2tpv3_set_lookup_key",
   .handler = vl_api_l2tpv3_set_lookup_key_t_handler,
   .endian = vl_api_l2tpv3_set_lookup_key_t_endian,
   .format_fn = vl_api_l2tpv3_set_lookup_key_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l2tpv3_set_lookup_key_t_tojson,
   .fromjson = vl_api_l2tpv3_set_lookup_key_t_fromjson,
   .calc_size = vl_api_l2tpv3_set_lookup_key_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L2TPV3_SET_LOOKUP_KEY_REPLY + msg_id_base,
  .name = "l2tpv3_set_lookup_key_reply",
  .handler = 0,
  .endian = vl_api_l2tpv3_set_lookup_key_reply_t_endian,
  .format_fn = vl_api_l2tpv3_set_lookup_key_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l2tpv3_set_lookup_key_reply_t_tojson,
  .fromjson = vl_api_l2tpv3_set_lookup_key_reply_t_fromjson,
  .calc_size = vl_api_l2tpv3_set_lookup_key_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
