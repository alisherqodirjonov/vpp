#define vl_endianfun		/* define message structures */
#include "ipip.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ipip.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "ipip.api.h"
#undef vl_printfun

#include "ipip.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("ipip_03c9c667", VL_MSG_IPIP_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_ipip);
   vl_msg_api_add_msg_name_crc (am, "ipip_add_tunnel_2ac399f5",
                                VL_API_IPIP_ADD_TUNNEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipip_add_tunnel_reply_5383d31f",
                                VL_API_IPIP_ADD_TUNNEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipip_del_tunnel_f9e6675e",
                                VL_API_IPIP_DEL_TUNNEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipip_del_tunnel_reply_e8d4e804",
                                VL_API_IPIP_DEL_TUNNEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipip_6rd_add_tunnel_b9ec1863",
                                VL_API_IPIP_6RD_ADD_TUNNEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipip_6rd_add_tunnel_reply_5383d31f",
                                VL_API_IPIP_6RD_ADD_TUNNEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipip_6rd_del_tunnel_f9e6675e",
                                VL_API_IPIP_6RD_DEL_TUNNEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipip_6rd_del_tunnel_reply_e8d4e804",
                                VL_API_IPIP_6RD_DEL_TUNNEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipip_tunnel_dump_f9e6675e",
                                VL_API_IPIP_TUNNEL_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipip_tunnel_details_d31cb34e",
                                VL_API_IPIP_TUNNEL_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPIP_ADD_TUNNEL + msg_id_base,
   .name = "ipip_add_tunnel",
   .handler = vl_api_ipip_add_tunnel_t_handler,
   .endian = vl_api_ipip_add_tunnel_t_endian,
   .format_fn = vl_api_ipip_add_tunnel_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipip_add_tunnel_t_tojson,
   .fromjson = vl_api_ipip_add_tunnel_t_fromjson,
   .calc_size = vl_api_ipip_add_tunnel_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPIP_ADD_TUNNEL_REPLY + msg_id_base,
  .name = "ipip_add_tunnel_reply",
  .handler = 0,
  .endian = vl_api_ipip_add_tunnel_reply_t_endian,
  .format_fn = vl_api_ipip_add_tunnel_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipip_add_tunnel_reply_t_tojson,
  .fromjson = vl_api_ipip_add_tunnel_reply_t_fromjson,
  .calc_size = vl_api_ipip_add_tunnel_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPIP_DEL_TUNNEL + msg_id_base,
   .name = "ipip_del_tunnel",
   .handler = vl_api_ipip_del_tunnel_t_handler,
   .endian = vl_api_ipip_del_tunnel_t_endian,
   .format_fn = vl_api_ipip_del_tunnel_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipip_del_tunnel_t_tojson,
   .fromjson = vl_api_ipip_del_tunnel_t_fromjson,
   .calc_size = vl_api_ipip_del_tunnel_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPIP_DEL_TUNNEL_REPLY + msg_id_base,
  .name = "ipip_del_tunnel_reply",
  .handler = 0,
  .endian = vl_api_ipip_del_tunnel_reply_t_endian,
  .format_fn = vl_api_ipip_del_tunnel_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipip_del_tunnel_reply_t_tojson,
  .fromjson = vl_api_ipip_del_tunnel_reply_t_fromjson,
  .calc_size = vl_api_ipip_del_tunnel_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPIP_6RD_ADD_TUNNEL + msg_id_base,
   .name = "ipip_6rd_add_tunnel",
   .handler = vl_api_ipip_6rd_add_tunnel_t_handler,
   .endian = vl_api_ipip_6rd_add_tunnel_t_endian,
   .format_fn = vl_api_ipip_6rd_add_tunnel_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipip_6rd_add_tunnel_t_tojson,
   .fromjson = vl_api_ipip_6rd_add_tunnel_t_fromjson,
   .calc_size = vl_api_ipip_6rd_add_tunnel_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPIP_6RD_ADD_TUNNEL_REPLY + msg_id_base,
  .name = "ipip_6rd_add_tunnel_reply",
  .handler = 0,
  .endian = vl_api_ipip_6rd_add_tunnel_reply_t_endian,
  .format_fn = vl_api_ipip_6rd_add_tunnel_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipip_6rd_add_tunnel_reply_t_tojson,
  .fromjson = vl_api_ipip_6rd_add_tunnel_reply_t_fromjson,
  .calc_size = vl_api_ipip_6rd_add_tunnel_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPIP_6RD_DEL_TUNNEL + msg_id_base,
   .name = "ipip_6rd_del_tunnel",
   .handler = vl_api_ipip_6rd_del_tunnel_t_handler,
   .endian = vl_api_ipip_6rd_del_tunnel_t_endian,
   .format_fn = vl_api_ipip_6rd_del_tunnel_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipip_6rd_del_tunnel_t_tojson,
   .fromjson = vl_api_ipip_6rd_del_tunnel_t_fromjson,
   .calc_size = vl_api_ipip_6rd_del_tunnel_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPIP_6RD_DEL_TUNNEL_REPLY + msg_id_base,
  .name = "ipip_6rd_del_tunnel_reply",
  .handler = 0,
  .endian = vl_api_ipip_6rd_del_tunnel_reply_t_endian,
  .format_fn = vl_api_ipip_6rd_del_tunnel_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipip_6rd_del_tunnel_reply_t_tojson,
  .fromjson = vl_api_ipip_6rd_del_tunnel_reply_t_fromjson,
  .calc_size = vl_api_ipip_6rd_del_tunnel_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPIP_TUNNEL_DUMP + msg_id_base,
   .name = "ipip_tunnel_dump",
   .handler = vl_api_ipip_tunnel_dump_t_handler,
   .endian = vl_api_ipip_tunnel_dump_t_endian,
   .format_fn = vl_api_ipip_tunnel_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipip_tunnel_dump_t_tojson,
   .fromjson = vl_api_ipip_tunnel_dump_t_fromjson,
   .calc_size = vl_api_ipip_tunnel_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPIP_TUNNEL_DETAILS + msg_id_base,
  .name = "ipip_tunnel_details",
  .handler = 0,
  .endian = vl_api_ipip_tunnel_details_t_endian,
  .format_fn = vl_api_ipip_tunnel_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipip_tunnel_details_t_tojson,
  .fromjson = vl_api_ipip_tunnel_details_t_fromjson,
  .calc_size = vl_api_ipip_tunnel_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
