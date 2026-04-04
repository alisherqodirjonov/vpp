#define vl_endianfun		/* define message structures */
#include "gre.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "gre.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "gre.api.h"
#undef vl_printfun

#include "gre.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("gre_05dfeb04", VL_MSG_GRE_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_gre);
   vl_msg_api_add_msg_name_crc (am, "gre_tunnel_add_del_a27d7f17",
                                VL_API_GRE_TUNNEL_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gre_tunnel_add_del_reply_5383d31f",
                                VL_API_GRE_TUNNEL_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gre_tunnel_add_del_v2_7d9576de",
                                VL_API_GRE_TUNNEL_ADD_DEL_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gre_tunnel_add_del_v2_reply_5383d31f",
                                VL_API_GRE_TUNNEL_ADD_DEL_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gre_tunnel_dump_f9e6675e",
                                VL_API_GRE_TUNNEL_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gre_tunnel_dump_reply_e8d4e804",
                                VL_API_GRE_TUNNEL_DUMP_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gre_tunnel_dump_v2_f9e6675e",
                                VL_API_GRE_TUNNEL_DUMP_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gre_tunnel_dump_v2_reply_e8d4e804",
                                VL_API_GRE_TUNNEL_DUMP_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gre_tunnel_details_24435433",
                                VL_API_GRE_TUNNEL_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gre_tunnel_details_v2_65521177",
                                VL_API_GRE_TUNNEL_DETAILS_V2 + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GRE_TUNNEL_DUMP + msg_id_base,
   .name = "gre_tunnel_dump",
   .handler = vl_api_gre_tunnel_dump_t_handler,
   .endian = vl_api_gre_tunnel_dump_t_endian,
   .format_fn = vl_api_gre_tunnel_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gre_tunnel_dump_t_tojson,
   .fromjson = vl_api_gre_tunnel_dump_t_fromjson,
   .calc_size = vl_api_gre_tunnel_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GRE_TUNNEL_DUMP_REPLY + msg_id_base,
  .name = "gre_tunnel_dump_reply",
  .handler = 0,
  .endian = vl_api_gre_tunnel_dump_reply_t_endian,
  .format_fn = vl_api_gre_tunnel_dump_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gre_tunnel_dump_reply_t_tojson,
  .fromjson = vl_api_gre_tunnel_dump_reply_t_fromjson,
  .calc_size = vl_api_gre_tunnel_dump_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GRE_TUNNEL_DUMP_V2 + msg_id_base,
   .name = "gre_tunnel_dump_v2",
   .handler = vl_api_gre_tunnel_dump_v2_t_handler,
   .endian = vl_api_gre_tunnel_dump_v2_t_endian,
   .format_fn = vl_api_gre_tunnel_dump_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gre_tunnel_dump_v2_t_tojson,
   .fromjson = vl_api_gre_tunnel_dump_v2_t_fromjson,
   .calc_size = vl_api_gre_tunnel_dump_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GRE_TUNNEL_DUMP_V2_REPLY + msg_id_base,
  .name = "gre_tunnel_dump_v2_reply",
  .handler = 0,
  .endian = vl_api_gre_tunnel_dump_v2_reply_t_endian,
  .format_fn = vl_api_gre_tunnel_dump_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gre_tunnel_dump_v2_reply_t_tojson,
  .fromjson = vl_api_gre_tunnel_dump_v2_reply_t_fromjson,
  .calc_size = vl_api_gre_tunnel_dump_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GRE_TUNNEL_ADD_DEL + msg_id_base,
   .name = "gre_tunnel_add_del",
   .handler = vl_api_gre_tunnel_add_del_t_handler,
   .endian = vl_api_gre_tunnel_add_del_t_endian,
   .format_fn = vl_api_gre_tunnel_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gre_tunnel_add_del_t_tojson,
   .fromjson = vl_api_gre_tunnel_add_del_t_fromjson,
   .calc_size = vl_api_gre_tunnel_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GRE_TUNNEL_ADD_DEL_REPLY + msg_id_base,
  .name = "gre_tunnel_add_del_reply",
  .handler = 0,
  .endian = vl_api_gre_tunnel_add_del_reply_t_endian,
  .format_fn = vl_api_gre_tunnel_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gre_tunnel_add_del_reply_t_tojson,
  .fromjson = vl_api_gre_tunnel_add_del_reply_t_fromjson,
  .calc_size = vl_api_gre_tunnel_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GRE_TUNNEL_ADD_DEL_V2 + msg_id_base,
   .name = "gre_tunnel_add_del_v2",
   .handler = vl_api_gre_tunnel_add_del_v2_t_handler,
   .endian = vl_api_gre_tunnel_add_del_v2_t_endian,
   .format_fn = vl_api_gre_tunnel_add_del_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gre_tunnel_add_del_v2_t_tojson,
   .fromjson = vl_api_gre_tunnel_add_del_v2_t_fromjson,
   .calc_size = vl_api_gre_tunnel_add_del_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GRE_TUNNEL_ADD_DEL_V2_REPLY + msg_id_base,
  .name = "gre_tunnel_add_del_v2_reply",
  .handler = 0,
  .endian = vl_api_gre_tunnel_add_del_v2_reply_t_endian,
  .format_fn = vl_api_gre_tunnel_add_del_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gre_tunnel_add_del_v2_reply_t_tojson,
  .fromjson = vl_api_gre_tunnel_add_del_v2_reply_t_fromjson,
  .calc_size = vl_api_gre_tunnel_add_del_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
