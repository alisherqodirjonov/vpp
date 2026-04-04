#define vl_endianfun		/* define message structures */
#include "geneve.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "geneve.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "geneve.api.h"
#undef vl_printfun

#include "geneve.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("geneve_5c01c4a7", VL_MSG_GENEVE_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_geneve);
   vl_msg_api_add_msg_name_crc (am, "geneve_add_del_tunnel_99445831",
                                VL_API_GENEVE_ADD_DEL_TUNNEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "geneve_add_del_tunnel_reply_5383d31f",
                                VL_API_GENEVE_ADD_DEL_TUNNEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "geneve_add_del_tunnel2_8c2a9999",
                                VL_API_GENEVE_ADD_DEL_TUNNEL2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "geneve_add_del_tunnel2_reply_5383d31f",
                                VL_API_GENEVE_ADD_DEL_TUNNEL2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "geneve_tunnel_dump_f9e6675e",
                                VL_API_GENEVE_TUNNEL_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "geneve_tunnel_details_6b16eb24",
                                VL_API_GENEVE_TUNNEL_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_geneve_bypass_65247409",
                                VL_API_SW_INTERFACE_SET_GENEVE_BYPASS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_geneve_bypass_reply_e8d4e804",
                                VL_API_SW_INTERFACE_SET_GENEVE_BYPASS_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GENEVE_ADD_DEL_TUNNEL + msg_id_base,
   .name = "geneve_add_del_tunnel",
   .handler = vl_api_geneve_add_del_tunnel_t_handler,
   .endian = vl_api_geneve_add_del_tunnel_t_endian,
   .format_fn = vl_api_geneve_add_del_tunnel_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_geneve_add_del_tunnel_t_tojson,
   .fromjson = vl_api_geneve_add_del_tunnel_t_fromjson,
   .calc_size = vl_api_geneve_add_del_tunnel_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GENEVE_ADD_DEL_TUNNEL_REPLY + msg_id_base,
  .name = "geneve_add_del_tunnel_reply",
  .handler = 0,
  .endian = vl_api_geneve_add_del_tunnel_reply_t_endian,
  .format_fn = vl_api_geneve_add_del_tunnel_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_geneve_add_del_tunnel_reply_t_tojson,
  .fromjson = vl_api_geneve_add_del_tunnel_reply_t_fromjson,
  .calc_size = vl_api_geneve_add_del_tunnel_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GENEVE_ADD_DEL_TUNNEL2 + msg_id_base,
   .name = "geneve_add_del_tunnel2",
   .handler = vl_api_geneve_add_del_tunnel2_t_handler,
   .endian = vl_api_geneve_add_del_tunnel2_t_endian,
   .format_fn = vl_api_geneve_add_del_tunnel2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_geneve_add_del_tunnel2_t_tojson,
   .fromjson = vl_api_geneve_add_del_tunnel2_t_fromjson,
   .calc_size = vl_api_geneve_add_del_tunnel2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GENEVE_ADD_DEL_TUNNEL2_REPLY + msg_id_base,
  .name = "geneve_add_del_tunnel2_reply",
  .handler = 0,
  .endian = vl_api_geneve_add_del_tunnel2_reply_t_endian,
  .format_fn = vl_api_geneve_add_del_tunnel2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_geneve_add_del_tunnel2_reply_t_tojson,
  .fromjson = vl_api_geneve_add_del_tunnel2_reply_t_fromjson,
  .calc_size = vl_api_geneve_add_del_tunnel2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GENEVE_TUNNEL_DUMP + msg_id_base,
   .name = "geneve_tunnel_dump",
   .handler = vl_api_geneve_tunnel_dump_t_handler,
   .endian = vl_api_geneve_tunnel_dump_t_endian,
   .format_fn = vl_api_geneve_tunnel_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_geneve_tunnel_dump_t_tojson,
   .fromjson = vl_api_geneve_tunnel_dump_t_fromjson,
   .calc_size = vl_api_geneve_tunnel_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GENEVE_TUNNEL_DETAILS + msg_id_base,
  .name = "geneve_tunnel_details",
  .handler = 0,
  .endian = vl_api_geneve_tunnel_details_t_endian,
  .format_fn = vl_api_geneve_tunnel_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_geneve_tunnel_details_t_tojson,
  .fromjson = vl_api_geneve_tunnel_details_t_fromjson,
  .calc_size = vl_api_geneve_tunnel_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SET_GENEVE_BYPASS + msg_id_base,
   .name = "sw_interface_set_geneve_bypass",
   .handler = vl_api_sw_interface_set_geneve_bypass_t_handler,
   .endian = vl_api_sw_interface_set_geneve_bypass_t_endian,
   .format_fn = vl_api_sw_interface_set_geneve_bypass_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_set_geneve_bypass_t_tojson,
   .fromjson = vl_api_sw_interface_set_geneve_bypass_t_fromjson,
   .calc_size = vl_api_sw_interface_set_geneve_bypass_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SET_GENEVE_BYPASS_REPLY + msg_id_base,
  .name = "sw_interface_set_geneve_bypass_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_set_geneve_bypass_reply_t_endian,
  .format_fn = vl_api_sw_interface_set_geneve_bypass_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_set_geneve_bypass_reply_t_tojson,
  .fromjson = vl_api_sw_interface_set_geneve_bypass_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_set_geneve_bypass_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
