#define vl_endianfun		/* define message structures */
#include "pot.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "pot.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "pot.api.h"
#undef vl_printfun

#include "pot.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("pot_a9d8e55c", VL_MSG_POT_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_pot);
   vl_msg_api_add_msg_name_crc (am, "pot_profile_add_ad5da3a3",
                                VL_API_POT_PROFILE_ADD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pot_profile_add_reply_e8d4e804",
                                VL_API_POT_PROFILE_ADD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pot_profile_activate_0770af98",
                                VL_API_POT_PROFILE_ACTIVATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pot_profile_activate_reply_e8d4e804",
                                VL_API_POT_PROFILE_ACTIVATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pot_profile_del_cd63f53b",
                                VL_API_POT_PROFILE_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pot_profile_del_reply_e8d4e804",
                                VL_API_POT_PROFILE_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pot_profile_show_config_dump_005b7d59",
                                VL_API_POT_PROFILE_SHOW_CONFIG_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pot_profile_show_config_details_b7ce0618",
                                VL_API_POT_PROFILE_SHOW_CONFIG_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_POT_PROFILE_ADD + msg_id_base,
   .name = "pot_profile_add",
   .handler = vl_api_pot_profile_add_t_handler,
   .endian = vl_api_pot_profile_add_t_endian,
   .format_fn = vl_api_pot_profile_add_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pot_profile_add_t_tojson,
   .fromjson = vl_api_pot_profile_add_t_fromjson,
   .calc_size = vl_api_pot_profile_add_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_POT_PROFILE_ADD_REPLY + msg_id_base,
  .name = "pot_profile_add_reply",
  .handler = 0,
  .endian = vl_api_pot_profile_add_reply_t_endian,
  .format_fn = vl_api_pot_profile_add_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pot_profile_add_reply_t_tojson,
  .fromjson = vl_api_pot_profile_add_reply_t_fromjson,
  .calc_size = vl_api_pot_profile_add_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_POT_PROFILE_ACTIVATE + msg_id_base,
   .name = "pot_profile_activate",
   .handler = vl_api_pot_profile_activate_t_handler,
   .endian = vl_api_pot_profile_activate_t_endian,
   .format_fn = vl_api_pot_profile_activate_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pot_profile_activate_t_tojson,
   .fromjson = vl_api_pot_profile_activate_t_fromjson,
   .calc_size = vl_api_pot_profile_activate_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_POT_PROFILE_ACTIVATE_REPLY + msg_id_base,
  .name = "pot_profile_activate_reply",
  .handler = 0,
  .endian = vl_api_pot_profile_activate_reply_t_endian,
  .format_fn = vl_api_pot_profile_activate_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pot_profile_activate_reply_t_tojson,
  .fromjson = vl_api_pot_profile_activate_reply_t_fromjson,
  .calc_size = vl_api_pot_profile_activate_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_POT_PROFILE_DEL + msg_id_base,
   .name = "pot_profile_del",
   .handler = vl_api_pot_profile_del_t_handler,
   .endian = vl_api_pot_profile_del_t_endian,
   .format_fn = vl_api_pot_profile_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pot_profile_del_t_tojson,
   .fromjson = vl_api_pot_profile_del_t_fromjson,
   .calc_size = vl_api_pot_profile_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_POT_PROFILE_DEL_REPLY + msg_id_base,
  .name = "pot_profile_del_reply",
  .handler = 0,
  .endian = vl_api_pot_profile_del_reply_t_endian,
  .format_fn = vl_api_pot_profile_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pot_profile_del_reply_t_tojson,
  .fromjson = vl_api_pot_profile_del_reply_t_fromjson,
  .calc_size = vl_api_pot_profile_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_POT_PROFILE_SHOW_CONFIG_DUMP + msg_id_base,
   .name = "pot_profile_show_config_dump",
   .handler = vl_api_pot_profile_show_config_dump_t_handler,
   .endian = vl_api_pot_profile_show_config_dump_t_endian,
   .format_fn = vl_api_pot_profile_show_config_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pot_profile_show_config_dump_t_tojson,
   .fromjson = vl_api_pot_profile_show_config_dump_t_fromjson,
   .calc_size = vl_api_pot_profile_show_config_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_POT_PROFILE_SHOW_CONFIG_DETAILS + msg_id_base,
  .name = "pot_profile_show_config_details",
  .handler = 0,
  .endian = vl_api_pot_profile_show_config_details_t_endian,
  .format_fn = vl_api_pot_profile_show_config_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pot_profile_show_config_details_t_tojson,
  .fromjson = vl_api_pot_profile_show_config_details_t_fromjson,
  .calc_size = vl_api_pot_profile_show_config_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
