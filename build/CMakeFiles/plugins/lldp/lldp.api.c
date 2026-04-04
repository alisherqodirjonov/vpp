#define vl_endianfun		/* define message structures */
#include "lldp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "lldp.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "lldp.api.h"
#undef vl_printfun

#include "lldp.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("lldp_85a9ebb2", VL_MSG_LLDP_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_lldp);
   vl_msg_api_add_msg_name_crc (am, "lldp_config_c14445df",
                                VL_API_LLDP_CONFIG + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lldp_config_reply_e8d4e804",
                                VL_API_LLDP_CONFIG_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_lldp_57afbcd4",
                                VL_API_SW_INTERFACE_SET_LLDP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_lldp_reply_e8d4e804",
                                VL_API_SW_INTERFACE_SET_LLDP_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lldp_dump_f75ba505",
                                VL_API_LLDP_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lldp_dump_reply_53b48f5d",
                                VL_API_LLDP_DUMP_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "lldp_details_c2d226cd",
                                VL_API_LLDP_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LLDP_DUMP + msg_id_base,
   .name = "lldp_dump",
   .handler = vl_api_lldp_dump_t_handler,
   .endian = vl_api_lldp_dump_t_endian,
   .format_fn = vl_api_lldp_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lldp_dump_t_tojson,
   .fromjson = vl_api_lldp_dump_t_fromjson,
   .calc_size = vl_api_lldp_dump_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LLDP_DUMP_REPLY + msg_id_base,
  .name = "lldp_dump_reply",
  .handler = 0,
  .endian = vl_api_lldp_dump_reply_t_endian,
  .format_fn = vl_api_lldp_dump_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lldp_dump_reply_t_tojson,
  .fromjson = vl_api_lldp_dump_reply_t_fromjson,
  .calc_size = vl_api_lldp_dump_reply_t_calc_size,
  .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LLDP_DETAILS + msg_id_base,
  .name = "lldp_details",
  .handler = 0,
  .endian = vl_api_lldp_details_t_endian,
  .format_fn = vl_api_lldp_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lldp_details_t_tojson,
  .fromjson = vl_api_lldp_details_t_fromjson,
  .calc_size = vl_api_lldp_details_t_calc_size,
  .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LLDP_CONFIG + msg_id_base,
   .name = "lldp_config",
   .handler = vl_api_lldp_config_t_handler,
   .endian = vl_api_lldp_config_t_endian,
   .format_fn = vl_api_lldp_config_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_lldp_config_t_tojson,
   .fromjson = vl_api_lldp_config_t_fromjson,
   .calc_size = vl_api_lldp_config_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LLDP_CONFIG_REPLY + msg_id_base,
  .name = "lldp_config_reply",
  .handler = 0,
  .endian = vl_api_lldp_config_reply_t_endian,
  .format_fn = vl_api_lldp_config_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_lldp_config_reply_t_tojson,
  .fromjson = vl_api_lldp_config_reply_t_fromjson,
  .calc_size = vl_api_lldp_config_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SET_LLDP + msg_id_base,
   .name = "sw_interface_set_lldp",
   .handler = vl_api_sw_interface_set_lldp_t_handler,
   .endian = vl_api_sw_interface_set_lldp_t_endian,
   .format_fn = vl_api_sw_interface_set_lldp_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_set_lldp_t_tojson,
   .fromjson = vl_api_sw_interface_set_lldp_t_fromjson,
   .calc_size = vl_api_sw_interface_set_lldp_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SET_LLDP_REPLY + msg_id_base,
  .name = "sw_interface_set_lldp_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_set_lldp_reply_t_endian,
  .format_fn = vl_api_sw_interface_set_lldp_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_set_lldp_reply_t_tojson,
  .fromjson = vl_api_sw_interface_set_lldp_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_set_lldp_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
