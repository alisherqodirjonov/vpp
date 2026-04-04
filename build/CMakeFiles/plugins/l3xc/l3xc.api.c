#define vl_endianfun		/* define message structures */
#include "l3xc.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "l3xc.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "l3xc.api.h"
#undef vl_printfun

#include "l3xc.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("l3xc_5a81a1af", VL_MSG_L3XC_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_l3xc);
   vl_msg_api_add_msg_name_crc (am, "l3xc_plugin_get_version_51077d14",
                                VL_API_L3XC_PLUGIN_GET_VERSION + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l3xc_plugin_get_version_reply_9b32cf86",
                                VL_API_L3XC_PLUGIN_GET_VERSION_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l3xc_update_e96aabdf",
                                VL_API_L3XC_UPDATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l3xc_update_reply_1992deab",
                                VL_API_L3XC_UPDATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l3xc_del_e7dbef91",
                                VL_API_L3XC_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l3xc_del_reply_e8d4e804",
                                VL_API_L3XC_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l3xc_dump_f9e6675e",
                                VL_API_L3XC_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "l3xc_details_bc5bf852",
                                VL_API_L3XC_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L3XC_PLUGIN_GET_VERSION + msg_id_base,
   .name = "l3xc_plugin_get_version",
   .handler = vl_api_l3xc_plugin_get_version_t_handler,
   .endian = vl_api_l3xc_plugin_get_version_t_endian,
   .format_fn = vl_api_l3xc_plugin_get_version_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l3xc_plugin_get_version_t_tojson,
   .fromjson = vl_api_l3xc_plugin_get_version_t_fromjson,
   .calc_size = vl_api_l3xc_plugin_get_version_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L3XC_PLUGIN_GET_VERSION_REPLY + msg_id_base,
  .name = "l3xc_plugin_get_version_reply",
  .handler = 0,
  .endian = vl_api_l3xc_plugin_get_version_reply_t_endian,
  .format_fn = vl_api_l3xc_plugin_get_version_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l3xc_plugin_get_version_reply_t_tojson,
  .fromjson = vl_api_l3xc_plugin_get_version_reply_t_fromjson,
  .calc_size = vl_api_l3xc_plugin_get_version_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L3XC_UPDATE + msg_id_base,
   .name = "l3xc_update",
   .handler = vl_api_l3xc_update_t_handler,
   .endian = vl_api_l3xc_update_t_endian,
   .format_fn = vl_api_l3xc_update_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l3xc_update_t_tojson,
   .fromjson = vl_api_l3xc_update_t_fromjson,
   .calc_size = vl_api_l3xc_update_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L3XC_UPDATE_REPLY + msg_id_base,
  .name = "l3xc_update_reply",
  .handler = 0,
  .endian = vl_api_l3xc_update_reply_t_endian,
  .format_fn = vl_api_l3xc_update_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l3xc_update_reply_t_tojson,
  .fromjson = vl_api_l3xc_update_reply_t_fromjson,
  .calc_size = vl_api_l3xc_update_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L3XC_DEL + msg_id_base,
   .name = "l3xc_del",
   .handler = vl_api_l3xc_del_t_handler,
   .endian = vl_api_l3xc_del_t_endian,
   .format_fn = vl_api_l3xc_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l3xc_del_t_tojson,
   .fromjson = vl_api_l3xc_del_t_fromjson,
   .calc_size = vl_api_l3xc_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L3XC_DEL_REPLY + msg_id_base,
  .name = "l3xc_del_reply",
  .handler = 0,
  .endian = vl_api_l3xc_del_reply_t_endian,
  .format_fn = vl_api_l3xc_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l3xc_del_reply_t_tojson,
  .fromjson = vl_api_l3xc_del_reply_t_fromjson,
  .calc_size = vl_api_l3xc_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_L3XC_DUMP + msg_id_base,
   .name = "l3xc_dump",
   .handler = vl_api_l3xc_dump_t_handler,
   .endian = vl_api_l3xc_dump_t_endian,
   .format_fn = vl_api_l3xc_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_l3xc_dump_t_tojson,
   .fromjson = vl_api_l3xc_dump_t_fromjson,
   .calc_size = vl_api_l3xc_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_L3XC_DETAILS + msg_id_base,
  .name = "l3xc_details",
  .handler = 0,
  .endian = vl_api_l3xc_details_t_endian,
  .format_fn = vl_api_l3xc_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_l3xc_details_t_tojson,
  .fromjson = vl_api_l3xc_details_t_fromjson,
  .calc_size = vl_api_l3xc_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
