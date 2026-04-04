#define vl_endianfun		/* define message structures */
#include "svs.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "svs.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "svs.api.h"
#undef vl_printfun

#include "svs.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("svs_06238424", VL_MSG_SVS_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_svs);
   vl_msg_api_add_msg_name_crc (am, "svs_plugin_get_version_51077d14",
                                VL_API_SVS_PLUGIN_GET_VERSION + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "svs_plugin_get_version_reply_9b32cf86",
                                VL_API_SVS_PLUGIN_GET_VERSION_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "svs_table_add_del_7d21cb2a",
                                VL_API_SVS_TABLE_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "svs_table_add_del_reply_e8d4e804",
                                VL_API_SVS_TABLE_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "svs_route_add_del_e49bc63c",
                                VL_API_SVS_ROUTE_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "svs_route_add_del_reply_e8d4e804",
                                VL_API_SVS_ROUTE_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "svs_enable_disable_634b89d2",
                                VL_API_SVS_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "svs_enable_disable_reply_e8d4e804",
                                VL_API_SVS_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "svs_dump_51077d14",
                                VL_API_SVS_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "svs_details_6282cd55",
                                VL_API_SVS_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SVS_PLUGIN_GET_VERSION + msg_id_base,
   .name = "svs_plugin_get_version",
   .handler = vl_api_svs_plugin_get_version_t_handler,
   .endian = vl_api_svs_plugin_get_version_t_endian,
   .format_fn = vl_api_svs_plugin_get_version_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_svs_plugin_get_version_t_tojson,
   .fromjson = vl_api_svs_plugin_get_version_t_fromjson,
   .calc_size = vl_api_svs_plugin_get_version_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SVS_PLUGIN_GET_VERSION_REPLY + msg_id_base,
  .name = "svs_plugin_get_version_reply",
  .handler = 0,
  .endian = vl_api_svs_plugin_get_version_reply_t_endian,
  .format_fn = vl_api_svs_plugin_get_version_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_svs_plugin_get_version_reply_t_tojson,
  .fromjson = vl_api_svs_plugin_get_version_reply_t_fromjson,
  .calc_size = vl_api_svs_plugin_get_version_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SVS_TABLE_ADD_DEL + msg_id_base,
   .name = "svs_table_add_del",
   .handler = vl_api_svs_table_add_del_t_handler,
   .endian = vl_api_svs_table_add_del_t_endian,
   .format_fn = vl_api_svs_table_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_svs_table_add_del_t_tojson,
   .fromjson = vl_api_svs_table_add_del_t_fromjson,
   .calc_size = vl_api_svs_table_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SVS_TABLE_ADD_DEL_REPLY + msg_id_base,
  .name = "svs_table_add_del_reply",
  .handler = 0,
  .endian = vl_api_svs_table_add_del_reply_t_endian,
  .format_fn = vl_api_svs_table_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_svs_table_add_del_reply_t_tojson,
  .fromjson = vl_api_svs_table_add_del_reply_t_fromjson,
  .calc_size = vl_api_svs_table_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SVS_ROUTE_ADD_DEL + msg_id_base,
   .name = "svs_route_add_del",
   .handler = vl_api_svs_route_add_del_t_handler,
   .endian = vl_api_svs_route_add_del_t_endian,
   .format_fn = vl_api_svs_route_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_svs_route_add_del_t_tojson,
   .fromjson = vl_api_svs_route_add_del_t_fromjson,
   .calc_size = vl_api_svs_route_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SVS_ROUTE_ADD_DEL_REPLY + msg_id_base,
  .name = "svs_route_add_del_reply",
  .handler = 0,
  .endian = vl_api_svs_route_add_del_reply_t_endian,
  .format_fn = vl_api_svs_route_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_svs_route_add_del_reply_t_tojson,
  .fromjson = vl_api_svs_route_add_del_reply_t_fromjson,
  .calc_size = vl_api_svs_route_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SVS_ENABLE_DISABLE + msg_id_base,
   .name = "svs_enable_disable",
   .handler = vl_api_svs_enable_disable_t_handler,
   .endian = vl_api_svs_enable_disable_t_endian,
   .format_fn = vl_api_svs_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_svs_enable_disable_t_tojson,
   .fromjson = vl_api_svs_enable_disable_t_fromjson,
   .calc_size = vl_api_svs_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SVS_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "svs_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_svs_enable_disable_reply_t_endian,
  .format_fn = vl_api_svs_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_svs_enable_disable_reply_t_tojson,
  .fromjson = vl_api_svs_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_svs_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SVS_DUMP + msg_id_base,
   .name = "svs_dump",
   .handler = vl_api_svs_dump_t_handler,
   .endian = vl_api_svs_dump_t_endian,
   .format_fn = vl_api_svs_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_svs_dump_t_tojson,
   .fromjson = vl_api_svs_dump_t_fromjson,
   .calc_size = vl_api_svs_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SVS_DETAILS + msg_id_base,
  .name = "svs_details",
  .handler = 0,
  .endian = vl_api_svs_details_t_endian,
  .format_fn = vl_api_svs_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_svs_details_t_tojson,
  .fromjson = vl_api_svs_details_t_fromjson,
  .calc_size = vl_api_svs_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
