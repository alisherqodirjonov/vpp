#define vl_endianfun		/* define message structures */
#include "nat66.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "nat66.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "nat66.api.h"
#undef vl_printfun

#include "nat66.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("nat66_5eeaa476", VL_MSG_NAT66_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_nat66);
   vl_msg_api_add_msg_name_crc (am, "nat66_plugin_enable_disable_56f2f83b",
                                VL_API_NAT66_PLUGIN_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat66_plugin_enable_disable_reply_e8d4e804",
                                VL_API_NAT66_PLUGIN_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat66_add_del_interface_f3699b83",
                                VL_API_NAT66_ADD_DEL_INTERFACE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat66_add_del_interface_reply_e8d4e804",
                                VL_API_NAT66_ADD_DEL_INTERFACE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat66_interface_dump_51077d14",
                                VL_API_NAT66_INTERFACE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat66_interface_details_5d286289",
                                VL_API_NAT66_INTERFACE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat66_add_del_static_mapping_3ed88f71",
                                VL_API_NAT66_ADD_DEL_STATIC_MAPPING + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat66_add_del_static_mapping_reply_e8d4e804",
                                VL_API_NAT66_ADD_DEL_STATIC_MAPPING_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat66_static_mapping_dump_51077d14",
                                VL_API_NAT66_STATIC_MAPPING_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat66_static_mapping_details_df39654b",
                                VL_API_NAT66_STATIC_MAPPING_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT66_PLUGIN_ENABLE_DISABLE + msg_id_base,
   .name = "nat66_plugin_enable_disable",
   .handler = vl_api_nat66_plugin_enable_disable_t_handler,
   .endian = vl_api_nat66_plugin_enable_disable_t_endian,
   .format_fn = vl_api_nat66_plugin_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat66_plugin_enable_disable_t_tojson,
   .fromjson = vl_api_nat66_plugin_enable_disable_t_fromjson,
   .calc_size = vl_api_nat66_plugin_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT66_PLUGIN_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "nat66_plugin_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_nat66_plugin_enable_disable_reply_t_endian,
  .format_fn = vl_api_nat66_plugin_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat66_plugin_enable_disable_reply_t_tojson,
  .fromjson = vl_api_nat66_plugin_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_nat66_plugin_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT66_ADD_DEL_INTERFACE + msg_id_base,
   .name = "nat66_add_del_interface",
   .handler = vl_api_nat66_add_del_interface_t_handler,
   .endian = vl_api_nat66_add_del_interface_t_endian,
   .format_fn = vl_api_nat66_add_del_interface_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat66_add_del_interface_t_tojson,
   .fromjson = vl_api_nat66_add_del_interface_t_fromjson,
   .calc_size = vl_api_nat66_add_del_interface_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT66_ADD_DEL_INTERFACE_REPLY + msg_id_base,
  .name = "nat66_add_del_interface_reply",
  .handler = 0,
  .endian = vl_api_nat66_add_del_interface_reply_t_endian,
  .format_fn = vl_api_nat66_add_del_interface_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat66_add_del_interface_reply_t_tojson,
  .fromjson = vl_api_nat66_add_del_interface_reply_t_fromjson,
  .calc_size = vl_api_nat66_add_del_interface_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT66_INTERFACE_DUMP + msg_id_base,
   .name = "nat66_interface_dump",
   .handler = vl_api_nat66_interface_dump_t_handler,
   .endian = vl_api_nat66_interface_dump_t_endian,
   .format_fn = vl_api_nat66_interface_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat66_interface_dump_t_tojson,
   .fromjson = vl_api_nat66_interface_dump_t_fromjson,
   .calc_size = vl_api_nat66_interface_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT66_INTERFACE_DETAILS + msg_id_base,
  .name = "nat66_interface_details",
  .handler = 0,
  .endian = vl_api_nat66_interface_details_t_endian,
  .format_fn = vl_api_nat66_interface_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat66_interface_details_t_tojson,
  .fromjson = vl_api_nat66_interface_details_t_fromjson,
  .calc_size = vl_api_nat66_interface_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT66_ADD_DEL_STATIC_MAPPING + msg_id_base,
   .name = "nat66_add_del_static_mapping",
   .handler = vl_api_nat66_add_del_static_mapping_t_handler,
   .endian = vl_api_nat66_add_del_static_mapping_t_endian,
   .format_fn = vl_api_nat66_add_del_static_mapping_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat66_add_del_static_mapping_t_tojson,
   .fromjson = vl_api_nat66_add_del_static_mapping_t_fromjson,
   .calc_size = vl_api_nat66_add_del_static_mapping_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT66_ADD_DEL_STATIC_MAPPING_REPLY + msg_id_base,
  .name = "nat66_add_del_static_mapping_reply",
  .handler = 0,
  .endian = vl_api_nat66_add_del_static_mapping_reply_t_endian,
  .format_fn = vl_api_nat66_add_del_static_mapping_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat66_add_del_static_mapping_reply_t_tojson,
  .fromjson = vl_api_nat66_add_del_static_mapping_reply_t_fromjson,
  .calc_size = vl_api_nat66_add_del_static_mapping_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT66_STATIC_MAPPING_DUMP + msg_id_base,
   .name = "nat66_static_mapping_dump",
   .handler = vl_api_nat66_static_mapping_dump_t_handler,
   .endian = vl_api_nat66_static_mapping_dump_t_endian,
   .format_fn = vl_api_nat66_static_mapping_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat66_static_mapping_dump_t_tojson,
   .fromjson = vl_api_nat66_static_mapping_dump_t_fromjson,
   .calc_size = vl_api_nat66_static_mapping_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT66_STATIC_MAPPING_DETAILS + msg_id_base,
  .name = "nat66_static_mapping_details",
  .handler = 0,
  .endian = vl_api_nat66_static_mapping_details_t_endian,
  .format_fn = vl_api_nat66_static_mapping_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat66_static_mapping_details_t_tojson,
  .fromjson = vl_api_nat66_static_mapping_details_t_fromjson,
  .calc_size = vl_api_nat66_static_mapping_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
