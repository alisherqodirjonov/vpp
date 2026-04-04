#define vl_endianfun		/* define message structures */
#include "det44.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "det44.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "det44.api.h"
#undef vl_printfun

#include "det44.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("det44_ee5882b1", VL_MSG_DET44_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_det44);
   vl_msg_api_add_msg_name_crc (am, "det44_plugin_enable_disable_617b6bf8",
                                VL_API_DET44_PLUGIN_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_plugin_enable_disable_reply_e8d4e804",
                                VL_API_DET44_PLUGIN_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_interface_add_del_feature_dc17a836",
                                VL_API_DET44_INTERFACE_ADD_DEL_FEATURE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_interface_add_del_feature_reply_e8d4e804",
                                VL_API_DET44_INTERFACE_ADD_DEL_FEATURE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_interface_dump_51077d14",
                                VL_API_DET44_INTERFACE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_interface_details_e60cc5be",
                                VL_API_DET44_INTERFACE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_add_del_map_1150a190",
                                VL_API_DET44_ADD_DEL_MAP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_add_del_map_reply_e8d4e804",
                                VL_API_DET44_ADD_DEL_MAP_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_forward_7f8a89cd",
                                VL_API_DET44_FORWARD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_forward_reply_a8ccbdc0",
                                VL_API_DET44_FORWARD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_reverse_a7573fe1",
                                VL_API_DET44_REVERSE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_reverse_reply_34066d48",
                                VL_API_DET44_REVERSE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_map_dump_51077d14",
                                VL_API_DET44_MAP_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_map_details_ad91dc83",
                                VL_API_DET44_MAP_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_close_session_out_f6b259d1",
                                VL_API_DET44_CLOSE_SESSION_OUT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_close_session_out_reply_e8d4e804",
                                VL_API_DET44_CLOSE_SESSION_OUT_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_close_session_in_3c68e073",
                                VL_API_DET44_CLOSE_SESSION_IN + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_close_session_in_reply_e8d4e804",
                                VL_API_DET44_CLOSE_SESSION_IN_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_session_dump_e45a3af7",
                                VL_API_DET44_SESSION_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_session_details_27f3c171",
                                VL_API_DET44_SESSION_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_set_timeouts_d4746b16",
                                VL_API_DET44_SET_TIMEOUTS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_set_timeouts_reply_e8d4e804",
                                VL_API_DET44_SET_TIMEOUTS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_get_timeouts_51077d14",
                                VL_API_DET44_GET_TIMEOUTS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "det44_get_timeouts_reply_3c4df4e1",
                                VL_API_DET44_GET_TIMEOUTS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_det_add_del_map_1150a190",
                                VL_API_NAT_DET_ADD_DEL_MAP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_det_add_del_map_reply_e8d4e804",
                                VL_API_NAT_DET_ADD_DEL_MAP_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_det_forward_7f8a89cd",
                                VL_API_NAT_DET_FORWARD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_det_forward_reply_a8ccbdc0",
                                VL_API_NAT_DET_FORWARD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_det_reverse_a7573fe1",
                                VL_API_NAT_DET_REVERSE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_det_reverse_reply_34066d48",
                                VL_API_NAT_DET_REVERSE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_det_map_dump_51077d14",
                                VL_API_NAT_DET_MAP_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_det_map_details_ad91dc83",
                                VL_API_NAT_DET_MAP_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_det_close_session_out_f6b259d1",
                                VL_API_NAT_DET_CLOSE_SESSION_OUT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_det_close_session_out_reply_e8d4e804",
                                VL_API_NAT_DET_CLOSE_SESSION_OUT_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_det_close_session_in_3c68e073",
                                VL_API_NAT_DET_CLOSE_SESSION_IN + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_det_close_session_in_reply_e8d4e804",
                                VL_API_NAT_DET_CLOSE_SESSION_IN_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_det_session_dump_e45a3af7",
                                VL_API_NAT_DET_SESSION_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nat_det_session_details_27f3c171",
                                VL_API_NAT_DET_SESSION_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DET44_PLUGIN_ENABLE_DISABLE + msg_id_base,
   .name = "det44_plugin_enable_disable",
   .handler = vl_api_det44_plugin_enable_disable_t_handler,
   .endian = vl_api_det44_plugin_enable_disable_t_endian,
   .format_fn = vl_api_det44_plugin_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_det44_plugin_enable_disable_t_tojson,
   .fromjson = vl_api_det44_plugin_enable_disable_t_fromjson,
   .calc_size = vl_api_det44_plugin_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DET44_PLUGIN_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "det44_plugin_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_det44_plugin_enable_disable_reply_t_endian,
  .format_fn = vl_api_det44_plugin_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_det44_plugin_enable_disable_reply_t_tojson,
  .fromjson = vl_api_det44_plugin_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_det44_plugin_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DET44_INTERFACE_ADD_DEL_FEATURE + msg_id_base,
   .name = "det44_interface_add_del_feature",
   .handler = vl_api_det44_interface_add_del_feature_t_handler,
   .endian = vl_api_det44_interface_add_del_feature_t_endian,
   .format_fn = vl_api_det44_interface_add_del_feature_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_det44_interface_add_del_feature_t_tojson,
   .fromjson = vl_api_det44_interface_add_del_feature_t_fromjson,
   .calc_size = vl_api_det44_interface_add_del_feature_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DET44_INTERFACE_ADD_DEL_FEATURE_REPLY + msg_id_base,
  .name = "det44_interface_add_del_feature_reply",
  .handler = 0,
  .endian = vl_api_det44_interface_add_del_feature_reply_t_endian,
  .format_fn = vl_api_det44_interface_add_del_feature_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_det44_interface_add_del_feature_reply_t_tojson,
  .fromjson = vl_api_det44_interface_add_del_feature_reply_t_fromjson,
  .calc_size = vl_api_det44_interface_add_del_feature_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DET44_INTERFACE_DUMP + msg_id_base,
   .name = "det44_interface_dump",
   .handler = vl_api_det44_interface_dump_t_handler,
   .endian = vl_api_det44_interface_dump_t_endian,
   .format_fn = vl_api_det44_interface_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_det44_interface_dump_t_tojson,
   .fromjson = vl_api_det44_interface_dump_t_fromjson,
   .calc_size = vl_api_det44_interface_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DET44_INTERFACE_DETAILS + msg_id_base,
  .name = "det44_interface_details",
  .handler = 0,
  .endian = vl_api_det44_interface_details_t_endian,
  .format_fn = vl_api_det44_interface_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_det44_interface_details_t_tojson,
  .fromjson = vl_api_det44_interface_details_t_fromjson,
  .calc_size = vl_api_det44_interface_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DET44_ADD_DEL_MAP + msg_id_base,
   .name = "det44_add_del_map",
   .handler = vl_api_det44_add_del_map_t_handler,
   .endian = vl_api_det44_add_del_map_t_endian,
   .format_fn = vl_api_det44_add_del_map_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_det44_add_del_map_t_tojson,
   .fromjson = vl_api_det44_add_del_map_t_fromjson,
   .calc_size = vl_api_det44_add_del_map_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DET44_ADD_DEL_MAP_REPLY + msg_id_base,
  .name = "det44_add_del_map_reply",
  .handler = 0,
  .endian = vl_api_det44_add_del_map_reply_t_endian,
  .format_fn = vl_api_det44_add_del_map_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_det44_add_del_map_reply_t_tojson,
  .fromjson = vl_api_det44_add_del_map_reply_t_fromjson,
  .calc_size = vl_api_det44_add_del_map_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DET44_FORWARD + msg_id_base,
   .name = "det44_forward",
   .handler = vl_api_det44_forward_t_handler,
   .endian = vl_api_det44_forward_t_endian,
   .format_fn = vl_api_det44_forward_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_det44_forward_t_tojson,
   .fromjson = vl_api_det44_forward_t_fromjson,
   .calc_size = vl_api_det44_forward_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DET44_FORWARD_REPLY + msg_id_base,
  .name = "det44_forward_reply",
  .handler = 0,
  .endian = vl_api_det44_forward_reply_t_endian,
  .format_fn = vl_api_det44_forward_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_det44_forward_reply_t_tojson,
  .fromjson = vl_api_det44_forward_reply_t_fromjson,
  .calc_size = vl_api_det44_forward_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DET44_REVERSE + msg_id_base,
   .name = "det44_reverse",
   .handler = vl_api_det44_reverse_t_handler,
   .endian = vl_api_det44_reverse_t_endian,
   .format_fn = vl_api_det44_reverse_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_det44_reverse_t_tojson,
   .fromjson = vl_api_det44_reverse_t_fromjson,
   .calc_size = vl_api_det44_reverse_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DET44_REVERSE_REPLY + msg_id_base,
  .name = "det44_reverse_reply",
  .handler = 0,
  .endian = vl_api_det44_reverse_reply_t_endian,
  .format_fn = vl_api_det44_reverse_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_det44_reverse_reply_t_tojson,
  .fromjson = vl_api_det44_reverse_reply_t_fromjson,
  .calc_size = vl_api_det44_reverse_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DET44_MAP_DUMP + msg_id_base,
   .name = "det44_map_dump",
   .handler = vl_api_det44_map_dump_t_handler,
   .endian = vl_api_det44_map_dump_t_endian,
   .format_fn = vl_api_det44_map_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_det44_map_dump_t_tojson,
   .fromjson = vl_api_det44_map_dump_t_fromjson,
   .calc_size = vl_api_det44_map_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DET44_MAP_DETAILS + msg_id_base,
  .name = "det44_map_details",
  .handler = 0,
  .endian = vl_api_det44_map_details_t_endian,
  .format_fn = vl_api_det44_map_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_det44_map_details_t_tojson,
  .fromjson = vl_api_det44_map_details_t_fromjson,
  .calc_size = vl_api_det44_map_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DET44_CLOSE_SESSION_OUT + msg_id_base,
   .name = "det44_close_session_out",
   .handler = vl_api_det44_close_session_out_t_handler,
   .endian = vl_api_det44_close_session_out_t_endian,
   .format_fn = vl_api_det44_close_session_out_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_det44_close_session_out_t_tojson,
   .fromjson = vl_api_det44_close_session_out_t_fromjson,
   .calc_size = vl_api_det44_close_session_out_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DET44_CLOSE_SESSION_OUT_REPLY + msg_id_base,
  .name = "det44_close_session_out_reply",
  .handler = 0,
  .endian = vl_api_det44_close_session_out_reply_t_endian,
  .format_fn = vl_api_det44_close_session_out_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_det44_close_session_out_reply_t_tojson,
  .fromjson = vl_api_det44_close_session_out_reply_t_fromjson,
  .calc_size = vl_api_det44_close_session_out_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DET44_CLOSE_SESSION_IN + msg_id_base,
   .name = "det44_close_session_in",
   .handler = vl_api_det44_close_session_in_t_handler,
   .endian = vl_api_det44_close_session_in_t_endian,
   .format_fn = vl_api_det44_close_session_in_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_det44_close_session_in_t_tojson,
   .fromjson = vl_api_det44_close_session_in_t_fromjson,
   .calc_size = vl_api_det44_close_session_in_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DET44_CLOSE_SESSION_IN_REPLY + msg_id_base,
  .name = "det44_close_session_in_reply",
  .handler = 0,
  .endian = vl_api_det44_close_session_in_reply_t_endian,
  .format_fn = vl_api_det44_close_session_in_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_det44_close_session_in_reply_t_tojson,
  .fromjson = vl_api_det44_close_session_in_reply_t_fromjson,
  .calc_size = vl_api_det44_close_session_in_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DET44_SESSION_DUMP + msg_id_base,
   .name = "det44_session_dump",
   .handler = vl_api_det44_session_dump_t_handler,
   .endian = vl_api_det44_session_dump_t_endian,
   .format_fn = vl_api_det44_session_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_det44_session_dump_t_tojson,
   .fromjson = vl_api_det44_session_dump_t_fromjson,
   .calc_size = vl_api_det44_session_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DET44_SESSION_DETAILS + msg_id_base,
  .name = "det44_session_details",
  .handler = 0,
  .endian = vl_api_det44_session_details_t_endian,
  .format_fn = vl_api_det44_session_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_det44_session_details_t_tojson,
  .fromjson = vl_api_det44_session_details_t_fromjson,
  .calc_size = vl_api_det44_session_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DET44_SET_TIMEOUTS + msg_id_base,
   .name = "det44_set_timeouts",
   .handler = vl_api_det44_set_timeouts_t_handler,
   .endian = vl_api_det44_set_timeouts_t_endian,
   .format_fn = vl_api_det44_set_timeouts_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_det44_set_timeouts_t_tojson,
   .fromjson = vl_api_det44_set_timeouts_t_fromjson,
   .calc_size = vl_api_det44_set_timeouts_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DET44_SET_TIMEOUTS_REPLY + msg_id_base,
  .name = "det44_set_timeouts_reply",
  .handler = 0,
  .endian = vl_api_det44_set_timeouts_reply_t_endian,
  .format_fn = vl_api_det44_set_timeouts_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_det44_set_timeouts_reply_t_tojson,
  .fromjson = vl_api_det44_set_timeouts_reply_t_fromjson,
  .calc_size = vl_api_det44_set_timeouts_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DET44_GET_TIMEOUTS + msg_id_base,
   .name = "det44_get_timeouts",
   .handler = vl_api_det44_get_timeouts_t_handler,
   .endian = vl_api_det44_get_timeouts_t_endian,
   .format_fn = vl_api_det44_get_timeouts_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_det44_get_timeouts_t_tojson,
   .fromjson = vl_api_det44_get_timeouts_t_fromjson,
   .calc_size = vl_api_det44_get_timeouts_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DET44_GET_TIMEOUTS_REPLY + msg_id_base,
  .name = "det44_get_timeouts_reply",
  .handler = 0,
  .endian = vl_api_det44_get_timeouts_reply_t_endian,
  .format_fn = vl_api_det44_get_timeouts_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_det44_get_timeouts_reply_t_tojson,
  .fromjson = vl_api_det44_get_timeouts_reply_t_fromjson,
  .calc_size = vl_api_det44_get_timeouts_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT_DET_ADD_DEL_MAP + msg_id_base,
   .name = "nat_det_add_del_map",
   .handler = vl_api_nat_det_add_del_map_t_handler,
   .endian = vl_api_nat_det_add_del_map_t_endian,
   .format_fn = vl_api_nat_det_add_del_map_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat_det_add_del_map_t_tojson,
   .fromjson = vl_api_nat_det_add_del_map_t_fromjson,
   .calc_size = vl_api_nat_det_add_del_map_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT_DET_ADD_DEL_MAP_REPLY + msg_id_base,
  .name = "nat_det_add_del_map_reply",
  .handler = 0,
  .endian = vl_api_nat_det_add_del_map_reply_t_endian,
  .format_fn = vl_api_nat_det_add_del_map_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat_det_add_del_map_reply_t_tojson,
  .fromjson = vl_api_nat_det_add_del_map_reply_t_fromjson,
  .calc_size = vl_api_nat_det_add_del_map_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT_DET_FORWARD + msg_id_base,
   .name = "nat_det_forward",
   .handler = vl_api_nat_det_forward_t_handler,
   .endian = vl_api_nat_det_forward_t_endian,
   .format_fn = vl_api_nat_det_forward_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat_det_forward_t_tojson,
   .fromjson = vl_api_nat_det_forward_t_fromjson,
   .calc_size = vl_api_nat_det_forward_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT_DET_FORWARD_REPLY + msg_id_base,
  .name = "nat_det_forward_reply",
  .handler = 0,
  .endian = vl_api_nat_det_forward_reply_t_endian,
  .format_fn = vl_api_nat_det_forward_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat_det_forward_reply_t_tojson,
  .fromjson = vl_api_nat_det_forward_reply_t_fromjson,
  .calc_size = vl_api_nat_det_forward_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT_DET_REVERSE + msg_id_base,
   .name = "nat_det_reverse",
   .handler = vl_api_nat_det_reverse_t_handler,
   .endian = vl_api_nat_det_reverse_t_endian,
   .format_fn = vl_api_nat_det_reverse_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat_det_reverse_t_tojson,
   .fromjson = vl_api_nat_det_reverse_t_fromjson,
   .calc_size = vl_api_nat_det_reverse_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT_DET_REVERSE_REPLY + msg_id_base,
  .name = "nat_det_reverse_reply",
  .handler = 0,
  .endian = vl_api_nat_det_reverse_reply_t_endian,
  .format_fn = vl_api_nat_det_reverse_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat_det_reverse_reply_t_tojson,
  .fromjson = vl_api_nat_det_reverse_reply_t_fromjson,
  .calc_size = vl_api_nat_det_reverse_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT_DET_MAP_DUMP + msg_id_base,
   .name = "nat_det_map_dump",
   .handler = vl_api_nat_det_map_dump_t_handler,
   .endian = vl_api_nat_det_map_dump_t_endian,
   .format_fn = vl_api_nat_det_map_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat_det_map_dump_t_tojson,
   .fromjson = vl_api_nat_det_map_dump_t_fromjson,
   .calc_size = vl_api_nat_det_map_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT_DET_MAP_DETAILS + msg_id_base,
  .name = "nat_det_map_details",
  .handler = 0,
  .endian = vl_api_nat_det_map_details_t_endian,
  .format_fn = vl_api_nat_det_map_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat_det_map_details_t_tojson,
  .fromjson = vl_api_nat_det_map_details_t_fromjson,
  .calc_size = vl_api_nat_det_map_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT_DET_CLOSE_SESSION_OUT + msg_id_base,
   .name = "nat_det_close_session_out",
   .handler = vl_api_nat_det_close_session_out_t_handler,
   .endian = vl_api_nat_det_close_session_out_t_endian,
   .format_fn = vl_api_nat_det_close_session_out_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat_det_close_session_out_t_tojson,
   .fromjson = vl_api_nat_det_close_session_out_t_fromjson,
   .calc_size = vl_api_nat_det_close_session_out_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT_DET_CLOSE_SESSION_OUT_REPLY + msg_id_base,
  .name = "nat_det_close_session_out_reply",
  .handler = 0,
  .endian = vl_api_nat_det_close_session_out_reply_t_endian,
  .format_fn = vl_api_nat_det_close_session_out_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat_det_close_session_out_reply_t_tojson,
  .fromjson = vl_api_nat_det_close_session_out_reply_t_fromjson,
  .calc_size = vl_api_nat_det_close_session_out_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT_DET_CLOSE_SESSION_IN + msg_id_base,
   .name = "nat_det_close_session_in",
   .handler = vl_api_nat_det_close_session_in_t_handler,
   .endian = vl_api_nat_det_close_session_in_t_endian,
   .format_fn = vl_api_nat_det_close_session_in_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat_det_close_session_in_t_tojson,
   .fromjson = vl_api_nat_det_close_session_in_t_fromjson,
   .calc_size = vl_api_nat_det_close_session_in_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT_DET_CLOSE_SESSION_IN_REPLY + msg_id_base,
  .name = "nat_det_close_session_in_reply",
  .handler = 0,
  .endian = vl_api_nat_det_close_session_in_reply_t_endian,
  .format_fn = vl_api_nat_det_close_session_in_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat_det_close_session_in_reply_t_tojson,
  .fromjson = vl_api_nat_det_close_session_in_reply_t_fromjson,
  .calc_size = vl_api_nat_det_close_session_in_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NAT_DET_SESSION_DUMP + msg_id_base,
   .name = "nat_det_session_dump",
   .handler = vl_api_nat_det_session_dump_t_handler,
   .endian = vl_api_nat_det_session_dump_t_endian,
   .format_fn = vl_api_nat_det_session_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nat_det_session_dump_t_tojson,
   .fromjson = vl_api_nat_det_session_dump_t_fromjson,
   .calc_size = vl_api_nat_det_session_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NAT_DET_SESSION_DETAILS + msg_id_base,
  .name = "nat_det_session_details",
  .handler = 0,
  .endian = vl_api_nat_det_session_details_t_endian,
  .format_fn = vl_api_nat_det_session_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nat_det_session_details_t_tojson,
  .fromjson = vl_api_nat_det_session_details_t_fromjson,
  .calc_size = vl_api_nat_det_session_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
