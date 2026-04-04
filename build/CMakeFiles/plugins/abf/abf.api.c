#define vl_endianfun		/* define message structures */
#include "abf.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "abf.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "abf.api.h"
#undef vl_printfun

#include "abf.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("abf_70fd229c", VL_MSG_ABF_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_abf);
   vl_msg_api_add_msg_name_crc (am, "abf_plugin_get_version_51077d14",
                                VL_API_ABF_PLUGIN_GET_VERSION + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "abf_plugin_get_version_reply_9b32cf86",
                                VL_API_ABF_PLUGIN_GET_VERSION_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "abf_policy_add_del_c6131197",
                                VL_API_ABF_POLICY_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "abf_policy_add_del_reply_e8d4e804",
                                VL_API_ABF_POLICY_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "abf_policy_details_b7487fa4",
                                VL_API_ABF_POLICY_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "abf_policy_dump_51077d14",
                                VL_API_ABF_POLICY_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "abf_itf_attach_add_del_25c8621b",
                                VL_API_ABF_ITF_ATTACH_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "abf_itf_attach_add_del_reply_e8d4e804",
                                VL_API_ABF_ITF_ATTACH_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "abf_itf_attach_details_7819523e",
                                VL_API_ABF_ITF_ATTACH_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "abf_itf_attach_dump_51077d14",
                                VL_API_ABF_ITF_ATTACH_DUMP + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ABF_PLUGIN_GET_VERSION + msg_id_base,
   .name = "abf_plugin_get_version",
   .handler = vl_api_abf_plugin_get_version_t_handler,
   .endian = vl_api_abf_plugin_get_version_t_endian,
   .format_fn = vl_api_abf_plugin_get_version_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_abf_plugin_get_version_t_tojson,
   .fromjson = vl_api_abf_plugin_get_version_t_fromjson,
   .calc_size = vl_api_abf_plugin_get_version_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ABF_PLUGIN_GET_VERSION_REPLY + msg_id_base,
  .name = "abf_plugin_get_version_reply",
  .handler = 0,
  .endian = vl_api_abf_plugin_get_version_reply_t_endian,
  .format_fn = vl_api_abf_plugin_get_version_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_abf_plugin_get_version_reply_t_tojson,
  .fromjson = vl_api_abf_plugin_get_version_reply_t_fromjson,
  .calc_size = vl_api_abf_plugin_get_version_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ABF_POLICY_ADD_DEL + msg_id_base,
   .name = "abf_policy_add_del",
   .handler = vl_api_abf_policy_add_del_t_handler,
   .endian = vl_api_abf_policy_add_del_t_endian,
   .format_fn = vl_api_abf_policy_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_abf_policy_add_del_t_tojson,
   .fromjson = vl_api_abf_policy_add_del_t_fromjson,
   .calc_size = vl_api_abf_policy_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ABF_POLICY_ADD_DEL_REPLY + msg_id_base,
  .name = "abf_policy_add_del_reply",
  .handler = 0,
  .endian = vl_api_abf_policy_add_del_reply_t_endian,
  .format_fn = vl_api_abf_policy_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_abf_policy_add_del_reply_t_tojson,
  .fromjson = vl_api_abf_policy_add_del_reply_t_fromjson,
  .calc_size = vl_api_abf_policy_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ABF_POLICY_DUMP + msg_id_base,
   .name = "abf_policy_dump",
   .handler = vl_api_abf_policy_dump_t_handler,
   .endian = vl_api_abf_policy_dump_t_endian,
   .format_fn = vl_api_abf_policy_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_abf_policy_dump_t_tojson,
   .fromjson = vl_api_abf_policy_dump_t_fromjson,
   .calc_size = vl_api_abf_policy_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ABF_POLICY_DETAILS + msg_id_base,
  .name = "abf_policy_details",
  .handler = 0,
  .endian = vl_api_abf_policy_details_t_endian,
  .format_fn = vl_api_abf_policy_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_abf_policy_details_t_tojson,
  .fromjson = vl_api_abf_policy_details_t_fromjson,
  .calc_size = vl_api_abf_policy_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ABF_ITF_ATTACH_ADD_DEL + msg_id_base,
   .name = "abf_itf_attach_add_del",
   .handler = vl_api_abf_itf_attach_add_del_t_handler,
   .endian = vl_api_abf_itf_attach_add_del_t_endian,
   .format_fn = vl_api_abf_itf_attach_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_abf_itf_attach_add_del_t_tojson,
   .fromjson = vl_api_abf_itf_attach_add_del_t_fromjson,
   .calc_size = vl_api_abf_itf_attach_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ABF_ITF_ATTACH_ADD_DEL_REPLY + msg_id_base,
  .name = "abf_itf_attach_add_del_reply",
  .handler = 0,
  .endian = vl_api_abf_itf_attach_add_del_reply_t_endian,
  .format_fn = vl_api_abf_itf_attach_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_abf_itf_attach_add_del_reply_t_tojson,
  .fromjson = vl_api_abf_itf_attach_add_del_reply_t_fromjson,
  .calc_size = vl_api_abf_itf_attach_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ABF_ITF_ATTACH_DUMP + msg_id_base,
   .name = "abf_itf_attach_dump",
   .handler = vl_api_abf_itf_attach_dump_t_handler,
   .endian = vl_api_abf_itf_attach_dump_t_endian,
   .format_fn = vl_api_abf_itf_attach_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_abf_itf_attach_dump_t_tojson,
   .fromjson = vl_api_abf_itf_attach_dump_t_fromjson,
   .calc_size = vl_api_abf_itf_attach_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ABF_ITF_ATTACH_DETAILS + msg_id_base,
  .name = "abf_itf_attach_details",
  .handler = 0,
  .endian = vl_api_abf_itf_attach_details_t_endian,
  .format_fn = vl_api_abf_itf_attach_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_abf_itf_attach_details_t_tojson,
  .fromjson = vl_api_abf_itf_attach_details_t_fromjson,
  .calc_size = vl_api_abf_itf_attach_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
