#define vl_endianfun		/* define message structures */
#include "flow.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "flow.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "flow.api.h"
#undef vl_printfun

#include "flow.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("flow_5ab59c04", VL_MSG_FLOW_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_flow);
   vl_msg_api_add_msg_name_crc (am, "flow_add_f946ed84",
                                VL_API_FLOW_ADD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flow_add_v2_5b757558",
                                VL_API_FLOW_ADD_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flow_add_reply_8587dc85",
                                VL_API_FLOW_ADD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flow_add_v2_reply_8587dc85",
                                VL_API_FLOW_ADD_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flow_del_b6b9b02c",
                                VL_API_FLOW_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flow_del_reply_e8d4e804",
                                VL_API_FLOW_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flow_enable_2024be69",
                                VL_API_FLOW_ENABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flow_enable_reply_e8d4e804",
                                VL_API_FLOW_ENABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flow_disable_2024be69",
                                VL_API_FLOW_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "flow_disable_reply_e8d4e804",
                                VL_API_FLOW_DISABLE_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_FLOW_ADD + msg_id_base,
   .name = "flow_add",
   .handler = vl_api_flow_add_t_handler,
   .endian = vl_api_flow_add_t_endian,
   .format_fn = vl_api_flow_add_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_flow_add_t_tojson,
   .fromjson = vl_api_flow_add_t_fromjson,
   .calc_size = vl_api_flow_add_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_FLOW_ADD_REPLY + msg_id_base,
  .name = "flow_add_reply",
  .handler = 0,
  .endian = vl_api_flow_add_reply_t_endian,
  .format_fn = vl_api_flow_add_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_flow_add_reply_t_tojson,
  .fromjson = vl_api_flow_add_reply_t_fromjson,
  .calc_size = vl_api_flow_add_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_FLOW_ADD_V2 + msg_id_base,
   .name = "flow_add_v2",
   .handler = vl_api_flow_add_v2_t_handler,
   .endian = vl_api_flow_add_v2_t_endian,
   .format_fn = vl_api_flow_add_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_flow_add_v2_t_tojson,
   .fromjson = vl_api_flow_add_v2_t_fromjson,
   .calc_size = vl_api_flow_add_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_FLOW_ADD_V2_REPLY + msg_id_base,
  .name = "flow_add_v2_reply",
  .handler = 0,
  .endian = vl_api_flow_add_v2_reply_t_endian,
  .format_fn = vl_api_flow_add_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_flow_add_v2_reply_t_tojson,
  .fromjson = vl_api_flow_add_v2_reply_t_fromjson,
  .calc_size = vl_api_flow_add_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_FLOW_DEL + msg_id_base,
   .name = "flow_del",
   .handler = vl_api_flow_del_t_handler,
   .endian = vl_api_flow_del_t_endian,
   .format_fn = vl_api_flow_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_flow_del_t_tojson,
   .fromjson = vl_api_flow_del_t_fromjson,
   .calc_size = vl_api_flow_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_FLOW_DEL_REPLY + msg_id_base,
  .name = "flow_del_reply",
  .handler = 0,
  .endian = vl_api_flow_del_reply_t_endian,
  .format_fn = vl_api_flow_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_flow_del_reply_t_tojson,
  .fromjson = vl_api_flow_del_reply_t_fromjson,
  .calc_size = vl_api_flow_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_FLOW_ENABLE + msg_id_base,
   .name = "flow_enable",
   .handler = vl_api_flow_enable_t_handler,
   .endian = vl_api_flow_enable_t_endian,
   .format_fn = vl_api_flow_enable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_flow_enable_t_tojson,
   .fromjson = vl_api_flow_enable_t_fromjson,
   .calc_size = vl_api_flow_enable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_FLOW_ENABLE_REPLY + msg_id_base,
  .name = "flow_enable_reply",
  .handler = 0,
  .endian = vl_api_flow_enable_reply_t_endian,
  .format_fn = vl_api_flow_enable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_flow_enable_reply_t_tojson,
  .fromjson = vl_api_flow_enable_reply_t_fromjson,
  .calc_size = vl_api_flow_enable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_FLOW_DISABLE + msg_id_base,
   .name = "flow_disable",
   .handler = vl_api_flow_disable_t_handler,
   .endian = vl_api_flow_disable_t_endian,
   .format_fn = vl_api_flow_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_flow_disable_t_tojson,
   .fromjson = vl_api_flow_disable_t_fromjson,
   .calc_size = vl_api_flow_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_FLOW_DISABLE_REPLY + msg_id_base,
  .name = "flow_disable_reply",
  .handler = 0,
  .endian = vl_api_flow_disable_reply_t_endian,
  .format_fn = vl_api_flow_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_flow_disable_reply_t_tojson,
  .fromjson = vl_api_flow_disable_reply_t_fromjson,
  .calc_size = vl_api_flow_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
