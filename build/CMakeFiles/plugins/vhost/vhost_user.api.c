#define vl_endianfun		/* define message structures */
#include "vhost_user.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "vhost_user.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "vhost_user.api.h"
#undef vl_printfun

#include "vhost_user.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("vhost_user_30000028", VL_MSG_VHOST_USER_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_vhost_user);
   vl_msg_api_add_msg_name_crc (am, "create_vhost_user_if_c785c6fc",
                                VL_API_CREATE_VHOST_USER_IF + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "create_vhost_user_if_reply_5383d31f",
                                VL_API_CREATE_VHOST_USER_IF_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "modify_vhost_user_if_0e71d40b",
                                VL_API_MODIFY_VHOST_USER_IF + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "modify_vhost_user_if_reply_e8d4e804",
                                VL_API_MODIFY_VHOST_USER_IF_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "create_vhost_user_if_v2_dba1cc1d",
                                VL_API_CREATE_VHOST_USER_IF_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "create_vhost_user_if_v2_reply_5383d31f",
                                VL_API_CREATE_VHOST_USER_IF_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "modify_vhost_user_if_v2_b2483771",
                                VL_API_MODIFY_VHOST_USER_IF_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "modify_vhost_user_if_v2_reply_e8d4e804",
                                VL_API_MODIFY_VHOST_USER_IF_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "delete_vhost_user_if_f9e6675e",
                                VL_API_DELETE_VHOST_USER_IF + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "delete_vhost_user_if_reply_e8d4e804",
                                VL_API_DELETE_VHOST_USER_IF_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_vhost_user_details_0cee1e53",
                                VL_API_SW_INTERFACE_VHOST_USER_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_vhost_user_dump_f9e6675e",
                                VL_API_SW_INTERFACE_VHOST_USER_DUMP + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CREATE_VHOST_USER_IF + msg_id_base,
   .name = "create_vhost_user_if",
   .handler = vl_api_create_vhost_user_if_t_handler,
   .endian = vl_api_create_vhost_user_if_t_endian,
   .format_fn = vl_api_create_vhost_user_if_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_create_vhost_user_if_t_tojson,
   .fromjson = vl_api_create_vhost_user_if_t_fromjson,
   .calc_size = vl_api_create_vhost_user_if_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CREATE_VHOST_USER_IF_REPLY + msg_id_base,
  .name = "create_vhost_user_if_reply",
  .handler = 0,
  .endian = vl_api_create_vhost_user_if_reply_t_endian,
  .format_fn = vl_api_create_vhost_user_if_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_create_vhost_user_if_reply_t_tojson,
  .fromjson = vl_api_create_vhost_user_if_reply_t_fromjson,
  .calc_size = vl_api_create_vhost_user_if_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MODIFY_VHOST_USER_IF + msg_id_base,
   .name = "modify_vhost_user_if",
   .handler = vl_api_modify_vhost_user_if_t_handler,
   .endian = vl_api_modify_vhost_user_if_t_endian,
   .format_fn = vl_api_modify_vhost_user_if_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_modify_vhost_user_if_t_tojson,
   .fromjson = vl_api_modify_vhost_user_if_t_fromjson,
   .calc_size = vl_api_modify_vhost_user_if_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MODIFY_VHOST_USER_IF_REPLY + msg_id_base,
  .name = "modify_vhost_user_if_reply",
  .handler = 0,
  .endian = vl_api_modify_vhost_user_if_reply_t_endian,
  .format_fn = vl_api_modify_vhost_user_if_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_modify_vhost_user_if_reply_t_tojson,
  .fromjson = vl_api_modify_vhost_user_if_reply_t_fromjson,
  .calc_size = vl_api_modify_vhost_user_if_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CREATE_VHOST_USER_IF_V2 + msg_id_base,
   .name = "create_vhost_user_if_v2",
   .handler = vl_api_create_vhost_user_if_v2_t_handler,
   .endian = vl_api_create_vhost_user_if_v2_t_endian,
   .format_fn = vl_api_create_vhost_user_if_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_create_vhost_user_if_v2_t_tojson,
   .fromjson = vl_api_create_vhost_user_if_v2_t_fromjson,
   .calc_size = vl_api_create_vhost_user_if_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CREATE_VHOST_USER_IF_V2_REPLY + msg_id_base,
  .name = "create_vhost_user_if_v2_reply",
  .handler = 0,
  .endian = vl_api_create_vhost_user_if_v2_reply_t_endian,
  .format_fn = vl_api_create_vhost_user_if_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_create_vhost_user_if_v2_reply_t_tojson,
  .fromjson = vl_api_create_vhost_user_if_v2_reply_t_fromjson,
  .calc_size = vl_api_create_vhost_user_if_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MODIFY_VHOST_USER_IF_V2 + msg_id_base,
   .name = "modify_vhost_user_if_v2",
   .handler = vl_api_modify_vhost_user_if_v2_t_handler,
   .endian = vl_api_modify_vhost_user_if_v2_t_endian,
   .format_fn = vl_api_modify_vhost_user_if_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_modify_vhost_user_if_v2_t_tojson,
   .fromjson = vl_api_modify_vhost_user_if_v2_t_fromjson,
   .calc_size = vl_api_modify_vhost_user_if_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MODIFY_VHOST_USER_IF_V2_REPLY + msg_id_base,
  .name = "modify_vhost_user_if_v2_reply",
  .handler = 0,
  .endian = vl_api_modify_vhost_user_if_v2_reply_t_endian,
  .format_fn = vl_api_modify_vhost_user_if_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_modify_vhost_user_if_v2_reply_t_tojson,
  .fromjson = vl_api_modify_vhost_user_if_v2_reply_t_fromjson,
  .calc_size = vl_api_modify_vhost_user_if_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DELETE_VHOST_USER_IF + msg_id_base,
   .name = "delete_vhost_user_if",
   .handler = vl_api_delete_vhost_user_if_t_handler,
   .endian = vl_api_delete_vhost_user_if_t_endian,
   .format_fn = vl_api_delete_vhost_user_if_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_delete_vhost_user_if_t_tojson,
   .fromjson = vl_api_delete_vhost_user_if_t_fromjson,
   .calc_size = vl_api_delete_vhost_user_if_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DELETE_VHOST_USER_IF_REPLY + msg_id_base,
  .name = "delete_vhost_user_if_reply",
  .handler = 0,
  .endian = vl_api_delete_vhost_user_if_reply_t_endian,
  .format_fn = vl_api_delete_vhost_user_if_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_delete_vhost_user_if_reply_t_tojson,
  .fromjson = vl_api_delete_vhost_user_if_reply_t_fromjson,
  .calc_size = vl_api_delete_vhost_user_if_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_VHOST_USER_DUMP + msg_id_base,
   .name = "sw_interface_vhost_user_dump",
   .handler = vl_api_sw_interface_vhost_user_dump_t_handler,
   .endian = vl_api_sw_interface_vhost_user_dump_t_endian,
   .format_fn = vl_api_sw_interface_vhost_user_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_vhost_user_dump_t_tojson,
   .fromjson = vl_api_sw_interface_vhost_user_dump_t_fromjson,
   .calc_size = vl_api_sw_interface_vhost_user_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_VHOST_USER_DETAILS + msg_id_base,
  .name = "sw_interface_vhost_user_details",
  .handler = 0,
  .endian = vl_api_sw_interface_vhost_user_details_t_endian,
  .format_fn = vl_api_sw_interface_vhost_user_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_vhost_user_details_t_tojson,
  .fromjson = vl_api_sw_interface_vhost_user_details_t_fromjson,
  .calc_size = vl_api_sw_interface_vhost_user_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
