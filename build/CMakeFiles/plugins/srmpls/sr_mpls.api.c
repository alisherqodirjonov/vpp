#define vl_endianfun		/* define message structures */
#include "sr_mpls.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "sr_mpls.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "sr_mpls.api.h"
#undef vl_printfun

#include "sr_mpls.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("sr_mpls_d1279a74", VL_MSG_SR_MPLS_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_sr_mpls);
   vl_msg_api_add_msg_name_crc (am, "sr_mpls_policy_add_a1a70c70",
                                VL_API_SR_MPLS_POLICY_ADD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_mpls_policy_add_reply_e8d4e804",
                                VL_API_SR_MPLS_POLICY_ADD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_mpls_policy_mod_88482c17",
                                VL_API_SR_MPLS_POLICY_MOD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_mpls_policy_mod_reply_e8d4e804",
                                VL_API_SR_MPLS_POLICY_MOD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_mpls_policy_del_e29d34fa",
                                VL_API_SR_MPLS_POLICY_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_mpls_policy_del_reply_e8d4e804",
                                VL_API_SR_MPLS_POLICY_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_mpls_steering_add_del_64acff63",
                                VL_API_SR_MPLS_STEERING_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_mpls_steering_add_del_reply_e8d4e804",
                                VL_API_SR_MPLS_STEERING_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_mpls_policy_assign_endpoint_color_0e7eb978",
                                VL_API_SR_MPLS_POLICY_ASSIGN_ENDPOINT_COLOR + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_mpls_policy_assign_endpoint_color_reply_e8d4e804",
                                VL_API_SR_MPLS_POLICY_ASSIGN_ENDPOINT_COLOR_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_MPLS_POLICY_ADD + msg_id_base,
   .name = "sr_mpls_policy_add",
   .handler = vl_api_sr_mpls_policy_add_t_handler,
   .endian = vl_api_sr_mpls_policy_add_t_endian,
   .format_fn = vl_api_sr_mpls_policy_add_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_mpls_policy_add_t_tojson,
   .fromjson = vl_api_sr_mpls_policy_add_t_fromjson,
   .calc_size = vl_api_sr_mpls_policy_add_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_MPLS_POLICY_ADD_REPLY + msg_id_base,
  .name = "sr_mpls_policy_add_reply",
  .handler = 0,
  .endian = vl_api_sr_mpls_policy_add_reply_t_endian,
  .format_fn = vl_api_sr_mpls_policy_add_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_mpls_policy_add_reply_t_tojson,
  .fromjson = vl_api_sr_mpls_policy_add_reply_t_fromjson,
  .calc_size = vl_api_sr_mpls_policy_add_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_MPLS_POLICY_MOD + msg_id_base,
   .name = "sr_mpls_policy_mod",
   .handler = vl_api_sr_mpls_policy_mod_t_handler,
   .endian = vl_api_sr_mpls_policy_mod_t_endian,
   .format_fn = vl_api_sr_mpls_policy_mod_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_mpls_policy_mod_t_tojson,
   .fromjson = vl_api_sr_mpls_policy_mod_t_fromjson,
   .calc_size = vl_api_sr_mpls_policy_mod_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_MPLS_POLICY_MOD_REPLY + msg_id_base,
  .name = "sr_mpls_policy_mod_reply",
  .handler = 0,
  .endian = vl_api_sr_mpls_policy_mod_reply_t_endian,
  .format_fn = vl_api_sr_mpls_policy_mod_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_mpls_policy_mod_reply_t_tojson,
  .fromjson = vl_api_sr_mpls_policy_mod_reply_t_fromjson,
  .calc_size = vl_api_sr_mpls_policy_mod_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_MPLS_POLICY_DEL + msg_id_base,
   .name = "sr_mpls_policy_del",
   .handler = vl_api_sr_mpls_policy_del_t_handler,
   .endian = vl_api_sr_mpls_policy_del_t_endian,
   .format_fn = vl_api_sr_mpls_policy_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_mpls_policy_del_t_tojson,
   .fromjson = vl_api_sr_mpls_policy_del_t_fromjson,
   .calc_size = vl_api_sr_mpls_policy_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_MPLS_POLICY_DEL_REPLY + msg_id_base,
  .name = "sr_mpls_policy_del_reply",
  .handler = 0,
  .endian = vl_api_sr_mpls_policy_del_reply_t_endian,
  .format_fn = vl_api_sr_mpls_policy_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_mpls_policy_del_reply_t_tojson,
  .fromjson = vl_api_sr_mpls_policy_del_reply_t_fromjson,
  .calc_size = vl_api_sr_mpls_policy_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_MPLS_STEERING_ADD_DEL + msg_id_base,
   .name = "sr_mpls_steering_add_del",
   .handler = vl_api_sr_mpls_steering_add_del_t_handler,
   .endian = vl_api_sr_mpls_steering_add_del_t_endian,
   .format_fn = vl_api_sr_mpls_steering_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_mpls_steering_add_del_t_tojson,
   .fromjson = vl_api_sr_mpls_steering_add_del_t_fromjson,
   .calc_size = vl_api_sr_mpls_steering_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_MPLS_STEERING_ADD_DEL_REPLY + msg_id_base,
  .name = "sr_mpls_steering_add_del_reply",
  .handler = 0,
  .endian = vl_api_sr_mpls_steering_add_del_reply_t_endian,
  .format_fn = vl_api_sr_mpls_steering_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_mpls_steering_add_del_reply_t_tojson,
  .fromjson = vl_api_sr_mpls_steering_add_del_reply_t_fromjson,
  .calc_size = vl_api_sr_mpls_steering_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_MPLS_POLICY_ASSIGN_ENDPOINT_COLOR + msg_id_base,
   .name = "sr_mpls_policy_assign_endpoint_color",
   .handler = vl_api_sr_mpls_policy_assign_endpoint_color_t_handler,
   .endian = vl_api_sr_mpls_policy_assign_endpoint_color_t_endian,
   .format_fn = vl_api_sr_mpls_policy_assign_endpoint_color_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_mpls_policy_assign_endpoint_color_t_tojson,
   .fromjson = vl_api_sr_mpls_policy_assign_endpoint_color_t_fromjson,
   .calc_size = vl_api_sr_mpls_policy_assign_endpoint_color_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_MPLS_POLICY_ASSIGN_ENDPOINT_COLOR_REPLY + msg_id_base,
  .name = "sr_mpls_policy_assign_endpoint_color_reply",
  .handler = 0,
  .endian = vl_api_sr_mpls_policy_assign_endpoint_color_reply_t_endian,
  .format_fn = vl_api_sr_mpls_policy_assign_endpoint_color_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_mpls_policy_assign_endpoint_color_reply_t_tojson,
  .fromjson = vl_api_sr_mpls_policy_assign_endpoint_color_reply_t_fromjson,
  .calc_size = vl_api_sr_mpls_policy_assign_endpoint_color_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
