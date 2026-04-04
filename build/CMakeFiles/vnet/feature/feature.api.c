#define vl_endianfun		/* define message structures */
#include "feature.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "feature.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "feature.api.h"
#undef vl_printfun

#include "feature.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("feature_ea1b6429", VL_MSG_FEATURE_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_feature);
   vl_msg_api_add_msg_name_crc (am, "feature_enable_disable_7531c862",
                                VL_API_FEATURE_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "feature_enable_disable_reply_e8d4e804",
                                VL_API_FEATURE_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "feature_is_enabled_55db09e2",
                                VL_API_FEATURE_IS_ENABLED + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "feature_is_enabled_reply_03f284b5",
                                VL_API_FEATURE_IS_ENABLED_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_FEATURE_ENABLE_DISABLE + msg_id_base,
   .name = "feature_enable_disable",
   .handler = vl_api_feature_enable_disable_t_handler,
   .endian = vl_api_feature_enable_disable_t_endian,
   .format_fn = vl_api_feature_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_feature_enable_disable_t_tojson,
   .fromjson = vl_api_feature_enable_disable_t_fromjson,
   .calc_size = vl_api_feature_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_FEATURE_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "feature_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_feature_enable_disable_reply_t_endian,
  .format_fn = vl_api_feature_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_feature_enable_disable_reply_t_tojson,
  .fromjson = vl_api_feature_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_feature_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_FEATURE_IS_ENABLED + msg_id_base,
   .name = "feature_is_enabled",
   .handler = vl_api_feature_is_enabled_t_handler,
   .endian = vl_api_feature_is_enabled_t_endian,
   .format_fn = vl_api_feature_is_enabled_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_feature_is_enabled_t_tojson,
   .fromjson = vl_api_feature_is_enabled_t_fromjson,
   .calc_size = vl_api_feature_is_enabled_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_FEATURE_IS_ENABLED_REPLY + msg_id_base,
  .name = "feature_is_enabled_reply",
  .handler = 0,
  .endian = vl_api_feature_is_enabled_reply_t_endian,
  .format_fn = vl_api_feature_is_enabled_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_feature_is_enabled_reply_t_tojson,
  .fromjson = vl_api_feature_is_enabled_reply_t_fromjson,
  .calc_size = vl_api_feature_is_enabled_reply_t_calc_size,
  .is_autoendian = 1};
   vl_msg_api_config (&c);
   return msg_id_base;
}
