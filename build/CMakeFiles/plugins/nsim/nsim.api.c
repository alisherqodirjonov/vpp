#define vl_endianfun		/* define message structures */
#include "nsim.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "nsim.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "nsim.api.h"
#undef vl_printfun

#include "nsim.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("nsim_0f1cc8e8", VL_MSG_NSIM_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_nsim);
   vl_msg_api_add_msg_name_crc (am, "nsim_cross_connect_enable_disable_9c3ead86",
                                VL_API_NSIM_CROSS_CONNECT_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nsim_cross_connect_enable_disable_reply_e8d4e804",
                                VL_API_NSIM_CROSS_CONNECT_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nsim_output_feature_enable_disable_3865946c",
                                VL_API_NSIM_OUTPUT_FEATURE_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nsim_output_feature_enable_disable_reply_e8d4e804",
                                VL_API_NSIM_OUTPUT_FEATURE_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nsim_configure_16ed400f",
                                VL_API_NSIM_CONFIGURE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nsim_configure_reply_e8d4e804",
                                VL_API_NSIM_CONFIGURE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nsim_configure2_64de8ed3",
                                VL_API_NSIM_CONFIGURE2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "nsim_configure2_reply_e8d4e804",
                                VL_API_NSIM_CONFIGURE2_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NSIM_CROSS_CONNECT_ENABLE_DISABLE + msg_id_base,
   .name = "nsim_cross_connect_enable_disable",
   .handler = vl_api_nsim_cross_connect_enable_disable_t_handler,
   .endian = vl_api_nsim_cross_connect_enable_disable_t_endian,
   .format_fn = vl_api_nsim_cross_connect_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nsim_cross_connect_enable_disable_t_tojson,
   .fromjson = vl_api_nsim_cross_connect_enable_disable_t_fromjson,
   .calc_size = vl_api_nsim_cross_connect_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NSIM_CROSS_CONNECT_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "nsim_cross_connect_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_nsim_cross_connect_enable_disable_reply_t_endian,
  .format_fn = vl_api_nsim_cross_connect_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nsim_cross_connect_enable_disable_reply_t_tojson,
  .fromjson = vl_api_nsim_cross_connect_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_nsim_cross_connect_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NSIM_OUTPUT_FEATURE_ENABLE_DISABLE + msg_id_base,
   .name = "nsim_output_feature_enable_disable",
   .handler = vl_api_nsim_output_feature_enable_disable_t_handler,
   .endian = vl_api_nsim_output_feature_enable_disable_t_endian,
   .format_fn = vl_api_nsim_output_feature_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nsim_output_feature_enable_disable_t_tojson,
   .fromjson = vl_api_nsim_output_feature_enable_disable_t_fromjson,
   .calc_size = vl_api_nsim_output_feature_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NSIM_OUTPUT_FEATURE_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "nsim_output_feature_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_nsim_output_feature_enable_disable_reply_t_endian,
  .format_fn = vl_api_nsim_output_feature_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nsim_output_feature_enable_disable_reply_t_tojson,
  .fromjson = vl_api_nsim_output_feature_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_nsim_output_feature_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NSIM_CONFIGURE + msg_id_base,
   .name = "nsim_configure",
   .handler = vl_api_nsim_configure_t_handler,
   .endian = vl_api_nsim_configure_t_endian,
   .format_fn = vl_api_nsim_configure_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nsim_configure_t_tojson,
   .fromjson = vl_api_nsim_configure_t_fromjson,
   .calc_size = vl_api_nsim_configure_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NSIM_CONFIGURE_REPLY + msg_id_base,
  .name = "nsim_configure_reply",
  .handler = 0,
  .endian = vl_api_nsim_configure_reply_t_endian,
  .format_fn = vl_api_nsim_configure_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nsim_configure_reply_t_tojson,
  .fromjson = vl_api_nsim_configure_reply_t_fromjson,
  .calc_size = vl_api_nsim_configure_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_NSIM_CONFIGURE2 + msg_id_base,
   .name = "nsim_configure2",
   .handler = vl_api_nsim_configure2_t_handler,
   .endian = vl_api_nsim_configure2_t_endian,
   .format_fn = vl_api_nsim_configure2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_nsim_configure2_t_tojson,
   .fromjson = vl_api_nsim_configure2_t_fromjson,
   .calc_size = vl_api_nsim_configure2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_NSIM_CONFIGURE2_REPLY + msg_id_base,
  .name = "nsim_configure2_reply",
  .handler = 0,
  .endian = vl_api_nsim_configure2_reply_t_endian,
  .format_fn = vl_api_nsim_configure2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_nsim_configure2_reply_t_tojson,
  .fromjson = vl_api_nsim_configure2_reply_t_fromjson,
  .calc_size = vl_api_nsim_configure2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
