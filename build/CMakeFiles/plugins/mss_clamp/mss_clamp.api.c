#define vl_endianfun		/* define message structures */
#include "mss_clamp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "mss_clamp.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "mss_clamp.api.h"
#undef vl_printfun

#include "mss_clamp.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("mss_clamp_74a0c674", VL_MSG_MSS_CLAMP_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_mss_clamp);
   vl_msg_api_add_msg_name_crc (am, "mss_clamp_enable_disable_d31b44e3",
                                VL_API_MSS_CLAMP_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mss_clamp_enable_disable_reply_e8d4e804",
                                VL_API_MSS_CLAMP_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mss_clamp_get_47250981",
                                VL_API_MSS_CLAMP_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mss_clamp_get_reply_53b48f5d",
                                VL_API_MSS_CLAMP_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mss_clamp_details_d3a4de61",
                                VL_API_MSS_CLAMP_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MSS_CLAMP_GET + msg_id_base,
   .name = "mss_clamp_get",
   .handler = vl_api_mss_clamp_get_t_handler,
   .endian = vl_api_mss_clamp_get_t_endian,
   .format_fn = vl_api_mss_clamp_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_mss_clamp_get_t_tojson,
   .fromjson = vl_api_mss_clamp_get_t_fromjson,
   .calc_size = vl_api_mss_clamp_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MSS_CLAMP_GET_REPLY + msg_id_base,
  .name = "mss_clamp_get_reply",
  .handler = 0,
  .endian = vl_api_mss_clamp_get_reply_t_endian,
  .format_fn = vl_api_mss_clamp_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_mss_clamp_get_reply_t_tojson,
  .fromjson = vl_api_mss_clamp_get_reply_t_fromjson,
  .calc_size = vl_api_mss_clamp_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MSS_CLAMP_DETAILS + msg_id_base,
  .name = "mss_clamp_details",
  .handler = 0,
  .endian = vl_api_mss_clamp_details_t_endian,
  .format_fn = vl_api_mss_clamp_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_mss_clamp_details_t_tojson,
  .fromjson = vl_api_mss_clamp_details_t_fromjson,
  .calc_size = vl_api_mss_clamp_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MSS_CLAMP_ENABLE_DISABLE + msg_id_base,
   .name = "mss_clamp_enable_disable",
   .handler = vl_api_mss_clamp_enable_disable_t_handler,
   .endian = vl_api_mss_clamp_enable_disable_t_endian,
   .format_fn = vl_api_mss_clamp_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_mss_clamp_enable_disable_t_tojson,
   .fromjson = vl_api_mss_clamp_enable_disable_t_fromjson,
   .calc_size = vl_api_mss_clamp_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MSS_CLAMP_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "mss_clamp_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_mss_clamp_enable_disable_reply_t_endian,
  .format_fn = vl_api_mss_clamp_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_mss_clamp_enable_disable_reply_t_tojson,
  .fromjson = vl_api_mss_clamp_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_mss_clamp_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
vlib_error_desc_t mss_clamp_error_counters[] = {
  {
   .name = "clamped",
   .desc = "packets clamped",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
};
