#define vl_endianfun		/* define message structures */
#include "trace.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "trace.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "trace.api.h"
#undef vl_printfun

#include "trace.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("trace_397cbf90", VL_MSG_TRACE_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_trace);
   vl_msg_api_add_msg_name_crc (am, "trace_profile_add_de08aa6d",
                                VL_API_TRACE_PROFILE_ADD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_profile_add_reply_e8d4e804",
                                VL_API_TRACE_PROFILE_ADD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_profile_del_51077d14",
                                VL_API_TRACE_PROFILE_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_profile_del_reply_e8d4e804",
                                VL_API_TRACE_PROFILE_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_profile_show_config_51077d14",
                                VL_API_TRACE_PROFILE_SHOW_CONFIG + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_profile_show_config_reply_0f1d374c",
                                VL_API_TRACE_PROFILE_SHOW_CONFIG_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TRACE_PROFILE_ADD + msg_id_base,
   .name = "trace_profile_add",
   .handler = vl_api_trace_profile_add_t_handler,
   .endian = vl_api_trace_profile_add_t_endian,
   .format_fn = vl_api_trace_profile_add_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_trace_profile_add_t_tojson,
   .fromjson = vl_api_trace_profile_add_t_fromjson,
   .calc_size = vl_api_trace_profile_add_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TRACE_PROFILE_ADD_REPLY + msg_id_base,
  .name = "trace_profile_add_reply",
  .handler = 0,
  .endian = vl_api_trace_profile_add_reply_t_endian,
  .format_fn = vl_api_trace_profile_add_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_trace_profile_add_reply_t_tojson,
  .fromjson = vl_api_trace_profile_add_reply_t_fromjson,
  .calc_size = vl_api_trace_profile_add_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TRACE_PROFILE_DEL + msg_id_base,
   .name = "trace_profile_del",
   .handler = vl_api_trace_profile_del_t_handler,
   .endian = vl_api_trace_profile_del_t_endian,
   .format_fn = vl_api_trace_profile_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_trace_profile_del_t_tojson,
   .fromjson = vl_api_trace_profile_del_t_fromjson,
   .calc_size = vl_api_trace_profile_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TRACE_PROFILE_DEL_REPLY + msg_id_base,
  .name = "trace_profile_del_reply",
  .handler = 0,
  .endian = vl_api_trace_profile_del_reply_t_endian,
  .format_fn = vl_api_trace_profile_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_trace_profile_del_reply_t_tojson,
  .fromjson = vl_api_trace_profile_del_reply_t_fromjson,
  .calc_size = vl_api_trace_profile_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TRACE_PROFILE_SHOW_CONFIG + msg_id_base,
   .name = "trace_profile_show_config",
   .handler = vl_api_trace_profile_show_config_t_handler,
   .endian = vl_api_trace_profile_show_config_t_endian,
   .format_fn = vl_api_trace_profile_show_config_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_trace_profile_show_config_t_tojson,
   .fromjson = vl_api_trace_profile_show_config_t_fromjson,
   .calc_size = vl_api_trace_profile_show_config_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TRACE_PROFILE_SHOW_CONFIG_REPLY + msg_id_base,
  .name = "trace_profile_show_config_reply",
  .handler = 0,
  .endian = vl_api_trace_profile_show_config_reply_t_endian,
  .format_fn = vl_api_trace_profile_show_config_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_trace_profile_show_config_reply_t_tojson,
  .fromjson = vl_api_trace_profile_show_config_reply_t_fromjson,
  .calc_size = vl_api_trace_profile_show_config_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
