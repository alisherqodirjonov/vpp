#define vl_endianfun		/* define message structures */
#include "vpe.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "vpe.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "vpe.api.h"
#undef vl_printfun

#include "vpe.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("vpe_33b45969", VL_MSG_VPE_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_vpe);
   vl_msg_api_add_msg_name_crc (am, "show_version_51077d14",
                                VL_API_SHOW_VERSION + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_version_reply_c919bde1",
                                VL_API_SHOW_VERSION_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_vpe_system_time_51077d14",
                                VL_API_SHOW_VPE_SYSTEM_TIME + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_vpe_system_time_reply_7ffd8193",
                                VL_API_SHOW_VPE_SYSTEM_TIME_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "log_dump_6ab31753",
                                VL_API_LOG_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "log_details_03d61cc0",
                                VL_API_LOG_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SHOW_VERSION + msg_id_base,
   .name = "show_version",
   .handler = vl_api_show_version_t_handler,
   .endian = vl_api_show_version_t_endian,
   .format_fn = vl_api_show_version_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_show_version_t_tojson,
   .fromjson = vl_api_show_version_t_fromjson,
   .calc_size = vl_api_show_version_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SHOW_VERSION_REPLY + msg_id_base,
  .name = "show_version_reply",
  .handler = 0,
  .endian = vl_api_show_version_reply_t_endian,
  .format_fn = vl_api_show_version_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_show_version_reply_t_tojson,
  .fromjson = vl_api_show_version_reply_t_fromjson,
  .calc_size = vl_api_show_version_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SHOW_VPE_SYSTEM_TIME + msg_id_base,
   .name = "show_vpe_system_time",
   .handler = vl_api_show_vpe_system_time_t_handler,
   .endian = vl_api_show_vpe_system_time_t_endian,
   .format_fn = vl_api_show_vpe_system_time_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_show_vpe_system_time_t_tojson,
   .fromjson = vl_api_show_vpe_system_time_t_fromjson,
   .calc_size = vl_api_show_vpe_system_time_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SHOW_VPE_SYSTEM_TIME_REPLY + msg_id_base,
  .name = "show_vpe_system_time_reply",
  .handler = 0,
  .endian = vl_api_show_vpe_system_time_reply_t_endian,
  .format_fn = vl_api_show_vpe_system_time_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_show_vpe_system_time_reply_t_tojson,
  .fromjson = vl_api_show_vpe_system_time_reply_t_fromjson,
  .calc_size = vl_api_show_vpe_system_time_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_LOG_DUMP + msg_id_base,
   .name = "log_dump",
   .handler = vl_api_log_dump_t_handler,
   .endian = vl_api_log_dump_t_endian,
   .format_fn = vl_api_log_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_log_dump_t_tojson,
   .fromjson = vl_api_log_dump_t_fromjson,
   .calc_size = vl_api_log_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_LOG_DETAILS + msg_id_base,
  .name = "log_details",
  .handler = 0,
  .endian = vl_api_log_details_t_endian,
  .format_fn = vl_api_log_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_log_details_t_tojson,
  .fromjson = vl_api_log_details_t_fromjson,
  .calc_size = vl_api_log_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
