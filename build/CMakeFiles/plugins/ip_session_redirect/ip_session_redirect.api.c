#define vl_endianfun		/* define message structures */
#include "ip_session_redirect.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ip_session_redirect.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "ip_session_redirect.api.h"
#undef vl_printfun

#include "ip_session_redirect.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("ip_session_redirect_53620f15", VL_MSG_IP_SESSION_REDIRECT_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_ip_session_redirect);
   vl_msg_api_add_msg_name_crc (am, "ip_session_redirect_add_2f78ffda",
                                VL_API_IP_SESSION_REDIRECT_ADD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_session_redirect_add_reply_e8d4e804",
                                VL_API_IP_SESSION_REDIRECT_ADD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_session_redirect_add_v2_0765f51f",
                                VL_API_IP_SESSION_REDIRECT_ADD_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_session_redirect_add_v2_reply_e8d4e804",
                                VL_API_IP_SESSION_REDIRECT_ADD_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_session_redirect_del_fb643388",
                                VL_API_IP_SESSION_REDIRECT_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_session_redirect_del_reply_e8d4e804",
                                VL_API_IP_SESSION_REDIRECT_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_session_redirect_dump_33554253",
                                VL_API_IP_SESSION_REDIRECT_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_session_redirect_details_4487a233",
                                VL_API_IP_SESSION_REDIRECT_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_SESSION_REDIRECT_ADD + msg_id_base,
   .name = "ip_session_redirect_add",
   .handler = vl_api_ip_session_redirect_add_t_handler,
   .endian = vl_api_ip_session_redirect_add_t_endian,
   .format_fn = vl_api_ip_session_redirect_add_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_session_redirect_add_t_tojson,
   .fromjson = vl_api_ip_session_redirect_add_t_fromjson,
   .calc_size = vl_api_ip_session_redirect_add_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_SESSION_REDIRECT_ADD_REPLY + msg_id_base,
  .name = "ip_session_redirect_add_reply",
  .handler = 0,
  .endian = vl_api_ip_session_redirect_add_reply_t_endian,
  .format_fn = vl_api_ip_session_redirect_add_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_session_redirect_add_reply_t_tojson,
  .fromjson = vl_api_ip_session_redirect_add_reply_t_fromjson,
  .calc_size = vl_api_ip_session_redirect_add_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_SESSION_REDIRECT_ADD_V2 + msg_id_base,
   .name = "ip_session_redirect_add_v2",
   .handler = vl_api_ip_session_redirect_add_v2_t_handler,
   .endian = vl_api_ip_session_redirect_add_v2_t_endian,
   .format_fn = vl_api_ip_session_redirect_add_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_session_redirect_add_v2_t_tojson,
   .fromjson = vl_api_ip_session_redirect_add_v2_t_fromjson,
   .calc_size = vl_api_ip_session_redirect_add_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_SESSION_REDIRECT_ADD_V2_REPLY + msg_id_base,
  .name = "ip_session_redirect_add_v2_reply",
  .handler = 0,
  .endian = vl_api_ip_session_redirect_add_v2_reply_t_endian,
  .format_fn = vl_api_ip_session_redirect_add_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_session_redirect_add_v2_reply_t_tojson,
  .fromjson = vl_api_ip_session_redirect_add_v2_reply_t_fromjson,
  .calc_size = vl_api_ip_session_redirect_add_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_SESSION_REDIRECT_DEL + msg_id_base,
   .name = "ip_session_redirect_del",
   .handler = vl_api_ip_session_redirect_del_t_handler,
   .endian = vl_api_ip_session_redirect_del_t_endian,
   .format_fn = vl_api_ip_session_redirect_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_session_redirect_del_t_tojson,
   .fromjson = vl_api_ip_session_redirect_del_t_fromjson,
   .calc_size = vl_api_ip_session_redirect_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_SESSION_REDIRECT_DEL_REPLY + msg_id_base,
  .name = "ip_session_redirect_del_reply",
  .handler = 0,
  .endian = vl_api_ip_session_redirect_del_reply_t_endian,
  .format_fn = vl_api_ip_session_redirect_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_session_redirect_del_reply_t_tojson,
  .fromjson = vl_api_ip_session_redirect_del_reply_t_fromjson,
  .calc_size = vl_api_ip_session_redirect_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_SESSION_REDIRECT_DUMP + msg_id_base,
   .name = "ip_session_redirect_dump",
   .handler = vl_api_ip_session_redirect_dump_t_handler,
   .endian = vl_api_ip_session_redirect_dump_t_endian,
   .format_fn = vl_api_ip_session_redirect_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_session_redirect_dump_t_tojson,
   .fromjson = vl_api_ip_session_redirect_dump_t_fromjson,
   .calc_size = vl_api_ip_session_redirect_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_SESSION_REDIRECT_DETAILS + msg_id_base,
  .name = "ip_session_redirect_details",
  .handler = 0,
  .endian = vl_api_ip_session_redirect_details_t_endian,
  .format_fn = vl_api_ip_session_redirect_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_session_redirect_details_t_tojson,
  .fromjson = vl_api_ip_session_redirect_details_t_fromjson,
  .calc_size = vl_api_ip_session_redirect_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
