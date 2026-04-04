#define vl_endianfun		/* define message structures */
#include "pppoe.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "pppoe.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "pppoe.api.h"
#undef vl_printfun

#include "pppoe.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("pppoe_57db3239", VL_MSG_PPPOE_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_pppoe);
   vl_msg_api_add_msg_name_crc (am, "pppoe_add_del_session_f6fd759e",
                                VL_API_PPPOE_ADD_DEL_SESSION + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pppoe_add_del_session_reply_5383d31f",
                                VL_API_PPPOE_ADD_DEL_SESSION_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pppoe_session_dump_f9e6675e",
                                VL_API_PPPOE_SESSION_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pppoe_session_details_4b8e8a4a",
                                VL_API_PPPOE_SESSION_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pppoe_add_del_cp_eacd9aaa",
                                VL_API_PPPOE_ADD_DEL_CP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "pppoe_add_del_cp_reply_e8d4e804",
                                VL_API_PPPOE_ADD_DEL_CP_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PPPOE_ADD_DEL_SESSION + msg_id_base,
   .name = "pppoe_add_del_session",
   .handler = vl_api_pppoe_add_del_session_t_handler,
   .endian = vl_api_pppoe_add_del_session_t_endian,
   .format_fn = vl_api_pppoe_add_del_session_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pppoe_add_del_session_t_tojson,
   .fromjson = vl_api_pppoe_add_del_session_t_fromjson,
   .calc_size = vl_api_pppoe_add_del_session_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PPPOE_ADD_DEL_SESSION_REPLY + msg_id_base,
  .name = "pppoe_add_del_session_reply",
  .handler = 0,
  .endian = vl_api_pppoe_add_del_session_reply_t_endian,
  .format_fn = vl_api_pppoe_add_del_session_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pppoe_add_del_session_reply_t_tojson,
  .fromjson = vl_api_pppoe_add_del_session_reply_t_fromjson,
  .calc_size = vl_api_pppoe_add_del_session_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PPPOE_SESSION_DUMP + msg_id_base,
   .name = "pppoe_session_dump",
   .handler = vl_api_pppoe_session_dump_t_handler,
   .endian = vl_api_pppoe_session_dump_t_endian,
   .format_fn = vl_api_pppoe_session_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pppoe_session_dump_t_tojson,
   .fromjson = vl_api_pppoe_session_dump_t_fromjson,
   .calc_size = vl_api_pppoe_session_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PPPOE_SESSION_DETAILS + msg_id_base,
  .name = "pppoe_session_details",
  .handler = 0,
  .endian = vl_api_pppoe_session_details_t_endian,
  .format_fn = vl_api_pppoe_session_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pppoe_session_details_t_tojson,
  .fromjson = vl_api_pppoe_session_details_t_fromjson,
  .calc_size = vl_api_pppoe_session_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_PPPOE_ADD_DEL_CP + msg_id_base,
   .name = "pppoe_add_del_cp",
   .handler = vl_api_pppoe_add_del_cp_t_handler,
   .endian = vl_api_pppoe_add_del_cp_t_endian,
   .format_fn = vl_api_pppoe_add_del_cp_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_pppoe_add_del_cp_t_tojson,
   .fromjson = vl_api_pppoe_add_del_cp_t_fromjson,
   .calc_size = vl_api_pppoe_add_del_cp_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_PPPOE_ADD_DEL_CP_REPLY + msg_id_base,
  .name = "pppoe_add_del_cp_reply",
  .handler = 0,
  .endian = vl_api_pppoe_add_del_cp_reply_t_endian,
  .format_fn = vl_api_pppoe_add_del_cp_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_pppoe_add_del_cp_reply_t_tojson,
  .fromjson = vl_api_pppoe_add_del_cp_reply_t_fromjson,
  .calc_size = vl_api_pppoe_add_del_cp_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
