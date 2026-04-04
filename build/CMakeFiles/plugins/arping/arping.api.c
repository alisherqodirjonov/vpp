#define vl_endianfun		/* define message structures */
#include "arping.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "arping.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "arping.api.h"
#undef vl_printfun

#include "arping.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("arping_d4cc4344", VL_MSG_ARPING_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_arping);
   vl_msg_api_add_msg_name_crc (am, "arping_48817482",
                                VL_API_ARPING + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "arping_reply_bb9d1cbd",
                                VL_API_ARPING_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "arping_acd_48817482",
                                VL_API_ARPING_ACD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "arping_acd_reply_e08c3b05",
                                VL_API_ARPING_ACD_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ARPING + msg_id_base,
   .name = "arping",
   .handler = vl_api_arping_t_handler,
   .endian = vl_api_arping_t_endian,
   .format_fn = vl_api_arping_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_arping_t_tojson,
   .fromjson = vl_api_arping_t_fromjson,
   .calc_size = vl_api_arping_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ARPING_REPLY + msg_id_base,
  .name = "arping_reply",
  .handler = 0,
  .endian = vl_api_arping_reply_t_endian,
  .format_fn = vl_api_arping_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_arping_reply_t_tojson,
  .fromjson = vl_api_arping_reply_t_fromjson,
  .calc_size = vl_api_arping_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ARPING_ACD + msg_id_base,
   .name = "arping_acd",
   .handler = vl_api_arping_acd_t_handler,
   .endian = vl_api_arping_acd_t_endian,
   .format_fn = vl_api_arping_acd_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_arping_acd_t_tojson,
   .fromjson = vl_api_arping_acd_t_fromjson,
   .calc_size = vl_api_arping_acd_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ARPING_ACD_REPLY + msg_id_base,
  .name = "arping_acd_reply",
  .handler = 0,
  .endian = vl_api_arping_acd_reply_t_endian,
  .format_fn = vl_api_arping_acd_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_arping_acd_reply_t_tojson,
  .fromjson = vl_api_arping_acd_reply_t_fromjson,
  .calc_size = vl_api_arping_acd_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
