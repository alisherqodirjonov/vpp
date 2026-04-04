#define vl_endianfun		/* define message structures */
#include "tracenode.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "tracenode.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "tracenode.api.h"
#undef vl_printfun

#include "tracenode.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("tracenode_963f3e79", VL_MSG_TRACENODE_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_tracenode);
   vl_msg_api_add_msg_name_crc (am, "tracenode_enable_disable_4013643c",
                                VL_API_TRACENODE_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "tracenode_enable_disable_reply_e8d4e804",
                                VL_API_TRACENODE_ENABLE_DISABLE_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TRACENODE_ENABLE_DISABLE + msg_id_base,
   .name = "tracenode_enable_disable",
   .handler = vl_api_tracenode_enable_disable_t_handler,
   .endian = vl_api_tracenode_enable_disable_t_endian,
   .format_fn = vl_api_tracenode_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_tracenode_enable_disable_t_tojson,
   .fromjson = vl_api_tracenode_enable_disable_t_fromjson,
   .calc_size = vl_api_tracenode_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_TRACENODE_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "tracenode_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_tracenode_enable_disable_reply_t_endian,
  .format_fn = vl_api_tracenode_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_tracenode_enable_disable_reply_t_tojson,
  .fromjson = vl_api_tracenode_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_tracenode_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
