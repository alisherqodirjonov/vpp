#define vl_endianfun		/* define message structures */
#include "rd_cp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "rd_cp.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "rd_cp.api.h"
#undef vl_printfun

#include "rd_cp.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("rd_cp_8a996e86", VL_MSG_RD_CP_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_rd_cp);
   vl_msg_api_add_msg_name_crc (am, "ip6_nd_address_autoconfig_9e14a4a7",
                                VL_API_IP6_ND_ADDRESS_AUTOCONFIG + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip6_nd_address_autoconfig_reply_e8d4e804",
                                VL_API_IP6_ND_ADDRESS_AUTOCONFIG_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP6_ND_ADDRESS_AUTOCONFIG + msg_id_base,
   .name = "ip6_nd_address_autoconfig",
   .handler = vl_api_ip6_nd_address_autoconfig_t_handler,
   .endian = vl_api_ip6_nd_address_autoconfig_t_endian,
   .format_fn = vl_api_ip6_nd_address_autoconfig_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip6_nd_address_autoconfig_t_tojson,
   .fromjson = vl_api_ip6_nd_address_autoconfig_t_fromjson,
   .calc_size = vl_api_ip6_nd_address_autoconfig_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP6_ND_ADDRESS_AUTOCONFIG_REPLY + msg_id_base,
  .name = "ip6_nd_address_autoconfig_reply",
  .handler = 0,
  .endian = vl_api_ip6_nd_address_autoconfig_reply_t_endian,
  .format_fn = vl_api_ip6_nd_address_autoconfig_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip6_nd_address_autoconfig_reply_t_tojson,
  .fromjson = vl_api_ip6_nd_address_autoconfig_reply_t_fromjson,
  .calc_size = vl_api_ip6_nd_address_autoconfig_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
