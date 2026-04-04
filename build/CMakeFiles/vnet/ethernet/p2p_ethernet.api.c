#define vl_endianfun		/* define message structures */
#include "p2p_ethernet.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "p2p_ethernet.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "p2p_ethernet.api.h"
#undef vl_printfun

#include "p2p_ethernet.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("p2p_ethernet_339e3d84", VL_MSG_P2P_ETHERNET_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_p2p_ethernet);
   vl_msg_api_add_msg_name_crc (am, "p2p_ethernet_add_36a1a6dc",
                                VL_API_P2P_ETHERNET_ADD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "p2p_ethernet_add_reply_5383d31f",
                                VL_API_P2P_ETHERNET_ADD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "p2p_ethernet_del_62f81c8c",
                                VL_API_P2P_ETHERNET_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "p2p_ethernet_del_reply_e8d4e804",
                                VL_API_P2P_ETHERNET_DEL_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_P2P_ETHERNET_ADD + msg_id_base,
   .name = "p2p_ethernet_add",
   .handler = vl_api_p2p_ethernet_add_t_handler,
   .endian = vl_api_p2p_ethernet_add_t_endian,
   .format_fn = vl_api_p2p_ethernet_add_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_p2p_ethernet_add_t_tojson,
   .fromjson = vl_api_p2p_ethernet_add_t_fromjson,
   .calc_size = vl_api_p2p_ethernet_add_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_P2P_ETHERNET_ADD_REPLY + msg_id_base,
  .name = "p2p_ethernet_add_reply",
  .handler = 0,
  .endian = vl_api_p2p_ethernet_add_reply_t_endian,
  .format_fn = vl_api_p2p_ethernet_add_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_p2p_ethernet_add_reply_t_tojson,
  .fromjson = vl_api_p2p_ethernet_add_reply_t_fromjson,
  .calc_size = vl_api_p2p_ethernet_add_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_P2P_ETHERNET_DEL + msg_id_base,
   .name = "p2p_ethernet_del",
   .handler = vl_api_p2p_ethernet_del_t_handler,
   .endian = vl_api_p2p_ethernet_del_t_endian,
   .format_fn = vl_api_p2p_ethernet_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_p2p_ethernet_del_t_tojson,
   .fromjson = vl_api_p2p_ethernet_del_t_fromjson,
   .calc_size = vl_api_p2p_ethernet_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_P2P_ETHERNET_DEL_REPLY + msg_id_base,
  .name = "p2p_ethernet_del_reply",
  .handler = 0,
  .endian = vl_api_p2p_ethernet_del_reply_t_endian,
  .format_fn = vl_api_p2p_ethernet_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_p2p_ethernet_del_reply_t_tojson,
  .fromjson = vl_api_p2p_ethernet_del_reply_t_fromjson,
  .calc_size = vl_api_p2p_ethernet_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
