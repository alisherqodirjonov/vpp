#define vl_endianfun		/* define message structures */
#include "udp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "udp.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "udp.api.h"
#undef vl_printfun

#include "udp.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("udp_04ed7c5e", VL_MSG_UDP_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_udp);
   vl_msg_api_add_msg_name_crc (am, "udp_encap_add_f74a60b1",
                                VL_API_UDP_ENCAP_ADD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "udp_encap_add_reply_e2fc8294",
                                VL_API_UDP_ENCAP_ADD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "udp_encap_del_3a91bde5",
                                VL_API_UDP_ENCAP_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "udp_encap_del_reply_e8d4e804",
                                VL_API_UDP_ENCAP_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "udp_encap_dump_51077d14",
                                VL_API_UDP_ENCAP_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "udp_encap_details_8cfb9c76",
                                VL_API_UDP_ENCAP_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "udp_decap_add_del_d14a4f47",
                                VL_API_UDP_DECAP_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "udp_decap_add_del_reply_e8d4e804",
                                VL_API_UDP_DECAP_ADD_DEL_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_UDP_ENCAP_ADD + msg_id_base,
   .name = "udp_encap_add",
   .handler = vl_api_udp_encap_add_t_handler,
   .endian = vl_api_udp_encap_add_t_endian,
   .format_fn = vl_api_udp_encap_add_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_udp_encap_add_t_tojson,
   .fromjson = vl_api_udp_encap_add_t_fromjson,
   .calc_size = vl_api_udp_encap_add_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_UDP_ENCAP_ADD_REPLY + msg_id_base,
  .name = "udp_encap_add_reply",
  .handler = 0,
  .endian = vl_api_udp_encap_add_reply_t_endian,
  .format_fn = vl_api_udp_encap_add_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_udp_encap_add_reply_t_tojson,
  .fromjson = vl_api_udp_encap_add_reply_t_fromjson,
  .calc_size = vl_api_udp_encap_add_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_UDP_ENCAP_DEL + msg_id_base,
   .name = "udp_encap_del",
   .handler = vl_api_udp_encap_del_t_handler,
   .endian = vl_api_udp_encap_del_t_endian,
   .format_fn = vl_api_udp_encap_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_udp_encap_del_t_tojson,
   .fromjson = vl_api_udp_encap_del_t_fromjson,
   .calc_size = vl_api_udp_encap_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_UDP_ENCAP_DEL_REPLY + msg_id_base,
  .name = "udp_encap_del_reply",
  .handler = 0,
  .endian = vl_api_udp_encap_del_reply_t_endian,
  .format_fn = vl_api_udp_encap_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_udp_encap_del_reply_t_tojson,
  .fromjson = vl_api_udp_encap_del_reply_t_fromjson,
  .calc_size = vl_api_udp_encap_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_UDP_ENCAP_DUMP + msg_id_base,
   .name = "udp_encap_dump",
   .handler = vl_api_udp_encap_dump_t_handler,
   .endian = vl_api_udp_encap_dump_t_endian,
   .format_fn = vl_api_udp_encap_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_udp_encap_dump_t_tojson,
   .fromjson = vl_api_udp_encap_dump_t_fromjson,
   .calc_size = vl_api_udp_encap_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_UDP_ENCAP_DETAILS + msg_id_base,
  .name = "udp_encap_details",
  .handler = 0,
  .endian = vl_api_udp_encap_details_t_endian,
  .format_fn = vl_api_udp_encap_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_udp_encap_details_t_tojson,
  .fromjson = vl_api_udp_encap_details_t_fromjson,
  .calc_size = vl_api_udp_encap_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_UDP_DECAP_ADD_DEL + msg_id_base,
   .name = "udp_decap_add_del",
   .handler = vl_api_udp_decap_add_del_t_handler,
   .endian = vl_api_udp_decap_add_del_t_endian,
   .format_fn = vl_api_udp_decap_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_udp_decap_add_del_t_tojson,
   .fromjson = vl_api_udp_decap_add_del_t_fromjson,
   .calc_size = vl_api_udp_decap_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_UDP_DECAP_ADD_DEL_REPLY + msg_id_base,
  .name = "udp_decap_add_del_reply",
  .handler = 0,
  .endian = vl_api_udp_decap_add_del_reply_t_endian,
  .format_fn = vl_api_udp_decap_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_udp_decap_add_del_reply_t_tojson,
  .fromjson = vl_api_udp_decap_add_del_reply_t_fromjson,
  .calc_size = vl_api_udp_decap_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
