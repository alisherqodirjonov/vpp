#define vl_endianfun		/* define message structures */
#include "af_packet.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "af_packet.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "af_packet.api.h"
#undef vl_printfun

#include "af_packet.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("af_packet_720ee900", VL_MSG_AF_PACKET_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_af_packet);
   vl_msg_api_add_msg_name_crc (am, "af_packet_create_a190415f",
                                VL_API_AF_PACKET_CREATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "af_packet_create_reply_5383d31f",
                                VL_API_AF_PACKET_CREATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "af_packet_create_v2_4aff0436",
                                VL_API_AF_PACKET_CREATE_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "af_packet_create_v2_reply_5383d31f",
                                VL_API_AF_PACKET_CREATE_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "af_packet_create_v3_b3a809d4",
                                VL_API_AF_PACKET_CREATE_V3 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "af_packet_create_v3_reply_5383d31f",
                                VL_API_AF_PACKET_CREATE_V3_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "af_packet_delete_863fa648",
                                VL_API_AF_PACKET_DELETE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "af_packet_delete_reply_e8d4e804",
                                VL_API_AF_PACKET_DELETE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "af_packet_set_l4_cksum_offload_319cd5c8",
                                VL_API_AF_PACKET_SET_L4_CKSUM_OFFLOAD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "af_packet_set_l4_cksum_offload_reply_e8d4e804",
                                VL_API_AF_PACKET_SET_L4_CKSUM_OFFLOAD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "af_packet_dump_51077d14",
                                VL_API_AF_PACKET_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "af_packet_details_58c7c042",
                                VL_API_AF_PACKET_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_AF_PACKET_CREATE + msg_id_base,
   .name = "af_packet_create",
   .handler = vl_api_af_packet_create_t_handler,
   .endian = vl_api_af_packet_create_t_endian,
   .format_fn = vl_api_af_packet_create_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_af_packet_create_t_tojson,
   .fromjson = vl_api_af_packet_create_t_fromjson,
   .calc_size = vl_api_af_packet_create_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_AF_PACKET_CREATE_REPLY + msg_id_base,
  .name = "af_packet_create_reply",
  .handler = 0,
  .endian = vl_api_af_packet_create_reply_t_endian,
  .format_fn = vl_api_af_packet_create_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_af_packet_create_reply_t_tojson,
  .fromjson = vl_api_af_packet_create_reply_t_fromjson,
  .calc_size = vl_api_af_packet_create_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_AF_PACKET_CREATE_V2 + msg_id_base,
   .name = "af_packet_create_v2",
   .handler = vl_api_af_packet_create_v2_t_handler,
   .endian = vl_api_af_packet_create_v2_t_endian,
   .format_fn = vl_api_af_packet_create_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_af_packet_create_v2_t_tojson,
   .fromjson = vl_api_af_packet_create_v2_t_fromjson,
   .calc_size = vl_api_af_packet_create_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_AF_PACKET_CREATE_V2_REPLY + msg_id_base,
  .name = "af_packet_create_v2_reply",
  .handler = 0,
  .endian = vl_api_af_packet_create_v2_reply_t_endian,
  .format_fn = vl_api_af_packet_create_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_af_packet_create_v2_reply_t_tojson,
  .fromjson = vl_api_af_packet_create_v2_reply_t_fromjson,
  .calc_size = vl_api_af_packet_create_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_AF_PACKET_CREATE_V3 + msg_id_base,
   .name = "af_packet_create_v3",
   .handler = vl_api_af_packet_create_v3_t_handler,
   .endian = vl_api_af_packet_create_v3_t_endian,
   .format_fn = vl_api_af_packet_create_v3_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_af_packet_create_v3_t_tojson,
   .fromjson = vl_api_af_packet_create_v3_t_fromjson,
   .calc_size = vl_api_af_packet_create_v3_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_AF_PACKET_CREATE_V3_REPLY + msg_id_base,
  .name = "af_packet_create_v3_reply",
  .handler = 0,
  .endian = vl_api_af_packet_create_v3_reply_t_endian,
  .format_fn = vl_api_af_packet_create_v3_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_af_packet_create_v3_reply_t_tojson,
  .fromjson = vl_api_af_packet_create_v3_reply_t_fromjson,
  .calc_size = vl_api_af_packet_create_v3_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_AF_PACKET_DELETE + msg_id_base,
   .name = "af_packet_delete",
   .handler = vl_api_af_packet_delete_t_handler,
   .endian = vl_api_af_packet_delete_t_endian,
   .format_fn = vl_api_af_packet_delete_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_af_packet_delete_t_tojson,
   .fromjson = vl_api_af_packet_delete_t_fromjson,
   .calc_size = vl_api_af_packet_delete_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_AF_PACKET_DELETE_REPLY + msg_id_base,
  .name = "af_packet_delete_reply",
  .handler = 0,
  .endian = vl_api_af_packet_delete_reply_t_endian,
  .format_fn = vl_api_af_packet_delete_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_af_packet_delete_reply_t_tojson,
  .fromjson = vl_api_af_packet_delete_reply_t_fromjson,
  .calc_size = vl_api_af_packet_delete_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_AF_PACKET_SET_L4_CKSUM_OFFLOAD + msg_id_base,
   .name = "af_packet_set_l4_cksum_offload",
   .handler = vl_api_af_packet_set_l4_cksum_offload_t_handler,
   .endian = vl_api_af_packet_set_l4_cksum_offload_t_endian,
   .format_fn = vl_api_af_packet_set_l4_cksum_offload_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_af_packet_set_l4_cksum_offload_t_tojson,
   .fromjson = vl_api_af_packet_set_l4_cksum_offload_t_fromjson,
   .calc_size = vl_api_af_packet_set_l4_cksum_offload_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_AF_PACKET_SET_L4_CKSUM_OFFLOAD_REPLY + msg_id_base,
  .name = "af_packet_set_l4_cksum_offload_reply",
  .handler = 0,
  .endian = vl_api_af_packet_set_l4_cksum_offload_reply_t_endian,
  .format_fn = vl_api_af_packet_set_l4_cksum_offload_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_af_packet_set_l4_cksum_offload_reply_t_tojson,
  .fromjson = vl_api_af_packet_set_l4_cksum_offload_reply_t_fromjson,
  .calc_size = vl_api_af_packet_set_l4_cksum_offload_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_AF_PACKET_DUMP + msg_id_base,
   .name = "af_packet_dump",
   .handler = vl_api_af_packet_dump_t_handler,
   .endian = vl_api_af_packet_dump_t_endian,
   .format_fn = vl_api_af_packet_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_af_packet_dump_t_tojson,
   .fromjson = vl_api_af_packet_dump_t_fromjson,
   .calc_size = vl_api_af_packet_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_AF_PACKET_DETAILS + msg_id_base,
  .name = "af_packet_details",
  .handler = 0,
  .endian = vl_api_af_packet_details_t_endian,
  .format_fn = vl_api_af_packet_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_af_packet_details_t_tojson,
  .fromjson = vl_api_af_packet_details_t_fromjson,
  .calc_size = vl_api_af_packet_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
