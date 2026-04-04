#define vl_endianfun		/* define message structures */
#include "ipsec.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ipsec.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "ipsec.api.h"
#undef vl_printfun

#include "ipsec.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("ipsec_b648c199", VL_MSG_IPSEC_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_ipsec);
   vl_msg_api_add_msg_name_crc (am, "ipsec_spd_add_del_20e89a95",
                                VL_API_IPSEC_SPD_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_spd_add_del_reply_e8d4e804",
                                VL_API_IPSEC_SPD_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_interface_add_del_spd_80f80cbb",
                                VL_API_IPSEC_INTERFACE_ADD_DEL_SPD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_interface_add_del_spd_reply_e8d4e804",
                                VL_API_IPSEC_INTERFACE_ADD_DEL_SPD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_spd_entry_add_del_338b7411",
                                VL_API_IPSEC_SPD_ENTRY_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_spd_entry_add_del_v2_7bfe69fc",
                                VL_API_IPSEC_SPD_ENTRY_ADD_DEL_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_spd_entry_add_del_reply_9ffac24b",
                                VL_API_IPSEC_SPD_ENTRY_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_spd_entry_add_del_v2_reply_9ffac24b",
                                VL_API_IPSEC_SPD_ENTRY_ADD_DEL_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_spds_dump_51077d14",
                                VL_API_IPSEC_SPDS_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_spds_details_a04bb254",
                                VL_API_IPSEC_SPDS_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_spd_dump_afefbf7d",
                                VL_API_IPSEC_SPD_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_spd_details_5813d7a2",
                                VL_API_IPSEC_SPD_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sad_entry_add_del_ab64b5c6",
                                VL_API_IPSEC_SAD_ENTRY_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sad_entry_add_del_v2_aca78b27",
                                VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sad_entry_add_del_v3_c77ebd92",
                                VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V3 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sad_entry_add_50229353",
                                VL_API_IPSEC_SAD_ENTRY_ADD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sad_entry_add_v2_9611297a",
                                VL_API_IPSEC_SAD_ENTRY_ADD_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sad_entry_del_3a91bde5",
                                VL_API_IPSEC_SAD_ENTRY_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sad_entry_del_reply_e8d4e804",
                                VL_API_IPSEC_SAD_ENTRY_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sad_bind_0649c0d9",
                                VL_API_IPSEC_SAD_BIND + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sad_bind_reply_e8d4e804",
                                VL_API_IPSEC_SAD_BIND_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sad_unbind_2076c2f4",
                                VL_API_IPSEC_SAD_UNBIND + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sad_unbind_reply_e8d4e804",
                                VL_API_IPSEC_SAD_UNBIND_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sad_entry_update_1412af86",
                                VL_API_IPSEC_SAD_ENTRY_UPDATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sad_entry_update_reply_e8d4e804",
                                VL_API_IPSEC_SAD_ENTRY_UPDATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sad_entry_add_del_reply_9ffac24b",
                                VL_API_IPSEC_SAD_ENTRY_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sad_entry_add_del_v2_reply_9ffac24b",
                                VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sad_entry_add_del_v3_reply_9ffac24b",
                                VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V3_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sad_entry_add_reply_9ffac24b",
                                VL_API_IPSEC_SAD_ENTRY_ADD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sad_entry_add_v2_reply_9ffac24b",
                                VL_API_IPSEC_SAD_ENTRY_ADD_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_tunnel_protect_update_30d5f133",
                                VL_API_IPSEC_TUNNEL_PROTECT_UPDATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_tunnel_protect_update_reply_e8d4e804",
                                VL_API_IPSEC_TUNNEL_PROTECT_UPDATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_tunnel_protect_del_cd239930",
                                VL_API_IPSEC_TUNNEL_PROTECT_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_tunnel_protect_del_reply_e8d4e804",
                                VL_API_IPSEC_TUNNEL_PROTECT_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_tunnel_protect_dump_f9e6675e",
                                VL_API_IPSEC_TUNNEL_PROTECT_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_tunnel_protect_details_21663a50",
                                VL_API_IPSEC_TUNNEL_PROTECT_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_spd_interface_dump_8971de19",
                                VL_API_IPSEC_SPD_INTERFACE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_spd_interface_details_7a0bcf3e",
                                VL_API_IPSEC_SPD_INTERFACE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_itf_create_6f50b3bc",
                                VL_API_IPSEC_ITF_CREATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_itf_create_reply_5383d31f",
                                VL_API_IPSEC_ITF_CREATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_itf_delete_f9e6675e",
                                VL_API_IPSEC_ITF_DELETE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_itf_delete_reply_e8d4e804",
                                VL_API_IPSEC_ITF_DELETE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_itf_dump_f9e6675e",
                                VL_API_IPSEC_ITF_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_itf_details_548a73b8",
                                VL_API_IPSEC_ITF_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sa_dump_2076c2f4",
                                VL_API_IPSEC_SA_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sa_v2_dump_2076c2f4",
                                VL_API_IPSEC_SA_V2_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sa_v3_dump_2076c2f4",
                                VL_API_IPSEC_SA_V3_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sa_v4_dump_2076c2f4",
                                VL_API_IPSEC_SA_V4_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sa_v5_dump_2076c2f4",
                                VL_API_IPSEC_SA_V5_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sa_details_345d14a7",
                                VL_API_IPSEC_SA_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sa_v2_details_e2130051",
                                VL_API_IPSEC_SA_V2_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sa_v3_details_2fc991ee",
                                VL_API_IPSEC_SA_V3_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sa_v4_details_87a322d7",
                                VL_API_IPSEC_SA_V4_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_sa_v5_details_3cfecfbd",
                                VL_API_IPSEC_SA_V5_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_backend_dump_51077d14",
                                VL_API_IPSEC_BACKEND_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_backend_details_ee601c29",
                                VL_API_IPSEC_BACKEND_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_select_backend_5bcfd3b7",
                                VL_API_IPSEC_SELECT_BACKEND + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_select_backend_reply_e8d4e804",
                                VL_API_IPSEC_SELECT_BACKEND_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_set_async_mode_a6465f7c",
                                VL_API_IPSEC_SET_ASYNC_MODE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ipsec_set_async_mode_reply_e8d4e804",
                                VL_API_IPSEC_SET_ASYNC_MODE_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SPD_ADD_DEL + msg_id_base,
   .name = "ipsec_spd_add_del",
   .handler = vl_api_ipsec_spd_add_del_t_handler,
   .endian = vl_api_ipsec_spd_add_del_t_endian,
   .format_fn = vl_api_ipsec_spd_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_spd_add_del_t_tojson,
   .fromjson = vl_api_ipsec_spd_add_del_t_fromjson,
   .calc_size = vl_api_ipsec_spd_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SPD_ADD_DEL_REPLY + msg_id_base,
  .name = "ipsec_spd_add_del_reply",
  .handler = 0,
  .endian = vl_api_ipsec_spd_add_del_reply_t_endian,
  .format_fn = vl_api_ipsec_spd_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_spd_add_del_reply_t_tojson,
  .fromjson = vl_api_ipsec_spd_add_del_reply_t_fromjson,
  .calc_size = vl_api_ipsec_spd_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_INTERFACE_ADD_DEL_SPD + msg_id_base,
   .name = "ipsec_interface_add_del_spd",
   .handler = vl_api_ipsec_interface_add_del_spd_t_handler,
   .endian = vl_api_ipsec_interface_add_del_spd_t_endian,
   .format_fn = vl_api_ipsec_interface_add_del_spd_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_interface_add_del_spd_t_tojson,
   .fromjson = vl_api_ipsec_interface_add_del_spd_t_fromjson,
   .calc_size = vl_api_ipsec_interface_add_del_spd_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_INTERFACE_ADD_DEL_SPD_REPLY + msg_id_base,
  .name = "ipsec_interface_add_del_spd_reply",
  .handler = 0,
  .endian = vl_api_ipsec_interface_add_del_spd_reply_t_endian,
  .format_fn = vl_api_ipsec_interface_add_del_spd_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_interface_add_del_spd_reply_t_tojson,
  .fromjson = vl_api_ipsec_interface_add_del_spd_reply_t_fromjson,
  .calc_size = vl_api_ipsec_interface_add_del_spd_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SPD_ENTRY_ADD_DEL + msg_id_base,
   .name = "ipsec_spd_entry_add_del",
   .handler = vl_api_ipsec_spd_entry_add_del_t_handler,
   .endian = vl_api_ipsec_spd_entry_add_del_t_endian,
   .format_fn = vl_api_ipsec_spd_entry_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_spd_entry_add_del_t_tojson,
   .fromjson = vl_api_ipsec_spd_entry_add_del_t_fromjson,
   .calc_size = vl_api_ipsec_spd_entry_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SPD_ENTRY_ADD_DEL_REPLY + msg_id_base,
  .name = "ipsec_spd_entry_add_del_reply",
  .handler = 0,
  .endian = vl_api_ipsec_spd_entry_add_del_reply_t_endian,
  .format_fn = vl_api_ipsec_spd_entry_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_spd_entry_add_del_reply_t_tojson,
  .fromjson = vl_api_ipsec_spd_entry_add_del_reply_t_fromjson,
  .calc_size = vl_api_ipsec_spd_entry_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SPD_ENTRY_ADD_DEL_V2 + msg_id_base,
   .name = "ipsec_spd_entry_add_del_v2",
   .handler = vl_api_ipsec_spd_entry_add_del_v2_t_handler,
   .endian = vl_api_ipsec_spd_entry_add_del_v2_t_endian,
   .format_fn = vl_api_ipsec_spd_entry_add_del_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_spd_entry_add_del_v2_t_tojson,
   .fromjson = vl_api_ipsec_spd_entry_add_del_v2_t_fromjson,
   .calc_size = vl_api_ipsec_spd_entry_add_del_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SPD_ENTRY_ADD_DEL_V2_REPLY + msg_id_base,
  .name = "ipsec_spd_entry_add_del_v2_reply",
  .handler = 0,
  .endian = vl_api_ipsec_spd_entry_add_del_v2_reply_t_endian,
  .format_fn = vl_api_ipsec_spd_entry_add_del_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_spd_entry_add_del_v2_reply_t_tojson,
  .fromjson = vl_api_ipsec_spd_entry_add_del_v2_reply_t_fromjson,
  .calc_size = vl_api_ipsec_spd_entry_add_del_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SPDS_DUMP + msg_id_base,
   .name = "ipsec_spds_dump",
   .handler = vl_api_ipsec_spds_dump_t_handler,
   .endian = vl_api_ipsec_spds_dump_t_endian,
   .format_fn = vl_api_ipsec_spds_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_spds_dump_t_tojson,
   .fromjson = vl_api_ipsec_spds_dump_t_fromjson,
   .calc_size = vl_api_ipsec_spds_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SPDS_DETAILS + msg_id_base,
  .name = "ipsec_spds_details",
  .handler = 0,
  .endian = vl_api_ipsec_spds_details_t_endian,
  .format_fn = vl_api_ipsec_spds_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_spds_details_t_tojson,
  .fromjson = vl_api_ipsec_spds_details_t_fromjson,
  .calc_size = vl_api_ipsec_spds_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SPD_DUMP + msg_id_base,
   .name = "ipsec_spd_dump",
   .handler = vl_api_ipsec_spd_dump_t_handler,
   .endian = vl_api_ipsec_spd_dump_t_endian,
   .format_fn = vl_api_ipsec_spd_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_spd_dump_t_tojson,
   .fromjson = vl_api_ipsec_spd_dump_t_fromjson,
   .calc_size = vl_api_ipsec_spd_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SPD_DETAILS + msg_id_base,
  .name = "ipsec_spd_details",
  .handler = 0,
  .endian = vl_api_ipsec_spd_details_t_endian,
  .format_fn = vl_api_ipsec_spd_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_spd_details_t_tojson,
  .fromjson = vl_api_ipsec_spd_details_t_fromjson,
  .calc_size = vl_api_ipsec_spd_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SAD_ENTRY_ADD_DEL + msg_id_base,
   .name = "ipsec_sad_entry_add_del",
   .handler = vl_api_ipsec_sad_entry_add_del_t_handler,
   .endian = vl_api_ipsec_sad_entry_add_del_t_endian,
   .format_fn = vl_api_ipsec_sad_entry_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_sad_entry_add_del_t_tojson,
   .fromjson = vl_api_ipsec_sad_entry_add_del_t_fromjson,
   .calc_size = vl_api_ipsec_sad_entry_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SAD_ENTRY_ADD_DEL_REPLY + msg_id_base,
  .name = "ipsec_sad_entry_add_del_reply",
  .handler = 0,
  .endian = vl_api_ipsec_sad_entry_add_del_reply_t_endian,
  .format_fn = vl_api_ipsec_sad_entry_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_sad_entry_add_del_reply_t_tojson,
  .fromjson = vl_api_ipsec_sad_entry_add_del_reply_t_fromjson,
  .calc_size = vl_api_ipsec_sad_entry_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V2 + msg_id_base,
   .name = "ipsec_sad_entry_add_del_v2",
   .handler = vl_api_ipsec_sad_entry_add_del_v2_t_handler,
   .endian = vl_api_ipsec_sad_entry_add_del_v2_t_endian,
   .format_fn = vl_api_ipsec_sad_entry_add_del_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_sad_entry_add_del_v2_t_tojson,
   .fromjson = vl_api_ipsec_sad_entry_add_del_v2_t_fromjson,
   .calc_size = vl_api_ipsec_sad_entry_add_del_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V2_REPLY + msg_id_base,
  .name = "ipsec_sad_entry_add_del_v2_reply",
  .handler = 0,
  .endian = vl_api_ipsec_sad_entry_add_del_v2_reply_t_endian,
  .format_fn = vl_api_ipsec_sad_entry_add_del_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_sad_entry_add_del_v2_reply_t_tojson,
  .fromjson = vl_api_ipsec_sad_entry_add_del_v2_reply_t_fromjson,
  .calc_size = vl_api_ipsec_sad_entry_add_del_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V3 + msg_id_base,
   .name = "ipsec_sad_entry_add_del_v3",
   .handler = vl_api_ipsec_sad_entry_add_del_v3_t_handler,
   .endian = vl_api_ipsec_sad_entry_add_del_v3_t_endian,
   .format_fn = vl_api_ipsec_sad_entry_add_del_v3_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_sad_entry_add_del_v3_t_tojson,
   .fromjson = vl_api_ipsec_sad_entry_add_del_v3_t_fromjson,
   .calc_size = vl_api_ipsec_sad_entry_add_del_v3_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V3_REPLY + msg_id_base,
  .name = "ipsec_sad_entry_add_del_v3_reply",
  .handler = 0,
  .endian = vl_api_ipsec_sad_entry_add_del_v3_reply_t_endian,
  .format_fn = vl_api_ipsec_sad_entry_add_del_v3_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_sad_entry_add_del_v3_reply_t_tojson,
  .fromjson = vl_api_ipsec_sad_entry_add_del_v3_reply_t_fromjson,
  .calc_size = vl_api_ipsec_sad_entry_add_del_v3_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SAD_ENTRY_ADD + msg_id_base,
   .name = "ipsec_sad_entry_add",
   .handler = vl_api_ipsec_sad_entry_add_t_handler,
   .endian = vl_api_ipsec_sad_entry_add_t_endian,
   .format_fn = vl_api_ipsec_sad_entry_add_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_sad_entry_add_t_tojson,
   .fromjson = vl_api_ipsec_sad_entry_add_t_fromjson,
   .calc_size = vl_api_ipsec_sad_entry_add_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SAD_ENTRY_ADD_REPLY + msg_id_base,
  .name = "ipsec_sad_entry_add_reply",
  .handler = 0,
  .endian = vl_api_ipsec_sad_entry_add_reply_t_endian,
  .format_fn = vl_api_ipsec_sad_entry_add_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_sad_entry_add_reply_t_tojson,
  .fromjson = vl_api_ipsec_sad_entry_add_reply_t_fromjson,
  .calc_size = vl_api_ipsec_sad_entry_add_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SAD_ENTRY_ADD_V2 + msg_id_base,
   .name = "ipsec_sad_entry_add_v2",
   .handler = vl_api_ipsec_sad_entry_add_v2_t_handler,
   .endian = vl_api_ipsec_sad_entry_add_v2_t_endian,
   .format_fn = vl_api_ipsec_sad_entry_add_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_sad_entry_add_v2_t_tojson,
   .fromjson = vl_api_ipsec_sad_entry_add_v2_t_fromjson,
   .calc_size = vl_api_ipsec_sad_entry_add_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SAD_ENTRY_ADD_V2_REPLY + msg_id_base,
  .name = "ipsec_sad_entry_add_v2_reply",
  .handler = 0,
  .endian = vl_api_ipsec_sad_entry_add_v2_reply_t_endian,
  .format_fn = vl_api_ipsec_sad_entry_add_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_sad_entry_add_v2_reply_t_tojson,
  .fromjson = vl_api_ipsec_sad_entry_add_v2_reply_t_fromjson,
  .calc_size = vl_api_ipsec_sad_entry_add_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SAD_ENTRY_DEL + msg_id_base,
   .name = "ipsec_sad_entry_del",
   .handler = vl_api_ipsec_sad_entry_del_t_handler,
   .endian = vl_api_ipsec_sad_entry_del_t_endian,
   .format_fn = vl_api_ipsec_sad_entry_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_sad_entry_del_t_tojson,
   .fromjson = vl_api_ipsec_sad_entry_del_t_fromjson,
   .calc_size = vl_api_ipsec_sad_entry_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SAD_ENTRY_DEL_REPLY + msg_id_base,
  .name = "ipsec_sad_entry_del_reply",
  .handler = 0,
  .endian = vl_api_ipsec_sad_entry_del_reply_t_endian,
  .format_fn = vl_api_ipsec_sad_entry_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_sad_entry_del_reply_t_tojson,
  .fromjson = vl_api_ipsec_sad_entry_del_reply_t_fromjson,
  .calc_size = vl_api_ipsec_sad_entry_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SAD_BIND + msg_id_base,
   .name = "ipsec_sad_bind",
   .handler = vl_api_ipsec_sad_bind_t_handler,
   .endian = vl_api_ipsec_sad_bind_t_endian,
   .format_fn = vl_api_ipsec_sad_bind_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_sad_bind_t_tojson,
   .fromjson = vl_api_ipsec_sad_bind_t_fromjson,
   .calc_size = vl_api_ipsec_sad_bind_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SAD_BIND_REPLY + msg_id_base,
  .name = "ipsec_sad_bind_reply",
  .handler = 0,
  .endian = vl_api_ipsec_sad_bind_reply_t_endian,
  .format_fn = vl_api_ipsec_sad_bind_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_sad_bind_reply_t_tojson,
  .fromjson = vl_api_ipsec_sad_bind_reply_t_fromjson,
  .calc_size = vl_api_ipsec_sad_bind_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SAD_UNBIND + msg_id_base,
   .name = "ipsec_sad_unbind",
   .handler = vl_api_ipsec_sad_unbind_t_handler,
   .endian = vl_api_ipsec_sad_unbind_t_endian,
   .format_fn = vl_api_ipsec_sad_unbind_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_sad_unbind_t_tojson,
   .fromjson = vl_api_ipsec_sad_unbind_t_fromjson,
   .calc_size = vl_api_ipsec_sad_unbind_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SAD_UNBIND_REPLY + msg_id_base,
  .name = "ipsec_sad_unbind_reply",
  .handler = 0,
  .endian = vl_api_ipsec_sad_unbind_reply_t_endian,
  .format_fn = vl_api_ipsec_sad_unbind_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_sad_unbind_reply_t_tojson,
  .fromjson = vl_api_ipsec_sad_unbind_reply_t_fromjson,
  .calc_size = vl_api_ipsec_sad_unbind_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SAD_ENTRY_UPDATE + msg_id_base,
   .name = "ipsec_sad_entry_update",
   .handler = vl_api_ipsec_sad_entry_update_t_handler,
   .endian = vl_api_ipsec_sad_entry_update_t_endian,
   .format_fn = vl_api_ipsec_sad_entry_update_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_sad_entry_update_t_tojson,
   .fromjson = vl_api_ipsec_sad_entry_update_t_fromjson,
   .calc_size = vl_api_ipsec_sad_entry_update_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SAD_ENTRY_UPDATE_REPLY + msg_id_base,
  .name = "ipsec_sad_entry_update_reply",
  .handler = 0,
  .endian = vl_api_ipsec_sad_entry_update_reply_t_endian,
  .format_fn = vl_api_ipsec_sad_entry_update_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_sad_entry_update_reply_t_tojson,
  .fromjson = vl_api_ipsec_sad_entry_update_reply_t_fromjson,
  .calc_size = vl_api_ipsec_sad_entry_update_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_TUNNEL_PROTECT_UPDATE + msg_id_base,
   .name = "ipsec_tunnel_protect_update",
   .handler = vl_api_ipsec_tunnel_protect_update_t_handler,
   .endian = vl_api_ipsec_tunnel_protect_update_t_endian,
   .format_fn = vl_api_ipsec_tunnel_protect_update_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_tunnel_protect_update_t_tojson,
   .fromjson = vl_api_ipsec_tunnel_protect_update_t_fromjson,
   .calc_size = vl_api_ipsec_tunnel_protect_update_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_TUNNEL_PROTECT_UPDATE_REPLY + msg_id_base,
  .name = "ipsec_tunnel_protect_update_reply",
  .handler = 0,
  .endian = vl_api_ipsec_tunnel_protect_update_reply_t_endian,
  .format_fn = vl_api_ipsec_tunnel_protect_update_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_tunnel_protect_update_reply_t_tojson,
  .fromjson = vl_api_ipsec_tunnel_protect_update_reply_t_fromjson,
  .calc_size = vl_api_ipsec_tunnel_protect_update_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_TUNNEL_PROTECT_DEL + msg_id_base,
   .name = "ipsec_tunnel_protect_del",
   .handler = vl_api_ipsec_tunnel_protect_del_t_handler,
   .endian = vl_api_ipsec_tunnel_protect_del_t_endian,
   .format_fn = vl_api_ipsec_tunnel_protect_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_tunnel_protect_del_t_tojson,
   .fromjson = vl_api_ipsec_tunnel_protect_del_t_fromjson,
   .calc_size = vl_api_ipsec_tunnel_protect_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_TUNNEL_PROTECT_DEL_REPLY + msg_id_base,
  .name = "ipsec_tunnel_protect_del_reply",
  .handler = 0,
  .endian = vl_api_ipsec_tunnel_protect_del_reply_t_endian,
  .format_fn = vl_api_ipsec_tunnel_protect_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_tunnel_protect_del_reply_t_tojson,
  .fromjson = vl_api_ipsec_tunnel_protect_del_reply_t_fromjson,
  .calc_size = vl_api_ipsec_tunnel_protect_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_TUNNEL_PROTECT_DUMP + msg_id_base,
   .name = "ipsec_tunnel_protect_dump",
   .handler = vl_api_ipsec_tunnel_protect_dump_t_handler,
   .endian = vl_api_ipsec_tunnel_protect_dump_t_endian,
   .format_fn = vl_api_ipsec_tunnel_protect_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_tunnel_protect_dump_t_tojson,
   .fromjson = vl_api_ipsec_tunnel_protect_dump_t_fromjson,
   .calc_size = vl_api_ipsec_tunnel_protect_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_TUNNEL_PROTECT_DETAILS + msg_id_base,
  .name = "ipsec_tunnel_protect_details",
  .handler = 0,
  .endian = vl_api_ipsec_tunnel_protect_details_t_endian,
  .format_fn = vl_api_ipsec_tunnel_protect_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_tunnel_protect_details_t_tojson,
  .fromjson = vl_api_ipsec_tunnel_protect_details_t_fromjson,
  .calc_size = vl_api_ipsec_tunnel_protect_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SPD_INTERFACE_DUMP + msg_id_base,
   .name = "ipsec_spd_interface_dump",
   .handler = vl_api_ipsec_spd_interface_dump_t_handler,
   .endian = vl_api_ipsec_spd_interface_dump_t_endian,
   .format_fn = vl_api_ipsec_spd_interface_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_spd_interface_dump_t_tojson,
   .fromjson = vl_api_ipsec_spd_interface_dump_t_fromjson,
   .calc_size = vl_api_ipsec_spd_interface_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SPD_INTERFACE_DETAILS + msg_id_base,
  .name = "ipsec_spd_interface_details",
  .handler = 0,
  .endian = vl_api_ipsec_spd_interface_details_t_endian,
  .format_fn = vl_api_ipsec_spd_interface_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_spd_interface_details_t_tojson,
  .fromjson = vl_api_ipsec_spd_interface_details_t_fromjson,
  .calc_size = vl_api_ipsec_spd_interface_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_ITF_CREATE + msg_id_base,
   .name = "ipsec_itf_create",
   .handler = vl_api_ipsec_itf_create_t_handler,
   .endian = vl_api_ipsec_itf_create_t_endian,
   .format_fn = vl_api_ipsec_itf_create_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_itf_create_t_tojson,
   .fromjson = vl_api_ipsec_itf_create_t_fromjson,
   .calc_size = vl_api_ipsec_itf_create_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_ITF_CREATE_REPLY + msg_id_base,
  .name = "ipsec_itf_create_reply",
  .handler = 0,
  .endian = vl_api_ipsec_itf_create_reply_t_endian,
  .format_fn = vl_api_ipsec_itf_create_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_itf_create_reply_t_tojson,
  .fromjson = vl_api_ipsec_itf_create_reply_t_fromjson,
  .calc_size = vl_api_ipsec_itf_create_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_ITF_DELETE + msg_id_base,
   .name = "ipsec_itf_delete",
   .handler = vl_api_ipsec_itf_delete_t_handler,
   .endian = vl_api_ipsec_itf_delete_t_endian,
   .format_fn = vl_api_ipsec_itf_delete_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_itf_delete_t_tojson,
   .fromjson = vl_api_ipsec_itf_delete_t_fromjson,
   .calc_size = vl_api_ipsec_itf_delete_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_ITF_DELETE_REPLY + msg_id_base,
  .name = "ipsec_itf_delete_reply",
  .handler = 0,
  .endian = vl_api_ipsec_itf_delete_reply_t_endian,
  .format_fn = vl_api_ipsec_itf_delete_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_itf_delete_reply_t_tojson,
  .fromjson = vl_api_ipsec_itf_delete_reply_t_fromjson,
  .calc_size = vl_api_ipsec_itf_delete_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_ITF_DUMP + msg_id_base,
   .name = "ipsec_itf_dump",
   .handler = vl_api_ipsec_itf_dump_t_handler,
   .endian = vl_api_ipsec_itf_dump_t_endian,
   .format_fn = vl_api_ipsec_itf_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_itf_dump_t_tojson,
   .fromjson = vl_api_ipsec_itf_dump_t_fromjson,
   .calc_size = vl_api_ipsec_itf_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_ITF_DETAILS + msg_id_base,
  .name = "ipsec_itf_details",
  .handler = 0,
  .endian = vl_api_ipsec_itf_details_t_endian,
  .format_fn = vl_api_ipsec_itf_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_itf_details_t_tojson,
  .fromjson = vl_api_ipsec_itf_details_t_fromjson,
  .calc_size = vl_api_ipsec_itf_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SA_DUMP + msg_id_base,
   .name = "ipsec_sa_dump",
   .handler = vl_api_ipsec_sa_dump_t_handler,
   .endian = vl_api_ipsec_sa_dump_t_endian,
   .format_fn = vl_api_ipsec_sa_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_sa_dump_t_tojson,
   .fromjson = vl_api_ipsec_sa_dump_t_fromjson,
   .calc_size = vl_api_ipsec_sa_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SA_DETAILS + msg_id_base,
  .name = "ipsec_sa_details",
  .handler = 0,
  .endian = vl_api_ipsec_sa_details_t_endian,
  .format_fn = vl_api_ipsec_sa_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_sa_details_t_tojson,
  .fromjson = vl_api_ipsec_sa_details_t_fromjson,
  .calc_size = vl_api_ipsec_sa_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SA_V2_DUMP + msg_id_base,
   .name = "ipsec_sa_v2_dump",
   .handler = vl_api_ipsec_sa_v2_dump_t_handler,
   .endian = vl_api_ipsec_sa_v2_dump_t_endian,
   .format_fn = vl_api_ipsec_sa_v2_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_sa_v2_dump_t_tojson,
   .fromjson = vl_api_ipsec_sa_v2_dump_t_fromjson,
   .calc_size = vl_api_ipsec_sa_v2_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SA_V2_DETAILS + msg_id_base,
  .name = "ipsec_sa_v2_details",
  .handler = 0,
  .endian = vl_api_ipsec_sa_v2_details_t_endian,
  .format_fn = vl_api_ipsec_sa_v2_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_sa_v2_details_t_tojson,
  .fromjson = vl_api_ipsec_sa_v2_details_t_fromjson,
  .calc_size = vl_api_ipsec_sa_v2_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SA_V3_DUMP + msg_id_base,
   .name = "ipsec_sa_v3_dump",
   .handler = vl_api_ipsec_sa_v3_dump_t_handler,
   .endian = vl_api_ipsec_sa_v3_dump_t_endian,
   .format_fn = vl_api_ipsec_sa_v3_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_sa_v3_dump_t_tojson,
   .fromjson = vl_api_ipsec_sa_v3_dump_t_fromjson,
   .calc_size = vl_api_ipsec_sa_v3_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SA_V3_DETAILS + msg_id_base,
  .name = "ipsec_sa_v3_details",
  .handler = 0,
  .endian = vl_api_ipsec_sa_v3_details_t_endian,
  .format_fn = vl_api_ipsec_sa_v3_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_sa_v3_details_t_tojson,
  .fromjson = vl_api_ipsec_sa_v3_details_t_fromjson,
  .calc_size = vl_api_ipsec_sa_v3_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SA_V4_DUMP + msg_id_base,
   .name = "ipsec_sa_v4_dump",
   .handler = vl_api_ipsec_sa_v4_dump_t_handler,
   .endian = vl_api_ipsec_sa_v4_dump_t_endian,
   .format_fn = vl_api_ipsec_sa_v4_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_sa_v4_dump_t_tojson,
   .fromjson = vl_api_ipsec_sa_v4_dump_t_fromjson,
   .calc_size = vl_api_ipsec_sa_v4_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SA_V4_DETAILS + msg_id_base,
  .name = "ipsec_sa_v4_details",
  .handler = 0,
  .endian = vl_api_ipsec_sa_v4_details_t_endian,
  .format_fn = vl_api_ipsec_sa_v4_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_sa_v4_details_t_tojson,
  .fromjson = vl_api_ipsec_sa_v4_details_t_fromjson,
  .calc_size = vl_api_ipsec_sa_v4_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SA_V5_DUMP + msg_id_base,
   .name = "ipsec_sa_v5_dump",
   .handler = vl_api_ipsec_sa_v5_dump_t_handler,
   .endian = vl_api_ipsec_sa_v5_dump_t_endian,
   .format_fn = vl_api_ipsec_sa_v5_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_sa_v5_dump_t_tojson,
   .fromjson = vl_api_ipsec_sa_v5_dump_t_fromjson,
   .calc_size = vl_api_ipsec_sa_v5_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SA_V5_DETAILS + msg_id_base,
  .name = "ipsec_sa_v5_details",
  .handler = 0,
  .endian = vl_api_ipsec_sa_v5_details_t_endian,
  .format_fn = vl_api_ipsec_sa_v5_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_sa_v5_details_t_tojson,
  .fromjson = vl_api_ipsec_sa_v5_details_t_fromjson,
  .calc_size = vl_api_ipsec_sa_v5_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_BACKEND_DUMP + msg_id_base,
   .name = "ipsec_backend_dump",
   .handler = vl_api_ipsec_backend_dump_t_handler,
   .endian = vl_api_ipsec_backend_dump_t_endian,
   .format_fn = vl_api_ipsec_backend_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_backend_dump_t_tojson,
   .fromjson = vl_api_ipsec_backend_dump_t_fromjson,
   .calc_size = vl_api_ipsec_backend_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_BACKEND_DETAILS + msg_id_base,
  .name = "ipsec_backend_details",
  .handler = 0,
  .endian = vl_api_ipsec_backend_details_t_endian,
  .format_fn = vl_api_ipsec_backend_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_backend_details_t_tojson,
  .fromjson = vl_api_ipsec_backend_details_t_fromjson,
  .calc_size = vl_api_ipsec_backend_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SELECT_BACKEND + msg_id_base,
   .name = "ipsec_select_backend",
   .handler = vl_api_ipsec_select_backend_t_handler,
   .endian = vl_api_ipsec_select_backend_t_endian,
   .format_fn = vl_api_ipsec_select_backend_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_select_backend_t_tojson,
   .fromjson = vl_api_ipsec_select_backend_t_fromjson,
   .calc_size = vl_api_ipsec_select_backend_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SELECT_BACKEND_REPLY + msg_id_base,
  .name = "ipsec_select_backend_reply",
  .handler = 0,
  .endian = vl_api_ipsec_select_backend_reply_t_endian,
  .format_fn = vl_api_ipsec_select_backend_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_select_backend_reply_t_tojson,
  .fromjson = vl_api_ipsec_select_backend_reply_t_fromjson,
  .calc_size = vl_api_ipsec_select_backend_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IPSEC_SET_ASYNC_MODE + msg_id_base,
   .name = "ipsec_set_async_mode",
   .handler = vl_api_ipsec_set_async_mode_t_handler,
   .endian = vl_api_ipsec_set_async_mode_t_endian,
   .format_fn = vl_api_ipsec_set_async_mode_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ipsec_set_async_mode_t_tojson,
   .fromjson = vl_api_ipsec_set_async_mode_t_fromjson,
   .calc_size = vl_api_ipsec_set_async_mode_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IPSEC_SET_ASYNC_MODE_REPLY + msg_id_base,
  .name = "ipsec_set_async_mode_reply",
  .handler = 0,
  .endian = vl_api_ipsec_set_async_mode_reply_t_endian,
  .format_fn = vl_api_ipsec_set_async_mode_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ipsec_set_async_mode_reply_t_tojson,
  .fromjson = vl_api_ipsec_set_async_mode_reply_t_fromjson,
  .calc_size = vl_api_ipsec_set_async_mode_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
vlib_error_desc_t esp_decrypt_error_counters[] = {
  {
   .name = "rx_pkts",
   .desc = "ESP pkts received",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "rx_post_pkts",
   .desc = "ESP-POST pkts received",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "handoff",
   .desc = "hand-off",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "decryption_failed",
   .desc = "ESP decryption failed",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "integ_error",
   .desc = "integrity check failed",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "crypto_engine_error",
   .desc = "crypto engine error (packet dropped)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "replay",
   .desc = "SA replayed packet",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "runt",
   .desc = "undersized packet",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "no_buffers",
   .desc = "no buffers (packet dropped)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "oversized_header",
   .desc = "buffer with oversized header (dropped)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "no_tail_space",
   .desc = "no enough buffer tail space (dropped)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "tun_no_proto",
   .desc = "no tunnel protocol",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "unsup_payload",
   .desc = "unsupported payload",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "no_avail_frame",
   .desc = "no available frame (packet dropped)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
};
vlib_error_desc_t esp_encrypt_error_counters[] = {
  {
   .name = "rx_pkts",
   .desc = "ESP pkts received",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "post_rx_pkts",
   .desc = "ESP-post pkts received",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "handoff",
   .desc = "Hand-off",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "seq_cycled",
   .desc = "sequence number cycled (packet dropped)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "crypto_engine_error",
   .desc = "crypto engine error (packet dropped)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "crypto_queue_full",
   .desc = "crypto queue full (packet dropped)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "no_buffers",
   .desc = "no buffers (packet dropped)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "no_protection",
   .desc = "no protecting SA (packet dropped)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "no_encryption",
   .desc = "no Encrypting SA (packet dropped)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "no_avail_frame",
   .desc = "no available frame (packet dropped)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
};
vlib_error_desc_t ah_encrypt_error_counters[] = {
  {
   .name = "rx_pkts",
   .desc = "AH pkts received",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "crypto_engine_error",
   .desc = "crypto engine error (packet dropped)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "seq_cycled",
   .desc = "sequence number cycled (packet dropped)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
};
vlib_error_desc_t ah_decrypt_error_counters[] = {
  {
   .name = "rx_pkts",
   .desc = "AH pkts received",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "decryption_failed",
   .desc = "AH decryption failed",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "integ_error",
   .desc = "Integrity check failed",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "no_tail_space",
   .desc = "not enough buffer tail space (dropped)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "drop_fragments",
   .desc = "IP fragments drop",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "replay",
   .desc = "SA replayed packet",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
};
vlib_error_desc_t ipsec_tun_error_counters[] = {
  {
   .name = "rx",
   .desc = "good packets received",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "disabled",
   .desc = "ipsec packets received on disabled interface",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "no_tunnel",
   .desc = "no matching tunnel",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "tunnel_mismatch",
   .desc = "SPI-tunnel mismatch",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "nat_keepalive",
   .desc = "NAT Keepalive",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "too_short",
   .desc = "Too Short",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "spi_0",
   .desc = "SPI 0",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
};
