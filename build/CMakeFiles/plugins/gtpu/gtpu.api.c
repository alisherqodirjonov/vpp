#define vl_endianfun		/* define message structures */
#include "gtpu.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "gtpu.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "gtpu.api.h"
#undef vl_printfun

#include "gtpu.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("gtpu_a3ac80d3", VL_MSG_GTPU_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_gtpu);
   vl_msg_api_add_msg_name_crc (am, "gtpu_add_del_tunnel_ca983a2b",
                                VL_API_GTPU_ADD_DEL_TUNNEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gtpu_add_del_tunnel_reply_5383d31f",
                                VL_API_GTPU_ADD_DEL_TUNNEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gtpu_add_del_tunnel_v2_a0c30713",
                                VL_API_GTPU_ADD_DEL_TUNNEL_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gtpu_add_del_tunnel_v2_reply_62b41304",
                                VL_API_GTPU_ADD_DEL_TUNNEL_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gtpu_tunnel_update_tteid_79f33816",
                                VL_API_GTPU_TUNNEL_UPDATE_TTEID + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gtpu_tunnel_update_tteid_reply_e8d4e804",
                                VL_API_GTPU_TUNNEL_UPDATE_TTEID_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gtpu_tunnel_dump_f9e6675e",
                                VL_API_GTPU_TUNNEL_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gtpu_tunnel_details_27f434ae",
                                VL_API_GTPU_TUNNEL_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gtpu_tunnel_v2_dump_f9e6675e",
                                VL_API_GTPU_TUNNEL_V2_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gtpu_tunnel_v2_details_8bf4ba92",
                                VL_API_GTPU_TUNNEL_V2_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_gtpu_bypass_65247409",
                                VL_API_SW_INTERFACE_SET_GTPU_BYPASS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_set_gtpu_bypass_reply_e8d4e804",
                                VL_API_SW_INTERFACE_SET_GTPU_BYPASS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gtpu_offload_rx_f0b08786",
                                VL_API_GTPU_OFFLOAD_RX + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gtpu_offload_rx_reply_e8d4e804",
                                VL_API_GTPU_OFFLOAD_RX_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gtpu_add_del_forward_c6ccce13",
                                VL_API_GTPU_ADD_DEL_FORWARD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gtpu_add_del_forward_reply_5383d31f",
                                VL_API_GTPU_ADD_DEL_FORWARD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gtpu_get_transfer_counts_61410788",
                                VL_API_GTPU_GET_TRANSFER_COUNTS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "gtpu_get_transfer_counts_reply_e35f04bc",
                                VL_API_GTPU_GET_TRANSFER_COUNTS_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GTPU_ADD_DEL_TUNNEL + msg_id_base,
   .name = "gtpu_add_del_tunnel",
   .handler = vl_api_gtpu_add_del_tunnel_t_handler,
   .endian = vl_api_gtpu_add_del_tunnel_t_endian,
   .format_fn = vl_api_gtpu_add_del_tunnel_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gtpu_add_del_tunnel_t_tojson,
   .fromjson = vl_api_gtpu_add_del_tunnel_t_fromjson,
   .calc_size = vl_api_gtpu_add_del_tunnel_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GTPU_ADD_DEL_TUNNEL_REPLY + msg_id_base,
  .name = "gtpu_add_del_tunnel_reply",
  .handler = 0,
  .endian = vl_api_gtpu_add_del_tunnel_reply_t_endian,
  .format_fn = vl_api_gtpu_add_del_tunnel_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gtpu_add_del_tunnel_reply_t_tojson,
  .fromjson = vl_api_gtpu_add_del_tunnel_reply_t_fromjson,
  .calc_size = vl_api_gtpu_add_del_tunnel_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GTPU_ADD_DEL_TUNNEL_V2 + msg_id_base,
   .name = "gtpu_add_del_tunnel_v2",
   .handler = vl_api_gtpu_add_del_tunnel_v2_t_handler,
   .endian = vl_api_gtpu_add_del_tunnel_v2_t_endian,
   .format_fn = vl_api_gtpu_add_del_tunnel_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gtpu_add_del_tunnel_v2_t_tojson,
   .fromjson = vl_api_gtpu_add_del_tunnel_v2_t_fromjson,
   .calc_size = vl_api_gtpu_add_del_tunnel_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GTPU_ADD_DEL_TUNNEL_V2_REPLY + msg_id_base,
  .name = "gtpu_add_del_tunnel_v2_reply",
  .handler = 0,
  .endian = vl_api_gtpu_add_del_tunnel_v2_reply_t_endian,
  .format_fn = vl_api_gtpu_add_del_tunnel_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gtpu_add_del_tunnel_v2_reply_t_tojson,
  .fromjson = vl_api_gtpu_add_del_tunnel_v2_reply_t_fromjson,
  .calc_size = vl_api_gtpu_add_del_tunnel_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GTPU_TUNNEL_UPDATE_TTEID + msg_id_base,
   .name = "gtpu_tunnel_update_tteid",
   .handler = vl_api_gtpu_tunnel_update_tteid_t_handler,
   .endian = vl_api_gtpu_tunnel_update_tteid_t_endian,
   .format_fn = vl_api_gtpu_tunnel_update_tteid_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gtpu_tunnel_update_tteid_t_tojson,
   .fromjson = vl_api_gtpu_tunnel_update_tteid_t_fromjson,
   .calc_size = vl_api_gtpu_tunnel_update_tteid_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GTPU_TUNNEL_UPDATE_TTEID_REPLY + msg_id_base,
  .name = "gtpu_tunnel_update_tteid_reply",
  .handler = 0,
  .endian = vl_api_gtpu_tunnel_update_tteid_reply_t_endian,
  .format_fn = vl_api_gtpu_tunnel_update_tteid_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gtpu_tunnel_update_tteid_reply_t_tojson,
  .fromjson = vl_api_gtpu_tunnel_update_tteid_reply_t_fromjson,
  .calc_size = vl_api_gtpu_tunnel_update_tteid_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GTPU_TUNNEL_DUMP + msg_id_base,
   .name = "gtpu_tunnel_dump",
   .handler = vl_api_gtpu_tunnel_dump_t_handler,
   .endian = vl_api_gtpu_tunnel_dump_t_endian,
   .format_fn = vl_api_gtpu_tunnel_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gtpu_tunnel_dump_t_tojson,
   .fromjson = vl_api_gtpu_tunnel_dump_t_fromjson,
   .calc_size = vl_api_gtpu_tunnel_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GTPU_TUNNEL_DETAILS + msg_id_base,
  .name = "gtpu_tunnel_details",
  .handler = 0,
  .endian = vl_api_gtpu_tunnel_details_t_endian,
  .format_fn = vl_api_gtpu_tunnel_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gtpu_tunnel_details_t_tojson,
  .fromjson = vl_api_gtpu_tunnel_details_t_fromjson,
  .calc_size = vl_api_gtpu_tunnel_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GTPU_TUNNEL_V2_DUMP + msg_id_base,
   .name = "gtpu_tunnel_v2_dump",
   .handler = vl_api_gtpu_tunnel_v2_dump_t_handler,
   .endian = vl_api_gtpu_tunnel_v2_dump_t_endian,
   .format_fn = vl_api_gtpu_tunnel_v2_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gtpu_tunnel_v2_dump_t_tojson,
   .fromjson = vl_api_gtpu_tunnel_v2_dump_t_fromjson,
   .calc_size = vl_api_gtpu_tunnel_v2_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GTPU_TUNNEL_V2_DETAILS + msg_id_base,
  .name = "gtpu_tunnel_v2_details",
  .handler = 0,
  .endian = vl_api_gtpu_tunnel_v2_details_t_endian,
  .format_fn = vl_api_gtpu_tunnel_v2_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gtpu_tunnel_v2_details_t_tojson,
  .fromjson = vl_api_gtpu_tunnel_v2_details_t_fromjson,
  .calc_size = vl_api_gtpu_tunnel_v2_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_SET_GTPU_BYPASS + msg_id_base,
   .name = "sw_interface_set_gtpu_bypass",
   .handler = vl_api_sw_interface_set_gtpu_bypass_t_handler,
   .endian = vl_api_sw_interface_set_gtpu_bypass_t_endian,
   .format_fn = vl_api_sw_interface_set_gtpu_bypass_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_set_gtpu_bypass_t_tojson,
   .fromjson = vl_api_sw_interface_set_gtpu_bypass_t_fromjson,
   .calc_size = vl_api_sw_interface_set_gtpu_bypass_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_SET_GTPU_BYPASS_REPLY + msg_id_base,
  .name = "sw_interface_set_gtpu_bypass_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_set_gtpu_bypass_reply_t_endian,
  .format_fn = vl_api_sw_interface_set_gtpu_bypass_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_set_gtpu_bypass_reply_t_tojson,
  .fromjson = vl_api_sw_interface_set_gtpu_bypass_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_set_gtpu_bypass_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GTPU_OFFLOAD_RX + msg_id_base,
   .name = "gtpu_offload_rx",
   .handler = vl_api_gtpu_offload_rx_t_handler,
   .endian = vl_api_gtpu_offload_rx_t_endian,
   .format_fn = vl_api_gtpu_offload_rx_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gtpu_offload_rx_t_tojson,
   .fromjson = vl_api_gtpu_offload_rx_t_fromjson,
   .calc_size = vl_api_gtpu_offload_rx_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GTPU_OFFLOAD_RX_REPLY + msg_id_base,
  .name = "gtpu_offload_rx_reply",
  .handler = 0,
  .endian = vl_api_gtpu_offload_rx_reply_t_endian,
  .format_fn = vl_api_gtpu_offload_rx_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gtpu_offload_rx_reply_t_tojson,
  .fromjson = vl_api_gtpu_offload_rx_reply_t_fromjson,
  .calc_size = vl_api_gtpu_offload_rx_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GTPU_ADD_DEL_FORWARD + msg_id_base,
   .name = "gtpu_add_del_forward",
   .handler = vl_api_gtpu_add_del_forward_t_handler,
   .endian = vl_api_gtpu_add_del_forward_t_endian,
   .format_fn = vl_api_gtpu_add_del_forward_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gtpu_add_del_forward_t_tojson,
   .fromjson = vl_api_gtpu_add_del_forward_t_fromjson,
   .calc_size = vl_api_gtpu_add_del_forward_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GTPU_ADD_DEL_FORWARD_REPLY + msg_id_base,
  .name = "gtpu_add_del_forward_reply",
  .handler = 0,
  .endian = vl_api_gtpu_add_del_forward_reply_t_endian,
  .format_fn = vl_api_gtpu_add_del_forward_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gtpu_add_del_forward_reply_t_tojson,
  .fromjson = vl_api_gtpu_add_del_forward_reply_t_fromjson,
  .calc_size = vl_api_gtpu_add_del_forward_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GTPU_GET_TRANSFER_COUNTS + msg_id_base,
   .name = "gtpu_get_transfer_counts",
   .handler = vl_api_gtpu_get_transfer_counts_t_handler,
   .endian = vl_api_gtpu_get_transfer_counts_t_endian,
   .format_fn = vl_api_gtpu_get_transfer_counts_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_gtpu_get_transfer_counts_t_tojson,
   .fromjson = vl_api_gtpu_get_transfer_counts_t_fromjson,
   .calc_size = vl_api_gtpu_get_transfer_counts_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GTPU_GET_TRANSFER_COUNTS_REPLY + msg_id_base,
  .name = "gtpu_get_transfer_counts_reply",
  .handler = 0,
  .endian = vl_api_gtpu_get_transfer_counts_reply_t_endian,
  .format_fn = vl_api_gtpu_get_transfer_counts_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_gtpu_get_transfer_counts_reply_t_tojson,
  .fromjson = vl_api_gtpu_get_transfer_counts_reply_t_fromjson,
  .calc_size = vl_api_gtpu_get_transfer_counts_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
