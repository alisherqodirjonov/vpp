#define vl_endianfun		/* define message structures */
#include "wireguard.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "wireguard.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "wireguard.api.h"
#undef vl_printfun

#include "wireguard.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("wireguard_4f5c87aa", VL_MSG_WIREGUARD_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_wireguard);
   vl_msg_api_add_msg_name_crc (am, "wireguard_interface_create_a530137e",
                                VL_API_WIREGUARD_INTERFACE_CREATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "wireguard_interface_create_reply_5383d31f",
                                VL_API_WIREGUARD_INTERFACE_CREATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "wireguard_interface_delete_f9e6675e",
                                VL_API_WIREGUARD_INTERFACE_DELETE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "wireguard_interface_delete_reply_e8d4e804",
                                VL_API_WIREGUARD_INTERFACE_DELETE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "wireguard_interface_dump_2c954158",
                                VL_API_WIREGUARD_INTERFACE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "wireguard_interface_details_0dd4865d",
                                VL_API_WIREGUARD_INTERFACE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_wireguard_peer_events_3bc666c8",
                                VL_API_WANT_WIREGUARD_PEER_EVENTS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_wireguard_peer_events_reply_e8d4e804",
                                VL_API_WANT_WIREGUARD_PEER_EVENTS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "wireguard_peer_event_4e1b5d67",
                                VL_API_WIREGUARD_PEER_EVENT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "wireguard_peer_add_9b8aad61",
                                VL_API_WIREGUARD_PEER_ADD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "wireguard_peer_add_reply_084a0cd3",
                                VL_API_WIREGUARD_PEER_ADD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "wireguard_peer_remove_3b74607a",
                                VL_API_WIREGUARD_PEER_REMOVE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "wireguard_peer_remove_reply_e8d4e804",
                                VL_API_WIREGUARD_PEER_REMOVE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "wireguard_peers_dump_3b74607a",
                                VL_API_WIREGUARD_PEERS_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "wireguard_peers_details_6a9f6bc3",
                                VL_API_WIREGUARD_PEERS_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "wg_set_async_mode_a6465f7c",
                                VL_API_WG_SET_ASYNC_MODE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "wg_set_async_mode_reply_e8d4e804",
                                VL_API_WG_SET_ASYNC_MODE_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_WANT_WIREGUARD_PEER_EVENTS + msg_id_base,
   .name = "want_wireguard_peer_events",
   .handler = vl_api_want_wireguard_peer_events_t_handler,
   .endian = vl_api_want_wireguard_peer_events_t_endian,
   .format_fn = vl_api_want_wireguard_peer_events_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_want_wireguard_peer_events_t_tojson,
   .fromjson = vl_api_want_wireguard_peer_events_t_fromjson,
   .calc_size = vl_api_want_wireguard_peer_events_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_WANT_WIREGUARD_PEER_EVENTS_REPLY + msg_id_base,
  .name = "want_wireguard_peer_events_reply",
  .handler = 0,
  .endian = vl_api_want_wireguard_peer_events_reply_t_endian,
  .format_fn = vl_api_want_wireguard_peer_events_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_want_wireguard_peer_events_reply_t_tojson,
  .fromjson = vl_api_want_wireguard_peer_events_reply_t_fromjson,
  .calc_size = vl_api_want_wireguard_peer_events_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_WIREGUARD_INTERFACE_CREATE + msg_id_base,
   .name = "wireguard_interface_create",
   .handler = vl_api_wireguard_interface_create_t_handler,
   .endian = vl_api_wireguard_interface_create_t_endian,
   .format_fn = vl_api_wireguard_interface_create_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_wireguard_interface_create_t_tojson,
   .fromjson = vl_api_wireguard_interface_create_t_fromjson,
   .calc_size = vl_api_wireguard_interface_create_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_WIREGUARD_INTERFACE_CREATE_REPLY + msg_id_base,
  .name = "wireguard_interface_create_reply",
  .handler = 0,
  .endian = vl_api_wireguard_interface_create_reply_t_endian,
  .format_fn = vl_api_wireguard_interface_create_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_wireguard_interface_create_reply_t_tojson,
  .fromjson = vl_api_wireguard_interface_create_reply_t_fromjson,
  .calc_size = vl_api_wireguard_interface_create_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_WIREGUARD_INTERFACE_DELETE + msg_id_base,
   .name = "wireguard_interface_delete",
   .handler = vl_api_wireguard_interface_delete_t_handler,
   .endian = vl_api_wireguard_interface_delete_t_endian,
   .format_fn = vl_api_wireguard_interface_delete_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_wireguard_interface_delete_t_tojson,
   .fromjson = vl_api_wireguard_interface_delete_t_fromjson,
   .calc_size = vl_api_wireguard_interface_delete_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_WIREGUARD_INTERFACE_DELETE_REPLY + msg_id_base,
  .name = "wireguard_interface_delete_reply",
  .handler = 0,
  .endian = vl_api_wireguard_interface_delete_reply_t_endian,
  .format_fn = vl_api_wireguard_interface_delete_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_wireguard_interface_delete_reply_t_tojson,
  .fromjson = vl_api_wireguard_interface_delete_reply_t_fromjson,
  .calc_size = vl_api_wireguard_interface_delete_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_WIREGUARD_INTERFACE_DUMP + msg_id_base,
   .name = "wireguard_interface_dump",
   .handler = vl_api_wireguard_interface_dump_t_handler,
   .endian = vl_api_wireguard_interface_dump_t_endian,
   .format_fn = vl_api_wireguard_interface_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_wireguard_interface_dump_t_tojson,
   .fromjson = vl_api_wireguard_interface_dump_t_fromjson,
   .calc_size = vl_api_wireguard_interface_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_WIREGUARD_INTERFACE_DETAILS + msg_id_base,
  .name = "wireguard_interface_details",
  .handler = 0,
  .endian = vl_api_wireguard_interface_details_t_endian,
  .format_fn = vl_api_wireguard_interface_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_wireguard_interface_details_t_tojson,
  .fromjson = vl_api_wireguard_interface_details_t_fromjson,
  .calc_size = vl_api_wireguard_interface_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_WIREGUARD_PEER_ADD + msg_id_base,
   .name = "wireguard_peer_add",
   .handler = vl_api_wireguard_peer_add_t_handler,
   .endian = vl_api_wireguard_peer_add_t_endian,
   .format_fn = vl_api_wireguard_peer_add_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_wireguard_peer_add_t_tojson,
   .fromjson = vl_api_wireguard_peer_add_t_fromjson,
   .calc_size = vl_api_wireguard_peer_add_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_WIREGUARD_PEER_ADD_REPLY + msg_id_base,
  .name = "wireguard_peer_add_reply",
  .handler = 0,
  .endian = vl_api_wireguard_peer_add_reply_t_endian,
  .format_fn = vl_api_wireguard_peer_add_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_wireguard_peer_add_reply_t_tojson,
  .fromjson = vl_api_wireguard_peer_add_reply_t_fromjson,
  .calc_size = vl_api_wireguard_peer_add_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_WIREGUARD_PEER_REMOVE + msg_id_base,
   .name = "wireguard_peer_remove",
   .handler = vl_api_wireguard_peer_remove_t_handler,
   .endian = vl_api_wireguard_peer_remove_t_endian,
   .format_fn = vl_api_wireguard_peer_remove_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_wireguard_peer_remove_t_tojson,
   .fromjson = vl_api_wireguard_peer_remove_t_fromjson,
   .calc_size = vl_api_wireguard_peer_remove_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_WIREGUARD_PEER_REMOVE_REPLY + msg_id_base,
  .name = "wireguard_peer_remove_reply",
  .handler = 0,
  .endian = vl_api_wireguard_peer_remove_reply_t_endian,
  .format_fn = vl_api_wireguard_peer_remove_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_wireguard_peer_remove_reply_t_tojson,
  .fromjson = vl_api_wireguard_peer_remove_reply_t_fromjson,
  .calc_size = vl_api_wireguard_peer_remove_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_WIREGUARD_PEERS_DUMP + msg_id_base,
   .name = "wireguard_peers_dump",
   .handler = vl_api_wireguard_peers_dump_t_handler,
   .endian = vl_api_wireguard_peers_dump_t_endian,
   .format_fn = vl_api_wireguard_peers_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_wireguard_peers_dump_t_tojson,
   .fromjson = vl_api_wireguard_peers_dump_t_fromjson,
   .calc_size = vl_api_wireguard_peers_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_WIREGUARD_PEERS_DETAILS + msg_id_base,
  .name = "wireguard_peers_details",
  .handler = 0,
  .endian = vl_api_wireguard_peers_details_t_endian,
  .format_fn = vl_api_wireguard_peers_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_wireguard_peers_details_t_tojson,
  .fromjson = vl_api_wireguard_peers_details_t_fromjson,
  .calc_size = vl_api_wireguard_peers_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_WG_SET_ASYNC_MODE + msg_id_base,
   .name = "wg_set_async_mode",
   .handler = vl_api_wg_set_async_mode_t_handler,
   .endian = vl_api_wg_set_async_mode_t_endian,
   .format_fn = vl_api_wg_set_async_mode_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_wg_set_async_mode_t_tojson,
   .fromjson = vl_api_wg_set_async_mode_t_fromjson,
   .calc_size = vl_api_wg_set_async_mode_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_WG_SET_ASYNC_MODE_REPLY + msg_id_base,
  .name = "wg_set_async_mode_reply",
  .handler = 0,
  .endian = vl_api_wg_set_async_mode_reply_t_endian,
  .format_fn = vl_api_wg_set_async_mode_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_wg_set_async_mode_reply_t_tojson,
  .fromjson = vl_api_wg_set_async_mode_reply_t_fromjson,
  .calc_size = vl_api_wg_set_async_mode_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
