#define vl_endianfun		/* define message structures */
#include "vrrp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "vrrp.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "vrrp.api.h"
#undef vl_printfun

#include "vrrp.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("vrrp_488c32da", VL_MSG_VRRP_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_vrrp);
   vl_msg_api_add_msg_name_crc (am, "vrrp_vr_add_del_c5cf15aa",
                                VL_API_VRRP_VR_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vrrp_vr_add_del_reply_e8d4e804",
                                VL_API_VRRP_VR_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vrrp_vr_update_0b51e2f4",
                                VL_API_VRRP_VR_UPDATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vrrp_vr_update_reply_5317d608",
                                VL_API_VRRP_VR_UPDATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vrrp_vr_del_6029baa1",
                                VL_API_VRRP_VR_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vrrp_vr_del_reply_e8d4e804",
                                VL_API_VRRP_VR_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vrrp_vr_dump_f9e6675e",
                                VL_API_VRRP_VR_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vrrp_vr_details_46edcebd",
                                VL_API_VRRP_VR_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vrrp_vr_start_stop_0662a3b7",
                                VL_API_VRRP_VR_START_STOP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vrrp_vr_start_stop_reply_e8d4e804",
                                VL_API_VRRP_VR_START_STOP_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vrrp_vr_set_peers_20bec71f",
                                VL_API_VRRP_VR_SET_PEERS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vrrp_vr_set_peers_reply_e8d4e804",
                                VL_API_VRRP_VR_SET_PEERS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vrrp_vr_peer_dump_6fa3f7c4",
                                VL_API_VRRP_VR_PEER_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vrrp_vr_peer_details_3d99c108",
                                VL_API_VRRP_VR_PEER_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vrrp_vr_track_if_add_del_d67df299",
                                VL_API_VRRP_VR_TRACK_IF_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vrrp_vr_track_if_add_del_reply_e8d4e804",
                                VL_API_VRRP_VR_TRACK_IF_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vrrp_vr_track_if_dump_a34dfc6d",
                                VL_API_VRRP_VR_TRACK_IF_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vrrp_vr_track_if_details_73c36f81",
                                VL_API_VRRP_VR_TRACK_IF_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "vrrp_vr_event_c1fea6a5",
                                VL_API_VRRP_VR_EVENT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_vrrp_vr_events_c5e2af94",
                                VL_API_WANT_VRRP_VR_EVENTS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_vrrp_vr_events_reply_e8d4e804",
                                VL_API_WANT_VRRP_VR_EVENTS_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_WANT_VRRP_VR_EVENTS + msg_id_base,
   .name = "want_vrrp_vr_events",
   .handler = vl_api_want_vrrp_vr_events_t_handler,
   .endian = vl_api_want_vrrp_vr_events_t_endian,
   .format_fn = vl_api_want_vrrp_vr_events_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_want_vrrp_vr_events_t_tojson,
   .fromjson = vl_api_want_vrrp_vr_events_t_fromjson,
   .calc_size = vl_api_want_vrrp_vr_events_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_WANT_VRRP_VR_EVENTS_REPLY + msg_id_base,
  .name = "want_vrrp_vr_events_reply",
  .handler = 0,
  .endian = vl_api_want_vrrp_vr_events_reply_t_endian,
  .format_fn = vl_api_want_vrrp_vr_events_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_want_vrrp_vr_events_reply_t_tojson,
  .fromjson = vl_api_want_vrrp_vr_events_reply_t_fromjson,
  .calc_size = vl_api_want_vrrp_vr_events_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VRRP_VR_ADD_DEL + msg_id_base,
   .name = "vrrp_vr_add_del",
   .handler = vl_api_vrrp_vr_add_del_t_handler,
   .endian = vl_api_vrrp_vr_add_del_t_endian,
   .format_fn = vl_api_vrrp_vr_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_vrrp_vr_add_del_t_tojson,
   .fromjson = vl_api_vrrp_vr_add_del_t_fromjson,
   .calc_size = vl_api_vrrp_vr_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VRRP_VR_ADD_DEL_REPLY + msg_id_base,
  .name = "vrrp_vr_add_del_reply",
  .handler = 0,
  .endian = vl_api_vrrp_vr_add_del_reply_t_endian,
  .format_fn = vl_api_vrrp_vr_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_vrrp_vr_add_del_reply_t_tojson,
  .fromjson = vl_api_vrrp_vr_add_del_reply_t_fromjson,
  .calc_size = vl_api_vrrp_vr_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VRRP_VR_UPDATE + msg_id_base,
   .name = "vrrp_vr_update",
   .handler = vl_api_vrrp_vr_update_t_handler,
   .endian = vl_api_vrrp_vr_update_t_endian,
   .format_fn = vl_api_vrrp_vr_update_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_vrrp_vr_update_t_tojson,
   .fromjson = vl_api_vrrp_vr_update_t_fromjson,
   .calc_size = vl_api_vrrp_vr_update_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VRRP_VR_UPDATE_REPLY + msg_id_base,
  .name = "vrrp_vr_update_reply",
  .handler = 0,
  .endian = vl_api_vrrp_vr_update_reply_t_endian,
  .format_fn = vl_api_vrrp_vr_update_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_vrrp_vr_update_reply_t_tojson,
  .fromjson = vl_api_vrrp_vr_update_reply_t_fromjson,
  .calc_size = vl_api_vrrp_vr_update_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VRRP_VR_DEL + msg_id_base,
   .name = "vrrp_vr_del",
   .handler = vl_api_vrrp_vr_del_t_handler,
   .endian = vl_api_vrrp_vr_del_t_endian,
   .format_fn = vl_api_vrrp_vr_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_vrrp_vr_del_t_tojson,
   .fromjson = vl_api_vrrp_vr_del_t_fromjson,
   .calc_size = vl_api_vrrp_vr_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VRRP_VR_DEL_REPLY + msg_id_base,
  .name = "vrrp_vr_del_reply",
  .handler = 0,
  .endian = vl_api_vrrp_vr_del_reply_t_endian,
  .format_fn = vl_api_vrrp_vr_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_vrrp_vr_del_reply_t_tojson,
  .fromjson = vl_api_vrrp_vr_del_reply_t_fromjson,
  .calc_size = vl_api_vrrp_vr_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VRRP_VR_DUMP + msg_id_base,
   .name = "vrrp_vr_dump",
   .handler = vl_api_vrrp_vr_dump_t_handler,
   .endian = vl_api_vrrp_vr_dump_t_endian,
   .format_fn = vl_api_vrrp_vr_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_vrrp_vr_dump_t_tojson,
   .fromjson = vl_api_vrrp_vr_dump_t_fromjson,
   .calc_size = vl_api_vrrp_vr_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VRRP_VR_DETAILS + msg_id_base,
  .name = "vrrp_vr_details",
  .handler = 0,
  .endian = vl_api_vrrp_vr_details_t_endian,
  .format_fn = vl_api_vrrp_vr_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_vrrp_vr_details_t_tojson,
  .fromjson = vl_api_vrrp_vr_details_t_fromjson,
  .calc_size = vl_api_vrrp_vr_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VRRP_VR_START_STOP + msg_id_base,
   .name = "vrrp_vr_start_stop",
   .handler = vl_api_vrrp_vr_start_stop_t_handler,
   .endian = vl_api_vrrp_vr_start_stop_t_endian,
   .format_fn = vl_api_vrrp_vr_start_stop_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_vrrp_vr_start_stop_t_tojson,
   .fromjson = vl_api_vrrp_vr_start_stop_t_fromjson,
   .calc_size = vl_api_vrrp_vr_start_stop_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VRRP_VR_START_STOP_REPLY + msg_id_base,
  .name = "vrrp_vr_start_stop_reply",
  .handler = 0,
  .endian = vl_api_vrrp_vr_start_stop_reply_t_endian,
  .format_fn = vl_api_vrrp_vr_start_stop_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_vrrp_vr_start_stop_reply_t_tojson,
  .fromjson = vl_api_vrrp_vr_start_stop_reply_t_fromjson,
  .calc_size = vl_api_vrrp_vr_start_stop_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VRRP_VR_SET_PEERS + msg_id_base,
   .name = "vrrp_vr_set_peers",
   .handler = vl_api_vrrp_vr_set_peers_t_handler,
   .endian = vl_api_vrrp_vr_set_peers_t_endian,
   .format_fn = vl_api_vrrp_vr_set_peers_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_vrrp_vr_set_peers_t_tojson,
   .fromjson = vl_api_vrrp_vr_set_peers_t_fromjson,
   .calc_size = vl_api_vrrp_vr_set_peers_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VRRP_VR_SET_PEERS_REPLY + msg_id_base,
  .name = "vrrp_vr_set_peers_reply",
  .handler = 0,
  .endian = vl_api_vrrp_vr_set_peers_reply_t_endian,
  .format_fn = vl_api_vrrp_vr_set_peers_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_vrrp_vr_set_peers_reply_t_tojson,
  .fromjson = vl_api_vrrp_vr_set_peers_reply_t_fromjson,
  .calc_size = vl_api_vrrp_vr_set_peers_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VRRP_VR_PEER_DUMP + msg_id_base,
   .name = "vrrp_vr_peer_dump",
   .handler = vl_api_vrrp_vr_peer_dump_t_handler,
   .endian = vl_api_vrrp_vr_peer_dump_t_endian,
   .format_fn = vl_api_vrrp_vr_peer_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_vrrp_vr_peer_dump_t_tojson,
   .fromjson = vl_api_vrrp_vr_peer_dump_t_fromjson,
   .calc_size = vl_api_vrrp_vr_peer_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VRRP_VR_PEER_DETAILS + msg_id_base,
  .name = "vrrp_vr_peer_details",
  .handler = 0,
  .endian = vl_api_vrrp_vr_peer_details_t_endian,
  .format_fn = vl_api_vrrp_vr_peer_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_vrrp_vr_peer_details_t_tojson,
  .fromjson = vl_api_vrrp_vr_peer_details_t_fromjson,
  .calc_size = vl_api_vrrp_vr_peer_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VRRP_VR_TRACK_IF_ADD_DEL + msg_id_base,
   .name = "vrrp_vr_track_if_add_del",
   .handler = vl_api_vrrp_vr_track_if_add_del_t_handler,
   .endian = vl_api_vrrp_vr_track_if_add_del_t_endian,
   .format_fn = vl_api_vrrp_vr_track_if_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_vrrp_vr_track_if_add_del_t_tojson,
   .fromjson = vl_api_vrrp_vr_track_if_add_del_t_fromjson,
   .calc_size = vl_api_vrrp_vr_track_if_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VRRP_VR_TRACK_IF_ADD_DEL_REPLY + msg_id_base,
  .name = "vrrp_vr_track_if_add_del_reply",
  .handler = 0,
  .endian = vl_api_vrrp_vr_track_if_add_del_reply_t_endian,
  .format_fn = vl_api_vrrp_vr_track_if_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_vrrp_vr_track_if_add_del_reply_t_tojson,
  .fromjson = vl_api_vrrp_vr_track_if_add_del_reply_t_fromjson,
  .calc_size = vl_api_vrrp_vr_track_if_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_VRRP_VR_TRACK_IF_DUMP + msg_id_base,
   .name = "vrrp_vr_track_if_dump",
   .handler = vl_api_vrrp_vr_track_if_dump_t_handler,
   .endian = vl_api_vrrp_vr_track_if_dump_t_endian,
   .format_fn = vl_api_vrrp_vr_track_if_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_vrrp_vr_track_if_dump_t_tojson,
   .fromjson = vl_api_vrrp_vr_track_if_dump_t_fromjson,
   .calc_size = vl_api_vrrp_vr_track_if_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_VRRP_VR_TRACK_IF_DETAILS + msg_id_base,
  .name = "vrrp_vr_track_if_details",
  .handler = 0,
  .endian = vl_api_vrrp_vr_track_if_details_t_endian,
  .format_fn = vl_api_vrrp_vr_track_if_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_vrrp_vr_track_if_details_t_tojson,
  .fromjson = vl_api_vrrp_vr_track_if_details_t_fromjson,
  .calc_size = vl_api_vrrp_vr_track_if_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
