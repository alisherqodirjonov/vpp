#define vl_endianfun		/* define message structures */
#include "bfd.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "bfd.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "bfd.api.h"
#undef vl_printfun

#include "bfd.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("bfd_3cb0ce20", VL_MSG_BFD_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_bfd);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_set_echo_source_f9e6675e",
                                VL_API_BFD_UDP_SET_ECHO_SOURCE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_set_echo_source_reply_e8d4e804",
                                VL_API_BFD_UDP_SET_ECHO_SOURCE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_del_echo_source_51077d14",
                                VL_API_BFD_UDP_DEL_ECHO_SOURCE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_del_echo_source_reply_e8d4e804",
                                VL_API_BFD_UDP_DEL_ECHO_SOURCE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_get_echo_source_51077d14",
                                VL_API_BFD_UDP_GET_ECHO_SOURCE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_get_echo_source_reply_e3d736a1",
                                VL_API_BFD_UDP_GET_ECHO_SOURCE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_add_939cd26a",
                                VL_API_BFD_UDP_ADD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_add_reply_e8d4e804",
                                VL_API_BFD_UDP_ADD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_upd_939cd26a",
                                VL_API_BFD_UDP_UPD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_upd_reply_1992deab",
                                VL_API_BFD_UDP_UPD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_mod_913df085",
                                VL_API_BFD_UDP_MOD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_mod_reply_e8d4e804",
                                VL_API_BFD_UDP_MOD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_del_dcb13a89",
                                VL_API_BFD_UDP_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_del_reply_e8d4e804",
                                VL_API_BFD_UDP_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_session_dump_51077d14",
                                VL_API_BFD_UDP_SESSION_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_session_details_09fb2f2d",
                                VL_API_BFD_UDP_SESSION_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_session_set_flags_04b4bdfd",
                                VL_API_BFD_UDP_SESSION_SET_FLAGS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_session_set_flags_reply_e8d4e804",
                                VL_API_BFD_UDP_SESSION_SET_FLAGS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_bfd_events_c5e2af94",
                                VL_API_WANT_BFD_EVENTS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_bfd_events_reply_e8d4e804",
                                VL_API_WANT_BFD_EVENTS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_session_event_8eaaf062",
                                VL_API_BFD_UDP_SESSION_EVENT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_auth_set_key_690b8877",
                                VL_API_BFD_AUTH_SET_KEY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_auth_set_key_reply_e8d4e804",
                                VL_API_BFD_AUTH_SET_KEY_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_auth_del_key_65310b22",
                                VL_API_BFD_AUTH_DEL_KEY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_auth_del_key_reply_e8d4e804",
                                VL_API_BFD_AUTH_DEL_KEY_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_auth_keys_dump_51077d14",
                                VL_API_BFD_AUTH_KEYS_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_auth_keys_details_84130e9f",
                                VL_API_BFD_AUTH_KEYS_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_auth_activate_21fd1bdb",
                                VL_API_BFD_UDP_AUTH_ACTIVATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_auth_activate_reply_e8d4e804",
                                VL_API_BFD_UDP_AUTH_ACTIVATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_auth_deactivate_9a05e2e0",
                                VL_API_BFD_UDP_AUTH_DEACTIVATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_auth_deactivate_reply_e8d4e804",
                                VL_API_BFD_UDP_AUTH_DEACTIVATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_enable_multihop_51077d14",
                                VL_API_BFD_UDP_ENABLE_MULTIHOP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_enable_multihop_reply_e8d4e804",
                                VL_API_BFD_UDP_ENABLE_MULTIHOP_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_set_tos_00fe25ce",
                                VL_API_BFD_UDP_SET_TOS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_set_tos_reply_e8d4e804",
                                VL_API_BFD_UDP_SET_TOS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_get_tos_51077d14",
                                VL_API_BFD_UDP_GET_TOS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bfd_udp_get_tos_reply_d8931abf",
                                VL_API_BFD_UDP_GET_TOS_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_WANT_BFD_EVENTS + msg_id_base,
   .name = "want_bfd_events",
   .handler = vl_api_want_bfd_events_t_handler,
   .endian = vl_api_want_bfd_events_t_endian,
   .format_fn = vl_api_want_bfd_events_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_want_bfd_events_t_tojson,
   .fromjson = vl_api_want_bfd_events_t_fromjson,
   .calc_size = vl_api_want_bfd_events_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_WANT_BFD_EVENTS_REPLY + msg_id_base,
  .name = "want_bfd_events_reply",
  .handler = 0,
  .endian = vl_api_want_bfd_events_reply_t_endian,
  .format_fn = vl_api_want_bfd_events_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_want_bfd_events_reply_t_tojson,
  .fromjson = vl_api_want_bfd_events_reply_t_fromjson,
  .calc_size = vl_api_want_bfd_events_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BFD_UDP_SET_ECHO_SOURCE + msg_id_base,
   .name = "bfd_udp_set_echo_source",
   .handler = vl_api_bfd_udp_set_echo_source_t_handler,
   .endian = vl_api_bfd_udp_set_echo_source_t_endian,
   .format_fn = vl_api_bfd_udp_set_echo_source_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bfd_udp_set_echo_source_t_tojson,
   .fromjson = vl_api_bfd_udp_set_echo_source_t_fromjson,
   .calc_size = vl_api_bfd_udp_set_echo_source_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BFD_UDP_SET_ECHO_SOURCE_REPLY + msg_id_base,
  .name = "bfd_udp_set_echo_source_reply",
  .handler = 0,
  .endian = vl_api_bfd_udp_set_echo_source_reply_t_endian,
  .format_fn = vl_api_bfd_udp_set_echo_source_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bfd_udp_set_echo_source_reply_t_tojson,
  .fromjson = vl_api_bfd_udp_set_echo_source_reply_t_fromjson,
  .calc_size = vl_api_bfd_udp_set_echo_source_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BFD_UDP_DEL_ECHO_SOURCE + msg_id_base,
   .name = "bfd_udp_del_echo_source",
   .handler = vl_api_bfd_udp_del_echo_source_t_handler,
   .endian = vl_api_bfd_udp_del_echo_source_t_endian,
   .format_fn = vl_api_bfd_udp_del_echo_source_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bfd_udp_del_echo_source_t_tojson,
   .fromjson = vl_api_bfd_udp_del_echo_source_t_fromjson,
   .calc_size = vl_api_bfd_udp_del_echo_source_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BFD_UDP_DEL_ECHO_SOURCE_REPLY + msg_id_base,
  .name = "bfd_udp_del_echo_source_reply",
  .handler = 0,
  .endian = vl_api_bfd_udp_del_echo_source_reply_t_endian,
  .format_fn = vl_api_bfd_udp_del_echo_source_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bfd_udp_del_echo_source_reply_t_tojson,
  .fromjson = vl_api_bfd_udp_del_echo_source_reply_t_fromjson,
  .calc_size = vl_api_bfd_udp_del_echo_source_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BFD_UDP_GET_ECHO_SOURCE + msg_id_base,
   .name = "bfd_udp_get_echo_source",
   .handler = vl_api_bfd_udp_get_echo_source_t_handler,
   .endian = vl_api_bfd_udp_get_echo_source_t_endian,
   .format_fn = vl_api_bfd_udp_get_echo_source_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bfd_udp_get_echo_source_t_tojson,
   .fromjson = vl_api_bfd_udp_get_echo_source_t_fromjson,
   .calc_size = vl_api_bfd_udp_get_echo_source_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BFD_UDP_GET_ECHO_SOURCE_REPLY + msg_id_base,
  .name = "bfd_udp_get_echo_source_reply",
  .handler = 0,
  .endian = vl_api_bfd_udp_get_echo_source_reply_t_endian,
  .format_fn = vl_api_bfd_udp_get_echo_source_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bfd_udp_get_echo_source_reply_t_tojson,
  .fromjson = vl_api_bfd_udp_get_echo_source_reply_t_fromjson,
  .calc_size = vl_api_bfd_udp_get_echo_source_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BFD_UDP_ADD + msg_id_base,
   .name = "bfd_udp_add",
   .handler = vl_api_bfd_udp_add_t_handler,
   .endian = vl_api_bfd_udp_add_t_endian,
   .format_fn = vl_api_bfd_udp_add_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bfd_udp_add_t_tojson,
   .fromjson = vl_api_bfd_udp_add_t_fromjson,
   .calc_size = vl_api_bfd_udp_add_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BFD_UDP_ADD_REPLY + msg_id_base,
  .name = "bfd_udp_add_reply",
  .handler = 0,
  .endian = vl_api_bfd_udp_add_reply_t_endian,
  .format_fn = vl_api_bfd_udp_add_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bfd_udp_add_reply_t_tojson,
  .fromjson = vl_api_bfd_udp_add_reply_t_fromjson,
  .calc_size = vl_api_bfd_udp_add_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BFD_UDP_UPD + msg_id_base,
   .name = "bfd_udp_upd",
   .handler = vl_api_bfd_udp_upd_t_handler,
   .endian = vl_api_bfd_udp_upd_t_endian,
   .format_fn = vl_api_bfd_udp_upd_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bfd_udp_upd_t_tojson,
   .fromjson = vl_api_bfd_udp_upd_t_fromjson,
   .calc_size = vl_api_bfd_udp_upd_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BFD_UDP_UPD_REPLY + msg_id_base,
  .name = "bfd_udp_upd_reply",
  .handler = 0,
  .endian = vl_api_bfd_udp_upd_reply_t_endian,
  .format_fn = vl_api_bfd_udp_upd_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bfd_udp_upd_reply_t_tojson,
  .fromjson = vl_api_bfd_udp_upd_reply_t_fromjson,
  .calc_size = vl_api_bfd_udp_upd_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BFD_UDP_MOD + msg_id_base,
   .name = "bfd_udp_mod",
   .handler = vl_api_bfd_udp_mod_t_handler,
   .endian = vl_api_bfd_udp_mod_t_endian,
   .format_fn = vl_api_bfd_udp_mod_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bfd_udp_mod_t_tojson,
   .fromjson = vl_api_bfd_udp_mod_t_fromjson,
   .calc_size = vl_api_bfd_udp_mod_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BFD_UDP_MOD_REPLY + msg_id_base,
  .name = "bfd_udp_mod_reply",
  .handler = 0,
  .endian = vl_api_bfd_udp_mod_reply_t_endian,
  .format_fn = vl_api_bfd_udp_mod_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bfd_udp_mod_reply_t_tojson,
  .fromjson = vl_api_bfd_udp_mod_reply_t_fromjson,
  .calc_size = vl_api_bfd_udp_mod_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BFD_UDP_DEL + msg_id_base,
   .name = "bfd_udp_del",
   .handler = vl_api_bfd_udp_del_t_handler,
   .endian = vl_api_bfd_udp_del_t_endian,
   .format_fn = vl_api_bfd_udp_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bfd_udp_del_t_tojson,
   .fromjson = vl_api_bfd_udp_del_t_fromjson,
   .calc_size = vl_api_bfd_udp_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BFD_UDP_DEL_REPLY + msg_id_base,
  .name = "bfd_udp_del_reply",
  .handler = 0,
  .endian = vl_api_bfd_udp_del_reply_t_endian,
  .format_fn = vl_api_bfd_udp_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bfd_udp_del_reply_t_tojson,
  .fromjson = vl_api_bfd_udp_del_reply_t_fromjson,
  .calc_size = vl_api_bfd_udp_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BFD_UDP_SESSION_DUMP + msg_id_base,
   .name = "bfd_udp_session_dump",
   .handler = vl_api_bfd_udp_session_dump_t_handler,
   .endian = vl_api_bfd_udp_session_dump_t_endian,
   .format_fn = vl_api_bfd_udp_session_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bfd_udp_session_dump_t_tojson,
   .fromjson = vl_api_bfd_udp_session_dump_t_fromjson,
   .calc_size = vl_api_bfd_udp_session_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BFD_UDP_SESSION_DETAILS + msg_id_base,
  .name = "bfd_udp_session_details",
  .handler = 0,
  .endian = vl_api_bfd_udp_session_details_t_endian,
  .format_fn = vl_api_bfd_udp_session_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bfd_udp_session_details_t_tojson,
  .fromjson = vl_api_bfd_udp_session_details_t_fromjson,
  .calc_size = vl_api_bfd_udp_session_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BFD_UDP_SESSION_SET_FLAGS + msg_id_base,
   .name = "bfd_udp_session_set_flags",
   .handler = vl_api_bfd_udp_session_set_flags_t_handler,
   .endian = vl_api_bfd_udp_session_set_flags_t_endian,
   .format_fn = vl_api_bfd_udp_session_set_flags_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bfd_udp_session_set_flags_t_tojson,
   .fromjson = vl_api_bfd_udp_session_set_flags_t_fromjson,
   .calc_size = vl_api_bfd_udp_session_set_flags_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BFD_UDP_SESSION_SET_FLAGS_REPLY + msg_id_base,
  .name = "bfd_udp_session_set_flags_reply",
  .handler = 0,
  .endian = vl_api_bfd_udp_session_set_flags_reply_t_endian,
  .format_fn = vl_api_bfd_udp_session_set_flags_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bfd_udp_session_set_flags_reply_t_tojson,
  .fromjson = vl_api_bfd_udp_session_set_flags_reply_t_fromjson,
  .calc_size = vl_api_bfd_udp_session_set_flags_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BFD_AUTH_SET_KEY + msg_id_base,
   .name = "bfd_auth_set_key",
   .handler = vl_api_bfd_auth_set_key_t_handler,
   .endian = vl_api_bfd_auth_set_key_t_endian,
   .format_fn = vl_api_bfd_auth_set_key_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bfd_auth_set_key_t_tojson,
   .fromjson = vl_api_bfd_auth_set_key_t_fromjson,
   .calc_size = vl_api_bfd_auth_set_key_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BFD_AUTH_SET_KEY_REPLY + msg_id_base,
  .name = "bfd_auth_set_key_reply",
  .handler = 0,
  .endian = vl_api_bfd_auth_set_key_reply_t_endian,
  .format_fn = vl_api_bfd_auth_set_key_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bfd_auth_set_key_reply_t_tojson,
  .fromjson = vl_api_bfd_auth_set_key_reply_t_fromjson,
  .calc_size = vl_api_bfd_auth_set_key_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BFD_AUTH_DEL_KEY + msg_id_base,
   .name = "bfd_auth_del_key",
   .handler = vl_api_bfd_auth_del_key_t_handler,
   .endian = vl_api_bfd_auth_del_key_t_endian,
   .format_fn = vl_api_bfd_auth_del_key_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bfd_auth_del_key_t_tojson,
   .fromjson = vl_api_bfd_auth_del_key_t_fromjson,
   .calc_size = vl_api_bfd_auth_del_key_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BFD_AUTH_DEL_KEY_REPLY + msg_id_base,
  .name = "bfd_auth_del_key_reply",
  .handler = 0,
  .endian = vl_api_bfd_auth_del_key_reply_t_endian,
  .format_fn = vl_api_bfd_auth_del_key_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bfd_auth_del_key_reply_t_tojson,
  .fromjson = vl_api_bfd_auth_del_key_reply_t_fromjson,
  .calc_size = vl_api_bfd_auth_del_key_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BFD_AUTH_KEYS_DUMP + msg_id_base,
   .name = "bfd_auth_keys_dump",
   .handler = vl_api_bfd_auth_keys_dump_t_handler,
   .endian = vl_api_bfd_auth_keys_dump_t_endian,
   .format_fn = vl_api_bfd_auth_keys_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bfd_auth_keys_dump_t_tojson,
   .fromjson = vl_api_bfd_auth_keys_dump_t_fromjson,
   .calc_size = vl_api_bfd_auth_keys_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BFD_AUTH_KEYS_DETAILS + msg_id_base,
  .name = "bfd_auth_keys_details",
  .handler = 0,
  .endian = vl_api_bfd_auth_keys_details_t_endian,
  .format_fn = vl_api_bfd_auth_keys_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bfd_auth_keys_details_t_tojson,
  .fromjson = vl_api_bfd_auth_keys_details_t_fromjson,
  .calc_size = vl_api_bfd_auth_keys_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BFD_UDP_AUTH_ACTIVATE + msg_id_base,
   .name = "bfd_udp_auth_activate",
   .handler = vl_api_bfd_udp_auth_activate_t_handler,
   .endian = vl_api_bfd_udp_auth_activate_t_endian,
   .format_fn = vl_api_bfd_udp_auth_activate_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bfd_udp_auth_activate_t_tojson,
   .fromjson = vl_api_bfd_udp_auth_activate_t_fromjson,
   .calc_size = vl_api_bfd_udp_auth_activate_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BFD_UDP_AUTH_ACTIVATE_REPLY + msg_id_base,
  .name = "bfd_udp_auth_activate_reply",
  .handler = 0,
  .endian = vl_api_bfd_udp_auth_activate_reply_t_endian,
  .format_fn = vl_api_bfd_udp_auth_activate_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bfd_udp_auth_activate_reply_t_tojson,
  .fromjson = vl_api_bfd_udp_auth_activate_reply_t_fromjson,
  .calc_size = vl_api_bfd_udp_auth_activate_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BFD_UDP_AUTH_DEACTIVATE + msg_id_base,
   .name = "bfd_udp_auth_deactivate",
   .handler = vl_api_bfd_udp_auth_deactivate_t_handler,
   .endian = vl_api_bfd_udp_auth_deactivate_t_endian,
   .format_fn = vl_api_bfd_udp_auth_deactivate_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bfd_udp_auth_deactivate_t_tojson,
   .fromjson = vl_api_bfd_udp_auth_deactivate_t_fromjson,
   .calc_size = vl_api_bfd_udp_auth_deactivate_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BFD_UDP_AUTH_DEACTIVATE_REPLY + msg_id_base,
  .name = "bfd_udp_auth_deactivate_reply",
  .handler = 0,
  .endian = vl_api_bfd_udp_auth_deactivate_reply_t_endian,
  .format_fn = vl_api_bfd_udp_auth_deactivate_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bfd_udp_auth_deactivate_reply_t_tojson,
  .fromjson = vl_api_bfd_udp_auth_deactivate_reply_t_fromjson,
  .calc_size = vl_api_bfd_udp_auth_deactivate_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BFD_UDP_ENABLE_MULTIHOP + msg_id_base,
   .name = "bfd_udp_enable_multihop",
   .handler = vl_api_bfd_udp_enable_multihop_t_handler,
   .endian = vl_api_bfd_udp_enable_multihop_t_endian,
   .format_fn = vl_api_bfd_udp_enable_multihop_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bfd_udp_enable_multihop_t_tojson,
   .fromjson = vl_api_bfd_udp_enable_multihop_t_fromjson,
   .calc_size = vl_api_bfd_udp_enable_multihop_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BFD_UDP_ENABLE_MULTIHOP_REPLY + msg_id_base,
  .name = "bfd_udp_enable_multihop_reply",
  .handler = 0,
  .endian = vl_api_bfd_udp_enable_multihop_reply_t_endian,
  .format_fn = vl_api_bfd_udp_enable_multihop_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bfd_udp_enable_multihop_reply_t_tojson,
  .fromjson = vl_api_bfd_udp_enable_multihop_reply_t_fromjson,
  .calc_size = vl_api_bfd_udp_enable_multihop_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BFD_UDP_SET_TOS + msg_id_base,
   .name = "bfd_udp_set_tos",
   .handler = vl_api_bfd_udp_set_tos_t_handler,
   .endian = vl_api_bfd_udp_set_tos_t_endian,
   .format_fn = vl_api_bfd_udp_set_tos_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bfd_udp_set_tos_t_tojson,
   .fromjson = vl_api_bfd_udp_set_tos_t_fromjson,
   .calc_size = vl_api_bfd_udp_set_tos_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BFD_UDP_SET_TOS_REPLY + msg_id_base,
  .name = "bfd_udp_set_tos_reply",
  .handler = 0,
  .endian = vl_api_bfd_udp_set_tos_reply_t_endian,
  .format_fn = vl_api_bfd_udp_set_tos_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bfd_udp_set_tos_reply_t_tojson,
  .fromjson = vl_api_bfd_udp_set_tos_reply_t_fromjson,
  .calc_size = vl_api_bfd_udp_set_tos_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BFD_UDP_GET_TOS + msg_id_base,
   .name = "bfd_udp_get_tos",
   .handler = vl_api_bfd_udp_get_tos_t_handler,
   .endian = vl_api_bfd_udp_get_tos_t_endian,
   .format_fn = vl_api_bfd_udp_get_tos_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bfd_udp_get_tos_t_tojson,
   .fromjson = vl_api_bfd_udp_get_tos_t_fromjson,
   .calc_size = vl_api_bfd_udp_get_tos_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BFD_UDP_GET_TOS_REPLY + msg_id_base,
  .name = "bfd_udp_get_tos_reply",
  .handler = 0,
  .endian = vl_api_bfd_udp_get_tos_reply_t_endian,
  .format_fn = vl_api_bfd_udp_get_tos_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bfd_udp_get_tos_reply_t_tojson,
  .fromjson = vl_api_bfd_udp_get_tos_reply_t_fromjson,
  .calc_size = vl_api_bfd_udp_get_tos_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
vlib_error_desc_t bfd_udp_error_counters[] = {
  {
   .name = "none",
   .desc = "OK",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "bad",
   .desc = "bad packet",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "disabled",
   .desc = "bfd packets received on disabled interfaces",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "version",
   .desc = "version",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "length",
   .desc = "too short",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "detect_multi",
   .desc = "detect-multi",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "multi_point",
   .desc = "multi-point",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "my_disc",
   .desc = "my-disc",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "your_disc",
   .desc = "your-disc",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "admin_down",
   .desc = "session admin-down",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "no_session",
   .desc = "no-session",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "failed_verification",
   .desc = "failed-verification",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "src_mismatch",
   .desc = "src-mismatch",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "dst_mismatch",
   .desc = "dst-mismatch",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "ttl",
   .desc = "ttl",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
};
