#define vl_endianfun		/* define message structures */
#include "session.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "session.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "session.api.h"
#undef vl_printfun

#include "session.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("session_af947b64", VL_MSG_SESSION_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_session);
   vl_msg_api_add_msg_name_crc (am, "app_attach_5f4a260d",
                                VL_API_APP_ATTACH + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "app_attach_reply_5c89c3b0",
                                VL_API_APP_ATTACH_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "application_detach_51077d14",
                                VL_API_APPLICATION_DETACH + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "application_detach_reply_e8d4e804",
                                VL_API_APPLICATION_DETACH_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "app_add_cert_key_pair_02eb8016",
                                VL_API_APP_ADD_CERT_KEY_PAIR + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "app_add_cert_key_pair_reply_b42958d0",
                                VL_API_APP_ADD_CERT_KEY_PAIR_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "app_del_cert_key_pair_8ac76db6",
                                VL_API_APP_DEL_CERT_KEY_PAIR + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "app_del_cert_key_pair_reply_e8d4e804",
                                VL_API_APP_DEL_CERT_KEY_PAIR_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "app_worker_add_del_753253dc",
                                VL_API_APP_WORKER_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "app_worker_add_del_reply_5735ffe7",
                                VL_API_APP_WORKER_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_enable_disable_c264d7bf",
                                VL_API_SESSION_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_enable_disable_reply_e8d4e804",
                                VL_API_SESSION_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_enable_disable_v2_f09fbf32",
                                VL_API_SESSION_ENABLE_DISABLE_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_enable_disable_v2_reply_e8d4e804",
                                VL_API_SESSION_ENABLE_DISABLE_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_sapi_enable_disable_c264d7bf",
                                VL_API_SESSION_SAPI_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_sapi_enable_disable_reply_e8d4e804",
                                VL_API_SESSION_SAPI_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "app_namespace_add_del_6306aecb",
                                VL_API_APP_NAMESPACE_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "app_namespace_add_del_v4_42c1d824",
                                VL_API_APP_NAMESPACE_ADD_DEL_V4 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "app_namespace_add_del_v4_reply_85137120",
                                VL_API_APP_NAMESPACE_ADD_DEL_V4_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "app_namespace_add_del_v2_ee0755cf",
                                VL_API_APP_NAMESPACE_ADD_DEL_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "app_namespace_add_del_v3_8a7e40a1",
                                VL_API_APP_NAMESPACE_ADD_DEL_V3 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "app_namespace_add_del_reply_85137120",
                                VL_API_APP_NAMESPACE_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "app_namespace_add_del_v2_reply_85137120",
                                VL_API_APP_NAMESPACE_ADD_DEL_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "app_namespace_add_del_v3_reply_85137120",
                                VL_API_APP_NAMESPACE_ADD_DEL_V3_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_rule_add_del_82a90af5",
                                VL_API_SESSION_RULE_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_rule_add_del_reply_e8d4e804",
                                VL_API_SESSION_RULE_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_rules_dump_51077d14",
                                VL_API_SESSION_RULES_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_rules_details_4ef746e7",
                                VL_API_SESSION_RULES_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_rules_v2_dump_51077d14",
                                VL_API_SESSION_RULES_V2_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_rules_v2_details_f91993dc",
                                VL_API_SESSION_RULES_V2_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_sdl_add_del_faeb89fc",
                                VL_API_SESSION_SDL_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_sdl_add_del_reply_e8d4e804",
                                VL_API_SESSION_SDL_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_sdl_add_del_v2_7f89d3fa",
                                VL_API_SESSION_SDL_ADD_DEL_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_sdl_add_del_v2_reply_e8d4e804",
                                VL_API_SESSION_SDL_ADD_DEL_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_sdl_dump_51077d14",
                                VL_API_SESSION_SDL_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_sdl_details_9a8ef5d0",
                                VL_API_SESSION_SDL_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_sdl_v2_dump_51077d14",
                                VL_API_SESSION_SDL_V2_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_sdl_v2_details_0a057683",
                                VL_API_SESSION_SDL_V2_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_sdl_v3_dump_51077d14",
                                VL_API_SESSION_SDL_V3_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "session_sdl_v3_details_829e367f",
                                VL_API_SESSION_SDL_V3_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_APP_ATTACH + msg_id_base,
   .name = "app_attach",
   .handler = vl_api_app_attach_t_handler,
   .endian = vl_api_app_attach_t_endian,
   .format_fn = vl_api_app_attach_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_app_attach_t_tojson,
   .fromjson = vl_api_app_attach_t_fromjson,
   .calc_size = vl_api_app_attach_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_APP_ATTACH_REPLY + msg_id_base,
  .name = "app_attach_reply",
  .handler = 0,
  .endian = vl_api_app_attach_reply_t_endian,
  .format_fn = vl_api_app_attach_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_app_attach_reply_t_tojson,
  .fromjson = vl_api_app_attach_reply_t_fromjson,
  .calc_size = vl_api_app_attach_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_APPLICATION_DETACH + msg_id_base,
   .name = "application_detach",
   .handler = vl_api_application_detach_t_handler,
   .endian = vl_api_application_detach_t_endian,
   .format_fn = vl_api_application_detach_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_application_detach_t_tojson,
   .fromjson = vl_api_application_detach_t_fromjson,
   .calc_size = vl_api_application_detach_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_APPLICATION_DETACH_REPLY + msg_id_base,
  .name = "application_detach_reply",
  .handler = 0,
  .endian = vl_api_application_detach_reply_t_endian,
  .format_fn = vl_api_application_detach_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_application_detach_reply_t_tojson,
  .fromjson = vl_api_application_detach_reply_t_fromjson,
  .calc_size = vl_api_application_detach_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_APP_ADD_CERT_KEY_PAIR + msg_id_base,
   .name = "app_add_cert_key_pair",
   .handler = vl_api_app_add_cert_key_pair_t_handler,
   .endian = vl_api_app_add_cert_key_pair_t_endian,
   .format_fn = vl_api_app_add_cert_key_pair_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_app_add_cert_key_pair_t_tojson,
   .fromjson = vl_api_app_add_cert_key_pair_t_fromjson,
   .calc_size = vl_api_app_add_cert_key_pair_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_APP_ADD_CERT_KEY_PAIR_REPLY + msg_id_base,
  .name = "app_add_cert_key_pair_reply",
  .handler = 0,
  .endian = vl_api_app_add_cert_key_pair_reply_t_endian,
  .format_fn = vl_api_app_add_cert_key_pair_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_app_add_cert_key_pair_reply_t_tojson,
  .fromjson = vl_api_app_add_cert_key_pair_reply_t_fromjson,
  .calc_size = vl_api_app_add_cert_key_pair_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_APP_DEL_CERT_KEY_PAIR + msg_id_base,
   .name = "app_del_cert_key_pair",
   .handler = vl_api_app_del_cert_key_pair_t_handler,
   .endian = vl_api_app_del_cert_key_pair_t_endian,
   .format_fn = vl_api_app_del_cert_key_pair_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_app_del_cert_key_pair_t_tojson,
   .fromjson = vl_api_app_del_cert_key_pair_t_fromjson,
   .calc_size = vl_api_app_del_cert_key_pair_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_APP_DEL_CERT_KEY_PAIR_REPLY + msg_id_base,
  .name = "app_del_cert_key_pair_reply",
  .handler = 0,
  .endian = vl_api_app_del_cert_key_pair_reply_t_endian,
  .format_fn = vl_api_app_del_cert_key_pair_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_app_del_cert_key_pair_reply_t_tojson,
  .fromjson = vl_api_app_del_cert_key_pair_reply_t_fromjson,
  .calc_size = vl_api_app_del_cert_key_pair_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_APP_WORKER_ADD_DEL + msg_id_base,
   .name = "app_worker_add_del",
   .handler = vl_api_app_worker_add_del_t_handler,
   .endian = vl_api_app_worker_add_del_t_endian,
   .format_fn = vl_api_app_worker_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_app_worker_add_del_t_tojson,
   .fromjson = vl_api_app_worker_add_del_t_fromjson,
   .calc_size = vl_api_app_worker_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_APP_WORKER_ADD_DEL_REPLY + msg_id_base,
  .name = "app_worker_add_del_reply",
  .handler = 0,
  .endian = vl_api_app_worker_add_del_reply_t_endian,
  .format_fn = vl_api_app_worker_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_app_worker_add_del_reply_t_tojson,
  .fromjson = vl_api_app_worker_add_del_reply_t_fromjson,
  .calc_size = vl_api_app_worker_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SESSION_ENABLE_DISABLE + msg_id_base,
   .name = "session_enable_disable",
   .handler = vl_api_session_enable_disable_t_handler,
   .endian = vl_api_session_enable_disable_t_endian,
   .format_fn = vl_api_session_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_session_enable_disable_t_tojson,
   .fromjson = vl_api_session_enable_disable_t_fromjson,
   .calc_size = vl_api_session_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SESSION_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "session_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_session_enable_disable_reply_t_endian,
  .format_fn = vl_api_session_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_session_enable_disable_reply_t_tojson,
  .fromjson = vl_api_session_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_session_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SESSION_ENABLE_DISABLE_V2 + msg_id_base,
   .name = "session_enable_disable_v2",
   .handler = vl_api_session_enable_disable_v2_t_handler,
   .endian = vl_api_session_enable_disable_v2_t_endian,
   .format_fn = vl_api_session_enable_disable_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_session_enable_disable_v2_t_tojson,
   .fromjson = vl_api_session_enable_disable_v2_t_fromjson,
   .calc_size = vl_api_session_enable_disable_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SESSION_ENABLE_DISABLE_V2_REPLY + msg_id_base,
  .name = "session_enable_disable_v2_reply",
  .handler = 0,
  .endian = vl_api_session_enable_disable_v2_reply_t_endian,
  .format_fn = vl_api_session_enable_disable_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_session_enable_disable_v2_reply_t_tojson,
  .fromjson = vl_api_session_enable_disable_v2_reply_t_fromjson,
  .calc_size = vl_api_session_enable_disable_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SESSION_SAPI_ENABLE_DISABLE + msg_id_base,
   .name = "session_sapi_enable_disable",
   .handler = vl_api_session_sapi_enable_disable_t_handler,
   .endian = vl_api_session_sapi_enable_disable_t_endian,
   .format_fn = vl_api_session_sapi_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_session_sapi_enable_disable_t_tojson,
   .fromjson = vl_api_session_sapi_enable_disable_t_fromjson,
   .calc_size = vl_api_session_sapi_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SESSION_SAPI_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "session_sapi_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_session_sapi_enable_disable_reply_t_endian,
  .format_fn = vl_api_session_sapi_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_session_sapi_enable_disable_reply_t_tojson,
  .fromjson = vl_api_session_sapi_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_session_sapi_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_APP_NAMESPACE_ADD_DEL + msg_id_base,
   .name = "app_namespace_add_del",
   .handler = vl_api_app_namespace_add_del_t_handler,
   .endian = vl_api_app_namespace_add_del_t_endian,
   .format_fn = vl_api_app_namespace_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_app_namespace_add_del_t_tojson,
   .fromjson = vl_api_app_namespace_add_del_t_fromjson,
   .calc_size = vl_api_app_namespace_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_APP_NAMESPACE_ADD_DEL_REPLY + msg_id_base,
  .name = "app_namespace_add_del_reply",
  .handler = 0,
  .endian = vl_api_app_namespace_add_del_reply_t_endian,
  .format_fn = vl_api_app_namespace_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_app_namespace_add_del_reply_t_tojson,
  .fromjson = vl_api_app_namespace_add_del_reply_t_fromjson,
  .calc_size = vl_api_app_namespace_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_APP_NAMESPACE_ADD_DEL_V4 + msg_id_base,
   .name = "app_namespace_add_del_v4",
   .handler = vl_api_app_namespace_add_del_v4_t_handler,
   .endian = vl_api_app_namespace_add_del_v4_t_endian,
   .format_fn = vl_api_app_namespace_add_del_v4_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_app_namespace_add_del_v4_t_tojson,
   .fromjson = vl_api_app_namespace_add_del_v4_t_fromjson,
   .calc_size = vl_api_app_namespace_add_del_v4_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_APP_NAMESPACE_ADD_DEL_V4_REPLY + msg_id_base,
  .name = "app_namespace_add_del_v4_reply",
  .handler = 0,
  .endian = vl_api_app_namespace_add_del_v4_reply_t_endian,
  .format_fn = vl_api_app_namespace_add_del_v4_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_app_namespace_add_del_v4_reply_t_tojson,
  .fromjson = vl_api_app_namespace_add_del_v4_reply_t_fromjson,
  .calc_size = vl_api_app_namespace_add_del_v4_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_APP_NAMESPACE_ADD_DEL_V2 + msg_id_base,
   .name = "app_namespace_add_del_v2",
   .handler = vl_api_app_namespace_add_del_v2_t_handler,
   .endian = vl_api_app_namespace_add_del_v2_t_endian,
   .format_fn = vl_api_app_namespace_add_del_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_app_namespace_add_del_v2_t_tojson,
   .fromjson = vl_api_app_namespace_add_del_v2_t_fromjson,
   .calc_size = vl_api_app_namespace_add_del_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_APP_NAMESPACE_ADD_DEL_V2_REPLY + msg_id_base,
  .name = "app_namespace_add_del_v2_reply",
  .handler = 0,
  .endian = vl_api_app_namespace_add_del_v2_reply_t_endian,
  .format_fn = vl_api_app_namespace_add_del_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_app_namespace_add_del_v2_reply_t_tojson,
  .fromjson = vl_api_app_namespace_add_del_v2_reply_t_fromjson,
  .calc_size = vl_api_app_namespace_add_del_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_APP_NAMESPACE_ADD_DEL_V3 + msg_id_base,
   .name = "app_namespace_add_del_v3",
   .handler = vl_api_app_namespace_add_del_v3_t_handler,
   .endian = vl_api_app_namespace_add_del_v3_t_endian,
   .format_fn = vl_api_app_namespace_add_del_v3_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_app_namespace_add_del_v3_t_tojson,
   .fromjson = vl_api_app_namespace_add_del_v3_t_fromjson,
   .calc_size = vl_api_app_namespace_add_del_v3_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_APP_NAMESPACE_ADD_DEL_V3_REPLY + msg_id_base,
  .name = "app_namespace_add_del_v3_reply",
  .handler = 0,
  .endian = vl_api_app_namespace_add_del_v3_reply_t_endian,
  .format_fn = vl_api_app_namespace_add_del_v3_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_app_namespace_add_del_v3_reply_t_tojson,
  .fromjson = vl_api_app_namespace_add_del_v3_reply_t_fromjson,
  .calc_size = vl_api_app_namespace_add_del_v3_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SESSION_RULE_ADD_DEL + msg_id_base,
   .name = "session_rule_add_del",
   .handler = vl_api_session_rule_add_del_t_handler,
   .endian = vl_api_session_rule_add_del_t_endian,
   .format_fn = vl_api_session_rule_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_session_rule_add_del_t_tojson,
   .fromjson = vl_api_session_rule_add_del_t_fromjson,
   .calc_size = vl_api_session_rule_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SESSION_RULE_ADD_DEL_REPLY + msg_id_base,
  .name = "session_rule_add_del_reply",
  .handler = 0,
  .endian = vl_api_session_rule_add_del_reply_t_endian,
  .format_fn = vl_api_session_rule_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_session_rule_add_del_reply_t_tojson,
  .fromjson = vl_api_session_rule_add_del_reply_t_fromjson,
  .calc_size = vl_api_session_rule_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SESSION_RULES_DUMP + msg_id_base,
   .name = "session_rules_dump",
   .handler = vl_api_session_rules_dump_t_handler,
   .endian = vl_api_session_rules_dump_t_endian,
   .format_fn = vl_api_session_rules_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_session_rules_dump_t_tojson,
   .fromjson = vl_api_session_rules_dump_t_fromjson,
   .calc_size = vl_api_session_rules_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SESSION_RULES_DETAILS + msg_id_base,
  .name = "session_rules_details",
  .handler = 0,
  .endian = vl_api_session_rules_details_t_endian,
  .format_fn = vl_api_session_rules_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_session_rules_details_t_tojson,
  .fromjson = vl_api_session_rules_details_t_fromjson,
  .calc_size = vl_api_session_rules_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SESSION_RULES_V2_DUMP + msg_id_base,
   .name = "session_rules_v2_dump",
   .handler = vl_api_session_rules_v2_dump_t_handler,
   .endian = vl_api_session_rules_v2_dump_t_endian,
   .format_fn = vl_api_session_rules_v2_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_session_rules_v2_dump_t_tojson,
   .fromjson = vl_api_session_rules_v2_dump_t_fromjson,
   .calc_size = vl_api_session_rules_v2_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SESSION_RULES_V2_DETAILS + msg_id_base,
  .name = "session_rules_v2_details",
  .handler = 0,
  .endian = vl_api_session_rules_v2_details_t_endian,
  .format_fn = vl_api_session_rules_v2_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_session_rules_v2_details_t_tojson,
  .fromjson = vl_api_session_rules_v2_details_t_fromjson,
  .calc_size = vl_api_session_rules_v2_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SESSION_SDL_ADD_DEL + msg_id_base,
   .name = "session_sdl_add_del",
   .handler = vl_api_session_sdl_add_del_t_handler,
   .endian = vl_api_session_sdl_add_del_t_endian,
   .format_fn = vl_api_session_sdl_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_session_sdl_add_del_t_tojson,
   .fromjson = vl_api_session_sdl_add_del_t_fromjson,
   .calc_size = vl_api_session_sdl_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SESSION_SDL_ADD_DEL_REPLY + msg_id_base,
  .name = "session_sdl_add_del_reply",
  .handler = 0,
  .endian = vl_api_session_sdl_add_del_reply_t_endian,
  .format_fn = vl_api_session_sdl_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_session_sdl_add_del_reply_t_tojson,
  .fromjson = vl_api_session_sdl_add_del_reply_t_fromjson,
  .calc_size = vl_api_session_sdl_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SESSION_SDL_ADD_DEL_V2 + msg_id_base,
   .name = "session_sdl_add_del_v2",
   .handler = vl_api_session_sdl_add_del_v2_t_handler,
   .endian = vl_api_session_sdl_add_del_v2_t_endian,
   .format_fn = vl_api_session_sdl_add_del_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_session_sdl_add_del_v2_t_tojson,
   .fromjson = vl_api_session_sdl_add_del_v2_t_fromjson,
   .calc_size = vl_api_session_sdl_add_del_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SESSION_SDL_ADD_DEL_V2_REPLY + msg_id_base,
  .name = "session_sdl_add_del_v2_reply",
  .handler = 0,
  .endian = vl_api_session_sdl_add_del_v2_reply_t_endian,
  .format_fn = vl_api_session_sdl_add_del_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_session_sdl_add_del_v2_reply_t_tojson,
  .fromjson = vl_api_session_sdl_add_del_v2_reply_t_fromjson,
  .calc_size = vl_api_session_sdl_add_del_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SESSION_SDL_DUMP + msg_id_base,
   .name = "session_sdl_dump",
   .handler = vl_api_session_sdl_dump_t_handler,
   .endian = vl_api_session_sdl_dump_t_endian,
   .format_fn = vl_api_session_sdl_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_session_sdl_dump_t_tojson,
   .fromjson = vl_api_session_sdl_dump_t_fromjson,
   .calc_size = vl_api_session_sdl_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SESSION_SDL_DETAILS + msg_id_base,
  .name = "session_sdl_details",
  .handler = 0,
  .endian = vl_api_session_sdl_details_t_endian,
  .format_fn = vl_api_session_sdl_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_session_sdl_details_t_tojson,
  .fromjson = vl_api_session_sdl_details_t_fromjson,
  .calc_size = vl_api_session_sdl_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SESSION_SDL_V2_DUMP + msg_id_base,
   .name = "session_sdl_v2_dump",
   .handler = vl_api_session_sdl_v2_dump_t_handler,
   .endian = vl_api_session_sdl_v2_dump_t_endian,
   .format_fn = vl_api_session_sdl_v2_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_session_sdl_v2_dump_t_tojson,
   .fromjson = vl_api_session_sdl_v2_dump_t_fromjson,
   .calc_size = vl_api_session_sdl_v2_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SESSION_SDL_V2_DETAILS + msg_id_base,
  .name = "session_sdl_v2_details",
  .handler = 0,
  .endian = vl_api_session_sdl_v2_details_t_endian,
  .format_fn = vl_api_session_sdl_v2_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_session_sdl_v2_details_t_tojson,
  .fromjson = vl_api_session_sdl_v2_details_t_fromjson,
  .calc_size = vl_api_session_sdl_v2_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SESSION_SDL_V3_DUMP + msg_id_base,
   .name = "session_sdl_v3_dump",
   .handler = vl_api_session_sdl_v3_dump_t_handler,
   .endian = vl_api_session_sdl_v3_dump_t_endian,
   .format_fn = vl_api_session_sdl_v3_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_session_sdl_v3_dump_t_tojson,
   .fromjson = vl_api_session_sdl_v3_dump_t_fromjson,
   .calc_size = vl_api_session_sdl_v3_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SESSION_SDL_V3_DETAILS + msg_id_base,
  .name = "session_sdl_v3_details",
  .handler = 0,
  .endian = vl_api_session_sdl_v3_details_t_endian,
  .format_fn = vl_api_session_sdl_v3_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_session_sdl_v3_details_t_tojson,
  .fromjson = vl_api_session_sdl_v3_details_t_fromjson,
  .calc_size = vl_api_session_sdl_v3_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
