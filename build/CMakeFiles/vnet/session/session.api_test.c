#define vl_endianfun            /* define message structures */
#include "session.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "session.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "session.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_app_attach_reply_t_handler()) */
#ifndef VL_API_APPLICATION_DETACH_REPLY_T_HANDLER
static void
vl_api_application_detach_reply_t_handler (vl_api_application_detach_reply_t * mp) {
   vat_main_t * vam = session_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_app_add_cert_key_pair_reply_t_handler()) */
#ifndef VL_API_APP_DEL_CERT_KEY_PAIR_REPLY_T_HANDLER
static void
vl_api_app_del_cert_key_pair_reply_t_handler (vl_api_app_del_cert_key_pair_reply_t * mp) {
   vat_main_t * vam = session_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_app_worker_add_del_reply_t_handler()) */
#ifndef VL_API_SESSION_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_session_enable_disable_reply_t_handler (vl_api_session_enable_disable_reply_t * mp) {
   vat_main_t * vam = session_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SESSION_ENABLE_DISABLE_V2_REPLY_T_HANDLER
static void
vl_api_session_enable_disable_v2_reply_t_handler (vl_api_session_enable_disable_v2_reply_t * mp) {
   vat_main_t * vam = session_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SESSION_SAPI_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_session_sapi_enable_disable_reply_t_handler (vl_api_session_sapi_enable_disable_reply_t * mp) {
   vat_main_t * vam = session_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_app_namespace_add_del_reply_t_handler()) */
/* Generation not supported (vl_api_app_namespace_add_del_v4_reply_t_handler()) */
/* Generation not supported (vl_api_app_namespace_add_del_v2_reply_t_handler()) */
/* Generation not supported (vl_api_app_namespace_add_del_v3_reply_t_handler()) */
#ifndef VL_API_SESSION_RULE_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_session_rule_add_del_reply_t_handler (vl_api_session_rule_add_del_reply_t * mp) {
   vat_main_t * vam = session_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_session_rules_details_t_handler()) */
/* Generation not supported (vl_api_session_rules_v2_details_t_handler()) */
#ifndef VL_API_SESSION_SDL_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_session_sdl_add_del_reply_t_handler (vl_api_session_sdl_add_del_reply_t * mp) {
   vat_main_t * vam = session_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_SESSION_SDL_ADD_DEL_V2_REPLY_T_HANDLER
static void
vl_api_session_sdl_add_del_v2_reply_t_handler (vl_api_session_sdl_add_del_v2_reply_t * mp) {
   vat_main_t * vam = session_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_session_sdl_details_t_handler()) */
/* Generation not supported (vl_api_session_sdl_v2_details_t_handler()) */
/* Generation not supported (vl_api_session_sdl_v3_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_APP_ATTACH_REPLY + msg_id_base,
    .name = "app_attach_reply",
    .handler = vl_api_app_attach_reply_t_handler,
    .endian = vl_api_app_attach_reply_t_endian,
    .format_fn = vl_api_app_attach_reply_t_format,
    .size = sizeof(vl_api_app_attach_reply_t),
    .traced = 1,
    .tojson = vl_api_app_attach_reply_t_tojson,
    .fromjson = vl_api_app_attach_reply_t_fromjson,
    .calc_size = vl_api_app_attach_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "app_attach", api_app_attach);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_APPLICATION_DETACH_REPLY + msg_id_base,
    .name = "application_detach_reply",
    .handler = vl_api_application_detach_reply_t_handler,
    .endian = vl_api_application_detach_reply_t_endian,
    .format_fn = vl_api_application_detach_reply_t_format,
    .size = sizeof(vl_api_application_detach_reply_t),
    .traced = 1,
    .tojson = vl_api_application_detach_reply_t_tojson,
    .fromjson = vl_api_application_detach_reply_t_fromjson,
    .calc_size = vl_api_application_detach_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "application_detach", api_application_detach);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_APP_ADD_CERT_KEY_PAIR_REPLY + msg_id_base,
    .name = "app_add_cert_key_pair_reply",
    .handler = vl_api_app_add_cert_key_pair_reply_t_handler,
    .endian = vl_api_app_add_cert_key_pair_reply_t_endian,
    .format_fn = vl_api_app_add_cert_key_pair_reply_t_format,
    .size = sizeof(vl_api_app_add_cert_key_pair_reply_t),
    .traced = 1,
    .tojson = vl_api_app_add_cert_key_pair_reply_t_tojson,
    .fromjson = vl_api_app_add_cert_key_pair_reply_t_fromjson,
    .calc_size = vl_api_app_add_cert_key_pair_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "app_add_cert_key_pair", api_app_add_cert_key_pair);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_APP_DEL_CERT_KEY_PAIR_REPLY + msg_id_base,
    .name = "app_del_cert_key_pair_reply",
    .handler = vl_api_app_del_cert_key_pair_reply_t_handler,
    .endian = vl_api_app_del_cert_key_pair_reply_t_endian,
    .format_fn = vl_api_app_del_cert_key_pair_reply_t_format,
    .size = sizeof(vl_api_app_del_cert_key_pair_reply_t),
    .traced = 1,
    .tojson = vl_api_app_del_cert_key_pair_reply_t_tojson,
    .fromjson = vl_api_app_del_cert_key_pair_reply_t_fromjson,
    .calc_size = vl_api_app_del_cert_key_pair_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "app_del_cert_key_pair", api_app_del_cert_key_pair);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_APP_WORKER_ADD_DEL_REPLY + msg_id_base,
    .name = "app_worker_add_del_reply",
    .handler = vl_api_app_worker_add_del_reply_t_handler,
    .endian = vl_api_app_worker_add_del_reply_t_endian,
    .format_fn = vl_api_app_worker_add_del_reply_t_format,
    .size = sizeof(vl_api_app_worker_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_app_worker_add_del_reply_t_tojson,
    .fromjson = vl_api_app_worker_add_del_reply_t_fromjson,
    .calc_size = vl_api_app_worker_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "app_worker_add_del", api_app_worker_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SESSION_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "session_enable_disable_reply",
    .handler = vl_api_session_enable_disable_reply_t_handler,
    .endian = vl_api_session_enable_disable_reply_t_endian,
    .format_fn = vl_api_session_enable_disable_reply_t_format,
    .size = sizeof(vl_api_session_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_session_enable_disable_reply_t_tojson,
    .fromjson = vl_api_session_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_session_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "session_enable_disable", api_session_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SESSION_ENABLE_DISABLE_V2_REPLY + msg_id_base,
    .name = "session_enable_disable_v2_reply",
    .handler = vl_api_session_enable_disable_v2_reply_t_handler,
    .endian = vl_api_session_enable_disable_v2_reply_t_endian,
    .format_fn = vl_api_session_enable_disable_v2_reply_t_format,
    .size = sizeof(vl_api_session_enable_disable_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_session_enable_disable_v2_reply_t_tojson,
    .fromjson = vl_api_session_enable_disable_v2_reply_t_fromjson,
    .calc_size = vl_api_session_enable_disable_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "session_enable_disable_v2", api_session_enable_disable_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SESSION_SAPI_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "session_sapi_enable_disable_reply",
    .handler = vl_api_session_sapi_enable_disable_reply_t_handler,
    .endian = vl_api_session_sapi_enable_disable_reply_t_endian,
    .format_fn = vl_api_session_sapi_enable_disable_reply_t_format,
    .size = sizeof(vl_api_session_sapi_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_session_sapi_enable_disable_reply_t_tojson,
    .fromjson = vl_api_session_sapi_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_session_sapi_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "session_sapi_enable_disable", api_session_sapi_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_APP_NAMESPACE_ADD_DEL_REPLY + msg_id_base,
    .name = "app_namespace_add_del_reply",
    .handler = vl_api_app_namespace_add_del_reply_t_handler,
    .endian = vl_api_app_namespace_add_del_reply_t_endian,
    .format_fn = vl_api_app_namespace_add_del_reply_t_format,
    .size = sizeof(vl_api_app_namespace_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_app_namespace_add_del_reply_t_tojson,
    .fromjson = vl_api_app_namespace_add_del_reply_t_fromjson,
    .calc_size = vl_api_app_namespace_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "app_namespace_add_del", api_app_namespace_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_APP_NAMESPACE_ADD_DEL_V4_REPLY + msg_id_base,
    .name = "app_namespace_add_del_v4_reply",
    .handler = vl_api_app_namespace_add_del_v4_reply_t_handler,
    .endian = vl_api_app_namespace_add_del_v4_reply_t_endian,
    .format_fn = vl_api_app_namespace_add_del_v4_reply_t_format,
    .size = sizeof(vl_api_app_namespace_add_del_v4_reply_t),
    .traced = 1,
    .tojson = vl_api_app_namespace_add_del_v4_reply_t_tojson,
    .fromjson = vl_api_app_namespace_add_del_v4_reply_t_fromjson,
    .calc_size = vl_api_app_namespace_add_del_v4_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "app_namespace_add_del_v4", api_app_namespace_add_del_v4);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_APP_NAMESPACE_ADD_DEL_V2_REPLY + msg_id_base,
    .name = "app_namespace_add_del_v2_reply",
    .handler = vl_api_app_namespace_add_del_v2_reply_t_handler,
    .endian = vl_api_app_namespace_add_del_v2_reply_t_endian,
    .format_fn = vl_api_app_namespace_add_del_v2_reply_t_format,
    .size = sizeof(vl_api_app_namespace_add_del_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_app_namespace_add_del_v2_reply_t_tojson,
    .fromjson = vl_api_app_namespace_add_del_v2_reply_t_fromjson,
    .calc_size = vl_api_app_namespace_add_del_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "app_namespace_add_del_v2", api_app_namespace_add_del_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_APP_NAMESPACE_ADD_DEL_V3_REPLY + msg_id_base,
    .name = "app_namespace_add_del_v3_reply",
    .handler = vl_api_app_namespace_add_del_v3_reply_t_handler,
    .endian = vl_api_app_namespace_add_del_v3_reply_t_endian,
    .format_fn = vl_api_app_namespace_add_del_v3_reply_t_format,
    .size = sizeof(vl_api_app_namespace_add_del_v3_reply_t),
    .traced = 1,
    .tojson = vl_api_app_namespace_add_del_v3_reply_t_tojson,
    .fromjson = vl_api_app_namespace_add_del_v3_reply_t_fromjson,
    .calc_size = vl_api_app_namespace_add_del_v3_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "app_namespace_add_del_v3", api_app_namespace_add_del_v3);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SESSION_RULE_ADD_DEL_REPLY + msg_id_base,
    .name = "session_rule_add_del_reply",
    .handler = vl_api_session_rule_add_del_reply_t_handler,
    .endian = vl_api_session_rule_add_del_reply_t_endian,
    .format_fn = vl_api_session_rule_add_del_reply_t_format,
    .size = sizeof(vl_api_session_rule_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_session_rule_add_del_reply_t_tojson,
    .fromjson = vl_api_session_rule_add_del_reply_t_fromjson,
    .calc_size = vl_api_session_rule_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "session_rule_add_del", api_session_rule_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SESSION_RULES_DETAILS + msg_id_base,
    .name = "session_rules_details",
    .handler = vl_api_session_rules_details_t_handler,
    .endian = vl_api_session_rules_details_t_endian,
    .format_fn = vl_api_session_rules_details_t_format,
    .size = sizeof(vl_api_session_rules_details_t),
    .traced = 1,
    .tojson = vl_api_session_rules_details_t_tojson,
    .fromjson = vl_api_session_rules_details_t_fromjson,
    .calc_size = vl_api_session_rules_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "session_rules_dump", api_session_rules_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SESSION_RULES_V2_DETAILS + msg_id_base,
    .name = "session_rules_v2_details",
    .handler = vl_api_session_rules_v2_details_t_handler,
    .endian = vl_api_session_rules_v2_details_t_endian,
    .format_fn = vl_api_session_rules_v2_details_t_format,
    .size = sizeof(vl_api_session_rules_v2_details_t),
    .traced = 1,
    .tojson = vl_api_session_rules_v2_details_t_tojson,
    .fromjson = vl_api_session_rules_v2_details_t_fromjson,
    .calc_size = vl_api_session_rules_v2_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "session_rules_v2_dump", api_session_rules_v2_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SESSION_SDL_ADD_DEL_REPLY + msg_id_base,
    .name = "session_sdl_add_del_reply",
    .handler = vl_api_session_sdl_add_del_reply_t_handler,
    .endian = vl_api_session_sdl_add_del_reply_t_endian,
    .format_fn = vl_api_session_sdl_add_del_reply_t_format,
    .size = sizeof(vl_api_session_sdl_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_session_sdl_add_del_reply_t_tojson,
    .fromjson = vl_api_session_sdl_add_del_reply_t_fromjson,
    .calc_size = vl_api_session_sdl_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "session_sdl_add_del", api_session_sdl_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SESSION_SDL_ADD_DEL_V2_REPLY + msg_id_base,
    .name = "session_sdl_add_del_v2_reply",
    .handler = vl_api_session_sdl_add_del_v2_reply_t_handler,
    .endian = vl_api_session_sdl_add_del_v2_reply_t_endian,
    .format_fn = vl_api_session_sdl_add_del_v2_reply_t_format,
    .size = sizeof(vl_api_session_sdl_add_del_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_session_sdl_add_del_v2_reply_t_tojson,
    .fromjson = vl_api_session_sdl_add_del_v2_reply_t_fromjson,
    .calc_size = vl_api_session_sdl_add_del_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "session_sdl_add_del_v2", api_session_sdl_add_del_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SESSION_SDL_DETAILS + msg_id_base,
    .name = "session_sdl_details",
    .handler = vl_api_session_sdl_details_t_handler,
    .endian = vl_api_session_sdl_details_t_endian,
    .format_fn = vl_api_session_sdl_details_t_format,
    .size = sizeof(vl_api_session_sdl_details_t),
    .traced = 1,
    .tojson = vl_api_session_sdl_details_t_tojson,
    .fromjson = vl_api_session_sdl_details_t_fromjson,
    .calc_size = vl_api_session_sdl_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "session_sdl_dump", api_session_sdl_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SESSION_SDL_V2_DETAILS + msg_id_base,
    .name = "session_sdl_v2_details",
    .handler = vl_api_session_sdl_v2_details_t_handler,
    .endian = vl_api_session_sdl_v2_details_t_endian,
    .format_fn = vl_api_session_sdl_v2_details_t_format,
    .size = sizeof(vl_api_session_sdl_v2_details_t),
    .traced = 1,
    .tojson = vl_api_session_sdl_v2_details_t_tojson,
    .fromjson = vl_api_session_sdl_v2_details_t_fromjson,
    .calc_size = vl_api_session_sdl_v2_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "session_sdl_v2_dump", api_session_sdl_v2_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SESSION_SDL_V3_DETAILS + msg_id_base,
    .name = "session_sdl_v3_details",
    .handler = vl_api_session_sdl_v3_details_t_handler,
    .endian = vl_api_session_sdl_v3_details_t_endian,
    .format_fn = vl_api_session_sdl_v3_details_t_format,
    .size = sizeof(vl_api_session_sdl_v3_details_t),
    .traced = 1,
    .tojson = vl_api_session_sdl_v3_details_t_tojson,
    .fromjson = vl_api_session_sdl_v3_details_t_fromjson,
    .calc_size = vl_api_session_sdl_v3_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "session_sdl_v3_dump", api_session_sdl_v3_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   session_test_main_t * mainp = &session_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("session_af947b64");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "session plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
