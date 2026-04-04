#define vl_endianfun            /* define message structures */
#include "bfd.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "bfd.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "bfd.api.h"
#undef vl_printfun

#ifndef VL_API_WANT_BFD_EVENTS_REPLY_T_HANDLER
static void
vl_api_want_bfd_events_reply_t_handler (vl_api_want_bfd_events_reply_t * mp) {
   vat_main_t * vam = bfd_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
static void
vl_api_bfd_udp_session_event_t_handler (vl_api_bfd_udp_session_event_t * mp) {
    vlib_cli_output(0, "bfd_udp_session_event event called:");
    vlib_cli_output(0, "%U", vl_api_bfd_udp_session_event_t_format, mp);
}
#ifndef VL_API_BFD_UDP_SET_ECHO_SOURCE_REPLY_T_HANDLER
static void
vl_api_bfd_udp_set_echo_source_reply_t_handler (vl_api_bfd_udp_set_echo_source_reply_t * mp) {
   vat_main_t * vam = bfd_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_BFD_UDP_DEL_ECHO_SOURCE_REPLY_T_HANDLER
static void
vl_api_bfd_udp_del_echo_source_reply_t_handler (vl_api_bfd_udp_del_echo_source_reply_t * mp) {
   vat_main_t * vam = bfd_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_bfd_udp_get_echo_source_reply_t_handler()) */
#ifndef VL_API_BFD_UDP_ADD_REPLY_T_HANDLER
static void
vl_api_bfd_udp_add_reply_t_handler (vl_api_bfd_udp_add_reply_t * mp) {
   vat_main_t * vam = bfd_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_bfd_udp_upd_reply_t_handler()) */
#ifndef VL_API_BFD_UDP_MOD_REPLY_T_HANDLER
static void
vl_api_bfd_udp_mod_reply_t_handler (vl_api_bfd_udp_mod_reply_t * mp) {
   vat_main_t * vam = bfd_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_BFD_UDP_DEL_REPLY_T_HANDLER
static void
vl_api_bfd_udp_del_reply_t_handler (vl_api_bfd_udp_del_reply_t * mp) {
   vat_main_t * vam = bfd_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_bfd_udp_session_details_t_handler()) */
#ifndef VL_API_BFD_UDP_SESSION_SET_FLAGS_REPLY_T_HANDLER
static void
vl_api_bfd_udp_session_set_flags_reply_t_handler (vl_api_bfd_udp_session_set_flags_reply_t * mp) {
   vat_main_t * vam = bfd_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_BFD_AUTH_SET_KEY_REPLY_T_HANDLER
static void
vl_api_bfd_auth_set_key_reply_t_handler (vl_api_bfd_auth_set_key_reply_t * mp) {
   vat_main_t * vam = bfd_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_BFD_AUTH_DEL_KEY_REPLY_T_HANDLER
static void
vl_api_bfd_auth_del_key_reply_t_handler (vl_api_bfd_auth_del_key_reply_t * mp) {
   vat_main_t * vam = bfd_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_bfd_auth_keys_details_t_handler()) */
#ifndef VL_API_BFD_UDP_AUTH_ACTIVATE_REPLY_T_HANDLER
static void
vl_api_bfd_udp_auth_activate_reply_t_handler (vl_api_bfd_udp_auth_activate_reply_t * mp) {
   vat_main_t * vam = bfd_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_BFD_UDP_AUTH_DEACTIVATE_REPLY_T_HANDLER
static void
vl_api_bfd_udp_auth_deactivate_reply_t_handler (vl_api_bfd_udp_auth_deactivate_reply_t * mp) {
   vat_main_t * vam = bfd_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_BFD_UDP_ENABLE_MULTIHOP_REPLY_T_HANDLER
static void
vl_api_bfd_udp_enable_multihop_reply_t_handler (vl_api_bfd_udp_enable_multihop_reply_t * mp) {
   vat_main_t * vam = bfd_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_BFD_UDP_SET_TOS_REPLY_T_HANDLER
static void
vl_api_bfd_udp_set_tos_reply_t_handler (vl_api_bfd_udp_set_tos_reply_t * mp) {
   vat_main_t * vam = bfd_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_bfd_udp_get_tos_reply_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_WANT_BFD_EVENTS_REPLY + msg_id_base,
    .name = "want_bfd_events_reply",
    .handler = vl_api_want_bfd_events_reply_t_handler,
    .endian = vl_api_want_bfd_events_reply_t_endian,
    .format_fn = vl_api_want_bfd_events_reply_t_format,
    .size = sizeof(vl_api_want_bfd_events_reply_t),
    .traced = 1,
    .tojson = vl_api_want_bfd_events_reply_t_tojson,
    .fromjson = vl_api_want_bfd_events_reply_t_fromjson,
    .calc_size = vl_api_want_bfd_events_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "want_bfd_events", api_want_bfd_events);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BFD_UDP_SESSION_EVENT + msg_id_base,
    .name = "bfd_udp_session_event",
    .handler = vl_api_bfd_udp_session_event_t_handler,
    .endian = vl_api_bfd_udp_session_event_t_endian,
    .format_fn = vl_api_bfd_udp_session_event_t_format,
    .size = sizeof(vl_api_bfd_udp_session_event_t),
    .traced = 1,
    .tojson = vl_api_bfd_udp_session_event_t_tojson,
    .fromjson = vl_api_bfd_udp_session_event_t_fromjson,
    .calc_size = vl_api_bfd_udp_session_event_t_calc_size,
   });   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BFD_UDP_SET_ECHO_SOURCE_REPLY + msg_id_base,
    .name = "bfd_udp_set_echo_source_reply",
    .handler = vl_api_bfd_udp_set_echo_source_reply_t_handler,
    .endian = vl_api_bfd_udp_set_echo_source_reply_t_endian,
    .format_fn = vl_api_bfd_udp_set_echo_source_reply_t_format,
    .size = sizeof(vl_api_bfd_udp_set_echo_source_reply_t),
    .traced = 1,
    .tojson = vl_api_bfd_udp_set_echo_source_reply_t_tojson,
    .fromjson = vl_api_bfd_udp_set_echo_source_reply_t_fromjson,
    .calc_size = vl_api_bfd_udp_set_echo_source_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bfd_udp_set_echo_source", api_bfd_udp_set_echo_source);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BFD_UDP_DEL_ECHO_SOURCE_REPLY + msg_id_base,
    .name = "bfd_udp_del_echo_source_reply",
    .handler = vl_api_bfd_udp_del_echo_source_reply_t_handler,
    .endian = vl_api_bfd_udp_del_echo_source_reply_t_endian,
    .format_fn = vl_api_bfd_udp_del_echo_source_reply_t_format,
    .size = sizeof(vl_api_bfd_udp_del_echo_source_reply_t),
    .traced = 1,
    .tojson = vl_api_bfd_udp_del_echo_source_reply_t_tojson,
    .fromjson = vl_api_bfd_udp_del_echo_source_reply_t_fromjson,
    .calc_size = vl_api_bfd_udp_del_echo_source_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bfd_udp_del_echo_source", api_bfd_udp_del_echo_source);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BFD_UDP_GET_ECHO_SOURCE_REPLY + msg_id_base,
    .name = "bfd_udp_get_echo_source_reply",
    .handler = vl_api_bfd_udp_get_echo_source_reply_t_handler,
    .endian = vl_api_bfd_udp_get_echo_source_reply_t_endian,
    .format_fn = vl_api_bfd_udp_get_echo_source_reply_t_format,
    .size = sizeof(vl_api_bfd_udp_get_echo_source_reply_t),
    .traced = 1,
    .tojson = vl_api_bfd_udp_get_echo_source_reply_t_tojson,
    .fromjson = vl_api_bfd_udp_get_echo_source_reply_t_fromjson,
    .calc_size = vl_api_bfd_udp_get_echo_source_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bfd_udp_get_echo_source", api_bfd_udp_get_echo_source);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BFD_UDP_ADD_REPLY + msg_id_base,
    .name = "bfd_udp_add_reply",
    .handler = vl_api_bfd_udp_add_reply_t_handler,
    .endian = vl_api_bfd_udp_add_reply_t_endian,
    .format_fn = vl_api_bfd_udp_add_reply_t_format,
    .size = sizeof(vl_api_bfd_udp_add_reply_t),
    .traced = 1,
    .tojson = vl_api_bfd_udp_add_reply_t_tojson,
    .fromjson = vl_api_bfd_udp_add_reply_t_fromjson,
    .calc_size = vl_api_bfd_udp_add_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bfd_udp_add", api_bfd_udp_add);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BFD_UDP_UPD_REPLY + msg_id_base,
    .name = "bfd_udp_upd_reply",
    .handler = vl_api_bfd_udp_upd_reply_t_handler,
    .endian = vl_api_bfd_udp_upd_reply_t_endian,
    .format_fn = vl_api_bfd_udp_upd_reply_t_format,
    .size = sizeof(vl_api_bfd_udp_upd_reply_t),
    .traced = 1,
    .tojson = vl_api_bfd_udp_upd_reply_t_tojson,
    .fromjson = vl_api_bfd_udp_upd_reply_t_fromjson,
    .calc_size = vl_api_bfd_udp_upd_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bfd_udp_upd", api_bfd_udp_upd);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BFD_UDP_MOD_REPLY + msg_id_base,
    .name = "bfd_udp_mod_reply",
    .handler = vl_api_bfd_udp_mod_reply_t_handler,
    .endian = vl_api_bfd_udp_mod_reply_t_endian,
    .format_fn = vl_api_bfd_udp_mod_reply_t_format,
    .size = sizeof(vl_api_bfd_udp_mod_reply_t),
    .traced = 1,
    .tojson = vl_api_bfd_udp_mod_reply_t_tojson,
    .fromjson = vl_api_bfd_udp_mod_reply_t_fromjson,
    .calc_size = vl_api_bfd_udp_mod_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bfd_udp_mod", api_bfd_udp_mod);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BFD_UDP_DEL_REPLY + msg_id_base,
    .name = "bfd_udp_del_reply",
    .handler = vl_api_bfd_udp_del_reply_t_handler,
    .endian = vl_api_bfd_udp_del_reply_t_endian,
    .format_fn = vl_api_bfd_udp_del_reply_t_format,
    .size = sizeof(vl_api_bfd_udp_del_reply_t),
    .traced = 1,
    .tojson = vl_api_bfd_udp_del_reply_t_tojson,
    .fromjson = vl_api_bfd_udp_del_reply_t_fromjson,
    .calc_size = vl_api_bfd_udp_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bfd_udp_del", api_bfd_udp_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BFD_UDP_SESSION_DETAILS + msg_id_base,
    .name = "bfd_udp_session_details",
    .handler = vl_api_bfd_udp_session_details_t_handler,
    .endian = vl_api_bfd_udp_session_details_t_endian,
    .format_fn = vl_api_bfd_udp_session_details_t_format,
    .size = sizeof(vl_api_bfd_udp_session_details_t),
    .traced = 1,
    .tojson = vl_api_bfd_udp_session_details_t_tojson,
    .fromjson = vl_api_bfd_udp_session_details_t_fromjson,
    .calc_size = vl_api_bfd_udp_session_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bfd_udp_session_dump", api_bfd_udp_session_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BFD_UDP_SESSION_SET_FLAGS_REPLY + msg_id_base,
    .name = "bfd_udp_session_set_flags_reply",
    .handler = vl_api_bfd_udp_session_set_flags_reply_t_handler,
    .endian = vl_api_bfd_udp_session_set_flags_reply_t_endian,
    .format_fn = vl_api_bfd_udp_session_set_flags_reply_t_format,
    .size = sizeof(vl_api_bfd_udp_session_set_flags_reply_t),
    .traced = 1,
    .tojson = vl_api_bfd_udp_session_set_flags_reply_t_tojson,
    .fromjson = vl_api_bfd_udp_session_set_flags_reply_t_fromjson,
    .calc_size = vl_api_bfd_udp_session_set_flags_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bfd_udp_session_set_flags", api_bfd_udp_session_set_flags);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BFD_AUTH_SET_KEY_REPLY + msg_id_base,
    .name = "bfd_auth_set_key_reply",
    .handler = vl_api_bfd_auth_set_key_reply_t_handler,
    .endian = vl_api_bfd_auth_set_key_reply_t_endian,
    .format_fn = vl_api_bfd_auth_set_key_reply_t_format,
    .size = sizeof(vl_api_bfd_auth_set_key_reply_t),
    .traced = 1,
    .tojson = vl_api_bfd_auth_set_key_reply_t_tojson,
    .fromjson = vl_api_bfd_auth_set_key_reply_t_fromjson,
    .calc_size = vl_api_bfd_auth_set_key_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bfd_auth_set_key", api_bfd_auth_set_key);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BFD_AUTH_DEL_KEY_REPLY + msg_id_base,
    .name = "bfd_auth_del_key_reply",
    .handler = vl_api_bfd_auth_del_key_reply_t_handler,
    .endian = vl_api_bfd_auth_del_key_reply_t_endian,
    .format_fn = vl_api_bfd_auth_del_key_reply_t_format,
    .size = sizeof(vl_api_bfd_auth_del_key_reply_t),
    .traced = 1,
    .tojson = vl_api_bfd_auth_del_key_reply_t_tojson,
    .fromjson = vl_api_bfd_auth_del_key_reply_t_fromjson,
    .calc_size = vl_api_bfd_auth_del_key_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bfd_auth_del_key", api_bfd_auth_del_key);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BFD_AUTH_KEYS_DETAILS + msg_id_base,
    .name = "bfd_auth_keys_details",
    .handler = vl_api_bfd_auth_keys_details_t_handler,
    .endian = vl_api_bfd_auth_keys_details_t_endian,
    .format_fn = vl_api_bfd_auth_keys_details_t_format,
    .size = sizeof(vl_api_bfd_auth_keys_details_t),
    .traced = 1,
    .tojson = vl_api_bfd_auth_keys_details_t_tojson,
    .fromjson = vl_api_bfd_auth_keys_details_t_fromjson,
    .calc_size = vl_api_bfd_auth_keys_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bfd_auth_keys_dump", api_bfd_auth_keys_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BFD_UDP_AUTH_ACTIVATE_REPLY + msg_id_base,
    .name = "bfd_udp_auth_activate_reply",
    .handler = vl_api_bfd_udp_auth_activate_reply_t_handler,
    .endian = vl_api_bfd_udp_auth_activate_reply_t_endian,
    .format_fn = vl_api_bfd_udp_auth_activate_reply_t_format,
    .size = sizeof(vl_api_bfd_udp_auth_activate_reply_t),
    .traced = 1,
    .tojson = vl_api_bfd_udp_auth_activate_reply_t_tojson,
    .fromjson = vl_api_bfd_udp_auth_activate_reply_t_fromjson,
    .calc_size = vl_api_bfd_udp_auth_activate_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bfd_udp_auth_activate", api_bfd_udp_auth_activate);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BFD_UDP_AUTH_DEACTIVATE_REPLY + msg_id_base,
    .name = "bfd_udp_auth_deactivate_reply",
    .handler = vl_api_bfd_udp_auth_deactivate_reply_t_handler,
    .endian = vl_api_bfd_udp_auth_deactivate_reply_t_endian,
    .format_fn = vl_api_bfd_udp_auth_deactivate_reply_t_format,
    .size = sizeof(vl_api_bfd_udp_auth_deactivate_reply_t),
    .traced = 1,
    .tojson = vl_api_bfd_udp_auth_deactivate_reply_t_tojson,
    .fromjson = vl_api_bfd_udp_auth_deactivate_reply_t_fromjson,
    .calc_size = vl_api_bfd_udp_auth_deactivate_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bfd_udp_auth_deactivate", api_bfd_udp_auth_deactivate);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BFD_UDP_ENABLE_MULTIHOP_REPLY + msg_id_base,
    .name = "bfd_udp_enable_multihop_reply",
    .handler = vl_api_bfd_udp_enable_multihop_reply_t_handler,
    .endian = vl_api_bfd_udp_enable_multihop_reply_t_endian,
    .format_fn = vl_api_bfd_udp_enable_multihop_reply_t_format,
    .size = sizeof(vl_api_bfd_udp_enable_multihop_reply_t),
    .traced = 1,
    .tojson = vl_api_bfd_udp_enable_multihop_reply_t_tojson,
    .fromjson = vl_api_bfd_udp_enable_multihop_reply_t_fromjson,
    .calc_size = vl_api_bfd_udp_enable_multihop_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bfd_udp_enable_multihop", api_bfd_udp_enable_multihop);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BFD_UDP_SET_TOS_REPLY + msg_id_base,
    .name = "bfd_udp_set_tos_reply",
    .handler = vl_api_bfd_udp_set_tos_reply_t_handler,
    .endian = vl_api_bfd_udp_set_tos_reply_t_endian,
    .format_fn = vl_api_bfd_udp_set_tos_reply_t_format,
    .size = sizeof(vl_api_bfd_udp_set_tos_reply_t),
    .traced = 1,
    .tojson = vl_api_bfd_udp_set_tos_reply_t_tojson,
    .fromjson = vl_api_bfd_udp_set_tos_reply_t_fromjson,
    .calc_size = vl_api_bfd_udp_set_tos_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bfd_udp_set_tos", api_bfd_udp_set_tos);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BFD_UDP_GET_TOS_REPLY + msg_id_base,
    .name = "bfd_udp_get_tos_reply",
    .handler = vl_api_bfd_udp_get_tos_reply_t_handler,
    .endian = vl_api_bfd_udp_get_tos_reply_t_endian,
    .format_fn = vl_api_bfd_udp_get_tos_reply_t_format,
    .size = sizeof(vl_api_bfd_udp_get_tos_reply_t),
    .traced = 1,
    .tojson = vl_api_bfd_udp_get_tos_reply_t_tojson,
    .fromjson = vl_api_bfd_udp_get_tos_reply_t_fromjson,
    .calc_size = vl_api_bfd_udp_get_tos_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bfd_udp_get_tos", api_bfd_udp_get_tos);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   bfd_test_main_t * mainp = &bfd_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("bfd_3cb0ce20");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "bfd plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
