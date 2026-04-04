#define vl_endianfun            /* define message structures */
#include "wireguard.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "wireguard.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "wireguard.api.h"
#undef vl_printfun

#ifndef VL_API_WANT_WIREGUARD_PEER_EVENTS_REPLY_T_HANDLER
static void
vl_api_want_wireguard_peer_events_reply_t_handler (vl_api_want_wireguard_peer_events_reply_t * mp) {
   vat_main_t * vam = wireguard_test_main.vat_main;
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
vl_api_wireguard_peer_event_t_handler (vl_api_wireguard_peer_event_t * mp) {
    vlib_cli_output(0, "wireguard_peer_event event called:");
    vlib_cli_output(0, "%U", vl_api_wireguard_peer_event_t_format, mp);
}
/* Generation not supported (vl_api_wireguard_interface_create_reply_t_handler()) */
#ifndef VL_API_WIREGUARD_INTERFACE_DELETE_REPLY_T_HANDLER
static void
vl_api_wireguard_interface_delete_reply_t_handler (vl_api_wireguard_interface_delete_reply_t * mp) {
   vat_main_t * vam = wireguard_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_wireguard_interface_details_t_handler()) */
/* Generation not supported (vl_api_wireguard_peer_add_reply_t_handler()) */
#ifndef VL_API_WIREGUARD_PEER_REMOVE_REPLY_T_HANDLER
static void
vl_api_wireguard_peer_remove_reply_t_handler (vl_api_wireguard_peer_remove_reply_t * mp) {
   vat_main_t * vam = wireguard_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_wireguard_peers_details_t_handler()) */
#ifndef VL_API_WG_SET_ASYNC_MODE_REPLY_T_HANDLER
static void
vl_api_wg_set_async_mode_reply_t_handler (vl_api_wg_set_async_mode_reply_t * mp) {
   vat_main_t * vam = wireguard_test_main.vat_main;
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
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_WANT_WIREGUARD_PEER_EVENTS_REPLY + msg_id_base,
    .name = "want_wireguard_peer_events_reply",
    .handler = vl_api_want_wireguard_peer_events_reply_t_handler,
    .endian = vl_api_want_wireguard_peer_events_reply_t_endian,
    .format_fn = vl_api_want_wireguard_peer_events_reply_t_format,
    .size = sizeof(vl_api_want_wireguard_peer_events_reply_t),
    .traced = 1,
    .tojson = vl_api_want_wireguard_peer_events_reply_t_tojson,
    .fromjson = vl_api_want_wireguard_peer_events_reply_t_fromjson,
    .calc_size = vl_api_want_wireguard_peer_events_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "want_wireguard_peer_events", api_want_wireguard_peer_events);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_WIREGUARD_PEER_EVENT + msg_id_base,
    .name = "wireguard_peer_event",
    .handler = vl_api_wireguard_peer_event_t_handler,
    .endian = vl_api_wireguard_peer_event_t_endian,
    .format_fn = vl_api_wireguard_peer_event_t_format,
    .size = sizeof(vl_api_wireguard_peer_event_t),
    .traced = 1,
    .tojson = vl_api_wireguard_peer_event_t_tojson,
    .fromjson = vl_api_wireguard_peer_event_t_fromjson,
    .calc_size = vl_api_wireguard_peer_event_t_calc_size,
   });   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_WIREGUARD_INTERFACE_CREATE_REPLY + msg_id_base,
    .name = "wireguard_interface_create_reply",
    .handler = vl_api_wireguard_interface_create_reply_t_handler,
    .endian = vl_api_wireguard_interface_create_reply_t_endian,
    .format_fn = vl_api_wireguard_interface_create_reply_t_format,
    .size = sizeof(vl_api_wireguard_interface_create_reply_t),
    .traced = 1,
    .tojson = vl_api_wireguard_interface_create_reply_t_tojson,
    .fromjson = vl_api_wireguard_interface_create_reply_t_fromjson,
    .calc_size = vl_api_wireguard_interface_create_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "wireguard_interface_create", api_wireguard_interface_create);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_WIREGUARD_INTERFACE_DELETE_REPLY + msg_id_base,
    .name = "wireguard_interface_delete_reply",
    .handler = vl_api_wireguard_interface_delete_reply_t_handler,
    .endian = vl_api_wireguard_interface_delete_reply_t_endian,
    .format_fn = vl_api_wireguard_interface_delete_reply_t_format,
    .size = sizeof(vl_api_wireguard_interface_delete_reply_t),
    .traced = 1,
    .tojson = vl_api_wireguard_interface_delete_reply_t_tojson,
    .fromjson = vl_api_wireguard_interface_delete_reply_t_fromjson,
    .calc_size = vl_api_wireguard_interface_delete_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "wireguard_interface_delete", api_wireguard_interface_delete);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_WIREGUARD_INTERFACE_DETAILS + msg_id_base,
    .name = "wireguard_interface_details",
    .handler = vl_api_wireguard_interface_details_t_handler,
    .endian = vl_api_wireguard_interface_details_t_endian,
    .format_fn = vl_api_wireguard_interface_details_t_format,
    .size = sizeof(vl_api_wireguard_interface_details_t),
    .traced = 1,
    .tojson = vl_api_wireguard_interface_details_t_tojson,
    .fromjson = vl_api_wireguard_interface_details_t_fromjson,
    .calc_size = vl_api_wireguard_interface_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "wireguard_interface_dump", api_wireguard_interface_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_WIREGUARD_PEER_ADD_REPLY + msg_id_base,
    .name = "wireguard_peer_add_reply",
    .handler = vl_api_wireguard_peer_add_reply_t_handler,
    .endian = vl_api_wireguard_peer_add_reply_t_endian,
    .format_fn = vl_api_wireguard_peer_add_reply_t_format,
    .size = sizeof(vl_api_wireguard_peer_add_reply_t),
    .traced = 1,
    .tojson = vl_api_wireguard_peer_add_reply_t_tojson,
    .fromjson = vl_api_wireguard_peer_add_reply_t_fromjson,
    .calc_size = vl_api_wireguard_peer_add_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "wireguard_peer_add", api_wireguard_peer_add);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_WIREGUARD_PEER_REMOVE_REPLY + msg_id_base,
    .name = "wireguard_peer_remove_reply",
    .handler = vl_api_wireguard_peer_remove_reply_t_handler,
    .endian = vl_api_wireguard_peer_remove_reply_t_endian,
    .format_fn = vl_api_wireguard_peer_remove_reply_t_format,
    .size = sizeof(vl_api_wireguard_peer_remove_reply_t),
    .traced = 1,
    .tojson = vl_api_wireguard_peer_remove_reply_t_tojson,
    .fromjson = vl_api_wireguard_peer_remove_reply_t_fromjson,
    .calc_size = vl_api_wireguard_peer_remove_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "wireguard_peer_remove", api_wireguard_peer_remove);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_WIREGUARD_PEERS_DETAILS + msg_id_base,
    .name = "wireguard_peers_details",
    .handler = vl_api_wireguard_peers_details_t_handler,
    .endian = vl_api_wireguard_peers_details_t_endian,
    .format_fn = vl_api_wireguard_peers_details_t_format,
    .size = sizeof(vl_api_wireguard_peers_details_t),
    .traced = 1,
    .tojson = vl_api_wireguard_peers_details_t_tojson,
    .fromjson = vl_api_wireguard_peers_details_t_fromjson,
    .calc_size = vl_api_wireguard_peers_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "wireguard_peers_dump", api_wireguard_peers_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_WG_SET_ASYNC_MODE_REPLY + msg_id_base,
    .name = "wg_set_async_mode_reply",
    .handler = vl_api_wg_set_async_mode_reply_t_handler,
    .endian = vl_api_wg_set_async_mode_reply_t_endian,
    .format_fn = vl_api_wg_set_async_mode_reply_t_format,
    .size = sizeof(vl_api_wg_set_async_mode_reply_t),
    .traced = 1,
    .tojson = vl_api_wg_set_async_mode_reply_t_tojson,
    .fromjson = vl_api_wg_set_async_mode_reply_t_fromjson,
    .calc_size = vl_api_wg_set_async_mode_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "wg_set_async_mode", api_wg_set_async_mode);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   wireguard_test_main_t * mainp = &wireguard_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("wireguard_4f5c87aa");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "wireguard plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
