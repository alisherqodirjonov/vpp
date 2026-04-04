#define vl_endianfun            /* define message structures */
#include "vrrp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "vrrp.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "vrrp.api.h"
#undef vl_printfun

#ifndef VL_API_WANT_VRRP_VR_EVENTS_REPLY_T_HANDLER
static void
vl_api_want_vrrp_vr_events_reply_t_handler (vl_api_want_vrrp_vr_events_reply_t * mp) {
   vat_main_t * vam = vrrp_test_main.vat_main;
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
vl_api_vrrp_vr_event_t_handler (vl_api_vrrp_vr_event_t * mp) {
    vlib_cli_output(0, "vrrp_vr_event event called:");
    vlib_cli_output(0, "%U", vl_api_vrrp_vr_event_t_format, mp);
}
#ifndef VL_API_VRRP_VR_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_vrrp_vr_add_del_reply_t_handler (vl_api_vrrp_vr_add_del_reply_t * mp) {
   vat_main_t * vam = vrrp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_vrrp_vr_update_reply_t_handler()) */
#ifndef VL_API_VRRP_VR_DEL_REPLY_T_HANDLER
static void
vl_api_vrrp_vr_del_reply_t_handler (vl_api_vrrp_vr_del_reply_t * mp) {
   vat_main_t * vam = vrrp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_vrrp_vr_details_t_handler()) */
#ifndef VL_API_VRRP_VR_START_STOP_REPLY_T_HANDLER
static void
vl_api_vrrp_vr_start_stop_reply_t_handler (vl_api_vrrp_vr_start_stop_reply_t * mp) {
   vat_main_t * vam = vrrp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_VRRP_VR_SET_PEERS_REPLY_T_HANDLER
static void
vl_api_vrrp_vr_set_peers_reply_t_handler (vl_api_vrrp_vr_set_peers_reply_t * mp) {
   vat_main_t * vam = vrrp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_vrrp_vr_peer_details_t_handler()) */
#ifndef VL_API_VRRP_VR_TRACK_IF_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_vrrp_vr_track_if_add_del_reply_t_handler (vl_api_vrrp_vr_track_if_add_del_reply_t * mp) {
   vat_main_t * vam = vrrp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_vrrp_vr_track_if_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_WANT_VRRP_VR_EVENTS_REPLY + msg_id_base,
    .name = "want_vrrp_vr_events_reply",
    .handler = vl_api_want_vrrp_vr_events_reply_t_handler,
    .endian = vl_api_want_vrrp_vr_events_reply_t_endian,
    .format_fn = vl_api_want_vrrp_vr_events_reply_t_format,
    .size = sizeof(vl_api_want_vrrp_vr_events_reply_t),
    .traced = 1,
    .tojson = vl_api_want_vrrp_vr_events_reply_t_tojson,
    .fromjson = vl_api_want_vrrp_vr_events_reply_t_fromjson,
    .calc_size = vl_api_want_vrrp_vr_events_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "want_vrrp_vr_events", api_want_vrrp_vr_events);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_VRRP_VR_EVENT + msg_id_base,
    .name = "vrrp_vr_event",
    .handler = vl_api_vrrp_vr_event_t_handler,
    .endian = vl_api_vrrp_vr_event_t_endian,
    .format_fn = vl_api_vrrp_vr_event_t_format,
    .size = sizeof(vl_api_vrrp_vr_event_t),
    .traced = 1,
    .tojson = vl_api_vrrp_vr_event_t_tojson,
    .fromjson = vl_api_vrrp_vr_event_t_fromjson,
    .calc_size = vl_api_vrrp_vr_event_t_calc_size,
   });   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_VRRP_VR_ADD_DEL_REPLY + msg_id_base,
    .name = "vrrp_vr_add_del_reply",
    .handler = vl_api_vrrp_vr_add_del_reply_t_handler,
    .endian = vl_api_vrrp_vr_add_del_reply_t_endian,
    .format_fn = vl_api_vrrp_vr_add_del_reply_t_format,
    .size = sizeof(vl_api_vrrp_vr_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_vrrp_vr_add_del_reply_t_tojson,
    .fromjson = vl_api_vrrp_vr_add_del_reply_t_fromjson,
    .calc_size = vl_api_vrrp_vr_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "vrrp_vr_add_del", api_vrrp_vr_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_VRRP_VR_UPDATE_REPLY + msg_id_base,
    .name = "vrrp_vr_update_reply",
    .handler = vl_api_vrrp_vr_update_reply_t_handler,
    .endian = vl_api_vrrp_vr_update_reply_t_endian,
    .format_fn = vl_api_vrrp_vr_update_reply_t_format,
    .size = sizeof(vl_api_vrrp_vr_update_reply_t),
    .traced = 1,
    .tojson = vl_api_vrrp_vr_update_reply_t_tojson,
    .fromjson = vl_api_vrrp_vr_update_reply_t_fromjson,
    .calc_size = vl_api_vrrp_vr_update_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "vrrp_vr_update", api_vrrp_vr_update);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_VRRP_VR_DEL_REPLY + msg_id_base,
    .name = "vrrp_vr_del_reply",
    .handler = vl_api_vrrp_vr_del_reply_t_handler,
    .endian = vl_api_vrrp_vr_del_reply_t_endian,
    .format_fn = vl_api_vrrp_vr_del_reply_t_format,
    .size = sizeof(vl_api_vrrp_vr_del_reply_t),
    .traced = 1,
    .tojson = vl_api_vrrp_vr_del_reply_t_tojson,
    .fromjson = vl_api_vrrp_vr_del_reply_t_fromjson,
    .calc_size = vl_api_vrrp_vr_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "vrrp_vr_del", api_vrrp_vr_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_VRRP_VR_DETAILS + msg_id_base,
    .name = "vrrp_vr_details",
    .handler = vl_api_vrrp_vr_details_t_handler,
    .endian = vl_api_vrrp_vr_details_t_endian,
    .format_fn = vl_api_vrrp_vr_details_t_format,
    .size = sizeof(vl_api_vrrp_vr_details_t),
    .traced = 1,
    .tojson = vl_api_vrrp_vr_details_t_tojson,
    .fromjson = vl_api_vrrp_vr_details_t_fromjson,
    .calc_size = vl_api_vrrp_vr_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "vrrp_vr_dump", api_vrrp_vr_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_VRRP_VR_START_STOP_REPLY + msg_id_base,
    .name = "vrrp_vr_start_stop_reply",
    .handler = vl_api_vrrp_vr_start_stop_reply_t_handler,
    .endian = vl_api_vrrp_vr_start_stop_reply_t_endian,
    .format_fn = vl_api_vrrp_vr_start_stop_reply_t_format,
    .size = sizeof(vl_api_vrrp_vr_start_stop_reply_t),
    .traced = 1,
    .tojson = vl_api_vrrp_vr_start_stop_reply_t_tojson,
    .fromjson = vl_api_vrrp_vr_start_stop_reply_t_fromjson,
    .calc_size = vl_api_vrrp_vr_start_stop_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "vrrp_vr_start_stop", api_vrrp_vr_start_stop);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_VRRP_VR_SET_PEERS_REPLY + msg_id_base,
    .name = "vrrp_vr_set_peers_reply",
    .handler = vl_api_vrrp_vr_set_peers_reply_t_handler,
    .endian = vl_api_vrrp_vr_set_peers_reply_t_endian,
    .format_fn = vl_api_vrrp_vr_set_peers_reply_t_format,
    .size = sizeof(vl_api_vrrp_vr_set_peers_reply_t),
    .traced = 1,
    .tojson = vl_api_vrrp_vr_set_peers_reply_t_tojson,
    .fromjson = vl_api_vrrp_vr_set_peers_reply_t_fromjson,
    .calc_size = vl_api_vrrp_vr_set_peers_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "vrrp_vr_set_peers", api_vrrp_vr_set_peers);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_VRRP_VR_PEER_DETAILS + msg_id_base,
    .name = "vrrp_vr_peer_details",
    .handler = vl_api_vrrp_vr_peer_details_t_handler,
    .endian = vl_api_vrrp_vr_peer_details_t_endian,
    .format_fn = vl_api_vrrp_vr_peer_details_t_format,
    .size = sizeof(vl_api_vrrp_vr_peer_details_t),
    .traced = 1,
    .tojson = vl_api_vrrp_vr_peer_details_t_tojson,
    .fromjson = vl_api_vrrp_vr_peer_details_t_fromjson,
    .calc_size = vl_api_vrrp_vr_peer_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "vrrp_vr_peer_dump", api_vrrp_vr_peer_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_VRRP_VR_TRACK_IF_ADD_DEL_REPLY + msg_id_base,
    .name = "vrrp_vr_track_if_add_del_reply",
    .handler = vl_api_vrrp_vr_track_if_add_del_reply_t_handler,
    .endian = vl_api_vrrp_vr_track_if_add_del_reply_t_endian,
    .format_fn = vl_api_vrrp_vr_track_if_add_del_reply_t_format,
    .size = sizeof(vl_api_vrrp_vr_track_if_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_vrrp_vr_track_if_add_del_reply_t_tojson,
    .fromjson = vl_api_vrrp_vr_track_if_add_del_reply_t_fromjson,
    .calc_size = vl_api_vrrp_vr_track_if_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "vrrp_vr_track_if_add_del", api_vrrp_vr_track_if_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_VRRP_VR_TRACK_IF_DETAILS + msg_id_base,
    .name = "vrrp_vr_track_if_details",
    .handler = vl_api_vrrp_vr_track_if_details_t_handler,
    .endian = vl_api_vrrp_vr_track_if_details_t_endian,
    .format_fn = vl_api_vrrp_vr_track_if_details_t_format,
    .size = sizeof(vl_api_vrrp_vr_track_if_details_t),
    .traced = 1,
    .tojson = vl_api_vrrp_vr_track_if_details_t_tojson,
    .fromjson = vl_api_vrrp_vr_track_if_details_t_fromjson,
    .calc_size = vl_api_vrrp_vr_track_if_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "vrrp_vr_track_if_dump", api_vrrp_vr_track_if_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   vrrp_test_main_t * mainp = &vrrp_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("vrrp_488c32da");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "vrrp plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
