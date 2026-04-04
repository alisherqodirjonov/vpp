#define vl_endianfun            /* define message structures */
#include "igmp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "igmp.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "igmp.api.h"
#undef vl_printfun

#ifndef VL_API_WANT_IGMP_EVENTS_REPLY_T_HANDLER
static void
vl_api_want_igmp_events_reply_t_handler (vl_api_want_igmp_events_reply_t * mp) {
   vat_main_t * vam = igmp_test_main.vat_main;
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
vl_api_igmp_event_t_handler (vl_api_igmp_event_t * mp) {
    vlib_cli_output(0, "igmp_event event called:");
    vlib_cli_output(0, "%U", vl_api_igmp_event_t_format, mp);
}
#ifndef VL_API_IGMP_LISTEN_REPLY_T_HANDLER
static void
vl_api_igmp_listen_reply_t_handler (vl_api_igmp_listen_reply_t * mp) {
   vat_main_t * vam = igmp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IGMP_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_igmp_enable_disable_reply_t_handler (vl_api_igmp_enable_disable_reply_t * mp) {
   vat_main_t * vam = igmp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IGMP_PROXY_DEVICE_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_igmp_proxy_device_add_del_reply_t_handler (vl_api_igmp_proxy_device_add_del_reply_t * mp) {
   vat_main_t * vam = igmp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IGMP_PROXY_DEVICE_ADD_DEL_INTERFACE_REPLY_T_HANDLER
static void
vl_api_igmp_proxy_device_add_del_interface_reply_t_handler (vl_api_igmp_proxy_device_add_del_interface_reply_t * mp) {
   vat_main_t * vam = igmp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_igmp_details_t_handler()) */
#ifndef VL_API_IGMP_CLEAR_INTERFACE_REPLY_T_HANDLER
static void
vl_api_igmp_clear_interface_reply_t_handler (vl_api_igmp_clear_interface_reply_t * mp) {
   vat_main_t * vam = igmp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_IGMP_GROUP_PREFIX_SET_REPLY_T_HANDLER
static void
vl_api_igmp_group_prefix_set_reply_t_handler (vl_api_igmp_group_prefix_set_reply_t * mp) {
   vat_main_t * vam = igmp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_igmp_group_prefix_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_WANT_IGMP_EVENTS_REPLY + msg_id_base,
    .name = "want_igmp_events_reply",
    .handler = vl_api_want_igmp_events_reply_t_handler,
    .endian = vl_api_want_igmp_events_reply_t_endian,
    .format_fn = vl_api_want_igmp_events_reply_t_format,
    .size = sizeof(vl_api_want_igmp_events_reply_t),
    .traced = 1,
    .tojson = vl_api_want_igmp_events_reply_t_tojson,
    .fromjson = vl_api_want_igmp_events_reply_t_fromjson,
    .calc_size = vl_api_want_igmp_events_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "want_igmp_events", api_want_igmp_events);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IGMP_EVENT + msg_id_base,
    .name = "igmp_event",
    .handler = vl_api_igmp_event_t_handler,
    .endian = vl_api_igmp_event_t_endian,
    .format_fn = vl_api_igmp_event_t_format,
    .size = sizeof(vl_api_igmp_event_t),
    .traced = 1,
    .tojson = vl_api_igmp_event_t_tojson,
    .fromjson = vl_api_igmp_event_t_fromjson,
    .calc_size = vl_api_igmp_event_t_calc_size,
   });   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IGMP_LISTEN_REPLY + msg_id_base,
    .name = "igmp_listen_reply",
    .handler = vl_api_igmp_listen_reply_t_handler,
    .endian = vl_api_igmp_listen_reply_t_endian,
    .format_fn = vl_api_igmp_listen_reply_t_format,
    .size = sizeof(vl_api_igmp_listen_reply_t),
    .traced = 1,
    .tojson = vl_api_igmp_listen_reply_t_tojson,
    .fromjson = vl_api_igmp_listen_reply_t_fromjson,
    .calc_size = vl_api_igmp_listen_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "igmp_listen", api_igmp_listen);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IGMP_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "igmp_enable_disable_reply",
    .handler = vl_api_igmp_enable_disable_reply_t_handler,
    .endian = vl_api_igmp_enable_disable_reply_t_endian,
    .format_fn = vl_api_igmp_enable_disable_reply_t_format,
    .size = sizeof(vl_api_igmp_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_igmp_enable_disable_reply_t_tojson,
    .fromjson = vl_api_igmp_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_igmp_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "igmp_enable_disable", api_igmp_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IGMP_PROXY_DEVICE_ADD_DEL_REPLY + msg_id_base,
    .name = "igmp_proxy_device_add_del_reply",
    .handler = vl_api_igmp_proxy_device_add_del_reply_t_handler,
    .endian = vl_api_igmp_proxy_device_add_del_reply_t_endian,
    .format_fn = vl_api_igmp_proxy_device_add_del_reply_t_format,
    .size = sizeof(vl_api_igmp_proxy_device_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_igmp_proxy_device_add_del_reply_t_tojson,
    .fromjson = vl_api_igmp_proxy_device_add_del_reply_t_fromjson,
    .calc_size = vl_api_igmp_proxy_device_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "igmp_proxy_device_add_del", api_igmp_proxy_device_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IGMP_PROXY_DEVICE_ADD_DEL_INTERFACE_REPLY + msg_id_base,
    .name = "igmp_proxy_device_add_del_interface_reply",
    .handler = vl_api_igmp_proxy_device_add_del_interface_reply_t_handler,
    .endian = vl_api_igmp_proxy_device_add_del_interface_reply_t_endian,
    .format_fn = vl_api_igmp_proxy_device_add_del_interface_reply_t_format,
    .size = sizeof(vl_api_igmp_proxy_device_add_del_interface_reply_t),
    .traced = 1,
    .tojson = vl_api_igmp_proxy_device_add_del_interface_reply_t_tojson,
    .fromjson = vl_api_igmp_proxy_device_add_del_interface_reply_t_fromjson,
    .calc_size = vl_api_igmp_proxy_device_add_del_interface_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "igmp_proxy_device_add_del_interface", api_igmp_proxy_device_add_del_interface);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IGMP_DETAILS + msg_id_base,
    .name = "igmp_details",
    .handler = vl_api_igmp_details_t_handler,
    .endian = vl_api_igmp_details_t_endian,
    .format_fn = vl_api_igmp_details_t_format,
    .size = sizeof(vl_api_igmp_details_t),
    .traced = 1,
    .tojson = vl_api_igmp_details_t_tojson,
    .fromjson = vl_api_igmp_details_t_fromjson,
    .calc_size = vl_api_igmp_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "igmp_dump", api_igmp_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IGMP_CLEAR_INTERFACE_REPLY + msg_id_base,
    .name = "igmp_clear_interface_reply",
    .handler = vl_api_igmp_clear_interface_reply_t_handler,
    .endian = vl_api_igmp_clear_interface_reply_t_endian,
    .format_fn = vl_api_igmp_clear_interface_reply_t_format,
    .size = sizeof(vl_api_igmp_clear_interface_reply_t),
    .traced = 1,
    .tojson = vl_api_igmp_clear_interface_reply_t_tojson,
    .fromjson = vl_api_igmp_clear_interface_reply_t_fromjson,
    .calc_size = vl_api_igmp_clear_interface_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "igmp_clear_interface", api_igmp_clear_interface);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IGMP_GROUP_PREFIX_SET_REPLY + msg_id_base,
    .name = "igmp_group_prefix_set_reply",
    .handler = vl_api_igmp_group_prefix_set_reply_t_handler,
    .endian = vl_api_igmp_group_prefix_set_reply_t_endian,
    .format_fn = vl_api_igmp_group_prefix_set_reply_t_format,
    .size = sizeof(vl_api_igmp_group_prefix_set_reply_t),
    .traced = 1,
    .tojson = vl_api_igmp_group_prefix_set_reply_t_tojson,
    .fromjson = vl_api_igmp_group_prefix_set_reply_t_fromjson,
    .calc_size = vl_api_igmp_group_prefix_set_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "igmp_group_prefix_set", api_igmp_group_prefix_set);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IGMP_GROUP_PREFIX_DETAILS + msg_id_base,
    .name = "igmp_group_prefix_details",
    .handler = vl_api_igmp_group_prefix_details_t_handler,
    .endian = vl_api_igmp_group_prefix_details_t_endian,
    .format_fn = vl_api_igmp_group_prefix_details_t_format,
    .size = sizeof(vl_api_igmp_group_prefix_details_t),
    .traced = 1,
    .tojson = vl_api_igmp_group_prefix_details_t_tojson,
    .fromjson = vl_api_igmp_group_prefix_details_t_fromjson,
    .calc_size = vl_api_igmp_group_prefix_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "igmp_group_prefix_dump", api_igmp_group_prefix_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   igmp_test_main_t * mainp = &igmp_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("igmp_2fd2bd5e");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "igmp plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
