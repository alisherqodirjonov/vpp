#define vl_endianfun            /* define message structures */
#include "l2tp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "l2tp.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "l2tp.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_l2tpv3_create_tunnel_reply_t_handler()) */
#ifndef VL_API_L2TPV3_SET_TUNNEL_COOKIES_REPLY_T_HANDLER
static void
vl_api_l2tpv3_set_tunnel_cookies_reply_t_handler (vl_api_l2tpv3_set_tunnel_cookies_reply_t * mp) {
   vat_main_t * vam = l2tp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_sw_if_l2tpv3_tunnel_details_t_handler()) */
#ifndef VL_API_L2TPV3_INTERFACE_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_l2tpv3_interface_enable_disable_reply_t_handler (vl_api_l2tpv3_interface_enable_disable_reply_t * mp) {
   vat_main_t * vam = l2tp_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_L2TPV3_SET_LOOKUP_KEY_REPLY_T_HANDLER
static void
vl_api_l2tpv3_set_lookup_key_reply_t_handler (vl_api_l2tpv3_set_lookup_key_reply_t * mp) {
   vat_main_t * vam = l2tp_test_main.vat_main;
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
    .id = VL_API_L2TPV3_CREATE_TUNNEL_REPLY + msg_id_base,
    .name = "l2tpv3_create_tunnel_reply",
    .handler = vl_api_l2tpv3_create_tunnel_reply_t_handler,
    .endian = vl_api_l2tpv3_create_tunnel_reply_t_endian,
    .format_fn = vl_api_l2tpv3_create_tunnel_reply_t_format,
    .size = sizeof(vl_api_l2tpv3_create_tunnel_reply_t),
    .traced = 1,
    .tojson = vl_api_l2tpv3_create_tunnel_reply_t_tojson,
    .fromjson = vl_api_l2tpv3_create_tunnel_reply_t_fromjson,
    .calc_size = vl_api_l2tpv3_create_tunnel_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "l2tpv3_create_tunnel", api_l2tpv3_create_tunnel);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_L2TPV3_SET_TUNNEL_COOKIES_REPLY + msg_id_base,
    .name = "l2tpv3_set_tunnel_cookies_reply",
    .handler = vl_api_l2tpv3_set_tunnel_cookies_reply_t_handler,
    .endian = vl_api_l2tpv3_set_tunnel_cookies_reply_t_endian,
    .format_fn = vl_api_l2tpv3_set_tunnel_cookies_reply_t_format,
    .size = sizeof(vl_api_l2tpv3_set_tunnel_cookies_reply_t),
    .traced = 1,
    .tojson = vl_api_l2tpv3_set_tunnel_cookies_reply_t_tojson,
    .fromjson = vl_api_l2tpv3_set_tunnel_cookies_reply_t_fromjson,
    .calc_size = vl_api_l2tpv3_set_tunnel_cookies_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "l2tpv3_set_tunnel_cookies", api_l2tpv3_set_tunnel_cookies);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_IF_L2TPV3_TUNNEL_DETAILS + msg_id_base,
    .name = "sw_if_l2tpv3_tunnel_details",
    .handler = vl_api_sw_if_l2tpv3_tunnel_details_t_handler,
    .endian = vl_api_sw_if_l2tpv3_tunnel_details_t_endian,
    .format_fn = vl_api_sw_if_l2tpv3_tunnel_details_t_format,
    .size = sizeof(vl_api_sw_if_l2tpv3_tunnel_details_t),
    .traced = 1,
    .tojson = vl_api_sw_if_l2tpv3_tunnel_details_t_tojson,
    .fromjson = vl_api_sw_if_l2tpv3_tunnel_details_t_fromjson,
    .calc_size = vl_api_sw_if_l2tpv3_tunnel_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_if_l2tpv3_tunnel_dump", api_sw_if_l2tpv3_tunnel_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_L2TPV3_INTERFACE_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "l2tpv3_interface_enable_disable_reply",
    .handler = vl_api_l2tpv3_interface_enable_disable_reply_t_handler,
    .endian = vl_api_l2tpv3_interface_enable_disable_reply_t_endian,
    .format_fn = vl_api_l2tpv3_interface_enable_disable_reply_t_format,
    .size = sizeof(vl_api_l2tpv3_interface_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_l2tpv3_interface_enable_disable_reply_t_tojson,
    .fromjson = vl_api_l2tpv3_interface_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_l2tpv3_interface_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "l2tpv3_interface_enable_disable", api_l2tpv3_interface_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_L2TPV3_SET_LOOKUP_KEY_REPLY + msg_id_base,
    .name = "l2tpv3_set_lookup_key_reply",
    .handler = vl_api_l2tpv3_set_lookup_key_reply_t_handler,
    .endian = vl_api_l2tpv3_set_lookup_key_reply_t_endian,
    .format_fn = vl_api_l2tpv3_set_lookup_key_reply_t_format,
    .size = sizeof(vl_api_l2tpv3_set_lookup_key_reply_t),
    .traced = 1,
    .tojson = vl_api_l2tpv3_set_lookup_key_reply_t_tojson,
    .fromjson = vl_api_l2tpv3_set_lookup_key_reply_t_fromjson,
    .calc_size = vl_api_l2tpv3_set_lookup_key_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "l2tpv3_set_lookup_key", api_l2tpv3_set_lookup_key);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   l2tp_test_main_t * mainp = &l2tp_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("l2tp_f73ff6b9");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "l2tp plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
