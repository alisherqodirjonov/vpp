#define vl_endianfun            /* define message structures */
#include "flow.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "flow.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "flow.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_flow_add_reply_t_handler()) */
/* Generation not supported (vl_api_flow_add_v2_reply_t_handler()) */
#ifndef VL_API_FLOW_DEL_REPLY_T_HANDLER
static void
vl_api_flow_del_reply_t_handler (vl_api_flow_del_reply_t * mp) {
   vat_main_t * vam = flow_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_FLOW_ENABLE_REPLY_T_HANDLER
static void
vl_api_flow_enable_reply_t_handler (vl_api_flow_enable_reply_t * mp) {
   vat_main_t * vam = flow_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_FLOW_DISABLE_REPLY_T_HANDLER
static void
vl_api_flow_disable_reply_t_handler (vl_api_flow_disable_reply_t * mp) {
   vat_main_t * vam = flow_test_main.vat_main;
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
    .id = VL_API_FLOW_ADD_REPLY + msg_id_base,
    .name = "flow_add_reply",
    .handler = vl_api_flow_add_reply_t_handler,
    .endian = vl_api_flow_add_reply_t_endian,
    .format_fn = vl_api_flow_add_reply_t_format,
    .size = sizeof(vl_api_flow_add_reply_t),
    .traced = 1,
    .tojson = vl_api_flow_add_reply_t_tojson,
    .fromjson = vl_api_flow_add_reply_t_fromjson,
    .calc_size = vl_api_flow_add_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "flow_add", api_flow_add);
   hash_set_mem (vam->help_by_name, "flow_add", "test flow add [src-ip <ip-addr/mask>] [dst-ip <ip-addr/mask>] [src-port <port/mask>] [dst-port <port/mask>] [proto <ip-proto>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_FLOW_ADD_V2_REPLY + msg_id_base,
    .name = "flow_add_v2_reply",
    .handler = vl_api_flow_add_v2_reply_t_handler,
    .endian = vl_api_flow_add_v2_reply_t_endian,
    .format_fn = vl_api_flow_add_v2_reply_t_format,
    .size = sizeof(vl_api_flow_add_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_flow_add_v2_reply_t_tojson,
    .fromjson = vl_api_flow_add_v2_reply_t_fromjson,
    .calc_size = vl_api_flow_add_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "flow_add_v2", api_flow_add_v2);
   hash_set_mem (vam->help_by_name, "flow_add_v2", "test flow add [src-ip <ip-addr/mask>] [dst-ip <ip-addr/mask>] [src-port <port/mask>] [dst-port <port/mask>] [proto <ip-proto>] [spec <spec-string>] [mask <mask-string>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_FLOW_DEL_REPLY + msg_id_base,
    .name = "flow_del_reply",
    .handler = vl_api_flow_del_reply_t_handler,
    .endian = vl_api_flow_del_reply_t_endian,
    .format_fn = vl_api_flow_del_reply_t_format,
    .size = sizeof(vl_api_flow_del_reply_t),
    .traced = 1,
    .tojson = vl_api_flow_del_reply_t_tojson,
    .fromjson = vl_api_flow_del_reply_t_fromjson,
    .calc_size = vl_api_flow_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "flow_del", api_flow_del);
   hash_set_mem (vam->help_by_name, "flow_del", "test flow del index <index>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_FLOW_ENABLE_REPLY + msg_id_base,
    .name = "flow_enable_reply",
    .handler = vl_api_flow_enable_reply_t_handler,
    .endian = vl_api_flow_enable_reply_t_endian,
    .format_fn = vl_api_flow_enable_reply_t_format,
    .size = sizeof(vl_api_flow_enable_reply_t),
    .traced = 1,
    .tojson = vl_api_flow_enable_reply_t_tojson,
    .fromjson = vl_api_flow_enable_reply_t_fromjson,
    .calc_size = vl_api_flow_enable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "flow_enable", api_flow_enable);
   hash_set_mem (vam->help_by_name, "flow_enable", "test flow enable index <index> <interface name>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_FLOW_DISABLE_REPLY + msg_id_base,
    .name = "flow_disable_reply",
    .handler = vl_api_flow_disable_reply_t_handler,
    .endian = vl_api_flow_disable_reply_t_endian,
    .format_fn = vl_api_flow_disable_reply_t_format,
    .size = sizeof(vl_api_flow_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_flow_disable_reply_t_tojson,
    .fromjson = vl_api_flow_disable_reply_t_fromjson,
    .calc_size = vl_api_flow_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "flow_disable", api_flow_disable);
   hash_set_mem (vam->help_by_name, "flow_disable", "test flow disable index <index> <interface name>");
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   flow_test_main_t * mainp = &flow_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("flow_5ab59c04");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "flow plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
