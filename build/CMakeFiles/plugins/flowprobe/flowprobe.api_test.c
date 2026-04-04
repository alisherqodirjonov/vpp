#define vl_endianfun            /* define message structures */
#include "flowprobe.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "flowprobe.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "flowprobe.api.h"
#undef vl_printfun

#ifndef VL_API_FLOWPROBE_TX_INTERFACE_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_flowprobe_tx_interface_add_del_reply_t_handler (vl_api_flowprobe_tx_interface_add_del_reply_t * mp) {
   vat_main_t * vam = flowprobe_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_FLOWPROBE_INTERFACE_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_flowprobe_interface_add_del_reply_t_handler (vl_api_flowprobe_interface_add_del_reply_t * mp) {
   vat_main_t * vam = flowprobe_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_flowprobe_interface_details_t_handler()) */
#ifndef VL_API_FLOWPROBE_PARAMS_REPLY_T_HANDLER
static void
vl_api_flowprobe_params_reply_t_handler (vl_api_flowprobe_params_reply_t * mp) {
   vat_main_t * vam = flowprobe_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_FLOWPROBE_SET_PARAMS_REPLY_T_HANDLER
static void
vl_api_flowprobe_set_params_reply_t_handler (vl_api_flowprobe_set_params_reply_t * mp) {
   vat_main_t * vam = flowprobe_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_flowprobe_get_params_reply_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_FLOWPROBE_TX_INTERFACE_ADD_DEL_REPLY + msg_id_base,
    .name = "flowprobe_tx_interface_add_del_reply",
    .handler = vl_api_flowprobe_tx_interface_add_del_reply_t_handler,
    .endian = vl_api_flowprobe_tx_interface_add_del_reply_t_endian,
    .format_fn = vl_api_flowprobe_tx_interface_add_del_reply_t_format,
    .size = sizeof(vl_api_flowprobe_tx_interface_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_flowprobe_tx_interface_add_del_reply_t_tojson,
    .fromjson = vl_api_flowprobe_tx_interface_add_del_reply_t_fromjson,
    .calc_size = vl_api_flowprobe_tx_interface_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "flowprobe_tx_interface_add_del", api_flowprobe_tx_interface_add_del);
   hash_set_mem (vam->help_by_name, "flowprobe_tx_interface_add_del", "<intfc> [disable]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_FLOWPROBE_INTERFACE_ADD_DEL_REPLY + msg_id_base,
    .name = "flowprobe_interface_add_del_reply",
    .handler = vl_api_flowprobe_interface_add_del_reply_t_handler,
    .endian = vl_api_flowprobe_interface_add_del_reply_t_endian,
    .format_fn = vl_api_flowprobe_interface_add_del_reply_t_format,
    .size = sizeof(vl_api_flowprobe_interface_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_flowprobe_interface_add_del_reply_t_tojson,
    .fromjson = vl_api_flowprobe_interface_add_del_reply_t_fromjson,
    .calc_size = vl_api_flowprobe_interface_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "flowprobe_interface_add_del", api_flowprobe_interface_add_del);
   hash_set_mem (vam->help_by_name, "flowprobe_interface_add_del", "(<intfc> | sw_if_index <if-idx>) [(ip4|ip6|l2)] [(rx|tx|both)] [disable]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_FLOWPROBE_INTERFACE_DETAILS + msg_id_base,
    .name = "flowprobe_interface_details",
    .handler = vl_api_flowprobe_interface_details_t_handler,
    .endian = vl_api_flowprobe_interface_details_t_endian,
    .format_fn = vl_api_flowprobe_interface_details_t_format,
    .size = sizeof(vl_api_flowprobe_interface_details_t),
    .traced = 1,
    .tojson = vl_api_flowprobe_interface_details_t_tojson,
    .fromjson = vl_api_flowprobe_interface_details_t_fromjson,
    .calc_size = vl_api_flowprobe_interface_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "flowprobe_interface_dump", api_flowprobe_interface_dump);
   hash_set_mem (vam->help_by_name, "flowprobe_interface_dump", "[<if-idx>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_FLOWPROBE_PARAMS_REPLY + msg_id_base,
    .name = "flowprobe_params_reply",
    .handler = vl_api_flowprobe_params_reply_t_handler,
    .endian = vl_api_flowprobe_params_reply_t_endian,
    .format_fn = vl_api_flowprobe_params_reply_t_format,
    .size = sizeof(vl_api_flowprobe_params_reply_t),
    .traced = 1,
    .tojson = vl_api_flowprobe_params_reply_t_tojson,
    .fromjson = vl_api_flowprobe_params_reply_t_fromjson,
    .calc_size = vl_api_flowprobe_params_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "flowprobe_params", api_flowprobe_params);
   hash_set_mem (vam->help_by_name, "flowprobe_params", "record <[l2] [l3] [l4]> [active <timer> passive <timer>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_FLOWPROBE_SET_PARAMS_REPLY + msg_id_base,
    .name = "flowprobe_set_params_reply",
    .handler = vl_api_flowprobe_set_params_reply_t_handler,
    .endian = vl_api_flowprobe_set_params_reply_t_endian,
    .format_fn = vl_api_flowprobe_set_params_reply_t_format,
    .size = sizeof(vl_api_flowprobe_set_params_reply_t),
    .traced = 1,
    .tojson = vl_api_flowprobe_set_params_reply_t_tojson,
    .fromjson = vl_api_flowprobe_set_params_reply_t_fromjson,
    .calc_size = vl_api_flowprobe_set_params_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "flowprobe_set_params", api_flowprobe_set_params);
   hash_set_mem (vam->help_by_name, "flowprobe_set_params", "record [l2] [l3] [l4] [active <timer>] [passive <timer>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_FLOWPROBE_GET_PARAMS_REPLY + msg_id_base,
    .name = "flowprobe_get_params_reply",
    .handler = vl_api_flowprobe_get_params_reply_t_handler,
    .endian = vl_api_flowprobe_get_params_reply_t_endian,
    .format_fn = vl_api_flowprobe_get_params_reply_t_format,
    .size = sizeof(vl_api_flowprobe_get_params_reply_t),
    .traced = 1,
    .tojson = vl_api_flowprobe_get_params_reply_t_tojson,
    .fromjson = vl_api_flowprobe_get_params_reply_t_fromjson,
    .calc_size = vl_api_flowprobe_get_params_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "flowprobe_get_params", api_flowprobe_get_params);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   flowprobe_test_main_t * mainp = &flowprobe_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("flowprobe_668f737a");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "flowprobe plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
