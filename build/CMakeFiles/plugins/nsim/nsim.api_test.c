#define vl_endianfun            /* define message structures */
#include "nsim.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "nsim.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "nsim.api.h"
#undef vl_printfun

#ifndef VL_API_NSIM_CROSS_CONNECT_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_nsim_cross_connect_enable_disable_reply_t_handler (vl_api_nsim_cross_connect_enable_disable_reply_t * mp) {
   vat_main_t * vam = nsim_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NSIM_OUTPUT_FEATURE_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_nsim_output_feature_enable_disable_reply_t_handler (vl_api_nsim_output_feature_enable_disable_reply_t * mp) {
   vat_main_t * vam = nsim_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NSIM_CONFIGURE_REPLY_T_HANDLER
static void
vl_api_nsim_configure_reply_t_handler (vl_api_nsim_configure_reply_t * mp) {
   vat_main_t * vam = nsim_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NSIM_CONFIGURE2_REPLY_T_HANDLER
static void
vl_api_nsim_configure2_reply_t_handler (vl_api_nsim_configure2_reply_t * mp) {
   vat_main_t * vam = nsim_test_main.vat_main;
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
    .id = VL_API_NSIM_CROSS_CONNECT_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "nsim_cross_connect_enable_disable_reply",
    .handler = vl_api_nsim_cross_connect_enable_disable_reply_t_handler,
    .endian = vl_api_nsim_cross_connect_enable_disable_reply_t_endian,
    .format_fn = vl_api_nsim_cross_connect_enable_disable_reply_t_format,
    .size = sizeof(vl_api_nsim_cross_connect_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_nsim_cross_connect_enable_disable_reply_t_tojson,
    .fromjson = vl_api_nsim_cross_connect_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_nsim_cross_connect_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nsim_cross_connect_enable_disable", api_nsim_cross_connect_enable_disable);
   hash_set_mem (vam->help_by_name, "nsim_cross_connect_enable_disable", "[<intfc0> | sw_if_index <swif0>] [<intfc1> | sw_if_index <swif1>] [disable]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NSIM_OUTPUT_FEATURE_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "nsim_output_feature_enable_disable_reply",
    .handler = vl_api_nsim_output_feature_enable_disable_reply_t_handler,
    .endian = vl_api_nsim_output_feature_enable_disable_reply_t_endian,
    .format_fn = vl_api_nsim_output_feature_enable_disable_reply_t_format,
    .size = sizeof(vl_api_nsim_output_feature_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_nsim_output_feature_enable_disable_reply_t_tojson,
    .fromjson = vl_api_nsim_output_feature_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_nsim_output_feature_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nsim_output_feature_enable_disable", api_nsim_output_feature_enable_disable);
   hash_set_mem (vam->help_by_name, "nsim_output_feature_enable_disable", "[<intfc> | sw_if_index <nnn> [disable]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NSIM_CONFIGURE_REPLY + msg_id_base,
    .name = "nsim_configure_reply",
    .handler = vl_api_nsim_configure_reply_t_handler,
    .endian = vl_api_nsim_configure_reply_t_endian,
    .format_fn = vl_api_nsim_configure_reply_t_format,
    .size = sizeof(vl_api_nsim_configure_reply_t),
    .traced = 1,
    .tojson = vl_api_nsim_configure_reply_t_tojson,
    .fromjson = vl_api_nsim_configure_reply_t_fromjson,
    .calc_size = vl_api_nsim_configure_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nsim_configure", api_nsim_configure);
   hash_set_mem (vam->help_by_name, "nsim_configure", "delay <time> bandwidth <bw> [packet-size <nn>] [packets-per-drop <nnnn>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NSIM_CONFIGURE2_REPLY + msg_id_base,
    .name = "nsim_configure2_reply",
    .handler = vl_api_nsim_configure2_reply_t_handler,
    .endian = vl_api_nsim_configure2_reply_t_endian,
    .format_fn = vl_api_nsim_configure2_reply_t_format,
    .size = sizeof(vl_api_nsim_configure2_reply_t),
    .traced = 1,
    .tojson = vl_api_nsim_configure2_reply_t_tojson,
    .fromjson = vl_api_nsim_configure2_reply_t_fromjson,
    .calc_size = vl_api_nsim_configure2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nsim_configure2", api_nsim_configure2);
   hash_set_mem (vam->help_by_name, "nsim_configure2", "delay <time> bandwidth <bw> [packet-size <nn>] [packets-per-drop <nnnn>]");
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   nsim_test_main_t * mainp = &nsim_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("nsim_0f1cc8e8");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "nsim plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
