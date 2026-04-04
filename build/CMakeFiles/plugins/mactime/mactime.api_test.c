#define vl_endianfun            /* define message structures */
#include "mactime.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "mactime.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "mactime.api.h"
#undef vl_printfun

#ifndef VL_API_MACTIME_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_mactime_enable_disable_reply_t_handler (vl_api_mactime_enable_disable_reply_t * mp) {
   vat_main_t * vam = mactime_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_MACTIME_ADD_DEL_RANGE_REPLY_T_HANDLER
static void
vl_api_mactime_add_del_range_reply_t_handler (vl_api_mactime_add_del_range_reply_t * mp) {
   vat_main_t * vam = mactime_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_mactime_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MACTIME_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "mactime_enable_disable_reply",
    .handler = vl_api_mactime_enable_disable_reply_t_handler,
    .endian = vl_api_mactime_enable_disable_reply_t_endian,
    .format_fn = vl_api_mactime_enable_disable_reply_t_format,
    .size = sizeof(vl_api_mactime_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_mactime_enable_disable_reply_t_tojson,
    .fromjson = vl_api_mactime_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_mactime_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "mactime_enable_disable", api_mactime_enable_disable);
   hash_set_mem (vam->help_by_name, "mactime_enable_disable", "<intfc> [disable]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MACTIME_ADD_DEL_RANGE_REPLY + msg_id_base,
    .name = "mactime_add_del_range_reply",
    .handler = vl_api_mactime_add_del_range_reply_t_handler,
    .endian = vl_api_mactime_add_del_range_reply_t_endian,
    .format_fn = vl_api_mactime_add_del_range_reply_t_format,
    .size = sizeof(vl_api_mactime_add_del_range_reply_t),
    .traced = 1,
    .tojson = vl_api_mactime_add_del_range_reply_t_tojson,
    .fromjson = vl_api_mactime_add_del_range_reply_t_fromjson,
    .calc_size = vl_api_mactime_add_del_range_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "mactime_add_del_range", api_mactime_add_del_range);
   hash_set_mem (vam->help_by_name, "mactime_add_del_range", "name <devname> mac <mac-addr> allow drop allow-range Mon - Fri 9:00 - 17:00");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MACTIME_DETAILS + msg_id_base,
    .name = "mactime_details",
    .handler = vl_api_mactime_details_t_handler,
    .endian = vl_api_mactime_details_t_endian,
    .format_fn = vl_api_mactime_details_t_format,
    .size = sizeof(vl_api_mactime_details_t),
    .traced = 1,
    .tojson = vl_api_mactime_details_t_tojson,
    .fromjson = vl_api_mactime_details_t_fromjson,
    .calc_size = vl_api_mactime_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "mactime_dump", api_mactime_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   mactime_test_main_t * mainp = &mactime_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("mactime_f50faf9b");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "mactime plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
