#define vl_endianfun            /* define message structures */
#include "vpe.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "vpe.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "vpe.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_show_version_reply_t_handler()) */
/* Generation not supported (vl_api_show_vpe_system_time_reply_t_handler()) */
/* Generation not supported (vl_api_log_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SHOW_VERSION_REPLY + msg_id_base,
    .name = "show_version_reply",
    .handler = vl_api_show_version_reply_t_handler,
    .endian = vl_api_show_version_reply_t_endian,
    .format_fn = vl_api_show_version_reply_t_format,
    .size = sizeof(vl_api_show_version_reply_t),
    .traced = 1,
    .tojson = vl_api_show_version_reply_t_tojson,
    .fromjson = vl_api_show_version_reply_t_fromjson,
    .calc_size = vl_api_show_version_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "show_version", api_show_version);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SHOW_VPE_SYSTEM_TIME_REPLY + msg_id_base,
    .name = "show_vpe_system_time_reply",
    .handler = vl_api_show_vpe_system_time_reply_t_handler,
    .endian = vl_api_show_vpe_system_time_reply_t_endian,
    .format_fn = vl_api_show_vpe_system_time_reply_t_format,
    .size = sizeof(vl_api_show_vpe_system_time_reply_t),
    .traced = 1,
    .tojson = vl_api_show_vpe_system_time_reply_t_tojson,
    .fromjson = vl_api_show_vpe_system_time_reply_t_fromjson,
    .calc_size = vl_api_show_vpe_system_time_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "show_vpe_system_time", api_show_vpe_system_time);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_LOG_DETAILS + msg_id_base,
    .name = "log_details",
    .handler = vl_api_log_details_t_handler,
    .endian = vl_api_log_details_t_endian,
    .format_fn = vl_api_log_details_t_format,
    .size = sizeof(vl_api_log_details_t),
    .traced = 1,
    .tojson = vl_api_log_details_t_tojson,
    .fromjson = vl_api_log_details_t_fromjson,
    .calc_size = vl_api_log_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "log_dump", api_log_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   vpe_test_main_t * mainp = &vpe_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("vpe_33b45969");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "vpe plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
