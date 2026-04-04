#define vl_endianfun            /* define message structures */
#include "abf.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "abf.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "abf.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_abf_plugin_get_version_reply_t_handler()) */
#ifndef VL_API_ABF_POLICY_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_abf_policy_add_del_reply_t_handler (vl_api_abf_policy_add_del_reply_t * mp) {
   vat_main_t * vam = abf_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_abf_policy_details_t_handler()) */
#ifndef VL_API_ABF_ITF_ATTACH_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_abf_itf_attach_add_del_reply_t_handler (vl_api_abf_itf_attach_add_del_reply_t * mp) {
   vat_main_t * vam = abf_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_abf_itf_attach_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ABF_PLUGIN_GET_VERSION_REPLY + msg_id_base,
    .name = "abf_plugin_get_version_reply",
    .handler = vl_api_abf_plugin_get_version_reply_t_handler,
    .endian = vl_api_abf_plugin_get_version_reply_t_endian,
    .format_fn = vl_api_abf_plugin_get_version_reply_t_format,
    .size = sizeof(vl_api_abf_plugin_get_version_reply_t),
    .traced = 1,
    .tojson = vl_api_abf_plugin_get_version_reply_t_tojson,
    .fromjson = vl_api_abf_plugin_get_version_reply_t_fromjson,
    .calc_size = vl_api_abf_plugin_get_version_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "abf_plugin_get_version", api_abf_plugin_get_version);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ABF_POLICY_ADD_DEL_REPLY + msg_id_base,
    .name = "abf_policy_add_del_reply",
    .handler = vl_api_abf_policy_add_del_reply_t_handler,
    .endian = vl_api_abf_policy_add_del_reply_t_endian,
    .format_fn = vl_api_abf_policy_add_del_reply_t_format,
    .size = sizeof(vl_api_abf_policy_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_abf_policy_add_del_reply_t_tojson,
    .fromjson = vl_api_abf_policy_add_del_reply_t_fromjson,
    .calc_size = vl_api_abf_policy_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "abf_policy_add_del", api_abf_policy_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ABF_POLICY_DETAILS + msg_id_base,
    .name = "abf_policy_details",
    .handler = vl_api_abf_policy_details_t_handler,
    .endian = vl_api_abf_policy_details_t_endian,
    .format_fn = vl_api_abf_policy_details_t_format,
    .size = sizeof(vl_api_abf_policy_details_t),
    .traced = 1,
    .tojson = vl_api_abf_policy_details_t_tojson,
    .fromjson = vl_api_abf_policy_details_t_fromjson,
    .calc_size = vl_api_abf_policy_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "abf_policy_dump", api_abf_policy_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ABF_ITF_ATTACH_ADD_DEL_REPLY + msg_id_base,
    .name = "abf_itf_attach_add_del_reply",
    .handler = vl_api_abf_itf_attach_add_del_reply_t_handler,
    .endian = vl_api_abf_itf_attach_add_del_reply_t_endian,
    .format_fn = vl_api_abf_itf_attach_add_del_reply_t_format,
    .size = sizeof(vl_api_abf_itf_attach_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_abf_itf_attach_add_del_reply_t_tojson,
    .fromjson = vl_api_abf_itf_attach_add_del_reply_t_fromjson,
    .calc_size = vl_api_abf_itf_attach_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "abf_itf_attach_add_del", api_abf_itf_attach_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ABF_ITF_ATTACH_DETAILS + msg_id_base,
    .name = "abf_itf_attach_details",
    .handler = vl_api_abf_itf_attach_details_t_handler,
    .endian = vl_api_abf_itf_attach_details_t_endian,
    .format_fn = vl_api_abf_itf_attach_details_t_format,
    .size = sizeof(vl_api_abf_itf_attach_details_t),
    .traced = 1,
    .tojson = vl_api_abf_itf_attach_details_t_tojson,
    .fromjson = vl_api_abf_itf_attach_details_t_fromjson,
    .calc_size = vl_api_abf_itf_attach_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "abf_itf_attach_dump", api_abf_itf_attach_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   abf_test_main_t * mainp = &abf_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("abf_70fd229c");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "abf plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
