#define vl_endianfun            /* define message structures */
#include "cnat.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "cnat.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "cnat.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_cnat_translation_update_reply_t_handler()) */
#ifndef VL_API_CNAT_TRANSLATION_DEL_REPLY_T_HANDLER
static void
vl_api_cnat_translation_del_reply_t_handler (vl_api_cnat_translation_del_reply_t * mp) {
   vat_main_t * vam = cnat_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_cnat_translation_details_t_handler()) */
#ifndef VL_API_CNAT_SESSION_PURGE_REPLY_T_HANDLER
static void
vl_api_cnat_session_purge_reply_t_handler (vl_api_cnat_session_purge_reply_t * mp) {
   vat_main_t * vam = cnat_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_cnat_session_details_t_handler()) */
#ifndef VL_API_CNAT_SET_SNAT_ADDRESSES_REPLY_T_HANDLER
static void
vl_api_cnat_set_snat_addresses_reply_t_handler (vl_api_cnat_set_snat_addresses_reply_t * mp) {
   vat_main_t * vam = cnat_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_cnat_get_snat_addresses_reply_t_handler()) */
#ifndef VL_API_CNAT_SNAT_POLICY_ADD_DEL_EXCLUDE_PFX_REPLY_T_HANDLER
static void
vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t_handler (vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t * mp) {
   vat_main_t * vam = cnat_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_CNAT_SNAT_POLICY_ADD_DEL_IF_REPLY_T_HANDLER
static void
vl_api_cnat_snat_policy_add_del_if_reply_t_handler (vl_api_cnat_snat_policy_add_del_if_reply_t * mp) {
   vat_main_t * vam = cnat_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_CNAT_SET_SNAT_POLICY_REPLY_T_HANDLER
static void
vl_api_cnat_set_snat_policy_reply_t_handler (vl_api_cnat_set_snat_policy_reply_t * mp) {
   vat_main_t * vam = cnat_test_main.vat_main;
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
    .id = VL_API_CNAT_TRANSLATION_UPDATE_REPLY + msg_id_base,
    .name = "cnat_translation_update_reply",
    .handler = vl_api_cnat_translation_update_reply_t_handler,
    .endian = vl_api_cnat_translation_update_reply_t_endian,
    .format_fn = vl_api_cnat_translation_update_reply_t_format,
    .size = sizeof(vl_api_cnat_translation_update_reply_t),
    .traced = 1,
    .tojson = vl_api_cnat_translation_update_reply_t_tojson,
    .fromjson = vl_api_cnat_translation_update_reply_t_fromjson,
    .calc_size = vl_api_cnat_translation_update_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "cnat_translation_update", api_cnat_translation_update);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CNAT_TRANSLATION_DEL_REPLY + msg_id_base,
    .name = "cnat_translation_del_reply",
    .handler = vl_api_cnat_translation_del_reply_t_handler,
    .endian = vl_api_cnat_translation_del_reply_t_endian,
    .format_fn = vl_api_cnat_translation_del_reply_t_format,
    .size = sizeof(vl_api_cnat_translation_del_reply_t),
    .traced = 1,
    .tojson = vl_api_cnat_translation_del_reply_t_tojson,
    .fromjson = vl_api_cnat_translation_del_reply_t_fromjson,
    .calc_size = vl_api_cnat_translation_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "cnat_translation_del", api_cnat_translation_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CNAT_TRANSLATION_DETAILS + msg_id_base,
    .name = "cnat_translation_details",
    .handler = vl_api_cnat_translation_details_t_handler,
    .endian = vl_api_cnat_translation_details_t_endian,
    .format_fn = vl_api_cnat_translation_details_t_format,
    .size = sizeof(vl_api_cnat_translation_details_t),
    .traced = 1,
    .tojson = vl_api_cnat_translation_details_t_tojson,
    .fromjson = vl_api_cnat_translation_details_t_fromjson,
    .calc_size = vl_api_cnat_translation_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "cnat_translation_dump", api_cnat_translation_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CNAT_SESSION_PURGE_REPLY + msg_id_base,
    .name = "cnat_session_purge_reply",
    .handler = vl_api_cnat_session_purge_reply_t_handler,
    .endian = vl_api_cnat_session_purge_reply_t_endian,
    .format_fn = vl_api_cnat_session_purge_reply_t_format,
    .size = sizeof(vl_api_cnat_session_purge_reply_t),
    .traced = 1,
    .tojson = vl_api_cnat_session_purge_reply_t_tojson,
    .fromjson = vl_api_cnat_session_purge_reply_t_fromjson,
    .calc_size = vl_api_cnat_session_purge_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "cnat_session_purge", api_cnat_session_purge);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CNAT_SESSION_DETAILS + msg_id_base,
    .name = "cnat_session_details",
    .handler = vl_api_cnat_session_details_t_handler,
    .endian = vl_api_cnat_session_details_t_endian,
    .format_fn = vl_api_cnat_session_details_t_format,
    .size = sizeof(vl_api_cnat_session_details_t),
    .traced = 1,
    .tojson = vl_api_cnat_session_details_t_tojson,
    .fromjson = vl_api_cnat_session_details_t_fromjson,
    .calc_size = vl_api_cnat_session_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "cnat_session_dump", api_cnat_session_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CNAT_SET_SNAT_ADDRESSES_REPLY + msg_id_base,
    .name = "cnat_set_snat_addresses_reply",
    .handler = vl_api_cnat_set_snat_addresses_reply_t_handler,
    .endian = vl_api_cnat_set_snat_addresses_reply_t_endian,
    .format_fn = vl_api_cnat_set_snat_addresses_reply_t_format,
    .size = sizeof(vl_api_cnat_set_snat_addresses_reply_t),
    .traced = 1,
    .tojson = vl_api_cnat_set_snat_addresses_reply_t_tojson,
    .fromjson = vl_api_cnat_set_snat_addresses_reply_t_fromjson,
    .calc_size = vl_api_cnat_set_snat_addresses_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "cnat_set_snat_addresses", api_cnat_set_snat_addresses);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CNAT_GET_SNAT_ADDRESSES_REPLY + msg_id_base,
    .name = "cnat_get_snat_addresses_reply",
    .handler = vl_api_cnat_get_snat_addresses_reply_t_handler,
    .endian = vl_api_cnat_get_snat_addresses_reply_t_endian,
    .format_fn = vl_api_cnat_get_snat_addresses_reply_t_format,
    .size = sizeof(vl_api_cnat_get_snat_addresses_reply_t),
    .traced = 1,
    .tojson = vl_api_cnat_get_snat_addresses_reply_t_tojson,
    .fromjson = vl_api_cnat_get_snat_addresses_reply_t_fromjson,
    .calc_size = vl_api_cnat_get_snat_addresses_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "cnat_get_snat_addresses", api_cnat_get_snat_addresses);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CNAT_SNAT_POLICY_ADD_DEL_EXCLUDE_PFX_REPLY + msg_id_base,
    .name = "cnat_snat_policy_add_del_exclude_pfx_reply",
    .handler = vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t_handler,
    .endian = vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t_endian,
    .format_fn = vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t_format,
    .size = sizeof(vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t),
    .traced = 1,
    .tojson = vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t_tojson,
    .fromjson = vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t_fromjson,
    .calc_size = vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "cnat_snat_policy_add_del_exclude_pfx", api_cnat_snat_policy_add_del_exclude_pfx);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CNAT_SNAT_POLICY_ADD_DEL_IF_REPLY + msg_id_base,
    .name = "cnat_snat_policy_add_del_if_reply",
    .handler = vl_api_cnat_snat_policy_add_del_if_reply_t_handler,
    .endian = vl_api_cnat_snat_policy_add_del_if_reply_t_endian,
    .format_fn = vl_api_cnat_snat_policy_add_del_if_reply_t_format,
    .size = sizeof(vl_api_cnat_snat_policy_add_del_if_reply_t),
    .traced = 1,
    .tojson = vl_api_cnat_snat_policy_add_del_if_reply_t_tojson,
    .fromjson = vl_api_cnat_snat_policy_add_del_if_reply_t_fromjson,
    .calc_size = vl_api_cnat_snat_policy_add_del_if_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "cnat_snat_policy_add_del_if", api_cnat_snat_policy_add_del_if);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CNAT_SET_SNAT_POLICY_REPLY + msg_id_base,
    .name = "cnat_set_snat_policy_reply",
    .handler = vl_api_cnat_set_snat_policy_reply_t_handler,
    .endian = vl_api_cnat_set_snat_policy_reply_t_endian,
    .format_fn = vl_api_cnat_set_snat_policy_reply_t_format,
    .size = sizeof(vl_api_cnat_set_snat_policy_reply_t),
    .traced = 1,
    .tojson = vl_api_cnat_set_snat_policy_reply_t_tojson,
    .fromjson = vl_api_cnat_set_snat_policy_reply_t_fromjson,
    .calc_size = vl_api_cnat_set_snat_policy_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "cnat_set_snat_policy", api_cnat_set_snat_policy);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   cnat_test_main_t * mainp = &cnat_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("cnat_10708a40");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "cnat plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
