#define vl_endianfun            /* define message structures */
#include "lisp_gpe.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "lisp_gpe.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "lisp_gpe.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_gpe_add_del_fwd_entry_reply_t_handler()) */
#ifndef VL_API_GPE_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_gpe_enable_disable_reply_t_handler (vl_api_gpe_enable_disable_reply_t * mp) {
   vat_main_t * vam = lisp_gpe_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_GPE_ADD_DEL_IFACE_REPLY_T_HANDLER
static void
vl_api_gpe_add_del_iface_reply_t_handler (vl_api_gpe_add_del_iface_reply_t * mp) {
   vat_main_t * vam = lisp_gpe_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_gpe_fwd_entry_vnis_get_reply_t_handler()) */
/* Generation not supported (vl_api_gpe_fwd_entries_get_reply_t_handler()) */
/* Generation not supported (vl_api_gpe_fwd_entry_path_details_t_handler()) */
#ifndef VL_API_GPE_SET_ENCAP_MODE_REPLY_T_HANDLER
static void
vl_api_gpe_set_encap_mode_reply_t_handler (vl_api_gpe_set_encap_mode_reply_t * mp) {
   vat_main_t * vam = lisp_gpe_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_gpe_get_encap_mode_reply_t_handler()) */
#ifndef VL_API_GPE_ADD_DEL_NATIVE_FWD_RPATH_REPLY_T_HANDLER
static void
vl_api_gpe_add_del_native_fwd_rpath_reply_t_handler (vl_api_gpe_add_del_native_fwd_rpath_reply_t * mp) {
   vat_main_t * vam = lisp_gpe_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_gpe_native_fwd_rpaths_get_reply_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GPE_ADD_DEL_FWD_ENTRY_REPLY + msg_id_base,
    .name = "gpe_add_del_fwd_entry_reply",
    .handler = vl_api_gpe_add_del_fwd_entry_reply_t_handler,
    .endian = vl_api_gpe_add_del_fwd_entry_reply_t_endian,
    .format_fn = vl_api_gpe_add_del_fwd_entry_reply_t_format,
    .size = sizeof(vl_api_gpe_add_del_fwd_entry_reply_t),
    .traced = 1,
    .tojson = vl_api_gpe_add_del_fwd_entry_reply_t_tojson,
    .fromjson = vl_api_gpe_add_del_fwd_entry_reply_t_fromjson,
    .calc_size = vl_api_gpe_add_del_fwd_entry_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "gpe_add_del_fwd_entry", api_gpe_add_del_fwd_entry);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GPE_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "gpe_enable_disable_reply",
    .handler = vl_api_gpe_enable_disable_reply_t_handler,
    .endian = vl_api_gpe_enable_disable_reply_t_endian,
    .format_fn = vl_api_gpe_enable_disable_reply_t_format,
    .size = sizeof(vl_api_gpe_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_gpe_enable_disable_reply_t_tojson,
    .fromjson = vl_api_gpe_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_gpe_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "gpe_enable_disable", api_gpe_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GPE_ADD_DEL_IFACE_REPLY + msg_id_base,
    .name = "gpe_add_del_iface_reply",
    .handler = vl_api_gpe_add_del_iface_reply_t_handler,
    .endian = vl_api_gpe_add_del_iface_reply_t_endian,
    .format_fn = vl_api_gpe_add_del_iface_reply_t_format,
    .size = sizeof(vl_api_gpe_add_del_iface_reply_t),
    .traced = 1,
    .tojson = vl_api_gpe_add_del_iface_reply_t_tojson,
    .fromjson = vl_api_gpe_add_del_iface_reply_t_fromjson,
    .calc_size = vl_api_gpe_add_del_iface_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "gpe_add_del_iface", api_gpe_add_del_iface);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GPE_FWD_ENTRY_VNIS_GET_REPLY + msg_id_base,
    .name = "gpe_fwd_entry_vnis_get_reply",
    .handler = vl_api_gpe_fwd_entry_vnis_get_reply_t_handler,
    .endian = vl_api_gpe_fwd_entry_vnis_get_reply_t_endian,
    .format_fn = vl_api_gpe_fwd_entry_vnis_get_reply_t_format,
    .size = sizeof(vl_api_gpe_fwd_entry_vnis_get_reply_t),
    .traced = 1,
    .tojson = vl_api_gpe_fwd_entry_vnis_get_reply_t_tojson,
    .fromjson = vl_api_gpe_fwd_entry_vnis_get_reply_t_fromjson,
    .calc_size = vl_api_gpe_fwd_entry_vnis_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "gpe_fwd_entry_vnis_get", api_gpe_fwd_entry_vnis_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GPE_FWD_ENTRIES_GET_REPLY + msg_id_base,
    .name = "gpe_fwd_entries_get_reply",
    .handler = vl_api_gpe_fwd_entries_get_reply_t_handler,
    .endian = vl_api_gpe_fwd_entries_get_reply_t_endian,
    .format_fn = vl_api_gpe_fwd_entries_get_reply_t_format,
    .size = sizeof(vl_api_gpe_fwd_entries_get_reply_t),
    .traced = 1,
    .tojson = vl_api_gpe_fwd_entries_get_reply_t_tojson,
    .fromjson = vl_api_gpe_fwd_entries_get_reply_t_fromjson,
    .calc_size = vl_api_gpe_fwd_entries_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "gpe_fwd_entries_get", api_gpe_fwd_entries_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GPE_FWD_ENTRY_PATH_DETAILS + msg_id_base,
    .name = "gpe_fwd_entry_path_details",
    .handler = vl_api_gpe_fwd_entry_path_details_t_handler,
    .endian = vl_api_gpe_fwd_entry_path_details_t_endian,
    .format_fn = vl_api_gpe_fwd_entry_path_details_t_format,
    .size = sizeof(vl_api_gpe_fwd_entry_path_details_t),
    .traced = 1,
    .tojson = vl_api_gpe_fwd_entry_path_details_t_tojson,
    .fromjson = vl_api_gpe_fwd_entry_path_details_t_fromjson,
    .calc_size = vl_api_gpe_fwd_entry_path_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "gpe_fwd_entry_path_dump", api_gpe_fwd_entry_path_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GPE_SET_ENCAP_MODE_REPLY + msg_id_base,
    .name = "gpe_set_encap_mode_reply",
    .handler = vl_api_gpe_set_encap_mode_reply_t_handler,
    .endian = vl_api_gpe_set_encap_mode_reply_t_endian,
    .format_fn = vl_api_gpe_set_encap_mode_reply_t_format,
    .size = sizeof(vl_api_gpe_set_encap_mode_reply_t),
    .traced = 1,
    .tojson = vl_api_gpe_set_encap_mode_reply_t_tojson,
    .fromjson = vl_api_gpe_set_encap_mode_reply_t_fromjson,
    .calc_size = vl_api_gpe_set_encap_mode_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "gpe_set_encap_mode", api_gpe_set_encap_mode);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GPE_GET_ENCAP_MODE_REPLY + msg_id_base,
    .name = "gpe_get_encap_mode_reply",
    .handler = vl_api_gpe_get_encap_mode_reply_t_handler,
    .endian = vl_api_gpe_get_encap_mode_reply_t_endian,
    .format_fn = vl_api_gpe_get_encap_mode_reply_t_format,
    .size = sizeof(vl_api_gpe_get_encap_mode_reply_t),
    .traced = 1,
    .tojson = vl_api_gpe_get_encap_mode_reply_t_tojson,
    .fromjson = vl_api_gpe_get_encap_mode_reply_t_fromjson,
    .calc_size = vl_api_gpe_get_encap_mode_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "gpe_get_encap_mode", api_gpe_get_encap_mode);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GPE_ADD_DEL_NATIVE_FWD_RPATH_REPLY + msg_id_base,
    .name = "gpe_add_del_native_fwd_rpath_reply",
    .handler = vl_api_gpe_add_del_native_fwd_rpath_reply_t_handler,
    .endian = vl_api_gpe_add_del_native_fwd_rpath_reply_t_endian,
    .format_fn = vl_api_gpe_add_del_native_fwd_rpath_reply_t_format,
    .size = sizeof(vl_api_gpe_add_del_native_fwd_rpath_reply_t),
    .traced = 1,
    .tojson = vl_api_gpe_add_del_native_fwd_rpath_reply_t_tojson,
    .fromjson = vl_api_gpe_add_del_native_fwd_rpath_reply_t_fromjson,
    .calc_size = vl_api_gpe_add_del_native_fwd_rpath_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "gpe_add_del_native_fwd_rpath", api_gpe_add_del_native_fwd_rpath);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GPE_NATIVE_FWD_RPATHS_GET_REPLY + msg_id_base,
    .name = "gpe_native_fwd_rpaths_get_reply",
    .handler = vl_api_gpe_native_fwd_rpaths_get_reply_t_handler,
    .endian = vl_api_gpe_native_fwd_rpaths_get_reply_t_endian,
    .format_fn = vl_api_gpe_native_fwd_rpaths_get_reply_t_format,
    .size = sizeof(vl_api_gpe_native_fwd_rpaths_get_reply_t),
    .traced = 1,
    .tojson = vl_api_gpe_native_fwd_rpaths_get_reply_t_tojson,
    .fromjson = vl_api_gpe_native_fwd_rpaths_get_reply_t_fromjson,
    .calc_size = vl_api_gpe_native_fwd_rpaths_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "gpe_native_fwd_rpaths_get", api_gpe_native_fwd_rpaths_get);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   lisp_gpe_test_main_t * mainp = &lisp_gpe_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("lisp_gpe_29addfc9");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "lisp_gpe plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
