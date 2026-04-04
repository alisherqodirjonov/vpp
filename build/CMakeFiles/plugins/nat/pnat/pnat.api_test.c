#define vl_endianfun            /* define message structures */
#include "pnat.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "pnat.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "pnat.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_pnat_bindings_get_reply_t_handler()) */
/* Generation not supported (vl_api_pnat_interfaces_get_reply_t_handler()) */
/* Generation not supported (vl_api_pnat_binding_add_reply_t_handler()) */
/* Generation not supported (vl_api_pnat_binding_add_v2_reply_t_handler()) */
#ifndef VL_API_PNAT_BINDING_DEL_REPLY_T_HANDLER
static void
vl_api_pnat_binding_del_reply_t_handler (vl_api_pnat_binding_del_reply_t * mp) {
   vat_main_t * vam = pnat_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_PNAT_BINDING_ATTACH_REPLY_T_HANDLER
static void
vl_api_pnat_binding_attach_reply_t_handler (vl_api_pnat_binding_attach_reply_t * mp) {
   vat_main_t * vam = pnat_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_PNAT_BINDING_DETACH_REPLY_T_HANDLER
static void
vl_api_pnat_binding_detach_reply_t_handler (vl_api_pnat_binding_detach_reply_t * mp) {
   vat_main_t * vam = pnat_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_pnat_flow_lookup_reply_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PNAT_BINDINGS_GET_REPLY + msg_id_base,
    .name = "pnat_bindings_get_reply",
    .handler = vl_api_pnat_bindings_get_reply_t_handler,
    .endian = vl_api_pnat_bindings_get_reply_t_endian,
    .format_fn = vl_api_pnat_bindings_get_reply_t_format,
    .size = sizeof(vl_api_pnat_bindings_get_reply_t),
    .traced = 1,
    .tojson = vl_api_pnat_bindings_get_reply_t_tojson,
    .fromjson = vl_api_pnat_bindings_get_reply_t_fromjson,
    .calc_size = vl_api_pnat_bindings_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "pnat_bindings_get", api_pnat_bindings_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PNAT_INTERFACES_GET_REPLY + msg_id_base,
    .name = "pnat_interfaces_get_reply",
    .handler = vl_api_pnat_interfaces_get_reply_t_handler,
    .endian = vl_api_pnat_interfaces_get_reply_t_endian,
    .format_fn = vl_api_pnat_interfaces_get_reply_t_format,
    .size = sizeof(vl_api_pnat_interfaces_get_reply_t),
    .traced = 1,
    .tojson = vl_api_pnat_interfaces_get_reply_t_tojson,
    .fromjson = vl_api_pnat_interfaces_get_reply_t_fromjson,
    .calc_size = vl_api_pnat_interfaces_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "pnat_interfaces_get", api_pnat_interfaces_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PNAT_BINDING_ADD_REPLY + msg_id_base,
    .name = "pnat_binding_add_reply",
    .handler = vl_api_pnat_binding_add_reply_t_handler,
    .endian = vl_api_pnat_binding_add_reply_t_endian,
    .format_fn = vl_api_pnat_binding_add_reply_t_format,
    .size = sizeof(vl_api_pnat_binding_add_reply_t),
    .traced = 1,
    .tojson = vl_api_pnat_binding_add_reply_t_tojson,
    .fromjson = vl_api_pnat_binding_add_reply_t_fromjson,
    .calc_size = vl_api_pnat_binding_add_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "pnat_binding_add", api_pnat_binding_add);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PNAT_BINDING_ADD_V2_REPLY + msg_id_base,
    .name = "pnat_binding_add_v2_reply",
    .handler = vl_api_pnat_binding_add_v2_reply_t_handler,
    .endian = vl_api_pnat_binding_add_v2_reply_t_endian,
    .format_fn = vl_api_pnat_binding_add_v2_reply_t_format,
    .size = sizeof(vl_api_pnat_binding_add_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_pnat_binding_add_v2_reply_t_tojson,
    .fromjson = vl_api_pnat_binding_add_v2_reply_t_fromjson,
    .calc_size = vl_api_pnat_binding_add_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "pnat_binding_add_v2", api_pnat_binding_add_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PNAT_BINDING_DEL_REPLY + msg_id_base,
    .name = "pnat_binding_del_reply",
    .handler = vl_api_pnat_binding_del_reply_t_handler,
    .endian = vl_api_pnat_binding_del_reply_t_endian,
    .format_fn = vl_api_pnat_binding_del_reply_t_format,
    .size = sizeof(vl_api_pnat_binding_del_reply_t),
    .traced = 1,
    .tojson = vl_api_pnat_binding_del_reply_t_tojson,
    .fromjson = vl_api_pnat_binding_del_reply_t_fromjson,
    .calc_size = vl_api_pnat_binding_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "pnat_binding_del", api_pnat_binding_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PNAT_BINDING_ATTACH_REPLY + msg_id_base,
    .name = "pnat_binding_attach_reply",
    .handler = vl_api_pnat_binding_attach_reply_t_handler,
    .endian = vl_api_pnat_binding_attach_reply_t_endian,
    .format_fn = vl_api_pnat_binding_attach_reply_t_format,
    .size = sizeof(vl_api_pnat_binding_attach_reply_t),
    .traced = 1,
    .tojson = vl_api_pnat_binding_attach_reply_t_tojson,
    .fromjson = vl_api_pnat_binding_attach_reply_t_fromjson,
    .calc_size = vl_api_pnat_binding_attach_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "pnat_binding_attach", api_pnat_binding_attach);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PNAT_BINDING_DETACH_REPLY + msg_id_base,
    .name = "pnat_binding_detach_reply",
    .handler = vl_api_pnat_binding_detach_reply_t_handler,
    .endian = vl_api_pnat_binding_detach_reply_t_endian,
    .format_fn = vl_api_pnat_binding_detach_reply_t_format,
    .size = sizeof(vl_api_pnat_binding_detach_reply_t),
    .traced = 1,
    .tojson = vl_api_pnat_binding_detach_reply_t_tojson,
    .fromjson = vl_api_pnat_binding_detach_reply_t_fromjson,
    .calc_size = vl_api_pnat_binding_detach_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "pnat_binding_detach", api_pnat_binding_detach);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PNAT_FLOW_LOOKUP_REPLY + msg_id_base,
    .name = "pnat_flow_lookup_reply",
    .handler = vl_api_pnat_flow_lookup_reply_t_handler,
    .endian = vl_api_pnat_flow_lookup_reply_t_endian,
    .format_fn = vl_api_pnat_flow_lookup_reply_t_format,
    .size = sizeof(vl_api_pnat_flow_lookup_reply_t),
    .traced = 1,
    .tojson = vl_api_pnat_flow_lookup_reply_t_tojson,
    .fromjson = vl_api_pnat_flow_lookup_reply_t_fromjson,
    .calc_size = vl_api_pnat_flow_lookup_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "pnat_flow_lookup", api_pnat_flow_lookup);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   pnat_test_main_t * mainp = &pnat_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("pnat_ec06ec84");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "pnat plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
