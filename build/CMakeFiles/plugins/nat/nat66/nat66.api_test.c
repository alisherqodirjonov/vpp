#define vl_endianfun            /* define message structures */
#include "nat66.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "nat66.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "nat66.api.h"
#undef vl_printfun

#ifndef VL_API_NAT66_PLUGIN_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_nat66_plugin_enable_disable_reply_t_handler (vl_api_nat66_plugin_enable_disable_reply_t * mp) {
   vat_main_t * vam = nat66_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NAT66_ADD_DEL_INTERFACE_REPLY_T_HANDLER
static void
vl_api_nat66_add_del_interface_reply_t_handler (vl_api_nat66_add_del_interface_reply_t * mp) {
   vat_main_t * vam = nat66_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat66_interface_details_t_handler()) */
#ifndef VL_API_NAT66_ADD_DEL_STATIC_MAPPING_REPLY_T_HANDLER
static void
vl_api_nat66_add_del_static_mapping_reply_t_handler (vl_api_nat66_add_del_static_mapping_reply_t * mp) {
   vat_main_t * vam = nat66_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat66_static_mapping_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT66_PLUGIN_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "nat66_plugin_enable_disable_reply",
    .handler = vl_api_nat66_plugin_enable_disable_reply_t_handler,
    .endian = vl_api_nat66_plugin_enable_disable_reply_t_endian,
    .format_fn = vl_api_nat66_plugin_enable_disable_reply_t_format,
    .size = sizeof(vl_api_nat66_plugin_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_nat66_plugin_enable_disable_reply_t_tojson,
    .fromjson = vl_api_nat66_plugin_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_nat66_plugin_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat66_plugin_enable_disable", api_nat66_plugin_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT66_ADD_DEL_INTERFACE_REPLY + msg_id_base,
    .name = "nat66_add_del_interface_reply",
    .handler = vl_api_nat66_add_del_interface_reply_t_handler,
    .endian = vl_api_nat66_add_del_interface_reply_t_endian,
    .format_fn = vl_api_nat66_add_del_interface_reply_t_format,
    .size = sizeof(vl_api_nat66_add_del_interface_reply_t),
    .traced = 1,
    .tojson = vl_api_nat66_add_del_interface_reply_t_tojson,
    .fromjson = vl_api_nat66_add_del_interface_reply_t_fromjson,
    .calc_size = vl_api_nat66_add_del_interface_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat66_add_del_interface", api_nat66_add_del_interface);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT66_INTERFACE_DETAILS + msg_id_base,
    .name = "nat66_interface_details",
    .handler = vl_api_nat66_interface_details_t_handler,
    .endian = vl_api_nat66_interface_details_t_endian,
    .format_fn = vl_api_nat66_interface_details_t_format,
    .size = sizeof(vl_api_nat66_interface_details_t),
    .traced = 1,
    .tojson = vl_api_nat66_interface_details_t_tojson,
    .fromjson = vl_api_nat66_interface_details_t_fromjson,
    .calc_size = vl_api_nat66_interface_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat66_interface_dump", api_nat66_interface_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT66_ADD_DEL_STATIC_MAPPING_REPLY + msg_id_base,
    .name = "nat66_add_del_static_mapping_reply",
    .handler = vl_api_nat66_add_del_static_mapping_reply_t_handler,
    .endian = vl_api_nat66_add_del_static_mapping_reply_t_endian,
    .format_fn = vl_api_nat66_add_del_static_mapping_reply_t_format,
    .size = sizeof(vl_api_nat66_add_del_static_mapping_reply_t),
    .traced = 1,
    .tojson = vl_api_nat66_add_del_static_mapping_reply_t_tojson,
    .fromjson = vl_api_nat66_add_del_static_mapping_reply_t_fromjson,
    .calc_size = vl_api_nat66_add_del_static_mapping_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat66_add_del_static_mapping", api_nat66_add_del_static_mapping);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT66_STATIC_MAPPING_DETAILS + msg_id_base,
    .name = "nat66_static_mapping_details",
    .handler = vl_api_nat66_static_mapping_details_t_handler,
    .endian = vl_api_nat66_static_mapping_details_t_endian,
    .format_fn = vl_api_nat66_static_mapping_details_t_format,
    .size = sizeof(vl_api_nat66_static_mapping_details_t),
    .traced = 1,
    .tojson = vl_api_nat66_static_mapping_details_t_tojson,
    .fromjson = vl_api_nat66_static_mapping_details_t_fromjson,
    .calc_size = vl_api_nat66_static_mapping_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat66_static_mapping_dump", api_nat66_static_mapping_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   nat66_test_main_t * mainp = &nat66_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("nat66_5eeaa476");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "nat66 plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
