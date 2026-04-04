#define vl_endianfun            /* define message structures */
#include "nat64.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "nat64.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "nat64.api.h"
#undef vl_printfun

#ifndef VL_API_NAT64_PLUGIN_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_nat64_plugin_enable_disable_reply_t_handler (vl_api_nat64_plugin_enable_disable_reply_t * mp) {
   vat_main_t * vam = nat64_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_NAT64_SET_TIMEOUTS_REPLY_T_HANDLER
static void
vl_api_nat64_set_timeouts_reply_t_handler (vl_api_nat64_set_timeouts_reply_t * mp) {
   vat_main_t * vam = nat64_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat64_get_timeouts_reply_t_handler()) */
#ifndef VL_API_NAT64_ADD_DEL_POOL_ADDR_RANGE_REPLY_T_HANDLER
static void
vl_api_nat64_add_del_pool_addr_range_reply_t_handler (vl_api_nat64_add_del_pool_addr_range_reply_t * mp) {
   vat_main_t * vam = nat64_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat64_pool_addr_details_t_handler()) */
#ifndef VL_API_NAT64_ADD_DEL_INTERFACE_REPLY_T_HANDLER
static void
vl_api_nat64_add_del_interface_reply_t_handler (vl_api_nat64_add_del_interface_reply_t * mp) {
   vat_main_t * vam = nat64_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat64_interface_details_t_handler()) */
#ifndef VL_API_NAT64_ADD_DEL_STATIC_BIB_REPLY_T_HANDLER
static void
vl_api_nat64_add_del_static_bib_reply_t_handler (vl_api_nat64_add_del_static_bib_reply_t * mp) {
   vat_main_t * vam = nat64_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat64_bib_details_t_handler()) */
/* Generation not supported (vl_api_nat64_st_details_t_handler()) */
#ifndef VL_API_NAT64_ADD_DEL_PREFIX_REPLY_T_HANDLER
static void
vl_api_nat64_add_del_prefix_reply_t_handler (vl_api_nat64_add_del_prefix_reply_t * mp) {
   vat_main_t * vam = nat64_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_nat64_prefix_details_t_handler()) */
#ifndef VL_API_NAT64_ADD_DEL_INTERFACE_ADDR_REPLY_T_HANDLER
static void
vl_api_nat64_add_del_interface_addr_reply_t_handler (vl_api_nat64_add_del_interface_addr_reply_t * mp) {
   vat_main_t * vam = nat64_test_main.vat_main;
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
    .id = VL_API_NAT64_PLUGIN_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "nat64_plugin_enable_disable_reply",
    .handler = vl_api_nat64_plugin_enable_disable_reply_t_handler,
    .endian = vl_api_nat64_plugin_enable_disable_reply_t_endian,
    .format_fn = vl_api_nat64_plugin_enable_disable_reply_t_format,
    .size = sizeof(vl_api_nat64_plugin_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_nat64_plugin_enable_disable_reply_t_tojson,
    .fromjson = vl_api_nat64_plugin_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_nat64_plugin_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat64_plugin_enable_disable", api_nat64_plugin_enable_disable);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT64_SET_TIMEOUTS_REPLY + msg_id_base,
    .name = "nat64_set_timeouts_reply",
    .handler = vl_api_nat64_set_timeouts_reply_t_handler,
    .endian = vl_api_nat64_set_timeouts_reply_t_endian,
    .format_fn = vl_api_nat64_set_timeouts_reply_t_format,
    .size = sizeof(vl_api_nat64_set_timeouts_reply_t),
    .traced = 1,
    .tojson = vl_api_nat64_set_timeouts_reply_t_tojson,
    .fromjson = vl_api_nat64_set_timeouts_reply_t_fromjson,
    .calc_size = vl_api_nat64_set_timeouts_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat64_set_timeouts", api_nat64_set_timeouts);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT64_GET_TIMEOUTS_REPLY + msg_id_base,
    .name = "nat64_get_timeouts_reply",
    .handler = vl_api_nat64_get_timeouts_reply_t_handler,
    .endian = vl_api_nat64_get_timeouts_reply_t_endian,
    .format_fn = vl_api_nat64_get_timeouts_reply_t_format,
    .size = sizeof(vl_api_nat64_get_timeouts_reply_t),
    .traced = 1,
    .tojson = vl_api_nat64_get_timeouts_reply_t_tojson,
    .fromjson = vl_api_nat64_get_timeouts_reply_t_fromjson,
    .calc_size = vl_api_nat64_get_timeouts_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat64_get_timeouts", api_nat64_get_timeouts);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT64_ADD_DEL_POOL_ADDR_RANGE_REPLY + msg_id_base,
    .name = "nat64_add_del_pool_addr_range_reply",
    .handler = vl_api_nat64_add_del_pool_addr_range_reply_t_handler,
    .endian = vl_api_nat64_add_del_pool_addr_range_reply_t_endian,
    .format_fn = vl_api_nat64_add_del_pool_addr_range_reply_t_format,
    .size = sizeof(vl_api_nat64_add_del_pool_addr_range_reply_t),
    .traced = 1,
    .tojson = vl_api_nat64_add_del_pool_addr_range_reply_t_tojson,
    .fromjson = vl_api_nat64_add_del_pool_addr_range_reply_t_fromjson,
    .calc_size = vl_api_nat64_add_del_pool_addr_range_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat64_add_del_pool_addr_range", api_nat64_add_del_pool_addr_range);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT64_POOL_ADDR_DETAILS + msg_id_base,
    .name = "nat64_pool_addr_details",
    .handler = vl_api_nat64_pool_addr_details_t_handler,
    .endian = vl_api_nat64_pool_addr_details_t_endian,
    .format_fn = vl_api_nat64_pool_addr_details_t_format,
    .size = sizeof(vl_api_nat64_pool_addr_details_t),
    .traced = 1,
    .tojson = vl_api_nat64_pool_addr_details_t_tojson,
    .fromjson = vl_api_nat64_pool_addr_details_t_fromjson,
    .calc_size = vl_api_nat64_pool_addr_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat64_pool_addr_dump", api_nat64_pool_addr_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT64_ADD_DEL_INTERFACE_REPLY + msg_id_base,
    .name = "nat64_add_del_interface_reply",
    .handler = vl_api_nat64_add_del_interface_reply_t_handler,
    .endian = vl_api_nat64_add_del_interface_reply_t_endian,
    .format_fn = vl_api_nat64_add_del_interface_reply_t_format,
    .size = sizeof(vl_api_nat64_add_del_interface_reply_t),
    .traced = 1,
    .tojson = vl_api_nat64_add_del_interface_reply_t_tojson,
    .fromjson = vl_api_nat64_add_del_interface_reply_t_fromjson,
    .calc_size = vl_api_nat64_add_del_interface_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat64_add_del_interface", api_nat64_add_del_interface);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT64_INTERFACE_DETAILS + msg_id_base,
    .name = "nat64_interface_details",
    .handler = vl_api_nat64_interface_details_t_handler,
    .endian = vl_api_nat64_interface_details_t_endian,
    .format_fn = vl_api_nat64_interface_details_t_format,
    .size = sizeof(vl_api_nat64_interface_details_t),
    .traced = 1,
    .tojson = vl_api_nat64_interface_details_t_tojson,
    .fromjson = vl_api_nat64_interface_details_t_fromjson,
    .calc_size = vl_api_nat64_interface_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat64_interface_dump", api_nat64_interface_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT64_ADD_DEL_STATIC_BIB_REPLY + msg_id_base,
    .name = "nat64_add_del_static_bib_reply",
    .handler = vl_api_nat64_add_del_static_bib_reply_t_handler,
    .endian = vl_api_nat64_add_del_static_bib_reply_t_endian,
    .format_fn = vl_api_nat64_add_del_static_bib_reply_t_format,
    .size = sizeof(vl_api_nat64_add_del_static_bib_reply_t),
    .traced = 1,
    .tojson = vl_api_nat64_add_del_static_bib_reply_t_tojson,
    .fromjson = vl_api_nat64_add_del_static_bib_reply_t_fromjson,
    .calc_size = vl_api_nat64_add_del_static_bib_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat64_add_del_static_bib", api_nat64_add_del_static_bib);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT64_BIB_DETAILS + msg_id_base,
    .name = "nat64_bib_details",
    .handler = vl_api_nat64_bib_details_t_handler,
    .endian = vl_api_nat64_bib_details_t_endian,
    .format_fn = vl_api_nat64_bib_details_t_format,
    .size = sizeof(vl_api_nat64_bib_details_t),
    .traced = 1,
    .tojson = vl_api_nat64_bib_details_t_tojson,
    .fromjson = vl_api_nat64_bib_details_t_fromjson,
    .calc_size = vl_api_nat64_bib_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat64_bib_dump", api_nat64_bib_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT64_ST_DETAILS + msg_id_base,
    .name = "nat64_st_details",
    .handler = vl_api_nat64_st_details_t_handler,
    .endian = vl_api_nat64_st_details_t_endian,
    .format_fn = vl_api_nat64_st_details_t_format,
    .size = sizeof(vl_api_nat64_st_details_t),
    .traced = 1,
    .tojson = vl_api_nat64_st_details_t_tojson,
    .fromjson = vl_api_nat64_st_details_t_fromjson,
    .calc_size = vl_api_nat64_st_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat64_st_dump", api_nat64_st_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT64_ADD_DEL_PREFIX_REPLY + msg_id_base,
    .name = "nat64_add_del_prefix_reply",
    .handler = vl_api_nat64_add_del_prefix_reply_t_handler,
    .endian = vl_api_nat64_add_del_prefix_reply_t_endian,
    .format_fn = vl_api_nat64_add_del_prefix_reply_t_format,
    .size = sizeof(vl_api_nat64_add_del_prefix_reply_t),
    .traced = 1,
    .tojson = vl_api_nat64_add_del_prefix_reply_t_tojson,
    .fromjson = vl_api_nat64_add_del_prefix_reply_t_fromjson,
    .calc_size = vl_api_nat64_add_del_prefix_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat64_add_del_prefix", api_nat64_add_del_prefix);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT64_PREFIX_DETAILS + msg_id_base,
    .name = "nat64_prefix_details",
    .handler = vl_api_nat64_prefix_details_t_handler,
    .endian = vl_api_nat64_prefix_details_t_endian,
    .format_fn = vl_api_nat64_prefix_details_t_format,
    .size = sizeof(vl_api_nat64_prefix_details_t),
    .traced = 1,
    .tojson = vl_api_nat64_prefix_details_t_tojson,
    .fromjson = vl_api_nat64_prefix_details_t_fromjson,
    .calc_size = vl_api_nat64_prefix_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat64_prefix_dump", api_nat64_prefix_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NAT64_ADD_DEL_INTERFACE_ADDR_REPLY + msg_id_base,
    .name = "nat64_add_del_interface_addr_reply",
    .handler = vl_api_nat64_add_del_interface_addr_reply_t_handler,
    .endian = vl_api_nat64_add_del_interface_addr_reply_t_endian,
    .format_fn = vl_api_nat64_add_del_interface_addr_reply_t_format,
    .size = sizeof(vl_api_nat64_add_del_interface_addr_reply_t),
    .traced = 1,
    .tojson = vl_api_nat64_add_del_interface_addr_reply_t_tojson,
    .fromjson = vl_api_nat64_add_del_interface_addr_reply_t_fromjson,
    .calc_size = vl_api_nat64_add_del_interface_addr_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "nat64_add_del_interface_addr", api_nat64_add_del_interface_addr);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   nat64_test_main_t * mainp = &nat64_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("nat64_b1b82fcf");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "nat64 plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
