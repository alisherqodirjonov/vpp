#define vl_endianfun            /* define message structures */
#include "mpls.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "mpls.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "mpls.api.h"
#undef vl_printfun

#ifndef VL_API_MPLS_IP_BIND_UNBIND_REPLY_T_HANDLER
static void
vl_api_mpls_ip_bind_unbind_reply_t_handler (vl_api_mpls_ip_bind_unbind_reply_t * mp) {
   vat_main_t * vam = mpls_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_mpls_tunnel_add_del_reply_t_handler()) */
/* Generation not supported (vl_api_mpls_tunnel_details_t_handler()) */
/* Generation not supported (vl_api_mpls_interface_details_t_handler()) */
#ifndef VL_API_MPLS_TABLE_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_mpls_table_add_del_reply_t_handler (vl_api_mpls_table_add_del_reply_t * mp) {
   vat_main_t * vam = mpls_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_mpls_table_details_t_handler()) */
/* Generation not supported (vl_api_mpls_route_add_del_reply_t_handler()) */
/* Generation not supported (vl_api_mpls_route_details_t_handler()) */
#ifndef VL_API_SW_INTERFACE_SET_MPLS_ENABLE_REPLY_T_HANDLER
static void
vl_api_sw_interface_set_mpls_enable_reply_t_handler (vl_api_sw_interface_set_mpls_enable_reply_t * mp) {
   vat_main_t * vam = mpls_test_main.vat_main;
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
    .id = VL_API_MPLS_IP_BIND_UNBIND_REPLY + msg_id_base,
    .name = "mpls_ip_bind_unbind_reply",
    .handler = vl_api_mpls_ip_bind_unbind_reply_t_handler,
    .endian = vl_api_mpls_ip_bind_unbind_reply_t_endian,
    .format_fn = vl_api_mpls_ip_bind_unbind_reply_t_format,
    .size = sizeof(vl_api_mpls_ip_bind_unbind_reply_t),
    .traced = 1,
    .tojson = vl_api_mpls_ip_bind_unbind_reply_t_tojson,
    .fromjson = vl_api_mpls_ip_bind_unbind_reply_t_fromjson,
    .calc_size = vl_api_mpls_ip_bind_unbind_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "mpls_ip_bind_unbind", api_mpls_ip_bind_unbind);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MPLS_TUNNEL_ADD_DEL_REPLY + msg_id_base,
    .name = "mpls_tunnel_add_del_reply",
    .handler = vl_api_mpls_tunnel_add_del_reply_t_handler,
    .endian = vl_api_mpls_tunnel_add_del_reply_t_endian,
    .format_fn = vl_api_mpls_tunnel_add_del_reply_t_format,
    .size = sizeof(vl_api_mpls_tunnel_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_mpls_tunnel_add_del_reply_t_tojson,
    .fromjson = vl_api_mpls_tunnel_add_del_reply_t_fromjson,
    .calc_size = vl_api_mpls_tunnel_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "mpls_tunnel_add_del", api_mpls_tunnel_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MPLS_TUNNEL_DETAILS + msg_id_base,
    .name = "mpls_tunnel_details",
    .handler = vl_api_mpls_tunnel_details_t_handler,
    .endian = vl_api_mpls_tunnel_details_t_endian,
    .format_fn = vl_api_mpls_tunnel_details_t_format,
    .size = sizeof(vl_api_mpls_tunnel_details_t),
    .traced = 1,
    .tojson = vl_api_mpls_tunnel_details_t_tojson,
    .fromjson = vl_api_mpls_tunnel_details_t_fromjson,
    .calc_size = vl_api_mpls_tunnel_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "mpls_tunnel_dump", api_mpls_tunnel_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MPLS_INTERFACE_DETAILS + msg_id_base,
    .name = "mpls_interface_details",
    .handler = vl_api_mpls_interface_details_t_handler,
    .endian = vl_api_mpls_interface_details_t_endian,
    .format_fn = vl_api_mpls_interface_details_t_format,
    .size = sizeof(vl_api_mpls_interface_details_t),
    .traced = 1,
    .tojson = vl_api_mpls_interface_details_t_tojson,
    .fromjson = vl_api_mpls_interface_details_t_fromjson,
    .calc_size = vl_api_mpls_interface_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "mpls_interface_dump", api_mpls_interface_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MPLS_TABLE_ADD_DEL_REPLY + msg_id_base,
    .name = "mpls_table_add_del_reply",
    .handler = vl_api_mpls_table_add_del_reply_t_handler,
    .endian = vl_api_mpls_table_add_del_reply_t_endian,
    .format_fn = vl_api_mpls_table_add_del_reply_t_format,
    .size = sizeof(vl_api_mpls_table_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_mpls_table_add_del_reply_t_tojson,
    .fromjson = vl_api_mpls_table_add_del_reply_t_fromjson,
    .calc_size = vl_api_mpls_table_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "mpls_table_add_del", api_mpls_table_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MPLS_TABLE_DETAILS + msg_id_base,
    .name = "mpls_table_details",
    .handler = vl_api_mpls_table_details_t_handler,
    .endian = vl_api_mpls_table_details_t_endian,
    .format_fn = vl_api_mpls_table_details_t_format,
    .size = sizeof(vl_api_mpls_table_details_t),
    .traced = 1,
    .tojson = vl_api_mpls_table_details_t_tojson,
    .fromjson = vl_api_mpls_table_details_t_fromjson,
    .calc_size = vl_api_mpls_table_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "mpls_table_dump", api_mpls_table_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MPLS_ROUTE_ADD_DEL_REPLY + msg_id_base,
    .name = "mpls_route_add_del_reply",
    .handler = vl_api_mpls_route_add_del_reply_t_handler,
    .endian = vl_api_mpls_route_add_del_reply_t_endian,
    .format_fn = vl_api_mpls_route_add_del_reply_t_format,
    .size = sizeof(vl_api_mpls_route_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_mpls_route_add_del_reply_t_tojson,
    .fromjson = vl_api_mpls_route_add_del_reply_t_fromjson,
    .calc_size = vl_api_mpls_route_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "mpls_route_add_del", api_mpls_route_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MPLS_ROUTE_DETAILS + msg_id_base,
    .name = "mpls_route_details",
    .handler = vl_api_mpls_route_details_t_handler,
    .endian = vl_api_mpls_route_details_t_endian,
    .format_fn = vl_api_mpls_route_details_t_format,
    .size = sizeof(vl_api_mpls_route_details_t),
    .traced = 1,
    .tojson = vl_api_mpls_route_details_t_tojson,
    .fromjson = vl_api_mpls_route_details_t_fromjson,
    .calc_size = vl_api_mpls_route_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "mpls_route_dump", api_mpls_route_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_SET_MPLS_ENABLE_REPLY + msg_id_base,
    .name = "sw_interface_set_mpls_enable_reply",
    .handler = vl_api_sw_interface_set_mpls_enable_reply_t_handler,
    .endian = vl_api_sw_interface_set_mpls_enable_reply_t_endian,
    .format_fn = vl_api_sw_interface_set_mpls_enable_reply_t_format,
    .size = sizeof(vl_api_sw_interface_set_mpls_enable_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_set_mpls_enable_reply_t_tojson,
    .fromjson = vl_api_sw_interface_set_mpls_enable_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_set_mpls_enable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_set_mpls_enable", api_sw_interface_set_mpls_enable);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   mpls_test_main_t * mainp = &mpls_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("mpls_85e5987f");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "mpls plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
