#define vl_endianfun            /* define message structures */
#include "ipip.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ipip.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "ipip.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_ipip_add_tunnel_reply_t_handler()) */
#ifndef VL_API_IPIP_DEL_TUNNEL_REPLY_T_HANDLER
static void
vl_api_ipip_del_tunnel_reply_t_handler (vl_api_ipip_del_tunnel_reply_t * mp) {
   vat_main_t * vam = ipip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_ipip_6rd_add_tunnel_reply_t_handler()) */
#ifndef VL_API_IPIP_6RD_DEL_TUNNEL_REPLY_T_HANDLER
static void
vl_api_ipip_6rd_del_tunnel_reply_t_handler (vl_api_ipip_6rd_del_tunnel_reply_t * mp) {
   vat_main_t * vam = ipip_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_ipip_tunnel_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPIP_ADD_TUNNEL_REPLY + msg_id_base,
    .name = "ipip_add_tunnel_reply",
    .handler = vl_api_ipip_add_tunnel_reply_t_handler,
    .endian = vl_api_ipip_add_tunnel_reply_t_endian,
    .format_fn = vl_api_ipip_add_tunnel_reply_t_format,
    .size = sizeof(vl_api_ipip_add_tunnel_reply_t),
    .traced = 1,
    .tojson = vl_api_ipip_add_tunnel_reply_t_tojson,
    .fromjson = vl_api_ipip_add_tunnel_reply_t_fromjson,
    .calc_size = vl_api_ipip_add_tunnel_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipip_add_tunnel", api_ipip_add_tunnel);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPIP_DEL_TUNNEL_REPLY + msg_id_base,
    .name = "ipip_del_tunnel_reply",
    .handler = vl_api_ipip_del_tunnel_reply_t_handler,
    .endian = vl_api_ipip_del_tunnel_reply_t_endian,
    .format_fn = vl_api_ipip_del_tunnel_reply_t_format,
    .size = sizeof(vl_api_ipip_del_tunnel_reply_t),
    .traced = 1,
    .tojson = vl_api_ipip_del_tunnel_reply_t_tojson,
    .fromjson = vl_api_ipip_del_tunnel_reply_t_fromjson,
    .calc_size = vl_api_ipip_del_tunnel_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipip_del_tunnel", api_ipip_del_tunnel);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPIP_6RD_ADD_TUNNEL_REPLY + msg_id_base,
    .name = "ipip_6rd_add_tunnel_reply",
    .handler = vl_api_ipip_6rd_add_tunnel_reply_t_handler,
    .endian = vl_api_ipip_6rd_add_tunnel_reply_t_endian,
    .format_fn = vl_api_ipip_6rd_add_tunnel_reply_t_format,
    .size = sizeof(vl_api_ipip_6rd_add_tunnel_reply_t),
    .traced = 1,
    .tojson = vl_api_ipip_6rd_add_tunnel_reply_t_tojson,
    .fromjson = vl_api_ipip_6rd_add_tunnel_reply_t_fromjson,
    .calc_size = vl_api_ipip_6rd_add_tunnel_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipip_6rd_add_tunnel", api_ipip_6rd_add_tunnel);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPIP_6RD_DEL_TUNNEL_REPLY + msg_id_base,
    .name = "ipip_6rd_del_tunnel_reply",
    .handler = vl_api_ipip_6rd_del_tunnel_reply_t_handler,
    .endian = vl_api_ipip_6rd_del_tunnel_reply_t_endian,
    .format_fn = vl_api_ipip_6rd_del_tunnel_reply_t_format,
    .size = sizeof(vl_api_ipip_6rd_del_tunnel_reply_t),
    .traced = 1,
    .tojson = vl_api_ipip_6rd_del_tunnel_reply_t_tojson,
    .fromjson = vl_api_ipip_6rd_del_tunnel_reply_t_fromjson,
    .calc_size = vl_api_ipip_6rd_del_tunnel_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipip_6rd_del_tunnel", api_ipip_6rd_del_tunnel);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPIP_TUNNEL_DETAILS + msg_id_base,
    .name = "ipip_tunnel_details",
    .handler = vl_api_ipip_tunnel_details_t_handler,
    .endian = vl_api_ipip_tunnel_details_t_endian,
    .format_fn = vl_api_ipip_tunnel_details_t_format,
    .size = sizeof(vl_api_ipip_tunnel_details_t),
    .traced = 1,
    .tojson = vl_api_ipip_tunnel_details_t_tojson,
    .fromjson = vl_api_ipip_tunnel_details_t_fromjson,
    .calc_size = vl_api_ipip_tunnel_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipip_tunnel_dump", api_ipip_tunnel_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   ipip_test_main_t * mainp = &ipip_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("ipip_03c9c667");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "ipip plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
