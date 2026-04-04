#define vl_endianfun            /* define message structures */
#include "gre.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "gre.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "gre.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_gre_tunnel_dump_reply_t_handler()) */
#ifndef VL_API_GRE_TUNNEL_DUMP_V2_REPLY_T_HANDLER
static void
vl_api_gre_tunnel_dump_v2_reply_t_handler (vl_api_gre_tunnel_dump_v2_reply_t * mp) {
   vat_main_t * vam = gre_test_main.vat_main;
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
vl_api_gre_tunnel_details_v2_t_handler (vl_api_gre_tunnel_details_v2_t * mp) {
    vlib_cli_output(0, "gre_tunnel_details_v2 event called:");
    vlib_cli_output(0, "%U", vl_api_gre_tunnel_details_v2_t_format, mp);
}
/* Generation not supported (vl_api_gre_tunnel_add_del_reply_t_handler()) */
/* Generation not supported (vl_api_gre_tunnel_add_del_v2_reply_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GRE_TUNNEL_DUMP_REPLY + msg_id_base,
    .name = "gre_tunnel_dump_reply",
    .handler = vl_api_gre_tunnel_dump_reply_t_handler,
    .endian = vl_api_gre_tunnel_dump_reply_t_endian,
    .format_fn = vl_api_gre_tunnel_dump_reply_t_format,
    .size = sizeof(vl_api_gre_tunnel_dump_reply_t),
    .traced = 1,
    .tojson = vl_api_gre_tunnel_dump_reply_t_tojson,
    .fromjson = vl_api_gre_tunnel_dump_reply_t_fromjson,
    .calc_size = vl_api_gre_tunnel_dump_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "gre_tunnel_dump", api_gre_tunnel_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GRE_TUNNEL_DETAILS + msg_id_base,
    .name = "gre_tunnel_details",
    .handler = vl_api_gre_tunnel_details_t_handler,
    .endian = vl_api_gre_tunnel_details_t_endian,
    .format_fn = vl_api_gre_tunnel_details_t_format,
    .size = sizeof(vl_api_gre_tunnel_details_t),
    .traced = 1,
    .tojson = vl_api_gre_tunnel_details_t_tojson,
    .fromjson = vl_api_gre_tunnel_details_t_fromjson,
    .calc_size = vl_api_gre_tunnel_details_t_calc_size,
   });   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GRE_TUNNEL_DUMP_V2_REPLY + msg_id_base,
    .name = "gre_tunnel_dump_v2_reply",
    .handler = vl_api_gre_tunnel_dump_v2_reply_t_handler,
    .endian = vl_api_gre_tunnel_dump_v2_reply_t_endian,
    .format_fn = vl_api_gre_tunnel_dump_v2_reply_t_format,
    .size = sizeof(vl_api_gre_tunnel_dump_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_gre_tunnel_dump_v2_reply_t_tojson,
    .fromjson = vl_api_gre_tunnel_dump_v2_reply_t_fromjson,
    .calc_size = vl_api_gre_tunnel_dump_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "gre_tunnel_dump_v2", api_gre_tunnel_dump_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GRE_TUNNEL_DETAILS_V2 + msg_id_base,
    .name = "gre_tunnel_details_v2",
    .handler = vl_api_gre_tunnel_details_v2_t_handler,
    .endian = vl_api_gre_tunnel_details_v2_t_endian,
    .format_fn = vl_api_gre_tunnel_details_v2_t_format,
    .size = sizeof(vl_api_gre_tunnel_details_v2_t),
    .traced = 1,
    .tojson = vl_api_gre_tunnel_details_v2_t_tojson,
    .fromjson = vl_api_gre_tunnel_details_v2_t_fromjson,
    .calc_size = vl_api_gre_tunnel_details_v2_t_calc_size,
   });   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GRE_TUNNEL_ADD_DEL_REPLY + msg_id_base,
    .name = "gre_tunnel_add_del_reply",
    .handler = vl_api_gre_tunnel_add_del_reply_t_handler,
    .endian = vl_api_gre_tunnel_add_del_reply_t_endian,
    .format_fn = vl_api_gre_tunnel_add_del_reply_t_format,
    .size = sizeof(vl_api_gre_tunnel_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_gre_tunnel_add_del_reply_t_tojson,
    .fromjson = vl_api_gre_tunnel_add_del_reply_t_fromjson,
    .calc_size = vl_api_gre_tunnel_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "gre_tunnel_add_del", api_gre_tunnel_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GRE_TUNNEL_ADD_DEL_V2_REPLY + msg_id_base,
    .name = "gre_tunnel_add_del_v2_reply",
    .handler = vl_api_gre_tunnel_add_del_v2_reply_t_handler,
    .endian = vl_api_gre_tunnel_add_del_v2_reply_t_endian,
    .format_fn = vl_api_gre_tunnel_add_del_v2_reply_t_format,
    .size = sizeof(vl_api_gre_tunnel_add_del_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_gre_tunnel_add_del_v2_reply_t_tojson,
    .fromjson = vl_api_gre_tunnel_add_del_v2_reply_t_fromjson,
    .calc_size = vl_api_gre_tunnel_add_del_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "gre_tunnel_add_del_v2", api_gre_tunnel_add_del_v2);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   gre_test_main_t * mainp = &gre_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("gre_05dfeb04");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "gre plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
