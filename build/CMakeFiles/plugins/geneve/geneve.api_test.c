#define vl_endianfun            /* define message structures */
#include "geneve.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "geneve.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "geneve.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_geneve_add_del_tunnel_reply_t_handler()) */
/* Generation not supported (vl_api_geneve_add_del_tunnel2_reply_t_handler()) */
/* Generation not supported (vl_api_geneve_tunnel_details_t_handler()) */
#ifndef VL_API_SW_INTERFACE_SET_GENEVE_BYPASS_REPLY_T_HANDLER
static void
vl_api_sw_interface_set_geneve_bypass_reply_t_handler (vl_api_sw_interface_set_geneve_bypass_reply_t * mp) {
   vat_main_t * vam = geneve_test_main.vat_main;
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
    .id = VL_API_GENEVE_ADD_DEL_TUNNEL_REPLY + msg_id_base,
    .name = "geneve_add_del_tunnel_reply",
    .handler = vl_api_geneve_add_del_tunnel_reply_t_handler,
    .endian = vl_api_geneve_add_del_tunnel_reply_t_endian,
    .format_fn = vl_api_geneve_add_del_tunnel_reply_t_format,
    .size = sizeof(vl_api_geneve_add_del_tunnel_reply_t),
    .traced = 1,
    .tojson = vl_api_geneve_add_del_tunnel_reply_t_tojson,
    .fromjson = vl_api_geneve_add_del_tunnel_reply_t_fromjson,
    .calc_size = vl_api_geneve_add_del_tunnel_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "geneve_add_del_tunnel", api_geneve_add_del_tunnel);
   hash_set_mem (vam->help_by_name, "geneve_add_del_tunnel", "src <ip-addr> { dst <ip-addr> | group <mcast-ip-addr> { <intfc> | mcast_sw_if_index <nn> } } vni <vni> [encap-vrf-id <nn>] [decap-next <l2|nn>] [del]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GENEVE_ADD_DEL_TUNNEL2_REPLY + msg_id_base,
    .name = "geneve_add_del_tunnel2_reply",
    .handler = vl_api_geneve_add_del_tunnel2_reply_t_handler,
    .endian = vl_api_geneve_add_del_tunnel2_reply_t_endian,
    .format_fn = vl_api_geneve_add_del_tunnel2_reply_t_format,
    .size = sizeof(vl_api_geneve_add_del_tunnel2_reply_t),
    .traced = 1,
    .tojson = vl_api_geneve_add_del_tunnel2_reply_t_tojson,
    .fromjson = vl_api_geneve_add_del_tunnel2_reply_t_fromjson,
    .calc_size = vl_api_geneve_add_del_tunnel2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "geneve_add_del_tunnel2", api_geneve_add_del_tunnel2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GENEVE_TUNNEL_DETAILS + msg_id_base,
    .name = "geneve_tunnel_details",
    .handler = vl_api_geneve_tunnel_details_t_handler,
    .endian = vl_api_geneve_tunnel_details_t_endian,
    .format_fn = vl_api_geneve_tunnel_details_t_format,
    .size = sizeof(vl_api_geneve_tunnel_details_t),
    .traced = 1,
    .tojson = vl_api_geneve_tunnel_details_t_tojson,
    .fromjson = vl_api_geneve_tunnel_details_t_fromjson,
    .calc_size = vl_api_geneve_tunnel_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "geneve_tunnel_dump", api_geneve_tunnel_dump);
   hash_set_mem (vam->help_by_name, "geneve_tunnel_dump", "[<intfc> | sw_if_index <nn>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SW_INTERFACE_SET_GENEVE_BYPASS_REPLY + msg_id_base,
    .name = "sw_interface_set_geneve_bypass_reply",
    .handler = vl_api_sw_interface_set_geneve_bypass_reply_t_handler,
    .endian = vl_api_sw_interface_set_geneve_bypass_reply_t_endian,
    .format_fn = vl_api_sw_interface_set_geneve_bypass_reply_t_format,
    .size = sizeof(vl_api_sw_interface_set_geneve_bypass_reply_t),
    .traced = 1,
    .tojson = vl_api_sw_interface_set_geneve_bypass_reply_t_tojson,
    .fromjson = vl_api_sw_interface_set_geneve_bypass_reply_t_fromjson,
    .calc_size = vl_api_sw_interface_set_geneve_bypass_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sw_interface_set_geneve_bypass", api_sw_interface_set_geneve_bypass);
   hash_set_mem (vam->help_by_name, "sw_interface_set_geneve_bypass", "<intfc> | sw_if_index <id> [ip4 | ip6] [enable | disable]");
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   geneve_test_main_t * mainp = &geneve_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("geneve_5c01c4a7");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "geneve plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
