#define vl_endianfun            /* define message structures */
#include "dns.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "dns.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "dns.api.h"
#undef vl_printfun

#ifndef VL_API_DNS_ENABLE_DISABLE_REPLY_T_HANDLER
static void
vl_api_dns_enable_disable_reply_t_handler (vl_api_dns_enable_disable_reply_t * mp) {
   vat_main_t * vam = dns_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_DNS_NAME_SERVER_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_dns_name_server_add_del_reply_t_handler (vl_api_dns_name_server_add_del_reply_t * mp) {
   vat_main_t * vam = dns_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_dns_resolve_name_reply_t_handler()) */
/* Generation not supported (vl_api_dns_resolve_ip_reply_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DNS_ENABLE_DISABLE_REPLY + msg_id_base,
    .name = "dns_enable_disable_reply",
    .handler = vl_api_dns_enable_disable_reply_t_handler,
    .endian = vl_api_dns_enable_disable_reply_t_endian,
    .format_fn = vl_api_dns_enable_disable_reply_t_format,
    .size = sizeof(vl_api_dns_enable_disable_reply_t),
    .traced = 1,
    .tojson = vl_api_dns_enable_disable_reply_t_tojson,
    .fromjson = vl_api_dns_enable_disable_reply_t_fromjson,
    .calc_size = vl_api_dns_enable_disable_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dns_enable_disable", api_dns_enable_disable);
   hash_set_mem (vam->help_by_name, "dns_enable_disable", "[enable][disable]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DNS_NAME_SERVER_ADD_DEL_REPLY + msg_id_base,
    .name = "dns_name_server_add_del_reply",
    .handler = vl_api_dns_name_server_add_del_reply_t_handler,
    .endian = vl_api_dns_name_server_add_del_reply_t_endian,
    .format_fn = vl_api_dns_name_server_add_del_reply_t_format,
    .size = sizeof(vl_api_dns_name_server_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_dns_name_server_add_del_reply_t_tojson,
    .fromjson = vl_api_dns_name_server_add_del_reply_t_fromjson,
    .calc_size = vl_api_dns_name_server_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dns_name_server_add_del", api_dns_name_server_add_del);
   hash_set_mem (vam->help_by_name, "dns_name_server_add_del", "<ip-address> [del]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DNS_RESOLVE_NAME_REPLY + msg_id_base,
    .name = "dns_resolve_name_reply",
    .handler = vl_api_dns_resolve_name_reply_t_handler,
    .endian = vl_api_dns_resolve_name_reply_t_endian,
    .format_fn = vl_api_dns_resolve_name_reply_t_format,
    .size = sizeof(vl_api_dns_resolve_name_reply_t),
    .traced = 1,
    .tojson = vl_api_dns_resolve_name_reply_t_tojson,
    .fromjson = vl_api_dns_resolve_name_reply_t_fromjson,
    .calc_size = vl_api_dns_resolve_name_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dns_resolve_name", api_dns_resolve_name);
   hash_set_mem (vam->help_by_name, "dns_resolve_name", "<hostname>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DNS_RESOLVE_IP_REPLY + msg_id_base,
    .name = "dns_resolve_ip_reply",
    .handler = vl_api_dns_resolve_ip_reply_t_handler,
    .endian = vl_api_dns_resolve_ip_reply_t_endian,
    .format_fn = vl_api_dns_resolve_ip_reply_t_format,
    .size = sizeof(vl_api_dns_resolve_ip_reply_t),
    .traced = 1,
    .tojson = vl_api_dns_resolve_ip_reply_t_tojson,
    .fromjson = vl_api_dns_resolve_ip_reply_t_fromjson,
    .calc_size = vl_api_dns_resolve_ip_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dns_resolve_ip", api_dns_resolve_ip);
   hash_set_mem (vam->help_by_name, "dns_resolve_ip", "<ip4|ip6>");
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   dns_test_main_t * mainp = &dns_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("dns_269575cd");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "dns plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
