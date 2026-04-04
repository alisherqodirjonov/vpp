#define vl_endianfun            /* define message structures */
#include "tcp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "tcp.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "tcp.api.h"
#undef vl_printfun

#ifndef VL_API_TCP_CONFIGURE_SRC_ADDRESSES_REPLY_T_HANDLER
static void
vl_api_tcp_configure_src_addresses_reply_t_handler (vl_api_tcp_configure_src_addresses_reply_t * mp) {
   vat_main_t * vam = tcp_test_main.vat_main;
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
    .id = VL_API_TCP_CONFIGURE_SRC_ADDRESSES_REPLY + msg_id_base,
    .name = "tcp_configure_src_addresses_reply",
    .handler = vl_api_tcp_configure_src_addresses_reply_t_handler,
    .endian = vl_api_tcp_configure_src_addresses_reply_t_endian,
    .format_fn = vl_api_tcp_configure_src_addresses_reply_t_format,
    .size = sizeof(vl_api_tcp_configure_src_addresses_reply_t),
    .traced = 1,
    .tojson = vl_api_tcp_configure_src_addresses_reply_t_tojson,
    .fromjson = vl_api_tcp_configure_src_addresses_reply_t_fromjson,
    .calc_size = vl_api_tcp_configure_src_addresses_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "tcp_configure_src_addresses", api_tcp_configure_src_addresses);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   tcp_test_main_t * mainp = &tcp_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("tcp_bd2e9222");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "tcp plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
