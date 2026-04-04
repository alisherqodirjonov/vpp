#define vl_endianfun            /* define message structures */
#include "avf.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "avf.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "avf.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_avf_create_reply_t_handler()) */
#ifndef VL_API_AVF_DELETE_REPLY_T_HANDLER
static void
vl_api_avf_delete_reply_t_handler (vl_api_avf_delete_reply_t * mp) {
   vat_main_t * vam = avf_test_main.vat_main;
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
    .id = VL_API_AVF_CREATE_REPLY + msg_id_base,
    .name = "avf_create_reply",
    .handler = vl_api_avf_create_reply_t_handler,
    .endian = vl_api_avf_create_reply_t_endian,
    .format_fn = vl_api_avf_create_reply_t_format,
    .size = sizeof(vl_api_avf_create_reply_t),
    .traced = 1,
    .tojson = vl_api_avf_create_reply_t_tojson,
    .fromjson = vl_api_avf_create_reply_t_fromjson,
    .calc_size = vl_api_avf_create_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "avf_create", api_avf_create);
   hash_set_mem (vam->help_by_name, "avf_create", "<pci-address> [rx-queue-size <size>] [tx-queue-size <size>] [num-rx-queues <size>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_AVF_DELETE_REPLY + msg_id_base,
    .name = "avf_delete_reply",
    .handler = vl_api_avf_delete_reply_t_handler,
    .endian = vl_api_avf_delete_reply_t_endian,
    .format_fn = vl_api_avf_delete_reply_t_format,
    .size = sizeof(vl_api_avf_delete_reply_t),
    .traced = 1,
    .tojson = vl_api_avf_delete_reply_t_tojson,
    .fromjson = vl_api_avf_delete_reply_t_fromjson,
    .calc_size = vl_api_avf_delete_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "avf_delete", api_avf_delete);
   hash_set_mem (vam->help_by_name, "avf_delete", "<sw_if_index>");
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   avf_test_main_t * mainp = &avf_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("avf_45056ab4");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "avf plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
