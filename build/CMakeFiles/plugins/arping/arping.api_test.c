#define vl_endianfun            /* define message structures */
#include "arping.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "arping.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "arping.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_arping_reply_t_handler()) */
/* Generation not supported (vl_api_arping_acd_reply_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ARPING_REPLY + msg_id_base,
    .name = "arping_reply",
    .handler = vl_api_arping_reply_t_handler,
    .endian = vl_api_arping_reply_t_endian,
    .format_fn = vl_api_arping_reply_t_format,
    .size = sizeof(vl_api_arping_reply_t),
    .traced = 1,
    .tojson = vl_api_arping_reply_t_tojson,
    .fromjson = vl_api_arping_reply_t_fromjson,
    .calc_size = vl_api_arping_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "arping", api_arping);
   hash_set_mem (vam->help_by_name, "arping", "<address> <interface> [gratuitouss] [repeat <count>] [interval <sec>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ARPING_ACD_REPLY + msg_id_base,
    .name = "arping_acd_reply",
    .handler = vl_api_arping_acd_reply_t_handler,
    .endian = vl_api_arping_acd_reply_t_endian,
    .format_fn = vl_api_arping_acd_reply_t_format,
    .size = sizeof(vl_api_arping_acd_reply_t),
    .traced = 1,
    .tojson = vl_api_arping_acd_reply_t_tojson,
    .fromjson = vl_api_arping_acd_reply_t_fromjson,
    .calc_size = vl_api_arping_acd_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "arping_acd", api_arping_acd);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   arping_test_main_t * mainp = &arping_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("arping_d4cc4344");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "arping plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
