#define vl_endianfun            /* define message structures */
#include "pppoe.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "pppoe.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "pppoe.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_pppoe_add_del_session_reply_t_handler()) */
/* Generation not supported (vl_api_pppoe_session_details_t_handler()) */
/* Generation not supported (vl_api_pppoe_add_del_cp_reply_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PPPOE_ADD_DEL_SESSION_REPLY + msg_id_base,
    .name = "pppoe_add_del_session_reply",
    .handler = vl_api_pppoe_add_del_session_reply_t_handler,
    .endian = vl_api_pppoe_add_del_session_reply_t_endian,
    .format_fn = vl_api_pppoe_add_del_session_reply_t_format,
    .size = sizeof(vl_api_pppoe_add_del_session_reply_t),
    .traced = 1,
    .tojson = vl_api_pppoe_add_del_session_reply_t_tojson,
    .fromjson = vl_api_pppoe_add_del_session_reply_t_fromjson,
    .calc_size = vl_api_pppoe_add_del_session_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "pppoe_add_del_session", api_pppoe_add_del_session);
   hash_set_mem (vam->help_by_name, "pppoe_add_del_session", "client-addr <client-addr> session-id <nn> [encap-if-index <nn>] [decap-next [ip4|ip6|node <name>]] local-mac <local-mac> client-mac <client-mac> [del]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PPPOE_SESSION_DETAILS + msg_id_base,
    .name = "pppoe_session_details",
    .handler = vl_api_pppoe_session_details_t_handler,
    .endian = vl_api_pppoe_session_details_t_endian,
    .format_fn = vl_api_pppoe_session_details_t_format,
    .size = sizeof(vl_api_pppoe_session_details_t),
    .traced = 1,
    .tojson = vl_api_pppoe_session_details_t_tojson,
    .fromjson = vl_api_pppoe_session_details_t_fromjson,
    .calc_size = vl_api_pppoe_session_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "pppoe_session_dump", api_pppoe_session_dump);
   hash_set_mem (vam->help_by_name, "pppoe_session_dump", "[<intfc> | sw_if_index <nn>]");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_PPPOE_ADD_DEL_CP_REPLY + msg_id_base,
    .name = "pppoe_add_del_cp_reply",
    .handler = vl_api_pppoe_add_del_cp_reply_t_handler,
    .endian = vl_api_pppoe_add_del_cp_reply_t_endian,
    .format_fn = vl_api_pppoe_add_del_cp_reply_t_format,
    .size = sizeof(vl_api_pppoe_add_del_cp_reply_t),
    .traced = 1,
    .tojson = vl_api_pppoe_add_del_cp_reply_t_tojson,
    .fromjson = vl_api_pppoe_add_del_cp_reply_t_fromjson,
    .calc_size = vl_api_pppoe_add_del_cp_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "pppoe_add_del_cp", api_pppoe_add_del_cp);
   hash_set_mem (vam->help_by_name, "pppoe_add_del_cp", "[ sw_if_index <intfc> is_add <bool> ]");
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   pppoe_test_main_t * mainp = &pppoe_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("pppoe_57db3239");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "pppoe plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
