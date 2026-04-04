#define vl_endianfun            /* define message structures */
#include "bier.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "bier.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "bier.api.h"
#undef vl_printfun

#ifndef VL_API_BIER_TABLE_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_bier_table_add_del_reply_t_handler (vl_api_bier_table_add_del_reply_t * mp) {
   vat_main_t * vam = bier_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_bier_table_details_t_handler()) */
#ifndef VL_API_BIER_ROUTE_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_bier_route_add_del_reply_t_handler (vl_api_bier_route_add_del_reply_t * mp) {
   vat_main_t * vam = bier_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_bier_route_details_t_handler()) */
/* Generation not supported (vl_api_bier_imp_add_reply_t_handler()) */
#ifndef VL_API_BIER_IMP_DEL_REPLY_T_HANDLER
static void
vl_api_bier_imp_del_reply_t_handler (vl_api_bier_imp_del_reply_t * mp) {
   vat_main_t * vam = bier_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_bier_imp_details_t_handler()) */
#ifndef VL_API_BIER_DISP_TABLE_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_bier_disp_table_add_del_reply_t_handler (vl_api_bier_disp_table_add_del_reply_t * mp) {
   vat_main_t * vam = bier_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_bier_disp_table_details_t_handler()) */
#ifndef VL_API_BIER_DISP_ENTRY_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_bier_disp_entry_add_del_reply_t_handler (vl_api_bier_disp_entry_add_del_reply_t * mp) {
   vat_main_t * vam = bier_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_bier_disp_entry_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BIER_TABLE_ADD_DEL_REPLY + msg_id_base,
    .name = "bier_table_add_del_reply",
    .handler = vl_api_bier_table_add_del_reply_t_handler,
    .endian = vl_api_bier_table_add_del_reply_t_endian,
    .format_fn = vl_api_bier_table_add_del_reply_t_format,
    .size = sizeof(vl_api_bier_table_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_bier_table_add_del_reply_t_tojson,
    .fromjson = vl_api_bier_table_add_del_reply_t_fromjson,
    .calc_size = vl_api_bier_table_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bier_table_add_del", api_bier_table_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BIER_TABLE_DETAILS + msg_id_base,
    .name = "bier_table_details",
    .handler = vl_api_bier_table_details_t_handler,
    .endian = vl_api_bier_table_details_t_endian,
    .format_fn = vl_api_bier_table_details_t_format,
    .size = sizeof(vl_api_bier_table_details_t),
    .traced = 1,
    .tojson = vl_api_bier_table_details_t_tojson,
    .fromjson = vl_api_bier_table_details_t_fromjson,
    .calc_size = vl_api_bier_table_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bier_table_dump", api_bier_table_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BIER_ROUTE_ADD_DEL_REPLY + msg_id_base,
    .name = "bier_route_add_del_reply",
    .handler = vl_api_bier_route_add_del_reply_t_handler,
    .endian = vl_api_bier_route_add_del_reply_t_endian,
    .format_fn = vl_api_bier_route_add_del_reply_t_format,
    .size = sizeof(vl_api_bier_route_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_bier_route_add_del_reply_t_tojson,
    .fromjson = vl_api_bier_route_add_del_reply_t_fromjson,
    .calc_size = vl_api_bier_route_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bier_route_add_del", api_bier_route_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BIER_ROUTE_DETAILS + msg_id_base,
    .name = "bier_route_details",
    .handler = vl_api_bier_route_details_t_handler,
    .endian = vl_api_bier_route_details_t_endian,
    .format_fn = vl_api_bier_route_details_t_format,
    .size = sizeof(vl_api_bier_route_details_t),
    .traced = 1,
    .tojson = vl_api_bier_route_details_t_tojson,
    .fromjson = vl_api_bier_route_details_t_fromjson,
    .calc_size = vl_api_bier_route_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bier_route_dump", api_bier_route_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BIER_IMP_ADD_REPLY + msg_id_base,
    .name = "bier_imp_add_reply",
    .handler = vl_api_bier_imp_add_reply_t_handler,
    .endian = vl_api_bier_imp_add_reply_t_endian,
    .format_fn = vl_api_bier_imp_add_reply_t_format,
    .size = sizeof(vl_api_bier_imp_add_reply_t),
    .traced = 1,
    .tojson = vl_api_bier_imp_add_reply_t_tojson,
    .fromjson = vl_api_bier_imp_add_reply_t_fromjson,
    .calc_size = vl_api_bier_imp_add_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bier_imp_add", api_bier_imp_add);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BIER_IMP_DEL_REPLY + msg_id_base,
    .name = "bier_imp_del_reply",
    .handler = vl_api_bier_imp_del_reply_t_handler,
    .endian = vl_api_bier_imp_del_reply_t_endian,
    .format_fn = vl_api_bier_imp_del_reply_t_format,
    .size = sizeof(vl_api_bier_imp_del_reply_t),
    .traced = 1,
    .tojson = vl_api_bier_imp_del_reply_t_tojson,
    .fromjson = vl_api_bier_imp_del_reply_t_fromjson,
    .calc_size = vl_api_bier_imp_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bier_imp_del", api_bier_imp_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BIER_IMP_DETAILS + msg_id_base,
    .name = "bier_imp_details",
    .handler = vl_api_bier_imp_details_t_handler,
    .endian = vl_api_bier_imp_details_t_endian,
    .format_fn = vl_api_bier_imp_details_t_format,
    .size = sizeof(vl_api_bier_imp_details_t),
    .traced = 1,
    .tojson = vl_api_bier_imp_details_t_tojson,
    .fromjson = vl_api_bier_imp_details_t_fromjson,
    .calc_size = vl_api_bier_imp_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bier_imp_dump", api_bier_imp_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BIER_DISP_TABLE_ADD_DEL_REPLY + msg_id_base,
    .name = "bier_disp_table_add_del_reply",
    .handler = vl_api_bier_disp_table_add_del_reply_t_handler,
    .endian = vl_api_bier_disp_table_add_del_reply_t_endian,
    .format_fn = vl_api_bier_disp_table_add_del_reply_t_format,
    .size = sizeof(vl_api_bier_disp_table_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_bier_disp_table_add_del_reply_t_tojson,
    .fromjson = vl_api_bier_disp_table_add_del_reply_t_fromjson,
    .calc_size = vl_api_bier_disp_table_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bier_disp_table_add_del", api_bier_disp_table_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BIER_DISP_TABLE_DETAILS + msg_id_base,
    .name = "bier_disp_table_details",
    .handler = vl_api_bier_disp_table_details_t_handler,
    .endian = vl_api_bier_disp_table_details_t_endian,
    .format_fn = vl_api_bier_disp_table_details_t_format,
    .size = sizeof(vl_api_bier_disp_table_details_t),
    .traced = 1,
    .tojson = vl_api_bier_disp_table_details_t_tojson,
    .fromjson = vl_api_bier_disp_table_details_t_fromjson,
    .calc_size = vl_api_bier_disp_table_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bier_disp_table_dump", api_bier_disp_table_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BIER_DISP_ENTRY_ADD_DEL_REPLY + msg_id_base,
    .name = "bier_disp_entry_add_del_reply",
    .handler = vl_api_bier_disp_entry_add_del_reply_t_handler,
    .endian = vl_api_bier_disp_entry_add_del_reply_t_endian,
    .format_fn = vl_api_bier_disp_entry_add_del_reply_t_format,
    .size = sizeof(vl_api_bier_disp_entry_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_bier_disp_entry_add_del_reply_t_tojson,
    .fromjson = vl_api_bier_disp_entry_add_del_reply_t_fromjson,
    .calc_size = vl_api_bier_disp_entry_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bier_disp_entry_add_del", api_bier_disp_entry_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_BIER_DISP_ENTRY_DETAILS + msg_id_base,
    .name = "bier_disp_entry_details",
    .handler = vl_api_bier_disp_entry_details_t_handler,
    .endian = vl_api_bier_disp_entry_details_t_endian,
    .format_fn = vl_api_bier_disp_entry_details_t_format,
    .size = sizeof(vl_api_bier_disp_entry_details_t),
    .traced = 1,
    .tojson = vl_api_bier_disp_entry_details_t_tojson,
    .fromjson = vl_api_bier_disp_entry_details_t_fromjson,
    .calc_size = vl_api_bier_disp_entry_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "bier_disp_entry_dump", api_bier_disp_entry_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   bier_test_main_t * mainp = &bier_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("bier_48fa264f");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "bier plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
