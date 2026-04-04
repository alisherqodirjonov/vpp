#define vl_endianfun            /* define message structures */
#include "dslite.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "dslite.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "dslite.api.h"
#undef vl_printfun

#ifndef VL_API_DSLITE_ADD_DEL_POOL_ADDR_RANGE_REPLY_T_HANDLER
static void
vl_api_dslite_add_del_pool_addr_range_reply_t_handler (vl_api_dslite_add_del_pool_addr_range_reply_t * mp) {
   vat_main_t * vam = dslite_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_dslite_address_details_t_handler()) */
#ifndef VL_API_DSLITE_SET_AFTR_ADDR_REPLY_T_HANDLER
static void
vl_api_dslite_set_aftr_addr_reply_t_handler (vl_api_dslite_set_aftr_addr_reply_t * mp) {
   vat_main_t * vam = dslite_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_dslite_get_aftr_addr_reply_t_handler()) */
#ifndef VL_API_DSLITE_SET_B4_ADDR_REPLY_T_HANDLER
static void
vl_api_dslite_set_b4_addr_reply_t_handler (vl_api_dslite_set_b4_addr_reply_t * mp) {
   vat_main_t * vam = dslite_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_dslite_get_b4_addr_reply_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DSLITE_ADD_DEL_POOL_ADDR_RANGE_REPLY + msg_id_base,
    .name = "dslite_add_del_pool_addr_range_reply",
    .handler = vl_api_dslite_add_del_pool_addr_range_reply_t_handler,
    .endian = vl_api_dslite_add_del_pool_addr_range_reply_t_endian,
    .format_fn = vl_api_dslite_add_del_pool_addr_range_reply_t_format,
    .size = sizeof(vl_api_dslite_add_del_pool_addr_range_reply_t),
    .traced = 1,
    .tojson = vl_api_dslite_add_del_pool_addr_range_reply_t_tojson,
    .fromjson = vl_api_dslite_add_del_pool_addr_range_reply_t_fromjson,
    .calc_size = vl_api_dslite_add_del_pool_addr_range_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dslite_add_del_pool_addr_range", api_dslite_add_del_pool_addr_range);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DSLITE_ADDRESS_DETAILS + msg_id_base,
    .name = "dslite_address_details",
    .handler = vl_api_dslite_address_details_t_handler,
    .endian = vl_api_dslite_address_details_t_endian,
    .format_fn = vl_api_dslite_address_details_t_format,
    .size = sizeof(vl_api_dslite_address_details_t),
    .traced = 1,
    .tojson = vl_api_dslite_address_details_t_tojson,
    .fromjson = vl_api_dslite_address_details_t_fromjson,
    .calc_size = vl_api_dslite_address_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dslite_address_dump", api_dslite_address_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DSLITE_SET_AFTR_ADDR_REPLY + msg_id_base,
    .name = "dslite_set_aftr_addr_reply",
    .handler = vl_api_dslite_set_aftr_addr_reply_t_handler,
    .endian = vl_api_dslite_set_aftr_addr_reply_t_endian,
    .format_fn = vl_api_dslite_set_aftr_addr_reply_t_format,
    .size = sizeof(vl_api_dslite_set_aftr_addr_reply_t),
    .traced = 1,
    .tojson = vl_api_dslite_set_aftr_addr_reply_t_tojson,
    .fromjson = vl_api_dslite_set_aftr_addr_reply_t_fromjson,
    .calc_size = vl_api_dslite_set_aftr_addr_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dslite_set_aftr_addr", api_dslite_set_aftr_addr);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DSLITE_GET_AFTR_ADDR_REPLY + msg_id_base,
    .name = "dslite_get_aftr_addr_reply",
    .handler = vl_api_dslite_get_aftr_addr_reply_t_handler,
    .endian = vl_api_dslite_get_aftr_addr_reply_t_endian,
    .format_fn = vl_api_dslite_get_aftr_addr_reply_t_format,
    .size = sizeof(vl_api_dslite_get_aftr_addr_reply_t),
    .traced = 1,
    .tojson = vl_api_dslite_get_aftr_addr_reply_t_tojson,
    .fromjson = vl_api_dslite_get_aftr_addr_reply_t_fromjson,
    .calc_size = vl_api_dslite_get_aftr_addr_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dslite_get_aftr_addr", api_dslite_get_aftr_addr);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DSLITE_SET_B4_ADDR_REPLY + msg_id_base,
    .name = "dslite_set_b4_addr_reply",
    .handler = vl_api_dslite_set_b4_addr_reply_t_handler,
    .endian = vl_api_dslite_set_b4_addr_reply_t_endian,
    .format_fn = vl_api_dslite_set_b4_addr_reply_t_format,
    .size = sizeof(vl_api_dslite_set_b4_addr_reply_t),
    .traced = 1,
    .tojson = vl_api_dslite_set_b4_addr_reply_t_tojson,
    .fromjson = vl_api_dslite_set_b4_addr_reply_t_fromjson,
    .calc_size = vl_api_dslite_set_b4_addr_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dslite_set_b4_addr", api_dslite_set_b4_addr);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_DSLITE_GET_B4_ADDR_REPLY + msg_id_base,
    .name = "dslite_get_b4_addr_reply",
    .handler = vl_api_dslite_get_b4_addr_reply_t_handler,
    .endian = vl_api_dslite_get_b4_addr_reply_t_endian,
    .format_fn = vl_api_dslite_get_b4_addr_reply_t_format,
    .size = sizeof(vl_api_dslite_get_b4_addr_reply_t),
    .traced = 1,
    .tojson = vl_api_dslite_get_b4_addr_reply_t_tojson,
    .fromjson = vl_api_dslite_get_b4_addr_reply_t_fromjson,
    .calc_size = vl_api_dslite_get_b4_addr_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "dslite_get_b4_addr", api_dslite_get_b4_addr);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   dslite_test_main_t * mainp = &dslite_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("dslite_4bc15f82");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "dslite plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
