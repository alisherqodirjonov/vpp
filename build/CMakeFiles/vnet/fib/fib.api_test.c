#define vl_endianfun            /* define message structures */
#include "fib.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "fib.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "fib.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_fib_source_add_reply_t_handler()) */
/* Generation not supported (vl_api_fib_source_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_FIB_SOURCE_ADD_REPLY + msg_id_base,
    .name = "fib_source_add_reply",
    .handler = vl_api_fib_source_add_reply_t_handler,
    .endian = vl_api_fib_source_add_reply_t_endian,
    .format_fn = vl_api_fib_source_add_reply_t_format,
    .size = sizeof(vl_api_fib_source_add_reply_t),
    .traced = 1,
    .tojson = vl_api_fib_source_add_reply_t_tojson,
    .fromjson = vl_api_fib_source_add_reply_t_fromjson,
    .calc_size = vl_api_fib_source_add_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "fib_source_add", api_fib_source_add);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_FIB_SOURCE_DETAILS + msg_id_base,
    .name = "fib_source_details",
    .handler = vl_api_fib_source_details_t_handler,
    .endian = vl_api_fib_source_details_t_endian,
    .format_fn = vl_api_fib_source_details_t_format,
    .size = sizeof(vl_api_fib_source_details_t),
    .traced = 1,
    .tojson = vl_api_fib_source_details_t_tojson,
    .fromjson = vl_api_fib_source_details_t_fromjson,
    .calc_size = vl_api_fib_source_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "fib_source_dump", api_fib_source_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   fib_test_main_t * mainp = &fib_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("fib_d97c97e5");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "fib plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
