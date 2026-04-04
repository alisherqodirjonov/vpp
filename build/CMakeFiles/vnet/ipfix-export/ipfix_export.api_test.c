#define vl_endianfun            /* define message structures */
#include "ipfix_export.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ipfix_export.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "ipfix_export.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_ipfix_all_exporter_get_reply_t_handler()) */
#ifndef VL_API_SET_IPFIX_EXPORTER_REPLY_T_HANDLER
static void
vl_api_set_ipfix_exporter_reply_t_handler (vl_api_set_ipfix_exporter_reply_t * mp) {
   vat_main_t * vam = ipfix_export_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_ipfix_exporter_details_t_handler()) */
/* Generation not supported (vl_api_ipfix_exporter_create_delete_reply_t_handler()) */
#ifndef VL_API_SET_IPFIX_CLASSIFY_STREAM_REPLY_T_HANDLER
static void
vl_api_set_ipfix_classify_stream_reply_t_handler (vl_api_set_ipfix_classify_stream_reply_t * mp) {
   vat_main_t * vam = ipfix_export_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_ipfix_classify_stream_details_t_handler()) */
#ifndef VL_API_IPFIX_CLASSIFY_TABLE_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_ipfix_classify_table_add_del_reply_t_handler (vl_api_ipfix_classify_table_add_del_reply_t * mp) {
   vat_main_t * vam = ipfix_export_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_ipfix_classify_table_details_t_handler()) */
#ifndef VL_API_IPFIX_FLUSH_REPLY_T_HANDLER
static void
vl_api_ipfix_flush_reply_t_handler (vl_api_ipfix_flush_reply_t * mp) {
   vat_main_t * vam = ipfix_export_test_main.vat_main;
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
    .id = VL_API_IPFIX_ALL_EXPORTER_GET_REPLY + msg_id_base,
    .name = "ipfix_all_exporter_get_reply",
    .handler = vl_api_ipfix_all_exporter_get_reply_t_handler,
    .endian = vl_api_ipfix_all_exporter_get_reply_t_endian,
    .format_fn = vl_api_ipfix_all_exporter_get_reply_t_format,
    .size = sizeof(vl_api_ipfix_all_exporter_get_reply_t),
    .traced = 1,
    .tojson = vl_api_ipfix_all_exporter_get_reply_t_tojson,
    .fromjson = vl_api_ipfix_all_exporter_get_reply_t_fromjson,
    .calc_size = vl_api_ipfix_all_exporter_get_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipfix_all_exporter_get", api_ipfix_all_exporter_get);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SET_IPFIX_EXPORTER_REPLY + msg_id_base,
    .name = "set_ipfix_exporter_reply",
    .handler = vl_api_set_ipfix_exporter_reply_t_handler,
    .endian = vl_api_set_ipfix_exporter_reply_t_endian,
    .format_fn = vl_api_set_ipfix_exporter_reply_t_format,
    .size = sizeof(vl_api_set_ipfix_exporter_reply_t),
    .traced = 1,
    .tojson = vl_api_set_ipfix_exporter_reply_t_tojson,
    .fromjson = vl_api_set_ipfix_exporter_reply_t_fromjson,
    .calc_size = vl_api_set_ipfix_exporter_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "set_ipfix_exporter", api_set_ipfix_exporter);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPFIX_EXPORTER_DETAILS + msg_id_base,
    .name = "ipfix_exporter_details",
    .handler = vl_api_ipfix_exporter_details_t_handler,
    .endian = vl_api_ipfix_exporter_details_t_endian,
    .format_fn = vl_api_ipfix_exporter_details_t_format,
    .size = sizeof(vl_api_ipfix_exporter_details_t),
    .traced = 1,
    .tojson = vl_api_ipfix_exporter_details_t_tojson,
    .fromjson = vl_api_ipfix_exporter_details_t_fromjson,
    .calc_size = vl_api_ipfix_exporter_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipfix_exporter_dump", api_ipfix_exporter_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPFIX_EXPORTER_CREATE_DELETE_REPLY + msg_id_base,
    .name = "ipfix_exporter_create_delete_reply",
    .handler = vl_api_ipfix_exporter_create_delete_reply_t_handler,
    .endian = vl_api_ipfix_exporter_create_delete_reply_t_endian,
    .format_fn = vl_api_ipfix_exporter_create_delete_reply_t_format,
    .size = sizeof(vl_api_ipfix_exporter_create_delete_reply_t),
    .traced = 1,
    .tojson = vl_api_ipfix_exporter_create_delete_reply_t_tojson,
    .fromjson = vl_api_ipfix_exporter_create_delete_reply_t_fromjson,
    .calc_size = vl_api_ipfix_exporter_create_delete_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipfix_exporter_create_delete", api_ipfix_exporter_create_delete);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SET_IPFIX_CLASSIFY_STREAM_REPLY + msg_id_base,
    .name = "set_ipfix_classify_stream_reply",
    .handler = vl_api_set_ipfix_classify_stream_reply_t_handler,
    .endian = vl_api_set_ipfix_classify_stream_reply_t_endian,
    .format_fn = vl_api_set_ipfix_classify_stream_reply_t_format,
    .size = sizeof(vl_api_set_ipfix_classify_stream_reply_t),
    .traced = 1,
    .tojson = vl_api_set_ipfix_classify_stream_reply_t_tojson,
    .fromjson = vl_api_set_ipfix_classify_stream_reply_t_fromjson,
    .calc_size = vl_api_set_ipfix_classify_stream_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "set_ipfix_classify_stream", api_set_ipfix_classify_stream);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPFIX_CLASSIFY_STREAM_DETAILS + msg_id_base,
    .name = "ipfix_classify_stream_details",
    .handler = vl_api_ipfix_classify_stream_details_t_handler,
    .endian = vl_api_ipfix_classify_stream_details_t_endian,
    .format_fn = vl_api_ipfix_classify_stream_details_t_format,
    .size = sizeof(vl_api_ipfix_classify_stream_details_t),
    .traced = 1,
    .tojson = vl_api_ipfix_classify_stream_details_t_tojson,
    .fromjson = vl_api_ipfix_classify_stream_details_t_fromjson,
    .calc_size = vl_api_ipfix_classify_stream_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipfix_classify_stream_dump", api_ipfix_classify_stream_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPFIX_CLASSIFY_TABLE_ADD_DEL_REPLY + msg_id_base,
    .name = "ipfix_classify_table_add_del_reply",
    .handler = vl_api_ipfix_classify_table_add_del_reply_t_handler,
    .endian = vl_api_ipfix_classify_table_add_del_reply_t_endian,
    .format_fn = vl_api_ipfix_classify_table_add_del_reply_t_format,
    .size = sizeof(vl_api_ipfix_classify_table_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_ipfix_classify_table_add_del_reply_t_tojson,
    .fromjson = vl_api_ipfix_classify_table_add_del_reply_t_fromjson,
    .calc_size = vl_api_ipfix_classify_table_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipfix_classify_table_add_del", api_ipfix_classify_table_add_del);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPFIX_CLASSIFY_TABLE_DETAILS + msg_id_base,
    .name = "ipfix_classify_table_details",
    .handler = vl_api_ipfix_classify_table_details_t_handler,
    .endian = vl_api_ipfix_classify_table_details_t_endian,
    .format_fn = vl_api_ipfix_classify_table_details_t_format,
    .size = sizeof(vl_api_ipfix_classify_table_details_t),
    .traced = 1,
    .tojson = vl_api_ipfix_classify_table_details_t_tojson,
    .fromjson = vl_api_ipfix_classify_table_details_t_fromjson,
    .calc_size = vl_api_ipfix_classify_table_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipfix_classify_table_dump", api_ipfix_classify_table_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_IPFIX_FLUSH_REPLY + msg_id_base,
    .name = "ipfix_flush_reply",
    .handler = vl_api_ipfix_flush_reply_t_handler,
    .endian = vl_api_ipfix_flush_reply_t_endian,
    .format_fn = vl_api_ipfix_flush_reply_t_format,
    .size = sizeof(vl_api_ipfix_flush_reply_t),
    .traced = 1,
    .tojson = vl_api_ipfix_flush_reply_t_tojson,
    .fromjson = vl_api_ipfix_flush_reply_t_fromjson,
    .calc_size = vl_api_ipfix_flush_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "ipfix_flush", api_ipfix_flush);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   ipfix_export_test_main_t * mainp = &ipfix_export_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("ipfix_export_e118ab1c");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "ipfix_export plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
