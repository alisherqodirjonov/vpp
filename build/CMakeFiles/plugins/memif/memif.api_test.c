#define vl_endianfun            /* define message structures */
#include "memif.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "memif.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "memif.api.h"
#undef vl_printfun

#ifndef VL_API_MEMIF_SOCKET_FILENAME_ADD_DEL_REPLY_T_HANDLER
static void
vl_api_memif_socket_filename_add_del_reply_t_handler (vl_api_memif_socket_filename_add_del_reply_t * mp) {
   vat_main_t * vam = memif_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_memif_socket_filename_add_del_v2_reply_t_handler()) */
/* Generation not supported (vl_api_memif_create_reply_t_handler()) */
/* Generation not supported (vl_api_memif_create_v2_reply_t_handler()) */
#ifndef VL_API_MEMIF_DELETE_REPLY_T_HANDLER
static void
vl_api_memif_delete_reply_t_handler (vl_api_memif_delete_reply_t * mp) {
   vat_main_t * vam = memif_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_memif_socket_filename_details_t_handler()) */
/* Generation not supported (vl_api_memif_details_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MEMIF_SOCKET_FILENAME_ADD_DEL_REPLY + msg_id_base,
    .name = "memif_socket_filename_add_del_reply",
    .handler = vl_api_memif_socket_filename_add_del_reply_t_handler,
    .endian = vl_api_memif_socket_filename_add_del_reply_t_endian,
    .format_fn = vl_api_memif_socket_filename_add_del_reply_t_format,
    .size = sizeof(vl_api_memif_socket_filename_add_del_reply_t),
    .traced = 1,
    .tojson = vl_api_memif_socket_filename_add_del_reply_t_tojson,
    .fromjson = vl_api_memif_socket_filename_add_del_reply_t_fromjson,
    .calc_size = vl_api_memif_socket_filename_add_del_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "memif_socket_filename_add_del", api_memif_socket_filename_add_del);
   hash_set_mem (vam->help_by_name, "memif_socket_filename_add_del", "[add|del] id <id> filename <file>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MEMIF_SOCKET_FILENAME_ADD_DEL_V2_REPLY + msg_id_base,
    .name = "memif_socket_filename_add_del_v2_reply",
    .handler = vl_api_memif_socket_filename_add_del_v2_reply_t_handler,
    .endian = vl_api_memif_socket_filename_add_del_v2_reply_t_endian,
    .format_fn = vl_api_memif_socket_filename_add_del_v2_reply_t_format,
    .size = sizeof(vl_api_memif_socket_filename_add_del_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_memif_socket_filename_add_del_v2_reply_t_tojson,
    .fromjson = vl_api_memif_socket_filename_add_del_v2_reply_t_fromjson,
    .calc_size = vl_api_memif_socket_filename_add_del_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "memif_socket_filename_add_del_v2", api_memif_socket_filename_add_del_v2);
   hash_set_mem (vam->help_by_name, "memif_socket_filename_add_del_v2", "[add|del] id <id> filename <file>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MEMIF_CREATE_REPLY + msg_id_base,
    .name = "memif_create_reply",
    .handler = vl_api_memif_create_reply_t_handler,
    .endian = vl_api_memif_create_reply_t_endian,
    .format_fn = vl_api_memif_create_reply_t_format,
    .size = sizeof(vl_api_memif_create_reply_t),
    .traced = 1,
    .tojson = vl_api_memif_create_reply_t_tojson,
    .fromjson = vl_api_memif_create_reply_t_fromjson,
    .calc_size = vl_api_memif_create_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "memif_create", api_memif_create);
   hash_set_mem (vam->help_by_name, "memif_create", "[id <id>] [socket-id <id>] [ring_size <size>] [buffer_size <size>] [hw_addr <mac_address>] [secret <string>] [mode ip] <master|slave>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MEMIF_CREATE_V2_REPLY + msg_id_base,
    .name = "memif_create_v2_reply",
    .handler = vl_api_memif_create_v2_reply_t_handler,
    .endian = vl_api_memif_create_v2_reply_t_endian,
    .format_fn = vl_api_memif_create_v2_reply_t_format,
    .size = sizeof(vl_api_memif_create_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_memif_create_v2_reply_t_tojson,
    .fromjson = vl_api_memif_create_v2_reply_t_fromjson,
    .calc_size = vl_api_memif_create_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "memif_create_v2", api_memif_create_v2);
   hash_set_mem (vam->help_by_name, "memif_create_v2", "[id <id>] [socket-id <id>] [ring_size <size>] [buffer_size <size>] [hw_addr <mac_address>] [secret <string>] [mode ip] <master|slave>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MEMIF_DELETE_REPLY + msg_id_base,
    .name = "memif_delete_reply",
    .handler = vl_api_memif_delete_reply_t_handler,
    .endian = vl_api_memif_delete_reply_t_endian,
    .format_fn = vl_api_memif_delete_reply_t_format,
    .size = sizeof(vl_api_memif_delete_reply_t),
    .traced = 1,
    .tojson = vl_api_memif_delete_reply_t_tojson,
    .fromjson = vl_api_memif_delete_reply_t_fromjson,
    .calc_size = vl_api_memif_delete_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "memif_delete", api_memif_delete);
   hash_set_mem (vam->help_by_name, "memif_delete", "<sw_if_index>");
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MEMIF_SOCKET_FILENAME_DETAILS + msg_id_base,
    .name = "memif_socket_filename_details",
    .handler = vl_api_memif_socket_filename_details_t_handler,
    .endian = vl_api_memif_socket_filename_details_t_endian,
    .format_fn = vl_api_memif_socket_filename_details_t_format,
    .size = sizeof(vl_api_memif_socket_filename_details_t),
    .traced = 1,
    .tojson = vl_api_memif_socket_filename_details_t_tojson,
    .fromjson = vl_api_memif_socket_filename_details_t_fromjson,
    .calc_size = vl_api_memif_socket_filename_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "memif_socket_filename_dump", api_memif_socket_filename_dump);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MEMIF_DETAILS + msg_id_base,
    .name = "memif_details",
    .handler = vl_api_memif_details_t_handler,
    .endian = vl_api_memif_details_t_endian,
    .format_fn = vl_api_memif_details_t_format,
    .size = sizeof(vl_api_memif_details_t),
    .traced = 1,
    .tojson = vl_api_memif_details_t_tojson,
    .fromjson = vl_api_memif_details_t_fromjson,
    .calc_size = vl_api_memif_details_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "memif_dump", api_memif_dump);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   memif_test_main_t * mainp = &memif_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("memif_bf42b70a");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "memif plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
