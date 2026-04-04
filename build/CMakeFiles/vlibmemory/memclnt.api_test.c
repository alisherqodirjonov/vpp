#define vl_endianfun            /* define message structures */
#include "memclnt.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "memclnt.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "memclnt.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_memclnt_create_reply_t_handler()) */
/* Generation not supported (vl_api_memclnt_delete_reply_t_handler()) */
#ifndef VL_API_RPC_CALL_REPLY_T_HANDLER
static void
vl_api_rpc_call_reply_t_handler (vl_api_rpc_call_reply_t * mp) {
   vat_main_t * vam = memclnt_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_get_first_msg_id_reply_t_handler()) */
/* Generation not supported (vl_api_api_versions_reply_t_handler()) */
/* Generation not supported (vl_api_sockclnt_create_reply_t_handler()) */
/* Generation not supported (vl_api_sockclnt_delete_reply_t_handler()) */
#ifndef VL_API_SOCK_INIT_SHM_REPLY_T_HANDLER
static void
vl_api_sock_init_shm_reply_t_handler (vl_api_sock_init_shm_reply_t * mp) {
   vat_main_t * vam = memclnt_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
#ifndef VL_API_MEMCLNT_KEEPALIVE_REPLY_T_HANDLER
static void
vl_api_memclnt_keepalive_reply_t_handler (vl_api_memclnt_keepalive_reply_t * mp) {
   vat_main_t * vam = memclnt_test_main.vat_main;
   i32 retval = ntohl(mp->retval);
   if (vam->async_mode) {
      vam->async_errors += (retval < 0);
   } else {
      vam->retval = retval;
      vam->result_ready = 1;
   }
}
#endif
/* Generation not supported (vl_api_control_ping_reply_t_handler()) */
/* Generation not supported (vl_api_memclnt_create_v2_reply_t_handler()) */
/* Generation not supported (vl_api_get_api_json_reply_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NULL + msg_id_base,
    .name = "null",
    .handler = vl_api_null_t_handler,
    .endian = vl_api_null_t_endian,
    .format_fn = vl_api_null_t_format,
    .size = sizeof(vl_api_null_t),
    .traced = 1,
    .tojson = vl_api_null_t_tojson,
    .fromjson = vl_api_null_t_fromjson,
    .calc_size = vl_api_null_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "memclnt_rx_thread_suspend", api_memclnt_rx_thread_suspend);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NULL + msg_id_base,
    .name = "null",
    .handler = vl_api_null_t_handler,
    .endian = vl_api_null_t_endian,
    .format_fn = vl_api_null_t_format,
    .size = sizeof(vl_api_null_t),
    .traced = 1,
    .tojson = vl_api_null_t_tojson,
    .fromjson = vl_api_null_t_fromjson,
    .calc_size = vl_api_null_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "memclnt_read_timeout", api_memclnt_read_timeout);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NULL + msg_id_base,
    .name = "null",
    .handler = vl_api_null_t_handler,
    .endian = vl_api_null_t_endian,
    .format_fn = vl_api_null_t_format,
    .size = sizeof(vl_api_null_t),
    .traced = 1,
    .tojson = vl_api_null_t_tojson,
    .fromjson = vl_api_null_t_fromjson,
    .calc_size = vl_api_null_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "rx_thread_exit", api_rx_thread_exit);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_NULL + msg_id_base,
    .name = "null",
    .handler = vl_api_null_t_handler,
    .endian = vl_api_null_t_endian,
    .format_fn = vl_api_null_t_format,
    .size = sizeof(vl_api_null_t),
    .traced = 1,
    .tojson = vl_api_null_t_tojson,
    .fromjson = vl_api_null_t_fromjson,
    .calc_size = vl_api_null_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "trace_plugin_msg_ids", api_trace_plugin_msg_ids);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MEMCLNT_CREATE_REPLY + msg_id_base,
    .name = "memclnt_create_reply",
    .handler = vl_api_memclnt_create_reply_t_handler,
    .endian = vl_api_memclnt_create_reply_t_endian,
    .format_fn = vl_api_memclnt_create_reply_t_format,
    .size = sizeof(vl_api_memclnt_create_reply_t),
    .traced = 1,
    .tojson = vl_api_memclnt_create_reply_t_tojson,
    .fromjson = vl_api_memclnt_create_reply_t_fromjson,
    .calc_size = vl_api_memclnt_create_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "memclnt_create", api_memclnt_create);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MEMCLNT_DELETE_REPLY + msg_id_base,
    .name = "memclnt_delete_reply",
    .handler = vl_api_memclnt_delete_reply_t_handler,
    .endian = vl_api_memclnt_delete_reply_t_endian,
    .format_fn = vl_api_memclnt_delete_reply_t_format,
    .size = sizeof(vl_api_memclnt_delete_reply_t),
    .traced = 1,
    .tojson = vl_api_memclnt_delete_reply_t_tojson,
    .fromjson = vl_api_memclnt_delete_reply_t_fromjson,
    .calc_size = vl_api_memclnt_delete_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "memclnt_delete", api_memclnt_delete);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_RPC_CALL_REPLY + msg_id_base,
    .name = "rpc_call_reply",
    .handler = vl_api_rpc_call_reply_t_handler,
    .endian = vl_api_rpc_call_reply_t_endian,
    .format_fn = vl_api_rpc_call_reply_t_format,
    .size = sizeof(vl_api_rpc_call_reply_t),
    .traced = 1,
    .tojson = vl_api_rpc_call_reply_t_tojson,
    .fromjson = vl_api_rpc_call_reply_t_fromjson,
    .calc_size = vl_api_rpc_call_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "rpc_call", api_rpc_call);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GET_FIRST_MSG_ID_REPLY + msg_id_base,
    .name = "get_first_msg_id_reply",
    .handler = vl_api_get_first_msg_id_reply_t_handler,
    .endian = vl_api_get_first_msg_id_reply_t_endian,
    .format_fn = vl_api_get_first_msg_id_reply_t_format,
    .size = sizeof(vl_api_get_first_msg_id_reply_t),
    .traced = 1,
    .tojson = vl_api_get_first_msg_id_reply_t_tojson,
    .fromjson = vl_api_get_first_msg_id_reply_t_fromjson,
    .calc_size = vl_api_get_first_msg_id_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "get_first_msg_id", api_get_first_msg_id);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_API_VERSIONS_REPLY + msg_id_base,
    .name = "api_versions_reply",
    .handler = vl_api_api_versions_reply_t_handler,
    .endian = vl_api_api_versions_reply_t_endian,
    .format_fn = vl_api_api_versions_reply_t_format,
    .size = sizeof(vl_api_api_versions_reply_t),
    .traced = 1,
    .tojson = vl_api_api_versions_reply_t_tojson,
    .fromjson = vl_api_api_versions_reply_t_fromjson,
    .calc_size = vl_api_api_versions_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "api_versions", api_api_versions);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SOCKCLNT_CREATE_REPLY + msg_id_base,
    .name = "sockclnt_create_reply",
    .handler = vl_api_sockclnt_create_reply_t_handler,
    .endian = vl_api_sockclnt_create_reply_t_endian,
    .format_fn = vl_api_sockclnt_create_reply_t_format,
    .size = sizeof(vl_api_sockclnt_create_reply_t),
    .traced = 1,
    .tojson = vl_api_sockclnt_create_reply_t_tojson,
    .fromjson = vl_api_sockclnt_create_reply_t_fromjson,
    .calc_size = vl_api_sockclnt_create_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sockclnt_create", api_sockclnt_create);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SOCKCLNT_DELETE_REPLY + msg_id_base,
    .name = "sockclnt_delete_reply",
    .handler = vl_api_sockclnt_delete_reply_t_handler,
    .endian = vl_api_sockclnt_delete_reply_t_endian,
    .format_fn = vl_api_sockclnt_delete_reply_t_format,
    .size = sizeof(vl_api_sockclnt_delete_reply_t),
    .traced = 1,
    .tojson = vl_api_sockclnt_delete_reply_t_tojson,
    .fromjson = vl_api_sockclnt_delete_reply_t_fromjson,
    .calc_size = vl_api_sockclnt_delete_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sockclnt_delete", api_sockclnt_delete);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SOCK_INIT_SHM_REPLY + msg_id_base,
    .name = "sock_init_shm_reply",
    .handler = vl_api_sock_init_shm_reply_t_handler,
    .endian = vl_api_sock_init_shm_reply_t_endian,
    .format_fn = vl_api_sock_init_shm_reply_t_format,
    .size = sizeof(vl_api_sock_init_shm_reply_t),
    .traced = 1,
    .tojson = vl_api_sock_init_shm_reply_t_tojson,
    .fromjson = vl_api_sock_init_shm_reply_t_fromjson,
    .calc_size = vl_api_sock_init_shm_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "sock_init_shm", api_sock_init_shm);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MEMCLNT_KEEPALIVE_REPLY + msg_id_base,
    .name = "memclnt_keepalive_reply",
    .handler = vl_api_memclnt_keepalive_reply_t_handler,
    .endian = vl_api_memclnt_keepalive_reply_t_endian,
    .format_fn = vl_api_memclnt_keepalive_reply_t_format,
    .size = sizeof(vl_api_memclnt_keepalive_reply_t),
    .traced = 1,
    .tojson = vl_api_memclnt_keepalive_reply_t_tojson,
    .fromjson = vl_api_memclnt_keepalive_reply_t_fromjson,
    .calc_size = vl_api_memclnt_keepalive_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "memclnt_keepalive", api_memclnt_keepalive);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CONTROL_PING_REPLY + msg_id_base,
    .name = "control_ping_reply",
    .handler = vl_api_control_ping_reply_t_handler,
    .endian = vl_api_control_ping_reply_t_endian,
    .format_fn = vl_api_control_ping_reply_t_format,
    .size = sizeof(vl_api_control_ping_reply_t),
    .traced = 1,
    .tojson = vl_api_control_ping_reply_t_tojson,
    .fromjson = vl_api_control_ping_reply_t_fromjson,
    .calc_size = vl_api_control_ping_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "control_ping", api_control_ping);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_MEMCLNT_CREATE_V2_REPLY + msg_id_base,
    .name = "memclnt_create_v2_reply",
    .handler = vl_api_memclnt_create_v2_reply_t_handler,
    .endian = vl_api_memclnt_create_v2_reply_t_endian,
    .format_fn = vl_api_memclnt_create_v2_reply_t_format,
    .size = sizeof(vl_api_memclnt_create_v2_reply_t),
    .traced = 1,
    .tojson = vl_api_memclnt_create_v2_reply_t_tojson,
    .fromjson = vl_api_memclnt_create_v2_reply_t_fromjson,
    .calc_size = vl_api_memclnt_create_v2_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "memclnt_create_v2", api_memclnt_create_v2);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GET_API_JSON_REPLY + msg_id_base,
    .name = "get_api_json_reply",
    .handler = vl_api_get_api_json_reply_t_handler,
    .endian = vl_api_get_api_json_reply_t_endian,
    .format_fn = vl_api_get_api_json_reply_t_format,
    .size = sizeof(vl_api_get_api_json_reply_t),
    .traced = 1,
    .tojson = vl_api_get_api_json_reply_t_tojson,
    .fromjson = vl_api_get_api_json_reply_t_fromjson,
    .calc_size = vl_api_get_api_json_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "get_api_json", api_get_api_json);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   memclnt_test_main_t * mainp = &memclnt_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("memclnt_b197c551");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "memclnt plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
