#define vl_endianfun		/* define message structures */
#include "memclnt.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "memclnt.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "memclnt.api.h"
#undef vl_printfun

#include "memclnt.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("memclnt_b197c551", VL_MSG_MEMCLNT_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_memclnt);
   vl_msg_api_add_msg_name_crc (am, "memclnt_create_9c5e1c2f",
                                VL_API_MEMCLNT_CREATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memclnt_create_reply_42ec4560",
                                VL_API_MEMCLNT_CREATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memclnt_delete_7e1c04e3",
                                VL_API_MEMCLNT_DELETE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memclnt_delete_reply_3d3b6312",
                                VL_API_MEMCLNT_DELETE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "rx_thread_exit_c3a3a452",
                                VL_API_RX_THREAD_EXIT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memclnt_rx_thread_suspend_c3a3a452",
                                VL_API_MEMCLNT_RX_THREAD_SUSPEND + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memclnt_read_timeout_c3a3a452",
                                VL_API_MEMCLNT_READ_TIMEOUT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "rpc_call_7e8a2c95",
                                VL_API_RPC_CALL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "rpc_call_reply_e8d4e804",
                                VL_API_RPC_CALL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "get_first_msg_id_ebf79a66",
                                VL_API_GET_FIRST_MSG_ID + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "get_first_msg_id_reply_7d337472",
                                VL_API_GET_FIRST_MSG_ID_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "api_versions_51077d14",
                                VL_API_API_VERSIONS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "api_versions_reply_5f0d99d6",
                                VL_API_API_VERSIONS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "trace_plugin_msg_ids_f476d3ce",
                                VL_API_TRACE_PLUGIN_MSG_IDS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sockclnt_create_455fb9c4",
                                VL_API_SOCKCLNT_CREATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sockclnt_create_reply_35166268",
                                VL_API_SOCKCLNT_CREATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sockclnt_delete_8ac76db6",
                                VL_API_SOCKCLNT_DELETE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sockclnt_delete_reply_8f38b1ee",
                                VL_API_SOCKCLNT_DELETE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sock_init_shm_51646d92",
                                VL_API_SOCK_INIT_SHM + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sock_init_shm_reply_e8d4e804",
                                VL_API_SOCK_INIT_SHM_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memclnt_keepalive_51077d14",
                                VL_API_MEMCLNT_KEEPALIVE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memclnt_keepalive_reply_e8d4e804",
                                VL_API_MEMCLNT_KEEPALIVE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "control_ping_51077d14",
                                VL_API_CONTROL_PING + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "control_ping_reply_f6b0b8ca",
                                VL_API_CONTROL_PING_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memclnt_create_v2_c4bd4882",
                                VL_API_MEMCLNT_CREATE_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "memclnt_create_v2_reply_42ec4560",
                                VL_API_MEMCLNT_CREATE_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "get_api_json_51077d14",
                                VL_API_GET_API_JSON + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "get_api_json_reply_ea715b59",
                                VL_API_GET_API_JSON_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MEMCLNT_RX_THREAD_SUSPEND + msg_id_base,
   .name = "memclnt_rx_thread_suspend",
   .handler = vl_api_memclnt_rx_thread_suspend_t_handler,
   .endian = vl_api_memclnt_rx_thread_suspend_t_endian,
   .format_fn = vl_api_memclnt_rx_thread_suspend_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_memclnt_rx_thread_suspend_t_tojson,
   .fromjson = vl_api_memclnt_rx_thread_suspend_t_fromjson,
   .calc_size = vl_api_memclnt_rx_thread_suspend_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MEMCLNT_READ_TIMEOUT + msg_id_base,
   .name = "memclnt_read_timeout",
   .handler = vl_api_memclnt_read_timeout_t_handler,
   .endian = vl_api_memclnt_read_timeout_t_endian,
   .format_fn = vl_api_memclnt_read_timeout_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_memclnt_read_timeout_t_tojson,
   .fromjson = vl_api_memclnt_read_timeout_t_fromjson,
   .calc_size = vl_api_memclnt_read_timeout_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_RX_THREAD_EXIT + msg_id_base,
   .name = "rx_thread_exit",
   .handler = vl_api_rx_thread_exit_t_handler,
   .endian = vl_api_rx_thread_exit_t_endian,
   .format_fn = vl_api_rx_thread_exit_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_rx_thread_exit_t_tojson,
   .fromjson = vl_api_rx_thread_exit_t_fromjson,
   .calc_size = vl_api_rx_thread_exit_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_TRACE_PLUGIN_MSG_IDS + msg_id_base,
   .name = "trace_plugin_msg_ids",
   .handler = vl_api_trace_plugin_msg_ids_t_handler,
   .endian = vl_api_trace_plugin_msg_ids_t_endian,
   .format_fn = vl_api_trace_plugin_msg_ids_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_trace_plugin_msg_ids_t_tojson,
   .fromjson = vl_api_trace_plugin_msg_ids_t_fromjson,
   .calc_size = vl_api_trace_plugin_msg_ids_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MEMCLNT_CREATE + msg_id_base,
   .name = "memclnt_create",
   .handler = vl_api_memclnt_create_t_handler,
   .endian = vl_api_memclnt_create_t_endian,
   .format_fn = vl_api_memclnt_create_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_memclnt_create_t_tojson,
   .fromjson = vl_api_memclnt_create_t_fromjson,
   .calc_size = vl_api_memclnt_create_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MEMCLNT_CREATE_REPLY + msg_id_base,
  .name = "memclnt_create_reply",
  .handler = 0,
  .endian = vl_api_memclnt_create_reply_t_endian,
  .format_fn = vl_api_memclnt_create_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_memclnt_create_reply_t_tojson,
  .fromjson = vl_api_memclnt_create_reply_t_fromjson,
  .calc_size = vl_api_memclnt_create_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MEMCLNT_DELETE + msg_id_base,
   .name = "memclnt_delete",
   .handler = vl_api_memclnt_delete_t_handler,
   .endian = vl_api_memclnt_delete_t_endian,
   .format_fn = vl_api_memclnt_delete_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_memclnt_delete_t_tojson,
   .fromjson = vl_api_memclnt_delete_t_fromjson,
   .calc_size = vl_api_memclnt_delete_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MEMCLNT_DELETE_REPLY + msg_id_base,
  .name = "memclnt_delete_reply",
  .handler = 0,
  .endian = vl_api_memclnt_delete_reply_t_endian,
  .format_fn = vl_api_memclnt_delete_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_memclnt_delete_reply_t_tojson,
  .fromjson = vl_api_memclnt_delete_reply_t_fromjson,
  .calc_size = vl_api_memclnt_delete_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_RPC_CALL + msg_id_base,
   .name = "rpc_call",
   .handler = vl_api_rpc_call_t_handler,
   .endian = vl_api_rpc_call_t_endian,
   .format_fn = vl_api_rpc_call_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_rpc_call_t_tojson,
   .fromjson = vl_api_rpc_call_t_fromjson,
   .calc_size = vl_api_rpc_call_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_RPC_CALL_REPLY + msg_id_base,
  .name = "rpc_call_reply",
  .handler = 0,
  .endian = vl_api_rpc_call_reply_t_endian,
  .format_fn = vl_api_rpc_call_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_rpc_call_reply_t_tojson,
  .fromjson = vl_api_rpc_call_reply_t_fromjson,
  .calc_size = vl_api_rpc_call_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GET_FIRST_MSG_ID + msg_id_base,
   .name = "get_first_msg_id",
   .handler = vl_api_get_first_msg_id_t_handler,
   .endian = vl_api_get_first_msg_id_t_endian,
   .format_fn = vl_api_get_first_msg_id_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_get_first_msg_id_t_tojson,
   .fromjson = vl_api_get_first_msg_id_t_fromjson,
   .calc_size = vl_api_get_first_msg_id_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GET_FIRST_MSG_ID_REPLY + msg_id_base,
  .name = "get_first_msg_id_reply",
  .handler = 0,
  .endian = vl_api_get_first_msg_id_reply_t_endian,
  .format_fn = vl_api_get_first_msg_id_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_get_first_msg_id_reply_t_tojson,
  .fromjson = vl_api_get_first_msg_id_reply_t_fromjson,
  .calc_size = vl_api_get_first_msg_id_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_API_VERSIONS + msg_id_base,
   .name = "api_versions",
   .handler = vl_api_api_versions_t_handler,
   .endian = vl_api_api_versions_t_endian,
   .format_fn = vl_api_api_versions_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_api_versions_t_tojson,
   .fromjson = vl_api_api_versions_t_fromjson,
   .calc_size = vl_api_api_versions_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_API_VERSIONS_REPLY + msg_id_base,
  .name = "api_versions_reply",
  .handler = 0,
  .endian = vl_api_api_versions_reply_t_endian,
  .format_fn = vl_api_api_versions_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_api_versions_reply_t_tojson,
  .fromjson = vl_api_api_versions_reply_t_fromjson,
  .calc_size = vl_api_api_versions_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SOCKCLNT_CREATE + msg_id_base,
   .name = "sockclnt_create",
   .handler = vl_api_sockclnt_create_t_handler,
   .endian = vl_api_sockclnt_create_t_endian,
   .format_fn = vl_api_sockclnt_create_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sockclnt_create_t_tojson,
   .fromjson = vl_api_sockclnt_create_t_fromjson,
   .calc_size = vl_api_sockclnt_create_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SOCKCLNT_CREATE_REPLY + msg_id_base,
  .name = "sockclnt_create_reply",
  .handler = 0,
  .endian = vl_api_sockclnt_create_reply_t_endian,
  .format_fn = vl_api_sockclnt_create_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sockclnt_create_reply_t_tojson,
  .fromjson = vl_api_sockclnt_create_reply_t_fromjson,
  .calc_size = vl_api_sockclnt_create_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SOCKCLNT_DELETE + msg_id_base,
   .name = "sockclnt_delete",
   .handler = vl_api_sockclnt_delete_t_handler,
   .endian = vl_api_sockclnt_delete_t_endian,
   .format_fn = vl_api_sockclnt_delete_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sockclnt_delete_t_tojson,
   .fromjson = vl_api_sockclnt_delete_t_fromjson,
   .calc_size = vl_api_sockclnt_delete_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SOCKCLNT_DELETE_REPLY + msg_id_base,
  .name = "sockclnt_delete_reply",
  .handler = 0,
  .endian = vl_api_sockclnt_delete_reply_t_endian,
  .format_fn = vl_api_sockclnt_delete_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sockclnt_delete_reply_t_tojson,
  .fromjson = vl_api_sockclnt_delete_reply_t_fromjson,
  .calc_size = vl_api_sockclnt_delete_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SOCK_INIT_SHM + msg_id_base,
   .name = "sock_init_shm",
   .handler = vl_api_sock_init_shm_t_handler,
   .endian = vl_api_sock_init_shm_t_endian,
   .format_fn = vl_api_sock_init_shm_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sock_init_shm_t_tojson,
   .fromjson = vl_api_sock_init_shm_t_fromjson,
   .calc_size = vl_api_sock_init_shm_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SOCK_INIT_SHM_REPLY + msg_id_base,
  .name = "sock_init_shm_reply",
  .handler = 0,
  .endian = vl_api_sock_init_shm_reply_t_endian,
  .format_fn = vl_api_sock_init_shm_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sock_init_shm_reply_t_tojson,
  .fromjson = vl_api_sock_init_shm_reply_t_fromjson,
  .calc_size = vl_api_sock_init_shm_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MEMCLNT_KEEPALIVE + msg_id_base,
   .name = "memclnt_keepalive",
   .handler = vl_api_memclnt_keepalive_t_handler,
   .endian = vl_api_memclnt_keepalive_t_endian,
   .format_fn = vl_api_memclnt_keepalive_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_memclnt_keepalive_t_tojson,
   .fromjson = vl_api_memclnt_keepalive_t_fromjson,
   .calc_size = vl_api_memclnt_keepalive_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MEMCLNT_KEEPALIVE_REPLY + msg_id_base,
  .name = "memclnt_keepalive_reply",
  .handler = 0,
  .endian = vl_api_memclnt_keepalive_reply_t_endian,
  .format_fn = vl_api_memclnt_keepalive_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_memclnt_keepalive_reply_t_tojson,
  .fromjson = vl_api_memclnt_keepalive_reply_t_fromjson,
  .calc_size = vl_api_memclnt_keepalive_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CONTROL_PING + msg_id_base,
   .name = "control_ping",
   .handler = vl_api_control_ping_t_handler,
   .endian = vl_api_control_ping_t_endian,
   .format_fn = vl_api_control_ping_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_control_ping_t_tojson,
   .fromjson = vl_api_control_ping_t_fromjson,
   .calc_size = vl_api_control_ping_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CONTROL_PING_REPLY + msg_id_base,
  .name = "control_ping_reply",
  .handler = 0,
  .endian = vl_api_control_ping_reply_t_endian,
  .format_fn = vl_api_control_ping_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_control_ping_reply_t_tojson,
  .fromjson = vl_api_control_ping_reply_t_fromjson,
  .calc_size = vl_api_control_ping_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MEMCLNT_CREATE_V2 + msg_id_base,
   .name = "memclnt_create_v2",
   .handler = vl_api_memclnt_create_v2_t_handler,
   .endian = vl_api_memclnt_create_v2_t_endian,
   .format_fn = vl_api_memclnt_create_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_memclnt_create_v2_t_tojson,
   .fromjson = vl_api_memclnt_create_v2_t_fromjson,
   .calc_size = vl_api_memclnt_create_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MEMCLNT_CREATE_V2_REPLY + msg_id_base,
  .name = "memclnt_create_v2_reply",
  .handler = 0,
  .endian = vl_api_memclnt_create_v2_reply_t_endian,
  .format_fn = vl_api_memclnt_create_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_memclnt_create_v2_reply_t_tojson,
  .fromjson = vl_api_memclnt_create_v2_reply_t_fromjson,
  .calc_size = vl_api_memclnt_create_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GET_API_JSON + msg_id_base,
   .name = "get_api_json",
   .handler = vl_api_get_api_json_t_handler,
   .endian = vl_api_get_api_json_t_endian,
   .format_fn = vl_api_get_api_json_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_get_api_json_t_tojson,
   .fromjson = vl_api_get_api_json_t_fromjson,
   .calc_size = vl_api_get_api_json_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GET_API_JSON_REPLY + msg_id_base,
  .name = "get_api_json_reply",
  .handler = 0,
  .endian = vl_api_get_api_json_reply_t_endian,
  .format_fn = vl_api_get_api_json_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_get_api_json_reply_t_tojson,
  .fromjson = vl_api_get_api_json_reply_t_fromjson,
  .calc_size = vl_api_get_api_json_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
