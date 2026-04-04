#define vl_endianfun            /* define message structures */
#include "vlib.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "vlib.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "vlib.api.h"
#undef vl_printfun

/* Generation not supported (vl_api_cli_reply_t_handler()) */
/* Generation not supported (vl_api_cli_inband_reply_t_handler()) */
/* Generation not supported (vl_api_get_node_index_reply_t_handler()) */
/* Generation not supported (vl_api_add_node_next_reply_t_handler()) */
/* Generation not supported (vl_api_show_threads_reply_t_handler()) */
/* Generation not supported (vl_api_get_node_graph_reply_t_handler()) */
/* Generation not supported (vl_api_get_next_index_reply_t_handler()) */
/* Generation not supported (vl_api_get_f64_endian_value_reply_t_handler()) */
/* Generation not supported (vl_api_get_f64_increment_by_one_reply_t_handler()) */
static void
setup_message_id_table (vat_main_t * vam, u16 msg_id_base) {
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CLI_REPLY + msg_id_base,
    .name = "cli_reply",
    .handler = vl_api_cli_reply_t_handler,
    .endian = vl_api_cli_reply_t_endian,
    .format_fn = vl_api_cli_reply_t_format,
    .size = sizeof(vl_api_cli_reply_t),
    .traced = 1,
    .tojson = vl_api_cli_reply_t_tojson,
    .fromjson = vl_api_cli_reply_t_fromjson,
    .calc_size = vl_api_cli_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "cli", api_cli);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_CLI_INBAND_REPLY + msg_id_base,
    .name = "cli_inband_reply",
    .handler = vl_api_cli_inband_reply_t_handler,
    .endian = vl_api_cli_inband_reply_t_endian,
    .format_fn = vl_api_cli_inband_reply_t_format,
    .size = sizeof(vl_api_cli_inband_reply_t),
    .traced = 1,
    .tojson = vl_api_cli_inband_reply_t_tojson,
    .fromjson = vl_api_cli_inband_reply_t_fromjson,
    .calc_size = vl_api_cli_inband_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "cli_inband", api_cli_inband);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GET_NODE_INDEX_REPLY + msg_id_base,
    .name = "get_node_index_reply",
    .handler = vl_api_get_node_index_reply_t_handler,
    .endian = vl_api_get_node_index_reply_t_endian,
    .format_fn = vl_api_get_node_index_reply_t_format,
    .size = sizeof(vl_api_get_node_index_reply_t),
    .traced = 1,
    .tojson = vl_api_get_node_index_reply_t_tojson,
    .fromjson = vl_api_get_node_index_reply_t_fromjson,
    .calc_size = vl_api_get_node_index_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "get_node_index", api_get_node_index);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_ADD_NODE_NEXT_REPLY + msg_id_base,
    .name = "add_node_next_reply",
    .handler = vl_api_add_node_next_reply_t_handler,
    .endian = vl_api_add_node_next_reply_t_endian,
    .format_fn = vl_api_add_node_next_reply_t_format,
    .size = sizeof(vl_api_add_node_next_reply_t),
    .traced = 1,
    .tojson = vl_api_add_node_next_reply_t_tojson,
    .fromjson = vl_api_add_node_next_reply_t_fromjson,
    .calc_size = vl_api_add_node_next_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "add_node_next", api_add_node_next);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_SHOW_THREADS_REPLY + msg_id_base,
    .name = "show_threads_reply",
    .handler = vl_api_show_threads_reply_t_handler,
    .endian = vl_api_show_threads_reply_t_endian,
    .format_fn = vl_api_show_threads_reply_t_format,
    .size = sizeof(vl_api_show_threads_reply_t),
    .traced = 1,
    .tojson = vl_api_show_threads_reply_t_tojson,
    .fromjson = vl_api_show_threads_reply_t_fromjson,
    .calc_size = vl_api_show_threads_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "show_threads", api_show_threads);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GET_NODE_GRAPH_REPLY + msg_id_base,
    .name = "get_node_graph_reply",
    .handler = vl_api_get_node_graph_reply_t_handler,
    .endian = vl_api_get_node_graph_reply_t_endian,
    .format_fn = vl_api_get_node_graph_reply_t_format,
    .size = sizeof(vl_api_get_node_graph_reply_t),
    .traced = 1,
    .tojson = vl_api_get_node_graph_reply_t_tojson,
    .fromjson = vl_api_get_node_graph_reply_t_fromjson,
    .calc_size = vl_api_get_node_graph_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "get_node_graph", api_get_node_graph);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GET_NEXT_INDEX_REPLY + msg_id_base,
    .name = "get_next_index_reply",
    .handler = vl_api_get_next_index_reply_t_handler,
    .endian = vl_api_get_next_index_reply_t_endian,
    .format_fn = vl_api_get_next_index_reply_t_format,
    .size = sizeof(vl_api_get_next_index_reply_t),
    .traced = 1,
    .tojson = vl_api_get_next_index_reply_t_tojson,
    .fromjson = vl_api_get_next_index_reply_t_fromjson,
    .calc_size = vl_api_get_next_index_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "get_next_index", api_get_next_index);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GET_F64_ENDIAN_VALUE_REPLY + msg_id_base,
    .name = "get_f64_endian_value_reply",
    .handler = vl_api_get_f64_endian_value_reply_t_handler,
    .endian = vl_api_get_f64_endian_value_reply_t_endian,
    .format_fn = vl_api_get_f64_endian_value_reply_t_format,
    .size = sizeof(vl_api_get_f64_endian_value_reply_t),
    .traced = 1,
    .tojson = vl_api_get_f64_endian_value_reply_t_tojson,
    .fromjson = vl_api_get_f64_endian_value_reply_t_fromjson,
    .calc_size = vl_api_get_f64_endian_value_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "get_f64_endian_value", api_get_f64_endian_value);
   vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = VL_API_GET_F64_INCREMENT_BY_ONE_REPLY + msg_id_base,
    .name = "get_f64_increment_by_one_reply",
    .handler = vl_api_get_f64_increment_by_one_reply_t_handler,
    .endian = vl_api_get_f64_increment_by_one_reply_t_endian,
    .format_fn = vl_api_get_f64_increment_by_one_reply_t_format,
    .size = sizeof(vl_api_get_f64_increment_by_one_reply_t),
    .traced = 1,
    .tojson = vl_api_get_f64_increment_by_one_reply_t_tojson,
    .fromjson = vl_api_get_f64_increment_by_one_reply_t_fromjson,
    .calc_size = vl_api_get_f64_increment_by_one_reply_t_calc_size,
   });   hash_set_mem (vam->function_by_name, "get_f64_increment_by_one", api_get_f64_increment_by_one);
}
clib_error_t * vat_plugin_register (vat_main_t *vam)
{
   vlib_test_main_t * mainp = &vlib_test_main;
   mainp->vat_main = vam;
   mainp->msg_id_base = vl_client_get_first_plugin_msg_id                        ("vlib_9a9e84e4");
   if (mainp->msg_id_base == (u16) ~0)
      return clib_error_return (0, "vlib plugin not loaded...");
   setup_message_id_table (vam, mainp->msg_id_base);
#ifdef VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE
    VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE(vam);
#endif
   return 0;
}
