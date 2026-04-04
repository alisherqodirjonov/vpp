#define vl_endianfun		/* define message structures */
#include "vlib.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "vlib.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "vlib.api.h"
#undef vl_printfun

#include "vlib.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("vlib_9a9e84e4", VL_MSG_VLIB_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_vlib);
   vl_msg_api_add_msg_name_crc (am, "cli_23bfbfff",
                                VL_API_CLI + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cli_inband_f8377302",
                                VL_API_CLI_INBAND + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cli_reply_06d68297",
                                VL_API_CLI_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cli_inband_reply_05879051",
                                VL_API_CLI_INBAND_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "get_node_index_f1984c64",
                                VL_API_GET_NODE_INDEX + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "get_node_index_reply_a8600b89",
                                VL_API_GET_NODE_INDEX_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "add_node_next_2457116d",
                                VL_API_ADD_NODE_NEXT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "add_node_next_reply_2ed75f32",
                                VL_API_ADD_NODE_NEXT_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_threads_51077d14",
                                VL_API_SHOW_THREADS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "show_threads_reply_efd78e83",
                                VL_API_SHOW_THREADS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "get_node_graph_51077d14",
                                VL_API_GET_NODE_GRAPH + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "get_node_graph_reply_06d68297",
                                VL_API_GET_NODE_GRAPH_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "get_next_index_2457116d",
                                VL_API_GET_NEXT_INDEX + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "get_next_index_reply_2ed75f32",
                                VL_API_GET_NEXT_INDEX_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "get_f64_endian_value_809fcd44",
                                VL_API_GET_F64_ENDIAN_VALUE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "get_f64_endian_value_reply_7e02e404",
                                VL_API_GET_F64_ENDIAN_VALUE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "get_f64_increment_by_one_b64f027e",
                                VL_API_GET_F64_INCREMENT_BY_ONE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "get_f64_increment_by_one_reply_d25dbaa3",
                                VL_API_GET_F64_INCREMENT_BY_ONE_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CLI + msg_id_base,
   .name = "cli",
   .handler = vl_api_cli_t_handler,
   .endian = vl_api_cli_t_endian,
   .format_fn = vl_api_cli_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_cli_t_tojson,
   .fromjson = vl_api_cli_t_fromjson,
   .calc_size = vl_api_cli_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CLI_REPLY + msg_id_base,
  .name = "cli_reply",
  .handler = 0,
  .endian = vl_api_cli_reply_t_endian,
  .format_fn = vl_api_cli_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_cli_reply_t_tojson,
  .fromjson = vl_api_cli_reply_t_fromjson,
  .calc_size = vl_api_cli_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CLI_INBAND + msg_id_base,
   .name = "cli_inband",
   .handler = vl_api_cli_inband_t_handler,
   .endian = vl_api_cli_inband_t_endian,
   .format_fn = vl_api_cli_inband_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_cli_inband_t_tojson,
   .fromjson = vl_api_cli_inband_t_fromjson,
   .calc_size = vl_api_cli_inband_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CLI_INBAND_REPLY + msg_id_base,
  .name = "cli_inband_reply",
  .handler = 0,
  .endian = vl_api_cli_inband_reply_t_endian,
  .format_fn = vl_api_cli_inband_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_cli_inband_reply_t_tojson,
  .fromjson = vl_api_cli_inband_reply_t_fromjson,
  .calc_size = vl_api_cli_inband_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GET_NODE_INDEX + msg_id_base,
   .name = "get_node_index",
   .handler = vl_api_get_node_index_t_handler,
   .endian = vl_api_get_node_index_t_endian,
   .format_fn = vl_api_get_node_index_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_get_node_index_t_tojson,
   .fromjson = vl_api_get_node_index_t_fromjson,
   .calc_size = vl_api_get_node_index_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GET_NODE_INDEX_REPLY + msg_id_base,
  .name = "get_node_index_reply",
  .handler = 0,
  .endian = vl_api_get_node_index_reply_t_endian,
  .format_fn = vl_api_get_node_index_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_get_node_index_reply_t_tojson,
  .fromjson = vl_api_get_node_index_reply_t_fromjson,
  .calc_size = vl_api_get_node_index_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ADD_NODE_NEXT + msg_id_base,
   .name = "add_node_next",
   .handler = vl_api_add_node_next_t_handler,
   .endian = vl_api_add_node_next_t_endian,
   .format_fn = vl_api_add_node_next_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_add_node_next_t_tojson,
   .fromjson = vl_api_add_node_next_t_fromjson,
   .calc_size = vl_api_add_node_next_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ADD_NODE_NEXT_REPLY + msg_id_base,
  .name = "add_node_next_reply",
  .handler = 0,
  .endian = vl_api_add_node_next_reply_t_endian,
  .format_fn = vl_api_add_node_next_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_add_node_next_reply_t_tojson,
  .fromjson = vl_api_add_node_next_reply_t_fromjson,
  .calc_size = vl_api_add_node_next_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SHOW_THREADS + msg_id_base,
   .name = "show_threads",
   .handler = vl_api_show_threads_t_handler,
   .endian = vl_api_show_threads_t_endian,
   .format_fn = vl_api_show_threads_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_show_threads_t_tojson,
   .fromjson = vl_api_show_threads_t_fromjson,
   .calc_size = vl_api_show_threads_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SHOW_THREADS_REPLY + msg_id_base,
  .name = "show_threads_reply",
  .handler = 0,
  .endian = vl_api_show_threads_reply_t_endian,
  .format_fn = vl_api_show_threads_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_show_threads_reply_t_tojson,
  .fromjson = vl_api_show_threads_reply_t_fromjson,
  .calc_size = vl_api_show_threads_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GET_NODE_GRAPH + msg_id_base,
   .name = "get_node_graph",
   .handler = vl_api_get_node_graph_t_handler,
   .endian = vl_api_get_node_graph_t_endian,
   .format_fn = vl_api_get_node_graph_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_get_node_graph_t_tojson,
   .fromjson = vl_api_get_node_graph_t_fromjson,
   .calc_size = vl_api_get_node_graph_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GET_NODE_GRAPH_REPLY + msg_id_base,
  .name = "get_node_graph_reply",
  .handler = 0,
  .endian = vl_api_get_node_graph_reply_t_endian,
  .format_fn = vl_api_get_node_graph_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_get_node_graph_reply_t_tojson,
  .fromjson = vl_api_get_node_graph_reply_t_fromjson,
  .calc_size = vl_api_get_node_graph_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GET_NEXT_INDEX + msg_id_base,
   .name = "get_next_index",
   .handler = vl_api_get_next_index_t_handler,
   .endian = vl_api_get_next_index_t_endian,
   .format_fn = vl_api_get_next_index_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_get_next_index_t_tojson,
   .fromjson = vl_api_get_next_index_t_fromjson,
   .calc_size = vl_api_get_next_index_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GET_NEXT_INDEX_REPLY + msg_id_base,
  .name = "get_next_index_reply",
  .handler = 0,
  .endian = vl_api_get_next_index_reply_t_endian,
  .format_fn = vl_api_get_next_index_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_get_next_index_reply_t_tojson,
  .fromjson = vl_api_get_next_index_reply_t_fromjson,
  .calc_size = vl_api_get_next_index_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GET_F64_ENDIAN_VALUE + msg_id_base,
   .name = "get_f64_endian_value",
   .handler = vl_api_get_f64_endian_value_t_handler,
   .endian = vl_api_get_f64_endian_value_t_endian,
   .format_fn = vl_api_get_f64_endian_value_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_get_f64_endian_value_t_tojson,
   .fromjson = vl_api_get_f64_endian_value_t_fromjson,
   .calc_size = vl_api_get_f64_endian_value_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GET_F64_ENDIAN_VALUE_REPLY + msg_id_base,
  .name = "get_f64_endian_value_reply",
  .handler = 0,
  .endian = vl_api_get_f64_endian_value_reply_t_endian,
  .format_fn = vl_api_get_f64_endian_value_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_get_f64_endian_value_reply_t_tojson,
  .fromjson = vl_api_get_f64_endian_value_reply_t_fromjson,
  .calc_size = vl_api_get_f64_endian_value_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GET_F64_INCREMENT_BY_ONE + msg_id_base,
   .name = "get_f64_increment_by_one",
   .handler = vl_api_get_f64_increment_by_one_t_handler,
   .endian = vl_api_get_f64_increment_by_one_t_endian,
   .format_fn = vl_api_get_f64_increment_by_one_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_get_f64_increment_by_one_t_tojson,
   .fromjson = vl_api_get_f64_increment_by_one_t_fromjson,
   .calc_size = vl_api_get_f64_increment_by_one_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GET_F64_INCREMENT_BY_ONE_REPLY + msg_id_base,
  .name = "get_f64_increment_by_one_reply",
  .handler = 0,
  .endian = vl_api_get_f64_increment_by_one_reply_t_endian,
  .format_fn = vl_api_get_f64_increment_by_one_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_get_f64_increment_by_one_reply_t_tojson,
  .fromjson = vl_api_get_f64_increment_by_one_reply_t_fromjson,
  .calc_size = vl_api_get_f64_increment_by_one_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
