#define vl_endianfun		/* define message structures */
#include "graph.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "graph.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "graph.api.h"
#undef vl_printfun

#include "graph.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("graph_a0b3fd1c", VL_MSG_GRAPH_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_graph);
   vl_msg_api_add_msg_name_crc (am, "graph_node_get_39c8792e",
                                VL_API_GRAPH_NODE_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "graph_node_get_reply_53b48f5d",
                                VL_API_GRAPH_NODE_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "graph_node_details_ac762018",
                                VL_API_GRAPH_NODE_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_GRAPH_NODE_GET + msg_id_base,
   .name = "graph_node_get",
   .handler = vl_api_graph_node_get_t_handler,
   .endian = vl_api_graph_node_get_t_endian,
   .format_fn = vl_api_graph_node_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_graph_node_get_t_tojson,
   .fromjson = vl_api_graph_node_get_t_fromjson,
   .calc_size = vl_api_graph_node_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GRAPH_NODE_GET_REPLY + msg_id_base,
  .name = "graph_node_get_reply",
  .handler = 0,
  .endian = vl_api_graph_node_get_reply_t_endian,
  .format_fn = vl_api_graph_node_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_graph_node_get_reply_t_tojson,
  .fromjson = vl_api_graph_node_get_reply_t_fromjson,
  .calc_size = vl_api_graph_node_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_GRAPH_NODE_DETAILS + msg_id_base,
  .name = "graph_node_details",
  .handler = 0,
  .endian = vl_api_graph_node_details_t_endian,
  .format_fn = vl_api_graph_node_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_graph_node_details_t_tojson,
  .fromjson = vl_api_graph_node_details_t_fromjson,
  .calc_size = vl_api_graph_node_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
