#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip_format_fns.h>
#include <vnet/ethernet/ethernet_format_fns.h>

#define vl_typedefs             /* define message structures */
#include <vlibmemory/vl_memory_api_h.h>
#include <vlibmemory/vlib.api_types.h>
#include <vlibmemory/vlib.api.h>
#undef vl_typedefs

#include "graph.api_enum.h"
#include "graph.api_types.h"

#define vl_endianfun		/* define message structures */
#include "graph.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "graph.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "graph.api.h"
#undef vl_printfun

#include "graph.api_tojson.h"
#include "graph.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_graph_node_get (cJSON *o)
{
    u16 msg_id = vac_get_msg_index(VL_API_GRAPH_NODE_GET_CRC);
  int len = 0;
  if (!o) return 0;
  vl_api_graph_node_get_t *mp = vl_api_graph_node_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }
  mp->_vl_msg_id = msg_id;

  vl_api_graph_node_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  cJSON *reply = cJSON_CreateArray();

  u16 reply_msg_id = vac_get_msg_index(VL_API_GRAPH_NODE_GET_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_GRAPH_NODE_DETAILS_CRC);

  while (1) {
    /* Read reply */
    char *p;
    int l;
    vac_read(&p, &l, 5); // XXX: Fix timeout

    /* Message can be one of [_details, control_ping_reply
     * or unrelated event]
     */
    u16 msg_id = ntohs(*((u16 *)p));
    if (msg_id == reply_msg_id) {
        vl_api_graph_node_get_reply_t *rmp = (vl_api_graph_node_get_reply_t *)p;
        vl_api_graph_node_get_reply_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_graph_node_get_reply_t_tojson(rmp));
        break;
    }

    if (msg_id == details_msg_id) {
        vl_api_graph_node_details_t *rmp = (vl_api_graph_node_details_t *)p;
        vl_api_graph_node_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_graph_node_details_t_tojson(rmp));
    }
  }
  return reply;
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("graph_node_get", api_graph_node_get, (cJSON * (*)(void *))vl_api_graph_node_get_t_tojson, 0x39c8792e);
   return 0;
}
