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

#include "vlib.api_enum.h"
#include "vlib.api_types.h"

#define vl_endianfun		/* define message structures */
#include "vlib.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "vlib.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "vlib.api.h"
#undef vl_printfun

#include "vlib.api_tojson.h"
#include "vlib.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_cli (cJSON *o)
{
  vl_api_cli_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_cli_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CLI_CRC);
  vl_api_cli_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CLI_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_cli_reply_t *rmp = (vl_api_cli_reply_t *)p;
  vl_api_cli_reply_t_endian(rmp, 0);
  return vl_api_cli_reply_t_tojson(rmp);
}

static cJSON *
api_cli_inband (cJSON *o)
{
  vl_api_cli_inband_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_cli_inband_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CLI_INBAND_CRC);
  vl_api_cli_inband_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CLI_INBAND_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_cli_inband_reply_t *rmp = (vl_api_cli_inband_reply_t *)p;
  vl_api_cli_inband_reply_t_endian(rmp, 0);
  return vl_api_cli_inband_reply_t_tojson(rmp);
}

static cJSON *
api_get_node_index (cJSON *o)
{
  vl_api_get_node_index_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_get_node_index_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_GET_NODE_INDEX_CRC);
  vl_api_get_node_index_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_GET_NODE_INDEX_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_get_node_index_reply_t *rmp = (vl_api_get_node_index_reply_t *)p;
  vl_api_get_node_index_reply_t_endian(rmp, 0);
  return vl_api_get_node_index_reply_t_tojson(rmp);
}

static cJSON *
api_add_node_next (cJSON *o)
{
  vl_api_add_node_next_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_add_node_next_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_ADD_NODE_NEXT_CRC);
  vl_api_add_node_next_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_ADD_NODE_NEXT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_add_node_next_reply_t *rmp = (vl_api_add_node_next_reply_t *)p;
  vl_api_add_node_next_reply_t_endian(rmp, 0);
  return vl_api_add_node_next_reply_t_tojson(rmp);
}

static cJSON *
api_show_threads (cJSON *o)
{
  vl_api_show_threads_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_show_threads_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SHOW_THREADS_CRC);
  vl_api_show_threads_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SHOW_THREADS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_show_threads_reply_t *rmp = (vl_api_show_threads_reply_t *)p;
  vl_api_show_threads_reply_t_endian(rmp, 0);
  return vl_api_show_threads_reply_t_tojson(rmp);
}

static cJSON *
api_get_node_graph (cJSON *o)
{
  vl_api_get_node_graph_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_get_node_graph_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_GET_NODE_GRAPH_CRC);
  vl_api_get_node_graph_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_GET_NODE_GRAPH_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_get_node_graph_reply_t *rmp = (vl_api_get_node_graph_reply_t *)p;
  vl_api_get_node_graph_reply_t_endian(rmp, 0);
  return vl_api_get_node_graph_reply_t_tojson(rmp);
}

static cJSON *
api_get_next_index (cJSON *o)
{
  vl_api_get_next_index_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_get_next_index_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_GET_NEXT_INDEX_CRC);
  vl_api_get_next_index_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_GET_NEXT_INDEX_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_get_next_index_reply_t *rmp = (vl_api_get_next_index_reply_t *)p;
  vl_api_get_next_index_reply_t_endian(rmp, 0);
  return vl_api_get_next_index_reply_t_tojson(rmp);
}

static cJSON *
api_get_f64_endian_value (cJSON *o)
{
  vl_api_get_f64_endian_value_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_get_f64_endian_value_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_GET_F64_ENDIAN_VALUE_CRC);
  vl_api_get_f64_endian_value_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_GET_F64_ENDIAN_VALUE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_get_f64_endian_value_reply_t *rmp = (vl_api_get_f64_endian_value_reply_t *)p;
  vl_api_get_f64_endian_value_reply_t_endian(rmp, 0);
  return vl_api_get_f64_endian_value_reply_t_tojson(rmp);
}

static cJSON *
api_get_f64_increment_by_one (cJSON *o)
{
  vl_api_get_f64_increment_by_one_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_get_f64_increment_by_one_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_GET_F64_INCREMENT_BY_ONE_CRC);
  vl_api_get_f64_increment_by_one_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_GET_F64_INCREMENT_BY_ONE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_get_f64_increment_by_one_reply_t *rmp = (vl_api_get_f64_increment_by_one_reply_t *)p;
  vl_api_get_f64_increment_by_one_reply_t_endian(rmp, 0);
  return vl_api_get_f64_increment_by_one_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("cli", api_cli, (cJSON * (*)(void *))vl_api_cli_t_tojson, 0x23bfbfff);
   vat2_register_function("cli_inband", api_cli_inband, (cJSON * (*)(void *))vl_api_cli_inband_t_tojson, 0xf8377302);
   vat2_register_function("get_node_index", api_get_node_index, (cJSON * (*)(void *))vl_api_get_node_index_t_tojson, 0xf1984c64);
   vat2_register_function("add_node_next", api_add_node_next, (cJSON * (*)(void *))vl_api_add_node_next_t_tojson, 0x2457116d);
   vat2_register_function("show_threads", api_show_threads, (cJSON * (*)(void *))vl_api_show_threads_t_tojson, 0x51077d14);
   vat2_register_function("get_node_graph", api_get_node_graph, (cJSON * (*)(void *))vl_api_get_node_graph_t_tojson, 0x51077d14);
   vat2_register_function("get_next_index", api_get_next_index, (cJSON * (*)(void *))vl_api_get_next_index_t_tojson, 0x2457116d);
   vat2_register_function("get_f64_endian_value", api_get_f64_endian_value, (cJSON * (*)(void *))vl_api_get_f64_endian_value_t_tojson, 0x809fcd44);
   vat2_register_function("get_f64_increment_by_one", api_get_f64_increment_by_one, (cJSON * (*)(void *))vl_api_get_f64_increment_by_one_t_tojson, 0xb64f027e);
   return 0;
}
