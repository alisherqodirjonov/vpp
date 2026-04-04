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

#include "lisp.api_enum.h"
#include "lisp.api_types.h"

#define vl_endianfun		/* define message structures */
#include "lisp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "lisp.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "lisp.api.h"
#undef vl_printfun

#include "lisp.api_tojson.h"
#include "lisp.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_lisp_add_del_locator_set (cJSON *o)
{
  vl_api_lisp_add_del_locator_set_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lisp_add_del_locator_set_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LISP_ADD_DEL_LOCATOR_SET_CRC);
  vl_api_lisp_add_del_locator_set_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LISP_ADD_DEL_LOCATOR_SET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lisp_add_del_locator_set_reply_t *rmp = (vl_api_lisp_add_del_locator_set_reply_t *)p;
  vl_api_lisp_add_del_locator_set_reply_t_endian(rmp, 0);
  return vl_api_lisp_add_del_locator_set_reply_t_tojson(rmp);
}

static cJSON *
api_lisp_add_del_locator (cJSON *o)
{
  vl_api_lisp_add_del_locator_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lisp_add_del_locator_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LISP_ADD_DEL_LOCATOR_CRC);
  vl_api_lisp_add_del_locator_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LISP_ADD_DEL_LOCATOR_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lisp_add_del_locator_reply_t *rmp = (vl_api_lisp_add_del_locator_reply_t *)p;
  vl_api_lisp_add_del_locator_reply_t_endian(rmp, 0);
  return vl_api_lisp_add_del_locator_reply_t_tojson(rmp);
}

static cJSON *
api_lisp_add_del_local_eid (cJSON *o)
{
  vl_api_lisp_add_del_local_eid_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lisp_add_del_local_eid_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LISP_ADD_DEL_LOCAL_EID_CRC);
  vl_api_lisp_add_del_local_eid_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LISP_ADD_DEL_LOCAL_EID_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lisp_add_del_local_eid_reply_t *rmp = (vl_api_lisp_add_del_local_eid_reply_t *)p;
  vl_api_lisp_add_del_local_eid_reply_t_endian(rmp, 0);
  return vl_api_lisp_add_del_local_eid_reply_t_tojson(rmp);
}

static cJSON *
api_lisp_add_del_map_server (cJSON *o)
{
  vl_api_lisp_add_del_map_server_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lisp_add_del_map_server_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LISP_ADD_DEL_MAP_SERVER_CRC);
  vl_api_lisp_add_del_map_server_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LISP_ADD_DEL_MAP_SERVER_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lisp_add_del_map_server_reply_t *rmp = (vl_api_lisp_add_del_map_server_reply_t *)p;
  vl_api_lisp_add_del_map_server_reply_t_endian(rmp, 0);
  return vl_api_lisp_add_del_map_server_reply_t_tojson(rmp);
}

static cJSON *
api_lisp_add_del_map_resolver (cJSON *o)
{
  vl_api_lisp_add_del_map_resolver_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lisp_add_del_map_resolver_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LISP_ADD_DEL_MAP_RESOLVER_CRC);
  vl_api_lisp_add_del_map_resolver_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LISP_ADD_DEL_MAP_RESOLVER_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lisp_add_del_map_resolver_reply_t *rmp = (vl_api_lisp_add_del_map_resolver_reply_t *)p;
  vl_api_lisp_add_del_map_resolver_reply_t_endian(rmp, 0);
  return vl_api_lisp_add_del_map_resolver_reply_t_tojson(rmp);
}

static cJSON *
api_lisp_enable_disable (cJSON *o)
{
  vl_api_lisp_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lisp_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LISP_ENABLE_DISABLE_CRC);
  vl_api_lisp_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LISP_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lisp_enable_disable_reply_t *rmp = (vl_api_lisp_enable_disable_reply_t *)p;
  vl_api_lisp_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_lisp_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_lisp_pitr_set_locator_set (cJSON *o)
{
  vl_api_lisp_pitr_set_locator_set_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lisp_pitr_set_locator_set_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LISP_PITR_SET_LOCATOR_SET_CRC);
  vl_api_lisp_pitr_set_locator_set_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LISP_PITR_SET_LOCATOR_SET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lisp_pitr_set_locator_set_reply_t *rmp = (vl_api_lisp_pitr_set_locator_set_reply_t *)p;
  vl_api_lisp_pitr_set_locator_set_reply_t_endian(rmp, 0);
  return vl_api_lisp_pitr_set_locator_set_reply_t_tojson(rmp);
}

static cJSON *
api_lisp_use_petr (cJSON *o)
{
  vl_api_lisp_use_petr_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lisp_use_petr_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LISP_USE_PETR_CRC);
  vl_api_lisp_use_petr_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LISP_USE_PETR_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lisp_use_petr_reply_t *rmp = (vl_api_lisp_use_petr_reply_t *)p;
  vl_api_lisp_use_petr_reply_t_endian(rmp, 0);
  return vl_api_lisp_use_petr_reply_t_tojson(rmp);
}

static cJSON *
api_show_lisp_use_petr (cJSON *o)
{
  vl_api_show_lisp_use_petr_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_show_lisp_use_petr_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SHOW_LISP_USE_PETR_CRC);
  vl_api_show_lisp_use_petr_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SHOW_LISP_USE_PETR_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_show_lisp_use_petr_reply_t *rmp = (vl_api_show_lisp_use_petr_reply_t *)p;
  vl_api_show_lisp_use_petr_reply_t_endian(rmp, 0);
  return vl_api_show_lisp_use_petr_reply_t_tojson(rmp);
}

static cJSON *
api_show_lisp_rloc_probe_state (cJSON *o)
{
  vl_api_show_lisp_rloc_probe_state_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_show_lisp_rloc_probe_state_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SHOW_LISP_RLOC_PROBE_STATE_CRC);
  vl_api_show_lisp_rloc_probe_state_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SHOW_LISP_RLOC_PROBE_STATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_show_lisp_rloc_probe_state_reply_t *rmp = (vl_api_show_lisp_rloc_probe_state_reply_t *)p;
  vl_api_show_lisp_rloc_probe_state_reply_t_endian(rmp, 0);
  return vl_api_show_lisp_rloc_probe_state_reply_t_tojson(rmp);
}

static cJSON *
api_lisp_rloc_probe_enable_disable (cJSON *o)
{
  vl_api_lisp_rloc_probe_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lisp_rloc_probe_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LISP_RLOC_PROBE_ENABLE_DISABLE_CRC);
  vl_api_lisp_rloc_probe_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LISP_RLOC_PROBE_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lisp_rloc_probe_enable_disable_reply_t *rmp = (vl_api_lisp_rloc_probe_enable_disable_reply_t *)p;
  vl_api_lisp_rloc_probe_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_lisp_rloc_probe_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_lisp_map_register_enable_disable (cJSON *o)
{
  vl_api_lisp_map_register_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lisp_map_register_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LISP_MAP_REGISTER_ENABLE_DISABLE_CRC);
  vl_api_lisp_map_register_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LISP_MAP_REGISTER_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lisp_map_register_enable_disable_reply_t *rmp = (vl_api_lisp_map_register_enable_disable_reply_t *)p;
  vl_api_lisp_map_register_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_lisp_map_register_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_show_lisp_map_register_state (cJSON *o)
{
  vl_api_show_lisp_map_register_state_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_show_lisp_map_register_state_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SHOW_LISP_MAP_REGISTER_STATE_CRC);
  vl_api_show_lisp_map_register_state_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SHOW_LISP_MAP_REGISTER_STATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_show_lisp_map_register_state_reply_t *rmp = (vl_api_show_lisp_map_register_state_reply_t *)p;
  vl_api_show_lisp_map_register_state_reply_t_endian(rmp, 0);
  return vl_api_show_lisp_map_register_state_reply_t_tojson(rmp);
}

static cJSON *
api_lisp_map_request_mode (cJSON *o)
{
  vl_api_lisp_map_request_mode_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lisp_map_request_mode_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LISP_MAP_REQUEST_MODE_CRC);
  vl_api_lisp_map_request_mode_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LISP_MAP_REQUEST_MODE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lisp_map_request_mode_reply_t *rmp = (vl_api_lisp_map_request_mode_reply_t *)p;
  vl_api_lisp_map_request_mode_reply_t_endian(rmp, 0);
  return vl_api_lisp_map_request_mode_reply_t_tojson(rmp);
}

static cJSON *
api_show_lisp_map_request_mode (cJSON *o)
{
  vl_api_show_lisp_map_request_mode_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_show_lisp_map_request_mode_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SHOW_LISP_MAP_REQUEST_MODE_CRC);
  vl_api_show_lisp_map_request_mode_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SHOW_LISP_MAP_REQUEST_MODE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_show_lisp_map_request_mode_reply_t *rmp = (vl_api_show_lisp_map_request_mode_reply_t *)p;
  vl_api_show_lisp_map_request_mode_reply_t_endian(rmp, 0);
  return vl_api_show_lisp_map_request_mode_reply_t_tojson(rmp);
}

static cJSON *
api_lisp_add_del_remote_mapping (cJSON *o)
{
  vl_api_lisp_add_del_remote_mapping_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lisp_add_del_remote_mapping_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LISP_ADD_DEL_REMOTE_MAPPING_CRC);
  vl_api_lisp_add_del_remote_mapping_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LISP_ADD_DEL_REMOTE_MAPPING_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lisp_add_del_remote_mapping_reply_t *rmp = (vl_api_lisp_add_del_remote_mapping_reply_t *)p;
  vl_api_lisp_add_del_remote_mapping_reply_t_endian(rmp, 0);
  return vl_api_lisp_add_del_remote_mapping_reply_t_tojson(rmp);
}

static cJSON *
api_lisp_add_del_adjacency (cJSON *o)
{
  vl_api_lisp_add_del_adjacency_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lisp_add_del_adjacency_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LISP_ADD_DEL_ADJACENCY_CRC);
  vl_api_lisp_add_del_adjacency_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LISP_ADD_DEL_ADJACENCY_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lisp_add_del_adjacency_reply_t *rmp = (vl_api_lisp_add_del_adjacency_reply_t *)p;
  vl_api_lisp_add_del_adjacency_reply_t_endian(rmp, 0);
  return vl_api_lisp_add_del_adjacency_reply_t_tojson(rmp);
}

static cJSON *
api_lisp_add_del_map_request_itr_rlocs (cJSON *o)
{
  vl_api_lisp_add_del_map_request_itr_rlocs_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lisp_add_del_map_request_itr_rlocs_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS_CRC);
  vl_api_lisp_add_del_map_request_itr_rlocs_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lisp_add_del_map_request_itr_rlocs_reply_t *rmp = (vl_api_lisp_add_del_map_request_itr_rlocs_reply_t *)p;
  vl_api_lisp_add_del_map_request_itr_rlocs_reply_t_endian(rmp, 0);
  return vl_api_lisp_add_del_map_request_itr_rlocs_reply_t_tojson(rmp);
}

static cJSON *
api_lisp_eid_table_add_del_map (cJSON *o)
{
  vl_api_lisp_eid_table_add_del_map_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lisp_eid_table_add_del_map_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LISP_EID_TABLE_ADD_DEL_MAP_CRC);
  vl_api_lisp_eid_table_add_del_map_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LISP_EID_TABLE_ADD_DEL_MAP_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lisp_eid_table_add_del_map_reply_t *rmp = (vl_api_lisp_eid_table_add_del_map_reply_t *)p;
  vl_api_lisp_eid_table_add_del_map_reply_t_endian(rmp, 0);
  return vl_api_lisp_eid_table_add_del_map_reply_t_tojson(rmp);
}

static cJSON *
api_lisp_locator_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_LISP_LOCATOR_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_lisp_locator_dump_t *mp = vl_api_lisp_locator_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_lisp_locator_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_LISP_LOCATOR_DETAILS_CRC);

  while (1) {
    /* Read reply */
    char *p;
    int l;
    vac_read(&p, &l, 5); // XXX: Fix timeout
    if (p == 0 || l == 0) {
      cJSON_free(reply);
      return 0;
    }

    /* Message can be one of [_details, control_ping_reply
     * or unrelated event]
     */
    u16 reply_msg_id = ntohs(*((u16 *)p));
    if (reply_msg_id == ping_reply_msg_id) {
        break;
    }

    if (reply_msg_id == details_msg_id) {
        if (l < sizeof(vl_api_lisp_locator_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_lisp_locator_details_t *rmp = (vl_api_lisp_locator_details_t *)p;
        vl_api_lisp_locator_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_lisp_locator_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_lisp_locator_set_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_LISP_LOCATOR_SET_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_lisp_locator_set_dump_t *mp = vl_api_lisp_locator_set_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_lisp_locator_set_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_LISP_LOCATOR_SET_DETAILS_CRC);

  while (1) {
    /* Read reply */
    char *p;
    int l;
    vac_read(&p, &l, 5); // XXX: Fix timeout
    if (p == 0 || l == 0) {
      cJSON_free(reply);
      return 0;
    }

    /* Message can be one of [_details, control_ping_reply
     * or unrelated event]
     */
    u16 reply_msg_id = ntohs(*((u16 *)p));
    if (reply_msg_id == ping_reply_msg_id) {
        break;
    }

    if (reply_msg_id == details_msg_id) {
        if (l < sizeof(vl_api_lisp_locator_set_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_lisp_locator_set_details_t *rmp = (vl_api_lisp_locator_set_details_t *)p;
        vl_api_lisp_locator_set_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_lisp_locator_set_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_lisp_eid_table_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_LISP_EID_TABLE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_lisp_eid_table_dump_t *mp = vl_api_lisp_eid_table_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_lisp_eid_table_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_LISP_EID_TABLE_DETAILS_CRC);

  while (1) {
    /* Read reply */
    char *p;
    int l;
    vac_read(&p, &l, 5); // XXX: Fix timeout
    if (p == 0 || l == 0) {
      cJSON_free(reply);
      return 0;
    }

    /* Message can be one of [_details, control_ping_reply
     * or unrelated event]
     */
    u16 reply_msg_id = ntohs(*((u16 *)p));
    if (reply_msg_id == ping_reply_msg_id) {
        break;
    }

    if (reply_msg_id == details_msg_id) {
        if (l < sizeof(vl_api_lisp_eid_table_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_lisp_eid_table_details_t *rmp = (vl_api_lisp_eid_table_details_t *)p;
        vl_api_lisp_eid_table_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_lisp_eid_table_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_lisp_adjacencies_get (cJSON *o)
{
  vl_api_lisp_adjacencies_get_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lisp_adjacencies_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LISP_ADJACENCIES_GET_CRC);
  vl_api_lisp_adjacencies_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LISP_ADJACENCIES_GET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lisp_adjacencies_get_reply_t *rmp = (vl_api_lisp_adjacencies_get_reply_t *)p;
  vl_api_lisp_adjacencies_get_reply_t_endian(rmp, 0);
  return vl_api_lisp_adjacencies_get_reply_t_tojson(rmp);
}

static cJSON *
api_lisp_eid_table_map_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_LISP_EID_TABLE_MAP_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_lisp_eid_table_map_dump_t *mp = vl_api_lisp_eid_table_map_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_lisp_eid_table_map_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_LISP_EID_TABLE_MAP_DETAILS_CRC);

  while (1) {
    /* Read reply */
    char *p;
    int l;
    vac_read(&p, &l, 5); // XXX: Fix timeout
    if (p == 0 || l == 0) {
      cJSON_free(reply);
      return 0;
    }

    /* Message can be one of [_details, control_ping_reply
     * or unrelated event]
     */
    u16 reply_msg_id = ntohs(*((u16 *)p));
    if (reply_msg_id == ping_reply_msg_id) {
        break;
    }

    if (reply_msg_id == details_msg_id) {
        if (l < sizeof(vl_api_lisp_eid_table_map_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_lisp_eid_table_map_details_t *rmp = (vl_api_lisp_eid_table_map_details_t *)p;
        vl_api_lisp_eid_table_map_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_lisp_eid_table_map_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_lisp_eid_table_vni_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_LISP_EID_TABLE_VNI_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_lisp_eid_table_vni_dump_t *mp = vl_api_lisp_eid_table_vni_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_lisp_eid_table_vni_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_LISP_EID_TABLE_VNI_DETAILS_CRC);

  while (1) {
    /* Read reply */
    char *p;
    int l;
    vac_read(&p, &l, 5); // XXX: Fix timeout
    if (p == 0 || l == 0) {
      cJSON_free(reply);
      return 0;
    }

    /* Message can be one of [_details, control_ping_reply
     * or unrelated event]
     */
    u16 reply_msg_id = ntohs(*((u16 *)p));
    if (reply_msg_id == ping_reply_msg_id) {
        break;
    }

    if (reply_msg_id == details_msg_id) {
        if (l < sizeof(vl_api_lisp_eid_table_vni_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_lisp_eid_table_vni_details_t *rmp = (vl_api_lisp_eid_table_vni_details_t *)p;
        vl_api_lisp_eid_table_vni_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_lisp_eid_table_vni_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_lisp_map_resolver_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_LISP_MAP_RESOLVER_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_lisp_map_resolver_dump_t *mp = vl_api_lisp_map_resolver_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_lisp_map_resolver_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_LISP_MAP_RESOLVER_DETAILS_CRC);

  while (1) {
    /* Read reply */
    char *p;
    int l;
    vac_read(&p, &l, 5); // XXX: Fix timeout
    if (p == 0 || l == 0) {
      cJSON_free(reply);
      return 0;
    }

    /* Message can be one of [_details, control_ping_reply
     * or unrelated event]
     */
    u16 reply_msg_id = ntohs(*((u16 *)p));
    if (reply_msg_id == ping_reply_msg_id) {
        break;
    }

    if (reply_msg_id == details_msg_id) {
        if (l < sizeof(vl_api_lisp_map_resolver_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_lisp_map_resolver_details_t *rmp = (vl_api_lisp_map_resolver_details_t *)p;
        vl_api_lisp_map_resolver_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_lisp_map_resolver_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_lisp_map_server_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_LISP_MAP_SERVER_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_lisp_map_server_dump_t *mp = vl_api_lisp_map_server_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_lisp_map_server_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_LISP_MAP_SERVER_DETAILS_CRC);

  while (1) {
    /* Read reply */
    char *p;
    int l;
    vac_read(&p, &l, 5); // XXX: Fix timeout
    if (p == 0 || l == 0) {
      cJSON_free(reply);
      return 0;
    }

    /* Message can be one of [_details, control_ping_reply
     * or unrelated event]
     */
    u16 reply_msg_id = ntohs(*((u16 *)p));
    if (reply_msg_id == ping_reply_msg_id) {
        break;
    }

    if (reply_msg_id == details_msg_id) {
        if (l < sizeof(vl_api_lisp_map_server_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_lisp_map_server_details_t *rmp = (vl_api_lisp_map_server_details_t *)p;
        vl_api_lisp_map_server_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_lisp_map_server_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_show_lisp_status (cJSON *o)
{
  vl_api_show_lisp_status_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_show_lisp_status_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SHOW_LISP_STATUS_CRC);
  vl_api_show_lisp_status_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SHOW_LISP_STATUS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_show_lisp_status_reply_t *rmp = (vl_api_show_lisp_status_reply_t *)p;
  vl_api_show_lisp_status_reply_t_endian(rmp, 0);
  return vl_api_show_lisp_status_reply_t_tojson(rmp);
}

static cJSON *
api_lisp_get_map_request_itr_rlocs (cJSON *o)
{
  vl_api_lisp_get_map_request_itr_rlocs_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lisp_get_map_request_itr_rlocs_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LISP_GET_MAP_REQUEST_ITR_RLOCS_CRC);
  vl_api_lisp_get_map_request_itr_rlocs_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LISP_GET_MAP_REQUEST_ITR_RLOCS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lisp_get_map_request_itr_rlocs_reply_t *rmp = (vl_api_lisp_get_map_request_itr_rlocs_reply_t *)p;
  vl_api_lisp_get_map_request_itr_rlocs_reply_t_endian(rmp, 0);
  return vl_api_lisp_get_map_request_itr_rlocs_reply_t_tojson(rmp);
}

static cJSON *
api_show_lisp_pitr (cJSON *o)
{
  vl_api_show_lisp_pitr_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_show_lisp_pitr_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SHOW_LISP_PITR_CRC);
  vl_api_show_lisp_pitr_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SHOW_LISP_PITR_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_show_lisp_pitr_reply_t *rmp = (vl_api_show_lisp_pitr_reply_t *)p;
  vl_api_show_lisp_pitr_reply_t_endian(rmp, 0);
  return vl_api_show_lisp_pitr_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("lisp_add_del_locator_set", api_lisp_add_del_locator_set, (cJSON * (*)(void *))vl_api_lisp_add_del_locator_set_t_tojson, 0x6fcd6471);
   vat2_register_function("lisp_add_del_locator", api_lisp_add_del_locator, (cJSON * (*)(void *))vl_api_lisp_add_del_locator_t_tojson, 0xaf4d8f13);
   vat2_register_function("lisp_add_del_local_eid", api_lisp_add_del_local_eid, (cJSON * (*)(void *))vl_api_lisp_add_del_local_eid_t_tojson, 0x4e5a83a2);
   vat2_register_function("lisp_add_del_map_server", api_lisp_add_del_map_server, (cJSON * (*)(void *))vl_api_lisp_add_del_map_server_t_tojson, 0xce19e32d);
   vat2_register_function("lisp_add_del_map_resolver", api_lisp_add_del_map_resolver, (cJSON * (*)(void *))vl_api_lisp_add_del_map_resolver_t_tojson, 0xce19e32d);
   vat2_register_function("lisp_enable_disable", api_lisp_enable_disable, (cJSON * (*)(void *))vl_api_lisp_enable_disable_t_tojson, 0xc264d7bf);
   vat2_register_function("lisp_pitr_set_locator_set", api_lisp_pitr_set_locator_set, (cJSON * (*)(void *))vl_api_lisp_pitr_set_locator_set_t_tojson, 0x486e2b76);
   vat2_register_function("lisp_use_petr", api_lisp_use_petr, (cJSON * (*)(void *))vl_api_lisp_use_petr_t_tojson, 0xd87dbad9);
   vat2_register_function("show_lisp_use_petr", api_show_lisp_use_petr, (cJSON * (*)(void *))vl_api_show_lisp_use_petr_t_tojson, 0x51077d14);
   vat2_register_function("show_lisp_rloc_probe_state", api_show_lisp_rloc_probe_state, (cJSON * (*)(void *))vl_api_show_lisp_rloc_probe_state_t_tojson, 0x51077d14);
   vat2_register_function("lisp_rloc_probe_enable_disable", api_lisp_rloc_probe_enable_disable, (cJSON * (*)(void *))vl_api_lisp_rloc_probe_enable_disable_t_tojson, 0xc264d7bf);
   vat2_register_function("lisp_map_register_enable_disable", api_lisp_map_register_enable_disable, (cJSON * (*)(void *))vl_api_lisp_map_register_enable_disable_t_tojson, 0xc264d7bf);
   vat2_register_function("show_lisp_map_register_state", api_show_lisp_map_register_state, (cJSON * (*)(void *))vl_api_show_lisp_map_register_state_t_tojson, 0x51077d14);
   vat2_register_function("lisp_map_request_mode", api_lisp_map_request_mode, (cJSON * (*)(void *))vl_api_lisp_map_request_mode_t_tojson, 0xf43c26ae);
   vat2_register_function("show_lisp_map_request_mode", api_show_lisp_map_request_mode, (cJSON * (*)(void *))vl_api_show_lisp_map_request_mode_t_tojson, 0x51077d14);
   vat2_register_function("lisp_add_del_remote_mapping", api_lisp_add_del_remote_mapping, (cJSON * (*)(void *))vl_api_lisp_add_del_remote_mapping_t_tojson, 0x6d5c789e);
   vat2_register_function("lisp_add_del_adjacency", api_lisp_add_del_adjacency, (cJSON * (*)(void *))vl_api_lisp_add_del_adjacency_t_tojson, 0x2ce0e6f6);
   vat2_register_function("lisp_add_del_map_request_itr_rlocs", api_lisp_add_del_map_request_itr_rlocs, (cJSON * (*)(void *))vl_api_lisp_add_del_map_request_itr_rlocs_t_tojson, 0x6be88e45);
   vat2_register_function("lisp_eid_table_add_del_map", api_lisp_eid_table_add_del_map, (cJSON * (*)(void *))vl_api_lisp_eid_table_add_del_map_t_tojson, 0x9481416b);
   vat2_register_function("lisp_locator_dump", api_lisp_locator_dump, (cJSON * (*)(void *))vl_api_lisp_locator_dump_t_tojson, 0xb954fad7);
   vat2_register_function("lisp_locator_set_dump", api_lisp_locator_set_dump, (cJSON * (*)(void *))vl_api_lisp_locator_set_dump_t_tojson, 0xc2cb5922);
   vat2_register_function("lisp_eid_table_dump", api_lisp_eid_table_dump, (cJSON * (*)(void *))vl_api_lisp_eid_table_dump_t_tojson, 0x629468b5);
   vat2_register_function("lisp_adjacencies_get", api_lisp_adjacencies_get, (cJSON * (*)(void *))vl_api_lisp_adjacencies_get_t_tojson, 0x8d1f2fe9);
   vat2_register_function("lisp_eid_table_map_dump", api_lisp_eid_table_map_dump, (cJSON * (*)(void *))vl_api_lisp_eid_table_map_dump_t_tojson, 0xd6cf0c3d);
   vat2_register_function("lisp_eid_table_vni_dump", api_lisp_eid_table_vni_dump, (cJSON * (*)(void *))vl_api_lisp_eid_table_vni_dump_t_tojson, 0x51077d14);
   vat2_register_function("lisp_map_resolver_dump", api_lisp_map_resolver_dump, (cJSON * (*)(void *))vl_api_lisp_map_resolver_dump_t_tojson, 0x51077d14);
   vat2_register_function("lisp_map_server_dump", api_lisp_map_server_dump, (cJSON * (*)(void *))vl_api_lisp_map_server_dump_t_tojson, 0x51077d14);
   vat2_register_function("show_lisp_status", api_show_lisp_status, (cJSON * (*)(void *))vl_api_show_lisp_status_t_tojson, 0x51077d14);
   vat2_register_function("lisp_get_map_request_itr_rlocs", api_lisp_get_map_request_itr_rlocs, (cJSON * (*)(void *))vl_api_lisp_get_map_request_itr_rlocs_t_tojson, 0x51077d14);
   vat2_register_function("show_lisp_pitr", api_show_lisp_pitr, (cJSON * (*)(void *))vl_api_show_lisp_pitr_t_tojson, 0x51077d14);
   return 0;
}
