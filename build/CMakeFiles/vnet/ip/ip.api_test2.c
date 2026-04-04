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

#include "ip.api_enum.h"
#include "ip.api_types.h"

#define vl_endianfun		/* define message structures */
#include "ip.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ip.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "ip.api.h"
#undef vl_printfun

#include "ip.api_tojson.h"
#include "ip.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_ip_path_mtu_get (cJSON *o)
{
    u16 msg_id = vac_get_msg_index(VL_API_IP_PATH_MTU_GET_CRC);
  int len = 0;
  if (!o) return 0;
  vl_api_ip_path_mtu_get_t *mp = vl_api_ip_path_mtu_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }
  mp->_vl_msg_id = msg_id;

  vl_api_ip_path_mtu_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  cJSON *reply = cJSON_CreateArray();

  u16 reply_msg_id = vac_get_msg_index(VL_API_IP_PATH_MTU_GET_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IP_PATH_MTU_DETAILS_CRC);

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
        vl_api_ip_path_mtu_get_reply_t *rmp = (vl_api_ip_path_mtu_get_reply_t *)p;
        vl_api_ip_path_mtu_get_reply_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ip_path_mtu_get_reply_t_tojson(rmp));
        break;
    }

    if (msg_id == details_msg_id) {
        vl_api_ip_path_mtu_details_t *rmp = (vl_api_ip_path_mtu_details_t *)p;
        vl_api_ip_path_mtu_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ip_path_mtu_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ip_table_add_del (cJSON *o)
{
  vl_api_ip_table_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_table_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_TABLE_ADD_DEL_CRC);
  vl_api_ip_table_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_TABLE_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_table_add_del_reply_t *rmp = (vl_api_ip_table_add_del_reply_t *)p;
  vl_api_ip_table_add_del_reply_t_endian(rmp, 0);
  return vl_api_ip_table_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_ip_table_add_del_v2 (cJSON *o)
{
  vl_api_ip_table_add_del_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_table_add_del_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_TABLE_ADD_DEL_V2_CRC);
  vl_api_ip_table_add_del_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_TABLE_ADD_DEL_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_table_add_del_v2_reply_t *rmp = (vl_api_ip_table_add_del_v2_reply_t *)p;
  vl_api_ip_table_add_del_v2_reply_t_endian(rmp, 0);
  return vl_api_ip_table_add_del_v2_reply_t_tojson(rmp);
}

static cJSON *
api_ip_table_allocate (cJSON *o)
{
  vl_api_ip_table_allocate_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_table_allocate_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_TABLE_ALLOCATE_CRC);
  vl_api_ip_table_allocate_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_TABLE_ALLOCATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_table_allocate_reply_t *rmp = (vl_api_ip_table_allocate_reply_t *)p;
  vl_api_ip_table_allocate_reply_t_endian(rmp, 0);
  return vl_api_ip_table_allocate_reply_t_tojson(rmp);
}

static cJSON *
api_ip_table_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IP_TABLE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ip_table_dump_t *mp = vl_api_ip_table_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ip_table_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IP_TABLE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ip_table_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ip_table_details_t *rmp = (vl_api_ip_table_details_t *)p;
        vl_api_ip_table_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ip_table_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ip_table_replace_begin (cJSON *o)
{
  vl_api_ip_table_replace_begin_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_table_replace_begin_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_TABLE_REPLACE_BEGIN_CRC);
  vl_api_ip_table_replace_begin_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_TABLE_REPLACE_BEGIN_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_table_replace_begin_reply_t *rmp = (vl_api_ip_table_replace_begin_reply_t *)p;
  vl_api_ip_table_replace_begin_reply_t_endian(rmp, 0);
  return vl_api_ip_table_replace_begin_reply_t_tojson(rmp);
}

static cJSON *
api_ip_table_replace_end (cJSON *o)
{
  vl_api_ip_table_replace_end_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_table_replace_end_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_TABLE_REPLACE_END_CRC);
  vl_api_ip_table_replace_end_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_TABLE_REPLACE_END_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_table_replace_end_reply_t *rmp = (vl_api_ip_table_replace_end_reply_t *)p;
  vl_api_ip_table_replace_end_reply_t_endian(rmp, 0);
  return vl_api_ip_table_replace_end_reply_t_tojson(rmp);
}

static cJSON *
api_ip_table_flush (cJSON *o)
{
  vl_api_ip_table_flush_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_table_flush_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_TABLE_FLUSH_CRC);
  vl_api_ip_table_flush_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_TABLE_FLUSH_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_table_flush_reply_t *rmp = (vl_api_ip_table_flush_reply_t *)p;
  vl_api_ip_table_flush_reply_t_endian(rmp, 0);
  return vl_api_ip_table_flush_reply_t_tojson(rmp);
}

static cJSON *
api_ip_route_add_del (cJSON *o)
{
  vl_api_ip_route_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_route_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_ROUTE_ADD_DEL_CRC);
  vl_api_ip_route_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_ROUTE_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_route_add_del_reply_t *rmp = (vl_api_ip_route_add_del_reply_t *)p;
  vl_api_ip_route_add_del_reply_t_endian(rmp, 0);
  return vl_api_ip_route_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_ip_route_add_del_v2 (cJSON *o)
{
  vl_api_ip_route_add_del_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_route_add_del_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_ROUTE_ADD_DEL_V2_CRC);
  vl_api_ip_route_add_del_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_ROUTE_ADD_DEL_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_route_add_del_v2_reply_t *rmp = (vl_api_ip_route_add_del_v2_reply_t *)p;
  vl_api_ip_route_add_del_v2_reply_t_endian(rmp, 0);
  return vl_api_ip_route_add_del_v2_reply_t_tojson(rmp);
}

static cJSON *
api_ip_route_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IP_ROUTE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ip_route_dump_t *mp = vl_api_ip_route_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ip_route_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IP_ROUTE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ip_route_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ip_route_details_t *rmp = (vl_api_ip_route_details_t *)p;
        vl_api_ip_route_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ip_route_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ip_route_v2_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IP_ROUTE_V2_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ip_route_v2_dump_t *mp = vl_api_ip_route_v2_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ip_route_v2_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IP_ROUTE_V2_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ip_route_v2_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ip_route_v2_details_t *rmp = (vl_api_ip_route_v2_details_t *)p;
        vl_api_ip_route_v2_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ip_route_v2_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ip_route_lookup (cJSON *o)
{
  vl_api_ip_route_lookup_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_route_lookup_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_ROUTE_LOOKUP_CRC);
  vl_api_ip_route_lookup_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_ROUTE_LOOKUP_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_route_lookup_reply_t *rmp = (vl_api_ip_route_lookup_reply_t *)p;
  vl_api_ip_route_lookup_reply_t_endian(rmp, 0);
  return vl_api_ip_route_lookup_reply_t_tojson(rmp);
}

static cJSON *
api_ip_route_lookup_v2 (cJSON *o)
{
  vl_api_ip_route_lookup_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_route_lookup_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_ROUTE_LOOKUP_V2_CRC);
  vl_api_ip_route_lookup_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_ROUTE_LOOKUP_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_route_lookup_v2_reply_t *rmp = (vl_api_ip_route_lookup_v2_reply_t *)p;
  vl_api_ip_route_lookup_v2_reply_t_endian(rmp, 0);
  return vl_api_ip_route_lookup_v2_reply_t_tojson(rmp);
}

static cJSON *
api_set_ip_flow_hash (cJSON *o)
{
  vl_api_set_ip_flow_hash_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_set_ip_flow_hash_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SET_IP_FLOW_HASH_CRC);
  vl_api_set_ip_flow_hash_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SET_IP_FLOW_HASH_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_set_ip_flow_hash_reply_t *rmp = (vl_api_set_ip_flow_hash_reply_t *)p;
  vl_api_set_ip_flow_hash_reply_t_endian(rmp, 0);
  return vl_api_set_ip_flow_hash_reply_t_tojson(rmp);
}

static cJSON *
api_set_ip_flow_hash_v2 (cJSON *o)
{
  vl_api_set_ip_flow_hash_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_set_ip_flow_hash_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SET_IP_FLOW_HASH_V2_CRC);
  vl_api_set_ip_flow_hash_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SET_IP_FLOW_HASH_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_set_ip_flow_hash_v2_reply_t *rmp = (vl_api_set_ip_flow_hash_v2_reply_t *)p;
  vl_api_set_ip_flow_hash_v2_reply_t_endian(rmp, 0);
  return vl_api_set_ip_flow_hash_v2_reply_t_tojson(rmp);
}

static cJSON *
api_set_ip_flow_hash_v3 (cJSON *o)
{
  vl_api_set_ip_flow_hash_v3_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_set_ip_flow_hash_v3_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SET_IP_FLOW_HASH_V3_CRC);
  vl_api_set_ip_flow_hash_v3_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SET_IP_FLOW_HASH_V3_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_set_ip_flow_hash_v3_reply_t *rmp = (vl_api_set_ip_flow_hash_v3_reply_t *)p;
  vl_api_set_ip_flow_hash_v3_reply_t_endian(rmp, 0);
  return vl_api_set_ip_flow_hash_v3_reply_t_tojson(rmp);
}

static cJSON *
api_set_ip_flow_hash_router_id (cJSON *o)
{
  vl_api_set_ip_flow_hash_router_id_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_set_ip_flow_hash_router_id_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SET_IP_FLOW_HASH_ROUTER_ID_CRC);
  vl_api_set_ip_flow_hash_router_id_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SET_IP_FLOW_HASH_ROUTER_ID_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_set_ip_flow_hash_router_id_reply_t *rmp = (vl_api_set_ip_flow_hash_router_id_reply_t *)p;
  vl_api_set_ip_flow_hash_router_id_reply_t_endian(rmp, 0);
  return vl_api_set_ip_flow_hash_router_id_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_ip6_enable_disable (cJSON *o)
{
  vl_api_sw_interface_ip6_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_ip6_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_IP6_ENABLE_DISABLE_CRC);
  vl_api_sw_interface_ip6_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_IP6_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_ip6_enable_disable_reply_t *rmp = (vl_api_sw_interface_ip6_enable_disable_reply_t *)p;
  vl_api_sw_interface_ip6_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_ip6_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_ip4_enable_disable (cJSON *o)
{
  vl_api_sw_interface_ip4_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_ip4_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_IP4_ENABLE_DISABLE_CRC);
  vl_api_sw_interface_ip4_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_IP4_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_ip4_enable_disable_reply_t *rmp = (vl_api_sw_interface_ip4_enable_disable_reply_t *)p;
  vl_api_sw_interface_ip4_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_ip4_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_ip_mtable_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IP_MTABLE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ip_mtable_dump_t *mp = vl_api_ip_mtable_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ip_mtable_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IP_MTABLE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ip_mtable_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ip_mtable_details_t *rmp = (vl_api_ip_mtable_details_t *)p;
        vl_api_ip_mtable_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ip_mtable_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ip_mroute_add_del (cJSON *o)
{
  vl_api_ip_mroute_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_mroute_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_MROUTE_ADD_DEL_CRC);
  vl_api_ip_mroute_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_MROUTE_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_mroute_add_del_reply_t *rmp = (vl_api_ip_mroute_add_del_reply_t *)p;
  vl_api_ip_mroute_add_del_reply_t_endian(rmp, 0);
  return vl_api_ip_mroute_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_ip_mroute_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IP_MROUTE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ip_mroute_dump_t *mp = vl_api_ip_mroute_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ip_mroute_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IP_MROUTE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ip_mroute_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ip_mroute_details_t *rmp = (vl_api_ip_mroute_details_t *)p;
        vl_api_ip_mroute_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ip_mroute_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ip_address_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IP_ADDRESS_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ip_address_dump_t *mp = vl_api_ip_address_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ip_address_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IP_ADDRESS_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ip_address_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ip_address_details_t *rmp = (vl_api_ip_address_details_t *)p;
        vl_api_ip_address_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ip_address_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ip_unnumbered_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IP_UNNUMBERED_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ip_unnumbered_dump_t *mp = vl_api_ip_unnumbered_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ip_unnumbered_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IP_UNNUMBERED_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ip_unnumbered_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ip_unnumbered_details_t *rmp = (vl_api_ip_unnumbered_details_t *)p;
        vl_api_ip_unnumbered_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ip_unnumbered_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ip_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IP_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ip_dump_t *mp = vl_api_ip_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ip_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IP_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ip_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ip_details_t *rmp = (vl_api_ip_details_t *)p;
        vl_api_ip_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ip_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_mfib_signal_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_MFIB_SIGNAL_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_mfib_signal_dump_t *mp = vl_api_mfib_signal_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_mfib_signal_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_MFIB_SIGNAL_DETAILS_CRC);

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
        if (l < sizeof(vl_api_mfib_signal_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_mfib_signal_details_t *rmp = (vl_api_mfib_signal_details_t *)p;
        vl_api_mfib_signal_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_mfib_signal_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ip_punt_police (cJSON *o)
{
  vl_api_ip_punt_police_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_punt_police_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_PUNT_POLICE_CRC);
  vl_api_ip_punt_police_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_PUNT_POLICE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_punt_police_reply_t *rmp = (vl_api_ip_punt_police_reply_t *)p;
  vl_api_ip_punt_police_reply_t_endian(rmp, 0);
  return vl_api_ip_punt_police_reply_t_tojson(rmp);
}

static cJSON *
api_ip_punt_redirect (cJSON *o)
{
  vl_api_ip_punt_redirect_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_punt_redirect_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_PUNT_REDIRECT_CRC);
  vl_api_ip_punt_redirect_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_PUNT_REDIRECT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_punt_redirect_reply_t *rmp = (vl_api_ip_punt_redirect_reply_t *)p;
  vl_api_ip_punt_redirect_reply_t_endian(rmp, 0);
  return vl_api_ip_punt_redirect_reply_t_tojson(rmp);
}

static cJSON *
api_ip_punt_redirect_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IP_PUNT_REDIRECT_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ip_punt_redirect_dump_t *mp = vl_api_ip_punt_redirect_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ip_punt_redirect_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IP_PUNT_REDIRECT_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ip_punt_redirect_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ip_punt_redirect_details_t *rmp = (vl_api_ip_punt_redirect_details_t *)p;
        vl_api_ip_punt_redirect_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ip_punt_redirect_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_add_del_ip_punt_redirect_v2 (cJSON *o)
{
  vl_api_add_del_ip_punt_redirect_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_add_del_ip_punt_redirect_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_ADD_DEL_IP_PUNT_REDIRECT_V2_CRC);
  vl_api_add_del_ip_punt_redirect_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_ADD_DEL_IP_PUNT_REDIRECT_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_add_del_ip_punt_redirect_v2_reply_t *rmp = (vl_api_add_del_ip_punt_redirect_v2_reply_t *)p;
  vl_api_add_del_ip_punt_redirect_v2_reply_t_endian(rmp, 0);
  return vl_api_add_del_ip_punt_redirect_v2_reply_t_tojson(rmp);
}

static cJSON *
api_ip_punt_redirect_v2_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IP_PUNT_REDIRECT_V2_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ip_punt_redirect_v2_dump_t *mp = vl_api_ip_punt_redirect_v2_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ip_punt_redirect_v2_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IP_PUNT_REDIRECT_V2_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ip_punt_redirect_v2_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ip_punt_redirect_v2_details_t *rmp = (vl_api_ip_punt_redirect_v2_details_t *)p;
        vl_api_ip_punt_redirect_v2_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ip_punt_redirect_v2_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ip_container_proxy_add_del (cJSON *o)
{
  vl_api_ip_container_proxy_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_container_proxy_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_CONTAINER_PROXY_ADD_DEL_CRC);
  vl_api_ip_container_proxy_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_CONTAINER_PROXY_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_container_proxy_add_del_reply_t *rmp = (vl_api_ip_container_proxy_add_del_reply_t *)p;
  vl_api_ip_container_proxy_add_del_reply_t_endian(rmp, 0);
  return vl_api_ip_container_proxy_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_ip_container_proxy_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IP_CONTAINER_PROXY_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ip_container_proxy_dump_t *mp = vl_api_ip_container_proxy_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ip_container_proxy_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IP_CONTAINER_PROXY_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ip_container_proxy_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ip_container_proxy_details_t *rmp = (vl_api_ip_container_proxy_details_t *)p;
        vl_api_ip_container_proxy_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ip_container_proxy_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ip_source_and_port_range_check_add_del (cJSON *o)
{
  vl_api_ip_source_and_port_range_check_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_source_and_port_range_check_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_SOURCE_AND_PORT_RANGE_CHECK_ADD_DEL_CRC);
  vl_api_ip_source_and_port_range_check_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_SOURCE_AND_PORT_RANGE_CHECK_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_source_and_port_range_check_add_del_reply_t *rmp = (vl_api_ip_source_and_port_range_check_add_del_reply_t *)p;
  vl_api_ip_source_and_port_range_check_add_del_reply_t_endian(rmp, 0);
  return vl_api_ip_source_and_port_range_check_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_ip_source_and_port_range_check_interface_add_del (cJSON *o)
{
  vl_api_ip_source_and_port_range_check_interface_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_source_and_port_range_check_interface_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_SOURCE_AND_PORT_RANGE_CHECK_INTERFACE_ADD_DEL_CRC);
  vl_api_ip_source_and_port_range_check_interface_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_SOURCE_AND_PORT_RANGE_CHECK_INTERFACE_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_source_and_port_range_check_interface_add_del_reply_t *rmp = (vl_api_ip_source_and_port_range_check_interface_add_del_reply_t *)p;
  vl_api_ip_source_and_port_range_check_interface_add_del_reply_t_endian(rmp, 0);
  return vl_api_ip_source_and_port_range_check_interface_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_ip6_set_link_local_address (cJSON *o)
{
  vl_api_sw_interface_ip6_set_link_local_address_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_ip6_set_link_local_address_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_IP6_SET_LINK_LOCAL_ADDRESS_CRC);
  vl_api_sw_interface_ip6_set_link_local_address_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_IP6_SET_LINK_LOCAL_ADDRESS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_ip6_set_link_local_address_reply_t *rmp = (vl_api_sw_interface_ip6_set_link_local_address_reply_t *)p;
  vl_api_sw_interface_ip6_set_link_local_address_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_ip6_set_link_local_address_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_ip6_get_link_local_address (cJSON *o)
{
  vl_api_sw_interface_ip6_get_link_local_address_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_ip6_get_link_local_address_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_IP6_GET_LINK_LOCAL_ADDRESS_CRC);
  vl_api_sw_interface_ip6_get_link_local_address_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_IP6_GET_LINK_LOCAL_ADDRESS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_ip6_get_link_local_address_reply_t *rmp = (vl_api_sw_interface_ip6_get_link_local_address_reply_t *)p;
  vl_api_sw_interface_ip6_get_link_local_address_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_ip6_get_link_local_address_reply_t_tojson(rmp);
}

static cJSON *
api_ioam_enable (cJSON *o)
{
  vl_api_ioam_enable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ioam_enable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IOAM_ENABLE_CRC);
  vl_api_ioam_enable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IOAM_ENABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ioam_enable_reply_t *rmp = (vl_api_ioam_enable_reply_t *)p;
  vl_api_ioam_enable_reply_t_endian(rmp, 0);
  return vl_api_ioam_enable_reply_t_tojson(rmp);
}

static cJSON *
api_ioam_disable (cJSON *o)
{
  vl_api_ioam_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ioam_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IOAM_DISABLE_CRC);
  vl_api_ioam_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IOAM_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ioam_disable_reply_t *rmp = (vl_api_ioam_disable_reply_t *)p;
  vl_api_ioam_disable_reply_t_endian(rmp, 0);
  return vl_api_ioam_disable_reply_t_tojson(rmp);
}

static cJSON *
api_ip_reassembly_set (cJSON *o)
{
  vl_api_ip_reassembly_set_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_reassembly_set_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_REASSEMBLY_SET_CRC);
  vl_api_ip_reassembly_set_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_REASSEMBLY_SET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_reassembly_set_reply_t *rmp = (vl_api_ip_reassembly_set_reply_t *)p;
  vl_api_ip_reassembly_set_reply_t_endian(rmp, 0);
  return vl_api_ip_reassembly_set_reply_t_tojson(rmp);
}

static cJSON *
api_ip_reassembly_get (cJSON *o)
{
  vl_api_ip_reassembly_get_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_reassembly_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_REASSEMBLY_GET_CRC);
  vl_api_ip_reassembly_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_REASSEMBLY_GET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_reassembly_get_reply_t *rmp = (vl_api_ip_reassembly_get_reply_t *)p;
  vl_api_ip_reassembly_get_reply_t_endian(rmp, 0);
  return vl_api_ip_reassembly_get_reply_t_tojson(rmp);
}

static cJSON *
api_ip_reassembly_enable_disable (cJSON *o)
{
  vl_api_ip_reassembly_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_reassembly_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_REASSEMBLY_ENABLE_DISABLE_CRC);
  vl_api_ip_reassembly_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_REASSEMBLY_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_reassembly_enable_disable_reply_t *rmp = (vl_api_ip_reassembly_enable_disable_reply_t *)p;
  vl_api_ip_reassembly_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_ip_reassembly_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_ip_local_reass_enable_disable (cJSON *o)
{
  vl_api_ip_local_reass_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_local_reass_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_LOCAL_REASS_ENABLE_DISABLE_CRC);
  vl_api_ip_local_reass_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_LOCAL_REASS_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_local_reass_enable_disable_reply_t *rmp = (vl_api_ip_local_reass_enable_disable_reply_t *)p;
  vl_api_ip_local_reass_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_ip_local_reass_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_ip_local_reass_get (cJSON *o)
{
  vl_api_ip_local_reass_get_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_local_reass_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_LOCAL_REASS_GET_CRC);
  vl_api_ip_local_reass_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_LOCAL_REASS_GET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_local_reass_get_reply_t *rmp = (vl_api_ip_local_reass_get_reply_t *)p;
  vl_api_ip_local_reass_get_reply_t_endian(rmp, 0);
  return vl_api_ip_local_reass_get_reply_t_tojson(rmp);
}

static cJSON *
api_ip_path_mtu_update (cJSON *o)
{
  vl_api_ip_path_mtu_update_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_path_mtu_update_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_PATH_MTU_UPDATE_CRC);
  vl_api_ip_path_mtu_update_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_PATH_MTU_UPDATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_path_mtu_update_reply_t *rmp = (vl_api_ip_path_mtu_update_reply_t *)p;
  vl_api_ip_path_mtu_update_reply_t_endian(rmp, 0);
  return vl_api_ip_path_mtu_update_reply_t_tojson(rmp);
}

static cJSON *
api_ip_path_mtu_replace_begin (cJSON *o)
{
  vl_api_ip_path_mtu_replace_begin_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_path_mtu_replace_begin_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_PATH_MTU_REPLACE_BEGIN_CRC);
  vl_api_ip_path_mtu_replace_begin_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_PATH_MTU_REPLACE_BEGIN_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_path_mtu_replace_begin_reply_t *rmp = (vl_api_ip_path_mtu_replace_begin_reply_t *)p;
  vl_api_ip_path_mtu_replace_begin_reply_t_endian(rmp, 0);
  return vl_api_ip_path_mtu_replace_begin_reply_t_tojson(rmp);
}

static cJSON *
api_ip_path_mtu_replace_end (cJSON *o)
{
  vl_api_ip_path_mtu_replace_end_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_path_mtu_replace_end_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_PATH_MTU_REPLACE_END_CRC);
  vl_api_ip_path_mtu_replace_end_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_PATH_MTU_REPLACE_END_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_path_mtu_replace_end_reply_t *rmp = (vl_api_ip_path_mtu_replace_end_reply_t *)p;
  vl_api_ip_path_mtu_replace_end_reply_t_endian(rmp, 0);
  return vl_api_ip_path_mtu_replace_end_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("ip_path_mtu_get", api_ip_path_mtu_get, (cJSON * (*)(void *))vl_api_ip_path_mtu_get_t_tojson, 0xf75ba505);
   vat2_register_function("ip_table_add_del", api_ip_table_add_del, (cJSON * (*)(void *))vl_api_ip_table_add_del_t_tojson, 0x0ffdaec0);
   vat2_register_function("ip_table_add_del_v2", api_ip_table_add_del_v2, (cJSON * (*)(void *))vl_api_ip_table_add_del_v2_t_tojson, 0x14e5081f);
   vat2_register_function("ip_table_allocate", api_ip_table_allocate, (cJSON * (*)(void *))vl_api_ip_table_allocate_t_tojson, 0xb9d2e09e);
   vat2_register_function("ip_table_dump", api_ip_table_dump, (cJSON * (*)(void *))vl_api_ip_table_dump_t_tojson, 0x51077d14);
   vat2_register_function("ip_table_replace_begin", api_ip_table_replace_begin, (cJSON * (*)(void *))vl_api_ip_table_replace_begin_t_tojson, 0xb9d2e09e);
   vat2_register_function("ip_table_replace_end", api_ip_table_replace_end, (cJSON * (*)(void *))vl_api_ip_table_replace_end_t_tojson, 0xb9d2e09e);
   vat2_register_function("ip_table_flush", api_ip_table_flush, (cJSON * (*)(void *))vl_api_ip_table_flush_t_tojson, 0xb9d2e09e);
   vat2_register_function("ip_route_add_del", api_ip_route_add_del, (cJSON * (*)(void *))vl_api_ip_route_add_del_t_tojson, 0xb8ecfe0d);
   vat2_register_function("ip_route_add_del_v2", api_ip_route_add_del_v2, (cJSON * (*)(void *))vl_api_ip_route_add_del_v2_t_tojson, 0x521ef330);
   vat2_register_function("ip_route_dump", api_ip_route_dump, (cJSON * (*)(void *))vl_api_ip_route_dump_t_tojson, 0xb9d2e09e);
   vat2_register_function("ip_route_v2_dump", api_ip_route_v2_dump, (cJSON * (*)(void *))vl_api_ip_route_v2_dump_t_tojson, 0xd16f72e6);
   vat2_register_function("ip_route_lookup", api_ip_route_lookup, (cJSON * (*)(void *))vl_api_ip_route_lookup_t_tojson, 0x710d6471);
   vat2_register_function("ip_route_lookup_v2", api_ip_route_lookup_v2, (cJSON * (*)(void *))vl_api_ip_route_lookup_v2_t_tojson, 0x710d6471);
   vat2_register_function("set_ip_flow_hash", api_set_ip_flow_hash, (cJSON * (*)(void *))vl_api_set_ip_flow_hash_t_tojson, 0x084ee09e);
   vat2_register_function("set_ip_flow_hash_v2", api_set_ip_flow_hash_v2, (cJSON * (*)(void *))vl_api_set_ip_flow_hash_v2_t_tojson, 0x6d132100);
   vat2_register_function("set_ip_flow_hash_v3", api_set_ip_flow_hash_v3, (cJSON * (*)(void *))vl_api_set_ip_flow_hash_v3_t_tojson, 0xb7876e07);
   vat2_register_function("set_ip_flow_hash_router_id", api_set_ip_flow_hash_router_id, (cJSON * (*)(void *))vl_api_set_ip_flow_hash_router_id_t_tojson, 0x03e4f48e);
   vat2_register_function("sw_interface_ip6_enable_disable", api_sw_interface_ip6_enable_disable, (cJSON * (*)(void *))vl_api_sw_interface_ip6_enable_disable_t_tojson, 0xae6cfcfb);
   vat2_register_function("sw_interface_ip4_enable_disable", api_sw_interface_ip4_enable_disable, (cJSON * (*)(void *))vl_api_sw_interface_ip4_enable_disable_t_tojson, 0xae6cfcfb);
   vat2_register_function("ip_mtable_dump", api_ip_mtable_dump, (cJSON * (*)(void *))vl_api_ip_mtable_dump_t_tojson, 0x51077d14);
   vat2_register_function("ip_mroute_add_del", api_ip_mroute_add_del, (cJSON * (*)(void *))vl_api_ip_mroute_add_del_t_tojson, 0x0dd7e790);
   vat2_register_function("ip_mroute_dump", api_ip_mroute_dump, (cJSON * (*)(void *))vl_api_ip_mroute_dump_t_tojson, 0xb9d2e09e);
   vat2_register_function("ip_address_dump", api_ip_address_dump, (cJSON * (*)(void *))vl_api_ip_address_dump_t_tojson, 0x2d033de4);
   vat2_register_function("ip_unnumbered_dump", api_ip_unnumbered_dump, (cJSON * (*)(void *))vl_api_ip_unnumbered_dump_t_tojson, 0xf9e6675e);
   vat2_register_function("ip_dump", api_ip_dump, (cJSON * (*)(void *))vl_api_ip_dump_t_tojson, 0x98d231ca);
   vat2_register_function("mfib_signal_dump", api_mfib_signal_dump, (cJSON * (*)(void *))vl_api_mfib_signal_dump_t_tojson, 0x51077d14);
   vat2_register_function("ip_punt_police", api_ip_punt_police, (cJSON * (*)(void *))vl_api_ip_punt_police_t_tojson, 0xdb867cea);
   vat2_register_function("ip_punt_redirect", api_ip_punt_redirect, (cJSON * (*)(void *))vl_api_ip_punt_redirect_t_tojson, 0x6580f635);
   vat2_register_function("ip_punt_redirect_dump", api_ip_punt_redirect_dump, (cJSON * (*)(void *))vl_api_ip_punt_redirect_dump_t_tojson, 0x2d033de4);
   vat2_register_function("add_del_ip_punt_redirect_v2", api_add_del_ip_punt_redirect_v2, (cJSON * (*)(void *))vl_api_add_del_ip_punt_redirect_v2_t_tojson, 0x9e804227);
   vat2_register_function("ip_punt_redirect_v2_dump", api_ip_punt_redirect_v2_dump, (cJSON * (*)(void *))vl_api_ip_punt_redirect_v2_dump_t_tojson, 0xd817a484);
   vat2_register_function("ip_container_proxy_add_del", api_ip_container_proxy_add_del, (cJSON * (*)(void *))vl_api_ip_container_proxy_add_del_t_tojson, 0x7df1dff1);
   vat2_register_function("ip_container_proxy_dump", api_ip_container_proxy_dump, (cJSON * (*)(void *))vl_api_ip_container_proxy_dump_t_tojson, 0x51077d14);
   vat2_register_function("ip_source_and_port_range_check_add_del", api_ip_source_and_port_range_check_add_del, (cJSON * (*)(void *))vl_api_ip_source_and_port_range_check_add_del_t_tojson, 0x92a067e3);
   vat2_register_function("ip_source_and_port_range_check_interface_add_del", api_ip_source_and_port_range_check_interface_add_del, (cJSON * (*)(void *))vl_api_ip_source_and_port_range_check_interface_add_del_t_tojson, 0xe1ba8987);
   vat2_register_function("sw_interface_ip6_set_link_local_address", api_sw_interface_ip6_set_link_local_address, (cJSON * (*)(void *))vl_api_sw_interface_ip6_set_link_local_address_t_tojson, 0x1c10f15f);
   vat2_register_function("sw_interface_ip6_get_link_local_address", api_sw_interface_ip6_get_link_local_address, (cJSON * (*)(void *))vl_api_sw_interface_ip6_get_link_local_address_t_tojson, 0xf9e6675e);
   vat2_register_function("ioam_enable", api_ioam_enable, (cJSON * (*)(void *))vl_api_ioam_enable_t_tojson, 0x51ccd868);
   vat2_register_function("ioam_disable", api_ioam_disable, (cJSON * (*)(void *))vl_api_ioam_disable_t_tojson, 0x6b16a45e);
   vat2_register_function("ip_reassembly_set", api_ip_reassembly_set, (cJSON * (*)(void *))vl_api_ip_reassembly_set_t_tojson, 0x16467d25);
   vat2_register_function("ip_reassembly_get", api_ip_reassembly_get, (cJSON * (*)(void *))vl_api_ip_reassembly_get_t_tojson, 0xea13ff63);
   vat2_register_function("ip_reassembly_enable_disable", api_ip_reassembly_enable_disable, (cJSON * (*)(void *))vl_api_ip_reassembly_enable_disable_t_tojson, 0xeb77968d);
   vat2_register_function("ip_local_reass_enable_disable", api_ip_local_reass_enable_disable, (cJSON * (*)(void *))vl_api_ip_local_reass_enable_disable_t_tojson, 0x34e2ccc4);
   vat2_register_function("ip_local_reass_get", api_ip_local_reass_get, (cJSON * (*)(void *))vl_api_ip_local_reass_get_t_tojson, 0x51077d14);
   vat2_register_function("ip_path_mtu_update", api_ip_path_mtu_update, (cJSON * (*)(void *))vl_api_ip_path_mtu_update_t_tojson, 0x10bbe5cb);
   vat2_register_function("ip_path_mtu_replace_begin", api_ip_path_mtu_replace_begin, (cJSON * (*)(void *))vl_api_ip_path_mtu_replace_begin_t_tojson, 0x51077d14);
   vat2_register_function("ip_path_mtu_replace_end", api_ip_path_mtu_replace_end, (cJSON * (*)(void *))vl_api_ip_path_mtu_replace_end_t_tojson, 0x51077d14);
   return 0;
}
