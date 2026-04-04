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

#include "det44.api_enum.h"
#include "det44.api_types.h"

#define vl_endianfun		/* define message structures */
#include "det44.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "det44.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "det44.api.h"
#undef vl_printfun

#include "det44.api_tojson.h"
#include "det44.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_det44_plugin_enable_disable (cJSON *o)
{
  vl_api_det44_plugin_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_det44_plugin_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DET44_PLUGIN_ENABLE_DISABLE_CRC);
  vl_api_det44_plugin_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DET44_PLUGIN_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_det44_plugin_enable_disable_reply_t *rmp = (vl_api_det44_plugin_enable_disable_reply_t *)p;
  vl_api_det44_plugin_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_det44_plugin_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_det44_interface_add_del_feature (cJSON *o)
{
  vl_api_det44_interface_add_del_feature_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_det44_interface_add_del_feature_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DET44_INTERFACE_ADD_DEL_FEATURE_CRC);
  vl_api_det44_interface_add_del_feature_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DET44_INTERFACE_ADD_DEL_FEATURE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_det44_interface_add_del_feature_reply_t *rmp = (vl_api_det44_interface_add_del_feature_reply_t *)p;
  vl_api_det44_interface_add_del_feature_reply_t_endian(rmp, 0);
  return vl_api_det44_interface_add_del_feature_reply_t_tojson(rmp);
}

static cJSON *
api_det44_interface_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_DET44_INTERFACE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_det44_interface_dump_t *mp = vl_api_det44_interface_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_det44_interface_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_DET44_INTERFACE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_det44_interface_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_det44_interface_details_t *rmp = (vl_api_det44_interface_details_t *)p;
        vl_api_det44_interface_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_det44_interface_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_det44_add_del_map (cJSON *o)
{
  vl_api_det44_add_del_map_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_det44_add_del_map_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DET44_ADD_DEL_MAP_CRC);
  vl_api_det44_add_del_map_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DET44_ADD_DEL_MAP_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_det44_add_del_map_reply_t *rmp = (vl_api_det44_add_del_map_reply_t *)p;
  vl_api_det44_add_del_map_reply_t_endian(rmp, 0);
  return vl_api_det44_add_del_map_reply_t_tojson(rmp);
}

static cJSON *
api_det44_forward (cJSON *o)
{
  vl_api_det44_forward_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_det44_forward_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DET44_FORWARD_CRC);
  vl_api_det44_forward_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DET44_FORWARD_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_det44_forward_reply_t *rmp = (vl_api_det44_forward_reply_t *)p;
  vl_api_det44_forward_reply_t_endian(rmp, 0);
  return vl_api_det44_forward_reply_t_tojson(rmp);
}

static cJSON *
api_det44_reverse (cJSON *o)
{
  vl_api_det44_reverse_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_det44_reverse_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DET44_REVERSE_CRC);
  vl_api_det44_reverse_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DET44_REVERSE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_det44_reverse_reply_t *rmp = (vl_api_det44_reverse_reply_t *)p;
  vl_api_det44_reverse_reply_t_endian(rmp, 0);
  return vl_api_det44_reverse_reply_t_tojson(rmp);
}

static cJSON *
api_det44_map_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_DET44_MAP_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_det44_map_dump_t *mp = vl_api_det44_map_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_det44_map_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_DET44_MAP_DETAILS_CRC);

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
        if (l < sizeof(vl_api_det44_map_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_det44_map_details_t *rmp = (vl_api_det44_map_details_t *)p;
        vl_api_det44_map_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_det44_map_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_det44_close_session_out (cJSON *o)
{
  vl_api_det44_close_session_out_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_det44_close_session_out_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DET44_CLOSE_SESSION_OUT_CRC);
  vl_api_det44_close_session_out_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DET44_CLOSE_SESSION_OUT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_det44_close_session_out_reply_t *rmp = (vl_api_det44_close_session_out_reply_t *)p;
  vl_api_det44_close_session_out_reply_t_endian(rmp, 0);
  return vl_api_det44_close_session_out_reply_t_tojson(rmp);
}

static cJSON *
api_det44_close_session_in (cJSON *o)
{
  vl_api_det44_close_session_in_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_det44_close_session_in_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DET44_CLOSE_SESSION_IN_CRC);
  vl_api_det44_close_session_in_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DET44_CLOSE_SESSION_IN_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_det44_close_session_in_reply_t *rmp = (vl_api_det44_close_session_in_reply_t *)p;
  vl_api_det44_close_session_in_reply_t_endian(rmp, 0);
  return vl_api_det44_close_session_in_reply_t_tojson(rmp);
}

static cJSON *
api_det44_session_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_DET44_SESSION_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_det44_session_dump_t *mp = vl_api_det44_session_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_det44_session_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_DET44_SESSION_DETAILS_CRC);

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
        if (l < sizeof(vl_api_det44_session_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_det44_session_details_t *rmp = (vl_api_det44_session_details_t *)p;
        vl_api_det44_session_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_det44_session_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_det44_set_timeouts (cJSON *o)
{
  vl_api_det44_set_timeouts_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_det44_set_timeouts_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DET44_SET_TIMEOUTS_CRC);
  vl_api_det44_set_timeouts_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DET44_SET_TIMEOUTS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_det44_set_timeouts_reply_t *rmp = (vl_api_det44_set_timeouts_reply_t *)p;
  vl_api_det44_set_timeouts_reply_t_endian(rmp, 0);
  return vl_api_det44_set_timeouts_reply_t_tojson(rmp);
}

static cJSON *
api_det44_get_timeouts (cJSON *o)
{
  vl_api_det44_get_timeouts_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_det44_get_timeouts_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DET44_GET_TIMEOUTS_CRC);
  vl_api_det44_get_timeouts_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DET44_GET_TIMEOUTS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_det44_get_timeouts_reply_t *rmp = (vl_api_det44_get_timeouts_reply_t *)p;
  vl_api_det44_get_timeouts_reply_t_endian(rmp, 0);
  return vl_api_det44_get_timeouts_reply_t_tojson(rmp);
}

static cJSON *
api_nat_det_add_del_map (cJSON *o)
{
  vl_api_nat_det_add_del_map_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat_det_add_del_map_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT_DET_ADD_DEL_MAP_CRC);
  vl_api_nat_det_add_del_map_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT_DET_ADD_DEL_MAP_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat_det_add_del_map_reply_t *rmp = (vl_api_nat_det_add_del_map_reply_t *)p;
  vl_api_nat_det_add_del_map_reply_t_endian(rmp, 0);
  return vl_api_nat_det_add_del_map_reply_t_tojson(rmp);
}

static cJSON *
api_nat_det_forward (cJSON *o)
{
  vl_api_nat_det_forward_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat_det_forward_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT_DET_FORWARD_CRC);
  vl_api_nat_det_forward_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT_DET_FORWARD_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat_det_forward_reply_t *rmp = (vl_api_nat_det_forward_reply_t *)p;
  vl_api_nat_det_forward_reply_t_endian(rmp, 0);
  return vl_api_nat_det_forward_reply_t_tojson(rmp);
}

static cJSON *
api_nat_det_reverse (cJSON *o)
{
  vl_api_nat_det_reverse_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat_det_reverse_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT_DET_REVERSE_CRC);
  vl_api_nat_det_reverse_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT_DET_REVERSE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat_det_reverse_reply_t *rmp = (vl_api_nat_det_reverse_reply_t *)p;
  vl_api_nat_det_reverse_reply_t_endian(rmp, 0);
  return vl_api_nat_det_reverse_reply_t_tojson(rmp);
}

static cJSON *
api_nat_det_map_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT_DET_MAP_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat_det_map_dump_t *mp = vl_api_nat_det_map_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat_det_map_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT_DET_MAP_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat_det_map_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat_det_map_details_t *rmp = (vl_api_nat_det_map_details_t *)p;
        vl_api_nat_det_map_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat_det_map_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat_det_close_session_out (cJSON *o)
{
  vl_api_nat_det_close_session_out_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat_det_close_session_out_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT_DET_CLOSE_SESSION_OUT_CRC);
  vl_api_nat_det_close_session_out_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT_DET_CLOSE_SESSION_OUT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat_det_close_session_out_reply_t *rmp = (vl_api_nat_det_close_session_out_reply_t *)p;
  vl_api_nat_det_close_session_out_reply_t_endian(rmp, 0);
  return vl_api_nat_det_close_session_out_reply_t_tojson(rmp);
}

static cJSON *
api_nat_det_close_session_in (cJSON *o)
{
  vl_api_nat_det_close_session_in_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat_det_close_session_in_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT_DET_CLOSE_SESSION_IN_CRC);
  vl_api_nat_det_close_session_in_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT_DET_CLOSE_SESSION_IN_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat_det_close_session_in_reply_t *rmp = (vl_api_nat_det_close_session_in_reply_t *)p;
  vl_api_nat_det_close_session_in_reply_t_endian(rmp, 0);
  return vl_api_nat_det_close_session_in_reply_t_tojson(rmp);
}

static cJSON *
api_nat_det_session_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT_DET_SESSION_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat_det_session_dump_t *mp = vl_api_nat_det_session_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat_det_session_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT_DET_SESSION_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat_det_session_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat_det_session_details_t *rmp = (vl_api_nat_det_session_details_t *)p;
        vl_api_nat_det_session_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat_det_session_details_t_tojson(rmp));
    }
  }
  return reply;
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("det44_plugin_enable_disable", api_det44_plugin_enable_disable, (cJSON * (*)(void *))vl_api_det44_plugin_enable_disable_t_tojson, 0x617b6bf8);
   vat2_register_function("det44_interface_add_del_feature", api_det44_interface_add_del_feature, (cJSON * (*)(void *))vl_api_det44_interface_add_del_feature_t_tojson, 0xdc17a836);
   vat2_register_function("det44_interface_dump", api_det44_interface_dump, (cJSON * (*)(void *))vl_api_det44_interface_dump_t_tojson, 0x51077d14);
   vat2_register_function("det44_add_del_map", api_det44_add_del_map, (cJSON * (*)(void *))vl_api_det44_add_del_map_t_tojson, 0x1150a190);
   vat2_register_function("det44_forward", api_det44_forward, (cJSON * (*)(void *))vl_api_det44_forward_t_tojson, 0x7f8a89cd);
   vat2_register_function("det44_reverse", api_det44_reverse, (cJSON * (*)(void *))vl_api_det44_reverse_t_tojson, 0xa7573fe1);
   vat2_register_function("det44_map_dump", api_det44_map_dump, (cJSON * (*)(void *))vl_api_det44_map_dump_t_tojson, 0x51077d14);
   vat2_register_function("det44_close_session_out", api_det44_close_session_out, (cJSON * (*)(void *))vl_api_det44_close_session_out_t_tojson, 0xf6b259d1);
   vat2_register_function("det44_close_session_in", api_det44_close_session_in, (cJSON * (*)(void *))vl_api_det44_close_session_in_t_tojson, 0x3c68e073);
   vat2_register_function("det44_session_dump", api_det44_session_dump, (cJSON * (*)(void *))vl_api_det44_session_dump_t_tojson, 0xe45a3af7);
   vat2_register_function("det44_set_timeouts", api_det44_set_timeouts, (cJSON * (*)(void *))vl_api_det44_set_timeouts_t_tojson, 0xd4746b16);
   vat2_register_function("det44_get_timeouts", api_det44_get_timeouts, (cJSON * (*)(void *))vl_api_det44_get_timeouts_t_tojson, 0x51077d14);
   vat2_register_function("nat_det_add_del_map", api_nat_det_add_del_map, (cJSON * (*)(void *))vl_api_nat_det_add_del_map_t_tojson, 0x1150a190);
   vat2_register_function("nat_det_forward", api_nat_det_forward, (cJSON * (*)(void *))vl_api_nat_det_forward_t_tojson, 0x7f8a89cd);
   vat2_register_function("nat_det_reverse", api_nat_det_reverse, (cJSON * (*)(void *))vl_api_nat_det_reverse_t_tojson, 0xa7573fe1);
   vat2_register_function("nat_det_map_dump", api_nat_det_map_dump, (cJSON * (*)(void *))vl_api_nat_det_map_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat_det_close_session_out", api_nat_det_close_session_out, (cJSON * (*)(void *))vl_api_nat_det_close_session_out_t_tojson, 0xf6b259d1);
   vat2_register_function("nat_det_close_session_in", api_nat_det_close_session_in, (cJSON * (*)(void *))vl_api_nat_det_close_session_in_t_tojson, 0x3c68e073);
   vat2_register_function("nat_det_session_dump", api_nat_det_session_dump, (cJSON * (*)(void *))vl_api_nat_det_session_dump_t_tojson, 0xe45a3af7);
   return 0;
}
