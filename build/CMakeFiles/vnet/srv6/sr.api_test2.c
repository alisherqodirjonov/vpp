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

#include "sr.api_enum.h"
#include "sr.api_types.h"

#define vl_endianfun		/* define message structures */
#include "sr.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "sr.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "sr.api.h"
#undef vl_printfun

#include "sr.api_tojson.h"
#include "sr.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_sr_localsid_add_del (cJSON *o)
{
  vl_api_sr_localsid_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sr_localsid_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SR_LOCALSID_ADD_DEL_CRC);
  vl_api_sr_localsid_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SR_LOCALSID_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sr_localsid_add_del_reply_t *rmp = (vl_api_sr_localsid_add_del_reply_t *)p;
  vl_api_sr_localsid_add_del_reply_t_endian(rmp, 0);
  return vl_api_sr_localsid_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_sr_policy_add (cJSON *o)
{
  vl_api_sr_policy_add_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sr_policy_add_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SR_POLICY_ADD_CRC);
  vl_api_sr_policy_add_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SR_POLICY_ADD_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sr_policy_add_reply_t *rmp = (vl_api_sr_policy_add_reply_t *)p;
  vl_api_sr_policy_add_reply_t_endian(rmp, 0);
  return vl_api_sr_policy_add_reply_t_tojson(rmp);
}

static cJSON *
api_sr_policy_mod (cJSON *o)
{
  vl_api_sr_policy_mod_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sr_policy_mod_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SR_POLICY_MOD_CRC);
  vl_api_sr_policy_mod_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SR_POLICY_MOD_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sr_policy_mod_reply_t *rmp = (vl_api_sr_policy_mod_reply_t *)p;
  vl_api_sr_policy_mod_reply_t_endian(rmp, 0);
  return vl_api_sr_policy_mod_reply_t_tojson(rmp);
}

static cJSON *
api_sr_policy_add_v2 (cJSON *o)
{
  vl_api_sr_policy_add_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sr_policy_add_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SR_POLICY_ADD_V2_CRC);
  vl_api_sr_policy_add_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SR_POLICY_ADD_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sr_policy_add_v2_reply_t *rmp = (vl_api_sr_policy_add_v2_reply_t *)p;
  vl_api_sr_policy_add_v2_reply_t_endian(rmp, 0);
  return vl_api_sr_policy_add_v2_reply_t_tojson(rmp);
}

static cJSON *
api_sr_policy_mod_v2 (cJSON *o)
{
  vl_api_sr_policy_mod_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sr_policy_mod_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SR_POLICY_MOD_V2_CRC);
  vl_api_sr_policy_mod_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SR_POLICY_MOD_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sr_policy_mod_v2_reply_t *rmp = (vl_api_sr_policy_mod_v2_reply_t *)p;
  vl_api_sr_policy_mod_v2_reply_t_endian(rmp, 0);
  return vl_api_sr_policy_mod_v2_reply_t_tojson(rmp);
}

static cJSON *
api_sr_policy_del (cJSON *o)
{
  vl_api_sr_policy_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sr_policy_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SR_POLICY_DEL_CRC);
  vl_api_sr_policy_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SR_POLICY_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sr_policy_del_reply_t *rmp = (vl_api_sr_policy_del_reply_t *)p;
  vl_api_sr_policy_del_reply_t_endian(rmp, 0);
  return vl_api_sr_policy_del_reply_t_tojson(rmp);
}

static cJSON *
api_sr_set_encap_source (cJSON *o)
{
  vl_api_sr_set_encap_source_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sr_set_encap_source_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SR_SET_ENCAP_SOURCE_CRC);
  vl_api_sr_set_encap_source_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SR_SET_ENCAP_SOURCE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sr_set_encap_source_reply_t *rmp = (vl_api_sr_set_encap_source_reply_t *)p;
  vl_api_sr_set_encap_source_reply_t_endian(rmp, 0);
  return vl_api_sr_set_encap_source_reply_t_tojson(rmp);
}

static cJSON *
api_sr_set_encap_hop_limit (cJSON *o)
{
  vl_api_sr_set_encap_hop_limit_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sr_set_encap_hop_limit_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SR_SET_ENCAP_HOP_LIMIT_CRC);
  vl_api_sr_set_encap_hop_limit_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SR_SET_ENCAP_HOP_LIMIT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sr_set_encap_hop_limit_reply_t *rmp = (vl_api_sr_set_encap_hop_limit_reply_t *)p;
  vl_api_sr_set_encap_hop_limit_reply_t_endian(rmp, 0);
  return vl_api_sr_set_encap_hop_limit_reply_t_tojson(rmp);
}

static cJSON *
api_sr_steering_add_del (cJSON *o)
{
  vl_api_sr_steering_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sr_steering_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SR_STEERING_ADD_DEL_CRC);
  vl_api_sr_steering_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SR_STEERING_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sr_steering_add_del_reply_t *rmp = (vl_api_sr_steering_add_del_reply_t *)p;
  vl_api_sr_steering_add_del_reply_t_endian(rmp, 0);
  return vl_api_sr_steering_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_sr_localsids_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_SR_LOCALSIDS_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_sr_localsids_dump_t *mp = vl_api_sr_localsids_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_sr_localsids_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SR_LOCALSIDS_DETAILS_CRC);

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
        if (l < sizeof(vl_api_sr_localsids_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_sr_localsids_details_t *rmp = (vl_api_sr_localsids_details_t *)p;
        vl_api_sr_localsids_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_sr_localsids_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_sr_localsids_with_packet_stats_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_SR_LOCALSIDS_WITH_PACKET_STATS_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_sr_localsids_with_packet_stats_dump_t *mp = vl_api_sr_localsids_with_packet_stats_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_sr_localsids_with_packet_stats_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SR_LOCALSIDS_WITH_PACKET_STATS_DETAILS_CRC);

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
        if (l < sizeof(vl_api_sr_localsids_with_packet_stats_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_sr_localsids_with_packet_stats_details_t *rmp = (vl_api_sr_localsids_with_packet_stats_details_t *)p;
        vl_api_sr_localsids_with_packet_stats_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_sr_localsids_with_packet_stats_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_sr_policies_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_SR_POLICIES_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_sr_policies_dump_t *mp = vl_api_sr_policies_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_sr_policies_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SR_POLICIES_DETAILS_CRC);

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
        if (l < sizeof(vl_api_sr_policies_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_sr_policies_details_t *rmp = (vl_api_sr_policies_details_t *)p;
        vl_api_sr_policies_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_sr_policies_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_sr_policies_v2_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_SR_POLICIES_V2_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_sr_policies_v2_dump_t *mp = vl_api_sr_policies_v2_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_sr_policies_v2_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SR_POLICIES_V2_DETAILS_CRC);

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
        if (l < sizeof(vl_api_sr_policies_v2_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_sr_policies_v2_details_t *rmp = (vl_api_sr_policies_v2_details_t *)p;
        vl_api_sr_policies_v2_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_sr_policies_v2_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_sr_policies_with_sl_index_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_SR_POLICIES_WITH_SL_INDEX_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_sr_policies_with_sl_index_dump_t *mp = vl_api_sr_policies_with_sl_index_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_sr_policies_with_sl_index_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SR_POLICIES_WITH_SL_INDEX_DETAILS_CRC);

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
        if (l < sizeof(vl_api_sr_policies_with_sl_index_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_sr_policies_with_sl_index_details_t *rmp = (vl_api_sr_policies_with_sl_index_details_t *)p;
        vl_api_sr_policies_with_sl_index_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_sr_policies_with_sl_index_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_sr_steering_pol_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_SR_STEERING_POL_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_sr_steering_pol_dump_t *mp = vl_api_sr_steering_pol_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_sr_steering_pol_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SR_STEERING_POL_DETAILS_CRC);

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
        if (l < sizeof(vl_api_sr_steering_pol_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_sr_steering_pol_details_t *rmp = (vl_api_sr_steering_pol_details_t *)p;
        vl_api_sr_steering_pol_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_sr_steering_pol_details_t_tojson(rmp));
    }
  }
  return reply;
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("sr_localsid_add_del", api_sr_localsid_add_del, (cJSON * (*)(void *))vl_api_sr_localsid_add_del_t_tojson, 0x5a36c324);
   vat2_register_function("sr_policy_add", api_sr_policy_add, (cJSON * (*)(void *))vl_api_sr_policy_add_t_tojson, 0x44ac92e8);
   vat2_register_function("sr_policy_mod", api_sr_policy_mod, (cJSON * (*)(void *))vl_api_sr_policy_mod_t_tojson, 0xb97bb56e);
   vat2_register_function("sr_policy_add_v2", api_sr_policy_add_v2, (cJSON * (*)(void *))vl_api_sr_policy_add_v2_t_tojson, 0xf6297f36);
   vat2_register_function("sr_policy_mod_v2", api_sr_policy_mod_v2, (cJSON * (*)(void *))vl_api_sr_policy_mod_v2_t_tojson, 0xc0544823);
   vat2_register_function("sr_policy_del", api_sr_policy_del, (cJSON * (*)(void *))vl_api_sr_policy_del_t_tojson, 0xcb4d48d5);
   vat2_register_function("sr_set_encap_source", api_sr_set_encap_source, (cJSON * (*)(void *))vl_api_sr_set_encap_source_t_tojson, 0xd3bad5e1);
   vat2_register_function("sr_set_encap_hop_limit", api_sr_set_encap_hop_limit, (cJSON * (*)(void *))vl_api_sr_set_encap_hop_limit_t_tojson, 0xaa75d7d0);
   vat2_register_function("sr_steering_add_del", api_sr_steering_add_del, (cJSON * (*)(void *))vl_api_sr_steering_add_del_t_tojson, 0xe46b0a0f);
   vat2_register_function("sr_localsids_dump", api_sr_localsids_dump, (cJSON * (*)(void *))vl_api_sr_localsids_dump_t_tojson, 0x51077d14);
   vat2_register_function("sr_localsids_with_packet_stats_dump", api_sr_localsids_with_packet_stats_dump, (cJSON * (*)(void *))vl_api_sr_localsids_with_packet_stats_dump_t_tojson, 0x51077d14);
   vat2_register_function("sr_policies_dump", api_sr_policies_dump, (cJSON * (*)(void *))vl_api_sr_policies_dump_t_tojson, 0x51077d14);
   vat2_register_function("sr_policies_v2_dump", api_sr_policies_v2_dump, (cJSON * (*)(void *))vl_api_sr_policies_v2_dump_t_tojson, 0x51077d14);
   vat2_register_function("sr_policies_with_sl_index_dump", api_sr_policies_with_sl_index_dump, (cJSON * (*)(void *))vl_api_sr_policies_with_sl_index_dump_t_tojson, 0x51077d14);
   vat2_register_function("sr_steering_pol_dump", api_sr_steering_pol_dump, (cJSON * (*)(void *))vl_api_sr_steering_pol_dump_t_tojson, 0x51077d14);
   return 0;
}
