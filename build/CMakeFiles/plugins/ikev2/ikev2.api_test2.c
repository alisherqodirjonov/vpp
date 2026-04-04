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

#include "ikev2.api_enum.h"
#include "ikev2.api_types.h"

#define vl_endianfun		/* define message structures */
#include "ikev2.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ikev2.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "ikev2.api.h"
#undef vl_printfun

#include "ikev2.api_tojson.h"
#include "ikev2.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_ikev2_plugin_get_version (cJSON *o)
{
  vl_api_ikev2_plugin_get_version_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_plugin_get_version_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_PLUGIN_GET_VERSION_CRC);
  vl_api_ikev2_plugin_get_version_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_PLUGIN_GET_VERSION_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_plugin_get_version_reply_t *rmp = (vl_api_ikev2_plugin_get_version_reply_t *)p;
  vl_api_ikev2_plugin_get_version_reply_t_endian(rmp, 0);
  return vl_api_ikev2_plugin_get_version_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_plugin_set_sleep_interval (cJSON *o)
{
  vl_api_ikev2_plugin_set_sleep_interval_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_plugin_set_sleep_interval_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_PLUGIN_SET_SLEEP_INTERVAL_CRC);
  vl_api_ikev2_plugin_set_sleep_interval_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_PLUGIN_SET_SLEEP_INTERVAL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_plugin_set_sleep_interval_reply_t *rmp = (vl_api_ikev2_plugin_set_sleep_interval_reply_t *)p;
  vl_api_ikev2_plugin_set_sleep_interval_reply_t_endian(rmp, 0);
  return vl_api_ikev2_plugin_set_sleep_interval_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_get_sleep_interval (cJSON *o)
{
  vl_api_ikev2_get_sleep_interval_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_get_sleep_interval_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_GET_SLEEP_INTERVAL_CRC);
  vl_api_ikev2_get_sleep_interval_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_GET_SLEEP_INTERVAL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_get_sleep_interval_reply_t *rmp = (vl_api_ikev2_get_sleep_interval_reply_t *)p;
  vl_api_ikev2_get_sleep_interval_reply_t_endian(rmp, 0);
  return vl_api_ikev2_get_sleep_interval_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_profile_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IKEV2_PROFILE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ikev2_profile_dump_t *mp = vl_api_ikev2_profile_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ikev2_profile_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IKEV2_PROFILE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ikev2_profile_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ikev2_profile_details_t *rmp = (vl_api_ikev2_profile_details_t *)p;
        vl_api_ikev2_profile_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ikev2_profile_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ikev2_sa_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IKEV2_SA_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ikev2_sa_dump_t *mp = vl_api_ikev2_sa_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ikev2_sa_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IKEV2_SA_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ikev2_sa_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ikev2_sa_details_t *rmp = (vl_api_ikev2_sa_details_t *)p;
        vl_api_ikev2_sa_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ikev2_sa_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ikev2_sa_v2_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IKEV2_SA_V2_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ikev2_sa_v2_dump_t *mp = vl_api_ikev2_sa_v2_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ikev2_sa_v2_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IKEV2_SA_V2_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ikev2_sa_v2_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ikev2_sa_v2_details_t *rmp = (vl_api_ikev2_sa_v2_details_t *)p;
        vl_api_ikev2_sa_v2_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ikev2_sa_v2_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ikev2_sa_v3_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IKEV2_SA_V3_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ikev2_sa_v3_dump_t *mp = vl_api_ikev2_sa_v3_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ikev2_sa_v3_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IKEV2_SA_V3_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ikev2_sa_v3_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ikev2_sa_v3_details_t *rmp = (vl_api_ikev2_sa_v3_details_t *)p;
        vl_api_ikev2_sa_v3_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ikev2_sa_v3_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ikev2_child_sa_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IKEV2_CHILD_SA_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ikev2_child_sa_dump_t *mp = vl_api_ikev2_child_sa_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ikev2_child_sa_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IKEV2_CHILD_SA_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ikev2_child_sa_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ikev2_child_sa_details_t *rmp = (vl_api_ikev2_child_sa_details_t *)p;
        vl_api_ikev2_child_sa_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ikev2_child_sa_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ikev2_child_sa_v2_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IKEV2_CHILD_SA_V2_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ikev2_child_sa_v2_dump_t *mp = vl_api_ikev2_child_sa_v2_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ikev2_child_sa_v2_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IKEV2_CHILD_SA_V2_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ikev2_child_sa_v2_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ikev2_child_sa_v2_details_t *rmp = (vl_api_ikev2_child_sa_v2_details_t *)p;
        vl_api_ikev2_child_sa_v2_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ikev2_child_sa_v2_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ikev2_nonce_get (cJSON *o)
{
  vl_api_ikev2_nonce_get_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_nonce_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_NONCE_GET_CRC);
  vl_api_ikev2_nonce_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_NONCE_GET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_nonce_get_reply_t *rmp = (vl_api_ikev2_nonce_get_reply_t *)p;
  vl_api_ikev2_nonce_get_reply_t_endian(rmp, 0);
  return vl_api_ikev2_nonce_get_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_traffic_selector_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IKEV2_TRAFFIC_SELECTOR_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ikev2_traffic_selector_dump_t *mp = vl_api_ikev2_traffic_selector_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ikev2_traffic_selector_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IKEV2_TRAFFIC_SELECTOR_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ikev2_traffic_selector_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ikev2_traffic_selector_details_t *rmp = (vl_api_ikev2_traffic_selector_details_t *)p;
        vl_api_ikev2_traffic_selector_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ikev2_traffic_selector_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ikev2_profile_add_del (cJSON *o)
{
  vl_api_ikev2_profile_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_profile_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_PROFILE_ADD_DEL_CRC);
  vl_api_ikev2_profile_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_PROFILE_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_profile_add_del_reply_t *rmp = (vl_api_ikev2_profile_add_del_reply_t *)p;
  vl_api_ikev2_profile_add_del_reply_t_endian(rmp, 0);
  return vl_api_ikev2_profile_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_profile_set_auth (cJSON *o)
{
  vl_api_ikev2_profile_set_auth_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_profile_set_auth_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_PROFILE_SET_AUTH_CRC);
  vl_api_ikev2_profile_set_auth_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_PROFILE_SET_AUTH_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_profile_set_auth_reply_t *rmp = (vl_api_ikev2_profile_set_auth_reply_t *)p;
  vl_api_ikev2_profile_set_auth_reply_t_endian(rmp, 0);
  return vl_api_ikev2_profile_set_auth_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_profile_set_id (cJSON *o)
{
  vl_api_ikev2_profile_set_id_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_profile_set_id_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_PROFILE_SET_ID_CRC);
  vl_api_ikev2_profile_set_id_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_PROFILE_SET_ID_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_profile_set_id_reply_t *rmp = (vl_api_ikev2_profile_set_id_reply_t *)p;
  vl_api_ikev2_profile_set_id_reply_t_endian(rmp, 0);
  return vl_api_ikev2_profile_set_id_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_profile_disable_natt (cJSON *o)
{
  vl_api_ikev2_profile_disable_natt_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_profile_disable_natt_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_PROFILE_DISABLE_NATT_CRC);
  vl_api_ikev2_profile_disable_natt_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_PROFILE_DISABLE_NATT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_profile_disable_natt_reply_t *rmp = (vl_api_ikev2_profile_disable_natt_reply_t *)p;
  vl_api_ikev2_profile_disable_natt_reply_t_endian(rmp, 0);
  return vl_api_ikev2_profile_disable_natt_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_profile_set_ts (cJSON *o)
{
  vl_api_ikev2_profile_set_ts_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_profile_set_ts_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_PROFILE_SET_TS_CRC);
  vl_api_ikev2_profile_set_ts_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_PROFILE_SET_TS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_profile_set_ts_reply_t *rmp = (vl_api_ikev2_profile_set_ts_reply_t *)p;
  vl_api_ikev2_profile_set_ts_reply_t_endian(rmp, 0);
  return vl_api_ikev2_profile_set_ts_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_set_local_key (cJSON *o)
{
  vl_api_ikev2_set_local_key_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_set_local_key_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_SET_LOCAL_KEY_CRC);
  vl_api_ikev2_set_local_key_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_SET_LOCAL_KEY_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_set_local_key_reply_t *rmp = (vl_api_ikev2_set_local_key_reply_t *)p;
  vl_api_ikev2_set_local_key_reply_t_endian(rmp, 0);
  return vl_api_ikev2_set_local_key_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_set_tunnel_interface (cJSON *o)
{
  vl_api_ikev2_set_tunnel_interface_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_set_tunnel_interface_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_SET_TUNNEL_INTERFACE_CRC);
  vl_api_ikev2_set_tunnel_interface_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_SET_TUNNEL_INTERFACE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_set_tunnel_interface_reply_t *rmp = (vl_api_ikev2_set_tunnel_interface_reply_t *)p;
  vl_api_ikev2_set_tunnel_interface_reply_t_endian(rmp, 0);
  return vl_api_ikev2_set_tunnel_interface_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_set_responder (cJSON *o)
{
  vl_api_ikev2_set_responder_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_set_responder_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_SET_RESPONDER_CRC);
  vl_api_ikev2_set_responder_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_SET_RESPONDER_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_set_responder_reply_t *rmp = (vl_api_ikev2_set_responder_reply_t *)p;
  vl_api_ikev2_set_responder_reply_t_endian(rmp, 0);
  return vl_api_ikev2_set_responder_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_set_responder_hostname (cJSON *o)
{
  vl_api_ikev2_set_responder_hostname_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_set_responder_hostname_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_SET_RESPONDER_HOSTNAME_CRC);
  vl_api_ikev2_set_responder_hostname_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_SET_RESPONDER_HOSTNAME_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_set_responder_hostname_reply_t *rmp = (vl_api_ikev2_set_responder_hostname_reply_t *)p;
  vl_api_ikev2_set_responder_hostname_reply_t_endian(rmp, 0);
  return vl_api_ikev2_set_responder_hostname_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_set_ike_transforms (cJSON *o)
{
  vl_api_ikev2_set_ike_transforms_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_set_ike_transforms_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_SET_IKE_TRANSFORMS_CRC);
  vl_api_ikev2_set_ike_transforms_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_SET_IKE_TRANSFORMS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_set_ike_transforms_reply_t *rmp = (vl_api_ikev2_set_ike_transforms_reply_t *)p;
  vl_api_ikev2_set_ike_transforms_reply_t_endian(rmp, 0);
  return vl_api_ikev2_set_ike_transforms_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_set_esp_transforms (cJSON *o)
{
  vl_api_ikev2_set_esp_transforms_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_set_esp_transforms_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_SET_ESP_TRANSFORMS_CRC);
  vl_api_ikev2_set_esp_transforms_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_SET_ESP_TRANSFORMS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_set_esp_transforms_reply_t *rmp = (vl_api_ikev2_set_esp_transforms_reply_t *)p;
  vl_api_ikev2_set_esp_transforms_reply_t_endian(rmp, 0);
  return vl_api_ikev2_set_esp_transforms_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_set_sa_lifetime (cJSON *o)
{
  vl_api_ikev2_set_sa_lifetime_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_set_sa_lifetime_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_SET_SA_LIFETIME_CRC);
  vl_api_ikev2_set_sa_lifetime_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_SET_SA_LIFETIME_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_set_sa_lifetime_reply_t *rmp = (vl_api_ikev2_set_sa_lifetime_reply_t *)p;
  vl_api_ikev2_set_sa_lifetime_reply_t_endian(rmp, 0);
  return vl_api_ikev2_set_sa_lifetime_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_initiate_sa_init (cJSON *o)
{
  vl_api_ikev2_initiate_sa_init_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_initiate_sa_init_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_INITIATE_SA_INIT_CRC);
  vl_api_ikev2_initiate_sa_init_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_INITIATE_SA_INIT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_initiate_sa_init_reply_t *rmp = (vl_api_ikev2_initiate_sa_init_reply_t *)p;
  vl_api_ikev2_initiate_sa_init_reply_t_endian(rmp, 0);
  return vl_api_ikev2_initiate_sa_init_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_initiate_del_ike_sa (cJSON *o)
{
  vl_api_ikev2_initiate_del_ike_sa_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_initiate_del_ike_sa_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_INITIATE_DEL_IKE_SA_CRC);
  vl_api_ikev2_initiate_del_ike_sa_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_INITIATE_DEL_IKE_SA_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_initiate_del_ike_sa_reply_t *rmp = (vl_api_ikev2_initiate_del_ike_sa_reply_t *)p;
  vl_api_ikev2_initiate_del_ike_sa_reply_t_endian(rmp, 0);
  return vl_api_ikev2_initiate_del_ike_sa_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_initiate_del_child_sa (cJSON *o)
{
  vl_api_ikev2_initiate_del_child_sa_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_initiate_del_child_sa_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_INITIATE_DEL_CHILD_SA_CRC);
  vl_api_ikev2_initiate_del_child_sa_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_INITIATE_DEL_CHILD_SA_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_initiate_del_child_sa_reply_t *rmp = (vl_api_ikev2_initiate_del_child_sa_reply_t *)p;
  vl_api_ikev2_initiate_del_child_sa_reply_t_endian(rmp, 0);
  return vl_api_ikev2_initiate_del_child_sa_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_initiate_rekey_child_sa (cJSON *o)
{
  vl_api_ikev2_initiate_rekey_child_sa_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_initiate_rekey_child_sa_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_INITIATE_REKEY_CHILD_SA_CRC);
  vl_api_ikev2_initiate_rekey_child_sa_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_INITIATE_REKEY_CHILD_SA_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_initiate_rekey_child_sa_reply_t *rmp = (vl_api_ikev2_initiate_rekey_child_sa_reply_t *)p;
  vl_api_ikev2_initiate_rekey_child_sa_reply_t_endian(rmp, 0);
  return vl_api_ikev2_initiate_rekey_child_sa_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_profile_set_udp_encap (cJSON *o)
{
  vl_api_ikev2_profile_set_udp_encap_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_profile_set_udp_encap_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_PROFILE_SET_UDP_ENCAP_CRC);
  vl_api_ikev2_profile_set_udp_encap_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_PROFILE_SET_UDP_ENCAP_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_profile_set_udp_encap_reply_t *rmp = (vl_api_ikev2_profile_set_udp_encap_reply_t *)p;
  vl_api_ikev2_profile_set_udp_encap_reply_t_endian(rmp, 0);
  return vl_api_ikev2_profile_set_udp_encap_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_profile_set_ipsec_udp_port (cJSON *o)
{
  vl_api_ikev2_profile_set_ipsec_udp_port_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_profile_set_ipsec_udp_port_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_PROFILE_SET_IPSEC_UDP_PORT_CRC);
  vl_api_ikev2_profile_set_ipsec_udp_port_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_PROFILE_SET_IPSEC_UDP_PORT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_profile_set_ipsec_udp_port_reply_t *rmp = (vl_api_ikev2_profile_set_ipsec_udp_port_reply_t *)p;
  vl_api_ikev2_profile_set_ipsec_udp_port_reply_t_endian(rmp, 0);
  return vl_api_ikev2_profile_set_ipsec_udp_port_reply_t_tojson(rmp);
}

static cJSON *
api_ikev2_profile_set_liveness (cJSON *o)
{
  vl_api_ikev2_profile_set_liveness_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ikev2_profile_set_liveness_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IKEV2_PROFILE_SET_LIVENESS_CRC);
  vl_api_ikev2_profile_set_liveness_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IKEV2_PROFILE_SET_LIVENESS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ikev2_profile_set_liveness_reply_t *rmp = (vl_api_ikev2_profile_set_liveness_reply_t *)p;
  vl_api_ikev2_profile_set_liveness_reply_t_endian(rmp, 0);
  return vl_api_ikev2_profile_set_liveness_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("ikev2_plugin_get_version", api_ikev2_plugin_get_version, (cJSON * (*)(void *))vl_api_ikev2_plugin_get_version_t_tojson, 0x51077d14);
   vat2_register_function("ikev2_plugin_set_sleep_interval", api_ikev2_plugin_set_sleep_interval, (cJSON * (*)(void *))vl_api_ikev2_plugin_set_sleep_interval_t_tojson, 0xb7c096ae);
   vat2_register_function("ikev2_get_sleep_interval", api_ikev2_get_sleep_interval, (cJSON * (*)(void *))vl_api_ikev2_get_sleep_interval_t_tojson, 0x51077d14);
   vat2_register_function("ikev2_profile_dump", api_ikev2_profile_dump, (cJSON * (*)(void *))vl_api_ikev2_profile_dump_t_tojson, 0x51077d14);
   vat2_register_function("ikev2_sa_dump", api_ikev2_sa_dump, (cJSON * (*)(void *))vl_api_ikev2_sa_dump_t_tojson, 0x51077d14);
   vat2_register_function("ikev2_sa_v2_dump", api_ikev2_sa_v2_dump, (cJSON * (*)(void *))vl_api_ikev2_sa_v2_dump_t_tojson, 0x51077d14);
   vat2_register_function("ikev2_sa_v3_dump", api_ikev2_sa_v3_dump, (cJSON * (*)(void *))vl_api_ikev2_sa_v3_dump_t_tojson, 0x51077d14);
   vat2_register_function("ikev2_child_sa_dump", api_ikev2_child_sa_dump, (cJSON * (*)(void *))vl_api_ikev2_child_sa_dump_t_tojson, 0x01eab609);
   vat2_register_function("ikev2_child_sa_v2_dump", api_ikev2_child_sa_v2_dump, (cJSON * (*)(void *))vl_api_ikev2_child_sa_v2_dump_t_tojson, 0x01eab609);
   vat2_register_function("ikev2_nonce_get", api_ikev2_nonce_get, (cJSON * (*)(void *))vl_api_ikev2_nonce_get_t_tojson, 0x7fe9ad51);
   vat2_register_function("ikev2_traffic_selector_dump", api_ikev2_traffic_selector_dump, (cJSON * (*)(void *))vl_api_ikev2_traffic_selector_dump_t_tojson, 0xa7385e33);
   vat2_register_function("ikev2_profile_add_del", api_ikev2_profile_add_del, (cJSON * (*)(void *))vl_api_ikev2_profile_add_del_t_tojson, 0x2c925b55);
   vat2_register_function("ikev2_profile_set_auth", api_ikev2_profile_set_auth, (cJSON * (*)(void *))vl_api_ikev2_profile_set_auth_t_tojson, 0x642c97cd);
   vat2_register_function("ikev2_profile_set_id", api_ikev2_profile_set_id, (cJSON * (*)(void *))vl_api_ikev2_profile_set_id_t_tojson, 0x4d7e2418);
   vat2_register_function("ikev2_profile_disable_natt", api_ikev2_profile_disable_natt, (cJSON * (*)(void *))vl_api_ikev2_profile_disable_natt_t_tojson, 0xebf79a66);
   vat2_register_function("ikev2_profile_set_ts", api_ikev2_profile_set_ts, (cJSON * (*)(void *))vl_api_ikev2_profile_set_ts_t_tojson, 0x8eb8cfd1);
   vat2_register_function("ikev2_set_local_key", api_ikev2_set_local_key, (cJSON * (*)(void *))vl_api_ikev2_set_local_key_t_tojson, 0x799b69ec);
   vat2_register_function("ikev2_set_tunnel_interface", api_ikev2_set_tunnel_interface, (cJSON * (*)(void *))vl_api_ikev2_set_tunnel_interface_t_tojson, 0xca67182c);
   vat2_register_function("ikev2_set_responder", api_ikev2_set_responder, (cJSON * (*)(void *))vl_api_ikev2_set_responder_t_tojson, 0xa2055df1);
   vat2_register_function("ikev2_set_responder_hostname", api_ikev2_set_responder_hostname, (cJSON * (*)(void *))vl_api_ikev2_set_responder_hostname_t_tojson, 0x350d6949);
   vat2_register_function("ikev2_set_ike_transforms", api_ikev2_set_ike_transforms, (cJSON * (*)(void *))vl_api_ikev2_set_ike_transforms_t_tojson, 0x076d7378);
   vat2_register_function("ikev2_set_esp_transforms", api_ikev2_set_esp_transforms, (cJSON * (*)(void *))vl_api_ikev2_set_esp_transforms_t_tojson, 0xa63dc205);
   vat2_register_function("ikev2_set_sa_lifetime", api_ikev2_set_sa_lifetime, (cJSON * (*)(void *))vl_api_ikev2_set_sa_lifetime_t_tojson, 0x7039feaa);
   vat2_register_function("ikev2_initiate_sa_init", api_ikev2_initiate_sa_init, (cJSON * (*)(void *))vl_api_ikev2_initiate_sa_init_t_tojson, 0xebf79a66);
   vat2_register_function("ikev2_initiate_del_ike_sa", api_ikev2_initiate_del_ike_sa, (cJSON * (*)(void *))vl_api_ikev2_initiate_del_ike_sa_t_tojson, 0x8d125bdd);
   vat2_register_function("ikev2_initiate_del_child_sa", api_ikev2_initiate_del_child_sa, (cJSON * (*)(void *))vl_api_ikev2_initiate_del_child_sa_t_tojson, 0x7f004d2e);
   vat2_register_function("ikev2_initiate_rekey_child_sa", api_ikev2_initiate_rekey_child_sa, (cJSON * (*)(void *))vl_api_ikev2_initiate_rekey_child_sa_t_tojson, 0x7f004d2e);
   vat2_register_function("ikev2_profile_set_udp_encap", api_ikev2_profile_set_udp_encap, (cJSON * (*)(void *))vl_api_ikev2_profile_set_udp_encap_t_tojson, 0xebf79a66);
   vat2_register_function("ikev2_profile_set_ipsec_udp_port", api_ikev2_profile_set_ipsec_udp_port, (cJSON * (*)(void *))vl_api_ikev2_profile_set_ipsec_udp_port_t_tojson, 0x615ce758);
   vat2_register_function("ikev2_profile_set_liveness", api_ikev2_profile_set_liveness, (cJSON * (*)(void *))vl_api_ikev2_profile_set_liveness_t_tojson, 0x6bdf4d65);
   return 0;
}
