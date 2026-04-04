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

#include "session.api_enum.h"
#include "session.api_types.h"

#define vl_endianfun		/* define message structures */
#include "session.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "session.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "session.api.h"
#undef vl_printfun

#include "session.api_tojson.h"
#include "session.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_app_attach (cJSON *o)
{
  vl_api_app_attach_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_app_attach_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_APP_ATTACH_CRC);
  vl_api_app_attach_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_APP_ATTACH_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_app_attach_reply_t *rmp = (vl_api_app_attach_reply_t *)p;
  vl_api_app_attach_reply_t_endian(rmp, 0);
  return vl_api_app_attach_reply_t_tojson(rmp);
}

static cJSON *
api_application_detach (cJSON *o)
{
  vl_api_application_detach_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_application_detach_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_APPLICATION_DETACH_CRC);
  vl_api_application_detach_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_APPLICATION_DETACH_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_application_detach_reply_t *rmp = (vl_api_application_detach_reply_t *)p;
  vl_api_application_detach_reply_t_endian(rmp, 0);
  return vl_api_application_detach_reply_t_tojson(rmp);
}

static cJSON *
api_app_add_cert_key_pair (cJSON *o)
{
  vl_api_app_add_cert_key_pair_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_app_add_cert_key_pair_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_APP_ADD_CERT_KEY_PAIR_CRC);
  vl_api_app_add_cert_key_pair_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_APP_ADD_CERT_KEY_PAIR_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_app_add_cert_key_pair_reply_t *rmp = (vl_api_app_add_cert_key_pair_reply_t *)p;
  vl_api_app_add_cert_key_pair_reply_t_endian(rmp, 0);
  return vl_api_app_add_cert_key_pair_reply_t_tojson(rmp);
}

static cJSON *
api_app_del_cert_key_pair (cJSON *o)
{
  vl_api_app_del_cert_key_pair_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_app_del_cert_key_pair_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_APP_DEL_CERT_KEY_PAIR_CRC);
  vl_api_app_del_cert_key_pair_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_APP_DEL_CERT_KEY_PAIR_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_app_del_cert_key_pair_reply_t *rmp = (vl_api_app_del_cert_key_pair_reply_t *)p;
  vl_api_app_del_cert_key_pair_reply_t_endian(rmp, 0);
  return vl_api_app_del_cert_key_pair_reply_t_tojson(rmp);
}

static cJSON *
api_app_worker_add_del (cJSON *o)
{
  vl_api_app_worker_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_app_worker_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_APP_WORKER_ADD_DEL_CRC);
  vl_api_app_worker_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_APP_WORKER_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_app_worker_add_del_reply_t *rmp = (vl_api_app_worker_add_del_reply_t *)p;
  vl_api_app_worker_add_del_reply_t_endian(rmp, 0);
  return vl_api_app_worker_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_session_enable_disable (cJSON *o)
{
  vl_api_session_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_session_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SESSION_ENABLE_DISABLE_CRC);
  vl_api_session_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SESSION_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_session_enable_disable_reply_t *rmp = (vl_api_session_enable_disable_reply_t *)p;
  vl_api_session_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_session_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_session_enable_disable_v2 (cJSON *o)
{
  vl_api_session_enable_disable_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_session_enable_disable_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SESSION_ENABLE_DISABLE_V2_CRC);
  vl_api_session_enable_disable_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SESSION_ENABLE_DISABLE_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_session_enable_disable_v2_reply_t *rmp = (vl_api_session_enable_disable_v2_reply_t *)p;
  vl_api_session_enable_disable_v2_reply_t_endian(rmp, 0);
  return vl_api_session_enable_disable_v2_reply_t_tojson(rmp);
}

static cJSON *
api_session_sapi_enable_disable (cJSON *o)
{
  vl_api_session_sapi_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_session_sapi_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SESSION_SAPI_ENABLE_DISABLE_CRC);
  vl_api_session_sapi_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SESSION_SAPI_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_session_sapi_enable_disable_reply_t *rmp = (vl_api_session_sapi_enable_disable_reply_t *)p;
  vl_api_session_sapi_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_session_sapi_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_app_namespace_add_del (cJSON *o)
{
  vl_api_app_namespace_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_app_namespace_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_APP_NAMESPACE_ADD_DEL_CRC);
  vl_api_app_namespace_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_APP_NAMESPACE_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_app_namespace_add_del_reply_t *rmp = (vl_api_app_namespace_add_del_reply_t *)p;
  vl_api_app_namespace_add_del_reply_t_endian(rmp, 0);
  return vl_api_app_namespace_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_app_namespace_add_del_v4 (cJSON *o)
{
  vl_api_app_namespace_add_del_v4_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_app_namespace_add_del_v4_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_APP_NAMESPACE_ADD_DEL_V4_CRC);
  vl_api_app_namespace_add_del_v4_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_APP_NAMESPACE_ADD_DEL_V4_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_app_namespace_add_del_v4_reply_t *rmp = (vl_api_app_namespace_add_del_v4_reply_t *)p;
  vl_api_app_namespace_add_del_v4_reply_t_endian(rmp, 0);
  return vl_api_app_namespace_add_del_v4_reply_t_tojson(rmp);
}

static cJSON *
api_app_namespace_add_del_v2 (cJSON *o)
{
  vl_api_app_namespace_add_del_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_app_namespace_add_del_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_APP_NAMESPACE_ADD_DEL_V2_CRC);
  vl_api_app_namespace_add_del_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_APP_NAMESPACE_ADD_DEL_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_app_namespace_add_del_v2_reply_t *rmp = (vl_api_app_namespace_add_del_v2_reply_t *)p;
  vl_api_app_namespace_add_del_v2_reply_t_endian(rmp, 0);
  return vl_api_app_namespace_add_del_v2_reply_t_tojson(rmp);
}

static cJSON *
api_app_namespace_add_del_v3 (cJSON *o)
{
  vl_api_app_namespace_add_del_v3_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_app_namespace_add_del_v3_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_APP_NAMESPACE_ADD_DEL_V3_CRC);
  vl_api_app_namespace_add_del_v3_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_APP_NAMESPACE_ADD_DEL_V3_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_app_namespace_add_del_v3_reply_t *rmp = (vl_api_app_namespace_add_del_v3_reply_t *)p;
  vl_api_app_namespace_add_del_v3_reply_t_endian(rmp, 0);
  return vl_api_app_namespace_add_del_v3_reply_t_tojson(rmp);
}

static cJSON *
api_session_rule_add_del (cJSON *o)
{
  vl_api_session_rule_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_session_rule_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SESSION_RULE_ADD_DEL_CRC);
  vl_api_session_rule_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SESSION_RULE_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_session_rule_add_del_reply_t *rmp = (vl_api_session_rule_add_del_reply_t *)p;
  vl_api_session_rule_add_del_reply_t_endian(rmp, 0);
  return vl_api_session_rule_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_session_rules_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_SESSION_RULES_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_session_rules_dump_t *mp = vl_api_session_rules_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_session_rules_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SESSION_RULES_DETAILS_CRC);

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
        if (l < sizeof(vl_api_session_rules_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_session_rules_details_t *rmp = (vl_api_session_rules_details_t *)p;
        vl_api_session_rules_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_session_rules_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_session_rules_v2_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_SESSION_RULES_V2_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_session_rules_v2_dump_t *mp = vl_api_session_rules_v2_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_session_rules_v2_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SESSION_RULES_V2_DETAILS_CRC);

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
        if (l < sizeof(vl_api_session_rules_v2_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_session_rules_v2_details_t *rmp = (vl_api_session_rules_v2_details_t *)p;
        vl_api_session_rules_v2_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_session_rules_v2_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_session_sdl_add_del (cJSON *o)
{
  vl_api_session_sdl_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_session_sdl_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SESSION_SDL_ADD_DEL_CRC);
  vl_api_session_sdl_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SESSION_SDL_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_session_sdl_add_del_reply_t *rmp = (vl_api_session_sdl_add_del_reply_t *)p;
  vl_api_session_sdl_add_del_reply_t_endian(rmp, 0);
  return vl_api_session_sdl_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_session_sdl_add_del_v2 (cJSON *o)
{
  vl_api_session_sdl_add_del_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_session_sdl_add_del_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SESSION_SDL_ADD_DEL_V2_CRC);
  vl_api_session_sdl_add_del_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SESSION_SDL_ADD_DEL_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_session_sdl_add_del_v2_reply_t *rmp = (vl_api_session_sdl_add_del_v2_reply_t *)p;
  vl_api_session_sdl_add_del_v2_reply_t_endian(rmp, 0);
  return vl_api_session_sdl_add_del_v2_reply_t_tojson(rmp);
}

static cJSON *
api_session_sdl_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_SESSION_SDL_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_session_sdl_dump_t *mp = vl_api_session_sdl_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_session_sdl_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SESSION_SDL_DETAILS_CRC);

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
        if (l < sizeof(vl_api_session_sdl_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_session_sdl_details_t *rmp = (vl_api_session_sdl_details_t *)p;
        vl_api_session_sdl_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_session_sdl_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_session_sdl_v2_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_SESSION_SDL_V2_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_session_sdl_v2_dump_t *mp = vl_api_session_sdl_v2_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_session_sdl_v2_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SESSION_SDL_V2_DETAILS_CRC);

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
        if (l < sizeof(vl_api_session_sdl_v2_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_session_sdl_v2_details_t *rmp = (vl_api_session_sdl_v2_details_t *)p;
        vl_api_session_sdl_v2_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_session_sdl_v2_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_session_sdl_v3_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_SESSION_SDL_V3_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_session_sdl_v3_dump_t *mp = vl_api_session_sdl_v3_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_session_sdl_v3_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SESSION_SDL_V3_DETAILS_CRC);

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
        if (l < sizeof(vl_api_session_sdl_v3_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_session_sdl_v3_details_t *rmp = (vl_api_session_sdl_v3_details_t *)p;
        vl_api_session_sdl_v3_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_session_sdl_v3_details_t_tojson(rmp));
    }
  }
  return reply;
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("app_attach", api_app_attach, (cJSON * (*)(void *))vl_api_app_attach_t_tojson, 0x5f4a260d);
   vat2_register_function("application_detach", api_application_detach, (cJSON * (*)(void *))vl_api_application_detach_t_tojson, 0x51077d14);
   vat2_register_function("app_add_cert_key_pair", api_app_add_cert_key_pair, (cJSON * (*)(void *))vl_api_app_add_cert_key_pair_t_tojson, 0x02eb8016);
   vat2_register_function("app_del_cert_key_pair", api_app_del_cert_key_pair, (cJSON * (*)(void *))vl_api_app_del_cert_key_pair_t_tojson, 0x8ac76db6);
   vat2_register_function("app_worker_add_del", api_app_worker_add_del, (cJSON * (*)(void *))vl_api_app_worker_add_del_t_tojson, 0x753253dc);
   vat2_register_function("session_enable_disable", api_session_enable_disable, (cJSON * (*)(void *))vl_api_session_enable_disable_t_tojson, 0xc264d7bf);
   vat2_register_function("session_enable_disable_v2", api_session_enable_disable_v2, (cJSON * (*)(void *))vl_api_session_enable_disable_v2_t_tojson, 0xf09fbf32);
   vat2_register_function("session_sapi_enable_disable", api_session_sapi_enable_disable, (cJSON * (*)(void *))vl_api_session_sapi_enable_disable_t_tojson, 0xc264d7bf);
   vat2_register_function("app_namespace_add_del", api_app_namespace_add_del, (cJSON * (*)(void *))vl_api_app_namespace_add_del_t_tojson, 0x6306aecb);
   vat2_register_function("app_namespace_add_del_v4", api_app_namespace_add_del_v4, (cJSON * (*)(void *))vl_api_app_namespace_add_del_v4_t_tojson, 0x42c1d824);
   vat2_register_function("app_namespace_add_del_v2", api_app_namespace_add_del_v2, (cJSON * (*)(void *))vl_api_app_namespace_add_del_v2_t_tojson, 0xee0755cf);
   vat2_register_function("app_namespace_add_del_v3", api_app_namespace_add_del_v3, (cJSON * (*)(void *))vl_api_app_namespace_add_del_v3_t_tojson, 0x8a7e40a1);
   vat2_register_function("session_rule_add_del", api_session_rule_add_del, (cJSON * (*)(void *))vl_api_session_rule_add_del_t_tojson, 0x82a90af5);
   vat2_register_function("session_rules_dump", api_session_rules_dump, (cJSON * (*)(void *))vl_api_session_rules_dump_t_tojson, 0x51077d14);
   vat2_register_function("session_rules_v2_dump", api_session_rules_v2_dump, (cJSON * (*)(void *))vl_api_session_rules_v2_dump_t_tojson, 0x51077d14);
   vat2_register_function("session_sdl_add_del", api_session_sdl_add_del, (cJSON * (*)(void *))vl_api_session_sdl_add_del_t_tojson, 0xfaeb89fc);
   vat2_register_function("session_sdl_add_del_v2", api_session_sdl_add_del_v2, (cJSON * (*)(void *))vl_api_session_sdl_add_del_v2_t_tojson, 0x7f89d3fa);
   vat2_register_function("session_sdl_dump", api_session_sdl_dump, (cJSON * (*)(void *))vl_api_session_sdl_dump_t_tojson, 0x51077d14);
   vat2_register_function("session_sdl_v2_dump", api_session_sdl_v2_dump, (cJSON * (*)(void *))vl_api_session_sdl_v2_dump_t_tojson, 0x51077d14);
   vat2_register_function("session_sdl_v3_dump", api_session_sdl_v3_dump, (cJSON * (*)(void *))vl_api_session_sdl_v3_dump_t_tojson, 0x51077d14);
   return 0;
}
