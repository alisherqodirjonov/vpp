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

#include "bfd.api_enum.h"
#include "bfd.api_types.h"

#define vl_endianfun		/* define message structures */
#include "bfd.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "bfd.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "bfd.api.h"
#undef vl_printfun

#include "bfd.api_tojson.h"
#include "bfd.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_want_bfd_events (cJSON *o)
{
  vl_api_want_bfd_events_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_want_bfd_events_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_WANT_BFD_EVENTS_CRC);
  vl_api_want_bfd_events_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_WANT_BFD_EVENTS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_want_bfd_events_reply_t *rmp = (vl_api_want_bfd_events_reply_t *)p;
  vl_api_want_bfd_events_reply_t_endian(rmp, 0);
  return vl_api_want_bfd_events_reply_t_tojson(rmp);
}

static cJSON *
api_bfd_udp_set_echo_source (cJSON *o)
{
  vl_api_bfd_udp_set_echo_source_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bfd_udp_set_echo_source_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BFD_UDP_SET_ECHO_SOURCE_CRC);
  vl_api_bfd_udp_set_echo_source_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BFD_UDP_SET_ECHO_SOURCE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bfd_udp_set_echo_source_reply_t *rmp = (vl_api_bfd_udp_set_echo_source_reply_t *)p;
  vl_api_bfd_udp_set_echo_source_reply_t_endian(rmp, 0);
  return vl_api_bfd_udp_set_echo_source_reply_t_tojson(rmp);
}

static cJSON *
api_bfd_udp_del_echo_source (cJSON *o)
{
  vl_api_bfd_udp_del_echo_source_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bfd_udp_del_echo_source_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BFD_UDP_DEL_ECHO_SOURCE_CRC);
  vl_api_bfd_udp_del_echo_source_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BFD_UDP_DEL_ECHO_SOURCE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bfd_udp_del_echo_source_reply_t *rmp = (vl_api_bfd_udp_del_echo_source_reply_t *)p;
  vl_api_bfd_udp_del_echo_source_reply_t_endian(rmp, 0);
  return vl_api_bfd_udp_del_echo_source_reply_t_tojson(rmp);
}

static cJSON *
api_bfd_udp_get_echo_source (cJSON *o)
{
  vl_api_bfd_udp_get_echo_source_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bfd_udp_get_echo_source_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BFD_UDP_GET_ECHO_SOURCE_CRC);
  vl_api_bfd_udp_get_echo_source_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BFD_UDP_GET_ECHO_SOURCE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bfd_udp_get_echo_source_reply_t *rmp = (vl_api_bfd_udp_get_echo_source_reply_t *)p;
  vl_api_bfd_udp_get_echo_source_reply_t_endian(rmp, 0);
  return vl_api_bfd_udp_get_echo_source_reply_t_tojson(rmp);
}

static cJSON *
api_bfd_udp_add (cJSON *o)
{
  vl_api_bfd_udp_add_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bfd_udp_add_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BFD_UDP_ADD_CRC);
  vl_api_bfd_udp_add_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BFD_UDP_ADD_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bfd_udp_add_reply_t *rmp = (vl_api_bfd_udp_add_reply_t *)p;
  vl_api_bfd_udp_add_reply_t_endian(rmp, 0);
  return vl_api_bfd_udp_add_reply_t_tojson(rmp);
}

static cJSON *
api_bfd_udp_upd (cJSON *o)
{
  vl_api_bfd_udp_upd_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bfd_udp_upd_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BFD_UDP_UPD_CRC);
  vl_api_bfd_udp_upd_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BFD_UDP_UPD_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bfd_udp_upd_reply_t *rmp = (vl_api_bfd_udp_upd_reply_t *)p;
  vl_api_bfd_udp_upd_reply_t_endian(rmp, 0);
  return vl_api_bfd_udp_upd_reply_t_tojson(rmp);
}

static cJSON *
api_bfd_udp_mod (cJSON *o)
{
  vl_api_bfd_udp_mod_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bfd_udp_mod_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BFD_UDP_MOD_CRC);
  vl_api_bfd_udp_mod_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BFD_UDP_MOD_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bfd_udp_mod_reply_t *rmp = (vl_api_bfd_udp_mod_reply_t *)p;
  vl_api_bfd_udp_mod_reply_t_endian(rmp, 0);
  return vl_api_bfd_udp_mod_reply_t_tojson(rmp);
}

static cJSON *
api_bfd_udp_del (cJSON *o)
{
  vl_api_bfd_udp_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bfd_udp_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BFD_UDP_DEL_CRC);
  vl_api_bfd_udp_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BFD_UDP_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bfd_udp_del_reply_t *rmp = (vl_api_bfd_udp_del_reply_t *)p;
  vl_api_bfd_udp_del_reply_t_endian(rmp, 0);
  return vl_api_bfd_udp_del_reply_t_tojson(rmp);
}

static cJSON *
api_bfd_udp_session_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_BFD_UDP_SESSION_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_bfd_udp_session_dump_t *mp = vl_api_bfd_udp_session_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_bfd_udp_session_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_BFD_UDP_SESSION_DETAILS_CRC);

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
        if (l < sizeof(vl_api_bfd_udp_session_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_bfd_udp_session_details_t *rmp = (vl_api_bfd_udp_session_details_t *)p;
        vl_api_bfd_udp_session_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_bfd_udp_session_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_bfd_udp_session_set_flags (cJSON *o)
{
  vl_api_bfd_udp_session_set_flags_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bfd_udp_session_set_flags_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BFD_UDP_SESSION_SET_FLAGS_CRC);
  vl_api_bfd_udp_session_set_flags_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BFD_UDP_SESSION_SET_FLAGS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bfd_udp_session_set_flags_reply_t *rmp = (vl_api_bfd_udp_session_set_flags_reply_t *)p;
  vl_api_bfd_udp_session_set_flags_reply_t_endian(rmp, 0);
  return vl_api_bfd_udp_session_set_flags_reply_t_tojson(rmp);
}

static cJSON *
api_bfd_auth_set_key (cJSON *o)
{
  vl_api_bfd_auth_set_key_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bfd_auth_set_key_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BFD_AUTH_SET_KEY_CRC);
  vl_api_bfd_auth_set_key_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BFD_AUTH_SET_KEY_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bfd_auth_set_key_reply_t *rmp = (vl_api_bfd_auth_set_key_reply_t *)p;
  vl_api_bfd_auth_set_key_reply_t_endian(rmp, 0);
  return vl_api_bfd_auth_set_key_reply_t_tojson(rmp);
}

static cJSON *
api_bfd_auth_del_key (cJSON *o)
{
  vl_api_bfd_auth_del_key_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bfd_auth_del_key_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BFD_AUTH_DEL_KEY_CRC);
  vl_api_bfd_auth_del_key_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BFD_AUTH_DEL_KEY_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bfd_auth_del_key_reply_t *rmp = (vl_api_bfd_auth_del_key_reply_t *)p;
  vl_api_bfd_auth_del_key_reply_t_endian(rmp, 0);
  return vl_api_bfd_auth_del_key_reply_t_tojson(rmp);
}

static cJSON *
api_bfd_auth_keys_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_BFD_AUTH_KEYS_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_bfd_auth_keys_dump_t *mp = vl_api_bfd_auth_keys_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_bfd_auth_keys_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_BFD_AUTH_KEYS_DETAILS_CRC);

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
        if (l < sizeof(vl_api_bfd_auth_keys_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_bfd_auth_keys_details_t *rmp = (vl_api_bfd_auth_keys_details_t *)p;
        vl_api_bfd_auth_keys_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_bfd_auth_keys_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_bfd_udp_auth_activate (cJSON *o)
{
  vl_api_bfd_udp_auth_activate_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bfd_udp_auth_activate_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BFD_UDP_AUTH_ACTIVATE_CRC);
  vl_api_bfd_udp_auth_activate_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BFD_UDP_AUTH_ACTIVATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bfd_udp_auth_activate_reply_t *rmp = (vl_api_bfd_udp_auth_activate_reply_t *)p;
  vl_api_bfd_udp_auth_activate_reply_t_endian(rmp, 0);
  return vl_api_bfd_udp_auth_activate_reply_t_tojson(rmp);
}

static cJSON *
api_bfd_udp_auth_deactivate (cJSON *o)
{
  vl_api_bfd_udp_auth_deactivate_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bfd_udp_auth_deactivate_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BFD_UDP_AUTH_DEACTIVATE_CRC);
  vl_api_bfd_udp_auth_deactivate_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BFD_UDP_AUTH_DEACTIVATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bfd_udp_auth_deactivate_reply_t *rmp = (vl_api_bfd_udp_auth_deactivate_reply_t *)p;
  vl_api_bfd_udp_auth_deactivate_reply_t_endian(rmp, 0);
  return vl_api_bfd_udp_auth_deactivate_reply_t_tojson(rmp);
}

static cJSON *
api_bfd_udp_enable_multihop (cJSON *o)
{
  vl_api_bfd_udp_enable_multihop_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bfd_udp_enable_multihop_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BFD_UDP_ENABLE_MULTIHOP_CRC);
  vl_api_bfd_udp_enable_multihop_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BFD_UDP_ENABLE_MULTIHOP_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bfd_udp_enable_multihop_reply_t *rmp = (vl_api_bfd_udp_enable_multihop_reply_t *)p;
  vl_api_bfd_udp_enable_multihop_reply_t_endian(rmp, 0);
  return vl_api_bfd_udp_enable_multihop_reply_t_tojson(rmp);
}

static cJSON *
api_bfd_udp_set_tos (cJSON *o)
{
  vl_api_bfd_udp_set_tos_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bfd_udp_set_tos_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BFD_UDP_SET_TOS_CRC);
  vl_api_bfd_udp_set_tos_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BFD_UDP_SET_TOS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bfd_udp_set_tos_reply_t *rmp = (vl_api_bfd_udp_set_tos_reply_t *)p;
  vl_api_bfd_udp_set_tos_reply_t_endian(rmp, 0);
  return vl_api_bfd_udp_set_tos_reply_t_tojson(rmp);
}

static cJSON *
api_bfd_udp_get_tos (cJSON *o)
{
  vl_api_bfd_udp_get_tos_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bfd_udp_get_tos_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BFD_UDP_GET_TOS_CRC);
  vl_api_bfd_udp_get_tos_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BFD_UDP_GET_TOS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bfd_udp_get_tos_reply_t *rmp = (vl_api_bfd_udp_get_tos_reply_t *)p;
  vl_api_bfd_udp_get_tos_reply_t_endian(rmp, 0);
  return vl_api_bfd_udp_get_tos_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("want_bfd_events", api_want_bfd_events, (cJSON * (*)(void *))vl_api_want_bfd_events_t_tojson, 0xc5e2af94);
   vat2_register_function("bfd_udp_set_echo_source", api_bfd_udp_set_echo_source, (cJSON * (*)(void *))vl_api_bfd_udp_set_echo_source_t_tojson, 0xf9e6675e);
   vat2_register_function("bfd_udp_del_echo_source", api_bfd_udp_del_echo_source, (cJSON * (*)(void *))vl_api_bfd_udp_del_echo_source_t_tojson, 0x51077d14);
   vat2_register_function("bfd_udp_get_echo_source", api_bfd_udp_get_echo_source, (cJSON * (*)(void *))vl_api_bfd_udp_get_echo_source_t_tojson, 0x51077d14);
   vat2_register_function("bfd_udp_add", api_bfd_udp_add, (cJSON * (*)(void *))vl_api_bfd_udp_add_t_tojson, 0x939cd26a);
   vat2_register_function("bfd_udp_upd", api_bfd_udp_upd, (cJSON * (*)(void *))vl_api_bfd_udp_upd_t_tojson, 0x939cd26a);
   vat2_register_function("bfd_udp_mod", api_bfd_udp_mod, (cJSON * (*)(void *))vl_api_bfd_udp_mod_t_tojson, 0x913df085);
   vat2_register_function("bfd_udp_del", api_bfd_udp_del, (cJSON * (*)(void *))vl_api_bfd_udp_del_t_tojson, 0xdcb13a89);
   vat2_register_function("bfd_udp_session_dump", api_bfd_udp_session_dump, (cJSON * (*)(void *))vl_api_bfd_udp_session_dump_t_tojson, 0x51077d14);
   vat2_register_function("bfd_udp_session_set_flags", api_bfd_udp_session_set_flags, (cJSON * (*)(void *))vl_api_bfd_udp_session_set_flags_t_tojson, 0x04b4bdfd);
   vat2_register_function("bfd_auth_set_key", api_bfd_auth_set_key, (cJSON * (*)(void *))vl_api_bfd_auth_set_key_t_tojson, 0x690b8877);
   vat2_register_function("bfd_auth_del_key", api_bfd_auth_del_key, (cJSON * (*)(void *))vl_api_bfd_auth_del_key_t_tojson, 0x65310b22);
   vat2_register_function("bfd_auth_keys_dump", api_bfd_auth_keys_dump, (cJSON * (*)(void *))vl_api_bfd_auth_keys_dump_t_tojson, 0x51077d14);
   vat2_register_function("bfd_udp_auth_activate", api_bfd_udp_auth_activate, (cJSON * (*)(void *))vl_api_bfd_udp_auth_activate_t_tojson, 0x21fd1bdb);
   vat2_register_function("bfd_udp_auth_deactivate", api_bfd_udp_auth_deactivate, (cJSON * (*)(void *))vl_api_bfd_udp_auth_deactivate_t_tojson, 0x9a05e2e0);
   vat2_register_function("bfd_udp_enable_multihop", api_bfd_udp_enable_multihop, (cJSON * (*)(void *))vl_api_bfd_udp_enable_multihop_t_tojson, 0x51077d14);
   vat2_register_function("bfd_udp_set_tos", api_bfd_udp_set_tos, (cJSON * (*)(void *))vl_api_bfd_udp_set_tos_t_tojson, 0x00fe25ce);
   vat2_register_function("bfd_udp_get_tos", api_bfd_udp_get_tos, (cJSON * (*)(void *))vl_api_bfd_udp_get_tos_t_tojson, 0x51077d14);
   return 0;
}
