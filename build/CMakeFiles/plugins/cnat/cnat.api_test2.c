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

#include "cnat.api_enum.h"
#include "cnat.api_types.h"

#define vl_endianfun		/* define message structures */
#include "cnat.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "cnat.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "cnat.api.h"
#undef vl_printfun

#include "cnat.api_tojson.h"
#include "cnat.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_cnat_translation_update (cJSON *o)
{
  vl_api_cnat_translation_update_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_cnat_translation_update_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CNAT_TRANSLATION_UPDATE_CRC);
  vl_api_cnat_translation_update_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CNAT_TRANSLATION_UPDATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_cnat_translation_update_reply_t *rmp = (vl_api_cnat_translation_update_reply_t *)p;
  vl_api_cnat_translation_update_reply_t_endian(rmp, 0);
  return vl_api_cnat_translation_update_reply_t_tojson(rmp);
}

static cJSON *
api_cnat_translation_del (cJSON *o)
{
  vl_api_cnat_translation_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_cnat_translation_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CNAT_TRANSLATION_DEL_CRC);
  vl_api_cnat_translation_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CNAT_TRANSLATION_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_cnat_translation_del_reply_t *rmp = (vl_api_cnat_translation_del_reply_t *)p;
  vl_api_cnat_translation_del_reply_t_endian(rmp, 0);
  return vl_api_cnat_translation_del_reply_t_tojson(rmp);
}

static cJSON *
api_cnat_translation_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_CNAT_TRANSLATION_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_cnat_translation_dump_t *mp = vl_api_cnat_translation_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_cnat_translation_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_CNAT_TRANSLATION_DETAILS_CRC);

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
        if (l < sizeof(vl_api_cnat_translation_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_cnat_translation_details_t *rmp = (vl_api_cnat_translation_details_t *)p;
        vl_api_cnat_translation_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_cnat_translation_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_cnat_session_purge (cJSON *o)
{
  vl_api_cnat_session_purge_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_cnat_session_purge_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CNAT_SESSION_PURGE_CRC);
  vl_api_cnat_session_purge_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CNAT_SESSION_PURGE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_cnat_session_purge_reply_t *rmp = (vl_api_cnat_session_purge_reply_t *)p;
  vl_api_cnat_session_purge_reply_t_endian(rmp, 0);
  return vl_api_cnat_session_purge_reply_t_tojson(rmp);
}

static cJSON *
api_cnat_session_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_CNAT_SESSION_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_cnat_session_dump_t *mp = vl_api_cnat_session_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_cnat_session_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_CNAT_SESSION_DETAILS_CRC);

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
        if (l < sizeof(vl_api_cnat_session_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_cnat_session_details_t *rmp = (vl_api_cnat_session_details_t *)p;
        vl_api_cnat_session_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_cnat_session_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_cnat_set_snat_addresses (cJSON *o)
{
  vl_api_cnat_set_snat_addresses_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_cnat_set_snat_addresses_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CNAT_SET_SNAT_ADDRESSES_CRC);
  vl_api_cnat_set_snat_addresses_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CNAT_SET_SNAT_ADDRESSES_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_cnat_set_snat_addresses_reply_t *rmp = (vl_api_cnat_set_snat_addresses_reply_t *)p;
  vl_api_cnat_set_snat_addresses_reply_t_endian(rmp, 0);
  return vl_api_cnat_set_snat_addresses_reply_t_tojson(rmp);
}

static cJSON *
api_cnat_get_snat_addresses (cJSON *o)
{
  vl_api_cnat_get_snat_addresses_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_cnat_get_snat_addresses_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CNAT_GET_SNAT_ADDRESSES_CRC);
  vl_api_cnat_get_snat_addresses_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CNAT_GET_SNAT_ADDRESSES_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_cnat_get_snat_addresses_reply_t *rmp = (vl_api_cnat_get_snat_addresses_reply_t *)p;
  vl_api_cnat_get_snat_addresses_reply_t_endian(rmp, 0);
  return vl_api_cnat_get_snat_addresses_reply_t_tojson(rmp);
}

static cJSON *
api_cnat_snat_policy_add_del_exclude_pfx (cJSON *o)
{
  vl_api_cnat_snat_policy_add_del_exclude_pfx_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_cnat_snat_policy_add_del_exclude_pfx_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CNAT_SNAT_POLICY_ADD_DEL_EXCLUDE_PFX_CRC);
  vl_api_cnat_snat_policy_add_del_exclude_pfx_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CNAT_SNAT_POLICY_ADD_DEL_EXCLUDE_PFX_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t *rmp = (vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t *)p;
  vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t_endian(rmp, 0);
  return vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t_tojson(rmp);
}

static cJSON *
api_cnat_snat_policy_add_del_if (cJSON *o)
{
  vl_api_cnat_snat_policy_add_del_if_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_cnat_snat_policy_add_del_if_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CNAT_SNAT_POLICY_ADD_DEL_IF_CRC);
  vl_api_cnat_snat_policy_add_del_if_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CNAT_SNAT_POLICY_ADD_DEL_IF_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_cnat_snat_policy_add_del_if_reply_t *rmp = (vl_api_cnat_snat_policy_add_del_if_reply_t *)p;
  vl_api_cnat_snat_policy_add_del_if_reply_t_endian(rmp, 0);
  return vl_api_cnat_snat_policy_add_del_if_reply_t_tojson(rmp);
}

static cJSON *
api_cnat_set_snat_policy (cJSON *o)
{
  vl_api_cnat_set_snat_policy_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_cnat_set_snat_policy_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CNAT_SET_SNAT_POLICY_CRC);
  vl_api_cnat_set_snat_policy_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CNAT_SET_SNAT_POLICY_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_cnat_set_snat_policy_reply_t *rmp = (vl_api_cnat_set_snat_policy_reply_t *)p;
  vl_api_cnat_set_snat_policy_reply_t_endian(rmp, 0);
  return vl_api_cnat_set_snat_policy_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("cnat_translation_update", api_cnat_translation_update, (cJSON * (*)(void *))vl_api_cnat_translation_update_t_tojson, 0xf8d40bc5);
   vat2_register_function("cnat_translation_del", api_cnat_translation_del, (cJSON * (*)(void *))vl_api_cnat_translation_del_t_tojson, 0x3a91bde5);
   vat2_register_function("cnat_translation_dump", api_cnat_translation_dump, (cJSON * (*)(void *))vl_api_cnat_translation_dump_t_tojson, 0x51077d14);
   vat2_register_function("cnat_session_purge", api_cnat_session_purge, (cJSON * (*)(void *))vl_api_cnat_session_purge_t_tojson, 0x51077d14);
   vat2_register_function("cnat_session_dump", api_cnat_session_dump, (cJSON * (*)(void *))vl_api_cnat_session_dump_t_tojson, 0x51077d14);
   vat2_register_function("cnat_set_snat_addresses", api_cnat_set_snat_addresses, (cJSON * (*)(void *))vl_api_cnat_set_snat_addresses_t_tojson, 0xd997e96c);
   vat2_register_function("cnat_get_snat_addresses", api_cnat_get_snat_addresses, (cJSON * (*)(void *))vl_api_cnat_get_snat_addresses_t_tojson, 0x51077d14);
   vat2_register_function("cnat_snat_policy_add_del_exclude_pfx", api_cnat_snat_policy_add_del_exclude_pfx, (cJSON * (*)(void *))vl_api_cnat_snat_policy_add_del_exclude_pfx_t_tojson, 0xe26dd79a);
   vat2_register_function("cnat_snat_policy_add_del_if", api_cnat_snat_policy_add_del_if, (cJSON * (*)(void *))vl_api_cnat_snat_policy_add_del_if_t_tojson, 0x4ebb8d02);
   vat2_register_function("cnat_set_snat_policy", api_cnat_set_snat_policy, (cJSON * (*)(void *))vl_api_cnat_set_snat_policy_t_tojson, 0xd3e6eaf4);
   return 0;
}
