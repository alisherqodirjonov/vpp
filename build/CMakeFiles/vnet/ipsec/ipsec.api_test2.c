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

#include "ipsec.api_enum.h"
#include "ipsec.api_types.h"

#define vl_endianfun		/* define message structures */
#include "ipsec.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ipsec.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "ipsec.api.h"
#undef vl_printfun

#include "ipsec.api_tojson.h"
#include "ipsec.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_ipsec_spd_add_del (cJSON *o)
{
  vl_api_ipsec_spd_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ipsec_spd_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IPSEC_SPD_ADD_DEL_CRC);
  vl_api_ipsec_spd_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IPSEC_SPD_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ipsec_spd_add_del_reply_t *rmp = (vl_api_ipsec_spd_add_del_reply_t *)p;
  vl_api_ipsec_spd_add_del_reply_t_endian(rmp, 0);
  return vl_api_ipsec_spd_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_ipsec_interface_add_del_spd (cJSON *o)
{
  vl_api_ipsec_interface_add_del_spd_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ipsec_interface_add_del_spd_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IPSEC_INTERFACE_ADD_DEL_SPD_CRC);
  vl_api_ipsec_interface_add_del_spd_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IPSEC_INTERFACE_ADD_DEL_SPD_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ipsec_interface_add_del_spd_reply_t *rmp = (vl_api_ipsec_interface_add_del_spd_reply_t *)p;
  vl_api_ipsec_interface_add_del_spd_reply_t_endian(rmp, 0);
  return vl_api_ipsec_interface_add_del_spd_reply_t_tojson(rmp);
}

static cJSON *
api_ipsec_spd_entry_add_del (cJSON *o)
{
  vl_api_ipsec_spd_entry_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ipsec_spd_entry_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IPSEC_SPD_ENTRY_ADD_DEL_CRC);
  vl_api_ipsec_spd_entry_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IPSEC_SPD_ENTRY_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ipsec_spd_entry_add_del_reply_t *rmp = (vl_api_ipsec_spd_entry_add_del_reply_t *)p;
  vl_api_ipsec_spd_entry_add_del_reply_t_endian(rmp, 0);
  return vl_api_ipsec_spd_entry_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_ipsec_spd_entry_add_del_v2 (cJSON *o)
{
  vl_api_ipsec_spd_entry_add_del_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ipsec_spd_entry_add_del_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IPSEC_SPD_ENTRY_ADD_DEL_V2_CRC);
  vl_api_ipsec_spd_entry_add_del_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IPSEC_SPD_ENTRY_ADD_DEL_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ipsec_spd_entry_add_del_v2_reply_t *rmp = (vl_api_ipsec_spd_entry_add_del_v2_reply_t *)p;
  vl_api_ipsec_spd_entry_add_del_v2_reply_t_endian(rmp, 0);
  return vl_api_ipsec_spd_entry_add_del_v2_reply_t_tojson(rmp);
}

static cJSON *
api_ipsec_spds_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IPSEC_SPDS_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ipsec_spds_dump_t *mp = vl_api_ipsec_spds_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ipsec_spds_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IPSEC_SPDS_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ipsec_spds_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ipsec_spds_details_t *rmp = (vl_api_ipsec_spds_details_t *)p;
        vl_api_ipsec_spds_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ipsec_spds_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ipsec_spd_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IPSEC_SPD_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ipsec_spd_dump_t *mp = vl_api_ipsec_spd_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ipsec_spd_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IPSEC_SPD_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ipsec_spd_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ipsec_spd_details_t *rmp = (vl_api_ipsec_spd_details_t *)p;
        vl_api_ipsec_spd_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ipsec_spd_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ipsec_sad_entry_add_del (cJSON *o)
{
  vl_api_ipsec_sad_entry_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ipsec_sad_entry_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IPSEC_SAD_ENTRY_ADD_DEL_CRC);
  vl_api_ipsec_sad_entry_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IPSEC_SAD_ENTRY_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ipsec_sad_entry_add_del_reply_t *rmp = (vl_api_ipsec_sad_entry_add_del_reply_t *)p;
  vl_api_ipsec_sad_entry_add_del_reply_t_endian(rmp, 0);
  return vl_api_ipsec_sad_entry_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_ipsec_sad_entry_add_del_v2 (cJSON *o)
{
  vl_api_ipsec_sad_entry_add_del_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ipsec_sad_entry_add_del_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V2_CRC);
  vl_api_ipsec_sad_entry_add_del_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ipsec_sad_entry_add_del_v2_reply_t *rmp = (vl_api_ipsec_sad_entry_add_del_v2_reply_t *)p;
  vl_api_ipsec_sad_entry_add_del_v2_reply_t_endian(rmp, 0);
  return vl_api_ipsec_sad_entry_add_del_v2_reply_t_tojson(rmp);
}

static cJSON *
api_ipsec_sad_entry_add_del_v3 (cJSON *o)
{
  vl_api_ipsec_sad_entry_add_del_v3_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ipsec_sad_entry_add_del_v3_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V3_CRC);
  vl_api_ipsec_sad_entry_add_del_v3_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V3_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ipsec_sad_entry_add_del_v3_reply_t *rmp = (vl_api_ipsec_sad_entry_add_del_v3_reply_t *)p;
  vl_api_ipsec_sad_entry_add_del_v3_reply_t_endian(rmp, 0);
  return vl_api_ipsec_sad_entry_add_del_v3_reply_t_tojson(rmp);
}

static cJSON *
api_ipsec_sad_entry_add (cJSON *o)
{
  vl_api_ipsec_sad_entry_add_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ipsec_sad_entry_add_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IPSEC_SAD_ENTRY_ADD_CRC);
  vl_api_ipsec_sad_entry_add_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IPSEC_SAD_ENTRY_ADD_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ipsec_sad_entry_add_reply_t *rmp = (vl_api_ipsec_sad_entry_add_reply_t *)p;
  vl_api_ipsec_sad_entry_add_reply_t_endian(rmp, 0);
  return vl_api_ipsec_sad_entry_add_reply_t_tojson(rmp);
}

static cJSON *
api_ipsec_sad_entry_add_v2 (cJSON *o)
{
  vl_api_ipsec_sad_entry_add_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ipsec_sad_entry_add_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IPSEC_SAD_ENTRY_ADD_V2_CRC);
  vl_api_ipsec_sad_entry_add_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IPSEC_SAD_ENTRY_ADD_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ipsec_sad_entry_add_v2_reply_t *rmp = (vl_api_ipsec_sad_entry_add_v2_reply_t *)p;
  vl_api_ipsec_sad_entry_add_v2_reply_t_endian(rmp, 0);
  return vl_api_ipsec_sad_entry_add_v2_reply_t_tojson(rmp);
}

static cJSON *
api_ipsec_sad_entry_del (cJSON *o)
{
  vl_api_ipsec_sad_entry_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ipsec_sad_entry_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IPSEC_SAD_ENTRY_DEL_CRC);
  vl_api_ipsec_sad_entry_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IPSEC_SAD_ENTRY_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ipsec_sad_entry_del_reply_t *rmp = (vl_api_ipsec_sad_entry_del_reply_t *)p;
  vl_api_ipsec_sad_entry_del_reply_t_endian(rmp, 0);
  return vl_api_ipsec_sad_entry_del_reply_t_tojson(rmp);
}

static cJSON *
api_ipsec_sad_bind (cJSON *o)
{
  vl_api_ipsec_sad_bind_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ipsec_sad_bind_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IPSEC_SAD_BIND_CRC);
  vl_api_ipsec_sad_bind_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IPSEC_SAD_BIND_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ipsec_sad_bind_reply_t *rmp = (vl_api_ipsec_sad_bind_reply_t *)p;
  vl_api_ipsec_sad_bind_reply_t_endian(rmp, 0);
  return vl_api_ipsec_sad_bind_reply_t_tojson(rmp);
}

static cJSON *
api_ipsec_sad_unbind (cJSON *o)
{
  vl_api_ipsec_sad_unbind_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ipsec_sad_unbind_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IPSEC_SAD_UNBIND_CRC);
  vl_api_ipsec_sad_unbind_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IPSEC_SAD_UNBIND_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ipsec_sad_unbind_reply_t *rmp = (vl_api_ipsec_sad_unbind_reply_t *)p;
  vl_api_ipsec_sad_unbind_reply_t_endian(rmp, 0);
  return vl_api_ipsec_sad_unbind_reply_t_tojson(rmp);
}

static cJSON *
api_ipsec_sad_entry_update (cJSON *o)
{
  vl_api_ipsec_sad_entry_update_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ipsec_sad_entry_update_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IPSEC_SAD_ENTRY_UPDATE_CRC);
  vl_api_ipsec_sad_entry_update_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IPSEC_SAD_ENTRY_UPDATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ipsec_sad_entry_update_reply_t *rmp = (vl_api_ipsec_sad_entry_update_reply_t *)p;
  vl_api_ipsec_sad_entry_update_reply_t_endian(rmp, 0);
  return vl_api_ipsec_sad_entry_update_reply_t_tojson(rmp);
}

static cJSON *
api_ipsec_tunnel_protect_update (cJSON *o)
{
  vl_api_ipsec_tunnel_protect_update_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ipsec_tunnel_protect_update_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IPSEC_TUNNEL_PROTECT_UPDATE_CRC);
  vl_api_ipsec_tunnel_protect_update_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IPSEC_TUNNEL_PROTECT_UPDATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ipsec_tunnel_protect_update_reply_t *rmp = (vl_api_ipsec_tunnel_protect_update_reply_t *)p;
  vl_api_ipsec_tunnel_protect_update_reply_t_endian(rmp, 0);
  return vl_api_ipsec_tunnel_protect_update_reply_t_tojson(rmp);
}

static cJSON *
api_ipsec_tunnel_protect_del (cJSON *o)
{
  vl_api_ipsec_tunnel_protect_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ipsec_tunnel_protect_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IPSEC_TUNNEL_PROTECT_DEL_CRC);
  vl_api_ipsec_tunnel_protect_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IPSEC_TUNNEL_PROTECT_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ipsec_tunnel_protect_del_reply_t *rmp = (vl_api_ipsec_tunnel_protect_del_reply_t *)p;
  vl_api_ipsec_tunnel_protect_del_reply_t_endian(rmp, 0);
  return vl_api_ipsec_tunnel_protect_del_reply_t_tojson(rmp);
}

static cJSON *
api_ipsec_tunnel_protect_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IPSEC_TUNNEL_PROTECT_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ipsec_tunnel_protect_dump_t *mp = vl_api_ipsec_tunnel_protect_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ipsec_tunnel_protect_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IPSEC_TUNNEL_PROTECT_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ipsec_tunnel_protect_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ipsec_tunnel_protect_details_t *rmp = (vl_api_ipsec_tunnel_protect_details_t *)p;
        vl_api_ipsec_tunnel_protect_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ipsec_tunnel_protect_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ipsec_spd_interface_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IPSEC_SPD_INTERFACE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ipsec_spd_interface_dump_t *mp = vl_api_ipsec_spd_interface_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ipsec_spd_interface_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IPSEC_SPD_INTERFACE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ipsec_spd_interface_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ipsec_spd_interface_details_t *rmp = (vl_api_ipsec_spd_interface_details_t *)p;
        vl_api_ipsec_spd_interface_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ipsec_spd_interface_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ipsec_itf_create (cJSON *o)
{
  vl_api_ipsec_itf_create_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ipsec_itf_create_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IPSEC_ITF_CREATE_CRC);
  vl_api_ipsec_itf_create_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IPSEC_ITF_CREATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ipsec_itf_create_reply_t *rmp = (vl_api_ipsec_itf_create_reply_t *)p;
  vl_api_ipsec_itf_create_reply_t_endian(rmp, 0);
  return vl_api_ipsec_itf_create_reply_t_tojson(rmp);
}

static cJSON *
api_ipsec_itf_delete (cJSON *o)
{
  vl_api_ipsec_itf_delete_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ipsec_itf_delete_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IPSEC_ITF_DELETE_CRC);
  vl_api_ipsec_itf_delete_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IPSEC_ITF_DELETE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ipsec_itf_delete_reply_t *rmp = (vl_api_ipsec_itf_delete_reply_t *)p;
  vl_api_ipsec_itf_delete_reply_t_endian(rmp, 0);
  return vl_api_ipsec_itf_delete_reply_t_tojson(rmp);
}

static cJSON *
api_ipsec_itf_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IPSEC_ITF_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ipsec_itf_dump_t *mp = vl_api_ipsec_itf_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ipsec_itf_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IPSEC_ITF_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ipsec_itf_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ipsec_itf_details_t *rmp = (vl_api_ipsec_itf_details_t *)p;
        vl_api_ipsec_itf_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ipsec_itf_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ipsec_sa_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IPSEC_SA_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ipsec_sa_dump_t *mp = vl_api_ipsec_sa_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ipsec_sa_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IPSEC_SA_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ipsec_sa_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ipsec_sa_details_t *rmp = (vl_api_ipsec_sa_details_t *)p;
        vl_api_ipsec_sa_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ipsec_sa_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ipsec_sa_v2_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IPSEC_SA_V2_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ipsec_sa_v2_dump_t *mp = vl_api_ipsec_sa_v2_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ipsec_sa_v2_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IPSEC_SA_V2_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ipsec_sa_v2_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ipsec_sa_v2_details_t *rmp = (vl_api_ipsec_sa_v2_details_t *)p;
        vl_api_ipsec_sa_v2_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ipsec_sa_v2_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ipsec_sa_v3_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IPSEC_SA_V3_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ipsec_sa_v3_dump_t *mp = vl_api_ipsec_sa_v3_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ipsec_sa_v3_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IPSEC_SA_V3_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ipsec_sa_v3_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ipsec_sa_v3_details_t *rmp = (vl_api_ipsec_sa_v3_details_t *)p;
        vl_api_ipsec_sa_v3_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ipsec_sa_v3_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ipsec_sa_v4_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IPSEC_SA_V4_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ipsec_sa_v4_dump_t *mp = vl_api_ipsec_sa_v4_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ipsec_sa_v4_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IPSEC_SA_V4_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ipsec_sa_v4_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ipsec_sa_v4_details_t *rmp = (vl_api_ipsec_sa_v4_details_t *)p;
        vl_api_ipsec_sa_v4_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ipsec_sa_v4_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ipsec_sa_v5_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IPSEC_SA_V5_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ipsec_sa_v5_dump_t *mp = vl_api_ipsec_sa_v5_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ipsec_sa_v5_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IPSEC_SA_V5_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ipsec_sa_v5_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ipsec_sa_v5_details_t *rmp = (vl_api_ipsec_sa_v5_details_t *)p;
        vl_api_ipsec_sa_v5_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ipsec_sa_v5_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ipsec_backend_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IPSEC_BACKEND_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ipsec_backend_dump_t *mp = vl_api_ipsec_backend_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ipsec_backend_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IPSEC_BACKEND_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ipsec_backend_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ipsec_backend_details_t *rmp = (vl_api_ipsec_backend_details_t *)p;
        vl_api_ipsec_backend_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ipsec_backend_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ipsec_select_backend (cJSON *o)
{
  vl_api_ipsec_select_backend_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ipsec_select_backend_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IPSEC_SELECT_BACKEND_CRC);
  vl_api_ipsec_select_backend_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IPSEC_SELECT_BACKEND_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ipsec_select_backend_reply_t *rmp = (vl_api_ipsec_select_backend_reply_t *)p;
  vl_api_ipsec_select_backend_reply_t_endian(rmp, 0);
  return vl_api_ipsec_select_backend_reply_t_tojson(rmp);
}

static cJSON *
api_ipsec_set_async_mode (cJSON *o)
{
  vl_api_ipsec_set_async_mode_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ipsec_set_async_mode_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IPSEC_SET_ASYNC_MODE_CRC);
  vl_api_ipsec_set_async_mode_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IPSEC_SET_ASYNC_MODE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ipsec_set_async_mode_reply_t *rmp = (vl_api_ipsec_set_async_mode_reply_t *)p;
  vl_api_ipsec_set_async_mode_reply_t_endian(rmp, 0);
  return vl_api_ipsec_set_async_mode_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("ipsec_spd_add_del", api_ipsec_spd_add_del, (cJSON * (*)(void *))vl_api_ipsec_spd_add_del_t_tojson, 0x20e89a95);
   vat2_register_function("ipsec_interface_add_del_spd", api_ipsec_interface_add_del_spd, (cJSON * (*)(void *))vl_api_ipsec_interface_add_del_spd_t_tojson, 0x80f80cbb);
   vat2_register_function("ipsec_spd_entry_add_del", api_ipsec_spd_entry_add_del, (cJSON * (*)(void *))vl_api_ipsec_spd_entry_add_del_t_tojson, 0x338b7411);
   vat2_register_function("ipsec_spd_entry_add_del_v2", api_ipsec_spd_entry_add_del_v2, (cJSON * (*)(void *))vl_api_ipsec_spd_entry_add_del_v2_t_tojson, 0x7bfe69fc);
   vat2_register_function("ipsec_spds_dump", api_ipsec_spds_dump, (cJSON * (*)(void *))vl_api_ipsec_spds_dump_t_tojson, 0x51077d14);
   vat2_register_function("ipsec_spd_dump", api_ipsec_spd_dump, (cJSON * (*)(void *))vl_api_ipsec_spd_dump_t_tojson, 0xafefbf7d);
   vat2_register_function("ipsec_sad_entry_add_del", api_ipsec_sad_entry_add_del, (cJSON * (*)(void *))vl_api_ipsec_sad_entry_add_del_t_tojson, 0xab64b5c6);
   vat2_register_function("ipsec_sad_entry_add_del_v2", api_ipsec_sad_entry_add_del_v2, (cJSON * (*)(void *))vl_api_ipsec_sad_entry_add_del_v2_t_tojson, 0xaca78b27);
   vat2_register_function("ipsec_sad_entry_add_del_v3", api_ipsec_sad_entry_add_del_v3, (cJSON * (*)(void *))vl_api_ipsec_sad_entry_add_del_v3_t_tojson, 0xc77ebd92);
   vat2_register_function("ipsec_sad_entry_add", api_ipsec_sad_entry_add, (cJSON * (*)(void *))vl_api_ipsec_sad_entry_add_t_tojson, 0x50229353);
   vat2_register_function("ipsec_sad_entry_add_v2", api_ipsec_sad_entry_add_v2, (cJSON * (*)(void *))vl_api_ipsec_sad_entry_add_v2_t_tojson, 0x9611297a);
   vat2_register_function("ipsec_sad_entry_del", api_ipsec_sad_entry_del, (cJSON * (*)(void *))vl_api_ipsec_sad_entry_del_t_tojson, 0x3a91bde5);
   vat2_register_function("ipsec_sad_bind", api_ipsec_sad_bind, (cJSON * (*)(void *))vl_api_ipsec_sad_bind_t_tojson, 0x0649c0d9);
   vat2_register_function("ipsec_sad_unbind", api_ipsec_sad_unbind, (cJSON * (*)(void *))vl_api_ipsec_sad_unbind_t_tojson, 0x2076c2f4);
   vat2_register_function("ipsec_sad_entry_update", api_ipsec_sad_entry_update, (cJSON * (*)(void *))vl_api_ipsec_sad_entry_update_t_tojson, 0x1412af86);
   vat2_register_function("ipsec_tunnel_protect_update", api_ipsec_tunnel_protect_update, (cJSON * (*)(void *))vl_api_ipsec_tunnel_protect_update_t_tojson, 0x30d5f133);
   vat2_register_function("ipsec_tunnel_protect_del", api_ipsec_tunnel_protect_del, (cJSON * (*)(void *))vl_api_ipsec_tunnel_protect_del_t_tojson, 0xcd239930);
   vat2_register_function("ipsec_tunnel_protect_dump", api_ipsec_tunnel_protect_dump, (cJSON * (*)(void *))vl_api_ipsec_tunnel_protect_dump_t_tojson, 0xf9e6675e);
   vat2_register_function("ipsec_spd_interface_dump", api_ipsec_spd_interface_dump, (cJSON * (*)(void *))vl_api_ipsec_spd_interface_dump_t_tojson, 0x8971de19);
   vat2_register_function("ipsec_itf_create", api_ipsec_itf_create, (cJSON * (*)(void *))vl_api_ipsec_itf_create_t_tojson, 0x6f50b3bc);
   vat2_register_function("ipsec_itf_delete", api_ipsec_itf_delete, (cJSON * (*)(void *))vl_api_ipsec_itf_delete_t_tojson, 0xf9e6675e);
   vat2_register_function("ipsec_itf_dump", api_ipsec_itf_dump, (cJSON * (*)(void *))vl_api_ipsec_itf_dump_t_tojson, 0xf9e6675e);
   vat2_register_function("ipsec_sa_dump", api_ipsec_sa_dump, (cJSON * (*)(void *))vl_api_ipsec_sa_dump_t_tojson, 0x2076c2f4);
   vat2_register_function("ipsec_sa_v2_dump", api_ipsec_sa_v2_dump, (cJSON * (*)(void *))vl_api_ipsec_sa_v2_dump_t_tojson, 0x2076c2f4);
   vat2_register_function("ipsec_sa_v3_dump", api_ipsec_sa_v3_dump, (cJSON * (*)(void *))vl_api_ipsec_sa_v3_dump_t_tojson, 0x2076c2f4);
   vat2_register_function("ipsec_sa_v4_dump", api_ipsec_sa_v4_dump, (cJSON * (*)(void *))vl_api_ipsec_sa_v4_dump_t_tojson, 0x2076c2f4);
   vat2_register_function("ipsec_sa_v5_dump", api_ipsec_sa_v5_dump, (cJSON * (*)(void *))vl_api_ipsec_sa_v5_dump_t_tojson, 0x2076c2f4);
   vat2_register_function("ipsec_backend_dump", api_ipsec_backend_dump, (cJSON * (*)(void *))vl_api_ipsec_backend_dump_t_tojson, 0x51077d14);
   vat2_register_function("ipsec_select_backend", api_ipsec_select_backend, (cJSON * (*)(void *))vl_api_ipsec_select_backend_t_tojson, 0x5bcfd3b7);
   vat2_register_function("ipsec_set_async_mode", api_ipsec_set_async_mode, (cJSON * (*)(void *))vl_api_ipsec_set_async_mode_t_tojson, 0xa6465f7c);
   return 0;
}
