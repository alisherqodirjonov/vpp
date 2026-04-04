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

#include "vrrp.api_enum.h"
#include "vrrp.api_types.h"

#define vl_endianfun		/* define message structures */
#include "vrrp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "vrrp.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "vrrp.api.h"
#undef vl_printfun

#include "vrrp.api_tojson.h"
#include "vrrp.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_want_vrrp_vr_events (cJSON *o)
{
  vl_api_want_vrrp_vr_events_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_want_vrrp_vr_events_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_WANT_VRRP_VR_EVENTS_CRC);
  vl_api_want_vrrp_vr_events_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_WANT_VRRP_VR_EVENTS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_want_vrrp_vr_events_reply_t *rmp = (vl_api_want_vrrp_vr_events_reply_t *)p;
  vl_api_want_vrrp_vr_events_reply_t_endian(rmp, 0);
  return vl_api_want_vrrp_vr_events_reply_t_tojson(rmp);
}

static cJSON *
api_vrrp_vr_add_del (cJSON *o)
{
  vl_api_vrrp_vr_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_vrrp_vr_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_VRRP_VR_ADD_DEL_CRC);
  vl_api_vrrp_vr_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_VRRP_VR_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_vrrp_vr_add_del_reply_t *rmp = (vl_api_vrrp_vr_add_del_reply_t *)p;
  vl_api_vrrp_vr_add_del_reply_t_endian(rmp, 0);
  return vl_api_vrrp_vr_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_vrrp_vr_update (cJSON *o)
{
  vl_api_vrrp_vr_update_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_vrrp_vr_update_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_VRRP_VR_UPDATE_CRC);
  vl_api_vrrp_vr_update_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_VRRP_VR_UPDATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_vrrp_vr_update_reply_t *rmp = (vl_api_vrrp_vr_update_reply_t *)p;
  vl_api_vrrp_vr_update_reply_t_endian(rmp, 0);
  return vl_api_vrrp_vr_update_reply_t_tojson(rmp);
}

static cJSON *
api_vrrp_vr_del (cJSON *o)
{
  vl_api_vrrp_vr_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_vrrp_vr_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_VRRP_VR_DEL_CRC);
  vl_api_vrrp_vr_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_VRRP_VR_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_vrrp_vr_del_reply_t *rmp = (vl_api_vrrp_vr_del_reply_t *)p;
  vl_api_vrrp_vr_del_reply_t_endian(rmp, 0);
  return vl_api_vrrp_vr_del_reply_t_tojson(rmp);
}

static cJSON *
api_vrrp_vr_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_VRRP_VR_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_vrrp_vr_dump_t *mp = vl_api_vrrp_vr_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_vrrp_vr_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_VRRP_VR_DETAILS_CRC);

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
        if (l < sizeof(vl_api_vrrp_vr_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_vrrp_vr_details_t *rmp = (vl_api_vrrp_vr_details_t *)p;
        vl_api_vrrp_vr_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_vrrp_vr_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_vrrp_vr_start_stop (cJSON *o)
{
  vl_api_vrrp_vr_start_stop_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_vrrp_vr_start_stop_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_VRRP_VR_START_STOP_CRC);
  vl_api_vrrp_vr_start_stop_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_VRRP_VR_START_STOP_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_vrrp_vr_start_stop_reply_t *rmp = (vl_api_vrrp_vr_start_stop_reply_t *)p;
  vl_api_vrrp_vr_start_stop_reply_t_endian(rmp, 0);
  return vl_api_vrrp_vr_start_stop_reply_t_tojson(rmp);
}

static cJSON *
api_vrrp_vr_set_peers (cJSON *o)
{
  vl_api_vrrp_vr_set_peers_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_vrrp_vr_set_peers_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_VRRP_VR_SET_PEERS_CRC);
  vl_api_vrrp_vr_set_peers_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_VRRP_VR_SET_PEERS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_vrrp_vr_set_peers_reply_t *rmp = (vl_api_vrrp_vr_set_peers_reply_t *)p;
  vl_api_vrrp_vr_set_peers_reply_t_endian(rmp, 0);
  return vl_api_vrrp_vr_set_peers_reply_t_tojson(rmp);
}

static cJSON *
api_vrrp_vr_peer_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_VRRP_VR_PEER_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_vrrp_vr_peer_dump_t *mp = vl_api_vrrp_vr_peer_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_vrrp_vr_peer_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_VRRP_VR_PEER_DETAILS_CRC);

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
        if (l < sizeof(vl_api_vrrp_vr_peer_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_vrrp_vr_peer_details_t *rmp = (vl_api_vrrp_vr_peer_details_t *)p;
        vl_api_vrrp_vr_peer_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_vrrp_vr_peer_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_vrrp_vr_track_if_add_del (cJSON *o)
{
  vl_api_vrrp_vr_track_if_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_vrrp_vr_track_if_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_VRRP_VR_TRACK_IF_ADD_DEL_CRC);
  vl_api_vrrp_vr_track_if_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_VRRP_VR_TRACK_IF_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_vrrp_vr_track_if_add_del_reply_t *rmp = (vl_api_vrrp_vr_track_if_add_del_reply_t *)p;
  vl_api_vrrp_vr_track_if_add_del_reply_t_endian(rmp, 0);
  return vl_api_vrrp_vr_track_if_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_vrrp_vr_track_if_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_VRRP_VR_TRACK_IF_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_vrrp_vr_track_if_dump_t *mp = vl_api_vrrp_vr_track_if_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_vrrp_vr_track_if_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_VRRP_VR_TRACK_IF_DETAILS_CRC);

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
        if (l < sizeof(vl_api_vrrp_vr_track_if_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_vrrp_vr_track_if_details_t *rmp = (vl_api_vrrp_vr_track_if_details_t *)p;
        vl_api_vrrp_vr_track_if_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_vrrp_vr_track_if_details_t_tojson(rmp));
    }
  }
  return reply;
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("want_vrrp_vr_events", api_want_vrrp_vr_events, (cJSON * (*)(void *))vl_api_want_vrrp_vr_events_t_tojson, 0xc5e2af94);
   vat2_register_function("vrrp_vr_add_del", api_vrrp_vr_add_del, (cJSON * (*)(void *))vl_api_vrrp_vr_add_del_t_tojson, 0xc5cf15aa);
   vat2_register_function("vrrp_vr_update", api_vrrp_vr_update, (cJSON * (*)(void *))vl_api_vrrp_vr_update_t_tojson, 0x0b51e2f4);
   vat2_register_function("vrrp_vr_del", api_vrrp_vr_del, (cJSON * (*)(void *))vl_api_vrrp_vr_del_t_tojson, 0x6029baa1);
   vat2_register_function("vrrp_vr_dump", api_vrrp_vr_dump, (cJSON * (*)(void *))vl_api_vrrp_vr_dump_t_tojson, 0xf9e6675e);
   vat2_register_function("vrrp_vr_start_stop", api_vrrp_vr_start_stop, (cJSON * (*)(void *))vl_api_vrrp_vr_start_stop_t_tojson, 0x0662a3b7);
   vat2_register_function("vrrp_vr_set_peers", api_vrrp_vr_set_peers, (cJSON * (*)(void *))vl_api_vrrp_vr_set_peers_t_tojson, 0x20bec71f);
   vat2_register_function("vrrp_vr_peer_dump", api_vrrp_vr_peer_dump, (cJSON * (*)(void *))vl_api_vrrp_vr_peer_dump_t_tojson, 0x6fa3f7c4);
   vat2_register_function("vrrp_vr_track_if_add_del", api_vrrp_vr_track_if_add_del, (cJSON * (*)(void *))vl_api_vrrp_vr_track_if_add_del_t_tojson, 0xd67df299);
   vat2_register_function("vrrp_vr_track_if_dump", api_vrrp_vr_track_if_dump, (cJSON * (*)(void *))vl_api_vrrp_vr_track_if_dump_t_tojson, 0xa34dfc6d);
   return 0;
}
