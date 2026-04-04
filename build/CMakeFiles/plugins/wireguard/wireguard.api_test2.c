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

#include "wireguard.api_enum.h"
#include "wireguard.api_types.h"

#define vl_endianfun		/* define message structures */
#include "wireguard.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "wireguard.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "wireguard.api.h"
#undef vl_printfun

#include "wireguard.api_tojson.h"
#include "wireguard.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_want_wireguard_peer_events (cJSON *o)
{
  vl_api_want_wireguard_peer_events_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_want_wireguard_peer_events_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_WANT_WIREGUARD_PEER_EVENTS_CRC);
  vl_api_want_wireguard_peer_events_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_WANT_WIREGUARD_PEER_EVENTS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_want_wireguard_peer_events_reply_t *rmp = (vl_api_want_wireguard_peer_events_reply_t *)p;
  vl_api_want_wireguard_peer_events_reply_t_endian(rmp, 0);
  return vl_api_want_wireguard_peer_events_reply_t_tojson(rmp);
}

static cJSON *
api_wireguard_interface_create (cJSON *o)
{
  vl_api_wireguard_interface_create_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_wireguard_interface_create_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_WIREGUARD_INTERFACE_CREATE_CRC);
  vl_api_wireguard_interface_create_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_WIREGUARD_INTERFACE_CREATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_wireguard_interface_create_reply_t *rmp = (vl_api_wireguard_interface_create_reply_t *)p;
  vl_api_wireguard_interface_create_reply_t_endian(rmp, 0);
  return vl_api_wireguard_interface_create_reply_t_tojson(rmp);
}

static cJSON *
api_wireguard_interface_delete (cJSON *o)
{
  vl_api_wireguard_interface_delete_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_wireguard_interface_delete_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_WIREGUARD_INTERFACE_DELETE_CRC);
  vl_api_wireguard_interface_delete_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_WIREGUARD_INTERFACE_DELETE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_wireguard_interface_delete_reply_t *rmp = (vl_api_wireguard_interface_delete_reply_t *)p;
  vl_api_wireguard_interface_delete_reply_t_endian(rmp, 0);
  return vl_api_wireguard_interface_delete_reply_t_tojson(rmp);
}

static cJSON *
api_wireguard_interface_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_WIREGUARD_INTERFACE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_wireguard_interface_dump_t *mp = vl_api_wireguard_interface_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_wireguard_interface_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_WIREGUARD_INTERFACE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_wireguard_interface_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_wireguard_interface_details_t *rmp = (vl_api_wireguard_interface_details_t *)p;
        vl_api_wireguard_interface_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_wireguard_interface_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_wireguard_peer_add (cJSON *o)
{
  vl_api_wireguard_peer_add_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_wireguard_peer_add_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_WIREGUARD_PEER_ADD_CRC);
  vl_api_wireguard_peer_add_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_WIREGUARD_PEER_ADD_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_wireguard_peer_add_reply_t *rmp = (vl_api_wireguard_peer_add_reply_t *)p;
  vl_api_wireguard_peer_add_reply_t_endian(rmp, 0);
  return vl_api_wireguard_peer_add_reply_t_tojson(rmp);
}

static cJSON *
api_wireguard_peer_remove (cJSON *o)
{
  vl_api_wireguard_peer_remove_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_wireguard_peer_remove_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_WIREGUARD_PEER_REMOVE_CRC);
  vl_api_wireguard_peer_remove_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_WIREGUARD_PEER_REMOVE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_wireguard_peer_remove_reply_t *rmp = (vl_api_wireguard_peer_remove_reply_t *)p;
  vl_api_wireguard_peer_remove_reply_t_endian(rmp, 0);
  return vl_api_wireguard_peer_remove_reply_t_tojson(rmp);
}

static cJSON *
api_wireguard_peers_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_WIREGUARD_PEERS_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_wireguard_peers_dump_t *mp = vl_api_wireguard_peers_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_wireguard_peers_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_WIREGUARD_PEERS_DETAILS_CRC);

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
        if (l < sizeof(vl_api_wireguard_peers_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_wireguard_peers_details_t *rmp = (vl_api_wireguard_peers_details_t *)p;
        vl_api_wireguard_peers_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_wireguard_peers_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_wg_set_async_mode (cJSON *o)
{
  vl_api_wg_set_async_mode_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_wg_set_async_mode_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_WG_SET_ASYNC_MODE_CRC);
  vl_api_wg_set_async_mode_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_WG_SET_ASYNC_MODE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_wg_set_async_mode_reply_t *rmp = (vl_api_wg_set_async_mode_reply_t *)p;
  vl_api_wg_set_async_mode_reply_t_endian(rmp, 0);
  return vl_api_wg_set_async_mode_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("want_wireguard_peer_events", api_want_wireguard_peer_events, (cJSON * (*)(void *))vl_api_want_wireguard_peer_events_t_tojson, 0x3bc666c8);
   vat2_register_function("wireguard_interface_create", api_wireguard_interface_create, (cJSON * (*)(void *))vl_api_wireguard_interface_create_t_tojson, 0xa530137e);
   vat2_register_function("wireguard_interface_delete", api_wireguard_interface_delete, (cJSON * (*)(void *))vl_api_wireguard_interface_delete_t_tojson, 0xf9e6675e);
   vat2_register_function("wireguard_interface_dump", api_wireguard_interface_dump, (cJSON * (*)(void *))vl_api_wireguard_interface_dump_t_tojson, 0x2c954158);
   vat2_register_function("wireguard_peer_add", api_wireguard_peer_add, (cJSON * (*)(void *))vl_api_wireguard_peer_add_t_tojson, 0x9b8aad61);
   vat2_register_function("wireguard_peer_remove", api_wireguard_peer_remove, (cJSON * (*)(void *))vl_api_wireguard_peer_remove_t_tojson, 0x3b74607a);
   vat2_register_function("wireguard_peers_dump", api_wireguard_peers_dump, (cJSON * (*)(void *))vl_api_wireguard_peers_dump_t_tojson, 0x3b74607a);
   vat2_register_function("wg_set_async_mode", api_wg_set_async_mode, (cJSON * (*)(void *))vl_api_wg_set_async_mode_t_tojson, 0xa6465f7c);
   return 0;
}
