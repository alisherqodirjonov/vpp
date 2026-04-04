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

#include "punt.api_enum.h"
#include "punt.api_types.h"

#define vl_endianfun		/* define message structures */
#include "punt.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "punt.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "punt.api.h"
#undef vl_printfun

#include "punt.api_tojson.h"
#include "punt.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_set_punt (cJSON *o)
{
  vl_api_set_punt_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_set_punt_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SET_PUNT_CRC);
  vl_api_set_punt_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SET_PUNT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_set_punt_reply_t *rmp = (vl_api_set_punt_reply_t *)p;
  vl_api_set_punt_reply_t_endian(rmp, 0);
  return vl_api_set_punt_reply_t_tojson(rmp);
}

static cJSON *
api_punt_socket_register (cJSON *o)
{
  vl_api_punt_socket_register_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_punt_socket_register_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_PUNT_SOCKET_REGISTER_CRC);
  vl_api_punt_socket_register_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_PUNT_SOCKET_REGISTER_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_punt_socket_register_reply_t *rmp = (vl_api_punt_socket_register_reply_t *)p;
  vl_api_punt_socket_register_reply_t_endian(rmp, 0);
  return vl_api_punt_socket_register_reply_t_tojson(rmp);
}

static cJSON *
api_punt_socket_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_PUNT_SOCKET_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_punt_socket_dump_t *mp = vl_api_punt_socket_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_punt_socket_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_PUNT_SOCKET_DETAILS_CRC);

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
        if (l < sizeof(vl_api_punt_socket_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_punt_socket_details_t *rmp = (vl_api_punt_socket_details_t *)p;
        vl_api_punt_socket_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_punt_socket_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_punt_socket_deregister (cJSON *o)
{
  vl_api_punt_socket_deregister_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_punt_socket_deregister_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_PUNT_SOCKET_DEREGISTER_CRC);
  vl_api_punt_socket_deregister_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_PUNT_SOCKET_DEREGISTER_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_punt_socket_deregister_reply_t *rmp = (vl_api_punt_socket_deregister_reply_t *)p;
  vl_api_punt_socket_deregister_reply_t_endian(rmp, 0);
  return vl_api_punt_socket_deregister_reply_t_tojson(rmp);
}

static cJSON *
api_punt_reason_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_PUNT_REASON_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_punt_reason_dump_t *mp = vl_api_punt_reason_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_punt_reason_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_PUNT_REASON_DETAILS_CRC);

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
        if (l < sizeof(vl_api_punt_reason_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_punt_reason_details_t *rmp = (vl_api_punt_reason_details_t *)p;
        vl_api_punt_reason_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_punt_reason_details_t_tojson(rmp));
    }
  }
  return reply;
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("set_punt", api_set_punt, (cJSON * (*)(void *))vl_api_set_punt_t_tojson, 0x47d0e347);
   vat2_register_function("punt_socket_register", api_punt_socket_register, (cJSON * (*)(void *))vl_api_punt_socket_register_t_tojson, 0x7875badb);
   vat2_register_function("punt_socket_dump", api_punt_socket_dump, (cJSON * (*)(void *))vl_api_punt_socket_dump_t_tojson, 0x916fb004);
   vat2_register_function("punt_socket_deregister", api_punt_socket_deregister, (cJSON * (*)(void *))vl_api_punt_socket_deregister_t_tojson, 0x75afa766);
   vat2_register_function("punt_reason_dump", api_punt_reason_dump, (cJSON * (*)(void *))vl_api_punt_reason_dump_t_tojson, 0x5c0dd4fe);
   return 0;
}
