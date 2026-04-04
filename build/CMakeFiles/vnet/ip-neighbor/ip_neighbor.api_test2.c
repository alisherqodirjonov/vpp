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

#include "ip_neighbor.api_enum.h"
#include "ip_neighbor.api_types.h"

#define vl_endianfun		/* define message structures */
#include "ip_neighbor.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ip_neighbor.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "ip_neighbor.api.h"
#undef vl_printfun

#include "ip_neighbor.api_tojson.h"
#include "ip_neighbor.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_want_ip_neighbor_events (cJSON *o)
{
  vl_api_want_ip_neighbor_events_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_want_ip_neighbor_events_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_WANT_IP_NEIGHBOR_EVENTS_CRC);
  vl_api_want_ip_neighbor_events_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_WANT_IP_NEIGHBOR_EVENTS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_want_ip_neighbor_events_reply_t *rmp = (vl_api_want_ip_neighbor_events_reply_t *)p;
  vl_api_want_ip_neighbor_events_reply_t_endian(rmp, 0);
  return vl_api_want_ip_neighbor_events_reply_t_tojson(rmp);
}

static cJSON *
api_want_ip_neighbor_events_v2 (cJSON *o)
{
  vl_api_want_ip_neighbor_events_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_want_ip_neighbor_events_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_WANT_IP_NEIGHBOR_EVENTS_V2_CRC);
  vl_api_want_ip_neighbor_events_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_WANT_IP_NEIGHBOR_EVENTS_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_want_ip_neighbor_events_v2_reply_t *rmp = (vl_api_want_ip_neighbor_events_v2_reply_t *)p;
  vl_api_want_ip_neighbor_events_v2_reply_t_endian(rmp, 0);
  return vl_api_want_ip_neighbor_events_v2_reply_t_tojson(rmp);
}

static cJSON *
api_ip_neighbor_add_del (cJSON *o)
{
  vl_api_ip_neighbor_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_neighbor_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_NEIGHBOR_ADD_DEL_CRC);
  vl_api_ip_neighbor_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_NEIGHBOR_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_neighbor_add_del_reply_t *rmp = (vl_api_ip_neighbor_add_del_reply_t *)p;
  vl_api_ip_neighbor_add_del_reply_t_endian(rmp, 0);
  return vl_api_ip_neighbor_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_ip_neighbor_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IP_NEIGHBOR_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ip_neighbor_dump_t *mp = vl_api_ip_neighbor_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ip_neighbor_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IP_NEIGHBOR_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ip_neighbor_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ip_neighbor_details_t *rmp = (vl_api_ip_neighbor_details_t *)p;
        vl_api_ip_neighbor_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ip_neighbor_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ip_neighbor_config (cJSON *o)
{
  vl_api_ip_neighbor_config_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_neighbor_config_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_NEIGHBOR_CONFIG_CRC);
  vl_api_ip_neighbor_config_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_NEIGHBOR_CONFIG_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_neighbor_config_reply_t *rmp = (vl_api_ip_neighbor_config_reply_t *)p;
  vl_api_ip_neighbor_config_reply_t_endian(rmp, 0);
  return vl_api_ip_neighbor_config_reply_t_tojson(rmp);
}

static cJSON *
api_ip_neighbor_config_get (cJSON *o)
{
  vl_api_ip_neighbor_config_get_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_neighbor_config_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_NEIGHBOR_CONFIG_GET_CRC);
  vl_api_ip_neighbor_config_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_NEIGHBOR_CONFIG_GET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_neighbor_config_get_reply_t *rmp = (vl_api_ip_neighbor_config_get_reply_t *)p;
  vl_api_ip_neighbor_config_get_reply_t_endian(rmp, 0);
  return vl_api_ip_neighbor_config_get_reply_t_tojson(rmp);
}

static cJSON *
api_ip_neighbor_replace_begin (cJSON *o)
{
  vl_api_ip_neighbor_replace_begin_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_neighbor_replace_begin_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_NEIGHBOR_REPLACE_BEGIN_CRC);
  vl_api_ip_neighbor_replace_begin_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_NEIGHBOR_REPLACE_BEGIN_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_neighbor_replace_begin_reply_t *rmp = (vl_api_ip_neighbor_replace_begin_reply_t *)p;
  vl_api_ip_neighbor_replace_begin_reply_t_endian(rmp, 0);
  return vl_api_ip_neighbor_replace_begin_reply_t_tojson(rmp);
}

static cJSON *
api_ip_neighbor_replace_end (cJSON *o)
{
  vl_api_ip_neighbor_replace_end_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_neighbor_replace_end_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_NEIGHBOR_REPLACE_END_CRC);
  vl_api_ip_neighbor_replace_end_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_NEIGHBOR_REPLACE_END_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_neighbor_replace_end_reply_t *rmp = (vl_api_ip_neighbor_replace_end_reply_t *)p;
  vl_api_ip_neighbor_replace_end_reply_t_endian(rmp, 0);
  return vl_api_ip_neighbor_replace_end_reply_t_tojson(rmp);
}

static cJSON *
api_ip_neighbor_flush (cJSON *o)
{
  vl_api_ip_neighbor_flush_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip_neighbor_flush_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP_NEIGHBOR_FLUSH_CRC);
  vl_api_ip_neighbor_flush_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP_NEIGHBOR_FLUSH_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip_neighbor_flush_reply_t *rmp = (vl_api_ip_neighbor_flush_reply_t *)p;
  vl_api_ip_neighbor_flush_reply_t_endian(rmp, 0);
  return vl_api_ip_neighbor_flush_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("want_ip_neighbor_events", api_want_ip_neighbor_events, (cJSON * (*)(void *))vl_api_want_ip_neighbor_events_t_tojson, 0x73e70a86);
   vat2_register_function("want_ip_neighbor_events_v2", api_want_ip_neighbor_events_v2, (cJSON * (*)(void *))vl_api_want_ip_neighbor_events_v2_t_tojson, 0x73e70a86);
   vat2_register_function("ip_neighbor_add_del", api_ip_neighbor_add_del, (cJSON * (*)(void *))vl_api_ip_neighbor_add_del_t_tojson, 0x0607c257);
   vat2_register_function("ip_neighbor_dump", api_ip_neighbor_dump, (cJSON * (*)(void *))vl_api_ip_neighbor_dump_t_tojson, 0xd817a484);
   vat2_register_function("ip_neighbor_config", api_ip_neighbor_config, (cJSON * (*)(void *))vl_api_ip_neighbor_config_t_tojson, 0xf4a5cf44);
   vat2_register_function("ip_neighbor_config_get", api_ip_neighbor_config_get, (cJSON * (*)(void *))vl_api_ip_neighbor_config_get_t_tojson, 0xa5db7bf7);
   vat2_register_function("ip_neighbor_replace_begin", api_ip_neighbor_replace_begin, (cJSON * (*)(void *))vl_api_ip_neighbor_replace_begin_t_tojson, 0x51077d14);
   vat2_register_function("ip_neighbor_replace_end", api_ip_neighbor_replace_end, (cJSON * (*)(void *))vl_api_ip_neighbor_replace_end_t_tojson, 0x51077d14);
   vat2_register_function("ip_neighbor_flush", api_ip_neighbor_flush, (cJSON * (*)(void *))vl_api_ip_neighbor_flush_t_tojson, 0x16aa35d2);
   return 0;
}
