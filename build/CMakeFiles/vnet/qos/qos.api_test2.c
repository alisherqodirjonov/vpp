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

#include "qos.api_enum.h"
#include "qos.api_types.h"

#define vl_endianfun		/* define message structures */
#include "qos.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "qos.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "qos.api.h"
#undef vl_printfun

#include "qos.api_tojson.h"
#include "qos.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_qos_store_enable_disable (cJSON *o)
{
  vl_api_qos_store_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_qos_store_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_QOS_STORE_ENABLE_DISABLE_CRC);
  vl_api_qos_store_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_QOS_STORE_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_qos_store_enable_disable_reply_t *rmp = (vl_api_qos_store_enable_disable_reply_t *)p;
  vl_api_qos_store_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_qos_store_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_qos_store_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_QOS_STORE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_qos_store_dump_t *mp = vl_api_qos_store_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_qos_store_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_QOS_STORE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_qos_store_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_qos_store_details_t *rmp = (vl_api_qos_store_details_t *)p;
        vl_api_qos_store_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_qos_store_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_qos_record_enable_disable (cJSON *o)
{
  vl_api_qos_record_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_qos_record_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_QOS_RECORD_ENABLE_DISABLE_CRC);
  vl_api_qos_record_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_QOS_RECORD_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_qos_record_enable_disable_reply_t *rmp = (vl_api_qos_record_enable_disable_reply_t *)p;
  vl_api_qos_record_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_qos_record_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_qos_record_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_QOS_RECORD_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_qos_record_dump_t *mp = vl_api_qos_record_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_qos_record_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_QOS_RECORD_DETAILS_CRC);

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
        if (l < sizeof(vl_api_qos_record_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_qos_record_details_t *rmp = (vl_api_qos_record_details_t *)p;
        vl_api_qos_record_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_qos_record_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_qos_egress_map_update (cJSON *o)
{
  vl_api_qos_egress_map_update_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_qos_egress_map_update_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_QOS_EGRESS_MAP_UPDATE_CRC);
  vl_api_qos_egress_map_update_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_QOS_EGRESS_MAP_UPDATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_qos_egress_map_update_reply_t *rmp = (vl_api_qos_egress_map_update_reply_t *)p;
  vl_api_qos_egress_map_update_reply_t_endian(rmp, 0);
  return vl_api_qos_egress_map_update_reply_t_tojson(rmp);
}

static cJSON *
api_qos_egress_map_delete (cJSON *o)
{
  vl_api_qos_egress_map_delete_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_qos_egress_map_delete_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_QOS_EGRESS_MAP_DELETE_CRC);
  vl_api_qos_egress_map_delete_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_QOS_EGRESS_MAP_DELETE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_qos_egress_map_delete_reply_t *rmp = (vl_api_qos_egress_map_delete_reply_t *)p;
  vl_api_qos_egress_map_delete_reply_t_endian(rmp, 0);
  return vl_api_qos_egress_map_delete_reply_t_tojson(rmp);
}

static cJSON *
api_qos_egress_map_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_QOS_EGRESS_MAP_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_qos_egress_map_dump_t *mp = vl_api_qos_egress_map_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_qos_egress_map_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_QOS_EGRESS_MAP_DETAILS_CRC);

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
        if (l < sizeof(vl_api_qos_egress_map_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_qos_egress_map_details_t *rmp = (vl_api_qos_egress_map_details_t *)p;
        vl_api_qos_egress_map_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_qos_egress_map_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_qos_mark_enable_disable (cJSON *o)
{
  vl_api_qos_mark_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_qos_mark_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_QOS_MARK_ENABLE_DISABLE_CRC);
  vl_api_qos_mark_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_QOS_MARK_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_qos_mark_enable_disable_reply_t *rmp = (vl_api_qos_mark_enable_disable_reply_t *)p;
  vl_api_qos_mark_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_qos_mark_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_qos_mark_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_QOS_MARK_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_qos_mark_dump_t *mp = vl_api_qos_mark_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_qos_mark_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_QOS_MARK_DETAILS_CRC);

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
        if (l < sizeof(vl_api_qos_mark_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_qos_mark_details_t *rmp = (vl_api_qos_mark_details_t *)p;
        vl_api_qos_mark_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_qos_mark_details_t_tojson(rmp));
    }
  }
  return reply;
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("qos_store_enable_disable", api_qos_store_enable_disable, (cJSON * (*)(void *))vl_api_qos_store_enable_disable_t_tojson, 0xf3abcc8b);
   vat2_register_function("qos_store_dump", api_qos_store_dump, (cJSON * (*)(void *))vl_api_qos_store_dump_t_tojson, 0x51077d14);
   vat2_register_function("qos_record_enable_disable", api_qos_record_enable_disable, (cJSON * (*)(void *))vl_api_qos_record_enable_disable_t_tojson, 0x2f1a4a38);
   vat2_register_function("qos_record_dump", api_qos_record_dump, (cJSON * (*)(void *))vl_api_qos_record_dump_t_tojson, 0x51077d14);
   vat2_register_function("qos_egress_map_update", api_qos_egress_map_update, (cJSON * (*)(void *))vl_api_qos_egress_map_update_t_tojson, 0x6d1c065f);
   vat2_register_function("qos_egress_map_delete", api_qos_egress_map_delete, (cJSON * (*)(void *))vl_api_qos_egress_map_delete_t_tojson, 0x3a91bde5);
   vat2_register_function("qos_egress_map_dump", api_qos_egress_map_dump, (cJSON * (*)(void *))vl_api_qos_egress_map_dump_t_tojson, 0x51077d14);
   vat2_register_function("qos_mark_enable_disable", api_qos_mark_enable_disable, (cJSON * (*)(void *))vl_api_qos_mark_enable_disable_t_tojson, 0x1a010f74);
   vat2_register_function("qos_mark_dump", api_qos_mark_dump, (cJSON * (*)(void *))vl_api_qos_mark_dump_t_tojson, 0xf9e6675e);
   return 0;
}
