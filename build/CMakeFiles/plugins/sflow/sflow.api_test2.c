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

#include "sflow.api_enum.h"
#include "sflow.api_types.h"

#define vl_endianfun		/* define message structures */
#include "sflow.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "sflow.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "sflow.api.h"
#undef vl_printfun

#include "sflow.api_tojson.h"
#include "sflow.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_sflow_enable_disable (cJSON *o)
{
  vl_api_sflow_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sflow_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SFLOW_ENABLE_DISABLE_CRC);
  vl_api_sflow_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SFLOW_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sflow_enable_disable_reply_t *rmp = (vl_api_sflow_enable_disable_reply_t *)p;
  vl_api_sflow_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_sflow_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_sflow_sampling_rate_get (cJSON *o)
{
  vl_api_sflow_sampling_rate_get_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sflow_sampling_rate_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SFLOW_SAMPLING_RATE_GET_CRC);
  vl_api_sflow_sampling_rate_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SFLOW_SAMPLING_RATE_GET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sflow_sampling_rate_get_reply_t *rmp = (vl_api_sflow_sampling_rate_get_reply_t *)p;
  vl_api_sflow_sampling_rate_get_reply_t_endian(rmp, 0);
  return vl_api_sflow_sampling_rate_get_reply_t_tojson(rmp);
}

static cJSON *
api_sflow_sampling_rate_set (cJSON *o)
{
  vl_api_sflow_sampling_rate_set_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sflow_sampling_rate_set_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SFLOW_SAMPLING_RATE_SET_CRC);
  vl_api_sflow_sampling_rate_set_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SFLOW_SAMPLING_RATE_SET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sflow_sampling_rate_set_reply_t *rmp = (vl_api_sflow_sampling_rate_set_reply_t *)p;
  vl_api_sflow_sampling_rate_set_reply_t_endian(rmp, 0);
  return vl_api_sflow_sampling_rate_set_reply_t_tojson(rmp);
}

static cJSON *
api_sflow_polling_interval_set (cJSON *o)
{
  vl_api_sflow_polling_interval_set_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sflow_polling_interval_set_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SFLOW_POLLING_INTERVAL_SET_CRC);
  vl_api_sflow_polling_interval_set_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SFLOW_POLLING_INTERVAL_SET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sflow_polling_interval_set_reply_t *rmp = (vl_api_sflow_polling_interval_set_reply_t *)p;
  vl_api_sflow_polling_interval_set_reply_t_endian(rmp, 0);
  return vl_api_sflow_polling_interval_set_reply_t_tojson(rmp);
}

static cJSON *
api_sflow_polling_interval_get (cJSON *o)
{
  vl_api_sflow_polling_interval_get_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sflow_polling_interval_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SFLOW_POLLING_INTERVAL_GET_CRC);
  vl_api_sflow_polling_interval_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SFLOW_POLLING_INTERVAL_GET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sflow_polling_interval_get_reply_t *rmp = (vl_api_sflow_polling_interval_get_reply_t *)p;
  vl_api_sflow_polling_interval_get_reply_t_endian(rmp, 0);
  return vl_api_sflow_polling_interval_get_reply_t_tojson(rmp);
}

static cJSON *
api_sflow_header_bytes_set (cJSON *o)
{
  vl_api_sflow_header_bytes_set_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sflow_header_bytes_set_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SFLOW_HEADER_BYTES_SET_CRC);
  vl_api_sflow_header_bytes_set_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SFLOW_HEADER_BYTES_SET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sflow_header_bytes_set_reply_t *rmp = (vl_api_sflow_header_bytes_set_reply_t *)p;
  vl_api_sflow_header_bytes_set_reply_t_endian(rmp, 0);
  return vl_api_sflow_header_bytes_set_reply_t_tojson(rmp);
}

static cJSON *
api_sflow_header_bytes_get (cJSON *o)
{
  vl_api_sflow_header_bytes_get_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sflow_header_bytes_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SFLOW_HEADER_BYTES_GET_CRC);
  vl_api_sflow_header_bytes_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SFLOW_HEADER_BYTES_GET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sflow_header_bytes_get_reply_t *rmp = (vl_api_sflow_header_bytes_get_reply_t *)p;
  vl_api_sflow_header_bytes_get_reply_t_endian(rmp, 0);
  return vl_api_sflow_header_bytes_get_reply_t_tojson(rmp);
}

static cJSON *
api_sflow_direction_set (cJSON *o)
{
  vl_api_sflow_direction_set_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sflow_direction_set_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SFLOW_DIRECTION_SET_CRC);
  vl_api_sflow_direction_set_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SFLOW_DIRECTION_SET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sflow_direction_set_reply_t *rmp = (vl_api_sflow_direction_set_reply_t *)p;
  vl_api_sflow_direction_set_reply_t_endian(rmp, 0);
  return vl_api_sflow_direction_set_reply_t_tojson(rmp);
}

static cJSON *
api_sflow_direction_get (cJSON *o)
{
  vl_api_sflow_direction_get_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sflow_direction_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SFLOW_DIRECTION_GET_CRC);
  vl_api_sflow_direction_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SFLOW_DIRECTION_GET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sflow_direction_get_reply_t *rmp = (vl_api_sflow_direction_get_reply_t *)p;
  vl_api_sflow_direction_get_reply_t_endian(rmp, 0);
  return vl_api_sflow_direction_get_reply_t_tojson(rmp);
}

static cJSON *
api_sflow_drop_monitoring_set (cJSON *o)
{
  vl_api_sflow_drop_monitoring_set_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sflow_drop_monitoring_set_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SFLOW_DROP_MONITORING_SET_CRC);
  vl_api_sflow_drop_monitoring_set_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SFLOW_DROP_MONITORING_SET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sflow_drop_monitoring_set_reply_t *rmp = (vl_api_sflow_drop_monitoring_set_reply_t *)p;
  vl_api_sflow_drop_monitoring_set_reply_t_endian(rmp, 0);
  return vl_api_sflow_drop_monitoring_set_reply_t_tojson(rmp);
}

static cJSON *
api_sflow_drop_monitoring_get (cJSON *o)
{
  vl_api_sflow_drop_monitoring_get_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sflow_drop_monitoring_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SFLOW_DROP_MONITORING_GET_CRC);
  vl_api_sflow_drop_monitoring_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SFLOW_DROP_MONITORING_GET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sflow_drop_monitoring_get_reply_t *rmp = (vl_api_sflow_drop_monitoring_get_reply_t *)p;
  vl_api_sflow_drop_monitoring_get_reply_t_endian(rmp, 0);
  return vl_api_sflow_drop_monitoring_get_reply_t_tojson(rmp);
}

static cJSON *
api_sflow_interface_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_SFLOW_INTERFACE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_sflow_interface_dump_t *mp = vl_api_sflow_interface_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_sflow_interface_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SFLOW_INTERFACE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_sflow_interface_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_sflow_interface_details_t *rmp = (vl_api_sflow_interface_details_t *)p;
        vl_api_sflow_interface_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_sflow_interface_details_t_tojson(rmp));
    }
  }
  return reply;
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("sflow_enable_disable", api_sflow_enable_disable, (cJSON * (*)(void *))vl_api_sflow_enable_disable_t_tojson, 0x8499814f);
   vat2_register_function("sflow_sampling_rate_get", api_sflow_sampling_rate_get, (cJSON * (*)(void *))vl_api_sflow_sampling_rate_get_t_tojson, 0x51077d14);
   vat2_register_function("sflow_sampling_rate_set", api_sflow_sampling_rate_set, (cJSON * (*)(void *))vl_api_sflow_sampling_rate_set_t_tojson, 0x94778f50);
   vat2_register_function("sflow_polling_interval_set", api_sflow_polling_interval_set, (cJSON * (*)(void *))vl_api_sflow_polling_interval_set_t_tojson, 0x7f19cb51);
   vat2_register_function("sflow_polling_interval_get", api_sflow_polling_interval_get, (cJSON * (*)(void *))vl_api_sflow_polling_interval_get_t_tojson, 0x51077d14);
   vat2_register_function("sflow_header_bytes_set", api_sflow_header_bytes_set, (cJSON * (*)(void *))vl_api_sflow_header_bytes_set_t_tojson, 0x5baf56f3);
   vat2_register_function("sflow_header_bytes_get", api_sflow_header_bytes_get, (cJSON * (*)(void *))vl_api_sflow_header_bytes_get_t_tojson, 0x51077d14);
   vat2_register_function("sflow_direction_set", api_sflow_direction_set, (cJSON * (*)(void *))vl_api_sflow_direction_set_t_tojson, 0xfbca6f34);
   vat2_register_function("sflow_direction_get", api_sflow_direction_get, (cJSON * (*)(void *))vl_api_sflow_direction_get_t_tojson, 0x51077d14);
   vat2_register_function("sflow_drop_monitoring_set", api_sflow_drop_monitoring_set, (cJSON * (*)(void *))vl_api_sflow_drop_monitoring_set_t_tojson, 0x100b1e04);
   vat2_register_function("sflow_drop_monitoring_get", api_sflow_drop_monitoring_get, (cJSON * (*)(void *))vl_api_sflow_drop_monitoring_get_t_tojson, 0x51077d14);
   vat2_register_function("sflow_interface_dump", api_sflow_interface_dump, (cJSON * (*)(void *))vl_api_sflow_interface_dump_t_tojson, 0x451a727d);
   return 0;
}
