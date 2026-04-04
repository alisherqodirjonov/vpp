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

#include "tracedump.api_enum.h"
#include "tracedump.api_types.h"

#define vl_endianfun		/* define message structures */
#include "tracedump.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "tracedump.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "tracedump.api.h"
#undef vl_printfun

#include "tracedump.api_tojson.h"
#include "tracedump.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_trace_dump (cJSON *o)
{
    u16 msg_id = vac_get_msg_index(VL_API_TRACE_DUMP_CRC);
  int len = 0;
  if (!o) return 0;
  vl_api_trace_dump_t *mp = vl_api_trace_dump_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }
  mp->_vl_msg_id = msg_id;

  vl_api_trace_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  cJSON *reply = cJSON_CreateArray();

  u16 reply_msg_id = vac_get_msg_index(VL_API_TRACE_DUMP_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_TRACE_DETAILS_CRC);

  while (1) {
    /* Read reply */
    char *p;
    int l;
    vac_read(&p, &l, 5); // XXX: Fix timeout

    /* Message can be one of [_details, control_ping_reply
     * or unrelated event]
     */
    u16 msg_id = ntohs(*((u16 *)p));
    if (msg_id == reply_msg_id) {
        vl_api_trace_dump_reply_t *rmp = (vl_api_trace_dump_reply_t *)p;
        vl_api_trace_dump_reply_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_trace_dump_reply_t_tojson(rmp));
        break;
    }

    if (msg_id == details_msg_id) {
        vl_api_trace_details_t *rmp = (vl_api_trace_details_t *)p;
        vl_api_trace_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_trace_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_trace_set_filters (cJSON *o)
{
  vl_api_trace_set_filters_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_trace_set_filters_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_TRACE_SET_FILTERS_CRC);
  vl_api_trace_set_filters_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_TRACE_SET_FILTERS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_trace_set_filters_reply_t *rmp = (vl_api_trace_set_filters_reply_t *)p;
  vl_api_trace_set_filters_reply_t_endian(rmp, 0);
  return vl_api_trace_set_filters_reply_t_tojson(rmp);
}

static cJSON *
api_trace_capture_packets (cJSON *o)
{
  vl_api_trace_capture_packets_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_trace_capture_packets_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_TRACE_CAPTURE_PACKETS_CRC);
  vl_api_trace_capture_packets_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_TRACE_CAPTURE_PACKETS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_trace_capture_packets_reply_t *rmp = (vl_api_trace_capture_packets_reply_t *)p;
  vl_api_trace_capture_packets_reply_t_endian(rmp, 0);
  return vl_api_trace_capture_packets_reply_t_tojson(rmp);
}

static cJSON *
api_trace_clear_capture (cJSON *o)
{
  vl_api_trace_clear_capture_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_trace_clear_capture_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_TRACE_CLEAR_CAPTURE_CRC);
  vl_api_trace_clear_capture_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_TRACE_CLEAR_CAPTURE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_trace_clear_capture_reply_t *rmp = (vl_api_trace_clear_capture_reply_t *)p;
  vl_api_trace_clear_capture_reply_t_endian(rmp, 0);
  return vl_api_trace_clear_capture_reply_t_tojson(rmp);
}

static cJSON *
api_trace_clear_cache (cJSON *o)
{
  vl_api_trace_clear_cache_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_trace_clear_cache_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_TRACE_CLEAR_CACHE_CRC);
  vl_api_trace_clear_cache_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_TRACE_CLEAR_CACHE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_trace_clear_cache_reply_t *rmp = (vl_api_trace_clear_cache_reply_t *)p;
  vl_api_trace_clear_cache_reply_t_endian(rmp, 0);
  return vl_api_trace_clear_cache_reply_t_tojson(rmp);
}

static cJSON *
api_trace_v2_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_TRACE_V2_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_trace_v2_dump_t *mp = vl_api_trace_v2_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_trace_v2_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_TRACE_V2_DETAILS_CRC);

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
        if (l < sizeof(vl_api_trace_v2_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_trace_v2_details_t *rmp = (vl_api_trace_v2_details_t *)p;
        vl_api_trace_v2_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_trace_v2_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_trace_set_filter_function (cJSON *o)
{
  vl_api_trace_set_filter_function_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_trace_set_filter_function_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_TRACE_SET_FILTER_FUNCTION_CRC);
  vl_api_trace_set_filter_function_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_TRACE_SET_FILTER_FUNCTION_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_trace_set_filter_function_reply_t *rmp = (vl_api_trace_set_filter_function_reply_t *)p;
  vl_api_trace_set_filter_function_reply_t_endian(rmp, 0);
  return vl_api_trace_set_filter_function_reply_t_tojson(rmp);
}

static cJSON *
api_trace_filter_function_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_TRACE_FILTER_FUNCTION_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_trace_filter_function_dump_t *mp = vl_api_trace_filter_function_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_trace_filter_function_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_TRACE_FILTER_FUNCTION_DETAILS_CRC);

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
        if (l < sizeof(vl_api_trace_filter_function_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_trace_filter_function_details_t *rmp = (vl_api_trace_filter_function_details_t *)p;
        vl_api_trace_filter_function_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_trace_filter_function_details_t_tojson(rmp));
    }
  }
  return reply;
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("trace_dump", api_trace_dump, (cJSON * (*)(void *))vl_api_trace_dump_t_tojson, 0xc7d6681f);
   vat2_register_function("trace_set_filters", api_trace_set_filters, (cJSON * (*)(void *))vl_api_trace_set_filters_t_tojson, 0xf522b44a);
   vat2_register_function("trace_capture_packets", api_trace_capture_packets, (cJSON * (*)(void *))vl_api_trace_capture_packets_t_tojson, 0x9e791a9b);
   vat2_register_function("trace_clear_capture", api_trace_clear_capture, (cJSON * (*)(void *))vl_api_trace_clear_capture_t_tojson, 0x51077d14);
   vat2_register_function("trace_clear_cache", api_trace_clear_cache, (cJSON * (*)(void *))vl_api_trace_clear_cache_t_tojson, 0x51077d14);
   vat2_register_function("trace_v2_dump", api_trace_v2_dump, (cJSON * (*)(void *))vl_api_trace_v2_dump_t_tojson, 0x83f88d8e);
   vat2_register_function("trace_set_filter_function", api_trace_set_filter_function, (cJSON * (*)(void *))vl_api_trace_set_filter_function_t_tojson, 0x616abb92);
   vat2_register_function("trace_filter_function_dump", api_trace_filter_function_dump, (cJSON * (*)(void *))vl_api_trace_filter_function_dump_t_tojson, 0x51077d14);
   return 0;
}
