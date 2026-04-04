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

#include "syslog.api_enum.h"
#include "syslog.api_types.h"

#define vl_endianfun		/* define message structures */
#include "syslog.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "syslog.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "syslog.api.h"
#undef vl_printfun

#include "syslog.api_tojson.h"
#include "syslog.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_syslog_set_sender (cJSON *o)
{
  vl_api_syslog_set_sender_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_syslog_set_sender_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SYSLOG_SET_SENDER_CRC);
  vl_api_syslog_set_sender_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SYSLOG_SET_SENDER_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_syslog_set_sender_reply_t *rmp = (vl_api_syslog_set_sender_reply_t *)p;
  vl_api_syslog_set_sender_reply_t_endian(rmp, 0);
  return vl_api_syslog_set_sender_reply_t_tojson(rmp);
}

static cJSON *
api_syslog_get_sender (cJSON *o)
{
  vl_api_syslog_get_sender_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_syslog_get_sender_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SYSLOG_GET_SENDER_CRC);
  vl_api_syslog_get_sender_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SYSLOG_GET_SENDER_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_syslog_get_sender_reply_t *rmp = (vl_api_syslog_get_sender_reply_t *)p;
  vl_api_syslog_get_sender_reply_t_endian(rmp, 0);
  return vl_api_syslog_get_sender_reply_t_tojson(rmp);
}

static cJSON *
api_syslog_set_filter (cJSON *o)
{
  vl_api_syslog_set_filter_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_syslog_set_filter_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SYSLOG_SET_FILTER_CRC);
  vl_api_syslog_set_filter_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SYSLOG_SET_FILTER_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_syslog_set_filter_reply_t *rmp = (vl_api_syslog_set_filter_reply_t *)p;
  vl_api_syslog_set_filter_reply_t_endian(rmp, 0);
  return vl_api_syslog_set_filter_reply_t_tojson(rmp);
}

static cJSON *
api_syslog_get_filter (cJSON *o)
{
  vl_api_syslog_get_filter_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_syslog_get_filter_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SYSLOG_GET_FILTER_CRC);
  vl_api_syslog_get_filter_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SYSLOG_GET_FILTER_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_syslog_get_filter_reply_t *rmp = (vl_api_syslog_get_filter_reply_t *)p;
  vl_api_syslog_get_filter_reply_t_endian(rmp, 0);
  return vl_api_syslog_get_filter_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("syslog_set_sender", api_syslog_set_sender, (cJSON * (*)(void *))vl_api_syslog_set_sender_t_tojson, 0xb8011d0b);
   vat2_register_function("syslog_get_sender", api_syslog_get_sender, (cJSON * (*)(void *))vl_api_syslog_get_sender_t_tojson, 0x51077d14);
   vat2_register_function("syslog_set_filter", api_syslog_set_filter, (cJSON * (*)(void *))vl_api_syslog_set_filter_t_tojson, 0x571348c3);
   vat2_register_function("syslog_get_filter", api_syslog_get_filter, (cJSON * (*)(void *))vl_api_syslog_get_filter_t_tojson, 0x51077d14);
   return 0;
}
