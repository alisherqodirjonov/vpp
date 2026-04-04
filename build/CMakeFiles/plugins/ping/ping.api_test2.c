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

#include "ping.api_enum.h"
#include "ping.api_types.h"

#define vl_endianfun		/* define message structures */
#include "ping.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ping.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "ping.api.h"
#undef vl_printfun

#include "ping.api_tojson.h"
#include "ping.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_want_ping_finished_events (cJSON *o)
{
  vl_api_want_ping_finished_events_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_want_ping_finished_events_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_WANT_PING_FINISHED_EVENTS_CRC);
  vl_api_want_ping_finished_events_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_WANT_PING_FINISHED_EVENTS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_want_ping_finished_events_reply_t *rmp = (vl_api_want_ping_finished_events_reply_t *)p;
  vl_api_want_ping_finished_events_reply_t_endian(rmp, 0);
  return vl_api_want_ping_finished_events_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("want_ping_finished_events", api_want_ping_finished_events, (cJSON * (*)(void *))vl_api_want_ping_finished_events_t_tojson, 0xe79ee58b);
   return 0;
}
