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

#include "fib.api_enum.h"
#include "fib.api_types.h"

#define vl_endianfun		/* define message structures */
#include "fib.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "fib.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "fib.api.h"
#undef vl_printfun

#include "fib.api_tojson.h"
#include "fib.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_fib_source_add (cJSON *o)
{
  vl_api_fib_source_add_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_fib_source_add_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_FIB_SOURCE_ADD_CRC);
  vl_api_fib_source_add_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_FIB_SOURCE_ADD_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_fib_source_add_reply_t *rmp = (vl_api_fib_source_add_reply_t *)p;
  vl_api_fib_source_add_reply_t_endian(rmp, 0);
  return vl_api_fib_source_add_reply_t_tojson(rmp);
}

static cJSON *
api_fib_source_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_FIB_SOURCE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_fib_source_dump_t *mp = vl_api_fib_source_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_fib_source_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_FIB_SOURCE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_fib_source_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_fib_source_details_t *rmp = (vl_api_fib_source_details_t *)p;
        vl_api_fib_source_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_fib_source_details_t_tojson(rmp));
    }
  }
  return reply;
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("fib_source_add", api_fib_source_add, (cJSON * (*)(void *))vl_api_fib_source_add_t_tojson, 0xb3ac2aec);
   vat2_register_function("fib_source_dump", api_fib_source_dump, (cJSON * (*)(void *))vl_api_fib_source_dump_t_tojson, 0x51077d14);
   return 0;
}
