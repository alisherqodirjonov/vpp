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

#include "tcp.api_enum.h"
#include "tcp.api_types.h"

#define vl_endianfun		/* define message structures */
#include "tcp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "tcp.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "tcp.api.h"
#undef vl_printfun

#include "tcp.api_tojson.h"
#include "tcp.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_tcp_configure_src_addresses (cJSON *o)
{
  vl_api_tcp_configure_src_addresses_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_tcp_configure_src_addresses_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_TCP_CONFIGURE_SRC_ADDRESSES_CRC);
  vl_api_tcp_configure_src_addresses_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_TCP_CONFIGURE_SRC_ADDRESSES_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_tcp_configure_src_addresses_reply_t *rmp = (vl_api_tcp_configure_src_addresses_reply_t *)p;
  vl_api_tcp_configure_src_addresses_reply_t_endian(rmp, 0);
  return vl_api_tcp_configure_src_addresses_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("tcp_configure_src_addresses", api_tcp_configure_src_addresses, (cJSON * (*)(void *))vl_api_tcp_configure_src_addresses_t_tojson, 0x67eede0d);
   return 0;
}
