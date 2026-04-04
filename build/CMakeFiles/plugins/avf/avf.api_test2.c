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

#include "avf.api_enum.h"
#include "avf.api_types.h"

#define vl_endianfun		/* define message structures */
#include "avf.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "avf.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "avf.api.h"
#undef vl_printfun

#include "avf.api_tojson.h"
#include "avf.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_avf_create (cJSON *o)
{
  vl_api_avf_create_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_avf_create_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_AVF_CREATE_CRC);
  vl_api_avf_create_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_AVF_CREATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_avf_create_reply_t *rmp = (vl_api_avf_create_reply_t *)p;
  vl_api_avf_create_reply_t_endian(rmp, 0);
  return vl_api_avf_create_reply_t_tojson(rmp);
}

static cJSON *
api_avf_delete (cJSON *o)
{
  vl_api_avf_delete_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_avf_delete_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_AVF_DELETE_CRC);
  vl_api_avf_delete_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_AVF_DELETE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_avf_delete_reply_t *rmp = (vl_api_avf_delete_reply_t *)p;
  vl_api_avf_delete_reply_t_endian(rmp, 0);
  return vl_api_avf_delete_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("avf_create", api_avf_create, (cJSON * (*)(void *))vl_api_avf_create_t_tojson, 0xdaab8ae2);
   vat2_register_function("avf_delete", api_avf_delete, (cJSON * (*)(void *))vl_api_avf_delete_t_tojson, 0xf9e6675e);
   return 0;
}
