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

#include "dev.api_enum.h"
#include "dev.api_types.h"

#define vl_endianfun		/* define message structures */
#include "dev.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "dev.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "dev.api.h"
#undef vl_printfun

#include "dev.api_tojson.h"
#include "dev.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_dev_attach (cJSON *o)
{
  vl_api_dev_attach_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_dev_attach_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DEV_ATTACH_CRC);
  vl_api_dev_attach_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DEV_ATTACH_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_dev_attach_reply_t *rmp = (vl_api_dev_attach_reply_t *)p;
  vl_api_dev_attach_reply_t_endian(rmp, 0);
  return vl_api_dev_attach_reply_t_tojson(rmp);
}

static cJSON *
api_dev_detach (cJSON *o)
{
  vl_api_dev_detach_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_dev_detach_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DEV_DETACH_CRC);
  vl_api_dev_detach_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DEV_DETACH_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_dev_detach_reply_t *rmp = (vl_api_dev_detach_reply_t *)p;
  vl_api_dev_detach_reply_t_endian(rmp, 0);
  return vl_api_dev_detach_reply_t_tojson(rmp);
}

static cJSON *
api_dev_create_port_if (cJSON *o)
{
  vl_api_dev_create_port_if_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_dev_create_port_if_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DEV_CREATE_PORT_IF_CRC);
  vl_api_dev_create_port_if_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DEV_CREATE_PORT_IF_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_dev_create_port_if_reply_t *rmp = (vl_api_dev_create_port_if_reply_t *)p;
  vl_api_dev_create_port_if_reply_t_endian(rmp, 0);
  return vl_api_dev_create_port_if_reply_t_tojson(rmp);
}

static cJSON *
api_dev_remove_port_if (cJSON *o)
{
  vl_api_dev_remove_port_if_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_dev_remove_port_if_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DEV_REMOVE_PORT_IF_CRC);
  vl_api_dev_remove_port_if_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DEV_REMOVE_PORT_IF_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_dev_remove_port_if_reply_t *rmp = (vl_api_dev_remove_port_if_reply_t *)p;
  vl_api_dev_remove_port_if_reply_t_endian(rmp, 0);
  return vl_api_dev_remove_port_if_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("dev_attach", api_dev_attach, (cJSON * (*)(void *))vl_api_dev_attach_t_tojson, 0x44b725fc);
   vat2_register_function("dev_detach", api_dev_detach, (cJSON * (*)(void *))vl_api_dev_detach_t_tojson, 0xafae52d6);
   vat2_register_function("dev_create_port_if", api_dev_create_port_if, (cJSON * (*)(void *))vl_api_dev_create_port_if_t_tojson, 0xdbdf06f3);
   vat2_register_function("dev_remove_port_if", api_dev_remove_port_if, (cJSON * (*)(void *))vl_api_dev_remove_port_if_t_tojson, 0x529cb13f);
   return 0;
}
