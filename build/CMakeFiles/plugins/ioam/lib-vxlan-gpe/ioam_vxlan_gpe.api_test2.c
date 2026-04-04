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

#include "ioam_vxlan_gpe.api_enum.h"
#include "ioam_vxlan_gpe.api_types.h"

#define vl_endianfun		/* define message structures */
#include "ioam_vxlan_gpe.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ioam_vxlan_gpe.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "ioam_vxlan_gpe.api.h"
#undef vl_printfun

#include "ioam_vxlan_gpe.api_tojson.h"
#include "ioam_vxlan_gpe.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_vxlan_gpe_ioam_enable (cJSON *o)
{
  vl_api_vxlan_gpe_ioam_enable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_vxlan_gpe_ioam_enable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_VXLAN_GPE_IOAM_ENABLE_CRC);
  vl_api_vxlan_gpe_ioam_enable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_VXLAN_GPE_IOAM_ENABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_vxlan_gpe_ioam_enable_reply_t *rmp = (vl_api_vxlan_gpe_ioam_enable_reply_t *)p;
  vl_api_vxlan_gpe_ioam_enable_reply_t_endian(rmp, 0);
  return vl_api_vxlan_gpe_ioam_enable_reply_t_tojson(rmp);
}

static cJSON *
api_vxlan_gpe_ioam_disable (cJSON *o)
{
  vl_api_vxlan_gpe_ioam_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_vxlan_gpe_ioam_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_VXLAN_GPE_IOAM_DISABLE_CRC);
  vl_api_vxlan_gpe_ioam_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_VXLAN_GPE_IOAM_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_vxlan_gpe_ioam_disable_reply_t *rmp = (vl_api_vxlan_gpe_ioam_disable_reply_t *)p;
  vl_api_vxlan_gpe_ioam_disable_reply_t_endian(rmp, 0);
  return vl_api_vxlan_gpe_ioam_disable_reply_t_tojson(rmp);
}

static cJSON *
api_vxlan_gpe_ioam_vni_enable (cJSON *o)
{
  vl_api_vxlan_gpe_ioam_vni_enable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_vxlan_gpe_ioam_vni_enable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_VXLAN_GPE_IOAM_VNI_ENABLE_CRC);
  vl_api_vxlan_gpe_ioam_vni_enable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_VXLAN_GPE_IOAM_VNI_ENABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_vxlan_gpe_ioam_vni_enable_reply_t *rmp = (vl_api_vxlan_gpe_ioam_vni_enable_reply_t *)p;
  vl_api_vxlan_gpe_ioam_vni_enable_reply_t_endian(rmp, 0);
  return vl_api_vxlan_gpe_ioam_vni_enable_reply_t_tojson(rmp);
}

static cJSON *
api_vxlan_gpe_ioam_vni_disable (cJSON *o)
{
  vl_api_vxlan_gpe_ioam_vni_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_vxlan_gpe_ioam_vni_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_VXLAN_GPE_IOAM_VNI_DISABLE_CRC);
  vl_api_vxlan_gpe_ioam_vni_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_VXLAN_GPE_IOAM_VNI_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_vxlan_gpe_ioam_vni_disable_reply_t *rmp = (vl_api_vxlan_gpe_ioam_vni_disable_reply_t *)p;
  vl_api_vxlan_gpe_ioam_vni_disable_reply_t_endian(rmp, 0);
  return vl_api_vxlan_gpe_ioam_vni_disable_reply_t_tojson(rmp);
}

static cJSON *
api_vxlan_gpe_ioam_transit_enable (cJSON *o)
{
  vl_api_vxlan_gpe_ioam_transit_enable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_vxlan_gpe_ioam_transit_enable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_VXLAN_GPE_IOAM_TRANSIT_ENABLE_CRC);
  vl_api_vxlan_gpe_ioam_transit_enable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_VXLAN_GPE_IOAM_TRANSIT_ENABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_vxlan_gpe_ioam_transit_enable_reply_t *rmp = (vl_api_vxlan_gpe_ioam_transit_enable_reply_t *)p;
  vl_api_vxlan_gpe_ioam_transit_enable_reply_t_endian(rmp, 0);
  return vl_api_vxlan_gpe_ioam_transit_enable_reply_t_tojson(rmp);
}

static cJSON *
api_vxlan_gpe_ioam_transit_disable (cJSON *o)
{
  vl_api_vxlan_gpe_ioam_transit_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_vxlan_gpe_ioam_transit_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_VXLAN_GPE_IOAM_TRANSIT_DISABLE_CRC);
  vl_api_vxlan_gpe_ioam_transit_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_VXLAN_GPE_IOAM_TRANSIT_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_vxlan_gpe_ioam_transit_disable_reply_t *rmp = (vl_api_vxlan_gpe_ioam_transit_disable_reply_t *)p;
  vl_api_vxlan_gpe_ioam_transit_disable_reply_t_endian(rmp, 0);
  return vl_api_vxlan_gpe_ioam_transit_disable_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("vxlan_gpe_ioam_enable", api_vxlan_gpe_ioam_enable, (cJSON * (*)(void *))vl_api_vxlan_gpe_ioam_enable_t_tojson, 0x2481bef7);
   vat2_register_function("vxlan_gpe_ioam_disable", api_vxlan_gpe_ioam_disable, (cJSON * (*)(void *))vl_api_vxlan_gpe_ioam_disable_t_tojson, 0x6b16a45e);
   vat2_register_function("vxlan_gpe_ioam_vni_enable", api_vxlan_gpe_ioam_vni_enable, (cJSON * (*)(void *))vl_api_vxlan_gpe_ioam_vni_enable_t_tojson, 0x0fbb5fb1);
   vat2_register_function("vxlan_gpe_ioam_vni_disable", api_vxlan_gpe_ioam_vni_disable, (cJSON * (*)(void *))vl_api_vxlan_gpe_ioam_vni_disable_t_tojson, 0x0fbb5fb1);
   vat2_register_function("vxlan_gpe_ioam_transit_enable", api_vxlan_gpe_ioam_transit_enable, (cJSON * (*)(void *))vl_api_vxlan_gpe_ioam_transit_enable_t_tojson, 0x3d3ec657);
   vat2_register_function("vxlan_gpe_ioam_transit_disable", api_vxlan_gpe_ioam_transit_disable, (cJSON * (*)(void *))vl_api_vxlan_gpe_ioam_transit_disable_t_tojson, 0x3d3ec657);
   return 0;
}
