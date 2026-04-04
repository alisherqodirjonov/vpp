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

#include "vxlan_gpe.api_enum.h"
#include "vxlan_gpe.api_types.h"

#define vl_endianfun		/* define message structures */
#include "vxlan_gpe.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "vxlan_gpe.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "vxlan_gpe.api.h"
#undef vl_printfun

#include "vxlan_gpe.api_tojson.h"
#include "vxlan_gpe.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_vxlan_gpe_add_del_tunnel (cJSON *o)
{
  vl_api_vxlan_gpe_add_del_tunnel_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_vxlan_gpe_add_del_tunnel_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_VXLAN_GPE_ADD_DEL_TUNNEL_CRC);
  vl_api_vxlan_gpe_add_del_tunnel_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_VXLAN_GPE_ADD_DEL_TUNNEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_vxlan_gpe_add_del_tunnel_reply_t *rmp = (vl_api_vxlan_gpe_add_del_tunnel_reply_t *)p;
  vl_api_vxlan_gpe_add_del_tunnel_reply_t_endian(rmp, 0);
  return vl_api_vxlan_gpe_add_del_tunnel_reply_t_tojson(rmp);
}

static cJSON *
api_vxlan_gpe_add_del_tunnel_v2 (cJSON *o)
{
  vl_api_vxlan_gpe_add_del_tunnel_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_vxlan_gpe_add_del_tunnel_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_VXLAN_GPE_ADD_DEL_TUNNEL_V2_CRC);
  vl_api_vxlan_gpe_add_del_tunnel_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_VXLAN_GPE_ADD_DEL_TUNNEL_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_vxlan_gpe_add_del_tunnel_v2_reply_t *rmp = (vl_api_vxlan_gpe_add_del_tunnel_v2_reply_t *)p;
  vl_api_vxlan_gpe_add_del_tunnel_v2_reply_t_endian(rmp, 0);
  return vl_api_vxlan_gpe_add_del_tunnel_v2_reply_t_tojson(rmp);
}

static cJSON *
api_vxlan_gpe_tunnel_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_VXLAN_GPE_TUNNEL_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_vxlan_gpe_tunnel_dump_t *mp = vl_api_vxlan_gpe_tunnel_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_vxlan_gpe_tunnel_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_VXLAN_GPE_TUNNEL_DETAILS_CRC);

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
        if (l < sizeof(vl_api_vxlan_gpe_tunnel_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_vxlan_gpe_tunnel_details_t *rmp = (vl_api_vxlan_gpe_tunnel_details_t *)p;
        vl_api_vxlan_gpe_tunnel_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_vxlan_gpe_tunnel_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_vxlan_gpe_tunnel_v2_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_VXLAN_GPE_TUNNEL_V2_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_vxlan_gpe_tunnel_v2_dump_t *mp = vl_api_vxlan_gpe_tunnel_v2_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_vxlan_gpe_tunnel_v2_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_VXLAN_GPE_TUNNEL_V2_DETAILS_CRC);

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
        if (l < sizeof(vl_api_vxlan_gpe_tunnel_v2_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_vxlan_gpe_tunnel_v2_details_t *rmp = (vl_api_vxlan_gpe_tunnel_v2_details_t *)p;
        vl_api_vxlan_gpe_tunnel_v2_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_vxlan_gpe_tunnel_v2_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_sw_interface_set_vxlan_gpe_bypass (cJSON *o)
{
  vl_api_sw_interface_set_vxlan_gpe_bypass_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_set_vxlan_gpe_bypass_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_VXLAN_GPE_BYPASS_CRC);
  vl_api_sw_interface_set_vxlan_gpe_bypass_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_SET_VXLAN_GPE_BYPASS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_set_vxlan_gpe_bypass_reply_t *rmp = (vl_api_sw_interface_set_vxlan_gpe_bypass_reply_t *)p;
  vl_api_sw_interface_set_vxlan_gpe_bypass_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_set_vxlan_gpe_bypass_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("vxlan_gpe_add_del_tunnel", api_vxlan_gpe_add_del_tunnel, (cJSON * (*)(void *))vl_api_vxlan_gpe_add_del_tunnel_t_tojson, 0xa645b2b0);
   vat2_register_function("vxlan_gpe_add_del_tunnel_v2", api_vxlan_gpe_add_del_tunnel_v2, (cJSON * (*)(void *))vl_api_vxlan_gpe_add_del_tunnel_v2_t_tojson, 0xd62fdb35);
   vat2_register_function("vxlan_gpe_tunnel_dump", api_vxlan_gpe_tunnel_dump, (cJSON * (*)(void *))vl_api_vxlan_gpe_tunnel_dump_t_tojson, 0xf9e6675e);
   vat2_register_function("vxlan_gpe_tunnel_v2_dump", api_vxlan_gpe_tunnel_v2_dump, (cJSON * (*)(void *))vl_api_vxlan_gpe_tunnel_v2_dump_t_tojson, 0xf9e6675e);
   vat2_register_function("sw_interface_set_vxlan_gpe_bypass", api_sw_interface_set_vxlan_gpe_bypass, (cJSON * (*)(void *))vl_api_sw_interface_set_vxlan_gpe_bypass_t_tojson, 0x65247409);
   return 0;
}
