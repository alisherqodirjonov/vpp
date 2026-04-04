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

#include "lb.api_enum.h"
#include "lb.api_types.h"

#define vl_endianfun		/* define message structures */
#include "lb.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "lb.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "lb.api.h"
#undef vl_printfun

#include "lb.api_tojson.h"
#include "lb.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_lb_conf (cJSON *o)
{
  vl_api_lb_conf_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lb_conf_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LB_CONF_CRC);
  vl_api_lb_conf_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LB_CONF_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lb_conf_reply_t *rmp = (vl_api_lb_conf_reply_t *)p;
  vl_api_lb_conf_reply_t_endian(rmp, 0);
  return vl_api_lb_conf_reply_t_tojson(rmp);
}

static cJSON *
api_lb_add_del_vip (cJSON *o)
{
  vl_api_lb_add_del_vip_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lb_add_del_vip_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LB_ADD_DEL_VIP_CRC);
  vl_api_lb_add_del_vip_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LB_ADD_DEL_VIP_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lb_add_del_vip_reply_t *rmp = (vl_api_lb_add_del_vip_reply_t *)p;
  vl_api_lb_add_del_vip_reply_t_endian(rmp, 0);
  return vl_api_lb_add_del_vip_reply_t_tojson(rmp);
}

static cJSON *
api_lb_add_del_vip_v2 (cJSON *o)
{
  vl_api_lb_add_del_vip_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lb_add_del_vip_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LB_ADD_DEL_VIP_V2_CRC);
  vl_api_lb_add_del_vip_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LB_ADD_DEL_VIP_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lb_add_del_vip_v2_reply_t *rmp = (vl_api_lb_add_del_vip_v2_reply_t *)p;
  vl_api_lb_add_del_vip_v2_reply_t_endian(rmp, 0);
  return vl_api_lb_add_del_vip_v2_reply_t_tojson(rmp);
}

static cJSON *
api_lb_add_del_as (cJSON *o)
{
  vl_api_lb_add_del_as_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lb_add_del_as_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LB_ADD_DEL_AS_CRC);
  vl_api_lb_add_del_as_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LB_ADD_DEL_AS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lb_add_del_as_reply_t *rmp = (vl_api_lb_add_del_as_reply_t *)p;
  vl_api_lb_add_del_as_reply_t_endian(rmp, 0);
  return vl_api_lb_add_del_as_reply_t_tojson(rmp);
}

static cJSON *
api_lb_flush_vip (cJSON *o)
{
  vl_api_lb_flush_vip_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lb_flush_vip_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LB_FLUSH_VIP_CRC);
  vl_api_lb_flush_vip_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LB_FLUSH_VIP_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lb_flush_vip_reply_t *rmp = (vl_api_lb_flush_vip_reply_t *)p;
  vl_api_lb_flush_vip_reply_t_endian(rmp, 0);
  return vl_api_lb_flush_vip_reply_t_tojson(rmp);
}

static cJSON *
api_lb_vip_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_LB_VIP_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_lb_vip_dump_t *mp = vl_api_lb_vip_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_lb_vip_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_LB_VIP_DETAILS_CRC);

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
        if (l < sizeof(vl_api_lb_vip_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_lb_vip_details_t *rmp = (vl_api_lb_vip_details_t *)p;
        vl_api_lb_vip_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_lb_vip_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_lb_as_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_LB_AS_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_lb_as_dump_t *mp = vl_api_lb_as_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_lb_as_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_LB_AS_DETAILS_CRC);

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
        if (l < sizeof(vl_api_lb_as_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_lb_as_details_t *rmp = (vl_api_lb_as_details_t *)p;
        vl_api_lb_as_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_lb_as_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_lb_add_del_intf_nat4 (cJSON *o)
{
  vl_api_lb_add_del_intf_nat4_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lb_add_del_intf_nat4_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LB_ADD_DEL_INTF_NAT4_CRC);
  vl_api_lb_add_del_intf_nat4_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LB_ADD_DEL_INTF_NAT4_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lb_add_del_intf_nat4_reply_t *rmp = (vl_api_lb_add_del_intf_nat4_reply_t *)p;
  vl_api_lb_add_del_intf_nat4_reply_t_endian(rmp, 0);
  return vl_api_lb_add_del_intf_nat4_reply_t_tojson(rmp);
}

static cJSON *
api_lb_add_del_intf_nat6 (cJSON *o)
{
  vl_api_lb_add_del_intf_nat6_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lb_add_del_intf_nat6_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LB_ADD_DEL_INTF_NAT6_CRC);
  vl_api_lb_add_del_intf_nat6_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LB_ADD_DEL_INTF_NAT6_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lb_add_del_intf_nat6_reply_t *rmp = (vl_api_lb_add_del_intf_nat6_reply_t *)p;
  vl_api_lb_add_del_intf_nat6_reply_t_endian(rmp, 0);
  return vl_api_lb_add_del_intf_nat6_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("lb_conf", api_lb_conf, (cJSON * (*)(void *))vl_api_lb_conf_t_tojson, 0x56cd3261);
   vat2_register_function("lb_add_del_vip", api_lb_add_del_vip, (cJSON * (*)(void *))vl_api_lb_add_del_vip_t_tojson, 0x6fa569c7);
   vat2_register_function("lb_add_del_vip_v2", api_lb_add_del_vip_v2, (cJSON * (*)(void *))vl_api_lb_add_del_vip_v2_t_tojson, 0x7c520e0f);
   vat2_register_function("lb_add_del_as", api_lb_add_del_as, (cJSON * (*)(void *))vl_api_lb_add_del_as_t_tojson, 0x35d72500);
   vat2_register_function("lb_flush_vip", api_lb_flush_vip, (cJSON * (*)(void *))vl_api_lb_flush_vip_t_tojson, 0x1063f819);
   vat2_register_function("lb_vip_dump", api_lb_vip_dump, (cJSON * (*)(void *))vl_api_lb_vip_dump_t_tojson, 0x56110cb7);
   vat2_register_function("lb_as_dump", api_lb_as_dump, (cJSON * (*)(void *))vl_api_lb_as_dump_t_tojson, 0x1063f819);
   vat2_register_function("lb_add_del_intf_nat4", api_lb_add_del_intf_nat4, (cJSON * (*)(void *))vl_api_lb_add_del_intf_nat4_t_tojson, 0x47d6e753);
   vat2_register_function("lb_add_del_intf_nat6", api_lb_add_del_intf_nat6, (cJSON * (*)(void *))vl_api_lb_add_del_intf_nat6_t_tojson, 0x47d6e753);
   return 0;
}
