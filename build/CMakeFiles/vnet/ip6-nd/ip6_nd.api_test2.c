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

#include "ip6_nd.api_enum.h"
#include "ip6_nd.api_types.h"

#define vl_endianfun		/* define message structures */
#include "ip6_nd.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ip6_nd.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "ip6_nd.api.h"
#undef vl_printfun

#include "ip6_nd.api_tojson.h"
#include "ip6_nd.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_want_ip6_ra_events (cJSON *o)
{
  vl_api_want_ip6_ra_events_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_want_ip6_ra_events_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_WANT_IP6_RA_EVENTS_CRC);
  vl_api_want_ip6_ra_events_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_WANT_IP6_RA_EVENTS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_want_ip6_ra_events_reply_t *rmp = (vl_api_want_ip6_ra_events_reply_t *)p;
  vl_api_want_ip6_ra_events_reply_t_endian(rmp, 0);
  return vl_api_want_ip6_ra_events_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_ip6nd_ra_config (cJSON *o)
{
  vl_api_sw_interface_ip6nd_ra_config_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_ip6nd_ra_config_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_IP6ND_RA_CONFIG_CRC);
  vl_api_sw_interface_ip6nd_ra_config_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_IP6ND_RA_CONFIG_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_ip6nd_ra_config_reply_t *rmp = (vl_api_sw_interface_ip6nd_ra_config_reply_t *)p;
  vl_api_sw_interface_ip6nd_ra_config_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_ip6nd_ra_config_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_ip6nd_ra_prefix (cJSON *o)
{
  vl_api_sw_interface_ip6nd_ra_prefix_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_ip6nd_ra_prefix_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_IP6ND_RA_PREFIX_CRC);
  vl_api_sw_interface_ip6nd_ra_prefix_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_IP6ND_RA_PREFIX_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_ip6nd_ra_prefix_reply_t *rmp = (vl_api_sw_interface_ip6nd_ra_prefix_reply_t *)p;
  vl_api_sw_interface_ip6nd_ra_prefix_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_ip6nd_ra_prefix_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_ip6nd_ra_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_IP6ND_RA_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_sw_interface_ip6nd_ra_dump_t *mp = vl_api_sw_interface_ip6nd_ra_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_sw_interface_ip6nd_ra_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_IP6ND_RA_DETAILS_CRC);

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
        if (l < sizeof(vl_api_sw_interface_ip6nd_ra_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_sw_interface_ip6nd_ra_details_t *rmp = (vl_api_sw_interface_ip6nd_ra_details_t *)p;
        vl_api_sw_interface_ip6nd_ra_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_sw_interface_ip6nd_ra_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ip6nd_proxy_enable_disable (cJSON *o)
{
  vl_api_ip6nd_proxy_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip6nd_proxy_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP6ND_PROXY_ENABLE_DISABLE_CRC);
  vl_api_ip6nd_proxy_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP6ND_PROXY_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip6nd_proxy_enable_disable_reply_t *rmp = (vl_api_ip6nd_proxy_enable_disable_reply_t *)p;
  vl_api_ip6nd_proxy_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_ip6nd_proxy_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_ip6nd_proxy_add_del (cJSON *o)
{
  vl_api_ip6nd_proxy_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip6nd_proxy_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP6ND_PROXY_ADD_DEL_CRC);
  vl_api_ip6nd_proxy_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP6ND_PROXY_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip6nd_proxy_add_del_reply_t *rmp = (vl_api_ip6nd_proxy_add_del_reply_t *)p;
  vl_api_ip6nd_proxy_add_del_reply_t_endian(rmp, 0);
  return vl_api_ip6nd_proxy_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_ip6nd_proxy_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IP6ND_PROXY_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_ip6nd_proxy_dump_t *mp = vl_api_ip6nd_proxy_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_ip6nd_proxy_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IP6ND_PROXY_DETAILS_CRC);

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
        if (l < sizeof(vl_api_ip6nd_proxy_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_ip6nd_proxy_details_t *rmp = (vl_api_ip6nd_proxy_details_t *)p;
        vl_api_ip6nd_proxy_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_ip6nd_proxy_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_ip6nd_send_router_solicitation (cJSON *o)
{
  vl_api_ip6nd_send_router_solicitation_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_ip6nd_send_router_solicitation_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IP6ND_SEND_ROUTER_SOLICITATION_CRC);
  vl_api_ip6nd_send_router_solicitation_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IP6ND_SEND_ROUTER_SOLICITATION_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_ip6nd_send_router_solicitation_reply_t *rmp = (vl_api_ip6nd_send_router_solicitation_reply_t *)p;
  vl_api_ip6nd_send_router_solicitation_reply_t_endian(rmp, 0);
  return vl_api_ip6nd_send_router_solicitation_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("want_ip6_ra_events", api_want_ip6_ra_events, (cJSON * (*)(void *))vl_api_want_ip6_ra_events_t_tojson, 0x3ec6d6c2);
   vat2_register_function("sw_interface_ip6nd_ra_config", api_sw_interface_ip6nd_ra_config, (cJSON * (*)(void *))vl_api_sw_interface_ip6nd_ra_config_t_tojson, 0x3eb00b1c);
   vat2_register_function("sw_interface_ip6nd_ra_prefix", api_sw_interface_ip6nd_ra_prefix, (cJSON * (*)(void *))vl_api_sw_interface_ip6nd_ra_prefix_t_tojson, 0x82cc1b28);
   vat2_register_function("sw_interface_ip6nd_ra_dump", api_sw_interface_ip6nd_ra_dump, (cJSON * (*)(void *))vl_api_sw_interface_ip6nd_ra_dump_t_tojson, 0xf9e6675e);
   vat2_register_function("ip6nd_proxy_enable_disable", api_ip6nd_proxy_enable_disable, (cJSON * (*)(void *))vl_api_ip6nd_proxy_enable_disable_t_tojson, 0x7daa1e3a);
   vat2_register_function("ip6nd_proxy_add_del", api_ip6nd_proxy_add_del, (cJSON * (*)(void *))vl_api_ip6nd_proxy_add_del_t_tojson, 0xc2e4a686);
   vat2_register_function("ip6nd_proxy_dump", api_ip6nd_proxy_dump, (cJSON * (*)(void *))vl_api_ip6nd_proxy_dump_t_tojson, 0x51077d14);
   vat2_register_function("ip6nd_send_router_solicitation", api_ip6nd_send_router_solicitation, (cJSON * (*)(void *))vl_api_ip6nd_send_router_solicitation_t_tojson, 0xe5de609c);
   return 0;
}
