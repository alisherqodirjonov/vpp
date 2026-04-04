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

#include "dhcp.api_enum.h"
#include "dhcp.api_types.h"

#define vl_endianfun		/* define message structures */
#include "dhcp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "dhcp.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "dhcp.api.h"
#undef vl_printfun

#include "dhcp.api_tojson.h"
#include "dhcp.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_dhcp_client_config (cJSON *o)
{
  vl_api_dhcp_client_config_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_dhcp_client_config_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DHCP_CLIENT_CONFIG_CRC);
  vl_api_dhcp_client_config_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DHCP_CLIENT_CONFIG_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_dhcp_client_config_reply_t *rmp = (vl_api_dhcp_client_config_reply_t *)p;
  vl_api_dhcp_client_config_reply_t_endian(rmp, 0);
  return vl_api_dhcp_client_config_reply_t_tojson(rmp);
}

static cJSON *
api_want_dhcp6_reply_events (cJSON *o)
{
  vl_api_want_dhcp6_reply_events_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_want_dhcp6_reply_events_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_WANT_DHCP6_REPLY_EVENTS_CRC);
  vl_api_want_dhcp6_reply_events_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_WANT_DHCP6_REPLY_EVENTS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_want_dhcp6_reply_events_reply_t *rmp = (vl_api_want_dhcp6_reply_events_reply_t *)p;
  vl_api_want_dhcp6_reply_events_reply_t_endian(rmp, 0);
  return vl_api_want_dhcp6_reply_events_reply_t_tojson(rmp);
}

static cJSON *
api_want_dhcp6_pd_reply_events (cJSON *o)
{
  vl_api_want_dhcp6_pd_reply_events_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_want_dhcp6_pd_reply_events_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_WANT_DHCP6_PD_REPLY_EVENTS_CRC);
  vl_api_want_dhcp6_pd_reply_events_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_WANT_DHCP6_PD_REPLY_EVENTS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_want_dhcp6_pd_reply_events_reply_t *rmp = (vl_api_want_dhcp6_pd_reply_events_reply_t *)p;
  vl_api_want_dhcp6_pd_reply_events_reply_t_endian(rmp, 0);
  return vl_api_want_dhcp6_pd_reply_events_reply_t_tojson(rmp);
}

static cJSON *
api_dhcp_plugin_get_version (cJSON *o)
{
  vl_api_dhcp_plugin_get_version_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_dhcp_plugin_get_version_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DHCP_PLUGIN_GET_VERSION_CRC);
  vl_api_dhcp_plugin_get_version_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DHCP_PLUGIN_GET_VERSION_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_dhcp_plugin_get_version_reply_t *rmp = (vl_api_dhcp_plugin_get_version_reply_t *)p;
  vl_api_dhcp_plugin_get_version_reply_t_endian(rmp, 0);
  return vl_api_dhcp_plugin_get_version_reply_t_tojson(rmp);
}

static cJSON *
api_dhcp_plugin_control_ping (cJSON *o)
{
  vl_api_dhcp_plugin_control_ping_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_dhcp_plugin_control_ping_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DHCP_PLUGIN_CONTROL_PING_CRC);
  vl_api_dhcp_plugin_control_ping_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DHCP_PLUGIN_CONTROL_PING_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_dhcp_plugin_control_ping_reply_t *rmp = (vl_api_dhcp_plugin_control_ping_reply_t *)p;
  vl_api_dhcp_plugin_control_ping_reply_t_endian(rmp, 0);
  return vl_api_dhcp_plugin_control_ping_reply_t_tojson(rmp);
}

static cJSON *
api_dhcp_proxy_config (cJSON *o)
{
  vl_api_dhcp_proxy_config_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_dhcp_proxy_config_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DHCP_PROXY_CONFIG_CRC);
  vl_api_dhcp_proxy_config_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DHCP_PROXY_CONFIG_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_dhcp_proxy_config_reply_t *rmp = (vl_api_dhcp_proxy_config_reply_t *)p;
  vl_api_dhcp_proxy_config_reply_t_endian(rmp, 0);
  return vl_api_dhcp_proxy_config_reply_t_tojson(rmp);
}

static cJSON *
api_dhcp_proxy_set_vss (cJSON *o)
{
  vl_api_dhcp_proxy_set_vss_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_dhcp_proxy_set_vss_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DHCP_PROXY_SET_VSS_CRC);
  vl_api_dhcp_proxy_set_vss_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DHCP_PROXY_SET_VSS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_dhcp_proxy_set_vss_reply_t *rmp = (vl_api_dhcp_proxy_set_vss_reply_t *)p;
  vl_api_dhcp_proxy_set_vss_reply_t_endian(rmp, 0);
  return vl_api_dhcp_proxy_set_vss_reply_t_tojson(rmp);
}

static cJSON *
api_dhcp_client_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_DHCP_CLIENT_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_dhcp_client_dump_t *mp = vl_api_dhcp_client_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_dhcp_client_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_DHCP_CLIENT_DETAILS_CRC);

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
        if (l < sizeof(vl_api_dhcp_client_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_dhcp_client_details_t *rmp = (vl_api_dhcp_client_details_t *)p;
        vl_api_dhcp_client_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_dhcp_client_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_dhcp_proxy_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_DHCP_PROXY_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_dhcp_proxy_dump_t *mp = vl_api_dhcp_proxy_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_dhcp_proxy_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_DHCP_PROXY_DETAILS_CRC);

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
        if (l < sizeof(vl_api_dhcp_proxy_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_dhcp_proxy_details_t *rmp = (vl_api_dhcp_proxy_details_t *)p;
        vl_api_dhcp_proxy_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_dhcp_proxy_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_dhcp_client_detect_enable_disable (cJSON *o)
{
  vl_api_dhcp_client_detect_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_dhcp_client_detect_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DHCP_CLIENT_DETECT_ENABLE_DISABLE_CRC);
  vl_api_dhcp_client_detect_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DHCP_CLIENT_DETECT_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_dhcp_client_detect_enable_disable_reply_t *rmp = (vl_api_dhcp_client_detect_enable_disable_reply_t *)p;
  vl_api_dhcp_client_detect_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_dhcp_client_detect_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_dhcp6_duid_ll_set (cJSON *o)
{
  vl_api_dhcp6_duid_ll_set_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_dhcp6_duid_ll_set_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DHCP6_DUID_LL_SET_CRC);
  vl_api_dhcp6_duid_ll_set_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DHCP6_DUID_LL_SET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_dhcp6_duid_ll_set_reply_t *rmp = (vl_api_dhcp6_duid_ll_set_reply_t *)p;
  vl_api_dhcp6_duid_ll_set_reply_t_endian(rmp, 0);
  return vl_api_dhcp6_duid_ll_set_reply_t_tojson(rmp);
}

static cJSON *
api_dhcp6_clients_enable_disable (cJSON *o)
{
  vl_api_dhcp6_clients_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_dhcp6_clients_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DHCP6_CLIENTS_ENABLE_DISABLE_CRC);
  vl_api_dhcp6_clients_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DHCP6_CLIENTS_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_dhcp6_clients_enable_disable_reply_t *rmp = (vl_api_dhcp6_clients_enable_disable_reply_t *)p;
  vl_api_dhcp6_clients_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_dhcp6_clients_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_dhcp6_send_client_message (cJSON *o)
{
  vl_api_dhcp6_send_client_message_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_dhcp6_send_client_message_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DHCP6_SEND_CLIENT_MESSAGE_CRC);
  vl_api_dhcp6_send_client_message_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DHCP6_SEND_CLIENT_MESSAGE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_dhcp6_send_client_message_reply_t *rmp = (vl_api_dhcp6_send_client_message_reply_t *)p;
  vl_api_dhcp6_send_client_message_reply_t_endian(rmp, 0);
  return vl_api_dhcp6_send_client_message_reply_t_tojson(rmp);
}

static cJSON *
api_dhcp6_pd_send_client_message (cJSON *o)
{
  vl_api_dhcp6_pd_send_client_message_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_dhcp6_pd_send_client_message_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DHCP6_PD_SEND_CLIENT_MESSAGE_CRC);
  vl_api_dhcp6_pd_send_client_message_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DHCP6_PD_SEND_CLIENT_MESSAGE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_dhcp6_pd_send_client_message_reply_t *rmp = (vl_api_dhcp6_pd_send_client_message_reply_t *)p;
  vl_api_dhcp6_pd_send_client_message_reply_t_endian(rmp, 0);
  return vl_api_dhcp6_pd_send_client_message_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("dhcp_client_config", api_dhcp_client_config, (cJSON * (*)(void *))vl_api_dhcp_client_config_t_tojson, 0x1af013ea);
   vat2_register_function("want_dhcp6_reply_events", api_want_dhcp6_reply_events, (cJSON * (*)(void *))vl_api_want_dhcp6_reply_events_t_tojson, 0x05b454b5);
   vat2_register_function("want_dhcp6_pd_reply_events", api_want_dhcp6_pd_reply_events, (cJSON * (*)(void *))vl_api_want_dhcp6_pd_reply_events_t_tojson, 0xc5e2af94);
   vat2_register_function("dhcp_plugin_get_version", api_dhcp_plugin_get_version, (cJSON * (*)(void *))vl_api_dhcp_plugin_get_version_t_tojson, 0x51077d14);
   vat2_register_function("dhcp_plugin_control_ping", api_dhcp_plugin_control_ping, (cJSON * (*)(void *))vl_api_dhcp_plugin_control_ping_t_tojson, 0x51077d14);
   vat2_register_function("dhcp_proxy_config", api_dhcp_proxy_config, (cJSON * (*)(void *))vl_api_dhcp_proxy_config_t_tojson, 0x4058a689);
   vat2_register_function("dhcp_proxy_set_vss", api_dhcp_proxy_set_vss, (cJSON * (*)(void *))vl_api_dhcp_proxy_set_vss_t_tojson, 0x50537301);
   vat2_register_function("dhcp_client_dump", api_dhcp_client_dump, (cJSON * (*)(void *))vl_api_dhcp_client_dump_t_tojson, 0x51077d14);
   vat2_register_function("dhcp_proxy_dump", api_dhcp_proxy_dump, (cJSON * (*)(void *))vl_api_dhcp_proxy_dump_t_tojson, 0x5c5b063f);
   vat2_register_function("dhcp_client_detect_enable_disable", api_dhcp_client_detect_enable_disable, (cJSON * (*)(void *))vl_api_dhcp_client_detect_enable_disable_t_tojson, 0xae6cfcfb);
   vat2_register_function("dhcp6_duid_ll_set", api_dhcp6_duid_ll_set, (cJSON * (*)(void *))vl_api_dhcp6_duid_ll_set_t_tojson, 0x0f6ca323);
   vat2_register_function("dhcp6_clients_enable_disable", api_dhcp6_clients_enable_disable, (cJSON * (*)(void *))vl_api_dhcp6_clients_enable_disable_t_tojson, 0xb3e225d2);
   vat2_register_function("dhcp6_send_client_message", api_dhcp6_send_client_message, (cJSON * (*)(void *))vl_api_dhcp6_send_client_message_t_tojson, 0xf8222476);
   vat2_register_function("dhcp6_pd_send_client_message", api_dhcp6_pd_send_client_message, (cJSON * (*)(void *))vl_api_dhcp6_pd_send_client_message_t_tojson, 0x3739fd8d);
   return 0;
}
