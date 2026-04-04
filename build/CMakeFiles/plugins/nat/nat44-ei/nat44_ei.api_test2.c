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

#include "nat44_ei.api_enum.h"
#include "nat44_ei.api_types.h"

#define vl_endianfun		/* define message structures */
#include "nat44_ei.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "nat44_ei.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "nat44_ei.api.h"
#undef vl_printfun

#include "nat44_ei.api_tojson.h"
#include "nat44_ei.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_nat44_ei_ha_resync (cJSON *o)
{
  vl_api_nat44_ei_ha_resync_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_ha_resync_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_HA_RESYNC_CRC);
  vl_api_nat44_ei_ha_resync_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_HA_RESYNC_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_ha_resync_reply_t *rmp = (vl_api_nat44_ei_ha_resync_reply_t *)p;
  vl_api_nat44_ei_ha_resync_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_ha_resync_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_output_interface_get (cJSON *o)
{
    u16 msg_id = vac_get_msg_index(VL_API_NAT44_EI_OUTPUT_INTERFACE_GET_CRC);
  int len = 0;
  if (!o) return 0;
  vl_api_nat44_ei_output_interface_get_t *mp = vl_api_nat44_ei_output_interface_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }
  mp->_vl_msg_id = msg_id;

  vl_api_nat44_ei_output_interface_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  cJSON *reply = cJSON_CreateArray();

  u16 reply_msg_id = vac_get_msg_index(VL_API_NAT44_EI_OUTPUT_INTERFACE_GET_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_EI_OUTPUT_INTERFACE_DETAILS_CRC);

  while (1) {
    /* Read reply */
    char *p;
    int l;
    vac_read(&p, &l, 5); // XXX: Fix timeout

    /* Message can be one of [_details, control_ping_reply
     * or unrelated event]
     */
    u16 msg_id = ntohs(*((u16 *)p));
    if (msg_id == reply_msg_id) {
        vl_api_nat44_ei_output_interface_get_reply_t *rmp = (vl_api_nat44_ei_output_interface_get_reply_t *)p;
        vl_api_nat44_ei_output_interface_get_reply_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_ei_output_interface_get_reply_t_tojson(rmp));
        break;
    }

    if (msg_id == details_msg_id) {
        vl_api_nat44_ei_output_interface_details_t *rmp = (vl_api_nat44_ei_output_interface_details_t *)p;
        vl_api_nat44_ei_output_interface_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_ei_output_interface_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_ei_plugin_enable_disable (cJSON *o)
{
  vl_api_nat44_ei_plugin_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_plugin_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_PLUGIN_ENABLE_DISABLE_CRC);
  vl_api_nat44_ei_plugin_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_PLUGIN_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_plugin_enable_disable_reply_t *rmp = (vl_api_nat44_ei_plugin_enable_disable_reply_t *)p;
  vl_api_nat44_ei_plugin_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_plugin_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_show_running_config (cJSON *o)
{
  vl_api_nat44_ei_show_running_config_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_show_running_config_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_SHOW_RUNNING_CONFIG_CRC);
  vl_api_nat44_ei_show_running_config_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_SHOW_RUNNING_CONFIG_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_show_running_config_reply_t *rmp = (vl_api_nat44_ei_show_running_config_reply_t *)p;
  vl_api_nat44_ei_show_running_config_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_show_running_config_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_set_log_level (cJSON *o)
{
  vl_api_nat44_ei_set_log_level_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_set_log_level_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_SET_LOG_LEVEL_CRC);
  vl_api_nat44_ei_set_log_level_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_SET_LOG_LEVEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_set_log_level_reply_t *rmp = (vl_api_nat44_ei_set_log_level_reply_t *)p;
  vl_api_nat44_ei_set_log_level_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_set_log_level_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_set_workers (cJSON *o)
{
  vl_api_nat44_ei_set_workers_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_set_workers_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_SET_WORKERS_CRC);
  vl_api_nat44_ei_set_workers_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_SET_WORKERS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_set_workers_reply_t *rmp = (vl_api_nat44_ei_set_workers_reply_t *)p;
  vl_api_nat44_ei_set_workers_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_set_workers_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_worker_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_EI_WORKER_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_ei_worker_dump_t *mp = vl_api_nat44_ei_worker_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_ei_worker_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_EI_WORKER_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_ei_worker_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_ei_worker_details_t *rmp = (vl_api_nat44_ei_worker_details_t *)p;
        vl_api_nat44_ei_worker_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_ei_worker_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_ei_ipfix_enable_disable (cJSON *o)
{
  vl_api_nat44_ei_ipfix_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_ipfix_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_IPFIX_ENABLE_DISABLE_CRC);
  vl_api_nat44_ei_ipfix_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_IPFIX_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_ipfix_enable_disable_reply_t *rmp = (vl_api_nat44_ei_ipfix_enable_disable_reply_t *)p;
  vl_api_nat44_ei_ipfix_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_ipfix_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_set_timeouts (cJSON *o)
{
  vl_api_nat44_ei_set_timeouts_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_set_timeouts_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_SET_TIMEOUTS_CRC);
  vl_api_nat44_ei_set_timeouts_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_SET_TIMEOUTS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_set_timeouts_reply_t *rmp = (vl_api_nat44_ei_set_timeouts_reply_t *)p;
  vl_api_nat44_ei_set_timeouts_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_set_timeouts_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_set_addr_and_port_alloc_alg (cJSON *o)
{
  vl_api_nat44_ei_set_addr_and_port_alloc_alg_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_set_addr_and_port_alloc_alg_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_SET_ADDR_AND_PORT_ALLOC_ALG_CRC);
  vl_api_nat44_ei_set_addr_and_port_alloc_alg_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_SET_ADDR_AND_PORT_ALLOC_ALG_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t *rmp = (vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t *)p;
  vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_get_addr_and_port_alloc_alg (cJSON *o)
{
  vl_api_nat44_ei_get_addr_and_port_alloc_alg_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_get_addr_and_port_alloc_alg_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_GET_ADDR_AND_PORT_ALLOC_ALG_CRC);
  vl_api_nat44_ei_get_addr_and_port_alloc_alg_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_GET_ADDR_AND_PORT_ALLOC_ALG_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t *rmp = (vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t *)p;
  vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_set_mss_clamping (cJSON *o)
{
  vl_api_nat44_ei_set_mss_clamping_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_set_mss_clamping_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_SET_MSS_CLAMPING_CRC);
  vl_api_nat44_ei_set_mss_clamping_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_SET_MSS_CLAMPING_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_set_mss_clamping_reply_t *rmp = (vl_api_nat44_ei_set_mss_clamping_reply_t *)p;
  vl_api_nat44_ei_set_mss_clamping_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_set_mss_clamping_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_get_mss_clamping (cJSON *o)
{
  vl_api_nat44_ei_get_mss_clamping_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_get_mss_clamping_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_GET_MSS_CLAMPING_CRC);
  vl_api_nat44_ei_get_mss_clamping_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_GET_MSS_CLAMPING_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_get_mss_clamping_reply_t *rmp = (vl_api_nat44_ei_get_mss_clamping_reply_t *)p;
  vl_api_nat44_ei_get_mss_clamping_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_get_mss_clamping_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_ha_set_listener (cJSON *o)
{
  vl_api_nat44_ei_ha_set_listener_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_ha_set_listener_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_HA_SET_LISTENER_CRC);
  vl_api_nat44_ei_ha_set_listener_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_HA_SET_LISTENER_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_ha_set_listener_reply_t *rmp = (vl_api_nat44_ei_ha_set_listener_reply_t *)p;
  vl_api_nat44_ei_ha_set_listener_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_ha_set_listener_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_ha_set_failover (cJSON *o)
{
  vl_api_nat44_ei_ha_set_failover_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_ha_set_failover_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_HA_SET_FAILOVER_CRC);
  vl_api_nat44_ei_ha_set_failover_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_HA_SET_FAILOVER_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_ha_set_failover_reply_t *rmp = (vl_api_nat44_ei_ha_set_failover_reply_t *)p;
  vl_api_nat44_ei_ha_set_failover_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_ha_set_failover_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_ha_get_listener (cJSON *o)
{
  vl_api_nat44_ei_ha_get_listener_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_ha_get_listener_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_HA_GET_LISTENER_CRC);
  vl_api_nat44_ei_ha_get_listener_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_HA_GET_LISTENER_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_ha_get_listener_reply_t *rmp = (vl_api_nat44_ei_ha_get_listener_reply_t *)p;
  vl_api_nat44_ei_ha_get_listener_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_ha_get_listener_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_ha_get_failover (cJSON *o)
{
  vl_api_nat44_ei_ha_get_failover_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_ha_get_failover_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_HA_GET_FAILOVER_CRC);
  vl_api_nat44_ei_ha_get_failover_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_HA_GET_FAILOVER_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_ha_get_failover_reply_t *rmp = (vl_api_nat44_ei_ha_get_failover_reply_t *)p;
  vl_api_nat44_ei_ha_get_failover_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_ha_get_failover_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_ha_flush (cJSON *o)
{
  vl_api_nat44_ei_ha_flush_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_ha_flush_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_HA_FLUSH_CRC);
  vl_api_nat44_ei_ha_flush_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_HA_FLUSH_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_ha_flush_reply_t *rmp = (vl_api_nat44_ei_ha_flush_reply_t *)p;
  vl_api_nat44_ei_ha_flush_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_ha_flush_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_del_user (cJSON *o)
{
  vl_api_nat44_ei_del_user_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_del_user_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_DEL_USER_CRC);
  vl_api_nat44_ei_del_user_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_DEL_USER_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_del_user_reply_t *rmp = (vl_api_nat44_ei_del_user_reply_t *)p;
  vl_api_nat44_ei_del_user_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_del_user_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_add_del_address_range (cJSON *o)
{
  vl_api_nat44_ei_add_del_address_range_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_add_del_address_range_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_ADD_DEL_ADDRESS_RANGE_CRC);
  vl_api_nat44_ei_add_del_address_range_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_ADD_DEL_ADDRESS_RANGE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_add_del_address_range_reply_t *rmp = (vl_api_nat44_ei_add_del_address_range_reply_t *)p;
  vl_api_nat44_ei_add_del_address_range_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_add_del_address_range_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_address_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_EI_ADDRESS_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_ei_address_dump_t *mp = vl_api_nat44_ei_address_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_ei_address_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_EI_ADDRESS_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_ei_address_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_ei_address_details_t *rmp = (vl_api_nat44_ei_address_details_t *)p;
        vl_api_nat44_ei_address_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_ei_address_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_ei_interface_add_del_feature (cJSON *o)
{
  vl_api_nat44_ei_interface_add_del_feature_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_interface_add_del_feature_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_INTERFACE_ADD_DEL_FEATURE_CRC);
  vl_api_nat44_ei_interface_add_del_feature_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_INTERFACE_ADD_DEL_FEATURE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_interface_add_del_feature_reply_t *rmp = (vl_api_nat44_ei_interface_add_del_feature_reply_t *)p;
  vl_api_nat44_ei_interface_add_del_feature_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_interface_add_del_feature_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_interface_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_EI_INTERFACE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_ei_interface_dump_t *mp = vl_api_nat44_ei_interface_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_ei_interface_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_EI_INTERFACE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_ei_interface_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_ei_interface_details_t *rmp = (vl_api_nat44_ei_interface_details_t *)p;
        vl_api_nat44_ei_interface_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_ei_interface_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_ei_interface_add_del_output_feature (cJSON *o)
{
  vl_api_nat44_ei_interface_add_del_output_feature_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_interface_add_del_output_feature_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_INTERFACE_ADD_DEL_OUTPUT_FEATURE_CRC);
  vl_api_nat44_ei_interface_add_del_output_feature_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_INTERFACE_ADD_DEL_OUTPUT_FEATURE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_interface_add_del_output_feature_reply_t *rmp = (vl_api_nat44_ei_interface_add_del_output_feature_reply_t *)p;
  vl_api_nat44_ei_interface_add_del_output_feature_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_interface_add_del_output_feature_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_interface_output_feature_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_EI_INTERFACE_OUTPUT_FEATURE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_ei_interface_output_feature_dump_t *mp = vl_api_nat44_ei_interface_output_feature_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_ei_interface_output_feature_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_EI_INTERFACE_OUTPUT_FEATURE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_ei_interface_output_feature_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_ei_interface_output_feature_details_t *rmp = (vl_api_nat44_ei_interface_output_feature_details_t *)p;
        vl_api_nat44_ei_interface_output_feature_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_ei_interface_output_feature_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_ei_add_del_output_interface (cJSON *o)
{
  vl_api_nat44_ei_add_del_output_interface_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_add_del_output_interface_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_ADD_DEL_OUTPUT_INTERFACE_CRC);
  vl_api_nat44_ei_add_del_output_interface_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_ADD_DEL_OUTPUT_INTERFACE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_add_del_output_interface_reply_t *rmp = (vl_api_nat44_ei_add_del_output_interface_reply_t *)p;
  vl_api_nat44_ei_add_del_output_interface_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_add_del_output_interface_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_add_del_static_mapping (cJSON *o)
{
  vl_api_nat44_ei_add_del_static_mapping_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_add_del_static_mapping_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_ADD_DEL_STATIC_MAPPING_CRC);
  vl_api_nat44_ei_add_del_static_mapping_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_ADD_DEL_STATIC_MAPPING_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_add_del_static_mapping_reply_t *rmp = (vl_api_nat44_ei_add_del_static_mapping_reply_t *)p;
  vl_api_nat44_ei_add_del_static_mapping_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_add_del_static_mapping_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_static_mapping_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_EI_STATIC_MAPPING_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_ei_static_mapping_dump_t *mp = vl_api_nat44_ei_static_mapping_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_ei_static_mapping_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_EI_STATIC_MAPPING_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_ei_static_mapping_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_ei_static_mapping_details_t *rmp = (vl_api_nat44_ei_static_mapping_details_t *)p;
        vl_api_nat44_ei_static_mapping_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_ei_static_mapping_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_ei_add_del_identity_mapping (cJSON *o)
{
  vl_api_nat44_ei_add_del_identity_mapping_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_add_del_identity_mapping_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_ADD_DEL_IDENTITY_MAPPING_CRC);
  vl_api_nat44_ei_add_del_identity_mapping_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_ADD_DEL_IDENTITY_MAPPING_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_add_del_identity_mapping_reply_t *rmp = (vl_api_nat44_ei_add_del_identity_mapping_reply_t *)p;
  vl_api_nat44_ei_add_del_identity_mapping_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_add_del_identity_mapping_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_identity_mapping_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_EI_IDENTITY_MAPPING_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_ei_identity_mapping_dump_t *mp = vl_api_nat44_ei_identity_mapping_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_ei_identity_mapping_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_EI_IDENTITY_MAPPING_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_ei_identity_mapping_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_ei_identity_mapping_details_t *rmp = (vl_api_nat44_ei_identity_mapping_details_t *)p;
        vl_api_nat44_ei_identity_mapping_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_ei_identity_mapping_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_ei_add_del_interface_addr (cJSON *o)
{
  vl_api_nat44_ei_add_del_interface_addr_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_add_del_interface_addr_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_ADD_DEL_INTERFACE_ADDR_CRC);
  vl_api_nat44_ei_add_del_interface_addr_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_ADD_DEL_INTERFACE_ADDR_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_add_del_interface_addr_reply_t *rmp = (vl_api_nat44_ei_add_del_interface_addr_reply_t *)p;
  vl_api_nat44_ei_add_del_interface_addr_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_add_del_interface_addr_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_interface_addr_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_EI_INTERFACE_ADDR_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_ei_interface_addr_dump_t *mp = vl_api_nat44_ei_interface_addr_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_ei_interface_addr_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_EI_INTERFACE_ADDR_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_ei_interface_addr_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_ei_interface_addr_details_t *rmp = (vl_api_nat44_ei_interface_addr_details_t *)p;
        vl_api_nat44_ei_interface_addr_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_ei_interface_addr_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_ei_user_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_EI_USER_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_ei_user_dump_t *mp = vl_api_nat44_ei_user_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_ei_user_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_EI_USER_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_ei_user_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_ei_user_details_t *rmp = (vl_api_nat44_ei_user_details_t *)p;
        vl_api_nat44_ei_user_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_ei_user_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_ei_user_session_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_EI_USER_SESSION_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_ei_user_session_dump_t *mp = vl_api_nat44_ei_user_session_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_ei_user_session_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_EI_USER_SESSION_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_ei_user_session_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_ei_user_session_details_t *rmp = (vl_api_nat44_ei_user_session_details_t *)p;
        vl_api_nat44_ei_user_session_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_ei_user_session_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_ei_user_session_v2_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_EI_USER_SESSION_V2_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_ei_user_session_v2_dump_t *mp = vl_api_nat44_ei_user_session_v2_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_ei_user_session_v2_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_EI_USER_SESSION_V2_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_ei_user_session_v2_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_ei_user_session_v2_details_t *rmp = (vl_api_nat44_ei_user_session_v2_details_t *)p;
        vl_api_nat44_ei_user_session_v2_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_ei_user_session_v2_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_ei_del_session (cJSON *o)
{
  vl_api_nat44_ei_del_session_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_del_session_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_DEL_SESSION_CRC);
  vl_api_nat44_ei_del_session_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_DEL_SESSION_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_del_session_reply_t *rmp = (vl_api_nat44_ei_del_session_reply_t *)p;
  vl_api_nat44_ei_del_session_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_del_session_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_forwarding_enable_disable (cJSON *o)
{
  vl_api_nat44_ei_forwarding_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_forwarding_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_FORWARDING_ENABLE_DISABLE_CRC);
  vl_api_nat44_ei_forwarding_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_FORWARDING_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_forwarding_enable_disable_reply_t *rmp = (vl_api_nat44_ei_forwarding_enable_disable_reply_t *)p;
  vl_api_nat44_ei_forwarding_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_forwarding_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_set_fq_options (cJSON *o)
{
  vl_api_nat44_ei_set_fq_options_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_set_fq_options_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_SET_FQ_OPTIONS_CRC);
  vl_api_nat44_ei_set_fq_options_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_SET_FQ_OPTIONS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_set_fq_options_reply_t *rmp = (vl_api_nat44_ei_set_fq_options_reply_t *)p;
  vl_api_nat44_ei_set_fq_options_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_set_fq_options_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ei_show_fq_options (cJSON *o)
{
  vl_api_nat44_ei_show_fq_options_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ei_show_fq_options_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_EI_SHOW_FQ_OPTIONS_CRC);
  vl_api_nat44_ei_show_fq_options_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_EI_SHOW_FQ_OPTIONS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ei_show_fq_options_reply_t *rmp = (vl_api_nat44_ei_show_fq_options_reply_t *)p;
  vl_api_nat44_ei_show_fq_options_reply_t_endian(rmp, 0);
  return vl_api_nat44_ei_show_fq_options_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("nat44_ei_ha_resync", api_nat44_ei_ha_resync, (cJSON * (*)(void *))vl_api_nat44_ei_ha_resync_t_tojson, 0xc8ab9e03);
   vat2_register_function("nat44_ei_output_interface_get", api_nat44_ei_output_interface_get, (cJSON * (*)(void *))vl_api_nat44_ei_output_interface_get_t_tojson, 0xf75ba505);
   vat2_register_function("nat44_ei_plugin_enable_disable", api_nat44_ei_plugin_enable_disable, (cJSON * (*)(void *))vl_api_nat44_ei_plugin_enable_disable_t_tojson, 0xbf692144);
   vat2_register_function("nat44_ei_show_running_config", api_nat44_ei_show_running_config, (cJSON * (*)(void *))vl_api_nat44_ei_show_running_config_t_tojson, 0x51077d14);
   vat2_register_function("nat44_ei_set_log_level", api_nat44_ei_set_log_level, (cJSON * (*)(void *))vl_api_nat44_ei_set_log_level_t_tojson, 0x70076bfe);
   vat2_register_function("nat44_ei_set_workers", api_nat44_ei_set_workers, (cJSON * (*)(void *))vl_api_nat44_ei_set_workers_t_tojson, 0xda926638);
   vat2_register_function("nat44_ei_worker_dump", api_nat44_ei_worker_dump, (cJSON * (*)(void *))vl_api_nat44_ei_worker_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat44_ei_ipfix_enable_disable", api_nat44_ei_ipfix_enable_disable, (cJSON * (*)(void *))vl_api_nat44_ei_ipfix_enable_disable_t_tojson, 0x9af4a2d2);
   vat2_register_function("nat44_ei_set_timeouts", api_nat44_ei_set_timeouts, (cJSON * (*)(void *))vl_api_nat44_ei_set_timeouts_t_tojson, 0xd4746b16);
   vat2_register_function("nat44_ei_set_addr_and_port_alloc_alg", api_nat44_ei_set_addr_and_port_alloc_alg, (cJSON * (*)(void *))vl_api_nat44_ei_set_addr_and_port_alloc_alg_t_tojson, 0xdeeb746f);
   vat2_register_function("nat44_ei_get_addr_and_port_alloc_alg", api_nat44_ei_get_addr_and_port_alloc_alg, (cJSON * (*)(void *))vl_api_nat44_ei_get_addr_and_port_alloc_alg_t_tojson, 0x51077d14);
   vat2_register_function("nat44_ei_set_mss_clamping", api_nat44_ei_set_mss_clamping, (cJSON * (*)(void *))vl_api_nat44_ei_set_mss_clamping_t_tojson, 0x25e90abb);
   vat2_register_function("nat44_ei_get_mss_clamping", api_nat44_ei_get_mss_clamping, (cJSON * (*)(void *))vl_api_nat44_ei_get_mss_clamping_t_tojson, 0x51077d14);
   vat2_register_function("nat44_ei_ha_set_listener", api_nat44_ei_ha_set_listener, (cJSON * (*)(void *))vl_api_nat44_ei_ha_set_listener_t_tojson, 0xe4a8cb4e);
   vat2_register_function("nat44_ei_ha_set_failover", api_nat44_ei_ha_set_failover, (cJSON * (*)(void *))vl_api_nat44_ei_ha_set_failover_t_tojson, 0x718246af);
   vat2_register_function("nat44_ei_ha_get_listener", api_nat44_ei_ha_get_listener, (cJSON * (*)(void *))vl_api_nat44_ei_ha_get_listener_t_tojson, 0x51077d14);
   vat2_register_function("nat44_ei_ha_get_failover", api_nat44_ei_ha_get_failover, (cJSON * (*)(void *))vl_api_nat44_ei_ha_get_failover_t_tojson, 0x51077d14);
   vat2_register_function("nat44_ei_ha_flush", api_nat44_ei_ha_flush, (cJSON * (*)(void *))vl_api_nat44_ei_ha_flush_t_tojson, 0x51077d14);
   vat2_register_function("nat44_ei_del_user", api_nat44_ei_del_user, (cJSON * (*)(void *))vl_api_nat44_ei_del_user_t_tojson, 0x99a9f998);
   vat2_register_function("nat44_ei_add_del_address_range", api_nat44_ei_add_del_address_range, (cJSON * (*)(void *))vl_api_nat44_ei_add_del_address_range_t_tojson, 0x35f21abc);
   vat2_register_function("nat44_ei_address_dump", api_nat44_ei_address_dump, (cJSON * (*)(void *))vl_api_nat44_ei_address_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat44_ei_interface_add_del_feature", api_nat44_ei_interface_add_del_feature, (cJSON * (*)(void *))vl_api_nat44_ei_interface_add_del_feature_t_tojson, 0x63a2db8b);
   vat2_register_function("nat44_ei_interface_dump", api_nat44_ei_interface_dump, (cJSON * (*)(void *))vl_api_nat44_ei_interface_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat44_ei_interface_add_del_output_feature", api_nat44_ei_interface_add_del_output_feature, (cJSON * (*)(void *))vl_api_nat44_ei_interface_add_del_output_feature_t_tojson, 0x63a2db8b);
   vat2_register_function("nat44_ei_interface_output_feature_dump", api_nat44_ei_interface_output_feature_dump, (cJSON * (*)(void *))vl_api_nat44_ei_interface_output_feature_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat44_ei_add_del_output_interface", api_nat44_ei_add_del_output_interface, (cJSON * (*)(void *))vl_api_nat44_ei_add_del_output_interface_t_tojson, 0x47d6e753);
   vat2_register_function("nat44_ei_add_del_static_mapping", api_nat44_ei_add_del_static_mapping, (cJSON * (*)(void *))vl_api_nat44_ei_add_del_static_mapping_t_tojson, 0xb404b7fe);
   vat2_register_function("nat44_ei_static_mapping_dump", api_nat44_ei_static_mapping_dump, (cJSON * (*)(void *))vl_api_nat44_ei_static_mapping_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat44_ei_add_del_identity_mapping", api_nat44_ei_add_del_identity_mapping, (cJSON * (*)(void *))vl_api_nat44_ei_add_del_identity_mapping_t_tojson, 0xcb8606b9);
   vat2_register_function("nat44_ei_identity_mapping_dump", api_nat44_ei_identity_mapping_dump, (cJSON * (*)(void *))vl_api_nat44_ei_identity_mapping_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat44_ei_add_del_interface_addr", api_nat44_ei_add_del_interface_addr, (cJSON * (*)(void *))vl_api_nat44_ei_add_del_interface_addr_t_tojson, 0x883abbcc);
   vat2_register_function("nat44_ei_interface_addr_dump", api_nat44_ei_interface_addr_dump, (cJSON * (*)(void *))vl_api_nat44_ei_interface_addr_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat44_ei_user_dump", api_nat44_ei_user_dump, (cJSON * (*)(void *))vl_api_nat44_ei_user_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat44_ei_user_session_dump", api_nat44_ei_user_session_dump, (cJSON * (*)(void *))vl_api_nat44_ei_user_session_dump_t_tojson, 0xe1899c98);
   vat2_register_function("nat44_ei_user_session_v2_dump", api_nat44_ei_user_session_v2_dump, (cJSON * (*)(void *))vl_api_nat44_ei_user_session_v2_dump_t_tojson, 0xe1899c98);
   vat2_register_function("nat44_ei_del_session", api_nat44_ei_del_session, (cJSON * (*)(void *))vl_api_nat44_ei_del_session_t_tojson, 0x74969ffe);
   vat2_register_function("nat44_ei_forwarding_enable_disable", api_nat44_ei_forwarding_enable_disable, (cJSON * (*)(void *))vl_api_nat44_ei_forwarding_enable_disable_t_tojson, 0xb3e225d2);
   vat2_register_function("nat44_ei_set_fq_options", api_nat44_ei_set_fq_options, (cJSON * (*)(void *))vl_api_nat44_ei_set_fq_options_t_tojson, 0x2399bd71);
   vat2_register_function("nat44_ei_show_fq_options", api_nat44_ei_show_fq_options, (cJSON * (*)(void *))vl_api_nat44_ei_show_fq_options_t_tojson, 0x51077d14);
   return 0;
}
