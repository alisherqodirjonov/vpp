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

#include "nat44_ed.api_enum.h"
#include "nat44_ed.api_types.h"

#define vl_endianfun		/* define message structures */
#include "nat44_ed.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "nat44_ed.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "nat44_ed.api.h"
#undef vl_printfun

#include "nat44_ed.api_tojson.h"
#include "nat44_ed.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_nat44_ed_output_interface_get (cJSON *o)
{
    u16 msg_id = vac_get_msg_index(VL_API_NAT44_ED_OUTPUT_INTERFACE_GET_CRC);
  int len = 0;
  if (!o) return 0;
  vl_api_nat44_ed_output_interface_get_t *mp = vl_api_nat44_ed_output_interface_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }
  mp->_vl_msg_id = msg_id;

  vl_api_nat44_ed_output_interface_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  cJSON *reply = cJSON_CreateArray();

  u16 reply_msg_id = vac_get_msg_index(VL_API_NAT44_ED_OUTPUT_INTERFACE_GET_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_ED_OUTPUT_INTERFACE_DETAILS_CRC);

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
        vl_api_nat44_ed_output_interface_get_reply_t *rmp = (vl_api_nat44_ed_output_interface_get_reply_t *)p;
        vl_api_nat44_ed_output_interface_get_reply_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_ed_output_interface_get_reply_t_tojson(rmp));
        break;
    }

    if (msg_id == details_msg_id) {
        vl_api_nat44_ed_output_interface_details_t *rmp = (vl_api_nat44_ed_output_interface_details_t *)p;
        vl_api_nat44_ed_output_interface_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_ed_output_interface_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_ed_plugin_enable_disable (cJSON *o)
{
  vl_api_nat44_ed_plugin_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ed_plugin_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_ED_PLUGIN_ENABLE_DISABLE_CRC);
  vl_api_nat44_ed_plugin_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_ED_PLUGIN_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ed_plugin_enable_disable_reply_t *rmp = (vl_api_nat44_ed_plugin_enable_disable_reply_t *)p;
  vl_api_nat44_ed_plugin_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_nat44_ed_plugin_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_forwarding_enable_disable (cJSON *o)
{
  vl_api_nat44_forwarding_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_forwarding_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_FORWARDING_ENABLE_DISABLE_CRC);
  vl_api_nat44_forwarding_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_FORWARDING_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_forwarding_enable_disable_reply_t *rmp = (vl_api_nat44_forwarding_enable_disable_reply_t *)p;
  vl_api_nat44_forwarding_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_nat44_forwarding_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_nat_ipfix_enable_disable (cJSON *o)
{
  vl_api_nat_ipfix_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat_ipfix_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT_IPFIX_ENABLE_DISABLE_CRC);
  vl_api_nat_ipfix_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT_IPFIX_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat_ipfix_enable_disable_reply_t *rmp = (vl_api_nat_ipfix_enable_disable_reply_t *)p;
  vl_api_nat_ipfix_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_nat_ipfix_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_nat_set_timeouts (cJSON *o)
{
  vl_api_nat_set_timeouts_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat_set_timeouts_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT_SET_TIMEOUTS_CRC);
  vl_api_nat_set_timeouts_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT_SET_TIMEOUTS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat_set_timeouts_reply_t *rmp = (vl_api_nat_set_timeouts_reply_t *)p;
  vl_api_nat_set_timeouts_reply_t_endian(rmp, 0);
  return vl_api_nat_set_timeouts_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_set_session_limit (cJSON *o)
{
  vl_api_nat44_set_session_limit_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_set_session_limit_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_SET_SESSION_LIMIT_CRC);
  vl_api_nat44_set_session_limit_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_SET_SESSION_LIMIT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_set_session_limit_reply_t *rmp = (vl_api_nat44_set_session_limit_reply_t *)p;
  vl_api_nat44_set_session_limit_reply_t_endian(rmp, 0);
  return vl_api_nat44_set_session_limit_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_show_running_config (cJSON *o)
{
  vl_api_nat44_show_running_config_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_show_running_config_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_SHOW_RUNNING_CONFIG_CRC);
  vl_api_nat44_show_running_config_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_SHOW_RUNNING_CONFIG_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_show_running_config_reply_t *rmp = (vl_api_nat44_show_running_config_reply_t *)p;
  vl_api_nat44_show_running_config_reply_t_endian(rmp, 0);
  return vl_api_nat44_show_running_config_reply_t_tojson(rmp);
}

static cJSON *
api_nat_set_workers (cJSON *o)
{
  vl_api_nat_set_workers_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat_set_workers_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT_SET_WORKERS_CRC);
  vl_api_nat_set_workers_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT_SET_WORKERS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat_set_workers_reply_t *rmp = (vl_api_nat_set_workers_reply_t *)p;
  vl_api_nat_set_workers_reply_t_endian(rmp, 0);
  return vl_api_nat_set_workers_reply_t_tojson(rmp);
}

static cJSON *
api_nat_worker_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT_WORKER_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat_worker_dump_t *mp = vl_api_nat_worker_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat_worker_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT_WORKER_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat_worker_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat_worker_details_t *rmp = (vl_api_nat_worker_details_t *)p;
        vl_api_nat_worker_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat_worker_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_ed_add_del_vrf_table (cJSON *o)
{
  vl_api_nat44_ed_add_del_vrf_table_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ed_add_del_vrf_table_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_ED_ADD_DEL_VRF_TABLE_CRC);
  vl_api_nat44_ed_add_del_vrf_table_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_ED_ADD_DEL_VRF_TABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ed_add_del_vrf_table_reply_t *rmp = (vl_api_nat44_ed_add_del_vrf_table_reply_t *)p;
  vl_api_nat44_ed_add_del_vrf_table_reply_t_endian(rmp, 0);
  return vl_api_nat44_ed_add_del_vrf_table_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ed_add_del_vrf_route (cJSON *o)
{
  vl_api_nat44_ed_add_del_vrf_route_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ed_add_del_vrf_route_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_ED_ADD_DEL_VRF_ROUTE_CRC);
  vl_api_nat44_ed_add_del_vrf_route_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_ED_ADD_DEL_VRF_ROUTE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ed_add_del_vrf_route_reply_t *rmp = (vl_api_nat44_ed_add_del_vrf_route_reply_t *)p;
  vl_api_nat44_ed_add_del_vrf_route_reply_t_endian(rmp, 0);
  return vl_api_nat44_ed_add_del_vrf_route_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ed_vrf_tables_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_ED_VRF_TABLES_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_ed_vrf_tables_dump_t *mp = vl_api_nat44_ed_vrf_tables_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_ed_vrf_tables_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_ED_VRF_TABLES_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_ed_vrf_tables_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_ed_vrf_tables_details_t *rmp = (vl_api_nat44_ed_vrf_tables_details_t *)p;
        vl_api_nat44_ed_vrf_tables_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_ed_vrf_tables_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_ed_vrf_tables_v2_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_ED_VRF_TABLES_V2_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_ed_vrf_tables_v2_dump_t *mp = vl_api_nat44_ed_vrf_tables_v2_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_ed_vrf_tables_v2_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_ED_VRF_TABLES_V2_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_ed_vrf_tables_v2_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_ed_vrf_tables_v2_details_t *rmp = (vl_api_nat44_ed_vrf_tables_v2_details_t *)p;
        vl_api_nat44_ed_vrf_tables_v2_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_ed_vrf_tables_v2_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat_set_mss_clamping (cJSON *o)
{
  vl_api_nat_set_mss_clamping_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat_set_mss_clamping_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT_SET_MSS_CLAMPING_CRC);
  vl_api_nat_set_mss_clamping_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT_SET_MSS_CLAMPING_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat_set_mss_clamping_reply_t *rmp = (vl_api_nat_set_mss_clamping_reply_t *)p;
  vl_api_nat_set_mss_clamping_reply_t_endian(rmp, 0);
  return vl_api_nat_set_mss_clamping_reply_t_tojson(rmp);
}

static cJSON *
api_nat_get_mss_clamping (cJSON *o)
{
  vl_api_nat_get_mss_clamping_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat_get_mss_clamping_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT_GET_MSS_CLAMPING_CRC);
  vl_api_nat_get_mss_clamping_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT_GET_MSS_CLAMPING_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat_get_mss_clamping_reply_t *rmp = (vl_api_nat_get_mss_clamping_reply_t *)p;
  vl_api_nat_get_mss_clamping_reply_t_endian(rmp, 0);
  return vl_api_nat_get_mss_clamping_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ed_set_fq_options (cJSON *o)
{
  vl_api_nat44_ed_set_fq_options_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ed_set_fq_options_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_ED_SET_FQ_OPTIONS_CRC);
  vl_api_nat44_ed_set_fq_options_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_ED_SET_FQ_OPTIONS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ed_set_fq_options_reply_t *rmp = (vl_api_nat44_ed_set_fq_options_reply_t *)p;
  vl_api_nat44_ed_set_fq_options_reply_t_endian(rmp, 0);
  return vl_api_nat44_ed_set_fq_options_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_ed_show_fq_options (cJSON *o)
{
  vl_api_nat44_ed_show_fq_options_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ed_show_fq_options_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_ED_SHOW_FQ_OPTIONS_CRC);
  vl_api_nat44_ed_show_fq_options_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_ED_SHOW_FQ_OPTIONS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ed_show_fq_options_reply_t *rmp = (vl_api_nat44_ed_show_fq_options_reply_t *)p;
  vl_api_nat44_ed_show_fq_options_reply_t_endian(rmp, 0);
  return vl_api_nat44_ed_show_fq_options_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_add_del_interface_addr (cJSON *o)
{
  vl_api_nat44_add_del_interface_addr_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_add_del_interface_addr_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_ADD_DEL_INTERFACE_ADDR_CRC);
  vl_api_nat44_add_del_interface_addr_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_ADD_DEL_INTERFACE_ADDR_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_add_del_interface_addr_reply_t *rmp = (vl_api_nat44_add_del_interface_addr_reply_t *)p;
  vl_api_nat44_add_del_interface_addr_reply_t_endian(rmp, 0);
  return vl_api_nat44_add_del_interface_addr_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_interface_addr_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_INTERFACE_ADDR_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_interface_addr_dump_t *mp = vl_api_nat44_interface_addr_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_interface_addr_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_INTERFACE_ADDR_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_interface_addr_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_interface_addr_details_t *rmp = (vl_api_nat44_interface_addr_details_t *)p;
        vl_api_nat44_interface_addr_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_interface_addr_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_add_del_address_range (cJSON *o)
{
  vl_api_nat44_add_del_address_range_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_add_del_address_range_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_ADD_DEL_ADDRESS_RANGE_CRC);
  vl_api_nat44_add_del_address_range_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_ADD_DEL_ADDRESS_RANGE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_add_del_address_range_reply_t *rmp = (vl_api_nat44_add_del_address_range_reply_t *)p;
  vl_api_nat44_add_del_address_range_reply_t_endian(rmp, 0);
  return vl_api_nat44_add_del_address_range_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_address_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_ADDRESS_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_address_dump_t *mp = vl_api_nat44_address_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_address_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_ADDRESS_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_address_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_address_details_t *rmp = (vl_api_nat44_address_details_t *)p;
        vl_api_nat44_address_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_address_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_interface_add_del_feature (cJSON *o)
{
  vl_api_nat44_interface_add_del_feature_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_interface_add_del_feature_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_INTERFACE_ADD_DEL_FEATURE_CRC);
  vl_api_nat44_interface_add_del_feature_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_INTERFACE_ADD_DEL_FEATURE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_interface_add_del_feature_reply_t *rmp = (vl_api_nat44_interface_add_del_feature_reply_t *)p;
  vl_api_nat44_interface_add_del_feature_reply_t_endian(rmp, 0);
  return vl_api_nat44_interface_add_del_feature_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_interface_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_INTERFACE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_interface_dump_t *mp = vl_api_nat44_interface_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_interface_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_INTERFACE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_interface_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_interface_details_t *rmp = (vl_api_nat44_interface_details_t *)p;
        vl_api_nat44_interface_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_interface_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_ed_add_del_output_interface (cJSON *o)
{
  vl_api_nat44_ed_add_del_output_interface_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_ed_add_del_output_interface_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_ED_ADD_DEL_OUTPUT_INTERFACE_CRC);
  vl_api_nat44_ed_add_del_output_interface_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_ED_ADD_DEL_OUTPUT_INTERFACE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_ed_add_del_output_interface_reply_t *rmp = (vl_api_nat44_ed_add_del_output_interface_reply_t *)p;
  vl_api_nat44_ed_add_del_output_interface_reply_t_endian(rmp, 0);
  return vl_api_nat44_ed_add_del_output_interface_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_add_del_static_mapping (cJSON *o)
{
  vl_api_nat44_add_del_static_mapping_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_add_del_static_mapping_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_ADD_DEL_STATIC_MAPPING_CRC);
  vl_api_nat44_add_del_static_mapping_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_ADD_DEL_STATIC_MAPPING_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_add_del_static_mapping_reply_t *rmp = (vl_api_nat44_add_del_static_mapping_reply_t *)p;
  vl_api_nat44_add_del_static_mapping_reply_t_endian(rmp, 0);
  return vl_api_nat44_add_del_static_mapping_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_add_del_static_mapping_v2 (cJSON *o)
{
  vl_api_nat44_add_del_static_mapping_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_add_del_static_mapping_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_ADD_DEL_STATIC_MAPPING_V2_CRC);
  vl_api_nat44_add_del_static_mapping_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_ADD_DEL_STATIC_MAPPING_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_add_del_static_mapping_v2_reply_t *rmp = (vl_api_nat44_add_del_static_mapping_v2_reply_t *)p;
  vl_api_nat44_add_del_static_mapping_v2_reply_t_endian(rmp, 0);
  return vl_api_nat44_add_del_static_mapping_v2_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_static_mapping_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_STATIC_MAPPING_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_static_mapping_dump_t *mp = vl_api_nat44_static_mapping_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_static_mapping_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_STATIC_MAPPING_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_static_mapping_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_static_mapping_details_t *rmp = (vl_api_nat44_static_mapping_details_t *)p;
        vl_api_nat44_static_mapping_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_static_mapping_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_add_del_identity_mapping (cJSON *o)
{
  vl_api_nat44_add_del_identity_mapping_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_add_del_identity_mapping_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_ADD_DEL_IDENTITY_MAPPING_CRC);
  vl_api_nat44_add_del_identity_mapping_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_ADD_DEL_IDENTITY_MAPPING_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_add_del_identity_mapping_reply_t *rmp = (vl_api_nat44_add_del_identity_mapping_reply_t *)p;
  vl_api_nat44_add_del_identity_mapping_reply_t_endian(rmp, 0);
  return vl_api_nat44_add_del_identity_mapping_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_identity_mapping_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_IDENTITY_MAPPING_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_identity_mapping_dump_t *mp = vl_api_nat44_identity_mapping_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_identity_mapping_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_IDENTITY_MAPPING_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_identity_mapping_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_identity_mapping_details_t *rmp = (vl_api_nat44_identity_mapping_details_t *)p;
        vl_api_nat44_identity_mapping_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_identity_mapping_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_add_del_lb_static_mapping (cJSON *o)
{
  vl_api_nat44_add_del_lb_static_mapping_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_add_del_lb_static_mapping_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_ADD_DEL_LB_STATIC_MAPPING_CRC);
  vl_api_nat44_add_del_lb_static_mapping_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_ADD_DEL_LB_STATIC_MAPPING_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_add_del_lb_static_mapping_reply_t *rmp = (vl_api_nat44_add_del_lb_static_mapping_reply_t *)p;
  vl_api_nat44_add_del_lb_static_mapping_reply_t_endian(rmp, 0);
  return vl_api_nat44_add_del_lb_static_mapping_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_lb_static_mapping_add_del_local (cJSON *o)
{
  vl_api_nat44_lb_static_mapping_add_del_local_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_lb_static_mapping_add_del_local_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_LB_STATIC_MAPPING_ADD_DEL_LOCAL_CRC);
  vl_api_nat44_lb_static_mapping_add_del_local_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_LB_STATIC_MAPPING_ADD_DEL_LOCAL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_lb_static_mapping_add_del_local_reply_t *rmp = (vl_api_nat44_lb_static_mapping_add_del_local_reply_t *)p;
  vl_api_nat44_lb_static_mapping_add_del_local_reply_t_endian(rmp, 0);
  return vl_api_nat44_lb_static_mapping_add_del_local_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_lb_static_mapping_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_LB_STATIC_MAPPING_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_lb_static_mapping_dump_t *mp = vl_api_nat44_lb_static_mapping_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_lb_static_mapping_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_LB_STATIC_MAPPING_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_lb_static_mapping_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_lb_static_mapping_details_t *rmp = (vl_api_nat44_lb_static_mapping_details_t *)p;
        vl_api_nat44_lb_static_mapping_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_lb_static_mapping_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_del_session (cJSON *o)
{
  vl_api_nat44_del_session_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat44_del_session_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT44_DEL_SESSION_CRC);
  vl_api_nat44_del_session_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT44_DEL_SESSION_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat44_del_session_reply_t *rmp = (vl_api_nat44_del_session_reply_t *)p;
  vl_api_nat44_del_session_reply_t_endian(rmp, 0);
  return vl_api_nat44_del_session_reply_t_tojson(rmp);
}

static cJSON *
api_nat44_user_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_USER_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_user_dump_t *mp = vl_api_nat44_user_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_user_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_USER_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_user_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_user_details_t *rmp = (vl_api_nat44_user_details_t *)p;
        vl_api_nat44_user_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_user_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_user_session_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_USER_SESSION_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_user_session_dump_t *mp = vl_api_nat44_user_session_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_user_session_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_USER_SESSION_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_user_session_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_user_session_details_t *rmp = (vl_api_nat44_user_session_details_t *)p;
        vl_api_nat44_user_session_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_user_session_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_user_session_v2_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_USER_SESSION_V2_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_user_session_v2_dump_t *mp = vl_api_nat44_user_session_v2_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_user_session_v2_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_USER_SESSION_V2_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_user_session_v2_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_user_session_v2_details_t *rmp = (vl_api_nat44_user_session_v2_details_t *)p;
        vl_api_nat44_user_session_v2_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_user_session_v2_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat44_user_session_v3_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT44_USER_SESSION_V3_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat44_user_session_v3_dump_t *mp = vl_api_nat44_user_session_v3_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat44_user_session_v3_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT44_USER_SESSION_V3_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat44_user_session_v3_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat44_user_session_v3_details_t *rmp = (vl_api_nat44_user_session_v3_details_t *)p;
        vl_api_nat44_user_session_v3_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat44_user_session_v3_details_t_tojson(rmp));
    }
  }
  return reply;
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("nat44_ed_output_interface_get", api_nat44_ed_output_interface_get, (cJSON * (*)(void *))vl_api_nat44_ed_output_interface_get_t_tojson, 0xf75ba505);
   vat2_register_function("nat44_ed_plugin_enable_disable", api_nat44_ed_plugin_enable_disable, (cJSON * (*)(void *))vl_api_nat44_ed_plugin_enable_disable_t_tojson, 0xbe17f8dd);
   vat2_register_function("nat44_forwarding_enable_disable", api_nat44_forwarding_enable_disable, (cJSON * (*)(void *))vl_api_nat44_forwarding_enable_disable_t_tojson, 0xb3e225d2);
   vat2_register_function("nat_ipfix_enable_disable", api_nat_ipfix_enable_disable, (cJSON * (*)(void *))vl_api_nat_ipfix_enable_disable_t_tojson, 0x9af4a2d2);
   vat2_register_function("nat_set_timeouts", api_nat_set_timeouts, (cJSON * (*)(void *))vl_api_nat_set_timeouts_t_tojson, 0xd4746b16);
   vat2_register_function("nat44_set_session_limit", api_nat44_set_session_limit, (cJSON * (*)(void *))vl_api_nat44_set_session_limit_t_tojson, 0x8899bbb1);
   vat2_register_function("nat44_show_running_config", api_nat44_show_running_config, (cJSON * (*)(void *))vl_api_nat44_show_running_config_t_tojson, 0x51077d14);
   vat2_register_function("nat_set_workers", api_nat_set_workers, (cJSON * (*)(void *))vl_api_nat_set_workers_t_tojson, 0xda926638);
   vat2_register_function("nat_worker_dump", api_nat_worker_dump, (cJSON * (*)(void *))vl_api_nat_worker_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat44_ed_add_del_vrf_table", api_nat44_ed_add_del_vrf_table, (cJSON * (*)(void *))vl_api_nat44_ed_add_del_vrf_table_t_tojson, 0x08330904);
   vat2_register_function("nat44_ed_add_del_vrf_route", api_nat44_ed_add_del_vrf_route, (cJSON * (*)(void *))vl_api_nat44_ed_add_del_vrf_route_t_tojson, 0x59187407);
   vat2_register_function("nat44_ed_vrf_tables_dump", api_nat44_ed_vrf_tables_dump, (cJSON * (*)(void *))vl_api_nat44_ed_vrf_tables_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat44_ed_vrf_tables_v2_dump", api_nat44_ed_vrf_tables_v2_dump, (cJSON * (*)(void *))vl_api_nat44_ed_vrf_tables_v2_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat_set_mss_clamping", api_nat_set_mss_clamping, (cJSON * (*)(void *))vl_api_nat_set_mss_clamping_t_tojson, 0x25e90abb);
   vat2_register_function("nat_get_mss_clamping", api_nat_get_mss_clamping, (cJSON * (*)(void *))vl_api_nat_get_mss_clamping_t_tojson, 0x51077d14);
   vat2_register_function("nat44_ed_set_fq_options", api_nat44_ed_set_fq_options, (cJSON * (*)(void *))vl_api_nat44_ed_set_fq_options_t_tojson, 0x2399bd71);
   vat2_register_function("nat44_ed_show_fq_options", api_nat44_ed_show_fq_options, (cJSON * (*)(void *))vl_api_nat44_ed_show_fq_options_t_tojson, 0x51077d14);
   vat2_register_function("nat44_add_del_interface_addr", api_nat44_add_del_interface_addr, (cJSON * (*)(void *))vl_api_nat44_add_del_interface_addr_t_tojson, 0x4aed50c0);
   vat2_register_function("nat44_interface_addr_dump", api_nat44_interface_addr_dump, (cJSON * (*)(void *))vl_api_nat44_interface_addr_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat44_add_del_address_range", api_nat44_add_del_address_range, (cJSON * (*)(void *))vl_api_nat44_add_del_address_range_t_tojson, 0x6f2b8055);
   vat2_register_function("nat44_address_dump", api_nat44_address_dump, (cJSON * (*)(void *))vl_api_nat44_address_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat44_interface_add_del_feature", api_nat44_interface_add_del_feature, (cJSON * (*)(void *))vl_api_nat44_interface_add_del_feature_t_tojson, 0xf3699b83);
   vat2_register_function("nat44_interface_dump", api_nat44_interface_dump, (cJSON * (*)(void *))vl_api_nat44_interface_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat44_ed_add_del_output_interface", api_nat44_ed_add_del_output_interface, (cJSON * (*)(void *))vl_api_nat44_ed_add_del_output_interface_t_tojson, 0x47d6e753);
   vat2_register_function("nat44_add_del_static_mapping", api_nat44_add_del_static_mapping, (cJSON * (*)(void *))vl_api_nat44_add_del_static_mapping_t_tojson, 0x5ae5f03e);
   vat2_register_function("nat44_add_del_static_mapping_v2", api_nat44_add_del_static_mapping_v2, (cJSON * (*)(void *))vl_api_nat44_add_del_static_mapping_v2_t_tojson, 0x5e205f1a);
   vat2_register_function("nat44_static_mapping_dump", api_nat44_static_mapping_dump, (cJSON * (*)(void *))vl_api_nat44_static_mapping_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat44_add_del_identity_mapping", api_nat44_add_del_identity_mapping, (cJSON * (*)(void *))vl_api_nat44_add_del_identity_mapping_t_tojson, 0x02faaa22);
   vat2_register_function("nat44_identity_mapping_dump", api_nat44_identity_mapping_dump, (cJSON * (*)(void *))vl_api_nat44_identity_mapping_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat44_add_del_lb_static_mapping", api_nat44_add_del_lb_static_mapping, (cJSON * (*)(void *))vl_api_nat44_add_del_lb_static_mapping_t_tojson, 0x4f68ee9d);
   vat2_register_function("nat44_lb_static_mapping_add_del_local", api_nat44_lb_static_mapping_add_del_local, (cJSON * (*)(void *))vl_api_nat44_lb_static_mapping_add_del_local_t_tojson, 0x7ca47547);
   vat2_register_function("nat44_lb_static_mapping_dump", api_nat44_lb_static_mapping_dump, (cJSON * (*)(void *))vl_api_nat44_lb_static_mapping_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat44_del_session", api_nat44_del_session, (cJSON * (*)(void *))vl_api_nat44_del_session_t_tojson, 0x15a5bf8c);
   vat2_register_function("nat44_user_dump", api_nat44_user_dump, (cJSON * (*)(void *))vl_api_nat44_user_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat44_user_session_dump", api_nat44_user_session_dump, (cJSON * (*)(void *))vl_api_nat44_user_session_dump_t_tojson, 0xe1899c98);
   vat2_register_function("nat44_user_session_v2_dump", api_nat44_user_session_v2_dump, (cJSON * (*)(void *))vl_api_nat44_user_session_v2_dump_t_tojson, 0xe1899c98);
   vat2_register_function("nat44_user_session_v3_dump", api_nat44_user_session_v3_dump, (cJSON * (*)(void *))vl_api_nat44_user_session_v3_dump_t_tojson, 0xe1899c98);
   return 0;
}
