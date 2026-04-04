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

#include "l2.api_enum.h"
#include "l2.api_types.h"

#define vl_endianfun		/* define message structures */
#include "l2.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "l2.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "l2.api.h"
#undef vl_printfun

#include "l2.api_tojson.h"
#include "l2.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_want_l2_macs_events (cJSON *o)
{
  vl_api_want_l2_macs_events_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_want_l2_macs_events_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_WANT_L2_MACS_EVENTS_CRC);
  vl_api_want_l2_macs_events_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_WANT_L2_MACS_EVENTS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_want_l2_macs_events_reply_t *rmp = (vl_api_want_l2_macs_events_reply_t *)p;
  vl_api_want_l2_macs_events_reply_t_endian(rmp, 0);
  return vl_api_want_l2_macs_events_reply_t_tojson(rmp);
}

static cJSON *
api_want_l2_arp_term_events (cJSON *o)
{
  vl_api_want_l2_arp_term_events_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_want_l2_arp_term_events_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_WANT_L2_ARP_TERM_EVENTS_CRC);
  vl_api_want_l2_arp_term_events_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_WANT_L2_ARP_TERM_EVENTS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_want_l2_arp_term_events_reply_t *rmp = (vl_api_want_l2_arp_term_events_reply_t *)p;
  vl_api_want_l2_arp_term_events_reply_t_endian(rmp, 0);
  return vl_api_want_l2_arp_term_events_reply_t_tojson(rmp);
}

static cJSON *
api_l2_xconnect_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_L2_XCONNECT_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_l2_xconnect_dump_t *mp = vl_api_l2_xconnect_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_l2_xconnect_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_L2_XCONNECT_DETAILS_CRC);

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
        if (l < sizeof(vl_api_l2_xconnect_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_l2_xconnect_details_t *rmp = (vl_api_l2_xconnect_details_t *)p;
        vl_api_l2_xconnect_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_l2_xconnect_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_l2_fib_table_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_L2_FIB_TABLE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_l2_fib_table_dump_t *mp = vl_api_l2_fib_table_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_l2_fib_table_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_L2_FIB_TABLE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_l2_fib_table_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_l2_fib_table_details_t *rmp = (vl_api_l2_fib_table_details_t *)p;
        vl_api_l2_fib_table_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_l2_fib_table_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_l2_fib_clear_table (cJSON *o)
{
  vl_api_l2_fib_clear_table_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_l2_fib_clear_table_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_L2_FIB_CLEAR_TABLE_CRC);
  vl_api_l2_fib_clear_table_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_L2_FIB_CLEAR_TABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_l2_fib_clear_table_reply_t *rmp = (vl_api_l2_fib_clear_table_reply_t *)p;
  vl_api_l2_fib_clear_table_reply_t_endian(rmp, 0);
  return vl_api_l2_fib_clear_table_reply_t_tojson(rmp);
}

static cJSON *
api_l2fib_flush_all (cJSON *o)
{
  vl_api_l2fib_flush_all_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_l2fib_flush_all_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_L2FIB_FLUSH_ALL_CRC);
  vl_api_l2fib_flush_all_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_L2FIB_FLUSH_ALL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_l2fib_flush_all_reply_t *rmp = (vl_api_l2fib_flush_all_reply_t *)p;
  vl_api_l2fib_flush_all_reply_t_endian(rmp, 0);
  return vl_api_l2fib_flush_all_reply_t_tojson(rmp);
}

static cJSON *
api_l2fib_flush_bd (cJSON *o)
{
  vl_api_l2fib_flush_bd_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_l2fib_flush_bd_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_L2FIB_FLUSH_BD_CRC);
  vl_api_l2fib_flush_bd_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_L2FIB_FLUSH_BD_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_l2fib_flush_bd_reply_t *rmp = (vl_api_l2fib_flush_bd_reply_t *)p;
  vl_api_l2fib_flush_bd_reply_t_endian(rmp, 0);
  return vl_api_l2fib_flush_bd_reply_t_tojson(rmp);
}

static cJSON *
api_l2fib_flush_int (cJSON *o)
{
  vl_api_l2fib_flush_int_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_l2fib_flush_int_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_L2FIB_FLUSH_INT_CRC);
  vl_api_l2fib_flush_int_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_L2FIB_FLUSH_INT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_l2fib_flush_int_reply_t *rmp = (vl_api_l2fib_flush_int_reply_t *)p;
  vl_api_l2fib_flush_int_reply_t_endian(rmp, 0);
  return vl_api_l2fib_flush_int_reply_t_tojson(rmp);
}

static cJSON *
api_l2fib_add_del (cJSON *o)
{
  vl_api_l2fib_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_l2fib_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_L2FIB_ADD_DEL_CRC);
  vl_api_l2fib_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_L2FIB_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_l2fib_add_del_reply_t *rmp = (vl_api_l2fib_add_del_reply_t *)p;
  vl_api_l2fib_add_del_reply_t_endian(rmp, 0);
  return vl_api_l2fib_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_want_l2_macs_events2 (cJSON *o)
{
  vl_api_want_l2_macs_events2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_want_l2_macs_events2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_WANT_L2_MACS_EVENTS2_CRC);
  vl_api_want_l2_macs_events2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_WANT_L2_MACS_EVENTS2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_want_l2_macs_events2_reply_t *rmp = (vl_api_want_l2_macs_events2_reply_t *)p;
  vl_api_want_l2_macs_events2_reply_t_endian(rmp, 0);
  return vl_api_want_l2_macs_events2_reply_t_tojson(rmp);
}

static cJSON *
api_l2fib_set_scan_delay (cJSON *o)
{
  vl_api_l2fib_set_scan_delay_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_l2fib_set_scan_delay_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_L2FIB_SET_SCAN_DELAY_CRC);
  vl_api_l2fib_set_scan_delay_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_L2FIB_SET_SCAN_DELAY_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_l2fib_set_scan_delay_reply_t *rmp = (vl_api_l2fib_set_scan_delay_reply_t *)p;
  vl_api_l2fib_set_scan_delay_reply_t_endian(rmp, 0);
  return vl_api_l2fib_set_scan_delay_reply_t_tojson(rmp);
}

static cJSON *
api_l2_flags (cJSON *o)
{
  vl_api_l2_flags_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_l2_flags_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_L2_FLAGS_CRC);
  vl_api_l2_flags_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_L2_FLAGS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_l2_flags_reply_t *rmp = (vl_api_l2_flags_reply_t *)p;
  vl_api_l2_flags_reply_t_endian(rmp, 0);
  return vl_api_l2_flags_reply_t_tojson(rmp);
}

static cJSON *
api_bridge_domain_set_mac_age (cJSON *o)
{
  vl_api_bridge_domain_set_mac_age_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bridge_domain_set_mac_age_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BRIDGE_DOMAIN_SET_MAC_AGE_CRC);
  vl_api_bridge_domain_set_mac_age_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BRIDGE_DOMAIN_SET_MAC_AGE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bridge_domain_set_mac_age_reply_t *rmp = (vl_api_bridge_domain_set_mac_age_reply_t *)p;
  vl_api_bridge_domain_set_mac_age_reply_t_endian(rmp, 0);
  return vl_api_bridge_domain_set_mac_age_reply_t_tojson(rmp);
}

static cJSON *
api_bridge_domain_set_default_learn_limit (cJSON *o)
{
  vl_api_bridge_domain_set_default_learn_limit_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bridge_domain_set_default_learn_limit_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BRIDGE_DOMAIN_SET_DEFAULT_LEARN_LIMIT_CRC);
  vl_api_bridge_domain_set_default_learn_limit_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BRIDGE_DOMAIN_SET_DEFAULT_LEARN_LIMIT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bridge_domain_set_default_learn_limit_reply_t *rmp = (vl_api_bridge_domain_set_default_learn_limit_reply_t *)p;
  vl_api_bridge_domain_set_default_learn_limit_reply_t_endian(rmp, 0);
  return vl_api_bridge_domain_set_default_learn_limit_reply_t_tojson(rmp);
}

static cJSON *
api_bridge_domain_set_learn_limit (cJSON *o)
{
  vl_api_bridge_domain_set_learn_limit_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bridge_domain_set_learn_limit_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BRIDGE_DOMAIN_SET_LEARN_LIMIT_CRC);
  vl_api_bridge_domain_set_learn_limit_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BRIDGE_DOMAIN_SET_LEARN_LIMIT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bridge_domain_set_learn_limit_reply_t *rmp = (vl_api_bridge_domain_set_learn_limit_reply_t *)p;
  vl_api_bridge_domain_set_learn_limit_reply_t_endian(rmp, 0);
  return vl_api_bridge_domain_set_learn_limit_reply_t_tojson(rmp);
}

static cJSON *
api_bridge_domain_add_del (cJSON *o)
{
  vl_api_bridge_domain_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bridge_domain_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BRIDGE_DOMAIN_ADD_DEL_CRC);
  vl_api_bridge_domain_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BRIDGE_DOMAIN_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bridge_domain_add_del_reply_t *rmp = (vl_api_bridge_domain_add_del_reply_t *)p;
  vl_api_bridge_domain_add_del_reply_t_endian(rmp, 0);
  return vl_api_bridge_domain_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_bridge_domain_add_del_v2 (cJSON *o)
{
  vl_api_bridge_domain_add_del_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bridge_domain_add_del_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BRIDGE_DOMAIN_ADD_DEL_V2_CRC);
  vl_api_bridge_domain_add_del_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BRIDGE_DOMAIN_ADD_DEL_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bridge_domain_add_del_v2_reply_t *rmp = (vl_api_bridge_domain_add_del_v2_reply_t *)p;
  vl_api_bridge_domain_add_del_v2_reply_t_endian(rmp, 0);
  return vl_api_bridge_domain_add_del_v2_reply_t_tojson(rmp);
}

static cJSON *
api_bridge_domain_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_BRIDGE_DOMAIN_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_bridge_domain_dump_t *mp = vl_api_bridge_domain_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_bridge_domain_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_BRIDGE_DOMAIN_DETAILS_CRC);

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
        if (l < sizeof(vl_api_bridge_domain_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_bridge_domain_details_t *rmp = (vl_api_bridge_domain_details_t *)p;
        vl_api_bridge_domain_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_bridge_domain_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_bridge_flags (cJSON *o)
{
  vl_api_bridge_flags_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bridge_flags_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BRIDGE_FLAGS_CRC);
  vl_api_bridge_flags_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BRIDGE_FLAGS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bridge_flags_reply_t *rmp = (vl_api_bridge_flags_reply_t *)p;
  vl_api_bridge_flags_reply_t_endian(rmp, 0);
  return vl_api_bridge_flags_reply_t_tojson(rmp);
}

static cJSON *
api_l2_interface_vlan_tag_rewrite (cJSON *o)
{
  vl_api_l2_interface_vlan_tag_rewrite_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_l2_interface_vlan_tag_rewrite_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_L2_INTERFACE_VLAN_TAG_REWRITE_CRC);
  vl_api_l2_interface_vlan_tag_rewrite_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_L2_INTERFACE_VLAN_TAG_REWRITE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_l2_interface_vlan_tag_rewrite_reply_t *rmp = (vl_api_l2_interface_vlan_tag_rewrite_reply_t *)p;
  vl_api_l2_interface_vlan_tag_rewrite_reply_t_endian(rmp, 0);
  return vl_api_l2_interface_vlan_tag_rewrite_reply_t_tojson(rmp);
}

static cJSON *
api_l2_interface_pbb_tag_rewrite (cJSON *o)
{
  vl_api_l2_interface_pbb_tag_rewrite_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_l2_interface_pbb_tag_rewrite_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_L2_INTERFACE_PBB_TAG_REWRITE_CRC);
  vl_api_l2_interface_pbb_tag_rewrite_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_L2_INTERFACE_PBB_TAG_REWRITE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_l2_interface_pbb_tag_rewrite_reply_t *rmp = (vl_api_l2_interface_pbb_tag_rewrite_reply_t *)p;
  vl_api_l2_interface_pbb_tag_rewrite_reply_t_endian(rmp, 0);
  return vl_api_l2_interface_pbb_tag_rewrite_reply_t_tojson(rmp);
}

static cJSON *
api_l2_patch_add_del (cJSON *o)
{
  vl_api_l2_patch_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_l2_patch_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_L2_PATCH_ADD_DEL_CRC);
  vl_api_l2_patch_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_L2_PATCH_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_l2_patch_add_del_reply_t *rmp = (vl_api_l2_patch_add_del_reply_t *)p;
  vl_api_l2_patch_add_del_reply_t_endian(rmp, 0);
  return vl_api_l2_patch_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_set_l2_xconnect (cJSON *o)
{
  vl_api_sw_interface_set_l2_xconnect_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_set_l2_xconnect_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_L2_XCONNECT_CRC);
  vl_api_sw_interface_set_l2_xconnect_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_SET_L2_XCONNECT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_set_l2_xconnect_reply_t *rmp = (vl_api_sw_interface_set_l2_xconnect_reply_t *)p;
  vl_api_sw_interface_set_l2_xconnect_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_set_l2_xconnect_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_set_l2_bridge (cJSON *o)
{
  vl_api_sw_interface_set_l2_bridge_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_set_l2_bridge_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_L2_BRIDGE_CRC);
  vl_api_sw_interface_set_l2_bridge_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_SET_L2_BRIDGE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_set_l2_bridge_reply_t *rmp = (vl_api_sw_interface_set_l2_bridge_reply_t *)p;
  vl_api_sw_interface_set_l2_bridge_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_set_l2_bridge_reply_t_tojson(rmp);
}

static cJSON *
api_bd_ip_mac_add_del (cJSON *o)
{
  vl_api_bd_ip_mac_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bd_ip_mac_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BD_IP_MAC_ADD_DEL_CRC);
  vl_api_bd_ip_mac_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BD_IP_MAC_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bd_ip_mac_add_del_reply_t *rmp = (vl_api_bd_ip_mac_add_del_reply_t *)p;
  vl_api_bd_ip_mac_add_del_reply_t_endian(rmp, 0);
  return vl_api_bd_ip_mac_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_bd_ip_mac_flush (cJSON *o)
{
  vl_api_bd_ip_mac_flush_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bd_ip_mac_flush_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BD_IP_MAC_FLUSH_CRC);
  vl_api_bd_ip_mac_flush_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BD_IP_MAC_FLUSH_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bd_ip_mac_flush_reply_t *rmp = (vl_api_bd_ip_mac_flush_reply_t *)p;
  vl_api_bd_ip_mac_flush_reply_t_endian(rmp, 0);
  return vl_api_bd_ip_mac_flush_reply_t_tojson(rmp);
}

static cJSON *
api_bd_ip_mac_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_BD_IP_MAC_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_bd_ip_mac_dump_t *mp = vl_api_bd_ip_mac_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_bd_ip_mac_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_BD_IP_MAC_DETAILS_CRC);

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
        if (l < sizeof(vl_api_bd_ip_mac_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_bd_ip_mac_details_t *rmp = (vl_api_bd_ip_mac_details_t *)p;
        vl_api_bd_ip_mac_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_bd_ip_mac_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_l2_interface_efp_filter (cJSON *o)
{
  vl_api_l2_interface_efp_filter_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_l2_interface_efp_filter_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_L2_INTERFACE_EFP_FILTER_CRC);
  vl_api_l2_interface_efp_filter_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_L2_INTERFACE_EFP_FILTER_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_l2_interface_efp_filter_reply_t *rmp = (vl_api_l2_interface_efp_filter_reply_t *)p;
  vl_api_l2_interface_efp_filter_reply_t_endian(rmp, 0);
  return vl_api_l2_interface_efp_filter_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_set_vpath (cJSON *o)
{
  vl_api_sw_interface_set_vpath_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_set_vpath_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_VPATH_CRC);
  vl_api_sw_interface_set_vpath_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_SET_VPATH_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_set_vpath_reply_t *rmp = (vl_api_sw_interface_set_vpath_reply_t *)p;
  vl_api_sw_interface_set_vpath_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_set_vpath_reply_t_tojson(rmp);
}

static cJSON *
api_bvi_create (cJSON *o)
{
  vl_api_bvi_create_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bvi_create_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BVI_CREATE_CRC);
  vl_api_bvi_create_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BVI_CREATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bvi_create_reply_t *rmp = (vl_api_bvi_create_reply_t *)p;
  vl_api_bvi_create_reply_t_endian(rmp, 0);
  return vl_api_bvi_create_reply_t_tojson(rmp);
}

static cJSON *
api_bvi_delete (cJSON *o)
{
  vl_api_bvi_delete_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bvi_delete_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BVI_DELETE_CRC);
  vl_api_bvi_delete_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BVI_DELETE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bvi_delete_reply_t *rmp = (vl_api_bvi_delete_reply_t *)p;
  vl_api_bvi_delete_reply_t_endian(rmp, 0);
  return vl_api_bvi_delete_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("want_l2_macs_events", api_want_l2_macs_events, (cJSON * (*)(void *))vl_api_want_l2_macs_events_t_tojson, 0x9aabdfde);
   vat2_register_function("want_l2_arp_term_events", api_want_l2_arp_term_events, (cJSON * (*)(void *))vl_api_want_l2_arp_term_events_t_tojson, 0x3ec6d6c2);
   vat2_register_function("l2_xconnect_dump", api_l2_xconnect_dump, (cJSON * (*)(void *))vl_api_l2_xconnect_dump_t_tojson, 0x51077d14);
   vat2_register_function("l2_fib_table_dump", api_l2_fib_table_dump, (cJSON * (*)(void *))vl_api_l2_fib_table_dump_t_tojson, 0xc25fdce6);
   vat2_register_function("l2_fib_clear_table", api_l2_fib_clear_table, (cJSON * (*)(void *))vl_api_l2_fib_clear_table_t_tojson, 0x51077d14);
   vat2_register_function("l2fib_flush_all", api_l2fib_flush_all, (cJSON * (*)(void *))vl_api_l2fib_flush_all_t_tojson, 0x51077d14);
   vat2_register_function("l2fib_flush_bd", api_l2fib_flush_bd, (cJSON * (*)(void *))vl_api_l2fib_flush_bd_t_tojson, 0xc25fdce6);
   vat2_register_function("l2fib_flush_int", api_l2fib_flush_int, (cJSON * (*)(void *))vl_api_l2fib_flush_int_t_tojson, 0xf9e6675e);
   vat2_register_function("l2fib_add_del", api_l2fib_add_del, (cJSON * (*)(void *))vl_api_l2fib_add_del_t_tojson, 0xeddda487);
   vat2_register_function("want_l2_macs_events2", api_want_l2_macs_events2, (cJSON * (*)(void *))vl_api_want_l2_macs_events2_t_tojson, 0xcc1377b0);
   vat2_register_function("l2fib_set_scan_delay", api_l2fib_set_scan_delay, (cJSON * (*)(void *))vl_api_l2fib_set_scan_delay_t_tojson, 0xa3b968a4);
   vat2_register_function("l2_flags", api_l2_flags, (cJSON * (*)(void *))vl_api_l2_flags_t_tojson, 0xfc41cfe8);
   vat2_register_function("bridge_domain_set_mac_age", api_bridge_domain_set_mac_age, (cJSON * (*)(void *))vl_api_bridge_domain_set_mac_age_t_tojson, 0xb537ad7b);
   vat2_register_function("bridge_domain_set_default_learn_limit", api_bridge_domain_set_default_learn_limit, (cJSON * (*)(void *))vl_api_bridge_domain_set_default_learn_limit_t_tojson, 0xf097ffce);
   vat2_register_function("bridge_domain_set_learn_limit", api_bridge_domain_set_learn_limit, (cJSON * (*)(void *))vl_api_bridge_domain_set_learn_limit_t_tojson, 0x89c52b5f);
   vat2_register_function("bridge_domain_add_del", api_bridge_domain_add_del, (cJSON * (*)(void *))vl_api_bridge_domain_add_del_t_tojson, 0x600b7170);
   vat2_register_function("bridge_domain_add_del_v2", api_bridge_domain_add_del_v2, (cJSON * (*)(void *))vl_api_bridge_domain_add_del_v2_t_tojson, 0x600b7170);
   vat2_register_function("bridge_domain_dump", api_bridge_domain_dump, (cJSON * (*)(void *))vl_api_bridge_domain_dump_t_tojson, 0x74396a43);
   vat2_register_function("bridge_flags", api_bridge_flags, (cJSON * (*)(void *))vl_api_bridge_flags_t_tojson, 0x1b0c5fbd);
   vat2_register_function("l2_interface_vlan_tag_rewrite", api_l2_interface_vlan_tag_rewrite, (cJSON * (*)(void *))vl_api_l2_interface_vlan_tag_rewrite_t_tojson, 0x62cc0bbc);
   vat2_register_function("l2_interface_pbb_tag_rewrite", api_l2_interface_pbb_tag_rewrite, (cJSON * (*)(void *))vl_api_l2_interface_pbb_tag_rewrite_t_tojson, 0x38e802a8);
   vat2_register_function("l2_patch_add_del", api_l2_patch_add_del, (cJSON * (*)(void *))vl_api_l2_patch_add_del_t_tojson, 0xa1f6a6f3);
   vat2_register_function("sw_interface_set_l2_xconnect", api_sw_interface_set_l2_xconnect, (cJSON * (*)(void *))vl_api_sw_interface_set_l2_xconnect_t_tojson, 0x4fa28a85);
   vat2_register_function("sw_interface_set_l2_bridge", api_sw_interface_set_l2_bridge, (cJSON * (*)(void *))vl_api_sw_interface_set_l2_bridge_t_tojson, 0xd0678b13);
   vat2_register_function("bd_ip_mac_add_del", api_bd_ip_mac_add_del, (cJSON * (*)(void *))vl_api_bd_ip_mac_add_del_t_tojson, 0x0257c869);
   vat2_register_function("bd_ip_mac_flush", api_bd_ip_mac_flush, (cJSON * (*)(void *))vl_api_bd_ip_mac_flush_t_tojson, 0xc25fdce6);
   vat2_register_function("bd_ip_mac_dump", api_bd_ip_mac_dump, (cJSON * (*)(void *))vl_api_bd_ip_mac_dump_t_tojson, 0xc25fdce6);
   vat2_register_function("l2_interface_efp_filter", api_l2_interface_efp_filter, (cJSON * (*)(void *))vl_api_l2_interface_efp_filter_t_tojson, 0x5501adee);
   vat2_register_function("sw_interface_set_vpath", api_sw_interface_set_vpath, (cJSON * (*)(void *))vl_api_sw_interface_set_vpath_t_tojson, 0xae6cfcfb);
   vat2_register_function("bvi_create", api_bvi_create, (cJSON * (*)(void *))vl_api_bvi_create_t_tojson, 0xf5398559);
   vat2_register_function("bvi_delete", api_bvi_delete, (cJSON * (*)(void *))vl_api_bvi_delete_t_tojson, 0xf9e6675e);
   return 0;
}
