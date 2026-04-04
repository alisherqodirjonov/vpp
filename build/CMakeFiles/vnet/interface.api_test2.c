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

#include "interface.api_enum.h"
#include "interface.api_types.h"

#define vl_endianfun		/* define message structures */
#include "interface.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "interface.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "interface.api.h"
#undef vl_printfun

#include "interface.api_tojson.h"
#include "interface.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_want_interface_events (cJSON *o)
{
  vl_api_want_interface_events_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_want_interface_events_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_WANT_INTERFACE_EVENTS_CRC);
  vl_api_want_interface_events_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_WANT_INTERFACE_EVENTS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_want_interface_events_reply_t *rmp = (vl_api_want_interface_events_reply_t *)p;
  vl_api_want_interface_events_reply_t_endian(rmp, 0);
  return vl_api_want_interface_events_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_tx_placement_get (cJSON *o)
{
    u16 msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_TX_PLACEMENT_GET_CRC);
  int len = 0;
  if (!o) return 0;
  vl_api_sw_interface_tx_placement_get_t *mp = vl_api_sw_interface_tx_placement_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }
  mp->_vl_msg_id = msg_id;

  vl_api_sw_interface_tx_placement_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  cJSON *reply = cJSON_CreateArray();

  u16 reply_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_TX_PLACEMENT_GET_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_TX_PLACEMENT_DETAILS_CRC);

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
        vl_api_sw_interface_tx_placement_get_reply_t *rmp = (vl_api_sw_interface_tx_placement_get_reply_t *)p;
        vl_api_sw_interface_tx_placement_get_reply_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_sw_interface_tx_placement_get_reply_t_tojson(rmp));
        break;
    }

    if (msg_id == details_msg_id) {
        vl_api_sw_interface_tx_placement_details_t *rmp = (vl_api_sw_interface_tx_placement_details_t *)p;
        vl_api_sw_interface_tx_placement_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_sw_interface_tx_placement_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_sw_interface_set_flags (cJSON *o)
{
  vl_api_sw_interface_set_flags_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_set_flags_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_FLAGS_CRC);
  vl_api_sw_interface_set_flags_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_SET_FLAGS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_set_flags_reply_t *rmp = (vl_api_sw_interface_set_flags_reply_t *)p;
  vl_api_sw_interface_set_flags_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_set_flags_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_set_promisc (cJSON *o)
{
  vl_api_sw_interface_set_promisc_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_set_promisc_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_PROMISC_CRC);
  vl_api_sw_interface_set_promisc_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_SET_PROMISC_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_set_promisc_reply_t *rmp = (vl_api_sw_interface_set_promisc_reply_t *)p;
  vl_api_sw_interface_set_promisc_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_set_promisc_reply_t_tojson(rmp);
}

static cJSON *
api_hw_interface_set_mtu (cJSON *o)
{
  vl_api_hw_interface_set_mtu_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_hw_interface_set_mtu_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_HW_INTERFACE_SET_MTU_CRC);
  vl_api_hw_interface_set_mtu_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_HW_INTERFACE_SET_MTU_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_hw_interface_set_mtu_reply_t *rmp = (vl_api_hw_interface_set_mtu_reply_t *)p;
  vl_api_hw_interface_set_mtu_reply_t_endian(rmp, 0);
  return vl_api_hw_interface_set_mtu_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_set_mtu (cJSON *o)
{
  vl_api_sw_interface_set_mtu_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_set_mtu_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_MTU_CRC);
  vl_api_sw_interface_set_mtu_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_SET_MTU_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_set_mtu_reply_t *rmp = (vl_api_sw_interface_set_mtu_reply_t *)p;
  vl_api_sw_interface_set_mtu_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_set_mtu_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_set_ip_directed_broadcast (cJSON *o)
{
  vl_api_sw_interface_set_ip_directed_broadcast_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_set_ip_directed_broadcast_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_IP_DIRECTED_BROADCAST_CRC);
  vl_api_sw_interface_set_ip_directed_broadcast_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_SET_IP_DIRECTED_BROADCAST_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_set_ip_directed_broadcast_reply_t *rmp = (vl_api_sw_interface_set_ip_directed_broadcast_reply_t *)p;
  vl_api_sw_interface_set_ip_directed_broadcast_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_set_ip_directed_broadcast_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_sw_interface_dump_t *mp = vl_api_sw_interface_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_sw_interface_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_sw_interface_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_sw_interface_details_t *rmp = (vl_api_sw_interface_details_t *)p;
        vl_api_sw_interface_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_sw_interface_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_sw_interface_add_del_address (cJSON *o)
{
  vl_api_sw_interface_add_del_address_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_add_del_address_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_ADD_DEL_ADDRESS_CRC);
  vl_api_sw_interface_add_del_address_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_ADD_DEL_ADDRESS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_add_del_address_reply_t *rmp = (vl_api_sw_interface_add_del_address_reply_t *)p;
  vl_api_sw_interface_add_del_address_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_add_del_address_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_address_replace_begin (cJSON *o)
{
  vl_api_sw_interface_address_replace_begin_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_address_replace_begin_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_ADDRESS_REPLACE_BEGIN_CRC);
  vl_api_sw_interface_address_replace_begin_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_ADDRESS_REPLACE_BEGIN_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_address_replace_begin_reply_t *rmp = (vl_api_sw_interface_address_replace_begin_reply_t *)p;
  vl_api_sw_interface_address_replace_begin_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_address_replace_begin_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_address_replace_end (cJSON *o)
{
  vl_api_sw_interface_address_replace_end_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_address_replace_end_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_ADDRESS_REPLACE_END_CRC);
  vl_api_sw_interface_address_replace_end_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_ADDRESS_REPLACE_END_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_address_replace_end_reply_t *rmp = (vl_api_sw_interface_address_replace_end_reply_t *)p;
  vl_api_sw_interface_address_replace_end_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_address_replace_end_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_set_table (cJSON *o)
{
  vl_api_sw_interface_set_table_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_set_table_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_TABLE_CRC);
  vl_api_sw_interface_set_table_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_SET_TABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_set_table_reply_t *rmp = (vl_api_sw_interface_set_table_reply_t *)p;
  vl_api_sw_interface_set_table_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_set_table_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_get_table (cJSON *o)
{
  vl_api_sw_interface_get_table_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_get_table_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_GET_TABLE_CRC);
  vl_api_sw_interface_get_table_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_GET_TABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_get_table_reply_t *rmp = (vl_api_sw_interface_get_table_reply_t *)p;
  vl_api_sw_interface_get_table_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_get_table_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_set_unnumbered (cJSON *o)
{
  vl_api_sw_interface_set_unnumbered_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_set_unnumbered_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_UNNUMBERED_CRC);
  vl_api_sw_interface_set_unnumbered_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_SET_UNNUMBERED_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_set_unnumbered_reply_t *rmp = (vl_api_sw_interface_set_unnumbered_reply_t *)p;
  vl_api_sw_interface_set_unnumbered_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_set_unnumbered_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_clear_stats (cJSON *o)
{
  vl_api_sw_interface_clear_stats_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_clear_stats_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_CLEAR_STATS_CRC);
  vl_api_sw_interface_clear_stats_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_CLEAR_STATS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_clear_stats_reply_t *rmp = (vl_api_sw_interface_clear_stats_reply_t *)p;
  vl_api_sw_interface_clear_stats_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_clear_stats_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_tag_add_del (cJSON *o)
{
  vl_api_sw_interface_tag_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_tag_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_TAG_ADD_DEL_CRC);
  vl_api_sw_interface_tag_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_TAG_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_tag_add_del_reply_t *rmp = (vl_api_sw_interface_tag_add_del_reply_t *)p;
  vl_api_sw_interface_tag_add_del_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_tag_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_add_del_mac_address (cJSON *o)
{
  vl_api_sw_interface_add_del_mac_address_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_add_del_mac_address_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_ADD_DEL_MAC_ADDRESS_CRC);
  vl_api_sw_interface_add_del_mac_address_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_ADD_DEL_MAC_ADDRESS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_add_del_mac_address_reply_t *rmp = (vl_api_sw_interface_add_del_mac_address_reply_t *)p;
  vl_api_sw_interface_add_del_mac_address_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_add_del_mac_address_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_set_mac_address (cJSON *o)
{
  vl_api_sw_interface_set_mac_address_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_set_mac_address_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_MAC_ADDRESS_CRC);
  vl_api_sw_interface_set_mac_address_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_SET_MAC_ADDRESS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_set_mac_address_reply_t *rmp = (vl_api_sw_interface_set_mac_address_reply_t *)p;
  vl_api_sw_interface_set_mac_address_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_set_mac_address_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_get_mac_address (cJSON *o)
{
  vl_api_sw_interface_get_mac_address_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_get_mac_address_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_GET_MAC_ADDRESS_CRC);
  vl_api_sw_interface_get_mac_address_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_GET_MAC_ADDRESS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_get_mac_address_reply_t *rmp = (vl_api_sw_interface_get_mac_address_reply_t *)p;
  vl_api_sw_interface_get_mac_address_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_get_mac_address_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_set_rx_mode (cJSON *o)
{
  vl_api_sw_interface_set_rx_mode_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_set_rx_mode_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_RX_MODE_CRC);
  vl_api_sw_interface_set_rx_mode_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_SET_RX_MODE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_set_rx_mode_reply_t *rmp = (vl_api_sw_interface_set_rx_mode_reply_t *)p;
  vl_api_sw_interface_set_rx_mode_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_set_rx_mode_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_set_rx_placement (cJSON *o)
{
  vl_api_sw_interface_set_rx_placement_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_set_rx_placement_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_RX_PLACEMENT_CRC);
  vl_api_sw_interface_set_rx_placement_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_SET_RX_PLACEMENT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_set_rx_placement_reply_t *rmp = (vl_api_sw_interface_set_rx_placement_reply_t *)p;
  vl_api_sw_interface_set_rx_placement_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_set_rx_placement_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_set_tx_placement (cJSON *o)
{
  vl_api_sw_interface_set_tx_placement_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_set_tx_placement_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_TX_PLACEMENT_CRC);
  vl_api_sw_interface_set_tx_placement_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_SET_TX_PLACEMENT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_set_tx_placement_reply_t *rmp = (vl_api_sw_interface_set_tx_placement_reply_t *)p;
  vl_api_sw_interface_set_tx_placement_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_set_tx_placement_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_set_interface_name (cJSON *o)
{
  vl_api_sw_interface_set_interface_name_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_set_interface_name_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_INTERFACE_NAME_CRC);
  vl_api_sw_interface_set_interface_name_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_SET_INTERFACE_NAME_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_set_interface_name_reply_t *rmp = (vl_api_sw_interface_set_interface_name_reply_t *)p;
  vl_api_sw_interface_set_interface_name_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_set_interface_name_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_rx_placement_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_RX_PLACEMENT_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_sw_interface_rx_placement_dump_t *mp = vl_api_sw_interface_rx_placement_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_sw_interface_rx_placement_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_RX_PLACEMENT_DETAILS_CRC);

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
        if (l < sizeof(vl_api_sw_interface_rx_placement_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_sw_interface_rx_placement_details_t *rmp = (vl_api_sw_interface_rx_placement_details_t *)p;
        vl_api_sw_interface_rx_placement_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_sw_interface_rx_placement_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_interface_name_renumber (cJSON *o)
{
  vl_api_interface_name_renumber_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_interface_name_renumber_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_INTERFACE_NAME_RENUMBER_CRC);
  vl_api_interface_name_renumber_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_INTERFACE_NAME_RENUMBER_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_interface_name_renumber_reply_t *rmp = (vl_api_interface_name_renumber_reply_t *)p;
  vl_api_interface_name_renumber_reply_t_endian(rmp, 0);
  return vl_api_interface_name_renumber_reply_t_tojson(rmp);
}

static cJSON *
api_create_subif (cJSON *o)
{
  vl_api_create_subif_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_create_subif_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CREATE_SUBIF_CRC);
  vl_api_create_subif_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CREATE_SUBIF_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_create_subif_reply_t *rmp = (vl_api_create_subif_reply_t *)p;
  vl_api_create_subif_reply_t_endian(rmp, 0);
  return vl_api_create_subif_reply_t_tojson(rmp);
}

static cJSON *
api_create_vlan_subif (cJSON *o)
{
  vl_api_create_vlan_subif_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_create_vlan_subif_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CREATE_VLAN_SUBIF_CRC);
  vl_api_create_vlan_subif_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CREATE_VLAN_SUBIF_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_create_vlan_subif_reply_t *rmp = (vl_api_create_vlan_subif_reply_t *)p;
  vl_api_create_vlan_subif_reply_t_endian(rmp, 0);
  return vl_api_create_vlan_subif_reply_t_tojson(rmp);
}

static cJSON *
api_delete_subif (cJSON *o)
{
  vl_api_delete_subif_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_delete_subif_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DELETE_SUBIF_CRC);
  vl_api_delete_subif_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DELETE_SUBIF_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_delete_subif_reply_t *rmp = (vl_api_delete_subif_reply_t *)p;
  vl_api_delete_subif_reply_t_endian(rmp, 0);
  return vl_api_delete_subif_reply_t_tojson(rmp);
}

static cJSON *
api_create_loopback (cJSON *o)
{
  vl_api_create_loopback_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_create_loopback_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CREATE_LOOPBACK_CRC);
  vl_api_create_loopback_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CREATE_LOOPBACK_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_create_loopback_reply_t *rmp = (vl_api_create_loopback_reply_t *)p;
  vl_api_create_loopback_reply_t_endian(rmp, 0);
  return vl_api_create_loopback_reply_t_tojson(rmp);
}

static cJSON *
api_create_loopback_instance (cJSON *o)
{
  vl_api_create_loopback_instance_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_create_loopback_instance_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CREATE_LOOPBACK_INSTANCE_CRC);
  vl_api_create_loopback_instance_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CREATE_LOOPBACK_INSTANCE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_create_loopback_instance_reply_t *rmp = (vl_api_create_loopback_instance_reply_t *)p;
  vl_api_create_loopback_instance_reply_t_endian(rmp, 0);
  return vl_api_create_loopback_instance_reply_t_tojson(rmp);
}

static cJSON *
api_delete_loopback (cJSON *o)
{
  vl_api_delete_loopback_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_delete_loopback_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DELETE_LOOPBACK_CRC);
  vl_api_delete_loopback_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DELETE_LOOPBACK_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_delete_loopback_reply_t *rmp = (vl_api_delete_loopback_reply_t *)p;
  vl_api_delete_loopback_reply_t_endian(rmp, 0);
  return vl_api_delete_loopback_reply_t_tojson(rmp);
}

static cJSON *
api_collect_detailed_interface_stats (cJSON *o)
{
  vl_api_collect_detailed_interface_stats_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_collect_detailed_interface_stats_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_COLLECT_DETAILED_INTERFACE_STATS_CRC);
  vl_api_collect_detailed_interface_stats_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_COLLECT_DETAILED_INTERFACE_STATS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_collect_detailed_interface_stats_reply_t *rmp = (vl_api_collect_detailed_interface_stats_reply_t *)p;
  vl_api_collect_detailed_interface_stats_reply_t_endian(rmp, 0);
  return vl_api_collect_detailed_interface_stats_reply_t_tojson(rmp);
}

static cJSON *
api_pcap_set_filter_function (cJSON *o)
{
  vl_api_pcap_set_filter_function_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_pcap_set_filter_function_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_PCAP_SET_FILTER_FUNCTION_CRC);
  vl_api_pcap_set_filter_function_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_PCAP_SET_FILTER_FUNCTION_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_pcap_set_filter_function_reply_t *rmp = (vl_api_pcap_set_filter_function_reply_t *)p;
  vl_api_pcap_set_filter_function_reply_t_endian(rmp, 0);
  return vl_api_pcap_set_filter_function_reply_t_tojson(rmp);
}

static cJSON *
api_pcap_trace_on (cJSON *o)
{
  vl_api_pcap_trace_on_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_pcap_trace_on_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_PCAP_TRACE_ON_CRC);
  vl_api_pcap_trace_on_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_PCAP_TRACE_ON_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_pcap_trace_on_reply_t *rmp = (vl_api_pcap_trace_on_reply_t *)p;
  vl_api_pcap_trace_on_reply_t_endian(rmp, 0);
  return vl_api_pcap_trace_on_reply_t_tojson(rmp);
}

static cJSON *
api_pcap_trace_off (cJSON *o)
{
  vl_api_pcap_trace_off_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_pcap_trace_off_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_PCAP_TRACE_OFF_CRC);
  vl_api_pcap_trace_off_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_PCAP_TRACE_OFF_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_pcap_trace_off_reply_t *rmp = (vl_api_pcap_trace_off_reply_t *)p;
  vl_api_pcap_trace_off_reply_t_endian(rmp, 0);
  return vl_api_pcap_trace_off_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("want_interface_events", api_want_interface_events, (cJSON * (*)(void *))vl_api_want_interface_events_t_tojson, 0x476f5a08);
   vat2_register_function("sw_interface_tx_placement_get", api_sw_interface_tx_placement_get, (cJSON * (*)(void *))vl_api_sw_interface_tx_placement_get_t_tojson, 0x47250981);
   vat2_register_function("sw_interface_set_flags", api_sw_interface_set_flags, (cJSON * (*)(void *))vl_api_sw_interface_set_flags_t_tojson, 0xf5aec1b8);
   vat2_register_function("sw_interface_set_promisc", api_sw_interface_set_promisc, (cJSON * (*)(void *))vl_api_sw_interface_set_promisc_t_tojson, 0xd40860d4);
   vat2_register_function("hw_interface_set_mtu", api_hw_interface_set_mtu, (cJSON * (*)(void *))vl_api_hw_interface_set_mtu_t_tojson, 0xe6746899);
   vat2_register_function("sw_interface_set_mtu", api_sw_interface_set_mtu, (cJSON * (*)(void *))vl_api_sw_interface_set_mtu_t_tojson, 0x5cbe85e5);
   vat2_register_function("sw_interface_set_ip_directed_broadcast", api_sw_interface_set_ip_directed_broadcast, (cJSON * (*)(void *))vl_api_sw_interface_set_ip_directed_broadcast_t_tojson, 0xae6cfcfb);
   vat2_register_function("sw_interface_dump", api_sw_interface_dump, (cJSON * (*)(void *))vl_api_sw_interface_dump_t_tojson, 0xaa610c27);
   vat2_register_function("sw_interface_add_del_address", api_sw_interface_add_del_address, (cJSON * (*)(void *))vl_api_sw_interface_add_del_address_t_tojson, 0x5463d73b);
   vat2_register_function("sw_interface_address_replace_begin", api_sw_interface_address_replace_begin, (cJSON * (*)(void *))vl_api_sw_interface_address_replace_begin_t_tojson, 0x51077d14);
   vat2_register_function("sw_interface_address_replace_end", api_sw_interface_address_replace_end, (cJSON * (*)(void *))vl_api_sw_interface_address_replace_end_t_tojson, 0x51077d14);
   vat2_register_function("sw_interface_set_table", api_sw_interface_set_table, (cJSON * (*)(void *))vl_api_sw_interface_set_table_t_tojson, 0xdf42a577);
   vat2_register_function("sw_interface_get_table", api_sw_interface_get_table, (cJSON * (*)(void *))vl_api_sw_interface_get_table_t_tojson, 0x2d033de4);
   vat2_register_function("sw_interface_set_unnumbered", api_sw_interface_set_unnumbered, (cJSON * (*)(void *))vl_api_sw_interface_set_unnumbered_t_tojson, 0x154a6439);
   vat2_register_function("sw_interface_clear_stats", api_sw_interface_clear_stats, (cJSON * (*)(void *))vl_api_sw_interface_clear_stats_t_tojson, 0xf9e6675e);
   vat2_register_function("sw_interface_tag_add_del", api_sw_interface_tag_add_del, (cJSON * (*)(void *))vl_api_sw_interface_tag_add_del_t_tojson, 0x426f8bc1);
   vat2_register_function("sw_interface_add_del_mac_address", api_sw_interface_add_del_mac_address, (cJSON * (*)(void *))vl_api_sw_interface_add_del_mac_address_t_tojson, 0x638bb9f4);
   vat2_register_function("sw_interface_set_mac_address", api_sw_interface_set_mac_address, (cJSON * (*)(void *))vl_api_sw_interface_set_mac_address_t_tojson, 0xc536e7eb);
   vat2_register_function("sw_interface_get_mac_address", api_sw_interface_get_mac_address, (cJSON * (*)(void *))vl_api_sw_interface_get_mac_address_t_tojson, 0xf9e6675e);
   vat2_register_function("sw_interface_set_rx_mode", api_sw_interface_set_rx_mode, (cJSON * (*)(void *))vl_api_sw_interface_set_rx_mode_t_tojson, 0xb04d1cfe);
   vat2_register_function("sw_interface_set_rx_placement", api_sw_interface_set_rx_placement, (cJSON * (*)(void *))vl_api_sw_interface_set_rx_placement_t_tojson, 0xdb65f3c9);
   vat2_register_function("sw_interface_set_tx_placement", api_sw_interface_set_tx_placement, (cJSON * (*)(void *))vl_api_sw_interface_set_tx_placement_t_tojson, 0x4e0cd5ff);
   vat2_register_function("sw_interface_set_interface_name", api_sw_interface_set_interface_name, (cJSON * (*)(void *))vl_api_sw_interface_set_interface_name_t_tojson, 0x45a1d548);
   vat2_register_function("sw_interface_rx_placement_dump", api_sw_interface_rx_placement_dump, (cJSON * (*)(void *))vl_api_sw_interface_rx_placement_dump_t_tojson, 0xf9e6675e);
   vat2_register_function("interface_name_renumber", api_interface_name_renumber, (cJSON * (*)(void *))vl_api_interface_name_renumber_t_tojson, 0x2b8858b8);
   vat2_register_function("create_subif", api_create_subif, (cJSON * (*)(void *))vl_api_create_subif_t_tojson, 0x790ca755);
   vat2_register_function("create_vlan_subif", api_create_vlan_subif, (cJSON * (*)(void *))vl_api_create_vlan_subif_t_tojson, 0xaf34ac8b);
   vat2_register_function("delete_subif", api_delete_subif, (cJSON * (*)(void *))vl_api_delete_subif_t_tojson, 0xf9e6675e);
   vat2_register_function("create_loopback", api_create_loopback, (cJSON * (*)(void *))vl_api_create_loopback_t_tojson, 0x42bb5d22);
   vat2_register_function("create_loopback_instance", api_create_loopback_instance, (cJSON * (*)(void *))vl_api_create_loopback_instance_t_tojson, 0xd36a3ee2);
   vat2_register_function("delete_loopback", api_delete_loopback, (cJSON * (*)(void *))vl_api_delete_loopback_t_tojson, 0xf9e6675e);
   vat2_register_function("collect_detailed_interface_stats", api_collect_detailed_interface_stats, (cJSON * (*)(void *))vl_api_collect_detailed_interface_stats_t_tojson, 0x5501adee);
   vat2_register_function("pcap_set_filter_function", api_pcap_set_filter_function, (cJSON * (*)(void *))vl_api_pcap_set_filter_function_t_tojson, 0x616abb92);
   vat2_register_function("pcap_trace_on", api_pcap_trace_on, (cJSON * (*)(void *))vl_api_pcap_trace_on_t_tojson, 0xcb39e968);
   vat2_register_function("pcap_trace_off", api_pcap_trace_off, (cJSON * (*)(void *))vl_api_pcap_trace_off_t_tojson, 0x51077d14);
   return 0;
}
