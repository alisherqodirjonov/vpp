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

#include "classify.api_enum.h"
#include "classify.api_types.h"

#define vl_endianfun		/* define message structures */
#include "classify.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "classify.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "classify.api.h"
#undef vl_printfun

#include "classify.api_tojson.h"
#include "classify.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_classify_add_del_table (cJSON *o)
{
  vl_api_classify_add_del_table_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_classify_add_del_table_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CLASSIFY_ADD_DEL_TABLE_CRC);
  vl_api_classify_add_del_table_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CLASSIFY_ADD_DEL_TABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_classify_add_del_table_reply_t *rmp = (vl_api_classify_add_del_table_reply_t *)p;
  vl_api_classify_add_del_table_reply_t_endian(rmp, 0);
  return vl_api_classify_add_del_table_reply_t_tojson(rmp);
}

static cJSON *
api_classify_add_del_session (cJSON *o)
{
  vl_api_classify_add_del_session_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_classify_add_del_session_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CLASSIFY_ADD_DEL_SESSION_CRC);
  vl_api_classify_add_del_session_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CLASSIFY_ADD_DEL_SESSION_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_classify_add_del_session_reply_t *rmp = (vl_api_classify_add_del_session_reply_t *)p;
  vl_api_classify_add_del_session_reply_t_endian(rmp, 0);
  return vl_api_classify_add_del_session_reply_t_tojson(rmp);
}

static cJSON *
api_policer_classify_set_interface (cJSON *o)
{
  vl_api_policer_classify_set_interface_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_policer_classify_set_interface_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_POLICER_CLASSIFY_SET_INTERFACE_CRC);
  vl_api_policer_classify_set_interface_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_POLICER_CLASSIFY_SET_INTERFACE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_policer_classify_set_interface_reply_t *rmp = (vl_api_policer_classify_set_interface_reply_t *)p;
  vl_api_policer_classify_set_interface_reply_t_endian(rmp, 0);
  return vl_api_policer_classify_set_interface_reply_t_tojson(rmp);
}

static cJSON *
api_policer_classify_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_POLICER_CLASSIFY_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_policer_classify_dump_t *mp = vl_api_policer_classify_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_policer_classify_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_POLICER_CLASSIFY_DETAILS_CRC);

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
        if (l < sizeof(vl_api_policer_classify_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_policer_classify_details_t *rmp = (vl_api_policer_classify_details_t *)p;
        vl_api_policer_classify_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_policer_classify_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_classify_table_ids (cJSON *o)
{
  vl_api_classify_table_ids_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_classify_table_ids_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CLASSIFY_TABLE_IDS_CRC);
  vl_api_classify_table_ids_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CLASSIFY_TABLE_IDS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_classify_table_ids_reply_t *rmp = (vl_api_classify_table_ids_reply_t *)p;
  vl_api_classify_table_ids_reply_t_endian(rmp, 0);
  return vl_api_classify_table_ids_reply_t_tojson(rmp);
}

static cJSON *
api_classify_table_by_interface (cJSON *o)
{
  vl_api_classify_table_by_interface_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_classify_table_by_interface_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CLASSIFY_TABLE_BY_INTERFACE_CRC);
  vl_api_classify_table_by_interface_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CLASSIFY_TABLE_BY_INTERFACE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_classify_table_by_interface_reply_t *rmp = (vl_api_classify_table_by_interface_reply_t *)p;
  vl_api_classify_table_by_interface_reply_t_endian(rmp, 0);
  return vl_api_classify_table_by_interface_reply_t_tojson(rmp);
}

static cJSON *
api_classify_table_info (cJSON *o)
{
  vl_api_classify_table_info_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_classify_table_info_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CLASSIFY_TABLE_INFO_CRC);
  vl_api_classify_table_info_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CLASSIFY_TABLE_INFO_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_classify_table_info_reply_t *rmp = (vl_api_classify_table_info_reply_t *)p;
  vl_api_classify_table_info_reply_t_endian(rmp, 0);
  return vl_api_classify_table_info_reply_t_tojson(rmp);
}

static cJSON *
api_classify_session_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_CLASSIFY_SESSION_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_classify_session_dump_t *mp = vl_api_classify_session_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_classify_session_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_CLASSIFY_SESSION_DETAILS_CRC);

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
        if (l < sizeof(vl_api_classify_session_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_classify_session_details_t *rmp = (vl_api_classify_session_details_t *)p;
        vl_api_classify_session_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_classify_session_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_flow_classify_set_interface (cJSON *o)
{
  vl_api_flow_classify_set_interface_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_flow_classify_set_interface_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_FLOW_CLASSIFY_SET_INTERFACE_CRC);
  vl_api_flow_classify_set_interface_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_FLOW_CLASSIFY_SET_INTERFACE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_flow_classify_set_interface_reply_t *rmp = (vl_api_flow_classify_set_interface_reply_t *)p;
  vl_api_flow_classify_set_interface_reply_t_endian(rmp, 0);
  return vl_api_flow_classify_set_interface_reply_t_tojson(rmp);
}

static cJSON *
api_flow_classify_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_FLOW_CLASSIFY_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_flow_classify_dump_t *mp = vl_api_flow_classify_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_flow_classify_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_FLOW_CLASSIFY_DETAILS_CRC);

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
        if (l < sizeof(vl_api_flow_classify_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_flow_classify_details_t *rmp = (vl_api_flow_classify_details_t *)p;
        vl_api_flow_classify_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_flow_classify_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_classify_set_interface_ip_table (cJSON *o)
{
  vl_api_classify_set_interface_ip_table_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_classify_set_interface_ip_table_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CLASSIFY_SET_INTERFACE_IP_TABLE_CRC);
  vl_api_classify_set_interface_ip_table_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CLASSIFY_SET_INTERFACE_IP_TABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_classify_set_interface_ip_table_reply_t *rmp = (vl_api_classify_set_interface_ip_table_reply_t *)p;
  vl_api_classify_set_interface_ip_table_reply_t_endian(rmp, 0);
  return vl_api_classify_set_interface_ip_table_reply_t_tojson(rmp);
}

static cJSON *
api_classify_set_interface_l2_tables (cJSON *o)
{
  vl_api_classify_set_interface_l2_tables_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_classify_set_interface_l2_tables_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CLASSIFY_SET_INTERFACE_L2_TABLES_CRC);
  vl_api_classify_set_interface_l2_tables_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CLASSIFY_SET_INTERFACE_L2_TABLES_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_classify_set_interface_l2_tables_reply_t *rmp = (vl_api_classify_set_interface_l2_tables_reply_t *)p;
  vl_api_classify_set_interface_l2_tables_reply_t_endian(rmp, 0);
  return vl_api_classify_set_interface_l2_tables_reply_t_tojson(rmp);
}

static cJSON *
api_input_acl_set_interface (cJSON *o)
{
  vl_api_input_acl_set_interface_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_input_acl_set_interface_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_INPUT_ACL_SET_INTERFACE_CRC);
  vl_api_input_acl_set_interface_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_INPUT_ACL_SET_INTERFACE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_input_acl_set_interface_reply_t *rmp = (vl_api_input_acl_set_interface_reply_t *)p;
  vl_api_input_acl_set_interface_reply_t_endian(rmp, 0);
  return vl_api_input_acl_set_interface_reply_t_tojson(rmp);
}

static cJSON *
api_punt_acl_add_del (cJSON *o)
{
  vl_api_punt_acl_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_punt_acl_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_PUNT_ACL_ADD_DEL_CRC);
  vl_api_punt_acl_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_PUNT_ACL_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_punt_acl_add_del_reply_t *rmp = (vl_api_punt_acl_add_del_reply_t *)p;
  vl_api_punt_acl_add_del_reply_t_endian(rmp, 0);
  return vl_api_punt_acl_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_punt_acl_get (cJSON *o)
{
  vl_api_punt_acl_get_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_punt_acl_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_PUNT_ACL_GET_CRC);
  vl_api_punt_acl_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_PUNT_ACL_GET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_punt_acl_get_reply_t *rmp = (vl_api_punt_acl_get_reply_t *)p;
  vl_api_punt_acl_get_reply_t_endian(rmp, 0);
  return vl_api_punt_acl_get_reply_t_tojson(rmp);
}

static cJSON *
api_output_acl_set_interface (cJSON *o)
{
  vl_api_output_acl_set_interface_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_output_acl_set_interface_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_OUTPUT_ACL_SET_INTERFACE_CRC);
  vl_api_output_acl_set_interface_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_OUTPUT_ACL_SET_INTERFACE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_output_acl_set_interface_reply_t *rmp = (vl_api_output_acl_set_interface_reply_t *)p;
  vl_api_output_acl_set_interface_reply_t_endian(rmp, 0);
  return vl_api_output_acl_set_interface_reply_t_tojson(rmp);
}

static cJSON *
api_classify_pcap_lookup_table (cJSON *o)
{
  vl_api_classify_pcap_lookup_table_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_classify_pcap_lookup_table_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CLASSIFY_PCAP_LOOKUP_TABLE_CRC);
  vl_api_classify_pcap_lookup_table_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CLASSIFY_PCAP_LOOKUP_TABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_classify_pcap_lookup_table_reply_t *rmp = (vl_api_classify_pcap_lookup_table_reply_t *)p;
  vl_api_classify_pcap_lookup_table_reply_t_endian(rmp, 0);
  return vl_api_classify_pcap_lookup_table_reply_t_tojson(rmp);
}

static cJSON *
api_classify_pcap_set_table (cJSON *o)
{
  vl_api_classify_pcap_set_table_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_classify_pcap_set_table_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CLASSIFY_PCAP_SET_TABLE_CRC);
  vl_api_classify_pcap_set_table_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CLASSIFY_PCAP_SET_TABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_classify_pcap_set_table_reply_t *rmp = (vl_api_classify_pcap_set_table_reply_t *)p;
  vl_api_classify_pcap_set_table_reply_t_endian(rmp, 0);
  return vl_api_classify_pcap_set_table_reply_t_tojson(rmp);
}

static cJSON *
api_classify_pcap_get_tables (cJSON *o)
{
  vl_api_classify_pcap_get_tables_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_classify_pcap_get_tables_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CLASSIFY_PCAP_GET_TABLES_CRC);
  vl_api_classify_pcap_get_tables_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CLASSIFY_PCAP_GET_TABLES_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_classify_pcap_get_tables_reply_t *rmp = (vl_api_classify_pcap_get_tables_reply_t *)p;
  vl_api_classify_pcap_get_tables_reply_t_endian(rmp, 0);
  return vl_api_classify_pcap_get_tables_reply_t_tojson(rmp);
}

static cJSON *
api_classify_trace_lookup_table (cJSON *o)
{
  vl_api_classify_trace_lookup_table_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_classify_trace_lookup_table_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CLASSIFY_TRACE_LOOKUP_TABLE_CRC);
  vl_api_classify_trace_lookup_table_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CLASSIFY_TRACE_LOOKUP_TABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_classify_trace_lookup_table_reply_t *rmp = (vl_api_classify_trace_lookup_table_reply_t *)p;
  vl_api_classify_trace_lookup_table_reply_t_endian(rmp, 0);
  return vl_api_classify_trace_lookup_table_reply_t_tojson(rmp);
}

static cJSON *
api_classify_trace_set_table (cJSON *o)
{
  vl_api_classify_trace_set_table_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_classify_trace_set_table_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CLASSIFY_TRACE_SET_TABLE_CRC);
  vl_api_classify_trace_set_table_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CLASSIFY_TRACE_SET_TABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_classify_trace_set_table_reply_t *rmp = (vl_api_classify_trace_set_table_reply_t *)p;
  vl_api_classify_trace_set_table_reply_t_endian(rmp, 0);
  return vl_api_classify_trace_set_table_reply_t_tojson(rmp);
}

static cJSON *
api_classify_trace_get_tables (cJSON *o)
{
  vl_api_classify_trace_get_tables_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_classify_trace_get_tables_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CLASSIFY_TRACE_GET_TABLES_CRC);
  vl_api_classify_trace_get_tables_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CLASSIFY_TRACE_GET_TABLES_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_classify_trace_get_tables_reply_t *rmp = (vl_api_classify_trace_get_tables_reply_t *)p;
  vl_api_classify_trace_get_tables_reply_t_endian(rmp, 0);
  return vl_api_classify_trace_get_tables_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("classify_add_del_table", api_classify_add_del_table, (cJSON * (*)(void *))vl_api_classify_add_del_table_t_tojson, 0x6849e39e);
   vat2_register_function("classify_add_del_session", api_classify_add_del_session, (cJSON * (*)(void *))vl_api_classify_add_del_session_t_tojson, 0xf20879f0);
   vat2_register_function("policer_classify_set_interface", api_policer_classify_set_interface, (cJSON * (*)(void *))vl_api_policer_classify_set_interface_t_tojson, 0xde7ad708);
   vat2_register_function("policer_classify_dump", api_policer_classify_dump, (cJSON * (*)(void *))vl_api_policer_classify_dump_t_tojson, 0x56cbb5fb);
   vat2_register_function("classify_table_ids", api_classify_table_ids, (cJSON * (*)(void *))vl_api_classify_table_ids_t_tojson, 0x51077d14);
   vat2_register_function("classify_table_by_interface", api_classify_table_by_interface, (cJSON * (*)(void *))vl_api_classify_table_by_interface_t_tojson, 0xf9e6675e);
   vat2_register_function("classify_table_info", api_classify_table_info, (cJSON * (*)(void *))vl_api_classify_table_info_t_tojson, 0x0cca2cd9);
   vat2_register_function("classify_session_dump", api_classify_session_dump, (cJSON * (*)(void *))vl_api_classify_session_dump_t_tojson, 0x0cca2cd9);
   vat2_register_function("flow_classify_set_interface", api_flow_classify_set_interface, (cJSON * (*)(void *))vl_api_flow_classify_set_interface_t_tojson, 0xb6192f1c);
   vat2_register_function("flow_classify_dump", api_flow_classify_dump, (cJSON * (*)(void *))vl_api_flow_classify_dump_t_tojson, 0x25dd3e4c);
   vat2_register_function("classify_set_interface_ip_table", api_classify_set_interface_ip_table, (cJSON * (*)(void *))vl_api_classify_set_interface_ip_table_t_tojson, 0xe0b097c7);
   vat2_register_function("classify_set_interface_l2_tables", api_classify_set_interface_l2_tables, (cJSON * (*)(void *))vl_api_classify_set_interface_l2_tables_t_tojson, 0x5a6ddf65);
   vat2_register_function("input_acl_set_interface", api_input_acl_set_interface, (cJSON * (*)(void *))vl_api_input_acl_set_interface_t_tojson, 0xde7ad708);
   vat2_register_function("punt_acl_add_del", api_punt_acl_add_del, (cJSON * (*)(void *))vl_api_punt_acl_add_del_t_tojson, 0xa93bf3a0);
   vat2_register_function("punt_acl_get", api_punt_acl_get, (cJSON * (*)(void *))vl_api_punt_acl_get_t_tojson, 0x51077d14);
   vat2_register_function("output_acl_set_interface", api_output_acl_set_interface, (cJSON * (*)(void *))vl_api_output_acl_set_interface_t_tojson, 0xde7ad708);
   vat2_register_function("classify_pcap_lookup_table", api_classify_pcap_lookup_table, (cJSON * (*)(void *))vl_api_classify_pcap_lookup_table_t_tojson, 0xe1b4cc6b);
   vat2_register_function("classify_pcap_set_table", api_classify_pcap_set_table, (cJSON * (*)(void *))vl_api_classify_pcap_set_table_t_tojson, 0x006051b3);
   vat2_register_function("classify_pcap_get_tables", api_classify_pcap_get_tables, (cJSON * (*)(void *))vl_api_classify_pcap_get_tables_t_tojson, 0xf9e6675e);
   vat2_register_function("classify_trace_lookup_table", api_classify_trace_lookup_table, (cJSON * (*)(void *))vl_api_classify_trace_lookup_table_t_tojson, 0x3f7b72e4);
   vat2_register_function("classify_trace_set_table", api_classify_trace_set_table, (cJSON * (*)(void *))vl_api_classify_trace_set_table_t_tojson, 0x3909b55a);
   vat2_register_function("classify_trace_get_tables", api_classify_trace_get_tables, (cJSON * (*)(void *))vl_api_classify_trace_get_tables_t_tojson, 0x51077d14);
   return 0;
}
