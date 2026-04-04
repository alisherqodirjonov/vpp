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

#include "acl.api_enum.h"
#include "acl.api_types.h"

#define vl_endianfun		/* define message structures */
#include "acl.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "acl.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "acl.api.h"
#undef vl_printfun

#include "acl.api_tojson.h"
#include "acl.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_acl_plugin_get_version (cJSON *o)
{
  vl_api_acl_plugin_get_version_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_acl_plugin_get_version_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_ACL_PLUGIN_GET_VERSION_CRC);
  vl_api_acl_plugin_get_version_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_ACL_PLUGIN_GET_VERSION_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_acl_plugin_get_version_reply_t *rmp = (vl_api_acl_plugin_get_version_reply_t *)p;
  vl_api_acl_plugin_get_version_reply_t_endian(rmp, 0);
  return vl_api_acl_plugin_get_version_reply_t_tojson(rmp);
}

static cJSON *
api_acl_plugin_control_ping (cJSON *o)
{
  vl_api_acl_plugin_control_ping_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_acl_plugin_control_ping_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_ACL_PLUGIN_CONTROL_PING_CRC);
  vl_api_acl_plugin_control_ping_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_ACL_PLUGIN_CONTROL_PING_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_acl_plugin_control_ping_reply_t *rmp = (vl_api_acl_plugin_control_ping_reply_t *)p;
  vl_api_acl_plugin_control_ping_reply_t_endian(rmp, 0);
  return vl_api_acl_plugin_control_ping_reply_t_tojson(rmp);
}

static cJSON *
api_acl_plugin_get_conn_table_max_entries (cJSON *o)
{
  vl_api_acl_plugin_get_conn_table_max_entries_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_acl_plugin_get_conn_table_max_entries_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_ACL_PLUGIN_GET_CONN_TABLE_MAX_ENTRIES_CRC);
  vl_api_acl_plugin_get_conn_table_max_entries_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_ACL_PLUGIN_GET_CONN_TABLE_MAX_ENTRIES_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_acl_plugin_get_conn_table_max_entries_reply_t *rmp = (vl_api_acl_plugin_get_conn_table_max_entries_reply_t *)p;
  vl_api_acl_plugin_get_conn_table_max_entries_reply_t_endian(rmp, 0);
  return vl_api_acl_plugin_get_conn_table_max_entries_reply_t_tojson(rmp);
}

static cJSON *
api_acl_add_replace (cJSON *o)
{
  vl_api_acl_add_replace_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_acl_add_replace_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_ACL_ADD_REPLACE_CRC);
  vl_api_acl_add_replace_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_ACL_ADD_REPLACE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_acl_add_replace_reply_t *rmp = (vl_api_acl_add_replace_reply_t *)p;
  vl_api_acl_add_replace_reply_t_endian(rmp, 0);
  return vl_api_acl_add_replace_reply_t_tojson(rmp);
}

static cJSON *
api_acl_del (cJSON *o)
{
  vl_api_acl_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_acl_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_ACL_DEL_CRC);
  vl_api_acl_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_ACL_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_acl_del_reply_t *rmp = (vl_api_acl_del_reply_t *)p;
  vl_api_acl_del_reply_t_endian(rmp, 0);
  return vl_api_acl_del_reply_t_tojson(rmp);
}

static cJSON *
api_acl_interface_add_del (cJSON *o)
{
  vl_api_acl_interface_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_acl_interface_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_ACL_INTERFACE_ADD_DEL_CRC);
  vl_api_acl_interface_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_ACL_INTERFACE_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_acl_interface_add_del_reply_t *rmp = (vl_api_acl_interface_add_del_reply_t *)p;
  vl_api_acl_interface_add_del_reply_t_endian(rmp, 0);
  return vl_api_acl_interface_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_acl_interface_set_acl_list (cJSON *o)
{
  vl_api_acl_interface_set_acl_list_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_acl_interface_set_acl_list_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_ACL_INTERFACE_SET_ACL_LIST_CRC);
  vl_api_acl_interface_set_acl_list_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_ACL_INTERFACE_SET_ACL_LIST_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_acl_interface_set_acl_list_reply_t *rmp = (vl_api_acl_interface_set_acl_list_reply_t *)p;
  vl_api_acl_interface_set_acl_list_reply_t_endian(rmp, 0);
  return vl_api_acl_interface_set_acl_list_reply_t_tojson(rmp);
}

static cJSON *
api_acl_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_ACL_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_acl_dump_t *mp = vl_api_acl_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_acl_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_ACL_DETAILS_CRC);

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
        if (l < sizeof(vl_api_acl_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_acl_details_t *rmp = (vl_api_acl_details_t *)p;
        vl_api_acl_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_acl_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_acl_interface_list_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_ACL_INTERFACE_LIST_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_acl_interface_list_dump_t *mp = vl_api_acl_interface_list_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_acl_interface_list_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_ACL_INTERFACE_LIST_DETAILS_CRC);

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
        if (l < sizeof(vl_api_acl_interface_list_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_acl_interface_list_details_t *rmp = (vl_api_acl_interface_list_details_t *)p;
        vl_api_acl_interface_list_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_acl_interface_list_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_macip_acl_add (cJSON *o)
{
  vl_api_macip_acl_add_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_macip_acl_add_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MACIP_ACL_ADD_CRC);
  vl_api_macip_acl_add_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MACIP_ACL_ADD_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_macip_acl_add_reply_t *rmp = (vl_api_macip_acl_add_reply_t *)p;
  vl_api_macip_acl_add_reply_t_endian(rmp, 0);
  return vl_api_macip_acl_add_reply_t_tojson(rmp);
}

static cJSON *
api_macip_acl_add_replace (cJSON *o)
{
  vl_api_macip_acl_add_replace_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_macip_acl_add_replace_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MACIP_ACL_ADD_REPLACE_CRC);
  vl_api_macip_acl_add_replace_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MACIP_ACL_ADD_REPLACE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_macip_acl_add_replace_reply_t *rmp = (vl_api_macip_acl_add_replace_reply_t *)p;
  vl_api_macip_acl_add_replace_reply_t_endian(rmp, 0);
  return vl_api_macip_acl_add_replace_reply_t_tojson(rmp);
}

static cJSON *
api_macip_acl_del (cJSON *o)
{
  vl_api_macip_acl_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_macip_acl_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MACIP_ACL_DEL_CRC);
  vl_api_macip_acl_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MACIP_ACL_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_macip_acl_del_reply_t *rmp = (vl_api_macip_acl_del_reply_t *)p;
  vl_api_macip_acl_del_reply_t_endian(rmp, 0);
  return vl_api_macip_acl_del_reply_t_tojson(rmp);
}

static cJSON *
api_macip_acl_interface_add_del (cJSON *o)
{
  vl_api_macip_acl_interface_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_macip_acl_interface_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MACIP_ACL_INTERFACE_ADD_DEL_CRC);
  vl_api_macip_acl_interface_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MACIP_ACL_INTERFACE_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_macip_acl_interface_add_del_reply_t *rmp = (vl_api_macip_acl_interface_add_del_reply_t *)p;
  vl_api_macip_acl_interface_add_del_reply_t_endian(rmp, 0);
  return vl_api_macip_acl_interface_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_macip_acl_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_MACIP_ACL_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_macip_acl_dump_t *mp = vl_api_macip_acl_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_macip_acl_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_MACIP_ACL_DETAILS_CRC);

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
        if (l < sizeof(vl_api_macip_acl_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_macip_acl_details_t *rmp = (vl_api_macip_acl_details_t *)p;
        vl_api_macip_acl_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_macip_acl_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_macip_acl_interface_get (cJSON *o)
{
  vl_api_macip_acl_interface_get_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_macip_acl_interface_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MACIP_ACL_INTERFACE_GET_CRC);
  vl_api_macip_acl_interface_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MACIP_ACL_INTERFACE_GET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_macip_acl_interface_get_reply_t *rmp = (vl_api_macip_acl_interface_get_reply_t *)p;
  vl_api_macip_acl_interface_get_reply_t_endian(rmp, 0);
  return vl_api_macip_acl_interface_get_reply_t_tojson(rmp);
}

static cJSON *
api_macip_acl_interface_list_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_MACIP_ACL_INTERFACE_LIST_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_macip_acl_interface_list_dump_t *mp = vl_api_macip_acl_interface_list_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_macip_acl_interface_list_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_MACIP_ACL_INTERFACE_LIST_DETAILS_CRC);

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
        if (l < sizeof(vl_api_macip_acl_interface_list_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_macip_acl_interface_list_details_t *rmp = (vl_api_macip_acl_interface_list_details_t *)p;
        vl_api_macip_acl_interface_list_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_macip_acl_interface_list_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_acl_interface_set_etype_whitelist (cJSON *o)
{
  vl_api_acl_interface_set_etype_whitelist_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_acl_interface_set_etype_whitelist_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_ACL_INTERFACE_SET_ETYPE_WHITELIST_CRC);
  vl_api_acl_interface_set_etype_whitelist_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_ACL_INTERFACE_SET_ETYPE_WHITELIST_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_acl_interface_set_etype_whitelist_reply_t *rmp = (vl_api_acl_interface_set_etype_whitelist_reply_t *)p;
  vl_api_acl_interface_set_etype_whitelist_reply_t_endian(rmp, 0);
  return vl_api_acl_interface_set_etype_whitelist_reply_t_tojson(rmp);
}

static cJSON *
api_acl_interface_etype_whitelist_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_ACL_INTERFACE_ETYPE_WHITELIST_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_acl_interface_etype_whitelist_dump_t *mp = vl_api_acl_interface_etype_whitelist_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_acl_interface_etype_whitelist_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_ACL_INTERFACE_ETYPE_WHITELIST_DETAILS_CRC);

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
        if (l < sizeof(vl_api_acl_interface_etype_whitelist_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_acl_interface_etype_whitelist_details_t *rmp = (vl_api_acl_interface_etype_whitelist_details_t *)p;
        vl_api_acl_interface_etype_whitelist_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_acl_interface_etype_whitelist_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_acl_stats_intf_counters_enable (cJSON *o)
{
  vl_api_acl_stats_intf_counters_enable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_acl_stats_intf_counters_enable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_ACL_STATS_INTF_COUNTERS_ENABLE_CRC);
  vl_api_acl_stats_intf_counters_enable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_ACL_STATS_INTF_COUNTERS_ENABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_acl_stats_intf_counters_enable_reply_t *rmp = (vl_api_acl_stats_intf_counters_enable_reply_t *)p;
  vl_api_acl_stats_intf_counters_enable_reply_t_endian(rmp, 0);
  return vl_api_acl_stats_intf_counters_enable_reply_t_tojson(rmp);
}

static cJSON *
api_acl_plugin_use_hash_lookup_set (cJSON *o)
{
  vl_api_acl_plugin_use_hash_lookup_set_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_acl_plugin_use_hash_lookup_set_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_SET_CRC);
  vl_api_acl_plugin_use_hash_lookup_set_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_SET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_acl_plugin_use_hash_lookup_set_reply_t *rmp = (vl_api_acl_plugin_use_hash_lookup_set_reply_t *)p;
  vl_api_acl_plugin_use_hash_lookup_set_reply_t_endian(rmp, 0);
  return vl_api_acl_plugin_use_hash_lookup_set_reply_t_tojson(rmp);
}

static cJSON *
api_acl_plugin_use_hash_lookup_get (cJSON *o)
{
  vl_api_acl_plugin_use_hash_lookup_get_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_acl_plugin_use_hash_lookup_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_GET_CRC);
  vl_api_acl_plugin_use_hash_lookup_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_GET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_acl_plugin_use_hash_lookup_get_reply_t *rmp = (vl_api_acl_plugin_use_hash_lookup_get_reply_t *)p;
  vl_api_acl_plugin_use_hash_lookup_get_reply_t_endian(rmp, 0);
  return vl_api_acl_plugin_use_hash_lookup_get_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("acl_plugin_get_version", api_acl_plugin_get_version, (cJSON * (*)(void *))vl_api_acl_plugin_get_version_t_tojson, 0x51077d14);
   vat2_register_function("acl_plugin_control_ping", api_acl_plugin_control_ping, (cJSON * (*)(void *))vl_api_acl_plugin_control_ping_t_tojson, 0x51077d14);
   vat2_register_function("acl_plugin_get_conn_table_max_entries", api_acl_plugin_get_conn_table_max_entries, (cJSON * (*)(void *))vl_api_acl_plugin_get_conn_table_max_entries_t_tojson, 0x51077d14);
   vat2_register_function("acl_add_replace", api_acl_add_replace, (cJSON * (*)(void *))vl_api_acl_add_replace_t_tojson, 0xee5c2f18);
   vat2_register_function("acl_del", api_acl_del, (cJSON * (*)(void *))vl_api_acl_del_t_tojson, 0xef34fea4);
   vat2_register_function("acl_interface_add_del", api_acl_interface_add_del, (cJSON * (*)(void *))vl_api_acl_interface_add_del_t_tojson, 0x4b54bebd);
   vat2_register_function("acl_interface_set_acl_list", api_acl_interface_set_acl_list, (cJSON * (*)(void *))vl_api_acl_interface_set_acl_list_t_tojson, 0x473982bd);
   vat2_register_function("acl_dump", api_acl_dump, (cJSON * (*)(void *))vl_api_acl_dump_t_tojson, 0xef34fea4);
   vat2_register_function("acl_interface_list_dump", api_acl_interface_list_dump, (cJSON * (*)(void *))vl_api_acl_interface_list_dump_t_tojson, 0xf9e6675e);
   vat2_register_function("macip_acl_add", api_macip_acl_add, (cJSON * (*)(void *))vl_api_macip_acl_add_t_tojson, 0xce6fbad0);
   vat2_register_function("macip_acl_add_replace", api_macip_acl_add_replace, (cJSON * (*)(void *))vl_api_macip_acl_add_replace_t_tojson, 0x2a461dd4);
   vat2_register_function("macip_acl_del", api_macip_acl_del, (cJSON * (*)(void *))vl_api_macip_acl_del_t_tojson, 0xef34fea4);
   vat2_register_function("macip_acl_interface_add_del", api_macip_acl_interface_add_del, (cJSON * (*)(void *))vl_api_macip_acl_interface_add_del_t_tojson, 0x4b8690b1);
   vat2_register_function("macip_acl_dump", api_macip_acl_dump, (cJSON * (*)(void *))vl_api_macip_acl_dump_t_tojson, 0xef34fea4);
   vat2_register_function("macip_acl_interface_get", api_macip_acl_interface_get, (cJSON * (*)(void *))vl_api_macip_acl_interface_get_t_tojson, 0x51077d14);
   vat2_register_function("macip_acl_interface_list_dump", api_macip_acl_interface_list_dump, (cJSON * (*)(void *))vl_api_macip_acl_interface_list_dump_t_tojson, 0xf9e6675e);
   vat2_register_function("acl_interface_set_etype_whitelist", api_acl_interface_set_etype_whitelist, (cJSON * (*)(void *))vl_api_acl_interface_set_etype_whitelist_t_tojson, 0x3f5c2d2d);
   vat2_register_function("acl_interface_etype_whitelist_dump", api_acl_interface_etype_whitelist_dump, (cJSON * (*)(void *))vl_api_acl_interface_etype_whitelist_dump_t_tojson, 0xf9e6675e);
   vat2_register_function("acl_stats_intf_counters_enable", api_acl_stats_intf_counters_enable, (cJSON * (*)(void *))vl_api_acl_stats_intf_counters_enable_t_tojson, 0xb3e225d2);
   vat2_register_function("acl_plugin_use_hash_lookup_set", api_acl_plugin_use_hash_lookup_set, (cJSON * (*)(void *))vl_api_acl_plugin_use_hash_lookup_set_t_tojson, 0xb3e225d2);
   vat2_register_function("acl_plugin_use_hash_lookup_get", api_acl_plugin_use_hash_lookup_get, (cJSON * (*)(void *))vl_api_acl_plugin_use_hash_lookup_get_t_tojson, 0x51077d14);
   return 0;
}
