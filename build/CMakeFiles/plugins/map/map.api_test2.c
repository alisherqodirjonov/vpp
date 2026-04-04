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

#include "map.api_enum.h"
#include "map.api_types.h"

#define vl_endianfun		/* define message structures */
#include "map.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "map.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "map.api.h"
#undef vl_printfun

#include "map.api_tojson.h"
#include "map.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_map_domains_get (cJSON *o)
{
    u16 msg_id = vac_get_msg_index(VL_API_MAP_DOMAINS_GET_CRC);
  int len = 0;
  if (!o) return 0;
  vl_api_map_domains_get_t *mp = vl_api_map_domains_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }
  mp->_vl_msg_id = msg_id;

  vl_api_map_domains_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  cJSON *reply = cJSON_CreateArray();

  u16 reply_msg_id = vac_get_msg_index(VL_API_MAP_DOMAINS_GET_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_MAP_DOMAIN_DETAILS_CRC);

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
        vl_api_map_domains_get_reply_t *rmp = (vl_api_map_domains_get_reply_t *)p;
        vl_api_map_domains_get_reply_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_map_domains_get_reply_t_tojson(rmp));
        break;
    }

    if (msg_id == details_msg_id) {
        vl_api_map_domain_details_t *rmp = (vl_api_map_domain_details_t *)p;
        vl_api_map_domain_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_map_domain_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_map_add_domain (cJSON *o)
{
  vl_api_map_add_domain_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_map_add_domain_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MAP_ADD_DOMAIN_CRC);
  vl_api_map_add_domain_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MAP_ADD_DOMAIN_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_map_add_domain_reply_t *rmp = (vl_api_map_add_domain_reply_t *)p;
  vl_api_map_add_domain_reply_t_endian(rmp, 0);
  return vl_api_map_add_domain_reply_t_tojson(rmp);
}

static cJSON *
api_map_del_domain (cJSON *o)
{
  vl_api_map_del_domain_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_map_del_domain_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MAP_DEL_DOMAIN_CRC);
  vl_api_map_del_domain_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MAP_DEL_DOMAIN_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_map_del_domain_reply_t *rmp = (vl_api_map_del_domain_reply_t *)p;
  vl_api_map_del_domain_reply_t_endian(rmp, 0);
  return vl_api_map_del_domain_reply_t_tojson(rmp);
}

static cJSON *
api_map_add_del_rule (cJSON *o)
{
  vl_api_map_add_del_rule_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_map_add_del_rule_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MAP_ADD_DEL_RULE_CRC);
  vl_api_map_add_del_rule_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MAP_ADD_DEL_RULE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_map_add_del_rule_reply_t *rmp = (vl_api_map_add_del_rule_reply_t *)p;
  vl_api_map_add_del_rule_reply_t_endian(rmp, 0);
  return vl_api_map_add_del_rule_reply_t_tojson(rmp);
}

static cJSON *
api_map_domain_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_MAP_DOMAIN_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_map_domain_dump_t *mp = vl_api_map_domain_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_map_domain_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_MAP_DOMAIN_DETAILS_CRC);

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
        if (l < sizeof(vl_api_map_domain_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_map_domain_details_t *rmp = (vl_api_map_domain_details_t *)p;
        vl_api_map_domain_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_map_domain_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_map_rule_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_MAP_RULE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_map_rule_dump_t *mp = vl_api_map_rule_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_map_rule_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_MAP_RULE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_map_rule_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_map_rule_details_t *rmp = (vl_api_map_rule_details_t *)p;
        vl_api_map_rule_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_map_rule_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_map_if_enable_disable (cJSON *o)
{
  vl_api_map_if_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_map_if_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MAP_IF_ENABLE_DISABLE_CRC);
  vl_api_map_if_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MAP_IF_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_map_if_enable_disable_reply_t *rmp = (vl_api_map_if_enable_disable_reply_t *)p;
  vl_api_map_if_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_map_if_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_map_summary_stats (cJSON *o)
{
  vl_api_map_summary_stats_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_map_summary_stats_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MAP_SUMMARY_STATS_CRC);
  vl_api_map_summary_stats_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MAP_SUMMARY_STATS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_map_summary_stats_reply_t *rmp = (vl_api_map_summary_stats_reply_t *)p;
  vl_api_map_summary_stats_reply_t_endian(rmp, 0);
  return vl_api_map_summary_stats_reply_t_tojson(rmp);
}

static cJSON *
api_map_param_set_fragmentation (cJSON *o)
{
  vl_api_map_param_set_fragmentation_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_map_param_set_fragmentation_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MAP_PARAM_SET_FRAGMENTATION_CRC);
  vl_api_map_param_set_fragmentation_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MAP_PARAM_SET_FRAGMENTATION_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_map_param_set_fragmentation_reply_t *rmp = (vl_api_map_param_set_fragmentation_reply_t *)p;
  vl_api_map_param_set_fragmentation_reply_t_endian(rmp, 0);
  return vl_api_map_param_set_fragmentation_reply_t_tojson(rmp);
}

static cJSON *
api_map_param_set_icmp (cJSON *o)
{
  vl_api_map_param_set_icmp_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_map_param_set_icmp_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MAP_PARAM_SET_ICMP_CRC);
  vl_api_map_param_set_icmp_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MAP_PARAM_SET_ICMP_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_map_param_set_icmp_reply_t *rmp = (vl_api_map_param_set_icmp_reply_t *)p;
  vl_api_map_param_set_icmp_reply_t_endian(rmp, 0);
  return vl_api_map_param_set_icmp_reply_t_tojson(rmp);
}

static cJSON *
api_map_param_set_icmp6 (cJSON *o)
{
  vl_api_map_param_set_icmp6_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_map_param_set_icmp6_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MAP_PARAM_SET_ICMP6_CRC);
  vl_api_map_param_set_icmp6_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MAP_PARAM_SET_ICMP6_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_map_param_set_icmp6_reply_t *rmp = (vl_api_map_param_set_icmp6_reply_t *)p;
  vl_api_map_param_set_icmp6_reply_t_endian(rmp, 0);
  return vl_api_map_param_set_icmp6_reply_t_tojson(rmp);
}

static cJSON *
api_map_param_add_del_pre_resolve (cJSON *o)
{
  vl_api_map_param_add_del_pre_resolve_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_map_param_add_del_pre_resolve_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MAP_PARAM_ADD_DEL_PRE_RESOLVE_CRC);
  vl_api_map_param_add_del_pre_resolve_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MAP_PARAM_ADD_DEL_PRE_RESOLVE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_map_param_add_del_pre_resolve_reply_t *rmp = (vl_api_map_param_add_del_pre_resolve_reply_t *)p;
  vl_api_map_param_add_del_pre_resolve_reply_t_endian(rmp, 0);
  return vl_api_map_param_add_del_pre_resolve_reply_t_tojson(rmp);
}

static cJSON *
api_map_param_set_security_check (cJSON *o)
{
  vl_api_map_param_set_security_check_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_map_param_set_security_check_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MAP_PARAM_SET_SECURITY_CHECK_CRC);
  vl_api_map_param_set_security_check_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MAP_PARAM_SET_SECURITY_CHECK_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_map_param_set_security_check_reply_t *rmp = (vl_api_map_param_set_security_check_reply_t *)p;
  vl_api_map_param_set_security_check_reply_t_endian(rmp, 0);
  return vl_api_map_param_set_security_check_reply_t_tojson(rmp);
}

static cJSON *
api_map_param_set_traffic_class (cJSON *o)
{
  vl_api_map_param_set_traffic_class_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_map_param_set_traffic_class_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MAP_PARAM_SET_TRAFFIC_CLASS_CRC);
  vl_api_map_param_set_traffic_class_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MAP_PARAM_SET_TRAFFIC_CLASS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_map_param_set_traffic_class_reply_t *rmp = (vl_api_map_param_set_traffic_class_reply_t *)p;
  vl_api_map_param_set_traffic_class_reply_t_endian(rmp, 0);
  return vl_api_map_param_set_traffic_class_reply_t_tojson(rmp);
}

static cJSON *
api_map_param_set_tcp (cJSON *o)
{
  vl_api_map_param_set_tcp_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_map_param_set_tcp_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MAP_PARAM_SET_TCP_CRC);
  vl_api_map_param_set_tcp_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MAP_PARAM_SET_TCP_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_map_param_set_tcp_reply_t *rmp = (vl_api_map_param_set_tcp_reply_t *)p;
  vl_api_map_param_set_tcp_reply_t_endian(rmp, 0);
  return vl_api_map_param_set_tcp_reply_t_tojson(rmp);
}

static cJSON *
api_map_param_get (cJSON *o)
{
  vl_api_map_param_get_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_map_param_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MAP_PARAM_GET_CRC);
  vl_api_map_param_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MAP_PARAM_GET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_map_param_get_reply_t *rmp = (vl_api_map_param_get_reply_t *)p;
  vl_api_map_param_get_reply_t_endian(rmp, 0);
  return vl_api_map_param_get_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("map_domains_get", api_map_domains_get, (cJSON * (*)(void *))vl_api_map_domains_get_t_tojson, 0xf75ba505);
   vat2_register_function("map_add_domain", api_map_add_domain, (cJSON * (*)(void *))vl_api_map_add_domain_t_tojson, 0x249f195c);
   vat2_register_function("map_del_domain", api_map_del_domain, (cJSON * (*)(void *))vl_api_map_del_domain_t_tojson, 0x8ac76db6);
   vat2_register_function("map_add_del_rule", api_map_add_del_rule, (cJSON * (*)(void *))vl_api_map_add_del_rule_t_tojson, 0xc65b32f7);
   vat2_register_function("map_domain_dump", api_map_domain_dump, (cJSON * (*)(void *))vl_api_map_domain_dump_t_tojson, 0x51077d14);
   vat2_register_function("map_rule_dump", api_map_rule_dump, (cJSON * (*)(void *))vl_api_map_rule_dump_t_tojson, 0xe43e6ff6);
   vat2_register_function("map_if_enable_disable", api_map_if_enable_disable, (cJSON * (*)(void *))vl_api_map_if_enable_disable_t_tojson, 0x59bb32f4);
   vat2_register_function("map_summary_stats", api_map_summary_stats, (cJSON * (*)(void *))vl_api_map_summary_stats_t_tojson, 0x51077d14);
   vat2_register_function("map_param_set_fragmentation", api_map_param_set_fragmentation, (cJSON * (*)(void *))vl_api_map_param_set_fragmentation_t_tojson, 0x9ff54d90);
   vat2_register_function("map_param_set_icmp", api_map_param_set_icmp, (cJSON * (*)(void *))vl_api_map_param_set_icmp_t_tojson, 0x58210cbf);
   vat2_register_function("map_param_set_icmp6", api_map_param_set_icmp6, (cJSON * (*)(void *))vl_api_map_param_set_icmp6_t_tojson, 0x5d01f8c1);
   vat2_register_function("map_param_add_del_pre_resolve", api_map_param_add_del_pre_resolve, (cJSON * (*)(void *))vl_api_map_param_add_del_pre_resolve_t_tojson, 0xdae5af03);
   vat2_register_function("map_param_set_security_check", api_map_param_set_security_check, (cJSON * (*)(void *))vl_api_map_param_set_security_check_t_tojson, 0x6abe9836);
   vat2_register_function("map_param_set_traffic_class", api_map_param_set_traffic_class, (cJSON * (*)(void *))vl_api_map_param_set_traffic_class_t_tojson, 0x9cac455c);
   vat2_register_function("map_param_set_tcp", api_map_param_set_tcp, (cJSON * (*)(void *))vl_api_map_param_set_tcp_t_tojson, 0x87a825d9);
   vat2_register_function("map_param_get", api_map_param_get, (cJSON * (*)(void *))vl_api_map_param_get_t_tojson, 0x51077d14);
   return 0;
}
