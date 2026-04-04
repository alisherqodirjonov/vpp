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

#include "dns.api_enum.h"
#include "dns.api_types.h"

#define vl_endianfun		/* define message structures */
#include "dns.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "dns.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "dns.api.h"
#undef vl_printfun

#include "dns.api_tojson.h"
#include "dns.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_dns_enable_disable (cJSON *o)
{
  vl_api_dns_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_dns_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DNS_ENABLE_DISABLE_CRC);
  vl_api_dns_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DNS_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_dns_enable_disable_reply_t *rmp = (vl_api_dns_enable_disable_reply_t *)p;
  vl_api_dns_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_dns_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_dns_name_server_add_del (cJSON *o)
{
  vl_api_dns_name_server_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_dns_name_server_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DNS_NAME_SERVER_ADD_DEL_CRC);
  vl_api_dns_name_server_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DNS_NAME_SERVER_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_dns_name_server_add_del_reply_t *rmp = (vl_api_dns_name_server_add_del_reply_t *)p;
  vl_api_dns_name_server_add_del_reply_t_endian(rmp, 0);
  return vl_api_dns_name_server_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_dns_resolve_name (cJSON *o)
{
  vl_api_dns_resolve_name_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_dns_resolve_name_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DNS_RESOLVE_NAME_CRC);
  vl_api_dns_resolve_name_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DNS_RESOLVE_NAME_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_dns_resolve_name_reply_t *rmp = (vl_api_dns_resolve_name_reply_t *)p;
  vl_api_dns_resolve_name_reply_t_endian(rmp, 0);
  return vl_api_dns_resolve_name_reply_t_tojson(rmp);
}

static cJSON *
api_dns_resolve_ip (cJSON *o)
{
  vl_api_dns_resolve_ip_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_dns_resolve_ip_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_DNS_RESOLVE_IP_CRC);
  vl_api_dns_resolve_ip_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_DNS_RESOLVE_IP_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_dns_resolve_ip_reply_t *rmp = (vl_api_dns_resolve_ip_reply_t *)p;
  vl_api_dns_resolve_ip_reply_t_endian(rmp, 0);
  return vl_api_dns_resolve_ip_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("dns_enable_disable", api_dns_enable_disable, (cJSON * (*)(void *))vl_api_dns_enable_disable_t_tojson, 0x8050327d);
   vat2_register_function("dns_name_server_add_del", api_dns_name_server_add_del, (cJSON * (*)(void *))vl_api_dns_name_server_add_del_t_tojson, 0x3bb05d8c);
   vat2_register_function("dns_resolve_name", api_dns_resolve_name, (cJSON * (*)(void *))vl_api_dns_resolve_name_t_tojson, 0xc6566676);
   vat2_register_function("dns_resolve_ip", api_dns_resolve_ip, (cJSON * (*)(void *))vl_api_dns_resolve_ip_t_tojson, 0xae96a1a3);
   return 0;
}
