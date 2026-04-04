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

#include "lcp.api_enum.h"
#include "lcp.api_types.h"

#define vl_endianfun		/* define message structures */
#include "lcp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "lcp.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "lcp.api.h"
#undef vl_printfun

#include "lcp.api_tojson.h"
#include "lcp.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_lcp_itf_pair_get (cJSON *o)
{
    u16 msg_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_GET_CRC);
  int len = 0;
  if (!o) return 0;
  vl_api_lcp_itf_pair_get_t *mp = vl_api_lcp_itf_pair_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }
  mp->_vl_msg_id = msg_id;

  vl_api_lcp_itf_pair_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  cJSON *reply = cJSON_CreateArray();

  u16 reply_msg_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_GET_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_DETAILS_CRC);

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
        vl_api_lcp_itf_pair_get_reply_t *rmp = (vl_api_lcp_itf_pair_get_reply_t *)p;
        vl_api_lcp_itf_pair_get_reply_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_lcp_itf_pair_get_reply_t_tojson(rmp));
        break;
    }

    if (msg_id == details_msg_id) {
        vl_api_lcp_itf_pair_details_t *rmp = (vl_api_lcp_itf_pair_details_t *)p;
        vl_api_lcp_itf_pair_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_lcp_itf_pair_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_lcp_itf_pair_get_v2 (cJSON *o)
{
    u16 msg_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_GET_V2_CRC);
  int len = 0;
  if (!o) return 0;
  vl_api_lcp_itf_pair_get_v2_t *mp = vl_api_lcp_itf_pair_get_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }
  mp->_vl_msg_id = msg_id;

  vl_api_lcp_itf_pair_get_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  cJSON *reply = cJSON_CreateArray();

  u16 reply_msg_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_GET_V2_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_DETAILS_CRC);

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
        vl_api_lcp_itf_pair_get_v2_reply_t *rmp = (vl_api_lcp_itf_pair_get_v2_reply_t *)p;
        vl_api_lcp_itf_pair_get_v2_reply_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_lcp_itf_pair_get_v2_reply_t_tojson(rmp));
        break;
    }

    if (msg_id == details_msg_id) {
        vl_api_lcp_itf_pair_details_t *rmp = (vl_api_lcp_itf_pair_details_t *)p;
        vl_api_lcp_itf_pair_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_lcp_itf_pair_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_lcp_default_ns_set (cJSON *o)
{
  vl_api_lcp_default_ns_set_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lcp_default_ns_set_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LCP_DEFAULT_NS_SET_CRC);
  vl_api_lcp_default_ns_set_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LCP_DEFAULT_NS_SET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lcp_default_ns_set_reply_t *rmp = (vl_api_lcp_default_ns_set_reply_t *)p;
  vl_api_lcp_default_ns_set_reply_t_endian(rmp, 0);
  return vl_api_lcp_default_ns_set_reply_t_tojson(rmp);
}

static cJSON *
api_lcp_default_ns_get (cJSON *o)
{
  vl_api_lcp_default_ns_get_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lcp_default_ns_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LCP_DEFAULT_NS_GET_CRC);
  vl_api_lcp_default_ns_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LCP_DEFAULT_NS_GET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lcp_default_ns_get_reply_t *rmp = (vl_api_lcp_default_ns_get_reply_t *)p;
  vl_api_lcp_default_ns_get_reply_t_endian(rmp, 0);
  return vl_api_lcp_default_ns_get_reply_t_tojson(rmp);
}

static cJSON *
api_lcp_itf_pair_add_del (cJSON *o)
{
  vl_api_lcp_itf_pair_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lcp_itf_pair_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_ADD_DEL_CRC);
  vl_api_lcp_itf_pair_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LCP_ITF_PAIR_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lcp_itf_pair_add_del_reply_t *rmp = (vl_api_lcp_itf_pair_add_del_reply_t *)p;
  vl_api_lcp_itf_pair_add_del_reply_t_endian(rmp, 0);
  return vl_api_lcp_itf_pair_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_lcp_itf_pair_add_del_v2 (cJSON *o)
{
  vl_api_lcp_itf_pair_add_del_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lcp_itf_pair_add_del_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_ADD_DEL_V2_CRC);
  vl_api_lcp_itf_pair_add_del_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LCP_ITF_PAIR_ADD_DEL_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lcp_itf_pair_add_del_v2_reply_t *rmp = (vl_api_lcp_itf_pair_add_del_v2_reply_t *)p;
  vl_api_lcp_itf_pair_add_del_v2_reply_t_endian(rmp, 0);
  return vl_api_lcp_itf_pair_add_del_v2_reply_t_tojson(rmp);
}

static cJSON *
api_lcp_itf_pair_add_del_v3 (cJSON *o)
{
  vl_api_lcp_itf_pair_add_del_v3_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lcp_itf_pair_add_del_v3_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_ADD_DEL_V3_CRC);
  vl_api_lcp_itf_pair_add_del_v3_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LCP_ITF_PAIR_ADD_DEL_V3_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lcp_itf_pair_add_del_v3_reply_t *rmp = (vl_api_lcp_itf_pair_add_del_v3_reply_t *)p;
  vl_api_lcp_itf_pair_add_del_v3_reply_t_endian(rmp, 0);
  return vl_api_lcp_itf_pair_add_del_v3_reply_t_tojson(rmp);
}

static cJSON *
api_lcp_ethertype_enable (cJSON *o)
{
  vl_api_lcp_ethertype_enable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lcp_ethertype_enable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LCP_ETHERTYPE_ENABLE_CRC);
  vl_api_lcp_ethertype_enable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LCP_ETHERTYPE_ENABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lcp_ethertype_enable_reply_t *rmp = (vl_api_lcp_ethertype_enable_reply_t *)p;
  vl_api_lcp_ethertype_enable_reply_t_endian(rmp, 0);
  return vl_api_lcp_ethertype_enable_reply_t_tojson(rmp);
}

static cJSON *
api_lcp_ethertype_get (cJSON *o)
{
  vl_api_lcp_ethertype_get_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lcp_ethertype_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LCP_ETHERTYPE_GET_CRC);
  vl_api_lcp_ethertype_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LCP_ETHERTYPE_GET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lcp_ethertype_get_reply_t *rmp = (vl_api_lcp_ethertype_get_reply_t *)p;
  vl_api_lcp_ethertype_get_reply_t_endian(rmp, 0);
  return vl_api_lcp_ethertype_get_reply_t_tojson(rmp);
}

static cJSON *
api_lcp_itf_pair_replace_begin (cJSON *o)
{
  vl_api_lcp_itf_pair_replace_begin_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lcp_itf_pair_replace_begin_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_REPLACE_BEGIN_CRC);
  vl_api_lcp_itf_pair_replace_begin_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LCP_ITF_PAIR_REPLACE_BEGIN_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lcp_itf_pair_replace_begin_reply_t *rmp = (vl_api_lcp_itf_pair_replace_begin_reply_t *)p;
  vl_api_lcp_itf_pair_replace_begin_reply_t_endian(rmp, 0);
  return vl_api_lcp_itf_pair_replace_begin_reply_t_tojson(rmp);
}

static cJSON *
api_lcp_itf_pair_replace_end (cJSON *o)
{
  vl_api_lcp_itf_pair_replace_end_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_lcp_itf_pair_replace_end_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_REPLACE_END_CRC);
  vl_api_lcp_itf_pair_replace_end_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_LCP_ITF_PAIR_REPLACE_END_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_lcp_itf_pair_replace_end_reply_t *rmp = (vl_api_lcp_itf_pair_replace_end_reply_t *)p;
  vl_api_lcp_itf_pair_replace_end_reply_t_endian(rmp, 0);
  return vl_api_lcp_itf_pair_replace_end_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("lcp_itf_pair_get", api_lcp_itf_pair_get, (cJSON * (*)(void *))vl_api_lcp_itf_pair_get_t_tojson, 0xf75ba505);
   vat2_register_function("lcp_itf_pair_get_v2", api_lcp_itf_pair_get_v2, (cJSON * (*)(void *))vl_api_lcp_itf_pair_get_v2_t_tojson, 0x47250981);
   vat2_register_function("lcp_default_ns_set", api_lcp_default_ns_set, (cJSON * (*)(void *))vl_api_lcp_default_ns_set_t_tojson, 0x69749409);
   vat2_register_function("lcp_default_ns_get", api_lcp_default_ns_get, (cJSON * (*)(void *))vl_api_lcp_default_ns_get_t_tojson, 0x51077d14);
   vat2_register_function("lcp_itf_pair_add_del", api_lcp_itf_pair_add_del, (cJSON * (*)(void *))vl_api_lcp_itf_pair_add_del_t_tojson, 0x40482b80);
   vat2_register_function("lcp_itf_pair_add_del_v2", api_lcp_itf_pair_add_del_v2, (cJSON * (*)(void *))vl_api_lcp_itf_pair_add_del_v2_t_tojson, 0x40482b80);
   vat2_register_function("lcp_itf_pair_add_del_v3", api_lcp_itf_pair_add_del_v3, (cJSON * (*)(void *))vl_api_lcp_itf_pair_add_del_v3_t_tojson, 0x40482b80);
   vat2_register_function("lcp_ethertype_enable", api_lcp_ethertype_enable, (cJSON * (*)(void *))vl_api_lcp_ethertype_enable_t_tojson, 0xf893dae1);
   vat2_register_function("lcp_ethertype_get", api_lcp_ethertype_get, (cJSON * (*)(void *))vl_api_lcp_ethertype_get_t_tojson, 0x51077d14);
   vat2_register_function("lcp_itf_pair_replace_begin", api_lcp_itf_pair_replace_begin, (cJSON * (*)(void *))vl_api_lcp_itf_pair_replace_begin_t_tojson, 0x51077d14);
   vat2_register_function("lcp_itf_pair_replace_end", api_lcp_itf_pair_replace_end, (cJSON * (*)(void *))vl_api_lcp_itf_pair_replace_end_t_tojson, 0x51077d14);
   return 0;
}
