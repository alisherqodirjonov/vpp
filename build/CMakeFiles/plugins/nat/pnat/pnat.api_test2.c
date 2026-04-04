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

#include "pnat.api_enum.h"
#include "pnat.api_types.h"

#define vl_endianfun		/* define message structures */
#include "pnat.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "pnat.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "pnat.api.h"
#undef vl_printfun

#include "pnat.api_tojson.h"
#include "pnat.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_pnat_bindings_get (cJSON *o)
{
    u16 msg_id = vac_get_msg_index(VL_API_PNAT_BINDINGS_GET_CRC);
  int len = 0;
  if (!o) return 0;
  vl_api_pnat_bindings_get_t *mp = vl_api_pnat_bindings_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }
  mp->_vl_msg_id = msg_id;

  vl_api_pnat_bindings_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  cJSON *reply = cJSON_CreateArray();

  u16 reply_msg_id = vac_get_msg_index(VL_API_PNAT_BINDINGS_GET_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_PNAT_BINDINGS_DETAILS_CRC);

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
        vl_api_pnat_bindings_get_reply_t *rmp = (vl_api_pnat_bindings_get_reply_t *)p;
        vl_api_pnat_bindings_get_reply_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_pnat_bindings_get_reply_t_tojson(rmp));
        break;
    }

    if (msg_id == details_msg_id) {
        vl_api_pnat_bindings_details_t *rmp = (vl_api_pnat_bindings_details_t *)p;
        vl_api_pnat_bindings_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_pnat_bindings_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_pnat_interfaces_get (cJSON *o)
{
    u16 msg_id = vac_get_msg_index(VL_API_PNAT_INTERFACES_GET_CRC);
  int len = 0;
  if (!o) return 0;
  vl_api_pnat_interfaces_get_t *mp = vl_api_pnat_interfaces_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }
  mp->_vl_msg_id = msg_id;

  vl_api_pnat_interfaces_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  cJSON *reply = cJSON_CreateArray();

  u16 reply_msg_id = vac_get_msg_index(VL_API_PNAT_INTERFACES_GET_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_PNAT_INTERFACES_DETAILS_CRC);

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
        vl_api_pnat_interfaces_get_reply_t *rmp = (vl_api_pnat_interfaces_get_reply_t *)p;
        vl_api_pnat_interfaces_get_reply_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_pnat_interfaces_get_reply_t_tojson(rmp));
        break;
    }

    if (msg_id == details_msg_id) {
        vl_api_pnat_interfaces_details_t *rmp = (vl_api_pnat_interfaces_details_t *)p;
        vl_api_pnat_interfaces_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_pnat_interfaces_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_pnat_binding_add (cJSON *o)
{
  vl_api_pnat_binding_add_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_pnat_binding_add_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_PNAT_BINDING_ADD_CRC);
  vl_api_pnat_binding_add_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_PNAT_BINDING_ADD_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_pnat_binding_add_reply_t *rmp = (vl_api_pnat_binding_add_reply_t *)p;
  vl_api_pnat_binding_add_reply_t_endian(rmp, 0);
  return vl_api_pnat_binding_add_reply_t_tojson(rmp);
}

static cJSON *
api_pnat_binding_add_v2 (cJSON *o)
{
  vl_api_pnat_binding_add_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_pnat_binding_add_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_PNAT_BINDING_ADD_V2_CRC);
  vl_api_pnat_binding_add_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_PNAT_BINDING_ADD_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_pnat_binding_add_v2_reply_t *rmp = (vl_api_pnat_binding_add_v2_reply_t *)p;
  vl_api_pnat_binding_add_v2_reply_t_endian(rmp, 0);
  return vl_api_pnat_binding_add_v2_reply_t_tojson(rmp);
}

static cJSON *
api_pnat_binding_del (cJSON *o)
{
  vl_api_pnat_binding_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_pnat_binding_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_PNAT_BINDING_DEL_CRC);
  vl_api_pnat_binding_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_PNAT_BINDING_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_pnat_binding_del_reply_t *rmp = (vl_api_pnat_binding_del_reply_t *)p;
  vl_api_pnat_binding_del_reply_t_endian(rmp, 0);
  return vl_api_pnat_binding_del_reply_t_tojson(rmp);
}

static cJSON *
api_pnat_binding_attach (cJSON *o)
{
  vl_api_pnat_binding_attach_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_pnat_binding_attach_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_PNAT_BINDING_ATTACH_CRC);
  vl_api_pnat_binding_attach_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_PNAT_BINDING_ATTACH_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_pnat_binding_attach_reply_t *rmp = (vl_api_pnat_binding_attach_reply_t *)p;
  vl_api_pnat_binding_attach_reply_t_endian(rmp, 0);
  return vl_api_pnat_binding_attach_reply_t_tojson(rmp);
}

static cJSON *
api_pnat_binding_detach (cJSON *o)
{
  vl_api_pnat_binding_detach_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_pnat_binding_detach_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_PNAT_BINDING_DETACH_CRC);
  vl_api_pnat_binding_detach_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_PNAT_BINDING_DETACH_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_pnat_binding_detach_reply_t *rmp = (vl_api_pnat_binding_detach_reply_t *)p;
  vl_api_pnat_binding_detach_reply_t_endian(rmp, 0);
  return vl_api_pnat_binding_detach_reply_t_tojson(rmp);
}

static cJSON *
api_pnat_flow_lookup (cJSON *o)
{
  vl_api_pnat_flow_lookup_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_pnat_flow_lookup_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_PNAT_FLOW_LOOKUP_CRC);
  vl_api_pnat_flow_lookup_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_PNAT_FLOW_LOOKUP_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_pnat_flow_lookup_reply_t *rmp = (vl_api_pnat_flow_lookup_reply_t *)p;
  vl_api_pnat_flow_lookup_reply_t_endian(rmp, 0);
  return vl_api_pnat_flow_lookup_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("pnat_bindings_get", api_pnat_bindings_get, (cJSON * (*)(void *))vl_api_pnat_bindings_get_t_tojson, 0xf75ba505);
   vat2_register_function("pnat_interfaces_get", api_pnat_interfaces_get, (cJSON * (*)(void *))vl_api_pnat_interfaces_get_t_tojson, 0xf75ba505);
   vat2_register_function("pnat_binding_add", api_pnat_binding_add, (cJSON * (*)(void *))vl_api_pnat_binding_add_t_tojson, 0x946ee0b7);
   vat2_register_function("pnat_binding_add_v2", api_pnat_binding_add_v2, (cJSON * (*)(void *))vl_api_pnat_binding_add_v2_t_tojson, 0x946ee0b7);
   vat2_register_function("pnat_binding_del", api_pnat_binding_del, (cJSON * (*)(void *))vl_api_pnat_binding_del_t_tojson, 0x9259df7b);
   vat2_register_function("pnat_binding_attach", api_pnat_binding_attach, (cJSON * (*)(void *))vl_api_pnat_binding_attach_t_tojson, 0x6e074232);
   vat2_register_function("pnat_binding_detach", api_pnat_binding_detach, (cJSON * (*)(void *))vl_api_pnat_binding_detach_t_tojson, 0x6e074232);
   vat2_register_function("pnat_flow_lookup", api_pnat_flow_lookup, (cJSON * (*)(void *))vl_api_pnat_flow_lookup_t_tojson, 0x1ef8747c);
   return 0;
}
