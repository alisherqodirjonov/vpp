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

#include "policer.api_enum.h"
#include "policer.api_types.h"

#define vl_endianfun		/* define message structures */
#include "policer.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "policer.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "policer.api.h"
#undef vl_printfun

#include "policer.api_tojson.h"
#include "policer.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_policer_dump_v2 (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_POLICER_DUMP_V2_CRC);
  int len;
  if (!o) return 0;
  vl_api_policer_dump_v2_t *mp = vl_api_policer_dump_v2_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_policer_dump_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_POLICER_DETAILS_CRC);

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
        if (l < sizeof(vl_api_policer_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_policer_details_t *rmp = (vl_api_policer_details_t *)p;
        vl_api_policer_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_policer_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_policer_bind (cJSON *o)
{
  vl_api_policer_bind_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_policer_bind_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_POLICER_BIND_CRC);
  vl_api_policer_bind_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_POLICER_BIND_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_policer_bind_reply_t *rmp = (vl_api_policer_bind_reply_t *)p;
  vl_api_policer_bind_reply_t_endian(rmp, 0);
  return vl_api_policer_bind_reply_t_tojson(rmp);
}

static cJSON *
api_policer_bind_v2 (cJSON *o)
{
  vl_api_policer_bind_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_policer_bind_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_POLICER_BIND_V2_CRC);
  vl_api_policer_bind_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_POLICER_BIND_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_policer_bind_v2_reply_t *rmp = (vl_api_policer_bind_v2_reply_t *)p;
  vl_api_policer_bind_v2_reply_t_endian(rmp, 0);
  return vl_api_policer_bind_v2_reply_t_tojson(rmp);
}

static cJSON *
api_policer_input (cJSON *o)
{
  vl_api_policer_input_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_policer_input_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_POLICER_INPUT_CRC);
  vl_api_policer_input_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_POLICER_INPUT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_policer_input_reply_t *rmp = (vl_api_policer_input_reply_t *)p;
  vl_api_policer_input_reply_t_endian(rmp, 0);
  return vl_api_policer_input_reply_t_tojson(rmp);
}

static cJSON *
api_policer_input_v2 (cJSON *o)
{
  vl_api_policer_input_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_policer_input_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_POLICER_INPUT_V2_CRC);
  vl_api_policer_input_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_POLICER_INPUT_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_policer_input_v2_reply_t *rmp = (vl_api_policer_input_v2_reply_t *)p;
  vl_api_policer_input_v2_reply_t_endian(rmp, 0);
  return vl_api_policer_input_v2_reply_t_tojson(rmp);
}

static cJSON *
api_policer_output (cJSON *o)
{
  vl_api_policer_output_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_policer_output_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_POLICER_OUTPUT_CRC);
  vl_api_policer_output_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_POLICER_OUTPUT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_policer_output_reply_t *rmp = (vl_api_policer_output_reply_t *)p;
  vl_api_policer_output_reply_t_endian(rmp, 0);
  return vl_api_policer_output_reply_t_tojson(rmp);
}

static cJSON *
api_policer_output_v2 (cJSON *o)
{
  vl_api_policer_output_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_policer_output_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_POLICER_OUTPUT_V2_CRC);
  vl_api_policer_output_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_POLICER_OUTPUT_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_policer_output_v2_reply_t *rmp = (vl_api_policer_output_v2_reply_t *)p;
  vl_api_policer_output_v2_reply_t_endian(rmp, 0);
  return vl_api_policer_output_v2_reply_t_tojson(rmp);
}

static cJSON *
api_policer_add_del (cJSON *o)
{
  vl_api_policer_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_policer_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_POLICER_ADD_DEL_CRC);
  vl_api_policer_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_POLICER_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_policer_add_del_reply_t *rmp = (vl_api_policer_add_del_reply_t *)p;
  vl_api_policer_add_del_reply_t_endian(rmp, 0);
  return vl_api_policer_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_policer_add (cJSON *o)
{
  vl_api_policer_add_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_policer_add_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_POLICER_ADD_CRC);
  vl_api_policer_add_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_POLICER_ADD_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_policer_add_reply_t *rmp = (vl_api_policer_add_reply_t *)p;
  vl_api_policer_add_reply_t_endian(rmp, 0);
  return vl_api_policer_add_reply_t_tojson(rmp);
}

static cJSON *
api_policer_del (cJSON *o)
{
  vl_api_policer_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_policer_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_POLICER_DEL_CRC);
  vl_api_policer_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_POLICER_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_policer_del_reply_t *rmp = (vl_api_policer_del_reply_t *)p;
  vl_api_policer_del_reply_t_endian(rmp, 0);
  return vl_api_policer_del_reply_t_tojson(rmp);
}

static cJSON *
api_policer_update (cJSON *o)
{
  vl_api_policer_update_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_policer_update_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_POLICER_UPDATE_CRC);
  vl_api_policer_update_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_POLICER_UPDATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_policer_update_reply_t *rmp = (vl_api_policer_update_reply_t *)p;
  vl_api_policer_update_reply_t_endian(rmp, 0);
  return vl_api_policer_update_reply_t_tojson(rmp);
}

static cJSON *
api_policer_reset (cJSON *o)
{
  vl_api_policer_reset_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_policer_reset_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_POLICER_RESET_CRC);
  vl_api_policer_reset_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_POLICER_RESET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_policer_reset_reply_t *rmp = (vl_api_policer_reset_reply_t *)p;
  vl_api_policer_reset_reply_t_endian(rmp, 0);
  return vl_api_policer_reset_reply_t_tojson(rmp);
}

static cJSON *
api_policer_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_POLICER_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_policer_dump_t *mp = vl_api_policer_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_policer_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_POLICER_DETAILS_CRC);

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
        if (l < sizeof(vl_api_policer_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_policer_details_t *rmp = (vl_api_policer_details_t *)p;
        vl_api_policer_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_policer_details_t_tojson(rmp));
    }
  }
  return reply;
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("policer_dump_v2", api_policer_dump_v2, (cJSON * (*)(void *))vl_api_policer_dump_v2_t_tojson, 0x7ff7912e);
   vat2_register_function("policer_bind", api_policer_bind, (cJSON * (*)(void *))vl_api_policer_bind_t_tojson, 0xdcf516f9);
   vat2_register_function("policer_bind_v2", api_policer_bind_v2, (cJSON * (*)(void *))vl_api_policer_bind_v2_t_tojson, 0xf87bd3c0);
   vat2_register_function("policer_input", api_policer_input, (cJSON * (*)(void *))vl_api_policer_input_t_tojson, 0x233f0ef5);
   vat2_register_function("policer_input_v2", api_policer_input_v2, (cJSON * (*)(void *))vl_api_policer_input_v2_t_tojson, 0x8388eb84);
   vat2_register_function("policer_output", api_policer_output, (cJSON * (*)(void *))vl_api_policer_output_t_tojson, 0x233f0ef5);
   vat2_register_function("policer_output_v2", api_policer_output_v2, (cJSON * (*)(void *))vl_api_policer_output_v2_t_tojson, 0x8388eb84);
   vat2_register_function("policer_add_del", api_policer_add_del, (cJSON * (*)(void *))vl_api_policer_add_del_t_tojson, 0x2b31dd38);
   vat2_register_function("policer_add", api_policer_add, (cJSON * (*)(void *))vl_api_policer_add_t_tojson, 0x4d949e35);
   vat2_register_function("policer_del", api_policer_del, (cJSON * (*)(void *))vl_api_policer_del_t_tojson, 0x7ff7912e);
   vat2_register_function("policer_update", api_policer_update, (cJSON * (*)(void *))vl_api_policer_update_t_tojson, 0xfd039ef0);
   vat2_register_function("policer_reset", api_policer_reset, (cJSON * (*)(void *))vl_api_policer_reset_t_tojson, 0x7ff7912e);
   vat2_register_function("policer_dump", api_policer_dump, (cJSON * (*)(void *))vl_api_policer_dump_t_tojson, 0x35f1ae0f);
   return 0;
}
