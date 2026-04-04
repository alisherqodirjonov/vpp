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

#include "pg.api_enum.h"
#include "pg.api_types.h"

#define vl_endianfun		/* define message structures */
#include "pg.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "pg.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "pg.api.h"
#undef vl_printfun

#include "pg.api_tojson.h"
#include "pg.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_pg_create_interface (cJSON *o)
{
  vl_api_pg_create_interface_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_pg_create_interface_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_PG_CREATE_INTERFACE_CRC);
  vl_api_pg_create_interface_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_PG_CREATE_INTERFACE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_pg_create_interface_reply_t *rmp = (vl_api_pg_create_interface_reply_t *)p;
  vl_api_pg_create_interface_reply_t_endian(rmp, 0);
  return vl_api_pg_create_interface_reply_t_tojson(rmp);
}

static cJSON *
api_pg_create_interface_v2 (cJSON *o)
{
  vl_api_pg_create_interface_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_pg_create_interface_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_PG_CREATE_INTERFACE_V2_CRC);
  vl_api_pg_create_interface_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_PG_CREATE_INTERFACE_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_pg_create_interface_v2_reply_t *rmp = (vl_api_pg_create_interface_v2_reply_t *)p;
  vl_api_pg_create_interface_v2_reply_t_endian(rmp, 0);
  return vl_api_pg_create_interface_v2_reply_t_tojson(rmp);
}

static cJSON *
api_pg_create_interface_v3 (cJSON *o)
{
  vl_api_pg_create_interface_v3_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_pg_create_interface_v3_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_PG_CREATE_INTERFACE_V3_CRC);
  vl_api_pg_create_interface_v3_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_PG_CREATE_INTERFACE_V3_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_pg_create_interface_v3_reply_t *rmp = (vl_api_pg_create_interface_v3_reply_t *)p;
  vl_api_pg_create_interface_v3_reply_t_endian(rmp, 0);
  return vl_api_pg_create_interface_v3_reply_t_tojson(rmp);
}

static cJSON *
api_pg_delete_interface (cJSON *o)
{
  vl_api_pg_delete_interface_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_pg_delete_interface_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_PG_DELETE_INTERFACE_CRC);
  vl_api_pg_delete_interface_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_PG_DELETE_INTERFACE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_pg_delete_interface_reply_t *rmp = (vl_api_pg_delete_interface_reply_t *)p;
  vl_api_pg_delete_interface_reply_t_endian(rmp, 0);
  return vl_api_pg_delete_interface_reply_t_tojson(rmp);
}

static cJSON *
api_pg_interface_enable_disable_coalesce (cJSON *o)
{
  vl_api_pg_interface_enable_disable_coalesce_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_pg_interface_enable_disable_coalesce_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_PG_INTERFACE_ENABLE_DISABLE_COALESCE_CRC);
  vl_api_pg_interface_enable_disable_coalesce_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_PG_INTERFACE_ENABLE_DISABLE_COALESCE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_pg_interface_enable_disable_coalesce_reply_t *rmp = (vl_api_pg_interface_enable_disable_coalesce_reply_t *)p;
  vl_api_pg_interface_enable_disable_coalesce_reply_t_endian(rmp, 0);
  return vl_api_pg_interface_enable_disable_coalesce_reply_t_tojson(rmp);
}

static cJSON *
api_pg_capture (cJSON *o)
{
  vl_api_pg_capture_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_pg_capture_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_PG_CAPTURE_CRC);
  vl_api_pg_capture_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_PG_CAPTURE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_pg_capture_reply_t *rmp = (vl_api_pg_capture_reply_t *)p;
  vl_api_pg_capture_reply_t_endian(rmp, 0);
  return vl_api_pg_capture_reply_t_tojson(rmp);
}

static cJSON *
api_pg_enable_disable (cJSON *o)
{
  vl_api_pg_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_pg_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_PG_ENABLE_DISABLE_CRC);
  vl_api_pg_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_PG_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_pg_enable_disable_reply_t *rmp = (vl_api_pg_enable_disable_reply_t *)p;
  vl_api_pg_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_pg_enable_disable_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("pg_create_interface", api_pg_create_interface, (cJSON * (*)(void *))vl_api_pg_create_interface_t_tojson, 0xb7c893d7);
   vat2_register_function("pg_create_interface_v2", api_pg_create_interface_v2, (cJSON * (*)(void *))vl_api_pg_create_interface_v2_t_tojson, 0x8657466a);
   vat2_register_function("pg_create_interface_v3", api_pg_create_interface_v3, (cJSON * (*)(void *))vl_api_pg_create_interface_v3_t_tojson, 0xb2aac653);
   vat2_register_function("pg_delete_interface", api_pg_delete_interface, (cJSON * (*)(void *))vl_api_pg_delete_interface_t_tojson, 0xf9e6675e);
   vat2_register_function("pg_interface_enable_disable_coalesce", api_pg_interface_enable_disable_coalesce, (cJSON * (*)(void *))vl_api_pg_interface_enable_disable_coalesce_t_tojson, 0xa2ef99e7);
   vat2_register_function("pg_capture", api_pg_capture, (cJSON * (*)(void *))vl_api_pg_capture_t_tojson, 0x3712fb6c);
   vat2_register_function("pg_enable_disable", api_pg_enable_disable, (cJSON * (*)(void *))vl_api_pg_enable_disable_t_tojson, 0x01f94f3a);
   return 0;
}
