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

#include "vat2_test.api_enum.h"
#include "vat2_test.api_types.h"

#define vl_endianfun		/* define message structures */
#include "vat2_test.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "vat2_test.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "vat2_test.api.h"
#undef vl_printfun

#include "vat2_test.api_tojson.h"
#include "vat2_test.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_test_prefix (cJSON *o)
{
  vl_api_test_prefix_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_test_prefix_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_TEST_PREFIX_CRC);
  vl_api_test_prefix_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_TEST_PREFIX_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_test_prefix_reply_t *rmp = (vl_api_test_prefix_reply_t *)p;
  vl_api_test_prefix_reply_t_endian(rmp, 0);
  return vl_api_test_prefix_reply_t_tojson(rmp);
}

static cJSON *
api_test_enum (cJSON *o)
{
  vl_api_test_enum_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_test_enum_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_TEST_ENUM_CRC);
  vl_api_test_enum_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_TEST_ENUM_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_test_enum_reply_t *rmp = (vl_api_test_enum_reply_t *)p;
  vl_api_test_enum_reply_t_endian(rmp, 0);
  return vl_api_test_enum_reply_t_tojson(rmp);
}

static cJSON *
api_test_string (cJSON *o)
{
  vl_api_test_string_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_test_string_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_TEST_STRING_CRC);
  vl_api_test_string_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_TEST_STRING_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_test_string_reply_t *rmp = (vl_api_test_string_reply_t *)p;
  vl_api_test_string_reply_t_endian(rmp, 0);
  return vl_api_test_string_reply_t_tojson(rmp);
}

static cJSON *
api_test_string2 (cJSON *o)
{
  vl_api_test_string2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_test_string2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_TEST_STRING2_CRC);
  vl_api_test_string2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_TEST_STRING2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_test_string2_reply_t *rmp = (vl_api_test_string2_reply_t *)p;
  vl_api_test_string2_reply_t_endian(rmp, 0);
  return vl_api_test_string2_reply_t_tojson(rmp);
}

static cJSON *
api_test_vla (cJSON *o)
{
  vl_api_test_vla_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_test_vla_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_TEST_VLA_CRC);
  vl_api_test_vla_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_TEST_VLA_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_test_vla_reply_t *rmp = (vl_api_test_vla_reply_t *)p;
  vl_api_test_vla_reply_t_endian(rmp, 0);
  return vl_api_test_vla_reply_t_tojson(rmp);
}

static cJSON *
api_test_vla2 (cJSON *o)
{
  vl_api_test_vla2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_test_vla2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_TEST_VLA2_CRC);
  vl_api_test_vla2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_TEST_VLA2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_test_vla2_reply_t *rmp = (vl_api_test_vla2_reply_t *)p;
  vl_api_test_vla2_reply_t_endian(rmp, 0);
  return vl_api_test_vla2_reply_t_tojson(rmp);
}

static cJSON *
api_test_vla3 (cJSON *o)
{
  vl_api_test_vla3_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_test_vla3_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_TEST_VLA3_CRC);
  vl_api_test_vla3_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_TEST_VLA3_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_test_vla3_reply_t *rmp = (vl_api_test_vla3_reply_t *)p;
  vl_api_test_vla3_reply_t_endian(rmp, 0);
  return vl_api_test_vla3_reply_t_tojson(rmp);
}

static cJSON *
api_test_vla4 (cJSON *o)
{
  vl_api_test_vla4_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_test_vla4_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_TEST_VLA4_CRC);
  vl_api_test_vla4_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_TEST_VLA4_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_test_vla4_reply_t *rmp = (vl_api_test_vla4_reply_t *)p;
  vl_api_test_vla4_reply_t_endian(rmp, 0);
  return vl_api_test_vla4_reply_t_tojson(rmp);
}

static cJSON *
api_test_vla5 (cJSON *o)
{
  vl_api_test_vla5_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_test_vla5_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_TEST_VLA5_CRC);
  vl_api_test_vla5_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_TEST_VLA5_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_test_vla5_reply_t *rmp = (vl_api_test_vla5_reply_t *)p;
  vl_api_test_vla5_reply_t_endian(rmp, 0);
  return vl_api_test_vla5_reply_t_tojson(rmp);
}

static cJSON *
api_test_addresses (cJSON *o)
{
  vl_api_test_addresses_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_test_addresses_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_TEST_ADDRESSES_CRC);
  vl_api_test_addresses_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_TEST_ADDRESSES_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_test_addresses_reply_t *rmp = (vl_api_test_addresses_reply_t *)p;
  vl_api_test_addresses_reply_t_endian(rmp, 0);
  return vl_api_test_addresses_reply_t_tojson(rmp);
}

static cJSON *
api_test_addresses2 (cJSON *o)
{
  vl_api_test_addresses2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_test_addresses2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_TEST_ADDRESSES2_CRC);
  vl_api_test_addresses2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_TEST_ADDRESSES2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_test_addresses2_reply_t *rmp = (vl_api_test_addresses2_reply_t *)p;
  vl_api_test_addresses2_reply_t_endian(rmp, 0);
  return vl_api_test_addresses2_reply_t_tojson(rmp);
}

static cJSON *
api_test_addresses3 (cJSON *o)
{
  vl_api_test_addresses3_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_test_addresses3_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_TEST_ADDRESSES3_CRC);
  vl_api_test_addresses3_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_TEST_ADDRESSES3_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_test_addresses3_reply_t *rmp = (vl_api_test_addresses3_reply_t *)p;
  vl_api_test_addresses3_reply_t_endian(rmp, 0);
  return vl_api_test_addresses3_reply_t_tojson(rmp);
}

static cJSON *
api_test_empty (cJSON *o)
{
  vl_api_test_empty_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_test_empty_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_TEST_EMPTY_CRC);
  vl_api_test_empty_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_TEST_EMPTY_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_test_empty_reply_t *rmp = (vl_api_test_empty_reply_t *)p;
  vl_api_test_empty_reply_t_endian(rmp, 0);
  return vl_api_test_empty_reply_t_tojson(rmp);
}

static cJSON *
api_test_interface (cJSON *o)
{
  vl_api_test_interface_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_test_interface_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_TEST_INTERFACE_CRC);
  vl_api_test_interface_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_TEST_INTERFACE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_test_interface_reply_t *rmp = (vl_api_test_interface_reply_t *)p;
  vl_api_test_interface_reply_t_endian(rmp, 0);
  return vl_api_test_interface_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("test_prefix", api_test_prefix, (cJSON * (*)(void *))vl_api_test_prefix_t_tojson, 0xd866c1a9);
   vat2_register_function("test_enum", api_test_enum, (cJSON * (*)(void *))vl_api_test_enum_t_tojson, 0xe3190a2e);
   vat2_register_function("test_string", api_test_string, (cJSON * (*)(void *))vl_api_test_string_t_tojson, 0x3955d673);
   vat2_register_function("test_string2", api_test_string2, (cJSON * (*)(void *))vl_api_test_string2_t_tojson, 0x64a8785b);
   vat2_register_function("test_vla", api_test_vla, (cJSON * (*)(void *))vl_api_test_vla_t_tojson, 0x5d944dfc);
   vat2_register_function("test_vla2", api_test_vla2, (cJSON * (*)(void *))vl_api_test_vla2_t_tojson, 0x471f6687);
   vat2_register_function("test_vla3", api_test_vla3, (cJSON * (*)(void *))vl_api_test_vla3_t_tojson, 0xbac4a968);
   vat2_register_function("test_vla4", api_test_vla4, (cJSON * (*)(void *))vl_api_test_vla4_t_tojson, 0xc061d9d1);
   vat2_register_function("test_vla5", api_test_vla5, (cJSON * (*)(void *))vl_api_test_vla5_t_tojson, 0x09b0e1f3);
   vat2_register_function("test_addresses", api_test_addresses, (cJSON * (*)(void *))vl_api_test_addresses_t_tojson, 0x2bef955c);
   vat2_register_function("test_addresses2", api_test_addresses2, (cJSON * (*)(void *))vl_api_test_addresses2_t_tojson, 0xff01dd23);
   vat2_register_function("test_addresses3", api_test_addresses3, (cJSON * (*)(void *))vl_api_test_addresses3_t_tojson, 0x7f3e48a1);
   vat2_register_function("test_empty", api_test_empty, (cJSON * (*)(void *))vl_api_test_empty_t_tojson, 0x51077d14);
   vat2_register_function("test_interface", api_test_interface, (cJSON * (*)(void *))vl_api_test_interface_t_tojson, 0x00e34dc0);
   return 0;
}
