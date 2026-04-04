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

#include "memclnt.api_enum.h"
#include "memclnt.api_types.h"

#define vl_endianfun		/* define message structures */
#include "memclnt.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "memclnt.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "memclnt.api.h"
#undef vl_printfun

#include "memclnt.api_tojson.h"
#include "memclnt.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_memclnt_create (cJSON *o)
{
  vl_api_memclnt_create_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_memclnt_create_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MEMCLNT_CREATE_CRC);
  vl_api_memclnt_create_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MEMCLNT_CREATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_memclnt_create_reply_t *rmp = (vl_api_memclnt_create_reply_t *)p;
  vl_api_memclnt_create_reply_t_endian(rmp, 0);
  return vl_api_memclnt_create_reply_t_tojson(rmp);
}

static cJSON *
api_memclnt_delete (cJSON *o)
{
  vl_api_memclnt_delete_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_memclnt_delete_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MEMCLNT_DELETE_CRC);
  vl_api_memclnt_delete_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MEMCLNT_DELETE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_memclnt_delete_reply_t *rmp = (vl_api_memclnt_delete_reply_t *)p;
  vl_api_memclnt_delete_reply_t_endian(rmp, 0);
  return vl_api_memclnt_delete_reply_t_tojson(rmp);
}

static cJSON *
api_rpc_call (cJSON *o)
{
  vl_api_rpc_call_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_rpc_call_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_RPC_CALL_CRC);
  vl_api_rpc_call_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_RPC_CALL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_rpc_call_reply_t *rmp = (vl_api_rpc_call_reply_t *)p;
  vl_api_rpc_call_reply_t_endian(rmp, 0);
  return vl_api_rpc_call_reply_t_tojson(rmp);
}

static cJSON *
api_get_first_msg_id (cJSON *o)
{
  vl_api_get_first_msg_id_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_get_first_msg_id_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_GET_FIRST_MSG_ID_CRC);
  vl_api_get_first_msg_id_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_GET_FIRST_MSG_ID_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_get_first_msg_id_reply_t *rmp = (vl_api_get_first_msg_id_reply_t *)p;
  vl_api_get_first_msg_id_reply_t_endian(rmp, 0);
  return vl_api_get_first_msg_id_reply_t_tojson(rmp);
}

static cJSON *
api_api_versions (cJSON *o)
{
  vl_api_api_versions_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_api_versions_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_API_VERSIONS_CRC);
  vl_api_api_versions_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_API_VERSIONS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_api_versions_reply_t *rmp = (vl_api_api_versions_reply_t *)p;
  vl_api_api_versions_reply_t_endian(rmp, 0);
  return vl_api_api_versions_reply_t_tojson(rmp);
}

static cJSON *
api_sockclnt_create (cJSON *o)
{
  vl_api_sockclnt_create_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sockclnt_create_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SOCKCLNT_CREATE_CRC);
  vl_api_sockclnt_create_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SOCKCLNT_CREATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sockclnt_create_reply_t *rmp = (vl_api_sockclnt_create_reply_t *)p;
  vl_api_sockclnt_create_reply_t_endian(rmp, 0);
  return vl_api_sockclnt_create_reply_t_tojson(rmp);
}

static cJSON *
api_sockclnt_delete (cJSON *o)
{
  vl_api_sockclnt_delete_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sockclnt_delete_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SOCKCLNT_DELETE_CRC);
  vl_api_sockclnt_delete_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SOCKCLNT_DELETE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sockclnt_delete_reply_t *rmp = (vl_api_sockclnt_delete_reply_t *)p;
  vl_api_sockclnt_delete_reply_t_endian(rmp, 0);
  return vl_api_sockclnt_delete_reply_t_tojson(rmp);
}

static cJSON *
api_sock_init_shm (cJSON *o)
{
  vl_api_sock_init_shm_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sock_init_shm_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SOCK_INIT_SHM_CRC);
  vl_api_sock_init_shm_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SOCK_INIT_SHM_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sock_init_shm_reply_t *rmp = (vl_api_sock_init_shm_reply_t *)p;
  vl_api_sock_init_shm_reply_t_endian(rmp, 0);
  return vl_api_sock_init_shm_reply_t_tojson(rmp);
}

static cJSON *
api_memclnt_keepalive (cJSON *o)
{
  vl_api_memclnt_keepalive_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_memclnt_keepalive_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MEMCLNT_KEEPALIVE_CRC);
  vl_api_memclnt_keepalive_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MEMCLNT_KEEPALIVE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_memclnt_keepalive_reply_t *rmp = (vl_api_memclnt_keepalive_reply_t *)p;
  vl_api_memclnt_keepalive_reply_t_endian(rmp, 0);
  return vl_api_memclnt_keepalive_reply_t_tojson(rmp);
}

static cJSON *
api_control_ping (cJSON *o)
{
  vl_api_control_ping_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_control_ping_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_CRC);
  vl_api_control_ping_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_control_ping_reply_t *rmp = (vl_api_control_ping_reply_t *)p;
  vl_api_control_ping_reply_t_endian(rmp, 0);
  return vl_api_control_ping_reply_t_tojson(rmp);
}

static cJSON *
api_memclnt_create_v2 (cJSON *o)
{
  vl_api_memclnt_create_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_memclnt_create_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_MEMCLNT_CREATE_V2_CRC);
  vl_api_memclnt_create_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_MEMCLNT_CREATE_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_memclnt_create_v2_reply_t *rmp = (vl_api_memclnt_create_v2_reply_t *)p;
  vl_api_memclnt_create_v2_reply_t_endian(rmp, 0);
  return vl_api_memclnt_create_v2_reply_t_tojson(rmp);
}

static cJSON *
api_get_api_json (cJSON *o)
{
  vl_api_get_api_json_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_get_api_json_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_GET_API_JSON_CRC);
  vl_api_get_api_json_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_GET_API_JSON_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_get_api_json_reply_t *rmp = (vl_api_get_api_json_reply_t *)p;
  vl_api_get_api_json_reply_t_endian(rmp, 0);
  return vl_api_get_api_json_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("memclnt_create", api_memclnt_create, (cJSON * (*)(void *))vl_api_memclnt_create_t_tojson, 0x9c5e1c2f);
   vat2_register_function("memclnt_delete", api_memclnt_delete, (cJSON * (*)(void *))vl_api_memclnt_delete_t_tojson, 0x7e1c04e3);
   vat2_register_function("rpc_call", api_rpc_call, (cJSON * (*)(void *))vl_api_rpc_call_t_tojson, 0x7e8a2c95);
   vat2_register_function("get_first_msg_id", api_get_first_msg_id, (cJSON * (*)(void *))vl_api_get_first_msg_id_t_tojson, 0xebf79a66);
   vat2_register_function("api_versions", api_api_versions, (cJSON * (*)(void *))vl_api_api_versions_t_tojson, 0x51077d14);
   vat2_register_function("sockclnt_create", api_sockclnt_create, (cJSON * (*)(void *))vl_api_sockclnt_create_t_tojson, 0x455fb9c4);
   vat2_register_function("sockclnt_delete", api_sockclnt_delete, (cJSON * (*)(void *))vl_api_sockclnt_delete_t_tojson, 0x8ac76db6);
   vat2_register_function("sock_init_shm", api_sock_init_shm, (cJSON * (*)(void *))vl_api_sock_init_shm_t_tojson, 0x51646d92);
   vat2_register_function("memclnt_keepalive", api_memclnt_keepalive, (cJSON * (*)(void *))vl_api_memclnt_keepalive_t_tojson, 0x51077d14);
   vat2_register_function("control_ping", api_control_ping, (cJSON * (*)(void *))vl_api_control_ping_t_tojson, 0x51077d14);
   vat2_register_function("memclnt_create_v2", api_memclnt_create_v2, (cJSON * (*)(void *))vl_api_memclnt_create_v2_t_tojson, 0xc4bd4882);
   vat2_register_function("get_api_json", api_get_api_json, (cJSON * (*)(void *))vl_api_get_api_json_t_tojson, 0x51077d14);
   return 0;
}
