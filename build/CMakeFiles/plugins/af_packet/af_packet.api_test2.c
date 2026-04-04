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

#include "af_packet.api_enum.h"
#include "af_packet.api_types.h"

#define vl_endianfun		/* define message structures */
#include "af_packet.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "af_packet.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "af_packet.api.h"
#undef vl_printfun

#include "af_packet.api_tojson.h"
#include "af_packet.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_af_packet_create (cJSON *o)
{
  vl_api_af_packet_create_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_af_packet_create_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_AF_PACKET_CREATE_CRC);
  vl_api_af_packet_create_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_AF_PACKET_CREATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_af_packet_create_reply_t *rmp = (vl_api_af_packet_create_reply_t *)p;
  vl_api_af_packet_create_reply_t_endian(rmp, 0);
  return vl_api_af_packet_create_reply_t_tojson(rmp);
}

static cJSON *
api_af_packet_create_v2 (cJSON *o)
{
  vl_api_af_packet_create_v2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_af_packet_create_v2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_AF_PACKET_CREATE_V2_CRC);
  vl_api_af_packet_create_v2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_AF_PACKET_CREATE_V2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_af_packet_create_v2_reply_t *rmp = (vl_api_af_packet_create_v2_reply_t *)p;
  vl_api_af_packet_create_v2_reply_t_endian(rmp, 0);
  return vl_api_af_packet_create_v2_reply_t_tojson(rmp);
}

static cJSON *
api_af_packet_create_v3 (cJSON *o)
{
  vl_api_af_packet_create_v3_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_af_packet_create_v3_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_AF_PACKET_CREATE_V3_CRC);
  vl_api_af_packet_create_v3_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_AF_PACKET_CREATE_V3_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_af_packet_create_v3_reply_t *rmp = (vl_api_af_packet_create_v3_reply_t *)p;
  vl_api_af_packet_create_v3_reply_t_endian(rmp, 0);
  return vl_api_af_packet_create_v3_reply_t_tojson(rmp);
}

static cJSON *
api_af_packet_delete (cJSON *o)
{
  vl_api_af_packet_delete_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_af_packet_delete_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_AF_PACKET_DELETE_CRC);
  vl_api_af_packet_delete_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_AF_PACKET_DELETE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_af_packet_delete_reply_t *rmp = (vl_api_af_packet_delete_reply_t *)p;
  vl_api_af_packet_delete_reply_t_endian(rmp, 0);
  return vl_api_af_packet_delete_reply_t_tojson(rmp);
}

static cJSON *
api_af_packet_set_l4_cksum_offload (cJSON *o)
{
  vl_api_af_packet_set_l4_cksum_offload_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_af_packet_set_l4_cksum_offload_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_AF_PACKET_SET_L4_CKSUM_OFFLOAD_CRC);
  vl_api_af_packet_set_l4_cksum_offload_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_AF_PACKET_SET_L4_CKSUM_OFFLOAD_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_af_packet_set_l4_cksum_offload_reply_t *rmp = (vl_api_af_packet_set_l4_cksum_offload_reply_t *)p;
  vl_api_af_packet_set_l4_cksum_offload_reply_t_endian(rmp, 0);
  return vl_api_af_packet_set_l4_cksum_offload_reply_t_tojson(rmp);
}

static cJSON *
api_af_packet_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_AF_PACKET_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_af_packet_dump_t *mp = vl_api_af_packet_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_af_packet_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_AF_PACKET_DETAILS_CRC);

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
        if (l < sizeof(vl_api_af_packet_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_af_packet_details_t *rmp = (vl_api_af_packet_details_t *)p;
        vl_api_af_packet_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_af_packet_details_t_tojson(rmp));
    }
  }
  return reply;
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("af_packet_create", api_af_packet_create, (cJSON * (*)(void *))vl_api_af_packet_create_t_tojson, 0xa190415f);
   vat2_register_function("af_packet_create_v2", api_af_packet_create_v2, (cJSON * (*)(void *))vl_api_af_packet_create_v2_t_tojson, 0x4aff0436);
   vat2_register_function("af_packet_create_v3", api_af_packet_create_v3, (cJSON * (*)(void *))vl_api_af_packet_create_v3_t_tojson, 0xb3a809d4);
   vat2_register_function("af_packet_delete", api_af_packet_delete, (cJSON * (*)(void *))vl_api_af_packet_delete_t_tojson, 0x863fa648);
   vat2_register_function("af_packet_set_l4_cksum_offload", api_af_packet_set_l4_cksum_offload, (cJSON * (*)(void *))vl_api_af_packet_set_l4_cksum_offload_t_tojson, 0x319cd5c8);
   vat2_register_function("af_packet_dump", api_af_packet_dump, (cJSON * (*)(void *))vl_api_af_packet_dump_t_tojson, 0x51077d14);
   return 0;
}
