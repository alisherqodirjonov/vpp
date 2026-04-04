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

#include "bond.api_enum.h"
#include "bond.api_types.h"

#define vl_endianfun		/* define message structures */
#include "bond.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "bond.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "bond.api.h"
#undef vl_printfun

#include "bond.api_tojson.h"
#include "bond.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_bond_create (cJSON *o)
{
  vl_api_bond_create_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bond_create_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BOND_CREATE_CRC);
  vl_api_bond_create_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BOND_CREATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bond_create_reply_t *rmp = (vl_api_bond_create_reply_t *)p;
  vl_api_bond_create_reply_t_endian(rmp, 0);
  return vl_api_bond_create_reply_t_tojson(rmp);
}

static cJSON *
api_bond_create2 (cJSON *o)
{
  vl_api_bond_create2_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bond_create2_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BOND_CREATE2_CRC);
  vl_api_bond_create2_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BOND_CREATE2_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bond_create2_reply_t *rmp = (vl_api_bond_create2_reply_t *)p;
  vl_api_bond_create2_reply_t_endian(rmp, 0);
  return vl_api_bond_create2_reply_t_tojson(rmp);
}

static cJSON *
api_bond_delete (cJSON *o)
{
  vl_api_bond_delete_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bond_delete_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BOND_DELETE_CRC);
  vl_api_bond_delete_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BOND_DELETE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bond_delete_reply_t *rmp = (vl_api_bond_delete_reply_t *)p;
  vl_api_bond_delete_reply_t_endian(rmp, 0);
  return vl_api_bond_delete_reply_t_tojson(rmp);
}

static cJSON *
api_bond_enslave (cJSON *o)
{
  vl_api_bond_enslave_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bond_enslave_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BOND_ENSLAVE_CRC);
  vl_api_bond_enslave_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BOND_ENSLAVE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bond_enslave_reply_t *rmp = (vl_api_bond_enslave_reply_t *)p;
  vl_api_bond_enslave_reply_t_endian(rmp, 0);
  return vl_api_bond_enslave_reply_t_tojson(rmp);
}

static cJSON *
api_bond_add_member (cJSON *o)
{
  vl_api_bond_add_member_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bond_add_member_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BOND_ADD_MEMBER_CRC);
  vl_api_bond_add_member_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BOND_ADD_MEMBER_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bond_add_member_reply_t *rmp = (vl_api_bond_add_member_reply_t *)p;
  vl_api_bond_add_member_reply_t_endian(rmp, 0);
  return vl_api_bond_add_member_reply_t_tojson(rmp);
}

static cJSON *
api_bond_detach_slave (cJSON *o)
{
  vl_api_bond_detach_slave_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bond_detach_slave_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BOND_DETACH_SLAVE_CRC);
  vl_api_bond_detach_slave_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BOND_DETACH_SLAVE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bond_detach_slave_reply_t *rmp = (vl_api_bond_detach_slave_reply_t *)p;
  vl_api_bond_detach_slave_reply_t_endian(rmp, 0);
  return vl_api_bond_detach_slave_reply_t_tojson(rmp);
}

static cJSON *
api_bond_detach_member (cJSON *o)
{
  vl_api_bond_detach_member_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_bond_detach_member_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_BOND_DETACH_MEMBER_CRC);
  vl_api_bond_detach_member_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_BOND_DETACH_MEMBER_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_bond_detach_member_reply_t *rmp = (vl_api_bond_detach_member_reply_t *)p;
  vl_api_bond_detach_member_reply_t_endian(rmp, 0);
  return vl_api_bond_detach_member_reply_t_tojson(rmp);
}

static cJSON *
api_sw_interface_bond_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_BOND_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_sw_interface_bond_dump_t *mp = vl_api_sw_interface_bond_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_sw_interface_bond_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_BOND_DETAILS_CRC);

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
        if (l < sizeof(vl_api_sw_interface_bond_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_sw_interface_bond_details_t *rmp = (vl_api_sw_interface_bond_details_t *)p;
        vl_api_sw_interface_bond_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_sw_interface_bond_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_sw_bond_interface_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_SW_BOND_INTERFACE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_sw_bond_interface_dump_t *mp = vl_api_sw_bond_interface_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_sw_bond_interface_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SW_BOND_INTERFACE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_sw_bond_interface_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_sw_bond_interface_details_t *rmp = (vl_api_sw_bond_interface_details_t *)p;
        vl_api_sw_bond_interface_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_sw_bond_interface_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_sw_interface_slave_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SLAVE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_sw_interface_slave_dump_t *mp = vl_api_sw_interface_slave_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_sw_interface_slave_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SLAVE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_sw_interface_slave_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_sw_interface_slave_details_t *rmp = (vl_api_sw_interface_slave_details_t *)p;
        vl_api_sw_interface_slave_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_sw_interface_slave_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_sw_member_interface_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_SW_MEMBER_INTERFACE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_sw_member_interface_dump_t *mp = vl_api_sw_member_interface_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_sw_member_interface_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SW_MEMBER_INTERFACE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_sw_member_interface_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_sw_member_interface_details_t *rmp = (vl_api_sw_member_interface_details_t *)p;
        vl_api_sw_member_interface_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_sw_member_interface_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_sw_interface_set_bond_weight (cJSON *o)
{
  vl_api_sw_interface_set_bond_weight_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_sw_interface_set_bond_weight_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_SET_BOND_WEIGHT_CRC);
  vl_api_sw_interface_set_bond_weight_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SW_INTERFACE_SET_BOND_WEIGHT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_sw_interface_set_bond_weight_reply_t *rmp = (vl_api_sw_interface_set_bond_weight_reply_t *)p;
  vl_api_sw_interface_set_bond_weight_reply_t_endian(rmp, 0);
  return vl_api_sw_interface_set_bond_weight_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("bond_create", api_bond_create, (cJSON * (*)(void *))vl_api_bond_create_t_tojson, 0xf1dbd4ff);
   vat2_register_function("bond_create2", api_bond_create2, (cJSON * (*)(void *))vl_api_bond_create2_t_tojson, 0x912fda76);
   vat2_register_function("bond_delete", api_bond_delete, (cJSON * (*)(void *))vl_api_bond_delete_t_tojson, 0xf9e6675e);
   vat2_register_function("bond_enslave", api_bond_enslave, (cJSON * (*)(void *))vl_api_bond_enslave_t_tojson, 0xe7d14948);
   vat2_register_function("bond_add_member", api_bond_add_member, (cJSON * (*)(void *))vl_api_bond_add_member_t_tojson, 0xe7d14948);
   vat2_register_function("bond_detach_slave", api_bond_detach_slave, (cJSON * (*)(void *))vl_api_bond_detach_slave_t_tojson, 0xf9e6675e);
   vat2_register_function("bond_detach_member", api_bond_detach_member, (cJSON * (*)(void *))vl_api_bond_detach_member_t_tojson, 0xf9e6675e);
   vat2_register_function("sw_interface_bond_dump", api_sw_interface_bond_dump, (cJSON * (*)(void *))vl_api_sw_interface_bond_dump_t_tojson, 0x51077d14);
   vat2_register_function("sw_bond_interface_dump", api_sw_bond_interface_dump, (cJSON * (*)(void *))vl_api_sw_bond_interface_dump_t_tojson, 0xf9e6675e);
   vat2_register_function("sw_interface_slave_dump", api_sw_interface_slave_dump, (cJSON * (*)(void *))vl_api_sw_interface_slave_dump_t_tojson, 0xf9e6675e);
   vat2_register_function("sw_member_interface_dump", api_sw_member_interface_dump, (cJSON * (*)(void *))vl_api_sw_member_interface_dump_t_tojson, 0xf9e6675e);
   vat2_register_function("sw_interface_set_bond_weight", api_sw_interface_set_bond_weight, (cJSON * (*)(void *))vl_api_sw_interface_set_bond_weight_t_tojson, 0xdeb510a0);
   return 0;
}
