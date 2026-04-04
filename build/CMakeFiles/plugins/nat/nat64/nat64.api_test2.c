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

#include "nat64.api_enum.h"
#include "nat64.api_types.h"

#define vl_endianfun		/* define message structures */
#include "nat64.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "nat64.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "nat64.api.h"
#undef vl_printfun

#include "nat64.api_tojson.h"
#include "nat64.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_nat64_plugin_enable_disable (cJSON *o)
{
  vl_api_nat64_plugin_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat64_plugin_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT64_PLUGIN_ENABLE_DISABLE_CRC);
  vl_api_nat64_plugin_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT64_PLUGIN_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat64_plugin_enable_disable_reply_t *rmp = (vl_api_nat64_plugin_enable_disable_reply_t *)p;
  vl_api_nat64_plugin_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_nat64_plugin_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_nat64_set_timeouts (cJSON *o)
{
  vl_api_nat64_set_timeouts_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat64_set_timeouts_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT64_SET_TIMEOUTS_CRC);
  vl_api_nat64_set_timeouts_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT64_SET_TIMEOUTS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat64_set_timeouts_reply_t *rmp = (vl_api_nat64_set_timeouts_reply_t *)p;
  vl_api_nat64_set_timeouts_reply_t_endian(rmp, 0);
  return vl_api_nat64_set_timeouts_reply_t_tojson(rmp);
}

static cJSON *
api_nat64_get_timeouts (cJSON *o)
{
  vl_api_nat64_get_timeouts_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat64_get_timeouts_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT64_GET_TIMEOUTS_CRC);
  vl_api_nat64_get_timeouts_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT64_GET_TIMEOUTS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat64_get_timeouts_reply_t *rmp = (vl_api_nat64_get_timeouts_reply_t *)p;
  vl_api_nat64_get_timeouts_reply_t_endian(rmp, 0);
  return vl_api_nat64_get_timeouts_reply_t_tojson(rmp);
}

static cJSON *
api_nat64_add_del_pool_addr_range (cJSON *o)
{
  vl_api_nat64_add_del_pool_addr_range_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat64_add_del_pool_addr_range_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT64_ADD_DEL_POOL_ADDR_RANGE_CRC);
  vl_api_nat64_add_del_pool_addr_range_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT64_ADD_DEL_POOL_ADDR_RANGE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat64_add_del_pool_addr_range_reply_t *rmp = (vl_api_nat64_add_del_pool_addr_range_reply_t *)p;
  vl_api_nat64_add_del_pool_addr_range_reply_t_endian(rmp, 0);
  return vl_api_nat64_add_del_pool_addr_range_reply_t_tojson(rmp);
}

static cJSON *
api_nat64_pool_addr_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT64_POOL_ADDR_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat64_pool_addr_dump_t *mp = vl_api_nat64_pool_addr_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat64_pool_addr_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT64_POOL_ADDR_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat64_pool_addr_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat64_pool_addr_details_t *rmp = (vl_api_nat64_pool_addr_details_t *)p;
        vl_api_nat64_pool_addr_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat64_pool_addr_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat64_add_del_interface (cJSON *o)
{
  vl_api_nat64_add_del_interface_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat64_add_del_interface_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT64_ADD_DEL_INTERFACE_CRC);
  vl_api_nat64_add_del_interface_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT64_ADD_DEL_INTERFACE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat64_add_del_interface_reply_t *rmp = (vl_api_nat64_add_del_interface_reply_t *)p;
  vl_api_nat64_add_del_interface_reply_t_endian(rmp, 0);
  return vl_api_nat64_add_del_interface_reply_t_tojson(rmp);
}

static cJSON *
api_nat64_interface_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT64_INTERFACE_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat64_interface_dump_t *mp = vl_api_nat64_interface_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat64_interface_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT64_INTERFACE_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat64_interface_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat64_interface_details_t *rmp = (vl_api_nat64_interface_details_t *)p;
        vl_api_nat64_interface_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat64_interface_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat64_add_del_static_bib (cJSON *o)
{
  vl_api_nat64_add_del_static_bib_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat64_add_del_static_bib_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT64_ADD_DEL_STATIC_BIB_CRC);
  vl_api_nat64_add_del_static_bib_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT64_ADD_DEL_STATIC_BIB_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat64_add_del_static_bib_reply_t *rmp = (vl_api_nat64_add_del_static_bib_reply_t *)p;
  vl_api_nat64_add_del_static_bib_reply_t_endian(rmp, 0);
  return vl_api_nat64_add_del_static_bib_reply_t_tojson(rmp);
}

static cJSON *
api_nat64_bib_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT64_BIB_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat64_bib_dump_t *mp = vl_api_nat64_bib_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat64_bib_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT64_BIB_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat64_bib_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat64_bib_details_t *rmp = (vl_api_nat64_bib_details_t *)p;
        vl_api_nat64_bib_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat64_bib_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat64_st_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT64_ST_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat64_st_dump_t *mp = vl_api_nat64_st_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat64_st_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT64_ST_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat64_st_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat64_st_details_t *rmp = (vl_api_nat64_st_details_t *)p;
        vl_api_nat64_st_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat64_st_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat64_add_del_prefix (cJSON *o)
{
  vl_api_nat64_add_del_prefix_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat64_add_del_prefix_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT64_ADD_DEL_PREFIX_CRC);
  vl_api_nat64_add_del_prefix_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT64_ADD_DEL_PREFIX_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat64_add_del_prefix_reply_t *rmp = (vl_api_nat64_add_del_prefix_reply_t *)p;
  vl_api_nat64_add_del_prefix_reply_t_endian(rmp, 0);
  return vl_api_nat64_add_del_prefix_reply_t_tojson(rmp);
}

static cJSON *
api_nat64_prefix_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_NAT64_PREFIX_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_nat64_prefix_dump_t *mp = vl_api_nat64_prefix_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_nat64_prefix_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_NAT64_PREFIX_DETAILS_CRC);

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
        if (l < sizeof(vl_api_nat64_prefix_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_nat64_prefix_details_t *rmp = (vl_api_nat64_prefix_details_t *)p;
        vl_api_nat64_prefix_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_nat64_prefix_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_nat64_add_del_interface_addr (cJSON *o)
{
  vl_api_nat64_add_del_interface_addr_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_nat64_add_del_interface_addr_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_NAT64_ADD_DEL_INTERFACE_ADDR_CRC);
  vl_api_nat64_add_del_interface_addr_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_NAT64_ADD_DEL_INTERFACE_ADDR_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_nat64_add_del_interface_addr_reply_t *rmp = (vl_api_nat64_add_del_interface_addr_reply_t *)p;
  vl_api_nat64_add_del_interface_addr_reply_t_endian(rmp, 0);
  return vl_api_nat64_add_del_interface_addr_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("nat64_plugin_enable_disable", api_nat64_plugin_enable_disable, (cJSON * (*)(void *))vl_api_nat64_plugin_enable_disable_t_tojson, 0x45948b90);
   vat2_register_function("nat64_set_timeouts", api_nat64_set_timeouts, (cJSON * (*)(void *))vl_api_nat64_set_timeouts_t_tojson, 0xd4746b16);
   vat2_register_function("nat64_get_timeouts", api_nat64_get_timeouts, (cJSON * (*)(void *))vl_api_nat64_get_timeouts_t_tojson, 0x51077d14);
   vat2_register_function("nat64_add_del_pool_addr_range", api_nat64_add_del_pool_addr_range, (cJSON * (*)(void *))vl_api_nat64_add_del_pool_addr_range_t_tojson, 0xa3b944e3);
   vat2_register_function("nat64_pool_addr_dump", api_nat64_pool_addr_dump, (cJSON * (*)(void *))vl_api_nat64_pool_addr_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat64_add_del_interface", api_nat64_add_del_interface, (cJSON * (*)(void *))vl_api_nat64_add_del_interface_t_tojson, 0xf3699b83);
   vat2_register_function("nat64_interface_dump", api_nat64_interface_dump, (cJSON * (*)(void *))vl_api_nat64_interface_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat64_add_del_static_bib", api_nat64_add_del_static_bib, (cJSON * (*)(void *))vl_api_nat64_add_del_static_bib_t_tojson, 0x1c404de5);
   vat2_register_function("nat64_bib_dump", api_nat64_bib_dump, (cJSON * (*)(void *))vl_api_nat64_bib_dump_t_tojson, 0xcfcb6b75);
   vat2_register_function("nat64_st_dump", api_nat64_st_dump, (cJSON * (*)(void *))vl_api_nat64_st_dump_t_tojson, 0xcfcb6b75);
   vat2_register_function("nat64_add_del_prefix", api_nat64_add_del_prefix, (cJSON * (*)(void *))vl_api_nat64_add_del_prefix_t_tojson, 0x727b2f4c);
   vat2_register_function("nat64_prefix_dump", api_nat64_prefix_dump, (cJSON * (*)(void *))vl_api_nat64_prefix_dump_t_tojson, 0x51077d14);
   vat2_register_function("nat64_add_del_interface_addr", api_nat64_add_del_interface_addr, (cJSON * (*)(void *))vl_api_nat64_add_del_interface_addr_t_tojson, 0x47d6e753);
   return 0;
}
