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

#include "igmp.api_enum.h"
#include "igmp.api_types.h"

#define vl_endianfun		/* define message structures */
#include "igmp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "igmp.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "igmp.api.h"
#undef vl_printfun

#include "igmp.api_tojson.h"
#include "igmp.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_want_igmp_events (cJSON *o)
{
  vl_api_want_igmp_events_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_want_igmp_events_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_WANT_IGMP_EVENTS_CRC);
  vl_api_want_igmp_events_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_WANT_IGMP_EVENTS_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_want_igmp_events_reply_t *rmp = (vl_api_want_igmp_events_reply_t *)p;
  vl_api_want_igmp_events_reply_t_endian(rmp, 0);
  return vl_api_want_igmp_events_reply_t_tojson(rmp);
}

static cJSON *
api_igmp_listen (cJSON *o)
{
  vl_api_igmp_listen_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_igmp_listen_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IGMP_LISTEN_CRC);
  vl_api_igmp_listen_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IGMP_LISTEN_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_igmp_listen_reply_t *rmp = (vl_api_igmp_listen_reply_t *)p;
  vl_api_igmp_listen_reply_t_endian(rmp, 0);
  return vl_api_igmp_listen_reply_t_tojson(rmp);
}

static cJSON *
api_igmp_enable_disable (cJSON *o)
{
  vl_api_igmp_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_igmp_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IGMP_ENABLE_DISABLE_CRC);
  vl_api_igmp_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IGMP_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_igmp_enable_disable_reply_t *rmp = (vl_api_igmp_enable_disable_reply_t *)p;
  vl_api_igmp_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_igmp_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_igmp_proxy_device_add_del (cJSON *o)
{
  vl_api_igmp_proxy_device_add_del_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_igmp_proxy_device_add_del_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IGMP_PROXY_DEVICE_ADD_DEL_CRC);
  vl_api_igmp_proxy_device_add_del_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IGMP_PROXY_DEVICE_ADD_DEL_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_igmp_proxy_device_add_del_reply_t *rmp = (vl_api_igmp_proxy_device_add_del_reply_t *)p;
  vl_api_igmp_proxy_device_add_del_reply_t_endian(rmp, 0);
  return vl_api_igmp_proxy_device_add_del_reply_t_tojson(rmp);
}

static cJSON *
api_igmp_proxy_device_add_del_interface (cJSON *o)
{
  vl_api_igmp_proxy_device_add_del_interface_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_igmp_proxy_device_add_del_interface_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IGMP_PROXY_DEVICE_ADD_DEL_INTERFACE_CRC);
  vl_api_igmp_proxy_device_add_del_interface_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IGMP_PROXY_DEVICE_ADD_DEL_INTERFACE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_igmp_proxy_device_add_del_interface_reply_t *rmp = (vl_api_igmp_proxy_device_add_del_interface_reply_t *)p;
  vl_api_igmp_proxy_device_add_del_interface_reply_t_endian(rmp, 0);
  return vl_api_igmp_proxy_device_add_del_interface_reply_t_tojson(rmp);
}

static cJSON *
api_igmp_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IGMP_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_igmp_dump_t *mp = vl_api_igmp_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_igmp_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IGMP_DETAILS_CRC);

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
        if (l < sizeof(vl_api_igmp_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_igmp_details_t *rmp = (vl_api_igmp_details_t *)p;
        vl_api_igmp_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_igmp_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_igmp_clear_interface (cJSON *o)
{
  vl_api_igmp_clear_interface_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_igmp_clear_interface_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IGMP_CLEAR_INTERFACE_CRC);
  vl_api_igmp_clear_interface_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IGMP_CLEAR_INTERFACE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_igmp_clear_interface_reply_t *rmp = (vl_api_igmp_clear_interface_reply_t *)p;
  vl_api_igmp_clear_interface_reply_t_endian(rmp, 0);
  return vl_api_igmp_clear_interface_reply_t_tojson(rmp);
}

static cJSON *
api_igmp_group_prefix_set (cJSON *o)
{
  vl_api_igmp_group_prefix_set_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_igmp_group_prefix_set_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_IGMP_GROUP_PREFIX_SET_CRC);
  vl_api_igmp_group_prefix_set_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_IGMP_GROUP_PREFIX_SET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_igmp_group_prefix_set_reply_t *rmp = (vl_api_igmp_group_prefix_set_reply_t *)p;
  vl_api_igmp_group_prefix_set_reply_t_endian(rmp, 0);
  return vl_api_igmp_group_prefix_set_reply_t_tojson(rmp);
}

static cJSON *
api_igmp_group_prefix_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_IGMP_GROUP_PREFIX_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_igmp_group_prefix_dump_t *mp = vl_api_igmp_group_prefix_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_igmp_group_prefix_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_IGMP_GROUP_PREFIX_DETAILS_CRC);

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
        if (l < sizeof(vl_api_igmp_group_prefix_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_igmp_group_prefix_details_t *rmp = (vl_api_igmp_group_prefix_details_t *)p;
        vl_api_igmp_group_prefix_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_igmp_group_prefix_details_t_tojson(rmp));
    }
  }
  return reply;
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("want_igmp_events", api_want_igmp_events, (cJSON * (*)(void *))vl_api_want_igmp_events_t_tojson, 0xcfaccc1f);
   vat2_register_function("igmp_listen", api_igmp_listen, (cJSON * (*)(void *))vl_api_igmp_listen_t_tojson, 0x19a49f1e);
   vat2_register_function("igmp_enable_disable", api_igmp_enable_disable, (cJSON * (*)(void *))vl_api_igmp_enable_disable_t_tojson, 0xb1edfb96);
   vat2_register_function("igmp_proxy_device_add_del", api_igmp_proxy_device_add_del, (cJSON * (*)(void *))vl_api_igmp_proxy_device_add_del_t_tojson, 0x0b9be9ce);
   vat2_register_function("igmp_proxy_device_add_del_interface", api_igmp_proxy_device_add_del_interface, (cJSON * (*)(void *))vl_api_igmp_proxy_device_add_del_interface_t_tojson, 0x1a9ec24a);
   vat2_register_function("igmp_dump", api_igmp_dump, (cJSON * (*)(void *))vl_api_igmp_dump_t_tojson, 0xf9e6675e);
   vat2_register_function("igmp_clear_interface", api_igmp_clear_interface, (cJSON * (*)(void *))vl_api_igmp_clear_interface_t_tojson, 0xf9e6675e);
   vat2_register_function("igmp_group_prefix_set", api_igmp_group_prefix_set, (cJSON * (*)(void *))vl_api_igmp_group_prefix_set_t_tojson, 0x5b14a5ce);
   vat2_register_function("igmp_group_prefix_dump", api_igmp_group_prefix_dump, (cJSON * (*)(void *))vl_api_igmp_group_prefix_dump_t_tojson, 0x51077d14);
   return 0;
}
