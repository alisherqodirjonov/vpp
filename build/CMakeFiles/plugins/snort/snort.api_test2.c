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

#include "snort.api_enum.h"
#include "snort.api_types.h"

#define vl_endianfun		/* define message structures */
#include "snort.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "snort.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "snort.api.h"
#undef vl_printfun

#include "snort.api_tojson.h"
#include "snort.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_snort_instance_get (cJSON *o)
{
    u16 msg_id = vac_get_msg_index(VL_API_SNORT_INSTANCE_GET_CRC);
  int len = 0;
  if (!o) return 0;
  vl_api_snort_instance_get_t *mp = vl_api_snort_instance_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }
  mp->_vl_msg_id = msg_id;

  vl_api_snort_instance_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  cJSON *reply = cJSON_CreateArray();

  u16 reply_msg_id = vac_get_msg_index(VL_API_SNORT_INSTANCE_GET_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SNORT_INSTANCE_DETAILS_CRC);

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
        vl_api_snort_instance_get_reply_t *rmp = (vl_api_snort_instance_get_reply_t *)p;
        vl_api_snort_instance_get_reply_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_snort_instance_get_reply_t_tojson(rmp));
        break;
    }

    if (msg_id == details_msg_id) {
        vl_api_snort_instance_details_t *rmp = (vl_api_snort_instance_details_t *)p;
        vl_api_snort_instance_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_snort_instance_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_snort_interface_get (cJSON *o)
{
    u16 msg_id = vac_get_msg_index(VL_API_SNORT_INTERFACE_GET_CRC);
  int len = 0;
  if (!o) return 0;
  vl_api_snort_interface_get_t *mp = vl_api_snort_interface_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }
  mp->_vl_msg_id = msg_id;

  vl_api_snort_interface_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  cJSON *reply = cJSON_CreateArray();

  u16 reply_msg_id = vac_get_msg_index(VL_API_SNORT_INTERFACE_GET_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SNORT_INTERFACE_DETAILS_CRC);

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
        vl_api_snort_interface_get_reply_t *rmp = (vl_api_snort_interface_get_reply_t *)p;
        vl_api_snort_interface_get_reply_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_snort_interface_get_reply_t_tojson(rmp));
        break;
    }

    if (msg_id == details_msg_id) {
        vl_api_snort_interface_details_t *rmp = (vl_api_snort_interface_details_t *)p;
        vl_api_snort_interface_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_snort_interface_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_snort_client_get (cJSON *o)
{
    u16 msg_id = vac_get_msg_index(VL_API_SNORT_CLIENT_GET_CRC);
  int len = 0;
  if (!o) return 0;
  vl_api_snort_client_get_t *mp = vl_api_snort_client_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }
  mp->_vl_msg_id = msg_id;

  vl_api_snort_client_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  cJSON *reply = cJSON_CreateArray();

  u16 reply_msg_id = vac_get_msg_index(VL_API_SNORT_CLIENT_GET_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_SNORT_CLIENT_DETAILS_CRC);

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
        vl_api_snort_client_get_reply_t *rmp = (vl_api_snort_client_get_reply_t *)p;
        vl_api_snort_client_get_reply_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_snort_client_get_reply_t_tojson(rmp));
        break;
    }

    if (msg_id == details_msg_id) {
        vl_api_snort_client_details_t *rmp = (vl_api_snort_client_details_t *)p;
        vl_api_snort_client_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_snort_client_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_snort_instance_create (cJSON *o)
{
  vl_api_snort_instance_create_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_snort_instance_create_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SNORT_INSTANCE_CREATE_CRC);
  vl_api_snort_instance_create_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SNORT_INSTANCE_CREATE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_snort_instance_create_reply_t *rmp = (vl_api_snort_instance_create_reply_t *)p;
  vl_api_snort_instance_create_reply_t_endian(rmp, 0);
  return vl_api_snort_instance_create_reply_t_tojson(rmp);
}

static cJSON *
api_snort_instance_delete (cJSON *o)
{
  vl_api_snort_instance_delete_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_snort_instance_delete_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SNORT_INSTANCE_DELETE_CRC);
  vl_api_snort_instance_delete_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SNORT_INSTANCE_DELETE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_snort_instance_delete_reply_t *rmp = (vl_api_snort_instance_delete_reply_t *)p;
  vl_api_snort_instance_delete_reply_t_endian(rmp, 0);
  return vl_api_snort_instance_delete_reply_t_tojson(rmp);
}

static cJSON *
api_snort_client_disconnect (cJSON *o)
{
  vl_api_snort_client_disconnect_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_snort_client_disconnect_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SNORT_CLIENT_DISCONNECT_CRC);
  vl_api_snort_client_disconnect_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SNORT_CLIENT_DISCONNECT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_snort_client_disconnect_reply_t *rmp = (vl_api_snort_client_disconnect_reply_t *)p;
  vl_api_snort_client_disconnect_reply_t_endian(rmp, 0);
  return vl_api_snort_client_disconnect_reply_t_tojson(rmp);
}

static cJSON *
api_snort_instance_disconnect (cJSON *o)
{
  vl_api_snort_instance_disconnect_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_snort_instance_disconnect_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SNORT_INSTANCE_DISCONNECT_CRC);
  vl_api_snort_instance_disconnect_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SNORT_INSTANCE_DISCONNECT_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_snort_instance_disconnect_reply_t *rmp = (vl_api_snort_instance_disconnect_reply_t *)p;
  vl_api_snort_instance_disconnect_reply_t_endian(rmp, 0);
  return vl_api_snort_instance_disconnect_reply_t_tojson(rmp);
}

static cJSON *
api_snort_interface_attach (cJSON *o)
{
  vl_api_snort_interface_attach_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_snort_interface_attach_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SNORT_INTERFACE_ATTACH_CRC);
  vl_api_snort_interface_attach_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SNORT_INTERFACE_ATTACH_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_snort_interface_attach_reply_t *rmp = (vl_api_snort_interface_attach_reply_t *)p;
  vl_api_snort_interface_attach_reply_t_endian(rmp, 0);
  return vl_api_snort_interface_attach_reply_t_tojson(rmp);
}

static cJSON *
api_snort_interface_detach (cJSON *o)
{
  vl_api_snort_interface_detach_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_snort_interface_detach_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SNORT_INTERFACE_DETACH_CRC);
  vl_api_snort_interface_detach_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SNORT_INTERFACE_DETACH_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_snort_interface_detach_reply_t *rmp = (vl_api_snort_interface_detach_reply_t *)p;
  vl_api_snort_interface_detach_reply_t_endian(rmp, 0);
  return vl_api_snort_interface_detach_reply_t_tojson(rmp);
}

static cJSON *
api_snort_input_mode_get (cJSON *o)
{
  vl_api_snort_input_mode_get_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_snort_input_mode_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SNORT_INPUT_MODE_GET_CRC);
  vl_api_snort_input_mode_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SNORT_INPUT_MODE_GET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_snort_input_mode_get_reply_t *rmp = (vl_api_snort_input_mode_get_reply_t *)p;
  vl_api_snort_input_mode_get_reply_t_endian(rmp, 0);
  return vl_api_snort_input_mode_get_reply_t_tojson(rmp);
}

static cJSON *
api_snort_input_mode_set (cJSON *o)
{
  vl_api_snort_input_mode_set_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_snort_input_mode_set_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_SNORT_INPUT_MODE_SET_CRC);
  vl_api_snort_input_mode_set_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_SNORT_INPUT_MODE_SET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_snort_input_mode_set_reply_t *rmp = (vl_api_snort_input_mode_set_reply_t *)p;
  vl_api_snort_input_mode_set_reply_t_endian(rmp, 0);
  return vl_api_snort_input_mode_set_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("snort_instance_get", api_snort_instance_get, (cJSON * (*)(void *))vl_api_snort_instance_get_t_tojson, 0x07c37475);
   vat2_register_function("snort_interface_get", api_snort_interface_get, (cJSON * (*)(void *))vl_api_snort_interface_get_t_tojson, 0x765a2424);
   vat2_register_function("snort_client_get", api_snort_client_get, (cJSON * (*)(void *))vl_api_snort_client_get_t_tojson, 0x51d54b70);
   vat2_register_function("snort_instance_create", api_snort_instance_create, (cJSON * (*)(void *))vl_api_snort_instance_create_t_tojson, 0x248cc390);
   vat2_register_function("snort_instance_delete", api_snort_instance_delete, (cJSON * (*)(void *))vl_api_snort_instance_delete_t_tojson, 0x6981211a);
   vat2_register_function("snort_client_disconnect", api_snort_client_disconnect, (cJSON * (*)(void *))vl_api_snort_client_disconnect_t_tojson, 0x30a221a6);
   vat2_register_function("snort_instance_disconnect", api_snort_instance_disconnect, (cJSON * (*)(void *))vl_api_snort_instance_disconnect_t_tojson, 0x6981211a);
   vat2_register_function("snort_interface_attach", api_snort_interface_attach, (cJSON * (*)(void *))vl_api_snort_interface_attach_t_tojson, 0x79ceda89);
   vat2_register_function("snort_interface_detach", api_snort_interface_detach, (cJSON * (*)(void *))vl_api_snort_interface_detach_t_tojson, 0x529cb13f);
   vat2_register_function("snort_input_mode_get", api_snort_input_mode_get, (cJSON * (*)(void *))vl_api_snort_input_mode_get_t_tojson, 0x51077d14);
   vat2_register_function("snort_input_mode_set", api_snort_input_mode_set, (cJSON * (*)(void *))vl_api_snort_input_mode_set_t_tojson, 0xd595d008);
   return 0;
}
