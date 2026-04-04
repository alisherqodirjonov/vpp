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

#include "lisp_gpe.api_enum.h"
#include "lisp_gpe.api_types.h"

#define vl_endianfun		/* define message structures */
#include "lisp_gpe.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "lisp_gpe.api.h"
#undef vl_calsizefun

#define vl_printfun
#include "lisp_gpe.api.h"
#undef vl_printfun

#include "lisp_gpe.api_tojson.h"
#include "lisp_gpe.api_fromjson.h"
#include <vpp-api/client/vppapiclient.h>

#include <vat2/vat2_helpers.h>

static cJSON *
api_gpe_add_del_fwd_entry (cJSON *o)
{
  vl_api_gpe_add_del_fwd_entry_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_gpe_add_del_fwd_entry_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_GPE_ADD_DEL_FWD_ENTRY_CRC);
  vl_api_gpe_add_del_fwd_entry_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_GPE_ADD_DEL_FWD_ENTRY_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_gpe_add_del_fwd_entry_reply_t *rmp = (vl_api_gpe_add_del_fwd_entry_reply_t *)p;
  vl_api_gpe_add_del_fwd_entry_reply_t_endian(rmp, 0);
  return vl_api_gpe_add_del_fwd_entry_reply_t_tojson(rmp);
}

static cJSON *
api_gpe_enable_disable (cJSON *o)
{
  vl_api_gpe_enable_disable_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_gpe_enable_disable_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_GPE_ENABLE_DISABLE_CRC);
  vl_api_gpe_enable_disable_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_GPE_ENABLE_DISABLE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_gpe_enable_disable_reply_t *rmp = (vl_api_gpe_enable_disable_reply_t *)p;
  vl_api_gpe_enable_disable_reply_t_endian(rmp, 0);
  return vl_api_gpe_enable_disable_reply_t_tojson(rmp);
}

static cJSON *
api_gpe_add_del_iface (cJSON *o)
{
  vl_api_gpe_add_del_iface_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_gpe_add_del_iface_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_GPE_ADD_DEL_IFACE_CRC);
  vl_api_gpe_add_del_iface_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_GPE_ADD_DEL_IFACE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_gpe_add_del_iface_reply_t *rmp = (vl_api_gpe_add_del_iface_reply_t *)p;
  vl_api_gpe_add_del_iface_reply_t_endian(rmp, 0);
  return vl_api_gpe_add_del_iface_reply_t_tojson(rmp);
}

static cJSON *
api_gpe_fwd_entry_vnis_get (cJSON *o)
{
  vl_api_gpe_fwd_entry_vnis_get_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_gpe_fwd_entry_vnis_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_GPE_FWD_ENTRY_VNIS_GET_CRC);
  vl_api_gpe_fwd_entry_vnis_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_GPE_FWD_ENTRY_VNIS_GET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_gpe_fwd_entry_vnis_get_reply_t *rmp = (vl_api_gpe_fwd_entry_vnis_get_reply_t *)p;
  vl_api_gpe_fwd_entry_vnis_get_reply_t_endian(rmp, 0);
  return vl_api_gpe_fwd_entry_vnis_get_reply_t_tojson(rmp);
}

static cJSON *
api_gpe_fwd_entries_get (cJSON *o)
{
  vl_api_gpe_fwd_entries_get_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_gpe_fwd_entries_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_GPE_FWD_ENTRIES_GET_CRC);
  vl_api_gpe_fwd_entries_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_GPE_FWD_ENTRIES_GET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_gpe_fwd_entries_get_reply_t *rmp = (vl_api_gpe_fwd_entries_get_reply_t *)p;
  vl_api_gpe_fwd_entries_get_reply_t_endian(rmp, 0);
  return vl_api_gpe_fwd_entries_get_reply_t_tojson(rmp);
}

static cJSON *
api_gpe_fwd_entry_path_dump (cJSON *o)
{
  u16 msg_id = vac_get_msg_index(VL_API_GPE_FWD_ENTRY_PATH_DUMP_CRC);
  int len;
  if (!o) return 0;
  vl_api_gpe_fwd_entry_path_dump_t *mp = vl_api_gpe_fwd_entry_path_dump_t_fromjson(o, &len);
  if (!mp) {
      fprintf(stderr, "Failed converting JSON to API\n");
      return 0;
  }
  mp->_vl_msg_id = msg_id;
  vl_api_gpe_fwd_entry_path_dump_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  vat2_control_ping(123); // FIX CONTEXT
  cJSON *reply = cJSON_CreateArray();

  u16 ping_reply_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
  u16 details_msg_id = vac_get_msg_index(VL_API_GPE_FWD_ENTRY_PATH_DETAILS_CRC);

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
        if (l < sizeof(vl_api_gpe_fwd_entry_path_details_t)) {
            cJSON_free(reply);
            return 0;
        }
        vl_api_gpe_fwd_entry_path_details_t *rmp = (vl_api_gpe_fwd_entry_path_details_t *)p;
        vl_api_gpe_fwd_entry_path_details_t_endian(rmp, 0);
        cJSON_AddItemToArray(reply, vl_api_gpe_fwd_entry_path_details_t_tojson(rmp));
    }
  }
  return reply;
}

static cJSON *
api_gpe_set_encap_mode (cJSON *o)
{
  vl_api_gpe_set_encap_mode_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_gpe_set_encap_mode_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_GPE_SET_ENCAP_MODE_CRC);
  vl_api_gpe_set_encap_mode_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_GPE_SET_ENCAP_MODE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_gpe_set_encap_mode_reply_t *rmp = (vl_api_gpe_set_encap_mode_reply_t *)p;
  vl_api_gpe_set_encap_mode_reply_t_endian(rmp, 0);
  return vl_api_gpe_set_encap_mode_reply_t_tojson(rmp);
}

static cJSON *
api_gpe_get_encap_mode (cJSON *o)
{
  vl_api_gpe_get_encap_mode_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_gpe_get_encap_mode_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_GPE_GET_ENCAP_MODE_CRC);
  vl_api_gpe_get_encap_mode_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_GPE_GET_ENCAP_MODE_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_gpe_get_encap_mode_reply_t *rmp = (vl_api_gpe_get_encap_mode_reply_t *)p;
  vl_api_gpe_get_encap_mode_reply_t_endian(rmp, 0);
  return vl_api_gpe_get_encap_mode_reply_t_tojson(rmp);
}

static cJSON *
api_gpe_add_del_native_fwd_rpath (cJSON *o)
{
  vl_api_gpe_add_del_native_fwd_rpath_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_gpe_add_del_native_fwd_rpath_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_GPE_ADD_DEL_NATIVE_FWD_RPATH_CRC);
  vl_api_gpe_add_del_native_fwd_rpath_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_GPE_ADD_DEL_NATIVE_FWD_RPATH_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_gpe_add_del_native_fwd_rpath_reply_t *rmp = (vl_api_gpe_add_del_native_fwd_rpath_reply_t *)p;
  vl_api_gpe_add_del_native_fwd_rpath_reply_t_endian(rmp, 0);
  return vl_api_gpe_add_del_native_fwd_rpath_reply_t_tojson(rmp);
}

static cJSON *
api_gpe_native_fwd_rpaths_get (cJSON *o)
{
  vl_api_gpe_native_fwd_rpaths_get_t *mp;
  int len;
  if (!o) return 0;
  mp = vl_api_gpe_native_fwd_rpaths_get_t_fromjson(o, &len);
  if (!mp) {
    fprintf(stderr, "Failed converting JSON to API\n");
    return 0;
  }

  mp->_vl_msg_id = vac_get_msg_index(VL_API_GPE_NATIVE_FWD_RPATHS_GET_CRC);
  vl_api_gpe_native_fwd_rpaths_get_t_endian(mp, 1);
  vac_write((char *)mp, len);
  cJSON_free(mp);

  /* Read reply */
  char *p;
  int l;
  vac_read(&p, &l, 5); // XXX: Fix timeout
  if (p == 0 || l == 0) return 0;
    // XXX Will fail in case of event received. Do loop
  if (ntohs(*((u16 *)p)) != vac_get_msg_index(VL_API_GPE_NATIVE_FWD_RPATHS_GET_REPLY_CRC)) {
    fprintf(stderr, "Mismatched reply\n");
    return 0;
  }
  vl_api_gpe_native_fwd_rpaths_get_reply_t *rmp = (vl_api_gpe_native_fwd_rpaths_get_reply_t *)p;
  vl_api_gpe_native_fwd_rpaths_get_reply_t_endian(rmp, 0);
  return vl_api_gpe_native_fwd_rpaths_get_reply_t_tojson(rmp);
}

void vat2_register_function(char *, cJSON * (*)(cJSON *), cJSON * (*)(void *), u32);
clib_error_t *
vat2_register_plugin (void) {
   vat2_register_function("gpe_add_del_fwd_entry", api_gpe_add_del_fwd_entry, (cJSON * (*)(void *))vl_api_gpe_add_del_fwd_entry_t_tojson, 0xf0847644);
   vat2_register_function("gpe_enable_disable", api_gpe_enable_disable, (cJSON * (*)(void *))vl_api_gpe_enable_disable_t_tojson, 0xc264d7bf);
   vat2_register_function("gpe_add_del_iface", api_gpe_add_del_iface, (cJSON * (*)(void *))vl_api_gpe_add_del_iface_t_tojson, 0x3ccff273);
   vat2_register_function("gpe_fwd_entry_vnis_get", api_gpe_fwd_entry_vnis_get, (cJSON * (*)(void *))vl_api_gpe_fwd_entry_vnis_get_t_tojson, 0x51077d14);
   vat2_register_function("gpe_fwd_entries_get", api_gpe_fwd_entries_get, (cJSON * (*)(void *))vl_api_gpe_fwd_entries_get_t_tojson, 0x8d1f2fe9);
   vat2_register_function("gpe_fwd_entry_path_dump", api_gpe_fwd_entry_path_dump, (cJSON * (*)(void *))vl_api_gpe_fwd_entry_path_dump_t_tojson, 0x39bce980);
   vat2_register_function("gpe_set_encap_mode", api_gpe_set_encap_mode, (cJSON * (*)(void *))vl_api_gpe_set_encap_mode_t_tojson, 0xbd819eac);
   vat2_register_function("gpe_get_encap_mode", api_gpe_get_encap_mode, (cJSON * (*)(void *))vl_api_gpe_get_encap_mode_t_tojson, 0x51077d14);
   vat2_register_function("gpe_add_del_native_fwd_rpath", api_gpe_add_del_native_fwd_rpath, (cJSON * (*)(void *))vl_api_gpe_add_del_native_fwd_rpath_t_tojson, 0x43fc8b54);
   vat2_register_function("gpe_native_fwd_rpaths_get", api_gpe_native_fwd_rpaths_get, (cJSON * (*)(void *))vl_api_gpe_native_fwd_rpaths_get_t_tojson, 0xf652ceb4);
   return 0;
}
