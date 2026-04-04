#define vl_endianfun		/* define message structures */
#include "cnat.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "cnat.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "cnat.api.h"
#undef vl_printfun

#include "cnat.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("cnat_10708a40", VL_MSG_CNAT_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_cnat);
   vl_msg_api_add_msg_name_crc (am, "cnat_translation_update_f8d40bc5",
                                VL_API_CNAT_TRANSLATION_UPDATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cnat_translation_update_reply_e2fc8294",
                                VL_API_CNAT_TRANSLATION_UPDATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cnat_translation_del_3a91bde5",
                                VL_API_CNAT_TRANSLATION_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cnat_translation_del_reply_e8d4e804",
                                VL_API_CNAT_TRANSLATION_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cnat_translation_details_1a5140b7",
                                VL_API_CNAT_TRANSLATION_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cnat_translation_dump_51077d14",
                                VL_API_CNAT_TRANSLATION_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cnat_session_purge_51077d14",
                                VL_API_CNAT_SESSION_PURGE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cnat_session_purge_reply_e8d4e804",
                                VL_API_CNAT_SESSION_PURGE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cnat_session_details_7e5017c7",
                                VL_API_CNAT_SESSION_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cnat_session_dump_51077d14",
                                VL_API_CNAT_SESSION_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cnat_set_snat_addresses_d997e96c",
                                VL_API_CNAT_SET_SNAT_ADDRESSES + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cnat_set_snat_addresses_reply_e8d4e804",
                                VL_API_CNAT_SET_SNAT_ADDRESSES_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cnat_get_snat_addresses_51077d14",
                                VL_API_CNAT_GET_SNAT_ADDRESSES + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cnat_get_snat_addresses_reply_879513c1",
                                VL_API_CNAT_GET_SNAT_ADDRESSES_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cnat_snat_policy_add_del_exclude_pfx_e26dd79a",
                                VL_API_CNAT_SNAT_POLICY_ADD_DEL_EXCLUDE_PFX + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cnat_snat_policy_add_del_exclude_pfx_reply_e8d4e804",
                                VL_API_CNAT_SNAT_POLICY_ADD_DEL_EXCLUDE_PFX_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cnat_snat_policy_add_del_if_4ebb8d02",
                                VL_API_CNAT_SNAT_POLICY_ADD_DEL_IF + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cnat_snat_policy_add_del_if_reply_e8d4e804",
                                VL_API_CNAT_SNAT_POLICY_ADD_DEL_IF_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cnat_set_snat_policy_d3e6eaf4",
                                VL_API_CNAT_SET_SNAT_POLICY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "cnat_set_snat_policy_reply_e8d4e804",
                                VL_API_CNAT_SET_SNAT_POLICY_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CNAT_TRANSLATION_UPDATE + msg_id_base,
   .name = "cnat_translation_update",
   .handler = vl_api_cnat_translation_update_t_handler,
   .endian = vl_api_cnat_translation_update_t_endian,
   .format_fn = vl_api_cnat_translation_update_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_cnat_translation_update_t_tojson,
   .fromjson = vl_api_cnat_translation_update_t_fromjson,
   .calc_size = vl_api_cnat_translation_update_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CNAT_TRANSLATION_UPDATE_REPLY + msg_id_base,
  .name = "cnat_translation_update_reply",
  .handler = 0,
  .endian = vl_api_cnat_translation_update_reply_t_endian,
  .format_fn = vl_api_cnat_translation_update_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_cnat_translation_update_reply_t_tojson,
  .fromjson = vl_api_cnat_translation_update_reply_t_fromjson,
  .calc_size = vl_api_cnat_translation_update_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CNAT_TRANSLATION_DEL + msg_id_base,
   .name = "cnat_translation_del",
   .handler = vl_api_cnat_translation_del_t_handler,
   .endian = vl_api_cnat_translation_del_t_endian,
   .format_fn = vl_api_cnat_translation_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_cnat_translation_del_t_tojson,
   .fromjson = vl_api_cnat_translation_del_t_fromjson,
   .calc_size = vl_api_cnat_translation_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CNAT_TRANSLATION_DEL_REPLY + msg_id_base,
  .name = "cnat_translation_del_reply",
  .handler = 0,
  .endian = vl_api_cnat_translation_del_reply_t_endian,
  .format_fn = vl_api_cnat_translation_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_cnat_translation_del_reply_t_tojson,
  .fromjson = vl_api_cnat_translation_del_reply_t_fromjson,
  .calc_size = vl_api_cnat_translation_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CNAT_TRANSLATION_DUMP + msg_id_base,
   .name = "cnat_translation_dump",
   .handler = vl_api_cnat_translation_dump_t_handler,
   .endian = vl_api_cnat_translation_dump_t_endian,
   .format_fn = vl_api_cnat_translation_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_cnat_translation_dump_t_tojson,
   .fromjson = vl_api_cnat_translation_dump_t_fromjson,
   .calc_size = vl_api_cnat_translation_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CNAT_TRANSLATION_DETAILS + msg_id_base,
  .name = "cnat_translation_details",
  .handler = 0,
  .endian = vl_api_cnat_translation_details_t_endian,
  .format_fn = vl_api_cnat_translation_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_cnat_translation_details_t_tojson,
  .fromjson = vl_api_cnat_translation_details_t_fromjson,
  .calc_size = vl_api_cnat_translation_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CNAT_SESSION_PURGE + msg_id_base,
   .name = "cnat_session_purge",
   .handler = vl_api_cnat_session_purge_t_handler,
   .endian = vl_api_cnat_session_purge_t_endian,
   .format_fn = vl_api_cnat_session_purge_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_cnat_session_purge_t_tojson,
   .fromjson = vl_api_cnat_session_purge_t_fromjson,
   .calc_size = vl_api_cnat_session_purge_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CNAT_SESSION_PURGE_REPLY + msg_id_base,
  .name = "cnat_session_purge_reply",
  .handler = 0,
  .endian = vl_api_cnat_session_purge_reply_t_endian,
  .format_fn = vl_api_cnat_session_purge_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_cnat_session_purge_reply_t_tojson,
  .fromjson = vl_api_cnat_session_purge_reply_t_fromjson,
  .calc_size = vl_api_cnat_session_purge_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CNAT_SESSION_DUMP + msg_id_base,
   .name = "cnat_session_dump",
   .handler = vl_api_cnat_session_dump_t_handler,
   .endian = vl_api_cnat_session_dump_t_endian,
   .format_fn = vl_api_cnat_session_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_cnat_session_dump_t_tojson,
   .fromjson = vl_api_cnat_session_dump_t_fromjson,
   .calc_size = vl_api_cnat_session_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CNAT_SESSION_DETAILS + msg_id_base,
  .name = "cnat_session_details",
  .handler = 0,
  .endian = vl_api_cnat_session_details_t_endian,
  .format_fn = vl_api_cnat_session_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_cnat_session_details_t_tojson,
  .fromjson = vl_api_cnat_session_details_t_fromjson,
  .calc_size = vl_api_cnat_session_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CNAT_SET_SNAT_ADDRESSES + msg_id_base,
   .name = "cnat_set_snat_addresses",
   .handler = vl_api_cnat_set_snat_addresses_t_handler,
   .endian = vl_api_cnat_set_snat_addresses_t_endian,
   .format_fn = vl_api_cnat_set_snat_addresses_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_cnat_set_snat_addresses_t_tojson,
   .fromjson = vl_api_cnat_set_snat_addresses_t_fromjson,
   .calc_size = vl_api_cnat_set_snat_addresses_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CNAT_SET_SNAT_ADDRESSES_REPLY + msg_id_base,
  .name = "cnat_set_snat_addresses_reply",
  .handler = 0,
  .endian = vl_api_cnat_set_snat_addresses_reply_t_endian,
  .format_fn = vl_api_cnat_set_snat_addresses_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_cnat_set_snat_addresses_reply_t_tojson,
  .fromjson = vl_api_cnat_set_snat_addresses_reply_t_fromjson,
  .calc_size = vl_api_cnat_set_snat_addresses_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CNAT_GET_SNAT_ADDRESSES + msg_id_base,
   .name = "cnat_get_snat_addresses",
   .handler = vl_api_cnat_get_snat_addresses_t_handler,
   .endian = vl_api_cnat_get_snat_addresses_t_endian,
   .format_fn = vl_api_cnat_get_snat_addresses_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_cnat_get_snat_addresses_t_tojson,
   .fromjson = vl_api_cnat_get_snat_addresses_t_fromjson,
   .calc_size = vl_api_cnat_get_snat_addresses_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CNAT_GET_SNAT_ADDRESSES_REPLY + msg_id_base,
  .name = "cnat_get_snat_addresses_reply",
  .handler = 0,
  .endian = vl_api_cnat_get_snat_addresses_reply_t_endian,
  .format_fn = vl_api_cnat_get_snat_addresses_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_cnat_get_snat_addresses_reply_t_tojson,
  .fromjson = vl_api_cnat_get_snat_addresses_reply_t_fromjson,
  .calc_size = vl_api_cnat_get_snat_addresses_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CNAT_SNAT_POLICY_ADD_DEL_EXCLUDE_PFX + msg_id_base,
   .name = "cnat_snat_policy_add_del_exclude_pfx",
   .handler = vl_api_cnat_snat_policy_add_del_exclude_pfx_t_handler,
   .endian = vl_api_cnat_snat_policy_add_del_exclude_pfx_t_endian,
   .format_fn = vl_api_cnat_snat_policy_add_del_exclude_pfx_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_cnat_snat_policy_add_del_exclude_pfx_t_tojson,
   .fromjson = vl_api_cnat_snat_policy_add_del_exclude_pfx_t_fromjson,
   .calc_size = vl_api_cnat_snat_policy_add_del_exclude_pfx_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CNAT_SNAT_POLICY_ADD_DEL_EXCLUDE_PFX_REPLY + msg_id_base,
  .name = "cnat_snat_policy_add_del_exclude_pfx_reply",
  .handler = 0,
  .endian = vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t_endian,
  .format_fn = vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t_tojson,
  .fromjson = vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t_fromjson,
  .calc_size = vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CNAT_SNAT_POLICY_ADD_DEL_IF + msg_id_base,
   .name = "cnat_snat_policy_add_del_if",
   .handler = vl_api_cnat_snat_policy_add_del_if_t_handler,
   .endian = vl_api_cnat_snat_policy_add_del_if_t_endian,
   .format_fn = vl_api_cnat_snat_policy_add_del_if_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_cnat_snat_policy_add_del_if_t_tojson,
   .fromjson = vl_api_cnat_snat_policy_add_del_if_t_fromjson,
   .calc_size = vl_api_cnat_snat_policy_add_del_if_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CNAT_SNAT_POLICY_ADD_DEL_IF_REPLY + msg_id_base,
  .name = "cnat_snat_policy_add_del_if_reply",
  .handler = 0,
  .endian = vl_api_cnat_snat_policy_add_del_if_reply_t_endian,
  .format_fn = vl_api_cnat_snat_policy_add_del_if_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_cnat_snat_policy_add_del_if_reply_t_tojson,
  .fromjson = vl_api_cnat_snat_policy_add_del_if_reply_t_fromjson,
  .calc_size = vl_api_cnat_snat_policy_add_del_if_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_CNAT_SET_SNAT_POLICY + msg_id_base,
   .name = "cnat_set_snat_policy",
   .handler = vl_api_cnat_set_snat_policy_t_handler,
   .endian = vl_api_cnat_set_snat_policy_t_endian,
   .format_fn = vl_api_cnat_set_snat_policy_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_cnat_set_snat_policy_t_tojson,
   .fromjson = vl_api_cnat_set_snat_policy_t_fromjson,
   .calc_size = vl_api_cnat_set_snat_policy_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_CNAT_SET_SNAT_POLICY_REPLY + msg_id_base,
  .name = "cnat_set_snat_policy_reply",
  .handler = 0,
  .endian = vl_api_cnat_set_snat_policy_reply_t_endian,
  .format_fn = vl_api_cnat_set_snat_policy_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_cnat_set_snat_policy_reply_t_tojson,
  .fromjson = vl_api_cnat_set_snat_policy_reply_t_fromjson,
  .calc_size = vl_api_cnat_set_snat_policy_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
