#define vl_endianfun		/* define message structures */
#include "sr.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "sr.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "sr.api.h"
#undef vl_printfun

#include "sr.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("sr_f0cc4ec6", VL_MSG_SR_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_sr);
   vl_msg_api_add_msg_name_crc (am, "sr_localsid_add_del_5a36c324",
                                VL_API_SR_LOCALSID_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_localsid_add_del_reply_e8d4e804",
                                VL_API_SR_LOCALSID_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_policy_add_44ac92e8",
                                VL_API_SR_POLICY_ADD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_policy_add_reply_e8d4e804",
                                VL_API_SR_POLICY_ADD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_policy_mod_b97bb56e",
                                VL_API_SR_POLICY_MOD + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_policy_mod_reply_e8d4e804",
                                VL_API_SR_POLICY_MOD_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_policy_add_v2_f6297f36",
                                VL_API_SR_POLICY_ADD_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_policy_add_v2_reply_e8d4e804",
                                VL_API_SR_POLICY_ADD_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_policy_mod_v2_c0544823",
                                VL_API_SR_POLICY_MOD_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_policy_mod_v2_reply_e8d4e804",
                                VL_API_SR_POLICY_MOD_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_policy_del_cb4d48d5",
                                VL_API_SR_POLICY_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_policy_del_reply_e8d4e804",
                                VL_API_SR_POLICY_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_set_encap_source_d3bad5e1",
                                VL_API_SR_SET_ENCAP_SOURCE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_set_encap_source_reply_e8d4e804",
                                VL_API_SR_SET_ENCAP_SOURCE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_set_encap_hop_limit_aa75d7d0",
                                VL_API_SR_SET_ENCAP_HOP_LIMIT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_set_encap_hop_limit_reply_e8d4e804",
                                VL_API_SR_SET_ENCAP_HOP_LIMIT_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_steering_add_del_e46b0a0f",
                                VL_API_SR_STEERING_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_steering_add_del_reply_e8d4e804",
                                VL_API_SR_STEERING_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_localsids_dump_51077d14",
                                VL_API_SR_LOCALSIDS_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_localsids_details_2e9221b9",
                                VL_API_SR_LOCALSIDS_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_localsids_with_packet_stats_dump_51077d14",
                                VL_API_SR_LOCALSIDS_WITH_PACKET_STATS_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_localsids_with_packet_stats_details_ce0b1ce0",
                                VL_API_SR_LOCALSIDS_WITH_PACKET_STATS_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_policies_dump_51077d14",
                                VL_API_SR_POLICIES_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_policies_details_db6ff2a1",
                                VL_API_SR_POLICIES_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_policies_v2_dump_51077d14",
                                VL_API_SR_POLICIES_V2_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_policies_v2_details_96dcb699",
                                VL_API_SR_POLICIES_V2_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_policies_with_sl_index_dump_51077d14",
                                VL_API_SR_POLICIES_WITH_SL_INDEX_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_policies_with_sl_index_details_ca2e9bc8",
                                VL_API_SR_POLICIES_WITH_SL_INDEX_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_steering_pol_dump_51077d14",
                                VL_API_SR_STEERING_POL_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sr_steering_pol_details_d41258c9",
                                VL_API_SR_STEERING_POL_DETAILS + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_LOCALSID_ADD_DEL + msg_id_base,
   .name = "sr_localsid_add_del",
   .handler = vl_api_sr_localsid_add_del_t_handler,
   .endian = vl_api_sr_localsid_add_del_t_endian,
   .format_fn = vl_api_sr_localsid_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_localsid_add_del_t_tojson,
   .fromjson = vl_api_sr_localsid_add_del_t_fromjson,
   .calc_size = vl_api_sr_localsid_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_LOCALSID_ADD_DEL_REPLY + msg_id_base,
  .name = "sr_localsid_add_del_reply",
  .handler = 0,
  .endian = vl_api_sr_localsid_add_del_reply_t_endian,
  .format_fn = vl_api_sr_localsid_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_localsid_add_del_reply_t_tojson,
  .fromjson = vl_api_sr_localsid_add_del_reply_t_fromjson,
  .calc_size = vl_api_sr_localsid_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_POLICY_ADD + msg_id_base,
   .name = "sr_policy_add",
   .handler = vl_api_sr_policy_add_t_handler,
   .endian = vl_api_sr_policy_add_t_endian,
   .format_fn = vl_api_sr_policy_add_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_policy_add_t_tojson,
   .fromjson = vl_api_sr_policy_add_t_fromjson,
   .calc_size = vl_api_sr_policy_add_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_POLICY_ADD_REPLY + msg_id_base,
  .name = "sr_policy_add_reply",
  .handler = 0,
  .endian = vl_api_sr_policy_add_reply_t_endian,
  .format_fn = vl_api_sr_policy_add_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_policy_add_reply_t_tojson,
  .fromjson = vl_api_sr_policy_add_reply_t_fromjson,
  .calc_size = vl_api_sr_policy_add_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_POLICY_MOD + msg_id_base,
   .name = "sr_policy_mod",
   .handler = vl_api_sr_policy_mod_t_handler,
   .endian = vl_api_sr_policy_mod_t_endian,
   .format_fn = vl_api_sr_policy_mod_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_policy_mod_t_tojson,
   .fromjson = vl_api_sr_policy_mod_t_fromjson,
   .calc_size = vl_api_sr_policy_mod_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_POLICY_MOD_REPLY + msg_id_base,
  .name = "sr_policy_mod_reply",
  .handler = 0,
  .endian = vl_api_sr_policy_mod_reply_t_endian,
  .format_fn = vl_api_sr_policy_mod_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_policy_mod_reply_t_tojson,
  .fromjson = vl_api_sr_policy_mod_reply_t_fromjson,
  .calc_size = vl_api_sr_policy_mod_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_POLICY_ADD_V2 + msg_id_base,
   .name = "sr_policy_add_v2",
   .handler = vl_api_sr_policy_add_v2_t_handler,
   .endian = vl_api_sr_policy_add_v2_t_endian,
   .format_fn = vl_api_sr_policy_add_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_policy_add_v2_t_tojson,
   .fromjson = vl_api_sr_policy_add_v2_t_fromjson,
   .calc_size = vl_api_sr_policy_add_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_POLICY_ADD_V2_REPLY + msg_id_base,
  .name = "sr_policy_add_v2_reply",
  .handler = 0,
  .endian = vl_api_sr_policy_add_v2_reply_t_endian,
  .format_fn = vl_api_sr_policy_add_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_policy_add_v2_reply_t_tojson,
  .fromjson = vl_api_sr_policy_add_v2_reply_t_fromjson,
  .calc_size = vl_api_sr_policy_add_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_POLICY_MOD_V2 + msg_id_base,
   .name = "sr_policy_mod_v2",
   .handler = vl_api_sr_policy_mod_v2_t_handler,
   .endian = vl_api_sr_policy_mod_v2_t_endian,
   .format_fn = vl_api_sr_policy_mod_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_policy_mod_v2_t_tojson,
   .fromjson = vl_api_sr_policy_mod_v2_t_fromjson,
   .calc_size = vl_api_sr_policy_mod_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_POLICY_MOD_V2_REPLY + msg_id_base,
  .name = "sr_policy_mod_v2_reply",
  .handler = 0,
  .endian = vl_api_sr_policy_mod_v2_reply_t_endian,
  .format_fn = vl_api_sr_policy_mod_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_policy_mod_v2_reply_t_tojson,
  .fromjson = vl_api_sr_policy_mod_v2_reply_t_fromjson,
  .calc_size = vl_api_sr_policy_mod_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_POLICY_DEL + msg_id_base,
   .name = "sr_policy_del",
   .handler = vl_api_sr_policy_del_t_handler,
   .endian = vl_api_sr_policy_del_t_endian,
   .format_fn = vl_api_sr_policy_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_policy_del_t_tojson,
   .fromjson = vl_api_sr_policy_del_t_fromjson,
   .calc_size = vl_api_sr_policy_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_POLICY_DEL_REPLY + msg_id_base,
  .name = "sr_policy_del_reply",
  .handler = 0,
  .endian = vl_api_sr_policy_del_reply_t_endian,
  .format_fn = vl_api_sr_policy_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_policy_del_reply_t_tojson,
  .fromjson = vl_api_sr_policy_del_reply_t_fromjson,
  .calc_size = vl_api_sr_policy_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_SET_ENCAP_SOURCE + msg_id_base,
   .name = "sr_set_encap_source",
   .handler = vl_api_sr_set_encap_source_t_handler,
   .endian = vl_api_sr_set_encap_source_t_endian,
   .format_fn = vl_api_sr_set_encap_source_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_set_encap_source_t_tojson,
   .fromjson = vl_api_sr_set_encap_source_t_fromjson,
   .calc_size = vl_api_sr_set_encap_source_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_SET_ENCAP_SOURCE_REPLY + msg_id_base,
  .name = "sr_set_encap_source_reply",
  .handler = 0,
  .endian = vl_api_sr_set_encap_source_reply_t_endian,
  .format_fn = vl_api_sr_set_encap_source_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_set_encap_source_reply_t_tojson,
  .fromjson = vl_api_sr_set_encap_source_reply_t_fromjson,
  .calc_size = vl_api_sr_set_encap_source_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_SET_ENCAP_HOP_LIMIT + msg_id_base,
   .name = "sr_set_encap_hop_limit",
   .handler = vl_api_sr_set_encap_hop_limit_t_handler,
   .endian = vl_api_sr_set_encap_hop_limit_t_endian,
   .format_fn = vl_api_sr_set_encap_hop_limit_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_set_encap_hop_limit_t_tojson,
   .fromjson = vl_api_sr_set_encap_hop_limit_t_fromjson,
   .calc_size = vl_api_sr_set_encap_hop_limit_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_SET_ENCAP_HOP_LIMIT_REPLY + msg_id_base,
  .name = "sr_set_encap_hop_limit_reply",
  .handler = 0,
  .endian = vl_api_sr_set_encap_hop_limit_reply_t_endian,
  .format_fn = vl_api_sr_set_encap_hop_limit_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_set_encap_hop_limit_reply_t_tojson,
  .fromjson = vl_api_sr_set_encap_hop_limit_reply_t_fromjson,
  .calc_size = vl_api_sr_set_encap_hop_limit_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_STEERING_ADD_DEL + msg_id_base,
   .name = "sr_steering_add_del",
   .handler = vl_api_sr_steering_add_del_t_handler,
   .endian = vl_api_sr_steering_add_del_t_endian,
   .format_fn = vl_api_sr_steering_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_steering_add_del_t_tojson,
   .fromjson = vl_api_sr_steering_add_del_t_fromjson,
   .calc_size = vl_api_sr_steering_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_STEERING_ADD_DEL_REPLY + msg_id_base,
  .name = "sr_steering_add_del_reply",
  .handler = 0,
  .endian = vl_api_sr_steering_add_del_reply_t_endian,
  .format_fn = vl_api_sr_steering_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_steering_add_del_reply_t_tojson,
  .fromjson = vl_api_sr_steering_add_del_reply_t_fromjson,
  .calc_size = vl_api_sr_steering_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_LOCALSIDS_DUMP + msg_id_base,
   .name = "sr_localsids_dump",
   .handler = vl_api_sr_localsids_dump_t_handler,
   .endian = vl_api_sr_localsids_dump_t_endian,
   .format_fn = vl_api_sr_localsids_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_localsids_dump_t_tojson,
   .fromjson = vl_api_sr_localsids_dump_t_fromjson,
   .calc_size = vl_api_sr_localsids_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_LOCALSIDS_DETAILS + msg_id_base,
  .name = "sr_localsids_details",
  .handler = 0,
  .endian = vl_api_sr_localsids_details_t_endian,
  .format_fn = vl_api_sr_localsids_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_localsids_details_t_tojson,
  .fromjson = vl_api_sr_localsids_details_t_fromjson,
  .calc_size = vl_api_sr_localsids_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_LOCALSIDS_WITH_PACKET_STATS_DUMP + msg_id_base,
   .name = "sr_localsids_with_packet_stats_dump",
   .handler = vl_api_sr_localsids_with_packet_stats_dump_t_handler,
   .endian = vl_api_sr_localsids_with_packet_stats_dump_t_endian,
   .format_fn = vl_api_sr_localsids_with_packet_stats_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_localsids_with_packet_stats_dump_t_tojson,
   .fromjson = vl_api_sr_localsids_with_packet_stats_dump_t_fromjson,
   .calc_size = vl_api_sr_localsids_with_packet_stats_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_LOCALSIDS_WITH_PACKET_STATS_DETAILS + msg_id_base,
  .name = "sr_localsids_with_packet_stats_details",
  .handler = 0,
  .endian = vl_api_sr_localsids_with_packet_stats_details_t_endian,
  .format_fn = vl_api_sr_localsids_with_packet_stats_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_localsids_with_packet_stats_details_t_tojson,
  .fromjson = vl_api_sr_localsids_with_packet_stats_details_t_fromjson,
  .calc_size = vl_api_sr_localsids_with_packet_stats_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_POLICIES_DUMP + msg_id_base,
   .name = "sr_policies_dump",
   .handler = vl_api_sr_policies_dump_t_handler,
   .endian = vl_api_sr_policies_dump_t_endian,
   .format_fn = vl_api_sr_policies_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_policies_dump_t_tojson,
   .fromjson = vl_api_sr_policies_dump_t_fromjson,
   .calc_size = vl_api_sr_policies_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_POLICIES_DETAILS + msg_id_base,
  .name = "sr_policies_details",
  .handler = 0,
  .endian = vl_api_sr_policies_details_t_endian,
  .format_fn = vl_api_sr_policies_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_policies_details_t_tojson,
  .fromjson = vl_api_sr_policies_details_t_fromjson,
  .calc_size = vl_api_sr_policies_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_POLICIES_V2_DUMP + msg_id_base,
   .name = "sr_policies_v2_dump",
   .handler = vl_api_sr_policies_v2_dump_t_handler,
   .endian = vl_api_sr_policies_v2_dump_t_endian,
   .format_fn = vl_api_sr_policies_v2_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_policies_v2_dump_t_tojson,
   .fromjson = vl_api_sr_policies_v2_dump_t_fromjson,
   .calc_size = vl_api_sr_policies_v2_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_POLICIES_V2_DETAILS + msg_id_base,
  .name = "sr_policies_v2_details",
  .handler = 0,
  .endian = vl_api_sr_policies_v2_details_t_endian,
  .format_fn = vl_api_sr_policies_v2_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_policies_v2_details_t_tojson,
  .fromjson = vl_api_sr_policies_v2_details_t_fromjson,
  .calc_size = vl_api_sr_policies_v2_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_POLICIES_WITH_SL_INDEX_DUMP + msg_id_base,
   .name = "sr_policies_with_sl_index_dump",
   .handler = vl_api_sr_policies_with_sl_index_dump_t_handler,
   .endian = vl_api_sr_policies_with_sl_index_dump_t_endian,
   .format_fn = vl_api_sr_policies_with_sl_index_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_policies_with_sl_index_dump_t_tojson,
   .fromjson = vl_api_sr_policies_with_sl_index_dump_t_fromjson,
   .calc_size = vl_api_sr_policies_with_sl_index_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_POLICIES_WITH_SL_INDEX_DETAILS + msg_id_base,
  .name = "sr_policies_with_sl_index_details",
  .handler = 0,
  .endian = vl_api_sr_policies_with_sl_index_details_t_endian,
  .format_fn = vl_api_sr_policies_with_sl_index_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_policies_with_sl_index_details_t_tojson,
  .fromjson = vl_api_sr_policies_with_sl_index_details_t_fromjson,
  .calc_size = vl_api_sr_policies_with_sl_index_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SR_STEERING_POL_DUMP + msg_id_base,
   .name = "sr_steering_pol_dump",
   .handler = vl_api_sr_steering_pol_dump_t_handler,
   .endian = vl_api_sr_steering_pol_dump_t_endian,
   .format_fn = vl_api_sr_steering_pol_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sr_steering_pol_dump_t_tojson,
   .fromjson = vl_api_sr_steering_pol_dump_t_fromjson,
   .calc_size = vl_api_sr_steering_pol_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SR_STEERING_POL_DETAILS + msg_id_base,
  .name = "sr_steering_pol_details",
  .handler = 0,
  .endian = vl_api_sr_steering_pol_details_t_endian,
  .format_fn = vl_api_sr_steering_pol_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sr_steering_pol_details_t_tojson,
  .fromjson = vl_api_sr_steering_pol_details_t_fromjson,
  .calc_size = vl_api_sr_steering_pol_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
