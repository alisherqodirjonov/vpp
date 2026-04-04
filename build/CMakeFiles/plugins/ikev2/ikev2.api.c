#define vl_endianfun		/* define message structures */
#include "ikev2.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ikev2.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "ikev2.api.h"
#undef vl_printfun

#include "ikev2.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("ikev2_14c94752", VL_MSG_IKEV2_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_ikev2);
   vl_msg_api_add_msg_name_crc (am, "ikev2_plugin_get_version_51077d14",
                                VL_API_IKEV2_PLUGIN_GET_VERSION + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_plugin_get_version_reply_9b32cf86",
                                VL_API_IKEV2_PLUGIN_GET_VERSION_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_plugin_set_sleep_interval_b7c096ae",
                                VL_API_IKEV2_PLUGIN_SET_SLEEP_INTERVAL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_plugin_set_sleep_interval_reply_e8d4e804",
                                VL_API_IKEV2_PLUGIN_SET_SLEEP_INTERVAL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_get_sleep_interval_51077d14",
                                VL_API_IKEV2_GET_SLEEP_INTERVAL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_get_sleep_interval_reply_78ab91dc",
                                VL_API_IKEV2_GET_SLEEP_INTERVAL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_profile_dump_51077d14",
                                VL_API_IKEV2_PROFILE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_profile_details_670d01d9",
                                VL_API_IKEV2_PROFILE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_sa_dump_51077d14",
                                VL_API_IKEV2_SA_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_sa_v2_dump_51077d14",
                                VL_API_IKEV2_SA_V2_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_sa_v3_dump_51077d14",
                                VL_API_IKEV2_SA_V3_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_sa_details_937c22d5",
                                VL_API_IKEV2_SA_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_sa_v2_details_a616e604",
                                VL_API_IKEV2_SA_V2_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_sa_v3_details_85c9a941",
                                VL_API_IKEV2_SA_V3_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_child_sa_dump_01eab609",
                                VL_API_IKEV2_CHILD_SA_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_child_sa_details_ff67741f",
                                VL_API_IKEV2_CHILD_SA_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_child_sa_v2_dump_01eab609",
                                VL_API_IKEV2_CHILD_SA_V2_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_child_sa_v2_details_1db62aa2",
                                VL_API_IKEV2_CHILD_SA_V2_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_nonce_get_7fe9ad51",
                                VL_API_IKEV2_NONCE_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_nonce_get_reply_1b37a342",
                                VL_API_IKEV2_NONCE_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_traffic_selector_dump_a7385e33",
                                VL_API_IKEV2_TRAFFIC_SELECTOR_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_traffic_selector_details_518cb06f",
                                VL_API_IKEV2_TRAFFIC_SELECTOR_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_profile_add_del_2c925b55",
                                VL_API_IKEV2_PROFILE_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_profile_add_del_reply_e8d4e804",
                                VL_API_IKEV2_PROFILE_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_profile_set_auth_642c97cd",
                                VL_API_IKEV2_PROFILE_SET_AUTH + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_profile_set_auth_reply_e8d4e804",
                                VL_API_IKEV2_PROFILE_SET_AUTH_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_profile_set_id_4d7e2418",
                                VL_API_IKEV2_PROFILE_SET_ID + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_profile_set_id_reply_e8d4e804",
                                VL_API_IKEV2_PROFILE_SET_ID_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_profile_disable_natt_ebf79a66",
                                VL_API_IKEV2_PROFILE_DISABLE_NATT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_profile_disable_natt_reply_e8d4e804",
                                VL_API_IKEV2_PROFILE_DISABLE_NATT_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_profile_set_ts_8eb8cfd1",
                                VL_API_IKEV2_PROFILE_SET_TS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_profile_set_ts_reply_e8d4e804",
                                VL_API_IKEV2_PROFILE_SET_TS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_set_local_key_799b69ec",
                                VL_API_IKEV2_SET_LOCAL_KEY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_set_local_key_reply_e8d4e804",
                                VL_API_IKEV2_SET_LOCAL_KEY_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_set_tunnel_interface_ca67182c",
                                VL_API_IKEV2_SET_TUNNEL_INTERFACE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_set_tunnel_interface_reply_e8d4e804",
                                VL_API_IKEV2_SET_TUNNEL_INTERFACE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_set_responder_a2055df1",
                                VL_API_IKEV2_SET_RESPONDER + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_set_responder_reply_e8d4e804",
                                VL_API_IKEV2_SET_RESPONDER_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_set_responder_hostname_350d6949",
                                VL_API_IKEV2_SET_RESPONDER_HOSTNAME + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_set_responder_hostname_reply_e8d4e804",
                                VL_API_IKEV2_SET_RESPONDER_HOSTNAME_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_set_ike_transforms_076d7378",
                                VL_API_IKEV2_SET_IKE_TRANSFORMS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_set_ike_transforms_reply_e8d4e804",
                                VL_API_IKEV2_SET_IKE_TRANSFORMS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_set_esp_transforms_a63dc205",
                                VL_API_IKEV2_SET_ESP_TRANSFORMS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_set_esp_transforms_reply_e8d4e804",
                                VL_API_IKEV2_SET_ESP_TRANSFORMS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_set_sa_lifetime_7039feaa",
                                VL_API_IKEV2_SET_SA_LIFETIME + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_set_sa_lifetime_reply_e8d4e804",
                                VL_API_IKEV2_SET_SA_LIFETIME_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_initiate_sa_init_ebf79a66",
                                VL_API_IKEV2_INITIATE_SA_INIT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_initiate_sa_init_reply_e8d4e804",
                                VL_API_IKEV2_INITIATE_SA_INIT_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_initiate_del_ike_sa_8d125bdd",
                                VL_API_IKEV2_INITIATE_DEL_IKE_SA + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_initiate_del_ike_sa_reply_e8d4e804",
                                VL_API_IKEV2_INITIATE_DEL_IKE_SA_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_initiate_del_child_sa_7f004d2e",
                                VL_API_IKEV2_INITIATE_DEL_CHILD_SA + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_initiate_del_child_sa_reply_e8d4e804",
                                VL_API_IKEV2_INITIATE_DEL_CHILD_SA_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_initiate_rekey_child_sa_7f004d2e",
                                VL_API_IKEV2_INITIATE_REKEY_CHILD_SA + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_initiate_rekey_child_sa_reply_e8d4e804",
                                VL_API_IKEV2_INITIATE_REKEY_CHILD_SA_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_profile_set_udp_encap_ebf79a66",
                                VL_API_IKEV2_PROFILE_SET_UDP_ENCAP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_profile_set_udp_encap_reply_e8d4e804",
                                VL_API_IKEV2_PROFILE_SET_UDP_ENCAP_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_profile_set_ipsec_udp_port_615ce758",
                                VL_API_IKEV2_PROFILE_SET_IPSEC_UDP_PORT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_profile_set_ipsec_udp_port_reply_e8d4e804",
                                VL_API_IKEV2_PROFILE_SET_IPSEC_UDP_PORT_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_profile_set_liveness_6bdf4d65",
                                VL_API_IKEV2_PROFILE_SET_LIVENESS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ikev2_profile_set_liveness_reply_e8d4e804",
                                VL_API_IKEV2_PROFILE_SET_LIVENESS_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_PLUGIN_GET_VERSION + msg_id_base,
   .name = "ikev2_plugin_get_version",
   .handler = vl_api_ikev2_plugin_get_version_t_handler,
   .endian = vl_api_ikev2_plugin_get_version_t_endian,
   .format_fn = vl_api_ikev2_plugin_get_version_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_plugin_get_version_t_tojson,
   .fromjson = vl_api_ikev2_plugin_get_version_t_fromjson,
   .calc_size = vl_api_ikev2_plugin_get_version_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_PLUGIN_GET_VERSION_REPLY + msg_id_base,
  .name = "ikev2_plugin_get_version_reply",
  .handler = 0,
  .endian = vl_api_ikev2_plugin_get_version_reply_t_endian,
  .format_fn = vl_api_ikev2_plugin_get_version_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_plugin_get_version_reply_t_tojson,
  .fromjson = vl_api_ikev2_plugin_get_version_reply_t_fromjson,
  .calc_size = vl_api_ikev2_plugin_get_version_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_PLUGIN_SET_SLEEP_INTERVAL + msg_id_base,
   .name = "ikev2_plugin_set_sleep_interval",
   .handler = vl_api_ikev2_plugin_set_sleep_interval_t_handler,
   .endian = vl_api_ikev2_plugin_set_sleep_interval_t_endian,
   .format_fn = vl_api_ikev2_plugin_set_sleep_interval_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_plugin_set_sleep_interval_t_tojson,
   .fromjson = vl_api_ikev2_plugin_set_sleep_interval_t_fromjson,
   .calc_size = vl_api_ikev2_plugin_set_sleep_interval_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_PLUGIN_SET_SLEEP_INTERVAL_REPLY + msg_id_base,
  .name = "ikev2_plugin_set_sleep_interval_reply",
  .handler = 0,
  .endian = vl_api_ikev2_plugin_set_sleep_interval_reply_t_endian,
  .format_fn = vl_api_ikev2_plugin_set_sleep_interval_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_plugin_set_sleep_interval_reply_t_tojson,
  .fromjson = vl_api_ikev2_plugin_set_sleep_interval_reply_t_fromjson,
  .calc_size = vl_api_ikev2_plugin_set_sleep_interval_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_GET_SLEEP_INTERVAL + msg_id_base,
   .name = "ikev2_get_sleep_interval",
   .handler = vl_api_ikev2_get_sleep_interval_t_handler,
   .endian = vl_api_ikev2_get_sleep_interval_t_endian,
   .format_fn = vl_api_ikev2_get_sleep_interval_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_get_sleep_interval_t_tojson,
   .fromjson = vl_api_ikev2_get_sleep_interval_t_fromjson,
   .calc_size = vl_api_ikev2_get_sleep_interval_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_GET_SLEEP_INTERVAL_REPLY + msg_id_base,
  .name = "ikev2_get_sleep_interval_reply",
  .handler = 0,
  .endian = vl_api_ikev2_get_sleep_interval_reply_t_endian,
  .format_fn = vl_api_ikev2_get_sleep_interval_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_get_sleep_interval_reply_t_tojson,
  .fromjson = vl_api_ikev2_get_sleep_interval_reply_t_fromjson,
  .calc_size = vl_api_ikev2_get_sleep_interval_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_PROFILE_DUMP + msg_id_base,
   .name = "ikev2_profile_dump",
   .handler = vl_api_ikev2_profile_dump_t_handler,
   .endian = vl_api_ikev2_profile_dump_t_endian,
   .format_fn = vl_api_ikev2_profile_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_profile_dump_t_tojson,
   .fromjson = vl_api_ikev2_profile_dump_t_fromjson,
   .calc_size = vl_api_ikev2_profile_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_PROFILE_DETAILS + msg_id_base,
  .name = "ikev2_profile_details",
  .handler = 0,
  .endian = vl_api_ikev2_profile_details_t_endian,
  .format_fn = vl_api_ikev2_profile_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_profile_details_t_tojson,
  .fromjson = vl_api_ikev2_profile_details_t_fromjson,
  .calc_size = vl_api_ikev2_profile_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_SA_DUMP + msg_id_base,
   .name = "ikev2_sa_dump",
   .handler = vl_api_ikev2_sa_dump_t_handler,
   .endian = vl_api_ikev2_sa_dump_t_endian,
   .format_fn = vl_api_ikev2_sa_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_sa_dump_t_tojson,
   .fromjson = vl_api_ikev2_sa_dump_t_fromjson,
   .calc_size = vl_api_ikev2_sa_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_SA_DETAILS + msg_id_base,
  .name = "ikev2_sa_details",
  .handler = 0,
  .endian = vl_api_ikev2_sa_details_t_endian,
  .format_fn = vl_api_ikev2_sa_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_sa_details_t_tojson,
  .fromjson = vl_api_ikev2_sa_details_t_fromjson,
  .calc_size = vl_api_ikev2_sa_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_SA_V2_DUMP + msg_id_base,
   .name = "ikev2_sa_v2_dump",
   .handler = vl_api_ikev2_sa_v2_dump_t_handler,
   .endian = vl_api_ikev2_sa_v2_dump_t_endian,
   .format_fn = vl_api_ikev2_sa_v2_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_sa_v2_dump_t_tojson,
   .fromjson = vl_api_ikev2_sa_v2_dump_t_fromjson,
   .calc_size = vl_api_ikev2_sa_v2_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_SA_V2_DETAILS + msg_id_base,
  .name = "ikev2_sa_v2_details",
  .handler = 0,
  .endian = vl_api_ikev2_sa_v2_details_t_endian,
  .format_fn = vl_api_ikev2_sa_v2_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_sa_v2_details_t_tojson,
  .fromjson = vl_api_ikev2_sa_v2_details_t_fromjson,
  .calc_size = vl_api_ikev2_sa_v2_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_SA_V3_DUMP + msg_id_base,
   .name = "ikev2_sa_v3_dump",
   .handler = vl_api_ikev2_sa_v3_dump_t_handler,
   .endian = vl_api_ikev2_sa_v3_dump_t_endian,
   .format_fn = vl_api_ikev2_sa_v3_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_sa_v3_dump_t_tojson,
   .fromjson = vl_api_ikev2_sa_v3_dump_t_fromjson,
   .calc_size = vl_api_ikev2_sa_v3_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_SA_V3_DETAILS + msg_id_base,
  .name = "ikev2_sa_v3_details",
  .handler = 0,
  .endian = vl_api_ikev2_sa_v3_details_t_endian,
  .format_fn = vl_api_ikev2_sa_v3_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_sa_v3_details_t_tojson,
  .fromjson = vl_api_ikev2_sa_v3_details_t_fromjson,
  .calc_size = vl_api_ikev2_sa_v3_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_CHILD_SA_DUMP + msg_id_base,
   .name = "ikev2_child_sa_dump",
   .handler = vl_api_ikev2_child_sa_dump_t_handler,
   .endian = vl_api_ikev2_child_sa_dump_t_endian,
   .format_fn = vl_api_ikev2_child_sa_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_child_sa_dump_t_tojson,
   .fromjson = vl_api_ikev2_child_sa_dump_t_fromjson,
   .calc_size = vl_api_ikev2_child_sa_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_CHILD_SA_DETAILS + msg_id_base,
  .name = "ikev2_child_sa_details",
  .handler = 0,
  .endian = vl_api_ikev2_child_sa_details_t_endian,
  .format_fn = vl_api_ikev2_child_sa_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_child_sa_details_t_tojson,
  .fromjson = vl_api_ikev2_child_sa_details_t_fromjson,
  .calc_size = vl_api_ikev2_child_sa_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_CHILD_SA_V2_DUMP + msg_id_base,
   .name = "ikev2_child_sa_v2_dump",
   .handler = vl_api_ikev2_child_sa_v2_dump_t_handler,
   .endian = vl_api_ikev2_child_sa_v2_dump_t_endian,
   .format_fn = vl_api_ikev2_child_sa_v2_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_child_sa_v2_dump_t_tojson,
   .fromjson = vl_api_ikev2_child_sa_v2_dump_t_fromjson,
   .calc_size = vl_api_ikev2_child_sa_v2_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_CHILD_SA_V2_DETAILS + msg_id_base,
  .name = "ikev2_child_sa_v2_details",
  .handler = 0,
  .endian = vl_api_ikev2_child_sa_v2_details_t_endian,
  .format_fn = vl_api_ikev2_child_sa_v2_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_child_sa_v2_details_t_tojson,
  .fromjson = vl_api_ikev2_child_sa_v2_details_t_fromjson,
  .calc_size = vl_api_ikev2_child_sa_v2_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_NONCE_GET + msg_id_base,
   .name = "ikev2_nonce_get",
   .handler = vl_api_ikev2_nonce_get_t_handler,
   .endian = vl_api_ikev2_nonce_get_t_endian,
   .format_fn = vl_api_ikev2_nonce_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_nonce_get_t_tojson,
   .fromjson = vl_api_ikev2_nonce_get_t_fromjson,
   .calc_size = vl_api_ikev2_nonce_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_NONCE_GET_REPLY + msg_id_base,
  .name = "ikev2_nonce_get_reply",
  .handler = 0,
  .endian = vl_api_ikev2_nonce_get_reply_t_endian,
  .format_fn = vl_api_ikev2_nonce_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_nonce_get_reply_t_tojson,
  .fromjson = vl_api_ikev2_nonce_get_reply_t_fromjson,
  .calc_size = vl_api_ikev2_nonce_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_TRAFFIC_SELECTOR_DUMP + msg_id_base,
   .name = "ikev2_traffic_selector_dump",
   .handler = vl_api_ikev2_traffic_selector_dump_t_handler,
   .endian = vl_api_ikev2_traffic_selector_dump_t_endian,
   .format_fn = vl_api_ikev2_traffic_selector_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_traffic_selector_dump_t_tojson,
   .fromjson = vl_api_ikev2_traffic_selector_dump_t_fromjson,
   .calc_size = vl_api_ikev2_traffic_selector_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_TRAFFIC_SELECTOR_DETAILS + msg_id_base,
  .name = "ikev2_traffic_selector_details",
  .handler = 0,
  .endian = vl_api_ikev2_traffic_selector_details_t_endian,
  .format_fn = vl_api_ikev2_traffic_selector_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_traffic_selector_details_t_tojson,
  .fromjson = vl_api_ikev2_traffic_selector_details_t_fromjson,
  .calc_size = vl_api_ikev2_traffic_selector_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_PROFILE_ADD_DEL + msg_id_base,
   .name = "ikev2_profile_add_del",
   .handler = vl_api_ikev2_profile_add_del_t_handler,
   .endian = vl_api_ikev2_profile_add_del_t_endian,
   .format_fn = vl_api_ikev2_profile_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_profile_add_del_t_tojson,
   .fromjson = vl_api_ikev2_profile_add_del_t_fromjson,
   .calc_size = vl_api_ikev2_profile_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_PROFILE_ADD_DEL_REPLY + msg_id_base,
  .name = "ikev2_profile_add_del_reply",
  .handler = 0,
  .endian = vl_api_ikev2_profile_add_del_reply_t_endian,
  .format_fn = vl_api_ikev2_profile_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_profile_add_del_reply_t_tojson,
  .fromjson = vl_api_ikev2_profile_add_del_reply_t_fromjson,
  .calc_size = vl_api_ikev2_profile_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_PROFILE_SET_AUTH + msg_id_base,
   .name = "ikev2_profile_set_auth",
   .handler = vl_api_ikev2_profile_set_auth_t_handler,
   .endian = vl_api_ikev2_profile_set_auth_t_endian,
   .format_fn = vl_api_ikev2_profile_set_auth_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_profile_set_auth_t_tojson,
   .fromjson = vl_api_ikev2_profile_set_auth_t_fromjson,
   .calc_size = vl_api_ikev2_profile_set_auth_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_PROFILE_SET_AUTH_REPLY + msg_id_base,
  .name = "ikev2_profile_set_auth_reply",
  .handler = 0,
  .endian = vl_api_ikev2_profile_set_auth_reply_t_endian,
  .format_fn = vl_api_ikev2_profile_set_auth_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_profile_set_auth_reply_t_tojson,
  .fromjson = vl_api_ikev2_profile_set_auth_reply_t_fromjson,
  .calc_size = vl_api_ikev2_profile_set_auth_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_PROFILE_SET_ID + msg_id_base,
   .name = "ikev2_profile_set_id",
   .handler = vl_api_ikev2_profile_set_id_t_handler,
   .endian = vl_api_ikev2_profile_set_id_t_endian,
   .format_fn = vl_api_ikev2_profile_set_id_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_profile_set_id_t_tojson,
   .fromjson = vl_api_ikev2_profile_set_id_t_fromjson,
   .calc_size = vl_api_ikev2_profile_set_id_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_PROFILE_SET_ID_REPLY + msg_id_base,
  .name = "ikev2_profile_set_id_reply",
  .handler = 0,
  .endian = vl_api_ikev2_profile_set_id_reply_t_endian,
  .format_fn = vl_api_ikev2_profile_set_id_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_profile_set_id_reply_t_tojson,
  .fromjson = vl_api_ikev2_profile_set_id_reply_t_fromjson,
  .calc_size = vl_api_ikev2_profile_set_id_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_PROFILE_DISABLE_NATT + msg_id_base,
   .name = "ikev2_profile_disable_natt",
   .handler = vl_api_ikev2_profile_disable_natt_t_handler,
   .endian = vl_api_ikev2_profile_disable_natt_t_endian,
   .format_fn = vl_api_ikev2_profile_disable_natt_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_profile_disable_natt_t_tojson,
   .fromjson = vl_api_ikev2_profile_disable_natt_t_fromjson,
   .calc_size = vl_api_ikev2_profile_disable_natt_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_PROFILE_DISABLE_NATT_REPLY + msg_id_base,
  .name = "ikev2_profile_disable_natt_reply",
  .handler = 0,
  .endian = vl_api_ikev2_profile_disable_natt_reply_t_endian,
  .format_fn = vl_api_ikev2_profile_disable_natt_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_profile_disable_natt_reply_t_tojson,
  .fromjson = vl_api_ikev2_profile_disable_natt_reply_t_fromjson,
  .calc_size = vl_api_ikev2_profile_disable_natt_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_PROFILE_SET_TS + msg_id_base,
   .name = "ikev2_profile_set_ts",
   .handler = vl_api_ikev2_profile_set_ts_t_handler,
   .endian = vl_api_ikev2_profile_set_ts_t_endian,
   .format_fn = vl_api_ikev2_profile_set_ts_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_profile_set_ts_t_tojson,
   .fromjson = vl_api_ikev2_profile_set_ts_t_fromjson,
   .calc_size = vl_api_ikev2_profile_set_ts_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_PROFILE_SET_TS_REPLY + msg_id_base,
  .name = "ikev2_profile_set_ts_reply",
  .handler = 0,
  .endian = vl_api_ikev2_profile_set_ts_reply_t_endian,
  .format_fn = vl_api_ikev2_profile_set_ts_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_profile_set_ts_reply_t_tojson,
  .fromjson = vl_api_ikev2_profile_set_ts_reply_t_fromjson,
  .calc_size = vl_api_ikev2_profile_set_ts_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_SET_LOCAL_KEY + msg_id_base,
   .name = "ikev2_set_local_key",
   .handler = vl_api_ikev2_set_local_key_t_handler,
   .endian = vl_api_ikev2_set_local_key_t_endian,
   .format_fn = vl_api_ikev2_set_local_key_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_set_local_key_t_tojson,
   .fromjson = vl_api_ikev2_set_local_key_t_fromjson,
   .calc_size = vl_api_ikev2_set_local_key_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_SET_LOCAL_KEY_REPLY + msg_id_base,
  .name = "ikev2_set_local_key_reply",
  .handler = 0,
  .endian = vl_api_ikev2_set_local_key_reply_t_endian,
  .format_fn = vl_api_ikev2_set_local_key_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_set_local_key_reply_t_tojson,
  .fromjson = vl_api_ikev2_set_local_key_reply_t_fromjson,
  .calc_size = vl_api_ikev2_set_local_key_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_SET_TUNNEL_INTERFACE + msg_id_base,
   .name = "ikev2_set_tunnel_interface",
   .handler = vl_api_ikev2_set_tunnel_interface_t_handler,
   .endian = vl_api_ikev2_set_tunnel_interface_t_endian,
   .format_fn = vl_api_ikev2_set_tunnel_interface_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_set_tunnel_interface_t_tojson,
   .fromjson = vl_api_ikev2_set_tunnel_interface_t_fromjson,
   .calc_size = vl_api_ikev2_set_tunnel_interface_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_SET_TUNNEL_INTERFACE_REPLY + msg_id_base,
  .name = "ikev2_set_tunnel_interface_reply",
  .handler = 0,
  .endian = vl_api_ikev2_set_tunnel_interface_reply_t_endian,
  .format_fn = vl_api_ikev2_set_tunnel_interface_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_set_tunnel_interface_reply_t_tojson,
  .fromjson = vl_api_ikev2_set_tunnel_interface_reply_t_fromjson,
  .calc_size = vl_api_ikev2_set_tunnel_interface_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_SET_RESPONDER + msg_id_base,
   .name = "ikev2_set_responder",
   .handler = vl_api_ikev2_set_responder_t_handler,
   .endian = vl_api_ikev2_set_responder_t_endian,
   .format_fn = vl_api_ikev2_set_responder_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_set_responder_t_tojson,
   .fromjson = vl_api_ikev2_set_responder_t_fromjson,
   .calc_size = vl_api_ikev2_set_responder_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_SET_RESPONDER_REPLY + msg_id_base,
  .name = "ikev2_set_responder_reply",
  .handler = 0,
  .endian = vl_api_ikev2_set_responder_reply_t_endian,
  .format_fn = vl_api_ikev2_set_responder_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_set_responder_reply_t_tojson,
  .fromjson = vl_api_ikev2_set_responder_reply_t_fromjson,
  .calc_size = vl_api_ikev2_set_responder_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_SET_RESPONDER_HOSTNAME + msg_id_base,
   .name = "ikev2_set_responder_hostname",
   .handler = vl_api_ikev2_set_responder_hostname_t_handler,
   .endian = vl_api_ikev2_set_responder_hostname_t_endian,
   .format_fn = vl_api_ikev2_set_responder_hostname_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_set_responder_hostname_t_tojson,
   .fromjson = vl_api_ikev2_set_responder_hostname_t_fromjson,
   .calc_size = vl_api_ikev2_set_responder_hostname_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_SET_RESPONDER_HOSTNAME_REPLY + msg_id_base,
  .name = "ikev2_set_responder_hostname_reply",
  .handler = 0,
  .endian = vl_api_ikev2_set_responder_hostname_reply_t_endian,
  .format_fn = vl_api_ikev2_set_responder_hostname_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_set_responder_hostname_reply_t_tojson,
  .fromjson = vl_api_ikev2_set_responder_hostname_reply_t_fromjson,
  .calc_size = vl_api_ikev2_set_responder_hostname_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_SET_IKE_TRANSFORMS + msg_id_base,
   .name = "ikev2_set_ike_transforms",
   .handler = vl_api_ikev2_set_ike_transforms_t_handler,
   .endian = vl_api_ikev2_set_ike_transforms_t_endian,
   .format_fn = vl_api_ikev2_set_ike_transforms_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_set_ike_transforms_t_tojson,
   .fromjson = vl_api_ikev2_set_ike_transforms_t_fromjson,
   .calc_size = vl_api_ikev2_set_ike_transforms_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_SET_IKE_TRANSFORMS_REPLY + msg_id_base,
  .name = "ikev2_set_ike_transforms_reply",
  .handler = 0,
  .endian = vl_api_ikev2_set_ike_transforms_reply_t_endian,
  .format_fn = vl_api_ikev2_set_ike_transforms_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_set_ike_transforms_reply_t_tojson,
  .fromjson = vl_api_ikev2_set_ike_transforms_reply_t_fromjson,
  .calc_size = vl_api_ikev2_set_ike_transforms_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_SET_ESP_TRANSFORMS + msg_id_base,
   .name = "ikev2_set_esp_transforms",
   .handler = vl_api_ikev2_set_esp_transforms_t_handler,
   .endian = vl_api_ikev2_set_esp_transforms_t_endian,
   .format_fn = vl_api_ikev2_set_esp_transforms_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_set_esp_transforms_t_tojson,
   .fromjson = vl_api_ikev2_set_esp_transforms_t_fromjson,
   .calc_size = vl_api_ikev2_set_esp_transforms_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_SET_ESP_TRANSFORMS_REPLY + msg_id_base,
  .name = "ikev2_set_esp_transforms_reply",
  .handler = 0,
  .endian = vl_api_ikev2_set_esp_transforms_reply_t_endian,
  .format_fn = vl_api_ikev2_set_esp_transforms_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_set_esp_transforms_reply_t_tojson,
  .fromjson = vl_api_ikev2_set_esp_transforms_reply_t_fromjson,
  .calc_size = vl_api_ikev2_set_esp_transforms_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_SET_SA_LIFETIME + msg_id_base,
   .name = "ikev2_set_sa_lifetime",
   .handler = vl_api_ikev2_set_sa_lifetime_t_handler,
   .endian = vl_api_ikev2_set_sa_lifetime_t_endian,
   .format_fn = vl_api_ikev2_set_sa_lifetime_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_set_sa_lifetime_t_tojson,
   .fromjson = vl_api_ikev2_set_sa_lifetime_t_fromjson,
   .calc_size = vl_api_ikev2_set_sa_lifetime_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_SET_SA_LIFETIME_REPLY + msg_id_base,
  .name = "ikev2_set_sa_lifetime_reply",
  .handler = 0,
  .endian = vl_api_ikev2_set_sa_lifetime_reply_t_endian,
  .format_fn = vl_api_ikev2_set_sa_lifetime_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_set_sa_lifetime_reply_t_tojson,
  .fromjson = vl_api_ikev2_set_sa_lifetime_reply_t_fromjson,
  .calc_size = vl_api_ikev2_set_sa_lifetime_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_INITIATE_SA_INIT + msg_id_base,
   .name = "ikev2_initiate_sa_init",
   .handler = vl_api_ikev2_initiate_sa_init_t_handler,
   .endian = vl_api_ikev2_initiate_sa_init_t_endian,
   .format_fn = vl_api_ikev2_initiate_sa_init_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_initiate_sa_init_t_tojson,
   .fromjson = vl_api_ikev2_initiate_sa_init_t_fromjson,
   .calc_size = vl_api_ikev2_initiate_sa_init_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_INITIATE_SA_INIT_REPLY + msg_id_base,
  .name = "ikev2_initiate_sa_init_reply",
  .handler = 0,
  .endian = vl_api_ikev2_initiate_sa_init_reply_t_endian,
  .format_fn = vl_api_ikev2_initiate_sa_init_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_initiate_sa_init_reply_t_tojson,
  .fromjson = vl_api_ikev2_initiate_sa_init_reply_t_fromjson,
  .calc_size = vl_api_ikev2_initiate_sa_init_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_INITIATE_DEL_IKE_SA + msg_id_base,
   .name = "ikev2_initiate_del_ike_sa",
   .handler = vl_api_ikev2_initiate_del_ike_sa_t_handler,
   .endian = vl_api_ikev2_initiate_del_ike_sa_t_endian,
   .format_fn = vl_api_ikev2_initiate_del_ike_sa_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_initiate_del_ike_sa_t_tojson,
   .fromjson = vl_api_ikev2_initiate_del_ike_sa_t_fromjson,
   .calc_size = vl_api_ikev2_initiate_del_ike_sa_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_INITIATE_DEL_IKE_SA_REPLY + msg_id_base,
  .name = "ikev2_initiate_del_ike_sa_reply",
  .handler = 0,
  .endian = vl_api_ikev2_initiate_del_ike_sa_reply_t_endian,
  .format_fn = vl_api_ikev2_initiate_del_ike_sa_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_initiate_del_ike_sa_reply_t_tojson,
  .fromjson = vl_api_ikev2_initiate_del_ike_sa_reply_t_fromjson,
  .calc_size = vl_api_ikev2_initiate_del_ike_sa_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_INITIATE_DEL_CHILD_SA + msg_id_base,
   .name = "ikev2_initiate_del_child_sa",
   .handler = vl_api_ikev2_initiate_del_child_sa_t_handler,
   .endian = vl_api_ikev2_initiate_del_child_sa_t_endian,
   .format_fn = vl_api_ikev2_initiate_del_child_sa_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_initiate_del_child_sa_t_tojson,
   .fromjson = vl_api_ikev2_initiate_del_child_sa_t_fromjson,
   .calc_size = vl_api_ikev2_initiate_del_child_sa_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_INITIATE_DEL_CHILD_SA_REPLY + msg_id_base,
  .name = "ikev2_initiate_del_child_sa_reply",
  .handler = 0,
  .endian = vl_api_ikev2_initiate_del_child_sa_reply_t_endian,
  .format_fn = vl_api_ikev2_initiate_del_child_sa_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_initiate_del_child_sa_reply_t_tojson,
  .fromjson = vl_api_ikev2_initiate_del_child_sa_reply_t_fromjson,
  .calc_size = vl_api_ikev2_initiate_del_child_sa_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_INITIATE_REKEY_CHILD_SA + msg_id_base,
   .name = "ikev2_initiate_rekey_child_sa",
   .handler = vl_api_ikev2_initiate_rekey_child_sa_t_handler,
   .endian = vl_api_ikev2_initiate_rekey_child_sa_t_endian,
   .format_fn = vl_api_ikev2_initiate_rekey_child_sa_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_initiate_rekey_child_sa_t_tojson,
   .fromjson = vl_api_ikev2_initiate_rekey_child_sa_t_fromjson,
   .calc_size = vl_api_ikev2_initiate_rekey_child_sa_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_INITIATE_REKEY_CHILD_SA_REPLY + msg_id_base,
  .name = "ikev2_initiate_rekey_child_sa_reply",
  .handler = 0,
  .endian = vl_api_ikev2_initiate_rekey_child_sa_reply_t_endian,
  .format_fn = vl_api_ikev2_initiate_rekey_child_sa_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_initiate_rekey_child_sa_reply_t_tojson,
  .fromjson = vl_api_ikev2_initiate_rekey_child_sa_reply_t_fromjson,
  .calc_size = vl_api_ikev2_initiate_rekey_child_sa_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_PROFILE_SET_UDP_ENCAP + msg_id_base,
   .name = "ikev2_profile_set_udp_encap",
   .handler = vl_api_ikev2_profile_set_udp_encap_t_handler,
   .endian = vl_api_ikev2_profile_set_udp_encap_t_endian,
   .format_fn = vl_api_ikev2_profile_set_udp_encap_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_profile_set_udp_encap_t_tojson,
   .fromjson = vl_api_ikev2_profile_set_udp_encap_t_fromjson,
   .calc_size = vl_api_ikev2_profile_set_udp_encap_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_PROFILE_SET_UDP_ENCAP_REPLY + msg_id_base,
  .name = "ikev2_profile_set_udp_encap_reply",
  .handler = 0,
  .endian = vl_api_ikev2_profile_set_udp_encap_reply_t_endian,
  .format_fn = vl_api_ikev2_profile_set_udp_encap_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_profile_set_udp_encap_reply_t_tojson,
  .fromjson = vl_api_ikev2_profile_set_udp_encap_reply_t_fromjson,
  .calc_size = vl_api_ikev2_profile_set_udp_encap_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_PROFILE_SET_IPSEC_UDP_PORT + msg_id_base,
   .name = "ikev2_profile_set_ipsec_udp_port",
   .handler = vl_api_ikev2_profile_set_ipsec_udp_port_t_handler,
   .endian = vl_api_ikev2_profile_set_ipsec_udp_port_t_endian,
   .format_fn = vl_api_ikev2_profile_set_ipsec_udp_port_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_profile_set_ipsec_udp_port_t_tojson,
   .fromjson = vl_api_ikev2_profile_set_ipsec_udp_port_t_fromjson,
   .calc_size = vl_api_ikev2_profile_set_ipsec_udp_port_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_PROFILE_SET_IPSEC_UDP_PORT_REPLY + msg_id_base,
  .name = "ikev2_profile_set_ipsec_udp_port_reply",
  .handler = 0,
  .endian = vl_api_ikev2_profile_set_ipsec_udp_port_reply_t_endian,
  .format_fn = vl_api_ikev2_profile_set_ipsec_udp_port_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_profile_set_ipsec_udp_port_reply_t_tojson,
  .fromjson = vl_api_ikev2_profile_set_ipsec_udp_port_reply_t_fromjson,
  .calc_size = vl_api_ikev2_profile_set_ipsec_udp_port_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IKEV2_PROFILE_SET_LIVENESS + msg_id_base,
   .name = "ikev2_profile_set_liveness",
   .handler = vl_api_ikev2_profile_set_liveness_t_handler,
   .endian = vl_api_ikev2_profile_set_liveness_t_endian,
   .format_fn = vl_api_ikev2_profile_set_liveness_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ikev2_profile_set_liveness_t_tojson,
   .fromjson = vl_api_ikev2_profile_set_liveness_t_fromjson,
   .calc_size = vl_api_ikev2_profile_set_liveness_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IKEV2_PROFILE_SET_LIVENESS_REPLY + msg_id_base,
  .name = "ikev2_profile_set_liveness_reply",
  .handler = 0,
  .endian = vl_api_ikev2_profile_set_liveness_reply_t_endian,
  .format_fn = vl_api_ikev2_profile_set_liveness_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ikev2_profile_set_liveness_reply_t_tojson,
  .fromjson = vl_api_ikev2_profile_set_liveness_reply_t_fromjson,
  .calc_size = vl_api_ikev2_profile_set_liveness_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
vlib_error_desc_t ikev2_error_counters[] = {
  {
   .name = "processed",
   .desc = "packets processed",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "ike_sa_init_retransmit",
   .desc = "IKE SA INIT retransmit",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "ike_sa_init_ignore",
   .desc = "IKE_SA_INIT ignore (IKE SA already auth)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "ike_req_retransmit",
   .desc = "IKE request retransmit",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "ike_req_ignore",
   .desc = "IKE request ignore (old msgid)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "not_ikev2",
   .desc = "Non IKEv2 packets received",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "bad_length",
   .desc = "Bad packet length",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "malformed_packet",
   .desc = "Malformed packet",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "no_buff_space",
   .desc = "No buffer space",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "keepalive",
   .desc = "IKE keepalive messages received",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "rekey_req",
   .desc = "IKE rekey requests received",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "init_sa_req",
   .desc = "IKE EXCHANGE SA requests received",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "ike_auth_req",
   .desc = "IKE AUTH SA requests received",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "handoff",
   .desc = "IKE packets handoff",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
};
