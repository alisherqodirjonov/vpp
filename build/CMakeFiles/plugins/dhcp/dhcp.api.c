#define vl_endianfun		/* define message structures */
#include "dhcp.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "dhcp.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "dhcp.api.h"
#undef vl_printfun

#include "dhcp.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("dhcp_287ada20", VL_MSG_DHCP_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_dhcp);
   vl_msg_api_add_msg_name_crc (am, "dhcp_plugin_get_version_51077d14",
                                VL_API_DHCP_PLUGIN_GET_VERSION + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp_plugin_get_version_reply_9b32cf86",
                                VL_API_DHCP_PLUGIN_GET_VERSION_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp_plugin_control_ping_51077d14",
                                VL_API_DHCP_PLUGIN_CONTROL_PING + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp_plugin_control_ping_reply_f6b0b8ca",
                                VL_API_DHCP_PLUGIN_CONTROL_PING_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp_proxy_config_4058a689",
                                VL_API_DHCP_PROXY_CONFIG + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp_proxy_config_reply_e8d4e804",
                                VL_API_DHCP_PROXY_CONFIG_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp_proxy_set_vss_50537301",
                                VL_API_DHCP_PROXY_SET_VSS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp_proxy_set_vss_reply_e8d4e804",
                                VL_API_DHCP_PROXY_SET_VSS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp_client_config_1af013ea",
                                VL_API_DHCP_CLIENT_CONFIG + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp_client_config_reply_e8d4e804",
                                VL_API_DHCP_CLIENT_CONFIG_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp_compl_event_e18124b7",
                                VL_API_DHCP_COMPL_EVENT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp_client_dump_51077d14",
                                VL_API_DHCP_CLIENT_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp_client_details_8897b2d8",
                                VL_API_DHCP_CLIENT_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp_proxy_dump_5c5b063f",
                                VL_API_DHCP_PROXY_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp_proxy_details_dcbaf540",
                                VL_API_DHCP_PROXY_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp_client_detect_enable_disable_ae6cfcfb",
                                VL_API_DHCP_CLIENT_DETECT_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp_client_detect_enable_disable_reply_e8d4e804",
                                VL_API_DHCP_CLIENT_DETECT_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp6_duid_ll_set_0f6ca323",
                                VL_API_DHCP6_DUID_LL_SET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp6_duid_ll_set_reply_e8d4e804",
                                VL_API_DHCP6_DUID_LL_SET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp6_clients_enable_disable_b3e225d2",
                                VL_API_DHCP6_CLIENTS_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp6_clients_enable_disable_reply_e8d4e804",
                                VL_API_DHCP6_CLIENTS_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp6_send_client_message_f8222476",
                                VL_API_DHCP6_SEND_CLIENT_MESSAGE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp6_send_client_message_reply_e8d4e804",
                                VL_API_DHCP6_SEND_CLIENT_MESSAGE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp6_pd_send_client_message_3739fd8d",
                                VL_API_DHCP6_PD_SEND_CLIENT_MESSAGE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp6_pd_send_client_message_reply_e8d4e804",
                                VL_API_DHCP6_PD_SEND_CLIENT_MESSAGE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_dhcp6_reply_events_05b454b5",
                                VL_API_WANT_DHCP6_REPLY_EVENTS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_dhcp6_reply_events_reply_e8d4e804",
                                VL_API_WANT_DHCP6_REPLY_EVENTS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_dhcp6_pd_reply_events_c5e2af94",
                                VL_API_WANT_DHCP6_PD_REPLY_EVENTS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_dhcp6_pd_reply_events_reply_e8d4e804",
                                VL_API_WANT_DHCP6_PD_REPLY_EVENTS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp6_reply_event_85b7b17e",
                                VL_API_DHCP6_REPLY_EVENT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "dhcp6_pd_reply_event_5e878029",
                                VL_API_DHCP6_PD_REPLY_EVENT + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DHCP_CLIENT_CONFIG + msg_id_base,
   .name = "dhcp_client_config",
   .handler = vl_api_dhcp_client_config_t_handler,
   .endian = vl_api_dhcp_client_config_t_endian,
   .format_fn = vl_api_dhcp_client_config_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dhcp_client_config_t_tojson,
   .fromjson = vl_api_dhcp_client_config_t_fromjson,
   .calc_size = vl_api_dhcp_client_config_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DHCP_CLIENT_CONFIG_REPLY + msg_id_base,
  .name = "dhcp_client_config_reply",
  .handler = 0,
  .endian = vl_api_dhcp_client_config_reply_t_endian,
  .format_fn = vl_api_dhcp_client_config_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dhcp_client_config_reply_t_tojson,
  .fromjson = vl_api_dhcp_client_config_reply_t_fromjson,
  .calc_size = vl_api_dhcp_client_config_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_WANT_DHCP6_REPLY_EVENTS + msg_id_base,
   .name = "want_dhcp6_reply_events",
   .handler = vl_api_want_dhcp6_reply_events_t_handler,
   .endian = vl_api_want_dhcp6_reply_events_t_endian,
   .format_fn = vl_api_want_dhcp6_reply_events_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_want_dhcp6_reply_events_t_tojson,
   .fromjson = vl_api_want_dhcp6_reply_events_t_fromjson,
   .calc_size = vl_api_want_dhcp6_reply_events_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_WANT_DHCP6_REPLY_EVENTS_REPLY + msg_id_base,
  .name = "want_dhcp6_reply_events_reply",
  .handler = 0,
  .endian = vl_api_want_dhcp6_reply_events_reply_t_endian,
  .format_fn = vl_api_want_dhcp6_reply_events_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_want_dhcp6_reply_events_reply_t_tojson,
  .fromjson = vl_api_want_dhcp6_reply_events_reply_t_fromjson,
  .calc_size = vl_api_want_dhcp6_reply_events_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_WANT_DHCP6_PD_REPLY_EVENTS + msg_id_base,
   .name = "want_dhcp6_pd_reply_events",
   .handler = vl_api_want_dhcp6_pd_reply_events_t_handler,
   .endian = vl_api_want_dhcp6_pd_reply_events_t_endian,
   .format_fn = vl_api_want_dhcp6_pd_reply_events_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_want_dhcp6_pd_reply_events_t_tojson,
   .fromjson = vl_api_want_dhcp6_pd_reply_events_t_fromjson,
   .calc_size = vl_api_want_dhcp6_pd_reply_events_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_WANT_DHCP6_PD_REPLY_EVENTS_REPLY + msg_id_base,
  .name = "want_dhcp6_pd_reply_events_reply",
  .handler = 0,
  .endian = vl_api_want_dhcp6_pd_reply_events_reply_t_endian,
  .format_fn = vl_api_want_dhcp6_pd_reply_events_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_want_dhcp6_pd_reply_events_reply_t_tojson,
  .fromjson = vl_api_want_dhcp6_pd_reply_events_reply_t_fromjson,
  .calc_size = vl_api_want_dhcp6_pd_reply_events_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DHCP_PLUGIN_GET_VERSION + msg_id_base,
   .name = "dhcp_plugin_get_version",
   .handler = vl_api_dhcp_plugin_get_version_t_handler,
   .endian = vl_api_dhcp_plugin_get_version_t_endian,
   .format_fn = vl_api_dhcp_plugin_get_version_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dhcp_plugin_get_version_t_tojson,
   .fromjson = vl_api_dhcp_plugin_get_version_t_fromjson,
   .calc_size = vl_api_dhcp_plugin_get_version_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DHCP_PLUGIN_GET_VERSION_REPLY + msg_id_base,
  .name = "dhcp_plugin_get_version_reply",
  .handler = 0,
  .endian = vl_api_dhcp_plugin_get_version_reply_t_endian,
  .format_fn = vl_api_dhcp_plugin_get_version_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dhcp_plugin_get_version_reply_t_tojson,
  .fromjson = vl_api_dhcp_plugin_get_version_reply_t_fromjson,
  .calc_size = vl_api_dhcp_plugin_get_version_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DHCP_PLUGIN_CONTROL_PING + msg_id_base,
   .name = "dhcp_plugin_control_ping",
   .handler = vl_api_dhcp_plugin_control_ping_t_handler,
   .endian = vl_api_dhcp_plugin_control_ping_t_endian,
   .format_fn = vl_api_dhcp_plugin_control_ping_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dhcp_plugin_control_ping_t_tojson,
   .fromjson = vl_api_dhcp_plugin_control_ping_t_fromjson,
   .calc_size = vl_api_dhcp_plugin_control_ping_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DHCP_PLUGIN_CONTROL_PING_REPLY + msg_id_base,
  .name = "dhcp_plugin_control_ping_reply",
  .handler = 0,
  .endian = vl_api_dhcp_plugin_control_ping_reply_t_endian,
  .format_fn = vl_api_dhcp_plugin_control_ping_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dhcp_plugin_control_ping_reply_t_tojson,
  .fromjson = vl_api_dhcp_plugin_control_ping_reply_t_fromjson,
  .calc_size = vl_api_dhcp_plugin_control_ping_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DHCP_PROXY_CONFIG + msg_id_base,
   .name = "dhcp_proxy_config",
   .handler = vl_api_dhcp_proxy_config_t_handler,
   .endian = vl_api_dhcp_proxy_config_t_endian,
   .format_fn = vl_api_dhcp_proxy_config_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dhcp_proxy_config_t_tojson,
   .fromjson = vl_api_dhcp_proxy_config_t_fromjson,
   .calc_size = vl_api_dhcp_proxy_config_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DHCP_PROXY_CONFIG_REPLY + msg_id_base,
  .name = "dhcp_proxy_config_reply",
  .handler = 0,
  .endian = vl_api_dhcp_proxy_config_reply_t_endian,
  .format_fn = vl_api_dhcp_proxy_config_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dhcp_proxy_config_reply_t_tojson,
  .fromjson = vl_api_dhcp_proxy_config_reply_t_fromjson,
  .calc_size = vl_api_dhcp_proxy_config_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DHCP_PROXY_SET_VSS + msg_id_base,
   .name = "dhcp_proxy_set_vss",
   .handler = vl_api_dhcp_proxy_set_vss_t_handler,
   .endian = vl_api_dhcp_proxy_set_vss_t_endian,
   .format_fn = vl_api_dhcp_proxy_set_vss_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dhcp_proxy_set_vss_t_tojson,
   .fromjson = vl_api_dhcp_proxy_set_vss_t_fromjson,
   .calc_size = vl_api_dhcp_proxy_set_vss_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DHCP_PROXY_SET_VSS_REPLY + msg_id_base,
  .name = "dhcp_proxy_set_vss_reply",
  .handler = 0,
  .endian = vl_api_dhcp_proxy_set_vss_reply_t_endian,
  .format_fn = vl_api_dhcp_proxy_set_vss_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dhcp_proxy_set_vss_reply_t_tojson,
  .fromjson = vl_api_dhcp_proxy_set_vss_reply_t_fromjson,
  .calc_size = vl_api_dhcp_proxy_set_vss_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DHCP_CLIENT_DUMP + msg_id_base,
   .name = "dhcp_client_dump",
   .handler = vl_api_dhcp_client_dump_t_handler,
   .endian = vl_api_dhcp_client_dump_t_endian,
   .format_fn = vl_api_dhcp_client_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dhcp_client_dump_t_tojson,
   .fromjson = vl_api_dhcp_client_dump_t_fromjson,
   .calc_size = vl_api_dhcp_client_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DHCP_CLIENT_DETAILS + msg_id_base,
  .name = "dhcp_client_details",
  .handler = 0,
  .endian = vl_api_dhcp_client_details_t_endian,
  .format_fn = vl_api_dhcp_client_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dhcp_client_details_t_tojson,
  .fromjson = vl_api_dhcp_client_details_t_fromjson,
  .calc_size = vl_api_dhcp_client_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DHCP_PROXY_DUMP + msg_id_base,
   .name = "dhcp_proxy_dump",
   .handler = vl_api_dhcp_proxy_dump_t_handler,
   .endian = vl_api_dhcp_proxy_dump_t_endian,
   .format_fn = vl_api_dhcp_proxy_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dhcp_proxy_dump_t_tojson,
   .fromjson = vl_api_dhcp_proxy_dump_t_fromjson,
   .calc_size = vl_api_dhcp_proxy_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DHCP_PROXY_DETAILS + msg_id_base,
  .name = "dhcp_proxy_details",
  .handler = 0,
  .endian = vl_api_dhcp_proxy_details_t_endian,
  .format_fn = vl_api_dhcp_proxy_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dhcp_proxy_details_t_tojson,
  .fromjson = vl_api_dhcp_proxy_details_t_fromjson,
  .calc_size = vl_api_dhcp_proxy_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DHCP_CLIENT_DETECT_ENABLE_DISABLE + msg_id_base,
   .name = "dhcp_client_detect_enable_disable",
   .handler = vl_api_dhcp_client_detect_enable_disable_t_handler,
   .endian = vl_api_dhcp_client_detect_enable_disable_t_endian,
   .format_fn = vl_api_dhcp_client_detect_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dhcp_client_detect_enable_disable_t_tojson,
   .fromjson = vl_api_dhcp_client_detect_enable_disable_t_fromjson,
   .calc_size = vl_api_dhcp_client_detect_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DHCP_CLIENT_DETECT_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "dhcp_client_detect_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_dhcp_client_detect_enable_disable_reply_t_endian,
  .format_fn = vl_api_dhcp_client_detect_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dhcp_client_detect_enable_disable_reply_t_tojson,
  .fromjson = vl_api_dhcp_client_detect_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_dhcp_client_detect_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DHCP6_DUID_LL_SET + msg_id_base,
   .name = "dhcp6_duid_ll_set",
   .handler = vl_api_dhcp6_duid_ll_set_t_handler,
   .endian = vl_api_dhcp6_duid_ll_set_t_endian,
   .format_fn = vl_api_dhcp6_duid_ll_set_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dhcp6_duid_ll_set_t_tojson,
   .fromjson = vl_api_dhcp6_duid_ll_set_t_fromjson,
   .calc_size = vl_api_dhcp6_duid_ll_set_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DHCP6_DUID_LL_SET_REPLY + msg_id_base,
  .name = "dhcp6_duid_ll_set_reply",
  .handler = 0,
  .endian = vl_api_dhcp6_duid_ll_set_reply_t_endian,
  .format_fn = vl_api_dhcp6_duid_ll_set_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dhcp6_duid_ll_set_reply_t_tojson,
  .fromjson = vl_api_dhcp6_duid_ll_set_reply_t_fromjson,
  .calc_size = vl_api_dhcp6_duid_ll_set_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DHCP6_CLIENTS_ENABLE_DISABLE + msg_id_base,
   .name = "dhcp6_clients_enable_disable",
   .handler = vl_api_dhcp6_clients_enable_disable_t_handler,
   .endian = vl_api_dhcp6_clients_enable_disable_t_endian,
   .format_fn = vl_api_dhcp6_clients_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dhcp6_clients_enable_disable_t_tojson,
   .fromjson = vl_api_dhcp6_clients_enable_disable_t_fromjson,
   .calc_size = vl_api_dhcp6_clients_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DHCP6_CLIENTS_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "dhcp6_clients_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_dhcp6_clients_enable_disable_reply_t_endian,
  .format_fn = vl_api_dhcp6_clients_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dhcp6_clients_enable_disable_reply_t_tojson,
  .fromjson = vl_api_dhcp6_clients_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_dhcp6_clients_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DHCP6_SEND_CLIENT_MESSAGE + msg_id_base,
   .name = "dhcp6_send_client_message",
   .handler = vl_api_dhcp6_send_client_message_t_handler,
   .endian = vl_api_dhcp6_send_client_message_t_endian,
   .format_fn = vl_api_dhcp6_send_client_message_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dhcp6_send_client_message_t_tojson,
   .fromjson = vl_api_dhcp6_send_client_message_t_fromjson,
   .calc_size = vl_api_dhcp6_send_client_message_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DHCP6_SEND_CLIENT_MESSAGE_REPLY + msg_id_base,
  .name = "dhcp6_send_client_message_reply",
  .handler = 0,
  .endian = vl_api_dhcp6_send_client_message_reply_t_endian,
  .format_fn = vl_api_dhcp6_send_client_message_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dhcp6_send_client_message_reply_t_tojson,
  .fromjson = vl_api_dhcp6_send_client_message_reply_t_fromjson,
  .calc_size = vl_api_dhcp6_send_client_message_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_DHCP6_PD_SEND_CLIENT_MESSAGE + msg_id_base,
   .name = "dhcp6_pd_send_client_message",
   .handler = vl_api_dhcp6_pd_send_client_message_t_handler,
   .endian = vl_api_dhcp6_pd_send_client_message_t_endian,
   .format_fn = vl_api_dhcp6_pd_send_client_message_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_dhcp6_pd_send_client_message_t_tojson,
   .fromjson = vl_api_dhcp6_pd_send_client_message_t_fromjson,
   .calc_size = vl_api_dhcp6_pd_send_client_message_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_DHCP6_PD_SEND_CLIENT_MESSAGE_REPLY + msg_id_base,
  .name = "dhcp6_pd_send_client_message_reply",
  .handler = 0,
  .endian = vl_api_dhcp6_pd_send_client_message_reply_t_endian,
  .format_fn = vl_api_dhcp6_pd_send_client_message_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_dhcp6_pd_send_client_message_reply_t_tojson,
  .fromjson = vl_api_dhcp6_pd_send_client_message_reply_t_fromjson,
  .calc_size = vl_api_dhcp6_pd_send_client_message_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
