#define vl_endianfun		/* define message structures */
#include "ip6_nd.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ip6_nd.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "ip6_nd.api.h"
#undef vl_printfun

#include "ip6_nd.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("ip6_nd_deae73c7", VL_MSG_IP6_ND_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_ip6_nd);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_ip6nd_ra_config_3eb00b1c",
                                VL_API_SW_INTERFACE_IP6ND_RA_CONFIG + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_ip6nd_ra_config_reply_e8d4e804",
                                VL_API_SW_INTERFACE_IP6ND_RA_CONFIG_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_ip6nd_ra_prefix_82cc1b28",
                                VL_API_SW_INTERFACE_IP6ND_RA_PREFIX + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_ip6nd_ra_prefix_reply_e8d4e804",
                                VL_API_SW_INTERFACE_IP6ND_RA_PREFIX_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_ip6nd_ra_dump_f9e6675e",
                                VL_API_SW_INTERFACE_IP6ND_RA_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_ip6nd_ra_details_d3198de5",
                                VL_API_SW_INTERFACE_IP6ND_RA_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip6nd_proxy_enable_disable_7daa1e3a",
                                VL_API_IP6ND_PROXY_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip6nd_proxy_enable_disable_reply_e8d4e804",
                                VL_API_IP6ND_PROXY_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip6nd_proxy_add_del_c2e4a686",
                                VL_API_IP6ND_PROXY_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip6nd_proxy_add_del_reply_e8d4e804",
                                VL_API_IP6ND_PROXY_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip6nd_proxy_details_30b9ff4a",
                                VL_API_IP6ND_PROXY_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip6nd_proxy_dump_51077d14",
                                VL_API_IP6ND_PROXY_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip6nd_send_router_solicitation_e5de609c",
                                VL_API_IP6ND_SEND_ROUTER_SOLICITATION + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip6nd_send_router_solicitation_reply_e8d4e804",
                                VL_API_IP6ND_SEND_ROUTER_SOLICITATION_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_ip6_ra_events_3ec6d6c2",
                                VL_API_WANT_IP6_RA_EVENTS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "want_ip6_ra_events_reply_e8d4e804",
                                VL_API_WANT_IP6_RA_EVENTS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip6_ra_event_0364c1c5",
                                VL_API_IP6_RA_EVENT + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_WANT_IP6_RA_EVENTS + msg_id_base,
   .name = "want_ip6_ra_events",
   .handler = vl_api_want_ip6_ra_events_t_handler,
   .endian = vl_api_want_ip6_ra_events_t_endian,
   .format_fn = vl_api_want_ip6_ra_events_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_want_ip6_ra_events_t_tojson,
   .fromjson = vl_api_want_ip6_ra_events_t_fromjson,
   .calc_size = vl_api_want_ip6_ra_events_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_WANT_IP6_RA_EVENTS_REPLY + msg_id_base,
  .name = "want_ip6_ra_events_reply",
  .handler = 0,
  .endian = vl_api_want_ip6_ra_events_reply_t_endian,
  .format_fn = vl_api_want_ip6_ra_events_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_want_ip6_ra_events_reply_t_tojson,
  .fromjson = vl_api_want_ip6_ra_events_reply_t_fromjson,
  .calc_size = vl_api_want_ip6_ra_events_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_IP6ND_RA_CONFIG + msg_id_base,
   .name = "sw_interface_ip6nd_ra_config",
   .handler = vl_api_sw_interface_ip6nd_ra_config_t_handler,
   .endian = vl_api_sw_interface_ip6nd_ra_config_t_endian,
   .format_fn = vl_api_sw_interface_ip6nd_ra_config_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_ip6nd_ra_config_t_tojson,
   .fromjson = vl_api_sw_interface_ip6nd_ra_config_t_fromjson,
   .calc_size = vl_api_sw_interface_ip6nd_ra_config_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_IP6ND_RA_CONFIG_REPLY + msg_id_base,
  .name = "sw_interface_ip6nd_ra_config_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_ip6nd_ra_config_reply_t_endian,
  .format_fn = vl_api_sw_interface_ip6nd_ra_config_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_ip6nd_ra_config_reply_t_tojson,
  .fromjson = vl_api_sw_interface_ip6nd_ra_config_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_ip6nd_ra_config_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_IP6ND_RA_PREFIX + msg_id_base,
   .name = "sw_interface_ip6nd_ra_prefix",
   .handler = vl_api_sw_interface_ip6nd_ra_prefix_t_handler,
   .endian = vl_api_sw_interface_ip6nd_ra_prefix_t_endian,
   .format_fn = vl_api_sw_interface_ip6nd_ra_prefix_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_ip6nd_ra_prefix_t_tojson,
   .fromjson = vl_api_sw_interface_ip6nd_ra_prefix_t_fromjson,
   .calc_size = vl_api_sw_interface_ip6nd_ra_prefix_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_IP6ND_RA_PREFIX_REPLY + msg_id_base,
  .name = "sw_interface_ip6nd_ra_prefix_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_ip6nd_ra_prefix_reply_t_endian,
  .format_fn = vl_api_sw_interface_ip6nd_ra_prefix_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_ip6nd_ra_prefix_reply_t_tojson,
  .fromjson = vl_api_sw_interface_ip6nd_ra_prefix_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_ip6nd_ra_prefix_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_IP6ND_RA_DUMP + msg_id_base,
   .name = "sw_interface_ip6nd_ra_dump",
   .handler = vl_api_sw_interface_ip6nd_ra_dump_t_handler,
   .endian = vl_api_sw_interface_ip6nd_ra_dump_t_endian,
   .format_fn = vl_api_sw_interface_ip6nd_ra_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_ip6nd_ra_dump_t_tojson,
   .fromjson = vl_api_sw_interface_ip6nd_ra_dump_t_fromjson,
   .calc_size = vl_api_sw_interface_ip6nd_ra_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_IP6ND_RA_DETAILS + msg_id_base,
  .name = "sw_interface_ip6nd_ra_details",
  .handler = 0,
  .endian = vl_api_sw_interface_ip6nd_ra_details_t_endian,
  .format_fn = vl_api_sw_interface_ip6nd_ra_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_ip6nd_ra_details_t_tojson,
  .fromjson = vl_api_sw_interface_ip6nd_ra_details_t_fromjson,
  .calc_size = vl_api_sw_interface_ip6nd_ra_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP6ND_PROXY_ENABLE_DISABLE + msg_id_base,
   .name = "ip6nd_proxy_enable_disable",
   .handler = vl_api_ip6nd_proxy_enable_disable_t_handler,
   .endian = vl_api_ip6nd_proxy_enable_disable_t_endian,
   .format_fn = vl_api_ip6nd_proxy_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip6nd_proxy_enable_disable_t_tojson,
   .fromjson = vl_api_ip6nd_proxy_enable_disable_t_fromjson,
   .calc_size = vl_api_ip6nd_proxy_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP6ND_PROXY_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "ip6nd_proxy_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_ip6nd_proxy_enable_disable_reply_t_endian,
  .format_fn = vl_api_ip6nd_proxy_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip6nd_proxy_enable_disable_reply_t_tojson,
  .fromjson = vl_api_ip6nd_proxy_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_ip6nd_proxy_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP6ND_PROXY_ADD_DEL + msg_id_base,
   .name = "ip6nd_proxy_add_del",
   .handler = vl_api_ip6nd_proxy_add_del_t_handler,
   .endian = vl_api_ip6nd_proxy_add_del_t_endian,
   .format_fn = vl_api_ip6nd_proxy_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip6nd_proxy_add_del_t_tojson,
   .fromjson = vl_api_ip6nd_proxy_add_del_t_fromjson,
   .calc_size = vl_api_ip6nd_proxy_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP6ND_PROXY_ADD_DEL_REPLY + msg_id_base,
  .name = "ip6nd_proxy_add_del_reply",
  .handler = 0,
  .endian = vl_api_ip6nd_proxy_add_del_reply_t_endian,
  .format_fn = vl_api_ip6nd_proxy_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip6nd_proxy_add_del_reply_t_tojson,
  .fromjson = vl_api_ip6nd_proxy_add_del_reply_t_fromjson,
  .calc_size = vl_api_ip6nd_proxy_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP6ND_PROXY_DUMP + msg_id_base,
   .name = "ip6nd_proxy_dump",
   .handler = vl_api_ip6nd_proxy_dump_t_handler,
   .endian = vl_api_ip6nd_proxy_dump_t_endian,
   .format_fn = vl_api_ip6nd_proxy_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip6nd_proxy_dump_t_tojson,
   .fromjson = vl_api_ip6nd_proxy_dump_t_fromjson,
   .calc_size = vl_api_ip6nd_proxy_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP6ND_PROXY_DETAILS + msg_id_base,
  .name = "ip6nd_proxy_details",
  .handler = 0,
  .endian = vl_api_ip6nd_proxy_details_t_endian,
  .format_fn = vl_api_ip6nd_proxy_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip6nd_proxy_details_t_tojson,
  .fromjson = vl_api_ip6nd_proxy_details_t_fromjson,
  .calc_size = vl_api_ip6nd_proxy_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP6ND_SEND_ROUTER_SOLICITATION + msg_id_base,
   .name = "ip6nd_send_router_solicitation",
   .handler = vl_api_ip6nd_send_router_solicitation_t_handler,
   .endian = vl_api_ip6nd_send_router_solicitation_t_endian,
   .format_fn = vl_api_ip6nd_send_router_solicitation_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip6nd_send_router_solicitation_t_tojson,
   .fromjson = vl_api_ip6nd_send_router_solicitation_t_fromjson,
   .calc_size = vl_api_ip6nd_send_router_solicitation_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP6ND_SEND_ROUTER_SOLICITATION_REPLY + msg_id_base,
  .name = "ip6nd_send_router_solicitation_reply",
  .handler = 0,
  .endian = vl_api_ip6nd_send_router_solicitation_reply_t_endian,
  .format_fn = vl_api_ip6nd_send_router_solicitation_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip6nd_send_router_solicitation_reply_t_tojson,
  .fromjson = vl_api_ip6nd_send_router_solicitation_reply_t_fromjson,
  .calc_size = vl_api_ip6nd_send_router_solicitation_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
