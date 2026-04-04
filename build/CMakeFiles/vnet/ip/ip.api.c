#define vl_endianfun		/* define message structures */
#include "ip.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "ip.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "ip.api.h"
#undef vl_printfun

#include "ip.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("ip_4a15ce55", VL_MSG_IP_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_ip);
   vl_msg_api_add_msg_name_crc (am, "ip_table_add_del_0ffdaec0",
                                VL_API_IP_TABLE_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_table_add_del_reply_e8d4e804",
                                VL_API_IP_TABLE_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_table_add_del_v2_14e5081f",
                                VL_API_IP_TABLE_ADD_DEL_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_table_add_del_v2_reply_e8d4e804",
                                VL_API_IP_TABLE_ADD_DEL_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_table_allocate_b9d2e09e",
                                VL_API_IP_TABLE_ALLOCATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_table_allocate_reply_1728303a",
                                VL_API_IP_TABLE_ALLOCATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_table_dump_51077d14",
                                VL_API_IP_TABLE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_table_replace_begin_b9d2e09e",
                                VL_API_IP_TABLE_REPLACE_BEGIN + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_table_replace_begin_reply_e8d4e804",
                                VL_API_IP_TABLE_REPLACE_BEGIN_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_table_replace_end_b9d2e09e",
                                VL_API_IP_TABLE_REPLACE_END + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_table_replace_end_reply_e8d4e804",
                                VL_API_IP_TABLE_REPLACE_END_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_table_flush_b9d2e09e",
                                VL_API_IP_TABLE_FLUSH + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_table_flush_reply_e8d4e804",
                                VL_API_IP_TABLE_FLUSH_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_table_details_c79fca0f",
                                VL_API_IP_TABLE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_route_add_del_b8ecfe0d",
                                VL_API_IP_ROUTE_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_route_add_del_v2_521ef330",
                                VL_API_IP_ROUTE_ADD_DEL_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_route_add_del_reply_1992deab",
                                VL_API_IP_ROUTE_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_route_add_del_v2_reply_1992deab",
                                VL_API_IP_ROUTE_ADD_DEL_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_route_dump_b9d2e09e",
                                VL_API_IP_ROUTE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_route_v2_dump_d16f72e6",
                                VL_API_IP_ROUTE_V2_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_route_details_bda8f315",
                                VL_API_IP_ROUTE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_route_v2_details_b09aa6c0",
                                VL_API_IP_ROUTE_V2_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_route_lookup_710d6471",
                                VL_API_IP_ROUTE_LOOKUP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_route_lookup_v2_710d6471",
                                VL_API_IP_ROUTE_LOOKUP_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_route_lookup_reply_5d8febcb",
                                VL_API_IP_ROUTE_LOOKUP_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_route_lookup_v2_reply_84cc9e03",
                                VL_API_IP_ROUTE_LOOKUP_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "set_ip_flow_hash_084ee09e",
                                VL_API_SET_IP_FLOW_HASH + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "set_ip_flow_hash_reply_e8d4e804",
                                VL_API_SET_IP_FLOW_HASH_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "set_ip_flow_hash_v2_6d132100",
                                VL_API_SET_IP_FLOW_HASH_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "set_ip_flow_hash_v2_reply_e8d4e804",
                                VL_API_SET_IP_FLOW_HASH_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "set_ip_flow_hash_v3_b7876e07",
                                VL_API_SET_IP_FLOW_HASH_V3 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "set_ip_flow_hash_v3_reply_e8d4e804",
                                VL_API_SET_IP_FLOW_HASH_V3_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "set_ip_flow_hash_router_id_03e4f48e",
                                VL_API_SET_IP_FLOW_HASH_ROUTER_ID + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "set_ip_flow_hash_router_id_reply_e8d4e804",
                                VL_API_SET_IP_FLOW_HASH_ROUTER_ID_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_ip6_enable_disable_ae6cfcfb",
                                VL_API_SW_INTERFACE_IP6_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_ip6_enable_disable_reply_e8d4e804",
                                VL_API_SW_INTERFACE_IP6_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_ip4_enable_disable_ae6cfcfb",
                                VL_API_SW_INTERFACE_IP4_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_ip4_enable_disable_reply_e8d4e804",
                                VL_API_SW_INTERFACE_IP4_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_mtable_dump_51077d14",
                                VL_API_IP_MTABLE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_mtable_details_b9d2e09e",
                                VL_API_IP_MTABLE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_mroute_add_del_0dd7e790",
                                VL_API_IP_MROUTE_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_mroute_add_del_reply_1992deab",
                                VL_API_IP_MROUTE_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_mroute_dump_b9d2e09e",
                                VL_API_IP_MROUTE_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_mroute_details_c5cb23fc",
                                VL_API_IP_MROUTE_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_address_details_ee29b797",
                                VL_API_IP_ADDRESS_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_address_dump_2d033de4",
                                VL_API_IP_ADDRESS_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_unnumbered_details_cc59bd42",
                                VL_API_IP_UNNUMBERED_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_unnumbered_dump_f9e6675e",
                                VL_API_IP_UNNUMBERED_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_details_eb152d07",
                                VL_API_IP_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_dump_98d231ca",
                                VL_API_IP_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mfib_signal_dump_51077d14",
                                VL_API_MFIB_SIGNAL_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "mfib_signal_details_6f4a4cfb",
                                VL_API_MFIB_SIGNAL_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_punt_police_db867cea",
                                VL_API_IP_PUNT_POLICE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_punt_police_reply_e8d4e804",
                                VL_API_IP_PUNT_POLICE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_punt_redirect_6580f635",
                                VL_API_IP_PUNT_REDIRECT + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_punt_redirect_reply_e8d4e804",
                                VL_API_IP_PUNT_REDIRECT_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_punt_redirect_dump_2d033de4",
                                VL_API_IP_PUNT_REDIRECT_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_punt_redirect_details_2cef63e7",
                                VL_API_IP_PUNT_REDIRECT_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "add_del_ip_punt_redirect_v2_9e804227",
                                VL_API_ADD_DEL_IP_PUNT_REDIRECT_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "add_del_ip_punt_redirect_v2_reply_e8d4e804",
                                VL_API_ADD_DEL_IP_PUNT_REDIRECT_V2_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_punt_redirect_v2_dump_d817a484",
                                VL_API_IP_PUNT_REDIRECT_V2_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_punt_redirect_v2_details_7ba42e1d",
                                VL_API_IP_PUNT_REDIRECT_V2_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_container_proxy_add_del_7df1dff1",
                                VL_API_IP_CONTAINER_PROXY_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_container_proxy_add_del_reply_e8d4e804",
                                VL_API_IP_CONTAINER_PROXY_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_container_proxy_dump_51077d14",
                                VL_API_IP_CONTAINER_PROXY_DUMP + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_container_proxy_details_a8085523",
                                VL_API_IP_CONTAINER_PROXY_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_source_and_port_range_check_add_del_92a067e3",
                                VL_API_IP_SOURCE_AND_PORT_RANGE_CHECK_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_source_and_port_range_check_add_del_reply_e8d4e804",
                                VL_API_IP_SOURCE_AND_PORT_RANGE_CHECK_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_source_and_port_range_check_interface_add_del_e1ba8987",
                                VL_API_IP_SOURCE_AND_PORT_RANGE_CHECK_INTERFACE_ADD_DEL + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_source_and_port_range_check_interface_add_del_reply_e8d4e804",
                                VL_API_IP_SOURCE_AND_PORT_RANGE_CHECK_INTERFACE_ADD_DEL_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_ip6_set_link_local_address_1c10f15f",
                                VL_API_SW_INTERFACE_IP6_SET_LINK_LOCAL_ADDRESS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_ip6_set_link_local_address_reply_e8d4e804",
                                VL_API_SW_INTERFACE_IP6_SET_LINK_LOCAL_ADDRESS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_ip6_get_link_local_address_f9e6675e",
                                VL_API_SW_INTERFACE_IP6_GET_LINK_LOCAL_ADDRESS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "sw_interface_ip6_get_link_local_address_reply_d16b7130",
                                VL_API_SW_INTERFACE_IP6_GET_LINK_LOCAL_ADDRESS_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ioam_enable_51ccd868",
                                VL_API_IOAM_ENABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ioam_enable_reply_e8d4e804",
                                VL_API_IOAM_ENABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ioam_disable_6b16a45e",
                                VL_API_IOAM_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ioam_disable_reply_e8d4e804",
                                VL_API_IOAM_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_reassembly_set_16467d25",
                                VL_API_IP_REASSEMBLY_SET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_reassembly_set_reply_e8d4e804",
                                VL_API_IP_REASSEMBLY_SET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_reassembly_get_ea13ff63",
                                VL_API_IP_REASSEMBLY_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_reassembly_get_reply_d5eb8d34",
                                VL_API_IP_REASSEMBLY_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_reassembly_enable_disable_eb77968d",
                                VL_API_IP_REASSEMBLY_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_reassembly_enable_disable_reply_e8d4e804",
                                VL_API_IP_REASSEMBLY_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_local_reass_enable_disable_34e2ccc4",
                                VL_API_IP_LOCAL_REASS_ENABLE_DISABLE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_local_reass_enable_disable_reply_e8d4e804",
                                VL_API_IP_LOCAL_REASS_ENABLE_DISABLE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_local_reass_get_51077d14",
                                VL_API_IP_LOCAL_REASS_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_local_reass_get_reply_3e93a702",
                                VL_API_IP_LOCAL_REASS_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_path_mtu_update_10bbe5cb",
                                VL_API_IP_PATH_MTU_UPDATE + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_path_mtu_update_reply_e8d4e804",
                                VL_API_IP_PATH_MTU_UPDATE_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_path_mtu_get_f75ba505",
                                VL_API_IP_PATH_MTU_GET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_path_mtu_get_reply_53b48f5d",
                                VL_API_IP_PATH_MTU_GET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_path_mtu_details_ac9539a7",
                                VL_API_IP_PATH_MTU_DETAILS + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_path_mtu_replace_begin_51077d14",
                                VL_API_IP_PATH_MTU_REPLACE_BEGIN + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_path_mtu_replace_begin_reply_e8d4e804",
                                VL_API_IP_PATH_MTU_REPLACE_BEGIN_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_path_mtu_replace_end_51077d14",
                                VL_API_IP_PATH_MTU_REPLACE_END + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "ip_path_mtu_replace_end_reply_e8d4e804",
                                VL_API_IP_PATH_MTU_REPLACE_END_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_PATH_MTU_GET + msg_id_base,
   .name = "ip_path_mtu_get",
   .handler = vl_api_ip_path_mtu_get_t_handler,
   .endian = vl_api_ip_path_mtu_get_t_endian,
   .format_fn = vl_api_ip_path_mtu_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_path_mtu_get_t_tojson,
   .fromjson = vl_api_ip_path_mtu_get_t_fromjson,
   .calc_size = vl_api_ip_path_mtu_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_PATH_MTU_GET_REPLY + msg_id_base,
  .name = "ip_path_mtu_get_reply",
  .handler = 0,
  .endian = vl_api_ip_path_mtu_get_reply_t_endian,
  .format_fn = vl_api_ip_path_mtu_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_path_mtu_get_reply_t_tojson,
  .fromjson = vl_api_ip_path_mtu_get_reply_t_fromjson,
  .calc_size = vl_api_ip_path_mtu_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_PATH_MTU_DETAILS + msg_id_base,
  .name = "ip_path_mtu_details",
  .handler = 0,
  .endian = vl_api_ip_path_mtu_details_t_endian,
  .format_fn = vl_api_ip_path_mtu_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_path_mtu_details_t_tojson,
  .fromjson = vl_api_ip_path_mtu_details_t_fromjson,
  .calc_size = vl_api_ip_path_mtu_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_TABLE_ADD_DEL + msg_id_base,
   .name = "ip_table_add_del",
   .handler = vl_api_ip_table_add_del_t_handler,
   .endian = vl_api_ip_table_add_del_t_endian,
   .format_fn = vl_api_ip_table_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_table_add_del_t_tojson,
   .fromjson = vl_api_ip_table_add_del_t_fromjson,
   .calc_size = vl_api_ip_table_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_TABLE_ADD_DEL_REPLY + msg_id_base,
  .name = "ip_table_add_del_reply",
  .handler = 0,
  .endian = vl_api_ip_table_add_del_reply_t_endian,
  .format_fn = vl_api_ip_table_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_table_add_del_reply_t_tojson,
  .fromjson = vl_api_ip_table_add_del_reply_t_fromjson,
  .calc_size = vl_api_ip_table_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_TABLE_ADD_DEL_V2 + msg_id_base,
   .name = "ip_table_add_del_v2",
   .handler = vl_api_ip_table_add_del_v2_t_handler,
   .endian = vl_api_ip_table_add_del_v2_t_endian,
   .format_fn = vl_api_ip_table_add_del_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_table_add_del_v2_t_tojson,
   .fromjson = vl_api_ip_table_add_del_v2_t_fromjson,
   .calc_size = vl_api_ip_table_add_del_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_TABLE_ADD_DEL_V2_REPLY + msg_id_base,
  .name = "ip_table_add_del_v2_reply",
  .handler = 0,
  .endian = vl_api_ip_table_add_del_v2_reply_t_endian,
  .format_fn = vl_api_ip_table_add_del_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_table_add_del_v2_reply_t_tojson,
  .fromjson = vl_api_ip_table_add_del_v2_reply_t_fromjson,
  .calc_size = vl_api_ip_table_add_del_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_TABLE_ALLOCATE + msg_id_base,
   .name = "ip_table_allocate",
   .handler = vl_api_ip_table_allocate_t_handler,
   .endian = vl_api_ip_table_allocate_t_endian,
   .format_fn = vl_api_ip_table_allocate_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_table_allocate_t_tojson,
   .fromjson = vl_api_ip_table_allocate_t_fromjson,
   .calc_size = vl_api_ip_table_allocate_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_TABLE_ALLOCATE_REPLY + msg_id_base,
  .name = "ip_table_allocate_reply",
  .handler = 0,
  .endian = vl_api_ip_table_allocate_reply_t_endian,
  .format_fn = vl_api_ip_table_allocate_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_table_allocate_reply_t_tojson,
  .fromjson = vl_api_ip_table_allocate_reply_t_fromjson,
  .calc_size = vl_api_ip_table_allocate_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_TABLE_DUMP + msg_id_base,
   .name = "ip_table_dump",
   .handler = vl_api_ip_table_dump_t_handler,
   .endian = vl_api_ip_table_dump_t_endian,
   .format_fn = vl_api_ip_table_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_table_dump_t_tojson,
   .fromjson = vl_api_ip_table_dump_t_fromjson,
   .calc_size = vl_api_ip_table_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_TABLE_DETAILS + msg_id_base,
  .name = "ip_table_details",
  .handler = 0,
  .endian = vl_api_ip_table_details_t_endian,
  .format_fn = vl_api_ip_table_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_table_details_t_tojson,
  .fromjson = vl_api_ip_table_details_t_fromjson,
  .calc_size = vl_api_ip_table_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_TABLE_REPLACE_BEGIN + msg_id_base,
   .name = "ip_table_replace_begin",
   .handler = vl_api_ip_table_replace_begin_t_handler,
   .endian = vl_api_ip_table_replace_begin_t_endian,
   .format_fn = vl_api_ip_table_replace_begin_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_table_replace_begin_t_tojson,
   .fromjson = vl_api_ip_table_replace_begin_t_fromjson,
   .calc_size = vl_api_ip_table_replace_begin_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_TABLE_REPLACE_BEGIN_REPLY + msg_id_base,
  .name = "ip_table_replace_begin_reply",
  .handler = 0,
  .endian = vl_api_ip_table_replace_begin_reply_t_endian,
  .format_fn = vl_api_ip_table_replace_begin_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_table_replace_begin_reply_t_tojson,
  .fromjson = vl_api_ip_table_replace_begin_reply_t_fromjson,
  .calc_size = vl_api_ip_table_replace_begin_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_TABLE_REPLACE_END + msg_id_base,
   .name = "ip_table_replace_end",
   .handler = vl_api_ip_table_replace_end_t_handler,
   .endian = vl_api_ip_table_replace_end_t_endian,
   .format_fn = vl_api_ip_table_replace_end_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_table_replace_end_t_tojson,
   .fromjson = vl_api_ip_table_replace_end_t_fromjson,
   .calc_size = vl_api_ip_table_replace_end_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_TABLE_REPLACE_END_REPLY + msg_id_base,
  .name = "ip_table_replace_end_reply",
  .handler = 0,
  .endian = vl_api_ip_table_replace_end_reply_t_endian,
  .format_fn = vl_api_ip_table_replace_end_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_table_replace_end_reply_t_tojson,
  .fromjson = vl_api_ip_table_replace_end_reply_t_fromjson,
  .calc_size = vl_api_ip_table_replace_end_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_TABLE_FLUSH + msg_id_base,
   .name = "ip_table_flush",
   .handler = vl_api_ip_table_flush_t_handler,
   .endian = vl_api_ip_table_flush_t_endian,
   .format_fn = vl_api_ip_table_flush_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_table_flush_t_tojson,
   .fromjson = vl_api_ip_table_flush_t_fromjson,
   .calc_size = vl_api_ip_table_flush_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_TABLE_FLUSH_REPLY + msg_id_base,
  .name = "ip_table_flush_reply",
  .handler = 0,
  .endian = vl_api_ip_table_flush_reply_t_endian,
  .format_fn = vl_api_ip_table_flush_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_table_flush_reply_t_tojson,
  .fromjson = vl_api_ip_table_flush_reply_t_fromjson,
  .calc_size = vl_api_ip_table_flush_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_ROUTE_ADD_DEL + msg_id_base,
   .name = "ip_route_add_del",
   .handler = vl_api_ip_route_add_del_t_handler,
   .endian = vl_api_ip_route_add_del_t_endian,
   .format_fn = vl_api_ip_route_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_route_add_del_t_tojson,
   .fromjson = vl_api_ip_route_add_del_t_fromjson,
   .calc_size = vl_api_ip_route_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_ROUTE_ADD_DEL_REPLY + msg_id_base,
  .name = "ip_route_add_del_reply",
  .handler = 0,
  .endian = vl_api_ip_route_add_del_reply_t_endian,
  .format_fn = vl_api_ip_route_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_route_add_del_reply_t_tojson,
  .fromjson = vl_api_ip_route_add_del_reply_t_fromjson,
  .calc_size = vl_api_ip_route_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_ROUTE_ADD_DEL_V2 + msg_id_base,
   .name = "ip_route_add_del_v2",
   .handler = vl_api_ip_route_add_del_v2_t_handler,
   .endian = vl_api_ip_route_add_del_v2_t_endian,
   .format_fn = vl_api_ip_route_add_del_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_route_add_del_v2_t_tojson,
   .fromjson = vl_api_ip_route_add_del_v2_t_fromjson,
   .calc_size = vl_api_ip_route_add_del_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_ROUTE_ADD_DEL_V2_REPLY + msg_id_base,
  .name = "ip_route_add_del_v2_reply",
  .handler = 0,
  .endian = vl_api_ip_route_add_del_v2_reply_t_endian,
  .format_fn = vl_api_ip_route_add_del_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_route_add_del_v2_reply_t_tojson,
  .fromjson = vl_api_ip_route_add_del_v2_reply_t_fromjson,
  .calc_size = vl_api_ip_route_add_del_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_ROUTE_DUMP + msg_id_base,
   .name = "ip_route_dump",
   .handler = vl_api_ip_route_dump_t_handler,
   .endian = vl_api_ip_route_dump_t_endian,
   .format_fn = vl_api_ip_route_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_route_dump_t_tojson,
   .fromjson = vl_api_ip_route_dump_t_fromjson,
   .calc_size = vl_api_ip_route_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_ROUTE_DETAILS + msg_id_base,
  .name = "ip_route_details",
  .handler = 0,
  .endian = vl_api_ip_route_details_t_endian,
  .format_fn = vl_api_ip_route_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_route_details_t_tojson,
  .fromjson = vl_api_ip_route_details_t_fromjson,
  .calc_size = vl_api_ip_route_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_ROUTE_V2_DUMP + msg_id_base,
   .name = "ip_route_v2_dump",
   .handler = vl_api_ip_route_v2_dump_t_handler,
   .endian = vl_api_ip_route_v2_dump_t_endian,
   .format_fn = vl_api_ip_route_v2_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_route_v2_dump_t_tojson,
   .fromjson = vl_api_ip_route_v2_dump_t_fromjson,
   .calc_size = vl_api_ip_route_v2_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_ROUTE_V2_DETAILS + msg_id_base,
  .name = "ip_route_v2_details",
  .handler = 0,
  .endian = vl_api_ip_route_v2_details_t_endian,
  .format_fn = vl_api_ip_route_v2_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_route_v2_details_t_tojson,
  .fromjson = vl_api_ip_route_v2_details_t_fromjson,
  .calc_size = vl_api_ip_route_v2_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_ROUTE_LOOKUP + msg_id_base,
   .name = "ip_route_lookup",
   .handler = vl_api_ip_route_lookup_t_handler,
   .endian = vl_api_ip_route_lookup_t_endian,
   .format_fn = vl_api_ip_route_lookup_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_route_lookup_t_tojson,
   .fromjson = vl_api_ip_route_lookup_t_fromjson,
   .calc_size = vl_api_ip_route_lookup_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_ROUTE_LOOKUP_REPLY + msg_id_base,
  .name = "ip_route_lookup_reply",
  .handler = 0,
  .endian = vl_api_ip_route_lookup_reply_t_endian,
  .format_fn = vl_api_ip_route_lookup_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_route_lookup_reply_t_tojson,
  .fromjson = vl_api_ip_route_lookup_reply_t_fromjson,
  .calc_size = vl_api_ip_route_lookup_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_ROUTE_LOOKUP_V2 + msg_id_base,
   .name = "ip_route_lookup_v2",
   .handler = vl_api_ip_route_lookup_v2_t_handler,
   .endian = vl_api_ip_route_lookup_v2_t_endian,
   .format_fn = vl_api_ip_route_lookup_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_route_lookup_v2_t_tojson,
   .fromjson = vl_api_ip_route_lookup_v2_t_fromjson,
   .calc_size = vl_api_ip_route_lookup_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_ROUTE_LOOKUP_V2_REPLY + msg_id_base,
  .name = "ip_route_lookup_v2_reply",
  .handler = 0,
  .endian = vl_api_ip_route_lookup_v2_reply_t_endian,
  .format_fn = vl_api_ip_route_lookup_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_route_lookup_v2_reply_t_tojson,
  .fromjson = vl_api_ip_route_lookup_v2_reply_t_fromjson,
  .calc_size = vl_api_ip_route_lookup_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SET_IP_FLOW_HASH + msg_id_base,
   .name = "set_ip_flow_hash",
   .handler = vl_api_set_ip_flow_hash_t_handler,
   .endian = vl_api_set_ip_flow_hash_t_endian,
   .format_fn = vl_api_set_ip_flow_hash_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_set_ip_flow_hash_t_tojson,
   .fromjson = vl_api_set_ip_flow_hash_t_fromjson,
   .calc_size = vl_api_set_ip_flow_hash_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SET_IP_FLOW_HASH_REPLY + msg_id_base,
  .name = "set_ip_flow_hash_reply",
  .handler = 0,
  .endian = vl_api_set_ip_flow_hash_reply_t_endian,
  .format_fn = vl_api_set_ip_flow_hash_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_set_ip_flow_hash_reply_t_tojson,
  .fromjson = vl_api_set_ip_flow_hash_reply_t_fromjson,
  .calc_size = vl_api_set_ip_flow_hash_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SET_IP_FLOW_HASH_V2 + msg_id_base,
   .name = "set_ip_flow_hash_v2",
   .handler = vl_api_set_ip_flow_hash_v2_t_handler,
   .endian = vl_api_set_ip_flow_hash_v2_t_endian,
   .format_fn = vl_api_set_ip_flow_hash_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_set_ip_flow_hash_v2_t_tojson,
   .fromjson = vl_api_set_ip_flow_hash_v2_t_fromjson,
   .calc_size = vl_api_set_ip_flow_hash_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SET_IP_FLOW_HASH_V2_REPLY + msg_id_base,
  .name = "set_ip_flow_hash_v2_reply",
  .handler = 0,
  .endian = vl_api_set_ip_flow_hash_v2_reply_t_endian,
  .format_fn = vl_api_set_ip_flow_hash_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_set_ip_flow_hash_v2_reply_t_tojson,
  .fromjson = vl_api_set_ip_flow_hash_v2_reply_t_fromjson,
  .calc_size = vl_api_set_ip_flow_hash_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SET_IP_FLOW_HASH_V3 + msg_id_base,
   .name = "set_ip_flow_hash_v3",
   .handler = vl_api_set_ip_flow_hash_v3_t_handler,
   .endian = vl_api_set_ip_flow_hash_v3_t_endian,
   .format_fn = vl_api_set_ip_flow_hash_v3_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_set_ip_flow_hash_v3_t_tojson,
   .fromjson = vl_api_set_ip_flow_hash_v3_t_fromjson,
   .calc_size = vl_api_set_ip_flow_hash_v3_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SET_IP_FLOW_HASH_V3_REPLY + msg_id_base,
  .name = "set_ip_flow_hash_v3_reply",
  .handler = 0,
  .endian = vl_api_set_ip_flow_hash_v3_reply_t_endian,
  .format_fn = vl_api_set_ip_flow_hash_v3_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_set_ip_flow_hash_v3_reply_t_tojson,
  .fromjson = vl_api_set_ip_flow_hash_v3_reply_t_fromjson,
  .calc_size = vl_api_set_ip_flow_hash_v3_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SET_IP_FLOW_HASH_ROUTER_ID + msg_id_base,
   .name = "set_ip_flow_hash_router_id",
   .handler = vl_api_set_ip_flow_hash_router_id_t_handler,
   .endian = vl_api_set_ip_flow_hash_router_id_t_endian,
   .format_fn = vl_api_set_ip_flow_hash_router_id_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_set_ip_flow_hash_router_id_t_tojson,
   .fromjson = vl_api_set_ip_flow_hash_router_id_t_fromjson,
   .calc_size = vl_api_set_ip_flow_hash_router_id_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SET_IP_FLOW_HASH_ROUTER_ID_REPLY + msg_id_base,
  .name = "set_ip_flow_hash_router_id_reply",
  .handler = 0,
  .endian = vl_api_set_ip_flow_hash_router_id_reply_t_endian,
  .format_fn = vl_api_set_ip_flow_hash_router_id_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_set_ip_flow_hash_router_id_reply_t_tojson,
  .fromjson = vl_api_set_ip_flow_hash_router_id_reply_t_fromjson,
  .calc_size = vl_api_set_ip_flow_hash_router_id_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_IP6_ENABLE_DISABLE + msg_id_base,
   .name = "sw_interface_ip6_enable_disable",
   .handler = vl_api_sw_interface_ip6_enable_disable_t_handler,
   .endian = vl_api_sw_interface_ip6_enable_disable_t_endian,
   .format_fn = vl_api_sw_interface_ip6_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_ip6_enable_disable_t_tojson,
   .fromjson = vl_api_sw_interface_ip6_enable_disable_t_fromjson,
   .calc_size = vl_api_sw_interface_ip6_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_IP6_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "sw_interface_ip6_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_ip6_enable_disable_reply_t_endian,
  .format_fn = vl_api_sw_interface_ip6_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_ip6_enable_disable_reply_t_tojson,
  .fromjson = vl_api_sw_interface_ip6_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_ip6_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_IP4_ENABLE_DISABLE + msg_id_base,
   .name = "sw_interface_ip4_enable_disable",
   .handler = vl_api_sw_interface_ip4_enable_disable_t_handler,
   .endian = vl_api_sw_interface_ip4_enable_disable_t_endian,
   .format_fn = vl_api_sw_interface_ip4_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_ip4_enable_disable_t_tojson,
   .fromjson = vl_api_sw_interface_ip4_enable_disable_t_fromjson,
   .calc_size = vl_api_sw_interface_ip4_enable_disable_t_calc_size,
   .is_autoendian = 1};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_IP4_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "sw_interface_ip4_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_ip4_enable_disable_reply_t_endian,
  .format_fn = vl_api_sw_interface_ip4_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_ip4_enable_disable_reply_t_tojson,
  .fromjson = vl_api_sw_interface_ip4_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_ip4_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_MTABLE_DUMP + msg_id_base,
   .name = "ip_mtable_dump",
   .handler = vl_api_ip_mtable_dump_t_handler,
   .endian = vl_api_ip_mtable_dump_t_endian,
   .format_fn = vl_api_ip_mtable_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_mtable_dump_t_tojson,
   .fromjson = vl_api_ip_mtable_dump_t_fromjson,
   .calc_size = vl_api_ip_mtable_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_MTABLE_DETAILS + msg_id_base,
  .name = "ip_mtable_details",
  .handler = 0,
  .endian = vl_api_ip_mtable_details_t_endian,
  .format_fn = vl_api_ip_mtable_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_mtable_details_t_tojson,
  .fromjson = vl_api_ip_mtable_details_t_fromjson,
  .calc_size = vl_api_ip_mtable_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_MROUTE_ADD_DEL + msg_id_base,
   .name = "ip_mroute_add_del",
   .handler = vl_api_ip_mroute_add_del_t_handler,
   .endian = vl_api_ip_mroute_add_del_t_endian,
   .format_fn = vl_api_ip_mroute_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_mroute_add_del_t_tojson,
   .fromjson = vl_api_ip_mroute_add_del_t_fromjson,
   .calc_size = vl_api_ip_mroute_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_MROUTE_ADD_DEL_REPLY + msg_id_base,
  .name = "ip_mroute_add_del_reply",
  .handler = 0,
  .endian = vl_api_ip_mroute_add_del_reply_t_endian,
  .format_fn = vl_api_ip_mroute_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_mroute_add_del_reply_t_tojson,
  .fromjson = vl_api_ip_mroute_add_del_reply_t_fromjson,
  .calc_size = vl_api_ip_mroute_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_MROUTE_DUMP + msg_id_base,
   .name = "ip_mroute_dump",
   .handler = vl_api_ip_mroute_dump_t_handler,
   .endian = vl_api_ip_mroute_dump_t_endian,
   .format_fn = vl_api_ip_mroute_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_mroute_dump_t_tojson,
   .fromjson = vl_api_ip_mroute_dump_t_fromjson,
   .calc_size = vl_api_ip_mroute_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_MROUTE_DETAILS + msg_id_base,
  .name = "ip_mroute_details",
  .handler = 0,
  .endian = vl_api_ip_mroute_details_t_endian,
  .format_fn = vl_api_ip_mroute_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_mroute_details_t_tojson,
  .fromjson = vl_api_ip_mroute_details_t_fromjson,
  .calc_size = vl_api_ip_mroute_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_ADDRESS_DUMP + msg_id_base,
   .name = "ip_address_dump",
   .handler = vl_api_ip_address_dump_t_handler,
   .endian = vl_api_ip_address_dump_t_endian,
   .format_fn = vl_api_ip_address_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_address_dump_t_tojson,
   .fromjson = vl_api_ip_address_dump_t_fromjson,
   .calc_size = vl_api_ip_address_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_ADDRESS_DETAILS + msg_id_base,
  .name = "ip_address_details",
  .handler = 0,
  .endian = vl_api_ip_address_details_t_endian,
  .format_fn = vl_api_ip_address_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_address_details_t_tojson,
  .fromjson = vl_api_ip_address_details_t_fromjson,
  .calc_size = vl_api_ip_address_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_UNNUMBERED_DUMP + msg_id_base,
   .name = "ip_unnumbered_dump",
   .handler = vl_api_ip_unnumbered_dump_t_handler,
   .endian = vl_api_ip_unnumbered_dump_t_endian,
   .format_fn = vl_api_ip_unnumbered_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_unnumbered_dump_t_tojson,
   .fromjson = vl_api_ip_unnumbered_dump_t_fromjson,
   .calc_size = vl_api_ip_unnumbered_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_UNNUMBERED_DETAILS + msg_id_base,
  .name = "ip_unnumbered_details",
  .handler = 0,
  .endian = vl_api_ip_unnumbered_details_t_endian,
  .format_fn = vl_api_ip_unnumbered_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_unnumbered_details_t_tojson,
  .fromjson = vl_api_ip_unnumbered_details_t_fromjson,
  .calc_size = vl_api_ip_unnumbered_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_DUMP + msg_id_base,
   .name = "ip_dump",
   .handler = vl_api_ip_dump_t_handler,
   .endian = vl_api_ip_dump_t_endian,
   .format_fn = vl_api_ip_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_dump_t_tojson,
   .fromjson = vl_api_ip_dump_t_fromjson,
   .calc_size = vl_api_ip_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_DETAILS + msg_id_base,
  .name = "ip_details",
  .handler = 0,
  .endian = vl_api_ip_details_t_endian,
  .format_fn = vl_api_ip_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_details_t_tojson,
  .fromjson = vl_api_ip_details_t_fromjson,
  .calc_size = vl_api_ip_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_MFIB_SIGNAL_DUMP + msg_id_base,
   .name = "mfib_signal_dump",
   .handler = vl_api_mfib_signal_dump_t_handler,
   .endian = vl_api_mfib_signal_dump_t_endian,
   .format_fn = vl_api_mfib_signal_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_mfib_signal_dump_t_tojson,
   .fromjson = vl_api_mfib_signal_dump_t_fromjson,
   .calc_size = vl_api_mfib_signal_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_MFIB_SIGNAL_DETAILS + msg_id_base,
  .name = "mfib_signal_details",
  .handler = 0,
  .endian = vl_api_mfib_signal_details_t_endian,
  .format_fn = vl_api_mfib_signal_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_mfib_signal_details_t_tojson,
  .fromjson = vl_api_mfib_signal_details_t_fromjson,
  .calc_size = vl_api_mfib_signal_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_PUNT_POLICE + msg_id_base,
   .name = "ip_punt_police",
   .handler = vl_api_ip_punt_police_t_handler,
   .endian = vl_api_ip_punt_police_t_endian,
   .format_fn = vl_api_ip_punt_police_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_punt_police_t_tojson,
   .fromjson = vl_api_ip_punt_police_t_fromjson,
   .calc_size = vl_api_ip_punt_police_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_PUNT_POLICE_REPLY + msg_id_base,
  .name = "ip_punt_police_reply",
  .handler = 0,
  .endian = vl_api_ip_punt_police_reply_t_endian,
  .format_fn = vl_api_ip_punt_police_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_punt_police_reply_t_tojson,
  .fromjson = vl_api_ip_punt_police_reply_t_fromjson,
  .calc_size = vl_api_ip_punt_police_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_PUNT_REDIRECT + msg_id_base,
   .name = "ip_punt_redirect",
   .handler = vl_api_ip_punt_redirect_t_handler,
   .endian = vl_api_ip_punt_redirect_t_endian,
   .format_fn = vl_api_ip_punt_redirect_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_punt_redirect_t_tojson,
   .fromjson = vl_api_ip_punt_redirect_t_fromjson,
   .calc_size = vl_api_ip_punt_redirect_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_PUNT_REDIRECT_REPLY + msg_id_base,
  .name = "ip_punt_redirect_reply",
  .handler = 0,
  .endian = vl_api_ip_punt_redirect_reply_t_endian,
  .format_fn = vl_api_ip_punt_redirect_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_punt_redirect_reply_t_tojson,
  .fromjson = vl_api_ip_punt_redirect_reply_t_fromjson,
  .calc_size = vl_api_ip_punt_redirect_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_PUNT_REDIRECT_DUMP + msg_id_base,
   .name = "ip_punt_redirect_dump",
   .handler = vl_api_ip_punt_redirect_dump_t_handler,
   .endian = vl_api_ip_punt_redirect_dump_t_endian,
   .format_fn = vl_api_ip_punt_redirect_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_punt_redirect_dump_t_tojson,
   .fromjson = vl_api_ip_punt_redirect_dump_t_fromjson,
   .calc_size = vl_api_ip_punt_redirect_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_PUNT_REDIRECT_DETAILS + msg_id_base,
  .name = "ip_punt_redirect_details",
  .handler = 0,
  .endian = vl_api_ip_punt_redirect_details_t_endian,
  .format_fn = vl_api_ip_punt_redirect_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_punt_redirect_details_t_tojson,
  .fromjson = vl_api_ip_punt_redirect_details_t_fromjson,
  .calc_size = vl_api_ip_punt_redirect_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_ADD_DEL_IP_PUNT_REDIRECT_V2 + msg_id_base,
   .name = "add_del_ip_punt_redirect_v2",
   .handler = vl_api_add_del_ip_punt_redirect_v2_t_handler,
   .endian = vl_api_add_del_ip_punt_redirect_v2_t_endian,
   .format_fn = vl_api_add_del_ip_punt_redirect_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_add_del_ip_punt_redirect_v2_t_tojson,
   .fromjson = vl_api_add_del_ip_punt_redirect_v2_t_fromjson,
   .calc_size = vl_api_add_del_ip_punt_redirect_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_ADD_DEL_IP_PUNT_REDIRECT_V2_REPLY + msg_id_base,
  .name = "add_del_ip_punt_redirect_v2_reply",
  .handler = 0,
  .endian = vl_api_add_del_ip_punt_redirect_v2_reply_t_endian,
  .format_fn = vl_api_add_del_ip_punt_redirect_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_add_del_ip_punt_redirect_v2_reply_t_tojson,
  .fromjson = vl_api_add_del_ip_punt_redirect_v2_reply_t_fromjson,
  .calc_size = vl_api_add_del_ip_punt_redirect_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_PUNT_REDIRECT_V2_DUMP + msg_id_base,
   .name = "ip_punt_redirect_v2_dump",
   .handler = vl_api_ip_punt_redirect_v2_dump_t_handler,
   .endian = vl_api_ip_punt_redirect_v2_dump_t_endian,
   .format_fn = vl_api_ip_punt_redirect_v2_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_punt_redirect_v2_dump_t_tojson,
   .fromjson = vl_api_ip_punt_redirect_v2_dump_t_fromjson,
   .calc_size = vl_api_ip_punt_redirect_v2_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_PUNT_REDIRECT_V2_DETAILS + msg_id_base,
  .name = "ip_punt_redirect_v2_details",
  .handler = 0,
  .endian = vl_api_ip_punt_redirect_v2_details_t_endian,
  .format_fn = vl_api_ip_punt_redirect_v2_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_punt_redirect_v2_details_t_tojson,
  .fromjson = vl_api_ip_punt_redirect_v2_details_t_fromjson,
  .calc_size = vl_api_ip_punt_redirect_v2_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_CONTAINER_PROXY_ADD_DEL + msg_id_base,
   .name = "ip_container_proxy_add_del",
   .handler = vl_api_ip_container_proxy_add_del_t_handler,
   .endian = vl_api_ip_container_proxy_add_del_t_endian,
   .format_fn = vl_api_ip_container_proxy_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_container_proxy_add_del_t_tojson,
   .fromjson = vl_api_ip_container_proxy_add_del_t_fromjson,
   .calc_size = vl_api_ip_container_proxy_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_CONTAINER_PROXY_ADD_DEL_REPLY + msg_id_base,
  .name = "ip_container_proxy_add_del_reply",
  .handler = 0,
  .endian = vl_api_ip_container_proxy_add_del_reply_t_endian,
  .format_fn = vl_api_ip_container_proxy_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_container_proxy_add_del_reply_t_tojson,
  .fromjson = vl_api_ip_container_proxy_add_del_reply_t_fromjson,
  .calc_size = vl_api_ip_container_proxy_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_CONTAINER_PROXY_DUMP + msg_id_base,
   .name = "ip_container_proxy_dump",
   .handler = vl_api_ip_container_proxy_dump_t_handler,
   .endian = vl_api_ip_container_proxy_dump_t_endian,
   .format_fn = vl_api_ip_container_proxy_dump_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_container_proxy_dump_t_tojson,
   .fromjson = vl_api_ip_container_proxy_dump_t_fromjson,
   .calc_size = vl_api_ip_container_proxy_dump_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_CONTAINER_PROXY_DETAILS + msg_id_base,
  .name = "ip_container_proxy_details",
  .handler = 0,
  .endian = vl_api_ip_container_proxy_details_t_endian,
  .format_fn = vl_api_ip_container_proxy_details_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_container_proxy_details_t_tojson,
  .fromjson = vl_api_ip_container_proxy_details_t_fromjson,
  .calc_size = vl_api_ip_container_proxy_details_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_SOURCE_AND_PORT_RANGE_CHECK_ADD_DEL + msg_id_base,
   .name = "ip_source_and_port_range_check_add_del",
   .handler = vl_api_ip_source_and_port_range_check_add_del_t_handler,
   .endian = vl_api_ip_source_and_port_range_check_add_del_t_endian,
   .format_fn = vl_api_ip_source_and_port_range_check_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_source_and_port_range_check_add_del_t_tojson,
   .fromjson = vl_api_ip_source_and_port_range_check_add_del_t_fromjson,
   .calc_size = vl_api_ip_source_and_port_range_check_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_SOURCE_AND_PORT_RANGE_CHECK_ADD_DEL_REPLY + msg_id_base,
  .name = "ip_source_and_port_range_check_add_del_reply",
  .handler = 0,
  .endian = vl_api_ip_source_and_port_range_check_add_del_reply_t_endian,
  .format_fn = vl_api_ip_source_and_port_range_check_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_source_and_port_range_check_add_del_reply_t_tojson,
  .fromjson = vl_api_ip_source_and_port_range_check_add_del_reply_t_fromjson,
  .calc_size = vl_api_ip_source_and_port_range_check_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_SOURCE_AND_PORT_RANGE_CHECK_INTERFACE_ADD_DEL + msg_id_base,
   .name = "ip_source_and_port_range_check_interface_add_del",
   .handler = vl_api_ip_source_and_port_range_check_interface_add_del_t_handler,
   .endian = vl_api_ip_source_and_port_range_check_interface_add_del_t_endian,
   .format_fn = vl_api_ip_source_and_port_range_check_interface_add_del_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_source_and_port_range_check_interface_add_del_t_tojson,
   .fromjson = vl_api_ip_source_and_port_range_check_interface_add_del_t_fromjson,
   .calc_size = vl_api_ip_source_and_port_range_check_interface_add_del_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_SOURCE_AND_PORT_RANGE_CHECK_INTERFACE_ADD_DEL_REPLY + msg_id_base,
  .name = "ip_source_and_port_range_check_interface_add_del_reply",
  .handler = 0,
  .endian = vl_api_ip_source_and_port_range_check_interface_add_del_reply_t_endian,
  .format_fn = vl_api_ip_source_and_port_range_check_interface_add_del_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_source_and_port_range_check_interface_add_del_reply_t_tojson,
  .fromjson = vl_api_ip_source_and_port_range_check_interface_add_del_reply_t_fromjson,
  .calc_size = vl_api_ip_source_and_port_range_check_interface_add_del_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_IP6_SET_LINK_LOCAL_ADDRESS + msg_id_base,
   .name = "sw_interface_ip6_set_link_local_address",
   .handler = vl_api_sw_interface_ip6_set_link_local_address_t_handler,
   .endian = vl_api_sw_interface_ip6_set_link_local_address_t_endian,
   .format_fn = vl_api_sw_interface_ip6_set_link_local_address_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_ip6_set_link_local_address_t_tojson,
   .fromjson = vl_api_sw_interface_ip6_set_link_local_address_t_fromjson,
   .calc_size = vl_api_sw_interface_ip6_set_link_local_address_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_IP6_SET_LINK_LOCAL_ADDRESS_REPLY + msg_id_base,
  .name = "sw_interface_ip6_set_link_local_address_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_ip6_set_link_local_address_reply_t_endian,
  .format_fn = vl_api_sw_interface_ip6_set_link_local_address_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_ip6_set_link_local_address_reply_t_tojson,
  .fromjson = vl_api_sw_interface_ip6_set_link_local_address_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_ip6_set_link_local_address_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_SW_INTERFACE_IP6_GET_LINK_LOCAL_ADDRESS + msg_id_base,
   .name = "sw_interface_ip6_get_link_local_address",
   .handler = vl_api_sw_interface_ip6_get_link_local_address_t_handler,
   .endian = vl_api_sw_interface_ip6_get_link_local_address_t_endian,
   .format_fn = vl_api_sw_interface_ip6_get_link_local_address_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_sw_interface_ip6_get_link_local_address_t_tojson,
   .fromjson = vl_api_sw_interface_ip6_get_link_local_address_t_fromjson,
   .calc_size = vl_api_sw_interface_ip6_get_link_local_address_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_SW_INTERFACE_IP6_GET_LINK_LOCAL_ADDRESS_REPLY + msg_id_base,
  .name = "sw_interface_ip6_get_link_local_address_reply",
  .handler = 0,
  .endian = vl_api_sw_interface_ip6_get_link_local_address_reply_t_endian,
  .format_fn = vl_api_sw_interface_ip6_get_link_local_address_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_sw_interface_ip6_get_link_local_address_reply_t_tojson,
  .fromjson = vl_api_sw_interface_ip6_get_link_local_address_reply_t_fromjson,
  .calc_size = vl_api_sw_interface_ip6_get_link_local_address_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IOAM_ENABLE + msg_id_base,
   .name = "ioam_enable",
   .handler = vl_api_ioam_enable_t_handler,
   .endian = vl_api_ioam_enable_t_endian,
   .format_fn = vl_api_ioam_enable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ioam_enable_t_tojson,
   .fromjson = vl_api_ioam_enable_t_fromjson,
   .calc_size = vl_api_ioam_enable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IOAM_ENABLE_REPLY + msg_id_base,
  .name = "ioam_enable_reply",
  .handler = 0,
  .endian = vl_api_ioam_enable_reply_t_endian,
  .format_fn = vl_api_ioam_enable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ioam_enable_reply_t_tojson,
  .fromjson = vl_api_ioam_enable_reply_t_fromjson,
  .calc_size = vl_api_ioam_enable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IOAM_DISABLE + msg_id_base,
   .name = "ioam_disable",
   .handler = vl_api_ioam_disable_t_handler,
   .endian = vl_api_ioam_disable_t_endian,
   .format_fn = vl_api_ioam_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ioam_disable_t_tojson,
   .fromjson = vl_api_ioam_disable_t_fromjson,
   .calc_size = vl_api_ioam_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IOAM_DISABLE_REPLY + msg_id_base,
  .name = "ioam_disable_reply",
  .handler = 0,
  .endian = vl_api_ioam_disable_reply_t_endian,
  .format_fn = vl_api_ioam_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ioam_disable_reply_t_tojson,
  .fromjson = vl_api_ioam_disable_reply_t_fromjson,
  .calc_size = vl_api_ioam_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_REASSEMBLY_SET + msg_id_base,
   .name = "ip_reassembly_set",
   .handler = vl_api_ip_reassembly_set_t_handler,
   .endian = vl_api_ip_reassembly_set_t_endian,
   .format_fn = vl_api_ip_reassembly_set_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_reassembly_set_t_tojson,
   .fromjson = vl_api_ip_reassembly_set_t_fromjson,
   .calc_size = vl_api_ip_reassembly_set_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_REASSEMBLY_SET_REPLY + msg_id_base,
  .name = "ip_reassembly_set_reply",
  .handler = 0,
  .endian = vl_api_ip_reassembly_set_reply_t_endian,
  .format_fn = vl_api_ip_reassembly_set_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_reassembly_set_reply_t_tojson,
  .fromjson = vl_api_ip_reassembly_set_reply_t_fromjson,
  .calc_size = vl_api_ip_reassembly_set_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_REASSEMBLY_GET + msg_id_base,
   .name = "ip_reassembly_get",
   .handler = vl_api_ip_reassembly_get_t_handler,
   .endian = vl_api_ip_reassembly_get_t_endian,
   .format_fn = vl_api_ip_reassembly_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_reassembly_get_t_tojson,
   .fromjson = vl_api_ip_reassembly_get_t_fromjson,
   .calc_size = vl_api_ip_reassembly_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_REASSEMBLY_GET_REPLY + msg_id_base,
  .name = "ip_reassembly_get_reply",
  .handler = 0,
  .endian = vl_api_ip_reassembly_get_reply_t_endian,
  .format_fn = vl_api_ip_reassembly_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_reassembly_get_reply_t_tojson,
  .fromjson = vl_api_ip_reassembly_get_reply_t_fromjson,
  .calc_size = vl_api_ip_reassembly_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_REASSEMBLY_ENABLE_DISABLE + msg_id_base,
   .name = "ip_reassembly_enable_disable",
   .handler = vl_api_ip_reassembly_enable_disable_t_handler,
   .endian = vl_api_ip_reassembly_enable_disable_t_endian,
   .format_fn = vl_api_ip_reassembly_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_reassembly_enable_disable_t_tojson,
   .fromjson = vl_api_ip_reassembly_enable_disable_t_fromjson,
   .calc_size = vl_api_ip_reassembly_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_REASSEMBLY_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "ip_reassembly_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_ip_reassembly_enable_disable_reply_t_endian,
  .format_fn = vl_api_ip_reassembly_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_reassembly_enable_disable_reply_t_tojson,
  .fromjson = vl_api_ip_reassembly_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_ip_reassembly_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_LOCAL_REASS_ENABLE_DISABLE + msg_id_base,
   .name = "ip_local_reass_enable_disable",
   .handler = vl_api_ip_local_reass_enable_disable_t_handler,
   .endian = vl_api_ip_local_reass_enable_disable_t_endian,
   .format_fn = vl_api_ip_local_reass_enable_disable_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_local_reass_enable_disable_t_tojson,
   .fromjson = vl_api_ip_local_reass_enable_disable_t_fromjson,
   .calc_size = vl_api_ip_local_reass_enable_disable_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_LOCAL_REASS_ENABLE_DISABLE_REPLY + msg_id_base,
  .name = "ip_local_reass_enable_disable_reply",
  .handler = 0,
  .endian = vl_api_ip_local_reass_enable_disable_reply_t_endian,
  .format_fn = vl_api_ip_local_reass_enable_disable_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_local_reass_enable_disable_reply_t_tojson,
  .fromjson = vl_api_ip_local_reass_enable_disable_reply_t_fromjson,
  .calc_size = vl_api_ip_local_reass_enable_disable_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_LOCAL_REASS_GET + msg_id_base,
   .name = "ip_local_reass_get",
   .handler = vl_api_ip_local_reass_get_t_handler,
   .endian = vl_api_ip_local_reass_get_t_endian,
   .format_fn = vl_api_ip_local_reass_get_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_local_reass_get_t_tojson,
   .fromjson = vl_api_ip_local_reass_get_t_fromjson,
   .calc_size = vl_api_ip_local_reass_get_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_LOCAL_REASS_GET_REPLY + msg_id_base,
  .name = "ip_local_reass_get_reply",
  .handler = 0,
  .endian = vl_api_ip_local_reass_get_reply_t_endian,
  .format_fn = vl_api_ip_local_reass_get_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_local_reass_get_reply_t_tojson,
  .fromjson = vl_api_ip_local_reass_get_reply_t_fromjson,
  .calc_size = vl_api_ip_local_reass_get_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_PATH_MTU_UPDATE + msg_id_base,
   .name = "ip_path_mtu_update",
   .handler = vl_api_ip_path_mtu_update_t_handler,
   .endian = vl_api_ip_path_mtu_update_t_endian,
   .format_fn = vl_api_ip_path_mtu_update_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_path_mtu_update_t_tojson,
   .fromjson = vl_api_ip_path_mtu_update_t_fromjson,
   .calc_size = vl_api_ip_path_mtu_update_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_PATH_MTU_UPDATE_REPLY + msg_id_base,
  .name = "ip_path_mtu_update_reply",
  .handler = 0,
  .endian = vl_api_ip_path_mtu_update_reply_t_endian,
  .format_fn = vl_api_ip_path_mtu_update_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_path_mtu_update_reply_t_tojson,
  .fromjson = vl_api_ip_path_mtu_update_reply_t_fromjson,
  .calc_size = vl_api_ip_path_mtu_update_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_PATH_MTU_REPLACE_BEGIN + msg_id_base,
   .name = "ip_path_mtu_replace_begin",
   .handler = vl_api_ip_path_mtu_replace_begin_t_handler,
   .endian = vl_api_ip_path_mtu_replace_begin_t_endian,
   .format_fn = vl_api_ip_path_mtu_replace_begin_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_path_mtu_replace_begin_t_tojson,
   .fromjson = vl_api_ip_path_mtu_replace_begin_t_fromjson,
   .calc_size = vl_api_ip_path_mtu_replace_begin_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_PATH_MTU_REPLACE_BEGIN_REPLY + msg_id_base,
  .name = "ip_path_mtu_replace_begin_reply",
  .handler = 0,
  .endian = vl_api_ip_path_mtu_replace_begin_reply_t_endian,
  .format_fn = vl_api_ip_path_mtu_replace_begin_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_path_mtu_replace_begin_reply_t_tojson,
  .fromjson = vl_api_ip_path_mtu_replace_begin_reply_t_fromjson,
  .calc_size = vl_api_ip_path_mtu_replace_begin_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_IP_PATH_MTU_REPLACE_END + msg_id_base,
   .name = "ip_path_mtu_replace_end",
   .handler = vl_api_ip_path_mtu_replace_end_t_handler,
   .endian = vl_api_ip_path_mtu_replace_end_t_endian,
   .format_fn = vl_api_ip_path_mtu_replace_end_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_ip_path_mtu_replace_end_t_tojson,
   .fromjson = vl_api_ip_path_mtu_replace_end_t_fromjson,
   .calc_size = vl_api_ip_path_mtu_replace_end_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_IP_PATH_MTU_REPLACE_END_REPLY + msg_id_base,
  .name = "ip_path_mtu_replace_end_reply",
  .handler = 0,
  .endian = vl_api_ip_path_mtu_replace_end_reply_t_endian,
  .format_fn = vl_api_ip_path_mtu_replace_end_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_ip_path_mtu_replace_end_reply_t_tojson,
  .fromjson = vl_api_ip_path_mtu_replace_end_reply_t_fromjson,
  .calc_size = vl_api_ip_path_mtu_replace_end_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
vlib_error_desc_t ip_frag_error_counters[] = {
  {
   .name = "none",
   .desc = "packet fragmented",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "small_packet",
   .desc = "packet smaller than MTU",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "fragment_sent",
   .desc = "number of sent fragments",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "cant_fragment_header",
   .desc = "can't fragment header",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "dont_fragment_set",
   .desc = "can't fragment this packet",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "malformed",
   .desc = "malformed packet",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "memory",
   .desc = "could not allocate buffer",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "unknown",
   .desc = "unknown error",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
};
vlib_error_desc_t ip4_error_counters[] = {
  {
   .name = "none",
   .desc = "valid ip4 packets",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "too_short",
   .desc = "ip4 length < 20 bytes",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "bad_length",
   .desc = "ip4 length > l2 length",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "bad_checksum",
   .desc = "bad ip4 checksum",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "version",
   .desc = "ip4 version != 4",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "options",
   .desc = "ip4 options present",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "fragment_offset_one",
   .desc = "ip4 fragment offset == 1",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "time_expired",
   .desc = "ip4 ttl <= 1",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "hdr_too_short",
   .desc = "ip4 IHL < 5",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "mtu_exceeded",
   .desc = "ip4 MTU exceeded and DF set",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "dst_lookup_miss",
   .desc = "ip4 destination lookup miss",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "src_lookup_miss",
   .desc = "ip4 source lookup miss",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "drop",
   .desc = "ip4 drop",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "punt",
   .desc = "ip4 punt",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "same_interface",
   .desc = "ip4 egress interface same as ingress",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "unknown_protocol",
   .desc = "unknown ip protocol",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "tcp_checksum",
   .desc = "bad tcp checksum",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "udp_checksum",
   .desc = "bad udp checksum",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "udp_length",
   .desc = "inconsistent udp/ip lengths",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "spoofed_local_packets",
   .desc = "ip4 spoofed local-address packet drops",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "inacl_table_miss",
   .desc = "input ACL table-miss drops",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "inacl_session_deny",
   .desc = "input ACL session deny drops",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "outacl_table_miss",
   .desc = "output ACL table-miss drops",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "outacl_session_deny",
   .desc = "output ACL session deny drops",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "rpf_failure",
   .desc = "Multicast RPF check failed",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_duplicate_fragment",
   .desc = "duplicate/overlapping fragments",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_limit_reached",
   .desc = "drops due to concurrent reassemblies limit",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_fragment_chain_too_long",
   .desc = "fragment chain too long (drop)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_no_buf",
   .desc = "out of buffers (drop)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_malformed_packet",
   .desc = "malformed packets",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_internal_error",
   .desc = "drops due to internal reassembly error",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_timeout",
   .desc = "fragments dropped due to reassembly timeout",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_to_custom_app",
   .desc = "send to custom drop app",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_success",
   .desc = "successful reassemblies",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "reass_fragments_reassembled",
   .desc = "fragments reassembled",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "reass_fragments_rcvd",
   .desc = "fragments received",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "reass_unsupp_ip_prot",
   .desc = "unsupported ip protocol",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
};
vlib_error_desc_t ip6_error_counters[] = {
  {
   .name = "none",
   .desc = "valid ip6 packets",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "too_short",
   .desc = "ip6 length < 40 bytes",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "bad_length",
   .desc = "ip6 length > l2 length",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "version",
   .desc = "ip6 version != 6",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "time_expired",
   .desc = "ip6 ttl <= 1",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "mtu_exceeded",
   .desc = "ip6 MTU exceeded",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "dst_lookup_miss",
   .desc = "ip6 destination lookup miss",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "src_lookup_miss",
   .desc = "ip6 source lookup miss",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "drop",
   .desc = "ip6 drop",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "punt",
   .desc = "ip6 punt",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "unknown_protocol",
   .desc = "unknown ip protocol",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "udp_checksum",
   .desc = "bad udp checksum",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "icmp_checksum",
   .desc = "bad icmp checksum",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "udp_length",
   .desc = "inconsistent udp/ip lengths",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "unknown_udp_port",
   .desc = "no listener for udp port",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "spoofed_local_packets",
   .desc = "ip6 spoofed local-address packet drops",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "inacl_table_miss",
   .desc = "input ACL table-miss drops",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "inacl_session_deny",
   .desc = "input ACL session deny drops",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "outacl_table_miss",
   .desc = "output ACL table-miss drops",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "outacl_session_deny",
   .desc = "output ACL session deny drops",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "rpf_failure",
   .desc = "Multicast RPF check failed",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_missing_upper",
   .desc = "missing-upper layer drops",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_duplicate_fragment",
   .desc = "duplicate fragments",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_overlapping_fragment",
   .desc = "overlapping fragments",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_limit_reached",
   .desc = "drops due to concurrent reassemblies limit",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_fragment_chain_too_long",
   .desc = "fragment chain too long (drop)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_no_buf",
   .desc = "out of buffers (drop)",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_timeout",
   .desc = "fragments dropped due to reassembly timeout",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_internal_error",
   .desc = "drops due to internal reassembly error",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_invalid_frag_len",
   .desc = "invalid fragment length",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_to_custom_app",
   .desc = "send to custom drop app",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_no_frag_hdr",
   .desc = "no fragmentation header",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_invalid_frag_size",
   .desc = "drop due to invalid fragment size",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "reass_success",
   .desc = "successful reassemblies",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "reass_fragments_reassembled",
   .desc = "fragments reassembled",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "reass_fragments_rcvd",
   .desc = "fragments received",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "reass_unsupp_ip_proto",
   .desc = "unsupported ip protocol",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
};
vlib_error_desc_t icmp4_error_counters[] = {
  {
   .name = "none",
   .desc = "valid packets",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "unknown_type",
   .desc = "unknown type",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "invalid_code_for_type",
   .desc = "invalid code for type",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "invalid_hop_limit_for_type",
   .desc = "hop_limit != 255",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "length_too_small_for_type",
   .desc = "payload length too small for type",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "options_with_odd_length",
   .desc = "total option length not multiple of 8 bytes",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "option_with_zero_length",
   .desc = "option has zero length",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "echo_replies_sent",
   .desc = "echo replies sent",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "dst_lookup_miss",
   .desc = "icmp6 dst address lookup misses",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "dest_unreach_sent",
   .desc = "destination unreachable response sent",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "ttl_expire_sent",
   .desc = "hop limit exceeded response sent",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "param_problem_sent",
   .desc = "parameter problem response sent",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "drop",
   .desc = "error message dropped",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
};
vlib_error_desc_t icmp6_error_counters[] = {
  {
   .name = "none",
   .desc = "valid packets",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "unknown_type",
   .desc = "unknown type",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "invalid_code_for_type",
   .desc = "invalid code for type",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "invalid_hop_limit_for_type",
   .desc = "hop_limit != 255",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "length_too_small_for_type",
   .desc = "payload length too small for type",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "options_with_odd_length",
   .desc = "total option length not multiple of 8 bytes",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "option_with_zero_length",
   .desc = "option has zero length",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "echo_replies_sent",
   .desc = "echo replies sent",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "neighbor_solicitation_source_not_on_link",
   .desc = "neighbor solicitations from source not on link",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "neighbor_solicitation_source_unknown",
   .desc = "neighbor solicitations for unknown targets",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "neighbor_advertisements_tx",
   .desc = "neighbor advertisements sent",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "neighbor_advertisements_rx",
   .desc = "neighbor advertisements received",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "router_solicitation_source_not_on_link",
   .desc = "router solicitations from source not on link",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "router_solicitation_unsupported_intf",
   .desc = "neighbor discovery unsupported interface",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "router_solicitation_radv_not_config",
   .desc = "neighbor discovery not configured",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "router_advertisement_source_not_link_local",
   .desc = "router advertisement source not link local",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "router_advertisements_tx",
   .desc = "router advertisements sent",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "router_advertisements_rx",
   .desc = "router advertisements received",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "dst_lookup_miss",
   .desc = "icmp6 dst address lookup misses",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "dest_unreach_sent",
   .desc = "destination unreachable response sent",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "packet_too_big_sent",
   .desc = "packet too big response sent",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "ttl_expire_sent",
   .desc = "hop limit exceeded response sent",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "param_problem_sent",
   .desc = "parameter problem response sent",
   .severity = VL_COUNTER_SEVERITY_INFO,
  },
  {
   .name = "drop",
   .desc = "error message dropped",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
  {
   .name = "alloc_failure",
   .desc = "buffer allocation failure",
   .severity = VL_COUNTER_SEVERITY_ERROR,
  },
};
