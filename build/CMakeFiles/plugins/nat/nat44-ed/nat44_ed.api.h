/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: nat44_ed.api
 * Automatically generated: please edit the input file NOT this file!
 */

#include <stdbool.h>
#if defined(vl_msg_id)||defined(vl_union_id) \
    || defined(vl_printfun) ||defined(vl_endianfun) \
    || defined(vl_api_version)||defined(vl_typedefs) \
    || defined(vl_msg_name)||defined(vl_msg_name_crc_list) \
    || defined(vl_api_version_tuple) || defined(vl_calcsizefun)
/* ok, something was selected */
#else
#warning no content included from nat44_ed.api
#endif

#define VL_API_PACKED(x) x __attribute__ ((packed))

/*
 * Note: VL_API_MAX_ARRAY_SIZE is set to an arbitrarily large limit.
 *
 * However, any message with a ~2 billion element array is likely to break the
 * api handling long before this limit causes array element endian issues.
 *
 * Applications should be written to create reasonable api messages.
 */
#define VL_API_MAX_ARRAY_SIZE 0x7fffffff

/* Imported API files */
#ifndef vl_api_version
#include <vnet/ip/ip_types.api.h>
#include <vnet/interface_types.api.h>
#include <nat/lib/nat_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_NAT44_ED_PLUGIN_ENABLE_DISABLE, vl_api_nat44_ed_plugin_enable_disable_t_handler)
vl_msg_id(VL_API_NAT44_ED_PLUGIN_ENABLE_DISABLE_REPLY, vl_api_nat44_ed_plugin_enable_disable_reply_t_handler)
vl_msg_id(VL_API_NAT44_FORWARDING_ENABLE_DISABLE, vl_api_nat44_forwarding_enable_disable_t_handler)
vl_msg_id(VL_API_NAT44_FORWARDING_ENABLE_DISABLE_REPLY, vl_api_nat44_forwarding_enable_disable_reply_t_handler)
vl_msg_id(VL_API_NAT_IPFIX_ENABLE_DISABLE, vl_api_nat_ipfix_enable_disable_t_handler)
vl_msg_id(VL_API_NAT_IPFIX_ENABLE_DISABLE_REPLY, vl_api_nat_ipfix_enable_disable_reply_t_handler)
vl_msg_id(VL_API_NAT_SET_TIMEOUTS, vl_api_nat_set_timeouts_t_handler)
vl_msg_id(VL_API_NAT_SET_TIMEOUTS_REPLY, vl_api_nat_set_timeouts_reply_t_handler)
vl_msg_id(VL_API_NAT44_SET_SESSION_LIMIT, vl_api_nat44_set_session_limit_t_handler)
vl_msg_id(VL_API_NAT44_SET_SESSION_LIMIT_REPLY, vl_api_nat44_set_session_limit_reply_t_handler)
vl_msg_id(VL_API_NAT44_SHOW_RUNNING_CONFIG, vl_api_nat44_show_running_config_t_handler)
vl_msg_id(VL_API_NAT44_SHOW_RUNNING_CONFIG_REPLY, vl_api_nat44_show_running_config_reply_t_handler)
vl_msg_id(VL_API_NAT_SET_WORKERS, vl_api_nat_set_workers_t_handler)
vl_msg_id(VL_API_NAT_SET_WORKERS_REPLY, vl_api_nat_set_workers_reply_t_handler)
vl_msg_id(VL_API_NAT_WORKER_DUMP, vl_api_nat_worker_dump_t_handler)
vl_msg_id(VL_API_NAT_WORKER_DETAILS, vl_api_nat_worker_details_t_handler)
vl_msg_id(VL_API_NAT44_ED_ADD_DEL_VRF_TABLE, vl_api_nat44_ed_add_del_vrf_table_t_handler)
vl_msg_id(VL_API_NAT44_ED_ADD_DEL_VRF_TABLE_REPLY, vl_api_nat44_ed_add_del_vrf_table_reply_t_handler)
vl_msg_id(VL_API_NAT44_ED_ADD_DEL_VRF_ROUTE, vl_api_nat44_ed_add_del_vrf_route_t_handler)
vl_msg_id(VL_API_NAT44_ED_ADD_DEL_VRF_ROUTE_REPLY, vl_api_nat44_ed_add_del_vrf_route_reply_t_handler)
vl_msg_id(VL_API_NAT44_ED_VRF_TABLES_DUMP, vl_api_nat44_ed_vrf_tables_dump_t_handler)
vl_msg_id(VL_API_NAT44_ED_VRF_TABLES_DETAILS, vl_api_nat44_ed_vrf_tables_details_t_handler)
vl_msg_id(VL_API_NAT44_ED_VRF_TABLES_V2_DUMP, vl_api_nat44_ed_vrf_tables_v2_dump_t_handler)
vl_msg_id(VL_API_NAT44_ED_VRF_TABLES_V2_DETAILS, vl_api_nat44_ed_vrf_tables_v2_details_t_handler)
vl_msg_id(VL_API_NAT_SET_MSS_CLAMPING, vl_api_nat_set_mss_clamping_t_handler)
vl_msg_id(VL_API_NAT_SET_MSS_CLAMPING_REPLY, vl_api_nat_set_mss_clamping_reply_t_handler)
vl_msg_id(VL_API_NAT_GET_MSS_CLAMPING, vl_api_nat_get_mss_clamping_t_handler)
vl_msg_id(VL_API_NAT_GET_MSS_CLAMPING_REPLY, vl_api_nat_get_mss_clamping_reply_t_handler)
vl_msg_id(VL_API_NAT44_ED_SET_FQ_OPTIONS, vl_api_nat44_ed_set_fq_options_t_handler)
vl_msg_id(VL_API_NAT44_ED_SET_FQ_OPTIONS_REPLY, vl_api_nat44_ed_set_fq_options_reply_t_handler)
vl_msg_id(VL_API_NAT44_ED_SHOW_FQ_OPTIONS, vl_api_nat44_ed_show_fq_options_t_handler)
vl_msg_id(VL_API_NAT44_ED_SHOW_FQ_OPTIONS_REPLY, vl_api_nat44_ed_show_fq_options_reply_t_handler)
vl_msg_id(VL_API_NAT44_ADD_DEL_INTERFACE_ADDR, vl_api_nat44_add_del_interface_addr_t_handler)
vl_msg_id(VL_API_NAT44_ADD_DEL_INTERFACE_ADDR_REPLY, vl_api_nat44_add_del_interface_addr_reply_t_handler)
vl_msg_id(VL_API_NAT44_INTERFACE_ADDR_DUMP, vl_api_nat44_interface_addr_dump_t_handler)
vl_msg_id(VL_API_NAT44_INTERFACE_ADDR_DETAILS, vl_api_nat44_interface_addr_details_t_handler)
vl_msg_id(VL_API_NAT44_ADD_DEL_ADDRESS_RANGE, vl_api_nat44_add_del_address_range_t_handler)
vl_msg_id(VL_API_NAT44_ADD_DEL_ADDRESS_RANGE_REPLY, vl_api_nat44_add_del_address_range_reply_t_handler)
vl_msg_id(VL_API_NAT44_ADDRESS_DUMP, vl_api_nat44_address_dump_t_handler)
vl_msg_id(VL_API_NAT44_ADDRESS_DETAILS, vl_api_nat44_address_details_t_handler)
vl_msg_id(VL_API_NAT44_INTERFACE_ADD_DEL_FEATURE, vl_api_nat44_interface_add_del_feature_t_handler)
vl_msg_id(VL_API_NAT44_INTERFACE_ADD_DEL_FEATURE_REPLY, vl_api_nat44_interface_add_del_feature_reply_t_handler)
vl_msg_id(VL_API_NAT44_INTERFACE_DUMP, vl_api_nat44_interface_dump_t_handler)
vl_msg_id(VL_API_NAT44_INTERFACE_DETAILS, vl_api_nat44_interface_details_t_handler)
vl_msg_id(VL_API_NAT44_ED_ADD_DEL_OUTPUT_INTERFACE, vl_api_nat44_ed_add_del_output_interface_t_handler)
vl_msg_id(VL_API_NAT44_ED_ADD_DEL_OUTPUT_INTERFACE_REPLY, vl_api_nat44_ed_add_del_output_interface_reply_t_handler)
vl_msg_id(VL_API_NAT44_ED_OUTPUT_INTERFACE_GET, vl_api_nat44_ed_output_interface_get_t_handler)
vl_msg_id(VL_API_NAT44_ED_OUTPUT_INTERFACE_GET_REPLY, vl_api_nat44_ed_output_interface_get_reply_t_handler)
vl_msg_id(VL_API_NAT44_ED_OUTPUT_INTERFACE_DETAILS, vl_api_nat44_ed_output_interface_details_t_handler)
vl_msg_id(VL_API_NAT44_ADD_DEL_STATIC_MAPPING, vl_api_nat44_add_del_static_mapping_t_handler)
vl_msg_id(VL_API_NAT44_ADD_DEL_STATIC_MAPPING_REPLY, vl_api_nat44_add_del_static_mapping_reply_t_handler)
vl_msg_id(VL_API_NAT44_ADD_DEL_STATIC_MAPPING_V2, vl_api_nat44_add_del_static_mapping_v2_t_handler)
vl_msg_id(VL_API_NAT44_ADD_DEL_STATIC_MAPPING_V2_REPLY, vl_api_nat44_add_del_static_mapping_v2_reply_t_handler)
vl_msg_id(VL_API_NAT44_STATIC_MAPPING_DUMP, vl_api_nat44_static_mapping_dump_t_handler)
vl_msg_id(VL_API_NAT44_STATIC_MAPPING_DETAILS, vl_api_nat44_static_mapping_details_t_handler)
vl_msg_id(VL_API_NAT44_ADD_DEL_IDENTITY_MAPPING, vl_api_nat44_add_del_identity_mapping_t_handler)
vl_msg_id(VL_API_NAT44_ADD_DEL_IDENTITY_MAPPING_REPLY, vl_api_nat44_add_del_identity_mapping_reply_t_handler)
vl_msg_id(VL_API_NAT44_IDENTITY_MAPPING_DUMP, vl_api_nat44_identity_mapping_dump_t_handler)
vl_msg_id(VL_API_NAT44_IDENTITY_MAPPING_DETAILS, vl_api_nat44_identity_mapping_details_t_handler)
vl_msg_id(VL_API_NAT44_ADD_DEL_LB_STATIC_MAPPING, vl_api_nat44_add_del_lb_static_mapping_t_handler)
vl_msg_id(VL_API_NAT44_ADD_DEL_LB_STATIC_MAPPING_REPLY, vl_api_nat44_add_del_lb_static_mapping_reply_t_handler)
vl_msg_id(VL_API_NAT44_LB_STATIC_MAPPING_ADD_DEL_LOCAL, vl_api_nat44_lb_static_mapping_add_del_local_t_handler)
vl_msg_id(VL_API_NAT44_LB_STATIC_MAPPING_ADD_DEL_LOCAL_REPLY, vl_api_nat44_lb_static_mapping_add_del_local_reply_t_handler)
vl_msg_id(VL_API_NAT44_LB_STATIC_MAPPING_DUMP, vl_api_nat44_lb_static_mapping_dump_t_handler)
vl_msg_id(VL_API_NAT44_LB_STATIC_MAPPING_DETAILS, vl_api_nat44_lb_static_mapping_details_t_handler)
vl_msg_id(VL_API_NAT44_DEL_SESSION, vl_api_nat44_del_session_t_handler)
vl_msg_id(VL_API_NAT44_DEL_SESSION_REPLY, vl_api_nat44_del_session_reply_t_handler)
vl_msg_id(VL_API_NAT44_USER_DUMP, vl_api_nat44_user_dump_t_handler)
vl_msg_id(VL_API_NAT44_USER_DETAILS, vl_api_nat44_user_details_t_handler)
vl_msg_id(VL_API_NAT44_USER_SESSION_DUMP, vl_api_nat44_user_session_dump_t_handler)
vl_msg_id(VL_API_NAT44_USER_SESSION_DETAILS, vl_api_nat44_user_session_details_t_handler)
vl_msg_id(VL_API_NAT44_USER_SESSION_V2_DUMP, vl_api_nat44_user_session_v2_dump_t_handler)
vl_msg_id(VL_API_NAT44_USER_SESSION_V2_DETAILS, vl_api_nat44_user_session_v2_details_t_handler)
vl_msg_id(VL_API_NAT44_USER_SESSION_V3_DETAILS, vl_api_nat44_user_session_v3_details_t_handler)
vl_msg_id(VL_API_NAT44_USER_SESSION_V3_DUMP, vl_api_nat44_user_session_v3_dump_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_nat44_ed_plugin_enable_disable_t, 1)
vl_msg_name(vl_api_nat44_ed_plugin_enable_disable_reply_t, 1)
vl_msg_name(vl_api_nat44_forwarding_enable_disable_t, 1)
vl_msg_name(vl_api_nat44_forwarding_enable_disable_reply_t, 1)
vl_msg_name(vl_api_nat_ipfix_enable_disable_t, 1)
vl_msg_name(vl_api_nat_ipfix_enable_disable_reply_t, 1)
vl_msg_name(vl_api_nat_set_timeouts_t, 1)
vl_msg_name(vl_api_nat_set_timeouts_reply_t, 1)
vl_msg_name(vl_api_nat44_set_session_limit_t, 1)
vl_msg_name(vl_api_nat44_set_session_limit_reply_t, 1)
vl_msg_name(vl_api_nat44_show_running_config_t, 1)
vl_msg_name(vl_api_nat44_show_running_config_reply_t, 1)
vl_msg_name(vl_api_nat_set_workers_t, 1)
vl_msg_name(vl_api_nat_set_workers_reply_t, 1)
vl_msg_name(vl_api_nat_worker_dump_t, 1)
vl_msg_name(vl_api_nat_worker_details_t, 1)
vl_msg_name(vl_api_nat44_ed_add_del_vrf_table_t, 1)
vl_msg_name(vl_api_nat44_ed_add_del_vrf_table_reply_t, 1)
vl_msg_name(vl_api_nat44_ed_add_del_vrf_route_t, 1)
vl_msg_name(vl_api_nat44_ed_add_del_vrf_route_reply_t, 1)
vl_msg_name(vl_api_nat44_ed_vrf_tables_dump_t, 1)
vl_msg_name(vl_api_nat44_ed_vrf_tables_details_t, 1)
vl_msg_name(vl_api_nat44_ed_vrf_tables_v2_dump_t, 1)
vl_msg_name(vl_api_nat44_ed_vrf_tables_v2_details_t, 1)
vl_msg_name(vl_api_nat_set_mss_clamping_t, 1)
vl_msg_name(vl_api_nat_set_mss_clamping_reply_t, 1)
vl_msg_name(vl_api_nat_get_mss_clamping_t, 1)
vl_msg_name(vl_api_nat_get_mss_clamping_reply_t, 1)
vl_msg_name(vl_api_nat44_ed_set_fq_options_t, 1)
vl_msg_name(vl_api_nat44_ed_set_fq_options_reply_t, 1)
vl_msg_name(vl_api_nat44_ed_show_fq_options_t, 1)
vl_msg_name(vl_api_nat44_ed_show_fq_options_reply_t, 1)
vl_msg_name(vl_api_nat44_add_del_interface_addr_t, 1)
vl_msg_name(vl_api_nat44_add_del_interface_addr_reply_t, 1)
vl_msg_name(vl_api_nat44_interface_addr_dump_t, 1)
vl_msg_name(vl_api_nat44_interface_addr_details_t, 1)
vl_msg_name(vl_api_nat44_add_del_address_range_t, 1)
vl_msg_name(vl_api_nat44_add_del_address_range_reply_t, 1)
vl_msg_name(vl_api_nat44_address_dump_t, 1)
vl_msg_name(vl_api_nat44_address_details_t, 1)
vl_msg_name(vl_api_nat44_interface_add_del_feature_t, 1)
vl_msg_name(vl_api_nat44_interface_add_del_feature_reply_t, 1)
vl_msg_name(vl_api_nat44_interface_dump_t, 1)
vl_msg_name(vl_api_nat44_interface_details_t, 1)
vl_msg_name(vl_api_nat44_ed_add_del_output_interface_t, 1)
vl_msg_name(vl_api_nat44_ed_add_del_output_interface_reply_t, 1)
vl_msg_name(vl_api_nat44_ed_output_interface_get_t, 1)
vl_msg_name(vl_api_nat44_ed_output_interface_get_reply_t, 1)
vl_msg_name(vl_api_nat44_ed_output_interface_details_t, 1)
vl_msg_name(vl_api_nat44_add_del_static_mapping_t, 1)
vl_msg_name(vl_api_nat44_add_del_static_mapping_reply_t, 1)
vl_msg_name(vl_api_nat44_add_del_static_mapping_v2_t, 1)
vl_msg_name(vl_api_nat44_add_del_static_mapping_v2_reply_t, 1)
vl_msg_name(vl_api_nat44_static_mapping_dump_t, 1)
vl_msg_name(vl_api_nat44_static_mapping_details_t, 1)
vl_msg_name(vl_api_nat44_add_del_identity_mapping_t, 1)
vl_msg_name(vl_api_nat44_add_del_identity_mapping_reply_t, 1)
vl_msg_name(vl_api_nat44_identity_mapping_dump_t, 1)
vl_msg_name(vl_api_nat44_identity_mapping_details_t, 1)
vl_msg_name(vl_api_nat44_add_del_lb_static_mapping_t, 1)
vl_msg_name(vl_api_nat44_add_del_lb_static_mapping_reply_t, 1)
vl_msg_name(vl_api_nat44_lb_static_mapping_add_del_local_t, 1)
vl_msg_name(vl_api_nat44_lb_static_mapping_add_del_local_reply_t, 1)
vl_msg_name(vl_api_nat44_lb_static_mapping_dump_t, 1)
vl_msg_name(vl_api_nat44_lb_static_mapping_details_t, 1)
vl_msg_name(vl_api_nat44_del_session_t, 1)
vl_msg_name(vl_api_nat44_del_session_reply_t, 1)
vl_msg_name(vl_api_nat44_user_dump_t, 1)
vl_msg_name(vl_api_nat44_user_details_t, 1)
vl_msg_name(vl_api_nat44_user_session_dump_t, 1)
vl_msg_name(vl_api_nat44_user_session_details_t, 1)
vl_msg_name(vl_api_nat44_user_session_v2_dump_t, 1)
vl_msg_name(vl_api_nat44_user_session_v2_details_t, 1)
vl_msg_name(vl_api_nat44_user_session_v3_details_t, 1)
vl_msg_name(vl_api_nat44_user_session_v3_dump_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_nat44_ed \
_(VL_API_NAT44_ED_PLUGIN_ENABLE_DISABLE, nat44_ed_plugin_enable_disable, be17f8dd) \
_(VL_API_NAT44_ED_PLUGIN_ENABLE_DISABLE_REPLY, nat44_ed_plugin_enable_disable_reply, e8d4e804) \
_(VL_API_NAT44_FORWARDING_ENABLE_DISABLE, nat44_forwarding_enable_disable, b3e225d2) \
_(VL_API_NAT44_FORWARDING_ENABLE_DISABLE_REPLY, nat44_forwarding_enable_disable_reply, e8d4e804) \
_(VL_API_NAT_IPFIX_ENABLE_DISABLE, nat_ipfix_enable_disable, 9af4a2d2) \
_(VL_API_NAT_IPFIX_ENABLE_DISABLE_REPLY, nat_ipfix_enable_disable_reply, e8d4e804) \
_(VL_API_NAT_SET_TIMEOUTS, nat_set_timeouts, d4746b16) \
_(VL_API_NAT_SET_TIMEOUTS_REPLY, nat_set_timeouts_reply, e8d4e804) \
_(VL_API_NAT44_SET_SESSION_LIMIT, nat44_set_session_limit, 8899bbb1) \
_(VL_API_NAT44_SET_SESSION_LIMIT_REPLY, nat44_set_session_limit_reply, e8d4e804) \
_(VL_API_NAT44_SHOW_RUNNING_CONFIG, nat44_show_running_config, 51077d14) \
_(VL_API_NAT44_SHOW_RUNNING_CONFIG_REPLY, nat44_show_running_config_reply, 93d8e267) \
_(VL_API_NAT_SET_WORKERS, nat_set_workers, da926638) \
_(VL_API_NAT_SET_WORKERS_REPLY, nat_set_workers_reply, e8d4e804) \
_(VL_API_NAT_WORKER_DUMP, nat_worker_dump, 51077d14) \
_(VL_API_NAT_WORKER_DETAILS, nat_worker_details, 84bf06fc) \
_(VL_API_NAT44_ED_ADD_DEL_VRF_TABLE, nat44_ed_add_del_vrf_table, 08330904) \
_(VL_API_NAT44_ED_ADD_DEL_VRF_TABLE_REPLY, nat44_ed_add_del_vrf_table_reply, e8d4e804) \
_(VL_API_NAT44_ED_ADD_DEL_VRF_ROUTE, nat44_ed_add_del_vrf_route, 59187407) \
_(VL_API_NAT44_ED_ADD_DEL_VRF_ROUTE_REPLY, nat44_ed_add_del_vrf_route_reply, e8d4e804) \
_(VL_API_NAT44_ED_VRF_TABLES_DUMP, nat44_ed_vrf_tables_dump, 51077d14) \
_(VL_API_NAT44_ED_VRF_TABLES_DETAILS, nat44_ed_vrf_tables_details, 7b264e4f) \
_(VL_API_NAT44_ED_VRF_TABLES_V2_DUMP, nat44_ed_vrf_tables_v2_dump, 51077d14) \
_(VL_API_NAT44_ED_VRF_TABLES_V2_DETAILS, nat44_ed_vrf_tables_v2_details, 7b264e4f) \
_(VL_API_NAT_SET_MSS_CLAMPING, nat_set_mss_clamping, 25e90abb) \
_(VL_API_NAT_SET_MSS_CLAMPING_REPLY, nat_set_mss_clamping_reply, e8d4e804) \
_(VL_API_NAT_GET_MSS_CLAMPING, nat_get_mss_clamping, 51077d14) \
_(VL_API_NAT_GET_MSS_CLAMPING_REPLY, nat_get_mss_clamping_reply, 1c0b2a78) \
_(VL_API_NAT44_ED_SET_FQ_OPTIONS, nat44_ed_set_fq_options, 2399bd71) \
_(VL_API_NAT44_ED_SET_FQ_OPTIONS_REPLY, nat44_ed_set_fq_options_reply, e8d4e804) \
_(VL_API_NAT44_ED_SHOW_FQ_OPTIONS, nat44_ed_show_fq_options, 51077d14) \
_(VL_API_NAT44_ED_SHOW_FQ_OPTIONS_REPLY, nat44_ed_show_fq_options_reply, 7213b545) \
_(VL_API_NAT44_ADD_DEL_INTERFACE_ADDR, nat44_add_del_interface_addr, 4aed50c0) \
_(VL_API_NAT44_ADD_DEL_INTERFACE_ADDR_REPLY, nat44_add_del_interface_addr_reply, e8d4e804) \
_(VL_API_NAT44_INTERFACE_ADDR_DUMP, nat44_interface_addr_dump, 51077d14) \
_(VL_API_NAT44_INTERFACE_ADDR_DETAILS, nat44_interface_addr_details, e4aca9ca) \
_(VL_API_NAT44_ADD_DEL_ADDRESS_RANGE, nat44_add_del_address_range, 6f2b8055) \
_(VL_API_NAT44_ADD_DEL_ADDRESS_RANGE_REPLY, nat44_add_del_address_range_reply, e8d4e804) \
_(VL_API_NAT44_ADDRESS_DUMP, nat44_address_dump, 51077d14) \
_(VL_API_NAT44_ADDRESS_DETAILS, nat44_address_details, 0d1beac1) \
_(VL_API_NAT44_INTERFACE_ADD_DEL_FEATURE, nat44_interface_add_del_feature, f3699b83) \
_(VL_API_NAT44_INTERFACE_ADD_DEL_FEATURE_REPLY, nat44_interface_add_del_feature_reply, e8d4e804) \
_(VL_API_NAT44_INTERFACE_DUMP, nat44_interface_dump, 51077d14) \
_(VL_API_NAT44_INTERFACE_DETAILS, nat44_interface_details, 5d286289) \
_(VL_API_NAT44_ED_ADD_DEL_OUTPUT_INTERFACE, nat44_ed_add_del_output_interface, 47d6e753) \
_(VL_API_NAT44_ED_ADD_DEL_OUTPUT_INTERFACE_REPLY, nat44_ed_add_del_output_interface_reply, e8d4e804) \
_(VL_API_NAT44_ED_OUTPUT_INTERFACE_GET, nat44_ed_output_interface_get, f75ba505) \
_(VL_API_NAT44_ED_OUTPUT_INTERFACE_GET_REPLY, nat44_ed_output_interface_get_reply, 53b48f5d) \
_(VL_API_NAT44_ED_OUTPUT_INTERFACE_DETAILS, nat44_ed_output_interface_details, 0b45011c) \
_(VL_API_NAT44_ADD_DEL_STATIC_MAPPING, nat44_add_del_static_mapping, 5ae5f03e) \
_(VL_API_NAT44_ADD_DEL_STATIC_MAPPING_REPLY, nat44_add_del_static_mapping_reply, e8d4e804) \
_(VL_API_NAT44_ADD_DEL_STATIC_MAPPING_V2, nat44_add_del_static_mapping_v2, 5e205f1a) \
_(VL_API_NAT44_ADD_DEL_STATIC_MAPPING_V2_REPLY, nat44_add_del_static_mapping_v2_reply, e8d4e804) \
_(VL_API_NAT44_STATIC_MAPPING_DUMP, nat44_static_mapping_dump, 51077d14) \
_(VL_API_NAT44_STATIC_MAPPING_DETAILS, nat44_static_mapping_details, 06cb40b2) \
_(VL_API_NAT44_ADD_DEL_IDENTITY_MAPPING, nat44_add_del_identity_mapping, 02faaa22) \
_(VL_API_NAT44_ADD_DEL_IDENTITY_MAPPING_REPLY, nat44_add_del_identity_mapping_reply, e8d4e804) \
_(VL_API_NAT44_IDENTITY_MAPPING_DUMP, nat44_identity_mapping_dump, 51077d14) \
_(VL_API_NAT44_IDENTITY_MAPPING_DETAILS, nat44_identity_mapping_details, 2a52a030) \
_(VL_API_NAT44_ADD_DEL_LB_STATIC_MAPPING, nat44_add_del_lb_static_mapping, 4f68ee9d) \
_(VL_API_NAT44_ADD_DEL_LB_STATIC_MAPPING_REPLY, nat44_add_del_lb_static_mapping_reply, e8d4e804) \
_(VL_API_NAT44_LB_STATIC_MAPPING_ADD_DEL_LOCAL, nat44_lb_static_mapping_add_del_local, 7ca47547) \
_(VL_API_NAT44_LB_STATIC_MAPPING_ADD_DEL_LOCAL_REPLY, nat44_lb_static_mapping_add_del_local_reply, e8d4e804) \
_(VL_API_NAT44_LB_STATIC_MAPPING_DUMP, nat44_lb_static_mapping_dump, 51077d14) \
_(VL_API_NAT44_LB_STATIC_MAPPING_DETAILS, nat44_lb_static_mapping_details, ed5ce876) \
_(VL_API_NAT44_DEL_SESSION, nat44_del_session, 15a5bf8c) \
_(VL_API_NAT44_DEL_SESSION_REPLY, nat44_del_session_reply, e8d4e804) \
_(VL_API_NAT44_USER_DUMP, nat44_user_dump, 51077d14) \
_(VL_API_NAT44_USER_DETAILS, nat44_user_details, 355896c2) \
_(VL_API_NAT44_USER_SESSION_DUMP, nat44_user_session_dump, e1899c98) \
_(VL_API_NAT44_USER_SESSION_DETAILS, nat44_user_session_details, 2cf6e16d) \
_(VL_API_NAT44_USER_SESSION_V2_DUMP, nat44_user_session_v2_dump, e1899c98) \
_(VL_API_NAT44_USER_SESSION_V2_DETAILS, nat44_user_session_v2_details, fd42b729) \
_(VL_API_NAT44_USER_SESSION_V3_DETAILS, nat44_user_session_v3_details, edae926e) \
_(VL_API_NAT44_USER_SESSION_V3_DUMP, nat44_user_session_v3_dump, e1899c98) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "nat44_ed.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_nat44_ed_printfun_types
#define included_nat44_ed_printfun_types

static inline u8 *format_vl_api_nat44_config_flags_t (u8 *s, va_list * args)
{
    vl_api_nat44_config_flags_t *a = va_arg (*args, vl_api_nat44_config_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "NAT44_IS_ENDPOINT_INDEPENDENT");
    case 1:
        return format(s, "NAT44_IS_ENDPOINT_DEPENDENT");
    case 2:
        return format(s, "NAT44_IS_STATIC_MAPPING_ONLY");
    case 4:
        return format(s, "NAT44_IS_CONNECTION_TRACKING");
    case 8:
        return format(s, "NAT44_IS_OUT2IN_DPO");
    }
    return s;
}

static inline u8 *format_vl_api_nat44_lb_addr_port_t (u8 *s, va_list * args)
{
    vl_api_nat44_lb_addr_port_t *a = va_arg (*args, vl_api_nat44_lb_addr_port_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uaddr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->addr, indent);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    s = format(s, "\n%Uprobability: %u", format_white_space, indent, a->probability);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_nat44_ed_printfun
#define included_nat44_ed_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "nat44_ed.api_tojson.h"
#include "nat44_ed.api_fromjson.h"

static inline u8 *vl_api_nat44_ed_plugin_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ed_plugin_enable_disable_t *a = va_arg (*args, vl_api_nat44_ed_plugin_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ed_plugin_enable_disable_t: */
    s = format(s, "vl_api_nat44_ed_plugin_enable_disable_t:");
    s = format(s, "\n%Uinside_vrf: %u", format_white_space, indent, a->inside_vrf);
    s = format(s, "\n%Uoutside_vrf: %u", format_white_space, indent, a->outside_vrf);
    s = format(s, "\n%Usessions: %u", format_white_space, indent, a->sessions);
    s = format(s, "\n%Usession_memory: %u", format_white_space, indent, a->session_memory);
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat44_config_flags_t, &a->flags, indent);
    return s;
}

static inline u8 *vl_api_nat44_ed_plugin_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ed_plugin_enable_disable_reply_t *a = va_arg (*args, vl_api_nat44_ed_plugin_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ed_plugin_enable_disable_reply_t: */
    s = format(s, "vl_api_nat44_ed_plugin_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_forwarding_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_forwarding_enable_disable_t *a = va_arg (*args, vl_api_nat44_forwarding_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_forwarding_enable_disable_t: */
    s = format(s, "vl_api_nat44_forwarding_enable_disable_t:");
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}

static inline u8 *vl_api_nat44_forwarding_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_forwarding_enable_disable_reply_t *a = va_arg (*args, vl_api_nat44_forwarding_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_forwarding_enable_disable_reply_t: */
    s = format(s, "vl_api_nat44_forwarding_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat_ipfix_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_ipfix_enable_disable_t *a = va_arg (*args, vl_api_nat_ipfix_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_ipfix_enable_disable_t: */
    s = format(s, "vl_api_nat_ipfix_enable_disable_t:");
    s = format(s, "\n%Udomain_id: %u", format_white_space, indent, a->domain_id);
    s = format(s, "\n%Usrc_port: %u", format_white_space, indent, a->src_port);
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}

static inline u8 *vl_api_nat_ipfix_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_ipfix_enable_disable_reply_t *a = va_arg (*args, vl_api_nat_ipfix_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_ipfix_enable_disable_reply_t: */
    s = format(s, "vl_api_nat_ipfix_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat_set_timeouts_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_set_timeouts_t *a = va_arg (*args, vl_api_nat_set_timeouts_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_set_timeouts_t: */
    s = format(s, "vl_api_nat_set_timeouts_t:");
    s = format(s, "\n%Uudp: %u", format_white_space, indent, a->udp);
    s = format(s, "\n%Utcp_established: %u", format_white_space, indent, a->tcp_established);
    s = format(s, "\n%Utcp_transitory: %u", format_white_space, indent, a->tcp_transitory);
    s = format(s, "\n%Uicmp: %u", format_white_space, indent, a->icmp);
    return s;
}

static inline u8 *vl_api_nat_set_timeouts_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_set_timeouts_reply_t *a = va_arg (*args, vl_api_nat_set_timeouts_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_set_timeouts_reply_t: */
    s = format(s, "vl_api_nat_set_timeouts_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_set_session_limit_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_set_session_limit_t *a = va_arg (*args, vl_api_nat44_set_session_limit_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_set_session_limit_t: */
    s = format(s, "vl_api_nat44_set_session_limit_t:");
    s = format(s, "\n%Usession_limit: %u", format_white_space, indent, a->session_limit);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    return s;
}

static inline u8 *vl_api_nat44_set_session_limit_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_set_session_limit_reply_t *a = va_arg (*args, vl_api_nat44_set_session_limit_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_set_session_limit_reply_t: */
    s = format(s, "vl_api_nat44_set_session_limit_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_show_running_config_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_show_running_config_t *a = va_arg (*args, vl_api_nat44_show_running_config_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_show_running_config_t: */
    s = format(s, "vl_api_nat44_show_running_config_t:");
    return s;
}

static inline u8 *vl_api_nat44_show_running_config_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_show_running_config_reply_t *a = va_arg (*args, vl_api_nat44_show_running_config_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_show_running_config_reply_t: */
    s = format(s, "vl_api_nat44_show_running_config_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uinside_vrf: %u", format_white_space, indent, a->inside_vrf);
    s = format(s, "\n%Uoutside_vrf: %u", format_white_space, indent, a->outside_vrf);
    s = format(s, "\n%Uusers: %u", format_white_space, indent, a->users);
    s = format(s, "\n%Usessions: %u", format_white_space, indent, a->sessions);
    s = format(s, "\n%Uuser_sessions: %u", format_white_space, indent, a->user_sessions);
    s = format(s, "\n%Uuser_buckets: %u", format_white_space, indent, a->user_buckets);
    s = format(s, "\n%Utranslation_buckets: %u", format_white_space, indent, a->translation_buckets);
    s = format(s, "\n%Uforwarding_enabled: %u", format_white_space, indent, a->forwarding_enabled);
    s = format(s, "\n%Uipfix_logging_enabled: %u", format_white_space, indent, a->ipfix_logging_enabled);
    s = format(s, "\n%Utimeouts: %U", format_white_space, indent, format_vl_api_nat_timeouts_t, &a->timeouts, indent);
    s = format(s, "\n%Ulog_level: %U", format_white_space, indent, format_vl_api_nat_log_level_t, &a->log_level, indent);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat44_config_flags_t, &a->flags, indent);
    return s;
}

static inline u8 *vl_api_nat_set_workers_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_set_workers_t *a = va_arg (*args, vl_api_nat_set_workers_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_set_workers_t: */
    s = format(s, "vl_api_nat_set_workers_t:");
    s = format(s, "\n%Uworker_mask: %llu", format_white_space, indent, a->worker_mask);
    return s;
}

static inline u8 *vl_api_nat_set_workers_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_set_workers_reply_t *a = va_arg (*args, vl_api_nat_set_workers_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_set_workers_reply_t: */
    s = format(s, "vl_api_nat_set_workers_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat_worker_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_worker_dump_t *a = va_arg (*args, vl_api_nat_worker_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_worker_dump_t: */
    s = format(s, "vl_api_nat_worker_dump_t:");
    return s;
}

static inline u8 *vl_api_nat_worker_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_worker_details_t *a = va_arg (*args, vl_api_nat_worker_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_worker_details_t: */
    s = format(s, "vl_api_nat_worker_details_t:");
    s = format(s, "\n%Uworker_index: %u", format_white_space, indent, a->worker_index);
    s = format(s, "\n%Ulcore_id: %u", format_white_space, indent, a->lcore_id);
    s = format(s, "\n%Uname: %s", format_white_space, indent, a->name);
    return s;
}

static inline u8 *vl_api_nat44_ed_add_del_vrf_table_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ed_add_del_vrf_table_t *a = va_arg (*args, vl_api_nat44_ed_add_del_vrf_table_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ed_add_del_vrf_table_t: */
    s = format(s, "vl_api_nat44_ed_add_del_vrf_table_t:");
    s = format(s, "\n%Utable_vrf_id: %u", format_white_space, indent, a->table_vrf_id);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    return s;
}

static inline u8 *vl_api_nat44_ed_add_del_vrf_table_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ed_add_del_vrf_table_reply_t *a = va_arg (*args, vl_api_nat44_ed_add_del_vrf_table_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ed_add_del_vrf_table_reply_t: */
    s = format(s, "vl_api_nat44_ed_add_del_vrf_table_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ed_add_del_vrf_route_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ed_add_del_vrf_route_t *a = va_arg (*args, vl_api_nat44_ed_add_del_vrf_route_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ed_add_del_vrf_route_t: */
    s = format(s, "vl_api_nat44_ed_add_del_vrf_route_t:");
    s = format(s, "\n%Utable_vrf_id: %u", format_white_space, indent, a->table_vrf_id);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    return s;
}

static inline u8 *vl_api_nat44_ed_add_del_vrf_route_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ed_add_del_vrf_route_reply_t *a = va_arg (*args, vl_api_nat44_ed_add_del_vrf_route_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ed_add_del_vrf_route_reply_t: */
    s = format(s, "vl_api_nat44_ed_add_del_vrf_route_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ed_vrf_tables_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ed_vrf_tables_dump_t *a = va_arg (*args, vl_api_nat44_ed_vrf_tables_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ed_vrf_tables_dump_t: */
    s = format(s, "vl_api_nat44_ed_vrf_tables_dump_t:");
    return s;
}

static inline u8 *vl_api_nat44_ed_vrf_tables_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ed_vrf_tables_details_t *a = va_arg (*args, vl_api_nat44_ed_vrf_tables_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ed_vrf_tables_details_t: */
    s = format(s, "vl_api_nat44_ed_vrf_tables_details_t:");
    s = format(s, "\n%Utable_vrf_id: %u", format_white_space, indent, a->table_vrf_id);
    s = format(s, "\n%Un_vrf_ids: %u", format_white_space, indent, a->n_vrf_ids);
    for (i = 0; i < a->n_vrf_ids; i++) {
        s = format(s, "\n%Uvrf_ids: %u",
                   format_white_space, indent, a->vrf_ids[i]);
    }
    return s;
}

static inline u8 *vl_api_nat44_ed_vrf_tables_v2_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ed_vrf_tables_v2_dump_t *a = va_arg (*args, vl_api_nat44_ed_vrf_tables_v2_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ed_vrf_tables_v2_dump_t: */
    s = format(s, "vl_api_nat44_ed_vrf_tables_v2_dump_t:");
    return s;
}

static inline u8 *vl_api_nat44_ed_vrf_tables_v2_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ed_vrf_tables_v2_details_t *a = va_arg (*args, vl_api_nat44_ed_vrf_tables_v2_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ed_vrf_tables_v2_details_t: */
    s = format(s, "vl_api_nat44_ed_vrf_tables_v2_details_t:");
    s = format(s, "\n%Utable_vrf_id: %u", format_white_space, indent, a->table_vrf_id);
    s = format(s, "\n%Un_vrf_ids: %u", format_white_space, indent, a->n_vrf_ids);
    for (i = 0; i < a->n_vrf_ids; i++) {
        s = format(s, "\n%Uvrf_ids: %u",
                   format_white_space, indent, a->vrf_ids[i]);
    }
    return s;
}

static inline u8 *vl_api_nat_set_mss_clamping_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_set_mss_clamping_t *a = va_arg (*args, vl_api_nat_set_mss_clamping_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_set_mss_clamping_t: */
    s = format(s, "vl_api_nat_set_mss_clamping_t:");
    s = format(s, "\n%Umss_value: %u", format_white_space, indent, a->mss_value);
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}

static inline u8 *vl_api_nat_set_mss_clamping_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_set_mss_clamping_reply_t *a = va_arg (*args, vl_api_nat_set_mss_clamping_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_set_mss_clamping_reply_t: */
    s = format(s, "vl_api_nat_set_mss_clamping_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat_get_mss_clamping_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_get_mss_clamping_t *a = va_arg (*args, vl_api_nat_get_mss_clamping_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_get_mss_clamping_t: */
    s = format(s, "vl_api_nat_get_mss_clamping_t:");
    return s;
}

static inline u8 *vl_api_nat_get_mss_clamping_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat_get_mss_clamping_reply_t *a = va_arg (*args, vl_api_nat_get_mss_clamping_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat_get_mss_clamping_reply_t: */
    s = format(s, "vl_api_nat_get_mss_clamping_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Umss_value: %u", format_white_space, indent, a->mss_value);
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}

static inline u8 *vl_api_nat44_ed_set_fq_options_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ed_set_fq_options_t *a = va_arg (*args, vl_api_nat44_ed_set_fq_options_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ed_set_fq_options_t: */
    s = format(s, "vl_api_nat44_ed_set_fq_options_t:");
    s = format(s, "\n%Uframe_queue_nelts: %u", format_white_space, indent, a->frame_queue_nelts);
    return s;
}

static inline u8 *vl_api_nat44_ed_set_fq_options_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ed_set_fq_options_reply_t *a = va_arg (*args, vl_api_nat44_ed_set_fq_options_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ed_set_fq_options_reply_t: */
    s = format(s, "vl_api_nat44_ed_set_fq_options_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ed_show_fq_options_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ed_show_fq_options_t *a = va_arg (*args, vl_api_nat44_ed_show_fq_options_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ed_show_fq_options_t: */
    s = format(s, "vl_api_nat44_ed_show_fq_options_t:");
    return s;
}

static inline u8 *vl_api_nat44_ed_show_fq_options_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ed_show_fq_options_reply_t *a = va_arg (*args, vl_api_nat44_ed_show_fq_options_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ed_show_fq_options_reply_t: */
    s = format(s, "vl_api_nat44_ed_show_fq_options_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uframe_queue_nelts: %u", format_white_space, indent, a->frame_queue_nelts);
    return s;
}

static inline u8 *vl_api_nat44_add_del_interface_addr_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_add_del_interface_addr_t *a = va_arg (*args, vl_api_nat44_add_del_interface_addr_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_add_del_interface_addr_t: */
    s = format(s, "vl_api_nat44_add_del_interface_addr_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat_config_flags_t, &a->flags, indent);
    return s;
}

static inline u8 *vl_api_nat44_add_del_interface_addr_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_add_del_interface_addr_reply_t *a = va_arg (*args, vl_api_nat44_add_del_interface_addr_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_add_del_interface_addr_reply_t: */
    s = format(s, "vl_api_nat44_add_del_interface_addr_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_interface_addr_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_interface_addr_dump_t *a = va_arg (*args, vl_api_nat44_interface_addr_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_interface_addr_dump_t: */
    s = format(s, "vl_api_nat44_interface_addr_dump_t:");
    return s;
}

static inline u8 *vl_api_nat44_interface_addr_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_interface_addr_details_t *a = va_arg (*args, vl_api_nat44_interface_addr_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_interface_addr_details_t: */
    s = format(s, "vl_api_nat44_interface_addr_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat_config_flags_t, &a->flags, indent);
    return s;
}

static inline u8 *vl_api_nat44_add_del_address_range_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_add_del_address_range_t *a = va_arg (*args, vl_api_nat44_add_del_address_range_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_add_del_address_range_t: */
    s = format(s, "vl_api_nat44_add_del_address_range_t:");
    s = format(s, "\n%Ufirst_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->first_ip_address, indent);
    s = format(s, "\n%Ulast_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->last_ip_address, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat_config_flags_t, &a->flags, indent);
    return s;
}

static inline u8 *vl_api_nat44_add_del_address_range_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_add_del_address_range_reply_t *a = va_arg (*args, vl_api_nat44_add_del_address_range_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_add_del_address_range_reply_t: */
    s = format(s, "vl_api_nat44_add_del_address_range_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_address_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_address_dump_t *a = va_arg (*args, vl_api_nat44_address_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_address_dump_t: */
    s = format(s, "vl_api_nat44_address_dump_t:");
    return s;
}

static inline u8 *vl_api_nat44_address_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_address_details_t *a = va_arg (*args, vl_api_nat44_address_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_address_details_t: */
    s = format(s, "vl_api_nat44_address_details_t:");
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip_address, indent);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    return s;
}

static inline u8 *vl_api_nat44_interface_add_del_feature_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_interface_add_del_feature_t *a = va_arg (*args, vl_api_nat44_interface_add_del_feature_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_interface_add_del_feature_t: */
    s = format(s, "vl_api_nat44_interface_add_del_feature_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_nat44_interface_add_del_feature_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_interface_add_del_feature_reply_t *a = va_arg (*args, vl_api_nat44_interface_add_del_feature_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_interface_add_del_feature_reply_t: */
    s = format(s, "vl_api_nat44_interface_add_del_feature_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_interface_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_interface_dump_t *a = va_arg (*args, vl_api_nat44_interface_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_interface_dump_t: */
    s = format(s, "vl_api_nat44_interface_dump_t:");
    return s;
}

static inline u8 *vl_api_nat44_interface_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_interface_details_t *a = va_arg (*args, vl_api_nat44_interface_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_interface_details_t: */
    s = format(s, "vl_api_nat44_interface_details_t:");
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_nat44_ed_add_del_output_interface_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ed_add_del_output_interface_t *a = va_arg (*args, vl_api_nat44_ed_add_del_output_interface_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ed_add_del_output_interface_t: */
    s = format(s, "vl_api_nat44_ed_add_del_output_interface_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_nat44_ed_add_del_output_interface_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ed_add_del_output_interface_reply_t *a = va_arg (*args, vl_api_nat44_ed_add_del_output_interface_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ed_add_del_output_interface_reply_t: */
    s = format(s, "vl_api_nat44_ed_add_del_output_interface_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ed_output_interface_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ed_output_interface_get_t *a = va_arg (*args, vl_api_nat44_ed_output_interface_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ed_output_interface_get_t: */
    s = format(s, "vl_api_nat44_ed_output_interface_get_t:");
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_nat44_ed_output_interface_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ed_output_interface_get_reply_t *a = va_arg (*args, vl_api_nat44_ed_output_interface_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ed_output_interface_get_reply_t: */
    s = format(s, "vl_api_nat44_ed_output_interface_get_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_nat44_ed_output_interface_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ed_output_interface_details_t *a = va_arg (*args, vl_api_nat44_ed_output_interface_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ed_output_interface_details_t: */
    s = format(s, "vl_api_nat44_ed_output_interface_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_nat44_add_del_static_mapping_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_add_del_static_mapping_t *a = va_arg (*args, vl_api_nat44_add_del_static_mapping_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_add_del_static_mapping_t: */
    s = format(s, "vl_api_nat44_add_del_static_mapping_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Ulocal_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->local_ip_address, indent);
    s = format(s, "\n%Uexternal_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->external_ip_address, indent);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Ulocal_port: %u", format_white_space, indent, a->local_port);
    s = format(s, "\n%Uexternal_port: %u", format_white_space, indent, a->external_port);
    s = format(s, "\n%Uexternal_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->external_sw_if_index, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    return s;
}

static inline u8 *vl_api_nat44_add_del_static_mapping_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_add_del_static_mapping_reply_t *a = va_arg (*args, vl_api_nat44_add_del_static_mapping_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_add_del_static_mapping_reply_t: */
    s = format(s, "vl_api_nat44_add_del_static_mapping_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_add_del_static_mapping_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_add_del_static_mapping_v2_t *a = va_arg (*args, vl_api_nat44_add_del_static_mapping_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_add_del_static_mapping_v2_t: */
    s = format(s, "vl_api_nat44_add_del_static_mapping_v2_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Umatch_pool: %u", format_white_space, indent, a->match_pool);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Upool_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->pool_ip_address, indent);
    s = format(s, "\n%Ulocal_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->local_ip_address, indent);
    s = format(s, "\n%Uexternal_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->external_ip_address, indent);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Ulocal_port: %u", format_white_space, indent, a->local_port);
    s = format(s, "\n%Uexternal_port: %u", format_white_space, indent, a->external_port);
    s = format(s, "\n%Uexternal_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->external_sw_if_index, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    return s;
}

static inline u8 *vl_api_nat44_add_del_static_mapping_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_add_del_static_mapping_v2_reply_t *a = va_arg (*args, vl_api_nat44_add_del_static_mapping_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_add_del_static_mapping_v2_reply_t: */
    s = format(s, "vl_api_nat44_add_del_static_mapping_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_static_mapping_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_static_mapping_dump_t *a = va_arg (*args, vl_api_nat44_static_mapping_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_static_mapping_dump_t: */
    s = format(s, "vl_api_nat44_static_mapping_dump_t:");
    return s;
}

static inline u8 *vl_api_nat44_static_mapping_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_static_mapping_details_t *a = va_arg (*args, vl_api_nat44_static_mapping_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_static_mapping_details_t: */
    s = format(s, "vl_api_nat44_static_mapping_details_t:");
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Ulocal_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->local_ip_address, indent);
    s = format(s, "\n%Uexternal_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->external_ip_address, indent);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Ulocal_port: %u", format_white_space, indent, a->local_port);
    s = format(s, "\n%Uexternal_port: %u", format_white_space, indent, a->external_port);
    s = format(s, "\n%Uexternal_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->external_sw_if_index, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    return s;
}

static inline u8 *vl_api_nat44_add_del_identity_mapping_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_add_del_identity_mapping_t *a = va_arg (*args, vl_api_nat44_add_del_identity_mapping_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_add_del_identity_mapping_t: */
    s = format(s, "vl_api_nat44_add_del_identity_mapping_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip_address, indent);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    return s;
}

static inline u8 *vl_api_nat44_add_del_identity_mapping_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_add_del_identity_mapping_reply_t *a = va_arg (*args, vl_api_nat44_add_del_identity_mapping_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_add_del_identity_mapping_reply_t: */
    s = format(s, "vl_api_nat44_add_del_identity_mapping_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_identity_mapping_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_identity_mapping_dump_t *a = va_arg (*args, vl_api_nat44_identity_mapping_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_identity_mapping_dump_t: */
    s = format(s, "vl_api_nat44_identity_mapping_dump_t:");
    return s;
}

static inline u8 *vl_api_nat44_identity_mapping_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_identity_mapping_details_t *a = va_arg (*args, vl_api_nat44_identity_mapping_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_identity_mapping_details_t: */
    s = format(s, "vl_api_nat44_identity_mapping_details_t:");
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip_address, indent);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    return s;
}

static inline u8 *vl_api_nat44_add_del_lb_static_mapping_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_add_del_lb_static_mapping_t *a = va_arg (*args, vl_api_nat44_add_del_lb_static_mapping_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_add_del_lb_static_mapping_t: */
    s = format(s, "vl_api_nat44_add_del_lb_static_mapping_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Uexternal_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->external_addr, indent);
    s = format(s, "\n%Uexternal_port: %u", format_white_space, indent, a->external_port);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Uaffinity: %u", format_white_space, indent, a->affinity);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    s = format(s, "\n%Ulocal_num: %u", format_white_space, indent, a->local_num);
    for (i = 0; i < a->local_num; i++) {
        s = format(s, "\n%Ulocals: %U",
                   format_white_space, indent, format_vl_api_nat44_lb_addr_port_t, &a->locals[i], indent);
    }
    return s;
}

static inline u8 *vl_api_nat44_add_del_lb_static_mapping_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_add_del_lb_static_mapping_reply_t *a = va_arg (*args, vl_api_nat44_add_del_lb_static_mapping_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_add_del_lb_static_mapping_reply_t: */
    s = format(s, "vl_api_nat44_add_del_lb_static_mapping_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_lb_static_mapping_add_del_local_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_lb_static_mapping_add_del_local_t *a = va_arg (*args, vl_api_nat44_lb_static_mapping_add_del_local_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_lb_static_mapping_add_del_local_t: */
    s = format(s, "vl_api_nat44_lb_static_mapping_add_del_local_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uexternal_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->external_addr, indent);
    s = format(s, "\n%Uexternal_port: %u", format_white_space, indent, a->external_port);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Ulocal: %U", format_white_space, indent, format_vl_api_nat44_lb_addr_port_t, &a->local, indent);
    return s;
}

static inline u8 *vl_api_nat44_lb_static_mapping_add_del_local_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_lb_static_mapping_add_del_local_reply_t *a = va_arg (*args, vl_api_nat44_lb_static_mapping_add_del_local_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_lb_static_mapping_add_del_local_reply_t: */
    s = format(s, "vl_api_nat44_lb_static_mapping_add_del_local_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_lb_static_mapping_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_lb_static_mapping_dump_t *a = va_arg (*args, vl_api_nat44_lb_static_mapping_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_lb_static_mapping_dump_t: */
    s = format(s, "vl_api_nat44_lb_static_mapping_dump_t:");
    return s;
}

static inline u8 *vl_api_nat44_lb_static_mapping_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_lb_static_mapping_details_t *a = va_arg (*args, vl_api_nat44_lb_static_mapping_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_lb_static_mapping_details_t: */
    s = format(s, "vl_api_nat44_lb_static_mapping_details_t:");
    s = format(s, "\n%Uexternal_addr: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->external_addr, indent);
    s = format(s, "\n%Uexternal_port: %u", format_white_space, indent, a->external_port);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Uaffinity: %u", format_white_space, indent, a->affinity);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    s = format(s, "\n%Ulocal_num: %u", format_white_space, indent, a->local_num);
    for (i = 0; i < a->local_num; i++) {
        s = format(s, "\n%Ulocals: %U",
                   format_white_space, indent, format_vl_api_nat44_lb_addr_port_t, &a->locals[i], indent);
    }
    return s;
}

static inline u8 *vl_api_nat44_del_session_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_del_session_t *a = va_arg (*args, vl_api_nat44_del_session_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_del_session_t: */
    s = format(s, "vl_api_nat44_del_session_t:");
    s = format(s, "\n%Uaddress: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->address, indent);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Uext_host_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ext_host_address, indent);
    s = format(s, "\n%Uext_host_port: %u", format_white_space, indent, a->ext_host_port);
    return s;
}

static inline u8 *vl_api_nat44_del_session_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_del_session_reply_t *a = va_arg (*args, vl_api_nat44_del_session_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_del_session_reply_t: */
    s = format(s, "vl_api_nat44_del_session_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_user_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_user_dump_t *a = va_arg (*args, vl_api_nat44_user_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_user_dump_t: */
    s = format(s, "vl_api_nat44_user_dump_t:");
    return s;
}

static inline u8 *vl_api_nat44_user_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_user_details_t *a = va_arg (*args, vl_api_nat44_user_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_user_details_t: */
    s = format(s, "vl_api_nat44_user_details_t:");
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip_address, indent);
    s = format(s, "\n%Unsessions: %u", format_white_space, indent, a->nsessions);
    s = format(s, "\n%Unstaticsessions: %u", format_white_space, indent, a->nstaticsessions);
    return s;
}

static inline u8 *vl_api_nat44_user_session_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_user_session_dump_t *a = va_arg (*args, vl_api_nat44_user_session_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_user_session_dump_t: */
    s = format(s, "vl_api_nat44_user_session_dump_t:");
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip_address, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    return s;
}

static inline u8 *vl_api_nat44_user_session_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_user_session_details_t *a = va_arg (*args, vl_api_nat44_user_session_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_user_session_details_t: */
    s = format(s, "vl_api_nat44_user_session_details_t:");
    s = format(s, "\n%Uoutside_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->outside_ip_address, indent);
    s = format(s, "\n%Uoutside_port: %u", format_white_space, indent, a->outside_port);
    s = format(s, "\n%Uinside_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->inside_ip_address, indent);
    s = format(s, "\n%Uinside_port: %u", format_white_space, indent, a->inside_port);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Ulast_heard: %llu", format_white_space, indent, a->last_heard);
    s = format(s, "\n%Utotal_bytes: %llu", format_white_space, indent, a->total_bytes);
    s = format(s, "\n%Utotal_pkts: %u", format_white_space, indent, a->total_pkts);
    s = format(s, "\n%Uext_host_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ext_host_address, indent);
    s = format(s, "\n%Uext_host_port: %u", format_white_space, indent, a->ext_host_port);
    s = format(s, "\n%Uext_host_nat_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ext_host_nat_address, indent);
    s = format(s, "\n%Uext_host_nat_port: %u", format_white_space, indent, a->ext_host_nat_port);
    return s;
}

static inline u8 *vl_api_nat44_user_session_v2_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_user_session_v2_dump_t *a = va_arg (*args, vl_api_nat44_user_session_v2_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_user_session_v2_dump_t: */
    s = format(s, "vl_api_nat44_user_session_v2_dump_t:");
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip_address, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    return s;
}

static inline u8 *vl_api_nat44_user_session_v2_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_user_session_v2_details_t *a = va_arg (*args, vl_api_nat44_user_session_v2_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_user_session_v2_details_t: */
    s = format(s, "vl_api_nat44_user_session_v2_details_t:");
    s = format(s, "\n%Uoutside_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->outside_ip_address, indent);
    s = format(s, "\n%Uoutside_port: %u", format_white_space, indent, a->outside_port);
    s = format(s, "\n%Uinside_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->inside_ip_address, indent);
    s = format(s, "\n%Uinside_port: %u", format_white_space, indent, a->inside_port);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Ulast_heard: %llu", format_white_space, indent, a->last_heard);
    s = format(s, "\n%Utotal_bytes: %llu", format_white_space, indent, a->total_bytes);
    s = format(s, "\n%Utotal_pkts: %u", format_white_space, indent, a->total_pkts);
    s = format(s, "\n%Uext_host_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ext_host_address, indent);
    s = format(s, "\n%Uext_host_port: %u", format_white_space, indent, a->ext_host_port);
    s = format(s, "\n%Uext_host_nat_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ext_host_nat_address, indent);
    s = format(s, "\n%Uext_host_nat_port: %u", format_white_space, indent, a->ext_host_nat_port);
    s = format(s, "\n%Uis_timed_out: %u", format_white_space, indent, a->is_timed_out);
    return s;
}

static inline u8 *vl_api_nat44_user_session_v3_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_user_session_v3_details_t *a = va_arg (*args, vl_api_nat44_user_session_v3_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_user_session_v3_details_t: */
    s = format(s, "vl_api_nat44_user_session_v3_details_t:");
    s = format(s, "\n%Uoutside_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->outside_ip_address, indent);
    s = format(s, "\n%Uoutside_port: %u", format_white_space, indent, a->outside_port);
    s = format(s, "\n%Uinside_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->inside_ip_address, indent);
    s = format(s, "\n%Uinside_port: %u", format_white_space, indent, a->inside_port);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Ulast_heard: %llu", format_white_space, indent, a->last_heard);
    s = format(s, "\n%Utime_since_last_heard: %llu", format_white_space, indent, a->time_since_last_heard);
    s = format(s, "\n%Utotal_bytes: %llu", format_white_space, indent, a->total_bytes);
    s = format(s, "\n%Utotal_pkts: %u", format_white_space, indent, a->total_pkts);
    s = format(s, "\n%Uext_host_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ext_host_address, indent);
    s = format(s, "\n%Uext_host_port: %u", format_white_space, indent, a->ext_host_port);
    s = format(s, "\n%Uext_host_nat_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ext_host_nat_address, indent);
    s = format(s, "\n%Uext_host_nat_port: %u", format_white_space, indent, a->ext_host_nat_port);
    s = format(s, "\n%Uis_timed_out: %u", format_white_space, indent, a->is_timed_out);
    return s;
}

static inline u8 *vl_api_nat44_user_session_v3_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_user_session_v3_dump_t *a = va_arg (*args, vl_api_nat44_user_session_v3_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_user_session_v3_dump_t: */
    s = format(s, "vl_api_nat44_user_session_v3_dump_t:");
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip_address, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_nat44_ed_endianfun
#define included_nat44_ed_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_nat44_config_flags_t_endian (vl_api_nat44_config_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->nat44_config_flags = a->nat44_config_flags (no-op) */
}

static inline void vl_api_nat44_lb_addr_port_t_endian (vl_api_nat44_lb_addr_port_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_ip4_address_t_endian(&a->addr, to_net);
    a->port = clib_net_to_host_u16(a->port);
    /* a->probability = a->probability (no-op) */
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
}

static inline void vl_api_nat44_ed_plugin_enable_disable_t_endian (vl_api_nat44_ed_plugin_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->inside_vrf = clib_net_to_host_u32(a->inside_vrf);
    a->outside_vrf = clib_net_to_host_u32(a->outside_vrf);
    a->sessions = clib_net_to_host_u32(a->sessions);
    a->session_memory = clib_net_to_host_u32(a->session_memory);
    /* a->enable = a->enable (no-op) */
    vl_api_nat44_config_flags_t_endian(&a->flags, to_net);
}

static inline void vl_api_nat44_ed_plugin_enable_disable_reply_t_endian (vl_api_nat44_ed_plugin_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_forwarding_enable_disable_t_endian (vl_api_nat44_forwarding_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->enable = a->enable (no-op) */
}

static inline void vl_api_nat44_forwarding_enable_disable_reply_t_endian (vl_api_nat44_forwarding_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat_ipfix_enable_disable_t_endian (vl_api_nat_ipfix_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->domain_id = clib_net_to_host_u32(a->domain_id);
    a->src_port = clib_net_to_host_u16(a->src_port);
    /* a->enable = a->enable (no-op) */
}

static inline void vl_api_nat_ipfix_enable_disable_reply_t_endian (vl_api_nat_ipfix_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat_set_timeouts_t_endian (vl_api_nat_set_timeouts_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->udp = clib_net_to_host_u32(a->udp);
    a->tcp_established = clib_net_to_host_u32(a->tcp_established);
    a->tcp_transitory = clib_net_to_host_u32(a->tcp_transitory);
    a->icmp = clib_net_to_host_u32(a->icmp);
}

static inline void vl_api_nat_set_timeouts_reply_t_endian (vl_api_nat_set_timeouts_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_set_session_limit_t_endian (vl_api_nat44_set_session_limit_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->session_limit = clib_net_to_host_u32(a->session_limit);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
}

static inline void vl_api_nat44_set_session_limit_reply_t_endian (vl_api_nat44_set_session_limit_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_show_running_config_t_endian (vl_api_nat44_show_running_config_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_show_running_config_reply_t_endian (vl_api_nat44_show_running_config_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->inside_vrf = clib_net_to_host_u32(a->inside_vrf);
    a->outside_vrf = clib_net_to_host_u32(a->outside_vrf);
    a->users = clib_net_to_host_u32(a->users);
    a->sessions = clib_net_to_host_u32(a->sessions);
    a->user_sessions = clib_net_to_host_u32(a->user_sessions);
    a->user_buckets = clib_net_to_host_u32(a->user_buckets);
    a->translation_buckets = clib_net_to_host_u32(a->translation_buckets);
    /* a->forwarding_enabled = a->forwarding_enabled (no-op) */
    /* a->ipfix_logging_enabled = a->ipfix_logging_enabled (no-op) */
    vl_api_nat_timeouts_t_endian(&a->timeouts, to_net);
    vl_api_nat_log_level_t_endian(&a->log_level, to_net);
    vl_api_nat44_config_flags_t_endian(&a->flags, to_net);
}

static inline void vl_api_nat_set_workers_t_endian (vl_api_nat_set_workers_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->worker_mask = clib_net_to_host_u64(a->worker_mask);
}

static inline void vl_api_nat_set_workers_reply_t_endian (vl_api_nat_set_workers_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat_worker_dump_t_endian (vl_api_nat_worker_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat_worker_details_t_endian (vl_api_nat_worker_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->worker_index = clib_net_to_host_u32(a->worker_index);
    a->lcore_id = clib_net_to_host_u32(a->lcore_id);
    /* a->name = a->name (no-op) */
}

static inline void vl_api_nat44_ed_add_del_vrf_table_t_endian (vl_api_nat44_ed_add_del_vrf_table_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->table_vrf_id = clib_net_to_host_u32(a->table_vrf_id);
    /* a->is_add = a->is_add (no-op) */
}

static inline void vl_api_nat44_ed_add_del_vrf_table_reply_t_endian (vl_api_nat44_ed_add_del_vrf_table_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ed_add_del_vrf_route_t_endian (vl_api_nat44_ed_add_del_vrf_route_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->table_vrf_id = clib_net_to_host_u32(a->table_vrf_id);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    /* a->is_add = a->is_add (no-op) */
}

static inline void vl_api_nat44_ed_add_del_vrf_route_reply_t_endian (vl_api_nat44_ed_add_del_vrf_route_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ed_vrf_tables_dump_t_endian (vl_api_nat44_ed_vrf_tables_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_ed_vrf_tables_details_t_endian (vl_api_nat44_ed_vrf_tables_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->table_vrf_id = clib_net_to_host_u32(a->table_vrf_id);
    a->n_vrf_ids = clib_net_to_host_u32(a->n_vrf_ids);
    u32 count = to_net ? clib_net_to_host_u32(a->n_vrf_ids) : a->n_vrf_ids;
    ASSERT((u32)count <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < count; i++) {
        a->vrf_ids[i] = clib_net_to_host_u32(a->vrf_ids[i]);
    }
}

static inline void vl_api_nat44_ed_vrf_tables_v2_dump_t_endian (vl_api_nat44_ed_vrf_tables_v2_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_ed_vrf_tables_v2_details_t_endian (vl_api_nat44_ed_vrf_tables_v2_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->table_vrf_id = clib_net_to_host_u32(a->table_vrf_id);
    a->n_vrf_ids = clib_net_to_host_u32(a->n_vrf_ids);
    u32 count = to_net ? clib_net_to_host_u32(a->n_vrf_ids) : a->n_vrf_ids;
    ASSERT((u32)count <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < count; i++) {
        a->vrf_ids[i] = clib_net_to_host_u32(a->vrf_ids[i]);
    }
}

static inline void vl_api_nat_set_mss_clamping_t_endian (vl_api_nat_set_mss_clamping_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->mss_value = clib_net_to_host_u16(a->mss_value);
    /* a->enable = a->enable (no-op) */
}

static inline void vl_api_nat_set_mss_clamping_reply_t_endian (vl_api_nat_set_mss_clamping_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat_get_mss_clamping_t_endian (vl_api_nat_get_mss_clamping_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat_get_mss_clamping_reply_t_endian (vl_api_nat_get_mss_clamping_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->mss_value = clib_net_to_host_u16(a->mss_value);
    /* a->enable = a->enable (no-op) */
}

static inline void vl_api_nat44_ed_set_fq_options_t_endian (vl_api_nat44_ed_set_fq_options_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->frame_queue_nelts = clib_net_to_host_u32(a->frame_queue_nelts);
}

static inline void vl_api_nat44_ed_set_fq_options_reply_t_endian (vl_api_nat44_ed_set_fq_options_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ed_show_fq_options_t_endian (vl_api_nat44_ed_show_fq_options_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_ed_show_fq_options_reply_t_endian (vl_api_nat44_ed_show_fq_options_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->frame_queue_nelts = clib_net_to_host_u32(a->frame_queue_nelts);
}

static inline void vl_api_nat44_add_del_interface_addr_t_endian (vl_api_nat44_add_del_interface_addr_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_nat_config_flags_t_endian(&a->flags, to_net);
}

static inline void vl_api_nat44_add_del_interface_addr_reply_t_endian (vl_api_nat44_add_del_interface_addr_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_interface_addr_dump_t_endian (vl_api_nat44_interface_addr_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_interface_addr_details_t_endian (vl_api_nat44_interface_addr_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_nat_config_flags_t_endian(&a->flags, to_net);
}

static inline void vl_api_nat44_add_del_address_range_t_endian (vl_api_nat44_add_del_address_range_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->first_ip_address, to_net);
    vl_api_ip4_address_t_endian(&a->last_ip_address, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    /* a->is_add = a->is_add (no-op) */
    vl_api_nat_config_flags_t_endian(&a->flags, to_net);
}

static inline void vl_api_nat44_add_del_address_range_reply_t_endian (vl_api_nat44_add_del_address_range_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_address_dump_t_endian (vl_api_nat44_address_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_address_details_t_endian (vl_api_nat44_address_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->ip_address, to_net);
    vl_api_nat_config_flags_t_endian(&a->flags, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
}

static inline void vl_api_nat44_interface_add_del_feature_t_endian (vl_api_nat44_interface_add_del_feature_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_nat_config_flags_t_endian(&a->flags, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_nat44_interface_add_del_feature_reply_t_endian (vl_api_nat44_interface_add_del_feature_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_interface_dump_t_endian (vl_api_nat44_interface_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_interface_details_t_endian (vl_api_nat44_interface_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_nat_config_flags_t_endian(&a->flags, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_nat44_ed_add_del_output_interface_t_endian (vl_api_nat44_ed_add_del_output_interface_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_nat44_ed_add_del_output_interface_reply_t_endian (vl_api_nat44_ed_add_del_output_interface_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ed_output_interface_get_t_endian (vl_api_nat44_ed_output_interface_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_nat44_ed_output_interface_get_reply_t_endian (vl_api_nat44_ed_output_interface_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_nat44_ed_output_interface_details_t_endian (vl_api_nat44_ed_output_interface_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_nat44_add_del_static_mapping_t_endian (vl_api_nat44_add_del_static_mapping_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_nat_config_flags_t_endian(&a->flags, to_net);
    vl_api_ip4_address_t_endian(&a->local_ip_address, to_net);
    vl_api_ip4_address_t_endian(&a->external_ip_address, to_net);
    /* a->protocol = a->protocol (no-op) */
    a->local_port = clib_net_to_host_u16(a->local_port);
    a->external_port = clib_net_to_host_u16(a->external_port);
    vl_api_interface_index_t_endian(&a->external_sw_if_index, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    /* a->tag = a->tag (no-op) */
}

static inline void vl_api_nat44_add_del_static_mapping_reply_t_endian (vl_api_nat44_add_del_static_mapping_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_add_del_static_mapping_v2_t_endian (vl_api_nat44_add_del_static_mapping_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    /* a->match_pool = a->match_pool (no-op) */
    vl_api_nat_config_flags_t_endian(&a->flags, to_net);
    vl_api_ip4_address_t_endian(&a->pool_ip_address, to_net);
    vl_api_ip4_address_t_endian(&a->local_ip_address, to_net);
    vl_api_ip4_address_t_endian(&a->external_ip_address, to_net);
    /* a->protocol = a->protocol (no-op) */
    a->local_port = clib_net_to_host_u16(a->local_port);
    a->external_port = clib_net_to_host_u16(a->external_port);
    vl_api_interface_index_t_endian(&a->external_sw_if_index, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    /* a->tag = a->tag (no-op) */
}

static inline void vl_api_nat44_add_del_static_mapping_v2_reply_t_endian (vl_api_nat44_add_del_static_mapping_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_static_mapping_dump_t_endian (vl_api_nat44_static_mapping_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_static_mapping_details_t_endian (vl_api_nat44_static_mapping_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_nat_config_flags_t_endian(&a->flags, to_net);
    vl_api_ip4_address_t_endian(&a->local_ip_address, to_net);
    vl_api_ip4_address_t_endian(&a->external_ip_address, to_net);
    /* a->protocol = a->protocol (no-op) */
    a->local_port = clib_net_to_host_u16(a->local_port);
    a->external_port = clib_net_to_host_u16(a->external_port);
    vl_api_interface_index_t_endian(&a->external_sw_if_index, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    /* a->tag = a->tag (no-op) */
}

static inline void vl_api_nat44_add_del_identity_mapping_t_endian (vl_api_nat44_add_del_identity_mapping_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_nat_config_flags_t_endian(&a->flags, to_net);
    vl_api_ip4_address_t_endian(&a->ip_address, to_net);
    /* a->protocol = a->protocol (no-op) */
    a->port = clib_net_to_host_u16(a->port);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    /* a->tag = a->tag (no-op) */
}

static inline void vl_api_nat44_add_del_identity_mapping_reply_t_endian (vl_api_nat44_add_del_identity_mapping_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_identity_mapping_dump_t_endian (vl_api_nat44_identity_mapping_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_identity_mapping_details_t_endian (vl_api_nat44_identity_mapping_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_nat_config_flags_t_endian(&a->flags, to_net);
    vl_api_ip4_address_t_endian(&a->ip_address, to_net);
    /* a->protocol = a->protocol (no-op) */
    a->port = clib_net_to_host_u16(a->port);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    /* a->tag = a->tag (no-op) */
}

static inline void vl_api_nat44_add_del_lb_static_mapping_t_endian (vl_api_nat44_add_del_lb_static_mapping_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_nat_config_flags_t_endian(&a->flags, to_net);
    vl_api_ip4_address_t_endian(&a->external_addr, to_net);
    a->external_port = clib_net_to_host_u16(a->external_port);
    /* a->protocol = a->protocol (no-op) */
    a->affinity = clib_net_to_host_u32(a->affinity);
    /* a->tag = a->tag (no-op) */
    a->local_num = clib_net_to_host_u32(a->local_num);
    u32 count = to_net ? clib_net_to_host_u32(a->local_num) : a->local_num;
    for (i = 0; i < count; i++) {
        vl_api_nat44_lb_addr_port_t_endian(&a->locals[i], to_net);
    }
}

static inline void vl_api_nat44_add_del_lb_static_mapping_reply_t_endian (vl_api_nat44_add_del_lb_static_mapping_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_lb_static_mapping_add_del_local_t_endian (vl_api_nat44_lb_static_mapping_add_del_local_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_ip4_address_t_endian(&a->external_addr, to_net);
    a->external_port = clib_net_to_host_u16(a->external_port);
    /* a->protocol = a->protocol (no-op) */
    vl_api_nat44_lb_addr_port_t_endian(&a->local, to_net);
}

static inline void vl_api_nat44_lb_static_mapping_add_del_local_reply_t_endian (vl_api_nat44_lb_static_mapping_add_del_local_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_lb_static_mapping_dump_t_endian (vl_api_nat44_lb_static_mapping_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_lb_static_mapping_details_t_endian (vl_api_nat44_lb_static_mapping_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->external_addr, to_net);
    a->external_port = clib_net_to_host_u16(a->external_port);
    /* a->protocol = a->protocol (no-op) */
    vl_api_nat_config_flags_t_endian(&a->flags, to_net);
    a->affinity = clib_net_to_host_u32(a->affinity);
    /* a->tag = a->tag (no-op) */
    a->local_num = clib_net_to_host_u32(a->local_num);
    u32 count = to_net ? clib_net_to_host_u32(a->local_num) : a->local_num;
    for (i = 0; i < count; i++) {
        vl_api_nat44_lb_addr_port_t_endian(&a->locals[i], to_net);
    }
}

static inline void vl_api_nat44_del_session_t_endian (vl_api_nat44_del_session_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->address, to_net);
    /* a->protocol = a->protocol (no-op) */
    a->port = clib_net_to_host_u16(a->port);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    vl_api_nat_config_flags_t_endian(&a->flags, to_net);
    vl_api_ip4_address_t_endian(&a->ext_host_address, to_net);
    a->ext_host_port = clib_net_to_host_u16(a->ext_host_port);
}

static inline void vl_api_nat44_del_session_reply_t_endian (vl_api_nat44_del_session_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_user_dump_t_endian (vl_api_nat44_user_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_user_details_t_endian (vl_api_nat44_user_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    vl_api_ip4_address_t_endian(&a->ip_address, to_net);
    a->nsessions = clib_net_to_host_u32(a->nsessions);
    a->nstaticsessions = clib_net_to_host_u32(a->nstaticsessions);
}

static inline void vl_api_nat44_user_session_dump_t_endian (vl_api_nat44_user_session_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->ip_address, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
}

static inline void vl_api_nat44_user_session_details_t_endian (vl_api_nat44_user_session_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->outside_ip_address, to_net);
    a->outside_port = clib_net_to_host_u16(a->outside_port);
    vl_api_ip4_address_t_endian(&a->inside_ip_address, to_net);
    a->inside_port = clib_net_to_host_u16(a->inside_port);
    a->protocol = clib_net_to_host_u16(a->protocol);
    vl_api_nat_config_flags_t_endian(&a->flags, to_net);
    a->last_heard = clib_net_to_host_u64(a->last_heard);
    a->total_bytes = clib_net_to_host_u64(a->total_bytes);
    a->total_pkts = clib_net_to_host_u32(a->total_pkts);
    vl_api_ip4_address_t_endian(&a->ext_host_address, to_net);
    a->ext_host_port = clib_net_to_host_u16(a->ext_host_port);
    vl_api_ip4_address_t_endian(&a->ext_host_nat_address, to_net);
    a->ext_host_nat_port = clib_net_to_host_u16(a->ext_host_nat_port);
}

static inline void vl_api_nat44_user_session_v2_dump_t_endian (vl_api_nat44_user_session_v2_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->ip_address, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
}

static inline void vl_api_nat44_user_session_v2_details_t_endian (vl_api_nat44_user_session_v2_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->outside_ip_address, to_net);
    a->outside_port = clib_net_to_host_u16(a->outside_port);
    vl_api_ip4_address_t_endian(&a->inside_ip_address, to_net);
    a->inside_port = clib_net_to_host_u16(a->inside_port);
    a->protocol = clib_net_to_host_u16(a->protocol);
    vl_api_nat_config_flags_t_endian(&a->flags, to_net);
    a->last_heard = clib_net_to_host_u64(a->last_heard);
    a->total_bytes = clib_net_to_host_u64(a->total_bytes);
    a->total_pkts = clib_net_to_host_u32(a->total_pkts);
    vl_api_ip4_address_t_endian(&a->ext_host_address, to_net);
    a->ext_host_port = clib_net_to_host_u16(a->ext_host_port);
    vl_api_ip4_address_t_endian(&a->ext_host_nat_address, to_net);
    a->ext_host_nat_port = clib_net_to_host_u16(a->ext_host_nat_port);
    /* a->is_timed_out = a->is_timed_out (no-op) */
}

static inline void vl_api_nat44_user_session_v3_details_t_endian (vl_api_nat44_user_session_v3_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->outside_ip_address, to_net);
    a->outside_port = clib_net_to_host_u16(a->outside_port);
    vl_api_ip4_address_t_endian(&a->inside_ip_address, to_net);
    a->inside_port = clib_net_to_host_u16(a->inside_port);
    a->protocol = clib_net_to_host_u16(a->protocol);
    vl_api_nat_config_flags_t_endian(&a->flags, to_net);
    a->last_heard = clib_net_to_host_u64(a->last_heard);
    a->time_since_last_heard = clib_net_to_host_u64(a->time_since_last_heard);
    a->total_bytes = clib_net_to_host_u64(a->total_bytes);
    a->total_pkts = clib_net_to_host_u32(a->total_pkts);
    vl_api_ip4_address_t_endian(&a->ext_host_address, to_net);
    a->ext_host_port = clib_net_to_host_u16(a->ext_host_port);
    vl_api_ip4_address_t_endian(&a->ext_host_nat_address, to_net);
    a->ext_host_nat_port = clib_net_to_host_u16(a->ext_host_nat_port);
    /* a->is_timed_out = a->is_timed_out (no-op) */
}

static inline void vl_api_nat44_user_session_v3_dump_t_endian (vl_api_nat44_user_session_v3_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->ip_address, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_nat44_ed_calcsizefun
#define included_nat44_ed_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_config_flags_t_calc_size (vl_api_nat44_config_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_lb_addr_port_t_calc_size (vl_api_nat44_lb_addr_port_t *a)
{
      return sizeof(*a) - sizeof(a->addr) + vl_api_ip4_address_t_calc_size(&a->addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ed_plugin_enable_disable_t_calc_size (vl_api_nat44_ed_plugin_enable_disable_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_nat44_config_flags_t_calc_size(&a->flags);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ed_plugin_enable_disable_reply_t_calc_size (vl_api_nat44_ed_plugin_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_forwarding_enable_disable_t_calc_size (vl_api_nat44_forwarding_enable_disable_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_forwarding_enable_disable_reply_t_calc_size (vl_api_nat44_forwarding_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_ipfix_enable_disable_t_calc_size (vl_api_nat_ipfix_enable_disable_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_ipfix_enable_disable_reply_t_calc_size (vl_api_nat_ipfix_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_set_timeouts_t_calc_size (vl_api_nat_set_timeouts_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_set_timeouts_reply_t_calc_size (vl_api_nat_set_timeouts_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_set_session_limit_t_calc_size (vl_api_nat44_set_session_limit_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_set_session_limit_reply_t_calc_size (vl_api_nat44_set_session_limit_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_show_running_config_t_calc_size (vl_api_nat44_show_running_config_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_show_running_config_reply_t_calc_size (vl_api_nat44_show_running_config_reply_t *a)
{
      return sizeof(*a) - sizeof(a->timeouts) + vl_api_nat_timeouts_t_calc_size(&a->timeouts) - sizeof(a->log_level) + vl_api_nat_log_level_t_calc_size(&a->log_level) - sizeof(a->flags) + vl_api_nat44_config_flags_t_calc_size(&a->flags);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_set_workers_t_calc_size (vl_api_nat_set_workers_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_set_workers_reply_t_calc_size (vl_api_nat_set_workers_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_worker_dump_t_calc_size (vl_api_nat_worker_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_worker_details_t_calc_size (vl_api_nat_worker_details_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ed_add_del_vrf_table_t_calc_size (vl_api_nat44_ed_add_del_vrf_table_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ed_add_del_vrf_table_reply_t_calc_size (vl_api_nat44_ed_add_del_vrf_table_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ed_add_del_vrf_route_t_calc_size (vl_api_nat44_ed_add_del_vrf_route_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ed_add_del_vrf_route_reply_t_calc_size (vl_api_nat44_ed_add_del_vrf_route_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ed_vrf_tables_dump_t_calc_size (vl_api_nat44_ed_vrf_tables_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ed_vrf_tables_details_t_calc_size (vl_api_nat44_ed_vrf_tables_details_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->n_vrf_ids) * sizeof(a->vrf_ids[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ed_vrf_tables_v2_dump_t_calc_size (vl_api_nat44_ed_vrf_tables_v2_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ed_vrf_tables_v2_details_t_calc_size (vl_api_nat44_ed_vrf_tables_v2_details_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->n_vrf_ids) * sizeof(a->vrf_ids[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_set_mss_clamping_t_calc_size (vl_api_nat_set_mss_clamping_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_set_mss_clamping_reply_t_calc_size (vl_api_nat_set_mss_clamping_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_get_mss_clamping_t_calc_size (vl_api_nat_get_mss_clamping_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat_get_mss_clamping_reply_t_calc_size (vl_api_nat_get_mss_clamping_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ed_set_fq_options_t_calc_size (vl_api_nat44_ed_set_fq_options_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ed_set_fq_options_reply_t_calc_size (vl_api_nat44_ed_set_fq_options_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ed_show_fq_options_t_calc_size (vl_api_nat44_ed_show_fq_options_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ed_show_fq_options_reply_t_calc_size (vl_api_nat44_ed_show_fq_options_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_add_del_interface_addr_t_calc_size (vl_api_nat44_add_del_interface_addr_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->flags) + vl_api_nat_config_flags_t_calc_size(&a->flags);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_add_del_interface_addr_reply_t_calc_size (vl_api_nat44_add_del_interface_addr_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_interface_addr_dump_t_calc_size (vl_api_nat44_interface_addr_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_interface_addr_details_t_calc_size (vl_api_nat44_interface_addr_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->flags) + vl_api_nat_config_flags_t_calc_size(&a->flags);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_add_del_address_range_t_calc_size (vl_api_nat44_add_del_address_range_t *a)
{
      return sizeof(*a) - sizeof(a->first_ip_address) + vl_api_ip4_address_t_calc_size(&a->first_ip_address) - sizeof(a->last_ip_address) + vl_api_ip4_address_t_calc_size(&a->last_ip_address) - sizeof(a->flags) + vl_api_nat_config_flags_t_calc_size(&a->flags);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_add_del_address_range_reply_t_calc_size (vl_api_nat44_add_del_address_range_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_address_dump_t_calc_size (vl_api_nat44_address_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_address_details_t_calc_size (vl_api_nat44_address_details_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_ip4_address_t_calc_size(&a->ip_address) - sizeof(a->flags) + vl_api_nat_config_flags_t_calc_size(&a->flags);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_interface_add_del_feature_t_calc_size (vl_api_nat44_interface_add_del_feature_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_nat_config_flags_t_calc_size(&a->flags) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_interface_add_del_feature_reply_t_calc_size (vl_api_nat44_interface_add_del_feature_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_interface_dump_t_calc_size (vl_api_nat44_interface_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_interface_details_t_calc_size (vl_api_nat44_interface_details_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_nat_config_flags_t_calc_size(&a->flags) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ed_add_del_output_interface_t_calc_size (vl_api_nat44_ed_add_del_output_interface_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ed_add_del_output_interface_reply_t_calc_size (vl_api_nat44_ed_add_del_output_interface_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ed_output_interface_get_t_calc_size (vl_api_nat44_ed_output_interface_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ed_output_interface_get_reply_t_calc_size (vl_api_nat44_ed_output_interface_get_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ed_output_interface_details_t_calc_size (vl_api_nat44_ed_output_interface_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_add_del_static_mapping_t_calc_size (vl_api_nat44_add_del_static_mapping_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_nat_config_flags_t_calc_size(&a->flags) - sizeof(a->local_ip_address) + vl_api_ip4_address_t_calc_size(&a->local_ip_address) - sizeof(a->external_ip_address) + vl_api_ip4_address_t_calc_size(&a->external_ip_address) - sizeof(a->external_sw_if_index) + vl_api_interface_index_t_calc_size(&a->external_sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_add_del_static_mapping_reply_t_calc_size (vl_api_nat44_add_del_static_mapping_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_add_del_static_mapping_v2_t_calc_size (vl_api_nat44_add_del_static_mapping_v2_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_nat_config_flags_t_calc_size(&a->flags) - sizeof(a->pool_ip_address) + vl_api_ip4_address_t_calc_size(&a->pool_ip_address) - sizeof(a->local_ip_address) + vl_api_ip4_address_t_calc_size(&a->local_ip_address) - sizeof(a->external_ip_address) + vl_api_ip4_address_t_calc_size(&a->external_ip_address) - sizeof(a->external_sw_if_index) + vl_api_interface_index_t_calc_size(&a->external_sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_add_del_static_mapping_v2_reply_t_calc_size (vl_api_nat44_add_del_static_mapping_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_static_mapping_dump_t_calc_size (vl_api_nat44_static_mapping_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_static_mapping_details_t_calc_size (vl_api_nat44_static_mapping_details_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_nat_config_flags_t_calc_size(&a->flags) - sizeof(a->local_ip_address) + vl_api_ip4_address_t_calc_size(&a->local_ip_address) - sizeof(a->external_ip_address) + vl_api_ip4_address_t_calc_size(&a->external_ip_address) - sizeof(a->external_sw_if_index) + vl_api_interface_index_t_calc_size(&a->external_sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_add_del_identity_mapping_t_calc_size (vl_api_nat44_add_del_identity_mapping_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_nat_config_flags_t_calc_size(&a->flags) - sizeof(a->ip_address) + vl_api_ip4_address_t_calc_size(&a->ip_address) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_add_del_identity_mapping_reply_t_calc_size (vl_api_nat44_add_del_identity_mapping_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_identity_mapping_dump_t_calc_size (vl_api_nat44_identity_mapping_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_identity_mapping_details_t_calc_size (vl_api_nat44_identity_mapping_details_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_nat_config_flags_t_calc_size(&a->flags) - sizeof(a->ip_address) + vl_api_ip4_address_t_calc_size(&a->ip_address) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_add_del_lb_static_mapping_t_calc_size (vl_api_nat44_add_del_lb_static_mapping_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_nat_config_flags_t_calc_size(&a->flags) - sizeof(a->external_addr) + vl_api_ip4_address_t_calc_size(&a->external_addr) + clib_net_to_host_u32(a->local_num) * sizeof(a->locals[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_add_del_lb_static_mapping_reply_t_calc_size (vl_api_nat44_add_del_lb_static_mapping_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_lb_static_mapping_add_del_local_t_calc_size (vl_api_nat44_lb_static_mapping_add_del_local_t *a)
{
      return sizeof(*a) - sizeof(a->external_addr) + vl_api_ip4_address_t_calc_size(&a->external_addr) - sizeof(a->local) + vl_api_nat44_lb_addr_port_t_calc_size(&a->local);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_lb_static_mapping_add_del_local_reply_t_calc_size (vl_api_nat44_lb_static_mapping_add_del_local_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_lb_static_mapping_dump_t_calc_size (vl_api_nat44_lb_static_mapping_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_lb_static_mapping_details_t_calc_size (vl_api_nat44_lb_static_mapping_details_t *a)
{
      return sizeof(*a) - sizeof(a->external_addr) + vl_api_ip4_address_t_calc_size(&a->external_addr) - sizeof(a->flags) + vl_api_nat_config_flags_t_calc_size(&a->flags) + clib_net_to_host_u32(a->local_num) * sizeof(a->locals[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_del_session_t_calc_size (vl_api_nat44_del_session_t *a)
{
      return sizeof(*a) - sizeof(a->address) + vl_api_ip4_address_t_calc_size(&a->address) - sizeof(a->flags) + vl_api_nat_config_flags_t_calc_size(&a->flags) - sizeof(a->ext_host_address) + vl_api_ip4_address_t_calc_size(&a->ext_host_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_del_session_reply_t_calc_size (vl_api_nat44_del_session_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_user_dump_t_calc_size (vl_api_nat44_user_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_user_details_t_calc_size (vl_api_nat44_user_details_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_ip4_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_user_session_dump_t_calc_size (vl_api_nat44_user_session_dump_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_ip4_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_user_session_details_t_calc_size (vl_api_nat44_user_session_details_t *a)
{
      return sizeof(*a) - sizeof(a->outside_ip_address) + vl_api_ip4_address_t_calc_size(&a->outside_ip_address) - sizeof(a->inside_ip_address) + vl_api_ip4_address_t_calc_size(&a->inside_ip_address) - sizeof(a->flags) + vl_api_nat_config_flags_t_calc_size(&a->flags) - sizeof(a->ext_host_address) + vl_api_ip4_address_t_calc_size(&a->ext_host_address) - sizeof(a->ext_host_nat_address) + vl_api_ip4_address_t_calc_size(&a->ext_host_nat_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_user_session_v2_dump_t_calc_size (vl_api_nat44_user_session_v2_dump_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_ip4_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_user_session_v2_details_t_calc_size (vl_api_nat44_user_session_v2_details_t *a)
{
      return sizeof(*a) - sizeof(a->outside_ip_address) + vl_api_ip4_address_t_calc_size(&a->outside_ip_address) - sizeof(a->inside_ip_address) + vl_api_ip4_address_t_calc_size(&a->inside_ip_address) - sizeof(a->flags) + vl_api_nat_config_flags_t_calc_size(&a->flags) - sizeof(a->ext_host_address) + vl_api_ip4_address_t_calc_size(&a->ext_host_address) - sizeof(a->ext_host_nat_address) + vl_api_ip4_address_t_calc_size(&a->ext_host_nat_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_user_session_v3_details_t_calc_size (vl_api_nat44_user_session_v3_details_t *a)
{
      return sizeof(*a) - sizeof(a->outside_ip_address) + vl_api_ip4_address_t_calc_size(&a->outside_ip_address) - sizeof(a->inside_ip_address) + vl_api_ip4_address_t_calc_size(&a->inside_ip_address) - sizeof(a->flags) + vl_api_nat_config_flags_t_calc_size(&a->flags) - sizeof(a->ext_host_address) + vl_api_ip4_address_t_calc_size(&a->ext_host_address) - sizeof(a->ext_host_nat_address) + vl_api_ip4_address_t_calc_size(&a->ext_host_nat_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_user_session_v3_dump_t_calc_size (vl_api_nat44_user_session_v3_dump_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_ip4_address_t_calc_size(&a->ip_address);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(nat44_ed.api, 5, 5, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(nat44_ed.api, 0x8c7fcb7f)

#endif

