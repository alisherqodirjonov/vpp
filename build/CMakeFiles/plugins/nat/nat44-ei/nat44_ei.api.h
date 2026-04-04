/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: nat44_ei.api
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
#warning no content included from nat44_ei.api
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
vl_msg_id(VL_API_NAT44_EI_PLUGIN_ENABLE_DISABLE, vl_api_nat44_ei_plugin_enable_disable_t_handler)
vl_msg_id(VL_API_NAT44_EI_PLUGIN_ENABLE_DISABLE_REPLY, vl_api_nat44_ei_plugin_enable_disable_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_SHOW_RUNNING_CONFIG, vl_api_nat44_ei_show_running_config_t_handler)
vl_msg_id(VL_API_NAT44_EI_SHOW_RUNNING_CONFIG_REPLY, vl_api_nat44_ei_show_running_config_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_SET_LOG_LEVEL, vl_api_nat44_ei_set_log_level_t_handler)
vl_msg_id(VL_API_NAT44_EI_SET_LOG_LEVEL_REPLY, vl_api_nat44_ei_set_log_level_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_SET_WORKERS, vl_api_nat44_ei_set_workers_t_handler)
vl_msg_id(VL_API_NAT44_EI_SET_WORKERS_REPLY, vl_api_nat44_ei_set_workers_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_WORKER_DUMP, vl_api_nat44_ei_worker_dump_t_handler)
vl_msg_id(VL_API_NAT44_EI_WORKER_DETAILS, vl_api_nat44_ei_worker_details_t_handler)
vl_msg_id(VL_API_NAT44_EI_IPFIX_ENABLE_DISABLE, vl_api_nat44_ei_ipfix_enable_disable_t_handler)
vl_msg_id(VL_API_NAT44_EI_IPFIX_ENABLE_DISABLE_REPLY, vl_api_nat44_ei_ipfix_enable_disable_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_SET_TIMEOUTS, vl_api_nat44_ei_set_timeouts_t_handler)
vl_msg_id(VL_API_NAT44_EI_SET_TIMEOUTS_REPLY, vl_api_nat44_ei_set_timeouts_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_SET_ADDR_AND_PORT_ALLOC_ALG, vl_api_nat44_ei_set_addr_and_port_alloc_alg_t_handler)
vl_msg_id(VL_API_NAT44_EI_SET_ADDR_AND_PORT_ALLOC_ALG_REPLY, vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_GET_ADDR_AND_PORT_ALLOC_ALG, vl_api_nat44_ei_get_addr_and_port_alloc_alg_t_handler)
vl_msg_id(VL_API_NAT44_EI_GET_ADDR_AND_PORT_ALLOC_ALG_REPLY, vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_SET_MSS_CLAMPING, vl_api_nat44_ei_set_mss_clamping_t_handler)
vl_msg_id(VL_API_NAT44_EI_SET_MSS_CLAMPING_REPLY, vl_api_nat44_ei_set_mss_clamping_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_GET_MSS_CLAMPING, vl_api_nat44_ei_get_mss_clamping_t_handler)
vl_msg_id(VL_API_NAT44_EI_GET_MSS_CLAMPING_REPLY, vl_api_nat44_ei_get_mss_clamping_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_HA_SET_LISTENER, vl_api_nat44_ei_ha_set_listener_t_handler)
vl_msg_id(VL_API_NAT44_EI_HA_SET_LISTENER_REPLY, vl_api_nat44_ei_ha_set_listener_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_HA_SET_FAILOVER, vl_api_nat44_ei_ha_set_failover_t_handler)
vl_msg_id(VL_API_NAT44_EI_HA_SET_FAILOVER_REPLY, vl_api_nat44_ei_ha_set_failover_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_HA_GET_LISTENER, vl_api_nat44_ei_ha_get_listener_t_handler)
vl_msg_id(VL_API_NAT44_EI_HA_GET_LISTENER_REPLY, vl_api_nat44_ei_ha_get_listener_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_HA_GET_FAILOVER, vl_api_nat44_ei_ha_get_failover_t_handler)
vl_msg_id(VL_API_NAT44_EI_HA_GET_FAILOVER_REPLY, vl_api_nat44_ei_ha_get_failover_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_HA_FLUSH, vl_api_nat44_ei_ha_flush_t_handler)
vl_msg_id(VL_API_NAT44_EI_HA_FLUSH_REPLY, vl_api_nat44_ei_ha_flush_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_HA_RESYNC, vl_api_nat44_ei_ha_resync_t_handler)
vl_msg_id(VL_API_NAT44_EI_HA_RESYNC_REPLY, vl_api_nat44_ei_ha_resync_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_HA_RESYNC_COMPLETED_EVENT, vl_api_nat44_ei_ha_resync_completed_event_t_handler)
vl_msg_id(VL_API_NAT44_EI_DEL_USER, vl_api_nat44_ei_del_user_t_handler)
vl_msg_id(VL_API_NAT44_EI_DEL_USER_REPLY, vl_api_nat44_ei_del_user_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_ADD_DEL_ADDRESS_RANGE, vl_api_nat44_ei_add_del_address_range_t_handler)
vl_msg_id(VL_API_NAT44_EI_ADD_DEL_ADDRESS_RANGE_REPLY, vl_api_nat44_ei_add_del_address_range_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_ADDRESS_DUMP, vl_api_nat44_ei_address_dump_t_handler)
vl_msg_id(VL_API_NAT44_EI_ADDRESS_DETAILS, vl_api_nat44_ei_address_details_t_handler)
vl_msg_id(VL_API_NAT44_EI_INTERFACE_ADD_DEL_FEATURE, vl_api_nat44_ei_interface_add_del_feature_t_handler)
vl_msg_id(VL_API_NAT44_EI_INTERFACE_ADD_DEL_FEATURE_REPLY, vl_api_nat44_ei_interface_add_del_feature_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_INTERFACE_DUMP, vl_api_nat44_ei_interface_dump_t_handler)
vl_msg_id(VL_API_NAT44_EI_INTERFACE_DETAILS, vl_api_nat44_ei_interface_details_t_handler)
vl_msg_id(VL_API_NAT44_EI_INTERFACE_ADD_DEL_OUTPUT_FEATURE, vl_api_nat44_ei_interface_add_del_output_feature_t_handler)
vl_msg_id(VL_API_NAT44_EI_INTERFACE_ADD_DEL_OUTPUT_FEATURE_REPLY, vl_api_nat44_ei_interface_add_del_output_feature_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_INTERFACE_OUTPUT_FEATURE_DUMP, vl_api_nat44_ei_interface_output_feature_dump_t_handler)
vl_msg_id(VL_API_NAT44_EI_INTERFACE_OUTPUT_FEATURE_DETAILS, vl_api_nat44_ei_interface_output_feature_details_t_handler)
vl_msg_id(VL_API_NAT44_EI_ADD_DEL_OUTPUT_INTERFACE, vl_api_nat44_ei_add_del_output_interface_t_handler)
vl_msg_id(VL_API_NAT44_EI_ADD_DEL_OUTPUT_INTERFACE_REPLY, vl_api_nat44_ei_add_del_output_interface_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_OUTPUT_INTERFACE_GET, vl_api_nat44_ei_output_interface_get_t_handler)
vl_msg_id(VL_API_NAT44_EI_OUTPUT_INTERFACE_GET_REPLY, vl_api_nat44_ei_output_interface_get_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_OUTPUT_INTERFACE_DETAILS, vl_api_nat44_ei_output_interface_details_t_handler)
vl_msg_id(VL_API_NAT44_EI_ADD_DEL_STATIC_MAPPING, vl_api_nat44_ei_add_del_static_mapping_t_handler)
vl_msg_id(VL_API_NAT44_EI_ADD_DEL_STATIC_MAPPING_REPLY, vl_api_nat44_ei_add_del_static_mapping_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_STATIC_MAPPING_DUMP, vl_api_nat44_ei_static_mapping_dump_t_handler)
vl_msg_id(VL_API_NAT44_EI_STATIC_MAPPING_DETAILS, vl_api_nat44_ei_static_mapping_details_t_handler)
vl_msg_id(VL_API_NAT44_EI_ADD_DEL_IDENTITY_MAPPING, vl_api_nat44_ei_add_del_identity_mapping_t_handler)
vl_msg_id(VL_API_NAT44_EI_ADD_DEL_IDENTITY_MAPPING_REPLY, vl_api_nat44_ei_add_del_identity_mapping_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_IDENTITY_MAPPING_DUMP, vl_api_nat44_ei_identity_mapping_dump_t_handler)
vl_msg_id(VL_API_NAT44_EI_IDENTITY_MAPPING_DETAILS, vl_api_nat44_ei_identity_mapping_details_t_handler)
vl_msg_id(VL_API_NAT44_EI_ADD_DEL_INTERFACE_ADDR, vl_api_nat44_ei_add_del_interface_addr_t_handler)
vl_msg_id(VL_API_NAT44_EI_ADD_DEL_INTERFACE_ADDR_REPLY, vl_api_nat44_ei_add_del_interface_addr_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_INTERFACE_ADDR_DUMP, vl_api_nat44_ei_interface_addr_dump_t_handler)
vl_msg_id(VL_API_NAT44_EI_INTERFACE_ADDR_DETAILS, vl_api_nat44_ei_interface_addr_details_t_handler)
vl_msg_id(VL_API_NAT44_EI_USER_DUMP, vl_api_nat44_ei_user_dump_t_handler)
vl_msg_id(VL_API_NAT44_EI_USER_DETAILS, vl_api_nat44_ei_user_details_t_handler)
vl_msg_id(VL_API_NAT44_EI_USER_SESSION_DUMP, vl_api_nat44_ei_user_session_dump_t_handler)
vl_msg_id(VL_API_NAT44_EI_USER_SESSION_DETAILS, vl_api_nat44_ei_user_session_details_t_handler)
vl_msg_id(VL_API_NAT44_EI_USER_SESSION_V2_DUMP, vl_api_nat44_ei_user_session_v2_dump_t_handler)
vl_msg_id(VL_API_NAT44_EI_USER_SESSION_V2_DETAILS, vl_api_nat44_ei_user_session_v2_details_t_handler)
vl_msg_id(VL_API_NAT44_EI_DEL_SESSION, vl_api_nat44_ei_del_session_t_handler)
vl_msg_id(VL_API_NAT44_EI_DEL_SESSION_REPLY, vl_api_nat44_ei_del_session_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_FORWARDING_ENABLE_DISABLE, vl_api_nat44_ei_forwarding_enable_disable_t_handler)
vl_msg_id(VL_API_NAT44_EI_FORWARDING_ENABLE_DISABLE_REPLY, vl_api_nat44_ei_forwarding_enable_disable_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_SET_FQ_OPTIONS, vl_api_nat44_ei_set_fq_options_t_handler)
vl_msg_id(VL_API_NAT44_EI_SET_FQ_OPTIONS_REPLY, vl_api_nat44_ei_set_fq_options_reply_t_handler)
vl_msg_id(VL_API_NAT44_EI_SHOW_FQ_OPTIONS, vl_api_nat44_ei_show_fq_options_t_handler)
vl_msg_id(VL_API_NAT44_EI_SHOW_FQ_OPTIONS_REPLY, vl_api_nat44_ei_show_fq_options_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_nat44_ei_plugin_enable_disable_t, 1)
vl_msg_name(vl_api_nat44_ei_plugin_enable_disable_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_show_running_config_t, 1)
vl_msg_name(vl_api_nat44_ei_show_running_config_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_set_log_level_t, 1)
vl_msg_name(vl_api_nat44_ei_set_log_level_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_set_workers_t, 1)
vl_msg_name(vl_api_nat44_ei_set_workers_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_worker_dump_t, 1)
vl_msg_name(vl_api_nat44_ei_worker_details_t, 1)
vl_msg_name(vl_api_nat44_ei_ipfix_enable_disable_t, 1)
vl_msg_name(vl_api_nat44_ei_ipfix_enable_disable_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_set_timeouts_t, 1)
vl_msg_name(vl_api_nat44_ei_set_timeouts_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_set_addr_and_port_alloc_alg_t, 1)
vl_msg_name(vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_get_addr_and_port_alloc_alg_t, 1)
vl_msg_name(vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_set_mss_clamping_t, 1)
vl_msg_name(vl_api_nat44_ei_set_mss_clamping_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_get_mss_clamping_t, 1)
vl_msg_name(vl_api_nat44_ei_get_mss_clamping_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_ha_set_listener_t, 1)
vl_msg_name(vl_api_nat44_ei_ha_set_listener_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_ha_set_failover_t, 1)
vl_msg_name(vl_api_nat44_ei_ha_set_failover_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_ha_get_listener_t, 1)
vl_msg_name(vl_api_nat44_ei_ha_get_listener_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_ha_get_failover_t, 1)
vl_msg_name(vl_api_nat44_ei_ha_get_failover_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_ha_flush_t, 1)
vl_msg_name(vl_api_nat44_ei_ha_flush_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_ha_resync_t, 1)
vl_msg_name(vl_api_nat44_ei_ha_resync_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_ha_resync_completed_event_t, 1)
vl_msg_name(vl_api_nat44_ei_del_user_t, 1)
vl_msg_name(vl_api_nat44_ei_del_user_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_add_del_address_range_t, 1)
vl_msg_name(vl_api_nat44_ei_add_del_address_range_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_address_dump_t, 1)
vl_msg_name(vl_api_nat44_ei_address_details_t, 1)
vl_msg_name(vl_api_nat44_ei_interface_add_del_feature_t, 1)
vl_msg_name(vl_api_nat44_ei_interface_add_del_feature_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_interface_dump_t, 1)
vl_msg_name(vl_api_nat44_ei_interface_details_t, 1)
vl_msg_name(vl_api_nat44_ei_interface_add_del_output_feature_t, 1)
vl_msg_name(vl_api_nat44_ei_interface_add_del_output_feature_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_interface_output_feature_dump_t, 1)
vl_msg_name(vl_api_nat44_ei_interface_output_feature_details_t, 1)
vl_msg_name(vl_api_nat44_ei_add_del_output_interface_t, 1)
vl_msg_name(vl_api_nat44_ei_add_del_output_interface_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_output_interface_get_t, 1)
vl_msg_name(vl_api_nat44_ei_output_interface_get_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_output_interface_details_t, 1)
vl_msg_name(vl_api_nat44_ei_add_del_static_mapping_t, 1)
vl_msg_name(vl_api_nat44_ei_add_del_static_mapping_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_static_mapping_dump_t, 1)
vl_msg_name(vl_api_nat44_ei_static_mapping_details_t, 1)
vl_msg_name(vl_api_nat44_ei_add_del_identity_mapping_t, 1)
vl_msg_name(vl_api_nat44_ei_add_del_identity_mapping_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_identity_mapping_dump_t, 1)
vl_msg_name(vl_api_nat44_ei_identity_mapping_details_t, 1)
vl_msg_name(vl_api_nat44_ei_add_del_interface_addr_t, 1)
vl_msg_name(vl_api_nat44_ei_add_del_interface_addr_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_interface_addr_dump_t, 1)
vl_msg_name(vl_api_nat44_ei_interface_addr_details_t, 1)
vl_msg_name(vl_api_nat44_ei_user_dump_t, 1)
vl_msg_name(vl_api_nat44_ei_user_details_t, 1)
vl_msg_name(vl_api_nat44_ei_user_session_dump_t, 1)
vl_msg_name(vl_api_nat44_ei_user_session_details_t, 1)
vl_msg_name(vl_api_nat44_ei_user_session_v2_dump_t, 1)
vl_msg_name(vl_api_nat44_ei_user_session_v2_details_t, 1)
vl_msg_name(vl_api_nat44_ei_del_session_t, 1)
vl_msg_name(vl_api_nat44_ei_del_session_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_forwarding_enable_disable_t, 1)
vl_msg_name(vl_api_nat44_ei_forwarding_enable_disable_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_set_fq_options_t, 1)
vl_msg_name(vl_api_nat44_ei_set_fq_options_reply_t, 1)
vl_msg_name(vl_api_nat44_ei_show_fq_options_t, 1)
vl_msg_name(vl_api_nat44_ei_show_fq_options_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_nat44_ei \
_(VL_API_NAT44_EI_PLUGIN_ENABLE_DISABLE, nat44_ei_plugin_enable_disable, bf692144) \
_(VL_API_NAT44_EI_PLUGIN_ENABLE_DISABLE_REPLY, nat44_ei_plugin_enable_disable_reply, e8d4e804) \
_(VL_API_NAT44_EI_SHOW_RUNNING_CONFIG, nat44_ei_show_running_config, 51077d14) \
_(VL_API_NAT44_EI_SHOW_RUNNING_CONFIG_REPLY, nat44_ei_show_running_config_reply, 41b66a81) \
_(VL_API_NAT44_EI_SET_LOG_LEVEL, nat44_ei_set_log_level, 70076bfe) \
_(VL_API_NAT44_EI_SET_LOG_LEVEL_REPLY, nat44_ei_set_log_level_reply, e8d4e804) \
_(VL_API_NAT44_EI_SET_WORKERS, nat44_ei_set_workers, da926638) \
_(VL_API_NAT44_EI_SET_WORKERS_REPLY, nat44_ei_set_workers_reply, e8d4e804) \
_(VL_API_NAT44_EI_WORKER_DUMP, nat44_ei_worker_dump, 51077d14) \
_(VL_API_NAT44_EI_WORKER_DETAILS, nat44_ei_worker_details, 84bf06fc) \
_(VL_API_NAT44_EI_IPFIX_ENABLE_DISABLE, nat44_ei_ipfix_enable_disable, 9af4a2d2) \
_(VL_API_NAT44_EI_IPFIX_ENABLE_DISABLE_REPLY, nat44_ei_ipfix_enable_disable_reply, e8d4e804) \
_(VL_API_NAT44_EI_SET_TIMEOUTS, nat44_ei_set_timeouts, d4746b16) \
_(VL_API_NAT44_EI_SET_TIMEOUTS_REPLY, nat44_ei_set_timeouts_reply, e8d4e804) \
_(VL_API_NAT44_EI_SET_ADDR_AND_PORT_ALLOC_ALG, nat44_ei_set_addr_and_port_alloc_alg, deeb746f) \
_(VL_API_NAT44_EI_SET_ADDR_AND_PORT_ALLOC_ALG_REPLY, nat44_ei_set_addr_and_port_alloc_alg_reply, e8d4e804) \
_(VL_API_NAT44_EI_GET_ADDR_AND_PORT_ALLOC_ALG, nat44_ei_get_addr_and_port_alloc_alg, 51077d14) \
_(VL_API_NAT44_EI_GET_ADDR_AND_PORT_ALLOC_ALG_REPLY, nat44_ei_get_addr_and_port_alloc_alg_reply, 3607a7d0) \
_(VL_API_NAT44_EI_SET_MSS_CLAMPING, nat44_ei_set_mss_clamping, 25e90abb) \
_(VL_API_NAT44_EI_SET_MSS_CLAMPING_REPLY, nat44_ei_set_mss_clamping_reply, e8d4e804) \
_(VL_API_NAT44_EI_GET_MSS_CLAMPING, nat44_ei_get_mss_clamping, 51077d14) \
_(VL_API_NAT44_EI_GET_MSS_CLAMPING_REPLY, nat44_ei_get_mss_clamping_reply, 1c0b2a78) \
_(VL_API_NAT44_EI_HA_SET_LISTENER, nat44_ei_ha_set_listener, e4a8cb4e) \
_(VL_API_NAT44_EI_HA_SET_LISTENER_REPLY, nat44_ei_ha_set_listener_reply, e8d4e804) \
_(VL_API_NAT44_EI_HA_SET_FAILOVER, nat44_ei_ha_set_failover, 718246af) \
_(VL_API_NAT44_EI_HA_SET_FAILOVER_REPLY, nat44_ei_ha_set_failover_reply, e8d4e804) \
_(VL_API_NAT44_EI_HA_GET_LISTENER, nat44_ei_ha_get_listener, 51077d14) \
_(VL_API_NAT44_EI_HA_GET_LISTENER_REPLY, nat44_ei_ha_get_listener_reply, 123ea41f) \
_(VL_API_NAT44_EI_HA_GET_FAILOVER, nat44_ei_ha_get_failover, 51077d14) \
_(VL_API_NAT44_EI_HA_GET_FAILOVER_REPLY, nat44_ei_ha_get_failover_reply, a67d8752) \
_(VL_API_NAT44_EI_HA_FLUSH, nat44_ei_ha_flush, 51077d14) \
_(VL_API_NAT44_EI_HA_FLUSH_REPLY, nat44_ei_ha_flush_reply, e8d4e804) \
_(VL_API_NAT44_EI_HA_RESYNC, nat44_ei_ha_resync, c8ab9e03) \
_(VL_API_NAT44_EI_HA_RESYNC_REPLY, nat44_ei_ha_resync_reply, e8d4e804) \
_(VL_API_NAT44_EI_HA_RESYNC_COMPLETED_EVENT, nat44_ei_ha_resync_completed_event, fdc598fb) \
_(VL_API_NAT44_EI_DEL_USER, nat44_ei_del_user, 99a9f998) \
_(VL_API_NAT44_EI_DEL_USER_REPLY, nat44_ei_del_user_reply, e8d4e804) \
_(VL_API_NAT44_EI_ADD_DEL_ADDRESS_RANGE, nat44_ei_add_del_address_range, 35f21abc) \
_(VL_API_NAT44_EI_ADD_DEL_ADDRESS_RANGE_REPLY, nat44_ei_add_del_address_range_reply, e8d4e804) \
_(VL_API_NAT44_EI_ADDRESS_DUMP, nat44_ei_address_dump, 51077d14) \
_(VL_API_NAT44_EI_ADDRESS_DETAILS, nat44_ei_address_details, 318f1202) \
_(VL_API_NAT44_EI_INTERFACE_ADD_DEL_FEATURE, nat44_ei_interface_add_del_feature, 63a2db8b) \
_(VL_API_NAT44_EI_INTERFACE_ADD_DEL_FEATURE_REPLY, nat44_ei_interface_add_del_feature_reply, e8d4e804) \
_(VL_API_NAT44_EI_INTERFACE_DUMP, nat44_ei_interface_dump, 51077d14) \
_(VL_API_NAT44_EI_INTERFACE_DETAILS, nat44_ei_interface_details, f446e508) \
_(VL_API_NAT44_EI_INTERFACE_ADD_DEL_OUTPUT_FEATURE, nat44_ei_interface_add_del_output_feature, 63a2db8b) \
_(VL_API_NAT44_EI_INTERFACE_ADD_DEL_OUTPUT_FEATURE_REPLY, nat44_ei_interface_add_del_output_feature_reply, e8d4e804) \
_(VL_API_NAT44_EI_INTERFACE_OUTPUT_FEATURE_DUMP, nat44_ei_interface_output_feature_dump, 51077d14) \
_(VL_API_NAT44_EI_INTERFACE_OUTPUT_FEATURE_DETAILS, nat44_ei_interface_output_feature_details, f446e508) \
_(VL_API_NAT44_EI_ADD_DEL_OUTPUT_INTERFACE, nat44_ei_add_del_output_interface, 47d6e753) \
_(VL_API_NAT44_EI_ADD_DEL_OUTPUT_INTERFACE_REPLY, nat44_ei_add_del_output_interface_reply, e8d4e804) \
_(VL_API_NAT44_EI_OUTPUT_INTERFACE_GET, nat44_ei_output_interface_get, f75ba505) \
_(VL_API_NAT44_EI_OUTPUT_INTERFACE_GET_REPLY, nat44_ei_output_interface_get_reply, 53b48f5d) \
_(VL_API_NAT44_EI_OUTPUT_INTERFACE_DETAILS, nat44_ei_output_interface_details, 0b45011c) \
_(VL_API_NAT44_EI_ADD_DEL_STATIC_MAPPING, nat44_ei_add_del_static_mapping, b404b7fe) \
_(VL_API_NAT44_EI_ADD_DEL_STATIC_MAPPING_REPLY, nat44_ei_add_del_static_mapping_reply, e8d4e804) \
_(VL_API_NAT44_EI_STATIC_MAPPING_DUMP, nat44_ei_static_mapping_dump, 51077d14) \
_(VL_API_NAT44_EI_STATIC_MAPPING_DETAILS, nat44_ei_static_mapping_details, 6b51ca6e) \
_(VL_API_NAT44_EI_ADD_DEL_IDENTITY_MAPPING, nat44_ei_add_del_identity_mapping, cb8606b9) \
_(VL_API_NAT44_EI_ADD_DEL_IDENTITY_MAPPING_REPLY, nat44_ei_add_del_identity_mapping_reply, e8d4e804) \
_(VL_API_NAT44_EI_IDENTITY_MAPPING_DUMP, nat44_ei_identity_mapping_dump, 51077d14) \
_(VL_API_NAT44_EI_IDENTITY_MAPPING_DETAILS, nat44_ei_identity_mapping_details, 30d53e26) \
_(VL_API_NAT44_EI_ADD_DEL_INTERFACE_ADDR, nat44_ei_add_del_interface_addr, 883abbcc) \
_(VL_API_NAT44_EI_ADD_DEL_INTERFACE_ADDR_REPLY, nat44_ei_add_del_interface_addr_reply, e8d4e804) \
_(VL_API_NAT44_EI_INTERFACE_ADDR_DUMP, nat44_ei_interface_addr_dump, 51077d14) \
_(VL_API_NAT44_EI_INTERFACE_ADDR_DETAILS, nat44_ei_interface_addr_details, 0b45011c) \
_(VL_API_NAT44_EI_USER_DUMP, nat44_ei_user_dump, 51077d14) \
_(VL_API_NAT44_EI_USER_DETAILS, nat44_ei_user_details, 355896c2) \
_(VL_API_NAT44_EI_USER_SESSION_DUMP, nat44_ei_user_session_dump, e1899c98) \
_(VL_API_NAT44_EI_USER_SESSION_DETAILS, nat44_ei_user_session_details, 19b7c0ac) \
_(VL_API_NAT44_EI_USER_SESSION_V2_DUMP, nat44_ei_user_session_v2_dump, e1899c98) \
_(VL_API_NAT44_EI_USER_SESSION_V2_DETAILS, nat44_ei_user_session_v2_details, 5bd3e9d6) \
_(VL_API_NAT44_EI_DEL_SESSION, nat44_ei_del_session, 74969ffe) \
_(VL_API_NAT44_EI_DEL_SESSION_REPLY, nat44_ei_del_session_reply, e8d4e804) \
_(VL_API_NAT44_EI_FORWARDING_ENABLE_DISABLE, nat44_ei_forwarding_enable_disable, b3e225d2) \
_(VL_API_NAT44_EI_FORWARDING_ENABLE_DISABLE_REPLY, nat44_ei_forwarding_enable_disable_reply, e8d4e804) \
_(VL_API_NAT44_EI_SET_FQ_OPTIONS, nat44_ei_set_fq_options, 2399bd71) \
_(VL_API_NAT44_EI_SET_FQ_OPTIONS_REPLY, nat44_ei_set_fq_options_reply, e8d4e804) \
_(VL_API_NAT44_EI_SHOW_FQ_OPTIONS, nat44_ei_show_fq_options, 51077d14) \
_(VL_API_NAT44_EI_SHOW_FQ_OPTIONS_REPLY, nat44_ei_show_fq_options_reply, 7213b545) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "nat44_ei.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_nat44_ei_printfun_types
#define included_nat44_ei_printfun_types

static inline u8 *format_vl_api_nat44_ei_config_flags_t (u8 *s, va_list * args)
{
    vl_api_nat44_ei_config_flags_t *a = va_arg (*args, vl_api_nat44_ei_config_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "NAT44_EI_NONE");
    case 1:
        return format(s, "NAT44_EI_STATIC_MAPPING_ONLY");
    case 2:
        return format(s, "NAT44_EI_CONNECTION_TRACKING");
    case 4:
        return format(s, "NAT44_EI_OUT2IN_DPO");
    case 8:
        return format(s, "NAT44_EI_ADDR_ONLY_MAPPING");
    case 16:
        return format(s, "NAT44_EI_IF_INSIDE");
    case 32:
        return format(s, "NAT44_EI_IF_OUTSIDE");
    case 64:
        return format(s, "NAT44_EI_STATIC_MAPPING");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_nat44_ei_printfun
#define included_nat44_ei_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "nat44_ei.api_tojson.h"
#include "nat44_ei.api_fromjson.h"

static inline u8 *vl_api_nat44_ei_plugin_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_plugin_enable_disable_t *a = va_arg (*args, vl_api_nat44_ei_plugin_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_plugin_enable_disable_t: */
    s = format(s, "vl_api_nat44_ei_plugin_enable_disable_t:");
    s = format(s, "\n%Uinside_vrf: %u", format_white_space, indent, a->inside_vrf);
    s = format(s, "\n%Uoutside_vrf: %u", format_white_space, indent, a->outside_vrf);
    s = format(s, "\n%Uusers: %u", format_white_space, indent, a->users);
    s = format(s, "\n%Uuser_memory: %u", format_white_space, indent, a->user_memory);
    s = format(s, "\n%Usessions: %u", format_white_space, indent, a->sessions);
    s = format(s, "\n%Usession_memory: %u", format_white_space, indent, a->session_memory);
    s = format(s, "\n%Uuser_sessions: %u", format_white_space, indent, a->user_sessions);
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat44_ei_config_flags_t, &a->flags, indent);
    return s;
}

static inline u8 *vl_api_nat44_ei_plugin_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_plugin_enable_disable_reply_t *a = va_arg (*args, vl_api_nat44_ei_plugin_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_plugin_enable_disable_reply_t: */
    s = format(s, "vl_api_nat44_ei_plugin_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_show_running_config_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_show_running_config_t *a = va_arg (*args, vl_api_nat44_ei_show_running_config_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_show_running_config_t: */
    s = format(s, "vl_api_nat44_ei_show_running_config_t:");
    return s;
}

static inline u8 *vl_api_nat44_ei_show_running_config_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_show_running_config_reply_t *a = va_arg (*args, vl_api_nat44_ei_show_running_config_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_show_running_config_reply_t: */
    s = format(s, "vl_api_nat44_ei_show_running_config_reply_t:");
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
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat44_ei_config_flags_t, &a->flags, indent);
    return s;
}

static inline u8 *vl_api_nat44_ei_set_log_level_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_set_log_level_t *a = va_arg (*args, vl_api_nat44_ei_set_log_level_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_set_log_level_t: */
    s = format(s, "vl_api_nat44_ei_set_log_level_t:");
    s = format(s, "\n%Ulog_level: %U", format_white_space, indent, format_vl_api_nat_log_level_t, &a->log_level, indent);
    return s;
}

static inline u8 *vl_api_nat44_ei_set_log_level_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_set_log_level_reply_t *a = va_arg (*args, vl_api_nat44_ei_set_log_level_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_set_log_level_reply_t: */
    s = format(s, "vl_api_nat44_ei_set_log_level_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_set_workers_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_set_workers_t *a = va_arg (*args, vl_api_nat44_ei_set_workers_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_set_workers_t: */
    s = format(s, "vl_api_nat44_ei_set_workers_t:");
    s = format(s, "\n%Uworker_mask: %llu", format_white_space, indent, a->worker_mask);
    return s;
}

static inline u8 *vl_api_nat44_ei_set_workers_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_set_workers_reply_t *a = va_arg (*args, vl_api_nat44_ei_set_workers_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_set_workers_reply_t: */
    s = format(s, "vl_api_nat44_ei_set_workers_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_worker_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_worker_dump_t *a = va_arg (*args, vl_api_nat44_ei_worker_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_worker_dump_t: */
    s = format(s, "vl_api_nat44_ei_worker_dump_t:");
    return s;
}

static inline u8 *vl_api_nat44_ei_worker_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_worker_details_t *a = va_arg (*args, vl_api_nat44_ei_worker_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_worker_details_t: */
    s = format(s, "vl_api_nat44_ei_worker_details_t:");
    s = format(s, "\n%Uworker_index: %u", format_white_space, indent, a->worker_index);
    s = format(s, "\n%Ulcore_id: %u", format_white_space, indent, a->lcore_id);
    s = format(s, "\n%Uname: %s", format_white_space, indent, a->name);
    return s;
}

static inline u8 *vl_api_nat44_ei_ipfix_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_ipfix_enable_disable_t *a = va_arg (*args, vl_api_nat44_ei_ipfix_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_ipfix_enable_disable_t: */
    s = format(s, "vl_api_nat44_ei_ipfix_enable_disable_t:");
    s = format(s, "\n%Udomain_id: %u", format_white_space, indent, a->domain_id);
    s = format(s, "\n%Usrc_port: %u", format_white_space, indent, a->src_port);
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}

static inline u8 *vl_api_nat44_ei_ipfix_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_ipfix_enable_disable_reply_t *a = va_arg (*args, vl_api_nat44_ei_ipfix_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_ipfix_enable_disable_reply_t: */
    s = format(s, "vl_api_nat44_ei_ipfix_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_set_timeouts_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_set_timeouts_t *a = va_arg (*args, vl_api_nat44_ei_set_timeouts_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_set_timeouts_t: */
    s = format(s, "vl_api_nat44_ei_set_timeouts_t:");
    s = format(s, "\n%Uudp: %u", format_white_space, indent, a->udp);
    s = format(s, "\n%Utcp_established: %u", format_white_space, indent, a->tcp_established);
    s = format(s, "\n%Utcp_transitory: %u", format_white_space, indent, a->tcp_transitory);
    s = format(s, "\n%Uicmp: %u", format_white_space, indent, a->icmp);
    return s;
}

static inline u8 *vl_api_nat44_ei_set_timeouts_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_set_timeouts_reply_t *a = va_arg (*args, vl_api_nat44_ei_set_timeouts_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_set_timeouts_reply_t: */
    s = format(s, "vl_api_nat44_ei_set_timeouts_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_set_addr_and_port_alloc_alg_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_set_addr_and_port_alloc_alg_t *a = va_arg (*args, vl_api_nat44_ei_set_addr_and_port_alloc_alg_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_set_addr_and_port_alloc_alg_t: */
    s = format(s, "vl_api_nat44_ei_set_addr_and_port_alloc_alg_t:");
    s = format(s, "\n%Ualg: %u", format_white_space, indent, a->alg);
    s = format(s, "\n%Upsid_offset: %u", format_white_space, indent, a->psid_offset);
    s = format(s, "\n%Upsid_length: %u", format_white_space, indent, a->psid_length);
    s = format(s, "\n%Upsid: %u", format_white_space, indent, a->psid);
    s = format(s, "\n%Ustart_port: %u", format_white_space, indent, a->start_port);
    s = format(s, "\n%Uend_port: %u", format_white_space, indent, a->end_port);
    return s;
}

static inline u8 *vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t *a = va_arg (*args, vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t: */
    s = format(s, "vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_get_addr_and_port_alloc_alg_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_get_addr_and_port_alloc_alg_t *a = va_arg (*args, vl_api_nat44_ei_get_addr_and_port_alloc_alg_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_get_addr_and_port_alloc_alg_t: */
    s = format(s, "vl_api_nat44_ei_get_addr_and_port_alloc_alg_t:");
    return s;
}

static inline u8 *vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t *a = va_arg (*args, vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t: */
    s = format(s, "vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ualg: %u", format_white_space, indent, a->alg);
    s = format(s, "\n%Upsid_offset: %u", format_white_space, indent, a->psid_offset);
    s = format(s, "\n%Upsid_length: %u", format_white_space, indent, a->psid_length);
    s = format(s, "\n%Upsid: %u", format_white_space, indent, a->psid);
    s = format(s, "\n%Ustart_port: %u", format_white_space, indent, a->start_port);
    s = format(s, "\n%Uend_port: %u", format_white_space, indent, a->end_port);
    return s;
}

static inline u8 *vl_api_nat44_ei_set_mss_clamping_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_set_mss_clamping_t *a = va_arg (*args, vl_api_nat44_ei_set_mss_clamping_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_set_mss_clamping_t: */
    s = format(s, "vl_api_nat44_ei_set_mss_clamping_t:");
    s = format(s, "\n%Umss_value: %u", format_white_space, indent, a->mss_value);
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}

static inline u8 *vl_api_nat44_ei_set_mss_clamping_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_set_mss_clamping_reply_t *a = va_arg (*args, vl_api_nat44_ei_set_mss_clamping_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_set_mss_clamping_reply_t: */
    s = format(s, "vl_api_nat44_ei_set_mss_clamping_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_get_mss_clamping_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_get_mss_clamping_t *a = va_arg (*args, vl_api_nat44_ei_get_mss_clamping_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_get_mss_clamping_t: */
    s = format(s, "vl_api_nat44_ei_get_mss_clamping_t:");
    return s;
}

static inline u8 *vl_api_nat44_ei_get_mss_clamping_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_get_mss_clamping_reply_t *a = va_arg (*args, vl_api_nat44_ei_get_mss_clamping_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_get_mss_clamping_reply_t: */
    s = format(s, "vl_api_nat44_ei_get_mss_clamping_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Umss_value: %u", format_white_space, indent, a->mss_value);
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}

static inline u8 *vl_api_nat44_ei_ha_set_listener_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_ha_set_listener_t *a = va_arg (*args, vl_api_nat44_ei_ha_set_listener_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_ha_set_listener_t: */
    s = format(s, "vl_api_nat44_ei_ha_set_listener_t:");
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip_address, indent);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    s = format(s, "\n%Upath_mtu: %u", format_white_space, indent, a->path_mtu);
    return s;
}

static inline u8 *vl_api_nat44_ei_ha_set_listener_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_ha_set_listener_reply_t *a = va_arg (*args, vl_api_nat44_ei_ha_set_listener_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_ha_set_listener_reply_t: */
    s = format(s, "vl_api_nat44_ei_ha_set_listener_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_ha_set_failover_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_ha_set_failover_t *a = va_arg (*args, vl_api_nat44_ei_ha_set_failover_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_ha_set_failover_t: */
    s = format(s, "vl_api_nat44_ei_ha_set_failover_t:");
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip_address, indent);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    s = format(s, "\n%Usession_refresh_interval: %u", format_white_space, indent, a->session_refresh_interval);
    return s;
}

static inline u8 *vl_api_nat44_ei_ha_set_failover_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_ha_set_failover_reply_t *a = va_arg (*args, vl_api_nat44_ei_ha_set_failover_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_ha_set_failover_reply_t: */
    s = format(s, "vl_api_nat44_ei_ha_set_failover_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_ha_get_listener_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_ha_get_listener_t *a = va_arg (*args, vl_api_nat44_ei_ha_get_listener_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_ha_get_listener_t: */
    s = format(s, "vl_api_nat44_ei_ha_get_listener_t:");
    return s;
}

static inline u8 *vl_api_nat44_ei_ha_get_listener_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_ha_get_listener_reply_t *a = va_arg (*args, vl_api_nat44_ei_ha_get_listener_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_ha_get_listener_reply_t: */
    s = format(s, "vl_api_nat44_ei_ha_get_listener_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip_address, indent);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    s = format(s, "\n%Upath_mtu: %u", format_white_space, indent, a->path_mtu);
    return s;
}

static inline u8 *vl_api_nat44_ei_ha_get_failover_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_ha_get_failover_t *a = va_arg (*args, vl_api_nat44_ei_ha_get_failover_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_ha_get_failover_t: */
    s = format(s, "vl_api_nat44_ei_ha_get_failover_t:");
    return s;
}

static inline u8 *vl_api_nat44_ei_ha_get_failover_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_ha_get_failover_reply_t *a = va_arg (*args, vl_api_nat44_ei_ha_get_failover_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_ha_get_failover_reply_t: */
    s = format(s, "vl_api_nat44_ei_ha_get_failover_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip_address, indent);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    s = format(s, "\n%Usession_refresh_interval: %u", format_white_space, indent, a->session_refresh_interval);
    return s;
}

static inline u8 *vl_api_nat44_ei_ha_flush_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_ha_flush_t *a = va_arg (*args, vl_api_nat44_ei_ha_flush_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_ha_flush_t: */
    s = format(s, "vl_api_nat44_ei_ha_flush_t:");
    return s;
}

static inline u8 *vl_api_nat44_ei_ha_flush_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_ha_flush_reply_t *a = va_arg (*args, vl_api_nat44_ei_ha_flush_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_ha_flush_reply_t: */
    s = format(s, "vl_api_nat44_ei_ha_flush_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_ha_resync_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_ha_resync_t *a = va_arg (*args, vl_api_nat44_ei_ha_resync_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_ha_resync_t: */
    s = format(s, "vl_api_nat44_ei_ha_resync_t:");
    s = format(s, "\n%Uwant_resync_event: %u", format_white_space, indent, a->want_resync_event);
    s = format(s, "\n%Upid: %u", format_white_space, indent, a->pid);
    return s;
}

static inline u8 *vl_api_nat44_ei_ha_resync_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_ha_resync_reply_t *a = va_arg (*args, vl_api_nat44_ei_ha_resync_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_ha_resync_reply_t: */
    s = format(s, "vl_api_nat44_ei_ha_resync_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_ha_resync_completed_event_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_ha_resync_completed_event_t *a = va_arg (*args, vl_api_nat44_ei_ha_resync_completed_event_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_ha_resync_completed_event_t: */
    s = format(s, "vl_api_nat44_ei_ha_resync_completed_event_t:");
    s = format(s, "\n%Upid: %u", format_white_space, indent, a->pid);
    s = format(s, "\n%Umissed_count: %u", format_white_space, indent, a->missed_count);
    return s;
}

static inline u8 *vl_api_nat44_ei_del_user_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_del_user_t *a = va_arg (*args, vl_api_nat44_ei_del_user_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_del_user_t: */
    s = format(s, "vl_api_nat44_ei_del_user_t:");
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip_address, indent);
    s = format(s, "\n%Ufib_index: %u", format_white_space, indent, a->fib_index);
    return s;
}

static inline u8 *vl_api_nat44_ei_del_user_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_del_user_reply_t *a = va_arg (*args, vl_api_nat44_ei_del_user_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_del_user_reply_t: */
    s = format(s, "vl_api_nat44_ei_del_user_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_add_del_address_range_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_add_del_address_range_t *a = va_arg (*args, vl_api_nat44_ei_add_del_address_range_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_add_del_address_range_t: */
    s = format(s, "vl_api_nat44_ei_add_del_address_range_t:");
    s = format(s, "\n%Ufirst_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->first_ip_address, indent);
    s = format(s, "\n%Ulast_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->last_ip_address, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    return s;
}

static inline u8 *vl_api_nat44_ei_add_del_address_range_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_add_del_address_range_reply_t *a = va_arg (*args, vl_api_nat44_ei_add_del_address_range_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_add_del_address_range_reply_t: */
    s = format(s, "vl_api_nat44_ei_add_del_address_range_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_address_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_address_dump_t *a = va_arg (*args, vl_api_nat44_ei_address_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_address_dump_t: */
    s = format(s, "vl_api_nat44_ei_address_dump_t:");
    return s;
}

static inline u8 *vl_api_nat44_ei_address_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_address_details_t *a = va_arg (*args, vl_api_nat44_ei_address_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_address_details_t: */
    s = format(s, "vl_api_nat44_ei_address_details_t:");
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip_address, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    return s;
}

static inline u8 *vl_api_nat44_ei_interface_add_del_feature_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_interface_add_del_feature_t *a = va_arg (*args, vl_api_nat44_ei_interface_add_del_feature_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_interface_add_del_feature_t: */
    s = format(s, "vl_api_nat44_ei_interface_add_del_feature_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat44_ei_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_nat44_ei_interface_add_del_feature_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_interface_add_del_feature_reply_t *a = va_arg (*args, vl_api_nat44_ei_interface_add_del_feature_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_interface_add_del_feature_reply_t: */
    s = format(s, "vl_api_nat44_ei_interface_add_del_feature_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_interface_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_interface_dump_t *a = va_arg (*args, vl_api_nat44_ei_interface_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_interface_dump_t: */
    s = format(s, "vl_api_nat44_ei_interface_dump_t:");
    return s;
}

static inline u8 *vl_api_nat44_ei_interface_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_interface_details_t *a = va_arg (*args, vl_api_nat44_ei_interface_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_interface_details_t: */
    s = format(s, "vl_api_nat44_ei_interface_details_t:");
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat44_ei_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_nat44_ei_interface_add_del_output_feature_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_interface_add_del_output_feature_t *a = va_arg (*args, vl_api_nat44_ei_interface_add_del_output_feature_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_interface_add_del_output_feature_t: */
    s = format(s, "vl_api_nat44_ei_interface_add_del_output_feature_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat44_ei_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_nat44_ei_interface_add_del_output_feature_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_interface_add_del_output_feature_reply_t *a = va_arg (*args, vl_api_nat44_ei_interface_add_del_output_feature_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_interface_add_del_output_feature_reply_t: */
    s = format(s, "vl_api_nat44_ei_interface_add_del_output_feature_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_interface_output_feature_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_interface_output_feature_dump_t *a = va_arg (*args, vl_api_nat44_ei_interface_output_feature_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_interface_output_feature_dump_t: */
    s = format(s, "vl_api_nat44_ei_interface_output_feature_dump_t:");
    return s;
}

static inline u8 *vl_api_nat44_ei_interface_output_feature_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_interface_output_feature_details_t *a = va_arg (*args, vl_api_nat44_ei_interface_output_feature_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_interface_output_feature_details_t: */
    s = format(s, "vl_api_nat44_ei_interface_output_feature_details_t:");
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat44_ei_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_nat44_ei_add_del_output_interface_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_add_del_output_interface_t *a = va_arg (*args, vl_api_nat44_ei_add_del_output_interface_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_add_del_output_interface_t: */
    s = format(s, "vl_api_nat44_ei_add_del_output_interface_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_nat44_ei_add_del_output_interface_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_add_del_output_interface_reply_t *a = va_arg (*args, vl_api_nat44_ei_add_del_output_interface_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_add_del_output_interface_reply_t: */
    s = format(s, "vl_api_nat44_ei_add_del_output_interface_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_output_interface_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_output_interface_get_t *a = va_arg (*args, vl_api_nat44_ei_output_interface_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_output_interface_get_t: */
    s = format(s, "vl_api_nat44_ei_output_interface_get_t:");
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_nat44_ei_output_interface_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_output_interface_get_reply_t *a = va_arg (*args, vl_api_nat44_ei_output_interface_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_output_interface_get_reply_t: */
    s = format(s, "vl_api_nat44_ei_output_interface_get_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_nat44_ei_output_interface_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_output_interface_details_t *a = va_arg (*args, vl_api_nat44_ei_output_interface_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_output_interface_details_t: */
    s = format(s, "vl_api_nat44_ei_output_interface_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_nat44_ei_add_del_static_mapping_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_add_del_static_mapping_t *a = va_arg (*args, vl_api_nat44_ei_add_del_static_mapping_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_add_del_static_mapping_t: */
    s = format(s, "vl_api_nat44_ei_add_del_static_mapping_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat44_ei_config_flags_t, &a->flags, indent);
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

static inline u8 *vl_api_nat44_ei_add_del_static_mapping_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_add_del_static_mapping_reply_t *a = va_arg (*args, vl_api_nat44_ei_add_del_static_mapping_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_add_del_static_mapping_reply_t: */
    s = format(s, "vl_api_nat44_ei_add_del_static_mapping_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_static_mapping_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_static_mapping_dump_t *a = va_arg (*args, vl_api_nat44_ei_static_mapping_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_static_mapping_dump_t: */
    s = format(s, "vl_api_nat44_ei_static_mapping_dump_t:");
    return s;
}

static inline u8 *vl_api_nat44_ei_static_mapping_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_static_mapping_details_t *a = va_arg (*args, vl_api_nat44_ei_static_mapping_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_static_mapping_details_t: */
    s = format(s, "vl_api_nat44_ei_static_mapping_details_t:");
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat44_ei_config_flags_t, &a->flags, indent);
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

static inline u8 *vl_api_nat44_ei_add_del_identity_mapping_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_add_del_identity_mapping_t *a = va_arg (*args, vl_api_nat44_ei_add_del_identity_mapping_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_add_del_identity_mapping_t: */
    s = format(s, "vl_api_nat44_ei_add_del_identity_mapping_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat44_ei_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip_address, indent);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    return s;
}

static inline u8 *vl_api_nat44_ei_add_del_identity_mapping_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_add_del_identity_mapping_reply_t *a = va_arg (*args, vl_api_nat44_ei_add_del_identity_mapping_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_add_del_identity_mapping_reply_t: */
    s = format(s, "vl_api_nat44_ei_add_del_identity_mapping_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_identity_mapping_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_identity_mapping_dump_t *a = va_arg (*args, vl_api_nat44_ei_identity_mapping_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_identity_mapping_dump_t: */
    s = format(s, "vl_api_nat44_ei_identity_mapping_dump_t:");
    return s;
}

static inline u8 *vl_api_nat44_ei_identity_mapping_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_identity_mapping_details_t *a = va_arg (*args, vl_api_nat44_ei_identity_mapping_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_identity_mapping_details_t: */
    s = format(s, "vl_api_nat44_ei_identity_mapping_details_t:");
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat44_ei_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip_address, indent);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    return s;
}

static inline u8 *vl_api_nat44_ei_add_del_interface_addr_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_add_del_interface_addr_t *a = va_arg (*args, vl_api_nat44_ei_add_del_interface_addr_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_add_del_interface_addr_t: */
    s = format(s, "vl_api_nat44_ei_add_del_interface_addr_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat44_ei_config_flags_t, &a->flags, indent);
    return s;
}

static inline u8 *vl_api_nat44_ei_add_del_interface_addr_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_add_del_interface_addr_reply_t *a = va_arg (*args, vl_api_nat44_ei_add_del_interface_addr_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_add_del_interface_addr_reply_t: */
    s = format(s, "vl_api_nat44_ei_add_del_interface_addr_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_interface_addr_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_interface_addr_dump_t *a = va_arg (*args, vl_api_nat44_ei_interface_addr_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_interface_addr_dump_t: */
    s = format(s, "vl_api_nat44_ei_interface_addr_dump_t:");
    return s;
}

static inline u8 *vl_api_nat44_ei_interface_addr_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_interface_addr_details_t *a = va_arg (*args, vl_api_nat44_ei_interface_addr_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_interface_addr_details_t: */
    s = format(s, "vl_api_nat44_ei_interface_addr_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_nat44_ei_user_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_user_dump_t *a = va_arg (*args, vl_api_nat44_ei_user_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_user_dump_t: */
    s = format(s, "vl_api_nat44_ei_user_dump_t:");
    return s;
}

static inline u8 *vl_api_nat44_ei_user_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_user_details_t *a = va_arg (*args, vl_api_nat44_ei_user_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_user_details_t: */
    s = format(s, "vl_api_nat44_ei_user_details_t:");
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip_address, indent);
    s = format(s, "\n%Unsessions: %u", format_white_space, indent, a->nsessions);
    s = format(s, "\n%Unstaticsessions: %u", format_white_space, indent, a->nstaticsessions);
    return s;
}

static inline u8 *vl_api_nat44_ei_user_session_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_user_session_dump_t *a = va_arg (*args, vl_api_nat44_ei_user_session_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_user_session_dump_t: */
    s = format(s, "vl_api_nat44_ei_user_session_dump_t:");
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip_address, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    return s;
}

static inline u8 *vl_api_nat44_ei_user_session_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_user_session_details_t *a = va_arg (*args, vl_api_nat44_ei_user_session_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_user_session_details_t: */
    s = format(s, "vl_api_nat44_ei_user_session_details_t:");
    s = format(s, "\n%Uoutside_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->outside_ip_address, indent);
    s = format(s, "\n%Uoutside_port: %u", format_white_space, indent, a->outside_port);
    s = format(s, "\n%Uinside_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->inside_ip_address, indent);
    s = format(s, "\n%Uinside_port: %u", format_white_space, indent, a->inside_port);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat44_ei_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Ulast_heard: %llu", format_white_space, indent, a->last_heard);
    s = format(s, "\n%Utotal_bytes: %llu", format_white_space, indent, a->total_bytes);
    s = format(s, "\n%Utotal_pkts: %u", format_white_space, indent, a->total_pkts);
    s = format(s, "\n%Uext_host_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ext_host_address, indent);
    s = format(s, "\n%Uext_host_port: %u", format_white_space, indent, a->ext_host_port);
    return s;
}

static inline u8 *vl_api_nat44_ei_user_session_v2_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_user_session_v2_dump_t *a = va_arg (*args, vl_api_nat44_ei_user_session_v2_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_user_session_v2_dump_t: */
    s = format(s, "vl_api_nat44_ei_user_session_v2_dump_t:");
    s = format(s, "\n%Uip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ip_address, indent);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    return s;
}

static inline u8 *vl_api_nat44_ei_user_session_v2_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_user_session_v2_details_t *a = va_arg (*args, vl_api_nat44_ei_user_session_v2_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_user_session_v2_details_t: */
    s = format(s, "vl_api_nat44_ei_user_session_v2_details_t:");
    s = format(s, "\n%Uoutside_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->outside_ip_address, indent);
    s = format(s, "\n%Uoutside_port: %u", format_white_space, indent, a->outside_port);
    s = format(s, "\n%Uinside_ip_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->inside_ip_address, indent);
    s = format(s, "\n%Uinside_port: %u", format_white_space, indent, a->inside_port);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat44_ei_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Ulast_heard: %llu", format_white_space, indent, a->last_heard);
    s = format(s, "\n%Utime_since_last_heard: %llu", format_white_space, indent, a->time_since_last_heard);
    s = format(s, "\n%Utotal_bytes: %llu", format_white_space, indent, a->total_bytes);
    s = format(s, "\n%Utotal_pkts: %u", format_white_space, indent, a->total_pkts);
    s = format(s, "\n%Uext_host_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ext_host_address, indent);
    s = format(s, "\n%Uext_host_port: %u", format_white_space, indent, a->ext_host_port);
    return s;
}

static inline u8 *vl_api_nat44_ei_del_session_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_del_session_t *a = va_arg (*args, vl_api_nat44_ei_del_session_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_del_session_t: */
    s = format(s, "vl_api_nat44_ei_del_session_t:");
    s = format(s, "\n%Uaddress: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->address, indent);
    s = format(s, "\n%Uprotocol: %u", format_white_space, indent, a->protocol);
    s = format(s, "\n%Uport: %u", format_white_space, indent, a->port);
    s = format(s, "\n%Uvrf_id: %u", format_white_space, indent, a->vrf_id);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_nat44_ei_config_flags_t, &a->flags, indent);
    s = format(s, "\n%Uext_host_address: %U", format_white_space, indent, format_vl_api_ip4_address_t, &a->ext_host_address, indent);
    s = format(s, "\n%Uext_host_port: %u", format_white_space, indent, a->ext_host_port);
    return s;
}

static inline u8 *vl_api_nat44_ei_del_session_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_del_session_reply_t *a = va_arg (*args, vl_api_nat44_ei_del_session_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_del_session_reply_t: */
    s = format(s, "vl_api_nat44_ei_del_session_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_forwarding_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_forwarding_enable_disable_t *a = va_arg (*args, vl_api_nat44_ei_forwarding_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_forwarding_enable_disable_t: */
    s = format(s, "vl_api_nat44_ei_forwarding_enable_disable_t:");
    s = format(s, "\n%Uenable: %u", format_white_space, indent, a->enable);
    return s;
}

static inline u8 *vl_api_nat44_ei_forwarding_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_forwarding_enable_disable_reply_t *a = va_arg (*args, vl_api_nat44_ei_forwarding_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_forwarding_enable_disable_reply_t: */
    s = format(s, "vl_api_nat44_ei_forwarding_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_set_fq_options_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_set_fq_options_t *a = va_arg (*args, vl_api_nat44_ei_set_fq_options_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_set_fq_options_t: */
    s = format(s, "vl_api_nat44_ei_set_fq_options_t:");
    s = format(s, "\n%Uframe_queue_nelts: %u", format_white_space, indent, a->frame_queue_nelts);
    return s;
}

static inline u8 *vl_api_nat44_ei_set_fq_options_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_set_fq_options_reply_t *a = va_arg (*args, vl_api_nat44_ei_set_fq_options_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_set_fq_options_reply_t: */
    s = format(s, "vl_api_nat44_ei_set_fq_options_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_nat44_ei_show_fq_options_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_show_fq_options_t *a = va_arg (*args, vl_api_nat44_ei_show_fq_options_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_show_fq_options_t: */
    s = format(s, "vl_api_nat44_ei_show_fq_options_t:");
    return s;
}

static inline u8 *vl_api_nat44_ei_show_fq_options_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nat44_ei_show_fq_options_reply_t *a = va_arg (*args, vl_api_nat44_ei_show_fq_options_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nat44_ei_show_fq_options_reply_t: */
    s = format(s, "vl_api_nat44_ei_show_fq_options_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uframe_queue_nelts: %u", format_white_space, indent, a->frame_queue_nelts);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_nat44_ei_endianfun
#define included_nat44_ei_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_nat44_ei_config_flags_t_endian (vl_api_nat44_ei_config_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->nat44_ei_config_flags = a->nat44_ei_config_flags (no-op) */
}

static inline void vl_api_nat44_ei_plugin_enable_disable_t_endian (vl_api_nat44_ei_plugin_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->inside_vrf = clib_net_to_host_u32(a->inside_vrf);
    a->outside_vrf = clib_net_to_host_u32(a->outside_vrf);
    a->users = clib_net_to_host_u32(a->users);
    a->user_memory = clib_net_to_host_u32(a->user_memory);
    a->sessions = clib_net_to_host_u32(a->sessions);
    a->session_memory = clib_net_to_host_u32(a->session_memory);
    a->user_sessions = clib_net_to_host_u32(a->user_sessions);
    /* a->enable = a->enable (no-op) */
    vl_api_nat44_ei_config_flags_t_endian(&a->flags, to_net);
}

static inline void vl_api_nat44_ei_plugin_enable_disable_reply_t_endian (vl_api_nat44_ei_plugin_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_show_running_config_t_endian (vl_api_nat44_ei_show_running_config_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_ei_show_running_config_reply_t_endian (vl_api_nat44_ei_show_running_config_reply_t *a, bool to_net)
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
    vl_api_nat44_ei_config_flags_t_endian(&a->flags, to_net);
}

static inline void vl_api_nat44_ei_set_log_level_t_endian (vl_api_nat44_ei_set_log_level_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_nat_log_level_t_endian(&a->log_level, to_net);
}

static inline void vl_api_nat44_ei_set_log_level_reply_t_endian (vl_api_nat44_ei_set_log_level_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_set_workers_t_endian (vl_api_nat44_ei_set_workers_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->worker_mask = clib_net_to_host_u64(a->worker_mask);
}

static inline void vl_api_nat44_ei_set_workers_reply_t_endian (vl_api_nat44_ei_set_workers_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_worker_dump_t_endian (vl_api_nat44_ei_worker_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_ei_worker_details_t_endian (vl_api_nat44_ei_worker_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->worker_index = clib_net_to_host_u32(a->worker_index);
    a->lcore_id = clib_net_to_host_u32(a->lcore_id);
    /* a->name = a->name (no-op) */
}

static inline void vl_api_nat44_ei_ipfix_enable_disable_t_endian (vl_api_nat44_ei_ipfix_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->domain_id = clib_net_to_host_u32(a->domain_id);
    a->src_port = clib_net_to_host_u16(a->src_port);
    /* a->enable = a->enable (no-op) */
}

static inline void vl_api_nat44_ei_ipfix_enable_disable_reply_t_endian (vl_api_nat44_ei_ipfix_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_set_timeouts_t_endian (vl_api_nat44_ei_set_timeouts_t *a, bool to_net)
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

static inline void vl_api_nat44_ei_set_timeouts_reply_t_endian (vl_api_nat44_ei_set_timeouts_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_set_addr_and_port_alloc_alg_t_endian (vl_api_nat44_ei_set_addr_and_port_alloc_alg_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->alg = a->alg (no-op) */
    /* a->psid_offset = a->psid_offset (no-op) */
    /* a->psid_length = a->psid_length (no-op) */
    a->psid = clib_net_to_host_u16(a->psid);
    a->start_port = clib_net_to_host_u16(a->start_port);
    a->end_port = clib_net_to_host_u16(a->end_port);
}

static inline void vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t_endian (vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_get_addr_and_port_alloc_alg_t_endian (vl_api_nat44_ei_get_addr_and_port_alloc_alg_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t_endian (vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->alg = a->alg (no-op) */
    /* a->psid_offset = a->psid_offset (no-op) */
    /* a->psid_length = a->psid_length (no-op) */
    a->psid = clib_net_to_host_u16(a->psid);
    a->start_port = clib_net_to_host_u16(a->start_port);
    a->end_port = clib_net_to_host_u16(a->end_port);
}

static inline void vl_api_nat44_ei_set_mss_clamping_t_endian (vl_api_nat44_ei_set_mss_clamping_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->mss_value = clib_net_to_host_u16(a->mss_value);
    /* a->enable = a->enable (no-op) */
}

static inline void vl_api_nat44_ei_set_mss_clamping_reply_t_endian (vl_api_nat44_ei_set_mss_clamping_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_get_mss_clamping_t_endian (vl_api_nat44_ei_get_mss_clamping_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_ei_get_mss_clamping_reply_t_endian (vl_api_nat44_ei_get_mss_clamping_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->mss_value = clib_net_to_host_u16(a->mss_value);
    /* a->enable = a->enable (no-op) */
}

static inline void vl_api_nat44_ei_ha_set_listener_t_endian (vl_api_nat44_ei_ha_set_listener_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->ip_address, to_net);
    a->port = clib_net_to_host_u16(a->port);
    a->path_mtu = clib_net_to_host_u32(a->path_mtu);
}

static inline void vl_api_nat44_ei_ha_set_listener_reply_t_endian (vl_api_nat44_ei_ha_set_listener_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_ha_set_failover_t_endian (vl_api_nat44_ei_ha_set_failover_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->ip_address, to_net);
    a->port = clib_net_to_host_u16(a->port);
    a->session_refresh_interval = clib_net_to_host_u32(a->session_refresh_interval);
}

static inline void vl_api_nat44_ei_ha_set_failover_reply_t_endian (vl_api_nat44_ei_ha_set_failover_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_ha_get_listener_t_endian (vl_api_nat44_ei_ha_get_listener_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_ei_ha_get_listener_reply_t_endian (vl_api_nat44_ei_ha_get_listener_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_ip4_address_t_endian(&a->ip_address, to_net);
    a->port = clib_net_to_host_u16(a->port);
    a->path_mtu = clib_net_to_host_u32(a->path_mtu);
}

static inline void vl_api_nat44_ei_ha_get_failover_t_endian (vl_api_nat44_ei_ha_get_failover_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_ei_ha_get_failover_reply_t_endian (vl_api_nat44_ei_ha_get_failover_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_ip4_address_t_endian(&a->ip_address, to_net);
    a->port = clib_net_to_host_u16(a->port);
    a->session_refresh_interval = clib_net_to_host_u32(a->session_refresh_interval);
}

static inline void vl_api_nat44_ei_ha_flush_t_endian (vl_api_nat44_ei_ha_flush_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_ei_ha_flush_reply_t_endian (vl_api_nat44_ei_ha_flush_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_ha_resync_t_endian (vl_api_nat44_ei_ha_resync_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->want_resync_event = a->want_resync_event (no-op) */
    a->pid = clib_net_to_host_u32(a->pid);
}

static inline void vl_api_nat44_ei_ha_resync_reply_t_endian (vl_api_nat44_ei_ha_resync_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_ha_resync_completed_event_t_endian (vl_api_nat44_ei_ha_resync_completed_event_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->pid = clib_net_to_host_u32(a->pid);
    a->missed_count = clib_net_to_host_u32(a->missed_count);
}

static inline void vl_api_nat44_ei_del_user_t_endian (vl_api_nat44_ei_del_user_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->ip_address, to_net);
    a->fib_index = clib_net_to_host_u32(a->fib_index);
}

static inline void vl_api_nat44_ei_del_user_reply_t_endian (vl_api_nat44_ei_del_user_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_add_del_address_range_t_endian (vl_api_nat44_ei_add_del_address_range_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->first_ip_address, to_net);
    vl_api_ip4_address_t_endian(&a->last_ip_address, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    /* a->is_add = a->is_add (no-op) */
}

static inline void vl_api_nat44_ei_add_del_address_range_reply_t_endian (vl_api_nat44_ei_add_del_address_range_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_address_dump_t_endian (vl_api_nat44_ei_address_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_ei_address_details_t_endian (vl_api_nat44_ei_address_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->ip_address, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
}

static inline void vl_api_nat44_ei_interface_add_del_feature_t_endian (vl_api_nat44_ei_interface_add_del_feature_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_nat44_ei_config_flags_t_endian(&a->flags, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_nat44_ei_interface_add_del_feature_reply_t_endian (vl_api_nat44_ei_interface_add_del_feature_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_interface_dump_t_endian (vl_api_nat44_ei_interface_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_ei_interface_details_t_endian (vl_api_nat44_ei_interface_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_nat44_ei_config_flags_t_endian(&a->flags, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_nat44_ei_interface_add_del_output_feature_t_endian (vl_api_nat44_ei_interface_add_del_output_feature_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_nat44_ei_config_flags_t_endian(&a->flags, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_nat44_ei_interface_add_del_output_feature_reply_t_endian (vl_api_nat44_ei_interface_add_del_output_feature_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_interface_output_feature_dump_t_endian (vl_api_nat44_ei_interface_output_feature_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_ei_interface_output_feature_details_t_endian (vl_api_nat44_ei_interface_output_feature_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_nat44_ei_config_flags_t_endian(&a->flags, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_nat44_ei_add_del_output_interface_t_endian (vl_api_nat44_ei_add_del_output_interface_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_nat44_ei_add_del_output_interface_reply_t_endian (vl_api_nat44_ei_add_del_output_interface_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_output_interface_get_t_endian (vl_api_nat44_ei_output_interface_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_nat44_ei_output_interface_get_reply_t_endian (vl_api_nat44_ei_output_interface_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_nat44_ei_output_interface_details_t_endian (vl_api_nat44_ei_output_interface_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_nat44_ei_add_del_static_mapping_t_endian (vl_api_nat44_ei_add_del_static_mapping_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_nat44_ei_config_flags_t_endian(&a->flags, to_net);
    vl_api_ip4_address_t_endian(&a->local_ip_address, to_net);
    vl_api_ip4_address_t_endian(&a->external_ip_address, to_net);
    /* a->protocol = a->protocol (no-op) */
    a->local_port = clib_net_to_host_u16(a->local_port);
    a->external_port = clib_net_to_host_u16(a->external_port);
    vl_api_interface_index_t_endian(&a->external_sw_if_index, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    /* a->tag = a->tag (no-op) */
}

static inline void vl_api_nat44_ei_add_del_static_mapping_reply_t_endian (vl_api_nat44_ei_add_del_static_mapping_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_static_mapping_dump_t_endian (vl_api_nat44_ei_static_mapping_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_ei_static_mapping_details_t_endian (vl_api_nat44_ei_static_mapping_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_nat44_ei_config_flags_t_endian(&a->flags, to_net);
    vl_api_ip4_address_t_endian(&a->local_ip_address, to_net);
    vl_api_ip4_address_t_endian(&a->external_ip_address, to_net);
    /* a->protocol = a->protocol (no-op) */
    a->local_port = clib_net_to_host_u16(a->local_port);
    a->external_port = clib_net_to_host_u16(a->external_port);
    vl_api_interface_index_t_endian(&a->external_sw_if_index, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    /* a->tag = a->tag (no-op) */
}

static inline void vl_api_nat44_ei_add_del_identity_mapping_t_endian (vl_api_nat44_ei_add_del_identity_mapping_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_nat44_ei_config_flags_t_endian(&a->flags, to_net);
    vl_api_ip4_address_t_endian(&a->ip_address, to_net);
    /* a->protocol = a->protocol (no-op) */
    a->port = clib_net_to_host_u16(a->port);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    /* a->tag = a->tag (no-op) */
}

static inline void vl_api_nat44_ei_add_del_identity_mapping_reply_t_endian (vl_api_nat44_ei_add_del_identity_mapping_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_identity_mapping_dump_t_endian (vl_api_nat44_ei_identity_mapping_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_ei_identity_mapping_details_t_endian (vl_api_nat44_ei_identity_mapping_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_nat44_ei_config_flags_t_endian(&a->flags, to_net);
    vl_api_ip4_address_t_endian(&a->ip_address, to_net);
    /* a->protocol = a->protocol (no-op) */
    a->port = clib_net_to_host_u16(a->port);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    /* a->tag = a->tag (no-op) */
}

static inline void vl_api_nat44_ei_add_del_interface_addr_t_endian (vl_api_nat44_ei_add_del_interface_addr_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_nat44_ei_config_flags_t_endian(&a->flags, to_net);
}

static inline void vl_api_nat44_ei_add_del_interface_addr_reply_t_endian (vl_api_nat44_ei_add_del_interface_addr_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_interface_addr_dump_t_endian (vl_api_nat44_ei_interface_addr_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_ei_interface_addr_details_t_endian (vl_api_nat44_ei_interface_addr_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_nat44_ei_user_dump_t_endian (vl_api_nat44_ei_user_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_ei_user_details_t_endian (vl_api_nat44_ei_user_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    vl_api_ip4_address_t_endian(&a->ip_address, to_net);
    a->nsessions = clib_net_to_host_u32(a->nsessions);
    a->nstaticsessions = clib_net_to_host_u32(a->nstaticsessions);
}

static inline void vl_api_nat44_ei_user_session_dump_t_endian (vl_api_nat44_ei_user_session_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->ip_address, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
}

static inline void vl_api_nat44_ei_user_session_details_t_endian (vl_api_nat44_ei_user_session_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->outside_ip_address, to_net);
    a->outside_port = clib_net_to_host_u16(a->outside_port);
    vl_api_ip4_address_t_endian(&a->inside_ip_address, to_net);
    a->inside_port = clib_net_to_host_u16(a->inside_port);
    a->protocol = clib_net_to_host_u16(a->protocol);
    vl_api_nat44_ei_config_flags_t_endian(&a->flags, to_net);
    a->last_heard = clib_net_to_host_u64(a->last_heard);
    a->total_bytes = clib_net_to_host_u64(a->total_bytes);
    a->total_pkts = clib_net_to_host_u32(a->total_pkts);
    vl_api_ip4_address_t_endian(&a->ext_host_address, to_net);
    a->ext_host_port = clib_net_to_host_u16(a->ext_host_port);
}

static inline void vl_api_nat44_ei_user_session_v2_dump_t_endian (vl_api_nat44_ei_user_session_v2_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->ip_address, to_net);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
}

static inline void vl_api_nat44_ei_user_session_v2_details_t_endian (vl_api_nat44_ei_user_session_v2_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->outside_ip_address, to_net);
    a->outside_port = clib_net_to_host_u16(a->outside_port);
    vl_api_ip4_address_t_endian(&a->inside_ip_address, to_net);
    a->inside_port = clib_net_to_host_u16(a->inside_port);
    a->protocol = clib_net_to_host_u16(a->protocol);
    vl_api_nat44_ei_config_flags_t_endian(&a->flags, to_net);
    a->last_heard = clib_net_to_host_u64(a->last_heard);
    a->time_since_last_heard = clib_net_to_host_u64(a->time_since_last_heard);
    a->total_bytes = clib_net_to_host_u64(a->total_bytes);
    a->total_pkts = clib_net_to_host_u32(a->total_pkts);
    vl_api_ip4_address_t_endian(&a->ext_host_address, to_net);
    a->ext_host_port = clib_net_to_host_u16(a->ext_host_port);
}

static inline void vl_api_nat44_ei_del_session_t_endian (vl_api_nat44_ei_del_session_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ip4_address_t_endian(&a->address, to_net);
    /* a->protocol = a->protocol (no-op) */
    a->port = clib_net_to_host_u16(a->port);
    a->vrf_id = clib_net_to_host_u32(a->vrf_id);
    vl_api_nat44_ei_config_flags_t_endian(&a->flags, to_net);
    vl_api_ip4_address_t_endian(&a->ext_host_address, to_net);
    a->ext_host_port = clib_net_to_host_u16(a->ext_host_port);
}

static inline void vl_api_nat44_ei_del_session_reply_t_endian (vl_api_nat44_ei_del_session_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_forwarding_enable_disable_t_endian (vl_api_nat44_ei_forwarding_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->enable = a->enable (no-op) */
}

static inline void vl_api_nat44_ei_forwarding_enable_disable_reply_t_endian (vl_api_nat44_ei_forwarding_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_set_fq_options_t_endian (vl_api_nat44_ei_set_fq_options_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->frame_queue_nelts = clib_net_to_host_u32(a->frame_queue_nelts);
}

static inline void vl_api_nat44_ei_set_fq_options_reply_t_endian (vl_api_nat44_ei_set_fq_options_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_nat44_ei_show_fq_options_t_endian (vl_api_nat44_ei_show_fq_options_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_nat44_ei_show_fq_options_reply_t_endian (vl_api_nat44_ei_show_fq_options_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->frame_queue_nelts = clib_net_to_host_u32(a->frame_queue_nelts);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_nat44_ei_calcsizefun
#define included_nat44_ei_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_config_flags_t_calc_size (vl_api_nat44_ei_config_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_plugin_enable_disable_t_calc_size (vl_api_nat44_ei_plugin_enable_disable_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_nat44_ei_config_flags_t_calc_size(&a->flags);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_plugin_enable_disable_reply_t_calc_size (vl_api_nat44_ei_plugin_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_show_running_config_t_calc_size (vl_api_nat44_ei_show_running_config_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_show_running_config_reply_t_calc_size (vl_api_nat44_ei_show_running_config_reply_t *a)
{
      return sizeof(*a) - sizeof(a->timeouts) + vl_api_nat_timeouts_t_calc_size(&a->timeouts) - sizeof(a->log_level) + vl_api_nat_log_level_t_calc_size(&a->log_level) - sizeof(a->flags) + vl_api_nat44_ei_config_flags_t_calc_size(&a->flags);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_set_log_level_t_calc_size (vl_api_nat44_ei_set_log_level_t *a)
{
      return sizeof(*a) - sizeof(a->log_level) + vl_api_nat_log_level_t_calc_size(&a->log_level);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_set_log_level_reply_t_calc_size (vl_api_nat44_ei_set_log_level_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_set_workers_t_calc_size (vl_api_nat44_ei_set_workers_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_set_workers_reply_t_calc_size (vl_api_nat44_ei_set_workers_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_worker_dump_t_calc_size (vl_api_nat44_ei_worker_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_worker_details_t_calc_size (vl_api_nat44_ei_worker_details_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_ipfix_enable_disable_t_calc_size (vl_api_nat44_ei_ipfix_enable_disable_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_ipfix_enable_disable_reply_t_calc_size (vl_api_nat44_ei_ipfix_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_set_timeouts_t_calc_size (vl_api_nat44_ei_set_timeouts_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_set_timeouts_reply_t_calc_size (vl_api_nat44_ei_set_timeouts_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_set_addr_and_port_alloc_alg_t_calc_size (vl_api_nat44_ei_set_addr_and_port_alloc_alg_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t_calc_size (vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_get_addr_and_port_alloc_alg_t_calc_size (vl_api_nat44_ei_get_addr_and_port_alloc_alg_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t_calc_size (vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_set_mss_clamping_t_calc_size (vl_api_nat44_ei_set_mss_clamping_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_set_mss_clamping_reply_t_calc_size (vl_api_nat44_ei_set_mss_clamping_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_get_mss_clamping_t_calc_size (vl_api_nat44_ei_get_mss_clamping_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_get_mss_clamping_reply_t_calc_size (vl_api_nat44_ei_get_mss_clamping_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_ha_set_listener_t_calc_size (vl_api_nat44_ei_ha_set_listener_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_ip4_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_ha_set_listener_reply_t_calc_size (vl_api_nat44_ei_ha_set_listener_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_ha_set_failover_t_calc_size (vl_api_nat44_ei_ha_set_failover_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_ip4_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_ha_set_failover_reply_t_calc_size (vl_api_nat44_ei_ha_set_failover_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_ha_get_listener_t_calc_size (vl_api_nat44_ei_ha_get_listener_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_ha_get_listener_reply_t_calc_size (vl_api_nat44_ei_ha_get_listener_reply_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_ip4_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_ha_get_failover_t_calc_size (vl_api_nat44_ei_ha_get_failover_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_ha_get_failover_reply_t_calc_size (vl_api_nat44_ei_ha_get_failover_reply_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_ip4_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_ha_flush_t_calc_size (vl_api_nat44_ei_ha_flush_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_ha_flush_reply_t_calc_size (vl_api_nat44_ei_ha_flush_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_ha_resync_t_calc_size (vl_api_nat44_ei_ha_resync_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_ha_resync_reply_t_calc_size (vl_api_nat44_ei_ha_resync_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_ha_resync_completed_event_t_calc_size (vl_api_nat44_ei_ha_resync_completed_event_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_del_user_t_calc_size (vl_api_nat44_ei_del_user_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_ip4_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_del_user_reply_t_calc_size (vl_api_nat44_ei_del_user_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_add_del_address_range_t_calc_size (vl_api_nat44_ei_add_del_address_range_t *a)
{
      return sizeof(*a) - sizeof(a->first_ip_address) + vl_api_ip4_address_t_calc_size(&a->first_ip_address) - sizeof(a->last_ip_address) + vl_api_ip4_address_t_calc_size(&a->last_ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_add_del_address_range_reply_t_calc_size (vl_api_nat44_ei_add_del_address_range_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_address_dump_t_calc_size (vl_api_nat44_ei_address_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_address_details_t_calc_size (vl_api_nat44_ei_address_details_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_ip4_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_interface_add_del_feature_t_calc_size (vl_api_nat44_ei_interface_add_del_feature_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_nat44_ei_config_flags_t_calc_size(&a->flags) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_interface_add_del_feature_reply_t_calc_size (vl_api_nat44_ei_interface_add_del_feature_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_interface_dump_t_calc_size (vl_api_nat44_ei_interface_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_interface_details_t_calc_size (vl_api_nat44_ei_interface_details_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_nat44_ei_config_flags_t_calc_size(&a->flags) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_interface_add_del_output_feature_t_calc_size (vl_api_nat44_ei_interface_add_del_output_feature_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_nat44_ei_config_flags_t_calc_size(&a->flags) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_interface_add_del_output_feature_reply_t_calc_size (vl_api_nat44_ei_interface_add_del_output_feature_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_interface_output_feature_dump_t_calc_size (vl_api_nat44_ei_interface_output_feature_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_interface_output_feature_details_t_calc_size (vl_api_nat44_ei_interface_output_feature_details_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_nat44_ei_config_flags_t_calc_size(&a->flags) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_add_del_output_interface_t_calc_size (vl_api_nat44_ei_add_del_output_interface_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_add_del_output_interface_reply_t_calc_size (vl_api_nat44_ei_add_del_output_interface_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_output_interface_get_t_calc_size (vl_api_nat44_ei_output_interface_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_output_interface_get_reply_t_calc_size (vl_api_nat44_ei_output_interface_get_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_output_interface_details_t_calc_size (vl_api_nat44_ei_output_interface_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_add_del_static_mapping_t_calc_size (vl_api_nat44_ei_add_del_static_mapping_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_nat44_ei_config_flags_t_calc_size(&a->flags) - sizeof(a->local_ip_address) + vl_api_ip4_address_t_calc_size(&a->local_ip_address) - sizeof(a->external_ip_address) + vl_api_ip4_address_t_calc_size(&a->external_ip_address) - sizeof(a->external_sw_if_index) + vl_api_interface_index_t_calc_size(&a->external_sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_add_del_static_mapping_reply_t_calc_size (vl_api_nat44_ei_add_del_static_mapping_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_static_mapping_dump_t_calc_size (vl_api_nat44_ei_static_mapping_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_static_mapping_details_t_calc_size (vl_api_nat44_ei_static_mapping_details_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_nat44_ei_config_flags_t_calc_size(&a->flags) - sizeof(a->local_ip_address) + vl_api_ip4_address_t_calc_size(&a->local_ip_address) - sizeof(a->external_ip_address) + vl_api_ip4_address_t_calc_size(&a->external_ip_address) - sizeof(a->external_sw_if_index) + vl_api_interface_index_t_calc_size(&a->external_sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_add_del_identity_mapping_t_calc_size (vl_api_nat44_ei_add_del_identity_mapping_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_nat44_ei_config_flags_t_calc_size(&a->flags) - sizeof(a->ip_address) + vl_api_ip4_address_t_calc_size(&a->ip_address) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_add_del_identity_mapping_reply_t_calc_size (vl_api_nat44_ei_add_del_identity_mapping_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_identity_mapping_dump_t_calc_size (vl_api_nat44_ei_identity_mapping_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_identity_mapping_details_t_calc_size (vl_api_nat44_ei_identity_mapping_details_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_nat44_ei_config_flags_t_calc_size(&a->flags) - sizeof(a->ip_address) + vl_api_ip4_address_t_calc_size(&a->ip_address) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_add_del_interface_addr_t_calc_size (vl_api_nat44_ei_add_del_interface_addr_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->flags) + vl_api_nat44_ei_config_flags_t_calc_size(&a->flags);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_add_del_interface_addr_reply_t_calc_size (vl_api_nat44_ei_add_del_interface_addr_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_interface_addr_dump_t_calc_size (vl_api_nat44_ei_interface_addr_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_interface_addr_details_t_calc_size (vl_api_nat44_ei_interface_addr_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_user_dump_t_calc_size (vl_api_nat44_ei_user_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_user_details_t_calc_size (vl_api_nat44_ei_user_details_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_ip4_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_user_session_dump_t_calc_size (vl_api_nat44_ei_user_session_dump_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_ip4_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_user_session_details_t_calc_size (vl_api_nat44_ei_user_session_details_t *a)
{
      return sizeof(*a) - sizeof(a->outside_ip_address) + vl_api_ip4_address_t_calc_size(&a->outside_ip_address) - sizeof(a->inside_ip_address) + vl_api_ip4_address_t_calc_size(&a->inside_ip_address) - sizeof(a->flags) + vl_api_nat44_ei_config_flags_t_calc_size(&a->flags) - sizeof(a->ext_host_address) + vl_api_ip4_address_t_calc_size(&a->ext_host_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_user_session_v2_dump_t_calc_size (vl_api_nat44_ei_user_session_v2_dump_t *a)
{
      return sizeof(*a) - sizeof(a->ip_address) + vl_api_ip4_address_t_calc_size(&a->ip_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_user_session_v2_details_t_calc_size (vl_api_nat44_ei_user_session_v2_details_t *a)
{
      return sizeof(*a) - sizeof(a->outside_ip_address) + vl_api_ip4_address_t_calc_size(&a->outside_ip_address) - sizeof(a->inside_ip_address) + vl_api_ip4_address_t_calc_size(&a->inside_ip_address) - sizeof(a->flags) + vl_api_nat44_ei_config_flags_t_calc_size(&a->flags) - sizeof(a->ext_host_address) + vl_api_ip4_address_t_calc_size(&a->ext_host_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_del_session_t_calc_size (vl_api_nat44_ei_del_session_t *a)
{
      return sizeof(*a) - sizeof(a->address) + vl_api_ip4_address_t_calc_size(&a->address) - sizeof(a->flags) + vl_api_nat44_ei_config_flags_t_calc_size(&a->flags) - sizeof(a->ext_host_address) + vl_api_ip4_address_t_calc_size(&a->ext_host_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_del_session_reply_t_calc_size (vl_api_nat44_ei_del_session_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_forwarding_enable_disable_t_calc_size (vl_api_nat44_ei_forwarding_enable_disable_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_forwarding_enable_disable_reply_t_calc_size (vl_api_nat44_ei_forwarding_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_set_fq_options_t_calc_size (vl_api_nat44_ei_set_fq_options_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_set_fq_options_reply_t_calc_size (vl_api_nat44_ei_set_fq_options_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_show_fq_options_t_calc_size (vl_api_nat44_ei_show_fq_options_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nat44_ei_show_fq_options_reply_t_calc_size (vl_api_nat44_ei_show_fq_options_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(nat44_ei.api, 1, 1, 1)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(nat44_ei.api, 0x20734fe0)

#endif

