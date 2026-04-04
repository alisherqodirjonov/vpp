#ifndef included_nat44_ei_api_types_h
#define included_nat44_ei_api_types_h
#define VL_API_NAT44_EI_API_VERSION_MAJOR 1
#define VL_API_NAT44_EI_API_VERSION_MINOR 1
#define VL_API_NAT44_EI_API_VERSION_PATCH 1
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/interface_types.api_types.h>
#include <nat/lib/nat_types.api_types.h>
typedef enum __attribute__((packed)) {
    NAT44_EI_NONE = 0,
    NAT44_EI_STATIC_MAPPING_ONLY = 1,
    NAT44_EI_CONNECTION_TRACKING = 2,
    NAT44_EI_OUT2IN_DPO = 4,
    NAT44_EI_ADDR_ONLY_MAPPING = 8,
    NAT44_EI_IF_INSIDE = 16,
    NAT44_EI_IF_OUTSIDE = 32,
    NAT44_EI_STATIC_MAPPING = 64,
} vl_api_nat44_ei_config_flags_t;
STATIC_ASSERT(sizeof(vl_api_nat44_ei_config_flags_t) == sizeof(u8), "size of API enum nat44_ei_config_flags is wrong");
typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_plugin_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 inside_vrf;
    u32 outside_vrf;
    u32 users;
    u32 user_memory;
    u32 sessions;
    u32 session_memory;
    u32 user_sessions;
    bool enable;
    vl_api_nat44_ei_config_flags_t flags;
} vl_api_nat44_ei_plugin_enable_disable_t;
#define VL_API_NAT44_EI_PLUGIN_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_plugin_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_plugin_enable_disable_reply_t;
#define VL_API_NAT44_EI_PLUGIN_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_show_running_config {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_nat44_ei_show_running_config_t;
#define VL_API_NAT44_EI_SHOW_RUNNING_CONFIG_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_show_running_config_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 inside_vrf;
    u32 outside_vrf;
    u32 users;
    u32 sessions;
    u32 user_sessions;
    u32 user_buckets;
    u32 translation_buckets;
    bool forwarding_enabled;
    bool ipfix_logging_enabled;
    vl_api_nat_timeouts_t timeouts;
    vl_api_nat_log_level_t log_level;
    vl_api_nat44_ei_config_flags_t flags;
} vl_api_nat44_ei_show_running_config_reply_t;
#define VL_API_NAT44_EI_SHOW_RUNNING_CONFIG_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_set_log_level {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_nat_log_level_t log_level;
} vl_api_nat44_ei_set_log_level_t;
#define VL_API_NAT44_EI_SET_LOG_LEVEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_set_log_level_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_set_log_level_reply_t;
#define VL_API_NAT44_EI_SET_LOG_LEVEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_set_workers {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u64 worker_mask;
} vl_api_nat44_ei_set_workers_t;
#define VL_API_NAT44_EI_SET_WORKERS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_set_workers_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_set_workers_reply_t;
#define VL_API_NAT44_EI_SET_WORKERS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_worker_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_nat44_ei_worker_dump_t;
#define VL_API_NAT44_EI_WORKER_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_worker_details {
    u16 _vl_msg_id;
    u32 context;
    u32 worker_index;
    u32 lcore_id;
    u8 name[64];
} vl_api_nat44_ei_worker_details_t;
#define VL_API_NAT44_EI_WORKER_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_ipfix_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 domain_id;
    u16 src_port;
    bool enable;
} vl_api_nat44_ei_ipfix_enable_disable_t;
#define VL_API_NAT44_EI_IPFIX_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_ipfix_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_ipfix_enable_disable_reply_t;
#define VL_API_NAT44_EI_IPFIX_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_set_timeouts {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 udp;
    u32 tcp_established;
    u32 tcp_transitory;
    u32 icmp;
} vl_api_nat44_ei_set_timeouts_t;
#define VL_API_NAT44_EI_SET_TIMEOUTS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_set_timeouts_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_set_timeouts_reply_t;
#define VL_API_NAT44_EI_SET_TIMEOUTS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_set_addr_and_port_alloc_alg {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 alg;
    u8 psid_offset;
    u8 psid_length;
    u16 psid;
    u16 start_port;
    u16 end_port;
} vl_api_nat44_ei_set_addr_and_port_alloc_alg_t;
#define VL_API_NAT44_EI_SET_ADDR_AND_PORT_ALLOC_ALG_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t;
#define VL_API_NAT44_EI_SET_ADDR_AND_PORT_ALLOC_ALG_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_get_addr_and_port_alloc_alg {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_nat44_ei_get_addr_and_port_alloc_alg_t;
#define VL_API_NAT44_EI_GET_ADDR_AND_PORT_ALLOC_ALG_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u8 alg;
    u8 psid_offset;
    u8 psid_length;
    u16 psid;
    u16 start_port;
    u16 end_port;
} vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t;
#define VL_API_NAT44_EI_GET_ADDR_AND_PORT_ALLOC_ALG_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_set_mss_clamping {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u16 mss_value;
    bool enable;
} vl_api_nat44_ei_set_mss_clamping_t;
#define VL_API_NAT44_EI_SET_MSS_CLAMPING_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_set_mss_clamping_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_set_mss_clamping_reply_t;
#define VL_API_NAT44_EI_SET_MSS_CLAMPING_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_get_mss_clamping {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_nat44_ei_get_mss_clamping_t;
#define VL_API_NAT44_EI_GET_MSS_CLAMPING_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_get_mss_clamping_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u16 mss_value;
    bool enable;
} vl_api_nat44_ei_get_mss_clamping_reply_t;
#define VL_API_NAT44_EI_GET_MSS_CLAMPING_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_ha_set_listener {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip4_address_t ip_address;
    u16 port;
    u32 path_mtu;
} vl_api_nat44_ei_ha_set_listener_t;
#define VL_API_NAT44_EI_HA_SET_LISTENER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_ha_set_listener_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_ha_set_listener_reply_t;
#define VL_API_NAT44_EI_HA_SET_LISTENER_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_ha_set_failover {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip4_address_t ip_address;
    u16 port;
    u32 session_refresh_interval;
} vl_api_nat44_ei_ha_set_failover_t;
#define VL_API_NAT44_EI_HA_SET_FAILOVER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_ha_set_failover_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_ha_set_failover_reply_t;
#define VL_API_NAT44_EI_HA_SET_FAILOVER_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_ha_get_listener {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_nat44_ei_ha_get_listener_t;
#define VL_API_NAT44_EI_HA_GET_LISTENER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_ha_get_listener_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_ip4_address_t ip_address;
    u16 port;
    u32 path_mtu;
} vl_api_nat44_ei_ha_get_listener_reply_t;
#define VL_API_NAT44_EI_HA_GET_LISTENER_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_ha_get_failover {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_nat44_ei_ha_get_failover_t;
#define VL_API_NAT44_EI_HA_GET_FAILOVER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_ha_get_failover_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_ip4_address_t ip_address;
    u16 port;
    u32 session_refresh_interval;
} vl_api_nat44_ei_ha_get_failover_reply_t;
#define VL_API_NAT44_EI_HA_GET_FAILOVER_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_ha_flush {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_nat44_ei_ha_flush_t;
#define VL_API_NAT44_EI_HA_FLUSH_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_ha_flush_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_ha_flush_reply_t;
#define VL_API_NAT44_EI_HA_FLUSH_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_ha_resync {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 want_resync_event;
    u32 pid;
} vl_api_nat44_ei_ha_resync_t;
#define VL_API_NAT44_EI_HA_RESYNC_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_ha_resync_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_ha_resync_reply_t;
#define VL_API_NAT44_EI_HA_RESYNC_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_ha_resync_completed_event {
    u16 _vl_msg_id;
    u32 client_index;
    u32 pid;
    u32 missed_count;
} vl_api_nat44_ei_ha_resync_completed_event_t;
#define VL_API_NAT44_EI_HA_RESYNC_COMPLETED_EVENT_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_del_user {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip4_address_t ip_address;
    u32 fib_index;
} vl_api_nat44_ei_del_user_t;
#define VL_API_NAT44_EI_DEL_USER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_del_user_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_del_user_reply_t;
#define VL_API_NAT44_EI_DEL_USER_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_add_del_address_range {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip4_address_t first_ip_address;
    vl_api_ip4_address_t last_ip_address;
    u32 vrf_id;
    bool is_add;
} vl_api_nat44_ei_add_del_address_range_t;
#define VL_API_NAT44_EI_ADD_DEL_ADDRESS_RANGE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_add_del_address_range_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_add_del_address_range_reply_t;
#define VL_API_NAT44_EI_ADD_DEL_ADDRESS_RANGE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_address_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_nat44_ei_address_dump_t;
#define VL_API_NAT44_EI_ADDRESS_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_address_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_ip4_address_t ip_address;
    u32 vrf_id;
} vl_api_nat44_ei_address_details_t;
#define VL_API_NAT44_EI_ADDRESS_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_interface_add_del_feature {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_nat44_ei_config_flags_t flags;
    vl_api_interface_index_t sw_if_index;
} vl_api_nat44_ei_interface_add_del_feature_t;
#define VL_API_NAT44_EI_INTERFACE_ADD_DEL_FEATURE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_interface_add_del_feature_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_interface_add_del_feature_reply_t;
#define VL_API_NAT44_EI_INTERFACE_ADD_DEL_FEATURE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_interface_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_nat44_ei_interface_dump_t;
#define VL_API_NAT44_EI_INTERFACE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_interface_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_nat44_ei_config_flags_t flags;
    vl_api_interface_index_t sw_if_index;
} vl_api_nat44_ei_interface_details_t;
#define VL_API_NAT44_EI_INTERFACE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_interface_add_del_output_feature {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_nat44_ei_config_flags_t flags;
    vl_api_interface_index_t sw_if_index;
} vl_api_nat44_ei_interface_add_del_output_feature_t;
#define VL_API_NAT44_EI_INTERFACE_ADD_DEL_OUTPUT_FEATURE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_interface_add_del_output_feature_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_interface_add_del_output_feature_reply_t;
#define VL_API_NAT44_EI_INTERFACE_ADD_DEL_OUTPUT_FEATURE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_interface_output_feature_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_nat44_ei_interface_output_feature_dump_t;
#define VL_API_NAT44_EI_INTERFACE_OUTPUT_FEATURE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_interface_output_feature_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_nat44_ei_config_flags_t flags;
    vl_api_interface_index_t sw_if_index;
} vl_api_nat44_ei_interface_output_feature_details_t;
#define VL_API_NAT44_EI_INTERFACE_OUTPUT_FEATURE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_add_del_output_interface {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_interface_index_t sw_if_index;
} vl_api_nat44_ei_add_del_output_interface_t;
#define VL_API_NAT44_EI_ADD_DEL_OUTPUT_INTERFACE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_add_del_output_interface_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_add_del_output_interface_reply_t;
#define VL_API_NAT44_EI_ADD_DEL_OUTPUT_INTERFACE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_output_interface_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 cursor;
} vl_api_nat44_ei_output_interface_get_t;
#define VL_API_NAT44_EI_OUTPUT_INTERFACE_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_output_interface_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 cursor;
} vl_api_nat44_ei_output_interface_get_reply_t;
#define VL_API_NAT44_EI_OUTPUT_INTERFACE_GET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_output_interface_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_nat44_ei_output_interface_details_t;
#define VL_API_NAT44_EI_OUTPUT_INTERFACE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_add_del_static_mapping {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_nat44_ei_config_flags_t flags;
    vl_api_ip4_address_t local_ip_address;
    vl_api_ip4_address_t external_ip_address;
    u8 protocol;
    u16 local_port;
    u16 external_port;
    vl_api_interface_index_t external_sw_if_index;
    u32 vrf_id;
    u8 tag[64];
} vl_api_nat44_ei_add_del_static_mapping_t;
#define VL_API_NAT44_EI_ADD_DEL_STATIC_MAPPING_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_add_del_static_mapping_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_add_del_static_mapping_reply_t;
#define VL_API_NAT44_EI_ADD_DEL_STATIC_MAPPING_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_static_mapping_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_nat44_ei_static_mapping_dump_t;
#define VL_API_NAT44_EI_STATIC_MAPPING_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_static_mapping_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_nat44_ei_config_flags_t flags;
    vl_api_ip4_address_t local_ip_address;
    vl_api_ip4_address_t external_ip_address;
    u8 protocol;
    u16 local_port;
    u16 external_port;
    vl_api_interface_index_t external_sw_if_index;
    u32 vrf_id;
    u8 tag[64];
} vl_api_nat44_ei_static_mapping_details_t;
#define VL_API_NAT44_EI_STATIC_MAPPING_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_add_del_identity_mapping {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_nat44_ei_config_flags_t flags;
    vl_api_ip4_address_t ip_address;
    u8 protocol;
    u16 port;
    vl_api_interface_index_t sw_if_index;
    u32 vrf_id;
    u8 tag[64];
} vl_api_nat44_ei_add_del_identity_mapping_t;
#define VL_API_NAT44_EI_ADD_DEL_IDENTITY_MAPPING_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_add_del_identity_mapping_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_add_del_identity_mapping_reply_t;
#define VL_API_NAT44_EI_ADD_DEL_IDENTITY_MAPPING_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_identity_mapping_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_nat44_ei_identity_mapping_dump_t;
#define VL_API_NAT44_EI_IDENTITY_MAPPING_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_identity_mapping_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_nat44_ei_config_flags_t flags;
    vl_api_ip4_address_t ip_address;
    u8 protocol;
    u16 port;
    vl_api_interface_index_t sw_if_index;
    u32 vrf_id;
    u8 tag[64];
} vl_api_nat44_ei_identity_mapping_details_t;
#define VL_API_NAT44_EI_IDENTITY_MAPPING_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_add_del_interface_addr {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_interface_index_t sw_if_index;
    vl_api_nat44_ei_config_flags_t flags;
} vl_api_nat44_ei_add_del_interface_addr_t;
#define VL_API_NAT44_EI_ADD_DEL_INTERFACE_ADDR_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_add_del_interface_addr_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_add_del_interface_addr_reply_t;
#define VL_API_NAT44_EI_ADD_DEL_INTERFACE_ADDR_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_interface_addr_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_nat44_ei_interface_addr_dump_t;
#define VL_API_NAT44_EI_INTERFACE_ADDR_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_interface_addr_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_nat44_ei_interface_addr_details_t;
#define VL_API_NAT44_EI_INTERFACE_ADDR_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_user_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_nat44_ei_user_dump_t;
#define VL_API_NAT44_EI_USER_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_user_details {
    u16 _vl_msg_id;
    u32 context;
    u32 vrf_id;
    vl_api_ip4_address_t ip_address;
    u32 nsessions;
    u32 nstaticsessions;
} vl_api_nat44_ei_user_details_t;
#define VL_API_NAT44_EI_USER_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_user_session_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip4_address_t ip_address;
    u32 vrf_id;
} vl_api_nat44_ei_user_session_dump_t;
#define VL_API_NAT44_EI_USER_SESSION_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_user_session_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_ip4_address_t outside_ip_address;
    u16 outside_port;
    vl_api_ip4_address_t inside_ip_address;
    u16 inside_port;
    u16 protocol;
    vl_api_nat44_ei_config_flags_t flags;
    u64 last_heard;
    u64 total_bytes;
    u32 total_pkts;
    vl_api_ip4_address_t ext_host_address;
    u16 ext_host_port;
} vl_api_nat44_ei_user_session_details_t;
#define VL_API_NAT44_EI_USER_SESSION_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_user_session_v2_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip4_address_t ip_address;
    u32 vrf_id;
} vl_api_nat44_ei_user_session_v2_dump_t;
#define VL_API_NAT44_EI_USER_SESSION_V2_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_user_session_v2_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_ip4_address_t outside_ip_address;
    u16 outside_port;
    vl_api_ip4_address_t inside_ip_address;
    u16 inside_port;
    u16 protocol;
    vl_api_nat44_ei_config_flags_t flags;
    u64 last_heard;
    u64 time_since_last_heard;
    u64 total_bytes;
    u32 total_pkts;
    vl_api_ip4_address_t ext_host_address;
    u16 ext_host_port;
} vl_api_nat44_ei_user_session_v2_details_t;
#define VL_API_NAT44_EI_USER_SESSION_V2_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_del_session {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip4_address_t address;
    u8 protocol;
    u16 port;
    u32 vrf_id;
    vl_api_nat44_ei_config_flags_t flags;
    vl_api_ip4_address_t ext_host_address;
    u16 ext_host_port;
} vl_api_nat44_ei_del_session_t;
#define VL_API_NAT44_EI_DEL_SESSION_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_del_session_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_del_session_reply_t;
#define VL_API_NAT44_EI_DEL_SESSION_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_forwarding_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool enable;
} vl_api_nat44_ei_forwarding_enable_disable_t;
#define VL_API_NAT44_EI_FORWARDING_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_forwarding_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_forwarding_enable_disable_reply_t;
#define VL_API_NAT44_EI_FORWARDING_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_set_fq_options {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 frame_queue_nelts;
} vl_api_nat44_ei_set_fq_options_t;
#define VL_API_NAT44_EI_SET_FQ_OPTIONS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_set_fq_options_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat44_ei_set_fq_options_reply_t;
#define VL_API_NAT44_EI_SET_FQ_OPTIONS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_show_fq_options {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_nat44_ei_show_fq_options_t;
#define VL_API_NAT44_EI_SHOW_FQ_OPTIONS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat44_ei_show_fq_options_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 frame_queue_nelts;
} vl_api_nat44_ei_show_fq_options_reply_t;
#define VL_API_NAT44_EI_SHOW_FQ_OPTIONS_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_NAT44_EI_PLUGIN_ENABLE_DISABLE_CRC "nat44_ei_plugin_enable_disable_bf692144"
#define VL_API_NAT44_EI_PLUGIN_ENABLE_DISABLE_REPLY_CRC "nat44_ei_plugin_enable_disable_reply_e8d4e804"
#define VL_API_NAT44_EI_SHOW_RUNNING_CONFIG_CRC "nat44_ei_show_running_config_51077d14"
#define VL_API_NAT44_EI_SHOW_RUNNING_CONFIG_REPLY_CRC "nat44_ei_show_running_config_reply_41b66a81"
#define VL_API_NAT44_EI_SET_LOG_LEVEL_CRC "nat44_ei_set_log_level_70076bfe"
#define VL_API_NAT44_EI_SET_LOG_LEVEL_REPLY_CRC "nat44_ei_set_log_level_reply_e8d4e804"
#define VL_API_NAT44_EI_SET_WORKERS_CRC "nat44_ei_set_workers_da926638"
#define VL_API_NAT44_EI_SET_WORKERS_REPLY_CRC "nat44_ei_set_workers_reply_e8d4e804"
#define VL_API_NAT44_EI_WORKER_DUMP_CRC "nat44_ei_worker_dump_51077d14"
#define VL_API_NAT44_EI_WORKER_DETAILS_CRC "nat44_ei_worker_details_84bf06fc"
#define VL_API_NAT44_EI_IPFIX_ENABLE_DISABLE_CRC "nat44_ei_ipfix_enable_disable_9af4a2d2"
#define VL_API_NAT44_EI_IPFIX_ENABLE_DISABLE_REPLY_CRC "nat44_ei_ipfix_enable_disable_reply_e8d4e804"
#define VL_API_NAT44_EI_SET_TIMEOUTS_CRC "nat44_ei_set_timeouts_d4746b16"
#define VL_API_NAT44_EI_SET_TIMEOUTS_REPLY_CRC "nat44_ei_set_timeouts_reply_e8d4e804"
#define VL_API_NAT44_EI_SET_ADDR_AND_PORT_ALLOC_ALG_CRC "nat44_ei_set_addr_and_port_alloc_alg_deeb746f"
#define VL_API_NAT44_EI_SET_ADDR_AND_PORT_ALLOC_ALG_REPLY_CRC "nat44_ei_set_addr_and_port_alloc_alg_reply_e8d4e804"
#define VL_API_NAT44_EI_GET_ADDR_AND_PORT_ALLOC_ALG_CRC "nat44_ei_get_addr_and_port_alloc_alg_51077d14"
#define VL_API_NAT44_EI_GET_ADDR_AND_PORT_ALLOC_ALG_REPLY_CRC "nat44_ei_get_addr_and_port_alloc_alg_reply_3607a7d0"
#define VL_API_NAT44_EI_SET_MSS_CLAMPING_CRC "nat44_ei_set_mss_clamping_25e90abb"
#define VL_API_NAT44_EI_SET_MSS_CLAMPING_REPLY_CRC "nat44_ei_set_mss_clamping_reply_e8d4e804"
#define VL_API_NAT44_EI_GET_MSS_CLAMPING_CRC "nat44_ei_get_mss_clamping_51077d14"
#define VL_API_NAT44_EI_GET_MSS_CLAMPING_REPLY_CRC "nat44_ei_get_mss_clamping_reply_1c0b2a78"
#define VL_API_NAT44_EI_HA_SET_LISTENER_CRC "nat44_ei_ha_set_listener_e4a8cb4e"
#define VL_API_NAT44_EI_HA_SET_LISTENER_REPLY_CRC "nat44_ei_ha_set_listener_reply_e8d4e804"
#define VL_API_NAT44_EI_HA_SET_FAILOVER_CRC "nat44_ei_ha_set_failover_718246af"
#define VL_API_NAT44_EI_HA_SET_FAILOVER_REPLY_CRC "nat44_ei_ha_set_failover_reply_e8d4e804"
#define VL_API_NAT44_EI_HA_GET_LISTENER_CRC "nat44_ei_ha_get_listener_51077d14"
#define VL_API_NAT44_EI_HA_GET_LISTENER_REPLY_CRC "nat44_ei_ha_get_listener_reply_123ea41f"
#define VL_API_NAT44_EI_HA_GET_FAILOVER_CRC "nat44_ei_ha_get_failover_51077d14"
#define VL_API_NAT44_EI_HA_GET_FAILOVER_REPLY_CRC "nat44_ei_ha_get_failover_reply_a67d8752"
#define VL_API_NAT44_EI_HA_FLUSH_CRC "nat44_ei_ha_flush_51077d14"
#define VL_API_NAT44_EI_HA_FLUSH_REPLY_CRC "nat44_ei_ha_flush_reply_e8d4e804"
#define VL_API_NAT44_EI_HA_RESYNC_CRC "nat44_ei_ha_resync_c8ab9e03"
#define VL_API_NAT44_EI_HA_RESYNC_REPLY_CRC "nat44_ei_ha_resync_reply_e8d4e804"
#define VL_API_NAT44_EI_HA_RESYNC_COMPLETED_EVENT_CRC "nat44_ei_ha_resync_completed_event_fdc598fb"
#define VL_API_NAT44_EI_DEL_USER_CRC "nat44_ei_del_user_99a9f998"
#define VL_API_NAT44_EI_DEL_USER_REPLY_CRC "nat44_ei_del_user_reply_e8d4e804"
#define VL_API_NAT44_EI_ADD_DEL_ADDRESS_RANGE_CRC "nat44_ei_add_del_address_range_35f21abc"
#define VL_API_NAT44_EI_ADD_DEL_ADDRESS_RANGE_REPLY_CRC "nat44_ei_add_del_address_range_reply_e8d4e804"
#define VL_API_NAT44_EI_ADDRESS_DUMP_CRC "nat44_ei_address_dump_51077d14"
#define VL_API_NAT44_EI_ADDRESS_DETAILS_CRC "nat44_ei_address_details_318f1202"
#define VL_API_NAT44_EI_INTERFACE_ADD_DEL_FEATURE_CRC "nat44_ei_interface_add_del_feature_63a2db8b"
#define VL_API_NAT44_EI_INTERFACE_ADD_DEL_FEATURE_REPLY_CRC "nat44_ei_interface_add_del_feature_reply_e8d4e804"
#define VL_API_NAT44_EI_INTERFACE_DUMP_CRC "nat44_ei_interface_dump_51077d14"
#define VL_API_NAT44_EI_INTERFACE_DETAILS_CRC "nat44_ei_interface_details_f446e508"
#define VL_API_NAT44_EI_INTERFACE_ADD_DEL_OUTPUT_FEATURE_CRC "nat44_ei_interface_add_del_output_feature_63a2db8b"
#define VL_API_NAT44_EI_INTERFACE_ADD_DEL_OUTPUT_FEATURE_REPLY_CRC "nat44_ei_interface_add_del_output_feature_reply_e8d4e804"
#define VL_API_NAT44_EI_INTERFACE_OUTPUT_FEATURE_DUMP_CRC "nat44_ei_interface_output_feature_dump_51077d14"
#define VL_API_NAT44_EI_INTERFACE_OUTPUT_FEATURE_DETAILS_CRC "nat44_ei_interface_output_feature_details_f446e508"
#define VL_API_NAT44_EI_ADD_DEL_OUTPUT_INTERFACE_CRC "nat44_ei_add_del_output_interface_47d6e753"
#define VL_API_NAT44_EI_ADD_DEL_OUTPUT_INTERFACE_REPLY_CRC "nat44_ei_add_del_output_interface_reply_e8d4e804"
#define VL_API_NAT44_EI_OUTPUT_INTERFACE_GET_CRC "nat44_ei_output_interface_get_f75ba505"
#define VL_API_NAT44_EI_OUTPUT_INTERFACE_GET_REPLY_CRC "nat44_ei_output_interface_get_reply_53b48f5d"
#define VL_API_NAT44_EI_OUTPUT_INTERFACE_DETAILS_CRC "nat44_ei_output_interface_details_0b45011c"
#define VL_API_NAT44_EI_ADD_DEL_STATIC_MAPPING_CRC "nat44_ei_add_del_static_mapping_b404b7fe"
#define VL_API_NAT44_EI_ADD_DEL_STATIC_MAPPING_REPLY_CRC "nat44_ei_add_del_static_mapping_reply_e8d4e804"
#define VL_API_NAT44_EI_STATIC_MAPPING_DUMP_CRC "nat44_ei_static_mapping_dump_51077d14"
#define VL_API_NAT44_EI_STATIC_MAPPING_DETAILS_CRC "nat44_ei_static_mapping_details_6b51ca6e"
#define VL_API_NAT44_EI_ADD_DEL_IDENTITY_MAPPING_CRC "nat44_ei_add_del_identity_mapping_cb8606b9"
#define VL_API_NAT44_EI_ADD_DEL_IDENTITY_MAPPING_REPLY_CRC "nat44_ei_add_del_identity_mapping_reply_e8d4e804"
#define VL_API_NAT44_EI_IDENTITY_MAPPING_DUMP_CRC "nat44_ei_identity_mapping_dump_51077d14"
#define VL_API_NAT44_EI_IDENTITY_MAPPING_DETAILS_CRC "nat44_ei_identity_mapping_details_30d53e26"
#define VL_API_NAT44_EI_ADD_DEL_INTERFACE_ADDR_CRC "nat44_ei_add_del_interface_addr_883abbcc"
#define VL_API_NAT44_EI_ADD_DEL_INTERFACE_ADDR_REPLY_CRC "nat44_ei_add_del_interface_addr_reply_e8d4e804"
#define VL_API_NAT44_EI_INTERFACE_ADDR_DUMP_CRC "nat44_ei_interface_addr_dump_51077d14"
#define VL_API_NAT44_EI_INTERFACE_ADDR_DETAILS_CRC "nat44_ei_interface_addr_details_0b45011c"
#define VL_API_NAT44_EI_USER_DUMP_CRC "nat44_ei_user_dump_51077d14"
#define VL_API_NAT44_EI_USER_DETAILS_CRC "nat44_ei_user_details_355896c2"
#define VL_API_NAT44_EI_USER_SESSION_DUMP_CRC "nat44_ei_user_session_dump_e1899c98"
#define VL_API_NAT44_EI_USER_SESSION_DETAILS_CRC "nat44_ei_user_session_details_19b7c0ac"
#define VL_API_NAT44_EI_USER_SESSION_V2_DUMP_CRC "nat44_ei_user_session_v2_dump_e1899c98"
#define VL_API_NAT44_EI_USER_SESSION_V2_DETAILS_CRC "nat44_ei_user_session_v2_details_5bd3e9d6"
#define VL_API_NAT44_EI_DEL_SESSION_CRC "nat44_ei_del_session_74969ffe"
#define VL_API_NAT44_EI_DEL_SESSION_REPLY_CRC "nat44_ei_del_session_reply_e8d4e804"
#define VL_API_NAT44_EI_FORWARDING_ENABLE_DISABLE_CRC "nat44_ei_forwarding_enable_disable_b3e225d2"
#define VL_API_NAT44_EI_FORWARDING_ENABLE_DISABLE_REPLY_CRC "nat44_ei_forwarding_enable_disable_reply_e8d4e804"
#define VL_API_NAT44_EI_SET_FQ_OPTIONS_CRC "nat44_ei_set_fq_options_2399bd71"
#define VL_API_NAT44_EI_SET_FQ_OPTIONS_REPLY_CRC "nat44_ei_set_fq_options_reply_e8d4e804"
#define VL_API_NAT44_EI_SHOW_FQ_OPTIONS_CRC "nat44_ei_show_fq_options_51077d14"
#define VL_API_NAT44_EI_SHOW_FQ_OPTIONS_REPLY_CRC "nat44_ei_show_fq_options_reply_7213b545"

#endif
