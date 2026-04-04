#ifndef __included_nat44_ei_api_json
#define __included_nat44_ei_api_json

#include <stdlib.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <vapi/vapi_internal.h>
#include <vapi/vapi.h>
#include <vapi/vapi_dbg.h>

#ifdef __cplusplus
extern "C" {
#endif
#ifndef __vl_api_string_swap_fns_defined__
#define __vl_api_string_swap_fns_defined__

#include <vlibapi/api_types.h>

static inline void vl_api_string_t_hton(vl_api_string_t *msg)
{
  msg->length = htobe32(msg->length);
}

static inline void vl_api_string_t_ntoh(vl_api_string_t *msg)
{
  msg->length = be32toh(msg->length);
}

#endif //__vl_api_string_swap_fns_defined__
#include <vapi/vlib.api.vapi.h>

extern vapi_msg_id_t vapi_msg_id_nat44_ei_plugin_enable_disable;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_plugin_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_show_running_config;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_show_running_config_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_set_log_level;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_set_log_level_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_set_workers;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_set_workers_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_worker_dump;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_worker_details;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_ipfix_enable_disable;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_ipfix_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_set_timeouts;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_set_timeouts_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_set_addr_and_port_alloc_alg;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_set_addr_and_port_alloc_alg_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_get_addr_and_port_alloc_alg;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_get_addr_and_port_alloc_alg_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_set_mss_clamping;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_set_mss_clamping_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_get_mss_clamping;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_get_mss_clamping_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_ha_set_listener;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_ha_set_listener_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_ha_set_failover;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_ha_set_failover_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_ha_get_listener;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_ha_get_listener_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_ha_get_failover;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_ha_get_failover_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_ha_flush;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_ha_flush_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_ha_resync;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_ha_resync_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_ha_resync_completed_event;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_del_user;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_del_user_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_add_del_address_range;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_add_del_address_range_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_address_dump;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_address_details;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_interface_add_del_feature;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_interface_add_del_feature_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_interface_dump;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_interface_details;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_interface_add_del_output_feature;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_interface_add_del_output_feature_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_interface_output_feature_dump;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_interface_output_feature_details;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_add_del_output_interface;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_add_del_output_interface_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_output_interface_get;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_output_interface_get_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_output_interface_details;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_add_del_static_mapping;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_add_del_static_mapping_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_static_mapping_dump;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_static_mapping_details;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_add_del_identity_mapping;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_add_del_identity_mapping_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_identity_mapping_dump;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_identity_mapping_details;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_add_del_interface_addr;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_add_del_interface_addr_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_interface_addr_dump;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_interface_addr_details;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_user_dump;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_user_details;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_user_session_dump;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_user_session_details;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_user_session_v2_dump;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_user_session_v2_details;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_del_session;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_del_session_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_forwarding_enable_disable;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_forwarding_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_set_fq_options;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_set_fq_options_reply;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_show_fq_options;
extern vapi_msg_id_t vapi_msg_id_nat44_ei_show_fq_options_reply;

#define DEFINE_VAPI_MSG_IDS_NAT44_EI_API_JSON\
  vapi_msg_id_t vapi_msg_id_nat44_ei_plugin_enable_disable;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_plugin_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_show_running_config;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_show_running_config_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_set_log_level;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_set_log_level_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_set_workers;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_set_workers_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_worker_dump;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_worker_details;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_ipfix_enable_disable;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_ipfix_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_set_timeouts;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_set_timeouts_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_set_addr_and_port_alloc_alg;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_set_addr_and_port_alloc_alg_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_get_addr_and_port_alloc_alg;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_get_addr_and_port_alloc_alg_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_set_mss_clamping;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_set_mss_clamping_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_get_mss_clamping;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_get_mss_clamping_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_ha_set_listener;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_ha_set_listener_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_ha_set_failover;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_ha_set_failover_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_ha_get_listener;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_ha_get_listener_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_ha_get_failover;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_ha_get_failover_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_ha_flush;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_ha_flush_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_ha_resync;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_ha_resync_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_ha_resync_completed_event;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_del_user;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_del_user_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_add_del_address_range;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_add_del_address_range_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_address_dump;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_address_details;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_interface_add_del_feature;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_interface_add_del_feature_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_interface_dump;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_interface_details;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_interface_add_del_output_feature;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_interface_add_del_output_feature_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_interface_output_feature_dump;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_interface_output_feature_details;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_add_del_output_interface;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_add_del_output_interface_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_output_interface_get;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_output_interface_get_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_output_interface_details;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_add_del_static_mapping;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_add_del_static_mapping_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_static_mapping_dump;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_static_mapping_details;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_add_del_identity_mapping;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_add_del_identity_mapping_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_identity_mapping_dump;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_identity_mapping_details;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_add_del_interface_addr;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_add_del_interface_addr_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_interface_addr_dump;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_interface_addr_details;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_user_dump;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_user_details;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_user_session_dump;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_user_session_details;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_user_session_v2_dump;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_user_session_v2_details;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_del_session;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_del_session_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_forwarding_enable_disable;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_forwarding_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_set_fq_options;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_set_fq_options_reply;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_show_fq_options;\
  vapi_msg_id_t vapi_msg_id_nat44_ei_show_fq_options_reply;


#ifndef defined_vapi_enum_address_family
#define defined_vapi_enum_address_family
typedef enum {
  ADDRESS_IP4 = 0,
  ADDRESS_IP6 = 1,
} __attribute__((packed)) vapi_enum_address_family;

#endif

#ifndef defined_vapi_enum_ip_feature_location
#define defined_vapi_enum_ip_feature_location
typedef enum {
  IP_API_FEATURE_INPUT = 0,
  IP_API_FEATURE_OUTPUT = 1,
  IP_API_FEATURE_LOCAL = 2,
  IP_API_FEATURE_PUNT = 3,
  IP_API_FEATURE_DROP = 4,
} __attribute__((packed)) vapi_enum_ip_feature_location;

#endif

#ifndef defined_vapi_enum_ip_ecn
#define defined_vapi_enum_ip_ecn
typedef enum {
  IP_API_ECN_NONE = 0,
  IP_API_ECN_ECT0 = 1,
  IP_API_ECN_ECT1 = 2,
  IP_API_ECN_CE = 3,
} __attribute__((packed)) vapi_enum_ip_ecn;

#endif

#ifndef defined_vapi_enum_ip_dscp
#define defined_vapi_enum_ip_dscp
typedef enum {
  IP_API_DSCP_CS0 = 0,
  IP_API_DSCP_CS1 = 8,
  IP_API_DSCP_AF11 = 10,
  IP_API_DSCP_AF12 = 12,
  IP_API_DSCP_AF13 = 14,
  IP_API_DSCP_CS2 = 16,
  IP_API_DSCP_AF21 = 18,
  IP_API_DSCP_AF22 = 20,
  IP_API_DSCP_AF23 = 22,
  IP_API_DSCP_CS3 = 24,
  IP_API_DSCP_AF31 = 26,
  IP_API_DSCP_AF32 = 28,
  IP_API_DSCP_AF33 = 30,
  IP_API_DSCP_CS4 = 32,
  IP_API_DSCP_AF41 = 34,
  IP_API_DSCP_AF42 = 36,
  IP_API_DSCP_AF43 = 38,
  IP_API_DSCP_CS5 = 40,
  IP_API_DSCP_EF = 46,
  IP_API_DSCP_CS6 = 48,
  IP_API_DSCP_CS7 = 50,
} __attribute__((packed)) vapi_enum_ip_dscp;

#endif

#ifndef defined_vapi_enum_ip_proto
#define defined_vapi_enum_ip_proto
typedef enum {
  IP_API_PROTO_HOPOPT = 0,
  IP_API_PROTO_ICMP = 1,
  IP_API_PROTO_IGMP = 2,
  IP_API_PROTO_TCP = 6,
  IP_API_PROTO_UDP = 17,
  IP_API_PROTO_GRE = 47,
  IP_API_PROTO_ESP = 50,
  IP_API_PROTO_AH = 51,
  IP_API_PROTO_ICMP6 = 58,
  IP_API_PROTO_EIGRP = 88,
  IP_API_PROTO_OSPF = 89,
  IP_API_PROTO_SCTP = 132,
  IP_API_PROTO_RESERVED = 255,
} __attribute__((packed)) vapi_enum_ip_proto;

#endif

#ifndef defined_vapi_enum_if_status_flags
#define defined_vapi_enum_if_status_flags
typedef enum {
  IF_STATUS_API_FLAG_ADMIN_UP = 1,
  IF_STATUS_API_FLAG_LINK_UP = 2,
}  vapi_enum_if_status_flags;

#endif

#ifndef defined_vapi_enum_mtu_proto
#define defined_vapi_enum_mtu_proto
typedef enum {
  MTU_PROTO_API_L3 = 0,
  MTU_PROTO_API_IP4 = 1,
  MTU_PROTO_API_IP6 = 2,
  MTU_PROTO_API_MPLS = 3,
}  vapi_enum_mtu_proto;

#endif

#ifndef defined_vapi_enum_link_duplex
#define defined_vapi_enum_link_duplex
typedef enum {
  LINK_DUPLEX_API_UNKNOWN = 0,
  LINK_DUPLEX_API_HALF = 1,
  LINK_DUPLEX_API_FULL = 2,
}  vapi_enum_link_duplex;

#endif

#ifndef defined_vapi_enum_sub_if_flags
#define defined_vapi_enum_sub_if_flags
typedef enum {
  SUB_IF_API_FLAG_NO_TAGS = 1,
  SUB_IF_API_FLAG_ONE_TAG = 2,
  SUB_IF_API_FLAG_TWO_TAGS = 4,
  SUB_IF_API_FLAG_DOT1AD = 8,
  SUB_IF_API_FLAG_EXACT_MATCH = 16,
  SUB_IF_API_FLAG_DEFAULT = 32,
  SUB_IF_API_FLAG_OUTER_VLAN_ID_ANY = 64,
  SUB_IF_API_FLAG_INNER_VLAN_ID_ANY = 128,
  SUB_IF_API_FLAG_MASK_VNET = 254,
  SUB_IF_API_FLAG_DOT1AH = 256,
}  vapi_enum_sub_if_flags;

#endif

#ifndef defined_vapi_enum_rx_mode
#define defined_vapi_enum_rx_mode
typedef enum {
  RX_MODE_API_UNKNOWN = 0,
  RX_MODE_API_POLLING = 1,
  RX_MODE_API_INTERRUPT = 2,
  RX_MODE_API_ADAPTIVE = 3,
  RX_MODE_API_DEFAULT = 4,
}  vapi_enum_rx_mode;

#endif

#ifndef defined_vapi_enum_if_type
#define defined_vapi_enum_if_type
typedef enum {
  IF_API_TYPE_HARDWARE = 0,
  IF_API_TYPE_SUB = 1,
  IF_API_TYPE_P2P = 2,
  IF_API_TYPE_PIPE = 3,
}  vapi_enum_if_type;

#endif

#ifndef defined_vapi_enum_direction
#define defined_vapi_enum_direction
typedef enum {
  RX = 0,
  TX = 1,
} __attribute__((packed)) vapi_enum_direction;

#endif

#ifndef defined_vapi_enum_nat_log_level
#define defined_vapi_enum_nat_log_level
typedef enum {
  NAT_LOG_NONE = 0,
  NAT_LOG_ERROR = 1,
  NAT_LOG_WARNING = 2,
  NAT_LOG_NOTICE = 3,
  NAT_LOG_INFO = 4,
  NAT_LOG_DEBUG = 5,
} __attribute__((packed)) vapi_enum_nat_log_level;

#endif

#ifndef defined_vapi_enum_nat_config_flags
#define defined_vapi_enum_nat_config_flags
typedef enum {
  NAT_IS_NONE = 0,
  NAT_IS_TWICE_NAT = 1,
  NAT_IS_SELF_TWICE_NAT = 2,
  NAT_IS_OUT2IN_ONLY = 4,
  NAT_IS_ADDR_ONLY = 8,
  NAT_IS_OUTSIDE = 16,
  NAT_IS_INSIDE = 32,
  NAT_IS_STATIC = 64,
  NAT_IS_EXT_HOST_VALID = 128,
} __attribute__((packed)) vapi_enum_nat_config_flags;

#endif

#ifndef defined_vapi_enum_nat44_ei_config_flags
#define defined_vapi_enum_nat44_ei_config_flags
typedef enum {
  NAT44_EI_NONE = 0,
  NAT44_EI_STATIC_MAPPING_ONLY = 1,
  NAT44_EI_CONNECTION_TRACKING = 2,
  NAT44_EI_OUT2IN_DPO = 4,
  NAT44_EI_ADDR_ONLY_MAPPING = 8,
  NAT44_EI_IF_INSIDE = 16,
  NAT44_EI_IF_OUTSIDE = 32,
  NAT44_EI_STATIC_MAPPING = 64,
} __attribute__((packed)) vapi_enum_nat44_ei_config_flags;

#endif

#ifndef defined_vapi_type_ip4_address
#define defined_vapi_type_ip4_address
typedef u8 vapi_type_ip4_address[4];

#endif

#ifndef defined_vapi_type_ip6_address
#define defined_vapi_type_ip6_address
typedef u8 vapi_type_ip6_address[16];

#endif

#ifndef defined_vapi_union_address_union
#define defined_vapi_union_address_union
typedef union {
  vapi_type_ip4_address ip4;
  vapi_type_ip6_address ip6;
} vapi_union_address_union;

#endif

#ifndef defined_vapi_type_prefix_matcher
#define defined_vapi_type_prefix_matcher
typedef struct __attribute__((__packed__)) {
  u8 le;
  u8 ge;
} vapi_type_prefix_matcher;

static inline void vapi_type_prefix_matcher_hton(vapi_type_prefix_matcher *msg)
{

}

static inline void vapi_type_prefix_matcher_ntoh(vapi_type_prefix_matcher *msg)
{

}
#endif

#ifndef defined_vapi_type_nat_timeouts
#define defined_vapi_type_nat_timeouts
typedef struct __attribute__((__packed__)) {
  u32 udp;
  u32 tcp_established;
  u32 tcp_transitory;
  u32 icmp;
} vapi_type_nat_timeouts;

static inline void vapi_type_nat_timeouts_hton(vapi_type_nat_timeouts *msg)
{
  msg->udp = htobe32(msg->udp);
  msg->tcp_established = htobe32(msg->tcp_established);
  msg->tcp_transitory = htobe32(msg->tcp_transitory);
  msg->icmp = htobe32(msg->icmp);
}

static inline void vapi_type_nat_timeouts_ntoh(vapi_type_nat_timeouts *msg)
{
  msg->udp = be32toh(msg->udp);
  msg->tcp_established = be32toh(msg->tcp_established);
  msg->tcp_transitory = be32toh(msg->tcp_transitory);
  msg->icmp = be32toh(msg->icmp);
}
#endif

#ifndef defined_vapi_type_address
#define defined_vapi_type_address
typedef struct __attribute__((__packed__)) {
  vapi_enum_address_family af;
  vapi_union_address_union un;
} vapi_type_address;

static inline void vapi_type_address_hton(vapi_type_address *msg)
{

}

static inline void vapi_type_address_ntoh(vapi_type_address *msg)
{

}
#endif

#ifndef defined_vapi_type_prefix
#define defined_vapi_type_prefix
typedef struct __attribute__((__packed__)) {
  vapi_type_address address;
  u8 len;
} vapi_type_prefix;

static inline void vapi_type_prefix_hton(vapi_type_prefix *msg)
{

}

static inline void vapi_type_prefix_ntoh(vapi_type_prefix *msg)
{

}
#endif

#ifndef defined_vapi_type_ip4_address_and_mask
#define defined_vapi_type_ip4_address_and_mask
typedef struct __attribute__((__packed__)) {
  vapi_type_ip4_address addr;
  vapi_type_ip4_address mask;
} vapi_type_ip4_address_and_mask;

static inline void vapi_type_ip4_address_and_mask_hton(vapi_type_ip4_address_and_mask *msg)
{

}

static inline void vapi_type_ip4_address_and_mask_ntoh(vapi_type_ip4_address_and_mask *msg)
{

}
#endif

#ifndef defined_vapi_type_ip6_address_and_mask
#define defined_vapi_type_ip6_address_and_mask
typedef struct __attribute__((__packed__)) {
  vapi_type_ip6_address addr;
  vapi_type_ip6_address mask;
} vapi_type_ip6_address_and_mask;

static inline void vapi_type_ip6_address_and_mask_hton(vapi_type_ip6_address_and_mask *msg)
{

}

static inline void vapi_type_ip6_address_and_mask_ntoh(vapi_type_ip6_address_and_mask *msg)
{

}
#endif

#ifndef defined_vapi_type_mprefix
#define defined_vapi_type_mprefix
typedef struct __attribute__((__packed__)) {
  vapi_enum_address_family af;
  u16 grp_address_length;
  vapi_union_address_union grp_address;
  vapi_union_address_union src_address;
} vapi_type_mprefix;

static inline void vapi_type_mprefix_hton(vapi_type_mprefix *msg)
{
  msg->grp_address_length = htobe16(msg->grp_address_length);
}

static inline void vapi_type_mprefix_ntoh(vapi_type_mprefix *msg)
{
  msg->grp_address_length = be16toh(msg->grp_address_length);
}
#endif

#ifndef defined_vapi_type_ip6_prefix
#define defined_vapi_type_ip6_prefix
typedef struct __attribute__((__packed__)) {
  vapi_type_ip6_address address;
  u8 len;
} vapi_type_ip6_prefix;

static inline void vapi_type_ip6_prefix_hton(vapi_type_ip6_prefix *msg)
{

}

static inline void vapi_type_ip6_prefix_ntoh(vapi_type_ip6_prefix *msg)
{

}
#endif

#ifndef defined_vapi_type_ip4_prefix
#define defined_vapi_type_ip4_prefix
typedef struct __attribute__((__packed__)) {
  vapi_type_ip4_address address;
  u8 len;
} vapi_type_ip4_prefix;

static inline void vapi_type_ip4_prefix_hton(vapi_type_ip4_prefix *msg)
{

}

static inline void vapi_type_ip4_prefix_ntoh(vapi_type_ip4_prefix *msg)
{

}
#endif

#ifndef defined_vapi_type_interface_index
#define defined_vapi_type_interface_index
typedef u32 vapi_type_interface_index;

#endif

#ifndef defined_vapi_type_address_with_prefix
#define defined_vapi_type_address_with_prefix
typedef vapi_type_prefix vapi_type_address_with_prefix;

#endif

#ifndef defined_vapi_type_ip4_address_with_prefix
#define defined_vapi_type_ip4_address_with_prefix
typedef vapi_type_ip4_prefix vapi_type_ip4_address_with_prefix;

#endif

#ifndef defined_vapi_type_ip6_address_with_prefix
#define defined_vapi_type_ip6_address_with_prefix
typedef vapi_type_ip6_prefix vapi_type_ip6_address_with_prefix;

#endif

#ifndef defined_vapi_msg_nat44_ei_plugin_enable_disable_reply
#define defined_vapi_msg_nat44_ei_plugin_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_plugin_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_plugin_enable_disable_reply payload;
} vapi_msg_nat44_ei_plugin_enable_disable_reply;

static inline void vapi_msg_nat44_ei_plugin_enable_disable_reply_payload_hton(vapi_payload_nat44_ei_plugin_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_plugin_enable_disable_reply_payload_ntoh(vapi_payload_nat44_ei_plugin_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_plugin_enable_disable_reply_hton(vapi_msg_nat44_ei_plugin_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_plugin_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_plugin_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_plugin_enable_disable_reply_ntoh(vapi_msg_nat44_ei_plugin_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_plugin_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_plugin_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_plugin_enable_disable_reply_msg_size(vapi_msg_nat44_ei_plugin_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_plugin_enable_disable_reply_msg_size(vapi_msg_nat44_ei_plugin_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_plugin_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_plugin_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_plugin_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_plugin_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_plugin_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_plugin_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_plugin_enable_disable_reply()
{
  static const char name[] = "nat44_ei_plugin_enable_disable_reply";
  static const char name_with_crc[] = "nat44_ei_plugin_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_plugin_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_plugin_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_plugin_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_plugin_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_plugin_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_plugin_enable_disable_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_plugin_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_plugin_enable_disable_reply", vapi_msg_id_nat44_ei_plugin_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_plugin_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_plugin_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_plugin_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_plugin_enable_disable
#define defined_vapi_msg_nat44_ei_plugin_enable_disable
typedef struct __attribute__ ((__packed__)) {
  u32 inside_vrf;
  u32 outside_vrf;
  u32 users;
  u32 user_memory;
  u32 sessions;
  u32 session_memory;
  u32 user_sessions;
  bool enable;
  vapi_enum_nat44_ei_config_flags flags; 
} vapi_payload_nat44_ei_plugin_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_plugin_enable_disable payload;
} vapi_msg_nat44_ei_plugin_enable_disable;

static inline void vapi_msg_nat44_ei_plugin_enable_disable_payload_hton(vapi_payload_nat44_ei_plugin_enable_disable *payload)
{
  payload->inside_vrf = htobe32(payload->inside_vrf);
  payload->outside_vrf = htobe32(payload->outside_vrf);
  payload->users = htobe32(payload->users);
  payload->user_memory = htobe32(payload->user_memory);
  payload->sessions = htobe32(payload->sessions);
  payload->session_memory = htobe32(payload->session_memory);
  payload->user_sessions = htobe32(payload->user_sessions);
}

static inline void vapi_msg_nat44_ei_plugin_enable_disable_payload_ntoh(vapi_payload_nat44_ei_plugin_enable_disable *payload)
{
  payload->inside_vrf = be32toh(payload->inside_vrf);
  payload->outside_vrf = be32toh(payload->outside_vrf);
  payload->users = be32toh(payload->users);
  payload->user_memory = be32toh(payload->user_memory);
  payload->sessions = be32toh(payload->sessions);
  payload->session_memory = be32toh(payload->session_memory);
  payload->user_sessions = be32toh(payload->user_sessions);
}

static inline void vapi_msg_nat44_ei_plugin_enable_disable_hton(vapi_msg_nat44_ei_plugin_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_plugin_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_plugin_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_plugin_enable_disable_ntoh(vapi_msg_nat44_ei_plugin_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_plugin_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_plugin_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_plugin_enable_disable_msg_size(vapi_msg_nat44_ei_plugin_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_plugin_enable_disable_msg_size(vapi_msg_nat44_ei_plugin_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_plugin_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_plugin_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_plugin_enable_disable));
      return -1;
    }
  if (vapi_calc_nat44_ei_plugin_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_plugin_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_plugin_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_plugin_enable_disable* vapi_alloc_nat44_ei_plugin_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_plugin_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_plugin_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_plugin_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_plugin_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_plugin_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_plugin_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_plugin_enable_disable_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_plugin_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_plugin_enable_disable_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_plugin_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_plugin_enable_disable()
{
  static const char name[] = "nat44_ei_plugin_enable_disable";
  static const char name_with_crc[] = "nat44_ei_plugin_enable_disable_bf692144";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_plugin_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_plugin_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_plugin_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_plugin_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_plugin_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_plugin_enable_disable = vapi_register_msg(&__vapi_metadata_nat44_ei_plugin_enable_disable);
  VAPI_DBG("Assigned msg id %d to nat44_ei_plugin_enable_disable", vapi_msg_id_nat44_ei_plugin_enable_disable);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_show_running_config_reply
#define defined_vapi_msg_nat44_ei_show_running_config_reply
typedef struct __attribute__ ((__packed__)) {
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
  vapi_type_nat_timeouts timeouts;
  vapi_enum_nat_log_level log_level;
  vapi_enum_nat44_ei_config_flags flags; 
} vapi_payload_nat44_ei_show_running_config_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_show_running_config_reply payload;
} vapi_msg_nat44_ei_show_running_config_reply;

static inline void vapi_msg_nat44_ei_show_running_config_reply_payload_hton(vapi_payload_nat44_ei_show_running_config_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->inside_vrf = htobe32(payload->inside_vrf);
  payload->outside_vrf = htobe32(payload->outside_vrf);
  payload->users = htobe32(payload->users);
  payload->sessions = htobe32(payload->sessions);
  payload->user_sessions = htobe32(payload->user_sessions);
  payload->user_buckets = htobe32(payload->user_buckets);
  payload->translation_buckets = htobe32(payload->translation_buckets);
  vapi_type_nat_timeouts_hton(&payload->timeouts);
}

static inline void vapi_msg_nat44_ei_show_running_config_reply_payload_ntoh(vapi_payload_nat44_ei_show_running_config_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->inside_vrf = be32toh(payload->inside_vrf);
  payload->outside_vrf = be32toh(payload->outside_vrf);
  payload->users = be32toh(payload->users);
  payload->sessions = be32toh(payload->sessions);
  payload->user_sessions = be32toh(payload->user_sessions);
  payload->user_buckets = be32toh(payload->user_buckets);
  payload->translation_buckets = be32toh(payload->translation_buckets);
  vapi_type_nat_timeouts_ntoh(&payload->timeouts);
}

static inline void vapi_msg_nat44_ei_show_running_config_reply_hton(vapi_msg_nat44_ei_show_running_config_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_show_running_config_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_show_running_config_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_show_running_config_reply_ntoh(vapi_msg_nat44_ei_show_running_config_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_show_running_config_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_show_running_config_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_show_running_config_reply_msg_size(vapi_msg_nat44_ei_show_running_config_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_show_running_config_reply_msg_size(vapi_msg_nat44_ei_show_running_config_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_show_running_config_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_show_running_config_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_show_running_config_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_show_running_config_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_show_running_config_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_show_running_config_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_show_running_config_reply()
{
  static const char name[] = "nat44_ei_show_running_config_reply";
  static const char name_with_crc[] = "nat44_ei_show_running_config_reply_41b66a81";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_show_running_config_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_show_running_config_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_show_running_config_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_show_running_config_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_show_running_config_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_show_running_config_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_show_running_config_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_show_running_config_reply", vapi_msg_id_nat44_ei_show_running_config_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_show_running_config_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_show_running_config_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_show_running_config_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_show_running_config
#define defined_vapi_msg_nat44_ei_show_running_config
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_nat44_ei_show_running_config;

static inline void vapi_msg_nat44_ei_show_running_config_hton(vapi_msg_nat44_ei_show_running_config *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_show_running_config'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_nat44_ei_show_running_config_ntoh(vapi_msg_nat44_ei_show_running_config *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_show_running_config'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_nat44_ei_show_running_config_msg_size(vapi_msg_nat44_ei_show_running_config *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_show_running_config_msg_size(vapi_msg_nat44_ei_show_running_config *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_show_running_config) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_show_running_config' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_show_running_config));
      return -1;
    }
  if (vapi_calc_nat44_ei_show_running_config_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_show_running_config' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_show_running_config_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_show_running_config* vapi_alloc_nat44_ei_show_running_config(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_show_running_config *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_show_running_config);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_show_running_config*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_show_running_config);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_show_running_config(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_show_running_config *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_show_running_config_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_show_running_config_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_show_running_config_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_show_running_config_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_show_running_config()
{
  static const char name[] = "nat44_ei_show_running_config";
  static const char name_with_crc[] = "nat44_ei_show_running_config_51077d14";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_show_running_config = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_show_running_config_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_show_running_config_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_show_running_config_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_show_running_config = vapi_register_msg(&__vapi_metadata_nat44_ei_show_running_config);
  VAPI_DBG("Assigned msg id %d to nat44_ei_show_running_config", vapi_msg_id_nat44_ei_show_running_config);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_set_log_level_reply
#define defined_vapi_msg_nat44_ei_set_log_level_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_set_log_level_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_set_log_level_reply payload;
} vapi_msg_nat44_ei_set_log_level_reply;

static inline void vapi_msg_nat44_ei_set_log_level_reply_payload_hton(vapi_payload_nat44_ei_set_log_level_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_set_log_level_reply_payload_ntoh(vapi_payload_nat44_ei_set_log_level_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_set_log_level_reply_hton(vapi_msg_nat44_ei_set_log_level_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_log_level_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_set_log_level_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_set_log_level_reply_ntoh(vapi_msg_nat44_ei_set_log_level_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_log_level_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_set_log_level_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_set_log_level_reply_msg_size(vapi_msg_nat44_ei_set_log_level_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_set_log_level_reply_msg_size(vapi_msg_nat44_ei_set_log_level_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_set_log_level_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_log_level_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_set_log_level_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_set_log_level_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_log_level_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_set_log_level_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_set_log_level_reply()
{
  static const char name[] = "nat44_ei_set_log_level_reply";
  static const char name_with_crc[] = "nat44_ei_set_log_level_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_set_log_level_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_set_log_level_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_set_log_level_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_log_level_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_log_level_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_set_log_level_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_set_log_level_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_set_log_level_reply", vapi_msg_id_nat44_ei_set_log_level_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_set_log_level_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_set_log_level_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_set_log_level_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_set_log_level
#define defined_vapi_msg_nat44_ei_set_log_level
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_nat_log_level log_level; 
} vapi_payload_nat44_ei_set_log_level;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_set_log_level payload;
} vapi_msg_nat44_ei_set_log_level;

static inline void vapi_msg_nat44_ei_set_log_level_payload_hton(vapi_payload_nat44_ei_set_log_level *payload)
{

}

static inline void vapi_msg_nat44_ei_set_log_level_payload_ntoh(vapi_payload_nat44_ei_set_log_level *payload)
{

}

static inline void vapi_msg_nat44_ei_set_log_level_hton(vapi_msg_nat44_ei_set_log_level *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_log_level'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_set_log_level_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_set_log_level_ntoh(vapi_msg_nat44_ei_set_log_level *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_log_level'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_set_log_level_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_set_log_level_msg_size(vapi_msg_nat44_ei_set_log_level *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_set_log_level_msg_size(vapi_msg_nat44_ei_set_log_level *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_set_log_level) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_log_level' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_set_log_level));
      return -1;
    }
  if (vapi_calc_nat44_ei_set_log_level_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_log_level' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_set_log_level_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_set_log_level* vapi_alloc_nat44_ei_set_log_level(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_set_log_level *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_set_log_level);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_set_log_level*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_set_log_level);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_set_log_level(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_set_log_level *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_set_log_level_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_set_log_level_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_set_log_level_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_set_log_level_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_set_log_level()
{
  static const char name[] = "nat44_ei_set_log_level";
  static const char name_with_crc[] = "nat44_ei_set_log_level_70076bfe";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_set_log_level = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_set_log_level, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_set_log_level_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_log_level_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_log_level_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_set_log_level = vapi_register_msg(&__vapi_metadata_nat44_ei_set_log_level);
  VAPI_DBG("Assigned msg id %d to nat44_ei_set_log_level", vapi_msg_id_nat44_ei_set_log_level);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_set_workers_reply
#define defined_vapi_msg_nat44_ei_set_workers_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_set_workers_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_set_workers_reply payload;
} vapi_msg_nat44_ei_set_workers_reply;

static inline void vapi_msg_nat44_ei_set_workers_reply_payload_hton(vapi_payload_nat44_ei_set_workers_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_set_workers_reply_payload_ntoh(vapi_payload_nat44_ei_set_workers_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_set_workers_reply_hton(vapi_msg_nat44_ei_set_workers_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_workers_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_set_workers_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_set_workers_reply_ntoh(vapi_msg_nat44_ei_set_workers_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_workers_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_set_workers_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_set_workers_reply_msg_size(vapi_msg_nat44_ei_set_workers_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_set_workers_reply_msg_size(vapi_msg_nat44_ei_set_workers_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_set_workers_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_workers_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_set_workers_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_set_workers_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_workers_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_set_workers_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_set_workers_reply()
{
  static const char name[] = "nat44_ei_set_workers_reply";
  static const char name_with_crc[] = "nat44_ei_set_workers_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_set_workers_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_set_workers_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_set_workers_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_workers_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_workers_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_set_workers_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_set_workers_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_set_workers_reply", vapi_msg_id_nat44_ei_set_workers_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_set_workers_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_set_workers_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_set_workers_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_set_workers
#define defined_vapi_msg_nat44_ei_set_workers
typedef struct __attribute__ ((__packed__)) {
  u64 worker_mask; 
} vapi_payload_nat44_ei_set_workers;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_set_workers payload;
} vapi_msg_nat44_ei_set_workers;

static inline void vapi_msg_nat44_ei_set_workers_payload_hton(vapi_payload_nat44_ei_set_workers *payload)
{
  payload->worker_mask = htobe64(payload->worker_mask);
}

static inline void vapi_msg_nat44_ei_set_workers_payload_ntoh(vapi_payload_nat44_ei_set_workers *payload)
{
  payload->worker_mask = be64toh(payload->worker_mask);
}

static inline void vapi_msg_nat44_ei_set_workers_hton(vapi_msg_nat44_ei_set_workers *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_workers'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_set_workers_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_set_workers_ntoh(vapi_msg_nat44_ei_set_workers *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_workers'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_set_workers_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_set_workers_msg_size(vapi_msg_nat44_ei_set_workers *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_set_workers_msg_size(vapi_msg_nat44_ei_set_workers *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_set_workers) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_workers' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_set_workers));
      return -1;
    }
  if (vapi_calc_nat44_ei_set_workers_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_workers' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_set_workers_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_set_workers* vapi_alloc_nat44_ei_set_workers(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_set_workers *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_set_workers);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_set_workers*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_set_workers);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_set_workers(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_set_workers *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_set_workers_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_set_workers_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_set_workers_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_set_workers_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_set_workers()
{
  static const char name[] = "nat44_ei_set_workers";
  static const char name_with_crc[] = "nat44_ei_set_workers_da926638";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_set_workers = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_set_workers, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_set_workers_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_workers_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_workers_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_set_workers = vapi_register_msg(&__vapi_metadata_nat44_ei_set_workers);
  VAPI_DBG("Assigned msg id %d to nat44_ei_set_workers", vapi_msg_id_nat44_ei_set_workers);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_worker_details
#define defined_vapi_msg_nat44_ei_worker_details
typedef struct __attribute__ ((__packed__)) {
  u32 worker_index;
  u32 lcore_id;
  u8 name[64]; 
} vapi_payload_nat44_ei_worker_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_worker_details payload;
} vapi_msg_nat44_ei_worker_details;

static inline void vapi_msg_nat44_ei_worker_details_payload_hton(vapi_payload_nat44_ei_worker_details *payload)
{
  payload->worker_index = htobe32(payload->worker_index);
  payload->lcore_id = htobe32(payload->lcore_id);
}

static inline void vapi_msg_nat44_ei_worker_details_payload_ntoh(vapi_payload_nat44_ei_worker_details *payload)
{
  payload->worker_index = be32toh(payload->worker_index);
  payload->lcore_id = be32toh(payload->lcore_id);
}

static inline void vapi_msg_nat44_ei_worker_details_hton(vapi_msg_nat44_ei_worker_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_worker_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_worker_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_worker_details_ntoh(vapi_msg_nat44_ei_worker_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_worker_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_worker_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_worker_details_msg_size(vapi_msg_nat44_ei_worker_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_worker_details_msg_size(vapi_msg_nat44_ei_worker_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_worker_details) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_worker_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_worker_details));
      return -1;
    }
  if (vapi_calc_nat44_ei_worker_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_worker_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_worker_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_worker_details()
{
  static const char name[] = "nat44_ei_worker_details";
  static const char name_with_crc[] = "nat44_ei_worker_details_84bf06fc";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_worker_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_worker_details, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_worker_details_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_worker_details_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_worker_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_worker_details = vapi_register_msg(&__vapi_metadata_nat44_ei_worker_details);
  VAPI_DBG("Assigned msg id %d to nat44_ei_worker_details", vapi_msg_id_nat44_ei_worker_details);
}

static inline void vapi_set_vapi_msg_nat44_ei_worker_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_worker_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_worker_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_worker_dump
#define defined_vapi_msg_nat44_ei_worker_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_nat44_ei_worker_dump;

static inline void vapi_msg_nat44_ei_worker_dump_hton(vapi_msg_nat44_ei_worker_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_worker_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_nat44_ei_worker_dump_ntoh(vapi_msg_nat44_ei_worker_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_worker_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_nat44_ei_worker_dump_msg_size(vapi_msg_nat44_ei_worker_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_worker_dump_msg_size(vapi_msg_nat44_ei_worker_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_worker_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_worker_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_worker_dump));
      return -1;
    }
  if (vapi_calc_nat44_ei_worker_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_worker_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_worker_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_worker_dump* vapi_alloc_nat44_ei_worker_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_worker_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_worker_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_worker_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_worker_dump);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_worker_dump(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_worker_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_worker_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_worker_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_worker_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_worker_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_worker_dump()
{
  static const char name[] = "nat44_ei_worker_dump";
  static const char name_with_crc[] = "nat44_ei_worker_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_worker_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_worker_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_worker_dump_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_worker_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_worker_dump = vapi_register_msg(&__vapi_metadata_nat44_ei_worker_dump);
  VAPI_DBG("Assigned msg id %d to nat44_ei_worker_dump", vapi_msg_id_nat44_ei_worker_dump);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_ipfix_enable_disable_reply
#define defined_vapi_msg_nat44_ei_ipfix_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_ipfix_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_ipfix_enable_disable_reply payload;
} vapi_msg_nat44_ei_ipfix_enable_disable_reply;

static inline void vapi_msg_nat44_ei_ipfix_enable_disable_reply_payload_hton(vapi_payload_nat44_ei_ipfix_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_ipfix_enable_disable_reply_payload_ntoh(vapi_payload_nat44_ei_ipfix_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_ipfix_enable_disable_reply_hton(vapi_msg_nat44_ei_ipfix_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ipfix_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_ipfix_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_ipfix_enable_disable_reply_ntoh(vapi_msg_nat44_ei_ipfix_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ipfix_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_ipfix_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_ipfix_enable_disable_reply_msg_size(vapi_msg_nat44_ei_ipfix_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_ipfix_enable_disable_reply_msg_size(vapi_msg_nat44_ei_ipfix_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_ipfix_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ipfix_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_ipfix_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_ipfix_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ipfix_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_ipfix_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_ipfix_enable_disable_reply()
{
  static const char name[] = "nat44_ei_ipfix_enable_disable_reply";
  static const char name_with_crc[] = "nat44_ei_ipfix_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_ipfix_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_ipfix_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_ipfix_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ipfix_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ipfix_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_ipfix_enable_disable_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_ipfix_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_ipfix_enable_disable_reply", vapi_msg_id_nat44_ei_ipfix_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_ipfix_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_ipfix_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_ipfix_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_ipfix_enable_disable
#define defined_vapi_msg_nat44_ei_ipfix_enable_disable
typedef struct __attribute__ ((__packed__)) {
  u32 domain_id;
  u16 src_port;
  bool enable; 
} vapi_payload_nat44_ei_ipfix_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_ipfix_enable_disable payload;
} vapi_msg_nat44_ei_ipfix_enable_disable;

static inline void vapi_msg_nat44_ei_ipfix_enable_disable_payload_hton(vapi_payload_nat44_ei_ipfix_enable_disable *payload)
{
  payload->domain_id = htobe32(payload->domain_id);
  payload->src_port = htobe16(payload->src_port);
}

static inline void vapi_msg_nat44_ei_ipfix_enable_disable_payload_ntoh(vapi_payload_nat44_ei_ipfix_enable_disable *payload)
{
  payload->domain_id = be32toh(payload->domain_id);
  payload->src_port = be16toh(payload->src_port);
}

static inline void vapi_msg_nat44_ei_ipfix_enable_disable_hton(vapi_msg_nat44_ei_ipfix_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ipfix_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_ipfix_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_ipfix_enable_disable_ntoh(vapi_msg_nat44_ei_ipfix_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ipfix_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_ipfix_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_ipfix_enable_disable_msg_size(vapi_msg_nat44_ei_ipfix_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_ipfix_enable_disable_msg_size(vapi_msg_nat44_ei_ipfix_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_ipfix_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ipfix_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_ipfix_enable_disable));
      return -1;
    }
  if (vapi_calc_nat44_ei_ipfix_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ipfix_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_ipfix_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_ipfix_enable_disable* vapi_alloc_nat44_ei_ipfix_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_ipfix_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_ipfix_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_ipfix_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_ipfix_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_ipfix_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_ipfix_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_ipfix_enable_disable_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_ipfix_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_ipfix_enable_disable_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_ipfix_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_ipfix_enable_disable()
{
  static const char name[] = "nat44_ei_ipfix_enable_disable";
  static const char name_with_crc[] = "nat44_ei_ipfix_enable_disable_9af4a2d2";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_ipfix_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_ipfix_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_ipfix_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ipfix_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ipfix_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_ipfix_enable_disable = vapi_register_msg(&__vapi_metadata_nat44_ei_ipfix_enable_disable);
  VAPI_DBG("Assigned msg id %d to nat44_ei_ipfix_enable_disable", vapi_msg_id_nat44_ei_ipfix_enable_disable);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_set_timeouts_reply
#define defined_vapi_msg_nat44_ei_set_timeouts_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_set_timeouts_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_set_timeouts_reply payload;
} vapi_msg_nat44_ei_set_timeouts_reply;

static inline void vapi_msg_nat44_ei_set_timeouts_reply_payload_hton(vapi_payload_nat44_ei_set_timeouts_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_set_timeouts_reply_payload_ntoh(vapi_payload_nat44_ei_set_timeouts_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_set_timeouts_reply_hton(vapi_msg_nat44_ei_set_timeouts_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_timeouts_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_set_timeouts_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_set_timeouts_reply_ntoh(vapi_msg_nat44_ei_set_timeouts_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_timeouts_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_set_timeouts_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_set_timeouts_reply_msg_size(vapi_msg_nat44_ei_set_timeouts_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_set_timeouts_reply_msg_size(vapi_msg_nat44_ei_set_timeouts_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_set_timeouts_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_timeouts_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_set_timeouts_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_set_timeouts_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_timeouts_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_set_timeouts_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_set_timeouts_reply()
{
  static const char name[] = "nat44_ei_set_timeouts_reply";
  static const char name_with_crc[] = "nat44_ei_set_timeouts_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_set_timeouts_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_set_timeouts_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_set_timeouts_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_timeouts_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_timeouts_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_set_timeouts_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_set_timeouts_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_set_timeouts_reply", vapi_msg_id_nat44_ei_set_timeouts_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_set_timeouts_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_set_timeouts_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_set_timeouts_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_set_timeouts
#define defined_vapi_msg_nat44_ei_set_timeouts
typedef struct __attribute__ ((__packed__)) {
  u32 udp;
  u32 tcp_established;
  u32 tcp_transitory;
  u32 icmp; 
} vapi_payload_nat44_ei_set_timeouts;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_set_timeouts payload;
} vapi_msg_nat44_ei_set_timeouts;

static inline void vapi_msg_nat44_ei_set_timeouts_payload_hton(vapi_payload_nat44_ei_set_timeouts *payload)
{
  payload->udp = htobe32(payload->udp);
  payload->tcp_established = htobe32(payload->tcp_established);
  payload->tcp_transitory = htobe32(payload->tcp_transitory);
  payload->icmp = htobe32(payload->icmp);
}

static inline void vapi_msg_nat44_ei_set_timeouts_payload_ntoh(vapi_payload_nat44_ei_set_timeouts *payload)
{
  payload->udp = be32toh(payload->udp);
  payload->tcp_established = be32toh(payload->tcp_established);
  payload->tcp_transitory = be32toh(payload->tcp_transitory);
  payload->icmp = be32toh(payload->icmp);
}

static inline void vapi_msg_nat44_ei_set_timeouts_hton(vapi_msg_nat44_ei_set_timeouts *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_timeouts'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_set_timeouts_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_set_timeouts_ntoh(vapi_msg_nat44_ei_set_timeouts *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_timeouts'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_set_timeouts_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_set_timeouts_msg_size(vapi_msg_nat44_ei_set_timeouts *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_set_timeouts_msg_size(vapi_msg_nat44_ei_set_timeouts *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_set_timeouts) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_timeouts' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_set_timeouts));
      return -1;
    }
  if (vapi_calc_nat44_ei_set_timeouts_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_timeouts' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_set_timeouts_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_set_timeouts* vapi_alloc_nat44_ei_set_timeouts(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_set_timeouts *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_set_timeouts);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_set_timeouts*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_set_timeouts);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_set_timeouts(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_set_timeouts *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_set_timeouts_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_set_timeouts_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_set_timeouts_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_set_timeouts_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_set_timeouts()
{
  static const char name[] = "nat44_ei_set_timeouts";
  static const char name_with_crc[] = "nat44_ei_set_timeouts_d4746b16";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_set_timeouts = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_set_timeouts, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_set_timeouts_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_timeouts_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_timeouts_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_set_timeouts = vapi_register_msg(&__vapi_metadata_nat44_ei_set_timeouts);
  VAPI_DBG("Assigned msg id %d to nat44_ei_set_timeouts", vapi_msg_id_nat44_ei_set_timeouts);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply
#define defined_vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_set_addr_and_port_alloc_alg_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_set_addr_and_port_alloc_alg_reply payload;
} vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply;

static inline void vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply_payload_hton(vapi_payload_nat44_ei_set_addr_and_port_alloc_alg_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply_payload_ntoh(vapi_payload_nat44_ei_set_addr_and_port_alloc_alg_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply_hton(vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply_ntoh(vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_set_addr_and_port_alloc_alg_reply_msg_size(vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_set_addr_and_port_alloc_alg_reply_msg_size(vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_addr_and_port_alloc_alg_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_set_addr_and_port_alloc_alg_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_addr_and_port_alloc_alg_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_set_addr_and_port_alloc_alg_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_set_addr_and_port_alloc_alg_reply()
{
  static const char name[] = "nat44_ei_set_addr_and_port_alloc_alg_reply";
  static const char name_with_crc[] = "nat44_ei_set_addr_and_port_alloc_alg_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_set_addr_and_port_alloc_alg_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_set_addr_and_port_alloc_alg_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_set_addr_and_port_alloc_alg_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_set_addr_and_port_alloc_alg_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_set_addr_and_port_alloc_alg_reply", vapi_msg_id_nat44_ei_set_addr_and_port_alloc_alg_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_set_addr_and_port_alloc_alg_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_set_addr_and_port_alloc_alg_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_set_addr_and_port_alloc_alg
#define defined_vapi_msg_nat44_ei_set_addr_and_port_alloc_alg
typedef struct __attribute__ ((__packed__)) {
  u8 alg;
  u8 psid_offset;
  u8 psid_length;
  u16 psid;
  u16 start_port;
  u16 end_port; 
} vapi_payload_nat44_ei_set_addr_and_port_alloc_alg;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_set_addr_and_port_alloc_alg payload;
} vapi_msg_nat44_ei_set_addr_and_port_alloc_alg;

static inline void vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_payload_hton(vapi_payload_nat44_ei_set_addr_and_port_alloc_alg *payload)
{
  payload->psid = htobe16(payload->psid);
  payload->start_port = htobe16(payload->start_port);
  payload->end_port = htobe16(payload->end_port);
}

static inline void vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_payload_ntoh(vapi_payload_nat44_ei_set_addr_and_port_alloc_alg *payload)
{
  payload->psid = be16toh(payload->psid);
  payload->start_port = be16toh(payload->start_port);
  payload->end_port = be16toh(payload->end_port);
}

static inline void vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_hton(vapi_msg_nat44_ei_set_addr_and_port_alloc_alg *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_addr_and_port_alloc_alg'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_ntoh(vapi_msg_nat44_ei_set_addr_and_port_alloc_alg *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_addr_and_port_alloc_alg'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_set_addr_and_port_alloc_alg_msg_size(vapi_msg_nat44_ei_set_addr_and_port_alloc_alg *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_set_addr_and_port_alloc_alg_msg_size(vapi_msg_nat44_ei_set_addr_and_port_alloc_alg *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_set_addr_and_port_alloc_alg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_addr_and_port_alloc_alg' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_set_addr_and_port_alloc_alg));
      return -1;
    }
  if (vapi_calc_nat44_ei_set_addr_and_port_alloc_alg_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_addr_and_port_alloc_alg' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_set_addr_and_port_alloc_alg_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_set_addr_and_port_alloc_alg* vapi_alloc_nat44_ei_set_addr_and_port_alloc_alg(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_set_addr_and_port_alloc_alg *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_set_addr_and_port_alloc_alg);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_set_addr_and_port_alloc_alg*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_set_addr_and_port_alloc_alg);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_set_addr_and_port_alloc_alg(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_set_addr_and_port_alloc_alg *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_set_addr_and_port_alloc_alg_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_set_addr_and_port_alloc_alg_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_set_addr_and_port_alloc_alg()
{
  static const char name[] = "nat44_ei_set_addr_and_port_alloc_alg";
  static const char name_with_crc[] = "nat44_ei_set_addr_and_port_alloc_alg_deeb746f";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_set_addr_and_port_alloc_alg = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_set_addr_and_port_alloc_alg, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_set_addr_and_port_alloc_alg_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_set_addr_and_port_alloc_alg = vapi_register_msg(&__vapi_metadata_nat44_ei_set_addr_and_port_alloc_alg);
  VAPI_DBG("Assigned msg id %d to nat44_ei_set_addr_and_port_alloc_alg", vapi_msg_id_nat44_ei_set_addr_and_port_alloc_alg);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply
#define defined_vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u8 alg;
  u8 psid_offset;
  u8 psid_length;
  u16 psid;
  u16 start_port;
  u16 end_port; 
} vapi_payload_nat44_ei_get_addr_and_port_alloc_alg_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_get_addr_and_port_alloc_alg_reply payload;
} vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply;

static inline void vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply_payload_hton(vapi_payload_nat44_ei_get_addr_and_port_alloc_alg_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->psid = htobe16(payload->psid);
  payload->start_port = htobe16(payload->start_port);
  payload->end_port = htobe16(payload->end_port);
}

static inline void vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply_payload_ntoh(vapi_payload_nat44_ei_get_addr_and_port_alloc_alg_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->psid = be16toh(payload->psid);
  payload->start_port = be16toh(payload->start_port);
  payload->end_port = be16toh(payload->end_port);
}

static inline void vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply_hton(vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply_ntoh(vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_get_addr_and_port_alloc_alg_reply_msg_size(vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_get_addr_and_port_alloc_alg_reply_msg_size(vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_get_addr_and_port_alloc_alg_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_get_addr_and_port_alloc_alg_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_get_addr_and_port_alloc_alg_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_get_addr_and_port_alloc_alg_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_get_addr_and_port_alloc_alg_reply()
{
  static const char name[] = "nat44_ei_get_addr_and_port_alloc_alg_reply";
  static const char name_with_crc[] = "nat44_ei_get_addr_and_port_alloc_alg_reply_3607a7d0";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_get_addr_and_port_alloc_alg_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_get_addr_and_port_alloc_alg_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_get_addr_and_port_alloc_alg_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_get_addr_and_port_alloc_alg_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_get_addr_and_port_alloc_alg_reply", vapi_msg_id_nat44_ei_get_addr_and_port_alloc_alg_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_get_addr_and_port_alloc_alg_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_get_addr_and_port_alloc_alg_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_get_addr_and_port_alloc_alg
#define defined_vapi_msg_nat44_ei_get_addr_and_port_alloc_alg
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_nat44_ei_get_addr_and_port_alloc_alg;

static inline void vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_hton(vapi_msg_nat44_ei_get_addr_and_port_alloc_alg *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_get_addr_and_port_alloc_alg'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_ntoh(vapi_msg_nat44_ei_get_addr_and_port_alloc_alg *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_get_addr_and_port_alloc_alg'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_nat44_ei_get_addr_and_port_alloc_alg_msg_size(vapi_msg_nat44_ei_get_addr_and_port_alloc_alg *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_get_addr_and_port_alloc_alg_msg_size(vapi_msg_nat44_ei_get_addr_and_port_alloc_alg *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_get_addr_and_port_alloc_alg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_get_addr_and_port_alloc_alg' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_get_addr_and_port_alloc_alg));
      return -1;
    }
  if (vapi_calc_nat44_ei_get_addr_and_port_alloc_alg_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_get_addr_and_port_alloc_alg' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_get_addr_and_port_alloc_alg_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_get_addr_and_port_alloc_alg* vapi_alloc_nat44_ei_get_addr_and_port_alloc_alg(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_get_addr_and_port_alloc_alg *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_get_addr_and_port_alloc_alg);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_get_addr_and_port_alloc_alg*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_get_addr_and_port_alloc_alg);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_get_addr_and_port_alloc_alg(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_get_addr_and_port_alloc_alg *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_get_addr_and_port_alloc_alg_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_get_addr_and_port_alloc_alg_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_get_addr_and_port_alloc_alg()
{
  static const char name[] = "nat44_ei_get_addr_and_port_alloc_alg";
  static const char name_with_crc[] = "nat44_ei_get_addr_and_port_alloc_alg_51077d14";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_get_addr_and_port_alloc_alg = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_get_addr_and_port_alloc_alg_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_get_addr_and_port_alloc_alg = vapi_register_msg(&__vapi_metadata_nat44_ei_get_addr_and_port_alloc_alg);
  VAPI_DBG("Assigned msg id %d to nat44_ei_get_addr_and_port_alloc_alg", vapi_msg_id_nat44_ei_get_addr_and_port_alloc_alg);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_set_mss_clamping_reply
#define defined_vapi_msg_nat44_ei_set_mss_clamping_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_set_mss_clamping_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_set_mss_clamping_reply payload;
} vapi_msg_nat44_ei_set_mss_clamping_reply;

static inline void vapi_msg_nat44_ei_set_mss_clamping_reply_payload_hton(vapi_payload_nat44_ei_set_mss_clamping_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_set_mss_clamping_reply_payload_ntoh(vapi_payload_nat44_ei_set_mss_clamping_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_set_mss_clamping_reply_hton(vapi_msg_nat44_ei_set_mss_clamping_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_mss_clamping_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_set_mss_clamping_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_set_mss_clamping_reply_ntoh(vapi_msg_nat44_ei_set_mss_clamping_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_mss_clamping_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_set_mss_clamping_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_set_mss_clamping_reply_msg_size(vapi_msg_nat44_ei_set_mss_clamping_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_set_mss_clamping_reply_msg_size(vapi_msg_nat44_ei_set_mss_clamping_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_set_mss_clamping_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_mss_clamping_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_set_mss_clamping_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_set_mss_clamping_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_mss_clamping_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_set_mss_clamping_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_set_mss_clamping_reply()
{
  static const char name[] = "nat44_ei_set_mss_clamping_reply";
  static const char name_with_crc[] = "nat44_ei_set_mss_clamping_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_set_mss_clamping_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_set_mss_clamping_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_set_mss_clamping_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_mss_clamping_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_mss_clamping_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_set_mss_clamping_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_set_mss_clamping_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_set_mss_clamping_reply", vapi_msg_id_nat44_ei_set_mss_clamping_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_set_mss_clamping_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_set_mss_clamping_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_set_mss_clamping_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_set_mss_clamping
#define defined_vapi_msg_nat44_ei_set_mss_clamping
typedef struct __attribute__ ((__packed__)) {
  u16 mss_value;
  bool enable; 
} vapi_payload_nat44_ei_set_mss_clamping;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_set_mss_clamping payload;
} vapi_msg_nat44_ei_set_mss_clamping;

static inline void vapi_msg_nat44_ei_set_mss_clamping_payload_hton(vapi_payload_nat44_ei_set_mss_clamping *payload)
{
  payload->mss_value = htobe16(payload->mss_value);
}

static inline void vapi_msg_nat44_ei_set_mss_clamping_payload_ntoh(vapi_payload_nat44_ei_set_mss_clamping *payload)
{
  payload->mss_value = be16toh(payload->mss_value);
}

static inline void vapi_msg_nat44_ei_set_mss_clamping_hton(vapi_msg_nat44_ei_set_mss_clamping *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_mss_clamping'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_set_mss_clamping_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_set_mss_clamping_ntoh(vapi_msg_nat44_ei_set_mss_clamping *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_mss_clamping'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_set_mss_clamping_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_set_mss_clamping_msg_size(vapi_msg_nat44_ei_set_mss_clamping *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_set_mss_clamping_msg_size(vapi_msg_nat44_ei_set_mss_clamping *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_set_mss_clamping) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_mss_clamping' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_set_mss_clamping));
      return -1;
    }
  if (vapi_calc_nat44_ei_set_mss_clamping_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_mss_clamping' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_set_mss_clamping_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_set_mss_clamping* vapi_alloc_nat44_ei_set_mss_clamping(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_set_mss_clamping *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_set_mss_clamping);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_set_mss_clamping*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_set_mss_clamping);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_set_mss_clamping(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_set_mss_clamping *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_set_mss_clamping_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_set_mss_clamping_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_set_mss_clamping_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_set_mss_clamping_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_set_mss_clamping()
{
  static const char name[] = "nat44_ei_set_mss_clamping";
  static const char name_with_crc[] = "nat44_ei_set_mss_clamping_25e90abb";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_set_mss_clamping = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_set_mss_clamping, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_set_mss_clamping_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_mss_clamping_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_mss_clamping_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_set_mss_clamping = vapi_register_msg(&__vapi_metadata_nat44_ei_set_mss_clamping);
  VAPI_DBG("Assigned msg id %d to nat44_ei_set_mss_clamping", vapi_msg_id_nat44_ei_set_mss_clamping);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_get_mss_clamping_reply
#define defined_vapi_msg_nat44_ei_get_mss_clamping_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u16 mss_value;
  bool enable; 
} vapi_payload_nat44_ei_get_mss_clamping_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_get_mss_clamping_reply payload;
} vapi_msg_nat44_ei_get_mss_clamping_reply;

static inline void vapi_msg_nat44_ei_get_mss_clamping_reply_payload_hton(vapi_payload_nat44_ei_get_mss_clamping_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->mss_value = htobe16(payload->mss_value);
}

static inline void vapi_msg_nat44_ei_get_mss_clamping_reply_payload_ntoh(vapi_payload_nat44_ei_get_mss_clamping_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->mss_value = be16toh(payload->mss_value);
}

static inline void vapi_msg_nat44_ei_get_mss_clamping_reply_hton(vapi_msg_nat44_ei_get_mss_clamping_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_get_mss_clamping_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_get_mss_clamping_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_get_mss_clamping_reply_ntoh(vapi_msg_nat44_ei_get_mss_clamping_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_get_mss_clamping_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_get_mss_clamping_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_get_mss_clamping_reply_msg_size(vapi_msg_nat44_ei_get_mss_clamping_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_get_mss_clamping_reply_msg_size(vapi_msg_nat44_ei_get_mss_clamping_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_get_mss_clamping_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_get_mss_clamping_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_get_mss_clamping_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_get_mss_clamping_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_get_mss_clamping_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_get_mss_clamping_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_get_mss_clamping_reply()
{
  static const char name[] = "nat44_ei_get_mss_clamping_reply";
  static const char name_with_crc[] = "nat44_ei_get_mss_clamping_reply_1c0b2a78";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_get_mss_clamping_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_get_mss_clamping_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_get_mss_clamping_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_get_mss_clamping_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_get_mss_clamping_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_get_mss_clamping_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_get_mss_clamping_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_get_mss_clamping_reply", vapi_msg_id_nat44_ei_get_mss_clamping_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_get_mss_clamping_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_get_mss_clamping_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_get_mss_clamping_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_get_mss_clamping
#define defined_vapi_msg_nat44_ei_get_mss_clamping
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_nat44_ei_get_mss_clamping;

static inline void vapi_msg_nat44_ei_get_mss_clamping_hton(vapi_msg_nat44_ei_get_mss_clamping *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_get_mss_clamping'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_nat44_ei_get_mss_clamping_ntoh(vapi_msg_nat44_ei_get_mss_clamping *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_get_mss_clamping'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_nat44_ei_get_mss_clamping_msg_size(vapi_msg_nat44_ei_get_mss_clamping *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_get_mss_clamping_msg_size(vapi_msg_nat44_ei_get_mss_clamping *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_get_mss_clamping) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_get_mss_clamping' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_get_mss_clamping));
      return -1;
    }
  if (vapi_calc_nat44_ei_get_mss_clamping_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_get_mss_clamping' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_get_mss_clamping_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_get_mss_clamping* vapi_alloc_nat44_ei_get_mss_clamping(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_get_mss_clamping *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_get_mss_clamping);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_get_mss_clamping*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_get_mss_clamping);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_get_mss_clamping(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_get_mss_clamping *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_get_mss_clamping_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_get_mss_clamping_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_get_mss_clamping_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_get_mss_clamping_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_get_mss_clamping()
{
  static const char name[] = "nat44_ei_get_mss_clamping";
  static const char name_with_crc[] = "nat44_ei_get_mss_clamping_51077d14";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_get_mss_clamping = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_get_mss_clamping_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_get_mss_clamping_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_get_mss_clamping_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_get_mss_clamping = vapi_register_msg(&__vapi_metadata_nat44_ei_get_mss_clamping);
  VAPI_DBG("Assigned msg id %d to nat44_ei_get_mss_clamping", vapi_msg_id_nat44_ei_get_mss_clamping);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_ha_set_listener_reply
#define defined_vapi_msg_nat44_ei_ha_set_listener_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_ha_set_listener_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_ha_set_listener_reply payload;
} vapi_msg_nat44_ei_ha_set_listener_reply;

static inline void vapi_msg_nat44_ei_ha_set_listener_reply_payload_hton(vapi_payload_nat44_ei_ha_set_listener_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_ha_set_listener_reply_payload_ntoh(vapi_payload_nat44_ei_ha_set_listener_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_ha_set_listener_reply_hton(vapi_msg_nat44_ei_ha_set_listener_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_set_listener_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_ha_set_listener_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_ha_set_listener_reply_ntoh(vapi_msg_nat44_ei_ha_set_listener_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_set_listener_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_ha_set_listener_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_ha_set_listener_reply_msg_size(vapi_msg_nat44_ei_ha_set_listener_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_ha_set_listener_reply_msg_size(vapi_msg_nat44_ei_ha_set_listener_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_ha_set_listener_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_set_listener_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_ha_set_listener_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_ha_set_listener_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_set_listener_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_ha_set_listener_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_ha_set_listener_reply()
{
  static const char name[] = "nat44_ei_ha_set_listener_reply";
  static const char name_with_crc[] = "nat44_ei_ha_set_listener_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_ha_set_listener_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_ha_set_listener_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_ha_set_listener_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_set_listener_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_set_listener_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_ha_set_listener_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_ha_set_listener_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_ha_set_listener_reply", vapi_msg_id_nat44_ei_ha_set_listener_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_ha_set_listener_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_ha_set_listener_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_ha_set_listener_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_ha_set_listener
#define defined_vapi_msg_nat44_ei_ha_set_listener
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address ip_address;
  u16 port;
  u32 path_mtu; 
} vapi_payload_nat44_ei_ha_set_listener;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_ha_set_listener payload;
} vapi_msg_nat44_ei_ha_set_listener;

static inline void vapi_msg_nat44_ei_ha_set_listener_payload_hton(vapi_payload_nat44_ei_ha_set_listener *payload)
{
  payload->port = htobe16(payload->port);
  payload->path_mtu = htobe32(payload->path_mtu);
}

static inline void vapi_msg_nat44_ei_ha_set_listener_payload_ntoh(vapi_payload_nat44_ei_ha_set_listener *payload)
{
  payload->port = be16toh(payload->port);
  payload->path_mtu = be32toh(payload->path_mtu);
}

static inline void vapi_msg_nat44_ei_ha_set_listener_hton(vapi_msg_nat44_ei_ha_set_listener *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_set_listener'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_ha_set_listener_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_ha_set_listener_ntoh(vapi_msg_nat44_ei_ha_set_listener *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_set_listener'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_ha_set_listener_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_ha_set_listener_msg_size(vapi_msg_nat44_ei_ha_set_listener *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_ha_set_listener_msg_size(vapi_msg_nat44_ei_ha_set_listener *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_ha_set_listener) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_set_listener' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_ha_set_listener));
      return -1;
    }
  if (vapi_calc_nat44_ei_ha_set_listener_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_set_listener' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_ha_set_listener_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_ha_set_listener* vapi_alloc_nat44_ei_ha_set_listener(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_ha_set_listener *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_ha_set_listener);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_ha_set_listener*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_ha_set_listener);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_ha_set_listener(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_ha_set_listener *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_ha_set_listener_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_ha_set_listener_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_ha_set_listener_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_ha_set_listener_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_ha_set_listener()
{
  static const char name[] = "nat44_ei_ha_set_listener";
  static const char name_with_crc[] = "nat44_ei_ha_set_listener_e4a8cb4e";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_ha_set_listener = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_ha_set_listener, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_ha_set_listener_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_set_listener_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_set_listener_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_ha_set_listener = vapi_register_msg(&__vapi_metadata_nat44_ei_ha_set_listener);
  VAPI_DBG("Assigned msg id %d to nat44_ei_ha_set_listener", vapi_msg_id_nat44_ei_ha_set_listener);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_ha_set_failover_reply
#define defined_vapi_msg_nat44_ei_ha_set_failover_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_ha_set_failover_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_ha_set_failover_reply payload;
} vapi_msg_nat44_ei_ha_set_failover_reply;

static inline void vapi_msg_nat44_ei_ha_set_failover_reply_payload_hton(vapi_payload_nat44_ei_ha_set_failover_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_ha_set_failover_reply_payload_ntoh(vapi_payload_nat44_ei_ha_set_failover_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_ha_set_failover_reply_hton(vapi_msg_nat44_ei_ha_set_failover_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_set_failover_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_ha_set_failover_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_ha_set_failover_reply_ntoh(vapi_msg_nat44_ei_ha_set_failover_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_set_failover_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_ha_set_failover_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_ha_set_failover_reply_msg_size(vapi_msg_nat44_ei_ha_set_failover_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_ha_set_failover_reply_msg_size(vapi_msg_nat44_ei_ha_set_failover_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_ha_set_failover_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_set_failover_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_ha_set_failover_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_ha_set_failover_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_set_failover_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_ha_set_failover_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_ha_set_failover_reply()
{
  static const char name[] = "nat44_ei_ha_set_failover_reply";
  static const char name_with_crc[] = "nat44_ei_ha_set_failover_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_ha_set_failover_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_ha_set_failover_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_ha_set_failover_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_set_failover_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_set_failover_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_ha_set_failover_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_ha_set_failover_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_ha_set_failover_reply", vapi_msg_id_nat44_ei_ha_set_failover_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_ha_set_failover_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_ha_set_failover_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_ha_set_failover_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_ha_set_failover
#define defined_vapi_msg_nat44_ei_ha_set_failover
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address ip_address;
  u16 port;
  u32 session_refresh_interval; 
} vapi_payload_nat44_ei_ha_set_failover;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_ha_set_failover payload;
} vapi_msg_nat44_ei_ha_set_failover;

static inline void vapi_msg_nat44_ei_ha_set_failover_payload_hton(vapi_payload_nat44_ei_ha_set_failover *payload)
{
  payload->port = htobe16(payload->port);
  payload->session_refresh_interval = htobe32(payload->session_refresh_interval);
}

static inline void vapi_msg_nat44_ei_ha_set_failover_payload_ntoh(vapi_payload_nat44_ei_ha_set_failover *payload)
{
  payload->port = be16toh(payload->port);
  payload->session_refresh_interval = be32toh(payload->session_refresh_interval);
}

static inline void vapi_msg_nat44_ei_ha_set_failover_hton(vapi_msg_nat44_ei_ha_set_failover *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_set_failover'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_ha_set_failover_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_ha_set_failover_ntoh(vapi_msg_nat44_ei_ha_set_failover *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_set_failover'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_ha_set_failover_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_ha_set_failover_msg_size(vapi_msg_nat44_ei_ha_set_failover *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_ha_set_failover_msg_size(vapi_msg_nat44_ei_ha_set_failover *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_ha_set_failover) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_set_failover' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_ha_set_failover));
      return -1;
    }
  if (vapi_calc_nat44_ei_ha_set_failover_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_set_failover' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_ha_set_failover_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_ha_set_failover* vapi_alloc_nat44_ei_ha_set_failover(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_ha_set_failover *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_ha_set_failover);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_ha_set_failover*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_ha_set_failover);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_ha_set_failover(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_ha_set_failover *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_ha_set_failover_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_ha_set_failover_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_ha_set_failover_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_ha_set_failover_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_ha_set_failover()
{
  static const char name[] = "nat44_ei_ha_set_failover";
  static const char name_with_crc[] = "nat44_ei_ha_set_failover_718246af";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_ha_set_failover = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_ha_set_failover, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_ha_set_failover_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_set_failover_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_set_failover_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_ha_set_failover = vapi_register_msg(&__vapi_metadata_nat44_ei_ha_set_failover);
  VAPI_DBG("Assigned msg id %d to nat44_ei_ha_set_failover", vapi_msg_id_nat44_ei_ha_set_failover);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_ha_get_listener_reply
#define defined_vapi_msg_nat44_ei_ha_get_listener_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_ip4_address ip_address;
  u16 port;
  u32 path_mtu; 
} vapi_payload_nat44_ei_ha_get_listener_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_ha_get_listener_reply payload;
} vapi_msg_nat44_ei_ha_get_listener_reply;

static inline void vapi_msg_nat44_ei_ha_get_listener_reply_payload_hton(vapi_payload_nat44_ei_ha_get_listener_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->port = htobe16(payload->port);
  payload->path_mtu = htobe32(payload->path_mtu);
}

static inline void vapi_msg_nat44_ei_ha_get_listener_reply_payload_ntoh(vapi_payload_nat44_ei_ha_get_listener_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->port = be16toh(payload->port);
  payload->path_mtu = be32toh(payload->path_mtu);
}

static inline void vapi_msg_nat44_ei_ha_get_listener_reply_hton(vapi_msg_nat44_ei_ha_get_listener_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_get_listener_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_ha_get_listener_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_ha_get_listener_reply_ntoh(vapi_msg_nat44_ei_ha_get_listener_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_get_listener_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_ha_get_listener_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_ha_get_listener_reply_msg_size(vapi_msg_nat44_ei_ha_get_listener_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_ha_get_listener_reply_msg_size(vapi_msg_nat44_ei_ha_get_listener_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_ha_get_listener_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_get_listener_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_ha_get_listener_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_ha_get_listener_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_get_listener_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_ha_get_listener_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_ha_get_listener_reply()
{
  static const char name[] = "nat44_ei_ha_get_listener_reply";
  static const char name_with_crc[] = "nat44_ei_ha_get_listener_reply_123ea41f";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_ha_get_listener_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_ha_get_listener_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_ha_get_listener_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_get_listener_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_get_listener_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_ha_get_listener_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_ha_get_listener_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_ha_get_listener_reply", vapi_msg_id_nat44_ei_ha_get_listener_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_ha_get_listener_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_ha_get_listener_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_ha_get_listener_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_ha_get_listener
#define defined_vapi_msg_nat44_ei_ha_get_listener
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_nat44_ei_ha_get_listener;

static inline void vapi_msg_nat44_ei_ha_get_listener_hton(vapi_msg_nat44_ei_ha_get_listener *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_get_listener'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_nat44_ei_ha_get_listener_ntoh(vapi_msg_nat44_ei_ha_get_listener *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_get_listener'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_nat44_ei_ha_get_listener_msg_size(vapi_msg_nat44_ei_ha_get_listener *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_ha_get_listener_msg_size(vapi_msg_nat44_ei_ha_get_listener *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_ha_get_listener) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_get_listener' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_ha_get_listener));
      return -1;
    }
  if (vapi_calc_nat44_ei_ha_get_listener_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_get_listener' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_ha_get_listener_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_ha_get_listener* vapi_alloc_nat44_ei_ha_get_listener(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_ha_get_listener *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_ha_get_listener);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_ha_get_listener*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_ha_get_listener);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_ha_get_listener(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_ha_get_listener *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_ha_get_listener_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_ha_get_listener_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_ha_get_listener_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_ha_get_listener_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_ha_get_listener()
{
  static const char name[] = "nat44_ei_ha_get_listener";
  static const char name_with_crc[] = "nat44_ei_ha_get_listener_51077d14";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_ha_get_listener = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_ha_get_listener_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_get_listener_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_get_listener_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_ha_get_listener = vapi_register_msg(&__vapi_metadata_nat44_ei_ha_get_listener);
  VAPI_DBG("Assigned msg id %d to nat44_ei_ha_get_listener", vapi_msg_id_nat44_ei_ha_get_listener);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_ha_get_failover_reply
#define defined_vapi_msg_nat44_ei_ha_get_failover_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_ip4_address ip_address;
  u16 port;
  u32 session_refresh_interval; 
} vapi_payload_nat44_ei_ha_get_failover_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_ha_get_failover_reply payload;
} vapi_msg_nat44_ei_ha_get_failover_reply;

static inline void vapi_msg_nat44_ei_ha_get_failover_reply_payload_hton(vapi_payload_nat44_ei_ha_get_failover_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->port = htobe16(payload->port);
  payload->session_refresh_interval = htobe32(payload->session_refresh_interval);
}

static inline void vapi_msg_nat44_ei_ha_get_failover_reply_payload_ntoh(vapi_payload_nat44_ei_ha_get_failover_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->port = be16toh(payload->port);
  payload->session_refresh_interval = be32toh(payload->session_refresh_interval);
}

static inline void vapi_msg_nat44_ei_ha_get_failover_reply_hton(vapi_msg_nat44_ei_ha_get_failover_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_get_failover_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_ha_get_failover_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_ha_get_failover_reply_ntoh(vapi_msg_nat44_ei_ha_get_failover_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_get_failover_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_ha_get_failover_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_ha_get_failover_reply_msg_size(vapi_msg_nat44_ei_ha_get_failover_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_ha_get_failover_reply_msg_size(vapi_msg_nat44_ei_ha_get_failover_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_ha_get_failover_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_get_failover_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_ha_get_failover_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_ha_get_failover_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_get_failover_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_ha_get_failover_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_ha_get_failover_reply()
{
  static const char name[] = "nat44_ei_ha_get_failover_reply";
  static const char name_with_crc[] = "nat44_ei_ha_get_failover_reply_a67d8752";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_ha_get_failover_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_ha_get_failover_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_ha_get_failover_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_get_failover_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_get_failover_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_ha_get_failover_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_ha_get_failover_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_ha_get_failover_reply", vapi_msg_id_nat44_ei_ha_get_failover_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_ha_get_failover_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_ha_get_failover_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_ha_get_failover_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_ha_get_failover
#define defined_vapi_msg_nat44_ei_ha_get_failover
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_nat44_ei_ha_get_failover;

static inline void vapi_msg_nat44_ei_ha_get_failover_hton(vapi_msg_nat44_ei_ha_get_failover *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_get_failover'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_nat44_ei_ha_get_failover_ntoh(vapi_msg_nat44_ei_ha_get_failover *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_get_failover'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_nat44_ei_ha_get_failover_msg_size(vapi_msg_nat44_ei_ha_get_failover *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_ha_get_failover_msg_size(vapi_msg_nat44_ei_ha_get_failover *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_ha_get_failover) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_get_failover' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_ha_get_failover));
      return -1;
    }
  if (vapi_calc_nat44_ei_ha_get_failover_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_get_failover' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_ha_get_failover_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_ha_get_failover* vapi_alloc_nat44_ei_ha_get_failover(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_ha_get_failover *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_ha_get_failover);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_ha_get_failover*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_ha_get_failover);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_ha_get_failover(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_ha_get_failover *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_ha_get_failover_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_ha_get_failover_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_ha_get_failover_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_ha_get_failover_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_ha_get_failover()
{
  static const char name[] = "nat44_ei_ha_get_failover";
  static const char name_with_crc[] = "nat44_ei_ha_get_failover_51077d14";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_ha_get_failover = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_ha_get_failover_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_get_failover_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_get_failover_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_ha_get_failover = vapi_register_msg(&__vapi_metadata_nat44_ei_ha_get_failover);
  VAPI_DBG("Assigned msg id %d to nat44_ei_ha_get_failover", vapi_msg_id_nat44_ei_ha_get_failover);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_ha_flush_reply
#define defined_vapi_msg_nat44_ei_ha_flush_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_ha_flush_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_ha_flush_reply payload;
} vapi_msg_nat44_ei_ha_flush_reply;

static inline void vapi_msg_nat44_ei_ha_flush_reply_payload_hton(vapi_payload_nat44_ei_ha_flush_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_ha_flush_reply_payload_ntoh(vapi_payload_nat44_ei_ha_flush_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_ha_flush_reply_hton(vapi_msg_nat44_ei_ha_flush_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_flush_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_ha_flush_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_ha_flush_reply_ntoh(vapi_msg_nat44_ei_ha_flush_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_flush_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_ha_flush_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_ha_flush_reply_msg_size(vapi_msg_nat44_ei_ha_flush_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_ha_flush_reply_msg_size(vapi_msg_nat44_ei_ha_flush_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_ha_flush_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_flush_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_ha_flush_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_ha_flush_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_flush_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_ha_flush_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_ha_flush_reply()
{
  static const char name[] = "nat44_ei_ha_flush_reply";
  static const char name_with_crc[] = "nat44_ei_ha_flush_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_ha_flush_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_ha_flush_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_ha_flush_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_flush_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_flush_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_ha_flush_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_ha_flush_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_ha_flush_reply", vapi_msg_id_nat44_ei_ha_flush_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_ha_flush_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_ha_flush_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_ha_flush_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_ha_flush
#define defined_vapi_msg_nat44_ei_ha_flush
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_nat44_ei_ha_flush;

static inline void vapi_msg_nat44_ei_ha_flush_hton(vapi_msg_nat44_ei_ha_flush *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_flush'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_nat44_ei_ha_flush_ntoh(vapi_msg_nat44_ei_ha_flush *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_flush'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_nat44_ei_ha_flush_msg_size(vapi_msg_nat44_ei_ha_flush *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_ha_flush_msg_size(vapi_msg_nat44_ei_ha_flush *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_ha_flush) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_flush' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_ha_flush));
      return -1;
    }
  if (vapi_calc_nat44_ei_ha_flush_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_flush' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_ha_flush_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_ha_flush* vapi_alloc_nat44_ei_ha_flush(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_ha_flush *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_ha_flush);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_ha_flush*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_ha_flush);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_ha_flush(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_ha_flush *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_ha_flush_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_ha_flush_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_ha_flush_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_ha_flush_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_ha_flush()
{
  static const char name[] = "nat44_ei_ha_flush";
  static const char name_with_crc[] = "nat44_ei_ha_flush_51077d14";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_ha_flush = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_ha_flush_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_flush_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_flush_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_ha_flush = vapi_register_msg(&__vapi_metadata_nat44_ei_ha_flush);
  VAPI_DBG("Assigned msg id %d to nat44_ei_ha_flush", vapi_msg_id_nat44_ei_ha_flush);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_ha_resync_reply
#define defined_vapi_msg_nat44_ei_ha_resync_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_ha_resync_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_ha_resync_reply payload;
} vapi_msg_nat44_ei_ha_resync_reply;

static inline void vapi_msg_nat44_ei_ha_resync_reply_payload_hton(vapi_payload_nat44_ei_ha_resync_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_ha_resync_reply_payload_ntoh(vapi_payload_nat44_ei_ha_resync_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_ha_resync_reply_hton(vapi_msg_nat44_ei_ha_resync_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_resync_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_ha_resync_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_ha_resync_reply_ntoh(vapi_msg_nat44_ei_ha_resync_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_resync_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_ha_resync_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_ha_resync_reply_msg_size(vapi_msg_nat44_ei_ha_resync_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_ha_resync_reply_msg_size(vapi_msg_nat44_ei_ha_resync_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_ha_resync_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_resync_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_ha_resync_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_ha_resync_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_resync_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_ha_resync_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_ha_resync_reply()
{
  static const char name[] = "nat44_ei_ha_resync_reply";
  static const char name_with_crc[] = "nat44_ei_ha_resync_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_ha_resync_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_ha_resync_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_ha_resync_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_resync_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_resync_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_ha_resync_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_ha_resync_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_ha_resync_reply", vapi_msg_id_nat44_ei_ha_resync_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_ha_resync_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_ha_resync_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_ha_resync_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_ha_resync
#define defined_vapi_msg_nat44_ei_ha_resync
typedef struct __attribute__ ((__packed__)) {
  u8 want_resync_event;
  u32 pid; 
} vapi_payload_nat44_ei_ha_resync;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_ha_resync payload;
} vapi_msg_nat44_ei_ha_resync;

static inline void vapi_msg_nat44_ei_ha_resync_payload_hton(vapi_payload_nat44_ei_ha_resync *payload)
{
  payload->pid = htobe32(payload->pid);
}

static inline void vapi_msg_nat44_ei_ha_resync_payload_ntoh(vapi_payload_nat44_ei_ha_resync *payload)
{
  payload->pid = be32toh(payload->pid);
}

static inline void vapi_msg_nat44_ei_ha_resync_hton(vapi_msg_nat44_ei_ha_resync *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_resync'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_ha_resync_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_ha_resync_ntoh(vapi_msg_nat44_ei_ha_resync *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_resync'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_ha_resync_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_ha_resync_msg_size(vapi_msg_nat44_ei_ha_resync *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_ha_resync_msg_size(vapi_msg_nat44_ei_ha_resync *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_ha_resync) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_resync' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_ha_resync));
      return -1;
    }
  if (vapi_calc_nat44_ei_ha_resync_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_resync' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_ha_resync_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_ha_resync* vapi_alloc_nat44_ei_ha_resync(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_ha_resync *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_ha_resync);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_ha_resync*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_ha_resync);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_ha_resync(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_ha_resync *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_ha_resync_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_ha_resync_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_ha_resync_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_ha_resync_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_ha_resync()
{
  static const char name[] = "nat44_ei_ha_resync";
  static const char name_with_crc[] = "nat44_ei_ha_resync_c8ab9e03";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_ha_resync = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_ha_resync, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_ha_resync_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_resync_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_resync_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_ha_resync = vapi_register_msg(&__vapi_metadata_nat44_ei_ha_resync);
  VAPI_DBG("Assigned msg id %d to nat44_ei_ha_resync", vapi_msg_id_nat44_ei_ha_resync);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_ha_resync_completed_event
#define defined_vapi_msg_nat44_ei_ha_resync_completed_event
typedef struct __attribute__ ((__packed__)) {
  u16 _vl_msg_id;
  u32 client_index;
  u32 pid;
  u32 missed_count; 
} vapi_payload_nat44_ei_ha_resync_completed_event;

typedef struct __attribute__ ((__packed__)) {

  vapi_payload_nat44_ei_ha_resync_completed_event payload;
} vapi_msg_nat44_ei_ha_resync_completed_event;

static inline void vapi_msg_nat44_ei_ha_resync_completed_event_payload_hton(vapi_payload_nat44_ei_ha_resync_completed_event *payload)
{
  payload->_vl_msg_id = htobe16(payload->_vl_msg_id);
  payload->client_index = htobe32(payload->client_index);
  payload->pid = htobe32(payload->pid);
  payload->missed_count = htobe32(payload->missed_count);
}

static inline void vapi_msg_nat44_ei_ha_resync_completed_event_payload_ntoh(vapi_payload_nat44_ei_ha_resync_completed_event *payload)
{
  payload->_vl_msg_id = be16toh(payload->_vl_msg_id);
  payload->client_index = be32toh(payload->client_index);
  payload->pid = be32toh(payload->pid);
  payload->missed_count = be32toh(payload->missed_count);
}

static inline void vapi_msg_nat44_ei_ha_resync_completed_event_hton(vapi_msg_nat44_ei_ha_resync_completed_event *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_resync_completed_event'@%p to big endian", msg);

  vapi_msg_nat44_ei_ha_resync_completed_event_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_ha_resync_completed_event_ntoh(vapi_msg_nat44_ei_ha_resync_completed_event *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_ha_resync_completed_event'@%p to host byte order", msg);

  vapi_msg_nat44_ei_ha_resync_completed_event_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_ha_resync_completed_event_msg_size(vapi_msg_nat44_ei_ha_resync_completed_event *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_ha_resync_completed_event_msg_size(vapi_msg_nat44_ei_ha_resync_completed_event *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_ha_resync_completed_event) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_resync_completed_event' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_ha_resync_completed_event));
      return -1;
    }
  if (vapi_calc_nat44_ei_ha_resync_completed_event_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_ha_resync_completed_event' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_ha_resync_completed_event_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_ha_resync_completed_event()
{
  static const char name[] = "nat44_ei_ha_resync_completed_event";
  static const char name_with_crc[] = "nat44_ei_ha_resync_completed_event_fdc598fb";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_ha_resync_completed_event = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    false,
    0,
    offsetof(vapi_msg_nat44_ei_ha_resync_completed_event, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_ha_resync_completed_event_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_resync_completed_event_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_ha_resync_completed_event_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_ha_resync_completed_event = vapi_register_msg(&__vapi_metadata_nat44_ei_ha_resync_completed_event);
  VAPI_DBG("Assigned msg id %d to nat44_ei_ha_resync_completed_event", vapi_msg_id_nat44_ei_ha_resync_completed_event);
}

static inline void vapi_set_vapi_msg_nat44_ei_ha_resync_completed_event_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_ha_resync_completed_event *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_ha_resync_completed_event, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_del_user_reply
#define defined_vapi_msg_nat44_ei_del_user_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_del_user_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_del_user_reply payload;
} vapi_msg_nat44_ei_del_user_reply;

static inline void vapi_msg_nat44_ei_del_user_reply_payload_hton(vapi_payload_nat44_ei_del_user_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_del_user_reply_payload_ntoh(vapi_payload_nat44_ei_del_user_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_del_user_reply_hton(vapi_msg_nat44_ei_del_user_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_del_user_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_del_user_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_del_user_reply_ntoh(vapi_msg_nat44_ei_del_user_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_del_user_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_del_user_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_del_user_reply_msg_size(vapi_msg_nat44_ei_del_user_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_del_user_reply_msg_size(vapi_msg_nat44_ei_del_user_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_del_user_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_del_user_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_del_user_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_del_user_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_del_user_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_del_user_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_del_user_reply()
{
  static const char name[] = "nat44_ei_del_user_reply";
  static const char name_with_crc[] = "nat44_ei_del_user_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_del_user_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_del_user_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_del_user_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_del_user_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_del_user_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_del_user_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_del_user_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_del_user_reply", vapi_msg_id_nat44_ei_del_user_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_del_user_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_del_user_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_del_user_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_del_user
#define defined_vapi_msg_nat44_ei_del_user
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address ip_address;
  u32 fib_index; 
} vapi_payload_nat44_ei_del_user;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_del_user payload;
} vapi_msg_nat44_ei_del_user;

static inline void vapi_msg_nat44_ei_del_user_payload_hton(vapi_payload_nat44_ei_del_user *payload)
{
  payload->fib_index = htobe32(payload->fib_index);
}

static inline void vapi_msg_nat44_ei_del_user_payload_ntoh(vapi_payload_nat44_ei_del_user *payload)
{
  payload->fib_index = be32toh(payload->fib_index);
}

static inline void vapi_msg_nat44_ei_del_user_hton(vapi_msg_nat44_ei_del_user *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_del_user'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_del_user_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_del_user_ntoh(vapi_msg_nat44_ei_del_user *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_del_user'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_del_user_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_del_user_msg_size(vapi_msg_nat44_ei_del_user *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_del_user_msg_size(vapi_msg_nat44_ei_del_user *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_del_user) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_del_user' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_del_user));
      return -1;
    }
  if (vapi_calc_nat44_ei_del_user_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_del_user' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_del_user_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_del_user* vapi_alloc_nat44_ei_del_user(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_del_user *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_del_user);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_del_user*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_del_user);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_del_user(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_del_user *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_del_user_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_del_user_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_del_user_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_del_user_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_del_user()
{
  static const char name[] = "nat44_ei_del_user";
  static const char name_with_crc[] = "nat44_ei_del_user_99a9f998";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_del_user = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_del_user, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_del_user_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_del_user_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_del_user_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_del_user = vapi_register_msg(&__vapi_metadata_nat44_ei_del_user);
  VAPI_DBG("Assigned msg id %d to nat44_ei_del_user", vapi_msg_id_nat44_ei_del_user);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_add_del_address_range_reply
#define defined_vapi_msg_nat44_ei_add_del_address_range_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_add_del_address_range_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_add_del_address_range_reply payload;
} vapi_msg_nat44_ei_add_del_address_range_reply;

static inline void vapi_msg_nat44_ei_add_del_address_range_reply_payload_hton(vapi_payload_nat44_ei_add_del_address_range_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_add_del_address_range_reply_payload_ntoh(vapi_payload_nat44_ei_add_del_address_range_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_add_del_address_range_reply_hton(vapi_msg_nat44_ei_add_del_address_range_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_add_del_address_range_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_add_del_address_range_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_add_del_address_range_reply_ntoh(vapi_msg_nat44_ei_add_del_address_range_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_add_del_address_range_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_add_del_address_range_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_add_del_address_range_reply_msg_size(vapi_msg_nat44_ei_add_del_address_range_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_add_del_address_range_reply_msg_size(vapi_msg_nat44_ei_add_del_address_range_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_add_del_address_range_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_add_del_address_range_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_add_del_address_range_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_add_del_address_range_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_add_del_address_range_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_add_del_address_range_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_add_del_address_range_reply()
{
  static const char name[] = "nat44_ei_add_del_address_range_reply";
  static const char name_with_crc[] = "nat44_ei_add_del_address_range_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_add_del_address_range_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_add_del_address_range_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_add_del_address_range_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_add_del_address_range_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_add_del_address_range_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_add_del_address_range_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_add_del_address_range_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_add_del_address_range_reply", vapi_msg_id_nat44_ei_add_del_address_range_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_add_del_address_range_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_add_del_address_range_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_add_del_address_range_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_add_del_address_range
#define defined_vapi_msg_nat44_ei_add_del_address_range
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address first_ip_address;
  vapi_type_ip4_address last_ip_address;
  u32 vrf_id;
  bool is_add; 
} vapi_payload_nat44_ei_add_del_address_range;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_add_del_address_range payload;
} vapi_msg_nat44_ei_add_del_address_range;

static inline void vapi_msg_nat44_ei_add_del_address_range_payload_hton(vapi_payload_nat44_ei_add_del_address_range *payload)
{
  payload->vrf_id = htobe32(payload->vrf_id);
}

static inline void vapi_msg_nat44_ei_add_del_address_range_payload_ntoh(vapi_payload_nat44_ei_add_del_address_range *payload)
{
  payload->vrf_id = be32toh(payload->vrf_id);
}

static inline void vapi_msg_nat44_ei_add_del_address_range_hton(vapi_msg_nat44_ei_add_del_address_range *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_add_del_address_range'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_add_del_address_range_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_add_del_address_range_ntoh(vapi_msg_nat44_ei_add_del_address_range *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_add_del_address_range'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_add_del_address_range_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_add_del_address_range_msg_size(vapi_msg_nat44_ei_add_del_address_range *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_add_del_address_range_msg_size(vapi_msg_nat44_ei_add_del_address_range *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_add_del_address_range) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_add_del_address_range' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_add_del_address_range));
      return -1;
    }
  if (vapi_calc_nat44_ei_add_del_address_range_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_add_del_address_range' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_add_del_address_range_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_add_del_address_range* vapi_alloc_nat44_ei_add_del_address_range(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_add_del_address_range *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_add_del_address_range);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_add_del_address_range*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_add_del_address_range);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_add_del_address_range(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_add_del_address_range *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_add_del_address_range_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_add_del_address_range_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_add_del_address_range_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_add_del_address_range_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_add_del_address_range()
{
  static const char name[] = "nat44_ei_add_del_address_range";
  static const char name_with_crc[] = "nat44_ei_add_del_address_range_35f21abc";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_add_del_address_range = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_add_del_address_range, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_add_del_address_range_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_add_del_address_range_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_add_del_address_range_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_add_del_address_range = vapi_register_msg(&__vapi_metadata_nat44_ei_add_del_address_range);
  VAPI_DBG("Assigned msg id %d to nat44_ei_add_del_address_range", vapi_msg_id_nat44_ei_add_del_address_range);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_address_details
#define defined_vapi_msg_nat44_ei_address_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address ip_address;
  u32 vrf_id; 
} vapi_payload_nat44_ei_address_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_address_details payload;
} vapi_msg_nat44_ei_address_details;

static inline void vapi_msg_nat44_ei_address_details_payload_hton(vapi_payload_nat44_ei_address_details *payload)
{
  payload->vrf_id = htobe32(payload->vrf_id);
}

static inline void vapi_msg_nat44_ei_address_details_payload_ntoh(vapi_payload_nat44_ei_address_details *payload)
{
  payload->vrf_id = be32toh(payload->vrf_id);
}

static inline void vapi_msg_nat44_ei_address_details_hton(vapi_msg_nat44_ei_address_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_address_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_address_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_address_details_ntoh(vapi_msg_nat44_ei_address_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_address_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_address_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_address_details_msg_size(vapi_msg_nat44_ei_address_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_address_details_msg_size(vapi_msg_nat44_ei_address_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_address_details) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_address_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_address_details));
      return -1;
    }
  if (vapi_calc_nat44_ei_address_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_address_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_address_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_address_details()
{
  static const char name[] = "nat44_ei_address_details";
  static const char name_with_crc[] = "nat44_ei_address_details_318f1202";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_address_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_address_details, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_address_details_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_address_details_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_address_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_address_details = vapi_register_msg(&__vapi_metadata_nat44_ei_address_details);
  VAPI_DBG("Assigned msg id %d to nat44_ei_address_details", vapi_msg_id_nat44_ei_address_details);
}

static inline void vapi_set_vapi_msg_nat44_ei_address_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_address_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_address_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_address_dump
#define defined_vapi_msg_nat44_ei_address_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_nat44_ei_address_dump;

static inline void vapi_msg_nat44_ei_address_dump_hton(vapi_msg_nat44_ei_address_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_address_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_nat44_ei_address_dump_ntoh(vapi_msg_nat44_ei_address_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_address_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_nat44_ei_address_dump_msg_size(vapi_msg_nat44_ei_address_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_address_dump_msg_size(vapi_msg_nat44_ei_address_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_address_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_address_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_address_dump));
      return -1;
    }
  if (vapi_calc_nat44_ei_address_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_address_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_address_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_address_dump* vapi_alloc_nat44_ei_address_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_address_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_address_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_address_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_address_dump);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_address_dump(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_address_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_address_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_address_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_address_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_address_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_address_dump()
{
  static const char name[] = "nat44_ei_address_dump";
  static const char name_with_crc[] = "nat44_ei_address_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_address_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_address_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_address_dump_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_address_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_address_dump = vapi_register_msg(&__vapi_metadata_nat44_ei_address_dump);
  VAPI_DBG("Assigned msg id %d to nat44_ei_address_dump", vapi_msg_id_nat44_ei_address_dump);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_interface_add_del_feature_reply
#define defined_vapi_msg_nat44_ei_interface_add_del_feature_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_interface_add_del_feature_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_interface_add_del_feature_reply payload;
} vapi_msg_nat44_ei_interface_add_del_feature_reply;

static inline void vapi_msg_nat44_ei_interface_add_del_feature_reply_payload_hton(vapi_payload_nat44_ei_interface_add_del_feature_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_interface_add_del_feature_reply_payload_ntoh(vapi_payload_nat44_ei_interface_add_del_feature_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_interface_add_del_feature_reply_hton(vapi_msg_nat44_ei_interface_add_del_feature_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_interface_add_del_feature_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_interface_add_del_feature_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_interface_add_del_feature_reply_ntoh(vapi_msg_nat44_ei_interface_add_del_feature_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_interface_add_del_feature_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_interface_add_del_feature_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_interface_add_del_feature_reply_msg_size(vapi_msg_nat44_ei_interface_add_del_feature_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_interface_add_del_feature_reply_msg_size(vapi_msg_nat44_ei_interface_add_del_feature_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_interface_add_del_feature_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_interface_add_del_feature_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_interface_add_del_feature_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_interface_add_del_feature_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_interface_add_del_feature_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_interface_add_del_feature_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_interface_add_del_feature_reply()
{
  static const char name[] = "nat44_ei_interface_add_del_feature_reply";
  static const char name_with_crc[] = "nat44_ei_interface_add_del_feature_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_interface_add_del_feature_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_interface_add_del_feature_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_interface_add_del_feature_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_interface_add_del_feature_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_interface_add_del_feature_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_interface_add_del_feature_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_interface_add_del_feature_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_interface_add_del_feature_reply", vapi_msg_id_nat44_ei_interface_add_del_feature_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_interface_add_del_feature_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_interface_add_del_feature_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_interface_add_del_feature_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_interface_add_del_feature
#define defined_vapi_msg_nat44_ei_interface_add_del_feature
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_enum_nat44_ei_config_flags flags;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_nat44_ei_interface_add_del_feature;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_interface_add_del_feature payload;
} vapi_msg_nat44_ei_interface_add_del_feature;

static inline void vapi_msg_nat44_ei_interface_add_del_feature_payload_hton(vapi_payload_nat44_ei_interface_add_del_feature *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_nat44_ei_interface_add_del_feature_payload_ntoh(vapi_payload_nat44_ei_interface_add_del_feature *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_nat44_ei_interface_add_del_feature_hton(vapi_msg_nat44_ei_interface_add_del_feature *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_interface_add_del_feature'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_interface_add_del_feature_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_interface_add_del_feature_ntoh(vapi_msg_nat44_ei_interface_add_del_feature *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_interface_add_del_feature'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_interface_add_del_feature_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_interface_add_del_feature_msg_size(vapi_msg_nat44_ei_interface_add_del_feature *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_interface_add_del_feature_msg_size(vapi_msg_nat44_ei_interface_add_del_feature *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_interface_add_del_feature) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_interface_add_del_feature' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_interface_add_del_feature));
      return -1;
    }
  if (vapi_calc_nat44_ei_interface_add_del_feature_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_interface_add_del_feature' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_interface_add_del_feature_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_interface_add_del_feature* vapi_alloc_nat44_ei_interface_add_del_feature(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_interface_add_del_feature *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_interface_add_del_feature);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_interface_add_del_feature*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_interface_add_del_feature);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_interface_add_del_feature(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_interface_add_del_feature *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_interface_add_del_feature_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_interface_add_del_feature_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_interface_add_del_feature_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_interface_add_del_feature_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_interface_add_del_feature()
{
  static const char name[] = "nat44_ei_interface_add_del_feature";
  static const char name_with_crc[] = "nat44_ei_interface_add_del_feature_63a2db8b";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_interface_add_del_feature = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_interface_add_del_feature, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_interface_add_del_feature_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_interface_add_del_feature_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_interface_add_del_feature_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_interface_add_del_feature = vapi_register_msg(&__vapi_metadata_nat44_ei_interface_add_del_feature);
  VAPI_DBG("Assigned msg id %d to nat44_ei_interface_add_del_feature", vapi_msg_id_nat44_ei_interface_add_del_feature);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_interface_details
#define defined_vapi_msg_nat44_ei_interface_details
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_nat44_ei_config_flags flags;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_nat44_ei_interface_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_interface_details payload;
} vapi_msg_nat44_ei_interface_details;

static inline void vapi_msg_nat44_ei_interface_details_payload_hton(vapi_payload_nat44_ei_interface_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_nat44_ei_interface_details_payload_ntoh(vapi_payload_nat44_ei_interface_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_nat44_ei_interface_details_hton(vapi_msg_nat44_ei_interface_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_interface_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_interface_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_interface_details_ntoh(vapi_msg_nat44_ei_interface_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_interface_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_interface_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_interface_details_msg_size(vapi_msg_nat44_ei_interface_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_interface_details_msg_size(vapi_msg_nat44_ei_interface_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_interface_details) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_interface_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_interface_details));
      return -1;
    }
  if (vapi_calc_nat44_ei_interface_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_interface_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_interface_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_interface_details()
{
  static const char name[] = "nat44_ei_interface_details";
  static const char name_with_crc[] = "nat44_ei_interface_details_f446e508";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_interface_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_interface_details, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_interface_details_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_interface_details_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_interface_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_interface_details = vapi_register_msg(&__vapi_metadata_nat44_ei_interface_details);
  VAPI_DBG("Assigned msg id %d to nat44_ei_interface_details", vapi_msg_id_nat44_ei_interface_details);
}

static inline void vapi_set_vapi_msg_nat44_ei_interface_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_interface_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_interface_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_interface_dump
#define defined_vapi_msg_nat44_ei_interface_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_nat44_ei_interface_dump;

static inline void vapi_msg_nat44_ei_interface_dump_hton(vapi_msg_nat44_ei_interface_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_interface_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_nat44_ei_interface_dump_ntoh(vapi_msg_nat44_ei_interface_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_interface_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_nat44_ei_interface_dump_msg_size(vapi_msg_nat44_ei_interface_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_interface_dump_msg_size(vapi_msg_nat44_ei_interface_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_interface_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_interface_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_interface_dump));
      return -1;
    }
  if (vapi_calc_nat44_ei_interface_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_interface_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_interface_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_interface_dump* vapi_alloc_nat44_ei_interface_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_interface_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_interface_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_interface_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_interface_dump);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_interface_dump(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_interface_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_interface_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_interface_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_interface_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_interface_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_interface_dump()
{
  static const char name[] = "nat44_ei_interface_dump";
  static const char name_with_crc[] = "nat44_ei_interface_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_interface_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_interface_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_interface_dump_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_interface_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_interface_dump = vapi_register_msg(&__vapi_metadata_nat44_ei_interface_dump);
  VAPI_DBG("Assigned msg id %d to nat44_ei_interface_dump", vapi_msg_id_nat44_ei_interface_dump);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_interface_add_del_output_feature_reply
#define defined_vapi_msg_nat44_ei_interface_add_del_output_feature_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_interface_add_del_output_feature_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_interface_add_del_output_feature_reply payload;
} vapi_msg_nat44_ei_interface_add_del_output_feature_reply;

static inline void vapi_msg_nat44_ei_interface_add_del_output_feature_reply_payload_hton(vapi_payload_nat44_ei_interface_add_del_output_feature_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_interface_add_del_output_feature_reply_payload_ntoh(vapi_payload_nat44_ei_interface_add_del_output_feature_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_interface_add_del_output_feature_reply_hton(vapi_msg_nat44_ei_interface_add_del_output_feature_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_interface_add_del_output_feature_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_interface_add_del_output_feature_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_interface_add_del_output_feature_reply_ntoh(vapi_msg_nat44_ei_interface_add_del_output_feature_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_interface_add_del_output_feature_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_interface_add_del_output_feature_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_interface_add_del_output_feature_reply_msg_size(vapi_msg_nat44_ei_interface_add_del_output_feature_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_interface_add_del_output_feature_reply_msg_size(vapi_msg_nat44_ei_interface_add_del_output_feature_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_interface_add_del_output_feature_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_interface_add_del_output_feature_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_interface_add_del_output_feature_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_interface_add_del_output_feature_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_interface_add_del_output_feature_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_interface_add_del_output_feature_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_interface_add_del_output_feature_reply()
{
  static const char name[] = "nat44_ei_interface_add_del_output_feature_reply";
  static const char name_with_crc[] = "nat44_ei_interface_add_del_output_feature_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_interface_add_del_output_feature_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_interface_add_del_output_feature_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_interface_add_del_output_feature_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_interface_add_del_output_feature_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_interface_add_del_output_feature_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_interface_add_del_output_feature_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_interface_add_del_output_feature_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_interface_add_del_output_feature_reply", vapi_msg_id_nat44_ei_interface_add_del_output_feature_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_interface_add_del_output_feature_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_interface_add_del_output_feature_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_interface_add_del_output_feature_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_interface_add_del_output_feature
#define defined_vapi_msg_nat44_ei_interface_add_del_output_feature
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_enum_nat44_ei_config_flags flags;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_nat44_ei_interface_add_del_output_feature;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_interface_add_del_output_feature payload;
} vapi_msg_nat44_ei_interface_add_del_output_feature;

static inline void vapi_msg_nat44_ei_interface_add_del_output_feature_payload_hton(vapi_payload_nat44_ei_interface_add_del_output_feature *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_nat44_ei_interface_add_del_output_feature_payload_ntoh(vapi_payload_nat44_ei_interface_add_del_output_feature *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_nat44_ei_interface_add_del_output_feature_hton(vapi_msg_nat44_ei_interface_add_del_output_feature *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_interface_add_del_output_feature'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_interface_add_del_output_feature_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_interface_add_del_output_feature_ntoh(vapi_msg_nat44_ei_interface_add_del_output_feature *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_interface_add_del_output_feature'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_interface_add_del_output_feature_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_interface_add_del_output_feature_msg_size(vapi_msg_nat44_ei_interface_add_del_output_feature *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_interface_add_del_output_feature_msg_size(vapi_msg_nat44_ei_interface_add_del_output_feature *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_interface_add_del_output_feature) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_interface_add_del_output_feature' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_interface_add_del_output_feature));
      return -1;
    }
  if (vapi_calc_nat44_ei_interface_add_del_output_feature_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_interface_add_del_output_feature' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_interface_add_del_output_feature_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_interface_add_del_output_feature* vapi_alloc_nat44_ei_interface_add_del_output_feature(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_interface_add_del_output_feature *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_interface_add_del_output_feature);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_interface_add_del_output_feature*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_interface_add_del_output_feature);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_interface_add_del_output_feature(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_interface_add_del_output_feature *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_interface_add_del_output_feature_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_interface_add_del_output_feature_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_interface_add_del_output_feature_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_interface_add_del_output_feature_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_interface_add_del_output_feature()
{
  static const char name[] = "nat44_ei_interface_add_del_output_feature";
  static const char name_with_crc[] = "nat44_ei_interface_add_del_output_feature_63a2db8b";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_interface_add_del_output_feature = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_interface_add_del_output_feature, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_interface_add_del_output_feature_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_interface_add_del_output_feature_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_interface_add_del_output_feature_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_interface_add_del_output_feature = vapi_register_msg(&__vapi_metadata_nat44_ei_interface_add_del_output_feature);
  VAPI_DBG("Assigned msg id %d to nat44_ei_interface_add_del_output_feature", vapi_msg_id_nat44_ei_interface_add_del_output_feature);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_interface_output_feature_details
#define defined_vapi_msg_nat44_ei_interface_output_feature_details
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_nat44_ei_config_flags flags;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_nat44_ei_interface_output_feature_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_interface_output_feature_details payload;
} vapi_msg_nat44_ei_interface_output_feature_details;

static inline void vapi_msg_nat44_ei_interface_output_feature_details_payload_hton(vapi_payload_nat44_ei_interface_output_feature_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_nat44_ei_interface_output_feature_details_payload_ntoh(vapi_payload_nat44_ei_interface_output_feature_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_nat44_ei_interface_output_feature_details_hton(vapi_msg_nat44_ei_interface_output_feature_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_interface_output_feature_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_interface_output_feature_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_interface_output_feature_details_ntoh(vapi_msg_nat44_ei_interface_output_feature_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_interface_output_feature_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_interface_output_feature_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_interface_output_feature_details_msg_size(vapi_msg_nat44_ei_interface_output_feature_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_interface_output_feature_details_msg_size(vapi_msg_nat44_ei_interface_output_feature_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_interface_output_feature_details) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_interface_output_feature_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_interface_output_feature_details));
      return -1;
    }
  if (vapi_calc_nat44_ei_interface_output_feature_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_interface_output_feature_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_interface_output_feature_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_interface_output_feature_details()
{
  static const char name[] = "nat44_ei_interface_output_feature_details";
  static const char name_with_crc[] = "nat44_ei_interface_output_feature_details_f446e508";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_interface_output_feature_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_interface_output_feature_details, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_interface_output_feature_details_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_interface_output_feature_details_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_interface_output_feature_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_interface_output_feature_details = vapi_register_msg(&__vapi_metadata_nat44_ei_interface_output_feature_details);
  VAPI_DBG("Assigned msg id %d to nat44_ei_interface_output_feature_details", vapi_msg_id_nat44_ei_interface_output_feature_details);
}

static inline void vapi_set_vapi_msg_nat44_ei_interface_output_feature_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_interface_output_feature_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_interface_output_feature_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_interface_output_feature_dump
#define defined_vapi_msg_nat44_ei_interface_output_feature_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_nat44_ei_interface_output_feature_dump;

static inline void vapi_msg_nat44_ei_interface_output_feature_dump_hton(vapi_msg_nat44_ei_interface_output_feature_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_interface_output_feature_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_nat44_ei_interface_output_feature_dump_ntoh(vapi_msg_nat44_ei_interface_output_feature_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_interface_output_feature_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_nat44_ei_interface_output_feature_dump_msg_size(vapi_msg_nat44_ei_interface_output_feature_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_interface_output_feature_dump_msg_size(vapi_msg_nat44_ei_interface_output_feature_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_interface_output_feature_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_interface_output_feature_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_interface_output_feature_dump));
      return -1;
    }
  if (vapi_calc_nat44_ei_interface_output_feature_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_interface_output_feature_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_interface_output_feature_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_interface_output_feature_dump* vapi_alloc_nat44_ei_interface_output_feature_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_interface_output_feature_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_interface_output_feature_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_interface_output_feature_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_interface_output_feature_dump);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_interface_output_feature_dump(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_interface_output_feature_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_interface_output_feature_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_interface_output_feature_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_interface_output_feature_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_interface_output_feature_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_interface_output_feature_dump()
{
  static const char name[] = "nat44_ei_interface_output_feature_dump";
  static const char name_with_crc[] = "nat44_ei_interface_output_feature_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_interface_output_feature_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_interface_output_feature_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_interface_output_feature_dump_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_interface_output_feature_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_interface_output_feature_dump = vapi_register_msg(&__vapi_metadata_nat44_ei_interface_output_feature_dump);
  VAPI_DBG("Assigned msg id %d to nat44_ei_interface_output_feature_dump", vapi_msg_id_nat44_ei_interface_output_feature_dump);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_add_del_output_interface_reply
#define defined_vapi_msg_nat44_ei_add_del_output_interface_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_add_del_output_interface_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_add_del_output_interface_reply payload;
} vapi_msg_nat44_ei_add_del_output_interface_reply;

static inline void vapi_msg_nat44_ei_add_del_output_interface_reply_payload_hton(vapi_payload_nat44_ei_add_del_output_interface_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_add_del_output_interface_reply_payload_ntoh(vapi_payload_nat44_ei_add_del_output_interface_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_add_del_output_interface_reply_hton(vapi_msg_nat44_ei_add_del_output_interface_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_add_del_output_interface_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_add_del_output_interface_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_add_del_output_interface_reply_ntoh(vapi_msg_nat44_ei_add_del_output_interface_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_add_del_output_interface_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_add_del_output_interface_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_add_del_output_interface_reply_msg_size(vapi_msg_nat44_ei_add_del_output_interface_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_add_del_output_interface_reply_msg_size(vapi_msg_nat44_ei_add_del_output_interface_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_add_del_output_interface_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_add_del_output_interface_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_add_del_output_interface_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_add_del_output_interface_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_add_del_output_interface_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_add_del_output_interface_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_add_del_output_interface_reply()
{
  static const char name[] = "nat44_ei_add_del_output_interface_reply";
  static const char name_with_crc[] = "nat44_ei_add_del_output_interface_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_add_del_output_interface_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_add_del_output_interface_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_add_del_output_interface_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_add_del_output_interface_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_add_del_output_interface_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_add_del_output_interface_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_add_del_output_interface_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_add_del_output_interface_reply", vapi_msg_id_nat44_ei_add_del_output_interface_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_add_del_output_interface_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_add_del_output_interface_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_add_del_output_interface_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_add_del_output_interface
#define defined_vapi_msg_nat44_ei_add_del_output_interface
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_nat44_ei_add_del_output_interface;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_add_del_output_interface payload;
} vapi_msg_nat44_ei_add_del_output_interface;

static inline void vapi_msg_nat44_ei_add_del_output_interface_payload_hton(vapi_payload_nat44_ei_add_del_output_interface *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_nat44_ei_add_del_output_interface_payload_ntoh(vapi_payload_nat44_ei_add_del_output_interface *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_nat44_ei_add_del_output_interface_hton(vapi_msg_nat44_ei_add_del_output_interface *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_add_del_output_interface'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_add_del_output_interface_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_add_del_output_interface_ntoh(vapi_msg_nat44_ei_add_del_output_interface *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_add_del_output_interface'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_add_del_output_interface_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_add_del_output_interface_msg_size(vapi_msg_nat44_ei_add_del_output_interface *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_add_del_output_interface_msg_size(vapi_msg_nat44_ei_add_del_output_interface *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_add_del_output_interface) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_add_del_output_interface' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_add_del_output_interface));
      return -1;
    }
  if (vapi_calc_nat44_ei_add_del_output_interface_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_add_del_output_interface' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_add_del_output_interface_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_add_del_output_interface* vapi_alloc_nat44_ei_add_del_output_interface(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_add_del_output_interface *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_add_del_output_interface);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_add_del_output_interface*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_add_del_output_interface);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_add_del_output_interface(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_add_del_output_interface *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_add_del_output_interface_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_add_del_output_interface_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_add_del_output_interface_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_add_del_output_interface_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_add_del_output_interface()
{
  static const char name[] = "nat44_ei_add_del_output_interface";
  static const char name_with_crc[] = "nat44_ei_add_del_output_interface_47d6e753";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_add_del_output_interface = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_add_del_output_interface, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_add_del_output_interface_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_add_del_output_interface_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_add_del_output_interface_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_add_del_output_interface = vapi_register_msg(&__vapi_metadata_nat44_ei_add_del_output_interface);
  VAPI_DBG("Assigned msg id %d to nat44_ei_add_del_output_interface", vapi_msg_id_nat44_ei_add_del_output_interface);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_output_interface_get_reply
#define defined_vapi_msg_nat44_ei_output_interface_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 cursor; 
} vapi_payload_nat44_ei_output_interface_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_output_interface_get_reply payload;
} vapi_msg_nat44_ei_output_interface_get_reply;

static inline void vapi_msg_nat44_ei_output_interface_get_reply_payload_hton(vapi_payload_nat44_ei_output_interface_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_nat44_ei_output_interface_get_reply_payload_ntoh(vapi_payload_nat44_ei_output_interface_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_nat44_ei_output_interface_get_reply_hton(vapi_msg_nat44_ei_output_interface_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_output_interface_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_output_interface_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_output_interface_get_reply_ntoh(vapi_msg_nat44_ei_output_interface_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_output_interface_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_output_interface_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_output_interface_get_reply_msg_size(vapi_msg_nat44_ei_output_interface_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_output_interface_get_reply_msg_size(vapi_msg_nat44_ei_output_interface_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_output_interface_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_output_interface_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_output_interface_get_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_output_interface_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_output_interface_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_output_interface_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_output_interface_get_reply()
{
  static const char name[] = "nat44_ei_output_interface_get_reply";
  static const char name_with_crc[] = "nat44_ei_output_interface_get_reply_53b48f5d";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_output_interface_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_output_interface_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_output_interface_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_output_interface_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_output_interface_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_output_interface_get_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_output_interface_get_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_output_interface_get_reply", vapi_msg_id_nat44_ei_output_interface_get_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_output_interface_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_output_interface_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_output_interface_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_output_interface_details
#define defined_vapi_msg_nat44_ei_output_interface_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_nat44_ei_output_interface_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_output_interface_details payload;
} vapi_msg_nat44_ei_output_interface_details;

static inline void vapi_msg_nat44_ei_output_interface_details_payload_hton(vapi_payload_nat44_ei_output_interface_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_nat44_ei_output_interface_details_payload_ntoh(vapi_payload_nat44_ei_output_interface_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_nat44_ei_output_interface_details_hton(vapi_msg_nat44_ei_output_interface_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_output_interface_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_output_interface_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_output_interface_details_ntoh(vapi_msg_nat44_ei_output_interface_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_output_interface_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_output_interface_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_output_interface_details_msg_size(vapi_msg_nat44_ei_output_interface_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_output_interface_details_msg_size(vapi_msg_nat44_ei_output_interface_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_output_interface_details) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_output_interface_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_output_interface_details));
      return -1;
    }
  if (vapi_calc_nat44_ei_output_interface_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_output_interface_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_output_interface_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_output_interface_details()
{
  static const char name[] = "nat44_ei_output_interface_details";
  static const char name_with_crc[] = "nat44_ei_output_interface_details_0b45011c";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_output_interface_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_output_interface_details, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_output_interface_details_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_output_interface_details_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_output_interface_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_output_interface_details = vapi_register_msg(&__vapi_metadata_nat44_ei_output_interface_details);
  VAPI_DBG("Assigned msg id %d to nat44_ei_output_interface_details", vapi_msg_id_nat44_ei_output_interface_details);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_output_interface_get
#define defined_vapi_msg_nat44_ei_output_interface_get
typedef struct __attribute__ ((__packed__)) {
  u32 cursor; 
} vapi_payload_nat44_ei_output_interface_get;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_output_interface_get payload;
} vapi_msg_nat44_ei_output_interface_get;

static inline void vapi_msg_nat44_ei_output_interface_get_payload_hton(vapi_payload_nat44_ei_output_interface_get *payload)
{
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_nat44_ei_output_interface_get_payload_ntoh(vapi_payload_nat44_ei_output_interface_get *payload)
{
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_nat44_ei_output_interface_get_hton(vapi_msg_nat44_ei_output_interface_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_output_interface_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_output_interface_get_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_output_interface_get_ntoh(vapi_msg_nat44_ei_output_interface_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_output_interface_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_output_interface_get_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_output_interface_get_msg_size(vapi_msg_nat44_ei_output_interface_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_output_interface_get_msg_size(vapi_msg_nat44_ei_output_interface_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_output_interface_get) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_output_interface_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_output_interface_get));
      return -1;
    }
  if (vapi_calc_nat44_ei_output_interface_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_output_interface_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_output_interface_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_output_interface_get* vapi_alloc_nat44_ei_output_interface_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_output_interface_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_output_interface_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_output_interface_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_output_interface_get);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_output_interface_get(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_output_interface_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_output_interface_get_reply *reply),
  void *reply_callback_ctx,
  vapi_error_e (*details_callback)(struct vapi_ctx_s *ctx,
                                   void *callback_ctx,
                                   vapi_error_e rv,
                                   bool is_last,
                                   vapi_payload_nat44_ei_output_interface_details *details),
  void *details_callback_ctx)
{
  if (!msg || !reply_callback || !details_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_output_interface_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_output_interface_details, VAPI_REQUEST_STREAM, 
                       (vapi_cb_t)details_callback, details_callback_ctx);
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_output_interface_get_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_output_interface_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_output_interface_get()
{
  static const char name[] = "nat44_ei_output_interface_get";
  static const char name_with_crc[] = "nat44_ei_output_interface_get_f75ba505";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_output_interface_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_output_interface_get, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_output_interface_get_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_output_interface_get_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_output_interface_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_output_interface_get = vapi_register_msg(&__vapi_metadata_nat44_ei_output_interface_get);
  VAPI_DBG("Assigned msg id %d to nat44_ei_output_interface_get", vapi_msg_id_nat44_ei_output_interface_get);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_add_del_static_mapping_reply
#define defined_vapi_msg_nat44_ei_add_del_static_mapping_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_add_del_static_mapping_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_add_del_static_mapping_reply payload;
} vapi_msg_nat44_ei_add_del_static_mapping_reply;

static inline void vapi_msg_nat44_ei_add_del_static_mapping_reply_payload_hton(vapi_payload_nat44_ei_add_del_static_mapping_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_add_del_static_mapping_reply_payload_ntoh(vapi_payload_nat44_ei_add_del_static_mapping_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_add_del_static_mapping_reply_hton(vapi_msg_nat44_ei_add_del_static_mapping_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_add_del_static_mapping_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_add_del_static_mapping_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_add_del_static_mapping_reply_ntoh(vapi_msg_nat44_ei_add_del_static_mapping_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_add_del_static_mapping_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_add_del_static_mapping_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_add_del_static_mapping_reply_msg_size(vapi_msg_nat44_ei_add_del_static_mapping_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_add_del_static_mapping_reply_msg_size(vapi_msg_nat44_ei_add_del_static_mapping_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_add_del_static_mapping_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_add_del_static_mapping_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_add_del_static_mapping_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_add_del_static_mapping_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_add_del_static_mapping_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_add_del_static_mapping_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_add_del_static_mapping_reply()
{
  static const char name[] = "nat44_ei_add_del_static_mapping_reply";
  static const char name_with_crc[] = "nat44_ei_add_del_static_mapping_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_add_del_static_mapping_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_add_del_static_mapping_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_add_del_static_mapping_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_add_del_static_mapping_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_add_del_static_mapping_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_add_del_static_mapping_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_add_del_static_mapping_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_add_del_static_mapping_reply", vapi_msg_id_nat44_ei_add_del_static_mapping_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_add_del_static_mapping_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_add_del_static_mapping_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_add_del_static_mapping_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_add_del_static_mapping
#define defined_vapi_msg_nat44_ei_add_del_static_mapping
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_enum_nat44_ei_config_flags flags;
  vapi_type_ip4_address local_ip_address;
  vapi_type_ip4_address external_ip_address;
  u8 protocol;
  u16 local_port;
  u16 external_port;
  vapi_type_interface_index external_sw_if_index;
  u32 vrf_id;
  u8 tag[64]; 
} vapi_payload_nat44_ei_add_del_static_mapping;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_add_del_static_mapping payload;
} vapi_msg_nat44_ei_add_del_static_mapping;

static inline void vapi_msg_nat44_ei_add_del_static_mapping_payload_hton(vapi_payload_nat44_ei_add_del_static_mapping *payload)
{
  payload->local_port = htobe16(payload->local_port);
  payload->external_port = htobe16(payload->external_port);
  payload->external_sw_if_index = htobe32(payload->external_sw_if_index);
  payload->vrf_id = htobe32(payload->vrf_id);
}

static inline void vapi_msg_nat44_ei_add_del_static_mapping_payload_ntoh(vapi_payload_nat44_ei_add_del_static_mapping *payload)
{
  payload->local_port = be16toh(payload->local_port);
  payload->external_port = be16toh(payload->external_port);
  payload->external_sw_if_index = be32toh(payload->external_sw_if_index);
  payload->vrf_id = be32toh(payload->vrf_id);
}

static inline void vapi_msg_nat44_ei_add_del_static_mapping_hton(vapi_msg_nat44_ei_add_del_static_mapping *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_add_del_static_mapping'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_add_del_static_mapping_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_add_del_static_mapping_ntoh(vapi_msg_nat44_ei_add_del_static_mapping *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_add_del_static_mapping'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_add_del_static_mapping_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_add_del_static_mapping_msg_size(vapi_msg_nat44_ei_add_del_static_mapping *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_add_del_static_mapping_msg_size(vapi_msg_nat44_ei_add_del_static_mapping *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_add_del_static_mapping) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_add_del_static_mapping' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_add_del_static_mapping));
      return -1;
    }
  if (vapi_calc_nat44_ei_add_del_static_mapping_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_add_del_static_mapping' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_add_del_static_mapping_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_add_del_static_mapping* vapi_alloc_nat44_ei_add_del_static_mapping(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_add_del_static_mapping *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_add_del_static_mapping);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_add_del_static_mapping*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_add_del_static_mapping);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_add_del_static_mapping(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_add_del_static_mapping *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_add_del_static_mapping_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_add_del_static_mapping_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_add_del_static_mapping_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_add_del_static_mapping_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_add_del_static_mapping()
{
  static const char name[] = "nat44_ei_add_del_static_mapping";
  static const char name_with_crc[] = "nat44_ei_add_del_static_mapping_b404b7fe";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_add_del_static_mapping = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_add_del_static_mapping, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_add_del_static_mapping_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_add_del_static_mapping_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_add_del_static_mapping_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_add_del_static_mapping = vapi_register_msg(&__vapi_metadata_nat44_ei_add_del_static_mapping);
  VAPI_DBG("Assigned msg id %d to nat44_ei_add_del_static_mapping", vapi_msg_id_nat44_ei_add_del_static_mapping);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_static_mapping_details
#define defined_vapi_msg_nat44_ei_static_mapping_details
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_nat44_ei_config_flags flags;
  vapi_type_ip4_address local_ip_address;
  vapi_type_ip4_address external_ip_address;
  u8 protocol;
  u16 local_port;
  u16 external_port;
  vapi_type_interface_index external_sw_if_index;
  u32 vrf_id;
  u8 tag[64]; 
} vapi_payload_nat44_ei_static_mapping_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_static_mapping_details payload;
} vapi_msg_nat44_ei_static_mapping_details;

static inline void vapi_msg_nat44_ei_static_mapping_details_payload_hton(vapi_payload_nat44_ei_static_mapping_details *payload)
{
  payload->local_port = htobe16(payload->local_port);
  payload->external_port = htobe16(payload->external_port);
  payload->external_sw_if_index = htobe32(payload->external_sw_if_index);
  payload->vrf_id = htobe32(payload->vrf_id);
}

static inline void vapi_msg_nat44_ei_static_mapping_details_payload_ntoh(vapi_payload_nat44_ei_static_mapping_details *payload)
{
  payload->local_port = be16toh(payload->local_port);
  payload->external_port = be16toh(payload->external_port);
  payload->external_sw_if_index = be32toh(payload->external_sw_if_index);
  payload->vrf_id = be32toh(payload->vrf_id);
}

static inline void vapi_msg_nat44_ei_static_mapping_details_hton(vapi_msg_nat44_ei_static_mapping_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_static_mapping_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_static_mapping_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_static_mapping_details_ntoh(vapi_msg_nat44_ei_static_mapping_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_static_mapping_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_static_mapping_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_static_mapping_details_msg_size(vapi_msg_nat44_ei_static_mapping_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_static_mapping_details_msg_size(vapi_msg_nat44_ei_static_mapping_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_static_mapping_details) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_static_mapping_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_static_mapping_details));
      return -1;
    }
  if (vapi_calc_nat44_ei_static_mapping_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_static_mapping_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_static_mapping_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_static_mapping_details()
{
  static const char name[] = "nat44_ei_static_mapping_details";
  static const char name_with_crc[] = "nat44_ei_static_mapping_details_6b51ca6e";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_static_mapping_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_static_mapping_details, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_static_mapping_details_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_static_mapping_details_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_static_mapping_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_static_mapping_details = vapi_register_msg(&__vapi_metadata_nat44_ei_static_mapping_details);
  VAPI_DBG("Assigned msg id %d to nat44_ei_static_mapping_details", vapi_msg_id_nat44_ei_static_mapping_details);
}

static inline void vapi_set_vapi_msg_nat44_ei_static_mapping_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_static_mapping_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_static_mapping_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_static_mapping_dump
#define defined_vapi_msg_nat44_ei_static_mapping_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_nat44_ei_static_mapping_dump;

static inline void vapi_msg_nat44_ei_static_mapping_dump_hton(vapi_msg_nat44_ei_static_mapping_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_static_mapping_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_nat44_ei_static_mapping_dump_ntoh(vapi_msg_nat44_ei_static_mapping_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_static_mapping_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_nat44_ei_static_mapping_dump_msg_size(vapi_msg_nat44_ei_static_mapping_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_static_mapping_dump_msg_size(vapi_msg_nat44_ei_static_mapping_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_static_mapping_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_static_mapping_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_static_mapping_dump));
      return -1;
    }
  if (vapi_calc_nat44_ei_static_mapping_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_static_mapping_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_static_mapping_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_static_mapping_dump* vapi_alloc_nat44_ei_static_mapping_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_static_mapping_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_static_mapping_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_static_mapping_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_static_mapping_dump);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_static_mapping_dump(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_static_mapping_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_static_mapping_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_static_mapping_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_static_mapping_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_static_mapping_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_static_mapping_dump()
{
  static const char name[] = "nat44_ei_static_mapping_dump";
  static const char name_with_crc[] = "nat44_ei_static_mapping_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_static_mapping_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_static_mapping_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_static_mapping_dump_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_static_mapping_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_static_mapping_dump = vapi_register_msg(&__vapi_metadata_nat44_ei_static_mapping_dump);
  VAPI_DBG("Assigned msg id %d to nat44_ei_static_mapping_dump", vapi_msg_id_nat44_ei_static_mapping_dump);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_add_del_identity_mapping_reply
#define defined_vapi_msg_nat44_ei_add_del_identity_mapping_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_add_del_identity_mapping_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_add_del_identity_mapping_reply payload;
} vapi_msg_nat44_ei_add_del_identity_mapping_reply;

static inline void vapi_msg_nat44_ei_add_del_identity_mapping_reply_payload_hton(vapi_payload_nat44_ei_add_del_identity_mapping_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_add_del_identity_mapping_reply_payload_ntoh(vapi_payload_nat44_ei_add_del_identity_mapping_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_add_del_identity_mapping_reply_hton(vapi_msg_nat44_ei_add_del_identity_mapping_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_add_del_identity_mapping_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_add_del_identity_mapping_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_add_del_identity_mapping_reply_ntoh(vapi_msg_nat44_ei_add_del_identity_mapping_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_add_del_identity_mapping_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_add_del_identity_mapping_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_add_del_identity_mapping_reply_msg_size(vapi_msg_nat44_ei_add_del_identity_mapping_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_add_del_identity_mapping_reply_msg_size(vapi_msg_nat44_ei_add_del_identity_mapping_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_add_del_identity_mapping_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_add_del_identity_mapping_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_add_del_identity_mapping_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_add_del_identity_mapping_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_add_del_identity_mapping_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_add_del_identity_mapping_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_add_del_identity_mapping_reply()
{
  static const char name[] = "nat44_ei_add_del_identity_mapping_reply";
  static const char name_with_crc[] = "nat44_ei_add_del_identity_mapping_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_add_del_identity_mapping_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_add_del_identity_mapping_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_add_del_identity_mapping_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_add_del_identity_mapping_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_add_del_identity_mapping_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_add_del_identity_mapping_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_add_del_identity_mapping_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_add_del_identity_mapping_reply", vapi_msg_id_nat44_ei_add_del_identity_mapping_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_add_del_identity_mapping_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_add_del_identity_mapping_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_add_del_identity_mapping_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_add_del_identity_mapping
#define defined_vapi_msg_nat44_ei_add_del_identity_mapping
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_enum_nat44_ei_config_flags flags;
  vapi_type_ip4_address ip_address;
  u8 protocol;
  u16 port;
  vapi_type_interface_index sw_if_index;
  u32 vrf_id;
  u8 tag[64]; 
} vapi_payload_nat44_ei_add_del_identity_mapping;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_add_del_identity_mapping payload;
} vapi_msg_nat44_ei_add_del_identity_mapping;

static inline void vapi_msg_nat44_ei_add_del_identity_mapping_payload_hton(vapi_payload_nat44_ei_add_del_identity_mapping *payload)
{
  payload->port = htobe16(payload->port);
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->vrf_id = htobe32(payload->vrf_id);
}

static inline void vapi_msg_nat44_ei_add_del_identity_mapping_payload_ntoh(vapi_payload_nat44_ei_add_del_identity_mapping *payload)
{
  payload->port = be16toh(payload->port);
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->vrf_id = be32toh(payload->vrf_id);
}

static inline void vapi_msg_nat44_ei_add_del_identity_mapping_hton(vapi_msg_nat44_ei_add_del_identity_mapping *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_add_del_identity_mapping'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_add_del_identity_mapping_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_add_del_identity_mapping_ntoh(vapi_msg_nat44_ei_add_del_identity_mapping *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_add_del_identity_mapping'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_add_del_identity_mapping_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_add_del_identity_mapping_msg_size(vapi_msg_nat44_ei_add_del_identity_mapping *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_add_del_identity_mapping_msg_size(vapi_msg_nat44_ei_add_del_identity_mapping *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_add_del_identity_mapping) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_add_del_identity_mapping' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_add_del_identity_mapping));
      return -1;
    }
  if (vapi_calc_nat44_ei_add_del_identity_mapping_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_add_del_identity_mapping' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_add_del_identity_mapping_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_add_del_identity_mapping* vapi_alloc_nat44_ei_add_del_identity_mapping(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_add_del_identity_mapping *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_add_del_identity_mapping);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_add_del_identity_mapping*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_add_del_identity_mapping);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_add_del_identity_mapping(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_add_del_identity_mapping *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_add_del_identity_mapping_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_add_del_identity_mapping_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_add_del_identity_mapping_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_add_del_identity_mapping_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_add_del_identity_mapping()
{
  static const char name[] = "nat44_ei_add_del_identity_mapping";
  static const char name_with_crc[] = "nat44_ei_add_del_identity_mapping_cb8606b9";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_add_del_identity_mapping = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_add_del_identity_mapping, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_add_del_identity_mapping_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_add_del_identity_mapping_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_add_del_identity_mapping_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_add_del_identity_mapping = vapi_register_msg(&__vapi_metadata_nat44_ei_add_del_identity_mapping);
  VAPI_DBG("Assigned msg id %d to nat44_ei_add_del_identity_mapping", vapi_msg_id_nat44_ei_add_del_identity_mapping);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_identity_mapping_details
#define defined_vapi_msg_nat44_ei_identity_mapping_details
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_nat44_ei_config_flags flags;
  vapi_type_ip4_address ip_address;
  u8 protocol;
  u16 port;
  vapi_type_interface_index sw_if_index;
  u32 vrf_id;
  u8 tag[64]; 
} vapi_payload_nat44_ei_identity_mapping_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_identity_mapping_details payload;
} vapi_msg_nat44_ei_identity_mapping_details;

static inline void vapi_msg_nat44_ei_identity_mapping_details_payload_hton(vapi_payload_nat44_ei_identity_mapping_details *payload)
{
  payload->port = htobe16(payload->port);
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->vrf_id = htobe32(payload->vrf_id);
}

static inline void vapi_msg_nat44_ei_identity_mapping_details_payload_ntoh(vapi_payload_nat44_ei_identity_mapping_details *payload)
{
  payload->port = be16toh(payload->port);
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->vrf_id = be32toh(payload->vrf_id);
}

static inline void vapi_msg_nat44_ei_identity_mapping_details_hton(vapi_msg_nat44_ei_identity_mapping_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_identity_mapping_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_identity_mapping_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_identity_mapping_details_ntoh(vapi_msg_nat44_ei_identity_mapping_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_identity_mapping_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_identity_mapping_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_identity_mapping_details_msg_size(vapi_msg_nat44_ei_identity_mapping_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_identity_mapping_details_msg_size(vapi_msg_nat44_ei_identity_mapping_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_identity_mapping_details) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_identity_mapping_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_identity_mapping_details));
      return -1;
    }
  if (vapi_calc_nat44_ei_identity_mapping_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_identity_mapping_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_identity_mapping_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_identity_mapping_details()
{
  static const char name[] = "nat44_ei_identity_mapping_details";
  static const char name_with_crc[] = "nat44_ei_identity_mapping_details_30d53e26";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_identity_mapping_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_identity_mapping_details, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_identity_mapping_details_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_identity_mapping_details_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_identity_mapping_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_identity_mapping_details = vapi_register_msg(&__vapi_metadata_nat44_ei_identity_mapping_details);
  VAPI_DBG("Assigned msg id %d to nat44_ei_identity_mapping_details", vapi_msg_id_nat44_ei_identity_mapping_details);
}

static inline void vapi_set_vapi_msg_nat44_ei_identity_mapping_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_identity_mapping_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_identity_mapping_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_identity_mapping_dump
#define defined_vapi_msg_nat44_ei_identity_mapping_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_nat44_ei_identity_mapping_dump;

static inline void vapi_msg_nat44_ei_identity_mapping_dump_hton(vapi_msg_nat44_ei_identity_mapping_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_identity_mapping_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_nat44_ei_identity_mapping_dump_ntoh(vapi_msg_nat44_ei_identity_mapping_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_identity_mapping_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_nat44_ei_identity_mapping_dump_msg_size(vapi_msg_nat44_ei_identity_mapping_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_identity_mapping_dump_msg_size(vapi_msg_nat44_ei_identity_mapping_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_identity_mapping_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_identity_mapping_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_identity_mapping_dump));
      return -1;
    }
  if (vapi_calc_nat44_ei_identity_mapping_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_identity_mapping_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_identity_mapping_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_identity_mapping_dump* vapi_alloc_nat44_ei_identity_mapping_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_identity_mapping_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_identity_mapping_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_identity_mapping_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_identity_mapping_dump);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_identity_mapping_dump(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_identity_mapping_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_identity_mapping_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_identity_mapping_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_identity_mapping_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_identity_mapping_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_identity_mapping_dump()
{
  static const char name[] = "nat44_ei_identity_mapping_dump";
  static const char name_with_crc[] = "nat44_ei_identity_mapping_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_identity_mapping_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_identity_mapping_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_identity_mapping_dump_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_identity_mapping_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_identity_mapping_dump = vapi_register_msg(&__vapi_metadata_nat44_ei_identity_mapping_dump);
  VAPI_DBG("Assigned msg id %d to nat44_ei_identity_mapping_dump", vapi_msg_id_nat44_ei_identity_mapping_dump);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_add_del_interface_addr_reply
#define defined_vapi_msg_nat44_ei_add_del_interface_addr_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_add_del_interface_addr_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_add_del_interface_addr_reply payload;
} vapi_msg_nat44_ei_add_del_interface_addr_reply;

static inline void vapi_msg_nat44_ei_add_del_interface_addr_reply_payload_hton(vapi_payload_nat44_ei_add_del_interface_addr_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_add_del_interface_addr_reply_payload_ntoh(vapi_payload_nat44_ei_add_del_interface_addr_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_add_del_interface_addr_reply_hton(vapi_msg_nat44_ei_add_del_interface_addr_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_add_del_interface_addr_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_add_del_interface_addr_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_add_del_interface_addr_reply_ntoh(vapi_msg_nat44_ei_add_del_interface_addr_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_add_del_interface_addr_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_add_del_interface_addr_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_add_del_interface_addr_reply_msg_size(vapi_msg_nat44_ei_add_del_interface_addr_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_add_del_interface_addr_reply_msg_size(vapi_msg_nat44_ei_add_del_interface_addr_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_add_del_interface_addr_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_add_del_interface_addr_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_add_del_interface_addr_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_add_del_interface_addr_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_add_del_interface_addr_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_add_del_interface_addr_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_add_del_interface_addr_reply()
{
  static const char name[] = "nat44_ei_add_del_interface_addr_reply";
  static const char name_with_crc[] = "nat44_ei_add_del_interface_addr_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_add_del_interface_addr_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_add_del_interface_addr_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_add_del_interface_addr_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_add_del_interface_addr_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_add_del_interface_addr_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_add_del_interface_addr_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_add_del_interface_addr_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_add_del_interface_addr_reply", vapi_msg_id_nat44_ei_add_del_interface_addr_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_add_del_interface_addr_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_add_del_interface_addr_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_add_del_interface_addr_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_add_del_interface_addr
#define defined_vapi_msg_nat44_ei_add_del_interface_addr
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_interface_index sw_if_index;
  vapi_enum_nat44_ei_config_flags flags; 
} vapi_payload_nat44_ei_add_del_interface_addr;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_add_del_interface_addr payload;
} vapi_msg_nat44_ei_add_del_interface_addr;

static inline void vapi_msg_nat44_ei_add_del_interface_addr_payload_hton(vapi_payload_nat44_ei_add_del_interface_addr *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_nat44_ei_add_del_interface_addr_payload_ntoh(vapi_payload_nat44_ei_add_del_interface_addr *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_nat44_ei_add_del_interface_addr_hton(vapi_msg_nat44_ei_add_del_interface_addr *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_add_del_interface_addr'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_add_del_interface_addr_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_add_del_interface_addr_ntoh(vapi_msg_nat44_ei_add_del_interface_addr *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_add_del_interface_addr'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_add_del_interface_addr_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_add_del_interface_addr_msg_size(vapi_msg_nat44_ei_add_del_interface_addr *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_add_del_interface_addr_msg_size(vapi_msg_nat44_ei_add_del_interface_addr *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_add_del_interface_addr) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_add_del_interface_addr' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_add_del_interface_addr));
      return -1;
    }
  if (vapi_calc_nat44_ei_add_del_interface_addr_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_add_del_interface_addr' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_add_del_interface_addr_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_add_del_interface_addr* vapi_alloc_nat44_ei_add_del_interface_addr(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_add_del_interface_addr *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_add_del_interface_addr);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_add_del_interface_addr*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_add_del_interface_addr);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_add_del_interface_addr(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_add_del_interface_addr *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_add_del_interface_addr_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_add_del_interface_addr_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_add_del_interface_addr_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_add_del_interface_addr_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_add_del_interface_addr()
{
  static const char name[] = "nat44_ei_add_del_interface_addr";
  static const char name_with_crc[] = "nat44_ei_add_del_interface_addr_883abbcc";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_add_del_interface_addr = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_add_del_interface_addr, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_add_del_interface_addr_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_add_del_interface_addr_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_add_del_interface_addr_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_add_del_interface_addr = vapi_register_msg(&__vapi_metadata_nat44_ei_add_del_interface_addr);
  VAPI_DBG("Assigned msg id %d to nat44_ei_add_del_interface_addr", vapi_msg_id_nat44_ei_add_del_interface_addr);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_interface_addr_details
#define defined_vapi_msg_nat44_ei_interface_addr_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_nat44_ei_interface_addr_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_interface_addr_details payload;
} vapi_msg_nat44_ei_interface_addr_details;

static inline void vapi_msg_nat44_ei_interface_addr_details_payload_hton(vapi_payload_nat44_ei_interface_addr_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_nat44_ei_interface_addr_details_payload_ntoh(vapi_payload_nat44_ei_interface_addr_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_nat44_ei_interface_addr_details_hton(vapi_msg_nat44_ei_interface_addr_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_interface_addr_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_interface_addr_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_interface_addr_details_ntoh(vapi_msg_nat44_ei_interface_addr_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_interface_addr_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_interface_addr_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_interface_addr_details_msg_size(vapi_msg_nat44_ei_interface_addr_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_interface_addr_details_msg_size(vapi_msg_nat44_ei_interface_addr_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_interface_addr_details) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_interface_addr_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_interface_addr_details));
      return -1;
    }
  if (vapi_calc_nat44_ei_interface_addr_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_interface_addr_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_interface_addr_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_interface_addr_details()
{
  static const char name[] = "nat44_ei_interface_addr_details";
  static const char name_with_crc[] = "nat44_ei_interface_addr_details_0b45011c";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_interface_addr_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_interface_addr_details, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_interface_addr_details_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_interface_addr_details_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_interface_addr_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_interface_addr_details = vapi_register_msg(&__vapi_metadata_nat44_ei_interface_addr_details);
  VAPI_DBG("Assigned msg id %d to nat44_ei_interface_addr_details", vapi_msg_id_nat44_ei_interface_addr_details);
}

static inline void vapi_set_vapi_msg_nat44_ei_interface_addr_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_interface_addr_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_interface_addr_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_interface_addr_dump
#define defined_vapi_msg_nat44_ei_interface_addr_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_nat44_ei_interface_addr_dump;

static inline void vapi_msg_nat44_ei_interface_addr_dump_hton(vapi_msg_nat44_ei_interface_addr_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_interface_addr_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_nat44_ei_interface_addr_dump_ntoh(vapi_msg_nat44_ei_interface_addr_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_interface_addr_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_nat44_ei_interface_addr_dump_msg_size(vapi_msg_nat44_ei_interface_addr_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_interface_addr_dump_msg_size(vapi_msg_nat44_ei_interface_addr_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_interface_addr_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_interface_addr_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_interface_addr_dump));
      return -1;
    }
  if (vapi_calc_nat44_ei_interface_addr_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_interface_addr_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_interface_addr_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_interface_addr_dump* vapi_alloc_nat44_ei_interface_addr_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_interface_addr_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_interface_addr_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_interface_addr_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_interface_addr_dump);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_interface_addr_dump(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_interface_addr_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_interface_addr_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_interface_addr_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_interface_addr_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_interface_addr_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_interface_addr_dump()
{
  static const char name[] = "nat44_ei_interface_addr_dump";
  static const char name_with_crc[] = "nat44_ei_interface_addr_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_interface_addr_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_interface_addr_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_interface_addr_dump_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_interface_addr_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_interface_addr_dump = vapi_register_msg(&__vapi_metadata_nat44_ei_interface_addr_dump);
  VAPI_DBG("Assigned msg id %d to nat44_ei_interface_addr_dump", vapi_msg_id_nat44_ei_interface_addr_dump);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_user_details
#define defined_vapi_msg_nat44_ei_user_details
typedef struct __attribute__ ((__packed__)) {
  u32 vrf_id;
  vapi_type_ip4_address ip_address;
  u32 nsessions;
  u32 nstaticsessions; 
} vapi_payload_nat44_ei_user_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_user_details payload;
} vapi_msg_nat44_ei_user_details;

static inline void vapi_msg_nat44_ei_user_details_payload_hton(vapi_payload_nat44_ei_user_details *payload)
{
  payload->vrf_id = htobe32(payload->vrf_id);
  payload->nsessions = htobe32(payload->nsessions);
  payload->nstaticsessions = htobe32(payload->nstaticsessions);
}

static inline void vapi_msg_nat44_ei_user_details_payload_ntoh(vapi_payload_nat44_ei_user_details *payload)
{
  payload->vrf_id = be32toh(payload->vrf_id);
  payload->nsessions = be32toh(payload->nsessions);
  payload->nstaticsessions = be32toh(payload->nstaticsessions);
}

static inline void vapi_msg_nat44_ei_user_details_hton(vapi_msg_nat44_ei_user_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_user_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_user_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_user_details_ntoh(vapi_msg_nat44_ei_user_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_user_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_user_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_user_details_msg_size(vapi_msg_nat44_ei_user_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_user_details_msg_size(vapi_msg_nat44_ei_user_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_user_details) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_user_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_user_details));
      return -1;
    }
  if (vapi_calc_nat44_ei_user_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_user_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_user_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_user_details()
{
  static const char name[] = "nat44_ei_user_details";
  static const char name_with_crc[] = "nat44_ei_user_details_355896c2";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_user_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_user_details, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_user_details_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_user_details_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_user_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_user_details = vapi_register_msg(&__vapi_metadata_nat44_ei_user_details);
  VAPI_DBG("Assigned msg id %d to nat44_ei_user_details", vapi_msg_id_nat44_ei_user_details);
}

static inline void vapi_set_vapi_msg_nat44_ei_user_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_user_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_user_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_user_dump
#define defined_vapi_msg_nat44_ei_user_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_nat44_ei_user_dump;

static inline void vapi_msg_nat44_ei_user_dump_hton(vapi_msg_nat44_ei_user_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_user_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_nat44_ei_user_dump_ntoh(vapi_msg_nat44_ei_user_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_user_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_nat44_ei_user_dump_msg_size(vapi_msg_nat44_ei_user_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_user_dump_msg_size(vapi_msg_nat44_ei_user_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_user_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_user_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_user_dump));
      return -1;
    }
  if (vapi_calc_nat44_ei_user_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_user_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_user_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_user_dump* vapi_alloc_nat44_ei_user_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_user_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_user_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_user_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_user_dump);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_user_dump(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_user_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_user_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_user_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_user_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_user_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_user_dump()
{
  static const char name[] = "nat44_ei_user_dump";
  static const char name_with_crc[] = "nat44_ei_user_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_user_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_user_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_user_dump_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_user_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_user_dump = vapi_register_msg(&__vapi_metadata_nat44_ei_user_dump);
  VAPI_DBG("Assigned msg id %d to nat44_ei_user_dump", vapi_msg_id_nat44_ei_user_dump);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_user_session_details
#define defined_vapi_msg_nat44_ei_user_session_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address outside_ip_address;
  u16 outside_port;
  vapi_type_ip4_address inside_ip_address;
  u16 inside_port;
  u16 protocol;
  vapi_enum_nat44_ei_config_flags flags;
  u64 last_heard;
  u64 total_bytes;
  u32 total_pkts;
  vapi_type_ip4_address ext_host_address;
  u16 ext_host_port; 
} vapi_payload_nat44_ei_user_session_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_user_session_details payload;
} vapi_msg_nat44_ei_user_session_details;

static inline void vapi_msg_nat44_ei_user_session_details_payload_hton(vapi_payload_nat44_ei_user_session_details *payload)
{
  payload->outside_port = htobe16(payload->outside_port);
  payload->inside_port = htobe16(payload->inside_port);
  payload->protocol = htobe16(payload->protocol);
  payload->last_heard = htobe64(payload->last_heard);
  payload->total_bytes = htobe64(payload->total_bytes);
  payload->total_pkts = htobe32(payload->total_pkts);
  payload->ext_host_port = htobe16(payload->ext_host_port);
}

static inline void vapi_msg_nat44_ei_user_session_details_payload_ntoh(vapi_payload_nat44_ei_user_session_details *payload)
{
  payload->outside_port = be16toh(payload->outside_port);
  payload->inside_port = be16toh(payload->inside_port);
  payload->protocol = be16toh(payload->protocol);
  payload->last_heard = be64toh(payload->last_heard);
  payload->total_bytes = be64toh(payload->total_bytes);
  payload->total_pkts = be32toh(payload->total_pkts);
  payload->ext_host_port = be16toh(payload->ext_host_port);
}

static inline void vapi_msg_nat44_ei_user_session_details_hton(vapi_msg_nat44_ei_user_session_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_user_session_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_user_session_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_user_session_details_ntoh(vapi_msg_nat44_ei_user_session_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_user_session_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_user_session_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_user_session_details_msg_size(vapi_msg_nat44_ei_user_session_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_user_session_details_msg_size(vapi_msg_nat44_ei_user_session_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_user_session_details) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_user_session_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_user_session_details));
      return -1;
    }
  if (vapi_calc_nat44_ei_user_session_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_user_session_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_user_session_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_user_session_details()
{
  static const char name[] = "nat44_ei_user_session_details";
  static const char name_with_crc[] = "nat44_ei_user_session_details_19b7c0ac";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_user_session_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_user_session_details, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_user_session_details_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_user_session_details_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_user_session_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_user_session_details = vapi_register_msg(&__vapi_metadata_nat44_ei_user_session_details);
  VAPI_DBG("Assigned msg id %d to nat44_ei_user_session_details", vapi_msg_id_nat44_ei_user_session_details);
}

static inline void vapi_set_vapi_msg_nat44_ei_user_session_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_user_session_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_user_session_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_user_session_dump
#define defined_vapi_msg_nat44_ei_user_session_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address ip_address;
  u32 vrf_id; 
} vapi_payload_nat44_ei_user_session_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_user_session_dump payload;
} vapi_msg_nat44_ei_user_session_dump;

static inline void vapi_msg_nat44_ei_user_session_dump_payload_hton(vapi_payload_nat44_ei_user_session_dump *payload)
{
  payload->vrf_id = htobe32(payload->vrf_id);
}

static inline void vapi_msg_nat44_ei_user_session_dump_payload_ntoh(vapi_payload_nat44_ei_user_session_dump *payload)
{
  payload->vrf_id = be32toh(payload->vrf_id);
}

static inline void vapi_msg_nat44_ei_user_session_dump_hton(vapi_msg_nat44_ei_user_session_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_user_session_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_user_session_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_user_session_dump_ntoh(vapi_msg_nat44_ei_user_session_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_user_session_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_user_session_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_user_session_dump_msg_size(vapi_msg_nat44_ei_user_session_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_user_session_dump_msg_size(vapi_msg_nat44_ei_user_session_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_user_session_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_user_session_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_user_session_dump));
      return -1;
    }
  if (vapi_calc_nat44_ei_user_session_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_user_session_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_user_session_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_user_session_dump* vapi_alloc_nat44_ei_user_session_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_user_session_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_user_session_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_user_session_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_user_session_dump);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_user_session_dump(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_user_session_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_user_session_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_user_session_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_user_session_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_user_session_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_user_session_dump()
{
  static const char name[] = "nat44_ei_user_session_dump";
  static const char name_with_crc[] = "nat44_ei_user_session_dump_e1899c98";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_user_session_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_user_session_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_user_session_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_user_session_dump_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_user_session_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_user_session_dump = vapi_register_msg(&__vapi_metadata_nat44_ei_user_session_dump);
  VAPI_DBG("Assigned msg id %d to nat44_ei_user_session_dump", vapi_msg_id_nat44_ei_user_session_dump);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_user_session_v2_details
#define defined_vapi_msg_nat44_ei_user_session_v2_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address outside_ip_address;
  u16 outside_port;
  vapi_type_ip4_address inside_ip_address;
  u16 inside_port;
  u16 protocol;
  vapi_enum_nat44_ei_config_flags flags;
  u64 last_heard;
  u64 time_since_last_heard;
  u64 total_bytes;
  u32 total_pkts;
  vapi_type_ip4_address ext_host_address;
  u16 ext_host_port; 
} vapi_payload_nat44_ei_user_session_v2_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_user_session_v2_details payload;
} vapi_msg_nat44_ei_user_session_v2_details;

static inline void vapi_msg_nat44_ei_user_session_v2_details_payload_hton(vapi_payload_nat44_ei_user_session_v2_details *payload)
{
  payload->outside_port = htobe16(payload->outside_port);
  payload->inside_port = htobe16(payload->inside_port);
  payload->protocol = htobe16(payload->protocol);
  payload->last_heard = htobe64(payload->last_heard);
  payload->time_since_last_heard = htobe64(payload->time_since_last_heard);
  payload->total_bytes = htobe64(payload->total_bytes);
  payload->total_pkts = htobe32(payload->total_pkts);
  payload->ext_host_port = htobe16(payload->ext_host_port);
}

static inline void vapi_msg_nat44_ei_user_session_v2_details_payload_ntoh(vapi_payload_nat44_ei_user_session_v2_details *payload)
{
  payload->outside_port = be16toh(payload->outside_port);
  payload->inside_port = be16toh(payload->inside_port);
  payload->protocol = be16toh(payload->protocol);
  payload->last_heard = be64toh(payload->last_heard);
  payload->time_since_last_heard = be64toh(payload->time_since_last_heard);
  payload->total_bytes = be64toh(payload->total_bytes);
  payload->total_pkts = be32toh(payload->total_pkts);
  payload->ext_host_port = be16toh(payload->ext_host_port);
}

static inline void vapi_msg_nat44_ei_user_session_v2_details_hton(vapi_msg_nat44_ei_user_session_v2_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_user_session_v2_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_user_session_v2_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_user_session_v2_details_ntoh(vapi_msg_nat44_ei_user_session_v2_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_user_session_v2_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_user_session_v2_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_user_session_v2_details_msg_size(vapi_msg_nat44_ei_user_session_v2_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_user_session_v2_details_msg_size(vapi_msg_nat44_ei_user_session_v2_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_user_session_v2_details) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_user_session_v2_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_user_session_v2_details));
      return -1;
    }
  if (vapi_calc_nat44_ei_user_session_v2_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_user_session_v2_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_user_session_v2_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_user_session_v2_details()
{
  static const char name[] = "nat44_ei_user_session_v2_details";
  static const char name_with_crc[] = "nat44_ei_user_session_v2_details_5bd3e9d6";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_user_session_v2_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_user_session_v2_details, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_user_session_v2_details_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_user_session_v2_details_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_user_session_v2_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_user_session_v2_details = vapi_register_msg(&__vapi_metadata_nat44_ei_user_session_v2_details);
  VAPI_DBG("Assigned msg id %d to nat44_ei_user_session_v2_details", vapi_msg_id_nat44_ei_user_session_v2_details);
}

static inline void vapi_set_vapi_msg_nat44_ei_user_session_v2_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_user_session_v2_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_user_session_v2_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_user_session_v2_dump
#define defined_vapi_msg_nat44_ei_user_session_v2_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address ip_address;
  u32 vrf_id; 
} vapi_payload_nat44_ei_user_session_v2_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_user_session_v2_dump payload;
} vapi_msg_nat44_ei_user_session_v2_dump;

static inline void vapi_msg_nat44_ei_user_session_v2_dump_payload_hton(vapi_payload_nat44_ei_user_session_v2_dump *payload)
{
  payload->vrf_id = htobe32(payload->vrf_id);
}

static inline void vapi_msg_nat44_ei_user_session_v2_dump_payload_ntoh(vapi_payload_nat44_ei_user_session_v2_dump *payload)
{
  payload->vrf_id = be32toh(payload->vrf_id);
}

static inline void vapi_msg_nat44_ei_user_session_v2_dump_hton(vapi_msg_nat44_ei_user_session_v2_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_user_session_v2_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_user_session_v2_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_user_session_v2_dump_ntoh(vapi_msg_nat44_ei_user_session_v2_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_user_session_v2_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_user_session_v2_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_user_session_v2_dump_msg_size(vapi_msg_nat44_ei_user_session_v2_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_user_session_v2_dump_msg_size(vapi_msg_nat44_ei_user_session_v2_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_user_session_v2_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_user_session_v2_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_user_session_v2_dump));
      return -1;
    }
  if (vapi_calc_nat44_ei_user_session_v2_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_user_session_v2_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_user_session_v2_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_user_session_v2_dump* vapi_alloc_nat44_ei_user_session_v2_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_user_session_v2_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_user_session_v2_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_user_session_v2_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_user_session_v2_dump);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_user_session_v2_dump(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_user_session_v2_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_user_session_v2_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_user_session_v2_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_user_session_v2_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_user_session_v2_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_user_session_v2_dump()
{
  static const char name[] = "nat44_ei_user_session_v2_dump";
  static const char name_with_crc[] = "nat44_ei_user_session_v2_dump_e1899c98";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_user_session_v2_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_user_session_v2_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_user_session_v2_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_user_session_v2_dump_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_user_session_v2_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_user_session_v2_dump = vapi_register_msg(&__vapi_metadata_nat44_ei_user_session_v2_dump);
  VAPI_DBG("Assigned msg id %d to nat44_ei_user_session_v2_dump", vapi_msg_id_nat44_ei_user_session_v2_dump);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_del_session_reply
#define defined_vapi_msg_nat44_ei_del_session_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_del_session_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_del_session_reply payload;
} vapi_msg_nat44_ei_del_session_reply;

static inline void vapi_msg_nat44_ei_del_session_reply_payload_hton(vapi_payload_nat44_ei_del_session_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_del_session_reply_payload_ntoh(vapi_payload_nat44_ei_del_session_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_del_session_reply_hton(vapi_msg_nat44_ei_del_session_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_del_session_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_del_session_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_del_session_reply_ntoh(vapi_msg_nat44_ei_del_session_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_del_session_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_del_session_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_del_session_reply_msg_size(vapi_msg_nat44_ei_del_session_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_del_session_reply_msg_size(vapi_msg_nat44_ei_del_session_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_del_session_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_del_session_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_del_session_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_del_session_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_del_session_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_del_session_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_del_session_reply()
{
  static const char name[] = "nat44_ei_del_session_reply";
  static const char name_with_crc[] = "nat44_ei_del_session_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_del_session_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_del_session_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_del_session_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_del_session_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_del_session_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_del_session_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_del_session_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_del_session_reply", vapi_msg_id_nat44_ei_del_session_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_del_session_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_del_session_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_del_session_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_del_session
#define defined_vapi_msg_nat44_ei_del_session
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address address;
  u8 protocol;
  u16 port;
  u32 vrf_id;
  vapi_enum_nat44_ei_config_flags flags;
  vapi_type_ip4_address ext_host_address;
  u16 ext_host_port; 
} vapi_payload_nat44_ei_del_session;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_del_session payload;
} vapi_msg_nat44_ei_del_session;

static inline void vapi_msg_nat44_ei_del_session_payload_hton(vapi_payload_nat44_ei_del_session *payload)
{
  payload->port = htobe16(payload->port);
  payload->vrf_id = htobe32(payload->vrf_id);
  payload->ext_host_port = htobe16(payload->ext_host_port);
}

static inline void vapi_msg_nat44_ei_del_session_payload_ntoh(vapi_payload_nat44_ei_del_session *payload)
{
  payload->port = be16toh(payload->port);
  payload->vrf_id = be32toh(payload->vrf_id);
  payload->ext_host_port = be16toh(payload->ext_host_port);
}

static inline void vapi_msg_nat44_ei_del_session_hton(vapi_msg_nat44_ei_del_session *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_del_session'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_del_session_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_del_session_ntoh(vapi_msg_nat44_ei_del_session *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_del_session'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_del_session_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_del_session_msg_size(vapi_msg_nat44_ei_del_session *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_del_session_msg_size(vapi_msg_nat44_ei_del_session *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_del_session) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_del_session' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_del_session));
      return -1;
    }
  if (vapi_calc_nat44_ei_del_session_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_del_session' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_del_session_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_del_session* vapi_alloc_nat44_ei_del_session(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_del_session *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_del_session);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_del_session*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_del_session);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_del_session(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_del_session *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_del_session_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_del_session_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_del_session_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_del_session_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_del_session()
{
  static const char name[] = "nat44_ei_del_session";
  static const char name_with_crc[] = "nat44_ei_del_session_74969ffe";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_del_session = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_del_session, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_del_session_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_del_session_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_del_session_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_del_session = vapi_register_msg(&__vapi_metadata_nat44_ei_del_session);
  VAPI_DBG("Assigned msg id %d to nat44_ei_del_session", vapi_msg_id_nat44_ei_del_session);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_forwarding_enable_disable_reply
#define defined_vapi_msg_nat44_ei_forwarding_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_forwarding_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_forwarding_enable_disable_reply payload;
} vapi_msg_nat44_ei_forwarding_enable_disable_reply;

static inline void vapi_msg_nat44_ei_forwarding_enable_disable_reply_payload_hton(vapi_payload_nat44_ei_forwarding_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_forwarding_enable_disable_reply_payload_ntoh(vapi_payload_nat44_ei_forwarding_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_forwarding_enable_disable_reply_hton(vapi_msg_nat44_ei_forwarding_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_forwarding_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_forwarding_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_forwarding_enable_disable_reply_ntoh(vapi_msg_nat44_ei_forwarding_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_forwarding_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_forwarding_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_forwarding_enable_disable_reply_msg_size(vapi_msg_nat44_ei_forwarding_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_forwarding_enable_disable_reply_msg_size(vapi_msg_nat44_ei_forwarding_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_forwarding_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_forwarding_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_forwarding_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_forwarding_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_forwarding_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_forwarding_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_forwarding_enable_disable_reply()
{
  static const char name[] = "nat44_ei_forwarding_enable_disable_reply";
  static const char name_with_crc[] = "nat44_ei_forwarding_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_forwarding_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_forwarding_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_forwarding_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_forwarding_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_forwarding_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_forwarding_enable_disable_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_forwarding_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_forwarding_enable_disable_reply", vapi_msg_id_nat44_ei_forwarding_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_forwarding_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_forwarding_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_forwarding_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_forwarding_enable_disable
#define defined_vapi_msg_nat44_ei_forwarding_enable_disable
typedef struct __attribute__ ((__packed__)) {
  bool enable; 
} vapi_payload_nat44_ei_forwarding_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_forwarding_enable_disable payload;
} vapi_msg_nat44_ei_forwarding_enable_disable;

static inline void vapi_msg_nat44_ei_forwarding_enable_disable_payload_hton(vapi_payload_nat44_ei_forwarding_enable_disable *payload)
{

}

static inline void vapi_msg_nat44_ei_forwarding_enable_disable_payload_ntoh(vapi_payload_nat44_ei_forwarding_enable_disable *payload)
{

}

static inline void vapi_msg_nat44_ei_forwarding_enable_disable_hton(vapi_msg_nat44_ei_forwarding_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_forwarding_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_forwarding_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_forwarding_enable_disable_ntoh(vapi_msg_nat44_ei_forwarding_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_forwarding_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_forwarding_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_forwarding_enable_disable_msg_size(vapi_msg_nat44_ei_forwarding_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_forwarding_enable_disable_msg_size(vapi_msg_nat44_ei_forwarding_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_forwarding_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_forwarding_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_forwarding_enable_disable));
      return -1;
    }
  if (vapi_calc_nat44_ei_forwarding_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_forwarding_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_forwarding_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_forwarding_enable_disable* vapi_alloc_nat44_ei_forwarding_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_forwarding_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_forwarding_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_forwarding_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_forwarding_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_forwarding_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_forwarding_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_forwarding_enable_disable_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_forwarding_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_forwarding_enable_disable_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_forwarding_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_forwarding_enable_disable()
{
  static const char name[] = "nat44_ei_forwarding_enable_disable";
  static const char name_with_crc[] = "nat44_ei_forwarding_enable_disable_b3e225d2";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_forwarding_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_forwarding_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_forwarding_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_forwarding_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_forwarding_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_forwarding_enable_disable = vapi_register_msg(&__vapi_metadata_nat44_ei_forwarding_enable_disable);
  VAPI_DBG("Assigned msg id %d to nat44_ei_forwarding_enable_disable", vapi_msg_id_nat44_ei_forwarding_enable_disable);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_set_fq_options_reply
#define defined_vapi_msg_nat44_ei_set_fq_options_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat44_ei_set_fq_options_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_set_fq_options_reply payload;
} vapi_msg_nat44_ei_set_fq_options_reply;

static inline void vapi_msg_nat44_ei_set_fq_options_reply_payload_hton(vapi_payload_nat44_ei_set_fq_options_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat44_ei_set_fq_options_reply_payload_ntoh(vapi_payload_nat44_ei_set_fq_options_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat44_ei_set_fq_options_reply_hton(vapi_msg_nat44_ei_set_fq_options_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_fq_options_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_set_fq_options_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_set_fq_options_reply_ntoh(vapi_msg_nat44_ei_set_fq_options_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_fq_options_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_set_fq_options_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_set_fq_options_reply_msg_size(vapi_msg_nat44_ei_set_fq_options_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_set_fq_options_reply_msg_size(vapi_msg_nat44_ei_set_fq_options_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_set_fq_options_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_fq_options_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_set_fq_options_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_set_fq_options_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_fq_options_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_set_fq_options_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_set_fq_options_reply()
{
  static const char name[] = "nat44_ei_set_fq_options_reply";
  static const char name_with_crc[] = "nat44_ei_set_fq_options_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_set_fq_options_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_set_fq_options_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_set_fq_options_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_fq_options_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_fq_options_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_set_fq_options_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_set_fq_options_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_set_fq_options_reply", vapi_msg_id_nat44_ei_set_fq_options_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_set_fq_options_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_set_fq_options_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_set_fq_options_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_set_fq_options
#define defined_vapi_msg_nat44_ei_set_fq_options
typedef struct __attribute__ ((__packed__)) {
  u32 frame_queue_nelts; 
} vapi_payload_nat44_ei_set_fq_options;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat44_ei_set_fq_options payload;
} vapi_msg_nat44_ei_set_fq_options;

static inline void vapi_msg_nat44_ei_set_fq_options_payload_hton(vapi_payload_nat44_ei_set_fq_options *payload)
{
  payload->frame_queue_nelts = htobe32(payload->frame_queue_nelts);
}

static inline void vapi_msg_nat44_ei_set_fq_options_payload_ntoh(vapi_payload_nat44_ei_set_fq_options *payload)
{
  payload->frame_queue_nelts = be32toh(payload->frame_queue_nelts);
}

static inline void vapi_msg_nat44_ei_set_fq_options_hton(vapi_msg_nat44_ei_set_fq_options *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_fq_options'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat44_ei_set_fq_options_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_set_fq_options_ntoh(vapi_msg_nat44_ei_set_fq_options *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_set_fq_options'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_set_fq_options_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_set_fq_options_msg_size(vapi_msg_nat44_ei_set_fq_options *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_set_fq_options_msg_size(vapi_msg_nat44_ei_set_fq_options *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_set_fq_options) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_fq_options' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_set_fq_options));
      return -1;
    }
  if (vapi_calc_nat44_ei_set_fq_options_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_set_fq_options' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_set_fq_options_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_set_fq_options* vapi_alloc_nat44_ei_set_fq_options(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_set_fq_options *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_set_fq_options);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_set_fq_options*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_set_fq_options);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_set_fq_options(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_set_fq_options *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_set_fq_options_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_set_fq_options_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_set_fq_options_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_set_fq_options_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_set_fq_options()
{
  static const char name[] = "nat44_ei_set_fq_options";
  static const char name_with_crc[] = "nat44_ei_set_fq_options_2399bd71";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_set_fq_options = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat44_ei_set_fq_options, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_set_fq_options_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_fq_options_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_set_fq_options_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_set_fq_options = vapi_register_msg(&__vapi_metadata_nat44_ei_set_fq_options);
  VAPI_DBG("Assigned msg id %d to nat44_ei_set_fq_options", vapi_msg_id_nat44_ei_set_fq_options);
}
#endif

#ifndef defined_vapi_msg_nat44_ei_show_fq_options_reply
#define defined_vapi_msg_nat44_ei_show_fq_options_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 frame_queue_nelts; 
} vapi_payload_nat44_ei_show_fq_options_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat44_ei_show_fq_options_reply payload;
} vapi_msg_nat44_ei_show_fq_options_reply;

static inline void vapi_msg_nat44_ei_show_fq_options_reply_payload_hton(vapi_payload_nat44_ei_show_fq_options_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->frame_queue_nelts = htobe32(payload->frame_queue_nelts);
}

static inline void vapi_msg_nat44_ei_show_fq_options_reply_payload_ntoh(vapi_payload_nat44_ei_show_fq_options_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->frame_queue_nelts = be32toh(payload->frame_queue_nelts);
}

static inline void vapi_msg_nat44_ei_show_fq_options_reply_hton(vapi_msg_nat44_ei_show_fq_options_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_show_fq_options_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat44_ei_show_fq_options_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat44_ei_show_fq_options_reply_ntoh(vapi_msg_nat44_ei_show_fq_options_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_show_fq_options_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat44_ei_show_fq_options_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat44_ei_show_fq_options_reply_msg_size(vapi_msg_nat44_ei_show_fq_options_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_show_fq_options_reply_msg_size(vapi_msg_nat44_ei_show_fq_options_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_show_fq_options_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_show_fq_options_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_show_fq_options_reply));
      return -1;
    }
  if (vapi_calc_nat44_ei_show_fq_options_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_show_fq_options_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_show_fq_options_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat44_ei_show_fq_options_reply()
{
  static const char name[] = "nat44_ei_show_fq_options_reply";
  static const char name_with_crc[] = "nat44_ei_show_fq_options_reply_7213b545";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_show_fq_options_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat44_ei_show_fq_options_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_show_fq_options_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_show_fq_options_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_show_fq_options_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_show_fq_options_reply = vapi_register_msg(&__vapi_metadata_nat44_ei_show_fq_options_reply);
  VAPI_DBG("Assigned msg id %d to nat44_ei_show_fq_options_reply", vapi_msg_id_nat44_ei_show_fq_options_reply);
}

static inline void vapi_set_vapi_msg_nat44_ei_show_fq_options_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat44_ei_show_fq_options_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat44_ei_show_fq_options_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat44_ei_show_fq_options
#define defined_vapi_msg_nat44_ei_show_fq_options
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_nat44_ei_show_fq_options;

static inline void vapi_msg_nat44_ei_show_fq_options_hton(vapi_msg_nat44_ei_show_fq_options *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_show_fq_options'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_nat44_ei_show_fq_options_ntoh(vapi_msg_nat44_ei_show_fq_options *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat44_ei_show_fq_options'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_nat44_ei_show_fq_options_msg_size(vapi_msg_nat44_ei_show_fq_options *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat44_ei_show_fq_options_msg_size(vapi_msg_nat44_ei_show_fq_options *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat44_ei_show_fq_options) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_show_fq_options' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat44_ei_show_fq_options));
      return -1;
    }
  if (vapi_calc_nat44_ei_show_fq_options_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat44_ei_show_fq_options' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat44_ei_show_fq_options_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat44_ei_show_fq_options* vapi_alloc_nat44_ei_show_fq_options(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat44_ei_show_fq_options *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat44_ei_show_fq_options);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat44_ei_show_fq_options*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat44_ei_show_fq_options);

  return msg;
}

static inline vapi_error_e vapi_nat44_ei_show_fq_options(struct vapi_ctx_s *ctx,
  vapi_msg_nat44_ei_show_fq_options *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat44_ei_show_fq_options_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_nat44_ei_show_fq_options_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat44_ei_show_fq_options_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_nat44_ei_show_fq_options_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat44_ei_show_fq_options()
{
  static const char name[] = "nat44_ei_show_fq_options";
  static const char name_with_crc[] = "nat44_ei_show_fq_options_51077d14";
  static vapi_message_desc_t __vapi_metadata_nat44_ei_show_fq_options = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_nat44_ei_show_fq_options_msg_size,
    (generic_swap_fn_t)vapi_msg_nat44_ei_show_fq_options_hton,
    (generic_swap_fn_t)vapi_msg_nat44_ei_show_fq_options_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat44_ei_show_fq_options = vapi_register_msg(&__vapi_metadata_nat44_ei_show_fq_options);
  VAPI_DBG("Assigned msg id %d to nat44_ei_show_fq_options", vapi_msg_id_nat44_ei_show_fq_options);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
