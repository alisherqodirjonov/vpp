#ifndef included_flow_types_api_types_h
#define included_flow_types_api_types_h
#define VL_API_FLOW_TYPES_API_VERSION_MAJOR 0
#define VL_API_FLOW_TYPES_API_VERSION_MINOR 0
#define VL_API_FLOW_TYPES_API_VERSION_PATCH 4
/* Imported API files */
#include <vnet/ethernet/ethernet_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
typedef enum {
    FLOW_TYPE_ETHERNET = 1,
    FLOW_TYPE_IP4 = 2,
    FLOW_TYPE_IP6 = 3,
    FLOW_TYPE_IP4_L2TPV3OIP = 4,
    FLOW_TYPE_IP4_IPSEC_ESP = 5,
    FLOW_TYPE_IP4_IPSEC_AH = 6,
    FLOW_TYPE_IP4_N_TUPLE = 7,
    FLOW_TYPE_IP6_N_TUPLE = 8,
    FLOW_TYPE_IP4_N_TUPLE_TAGGED = 9,
    FLOW_TYPE_IP6_N_TUPLE_TAGGED = 10,
    FLOW_TYPE_IP4_VXLAN = 11,
    FLOW_TYPE_IP6_VXLAN = 12,
    FLOW_TYPE_IP4_GTPC = 13,
    FLOW_TYPE_IP4_GTPU = 14,
} vl_api_flow_type_t;
typedef enum {
    FLOW_TYPE_ETHERNET_V2 = 1,
    FLOW_TYPE_IP4_V2 = 2,
    FLOW_TYPE_IP6_V2 = 3,
    FLOW_TYPE_IP4_L2TPV3OIP_V2 = 4,
    FLOW_TYPE_IP4_IPSEC_ESP_V2 = 5,
    FLOW_TYPE_IP4_IPSEC_AH_V2 = 6,
    FLOW_TYPE_IP4_N_TUPLE_V2 = 7,
    FLOW_TYPE_IP6_N_TUPLE_V2 = 8,
    FLOW_TYPE_IP4_N_TUPLE_TAGGED_V2 = 9,
    FLOW_TYPE_IP6_N_TUPLE_TAGGED_V2 = 10,
    FLOW_TYPE_IP4_VXLAN_V2 = 11,
    FLOW_TYPE_IP6_VXLAN_V2 = 12,
    FLOW_TYPE_IP4_GTPC_V2 = 13,
    FLOW_TYPE_IP4_GTPU_V2 = 14,
    FLOW_TYPE_GENERIC_V2 = 15,
} vl_api_flow_type_v2_t;
typedef enum {
    FLOW_ACTION_COUNT = 1,
    FLOW_ACTION_MARK = 2,
    FLOW_ACTION_BUFFER_ADVANCE = 4,
    FLOW_ACTION_REDIRECT_TO_NODE = 8,
    FLOW_ACTION_REDIRECT_TO_QUEUE = 16,
    FLOW_ACTION_DROP = 64,
} vl_api_flow_action_t;
typedef enum {
    FLOW_ACTION_COUNT_V2 = 1,
    FLOW_ACTION_MARK_V2 = 2,
    FLOW_ACTION_BUFFER_ADVANCE_V2 = 4,
    FLOW_ACTION_REDIRECT_TO_NODE_V2 = 8,
    FLOW_ACTION_REDIRECT_TO_QUEUE_V2 = 16,
    FLOW_ACTION_RSS_V2 = 32,
    FLOW_ACTION_DROP_V2 = 64,
} vl_api_flow_action_v2_t;
typedef enum {
    RSS_FUNC_DEFAULT = 0,
    RSS_FUNC_TOEPLITZ = 1,
    RSS_FUNC_SIMPLE_XOR = 2,
    RSS_FUNC_SYMMETRIC_TOEPLITZ = 3,
} vl_api_rss_function_t;
typedef struct __attribute__ ((packed)) _vl_api_generic_pattern {
    u8 spec[1024];
    u8 mask[1024];
} vl_api_generic_pattern_t;
#define VL_API_GENERIC_PATTERN_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip_port_and_mask {
    u16 port;
    u16 mask;
} vl_api_ip_port_and_mask_t;
#define VL_API_IP_PORT_AND_MASK_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip_prot_and_mask {
    vl_api_ip_proto_t prot;
    u8 mask;
} vl_api_ip_prot_and_mask_t;
#define VL_API_IP_PROT_AND_MASK_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_ethernet {
    i32 foo;
    vl_api_mac_address_t src_addr;
    vl_api_mac_address_t dst_addr;
    u16 type;
} vl_api_flow_ethernet_t;
#define VL_API_FLOW_ETHERNET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_ip4 {
    i32 foo;
    vl_api_ip4_address_and_mask_t src_addr;
    vl_api_ip4_address_and_mask_t dst_addr;
    vl_api_ip_prot_and_mask_t protocol;
} vl_api_flow_ip4_t;
#define VL_API_FLOW_IP4_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_ip6 {
    i32 foo;
    vl_api_ip6_address_and_mask_t src_addr;
    vl_api_ip6_address_and_mask_t dst_addr;
    vl_api_ip_prot_and_mask_t protocol;
} vl_api_flow_ip6_t;
#define VL_API_FLOW_IP6_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_ip4_n_tuple {
    i32 foo;
    vl_api_ip4_address_and_mask_t src_addr;
    vl_api_ip4_address_and_mask_t dst_addr;
    vl_api_ip_prot_and_mask_t protocol;
    vl_api_ip_port_and_mask_t src_port;
    vl_api_ip_port_and_mask_t dst_port;
} vl_api_flow_ip4_n_tuple_t;
#define VL_API_FLOW_IP4_N_TUPLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_ip6_n_tuple {
    i32 foo;
    vl_api_ip6_address_and_mask_t src_addr;
    vl_api_ip6_address_and_mask_t dst_addr;
    vl_api_ip_prot_and_mask_t protocol;
    vl_api_ip_port_and_mask_t src_port;
    vl_api_ip_port_and_mask_t dst_port;
} vl_api_flow_ip6_n_tuple_t;
#define VL_API_FLOW_IP6_N_TUPLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_ip4_n_tuple_tagged {
    i32 foo;
    vl_api_ip4_address_and_mask_t src_addr;
    vl_api_ip4_address_and_mask_t dst_addr;
    vl_api_ip_prot_and_mask_t protocol;
    vl_api_ip_port_and_mask_t src_port;
    vl_api_ip_port_and_mask_t dst_port;
} vl_api_flow_ip4_n_tuple_tagged_t;
#define VL_API_FLOW_IP4_N_TUPLE_TAGGED_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_ip6_n_tuple_tagged {
    i32 foo;
    vl_api_ip6_address_and_mask_t src_addr;
    vl_api_ip6_address_and_mask_t dst_addr;
    vl_api_ip_prot_and_mask_t protocol;
    vl_api_ip_port_and_mask_t src_port;
    vl_api_ip_port_and_mask_t dst_port;
} vl_api_flow_ip6_n_tuple_tagged_t;
#define VL_API_FLOW_IP6_N_TUPLE_TAGGED_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_ip4_l2tpv3oip {
    i32 foo;
    vl_api_ip4_address_and_mask_t src_addr;
    vl_api_ip4_address_and_mask_t dst_addr;
    vl_api_ip_prot_and_mask_t protocol;
    u32 session_id;
} vl_api_flow_ip4_l2tpv3oip_t;
#define VL_API_FLOW_IP4_L2TPV3OIP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_ip4_ipsec_esp {
    i32 foo;
    vl_api_ip4_address_and_mask_t src_addr;
    vl_api_ip4_address_and_mask_t dst_addr;
    vl_api_ip_prot_and_mask_t protocol;
    u32 spi;
} vl_api_flow_ip4_ipsec_esp_t;
#define VL_API_FLOW_IP4_IPSEC_ESP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_ip4_ipsec_ah {
    i32 foo;
    vl_api_ip4_address_and_mask_t src_addr;
    vl_api_ip4_address_and_mask_t dst_addr;
    vl_api_ip_prot_and_mask_t protocol;
    u32 spi;
} vl_api_flow_ip4_ipsec_ah_t;
#define VL_API_FLOW_IP4_IPSEC_AH_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_ip4_vxlan {
    i32 foo;
    vl_api_ip4_address_and_mask_t src_addr;
    vl_api_ip4_address_and_mask_t dst_addr;
    vl_api_ip_prot_and_mask_t protocol;
    vl_api_ip_port_and_mask_t src_port;
    vl_api_ip_port_and_mask_t dst_port;
    u32 vni;
} vl_api_flow_ip4_vxlan_t;
#define VL_API_FLOW_IP4_VXLAN_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_ip6_vxlan {
    i32 foo;
    vl_api_ip6_address_and_mask_t src_addr;
    vl_api_ip6_address_and_mask_t dst_addr;
    vl_api_ip_prot_and_mask_t protocol;
    vl_api_ip_port_and_mask_t src_port;
    vl_api_ip_port_and_mask_t dst_port;
    u32 vni;
} vl_api_flow_ip6_vxlan_t;
#define VL_API_FLOW_IP6_VXLAN_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_ip4_gtpc {
    i32 foo;
    vl_api_ip4_address_and_mask_t src_addr;
    vl_api_ip4_address_and_mask_t dst_addr;
    vl_api_ip_prot_and_mask_t protocol;
    vl_api_ip_port_and_mask_t src_port;
    vl_api_ip_port_and_mask_t dst_port;
    u32 teid;
} vl_api_flow_ip4_gtpc_t;
#define VL_API_FLOW_IP4_GTPC_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_ip4_gtpu {
    i32 foo;
    vl_api_ip4_address_and_mask_t src_addr;
    vl_api_ip4_address_and_mask_t dst_addr;
    vl_api_ip_prot_and_mask_t protocol;
    vl_api_ip_port_and_mask_t src_port;
    vl_api_ip_port_and_mask_t dst_port;
    u32 teid;
} vl_api_flow_ip4_gtpu_t;
#define VL_API_FLOW_IP4_GTPU_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_generic {
    i32 foo;
    vl_api_generic_pattern_t pattern;
} vl_api_flow_generic_t;
#define VL_API_FLOW_GENERIC_IS_CONSTANT_SIZE (1)

typedef union __attribute__ ((packed)) _vl_api_flow {
    vl_api_flow_ethernet_t ethernet;
    vl_api_flow_ip4_t ip4;
    vl_api_flow_ip6_t ip6;
    vl_api_flow_ip4_l2tpv3oip_t ip4_l2tpv3oip;
    vl_api_flow_ip4_ipsec_esp_t ip4_ipsec_esp;
    vl_api_flow_ip4_ipsec_ah_t ip4_ipsec_ah;
    vl_api_flow_ip4_n_tuple_t ip4_n_tuple;
    vl_api_flow_ip6_n_tuple_t ip6_n_tuple;
    vl_api_flow_ip4_n_tuple_tagged_t ip4_n_tuple_tagged;
    vl_api_flow_ip6_n_tuple_tagged_t ip6_n_tuple_tagged;
    vl_api_flow_ip4_vxlan_t ip4_vxlan;
    vl_api_flow_ip6_vxlan_t ip6_vxlan;
    vl_api_flow_ip4_gtpc_t ip4_gtpc;
    vl_api_flow_ip4_gtpu_t ip4_gtpu;
} vl_api_flow_t;
#define VL_API_FLOW_IS_CONSTANT_SIZE (1)

typedef union __attribute__ ((packed)) _vl_api_flow_v2 {
    vl_api_flow_ethernet_t ethernet;
    vl_api_flow_ip4_t ip4;
    vl_api_flow_ip6_t ip6;
    vl_api_flow_ip4_l2tpv3oip_t ip4_l2tpv3oip;
    vl_api_flow_ip4_ipsec_esp_t ip4_ipsec_esp;
    vl_api_flow_ip4_ipsec_ah_t ip4_ipsec_ah;
    vl_api_flow_ip4_n_tuple_t ip4_n_tuple;
    vl_api_flow_ip6_n_tuple_t ip6_n_tuple;
    vl_api_flow_ip4_n_tuple_tagged_t ip4_n_tuple_tagged;
    vl_api_flow_ip6_n_tuple_tagged_t ip6_n_tuple_tagged;
    vl_api_flow_ip4_vxlan_t ip4_vxlan;
    vl_api_flow_ip6_vxlan_t ip6_vxlan;
    vl_api_flow_ip4_gtpc_t ip4_gtpc;
    vl_api_flow_ip4_gtpu_t ip4_gtpu;
    vl_api_flow_generic_t generic;
} vl_api_flow_v2_t;
#define VL_API_FLOW_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_rule {
    vl_api_flow_type_t type;
    u32 index;
    vl_api_flow_action_t actions;
    u32 mark_flow_id;
    u32 redirect_node_index;
    u32 redirect_device_input_next_index;
    u32 redirect_queue;
    i32 buffer_advance;
    vl_api_flow_t flow;
} vl_api_flow_rule_t;
#define VL_API_FLOW_RULE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_rule_v2 {
    vl_api_flow_type_v2_t type;
    u32 index;
    vl_api_flow_action_v2_t actions;
    u32 mark_flow_id;
    u32 redirect_node_index;
    u32 redirect_device_input_next_index;
    u32 redirect_queue;
    u32 queue_index;
    u32 queue_num;
    i32 buffer_advance;
    u64 rss_types;
    vl_api_rss_function_t rss_fun;
    vl_api_flow_v2_t flow;
} vl_api_flow_rule_v2_t;
#define VL_API_FLOW_RULE_V2_IS_CONSTANT_SIZE (1)


#endif
