#ifndef __included_flow_api_json
#define __included_flow_api_json

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

extern vapi_msg_id_t vapi_msg_id_flow_add;
extern vapi_msg_id_t vapi_msg_id_flow_add_v2;
extern vapi_msg_id_t vapi_msg_id_flow_add_reply;
extern vapi_msg_id_t vapi_msg_id_flow_add_v2_reply;
extern vapi_msg_id_t vapi_msg_id_flow_del;
extern vapi_msg_id_t vapi_msg_id_flow_del_reply;
extern vapi_msg_id_t vapi_msg_id_flow_enable;
extern vapi_msg_id_t vapi_msg_id_flow_enable_reply;
extern vapi_msg_id_t vapi_msg_id_flow_disable;
extern vapi_msg_id_t vapi_msg_id_flow_disable_reply;

#define DEFINE_VAPI_MSG_IDS_FLOW_API_JSON\
  vapi_msg_id_t vapi_msg_id_flow_add;\
  vapi_msg_id_t vapi_msg_id_flow_add_v2;\
  vapi_msg_id_t vapi_msg_id_flow_add_reply;\
  vapi_msg_id_t vapi_msg_id_flow_add_v2_reply;\
  vapi_msg_id_t vapi_msg_id_flow_del;\
  vapi_msg_id_t vapi_msg_id_flow_del_reply;\
  vapi_msg_id_t vapi_msg_id_flow_enable;\
  vapi_msg_id_t vapi_msg_id_flow_enable_reply;\
  vapi_msg_id_t vapi_msg_id_flow_disable;\
  vapi_msg_id_t vapi_msg_id_flow_disable_reply;


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

#ifndef defined_vapi_enum_flow_type
#define defined_vapi_enum_flow_type
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
}  vapi_enum_flow_type;

#endif

#ifndef defined_vapi_enum_flow_type_v2
#define defined_vapi_enum_flow_type_v2
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
}  vapi_enum_flow_type_v2;

#endif

#ifndef defined_vapi_enum_flow_action
#define defined_vapi_enum_flow_action
typedef enum {
  FLOW_ACTION_COUNT = 1,
  FLOW_ACTION_MARK = 2,
  FLOW_ACTION_BUFFER_ADVANCE = 4,
  FLOW_ACTION_REDIRECT_TO_NODE = 8,
  FLOW_ACTION_REDIRECT_TO_QUEUE = 16,
  FLOW_ACTION_DROP = 64,
}  vapi_enum_flow_action;

#endif

#ifndef defined_vapi_enum_flow_action_v2
#define defined_vapi_enum_flow_action_v2
typedef enum {
  FLOW_ACTION_COUNT_V2 = 1,
  FLOW_ACTION_MARK_V2 = 2,
  FLOW_ACTION_BUFFER_ADVANCE_V2 = 4,
  FLOW_ACTION_REDIRECT_TO_NODE_V2 = 8,
  FLOW_ACTION_REDIRECT_TO_QUEUE_V2 = 16,
  FLOW_ACTION_RSS_V2 = 32,
  FLOW_ACTION_DROP_V2 = 64,
}  vapi_enum_flow_action_v2;

#endif

#ifndef defined_vapi_enum_rss_function
#define defined_vapi_enum_rss_function
typedef enum {
  RSS_FUNC_DEFAULT = 0,
  RSS_FUNC_TOEPLITZ = 1,
  RSS_FUNC_SIMPLE_XOR = 2,
  RSS_FUNC_SYMMETRIC_TOEPLITZ = 3,
}  vapi_enum_rss_function;

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

#ifndef defined_vapi_type_mac_address
#define defined_vapi_type_mac_address
typedef u8 vapi_type_mac_address[6];

#endif

#ifndef defined_vapi_type_flow_ethernet
#define defined_vapi_type_flow_ethernet
typedef struct __attribute__((__packed__)) {
  i32 foo;
  vapi_type_mac_address src_addr;
  vapi_type_mac_address dst_addr;
  u16 type;
} vapi_type_flow_ethernet;

static inline void vapi_type_flow_ethernet_hton(vapi_type_flow_ethernet *msg)
{
  msg->foo = htobe32(msg->foo);
  msg->type = htobe16(msg->type);
}

static inline void vapi_type_flow_ethernet_ntoh(vapi_type_flow_ethernet *msg)
{
  msg->foo = be32toh(msg->foo);
  msg->type = be16toh(msg->type);
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

#ifndef defined_vapi_type_ip_prot_and_mask
#define defined_vapi_type_ip_prot_and_mask
typedef struct __attribute__((__packed__)) {
  vapi_enum_ip_proto prot;
  u8 mask;
} vapi_type_ip_prot_and_mask;

static inline void vapi_type_ip_prot_and_mask_hton(vapi_type_ip_prot_and_mask *msg)
{

}

static inline void vapi_type_ip_prot_and_mask_ntoh(vapi_type_ip_prot_and_mask *msg)
{

}
#endif

#ifndef defined_vapi_type_flow_ip4
#define defined_vapi_type_flow_ip4
typedef struct __attribute__((__packed__)) {
  i32 foo;
  vapi_type_ip4_address_and_mask src_addr;
  vapi_type_ip4_address_and_mask dst_addr;
  vapi_type_ip_prot_and_mask protocol;
} vapi_type_flow_ip4;

static inline void vapi_type_flow_ip4_hton(vapi_type_flow_ip4 *msg)
{
  msg->foo = htobe32(msg->foo);
}

static inline void vapi_type_flow_ip4_ntoh(vapi_type_flow_ip4 *msg)
{
  msg->foo = be32toh(msg->foo);
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

#ifndef defined_vapi_type_flow_ip6
#define defined_vapi_type_flow_ip6
typedef struct __attribute__((__packed__)) {
  i32 foo;
  vapi_type_ip6_address_and_mask src_addr;
  vapi_type_ip6_address_and_mask dst_addr;
  vapi_type_ip_prot_and_mask protocol;
} vapi_type_flow_ip6;

static inline void vapi_type_flow_ip6_hton(vapi_type_flow_ip6 *msg)
{
  msg->foo = htobe32(msg->foo);
}

static inline void vapi_type_flow_ip6_ntoh(vapi_type_flow_ip6 *msg)
{
  msg->foo = be32toh(msg->foo);
}
#endif

#ifndef defined_vapi_type_flow_ip4_l2tpv3oip
#define defined_vapi_type_flow_ip4_l2tpv3oip
typedef struct __attribute__((__packed__)) {
  i32 foo;
  vapi_type_ip4_address_and_mask src_addr;
  vapi_type_ip4_address_and_mask dst_addr;
  vapi_type_ip_prot_and_mask protocol;
  u32 session_id;
} vapi_type_flow_ip4_l2tpv3oip;

static inline void vapi_type_flow_ip4_l2tpv3oip_hton(vapi_type_flow_ip4_l2tpv3oip *msg)
{
  msg->foo = htobe32(msg->foo);
  msg->session_id = htobe32(msg->session_id);
}

static inline void vapi_type_flow_ip4_l2tpv3oip_ntoh(vapi_type_flow_ip4_l2tpv3oip *msg)
{
  msg->foo = be32toh(msg->foo);
  msg->session_id = be32toh(msg->session_id);
}
#endif

#ifndef defined_vapi_type_flow_ip4_ipsec_esp
#define defined_vapi_type_flow_ip4_ipsec_esp
typedef struct __attribute__((__packed__)) {
  i32 foo;
  vapi_type_ip4_address_and_mask src_addr;
  vapi_type_ip4_address_and_mask dst_addr;
  vapi_type_ip_prot_and_mask protocol;
  u32 spi;
} vapi_type_flow_ip4_ipsec_esp;

static inline void vapi_type_flow_ip4_ipsec_esp_hton(vapi_type_flow_ip4_ipsec_esp *msg)
{
  msg->foo = htobe32(msg->foo);
  msg->spi = htobe32(msg->spi);
}

static inline void vapi_type_flow_ip4_ipsec_esp_ntoh(vapi_type_flow_ip4_ipsec_esp *msg)
{
  msg->foo = be32toh(msg->foo);
  msg->spi = be32toh(msg->spi);
}
#endif

#ifndef defined_vapi_type_flow_ip4_ipsec_ah
#define defined_vapi_type_flow_ip4_ipsec_ah
typedef struct __attribute__((__packed__)) {
  i32 foo;
  vapi_type_ip4_address_and_mask src_addr;
  vapi_type_ip4_address_and_mask dst_addr;
  vapi_type_ip_prot_and_mask protocol;
  u32 spi;
} vapi_type_flow_ip4_ipsec_ah;

static inline void vapi_type_flow_ip4_ipsec_ah_hton(vapi_type_flow_ip4_ipsec_ah *msg)
{
  msg->foo = htobe32(msg->foo);
  msg->spi = htobe32(msg->spi);
}

static inline void vapi_type_flow_ip4_ipsec_ah_ntoh(vapi_type_flow_ip4_ipsec_ah *msg)
{
  msg->foo = be32toh(msg->foo);
  msg->spi = be32toh(msg->spi);
}
#endif

#ifndef defined_vapi_type_ip_port_and_mask
#define defined_vapi_type_ip_port_and_mask
typedef struct __attribute__((__packed__)) {
  u16 port;
  u16 mask;
} vapi_type_ip_port_and_mask;

static inline void vapi_type_ip_port_and_mask_hton(vapi_type_ip_port_and_mask *msg)
{
  msg->port = htobe16(msg->port);
  msg->mask = htobe16(msg->mask);
}

static inline void vapi_type_ip_port_and_mask_ntoh(vapi_type_ip_port_and_mask *msg)
{
  msg->port = be16toh(msg->port);
  msg->mask = be16toh(msg->mask);
}
#endif

#ifndef defined_vapi_type_flow_ip4_n_tuple
#define defined_vapi_type_flow_ip4_n_tuple
typedef struct __attribute__((__packed__)) {
  i32 foo;
  vapi_type_ip4_address_and_mask src_addr;
  vapi_type_ip4_address_and_mask dst_addr;
  vapi_type_ip_prot_and_mask protocol;
  vapi_type_ip_port_and_mask src_port;
  vapi_type_ip_port_and_mask dst_port;
} vapi_type_flow_ip4_n_tuple;

static inline void vapi_type_flow_ip4_n_tuple_hton(vapi_type_flow_ip4_n_tuple *msg)
{
  msg->foo = htobe32(msg->foo);
  vapi_type_ip_port_and_mask_hton(&msg->src_port);
  vapi_type_ip_port_and_mask_hton(&msg->dst_port);
}

static inline void vapi_type_flow_ip4_n_tuple_ntoh(vapi_type_flow_ip4_n_tuple *msg)
{
  msg->foo = be32toh(msg->foo);
  vapi_type_ip_port_and_mask_ntoh(&msg->src_port);
  vapi_type_ip_port_and_mask_ntoh(&msg->dst_port);
}
#endif

#ifndef defined_vapi_type_flow_ip6_n_tuple
#define defined_vapi_type_flow_ip6_n_tuple
typedef struct __attribute__((__packed__)) {
  i32 foo;
  vapi_type_ip6_address_and_mask src_addr;
  vapi_type_ip6_address_and_mask dst_addr;
  vapi_type_ip_prot_and_mask protocol;
  vapi_type_ip_port_and_mask src_port;
  vapi_type_ip_port_and_mask dst_port;
} vapi_type_flow_ip6_n_tuple;

static inline void vapi_type_flow_ip6_n_tuple_hton(vapi_type_flow_ip6_n_tuple *msg)
{
  msg->foo = htobe32(msg->foo);
  vapi_type_ip_port_and_mask_hton(&msg->src_port);
  vapi_type_ip_port_and_mask_hton(&msg->dst_port);
}

static inline void vapi_type_flow_ip6_n_tuple_ntoh(vapi_type_flow_ip6_n_tuple *msg)
{
  msg->foo = be32toh(msg->foo);
  vapi_type_ip_port_and_mask_ntoh(&msg->src_port);
  vapi_type_ip_port_and_mask_ntoh(&msg->dst_port);
}
#endif

#ifndef defined_vapi_type_flow_ip4_n_tuple_tagged
#define defined_vapi_type_flow_ip4_n_tuple_tagged
typedef struct __attribute__((__packed__)) {
  i32 foo;
  vapi_type_ip4_address_and_mask src_addr;
  vapi_type_ip4_address_and_mask dst_addr;
  vapi_type_ip_prot_and_mask protocol;
  vapi_type_ip_port_and_mask src_port;
  vapi_type_ip_port_and_mask dst_port;
} vapi_type_flow_ip4_n_tuple_tagged;

static inline void vapi_type_flow_ip4_n_tuple_tagged_hton(vapi_type_flow_ip4_n_tuple_tagged *msg)
{
  msg->foo = htobe32(msg->foo);
  vapi_type_ip_port_and_mask_hton(&msg->src_port);
  vapi_type_ip_port_and_mask_hton(&msg->dst_port);
}

static inline void vapi_type_flow_ip4_n_tuple_tagged_ntoh(vapi_type_flow_ip4_n_tuple_tagged *msg)
{
  msg->foo = be32toh(msg->foo);
  vapi_type_ip_port_and_mask_ntoh(&msg->src_port);
  vapi_type_ip_port_and_mask_ntoh(&msg->dst_port);
}
#endif

#ifndef defined_vapi_type_flow_ip6_n_tuple_tagged
#define defined_vapi_type_flow_ip6_n_tuple_tagged
typedef struct __attribute__((__packed__)) {
  i32 foo;
  vapi_type_ip6_address_and_mask src_addr;
  vapi_type_ip6_address_and_mask dst_addr;
  vapi_type_ip_prot_and_mask protocol;
  vapi_type_ip_port_and_mask src_port;
  vapi_type_ip_port_and_mask dst_port;
} vapi_type_flow_ip6_n_tuple_tagged;

static inline void vapi_type_flow_ip6_n_tuple_tagged_hton(vapi_type_flow_ip6_n_tuple_tagged *msg)
{
  msg->foo = htobe32(msg->foo);
  vapi_type_ip_port_and_mask_hton(&msg->src_port);
  vapi_type_ip_port_and_mask_hton(&msg->dst_port);
}

static inline void vapi_type_flow_ip6_n_tuple_tagged_ntoh(vapi_type_flow_ip6_n_tuple_tagged *msg)
{
  msg->foo = be32toh(msg->foo);
  vapi_type_ip_port_and_mask_ntoh(&msg->src_port);
  vapi_type_ip_port_and_mask_ntoh(&msg->dst_port);
}
#endif

#ifndef defined_vapi_type_flow_ip4_vxlan
#define defined_vapi_type_flow_ip4_vxlan
typedef struct __attribute__((__packed__)) {
  i32 foo;
  vapi_type_ip4_address_and_mask src_addr;
  vapi_type_ip4_address_and_mask dst_addr;
  vapi_type_ip_prot_and_mask protocol;
  vapi_type_ip_port_and_mask src_port;
  vapi_type_ip_port_and_mask dst_port;
  u32 vni;
} vapi_type_flow_ip4_vxlan;

static inline void vapi_type_flow_ip4_vxlan_hton(vapi_type_flow_ip4_vxlan *msg)
{
  msg->foo = htobe32(msg->foo);
  vapi_type_ip_port_and_mask_hton(&msg->src_port);
  vapi_type_ip_port_and_mask_hton(&msg->dst_port);
  msg->vni = htobe32(msg->vni);
}

static inline void vapi_type_flow_ip4_vxlan_ntoh(vapi_type_flow_ip4_vxlan *msg)
{
  msg->foo = be32toh(msg->foo);
  vapi_type_ip_port_and_mask_ntoh(&msg->src_port);
  vapi_type_ip_port_and_mask_ntoh(&msg->dst_port);
  msg->vni = be32toh(msg->vni);
}
#endif

#ifndef defined_vapi_type_flow_ip6_vxlan
#define defined_vapi_type_flow_ip6_vxlan
typedef struct __attribute__((__packed__)) {
  i32 foo;
  vapi_type_ip6_address_and_mask src_addr;
  vapi_type_ip6_address_and_mask dst_addr;
  vapi_type_ip_prot_and_mask protocol;
  vapi_type_ip_port_and_mask src_port;
  vapi_type_ip_port_and_mask dst_port;
  u32 vni;
} vapi_type_flow_ip6_vxlan;

static inline void vapi_type_flow_ip6_vxlan_hton(vapi_type_flow_ip6_vxlan *msg)
{
  msg->foo = htobe32(msg->foo);
  vapi_type_ip_port_and_mask_hton(&msg->src_port);
  vapi_type_ip_port_and_mask_hton(&msg->dst_port);
  msg->vni = htobe32(msg->vni);
}

static inline void vapi_type_flow_ip6_vxlan_ntoh(vapi_type_flow_ip6_vxlan *msg)
{
  msg->foo = be32toh(msg->foo);
  vapi_type_ip_port_and_mask_ntoh(&msg->src_port);
  vapi_type_ip_port_and_mask_ntoh(&msg->dst_port);
  msg->vni = be32toh(msg->vni);
}
#endif

#ifndef defined_vapi_type_flow_ip4_gtpc
#define defined_vapi_type_flow_ip4_gtpc
typedef struct __attribute__((__packed__)) {
  i32 foo;
  vapi_type_ip4_address_and_mask src_addr;
  vapi_type_ip4_address_and_mask dst_addr;
  vapi_type_ip_prot_and_mask protocol;
  vapi_type_ip_port_and_mask src_port;
  vapi_type_ip_port_and_mask dst_port;
  u32 teid;
} vapi_type_flow_ip4_gtpc;

static inline void vapi_type_flow_ip4_gtpc_hton(vapi_type_flow_ip4_gtpc *msg)
{
  msg->foo = htobe32(msg->foo);
  vapi_type_ip_port_and_mask_hton(&msg->src_port);
  vapi_type_ip_port_and_mask_hton(&msg->dst_port);
  msg->teid = htobe32(msg->teid);
}

static inline void vapi_type_flow_ip4_gtpc_ntoh(vapi_type_flow_ip4_gtpc *msg)
{
  msg->foo = be32toh(msg->foo);
  vapi_type_ip_port_and_mask_ntoh(&msg->src_port);
  vapi_type_ip_port_and_mask_ntoh(&msg->dst_port);
  msg->teid = be32toh(msg->teid);
}
#endif

#ifndef defined_vapi_type_flow_ip4_gtpu
#define defined_vapi_type_flow_ip4_gtpu
typedef struct __attribute__((__packed__)) {
  i32 foo;
  vapi_type_ip4_address_and_mask src_addr;
  vapi_type_ip4_address_and_mask dst_addr;
  vapi_type_ip_prot_and_mask protocol;
  vapi_type_ip_port_and_mask src_port;
  vapi_type_ip_port_and_mask dst_port;
  u32 teid;
} vapi_type_flow_ip4_gtpu;

static inline void vapi_type_flow_ip4_gtpu_hton(vapi_type_flow_ip4_gtpu *msg)
{
  msg->foo = htobe32(msg->foo);
  vapi_type_ip_port_and_mask_hton(&msg->src_port);
  vapi_type_ip_port_and_mask_hton(&msg->dst_port);
  msg->teid = htobe32(msg->teid);
}

static inline void vapi_type_flow_ip4_gtpu_ntoh(vapi_type_flow_ip4_gtpu *msg)
{
  msg->foo = be32toh(msg->foo);
  vapi_type_ip_port_and_mask_ntoh(&msg->src_port);
  vapi_type_ip_port_and_mask_ntoh(&msg->dst_port);
  msg->teid = be32toh(msg->teid);
}
#endif

#ifndef defined_vapi_union_flow
#define defined_vapi_union_flow
typedef union {
  vapi_type_flow_ethernet ethernet;
  vapi_type_flow_ip4 ip4;
  vapi_type_flow_ip6 ip6;
  vapi_type_flow_ip4_l2tpv3oip ip4_l2tpv3oip;
  vapi_type_flow_ip4_ipsec_esp ip4_ipsec_esp;
  vapi_type_flow_ip4_ipsec_ah ip4_ipsec_ah;
  vapi_type_flow_ip4_n_tuple ip4_n_tuple;
  vapi_type_flow_ip6_n_tuple ip6_n_tuple;
  vapi_type_flow_ip4_n_tuple_tagged ip4_n_tuple_tagged;
  vapi_type_flow_ip6_n_tuple_tagged ip6_n_tuple_tagged;
  vapi_type_flow_ip4_vxlan ip4_vxlan;
  vapi_type_flow_ip6_vxlan ip6_vxlan;
  vapi_type_flow_ip4_gtpc ip4_gtpc;
  vapi_type_flow_ip4_gtpu ip4_gtpu;
} vapi_union_flow;

#endif

#ifndef defined_vapi_type_generic_pattern
#define defined_vapi_type_generic_pattern
typedef struct __attribute__((__packed__)) {
  u8 spec[1024];
  u8 mask[1024];
} vapi_type_generic_pattern;

static inline void vapi_type_generic_pattern_hton(vapi_type_generic_pattern *msg)
{

}

static inline void vapi_type_generic_pattern_ntoh(vapi_type_generic_pattern *msg)
{

}
#endif

#ifndef defined_vapi_type_flow_generic
#define defined_vapi_type_flow_generic
typedef struct __attribute__((__packed__)) {
  i32 foo;
  vapi_type_generic_pattern pattern;
} vapi_type_flow_generic;

static inline void vapi_type_flow_generic_hton(vapi_type_flow_generic *msg)
{
  msg->foo = htobe32(msg->foo);
}

static inline void vapi_type_flow_generic_ntoh(vapi_type_flow_generic *msg)
{
  msg->foo = be32toh(msg->foo);
}
#endif

#ifndef defined_vapi_union_flow_v2
#define defined_vapi_union_flow_v2
typedef union {
  vapi_type_flow_ethernet ethernet;
  vapi_type_flow_ip4 ip4;
  vapi_type_flow_ip6 ip6;
  vapi_type_flow_ip4_l2tpv3oip ip4_l2tpv3oip;
  vapi_type_flow_ip4_ipsec_esp ip4_ipsec_esp;
  vapi_type_flow_ip4_ipsec_ah ip4_ipsec_ah;
  vapi_type_flow_ip4_n_tuple ip4_n_tuple;
  vapi_type_flow_ip6_n_tuple ip6_n_tuple;
  vapi_type_flow_ip4_n_tuple_tagged ip4_n_tuple_tagged;
  vapi_type_flow_ip6_n_tuple_tagged ip6_n_tuple_tagged;
  vapi_type_flow_ip4_vxlan ip4_vxlan;
  vapi_type_flow_ip6_vxlan ip6_vxlan;
  vapi_type_flow_ip4_gtpc ip4_gtpc;
  vapi_type_flow_ip4_gtpu ip4_gtpu;
  vapi_type_flow_generic generic;
} vapi_union_flow_v2;

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

#ifndef defined_vapi_type_flow_rule
#define defined_vapi_type_flow_rule
typedef struct __attribute__((__packed__)) {
  vapi_enum_flow_type type;
  u32 index;
  vapi_enum_flow_action actions;
  u32 mark_flow_id;
  u32 redirect_node_index;
  u32 redirect_device_input_next_index;
  u32 redirect_queue;
  i32 buffer_advance;
  vapi_union_flow flow;
} vapi_type_flow_rule;

static inline void vapi_type_flow_rule_hton(vapi_type_flow_rule *msg)
{
  msg->type = (vapi_enum_flow_type)htobe32(msg->type);
  msg->index = htobe32(msg->index);
  msg->actions = (vapi_enum_flow_action)htobe32(msg->actions);
  msg->mark_flow_id = htobe32(msg->mark_flow_id);
  msg->redirect_node_index = htobe32(msg->redirect_node_index);
  msg->redirect_device_input_next_index = htobe32(msg->redirect_device_input_next_index);
  msg->redirect_queue = htobe32(msg->redirect_queue);
  msg->buffer_advance = htobe32(msg->buffer_advance);
}

static inline void vapi_type_flow_rule_ntoh(vapi_type_flow_rule *msg)
{
  msg->type = (vapi_enum_flow_type)be32toh(msg->type);
  msg->index = be32toh(msg->index);
  msg->actions = (vapi_enum_flow_action)be32toh(msg->actions);
  msg->mark_flow_id = be32toh(msg->mark_flow_id);
  msg->redirect_node_index = be32toh(msg->redirect_node_index);
  msg->redirect_device_input_next_index = be32toh(msg->redirect_device_input_next_index);
  msg->redirect_queue = be32toh(msg->redirect_queue);
  msg->buffer_advance = be32toh(msg->buffer_advance);
}
#endif

#ifndef defined_vapi_type_flow_rule_v2
#define defined_vapi_type_flow_rule_v2
typedef struct __attribute__((__packed__)) {
  vapi_enum_flow_type_v2 type;
  u32 index;
  vapi_enum_flow_action_v2 actions;
  u32 mark_flow_id;
  u32 redirect_node_index;
  u32 redirect_device_input_next_index;
  u32 redirect_queue;
  u32 queue_index;
  u32 queue_num;
  i32 buffer_advance;
  u64 rss_types;
  vapi_enum_rss_function rss_fun;
  vapi_union_flow_v2 flow;
} vapi_type_flow_rule_v2;

static inline void vapi_type_flow_rule_v2_hton(vapi_type_flow_rule_v2 *msg)
{
  msg->type = (vapi_enum_flow_type_v2)htobe32(msg->type);
  msg->index = htobe32(msg->index);
  msg->actions = (vapi_enum_flow_action_v2)htobe32(msg->actions);
  msg->mark_flow_id = htobe32(msg->mark_flow_id);
  msg->redirect_node_index = htobe32(msg->redirect_node_index);
  msg->redirect_device_input_next_index = htobe32(msg->redirect_device_input_next_index);
  msg->redirect_queue = htobe32(msg->redirect_queue);
  msg->queue_index = htobe32(msg->queue_index);
  msg->queue_num = htobe32(msg->queue_num);
  msg->buffer_advance = htobe32(msg->buffer_advance);
  msg->rss_types = htobe64(msg->rss_types);
  msg->rss_fun = (vapi_enum_rss_function)htobe32(msg->rss_fun);
}

static inline void vapi_type_flow_rule_v2_ntoh(vapi_type_flow_rule_v2 *msg)
{
  msg->type = (vapi_enum_flow_type_v2)be32toh(msg->type);
  msg->index = be32toh(msg->index);
  msg->actions = (vapi_enum_flow_action_v2)be32toh(msg->actions);
  msg->mark_flow_id = be32toh(msg->mark_flow_id);
  msg->redirect_node_index = be32toh(msg->redirect_node_index);
  msg->redirect_device_input_next_index = be32toh(msg->redirect_device_input_next_index);
  msg->redirect_queue = be32toh(msg->redirect_queue);
  msg->queue_index = be32toh(msg->queue_index);
  msg->queue_num = be32toh(msg->queue_num);
  msg->buffer_advance = be32toh(msg->buffer_advance);
  msg->rss_types = be64toh(msg->rss_types);
  msg->rss_fun = (vapi_enum_rss_function)be32toh(msg->rss_fun);
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

#ifndef defined_vapi_msg_flow_add_reply
#define defined_vapi_msg_flow_add_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 flow_index; 
} vapi_payload_flow_add_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_flow_add_reply payload;
} vapi_msg_flow_add_reply;

static inline void vapi_msg_flow_add_reply_payload_hton(vapi_payload_flow_add_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->flow_index = htobe32(payload->flow_index);
}

static inline void vapi_msg_flow_add_reply_payload_ntoh(vapi_payload_flow_add_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->flow_index = be32toh(payload->flow_index);
}

static inline void vapi_msg_flow_add_reply_hton(vapi_msg_flow_add_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_add_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_flow_add_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_flow_add_reply_ntoh(vapi_msg_flow_add_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_add_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_flow_add_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_flow_add_reply_msg_size(vapi_msg_flow_add_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_flow_add_reply_msg_size(vapi_msg_flow_add_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_flow_add_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_add_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_flow_add_reply));
      return -1;
    }
  if (vapi_calc_flow_add_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_add_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_flow_add_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_flow_add_reply()
{
  static const char name[] = "flow_add_reply";
  static const char name_with_crc[] = "flow_add_reply_8587dc85";
  static vapi_message_desc_t __vapi_metadata_flow_add_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_flow_add_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_flow_add_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_flow_add_reply_hton,
    (generic_swap_fn_t)vapi_msg_flow_add_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_flow_add_reply = vapi_register_msg(&__vapi_metadata_flow_add_reply);
  VAPI_DBG("Assigned msg id %d to flow_add_reply", vapi_msg_id_flow_add_reply);
}

static inline void vapi_set_vapi_msg_flow_add_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_flow_add_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_flow_add_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_flow_add
#define defined_vapi_msg_flow_add
typedef struct __attribute__ ((__packed__)) {
  vapi_type_flow_rule flow; 
} vapi_payload_flow_add;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_flow_add payload;
} vapi_msg_flow_add;

static inline void vapi_msg_flow_add_payload_hton(vapi_payload_flow_add *payload)
{
  vapi_type_flow_rule_hton(&payload->flow);
}

static inline void vapi_msg_flow_add_payload_ntoh(vapi_payload_flow_add *payload)
{
  vapi_type_flow_rule_ntoh(&payload->flow);
}

static inline void vapi_msg_flow_add_hton(vapi_msg_flow_add *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_add'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_flow_add_payload_hton(&msg->payload);
}

static inline void vapi_msg_flow_add_ntoh(vapi_msg_flow_add *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_add'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_flow_add_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_flow_add_msg_size(vapi_msg_flow_add *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_flow_add_msg_size(vapi_msg_flow_add *msg, uword buf_size)
{
  if (sizeof(vapi_msg_flow_add) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_add' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_flow_add));
      return -1;
    }
  if (vapi_calc_flow_add_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_add' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_flow_add_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_flow_add* vapi_alloc_flow_add(struct vapi_ctx_s *ctx)
{
  vapi_msg_flow_add *msg = NULL;
  const size_t size = sizeof(vapi_msg_flow_add);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_flow_add*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_flow_add);

  return msg;
}

static inline vapi_error_e vapi_flow_add(struct vapi_ctx_s *ctx,
  vapi_msg_flow_add *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_flow_add_reply *reply),
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
  vapi_msg_flow_add_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_flow_add_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_flow_add_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_flow_add()
{
  static const char name[] = "flow_add";
  static const char name_with_crc[] = "flow_add_f946ed84";
  static vapi_message_desc_t __vapi_metadata_flow_add = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_flow_add, payload),
    (verify_msg_size_fn_t)vapi_verify_flow_add_msg_size,
    (generic_swap_fn_t)vapi_msg_flow_add_hton,
    (generic_swap_fn_t)vapi_msg_flow_add_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_flow_add = vapi_register_msg(&__vapi_metadata_flow_add);
  VAPI_DBG("Assigned msg id %d to flow_add", vapi_msg_id_flow_add);
}
#endif

#ifndef defined_vapi_msg_flow_add_v2_reply
#define defined_vapi_msg_flow_add_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 flow_index; 
} vapi_payload_flow_add_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_flow_add_v2_reply payload;
} vapi_msg_flow_add_v2_reply;

static inline void vapi_msg_flow_add_v2_reply_payload_hton(vapi_payload_flow_add_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->flow_index = htobe32(payload->flow_index);
}

static inline void vapi_msg_flow_add_v2_reply_payload_ntoh(vapi_payload_flow_add_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->flow_index = be32toh(payload->flow_index);
}

static inline void vapi_msg_flow_add_v2_reply_hton(vapi_msg_flow_add_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_add_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_flow_add_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_flow_add_v2_reply_ntoh(vapi_msg_flow_add_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_add_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_flow_add_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_flow_add_v2_reply_msg_size(vapi_msg_flow_add_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_flow_add_v2_reply_msg_size(vapi_msg_flow_add_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_flow_add_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_add_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_flow_add_v2_reply));
      return -1;
    }
  if (vapi_calc_flow_add_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_add_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_flow_add_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_flow_add_v2_reply()
{
  static const char name[] = "flow_add_v2_reply";
  static const char name_with_crc[] = "flow_add_v2_reply_8587dc85";
  static vapi_message_desc_t __vapi_metadata_flow_add_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_flow_add_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_flow_add_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_flow_add_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_flow_add_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_flow_add_v2_reply = vapi_register_msg(&__vapi_metadata_flow_add_v2_reply);
  VAPI_DBG("Assigned msg id %d to flow_add_v2_reply", vapi_msg_id_flow_add_v2_reply);
}

static inline void vapi_set_vapi_msg_flow_add_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_flow_add_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_flow_add_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_flow_add_v2
#define defined_vapi_msg_flow_add_v2
typedef struct __attribute__ ((__packed__)) {
  vapi_type_flow_rule_v2 flow; 
} vapi_payload_flow_add_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_flow_add_v2 payload;
} vapi_msg_flow_add_v2;

static inline void vapi_msg_flow_add_v2_payload_hton(vapi_payload_flow_add_v2 *payload)
{
  vapi_type_flow_rule_v2_hton(&payload->flow);
}

static inline void vapi_msg_flow_add_v2_payload_ntoh(vapi_payload_flow_add_v2 *payload)
{
  vapi_type_flow_rule_v2_ntoh(&payload->flow);
}

static inline void vapi_msg_flow_add_v2_hton(vapi_msg_flow_add_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_add_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_flow_add_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_flow_add_v2_ntoh(vapi_msg_flow_add_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_add_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_flow_add_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_flow_add_v2_msg_size(vapi_msg_flow_add_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_flow_add_v2_msg_size(vapi_msg_flow_add_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_flow_add_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_add_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_flow_add_v2));
      return -1;
    }
  if (vapi_calc_flow_add_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_add_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_flow_add_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_flow_add_v2* vapi_alloc_flow_add_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_flow_add_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_flow_add_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_flow_add_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_flow_add_v2);

  return msg;
}

static inline vapi_error_e vapi_flow_add_v2(struct vapi_ctx_s *ctx,
  vapi_msg_flow_add_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_flow_add_v2_reply *reply),
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
  vapi_msg_flow_add_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_flow_add_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_flow_add_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_flow_add_v2()
{
  static const char name[] = "flow_add_v2";
  static const char name_with_crc[] = "flow_add_v2_5b757558";
  static vapi_message_desc_t __vapi_metadata_flow_add_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_flow_add_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_flow_add_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_flow_add_v2_hton,
    (generic_swap_fn_t)vapi_msg_flow_add_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_flow_add_v2 = vapi_register_msg(&__vapi_metadata_flow_add_v2);
  VAPI_DBG("Assigned msg id %d to flow_add_v2", vapi_msg_id_flow_add_v2);
}
#endif

#ifndef defined_vapi_msg_flow_del_reply
#define defined_vapi_msg_flow_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_flow_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_flow_del_reply payload;
} vapi_msg_flow_del_reply;

static inline void vapi_msg_flow_del_reply_payload_hton(vapi_payload_flow_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_flow_del_reply_payload_ntoh(vapi_payload_flow_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_flow_del_reply_hton(vapi_msg_flow_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_flow_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_flow_del_reply_ntoh(vapi_msg_flow_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_flow_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_flow_del_reply_msg_size(vapi_msg_flow_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_flow_del_reply_msg_size(vapi_msg_flow_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_flow_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_flow_del_reply));
      return -1;
    }
  if (vapi_calc_flow_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_flow_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_flow_del_reply()
{
  static const char name[] = "flow_del_reply";
  static const char name_with_crc[] = "flow_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_flow_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_flow_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_flow_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_flow_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_flow_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_flow_del_reply = vapi_register_msg(&__vapi_metadata_flow_del_reply);
  VAPI_DBG("Assigned msg id %d to flow_del_reply", vapi_msg_id_flow_del_reply);
}

static inline void vapi_set_vapi_msg_flow_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_flow_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_flow_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_flow_del
#define defined_vapi_msg_flow_del
typedef struct __attribute__ ((__packed__)) {
  u32 flow_index; 
} vapi_payload_flow_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_flow_del payload;
} vapi_msg_flow_del;

static inline void vapi_msg_flow_del_payload_hton(vapi_payload_flow_del *payload)
{
  payload->flow_index = htobe32(payload->flow_index);
}

static inline void vapi_msg_flow_del_payload_ntoh(vapi_payload_flow_del *payload)
{
  payload->flow_index = be32toh(payload->flow_index);
}

static inline void vapi_msg_flow_del_hton(vapi_msg_flow_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_flow_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_flow_del_ntoh(vapi_msg_flow_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_flow_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_flow_del_msg_size(vapi_msg_flow_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_flow_del_msg_size(vapi_msg_flow_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_flow_del) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_flow_del));
      return -1;
    }
  if (vapi_calc_flow_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_flow_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_flow_del* vapi_alloc_flow_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_flow_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_flow_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_flow_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_flow_del);

  return msg;
}

static inline vapi_error_e vapi_flow_del(struct vapi_ctx_s *ctx,
  vapi_msg_flow_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_flow_del_reply *reply),
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
  vapi_msg_flow_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_flow_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_flow_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_flow_del()
{
  static const char name[] = "flow_del";
  static const char name_with_crc[] = "flow_del_b6b9b02c";
  static vapi_message_desc_t __vapi_metadata_flow_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_flow_del, payload),
    (verify_msg_size_fn_t)vapi_verify_flow_del_msg_size,
    (generic_swap_fn_t)vapi_msg_flow_del_hton,
    (generic_swap_fn_t)vapi_msg_flow_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_flow_del = vapi_register_msg(&__vapi_metadata_flow_del);
  VAPI_DBG("Assigned msg id %d to flow_del", vapi_msg_id_flow_del);
}
#endif

#ifndef defined_vapi_msg_flow_enable_reply
#define defined_vapi_msg_flow_enable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_flow_enable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_flow_enable_reply payload;
} vapi_msg_flow_enable_reply;

static inline void vapi_msg_flow_enable_reply_payload_hton(vapi_payload_flow_enable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_flow_enable_reply_payload_ntoh(vapi_payload_flow_enable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_flow_enable_reply_hton(vapi_msg_flow_enable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_enable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_flow_enable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_flow_enable_reply_ntoh(vapi_msg_flow_enable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_enable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_flow_enable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_flow_enable_reply_msg_size(vapi_msg_flow_enable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_flow_enable_reply_msg_size(vapi_msg_flow_enable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_flow_enable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_enable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_flow_enable_reply));
      return -1;
    }
  if (vapi_calc_flow_enable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_enable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_flow_enable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_flow_enable_reply()
{
  static const char name[] = "flow_enable_reply";
  static const char name_with_crc[] = "flow_enable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_flow_enable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_flow_enable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_flow_enable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_flow_enable_reply_hton,
    (generic_swap_fn_t)vapi_msg_flow_enable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_flow_enable_reply = vapi_register_msg(&__vapi_metadata_flow_enable_reply);
  VAPI_DBG("Assigned msg id %d to flow_enable_reply", vapi_msg_id_flow_enable_reply);
}

static inline void vapi_set_vapi_msg_flow_enable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_flow_enable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_flow_enable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_flow_enable
#define defined_vapi_msg_flow_enable
typedef struct __attribute__ ((__packed__)) {
  u32 flow_index;
  u32 hw_if_index; 
} vapi_payload_flow_enable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_flow_enable payload;
} vapi_msg_flow_enable;

static inline void vapi_msg_flow_enable_payload_hton(vapi_payload_flow_enable *payload)
{
  payload->flow_index = htobe32(payload->flow_index);
  payload->hw_if_index = htobe32(payload->hw_if_index);
}

static inline void vapi_msg_flow_enable_payload_ntoh(vapi_payload_flow_enable *payload)
{
  payload->flow_index = be32toh(payload->flow_index);
  payload->hw_if_index = be32toh(payload->hw_if_index);
}

static inline void vapi_msg_flow_enable_hton(vapi_msg_flow_enable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_enable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_flow_enable_payload_hton(&msg->payload);
}

static inline void vapi_msg_flow_enable_ntoh(vapi_msg_flow_enable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_enable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_flow_enable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_flow_enable_msg_size(vapi_msg_flow_enable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_flow_enable_msg_size(vapi_msg_flow_enable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_flow_enable) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_enable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_flow_enable));
      return -1;
    }
  if (vapi_calc_flow_enable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_enable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_flow_enable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_flow_enable* vapi_alloc_flow_enable(struct vapi_ctx_s *ctx)
{
  vapi_msg_flow_enable *msg = NULL;
  const size_t size = sizeof(vapi_msg_flow_enable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_flow_enable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_flow_enable);

  return msg;
}

static inline vapi_error_e vapi_flow_enable(struct vapi_ctx_s *ctx,
  vapi_msg_flow_enable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_flow_enable_reply *reply),
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
  vapi_msg_flow_enable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_flow_enable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_flow_enable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_flow_enable()
{
  static const char name[] = "flow_enable";
  static const char name_with_crc[] = "flow_enable_2024be69";
  static vapi_message_desc_t __vapi_metadata_flow_enable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_flow_enable, payload),
    (verify_msg_size_fn_t)vapi_verify_flow_enable_msg_size,
    (generic_swap_fn_t)vapi_msg_flow_enable_hton,
    (generic_swap_fn_t)vapi_msg_flow_enable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_flow_enable = vapi_register_msg(&__vapi_metadata_flow_enable);
  VAPI_DBG("Assigned msg id %d to flow_enable", vapi_msg_id_flow_enable);
}
#endif

#ifndef defined_vapi_msg_flow_disable_reply
#define defined_vapi_msg_flow_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_flow_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_flow_disable_reply payload;
} vapi_msg_flow_disable_reply;

static inline void vapi_msg_flow_disable_reply_payload_hton(vapi_payload_flow_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_flow_disable_reply_payload_ntoh(vapi_payload_flow_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_flow_disable_reply_hton(vapi_msg_flow_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_flow_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_flow_disable_reply_ntoh(vapi_msg_flow_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_flow_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_flow_disable_reply_msg_size(vapi_msg_flow_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_flow_disable_reply_msg_size(vapi_msg_flow_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_flow_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_flow_disable_reply));
      return -1;
    }
  if (vapi_calc_flow_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_flow_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_flow_disable_reply()
{
  static const char name[] = "flow_disable_reply";
  static const char name_with_crc[] = "flow_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_flow_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_flow_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_flow_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_flow_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_flow_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_flow_disable_reply = vapi_register_msg(&__vapi_metadata_flow_disable_reply);
  VAPI_DBG("Assigned msg id %d to flow_disable_reply", vapi_msg_id_flow_disable_reply);
}

static inline void vapi_set_vapi_msg_flow_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_flow_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_flow_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_flow_disable
#define defined_vapi_msg_flow_disable
typedef struct __attribute__ ((__packed__)) {
  u32 flow_index;
  u32 hw_if_index; 
} vapi_payload_flow_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_flow_disable payload;
} vapi_msg_flow_disable;

static inline void vapi_msg_flow_disable_payload_hton(vapi_payload_flow_disable *payload)
{
  payload->flow_index = htobe32(payload->flow_index);
  payload->hw_if_index = htobe32(payload->hw_if_index);
}

static inline void vapi_msg_flow_disable_payload_ntoh(vapi_payload_flow_disable *payload)
{
  payload->flow_index = be32toh(payload->flow_index);
  payload->hw_if_index = be32toh(payload->hw_if_index);
}

static inline void vapi_msg_flow_disable_hton(vapi_msg_flow_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_flow_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_flow_disable_ntoh(vapi_msg_flow_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_flow_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_flow_disable_msg_size(vapi_msg_flow_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_flow_disable_msg_size(vapi_msg_flow_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_flow_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_flow_disable));
      return -1;
    }
  if (vapi_calc_flow_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_flow_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_flow_disable* vapi_alloc_flow_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_flow_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_flow_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_flow_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_flow_disable);

  return msg;
}

static inline vapi_error_e vapi_flow_disable(struct vapi_ctx_s *ctx,
  vapi_msg_flow_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_flow_disable_reply *reply),
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
  vapi_msg_flow_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_flow_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_flow_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_flow_disable()
{
  static const char name[] = "flow_disable";
  static const char name_with_crc[] = "flow_disable_2024be69";
  static vapi_message_desc_t __vapi_metadata_flow_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_flow_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_flow_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_flow_disable_hton,
    (generic_swap_fn_t)vapi_msg_flow_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_flow_disable = vapi_register_msg(&__vapi_metadata_flow_disable);
  VAPI_DBG("Assigned msg id %d to flow_disable", vapi_msg_id_flow_disable);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
