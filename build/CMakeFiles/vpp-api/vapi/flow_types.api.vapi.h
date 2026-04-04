#ifndef __included_flow_types_api_json
#define __included_flow_types_api_json

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


#define DEFINE_VAPI_MSG_IDS_FLOW_TYPES_API_JSON\



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


#ifdef __cplusplus
}
#endif

#endif
