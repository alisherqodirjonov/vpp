#ifndef __included_ipsec_types_api_json
#define __included_ipsec_types_api_json

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


#define DEFINE_VAPI_MSG_IDS_IPSEC_TYPES_API_JSON\



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

#ifndef defined_vapi_enum_tunnel_encap_decap_flags
#define defined_vapi_enum_tunnel_encap_decap_flags
typedef enum {
  TUNNEL_API_ENCAP_DECAP_FLAG_NONE = 0,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DF = 1,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_SET_DF = 2,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP = 4,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN = 8,
  TUNNEL_API_ENCAP_DECAP_FLAG_DECAP_COPY_ECN = 16,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_INNER_HASH = 32,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_HOP_LIMIT = 64,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_FLOW_LABEL = 128,
} __attribute__((packed)) vapi_enum_tunnel_encap_decap_flags;

#endif

#ifndef defined_vapi_enum_tunnel_mode
#define defined_vapi_enum_tunnel_mode
typedef enum {
  TUNNEL_API_MODE_P2P = 0,
  TUNNEL_API_MODE_MP = 1,
} __attribute__((packed)) vapi_enum_tunnel_mode;

#endif

#ifndef defined_vapi_enum_ipsec_crypto_alg
#define defined_vapi_enum_ipsec_crypto_alg
typedef enum {
  IPSEC_API_CRYPTO_ALG_NONE = 0,
  IPSEC_API_CRYPTO_ALG_AES_CBC_128 = 1,
  IPSEC_API_CRYPTO_ALG_AES_CBC_192 = 2,
  IPSEC_API_CRYPTO_ALG_AES_CBC_256 = 3,
  IPSEC_API_CRYPTO_ALG_AES_CTR_128 = 4,
  IPSEC_API_CRYPTO_ALG_AES_CTR_192 = 5,
  IPSEC_API_CRYPTO_ALG_AES_CTR_256 = 6,
  IPSEC_API_CRYPTO_ALG_AES_GCM_128 = 7,
  IPSEC_API_CRYPTO_ALG_AES_GCM_192 = 8,
  IPSEC_API_CRYPTO_ALG_AES_GCM_256 = 9,
  IPSEC_API_CRYPTO_ALG_DES_CBC = 10,
  IPSEC_API_CRYPTO_ALG_3DES_CBC = 11,
  IPSEC_API_CRYPTO_ALG_CHACHA20_POLY1305 = 12,
  IPSEC_API_CRYPTO_ALG_AES_NULL_GMAC_128 = 13,
  IPSEC_API_CRYPTO_ALG_AES_NULL_GMAC_192 = 14,
  IPSEC_API_CRYPTO_ALG_AES_NULL_GMAC_256 = 15,
}  vapi_enum_ipsec_crypto_alg;

#endif

#ifndef defined_vapi_enum_ipsec_integ_alg
#define defined_vapi_enum_ipsec_integ_alg
typedef enum {
  IPSEC_API_INTEG_ALG_NONE = 0,
  IPSEC_API_INTEG_ALG_MD5_96 = 1,
  IPSEC_API_INTEG_ALG_SHA1_96 = 2,
  IPSEC_API_INTEG_ALG_SHA_256_96 = 3,
  IPSEC_API_INTEG_ALG_SHA_256_128 = 4,
  IPSEC_API_INTEG_ALG_SHA_384_192 = 5,
  IPSEC_API_INTEG_ALG_SHA_512_256 = 6,
}  vapi_enum_ipsec_integ_alg;

#endif

#ifndef defined_vapi_enum_ipsec_sad_flags
#define defined_vapi_enum_ipsec_sad_flags
typedef enum {
  IPSEC_API_SAD_FLAG_NONE = 0,
  IPSEC_API_SAD_FLAG_USE_ESN = 1,
  IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY = 2,
  IPSEC_API_SAD_FLAG_IS_TUNNEL = 4,
  IPSEC_API_SAD_FLAG_IS_TUNNEL_V6 = 8,
  IPSEC_API_SAD_FLAG_UDP_ENCAP = 16,
  IPSEC_API_SAD_FLAG_IS_INBOUND = 64,
  IPSEC_API_SAD_FLAG_ASYNC = 128,
}  vapi_enum_ipsec_sad_flags;

#endif

#ifndef defined_vapi_enum_ipsec_proto
#define defined_vapi_enum_ipsec_proto
typedef enum {
  IPSEC_API_PROTO_ESP = 50,
  IPSEC_API_PROTO_AH = 51,
}  vapi_enum_ipsec_proto;

#endif

#ifndef defined_vapi_enum_ipsec_spd_action
#define defined_vapi_enum_ipsec_spd_action
typedef enum {
  IPSEC_API_SPD_ACTION_BYPASS = 0,
  IPSEC_API_SPD_ACTION_DISCARD = 1,
  IPSEC_API_SPD_ACTION_RESOLVE = 2,
  IPSEC_API_SPD_ACTION_PROTECT = 3,
}  vapi_enum_ipsec_spd_action;

#endif

#ifndef defined_vapi_enum_tunnel_flags
#define defined_vapi_enum_tunnel_flags
typedef enum {
  TUNNEL_API_FLAG_TRACK_MTU = 1,
} __attribute__((packed)) vapi_enum_tunnel_flags;

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

#ifndef defined_vapi_type_key
#define defined_vapi_type_key
typedef struct __attribute__((__packed__)) {
  u8 length;
  u8 data[128];
} vapi_type_key;

static inline void vapi_type_key_hton(vapi_type_key *msg)
{

}

static inline void vapi_type_key_ntoh(vapi_type_key *msg)
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

#ifndef defined_vapi_type_tunnel
#define defined_vapi_type_tunnel
typedef struct __attribute__((__packed__)) {
  u32 instance;
  vapi_type_address src;
  vapi_type_address dst;
  vapi_type_interface_index sw_if_index;
  u32 table_id;
  vapi_enum_tunnel_encap_decap_flags encap_decap_flags;
  vapi_enum_tunnel_mode mode;
  vapi_enum_tunnel_flags flags;
  vapi_enum_ip_dscp dscp;
  u8 hop_limit;
} vapi_type_tunnel;

static inline void vapi_type_tunnel_hton(vapi_type_tunnel *msg)
{
  msg->instance = htobe32(msg->instance);
  msg->sw_if_index = htobe32(msg->sw_if_index);
  msg->table_id = htobe32(msg->table_id);
}

static inline void vapi_type_tunnel_ntoh(vapi_type_tunnel *msg)
{
  msg->instance = be32toh(msg->instance);
  msg->sw_if_index = be32toh(msg->sw_if_index);
  msg->table_id = be32toh(msg->table_id);
}
#endif

#ifndef defined_vapi_type_ipsec_spd_entry
#define defined_vapi_type_ipsec_spd_entry
typedef struct __attribute__((__packed__)) {
  u32 spd_id;
  i32 priority;
  bool is_outbound;
  u32 sa_id;
  vapi_enum_ipsec_spd_action policy;
  u8 protocol;
  vapi_type_address remote_address_start;
  vapi_type_address remote_address_stop;
  vapi_type_address local_address_start;
  vapi_type_address local_address_stop;
  u16 remote_port_start;
  u16 remote_port_stop;
  u16 local_port_start;
  u16 local_port_stop;
} vapi_type_ipsec_spd_entry;

static inline void vapi_type_ipsec_spd_entry_hton(vapi_type_ipsec_spd_entry *msg)
{
  msg->spd_id = htobe32(msg->spd_id);
  msg->priority = htobe32(msg->priority);
  msg->sa_id = htobe32(msg->sa_id);
  msg->policy = (vapi_enum_ipsec_spd_action)htobe32(msg->policy);
  msg->remote_port_start = htobe16(msg->remote_port_start);
  msg->remote_port_stop = htobe16(msg->remote_port_stop);
  msg->local_port_start = htobe16(msg->local_port_start);
  msg->local_port_stop = htobe16(msg->local_port_stop);
}

static inline void vapi_type_ipsec_spd_entry_ntoh(vapi_type_ipsec_spd_entry *msg)
{
  msg->spd_id = be32toh(msg->spd_id);
  msg->priority = be32toh(msg->priority);
  msg->sa_id = be32toh(msg->sa_id);
  msg->policy = (vapi_enum_ipsec_spd_action)be32toh(msg->policy);
  msg->remote_port_start = be16toh(msg->remote_port_start);
  msg->remote_port_stop = be16toh(msg->remote_port_stop);
  msg->local_port_start = be16toh(msg->local_port_start);
  msg->local_port_stop = be16toh(msg->local_port_stop);
}
#endif

#ifndef defined_vapi_type_ipsec_spd_entry_v2
#define defined_vapi_type_ipsec_spd_entry_v2
typedef struct __attribute__((__packed__)) {
  u32 spd_id;
  i32 priority;
  bool is_outbound;
  u32 sa_id;
  vapi_enum_ipsec_spd_action policy;
  u8 protocol;
  vapi_type_address remote_address_start;
  vapi_type_address remote_address_stop;
  vapi_type_address local_address_start;
  vapi_type_address local_address_stop;
  u16 remote_port_start;
  u16 remote_port_stop;
  u16 local_port_start;
  u16 local_port_stop;
} vapi_type_ipsec_spd_entry_v2;

static inline void vapi_type_ipsec_spd_entry_v2_hton(vapi_type_ipsec_spd_entry_v2 *msg)
{
  msg->spd_id = htobe32(msg->spd_id);
  msg->priority = htobe32(msg->priority);
  msg->sa_id = htobe32(msg->sa_id);
  msg->policy = (vapi_enum_ipsec_spd_action)htobe32(msg->policy);
  msg->remote_port_start = htobe16(msg->remote_port_start);
  msg->remote_port_stop = htobe16(msg->remote_port_stop);
  msg->local_port_start = htobe16(msg->local_port_start);
  msg->local_port_stop = htobe16(msg->local_port_stop);
}

static inline void vapi_type_ipsec_spd_entry_v2_ntoh(vapi_type_ipsec_spd_entry_v2 *msg)
{
  msg->spd_id = be32toh(msg->spd_id);
  msg->priority = be32toh(msg->priority);
  msg->sa_id = be32toh(msg->sa_id);
  msg->policy = (vapi_enum_ipsec_spd_action)be32toh(msg->policy);
  msg->remote_port_start = be16toh(msg->remote_port_start);
  msg->remote_port_stop = be16toh(msg->remote_port_stop);
  msg->local_port_start = be16toh(msg->local_port_start);
  msg->local_port_stop = be16toh(msg->local_port_stop);
}
#endif

#ifndef defined_vapi_type_ipsec_sad_entry
#define defined_vapi_type_ipsec_sad_entry
typedef struct __attribute__((__packed__)) {
  u32 sad_id;
  u32 spi;
  vapi_enum_ipsec_proto protocol;
  vapi_enum_ipsec_crypto_alg crypto_algorithm;
  vapi_type_key crypto_key;
  vapi_enum_ipsec_integ_alg integrity_algorithm;
  vapi_type_key integrity_key;
  vapi_enum_ipsec_sad_flags flags;
  vapi_type_address tunnel_src;
  vapi_type_address tunnel_dst;
  u32 tx_table_id;
  u32 salt;
  u16 udp_src_port;
  u16 udp_dst_port;
} vapi_type_ipsec_sad_entry;

static inline void vapi_type_ipsec_sad_entry_hton(vapi_type_ipsec_sad_entry *msg)
{
  msg->sad_id = htobe32(msg->sad_id);
  msg->spi = htobe32(msg->spi);
  msg->protocol = (vapi_enum_ipsec_proto)htobe32(msg->protocol);
  msg->crypto_algorithm = (vapi_enum_ipsec_crypto_alg)htobe32(msg->crypto_algorithm);
  msg->integrity_algorithm = (vapi_enum_ipsec_integ_alg)htobe32(msg->integrity_algorithm);
  msg->flags = (vapi_enum_ipsec_sad_flags)htobe32(msg->flags);
  msg->tx_table_id = htobe32(msg->tx_table_id);
  msg->salt = htobe32(msg->salt);
  msg->udp_src_port = htobe16(msg->udp_src_port);
  msg->udp_dst_port = htobe16(msg->udp_dst_port);
}

static inline void vapi_type_ipsec_sad_entry_ntoh(vapi_type_ipsec_sad_entry *msg)
{
  msg->sad_id = be32toh(msg->sad_id);
  msg->spi = be32toh(msg->spi);
  msg->protocol = (vapi_enum_ipsec_proto)be32toh(msg->protocol);
  msg->crypto_algorithm = (vapi_enum_ipsec_crypto_alg)be32toh(msg->crypto_algorithm);
  msg->integrity_algorithm = (vapi_enum_ipsec_integ_alg)be32toh(msg->integrity_algorithm);
  msg->flags = (vapi_enum_ipsec_sad_flags)be32toh(msg->flags);
  msg->tx_table_id = be32toh(msg->tx_table_id);
  msg->salt = be32toh(msg->salt);
  msg->udp_src_port = be16toh(msg->udp_src_port);
  msg->udp_dst_port = be16toh(msg->udp_dst_port);
}
#endif

#ifndef defined_vapi_type_ipsec_sad_entry_v2
#define defined_vapi_type_ipsec_sad_entry_v2
typedef struct __attribute__((__packed__)) {
  u32 sad_id;
  u32 spi;
  vapi_enum_ipsec_proto protocol;
  vapi_enum_ipsec_crypto_alg crypto_algorithm;
  vapi_type_key crypto_key;
  vapi_enum_ipsec_integ_alg integrity_algorithm;
  vapi_type_key integrity_key;
  vapi_enum_ipsec_sad_flags flags;
  vapi_type_address tunnel_src;
  vapi_type_address tunnel_dst;
  vapi_enum_tunnel_encap_decap_flags tunnel_flags;
  vapi_enum_ip_dscp dscp;
  u32 tx_table_id;
  u32 salt;
  u16 udp_src_port;
  u16 udp_dst_port;
} vapi_type_ipsec_sad_entry_v2;

static inline void vapi_type_ipsec_sad_entry_v2_hton(vapi_type_ipsec_sad_entry_v2 *msg)
{
  msg->sad_id = htobe32(msg->sad_id);
  msg->spi = htobe32(msg->spi);
  msg->protocol = (vapi_enum_ipsec_proto)htobe32(msg->protocol);
  msg->crypto_algorithm = (vapi_enum_ipsec_crypto_alg)htobe32(msg->crypto_algorithm);
  msg->integrity_algorithm = (vapi_enum_ipsec_integ_alg)htobe32(msg->integrity_algorithm);
  msg->flags = (vapi_enum_ipsec_sad_flags)htobe32(msg->flags);
  msg->tx_table_id = htobe32(msg->tx_table_id);
  msg->salt = htobe32(msg->salt);
  msg->udp_src_port = htobe16(msg->udp_src_port);
  msg->udp_dst_port = htobe16(msg->udp_dst_port);
}

static inline void vapi_type_ipsec_sad_entry_v2_ntoh(vapi_type_ipsec_sad_entry_v2 *msg)
{
  msg->sad_id = be32toh(msg->sad_id);
  msg->spi = be32toh(msg->spi);
  msg->protocol = (vapi_enum_ipsec_proto)be32toh(msg->protocol);
  msg->crypto_algorithm = (vapi_enum_ipsec_crypto_alg)be32toh(msg->crypto_algorithm);
  msg->integrity_algorithm = (vapi_enum_ipsec_integ_alg)be32toh(msg->integrity_algorithm);
  msg->flags = (vapi_enum_ipsec_sad_flags)be32toh(msg->flags);
  msg->tx_table_id = be32toh(msg->tx_table_id);
  msg->salt = be32toh(msg->salt);
  msg->udp_src_port = be16toh(msg->udp_src_port);
  msg->udp_dst_port = be16toh(msg->udp_dst_port);
}
#endif

#ifndef defined_vapi_type_ipsec_sad_entry_v3
#define defined_vapi_type_ipsec_sad_entry_v3
typedef struct __attribute__((__packed__)) {
  u32 sad_id;
  u32 spi;
  vapi_enum_ipsec_proto protocol;
  vapi_enum_ipsec_crypto_alg crypto_algorithm;
  vapi_type_key crypto_key;
  vapi_enum_ipsec_integ_alg integrity_algorithm;
  vapi_type_key integrity_key;
  vapi_enum_ipsec_sad_flags flags;
  vapi_type_tunnel tunnel;
  u32 salt;
  u16 udp_src_port;
  u16 udp_dst_port;
} vapi_type_ipsec_sad_entry_v3;

static inline void vapi_type_ipsec_sad_entry_v3_hton(vapi_type_ipsec_sad_entry_v3 *msg)
{
  msg->sad_id = htobe32(msg->sad_id);
  msg->spi = htobe32(msg->spi);
  msg->protocol = (vapi_enum_ipsec_proto)htobe32(msg->protocol);
  msg->crypto_algorithm = (vapi_enum_ipsec_crypto_alg)htobe32(msg->crypto_algorithm);
  msg->integrity_algorithm = (vapi_enum_ipsec_integ_alg)htobe32(msg->integrity_algorithm);
  msg->flags = (vapi_enum_ipsec_sad_flags)htobe32(msg->flags);
  vapi_type_tunnel_hton(&msg->tunnel);
  msg->salt = htobe32(msg->salt);
  msg->udp_src_port = htobe16(msg->udp_src_port);
  msg->udp_dst_port = htobe16(msg->udp_dst_port);
}

static inline void vapi_type_ipsec_sad_entry_v3_ntoh(vapi_type_ipsec_sad_entry_v3 *msg)
{
  msg->sad_id = be32toh(msg->sad_id);
  msg->spi = be32toh(msg->spi);
  msg->protocol = (vapi_enum_ipsec_proto)be32toh(msg->protocol);
  msg->crypto_algorithm = (vapi_enum_ipsec_crypto_alg)be32toh(msg->crypto_algorithm);
  msg->integrity_algorithm = (vapi_enum_ipsec_integ_alg)be32toh(msg->integrity_algorithm);
  msg->flags = (vapi_enum_ipsec_sad_flags)be32toh(msg->flags);
  vapi_type_tunnel_ntoh(&msg->tunnel);
  msg->salt = be32toh(msg->salt);
  msg->udp_src_port = be16toh(msg->udp_src_port);
  msg->udp_dst_port = be16toh(msg->udp_dst_port);
}
#endif

#ifndef defined_vapi_type_ipsec_sad_entry_v4
#define defined_vapi_type_ipsec_sad_entry_v4
typedef struct __attribute__((__packed__)) {
  u32 sad_id;
  u32 spi;
  vapi_enum_ipsec_proto protocol;
  vapi_enum_ipsec_crypto_alg crypto_algorithm;
  vapi_type_key crypto_key;
  vapi_enum_ipsec_integ_alg integrity_algorithm;
  vapi_type_key integrity_key;
  vapi_enum_ipsec_sad_flags flags;
  vapi_type_tunnel tunnel;
  u32 salt;
  u16 udp_src_port;
  u16 udp_dst_port;
  u32 anti_replay_window_size;
} vapi_type_ipsec_sad_entry_v4;

static inline void vapi_type_ipsec_sad_entry_v4_hton(vapi_type_ipsec_sad_entry_v4 *msg)
{
  msg->sad_id = htobe32(msg->sad_id);
  msg->spi = htobe32(msg->spi);
  msg->protocol = (vapi_enum_ipsec_proto)htobe32(msg->protocol);
  msg->crypto_algorithm = (vapi_enum_ipsec_crypto_alg)htobe32(msg->crypto_algorithm);
  msg->integrity_algorithm = (vapi_enum_ipsec_integ_alg)htobe32(msg->integrity_algorithm);
  msg->flags = (vapi_enum_ipsec_sad_flags)htobe32(msg->flags);
  vapi_type_tunnel_hton(&msg->tunnel);
  msg->salt = htobe32(msg->salt);
  msg->udp_src_port = htobe16(msg->udp_src_port);
  msg->udp_dst_port = htobe16(msg->udp_dst_port);
  msg->anti_replay_window_size = htobe32(msg->anti_replay_window_size);
}

static inline void vapi_type_ipsec_sad_entry_v4_ntoh(vapi_type_ipsec_sad_entry_v4 *msg)
{
  msg->sad_id = be32toh(msg->sad_id);
  msg->spi = be32toh(msg->spi);
  msg->protocol = (vapi_enum_ipsec_proto)be32toh(msg->protocol);
  msg->crypto_algorithm = (vapi_enum_ipsec_crypto_alg)be32toh(msg->crypto_algorithm);
  msg->integrity_algorithm = (vapi_enum_ipsec_integ_alg)be32toh(msg->integrity_algorithm);
  msg->flags = (vapi_enum_ipsec_sad_flags)be32toh(msg->flags);
  vapi_type_tunnel_ntoh(&msg->tunnel);
  msg->salt = be32toh(msg->salt);
  msg->udp_src_port = be16toh(msg->udp_src_port);
  msg->udp_dst_port = be16toh(msg->udp_dst_port);
  msg->anti_replay_window_size = be32toh(msg->anti_replay_window_size);
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
