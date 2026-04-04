#ifndef __included_ikev2_types_api_json
#define __included_ikev2_types_api_json

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


#define DEFINE_VAPI_MSG_IDS_IKEV2_TYPES_API_JSON\



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

#ifndef defined_vapi_enum_ikev2_state
#define defined_vapi_enum_ikev2_state
typedef enum {
  UNKNOWN = 0,
  SA_INIT = 1,
  DELETED = 2,
  AUTH_FAILED = 3,
  AUTHENTICATED = 4,
  NOTIFY_AND_DELETE = 5,
  TS_UNACCEPTABLE = 6,
  NO_PROPOSAL_CHOSEN = 7,
}  vapi_enum_ikev2_state;

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

#ifndef defined_vapi_type_ikev2_id
#define defined_vapi_type_ikev2_id
typedef struct __attribute__((__packed__)) {
  u8 type;
  u8 data_len;
  u8 data[64];
} vapi_type_ikev2_id;

static inline void vapi_type_ikev2_id_hton(vapi_type_ikev2_id *msg)
{

}

static inline void vapi_type_ikev2_id_ntoh(vapi_type_ikev2_id *msg)
{

}
#endif

#ifndef defined_vapi_type_ikev2_auth
#define defined_vapi_type_ikev2_auth
typedef struct __attribute__((__packed__)) {
  u8 method;
  u8 hex;
  u32 data_len;
  u8 data[0];
} vapi_type_ikev2_auth;

static inline void vapi_type_ikev2_auth_hton(vapi_type_ikev2_auth *msg)
{
  msg->data_len = htobe32(msg->data_len);
}

static inline void vapi_type_ikev2_auth_ntoh(vapi_type_ikev2_auth *msg)
{
  msg->data_len = be32toh(msg->data_len);
}
#endif

#ifndef defined_vapi_type_ikev2_ike_transforms
#define defined_vapi_type_ikev2_ike_transforms
typedef struct __attribute__((__packed__)) {
  u8 crypto_alg;
  u32 crypto_key_size;
  u8 integ_alg;
  u8 dh_group;
} vapi_type_ikev2_ike_transforms;

static inline void vapi_type_ikev2_ike_transforms_hton(vapi_type_ikev2_ike_transforms *msg)
{
  msg->crypto_key_size = htobe32(msg->crypto_key_size);
}

static inline void vapi_type_ikev2_ike_transforms_ntoh(vapi_type_ikev2_ike_transforms *msg)
{
  msg->crypto_key_size = be32toh(msg->crypto_key_size);
}
#endif

#ifndef defined_vapi_type_ikev2_esp_transforms
#define defined_vapi_type_ikev2_esp_transforms
typedef struct __attribute__((__packed__)) {
  u8 crypto_alg;
  u32 crypto_key_size;
  u8 integ_alg;
} vapi_type_ikev2_esp_transforms;

static inline void vapi_type_ikev2_esp_transforms_hton(vapi_type_ikev2_esp_transforms *msg)
{
  msg->crypto_key_size = htobe32(msg->crypto_key_size);
}

static inline void vapi_type_ikev2_esp_transforms_ntoh(vapi_type_ikev2_esp_transforms *msg)
{
  msg->crypto_key_size = be32toh(msg->crypto_key_size);
}
#endif

#ifndef defined_vapi_type_ikev2_sa_transform
#define defined_vapi_type_ikev2_sa_transform
typedef struct __attribute__((__packed__)) {
  u8 transform_type;
  u16 transform_id;
  u16 key_len;
  u16 key_trunc;
  u16 block_size;
  u8 dh_group;
} vapi_type_ikev2_sa_transform;

static inline void vapi_type_ikev2_sa_transform_hton(vapi_type_ikev2_sa_transform *msg)
{
  msg->transform_id = htobe16(msg->transform_id);
  msg->key_len = htobe16(msg->key_len);
  msg->key_trunc = htobe16(msg->key_trunc);
  msg->block_size = htobe16(msg->block_size);
}

static inline void vapi_type_ikev2_sa_transform_ntoh(vapi_type_ikev2_sa_transform *msg)
{
  msg->transform_id = be16toh(msg->transform_id);
  msg->key_len = be16toh(msg->key_len);
  msg->key_trunc = be16toh(msg->key_trunc);
  msg->block_size = be16toh(msg->block_size);
}
#endif

#ifndef defined_vapi_type_ikev2_keys
#define defined_vapi_type_ikev2_keys
typedef struct __attribute__((__packed__)) {
  u8 sk_d[64];
  u8 sk_d_len;
  u8 sk_ai[64];
  u8 sk_ai_len;
  u8 sk_ar[64];
  u8 sk_ar_len;
  u8 sk_ei[64];
  u8 sk_ei_len;
  u8 sk_er[64];
  u8 sk_er_len;
  u8 sk_pi[64];
  u8 sk_pi_len;
  u8 sk_pr[64];
  u8 sk_pr_len;
} vapi_type_ikev2_keys;

static inline void vapi_type_ikev2_keys_hton(vapi_type_ikev2_keys *msg)
{

}

static inline void vapi_type_ikev2_keys_ntoh(vapi_type_ikev2_keys *msg)
{

}
#endif

#ifndef defined_vapi_type_ikev2_child_sa
#define defined_vapi_type_ikev2_child_sa
typedef struct __attribute__((__packed__)) {
  u32 sa_index;
  u32 child_sa_index;
  u32 i_spi;
  u32 r_spi;
  vapi_type_ikev2_keys keys;
  vapi_type_ikev2_sa_transform encryption;
  vapi_type_ikev2_sa_transform integrity;
  vapi_type_ikev2_sa_transform esn;
} vapi_type_ikev2_child_sa;

static inline void vapi_type_ikev2_child_sa_hton(vapi_type_ikev2_child_sa *msg)
{
  msg->sa_index = htobe32(msg->sa_index);
  msg->child_sa_index = htobe32(msg->child_sa_index);
  msg->i_spi = htobe32(msg->i_spi);
  msg->r_spi = htobe32(msg->r_spi);
  vapi_type_ikev2_sa_transform_hton(&msg->encryption);
  vapi_type_ikev2_sa_transform_hton(&msg->integrity);
  vapi_type_ikev2_sa_transform_hton(&msg->esn);
}

static inline void vapi_type_ikev2_child_sa_ntoh(vapi_type_ikev2_child_sa *msg)
{
  msg->sa_index = be32toh(msg->sa_index);
  msg->child_sa_index = be32toh(msg->child_sa_index);
  msg->i_spi = be32toh(msg->i_spi);
  msg->r_spi = be32toh(msg->r_spi);
  vapi_type_ikev2_sa_transform_ntoh(&msg->encryption);
  vapi_type_ikev2_sa_transform_ntoh(&msg->integrity);
  vapi_type_ikev2_sa_transform_ntoh(&msg->esn);
}
#endif

#ifndef defined_vapi_type_ikev2_child_sa_v2
#define defined_vapi_type_ikev2_child_sa_v2
typedef struct __attribute__((__packed__)) {
  u32 sa_index;
  u32 child_sa_index;
  u32 i_spi;
  u32 r_spi;
  vapi_type_ikev2_keys keys;
  vapi_type_ikev2_sa_transform encryption;
  vapi_type_ikev2_sa_transform integrity;
  vapi_type_ikev2_sa_transform esn;
  f64 uptime;
} vapi_type_ikev2_child_sa_v2;

static inline void vapi_type_ikev2_child_sa_v2_hton(vapi_type_ikev2_child_sa_v2 *msg)
{
  msg->sa_index = htobe32(msg->sa_index);
  msg->child_sa_index = htobe32(msg->child_sa_index);
  msg->i_spi = htobe32(msg->i_spi);
  msg->r_spi = htobe32(msg->r_spi);
  vapi_type_ikev2_sa_transform_hton(&msg->encryption);
  vapi_type_ikev2_sa_transform_hton(&msg->integrity);
  vapi_type_ikev2_sa_transform_hton(&msg->esn);
}

static inline void vapi_type_ikev2_child_sa_v2_ntoh(vapi_type_ikev2_child_sa_v2 *msg)
{
  msg->sa_index = be32toh(msg->sa_index);
  msg->child_sa_index = be32toh(msg->child_sa_index);
  msg->i_spi = be32toh(msg->i_spi);
  msg->r_spi = be32toh(msg->r_spi);
  vapi_type_ikev2_sa_transform_ntoh(&msg->encryption);
  vapi_type_ikev2_sa_transform_ntoh(&msg->integrity);
  vapi_type_ikev2_sa_transform_ntoh(&msg->esn);
}
#endif

#ifndef defined_vapi_type_ikev2_sa_stats
#define defined_vapi_type_ikev2_sa_stats
typedef struct __attribute__((__packed__)) {
  u16 n_keepalives;
  u16 n_rekey_req;
  u16 n_sa_init_req;
  u16 n_sa_auth_req;
  u16 n_retransmit;
  u16 n_init_sa_retransmit;
} vapi_type_ikev2_sa_stats;

static inline void vapi_type_ikev2_sa_stats_hton(vapi_type_ikev2_sa_stats *msg)
{
  msg->n_keepalives = htobe16(msg->n_keepalives);
  msg->n_rekey_req = htobe16(msg->n_rekey_req);
  msg->n_sa_init_req = htobe16(msg->n_sa_init_req);
  msg->n_sa_auth_req = htobe16(msg->n_sa_auth_req);
  msg->n_retransmit = htobe16(msg->n_retransmit);
  msg->n_init_sa_retransmit = htobe16(msg->n_init_sa_retransmit);
}

static inline void vapi_type_ikev2_sa_stats_ntoh(vapi_type_ikev2_sa_stats *msg)
{
  msg->n_keepalives = be16toh(msg->n_keepalives);
  msg->n_rekey_req = be16toh(msg->n_rekey_req);
  msg->n_sa_init_req = be16toh(msg->n_sa_init_req);
  msg->n_sa_auth_req = be16toh(msg->n_sa_auth_req);
  msg->n_retransmit = be16toh(msg->n_retransmit);
  msg->n_init_sa_retransmit = be16toh(msg->n_init_sa_retransmit);
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

#ifndef defined_vapi_type_ikev2_ts
#define defined_vapi_type_ikev2_ts
typedef struct __attribute__((__packed__)) {
  u32 sa_index;
  u32 child_sa_index;
  bool is_local;
  u8 protocol_id;
  u16 start_port;
  u16 end_port;
  vapi_type_address start_addr;
  vapi_type_address end_addr;
} vapi_type_ikev2_ts;

static inline void vapi_type_ikev2_ts_hton(vapi_type_ikev2_ts *msg)
{
  msg->sa_index = htobe32(msg->sa_index);
  msg->child_sa_index = htobe32(msg->child_sa_index);
  msg->start_port = htobe16(msg->start_port);
  msg->end_port = htobe16(msg->end_port);
}

static inline void vapi_type_ikev2_ts_ntoh(vapi_type_ikev2_ts *msg)
{
  msg->sa_index = be32toh(msg->sa_index);
  msg->child_sa_index = be32toh(msg->child_sa_index);
  msg->start_port = be16toh(msg->start_port);
  msg->end_port = be16toh(msg->end_port);
}
#endif

#ifndef defined_vapi_type_interface_index
#define defined_vapi_type_interface_index
typedef u32 vapi_type_interface_index;

#endif

#ifndef defined_vapi_type_ikev2_responder
#define defined_vapi_type_ikev2_responder
typedef struct __attribute__((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_type_address addr;
} vapi_type_ikev2_responder;

static inline void vapi_type_ikev2_responder_hton(vapi_type_ikev2_responder *msg)
{
  msg->sw_if_index = htobe32(msg->sw_if_index);
}

static inline void vapi_type_ikev2_responder_ntoh(vapi_type_ikev2_responder *msg)
{
  msg->sw_if_index = be32toh(msg->sw_if_index);
}
#endif

#ifndef defined_vapi_type_ikev2_profile
#define defined_vapi_type_ikev2_profile
typedef struct __attribute__((__packed__)) {
  u8 name[64];
  vapi_type_ikev2_id loc_id;
  vapi_type_ikev2_id rem_id;
  vapi_type_ikev2_ts loc_ts;
  vapi_type_ikev2_ts rem_ts;
  vapi_type_ikev2_responder responder;
  vapi_type_ikev2_ike_transforms ike_ts;
  vapi_type_ikev2_esp_transforms esp_ts;
  u64 lifetime;
  u64 lifetime_maxdata;
  u32 lifetime_jitter;
  u32 handover;
  u16 ipsec_over_udp_port;
  u32 tun_itf;
  bool udp_encap;
  bool natt_disabled;
  vapi_type_ikev2_auth auth;
} vapi_type_ikev2_profile;

static inline void vapi_type_ikev2_profile_hton(vapi_type_ikev2_profile *msg)
{
  vapi_type_ikev2_ts_hton(&msg->loc_ts);
  vapi_type_ikev2_ts_hton(&msg->rem_ts);
  vapi_type_ikev2_responder_hton(&msg->responder);
  vapi_type_ikev2_ike_transforms_hton(&msg->ike_ts);
  vapi_type_ikev2_esp_transforms_hton(&msg->esp_ts);
  msg->lifetime = htobe64(msg->lifetime);
  msg->lifetime_maxdata = htobe64(msg->lifetime_maxdata);
  msg->lifetime_jitter = htobe32(msg->lifetime_jitter);
  msg->handover = htobe32(msg->handover);
  msg->ipsec_over_udp_port = htobe16(msg->ipsec_over_udp_port);
  msg->tun_itf = htobe32(msg->tun_itf);
  vapi_type_ikev2_auth_hton(&msg->auth);
}

static inline void vapi_type_ikev2_profile_ntoh(vapi_type_ikev2_profile *msg)
{
  vapi_type_ikev2_ts_ntoh(&msg->loc_ts);
  vapi_type_ikev2_ts_ntoh(&msg->rem_ts);
  vapi_type_ikev2_responder_ntoh(&msg->responder);
  vapi_type_ikev2_ike_transforms_ntoh(&msg->ike_ts);
  vapi_type_ikev2_esp_transforms_ntoh(&msg->esp_ts);
  msg->lifetime = be64toh(msg->lifetime);
  msg->lifetime_maxdata = be64toh(msg->lifetime_maxdata);
  msg->lifetime_jitter = be32toh(msg->lifetime_jitter);
  msg->handover = be32toh(msg->handover);
  msg->ipsec_over_udp_port = be16toh(msg->ipsec_over_udp_port);
  msg->tun_itf = be32toh(msg->tun_itf);
  vapi_type_ikev2_auth_ntoh(&msg->auth);
}
#endif

#ifndef defined_vapi_type_ikev2_sa
#define defined_vapi_type_ikev2_sa
typedef struct __attribute__((__packed__)) {
  u32 sa_index;
  u32 profile_index;
  u64 ispi;
  u64 rspi;
  vapi_type_address iaddr;
  vapi_type_address raddr;
  vapi_type_ikev2_keys keys;
  vapi_type_ikev2_id i_id;
  vapi_type_ikev2_id r_id;
  vapi_type_ikev2_sa_transform encryption;
  vapi_type_ikev2_sa_transform integrity;
  vapi_type_ikev2_sa_transform prf;
  vapi_type_ikev2_sa_transform dh;
  vapi_type_ikev2_sa_stats stats;
} vapi_type_ikev2_sa;

static inline void vapi_type_ikev2_sa_hton(vapi_type_ikev2_sa *msg)
{
  msg->sa_index = htobe32(msg->sa_index);
  msg->profile_index = htobe32(msg->profile_index);
  msg->ispi = htobe64(msg->ispi);
  msg->rspi = htobe64(msg->rspi);
  vapi_type_ikev2_sa_transform_hton(&msg->encryption);
  vapi_type_ikev2_sa_transform_hton(&msg->integrity);
  vapi_type_ikev2_sa_transform_hton(&msg->prf);
  vapi_type_ikev2_sa_transform_hton(&msg->dh);
  vapi_type_ikev2_sa_stats_hton(&msg->stats);
}

static inline void vapi_type_ikev2_sa_ntoh(vapi_type_ikev2_sa *msg)
{
  msg->sa_index = be32toh(msg->sa_index);
  msg->profile_index = be32toh(msg->profile_index);
  msg->ispi = be64toh(msg->ispi);
  msg->rspi = be64toh(msg->rspi);
  vapi_type_ikev2_sa_transform_ntoh(&msg->encryption);
  vapi_type_ikev2_sa_transform_ntoh(&msg->integrity);
  vapi_type_ikev2_sa_transform_ntoh(&msg->prf);
  vapi_type_ikev2_sa_transform_ntoh(&msg->dh);
  vapi_type_ikev2_sa_stats_ntoh(&msg->stats);
}
#endif

#ifndef defined_vapi_type_ikev2_sa_v2
#define defined_vapi_type_ikev2_sa_v2
typedef struct __attribute__((__packed__)) {
  u32 sa_index;
  u8 profile_name[64];
  vapi_enum_ikev2_state state;
  u64 ispi;
  u64 rspi;
  vapi_type_address iaddr;
  vapi_type_address raddr;
  vapi_type_ikev2_keys keys;
  vapi_type_ikev2_id i_id;
  vapi_type_ikev2_id r_id;
  vapi_type_ikev2_sa_transform encryption;
  vapi_type_ikev2_sa_transform integrity;
  vapi_type_ikev2_sa_transform prf;
  vapi_type_ikev2_sa_transform dh;
  vapi_type_ikev2_sa_stats stats;
} vapi_type_ikev2_sa_v2;

static inline void vapi_type_ikev2_sa_v2_hton(vapi_type_ikev2_sa_v2 *msg)
{
  msg->sa_index = htobe32(msg->sa_index);
  msg->state = (vapi_enum_ikev2_state)htobe32(msg->state);
  msg->ispi = htobe64(msg->ispi);
  msg->rspi = htobe64(msg->rspi);
  vapi_type_ikev2_sa_transform_hton(&msg->encryption);
  vapi_type_ikev2_sa_transform_hton(&msg->integrity);
  vapi_type_ikev2_sa_transform_hton(&msg->prf);
  vapi_type_ikev2_sa_transform_hton(&msg->dh);
  vapi_type_ikev2_sa_stats_hton(&msg->stats);
}

static inline void vapi_type_ikev2_sa_v2_ntoh(vapi_type_ikev2_sa_v2 *msg)
{
  msg->sa_index = be32toh(msg->sa_index);
  msg->state = (vapi_enum_ikev2_state)be32toh(msg->state);
  msg->ispi = be64toh(msg->ispi);
  msg->rspi = be64toh(msg->rspi);
  vapi_type_ikev2_sa_transform_ntoh(&msg->encryption);
  vapi_type_ikev2_sa_transform_ntoh(&msg->integrity);
  vapi_type_ikev2_sa_transform_ntoh(&msg->prf);
  vapi_type_ikev2_sa_transform_ntoh(&msg->dh);
  vapi_type_ikev2_sa_stats_ntoh(&msg->stats);
}
#endif

#ifndef defined_vapi_type_ikev2_sa_v3
#define defined_vapi_type_ikev2_sa_v3
typedef struct __attribute__((__packed__)) {
  u32 sa_index;
  u8 profile_name[64];
  vapi_enum_ikev2_state state;
  u64 ispi;
  u64 rspi;
  vapi_type_address iaddr;
  vapi_type_address raddr;
  vapi_type_ikev2_keys keys;
  vapi_type_ikev2_id i_id;
  vapi_type_ikev2_id r_id;
  vapi_type_ikev2_sa_transform encryption;
  vapi_type_ikev2_sa_transform integrity;
  vapi_type_ikev2_sa_transform prf;
  vapi_type_ikev2_sa_transform dh;
  vapi_type_ikev2_sa_stats stats;
  f64 uptime;
} vapi_type_ikev2_sa_v3;

static inline void vapi_type_ikev2_sa_v3_hton(vapi_type_ikev2_sa_v3 *msg)
{
  msg->sa_index = htobe32(msg->sa_index);
  msg->state = (vapi_enum_ikev2_state)htobe32(msg->state);
  msg->ispi = htobe64(msg->ispi);
  msg->rspi = htobe64(msg->rspi);
  vapi_type_ikev2_sa_transform_hton(&msg->encryption);
  vapi_type_ikev2_sa_transform_hton(&msg->integrity);
  vapi_type_ikev2_sa_transform_hton(&msg->prf);
  vapi_type_ikev2_sa_transform_hton(&msg->dh);
  vapi_type_ikev2_sa_stats_hton(&msg->stats);
}

static inline void vapi_type_ikev2_sa_v3_ntoh(vapi_type_ikev2_sa_v3 *msg)
{
  msg->sa_index = be32toh(msg->sa_index);
  msg->state = (vapi_enum_ikev2_state)be32toh(msg->state);
  msg->ispi = be64toh(msg->ispi);
  msg->rspi = be64toh(msg->rspi);
  vapi_type_ikev2_sa_transform_ntoh(&msg->encryption);
  vapi_type_ikev2_sa_transform_ntoh(&msg->integrity);
  vapi_type_ikev2_sa_transform_ntoh(&msg->prf);
  vapi_type_ikev2_sa_transform_ntoh(&msg->dh);
  vapi_type_ikev2_sa_stats_ntoh(&msg->stats);
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
