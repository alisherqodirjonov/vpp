#ifndef __included_ikev2_api_json
#define __included_ikev2_api_json

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

extern vapi_msg_id_t vapi_msg_id_ikev2_plugin_get_version;
extern vapi_msg_id_t vapi_msg_id_ikev2_plugin_get_version_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_plugin_set_sleep_interval;
extern vapi_msg_id_t vapi_msg_id_ikev2_plugin_set_sleep_interval_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_get_sleep_interval;
extern vapi_msg_id_t vapi_msg_id_ikev2_get_sleep_interval_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_profile_dump;
extern vapi_msg_id_t vapi_msg_id_ikev2_profile_details;
extern vapi_msg_id_t vapi_msg_id_ikev2_sa_dump;
extern vapi_msg_id_t vapi_msg_id_ikev2_sa_v2_dump;
extern vapi_msg_id_t vapi_msg_id_ikev2_sa_v3_dump;
extern vapi_msg_id_t vapi_msg_id_ikev2_sa_details;
extern vapi_msg_id_t vapi_msg_id_ikev2_sa_v2_details;
extern vapi_msg_id_t vapi_msg_id_ikev2_sa_v3_details;
extern vapi_msg_id_t vapi_msg_id_ikev2_child_sa_dump;
extern vapi_msg_id_t vapi_msg_id_ikev2_child_sa_details;
extern vapi_msg_id_t vapi_msg_id_ikev2_child_sa_v2_dump;
extern vapi_msg_id_t vapi_msg_id_ikev2_child_sa_v2_details;
extern vapi_msg_id_t vapi_msg_id_ikev2_nonce_get;
extern vapi_msg_id_t vapi_msg_id_ikev2_nonce_get_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_traffic_selector_dump;
extern vapi_msg_id_t vapi_msg_id_ikev2_traffic_selector_details;
extern vapi_msg_id_t vapi_msg_id_ikev2_profile_add_del;
extern vapi_msg_id_t vapi_msg_id_ikev2_profile_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_profile_set_auth;
extern vapi_msg_id_t vapi_msg_id_ikev2_profile_set_auth_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_profile_set_id;
extern vapi_msg_id_t vapi_msg_id_ikev2_profile_set_id_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_profile_disable_natt;
extern vapi_msg_id_t vapi_msg_id_ikev2_profile_disable_natt_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_profile_set_ts;
extern vapi_msg_id_t vapi_msg_id_ikev2_profile_set_ts_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_set_local_key;
extern vapi_msg_id_t vapi_msg_id_ikev2_set_local_key_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_set_tunnel_interface;
extern vapi_msg_id_t vapi_msg_id_ikev2_set_tunnel_interface_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_set_responder;
extern vapi_msg_id_t vapi_msg_id_ikev2_set_responder_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_set_responder_hostname;
extern vapi_msg_id_t vapi_msg_id_ikev2_set_responder_hostname_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_set_ike_transforms;
extern vapi_msg_id_t vapi_msg_id_ikev2_set_ike_transforms_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_set_esp_transforms;
extern vapi_msg_id_t vapi_msg_id_ikev2_set_esp_transforms_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_set_sa_lifetime;
extern vapi_msg_id_t vapi_msg_id_ikev2_set_sa_lifetime_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_initiate_sa_init;
extern vapi_msg_id_t vapi_msg_id_ikev2_initiate_sa_init_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_initiate_del_ike_sa;
extern vapi_msg_id_t vapi_msg_id_ikev2_initiate_del_ike_sa_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_initiate_del_child_sa;
extern vapi_msg_id_t vapi_msg_id_ikev2_initiate_del_child_sa_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_initiate_rekey_child_sa;
extern vapi_msg_id_t vapi_msg_id_ikev2_initiate_rekey_child_sa_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_profile_set_udp_encap;
extern vapi_msg_id_t vapi_msg_id_ikev2_profile_set_udp_encap_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_profile_set_ipsec_udp_port;
extern vapi_msg_id_t vapi_msg_id_ikev2_profile_set_ipsec_udp_port_reply;
extern vapi_msg_id_t vapi_msg_id_ikev2_profile_set_liveness;
extern vapi_msg_id_t vapi_msg_id_ikev2_profile_set_liveness_reply;

#define DEFINE_VAPI_MSG_IDS_IKEV2_API_JSON\
  vapi_msg_id_t vapi_msg_id_ikev2_plugin_get_version;\
  vapi_msg_id_t vapi_msg_id_ikev2_plugin_get_version_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_plugin_set_sleep_interval;\
  vapi_msg_id_t vapi_msg_id_ikev2_plugin_set_sleep_interval_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_get_sleep_interval;\
  vapi_msg_id_t vapi_msg_id_ikev2_get_sleep_interval_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_profile_dump;\
  vapi_msg_id_t vapi_msg_id_ikev2_profile_details;\
  vapi_msg_id_t vapi_msg_id_ikev2_sa_dump;\
  vapi_msg_id_t vapi_msg_id_ikev2_sa_v2_dump;\
  vapi_msg_id_t vapi_msg_id_ikev2_sa_v3_dump;\
  vapi_msg_id_t vapi_msg_id_ikev2_sa_details;\
  vapi_msg_id_t vapi_msg_id_ikev2_sa_v2_details;\
  vapi_msg_id_t vapi_msg_id_ikev2_sa_v3_details;\
  vapi_msg_id_t vapi_msg_id_ikev2_child_sa_dump;\
  vapi_msg_id_t vapi_msg_id_ikev2_child_sa_details;\
  vapi_msg_id_t vapi_msg_id_ikev2_child_sa_v2_dump;\
  vapi_msg_id_t vapi_msg_id_ikev2_child_sa_v2_details;\
  vapi_msg_id_t vapi_msg_id_ikev2_nonce_get;\
  vapi_msg_id_t vapi_msg_id_ikev2_nonce_get_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_traffic_selector_dump;\
  vapi_msg_id_t vapi_msg_id_ikev2_traffic_selector_details;\
  vapi_msg_id_t vapi_msg_id_ikev2_profile_add_del;\
  vapi_msg_id_t vapi_msg_id_ikev2_profile_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_profile_set_auth;\
  vapi_msg_id_t vapi_msg_id_ikev2_profile_set_auth_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_profile_set_id;\
  vapi_msg_id_t vapi_msg_id_ikev2_profile_set_id_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_profile_disable_natt;\
  vapi_msg_id_t vapi_msg_id_ikev2_profile_disable_natt_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_profile_set_ts;\
  vapi_msg_id_t vapi_msg_id_ikev2_profile_set_ts_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_set_local_key;\
  vapi_msg_id_t vapi_msg_id_ikev2_set_local_key_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_set_tunnel_interface;\
  vapi_msg_id_t vapi_msg_id_ikev2_set_tunnel_interface_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_set_responder;\
  vapi_msg_id_t vapi_msg_id_ikev2_set_responder_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_set_responder_hostname;\
  vapi_msg_id_t vapi_msg_id_ikev2_set_responder_hostname_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_set_ike_transforms;\
  vapi_msg_id_t vapi_msg_id_ikev2_set_ike_transforms_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_set_esp_transforms;\
  vapi_msg_id_t vapi_msg_id_ikev2_set_esp_transforms_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_set_sa_lifetime;\
  vapi_msg_id_t vapi_msg_id_ikev2_set_sa_lifetime_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_initiate_sa_init;\
  vapi_msg_id_t vapi_msg_id_ikev2_initiate_sa_init_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_initiate_del_ike_sa;\
  vapi_msg_id_t vapi_msg_id_ikev2_initiate_del_ike_sa_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_initiate_del_child_sa;\
  vapi_msg_id_t vapi_msg_id_ikev2_initiate_del_child_sa_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_initiate_rekey_child_sa;\
  vapi_msg_id_t vapi_msg_id_ikev2_initiate_rekey_child_sa_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_profile_set_udp_encap;\
  vapi_msg_id_t vapi_msg_id_ikev2_profile_set_udp_encap_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_profile_set_ipsec_udp_port;\
  vapi_msg_id_t vapi_msg_id_ikev2_profile_set_ipsec_udp_port_reply;\
  vapi_msg_id_t vapi_msg_id_ikev2_profile_set_liveness;\
  vapi_msg_id_t vapi_msg_id_ikev2_profile_set_liveness_reply;


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

#ifndef defined_vapi_msg_ikev2_plugin_get_version_reply
#define defined_vapi_msg_ikev2_plugin_get_version_reply
typedef struct __attribute__ ((__packed__)) {
  u32 major;
  u32 minor; 
} vapi_payload_ikev2_plugin_get_version_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_plugin_get_version_reply payload;
} vapi_msg_ikev2_plugin_get_version_reply;

static inline void vapi_msg_ikev2_plugin_get_version_reply_payload_hton(vapi_payload_ikev2_plugin_get_version_reply *payload)
{
  payload->major = htobe32(payload->major);
  payload->minor = htobe32(payload->minor);
}

static inline void vapi_msg_ikev2_plugin_get_version_reply_payload_ntoh(vapi_payload_ikev2_plugin_get_version_reply *payload)
{
  payload->major = be32toh(payload->major);
  payload->minor = be32toh(payload->minor);
}

static inline void vapi_msg_ikev2_plugin_get_version_reply_hton(vapi_msg_ikev2_plugin_get_version_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_plugin_get_version_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_plugin_get_version_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_plugin_get_version_reply_ntoh(vapi_msg_ikev2_plugin_get_version_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_plugin_get_version_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_plugin_get_version_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_plugin_get_version_reply_msg_size(vapi_msg_ikev2_plugin_get_version_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_plugin_get_version_reply_msg_size(vapi_msg_ikev2_plugin_get_version_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_plugin_get_version_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_plugin_get_version_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_plugin_get_version_reply));
      return -1;
    }
  if (vapi_calc_ikev2_plugin_get_version_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_plugin_get_version_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_plugin_get_version_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_plugin_get_version_reply()
{
  static const char name[] = "ikev2_plugin_get_version_reply";
  static const char name_with_crc[] = "ikev2_plugin_get_version_reply_9b32cf86";
  static vapi_message_desc_t __vapi_metadata_ikev2_plugin_get_version_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_plugin_get_version_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_plugin_get_version_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_plugin_get_version_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_plugin_get_version_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_plugin_get_version_reply = vapi_register_msg(&__vapi_metadata_ikev2_plugin_get_version_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_plugin_get_version_reply", vapi_msg_id_ikev2_plugin_get_version_reply);
}

static inline void vapi_set_vapi_msg_ikev2_plugin_get_version_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_plugin_get_version_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_plugin_get_version_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_plugin_get_version
#define defined_vapi_msg_ikev2_plugin_get_version
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ikev2_plugin_get_version;

static inline void vapi_msg_ikev2_plugin_get_version_hton(vapi_msg_ikev2_plugin_get_version *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_plugin_get_version'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ikev2_plugin_get_version_ntoh(vapi_msg_ikev2_plugin_get_version *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_plugin_get_version'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ikev2_plugin_get_version_msg_size(vapi_msg_ikev2_plugin_get_version *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_plugin_get_version_msg_size(vapi_msg_ikev2_plugin_get_version *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_plugin_get_version) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_plugin_get_version' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_plugin_get_version));
      return -1;
    }
  if (vapi_calc_ikev2_plugin_get_version_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_plugin_get_version' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_plugin_get_version_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_plugin_get_version* vapi_alloc_ikev2_plugin_get_version(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_plugin_get_version *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_plugin_get_version);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_plugin_get_version*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_plugin_get_version);

  return msg;
}

static inline vapi_error_e vapi_ikev2_plugin_get_version(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_plugin_get_version *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_plugin_get_version_reply *reply),
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
  vapi_msg_ikev2_plugin_get_version_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_plugin_get_version_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_plugin_get_version_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_plugin_get_version()
{
  static const char name[] = "ikev2_plugin_get_version";
  static const char name_with_crc[] = "ikev2_plugin_get_version_51077d14";
  static vapi_message_desc_t __vapi_metadata_ikev2_plugin_get_version = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ikev2_plugin_get_version_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_plugin_get_version_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_plugin_get_version_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_plugin_get_version = vapi_register_msg(&__vapi_metadata_ikev2_plugin_get_version);
  VAPI_DBG("Assigned msg id %d to ikev2_plugin_get_version", vapi_msg_id_ikev2_plugin_get_version);
}
#endif

#ifndef defined_vapi_msg_ikev2_plugin_set_sleep_interval_reply
#define defined_vapi_msg_ikev2_plugin_set_sleep_interval_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ikev2_plugin_set_sleep_interval_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_plugin_set_sleep_interval_reply payload;
} vapi_msg_ikev2_plugin_set_sleep_interval_reply;

static inline void vapi_msg_ikev2_plugin_set_sleep_interval_reply_payload_hton(vapi_payload_ikev2_plugin_set_sleep_interval_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_plugin_set_sleep_interval_reply_payload_ntoh(vapi_payload_ikev2_plugin_set_sleep_interval_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_plugin_set_sleep_interval_reply_hton(vapi_msg_ikev2_plugin_set_sleep_interval_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_plugin_set_sleep_interval_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_plugin_set_sleep_interval_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_plugin_set_sleep_interval_reply_ntoh(vapi_msg_ikev2_plugin_set_sleep_interval_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_plugin_set_sleep_interval_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_plugin_set_sleep_interval_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_plugin_set_sleep_interval_reply_msg_size(vapi_msg_ikev2_plugin_set_sleep_interval_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_plugin_set_sleep_interval_reply_msg_size(vapi_msg_ikev2_plugin_set_sleep_interval_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_plugin_set_sleep_interval_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_plugin_set_sleep_interval_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_plugin_set_sleep_interval_reply));
      return -1;
    }
  if (vapi_calc_ikev2_plugin_set_sleep_interval_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_plugin_set_sleep_interval_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_plugin_set_sleep_interval_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_plugin_set_sleep_interval_reply()
{
  static const char name[] = "ikev2_plugin_set_sleep_interval_reply";
  static const char name_with_crc[] = "ikev2_plugin_set_sleep_interval_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ikev2_plugin_set_sleep_interval_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_plugin_set_sleep_interval_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_plugin_set_sleep_interval_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_plugin_set_sleep_interval_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_plugin_set_sleep_interval_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_plugin_set_sleep_interval_reply = vapi_register_msg(&__vapi_metadata_ikev2_plugin_set_sleep_interval_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_plugin_set_sleep_interval_reply", vapi_msg_id_ikev2_plugin_set_sleep_interval_reply);
}

static inline void vapi_set_vapi_msg_ikev2_plugin_set_sleep_interval_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_plugin_set_sleep_interval_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_plugin_set_sleep_interval_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_plugin_set_sleep_interval
#define defined_vapi_msg_ikev2_plugin_set_sleep_interval
typedef struct __attribute__ ((__packed__)) {
  f64 timeout; 
} vapi_payload_ikev2_plugin_set_sleep_interval;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_plugin_set_sleep_interval payload;
} vapi_msg_ikev2_plugin_set_sleep_interval;

static inline void vapi_msg_ikev2_plugin_set_sleep_interval_payload_hton(vapi_payload_ikev2_plugin_set_sleep_interval *payload)
{

}

static inline void vapi_msg_ikev2_plugin_set_sleep_interval_payload_ntoh(vapi_payload_ikev2_plugin_set_sleep_interval *payload)
{

}

static inline void vapi_msg_ikev2_plugin_set_sleep_interval_hton(vapi_msg_ikev2_plugin_set_sleep_interval *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_plugin_set_sleep_interval'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_plugin_set_sleep_interval_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_plugin_set_sleep_interval_ntoh(vapi_msg_ikev2_plugin_set_sleep_interval *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_plugin_set_sleep_interval'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_plugin_set_sleep_interval_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_plugin_set_sleep_interval_msg_size(vapi_msg_ikev2_plugin_set_sleep_interval *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_plugin_set_sleep_interval_msg_size(vapi_msg_ikev2_plugin_set_sleep_interval *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_plugin_set_sleep_interval) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_plugin_set_sleep_interval' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_plugin_set_sleep_interval));
      return -1;
    }
  if (vapi_calc_ikev2_plugin_set_sleep_interval_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_plugin_set_sleep_interval' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_plugin_set_sleep_interval_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_plugin_set_sleep_interval* vapi_alloc_ikev2_plugin_set_sleep_interval(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_plugin_set_sleep_interval *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_plugin_set_sleep_interval);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_plugin_set_sleep_interval*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_plugin_set_sleep_interval);

  return msg;
}

static inline vapi_error_e vapi_ikev2_plugin_set_sleep_interval(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_plugin_set_sleep_interval *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_plugin_set_sleep_interval_reply *reply),
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
  vapi_msg_ikev2_plugin_set_sleep_interval_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_plugin_set_sleep_interval_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_plugin_set_sleep_interval_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_plugin_set_sleep_interval()
{
  static const char name[] = "ikev2_plugin_set_sleep_interval";
  static const char name_with_crc[] = "ikev2_plugin_set_sleep_interval_b7c096ae";
  static vapi_message_desc_t __vapi_metadata_ikev2_plugin_set_sleep_interval = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_plugin_set_sleep_interval, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_plugin_set_sleep_interval_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_plugin_set_sleep_interval_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_plugin_set_sleep_interval_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_plugin_set_sleep_interval = vapi_register_msg(&__vapi_metadata_ikev2_plugin_set_sleep_interval);
  VAPI_DBG("Assigned msg id %d to ikev2_plugin_set_sleep_interval", vapi_msg_id_ikev2_plugin_set_sleep_interval);
}
#endif

#ifndef defined_vapi_msg_ikev2_get_sleep_interval_reply
#define defined_vapi_msg_ikev2_get_sleep_interval_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  f64 sleep_interval; 
} vapi_payload_ikev2_get_sleep_interval_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_get_sleep_interval_reply payload;
} vapi_msg_ikev2_get_sleep_interval_reply;

static inline void vapi_msg_ikev2_get_sleep_interval_reply_payload_hton(vapi_payload_ikev2_get_sleep_interval_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_get_sleep_interval_reply_payload_ntoh(vapi_payload_ikev2_get_sleep_interval_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_get_sleep_interval_reply_hton(vapi_msg_ikev2_get_sleep_interval_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_get_sleep_interval_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_get_sleep_interval_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_get_sleep_interval_reply_ntoh(vapi_msg_ikev2_get_sleep_interval_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_get_sleep_interval_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_get_sleep_interval_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_get_sleep_interval_reply_msg_size(vapi_msg_ikev2_get_sleep_interval_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_get_sleep_interval_reply_msg_size(vapi_msg_ikev2_get_sleep_interval_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_get_sleep_interval_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_get_sleep_interval_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_get_sleep_interval_reply));
      return -1;
    }
  if (vapi_calc_ikev2_get_sleep_interval_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_get_sleep_interval_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_get_sleep_interval_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_get_sleep_interval_reply()
{
  static const char name[] = "ikev2_get_sleep_interval_reply";
  static const char name_with_crc[] = "ikev2_get_sleep_interval_reply_78ab91dc";
  static vapi_message_desc_t __vapi_metadata_ikev2_get_sleep_interval_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_get_sleep_interval_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_get_sleep_interval_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_get_sleep_interval_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_get_sleep_interval_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_get_sleep_interval_reply = vapi_register_msg(&__vapi_metadata_ikev2_get_sleep_interval_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_get_sleep_interval_reply", vapi_msg_id_ikev2_get_sleep_interval_reply);
}

static inline void vapi_set_vapi_msg_ikev2_get_sleep_interval_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_get_sleep_interval_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_get_sleep_interval_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_get_sleep_interval
#define defined_vapi_msg_ikev2_get_sleep_interval
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ikev2_get_sleep_interval;

static inline void vapi_msg_ikev2_get_sleep_interval_hton(vapi_msg_ikev2_get_sleep_interval *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_get_sleep_interval'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ikev2_get_sleep_interval_ntoh(vapi_msg_ikev2_get_sleep_interval *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_get_sleep_interval'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ikev2_get_sleep_interval_msg_size(vapi_msg_ikev2_get_sleep_interval *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_get_sleep_interval_msg_size(vapi_msg_ikev2_get_sleep_interval *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_get_sleep_interval) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_get_sleep_interval' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_get_sleep_interval));
      return -1;
    }
  if (vapi_calc_ikev2_get_sleep_interval_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_get_sleep_interval' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_get_sleep_interval_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_get_sleep_interval* vapi_alloc_ikev2_get_sleep_interval(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_get_sleep_interval *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_get_sleep_interval);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_get_sleep_interval*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_get_sleep_interval);

  return msg;
}

static inline vapi_error_e vapi_ikev2_get_sleep_interval(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_get_sleep_interval *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_get_sleep_interval_reply *reply),
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
  vapi_msg_ikev2_get_sleep_interval_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_get_sleep_interval_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_get_sleep_interval_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_get_sleep_interval()
{
  static const char name[] = "ikev2_get_sleep_interval";
  static const char name_with_crc[] = "ikev2_get_sleep_interval_51077d14";
  static vapi_message_desc_t __vapi_metadata_ikev2_get_sleep_interval = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ikev2_get_sleep_interval_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_get_sleep_interval_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_get_sleep_interval_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_get_sleep_interval = vapi_register_msg(&__vapi_metadata_ikev2_get_sleep_interval);
  VAPI_DBG("Assigned msg id %d to ikev2_get_sleep_interval", vapi_msg_id_ikev2_get_sleep_interval);
}
#endif

#ifndef defined_vapi_msg_ikev2_profile_details
#define defined_vapi_msg_ikev2_profile_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ikev2_profile profile; 
} vapi_payload_ikev2_profile_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_profile_details payload;
} vapi_msg_ikev2_profile_details;

static inline void vapi_msg_ikev2_profile_details_payload_hton(vapi_payload_ikev2_profile_details *payload)
{
  vapi_type_ikev2_profile_hton(&payload->profile);
}

static inline void vapi_msg_ikev2_profile_details_payload_ntoh(vapi_payload_ikev2_profile_details *payload)
{
  vapi_type_ikev2_profile_ntoh(&payload->profile);
}

static inline void vapi_msg_ikev2_profile_details_hton(vapi_msg_ikev2_profile_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_profile_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_profile_details_ntoh(vapi_msg_ikev2_profile_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_profile_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_profile_details_msg_size(vapi_msg_ikev2_profile_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.profile.auth.data[0]) * msg->payload.profile.auth.data_len;
}

static inline int vapi_verify_ikev2_profile_details_msg_size(vapi_msg_ikev2_profile_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_profile_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_profile_details));
      return -1;
    }
  if (vapi_calc_ikev2_profile_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_profile_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_profile_details()
{
  static const char name[] = "ikev2_profile_details";
  static const char name_with_crc[] = "ikev2_profile_details_670d01d9";
  static vapi_message_desc_t __vapi_metadata_ikev2_profile_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_profile_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_profile_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_details_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_profile_details = vapi_register_msg(&__vapi_metadata_ikev2_profile_details);
  VAPI_DBG("Assigned msg id %d to ikev2_profile_details", vapi_msg_id_ikev2_profile_details);
}

static inline void vapi_set_vapi_msg_ikev2_profile_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_profile_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_profile_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_profile_dump
#define defined_vapi_msg_ikev2_profile_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ikev2_profile_dump;

static inline void vapi_msg_ikev2_profile_dump_hton(vapi_msg_ikev2_profile_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ikev2_profile_dump_ntoh(vapi_msg_ikev2_profile_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ikev2_profile_dump_msg_size(vapi_msg_ikev2_profile_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_profile_dump_msg_size(vapi_msg_ikev2_profile_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_profile_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_profile_dump));
      return -1;
    }
  if (vapi_calc_ikev2_profile_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_profile_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_profile_dump* vapi_alloc_ikev2_profile_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_profile_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_profile_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_profile_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_profile_dump);

  return msg;
}

static inline vapi_error_e vapi_ikev2_profile_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_profile_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_profile_details *reply),
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
  vapi_msg_ikev2_profile_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_profile_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_ikev2_profile_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_profile_dump()
{
  static const char name[] = "ikev2_profile_dump";
  static const char name_with_crc[] = "ikev2_profile_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_ikev2_profile_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ikev2_profile_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_dump_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_profile_dump = vapi_register_msg(&__vapi_metadata_ikev2_profile_dump);
  VAPI_DBG("Assigned msg id %d to ikev2_profile_dump", vapi_msg_id_ikev2_profile_dump);
}
#endif

#ifndef defined_vapi_msg_ikev2_sa_details
#define defined_vapi_msg_ikev2_sa_details
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_ikev2_sa sa; 
} vapi_payload_ikev2_sa_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_sa_details payload;
} vapi_msg_ikev2_sa_details;

static inline void vapi_msg_ikev2_sa_details_payload_hton(vapi_payload_ikev2_sa_details *payload)
{
  payload->retval = htobe32(payload->retval);
  vapi_type_ikev2_sa_hton(&payload->sa);
}

static inline void vapi_msg_ikev2_sa_details_payload_ntoh(vapi_payload_ikev2_sa_details *payload)
{
  payload->retval = be32toh(payload->retval);
  vapi_type_ikev2_sa_ntoh(&payload->sa);
}

static inline void vapi_msg_ikev2_sa_details_hton(vapi_msg_ikev2_sa_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_sa_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_sa_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_sa_details_ntoh(vapi_msg_ikev2_sa_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_sa_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_sa_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_sa_details_msg_size(vapi_msg_ikev2_sa_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_sa_details_msg_size(vapi_msg_ikev2_sa_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_sa_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_sa_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_sa_details));
      return -1;
    }
  if (vapi_calc_ikev2_sa_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_sa_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_sa_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_sa_details()
{
  static const char name[] = "ikev2_sa_details";
  static const char name_with_crc[] = "ikev2_sa_details_937c22d5";
  static vapi_message_desc_t __vapi_metadata_ikev2_sa_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_sa_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_sa_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_sa_details_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_sa_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_sa_details = vapi_register_msg(&__vapi_metadata_ikev2_sa_details);
  VAPI_DBG("Assigned msg id %d to ikev2_sa_details", vapi_msg_id_ikev2_sa_details);
}

static inline void vapi_set_vapi_msg_ikev2_sa_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_sa_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_sa_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_sa_dump
#define defined_vapi_msg_ikev2_sa_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ikev2_sa_dump;

static inline void vapi_msg_ikev2_sa_dump_hton(vapi_msg_ikev2_sa_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_sa_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ikev2_sa_dump_ntoh(vapi_msg_ikev2_sa_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_sa_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ikev2_sa_dump_msg_size(vapi_msg_ikev2_sa_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_sa_dump_msg_size(vapi_msg_ikev2_sa_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_sa_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_sa_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_sa_dump));
      return -1;
    }
  if (vapi_calc_ikev2_sa_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_sa_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_sa_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_sa_dump* vapi_alloc_ikev2_sa_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_sa_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_sa_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_sa_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_sa_dump);

  return msg;
}

static inline vapi_error_e vapi_ikev2_sa_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_sa_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_sa_details *reply),
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
  vapi_msg_ikev2_sa_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_sa_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_ikev2_sa_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_sa_dump()
{
  static const char name[] = "ikev2_sa_dump";
  static const char name_with_crc[] = "ikev2_sa_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_ikev2_sa_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ikev2_sa_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_sa_dump_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_sa_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_sa_dump = vapi_register_msg(&__vapi_metadata_ikev2_sa_dump);
  VAPI_DBG("Assigned msg id %d to ikev2_sa_dump", vapi_msg_id_ikev2_sa_dump);
}
#endif

#ifndef defined_vapi_msg_ikev2_sa_v2_details
#define defined_vapi_msg_ikev2_sa_v2_details
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_ikev2_sa_v2 sa; 
} vapi_payload_ikev2_sa_v2_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_sa_v2_details payload;
} vapi_msg_ikev2_sa_v2_details;

static inline void vapi_msg_ikev2_sa_v2_details_payload_hton(vapi_payload_ikev2_sa_v2_details *payload)
{
  payload->retval = htobe32(payload->retval);
  vapi_type_ikev2_sa_v2_hton(&payload->sa);
}

static inline void vapi_msg_ikev2_sa_v2_details_payload_ntoh(vapi_payload_ikev2_sa_v2_details *payload)
{
  payload->retval = be32toh(payload->retval);
  vapi_type_ikev2_sa_v2_ntoh(&payload->sa);
}

static inline void vapi_msg_ikev2_sa_v2_details_hton(vapi_msg_ikev2_sa_v2_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_sa_v2_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_sa_v2_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_sa_v2_details_ntoh(vapi_msg_ikev2_sa_v2_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_sa_v2_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_sa_v2_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_sa_v2_details_msg_size(vapi_msg_ikev2_sa_v2_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_sa_v2_details_msg_size(vapi_msg_ikev2_sa_v2_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_sa_v2_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_sa_v2_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_sa_v2_details));
      return -1;
    }
  if (vapi_calc_ikev2_sa_v2_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_sa_v2_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_sa_v2_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_sa_v2_details()
{
  static const char name[] = "ikev2_sa_v2_details";
  static const char name_with_crc[] = "ikev2_sa_v2_details_a616e604";
  static vapi_message_desc_t __vapi_metadata_ikev2_sa_v2_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_sa_v2_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_sa_v2_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_sa_v2_details_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_sa_v2_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_sa_v2_details = vapi_register_msg(&__vapi_metadata_ikev2_sa_v2_details);
  VAPI_DBG("Assigned msg id %d to ikev2_sa_v2_details", vapi_msg_id_ikev2_sa_v2_details);
}

static inline void vapi_set_vapi_msg_ikev2_sa_v2_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_sa_v2_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_sa_v2_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_sa_v2_dump
#define defined_vapi_msg_ikev2_sa_v2_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ikev2_sa_v2_dump;

static inline void vapi_msg_ikev2_sa_v2_dump_hton(vapi_msg_ikev2_sa_v2_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_sa_v2_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ikev2_sa_v2_dump_ntoh(vapi_msg_ikev2_sa_v2_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_sa_v2_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ikev2_sa_v2_dump_msg_size(vapi_msg_ikev2_sa_v2_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_sa_v2_dump_msg_size(vapi_msg_ikev2_sa_v2_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_sa_v2_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_sa_v2_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_sa_v2_dump));
      return -1;
    }
  if (vapi_calc_ikev2_sa_v2_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_sa_v2_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_sa_v2_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_sa_v2_dump* vapi_alloc_ikev2_sa_v2_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_sa_v2_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_sa_v2_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_sa_v2_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_sa_v2_dump);

  return msg;
}

static inline vapi_error_e vapi_ikev2_sa_v2_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_sa_v2_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_sa_v2_details *reply),
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
  vapi_msg_ikev2_sa_v2_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_sa_v2_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_ikev2_sa_v2_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_sa_v2_dump()
{
  static const char name[] = "ikev2_sa_v2_dump";
  static const char name_with_crc[] = "ikev2_sa_v2_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_ikev2_sa_v2_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ikev2_sa_v2_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_sa_v2_dump_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_sa_v2_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_sa_v2_dump = vapi_register_msg(&__vapi_metadata_ikev2_sa_v2_dump);
  VAPI_DBG("Assigned msg id %d to ikev2_sa_v2_dump", vapi_msg_id_ikev2_sa_v2_dump);
}
#endif

#ifndef defined_vapi_msg_ikev2_sa_v3_details
#define defined_vapi_msg_ikev2_sa_v3_details
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_ikev2_sa_v3 sa; 
} vapi_payload_ikev2_sa_v3_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_sa_v3_details payload;
} vapi_msg_ikev2_sa_v3_details;

static inline void vapi_msg_ikev2_sa_v3_details_payload_hton(vapi_payload_ikev2_sa_v3_details *payload)
{
  payload->retval = htobe32(payload->retval);
  vapi_type_ikev2_sa_v3_hton(&payload->sa);
}

static inline void vapi_msg_ikev2_sa_v3_details_payload_ntoh(vapi_payload_ikev2_sa_v3_details *payload)
{
  payload->retval = be32toh(payload->retval);
  vapi_type_ikev2_sa_v3_ntoh(&payload->sa);
}

static inline void vapi_msg_ikev2_sa_v3_details_hton(vapi_msg_ikev2_sa_v3_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_sa_v3_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_sa_v3_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_sa_v3_details_ntoh(vapi_msg_ikev2_sa_v3_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_sa_v3_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_sa_v3_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_sa_v3_details_msg_size(vapi_msg_ikev2_sa_v3_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_sa_v3_details_msg_size(vapi_msg_ikev2_sa_v3_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_sa_v3_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_sa_v3_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_sa_v3_details));
      return -1;
    }
  if (vapi_calc_ikev2_sa_v3_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_sa_v3_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_sa_v3_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_sa_v3_details()
{
  static const char name[] = "ikev2_sa_v3_details";
  static const char name_with_crc[] = "ikev2_sa_v3_details_85c9a941";
  static vapi_message_desc_t __vapi_metadata_ikev2_sa_v3_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_sa_v3_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_sa_v3_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_sa_v3_details_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_sa_v3_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_sa_v3_details = vapi_register_msg(&__vapi_metadata_ikev2_sa_v3_details);
  VAPI_DBG("Assigned msg id %d to ikev2_sa_v3_details", vapi_msg_id_ikev2_sa_v3_details);
}

static inline void vapi_set_vapi_msg_ikev2_sa_v3_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_sa_v3_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_sa_v3_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_sa_v3_dump
#define defined_vapi_msg_ikev2_sa_v3_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ikev2_sa_v3_dump;

static inline void vapi_msg_ikev2_sa_v3_dump_hton(vapi_msg_ikev2_sa_v3_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_sa_v3_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ikev2_sa_v3_dump_ntoh(vapi_msg_ikev2_sa_v3_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_sa_v3_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ikev2_sa_v3_dump_msg_size(vapi_msg_ikev2_sa_v3_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_sa_v3_dump_msg_size(vapi_msg_ikev2_sa_v3_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_sa_v3_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_sa_v3_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_sa_v3_dump));
      return -1;
    }
  if (vapi_calc_ikev2_sa_v3_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_sa_v3_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_sa_v3_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_sa_v3_dump* vapi_alloc_ikev2_sa_v3_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_sa_v3_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_sa_v3_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_sa_v3_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_sa_v3_dump);

  return msg;
}

static inline vapi_error_e vapi_ikev2_sa_v3_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_sa_v3_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_sa_v3_details *reply),
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
  vapi_msg_ikev2_sa_v3_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_sa_v3_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_ikev2_sa_v3_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_sa_v3_dump()
{
  static const char name[] = "ikev2_sa_v3_dump";
  static const char name_with_crc[] = "ikev2_sa_v3_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_ikev2_sa_v3_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ikev2_sa_v3_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_sa_v3_dump_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_sa_v3_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_sa_v3_dump = vapi_register_msg(&__vapi_metadata_ikev2_sa_v3_dump);
  VAPI_DBG("Assigned msg id %d to ikev2_sa_v3_dump", vapi_msg_id_ikev2_sa_v3_dump);
}
#endif

#ifndef defined_vapi_msg_ikev2_child_sa_details
#define defined_vapi_msg_ikev2_child_sa_details
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_ikev2_child_sa child_sa; 
} vapi_payload_ikev2_child_sa_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_child_sa_details payload;
} vapi_msg_ikev2_child_sa_details;

static inline void vapi_msg_ikev2_child_sa_details_payload_hton(vapi_payload_ikev2_child_sa_details *payload)
{
  payload->retval = htobe32(payload->retval);
  vapi_type_ikev2_child_sa_hton(&payload->child_sa);
}

static inline void vapi_msg_ikev2_child_sa_details_payload_ntoh(vapi_payload_ikev2_child_sa_details *payload)
{
  payload->retval = be32toh(payload->retval);
  vapi_type_ikev2_child_sa_ntoh(&payload->child_sa);
}

static inline void vapi_msg_ikev2_child_sa_details_hton(vapi_msg_ikev2_child_sa_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_child_sa_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_child_sa_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_child_sa_details_ntoh(vapi_msg_ikev2_child_sa_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_child_sa_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_child_sa_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_child_sa_details_msg_size(vapi_msg_ikev2_child_sa_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_child_sa_details_msg_size(vapi_msg_ikev2_child_sa_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_child_sa_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_child_sa_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_child_sa_details));
      return -1;
    }
  if (vapi_calc_ikev2_child_sa_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_child_sa_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_child_sa_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_child_sa_details()
{
  static const char name[] = "ikev2_child_sa_details";
  static const char name_with_crc[] = "ikev2_child_sa_details_ff67741f";
  static vapi_message_desc_t __vapi_metadata_ikev2_child_sa_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_child_sa_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_child_sa_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_child_sa_details_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_child_sa_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_child_sa_details = vapi_register_msg(&__vapi_metadata_ikev2_child_sa_details);
  VAPI_DBG("Assigned msg id %d to ikev2_child_sa_details", vapi_msg_id_ikev2_child_sa_details);
}

static inline void vapi_set_vapi_msg_ikev2_child_sa_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_child_sa_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_child_sa_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_child_sa_dump
#define defined_vapi_msg_ikev2_child_sa_dump
typedef struct __attribute__ ((__packed__)) {
  u32 sa_index; 
} vapi_payload_ikev2_child_sa_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_child_sa_dump payload;
} vapi_msg_ikev2_child_sa_dump;

static inline void vapi_msg_ikev2_child_sa_dump_payload_hton(vapi_payload_ikev2_child_sa_dump *payload)
{
  payload->sa_index = htobe32(payload->sa_index);
}

static inline void vapi_msg_ikev2_child_sa_dump_payload_ntoh(vapi_payload_ikev2_child_sa_dump *payload)
{
  payload->sa_index = be32toh(payload->sa_index);
}

static inline void vapi_msg_ikev2_child_sa_dump_hton(vapi_msg_ikev2_child_sa_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_child_sa_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_child_sa_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_child_sa_dump_ntoh(vapi_msg_ikev2_child_sa_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_child_sa_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_child_sa_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_child_sa_dump_msg_size(vapi_msg_ikev2_child_sa_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_child_sa_dump_msg_size(vapi_msg_ikev2_child_sa_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_child_sa_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_child_sa_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_child_sa_dump));
      return -1;
    }
  if (vapi_calc_ikev2_child_sa_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_child_sa_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_child_sa_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_child_sa_dump* vapi_alloc_ikev2_child_sa_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_child_sa_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_child_sa_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_child_sa_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_child_sa_dump);

  return msg;
}

static inline vapi_error_e vapi_ikev2_child_sa_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_child_sa_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_child_sa_details *reply),
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
  vapi_msg_ikev2_child_sa_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_child_sa_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_ikev2_child_sa_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_child_sa_dump()
{
  static const char name[] = "ikev2_child_sa_dump";
  static const char name_with_crc[] = "ikev2_child_sa_dump_01eab609";
  static vapi_message_desc_t __vapi_metadata_ikev2_child_sa_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_child_sa_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_child_sa_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_child_sa_dump_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_child_sa_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_child_sa_dump = vapi_register_msg(&__vapi_metadata_ikev2_child_sa_dump);
  VAPI_DBG("Assigned msg id %d to ikev2_child_sa_dump", vapi_msg_id_ikev2_child_sa_dump);
}
#endif

#ifndef defined_vapi_msg_ikev2_child_sa_v2_details
#define defined_vapi_msg_ikev2_child_sa_v2_details
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_ikev2_child_sa_v2 child_sa; 
} vapi_payload_ikev2_child_sa_v2_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_child_sa_v2_details payload;
} vapi_msg_ikev2_child_sa_v2_details;

static inline void vapi_msg_ikev2_child_sa_v2_details_payload_hton(vapi_payload_ikev2_child_sa_v2_details *payload)
{
  payload->retval = htobe32(payload->retval);
  vapi_type_ikev2_child_sa_v2_hton(&payload->child_sa);
}

static inline void vapi_msg_ikev2_child_sa_v2_details_payload_ntoh(vapi_payload_ikev2_child_sa_v2_details *payload)
{
  payload->retval = be32toh(payload->retval);
  vapi_type_ikev2_child_sa_v2_ntoh(&payload->child_sa);
}

static inline void vapi_msg_ikev2_child_sa_v2_details_hton(vapi_msg_ikev2_child_sa_v2_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_child_sa_v2_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_child_sa_v2_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_child_sa_v2_details_ntoh(vapi_msg_ikev2_child_sa_v2_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_child_sa_v2_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_child_sa_v2_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_child_sa_v2_details_msg_size(vapi_msg_ikev2_child_sa_v2_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_child_sa_v2_details_msg_size(vapi_msg_ikev2_child_sa_v2_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_child_sa_v2_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_child_sa_v2_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_child_sa_v2_details));
      return -1;
    }
  if (vapi_calc_ikev2_child_sa_v2_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_child_sa_v2_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_child_sa_v2_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_child_sa_v2_details()
{
  static const char name[] = "ikev2_child_sa_v2_details";
  static const char name_with_crc[] = "ikev2_child_sa_v2_details_1db62aa2";
  static vapi_message_desc_t __vapi_metadata_ikev2_child_sa_v2_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_child_sa_v2_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_child_sa_v2_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_child_sa_v2_details_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_child_sa_v2_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_child_sa_v2_details = vapi_register_msg(&__vapi_metadata_ikev2_child_sa_v2_details);
  VAPI_DBG("Assigned msg id %d to ikev2_child_sa_v2_details", vapi_msg_id_ikev2_child_sa_v2_details);
}

static inline void vapi_set_vapi_msg_ikev2_child_sa_v2_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_child_sa_v2_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_child_sa_v2_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_child_sa_v2_dump
#define defined_vapi_msg_ikev2_child_sa_v2_dump
typedef struct __attribute__ ((__packed__)) {
  u32 sa_index; 
} vapi_payload_ikev2_child_sa_v2_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_child_sa_v2_dump payload;
} vapi_msg_ikev2_child_sa_v2_dump;

static inline void vapi_msg_ikev2_child_sa_v2_dump_payload_hton(vapi_payload_ikev2_child_sa_v2_dump *payload)
{
  payload->sa_index = htobe32(payload->sa_index);
}

static inline void vapi_msg_ikev2_child_sa_v2_dump_payload_ntoh(vapi_payload_ikev2_child_sa_v2_dump *payload)
{
  payload->sa_index = be32toh(payload->sa_index);
}

static inline void vapi_msg_ikev2_child_sa_v2_dump_hton(vapi_msg_ikev2_child_sa_v2_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_child_sa_v2_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_child_sa_v2_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_child_sa_v2_dump_ntoh(vapi_msg_ikev2_child_sa_v2_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_child_sa_v2_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_child_sa_v2_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_child_sa_v2_dump_msg_size(vapi_msg_ikev2_child_sa_v2_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_child_sa_v2_dump_msg_size(vapi_msg_ikev2_child_sa_v2_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_child_sa_v2_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_child_sa_v2_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_child_sa_v2_dump));
      return -1;
    }
  if (vapi_calc_ikev2_child_sa_v2_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_child_sa_v2_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_child_sa_v2_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_child_sa_v2_dump* vapi_alloc_ikev2_child_sa_v2_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_child_sa_v2_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_child_sa_v2_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_child_sa_v2_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_child_sa_v2_dump);

  return msg;
}

static inline vapi_error_e vapi_ikev2_child_sa_v2_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_child_sa_v2_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_child_sa_v2_details *reply),
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
  vapi_msg_ikev2_child_sa_v2_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_child_sa_v2_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_ikev2_child_sa_v2_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_child_sa_v2_dump()
{
  static const char name[] = "ikev2_child_sa_v2_dump";
  static const char name_with_crc[] = "ikev2_child_sa_v2_dump_01eab609";
  static vapi_message_desc_t __vapi_metadata_ikev2_child_sa_v2_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_child_sa_v2_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_child_sa_v2_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_child_sa_v2_dump_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_child_sa_v2_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_child_sa_v2_dump = vapi_register_msg(&__vapi_metadata_ikev2_child_sa_v2_dump);
  VAPI_DBG("Assigned msg id %d to ikev2_child_sa_v2_dump", vapi_msg_id_ikev2_child_sa_v2_dump);
}
#endif

#ifndef defined_vapi_msg_ikev2_nonce_get_reply
#define defined_vapi_msg_ikev2_nonce_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 data_len;
  u8 nonce[0]; 
} vapi_payload_ikev2_nonce_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_nonce_get_reply payload;
} vapi_msg_ikev2_nonce_get_reply;

static inline void vapi_msg_ikev2_nonce_get_reply_payload_hton(vapi_payload_ikev2_nonce_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->data_len = htobe32(payload->data_len);
}

static inline void vapi_msg_ikev2_nonce_get_reply_payload_ntoh(vapi_payload_ikev2_nonce_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->data_len = be32toh(payload->data_len);
}

static inline void vapi_msg_ikev2_nonce_get_reply_hton(vapi_msg_ikev2_nonce_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_nonce_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_nonce_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_nonce_get_reply_ntoh(vapi_msg_ikev2_nonce_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_nonce_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_nonce_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_nonce_get_reply_msg_size(vapi_msg_ikev2_nonce_get_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.nonce[0]) * msg->payload.data_len;
}

static inline int vapi_verify_ikev2_nonce_get_reply_msg_size(vapi_msg_ikev2_nonce_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_nonce_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_nonce_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_nonce_get_reply));
      return -1;
    }
  if (vapi_calc_ikev2_nonce_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_nonce_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_nonce_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_nonce_get_reply()
{
  static const char name[] = "ikev2_nonce_get_reply";
  static const char name_with_crc[] = "ikev2_nonce_get_reply_1b37a342";
  static vapi_message_desc_t __vapi_metadata_ikev2_nonce_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_nonce_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_nonce_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_nonce_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_nonce_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_nonce_get_reply = vapi_register_msg(&__vapi_metadata_ikev2_nonce_get_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_nonce_get_reply", vapi_msg_id_ikev2_nonce_get_reply);
}

static inline void vapi_set_vapi_msg_ikev2_nonce_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_nonce_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_nonce_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_nonce_get
#define defined_vapi_msg_ikev2_nonce_get
typedef struct __attribute__ ((__packed__)) {
  bool is_initiator;
  u32 sa_index; 
} vapi_payload_ikev2_nonce_get;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_nonce_get payload;
} vapi_msg_ikev2_nonce_get;

static inline void vapi_msg_ikev2_nonce_get_payload_hton(vapi_payload_ikev2_nonce_get *payload)
{
  payload->sa_index = htobe32(payload->sa_index);
}

static inline void vapi_msg_ikev2_nonce_get_payload_ntoh(vapi_payload_ikev2_nonce_get *payload)
{
  payload->sa_index = be32toh(payload->sa_index);
}

static inline void vapi_msg_ikev2_nonce_get_hton(vapi_msg_ikev2_nonce_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_nonce_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_nonce_get_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_nonce_get_ntoh(vapi_msg_ikev2_nonce_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_nonce_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_nonce_get_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_nonce_get_msg_size(vapi_msg_ikev2_nonce_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_nonce_get_msg_size(vapi_msg_ikev2_nonce_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_nonce_get) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_nonce_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_nonce_get));
      return -1;
    }
  if (vapi_calc_ikev2_nonce_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_nonce_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_nonce_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_nonce_get* vapi_alloc_ikev2_nonce_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_nonce_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_nonce_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_nonce_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_nonce_get);

  return msg;
}

static inline vapi_error_e vapi_ikev2_nonce_get(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_nonce_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_nonce_get_reply *reply),
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
  vapi_msg_ikev2_nonce_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_nonce_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_nonce_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_nonce_get()
{
  static const char name[] = "ikev2_nonce_get";
  static const char name_with_crc[] = "ikev2_nonce_get_7fe9ad51";
  static vapi_message_desc_t __vapi_metadata_ikev2_nonce_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_nonce_get, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_nonce_get_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_nonce_get_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_nonce_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_nonce_get = vapi_register_msg(&__vapi_metadata_ikev2_nonce_get);
  VAPI_DBG("Assigned msg id %d to ikev2_nonce_get", vapi_msg_id_ikev2_nonce_get);
}
#endif

#ifndef defined_vapi_msg_ikev2_traffic_selector_details
#define defined_vapi_msg_ikev2_traffic_selector_details
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_ikev2_ts ts; 
} vapi_payload_ikev2_traffic_selector_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_traffic_selector_details payload;
} vapi_msg_ikev2_traffic_selector_details;

static inline void vapi_msg_ikev2_traffic_selector_details_payload_hton(vapi_payload_ikev2_traffic_selector_details *payload)
{
  payload->retval = htobe32(payload->retval);
  vapi_type_ikev2_ts_hton(&payload->ts);
}

static inline void vapi_msg_ikev2_traffic_selector_details_payload_ntoh(vapi_payload_ikev2_traffic_selector_details *payload)
{
  payload->retval = be32toh(payload->retval);
  vapi_type_ikev2_ts_ntoh(&payload->ts);
}

static inline void vapi_msg_ikev2_traffic_selector_details_hton(vapi_msg_ikev2_traffic_selector_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_traffic_selector_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_traffic_selector_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_traffic_selector_details_ntoh(vapi_msg_ikev2_traffic_selector_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_traffic_selector_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_traffic_selector_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_traffic_selector_details_msg_size(vapi_msg_ikev2_traffic_selector_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_traffic_selector_details_msg_size(vapi_msg_ikev2_traffic_selector_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_traffic_selector_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_traffic_selector_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_traffic_selector_details));
      return -1;
    }
  if (vapi_calc_ikev2_traffic_selector_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_traffic_selector_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_traffic_selector_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_traffic_selector_details()
{
  static const char name[] = "ikev2_traffic_selector_details";
  static const char name_with_crc[] = "ikev2_traffic_selector_details_518cb06f";
  static vapi_message_desc_t __vapi_metadata_ikev2_traffic_selector_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_traffic_selector_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_traffic_selector_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_traffic_selector_details_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_traffic_selector_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_traffic_selector_details = vapi_register_msg(&__vapi_metadata_ikev2_traffic_selector_details);
  VAPI_DBG("Assigned msg id %d to ikev2_traffic_selector_details", vapi_msg_id_ikev2_traffic_selector_details);
}

static inline void vapi_set_vapi_msg_ikev2_traffic_selector_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_traffic_selector_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_traffic_selector_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_traffic_selector_dump
#define defined_vapi_msg_ikev2_traffic_selector_dump
typedef struct __attribute__ ((__packed__)) {
  bool is_initiator;
  u32 sa_index;
  u32 child_sa_index; 
} vapi_payload_ikev2_traffic_selector_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_traffic_selector_dump payload;
} vapi_msg_ikev2_traffic_selector_dump;

static inline void vapi_msg_ikev2_traffic_selector_dump_payload_hton(vapi_payload_ikev2_traffic_selector_dump *payload)
{
  payload->sa_index = htobe32(payload->sa_index);
  payload->child_sa_index = htobe32(payload->child_sa_index);
}

static inline void vapi_msg_ikev2_traffic_selector_dump_payload_ntoh(vapi_payload_ikev2_traffic_selector_dump *payload)
{
  payload->sa_index = be32toh(payload->sa_index);
  payload->child_sa_index = be32toh(payload->child_sa_index);
}

static inline void vapi_msg_ikev2_traffic_selector_dump_hton(vapi_msg_ikev2_traffic_selector_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_traffic_selector_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_traffic_selector_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_traffic_selector_dump_ntoh(vapi_msg_ikev2_traffic_selector_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_traffic_selector_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_traffic_selector_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_traffic_selector_dump_msg_size(vapi_msg_ikev2_traffic_selector_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_traffic_selector_dump_msg_size(vapi_msg_ikev2_traffic_selector_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_traffic_selector_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_traffic_selector_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_traffic_selector_dump));
      return -1;
    }
  if (vapi_calc_ikev2_traffic_selector_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_traffic_selector_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_traffic_selector_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_traffic_selector_dump* vapi_alloc_ikev2_traffic_selector_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_traffic_selector_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_traffic_selector_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_traffic_selector_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_traffic_selector_dump);

  return msg;
}

static inline vapi_error_e vapi_ikev2_traffic_selector_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_traffic_selector_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_traffic_selector_details *reply),
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
  vapi_msg_ikev2_traffic_selector_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_traffic_selector_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_ikev2_traffic_selector_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_traffic_selector_dump()
{
  static const char name[] = "ikev2_traffic_selector_dump";
  static const char name_with_crc[] = "ikev2_traffic_selector_dump_a7385e33";
  static vapi_message_desc_t __vapi_metadata_ikev2_traffic_selector_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_traffic_selector_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_traffic_selector_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_traffic_selector_dump_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_traffic_selector_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_traffic_selector_dump = vapi_register_msg(&__vapi_metadata_ikev2_traffic_selector_dump);
  VAPI_DBG("Assigned msg id %d to ikev2_traffic_selector_dump", vapi_msg_id_ikev2_traffic_selector_dump);
}
#endif

#ifndef defined_vapi_msg_ikev2_profile_add_del_reply
#define defined_vapi_msg_ikev2_profile_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ikev2_profile_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_profile_add_del_reply payload;
} vapi_msg_ikev2_profile_add_del_reply;

static inline void vapi_msg_ikev2_profile_add_del_reply_payload_hton(vapi_payload_ikev2_profile_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_profile_add_del_reply_payload_ntoh(vapi_payload_ikev2_profile_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_profile_add_del_reply_hton(vapi_msg_ikev2_profile_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_profile_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_profile_add_del_reply_ntoh(vapi_msg_ikev2_profile_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_profile_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_profile_add_del_reply_msg_size(vapi_msg_ikev2_profile_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_profile_add_del_reply_msg_size(vapi_msg_ikev2_profile_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_profile_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_profile_add_del_reply));
      return -1;
    }
  if (vapi_calc_ikev2_profile_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_profile_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_profile_add_del_reply()
{
  static const char name[] = "ikev2_profile_add_del_reply";
  static const char name_with_crc[] = "ikev2_profile_add_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ikev2_profile_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_profile_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_profile_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_profile_add_del_reply = vapi_register_msg(&__vapi_metadata_ikev2_profile_add_del_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_profile_add_del_reply", vapi_msg_id_ikev2_profile_add_del_reply);
}

static inline void vapi_set_vapi_msg_ikev2_profile_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_profile_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_profile_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_profile_add_del
#define defined_vapi_msg_ikev2_profile_add_del
typedef struct __attribute__ ((__packed__)) {
  u8 name[64];
  bool is_add; 
} vapi_payload_ikev2_profile_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_profile_add_del payload;
} vapi_msg_ikev2_profile_add_del;

static inline void vapi_msg_ikev2_profile_add_del_payload_hton(vapi_payload_ikev2_profile_add_del *payload)
{

}

static inline void vapi_msg_ikev2_profile_add_del_payload_ntoh(vapi_payload_ikev2_profile_add_del *payload)
{

}

static inline void vapi_msg_ikev2_profile_add_del_hton(vapi_msg_ikev2_profile_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_profile_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_profile_add_del_ntoh(vapi_msg_ikev2_profile_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_profile_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_profile_add_del_msg_size(vapi_msg_ikev2_profile_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_profile_add_del_msg_size(vapi_msg_ikev2_profile_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_profile_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_profile_add_del));
      return -1;
    }
  if (vapi_calc_ikev2_profile_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_profile_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_profile_add_del* vapi_alloc_ikev2_profile_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_profile_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_profile_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_profile_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_profile_add_del);

  return msg;
}

static inline vapi_error_e vapi_ikev2_profile_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_profile_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_profile_add_del_reply *reply),
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
  vapi_msg_ikev2_profile_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_profile_add_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_profile_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_profile_add_del()
{
  static const char name[] = "ikev2_profile_add_del";
  static const char name_with_crc[] = "ikev2_profile_add_del_2c925b55";
  static vapi_message_desc_t __vapi_metadata_ikev2_profile_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_profile_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_profile_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_add_del_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_profile_add_del = vapi_register_msg(&__vapi_metadata_ikev2_profile_add_del);
  VAPI_DBG("Assigned msg id %d to ikev2_profile_add_del", vapi_msg_id_ikev2_profile_add_del);
}
#endif

#ifndef defined_vapi_msg_ikev2_profile_set_auth_reply
#define defined_vapi_msg_ikev2_profile_set_auth_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ikev2_profile_set_auth_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_profile_set_auth_reply payload;
} vapi_msg_ikev2_profile_set_auth_reply;

static inline void vapi_msg_ikev2_profile_set_auth_reply_payload_hton(vapi_payload_ikev2_profile_set_auth_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_profile_set_auth_reply_payload_ntoh(vapi_payload_ikev2_profile_set_auth_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_profile_set_auth_reply_hton(vapi_msg_ikev2_profile_set_auth_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_auth_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_profile_set_auth_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_profile_set_auth_reply_ntoh(vapi_msg_ikev2_profile_set_auth_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_auth_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_profile_set_auth_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_profile_set_auth_reply_msg_size(vapi_msg_ikev2_profile_set_auth_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_profile_set_auth_reply_msg_size(vapi_msg_ikev2_profile_set_auth_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_profile_set_auth_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_auth_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_profile_set_auth_reply));
      return -1;
    }
  if (vapi_calc_ikev2_profile_set_auth_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_auth_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_profile_set_auth_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_profile_set_auth_reply()
{
  static const char name[] = "ikev2_profile_set_auth_reply";
  static const char name_with_crc[] = "ikev2_profile_set_auth_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ikev2_profile_set_auth_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_profile_set_auth_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_profile_set_auth_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_auth_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_auth_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_profile_set_auth_reply = vapi_register_msg(&__vapi_metadata_ikev2_profile_set_auth_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_profile_set_auth_reply", vapi_msg_id_ikev2_profile_set_auth_reply);
}

static inline void vapi_set_vapi_msg_ikev2_profile_set_auth_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_profile_set_auth_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_profile_set_auth_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_profile_set_auth
#define defined_vapi_msg_ikev2_profile_set_auth
typedef struct __attribute__ ((__packed__)) {
  u8 name[64];
  u8 auth_method;
  bool is_hex;
  u32 data_len;
  u8 data[0]; 
} vapi_payload_ikev2_profile_set_auth;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_profile_set_auth payload;
} vapi_msg_ikev2_profile_set_auth;

static inline void vapi_msg_ikev2_profile_set_auth_payload_hton(vapi_payload_ikev2_profile_set_auth *payload)
{
  payload->data_len = htobe32(payload->data_len);
}

static inline void vapi_msg_ikev2_profile_set_auth_payload_ntoh(vapi_payload_ikev2_profile_set_auth *payload)
{
  payload->data_len = be32toh(payload->data_len);
}

static inline void vapi_msg_ikev2_profile_set_auth_hton(vapi_msg_ikev2_profile_set_auth *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_auth'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_profile_set_auth_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_profile_set_auth_ntoh(vapi_msg_ikev2_profile_set_auth *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_auth'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_profile_set_auth_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_profile_set_auth_msg_size(vapi_msg_ikev2_profile_set_auth *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.data[0]) * msg->payload.data_len;
}

static inline int vapi_verify_ikev2_profile_set_auth_msg_size(vapi_msg_ikev2_profile_set_auth *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_profile_set_auth) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_auth' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_profile_set_auth));
      return -1;
    }
  if (vapi_calc_ikev2_profile_set_auth_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_auth' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_profile_set_auth_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_profile_set_auth* vapi_alloc_ikev2_profile_set_auth(struct vapi_ctx_s *ctx, size_t _data_array_size)
{
  vapi_msg_ikev2_profile_set_auth *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_profile_set_auth) + sizeof(msg->payload.data[0]) * _data_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_profile_set_auth*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_profile_set_auth);
  msg->payload.data_len = _data_array_size;

  return msg;
}

static inline vapi_error_e vapi_ikev2_profile_set_auth(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_profile_set_auth *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_profile_set_auth_reply *reply),
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
  vapi_msg_ikev2_profile_set_auth_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_profile_set_auth_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_profile_set_auth_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_profile_set_auth()
{
  static const char name[] = "ikev2_profile_set_auth";
  static const char name_with_crc[] = "ikev2_profile_set_auth_642c97cd";
  static vapi_message_desc_t __vapi_metadata_ikev2_profile_set_auth = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_profile_set_auth, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_profile_set_auth_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_auth_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_auth_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_profile_set_auth = vapi_register_msg(&__vapi_metadata_ikev2_profile_set_auth);
  VAPI_DBG("Assigned msg id %d to ikev2_profile_set_auth", vapi_msg_id_ikev2_profile_set_auth);
}
#endif

#ifndef defined_vapi_msg_ikev2_profile_set_id_reply
#define defined_vapi_msg_ikev2_profile_set_id_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ikev2_profile_set_id_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_profile_set_id_reply payload;
} vapi_msg_ikev2_profile_set_id_reply;

static inline void vapi_msg_ikev2_profile_set_id_reply_payload_hton(vapi_payload_ikev2_profile_set_id_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_profile_set_id_reply_payload_ntoh(vapi_payload_ikev2_profile_set_id_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_profile_set_id_reply_hton(vapi_msg_ikev2_profile_set_id_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_id_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_profile_set_id_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_profile_set_id_reply_ntoh(vapi_msg_ikev2_profile_set_id_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_id_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_profile_set_id_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_profile_set_id_reply_msg_size(vapi_msg_ikev2_profile_set_id_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_profile_set_id_reply_msg_size(vapi_msg_ikev2_profile_set_id_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_profile_set_id_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_id_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_profile_set_id_reply));
      return -1;
    }
  if (vapi_calc_ikev2_profile_set_id_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_id_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_profile_set_id_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_profile_set_id_reply()
{
  static const char name[] = "ikev2_profile_set_id_reply";
  static const char name_with_crc[] = "ikev2_profile_set_id_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ikev2_profile_set_id_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_profile_set_id_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_profile_set_id_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_id_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_id_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_profile_set_id_reply = vapi_register_msg(&__vapi_metadata_ikev2_profile_set_id_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_profile_set_id_reply", vapi_msg_id_ikev2_profile_set_id_reply);
}

static inline void vapi_set_vapi_msg_ikev2_profile_set_id_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_profile_set_id_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_profile_set_id_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_profile_set_id
#define defined_vapi_msg_ikev2_profile_set_id
typedef struct __attribute__ ((__packed__)) {
  u8 name[64];
  bool is_local;
  u8 id_type;
  u32 data_len;
  u8 data[0]; 
} vapi_payload_ikev2_profile_set_id;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_profile_set_id payload;
} vapi_msg_ikev2_profile_set_id;

static inline void vapi_msg_ikev2_profile_set_id_payload_hton(vapi_payload_ikev2_profile_set_id *payload)
{
  payload->data_len = htobe32(payload->data_len);
}

static inline void vapi_msg_ikev2_profile_set_id_payload_ntoh(vapi_payload_ikev2_profile_set_id *payload)
{
  payload->data_len = be32toh(payload->data_len);
}

static inline void vapi_msg_ikev2_profile_set_id_hton(vapi_msg_ikev2_profile_set_id *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_id'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_profile_set_id_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_profile_set_id_ntoh(vapi_msg_ikev2_profile_set_id *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_id'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_profile_set_id_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_profile_set_id_msg_size(vapi_msg_ikev2_profile_set_id *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.data[0]) * msg->payload.data_len;
}

static inline int vapi_verify_ikev2_profile_set_id_msg_size(vapi_msg_ikev2_profile_set_id *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_profile_set_id) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_id' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_profile_set_id));
      return -1;
    }
  if (vapi_calc_ikev2_profile_set_id_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_id' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_profile_set_id_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_profile_set_id* vapi_alloc_ikev2_profile_set_id(struct vapi_ctx_s *ctx, size_t _data_array_size)
{
  vapi_msg_ikev2_profile_set_id *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_profile_set_id) + sizeof(msg->payload.data[0]) * _data_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_profile_set_id*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_profile_set_id);
  msg->payload.data_len = _data_array_size;

  return msg;
}

static inline vapi_error_e vapi_ikev2_profile_set_id(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_profile_set_id *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_profile_set_id_reply *reply),
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
  vapi_msg_ikev2_profile_set_id_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_profile_set_id_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_profile_set_id_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_profile_set_id()
{
  static const char name[] = "ikev2_profile_set_id";
  static const char name_with_crc[] = "ikev2_profile_set_id_4d7e2418";
  static vapi_message_desc_t __vapi_metadata_ikev2_profile_set_id = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_profile_set_id, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_profile_set_id_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_id_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_id_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_profile_set_id = vapi_register_msg(&__vapi_metadata_ikev2_profile_set_id);
  VAPI_DBG("Assigned msg id %d to ikev2_profile_set_id", vapi_msg_id_ikev2_profile_set_id);
}
#endif

#ifndef defined_vapi_msg_ikev2_profile_disable_natt_reply
#define defined_vapi_msg_ikev2_profile_disable_natt_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ikev2_profile_disable_natt_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_profile_disable_natt_reply payload;
} vapi_msg_ikev2_profile_disable_natt_reply;

static inline void vapi_msg_ikev2_profile_disable_natt_reply_payload_hton(vapi_payload_ikev2_profile_disable_natt_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_profile_disable_natt_reply_payload_ntoh(vapi_payload_ikev2_profile_disable_natt_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_profile_disable_natt_reply_hton(vapi_msg_ikev2_profile_disable_natt_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_disable_natt_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_profile_disable_natt_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_profile_disable_natt_reply_ntoh(vapi_msg_ikev2_profile_disable_natt_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_disable_natt_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_profile_disable_natt_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_profile_disable_natt_reply_msg_size(vapi_msg_ikev2_profile_disable_natt_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_profile_disable_natt_reply_msg_size(vapi_msg_ikev2_profile_disable_natt_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_profile_disable_natt_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_disable_natt_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_profile_disable_natt_reply));
      return -1;
    }
  if (vapi_calc_ikev2_profile_disable_natt_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_disable_natt_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_profile_disable_natt_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_profile_disable_natt_reply()
{
  static const char name[] = "ikev2_profile_disable_natt_reply";
  static const char name_with_crc[] = "ikev2_profile_disable_natt_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ikev2_profile_disable_natt_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_profile_disable_natt_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_profile_disable_natt_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_disable_natt_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_disable_natt_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_profile_disable_natt_reply = vapi_register_msg(&__vapi_metadata_ikev2_profile_disable_natt_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_profile_disable_natt_reply", vapi_msg_id_ikev2_profile_disable_natt_reply);
}

static inline void vapi_set_vapi_msg_ikev2_profile_disable_natt_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_profile_disable_natt_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_profile_disable_natt_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_profile_disable_natt
#define defined_vapi_msg_ikev2_profile_disable_natt
typedef struct __attribute__ ((__packed__)) {
  u8 name[64]; 
} vapi_payload_ikev2_profile_disable_natt;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_profile_disable_natt payload;
} vapi_msg_ikev2_profile_disable_natt;

static inline void vapi_msg_ikev2_profile_disable_natt_payload_hton(vapi_payload_ikev2_profile_disable_natt *payload)
{

}

static inline void vapi_msg_ikev2_profile_disable_natt_payload_ntoh(vapi_payload_ikev2_profile_disable_natt *payload)
{

}

static inline void vapi_msg_ikev2_profile_disable_natt_hton(vapi_msg_ikev2_profile_disable_natt *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_disable_natt'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_profile_disable_natt_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_profile_disable_natt_ntoh(vapi_msg_ikev2_profile_disable_natt *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_disable_natt'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_profile_disable_natt_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_profile_disable_natt_msg_size(vapi_msg_ikev2_profile_disable_natt *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_profile_disable_natt_msg_size(vapi_msg_ikev2_profile_disable_natt *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_profile_disable_natt) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_disable_natt' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_profile_disable_natt));
      return -1;
    }
  if (vapi_calc_ikev2_profile_disable_natt_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_disable_natt' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_profile_disable_natt_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_profile_disable_natt* vapi_alloc_ikev2_profile_disable_natt(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_profile_disable_natt *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_profile_disable_natt);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_profile_disable_natt*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_profile_disable_natt);

  return msg;
}

static inline vapi_error_e vapi_ikev2_profile_disable_natt(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_profile_disable_natt *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_profile_disable_natt_reply *reply),
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
  vapi_msg_ikev2_profile_disable_natt_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_profile_disable_natt_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_profile_disable_natt_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_profile_disable_natt()
{
  static const char name[] = "ikev2_profile_disable_natt";
  static const char name_with_crc[] = "ikev2_profile_disable_natt_ebf79a66";
  static vapi_message_desc_t __vapi_metadata_ikev2_profile_disable_natt = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_profile_disable_natt, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_profile_disable_natt_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_disable_natt_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_disable_natt_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_profile_disable_natt = vapi_register_msg(&__vapi_metadata_ikev2_profile_disable_natt);
  VAPI_DBG("Assigned msg id %d to ikev2_profile_disable_natt", vapi_msg_id_ikev2_profile_disable_natt);
}
#endif

#ifndef defined_vapi_msg_ikev2_profile_set_ts_reply
#define defined_vapi_msg_ikev2_profile_set_ts_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ikev2_profile_set_ts_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_profile_set_ts_reply payload;
} vapi_msg_ikev2_profile_set_ts_reply;

static inline void vapi_msg_ikev2_profile_set_ts_reply_payload_hton(vapi_payload_ikev2_profile_set_ts_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_profile_set_ts_reply_payload_ntoh(vapi_payload_ikev2_profile_set_ts_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_profile_set_ts_reply_hton(vapi_msg_ikev2_profile_set_ts_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_ts_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_profile_set_ts_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_profile_set_ts_reply_ntoh(vapi_msg_ikev2_profile_set_ts_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_ts_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_profile_set_ts_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_profile_set_ts_reply_msg_size(vapi_msg_ikev2_profile_set_ts_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_profile_set_ts_reply_msg_size(vapi_msg_ikev2_profile_set_ts_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_profile_set_ts_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_ts_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_profile_set_ts_reply));
      return -1;
    }
  if (vapi_calc_ikev2_profile_set_ts_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_ts_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_profile_set_ts_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_profile_set_ts_reply()
{
  static const char name[] = "ikev2_profile_set_ts_reply";
  static const char name_with_crc[] = "ikev2_profile_set_ts_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ikev2_profile_set_ts_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_profile_set_ts_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_profile_set_ts_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_ts_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_ts_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_profile_set_ts_reply = vapi_register_msg(&__vapi_metadata_ikev2_profile_set_ts_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_profile_set_ts_reply", vapi_msg_id_ikev2_profile_set_ts_reply);
}

static inline void vapi_set_vapi_msg_ikev2_profile_set_ts_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_profile_set_ts_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_profile_set_ts_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_profile_set_ts
#define defined_vapi_msg_ikev2_profile_set_ts
typedef struct __attribute__ ((__packed__)) {
  u8 name[64];
  vapi_type_ikev2_ts ts; 
} vapi_payload_ikev2_profile_set_ts;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_profile_set_ts payload;
} vapi_msg_ikev2_profile_set_ts;

static inline void vapi_msg_ikev2_profile_set_ts_payload_hton(vapi_payload_ikev2_profile_set_ts *payload)
{
  vapi_type_ikev2_ts_hton(&payload->ts);
}

static inline void vapi_msg_ikev2_profile_set_ts_payload_ntoh(vapi_payload_ikev2_profile_set_ts *payload)
{
  vapi_type_ikev2_ts_ntoh(&payload->ts);
}

static inline void vapi_msg_ikev2_profile_set_ts_hton(vapi_msg_ikev2_profile_set_ts *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_ts'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_profile_set_ts_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_profile_set_ts_ntoh(vapi_msg_ikev2_profile_set_ts *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_ts'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_profile_set_ts_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_profile_set_ts_msg_size(vapi_msg_ikev2_profile_set_ts *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_profile_set_ts_msg_size(vapi_msg_ikev2_profile_set_ts *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_profile_set_ts) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_ts' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_profile_set_ts));
      return -1;
    }
  if (vapi_calc_ikev2_profile_set_ts_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_ts' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_profile_set_ts_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_profile_set_ts* vapi_alloc_ikev2_profile_set_ts(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_profile_set_ts *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_profile_set_ts);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_profile_set_ts*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_profile_set_ts);

  return msg;
}

static inline vapi_error_e vapi_ikev2_profile_set_ts(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_profile_set_ts *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_profile_set_ts_reply *reply),
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
  vapi_msg_ikev2_profile_set_ts_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_profile_set_ts_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_profile_set_ts_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_profile_set_ts()
{
  static const char name[] = "ikev2_profile_set_ts";
  static const char name_with_crc[] = "ikev2_profile_set_ts_8eb8cfd1";
  static vapi_message_desc_t __vapi_metadata_ikev2_profile_set_ts = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_profile_set_ts, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_profile_set_ts_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_ts_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_ts_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_profile_set_ts = vapi_register_msg(&__vapi_metadata_ikev2_profile_set_ts);
  VAPI_DBG("Assigned msg id %d to ikev2_profile_set_ts", vapi_msg_id_ikev2_profile_set_ts);
}
#endif

#ifndef defined_vapi_msg_ikev2_set_local_key_reply
#define defined_vapi_msg_ikev2_set_local_key_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ikev2_set_local_key_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_set_local_key_reply payload;
} vapi_msg_ikev2_set_local_key_reply;

static inline void vapi_msg_ikev2_set_local_key_reply_payload_hton(vapi_payload_ikev2_set_local_key_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_set_local_key_reply_payload_ntoh(vapi_payload_ikev2_set_local_key_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_set_local_key_reply_hton(vapi_msg_ikev2_set_local_key_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_local_key_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_set_local_key_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_set_local_key_reply_ntoh(vapi_msg_ikev2_set_local_key_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_local_key_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_set_local_key_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_set_local_key_reply_msg_size(vapi_msg_ikev2_set_local_key_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_set_local_key_reply_msg_size(vapi_msg_ikev2_set_local_key_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_set_local_key_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_local_key_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_set_local_key_reply));
      return -1;
    }
  if (vapi_calc_ikev2_set_local_key_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_local_key_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_set_local_key_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_set_local_key_reply()
{
  static const char name[] = "ikev2_set_local_key_reply";
  static const char name_with_crc[] = "ikev2_set_local_key_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ikev2_set_local_key_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_set_local_key_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_set_local_key_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_set_local_key_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_set_local_key_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_set_local_key_reply = vapi_register_msg(&__vapi_metadata_ikev2_set_local_key_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_set_local_key_reply", vapi_msg_id_ikev2_set_local_key_reply);
}

static inline void vapi_set_vapi_msg_ikev2_set_local_key_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_set_local_key_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_set_local_key_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_set_local_key
#define defined_vapi_msg_ikev2_set_local_key
typedef struct __attribute__ ((__packed__)) {
  u8 key_file[256]; 
} vapi_payload_ikev2_set_local_key;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_set_local_key payload;
} vapi_msg_ikev2_set_local_key;

static inline void vapi_msg_ikev2_set_local_key_payload_hton(vapi_payload_ikev2_set_local_key *payload)
{

}

static inline void vapi_msg_ikev2_set_local_key_payload_ntoh(vapi_payload_ikev2_set_local_key *payload)
{

}

static inline void vapi_msg_ikev2_set_local_key_hton(vapi_msg_ikev2_set_local_key *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_local_key'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_set_local_key_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_set_local_key_ntoh(vapi_msg_ikev2_set_local_key *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_local_key'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_set_local_key_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_set_local_key_msg_size(vapi_msg_ikev2_set_local_key *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_set_local_key_msg_size(vapi_msg_ikev2_set_local_key *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_set_local_key) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_local_key' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_set_local_key));
      return -1;
    }
  if (vapi_calc_ikev2_set_local_key_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_local_key' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_set_local_key_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_set_local_key* vapi_alloc_ikev2_set_local_key(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_set_local_key *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_set_local_key);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_set_local_key*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_set_local_key);

  return msg;
}

static inline vapi_error_e vapi_ikev2_set_local_key(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_set_local_key *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_set_local_key_reply *reply),
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
  vapi_msg_ikev2_set_local_key_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_set_local_key_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_set_local_key_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_set_local_key()
{
  static const char name[] = "ikev2_set_local_key";
  static const char name_with_crc[] = "ikev2_set_local_key_799b69ec";
  static vapi_message_desc_t __vapi_metadata_ikev2_set_local_key = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_set_local_key, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_set_local_key_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_set_local_key_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_set_local_key_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_set_local_key = vapi_register_msg(&__vapi_metadata_ikev2_set_local_key);
  VAPI_DBG("Assigned msg id %d to ikev2_set_local_key", vapi_msg_id_ikev2_set_local_key);
}
#endif

#ifndef defined_vapi_msg_ikev2_set_tunnel_interface_reply
#define defined_vapi_msg_ikev2_set_tunnel_interface_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ikev2_set_tunnel_interface_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_set_tunnel_interface_reply payload;
} vapi_msg_ikev2_set_tunnel_interface_reply;

static inline void vapi_msg_ikev2_set_tunnel_interface_reply_payload_hton(vapi_payload_ikev2_set_tunnel_interface_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_set_tunnel_interface_reply_payload_ntoh(vapi_payload_ikev2_set_tunnel_interface_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_set_tunnel_interface_reply_hton(vapi_msg_ikev2_set_tunnel_interface_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_tunnel_interface_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_set_tunnel_interface_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_set_tunnel_interface_reply_ntoh(vapi_msg_ikev2_set_tunnel_interface_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_tunnel_interface_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_set_tunnel_interface_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_set_tunnel_interface_reply_msg_size(vapi_msg_ikev2_set_tunnel_interface_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_set_tunnel_interface_reply_msg_size(vapi_msg_ikev2_set_tunnel_interface_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_set_tunnel_interface_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_tunnel_interface_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_set_tunnel_interface_reply));
      return -1;
    }
  if (vapi_calc_ikev2_set_tunnel_interface_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_tunnel_interface_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_set_tunnel_interface_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_set_tunnel_interface_reply()
{
  static const char name[] = "ikev2_set_tunnel_interface_reply";
  static const char name_with_crc[] = "ikev2_set_tunnel_interface_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ikev2_set_tunnel_interface_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_set_tunnel_interface_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_set_tunnel_interface_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_set_tunnel_interface_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_set_tunnel_interface_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_set_tunnel_interface_reply = vapi_register_msg(&__vapi_metadata_ikev2_set_tunnel_interface_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_set_tunnel_interface_reply", vapi_msg_id_ikev2_set_tunnel_interface_reply);
}

static inline void vapi_set_vapi_msg_ikev2_set_tunnel_interface_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_set_tunnel_interface_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_set_tunnel_interface_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_set_tunnel_interface
#define defined_vapi_msg_ikev2_set_tunnel_interface
typedef struct __attribute__ ((__packed__)) {
  u8 name[64];
  vapi_type_interface_index sw_if_index; 
} vapi_payload_ikev2_set_tunnel_interface;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_set_tunnel_interface payload;
} vapi_msg_ikev2_set_tunnel_interface;

static inline void vapi_msg_ikev2_set_tunnel_interface_payload_hton(vapi_payload_ikev2_set_tunnel_interface *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ikev2_set_tunnel_interface_payload_ntoh(vapi_payload_ikev2_set_tunnel_interface *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ikev2_set_tunnel_interface_hton(vapi_msg_ikev2_set_tunnel_interface *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_tunnel_interface'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_set_tunnel_interface_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_set_tunnel_interface_ntoh(vapi_msg_ikev2_set_tunnel_interface *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_tunnel_interface'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_set_tunnel_interface_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_set_tunnel_interface_msg_size(vapi_msg_ikev2_set_tunnel_interface *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_set_tunnel_interface_msg_size(vapi_msg_ikev2_set_tunnel_interface *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_set_tunnel_interface) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_tunnel_interface' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_set_tunnel_interface));
      return -1;
    }
  if (vapi_calc_ikev2_set_tunnel_interface_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_tunnel_interface' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_set_tunnel_interface_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_set_tunnel_interface* vapi_alloc_ikev2_set_tunnel_interface(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_set_tunnel_interface *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_set_tunnel_interface);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_set_tunnel_interface*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_set_tunnel_interface);

  return msg;
}

static inline vapi_error_e vapi_ikev2_set_tunnel_interface(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_set_tunnel_interface *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_set_tunnel_interface_reply *reply),
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
  vapi_msg_ikev2_set_tunnel_interface_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_set_tunnel_interface_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_set_tunnel_interface_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_set_tunnel_interface()
{
  static const char name[] = "ikev2_set_tunnel_interface";
  static const char name_with_crc[] = "ikev2_set_tunnel_interface_ca67182c";
  static vapi_message_desc_t __vapi_metadata_ikev2_set_tunnel_interface = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_set_tunnel_interface, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_set_tunnel_interface_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_set_tunnel_interface_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_set_tunnel_interface_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_set_tunnel_interface = vapi_register_msg(&__vapi_metadata_ikev2_set_tunnel_interface);
  VAPI_DBG("Assigned msg id %d to ikev2_set_tunnel_interface", vapi_msg_id_ikev2_set_tunnel_interface);
}
#endif

#ifndef defined_vapi_msg_ikev2_set_responder_reply
#define defined_vapi_msg_ikev2_set_responder_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ikev2_set_responder_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_set_responder_reply payload;
} vapi_msg_ikev2_set_responder_reply;

static inline void vapi_msg_ikev2_set_responder_reply_payload_hton(vapi_payload_ikev2_set_responder_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_set_responder_reply_payload_ntoh(vapi_payload_ikev2_set_responder_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_set_responder_reply_hton(vapi_msg_ikev2_set_responder_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_responder_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_set_responder_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_set_responder_reply_ntoh(vapi_msg_ikev2_set_responder_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_responder_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_set_responder_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_set_responder_reply_msg_size(vapi_msg_ikev2_set_responder_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_set_responder_reply_msg_size(vapi_msg_ikev2_set_responder_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_set_responder_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_responder_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_set_responder_reply));
      return -1;
    }
  if (vapi_calc_ikev2_set_responder_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_responder_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_set_responder_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_set_responder_reply()
{
  static const char name[] = "ikev2_set_responder_reply";
  static const char name_with_crc[] = "ikev2_set_responder_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ikev2_set_responder_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_set_responder_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_set_responder_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_set_responder_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_set_responder_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_set_responder_reply = vapi_register_msg(&__vapi_metadata_ikev2_set_responder_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_set_responder_reply", vapi_msg_id_ikev2_set_responder_reply);
}

static inline void vapi_set_vapi_msg_ikev2_set_responder_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_set_responder_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_set_responder_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_set_responder
#define defined_vapi_msg_ikev2_set_responder
typedef struct __attribute__ ((__packed__)) {
  u8 name[64];
  vapi_type_ikev2_responder responder; 
} vapi_payload_ikev2_set_responder;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_set_responder payload;
} vapi_msg_ikev2_set_responder;

static inline void vapi_msg_ikev2_set_responder_payload_hton(vapi_payload_ikev2_set_responder *payload)
{
  vapi_type_ikev2_responder_hton(&payload->responder);
}

static inline void vapi_msg_ikev2_set_responder_payload_ntoh(vapi_payload_ikev2_set_responder *payload)
{
  vapi_type_ikev2_responder_ntoh(&payload->responder);
}

static inline void vapi_msg_ikev2_set_responder_hton(vapi_msg_ikev2_set_responder *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_responder'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_set_responder_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_set_responder_ntoh(vapi_msg_ikev2_set_responder *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_responder'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_set_responder_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_set_responder_msg_size(vapi_msg_ikev2_set_responder *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_set_responder_msg_size(vapi_msg_ikev2_set_responder *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_set_responder) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_responder' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_set_responder));
      return -1;
    }
  if (vapi_calc_ikev2_set_responder_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_responder' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_set_responder_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_set_responder* vapi_alloc_ikev2_set_responder(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_set_responder *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_set_responder);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_set_responder*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_set_responder);

  return msg;
}

static inline vapi_error_e vapi_ikev2_set_responder(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_set_responder *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_set_responder_reply *reply),
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
  vapi_msg_ikev2_set_responder_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_set_responder_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_set_responder_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_set_responder()
{
  static const char name[] = "ikev2_set_responder";
  static const char name_with_crc[] = "ikev2_set_responder_a2055df1";
  static vapi_message_desc_t __vapi_metadata_ikev2_set_responder = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_set_responder, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_set_responder_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_set_responder_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_set_responder_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_set_responder = vapi_register_msg(&__vapi_metadata_ikev2_set_responder);
  VAPI_DBG("Assigned msg id %d to ikev2_set_responder", vapi_msg_id_ikev2_set_responder);
}
#endif

#ifndef defined_vapi_msg_ikev2_set_responder_hostname_reply
#define defined_vapi_msg_ikev2_set_responder_hostname_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ikev2_set_responder_hostname_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_set_responder_hostname_reply payload;
} vapi_msg_ikev2_set_responder_hostname_reply;

static inline void vapi_msg_ikev2_set_responder_hostname_reply_payload_hton(vapi_payload_ikev2_set_responder_hostname_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_set_responder_hostname_reply_payload_ntoh(vapi_payload_ikev2_set_responder_hostname_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_set_responder_hostname_reply_hton(vapi_msg_ikev2_set_responder_hostname_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_responder_hostname_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_set_responder_hostname_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_set_responder_hostname_reply_ntoh(vapi_msg_ikev2_set_responder_hostname_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_responder_hostname_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_set_responder_hostname_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_set_responder_hostname_reply_msg_size(vapi_msg_ikev2_set_responder_hostname_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_set_responder_hostname_reply_msg_size(vapi_msg_ikev2_set_responder_hostname_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_set_responder_hostname_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_responder_hostname_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_set_responder_hostname_reply));
      return -1;
    }
  if (vapi_calc_ikev2_set_responder_hostname_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_responder_hostname_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_set_responder_hostname_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_set_responder_hostname_reply()
{
  static const char name[] = "ikev2_set_responder_hostname_reply";
  static const char name_with_crc[] = "ikev2_set_responder_hostname_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ikev2_set_responder_hostname_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_set_responder_hostname_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_set_responder_hostname_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_set_responder_hostname_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_set_responder_hostname_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_set_responder_hostname_reply = vapi_register_msg(&__vapi_metadata_ikev2_set_responder_hostname_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_set_responder_hostname_reply", vapi_msg_id_ikev2_set_responder_hostname_reply);
}

static inline void vapi_set_vapi_msg_ikev2_set_responder_hostname_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_set_responder_hostname_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_set_responder_hostname_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_set_responder_hostname
#define defined_vapi_msg_ikev2_set_responder_hostname
typedef struct __attribute__ ((__packed__)) {
  u8 name[64];
  u8 hostname[64];
  vapi_type_interface_index sw_if_index; 
} vapi_payload_ikev2_set_responder_hostname;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_set_responder_hostname payload;
} vapi_msg_ikev2_set_responder_hostname;

static inline void vapi_msg_ikev2_set_responder_hostname_payload_hton(vapi_payload_ikev2_set_responder_hostname *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ikev2_set_responder_hostname_payload_ntoh(vapi_payload_ikev2_set_responder_hostname *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ikev2_set_responder_hostname_hton(vapi_msg_ikev2_set_responder_hostname *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_responder_hostname'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_set_responder_hostname_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_set_responder_hostname_ntoh(vapi_msg_ikev2_set_responder_hostname *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_responder_hostname'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_set_responder_hostname_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_set_responder_hostname_msg_size(vapi_msg_ikev2_set_responder_hostname *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_set_responder_hostname_msg_size(vapi_msg_ikev2_set_responder_hostname *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_set_responder_hostname) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_responder_hostname' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_set_responder_hostname));
      return -1;
    }
  if (vapi_calc_ikev2_set_responder_hostname_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_responder_hostname' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_set_responder_hostname_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_set_responder_hostname* vapi_alloc_ikev2_set_responder_hostname(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_set_responder_hostname *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_set_responder_hostname);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_set_responder_hostname*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_set_responder_hostname);

  return msg;
}

static inline vapi_error_e vapi_ikev2_set_responder_hostname(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_set_responder_hostname *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_set_responder_hostname_reply *reply),
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
  vapi_msg_ikev2_set_responder_hostname_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_set_responder_hostname_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_set_responder_hostname_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_set_responder_hostname()
{
  static const char name[] = "ikev2_set_responder_hostname";
  static const char name_with_crc[] = "ikev2_set_responder_hostname_350d6949";
  static vapi_message_desc_t __vapi_metadata_ikev2_set_responder_hostname = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_set_responder_hostname, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_set_responder_hostname_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_set_responder_hostname_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_set_responder_hostname_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_set_responder_hostname = vapi_register_msg(&__vapi_metadata_ikev2_set_responder_hostname);
  VAPI_DBG("Assigned msg id %d to ikev2_set_responder_hostname", vapi_msg_id_ikev2_set_responder_hostname);
}
#endif

#ifndef defined_vapi_msg_ikev2_set_ike_transforms_reply
#define defined_vapi_msg_ikev2_set_ike_transforms_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ikev2_set_ike_transforms_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_set_ike_transforms_reply payload;
} vapi_msg_ikev2_set_ike_transforms_reply;

static inline void vapi_msg_ikev2_set_ike_transforms_reply_payload_hton(vapi_payload_ikev2_set_ike_transforms_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_set_ike_transforms_reply_payload_ntoh(vapi_payload_ikev2_set_ike_transforms_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_set_ike_transforms_reply_hton(vapi_msg_ikev2_set_ike_transforms_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_ike_transforms_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_set_ike_transforms_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_set_ike_transforms_reply_ntoh(vapi_msg_ikev2_set_ike_transforms_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_ike_transforms_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_set_ike_transforms_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_set_ike_transforms_reply_msg_size(vapi_msg_ikev2_set_ike_transforms_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_set_ike_transforms_reply_msg_size(vapi_msg_ikev2_set_ike_transforms_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_set_ike_transforms_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_ike_transforms_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_set_ike_transforms_reply));
      return -1;
    }
  if (vapi_calc_ikev2_set_ike_transforms_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_ike_transforms_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_set_ike_transforms_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_set_ike_transforms_reply()
{
  static const char name[] = "ikev2_set_ike_transforms_reply";
  static const char name_with_crc[] = "ikev2_set_ike_transforms_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ikev2_set_ike_transforms_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_set_ike_transforms_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_set_ike_transforms_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_set_ike_transforms_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_set_ike_transforms_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_set_ike_transforms_reply = vapi_register_msg(&__vapi_metadata_ikev2_set_ike_transforms_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_set_ike_transforms_reply", vapi_msg_id_ikev2_set_ike_transforms_reply);
}

static inline void vapi_set_vapi_msg_ikev2_set_ike_transforms_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_set_ike_transforms_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_set_ike_transforms_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_set_ike_transforms
#define defined_vapi_msg_ikev2_set_ike_transforms
typedef struct __attribute__ ((__packed__)) {
  u8 name[64];
  vapi_type_ikev2_ike_transforms tr; 
} vapi_payload_ikev2_set_ike_transforms;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_set_ike_transforms payload;
} vapi_msg_ikev2_set_ike_transforms;

static inline void vapi_msg_ikev2_set_ike_transforms_payload_hton(vapi_payload_ikev2_set_ike_transforms *payload)
{
  vapi_type_ikev2_ike_transforms_hton(&payload->tr);
}

static inline void vapi_msg_ikev2_set_ike_transforms_payload_ntoh(vapi_payload_ikev2_set_ike_transforms *payload)
{
  vapi_type_ikev2_ike_transforms_ntoh(&payload->tr);
}

static inline void vapi_msg_ikev2_set_ike_transforms_hton(vapi_msg_ikev2_set_ike_transforms *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_ike_transforms'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_set_ike_transforms_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_set_ike_transforms_ntoh(vapi_msg_ikev2_set_ike_transforms *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_ike_transforms'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_set_ike_transforms_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_set_ike_transforms_msg_size(vapi_msg_ikev2_set_ike_transforms *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_set_ike_transforms_msg_size(vapi_msg_ikev2_set_ike_transforms *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_set_ike_transforms) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_ike_transforms' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_set_ike_transforms));
      return -1;
    }
  if (vapi_calc_ikev2_set_ike_transforms_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_ike_transforms' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_set_ike_transforms_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_set_ike_transforms* vapi_alloc_ikev2_set_ike_transforms(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_set_ike_transforms *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_set_ike_transforms);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_set_ike_transforms*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_set_ike_transforms);

  return msg;
}

static inline vapi_error_e vapi_ikev2_set_ike_transforms(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_set_ike_transforms *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_set_ike_transforms_reply *reply),
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
  vapi_msg_ikev2_set_ike_transforms_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_set_ike_transforms_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_set_ike_transforms_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_set_ike_transforms()
{
  static const char name[] = "ikev2_set_ike_transforms";
  static const char name_with_crc[] = "ikev2_set_ike_transforms_076d7378";
  static vapi_message_desc_t __vapi_metadata_ikev2_set_ike_transforms = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_set_ike_transforms, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_set_ike_transforms_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_set_ike_transforms_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_set_ike_transforms_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_set_ike_transforms = vapi_register_msg(&__vapi_metadata_ikev2_set_ike_transforms);
  VAPI_DBG("Assigned msg id %d to ikev2_set_ike_transforms", vapi_msg_id_ikev2_set_ike_transforms);
}
#endif

#ifndef defined_vapi_msg_ikev2_set_esp_transforms_reply
#define defined_vapi_msg_ikev2_set_esp_transforms_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ikev2_set_esp_transforms_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_set_esp_transforms_reply payload;
} vapi_msg_ikev2_set_esp_transforms_reply;

static inline void vapi_msg_ikev2_set_esp_transforms_reply_payload_hton(vapi_payload_ikev2_set_esp_transforms_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_set_esp_transforms_reply_payload_ntoh(vapi_payload_ikev2_set_esp_transforms_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_set_esp_transforms_reply_hton(vapi_msg_ikev2_set_esp_transforms_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_esp_transforms_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_set_esp_transforms_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_set_esp_transforms_reply_ntoh(vapi_msg_ikev2_set_esp_transforms_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_esp_transforms_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_set_esp_transforms_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_set_esp_transforms_reply_msg_size(vapi_msg_ikev2_set_esp_transforms_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_set_esp_transforms_reply_msg_size(vapi_msg_ikev2_set_esp_transforms_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_set_esp_transforms_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_esp_transforms_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_set_esp_transforms_reply));
      return -1;
    }
  if (vapi_calc_ikev2_set_esp_transforms_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_esp_transforms_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_set_esp_transforms_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_set_esp_transforms_reply()
{
  static const char name[] = "ikev2_set_esp_transforms_reply";
  static const char name_with_crc[] = "ikev2_set_esp_transforms_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ikev2_set_esp_transforms_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_set_esp_transforms_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_set_esp_transforms_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_set_esp_transforms_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_set_esp_transforms_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_set_esp_transforms_reply = vapi_register_msg(&__vapi_metadata_ikev2_set_esp_transforms_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_set_esp_transforms_reply", vapi_msg_id_ikev2_set_esp_transforms_reply);
}

static inline void vapi_set_vapi_msg_ikev2_set_esp_transforms_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_set_esp_transforms_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_set_esp_transforms_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_set_esp_transforms
#define defined_vapi_msg_ikev2_set_esp_transforms
typedef struct __attribute__ ((__packed__)) {
  u8 name[64];
  vapi_type_ikev2_esp_transforms tr; 
} vapi_payload_ikev2_set_esp_transforms;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_set_esp_transforms payload;
} vapi_msg_ikev2_set_esp_transforms;

static inline void vapi_msg_ikev2_set_esp_transforms_payload_hton(vapi_payload_ikev2_set_esp_transforms *payload)
{
  vapi_type_ikev2_esp_transforms_hton(&payload->tr);
}

static inline void vapi_msg_ikev2_set_esp_transforms_payload_ntoh(vapi_payload_ikev2_set_esp_transforms *payload)
{
  vapi_type_ikev2_esp_transforms_ntoh(&payload->tr);
}

static inline void vapi_msg_ikev2_set_esp_transforms_hton(vapi_msg_ikev2_set_esp_transforms *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_esp_transforms'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_set_esp_transforms_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_set_esp_transforms_ntoh(vapi_msg_ikev2_set_esp_transforms *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_esp_transforms'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_set_esp_transforms_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_set_esp_transforms_msg_size(vapi_msg_ikev2_set_esp_transforms *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_set_esp_transforms_msg_size(vapi_msg_ikev2_set_esp_transforms *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_set_esp_transforms) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_esp_transforms' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_set_esp_transforms));
      return -1;
    }
  if (vapi_calc_ikev2_set_esp_transforms_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_esp_transforms' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_set_esp_transforms_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_set_esp_transforms* vapi_alloc_ikev2_set_esp_transforms(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_set_esp_transforms *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_set_esp_transforms);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_set_esp_transforms*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_set_esp_transforms);

  return msg;
}

static inline vapi_error_e vapi_ikev2_set_esp_transforms(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_set_esp_transforms *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_set_esp_transforms_reply *reply),
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
  vapi_msg_ikev2_set_esp_transforms_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_set_esp_transforms_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_set_esp_transforms_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_set_esp_transforms()
{
  static const char name[] = "ikev2_set_esp_transforms";
  static const char name_with_crc[] = "ikev2_set_esp_transforms_a63dc205";
  static vapi_message_desc_t __vapi_metadata_ikev2_set_esp_transforms = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_set_esp_transforms, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_set_esp_transforms_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_set_esp_transforms_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_set_esp_transforms_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_set_esp_transforms = vapi_register_msg(&__vapi_metadata_ikev2_set_esp_transforms);
  VAPI_DBG("Assigned msg id %d to ikev2_set_esp_transforms", vapi_msg_id_ikev2_set_esp_transforms);
}
#endif

#ifndef defined_vapi_msg_ikev2_set_sa_lifetime_reply
#define defined_vapi_msg_ikev2_set_sa_lifetime_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ikev2_set_sa_lifetime_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_set_sa_lifetime_reply payload;
} vapi_msg_ikev2_set_sa_lifetime_reply;

static inline void vapi_msg_ikev2_set_sa_lifetime_reply_payload_hton(vapi_payload_ikev2_set_sa_lifetime_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_set_sa_lifetime_reply_payload_ntoh(vapi_payload_ikev2_set_sa_lifetime_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_set_sa_lifetime_reply_hton(vapi_msg_ikev2_set_sa_lifetime_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_sa_lifetime_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_set_sa_lifetime_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_set_sa_lifetime_reply_ntoh(vapi_msg_ikev2_set_sa_lifetime_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_sa_lifetime_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_set_sa_lifetime_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_set_sa_lifetime_reply_msg_size(vapi_msg_ikev2_set_sa_lifetime_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_set_sa_lifetime_reply_msg_size(vapi_msg_ikev2_set_sa_lifetime_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_set_sa_lifetime_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_sa_lifetime_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_set_sa_lifetime_reply));
      return -1;
    }
  if (vapi_calc_ikev2_set_sa_lifetime_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_sa_lifetime_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_set_sa_lifetime_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_set_sa_lifetime_reply()
{
  static const char name[] = "ikev2_set_sa_lifetime_reply";
  static const char name_with_crc[] = "ikev2_set_sa_lifetime_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ikev2_set_sa_lifetime_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_set_sa_lifetime_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_set_sa_lifetime_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_set_sa_lifetime_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_set_sa_lifetime_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_set_sa_lifetime_reply = vapi_register_msg(&__vapi_metadata_ikev2_set_sa_lifetime_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_set_sa_lifetime_reply", vapi_msg_id_ikev2_set_sa_lifetime_reply);
}

static inline void vapi_set_vapi_msg_ikev2_set_sa_lifetime_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_set_sa_lifetime_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_set_sa_lifetime_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_set_sa_lifetime
#define defined_vapi_msg_ikev2_set_sa_lifetime
typedef struct __attribute__ ((__packed__)) {
  u8 name[64];
  u64 lifetime;
  u32 lifetime_jitter;
  u32 handover;
  u64 lifetime_maxdata; 
} vapi_payload_ikev2_set_sa_lifetime;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_set_sa_lifetime payload;
} vapi_msg_ikev2_set_sa_lifetime;

static inline void vapi_msg_ikev2_set_sa_lifetime_payload_hton(vapi_payload_ikev2_set_sa_lifetime *payload)
{
  payload->lifetime = htobe64(payload->lifetime);
  payload->lifetime_jitter = htobe32(payload->lifetime_jitter);
  payload->handover = htobe32(payload->handover);
  payload->lifetime_maxdata = htobe64(payload->lifetime_maxdata);
}

static inline void vapi_msg_ikev2_set_sa_lifetime_payload_ntoh(vapi_payload_ikev2_set_sa_lifetime *payload)
{
  payload->lifetime = be64toh(payload->lifetime);
  payload->lifetime_jitter = be32toh(payload->lifetime_jitter);
  payload->handover = be32toh(payload->handover);
  payload->lifetime_maxdata = be64toh(payload->lifetime_maxdata);
}

static inline void vapi_msg_ikev2_set_sa_lifetime_hton(vapi_msg_ikev2_set_sa_lifetime *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_sa_lifetime'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_set_sa_lifetime_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_set_sa_lifetime_ntoh(vapi_msg_ikev2_set_sa_lifetime *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_set_sa_lifetime'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_set_sa_lifetime_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_set_sa_lifetime_msg_size(vapi_msg_ikev2_set_sa_lifetime *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_set_sa_lifetime_msg_size(vapi_msg_ikev2_set_sa_lifetime *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_set_sa_lifetime) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_sa_lifetime' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_set_sa_lifetime));
      return -1;
    }
  if (vapi_calc_ikev2_set_sa_lifetime_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_set_sa_lifetime' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_set_sa_lifetime_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_set_sa_lifetime* vapi_alloc_ikev2_set_sa_lifetime(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_set_sa_lifetime *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_set_sa_lifetime);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_set_sa_lifetime*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_set_sa_lifetime);

  return msg;
}

static inline vapi_error_e vapi_ikev2_set_sa_lifetime(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_set_sa_lifetime *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_set_sa_lifetime_reply *reply),
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
  vapi_msg_ikev2_set_sa_lifetime_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_set_sa_lifetime_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_set_sa_lifetime_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_set_sa_lifetime()
{
  static const char name[] = "ikev2_set_sa_lifetime";
  static const char name_with_crc[] = "ikev2_set_sa_lifetime_7039feaa";
  static vapi_message_desc_t __vapi_metadata_ikev2_set_sa_lifetime = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_set_sa_lifetime, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_set_sa_lifetime_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_set_sa_lifetime_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_set_sa_lifetime_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_set_sa_lifetime = vapi_register_msg(&__vapi_metadata_ikev2_set_sa_lifetime);
  VAPI_DBG("Assigned msg id %d to ikev2_set_sa_lifetime", vapi_msg_id_ikev2_set_sa_lifetime);
}
#endif

#ifndef defined_vapi_msg_ikev2_initiate_sa_init_reply
#define defined_vapi_msg_ikev2_initiate_sa_init_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ikev2_initiate_sa_init_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_initiate_sa_init_reply payload;
} vapi_msg_ikev2_initiate_sa_init_reply;

static inline void vapi_msg_ikev2_initiate_sa_init_reply_payload_hton(vapi_payload_ikev2_initiate_sa_init_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_initiate_sa_init_reply_payload_ntoh(vapi_payload_ikev2_initiate_sa_init_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_initiate_sa_init_reply_hton(vapi_msg_ikev2_initiate_sa_init_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_initiate_sa_init_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_initiate_sa_init_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_initiate_sa_init_reply_ntoh(vapi_msg_ikev2_initiate_sa_init_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_initiate_sa_init_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_initiate_sa_init_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_initiate_sa_init_reply_msg_size(vapi_msg_ikev2_initiate_sa_init_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_initiate_sa_init_reply_msg_size(vapi_msg_ikev2_initiate_sa_init_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_initiate_sa_init_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_initiate_sa_init_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_initiate_sa_init_reply));
      return -1;
    }
  if (vapi_calc_ikev2_initiate_sa_init_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_initiate_sa_init_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_initiate_sa_init_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_initiate_sa_init_reply()
{
  static const char name[] = "ikev2_initiate_sa_init_reply";
  static const char name_with_crc[] = "ikev2_initiate_sa_init_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ikev2_initiate_sa_init_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_initiate_sa_init_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_initiate_sa_init_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_initiate_sa_init_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_initiate_sa_init_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_initiate_sa_init_reply = vapi_register_msg(&__vapi_metadata_ikev2_initiate_sa_init_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_initiate_sa_init_reply", vapi_msg_id_ikev2_initiate_sa_init_reply);
}

static inline void vapi_set_vapi_msg_ikev2_initiate_sa_init_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_initiate_sa_init_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_initiate_sa_init_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_initiate_sa_init
#define defined_vapi_msg_ikev2_initiate_sa_init
typedef struct __attribute__ ((__packed__)) {
  u8 name[64]; 
} vapi_payload_ikev2_initiate_sa_init;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_initiate_sa_init payload;
} vapi_msg_ikev2_initiate_sa_init;

static inline void vapi_msg_ikev2_initiate_sa_init_payload_hton(vapi_payload_ikev2_initiate_sa_init *payload)
{

}

static inline void vapi_msg_ikev2_initiate_sa_init_payload_ntoh(vapi_payload_ikev2_initiate_sa_init *payload)
{

}

static inline void vapi_msg_ikev2_initiate_sa_init_hton(vapi_msg_ikev2_initiate_sa_init *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_initiate_sa_init'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_initiate_sa_init_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_initiate_sa_init_ntoh(vapi_msg_ikev2_initiate_sa_init *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_initiate_sa_init'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_initiate_sa_init_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_initiate_sa_init_msg_size(vapi_msg_ikev2_initiate_sa_init *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_initiate_sa_init_msg_size(vapi_msg_ikev2_initiate_sa_init *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_initiate_sa_init) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_initiate_sa_init' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_initiate_sa_init));
      return -1;
    }
  if (vapi_calc_ikev2_initiate_sa_init_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_initiate_sa_init' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_initiate_sa_init_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_initiate_sa_init* vapi_alloc_ikev2_initiate_sa_init(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_initiate_sa_init *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_initiate_sa_init);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_initiate_sa_init*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_initiate_sa_init);

  return msg;
}

static inline vapi_error_e vapi_ikev2_initiate_sa_init(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_initiate_sa_init *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_initiate_sa_init_reply *reply),
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
  vapi_msg_ikev2_initiate_sa_init_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_initiate_sa_init_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_initiate_sa_init_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_initiate_sa_init()
{
  static const char name[] = "ikev2_initiate_sa_init";
  static const char name_with_crc[] = "ikev2_initiate_sa_init_ebf79a66";
  static vapi_message_desc_t __vapi_metadata_ikev2_initiate_sa_init = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_initiate_sa_init, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_initiate_sa_init_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_initiate_sa_init_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_initiate_sa_init_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_initiate_sa_init = vapi_register_msg(&__vapi_metadata_ikev2_initiate_sa_init);
  VAPI_DBG("Assigned msg id %d to ikev2_initiate_sa_init", vapi_msg_id_ikev2_initiate_sa_init);
}
#endif

#ifndef defined_vapi_msg_ikev2_initiate_del_ike_sa_reply
#define defined_vapi_msg_ikev2_initiate_del_ike_sa_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ikev2_initiate_del_ike_sa_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_initiate_del_ike_sa_reply payload;
} vapi_msg_ikev2_initiate_del_ike_sa_reply;

static inline void vapi_msg_ikev2_initiate_del_ike_sa_reply_payload_hton(vapi_payload_ikev2_initiate_del_ike_sa_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_initiate_del_ike_sa_reply_payload_ntoh(vapi_payload_ikev2_initiate_del_ike_sa_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_initiate_del_ike_sa_reply_hton(vapi_msg_ikev2_initiate_del_ike_sa_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_initiate_del_ike_sa_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_initiate_del_ike_sa_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_initiate_del_ike_sa_reply_ntoh(vapi_msg_ikev2_initiate_del_ike_sa_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_initiate_del_ike_sa_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_initiate_del_ike_sa_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_initiate_del_ike_sa_reply_msg_size(vapi_msg_ikev2_initiate_del_ike_sa_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_initiate_del_ike_sa_reply_msg_size(vapi_msg_ikev2_initiate_del_ike_sa_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_initiate_del_ike_sa_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_initiate_del_ike_sa_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_initiate_del_ike_sa_reply));
      return -1;
    }
  if (vapi_calc_ikev2_initiate_del_ike_sa_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_initiate_del_ike_sa_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_initiate_del_ike_sa_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_initiate_del_ike_sa_reply()
{
  static const char name[] = "ikev2_initiate_del_ike_sa_reply";
  static const char name_with_crc[] = "ikev2_initiate_del_ike_sa_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ikev2_initiate_del_ike_sa_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_initiate_del_ike_sa_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_initiate_del_ike_sa_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_initiate_del_ike_sa_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_initiate_del_ike_sa_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_initiate_del_ike_sa_reply = vapi_register_msg(&__vapi_metadata_ikev2_initiate_del_ike_sa_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_initiate_del_ike_sa_reply", vapi_msg_id_ikev2_initiate_del_ike_sa_reply);
}

static inline void vapi_set_vapi_msg_ikev2_initiate_del_ike_sa_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_initiate_del_ike_sa_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_initiate_del_ike_sa_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_initiate_del_ike_sa
#define defined_vapi_msg_ikev2_initiate_del_ike_sa
typedef struct __attribute__ ((__packed__)) {
  u64 ispi; 
} vapi_payload_ikev2_initiate_del_ike_sa;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_initiate_del_ike_sa payload;
} vapi_msg_ikev2_initiate_del_ike_sa;

static inline void vapi_msg_ikev2_initiate_del_ike_sa_payload_hton(vapi_payload_ikev2_initiate_del_ike_sa *payload)
{
  payload->ispi = htobe64(payload->ispi);
}

static inline void vapi_msg_ikev2_initiate_del_ike_sa_payload_ntoh(vapi_payload_ikev2_initiate_del_ike_sa *payload)
{
  payload->ispi = be64toh(payload->ispi);
}

static inline void vapi_msg_ikev2_initiate_del_ike_sa_hton(vapi_msg_ikev2_initiate_del_ike_sa *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_initiate_del_ike_sa'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_initiate_del_ike_sa_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_initiate_del_ike_sa_ntoh(vapi_msg_ikev2_initiate_del_ike_sa *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_initiate_del_ike_sa'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_initiate_del_ike_sa_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_initiate_del_ike_sa_msg_size(vapi_msg_ikev2_initiate_del_ike_sa *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_initiate_del_ike_sa_msg_size(vapi_msg_ikev2_initiate_del_ike_sa *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_initiate_del_ike_sa) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_initiate_del_ike_sa' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_initiate_del_ike_sa));
      return -1;
    }
  if (vapi_calc_ikev2_initiate_del_ike_sa_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_initiate_del_ike_sa' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_initiate_del_ike_sa_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_initiate_del_ike_sa* vapi_alloc_ikev2_initiate_del_ike_sa(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_initiate_del_ike_sa *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_initiate_del_ike_sa);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_initiate_del_ike_sa*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_initiate_del_ike_sa);

  return msg;
}

static inline vapi_error_e vapi_ikev2_initiate_del_ike_sa(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_initiate_del_ike_sa *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_initiate_del_ike_sa_reply *reply),
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
  vapi_msg_ikev2_initiate_del_ike_sa_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_initiate_del_ike_sa_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_initiate_del_ike_sa_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_initiate_del_ike_sa()
{
  static const char name[] = "ikev2_initiate_del_ike_sa";
  static const char name_with_crc[] = "ikev2_initiate_del_ike_sa_8d125bdd";
  static vapi_message_desc_t __vapi_metadata_ikev2_initiate_del_ike_sa = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_initiate_del_ike_sa, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_initiate_del_ike_sa_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_initiate_del_ike_sa_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_initiate_del_ike_sa_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_initiate_del_ike_sa = vapi_register_msg(&__vapi_metadata_ikev2_initiate_del_ike_sa);
  VAPI_DBG("Assigned msg id %d to ikev2_initiate_del_ike_sa", vapi_msg_id_ikev2_initiate_del_ike_sa);
}
#endif

#ifndef defined_vapi_msg_ikev2_initiate_del_child_sa_reply
#define defined_vapi_msg_ikev2_initiate_del_child_sa_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ikev2_initiate_del_child_sa_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_initiate_del_child_sa_reply payload;
} vapi_msg_ikev2_initiate_del_child_sa_reply;

static inline void vapi_msg_ikev2_initiate_del_child_sa_reply_payload_hton(vapi_payload_ikev2_initiate_del_child_sa_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_initiate_del_child_sa_reply_payload_ntoh(vapi_payload_ikev2_initiate_del_child_sa_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_initiate_del_child_sa_reply_hton(vapi_msg_ikev2_initiate_del_child_sa_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_initiate_del_child_sa_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_initiate_del_child_sa_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_initiate_del_child_sa_reply_ntoh(vapi_msg_ikev2_initiate_del_child_sa_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_initiate_del_child_sa_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_initiate_del_child_sa_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_initiate_del_child_sa_reply_msg_size(vapi_msg_ikev2_initiate_del_child_sa_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_initiate_del_child_sa_reply_msg_size(vapi_msg_ikev2_initiate_del_child_sa_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_initiate_del_child_sa_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_initiate_del_child_sa_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_initiate_del_child_sa_reply));
      return -1;
    }
  if (vapi_calc_ikev2_initiate_del_child_sa_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_initiate_del_child_sa_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_initiate_del_child_sa_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_initiate_del_child_sa_reply()
{
  static const char name[] = "ikev2_initiate_del_child_sa_reply";
  static const char name_with_crc[] = "ikev2_initiate_del_child_sa_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ikev2_initiate_del_child_sa_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_initiate_del_child_sa_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_initiate_del_child_sa_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_initiate_del_child_sa_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_initiate_del_child_sa_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_initiate_del_child_sa_reply = vapi_register_msg(&__vapi_metadata_ikev2_initiate_del_child_sa_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_initiate_del_child_sa_reply", vapi_msg_id_ikev2_initiate_del_child_sa_reply);
}

static inline void vapi_set_vapi_msg_ikev2_initiate_del_child_sa_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_initiate_del_child_sa_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_initiate_del_child_sa_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_initiate_del_child_sa
#define defined_vapi_msg_ikev2_initiate_del_child_sa
typedef struct __attribute__ ((__packed__)) {
  u32 ispi; 
} vapi_payload_ikev2_initiate_del_child_sa;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_initiate_del_child_sa payload;
} vapi_msg_ikev2_initiate_del_child_sa;

static inline void vapi_msg_ikev2_initiate_del_child_sa_payload_hton(vapi_payload_ikev2_initiate_del_child_sa *payload)
{
  payload->ispi = htobe32(payload->ispi);
}

static inline void vapi_msg_ikev2_initiate_del_child_sa_payload_ntoh(vapi_payload_ikev2_initiate_del_child_sa *payload)
{
  payload->ispi = be32toh(payload->ispi);
}

static inline void vapi_msg_ikev2_initiate_del_child_sa_hton(vapi_msg_ikev2_initiate_del_child_sa *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_initiate_del_child_sa'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_initiate_del_child_sa_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_initiate_del_child_sa_ntoh(vapi_msg_ikev2_initiate_del_child_sa *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_initiate_del_child_sa'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_initiate_del_child_sa_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_initiate_del_child_sa_msg_size(vapi_msg_ikev2_initiate_del_child_sa *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_initiate_del_child_sa_msg_size(vapi_msg_ikev2_initiate_del_child_sa *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_initiate_del_child_sa) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_initiate_del_child_sa' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_initiate_del_child_sa));
      return -1;
    }
  if (vapi_calc_ikev2_initiate_del_child_sa_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_initiate_del_child_sa' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_initiate_del_child_sa_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_initiate_del_child_sa* vapi_alloc_ikev2_initiate_del_child_sa(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_initiate_del_child_sa *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_initiate_del_child_sa);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_initiate_del_child_sa*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_initiate_del_child_sa);

  return msg;
}

static inline vapi_error_e vapi_ikev2_initiate_del_child_sa(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_initiate_del_child_sa *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_initiate_del_child_sa_reply *reply),
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
  vapi_msg_ikev2_initiate_del_child_sa_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_initiate_del_child_sa_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_initiate_del_child_sa_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_initiate_del_child_sa()
{
  static const char name[] = "ikev2_initiate_del_child_sa";
  static const char name_with_crc[] = "ikev2_initiate_del_child_sa_7f004d2e";
  static vapi_message_desc_t __vapi_metadata_ikev2_initiate_del_child_sa = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_initiate_del_child_sa, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_initiate_del_child_sa_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_initiate_del_child_sa_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_initiate_del_child_sa_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_initiate_del_child_sa = vapi_register_msg(&__vapi_metadata_ikev2_initiate_del_child_sa);
  VAPI_DBG("Assigned msg id %d to ikev2_initiate_del_child_sa", vapi_msg_id_ikev2_initiate_del_child_sa);
}
#endif

#ifndef defined_vapi_msg_ikev2_initiate_rekey_child_sa_reply
#define defined_vapi_msg_ikev2_initiate_rekey_child_sa_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ikev2_initiate_rekey_child_sa_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_initiate_rekey_child_sa_reply payload;
} vapi_msg_ikev2_initiate_rekey_child_sa_reply;

static inline void vapi_msg_ikev2_initiate_rekey_child_sa_reply_payload_hton(vapi_payload_ikev2_initiate_rekey_child_sa_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_initiate_rekey_child_sa_reply_payload_ntoh(vapi_payload_ikev2_initiate_rekey_child_sa_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_initiate_rekey_child_sa_reply_hton(vapi_msg_ikev2_initiate_rekey_child_sa_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_initiate_rekey_child_sa_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_initiate_rekey_child_sa_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_initiate_rekey_child_sa_reply_ntoh(vapi_msg_ikev2_initiate_rekey_child_sa_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_initiate_rekey_child_sa_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_initiate_rekey_child_sa_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_initiate_rekey_child_sa_reply_msg_size(vapi_msg_ikev2_initiate_rekey_child_sa_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_initiate_rekey_child_sa_reply_msg_size(vapi_msg_ikev2_initiate_rekey_child_sa_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_initiate_rekey_child_sa_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_initiate_rekey_child_sa_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_initiate_rekey_child_sa_reply));
      return -1;
    }
  if (vapi_calc_ikev2_initiate_rekey_child_sa_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_initiate_rekey_child_sa_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_initiate_rekey_child_sa_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_initiate_rekey_child_sa_reply()
{
  static const char name[] = "ikev2_initiate_rekey_child_sa_reply";
  static const char name_with_crc[] = "ikev2_initiate_rekey_child_sa_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ikev2_initiate_rekey_child_sa_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_initiate_rekey_child_sa_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_initiate_rekey_child_sa_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_initiate_rekey_child_sa_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_initiate_rekey_child_sa_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_initiate_rekey_child_sa_reply = vapi_register_msg(&__vapi_metadata_ikev2_initiate_rekey_child_sa_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_initiate_rekey_child_sa_reply", vapi_msg_id_ikev2_initiate_rekey_child_sa_reply);
}

static inline void vapi_set_vapi_msg_ikev2_initiate_rekey_child_sa_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_initiate_rekey_child_sa_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_initiate_rekey_child_sa_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_initiate_rekey_child_sa
#define defined_vapi_msg_ikev2_initiate_rekey_child_sa
typedef struct __attribute__ ((__packed__)) {
  u32 ispi; 
} vapi_payload_ikev2_initiate_rekey_child_sa;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_initiate_rekey_child_sa payload;
} vapi_msg_ikev2_initiate_rekey_child_sa;

static inline void vapi_msg_ikev2_initiate_rekey_child_sa_payload_hton(vapi_payload_ikev2_initiate_rekey_child_sa *payload)
{
  payload->ispi = htobe32(payload->ispi);
}

static inline void vapi_msg_ikev2_initiate_rekey_child_sa_payload_ntoh(vapi_payload_ikev2_initiate_rekey_child_sa *payload)
{
  payload->ispi = be32toh(payload->ispi);
}

static inline void vapi_msg_ikev2_initiate_rekey_child_sa_hton(vapi_msg_ikev2_initiate_rekey_child_sa *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_initiate_rekey_child_sa'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_initiate_rekey_child_sa_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_initiate_rekey_child_sa_ntoh(vapi_msg_ikev2_initiate_rekey_child_sa *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_initiate_rekey_child_sa'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_initiate_rekey_child_sa_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_initiate_rekey_child_sa_msg_size(vapi_msg_ikev2_initiate_rekey_child_sa *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_initiate_rekey_child_sa_msg_size(vapi_msg_ikev2_initiate_rekey_child_sa *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_initiate_rekey_child_sa) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_initiate_rekey_child_sa' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_initiate_rekey_child_sa));
      return -1;
    }
  if (vapi_calc_ikev2_initiate_rekey_child_sa_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_initiate_rekey_child_sa' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_initiate_rekey_child_sa_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_initiate_rekey_child_sa* vapi_alloc_ikev2_initiate_rekey_child_sa(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_initiate_rekey_child_sa *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_initiate_rekey_child_sa);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_initiate_rekey_child_sa*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_initiate_rekey_child_sa);

  return msg;
}

static inline vapi_error_e vapi_ikev2_initiate_rekey_child_sa(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_initiate_rekey_child_sa *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_initiate_rekey_child_sa_reply *reply),
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
  vapi_msg_ikev2_initiate_rekey_child_sa_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_initiate_rekey_child_sa_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_initiate_rekey_child_sa_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_initiate_rekey_child_sa()
{
  static const char name[] = "ikev2_initiate_rekey_child_sa";
  static const char name_with_crc[] = "ikev2_initiate_rekey_child_sa_7f004d2e";
  static vapi_message_desc_t __vapi_metadata_ikev2_initiate_rekey_child_sa = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_initiate_rekey_child_sa, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_initiate_rekey_child_sa_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_initiate_rekey_child_sa_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_initiate_rekey_child_sa_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_initiate_rekey_child_sa = vapi_register_msg(&__vapi_metadata_ikev2_initiate_rekey_child_sa);
  VAPI_DBG("Assigned msg id %d to ikev2_initiate_rekey_child_sa", vapi_msg_id_ikev2_initiate_rekey_child_sa);
}
#endif

#ifndef defined_vapi_msg_ikev2_profile_set_udp_encap_reply
#define defined_vapi_msg_ikev2_profile_set_udp_encap_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ikev2_profile_set_udp_encap_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_profile_set_udp_encap_reply payload;
} vapi_msg_ikev2_profile_set_udp_encap_reply;

static inline void vapi_msg_ikev2_profile_set_udp_encap_reply_payload_hton(vapi_payload_ikev2_profile_set_udp_encap_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_profile_set_udp_encap_reply_payload_ntoh(vapi_payload_ikev2_profile_set_udp_encap_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_profile_set_udp_encap_reply_hton(vapi_msg_ikev2_profile_set_udp_encap_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_udp_encap_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_profile_set_udp_encap_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_profile_set_udp_encap_reply_ntoh(vapi_msg_ikev2_profile_set_udp_encap_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_udp_encap_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_profile_set_udp_encap_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_profile_set_udp_encap_reply_msg_size(vapi_msg_ikev2_profile_set_udp_encap_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_profile_set_udp_encap_reply_msg_size(vapi_msg_ikev2_profile_set_udp_encap_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_profile_set_udp_encap_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_udp_encap_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_profile_set_udp_encap_reply));
      return -1;
    }
  if (vapi_calc_ikev2_profile_set_udp_encap_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_udp_encap_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_profile_set_udp_encap_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_profile_set_udp_encap_reply()
{
  static const char name[] = "ikev2_profile_set_udp_encap_reply";
  static const char name_with_crc[] = "ikev2_profile_set_udp_encap_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ikev2_profile_set_udp_encap_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_profile_set_udp_encap_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_profile_set_udp_encap_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_udp_encap_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_udp_encap_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_profile_set_udp_encap_reply = vapi_register_msg(&__vapi_metadata_ikev2_profile_set_udp_encap_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_profile_set_udp_encap_reply", vapi_msg_id_ikev2_profile_set_udp_encap_reply);
}

static inline void vapi_set_vapi_msg_ikev2_profile_set_udp_encap_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_profile_set_udp_encap_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_profile_set_udp_encap_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_profile_set_udp_encap
#define defined_vapi_msg_ikev2_profile_set_udp_encap
typedef struct __attribute__ ((__packed__)) {
  u8 name[64]; 
} vapi_payload_ikev2_profile_set_udp_encap;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_profile_set_udp_encap payload;
} vapi_msg_ikev2_profile_set_udp_encap;

static inline void vapi_msg_ikev2_profile_set_udp_encap_payload_hton(vapi_payload_ikev2_profile_set_udp_encap *payload)
{

}

static inline void vapi_msg_ikev2_profile_set_udp_encap_payload_ntoh(vapi_payload_ikev2_profile_set_udp_encap *payload)
{

}

static inline void vapi_msg_ikev2_profile_set_udp_encap_hton(vapi_msg_ikev2_profile_set_udp_encap *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_udp_encap'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_profile_set_udp_encap_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_profile_set_udp_encap_ntoh(vapi_msg_ikev2_profile_set_udp_encap *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_udp_encap'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_profile_set_udp_encap_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_profile_set_udp_encap_msg_size(vapi_msg_ikev2_profile_set_udp_encap *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_profile_set_udp_encap_msg_size(vapi_msg_ikev2_profile_set_udp_encap *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_profile_set_udp_encap) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_udp_encap' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_profile_set_udp_encap));
      return -1;
    }
  if (vapi_calc_ikev2_profile_set_udp_encap_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_udp_encap' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_profile_set_udp_encap_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_profile_set_udp_encap* vapi_alloc_ikev2_profile_set_udp_encap(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_profile_set_udp_encap *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_profile_set_udp_encap);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_profile_set_udp_encap*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_profile_set_udp_encap);

  return msg;
}

static inline vapi_error_e vapi_ikev2_profile_set_udp_encap(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_profile_set_udp_encap *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_profile_set_udp_encap_reply *reply),
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
  vapi_msg_ikev2_profile_set_udp_encap_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_profile_set_udp_encap_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_profile_set_udp_encap_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_profile_set_udp_encap()
{
  static const char name[] = "ikev2_profile_set_udp_encap";
  static const char name_with_crc[] = "ikev2_profile_set_udp_encap_ebf79a66";
  static vapi_message_desc_t __vapi_metadata_ikev2_profile_set_udp_encap = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_profile_set_udp_encap, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_profile_set_udp_encap_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_udp_encap_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_udp_encap_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_profile_set_udp_encap = vapi_register_msg(&__vapi_metadata_ikev2_profile_set_udp_encap);
  VAPI_DBG("Assigned msg id %d to ikev2_profile_set_udp_encap", vapi_msg_id_ikev2_profile_set_udp_encap);
}
#endif

#ifndef defined_vapi_msg_ikev2_profile_set_ipsec_udp_port_reply
#define defined_vapi_msg_ikev2_profile_set_ipsec_udp_port_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ikev2_profile_set_ipsec_udp_port_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_profile_set_ipsec_udp_port_reply payload;
} vapi_msg_ikev2_profile_set_ipsec_udp_port_reply;

static inline void vapi_msg_ikev2_profile_set_ipsec_udp_port_reply_payload_hton(vapi_payload_ikev2_profile_set_ipsec_udp_port_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_profile_set_ipsec_udp_port_reply_payload_ntoh(vapi_payload_ikev2_profile_set_ipsec_udp_port_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_profile_set_ipsec_udp_port_reply_hton(vapi_msg_ikev2_profile_set_ipsec_udp_port_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_ipsec_udp_port_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_profile_set_ipsec_udp_port_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_profile_set_ipsec_udp_port_reply_ntoh(vapi_msg_ikev2_profile_set_ipsec_udp_port_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_ipsec_udp_port_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_profile_set_ipsec_udp_port_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_profile_set_ipsec_udp_port_reply_msg_size(vapi_msg_ikev2_profile_set_ipsec_udp_port_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_profile_set_ipsec_udp_port_reply_msg_size(vapi_msg_ikev2_profile_set_ipsec_udp_port_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_profile_set_ipsec_udp_port_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_ipsec_udp_port_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_profile_set_ipsec_udp_port_reply));
      return -1;
    }
  if (vapi_calc_ikev2_profile_set_ipsec_udp_port_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_ipsec_udp_port_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_profile_set_ipsec_udp_port_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_profile_set_ipsec_udp_port_reply()
{
  static const char name[] = "ikev2_profile_set_ipsec_udp_port_reply";
  static const char name_with_crc[] = "ikev2_profile_set_ipsec_udp_port_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ikev2_profile_set_ipsec_udp_port_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_profile_set_ipsec_udp_port_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_profile_set_ipsec_udp_port_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_ipsec_udp_port_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_ipsec_udp_port_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_profile_set_ipsec_udp_port_reply = vapi_register_msg(&__vapi_metadata_ikev2_profile_set_ipsec_udp_port_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_profile_set_ipsec_udp_port_reply", vapi_msg_id_ikev2_profile_set_ipsec_udp_port_reply);
}

static inline void vapi_set_vapi_msg_ikev2_profile_set_ipsec_udp_port_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_profile_set_ipsec_udp_port_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_profile_set_ipsec_udp_port_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_profile_set_ipsec_udp_port
#define defined_vapi_msg_ikev2_profile_set_ipsec_udp_port
typedef struct __attribute__ ((__packed__)) {
  u8 is_set;
  u16 port;
  u8 name[64]; 
} vapi_payload_ikev2_profile_set_ipsec_udp_port;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_profile_set_ipsec_udp_port payload;
} vapi_msg_ikev2_profile_set_ipsec_udp_port;

static inline void vapi_msg_ikev2_profile_set_ipsec_udp_port_payload_hton(vapi_payload_ikev2_profile_set_ipsec_udp_port *payload)
{
  payload->port = htobe16(payload->port);
}

static inline void vapi_msg_ikev2_profile_set_ipsec_udp_port_payload_ntoh(vapi_payload_ikev2_profile_set_ipsec_udp_port *payload)
{
  payload->port = be16toh(payload->port);
}

static inline void vapi_msg_ikev2_profile_set_ipsec_udp_port_hton(vapi_msg_ikev2_profile_set_ipsec_udp_port *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_ipsec_udp_port'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_profile_set_ipsec_udp_port_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_profile_set_ipsec_udp_port_ntoh(vapi_msg_ikev2_profile_set_ipsec_udp_port *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_ipsec_udp_port'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_profile_set_ipsec_udp_port_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_profile_set_ipsec_udp_port_msg_size(vapi_msg_ikev2_profile_set_ipsec_udp_port *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_profile_set_ipsec_udp_port_msg_size(vapi_msg_ikev2_profile_set_ipsec_udp_port *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_profile_set_ipsec_udp_port) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_ipsec_udp_port' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_profile_set_ipsec_udp_port));
      return -1;
    }
  if (vapi_calc_ikev2_profile_set_ipsec_udp_port_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_ipsec_udp_port' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_profile_set_ipsec_udp_port_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_profile_set_ipsec_udp_port* vapi_alloc_ikev2_profile_set_ipsec_udp_port(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_profile_set_ipsec_udp_port *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_profile_set_ipsec_udp_port);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_profile_set_ipsec_udp_port*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_profile_set_ipsec_udp_port);

  return msg;
}

static inline vapi_error_e vapi_ikev2_profile_set_ipsec_udp_port(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_profile_set_ipsec_udp_port *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_profile_set_ipsec_udp_port_reply *reply),
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
  vapi_msg_ikev2_profile_set_ipsec_udp_port_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_profile_set_ipsec_udp_port_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_profile_set_ipsec_udp_port_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_profile_set_ipsec_udp_port()
{
  static const char name[] = "ikev2_profile_set_ipsec_udp_port";
  static const char name_with_crc[] = "ikev2_profile_set_ipsec_udp_port_615ce758";
  static vapi_message_desc_t __vapi_metadata_ikev2_profile_set_ipsec_udp_port = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_profile_set_ipsec_udp_port, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_profile_set_ipsec_udp_port_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_ipsec_udp_port_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_ipsec_udp_port_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_profile_set_ipsec_udp_port = vapi_register_msg(&__vapi_metadata_ikev2_profile_set_ipsec_udp_port);
  VAPI_DBG("Assigned msg id %d to ikev2_profile_set_ipsec_udp_port", vapi_msg_id_ikev2_profile_set_ipsec_udp_port);
}
#endif

#ifndef defined_vapi_msg_ikev2_profile_set_liveness_reply
#define defined_vapi_msg_ikev2_profile_set_liveness_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ikev2_profile_set_liveness_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ikev2_profile_set_liveness_reply payload;
} vapi_msg_ikev2_profile_set_liveness_reply;

static inline void vapi_msg_ikev2_profile_set_liveness_reply_payload_hton(vapi_payload_ikev2_profile_set_liveness_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ikev2_profile_set_liveness_reply_payload_ntoh(vapi_payload_ikev2_profile_set_liveness_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ikev2_profile_set_liveness_reply_hton(vapi_msg_ikev2_profile_set_liveness_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_liveness_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ikev2_profile_set_liveness_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_profile_set_liveness_reply_ntoh(vapi_msg_ikev2_profile_set_liveness_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_liveness_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ikev2_profile_set_liveness_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_profile_set_liveness_reply_msg_size(vapi_msg_ikev2_profile_set_liveness_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_profile_set_liveness_reply_msg_size(vapi_msg_ikev2_profile_set_liveness_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_profile_set_liveness_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_liveness_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_profile_set_liveness_reply));
      return -1;
    }
  if (vapi_calc_ikev2_profile_set_liveness_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_liveness_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_profile_set_liveness_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ikev2_profile_set_liveness_reply()
{
  static const char name[] = "ikev2_profile_set_liveness_reply";
  static const char name_with_crc[] = "ikev2_profile_set_liveness_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ikev2_profile_set_liveness_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ikev2_profile_set_liveness_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_profile_set_liveness_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_liveness_reply_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_liveness_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_profile_set_liveness_reply = vapi_register_msg(&__vapi_metadata_ikev2_profile_set_liveness_reply);
  VAPI_DBG("Assigned msg id %d to ikev2_profile_set_liveness_reply", vapi_msg_id_ikev2_profile_set_liveness_reply);
}

static inline void vapi_set_vapi_msg_ikev2_profile_set_liveness_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ikev2_profile_set_liveness_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ikev2_profile_set_liveness_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ikev2_profile_set_liveness
#define defined_vapi_msg_ikev2_profile_set_liveness
typedef struct __attribute__ ((__packed__)) {
  u32 period;
  u32 max_retries; 
} vapi_payload_ikev2_profile_set_liveness;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ikev2_profile_set_liveness payload;
} vapi_msg_ikev2_profile_set_liveness;

static inline void vapi_msg_ikev2_profile_set_liveness_payload_hton(vapi_payload_ikev2_profile_set_liveness *payload)
{
  payload->period = htobe32(payload->period);
  payload->max_retries = htobe32(payload->max_retries);
}

static inline void vapi_msg_ikev2_profile_set_liveness_payload_ntoh(vapi_payload_ikev2_profile_set_liveness *payload)
{
  payload->period = be32toh(payload->period);
  payload->max_retries = be32toh(payload->max_retries);
}

static inline void vapi_msg_ikev2_profile_set_liveness_hton(vapi_msg_ikev2_profile_set_liveness *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_liveness'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ikev2_profile_set_liveness_payload_hton(&msg->payload);
}

static inline void vapi_msg_ikev2_profile_set_liveness_ntoh(vapi_msg_ikev2_profile_set_liveness *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ikev2_profile_set_liveness'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ikev2_profile_set_liveness_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ikev2_profile_set_liveness_msg_size(vapi_msg_ikev2_profile_set_liveness *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ikev2_profile_set_liveness_msg_size(vapi_msg_ikev2_profile_set_liveness *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ikev2_profile_set_liveness) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_liveness' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ikev2_profile_set_liveness));
      return -1;
    }
  if (vapi_calc_ikev2_profile_set_liveness_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ikev2_profile_set_liveness' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ikev2_profile_set_liveness_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ikev2_profile_set_liveness* vapi_alloc_ikev2_profile_set_liveness(struct vapi_ctx_s *ctx)
{
  vapi_msg_ikev2_profile_set_liveness *msg = NULL;
  const size_t size = sizeof(vapi_msg_ikev2_profile_set_liveness);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ikev2_profile_set_liveness*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ikev2_profile_set_liveness);

  return msg;
}

static inline vapi_error_e vapi_ikev2_profile_set_liveness(struct vapi_ctx_s *ctx,
  vapi_msg_ikev2_profile_set_liveness *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ikev2_profile_set_liveness_reply *reply),
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
  vapi_msg_ikev2_profile_set_liveness_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ikev2_profile_set_liveness_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ikev2_profile_set_liveness_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ikev2_profile_set_liveness()
{
  static const char name[] = "ikev2_profile_set_liveness";
  static const char name_with_crc[] = "ikev2_profile_set_liveness_6bdf4d65";
  static vapi_message_desc_t __vapi_metadata_ikev2_profile_set_liveness = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ikev2_profile_set_liveness, payload),
    (verify_msg_size_fn_t)vapi_verify_ikev2_profile_set_liveness_msg_size,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_liveness_hton,
    (generic_swap_fn_t)vapi_msg_ikev2_profile_set_liveness_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ikev2_profile_set_liveness = vapi_register_msg(&__vapi_metadata_ikev2_profile_set_liveness);
  VAPI_DBG("Assigned msg id %d to ikev2_profile_set_liveness", vapi_msg_id_ikev2_profile_set_liveness);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
