#ifndef __included_lisp_api_json
#define __included_lisp_api_json

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

extern vapi_msg_id_t vapi_msg_id_lisp_add_del_locator_set;
extern vapi_msg_id_t vapi_msg_id_lisp_add_del_locator_set_reply;
extern vapi_msg_id_t vapi_msg_id_lisp_add_del_locator;
extern vapi_msg_id_t vapi_msg_id_lisp_add_del_locator_reply;
extern vapi_msg_id_t vapi_msg_id_lisp_add_del_local_eid;
extern vapi_msg_id_t vapi_msg_id_lisp_add_del_local_eid_reply;
extern vapi_msg_id_t vapi_msg_id_lisp_add_del_map_server;
extern vapi_msg_id_t vapi_msg_id_lisp_add_del_map_server_reply;
extern vapi_msg_id_t vapi_msg_id_lisp_add_del_map_resolver;
extern vapi_msg_id_t vapi_msg_id_lisp_add_del_map_resolver_reply;
extern vapi_msg_id_t vapi_msg_id_lisp_enable_disable;
extern vapi_msg_id_t vapi_msg_id_lisp_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_lisp_pitr_set_locator_set;
extern vapi_msg_id_t vapi_msg_id_lisp_pitr_set_locator_set_reply;
extern vapi_msg_id_t vapi_msg_id_lisp_use_petr;
extern vapi_msg_id_t vapi_msg_id_lisp_use_petr_reply;
extern vapi_msg_id_t vapi_msg_id_show_lisp_use_petr;
extern vapi_msg_id_t vapi_msg_id_show_lisp_use_petr_reply;
extern vapi_msg_id_t vapi_msg_id_show_lisp_rloc_probe_state;
extern vapi_msg_id_t vapi_msg_id_show_lisp_rloc_probe_state_reply;
extern vapi_msg_id_t vapi_msg_id_lisp_rloc_probe_enable_disable;
extern vapi_msg_id_t vapi_msg_id_lisp_rloc_probe_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_lisp_map_register_enable_disable;
extern vapi_msg_id_t vapi_msg_id_lisp_map_register_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_show_lisp_map_register_state;
extern vapi_msg_id_t vapi_msg_id_show_lisp_map_register_state_reply;
extern vapi_msg_id_t vapi_msg_id_lisp_map_request_mode;
extern vapi_msg_id_t vapi_msg_id_lisp_map_request_mode_reply;
extern vapi_msg_id_t vapi_msg_id_show_lisp_map_request_mode;
extern vapi_msg_id_t vapi_msg_id_show_lisp_map_request_mode_reply;
extern vapi_msg_id_t vapi_msg_id_lisp_add_del_remote_mapping;
extern vapi_msg_id_t vapi_msg_id_lisp_add_del_remote_mapping_reply;
extern vapi_msg_id_t vapi_msg_id_lisp_add_del_adjacency;
extern vapi_msg_id_t vapi_msg_id_lisp_add_del_adjacency_reply;
extern vapi_msg_id_t vapi_msg_id_lisp_add_del_map_request_itr_rlocs;
extern vapi_msg_id_t vapi_msg_id_lisp_add_del_map_request_itr_rlocs_reply;
extern vapi_msg_id_t vapi_msg_id_lisp_eid_table_add_del_map;
extern vapi_msg_id_t vapi_msg_id_lisp_eid_table_add_del_map_reply;
extern vapi_msg_id_t vapi_msg_id_lisp_locator_dump;
extern vapi_msg_id_t vapi_msg_id_lisp_locator_details;
extern vapi_msg_id_t vapi_msg_id_lisp_locator_set_details;
extern vapi_msg_id_t vapi_msg_id_lisp_locator_set_dump;
extern vapi_msg_id_t vapi_msg_id_lisp_eid_table_details;
extern vapi_msg_id_t vapi_msg_id_lisp_eid_table_dump;
extern vapi_msg_id_t vapi_msg_id_lisp_adjacencies_get_reply;
extern vapi_msg_id_t vapi_msg_id_lisp_adjacencies_get;
extern vapi_msg_id_t vapi_msg_id_lisp_eid_table_map_details;
extern vapi_msg_id_t vapi_msg_id_lisp_eid_table_map_dump;
extern vapi_msg_id_t vapi_msg_id_lisp_eid_table_vni_dump;
extern vapi_msg_id_t vapi_msg_id_lisp_eid_table_vni_details;
extern vapi_msg_id_t vapi_msg_id_lisp_map_resolver_details;
extern vapi_msg_id_t vapi_msg_id_lisp_map_resolver_dump;
extern vapi_msg_id_t vapi_msg_id_lisp_map_server_details;
extern vapi_msg_id_t vapi_msg_id_lisp_map_server_dump;
extern vapi_msg_id_t vapi_msg_id_show_lisp_status;
extern vapi_msg_id_t vapi_msg_id_show_lisp_status_reply;
extern vapi_msg_id_t vapi_msg_id_lisp_get_map_request_itr_rlocs;
extern vapi_msg_id_t vapi_msg_id_lisp_get_map_request_itr_rlocs_reply;
extern vapi_msg_id_t vapi_msg_id_show_lisp_pitr;
extern vapi_msg_id_t vapi_msg_id_show_lisp_pitr_reply;

#define DEFINE_VAPI_MSG_IDS_LISP_API_JSON\
  vapi_msg_id_t vapi_msg_id_lisp_add_del_locator_set;\
  vapi_msg_id_t vapi_msg_id_lisp_add_del_locator_set_reply;\
  vapi_msg_id_t vapi_msg_id_lisp_add_del_locator;\
  vapi_msg_id_t vapi_msg_id_lisp_add_del_locator_reply;\
  vapi_msg_id_t vapi_msg_id_lisp_add_del_local_eid;\
  vapi_msg_id_t vapi_msg_id_lisp_add_del_local_eid_reply;\
  vapi_msg_id_t vapi_msg_id_lisp_add_del_map_server;\
  vapi_msg_id_t vapi_msg_id_lisp_add_del_map_server_reply;\
  vapi_msg_id_t vapi_msg_id_lisp_add_del_map_resolver;\
  vapi_msg_id_t vapi_msg_id_lisp_add_del_map_resolver_reply;\
  vapi_msg_id_t vapi_msg_id_lisp_enable_disable;\
  vapi_msg_id_t vapi_msg_id_lisp_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_lisp_pitr_set_locator_set;\
  vapi_msg_id_t vapi_msg_id_lisp_pitr_set_locator_set_reply;\
  vapi_msg_id_t vapi_msg_id_lisp_use_petr;\
  vapi_msg_id_t vapi_msg_id_lisp_use_petr_reply;\
  vapi_msg_id_t vapi_msg_id_show_lisp_use_petr;\
  vapi_msg_id_t vapi_msg_id_show_lisp_use_petr_reply;\
  vapi_msg_id_t vapi_msg_id_show_lisp_rloc_probe_state;\
  vapi_msg_id_t vapi_msg_id_show_lisp_rloc_probe_state_reply;\
  vapi_msg_id_t vapi_msg_id_lisp_rloc_probe_enable_disable;\
  vapi_msg_id_t vapi_msg_id_lisp_rloc_probe_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_lisp_map_register_enable_disable;\
  vapi_msg_id_t vapi_msg_id_lisp_map_register_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_show_lisp_map_register_state;\
  vapi_msg_id_t vapi_msg_id_show_lisp_map_register_state_reply;\
  vapi_msg_id_t vapi_msg_id_lisp_map_request_mode;\
  vapi_msg_id_t vapi_msg_id_lisp_map_request_mode_reply;\
  vapi_msg_id_t vapi_msg_id_show_lisp_map_request_mode;\
  vapi_msg_id_t vapi_msg_id_show_lisp_map_request_mode_reply;\
  vapi_msg_id_t vapi_msg_id_lisp_add_del_remote_mapping;\
  vapi_msg_id_t vapi_msg_id_lisp_add_del_remote_mapping_reply;\
  vapi_msg_id_t vapi_msg_id_lisp_add_del_adjacency;\
  vapi_msg_id_t vapi_msg_id_lisp_add_del_adjacency_reply;\
  vapi_msg_id_t vapi_msg_id_lisp_add_del_map_request_itr_rlocs;\
  vapi_msg_id_t vapi_msg_id_lisp_add_del_map_request_itr_rlocs_reply;\
  vapi_msg_id_t vapi_msg_id_lisp_eid_table_add_del_map;\
  vapi_msg_id_t vapi_msg_id_lisp_eid_table_add_del_map_reply;\
  vapi_msg_id_t vapi_msg_id_lisp_locator_dump;\
  vapi_msg_id_t vapi_msg_id_lisp_locator_details;\
  vapi_msg_id_t vapi_msg_id_lisp_locator_set_details;\
  vapi_msg_id_t vapi_msg_id_lisp_locator_set_dump;\
  vapi_msg_id_t vapi_msg_id_lisp_eid_table_details;\
  vapi_msg_id_t vapi_msg_id_lisp_eid_table_dump;\
  vapi_msg_id_t vapi_msg_id_lisp_adjacencies_get_reply;\
  vapi_msg_id_t vapi_msg_id_lisp_adjacencies_get;\
  vapi_msg_id_t vapi_msg_id_lisp_eid_table_map_details;\
  vapi_msg_id_t vapi_msg_id_lisp_eid_table_map_dump;\
  vapi_msg_id_t vapi_msg_id_lisp_eid_table_vni_dump;\
  vapi_msg_id_t vapi_msg_id_lisp_eid_table_vni_details;\
  vapi_msg_id_t vapi_msg_id_lisp_map_resolver_details;\
  vapi_msg_id_t vapi_msg_id_lisp_map_resolver_dump;\
  vapi_msg_id_t vapi_msg_id_lisp_map_server_details;\
  vapi_msg_id_t vapi_msg_id_lisp_map_server_dump;\
  vapi_msg_id_t vapi_msg_id_show_lisp_status;\
  vapi_msg_id_t vapi_msg_id_show_lisp_status_reply;\
  vapi_msg_id_t vapi_msg_id_lisp_get_map_request_itr_rlocs;\
  vapi_msg_id_t vapi_msg_id_lisp_get_map_request_itr_rlocs_reply;\
  vapi_msg_id_t vapi_msg_id_show_lisp_pitr;\
  vapi_msg_id_t vapi_msg_id_show_lisp_pitr_reply;


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

#ifndef defined_vapi_enum_eid_type
#define defined_vapi_enum_eid_type
typedef enum {
  EID_TYPE_API_PREFIX = 0,
  EID_TYPE_API_MAC = 1,
  EID_TYPE_API_NSH = 2,
} __attribute__((packed)) vapi_enum_eid_type;

#endif

#ifndef defined_vapi_enum_hmac_key_id
#define defined_vapi_enum_hmac_key_id
typedef enum {
  KEY_ID_API_HMAC_NO_KEY = 0,
  KEY_ID_API_HMAC_SHA_1_96 = 1,
  KEY_ID_API_HMAC_SHA_256_128 = 2,
} __attribute__((packed)) vapi_enum_hmac_key_id;

#endif

#ifndef defined_vapi_enum_lisp_locator_set_filter
#define defined_vapi_enum_lisp_locator_set_filter
typedef enum {
  LISP_LOCATOR_SET_FILTER_API_ALL = 0,
  LISP_LOCATOR_SET_FILTER_API_LOCAL = 1,
  LISP_LOCATOR_SET_FILTER_API_REMOTE = 2,
} __attribute__((packed)) vapi_enum_lisp_locator_set_filter;

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

#ifndef defined_vapi_type_mac_address
#define defined_vapi_type_mac_address
typedef u8 vapi_type_mac_address[6];

#endif

#ifndef defined_vapi_type_nsh
#define defined_vapi_type_nsh
typedef struct __attribute__((__packed__)) {
  u32 spi;
  u8 si;
} vapi_type_nsh;

static inline void vapi_type_nsh_hton(vapi_type_nsh *msg)
{
  msg->spi = htobe32(msg->spi);
}

static inline void vapi_type_nsh_ntoh(vapi_type_nsh *msg)
{
  msg->spi = be32toh(msg->spi);
}
#endif

#ifndef defined_vapi_union_eid_address
#define defined_vapi_union_eid_address
typedef union {
  vapi_type_prefix prefix;
  vapi_type_mac_address mac;
  vapi_type_nsh nsh;
} vapi_union_eid_address;

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

#ifndef defined_vapi_type_hmac_key
#define defined_vapi_type_hmac_key
typedef struct __attribute__((__packed__)) {
  vapi_enum_hmac_key_id id;
  u8 key[64];
} vapi_type_hmac_key;

static inline void vapi_type_hmac_key_hton(vapi_type_hmac_key *msg)
{

}

static inline void vapi_type_hmac_key_ntoh(vapi_type_hmac_key *msg)
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

#ifndef defined_vapi_type_local_locator
#define defined_vapi_type_local_locator
typedef struct __attribute__((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u8 priority;
  u8 weight;
} vapi_type_local_locator;

static inline void vapi_type_local_locator_hton(vapi_type_local_locator *msg)
{
  msg->sw_if_index = htobe32(msg->sw_if_index);
}

static inline void vapi_type_local_locator_ntoh(vapi_type_local_locator *msg)
{
  msg->sw_if_index = be32toh(msg->sw_if_index);
}
#endif

#ifndef defined_vapi_type_remote_locator
#define defined_vapi_type_remote_locator
typedef struct __attribute__((__packed__)) {
  u8 priority;
  u8 weight;
  vapi_type_address ip_address;
} vapi_type_remote_locator;

static inline void vapi_type_remote_locator_hton(vapi_type_remote_locator *msg)
{

}

static inline void vapi_type_remote_locator_ntoh(vapi_type_remote_locator *msg)
{

}
#endif

#ifndef defined_vapi_type_eid
#define defined_vapi_type_eid
typedef struct __attribute__((__packed__)) {
  vapi_enum_eid_type type;
  vapi_union_eid_address address;
} vapi_type_eid;

static inline void vapi_type_eid_hton(vapi_type_eid *msg)
{

}

static inline void vapi_type_eid_ntoh(vapi_type_eid *msg)
{

}
#endif

#ifndef defined_vapi_type_lisp_adjacency
#define defined_vapi_type_lisp_adjacency
typedef struct __attribute__((__packed__)) {
  vapi_type_eid reid;
  vapi_type_eid leid;
} vapi_type_lisp_adjacency;

static inline void vapi_type_lisp_adjacency_hton(vapi_type_lisp_adjacency *msg)
{

}

static inline void vapi_type_lisp_adjacency_ntoh(vapi_type_lisp_adjacency *msg)
{

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

#ifndef defined_vapi_msg_lisp_add_del_locator_set_reply
#define defined_vapi_msg_lisp_add_del_locator_set_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 ls_index; 
} vapi_payload_lisp_add_del_locator_set_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_add_del_locator_set_reply payload;
} vapi_msg_lisp_add_del_locator_set_reply;

static inline void vapi_msg_lisp_add_del_locator_set_reply_payload_hton(vapi_payload_lisp_add_del_locator_set_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->ls_index = htobe32(payload->ls_index);
}

static inline void vapi_msg_lisp_add_del_locator_set_reply_payload_ntoh(vapi_payload_lisp_add_del_locator_set_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->ls_index = be32toh(payload->ls_index);
}

static inline void vapi_msg_lisp_add_del_locator_set_reply_hton(vapi_msg_lisp_add_del_locator_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_locator_set_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_add_del_locator_set_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_add_del_locator_set_reply_ntoh(vapi_msg_lisp_add_del_locator_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_locator_set_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_add_del_locator_set_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_add_del_locator_set_reply_msg_size(vapi_msg_lisp_add_del_locator_set_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_add_del_locator_set_reply_msg_size(vapi_msg_lisp_add_del_locator_set_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_add_del_locator_set_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_locator_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_add_del_locator_set_reply));
      return -1;
    }
  if (vapi_calc_lisp_add_del_locator_set_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_locator_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_add_del_locator_set_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_add_del_locator_set_reply()
{
  static const char name[] = "lisp_add_del_locator_set_reply";
  static const char name_with_crc[] = "lisp_add_del_locator_set_reply_b6666db4";
  static vapi_message_desc_t __vapi_metadata_lisp_add_del_locator_set_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_add_del_locator_set_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_add_del_locator_set_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_locator_set_reply_hton,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_locator_set_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_add_del_locator_set_reply = vapi_register_msg(&__vapi_metadata_lisp_add_del_locator_set_reply);
  VAPI_DBG("Assigned msg id %d to lisp_add_del_locator_set_reply", vapi_msg_id_lisp_add_del_locator_set_reply);
}

static inline void vapi_set_vapi_msg_lisp_add_del_locator_set_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_add_del_locator_set_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_add_del_locator_set_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_add_del_locator_set
#define defined_vapi_msg_lisp_add_del_locator_set
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  u8 locator_set_name[64];
  u32 locator_num;
  vapi_type_local_locator locators[0]; 
} vapi_payload_lisp_add_del_locator_set;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lisp_add_del_locator_set payload;
} vapi_msg_lisp_add_del_locator_set;

static inline void vapi_msg_lisp_add_del_locator_set_payload_hton(vapi_payload_lisp_add_del_locator_set *payload)
{
  payload->locator_num = htobe32(payload->locator_num);
  do { unsigned i; for (i = 0; i < be32toh(payload->locator_num); ++i) { vapi_type_local_locator_hton(&payload->locators[i]); } } while(0);
}

static inline void vapi_msg_lisp_add_del_locator_set_payload_ntoh(vapi_payload_lisp_add_del_locator_set *payload)
{
  payload->locator_num = be32toh(payload->locator_num);
  do { unsigned i; for (i = 0; i < payload->locator_num; ++i) { vapi_type_local_locator_ntoh(&payload->locators[i]); } } while(0);
}

static inline void vapi_msg_lisp_add_del_locator_set_hton(vapi_msg_lisp_add_del_locator_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_locator_set'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lisp_add_del_locator_set_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_add_del_locator_set_ntoh(vapi_msg_lisp_add_del_locator_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_locator_set'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lisp_add_del_locator_set_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_add_del_locator_set_msg_size(vapi_msg_lisp_add_del_locator_set *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.locators[0]) * msg->payload.locator_num;
}

static inline int vapi_verify_lisp_add_del_locator_set_msg_size(vapi_msg_lisp_add_del_locator_set *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_add_del_locator_set) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_locator_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_add_del_locator_set));
      return -1;
    }
  if (vapi_calc_lisp_add_del_locator_set_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_locator_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_add_del_locator_set_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_add_del_locator_set* vapi_alloc_lisp_add_del_locator_set(struct vapi_ctx_s *ctx, size_t _locators_array_size)
{
  vapi_msg_lisp_add_del_locator_set *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_add_del_locator_set) + sizeof(msg->payload.locators[0]) * _locators_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_add_del_locator_set*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_add_del_locator_set);
  msg->payload.locator_num = _locators_array_size;

  return msg;
}

static inline vapi_error_e vapi_lisp_add_del_locator_set(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_add_del_locator_set *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_add_del_locator_set_reply *reply),
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
  vapi_msg_lisp_add_del_locator_set_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_add_del_locator_set_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lisp_add_del_locator_set_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_add_del_locator_set()
{
  static const char name[] = "lisp_add_del_locator_set";
  static const char name_with_crc[] = "lisp_add_del_locator_set_6fcd6471";
  static vapi_message_desc_t __vapi_metadata_lisp_add_del_locator_set = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lisp_add_del_locator_set, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_add_del_locator_set_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_locator_set_hton,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_locator_set_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_add_del_locator_set = vapi_register_msg(&__vapi_metadata_lisp_add_del_locator_set);
  VAPI_DBG("Assigned msg id %d to lisp_add_del_locator_set", vapi_msg_id_lisp_add_del_locator_set);
}
#endif

#ifndef defined_vapi_msg_lisp_add_del_locator_reply
#define defined_vapi_msg_lisp_add_del_locator_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lisp_add_del_locator_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_add_del_locator_reply payload;
} vapi_msg_lisp_add_del_locator_reply;

static inline void vapi_msg_lisp_add_del_locator_reply_payload_hton(vapi_payload_lisp_add_del_locator_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lisp_add_del_locator_reply_payload_ntoh(vapi_payload_lisp_add_del_locator_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lisp_add_del_locator_reply_hton(vapi_msg_lisp_add_del_locator_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_locator_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_add_del_locator_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_add_del_locator_reply_ntoh(vapi_msg_lisp_add_del_locator_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_locator_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_add_del_locator_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_add_del_locator_reply_msg_size(vapi_msg_lisp_add_del_locator_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_add_del_locator_reply_msg_size(vapi_msg_lisp_add_del_locator_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_add_del_locator_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_locator_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_add_del_locator_reply));
      return -1;
    }
  if (vapi_calc_lisp_add_del_locator_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_locator_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_add_del_locator_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_add_del_locator_reply()
{
  static const char name[] = "lisp_add_del_locator_reply";
  static const char name_with_crc[] = "lisp_add_del_locator_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lisp_add_del_locator_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_add_del_locator_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_add_del_locator_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_locator_reply_hton,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_locator_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_add_del_locator_reply = vapi_register_msg(&__vapi_metadata_lisp_add_del_locator_reply);
  VAPI_DBG("Assigned msg id %d to lisp_add_del_locator_reply", vapi_msg_id_lisp_add_del_locator_reply);
}

static inline void vapi_set_vapi_msg_lisp_add_del_locator_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_add_del_locator_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_add_del_locator_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_add_del_locator
#define defined_vapi_msg_lisp_add_del_locator
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  u8 locator_set_name[64];
  vapi_type_interface_index sw_if_index;
  u8 priority;
  u8 weight; 
} vapi_payload_lisp_add_del_locator;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lisp_add_del_locator payload;
} vapi_msg_lisp_add_del_locator;

static inline void vapi_msg_lisp_add_del_locator_payload_hton(vapi_payload_lisp_add_del_locator *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_lisp_add_del_locator_payload_ntoh(vapi_payload_lisp_add_del_locator *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_lisp_add_del_locator_hton(vapi_msg_lisp_add_del_locator *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_locator'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lisp_add_del_locator_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_add_del_locator_ntoh(vapi_msg_lisp_add_del_locator *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_locator'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lisp_add_del_locator_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_add_del_locator_msg_size(vapi_msg_lisp_add_del_locator *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_add_del_locator_msg_size(vapi_msg_lisp_add_del_locator *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_add_del_locator) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_locator' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_add_del_locator));
      return -1;
    }
  if (vapi_calc_lisp_add_del_locator_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_locator' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_add_del_locator_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_add_del_locator* vapi_alloc_lisp_add_del_locator(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_add_del_locator *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_add_del_locator);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_add_del_locator*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_add_del_locator);

  return msg;
}

static inline vapi_error_e vapi_lisp_add_del_locator(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_add_del_locator *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_add_del_locator_reply *reply),
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
  vapi_msg_lisp_add_del_locator_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_add_del_locator_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lisp_add_del_locator_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_add_del_locator()
{
  static const char name[] = "lisp_add_del_locator";
  static const char name_with_crc[] = "lisp_add_del_locator_af4d8f13";
  static vapi_message_desc_t __vapi_metadata_lisp_add_del_locator = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lisp_add_del_locator, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_add_del_locator_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_locator_hton,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_locator_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_add_del_locator = vapi_register_msg(&__vapi_metadata_lisp_add_del_locator);
  VAPI_DBG("Assigned msg id %d to lisp_add_del_locator", vapi_msg_id_lisp_add_del_locator);
}
#endif

#ifndef defined_vapi_msg_lisp_add_del_local_eid_reply
#define defined_vapi_msg_lisp_add_del_local_eid_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lisp_add_del_local_eid_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_add_del_local_eid_reply payload;
} vapi_msg_lisp_add_del_local_eid_reply;

static inline void vapi_msg_lisp_add_del_local_eid_reply_payload_hton(vapi_payload_lisp_add_del_local_eid_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lisp_add_del_local_eid_reply_payload_ntoh(vapi_payload_lisp_add_del_local_eid_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lisp_add_del_local_eid_reply_hton(vapi_msg_lisp_add_del_local_eid_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_local_eid_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_add_del_local_eid_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_add_del_local_eid_reply_ntoh(vapi_msg_lisp_add_del_local_eid_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_local_eid_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_add_del_local_eid_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_add_del_local_eid_reply_msg_size(vapi_msg_lisp_add_del_local_eid_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_add_del_local_eid_reply_msg_size(vapi_msg_lisp_add_del_local_eid_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_add_del_local_eid_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_local_eid_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_add_del_local_eid_reply));
      return -1;
    }
  if (vapi_calc_lisp_add_del_local_eid_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_local_eid_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_add_del_local_eid_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_add_del_local_eid_reply()
{
  static const char name[] = "lisp_add_del_local_eid_reply";
  static const char name_with_crc[] = "lisp_add_del_local_eid_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lisp_add_del_local_eid_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_add_del_local_eid_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_add_del_local_eid_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_local_eid_reply_hton,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_local_eid_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_add_del_local_eid_reply = vapi_register_msg(&__vapi_metadata_lisp_add_del_local_eid_reply);
  VAPI_DBG("Assigned msg id %d to lisp_add_del_local_eid_reply", vapi_msg_id_lisp_add_del_local_eid_reply);
}

static inline void vapi_set_vapi_msg_lisp_add_del_local_eid_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_add_del_local_eid_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_add_del_local_eid_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_add_del_local_eid
#define defined_vapi_msg_lisp_add_del_local_eid
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_eid eid;
  u8 locator_set_name[64];
  u32 vni;
  vapi_type_hmac_key key; 
} vapi_payload_lisp_add_del_local_eid;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lisp_add_del_local_eid payload;
} vapi_msg_lisp_add_del_local_eid;

static inline void vapi_msg_lisp_add_del_local_eid_payload_hton(vapi_payload_lisp_add_del_local_eid *payload)
{
  payload->vni = htobe32(payload->vni);
}

static inline void vapi_msg_lisp_add_del_local_eid_payload_ntoh(vapi_payload_lisp_add_del_local_eid *payload)
{
  payload->vni = be32toh(payload->vni);
}

static inline void vapi_msg_lisp_add_del_local_eid_hton(vapi_msg_lisp_add_del_local_eid *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_local_eid'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lisp_add_del_local_eid_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_add_del_local_eid_ntoh(vapi_msg_lisp_add_del_local_eid *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_local_eid'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lisp_add_del_local_eid_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_add_del_local_eid_msg_size(vapi_msg_lisp_add_del_local_eid *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_add_del_local_eid_msg_size(vapi_msg_lisp_add_del_local_eid *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_add_del_local_eid) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_local_eid' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_add_del_local_eid));
      return -1;
    }
  if (vapi_calc_lisp_add_del_local_eid_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_local_eid' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_add_del_local_eid_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_add_del_local_eid* vapi_alloc_lisp_add_del_local_eid(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_add_del_local_eid *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_add_del_local_eid);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_add_del_local_eid*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_add_del_local_eid);

  return msg;
}

static inline vapi_error_e vapi_lisp_add_del_local_eid(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_add_del_local_eid *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_add_del_local_eid_reply *reply),
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
  vapi_msg_lisp_add_del_local_eid_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_add_del_local_eid_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lisp_add_del_local_eid_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_add_del_local_eid()
{
  static const char name[] = "lisp_add_del_local_eid";
  static const char name_with_crc[] = "lisp_add_del_local_eid_4e5a83a2";
  static vapi_message_desc_t __vapi_metadata_lisp_add_del_local_eid = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lisp_add_del_local_eid, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_add_del_local_eid_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_local_eid_hton,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_local_eid_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_add_del_local_eid = vapi_register_msg(&__vapi_metadata_lisp_add_del_local_eid);
  VAPI_DBG("Assigned msg id %d to lisp_add_del_local_eid", vapi_msg_id_lisp_add_del_local_eid);
}
#endif

#ifndef defined_vapi_msg_lisp_add_del_map_server_reply
#define defined_vapi_msg_lisp_add_del_map_server_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lisp_add_del_map_server_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_add_del_map_server_reply payload;
} vapi_msg_lisp_add_del_map_server_reply;

static inline void vapi_msg_lisp_add_del_map_server_reply_payload_hton(vapi_payload_lisp_add_del_map_server_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lisp_add_del_map_server_reply_payload_ntoh(vapi_payload_lisp_add_del_map_server_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lisp_add_del_map_server_reply_hton(vapi_msg_lisp_add_del_map_server_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_map_server_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_add_del_map_server_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_add_del_map_server_reply_ntoh(vapi_msg_lisp_add_del_map_server_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_map_server_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_add_del_map_server_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_add_del_map_server_reply_msg_size(vapi_msg_lisp_add_del_map_server_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_add_del_map_server_reply_msg_size(vapi_msg_lisp_add_del_map_server_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_add_del_map_server_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_map_server_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_add_del_map_server_reply));
      return -1;
    }
  if (vapi_calc_lisp_add_del_map_server_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_map_server_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_add_del_map_server_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_add_del_map_server_reply()
{
  static const char name[] = "lisp_add_del_map_server_reply";
  static const char name_with_crc[] = "lisp_add_del_map_server_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lisp_add_del_map_server_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_add_del_map_server_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_add_del_map_server_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_map_server_reply_hton,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_map_server_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_add_del_map_server_reply = vapi_register_msg(&__vapi_metadata_lisp_add_del_map_server_reply);
  VAPI_DBG("Assigned msg id %d to lisp_add_del_map_server_reply", vapi_msg_id_lisp_add_del_map_server_reply);
}

static inline void vapi_set_vapi_msg_lisp_add_del_map_server_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_add_del_map_server_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_add_del_map_server_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_add_del_map_server
#define defined_vapi_msg_lisp_add_del_map_server
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_address ip_address; 
} vapi_payload_lisp_add_del_map_server;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lisp_add_del_map_server payload;
} vapi_msg_lisp_add_del_map_server;

static inline void vapi_msg_lisp_add_del_map_server_payload_hton(vapi_payload_lisp_add_del_map_server *payload)
{

}

static inline void vapi_msg_lisp_add_del_map_server_payload_ntoh(vapi_payload_lisp_add_del_map_server *payload)
{

}

static inline void vapi_msg_lisp_add_del_map_server_hton(vapi_msg_lisp_add_del_map_server *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_map_server'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lisp_add_del_map_server_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_add_del_map_server_ntoh(vapi_msg_lisp_add_del_map_server *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_map_server'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lisp_add_del_map_server_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_add_del_map_server_msg_size(vapi_msg_lisp_add_del_map_server *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_add_del_map_server_msg_size(vapi_msg_lisp_add_del_map_server *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_add_del_map_server) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_map_server' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_add_del_map_server));
      return -1;
    }
  if (vapi_calc_lisp_add_del_map_server_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_map_server' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_add_del_map_server_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_add_del_map_server* vapi_alloc_lisp_add_del_map_server(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_add_del_map_server *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_add_del_map_server);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_add_del_map_server*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_add_del_map_server);

  return msg;
}

static inline vapi_error_e vapi_lisp_add_del_map_server(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_add_del_map_server *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_add_del_map_server_reply *reply),
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
  vapi_msg_lisp_add_del_map_server_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_add_del_map_server_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lisp_add_del_map_server_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_add_del_map_server()
{
  static const char name[] = "lisp_add_del_map_server";
  static const char name_with_crc[] = "lisp_add_del_map_server_ce19e32d";
  static vapi_message_desc_t __vapi_metadata_lisp_add_del_map_server = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lisp_add_del_map_server, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_add_del_map_server_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_map_server_hton,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_map_server_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_add_del_map_server = vapi_register_msg(&__vapi_metadata_lisp_add_del_map_server);
  VAPI_DBG("Assigned msg id %d to lisp_add_del_map_server", vapi_msg_id_lisp_add_del_map_server);
}
#endif

#ifndef defined_vapi_msg_lisp_add_del_map_resolver_reply
#define defined_vapi_msg_lisp_add_del_map_resolver_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lisp_add_del_map_resolver_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_add_del_map_resolver_reply payload;
} vapi_msg_lisp_add_del_map_resolver_reply;

static inline void vapi_msg_lisp_add_del_map_resolver_reply_payload_hton(vapi_payload_lisp_add_del_map_resolver_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lisp_add_del_map_resolver_reply_payload_ntoh(vapi_payload_lisp_add_del_map_resolver_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lisp_add_del_map_resolver_reply_hton(vapi_msg_lisp_add_del_map_resolver_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_map_resolver_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_add_del_map_resolver_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_add_del_map_resolver_reply_ntoh(vapi_msg_lisp_add_del_map_resolver_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_map_resolver_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_add_del_map_resolver_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_add_del_map_resolver_reply_msg_size(vapi_msg_lisp_add_del_map_resolver_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_add_del_map_resolver_reply_msg_size(vapi_msg_lisp_add_del_map_resolver_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_add_del_map_resolver_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_map_resolver_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_add_del_map_resolver_reply));
      return -1;
    }
  if (vapi_calc_lisp_add_del_map_resolver_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_map_resolver_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_add_del_map_resolver_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_add_del_map_resolver_reply()
{
  static const char name[] = "lisp_add_del_map_resolver_reply";
  static const char name_with_crc[] = "lisp_add_del_map_resolver_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lisp_add_del_map_resolver_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_add_del_map_resolver_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_add_del_map_resolver_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_map_resolver_reply_hton,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_map_resolver_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_add_del_map_resolver_reply = vapi_register_msg(&__vapi_metadata_lisp_add_del_map_resolver_reply);
  VAPI_DBG("Assigned msg id %d to lisp_add_del_map_resolver_reply", vapi_msg_id_lisp_add_del_map_resolver_reply);
}

static inline void vapi_set_vapi_msg_lisp_add_del_map_resolver_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_add_del_map_resolver_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_add_del_map_resolver_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_add_del_map_resolver
#define defined_vapi_msg_lisp_add_del_map_resolver
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_address ip_address; 
} vapi_payload_lisp_add_del_map_resolver;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lisp_add_del_map_resolver payload;
} vapi_msg_lisp_add_del_map_resolver;

static inline void vapi_msg_lisp_add_del_map_resolver_payload_hton(vapi_payload_lisp_add_del_map_resolver *payload)
{

}

static inline void vapi_msg_lisp_add_del_map_resolver_payload_ntoh(vapi_payload_lisp_add_del_map_resolver *payload)
{

}

static inline void vapi_msg_lisp_add_del_map_resolver_hton(vapi_msg_lisp_add_del_map_resolver *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_map_resolver'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lisp_add_del_map_resolver_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_add_del_map_resolver_ntoh(vapi_msg_lisp_add_del_map_resolver *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_map_resolver'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lisp_add_del_map_resolver_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_add_del_map_resolver_msg_size(vapi_msg_lisp_add_del_map_resolver *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_add_del_map_resolver_msg_size(vapi_msg_lisp_add_del_map_resolver *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_add_del_map_resolver) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_map_resolver' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_add_del_map_resolver));
      return -1;
    }
  if (vapi_calc_lisp_add_del_map_resolver_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_map_resolver' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_add_del_map_resolver_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_add_del_map_resolver* vapi_alloc_lisp_add_del_map_resolver(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_add_del_map_resolver *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_add_del_map_resolver);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_add_del_map_resolver*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_add_del_map_resolver);

  return msg;
}

static inline vapi_error_e vapi_lisp_add_del_map_resolver(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_add_del_map_resolver *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_add_del_map_resolver_reply *reply),
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
  vapi_msg_lisp_add_del_map_resolver_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_add_del_map_resolver_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lisp_add_del_map_resolver_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_add_del_map_resolver()
{
  static const char name[] = "lisp_add_del_map_resolver";
  static const char name_with_crc[] = "lisp_add_del_map_resolver_ce19e32d";
  static vapi_message_desc_t __vapi_metadata_lisp_add_del_map_resolver = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lisp_add_del_map_resolver, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_add_del_map_resolver_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_map_resolver_hton,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_map_resolver_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_add_del_map_resolver = vapi_register_msg(&__vapi_metadata_lisp_add_del_map_resolver);
  VAPI_DBG("Assigned msg id %d to lisp_add_del_map_resolver", vapi_msg_id_lisp_add_del_map_resolver);
}
#endif

#ifndef defined_vapi_msg_lisp_enable_disable_reply
#define defined_vapi_msg_lisp_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lisp_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_enable_disable_reply payload;
} vapi_msg_lisp_enable_disable_reply;

static inline void vapi_msg_lisp_enable_disable_reply_payload_hton(vapi_payload_lisp_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lisp_enable_disable_reply_payload_ntoh(vapi_payload_lisp_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lisp_enable_disable_reply_hton(vapi_msg_lisp_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_enable_disable_reply_ntoh(vapi_msg_lisp_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_enable_disable_reply_msg_size(vapi_msg_lisp_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_enable_disable_reply_msg_size(vapi_msg_lisp_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_lisp_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_enable_disable_reply()
{
  static const char name[] = "lisp_enable_disable_reply";
  static const char name_with_crc[] = "lisp_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lisp_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_lisp_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_enable_disable_reply = vapi_register_msg(&__vapi_metadata_lisp_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to lisp_enable_disable_reply", vapi_msg_id_lisp_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_lisp_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_enable_disable
#define defined_vapi_msg_lisp_enable_disable
typedef struct __attribute__ ((__packed__)) {
  bool is_enable; 
} vapi_payload_lisp_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lisp_enable_disable payload;
} vapi_msg_lisp_enable_disable;

static inline void vapi_msg_lisp_enable_disable_payload_hton(vapi_payload_lisp_enable_disable *payload)
{

}

static inline void vapi_msg_lisp_enable_disable_payload_ntoh(vapi_payload_lisp_enable_disable *payload)
{

}

static inline void vapi_msg_lisp_enable_disable_hton(vapi_msg_lisp_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lisp_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_enable_disable_ntoh(vapi_msg_lisp_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lisp_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_enable_disable_msg_size(vapi_msg_lisp_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_enable_disable_msg_size(vapi_msg_lisp_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_enable_disable));
      return -1;
    }
  if (vapi_calc_lisp_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_enable_disable* vapi_alloc_lisp_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_lisp_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_enable_disable_reply *reply),
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
  vapi_msg_lisp_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lisp_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_enable_disable()
{
  static const char name[] = "lisp_enable_disable";
  static const char name_with_crc[] = "lisp_enable_disable_c264d7bf";
  static vapi_message_desc_t __vapi_metadata_lisp_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lisp_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_lisp_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_enable_disable = vapi_register_msg(&__vapi_metadata_lisp_enable_disable);
  VAPI_DBG("Assigned msg id %d to lisp_enable_disable", vapi_msg_id_lisp_enable_disable);
}
#endif

#ifndef defined_vapi_msg_lisp_pitr_set_locator_set_reply
#define defined_vapi_msg_lisp_pitr_set_locator_set_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lisp_pitr_set_locator_set_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_pitr_set_locator_set_reply payload;
} vapi_msg_lisp_pitr_set_locator_set_reply;

static inline void vapi_msg_lisp_pitr_set_locator_set_reply_payload_hton(vapi_payload_lisp_pitr_set_locator_set_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lisp_pitr_set_locator_set_reply_payload_ntoh(vapi_payload_lisp_pitr_set_locator_set_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lisp_pitr_set_locator_set_reply_hton(vapi_msg_lisp_pitr_set_locator_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_pitr_set_locator_set_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_pitr_set_locator_set_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_pitr_set_locator_set_reply_ntoh(vapi_msg_lisp_pitr_set_locator_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_pitr_set_locator_set_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_pitr_set_locator_set_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_pitr_set_locator_set_reply_msg_size(vapi_msg_lisp_pitr_set_locator_set_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_pitr_set_locator_set_reply_msg_size(vapi_msg_lisp_pitr_set_locator_set_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_pitr_set_locator_set_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_pitr_set_locator_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_pitr_set_locator_set_reply));
      return -1;
    }
  if (vapi_calc_lisp_pitr_set_locator_set_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_pitr_set_locator_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_pitr_set_locator_set_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_pitr_set_locator_set_reply()
{
  static const char name[] = "lisp_pitr_set_locator_set_reply";
  static const char name_with_crc[] = "lisp_pitr_set_locator_set_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lisp_pitr_set_locator_set_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_pitr_set_locator_set_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_pitr_set_locator_set_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_pitr_set_locator_set_reply_hton,
    (generic_swap_fn_t)vapi_msg_lisp_pitr_set_locator_set_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_pitr_set_locator_set_reply = vapi_register_msg(&__vapi_metadata_lisp_pitr_set_locator_set_reply);
  VAPI_DBG("Assigned msg id %d to lisp_pitr_set_locator_set_reply", vapi_msg_id_lisp_pitr_set_locator_set_reply);
}

static inline void vapi_set_vapi_msg_lisp_pitr_set_locator_set_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_pitr_set_locator_set_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_pitr_set_locator_set_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_pitr_set_locator_set
#define defined_vapi_msg_lisp_pitr_set_locator_set
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  u8 ls_name[64]; 
} vapi_payload_lisp_pitr_set_locator_set;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lisp_pitr_set_locator_set payload;
} vapi_msg_lisp_pitr_set_locator_set;

static inline void vapi_msg_lisp_pitr_set_locator_set_payload_hton(vapi_payload_lisp_pitr_set_locator_set *payload)
{

}

static inline void vapi_msg_lisp_pitr_set_locator_set_payload_ntoh(vapi_payload_lisp_pitr_set_locator_set *payload)
{

}

static inline void vapi_msg_lisp_pitr_set_locator_set_hton(vapi_msg_lisp_pitr_set_locator_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_pitr_set_locator_set'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lisp_pitr_set_locator_set_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_pitr_set_locator_set_ntoh(vapi_msg_lisp_pitr_set_locator_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_pitr_set_locator_set'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lisp_pitr_set_locator_set_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_pitr_set_locator_set_msg_size(vapi_msg_lisp_pitr_set_locator_set *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_pitr_set_locator_set_msg_size(vapi_msg_lisp_pitr_set_locator_set *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_pitr_set_locator_set) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_pitr_set_locator_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_pitr_set_locator_set));
      return -1;
    }
  if (vapi_calc_lisp_pitr_set_locator_set_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_pitr_set_locator_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_pitr_set_locator_set_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_pitr_set_locator_set* vapi_alloc_lisp_pitr_set_locator_set(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_pitr_set_locator_set *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_pitr_set_locator_set);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_pitr_set_locator_set*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_pitr_set_locator_set);

  return msg;
}

static inline vapi_error_e vapi_lisp_pitr_set_locator_set(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_pitr_set_locator_set *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_pitr_set_locator_set_reply *reply),
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
  vapi_msg_lisp_pitr_set_locator_set_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_pitr_set_locator_set_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lisp_pitr_set_locator_set_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_pitr_set_locator_set()
{
  static const char name[] = "lisp_pitr_set_locator_set";
  static const char name_with_crc[] = "lisp_pitr_set_locator_set_486e2b76";
  static vapi_message_desc_t __vapi_metadata_lisp_pitr_set_locator_set = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lisp_pitr_set_locator_set, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_pitr_set_locator_set_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_pitr_set_locator_set_hton,
    (generic_swap_fn_t)vapi_msg_lisp_pitr_set_locator_set_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_pitr_set_locator_set = vapi_register_msg(&__vapi_metadata_lisp_pitr_set_locator_set);
  VAPI_DBG("Assigned msg id %d to lisp_pitr_set_locator_set", vapi_msg_id_lisp_pitr_set_locator_set);
}
#endif

#ifndef defined_vapi_msg_lisp_use_petr_reply
#define defined_vapi_msg_lisp_use_petr_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lisp_use_petr_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_use_petr_reply payload;
} vapi_msg_lisp_use_petr_reply;

static inline void vapi_msg_lisp_use_petr_reply_payload_hton(vapi_payload_lisp_use_petr_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lisp_use_petr_reply_payload_ntoh(vapi_payload_lisp_use_petr_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lisp_use_petr_reply_hton(vapi_msg_lisp_use_petr_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_use_petr_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_use_petr_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_use_petr_reply_ntoh(vapi_msg_lisp_use_petr_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_use_petr_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_use_petr_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_use_petr_reply_msg_size(vapi_msg_lisp_use_petr_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_use_petr_reply_msg_size(vapi_msg_lisp_use_petr_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_use_petr_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_use_petr_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_use_petr_reply));
      return -1;
    }
  if (vapi_calc_lisp_use_petr_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_use_petr_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_use_petr_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_use_petr_reply()
{
  static const char name[] = "lisp_use_petr_reply";
  static const char name_with_crc[] = "lisp_use_petr_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lisp_use_petr_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_use_petr_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_use_petr_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_use_petr_reply_hton,
    (generic_swap_fn_t)vapi_msg_lisp_use_petr_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_use_petr_reply = vapi_register_msg(&__vapi_metadata_lisp_use_petr_reply);
  VAPI_DBG("Assigned msg id %d to lisp_use_petr_reply", vapi_msg_id_lisp_use_petr_reply);
}

static inline void vapi_set_vapi_msg_lisp_use_petr_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_use_petr_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_use_petr_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_use_petr
#define defined_vapi_msg_lisp_use_petr
typedef struct __attribute__ ((__packed__)) {
  vapi_type_address ip_address;
  bool is_add; 
} vapi_payload_lisp_use_petr;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lisp_use_petr payload;
} vapi_msg_lisp_use_petr;

static inline void vapi_msg_lisp_use_petr_payload_hton(vapi_payload_lisp_use_petr *payload)
{

}

static inline void vapi_msg_lisp_use_petr_payload_ntoh(vapi_payload_lisp_use_petr *payload)
{

}

static inline void vapi_msg_lisp_use_petr_hton(vapi_msg_lisp_use_petr *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_use_petr'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lisp_use_petr_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_use_petr_ntoh(vapi_msg_lisp_use_petr *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_use_petr'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lisp_use_petr_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_use_petr_msg_size(vapi_msg_lisp_use_petr *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_use_petr_msg_size(vapi_msg_lisp_use_petr *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_use_petr) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_use_petr' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_use_petr));
      return -1;
    }
  if (vapi_calc_lisp_use_petr_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_use_petr' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_use_petr_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_use_petr* vapi_alloc_lisp_use_petr(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_use_petr *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_use_petr);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_use_petr*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_use_petr);

  return msg;
}

static inline vapi_error_e vapi_lisp_use_petr(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_use_petr *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_use_petr_reply *reply),
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
  vapi_msg_lisp_use_petr_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_use_petr_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lisp_use_petr_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_use_petr()
{
  static const char name[] = "lisp_use_petr";
  static const char name_with_crc[] = "lisp_use_petr_d87dbad9";
  static vapi_message_desc_t __vapi_metadata_lisp_use_petr = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lisp_use_petr, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_use_petr_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_use_petr_hton,
    (generic_swap_fn_t)vapi_msg_lisp_use_petr_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_use_petr = vapi_register_msg(&__vapi_metadata_lisp_use_petr);
  VAPI_DBG("Assigned msg id %d to lisp_use_petr", vapi_msg_id_lisp_use_petr);
}
#endif

#ifndef defined_vapi_msg_show_lisp_use_petr_reply
#define defined_vapi_msg_show_lisp_use_petr_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  bool is_petr_enable;
  vapi_type_address ip_address; 
} vapi_payload_show_lisp_use_petr_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_show_lisp_use_petr_reply payload;
} vapi_msg_show_lisp_use_petr_reply;

static inline void vapi_msg_show_lisp_use_petr_reply_payload_hton(vapi_payload_show_lisp_use_petr_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_show_lisp_use_petr_reply_payload_ntoh(vapi_payload_show_lisp_use_petr_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_show_lisp_use_petr_reply_hton(vapi_msg_show_lisp_use_petr_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_use_petr_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_show_lisp_use_petr_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_show_lisp_use_petr_reply_ntoh(vapi_msg_show_lisp_use_petr_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_use_petr_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_show_lisp_use_petr_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_show_lisp_use_petr_reply_msg_size(vapi_msg_show_lisp_use_petr_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_show_lisp_use_petr_reply_msg_size(vapi_msg_show_lisp_use_petr_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_show_lisp_use_petr_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_use_petr_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_show_lisp_use_petr_reply));
      return -1;
    }
  if (vapi_calc_show_lisp_use_petr_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_use_petr_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_show_lisp_use_petr_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_show_lisp_use_petr_reply()
{
  static const char name[] = "show_lisp_use_petr_reply";
  static const char name_with_crc[] = "show_lisp_use_petr_reply_22b9a4b0";
  static vapi_message_desc_t __vapi_metadata_show_lisp_use_petr_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_show_lisp_use_petr_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_show_lisp_use_petr_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_show_lisp_use_petr_reply_hton,
    (generic_swap_fn_t)vapi_msg_show_lisp_use_petr_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_show_lisp_use_petr_reply = vapi_register_msg(&__vapi_metadata_show_lisp_use_petr_reply);
  VAPI_DBG("Assigned msg id %d to show_lisp_use_petr_reply", vapi_msg_id_show_lisp_use_petr_reply);
}

static inline void vapi_set_vapi_msg_show_lisp_use_petr_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_show_lisp_use_petr_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_show_lisp_use_petr_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_show_lisp_use_petr
#define defined_vapi_msg_show_lisp_use_petr
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_show_lisp_use_petr;

static inline void vapi_msg_show_lisp_use_petr_hton(vapi_msg_show_lisp_use_petr *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_use_petr'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_show_lisp_use_petr_ntoh(vapi_msg_show_lisp_use_petr *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_use_petr'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_show_lisp_use_petr_msg_size(vapi_msg_show_lisp_use_petr *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_show_lisp_use_petr_msg_size(vapi_msg_show_lisp_use_petr *msg, uword buf_size)
{
  if (sizeof(vapi_msg_show_lisp_use_petr) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_use_petr' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_show_lisp_use_petr));
      return -1;
    }
  if (vapi_calc_show_lisp_use_petr_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_use_petr' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_show_lisp_use_petr_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_show_lisp_use_petr* vapi_alloc_show_lisp_use_petr(struct vapi_ctx_s *ctx)
{
  vapi_msg_show_lisp_use_petr *msg = NULL;
  const size_t size = sizeof(vapi_msg_show_lisp_use_petr);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_show_lisp_use_petr*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_show_lisp_use_petr);

  return msg;
}

static inline vapi_error_e vapi_show_lisp_use_petr(struct vapi_ctx_s *ctx,
  vapi_msg_show_lisp_use_petr *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_show_lisp_use_petr_reply *reply),
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
  vapi_msg_show_lisp_use_petr_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_show_lisp_use_petr_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_show_lisp_use_petr_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_show_lisp_use_petr()
{
  static const char name[] = "show_lisp_use_petr";
  static const char name_with_crc[] = "show_lisp_use_petr_51077d14";
  static vapi_message_desc_t __vapi_metadata_show_lisp_use_petr = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_show_lisp_use_petr_msg_size,
    (generic_swap_fn_t)vapi_msg_show_lisp_use_petr_hton,
    (generic_swap_fn_t)vapi_msg_show_lisp_use_petr_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_show_lisp_use_petr = vapi_register_msg(&__vapi_metadata_show_lisp_use_petr);
  VAPI_DBG("Assigned msg id %d to show_lisp_use_petr", vapi_msg_id_show_lisp_use_petr);
}
#endif

#ifndef defined_vapi_msg_show_lisp_rloc_probe_state_reply
#define defined_vapi_msg_show_lisp_rloc_probe_state_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  bool is_enabled; 
} vapi_payload_show_lisp_rloc_probe_state_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_show_lisp_rloc_probe_state_reply payload;
} vapi_msg_show_lisp_rloc_probe_state_reply;

static inline void vapi_msg_show_lisp_rloc_probe_state_reply_payload_hton(vapi_payload_show_lisp_rloc_probe_state_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_show_lisp_rloc_probe_state_reply_payload_ntoh(vapi_payload_show_lisp_rloc_probe_state_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_show_lisp_rloc_probe_state_reply_hton(vapi_msg_show_lisp_rloc_probe_state_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_rloc_probe_state_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_show_lisp_rloc_probe_state_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_show_lisp_rloc_probe_state_reply_ntoh(vapi_msg_show_lisp_rloc_probe_state_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_rloc_probe_state_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_show_lisp_rloc_probe_state_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_show_lisp_rloc_probe_state_reply_msg_size(vapi_msg_show_lisp_rloc_probe_state_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_show_lisp_rloc_probe_state_reply_msg_size(vapi_msg_show_lisp_rloc_probe_state_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_show_lisp_rloc_probe_state_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_rloc_probe_state_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_show_lisp_rloc_probe_state_reply));
      return -1;
    }
  if (vapi_calc_show_lisp_rloc_probe_state_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_rloc_probe_state_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_show_lisp_rloc_probe_state_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_show_lisp_rloc_probe_state_reply()
{
  static const char name[] = "show_lisp_rloc_probe_state_reply";
  static const char name_with_crc[] = "show_lisp_rloc_probe_state_reply_e33a377b";
  static vapi_message_desc_t __vapi_metadata_show_lisp_rloc_probe_state_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_show_lisp_rloc_probe_state_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_show_lisp_rloc_probe_state_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_show_lisp_rloc_probe_state_reply_hton,
    (generic_swap_fn_t)vapi_msg_show_lisp_rloc_probe_state_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_show_lisp_rloc_probe_state_reply = vapi_register_msg(&__vapi_metadata_show_lisp_rloc_probe_state_reply);
  VAPI_DBG("Assigned msg id %d to show_lisp_rloc_probe_state_reply", vapi_msg_id_show_lisp_rloc_probe_state_reply);
}

static inline void vapi_set_vapi_msg_show_lisp_rloc_probe_state_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_show_lisp_rloc_probe_state_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_show_lisp_rloc_probe_state_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_show_lisp_rloc_probe_state
#define defined_vapi_msg_show_lisp_rloc_probe_state
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_show_lisp_rloc_probe_state;

static inline void vapi_msg_show_lisp_rloc_probe_state_hton(vapi_msg_show_lisp_rloc_probe_state *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_rloc_probe_state'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_show_lisp_rloc_probe_state_ntoh(vapi_msg_show_lisp_rloc_probe_state *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_rloc_probe_state'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_show_lisp_rloc_probe_state_msg_size(vapi_msg_show_lisp_rloc_probe_state *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_show_lisp_rloc_probe_state_msg_size(vapi_msg_show_lisp_rloc_probe_state *msg, uword buf_size)
{
  if (sizeof(vapi_msg_show_lisp_rloc_probe_state) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_rloc_probe_state' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_show_lisp_rloc_probe_state));
      return -1;
    }
  if (vapi_calc_show_lisp_rloc_probe_state_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_rloc_probe_state' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_show_lisp_rloc_probe_state_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_show_lisp_rloc_probe_state* vapi_alloc_show_lisp_rloc_probe_state(struct vapi_ctx_s *ctx)
{
  vapi_msg_show_lisp_rloc_probe_state *msg = NULL;
  const size_t size = sizeof(vapi_msg_show_lisp_rloc_probe_state);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_show_lisp_rloc_probe_state*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_show_lisp_rloc_probe_state);

  return msg;
}

static inline vapi_error_e vapi_show_lisp_rloc_probe_state(struct vapi_ctx_s *ctx,
  vapi_msg_show_lisp_rloc_probe_state *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_show_lisp_rloc_probe_state_reply *reply),
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
  vapi_msg_show_lisp_rloc_probe_state_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_show_lisp_rloc_probe_state_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_show_lisp_rloc_probe_state_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_show_lisp_rloc_probe_state()
{
  static const char name[] = "show_lisp_rloc_probe_state";
  static const char name_with_crc[] = "show_lisp_rloc_probe_state_51077d14";
  static vapi_message_desc_t __vapi_metadata_show_lisp_rloc_probe_state = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_show_lisp_rloc_probe_state_msg_size,
    (generic_swap_fn_t)vapi_msg_show_lisp_rloc_probe_state_hton,
    (generic_swap_fn_t)vapi_msg_show_lisp_rloc_probe_state_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_show_lisp_rloc_probe_state = vapi_register_msg(&__vapi_metadata_show_lisp_rloc_probe_state);
  VAPI_DBG("Assigned msg id %d to show_lisp_rloc_probe_state", vapi_msg_id_show_lisp_rloc_probe_state);
}
#endif

#ifndef defined_vapi_msg_lisp_rloc_probe_enable_disable_reply
#define defined_vapi_msg_lisp_rloc_probe_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lisp_rloc_probe_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_rloc_probe_enable_disable_reply payload;
} vapi_msg_lisp_rloc_probe_enable_disable_reply;

static inline void vapi_msg_lisp_rloc_probe_enable_disable_reply_payload_hton(vapi_payload_lisp_rloc_probe_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lisp_rloc_probe_enable_disable_reply_payload_ntoh(vapi_payload_lisp_rloc_probe_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lisp_rloc_probe_enable_disable_reply_hton(vapi_msg_lisp_rloc_probe_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_rloc_probe_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_rloc_probe_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_rloc_probe_enable_disable_reply_ntoh(vapi_msg_lisp_rloc_probe_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_rloc_probe_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_rloc_probe_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_rloc_probe_enable_disable_reply_msg_size(vapi_msg_lisp_rloc_probe_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_rloc_probe_enable_disable_reply_msg_size(vapi_msg_lisp_rloc_probe_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_rloc_probe_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_rloc_probe_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_rloc_probe_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_lisp_rloc_probe_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_rloc_probe_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_rloc_probe_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_rloc_probe_enable_disable_reply()
{
  static const char name[] = "lisp_rloc_probe_enable_disable_reply";
  static const char name_with_crc[] = "lisp_rloc_probe_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lisp_rloc_probe_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_rloc_probe_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_rloc_probe_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_rloc_probe_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_lisp_rloc_probe_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_rloc_probe_enable_disable_reply = vapi_register_msg(&__vapi_metadata_lisp_rloc_probe_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to lisp_rloc_probe_enable_disable_reply", vapi_msg_id_lisp_rloc_probe_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_lisp_rloc_probe_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_rloc_probe_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_rloc_probe_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_rloc_probe_enable_disable
#define defined_vapi_msg_lisp_rloc_probe_enable_disable
typedef struct __attribute__ ((__packed__)) {
  bool is_enable; 
} vapi_payload_lisp_rloc_probe_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lisp_rloc_probe_enable_disable payload;
} vapi_msg_lisp_rloc_probe_enable_disable;

static inline void vapi_msg_lisp_rloc_probe_enable_disable_payload_hton(vapi_payload_lisp_rloc_probe_enable_disable *payload)
{

}

static inline void vapi_msg_lisp_rloc_probe_enable_disable_payload_ntoh(vapi_payload_lisp_rloc_probe_enable_disable *payload)
{

}

static inline void vapi_msg_lisp_rloc_probe_enable_disable_hton(vapi_msg_lisp_rloc_probe_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_rloc_probe_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lisp_rloc_probe_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_rloc_probe_enable_disable_ntoh(vapi_msg_lisp_rloc_probe_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_rloc_probe_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lisp_rloc_probe_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_rloc_probe_enable_disable_msg_size(vapi_msg_lisp_rloc_probe_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_rloc_probe_enable_disable_msg_size(vapi_msg_lisp_rloc_probe_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_rloc_probe_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_rloc_probe_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_rloc_probe_enable_disable));
      return -1;
    }
  if (vapi_calc_lisp_rloc_probe_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_rloc_probe_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_rloc_probe_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_rloc_probe_enable_disable* vapi_alloc_lisp_rloc_probe_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_rloc_probe_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_rloc_probe_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_rloc_probe_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_rloc_probe_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_lisp_rloc_probe_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_rloc_probe_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_rloc_probe_enable_disable_reply *reply),
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
  vapi_msg_lisp_rloc_probe_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_rloc_probe_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lisp_rloc_probe_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_rloc_probe_enable_disable()
{
  static const char name[] = "lisp_rloc_probe_enable_disable";
  static const char name_with_crc[] = "lisp_rloc_probe_enable_disable_c264d7bf";
  static vapi_message_desc_t __vapi_metadata_lisp_rloc_probe_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lisp_rloc_probe_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_rloc_probe_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_rloc_probe_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_lisp_rloc_probe_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_rloc_probe_enable_disable = vapi_register_msg(&__vapi_metadata_lisp_rloc_probe_enable_disable);
  VAPI_DBG("Assigned msg id %d to lisp_rloc_probe_enable_disable", vapi_msg_id_lisp_rloc_probe_enable_disable);
}
#endif

#ifndef defined_vapi_msg_lisp_map_register_enable_disable_reply
#define defined_vapi_msg_lisp_map_register_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lisp_map_register_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_map_register_enable_disable_reply payload;
} vapi_msg_lisp_map_register_enable_disable_reply;

static inline void vapi_msg_lisp_map_register_enable_disable_reply_payload_hton(vapi_payload_lisp_map_register_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lisp_map_register_enable_disable_reply_payload_ntoh(vapi_payload_lisp_map_register_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lisp_map_register_enable_disable_reply_hton(vapi_msg_lisp_map_register_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_map_register_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_map_register_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_map_register_enable_disable_reply_ntoh(vapi_msg_lisp_map_register_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_map_register_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_map_register_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_map_register_enable_disable_reply_msg_size(vapi_msg_lisp_map_register_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_map_register_enable_disable_reply_msg_size(vapi_msg_lisp_map_register_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_map_register_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_map_register_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_map_register_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_lisp_map_register_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_map_register_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_map_register_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_map_register_enable_disable_reply()
{
  static const char name[] = "lisp_map_register_enable_disable_reply";
  static const char name_with_crc[] = "lisp_map_register_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lisp_map_register_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_map_register_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_map_register_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_map_register_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_lisp_map_register_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_map_register_enable_disable_reply = vapi_register_msg(&__vapi_metadata_lisp_map_register_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to lisp_map_register_enable_disable_reply", vapi_msg_id_lisp_map_register_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_lisp_map_register_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_map_register_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_map_register_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_map_register_enable_disable
#define defined_vapi_msg_lisp_map_register_enable_disable
typedef struct __attribute__ ((__packed__)) {
  bool is_enable; 
} vapi_payload_lisp_map_register_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lisp_map_register_enable_disable payload;
} vapi_msg_lisp_map_register_enable_disable;

static inline void vapi_msg_lisp_map_register_enable_disable_payload_hton(vapi_payload_lisp_map_register_enable_disable *payload)
{

}

static inline void vapi_msg_lisp_map_register_enable_disable_payload_ntoh(vapi_payload_lisp_map_register_enable_disable *payload)
{

}

static inline void vapi_msg_lisp_map_register_enable_disable_hton(vapi_msg_lisp_map_register_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_map_register_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lisp_map_register_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_map_register_enable_disable_ntoh(vapi_msg_lisp_map_register_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_map_register_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lisp_map_register_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_map_register_enable_disable_msg_size(vapi_msg_lisp_map_register_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_map_register_enable_disable_msg_size(vapi_msg_lisp_map_register_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_map_register_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_map_register_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_map_register_enable_disable));
      return -1;
    }
  if (vapi_calc_lisp_map_register_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_map_register_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_map_register_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_map_register_enable_disable* vapi_alloc_lisp_map_register_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_map_register_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_map_register_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_map_register_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_map_register_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_lisp_map_register_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_map_register_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_map_register_enable_disable_reply *reply),
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
  vapi_msg_lisp_map_register_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_map_register_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lisp_map_register_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_map_register_enable_disable()
{
  static const char name[] = "lisp_map_register_enable_disable";
  static const char name_with_crc[] = "lisp_map_register_enable_disable_c264d7bf";
  static vapi_message_desc_t __vapi_metadata_lisp_map_register_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lisp_map_register_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_map_register_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_map_register_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_lisp_map_register_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_map_register_enable_disable = vapi_register_msg(&__vapi_metadata_lisp_map_register_enable_disable);
  VAPI_DBG("Assigned msg id %d to lisp_map_register_enable_disable", vapi_msg_id_lisp_map_register_enable_disable);
}
#endif

#ifndef defined_vapi_msg_show_lisp_map_register_state_reply
#define defined_vapi_msg_show_lisp_map_register_state_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  bool is_enabled; 
} vapi_payload_show_lisp_map_register_state_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_show_lisp_map_register_state_reply payload;
} vapi_msg_show_lisp_map_register_state_reply;

static inline void vapi_msg_show_lisp_map_register_state_reply_payload_hton(vapi_payload_show_lisp_map_register_state_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_show_lisp_map_register_state_reply_payload_ntoh(vapi_payload_show_lisp_map_register_state_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_show_lisp_map_register_state_reply_hton(vapi_msg_show_lisp_map_register_state_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_map_register_state_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_show_lisp_map_register_state_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_show_lisp_map_register_state_reply_ntoh(vapi_msg_show_lisp_map_register_state_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_map_register_state_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_show_lisp_map_register_state_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_show_lisp_map_register_state_reply_msg_size(vapi_msg_show_lisp_map_register_state_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_show_lisp_map_register_state_reply_msg_size(vapi_msg_show_lisp_map_register_state_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_show_lisp_map_register_state_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_map_register_state_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_show_lisp_map_register_state_reply));
      return -1;
    }
  if (vapi_calc_show_lisp_map_register_state_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_map_register_state_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_show_lisp_map_register_state_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_show_lisp_map_register_state_reply()
{
  static const char name[] = "show_lisp_map_register_state_reply";
  static const char name_with_crc[] = "show_lisp_map_register_state_reply_e33a377b";
  static vapi_message_desc_t __vapi_metadata_show_lisp_map_register_state_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_show_lisp_map_register_state_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_show_lisp_map_register_state_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_show_lisp_map_register_state_reply_hton,
    (generic_swap_fn_t)vapi_msg_show_lisp_map_register_state_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_show_lisp_map_register_state_reply = vapi_register_msg(&__vapi_metadata_show_lisp_map_register_state_reply);
  VAPI_DBG("Assigned msg id %d to show_lisp_map_register_state_reply", vapi_msg_id_show_lisp_map_register_state_reply);
}

static inline void vapi_set_vapi_msg_show_lisp_map_register_state_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_show_lisp_map_register_state_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_show_lisp_map_register_state_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_show_lisp_map_register_state
#define defined_vapi_msg_show_lisp_map_register_state
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_show_lisp_map_register_state;

static inline void vapi_msg_show_lisp_map_register_state_hton(vapi_msg_show_lisp_map_register_state *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_map_register_state'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_show_lisp_map_register_state_ntoh(vapi_msg_show_lisp_map_register_state *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_map_register_state'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_show_lisp_map_register_state_msg_size(vapi_msg_show_lisp_map_register_state *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_show_lisp_map_register_state_msg_size(vapi_msg_show_lisp_map_register_state *msg, uword buf_size)
{
  if (sizeof(vapi_msg_show_lisp_map_register_state) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_map_register_state' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_show_lisp_map_register_state));
      return -1;
    }
  if (vapi_calc_show_lisp_map_register_state_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_map_register_state' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_show_lisp_map_register_state_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_show_lisp_map_register_state* vapi_alloc_show_lisp_map_register_state(struct vapi_ctx_s *ctx)
{
  vapi_msg_show_lisp_map_register_state *msg = NULL;
  const size_t size = sizeof(vapi_msg_show_lisp_map_register_state);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_show_lisp_map_register_state*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_show_lisp_map_register_state);

  return msg;
}

static inline vapi_error_e vapi_show_lisp_map_register_state(struct vapi_ctx_s *ctx,
  vapi_msg_show_lisp_map_register_state *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_show_lisp_map_register_state_reply *reply),
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
  vapi_msg_show_lisp_map_register_state_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_show_lisp_map_register_state_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_show_lisp_map_register_state_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_show_lisp_map_register_state()
{
  static const char name[] = "show_lisp_map_register_state";
  static const char name_with_crc[] = "show_lisp_map_register_state_51077d14";
  static vapi_message_desc_t __vapi_metadata_show_lisp_map_register_state = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_show_lisp_map_register_state_msg_size,
    (generic_swap_fn_t)vapi_msg_show_lisp_map_register_state_hton,
    (generic_swap_fn_t)vapi_msg_show_lisp_map_register_state_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_show_lisp_map_register_state = vapi_register_msg(&__vapi_metadata_show_lisp_map_register_state);
  VAPI_DBG("Assigned msg id %d to show_lisp_map_register_state", vapi_msg_id_show_lisp_map_register_state);
}
#endif

#ifndef defined_vapi_msg_lisp_map_request_mode_reply
#define defined_vapi_msg_lisp_map_request_mode_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lisp_map_request_mode_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_map_request_mode_reply payload;
} vapi_msg_lisp_map_request_mode_reply;

static inline void vapi_msg_lisp_map_request_mode_reply_payload_hton(vapi_payload_lisp_map_request_mode_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lisp_map_request_mode_reply_payload_ntoh(vapi_payload_lisp_map_request_mode_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lisp_map_request_mode_reply_hton(vapi_msg_lisp_map_request_mode_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_map_request_mode_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_map_request_mode_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_map_request_mode_reply_ntoh(vapi_msg_lisp_map_request_mode_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_map_request_mode_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_map_request_mode_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_map_request_mode_reply_msg_size(vapi_msg_lisp_map_request_mode_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_map_request_mode_reply_msg_size(vapi_msg_lisp_map_request_mode_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_map_request_mode_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_map_request_mode_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_map_request_mode_reply));
      return -1;
    }
  if (vapi_calc_lisp_map_request_mode_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_map_request_mode_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_map_request_mode_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_map_request_mode_reply()
{
  static const char name[] = "lisp_map_request_mode_reply";
  static const char name_with_crc[] = "lisp_map_request_mode_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lisp_map_request_mode_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_map_request_mode_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_map_request_mode_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_map_request_mode_reply_hton,
    (generic_swap_fn_t)vapi_msg_lisp_map_request_mode_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_map_request_mode_reply = vapi_register_msg(&__vapi_metadata_lisp_map_request_mode_reply);
  VAPI_DBG("Assigned msg id %d to lisp_map_request_mode_reply", vapi_msg_id_lisp_map_request_mode_reply);
}

static inline void vapi_set_vapi_msg_lisp_map_request_mode_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_map_request_mode_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_map_request_mode_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_map_request_mode
#define defined_vapi_msg_lisp_map_request_mode
typedef struct __attribute__ ((__packed__)) {
  bool is_src_dst; 
} vapi_payload_lisp_map_request_mode;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lisp_map_request_mode payload;
} vapi_msg_lisp_map_request_mode;

static inline void vapi_msg_lisp_map_request_mode_payload_hton(vapi_payload_lisp_map_request_mode *payload)
{

}

static inline void vapi_msg_lisp_map_request_mode_payload_ntoh(vapi_payload_lisp_map_request_mode *payload)
{

}

static inline void vapi_msg_lisp_map_request_mode_hton(vapi_msg_lisp_map_request_mode *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_map_request_mode'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lisp_map_request_mode_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_map_request_mode_ntoh(vapi_msg_lisp_map_request_mode *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_map_request_mode'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lisp_map_request_mode_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_map_request_mode_msg_size(vapi_msg_lisp_map_request_mode *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_map_request_mode_msg_size(vapi_msg_lisp_map_request_mode *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_map_request_mode) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_map_request_mode' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_map_request_mode));
      return -1;
    }
  if (vapi_calc_lisp_map_request_mode_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_map_request_mode' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_map_request_mode_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_map_request_mode* vapi_alloc_lisp_map_request_mode(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_map_request_mode *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_map_request_mode);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_map_request_mode*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_map_request_mode);

  return msg;
}

static inline vapi_error_e vapi_lisp_map_request_mode(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_map_request_mode *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_map_request_mode_reply *reply),
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
  vapi_msg_lisp_map_request_mode_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_map_request_mode_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lisp_map_request_mode_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_map_request_mode()
{
  static const char name[] = "lisp_map_request_mode";
  static const char name_with_crc[] = "lisp_map_request_mode_f43c26ae";
  static vapi_message_desc_t __vapi_metadata_lisp_map_request_mode = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lisp_map_request_mode, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_map_request_mode_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_map_request_mode_hton,
    (generic_swap_fn_t)vapi_msg_lisp_map_request_mode_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_map_request_mode = vapi_register_msg(&__vapi_metadata_lisp_map_request_mode);
  VAPI_DBG("Assigned msg id %d to lisp_map_request_mode", vapi_msg_id_lisp_map_request_mode);
}
#endif

#ifndef defined_vapi_msg_show_lisp_map_request_mode_reply
#define defined_vapi_msg_show_lisp_map_request_mode_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  bool is_src_dst; 
} vapi_payload_show_lisp_map_request_mode_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_show_lisp_map_request_mode_reply payload;
} vapi_msg_show_lisp_map_request_mode_reply;

static inline void vapi_msg_show_lisp_map_request_mode_reply_payload_hton(vapi_payload_show_lisp_map_request_mode_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_show_lisp_map_request_mode_reply_payload_ntoh(vapi_payload_show_lisp_map_request_mode_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_show_lisp_map_request_mode_reply_hton(vapi_msg_show_lisp_map_request_mode_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_map_request_mode_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_show_lisp_map_request_mode_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_show_lisp_map_request_mode_reply_ntoh(vapi_msg_show_lisp_map_request_mode_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_map_request_mode_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_show_lisp_map_request_mode_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_show_lisp_map_request_mode_reply_msg_size(vapi_msg_show_lisp_map_request_mode_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_show_lisp_map_request_mode_reply_msg_size(vapi_msg_show_lisp_map_request_mode_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_show_lisp_map_request_mode_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_map_request_mode_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_show_lisp_map_request_mode_reply));
      return -1;
    }
  if (vapi_calc_show_lisp_map_request_mode_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_map_request_mode_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_show_lisp_map_request_mode_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_show_lisp_map_request_mode_reply()
{
  static const char name[] = "show_lisp_map_request_mode_reply";
  static const char name_with_crc[] = "show_lisp_map_request_mode_reply_5b05038e";
  static vapi_message_desc_t __vapi_metadata_show_lisp_map_request_mode_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_show_lisp_map_request_mode_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_show_lisp_map_request_mode_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_show_lisp_map_request_mode_reply_hton,
    (generic_swap_fn_t)vapi_msg_show_lisp_map_request_mode_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_show_lisp_map_request_mode_reply = vapi_register_msg(&__vapi_metadata_show_lisp_map_request_mode_reply);
  VAPI_DBG("Assigned msg id %d to show_lisp_map_request_mode_reply", vapi_msg_id_show_lisp_map_request_mode_reply);
}

static inline void vapi_set_vapi_msg_show_lisp_map_request_mode_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_show_lisp_map_request_mode_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_show_lisp_map_request_mode_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_show_lisp_map_request_mode
#define defined_vapi_msg_show_lisp_map_request_mode
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_show_lisp_map_request_mode;

static inline void vapi_msg_show_lisp_map_request_mode_hton(vapi_msg_show_lisp_map_request_mode *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_map_request_mode'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_show_lisp_map_request_mode_ntoh(vapi_msg_show_lisp_map_request_mode *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_map_request_mode'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_show_lisp_map_request_mode_msg_size(vapi_msg_show_lisp_map_request_mode *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_show_lisp_map_request_mode_msg_size(vapi_msg_show_lisp_map_request_mode *msg, uword buf_size)
{
  if (sizeof(vapi_msg_show_lisp_map_request_mode) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_map_request_mode' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_show_lisp_map_request_mode));
      return -1;
    }
  if (vapi_calc_show_lisp_map_request_mode_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_map_request_mode' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_show_lisp_map_request_mode_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_show_lisp_map_request_mode* vapi_alloc_show_lisp_map_request_mode(struct vapi_ctx_s *ctx)
{
  vapi_msg_show_lisp_map_request_mode *msg = NULL;
  const size_t size = sizeof(vapi_msg_show_lisp_map_request_mode);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_show_lisp_map_request_mode*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_show_lisp_map_request_mode);

  return msg;
}

static inline vapi_error_e vapi_show_lisp_map_request_mode(struct vapi_ctx_s *ctx,
  vapi_msg_show_lisp_map_request_mode *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_show_lisp_map_request_mode_reply *reply),
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
  vapi_msg_show_lisp_map_request_mode_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_show_lisp_map_request_mode_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_show_lisp_map_request_mode_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_show_lisp_map_request_mode()
{
  static const char name[] = "show_lisp_map_request_mode";
  static const char name_with_crc[] = "show_lisp_map_request_mode_51077d14";
  static vapi_message_desc_t __vapi_metadata_show_lisp_map_request_mode = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_show_lisp_map_request_mode_msg_size,
    (generic_swap_fn_t)vapi_msg_show_lisp_map_request_mode_hton,
    (generic_swap_fn_t)vapi_msg_show_lisp_map_request_mode_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_show_lisp_map_request_mode = vapi_register_msg(&__vapi_metadata_show_lisp_map_request_mode);
  VAPI_DBG("Assigned msg id %d to show_lisp_map_request_mode", vapi_msg_id_show_lisp_map_request_mode);
}
#endif

#ifndef defined_vapi_msg_lisp_add_del_remote_mapping_reply
#define defined_vapi_msg_lisp_add_del_remote_mapping_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lisp_add_del_remote_mapping_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_add_del_remote_mapping_reply payload;
} vapi_msg_lisp_add_del_remote_mapping_reply;

static inline void vapi_msg_lisp_add_del_remote_mapping_reply_payload_hton(vapi_payload_lisp_add_del_remote_mapping_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lisp_add_del_remote_mapping_reply_payload_ntoh(vapi_payload_lisp_add_del_remote_mapping_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lisp_add_del_remote_mapping_reply_hton(vapi_msg_lisp_add_del_remote_mapping_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_remote_mapping_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_add_del_remote_mapping_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_add_del_remote_mapping_reply_ntoh(vapi_msg_lisp_add_del_remote_mapping_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_remote_mapping_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_add_del_remote_mapping_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_add_del_remote_mapping_reply_msg_size(vapi_msg_lisp_add_del_remote_mapping_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_add_del_remote_mapping_reply_msg_size(vapi_msg_lisp_add_del_remote_mapping_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_add_del_remote_mapping_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_remote_mapping_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_add_del_remote_mapping_reply));
      return -1;
    }
  if (vapi_calc_lisp_add_del_remote_mapping_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_remote_mapping_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_add_del_remote_mapping_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_add_del_remote_mapping_reply()
{
  static const char name[] = "lisp_add_del_remote_mapping_reply";
  static const char name_with_crc[] = "lisp_add_del_remote_mapping_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lisp_add_del_remote_mapping_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_add_del_remote_mapping_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_add_del_remote_mapping_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_remote_mapping_reply_hton,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_remote_mapping_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_add_del_remote_mapping_reply = vapi_register_msg(&__vapi_metadata_lisp_add_del_remote_mapping_reply);
  VAPI_DBG("Assigned msg id %d to lisp_add_del_remote_mapping_reply", vapi_msg_id_lisp_add_del_remote_mapping_reply);
}

static inline void vapi_set_vapi_msg_lisp_add_del_remote_mapping_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_add_del_remote_mapping_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_add_del_remote_mapping_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_add_del_remote_mapping
#define defined_vapi_msg_lisp_add_del_remote_mapping
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  bool is_src_dst;
  bool del_all;
  u32 vni;
  u8 action;
  vapi_type_eid deid;
  vapi_type_eid seid;
  u32 rloc_num;
  vapi_type_remote_locator rlocs[0]; 
} vapi_payload_lisp_add_del_remote_mapping;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lisp_add_del_remote_mapping payload;
} vapi_msg_lisp_add_del_remote_mapping;

static inline void vapi_msg_lisp_add_del_remote_mapping_payload_hton(vapi_payload_lisp_add_del_remote_mapping *payload)
{
  payload->vni = htobe32(payload->vni);
  payload->rloc_num = htobe32(payload->rloc_num);
}

static inline void vapi_msg_lisp_add_del_remote_mapping_payload_ntoh(vapi_payload_lisp_add_del_remote_mapping *payload)
{
  payload->vni = be32toh(payload->vni);
  payload->rloc_num = be32toh(payload->rloc_num);
}

static inline void vapi_msg_lisp_add_del_remote_mapping_hton(vapi_msg_lisp_add_del_remote_mapping *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_remote_mapping'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lisp_add_del_remote_mapping_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_add_del_remote_mapping_ntoh(vapi_msg_lisp_add_del_remote_mapping *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_remote_mapping'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lisp_add_del_remote_mapping_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_add_del_remote_mapping_msg_size(vapi_msg_lisp_add_del_remote_mapping *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.rlocs[0]) * msg->payload.rloc_num;
}

static inline int vapi_verify_lisp_add_del_remote_mapping_msg_size(vapi_msg_lisp_add_del_remote_mapping *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_add_del_remote_mapping) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_remote_mapping' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_add_del_remote_mapping));
      return -1;
    }
  if (vapi_calc_lisp_add_del_remote_mapping_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_remote_mapping' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_add_del_remote_mapping_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_add_del_remote_mapping* vapi_alloc_lisp_add_del_remote_mapping(struct vapi_ctx_s *ctx, size_t _rlocs_array_size)
{
  vapi_msg_lisp_add_del_remote_mapping *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_add_del_remote_mapping) + sizeof(msg->payload.rlocs[0]) * _rlocs_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_add_del_remote_mapping*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_add_del_remote_mapping);
  msg->payload.rloc_num = _rlocs_array_size;

  return msg;
}

static inline vapi_error_e vapi_lisp_add_del_remote_mapping(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_add_del_remote_mapping *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_add_del_remote_mapping_reply *reply),
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
  vapi_msg_lisp_add_del_remote_mapping_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_add_del_remote_mapping_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lisp_add_del_remote_mapping_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_add_del_remote_mapping()
{
  static const char name[] = "lisp_add_del_remote_mapping";
  static const char name_with_crc[] = "lisp_add_del_remote_mapping_6d5c789e";
  static vapi_message_desc_t __vapi_metadata_lisp_add_del_remote_mapping = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lisp_add_del_remote_mapping, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_add_del_remote_mapping_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_remote_mapping_hton,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_remote_mapping_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_add_del_remote_mapping = vapi_register_msg(&__vapi_metadata_lisp_add_del_remote_mapping);
  VAPI_DBG("Assigned msg id %d to lisp_add_del_remote_mapping", vapi_msg_id_lisp_add_del_remote_mapping);
}
#endif

#ifndef defined_vapi_msg_lisp_add_del_adjacency_reply
#define defined_vapi_msg_lisp_add_del_adjacency_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lisp_add_del_adjacency_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_add_del_adjacency_reply payload;
} vapi_msg_lisp_add_del_adjacency_reply;

static inline void vapi_msg_lisp_add_del_adjacency_reply_payload_hton(vapi_payload_lisp_add_del_adjacency_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lisp_add_del_adjacency_reply_payload_ntoh(vapi_payload_lisp_add_del_adjacency_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lisp_add_del_adjacency_reply_hton(vapi_msg_lisp_add_del_adjacency_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_adjacency_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_add_del_adjacency_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_add_del_adjacency_reply_ntoh(vapi_msg_lisp_add_del_adjacency_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_adjacency_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_add_del_adjacency_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_add_del_adjacency_reply_msg_size(vapi_msg_lisp_add_del_adjacency_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_add_del_adjacency_reply_msg_size(vapi_msg_lisp_add_del_adjacency_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_add_del_adjacency_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_adjacency_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_add_del_adjacency_reply));
      return -1;
    }
  if (vapi_calc_lisp_add_del_adjacency_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_adjacency_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_add_del_adjacency_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_add_del_adjacency_reply()
{
  static const char name[] = "lisp_add_del_adjacency_reply";
  static const char name_with_crc[] = "lisp_add_del_adjacency_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lisp_add_del_adjacency_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_add_del_adjacency_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_add_del_adjacency_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_adjacency_reply_hton,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_adjacency_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_add_del_adjacency_reply = vapi_register_msg(&__vapi_metadata_lisp_add_del_adjacency_reply);
  VAPI_DBG("Assigned msg id %d to lisp_add_del_adjacency_reply", vapi_msg_id_lisp_add_del_adjacency_reply);
}

static inline void vapi_set_vapi_msg_lisp_add_del_adjacency_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_add_del_adjacency_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_add_del_adjacency_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_add_del_adjacency
#define defined_vapi_msg_lisp_add_del_adjacency
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  u32 vni;
  vapi_type_eid reid;
  vapi_type_eid leid; 
} vapi_payload_lisp_add_del_adjacency;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lisp_add_del_adjacency payload;
} vapi_msg_lisp_add_del_adjacency;

static inline void vapi_msg_lisp_add_del_adjacency_payload_hton(vapi_payload_lisp_add_del_adjacency *payload)
{
  payload->vni = htobe32(payload->vni);
}

static inline void vapi_msg_lisp_add_del_adjacency_payload_ntoh(vapi_payload_lisp_add_del_adjacency *payload)
{
  payload->vni = be32toh(payload->vni);
}

static inline void vapi_msg_lisp_add_del_adjacency_hton(vapi_msg_lisp_add_del_adjacency *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_adjacency'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lisp_add_del_adjacency_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_add_del_adjacency_ntoh(vapi_msg_lisp_add_del_adjacency *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_adjacency'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lisp_add_del_adjacency_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_add_del_adjacency_msg_size(vapi_msg_lisp_add_del_adjacency *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_add_del_adjacency_msg_size(vapi_msg_lisp_add_del_adjacency *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_add_del_adjacency) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_adjacency' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_add_del_adjacency));
      return -1;
    }
  if (vapi_calc_lisp_add_del_adjacency_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_adjacency' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_add_del_adjacency_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_add_del_adjacency* vapi_alloc_lisp_add_del_adjacency(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_add_del_adjacency *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_add_del_adjacency);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_add_del_adjacency*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_add_del_adjacency);

  return msg;
}

static inline vapi_error_e vapi_lisp_add_del_adjacency(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_add_del_adjacency *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_add_del_adjacency_reply *reply),
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
  vapi_msg_lisp_add_del_adjacency_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_add_del_adjacency_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lisp_add_del_adjacency_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_add_del_adjacency()
{
  static const char name[] = "lisp_add_del_adjacency";
  static const char name_with_crc[] = "lisp_add_del_adjacency_2ce0e6f6";
  static vapi_message_desc_t __vapi_metadata_lisp_add_del_adjacency = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lisp_add_del_adjacency, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_add_del_adjacency_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_adjacency_hton,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_adjacency_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_add_del_adjacency = vapi_register_msg(&__vapi_metadata_lisp_add_del_adjacency);
  VAPI_DBG("Assigned msg id %d to lisp_add_del_adjacency", vapi_msg_id_lisp_add_del_adjacency);
}
#endif

#ifndef defined_vapi_msg_lisp_add_del_map_request_itr_rlocs_reply
#define defined_vapi_msg_lisp_add_del_map_request_itr_rlocs_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lisp_add_del_map_request_itr_rlocs_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_add_del_map_request_itr_rlocs_reply payload;
} vapi_msg_lisp_add_del_map_request_itr_rlocs_reply;

static inline void vapi_msg_lisp_add_del_map_request_itr_rlocs_reply_payload_hton(vapi_payload_lisp_add_del_map_request_itr_rlocs_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lisp_add_del_map_request_itr_rlocs_reply_payload_ntoh(vapi_payload_lisp_add_del_map_request_itr_rlocs_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lisp_add_del_map_request_itr_rlocs_reply_hton(vapi_msg_lisp_add_del_map_request_itr_rlocs_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_map_request_itr_rlocs_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_add_del_map_request_itr_rlocs_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_add_del_map_request_itr_rlocs_reply_ntoh(vapi_msg_lisp_add_del_map_request_itr_rlocs_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_map_request_itr_rlocs_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_add_del_map_request_itr_rlocs_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_add_del_map_request_itr_rlocs_reply_msg_size(vapi_msg_lisp_add_del_map_request_itr_rlocs_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_add_del_map_request_itr_rlocs_reply_msg_size(vapi_msg_lisp_add_del_map_request_itr_rlocs_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_add_del_map_request_itr_rlocs_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_map_request_itr_rlocs_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_add_del_map_request_itr_rlocs_reply));
      return -1;
    }
  if (vapi_calc_lisp_add_del_map_request_itr_rlocs_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_map_request_itr_rlocs_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_add_del_map_request_itr_rlocs_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_add_del_map_request_itr_rlocs_reply()
{
  static const char name[] = "lisp_add_del_map_request_itr_rlocs_reply";
  static const char name_with_crc[] = "lisp_add_del_map_request_itr_rlocs_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lisp_add_del_map_request_itr_rlocs_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_add_del_map_request_itr_rlocs_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_add_del_map_request_itr_rlocs_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_map_request_itr_rlocs_reply_hton,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_map_request_itr_rlocs_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_add_del_map_request_itr_rlocs_reply = vapi_register_msg(&__vapi_metadata_lisp_add_del_map_request_itr_rlocs_reply);
  VAPI_DBG("Assigned msg id %d to lisp_add_del_map_request_itr_rlocs_reply", vapi_msg_id_lisp_add_del_map_request_itr_rlocs_reply);
}

static inline void vapi_set_vapi_msg_lisp_add_del_map_request_itr_rlocs_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_add_del_map_request_itr_rlocs_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_add_del_map_request_itr_rlocs_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_add_del_map_request_itr_rlocs
#define defined_vapi_msg_lisp_add_del_map_request_itr_rlocs
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  u8 locator_set_name[64]; 
} vapi_payload_lisp_add_del_map_request_itr_rlocs;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lisp_add_del_map_request_itr_rlocs payload;
} vapi_msg_lisp_add_del_map_request_itr_rlocs;

static inline void vapi_msg_lisp_add_del_map_request_itr_rlocs_payload_hton(vapi_payload_lisp_add_del_map_request_itr_rlocs *payload)
{

}

static inline void vapi_msg_lisp_add_del_map_request_itr_rlocs_payload_ntoh(vapi_payload_lisp_add_del_map_request_itr_rlocs *payload)
{

}

static inline void vapi_msg_lisp_add_del_map_request_itr_rlocs_hton(vapi_msg_lisp_add_del_map_request_itr_rlocs *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_map_request_itr_rlocs'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lisp_add_del_map_request_itr_rlocs_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_add_del_map_request_itr_rlocs_ntoh(vapi_msg_lisp_add_del_map_request_itr_rlocs *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_add_del_map_request_itr_rlocs'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lisp_add_del_map_request_itr_rlocs_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_add_del_map_request_itr_rlocs_msg_size(vapi_msg_lisp_add_del_map_request_itr_rlocs *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_add_del_map_request_itr_rlocs_msg_size(vapi_msg_lisp_add_del_map_request_itr_rlocs *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_add_del_map_request_itr_rlocs) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_map_request_itr_rlocs' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_add_del_map_request_itr_rlocs));
      return -1;
    }
  if (vapi_calc_lisp_add_del_map_request_itr_rlocs_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_add_del_map_request_itr_rlocs' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_add_del_map_request_itr_rlocs_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_add_del_map_request_itr_rlocs* vapi_alloc_lisp_add_del_map_request_itr_rlocs(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_add_del_map_request_itr_rlocs *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_add_del_map_request_itr_rlocs);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_add_del_map_request_itr_rlocs*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_add_del_map_request_itr_rlocs);

  return msg;
}

static inline vapi_error_e vapi_lisp_add_del_map_request_itr_rlocs(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_add_del_map_request_itr_rlocs *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_add_del_map_request_itr_rlocs_reply *reply),
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
  vapi_msg_lisp_add_del_map_request_itr_rlocs_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_add_del_map_request_itr_rlocs_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lisp_add_del_map_request_itr_rlocs_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_add_del_map_request_itr_rlocs()
{
  static const char name[] = "lisp_add_del_map_request_itr_rlocs";
  static const char name_with_crc[] = "lisp_add_del_map_request_itr_rlocs_6be88e45";
  static vapi_message_desc_t __vapi_metadata_lisp_add_del_map_request_itr_rlocs = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lisp_add_del_map_request_itr_rlocs, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_add_del_map_request_itr_rlocs_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_map_request_itr_rlocs_hton,
    (generic_swap_fn_t)vapi_msg_lisp_add_del_map_request_itr_rlocs_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_add_del_map_request_itr_rlocs = vapi_register_msg(&__vapi_metadata_lisp_add_del_map_request_itr_rlocs);
  VAPI_DBG("Assigned msg id %d to lisp_add_del_map_request_itr_rlocs", vapi_msg_id_lisp_add_del_map_request_itr_rlocs);
}
#endif

#ifndef defined_vapi_msg_lisp_eid_table_add_del_map_reply
#define defined_vapi_msg_lisp_eid_table_add_del_map_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lisp_eid_table_add_del_map_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_eid_table_add_del_map_reply payload;
} vapi_msg_lisp_eid_table_add_del_map_reply;

static inline void vapi_msg_lisp_eid_table_add_del_map_reply_payload_hton(vapi_payload_lisp_eid_table_add_del_map_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lisp_eid_table_add_del_map_reply_payload_ntoh(vapi_payload_lisp_eid_table_add_del_map_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lisp_eid_table_add_del_map_reply_hton(vapi_msg_lisp_eid_table_add_del_map_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_eid_table_add_del_map_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_eid_table_add_del_map_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_eid_table_add_del_map_reply_ntoh(vapi_msg_lisp_eid_table_add_del_map_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_eid_table_add_del_map_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_eid_table_add_del_map_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_eid_table_add_del_map_reply_msg_size(vapi_msg_lisp_eid_table_add_del_map_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_eid_table_add_del_map_reply_msg_size(vapi_msg_lisp_eid_table_add_del_map_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_eid_table_add_del_map_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_eid_table_add_del_map_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_eid_table_add_del_map_reply));
      return -1;
    }
  if (vapi_calc_lisp_eid_table_add_del_map_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_eid_table_add_del_map_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_eid_table_add_del_map_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_eid_table_add_del_map_reply()
{
  static const char name[] = "lisp_eid_table_add_del_map_reply";
  static const char name_with_crc[] = "lisp_eid_table_add_del_map_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lisp_eid_table_add_del_map_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_eid_table_add_del_map_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_eid_table_add_del_map_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_eid_table_add_del_map_reply_hton,
    (generic_swap_fn_t)vapi_msg_lisp_eid_table_add_del_map_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_eid_table_add_del_map_reply = vapi_register_msg(&__vapi_metadata_lisp_eid_table_add_del_map_reply);
  VAPI_DBG("Assigned msg id %d to lisp_eid_table_add_del_map_reply", vapi_msg_id_lisp_eid_table_add_del_map_reply);
}

static inline void vapi_set_vapi_msg_lisp_eid_table_add_del_map_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_eid_table_add_del_map_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_eid_table_add_del_map_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_eid_table_add_del_map
#define defined_vapi_msg_lisp_eid_table_add_del_map
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  u32 vni;
  u32 dp_table;
  bool is_l2; 
} vapi_payload_lisp_eid_table_add_del_map;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lisp_eid_table_add_del_map payload;
} vapi_msg_lisp_eid_table_add_del_map;

static inline void vapi_msg_lisp_eid_table_add_del_map_payload_hton(vapi_payload_lisp_eid_table_add_del_map *payload)
{
  payload->vni = htobe32(payload->vni);
  payload->dp_table = htobe32(payload->dp_table);
}

static inline void vapi_msg_lisp_eid_table_add_del_map_payload_ntoh(vapi_payload_lisp_eid_table_add_del_map *payload)
{
  payload->vni = be32toh(payload->vni);
  payload->dp_table = be32toh(payload->dp_table);
}

static inline void vapi_msg_lisp_eid_table_add_del_map_hton(vapi_msg_lisp_eid_table_add_del_map *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_eid_table_add_del_map'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lisp_eid_table_add_del_map_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_eid_table_add_del_map_ntoh(vapi_msg_lisp_eid_table_add_del_map *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_eid_table_add_del_map'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lisp_eid_table_add_del_map_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_eid_table_add_del_map_msg_size(vapi_msg_lisp_eid_table_add_del_map *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_eid_table_add_del_map_msg_size(vapi_msg_lisp_eid_table_add_del_map *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_eid_table_add_del_map) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_eid_table_add_del_map' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_eid_table_add_del_map));
      return -1;
    }
  if (vapi_calc_lisp_eid_table_add_del_map_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_eid_table_add_del_map' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_eid_table_add_del_map_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_eid_table_add_del_map* vapi_alloc_lisp_eid_table_add_del_map(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_eid_table_add_del_map *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_eid_table_add_del_map);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_eid_table_add_del_map*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_eid_table_add_del_map);

  return msg;
}

static inline vapi_error_e vapi_lisp_eid_table_add_del_map(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_eid_table_add_del_map *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_eid_table_add_del_map_reply *reply),
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
  vapi_msg_lisp_eid_table_add_del_map_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_eid_table_add_del_map_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lisp_eid_table_add_del_map_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_eid_table_add_del_map()
{
  static const char name[] = "lisp_eid_table_add_del_map";
  static const char name_with_crc[] = "lisp_eid_table_add_del_map_9481416b";
  static vapi_message_desc_t __vapi_metadata_lisp_eid_table_add_del_map = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lisp_eid_table_add_del_map, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_eid_table_add_del_map_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_eid_table_add_del_map_hton,
    (generic_swap_fn_t)vapi_msg_lisp_eid_table_add_del_map_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_eid_table_add_del_map = vapi_register_msg(&__vapi_metadata_lisp_eid_table_add_del_map);
  VAPI_DBG("Assigned msg id %d to lisp_eid_table_add_del_map", vapi_msg_id_lisp_eid_table_add_del_map);
}
#endif

#ifndef defined_vapi_msg_lisp_locator_details
#define defined_vapi_msg_lisp_locator_details
typedef struct __attribute__ ((__packed__)) {
  u8 local;
  vapi_type_interface_index sw_if_index;
  vapi_type_address ip_address;
  u8 priority;
  u8 weight; 
} vapi_payload_lisp_locator_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_locator_details payload;
} vapi_msg_lisp_locator_details;

static inline void vapi_msg_lisp_locator_details_payload_hton(vapi_payload_lisp_locator_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_lisp_locator_details_payload_ntoh(vapi_payload_lisp_locator_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_lisp_locator_details_hton(vapi_msg_lisp_locator_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_locator_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_locator_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_locator_details_ntoh(vapi_msg_lisp_locator_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_locator_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_locator_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_locator_details_msg_size(vapi_msg_lisp_locator_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_locator_details_msg_size(vapi_msg_lisp_locator_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_locator_details) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_locator_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_locator_details));
      return -1;
    }
  if (vapi_calc_lisp_locator_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_locator_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_locator_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_locator_details()
{
  static const char name[] = "lisp_locator_details";
  static const char name_with_crc[] = "lisp_locator_details_2c620ffe";
  static vapi_message_desc_t __vapi_metadata_lisp_locator_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_locator_details, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_locator_details_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_locator_details_hton,
    (generic_swap_fn_t)vapi_msg_lisp_locator_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_locator_details = vapi_register_msg(&__vapi_metadata_lisp_locator_details);
  VAPI_DBG("Assigned msg id %d to lisp_locator_details", vapi_msg_id_lisp_locator_details);
}

static inline void vapi_set_vapi_msg_lisp_locator_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_locator_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_locator_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_locator_dump
#define defined_vapi_msg_lisp_locator_dump
typedef struct __attribute__ ((__packed__)) {
  u32 ls_index;
  u8 ls_name[64];
  u8 is_index_set; 
} vapi_payload_lisp_locator_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lisp_locator_dump payload;
} vapi_msg_lisp_locator_dump;

static inline void vapi_msg_lisp_locator_dump_payload_hton(vapi_payload_lisp_locator_dump *payload)
{
  payload->ls_index = htobe32(payload->ls_index);
}

static inline void vapi_msg_lisp_locator_dump_payload_ntoh(vapi_payload_lisp_locator_dump *payload)
{
  payload->ls_index = be32toh(payload->ls_index);
}

static inline void vapi_msg_lisp_locator_dump_hton(vapi_msg_lisp_locator_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_locator_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lisp_locator_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_locator_dump_ntoh(vapi_msg_lisp_locator_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_locator_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lisp_locator_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_locator_dump_msg_size(vapi_msg_lisp_locator_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_locator_dump_msg_size(vapi_msg_lisp_locator_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_locator_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_locator_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_locator_dump));
      return -1;
    }
  if (vapi_calc_lisp_locator_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_locator_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_locator_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_locator_dump* vapi_alloc_lisp_locator_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_locator_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_locator_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_locator_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_locator_dump);

  return msg;
}

static inline vapi_error_e vapi_lisp_locator_dump(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_locator_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_locator_details *reply),
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
  vapi_msg_lisp_locator_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_locator_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_lisp_locator_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_locator_dump()
{
  static const char name[] = "lisp_locator_dump";
  static const char name_with_crc[] = "lisp_locator_dump_b954fad7";
  static vapi_message_desc_t __vapi_metadata_lisp_locator_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lisp_locator_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_locator_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_locator_dump_hton,
    (generic_swap_fn_t)vapi_msg_lisp_locator_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_locator_dump = vapi_register_msg(&__vapi_metadata_lisp_locator_dump);
  VAPI_DBG("Assigned msg id %d to lisp_locator_dump", vapi_msg_id_lisp_locator_dump);
}
#endif

#ifndef defined_vapi_msg_lisp_locator_set_details
#define defined_vapi_msg_lisp_locator_set_details
typedef struct __attribute__ ((__packed__)) {
  u32 ls_index;
  u8 ls_name[64]; 
} vapi_payload_lisp_locator_set_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_locator_set_details payload;
} vapi_msg_lisp_locator_set_details;

static inline void vapi_msg_lisp_locator_set_details_payload_hton(vapi_payload_lisp_locator_set_details *payload)
{
  payload->ls_index = htobe32(payload->ls_index);
}

static inline void vapi_msg_lisp_locator_set_details_payload_ntoh(vapi_payload_lisp_locator_set_details *payload)
{
  payload->ls_index = be32toh(payload->ls_index);
}

static inline void vapi_msg_lisp_locator_set_details_hton(vapi_msg_lisp_locator_set_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_locator_set_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_locator_set_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_locator_set_details_ntoh(vapi_msg_lisp_locator_set_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_locator_set_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_locator_set_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_locator_set_details_msg_size(vapi_msg_lisp_locator_set_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_locator_set_details_msg_size(vapi_msg_lisp_locator_set_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_locator_set_details) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_locator_set_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_locator_set_details));
      return -1;
    }
  if (vapi_calc_lisp_locator_set_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_locator_set_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_locator_set_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_locator_set_details()
{
  static const char name[] = "lisp_locator_set_details";
  static const char name_with_crc[] = "lisp_locator_set_details_5b33a105";
  static vapi_message_desc_t __vapi_metadata_lisp_locator_set_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_locator_set_details, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_locator_set_details_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_locator_set_details_hton,
    (generic_swap_fn_t)vapi_msg_lisp_locator_set_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_locator_set_details = vapi_register_msg(&__vapi_metadata_lisp_locator_set_details);
  VAPI_DBG("Assigned msg id %d to lisp_locator_set_details", vapi_msg_id_lisp_locator_set_details);
}

static inline void vapi_set_vapi_msg_lisp_locator_set_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_locator_set_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_locator_set_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_locator_set_dump
#define defined_vapi_msg_lisp_locator_set_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_lisp_locator_set_filter filter; 
} vapi_payload_lisp_locator_set_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lisp_locator_set_dump payload;
} vapi_msg_lisp_locator_set_dump;

static inline void vapi_msg_lisp_locator_set_dump_payload_hton(vapi_payload_lisp_locator_set_dump *payload)
{

}

static inline void vapi_msg_lisp_locator_set_dump_payload_ntoh(vapi_payload_lisp_locator_set_dump *payload)
{

}

static inline void vapi_msg_lisp_locator_set_dump_hton(vapi_msg_lisp_locator_set_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_locator_set_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lisp_locator_set_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_locator_set_dump_ntoh(vapi_msg_lisp_locator_set_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_locator_set_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lisp_locator_set_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_locator_set_dump_msg_size(vapi_msg_lisp_locator_set_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_locator_set_dump_msg_size(vapi_msg_lisp_locator_set_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_locator_set_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_locator_set_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_locator_set_dump));
      return -1;
    }
  if (vapi_calc_lisp_locator_set_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_locator_set_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_locator_set_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_locator_set_dump* vapi_alloc_lisp_locator_set_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_locator_set_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_locator_set_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_locator_set_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_locator_set_dump);

  return msg;
}

static inline vapi_error_e vapi_lisp_locator_set_dump(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_locator_set_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_locator_set_details *reply),
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
  vapi_msg_lisp_locator_set_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_locator_set_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_lisp_locator_set_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_locator_set_dump()
{
  static const char name[] = "lisp_locator_set_dump";
  static const char name_with_crc[] = "lisp_locator_set_dump_c2cb5922";
  static vapi_message_desc_t __vapi_metadata_lisp_locator_set_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lisp_locator_set_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_locator_set_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_locator_set_dump_hton,
    (generic_swap_fn_t)vapi_msg_lisp_locator_set_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_locator_set_dump = vapi_register_msg(&__vapi_metadata_lisp_locator_set_dump);
  VAPI_DBG("Assigned msg id %d to lisp_locator_set_dump", vapi_msg_id_lisp_locator_set_dump);
}
#endif

#ifndef defined_vapi_msg_lisp_eid_table_details
#define defined_vapi_msg_lisp_eid_table_details
typedef struct __attribute__ ((__packed__)) {
  u32 locator_set_index;
  u8 action;
  bool is_local;
  bool is_src_dst;
  u32 vni;
  vapi_type_eid deid;
  vapi_type_eid seid;
  u32 ttl;
  u8 authoritative;
  vapi_type_hmac_key key; 
} vapi_payload_lisp_eid_table_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_eid_table_details payload;
} vapi_msg_lisp_eid_table_details;

static inline void vapi_msg_lisp_eid_table_details_payload_hton(vapi_payload_lisp_eid_table_details *payload)
{
  payload->locator_set_index = htobe32(payload->locator_set_index);
  payload->vni = htobe32(payload->vni);
  payload->ttl = htobe32(payload->ttl);
}

static inline void vapi_msg_lisp_eid_table_details_payload_ntoh(vapi_payload_lisp_eid_table_details *payload)
{
  payload->locator_set_index = be32toh(payload->locator_set_index);
  payload->vni = be32toh(payload->vni);
  payload->ttl = be32toh(payload->ttl);
}

static inline void vapi_msg_lisp_eid_table_details_hton(vapi_msg_lisp_eid_table_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_eid_table_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_eid_table_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_eid_table_details_ntoh(vapi_msg_lisp_eid_table_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_eid_table_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_eid_table_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_eid_table_details_msg_size(vapi_msg_lisp_eid_table_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_eid_table_details_msg_size(vapi_msg_lisp_eid_table_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_eid_table_details) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_eid_table_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_eid_table_details));
      return -1;
    }
  if (vapi_calc_lisp_eid_table_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_eid_table_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_eid_table_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_eid_table_details()
{
  static const char name[] = "lisp_eid_table_details";
  static const char name_with_crc[] = "lisp_eid_table_details_1c29f792";
  static vapi_message_desc_t __vapi_metadata_lisp_eid_table_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_eid_table_details, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_eid_table_details_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_eid_table_details_hton,
    (generic_swap_fn_t)vapi_msg_lisp_eid_table_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_eid_table_details = vapi_register_msg(&__vapi_metadata_lisp_eid_table_details);
  VAPI_DBG("Assigned msg id %d to lisp_eid_table_details", vapi_msg_id_lisp_eid_table_details);
}

static inline void vapi_set_vapi_msg_lisp_eid_table_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_eid_table_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_eid_table_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_eid_table_dump
#define defined_vapi_msg_lisp_eid_table_dump
typedef struct __attribute__ ((__packed__)) {
  u8 eid_set;
  u8 prefix_length;
  u32 vni;
  vapi_type_eid eid;
  vapi_enum_lisp_locator_set_filter filter; 
} vapi_payload_lisp_eid_table_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lisp_eid_table_dump payload;
} vapi_msg_lisp_eid_table_dump;

static inline void vapi_msg_lisp_eid_table_dump_payload_hton(vapi_payload_lisp_eid_table_dump *payload)
{
  payload->vni = htobe32(payload->vni);
}

static inline void vapi_msg_lisp_eid_table_dump_payload_ntoh(vapi_payload_lisp_eid_table_dump *payload)
{
  payload->vni = be32toh(payload->vni);
}

static inline void vapi_msg_lisp_eid_table_dump_hton(vapi_msg_lisp_eid_table_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_eid_table_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lisp_eid_table_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_eid_table_dump_ntoh(vapi_msg_lisp_eid_table_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_eid_table_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lisp_eid_table_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_eid_table_dump_msg_size(vapi_msg_lisp_eid_table_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_eid_table_dump_msg_size(vapi_msg_lisp_eid_table_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_eid_table_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_eid_table_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_eid_table_dump));
      return -1;
    }
  if (vapi_calc_lisp_eid_table_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_eid_table_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_eid_table_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_eid_table_dump* vapi_alloc_lisp_eid_table_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_eid_table_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_eid_table_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_eid_table_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_eid_table_dump);

  return msg;
}

static inline vapi_error_e vapi_lisp_eid_table_dump(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_eid_table_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_eid_table_details *reply),
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
  vapi_msg_lisp_eid_table_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_eid_table_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_lisp_eid_table_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_eid_table_dump()
{
  static const char name[] = "lisp_eid_table_dump";
  static const char name_with_crc[] = "lisp_eid_table_dump_629468b5";
  static vapi_message_desc_t __vapi_metadata_lisp_eid_table_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lisp_eid_table_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_eid_table_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_eid_table_dump_hton,
    (generic_swap_fn_t)vapi_msg_lisp_eid_table_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_eid_table_dump = vapi_register_msg(&__vapi_metadata_lisp_eid_table_dump);
  VAPI_DBG("Assigned msg id %d to lisp_eid_table_dump", vapi_msg_id_lisp_eid_table_dump);
}
#endif

#ifndef defined_vapi_msg_lisp_adjacencies_get_reply
#define defined_vapi_msg_lisp_adjacencies_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 count;
  vapi_type_lisp_adjacency adjacencies[0]; 
} vapi_payload_lisp_adjacencies_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_adjacencies_get_reply payload;
} vapi_msg_lisp_adjacencies_get_reply;

static inline void vapi_msg_lisp_adjacencies_get_reply_payload_hton(vapi_payload_lisp_adjacencies_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->count = htobe32(payload->count);
}

static inline void vapi_msg_lisp_adjacencies_get_reply_payload_ntoh(vapi_payload_lisp_adjacencies_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->count = be32toh(payload->count);
}

static inline void vapi_msg_lisp_adjacencies_get_reply_hton(vapi_msg_lisp_adjacencies_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_adjacencies_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_adjacencies_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_adjacencies_get_reply_ntoh(vapi_msg_lisp_adjacencies_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_adjacencies_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_adjacencies_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_adjacencies_get_reply_msg_size(vapi_msg_lisp_adjacencies_get_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.adjacencies[0]) * msg->payload.count;
}

static inline int vapi_verify_lisp_adjacencies_get_reply_msg_size(vapi_msg_lisp_adjacencies_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_adjacencies_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_adjacencies_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_adjacencies_get_reply));
      return -1;
    }
  if (vapi_calc_lisp_adjacencies_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_adjacencies_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_adjacencies_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_adjacencies_get_reply()
{
  static const char name[] = "lisp_adjacencies_get_reply";
  static const char name_with_crc[] = "lisp_adjacencies_get_reply_807257bf";
  static vapi_message_desc_t __vapi_metadata_lisp_adjacencies_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_adjacencies_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_adjacencies_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_adjacencies_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_lisp_adjacencies_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_adjacencies_get_reply = vapi_register_msg(&__vapi_metadata_lisp_adjacencies_get_reply);
  VAPI_DBG("Assigned msg id %d to lisp_adjacencies_get_reply", vapi_msg_id_lisp_adjacencies_get_reply);
}

static inline void vapi_set_vapi_msg_lisp_adjacencies_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_adjacencies_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_adjacencies_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_adjacencies_get
#define defined_vapi_msg_lisp_adjacencies_get
typedef struct __attribute__ ((__packed__)) {
  u32 vni; 
} vapi_payload_lisp_adjacencies_get;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lisp_adjacencies_get payload;
} vapi_msg_lisp_adjacencies_get;

static inline void vapi_msg_lisp_adjacencies_get_payload_hton(vapi_payload_lisp_adjacencies_get *payload)
{
  payload->vni = htobe32(payload->vni);
}

static inline void vapi_msg_lisp_adjacencies_get_payload_ntoh(vapi_payload_lisp_adjacencies_get *payload)
{
  payload->vni = be32toh(payload->vni);
}

static inline void vapi_msg_lisp_adjacencies_get_hton(vapi_msg_lisp_adjacencies_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_adjacencies_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lisp_adjacencies_get_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_adjacencies_get_ntoh(vapi_msg_lisp_adjacencies_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_adjacencies_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lisp_adjacencies_get_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_adjacencies_get_msg_size(vapi_msg_lisp_adjacencies_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_adjacencies_get_msg_size(vapi_msg_lisp_adjacencies_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_adjacencies_get) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_adjacencies_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_adjacencies_get));
      return -1;
    }
  if (vapi_calc_lisp_adjacencies_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_adjacencies_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_adjacencies_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_adjacencies_get* vapi_alloc_lisp_adjacencies_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_adjacencies_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_adjacencies_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_adjacencies_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_adjacencies_get);

  return msg;
}

static inline vapi_error_e vapi_lisp_adjacencies_get(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_adjacencies_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_adjacencies_get_reply *reply),
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
  vapi_msg_lisp_adjacencies_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_adjacencies_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lisp_adjacencies_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_adjacencies_get()
{
  static const char name[] = "lisp_adjacencies_get";
  static const char name_with_crc[] = "lisp_adjacencies_get_8d1f2fe9";
  static vapi_message_desc_t __vapi_metadata_lisp_adjacencies_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lisp_adjacencies_get, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_adjacencies_get_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_adjacencies_get_hton,
    (generic_swap_fn_t)vapi_msg_lisp_adjacencies_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_adjacencies_get = vapi_register_msg(&__vapi_metadata_lisp_adjacencies_get);
  VAPI_DBG("Assigned msg id %d to lisp_adjacencies_get", vapi_msg_id_lisp_adjacencies_get);
}
#endif

#ifndef defined_vapi_msg_lisp_eid_table_map_details
#define defined_vapi_msg_lisp_eid_table_map_details
typedef struct __attribute__ ((__packed__)) {
  u32 vni;
  u32 dp_table; 
} vapi_payload_lisp_eid_table_map_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_eid_table_map_details payload;
} vapi_msg_lisp_eid_table_map_details;

static inline void vapi_msg_lisp_eid_table_map_details_payload_hton(vapi_payload_lisp_eid_table_map_details *payload)
{
  payload->vni = htobe32(payload->vni);
  payload->dp_table = htobe32(payload->dp_table);
}

static inline void vapi_msg_lisp_eid_table_map_details_payload_ntoh(vapi_payload_lisp_eid_table_map_details *payload)
{
  payload->vni = be32toh(payload->vni);
  payload->dp_table = be32toh(payload->dp_table);
}

static inline void vapi_msg_lisp_eid_table_map_details_hton(vapi_msg_lisp_eid_table_map_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_eid_table_map_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_eid_table_map_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_eid_table_map_details_ntoh(vapi_msg_lisp_eid_table_map_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_eid_table_map_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_eid_table_map_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_eid_table_map_details_msg_size(vapi_msg_lisp_eid_table_map_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_eid_table_map_details_msg_size(vapi_msg_lisp_eid_table_map_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_eid_table_map_details) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_eid_table_map_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_eid_table_map_details));
      return -1;
    }
  if (vapi_calc_lisp_eid_table_map_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_eid_table_map_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_eid_table_map_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_eid_table_map_details()
{
  static const char name[] = "lisp_eid_table_map_details";
  static const char name_with_crc[] = "lisp_eid_table_map_details_0b6859e2";
  static vapi_message_desc_t __vapi_metadata_lisp_eid_table_map_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_eid_table_map_details, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_eid_table_map_details_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_eid_table_map_details_hton,
    (generic_swap_fn_t)vapi_msg_lisp_eid_table_map_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_eid_table_map_details = vapi_register_msg(&__vapi_metadata_lisp_eid_table_map_details);
  VAPI_DBG("Assigned msg id %d to lisp_eid_table_map_details", vapi_msg_id_lisp_eid_table_map_details);
}

static inline void vapi_set_vapi_msg_lisp_eid_table_map_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_eid_table_map_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_eid_table_map_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_eid_table_map_dump
#define defined_vapi_msg_lisp_eid_table_map_dump
typedef struct __attribute__ ((__packed__)) {
  bool is_l2; 
} vapi_payload_lisp_eid_table_map_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lisp_eid_table_map_dump payload;
} vapi_msg_lisp_eid_table_map_dump;

static inline void vapi_msg_lisp_eid_table_map_dump_payload_hton(vapi_payload_lisp_eid_table_map_dump *payload)
{

}

static inline void vapi_msg_lisp_eid_table_map_dump_payload_ntoh(vapi_payload_lisp_eid_table_map_dump *payload)
{

}

static inline void vapi_msg_lisp_eid_table_map_dump_hton(vapi_msg_lisp_eid_table_map_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_eid_table_map_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lisp_eid_table_map_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_eid_table_map_dump_ntoh(vapi_msg_lisp_eid_table_map_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_eid_table_map_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lisp_eid_table_map_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_eid_table_map_dump_msg_size(vapi_msg_lisp_eid_table_map_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_eid_table_map_dump_msg_size(vapi_msg_lisp_eid_table_map_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_eid_table_map_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_eid_table_map_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_eid_table_map_dump));
      return -1;
    }
  if (vapi_calc_lisp_eid_table_map_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_eid_table_map_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_eid_table_map_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_eid_table_map_dump* vapi_alloc_lisp_eid_table_map_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_eid_table_map_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_eid_table_map_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_eid_table_map_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_eid_table_map_dump);

  return msg;
}

static inline vapi_error_e vapi_lisp_eid_table_map_dump(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_eid_table_map_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_eid_table_map_details *reply),
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
  vapi_msg_lisp_eid_table_map_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_eid_table_map_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_lisp_eid_table_map_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_eid_table_map_dump()
{
  static const char name[] = "lisp_eid_table_map_dump";
  static const char name_with_crc[] = "lisp_eid_table_map_dump_d6cf0c3d";
  static vapi_message_desc_t __vapi_metadata_lisp_eid_table_map_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lisp_eid_table_map_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_eid_table_map_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_eid_table_map_dump_hton,
    (generic_swap_fn_t)vapi_msg_lisp_eid_table_map_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_eid_table_map_dump = vapi_register_msg(&__vapi_metadata_lisp_eid_table_map_dump);
  VAPI_DBG("Assigned msg id %d to lisp_eid_table_map_dump", vapi_msg_id_lisp_eid_table_map_dump);
}
#endif

#ifndef defined_vapi_msg_lisp_eid_table_vni_details
#define defined_vapi_msg_lisp_eid_table_vni_details
typedef struct __attribute__ ((__packed__)) {
  u32 vni; 
} vapi_payload_lisp_eid_table_vni_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_eid_table_vni_details payload;
} vapi_msg_lisp_eid_table_vni_details;

static inline void vapi_msg_lisp_eid_table_vni_details_payload_hton(vapi_payload_lisp_eid_table_vni_details *payload)
{
  payload->vni = htobe32(payload->vni);
}

static inline void vapi_msg_lisp_eid_table_vni_details_payload_ntoh(vapi_payload_lisp_eid_table_vni_details *payload)
{
  payload->vni = be32toh(payload->vni);
}

static inline void vapi_msg_lisp_eid_table_vni_details_hton(vapi_msg_lisp_eid_table_vni_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_eid_table_vni_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_eid_table_vni_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_eid_table_vni_details_ntoh(vapi_msg_lisp_eid_table_vni_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_eid_table_vni_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_eid_table_vni_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_eid_table_vni_details_msg_size(vapi_msg_lisp_eid_table_vni_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_eid_table_vni_details_msg_size(vapi_msg_lisp_eid_table_vni_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_eid_table_vni_details) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_eid_table_vni_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_eid_table_vni_details));
      return -1;
    }
  if (vapi_calc_lisp_eid_table_vni_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_eid_table_vni_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_eid_table_vni_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_eid_table_vni_details()
{
  static const char name[] = "lisp_eid_table_vni_details";
  static const char name_with_crc[] = "lisp_eid_table_vni_details_64abc01e";
  static vapi_message_desc_t __vapi_metadata_lisp_eid_table_vni_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_eid_table_vni_details, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_eid_table_vni_details_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_eid_table_vni_details_hton,
    (generic_swap_fn_t)vapi_msg_lisp_eid_table_vni_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_eid_table_vni_details = vapi_register_msg(&__vapi_metadata_lisp_eid_table_vni_details);
  VAPI_DBG("Assigned msg id %d to lisp_eid_table_vni_details", vapi_msg_id_lisp_eid_table_vni_details);
}

static inline void vapi_set_vapi_msg_lisp_eid_table_vni_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_eid_table_vni_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_eid_table_vni_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_eid_table_vni_dump
#define defined_vapi_msg_lisp_eid_table_vni_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_lisp_eid_table_vni_dump;

static inline void vapi_msg_lisp_eid_table_vni_dump_hton(vapi_msg_lisp_eid_table_vni_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_eid_table_vni_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_lisp_eid_table_vni_dump_ntoh(vapi_msg_lisp_eid_table_vni_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_eid_table_vni_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_lisp_eid_table_vni_dump_msg_size(vapi_msg_lisp_eid_table_vni_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_eid_table_vni_dump_msg_size(vapi_msg_lisp_eid_table_vni_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_eid_table_vni_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_eid_table_vni_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_eid_table_vni_dump));
      return -1;
    }
  if (vapi_calc_lisp_eid_table_vni_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_eid_table_vni_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_eid_table_vni_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_eid_table_vni_dump* vapi_alloc_lisp_eid_table_vni_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_eid_table_vni_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_eid_table_vni_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_eid_table_vni_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_eid_table_vni_dump);

  return msg;
}

static inline vapi_error_e vapi_lisp_eid_table_vni_dump(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_eid_table_vni_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_eid_table_vni_details *reply),
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
  vapi_msg_lisp_eid_table_vni_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_eid_table_vni_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_lisp_eid_table_vni_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_eid_table_vni_dump()
{
  static const char name[] = "lisp_eid_table_vni_dump";
  static const char name_with_crc[] = "lisp_eid_table_vni_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_lisp_eid_table_vni_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_lisp_eid_table_vni_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_eid_table_vni_dump_hton,
    (generic_swap_fn_t)vapi_msg_lisp_eid_table_vni_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_eid_table_vni_dump = vapi_register_msg(&__vapi_metadata_lisp_eid_table_vni_dump);
  VAPI_DBG("Assigned msg id %d to lisp_eid_table_vni_dump", vapi_msg_id_lisp_eid_table_vni_dump);
}
#endif

#ifndef defined_vapi_msg_lisp_map_resolver_details
#define defined_vapi_msg_lisp_map_resolver_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_address ip_address; 
} vapi_payload_lisp_map_resolver_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_map_resolver_details payload;
} vapi_msg_lisp_map_resolver_details;

static inline void vapi_msg_lisp_map_resolver_details_payload_hton(vapi_payload_lisp_map_resolver_details *payload)
{

}

static inline void vapi_msg_lisp_map_resolver_details_payload_ntoh(vapi_payload_lisp_map_resolver_details *payload)
{

}

static inline void vapi_msg_lisp_map_resolver_details_hton(vapi_msg_lisp_map_resolver_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_map_resolver_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_map_resolver_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_map_resolver_details_ntoh(vapi_msg_lisp_map_resolver_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_map_resolver_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_map_resolver_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_map_resolver_details_msg_size(vapi_msg_lisp_map_resolver_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_map_resolver_details_msg_size(vapi_msg_lisp_map_resolver_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_map_resolver_details) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_map_resolver_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_map_resolver_details));
      return -1;
    }
  if (vapi_calc_lisp_map_resolver_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_map_resolver_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_map_resolver_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_map_resolver_details()
{
  static const char name[] = "lisp_map_resolver_details";
  static const char name_with_crc[] = "lisp_map_resolver_details_3e78fc57";
  static vapi_message_desc_t __vapi_metadata_lisp_map_resolver_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_map_resolver_details, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_map_resolver_details_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_map_resolver_details_hton,
    (generic_swap_fn_t)vapi_msg_lisp_map_resolver_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_map_resolver_details = vapi_register_msg(&__vapi_metadata_lisp_map_resolver_details);
  VAPI_DBG("Assigned msg id %d to lisp_map_resolver_details", vapi_msg_id_lisp_map_resolver_details);
}

static inline void vapi_set_vapi_msg_lisp_map_resolver_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_map_resolver_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_map_resolver_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_map_resolver_dump
#define defined_vapi_msg_lisp_map_resolver_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_lisp_map_resolver_dump;

static inline void vapi_msg_lisp_map_resolver_dump_hton(vapi_msg_lisp_map_resolver_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_map_resolver_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_lisp_map_resolver_dump_ntoh(vapi_msg_lisp_map_resolver_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_map_resolver_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_lisp_map_resolver_dump_msg_size(vapi_msg_lisp_map_resolver_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_map_resolver_dump_msg_size(vapi_msg_lisp_map_resolver_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_map_resolver_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_map_resolver_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_map_resolver_dump));
      return -1;
    }
  if (vapi_calc_lisp_map_resolver_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_map_resolver_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_map_resolver_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_map_resolver_dump* vapi_alloc_lisp_map_resolver_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_map_resolver_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_map_resolver_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_map_resolver_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_map_resolver_dump);

  return msg;
}

static inline vapi_error_e vapi_lisp_map_resolver_dump(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_map_resolver_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_map_resolver_details *reply),
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
  vapi_msg_lisp_map_resolver_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_map_resolver_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_lisp_map_resolver_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_map_resolver_dump()
{
  static const char name[] = "lisp_map_resolver_dump";
  static const char name_with_crc[] = "lisp_map_resolver_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_lisp_map_resolver_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_lisp_map_resolver_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_map_resolver_dump_hton,
    (generic_swap_fn_t)vapi_msg_lisp_map_resolver_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_map_resolver_dump = vapi_register_msg(&__vapi_metadata_lisp_map_resolver_dump);
  VAPI_DBG("Assigned msg id %d to lisp_map_resolver_dump", vapi_msg_id_lisp_map_resolver_dump);
}
#endif

#ifndef defined_vapi_msg_lisp_map_server_details
#define defined_vapi_msg_lisp_map_server_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_address ip_address; 
} vapi_payload_lisp_map_server_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_map_server_details payload;
} vapi_msg_lisp_map_server_details;

static inline void vapi_msg_lisp_map_server_details_payload_hton(vapi_payload_lisp_map_server_details *payload)
{

}

static inline void vapi_msg_lisp_map_server_details_payload_ntoh(vapi_payload_lisp_map_server_details *payload)
{

}

static inline void vapi_msg_lisp_map_server_details_hton(vapi_msg_lisp_map_server_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_map_server_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_map_server_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_map_server_details_ntoh(vapi_msg_lisp_map_server_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_map_server_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_map_server_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_map_server_details_msg_size(vapi_msg_lisp_map_server_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_map_server_details_msg_size(vapi_msg_lisp_map_server_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_map_server_details) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_map_server_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_map_server_details));
      return -1;
    }
  if (vapi_calc_lisp_map_server_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_map_server_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_map_server_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_map_server_details()
{
  static const char name[] = "lisp_map_server_details";
  static const char name_with_crc[] = "lisp_map_server_details_3e78fc57";
  static vapi_message_desc_t __vapi_metadata_lisp_map_server_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_map_server_details, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_map_server_details_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_map_server_details_hton,
    (generic_swap_fn_t)vapi_msg_lisp_map_server_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_map_server_details = vapi_register_msg(&__vapi_metadata_lisp_map_server_details);
  VAPI_DBG("Assigned msg id %d to lisp_map_server_details", vapi_msg_id_lisp_map_server_details);
}

static inline void vapi_set_vapi_msg_lisp_map_server_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_map_server_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_map_server_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_map_server_dump
#define defined_vapi_msg_lisp_map_server_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_lisp_map_server_dump;

static inline void vapi_msg_lisp_map_server_dump_hton(vapi_msg_lisp_map_server_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_map_server_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_lisp_map_server_dump_ntoh(vapi_msg_lisp_map_server_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_map_server_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_lisp_map_server_dump_msg_size(vapi_msg_lisp_map_server_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_map_server_dump_msg_size(vapi_msg_lisp_map_server_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_map_server_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_map_server_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_map_server_dump));
      return -1;
    }
  if (vapi_calc_lisp_map_server_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_map_server_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_map_server_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_map_server_dump* vapi_alloc_lisp_map_server_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_map_server_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_map_server_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_map_server_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_map_server_dump);

  return msg;
}

static inline vapi_error_e vapi_lisp_map_server_dump(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_map_server_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_map_server_details *reply),
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
  vapi_msg_lisp_map_server_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_map_server_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_lisp_map_server_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_map_server_dump()
{
  static const char name[] = "lisp_map_server_dump";
  static const char name_with_crc[] = "lisp_map_server_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_lisp_map_server_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_lisp_map_server_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_map_server_dump_hton,
    (generic_swap_fn_t)vapi_msg_lisp_map_server_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_map_server_dump = vapi_register_msg(&__vapi_metadata_lisp_map_server_dump);
  VAPI_DBG("Assigned msg id %d to lisp_map_server_dump", vapi_msg_id_lisp_map_server_dump);
}
#endif

#ifndef defined_vapi_msg_show_lisp_status_reply
#define defined_vapi_msg_show_lisp_status_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  bool is_lisp_enabled;
  bool is_gpe_enabled; 
} vapi_payload_show_lisp_status_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_show_lisp_status_reply payload;
} vapi_msg_show_lisp_status_reply;

static inline void vapi_msg_show_lisp_status_reply_payload_hton(vapi_payload_show_lisp_status_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_show_lisp_status_reply_payload_ntoh(vapi_payload_show_lisp_status_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_show_lisp_status_reply_hton(vapi_msg_show_lisp_status_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_status_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_show_lisp_status_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_show_lisp_status_reply_ntoh(vapi_msg_show_lisp_status_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_status_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_show_lisp_status_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_show_lisp_status_reply_msg_size(vapi_msg_show_lisp_status_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_show_lisp_status_reply_msg_size(vapi_msg_show_lisp_status_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_show_lisp_status_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_status_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_show_lisp_status_reply));
      return -1;
    }
  if (vapi_calc_show_lisp_status_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_status_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_show_lisp_status_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_show_lisp_status_reply()
{
  static const char name[] = "show_lisp_status_reply";
  static const char name_with_crc[] = "show_lisp_status_reply_9e8f10c0";
  static vapi_message_desc_t __vapi_metadata_show_lisp_status_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_show_lisp_status_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_show_lisp_status_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_show_lisp_status_reply_hton,
    (generic_swap_fn_t)vapi_msg_show_lisp_status_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_show_lisp_status_reply = vapi_register_msg(&__vapi_metadata_show_lisp_status_reply);
  VAPI_DBG("Assigned msg id %d to show_lisp_status_reply", vapi_msg_id_show_lisp_status_reply);
}

static inline void vapi_set_vapi_msg_show_lisp_status_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_show_lisp_status_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_show_lisp_status_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_show_lisp_status
#define defined_vapi_msg_show_lisp_status
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_show_lisp_status;

static inline void vapi_msg_show_lisp_status_hton(vapi_msg_show_lisp_status *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_status'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_show_lisp_status_ntoh(vapi_msg_show_lisp_status *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_status'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_show_lisp_status_msg_size(vapi_msg_show_lisp_status *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_show_lisp_status_msg_size(vapi_msg_show_lisp_status *msg, uword buf_size)
{
  if (sizeof(vapi_msg_show_lisp_status) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_status' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_show_lisp_status));
      return -1;
    }
  if (vapi_calc_show_lisp_status_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_status' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_show_lisp_status_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_show_lisp_status* vapi_alloc_show_lisp_status(struct vapi_ctx_s *ctx)
{
  vapi_msg_show_lisp_status *msg = NULL;
  const size_t size = sizeof(vapi_msg_show_lisp_status);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_show_lisp_status*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_show_lisp_status);

  return msg;
}

static inline vapi_error_e vapi_show_lisp_status(struct vapi_ctx_s *ctx,
  vapi_msg_show_lisp_status *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_show_lisp_status_reply *reply),
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
  vapi_msg_show_lisp_status_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_show_lisp_status_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_show_lisp_status_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_show_lisp_status()
{
  static const char name[] = "show_lisp_status";
  static const char name_with_crc[] = "show_lisp_status_51077d14";
  static vapi_message_desc_t __vapi_metadata_show_lisp_status = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_show_lisp_status_msg_size,
    (generic_swap_fn_t)vapi_msg_show_lisp_status_hton,
    (generic_swap_fn_t)vapi_msg_show_lisp_status_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_show_lisp_status = vapi_register_msg(&__vapi_metadata_show_lisp_status);
  VAPI_DBG("Assigned msg id %d to show_lisp_status", vapi_msg_id_show_lisp_status);
}
#endif

#ifndef defined_vapi_msg_lisp_get_map_request_itr_rlocs_reply
#define defined_vapi_msg_lisp_get_map_request_itr_rlocs_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u8 locator_set_name[64]; 
} vapi_payload_lisp_get_map_request_itr_rlocs_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lisp_get_map_request_itr_rlocs_reply payload;
} vapi_msg_lisp_get_map_request_itr_rlocs_reply;

static inline void vapi_msg_lisp_get_map_request_itr_rlocs_reply_payload_hton(vapi_payload_lisp_get_map_request_itr_rlocs_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lisp_get_map_request_itr_rlocs_reply_payload_ntoh(vapi_payload_lisp_get_map_request_itr_rlocs_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lisp_get_map_request_itr_rlocs_reply_hton(vapi_msg_lisp_get_map_request_itr_rlocs_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_get_map_request_itr_rlocs_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lisp_get_map_request_itr_rlocs_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lisp_get_map_request_itr_rlocs_reply_ntoh(vapi_msg_lisp_get_map_request_itr_rlocs_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_get_map_request_itr_rlocs_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lisp_get_map_request_itr_rlocs_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lisp_get_map_request_itr_rlocs_reply_msg_size(vapi_msg_lisp_get_map_request_itr_rlocs_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_get_map_request_itr_rlocs_reply_msg_size(vapi_msg_lisp_get_map_request_itr_rlocs_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_get_map_request_itr_rlocs_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_get_map_request_itr_rlocs_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_get_map_request_itr_rlocs_reply));
      return -1;
    }
  if (vapi_calc_lisp_get_map_request_itr_rlocs_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_get_map_request_itr_rlocs_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_get_map_request_itr_rlocs_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lisp_get_map_request_itr_rlocs_reply()
{
  static const char name[] = "lisp_get_map_request_itr_rlocs_reply";
  static const char name_with_crc[] = "lisp_get_map_request_itr_rlocs_reply_76580f3a";
  static vapi_message_desc_t __vapi_metadata_lisp_get_map_request_itr_rlocs_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lisp_get_map_request_itr_rlocs_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lisp_get_map_request_itr_rlocs_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_get_map_request_itr_rlocs_reply_hton,
    (generic_swap_fn_t)vapi_msg_lisp_get_map_request_itr_rlocs_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_get_map_request_itr_rlocs_reply = vapi_register_msg(&__vapi_metadata_lisp_get_map_request_itr_rlocs_reply);
  VAPI_DBG("Assigned msg id %d to lisp_get_map_request_itr_rlocs_reply", vapi_msg_id_lisp_get_map_request_itr_rlocs_reply);
}

static inline void vapi_set_vapi_msg_lisp_get_map_request_itr_rlocs_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lisp_get_map_request_itr_rlocs_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lisp_get_map_request_itr_rlocs_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lisp_get_map_request_itr_rlocs
#define defined_vapi_msg_lisp_get_map_request_itr_rlocs
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_lisp_get_map_request_itr_rlocs;

static inline void vapi_msg_lisp_get_map_request_itr_rlocs_hton(vapi_msg_lisp_get_map_request_itr_rlocs *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_get_map_request_itr_rlocs'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_lisp_get_map_request_itr_rlocs_ntoh(vapi_msg_lisp_get_map_request_itr_rlocs *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lisp_get_map_request_itr_rlocs'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_lisp_get_map_request_itr_rlocs_msg_size(vapi_msg_lisp_get_map_request_itr_rlocs *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lisp_get_map_request_itr_rlocs_msg_size(vapi_msg_lisp_get_map_request_itr_rlocs *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lisp_get_map_request_itr_rlocs) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_get_map_request_itr_rlocs' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lisp_get_map_request_itr_rlocs));
      return -1;
    }
  if (vapi_calc_lisp_get_map_request_itr_rlocs_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lisp_get_map_request_itr_rlocs' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lisp_get_map_request_itr_rlocs_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lisp_get_map_request_itr_rlocs* vapi_alloc_lisp_get_map_request_itr_rlocs(struct vapi_ctx_s *ctx)
{
  vapi_msg_lisp_get_map_request_itr_rlocs *msg = NULL;
  const size_t size = sizeof(vapi_msg_lisp_get_map_request_itr_rlocs);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lisp_get_map_request_itr_rlocs*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lisp_get_map_request_itr_rlocs);

  return msg;
}

static inline vapi_error_e vapi_lisp_get_map_request_itr_rlocs(struct vapi_ctx_s *ctx,
  vapi_msg_lisp_get_map_request_itr_rlocs *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lisp_get_map_request_itr_rlocs_reply *reply),
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
  vapi_msg_lisp_get_map_request_itr_rlocs_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lisp_get_map_request_itr_rlocs_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lisp_get_map_request_itr_rlocs_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lisp_get_map_request_itr_rlocs()
{
  static const char name[] = "lisp_get_map_request_itr_rlocs";
  static const char name_with_crc[] = "lisp_get_map_request_itr_rlocs_51077d14";
  static vapi_message_desc_t __vapi_metadata_lisp_get_map_request_itr_rlocs = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_lisp_get_map_request_itr_rlocs_msg_size,
    (generic_swap_fn_t)vapi_msg_lisp_get_map_request_itr_rlocs_hton,
    (generic_swap_fn_t)vapi_msg_lisp_get_map_request_itr_rlocs_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lisp_get_map_request_itr_rlocs = vapi_register_msg(&__vapi_metadata_lisp_get_map_request_itr_rlocs);
  VAPI_DBG("Assigned msg id %d to lisp_get_map_request_itr_rlocs", vapi_msg_id_lisp_get_map_request_itr_rlocs);
}
#endif

#ifndef defined_vapi_msg_show_lisp_pitr_reply
#define defined_vapi_msg_show_lisp_pitr_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  bool is_enabled;
  u8 locator_set_name[64]; 
} vapi_payload_show_lisp_pitr_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_show_lisp_pitr_reply payload;
} vapi_msg_show_lisp_pitr_reply;

static inline void vapi_msg_show_lisp_pitr_reply_payload_hton(vapi_payload_show_lisp_pitr_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_show_lisp_pitr_reply_payload_ntoh(vapi_payload_show_lisp_pitr_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_show_lisp_pitr_reply_hton(vapi_msg_show_lisp_pitr_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_pitr_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_show_lisp_pitr_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_show_lisp_pitr_reply_ntoh(vapi_msg_show_lisp_pitr_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_pitr_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_show_lisp_pitr_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_show_lisp_pitr_reply_msg_size(vapi_msg_show_lisp_pitr_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_show_lisp_pitr_reply_msg_size(vapi_msg_show_lisp_pitr_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_show_lisp_pitr_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_pitr_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_show_lisp_pitr_reply));
      return -1;
    }
  if (vapi_calc_show_lisp_pitr_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_pitr_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_show_lisp_pitr_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_show_lisp_pitr_reply()
{
  static const char name[] = "show_lisp_pitr_reply";
  static const char name_with_crc[] = "show_lisp_pitr_reply_27aa69b1";
  static vapi_message_desc_t __vapi_metadata_show_lisp_pitr_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_show_lisp_pitr_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_show_lisp_pitr_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_show_lisp_pitr_reply_hton,
    (generic_swap_fn_t)vapi_msg_show_lisp_pitr_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_show_lisp_pitr_reply = vapi_register_msg(&__vapi_metadata_show_lisp_pitr_reply);
  VAPI_DBG("Assigned msg id %d to show_lisp_pitr_reply", vapi_msg_id_show_lisp_pitr_reply);
}

static inline void vapi_set_vapi_msg_show_lisp_pitr_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_show_lisp_pitr_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_show_lisp_pitr_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_show_lisp_pitr
#define defined_vapi_msg_show_lisp_pitr
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_show_lisp_pitr;

static inline void vapi_msg_show_lisp_pitr_hton(vapi_msg_show_lisp_pitr *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_pitr'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_show_lisp_pitr_ntoh(vapi_msg_show_lisp_pitr *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_lisp_pitr'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_show_lisp_pitr_msg_size(vapi_msg_show_lisp_pitr *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_show_lisp_pitr_msg_size(vapi_msg_show_lisp_pitr *msg, uword buf_size)
{
  if (sizeof(vapi_msg_show_lisp_pitr) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_pitr' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_show_lisp_pitr));
      return -1;
    }
  if (vapi_calc_show_lisp_pitr_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'show_lisp_pitr' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_show_lisp_pitr_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_show_lisp_pitr* vapi_alloc_show_lisp_pitr(struct vapi_ctx_s *ctx)
{
  vapi_msg_show_lisp_pitr *msg = NULL;
  const size_t size = sizeof(vapi_msg_show_lisp_pitr);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_show_lisp_pitr*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_show_lisp_pitr);

  return msg;
}

static inline vapi_error_e vapi_show_lisp_pitr(struct vapi_ctx_s *ctx,
  vapi_msg_show_lisp_pitr *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_show_lisp_pitr_reply *reply),
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
  vapi_msg_show_lisp_pitr_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_show_lisp_pitr_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_show_lisp_pitr_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_show_lisp_pitr()
{
  static const char name[] = "show_lisp_pitr";
  static const char name_with_crc[] = "show_lisp_pitr_51077d14";
  static vapi_message_desc_t __vapi_metadata_show_lisp_pitr = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_show_lisp_pitr_msg_size,
    (generic_swap_fn_t)vapi_msg_show_lisp_pitr_hton,
    (generic_swap_fn_t)vapi_msg_show_lisp_pitr_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_show_lisp_pitr = vapi_register_msg(&__vapi_metadata_show_lisp_pitr);
  VAPI_DBG("Assigned msg id %d to show_lisp_pitr", vapi_msg_id_show_lisp_pitr);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
