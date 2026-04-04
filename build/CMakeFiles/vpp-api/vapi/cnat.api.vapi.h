#ifndef __included_cnat_api_json
#define __included_cnat_api_json

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

extern vapi_msg_id_t vapi_msg_id_cnat_translation_update;
extern vapi_msg_id_t vapi_msg_id_cnat_translation_update_reply;
extern vapi_msg_id_t vapi_msg_id_cnat_translation_del;
extern vapi_msg_id_t vapi_msg_id_cnat_translation_del_reply;
extern vapi_msg_id_t vapi_msg_id_cnat_translation_details;
extern vapi_msg_id_t vapi_msg_id_cnat_translation_dump;
extern vapi_msg_id_t vapi_msg_id_cnat_session_purge;
extern vapi_msg_id_t vapi_msg_id_cnat_session_purge_reply;
extern vapi_msg_id_t vapi_msg_id_cnat_session_details;
extern vapi_msg_id_t vapi_msg_id_cnat_session_dump;
extern vapi_msg_id_t vapi_msg_id_cnat_set_snat_addresses;
extern vapi_msg_id_t vapi_msg_id_cnat_set_snat_addresses_reply;
extern vapi_msg_id_t vapi_msg_id_cnat_get_snat_addresses;
extern vapi_msg_id_t vapi_msg_id_cnat_get_snat_addresses_reply;
extern vapi_msg_id_t vapi_msg_id_cnat_snat_policy_add_del_exclude_pfx;
extern vapi_msg_id_t vapi_msg_id_cnat_snat_policy_add_del_exclude_pfx_reply;
extern vapi_msg_id_t vapi_msg_id_cnat_snat_policy_add_del_if;
extern vapi_msg_id_t vapi_msg_id_cnat_snat_policy_add_del_if_reply;
extern vapi_msg_id_t vapi_msg_id_cnat_set_snat_policy;
extern vapi_msg_id_t vapi_msg_id_cnat_set_snat_policy_reply;

#define DEFINE_VAPI_MSG_IDS_CNAT_API_JSON\
  vapi_msg_id_t vapi_msg_id_cnat_translation_update;\
  vapi_msg_id_t vapi_msg_id_cnat_translation_update_reply;\
  vapi_msg_id_t vapi_msg_id_cnat_translation_del;\
  vapi_msg_id_t vapi_msg_id_cnat_translation_del_reply;\
  vapi_msg_id_t vapi_msg_id_cnat_translation_details;\
  vapi_msg_id_t vapi_msg_id_cnat_translation_dump;\
  vapi_msg_id_t vapi_msg_id_cnat_session_purge;\
  vapi_msg_id_t vapi_msg_id_cnat_session_purge_reply;\
  vapi_msg_id_t vapi_msg_id_cnat_session_details;\
  vapi_msg_id_t vapi_msg_id_cnat_session_dump;\
  vapi_msg_id_t vapi_msg_id_cnat_set_snat_addresses;\
  vapi_msg_id_t vapi_msg_id_cnat_set_snat_addresses_reply;\
  vapi_msg_id_t vapi_msg_id_cnat_get_snat_addresses;\
  vapi_msg_id_t vapi_msg_id_cnat_get_snat_addresses_reply;\
  vapi_msg_id_t vapi_msg_id_cnat_snat_policy_add_del_exclude_pfx;\
  vapi_msg_id_t vapi_msg_id_cnat_snat_policy_add_del_exclude_pfx_reply;\
  vapi_msg_id_t vapi_msg_id_cnat_snat_policy_add_del_if;\
  vapi_msg_id_t vapi_msg_id_cnat_snat_policy_add_del_if_reply;\
  vapi_msg_id_t vapi_msg_id_cnat_set_snat_policy;\
  vapi_msg_id_t vapi_msg_id_cnat_set_snat_policy_reply;


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

#ifndef defined_vapi_enum_fib_path_nh_proto
#define defined_vapi_enum_fib_path_nh_proto
typedef enum {
  FIB_API_PATH_NH_PROTO_IP4 = 0,
  FIB_API_PATH_NH_PROTO_IP6 = 1,
  FIB_API_PATH_NH_PROTO_MPLS = 2,
  FIB_API_PATH_NH_PROTO_ETHERNET = 3,
  FIB_API_PATH_NH_PROTO_BIER = 4,
}  vapi_enum_fib_path_nh_proto;

#endif

#ifndef defined_vapi_enum_fib_path_flags
#define defined_vapi_enum_fib_path_flags
typedef enum {
  FIB_API_PATH_FLAG_NONE = 0,
  FIB_API_PATH_FLAG_RESOLVE_VIA_ATTACHED = 1,
  FIB_API_PATH_FLAG_RESOLVE_VIA_HOST = 2,
  FIB_API_PATH_FLAG_POP_PW_CW = 4,
}  vapi_enum_fib_path_flags;

#endif

#ifndef defined_vapi_enum_fib_path_type
#define defined_vapi_enum_fib_path_type
typedef enum {
  FIB_API_PATH_TYPE_NORMAL = 0,
  FIB_API_PATH_TYPE_LOCAL = 1,
  FIB_API_PATH_TYPE_DROP = 2,
  FIB_API_PATH_TYPE_UDP_ENCAP = 3,
  FIB_API_PATH_TYPE_BIER_IMP = 4,
  FIB_API_PATH_TYPE_ICMP_UNREACH = 5,
  FIB_API_PATH_TYPE_ICMP_PROHIBIT = 6,
  FIB_API_PATH_TYPE_SOURCE_LOOKUP = 7,
  FIB_API_PATH_TYPE_DVR = 8,
  FIB_API_PATH_TYPE_INTERFACE_RX = 9,
  FIB_API_PATH_TYPE_CLASSIFY = 10,
}  vapi_enum_fib_path_type;

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

#ifndef defined_vapi_enum_fib_path_nh_proto
#define defined_vapi_enum_fib_path_nh_proto
typedef enum {
  FIB_API_PATH_NH_PROTO_IP4 = 0,
  FIB_API_PATH_NH_PROTO_IP6 = 1,
  FIB_API_PATH_NH_PROTO_MPLS = 2,
  FIB_API_PATH_NH_PROTO_ETHERNET = 3,
  FIB_API_PATH_NH_PROTO_BIER = 4,
}  vapi_enum_fib_path_nh_proto;

#endif

#ifndef defined_vapi_enum_fib_path_flags
#define defined_vapi_enum_fib_path_flags
typedef enum {
  FIB_API_PATH_FLAG_NONE = 0,
  FIB_API_PATH_FLAG_RESOLVE_VIA_ATTACHED = 1,
  FIB_API_PATH_FLAG_RESOLVE_VIA_HOST = 2,
  FIB_API_PATH_FLAG_POP_PW_CW = 4,
}  vapi_enum_fib_path_flags;

#endif

#ifndef defined_vapi_enum_fib_path_type
#define defined_vapi_enum_fib_path_type
typedef enum {
  FIB_API_PATH_TYPE_NORMAL = 0,
  FIB_API_PATH_TYPE_LOCAL = 1,
  FIB_API_PATH_TYPE_DROP = 2,
  FIB_API_PATH_TYPE_UDP_ENCAP = 3,
  FIB_API_PATH_TYPE_BIER_IMP = 4,
  FIB_API_PATH_TYPE_ICMP_UNREACH = 5,
  FIB_API_PATH_TYPE_ICMP_PROHIBIT = 6,
  FIB_API_PATH_TYPE_SOURCE_LOOKUP = 7,
  FIB_API_PATH_TYPE_DVR = 8,
  FIB_API_PATH_TYPE_INTERFACE_RX = 9,
  FIB_API_PATH_TYPE_CLASSIFY = 10,
}  vapi_enum_fib_path_type;

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

#ifndef defined_vapi_enum_fib_path_nh_proto
#define defined_vapi_enum_fib_path_nh_proto
typedef enum {
  FIB_API_PATH_NH_PROTO_IP4 = 0,
  FIB_API_PATH_NH_PROTO_IP6 = 1,
  FIB_API_PATH_NH_PROTO_MPLS = 2,
  FIB_API_PATH_NH_PROTO_ETHERNET = 3,
  FIB_API_PATH_NH_PROTO_BIER = 4,
}  vapi_enum_fib_path_nh_proto;

#endif

#ifndef defined_vapi_enum_fib_path_flags
#define defined_vapi_enum_fib_path_flags
typedef enum {
  FIB_API_PATH_FLAG_NONE = 0,
  FIB_API_PATH_FLAG_RESOLVE_VIA_ATTACHED = 1,
  FIB_API_PATH_FLAG_RESOLVE_VIA_HOST = 2,
  FIB_API_PATH_FLAG_POP_PW_CW = 4,
}  vapi_enum_fib_path_flags;

#endif

#ifndef defined_vapi_enum_fib_path_type
#define defined_vapi_enum_fib_path_type
typedef enum {
  FIB_API_PATH_TYPE_NORMAL = 0,
  FIB_API_PATH_TYPE_LOCAL = 1,
  FIB_API_PATH_TYPE_DROP = 2,
  FIB_API_PATH_TYPE_UDP_ENCAP = 3,
  FIB_API_PATH_TYPE_BIER_IMP = 4,
  FIB_API_PATH_TYPE_ICMP_UNREACH = 5,
  FIB_API_PATH_TYPE_ICMP_PROHIBIT = 6,
  FIB_API_PATH_TYPE_SOURCE_LOOKUP = 7,
  FIB_API_PATH_TYPE_DVR = 8,
  FIB_API_PATH_TYPE_INTERFACE_RX = 9,
  FIB_API_PATH_TYPE_CLASSIFY = 10,
}  vapi_enum_fib_path_type;

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

#ifndef defined_vapi_enum_mfib_entry_flags
#define defined_vapi_enum_mfib_entry_flags
typedef enum {
  MFIB_API_ENTRY_FLAG_NONE = 0,
  MFIB_API_ENTRY_FLAG_SIGNAL = 1,
  MFIB_API_ENTRY_FLAG_DROP = 2,
  MFIB_API_ENTRY_FLAG_CONNECTED = 4,
  MFIB_API_ENTRY_FLAG_ACCEPT_ALL_ITF = 8,
}  vapi_enum_mfib_entry_flags;

#endif

#ifndef defined_vapi_enum_mfib_itf_flags
#define defined_vapi_enum_mfib_itf_flags
typedef enum {
  MFIB_API_ITF_FLAG_NONE = 0,
  MFIB_API_ITF_FLAG_NEGATE_SIGNAL = 1,
  MFIB_API_ITF_FLAG_ACCEPT = 2,
  MFIB_API_ITF_FLAG_FORWARD = 4,
  MFIB_API_ITF_FLAG_SIGNAL_PRESENT = 8,
  MFIB_API_ITF_FLAG_DONT_PRESERVE = 16,
}  vapi_enum_mfib_itf_flags;

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

#ifndef defined_vapi_enum_ip_reass_type
#define defined_vapi_enum_ip_reass_type
typedef enum {
  IP_REASS_TYPE_FULL = 0,
  IP_REASS_TYPE_SHALLOW_VIRTUAL = 1,
}  vapi_enum_ip_reass_type;

#endif

#ifndef defined_vapi_enum_cnat_translation_flags
#define defined_vapi_enum_cnat_translation_flags
typedef enum {
  CNAT_TRANSLATION_ALLOC_PORT = 1,
  CNAT_TRANSLATION_NO_RETURN_SESSION = 4,
} __attribute__((packed)) vapi_enum_cnat_translation_flags;

#endif

#ifndef defined_vapi_enum_cnat_endpoint_tuple_flags
#define defined_vapi_enum_cnat_endpoint_tuple_flags
typedef enum {
  CNAT_EPT_NO_NAT = 1,
} __attribute__((packed)) vapi_enum_cnat_endpoint_tuple_flags;

#endif

#ifndef defined_vapi_enum_cnat_lb_type
#define defined_vapi_enum_cnat_lb_type
typedef enum {
  CNAT_LB_TYPE_DEFAULT = 0,
  CNAT_LB_TYPE_MAGLEV = 1,
} __attribute__((packed)) vapi_enum_cnat_lb_type;

#endif

#ifndef defined_vapi_enum_cnat_snat_policy_table
#define defined_vapi_enum_cnat_snat_policy_table
typedef enum {
  CNAT_POLICY_INCLUDE_V4 = 0,
  CNAT_POLICY_INCLUDE_V6 = 1,
  CNAT_POLICY_POD = 2,
  CNAT_POLICY_HOST = 3,
} __attribute__((packed)) vapi_enum_cnat_snat_policy_table;

#endif

#ifndef defined_vapi_enum_cnat_snat_policies
#define defined_vapi_enum_cnat_snat_policies
typedef enum {
  CNAT_POLICY_NONE = 0,
  CNAT_POLICY_IF_PFX = 1,
  CNAT_POLICY_K8S = 2,
} __attribute__((packed)) vapi_enum_cnat_snat_policies;

#endif

#ifndef defined_vapi_enum_ip_flow_hash_config
#define defined_vapi_enum_ip_flow_hash_config
typedef enum {
  IP_API_FLOW_HASH_SRC_IP = 1,
  IP_API_FLOW_HASH_DST_IP = 2,
  IP_API_FLOW_HASH_SRC_PORT = 4,
  IP_API_FLOW_HASH_DST_PORT = 8,
  IP_API_FLOW_HASH_PROTO = 16,
  IP_API_FLOW_HASH_REVERSE = 32,
  IP_API_FLOW_HASH_SYMETRIC = 64,
  IP_API_FLOW_HASH_FLOW_LABEL = 128,
}  vapi_enum_ip_flow_hash_config;

#endif

#ifndef defined_vapi_enum_ip_flow_hash_config_v2
#define defined_vapi_enum_ip_flow_hash_config_v2
typedef enum {
  IP_API_V2_FLOW_HASH_SRC_IP = 1,
  IP_API_V2_FLOW_HASH_DST_IP = 2,
  IP_API_V2_FLOW_HASH_SRC_PORT = 4,
  IP_API_V2_FLOW_HASH_DST_PORT = 8,
  IP_API_V2_FLOW_HASH_PROTO = 16,
  IP_API_V2_FLOW_HASH_REVERSE = 32,
  IP_API_V2_FLOW_HASH_SYMETRIC = 64,
  IP_API_V2_FLOW_HASH_FLOW_LABEL = 128,
  IP_API_V2_FLOW_HASH_GTPV1_TEID = 256,
}  vapi_enum_ip_flow_hash_config_v2;

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

#ifndef defined_vapi_type_fib_mpls_label
#define defined_vapi_type_fib_mpls_label
typedef struct __attribute__((__packed__)) {
  u8 is_uniform;
  u32 label;
  u8 ttl;
  u8 exp;
} vapi_type_fib_mpls_label;

static inline void vapi_type_fib_mpls_label_hton(vapi_type_fib_mpls_label *msg)
{
  msg->label = htobe32(msg->label);
}

static inline void vapi_type_fib_mpls_label_ntoh(vapi_type_fib_mpls_label *msg)
{
  msg->label = be32toh(msg->label);
}
#endif

#ifndef defined_vapi_type_ip_table
#define defined_vapi_type_ip_table
typedef struct __attribute__((__packed__)) {
  u32 table_id;
  bool is_ip6;
  u8 name[64];
} vapi_type_ip_table;

static inline void vapi_type_ip_table_hton(vapi_type_ip_table *msg)
{
  msg->table_id = htobe32(msg->table_id);
}

static inline void vapi_type_ip_table_ntoh(vapi_type_ip_table *msg)
{
  msg->table_id = be32toh(msg->table_id);
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

#ifndef defined_vapi_type_fib_path_nh
#define defined_vapi_type_fib_path_nh
typedef struct __attribute__((__packed__)) {
  vapi_union_address_union address;
  u32 via_label;
  u32 obj_id;
  u32 classify_table_index;
} vapi_type_fib_path_nh;

static inline void vapi_type_fib_path_nh_hton(vapi_type_fib_path_nh *msg)
{
  msg->via_label = htobe32(msg->via_label);
  msg->obj_id = htobe32(msg->obj_id);
  msg->classify_table_index = htobe32(msg->classify_table_index);
}

static inline void vapi_type_fib_path_nh_ntoh(vapi_type_fib_path_nh *msg)
{
  msg->via_label = be32toh(msg->via_label);
  msg->obj_id = be32toh(msg->obj_id);
  msg->classify_table_index = be32toh(msg->classify_table_index);
}
#endif

#ifndef defined_vapi_type_fib_path
#define defined_vapi_type_fib_path
typedef struct __attribute__((__packed__)) {
  u32 sw_if_index;
  u32 table_id;
  u32 rpf_id;
  u8 weight;
  u8 preference;
  vapi_enum_fib_path_type type;
  vapi_enum_fib_path_flags flags;
  vapi_enum_fib_path_nh_proto proto;
  vapi_type_fib_path_nh nh;
  u8 n_labels;
  vapi_type_fib_mpls_label label_stack[16];
} vapi_type_fib_path;

static inline void vapi_type_fib_path_hton(vapi_type_fib_path *msg)
{
  msg->sw_if_index = htobe32(msg->sw_if_index);
  msg->table_id = htobe32(msg->table_id);
  msg->rpf_id = htobe32(msg->rpf_id);
  msg->type = (vapi_enum_fib_path_type)htobe32(msg->type);
  msg->flags = (vapi_enum_fib_path_flags)htobe32(msg->flags);
  msg->proto = (vapi_enum_fib_path_nh_proto)htobe32(msg->proto);
  vapi_type_fib_path_nh_hton(&msg->nh);
  do { unsigned i; for (i = 0; i < 16; ++i) { vapi_type_fib_mpls_label_hton(&msg->label_stack[i]); } } while(0);
}

static inline void vapi_type_fib_path_ntoh(vapi_type_fib_path *msg)
{
  msg->sw_if_index = be32toh(msg->sw_if_index);
  msg->table_id = be32toh(msg->table_id);
  msg->rpf_id = be32toh(msg->rpf_id);
  msg->type = (vapi_enum_fib_path_type)be32toh(msg->type);
  msg->flags = (vapi_enum_fib_path_flags)be32toh(msg->flags);
  msg->proto = (vapi_enum_fib_path_nh_proto)be32toh(msg->proto);
  vapi_type_fib_path_nh_ntoh(&msg->nh);
  do { unsigned i; for (i = 0; i < 16; ++i) { vapi_type_fib_mpls_label_ntoh(&msg->label_stack[i]); } } while(0);
}
#endif

#ifndef defined_vapi_type_mfib_path
#define defined_vapi_type_mfib_path
typedef struct __attribute__((__packed__)) {
  vapi_enum_mfib_itf_flags itf_flags;
  vapi_type_fib_path path;
} vapi_type_mfib_path;

static inline void vapi_type_mfib_path_hton(vapi_type_mfib_path *msg)
{
  msg->itf_flags = (vapi_enum_mfib_itf_flags)htobe32(msg->itf_flags);
  vapi_type_fib_path_hton(&msg->path);
}

static inline void vapi_type_mfib_path_ntoh(vapi_type_mfib_path *msg)
{
  msg->itf_flags = (vapi_enum_mfib_itf_flags)be32toh(msg->itf_flags);
  vapi_type_fib_path_ntoh(&msg->path);
}
#endif

#ifndef defined_vapi_type_ip_route
#define defined_vapi_type_ip_route
typedef struct __attribute__((__packed__)) {
  u32 table_id;
  u32 stats_index;
  vapi_type_prefix prefix;
  u8 n_paths;
  vapi_type_fib_path paths[0];
} vapi_type_ip_route;

static inline void vapi_type_ip_route_hton(vapi_type_ip_route *msg)
{
  msg->table_id = htobe32(msg->table_id);
  msg->stats_index = htobe32(msg->stats_index);
  do { unsigned i; for (i = 0; i < msg->n_paths; ++i) { vapi_type_fib_path_hton(&msg->paths[i]); } } while(0);
}

static inline void vapi_type_ip_route_ntoh(vapi_type_ip_route *msg)
{
  msg->table_id = be32toh(msg->table_id);
  msg->stats_index = be32toh(msg->stats_index);
  do { unsigned i; for (i = 0; i < msg->n_paths; ++i) { vapi_type_fib_path_ntoh(&msg->paths[i]); } } while(0);
}
#endif

#ifndef defined_vapi_type_ip_route_v2
#define defined_vapi_type_ip_route_v2
typedef struct __attribute__((__packed__)) {
  u32 table_id;
  u32 stats_index;
  vapi_type_prefix prefix;
  u8 n_paths;
  u8 src;
  vapi_type_fib_path paths[0];
} vapi_type_ip_route_v2;

static inline void vapi_type_ip_route_v2_hton(vapi_type_ip_route_v2 *msg)
{
  msg->table_id = htobe32(msg->table_id);
  msg->stats_index = htobe32(msg->stats_index);
  do { unsigned i; for (i = 0; i < msg->n_paths; ++i) { vapi_type_fib_path_hton(&msg->paths[i]); } } while(0);
}

static inline void vapi_type_ip_route_v2_ntoh(vapi_type_ip_route_v2 *msg)
{
  msg->table_id = be32toh(msg->table_id);
  msg->stats_index = be32toh(msg->stats_index);
  do { unsigned i; for (i = 0; i < msg->n_paths; ++i) { vapi_type_fib_path_ntoh(&msg->paths[i]); } } while(0);
}
#endif

#ifndef defined_vapi_type_ip_mroute
#define defined_vapi_type_ip_mroute
typedef struct __attribute__((__packed__)) {
  u32 table_id;
  vapi_enum_mfib_entry_flags entry_flags;
  u32 rpf_id;
  vapi_type_mprefix prefix;
  u8 n_paths;
  vapi_type_mfib_path paths[0];
} vapi_type_ip_mroute;

static inline void vapi_type_ip_mroute_hton(vapi_type_ip_mroute *msg)
{
  msg->table_id = htobe32(msg->table_id);
  msg->entry_flags = (vapi_enum_mfib_entry_flags)htobe32(msg->entry_flags);
  msg->rpf_id = htobe32(msg->rpf_id);
  vapi_type_mprefix_hton(&msg->prefix);
  do { unsigned i; for (i = 0; i < msg->n_paths; ++i) { vapi_type_mfib_path_hton(&msg->paths[i]); } } while(0);
}

static inline void vapi_type_ip_mroute_ntoh(vapi_type_ip_mroute *msg)
{
  msg->table_id = be32toh(msg->table_id);
  msg->entry_flags = (vapi_enum_mfib_entry_flags)be32toh(msg->entry_flags);
  msg->rpf_id = be32toh(msg->rpf_id);
  vapi_type_mprefix_ntoh(&msg->prefix);
  do { unsigned i; for (i = 0; i < msg->n_paths; ++i) { vapi_type_mfib_path_ntoh(&msg->paths[i]); } } while(0);
}
#endif

#ifndef defined_vapi_type_interface_index
#define defined_vapi_type_interface_index
typedef u32 vapi_type_interface_index;

#endif

#ifndef defined_vapi_type_punt_redirect
#define defined_vapi_type_punt_redirect
typedef struct __attribute__((__packed__)) {
  vapi_type_interface_index rx_sw_if_index;
  vapi_type_interface_index tx_sw_if_index;
  vapi_type_address nh;
} vapi_type_punt_redirect;

static inline void vapi_type_punt_redirect_hton(vapi_type_punt_redirect *msg)
{
  msg->rx_sw_if_index = htobe32(msg->rx_sw_if_index);
  msg->tx_sw_if_index = htobe32(msg->tx_sw_if_index);
}

static inline void vapi_type_punt_redirect_ntoh(vapi_type_punt_redirect *msg)
{
  msg->rx_sw_if_index = be32toh(msg->rx_sw_if_index);
  msg->tx_sw_if_index = be32toh(msg->tx_sw_if_index);
}
#endif

#ifndef defined_vapi_type_punt_redirect_v2
#define defined_vapi_type_punt_redirect_v2
typedef struct __attribute__((__packed__)) {
  vapi_type_interface_index rx_sw_if_index;
  vapi_enum_address_family af;
  u32 n_paths;
  vapi_type_fib_path paths[0];
} vapi_type_punt_redirect_v2;

static inline void vapi_type_punt_redirect_v2_hton(vapi_type_punt_redirect_v2 *msg)
{
  msg->rx_sw_if_index = htobe32(msg->rx_sw_if_index);
  msg->n_paths = htobe32(msg->n_paths);
  do { unsigned i; for (i = 0; i < be32toh(msg->n_paths); ++i) { vapi_type_fib_path_hton(&msg->paths[i]); } } while(0);
}

static inline void vapi_type_punt_redirect_v2_ntoh(vapi_type_punt_redirect_v2 *msg)
{
  msg->rx_sw_if_index = be32toh(msg->rx_sw_if_index);
  msg->n_paths = be32toh(msg->n_paths);
  do { unsigned i; for (i = 0; i < msg->n_paths; ++i) { vapi_type_fib_path_ntoh(&msg->paths[i]); } } while(0);
}
#endif

#ifndef defined_vapi_type_ip_path_mtu
#define defined_vapi_type_ip_path_mtu
typedef struct __attribute__((__packed__)) {
  u32 client_index;
  u32 context;
  u32 table_id;
  vapi_type_address nh;
  u16 path_mtu;
} vapi_type_ip_path_mtu;

static inline void vapi_type_ip_path_mtu_hton(vapi_type_ip_path_mtu *msg)
{
  msg->client_index = htobe32(msg->client_index);
  msg->context = htobe32(msg->context);
  msg->table_id = htobe32(msg->table_id);
  msg->path_mtu = htobe16(msg->path_mtu);
}

static inline void vapi_type_ip_path_mtu_ntoh(vapi_type_ip_path_mtu *msg)
{
  msg->client_index = be32toh(msg->client_index);
  msg->context = be32toh(msg->context);
  msg->table_id = be32toh(msg->table_id);
  msg->path_mtu = be16toh(msg->path_mtu);
}
#endif

#ifndef defined_vapi_type_cnat_endpoint
#define defined_vapi_type_cnat_endpoint
typedef struct __attribute__((__packed__)) {
  vapi_type_address addr;
  vapi_type_interface_index sw_if_index;
  vapi_enum_address_family if_af;
  u16 port;
} vapi_type_cnat_endpoint;

static inline void vapi_type_cnat_endpoint_hton(vapi_type_cnat_endpoint *msg)
{
  msg->sw_if_index = htobe32(msg->sw_if_index);
  msg->port = htobe16(msg->port);
}

static inline void vapi_type_cnat_endpoint_ntoh(vapi_type_cnat_endpoint *msg)
{
  msg->sw_if_index = be32toh(msg->sw_if_index);
  msg->port = be16toh(msg->port);
}
#endif

#ifndef defined_vapi_type_cnat_endpoint_tuple
#define defined_vapi_type_cnat_endpoint_tuple
typedef struct __attribute__((__packed__)) {
  vapi_type_cnat_endpoint dst_ep;
  vapi_type_cnat_endpoint src_ep;
  u8 flags;
} vapi_type_cnat_endpoint_tuple;

static inline void vapi_type_cnat_endpoint_tuple_hton(vapi_type_cnat_endpoint_tuple *msg)
{
  vapi_type_cnat_endpoint_hton(&msg->dst_ep);
  vapi_type_cnat_endpoint_hton(&msg->src_ep);
}

static inline void vapi_type_cnat_endpoint_tuple_ntoh(vapi_type_cnat_endpoint_tuple *msg)
{
  vapi_type_cnat_endpoint_ntoh(&msg->dst_ep);
  vapi_type_cnat_endpoint_ntoh(&msg->src_ep);
}
#endif

#ifndef defined_vapi_type_cnat_translation
#define defined_vapi_type_cnat_translation
typedef struct __attribute__((__packed__)) {
  vapi_type_cnat_endpoint vip;
  u32 id;
  vapi_enum_ip_proto ip_proto;
  u8 is_real_ip;
  u8 flags;
  vapi_enum_cnat_lb_type lb_type;
  u32 n_paths;
  vapi_enum_ip_flow_hash_config_v2 flow_hash_config;
  vapi_type_cnat_endpoint_tuple paths[0];
} vapi_type_cnat_translation;

static inline void vapi_type_cnat_translation_hton(vapi_type_cnat_translation *msg)
{
  vapi_type_cnat_endpoint_hton(&msg->vip);
  msg->id = htobe32(msg->id);
  msg->n_paths = htobe32(msg->n_paths);
  msg->flow_hash_config = (vapi_enum_ip_flow_hash_config_v2)htobe32(msg->flow_hash_config);
  do { unsigned i; for (i = 0; i < be32toh(msg->n_paths); ++i) { vapi_type_cnat_endpoint_tuple_hton(&msg->paths[i]); } } while(0);
}

static inline void vapi_type_cnat_translation_ntoh(vapi_type_cnat_translation *msg)
{
  vapi_type_cnat_endpoint_ntoh(&msg->vip);
  msg->id = be32toh(msg->id);
  msg->n_paths = be32toh(msg->n_paths);
  msg->flow_hash_config = (vapi_enum_ip_flow_hash_config_v2)be32toh(msg->flow_hash_config);
  do { unsigned i; for (i = 0; i < msg->n_paths; ++i) { vapi_type_cnat_endpoint_tuple_ntoh(&msg->paths[i]); } } while(0);
}
#endif

#ifndef defined_vapi_type_cnat_session
#define defined_vapi_type_cnat_session
typedef struct __attribute__((__packed__)) {
  vapi_type_cnat_endpoint src;
  vapi_type_cnat_endpoint dst;
  vapi_type_cnat_endpoint new;
  vapi_enum_ip_proto ip_proto;
  u8 location;
  f64 timestamp;
} vapi_type_cnat_session;

static inline void vapi_type_cnat_session_hton(vapi_type_cnat_session *msg)
{
  vapi_type_cnat_endpoint_hton(&msg->src);
  vapi_type_cnat_endpoint_hton(&msg->dst);
  vapi_type_cnat_endpoint_hton(&msg->new);
}

static inline void vapi_type_cnat_session_ntoh(vapi_type_cnat_session *msg)
{
  vapi_type_cnat_endpoint_ntoh(&msg->src);
  vapi_type_cnat_endpoint_ntoh(&msg->dst);
  vapi_type_cnat_endpoint_ntoh(&msg->new);
}
#endif

#ifndef defined_vapi_type_mac_address
#define defined_vapi_type_mac_address
typedef u8 vapi_type_mac_address[6];

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

#ifndef defined_vapi_msg_cnat_translation_update_reply
#define defined_vapi_msg_cnat_translation_update_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 id; 
} vapi_payload_cnat_translation_update_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_cnat_translation_update_reply payload;
} vapi_msg_cnat_translation_update_reply;

static inline void vapi_msg_cnat_translation_update_reply_payload_hton(vapi_payload_cnat_translation_update_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->id = htobe32(payload->id);
}

static inline void vapi_msg_cnat_translation_update_reply_payload_ntoh(vapi_payload_cnat_translation_update_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->id = be32toh(payload->id);
}

static inline void vapi_msg_cnat_translation_update_reply_hton(vapi_msg_cnat_translation_update_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_translation_update_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_cnat_translation_update_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_cnat_translation_update_reply_ntoh(vapi_msg_cnat_translation_update_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_translation_update_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_cnat_translation_update_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_cnat_translation_update_reply_msg_size(vapi_msg_cnat_translation_update_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_cnat_translation_update_reply_msg_size(vapi_msg_cnat_translation_update_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cnat_translation_update_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_translation_update_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cnat_translation_update_reply));
      return -1;
    }
  if (vapi_calc_cnat_translation_update_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_translation_update_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cnat_translation_update_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_cnat_translation_update_reply()
{
  static const char name[] = "cnat_translation_update_reply";
  static const char name_with_crc[] = "cnat_translation_update_reply_e2fc8294";
  static vapi_message_desc_t __vapi_metadata_cnat_translation_update_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_cnat_translation_update_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_cnat_translation_update_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_cnat_translation_update_reply_hton,
    (generic_swap_fn_t)vapi_msg_cnat_translation_update_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cnat_translation_update_reply = vapi_register_msg(&__vapi_metadata_cnat_translation_update_reply);
  VAPI_DBG("Assigned msg id %d to cnat_translation_update_reply", vapi_msg_id_cnat_translation_update_reply);
}

static inline void vapi_set_vapi_msg_cnat_translation_update_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_cnat_translation_update_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_cnat_translation_update_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_cnat_translation_update
#define defined_vapi_msg_cnat_translation_update
typedef struct __attribute__ ((__packed__)) {
  vapi_type_cnat_translation translation; 
} vapi_payload_cnat_translation_update;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_cnat_translation_update payload;
} vapi_msg_cnat_translation_update;

static inline void vapi_msg_cnat_translation_update_payload_hton(vapi_payload_cnat_translation_update *payload)
{
  vapi_type_cnat_translation_hton(&payload->translation);
}

static inline void vapi_msg_cnat_translation_update_payload_ntoh(vapi_payload_cnat_translation_update *payload)
{
  vapi_type_cnat_translation_ntoh(&payload->translation);
}

static inline void vapi_msg_cnat_translation_update_hton(vapi_msg_cnat_translation_update *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_translation_update'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_cnat_translation_update_payload_hton(&msg->payload);
}

static inline void vapi_msg_cnat_translation_update_ntoh(vapi_msg_cnat_translation_update *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_translation_update'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_cnat_translation_update_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_cnat_translation_update_msg_size(vapi_msg_cnat_translation_update *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.translation.paths[0]) * msg->payload.translation.n_paths;
}

static inline int vapi_verify_cnat_translation_update_msg_size(vapi_msg_cnat_translation_update *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cnat_translation_update) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_translation_update' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cnat_translation_update));
      return -1;
    }
  if (vapi_calc_cnat_translation_update_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_translation_update' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cnat_translation_update_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_cnat_translation_update* vapi_alloc_cnat_translation_update(struct vapi_ctx_s *ctx, size_t translation_paths_array_size)
{
  vapi_msg_cnat_translation_update *msg = NULL;
  const size_t size = sizeof(vapi_msg_cnat_translation_update) + sizeof(msg->payload.translation.paths[0]) * translation_paths_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_cnat_translation_update*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_cnat_translation_update);
  msg->payload.translation.n_paths = translation_paths_array_size;

  return msg;
}

static inline vapi_error_e vapi_cnat_translation_update(struct vapi_ctx_s *ctx,
  vapi_msg_cnat_translation_update *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_cnat_translation_update_reply *reply),
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
  vapi_msg_cnat_translation_update_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_cnat_translation_update_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_cnat_translation_update_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_cnat_translation_update()
{
  static const char name[] = "cnat_translation_update";
  static const char name_with_crc[] = "cnat_translation_update_f8d40bc5";
  static vapi_message_desc_t __vapi_metadata_cnat_translation_update = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_cnat_translation_update, payload),
    (verify_msg_size_fn_t)vapi_verify_cnat_translation_update_msg_size,
    (generic_swap_fn_t)vapi_msg_cnat_translation_update_hton,
    (generic_swap_fn_t)vapi_msg_cnat_translation_update_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cnat_translation_update = vapi_register_msg(&__vapi_metadata_cnat_translation_update);
  VAPI_DBG("Assigned msg id %d to cnat_translation_update", vapi_msg_id_cnat_translation_update);
}
#endif

#ifndef defined_vapi_msg_cnat_translation_del_reply
#define defined_vapi_msg_cnat_translation_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_cnat_translation_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_cnat_translation_del_reply payload;
} vapi_msg_cnat_translation_del_reply;

static inline void vapi_msg_cnat_translation_del_reply_payload_hton(vapi_payload_cnat_translation_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_cnat_translation_del_reply_payload_ntoh(vapi_payload_cnat_translation_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_cnat_translation_del_reply_hton(vapi_msg_cnat_translation_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_translation_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_cnat_translation_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_cnat_translation_del_reply_ntoh(vapi_msg_cnat_translation_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_translation_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_cnat_translation_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_cnat_translation_del_reply_msg_size(vapi_msg_cnat_translation_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_cnat_translation_del_reply_msg_size(vapi_msg_cnat_translation_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cnat_translation_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_translation_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cnat_translation_del_reply));
      return -1;
    }
  if (vapi_calc_cnat_translation_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_translation_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cnat_translation_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_cnat_translation_del_reply()
{
  static const char name[] = "cnat_translation_del_reply";
  static const char name_with_crc[] = "cnat_translation_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_cnat_translation_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_cnat_translation_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_cnat_translation_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_cnat_translation_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_cnat_translation_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cnat_translation_del_reply = vapi_register_msg(&__vapi_metadata_cnat_translation_del_reply);
  VAPI_DBG("Assigned msg id %d to cnat_translation_del_reply", vapi_msg_id_cnat_translation_del_reply);
}

static inline void vapi_set_vapi_msg_cnat_translation_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_cnat_translation_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_cnat_translation_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_cnat_translation_del
#define defined_vapi_msg_cnat_translation_del
typedef struct __attribute__ ((__packed__)) {
  u32 id; 
} vapi_payload_cnat_translation_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_cnat_translation_del payload;
} vapi_msg_cnat_translation_del;

static inline void vapi_msg_cnat_translation_del_payload_hton(vapi_payload_cnat_translation_del *payload)
{
  payload->id = htobe32(payload->id);
}

static inline void vapi_msg_cnat_translation_del_payload_ntoh(vapi_payload_cnat_translation_del *payload)
{
  payload->id = be32toh(payload->id);
}

static inline void vapi_msg_cnat_translation_del_hton(vapi_msg_cnat_translation_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_translation_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_cnat_translation_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_cnat_translation_del_ntoh(vapi_msg_cnat_translation_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_translation_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_cnat_translation_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_cnat_translation_del_msg_size(vapi_msg_cnat_translation_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_cnat_translation_del_msg_size(vapi_msg_cnat_translation_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cnat_translation_del) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_translation_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cnat_translation_del));
      return -1;
    }
  if (vapi_calc_cnat_translation_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_translation_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cnat_translation_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_cnat_translation_del* vapi_alloc_cnat_translation_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_cnat_translation_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_cnat_translation_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_cnat_translation_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_cnat_translation_del);

  return msg;
}

static inline vapi_error_e vapi_cnat_translation_del(struct vapi_ctx_s *ctx,
  vapi_msg_cnat_translation_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_cnat_translation_del_reply *reply),
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
  vapi_msg_cnat_translation_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_cnat_translation_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_cnat_translation_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_cnat_translation_del()
{
  static const char name[] = "cnat_translation_del";
  static const char name_with_crc[] = "cnat_translation_del_3a91bde5";
  static vapi_message_desc_t __vapi_metadata_cnat_translation_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_cnat_translation_del, payload),
    (verify_msg_size_fn_t)vapi_verify_cnat_translation_del_msg_size,
    (generic_swap_fn_t)vapi_msg_cnat_translation_del_hton,
    (generic_swap_fn_t)vapi_msg_cnat_translation_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cnat_translation_del = vapi_register_msg(&__vapi_metadata_cnat_translation_del);
  VAPI_DBG("Assigned msg id %d to cnat_translation_del", vapi_msg_id_cnat_translation_del);
}
#endif

#ifndef defined_vapi_msg_cnat_translation_details
#define defined_vapi_msg_cnat_translation_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_cnat_translation translation; 
} vapi_payload_cnat_translation_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_cnat_translation_details payload;
} vapi_msg_cnat_translation_details;

static inline void vapi_msg_cnat_translation_details_payload_hton(vapi_payload_cnat_translation_details *payload)
{
  vapi_type_cnat_translation_hton(&payload->translation);
}

static inline void vapi_msg_cnat_translation_details_payload_ntoh(vapi_payload_cnat_translation_details *payload)
{
  vapi_type_cnat_translation_ntoh(&payload->translation);
}

static inline void vapi_msg_cnat_translation_details_hton(vapi_msg_cnat_translation_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_translation_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_cnat_translation_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_cnat_translation_details_ntoh(vapi_msg_cnat_translation_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_translation_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_cnat_translation_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_cnat_translation_details_msg_size(vapi_msg_cnat_translation_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.translation.paths[0]) * msg->payload.translation.n_paths;
}

static inline int vapi_verify_cnat_translation_details_msg_size(vapi_msg_cnat_translation_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cnat_translation_details) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_translation_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cnat_translation_details));
      return -1;
    }
  if (vapi_calc_cnat_translation_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_translation_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cnat_translation_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_cnat_translation_details()
{
  static const char name[] = "cnat_translation_details";
  static const char name_with_crc[] = "cnat_translation_details_1a5140b7";
  static vapi_message_desc_t __vapi_metadata_cnat_translation_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_cnat_translation_details, payload),
    (verify_msg_size_fn_t)vapi_verify_cnat_translation_details_msg_size,
    (generic_swap_fn_t)vapi_msg_cnat_translation_details_hton,
    (generic_swap_fn_t)vapi_msg_cnat_translation_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cnat_translation_details = vapi_register_msg(&__vapi_metadata_cnat_translation_details);
  VAPI_DBG("Assigned msg id %d to cnat_translation_details", vapi_msg_id_cnat_translation_details);
}

static inline void vapi_set_vapi_msg_cnat_translation_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_cnat_translation_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_cnat_translation_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_cnat_translation_dump
#define defined_vapi_msg_cnat_translation_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_cnat_translation_dump;

static inline void vapi_msg_cnat_translation_dump_hton(vapi_msg_cnat_translation_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_translation_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_cnat_translation_dump_ntoh(vapi_msg_cnat_translation_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_translation_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_cnat_translation_dump_msg_size(vapi_msg_cnat_translation_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_cnat_translation_dump_msg_size(vapi_msg_cnat_translation_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cnat_translation_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_translation_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cnat_translation_dump));
      return -1;
    }
  if (vapi_calc_cnat_translation_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_translation_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cnat_translation_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_cnat_translation_dump* vapi_alloc_cnat_translation_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_cnat_translation_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_cnat_translation_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_cnat_translation_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_cnat_translation_dump);

  return msg;
}

static inline vapi_error_e vapi_cnat_translation_dump(struct vapi_ctx_s *ctx,
  vapi_msg_cnat_translation_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_cnat_translation_details *reply),
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
  vapi_msg_cnat_translation_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_cnat_translation_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_cnat_translation_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_cnat_translation_dump()
{
  static const char name[] = "cnat_translation_dump";
  static const char name_with_crc[] = "cnat_translation_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_cnat_translation_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_cnat_translation_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_cnat_translation_dump_hton,
    (generic_swap_fn_t)vapi_msg_cnat_translation_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cnat_translation_dump = vapi_register_msg(&__vapi_metadata_cnat_translation_dump);
  VAPI_DBG("Assigned msg id %d to cnat_translation_dump", vapi_msg_id_cnat_translation_dump);
}
#endif

#ifndef defined_vapi_msg_cnat_session_purge_reply
#define defined_vapi_msg_cnat_session_purge_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_cnat_session_purge_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_cnat_session_purge_reply payload;
} vapi_msg_cnat_session_purge_reply;

static inline void vapi_msg_cnat_session_purge_reply_payload_hton(vapi_payload_cnat_session_purge_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_cnat_session_purge_reply_payload_ntoh(vapi_payload_cnat_session_purge_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_cnat_session_purge_reply_hton(vapi_msg_cnat_session_purge_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_session_purge_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_cnat_session_purge_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_cnat_session_purge_reply_ntoh(vapi_msg_cnat_session_purge_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_session_purge_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_cnat_session_purge_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_cnat_session_purge_reply_msg_size(vapi_msg_cnat_session_purge_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_cnat_session_purge_reply_msg_size(vapi_msg_cnat_session_purge_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cnat_session_purge_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_session_purge_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cnat_session_purge_reply));
      return -1;
    }
  if (vapi_calc_cnat_session_purge_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_session_purge_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cnat_session_purge_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_cnat_session_purge_reply()
{
  static const char name[] = "cnat_session_purge_reply";
  static const char name_with_crc[] = "cnat_session_purge_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_cnat_session_purge_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_cnat_session_purge_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_cnat_session_purge_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_cnat_session_purge_reply_hton,
    (generic_swap_fn_t)vapi_msg_cnat_session_purge_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cnat_session_purge_reply = vapi_register_msg(&__vapi_metadata_cnat_session_purge_reply);
  VAPI_DBG("Assigned msg id %d to cnat_session_purge_reply", vapi_msg_id_cnat_session_purge_reply);
}

static inline void vapi_set_vapi_msg_cnat_session_purge_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_cnat_session_purge_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_cnat_session_purge_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_cnat_session_purge
#define defined_vapi_msg_cnat_session_purge
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_cnat_session_purge;

static inline void vapi_msg_cnat_session_purge_hton(vapi_msg_cnat_session_purge *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_session_purge'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_cnat_session_purge_ntoh(vapi_msg_cnat_session_purge *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_session_purge'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_cnat_session_purge_msg_size(vapi_msg_cnat_session_purge *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_cnat_session_purge_msg_size(vapi_msg_cnat_session_purge *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cnat_session_purge) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_session_purge' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cnat_session_purge));
      return -1;
    }
  if (vapi_calc_cnat_session_purge_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_session_purge' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cnat_session_purge_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_cnat_session_purge* vapi_alloc_cnat_session_purge(struct vapi_ctx_s *ctx)
{
  vapi_msg_cnat_session_purge *msg = NULL;
  const size_t size = sizeof(vapi_msg_cnat_session_purge);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_cnat_session_purge*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_cnat_session_purge);

  return msg;
}

static inline vapi_error_e vapi_cnat_session_purge(struct vapi_ctx_s *ctx,
  vapi_msg_cnat_session_purge *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_cnat_session_purge_reply *reply),
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
  vapi_msg_cnat_session_purge_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_cnat_session_purge_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_cnat_session_purge_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_cnat_session_purge()
{
  static const char name[] = "cnat_session_purge";
  static const char name_with_crc[] = "cnat_session_purge_51077d14";
  static vapi_message_desc_t __vapi_metadata_cnat_session_purge = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_cnat_session_purge_msg_size,
    (generic_swap_fn_t)vapi_msg_cnat_session_purge_hton,
    (generic_swap_fn_t)vapi_msg_cnat_session_purge_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cnat_session_purge = vapi_register_msg(&__vapi_metadata_cnat_session_purge);
  VAPI_DBG("Assigned msg id %d to cnat_session_purge", vapi_msg_id_cnat_session_purge);
}
#endif

#ifndef defined_vapi_msg_cnat_session_details
#define defined_vapi_msg_cnat_session_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_cnat_session session; 
} vapi_payload_cnat_session_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_cnat_session_details payload;
} vapi_msg_cnat_session_details;

static inline void vapi_msg_cnat_session_details_payload_hton(vapi_payload_cnat_session_details *payload)
{
  vapi_type_cnat_session_hton(&payload->session);
}

static inline void vapi_msg_cnat_session_details_payload_ntoh(vapi_payload_cnat_session_details *payload)
{
  vapi_type_cnat_session_ntoh(&payload->session);
}

static inline void vapi_msg_cnat_session_details_hton(vapi_msg_cnat_session_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_session_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_cnat_session_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_cnat_session_details_ntoh(vapi_msg_cnat_session_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_session_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_cnat_session_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_cnat_session_details_msg_size(vapi_msg_cnat_session_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_cnat_session_details_msg_size(vapi_msg_cnat_session_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cnat_session_details) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_session_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cnat_session_details));
      return -1;
    }
  if (vapi_calc_cnat_session_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_session_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cnat_session_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_cnat_session_details()
{
  static const char name[] = "cnat_session_details";
  static const char name_with_crc[] = "cnat_session_details_7e5017c7";
  static vapi_message_desc_t __vapi_metadata_cnat_session_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_cnat_session_details, payload),
    (verify_msg_size_fn_t)vapi_verify_cnat_session_details_msg_size,
    (generic_swap_fn_t)vapi_msg_cnat_session_details_hton,
    (generic_swap_fn_t)vapi_msg_cnat_session_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cnat_session_details = vapi_register_msg(&__vapi_metadata_cnat_session_details);
  VAPI_DBG("Assigned msg id %d to cnat_session_details", vapi_msg_id_cnat_session_details);
}

static inline void vapi_set_vapi_msg_cnat_session_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_cnat_session_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_cnat_session_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_cnat_session_dump
#define defined_vapi_msg_cnat_session_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_cnat_session_dump;

static inline void vapi_msg_cnat_session_dump_hton(vapi_msg_cnat_session_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_session_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_cnat_session_dump_ntoh(vapi_msg_cnat_session_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_session_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_cnat_session_dump_msg_size(vapi_msg_cnat_session_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_cnat_session_dump_msg_size(vapi_msg_cnat_session_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cnat_session_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_session_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cnat_session_dump));
      return -1;
    }
  if (vapi_calc_cnat_session_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_session_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cnat_session_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_cnat_session_dump* vapi_alloc_cnat_session_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_cnat_session_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_cnat_session_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_cnat_session_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_cnat_session_dump);

  return msg;
}

static inline vapi_error_e vapi_cnat_session_dump(struct vapi_ctx_s *ctx,
  vapi_msg_cnat_session_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_cnat_session_details *reply),
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
  vapi_msg_cnat_session_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_cnat_session_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_cnat_session_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_cnat_session_dump()
{
  static const char name[] = "cnat_session_dump";
  static const char name_with_crc[] = "cnat_session_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_cnat_session_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_cnat_session_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_cnat_session_dump_hton,
    (generic_swap_fn_t)vapi_msg_cnat_session_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cnat_session_dump = vapi_register_msg(&__vapi_metadata_cnat_session_dump);
  VAPI_DBG("Assigned msg id %d to cnat_session_dump", vapi_msg_id_cnat_session_dump);
}
#endif

#ifndef defined_vapi_msg_cnat_set_snat_addresses_reply
#define defined_vapi_msg_cnat_set_snat_addresses_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_cnat_set_snat_addresses_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_cnat_set_snat_addresses_reply payload;
} vapi_msg_cnat_set_snat_addresses_reply;

static inline void vapi_msg_cnat_set_snat_addresses_reply_payload_hton(vapi_payload_cnat_set_snat_addresses_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_cnat_set_snat_addresses_reply_payload_ntoh(vapi_payload_cnat_set_snat_addresses_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_cnat_set_snat_addresses_reply_hton(vapi_msg_cnat_set_snat_addresses_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_set_snat_addresses_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_cnat_set_snat_addresses_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_cnat_set_snat_addresses_reply_ntoh(vapi_msg_cnat_set_snat_addresses_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_set_snat_addresses_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_cnat_set_snat_addresses_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_cnat_set_snat_addresses_reply_msg_size(vapi_msg_cnat_set_snat_addresses_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_cnat_set_snat_addresses_reply_msg_size(vapi_msg_cnat_set_snat_addresses_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cnat_set_snat_addresses_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_set_snat_addresses_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cnat_set_snat_addresses_reply));
      return -1;
    }
  if (vapi_calc_cnat_set_snat_addresses_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_set_snat_addresses_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cnat_set_snat_addresses_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_cnat_set_snat_addresses_reply()
{
  static const char name[] = "cnat_set_snat_addresses_reply";
  static const char name_with_crc[] = "cnat_set_snat_addresses_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_cnat_set_snat_addresses_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_cnat_set_snat_addresses_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_cnat_set_snat_addresses_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_cnat_set_snat_addresses_reply_hton,
    (generic_swap_fn_t)vapi_msg_cnat_set_snat_addresses_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cnat_set_snat_addresses_reply = vapi_register_msg(&__vapi_metadata_cnat_set_snat_addresses_reply);
  VAPI_DBG("Assigned msg id %d to cnat_set_snat_addresses_reply", vapi_msg_id_cnat_set_snat_addresses_reply);
}

static inline void vapi_set_vapi_msg_cnat_set_snat_addresses_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_cnat_set_snat_addresses_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_cnat_set_snat_addresses_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_cnat_set_snat_addresses
#define defined_vapi_msg_cnat_set_snat_addresses
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address snat_ip4;
  vapi_type_ip6_address snat_ip6;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_cnat_set_snat_addresses;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_cnat_set_snat_addresses payload;
} vapi_msg_cnat_set_snat_addresses;

static inline void vapi_msg_cnat_set_snat_addresses_payload_hton(vapi_payload_cnat_set_snat_addresses *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_cnat_set_snat_addresses_payload_ntoh(vapi_payload_cnat_set_snat_addresses *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_cnat_set_snat_addresses_hton(vapi_msg_cnat_set_snat_addresses *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_set_snat_addresses'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_cnat_set_snat_addresses_payload_hton(&msg->payload);
}

static inline void vapi_msg_cnat_set_snat_addresses_ntoh(vapi_msg_cnat_set_snat_addresses *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_set_snat_addresses'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_cnat_set_snat_addresses_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_cnat_set_snat_addresses_msg_size(vapi_msg_cnat_set_snat_addresses *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_cnat_set_snat_addresses_msg_size(vapi_msg_cnat_set_snat_addresses *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cnat_set_snat_addresses) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_set_snat_addresses' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cnat_set_snat_addresses));
      return -1;
    }
  if (vapi_calc_cnat_set_snat_addresses_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_set_snat_addresses' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cnat_set_snat_addresses_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_cnat_set_snat_addresses* vapi_alloc_cnat_set_snat_addresses(struct vapi_ctx_s *ctx)
{
  vapi_msg_cnat_set_snat_addresses *msg = NULL;
  const size_t size = sizeof(vapi_msg_cnat_set_snat_addresses);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_cnat_set_snat_addresses*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_cnat_set_snat_addresses);

  return msg;
}

static inline vapi_error_e vapi_cnat_set_snat_addresses(struct vapi_ctx_s *ctx,
  vapi_msg_cnat_set_snat_addresses *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_cnat_set_snat_addresses_reply *reply),
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
  vapi_msg_cnat_set_snat_addresses_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_cnat_set_snat_addresses_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_cnat_set_snat_addresses_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_cnat_set_snat_addresses()
{
  static const char name[] = "cnat_set_snat_addresses";
  static const char name_with_crc[] = "cnat_set_snat_addresses_d997e96c";
  static vapi_message_desc_t __vapi_metadata_cnat_set_snat_addresses = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_cnat_set_snat_addresses, payload),
    (verify_msg_size_fn_t)vapi_verify_cnat_set_snat_addresses_msg_size,
    (generic_swap_fn_t)vapi_msg_cnat_set_snat_addresses_hton,
    (generic_swap_fn_t)vapi_msg_cnat_set_snat_addresses_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cnat_set_snat_addresses = vapi_register_msg(&__vapi_metadata_cnat_set_snat_addresses);
  VAPI_DBG("Assigned msg id %d to cnat_set_snat_addresses", vapi_msg_id_cnat_set_snat_addresses);
}
#endif

#ifndef defined_vapi_msg_cnat_get_snat_addresses_reply
#define defined_vapi_msg_cnat_get_snat_addresses_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 id;
  vapi_type_ip4_address snat_ip4;
  vapi_type_ip6_address snat_ip6;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_cnat_get_snat_addresses_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_cnat_get_snat_addresses_reply payload;
} vapi_msg_cnat_get_snat_addresses_reply;

static inline void vapi_msg_cnat_get_snat_addresses_reply_payload_hton(vapi_payload_cnat_get_snat_addresses_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->id = htobe32(payload->id);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_cnat_get_snat_addresses_reply_payload_ntoh(vapi_payload_cnat_get_snat_addresses_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->id = be32toh(payload->id);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_cnat_get_snat_addresses_reply_hton(vapi_msg_cnat_get_snat_addresses_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_get_snat_addresses_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_cnat_get_snat_addresses_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_cnat_get_snat_addresses_reply_ntoh(vapi_msg_cnat_get_snat_addresses_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_get_snat_addresses_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_cnat_get_snat_addresses_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_cnat_get_snat_addresses_reply_msg_size(vapi_msg_cnat_get_snat_addresses_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_cnat_get_snat_addresses_reply_msg_size(vapi_msg_cnat_get_snat_addresses_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cnat_get_snat_addresses_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_get_snat_addresses_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cnat_get_snat_addresses_reply));
      return -1;
    }
  if (vapi_calc_cnat_get_snat_addresses_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_get_snat_addresses_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cnat_get_snat_addresses_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_cnat_get_snat_addresses_reply()
{
  static const char name[] = "cnat_get_snat_addresses_reply";
  static const char name_with_crc[] = "cnat_get_snat_addresses_reply_879513c1";
  static vapi_message_desc_t __vapi_metadata_cnat_get_snat_addresses_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_cnat_get_snat_addresses_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_cnat_get_snat_addresses_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_cnat_get_snat_addresses_reply_hton,
    (generic_swap_fn_t)vapi_msg_cnat_get_snat_addresses_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cnat_get_snat_addresses_reply = vapi_register_msg(&__vapi_metadata_cnat_get_snat_addresses_reply);
  VAPI_DBG("Assigned msg id %d to cnat_get_snat_addresses_reply", vapi_msg_id_cnat_get_snat_addresses_reply);
}

static inline void vapi_set_vapi_msg_cnat_get_snat_addresses_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_cnat_get_snat_addresses_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_cnat_get_snat_addresses_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_cnat_get_snat_addresses
#define defined_vapi_msg_cnat_get_snat_addresses
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_cnat_get_snat_addresses;

static inline void vapi_msg_cnat_get_snat_addresses_hton(vapi_msg_cnat_get_snat_addresses *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_get_snat_addresses'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_cnat_get_snat_addresses_ntoh(vapi_msg_cnat_get_snat_addresses *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_get_snat_addresses'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_cnat_get_snat_addresses_msg_size(vapi_msg_cnat_get_snat_addresses *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_cnat_get_snat_addresses_msg_size(vapi_msg_cnat_get_snat_addresses *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cnat_get_snat_addresses) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_get_snat_addresses' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cnat_get_snat_addresses));
      return -1;
    }
  if (vapi_calc_cnat_get_snat_addresses_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_get_snat_addresses' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cnat_get_snat_addresses_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_cnat_get_snat_addresses* vapi_alloc_cnat_get_snat_addresses(struct vapi_ctx_s *ctx)
{
  vapi_msg_cnat_get_snat_addresses *msg = NULL;
  const size_t size = sizeof(vapi_msg_cnat_get_snat_addresses);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_cnat_get_snat_addresses*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_cnat_get_snat_addresses);

  return msg;
}

static inline vapi_error_e vapi_cnat_get_snat_addresses(struct vapi_ctx_s *ctx,
  vapi_msg_cnat_get_snat_addresses *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_cnat_get_snat_addresses_reply *reply),
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
  vapi_msg_cnat_get_snat_addresses_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_cnat_get_snat_addresses_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_cnat_get_snat_addresses_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_cnat_get_snat_addresses()
{
  static const char name[] = "cnat_get_snat_addresses";
  static const char name_with_crc[] = "cnat_get_snat_addresses_51077d14";
  static vapi_message_desc_t __vapi_metadata_cnat_get_snat_addresses = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_cnat_get_snat_addresses_msg_size,
    (generic_swap_fn_t)vapi_msg_cnat_get_snat_addresses_hton,
    (generic_swap_fn_t)vapi_msg_cnat_get_snat_addresses_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cnat_get_snat_addresses = vapi_register_msg(&__vapi_metadata_cnat_get_snat_addresses);
  VAPI_DBG("Assigned msg id %d to cnat_get_snat_addresses", vapi_msg_id_cnat_get_snat_addresses);
}
#endif

#ifndef defined_vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply
#define defined_vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_cnat_snat_policy_add_del_exclude_pfx_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_cnat_snat_policy_add_del_exclude_pfx_reply payload;
} vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply;

static inline void vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply_payload_hton(vapi_payload_cnat_snat_policy_add_del_exclude_pfx_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply_payload_ntoh(vapi_payload_cnat_snat_policy_add_del_exclude_pfx_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply_hton(vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply_ntoh(vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_cnat_snat_policy_add_del_exclude_pfx_reply_msg_size(vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_cnat_snat_policy_add_del_exclude_pfx_reply_msg_size(vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_snat_policy_add_del_exclude_pfx_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply));
      return -1;
    }
  if (vapi_calc_cnat_snat_policy_add_del_exclude_pfx_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_snat_policy_add_del_exclude_pfx_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cnat_snat_policy_add_del_exclude_pfx_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_cnat_snat_policy_add_del_exclude_pfx_reply()
{
  static const char name[] = "cnat_snat_policy_add_del_exclude_pfx_reply";
  static const char name_with_crc[] = "cnat_snat_policy_add_del_exclude_pfx_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_cnat_snat_policy_add_del_exclude_pfx_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_cnat_snat_policy_add_del_exclude_pfx_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply_hton,
    (generic_swap_fn_t)vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cnat_snat_policy_add_del_exclude_pfx_reply = vapi_register_msg(&__vapi_metadata_cnat_snat_policy_add_del_exclude_pfx_reply);
  VAPI_DBG("Assigned msg id %d to cnat_snat_policy_add_del_exclude_pfx_reply", vapi_msg_id_cnat_snat_policy_add_del_exclude_pfx_reply);
}

static inline void vapi_set_vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_cnat_snat_policy_add_del_exclude_pfx_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_cnat_snat_policy_add_del_exclude_pfx_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_cnat_snat_policy_add_del_exclude_pfx
#define defined_vapi_msg_cnat_snat_policy_add_del_exclude_pfx
typedef struct __attribute__ ((__packed__)) {
  u8 is_add;
  vapi_type_prefix prefix; 
} vapi_payload_cnat_snat_policy_add_del_exclude_pfx;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_cnat_snat_policy_add_del_exclude_pfx payload;
} vapi_msg_cnat_snat_policy_add_del_exclude_pfx;

static inline void vapi_msg_cnat_snat_policy_add_del_exclude_pfx_payload_hton(vapi_payload_cnat_snat_policy_add_del_exclude_pfx *payload)
{

}

static inline void vapi_msg_cnat_snat_policy_add_del_exclude_pfx_payload_ntoh(vapi_payload_cnat_snat_policy_add_del_exclude_pfx *payload)
{

}

static inline void vapi_msg_cnat_snat_policy_add_del_exclude_pfx_hton(vapi_msg_cnat_snat_policy_add_del_exclude_pfx *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_snat_policy_add_del_exclude_pfx'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_cnat_snat_policy_add_del_exclude_pfx_payload_hton(&msg->payload);
}

static inline void vapi_msg_cnat_snat_policy_add_del_exclude_pfx_ntoh(vapi_msg_cnat_snat_policy_add_del_exclude_pfx *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_snat_policy_add_del_exclude_pfx'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_cnat_snat_policy_add_del_exclude_pfx_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_cnat_snat_policy_add_del_exclude_pfx_msg_size(vapi_msg_cnat_snat_policy_add_del_exclude_pfx *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_cnat_snat_policy_add_del_exclude_pfx_msg_size(vapi_msg_cnat_snat_policy_add_del_exclude_pfx *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cnat_snat_policy_add_del_exclude_pfx) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_snat_policy_add_del_exclude_pfx' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cnat_snat_policy_add_del_exclude_pfx));
      return -1;
    }
  if (vapi_calc_cnat_snat_policy_add_del_exclude_pfx_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_snat_policy_add_del_exclude_pfx' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cnat_snat_policy_add_del_exclude_pfx_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_cnat_snat_policy_add_del_exclude_pfx* vapi_alloc_cnat_snat_policy_add_del_exclude_pfx(struct vapi_ctx_s *ctx)
{
  vapi_msg_cnat_snat_policy_add_del_exclude_pfx *msg = NULL;
  const size_t size = sizeof(vapi_msg_cnat_snat_policy_add_del_exclude_pfx);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_cnat_snat_policy_add_del_exclude_pfx*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_cnat_snat_policy_add_del_exclude_pfx);

  return msg;
}

static inline vapi_error_e vapi_cnat_snat_policy_add_del_exclude_pfx(struct vapi_ctx_s *ctx,
  vapi_msg_cnat_snat_policy_add_del_exclude_pfx *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_cnat_snat_policy_add_del_exclude_pfx_reply *reply),
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
  vapi_msg_cnat_snat_policy_add_del_exclude_pfx_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_cnat_snat_policy_add_del_exclude_pfx_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_cnat_snat_policy_add_del_exclude_pfx_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_cnat_snat_policy_add_del_exclude_pfx()
{
  static const char name[] = "cnat_snat_policy_add_del_exclude_pfx";
  static const char name_with_crc[] = "cnat_snat_policy_add_del_exclude_pfx_e26dd79a";
  static vapi_message_desc_t __vapi_metadata_cnat_snat_policy_add_del_exclude_pfx = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_cnat_snat_policy_add_del_exclude_pfx, payload),
    (verify_msg_size_fn_t)vapi_verify_cnat_snat_policy_add_del_exclude_pfx_msg_size,
    (generic_swap_fn_t)vapi_msg_cnat_snat_policy_add_del_exclude_pfx_hton,
    (generic_swap_fn_t)vapi_msg_cnat_snat_policy_add_del_exclude_pfx_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cnat_snat_policy_add_del_exclude_pfx = vapi_register_msg(&__vapi_metadata_cnat_snat_policy_add_del_exclude_pfx);
  VAPI_DBG("Assigned msg id %d to cnat_snat_policy_add_del_exclude_pfx", vapi_msg_id_cnat_snat_policy_add_del_exclude_pfx);
}
#endif

#ifndef defined_vapi_msg_cnat_snat_policy_add_del_if_reply
#define defined_vapi_msg_cnat_snat_policy_add_del_if_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_cnat_snat_policy_add_del_if_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_cnat_snat_policy_add_del_if_reply payload;
} vapi_msg_cnat_snat_policy_add_del_if_reply;

static inline void vapi_msg_cnat_snat_policy_add_del_if_reply_payload_hton(vapi_payload_cnat_snat_policy_add_del_if_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_cnat_snat_policy_add_del_if_reply_payload_ntoh(vapi_payload_cnat_snat_policy_add_del_if_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_cnat_snat_policy_add_del_if_reply_hton(vapi_msg_cnat_snat_policy_add_del_if_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_snat_policy_add_del_if_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_cnat_snat_policy_add_del_if_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_cnat_snat_policy_add_del_if_reply_ntoh(vapi_msg_cnat_snat_policy_add_del_if_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_snat_policy_add_del_if_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_cnat_snat_policy_add_del_if_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_cnat_snat_policy_add_del_if_reply_msg_size(vapi_msg_cnat_snat_policy_add_del_if_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_cnat_snat_policy_add_del_if_reply_msg_size(vapi_msg_cnat_snat_policy_add_del_if_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cnat_snat_policy_add_del_if_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_snat_policy_add_del_if_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cnat_snat_policy_add_del_if_reply));
      return -1;
    }
  if (vapi_calc_cnat_snat_policy_add_del_if_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_snat_policy_add_del_if_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cnat_snat_policy_add_del_if_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_cnat_snat_policy_add_del_if_reply()
{
  static const char name[] = "cnat_snat_policy_add_del_if_reply";
  static const char name_with_crc[] = "cnat_snat_policy_add_del_if_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_cnat_snat_policy_add_del_if_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_cnat_snat_policy_add_del_if_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_cnat_snat_policy_add_del_if_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_cnat_snat_policy_add_del_if_reply_hton,
    (generic_swap_fn_t)vapi_msg_cnat_snat_policy_add_del_if_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cnat_snat_policy_add_del_if_reply = vapi_register_msg(&__vapi_metadata_cnat_snat_policy_add_del_if_reply);
  VAPI_DBG("Assigned msg id %d to cnat_snat_policy_add_del_if_reply", vapi_msg_id_cnat_snat_policy_add_del_if_reply);
}

static inline void vapi_set_vapi_msg_cnat_snat_policy_add_del_if_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_cnat_snat_policy_add_del_if_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_cnat_snat_policy_add_del_if_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_cnat_snat_policy_add_del_if
#define defined_vapi_msg_cnat_snat_policy_add_del_if
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u8 is_add;
  vapi_enum_cnat_snat_policy_table table; 
} vapi_payload_cnat_snat_policy_add_del_if;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_cnat_snat_policy_add_del_if payload;
} vapi_msg_cnat_snat_policy_add_del_if;

static inline void vapi_msg_cnat_snat_policy_add_del_if_payload_hton(vapi_payload_cnat_snat_policy_add_del_if *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_cnat_snat_policy_add_del_if_payload_ntoh(vapi_payload_cnat_snat_policy_add_del_if *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_cnat_snat_policy_add_del_if_hton(vapi_msg_cnat_snat_policy_add_del_if *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_snat_policy_add_del_if'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_cnat_snat_policy_add_del_if_payload_hton(&msg->payload);
}

static inline void vapi_msg_cnat_snat_policy_add_del_if_ntoh(vapi_msg_cnat_snat_policy_add_del_if *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_snat_policy_add_del_if'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_cnat_snat_policy_add_del_if_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_cnat_snat_policy_add_del_if_msg_size(vapi_msg_cnat_snat_policy_add_del_if *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_cnat_snat_policy_add_del_if_msg_size(vapi_msg_cnat_snat_policy_add_del_if *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cnat_snat_policy_add_del_if) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_snat_policy_add_del_if' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cnat_snat_policy_add_del_if));
      return -1;
    }
  if (vapi_calc_cnat_snat_policy_add_del_if_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_snat_policy_add_del_if' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cnat_snat_policy_add_del_if_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_cnat_snat_policy_add_del_if* vapi_alloc_cnat_snat_policy_add_del_if(struct vapi_ctx_s *ctx)
{
  vapi_msg_cnat_snat_policy_add_del_if *msg = NULL;
  const size_t size = sizeof(vapi_msg_cnat_snat_policy_add_del_if);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_cnat_snat_policy_add_del_if*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_cnat_snat_policy_add_del_if);

  return msg;
}

static inline vapi_error_e vapi_cnat_snat_policy_add_del_if(struct vapi_ctx_s *ctx,
  vapi_msg_cnat_snat_policy_add_del_if *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_cnat_snat_policy_add_del_if_reply *reply),
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
  vapi_msg_cnat_snat_policy_add_del_if_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_cnat_snat_policy_add_del_if_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_cnat_snat_policy_add_del_if_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_cnat_snat_policy_add_del_if()
{
  static const char name[] = "cnat_snat_policy_add_del_if";
  static const char name_with_crc[] = "cnat_snat_policy_add_del_if_4ebb8d02";
  static vapi_message_desc_t __vapi_metadata_cnat_snat_policy_add_del_if = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_cnat_snat_policy_add_del_if, payload),
    (verify_msg_size_fn_t)vapi_verify_cnat_snat_policy_add_del_if_msg_size,
    (generic_swap_fn_t)vapi_msg_cnat_snat_policy_add_del_if_hton,
    (generic_swap_fn_t)vapi_msg_cnat_snat_policy_add_del_if_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cnat_snat_policy_add_del_if = vapi_register_msg(&__vapi_metadata_cnat_snat_policy_add_del_if);
  VAPI_DBG("Assigned msg id %d to cnat_snat_policy_add_del_if", vapi_msg_id_cnat_snat_policy_add_del_if);
}
#endif

#ifndef defined_vapi_msg_cnat_set_snat_policy_reply
#define defined_vapi_msg_cnat_set_snat_policy_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_cnat_set_snat_policy_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_cnat_set_snat_policy_reply payload;
} vapi_msg_cnat_set_snat_policy_reply;

static inline void vapi_msg_cnat_set_snat_policy_reply_payload_hton(vapi_payload_cnat_set_snat_policy_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_cnat_set_snat_policy_reply_payload_ntoh(vapi_payload_cnat_set_snat_policy_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_cnat_set_snat_policy_reply_hton(vapi_msg_cnat_set_snat_policy_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_set_snat_policy_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_cnat_set_snat_policy_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_cnat_set_snat_policy_reply_ntoh(vapi_msg_cnat_set_snat_policy_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_set_snat_policy_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_cnat_set_snat_policy_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_cnat_set_snat_policy_reply_msg_size(vapi_msg_cnat_set_snat_policy_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_cnat_set_snat_policy_reply_msg_size(vapi_msg_cnat_set_snat_policy_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cnat_set_snat_policy_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_set_snat_policy_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cnat_set_snat_policy_reply));
      return -1;
    }
  if (vapi_calc_cnat_set_snat_policy_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_set_snat_policy_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cnat_set_snat_policy_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_cnat_set_snat_policy_reply()
{
  static const char name[] = "cnat_set_snat_policy_reply";
  static const char name_with_crc[] = "cnat_set_snat_policy_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_cnat_set_snat_policy_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_cnat_set_snat_policy_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_cnat_set_snat_policy_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_cnat_set_snat_policy_reply_hton,
    (generic_swap_fn_t)vapi_msg_cnat_set_snat_policy_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cnat_set_snat_policy_reply = vapi_register_msg(&__vapi_metadata_cnat_set_snat_policy_reply);
  VAPI_DBG("Assigned msg id %d to cnat_set_snat_policy_reply", vapi_msg_id_cnat_set_snat_policy_reply);
}

static inline void vapi_set_vapi_msg_cnat_set_snat_policy_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_cnat_set_snat_policy_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_cnat_set_snat_policy_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_cnat_set_snat_policy
#define defined_vapi_msg_cnat_set_snat_policy
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_cnat_snat_policies policy; 
} vapi_payload_cnat_set_snat_policy;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_cnat_set_snat_policy payload;
} vapi_msg_cnat_set_snat_policy;

static inline void vapi_msg_cnat_set_snat_policy_payload_hton(vapi_payload_cnat_set_snat_policy *payload)
{

}

static inline void vapi_msg_cnat_set_snat_policy_payload_ntoh(vapi_payload_cnat_set_snat_policy *payload)
{

}

static inline void vapi_msg_cnat_set_snat_policy_hton(vapi_msg_cnat_set_snat_policy *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_set_snat_policy'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_cnat_set_snat_policy_payload_hton(&msg->payload);
}

static inline void vapi_msg_cnat_set_snat_policy_ntoh(vapi_msg_cnat_set_snat_policy *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cnat_set_snat_policy'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_cnat_set_snat_policy_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_cnat_set_snat_policy_msg_size(vapi_msg_cnat_set_snat_policy *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_cnat_set_snat_policy_msg_size(vapi_msg_cnat_set_snat_policy *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cnat_set_snat_policy) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_set_snat_policy' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cnat_set_snat_policy));
      return -1;
    }
  if (vapi_calc_cnat_set_snat_policy_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cnat_set_snat_policy' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cnat_set_snat_policy_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_cnat_set_snat_policy* vapi_alloc_cnat_set_snat_policy(struct vapi_ctx_s *ctx)
{
  vapi_msg_cnat_set_snat_policy *msg = NULL;
  const size_t size = sizeof(vapi_msg_cnat_set_snat_policy);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_cnat_set_snat_policy*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_cnat_set_snat_policy);

  return msg;
}

static inline vapi_error_e vapi_cnat_set_snat_policy(struct vapi_ctx_s *ctx,
  vapi_msg_cnat_set_snat_policy *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_cnat_set_snat_policy_reply *reply),
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
  vapi_msg_cnat_set_snat_policy_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_cnat_set_snat_policy_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_cnat_set_snat_policy_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_cnat_set_snat_policy()
{
  static const char name[] = "cnat_set_snat_policy";
  static const char name_with_crc[] = "cnat_set_snat_policy_d3e6eaf4";
  static vapi_message_desc_t __vapi_metadata_cnat_set_snat_policy = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_cnat_set_snat_policy, payload),
    (verify_msg_size_fn_t)vapi_verify_cnat_set_snat_policy_msg_size,
    (generic_swap_fn_t)vapi_msg_cnat_set_snat_policy_hton,
    (generic_swap_fn_t)vapi_msg_cnat_set_snat_policy_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cnat_set_snat_policy = vapi_register_msg(&__vapi_metadata_cnat_set_snat_policy);
  VAPI_DBG("Assigned msg id %d to cnat_set_snat_policy", vapi_msg_id_cnat_set_snat_policy);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
