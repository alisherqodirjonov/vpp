#ifndef __included_l2_api_json
#define __included_l2_api_json

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

extern vapi_msg_id_t vapi_msg_id_l2_xconnect_details;
extern vapi_msg_id_t vapi_msg_id_l2_xconnect_dump;
extern vapi_msg_id_t vapi_msg_id_l2_fib_table_details;
extern vapi_msg_id_t vapi_msg_id_l2_fib_table_dump;
extern vapi_msg_id_t vapi_msg_id_l2_fib_clear_table;
extern vapi_msg_id_t vapi_msg_id_l2_fib_clear_table_reply;
extern vapi_msg_id_t vapi_msg_id_l2fib_flush_all;
extern vapi_msg_id_t vapi_msg_id_l2fib_flush_all_reply;
extern vapi_msg_id_t vapi_msg_id_l2fib_flush_bd;
extern vapi_msg_id_t vapi_msg_id_l2fib_flush_bd_reply;
extern vapi_msg_id_t vapi_msg_id_l2fib_flush_int;
extern vapi_msg_id_t vapi_msg_id_l2fib_flush_int_reply;
extern vapi_msg_id_t vapi_msg_id_l2fib_add_del;
extern vapi_msg_id_t vapi_msg_id_l2fib_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_want_l2_macs_events;
extern vapi_msg_id_t vapi_msg_id_want_l2_macs_events_reply;
extern vapi_msg_id_t vapi_msg_id_want_l2_macs_events2;
extern vapi_msg_id_t vapi_msg_id_want_l2_macs_events2_reply;
extern vapi_msg_id_t vapi_msg_id_l2fib_set_scan_delay;
extern vapi_msg_id_t vapi_msg_id_l2fib_set_scan_delay_reply;
extern vapi_msg_id_t vapi_msg_id_l2_macs_event;
extern vapi_msg_id_t vapi_msg_id_l2_flags;
extern vapi_msg_id_t vapi_msg_id_l2_flags_reply;
extern vapi_msg_id_t vapi_msg_id_bridge_domain_set_mac_age;
extern vapi_msg_id_t vapi_msg_id_bridge_domain_set_mac_age_reply;
extern vapi_msg_id_t vapi_msg_id_bridge_domain_set_default_learn_limit;
extern vapi_msg_id_t vapi_msg_id_bridge_domain_set_default_learn_limit_reply;
extern vapi_msg_id_t vapi_msg_id_bridge_domain_set_learn_limit;
extern vapi_msg_id_t vapi_msg_id_bridge_domain_set_learn_limit_reply;
extern vapi_msg_id_t vapi_msg_id_bridge_domain_add_del;
extern vapi_msg_id_t vapi_msg_id_bridge_domain_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_bridge_domain_add_del_v2;
extern vapi_msg_id_t vapi_msg_id_bridge_domain_add_del_v2_reply;
extern vapi_msg_id_t vapi_msg_id_bridge_domain_dump;
extern vapi_msg_id_t vapi_msg_id_bridge_domain_details;
extern vapi_msg_id_t vapi_msg_id_bridge_flags;
extern vapi_msg_id_t vapi_msg_id_bridge_flags_reply;
extern vapi_msg_id_t vapi_msg_id_l2_interface_vlan_tag_rewrite;
extern vapi_msg_id_t vapi_msg_id_l2_interface_vlan_tag_rewrite_reply;
extern vapi_msg_id_t vapi_msg_id_l2_interface_pbb_tag_rewrite;
extern vapi_msg_id_t vapi_msg_id_l2_interface_pbb_tag_rewrite_reply;
extern vapi_msg_id_t vapi_msg_id_l2_patch_add_del;
extern vapi_msg_id_t vapi_msg_id_l2_patch_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_sw_interface_set_l2_xconnect;
extern vapi_msg_id_t vapi_msg_id_sw_interface_set_l2_xconnect_reply;
extern vapi_msg_id_t vapi_msg_id_sw_interface_set_l2_bridge;
extern vapi_msg_id_t vapi_msg_id_sw_interface_set_l2_bridge_reply;
extern vapi_msg_id_t vapi_msg_id_bd_ip_mac_add_del;
extern vapi_msg_id_t vapi_msg_id_bd_ip_mac_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_bd_ip_mac_flush;
extern vapi_msg_id_t vapi_msg_id_bd_ip_mac_flush_reply;
extern vapi_msg_id_t vapi_msg_id_bd_ip_mac_details;
extern vapi_msg_id_t vapi_msg_id_bd_ip_mac_dump;
extern vapi_msg_id_t vapi_msg_id_l2_interface_efp_filter;
extern vapi_msg_id_t vapi_msg_id_l2_interface_efp_filter_reply;
extern vapi_msg_id_t vapi_msg_id_sw_interface_set_vpath;
extern vapi_msg_id_t vapi_msg_id_sw_interface_set_vpath_reply;
extern vapi_msg_id_t vapi_msg_id_bvi_create;
extern vapi_msg_id_t vapi_msg_id_bvi_create_reply;
extern vapi_msg_id_t vapi_msg_id_bvi_delete;
extern vapi_msg_id_t vapi_msg_id_bvi_delete_reply;
extern vapi_msg_id_t vapi_msg_id_want_l2_arp_term_events;
extern vapi_msg_id_t vapi_msg_id_want_l2_arp_term_events_reply;
extern vapi_msg_id_t vapi_msg_id_l2_arp_term_event;

#define DEFINE_VAPI_MSG_IDS_L2_API_JSON\
  vapi_msg_id_t vapi_msg_id_l2_xconnect_details;\
  vapi_msg_id_t vapi_msg_id_l2_xconnect_dump;\
  vapi_msg_id_t vapi_msg_id_l2_fib_table_details;\
  vapi_msg_id_t vapi_msg_id_l2_fib_table_dump;\
  vapi_msg_id_t vapi_msg_id_l2_fib_clear_table;\
  vapi_msg_id_t vapi_msg_id_l2_fib_clear_table_reply;\
  vapi_msg_id_t vapi_msg_id_l2fib_flush_all;\
  vapi_msg_id_t vapi_msg_id_l2fib_flush_all_reply;\
  vapi_msg_id_t vapi_msg_id_l2fib_flush_bd;\
  vapi_msg_id_t vapi_msg_id_l2fib_flush_bd_reply;\
  vapi_msg_id_t vapi_msg_id_l2fib_flush_int;\
  vapi_msg_id_t vapi_msg_id_l2fib_flush_int_reply;\
  vapi_msg_id_t vapi_msg_id_l2fib_add_del;\
  vapi_msg_id_t vapi_msg_id_l2fib_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_want_l2_macs_events;\
  vapi_msg_id_t vapi_msg_id_want_l2_macs_events_reply;\
  vapi_msg_id_t vapi_msg_id_want_l2_macs_events2;\
  vapi_msg_id_t vapi_msg_id_want_l2_macs_events2_reply;\
  vapi_msg_id_t vapi_msg_id_l2fib_set_scan_delay;\
  vapi_msg_id_t vapi_msg_id_l2fib_set_scan_delay_reply;\
  vapi_msg_id_t vapi_msg_id_l2_macs_event;\
  vapi_msg_id_t vapi_msg_id_l2_flags;\
  vapi_msg_id_t vapi_msg_id_l2_flags_reply;\
  vapi_msg_id_t vapi_msg_id_bridge_domain_set_mac_age;\
  vapi_msg_id_t vapi_msg_id_bridge_domain_set_mac_age_reply;\
  vapi_msg_id_t vapi_msg_id_bridge_domain_set_default_learn_limit;\
  vapi_msg_id_t vapi_msg_id_bridge_domain_set_default_learn_limit_reply;\
  vapi_msg_id_t vapi_msg_id_bridge_domain_set_learn_limit;\
  vapi_msg_id_t vapi_msg_id_bridge_domain_set_learn_limit_reply;\
  vapi_msg_id_t vapi_msg_id_bridge_domain_add_del;\
  vapi_msg_id_t vapi_msg_id_bridge_domain_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_bridge_domain_add_del_v2;\
  vapi_msg_id_t vapi_msg_id_bridge_domain_add_del_v2_reply;\
  vapi_msg_id_t vapi_msg_id_bridge_domain_dump;\
  vapi_msg_id_t vapi_msg_id_bridge_domain_details;\
  vapi_msg_id_t vapi_msg_id_bridge_flags;\
  vapi_msg_id_t vapi_msg_id_bridge_flags_reply;\
  vapi_msg_id_t vapi_msg_id_l2_interface_vlan_tag_rewrite;\
  vapi_msg_id_t vapi_msg_id_l2_interface_vlan_tag_rewrite_reply;\
  vapi_msg_id_t vapi_msg_id_l2_interface_pbb_tag_rewrite;\
  vapi_msg_id_t vapi_msg_id_l2_interface_pbb_tag_rewrite_reply;\
  vapi_msg_id_t vapi_msg_id_l2_patch_add_del;\
  vapi_msg_id_t vapi_msg_id_l2_patch_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_sw_interface_set_l2_xconnect;\
  vapi_msg_id_t vapi_msg_id_sw_interface_set_l2_xconnect_reply;\
  vapi_msg_id_t vapi_msg_id_sw_interface_set_l2_bridge;\
  vapi_msg_id_t vapi_msg_id_sw_interface_set_l2_bridge_reply;\
  vapi_msg_id_t vapi_msg_id_bd_ip_mac_add_del;\
  vapi_msg_id_t vapi_msg_id_bd_ip_mac_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_bd_ip_mac_flush;\
  vapi_msg_id_t vapi_msg_id_bd_ip_mac_flush_reply;\
  vapi_msg_id_t vapi_msg_id_bd_ip_mac_details;\
  vapi_msg_id_t vapi_msg_id_bd_ip_mac_dump;\
  vapi_msg_id_t vapi_msg_id_l2_interface_efp_filter;\
  vapi_msg_id_t vapi_msg_id_l2_interface_efp_filter_reply;\
  vapi_msg_id_t vapi_msg_id_sw_interface_set_vpath;\
  vapi_msg_id_t vapi_msg_id_sw_interface_set_vpath_reply;\
  vapi_msg_id_t vapi_msg_id_bvi_create;\
  vapi_msg_id_t vapi_msg_id_bvi_create_reply;\
  vapi_msg_id_t vapi_msg_id_bvi_delete;\
  vapi_msg_id_t vapi_msg_id_bvi_delete_reply;\
  vapi_msg_id_t vapi_msg_id_want_l2_arp_term_events;\
  vapi_msg_id_t vapi_msg_id_want_l2_arp_term_events_reply;\
  vapi_msg_id_t vapi_msg_id_l2_arp_term_event;


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

#ifndef defined_vapi_enum_mac_event_action
#define defined_vapi_enum_mac_event_action
typedef enum {
  MAC_EVENT_ACTION_API_ADD = 0,
  MAC_EVENT_ACTION_API_DELETE = 1,
  MAC_EVENT_ACTION_API_MOVE = 2,
}  vapi_enum_mac_event_action;

#endif

#ifndef defined_vapi_enum_bd_flags
#define defined_vapi_enum_bd_flags
typedef enum {
  BRIDGE_API_FLAG_NONE = 0,
  BRIDGE_API_FLAG_LEARN = 1,
  BRIDGE_API_FLAG_FWD = 2,
  BRIDGE_API_FLAG_FLOOD = 4,
  BRIDGE_API_FLAG_UU_FLOOD = 8,
  BRIDGE_API_FLAG_ARP_TERM = 16,
  BRIDGE_API_FLAG_ARP_UFWD = 32,
}  vapi_enum_bd_flags;

#endif

#ifndef defined_vapi_enum_l2_port_type
#define defined_vapi_enum_l2_port_type
typedef enum {
  L2_API_PORT_TYPE_NORMAL = 0,
  L2_API_PORT_TYPE_BVI = 1,
  L2_API_PORT_TYPE_UU_FWD = 2,
}  vapi_enum_l2_port_type;

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

#ifndef defined_vapi_type_mac_address
#define defined_vapi_type_mac_address
typedef u8 vapi_type_mac_address[6];

#endif

#ifndef defined_vapi_type_mac_entry
#define defined_vapi_type_mac_entry
typedef struct __attribute__((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_type_mac_address mac_addr;
  vapi_enum_mac_event_action action;
  u8 flags;
} vapi_type_mac_entry;

static inline void vapi_type_mac_entry_hton(vapi_type_mac_entry *msg)
{
  msg->sw_if_index = htobe32(msg->sw_if_index);
  msg->action = (vapi_enum_mac_event_action)htobe32(msg->action);
}

static inline void vapi_type_mac_entry_ntoh(vapi_type_mac_entry *msg)
{
  msg->sw_if_index = be32toh(msg->sw_if_index);
  msg->action = (vapi_enum_mac_event_action)be32toh(msg->action);
}
#endif

#ifndef defined_vapi_type_bridge_domain_sw_if
#define defined_vapi_type_bridge_domain_sw_if
typedef struct __attribute__((__packed__)) {
  u32 context;
  vapi_type_interface_index sw_if_index;
  u8 shg;
} vapi_type_bridge_domain_sw_if;

static inline void vapi_type_bridge_domain_sw_if_hton(vapi_type_bridge_domain_sw_if *msg)
{
  msg->context = htobe32(msg->context);
  msg->sw_if_index = htobe32(msg->sw_if_index);
}

static inline void vapi_type_bridge_domain_sw_if_ntoh(vapi_type_bridge_domain_sw_if *msg)
{
  msg->context = be32toh(msg->context);
  msg->sw_if_index = be32toh(msg->sw_if_index);
}
#endif

#ifndef defined_vapi_type_bd_ip_mac
#define defined_vapi_type_bd_ip_mac
typedef struct __attribute__((__packed__)) {
  u32 bd_id;
  vapi_type_address ip;
  vapi_type_mac_address mac;
} vapi_type_bd_ip_mac;

static inline void vapi_type_bd_ip_mac_hton(vapi_type_bd_ip_mac *msg)
{
  msg->bd_id = htobe32(msg->bd_id);
}

static inline void vapi_type_bd_ip_mac_ntoh(vapi_type_bd_ip_mac *msg)
{
  msg->bd_id = be32toh(msg->bd_id);
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

#ifndef defined_vapi_msg_l2_xconnect_details
#define defined_vapi_msg_l2_xconnect_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index rx_sw_if_index;
  vapi_type_interface_index tx_sw_if_index; 
} vapi_payload_l2_xconnect_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_l2_xconnect_details payload;
} vapi_msg_l2_xconnect_details;

static inline void vapi_msg_l2_xconnect_details_payload_hton(vapi_payload_l2_xconnect_details *payload)
{
  payload->rx_sw_if_index = htobe32(payload->rx_sw_if_index);
  payload->tx_sw_if_index = htobe32(payload->tx_sw_if_index);
}

static inline void vapi_msg_l2_xconnect_details_payload_ntoh(vapi_payload_l2_xconnect_details *payload)
{
  payload->rx_sw_if_index = be32toh(payload->rx_sw_if_index);
  payload->tx_sw_if_index = be32toh(payload->tx_sw_if_index);
}

static inline void vapi_msg_l2_xconnect_details_hton(vapi_msg_l2_xconnect_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_xconnect_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_l2_xconnect_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2_xconnect_details_ntoh(vapi_msg_l2_xconnect_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_xconnect_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_l2_xconnect_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2_xconnect_details_msg_size(vapi_msg_l2_xconnect_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2_xconnect_details_msg_size(vapi_msg_l2_xconnect_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2_xconnect_details) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_xconnect_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2_xconnect_details));
      return -1;
    }
  if (vapi_calc_l2_xconnect_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_xconnect_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2_xconnect_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_l2_xconnect_details()
{
  static const char name[] = "l2_xconnect_details";
  static const char name_with_crc[] = "l2_xconnect_details_472b6b67";
  static vapi_message_desc_t __vapi_metadata_l2_xconnect_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_l2_xconnect_details, payload),
    (verify_msg_size_fn_t)vapi_verify_l2_xconnect_details_msg_size,
    (generic_swap_fn_t)vapi_msg_l2_xconnect_details_hton,
    (generic_swap_fn_t)vapi_msg_l2_xconnect_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2_xconnect_details = vapi_register_msg(&__vapi_metadata_l2_xconnect_details);
  VAPI_DBG("Assigned msg id %d to l2_xconnect_details", vapi_msg_id_l2_xconnect_details);
}

static inline void vapi_set_vapi_msg_l2_xconnect_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_l2_xconnect_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_l2_xconnect_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_l2_xconnect_dump
#define defined_vapi_msg_l2_xconnect_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_l2_xconnect_dump;

static inline void vapi_msg_l2_xconnect_dump_hton(vapi_msg_l2_xconnect_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_xconnect_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_l2_xconnect_dump_ntoh(vapi_msg_l2_xconnect_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_xconnect_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_l2_xconnect_dump_msg_size(vapi_msg_l2_xconnect_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2_xconnect_dump_msg_size(vapi_msg_l2_xconnect_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2_xconnect_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_xconnect_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2_xconnect_dump));
      return -1;
    }
  if (vapi_calc_l2_xconnect_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_xconnect_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2_xconnect_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_l2_xconnect_dump* vapi_alloc_l2_xconnect_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_l2_xconnect_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_l2_xconnect_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_l2_xconnect_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_l2_xconnect_dump);

  return msg;
}

static inline vapi_error_e vapi_l2_xconnect_dump(struct vapi_ctx_s *ctx,
  vapi_msg_l2_xconnect_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_l2_xconnect_details *reply),
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
  vapi_msg_l2_xconnect_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_l2_xconnect_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_l2_xconnect_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_l2_xconnect_dump()
{
  static const char name[] = "l2_xconnect_dump";
  static const char name_with_crc[] = "l2_xconnect_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_l2_xconnect_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_l2_xconnect_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_l2_xconnect_dump_hton,
    (generic_swap_fn_t)vapi_msg_l2_xconnect_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2_xconnect_dump = vapi_register_msg(&__vapi_metadata_l2_xconnect_dump);
  VAPI_DBG("Assigned msg id %d to l2_xconnect_dump", vapi_msg_id_l2_xconnect_dump);
}
#endif

#ifndef defined_vapi_msg_l2_fib_table_details
#define defined_vapi_msg_l2_fib_table_details
typedef struct __attribute__ ((__packed__)) {
  u32 bd_id;
  vapi_type_mac_address mac;
  vapi_type_interface_index sw_if_index;
  bool static_mac;
  bool filter_mac;
  bool bvi_mac; 
} vapi_payload_l2_fib_table_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_l2_fib_table_details payload;
} vapi_msg_l2_fib_table_details;

static inline void vapi_msg_l2_fib_table_details_payload_hton(vapi_payload_l2_fib_table_details *payload)
{
  payload->bd_id = htobe32(payload->bd_id);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_l2_fib_table_details_payload_ntoh(vapi_payload_l2_fib_table_details *payload)
{
  payload->bd_id = be32toh(payload->bd_id);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_l2_fib_table_details_hton(vapi_msg_l2_fib_table_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_fib_table_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_l2_fib_table_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2_fib_table_details_ntoh(vapi_msg_l2_fib_table_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_fib_table_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_l2_fib_table_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2_fib_table_details_msg_size(vapi_msg_l2_fib_table_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2_fib_table_details_msg_size(vapi_msg_l2_fib_table_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2_fib_table_details) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_fib_table_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2_fib_table_details));
      return -1;
    }
  if (vapi_calc_l2_fib_table_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_fib_table_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2_fib_table_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_l2_fib_table_details()
{
  static const char name[] = "l2_fib_table_details";
  static const char name_with_crc[] = "l2_fib_table_details_a44ef6b8";
  static vapi_message_desc_t __vapi_metadata_l2_fib_table_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_l2_fib_table_details, payload),
    (verify_msg_size_fn_t)vapi_verify_l2_fib_table_details_msg_size,
    (generic_swap_fn_t)vapi_msg_l2_fib_table_details_hton,
    (generic_swap_fn_t)vapi_msg_l2_fib_table_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2_fib_table_details = vapi_register_msg(&__vapi_metadata_l2_fib_table_details);
  VAPI_DBG("Assigned msg id %d to l2_fib_table_details", vapi_msg_id_l2_fib_table_details);
}

static inline void vapi_set_vapi_msg_l2_fib_table_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_l2_fib_table_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_l2_fib_table_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_l2_fib_table_dump
#define defined_vapi_msg_l2_fib_table_dump
typedef struct __attribute__ ((__packed__)) {
  u32 bd_id; 
} vapi_payload_l2_fib_table_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_l2_fib_table_dump payload;
} vapi_msg_l2_fib_table_dump;

static inline void vapi_msg_l2_fib_table_dump_payload_hton(vapi_payload_l2_fib_table_dump *payload)
{
  payload->bd_id = htobe32(payload->bd_id);
}

static inline void vapi_msg_l2_fib_table_dump_payload_ntoh(vapi_payload_l2_fib_table_dump *payload)
{
  payload->bd_id = be32toh(payload->bd_id);
}

static inline void vapi_msg_l2_fib_table_dump_hton(vapi_msg_l2_fib_table_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_fib_table_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_l2_fib_table_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2_fib_table_dump_ntoh(vapi_msg_l2_fib_table_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_fib_table_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_l2_fib_table_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2_fib_table_dump_msg_size(vapi_msg_l2_fib_table_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2_fib_table_dump_msg_size(vapi_msg_l2_fib_table_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2_fib_table_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_fib_table_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2_fib_table_dump));
      return -1;
    }
  if (vapi_calc_l2_fib_table_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_fib_table_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2_fib_table_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_l2_fib_table_dump* vapi_alloc_l2_fib_table_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_l2_fib_table_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_l2_fib_table_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_l2_fib_table_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_l2_fib_table_dump);

  return msg;
}

static inline vapi_error_e vapi_l2_fib_table_dump(struct vapi_ctx_s *ctx,
  vapi_msg_l2_fib_table_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_l2_fib_table_details *reply),
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
  vapi_msg_l2_fib_table_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_l2_fib_table_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_l2_fib_table_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_l2_fib_table_dump()
{
  static const char name[] = "l2_fib_table_dump";
  static const char name_with_crc[] = "l2_fib_table_dump_c25fdce6";
  static vapi_message_desc_t __vapi_metadata_l2_fib_table_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_l2_fib_table_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_l2_fib_table_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_l2_fib_table_dump_hton,
    (generic_swap_fn_t)vapi_msg_l2_fib_table_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2_fib_table_dump = vapi_register_msg(&__vapi_metadata_l2_fib_table_dump);
  VAPI_DBG("Assigned msg id %d to l2_fib_table_dump", vapi_msg_id_l2_fib_table_dump);
}
#endif

#ifndef defined_vapi_msg_l2_fib_clear_table_reply
#define defined_vapi_msg_l2_fib_clear_table_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_l2_fib_clear_table_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_l2_fib_clear_table_reply payload;
} vapi_msg_l2_fib_clear_table_reply;

static inline void vapi_msg_l2_fib_clear_table_reply_payload_hton(vapi_payload_l2_fib_clear_table_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_l2_fib_clear_table_reply_payload_ntoh(vapi_payload_l2_fib_clear_table_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_l2_fib_clear_table_reply_hton(vapi_msg_l2_fib_clear_table_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_fib_clear_table_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_l2_fib_clear_table_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2_fib_clear_table_reply_ntoh(vapi_msg_l2_fib_clear_table_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_fib_clear_table_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_l2_fib_clear_table_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2_fib_clear_table_reply_msg_size(vapi_msg_l2_fib_clear_table_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2_fib_clear_table_reply_msg_size(vapi_msg_l2_fib_clear_table_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2_fib_clear_table_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_fib_clear_table_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2_fib_clear_table_reply));
      return -1;
    }
  if (vapi_calc_l2_fib_clear_table_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_fib_clear_table_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2_fib_clear_table_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_l2_fib_clear_table_reply()
{
  static const char name[] = "l2_fib_clear_table_reply";
  static const char name_with_crc[] = "l2_fib_clear_table_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_l2_fib_clear_table_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_l2_fib_clear_table_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_l2_fib_clear_table_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_l2_fib_clear_table_reply_hton,
    (generic_swap_fn_t)vapi_msg_l2_fib_clear_table_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2_fib_clear_table_reply = vapi_register_msg(&__vapi_metadata_l2_fib_clear_table_reply);
  VAPI_DBG("Assigned msg id %d to l2_fib_clear_table_reply", vapi_msg_id_l2_fib_clear_table_reply);
}

static inline void vapi_set_vapi_msg_l2_fib_clear_table_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_l2_fib_clear_table_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_l2_fib_clear_table_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_l2_fib_clear_table
#define defined_vapi_msg_l2_fib_clear_table
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_l2_fib_clear_table;

static inline void vapi_msg_l2_fib_clear_table_hton(vapi_msg_l2_fib_clear_table *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_fib_clear_table'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_l2_fib_clear_table_ntoh(vapi_msg_l2_fib_clear_table *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_fib_clear_table'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_l2_fib_clear_table_msg_size(vapi_msg_l2_fib_clear_table *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2_fib_clear_table_msg_size(vapi_msg_l2_fib_clear_table *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2_fib_clear_table) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_fib_clear_table' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2_fib_clear_table));
      return -1;
    }
  if (vapi_calc_l2_fib_clear_table_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_fib_clear_table' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2_fib_clear_table_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_l2_fib_clear_table* vapi_alloc_l2_fib_clear_table(struct vapi_ctx_s *ctx)
{
  vapi_msg_l2_fib_clear_table *msg = NULL;
  const size_t size = sizeof(vapi_msg_l2_fib_clear_table);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_l2_fib_clear_table*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_l2_fib_clear_table);

  return msg;
}

static inline vapi_error_e vapi_l2_fib_clear_table(struct vapi_ctx_s *ctx,
  vapi_msg_l2_fib_clear_table *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_l2_fib_clear_table_reply *reply),
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
  vapi_msg_l2_fib_clear_table_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_l2_fib_clear_table_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_l2_fib_clear_table_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_l2_fib_clear_table()
{
  static const char name[] = "l2_fib_clear_table";
  static const char name_with_crc[] = "l2_fib_clear_table_51077d14";
  static vapi_message_desc_t __vapi_metadata_l2_fib_clear_table = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_l2_fib_clear_table_msg_size,
    (generic_swap_fn_t)vapi_msg_l2_fib_clear_table_hton,
    (generic_swap_fn_t)vapi_msg_l2_fib_clear_table_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2_fib_clear_table = vapi_register_msg(&__vapi_metadata_l2_fib_clear_table);
  VAPI_DBG("Assigned msg id %d to l2_fib_clear_table", vapi_msg_id_l2_fib_clear_table);
}
#endif

#ifndef defined_vapi_msg_l2fib_flush_all_reply
#define defined_vapi_msg_l2fib_flush_all_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_l2fib_flush_all_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_l2fib_flush_all_reply payload;
} vapi_msg_l2fib_flush_all_reply;

static inline void vapi_msg_l2fib_flush_all_reply_payload_hton(vapi_payload_l2fib_flush_all_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_l2fib_flush_all_reply_payload_ntoh(vapi_payload_l2fib_flush_all_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_l2fib_flush_all_reply_hton(vapi_msg_l2fib_flush_all_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2fib_flush_all_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_l2fib_flush_all_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2fib_flush_all_reply_ntoh(vapi_msg_l2fib_flush_all_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2fib_flush_all_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_l2fib_flush_all_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2fib_flush_all_reply_msg_size(vapi_msg_l2fib_flush_all_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2fib_flush_all_reply_msg_size(vapi_msg_l2fib_flush_all_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2fib_flush_all_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'l2fib_flush_all_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2fib_flush_all_reply));
      return -1;
    }
  if (vapi_calc_l2fib_flush_all_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2fib_flush_all_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2fib_flush_all_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_l2fib_flush_all_reply()
{
  static const char name[] = "l2fib_flush_all_reply";
  static const char name_with_crc[] = "l2fib_flush_all_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_l2fib_flush_all_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_l2fib_flush_all_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_l2fib_flush_all_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_l2fib_flush_all_reply_hton,
    (generic_swap_fn_t)vapi_msg_l2fib_flush_all_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2fib_flush_all_reply = vapi_register_msg(&__vapi_metadata_l2fib_flush_all_reply);
  VAPI_DBG("Assigned msg id %d to l2fib_flush_all_reply", vapi_msg_id_l2fib_flush_all_reply);
}

static inline void vapi_set_vapi_msg_l2fib_flush_all_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_l2fib_flush_all_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_l2fib_flush_all_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_l2fib_flush_all
#define defined_vapi_msg_l2fib_flush_all
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_l2fib_flush_all;

static inline void vapi_msg_l2fib_flush_all_hton(vapi_msg_l2fib_flush_all *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2fib_flush_all'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_l2fib_flush_all_ntoh(vapi_msg_l2fib_flush_all *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2fib_flush_all'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_l2fib_flush_all_msg_size(vapi_msg_l2fib_flush_all *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2fib_flush_all_msg_size(vapi_msg_l2fib_flush_all *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2fib_flush_all) > buf_size)
    {
      VAPI_ERR("Truncated 'l2fib_flush_all' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2fib_flush_all));
      return -1;
    }
  if (vapi_calc_l2fib_flush_all_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2fib_flush_all' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2fib_flush_all_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_l2fib_flush_all* vapi_alloc_l2fib_flush_all(struct vapi_ctx_s *ctx)
{
  vapi_msg_l2fib_flush_all *msg = NULL;
  const size_t size = sizeof(vapi_msg_l2fib_flush_all);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_l2fib_flush_all*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_l2fib_flush_all);

  return msg;
}

static inline vapi_error_e vapi_l2fib_flush_all(struct vapi_ctx_s *ctx,
  vapi_msg_l2fib_flush_all *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_l2fib_flush_all_reply *reply),
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
  vapi_msg_l2fib_flush_all_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_l2fib_flush_all_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_l2fib_flush_all_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_l2fib_flush_all()
{
  static const char name[] = "l2fib_flush_all";
  static const char name_with_crc[] = "l2fib_flush_all_51077d14";
  static vapi_message_desc_t __vapi_metadata_l2fib_flush_all = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_l2fib_flush_all_msg_size,
    (generic_swap_fn_t)vapi_msg_l2fib_flush_all_hton,
    (generic_swap_fn_t)vapi_msg_l2fib_flush_all_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2fib_flush_all = vapi_register_msg(&__vapi_metadata_l2fib_flush_all);
  VAPI_DBG("Assigned msg id %d to l2fib_flush_all", vapi_msg_id_l2fib_flush_all);
}
#endif

#ifndef defined_vapi_msg_l2fib_flush_bd_reply
#define defined_vapi_msg_l2fib_flush_bd_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_l2fib_flush_bd_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_l2fib_flush_bd_reply payload;
} vapi_msg_l2fib_flush_bd_reply;

static inline void vapi_msg_l2fib_flush_bd_reply_payload_hton(vapi_payload_l2fib_flush_bd_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_l2fib_flush_bd_reply_payload_ntoh(vapi_payload_l2fib_flush_bd_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_l2fib_flush_bd_reply_hton(vapi_msg_l2fib_flush_bd_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2fib_flush_bd_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_l2fib_flush_bd_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2fib_flush_bd_reply_ntoh(vapi_msg_l2fib_flush_bd_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2fib_flush_bd_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_l2fib_flush_bd_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2fib_flush_bd_reply_msg_size(vapi_msg_l2fib_flush_bd_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2fib_flush_bd_reply_msg_size(vapi_msg_l2fib_flush_bd_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2fib_flush_bd_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'l2fib_flush_bd_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2fib_flush_bd_reply));
      return -1;
    }
  if (vapi_calc_l2fib_flush_bd_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2fib_flush_bd_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2fib_flush_bd_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_l2fib_flush_bd_reply()
{
  static const char name[] = "l2fib_flush_bd_reply";
  static const char name_with_crc[] = "l2fib_flush_bd_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_l2fib_flush_bd_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_l2fib_flush_bd_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_l2fib_flush_bd_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_l2fib_flush_bd_reply_hton,
    (generic_swap_fn_t)vapi_msg_l2fib_flush_bd_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2fib_flush_bd_reply = vapi_register_msg(&__vapi_metadata_l2fib_flush_bd_reply);
  VAPI_DBG("Assigned msg id %d to l2fib_flush_bd_reply", vapi_msg_id_l2fib_flush_bd_reply);
}

static inline void vapi_set_vapi_msg_l2fib_flush_bd_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_l2fib_flush_bd_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_l2fib_flush_bd_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_l2fib_flush_bd
#define defined_vapi_msg_l2fib_flush_bd
typedef struct __attribute__ ((__packed__)) {
  u32 bd_id; 
} vapi_payload_l2fib_flush_bd;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_l2fib_flush_bd payload;
} vapi_msg_l2fib_flush_bd;

static inline void vapi_msg_l2fib_flush_bd_payload_hton(vapi_payload_l2fib_flush_bd *payload)
{
  payload->bd_id = htobe32(payload->bd_id);
}

static inline void vapi_msg_l2fib_flush_bd_payload_ntoh(vapi_payload_l2fib_flush_bd *payload)
{
  payload->bd_id = be32toh(payload->bd_id);
}

static inline void vapi_msg_l2fib_flush_bd_hton(vapi_msg_l2fib_flush_bd *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2fib_flush_bd'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_l2fib_flush_bd_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2fib_flush_bd_ntoh(vapi_msg_l2fib_flush_bd *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2fib_flush_bd'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_l2fib_flush_bd_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2fib_flush_bd_msg_size(vapi_msg_l2fib_flush_bd *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2fib_flush_bd_msg_size(vapi_msg_l2fib_flush_bd *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2fib_flush_bd) > buf_size)
    {
      VAPI_ERR("Truncated 'l2fib_flush_bd' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2fib_flush_bd));
      return -1;
    }
  if (vapi_calc_l2fib_flush_bd_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2fib_flush_bd' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2fib_flush_bd_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_l2fib_flush_bd* vapi_alloc_l2fib_flush_bd(struct vapi_ctx_s *ctx)
{
  vapi_msg_l2fib_flush_bd *msg = NULL;
  const size_t size = sizeof(vapi_msg_l2fib_flush_bd);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_l2fib_flush_bd*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_l2fib_flush_bd);

  return msg;
}

static inline vapi_error_e vapi_l2fib_flush_bd(struct vapi_ctx_s *ctx,
  vapi_msg_l2fib_flush_bd *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_l2fib_flush_bd_reply *reply),
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
  vapi_msg_l2fib_flush_bd_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_l2fib_flush_bd_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_l2fib_flush_bd_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_l2fib_flush_bd()
{
  static const char name[] = "l2fib_flush_bd";
  static const char name_with_crc[] = "l2fib_flush_bd_c25fdce6";
  static vapi_message_desc_t __vapi_metadata_l2fib_flush_bd = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_l2fib_flush_bd, payload),
    (verify_msg_size_fn_t)vapi_verify_l2fib_flush_bd_msg_size,
    (generic_swap_fn_t)vapi_msg_l2fib_flush_bd_hton,
    (generic_swap_fn_t)vapi_msg_l2fib_flush_bd_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2fib_flush_bd = vapi_register_msg(&__vapi_metadata_l2fib_flush_bd);
  VAPI_DBG("Assigned msg id %d to l2fib_flush_bd", vapi_msg_id_l2fib_flush_bd);
}
#endif

#ifndef defined_vapi_msg_l2fib_flush_int_reply
#define defined_vapi_msg_l2fib_flush_int_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_l2fib_flush_int_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_l2fib_flush_int_reply payload;
} vapi_msg_l2fib_flush_int_reply;

static inline void vapi_msg_l2fib_flush_int_reply_payload_hton(vapi_payload_l2fib_flush_int_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_l2fib_flush_int_reply_payload_ntoh(vapi_payload_l2fib_flush_int_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_l2fib_flush_int_reply_hton(vapi_msg_l2fib_flush_int_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2fib_flush_int_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_l2fib_flush_int_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2fib_flush_int_reply_ntoh(vapi_msg_l2fib_flush_int_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2fib_flush_int_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_l2fib_flush_int_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2fib_flush_int_reply_msg_size(vapi_msg_l2fib_flush_int_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2fib_flush_int_reply_msg_size(vapi_msg_l2fib_flush_int_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2fib_flush_int_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'l2fib_flush_int_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2fib_flush_int_reply));
      return -1;
    }
  if (vapi_calc_l2fib_flush_int_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2fib_flush_int_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2fib_flush_int_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_l2fib_flush_int_reply()
{
  static const char name[] = "l2fib_flush_int_reply";
  static const char name_with_crc[] = "l2fib_flush_int_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_l2fib_flush_int_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_l2fib_flush_int_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_l2fib_flush_int_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_l2fib_flush_int_reply_hton,
    (generic_swap_fn_t)vapi_msg_l2fib_flush_int_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2fib_flush_int_reply = vapi_register_msg(&__vapi_metadata_l2fib_flush_int_reply);
  VAPI_DBG("Assigned msg id %d to l2fib_flush_int_reply", vapi_msg_id_l2fib_flush_int_reply);
}

static inline void vapi_set_vapi_msg_l2fib_flush_int_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_l2fib_flush_int_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_l2fib_flush_int_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_l2fib_flush_int
#define defined_vapi_msg_l2fib_flush_int
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_l2fib_flush_int;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_l2fib_flush_int payload;
} vapi_msg_l2fib_flush_int;

static inline void vapi_msg_l2fib_flush_int_payload_hton(vapi_payload_l2fib_flush_int *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_l2fib_flush_int_payload_ntoh(vapi_payload_l2fib_flush_int *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_l2fib_flush_int_hton(vapi_msg_l2fib_flush_int *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2fib_flush_int'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_l2fib_flush_int_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2fib_flush_int_ntoh(vapi_msg_l2fib_flush_int *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2fib_flush_int'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_l2fib_flush_int_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2fib_flush_int_msg_size(vapi_msg_l2fib_flush_int *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2fib_flush_int_msg_size(vapi_msg_l2fib_flush_int *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2fib_flush_int) > buf_size)
    {
      VAPI_ERR("Truncated 'l2fib_flush_int' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2fib_flush_int));
      return -1;
    }
  if (vapi_calc_l2fib_flush_int_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2fib_flush_int' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2fib_flush_int_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_l2fib_flush_int* vapi_alloc_l2fib_flush_int(struct vapi_ctx_s *ctx)
{
  vapi_msg_l2fib_flush_int *msg = NULL;
  const size_t size = sizeof(vapi_msg_l2fib_flush_int);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_l2fib_flush_int*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_l2fib_flush_int);

  return msg;
}

static inline vapi_error_e vapi_l2fib_flush_int(struct vapi_ctx_s *ctx,
  vapi_msg_l2fib_flush_int *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_l2fib_flush_int_reply *reply),
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
  vapi_msg_l2fib_flush_int_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_l2fib_flush_int_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_l2fib_flush_int_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_l2fib_flush_int()
{
  static const char name[] = "l2fib_flush_int";
  static const char name_with_crc[] = "l2fib_flush_int_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_l2fib_flush_int = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_l2fib_flush_int, payload),
    (verify_msg_size_fn_t)vapi_verify_l2fib_flush_int_msg_size,
    (generic_swap_fn_t)vapi_msg_l2fib_flush_int_hton,
    (generic_swap_fn_t)vapi_msg_l2fib_flush_int_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2fib_flush_int = vapi_register_msg(&__vapi_metadata_l2fib_flush_int);
  VAPI_DBG("Assigned msg id %d to l2fib_flush_int", vapi_msg_id_l2fib_flush_int);
}
#endif

#ifndef defined_vapi_msg_l2fib_add_del_reply
#define defined_vapi_msg_l2fib_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_l2fib_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_l2fib_add_del_reply payload;
} vapi_msg_l2fib_add_del_reply;

static inline void vapi_msg_l2fib_add_del_reply_payload_hton(vapi_payload_l2fib_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_l2fib_add_del_reply_payload_ntoh(vapi_payload_l2fib_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_l2fib_add_del_reply_hton(vapi_msg_l2fib_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2fib_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_l2fib_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2fib_add_del_reply_ntoh(vapi_msg_l2fib_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2fib_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_l2fib_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2fib_add_del_reply_msg_size(vapi_msg_l2fib_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2fib_add_del_reply_msg_size(vapi_msg_l2fib_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2fib_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'l2fib_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2fib_add_del_reply));
      return -1;
    }
  if (vapi_calc_l2fib_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2fib_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2fib_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_l2fib_add_del_reply()
{
  static const char name[] = "l2fib_add_del_reply";
  static const char name_with_crc[] = "l2fib_add_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_l2fib_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_l2fib_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_l2fib_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_l2fib_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_l2fib_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2fib_add_del_reply = vapi_register_msg(&__vapi_metadata_l2fib_add_del_reply);
  VAPI_DBG("Assigned msg id %d to l2fib_add_del_reply", vapi_msg_id_l2fib_add_del_reply);
}

static inline void vapi_set_vapi_msg_l2fib_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_l2fib_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_l2fib_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_l2fib_add_del
#define defined_vapi_msg_l2fib_add_del
typedef struct __attribute__ ((__packed__)) {
  vapi_type_mac_address mac;
  u32 bd_id;
  vapi_type_interface_index sw_if_index;
  bool is_add;
  bool static_mac;
  bool filter_mac;
  bool bvi_mac; 
} vapi_payload_l2fib_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_l2fib_add_del payload;
} vapi_msg_l2fib_add_del;

static inline void vapi_msg_l2fib_add_del_payload_hton(vapi_payload_l2fib_add_del *payload)
{
  payload->bd_id = htobe32(payload->bd_id);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_l2fib_add_del_payload_ntoh(vapi_payload_l2fib_add_del *payload)
{
  payload->bd_id = be32toh(payload->bd_id);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_l2fib_add_del_hton(vapi_msg_l2fib_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2fib_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_l2fib_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2fib_add_del_ntoh(vapi_msg_l2fib_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2fib_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_l2fib_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2fib_add_del_msg_size(vapi_msg_l2fib_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2fib_add_del_msg_size(vapi_msg_l2fib_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2fib_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'l2fib_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2fib_add_del));
      return -1;
    }
  if (vapi_calc_l2fib_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2fib_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2fib_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_l2fib_add_del* vapi_alloc_l2fib_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_l2fib_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_l2fib_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_l2fib_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_l2fib_add_del);

  return msg;
}

static inline vapi_error_e vapi_l2fib_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_l2fib_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_l2fib_add_del_reply *reply),
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
  vapi_msg_l2fib_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_l2fib_add_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_l2fib_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_l2fib_add_del()
{
  static const char name[] = "l2fib_add_del";
  static const char name_with_crc[] = "l2fib_add_del_eddda487";
  static vapi_message_desc_t __vapi_metadata_l2fib_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_l2fib_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_l2fib_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_l2fib_add_del_hton,
    (generic_swap_fn_t)vapi_msg_l2fib_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2fib_add_del = vapi_register_msg(&__vapi_metadata_l2fib_add_del);
  VAPI_DBG("Assigned msg id %d to l2fib_add_del", vapi_msg_id_l2fib_add_del);
}
#endif

#ifndef defined_vapi_msg_want_l2_macs_events_reply
#define defined_vapi_msg_want_l2_macs_events_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_want_l2_macs_events_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_want_l2_macs_events_reply payload;
} vapi_msg_want_l2_macs_events_reply;

static inline void vapi_msg_want_l2_macs_events_reply_payload_hton(vapi_payload_want_l2_macs_events_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_want_l2_macs_events_reply_payload_ntoh(vapi_payload_want_l2_macs_events_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_want_l2_macs_events_reply_hton(vapi_msg_want_l2_macs_events_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_l2_macs_events_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_want_l2_macs_events_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_want_l2_macs_events_reply_ntoh(vapi_msg_want_l2_macs_events_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_l2_macs_events_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_want_l2_macs_events_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_want_l2_macs_events_reply_msg_size(vapi_msg_want_l2_macs_events_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_want_l2_macs_events_reply_msg_size(vapi_msg_want_l2_macs_events_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_want_l2_macs_events_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'want_l2_macs_events_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_want_l2_macs_events_reply));
      return -1;
    }
  if (vapi_calc_want_l2_macs_events_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'want_l2_macs_events_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_want_l2_macs_events_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_want_l2_macs_events_reply()
{
  static const char name[] = "want_l2_macs_events_reply";
  static const char name_with_crc[] = "want_l2_macs_events_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_want_l2_macs_events_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_want_l2_macs_events_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_want_l2_macs_events_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_want_l2_macs_events_reply_hton,
    (generic_swap_fn_t)vapi_msg_want_l2_macs_events_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_want_l2_macs_events_reply = vapi_register_msg(&__vapi_metadata_want_l2_macs_events_reply);
  VAPI_DBG("Assigned msg id %d to want_l2_macs_events_reply", vapi_msg_id_want_l2_macs_events_reply);
}

static inline void vapi_set_vapi_msg_want_l2_macs_events_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_want_l2_macs_events_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_want_l2_macs_events_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_want_l2_macs_events
#define defined_vapi_msg_want_l2_macs_events
typedef struct __attribute__ ((__packed__)) {
  u32 learn_limit;
  u8 scan_delay;
  u8 max_macs_in_event;
  bool enable_disable;
  u32 pid; 
} vapi_payload_want_l2_macs_events;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_want_l2_macs_events payload;
} vapi_msg_want_l2_macs_events;

static inline void vapi_msg_want_l2_macs_events_payload_hton(vapi_payload_want_l2_macs_events *payload)
{
  payload->learn_limit = htobe32(payload->learn_limit);
  payload->pid = htobe32(payload->pid);
}

static inline void vapi_msg_want_l2_macs_events_payload_ntoh(vapi_payload_want_l2_macs_events *payload)
{
  payload->learn_limit = be32toh(payload->learn_limit);
  payload->pid = be32toh(payload->pid);
}

static inline void vapi_msg_want_l2_macs_events_hton(vapi_msg_want_l2_macs_events *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_l2_macs_events'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_want_l2_macs_events_payload_hton(&msg->payload);
}

static inline void vapi_msg_want_l2_macs_events_ntoh(vapi_msg_want_l2_macs_events *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_l2_macs_events'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_want_l2_macs_events_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_want_l2_macs_events_msg_size(vapi_msg_want_l2_macs_events *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_want_l2_macs_events_msg_size(vapi_msg_want_l2_macs_events *msg, uword buf_size)
{
  if (sizeof(vapi_msg_want_l2_macs_events) > buf_size)
    {
      VAPI_ERR("Truncated 'want_l2_macs_events' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_want_l2_macs_events));
      return -1;
    }
  if (vapi_calc_want_l2_macs_events_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'want_l2_macs_events' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_want_l2_macs_events_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_want_l2_macs_events* vapi_alloc_want_l2_macs_events(struct vapi_ctx_s *ctx)
{
  vapi_msg_want_l2_macs_events *msg = NULL;
  const size_t size = sizeof(vapi_msg_want_l2_macs_events);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_want_l2_macs_events*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_want_l2_macs_events);

  return msg;
}

static inline vapi_error_e vapi_want_l2_macs_events(struct vapi_ctx_s *ctx,
  vapi_msg_want_l2_macs_events *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_want_l2_macs_events_reply *reply),
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
  vapi_msg_want_l2_macs_events_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_want_l2_macs_events_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_want_l2_macs_events_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_want_l2_macs_events()
{
  static const char name[] = "want_l2_macs_events";
  static const char name_with_crc[] = "want_l2_macs_events_9aabdfde";
  static vapi_message_desc_t __vapi_metadata_want_l2_macs_events = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_want_l2_macs_events, payload),
    (verify_msg_size_fn_t)vapi_verify_want_l2_macs_events_msg_size,
    (generic_swap_fn_t)vapi_msg_want_l2_macs_events_hton,
    (generic_swap_fn_t)vapi_msg_want_l2_macs_events_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_want_l2_macs_events = vapi_register_msg(&__vapi_metadata_want_l2_macs_events);
  VAPI_DBG("Assigned msg id %d to want_l2_macs_events", vapi_msg_id_want_l2_macs_events);
}
#endif

#ifndef defined_vapi_msg_want_l2_macs_events2_reply
#define defined_vapi_msg_want_l2_macs_events2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_want_l2_macs_events2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_want_l2_macs_events2_reply payload;
} vapi_msg_want_l2_macs_events2_reply;

static inline void vapi_msg_want_l2_macs_events2_reply_payload_hton(vapi_payload_want_l2_macs_events2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_want_l2_macs_events2_reply_payload_ntoh(vapi_payload_want_l2_macs_events2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_want_l2_macs_events2_reply_hton(vapi_msg_want_l2_macs_events2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_l2_macs_events2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_want_l2_macs_events2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_want_l2_macs_events2_reply_ntoh(vapi_msg_want_l2_macs_events2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_l2_macs_events2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_want_l2_macs_events2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_want_l2_macs_events2_reply_msg_size(vapi_msg_want_l2_macs_events2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_want_l2_macs_events2_reply_msg_size(vapi_msg_want_l2_macs_events2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_want_l2_macs_events2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'want_l2_macs_events2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_want_l2_macs_events2_reply));
      return -1;
    }
  if (vapi_calc_want_l2_macs_events2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'want_l2_macs_events2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_want_l2_macs_events2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_want_l2_macs_events2_reply()
{
  static const char name[] = "want_l2_macs_events2_reply";
  static const char name_with_crc[] = "want_l2_macs_events2_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_want_l2_macs_events2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_want_l2_macs_events2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_want_l2_macs_events2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_want_l2_macs_events2_reply_hton,
    (generic_swap_fn_t)vapi_msg_want_l2_macs_events2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_want_l2_macs_events2_reply = vapi_register_msg(&__vapi_metadata_want_l2_macs_events2_reply);
  VAPI_DBG("Assigned msg id %d to want_l2_macs_events2_reply", vapi_msg_id_want_l2_macs_events2_reply);
}

static inline void vapi_set_vapi_msg_want_l2_macs_events2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_want_l2_macs_events2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_want_l2_macs_events2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_want_l2_macs_events2
#define defined_vapi_msg_want_l2_macs_events2
typedef struct __attribute__ ((__packed__)) {
  u8 max_macs_in_event;
  bool enable_disable;
  u32 pid; 
} vapi_payload_want_l2_macs_events2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_want_l2_macs_events2 payload;
} vapi_msg_want_l2_macs_events2;

static inline void vapi_msg_want_l2_macs_events2_payload_hton(vapi_payload_want_l2_macs_events2 *payload)
{
  payload->pid = htobe32(payload->pid);
}

static inline void vapi_msg_want_l2_macs_events2_payload_ntoh(vapi_payload_want_l2_macs_events2 *payload)
{
  payload->pid = be32toh(payload->pid);
}

static inline void vapi_msg_want_l2_macs_events2_hton(vapi_msg_want_l2_macs_events2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_l2_macs_events2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_want_l2_macs_events2_payload_hton(&msg->payload);
}

static inline void vapi_msg_want_l2_macs_events2_ntoh(vapi_msg_want_l2_macs_events2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_l2_macs_events2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_want_l2_macs_events2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_want_l2_macs_events2_msg_size(vapi_msg_want_l2_macs_events2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_want_l2_macs_events2_msg_size(vapi_msg_want_l2_macs_events2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_want_l2_macs_events2) > buf_size)
    {
      VAPI_ERR("Truncated 'want_l2_macs_events2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_want_l2_macs_events2));
      return -1;
    }
  if (vapi_calc_want_l2_macs_events2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'want_l2_macs_events2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_want_l2_macs_events2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_want_l2_macs_events2* vapi_alloc_want_l2_macs_events2(struct vapi_ctx_s *ctx)
{
  vapi_msg_want_l2_macs_events2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_want_l2_macs_events2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_want_l2_macs_events2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_want_l2_macs_events2);

  return msg;
}

static inline vapi_error_e vapi_want_l2_macs_events2(struct vapi_ctx_s *ctx,
  vapi_msg_want_l2_macs_events2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_want_l2_macs_events2_reply *reply),
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
  vapi_msg_want_l2_macs_events2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_want_l2_macs_events2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_want_l2_macs_events2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_want_l2_macs_events2()
{
  static const char name[] = "want_l2_macs_events2";
  static const char name_with_crc[] = "want_l2_macs_events2_cc1377b0";
  static vapi_message_desc_t __vapi_metadata_want_l2_macs_events2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_want_l2_macs_events2, payload),
    (verify_msg_size_fn_t)vapi_verify_want_l2_macs_events2_msg_size,
    (generic_swap_fn_t)vapi_msg_want_l2_macs_events2_hton,
    (generic_swap_fn_t)vapi_msg_want_l2_macs_events2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_want_l2_macs_events2 = vapi_register_msg(&__vapi_metadata_want_l2_macs_events2);
  VAPI_DBG("Assigned msg id %d to want_l2_macs_events2", vapi_msg_id_want_l2_macs_events2);
}
#endif

#ifndef defined_vapi_msg_l2fib_set_scan_delay_reply
#define defined_vapi_msg_l2fib_set_scan_delay_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_l2fib_set_scan_delay_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_l2fib_set_scan_delay_reply payload;
} vapi_msg_l2fib_set_scan_delay_reply;

static inline void vapi_msg_l2fib_set_scan_delay_reply_payload_hton(vapi_payload_l2fib_set_scan_delay_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_l2fib_set_scan_delay_reply_payload_ntoh(vapi_payload_l2fib_set_scan_delay_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_l2fib_set_scan_delay_reply_hton(vapi_msg_l2fib_set_scan_delay_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2fib_set_scan_delay_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_l2fib_set_scan_delay_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2fib_set_scan_delay_reply_ntoh(vapi_msg_l2fib_set_scan_delay_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2fib_set_scan_delay_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_l2fib_set_scan_delay_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2fib_set_scan_delay_reply_msg_size(vapi_msg_l2fib_set_scan_delay_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2fib_set_scan_delay_reply_msg_size(vapi_msg_l2fib_set_scan_delay_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2fib_set_scan_delay_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'l2fib_set_scan_delay_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2fib_set_scan_delay_reply));
      return -1;
    }
  if (vapi_calc_l2fib_set_scan_delay_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2fib_set_scan_delay_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2fib_set_scan_delay_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_l2fib_set_scan_delay_reply()
{
  static const char name[] = "l2fib_set_scan_delay_reply";
  static const char name_with_crc[] = "l2fib_set_scan_delay_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_l2fib_set_scan_delay_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_l2fib_set_scan_delay_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_l2fib_set_scan_delay_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_l2fib_set_scan_delay_reply_hton,
    (generic_swap_fn_t)vapi_msg_l2fib_set_scan_delay_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2fib_set_scan_delay_reply = vapi_register_msg(&__vapi_metadata_l2fib_set_scan_delay_reply);
  VAPI_DBG("Assigned msg id %d to l2fib_set_scan_delay_reply", vapi_msg_id_l2fib_set_scan_delay_reply);
}

static inline void vapi_set_vapi_msg_l2fib_set_scan_delay_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_l2fib_set_scan_delay_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_l2fib_set_scan_delay_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_l2fib_set_scan_delay
#define defined_vapi_msg_l2fib_set_scan_delay
typedef struct __attribute__ ((__packed__)) {
  u16 scan_delay; 
} vapi_payload_l2fib_set_scan_delay;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_l2fib_set_scan_delay payload;
} vapi_msg_l2fib_set_scan_delay;

static inline void vapi_msg_l2fib_set_scan_delay_payload_hton(vapi_payload_l2fib_set_scan_delay *payload)
{
  payload->scan_delay = htobe16(payload->scan_delay);
}

static inline void vapi_msg_l2fib_set_scan_delay_payload_ntoh(vapi_payload_l2fib_set_scan_delay *payload)
{
  payload->scan_delay = be16toh(payload->scan_delay);
}

static inline void vapi_msg_l2fib_set_scan_delay_hton(vapi_msg_l2fib_set_scan_delay *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2fib_set_scan_delay'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_l2fib_set_scan_delay_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2fib_set_scan_delay_ntoh(vapi_msg_l2fib_set_scan_delay *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2fib_set_scan_delay'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_l2fib_set_scan_delay_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2fib_set_scan_delay_msg_size(vapi_msg_l2fib_set_scan_delay *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2fib_set_scan_delay_msg_size(vapi_msg_l2fib_set_scan_delay *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2fib_set_scan_delay) > buf_size)
    {
      VAPI_ERR("Truncated 'l2fib_set_scan_delay' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2fib_set_scan_delay));
      return -1;
    }
  if (vapi_calc_l2fib_set_scan_delay_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2fib_set_scan_delay' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2fib_set_scan_delay_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_l2fib_set_scan_delay* vapi_alloc_l2fib_set_scan_delay(struct vapi_ctx_s *ctx)
{
  vapi_msg_l2fib_set_scan_delay *msg = NULL;
  const size_t size = sizeof(vapi_msg_l2fib_set_scan_delay);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_l2fib_set_scan_delay*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_l2fib_set_scan_delay);

  return msg;
}

static inline vapi_error_e vapi_l2fib_set_scan_delay(struct vapi_ctx_s *ctx,
  vapi_msg_l2fib_set_scan_delay *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_l2fib_set_scan_delay_reply *reply),
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
  vapi_msg_l2fib_set_scan_delay_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_l2fib_set_scan_delay_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_l2fib_set_scan_delay_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_l2fib_set_scan_delay()
{
  static const char name[] = "l2fib_set_scan_delay";
  static const char name_with_crc[] = "l2fib_set_scan_delay_a3b968a4";
  static vapi_message_desc_t __vapi_metadata_l2fib_set_scan_delay = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_l2fib_set_scan_delay, payload),
    (verify_msg_size_fn_t)vapi_verify_l2fib_set_scan_delay_msg_size,
    (generic_swap_fn_t)vapi_msg_l2fib_set_scan_delay_hton,
    (generic_swap_fn_t)vapi_msg_l2fib_set_scan_delay_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2fib_set_scan_delay = vapi_register_msg(&__vapi_metadata_l2fib_set_scan_delay);
  VAPI_DBG("Assigned msg id %d to l2fib_set_scan_delay", vapi_msg_id_l2fib_set_scan_delay);
}
#endif

#ifndef defined_vapi_msg_l2_macs_event
#define defined_vapi_msg_l2_macs_event
typedef struct __attribute__ ((__packed__)) {
  u16 _vl_msg_id;
  u32 client_index;
  u32 pid;
  u32 n_macs;
  vapi_type_mac_entry mac[0]; 
} vapi_payload_l2_macs_event;

typedef struct __attribute__ ((__packed__)) {

  vapi_payload_l2_macs_event payload;
} vapi_msg_l2_macs_event;

static inline void vapi_msg_l2_macs_event_payload_hton(vapi_payload_l2_macs_event *payload)
{
  payload->_vl_msg_id = htobe16(payload->_vl_msg_id);
  payload->client_index = htobe32(payload->client_index);
  payload->pid = htobe32(payload->pid);
  payload->n_macs = htobe32(payload->n_macs);
  do { unsigned i; for (i = 0; i < be32toh(payload->n_macs); ++i) { vapi_type_mac_entry_hton(&payload->mac[i]); } } while(0);
}

static inline void vapi_msg_l2_macs_event_payload_ntoh(vapi_payload_l2_macs_event *payload)
{
  payload->_vl_msg_id = be16toh(payload->_vl_msg_id);
  payload->client_index = be32toh(payload->client_index);
  payload->pid = be32toh(payload->pid);
  payload->n_macs = be32toh(payload->n_macs);
  do { unsigned i; for (i = 0; i < payload->n_macs; ++i) { vapi_type_mac_entry_ntoh(&payload->mac[i]); } } while(0);
}

static inline void vapi_msg_l2_macs_event_hton(vapi_msg_l2_macs_event *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_macs_event'@%p to big endian", msg);

  vapi_msg_l2_macs_event_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2_macs_event_ntoh(vapi_msg_l2_macs_event *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_macs_event'@%p to host byte order", msg);

  vapi_msg_l2_macs_event_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2_macs_event_msg_size(vapi_msg_l2_macs_event *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.mac[0]) * msg->payload.n_macs;
}

static inline int vapi_verify_l2_macs_event_msg_size(vapi_msg_l2_macs_event *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2_macs_event) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_macs_event' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2_macs_event));
      return -1;
    }
  if (vapi_calc_l2_macs_event_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_macs_event' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2_macs_event_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_l2_macs_event()
{
  static const char name[] = "l2_macs_event";
  static const char name_with_crc[] = "l2_macs_event_44b8fd64";
  static vapi_message_desc_t __vapi_metadata_l2_macs_event = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    false,
    0,
    offsetof(vapi_msg_l2_macs_event, payload),
    (verify_msg_size_fn_t)vapi_verify_l2_macs_event_msg_size,
    (generic_swap_fn_t)vapi_msg_l2_macs_event_hton,
    (generic_swap_fn_t)vapi_msg_l2_macs_event_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2_macs_event = vapi_register_msg(&__vapi_metadata_l2_macs_event);
  VAPI_DBG("Assigned msg id %d to l2_macs_event", vapi_msg_id_l2_macs_event);
}

static inline void vapi_set_vapi_msg_l2_macs_event_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_l2_macs_event *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_l2_macs_event, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_l2_flags_reply
#define defined_vapi_msg_l2_flags_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 resulting_feature_bitmap; 
} vapi_payload_l2_flags_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_l2_flags_reply payload;
} vapi_msg_l2_flags_reply;

static inline void vapi_msg_l2_flags_reply_payload_hton(vapi_payload_l2_flags_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->resulting_feature_bitmap = htobe32(payload->resulting_feature_bitmap);
}

static inline void vapi_msg_l2_flags_reply_payload_ntoh(vapi_payload_l2_flags_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->resulting_feature_bitmap = be32toh(payload->resulting_feature_bitmap);
}

static inline void vapi_msg_l2_flags_reply_hton(vapi_msg_l2_flags_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_flags_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_l2_flags_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2_flags_reply_ntoh(vapi_msg_l2_flags_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_flags_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_l2_flags_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2_flags_reply_msg_size(vapi_msg_l2_flags_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2_flags_reply_msg_size(vapi_msg_l2_flags_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2_flags_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_flags_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2_flags_reply));
      return -1;
    }
  if (vapi_calc_l2_flags_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_flags_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2_flags_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_l2_flags_reply()
{
  static const char name[] = "l2_flags_reply";
  static const char name_with_crc[] = "l2_flags_reply_29b2a2b3";
  static vapi_message_desc_t __vapi_metadata_l2_flags_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_l2_flags_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_l2_flags_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_l2_flags_reply_hton,
    (generic_swap_fn_t)vapi_msg_l2_flags_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2_flags_reply = vapi_register_msg(&__vapi_metadata_l2_flags_reply);
  VAPI_DBG("Assigned msg id %d to l2_flags_reply", vapi_msg_id_l2_flags_reply);
}

static inline void vapi_set_vapi_msg_l2_flags_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_l2_flags_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_l2_flags_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_l2_flags
#define defined_vapi_msg_l2_flags
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  bool is_set;
  u32 feature_bitmap; 
} vapi_payload_l2_flags;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_l2_flags payload;
} vapi_msg_l2_flags;

static inline void vapi_msg_l2_flags_payload_hton(vapi_payload_l2_flags *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->feature_bitmap = htobe32(payload->feature_bitmap);
}

static inline void vapi_msg_l2_flags_payload_ntoh(vapi_payload_l2_flags *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->feature_bitmap = be32toh(payload->feature_bitmap);
}

static inline void vapi_msg_l2_flags_hton(vapi_msg_l2_flags *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_flags'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_l2_flags_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2_flags_ntoh(vapi_msg_l2_flags *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_flags'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_l2_flags_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2_flags_msg_size(vapi_msg_l2_flags *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2_flags_msg_size(vapi_msg_l2_flags *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2_flags) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_flags' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2_flags));
      return -1;
    }
  if (vapi_calc_l2_flags_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_flags' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2_flags_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_l2_flags* vapi_alloc_l2_flags(struct vapi_ctx_s *ctx)
{
  vapi_msg_l2_flags *msg = NULL;
  const size_t size = sizeof(vapi_msg_l2_flags);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_l2_flags*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_l2_flags);

  return msg;
}

static inline vapi_error_e vapi_l2_flags(struct vapi_ctx_s *ctx,
  vapi_msg_l2_flags *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_l2_flags_reply *reply),
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
  vapi_msg_l2_flags_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_l2_flags_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_l2_flags_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_l2_flags()
{
  static const char name[] = "l2_flags";
  static const char name_with_crc[] = "l2_flags_fc41cfe8";
  static vapi_message_desc_t __vapi_metadata_l2_flags = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_l2_flags, payload),
    (verify_msg_size_fn_t)vapi_verify_l2_flags_msg_size,
    (generic_swap_fn_t)vapi_msg_l2_flags_hton,
    (generic_swap_fn_t)vapi_msg_l2_flags_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2_flags = vapi_register_msg(&__vapi_metadata_l2_flags);
  VAPI_DBG("Assigned msg id %d to l2_flags", vapi_msg_id_l2_flags);
}
#endif

#ifndef defined_vapi_msg_bridge_domain_set_mac_age_reply
#define defined_vapi_msg_bridge_domain_set_mac_age_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bridge_domain_set_mac_age_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bridge_domain_set_mac_age_reply payload;
} vapi_msg_bridge_domain_set_mac_age_reply;

static inline void vapi_msg_bridge_domain_set_mac_age_reply_payload_hton(vapi_payload_bridge_domain_set_mac_age_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bridge_domain_set_mac_age_reply_payload_ntoh(vapi_payload_bridge_domain_set_mac_age_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bridge_domain_set_mac_age_reply_hton(vapi_msg_bridge_domain_set_mac_age_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_set_mac_age_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bridge_domain_set_mac_age_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bridge_domain_set_mac_age_reply_ntoh(vapi_msg_bridge_domain_set_mac_age_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_set_mac_age_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bridge_domain_set_mac_age_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bridge_domain_set_mac_age_reply_msg_size(vapi_msg_bridge_domain_set_mac_age_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bridge_domain_set_mac_age_reply_msg_size(vapi_msg_bridge_domain_set_mac_age_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bridge_domain_set_mac_age_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_set_mac_age_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bridge_domain_set_mac_age_reply));
      return -1;
    }
  if (vapi_calc_bridge_domain_set_mac_age_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_set_mac_age_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bridge_domain_set_mac_age_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bridge_domain_set_mac_age_reply()
{
  static const char name[] = "bridge_domain_set_mac_age_reply";
  static const char name_with_crc[] = "bridge_domain_set_mac_age_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bridge_domain_set_mac_age_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bridge_domain_set_mac_age_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bridge_domain_set_mac_age_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bridge_domain_set_mac_age_reply_hton,
    (generic_swap_fn_t)vapi_msg_bridge_domain_set_mac_age_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bridge_domain_set_mac_age_reply = vapi_register_msg(&__vapi_metadata_bridge_domain_set_mac_age_reply);
  VAPI_DBG("Assigned msg id %d to bridge_domain_set_mac_age_reply", vapi_msg_id_bridge_domain_set_mac_age_reply);
}

static inline void vapi_set_vapi_msg_bridge_domain_set_mac_age_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bridge_domain_set_mac_age_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bridge_domain_set_mac_age_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bridge_domain_set_mac_age
#define defined_vapi_msg_bridge_domain_set_mac_age
typedef struct __attribute__ ((__packed__)) {
  u32 bd_id;
  u8 mac_age; 
} vapi_payload_bridge_domain_set_mac_age;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bridge_domain_set_mac_age payload;
} vapi_msg_bridge_domain_set_mac_age;

static inline void vapi_msg_bridge_domain_set_mac_age_payload_hton(vapi_payload_bridge_domain_set_mac_age *payload)
{
  payload->bd_id = htobe32(payload->bd_id);
}

static inline void vapi_msg_bridge_domain_set_mac_age_payload_ntoh(vapi_payload_bridge_domain_set_mac_age *payload)
{
  payload->bd_id = be32toh(payload->bd_id);
}

static inline void vapi_msg_bridge_domain_set_mac_age_hton(vapi_msg_bridge_domain_set_mac_age *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_set_mac_age'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bridge_domain_set_mac_age_payload_hton(&msg->payload);
}

static inline void vapi_msg_bridge_domain_set_mac_age_ntoh(vapi_msg_bridge_domain_set_mac_age *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_set_mac_age'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bridge_domain_set_mac_age_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bridge_domain_set_mac_age_msg_size(vapi_msg_bridge_domain_set_mac_age *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bridge_domain_set_mac_age_msg_size(vapi_msg_bridge_domain_set_mac_age *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bridge_domain_set_mac_age) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_set_mac_age' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bridge_domain_set_mac_age));
      return -1;
    }
  if (vapi_calc_bridge_domain_set_mac_age_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_set_mac_age' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bridge_domain_set_mac_age_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bridge_domain_set_mac_age* vapi_alloc_bridge_domain_set_mac_age(struct vapi_ctx_s *ctx)
{
  vapi_msg_bridge_domain_set_mac_age *msg = NULL;
  const size_t size = sizeof(vapi_msg_bridge_domain_set_mac_age);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bridge_domain_set_mac_age*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bridge_domain_set_mac_age);

  return msg;
}

static inline vapi_error_e vapi_bridge_domain_set_mac_age(struct vapi_ctx_s *ctx,
  vapi_msg_bridge_domain_set_mac_age *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bridge_domain_set_mac_age_reply *reply),
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
  vapi_msg_bridge_domain_set_mac_age_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bridge_domain_set_mac_age_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bridge_domain_set_mac_age_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bridge_domain_set_mac_age()
{
  static const char name[] = "bridge_domain_set_mac_age";
  static const char name_with_crc[] = "bridge_domain_set_mac_age_b537ad7b";
  static vapi_message_desc_t __vapi_metadata_bridge_domain_set_mac_age = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bridge_domain_set_mac_age, payload),
    (verify_msg_size_fn_t)vapi_verify_bridge_domain_set_mac_age_msg_size,
    (generic_swap_fn_t)vapi_msg_bridge_domain_set_mac_age_hton,
    (generic_swap_fn_t)vapi_msg_bridge_domain_set_mac_age_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bridge_domain_set_mac_age = vapi_register_msg(&__vapi_metadata_bridge_domain_set_mac_age);
  VAPI_DBG("Assigned msg id %d to bridge_domain_set_mac_age", vapi_msg_id_bridge_domain_set_mac_age);
}
#endif

#ifndef defined_vapi_msg_bridge_domain_set_default_learn_limit_reply
#define defined_vapi_msg_bridge_domain_set_default_learn_limit_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bridge_domain_set_default_learn_limit_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bridge_domain_set_default_learn_limit_reply payload;
} vapi_msg_bridge_domain_set_default_learn_limit_reply;

static inline void vapi_msg_bridge_domain_set_default_learn_limit_reply_payload_hton(vapi_payload_bridge_domain_set_default_learn_limit_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bridge_domain_set_default_learn_limit_reply_payload_ntoh(vapi_payload_bridge_domain_set_default_learn_limit_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bridge_domain_set_default_learn_limit_reply_hton(vapi_msg_bridge_domain_set_default_learn_limit_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_set_default_learn_limit_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bridge_domain_set_default_learn_limit_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bridge_domain_set_default_learn_limit_reply_ntoh(vapi_msg_bridge_domain_set_default_learn_limit_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_set_default_learn_limit_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bridge_domain_set_default_learn_limit_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bridge_domain_set_default_learn_limit_reply_msg_size(vapi_msg_bridge_domain_set_default_learn_limit_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bridge_domain_set_default_learn_limit_reply_msg_size(vapi_msg_bridge_domain_set_default_learn_limit_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bridge_domain_set_default_learn_limit_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_set_default_learn_limit_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bridge_domain_set_default_learn_limit_reply));
      return -1;
    }
  if (vapi_calc_bridge_domain_set_default_learn_limit_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_set_default_learn_limit_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bridge_domain_set_default_learn_limit_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bridge_domain_set_default_learn_limit_reply()
{
  static const char name[] = "bridge_domain_set_default_learn_limit_reply";
  static const char name_with_crc[] = "bridge_domain_set_default_learn_limit_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bridge_domain_set_default_learn_limit_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bridge_domain_set_default_learn_limit_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bridge_domain_set_default_learn_limit_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bridge_domain_set_default_learn_limit_reply_hton,
    (generic_swap_fn_t)vapi_msg_bridge_domain_set_default_learn_limit_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bridge_domain_set_default_learn_limit_reply = vapi_register_msg(&__vapi_metadata_bridge_domain_set_default_learn_limit_reply);
  VAPI_DBG("Assigned msg id %d to bridge_domain_set_default_learn_limit_reply", vapi_msg_id_bridge_domain_set_default_learn_limit_reply);
}

static inline void vapi_set_vapi_msg_bridge_domain_set_default_learn_limit_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bridge_domain_set_default_learn_limit_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bridge_domain_set_default_learn_limit_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bridge_domain_set_default_learn_limit
#define defined_vapi_msg_bridge_domain_set_default_learn_limit
typedef struct __attribute__ ((__packed__)) {
  u32 learn_limit; 
} vapi_payload_bridge_domain_set_default_learn_limit;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bridge_domain_set_default_learn_limit payload;
} vapi_msg_bridge_domain_set_default_learn_limit;

static inline void vapi_msg_bridge_domain_set_default_learn_limit_payload_hton(vapi_payload_bridge_domain_set_default_learn_limit *payload)
{
  payload->learn_limit = htobe32(payload->learn_limit);
}

static inline void vapi_msg_bridge_domain_set_default_learn_limit_payload_ntoh(vapi_payload_bridge_domain_set_default_learn_limit *payload)
{
  payload->learn_limit = be32toh(payload->learn_limit);
}

static inline void vapi_msg_bridge_domain_set_default_learn_limit_hton(vapi_msg_bridge_domain_set_default_learn_limit *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_set_default_learn_limit'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bridge_domain_set_default_learn_limit_payload_hton(&msg->payload);
}

static inline void vapi_msg_bridge_domain_set_default_learn_limit_ntoh(vapi_msg_bridge_domain_set_default_learn_limit *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_set_default_learn_limit'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bridge_domain_set_default_learn_limit_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bridge_domain_set_default_learn_limit_msg_size(vapi_msg_bridge_domain_set_default_learn_limit *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bridge_domain_set_default_learn_limit_msg_size(vapi_msg_bridge_domain_set_default_learn_limit *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bridge_domain_set_default_learn_limit) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_set_default_learn_limit' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bridge_domain_set_default_learn_limit));
      return -1;
    }
  if (vapi_calc_bridge_domain_set_default_learn_limit_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_set_default_learn_limit' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bridge_domain_set_default_learn_limit_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bridge_domain_set_default_learn_limit* vapi_alloc_bridge_domain_set_default_learn_limit(struct vapi_ctx_s *ctx)
{
  vapi_msg_bridge_domain_set_default_learn_limit *msg = NULL;
  const size_t size = sizeof(vapi_msg_bridge_domain_set_default_learn_limit);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bridge_domain_set_default_learn_limit*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bridge_domain_set_default_learn_limit);

  return msg;
}

static inline vapi_error_e vapi_bridge_domain_set_default_learn_limit(struct vapi_ctx_s *ctx,
  vapi_msg_bridge_domain_set_default_learn_limit *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bridge_domain_set_default_learn_limit_reply *reply),
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
  vapi_msg_bridge_domain_set_default_learn_limit_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bridge_domain_set_default_learn_limit_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bridge_domain_set_default_learn_limit_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bridge_domain_set_default_learn_limit()
{
  static const char name[] = "bridge_domain_set_default_learn_limit";
  static const char name_with_crc[] = "bridge_domain_set_default_learn_limit_f097ffce";
  static vapi_message_desc_t __vapi_metadata_bridge_domain_set_default_learn_limit = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bridge_domain_set_default_learn_limit, payload),
    (verify_msg_size_fn_t)vapi_verify_bridge_domain_set_default_learn_limit_msg_size,
    (generic_swap_fn_t)vapi_msg_bridge_domain_set_default_learn_limit_hton,
    (generic_swap_fn_t)vapi_msg_bridge_domain_set_default_learn_limit_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bridge_domain_set_default_learn_limit = vapi_register_msg(&__vapi_metadata_bridge_domain_set_default_learn_limit);
  VAPI_DBG("Assigned msg id %d to bridge_domain_set_default_learn_limit", vapi_msg_id_bridge_domain_set_default_learn_limit);
}
#endif

#ifndef defined_vapi_msg_bridge_domain_set_learn_limit_reply
#define defined_vapi_msg_bridge_domain_set_learn_limit_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bridge_domain_set_learn_limit_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bridge_domain_set_learn_limit_reply payload;
} vapi_msg_bridge_domain_set_learn_limit_reply;

static inline void vapi_msg_bridge_domain_set_learn_limit_reply_payload_hton(vapi_payload_bridge_domain_set_learn_limit_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bridge_domain_set_learn_limit_reply_payload_ntoh(vapi_payload_bridge_domain_set_learn_limit_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bridge_domain_set_learn_limit_reply_hton(vapi_msg_bridge_domain_set_learn_limit_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_set_learn_limit_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bridge_domain_set_learn_limit_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bridge_domain_set_learn_limit_reply_ntoh(vapi_msg_bridge_domain_set_learn_limit_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_set_learn_limit_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bridge_domain_set_learn_limit_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bridge_domain_set_learn_limit_reply_msg_size(vapi_msg_bridge_domain_set_learn_limit_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bridge_domain_set_learn_limit_reply_msg_size(vapi_msg_bridge_domain_set_learn_limit_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bridge_domain_set_learn_limit_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_set_learn_limit_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bridge_domain_set_learn_limit_reply));
      return -1;
    }
  if (vapi_calc_bridge_domain_set_learn_limit_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_set_learn_limit_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bridge_domain_set_learn_limit_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bridge_domain_set_learn_limit_reply()
{
  static const char name[] = "bridge_domain_set_learn_limit_reply";
  static const char name_with_crc[] = "bridge_domain_set_learn_limit_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bridge_domain_set_learn_limit_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bridge_domain_set_learn_limit_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bridge_domain_set_learn_limit_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bridge_domain_set_learn_limit_reply_hton,
    (generic_swap_fn_t)vapi_msg_bridge_domain_set_learn_limit_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bridge_domain_set_learn_limit_reply = vapi_register_msg(&__vapi_metadata_bridge_domain_set_learn_limit_reply);
  VAPI_DBG("Assigned msg id %d to bridge_domain_set_learn_limit_reply", vapi_msg_id_bridge_domain_set_learn_limit_reply);
}

static inline void vapi_set_vapi_msg_bridge_domain_set_learn_limit_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bridge_domain_set_learn_limit_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bridge_domain_set_learn_limit_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bridge_domain_set_learn_limit
#define defined_vapi_msg_bridge_domain_set_learn_limit
typedef struct __attribute__ ((__packed__)) {
  u32 bd_id;
  u32 learn_limit; 
} vapi_payload_bridge_domain_set_learn_limit;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bridge_domain_set_learn_limit payload;
} vapi_msg_bridge_domain_set_learn_limit;

static inline void vapi_msg_bridge_domain_set_learn_limit_payload_hton(vapi_payload_bridge_domain_set_learn_limit *payload)
{
  payload->bd_id = htobe32(payload->bd_id);
  payload->learn_limit = htobe32(payload->learn_limit);
}

static inline void vapi_msg_bridge_domain_set_learn_limit_payload_ntoh(vapi_payload_bridge_domain_set_learn_limit *payload)
{
  payload->bd_id = be32toh(payload->bd_id);
  payload->learn_limit = be32toh(payload->learn_limit);
}

static inline void vapi_msg_bridge_domain_set_learn_limit_hton(vapi_msg_bridge_domain_set_learn_limit *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_set_learn_limit'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bridge_domain_set_learn_limit_payload_hton(&msg->payload);
}

static inline void vapi_msg_bridge_domain_set_learn_limit_ntoh(vapi_msg_bridge_domain_set_learn_limit *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_set_learn_limit'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bridge_domain_set_learn_limit_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bridge_domain_set_learn_limit_msg_size(vapi_msg_bridge_domain_set_learn_limit *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bridge_domain_set_learn_limit_msg_size(vapi_msg_bridge_domain_set_learn_limit *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bridge_domain_set_learn_limit) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_set_learn_limit' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bridge_domain_set_learn_limit));
      return -1;
    }
  if (vapi_calc_bridge_domain_set_learn_limit_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_set_learn_limit' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bridge_domain_set_learn_limit_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bridge_domain_set_learn_limit* vapi_alloc_bridge_domain_set_learn_limit(struct vapi_ctx_s *ctx)
{
  vapi_msg_bridge_domain_set_learn_limit *msg = NULL;
  const size_t size = sizeof(vapi_msg_bridge_domain_set_learn_limit);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bridge_domain_set_learn_limit*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bridge_domain_set_learn_limit);

  return msg;
}

static inline vapi_error_e vapi_bridge_domain_set_learn_limit(struct vapi_ctx_s *ctx,
  vapi_msg_bridge_domain_set_learn_limit *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bridge_domain_set_learn_limit_reply *reply),
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
  vapi_msg_bridge_domain_set_learn_limit_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bridge_domain_set_learn_limit_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bridge_domain_set_learn_limit_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bridge_domain_set_learn_limit()
{
  static const char name[] = "bridge_domain_set_learn_limit";
  static const char name_with_crc[] = "bridge_domain_set_learn_limit_89c52b5f";
  static vapi_message_desc_t __vapi_metadata_bridge_domain_set_learn_limit = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bridge_domain_set_learn_limit, payload),
    (verify_msg_size_fn_t)vapi_verify_bridge_domain_set_learn_limit_msg_size,
    (generic_swap_fn_t)vapi_msg_bridge_domain_set_learn_limit_hton,
    (generic_swap_fn_t)vapi_msg_bridge_domain_set_learn_limit_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bridge_domain_set_learn_limit = vapi_register_msg(&__vapi_metadata_bridge_domain_set_learn_limit);
  VAPI_DBG("Assigned msg id %d to bridge_domain_set_learn_limit", vapi_msg_id_bridge_domain_set_learn_limit);
}
#endif

#ifndef defined_vapi_msg_bridge_domain_add_del_reply
#define defined_vapi_msg_bridge_domain_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bridge_domain_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bridge_domain_add_del_reply payload;
} vapi_msg_bridge_domain_add_del_reply;

static inline void vapi_msg_bridge_domain_add_del_reply_payload_hton(vapi_payload_bridge_domain_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bridge_domain_add_del_reply_payload_ntoh(vapi_payload_bridge_domain_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bridge_domain_add_del_reply_hton(vapi_msg_bridge_domain_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bridge_domain_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bridge_domain_add_del_reply_ntoh(vapi_msg_bridge_domain_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bridge_domain_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bridge_domain_add_del_reply_msg_size(vapi_msg_bridge_domain_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bridge_domain_add_del_reply_msg_size(vapi_msg_bridge_domain_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bridge_domain_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bridge_domain_add_del_reply));
      return -1;
    }
  if (vapi_calc_bridge_domain_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bridge_domain_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bridge_domain_add_del_reply()
{
  static const char name[] = "bridge_domain_add_del_reply";
  static const char name_with_crc[] = "bridge_domain_add_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bridge_domain_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bridge_domain_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bridge_domain_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bridge_domain_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_bridge_domain_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bridge_domain_add_del_reply = vapi_register_msg(&__vapi_metadata_bridge_domain_add_del_reply);
  VAPI_DBG("Assigned msg id %d to bridge_domain_add_del_reply", vapi_msg_id_bridge_domain_add_del_reply);
}

static inline void vapi_set_vapi_msg_bridge_domain_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bridge_domain_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bridge_domain_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bridge_domain_add_del
#define defined_vapi_msg_bridge_domain_add_del
typedef struct __attribute__ ((__packed__)) {
  u32 bd_id;
  bool flood;
  bool uu_flood;
  bool forward;
  bool learn;
  bool arp_term;
  bool arp_ufwd;
  u8 mac_age;
  u8 bd_tag[64];
  bool is_add; 
} vapi_payload_bridge_domain_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bridge_domain_add_del payload;
} vapi_msg_bridge_domain_add_del;

static inline void vapi_msg_bridge_domain_add_del_payload_hton(vapi_payload_bridge_domain_add_del *payload)
{
  payload->bd_id = htobe32(payload->bd_id);
}

static inline void vapi_msg_bridge_domain_add_del_payload_ntoh(vapi_payload_bridge_domain_add_del *payload)
{
  payload->bd_id = be32toh(payload->bd_id);
}

static inline void vapi_msg_bridge_domain_add_del_hton(vapi_msg_bridge_domain_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bridge_domain_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_bridge_domain_add_del_ntoh(vapi_msg_bridge_domain_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bridge_domain_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bridge_domain_add_del_msg_size(vapi_msg_bridge_domain_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bridge_domain_add_del_msg_size(vapi_msg_bridge_domain_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bridge_domain_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bridge_domain_add_del));
      return -1;
    }
  if (vapi_calc_bridge_domain_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bridge_domain_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bridge_domain_add_del* vapi_alloc_bridge_domain_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_bridge_domain_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_bridge_domain_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bridge_domain_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bridge_domain_add_del);

  return msg;
}

static inline vapi_error_e vapi_bridge_domain_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_bridge_domain_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bridge_domain_add_del_reply *reply),
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
  vapi_msg_bridge_domain_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bridge_domain_add_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bridge_domain_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bridge_domain_add_del()
{
  static const char name[] = "bridge_domain_add_del";
  static const char name_with_crc[] = "bridge_domain_add_del_600b7170";
  static vapi_message_desc_t __vapi_metadata_bridge_domain_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bridge_domain_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_bridge_domain_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_bridge_domain_add_del_hton,
    (generic_swap_fn_t)vapi_msg_bridge_domain_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bridge_domain_add_del = vapi_register_msg(&__vapi_metadata_bridge_domain_add_del);
  VAPI_DBG("Assigned msg id %d to bridge_domain_add_del", vapi_msg_id_bridge_domain_add_del);
}
#endif

#ifndef defined_vapi_msg_bridge_domain_add_del_v2_reply
#define defined_vapi_msg_bridge_domain_add_del_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 bd_id; 
} vapi_payload_bridge_domain_add_del_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bridge_domain_add_del_v2_reply payload;
} vapi_msg_bridge_domain_add_del_v2_reply;

static inline void vapi_msg_bridge_domain_add_del_v2_reply_payload_hton(vapi_payload_bridge_domain_add_del_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->bd_id = htobe32(payload->bd_id);
}

static inline void vapi_msg_bridge_domain_add_del_v2_reply_payload_ntoh(vapi_payload_bridge_domain_add_del_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->bd_id = be32toh(payload->bd_id);
}

static inline void vapi_msg_bridge_domain_add_del_v2_reply_hton(vapi_msg_bridge_domain_add_del_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_add_del_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bridge_domain_add_del_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bridge_domain_add_del_v2_reply_ntoh(vapi_msg_bridge_domain_add_del_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_add_del_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bridge_domain_add_del_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bridge_domain_add_del_v2_reply_msg_size(vapi_msg_bridge_domain_add_del_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bridge_domain_add_del_v2_reply_msg_size(vapi_msg_bridge_domain_add_del_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bridge_domain_add_del_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_add_del_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bridge_domain_add_del_v2_reply));
      return -1;
    }
  if (vapi_calc_bridge_domain_add_del_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_add_del_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bridge_domain_add_del_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bridge_domain_add_del_v2_reply()
{
  static const char name[] = "bridge_domain_add_del_v2_reply";
  static const char name_with_crc[] = "bridge_domain_add_del_v2_reply_fcb1e980";
  static vapi_message_desc_t __vapi_metadata_bridge_domain_add_del_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bridge_domain_add_del_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bridge_domain_add_del_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bridge_domain_add_del_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_bridge_domain_add_del_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bridge_domain_add_del_v2_reply = vapi_register_msg(&__vapi_metadata_bridge_domain_add_del_v2_reply);
  VAPI_DBG("Assigned msg id %d to bridge_domain_add_del_v2_reply", vapi_msg_id_bridge_domain_add_del_v2_reply);
}

static inline void vapi_set_vapi_msg_bridge_domain_add_del_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bridge_domain_add_del_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bridge_domain_add_del_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bridge_domain_add_del_v2
#define defined_vapi_msg_bridge_domain_add_del_v2
typedef struct __attribute__ ((__packed__)) {
  u32 bd_id;
  bool flood;
  bool uu_flood;
  bool forward;
  bool learn;
  bool arp_term;
  bool arp_ufwd;
  u8 mac_age;
  u8 bd_tag[64];
  bool is_add; 
} vapi_payload_bridge_domain_add_del_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bridge_domain_add_del_v2 payload;
} vapi_msg_bridge_domain_add_del_v2;

static inline void vapi_msg_bridge_domain_add_del_v2_payload_hton(vapi_payload_bridge_domain_add_del_v2 *payload)
{
  payload->bd_id = htobe32(payload->bd_id);
}

static inline void vapi_msg_bridge_domain_add_del_v2_payload_ntoh(vapi_payload_bridge_domain_add_del_v2 *payload)
{
  payload->bd_id = be32toh(payload->bd_id);
}

static inline void vapi_msg_bridge_domain_add_del_v2_hton(vapi_msg_bridge_domain_add_del_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_add_del_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bridge_domain_add_del_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_bridge_domain_add_del_v2_ntoh(vapi_msg_bridge_domain_add_del_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_add_del_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bridge_domain_add_del_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bridge_domain_add_del_v2_msg_size(vapi_msg_bridge_domain_add_del_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bridge_domain_add_del_v2_msg_size(vapi_msg_bridge_domain_add_del_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bridge_domain_add_del_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_add_del_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bridge_domain_add_del_v2));
      return -1;
    }
  if (vapi_calc_bridge_domain_add_del_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_add_del_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bridge_domain_add_del_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bridge_domain_add_del_v2* vapi_alloc_bridge_domain_add_del_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_bridge_domain_add_del_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_bridge_domain_add_del_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bridge_domain_add_del_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bridge_domain_add_del_v2);

  return msg;
}

static inline vapi_error_e vapi_bridge_domain_add_del_v2(struct vapi_ctx_s *ctx,
  vapi_msg_bridge_domain_add_del_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bridge_domain_add_del_v2_reply *reply),
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
  vapi_msg_bridge_domain_add_del_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bridge_domain_add_del_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bridge_domain_add_del_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bridge_domain_add_del_v2()
{
  static const char name[] = "bridge_domain_add_del_v2";
  static const char name_with_crc[] = "bridge_domain_add_del_v2_600b7170";
  static vapi_message_desc_t __vapi_metadata_bridge_domain_add_del_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bridge_domain_add_del_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_bridge_domain_add_del_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_bridge_domain_add_del_v2_hton,
    (generic_swap_fn_t)vapi_msg_bridge_domain_add_del_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bridge_domain_add_del_v2 = vapi_register_msg(&__vapi_metadata_bridge_domain_add_del_v2);
  VAPI_DBG("Assigned msg id %d to bridge_domain_add_del_v2", vapi_msg_id_bridge_domain_add_del_v2);
}
#endif

#ifndef defined_vapi_msg_bridge_domain_details
#define defined_vapi_msg_bridge_domain_details
typedef struct __attribute__ ((__packed__)) {
  u32 bd_id;
  bool flood;
  bool uu_flood;
  bool forward;
  bool learn;
  bool arp_term;
  bool arp_ufwd;
  u8 mac_age;
  u8 bd_tag[64];
  vapi_type_interface_index bvi_sw_if_index;
  vapi_type_interface_index uu_fwd_sw_if_index;
  u32 n_sw_ifs;
  vapi_type_bridge_domain_sw_if sw_if_details[0]; 
} vapi_payload_bridge_domain_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bridge_domain_details payload;
} vapi_msg_bridge_domain_details;

static inline void vapi_msg_bridge_domain_details_payload_hton(vapi_payload_bridge_domain_details *payload)
{
  payload->bd_id = htobe32(payload->bd_id);
  payload->bvi_sw_if_index = htobe32(payload->bvi_sw_if_index);
  payload->uu_fwd_sw_if_index = htobe32(payload->uu_fwd_sw_if_index);
  payload->n_sw_ifs = htobe32(payload->n_sw_ifs);
  do { unsigned i; for (i = 0; i < be32toh(payload->n_sw_ifs); ++i) { vapi_type_bridge_domain_sw_if_hton(&payload->sw_if_details[i]); } } while(0);
}

static inline void vapi_msg_bridge_domain_details_payload_ntoh(vapi_payload_bridge_domain_details *payload)
{
  payload->bd_id = be32toh(payload->bd_id);
  payload->bvi_sw_if_index = be32toh(payload->bvi_sw_if_index);
  payload->uu_fwd_sw_if_index = be32toh(payload->uu_fwd_sw_if_index);
  payload->n_sw_ifs = be32toh(payload->n_sw_ifs);
  do { unsigned i; for (i = 0; i < payload->n_sw_ifs; ++i) { vapi_type_bridge_domain_sw_if_ntoh(&payload->sw_if_details[i]); } } while(0);
}

static inline void vapi_msg_bridge_domain_details_hton(vapi_msg_bridge_domain_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bridge_domain_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_bridge_domain_details_ntoh(vapi_msg_bridge_domain_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bridge_domain_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bridge_domain_details_msg_size(vapi_msg_bridge_domain_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.sw_if_details[0]) * msg->payload.n_sw_ifs;
}

static inline int vapi_verify_bridge_domain_details_msg_size(vapi_msg_bridge_domain_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bridge_domain_details) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bridge_domain_details));
      return -1;
    }
  if (vapi_calc_bridge_domain_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bridge_domain_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bridge_domain_details()
{
  static const char name[] = "bridge_domain_details";
  static const char name_with_crc[] = "bridge_domain_details_0fa506fd";
  static vapi_message_desc_t __vapi_metadata_bridge_domain_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bridge_domain_details, payload),
    (verify_msg_size_fn_t)vapi_verify_bridge_domain_details_msg_size,
    (generic_swap_fn_t)vapi_msg_bridge_domain_details_hton,
    (generic_swap_fn_t)vapi_msg_bridge_domain_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bridge_domain_details = vapi_register_msg(&__vapi_metadata_bridge_domain_details);
  VAPI_DBG("Assigned msg id %d to bridge_domain_details", vapi_msg_id_bridge_domain_details);
}

static inline void vapi_set_vapi_msg_bridge_domain_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bridge_domain_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bridge_domain_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bridge_domain_dump
#define defined_vapi_msg_bridge_domain_dump
typedef struct __attribute__ ((__packed__)) {
  u32 bd_id;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_bridge_domain_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bridge_domain_dump payload;
} vapi_msg_bridge_domain_dump;

static inline void vapi_msg_bridge_domain_dump_payload_hton(vapi_payload_bridge_domain_dump *payload)
{
  payload->bd_id = htobe32(payload->bd_id);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_bridge_domain_dump_payload_ntoh(vapi_payload_bridge_domain_dump *payload)
{
  payload->bd_id = be32toh(payload->bd_id);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_bridge_domain_dump_hton(vapi_msg_bridge_domain_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bridge_domain_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_bridge_domain_dump_ntoh(vapi_msg_bridge_domain_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_domain_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bridge_domain_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bridge_domain_dump_msg_size(vapi_msg_bridge_domain_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bridge_domain_dump_msg_size(vapi_msg_bridge_domain_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bridge_domain_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bridge_domain_dump));
      return -1;
    }
  if (vapi_calc_bridge_domain_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_domain_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bridge_domain_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bridge_domain_dump* vapi_alloc_bridge_domain_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_bridge_domain_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_bridge_domain_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bridge_domain_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bridge_domain_dump);

  return msg;
}

static inline vapi_error_e vapi_bridge_domain_dump(struct vapi_ctx_s *ctx,
  vapi_msg_bridge_domain_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bridge_domain_details *reply),
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
  vapi_msg_bridge_domain_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bridge_domain_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_bridge_domain_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bridge_domain_dump()
{
  static const char name[] = "bridge_domain_dump";
  static const char name_with_crc[] = "bridge_domain_dump_74396a43";
  static vapi_message_desc_t __vapi_metadata_bridge_domain_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bridge_domain_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_bridge_domain_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_bridge_domain_dump_hton,
    (generic_swap_fn_t)vapi_msg_bridge_domain_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bridge_domain_dump = vapi_register_msg(&__vapi_metadata_bridge_domain_dump);
  VAPI_DBG("Assigned msg id %d to bridge_domain_dump", vapi_msg_id_bridge_domain_dump);
}
#endif

#ifndef defined_vapi_msg_bridge_flags_reply
#define defined_vapi_msg_bridge_flags_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 resulting_feature_bitmap; 
} vapi_payload_bridge_flags_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bridge_flags_reply payload;
} vapi_msg_bridge_flags_reply;

static inline void vapi_msg_bridge_flags_reply_payload_hton(vapi_payload_bridge_flags_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->resulting_feature_bitmap = htobe32(payload->resulting_feature_bitmap);
}

static inline void vapi_msg_bridge_flags_reply_payload_ntoh(vapi_payload_bridge_flags_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->resulting_feature_bitmap = be32toh(payload->resulting_feature_bitmap);
}

static inline void vapi_msg_bridge_flags_reply_hton(vapi_msg_bridge_flags_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_flags_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bridge_flags_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bridge_flags_reply_ntoh(vapi_msg_bridge_flags_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_flags_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bridge_flags_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bridge_flags_reply_msg_size(vapi_msg_bridge_flags_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bridge_flags_reply_msg_size(vapi_msg_bridge_flags_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bridge_flags_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_flags_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bridge_flags_reply));
      return -1;
    }
  if (vapi_calc_bridge_flags_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_flags_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bridge_flags_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bridge_flags_reply()
{
  static const char name[] = "bridge_flags_reply";
  static const char name_with_crc[] = "bridge_flags_reply_29b2a2b3";
  static vapi_message_desc_t __vapi_metadata_bridge_flags_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bridge_flags_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bridge_flags_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bridge_flags_reply_hton,
    (generic_swap_fn_t)vapi_msg_bridge_flags_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bridge_flags_reply = vapi_register_msg(&__vapi_metadata_bridge_flags_reply);
  VAPI_DBG("Assigned msg id %d to bridge_flags_reply", vapi_msg_id_bridge_flags_reply);
}

static inline void vapi_set_vapi_msg_bridge_flags_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bridge_flags_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bridge_flags_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bridge_flags
#define defined_vapi_msg_bridge_flags
typedef struct __attribute__ ((__packed__)) {
  u32 bd_id;
  bool is_set;
  vapi_enum_bd_flags flags; 
} vapi_payload_bridge_flags;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bridge_flags payload;
} vapi_msg_bridge_flags;

static inline void vapi_msg_bridge_flags_payload_hton(vapi_payload_bridge_flags *payload)
{
  payload->bd_id = htobe32(payload->bd_id);
  payload->flags = (vapi_enum_bd_flags)htobe32(payload->flags);
}

static inline void vapi_msg_bridge_flags_payload_ntoh(vapi_payload_bridge_flags *payload)
{
  payload->bd_id = be32toh(payload->bd_id);
  payload->flags = (vapi_enum_bd_flags)be32toh(payload->flags);
}

static inline void vapi_msg_bridge_flags_hton(vapi_msg_bridge_flags *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_flags'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bridge_flags_payload_hton(&msg->payload);
}

static inline void vapi_msg_bridge_flags_ntoh(vapi_msg_bridge_flags *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bridge_flags'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bridge_flags_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bridge_flags_msg_size(vapi_msg_bridge_flags *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bridge_flags_msg_size(vapi_msg_bridge_flags *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bridge_flags) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_flags' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bridge_flags));
      return -1;
    }
  if (vapi_calc_bridge_flags_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bridge_flags' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bridge_flags_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bridge_flags* vapi_alloc_bridge_flags(struct vapi_ctx_s *ctx)
{
  vapi_msg_bridge_flags *msg = NULL;
  const size_t size = sizeof(vapi_msg_bridge_flags);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bridge_flags*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bridge_flags);

  return msg;
}

static inline vapi_error_e vapi_bridge_flags(struct vapi_ctx_s *ctx,
  vapi_msg_bridge_flags *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bridge_flags_reply *reply),
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
  vapi_msg_bridge_flags_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bridge_flags_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bridge_flags_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bridge_flags()
{
  static const char name[] = "bridge_flags";
  static const char name_with_crc[] = "bridge_flags_1b0c5fbd";
  static vapi_message_desc_t __vapi_metadata_bridge_flags = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bridge_flags, payload),
    (verify_msg_size_fn_t)vapi_verify_bridge_flags_msg_size,
    (generic_swap_fn_t)vapi_msg_bridge_flags_hton,
    (generic_swap_fn_t)vapi_msg_bridge_flags_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bridge_flags = vapi_register_msg(&__vapi_metadata_bridge_flags);
  VAPI_DBG("Assigned msg id %d to bridge_flags", vapi_msg_id_bridge_flags);
}
#endif

#ifndef defined_vapi_msg_l2_interface_vlan_tag_rewrite_reply
#define defined_vapi_msg_l2_interface_vlan_tag_rewrite_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_l2_interface_vlan_tag_rewrite_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_l2_interface_vlan_tag_rewrite_reply payload;
} vapi_msg_l2_interface_vlan_tag_rewrite_reply;

static inline void vapi_msg_l2_interface_vlan_tag_rewrite_reply_payload_hton(vapi_payload_l2_interface_vlan_tag_rewrite_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_l2_interface_vlan_tag_rewrite_reply_payload_ntoh(vapi_payload_l2_interface_vlan_tag_rewrite_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_l2_interface_vlan_tag_rewrite_reply_hton(vapi_msg_l2_interface_vlan_tag_rewrite_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_interface_vlan_tag_rewrite_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_l2_interface_vlan_tag_rewrite_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2_interface_vlan_tag_rewrite_reply_ntoh(vapi_msg_l2_interface_vlan_tag_rewrite_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_interface_vlan_tag_rewrite_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_l2_interface_vlan_tag_rewrite_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2_interface_vlan_tag_rewrite_reply_msg_size(vapi_msg_l2_interface_vlan_tag_rewrite_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2_interface_vlan_tag_rewrite_reply_msg_size(vapi_msg_l2_interface_vlan_tag_rewrite_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2_interface_vlan_tag_rewrite_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_interface_vlan_tag_rewrite_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2_interface_vlan_tag_rewrite_reply));
      return -1;
    }
  if (vapi_calc_l2_interface_vlan_tag_rewrite_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_interface_vlan_tag_rewrite_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2_interface_vlan_tag_rewrite_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_l2_interface_vlan_tag_rewrite_reply()
{
  static const char name[] = "l2_interface_vlan_tag_rewrite_reply";
  static const char name_with_crc[] = "l2_interface_vlan_tag_rewrite_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_l2_interface_vlan_tag_rewrite_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_l2_interface_vlan_tag_rewrite_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_l2_interface_vlan_tag_rewrite_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_l2_interface_vlan_tag_rewrite_reply_hton,
    (generic_swap_fn_t)vapi_msg_l2_interface_vlan_tag_rewrite_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2_interface_vlan_tag_rewrite_reply = vapi_register_msg(&__vapi_metadata_l2_interface_vlan_tag_rewrite_reply);
  VAPI_DBG("Assigned msg id %d to l2_interface_vlan_tag_rewrite_reply", vapi_msg_id_l2_interface_vlan_tag_rewrite_reply);
}

static inline void vapi_set_vapi_msg_l2_interface_vlan_tag_rewrite_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_l2_interface_vlan_tag_rewrite_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_l2_interface_vlan_tag_rewrite_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_l2_interface_vlan_tag_rewrite
#define defined_vapi_msg_l2_interface_vlan_tag_rewrite
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u32 vtr_op;
  u32 push_dot1q;
  u32 tag1;
  u32 tag2; 
} vapi_payload_l2_interface_vlan_tag_rewrite;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_l2_interface_vlan_tag_rewrite payload;
} vapi_msg_l2_interface_vlan_tag_rewrite;

static inline void vapi_msg_l2_interface_vlan_tag_rewrite_payload_hton(vapi_payload_l2_interface_vlan_tag_rewrite *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->vtr_op = htobe32(payload->vtr_op);
  payload->push_dot1q = htobe32(payload->push_dot1q);
  payload->tag1 = htobe32(payload->tag1);
  payload->tag2 = htobe32(payload->tag2);
}

static inline void vapi_msg_l2_interface_vlan_tag_rewrite_payload_ntoh(vapi_payload_l2_interface_vlan_tag_rewrite *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->vtr_op = be32toh(payload->vtr_op);
  payload->push_dot1q = be32toh(payload->push_dot1q);
  payload->tag1 = be32toh(payload->tag1);
  payload->tag2 = be32toh(payload->tag2);
}

static inline void vapi_msg_l2_interface_vlan_tag_rewrite_hton(vapi_msg_l2_interface_vlan_tag_rewrite *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_interface_vlan_tag_rewrite'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_l2_interface_vlan_tag_rewrite_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2_interface_vlan_tag_rewrite_ntoh(vapi_msg_l2_interface_vlan_tag_rewrite *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_interface_vlan_tag_rewrite'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_l2_interface_vlan_tag_rewrite_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2_interface_vlan_tag_rewrite_msg_size(vapi_msg_l2_interface_vlan_tag_rewrite *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2_interface_vlan_tag_rewrite_msg_size(vapi_msg_l2_interface_vlan_tag_rewrite *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2_interface_vlan_tag_rewrite) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_interface_vlan_tag_rewrite' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2_interface_vlan_tag_rewrite));
      return -1;
    }
  if (vapi_calc_l2_interface_vlan_tag_rewrite_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_interface_vlan_tag_rewrite' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2_interface_vlan_tag_rewrite_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_l2_interface_vlan_tag_rewrite* vapi_alloc_l2_interface_vlan_tag_rewrite(struct vapi_ctx_s *ctx)
{
  vapi_msg_l2_interface_vlan_tag_rewrite *msg = NULL;
  const size_t size = sizeof(vapi_msg_l2_interface_vlan_tag_rewrite);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_l2_interface_vlan_tag_rewrite*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_l2_interface_vlan_tag_rewrite);

  return msg;
}

static inline vapi_error_e vapi_l2_interface_vlan_tag_rewrite(struct vapi_ctx_s *ctx,
  vapi_msg_l2_interface_vlan_tag_rewrite *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_l2_interface_vlan_tag_rewrite_reply *reply),
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
  vapi_msg_l2_interface_vlan_tag_rewrite_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_l2_interface_vlan_tag_rewrite_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_l2_interface_vlan_tag_rewrite_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_l2_interface_vlan_tag_rewrite()
{
  static const char name[] = "l2_interface_vlan_tag_rewrite";
  static const char name_with_crc[] = "l2_interface_vlan_tag_rewrite_62cc0bbc";
  static vapi_message_desc_t __vapi_metadata_l2_interface_vlan_tag_rewrite = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_l2_interface_vlan_tag_rewrite, payload),
    (verify_msg_size_fn_t)vapi_verify_l2_interface_vlan_tag_rewrite_msg_size,
    (generic_swap_fn_t)vapi_msg_l2_interface_vlan_tag_rewrite_hton,
    (generic_swap_fn_t)vapi_msg_l2_interface_vlan_tag_rewrite_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2_interface_vlan_tag_rewrite = vapi_register_msg(&__vapi_metadata_l2_interface_vlan_tag_rewrite);
  VAPI_DBG("Assigned msg id %d to l2_interface_vlan_tag_rewrite", vapi_msg_id_l2_interface_vlan_tag_rewrite);
}
#endif

#ifndef defined_vapi_msg_l2_interface_pbb_tag_rewrite_reply
#define defined_vapi_msg_l2_interface_pbb_tag_rewrite_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_l2_interface_pbb_tag_rewrite_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_l2_interface_pbb_tag_rewrite_reply payload;
} vapi_msg_l2_interface_pbb_tag_rewrite_reply;

static inline void vapi_msg_l2_interface_pbb_tag_rewrite_reply_payload_hton(vapi_payload_l2_interface_pbb_tag_rewrite_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_l2_interface_pbb_tag_rewrite_reply_payload_ntoh(vapi_payload_l2_interface_pbb_tag_rewrite_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_l2_interface_pbb_tag_rewrite_reply_hton(vapi_msg_l2_interface_pbb_tag_rewrite_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_interface_pbb_tag_rewrite_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_l2_interface_pbb_tag_rewrite_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2_interface_pbb_tag_rewrite_reply_ntoh(vapi_msg_l2_interface_pbb_tag_rewrite_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_interface_pbb_tag_rewrite_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_l2_interface_pbb_tag_rewrite_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2_interface_pbb_tag_rewrite_reply_msg_size(vapi_msg_l2_interface_pbb_tag_rewrite_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2_interface_pbb_tag_rewrite_reply_msg_size(vapi_msg_l2_interface_pbb_tag_rewrite_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2_interface_pbb_tag_rewrite_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_interface_pbb_tag_rewrite_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2_interface_pbb_tag_rewrite_reply));
      return -1;
    }
  if (vapi_calc_l2_interface_pbb_tag_rewrite_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_interface_pbb_tag_rewrite_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2_interface_pbb_tag_rewrite_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_l2_interface_pbb_tag_rewrite_reply()
{
  static const char name[] = "l2_interface_pbb_tag_rewrite_reply";
  static const char name_with_crc[] = "l2_interface_pbb_tag_rewrite_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_l2_interface_pbb_tag_rewrite_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_l2_interface_pbb_tag_rewrite_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_l2_interface_pbb_tag_rewrite_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_l2_interface_pbb_tag_rewrite_reply_hton,
    (generic_swap_fn_t)vapi_msg_l2_interface_pbb_tag_rewrite_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2_interface_pbb_tag_rewrite_reply = vapi_register_msg(&__vapi_metadata_l2_interface_pbb_tag_rewrite_reply);
  VAPI_DBG("Assigned msg id %d to l2_interface_pbb_tag_rewrite_reply", vapi_msg_id_l2_interface_pbb_tag_rewrite_reply);
}

static inline void vapi_set_vapi_msg_l2_interface_pbb_tag_rewrite_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_l2_interface_pbb_tag_rewrite_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_l2_interface_pbb_tag_rewrite_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_l2_interface_pbb_tag_rewrite
#define defined_vapi_msg_l2_interface_pbb_tag_rewrite
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u32 vtr_op;
  u16 outer_tag;
  vapi_type_mac_address b_dmac;
  vapi_type_mac_address b_smac;
  u16 b_vlanid;
  u32 i_sid; 
} vapi_payload_l2_interface_pbb_tag_rewrite;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_l2_interface_pbb_tag_rewrite payload;
} vapi_msg_l2_interface_pbb_tag_rewrite;

static inline void vapi_msg_l2_interface_pbb_tag_rewrite_payload_hton(vapi_payload_l2_interface_pbb_tag_rewrite *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->vtr_op = htobe32(payload->vtr_op);
  payload->outer_tag = htobe16(payload->outer_tag);
  payload->b_vlanid = htobe16(payload->b_vlanid);
  payload->i_sid = htobe32(payload->i_sid);
}

static inline void vapi_msg_l2_interface_pbb_tag_rewrite_payload_ntoh(vapi_payload_l2_interface_pbb_tag_rewrite *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->vtr_op = be32toh(payload->vtr_op);
  payload->outer_tag = be16toh(payload->outer_tag);
  payload->b_vlanid = be16toh(payload->b_vlanid);
  payload->i_sid = be32toh(payload->i_sid);
}

static inline void vapi_msg_l2_interface_pbb_tag_rewrite_hton(vapi_msg_l2_interface_pbb_tag_rewrite *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_interface_pbb_tag_rewrite'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_l2_interface_pbb_tag_rewrite_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2_interface_pbb_tag_rewrite_ntoh(vapi_msg_l2_interface_pbb_tag_rewrite *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_interface_pbb_tag_rewrite'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_l2_interface_pbb_tag_rewrite_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2_interface_pbb_tag_rewrite_msg_size(vapi_msg_l2_interface_pbb_tag_rewrite *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2_interface_pbb_tag_rewrite_msg_size(vapi_msg_l2_interface_pbb_tag_rewrite *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2_interface_pbb_tag_rewrite) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_interface_pbb_tag_rewrite' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2_interface_pbb_tag_rewrite));
      return -1;
    }
  if (vapi_calc_l2_interface_pbb_tag_rewrite_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_interface_pbb_tag_rewrite' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2_interface_pbb_tag_rewrite_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_l2_interface_pbb_tag_rewrite* vapi_alloc_l2_interface_pbb_tag_rewrite(struct vapi_ctx_s *ctx)
{
  vapi_msg_l2_interface_pbb_tag_rewrite *msg = NULL;
  const size_t size = sizeof(vapi_msg_l2_interface_pbb_tag_rewrite);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_l2_interface_pbb_tag_rewrite*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_l2_interface_pbb_tag_rewrite);

  return msg;
}

static inline vapi_error_e vapi_l2_interface_pbb_tag_rewrite(struct vapi_ctx_s *ctx,
  vapi_msg_l2_interface_pbb_tag_rewrite *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_l2_interface_pbb_tag_rewrite_reply *reply),
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
  vapi_msg_l2_interface_pbb_tag_rewrite_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_l2_interface_pbb_tag_rewrite_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_l2_interface_pbb_tag_rewrite_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_l2_interface_pbb_tag_rewrite()
{
  static const char name[] = "l2_interface_pbb_tag_rewrite";
  static const char name_with_crc[] = "l2_interface_pbb_tag_rewrite_38e802a8";
  static vapi_message_desc_t __vapi_metadata_l2_interface_pbb_tag_rewrite = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_l2_interface_pbb_tag_rewrite, payload),
    (verify_msg_size_fn_t)vapi_verify_l2_interface_pbb_tag_rewrite_msg_size,
    (generic_swap_fn_t)vapi_msg_l2_interface_pbb_tag_rewrite_hton,
    (generic_swap_fn_t)vapi_msg_l2_interface_pbb_tag_rewrite_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2_interface_pbb_tag_rewrite = vapi_register_msg(&__vapi_metadata_l2_interface_pbb_tag_rewrite);
  VAPI_DBG("Assigned msg id %d to l2_interface_pbb_tag_rewrite", vapi_msg_id_l2_interface_pbb_tag_rewrite);
}
#endif

#ifndef defined_vapi_msg_l2_patch_add_del_reply
#define defined_vapi_msg_l2_patch_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_l2_patch_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_l2_patch_add_del_reply payload;
} vapi_msg_l2_patch_add_del_reply;

static inline void vapi_msg_l2_patch_add_del_reply_payload_hton(vapi_payload_l2_patch_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_l2_patch_add_del_reply_payload_ntoh(vapi_payload_l2_patch_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_l2_patch_add_del_reply_hton(vapi_msg_l2_patch_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_patch_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_l2_patch_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2_patch_add_del_reply_ntoh(vapi_msg_l2_patch_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_patch_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_l2_patch_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2_patch_add_del_reply_msg_size(vapi_msg_l2_patch_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2_patch_add_del_reply_msg_size(vapi_msg_l2_patch_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2_patch_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_patch_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2_patch_add_del_reply));
      return -1;
    }
  if (vapi_calc_l2_patch_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_patch_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2_patch_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_l2_patch_add_del_reply()
{
  static const char name[] = "l2_patch_add_del_reply";
  static const char name_with_crc[] = "l2_patch_add_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_l2_patch_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_l2_patch_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_l2_patch_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_l2_patch_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_l2_patch_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2_patch_add_del_reply = vapi_register_msg(&__vapi_metadata_l2_patch_add_del_reply);
  VAPI_DBG("Assigned msg id %d to l2_patch_add_del_reply", vapi_msg_id_l2_patch_add_del_reply);
}

static inline void vapi_set_vapi_msg_l2_patch_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_l2_patch_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_l2_patch_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_l2_patch_add_del
#define defined_vapi_msg_l2_patch_add_del
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index rx_sw_if_index;
  vapi_type_interface_index tx_sw_if_index;
  bool is_add; 
} vapi_payload_l2_patch_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_l2_patch_add_del payload;
} vapi_msg_l2_patch_add_del;

static inline void vapi_msg_l2_patch_add_del_payload_hton(vapi_payload_l2_patch_add_del *payload)
{
  payload->rx_sw_if_index = htobe32(payload->rx_sw_if_index);
  payload->tx_sw_if_index = htobe32(payload->tx_sw_if_index);
}

static inline void vapi_msg_l2_patch_add_del_payload_ntoh(vapi_payload_l2_patch_add_del *payload)
{
  payload->rx_sw_if_index = be32toh(payload->rx_sw_if_index);
  payload->tx_sw_if_index = be32toh(payload->tx_sw_if_index);
}

static inline void vapi_msg_l2_patch_add_del_hton(vapi_msg_l2_patch_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_patch_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_l2_patch_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2_patch_add_del_ntoh(vapi_msg_l2_patch_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_patch_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_l2_patch_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2_patch_add_del_msg_size(vapi_msg_l2_patch_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2_patch_add_del_msg_size(vapi_msg_l2_patch_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2_patch_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_patch_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2_patch_add_del));
      return -1;
    }
  if (vapi_calc_l2_patch_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_patch_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2_patch_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_l2_patch_add_del* vapi_alloc_l2_patch_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_l2_patch_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_l2_patch_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_l2_patch_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_l2_patch_add_del);

  return msg;
}

static inline vapi_error_e vapi_l2_patch_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_l2_patch_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_l2_patch_add_del_reply *reply),
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
  vapi_msg_l2_patch_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_l2_patch_add_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_l2_patch_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_l2_patch_add_del()
{
  static const char name[] = "l2_patch_add_del";
  static const char name_with_crc[] = "l2_patch_add_del_a1f6a6f3";
  static vapi_message_desc_t __vapi_metadata_l2_patch_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_l2_patch_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_l2_patch_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_l2_patch_add_del_hton,
    (generic_swap_fn_t)vapi_msg_l2_patch_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2_patch_add_del = vapi_register_msg(&__vapi_metadata_l2_patch_add_del);
  VAPI_DBG("Assigned msg id %d to l2_patch_add_del", vapi_msg_id_l2_patch_add_del);
}
#endif

#ifndef defined_vapi_msg_sw_interface_set_l2_xconnect_reply
#define defined_vapi_msg_sw_interface_set_l2_xconnect_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_sw_interface_set_l2_xconnect_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sw_interface_set_l2_xconnect_reply payload;
} vapi_msg_sw_interface_set_l2_xconnect_reply;

static inline void vapi_msg_sw_interface_set_l2_xconnect_reply_payload_hton(vapi_payload_sw_interface_set_l2_xconnect_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_sw_interface_set_l2_xconnect_reply_payload_ntoh(vapi_payload_sw_interface_set_l2_xconnect_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_sw_interface_set_l2_xconnect_reply_hton(vapi_msg_sw_interface_set_l2_xconnect_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_set_l2_xconnect_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sw_interface_set_l2_xconnect_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_set_l2_xconnect_reply_ntoh(vapi_msg_sw_interface_set_l2_xconnect_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_set_l2_xconnect_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sw_interface_set_l2_xconnect_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_set_l2_xconnect_reply_msg_size(vapi_msg_sw_interface_set_l2_xconnect_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_set_l2_xconnect_reply_msg_size(vapi_msg_sw_interface_set_l2_xconnect_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_set_l2_xconnect_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_set_l2_xconnect_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_set_l2_xconnect_reply));
      return -1;
    }
  if (vapi_calc_sw_interface_set_l2_xconnect_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_set_l2_xconnect_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_set_l2_xconnect_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sw_interface_set_l2_xconnect_reply()
{
  static const char name[] = "sw_interface_set_l2_xconnect_reply";
  static const char name_with_crc[] = "sw_interface_set_l2_xconnect_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_sw_interface_set_l2_xconnect_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sw_interface_set_l2_xconnect_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_set_l2_xconnect_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_set_l2_xconnect_reply_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_set_l2_xconnect_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_set_l2_xconnect_reply = vapi_register_msg(&__vapi_metadata_sw_interface_set_l2_xconnect_reply);
  VAPI_DBG("Assigned msg id %d to sw_interface_set_l2_xconnect_reply", vapi_msg_id_sw_interface_set_l2_xconnect_reply);
}

static inline void vapi_set_vapi_msg_sw_interface_set_l2_xconnect_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sw_interface_set_l2_xconnect_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sw_interface_set_l2_xconnect_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sw_interface_set_l2_xconnect
#define defined_vapi_msg_sw_interface_set_l2_xconnect
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index rx_sw_if_index;
  vapi_type_interface_index tx_sw_if_index;
  bool enable; 
} vapi_payload_sw_interface_set_l2_xconnect;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sw_interface_set_l2_xconnect payload;
} vapi_msg_sw_interface_set_l2_xconnect;

static inline void vapi_msg_sw_interface_set_l2_xconnect_payload_hton(vapi_payload_sw_interface_set_l2_xconnect *payload)
{
  payload->rx_sw_if_index = htobe32(payload->rx_sw_if_index);
  payload->tx_sw_if_index = htobe32(payload->tx_sw_if_index);
}

static inline void vapi_msg_sw_interface_set_l2_xconnect_payload_ntoh(vapi_payload_sw_interface_set_l2_xconnect *payload)
{
  payload->rx_sw_if_index = be32toh(payload->rx_sw_if_index);
  payload->tx_sw_if_index = be32toh(payload->tx_sw_if_index);
}

static inline void vapi_msg_sw_interface_set_l2_xconnect_hton(vapi_msg_sw_interface_set_l2_xconnect *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_set_l2_xconnect'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sw_interface_set_l2_xconnect_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_set_l2_xconnect_ntoh(vapi_msg_sw_interface_set_l2_xconnect *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_set_l2_xconnect'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sw_interface_set_l2_xconnect_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_set_l2_xconnect_msg_size(vapi_msg_sw_interface_set_l2_xconnect *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_set_l2_xconnect_msg_size(vapi_msg_sw_interface_set_l2_xconnect *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_set_l2_xconnect) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_set_l2_xconnect' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_set_l2_xconnect));
      return -1;
    }
  if (vapi_calc_sw_interface_set_l2_xconnect_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_set_l2_xconnect' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_set_l2_xconnect_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sw_interface_set_l2_xconnect* vapi_alloc_sw_interface_set_l2_xconnect(struct vapi_ctx_s *ctx)
{
  vapi_msg_sw_interface_set_l2_xconnect *msg = NULL;
  const size_t size = sizeof(vapi_msg_sw_interface_set_l2_xconnect);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sw_interface_set_l2_xconnect*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sw_interface_set_l2_xconnect);

  return msg;
}

static inline vapi_error_e vapi_sw_interface_set_l2_xconnect(struct vapi_ctx_s *ctx,
  vapi_msg_sw_interface_set_l2_xconnect *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sw_interface_set_l2_xconnect_reply *reply),
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
  vapi_msg_sw_interface_set_l2_xconnect_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sw_interface_set_l2_xconnect_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sw_interface_set_l2_xconnect_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sw_interface_set_l2_xconnect()
{
  static const char name[] = "sw_interface_set_l2_xconnect";
  static const char name_with_crc[] = "sw_interface_set_l2_xconnect_4fa28a85";
  static vapi_message_desc_t __vapi_metadata_sw_interface_set_l2_xconnect = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sw_interface_set_l2_xconnect, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_set_l2_xconnect_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_set_l2_xconnect_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_set_l2_xconnect_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_set_l2_xconnect = vapi_register_msg(&__vapi_metadata_sw_interface_set_l2_xconnect);
  VAPI_DBG("Assigned msg id %d to sw_interface_set_l2_xconnect", vapi_msg_id_sw_interface_set_l2_xconnect);
}
#endif

#ifndef defined_vapi_msg_sw_interface_set_l2_bridge_reply
#define defined_vapi_msg_sw_interface_set_l2_bridge_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_sw_interface_set_l2_bridge_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sw_interface_set_l2_bridge_reply payload;
} vapi_msg_sw_interface_set_l2_bridge_reply;

static inline void vapi_msg_sw_interface_set_l2_bridge_reply_payload_hton(vapi_payload_sw_interface_set_l2_bridge_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_sw_interface_set_l2_bridge_reply_payload_ntoh(vapi_payload_sw_interface_set_l2_bridge_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_sw_interface_set_l2_bridge_reply_hton(vapi_msg_sw_interface_set_l2_bridge_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_set_l2_bridge_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sw_interface_set_l2_bridge_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_set_l2_bridge_reply_ntoh(vapi_msg_sw_interface_set_l2_bridge_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_set_l2_bridge_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sw_interface_set_l2_bridge_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_set_l2_bridge_reply_msg_size(vapi_msg_sw_interface_set_l2_bridge_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_set_l2_bridge_reply_msg_size(vapi_msg_sw_interface_set_l2_bridge_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_set_l2_bridge_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_set_l2_bridge_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_set_l2_bridge_reply));
      return -1;
    }
  if (vapi_calc_sw_interface_set_l2_bridge_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_set_l2_bridge_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_set_l2_bridge_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sw_interface_set_l2_bridge_reply()
{
  static const char name[] = "sw_interface_set_l2_bridge_reply";
  static const char name_with_crc[] = "sw_interface_set_l2_bridge_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_sw_interface_set_l2_bridge_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sw_interface_set_l2_bridge_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_set_l2_bridge_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_set_l2_bridge_reply_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_set_l2_bridge_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_set_l2_bridge_reply = vapi_register_msg(&__vapi_metadata_sw_interface_set_l2_bridge_reply);
  VAPI_DBG("Assigned msg id %d to sw_interface_set_l2_bridge_reply", vapi_msg_id_sw_interface_set_l2_bridge_reply);
}

static inline void vapi_set_vapi_msg_sw_interface_set_l2_bridge_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sw_interface_set_l2_bridge_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sw_interface_set_l2_bridge_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sw_interface_set_l2_bridge
#define defined_vapi_msg_sw_interface_set_l2_bridge
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index rx_sw_if_index;
  u32 bd_id;
  vapi_enum_l2_port_type port_type;
  u8 shg;
  bool enable; 
} vapi_payload_sw_interface_set_l2_bridge;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sw_interface_set_l2_bridge payload;
} vapi_msg_sw_interface_set_l2_bridge;

static inline void vapi_msg_sw_interface_set_l2_bridge_payload_hton(vapi_payload_sw_interface_set_l2_bridge *payload)
{
  payload->rx_sw_if_index = htobe32(payload->rx_sw_if_index);
  payload->bd_id = htobe32(payload->bd_id);
  payload->port_type = (vapi_enum_l2_port_type)htobe32(payload->port_type);
}

static inline void vapi_msg_sw_interface_set_l2_bridge_payload_ntoh(vapi_payload_sw_interface_set_l2_bridge *payload)
{
  payload->rx_sw_if_index = be32toh(payload->rx_sw_if_index);
  payload->bd_id = be32toh(payload->bd_id);
  payload->port_type = (vapi_enum_l2_port_type)be32toh(payload->port_type);
}

static inline void vapi_msg_sw_interface_set_l2_bridge_hton(vapi_msg_sw_interface_set_l2_bridge *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_set_l2_bridge'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sw_interface_set_l2_bridge_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_set_l2_bridge_ntoh(vapi_msg_sw_interface_set_l2_bridge *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_set_l2_bridge'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sw_interface_set_l2_bridge_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_set_l2_bridge_msg_size(vapi_msg_sw_interface_set_l2_bridge *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_set_l2_bridge_msg_size(vapi_msg_sw_interface_set_l2_bridge *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_set_l2_bridge) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_set_l2_bridge' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_set_l2_bridge));
      return -1;
    }
  if (vapi_calc_sw_interface_set_l2_bridge_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_set_l2_bridge' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_set_l2_bridge_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sw_interface_set_l2_bridge* vapi_alloc_sw_interface_set_l2_bridge(struct vapi_ctx_s *ctx)
{
  vapi_msg_sw_interface_set_l2_bridge *msg = NULL;
  const size_t size = sizeof(vapi_msg_sw_interface_set_l2_bridge);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sw_interface_set_l2_bridge*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sw_interface_set_l2_bridge);

  return msg;
}

static inline vapi_error_e vapi_sw_interface_set_l2_bridge(struct vapi_ctx_s *ctx,
  vapi_msg_sw_interface_set_l2_bridge *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sw_interface_set_l2_bridge_reply *reply),
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
  vapi_msg_sw_interface_set_l2_bridge_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sw_interface_set_l2_bridge_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sw_interface_set_l2_bridge_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sw_interface_set_l2_bridge()
{
  static const char name[] = "sw_interface_set_l2_bridge";
  static const char name_with_crc[] = "sw_interface_set_l2_bridge_d0678b13";
  static vapi_message_desc_t __vapi_metadata_sw_interface_set_l2_bridge = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sw_interface_set_l2_bridge, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_set_l2_bridge_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_set_l2_bridge_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_set_l2_bridge_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_set_l2_bridge = vapi_register_msg(&__vapi_metadata_sw_interface_set_l2_bridge);
  VAPI_DBG("Assigned msg id %d to sw_interface_set_l2_bridge", vapi_msg_id_sw_interface_set_l2_bridge);
}
#endif

#ifndef defined_vapi_msg_bd_ip_mac_add_del_reply
#define defined_vapi_msg_bd_ip_mac_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bd_ip_mac_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bd_ip_mac_add_del_reply payload;
} vapi_msg_bd_ip_mac_add_del_reply;

static inline void vapi_msg_bd_ip_mac_add_del_reply_payload_hton(vapi_payload_bd_ip_mac_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bd_ip_mac_add_del_reply_payload_ntoh(vapi_payload_bd_ip_mac_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bd_ip_mac_add_del_reply_hton(vapi_msg_bd_ip_mac_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bd_ip_mac_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bd_ip_mac_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bd_ip_mac_add_del_reply_ntoh(vapi_msg_bd_ip_mac_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bd_ip_mac_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bd_ip_mac_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bd_ip_mac_add_del_reply_msg_size(vapi_msg_bd_ip_mac_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bd_ip_mac_add_del_reply_msg_size(vapi_msg_bd_ip_mac_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bd_ip_mac_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bd_ip_mac_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bd_ip_mac_add_del_reply));
      return -1;
    }
  if (vapi_calc_bd_ip_mac_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bd_ip_mac_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bd_ip_mac_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bd_ip_mac_add_del_reply()
{
  static const char name[] = "bd_ip_mac_add_del_reply";
  static const char name_with_crc[] = "bd_ip_mac_add_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bd_ip_mac_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bd_ip_mac_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bd_ip_mac_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bd_ip_mac_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_bd_ip_mac_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bd_ip_mac_add_del_reply = vapi_register_msg(&__vapi_metadata_bd_ip_mac_add_del_reply);
  VAPI_DBG("Assigned msg id %d to bd_ip_mac_add_del_reply", vapi_msg_id_bd_ip_mac_add_del_reply);
}

static inline void vapi_set_vapi_msg_bd_ip_mac_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bd_ip_mac_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bd_ip_mac_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bd_ip_mac_add_del
#define defined_vapi_msg_bd_ip_mac_add_del
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_bd_ip_mac entry; 
} vapi_payload_bd_ip_mac_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bd_ip_mac_add_del payload;
} vapi_msg_bd_ip_mac_add_del;

static inline void vapi_msg_bd_ip_mac_add_del_payload_hton(vapi_payload_bd_ip_mac_add_del *payload)
{
  vapi_type_bd_ip_mac_hton(&payload->entry);
}

static inline void vapi_msg_bd_ip_mac_add_del_payload_ntoh(vapi_payload_bd_ip_mac_add_del *payload)
{
  vapi_type_bd_ip_mac_ntoh(&payload->entry);
}

static inline void vapi_msg_bd_ip_mac_add_del_hton(vapi_msg_bd_ip_mac_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bd_ip_mac_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bd_ip_mac_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_bd_ip_mac_add_del_ntoh(vapi_msg_bd_ip_mac_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bd_ip_mac_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bd_ip_mac_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bd_ip_mac_add_del_msg_size(vapi_msg_bd_ip_mac_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bd_ip_mac_add_del_msg_size(vapi_msg_bd_ip_mac_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bd_ip_mac_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'bd_ip_mac_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bd_ip_mac_add_del));
      return -1;
    }
  if (vapi_calc_bd_ip_mac_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bd_ip_mac_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bd_ip_mac_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bd_ip_mac_add_del* vapi_alloc_bd_ip_mac_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_bd_ip_mac_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_bd_ip_mac_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bd_ip_mac_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bd_ip_mac_add_del);

  return msg;
}

static inline vapi_error_e vapi_bd_ip_mac_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_bd_ip_mac_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bd_ip_mac_add_del_reply *reply),
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
  vapi_msg_bd_ip_mac_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bd_ip_mac_add_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bd_ip_mac_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bd_ip_mac_add_del()
{
  static const char name[] = "bd_ip_mac_add_del";
  static const char name_with_crc[] = "bd_ip_mac_add_del_0257c869";
  static vapi_message_desc_t __vapi_metadata_bd_ip_mac_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bd_ip_mac_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_bd_ip_mac_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_bd_ip_mac_add_del_hton,
    (generic_swap_fn_t)vapi_msg_bd_ip_mac_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bd_ip_mac_add_del = vapi_register_msg(&__vapi_metadata_bd_ip_mac_add_del);
  VAPI_DBG("Assigned msg id %d to bd_ip_mac_add_del", vapi_msg_id_bd_ip_mac_add_del);
}
#endif

#ifndef defined_vapi_msg_bd_ip_mac_flush_reply
#define defined_vapi_msg_bd_ip_mac_flush_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bd_ip_mac_flush_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bd_ip_mac_flush_reply payload;
} vapi_msg_bd_ip_mac_flush_reply;

static inline void vapi_msg_bd_ip_mac_flush_reply_payload_hton(vapi_payload_bd_ip_mac_flush_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bd_ip_mac_flush_reply_payload_ntoh(vapi_payload_bd_ip_mac_flush_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bd_ip_mac_flush_reply_hton(vapi_msg_bd_ip_mac_flush_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bd_ip_mac_flush_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bd_ip_mac_flush_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bd_ip_mac_flush_reply_ntoh(vapi_msg_bd_ip_mac_flush_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bd_ip_mac_flush_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bd_ip_mac_flush_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bd_ip_mac_flush_reply_msg_size(vapi_msg_bd_ip_mac_flush_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bd_ip_mac_flush_reply_msg_size(vapi_msg_bd_ip_mac_flush_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bd_ip_mac_flush_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bd_ip_mac_flush_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bd_ip_mac_flush_reply));
      return -1;
    }
  if (vapi_calc_bd_ip_mac_flush_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bd_ip_mac_flush_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bd_ip_mac_flush_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bd_ip_mac_flush_reply()
{
  static const char name[] = "bd_ip_mac_flush_reply";
  static const char name_with_crc[] = "bd_ip_mac_flush_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bd_ip_mac_flush_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bd_ip_mac_flush_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bd_ip_mac_flush_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bd_ip_mac_flush_reply_hton,
    (generic_swap_fn_t)vapi_msg_bd_ip_mac_flush_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bd_ip_mac_flush_reply = vapi_register_msg(&__vapi_metadata_bd_ip_mac_flush_reply);
  VAPI_DBG("Assigned msg id %d to bd_ip_mac_flush_reply", vapi_msg_id_bd_ip_mac_flush_reply);
}

static inline void vapi_set_vapi_msg_bd_ip_mac_flush_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bd_ip_mac_flush_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bd_ip_mac_flush_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bd_ip_mac_flush
#define defined_vapi_msg_bd_ip_mac_flush
typedef struct __attribute__ ((__packed__)) {
  u32 bd_id; 
} vapi_payload_bd_ip_mac_flush;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bd_ip_mac_flush payload;
} vapi_msg_bd_ip_mac_flush;

static inline void vapi_msg_bd_ip_mac_flush_payload_hton(vapi_payload_bd_ip_mac_flush *payload)
{
  payload->bd_id = htobe32(payload->bd_id);
}

static inline void vapi_msg_bd_ip_mac_flush_payload_ntoh(vapi_payload_bd_ip_mac_flush *payload)
{
  payload->bd_id = be32toh(payload->bd_id);
}

static inline void vapi_msg_bd_ip_mac_flush_hton(vapi_msg_bd_ip_mac_flush *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bd_ip_mac_flush'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bd_ip_mac_flush_payload_hton(&msg->payload);
}

static inline void vapi_msg_bd_ip_mac_flush_ntoh(vapi_msg_bd_ip_mac_flush *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bd_ip_mac_flush'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bd_ip_mac_flush_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bd_ip_mac_flush_msg_size(vapi_msg_bd_ip_mac_flush *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bd_ip_mac_flush_msg_size(vapi_msg_bd_ip_mac_flush *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bd_ip_mac_flush) > buf_size)
    {
      VAPI_ERR("Truncated 'bd_ip_mac_flush' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bd_ip_mac_flush));
      return -1;
    }
  if (vapi_calc_bd_ip_mac_flush_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bd_ip_mac_flush' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bd_ip_mac_flush_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bd_ip_mac_flush* vapi_alloc_bd_ip_mac_flush(struct vapi_ctx_s *ctx)
{
  vapi_msg_bd_ip_mac_flush *msg = NULL;
  const size_t size = sizeof(vapi_msg_bd_ip_mac_flush);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bd_ip_mac_flush*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bd_ip_mac_flush);

  return msg;
}

static inline vapi_error_e vapi_bd_ip_mac_flush(struct vapi_ctx_s *ctx,
  vapi_msg_bd_ip_mac_flush *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bd_ip_mac_flush_reply *reply),
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
  vapi_msg_bd_ip_mac_flush_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bd_ip_mac_flush_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bd_ip_mac_flush_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bd_ip_mac_flush()
{
  static const char name[] = "bd_ip_mac_flush";
  static const char name_with_crc[] = "bd_ip_mac_flush_c25fdce6";
  static vapi_message_desc_t __vapi_metadata_bd_ip_mac_flush = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bd_ip_mac_flush, payload),
    (verify_msg_size_fn_t)vapi_verify_bd_ip_mac_flush_msg_size,
    (generic_swap_fn_t)vapi_msg_bd_ip_mac_flush_hton,
    (generic_swap_fn_t)vapi_msg_bd_ip_mac_flush_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bd_ip_mac_flush = vapi_register_msg(&__vapi_metadata_bd_ip_mac_flush);
  VAPI_DBG("Assigned msg id %d to bd_ip_mac_flush", vapi_msg_id_bd_ip_mac_flush);
}
#endif

#ifndef defined_vapi_msg_bd_ip_mac_details
#define defined_vapi_msg_bd_ip_mac_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_bd_ip_mac entry; 
} vapi_payload_bd_ip_mac_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bd_ip_mac_details payload;
} vapi_msg_bd_ip_mac_details;

static inline void vapi_msg_bd_ip_mac_details_payload_hton(vapi_payload_bd_ip_mac_details *payload)
{
  vapi_type_bd_ip_mac_hton(&payload->entry);
}

static inline void vapi_msg_bd_ip_mac_details_payload_ntoh(vapi_payload_bd_ip_mac_details *payload)
{
  vapi_type_bd_ip_mac_ntoh(&payload->entry);
}

static inline void vapi_msg_bd_ip_mac_details_hton(vapi_msg_bd_ip_mac_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bd_ip_mac_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bd_ip_mac_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_bd_ip_mac_details_ntoh(vapi_msg_bd_ip_mac_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bd_ip_mac_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bd_ip_mac_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bd_ip_mac_details_msg_size(vapi_msg_bd_ip_mac_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bd_ip_mac_details_msg_size(vapi_msg_bd_ip_mac_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bd_ip_mac_details) > buf_size)
    {
      VAPI_ERR("Truncated 'bd_ip_mac_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bd_ip_mac_details));
      return -1;
    }
  if (vapi_calc_bd_ip_mac_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bd_ip_mac_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bd_ip_mac_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bd_ip_mac_details()
{
  static const char name[] = "bd_ip_mac_details";
  static const char name_with_crc[] = "bd_ip_mac_details_545af86a";
  static vapi_message_desc_t __vapi_metadata_bd_ip_mac_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bd_ip_mac_details, payload),
    (verify_msg_size_fn_t)vapi_verify_bd_ip_mac_details_msg_size,
    (generic_swap_fn_t)vapi_msg_bd_ip_mac_details_hton,
    (generic_swap_fn_t)vapi_msg_bd_ip_mac_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bd_ip_mac_details = vapi_register_msg(&__vapi_metadata_bd_ip_mac_details);
  VAPI_DBG("Assigned msg id %d to bd_ip_mac_details", vapi_msg_id_bd_ip_mac_details);
}

static inline void vapi_set_vapi_msg_bd_ip_mac_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bd_ip_mac_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bd_ip_mac_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bd_ip_mac_dump
#define defined_vapi_msg_bd_ip_mac_dump
typedef struct __attribute__ ((__packed__)) {
  u32 bd_id; 
} vapi_payload_bd_ip_mac_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bd_ip_mac_dump payload;
} vapi_msg_bd_ip_mac_dump;

static inline void vapi_msg_bd_ip_mac_dump_payload_hton(vapi_payload_bd_ip_mac_dump *payload)
{
  payload->bd_id = htobe32(payload->bd_id);
}

static inline void vapi_msg_bd_ip_mac_dump_payload_ntoh(vapi_payload_bd_ip_mac_dump *payload)
{
  payload->bd_id = be32toh(payload->bd_id);
}

static inline void vapi_msg_bd_ip_mac_dump_hton(vapi_msg_bd_ip_mac_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bd_ip_mac_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bd_ip_mac_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_bd_ip_mac_dump_ntoh(vapi_msg_bd_ip_mac_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bd_ip_mac_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bd_ip_mac_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bd_ip_mac_dump_msg_size(vapi_msg_bd_ip_mac_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bd_ip_mac_dump_msg_size(vapi_msg_bd_ip_mac_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bd_ip_mac_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'bd_ip_mac_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bd_ip_mac_dump));
      return -1;
    }
  if (vapi_calc_bd_ip_mac_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bd_ip_mac_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bd_ip_mac_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bd_ip_mac_dump* vapi_alloc_bd_ip_mac_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_bd_ip_mac_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_bd_ip_mac_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bd_ip_mac_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bd_ip_mac_dump);

  return msg;
}

static inline vapi_error_e vapi_bd_ip_mac_dump(struct vapi_ctx_s *ctx,
  vapi_msg_bd_ip_mac_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bd_ip_mac_details *reply),
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
  vapi_msg_bd_ip_mac_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bd_ip_mac_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_bd_ip_mac_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bd_ip_mac_dump()
{
  static const char name[] = "bd_ip_mac_dump";
  static const char name_with_crc[] = "bd_ip_mac_dump_c25fdce6";
  static vapi_message_desc_t __vapi_metadata_bd_ip_mac_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bd_ip_mac_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_bd_ip_mac_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_bd_ip_mac_dump_hton,
    (generic_swap_fn_t)vapi_msg_bd_ip_mac_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bd_ip_mac_dump = vapi_register_msg(&__vapi_metadata_bd_ip_mac_dump);
  VAPI_DBG("Assigned msg id %d to bd_ip_mac_dump", vapi_msg_id_bd_ip_mac_dump);
}
#endif

#ifndef defined_vapi_msg_l2_interface_efp_filter_reply
#define defined_vapi_msg_l2_interface_efp_filter_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_l2_interface_efp_filter_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_l2_interface_efp_filter_reply payload;
} vapi_msg_l2_interface_efp_filter_reply;

static inline void vapi_msg_l2_interface_efp_filter_reply_payload_hton(vapi_payload_l2_interface_efp_filter_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_l2_interface_efp_filter_reply_payload_ntoh(vapi_payload_l2_interface_efp_filter_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_l2_interface_efp_filter_reply_hton(vapi_msg_l2_interface_efp_filter_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_interface_efp_filter_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_l2_interface_efp_filter_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2_interface_efp_filter_reply_ntoh(vapi_msg_l2_interface_efp_filter_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_interface_efp_filter_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_l2_interface_efp_filter_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2_interface_efp_filter_reply_msg_size(vapi_msg_l2_interface_efp_filter_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2_interface_efp_filter_reply_msg_size(vapi_msg_l2_interface_efp_filter_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2_interface_efp_filter_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_interface_efp_filter_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2_interface_efp_filter_reply));
      return -1;
    }
  if (vapi_calc_l2_interface_efp_filter_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_interface_efp_filter_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2_interface_efp_filter_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_l2_interface_efp_filter_reply()
{
  static const char name[] = "l2_interface_efp_filter_reply";
  static const char name_with_crc[] = "l2_interface_efp_filter_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_l2_interface_efp_filter_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_l2_interface_efp_filter_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_l2_interface_efp_filter_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_l2_interface_efp_filter_reply_hton,
    (generic_swap_fn_t)vapi_msg_l2_interface_efp_filter_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2_interface_efp_filter_reply = vapi_register_msg(&__vapi_metadata_l2_interface_efp_filter_reply);
  VAPI_DBG("Assigned msg id %d to l2_interface_efp_filter_reply", vapi_msg_id_l2_interface_efp_filter_reply);
}

static inline void vapi_set_vapi_msg_l2_interface_efp_filter_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_l2_interface_efp_filter_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_l2_interface_efp_filter_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_l2_interface_efp_filter
#define defined_vapi_msg_l2_interface_efp_filter
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  bool enable_disable; 
} vapi_payload_l2_interface_efp_filter;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_l2_interface_efp_filter payload;
} vapi_msg_l2_interface_efp_filter;

static inline void vapi_msg_l2_interface_efp_filter_payload_hton(vapi_payload_l2_interface_efp_filter *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_l2_interface_efp_filter_payload_ntoh(vapi_payload_l2_interface_efp_filter *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_l2_interface_efp_filter_hton(vapi_msg_l2_interface_efp_filter *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_interface_efp_filter'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_l2_interface_efp_filter_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2_interface_efp_filter_ntoh(vapi_msg_l2_interface_efp_filter *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_interface_efp_filter'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_l2_interface_efp_filter_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2_interface_efp_filter_msg_size(vapi_msg_l2_interface_efp_filter *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2_interface_efp_filter_msg_size(vapi_msg_l2_interface_efp_filter *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2_interface_efp_filter) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_interface_efp_filter' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2_interface_efp_filter));
      return -1;
    }
  if (vapi_calc_l2_interface_efp_filter_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_interface_efp_filter' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2_interface_efp_filter_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_l2_interface_efp_filter* vapi_alloc_l2_interface_efp_filter(struct vapi_ctx_s *ctx)
{
  vapi_msg_l2_interface_efp_filter *msg = NULL;
  const size_t size = sizeof(vapi_msg_l2_interface_efp_filter);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_l2_interface_efp_filter*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_l2_interface_efp_filter);

  return msg;
}

static inline vapi_error_e vapi_l2_interface_efp_filter(struct vapi_ctx_s *ctx,
  vapi_msg_l2_interface_efp_filter *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_l2_interface_efp_filter_reply *reply),
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
  vapi_msg_l2_interface_efp_filter_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_l2_interface_efp_filter_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_l2_interface_efp_filter_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_l2_interface_efp_filter()
{
  static const char name[] = "l2_interface_efp_filter";
  static const char name_with_crc[] = "l2_interface_efp_filter_5501adee";
  static vapi_message_desc_t __vapi_metadata_l2_interface_efp_filter = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_l2_interface_efp_filter, payload),
    (verify_msg_size_fn_t)vapi_verify_l2_interface_efp_filter_msg_size,
    (generic_swap_fn_t)vapi_msg_l2_interface_efp_filter_hton,
    (generic_swap_fn_t)vapi_msg_l2_interface_efp_filter_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2_interface_efp_filter = vapi_register_msg(&__vapi_metadata_l2_interface_efp_filter);
  VAPI_DBG("Assigned msg id %d to l2_interface_efp_filter", vapi_msg_id_l2_interface_efp_filter);
}
#endif

#ifndef defined_vapi_msg_sw_interface_set_vpath_reply
#define defined_vapi_msg_sw_interface_set_vpath_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_sw_interface_set_vpath_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sw_interface_set_vpath_reply payload;
} vapi_msg_sw_interface_set_vpath_reply;

static inline void vapi_msg_sw_interface_set_vpath_reply_payload_hton(vapi_payload_sw_interface_set_vpath_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_sw_interface_set_vpath_reply_payload_ntoh(vapi_payload_sw_interface_set_vpath_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_sw_interface_set_vpath_reply_hton(vapi_msg_sw_interface_set_vpath_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_set_vpath_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sw_interface_set_vpath_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_set_vpath_reply_ntoh(vapi_msg_sw_interface_set_vpath_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_set_vpath_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sw_interface_set_vpath_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_set_vpath_reply_msg_size(vapi_msg_sw_interface_set_vpath_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_set_vpath_reply_msg_size(vapi_msg_sw_interface_set_vpath_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_set_vpath_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_set_vpath_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_set_vpath_reply));
      return -1;
    }
  if (vapi_calc_sw_interface_set_vpath_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_set_vpath_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_set_vpath_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sw_interface_set_vpath_reply()
{
  static const char name[] = "sw_interface_set_vpath_reply";
  static const char name_with_crc[] = "sw_interface_set_vpath_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_sw_interface_set_vpath_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sw_interface_set_vpath_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_set_vpath_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_set_vpath_reply_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_set_vpath_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_set_vpath_reply = vapi_register_msg(&__vapi_metadata_sw_interface_set_vpath_reply);
  VAPI_DBG("Assigned msg id %d to sw_interface_set_vpath_reply", vapi_msg_id_sw_interface_set_vpath_reply);
}

static inline void vapi_set_vapi_msg_sw_interface_set_vpath_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sw_interface_set_vpath_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sw_interface_set_vpath_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sw_interface_set_vpath
#define defined_vapi_msg_sw_interface_set_vpath
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  bool enable; 
} vapi_payload_sw_interface_set_vpath;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sw_interface_set_vpath payload;
} vapi_msg_sw_interface_set_vpath;

static inline void vapi_msg_sw_interface_set_vpath_payload_hton(vapi_payload_sw_interface_set_vpath *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_sw_interface_set_vpath_payload_ntoh(vapi_payload_sw_interface_set_vpath *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_sw_interface_set_vpath_hton(vapi_msg_sw_interface_set_vpath *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_set_vpath'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sw_interface_set_vpath_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_set_vpath_ntoh(vapi_msg_sw_interface_set_vpath *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_set_vpath'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sw_interface_set_vpath_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_set_vpath_msg_size(vapi_msg_sw_interface_set_vpath *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_set_vpath_msg_size(vapi_msg_sw_interface_set_vpath *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_set_vpath) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_set_vpath' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_set_vpath));
      return -1;
    }
  if (vapi_calc_sw_interface_set_vpath_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_set_vpath' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_set_vpath_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sw_interface_set_vpath* vapi_alloc_sw_interface_set_vpath(struct vapi_ctx_s *ctx)
{
  vapi_msg_sw_interface_set_vpath *msg = NULL;
  const size_t size = sizeof(vapi_msg_sw_interface_set_vpath);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sw_interface_set_vpath*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sw_interface_set_vpath);

  return msg;
}

static inline vapi_error_e vapi_sw_interface_set_vpath(struct vapi_ctx_s *ctx,
  vapi_msg_sw_interface_set_vpath *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sw_interface_set_vpath_reply *reply),
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
  vapi_msg_sw_interface_set_vpath_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sw_interface_set_vpath_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sw_interface_set_vpath_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sw_interface_set_vpath()
{
  static const char name[] = "sw_interface_set_vpath";
  static const char name_with_crc[] = "sw_interface_set_vpath_ae6cfcfb";
  static vapi_message_desc_t __vapi_metadata_sw_interface_set_vpath = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sw_interface_set_vpath, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_set_vpath_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_set_vpath_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_set_vpath_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_set_vpath = vapi_register_msg(&__vapi_metadata_sw_interface_set_vpath);
  VAPI_DBG("Assigned msg id %d to sw_interface_set_vpath", vapi_msg_id_sw_interface_set_vpath);
}
#endif

#ifndef defined_vapi_msg_bvi_create_reply
#define defined_vapi_msg_bvi_create_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_bvi_create_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bvi_create_reply payload;
} vapi_msg_bvi_create_reply;

static inline void vapi_msg_bvi_create_reply_payload_hton(vapi_payload_bvi_create_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_bvi_create_reply_payload_ntoh(vapi_payload_bvi_create_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_bvi_create_reply_hton(vapi_msg_bvi_create_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bvi_create_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bvi_create_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bvi_create_reply_ntoh(vapi_msg_bvi_create_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bvi_create_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bvi_create_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bvi_create_reply_msg_size(vapi_msg_bvi_create_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bvi_create_reply_msg_size(vapi_msg_bvi_create_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bvi_create_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bvi_create_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bvi_create_reply));
      return -1;
    }
  if (vapi_calc_bvi_create_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bvi_create_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bvi_create_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bvi_create_reply()
{
  static const char name[] = "bvi_create_reply";
  static const char name_with_crc[] = "bvi_create_reply_5383d31f";
  static vapi_message_desc_t __vapi_metadata_bvi_create_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bvi_create_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bvi_create_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bvi_create_reply_hton,
    (generic_swap_fn_t)vapi_msg_bvi_create_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bvi_create_reply = vapi_register_msg(&__vapi_metadata_bvi_create_reply);
  VAPI_DBG("Assigned msg id %d to bvi_create_reply", vapi_msg_id_bvi_create_reply);
}

static inline void vapi_set_vapi_msg_bvi_create_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bvi_create_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bvi_create_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bvi_create
#define defined_vapi_msg_bvi_create
typedef struct __attribute__ ((__packed__)) {
  vapi_type_mac_address mac;
  u32 user_instance; 
} vapi_payload_bvi_create;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bvi_create payload;
} vapi_msg_bvi_create;

static inline void vapi_msg_bvi_create_payload_hton(vapi_payload_bvi_create *payload)
{
  payload->user_instance = htobe32(payload->user_instance);
}

static inline void vapi_msg_bvi_create_payload_ntoh(vapi_payload_bvi_create *payload)
{
  payload->user_instance = be32toh(payload->user_instance);
}

static inline void vapi_msg_bvi_create_hton(vapi_msg_bvi_create *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bvi_create'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bvi_create_payload_hton(&msg->payload);
}

static inline void vapi_msg_bvi_create_ntoh(vapi_msg_bvi_create *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bvi_create'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bvi_create_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bvi_create_msg_size(vapi_msg_bvi_create *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bvi_create_msg_size(vapi_msg_bvi_create *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bvi_create) > buf_size)
    {
      VAPI_ERR("Truncated 'bvi_create' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bvi_create));
      return -1;
    }
  if (vapi_calc_bvi_create_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bvi_create' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bvi_create_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bvi_create* vapi_alloc_bvi_create(struct vapi_ctx_s *ctx)
{
  vapi_msg_bvi_create *msg = NULL;
  const size_t size = sizeof(vapi_msg_bvi_create);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bvi_create*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bvi_create);

  return msg;
}

static inline vapi_error_e vapi_bvi_create(struct vapi_ctx_s *ctx,
  vapi_msg_bvi_create *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bvi_create_reply *reply),
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
  vapi_msg_bvi_create_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bvi_create_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bvi_create_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bvi_create()
{
  static const char name[] = "bvi_create";
  static const char name_with_crc[] = "bvi_create_f5398559";
  static vapi_message_desc_t __vapi_metadata_bvi_create = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bvi_create, payload),
    (verify_msg_size_fn_t)vapi_verify_bvi_create_msg_size,
    (generic_swap_fn_t)vapi_msg_bvi_create_hton,
    (generic_swap_fn_t)vapi_msg_bvi_create_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bvi_create = vapi_register_msg(&__vapi_metadata_bvi_create);
  VAPI_DBG("Assigned msg id %d to bvi_create", vapi_msg_id_bvi_create);
}
#endif

#ifndef defined_vapi_msg_bvi_delete_reply
#define defined_vapi_msg_bvi_delete_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bvi_delete_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bvi_delete_reply payload;
} vapi_msg_bvi_delete_reply;

static inline void vapi_msg_bvi_delete_reply_payload_hton(vapi_payload_bvi_delete_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bvi_delete_reply_payload_ntoh(vapi_payload_bvi_delete_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bvi_delete_reply_hton(vapi_msg_bvi_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bvi_delete_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bvi_delete_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bvi_delete_reply_ntoh(vapi_msg_bvi_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bvi_delete_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bvi_delete_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bvi_delete_reply_msg_size(vapi_msg_bvi_delete_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bvi_delete_reply_msg_size(vapi_msg_bvi_delete_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bvi_delete_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bvi_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bvi_delete_reply));
      return -1;
    }
  if (vapi_calc_bvi_delete_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bvi_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bvi_delete_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bvi_delete_reply()
{
  static const char name[] = "bvi_delete_reply";
  static const char name_with_crc[] = "bvi_delete_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bvi_delete_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bvi_delete_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bvi_delete_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bvi_delete_reply_hton,
    (generic_swap_fn_t)vapi_msg_bvi_delete_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bvi_delete_reply = vapi_register_msg(&__vapi_metadata_bvi_delete_reply);
  VAPI_DBG("Assigned msg id %d to bvi_delete_reply", vapi_msg_id_bvi_delete_reply);
}

static inline void vapi_set_vapi_msg_bvi_delete_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bvi_delete_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bvi_delete_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bvi_delete
#define defined_vapi_msg_bvi_delete
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_bvi_delete;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bvi_delete payload;
} vapi_msg_bvi_delete;

static inline void vapi_msg_bvi_delete_payload_hton(vapi_payload_bvi_delete *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_bvi_delete_payload_ntoh(vapi_payload_bvi_delete *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_bvi_delete_hton(vapi_msg_bvi_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bvi_delete'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bvi_delete_payload_hton(&msg->payload);
}

static inline void vapi_msg_bvi_delete_ntoh(vapi_msg_bvi_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bvi_delete'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bvi_delete_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bvi_delete_msg_size(vapi_msg_bvi_delete *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bvi_delete_msg_size(vapi_msg_bvi_delete *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bvi_delete) > buf_size)
    {
      VAPI_ERR("Truncated 'bvi_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bvi_delete));
      return -1;
    }
  if (vapi_calc_bvi_delete_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bvi_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bvi_delete_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bvi_delete* vapi_alloc_bvi_delete(struct vapi_ctx_s *ctx)
{
  vapi_msg_bvi_delete *msg = NULL;
  const size_t size = sizeof(vapi_msg_bvi_delete);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bvi_delete*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bvi_delete);

  return msg;
}

static inline vapi_error_e vapi_bvi_delete(struct vapi_ctx_s *ctx,
  vapi_msg_bvi_delete *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bvi_delete_reply *reply),
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
  vapi_msg_bvi_delete_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bvi_delete_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bvi_delete_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bvi_delete()
{
  static const char name[] = "bvi_delete";
  static const char name_with_crc[] = "bvi_delete_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_bvi_delete = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bvi_delete, payload),
    (verify_msg_size_fn_t)vapi_verify_bvi_delete_msg_size,
    (generic_swap_fn_t)vapi_msg_bvi_delete_hton,
    (generic_swap_fn_t)vapi_msg_bvi_delete_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bvi_delete = vapi_register_msg(&__vapi_metadata_bvi_delete);
  VAPI_DBG("Assigned msg id %d to bvi_delete", vapi_msg_id_bvi_delete);
}
#endif

#ifndef defined_vapi_msg_want_l2_arp_term_events_reply
#define defined_vapi_msg_want_l2_arp_term_events_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_want_l2_arp_term_events_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_want_l2_arp_term_events_reply payload;
} vapi_msg_want_l2_arp_term_events_reply;

static inline void vapi_msg_want_l2_arp_term_events_reply_payload_hton(vapi_payload_want_l2_arp_term_events_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_want_l2_arp_term_events_reply_payload_ntoh(vapi_payload_want_l2_arp_term_events_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_want_l2_arp_term_events_reply_hton(vapi_msg_want_l2_arp_term_events_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_l2_arp_term_events_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_want_l2_arp_term_events_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_want_l2_arp_term_events_reply_ntoh(vapi_msg_want_l2_arp_term_events_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_l2_arp_term_events_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_want_l2_arp_term_events_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_want_l2_arp_term_events_reply_msg_size(vapi_msg_want_l2_arp_term_events_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_want_l2_arp_term_events_reply_msg_size(vapi_msg_want_l2_arp_term_events_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_want_l2_arp_term_events_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'want_l2_arp_term_events_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_want_l2_arp_term_events_reply));
      return -1;
    }
  if (vapi_calc_want_l2_arp_term_events_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'want_l2_arp_term_events_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_want_l2_arp_term_events_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_want_l2_arp_term_events_reply()
{
  static const char name[] = "want_l2_arp_term_events_reply";
  static const char name_with_crc[] = "want_l2_arp_term_events_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_want_l2_arp_term_events_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_want_l2_arp_term_events_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_want_l2_arp_term_events_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_want_l2_arp_term_events_reply_hton,
    (generic_swap_fn_t)vapi_msg_want_l2_arp_term_events_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_want_l2_arp_term_events_reply = vapi_register_msg(&__vapi_metadata_want_l2_arp_term_events_reply);
  VAPI_DBG("Assigned msg id %d to want_l2_arp_term_events_reply", vapi_msg_id_want_l2_arp_term_events_reply);
}

static inline void vapi_set_vapi_msg_want_l2_arp_term_events_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_want_l2_arp_term_events_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_want_l2_arp_term_events_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_want_l2_arp_term_events
#define defined_vapi_msg_want_l2_arp_term_events
typedef struct __attribute__ ((__packed__)) {
  bool enable;
  u32 pid; 
} vapi_payload_want_l2_arp_term_events;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_want_l2_arp_term_events payload;
} vapi_msg_want_l2_arp_term_events;

static inline void vapi_msg_want_l2_arp_term_events_payload_hton(vapi_payload_want_l2_arp_term_events *payload)
{
  payload->pid = htobe32(payload->pid);
}

static inline void vapi_msg_want_l2_arp_term_events_payload_ntoh(vapi_payload_want_l2_arp_term_events *payload)
{
  payload->pid = be32toh(payload->pid);
}

static inline void vapi_msg_want_l2_arp_term_events_hton(vapi_msg_want_l2_arp_term_events *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_l2_arp_term_events'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_want_l2_arp_term_events_payload_hton(&msg->payload);
}

static inline void vapi_msg_want_l2_arp_term_events_ntoh(vapi_msg_want_l2_arp_term_events *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_l2_arp_term_events'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_want_l2_arp_term_events_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_want_l2_arp_term_events_msg_size(vapi_msg_want_l2_arp_term_events *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_want_l2_arp_term_events_msg_size(vapi_msg_want_l2_arp_term_events *msg, uword buf_size)
{
  if (sizeof(vapi_msg_want_l2_arp_term_events) > buf_size)
    {
      VAPI_ERR("Truncated 'want_l2_arp_term_events' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_want_l2_arp_term_events));
      return -1;
    }
  if (vapi_calc_want_l2_arp_term_events_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'want_l2_arp_term_events' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_want_l2_arp_term_events_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_want_l2_arp_term_events* vapi_alloc_want_l2_arp_term_events(struct vapi_ctx_s *ctx)
{
  vapi_msg_want_l2_arp_term_events *msg = NULL;
  const size_t size = sizeof(vapi_msg_want_l2_arp_term_events);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_want_l2_arp_term_events*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_want_l2_arp_term_events);

  return msg;
}

static inline vapi_error_e vapi_want_l2_arp_term_events(struct vapi_ctx_s *ctx,
  vapi_msg_want_l2_arp_term_events *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_want_l2_arp_term_events_reply *reply),
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
  vapi_msg_want_l2_arp_term_events_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_want_l2_arp_term_events_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_want_l2_arp_term_events_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_want_l2_arp_term_events()
{
  static const char name[] = "want_l2_arp_term_events";
  static const char name_with_crc[] = "want_l2_arp_term_events_3ec6d6c2";
  static vapi_message_desc_t __vapi_metadata_want_l2_arp_term_events = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_want_l2_arp_term_events, payload),
    (verify_msg_size_fn_t)vapi_verify_want_l2_arp_term_events_msg_size,
    (generic_swap_fn_t)vapi_msg_want_l2_arp_term_events_hton,
    (generic_swap_fn_t)vapi_msg_want_l2_arp_term_events_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_want_l2_arp_term_events = vapi_register_msg(&__vapi_metadata_want_l2_arp_term_events);
  VAPI_DBG("Assigned msg id %d to want_l2_arp_term_events", vapi_msg_id_want_l2_arp_term_events);
}
#endif

#ifndef defined_vapi_msg_l2_arp_term_event
#define defined_vapi_msg_l2_arp_term_event
typedef struct __attribute__ ((__packed__)) {
  u16 _vl_msg_id;
  u32 client_index;
  u32 pid;
  vapi_type_address ip;
  vapi_type_interface_index sw_if_index;
  vapi_type_mac_address mac; 
} vapi_payload_l2_arp_term_event;

typedef struct __attribute__ ((__packed__)) {

  vapi_payload_l2_arp_term_event payload;
} vapi_msg_l2_arp_term_event;

static inline void vapi_msg_l2_arp_term_event_payload_hton(vapi_payload_l2_arp_term_event *payload)
{
  payload->_vl_msg_id = htobe16(payload->_vl_msg_id);
  payload->client_index = htobe32(payload->client_index);
  payload->pid = htobe32(payload->pid);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_l2_arp_term_event_payload_ntoh(vapi_payload_l2_arp_term_event *payload)
{
  payload->_vl_msg_id = be16toh(payload->_vl_msg_id);
  payload->client_index = be32toh(payload->client_index);
  payload->pid = be32toh(payload->pid);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_l2_arp_term_event_hton(vapi_msg_l2_arp_term_event *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_arp_term_event'@%p to big endian", msg);

  vapi_msg_l2_arp_term_event_payload_hton(&msg->payload);
}

static inline void vapi_msg_l2_arp_term_event_ntoh(vapi_msg_l2_arp_term_event *msg)
{
  VAPI_DBG("Swapping `vapi_msg_l2_arp_term_event'@%p to host byte order", msg);

  vapi_msg_l2_arp_term_event_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_l2_arp_term_event_msg_size(vapi_msg_l2_arp_term_event *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_l2_arp_term_event_msg_size(vapi_msg_l2_arp_term_event *msg, uword buf_size)
{
  if (sizeof(vapi_msg_l2_arp_term_event) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_arp_term_event' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_l2_arp_term_event));
      return -1;
    }
  if (vapi_calc_l2_arp_term_event_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'l2_arp_term_event' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_l2_arp_term_event_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_l2_arp_term_event()
{
  static const char name[] = "l2_arp_term_event";
  static const char name_with_crc[] = "l2_arp_term_event_6963e07a";
  static vapi_message_desc_t __vapi_metadata_l2_arp_term_event = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    false,
    0,
    offsetof(vapi_msg_l2_arp_term_event, payload),
    (verify_msg_size_fn_t)vapi_verify_l2_arp_term_event_msg_size,
    (generic_swap_fn_t)vapi_msg_l2_arp_term_event_hton,
    (generic_swap_fn_t)vapi_msg_l2_arp_term_event_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_l2_arp_term_event = vapi_register_msg(&__vapi_metadata_l2_arp_term_event);
  VAPI_DBG("Assigned msg id %d to l2_arp_term_event", vapi_msg_id_l2_arp_term_event);
}

static inline void vapi_set_vapi_msg_l2_arp_term_event_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_l2_arp_term_event *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_l2_arp_term_event, (vapi_event_cb)callback, callback_ctx);
};
#endif


#ifdef __cplusplus
}
#endif

#endif
