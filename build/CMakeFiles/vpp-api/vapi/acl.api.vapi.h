#ifndef __included_acl_api_json
#define __included_acl_api_json

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

extern vapi_msg_id_t vapi_msg_id_acl_plugin_get_version;
extern vapi_msg_id_t vapi_msg_id_acl_plugin_get_version_reply;
extern vapi_msg_id_t vapi_msg_id_acl_plugin_control_ping;
extern vapi_msg_id_t vapi_msg_id_acl_plugin_control_ping_reply;
extern vapi_msg_id_t vapi_msg_id_acl_plugin_get_conn_table_max_entries;
extern vapi_msg_id_t vapi_msg_id_acl_plugin_get_conn_table_max_entries_reply;
extern vapi_msg_id_t vapi_msg_id_acl_add_replace;
extern vapi_msg_id_t vapi_msg_id_acl_add_replace_reply;
extern vapi_msg_id_t vapi_msg_id_acl_del;
extern vapi_msg_id_t vapi_msg_id_acl_del_reply;
extern vapi_msg_id_t vapi_msg_id_acl_interface_add_del;
extern vapi_msg_id_t vapi_msg_id_acl_interface_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_acl_interface_set_acl_list;
extern vapi_msg_id_t vapi_msg_id_acl_interface_set_acl_list_reply;
extern vapi_msg_id_t vapi_msg_id_acl_dump;
extern vapi_msg_id_t vapi_msg_id_acl_details;
extern vapi_msg_id_t vapi_msg_id_acl_interface_list_dump;
extern vapi_msg_id_t vapi_msg_id_acl_interface_list_details;
extern vapi_msg_id_t vapi_msg_id_macip_acl_add;
extern vapi_msg_id_t vapi_msg_id_macip_acl_add_reply;
extern vapi_msg_id_t vapi_msg_id_macip_acl_add_replace;
extern vapi_msg_id_t vapi_msg_id_macip_acl_add_replace_reply;
extern vapi_msg_id_t vapi_msg_id_macip_acl_del;
extern vapi_msg_id_t vapi_msg_id_macip_acl_del_reply;
extern vapi_msg_id_t vapi_msg_id_macip_acl_interface_add_del;
extern vapi_msg_id_t vapi_msg_id_macip_acl_interface_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_macip_acl_dump;
extern vapi_msg_id_t vapi_msg_id_macip_acl_details;
extern vapi_msg_id_t vapi_msg_id_macip_acl_interface_get;
extern vapi_msg_id_t vapi_msg_id_macip_acl_interface_get_reply;
extern vapi_msg_id_t vapi_msg_id_macip_acl_interface_list_dump;
extern vapi_msg_id_t vapi_msg_id_macip_acl_interface_list_details;
extern vapi_msg_id_t vapi_msg_id_acl_interface_set_etype_whitelist;
extern vapi_msg_id_t vapi_msg_id_acl_interface_set_etype_whitelist_reply;
extern vapi_msg_id_t vapi_msg_id_acl_interface_etype_whitelist_dump;
extern vapi_msg_id_t vapi_msg_id_acl_interface_etype_whitelist_details;
extern vapi_msg_id_t vapi_msg_id_acl_stats_intf_counters_enable;
extern vapi_msg_id_t vapi_msg_id_acl_stats_intf_counters_enable_reply;
extern vapi_msg_id_t vapi_msg_id_acl_plugin_use_hash_lookup_set;
extern vapi_msg_id_t vapi_msg_id_acl_plugin_use_hash_lookup_set_reply;
extern vapi_msg_id_t vapi_msg_id_acl_plugin_use_hash_lookup_get;
extern vapi_msg_id_t vapi_msg_id_acl_plugin_use_hash_lookup_get_reply;

#define DEFINE_VAPI_MSG_IDS_ACL_API_JSON\
  vapi_msg_id_t vapi_msg_id_acl_plugin_get_version;\
  vapi_msg_id_t vapi_msg_id_acl_plugin_get_version_reply;\
  vapi_msg_id_t vapi_msg_id_acl_plugin_control_ping;\
  vapi_msg_id_t vapi_msg_id_acl_plugin_control_ping_reply;\
  vapi_msg_id_t vapi_msg_id_acl_plugin_get_conn_table_max_entries;\
  vapi_msg_id_t vapi_msg_id_acl_plugin_get_conn_table_max_entries_reply;\
  vapi_msg_id_t vapi_msg_id_acl_add_replace;\
  vapi_msg_id_t vapi_msg_id_acl_add_replace_reply;\
  vapi_msg_id_t vapi_msg_id_acl_del;\
  vapi_msg_id_t vapi_msg_id_acl_del_reply;\
  vapi_msg_id_t vapi_msg_id_acl_interface_add_del;\
  vapi_msg_id_t vapi_msg_id_acl_interface_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_acl_interface_set_acl_list;\
  vapi_msg_id_t vapi_msg_id_acl_interface_set_acl_list_reply;\
  vapi_msg_id_t vapi_msg_id_acl_dump;\
  vapi_msg_id_t vapi_msg_id_acl_details;\
  vapi_msg_id_t vapi_msg_id_acl_interface_list_dump;\
  vapi_msg_id_t vapi_msg_id_acl_interface_list_details;\
  vapi_msg_id_t vapi_msg_id_macip_acl_add;\
  vapi_msg_id_t vapi_msg_id_macip_acl_add_reply;\
  vapi_msg_id_t vapi_msg_id_macip_acl_add_replace;\
  vapi_msg_id_t vapi_msg_id_macip_acl_add_replace_reply;\
  vapi_msg_id_t vapi_msg_id_macip_acl_del;\
  vapi_msg_id_t vapi_msg_id_macip_acl_del_reply;\
  vapi_msg_id_t vapi_msg_id_macip_acl_interface_add_del;\
  vapi_msg_id_t vapi_msg_id_macip_acl_interface_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_macip_acl_dump;\
  vapi_msg_id_t vapi_msg_id_macip_acl_details;\
  vapi_msg_id_t vapi_msg_id_macip_acl_interface_get;\
  vapi_msg_id_t vapi_msg_id_macip_acl_interface_get_reply;\
  vapi_msg_id_t vapi_msg_id_macip_acl_interface_list_dump;\
  vapi_msg_id_t vapi_msg_id_macip_acl_interface_list_details;\
  vapi_msg_id_t vapi_msg_id_acl_interface_set_etype_whitelist;\
  vapi_msg_id_t vapi_msg_id_acl_interface_set_etype_whitelist_reply;\
  vapi_msg_id_t vapi_msg_id_acl_interface_etype_whitelist_dump;\
  vapi_msg_id_t vapi_msg_id_acl_interface_etype_whitelist_details;\
  vapi_msg_id_t vapi_msg_id_acl_stats_intf_counters_enable;\
  vapi_msg_id_t vapi_msg_id_acl_stats_intf_counters_enable_reply;\
  vapi_msg_id_t vapi_msg_id_acl_plugin_use_hash_lookup_set;\
  vapi_msg_id_t vapi_msg_id_acl_plugin_use_hash_lookup_set_reply;\
  vapi_msg_id_t vapi_msg_id_acl_plugin_use_hash_lookup_get;\
  vapi_msg_id_t vapi_msg_id_acl_plugin_use_hash_lookup_get_reply;


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

#ifndef defined_vapi_enum_acl_action
#define defined_vapi_enum_acl_action
typedef enum {
  ACL_ACTION_API_DENY = 0,
  ACL_ACTION_API_PERMIT = 1,
  ACL_ACTION_API_PERMIT_REFLECT = 2,
} __attribute__((packed)) vapi_enum_acl_action;

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

#ifndef defined_vapi_type_acl_rule
#define defined_vapi_type_acl_rule
typedef struct __attribute__((__packed__)) {
  vapi_enum_acl_action is_permit;
  vapi_type_prefix src_prefix;
  vapi_type_prefix dst_prefix;
  vapi_enum_ip_proto proto;
  u16 srcport_or_icmptype_first;
  u16 srcport_or_icmptype_last;
  u16 dstport_or_icmpcode_first;
  u16 dstport_or_icmpcode_last;
  u8 tcp_flags_mask;
  u8 tcp_flags_value;
} vapi_type_acl_rule;

static inline void vapi_type_acl_rule_hton(vapi_type_acl_rule *msg)
{
  msg->srcport_or_icmptype_first = htobe16(msg->srcport_or_icmptype_first);
  msg->srcport_or_icmptype_last = htobe16(msg->srcport_or_icmptype_last);
  msg->dstport_or_icmpcode_first = htobe16(msg->dstport_or_icmpcode_first);
  msg->dstport_or_icmpcode_last = htobe16(msg->dstport_or_icmpcode_last);
}

static inline void vapi_type_acl_rule_ntoh(vapi_type_acl_rule *msg)
{
  msg->srcport_or_icmptype_first = be16toh(msg->srcport_or_icmptype_first);
  msg->srcport_or_icmptype_last = be16toh(msg->srcport_or_icmptype_last);
  msg->dstport_or_icmpcode_first = be16toh(msg->dstport_or_icmpcode_first);
  msg->dstport_or_icmpcode_last = be16toh(msg->dstport_or_icmpcode_last);
}
#endif

#ifndef defined_vapi_type_mac_address
#define defined_vapi_type_mac_address
typedef u8 vapi_type_mac_address[6];

#endif

#ifndef defined_vapi_type_macip_acl_rule
#define defined_vapi_type_macip_acl_rule
typedef struct __attribute__((__packed__)) {
  vapi_enum_acl_action is_permit;
  vapi_type_mac_address src_mac;
  vapi_type_mac_address src_mac_mask;
  vapi_type_prefix src_prefix;
} vapi_type_macip_acl_rule;

static inline void vapi_type_macip_acl_rule_hton(vapi_type_macip_acl_rule *msg)
{

}

static inline void vapi_type_macip_acl_rule_ntoh(vapi_type_macip_acl_rule *msg)
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

#ifndef defined_vapi_msg_acl_plugin_get_version_reply
#define defined_vapi_msg_acl_plugin_get_version_reply
typedef struct __attribute__ ((__packed__)) {
  u32 major;
  u32 minor; 
} vapi_payload_acl_plugin_get_version_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_acl_plugin_get_version_reply payload;
} vapi_msg_acl_plugin_get_version_reply;

static inline void vapi_msg_acl_plugin_get_version_reply_payload_hton(vapi_payload_acl_plugin_get_version_reply *payload)
{
  payload->major = htobe32(payload->major);
  payload->minor = htobe32(payload->minor);
}

static inline void vapi_msg_acl_plugin_get_version_reply_payload_ntoh(vapi_payload_acl_plugin_get_version_reply *payload)
{
  payload->major = be32toh(payload->major);
  payload->minor = be32toh(payload->minor);
}

static inline void vapi_msg_acl_plugin_get_version_reply_hton(vapi_msg_acl_plugin_get_version_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_plugin_get_version_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_acl_plugin_get_version_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_plugin_get_version_reply_ntoh(vapi_msg_acl_plugin_get_version_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_plugin_get_version_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_acl_plugin_get_version_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_plugin_get_version_reply_msg_size(vapi_msg_acl_plugin_get_version_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_plugin_get_version_reply_msg_size(vapi_msg_acl_plugin_get_version_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_plugin_get_version_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_plugin_get_version_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_plugin_get_version_reply));
      return -1;
    }
  if (vapi_calc_acl_plugin_get_version_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_plugin_get_version_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_plugin_get_version_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_acl_plugin_get_version_reply()
{
  static const char name[] = "acl_plugin_get_version_reply";
  static const char name_with_crc[] = "acl_plugin_get_version_reply_9b32cf86";
  static vapi_message_desc_t __vapi_metadata_acl_plugin_get_version_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_acl_plugin_get_version_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_plugin_get_version_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_plugin_get_version_reply_hton,
    (generic_swap_fn_t)vapi_msg_acl_plugin_get_version_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_plugin_get_version_reply = vapi_register_msg(&__vapi_metadata_acl_plugin_get_version_reply);
  VAPI_DBG("Assigned msg id %d to acl_plugin_get_version_reply", vapi_msg_id_acl_plugin_get_version_reply);
}

static inline void vapi_set_vapi_msg_acl_plugin_get_version_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_acl_plugin_get_version_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_acl_plugin_get_version_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_acl_plugin_get_version
#define defined_vapi_msg_acl_plugin_get_version
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_acl_plugin_get_version;

static inline void vapi_msg_acl_plugin_get_version_hton(vapi_msg_acl_plugin_get_version *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_plugin_get_version'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_acl_plugin_get_version_ntoh(vapi_msg_acl_plugin_get_version *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_plugin_get_version'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_acl_plugin_get_version_msg_size(vapi_msg_acl_plugin_get_version *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_plugin_get_version_msg_size(vapi_msg_acl_plugin_get_version *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_plugin_get_version) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_plugin_get_version' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_plugin_get_version));
      return -1;
    }
  if (vapi_calc_acl_plugin_get_version_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_plugin_get_version' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_plugin_get_version_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_acl_plugin_get_version* vapi_alloc_acl_plugin_get_version(struct vapi_ctx_s *ctx)
{
  vapi_msg_acl_plugin_get_version *msg = NULL;
  const size_t size = sizeof(vapi_msg_acl_plugin_get_version);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_acl_plugin_get_version*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_acl_plugin_get_version);

  return msg;
}

static inline vapi_error_e vapi_acl_plugin_get_version(struct vapi_ctx_s *ctx,
  vapi_msg_acl_plugin_get_version *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_acl_plugin_get_version_reply *reply),
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
  vapi_msg_acl_plugin_get_version_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_acl_plugin_get_version_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_acl_plugin_get_version_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_acl_plugin_get_version()
{
  static const char name[] = "acl_plugin_get_version";
  static const char name_with_crc[] = "acl_plugin_get_version_51077d14";
  static vapi_message_desc_t __vapi_metadata_acl_plugin_get_version = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_acl_plugin_get_version_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_plugin_get_version_hton,
    (generic_swap_fn_t)vapi_msg_acl_plugin_get_version_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_plugin_get_version = vapi_register_msg(&__vapi_metadata_acl_plugin_get_version);
  VAPI_DBG("Assigned msg id %d to acl_plugin_get_version", vapi_msg_id_acl_plugin_get_version);
}
#endif

#ifndef defined_vapi_msg_acl_plugin_control_ping_reply
#define defined_vapi_msg_acl_plugin_control_ping_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 client_index;
  u32 vpe_pid; 
} vapi_payload_acl_plugin_control_ping_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_acl_plugin_control_ping_reply payload;
} vapi_msg_acl_plugin_control_ping_reply;

static inline void vapi_msg_acl_plugin_control_ping_reply_payload_hton(vapi_payload_acl_plugin_control_ping_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->client_index = htobe32(payload->client_index);
  payload->vpe_pid = htobe32(payload->vpe_pid);
}

static inline void vapi_msg_acl_plugin_control_ping_reply_payload_ntoh(vapi_payload_acl_plugin_control_ping_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->client_index = be32toh(payload->client_index);
  payload->vpe_pid = be32toh(payload->vpe_pid);
}

static inline void vapi_msg_acl_plugin_control_ping_reply_hton(vapi_msg_acl_plugin_control_ping_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_plugin_control_ping_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_acl_plugin_control_ping_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_plugin_control_ping_reply_ntoh(vapi_msg_acl_plugin_control_ping_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_plugin_control_ping_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_acl_plugin_control_ping_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_plugin_control_ping_reply_msg_size(vapi_msg_acl_plugin_control_ping_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_plugin_control_ping_reply_msg_size(vapi_msg_acl_plugin_control_ping_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_plugin_control_ping_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_plugin_control_ping_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_plugin_control_ping_reply));
      return -1;
    }
  if (vapi_calc_acl_plugin_control_ping_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_plugin_control_ping_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_plugin_control_ping_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_acl_plugin_control_ping_reply()
{
  static const char name[] = "acl_plugin_control_ping_reply";
  static const char name_with_crc[] = "acl_plugin_control_ping_reply_f6b0b8ca";
  static vapi_message_desc_t __vapi_metadata_acl_plugin_control_ping_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_acl_plugin_control_ping_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_plugin_control_ping_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_plugin_control_ping_reply_hton,
    (generic_swap_fn_t)vapi_msg_acl_plugin_control_ping_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_plugin_control_ping_reply = vapi_register_msg(&__vapi_metadata_acl_plugin_control_ping_reply);
  VAPI_DBG("Assigned msg id %d to acl_plugin_control_ping_reply", vapi_msg_id_acl_plugin_control_ping_reply);
}

static inline void vapi_set_vapi_msg_acl_plugin_control_ping_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_acl_plugin_control_ping_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_acl_plugin_control_ping_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_acl_plugin_control_ping
#define defined_vapi_msg_acl_plugin_control_ping
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_acl_plugin_control_ping;

static inline void vapi_msg_acl_plugin_control_ping_hton(vapi_msg_acl_plugin_control_ping *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_plugin_control_ping'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_acl_plugin_control_ping_ntoh(vapi_msg_acl_plugin_control_ping *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_plugin_control_ping'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_acl_plugin_control_ping_msg_size(vapi_msg_acl_plugin_control_ping *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_plugin_control_ping_msg_size(vapi_msg_acl_plugin_control_ping *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_plugin_control_ping) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_plugin_control_ping' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_plugin_control_ping));
      return -1;
    }
  if (vapi_calc_acl_plugin_control_ping_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_plugin_control_ping' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_plugin_control_ping_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_acl_plugin_control_ping* vapi_alloc_acl_plugin_control_ping(struct vapi_ctx_s *ctx)
{
  vapi_msg_acl_plugin_control_ping *msg = NULL;
  const size_t size = sizeof(vapi_msg_acl_plugin_control_ping);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_acl_plugin_control_ping*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_acl_plugin_control_ping);

  return msg;
}

static inline vapi_error_e vapi_acl_plugin_control_ping(struct vapi_ctx_s *ctx,
  vapi_msg_acl_plugin_control_ping *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_acl_plugin_control_ping_reply *reply),
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
  vapi_msg_acl_plugin_control_ping_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_acl_plugin_control_ping_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_acl_plugin_control_ping_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_acl_plugin_control_ping()
{
  static const char name[] = "acl_plugin_control_ping";
  static const char name_with_crc[] = "acl_plugin_control_ping_51077d14";
  static vapi_message_desc_t __vapi_metadata_acl_plugin_control_ping = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_acl_plugin_control_ping_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_plugin_control_ping_hton,
    (generic_swap_fn_t)vapi_msg_acl_plugin_control_ping_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_plugin_control_ping = vapi_register_msg(&__vapi_metadata_acl_plugin_control_ping);
  VAPI_DBG("Assigned msg id %d to acl_plugin_control_ping", vapi_msg_id_acl_plugin_control_ping);
}
#endif

#ifndef defined_vapi_msg_acl_plugin_get_conn_table_max_entries_reply
#define defined_vapi_msg_acl_plugin_get_conn_table_max_entries_reply
typedef struct __attribute__ ((__packed__)) {
  u64 conn_table_max_entries; 
} vapi_payload_acl_plugin_get_conn_table_max_entries_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_acl_plugin_get_conn_table_max_entries_reply payload;
} vapi_msg_acl_plugin_get_conn_table_max_entries_reply;

static inline void vapi_msg_acl_plugin_get_conn_table_max_entries_reply_payload_hton(vapi_payload_acl_plugin_get_conn_table_max_entries_reply *payload)
{
  payload->conn_table_max_entries = htobe64(payload->conn_table_max_entries);
}

static inline void vapi_msg_acl_plugin_get_conn_table_max_entries_reply_payload_ntoh(vapi_payload_acl_plugin_get_conn_table_max_entries_reply *payload)
{
  payload->conn_table_max_entries = be64toh(payload->conn_table_max_entries);
}

static inline void vapi_msg_acl_plugin_get_conn_table_max_entries_reply_hton(vapi_msg_acl_plugin_get_conn_table_max_entries_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_plugin_get_conn_table_max_entries_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_acl_plugin_get_conn_table_max_entries_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_plugin_get_conn_table_max_entries_reply_ntoh(vapi_msg_acl_plugin_get_conn_table_max_entries_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_plugin_get_conn_table_max_entries_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_acl_plugin_get_conn_table_max_entries_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_plugin_get_conn_table_max_entries_reply_msg_size(vapi_msg_acl_plugin_get_conn_table_max_entries_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_plugin_get_conn_table_max_entries_reply_msg_size(vapi_msg_acl_plugin_get_conn_table_max_entries_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_plugin_get_conn_table_max_entries_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_plugin_get_conn_table_max_entries_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_plugin_get_conn_table_max_entries_reply));
      return -1;
    }
  if (vapi_calc_acl_plugin_get_conn_table_max_entries_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_plugin_get_conn_table_max_entries_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_plugin_get_conn_table_max_entries_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_acl_plugin_get_conn_table_max_entries_reply()
{
  static const char name[] = "acl_plugin_get_conn_table_max_entries_reply";
  static const char name_with_crc[] = "acl_plugin_get_conn_table_max_entries_reply_7a096d3d";
  static vapi_message_desc_t __vapi_metadata_acl_plugin_get_conn_table_max_entries_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_acl_plugin_get_conn_table_max_entries_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_plugin_get_conn_table_max_entries_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_plugin_get_conn_table_max_entries_reply_hton,
    (generic_swap_fn_t)vapi_msg_acl_plugin_get_conn_table_max_entries_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_plugin_get_conn_table_max_entries_reply = vapi_register_msg(&__vapi_metadata_acl_plugin_get_conn_table_max_entries_reply);
  VAPI_DBG("Assigned msg id %d to acl_plugin_get_conn_table_max_entries_reply", vapi_msg_id_acl_plugin_get_conn_table_max_entries_reply);
}

static inline void vapi_set_vapi_msg_acl_plugin_get_conn_table_max_entries_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_acl_plugin_get_conn_table_max_entries_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_acl_plugin_get_conn_table_max_entries_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_acl_plugin_get_conn_table_max_entries
#define defined_vapi_msg_acl_plugin_get_conn_table_max_entries
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_acl_plugin_get_conn_table_max_entries;

static inline void vapi_msg_acl_plugin_get_conn_table_max_entries_hton(vapi_msg_acl_plugin_get_conn_table_max_entries *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_plugin_get_conn_table_max_entries'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_acl_plugin_get_conn_table_max_entries_ntoh(vapi_msg_acl_plugin_get_conn_table_max_entries *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_plugin_get_conn_table_max_entries'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_acl_plugin_get_conn_table_max_entries_msg_size(vapi_msg_acl_plugin_get_conn_table_max_entries *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_plugin_get_conn_table_max_entries_msg_size(vapi_msg_acl_plugin_get_conn_table_max_entries *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_plugin_get_conn_table_max_entries) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_plugin_get_conn_table_max_entries' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_plugin_get_conn_table_max_entries));
      return -1;
    }
  if (vapi_calc_acl_plugin_get_conn_table_max_entries_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_plugin_get_conn_table_max_entries' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_plugin_get_conn_table_max_entries_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_acl_plugin_get_conn_table_max_entries* vapi_alloc_acl_plugin_get_conn_table_max_entries(struct vapi_ctx_s *ctx)
{
  vapi_msg_acl_plugin_get_conn_table_max_entries *msg = NULL;
  const size_t size = sizeof(vapi_msg_acl_plugin_get_conn_table_max_entries);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_acl_plugin_get_conn_table_max_entries*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_acl_plugin_get_conn_table_max_entries);

  return msg;
}

static inline vapi_error_e vapi_acl_plugin_get_conn_table_max_entries(struct vapi_ctx_s *ctx,
  vapi_msg_acl_plugin_get_conn_table_max_entries *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_acl_plugin_get_conn_table_max_entries_reply *reply),
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
  vapi_msg_acl_plugin_get_conn_table_max_entries_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_acl_plugin_get_conn_table_max_entries_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_acl_plugin_get_conn_table_max_entries_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_acl_plugin_get_conn_table_max_entries()
{
  static const char name[] = "acl_plugin_get_conn_table_max_entries";
  static const char name_with_crc[] = "acl_plugin_get_conn_table_max_entries_51077d14";
  static vapi_message_desc_t __vapi_metadata_acl_plugin_get_conn_table_max_entries = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_acl_plugin_get_conn_table_max_entries_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_plugin_get_conn_table_max_entries_hton,
    (generic_swap_fn_t)vapi_msg_acl_plugin_get_conn_table_max_entries_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_plugin_get_conn_table_max_entries = vapi_register_msg(&__vapi_metadata_acl_plugin_get_conn_table_max_entries);
  VAPI_DBG("Assigned msg id %d to acl_plugin_get_conn_table_max_entries", vapi_msg_id_acl_plugin_get_conn_table_max_entries);
}
#endif

#ifndef defined_vapi_msg_acl_add_replace_reply
#define defined_vapi_msg_acl_add_replace_reply
typedef struct __attribute__ ((__packed__)) {
  u32 acl_index;
  i32 retval; 
} vapi_payload_acl_add_replace_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_acl_add_replace_reply payload;
} vapi_msg_acl_add_replace_reply;

static inline void vapi_msg_acl_add_replace_reply_payload_hton(vapi_payload_acl_add_replace_reply *payload)
{
  payload->acl_index = htobe32(payload->acl_index);
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_acl_add_replace_reply_payload_ntoh(vapi_payload_acl_add_replace_reply *payload)
{
  payload->acl_index = be32toh(payload->acl_index);
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_acl_add_replace_reply_hton(vapi_msg_acl_add_replace_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_add_replace_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_acl_add_replace_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_add_replace_reply_ntoh(vapi_msg_acl_add_replace_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_add_replace_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_acl_add_replace_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_add_replace_reply_msg_size(vapi_msg_acl_add_replace_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_add_replace_reply_msg_size(vapi_msg_acl_add_replace_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_add_replace_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_add_replace_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_add_replace_reply));
      return -1;
    }
  if (vapi_calc_acl_add_replace_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_add_replace_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_add_replace_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_acl_add_replace_reply()
{
  static const char name[] = "acl_add_replace_reply";
  static const char name_with_crc[] = "acl_add_replace_reply_ac407b0c";
  static vapi_message_desc_t __vapi_metadata_acl_add_replace_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_acl_add_replace_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_add_replace_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_add_replace_reply_hton,
    (generic_swap_fn_t)vapi_msg_acl_add_replace_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_add_replace_reply = vapi_register_msg(&__vapi_metadata_acl_add_replace_reply);
  VAPI_DBG("Assigned msg id %d to acl_add_replace_reply", vapi_msg_id_acl_add_replace_reply);
}

static inline void vapi_set_vapi_msg_acl_add_replace_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_acl_add_replace_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_acl_add_replace_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_acl_add_replace
#define defined_vapi_msg_acl_add_replace
typedef struct __attribute__ ((__packed__)) {
  u32 acl_index;
  u8 tag[64];
  u32 count;
  vapi_type_acl_rule r[0]; 
} vapi_payload_acl_add_replace;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_acl_add_replace payload;
} vapi_msg_acl_add_replace;

static inline void vapi_msg_acl_add_replace_payload_hton(vapi_payload_acl_add_replace *payload)
{
  payload->acl_index = htobe32(payload->acl_index);
  payload->count = htobe32(payload->count);
  do { unsigned i; for (i = 0; i < be32toh(payload->count); ++i) { vapi_type_acl_rule_hton(&payload->r[i]); } } while(0);
}

static inline void vapi_msg_acl_add_replace_payload_ntoh(vapi_payload_acl_add_replace *payload)
{
  payload->acl_index = be32toh(payload->acl_index);
  payload->count = be32toh(payload->count);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { vapi_type_acl_rule_ntoh(&payload->r[i]); } } while(0);
}

static inline void vapi_msg_acl_add_replace_hton(vapi_msg_acl_add_replace *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_add_replace'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_acl_add_replace_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_add_replace_ntoh(vapi_msg_acl_add_replace *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_add_replace'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_acl_add_replace_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_add_replace_msg_size(vapi_msg_acl_add_replace *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.r[0]) * msg->payload.count;
}

static inline int vapi_verify_acl_add_replace_msg_size(vapi_msg_acl_add_replace *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_add_replace) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_add_replace' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_add_replace));
      return -1;
    }
  if (vapi_calc_acl_add_replace_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_add_replace' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_add_replace_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_acl_add_replace* vapi_alloc_acl_add_replace(struct vapi_ctx_s *ctx, size_t _r_array_size)
{
  vapi_msg_acl_add_replace *msg = NULL;
  const size_t size = sizeof(vapi_msg_acl_add_replace) + sizeof(msg->payload.r[0]) * _r_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_acl_add_replace*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_acl_add_replace);
  msg->payload.count = _r_array_size;

  return msg;
}

static inline vapi_error_e vapi_acl_add_replace(struct vapi_ctx_s *ctx,
  vapi_msg_acl_add_replace *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_acl_add_replace_reply *reply),
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
  vapi_msg_acl_add_replace_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_acl_add_replace_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_acl_add_replace_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_acl_add_replace()
{
  static const char name[] = "acl_add_replace";
  static const char name_with_crc[] = "acl_add_replace_ee5c2f18";
  static vapi_message_desc_t __vapi_metadata_acl_add_replace = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_acl_add_replace, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_add_replace_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_add_replace_hton,
    (generic_swap_fn_t)vapi_msg_acl_add_replace_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_add_replace = vapi_register_msg(&__vapi_metadata_acl_add_replace);
  VAPI_DBG("Assigned msg id %d to acl_add_replace", vapi_msg_id_acl_add_replace);
}
#endif

#ifndef defined_vapi_msg_acl_del_reply
#define defined_vapi_msg_acl_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_acl_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_acl_del_reply payload;
} vapi_msg_acl_del_reply;

static inline void vapi_msg_acl_del_reply_payload_hton(vapi_payload_acl_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_acl_del_reply_payload_ntoh(vapi_payload_acl_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_acl_del_reply_hton(vapi_msg_acl_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_acl_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_del_reply_ntoh(vapi_msg_acl_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_acl_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_del_reply_msg_size(vapi_msg_acl_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_del_reply_msg_size(vapi_msg_acl_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_del_reply));
      return -1;
    }
  if (vapi_calc_acl_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_acl_del_reply()
{
  static const char name[] = "acl_del_reply";
  static const char name_with_crc[] = "acl_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_acl_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_acl_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_acl_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_del_reply = vapi_register_msg(&__vapi_metadata_acl_del_reply);
  VAPI_DBG("Assigned msg id %d to acl_del_reply", vapi_msg_id_acl_del_reply);
}

static inline void vapi_set_vapi_msg_acl_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_acl_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_acl_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_acl_del
#define defined_vapi_msg_acl_del
typedef struct __attribute__ ((__packed__)) {
  u32 acl_index; 
} vapi_payload_acl_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_acl_del payload;
} vapi_msg_acl_del;

static inline void vapi_msg_acl_del_payload_hton(vapi_payload_acl_del *payload)
{
  payload->acl_index = htobe32(payload->acl_index);
}

static inline void vapi_msg_acl_del_payload_ntoh(vapi_payload_acl_del *payload)
{
  payload->acl_index = be32toh(payload->acl_index);
}

static inline void vapi_msg_acl_del_hton(vapi_msg_acl_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_acl_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_del_ntoh(vapi_msg_acl_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_acl_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_del_msg_size(vapi_msg_acl_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_del_msg_size(vapi_msg_acl_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_del) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_del));
      return -1;
    }
  if (vapi_calc_acl_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_acl_del* vapi_alloc_acl_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_acl_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_acl_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_acl_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_acl_del);

  return msg;
}

static inline vapi_error_e vapi_acl_del(struct vapi_ctx_s *ctx,
  vapi_msg_acl_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_acl_del_reply *reply),
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
  vapi_msg_acl_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_acl_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_acl_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_acl_del()
{
  static const char name[] = "acl_del";
  static const char name_with_crc[] = "acl_del_ef34fea4";
  static vapi_message_desc_t __vapi_metadata_acl_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_acl_del, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_del_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_del_hton,
    (generic_swap_fn_t)vapi_msg_acl_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_del = vapi_register_msg(&__vapi_metadata_acl_del);
  VAPI_DBG("Assigned msg id %d to acl_del", vapi_msg_id_acl_del);
}
#endif

#ifndef defined_vapi_msg_acl_interface_add_del_reply
#define defined_vapi_msg_acl_interface_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_acl_interface_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_acl_interface_add_del_reply payload;
} vapi_msg_acl_interface_add_del_reply;

static inline void vapi_msg_acl_interface_add_del_reply_payload_hton(vapi_payload_acl_interface_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_acl_interface_add_del_reply_payload_ntoh(vapi_payload_acl_interface_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_acl_interface_add_del_reply_hton(vapi_msg_acl_interface_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_interface_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_acl_interface_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_interface_add_del_reply_ntoh(vapi_msg_acl_interface_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_interface_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_acl_interface_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_interface_add_del_reply_msg_size(vapi_msg_acl_interface_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_interface_add_del_reply_msg_size(vapi_msg_acl_interface_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_interface_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_interface_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_interface_add_del_reply));
      return -1;
    }
  if (vapi_calc_acl_interface_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_interface_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_interface_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_acl_interface_add_del_reply()
{
  static const char name[] = "acl_interface_add_del_reply";
  static const char name_with_crc[] = "acl_interface_add_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_acl_interface_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_acl_interface_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_interface_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_interface_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_acl_interface_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_interface_add_del_reply = vapi_register_msg(&__vapi_metadata_acl_interface_add_del_reply);
  VAPI_DBG("Assigned msg id %d to acl_interface_add_del_reply", vapi_msg_id_acl_interface_add_del_reply);
}

static inline void vapi_set_vapi_msg_acl_interface_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_acl_interface_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_acl_interface_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_acl_interface_add_del
#define defined_vapi_msg_acl_interface_add_del
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  bool is_input;
  vapi_type_interface_index sw_if_index;
  u32 acl_index; 
} vapi_payload_acl_interface_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_acl_interface_add_del payload;
} vapi_msg_acl_interface_add_del;

static inline void vapi_msg_acl_interface_add_del_payload_hton(vapi_payload_acl_interface_add_del *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->acl_index = htobe32(payload->acl_index);
}

static inline void vapi_msg_acl_interface_add_del_payload_ntoh(vapi_payload_acl_interface_add_del *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->acl_index = be32toh(payload->acl_index);
}

static inline void vapi_msg_acl_interface_add_del_hton(vapi_msg_acl_interface_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_interface_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_acl_interface_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_interface_add_del_ntoh(vapi_msg_acl_interface_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_interface_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_acl_interface_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_interface_add_del_msg_size(vapi_msg_acl_interface_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_interface_add_del_msg_size(vapi_msg_acl_interface_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_interface_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_interface_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_interface_add_del));
      return -1;
    }
  if (vapi_calc_acl_interface_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_interface_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_interface_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_acl_interface_add_del* vapi_alloc_acl_interface_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_acl_interface_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_acl_interface_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_acl_interface_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_acl_interface_add_del);

  return msg;
}

static inline vapi_error_e vapi_acl_interface_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_acl_interface_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_acl_interface_add_del_reply *reply),
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
  vapi_msg_acl_interface_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_acl_interface_add_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_acl_interface_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_acl_interface_add_del()
{
  static const char name[] = "acl_interface_add_del";
  static const char name_with_crc[] = "acl_interface_add_del_4b54bebd";
  static vapi_message_desc_t __vapi_metadata_acl_interface_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_acl_interface_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_interface_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_interface_add_del_hton,
    (generic_swap_fn_t)vapi_msg_acl_interface_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_interface_add_del = vapi_register_msg(&__vapi_metadata_acl_interface_add_del);
  VAPI_DBG("Assigned msg id %d to acl_interface_add_del", vapi_msg_id_acl_interface_add_del);
}
#endif

#ifndef defined_vapi_msg_acl_interface_set_acl_list_reply
#define defined_vapi_msg_acl_interface_set_acl_list_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_acl_interface_set_acl_list_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_acl_interface_set_acl_list_reply payload;
} vapi_msg_acl_interface_set_acl_list_reply;

static inline void vapi_msg_acl_interface_set_acl_list_reply_payload_hton(vapi_payload_acl_interface_set_acl_list_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_acl_interface_set_acl_list_reply_payload_ntoh(vapi_payload_acl_interface_set_acl_list_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_acl_interface_set_acl_list_reply_hton(vapi_msg_acl_interface_set_acl_list_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_interface_set_acl_list_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_acl_interface_set_acl_list_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_interface_set_acl_list_reply_ntoh(vapi_msg_acl_interface_set_acl_list_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_interface_set_acl_list_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_acl_interface_set_acl_list_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_interface_set_acl_list_reply_msg_size(vapi_msg_acl_interface_set_acl_list_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_interface_set_acl_list_reply_msg_size(vapi_msg_acl_interface_set_acl_list_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_interface_set_acl_list_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_interface_set_acl_list_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_interface_set_acl_list_reply));
      return -1;
    }
  if (vapi_calc_acl_interface_set_acl_list_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_interface_set_acl_list_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_interface_set_acl_list_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_acl_interface_set_acl_list_reply()
{
  static const char name[] = "acl_interface_set_acl_list_reply";
  static const char name_with_crc[] = "acl_interface_set_acl_list_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_acl_interface_set_acl_list_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_acl_interface_set_acl_list_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_interface_set_acl_list_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_interface_set_acl_list_reply_hton,
    (generic_swap_fn_t)vapi_msg_acl_interface_set_acl_list_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_interface_set_acl_list_reply = vapi_register_msg(&__vapi_metadata_acl_interface_set_acl_list_reply);
  VAPI_DBG("Assigned msg id %d to acl_interface_set_acl_list_reply", vapi_msg_id_acl_interface_set_acl_list_reply);
}

static inline void vapi_set_vapi_msg_acl_interface_set_acl_list_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_acl_interface_set_acl_list_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_acl_interface_set_acl_list_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_acl_interface_set_acl_list
#define defined_vapi_msg_acl_interface_set_acl_list
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u8 count;
  u8 n_input;
  u32 acls[0]; 
} vapi_payload_acl_interface_set_acl_list;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_acl_interface_set_acl_list payload;
} vapi_msg_acl_interface_set_acl_list;

static inline void vapi_msg_acl_interface_set_acl_list_payload_hton(vapi_payload_acl_interface_set_acl_list *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { payload->acls[i] = htobe32(payload->acls[i]); } } while(0);
}

static inline void vapi_msg_acl_interface_set_acl_list_payload_ntoh(vapi_payload_acl_interface_set_acl_list *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { payload->acls[i] = be32toh(payload->acls[i]); } } while(0);
}

static inline void vapi_msg_acl_interface_set_acl_list_hton(vapi_msg_acl_interface_set_acl_list *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_interface_set_acl_list'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_acl_interface_set_acl_list_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_interface_set_acl_list_ntoh(vapi_msg_acl_interface_set_acl_list *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_interface_set_acl_list'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_acl_interface_set_acl_list_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_interface_set_acl_list_msg_size(vapi_msg_acl_interface_set_acl_list *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.acls[0]) * msg->payload.count;
}

static inline int vapi_verify_acl_interface_set_acl_list_msg_size(vapi_msg_acl_interface_set_acl_list *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_interface_set_acl_list) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_interface_set_acl_list' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_interface_set_acl_list));
      return -1;
    }
  if (vapi_calc_acl_interface_set_acl_list_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_interface_set_acl_list' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_interface_set_acl_list_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_acl_interface_set_acl_list* vapi_alloc_acl_interface_set_acl_list(struct vapi_ctx_s *ctx, size_t _acls_array_size)
{
  vapi_msg_acl_interface_set_acl_list *msg = NULL;
  const size_t size = sizeof(vapi_msg_acl_interface_set_acl_list) + sizeof(msg->payload.acls[0]) * _acls_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_acl_interface_set_acl_list*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_acl_interface_set_acl_list);
  msg->payload.count = _acls_array_size;

  return msg;
}

static inline vapi_error_e vapi_acl_interface_set_acl_list(struct vapi_ctx_s *ctx,
  vapi_msg_acl_interface_set_acl_list *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_acl_interface_set_acl_list_reply *reply),
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
  vapi_msg_acl_interface_set_acl_list_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_acl_interface_set_acl_list_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_acl_interface_set_acl_list_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_acl_interface_set_acl_list()
{
  static const char name[] = "acl_interface_set_acl_list";
  static const char name_with_crc[] = "acl_interface_set_acl_list_473982bd";
  static vapi_message_desc_t __vapi_metadata_acl_interface_set_acl_list = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_acl_interface_set_acl_list, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_interface_set_acl_list_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_interface_set_acl_list_hton,
    (generic_swap_fn_t)vapi_msg_acl_interface_set_acl_list_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_interface_set_acl_list = vapi_register_msg(&__vapi_metadata_acl_interface_set_acl_list);
  VAPI_DBG("Assigned msg id %d to acl_interface_set_acl_list", vapi_msg_id_acl_interface_set_acl_list);
}
#endif

#ifndef defined_vapi_msg_acl_details
#define defined_vapi_msg_acl_details
typedef struct __attribute__ ((__packed__)) {
  u32 acl_index;
  u8 tag[64];
  u32 count;
  vapi_type_acl_rule r[0]; 
} vapi_payload_acl_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_acl_details payload;
} vapi_msg_acl_details;

static inline void vapi_msg_acl_details_payload_hton(vapi_payload_acl_details *payload)
{
  payload->acl_index = htobe32(payload->acl_index);
  payload->count = htobe32(payload->count);
  do { unsigned i; for (i = 0; i < be32toh(payload->count); ++i) { vapi_type_acl_rule_hton(&payload->r[i]); } } while(0);
}

static inline void vapi_msg_acl_details_payload_ntoh(vapi_payload_acl_details *payload)
{
  payload->acl_index = be32toh(payload->acl_index);
  payload->count = be32toh(payload->count);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { vapi_type_acl_rule_ntoh(&payload->r[i]); } } while(0);
}

static inline void vapi_msg_acl_details_hton(vapi_msg_acl_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_acl_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_details_ntoh(vapi_msg_acl_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_acl_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_details_msg_size(vapi_msg_acl_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.r[0]) * msg->payload.count;
}

static inline int vapi_verify_acl_details_msg_size(vapi_msg_acl_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_details) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_details));
      return -1;
    }
  if (vapi_calc_acl_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_acl_details()
{
  static const char name[] = "acl_details";
  static const char name_with_crc[] = "acl_details_95babae0";
  static vapi_message_desc_t __vapi_metadata_acl_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_acl_details, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_details_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_details_hton,
    (generic_swap_fn_t)vapi_msg_acl_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_details = vapi_register_msg(&__vapi_metadata_acl_details);
  VAPI_DBG("Assigned msg id %d to acl_details", vapi_msg_id_acl_details);
}

static inline void vapi_set_vapi_msg_acl_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_acl_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_acl_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_acl_dump
#define defined_vapi_msg_acl_dump
typedef struct __attribute__ ((__packed__)) {
  u32 acl_index; 
} vapi_payload_acl_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_acl_dump payload;
} vapi_msg_acl_dump;

static inline void vapi_msg_acl_dump_payload_hton(vapi_payload_acl_dump *payload)
{
  payload->acl_index = htobe32(payload->acl_index);
}

static inline void vapi_msg_acl_dump_payload_ntoh(vapi_payload_acl_dump *payload)
{
  payload->acl_index = be32toh(payload->acl_index);
}

static inline void vapi_msg_acl_dump_hton(vapi_msg_acl_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_acl_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_dump_ntoh(vapi_msg_acl_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_acl_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_dump_msg_size(vapi_msg_acl_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_dump_msg_size(vapi_msg_acl_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_dump));
      return -1;
    }
  if (vapi_calc_acl_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_acl_dump* vapi_alloc_acl_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_acl_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_acl_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_acl_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_acl_dump);

  return msg;
}

static inline vapi_error_e vapi_acl_dump(struct vapi_ctx_s *ctx,
  vapi_msg_acl_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_acl_details *reply),
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
  vapi_msg_acl_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_acl_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_acl_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_acl_dump()
{
  static const char name[] = "acl_dump";
  static const char name_with_crc[] = "acl_dump_ef34fea4";
  static vapi_message_desc_t __vapi_metadata_acl_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_acl_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_dump_hton,
    (generic_swap_fn_t)vapi_msg_acl_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_dump = vapi_register_msg(&__vapi_metadata_acl_dump);
  VAPI_DBG("Assigned msg id %d to acl_dump", vapi_msg_id_acl_dump);
}
#endif

#ifndef defined_vapi_msg_acl_interface_list_details
#define defined_vapi_msg_acl_interface_list_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u8 count;
  u8 n_input;
  u32 acls[0]; 
} vapi_payload_acl_interface_list_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_acl_interface_list_details payload;
} vapi_msg_acl_interface_list_details;

static inline void vapi_msg_acl_interface_list_details_payload_hton(vapi_payload_acl_interface_list_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { payload->acls[i] = htobe32(payload->acls[i]); } } while(0);
}

static inline void vapi_msg_acl_interface_list_details_payload_ntoh(vapi_payload_acl_interface_list_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { payload->acls[i] = be32toh(payload->acls[i]); } } while(0);
}

static inline void vapi_msg_acl_interface_list_details_hton(vapi_msg_acl_interface_list_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_interface_list_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_acl_interface_list_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_interface_list_details_ntoh(vapi_msg_acl_interface_list_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_interface_list_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_acl_interface_list_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_interface_list_details_msg_size(vapi_msg_acl_interface_list_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.acls[0]) * msg->payload.count;
}

static inline int vapi_verify_acl_interface_list_details_msg_size(vapi_msg_acl_interface_list_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_interface_list_details) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_interface_list_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_interface_list_details));
      return -1;
    }
  if (vapi_calc_acl_interface_list_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_interface_list_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_interface_list_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_acl_interface_list_details()
{
  static const char name[] = "acl_interface_list_details";
  static const char name_with_crc[] = "acl_interface_list_details_e695d256";
  static vapi_message_desc_t __vapi_metadata_acl_interface_list_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_acl_interface_list_details, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_interface_list_details_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_interface_list_details_hton,
    (generic_swap_fn_t)vapi_msg_acl_interface_list_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_interface_list_details = vapi_register_msg(&__vapi_metadata_acl_interface_list_details);
  VAPI_DBG("Assigned msg id %d to acl_interface_list_details", vapi_msg_id_acl_interface_list_details);
}

static inline void vapi_set_vapi_msg_acl_interface_list_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_acl_interface_list_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_acl_interface_list_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_acl_interface_list_dump
#define defined_vapi_msg_acl_interface_list_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_acl_interface_list_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_acl_interface_list_dump payload;
} vapi_msg_acl_interface_list_dump;

static inline void vapi_msg_acl_interface_list_dump_payload_hton(vapi_payload_acl_interface_list_dump *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_acl_interface_list_dump_payload_ntoh(vapi_payload_acl_interface_list_dump *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_acl_interface_list_dump_hton(vapi_msg_acl_interface_list_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_interface_list_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_acl_interface_list_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_interface_list_dump_ntoh(vapi_msg_acl_interface_list_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_interface_list_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_acl_interface_list_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_interface_list_dump_msg_size(vapi_msg_acl_interface_list_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_interface_list_dump_msg_size(vapi_msg_acl_interface_list_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_interface_list_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_interface_list_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_interface_list_dump));
      return -1;
    }
  if (vapi_calc_acl_interface_list_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_interface_list_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_interface_list_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_acl_interface_list_dump* vapi_alloc_acl_interface_list_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_acl_interface_list_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_acl_interface_list_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_acl_interface_list_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_acl_interface_list_dump);

  return msg;
}

static inline vapi_error_e vapi_acl_interface_list_dump(struct vapi_ctx_s *ctx,
  vapi_msg_acl_interface_list_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_acl_interface_list_details *reply),
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
  vapi_msg_acl_interface_list_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_acl_interface_list_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_acl_interface_list_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_acl_interface_list_dump()
{
  static const char name[] = "acl_interface_list_dump";
  static const char name_with_crc[] = "acl_interface_list_dump_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_acl_interface_list_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_acl_interface_list_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_interface_list_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_interface_list_dump_hton,
    (generic_swap_fn_t)vapi_msg_acl_interface_list_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_interface_list_dump = vapi_register_msg(&__vapi_metadata_acl_interface_list_dump);
  VAPI_DBG("Assigned msg id %d to acl_interface_list_dump", vapi_msg_id_acl_interface_list_dump);
}
#endif

#ifndef defined_vapi_msg_macip_acl_add_reply
#define defined_vapi_msg_macip_acl_add_reply
typedef struct __attribute__ ((__packed__)) {
  u32 acl_index;
  i32 retval; 
} vapi_payload_macip_acl_add_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_macip_acl_add_reply payload;
} vapi_msg_macip_acl_add_reply;

static inline void vapi_msg_macip_acl_add_reply_payload_hton(vapi_payload_macip_acl_add_reply *payload)
{
  payload->acl_index = htobe32(payload->acl_index);
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_macip_acl_add_reply_payload_ntoh(vapi_payload_macip_acl_add_reply *payload)
{
  payload->acl_index = be32toh(payload->acl_index);
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_macip_acl_add_reply_hton(vapi_msg_macip_acl_add_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_add_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_macip_acl_add_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_macip_acl_add_reply_ntoh(vapi_msg_macip_acl_add_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_add_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_macip_acl_add_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_macip_acl_add_reply_msg_size(vapi_msg_macip_acl_add_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_macip_acl_add_reply_msg_size(vapi_msg_macip_acl_add_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_macip_acl_add_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_add_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_macip_acl_add_reply));
      return -1;
    }
  if (vapi_calc_macip_acl_add_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_add_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_macip_acl_add_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_macip_acl_add_reply()
{
  static const char name[] = "macip_acl_add_reply";
  static const char name_with_crc[] = "macip_acl_add_reply_ac407b0c";
  static vapi_message_desc_t __vapi_metadata_macip_acl_add_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_macip_acl_add_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_macip_acl_add_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_macip_acl_add_reply_hton,
    (generic_swap_fn_t)vapi_msg_macip_acl_add_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_macip_acl_add_reply = vapi_register_msg(&__vapi_metadata_macip_acl_add_reply);
  VAPI_DBG("Assigned msg id %d to macip_acl_add_reply", vapi_msg_id_macip_acl_add_reply);
}

static inline void vapi_set_vapi_msg_macip_acl_add_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_macip_acl_add_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_macip_acl_add_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_macip_acl_add
#define defined_vapi_msg_macip_acl_add
typedef struct __attribute__ ((__packed__)) {
  u8 tag[64];
  u32 count;
  vapi_type_macip_acl_rule r[0]; 
} vapi_payload_macip_acl_add;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_macip_acl_add payload;
} vapi_msg_macip_acl_add;

static inline void vapi_msg_macip_acl_add_payload_hton(vapi_payload_macip_acl_add *payload)
{
  payload->count = htobe32(payload->count);
}

static inline void vapi_msg_macip_acl_add_payload_ntoh(vapi_payload_macip_acl_add *payload)
{
  payload->count = be32toh(payload->count);
}

static inline void vapi_msg_macip_acl_add_hton(vapi_msg_macip_acl_add *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_add'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_macip_acl_add_payload_hton(&msg->payload);
}

static inline void vapi_msg_macip_acl_add_ntoh(vapi_msg_macip_acl_add *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_add'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_macip_acl_add_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_macip_acl_add_msg_size(vapi_msg_macip_acl_add *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.r[0]) * msg->payload.count;
}

static inline int vapi_verify_macip_acl_add_msg_size(vapi_msg_macip_acl_add *msg, uword buf_size)
{
  if (sizeof(vapi_msg_macip_acl_add) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_add' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_macip_acl_add));
      return -1;
    }
  if (vapi_calc_macip_acl_add_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_add' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_macip_acl_add_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_macip_acl_add* vapi_alloc_macip_acl_add(struct vapi_ctx_s *ctx, size_t _r_array_size)
{
  vapi_msg_macip_acl_add *msg = NULL;
  const size_t size = sizeof(vapi_msg_macip_acl_add) + sizeof(msg->payload.r[0]) * _r_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_macip_acl_add*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_macip_acl_add);
  msg->payload.count = _r_array_size;

  return msg;
}

static inline vapi_error_e vapi_macip_acl_add(struct vapi_ctx_s *ctx,
  vapi_msg_macip_acl_add *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_macip_acl_add_reply *reply),
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
  vapi_msg_macip_acl_add_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_macip_acl_add_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_macip_acl_add_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_macip_acl_add()
{
  static const char name[] = "macip_acl_add";
  static const char name_with_crc[] = "macip_acl_add_ce6fbad0";
  static vapi_message_desc_t __vapi_metadata_macip_acl_add = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_macip_acl_add, payload),
    (verify_msg_size_fn_t)vapi_verify_macip_acl_add_msg_size,
    (generic_swap_fn_t)vapi_msg_macip_acl_add_hton,
    (generic_swap_fn_t)vapi_msg_macip_acl_add_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_macip_acl_add = vapi_register_msg(&__vapi_metadata_macip_acl_add);
  VAPI_DBG("Assigned msg id %d to macip_acl_add", vapi_msg_id_macip_acl_add);
}
#endif

#ifndef defined_vapi_msg_macip_acl_add_replace_reply
#define defined_vapi_msg_macip_acl_add_replace_reply
typedef struct __attribute__ ((__packed__)) {
  u32 acl_index;
  i32 retval; 
} vapi_payload_macip_acl_add_replace_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_macip_acl_add_replace_reply payload;
} vapi_msg_macip_acl_add_replace_reply;

static inline void vapi_msg_macip_acl_add_replace_reply_payload_hton(vapi_payload_macip_acl_add_replace_reply *payload)
{
  payload->acl_index = htobe32(payload->acl_index);
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_macip_acl_add_replace_reply_payload_ntoh(vapi_payload_macip_acl_add_replace_reply *payload)
{
  payload->acl_index = be32toh(payload->acl_index);
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_macip_acl_add_replace_reply_hton(vapi_msg_macip_acl_add_replace_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_add_replace_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_macip_acl_add_replace_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_macip_acl_add_replace_reply_ntoh(vapi_msg_macip_acl_add_replace_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_add_replace_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_macip_acl_add_replace_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_macip_acl_add_replace_reply_msg_size(vapi_msg_macip_acl_add_replace_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_macip_acl_add_replace_reply_msg_size(vapi_msg_macip_acl_add_replace_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_macip_acl_add_replace_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_add_replace_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_macip_acl_add_replace_reply));
      return -1;
    }
  if (vapi_calc_macip_acl_add_replace_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_add_replace_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_macip_acl_add_replace_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_macip_acl_add_replace_reply()
{
  static const char name[] = "macip_acl_add_replace_reply";
  static const char name_with_crc[] = "macip_acl_add_replace_reply_ac407b0c";
  static vapi_message_desc_t __vapi_metadata_macip_acl_add_replace_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_macip_acl_add_replace_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_macip_acl_add_replace_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_macip_acl_add_replace_reply_hton,
    (generic_swap_fn_t)vapi_msg_macip_acl_add_replace_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_macip_acl_add_replace_reply = vapi_register_msg(&__vapi_metadata_macip_acl_add_replace_reply);
  VAPI_DBG("Assigned msg id %d to macip_acl_add_replace_reply", vapi_msg_id_macip_acl_add_replace_reply);
}

static inline void vapi_set_vapi_msg_macip_acl_add_replace_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_macip_acl_add_replace_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_macip_acl_add_replace_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_macip_acl_add_replace
#define defined_vapi_msg_macip_acl_add_replace
typedef struct __attribute__ ((__packed__)) {
  u32 acl_index;
  u8 tag[64];
  u32 count;
  vapi_type_macip_acl_rule r[0]; 
} vapi_payload_macip_acl_add_replace;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_macip_acl_add_replace payload;
} vapi_msg_macip_acl_add_replace;

static inline void vapi_msg_macip_acl_add_replace_payload_hton(vapi_payload_macip_acl_add_replace *payload)
{
  payload->acl_index = htobe32(payload->acl_index);
  payload->count = htobe32(payload->count);
}

static inline void vapi_msg_macip_acl_add_replace_payload_ntoh(vapi_payload_macip_acl_add_replace *payload)
{
  payload->acl_index = be32toh(payload->acl_index);
  payload->count = be32toh(payload->count);
}

static inline void vapi_msg_macip_acl_add_replace_hton(vapi_msg_macip_acl_add_replace *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_add_replace'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_macip_acl_add_replace_payload_hton(&msg->payload);
}

static inline void vapi_msg_macip_acl_add_replace_ntoh(vapi_msg_macip_acl_add_replace *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_add_replace'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_macip_acl_add_replace_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_macip_acl_add_replace_msg_size(vapi_msg_macip_acl_add_replace *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.r[0]) * msg->payload.count;
}

static inline int vapi_verify_macip_acl_add_replace_msg_size(vapi_msg_macip_acl_add_replace *msg, uword buf_size)
{
  if (sizeof(vapi_msg_macip_acl_add_replace) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_add_replace' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_macip_acl_add_replace));
      return -1;
    }
  if (vapi_calc_macip_acl_add_replace_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_add_replace' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_macip_acl_add_replace_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_macip_acl_add_replace* vapi_alloc_macip_acl_add_replace(struct vapi_ctx_s *ctx, size_t _r_array_size)
{
  vapi_msg_macip_acl_add_replace *msg = NULL;
  const size_t size = sizeof(vapi_msg_macip_acl_add_replace) + sizeof(msg->payload.r[0]) * _r_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_macip_acl_add_replace*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_macip_acl_add_replace);
  msg->payload.count = _r_array_size;

  return msg;
}

static inline vapi_error_e vapi_macip_acl_add_replace(struct vapi_ctx_s *ctx,
  vapi_msg_macip_acl_add_replace *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_macip_acl_add_replace_reply *reply),
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
  vapi_msg_macip_acl_add_replace_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_macip_acl_add_replace_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_macip_acl_add_replace_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_macip_acl_add_replace()
{
  static const char name[] = "macip_acl_add_replace";
  static const char name_with_crc[] = "macip_acl_add_replace_2a461dd4";
  static vapi_message_desc_t __vapi_metadata_macip_acl_add_replace = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_macip_acl_add_replace, payload),
    (verify_msg_size_fn_t)vapi_verify_macip_acl_add_replace_msg_size,
    (generic_swap_fn_t)vapi_msg_macip_acl_add_replace_hton,
    (generic_swap_fn_t)vapi_msg_macip_acl_add_replace_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_macip_acl_add_replace = vapi_register_msg(&__vapi_metadata_macip_acl_add_replace);
  VAPI_DBG("Assigned msg id %d to macip_acl_add_replace", vapi_msg_id_macip_acl_add_replace);
}
#endif

#ifndef defined_vapi_msg_macip_acl_del_reply
#define defined_vapi_msg_macip_acl_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_macip_acl_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_macip_acl_del_reply payload;
} vapi_msg_macip_acl_del_reply;

static inline void vapi_msg_macip_acl_del_reply_payload_hton(vapi_payload_macip_acl_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_macip_acl_del_reply_payload_ntoh(vapi_payload_macip_acl_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_macip_acl_del_reply_hton(vapi_msg_macip_acl_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_macip_acl_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_macip_acl_del_reply_ntoh(vapi_msg_macip_acl_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_macip_acl_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_macip_acl_del_reply_msg_size(vapi_msg_macip_acl_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_macip_acl_del_reply_msg_size(vapi_msg_macip_acl_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_macip_acl_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_macip_acl_del_reply));
      return -1;
    }
  if (vapi_calc_macip_acl_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_macip_acl_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_macip_acl_del_reply()
{
  static const char name[] = "macip_acl_del_reply";
  static const char name_with_crc[] = "macip_acl_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_macip_acl_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_macip_acl_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_macip_acl_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_macip_acl_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_macip_acl_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_macip_acl_del_reply = vapi_register_msg(&__vapi_metadata_macip_acl_del_reply);
  VAPI_DBG("Assigned msg id %d to macip_acl_del_reply", vapi_msg_id_macip_acl_del_reply);
}

static inline void vapi_set_vapi_msg_macip_acl_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_macip_acl_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_macip_acl_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_macip_acl_del
#define defined_vapi_msg_macip_acl_del
typedef struct __attribute__ ((__packed__)) {
  u32 acl_index; 
} vapi_payload_macip_acl_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_macip_acl_del payload;
} vapi_msg_macip_acl_del;

static inline void vapi_msg_macip_acl_del_payload_hton(vapi_payload_macip_acl_del *payload)
{
  payload->acl_index = htobe32(payload->acl_index);
}

static inline void vapi_msg_macip_acl_del_payload_ntoh(vapi_payload_macip_acl_del *payload)
{
  payload->acl_index = be32toh(payload->acl_index);
}

static inline void vapi_msg_macip_acl_del_hton(vapi_msg_macip_acl_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_macip_acl_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_macip_acl_del_ntoh(vapi_msg_macip_acl_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_macip_acl_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_macip_acl_del_msg_size(vapi_msg_macip_acl_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_macip_acl_del_msg_size(vapi_msg_macip_acl_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_macip_acl_del) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_macip_acl_del));
      return -1;
    }
  if (vapi_calc_macip_acl_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_macip_acl_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_macip_acl_del* vapi_alloc_macip_acl_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_macip_acl_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_macip_acl_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_macip_acl_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_macip_acl_del);

  return msg;
}

static inline vapi_error_e vapi_macip_acl_del(struct vapi_ctx_s *ctx,
  vapi_msg_macip_acl_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_macip_acl_del_reply *reply),
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
  vapi_msg_macip_acl_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_macip_acl_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_macip_acl_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_macip_acl_del()
{
  static const char name[] = "macip_acl_del";
  static const char name_with_crc[] = "macip_acl_del_ef34fea4";
  static vapi_message_desc_t __vapi_metadata_macip_acl_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_macip_acl_del, payload),
    (verify_msg_size_fn_t)vapi_verify_macip_acl_del_msg_size,
    (generic_swap_fn_t)vapi_msg_macip_acl_del_hton,
    (generic_swap_fn_t)vapi_msg_macip_acl_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_macip_acl_del = vapi_register_msg(&__vapi_metadata_macip_acl_del);
  VAPI_DBG("Assigned msg id %d to macip_acl_del", vapi_msg_id_macip_acl_del);
}
#endif

#ifndef defined_vapi_msg_macip_acl_interface_add_del_reply
#define defined_vapi_msg_macip_acl_interface_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_macip_acl_interface_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_macip_acl_interface_add_del_reply payload;
} vapi_msg_macip_acl_interface_add_del_reply;

static inline void vapi_msg_macip_acl_interface_add_del_reply_payload_hton(vapi_payload_macip_acl_interface_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_macip_acl_interface_add_del_reply_payload_ntoh(vapi_payload_macip_acl_interface_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_macip_acl_interface_add_del_reply_hton(vapi_msg_macip_acl_interface_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_interface_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_macip_acl_interface_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_macip_acl_interface_add_del_reply_ntoh(vapi_msg_macip_acl_interface_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_interface_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_macip_acl_interface_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_macip_acl_interface_add_del_reply_msg_size(vapi_msg_macip_acl_interface_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_macip_acl_interface_add_del_reply_msg_size(vapi_msg_macip_acl_interface_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_macip_acl_interface_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_interface_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_macip_acl_interface_add_del_reply));
      return -1;
    }
  if (vapi_calc_macip_acl_interface_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_interface_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_macip_acl_interface_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_macip_acl_interface_add_del_reply()
{
  static const char name[] = "macip_acl_interface_add_del_reply";
  static const char name_with_crc[] = "macip_acl_interface_add_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_macip_acl_interface_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_macip_acl_interface_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_macip_acl_interface_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_macip_acl_interface_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_macip_acl_interface_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_macip_acl_interface_add_del_reply = vapi_register_msg(&__vapi_metadata_macip_acl_interface_add_del_reply);
  VAPI_DBG("Assigned msg id %d to macip_acl_interface_add_del_reply", vapi_msg_id_macip_acl_interface_add_del_reply);
}

static inline void vapi_set_vapi_msg_macip_acl_interface_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_macip_acl_interface_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_macip_acl_interface_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_macip_acl_interface_add_del
#define defined_vapi_msg_macip_acl_interface_add_del
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_interface_index sw_if_index;
  u32 acl_index; 
} vapi_payload_macip_acl_interface_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_macip_acl_interface_add_del payload;
} vapi_msg_macip_acl_interface_add_del;

static inline void vapi_msg_macip_acl_interface_add_del_payload_hton(vapi_payload_macip_acl_interface_add_del *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->acl_index = htobe32(payload->acl_index);
}

static inline void vapi_msg_macip_acl_interface_add_del_payload_ntoh(vapi_payload_macip_acl_interface_add_del *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->acl_index = be32toh(payload->acl_index);
}

static inline void vapi_msg_macip_acl_interface_add_del_hton(vapi_msg_macip_acl_interface_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_interface_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_macip_acl_interface_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_macip_acl_interface_add_del_ntoh(vapi_msg_macip_acl_interface_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_interface_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_macip_acl_interface_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_macip_acl_interface_add_del_msg_size(vapi_msg_macip_acl_interface_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_macip_acl_interface_add_del_msg_size(vapi_msg_macip_acl_interface_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_macip_acl_interface_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_interface_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_macip_acl_interface_add_del));
      return -1;
    }
  if (vapi_calc_macip_acl_interface_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_interface_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_macip_acl_interface_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_macip_acl_interface_add_del* vapi_alloc_macip_acl_interface_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_macip_acl_interface_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_macip_acl_interface_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_macip_acl_interface_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_macip_acl_interface_add_del);

  return msg;
}

static inline vapi_error_e vapi_macip_acl_interface_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_macip_acl_interface_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_macip_acl_interface_add_del_reply *reply),
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
  vapi_msg_macip_acl_interface_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_macip_acl_interface_add_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_macip_acl_interface_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_macip_acl_interface_add_del()
{
  static const char name[] = "macip_acl_interface_add_del";
  static const char name_with_crc[] = "macip_acl_interface_add_del_4b8690b1";
  static vapi_message_desc_t __vapi_metadata_macip_acl_interface_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_macip_acl_interface_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_macip_acl_interface_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_macip_acl_interface_add_del_hton,
    (generic_swap_fn_t)vapi_msg_macip_acl_interface_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_macip_acl_interface_add_del = vapi_register_msg(&__vapi_metadata_macip_acl_interface_add_del);
  VAPI_DBG("Assigned msg id %d to macip_acl_interface_add_del", vapi_msg_id_macip_acl_interface_add_del);
}
#endif

#ifndef defined_vapi_msg_macip_acl_details
#define defined_vapi_msg_macip_acl_details
typedef struct __attribute__ ((__packed__)) {
  u32 acl_index;
  u8 tag[64];
  u32 count;
  vapi_type_macip_acl_rule r[0]; 
} vapi_payload_macip_acl_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_macip_acl_details payload;
} vapi_msg_macip_acl_details;

static inline void vapi_msg_macip_acl_details_payload_hton(vapi_payload_macip_acl_details *payload)
{
  payload->acl_index = htobe32(payload->acl_index);
  payload->count = htobe32(payload->count);
}

static inline void vapi_msg_macip_acl_details_payload_ntoh(vapi_payload_macip_acl_details *payload)
{
  payload->acl_index = be32toh(payload->acl_index);
  payload->count = be32toh(payload->count);
}

static inline void vapi_msg_macip_acl_details_hton(vapi_msg_macip_acl_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_macip_acl_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_macip_acl_details_ntoh(vapi_msg_macip_acl_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_macip_acl_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_macip_acl_details_msg_size(vapi_msg_macip_acl_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.r[0]) * msg->payload.count;
}

static inline int vapi_verify_macip_acl_details_msg_size(vapi_msg_macip_acl_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_macip_acl_details) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_macip_acl_details));
      return -1;
    }
  if (vapi_calc_macip_acl_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_macip_acl_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_macip_acl_details()
{
  static const char name[] = "macip_acl_details";
  static const char name_with_crc[] = "macip_acl_details_27135b59";
  static vapi_message_desc_t __vapi_metadata_macip_acl_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_macip_acl_details, payload),
    (verify_msg_size_fn_t)vapi_verify_macip_acl_details_msg_size,
    (generic_swap_fn_t)vapi_msg_macip_acl_details_hton,
    (generic_swap_fn_t)vapi_msg_macip_acl_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_macip_acl_details = vapi_register_msg(&__vapi_metadata_macip_acl_details);
  VAPI_DBG("Assigned msg id %d to macip_acl_details", vapi_msg_id_macip_acl_details);
}

static inline void vapi_set_vapi_msg_macip_acl_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_macip_acl_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_macip_acl_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_macip_acl_dump
#define defined_vapi_msg_macip_acl_dump
typedef struct __attribute__ ((__packed__)) {
  u32 acl_index; 
} vapi_payload_macip_acl_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_macip_acl_dump payload;
} vapi_msg_macip_acl_dump;

static inline void vapi_msg_macip_acl_dump_payload_hton(vapi_payload_macip_acl_dump *payload)
{
  payload->acl_index = htobe32(payload->acl_index);
}

static inline void vapi_msg_macip_acl_dump_payload_ntoh(vapi_payload_macip_acl_dump *payload)
{
  payload->acl_index = be32toh(payload->acl_index);
}

static inline void vapi_msg_macip_acl_dump_hton(vapi_msg_macip_acl_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_macip_acl_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_macip_acl_dump_ntoh(vapi_msg_macip_acl_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_macip_acl_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_macip_acl_dump_msg_size(vapi_msg_macip_acl_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_macip_acl_dump_msg_size(vapi_msg_macip_acl_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_macip_acl_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_macip_acl_dump));
      return -1;
    }
  if (vapi_calc_macip_acl_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_macip_acl_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_macip_acl_dump* vapi_alloc_macip_acl_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_macip_acl_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_macip_acl_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_macip_acl_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_macip_acl_dump);

  return msg;
}

static inline vapi_error_e vapi_macip_acl_dump(struct vapi_ctx_s *ctx,
  vapi_msg_macip_acl_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_macip_acl_details *reply),
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
  vapi_msg_macip_acl_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_macip_acl_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_macip_acl_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_macip_acl_dump()
{
  static const char name[] = "macip_acl_dump";
  static const char name_with_crc[] = "macip_acl_dump_ef34fea4";
  static vapi_message_desc_t __vapi_metadata_macip_acl_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_macip_acl_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_macip_acl_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_macip_acl_dump_hton,
    (generic_swap_fn_t)vapi_msg_macip_acl_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_macip_acl_dump = vapi_register_msg(&__vapi_metadata_macip_acl_dump);
  VAPI_DBG("Assigned msg id %d to macip_acl_dump", vapi_msg_id_macip_acl_dump);
}
#endif

#ifndef defined_vapi_msg_macip_acl_interface_get_reply
#define defined_vapi_msg_macip_acl_interface_get_reply
typedef struct __attribute__ ((__packed__)) {
  u32 count;
  u32 acls[0]; 
} vapi_payload_macip_acl_interface_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_macip_acl_interface_get_reply payload;
} vapi_msg_macip_acl_interface_get_reply;

static inline void vapi_msg_macip_acl_interface_get_reply_payload_hton(vapi_payload_macip_acl_interface_get_reply *payload)
{
  payload->count = htobe32(payload->count);
  do { unsigned i; for (i = 0; i < be32toh(payload->count); ++i) { payload->acls[i] = htobe32(payload->acls[i]); } } while(0);
}

static inline void vapi_msg_macip_acl_interface_get_reply_payload_ntoh(vapi_payload_macip_acl_interface_get_reply *payload)
{
  payload->count = be32toh(payload->count);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { payload->acls[i] = be32toh(payload->acls[i]); } } while(0);
}

static inline void vapi_msg_macip_acl_interface_get_reply_hton(vapi_msg_macip_acl_interface_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_interface_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_macip_acl_interface_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_macip_acl_interface_get_reply_ntoh(vapi_msg_macip_acl_interface_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_interface_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_macip_acl_interface_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_macip_acl_interface_get_reply_msg_size(vapi_msg_macip_acl_interface_get_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.acls[0]) * msg->payload.count;
}

static inline int vapi_verify_macip_acl_interface_get_reply_msg_size(vapi_msg_macip_acl_interface_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_macip_acl_interface_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_interface_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_macip_acl_interface_get_reply));
      return -1;
    }
  if (vapi_calc_macip_acl_interface_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_interface_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_macip_acl_interface_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_macip_acl_interface_get_reply()
{
  static const char name[] = "macip_acl_interface_get_reply";
  static const char name_with_crc[] = "macip_acl_interface_get_reply_accf9b05";
  static vapi_message_desc_t __vapi_metadata_macip_acl_interface_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_macip_acl_interface_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_macip_acl_interface_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_macip_acl_interface_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_macip_acl_interface_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_macip_acl_interface_get_reply = vapi_register_msg(&__vapi_metadata_macip_acl_interface_get_reply);
  VAPI_DBG("Assigned msg id %d to macip_acl_interface_get_reply", vapi_msg_id_macip_acl_interface_get_reply);
}

static inline void vapi_set_vapi_msg_macip_acl_interface_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_macip_acl_interface_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_macip_acl_interface_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_macip_acl_interface_get
#define defined_vapi_msg_macip_acl_interface_get
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_macip_acl_interface_get;

static inline void vapi_msg_macip_acl_interface_get_hton(vapi_msg_macip_acl_interface_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_interface_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_macip_acl_interface_get_ntoh(vapi_msg_macip_acl_interface_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_interface_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_macip_acl_interface_get_msg_size(vapi_msg_macip_acl_interface_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_macip_acl_interface_get_msg_size(vapi_msg_macip_acl_interface_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_macip_acl_interface_get) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_interface_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_macip_acl_interface_get));
      return -1;
    }
  if (vapi_calc_macip_acl_interface_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_interface_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_macip_acl_interface_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_macip_acl_interface_get* vapi_alloc_macip_acl_interface_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_macip_acl_interface_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_macip_acl_interface_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_macip_acl_interface_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_macip_acl_interface_get);

  return msg;
}

static inline vapi_error_e vapi_macip_acl_interface_get(struct vapi_ctx_s *ctx,
  vapi_msg_macip_acl_interface_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_macip_acl_interface_get_reply *reply),
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
  vapi_msg_macip_acl_interface_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_macip_acl_interface_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_macip_acl_interface_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_macip_acl_interface_get()
{
  static const char name[] = "macip_acl_interface_get";
  static const char name_with_crc[] = "macip_acl_interface_get_51077d14";
  static vapi_message_desc_t __vapi_metadata_macip_acl_interface_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_macip_acl_interface_get_msg_size,
    (generic_swap_fn_t)vapi_msg_macip_acl_interface_get_hton,
    (generic_swap_fn_t)vapi_msg_macip_acl_interface_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_macip_acl_interface_get = vapi_register_msg(&__vapi_metadata_macip_acl_interface_get);
  VAPI_DBG("Assigned msg id %d to macip_acl_interface_get", vapi_msg_id_macip_acl_interface_get);
}
#endif

#ifndef defined_vapi_msg_macip_acl_interface_list_details
#define defined_vapi_msg_macip_acl_interface_list_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u8 count;
  u32 acls[0]; 
} vapi_payload_macip_acl_interface_list_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_macip_acl_interface_list_details payload;
} vapi_msg_macip_acl_interface_list_details;

static inline void vapi_msg_macip_acl_interface_list_details_payload_hton(vapi_payload_macip_acl_interface_list_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { payload->acls[i] = htobe32(payload->acls[i]); } } while(0);
}

static inline void vapi_msg_macip_acl_interface_list_details_payload_ntoh(vapi_payload_macip_acl_interface_list_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { payload->acls[i] = be32toh(payload->acls[i]); } } while(0);
}

static inline void vapi_msg_macip_acl_interface_list_details_hton(vapi_msg_macip_acl_interface_list_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_interface_list_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_macip_acl_interface_list_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_macip_acl_interface_list_details_ntoh(vapi_msg_macip_acl_interface_list_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_interface_list_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_macip_acl_interface_list_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_macip_acl_interface_list_details_msg_size(vapi_msg_macip_acl_interface_list_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.acls[0]) * msg->payload.count;
}

static inline int vapi_verify_macip_acl_interface_list_details_msg_size(vapi_msg_macip_acl_interface_list_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_macip_acl_interface_list_details) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_interface_list_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_macip_acl_interface_list_details));
      return -1;
    }
  if (vapi_calc_macip_acl_interface_list_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_interface_list_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_macip_acl_interface_list_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_macip_acl_interface_list_details()
{
  static const char name[] = "macip_acl_interface_list_details";
  static const char name_with_crc[] = "macip_acl_interface_list_details_a0c5d56d";
  static vapi_message_desc_t __vapi_metadata_macip_acl_interface_list_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_macip_acl_interface_list_details, payload),
    (verify_msg_size_fn_t)vapi_verify_macip_acl_interface_list_details_msg_size,
    (generic_swap_fn_t)vapi_msg_macip_acl_interface_list_details_hton,
    (generic_swap_fn_t)vapi_msg_macip_acl_interface_list_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_macip_acl_interface_list_details = vapi_register_msg(&__vapi_metadata_macip_acl_interface_list_details);
  VAPI_DBG("Assigned msg id %d to macip_acl_interface_list_details", vapi_msg_id_macip_acl_interface_list_details);
}

static inline void vapi_set_vapi_msg_macip_acl_interface_list_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_macip_acl_interface_list_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_macip_acl_interface_list_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_macip_acl_interface_list_dump
#define defined_vapi_msg_macip_acl_interface_list_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_macip_acl_interface_list_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_macip_acl_interface_list_dump payload;
} vapi_msg_macip_acl_interface_list_dump;

static inline void vapi_msg_macip_acl_interface_list_dump_payload_hton(vapi_payload_macip_acl_interface_list_dump *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_macip_acl_interface_list_dump_payload_ntoh(vapi_payload_macip_acl_interface_list_dump *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_macip_acl_interface_list_dump_hton(vapi_msg_macip_acl_interface_list_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_interface_list_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_macip_acl_interface_list_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_macip_acl_interface_list_dump_ntoh(vapi_msg_macip_acl_interface_list_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_macip_acl_interface_list_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_macip_acl_interface_list_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_macip_acl_interface_list_dump_msg_size(vapi_msg_macip_acl_interface_list_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_macip_acl_interface_list_dump_msg_size(vapi_msg_macip_acl_interface_list_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_macip_acl_interface_list_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_interface_list_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_macip_acl_interface_list_dump));
      return -1;
    }
  if (vapi_calc_macip_acl_interface_list_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'macip_acl_interface_list_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_macip_acl_interface_list_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_macip_acl_interface_list_dump* vapi_alloc_macip_acl_interface_list_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_macip_acl_interface_list_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_macip_acl_interface_list_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_macip_acl_interface_list_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_macip_acl_interface_list_dump);

  return msg;
}

static inline vapi_error_e vapi_macip_acl_interface_list_dump(struct vapi_ctx_s *ctx,
  vapi_msg_macip_acl_interface_list_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_macip_acl_interface_list_details *reply),
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
  vapi_msg_macip_acl_interface_list_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_macip_acl_interface_list_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_macip_acl_interface_list_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_macip_acl_interface_list_dump()
{
  static const char name[] = "macip_acl_interface_list_dump";
  static const char name_with_crc[] = "macip_acl_interface_list_dump_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_macip_acl_interface_list_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_macip_acl_interface_list_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_macip_acl_interface_list_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_macip_acl_interface_list_dump_hton,
    (generic_swap_fn_t)vapi_msg_macip_acl_interface_list_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_macip_acl_interface_list_dump = vapi_register_msg(&__vapi_metadata_macip_acl_interface_list_dump);
  VAPI_DBG("Assigned msg id %d to macip_acl_interface_list_dump", vapi_msg_id_macip_acl_interface_list_dump);
}
#endif

#ifndef defined_vapi_msg_acl_interface_set_etype_whitelist_reply
#define defined_vapi_msg_acl_interface_set_etype_whitelist_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_acl_interface_set_etype_whitelist_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_acl_interface_set_etype_whitelist_reply payload;
} vapi_msg_acl_interface_set_etype_whitelist_reply;

static inline void vapi_msg_acl_interface_set_etype_whitelist_reply_payload_hton(vapi_payload_acl_interface_set_etype_whitelist_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_acl_interface_set_etype_whitelist_reply_payload_ntoh(vapi_payload_acl_interface_set_etype_whitelist_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_acl_interface_set_etype_whitelist_reply_hton(vapi_msg_acl_interface_set_etype_whitelist_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_interface_set_etype_whitelist_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_acl_interface_set_etype_whitelist_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_interface_set_etype_whitelist_reply_ntoh(vapi_msg_acl_interface_set_etype_whitelist_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_interface_set_etype_whitelist_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_acl_interface_set_etype_whitelist_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_interface_set_etype_whitelist_reply_msg_size(vapi_msg_acl_interface_set_etype_whitelist_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_interface_set_etype_whitelist_reply_msg_size(vapi_msg_acl_interface_set_etype_whitelist_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_interface_set_etype_whitelist_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_interface_set_etype_whitelist_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_interface_set_etype_whitelist_reply));
      return -1;
    }
  if (vapi_calc_acl_interface_set_etype_whitelist_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_interface_set_etype_whitelist_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_interface_set_etype_whitelist_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_acl_interface_set_etype_whitelist_reply()
{
  static const char name[] = "acl_interface_set_etype_whitelist_reply";
  static const char name_with_crc[] = "acl_interface_set_etype_whitelist_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_acl_interface_set_etype_whitelist_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_acl_interface_set_etype_whitelist_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_interface_set_etype_whitelist_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_interface_set_etype_whitelist_reply_hton,
    (generic_swap_fn_t)vapi_msg_acl_interface_set_etype_whitelist_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_interface_set_etype_whitelist_reply = vapi_register_msg(&__vapi_metadata_acl_interface_set_etype_whitelist_reply);
  VAPI_DBG("Assigned msg id %d to acl_interface_set_etype_whitelist_reply", vapi_msg_id_acl_interface_set_etype_whitelist_reply);
}

static inline void vapi_set_vapi_msg_acl_interface_set_etype_whitelist_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_acl_interface_set_etype_whitelist_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_acl_interface_set_etype_whitelist_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_acl_interface_set_etype_whitelist
#define defined_vapi_msg_acl_interface_set_etype_whitelist
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u8 count;
  u8 n_input;
  u16 whitelist[0]; 
} vapi_payload_acl_interface_set_etype_whitelist;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_acl_interface_set_etype_whitelist payload;
} vapi_msg_acl_interface_set_etype_whitelist;

static inline void vapi_msg_acl_interface_set_etype_whitelist_payload_hton(vapi_payload_acl_interface_set_etype_whitelist *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { payload->whitelist[i] = htobe16(payload->whitelist[i]); } } while(0);
}

static inline void vapi_msg_acl_interface_set_etype_whitelist_payload_ntoh(vapi_payload_acl_interface_set_etype_whitelist *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { payload->whitelist[i] = be16toh(payload->whitelist[i]); } } while(0);
}

static inline void vapi_msg_acl_interface_set_etype_whitelist_hton(vapi_msg_acl_interface_set_etype_whitelist *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_interface_set_etype_whitelist'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_acl_interface_set_etype_whitelist_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_interface_set_etype_whitelist_ntoh(vapi_msg_acl_interface_set_etype_whitelist *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_interface_set_etype_whitelist'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_acl_interface_set_etype_whitelist_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_interface_set_etype_whitelist_msg_size(vapi_msg_acl_interface_set_etype_whitelist *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.whitelist[0]) * msg->payload.count;
}

static inline int vapi_verify_acl_interface_set_etype_whitelist_msg_size(vapi_msg_acl_interface_set_etype_whitelist *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_interface_set_etype_whitelist) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_interface_set_etype_whitelist' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_interface_set_etype_whitelist));
      return -1;
    }
  if (vapi_calc_acl_interface_set_etype_whitelist_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_interface_set_etype_whitelist' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_interface_set_etype_whitelist_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_acl_interface_set_etype_whitelist* vapi_alloc_acl_interface_set_etype_whitelist(struct vapi_ctx_s *ctx, size_t _whitelist_array_size)
{
  vapi_msg_acl_interface_set_etype_whitelist *msg = NULL;
  const size_t size = sizeof(vapi_msg_acl_interface_set_etype_whitelist) + sizeof(msg->payload.whitelist[0]) * _whitelist_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_acl_interface_set_etype_whitelist*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_acl_interface_set_etype_whitelist);
  msg->payload.count = _whitelist_array_size;

  return msg;
}

static inline vapi_error_e vapi_acl_interface_set_etype_whitelist(struct vapi_ctx_s *ctx,
  vapi_msg_acl_interface_set_etype_whitelist *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_acl_interface_set_etype_whitelist_reply *reply),
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
  vapi_msg_acl_interface_set_etype_whitelist_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_acl_interface_set_etype_whitelist_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_acl_interface_set_etype_whitelist_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_acl_interface_set_etype_whitelist()
{
  static const char name[] = "acl_interface_set_etype_whitelist";
  static const char name_with_crc[] = "acl_interface_set_etype_whitelist_3f5c2d2d";
  static vapi_message_desc_t __vapi_metadata_acl_interface_set_etype_whitelist = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_acl_interface_set_etype_whitelist, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_interface_set_etype_whitelist_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_interface_set_etype_whitelist_hton,
    (generic_swap_fn_t)vapi_msg_acl_interface_set_etype_whitelist_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_interface_set_etype_whitelist = vapi_register_msg(&__vapi_metadata_acl_interface_set_etype_whitelist);
  VAPI_DBG("Assigned msg id %d to acl_interface_set_etype_whitelist", vapi_msg_id_acl_interface_set_etype_whitelist);
}
#endif

#ifndef defined_vapi_msg_acl_interface_etype_whitelist_details
#define defined_vapi_msg_acl_interface_etype_whitelist_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u8 count;
  u8 n_input;
  u16 whitelist[0]; 
} vapi_payload_acl_interface_etype_whitelist_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_acl_interface_etype_whitelist_details payload;
} vapi_msg_acl_interface_etype_whitelist_details;

static inline void vapi_msg_acl_interface_etype_whitelist_details_payload_hton(vapi_payload_acl_interface_etype_whitelist_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { payload->whitelist[i] = htobe16(payload->whitelist[i]); } } while(0);
}

static inline void vapi_msg_acl_interface_etype_whitelist_details_payload_ntoh(vapi_payload_acl_interface_etype_whitelist_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { payload->whitelist[i] = be16toh(payload->whitelist[i]); } } while(0);
}

static inline void vapi_msg_acl_interface_etype_whitelist_details_hton(vapi_msg_acl_interface_etype_whitelist_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_interface_etype_whitelist_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_acl_interface_etype_whitelist_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_interface_etype_whitelist_details_ntoh(vapi_msg_acl_interface_etype_whitelist_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_interface_etype_whitelist_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_acl_interface_etype_whitelist_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_interface_etype_whitelist_details_msg_size(vapi_msg_acl_interface_etype_whitelist_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.whitelist[0]) * msg->payload.count;
}

static inline int vapi_verify_acl_interface_etype_whitelist_details_msg_size(vapi_msg_acl_interface_etype_whitelist_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_interface_etype_whitelist_details) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_interface_etype_whitelist_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_interface_etype_whitelist_details));
      return -1;
    }
  if (vapi_calc_acl_interface_etype_whitelist_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_interface_etype_whitelist_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_interface_etype_whitelist_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_acl_interface_etype_whitelist_details()
{
  static const char name[] = "acl_interface_etype_whitelist_details";
  static const char name_with_crc[] = "acl_interface_etype_whitelist_details_cc2bfded";
  static vapi_message_desc_t __vapi_metadata_acl_interface_etype_whitelist_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_acl_interface_etype_whitelist_details, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_interface_etype_whitelist_details_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_interface_etype_whitelist_details_hton,
    (generic_swap_fn_t)vapi_msg_acl_interface_etype_whitelist_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_interface_etype_whitelist_details = vapi_register_msg(&__vapi_metadata_acl_interface_etype_whitelist_details);
  VAPI_DBG("Assigned msg id %d to acl_interface_etype_whitelist_details", vapi_msg_id_acl_interface_etype_whitelist_details);
}

static inline void vapi_set_vapi_msg_acl_interface_etype_whitelist_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_acl_interface_etype_whitelist_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_acl_interface_etype_whitelist_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_acl_interface_etype_whitelist_dump
#define defined_vapi_msg_acl_interface_etype_whitelist_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_acl_interface_etype_whitelist_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_acl_interface_etype_whitelist_dump payload;
} vapi_msg_acl_interface_etype_whitelist_dump;

static inline void vapi_msg_acl_interface_etype_whitelist_dump_payload_hton(vapi_payload_acl_interface_etype_whitelist_dump *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_acl_interface_etype_whitelist_dump_payload_ntoh(vapi_payload_acl_interface_etype_whitelist_dump *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_acl_interface_etype_whitelist_dump_hton(vapi_msg_acl_interface_etype_whitelist_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_interface_etype_whitelist_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_acl_interface_etype_whitelist_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_interface_etype_whitelist_dump_ntoh(vapi_msg_acl_interface_etype_whitelist_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_interface_etype_whitelist_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_acl_interface_etype_whitelist_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_interface_etype_whitelist_dump_msg_size(vapi_msg_acl_interface_etype_whitelist_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_interface_etype_whitelist_dump_msg_size(vapi_msg_acl_interface_etype_whitelist_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_interface_etype_whitelist_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_interface_etype_whitelist_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_interface_etype_whitelist_dump));
      return -1;
    }
  if (vapi_calc_acl_interface_etype_whitelist_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_interface_etype_whitelist_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_interface_etype_whitelist_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_acl_interface_etype_whitelist_dump* vapi_alloc_acl_interface_etype_whitelist_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_acl_interface_etype_whitelist_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_acl_interface_etype_whitelist_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_acl_interface_etype_whitelist_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_acl_interface_etype_whitelist_dump);

  return msg;
}

static inline vapi_error_e vapi_acl_interface_etype_whitelist_dump(struct vapi_ctx_s *ctx,
  vapi_msg_acl_interface_etype_whitelist_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_acl_interface_etype_whitelist_details *reply),
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
  vapi_msg_acl_interface_etype_whitelist_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_acl_interface_etype_whitelist_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_acl_interface_etype_whitelist_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_acl_interface_etype_whitelist_dump()
{
  static const char name[] = "acl_interface_etype_whitelist_dump";
  static const char name_with_crc[] = "acl_interface_etype_whitelist_dump_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_acl_interface_etype_whitelist_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_acl_interface_etype_whitelist_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_interface_etype_whitelist_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_interface_etype_whitelist_dump_hton,
    (generic_swap_fn_t)vapi_msg_acl_interface_etype_whitelist_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_interface_etype_whitelist_dump = vapi_register_msg(&__vapi_metadata_acl_interface_etype_whitelist_dump);
  VAPI_DBG("Assigned msg id %d to acl_interface_etype_whitelist_dump", vapi_msg_id_acl_interface_etype_whitelist_dump);
}
#endif

#ifndef defined_vapi_msg_acl_stats_intf_counters_enable_reply
#define defined_vapi_msg_acl_stats_intf_counters_enable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_acl_stats_intf_counters_enable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_acl_stats_intf_counters_enable_reply payload;
} vapi_msg_acl_stats_intf_counters_enable_reply;

static inline void vapi_msg_acl_stats_intf_counters_enable_reply_payload_hton(vapi_payload_acl_stats_intf_counters_enable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_acl_stats_intf_counters_enable_reply_payload_ntoh(vapi_payload_acl_stats_intf_counters_enable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_acl_stats_intf_counters_enable_reply_hton(vapi_msg_acl_stats_intf_counters_enable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_stats_intf_counters_enable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_acl_stats_intf_counters_enable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_stats_intf_counters_enable_reply_ntoh(vapi_msg_acl_stats_intf_counters_enable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_stats_intf_counters_enable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_acl_stats_intf_counters_enable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_stats_intf_counters_enable_reply_msg_size(vapi_msg_acl_stats_intf_counters_enable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_stats_intf_counters_enable_reply_msg_size(vapi_msg_acl_stats_intf_counters_enable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_stats_intf_counters_enable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_stats_intf_counters_enable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_stats_intf_counters_enable_reply));
      return -1;
    }
  if (vapi_calc_acl_stats_intf_counters_enable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_stats_intf_counters_enable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_stats_intf_counters_enable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_acl_stats_intf_counters_enable_reply()
{
  static const char name[] = "acl_stats_intf_counters_enable_reply";
  static const char name_with_crc[] = "acl_stats_intf_counters_enable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_acl_stats_intf_counters_enable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_acl_stats_intf_counters_enable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_stats_intf_counters_enable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_stats_intf_counters_enable_reply_hton,
    (generic_swap_fn_t)vapi_msg_acl_stats_intf_counters_enable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_stats_intf_counters_enable_reply = vapi_register_msg(&__vapi_metadata_acl_stats_intf_counters_enable_reply);
  VAPI_DBG("Assigned msg id %d to acl_stats_intf_counters_enable_reply", vapi_msg_id_acl_stats_intf_counters_enable_reply);
}

static inline void vapi_set_vapi_msg_acl_stats_intf_counters_enable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_acl_stats_intf_counters_enable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_acl_stats_intf_counters_enable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_acl_stats_intf_counters_enable
#define defined_vapi_msg_acl_stats_intf_counters_enable
typedef struct __attribute__ ((__packed__)) {
  bool enable; 
} vapi_payload_acl_stats_intf_counters_enable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_acl_stats_intf_counters_enable payload;
} vapi_msg_acl_stats_intf_counters_enable;

static inline void vapi_msg_acl_stats_intf_counters_enable_payload_hton(vapi_payload_acl_stats_intf_counters_enable *payload)
{

}

static inline void vapi_msg_acl_stats_intf_counters_enable_payload_ntoh(vapi_payload_acl_stats_intf_counters_enable *payload)
{

}

static inline void vapi_msg_acl_stats_intf_counters_enable_hton(vapi_msg_acl_stats_intf_counters_enable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_stats_intf_counters_enable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_acl_stats_intf_counters_enable_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_stats_intf_counters_enable_ntoh(vapi_msg_acl_stats_intf_counters_enable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_stats_intf_counters_enable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_acl_stats_intf_counters_enable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_stats_intf_counters_enable_msg_size(vapi_msg_acl_stats_intf_counters_enable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_stats_intf_counters_enable_msg_size(vapi_msg_acl_stats_intf_counters_enable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_stats_intf_counters_enable) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_stats_intf_counters_enable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_stats_intf_counters_enable));
      return -1;
    }
  if (vapi_calc_acl_stats_intf_counters_enable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_stats_intf_counters_enable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_stats_intf_counters_enable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_acl_stats_intf_counters_enable* vapi_alloc_acl_stats_intf_counters_enable(struct vapi_ctx_s *ctx)
{
  vapi_msg_acl_stats_intf_counters_enable *msg = NULL;
  const size_t size = sizeof(vapi_msg_acl_stats_intf_counters_enable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_acl_stats_intf_counters_enable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_acl_stats_intf_counters_enable);

  return msg;
}

static inline vapi_error_e vapi_acl_stats_intf_counters_enable(struct vapi_ctx_s *ctx,
  vapi_msg_acl_stats_intf_counters_enable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_acl_stats_intf_counters_enable_reply *reply),
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
  vapi_msg_acl_stats_intf_counters_enable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_acl_stats_intf_counters_enable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_acl_stats_intf_counters_enable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_acl_stats_intf_counters_enable()
{
  static const char name[] = "acl_stats_intf_counters_enable";
  static const char name_with_crc[] = "acl_stats_intf_counters_enable_b3e225d2";
  static vapi_message_desc_t __vapi_metadata_acl_stats_intf_counters_enable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_acl_stats_intf_counters_enable, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_stats_intf_counters_enable_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_stats_intf_counters_enable_hton,
    (generic_swap_fn_t)vapi_msg_acl_stats_intf_counters_enable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_stats_intf_counters_enable = vapi_register_msg(&__vapi_metadata_acl_stats_intf_counters_enable);
  VAPI_DBG("Assigned msg id %d to acl_stats_intf_counters_enable", vapi_msg_id_acl_stats_intf_counters_enable);
}
#endif

#ifndef defined_vapi_msg_acl_plugin_use_hash_lookup_set_reply
#define defined_vapi_msg_acl_plugin_use_hash_lookup_set_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_acl_plugin_use_hash_lookup_set_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_acl_plugin_use_hash_lookup_set_reply payload;
} vapi_msg_acl_plugin_use_hash_lookup_set_reply;

static inline void vapi_msg_acl_plugin_use_hash_lookup_set_reply_payload_hton(vapi_payload_acl_plugin_use_hash_lookup_set_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_acl_plugin_use_hash_lookup_set_reply_payload_ntoh(vapi_payload_acl_plugin_use_hash_lookup_set_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_acl_plugin_use_hash_lookup_set_reply_hton(vapi_msg_acl_plugin_use_hash_lookup_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_plugin_use_hash_lookup_set_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_acl_plugin_use_hash_lookup_set_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_plugin_use_hash_lookup_set_reply_ntoh(vapi_msg_acl_plugin_use_hash_lookup_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_plugin_use_hash_lookup_set_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_acl_plugin_use_hash_lookup_set_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_plugin_use_hash_lookup_set_reply_msg_size(vapi_msg_acl_plugin_use_hash_lookup_set_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_plugin_use_hash_lookup_set_reply_msg_size(vapi_msg_acl_plugin_use_hash_lookup_set_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_plugin_use_hash_lookup_set_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_plugin_use_hash_lookup_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_plugin_use_hash_lookup_set_reply));
      return -1;
    }
  if (vapi_calc_acl_plugin_use_hash_lookup_set_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_plugin_use_hash_lookup_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_plugin_use_hash_lookup_set_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_acl_plugin_use_hash_lookup_set_reply()
{
  static const char name[] = "acl_plugin_use_hash_lookup_set_reply";
  static const char name_with_crc[] = "acl_plugin_use_hash_lookup_set_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_acl_plugin_use_hash_lookup_set_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_acl_plugin_use_hash_lookup_set_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_plugin_use_hash_lookup_set_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_plugin_use_hash_lookup_set_reply_hton,
    (generic_swap_fn_t)vapi_msg_acl_plugin_use_hash_lookup_set_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_plugin_use_hash_lookup_set_reply = vapi_register_msg(&__vapi_metadata_acl_plugin_use_hash_lookup_set_reply);
  VAPI_DBG("Assigned msg id %d to acl_plugin_use_hash_lookup_set_reply", vapi_msg_id_acl_plugin_use_hash_lookup_set_reply);
}

static inline void vapi_set_vapi_msg_acl_plugin_use_hash_lookup_set_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_acl_plugin_use_hash_lookup_set_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_acl_plugin_use_hash_lookup_set_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_acl_plugin_use_hash_lookup_set
#define defined_vapi_msg_acl_plugin_use_hash_lookup_set
typedef struct __attribute__ ((__packed__)) {
  bool enable; 
} vapi_payload_acl_plugin_use_hash_lookup_set;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_acl_plugin_use_hash_lookup_set payload;
} vapi_msg_acl_plugin_use_hash_lookup_set;

static inline void vapi_msg_acl_plugin_use_hash_lookup_set_payload_hton(vapi_payload_acl_plugin_use_hash_lookup_set *payload)
{

}

static inline void vapi_msg_acl_plugin_use_hash_lookup_set_payload_ntoh(vapi_payload_acl_plugin_use_hash_lookup_set *payload)
{

}

static inline void vapi_msg_acl_plugin_use_hash_lookup_set_hton(vapi_msg_acl_plugin_use_hash_lookup_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_plugin_use_hash_lookup_set'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_acl_plugin_use_hash_lookup_set_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_plugin_use_hash_lookup_set_ntoh(vapi_msg_acl_plugin_use_hash_lookup_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_plugin_use_hash_lookup_set'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_acl_plugin_use_hash_lookup_set_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_plugin_use_hash_lookup_set_msg_size(vapi_msg_acl_plugin_use_hash_lookup_set *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_plugin_use_hash_lookup_set_msg_size(vapi_msg_acl_plugin_use_hash_lookup_set *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_plugin_use_hash_lookup_set) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_plugin_use_hash_lookup_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_plugin_use_hash_lookup_set));
      return -1;
    }
  if (vapi_calc_acl_plugin_use_hash_lookup_set_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_plugin_use_hash_lookup_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_plugin_use_hash_lookup_set_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_acl_plugin_use_hash_lookup_set* vapi_alloc_acl_plugin_use_hash_lookup_set(struct vapi_ctx_s *ctx)
{
  vapi_msg_acl_plugin_use_hash_lookup_set *msg = NULL;
  const size_t size = sizeof(vapi_msg_acl_plugin_use_hash_lookup_set);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_acl_plugin_use_hash_lookup_set*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_acl_plugin_use_hash_lookup_set);

  return msg;
}

static inline vapi_error_e vapi_acl_plugin_use_hash_lookup_set(struct vapi_ctx_s *ctx,
  vapi_msg_acl_plugin_use_hash_lookup_set *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_acl_plugin_use_hash_lookup_set_reply *reply),
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
  vapi_msg_acl_plugin_use_hash_lookup_set_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_acl_plugin_use_hash_lookup_set_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_acl_plugin_use_hash_lookup_set_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_acl_plugin_use_hash_lookup_set()
{
  static const char name[] = "acl_plugin_use_hash_lookup_set";
  static const char name_with_crc[] = "acl_plugin_use_hash_lookup_set_b3e225d2";
  static vapi_message_desc_t __vapi_metadata_acl_plugin_use_hash_lookup_set = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_acl_plugin_use_hash_lookup_set, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_plugin_use_hash_lookup_set_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_plugin_use_hash_lookup_set_hton,
    (generic_swap_fn_t)vapi_msg_acl_plugin_use_hash_lookup_set_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_plugin_use_hash_lookup_set = vapi_register_msg(&__vapi_metadata_acl_plugin_use_hash_lookup_set);
  VAPI_DBG("Assigned msg id %d to acl_plugin_use_hash_lookup_set", vapi_msg_id_acl_plugin_use_hash_lookup_set);
}
#endif

#ifndef defined_vapi_msg_acl_plugin_use_hash_lookup_get_reply
#define defined_vapi_msg_acl_plugin_use_hash_lookup_get_reply
typedef struct __attribute__ ((__packed__)) {
  bool enable; 
} vapi_payload_acl_plugin_use_hash_lookup_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_acl_plugin_use_hash_lookup_get_reply payload;
} vapi_msg_acl_plugin_use_hash_lookup_get_reply;

static inline void vapi_msg_acl_plugin_use_hash_lookup_get_reply_payload_hton(vapi_payload_acl_plugin_use_hash_lookup_get_reply *payload)
{

}

static inline void vapi_msg_acl_plugin_use_hash_lookup_get_reply_payload_ntoh(vapi_payload_acl_plugin_use_hash_lookup_get_reply *payload)
{

}

static inline void vapi_msg_acl_plugin_use_hash_lookup_get_reply_hton(vapi_msg_acl_plugin_use_hash_lookup_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_plugin_use_hash_lookup_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_acl_plugin_use_hash_lookup_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_acl_plugin_use_hash_lookup_get_reply_ntoh(vapi_msg_acl_plugin_use_hash_lookup_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_plugin_use_hash_lookup_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_acl_plugin_use_hash_lookup_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_acl_plugin_use_hash_lookup_get_reply_msg_size(vapi_msg_acl_plugin_use_hash_lookup_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_plugin_use_hash_lookup_get_reply_msg_size(vapi_msg_acl_plugin_use_hash_lookup_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_plugin_use_hash_lookup_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_plugin_use_hash_lookup_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_plugin_use_hash_lookup_get_reply));
      return -1;
    }
  if (vapi_calc_acl_plugin_use_hash_lookup_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_plugin_use_hash_lookup_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_plugin_use_hash_lookup_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_acl_plugin_use_hash_lookup_get_reply()
{
  static const char name[] = "acl_plugin_use_hash_lookup_get_reply";
  static const char name_with_crc[] = "acl_plugin_use_hash_lookup_get_reply_5392ad31";
  static vapi_message_desc_t __vapi_metadata_acl_plugin_use_hash_lookup_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_acl_plugin_use_hash_lookup_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_acl_plugin_use_hash_lookup_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_plugin_use_hash_lookup_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_acl_plugin_use_hash_lookup_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_plugin_use_hash_lookup_get_reply = vapi_register_msg(&__vapi_metadata_acl_plugin_use_hash_lookup_get_reply);
  VAPI_DBG("Assigned msg id %d to acl_plugin_use_hash_lookup_get_reply", vapi_msg_id_acl_plugin_use_hash_lookup_get_reply);
}

static inline void vapi_set_vapi_msg_acl_plugin_use_hash_lookup_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_acl_plugin_use_hash_lookup_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_acl_plugin_use_hash_lookup_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_acl_plugin_use_hash_lookup_get
#define defined_vapi_msg_acl_plugin_use_hash_lookup_get
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_acl_plugin_use_hash_lookup_get;

static inline void vapi_msg_acl_plugin_use_hash_lookup_get_hton(vapi_msg_acl_plugin_use_hash_lookup_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_plugin_use_hash_lookup_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_acl_plugin_use_hash_lookup_get_ntoh(vapi_msg_acl_plugin_use_hash_lookup_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_acl_plugin_use_hash_lookup_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_acl_plugin_use_hash_lookup_get_msg_size(vapi_msg_acl_plugin_use_hash_lookup_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_acl_plugin_use_hash_lookup_get_msg_size(vapi_msg_acl_plugin_use_hash_lookup_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_acl_plugin_use_hash_lookup_get) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_plugin_use_hash_lookup_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_acl_plugin_use_hash_lookup_get));
      return -1;
    }
  if (vapi_calc_acl_plugin_use_hash_lookup_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'acl_plugin_use_hash_lookup_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_acl_plugin_use_hash_lookup_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_acl_plugin_use_hash_lookup_get* vapi_alloc_acl_plugin_use_hash_lookup_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_acl_plugin_use_hash_lookup_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_acl_plugin_use_hash_lookup_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_acl_plugin_use_hash_lookup_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_acl_plugin_use_hash_lookup_get);

  return msg;
}

static inline vapi_error_e vapi_acl_plugin_use_hash_lookup_get(struct vapi_ctx_s *ctx,
  vapi_msg_acl_plugin_use_hash_lookup_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_acl_plugin_use_hash_lookup_get_reply *reply),
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
  vapi_msg_acl_plugin_use_hash_lookup_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_acl_plugin_use_hash_lookup_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_acl_plugin_use_hash_lookup_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_acl_plugin_use_hash_lookup_get()
{
  static const char name[] = "acl_plugin_use_hash_lookup_get";
  static const char name_with_crc[] = "acl_plugin_use_hash_lookup_get_51077d14";
  static vapi_message_desc_t __vapi_metadata_acl_plugin_use_hash_lookup_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_acl_plugin_use_hash_lookup_get_msg_size,
    (generic_swap_fn_t)vapi_msg_acl_plugin_use_hash_lookup_get_hton,
    (generic_swap_fn_t)vapi_msg_acl_plugin_use_hash_lookup_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_acl_plugin_use_hash_lookup_get = vapi_register_msg(&__vapi_metadata_acl_plugin_use_hash_lookup_get);
  VAPI_DBG("Assigned msg id %d to acl_plugin_use_hash_lookup_get", vapi_msg_id_acl_plugin_use_hash_lookup_get);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
