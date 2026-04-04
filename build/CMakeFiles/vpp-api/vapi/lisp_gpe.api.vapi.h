#ifndef __included_lisp_gpe_api_json
#define __included_lisp_gpe_api_json

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

extern vapi_msg_id_t vapi_msg_id_gpe_add_del_fwd_entry;
extern vapi_msg_id_t vapi_msg_id_gpe_add_del_fwd_entry_reply;
extern vapi_msg_id_t vapi_msg_id_gpe_enable_disable;
extern vapi_msg_id_t vapi_msg_id_gpe_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_gpe_add_del_iface;
extern vapi_msg_id_t vapi_msg_id_gpe_add_del_iface_reply;
extern vapi_msg_id_t vapi_msg_id_gpe_fwd_entry_vnis_get;
extern vapi_msg_id_t vapi_msg_id_gpe_fwd_entry_vnis_get_reply;
extern vapi_msg_id_t vapi_msg_id_gpe_fwd_entries_get;
extern vapi_msg_id_t vapi_msg_id_gpe_fwd_entries_get_reply;
extern vapi_msg_id_t vapi_msg_id_gpe_fwd_entry_path_dump;
extern vapi_msg_id_t vapi_msg_id_gpe_fwd_entry_path_details;
extern vapi_msg_id_t vapi_msg_id_gpe_set_encap_mode;
extern vapi_msg_id_t vapi_msg_id_gpe_set_encap_mode_reply;
extern vapi_msg_id_t vapi_msg_id_gpe_get_encap_mode;
extern vapi_msg_id_t vapi_msg_id_gpe_get_encap_mode_reply;
extern vapi_msg_id_t vapi_msg_id_gpe_add_del_native_fwd_rpath;
extern vapi_msg_id_t vapi_msg_id_gpe_add_del_native_fwd_rpath_reply;
extern vapi_msg_id_t vapi_msg_id_gpe_native_fwd_rpaths_get;
extern vapi_msg_id_t vapi_msg_id_gpe_native_fwd_rpaths_get_reply;

#define DEFINE_VAPI_MSG_IDS_LISP_GPE_API_JSON\
  vapi_msg_id_t vapi_msg_id_gpe_add_del_fwd_entry;\
  vapi_msg_id_t vapi_msg_id_gpe_add_del_fwd_entry_reply;\
  vapi_msg_id_t vapi_msg_id_gpe_enable_disable;\
  vapi_msg_id_t vapi_msg_id_gpe_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_gpe_add_del_iface;\
  vapi_msg_id_t vapi_msg_id_gpe_add_del_iface_reply;\
  vapi_msg_id_t vapi_msg_id_gpe_fwd_entry_vnis_get;\
  vapi_msg_id_t vapi_msg_id_gpe_fwd_entry_vnis_get_reply;\
  vapi_msg_id_t vapi_msg_id_gpe_fwd_entries_get;\
  vapi_msg_id_t vapi_msg_id_gpe_fwd_entries_get_reply;\
  vapi_msg_id_t vapi_msg_id_gpe_fwd_entry_path_dump;\
  vapi_msg_id_t vapi_msg_id_gpe_fwd_entry_path_details;\
  vapi_msg_id_t vapi_msg_id_gpe_set_encap_mode;\
  vapi_msg_id_t vapi_msg_id_gpe_set_encap_mode_reply;\
  vapi_msg_id_t vapi_msg_id_gpe_get_encap_mode;\
  vapi_msg_id_t vapi_msg_id_gpe_get_encap_mode_reply;\
  vapi_msg_id_t vapi_msg_id_gpe_add_del_native_fwd_rpath;\
  vapi_msg_id_t vapi_msg_id_gpe_add_del_native_fwd_rpath_reply;\
  vapi_msg_id_t vapi_msg_id_gpe_native_fwd_rpaths_get;\
  vapi_msg_id_t vapi_msg_id_gpe_native_fwd_rpaths_get_reply;


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

#ifndef defined_vapi_type_gpe_locator
#define defined_vapi_type_gpe_locator
typedef struct __attribute__((__packed__)) {
  u8 weight;
  vapi_type_address addr;
} vapi_type_gpe_locator;

static inline void vapi_type_gpe_locator_hton(vapi_type_gpe_locator *msg)
{

}

static inline void vapi_type_gpe_locator_ntoh(vapi_type_gpe_locator *msg)
{

}
#endif

#ifndef defined_vapi_type_gpe_native_fwd_rpath
#define defined_vapi_type_gpe_native_fwd_rpath
typedef struct __attribute__((__packed__)) {
  u32 fib_index;
  vapi_type_interface_index nh_sw_if_index;
  vapi_type_address nh_addr;
} vapi_type_gpe_native_fwd_rpath;

static inline void vapi_type_gpe_native_fwd_rpath_hton(vapi_type_gpe_native_fwd_rpath *msg)
{
  msg->fib_index = htobe32(msg->fib_index);
  msg->nh_sw_if_index = htobe32(msg->nh_sw_if_index);
}

static inline void vapi_type_gpe_native_fwd_rpath_ntoh(vapi_type_gpe_native_fwd_rpath *msg)
{
  msg->fib_index = be32toh(msg->fib_index);
  msg->nh_sw_if_index = be32toh(msg->nh_sw_if_index);
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

#ifndef defined_vapi_type_gpe_fwd_entry
#define defined_vapi_type_gpe_fwd_entry
typedef struct __attribute__((__packed__)) {
  u32 fwd_entry_index;
  u32 dp_table;
  vapi_type_eid leid;
  vapi_type_eid reid;
  u32 vni;
  u8 action;
} vapi_type_gpe_fwd_entry;

static inline void vapi_type_gpe_fwd_entry_hton(vapi_type_gpe_fwd_entry *msg)
{
  msg->fwd_entry_index = htobe32(msg->fwd_entry_index);
  msg->dp_table = htobe32(msg->dp_table);
  msg->vni = htobe32(msg->vni);
}

static inline void vapi_type_gpe_fwd_entry_ntoh(vapi_type_gpe_fwd_entry *msg)
{
  msg->fwd_entry_index = be32toh(msg->fwd_entry_index);
  msg->dp_table = be32toh(msg->dp_table);
  msg->vni = be32toh(msg->vni);
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

#ifndef defined_vapi_msg_gpe_add_del_fwd_entry_reply
#define defined_vapi_msg_gpe_add_del_fwd_entry_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 fwd_entry_index; 
} vapi_payload_gpe_add_del_fwd_entry_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_gpe_add_del_fwd_entry_reply payload;
} vapi_msg_gpe_add_del_fwd_entry_reply;

static inline void vapi_msg_gpe_add_del_fwd_entry_reply_payload_hton(vapi_payload_gpe_add_del_fwd_entry_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->fwd_entry_index = htobe32(payload->fwd_entry_index);
}

static inline void vapi_msg_gpe_add_del_fwd_entry_reply_payload_ntoh(vapi_payload_gpe_add_del_fwd_entry_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->fwd_entry_index = be32toh(payload->fwd_entry_index);
}

static inline void vapi_msg_gpe_add_del_fwd_entry_reply_hton(vapi_msg_gpe_add_del_fwd_entry_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_add_del_fwd_entry_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_gpe_add_del_fwd_entry_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_gpe_add_del_fwd_entry_reply_ntoh(vapi_msg_gpe_add_del_fwd_entry_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_add_del_fwd_entry_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_gpe_add_del_fwd_entry_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gpe_add_del_fwd_entry_reply_msg_size(vapi_msg_gpe_add_del_fwd_entry_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gpe_add_del_fwd_entry_reply_msg_size(vapi_msg_gpe_add_del_fwd_entry_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gpe_add_del_fwd_entry_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_add_del_fwd_entry_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gpe_add_del_fwd_entry_reply));
      return -1;
    }
  if (vapi_calc_gpe_add_del_fwd_entry_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_add_del_fwd_entry_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gpe_add_del_fwd_entry_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_gpe_add_del_fwd_entry_reply()
{
  static const char name[] = "gpe_add_del_fwd_entry_reply";
  static const char name_with_crc[] = "gpe_add_del_fwd_entry_reply_efe5f176";
  static vapi_message_desc_t __vapi_metadata_gpe_add_del_fwd_entry_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_gpe_add_del_fwd_entry_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_gpe_add_del_fwd_entry_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_gpe_add_del_fwd_entry_reply_hton,
    (generic_swap_fn_t)vapi_msg_gpe_add_del_fwd_entry_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gpe_add_del_fwd_entry_reply = vapi_register_msg(&__vapi_metadata_gpe_add_del_fwd_entry_reply);
  VAPI_DBG("Assigned msg id %d to gpe_add_del_fwd_entry_reply", vapi_msg_id_gpe_add_del_fwd_entry_reply);
}

static inline void vapi_set_vapi_msg_gpe_add_del_fwd_entry_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_gpe_add_del_fwd_entry_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_gpe_add_del_fwd_entry_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_gpe_add_del_fwd_entry
#define defined_vapi_msg_gpe_add_del_fwd_entry
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_eid rmt_eid;
  vapi_type_eid lcl_eid;
  u32 vni;
  u32 dp_table;
  u8 action;
  u32 loc_num;
  vapi_type_gpe_locator locs[0]; 
} vapi_payload_gpe_add_del_fwd_entry;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_gpe_add_del_fwd_entry payload;
} vapi_msg_gpe_add_del_fwd_entry;

static inline void vapi_msg_gpe_add_del_fwd_entry_payload_hton(vapi_payload_gpe_add_del_fwd_entry *payload)
{
  payload->vni = htobe32(payload->vni);
  payload->dp_table = htobe32(payload->dp_table);
  payload->loc_num = htobe32(payload->loc_num);
}

static inline void vapi_msg_gpe_add_del_fwd_entry_payload_ntoh(vapi_payload_gpe_add_del_fwd_entry *payload)
{
  payload->vni = be32toh(payload->vni);
  payload->dp_table = be32toh(payload->dp_table);
  payload->loc_num = be32toh(payload->loc_num);
}

static inline void vapi_msg_gpe_add_del_fwd_entry_hton(vapi_msg_gpe_add_del_fwd_entry *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_add_del_fwd_entry'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_gpe_add_del_fwd_entry_payload_hton(&msg->payload);
}

static inline void vapi_msg_gpe_add_del_fwd_entry_ntoh(vapi_msg_gpe_add_del_fwd_entry *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_add_del_fwd_entry'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_gpe_add_del_fwd_entry_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gpe_add_del_fwd_entry_msg_size(vapi_msg_gpe_add_del_fwd_entry *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.locs[0]) * msg->payload.loc_num;
}

static inline int vapi_verify_gpe_add_del_fwd_entry_msg_size(vapi_msg_gpe_add_del_fwd_entry *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gpe_add_del_fwd_entry) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_add_del_fwd_entry' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gpe_add_del_fwd_entry));
      return -1;
    }
  if (vapi_calc_gpe_add_del_fwd_entry_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_add_del_fwd_entry' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gpe_add_del_fwd_entry_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_gpe_add_del_fwd_entry* vapi_alloc_gpe_add_del_fwd_entry(struct vapi_ctx_s *ctx, size_t _locs_array_size)
{
  vapi_msg_gpe_add_del_fwd_entry *msg = NULL;
  const size_t size = sizeof(vapi_msg_gpe_add_del_fwd_entry) + sizeof(msg->payload.locs[0]) * _locs_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_gpe_add_del_fwd_entry*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_gpe_add_del_fwd_entry);
  msg->payload.loc_num = _locs_array_size;

  return msg;
}

static inline vapi_error_e vapi_gpe_add_del_fwd_entry(struct vapi_ctx_s *ctx,
  vapi_msg_gpe_add_del_fwd_entry *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_gpe_add_del_fwd_entry_reply *reply),
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
  vapi_msg_gpe_add_del_fwd_entry_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_gpe_add_del_fwd_entry_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_gpe_add_del_fwd_entry_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_gpe_add_del_fwd_entry()
{
  static const char name[] = "gpe_add_del_fwd_entry";
  static const char name_with_crc[] = "gpe_add_del_fwd_entry_f0847644";
  static vapi_message_desc_t __vapi_metadata_gpe_add_del_fwd_entry = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_gpe_add_del_fwd_entry, payload),
    (verify_msg_size_fn_t)vapi_verify_gpe_add_del_fwd_entry_msg_size,
    (generic_swap_fn_t)vapi_msg_gpe_add_del_fwd_entry_hton,
    (generic_swap_fn_t)vapi_msg_gpe_add_del_fwd_entry_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gpe_add_del_fwd_entry = vapi_register_msg(&__vapi_metadata_gpe_add_del_fwd_entry);
  VAPI_DBG("Assigned msg id %d to gpe_add_del_fwd_entry", vapi_msg_id_gpe_add_del_fwd_entry);
}
#endif

#ifndef defined_vapi_msg_gpe_enable_disable_reply
#define defined_vapi_msg_gpe_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_gpe_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_gpe_enable_disable_reply payload;
} vapi_msg_gpe_enable_disable_reply;

static inline void vapi_msg_gpe_enable_disable_reply_payload_hton(vapi_payload_gpe_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_gpe_enable_disable_reply_payload_ntoh(vapi_payload_gpe_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_gpe_enable_disable_reply_hton(vapi_msg_gpe_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_gpe_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_gpe_enable_disable_reply_ntoh(vapi_msg_gpe_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_gpe_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gpe_enable_disable_reply_msg_size(vapi_msg_gpe_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gpe_enable_disable_reply_msg_size(vapi_msg_gpe_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gpe_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gpe_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_gpe_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gpe_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_gpe_enable_disable_reply()
{
  static const char name[] = "gpe_enable_disable_reply";
  static const char name_with_crc[] = "gpe_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_gpe_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_gpe_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_gpe_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_gpe_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_gpe_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gpe_enable_disable_reply = vapi_register_msg(&__vapi_metadata_gpe_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to gpe_enable_disable_reply", vapi_msg_id_gpe_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_gpe_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_gpe_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_gpe_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_gpe_enable_disable
#define defined_vapi_msg_gpe_enable_disable
typedef struct __attribute__ ((__packed__)) {
  bool is_enable; 
} vapi_payload_gpe_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_gpe_enable_disable payload;
} vapi_msg_gpe_enable_disable;

static inline void vapi_msg_gpe_enable_disable_payload_hton(vapi_payload_gpe_enable_disable *payload)
{

}

static inline void vapi_msg_gpe_enable_disable_payload_ntoh(vapi_payload_gpe_enable_disable *payload)
{

}

static inline void vapi_msg_gpe_enable_disable_hton(vapi_msg_gpe_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_gpe_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_gpe_enable_disable_ntoh(vapi_msg_gpe_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_gpe_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gpe_enable_disable_msg_size(vapi_msg_gpe_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gpe_enable_disable_msg_size(vapi_msg_gpe_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gpe_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gpe_enable_disable));
      return -1;
    }
  if (vapi_calc_gpe_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gpe_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_gpe_enable_disable* vapi_alloc_gpe_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_gpe_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_gpe_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_gpe_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_gpe_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_gpe_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_gpe_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_gpe_enable_disable_reply *reply),
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
  vapi_msg_gpe_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_gpe_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_gpe_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_gpe_enable_disable()
{
  static const char name[] = "gpe_enable_disable";
  static const char name_with_crc[] = "gpe_enable_disable_c264d7bf";
  static vapi_message_desc_t __vapi_metadata_gpe_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_gpe_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_gpe_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_gpe_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_gpe_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gpe_enable_disable = vapi_register_msg(&__vapi_metadata_gpe_enable_disable);
  VAPI_DBG("Assigned msg id %d to gpe_enable_disable", vapi_msg_id_gpe_enable_disable);
}
#endif

#ifndef defined_vapi_msg_gpe_add_del_iface_reply
#define defined_vapi_msg_gpe_add_del_iface_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_gpe_add_del_iface_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_gpe_add_del_iface_reply payload;
} vapi_msg_gpe_add_del_iface_reply;

static inline void vapi_msg_gpe_add_del_iface_reply_payload_hton(vapi_payload_gpe_add_del_iface_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_gpe_add_del_iface_reply_payload_ntoh(vapi_payload_gpe_add_del_iface_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_gpe_add_del_iface_reply_hton(vapi_msg_gpe_add_del_iface_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_add_del_iface_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_gpe_add_del_iface_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_gpe_add_del_iface_reply_ntoh(vapi_msg_gpe_add_del_iface_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_add_del_iface_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_gpe_add_del_iface_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gpe_add_del_iface_reply_msg_size(vapi_msg_gpe_add_del_iface_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gpe_add_del_iface_reply_msg_size(vapi_msg_gpe_add_del_iface_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gpe_add_del_iface_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_add_del_iface_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gpe_add_del_iface_reply));
      return -1;
    }
  if (vapi_calc_gpe_add_del_iface_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_add_del_iface_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gpe_add_del_iface_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_gpe_add_del_iface_reply()
{
  static const char name[] = "gpe_add_del_iface_reply";
  static const char name_with_crc[] = "gpe_add_del_iface_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_gpe_add_del_iface_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_gpe_add_del_iface_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_gpe_add_del_iface_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_gpe_add_del_iface_reply_hton,
    (generic_swap_fn_t)vapi_msg_gpe_add_del_iface_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gpe_add_del_iface_reply = vapi_register_msg(&__vapi_metadata_gpe_add_del_iface_reply);
  VAPI_DBG("Assigned msg id %d to gpe_add_del_iface_reply", vapi_msg_id_gpe_add_del_iface_reply);
}

static inline void vapi_set_vapi_msg_gpe_add_del_iface_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_gpe_add_del_iface_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_gpe_add_del_iface_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_gpe_add_del_iface
#define defined_vapi_msg_gpe_add_del_iface
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  bool is_l2;
  u32 dp_table;
  u32 vni; 
} vapi_payload_gpe_add_del_iface;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_gpe_add_del_iface payload;
} vapi_msg_gpe_add_del_iface;

static inline void vapi_msg_gpe_add_del_iface_payload_hton(vapi_payload_gpe_add_del_iface *payload)
{
  payload->dp_table = htobe32(payload->dp_table);
  payload->vni = htobe32(payload->vni);
}

static inline void vapi_msg_gpe_add_del_iface_payload_ntoh(vapi_payload_gpe_add_del_iface *payload)
{
  payload->dp_table = be32toh(payload->dp_table);
  payload->vni = be32toh(payload->vni);
}

static inline void vapi_msg_gpe_add_del_iface_hton(vapi_msg_gpe_add_del_iface *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_add_del_iface'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_gpe_add_del_iface_payload_hton(&msg->payload);
}

static inline void vapi_msg_gpe_add_del_iface_ntoh(vapi_msg_gpe_add_del_iface *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_add_del_iface'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_gpe_add_del_iface_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gpe_add_del_iface_msg_size(vapi_msg_gpe_add_del_iface *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gpe_add_del_iface_msg_size(vapi_msg_gpe_add_del_iface *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gpe_add_del_iface) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_add_del_iface' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gpe_add_del_iface));
      return -1;
    }
  if (vapi_calc_gpe_add_del_iface_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_add_del_iface' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gpe_add_del_iface_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_gpe_add_del_iface* vapi_alloc_gpe_add_del_iface(struct vapi_ctx_s *ctx)
{
  vapi_msg_gpe_add_del_iface *msg = NULL;
  const size_t size = sizeof(vapi_msg_gpe_add_del_iface);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_gpe_add_del_iface*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_gpe_add_del_iface);

  return msg;
}

static inline vapi_error_e vapi_gpe_add_del_iface(struct vapi_ctx_s *ctx,
  vapi_msg_gpe_add_del_iface *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_gpe_add_del_iface_reply *reply),
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
  vapi_msg_gpe_add_del_iface_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_gpe_add_del_iface_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_gpe_add_del_iface_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_gpe_add_del_iface()
{
  static const char name[] = "gpe_add_del_iface";
  static const char name_with_crc[] = "gpe_add_del_iface_3ccff273";
  static vapi_message_desc_t __vapi_metadata_gpe_add_del_iface = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_gpe_add_del_iface, payload),
    (verify_msg_size_fn_t)vapi_verify_gpe_add_del_iface_msg_size,
    (generic_swap_fn_t)vapi_msg_gpe_add_del_iface_hton,
    (generic_swap_fn_t)vapi_msg_gpe_add_del_iface_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gpe_add_del_iface = vapi_register_msg(&__vapi_metadata_gpe_add_del_iface);
  VAPI_DBG("Assigned msg id %d to gpe_add_del_iface", vapi_msg_id_gpe_add_del_iface);
}
#endif

#ifndef defined_vapi_msg_gpe_fwd_entry_vnis_get_reply
#define defined_vapi_msg_gpe_fwd_entry_vnis_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 count;
  u32 vnis[0]; 
} vapi_payload_gpe_fwd_entry_vnis_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_gpe_fwd_entry_vnis_get_reply payload;
} vapi_msg_gpe_fwd_entry_vnis_get_reply;

static inline void vapi_msg_gpe_fwd_entry_vnis_get_reply_payload_hton(vapi_payload_gpe_fwd_entry_vnis_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->count = htobe32(payload->count);
  do { unsigned i; for (i = 0; i < be32toh(payload->count); ++i) { payload->vnis[i] = htobe32(payload->vnis[i]); } } while(0);
}

static inline void vapi_msg_gpe_fwd_entry_vnis_get_reply_payload_ntoh(vapi_payload_gpe_fwd_entry_vnis_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->count = be32toh(payload->count);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { payload->vnis[i] = be32toh(payload->vnis[i]); } } while(0);
}

static inline void vapi_msg_gpe_fwd_entry_vnis_get_reply_hton(vapi_msg_gpe_fwd_entry_vnis_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_fwd_entry_vnis_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_gpe_fwd_entry_vnis_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_gpe_fwd_entry_vnis_get_reply_ntoh(vapi_msg_gpe_fwd_entry_vnis_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_fwd_entry_vnis_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_gpe_fwd_entry_vnis_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gpe_fwd_entry_vnis_get_reply_msg_size(vapi_msg_gpe_fwd_entry_vnis_get_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.vnis[0]) * msg->payload.count;
}

static inline int vapi_verify_gpe_fwd_entry_vnis_get_reply_msg_size(vapi_msg_gpe_fwd_entry_vnis_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gpe_fwd_entry_vnis_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_fwd_entry_vnis_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gpe_fwd_entry_vnis_get_reply));
      return -1;
    }
  if (vapi_calc_gpe_fwd_entry_vnis_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_fwd_entry_vnis_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gpe_fwd_entry_vnis_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_gpe_fwd_entry_vnis_get_reply()
{
  static const char name[] = "gpe_fwd_entry_vnis_get_reply";
  static const char name_with_crc[] = "gpe_fwd_entry_vnis_get_reply_aa70da20";
  static vapi_message_desc_t __vapi_metadata_gpe_fwd_entry_vnis_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_gpe_fwd_entry_vnis_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_gpe_fwd_entry_vnis_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_gpe_fwd_entry_vnis_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_gpe_fwd_entry_vnis_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gpe_fwd_entry_vnis_get_reply = vapi_register_msg(&__vapi_metadata_gpe_fwd_entry_vnis_get_reply);
  VAPI_DBG("Assigned msg id %d to gpe_fwd_entry_vnis_get_reply", vapi_msg_id_gpe_fwd_entry_vnis_get_reply);
}

static inline void vapi_set_vapi_msg_gpe_fwd_entry_vnis_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_gpe_fwd_entry_vnis_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_gpe_fwd_entry_vnis_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_gpe_fwd_entry_vnis_get
#define defined_vapi_msg_gpe_fwd_entry_vnis_get
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_gpe_fwd_entry_vnis_get;

static inline void vapi_msg_gpe_fwd_entry_vnis_get_hton(vapi_msg_gpe_fwd_entry_vnis_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_fwd_entry_vnis_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_gpe_fwd_entry_vnis_get_ntoh(vapi_msg_gpe_fwd_entry_vnis_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_fwd_entry_vnis_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_gpe_fwd_entry_vnis_get_msg_size(vapi_msg_gpe_fwd_entry_vnis_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gpe_fwd_entry_vnis_get_msg_size(vapi_msg_gpe_fwd_entry_vnis_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gpe_fwd_entry_vnis_get) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_fwd_entry_vnis_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gpe_fwd_entry_vnis_get));
      return -1;
    }
  if (vapi_calc_gpe_fwd_entry_vnis_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_fwd_entry_vnis_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gpe_fwd_entry_vnis_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_gpe_fwd_entry_vnis_get* vapi_alloc_gpe_fwd_entry_vnis_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_gpe_fwd_entry_vnis_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_gpe_fwd_entry_vnis_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_gpe_fwd_entry_vnis_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_gpe_fwd_entry_vnis_get);

  return msg;
}

static inline vapi_error_e vapi_gpe_fwd_entry_vnis_get(struct vapi_ctx_s *ctx,
  vapi_msg_gpe_fwd_entry_vnis_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_gpe_fwd_entry_vnis_get_reply *reply),
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
  vapi_msg_gpe_fwd_entry_vnis_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_gpe_fwd_entry_vnis_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_gpe_fwd_entry_vnis_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_gpe_fwd_entry_vnis_get()
{
  static const char name[] = "gpe_fwd_entry_vnis_get";
  static const char name_with_crc[] = "gpe_fwd_entry_vnis_get_51077d14";
  static vapi_message_desc_t __vapi_metadata_gpe_fwd_entry_vnis_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_gpe_fwd_entry_vnis_get_msg_size,
    (generic_swap_fn_t)vapi_msg_gpe_fwd_entry_vnis_get_hton,
    (generic_swap_fn_t)vapi_msg_gpe_fwd_entry_vnis_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gpe_fwd_entry_vnis_get = vapi_register_msg(&__vapi_metadata_gpe_fwd_entry_vnis_get);
  VAPI_DBG("Assigned msg id %d to gpe_fwd_entry_vnis_get", vapi_msg_id_gpe_fwd_entry_vnis_get);
}
#endif

#ifndef defined_vapi_msg_gpe_fwd_entries_get_reply
#define defined_vapi_msg_gpe_fwd_entries_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 count;
  vapi_type_gpe_fwd_entry entries[0]; 
} vapi_payload_gpe_fwd_entries_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_gpe_fwd_entries_get_reply payload;
} vapi_msg_gpe_fwd_entries_get_reply;

static inline void vapi_msg_gpe_fwd_entries_get_reply_payload_hton(vapi_payload_gpe_fwd_entries_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->count = htobe32(payload->count);
  do { unsigned i; for (i = 0; i < be32toh(payload->count); ++i) { vapi_type_gpe_fwd_entry_hton(&payload->entries[i]); } } while(0);
}

static inline void vapi_msg_gpe_fwd_entries_get_reply_payload_ntoh(vapi_payload_gpe_fwd_entries_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->count = be32toh(payload->count);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { vapi_type_gpe_fwd_entry_ntoh(&payload->entries[i]); } } while(0);
}

static inline void vapi_msg_gpe_fwd_entries_get_reply_hton(vapi_msg_gpe_fwd_entries_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_fwd_entries_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_gpe_fwd_entries_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_gpe_fwd_entries_get_reply_ntoh(vapi_msg_gpe_fwd_entries_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_fwd_entries_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_gpe_fwd_entries_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gpe_fwd_entries_get_reply_msg_size(vapi_msg_gpe_fwd_entries_get_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.entries[0]) * msg->payload.count;
}

static inline int vapi_verify_gpe_fwd_entries_get_reply_msg_size(vapi_msg_gpe_fwd_entries_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gpe_fwd_entries_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_fwd_entries_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gpe_fwd_entries_get_reply));
      return -1;
    }
  if (vapi_calc_gpe_fwd_entries_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_fwd_entries_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gpe_fwd_entries_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_gpe_fwd_entries_get_reply()
{
  static const char name[] = "gpe_fwd_entries_get_reply";
  static const char name_with_crc[] = "gpe_fwd_entries_get_reply_c4844876";
  static vapi_message_desc_t __vapi_metadata_gpe_fwd_entries_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_gpe_fwd_entries_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_gpe_fwd_entries_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_gpe_fwd_entries_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_gpe_fwd_entries_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gpe_fwd_entries_get_reply = vapi_register_msg(&__vapi_metadata_gpe_fwd_entries_get_reply);
  VAPI_DBG("Assigned msg id %d to gpe_fwd_entries_get_reply", vapi_msg_id_gpe_fwd_entries_get_reply);
}

static inline void vapi_set_vapi_msg_gpe_fwd_entries_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_gpe_fwd_entries_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_gpe_fwd_entries_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_gpe_fwd_entries_get
#define defined_vapi_msg_gpe_fwd_entries_get
typedef struct __attribute__ ((__packed__)) {
  u32 vni; 
} vapi_payload_gpe_fwd_entries_get;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_gpe_fwd_entries_get payload;
} vapi_msg_gpe_fwd_entries_get;

static inline void vapi_msg_gpe_fwd_entries_get_payload_hton(vapi_payload_gpe_fwd_entries_get *payload)
{
  payload->vni = htobe32(payload->vni);
}

static inline void vapi_msg_gpe_fwd_entries_get_payload_ntoh(vapi_payload_gpe_fwd_entries_get *payload)
{
  payload->vni = be32toh(payload->vni);
}

static inline void vapi_msg_gpe_fwd_entries_get_hton(vapi_msg_gpe_fwd_entries_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_fwd_entries_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_gpe_fwd_entries_get_payload_hton(&msg->payload);
}

static inline void vapi_msg_gpe_fwd_entries_get_ntoh(vapi_msg_gpe_fwd_entries_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_fwd_entries_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_gpe_fwd_entries_get_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gpe_fwd_entries_get_msg_size(vapi_msg_gpe_fwd_entries_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gpe_fwd_entries_get_msg_size(vapi_msg_gpe_fwd_entries_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gpe_fwd_entries_get) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_fwd_entries_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gpe_fwd_entries_get));
      return -1;
    }
  if (vapi_calc_gpe_fwd_entries_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_fwd_entries_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gpe_fwd_entries_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_gpe_fwd_entries_get* vapi_alloc_gpe_fwd_entries_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_gpe_fwd_entries_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_gpe_fwd_entries_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_gpe_fwd_entries_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_gpe_fwd_entries_get);

  return msg;
}

static inline vapi_error_e vapi_gpe_fwd_entries_get(struct vapi_ctx_s *ctx,
  vapi_msg_gpe_fwd_entries_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_gpe_fwd_entries_get_reply *reply),
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
  vapi_msg_gpe_fwd_entries_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_gpe_fwd_entries_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_gpe_fwd_entries_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_gpe_fwd_entries_get()
{
  static const char name[] = "gpe_fwd_entries_get";
  static const char name_with_crc[] = "gpe_fwd_entries_get_8d1f2fe9";
  static vapi_message_desc_t __vapi_metadata_gpe_fwd_entries_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_gpe_fwd_entries_get, payload),
    (verify_msg_size_fn_t)vapi_verify_gpe_fwd_entries_get_msg_size,
    (generic_swap_fn_t)vapi_msg_gpe_fwd_entries_get_hton,
    (generic_swap_fn_t)vapi_msg_gpe_fwd_entries_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gpe_fwd_entries_get = vapi_register_msg(&__vapi_metadata_gpe_fwd_entries_get);
  VAPI_DBG("Assigned msg id %d to gpe_fwd_entries_get", vapi_msg_id_gpe_fwd_entries_get);
}
#endif

#ifndef defined_vapi_msg_gpe_fwd_entry_path_details
#define defined_vapi_msg_gpe_fwd_entry_path_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_gpe_locator lcl_loc;
  vapi_type_gpe_locator rmt_loc; 
} vapi_payload_gpe_fwd_entry_path_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_gpe_fwd_entry_path_details payload;
} vapi_msg_gpe_fwd_entry_path_details;

static inline void vapi_msg_gpe_fwd_entry_path_details_payload_hton(vapi_payload_gpe_fwd_entry_path_details *payload)
{

}

static inline void vapi_msg_gpe_fwd_entry_path_details_payload_ntoh(vapi_payload_gpe_fwd_entry_path_details *payload)
{

}

static inline void vapi_msg_gpe_fwd_entry_path_details_hton(vapi_msg_gpe_fwd_entry_path_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_fwd_entry_path_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_gpe_fwd_entry_path_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_gpe_fwd_entry_path_details_ntoh(vapi_msg_gpe_fwd_entry_path_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_fwd_entry_path_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_gpe_fwd_entry_path_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gpe_fwd_entry_path_details_msg_size(vapi_msg_gpe_fwd_entry_path_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gpe_fwd_entry_path_details_msg_size(vapi_msg_gpe_fwd_entry_path_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gpe_fwd_entry_path_details) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_fwd_entry_path_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gpe_fwd_entry_path_details));
      return -1;
    }
  if (vapi_calc_gpe_fwd_entry_path_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_fwd_entry_path_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gpe_fwd_entry_path_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_gpe_fwd_entry_path_details()
{
  static const char name[] = "gpe_fwd_entry_path_details";
  static const char name_with_crc[] = "gpe_fwd_entry_path_details_483df51a";
  static vapi_message_desc_t __vapi_metadata_gpe_fwd_entry_path_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_gpe_fwd_entry_path_details, payload),
    (verify_msg_size_fn_t)vapi_verify_gpe_fwd_entry_path_details_msg_size,
    (generic_swap_fn_t)vapi_msg_gpe_fwd_entry_path_details_hton,
    (generic_swap_fn_t)vapi_msg_gpe_fwd_entry_path_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gpe_fwd_entry_path_details = vapi_register_msg(&__vapi_metadata_gpe_fwd_entry_path_details);
  VAPI_DBG("Assigned msg id %d to gpe_fwd_entry_path_details", vapi_msg_id_gpe_fwd_entry_path_details);
}

static inline void vapi_set_vapi_msg_gpe_fwd_entry_path_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_gpe_fwd_entry_path_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_gpe_fwd_entry_path_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_gpe_fwd_entry_path_dump
#define defined_vapi_msg_gpe_fwd_entry_path_dump
typedef struct __attribute__ ((__packed__)) {
  u32 fwd_entry_index; 
} vapi_payload_gpe_fwd_entry_path_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_gpe_fwd_entry_path_dump payload;
} vapi_msg_gpe_fwd_entry_path_dump;

static inline void vapi_msg_gpe_fwd_entry_path_dump_payload_hton(vapi_payload_gpe_fwd_entry_path_dump *payload)
{
  payload->fwd_entry_index = htobe32(payload->fwd_entry_index);
}

static inline void vapi_msg_gpe_fwd_entry_path_dump_payload_ntoh(vapi_payload_gpe_fwd_entry_path_dump *payload)
{
  payload->fwd_entry_index = be32toh(payload->fwd_entry_index);
}

static inline void vapi_msg_gpe_fwd_entry_path_dump_hton(vapi_msg_gpe_fwd_entry_path_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_fwd_entry_path_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_gpe_fwd_entry_path_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_gpe_fwd_entry_path_dump_ntoh(vapi_msg_gpe_fwd_entry_path_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_fwd_entry_path_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_gpe_fwd_entry_path_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gpe_fwd_entry_path_dump_msg_size(vapi_msg_gpe_fwd_entry_path_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gpe_fwd_entry_path_dump_msg_size(vapi_msg_gpe_fwd_entry_path_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gpe_fwd_entry_path_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_fwd_entry_path_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gpe_fwd_entry_path_dump));
      return -1;
    }
  if (vapi_calc_gpe_fwd_entry_path_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_fwd_entry_path_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gpe_fwd_entry_path_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_gpe_fwd_entry_path_dump* vapi_alloc_gpe_fwd_entry_path_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_gpe_fwd_entry_path_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_gpe_fwd_entry_path_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_gpe_fwd_entry_path_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_gpe_fwd_entry_path_dump);

  return msg;
}

static inline vapi_error_e vapi_gpe_fwd_entry_path_dump(struct vapi_ctx_s *ctx,
  vapi_msg_gpe_fwd_entry_path_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_gpe_fwd_entry_path_details *reply),
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
  vapi_msg_gpe_fwd_entry_path_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_gpe_fwd_entry_path_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_gpe_fwd_entry_path_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_gpe_fwd_entry_path_dump()
{
  static const char name[] = "gpe_fwd_entry_path_dump";
  static const char name_with_crc[] = "gpe_fwd_entry_path_dump_39bce980";
  static vapi_message_desc_t __vapi_metadata_gpe_fwd_entry_path_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_gpe_fwd_entry_path_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_gpe_fwd_entry_path_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_gpe_fwd_entry_path_dump_hton,
    (generic_swap_fn_t)vapi_msg_gpe_fwd_entry_path_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gpe_fwd_entry_path_dump = vapi_register_msg(&__vapi_metadata_gpe_fwd_entry_path_dump);
  VAPI_DBG("Assigned msg id %d to gpe_fwd_entry_path_dump", vapi_msg_id_gpe_fwd_entry_path_dump);
}
#endif

#ifndef defined_vapi_msg_gpe_set_encap_mode_reply
#define defined_vapi_msg_gpe_set_encap_mode_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_gpe_set_encap_mode_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_gpe_set_encap_mode_reply payload;
} vapi_msg_gpe_set_encap_mode_reply;

static inline void vapi_msg_gpe_set_encap_mode_reply_payload_hton(vapi_payload_gpe_set_encap_mode_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_gpe_set_encap_mode_reply_payload_ntoh(vapi_payload_gpe_set_encap_mode_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_gpe_set_encap_mode_reply_hton(vapi_msg_gpe_set_encap_mode_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_set_encap_mode_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_gpe_set_encap_mode_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_gpe_set_encap_mode_reply_ntoh(vapi_msg_gpe_set_encap_mode_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_set_encap_mode_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_gpe_set_encap_mode_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gpe_set_encap_mode_reply_msg_size(vapi_msg_gpe_set_encap_mode_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gpe_set_encap_mode_reply_msg_size(vapi_msg_gpe_set_encap_mode_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gpe_set_encap_mode_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_set_encap_mode_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gpe_set_encap_mode_reply));
      return -1;
    }
  if (vapi_calc_gpe_set_encap_mode_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_set_encap_mode_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gpe_set_encap_mode_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_gpe_set_encap_mode_reply()
{
  static const char name[] = "gpe_set_encap_mode_reply";
  static const char name_with_crc[] = "gpe_set_encap_mode_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_gpe_set_encap_mode_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_gpe_set_encap_mode_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_gpe_set_encap_mode_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_gpe_set_encap_mode_reply_hton,
    (generic_swap_fn_t)vapi_msg_gpe_set_encap_mode_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gpe_set_encap_mode_reply = vapi_register_msg(&__vapi_metadata_gpe_set_encap_mode_reply);
  VAPI_DBG("Assigned msg id %d to gpe_set_encap_mode_reply", vapi_msg_id_gpe_set_encap_mode_reply);
}

static inline void vapi_set_vapi_msg_gpe_set_encap_mode_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_gpe_set_encap_mode_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_gpe_set_encap_mode_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_gpe_set_encap_mode
#define defined_vapi_msg_gpe_set_encap_mode
typedef struct __attribute__ ((__packed__)) {
  bool is_vxlan; 
} vapi_payload_gpe_set_encap_mode;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_gpe_set_encap_mode payload;
} vapi_msg_gpe_set_encap_mode;

static inline void vapi_msg_gpe_set_encap_mode_payload_hton(vapi_payload_gpe_set_encap_mode *payload)
{

}

static inline void vapi_msg_gpe_set_encap_mode_payload_ntoh(vapi_payload_gpe_set_encap_mode *payload)
{

}

static inline void vapi_msg_gpe_set_encap_mode_hton(vapi_msg_gpe_set_encap_mode *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_set_encap_mode'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_gpe_set_encap_mode_payload_hton(&msg->payload);
}

static inline void vapi_msg_gpe_set_encap_mode_ntoh(vapi_msg_gpe_set_encap_mode *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_set_encap_mode'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_gpe_set_encap_mode_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gpe_set_encap_mode_msg_size(vapi_msg_gpe_set_encap_mode *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gpe_set_encap_mode_msg_size(vapi_msg_gpe_set_encap_mode *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gpe_set_encap_mode) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_set_encap_mode' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gpe_set_encap_mode));
      return -1;
    }
  if (vapi_calc_gpe_set_encap_mode_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_set_encap_mode' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gpe_set_encap_mode_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_gpe_set_encap_mode* vapi_alloc_gpe_set_encap_mode(struct vapi_ctx_s *ctx)
{
  vapi_msg_gpe_set_encap_mode *msg = NULL;
  const size_t size = sizeof(vapi_msg_gpe_set_encap_mode);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_gpe_set_encap_mode*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_gpe_set_encap_mode);

  return msg;
}

static inline vapi_error_e vapi_gpe_set_encap_mode(struct vapi_ctx_s *ctx,
  vapi_msg_gpe_set_encap_mode *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_gpe_set_encap_mode_reply *reply),
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
  vapi_msg_gpe_set_encap_mode_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_gpe_set_encap_mode_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_gpe_set_encap_mode_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_gpe_set_encap_mode()
{
  static const char name[] = "gpe_set_encap_mode";
  static const char name_with_crc[] = "gpe_set_encap_mode_bd819eac";
  static vapi_message_desc_t __vapi_metadata_gpe_set_encap_mode = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_gpe_set_encap_mode, payload),
    (verify_msg_size_fn_t)vapi_verify_gpe_set_encap_mode_msg_size,
    (generic_swap_fn_t)vapi_msg_gpe_set_encap_mode_hton,
    (generic_swap_fn_t)vapi_msg_gpe_set_encap_mode_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gpe_set_encap_mode = vapi_register_msg(&__vapi_metadata_gpe_set_encap_mode);
  VAPI_DBG("Assigned msg id %d to gpe_set_encap_mode", vapi_msg_id_gpe_set_encap_mode);
}
#endif

#ifndef defined_vapi_msg_gpe_get_encap_mode_reply
#define defined_vapi_msg_gpe_get_encap_mode_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u8 encap_mode; 
} vapi_payload_gpe_get_encap_mode_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_gpe_get_encap_mode_reply payload;
} vapi_msg_gpe_get_encap_mode_reply;

static inline void vapi_msg_gpe_get_encap_mode_reply_payload_hton(vapi_payload_gpe_get_encap_mode_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_gpe_get_encap_mode_reply_payload_ntoh(vapi_payload_gpe_get_encap_mode_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_gpe_get_encap_mode_reply_hton(vapi_msg_gpe_get_encap_mode_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_get_encap_mode_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_gpe_get_encap_mode_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_gpe_get_encap_mode_reply_ntoh(vapi_msg_gpe_get_encap_mode_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_get_encap_mode_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_gpe_get_encap_mode_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gpe_get_encap_mode_reply_msg_size(vapi_msg_gpe_get_encap_mode_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gpe_get_encap_mode_reply_msg_size(vapi_msg_gpe_get_encap_mode_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gpe_get_encap_mode_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_get_encap_mode_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gpe_get_encap_mode_reply));
      return -1;
    }
  if (vapi_calc_gpe_get_encap_mode_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_get_encap_mode_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gpe_get_encap_mode_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_gpe_get_encap_mode_reply()
{
  static const char name[] = "gpe_get_encap_mode_reply";
  static const char name_with_crc[] = "gpe_get_encap_mode_reply_36e3f7ca";
  static vapi_message_desc_t __vapi_metadata_gpe_get_encap_mode_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_gpe_get_encap_mode_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_gpe_get_encap_mode_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_gpe_get_encap_mode_reply_hton,
    (generic_swap_fn_t)vapi_msg_gpe_get_encap_mode_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gpe_get_encap_mode_reply = vapi_register_msg(&__vapi_metadata_gpe_get_encap_mode_reply);
  VAPI_DBG("Assigned msg id %d to gpe_get_encap_mode_reply", vapi_msg_id_gpe_get_encap_mode_reply);
}

static inline void vapi_set_vapi_msg_gpe_get_encap_mode_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_gpe_get_encap_mode_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_gpe_get_encap_mode_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_gpe_get_encap_mode
#define defined_vapi_msg_gpe_get_encap_mode
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_gpe_get_encap_mode;

static inline void vapi_msg_gpe_get_encap_mode_hton(vapi_msg_gpe_get_encap_mode *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_get_encap_mode'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_gpe_get_encap_mode_ntoh(vapi_msg_gpe_get_encap_mode *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_get_encap_mode'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_gpe_get_encap_mode_msg_size(vapi_msg_gpe_get_encap_mode *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gpe_get_encap_mode_msg_size(vapi_msg_gpe_get_encap_mode *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gpe_get_encap_mode) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_get_encap_mode' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gpe_get_encap_mode));
      return -1;
    }
  if (vapi_calc_gpe_get_encap_mode_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_get_encap_mode' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gpe_get_encap_mode_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_gpe_get_encap_mode* vapi_alloc_gpe_get_encap_mode(struct vapi_ctx_s *ctx)
{
  vapi_msg_gpe_get_encap_mode *msg = NULL;
  const size_t size = sizeof(vapi_msg_gpe_get_encap_mode);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_gpe_get_encap_mode*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_gpe_get_encap_mode);

  return msg;
}

static inline vapi_error_e vapi_gpe_get_encap_mode(struct vapi_ctx_s *ctx,
  vapi_msg_gpe_get_encap_mode *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_gpe_get_encap_mode_reply *reply),
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
  vapi_msg_gpe_get_encap_mode_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_gpe_get_encap_mode_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_gpe_get_encap_mode_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_gpe_get_encap_mode()
{
  static const char name[] = "gpe_get_encap_mode";
  static const char name_with_crc[] = "gpe_get_encap_mode_51077d14";
  static vapi_message_desc_t __vapi_metadata_gpe_get_encap_mode = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_gpe_get_encap_mode_msg_size,
    (generic_swap_fn_t)vapi_msg_gpe_get_encap_mode_hton,
    (generic_swap_fn_t)vapi_msg_gpe_get_encap_mode_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gpe_get_encap_mode = vapi_register_msg(&__vapi_metadata_gpe_get_encap_mode);
  VAPI_DBG("Assigned msg id %d to gpe_get_encap_mode", vapi_msg_id_gpe_get_encap_mode);
}
#endif

#ifndef defined_vapi_msg_gpe_add_del_native_fwd_rpath_reply
#define defined_vapi_msg_gpe_add_del_native_fwd_rpath_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_gpe_add_del_native_fwd_rpath_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_gpe_add_del_native_fwd_rpath_reply payload;
} vapi_msg_gpe_add_del_native_fwd_rpath_reply;

static inline void vapi_msg_gpe_add_del_native_fwd_rpath_reply_payload_hton(vapi_payload_gpe_add_del_native_fwd_rpath_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_gpe_add_del_native_fwd_rpath_reply_payload_ntoh(vapi_payload_gpe_add_del_native_fwd_rpath_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_gpe_add_del_native_fwd_rpath_reply_hton(vapi_msg_gpe_add_del_native_fwd_rpath_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_add_del_native_fwd_rpath_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_gpe_add_del_native_fwd_rpath_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_gpe_add_del_native_fwd_rpath_reply_ntoh(vapi_msg_gpe_add_del_native_fwd_rpath_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_add_del_native_fwd_rpath_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_gpe_add_del_native_fwd_rpath_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gpe_add_del_native_fwd_rpath_reply_msg_size(vapi_msg_gpe_add_del_native_fwd_rpath_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gpe_add_del_native_fwd_rpath_reply_msg_size(vapi_msg_gpe_add_del_native_fwd_rpath_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gpe_add_del_native_fwd_rpath_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_add_del_native_fwd_rpath_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gpe_add_del_native_fwd_rpath_reply));
      return -1;
    }
  if (vapi_calc_gpe_add_del_native_fwd_rpath_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_add_del_native_fwd_rpath_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gpe_add_del_native_fwd_rpath_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_gpe_add_del_native_fwd_rpath_reply()
{
  static const char name[] = "gpe_add_del_native_fwd_rpath_reply";
  static const char name_with_crc[] = "gpe_add_del_native_fwd_rpath_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_gpe_add_del_native_fwd_rpath_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_gpe_add_del_native_fwd_rpath_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_gpe_add_del_native_fwd_rpath_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_gpe_add_del_native_fwd_rpath_reply_hton,
    (generic_swap_fn_t)vapi_msg_gpe_add_del_native_fwd_rpath_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gpe_add_del_native_fwd_rpath_reply = vapi_register_msg(&__vapi_metadata_gpe_add_del_native_fwd_rpath_reply);
  VAPI_DBG("Assigned msg id %d to gpe_add_del_native_fwd_rpath_reply", vapi_msg_id_gpe_add_del_native_fwd_rpath_reply);
}

static inline void vapi_set_vapi_msg_gpe_add_del_native_fwd_rpath_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_gpe_add_del_native_fwd_rpath_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_gpe_add_del_native_fwd_rpath_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_gpe_add_del_native_fwd_rpath
#define defined_vapi_msg_gpe_add_del_native_fwd_rpath
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  u32 table_id;
  vapi_type_interface_index nh_sw_if_index;
  vapi_type_address nh_addr; 
} vapi_payload_gpe_add_del_native_fwd_rpath;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_gpe_add_del_native_fwd_rpath payload;
} vapi_msg_gpe_add_del_native_fwd_rpath;

static inline void vapi_msg_gpe_add_del_native_fwd_rpath_payload_hton(vapi_payload_gpe_add_del_native_fwd_rpath *payload)
{
  payload->table_id = htobe32(payload->table_id);
  payload->nh_sw_if_index = htobe32(payload->nh_sw_if_index);
}

static inline void vapi_msg_gpe_add_del_native_fwd_rpath_payload_ntoh(vapi_payload_gpe_add_del_native_fwd_rpath *payload)
{
  payload->table_id = be32toh(payload->table_id);
  payload->nh_sw_if_index = be32toh(payload->nh_sw_if_index);
}

static inline void vapi_msg_gpe_add_del_native_fwd_rpath_hton(vapi_msg_gpe_add_del_native_fwd_rpath *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_add_del_native_fwd_rpath'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_gpe_add_del_native_fwd_rpath_payload_hton(&msg->payload);
}

static inline void vapi_msg_gpe_add_del_native_fwd_rpath_ntoh(vapi_msg_gpe_add_del_native_fwd_rpath *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_add_del_native_fwd_rpath'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_gpe_add_del_native_fwd_rpath_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gpe_add_del_native_fwd_rpath_msg_size(vapi_msg_gpe_add_del_native_fwd_rpath *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gpe_add_del_native_fwd_rpath_msg_size(vapi_msg_gpe_add_del_native_fwd_rpath *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gpe_add_del_native_fwd_rpath) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_add_del_native_fwd_rpath' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gpe_add_del_native_fwd_rpath));
      return -1;
    }
  if (vapi_calc_gpe_add_del_native_fwd_rpath_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_add_del_native_fwd_rpath' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gpe_add_del_native_fwd_rpath_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_gpe_add_del_native_fwd_rpath* vapi_alloc_gpe_add_del_native_fwd_rpath(struct vapi_ctx_s *ctx)
{
  vapi_msg_gpe_add_del_native_fwd_rpath *msg = NULL;
  const size_t size = sizeof(vapi_msg_gpe_add_del_native_fwd_rpath);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_gpe_add_del_native_fwd_rpath*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_gpe_add_del_native_fwd_rpath);

  return msg;
}

static inline vapi_error_e vapi_gpe_add_del_native_fwd_rpath(struct vapi_ctx_s *ctx,
  vapi_msg_gpe_add_del_native_fwd_rpath *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_gpe_add_del_native_fwd_rpath_reply *reply),
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
  vapi_msg_gpe_add_del_native_fwd_rpath_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_gpe_add_del_native_fwd_rpath_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_gpe_add_del_native_fwd_rpath_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_gpe_add_del_native_fwd_rpath()
{
  static const char name[] = "gpe_add_del_native_fwd_rpath";
  static const char name_with_crc[] = "gpe_add_del_native_fwd_rpath_43fc8b54";
  static vapi_message_desc_t __vapi_metadata_gpe_add_del_native_fwd_rpath = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_gpe_add_del_native_fwd_rpath, payload),
    (verify_msg_size_fn_t)vapi_verify_gpe_add_del_native_fwd_rpath_msg_size,
    (generic_swap_fn_t)vapi_msg_gpe_add_del_native_fwd_rpath_hton,
    (generic_swap_fn_t)vapi_msg_gpe_add_del_native_fwd_rpath_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gpe_add_del_native_fwd_rpath = vapi_register_msg(&__vapi_metadata_gpe_add_del_native_fwd_rpath);
  VAPI_DBG("Assigned msg id %d to gpe_add_del_native_fwd_rpath", vapi_msg_id_gpe_add_del_native_fwd_rpath);
}
#endif

#ifndef defined_vapi_msg_gpe_native_fwd_rpaths_get_reply
#define defined_vapi_msg_gpe_native_fwd_rpaths_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 count;
  vapi_type_gpe_native_fwd_rpath entries[0]; 
} vapi_payload_gpe_native_fwd_rpaths_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_gpe_native_fwd_rpaths_get_reply payload;
} vapi_msg_gpe_native_fwd_rpaths_get_reply;

static inline void vapi_msg_gpe_native_fwd_rpaths_get_reply_payload_hton(vapi_payload_gpe_native_fwd_rpaths_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->count = htobe32(payload->count);
  do { unsigned i; for (i = 0; i < be32toh(payload->count); ++i) { vapi_type_gpe_native_fwd_rpath_hton(&payload->entries[i]); } } while(0);
}

static inline void vapi_msg_gpe_native_fwd_rpaths_get_reply_payload_ntoh(vapi_payload_gpe_native_fwd_rpaths_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->count = be32toh(payload->count);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { vapi_type_gpe_native_fwd_rpath_ntoh(&payload->entries[i]); } } while(0);
}

static inline void vapi_msg_gpe_native_fwd_rpaths_get_reply_hton(vapi_msg_gpe_native_fwd_rpaths_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_native_fwd_rpaths_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_gpe_native_fwd_rpaths_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_gpe_native_fwd_rpaths_get_reply_ntoh(vapi_msg_gpe_native_fwd_rpaths_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_native_fwd_rpaths_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_gpe_native_fwd_rpaths_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gpe_native_fwd_rpaths_get_reply_msg_size(vapi_msg_gpe_native_fwd_rpaths_get_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.entries[0]) * msg->payload.count;
}

static inline int vapi_verify_gpe_native_fwd_rpaths_get_reply_msg_size(vapi_msg_gpe_native_fwd_rpaths_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gpe_native_fwd_rpaths_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_native_fwd_rpaths_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gpe_native_fwd_rpaths_get_reply));
      return -1;
    }
  if (vapi_calc_gpe_native_fwd_rpaths_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_native_fwd_rpaths_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gpe_native_fwd_rpaths_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_gpe_native_fwd_rpaths_get_reply()
{
  static const char name[] = "gpe_native_fwd_rpaths_get_reply";
  static const char name_with_crc[] = "gpe_native_fwd_rpaths_get_reply_7a1ca5a2";
  static vapi_message_desc_t __vapi_metadata_gpe_native_fwd_rpaths_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_gpe_native_fwd_rpaths_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_gpe_native_fwd_rpaths_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_gpe_native_fwd_rpaths_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_gpe_native_fwd_rpaths_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gpe_native_fwd_rpaths_get_reply = vapi_register_msg(&__vapi_metadata_gpe_native_fwd_rpaths_get_reply);
  VAPI_DBG("Assigned msg id %d to gpe_native_fwd_rpaths_get_reply", vapi_msg_id_gpe_native_fwd_rpaths_get_reply);
}

static inline void vapi_set_vapi_msg_gpe_native_fwd_rpaths_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_gpe_native_fwd_rpaths_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_gpe_native_fwd_rpaths_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_gpe_native_fwd_rpaths_get
#define defined_vapi_msg_gpe_native_fwd_rpaths_get
typedef struct __attribute__ ((__packed__)) {
  bool is_ip4; 
} vapi_payload_gpe_native_fwd_rpaths_get;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_gpe_native_fwd_rpaths_get payload;
} vapi_msg_gpe_native_fwd_rpaths_get;

static inline void vapi_msg_gpe_native_fwd_rpaths_get_payload_hton(vapi_payload_gpe_native_fwd_rpaths_get *payload)
{

}

static inline void vapi_msg_gpe_native_fwd_rpaths_get_payload_ntoh(vapi_payload_gpe_native_fwd_rpaths_get *payload)
{

}

static inline void vapi_msg_gpe_native_fwd_rpaths_get_hton(vapi_msg_gpe_native_fwd_rpaths_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_native_fwd_rpaths_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_gpe_native_fwd_rpaths_get_payload_hton(&msg->payload);
}

static inline void vapi_msg_gpe_native_fwd_rpaths_get_ntoh(vapi_msg_gpe_native_fwd_rpaths_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gpe_native_fwd_rpaths_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_gpe_native_fwd_rpaths_get_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gpe_native_fwd_rpaths_get_msg_size(vapi_msg_gpe_native_fwd_rpaths_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gpe_native_fwd_rpaths_get_msg_size(vapi_msg_gpe_native_fwd_rpaths_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gpe_native_fwd_rpaths_get) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_native_fwd_rpaths_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gpe_native_fwd_rpaths_get));
      return -1;
    }
  if (vapi_calc_gpe_native_fwd_rpaths_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gpe_native_fwd_rpaths_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gpe_native_fwd_rpaths_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_gpe_native_fwd_rpaths_get* vapi_alloc_gpe_native_fwd_rpaths_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_gpe_native_fwd_rpaths_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_gpe_native_fwd_rpaths_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_gpe_native_fwd_rpaths_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_gpe_native_fwd_rpaths_get);

  return msg;
}

static inline vapi_error_e vapi_gpe_native_fwd_rpaths_get(struct vapi_ctx_s *ctx,
  vapi_msg_gpe_native_fwd_rpaths_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_gpe_native_fwd_rpaths_get_reply *reply),
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
  vapi_msg_gpe_native_fwd_rpaths_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_gpe_native_fwd_rpaths_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_gpe_native_fwd_rpaths_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_gpe_native_fwd_rpaths_get()
{
  static const char name[] = "gpe_native_fwd_rpaths_get";
  static const char name_with_crc[] = "gpe_native_fwd_rpaths_get_f652ceb4";
  static vapi_message_desc_t __vapi_metadata_gpe_native_fwd_rpaths_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_gpe_native_fwd_rpaths_get, payload),
    (verify_msg_size_fn_t)vapi_verify_gpe_native_fwd_rpaths_get_msg_size,
    (generic_swap_fn_t)vapi_msg_gpe_native_fwd_rpaths_get_hton,
    (generic_swap_fn_t)vapi_msg_gpe_native_fwd_rpaths_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gpe_native_fwd_rpaths_get = vapi_register_msg(&__vapi_metadata_gpe_native_fwd_rpaths_get);
  VAPI_DBG("Assigned msg id %d to gpe_native_fwd_rpaths_get", vapi_msg_id_gpe_native_fwd_rpaths_get);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
