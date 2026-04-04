#ifndef __included_nat64_api_json
#define __included_nat64_api_json

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

extern vapi_msg_id_t vapi_msg_id_nat64_plugin_enable_disable;
extern vapi_msg_id_t vapi_msg_id_nat64_plugin_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_nat64_set_timeouts;
extern vapi_msg_id_t vapi_msg_id_nat64_set_timeouts_reply;
extern vapi_msg_id_t vapi_msg_id_nat64_get_timeouts;
extern vapi_msg_id_t vapi_msg_id_nat64_get_timeouts_reply;
extern vapi_msg_id_t vapi_msg_id_nat64_add_del_pool_addr_range;
extern vapi_msg_id_t vapi_msg_id_nat64_add_del_pool_addr_range_reply;
extern vapi_msg_id_t vapi_msg_id_nat64_pool_addr_dump;
extern vapi_msg_id_t vapi_msg_id_nat64_pool_addr_details;
extern vapi_msg_id_t vapi_msg_id_nat64_add_del_interface;
extern vapi_msg_id_t vapi_msg_id_nat64_add_del_interface_reply;
extern vapi_msg_id_t vapi_msg_id_nat64_interface_dump;
extern vapi_msg_id_t vapi_msg_id_nat64_interface_details;
extern vapi_msg_id_t vapi_msg_id_nat64_add_del_static_bib;
extern vapi_msg_id_t vapi_msg_id_nat64_add_del_static_bib_reply;
extern vapi_msg_id_t vapi_msg_id_nat64_bib_dump;
extern vapi_msg_id_t vapi_msg_id_nat64_bib_details;
extern vapi_msg_id_t vapi_msg_id_nat64_st_dump;
extern vapi_msg_id_t vapi_msg_id_nat64_st_details;
extern vapi_msg_id_t vapi_msg_id_nat64_add_del_prefix;
extern vapi_msg_id_t vapi_msg_id_nat64_add_del_prefix_reply;
extern vapi_msg_id_t vapi_msg_id_nat64_prefix_dump;
extern vapi_msg_id_t vapi_msg_id_nat64_prefix_details;
extern vapi_msg_id_t vapi_msg_id_nat64_add_del_interface_addr;
extern vapi_msg_id_t vapi_msg_id_nat64_add_del_interface_addr_reply;

#define DEFINE_VAPI_MSG_IDS_NAT64_API_JSON\
  vapi_msg_id_t vapi_msg_id_nat64_plugin_enable_disable;\
  vapi_msg_id_t vapi_msg_id_nat64_plugin_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_nat64_set_timeouts;\
  vapi_msg_id_t vapi_msg_id_nat64_set_timeouts_reply;\
  vapi_msg_id_t vapi_msg_id_nat64_get_timeouts;\
  vapi_msg_id_t vapi_msg_id_nat64_get_timeouts_reply;\
  vapi_msg_id_t vapi_msg_id_nat64_add_del_pool_addr_range;\
  vapi_msg_id_t vapi_msg_id_nat64_add_del_pool_addr_range_reply;\
  vapi_msg_id_t vapi_msg_id_nat64_pool_addr_dump;\
  vapi_msg_id_t vapi_msg_id_nat64_pool_addr_details;\
  vapi_msg_id_t vapi_msg_id_nat64_add_del_interface;\
  vapi_msg_id_t vapi_msg_id_nat64_add_del_interface_reply;\
  vapi_msg_id_t vapi_msg_id_nat64_interface_dump;\
  vapi_msg_id_t vapi_msg_id_nat64_interface_details;\
  vapi_msg_id_t vapi_msg_id_nat64_add_del_static_bib;\
  vapi_msg_id_t vapi_msg_id_nat64_add_del_static_bib_reply;\
  vapi_msg_id_t vapi_msg_id_nat64_bib_dump;\
  vapi_msg_id_t vapi_msg_id_nat64_bib_details;\
  vapi_msg_id_t vapi_msg_id_nat64_st_dump;\
  vapi_msg_id_t vapi_msg_id_nat64_st_details;\
  vapi_msg_id_t vapi_msg_id_nat64_add_del_prefix;\
  vapi_msg_id_t vapi_msg_id_nat64_add_del_prefix_reply;\
  vapi_msg_id_t vapi_msg_id_nat64_prefix_dump;\
  vapi_msg_id_t vapi_msg_id_nat64_prefix_details;\
  vapi_msg_id_t vapi_msg_id_nat64_add_del_interface_addr;\
  vapi_msg_id_t vapi_msg_id_nat64_add_del_interface_addr_reply;


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

#ifndef defined_vapi_enum_nat_log_level
#define defined_vapi_enum_nat_log_level
typedef enum {
  NAT_LOG_NONE = 0,
  NAT_LOG_ERROR = 1,
  NAT_LOG_WARNING = 2,
  NAT_LOG_NOTICE = 3,
  NAT_LOG_INFO = 4,
  NAT_LOG_DEBUG = 5,
} __attribute__((packed)) vapi_enum_nat_log_level;

#endif

#ifndef defined_vapi_enum_nat_config_flags
#define defined_vapi_enum_nat_config_flags
typedef enum {
  NAT_IS_NONE = 0,
  NAT_IS_TWICE_NAT = 1,
  NAT_IS_SELF_TWICE_NAT = 2,
  NAT_IS_OUT2IN_ONLY = 4,
  NAT_IS_ADDR_ONLY = 8,
  NAT_IS_OUTSIDE = 16,
  NAT_IS_INSIDE = 32,
  NAT_IS_STATIC = 64,
  NAT_IS_EXT_HOST_VALID = 128,
} __attribute__((packed)) vapi_enum_nat_config_flags;

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

#ifndef defined_vapi_type_nat_timeouts
#define defined_vapi_type_nat_timeouts
typedef struct __attribute__((__packed__)) {
  u32 udp;
  u32 tcp_established;
  u32 tcp_transitory;
  u32 icmp;
} vapi_type_nat_timeouts;

static inline void vapi_type_nat_timeouts_hton(vapi_type_nat_timeouts *msg)
{
  msg->udp = htobe32(msg->udp);
  msg->tcp_established = htobe32(msg->tcp_established);
  msg->tcp_transitory = htobe32(msg->tcp_transitory);
  msg->icmp = htobe32(msg->icmp);
}

static inline void vapi_type_nat_timeouts_ntoh(vapi_type_nat_timeouts *msg)
{
  msg->udp = be32toh(msg->udp);
  msg->tcp_established = be32toh(msg->tcp_established);
  msg->tcp_transitory = be32toh(msg->tcp_transitory);
  msg->icmp = be32toh(msg->icmp);
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

#ifndef defined_vapi_msg_nat64_plugin_enable_disable_reply
#define defined_vapi_msg_nat64_plugin_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat64_plugin_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat64_plugin_enable_disable_reply payload;
} vapi_msg_nat64_plugin_enable_disable_reply;

static inline void vapi_msg_nat64_plugin_enable_disable_reply_payload_hton(vapi_payload_nat64_plugin_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat64_plugin_enable_disable_reply_payload_ntoh(vapi_payload_nat64_plugin_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat64_plugin_enable_disable_reply_hton(vapi_msg_nat64_plugin_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_plugin_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat64_plugin_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_plugin_enable_disable_reply_ntoh(vapi_msg_nat64_plugin_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_plugin_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat64_plugin_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_plugin_enable_disable_reply_msg_size(vapi_msg_nat64_plugin_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_plugin_enable_disable_reply_msg_size(vapi_msg_nat64_plugin_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_plugin_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_plugin_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_plugin_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_nat64_plugin_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_plugin_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_plugin_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat64_plugin_enable_disable_reply()
{
  static const char name[] = "nat64_plugin_enable_disable_reply";
  static const char name_with_crc[] = "nat64_plugin_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat64_plugin_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat64_plugin_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_plugin_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_plugin_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat64_plugin_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_plugin_enable_disable_reply = vapi_register_msg(&__vapi_metadata_nat64_plugin_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to nat64_plugin_enable_disable_reply", vapi_msg_id_nat64_plugin_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_nat64_plugin_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat64_plugin_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat64_plugin_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat64_plugin_enable_disable
#define defined_vapi_msg_nat64_plugin_enable_disable
typedef struct __attribute__ ((__packed__)) {
  u32 bib_buckets;
  u32 bib_memory_size;
  u32 st_buckets;
  u32 st_memory_size;
  bool enable; 
} vapi_payload_nat64_plugin_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat64_plugin_enable_disable payload;
} vapi_msg_nat64_plugin_enable_disable;

static inline void vapi_msg_nat64_plugin_enable_disable_payload_hton(vapi_payload_nat64_plugin_enable_disable *payload)
{
  payload->bib_buckets = htobe32(payload->bib_buckets);
  payload->bib_memory_size = htobe32(payload->bib_memory_size);
  payload->st_buckets = htobe32(payload->st_buckets);
  payload->st_memory_size = htobe32(payload->st_memory_size);
}

static inline void vapi_msg_nat64_plugin_enable_disable_payload_ntoh(vapi_payload_nat64_plugin_enable_disable *payload)
{
  payload->bib_buckets = be32toh(payload->bib_buckets);
  payload->bib_memory_size = be32toh(payload->bib_memory_size);
  payload->st_buckets = be32toh(payload->st_buckets);
  payload->st_memory_size = be32toh(payload->st_memory_size);
}

static inline void vapi_msg_nat64_plugin_enable_disable_hton(vapi_msg_nat64_plugin_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_plugin_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat64_plugin_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_plugin_enable_disable_ntoh(vapi_msg_nat64_plugin_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_plugin_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat64_plugin_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_plugin_enable_disable_msg_size(vapi_msg_nat64_plugin_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_plugin_enable_disable_msg_size(vapi_msg_nat64_plugin_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_plugin_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_plugin_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_plugin_enable_disable));
      return -1;
    }
  if (vapi_calc_nat64_plugin_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_plugin_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_plugin_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat64_plugin_enable_disable* vapi_alloc_nat64_plugin_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat64_plugin_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat64_plugin_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat64_plugin_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat64_plugin_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_nat64_plugin_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_nat64_plugin_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat64_plugin_enable_disable_reply *reply),
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
  vapi_msg_nat64_plugin_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat64_plugin_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_nat64_plugin_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat64_plugin_enable_disable()
{
  static const char name[] = "nat64_plugin_enable_disable";
  static const char name_with_crc[] = "nat64_plugin_enable_disable_45948b90";
  static vapi_message_desc_t __vapi_metadata_nat64_plugin_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat64_plugin_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_plugin_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_plugin_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_nat64_plugin_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_plugin_enable_disable = vapi_register_msg(&__vapi_metadata_nat64_plugin_enable_disable);
  VAPI_DBG("Assigned msg id %d to nat64_plugin_enable_disable", vapi_msg_id_nat64_plugin_enable_disable);
}
#endif

#ifndef defined_vapi_msg_nat64_set_timeouts_reply
#define defined_vapi_msg_nat64_set_timeouts_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat64_set_timeouts_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat64_set_timeouts_reply payload;
} vapi_msg_nat64_set_timeouts_reply;

static inline void vapi_msg_nat64_set_timeouts_reply_payload_hton(vapi_payload_nat64_set_timeouts_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat64_set_timeouts_reply_payload_ntoh(vapi_payload_nat64_set_timeouts_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat64_set_timeouts_reply_hton(vapi_msg_nat64_set_timeouts_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_set_timeouts_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat64_set_timeouts_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_set_timeouts_reply_ntoh(vapi_msg_nat64_set_timeouts_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_set_timeouts_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat64_set_timeouts_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_set_timeouts_reply_msg_size(vapi_msg_nat64_set_timeouts_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_set_timeouts_reply_msg_size(vapi_msg_nat64_set_timeouts_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_set_timeouts_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_set_timeouts_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_set_timeouts_reply));
      return -1;
    }
  if (vapi_calc_nat64_set_timeouts_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_set_timeouts_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_set_timeouts_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat64_set_timeouts_reply()
{
  static const char name[] = "nat64_set_timeouts_reply";
  static const char name_with_crc[] = "nat64_set_timeouts_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat64_set_timeouts_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat64_set_timeouts_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_set_timeouts_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_set_timeouts_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat64_set_timeouts_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_set_timeouts_reply = vapi_register_msg(&__vapi_metadata_nat64_set_timeouts_reply);
  VAPI_DBG("Assigned msg id %d to nat64_set_timeouts_reply", vapi_msg_id_nat64_set_timeouts_reply);
}

static inline void vapi_set_vapi_msg_nat64_set_timeouts_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat64_set_timeouts_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat64_set_timeouts_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat64_set_timeouts
#define defined_vapi_msg_nat64_set_timeouts
typedef struct __attribute__ ((__packed__)) {
  u32 udp;
  u32 tcp_established;
  u32 tcp_transitory;
  u32 icmp; 
} vapi_payload_nat64_set_timeouts;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat64_set_timeouts payload;
} vapi_msg_nat64_set_timeouts;

static inline void vapi_msg_nat64_set_timeouts_payload_hton(vapi_payload_nat64_set_timeouts *payload)
{
  payload->udp = htobe32(payload->udp);
  payload->tcp_established = htobe32(payload->tcp_established);
  payload->tcp_transitory = htobe32(payload->tcp_transitory);
  payload->icmp = htobe32(payload->icmp);
}

static inline void vapi_msg_nat64_set_timeouts_payload_ntoh(vapi_payload_nat64_set_timeouts *payload)
{
  payload->udp = be32toh(payload->udp);
  payload->tcp_established = be32toh(payload->tcp_established);
  payload->tcp_transitory = be32toh(payload->tcp_transitory);
  payload->icmp = be32toh(payload->icmp);
}

static inline void vapi_msg_nat64_set_timeouts_hton(vapi_msg_nat64_set_timeouts *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_set_timeouts'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat64_set_timeouts_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_set_timeouts_ntoh(vapi_msg_nat64_set_timeouts *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_set_timeouts'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat64_set_timeouts_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_set_timeouts_msg_size(vapi_msg_nat64_set_timeouts *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_set_timeouts_msg_size(vapi_msg_nat64_set_timeouts *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_set_timeouts) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_set_timeouts' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_set_timeouts));
      return -1;
    }
  if (vapi_calc_nat64_set_timeouts_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_set_timeouts' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_set_timeouts_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat64_set_timeouts* vapi_alloc_nat64_set_timeouts(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat64_set_timeouts *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat64_set_timeouts);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat64_set_timeouts*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat64_set_timeouts);

  return msg;
}

static inline vapi_error_e vapi_nat64_set_timeouts(struct vapi_ctx_s *ctx,
  vapi_msg_nat64_set_timeouts *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat64_set_timeouts_reply *reply),
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
  vapi_msg_nat64_set_timeouts_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat64_set_timeouts_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_nat64_set_timeouts_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat64_set_timeouts()
{
  static const char name[] = "nat64_set_timeouts";
  static const char name_with_crc[] = "nat64_set_timeouts_d4746b16";
  static vapi_message_desc_t __vapi_metadata_nat64_set_timeouts = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat64_set_timeouts, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_set_timeouts_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_set_timeouts_hton,
    (generic_swap_fn_t)vapi_msg_nat64_set_timeouts_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_set_timeouts = vapi_register_msg(&__vapi_metadata_nat64_set_timeouts);
  VAPI_DBG("Assigned msg id %d to nat64_set_timeouts", vapi_msg_id_nat64_set_timeouts);
}
#endif

#ifndef defined_vapi_msg_nat64_get_timeouts_reply
#define defined_vapi_msg_nat64_get_timeouts_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 udp;
  u32 tcp_established;
  u32 tcp_transitory;
  u32 icmp; 
} vapi_payload_nat64_get_timeouts_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat64_get_timeouts_reply payload;
} vapi_msg_nat64_get_timeouts_reply;

static inline void vapi_msg_nat64_get_timeouts_reply_payload_hton(vapi_payload_nat64_get_timeouts_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->udp = htobe32(payload->udp);
  payload->tcp_established = htobe32(payload->tcp_established);
  payload->tcp_transitory = htobe32(payload->tcp_transitory);
  payload->icmp = htobe32(payload->icmp);
}

static inline void vapi_msg_nat64_get_timeouts_reply_payload_ntoh(vapi_payload_nat64_get_timeouts_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->udp = be32toh(payload->udp);
  payload->tcp_established = be32toh(payload->tcp_established);
  payload->tcp_transitory = be32toh(payload->tcp_transitory);
  payload->icmp = be32toh(payload->icmp);
}

static inline void vapi_msg_nat64_get_timeouts_reply_hton(vapi_msg_nat64_get_timeouts_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_get_timeouts_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat64_get_timeouts_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_get_timeouts_reply_ntoh(vapi_msg_nat64_get_timeouts_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_get_timeouts_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat64_get_timeouts_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_get_timeouts_reply_msg_size(vapi_msg_nat64_get_timeouts_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_get_timeouts_reply_msg_size(vapi_msg_nat64_get_timeouts_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_get_timeouts_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_get_timeouts_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_get_timeouts_reply));
      return -1;
    }
  if (vapi_calc_nat64_get_timeouts_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_get_timeouts_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_get_timeouts_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat64_get_timeouts_reply()
{
  static const char name[] = "nat64_get_timeouts_reply";
  static const char name_with_crc[] = "nat64_get_timeouts_reply_3c4df4e1";
  static vapi_message_desc_t __vapi_metadata_nat64_get_timeouts_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat64_get_timeouts_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_get_timeouts_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_get_timeouts_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat64_get_timeouts_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_get_timeouts_reply = vapi_register_msg(&__vapi_metadata_nat64_get_timeouts_reply);
  VAPI_DBG("Assigned msg id %d to nat64_get_timeouts_reply", vapi_msg_id_nat64_get_timeouts_reply);
}

static inline void vapi_set_vapi_msg_nat64_get_timeouts_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat64_get_timeouts_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat64_get_timeouts_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat64_get_timeouts
#define defined_vapi_msg_nat64_get_timeouts
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_nat64_get_timeouts;

static inline void vapi_msg_nat64_get_timeouts_hton(vapi_msg_nat64_get_timeouts *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_get_timeouts'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_nat64_get_timeouts_ntoh(vapi_msg_nat64_get_timeouts *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_get_timeouts'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_nat64_get_timeouts_msg_size(vapi_msg_nat64_get_timeouts *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_get_timeouts_msg_size(vapi_msg_nat64_get_timeouts *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_get_timeouts) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_get_timeouts' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_get_timeouts));
      return -1;
    }
  if (vapi_calc_nat64_get_timeouts_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_get_timeouts' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_get_timeouts_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat64_get_timeouts* vapi_alloc_nat64_get_timeouts(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat64_get_timeouts *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat64_get_timeouts);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat64_get_timeouts*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat64_get_timeouts);

  return msg;
}

static inline vapi_error_e vapi_nat64_get_timeouts(struct vapi_ctx_s *ctx,
  vapi_msg_nat64_get_timeouts *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat64_get_timeouts_reply *reply),
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
  vapi_msg_nat64_get_timeouts_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat64_get_timeouts_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_nat64_get_timeouts_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat64_get_timeouts()
{
  static const char name[] = "nat64_get_timeouts";
  static const char name_with_crc[] = "nat64_get_timeouts_51077d14";
  static vapi_message_desc_t __vapi_metadata_nat64_get_timeouts = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_nat64_get_timeouts_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_get_timeouts_hton,
    (generic_swap_fn_t)vapi_msg_nat64_get_timeouts_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_get_timeouts = vapi_register_msg(&__vapi_metadata_nat64_get_timeouts);
  VAPI_DBG("Assigned msg id %d to nat64_get_timeouts", vapi_msg_id_nat64_get_timeouts);
}
#endif

#ifndef defined_vapi_msg_nat64_add_del_pool_addr_range_reply
#define defined_vapi_msg_nat64_add_del_pool_addr_range_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat64_add_del_pool_addr_range_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat64_add_del_pool_addr_range_reply payload;
} vapi_msg_nat64_add_del_pool_addr_range_reply;

static inline void vapi_msg_nat64_add_del_pool_addr_range_reply_payload_hton(vapi_payload_nat64_add_del_pool_addr_range_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat64_add_del_pool_addr_range_reply_payload_ntoh(vapi_payload_nat64_add_del_pool_addr_range_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat64_add_del_pool_addr_range_reply_hton(vapi_msg_nat64_add_del_pool_addr_range_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_add_del_pool_addr_range_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat64_add_del_pool_addr_range_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_add_del_pool_addr_range_reply_ntoh(vapi_msg_nat64_add_del_pool_addr_range_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_add_del_pool_addr_range_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat64_add_del_pool_addr_range_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_add_del_pool_addr_range_reply_msg_size(vapi_msg_nat64_add_del_pool_addr_range_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_add_del_pool_addr_range_reply_msg_size(vapi_msg_nat64_add_del_pool_addr_range_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_add_del_pool_addr_range_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_add_del_pool_addr_range_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_add_del_pool_addr_range_reply));
      return -1;
    }
  if (vapi_calc_nat64_add_del_pool_addr_range_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_add_del_pool_addr_range_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_add_del_pool_addr_range_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat64_add_del_pool_addr_range_reply()
{
  static const char name[] = "nat64_add_del_pool_addr_range_reply";
  static const char name_with_crc[] = "nat64_add_del_pool_addr_range_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat64_add_del_pool_addr_range_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat64_add_del_pool_addr_range_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_add_del_pool_addr_range_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_add_del_pool_addr_range_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat64_add_del_pool_addr_range_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_add_del_pool_addr_range_reply = vapi_register_msg(&__vapi_metadata_nat64_add_del_pool_addr_range_reply);
  VAPI_DBG("Assigned msg id %d to nat64_add_del_pool_addr_range_reply", vapi_msg_id_nat64_add_del_pool_addr_range_reply);
}

static inline void vapi_set_vapi_msg_nat64_add_del_pool_addr_range_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat64_add_del_pool_addr_range_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat64_add_del_pool_addr_range_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat64_add_del_pool_addr_range
#define defined_vapi_msg_nat64_add_del_pool_addr_range
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address start_addr;
  vapi_type_ip4_address end_addr;
  u32 vrf_id;
  bool is_add; 
} vapi_payload_nat64_add_del_pool_addr_range;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat64_add_del_pool_addr_range payload;
} vapi_msg_nat64_add_del_pool_addr_range;

static inline void vapi_msg_nat64_add_del_pool_addr_range_payload_hton(vapi_payload_nat64_add_del_pool_addr_range *payload)
{
  payload->vrf_id = htobe32(payload->vrf_id);
}

static inline void vapi_msg_nat64_add_del_pool_addr_range_payload_ntoh(vapi_payload_nat64_add_del_pool_addr_range *payload)
{
  payload->vrf_id = be32toh(payload->vrf_id);
}

static inline void vapi_msg_nat64_add_del_pool_addr_range_hton(vapi_msg_nat64_add_del_pool_addr_range *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_add_del_pool_addr_range'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat64_add_del_pool_addr_range_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_add_del_pool_addr_range_ntoh(vapi_msg_nat64_add_del_pool_addr_range *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_add_del_pool_addr_range'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat64_add_del_pool_addr_range_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_add_del_pool_addr_range_msg_size(vapi_msg_nat64_add_del_pool_addr_range *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_add_del_pool_addr_range_msg_size(vapi_msg_nat64_add_del_pool_addr_range *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_add_del_pool_addr_range) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_add_del_pool_addr_range' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_add_del_pool_addr_range));
      return -1;
    }
  if (vapi_calc_nat64_add_del_pool_addr_range_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_add_del_pool_addr_range' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_add_del_pool_addr_range_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat64_add_del_pool_addr_range* vapi_alloc_nat64_add_del_pool_addr_range(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat64_add_del_pool_addr_range *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat64_add_del_pool_addr_range);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat64_add_del_pool_addr_range*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat64_add_del_pool_addr_range);

  return msg;
}

static inline vapi_error_e vapi_nat64_add_del_pool_addr_range(struct vapi_ctx_s *ctx,
  vapi_msg_nat64_add_del_pool_addr_range *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat64_add_del_pool_addr_range_reply *reply),
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
  vapi_msg_nat64_add_del_pool_addr_range_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat64_add_del_pool_addr_range_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_nat64_add_del_pool_addr_range_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat64_add_del_pool_addr_range()
{
  static const char name[] = "nat64_add_del_pool_addr_range";
  static const char name_with_crc[] = "nat64_add_del_pool_addr_range_a3b944e3";
  static vapi_message_desc_t __vapi_metadata_nat64_add_del_pool_addr_range = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat64_add_del_pool_addr_range, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_add_del_pool_addr_range_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_add_del_pool_addr_range_hton,
    (generic_swap_fn_t)vapi_msg_nat64_add_del_pool_addr_range_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_add_del_pool_addr_range = vapi_register_msg(&__vapi_metadata_nat64_add_del_pool_addr_range);
  VAPI_DBG("Assigned msg id %d to nat64_add_del_pool_addr_range", vapi_msg_id_nat64_add_del_pool_addr_range);
}
#endif

#ifndef defined_vapi_msg_nat64_pool_addr_details
#define defined_vapi_msg_nat64_pool_addr_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address address;
  u32 vrf_id; 
} vapi_payload_nat64_pool_addr_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat64_pool_addr_details payload;
} vapi_msg_nat64_pool_addr_details;

static inline void vapi_msg_nat64_pool_addr_details_payload_hton(vapi_payload_nat64_pool_addr_details *payload)
{
  payload->vrf_id = htobe32(payload->vrf_id);
}

static inline void vapi_msg_nat64_pool_addr_details_payload_ntoh(vapi_payload_nat64_pool_addr_details *payload)
{
  payload->vrf_id = be32toh(payload->vrf_id);
}

static inline void vapi_msg_nat64_pool_addr_details_hton(vapi_msg_nat64_pool_addr_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_pool_addr_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat64_pool_addr_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_pool_addr_details_ntoh(vapi_msg_nat64_pool_addr_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_pool_addr_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat64_pool_addr_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_pool_addr_details_msg_size(vapi_msg_nat64_pool_addr_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_pool_addr_details_msg_size(vapi_msg_nat64_pool_addr_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_pool_addr_details) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_pool_addr_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_pool_addr_details));
      return -1;
    }
  if (vapi_calc_nat64_pool_addr_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_pool_addr_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_pool_addr_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat64_pool_addr_details()
{
  static const char name[] = "nat64_pool_addr_details";
  static const char name_with_crc[] = "nat64_pool_addr_details_9bb99cdb";
  static vapi_message_desc_t __vapi_metadata_nat64_pool_addr_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat64_pool_addr_details, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_pool_addr_details_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_pool_addr_details_hton,
    (generic_swap_fn_t)vapi_msg_nat64_pool_addr_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_pool_addr_details = vapi_register_msg(&__vapi_metadata_nat64_pool_addr_details);
  VAPI_DBG("Assigned msg id %d to nat64_pool_addr_details", vapi_msg_id_nat64_pool_addr_details);
}

static inline void vapi_set_vapi_msg_nat64_pool_addr_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat64_pool_addr_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat64_pool_addr_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat64_pool_addr_dump
#define defined_vapi_msg_nat64_pool_addr_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_nat64_pool_addr_dump;

static inline void vapi_msg_nat64_pool_addr_dump_hton(vapi_msg_nat64_pool_addr_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_pool_addr_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_nat64_pool_addr_dump_ntoh(vapi_msg_nat64_pool_addr_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_pool_addr_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_nat64_pool_addr_dump_msg_size(vapi_msg_nat64_pool_addr_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_pool_addr_dump_msg_size(vapi_msg_nat64_pool_addr_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_pool_addr_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_pool_addr_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_pool_addr_dump));
      return -1;
    }
  if (vapi_calc_nat64_pool_addr_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_pool_addr_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_pool_addr_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat64_pool_addr_dump* vapi_alloc_nat64_pool_addr_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat64_pool_addr_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat64_pool_addr_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat64_pool_addr_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat64_pool_addr_dump);

  return msg;
}

static inline vapi_error_e vapi_nat64_pool_addr_dump(struct vapi_ctx_s *ctx,
  vapi_msg_nat64_pool_addr_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat64_pool_addr_details *reply),
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
  vapi_msg_nat64_pool_addr_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat64_pool_addr_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_nat64_pool_addr_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat64_pool_addr_dump()
{
  static const char name[] = "nat64_pool_addr_dump";
  static const char name_with_crc[] = "nat64_pool_addr_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_nat64_pool_addr_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_nat64_pool_addr_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_pool_addr_dump_hton,
    (generic_swap_fn_t)vapi_msg_nat64_pool_addr_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_pool_addr_dump = vapi_register_msg(&__vapi_metadata_nat64_pool_addr_dump);
  VAPI_DBG("Assigned msg id %d to nat64_pool_addr_dump", vapi_msg_id_nat64_pool_addr_dump);
}
#endif

#ifndef defined_vapi_msg_nat64_add_del_interface_reply
#define defined_vapi_msg_nat64_add_del_interface_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat64_add_del_interface_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat64_add_del_interface_reply payload;
} vapi_msg_nat64_add_del_interface_reply;

static inline void vapi_msg_nat64_add_del_interface_reply_payload_hton(vapi_payload_nat64_add_del_interface_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat64_add_del_interface_reply_payload_ntoh(vapi_payload_nat64_add_del_interface_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat64_add_del_interface_reply_hton(vapi_msg_nat64_add_del_interface_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_add_del_interface_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat64_add_del_interface_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_add_del_interface_reply_ntoh(vapi_msg_nat64_add_del_interface_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_add_del_interface_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat64_add_del_interface_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_add_del_interface_reply_msg_size(vapi_msg_nat64_add_del_interface_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_add_del_interface_reply_msg_size(vapi_msg_nat64_add_del_interface_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_add_del_interface_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_add_del_interface_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_add_del_interface_reply));
      return -1;
    }
  if (vapi_calc_nat64_add_del_interface_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_add_del_interface_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_add_del_interface_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat64_add_del_interface_reply()
{
  static const char name[] = "nat64_add_del_interface_reply";
  static const char name_with_crc[] = "nat64_add_del_interface_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat64_add_del_interface_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat64_add_del_interface_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_add_del_interface_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_add_del_interface_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat64_add_del_interface_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_add_del_interface_reply = vapi_register_msg(&__vapi_metadata_nat64_add_del_interface_reply);
  VAPI_DBG("Assigned msg id %d to nat64_add_del_interface_reply", vapi_msg_id_nat64_add_del_interface_reply);
}

static inline void vapi_set_vapi_msg_nat64_add_del_interface_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat64_add_del_interface_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat64_add_del_interface_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat64_add_del_interface
#define defined_vapi_msg_nat64_add_del_interface
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_enum_nat_config_flags flags;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_nat64_add_del_interface;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat64_add_del_interface payload;
} vapi_msg_nat64_add_del_interface;

static inline void vapi_msg_nat64_add_del_interface_payload_hton(vapi_payload_nat64_add_del_interface *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_nat64_add_del_interface_payload_ntoh(vapi_payload_nat64_add_del_interface *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_nat64_add_del_interface_hton(vapi_msg_nat64_add_del_interface *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_add_del_interface'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat64_add_del_interface_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_add_del_interface_ntoh(vapi_msg_nat64_add_del_interface *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_add_del_interface'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat64_add_del_interface_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_add_del_interface_msg_size(vapi_msg_nat64_add_del_interface *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_add_del_interface_msg_size(vapi_msg_nat64_add_del_interface *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_add_del_interface) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_add_del_interface' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_add_del_interface));
      return -1;
    }
  if (vapi_calc_nat64_add_del_interface_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_add_del_interface' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_add_del_interface_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat64_add_del_interface* vapi_alloc_nat64_add_del_interface(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat64_add_del_interface *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat64_add_del_interface);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat64_add_del_interface*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat64_add_del_interface);

  return msg;
}

static inline vapi_error_e vapi_nat64_add_del_interface(struct vapi_ctx_s *ctx,
  vapi_msg_nat64_add_del_interface *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat64_add_del_interface_reply *reply),
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
  vapi_msg_nat64_add_del_interface_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat64_add_del_interface_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_nat64_add_del_interface_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat64_add_del_interface()
{
  static const char name[] = "nat64_add_del_interface";
  static const char name_with_crc[] = "nat64_add_del_interface_f3699b83";
  static vapi_message_desc_t __vapi_metadata_nat64_add_del_interface = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat64_add_del_interface, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_add_del_interface_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_add_del_interface_hton,
    (generic_swap_fn_t)vapi_msg_nat64_add_del_interface_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_add_del_interface = vapi_register_msg(&__vapi_metadata_nat64_add_del_interface);
  VAPI_DBG("Assigned msg id %d to nat64_add_del_interface", vapi_msg_id_nat64_add_del_interface);
}
#endif

#ifndef defined_vapi_msg_nat64_interface_details
#define defined_vapi_msg_nat64_interface_details
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_nat_config_flags flags;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_nat64_interface_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat64_interface_details payload;
} vapi_msg_nat64_interface_details;

static inline void vapi_msg_nat64_interface_details_payload_hton(vapi_payload_nat64_interface_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_nat64_interface_details_payload_ntoh(vapi_payload_nat64_interface_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_nat64_interface_details_hton(vapi_msg_nat64_interface_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_interface_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat64_interface_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_interface_details_ntoh(vapi_msg_nat64_interface_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_interface_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat64_interface_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_interface_details_msg_size(vapi_msg_nat64_interface_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_interface_details_msg_size(vapi_msg_nat64_interface_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_interface_details) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_interface_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_interface_details));
      return -1;
    }
  if (vapi_calc_nat64_interface_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_interface_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_interface_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat64_interface_details()
{
  static const char name[] = "nat64_interface_details";
  static const char name_with_crc[] = "nat64_interface_details_5d286289";
  static vapi_message_desc_t __vapi_metadata_nat64_interface_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat64_interface_details, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_interface_details_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_interface_details_hton,
    (generic_swap_fn_t)vapi_msg_nat64_interface_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_interface_details = vapi_register_msg(&__vapi_metadata_nat64_interface_details);
  VAPI_DBG("Assigned msg id %d to nat64_interface_details", vapi_msg_id_nat64_interface_details);
}

static inline void vapi_set_vapi_msg_nat64_interface_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat64_interface_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat64_interface_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat64_interface_dump
#define defined_vapi_msg_nat64_interface_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_nat64_interface_dump;

static inline void vapi_msg_nat64_interface_dump_hton(vapi_msg_nat64_interface_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_interface_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_nat64_interface_dump_ntoh(vapi_msg_nat64_interface_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_interface_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_nat64_interface_dump_msg_size(vapi_msg_nat64_interface_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_interface_dump_msg_size(vapi_msg_nat64_interface_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_interface_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_interface_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_interface_dump));
      return -1;
    }
  if (vapi_calc_nat64_interface_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_interface_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_interface_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat64_interface_dump* vapi_alloc_nat64_interface_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat64_interface_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat64_interface_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat64_interface_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat64_interface_dump);

  return msg;
}

static inline vapi_error_e vapi_nat64_interface_dump(struct vapi_ctx_s *ctx,
  vapi_msg_nat64_interface_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat64_interface_details *reply),
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
  vapi_msg_nat64_interface_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat64_interface_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_nat64_interface_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat64_interface_dump()
{
  static const char name[] = "nat64_interface_dump";
  static const char name_with_crc[] = "nat64_interface_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_nat64_interface_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_nat64_interface_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_interface_dump_hton,
    (generic_swap_fn_t)vapi_msg_nat64_interface_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_interface_dump = vapi_register_msg(&__vapi_metadata_nat64_interface_dump);
  VAPI_DBG("Assigned msg id %d to nat64_interface_dump", vapi_msg_id_nat64_interface_dump);
}
#endif

#ifndef defined_vapi_msg_nat64_add_del_static_bib_reply
#define defined_vapi_msg_nat64_add_del_static_bib_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat64_add_del_static_bib_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat64_add_del_static_bib_reply payload;
} vapi_msg_nat64_add_del_static_bib_reply;

static inline void vapi_msg_nat64_add_del_static_bib_reply_payload_hton(vapi_payload_nat64_add_del_static_bib_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat64_add_del_static_bib_reply_payload_ntoh(vapi_payload_nat64_add_del_static_bib_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat64_add_del_static_bib_reply_hton(vapi_msg_nat64_add_del_static_bib_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_add_del_static_bib_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat64_add_del_static_bib_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_add_del_static_bib_reply_ntoh(vapi_msg_nat64_add_del_static_bib_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_add_del_static_bib_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat64_add_del_static_bib_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_add_del_static_bib_reply_msg_size(vapi_msg_nat64_add_del_static_bib_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_add_del_static_bib_reply_msg_size(vapi_msg_nat64_add_del_static_bib_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_add_del_static_bib_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_add_del_static_bib_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_add_del_static_bib_reply));
      return -1;
    }
  if (vapi_calc_nat64_add_del_static_bib_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_add_del_static_bib_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_add_del_static_bib_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat64_add_del_static_bib_reply()
{
  static const char name[] = "nat64_add_del_static_bib_reply";
  static const char name_with_crc[] = "nat64_add_del_static_bib_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat64_add_del_static_bib_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat64_add_del_static_bib_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_add_del_static_bib_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_add_del_static_bib_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat64_add_del_static_bib_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_add_del_static_bib_reply = vapi_register_msg(&__vapi_metadata_nat64_add_del_static_bib_reply);
  VAPI_DBG("Assigned msg id %d to nat64_add_del_static_bib_reply", vapi_msg_id_nat64_add_del_static_bib_reply);
}

static inline void vapi_set_vapi_msg_nat64_add_del_static_bib_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat64_add_del_static_bib_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat64_add_del_static_bib_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat64_add_del_static_bib
#define defined_vapi_msg_nat64_add_del_static_bib
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip6_address i_addr;
  vapi_type_ip4_address o_addr;
  u16 i_port;
  u16 o_port;
  u32 vrf_id;
  u8 proto;
  bool is_add; 
} vapi_payload_nat64_add_del_static_bib;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat64_add_del_static_bib payload;
} vapi_msg_nat64_add_del_static_bib;

static inline void vapi_msg_nat64_add_del_static_bib_payload_hton(vapi_payload_nat64_add_del_static_bib *payload)
{
  payload->i_port = htobe16(payload->i_port);
  payload->o_port = htobe16(payload->o_port);
  payload->vrf_id = htobe32(payload->vrf_id);
}

static inline void vapi_msg_nat64_add_del_static_bib_payload_ntoh(vapi_payload_nat64_add_del_static_bib *payload)
{
  payload->i_port = be16toh(payload->i_port);
  payload->o_port = be16toh(payload->o_port);
  payload->vrf_id = be32toh(payload->vrf_id);
}

static inline void vapi_msg_nat64_add_del_static_bib_hton(vapi_msg_nat64_add_del_static_bib *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_add_del_static_bib'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat64_add_del_static_bib_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_add_del_static_bib_ntoh(vapi_msg_nat64_add_del_static_bib *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_add_del_static_bib'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat64_add_del_static_bib_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_add_del_static_bib_msg_size(vapi_msg_nat64_add_del_static_bib *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_add_del_static_bib_msg_size(vapi_msg_nat64_add_del_static_bib *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_add_del_static_bib) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_add_del_static_bib' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_add_del_static_bib));
      return -1;
    }
  if (vapi_calc_nat64_add_del_static_bib_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_add_del_static_bib' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_add_del_static_bib_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat64_add_del_static_bib* vapi_alloc_nat64_add_del_static_bib(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat64_add_del_static_bib *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat64_add_del_static_bib);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat64_add_del_static_bib*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat64_add_del_static_bib);

  return msg;
}

static inline vapi_error_e vapi_nat64_add_del_static_bib(struct vapi_ctx_s *ctx,
  vapi_msg_nat64_add_del_static_bib *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat64_add_del_static_bib_reply *reply),
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
  vapi_msg_nat64_add_del_static_bib_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat64_add_del_static_bib_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_nat64_add_del_static_bib_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat64_add_del_static_bib()
{
  static const char name[] = "nat64_add_del_static_bib";
  static const char name_with_crc[] = "nat64_add_del_static_bib_1c404de5";
  static vapi_message_desc_t __vapi_metadata_nat64_add_del_static_bib = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat64_add_del_static_bib, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_add_del_static_bib_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_add_del_static_bib_hton,
    (generic_swap_fn_t)vapi_msg_nat64_add_del_static_bib_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_add_del_static_bib = vapi_register_msg(&__vapi_metadata_nat64_add_del_static_bib);
  VAPI_DBG("Assigned msg id %d to nat64_add_del_static_bib", vapi_msg_id_nat64_add_del_static_bib);
}
#endif

#ifndef defined_vapi_msg_nat64_bib_details
#define defined_vapi_msg_nat64_bib_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip6_address i_addr;
  vapi_type_ip4_address o_addr;
  u16 i_port;
  u16 o_port;
  u32 vrf_id;
  u8 proto;
  vapi_enum_nat_config_flags flags;
  u32 ses_num; 
} vapi_payload_nat64_bib_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat64_bib_details payload;
} vapi_msg_nat64_bib_details;

static inline void vapi_msg_nat64_bib_details_payload_hton(vapi_payload_nat64_bib_details *payload)
{
  payload->i_port = htobe16(payload->i_port);
  payload->o_port = htobe16(payload->o_port);
  payload->vrf_id = htobe32(payload->vrf_id);
  payload->ses_num = htobe32(payload->ses_num);
}

static inline void vapi_msg_nat64_bib_details_payload_ntoh(vapi_payload_nat64_bib_details *payload)
{
  payload->i_port = be16toh(payload->i_port);
  payload->o_port = be16toh(payload->o_port);
  payload->vrf_id = be32toh(payload->vrf_id);
  payload->ses_num = be32toh(payload->ses_num);
}

static inline void vapi_msg_nat64_bib_details_hton(vapi_msg_nat64_bib_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_bib_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat64_bib_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_bib_details_ntoh(vapi_msg_nat64_bib_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_bib_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat64_bib_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_bib_details_msg_size(vapi_msg_nat64_bib_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_bib_details_msg_size(vapi_msg_nat64_bib_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_bib_details) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_bib_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_bib_details));
      return -1;
    }
  if (vapi_calc_nat64_bib_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_bib_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_bib_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat64_bib_details()
{
  static const char name[] = "nat64_bib_details";
  static const char name_with_crc[] = "nat64_bib_details_43bc3ddf";
  static vapi_message_desc_t __vapi_metadata_nat64_bib_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat64_bib_details, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_bib_details_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_bib_details_hton,
    (generic_swap_fn_t)vapi_msg_nat64_bib_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_bib_details = vapi_register_msg(&__vapi_metadata_nat64_bib_details);
  VAPI_DBG("Assigned msg id %d to nat64_bib_details", vapi_msg_id_nat64_bib_details);
}

static inline void vapi_set_vapi_msg_nat64_bib_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat64_bib_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat64_bib_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat64_bib_dump
#define defined_vapi_msg_nat64_bib_dump
typedef struct __attribute__ ((__packed__)) {
  u8 proto; 
} vapi_payload_nat64_bib_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat64_bib_dump payload;
} vapi_msg_nat64_bib_dump;

static inline void vapi_msg_nat64_bib_dump_payload_hton(vapi_payload_nat64_bib_dump *payload)
{

}

static inline void vapi_msg_nat64_bib_dump_payload_ntoh(vapi_payload_nat64_bib_dump *payload)
{

}

static inline void vapi_msg_nat64_bib_dump_hton(vapi_msg_nat64_bib_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_bib_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat64_bib_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_bib_dump_ntoh(vapi_msg_nat64_bib_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_bib_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat64_bib_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_bib_dump_msg_size(vapi_msg_nat64_bib_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_bib_dump_msg_size(vapi_msg_nat64_bib_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_bib_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_bib_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_bib_dump));
      return -1;
    }
  if (vapi_calc_nat64_bib_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_bib_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_bib_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat64_bib_dump* vapi_alloc_nat64_bib_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat64_bib_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat64_bib_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat64_bib_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat64_bib_dump);

  return msg;
}

static inline vapi_error_e vapi_nat64_bib_dump(struct vapi_ctx_s *ctx,
  vapi_msg_nat64_bib_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat64_bib_details *reply),
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
  vapi_msg_nat64_bib_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat64_bib_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_nat64_bib_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat64_bib_dump()
{
  static const char name[] = "nat64_bib_dump";
  static const char name_with_crc[] = "nat64_bib_dump_cfcb6b75";
  static vapi_message_desc_t __vapi_metadata_nat64_bib_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat64_bib_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_bib_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_bib_dump_hton,
    (generic_swap_fn_t)vapi_msg_nat64_bib_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_bib_dump = vapi_register_msg(&__vapi_metadata_nat64_bib_dump);
  VAPI_DBG("Assigned msg id %d to nat64_bib_dump", vapi_msg_id_nat64_bib_dump);
}
#endif

#ifndef defined_vapi_msg_nat64_st_details
#define defined_vapi_msg_nat64_st_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip6_address il_addr;
  vapi_type_ip4_address ol_addr;
  u16 il_port;
  u16 ol_port;
  vapi_type_ip6_address ir_addr;
  vapi_type_ip4_address or_addr;
  u16 r_port;
  u32 vrf_id;
  u8 proto; 
} vapi_payload_nat64_st_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat64_st_details payload;
} vapi_msg_nat64_st_details;

static inline void vapi_msg_nat64_st_details_payload_hton(vapi_payload_nat64_st_details *payload)
{
  payload->il_port = htobe16(payload->il_port);
  payload->ol_port = htobe16(payload->ol_port);
  payload->r_port = htobe16(payload->r_port);
  payload->vrf_id = htobe32(payload->vrf_id);
}

static inline void vapi_msg_nat64_st_details_payload_ntoh(vapi_payload_nat64_st_details *payload)
{
  payload->il_port = be16toh(payload->il_port);
  payload->ol_port = be16toh(payload->ol_port);
  payload->r_port = be16toh(payload->r_port);
  payload->vrf_id = be32toh(payload->vrf_id);
}

static inline void vapi_msg_nat64_st_details_hton(vapi_msg_nat64_st_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_st_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat64_st_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_st_details_ntoh(vapi_msg_nat64_st_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_st_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat64_st_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_st_details_msg_size(vapi_msg_nat64_st_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_st_details_msg_size(vapi_msg_nat64_st_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_st_details) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_st_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_st_details));
      return -1;
    }
  if (vapi_calc_nat64_st_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_st_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_st_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat64_st_details()
{
  static const char name[] = "nat64_st_details";
  static const char name_with_crc[] = "nat64_st_details_dd3361ed";
  static vapi_message_desc_t __vapi_metadata_nat64_st_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat64_st_details, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_st_details_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_st_details_hton,
    (generic_swap_fn_t)vapi_msg_nat64_st_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_st_details = vapi_register_msg(&__vapi_metadata_nat64_st_details);
  VAPI_DBG("Assigned msg id %d to nat64_st_details", vapi_msg_id_nat64_st_details);
}

static inline void vapi_set_vapi_msg_nat64_st_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat64_st_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat64_st_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat64_st_dump
#define defined_vapi_msg_nat64_st_dump
typedef struct __attribute__ ((__packed__)) {
  u8 proto; 
} vapi_payload_nat64_st_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat64_st_dump payload;
} vapi_msg_nat64_st_dump;

static inline void vapi_msg_nat64_st_dump_payload_hton(vapi_payload_nat64_st_dump *payload)
{

}

static inline void vapi_msg_nat64_st_dump_payload_ntoh(vapi_payload_nat64_st_dump *payload)
{

}

static inline void vapi_msg_nat64_st_dump_hton(vapi_msg_nat64_st_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_st_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat64_st_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_st_dump_ntoh(vapi_msg_nat64_st_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_st_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat64_st_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_st_dump_msg_size(vapi_msg_nat64_st_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_st_dump_msg_size(vapi_msg_nat64_st_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_st_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_st_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_st_dump));
      return -1;
    }
  if (vapi_calc_nat64_st_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_st_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_st_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat64_st_dump* vapi_alloc_nat64_st_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat64_st_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat64_st_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat64_st_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat64_st_dump);

  return msg;
}

static inline vapi_error_e vapi_nat64_st_dump(struct vapi_ctx_s *ctx,
  vapi_msg_nat64_st_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat64_st_details *reply),
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
  vapi_msg_nat64_st_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat64_st_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_nat64_st_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat64_st_dump()
{
  static const char name[] = "nat64_st_dump";
  static const char name_with_crc[] = "nat64_st_dump_cfcb6b75";
  static vapi_message_desc_t __vapi_metadata_nat64_st_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat64_st_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_st_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_st_dump_hton,
    (generic_swap_fn_t)vapi_msg_nat64_st_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_st_dump = vapi_register_msg(&__vapi_metadata_nat64_st_dump);
  VAPI_DBG("Assigned msg id %d to nat64_st_dump", vapi_msg_id_nat64_st_dump);
}
#endif

#ifndef defined_vapi_msg_nat64_add_del_prefix_reply
#define defined_vapi_msg_nat64_add_del_prefix_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat64_add_del_prefix_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat64_add_del_prefix_reply payload;
} vapi_msg_nat64_add_del_prefix_reply;

static inline void vapi_msg_nat64_add_del_prefix_reply_payload_hton(vapi_payload_nat64_add_del_prefix_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat64_add_del_prefix_reply_payload_ntoh(vapi_payload_nat64_add_del_prefix_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat64_add_del_prefix_reply_hton(vapi_msg_nat64_add_del_prefix_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_add_del_prefix_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat64_add_del_prefix_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_add_del_prefix_reply_ntoh(vapi_msg_nat64_add_del_prefix_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_add_del_prefix_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat64_add_del_prefix_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_add_del_prefix_reply_msg_size(vapi_msg_nat64_add_del_prefix_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_add_del_prefix_reply_msg_size(vapi_msg_nat64_add_del_prefix_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_add_del_prefix_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_add_del_prefix_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_add_del_prefix_reply));
      return -1;
    }
  if (vapi_calc_nat64_add_del_prefix_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_add_del_prefix_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_add_del_prefix_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat64_add_del_prefix_reply()
{
  static const char name[] = "nat64_add_del_prefix_reply";
  static const char name_with_crc[] = "nat64_add_del_prefix_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat64_add_del_prefix_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat64_add_del_prefix_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_add_del_prefix_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_add_del_prefix_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat64_add_del_prefix_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_add_del_prefix_reply = vapi_register_msg(&__vapi_metadata_nat64_add_del_prefix_reply);
  VAPI_DBG("Assigned msg id %d to nat64_add_del_prefix_reply", vapi_msg_id_nat64_add_del_prefix_reply);
}

static inline void vapi_set_vapi_msg_nat64_add_del_prefix_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat64_add_del_prefix_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat64_add_del_prefix_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat64_add_del_prefix
#define defined_vapi_msg_nat64_add_del_prefix
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip6_prefix prefix;
  u32 vrf_id;
  bool is_add; 
} vapi_payload_nat64_add_del_prefix;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat64_add_del_prefix payload;
} vapi_msg_nat64_add_del_prefix;

static inline void vapi_msg_nat64_add_del_prefix_payload_hton(vapi_payload_nat64_add_del_prefix *payload)
{
  payload->vrf_id = htobe32(payload->vrf_id);
}

static inline void vapi_msg_nat64_add_del_prefix_payload_ntoh(vapi_payload_nat64_add_del_prefix *payload)
{
  payload->vrf_id = be32toh(payload->vrf_id);
}

static inline void vapi_msg_nat64_add_del_prefix_hton(vapi_msg_nat64_add_del_prefix *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_add_del_prefix'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat64_add_del_prefix_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_add_del_prefix_ntoh(vapi_msg_nat64_add_del_prefix *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_add_del_prefix'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat64_add_del_prefix_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_add_del_prefix_msg_size(vapi_msg_nat64_add_del_prefix *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_add_del_prefix_msg_size(vapi_msg_nat64_add_del_prefix *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_add_del_prefix) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_add_del_prefix' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_add_del_prefix));
      return -1;
    }
  if (vapi_calc_nat64_add_del_prefix_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_add_del_prefix' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_add_del_prefix_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat64_add_del_prefix* vapi_alloc_nat64_add_del_prefix(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat64_add_del_prefix *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat64_add_del_prefix);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat64_add_del_prefix*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat64_add_del_prefix);

  return msg;
}

static inline vapi_error_e vapi_nat64_add_del_prefix(struct vapi_ctx_s *ctx,
  vapi_msg_nat64_add_del_prefix *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat64_add_del_prefix_reply *reply),
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
  vapi_msg_nat64_add_del_prefix_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat64_add_del_prefix_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_nat64_add_del_prefix_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat64_add_del_prefix()
{
  static const char name[] = "nat64_add_del_prefix";
  static const char name_with_crc[] = "nat64_add_del_prefix_727b2f4c";
  static vapi_message_desc_t __vapi_metadata_nat64_add_del_prefix = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat64_add_del_prefix, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_add_del_prefix_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_add_del_prefix_hton,
    (generic_swap_fn_t)vapi_msg_nat64_add_del_prefix_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_add_del_prefix = vapi_register_msg(&__vapi_metadata_nat64_add_del_prefix);
  VAPI_DBG("Assigned msg id %d to nat64_add_del_prefix", vapi_msg_id_nat64_add_del_prefix);
}
#endif

#ifndef defined_vapi_msg_nat64_prefix_details
#define defined_vapi_msg_nat64_prefix_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip6_prefix prefix;
  u32 vrf_id; 
} vapi_payload_nat64_prefix_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat64_prefix_details payload;
} vapi_msg_nat64_prefix_details;

static inline void vapi_msg_nat64_prefix_details_payload_hton(vapi_payload_nat64_prefix_details *payload)
{
  payload->vrf_id = htobe32(payload->vrf_id);
}

static inline void vapi_msg_nat64_prefix_details_payload_ntoh(vapi_payload_nat64_prefix_details *payload)
{
  payload->vrf_id = be32toh(payload->vrf_id);
}

static inline void vapi_msg_nat64_prefix_details_hton(vapi_msg_nat64_prefix_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_prefix_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat64_prefix_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_prefix_details_ntoh(vapi_msg_nat64_prefix_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_prefix_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat64_prefix_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_prefix_details_msg_size(vapi_msg_nat64_prefix_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_prefix_details_msg_size(vapi_msg_nat64_prefix_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_prefix_details) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_prefix_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_prefix_details));
      return -1;
    }
  if (vapi_calc_nat64_prefix_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_prefix_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_prefix_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat64_prefix_details()
{
  static const char name[] = "nat64_prefix_details";
  static const char name_with_crc[] = "nat64_prefix_details_20568de3";
  static vapi_message_desc_t __vapi_metadata_nat64_prefix_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat64_prefix_details, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_prefix_details_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_prefix_details_hton,
    (generic_swap_fn_t)vapi_msg_nat64_prefix_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_prefix_details = vapi_register_msg(&__vapi_metadata_nat64_prefix_details);
  VAPI_DBG("Assigned msg id %d to nat64_prefix_details", vapi_msg_id_nat64_prefix_details);
}

static inline void vapi_set_vapi_msg_nat64_prefix_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat64_prefix_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat64_prefix_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat64_prefix_dump
#define defined_vapi_msg_nat64_prefix_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_nat64_prefix_dump;

static inline void vapi_msg_nat64_prefix_dump_hton(vapi_msg_nat64_prefix_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_prefix_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_nat64_prefix_dump_ntoh(vapi_msg_nat64_prefix_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_prefix_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_nat64_prefix_dump_msg_size(vapi_msg_nat64_prefix_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_prefix_dump_msg_size(vapi_msg_nat64_prefix_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_prefix_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_prefix_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_prefix_dump));
      return -1;
    }
  if (vapi_calc_nat64_prefix_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_prefix_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_prefix_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat64_prefix_dump* vapi_alloc_nat64_prefix_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat64_prefix_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat64_prefix_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat64_prefix_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat64_prefix_dump);

  return msg;
}

static inline vapi_error_e vapi_nat64_prefix_dump(struct vapi_ctx_s *ctx,
  vapi_msg_nat64_prefix_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat64_prefix_details *reply),
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
  vapi_msg_nat64_prefix_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat64_prefix_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_nat64_prefix_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat64_prefix_dump()
{
  static const char name[] = "nat64_prefix_dump";
  static const char name_with_crc[] = "nat64_prefix_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_nat64_prefix_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_nat64_prefix_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_prefix_dump_hton,
    (generic_swap_fn_t)vapi_msg_nat64_prefix_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_prefix_dump = vapi_register_msg(&__vapi_metadata_nat64_prefix_dump);
  VAPI_DBG("Assigned msg id %d to nat64_prefix_dump", vapi_msg_id_nat64_prefix_dump);
}
#endif

#ifndef defined_vapi_msg_nat64_add_del_interface_addr_reply
#define defined_vapi_msg_nat64_add_del_interface_addr_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat64_add_del_interface_addr_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat64_add_del_interface_addr_reply payload;
} vapi_msg_nat64_add_del_interface_addr_reply;

static inline void vapi_msg_nat64_add_del_interface_addr_reply_payload_hton(vapi_payload_nat64_add_del_interface_addr_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat64_add_del_interface_addr_reply_payload_ntoh(vapi_payload_nat64_add_del_interface_addr_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat64_add_del_interface_addr_reply_hton(vapi_msg_nat64_add_del_interface_addr_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_add_del_interface_addr_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat64_add_del_interface_addr_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_add_del_interface_addr_reply_ntoh(vapi_msg_nat64_add_del_interface_addr_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_add_del_interface_addr_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat64_add_del_interface_addr_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_add_del_interface_addr_reply_msg_size(vapi_msg_nat64_add_del_interface_addr_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_add_del_interface_addr_reply_msg_size(vapi_msg_nat64_add_del_interface_addr_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_add_del_interface_addr_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_add_del_interface_addr_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_add_del_interface_addr_reply));
      return -1;
    }
  if (vapi_calc_nat64_add_del_interface_addr_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_add_del_interface_addr_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_add_del_interface_addr_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat64_add_del_interface_addr_reply()
{
  static const char name[] = "nat64_add_del_interface_addr_reply";
  static const char name_with_crc[] = "nat64_add_del_interface_addr_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat64_add_del_interface_addr_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat64_add_del_interface_addr_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_add_del_interface_addr_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_add_del_interface_addr_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat64_add_del_interface_addr_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_add_del_interface_addr_reply = vapi_register_msg(&__vapi_metadata_nat64_add_del_interface_addr_reply);
  VAPI_DBG("Assigned msg id %d to nat64_add_del_interface_addr_reply", vapi_msg_id_nat64_add_del_interface_addr_reply);
}

static inline void vapi_set_vapi_msg_nat64_add_del_interface_addr_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat64_add_del_interface_addr_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat64_add_del_interface_addr_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat64_add_del_interface_addr
#define defined_vapi_msg_nat64_add_del_interface_addr
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_nat64_add_del_interface_addr;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat64_add_del_interface_addr payload;
} vapi_msg_nat64_add_del_interface_addr;

static inline void vapi_msg_nat64_add_del_interface_addr_payload_hton(vapi_payload_nat64_add_del_interface_addr *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_nat64_add_del_interface_addr_payload_ntoh(vapi_payload_nat64_add_del_interface_addr *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_nat64_add_del_interface_addr_hton(vapi_msg_nat64_add_del_interface_addr *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_add_del_interface_addr'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat64_add_del_interface_addr_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat64_add_del_interface_addr_ntoh(vapi_msg_nat64_add_del_interface_addr *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat64_add_del_interface_addr'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat64_add_del_interface_addr_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat64_add_del_interface_addr_msg_size(vapi_msg_nat64_add_del_interface_addr *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat64_add_del_interface_addr_msg_size(vapi_msg_nat64_add_del_interface_addr *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat64_add_del_interface_addr) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_add_del_interface_addr' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat64_add_del_interface_addr));
      return -1;
    }
  if (vapi_calc_nat64_add_del_interface_addr_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat64_add_del_interface_addr' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat64_add_del_interface_addr_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat64_add_del_interface_addr* vapi_alloc_nat64_add_del_interface_addr(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat64_add_del_interface_addr *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat64_add_del_interface_addr);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat64_add_del_interface_addr*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat64_add_del_interface_addr);

  return msg;
}

static inline vapi_error_e vapi_nat64_add_del_interface_addr(struct vapi_ctx_s *ctx,
  vapi_msg_nat64_add_del_interface_addr *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat64_add_del_interface_addr_reply *reply),
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
  vapi_msg_nat64_add_del_interface_addr_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat64_add_del_interface_addr_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_nat64_add_del_interface_addr_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat64_add_del_interface_addr()
{
  static const char name[] = "nat64_add_del_interface_addr";
  static const char name_with_crc[] = "nat64_add_del_interface_addr_47d6e753";
  static vapi_message_desc_t __vapi_metadata_nat64_add_del_interface_addr = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat64_add_del_interface_addr, payload),
    (verify_msg_size_fn_t)vapi_verify_nat64_add_del_interface_addr_msg_size,
    (generic_swap_fn_t)vapi_msg_nat64_add_del_interface_addr_hton,
    (generic_swap_fn_t)vapi_msg_nat64_add_del_interface_addr_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat64_add_del_interface_addr = vapi_register_msg(&__vapi_metadata_nat64_add_del_interface_addr);
  VAPI_DBG("Assigned msg id %d to nat64_add_del_interface_addr", vapi_msg_id_nat64_add_del_interface_addr);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
