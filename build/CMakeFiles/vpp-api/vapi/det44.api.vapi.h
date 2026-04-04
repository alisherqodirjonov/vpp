#ifndef __included_det44_api_json
#define __included_det44_api_json

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

extern vapi_msg_id_t vapi_msg_id_det44_plugin_enable_disable;
extern vapi_msg_id_t vapi_msg_id_det44_plugin_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_det44_interface_add_del_feature;
extern vapi_msg_id_t vapi_msg_id_det44_interface_add_del_feature_reply;
extern vapi_msg_id_t vapi_msg_id_det44_interface_dump;
extern vapi_msg_id_t vapi_msg_id_det44_interface_details;
extern vapi_msg_id_t vapi_msg_id_det44_add_del_map;
extern vapi_msg_id_t vapi_msg_id_det44_add_del_map_reply;
extern vapi_msg_id_t vapi_msg_id_det44_forward;
extern vapi_msg_id_t vapi_msg_id_det44_forward_reply;
extern vapi_msg_id_t vapi_msg_id_det44_reverse;
extern vapi_msg_id_t vapi_msg_id_det44_reverse_reply;
extern vapi_msg_id_t vapi_msg_id_det44_map_dump;
extern vapi_msg_id_t vapi_msg_id_det44_map_details;
extern vapi_msg_id_t vapi_msg_id_det44_close_session_out;
extern vapi_msg_id_t vapi_msg_id_det44_close_session_out_reply;
extern vapi_msg_id_t vapi_msg_id_det44_close_session_in;
extern vapi_msg_id_t vapi_msg_id_det44_close_session_in_reply;
extern vapi_msg_id_t vapi_msg_id_det44_session_dump;
extern vapi_msg_id_t vapi_msg_id_det44_session_details;
extern vapi_msg_id_t vapi_msg_id_det44_set_timeouts;
extern vapi_msg_id_t vapi_msg_id_det44_set_timeouts_reply;
extern vapi_msg_id_t vapi_msg_id_det44_get_timeouts;
extern vapi_msg_id_t vapi_msg_id_det44_get_timeouts_reply;
extern vapi_msg_id_t vapi_msg_id_nat_det_add_del_map;
extern vapi_msg_id_t vapi_msg_id_nat_det_add_del_map_reply;
extern vapi_msg_id_t vapi_msg_id_nat_det_forward;
extern vapi_msg_id_t vapi_msg_id_nat_det_forward_reply;
extern vapi_msg_id_t vapi_msg_id_nat_det_reverse;
extern vapi_msg_id_t vapi_msg_id_nat_det_reverse_reply;
extern vapi_msg_id_t vapi_msg_id_nat_det_map_dump;
extern vapi_msg_id_t vapi_msg_id_nat_det_map_details;
extern vapi_msg_id_t vapi_msg_id_nat_det_close_session_out;
extern vapi_msg_id_t vapi_msg_id_nat_det_close_session_out_reply;
extern vapi_msg_id_t vapi_msg_id_nat_det_close_session_in;
extern vapi_msg_id_t vapi_msg_id_nat_det_close_session_in_reply;
extern vapi_msg_id_t vapi_msg_id_nat_det_session_dump;
extern vapi_msg_id_t vapi_msg_id_nat_det_session_details;

#define DEFINE_VAPI_MSG_IDS_DET44_API_JSON\
  vapi_msg_id_t vapi_msg_id_det44_plugin_enable_disable;\
  vapi_msg_id_t vapi_msg_id_det44_plugin_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_det44_interface_add_del_feature;\
  vapi_msg_id_t vapi_msg_id_det44_interface_add_del_feature_reply;\
  vapi_msg_id_t vapi_msg_id_det44_interface_dump;\
  vapi_msg_id_t vapi_msg_id_det44_interface_details;\
  vapi_msg_id_t vapi_msg_id_det44_add_del_map;\
  vapi_msg_id_t vapi_msg_id_det44_add_del_map_reply;\
  vapi_msg_id_t vapi_msg_id_det44_forward;\
  vapi_msg_id_t vapi_msg_id_det44_forward_reply;\
  vapi_msg_id_t vapi_msg_id_det44_reverse;\
  vapi_msg_id_t vapi_msg_id_det44_reverse_reply;\
  vapi_msg_id_t vapi_msg_id_det44_map_dump;\
  vapi_msg_id_t vapi_msg_id_det44_map_details;\
  vapi_msg_id_t vapi_msg_id_det44_close_session_out;\
  vapi_msg_id_t vapi_msg_id_det44_close_session_out_reply;\
  vapi_msg_id_t vapi_msg_id_det44_close_session_in;\
  vapi_msg_id_t vapi_msg_id_det44_close_session_in_reply;\
  vapi_msg_id_t vapi_msg_id_det44_session_dump;\
  vapi_msg_id_t vapi_msg_id_det44_session_details;\
  vapi_msg_id_t vapi_msg_id_det44_set_timeouts;\
  vapi_msg_id_t vapi_msg_id_det44_set_timeouts_reply;\
  vapi_msg_id_t vapi_msg_id_det44_get_timeouts;\
  vapi_msg_id_t vapi_msg_id_det44_get_timeouts_reply;\
  vapi_msg_id_t vapi_msg_id_nat_det_add_del_map;\
  vapi_msg_id_t vapi_msg_id_nat_det_add_del_map_reply;\
  vapi_msg_id_t vapi_msg_id_nat_det_forward;\
  vapi_msg_id_t vapi_msg_id_nat_det_forward_reply;\
  vapi_msg_id_t vapi_msg_id_nat_det_reverse;\
  vapi_msg_id_t vapi_msg_id_nat_det_reverse_reply;\
  vapi_msg_id_t vapi_msg_id_nat_det_map_dump;\
  vapi_msg_id_t vapi_msg_id_nat_det_map_details;\
  vapi_msg_id_t vapi_msg_id_nat_det_close_session_out;\
  vapi_msg_id_t vapi_msg_id_nat_det_close_session_out_reply;\
  vapi_msg_id_t vapi_msg_id_nat_det_close_session_in;\
  vapi_msg_id_t vapi_msg_id_nat_det_close_session_in_reply;\
  vapi_msg_id_t vapi_msg_id_nat_det_session_dump;\
  vapi_msg_id_t vapi_msg_id_nat_det_session_details;


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

#ifndef defined_vapi_msg_det44_plugin_enable_disable_reply
#define defined_vapi_msg_det44_plugin_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_det44_plugin_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_det44_plugin_enable_disable_reply payload;
} vapi_msg_det44_plugin_enable_disable_reply;

static inline void vapi_msg_det44_plugin_enable_disable_reply_payload_hton(vapi_payload_det44_plugin_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_det44_plugin_enable_disable_reply_payload_ntoh(vapi_payload_det44_plugin_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_det44_plugin_enable_disable_reply_hton(vapi_msg_det44_plugin_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_plugin_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_det44_plugin_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_plugin_enable_disable_reply_ntoh(vapi_msg_det44_plugin_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_plugin_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_det44_plugin_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_plugin_enable_disable_reply_msg_size(vapi_msg_det44_plugin_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_plugin_enable_disable_reply_msg_size(vapi_msg_det44_plugin_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_plugin_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_plugin_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_plugin_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_det44_plugin_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_plugin_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_plugin_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_det44_plugin_enable_disable_reply()
{
  static const char name[] = "det44_plugin_enable_disable_reply";
  static const char name_with_crc[] = "det44_plugin_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_det44_plugin_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_det44_plugin_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_plugin_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_plugin_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_det44_plugin_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_plugin_enable_disable_reply = vapi_register_msg(&__vapi_metadata_det44_plugin_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to det44_plugin_enable_disable_reply", vapi_msg_id_det44_plugin_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_det44_plugin_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_det44_plugin_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_det44_plugin_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_det44_plugin_enable_disable
#define defined_vapi_msg_det44_plugin_enable_disable
typedef struct __attribute__ ((__packed__)) {
  u32 inside_vrf;
  u32 outside_vrf;
  bool enable; 
} vapi_payload_det44_plugin_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_det44_plugin_enable_disable payload;
} vapi_msg_det44_plugin_enable_disable;

static inline void vapi_msg_det44_plugin_enable_disable_payload_hton(vapi_payload_det44_plugin_enable_disable *payload)
{
  payload->inside_vrf = htobe32(payload->inside_vrf);
  payload->outside_vrf = htobe32(payload->outside_vrf);
}

static inline void vapi_msg_det44_plugin_enable_disable_payload_ntoh(vapi_payload_det44_plugin_enable_disable *payload)
{
  payload->inside_vrf = be32toh(payload->inside_vrf);
  payload->outside_vrf = be32toh(payload->outside_vrf);
}

static inline void vapi_msg_det44_plugin_enable_disable_hton(vapi_msg_det44_plugin_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_plugin_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_det44_plugin_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_plugin_enable_disable_ntoh(vapi_msg_det44_plugin_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_plugin_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_det44_plugin_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_plugin_enable_disable_msg_size(vapi_msg_det44_plugin_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_plugin_enable_disable_msg_size(vapi_msg_det44_plugin_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_plugin_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_plugin_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_plugin_enable_disable));
      return -1;
    }
  if (vapi_calc_det44_plugin_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_plugin_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_plugin_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_det44_plugin_enable_disable* vapi_alloc_det44_plugin_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_det44_plugin_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_det44_plugin_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_det44_plugin_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_det44_plugin_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_det44_plugin_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_det44_plugin_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_det44_plugin_enable_disable_reply *reply),
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
  vapi_msg_det44_plugin_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_det44_plugin_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_det44_plugin_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_det44_plugin_enable_disable()
{
  static const char name[] = "det44_plugin_enable_disable";
  static const char name_with_crc[] = "det44_plugin_enable_disable_617b6bf8";
  static vapi_message_desc_t __vapi_metadata_det44_plugin_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_det44_plugin_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_plugin_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_plugin_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_det44_plugin_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_plugin_enable_disable = vapi_register_msg(&__vapi_metadata_det44_plugin_enable_disable);
  VAPI_DBG("Assigned msg id %d to det44_plugin_enable_disable", vapi_msg_id_det44_plugin_enable_disable);
}
#endif

#ifndef defined_vapi_msg_det44_interface_add_del_feature_reply
#define defined_vapi_msg_det44_interface_add_del_feature_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_det44_interface_add_del_feature_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_det44_interface_add_del_feature_reply payload;
} vapi_msg_det44_interface_add_del_feature_reply;

static inline void vapi_msg_det44_interface_add_del_feature_reply_payload_hton(vapi_payload_det44_interface_add_del_feature_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_det44_interface_add_del_feature_reply_payload_ntoh(vapi_payload_det44_interface_add_del_feature_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_det44_interface_add_del_feature_reply_hton(vapi_msg_det44_interface_add_del_feature_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_interface_add_del_feature_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_det44_interface_add_del_feature_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_interface_add_del_feature_reply_ntoh(vapi_msg_det44_interface_add_del_feature_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_interface_add_del_feature_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_det44_interface_add_del_feature_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_interface_add_del_feature_reply_msg_size(vapi_msg_det44_interface_add_del_feature_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_interface_add_del_feature_reply_msg_size(vapi_msg_det44_interface_add_del_feature_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_interface_add_del_feature_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_interface_add_del_feature_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_interface_add_del_feature_reply));
      return -1;
    }
  if (vapi_calc_det44_interface_add_del_feature_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_interface_add_del_feature_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_interface_add_del_feature_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_det44_interface_add_del_feature_reply()
{
  static const char name[] = "det44_interface_add_del_feature_reply";
  static const char name_with_crc[] = "det44_interface_add_del_feature_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_det44_interface_add_del_feature_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_det44_interface_add_del_feature_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_interface_add_del_feature_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_interface_add_del_feature_reply_hton,
    (generic_swap_fn_t)vapi_msg_det44_interface_add_del_feature_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_interface_add_del_feature_reply = vapi_register_msg(&__vapi_metadata_det44_interface_add_del_feature_reply);
  VAPI_DBG("Assigned msg id %d to det44_interface_add_del_feature_reply", vapi_msg_id_det44_interface_add_del_feature_reply);
}

static inline void vapi_set_vapi_msg_det44_interface_add_del_feature_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_det44_interface_add_del_feature_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_det44_interface_add_del_feature_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_det44_interface_add_del_feature
#define defined_vapi_msg_det44_interface_add_del_feature
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  bool is_inside;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_det44_interface_add_del_feature;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_det44_interface_add_del_feature payload;
} vapi_msg_det44_interface_add_del_feature;

static inline void vapi_msg_det44_interface_add_del_feature_payload_hton(vapi_payload_det44_interface_add_del_feature *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_det44_interface_add_del_feature_payload_ntoh(vapi_payload_det44_interface_add_del_feature *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_det44_interface_add_del_feature_hton(vapi_msg_det44_interface_add_del_feature *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_interface_add_del_feature'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_det44_interface_add_del_feature_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_interface_add_del_feature_ntoh(vapi_msg_det44_interface_add_del_feature *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_interface_add_del_feature'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_det44_interface_add_del_feature_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_interface_add_del_feature_msg_size(vapi_msg_det44_interface_add_del_feature *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_interface_add_del_feature_msg_size(vapi_msg_det44_interface_add_del_feature *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_interface_add_del_feature) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_interface_add_del_feature' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_interface_add_del_feature));
      return -1;
    }
  if (vapi_calc_det44_interface_add_del_feature_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_interface_add_del_feature' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_interface_add_del_feature_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_det44_interface_add_del_feature* vapi_alloc_det44_interface_add_del_feature(struct vapi_ctx_s *ctx)
{
  vapi_msg_det44_interface_add_del_feature *msg = NULL;
  const size_t size = sizeof(vapi_msg_det44_interface_add_del_feature);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_det44_interface_add_del_feature*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_det44_interface_add_del_feature);

  return msg;
}

static inline vapi_error_e vapi_det44_interface_add_del_feature(struct vapi_ctx_s *ctx,
  vapi_msg_det44_interface_add_del_feature *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_det44_interface_add_del_feature_reply *reply),
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
  vapi_msg_det44_interface_add_del_feature_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_det44_interface_add_del_feature_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_det44_interface_add_del_feature_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_det44_interface_add_del_feature()
{
  static const char name[] = "det44_interface_add_del_feature";
  static const char name_with_crc[] = "det44_interface_add_del_feature_dc17a836";
  static vapi_message_desc_t __vapi_metadata_det44_interface_add_del_feature = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_det44_interface_add_del_feature, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_interface_add_del_feature_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_interface_add_del_feature_hton,
    (generic_swap_fn_t)vapi_msg_det44_interface_add_del_feature_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_interface_add_del_feature = vapi_register_msg(&__vapi_metadata_det44_interface_add_del_feature);
  VAPI_DBG("Assigned msg id %d to det44_interface_add_del_feature", vapi_msg_id_det44_interface_add_del_feature);
}
#endif

#ifndef defined_vapi_msg_det44_interface_details
#define defined_vapi_msg_det44_interface_details
typedef struct __attribute__ ((__packed__)) {
  bool is_inside;
  bool is_outside;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_det44_interface_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_det44_interface_details payload;
} vapi_msg_det44_interface_details;

static inline void vapi_msg_det44_interface_details_payload_hton(vapi_payload_det44_interface_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_det44_interface_details_payload_ntoh(vapi_payload_det44_interface_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_det44_interface_details_hton(vapi_msg_det44_interface_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_interface_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_det44_interface_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_interface_details_ntoh(vapi_msg_det44_interface_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_interface_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_det44_interface_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_interface_details_msg_size(vapi_msg_det44_interface_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_interface_details_msg_size(vapi_msg_det44_interface_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_interface_details) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_interface_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_interface_details));
      return -1;
    }
  if (vapi_calc_det44_interface_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_interface_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_interface_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_det44_interface_details()
{
  static const char name[] = "det44_interface_details";
  static const char name_with_crc[] = "det44_interface_details_e60cc5be";
  static vapi_message_desc_t __vapi_metadata_det44_interface_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_det44_interface_details, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_interface_details_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_interface_details_hton,
    (generic_swap_fn_t)vapi_msg_det44_interface_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_interface_details = vapi_register_msg(&__vapi_metadata_det44_interface_details);
  VAPI_DBG("Assigned msg id %d to det44_interface_details", vapi_msg_id_det44_interface_details);
}

static inline void vapi_set_vapi_msg_det44_interface_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_det44_interface_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_det44_interface_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_det44_interface_dump
#define defined_vapi_msg_det44_interface_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_det44_interface_dump;

static inline void vapi_msg_det44_interface_dump_hton(vapi_msg_det44_interface_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_interface_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_det44_interface_dump_ntoh(vapi_msg_det44_interface_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_interface_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_det44_interface_dump_msg_size(vapi_msg_det44_interface_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_interface_dump_msg_size(vapi_msg_det44_interface_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_interface_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_interface_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_interface_dump));
      return -1;
    }
  if (vapi_calc_det44_interface_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_interface_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_interface_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_det44_interface_dump* vapi_alloc_det44_interface_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_det44_interface_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_det44_interface_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_det44_interface_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_det44_interface_dump);

  return msg;
}

static inline vapi_error_e vapi_det44_interface_dump(struct vapi_ctx_s *ctx,
  vapi_msg_det44_interface_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_det44_interface_details *reply),
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
  vapi_msg_det44_interface_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_det44_interface_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_det44_interface_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_det44_interface_dump()
{
  static const char name[] = "det44_interface_dump";
  static const char name_with_crc[] = "det44_interface_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_det44_interface_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_det44_interface_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_interface_dump_hton,
    (generic_swap_fn_t)vapi_msg_det44_interface_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_interface_dump = vapi_register_msg(&__vapi_metadata_det44_interface_dump);
  VAPI_DBG("Assigned msg id %d to det44_interface_dump", vapi_msg_id_det44_interface_dump);
}
#endif

#ifndef defined_vapi_msg_det44_add_del_map_reply
#define defined_vapi_msg_det44_add_del_map_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_det44_add_del_map_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_det44_add_del_map_reply payload;
} vapi_msg_det44_add_del_map_reply;

static inline void vapi_msg_det44_add_del_map_reply_payload_hton(vapi_payload_det44_add_del_map_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_det44_add_del_map_reply_payload_ntoh(vapi_payload_det44_add_del_map_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_det44_add_del_map_reply_hton(vapi_msg_det44_add_del_map_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_add_del_map_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_det44_add_del_map_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_add_del_map_reply_ntoh(vapi_msg_det44_add_del_map_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_add_del_map_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_det44_add_del_map_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_add_del_map_reply_msg_size(vapi_msg_det44_add_del_map_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_add_del_map_reply_msg_size(vapi_msg_det44_add_del_map_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_add_del_map_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_add_del_map_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_add_del_map_reply));
      return -1;
    }
  if (vapi_calc_det44_add_del_map_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_add_del_map_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_add_del_map_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_det44_add_del_map_reply()
{
  static const char name[] = "det44_add_del_map_reply";
  static const char name_with_crc[] = "det44_add_del_map_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_det44_add_del_map_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_det44_add_del_map_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_add_del_map_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_add_del_map_reply_hton,
    (generic_swap_fn_t)vapi_msg_det44_add_del_map_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_add_del_map_reply = vapi_register_msg(&__vapi_metadata_det44_add_del_map_reply);
  VAPI_DBG("Assigned msg id %d to det44_add_del_map_reply", vapi_msg_id_det44_add_del_map_reply);
}

static inline void vapi_set_vapi_msg_det44_add_del_map_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_det44_add_del_map_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_det44_add_del_map_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_det44_add_del_map
#define defined_vapi_msg_det44_add_del_map
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_ip4_address in_addr;
  u8 in_plen;
  vapi_type_ip4_address out_addr;
  u8 out_plen; 
} vapi_payload_det44_add_del_map;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_det44_add_del_map payload;
} vapi_msg_det44_add_del_map;

static inline void vapi_msg_det44_add_del_map_payload_hton(vapi_payload_det44_add_del_map *payload)
{

}

static inline void vapi_msg_det44_add_del_map_payload_ntoh(vapi_payload_det44_add_del_map *payload)
{

}

static inline void vapi_msg_det44_add_del_map_hton(vapi_msg_det44_add_del_map *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_add_del_map'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_det44_add_del_map_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_add_del_map_ntoh(vapi_msg_det44_add_del_map *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_add_del_map'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_det44_add_del_map_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_add_del_map_msg_size(vapi_msg_det44_add_del_map *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_add_del_map_msg_size(vapi_msg_det44_add_del_map *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_add_del_map) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_add_del_map' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_add_del_map));
      return -1;
    }
  if (vapi_calc_det44_add_del_map_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_add_del_map' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_add_del_map_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_det44_add_del_map* vapi_alloc_det44_add_del_map(struct vapi_ctx_s *ctx)
{
  vapi_msg_det44_add_del_map *msg = NULL;
  const size_t size = sizeof(vapi_msg_det44_add_del_map);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_det44_add_del_map*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_det44_add_del_map);

  return msg;
}

static inline vapi_error_e vapi_det44_add_del_map(struct vapi_ctx_s *ctx,
  vapi_msg_det44_add_del_map *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_det44_add_del_map_reply *reply),
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
  vapi_msg_det44_add_del_map_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_det44_add_del_map_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_det44_add_del_map_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_det44_add_del_map()
{
  static const char name[] = "det44_add_del_map";
  static const char name_with_crc[] = "det44_add_del_map_1150a190";
  static vapi_message_desc_t __vapi_metadata_det44_add_del_map = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_det44_add_del_map, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_add_del_map_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_add_del_map_hton,
    (generic_swap_fn_t)vapi_msg_det44_add_del_map_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_add_del_map = vapi_register_msg(&__vapi_metadata_det44_add_del_map);
  VAPI_DBG("Assigned msg id %d to det44_add_del_map", vapi_msg_id_det44_add_del_map);
}
#endif

#ifndef defined_vapi_msg_det44_forward_reply
#define defined_vapi_msg_det44_forward_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u16 out_port_lo;
  u16 out_port_hi;
  vapi_type_ip4_address out_addr; 
} vapi_payload_det44_forward_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_det44_forward_reply payload;
} vapi_msg_det44_forward_reply;

static inline void vapi_msg_det44_forward_reply_payload_hton(vapi_payload_det44_forward_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->out_port_lo = htobe16(payload->out_port_lo);
  payload->out_port_hi = htobe16(payload->out_port_hi);
}

static inline void vapi_msg_det44_forward_reply_payload_ntoh(vapi_payload_det44_forward_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->out_port_lo = be16toh(payload->out_port_lo);
  payload->out_port_hi = be16toh(payload->out_port_hi);
}

static inline void vapi_msg_det44_forward_reply_hton(vapi_msg_det44_forward_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_forward_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_det44_forward_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_forward_reply_ntoh(vapi_msg_det44_forward_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_forward_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_det44_forward_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_forward_reply_msg_size(vapi_msg_det44_forward_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_forward_reply_msg_size(vapi_msg_det44_forward_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_forward_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_forward_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_forward_reply));
      return -1;
    }
  if (vapi_calc_det44_forward_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_forward_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_forward_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_det44_forward_reply()
{
  static const char name[] = "det44_forward_reply";
  static const char name_with_crc[] = "det44_forward_reply_a8ccbdc0";
  static vapi_message_desc_t __vapi_metadata_det44_forward_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_det44_forward_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_forward_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_forward_reply_hton,
    (generic_swap_fn_t)vapi_msg_det44_forward_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_forward_reply = vapi_register_msg(&__vapi_metadata_det44_forward_reply);
  VAPI_DBG("Assigned msg id %d to det44_forward_reply", vapi_msg_id_det44_forward_reply);
}

static inline void vapi_set_vapi_msg_det44_forward_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_det44_forward_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_det44_forward_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_det44_forward
#define defined_vapi_msg_det44_forward
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address in_addr; 
} vapi_payload_det44_forward;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_det44_forward payload;
} vapi_msg_det44_forward;

static inline void vapi_msg_det44_forward_payload_hton(vapi_payload_det44_forward *payload)
{

}

static inline void vapi_msg_det44_forward_payload_ntoh(vapi_payload_det44_forward *payload)
{

}

static inline void vapi_msg_det44_forward_hton(vapi_msg_det44_forward *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_forward'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_det44_forward_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_forward_ntoh(vapi_msg_det44_forward *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_forward'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_det44_forward_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_forward_msg_size(vapi_msg_det44_forward *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_forward_msg_size(vapi_msg_det44_forward *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_forward) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_forward' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_forward));
      return -1;
    }
  if (vapi_calc_det44_forward_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_forward' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_forward_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_det44_forward* vapi_alloc_det44_forward(struct vapi_ctx_s *ctx)
{
  vapi_msg_det44_forward *msg = NULL;
  const size_t size = sizeof(vapi_msg_det44_forward);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_det44_forward*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_det44_forward);

  return msg;
}

static inline vapi_error_e vapi_det44_forward(struct vapi_ctx_s *ctx,
  vapi_msg_det44_forward *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_det44_forward_reply *reply),
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
  vapi_msg_det44_forward_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_det44_forward_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_det44_forward_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_det44_forward()
{
  static const char name[] = "det44_forward";
  static const char name_with_crc[] = "det44_forward_7f8a89cd";
  static vapi_message_desc_t __vapi_metadata_det44_forward = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_det44_forward, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_forward_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_forward_hton,
    (generic_swap_fn_t)vapi_msg_det44_forward_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_forward = vapi_register_msg(&__vapi_metadata_det44_forward);
  VAPI_DBG("Assigned msg id %d to det44_forward", vapi_msg_id_det44_forward);
}
#endif

#ifndef defined_vapi_msg_det44_reverse_reply
#define defined_vapi_msg_det44_reverse_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_ip4_address in_addr; 
} vapi_payload_det44_reverse_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_det44_reverse_reply payload;
} vapi_msg_det44_reverse_reply;

static inline void vapi_msg_det44_reverse_reply_payload_hton(vapi_payload_det44_reverse_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_det44_reverse_reply_payload_ntoh(vapi_payload_det44_reverse_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_det44_reverse_reply_hton(vapi_msg_det44_reverse_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_reverse_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_det44_reverse_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_reverse_reply_ntoh(vapi_msg_det44_reverse_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_reverse_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_det44_reverse_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_reverse_reply_msg_size(vapi_msg_det44_reverse_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_reverse_reply_msg_size(vapi_msg_det44_reverse_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_reverse_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_reverse_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_reverse_reply));
      return -1;
    }
  if (vapi_calc_det44_reverse_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_reverse_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_reverse_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_det44_reverse_reply()
{
  static const char name[] = "det44_reverse_reply";
  static const char name_with_crc[] = "det44_reverse_reply_34066d48";
  static vapi_message_desc_t __vapi_metadata_det44_reverse_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_det44_reverse_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_reverse_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_reverse_reply_hton,
    (generic_swap_fn_t)vapi_msg_det44_reverse_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_reverse_reply = vapi_register_msg(&__vapi_metadata_det44_reverse_reply);
  VAPI_DBG("Assigned msg id %d to det44_reverse_reply", vapi_msg_id_det44_reverse_reply);
}

static inline void vapi_set_vapi_msg_det44_reverse_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_det44_reverse_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_det44_reverse_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_det44_reverse
#define defined_vapi_msg_det44_reverse
typedef struct __attribute__ ((__packed__)) {
  u16 out_port;
  vapi_type_ip4_address out_addr; 
} vapi_payload_det44_reverse;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_det44_reverse payload;
} vapi_msg_det44_reverse;

static inline void vapi_msg_det44_reverse_payload_hton(vapi_payload_det44_reverse *payload)
{
  payload->out_port = htobe16(payload->out_port);
}

static inline void vapi_msg_det44_reverse_payload_ntoh(vapi_payload_det44_reverse *payload)
{
  payload->out_port = be16toh(payload->out_port);
}

static inline void vapi_msg_det44_reverse_hton(vapi_msg_det44_reverse *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_reverse'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_det44_reverse_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_reverse_ntoh(vapi_msg_det44_reverse *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_reverse'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_det44_reverse_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_reverse_msg_size(vapi_msg_det44_reverse *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_reverse_msg_size(vapi_msg_det44_reverse *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_reverse) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_reverse' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_reverse));
      return -1;
    }
  if (vapi_calc_det44_reverse_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_reverse' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_reverse_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_det44_reverse* vapi_alloc_det44_reverse(struct vapi_ctx_s *ctx)
{
  vapi_msg_det44_reverse *msg = NULL;
  const size_t size = sizeof(vapi_msg_det44_reverse);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_det44_reverse*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_det44_reverse);

  return msg;
}

static inline vapi_error_e vapi_det44_reverse(struct vapi_ctx_s *ctx,
  vapi_msg_det44_reverse *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_det44_reverse_reply *reply),
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
  vapi_msg_det44_reverse_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_det44_reverse_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_det44_reverse_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_det44_reverse()
{
  static const char name[] = "det44_reverse";
  static const char name_with_crc[] = "det44_reverse_a7573fe1";
  static vapi_message_desc_t __vapi_metadata_det44_reverse = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_det44_reverse, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_reverse_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_reverse_hton,
    (generic_swap_fn_t)vapi_msg_det44_reverse_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_reverse = vapi_register_msg(&__vapi_metadata_det44_reverse);
  VAPI_DBG("Assigned msg id %d to det44_reverse", vapi_msg_id_det44_reverse);
}
#endif

#ifndef defined_vapi_msg_det44_map_details
#define defined_vapi_msg_det44_map_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address in_addr;
  u8 in_plen;
  vapi_type_ip4_address out_addr;
  u8 out_plen;
  u32 sharing_ratio;
  u16 ports_per_host;
  u32 ses_num; 
} vapi_payload_det44_map_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_det44_map_details payload;
} vapi_msg_det44_map_details;

static inline void vapi_msg_det44_map_details_payload_hton(vapi_payload_det44_map_details *payload)
{
  payload->sharing_ratio = htobe32(payload->sharing_ratio);
  payload->ports_per_host = htobe16(payload->ports_per_host);
  payload->ses_num = htobe32(payload->ses_num);
}

static inline void vapi_msg_det44_map_details_payload_ntoh(vapi_payload_det44_map_details *payload)
{
  payload->sharing_ratio = be32toh(payload->sharing_ratio);
  payload->ports_per_host = be16toh(payload->ports_per_host);
  payload->ses_num = be32toh(payload->ses_num);
}

static inline void vapi_msg_det44_map_details_hton(vapi_msg_det44_map_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_map_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_det44_map_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_map_details_ntoh(vapi_msg_det44_map_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_map_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_det44_map_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_map_details_msg_size(vapi_msg_det44_map_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_map_details_msg_size(vapi_msg_det44_map_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_map_details) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_map_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_map_details));
      return -1;
    }
  if (vapi_calc_det44_map_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_map_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_map_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_det44_map_details()
{
  static const char name[] = "det44_map_details";
  static const char name_with_crc[] = "det44_map_details_ad91dc83";
  static vapi_message_desc_t __vapi_metadata_det44_map_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_det44_map_details, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_map_details_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_map_details_hton,
    (generic_swap_fn_t)vapi_msg_det44_map_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_map_details = vapi_register_msg(&__vapi_metadata_det44_map_details);
  VAPI_DBG("Assigned msg id %d to det44_map_details", vapi_msg_id_det44_map_details);
}

static inline void vapi_set_vapi_msg_det44_map_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_det44_map_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_det44_map_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_det44_map_dump
#define defined_vapi_msg_det44_map_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_det44_map_dump;

static inline void vapi_msg_det44_map_dump_hton(vapi_msg_det44_map_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_map_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_det44_map_dump_ntoh(vapi_msg_det44_map_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_map_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_det44_map_dump_msg_size(vapi_msg_det44_map_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_map_dump_msg_size(vapi_msg_det44_map_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_map_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_map_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_map_dump));
      return -1;
    }
  if (vapi_calc_det44_map_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_map_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_map_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_det44_map_dump* vapi_alloc_det44_map_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_det44_map_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_det44_map_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_det44_map_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_det44_map_dump);

  return msg;
}

static inline vapi_error_e vapi_det44_map_dump(struct vapi_ctx_s *ctx,
  vapi_msg_det44_map_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_det44_map_details *reply),
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
  vapi_msg_det44_map_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_det44_map_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_det44_map_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_det44_map_dump()
{
  static const char name[] = "det44_map_dump";
  static const char name_with_crc[] = "det44_map_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_det44_map_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_det44_map_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_map_dump_hton,
    (generic_swap_fn_t)vapi_msg_det44_map_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_map_dump = vapi_register_msg(&__vapi_metadata_det44_map_dump);
  VAPI_DBG("Assigned msg id %d to det44_map_dump", vapi_msg_id_det44_map_dump);
}
#endif

#ifndef defined_vapi_msg_det44_close_session_out_reply
#define defined_vapi_msg_det44_close_session_out_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_det44_close_session_out_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_det44_close_session_out_reply payload;
} vapi_msg_det44_close_session_out_reply;

static inline void vapi_msg_det44_close_session_out_reply_payload_hton(vapi_payload_det44_close_session_out_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_det44_close_session_out_reply_payload_ntoh(vapi_payload_det44_close_session_out_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_det44_close_session_out_reply_hton(vapi_msg_det44_close_session_out_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_close_session_out_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_det44_close_session_out_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_close_session_out_reply_ntoh(vapi_msg_det44_close_session_out_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_close_session_out_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_det44_close_session_out_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_close_session_out_reply_msg_size(vapi_msg_det44_close_session_out_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_close_session_out_reply_msg_size(vapi_msg_det44_close_session_out_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_close_session_out_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_close_session_out_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_close_session_out_reply));
      return -1;
    }
  if (vapi_calc_det44_close_session_out_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_close_session_out_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_close_session_out_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_det44_close_session_out_reply()
{
  static const char name[] = "det44_close_session_out_reply";
  static const char name_with_crc[] = "det44_close_session_out_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_det44_close_session_out_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_det44_close_session_out_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_close_session_out_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_close_session_out_reply_hton,
    (generic_swap_fn_t)vapi_msg_det44_close_session_out_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_close_session_out_reply = vapi_register_msg(&__vapi_metadata_det44_close_session_out_reply);
  VAPI_DBG("Assigned msg id %d to det44_close_session_out_reply", vapi_msg_id_det44_close_session_out_reply);
}

static inline void vapi_set_vapi_msg_det44_close_session_out_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_det44_close_session_out_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_det44_close_session_out_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_det44_close_session_out
#define defined_vapi_msg_det44_close_session_out
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address out_addr;
  u16 out_port;
  vapi_type_ip4_address ext_addr;
  u16 ext_port; 
} vapi_payload_det44_close_session_out;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_det44_close_session_out payload;
} vapi_msg_det44_close_session_out;

static inline void vapi_msg_det44_close_session_out_payload_hton(vapi_payload_det44_close_session_out *payload)
{
  payload->out_port = htobe16(payload->out_port);
  payload->ext_port = htobe16(payload->ext_port);
}

static inline void vapi_msg_det44_close_session_out_payload_ntoh(vapi_payload_det44_close_session_out *payload)
{
  payload->out_port = be16toh(payload->out_port);
  payload->ext_port = be16toh(payload->ext_port);
}

static inline void vapi_msg_det44_close_session_out_hton(vapi_msg_det44_close_session_out *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_close_session_out'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_det44_close_session_out_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_close_session_out_ntoh(vapi_msg_det44_close_session_out *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_close_session_out'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_det44_close_session_out_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_close_session_out_msg_size(vapi_msg_det44_close_session_out *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_close_session_out_msg_size(vapi_msg_det44_close_session_out *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_close_session_out) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_close_session_out' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_close_session_out));
      return -1;
    }
  if (vapi_calc_det44_close_session_out_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_close_session_out' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_close_session_out_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_det44_close_session_out* vapi_alloc_det44_close_session_out(struct vapi_ctx_s *ctx)
{
  vapi_msg_det44_close_session_out *msg = NULL;
  const size_t size = sizeof(vapi_msg_det44_close_session_out);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_det44_close_session_out*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_det44_close_session_out);

  return msg;
}

static inline vapi_error_e vapi_det44_close_session_out(struct vapi_ctx_s *ctx,
  vapi_msg_det44_close_session_out *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_det44_close_session_out_reply *reply),
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
  vapi_msg_det44_close_session_out_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_det44_close_session_out_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_det44_close_session_out_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_det44_close_session_out()
{
  static const char name[] = "det44_close_session_out";
  static const char name_with_crc[] = "det44_close_session_out_f6b259d1";
  static vapi_message_desc_t __vapi_metadata_det44_close_session_out = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_det44_close_session_out, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_close_session_out_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_close_session_out_hton,
    (generic_swap_fn_t)vapi_msg_det44_close_session_out_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_close_session_out = vapi_register_msg(&__vapi_metadata_det44_close_session_out);
  VAPI_DBG("Assigned msg id %d to det44_close_session_out", vapi_msg_id_det44_close_session_out);
}
#endif

#ifndef defined_vapi_msg_det44_close_session_in_reply
#define defined_vapi_msg_det44_close_session_in_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_det44_close_session_in_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_det44_close_session_in_reply payload;
} vapi_msg_det44_close_session_in_reply;

static inline void vapi_msg_det44_close_session_in_reply_payload_hton(vapi_payload_det44_close_session_in_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_det44_close_session_in_reply_payload_ntoh(vapi_payload_det44_close_session_in_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_det44_close_session_in_reply_hton(vapi_msg_det44_close_session_in_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_close_session_in_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_det44_close_session_in_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_close_session_in_reply_ntoh(vapi_msg_det44_close_session_in_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_close_session_in_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_det44_close_session_in_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_close_session_in_reply_msg_size(vapi_msg_det44_close_session_in_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_close_session_in_reply_msg_size(vapi_msg_det44_close_session_in_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_close_session_in_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_close_session_in_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_close_session_in_reply));
      return -1;
    }
  if (vapi_calc_det44_close_session_in_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_close_session_in_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_close_session_in_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_det44_close_session_in_reply()
{
  static const char name[] = "det44_close_session_in_reply";
  static const char name_with_crc[] = "det44_close_session_in_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_det44_close_session_in_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_det44_close_session_in_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_close_session_in_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_close_session_in_reply_hton,
    (generic_swap_fn_t)vapi_msg_det44_close_session_in_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_close_session_in_reply = vapi_register_msg(&__vapi_metadata_det44_close_session_in_reply);
  VAPI_DBG("Assigned msg id %d to det44_close_session_in_reply", vapi_msg_id_det44_close_session_in_reply);
}

static inline void vapi_set_vapi_msg_det44_close_session_in_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_det44_close_session_in_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_det44_close_session_in_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_det44_close_session_in
#define defined_vapi_msg_det44_close_session_in
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address in_addr;
  u16 in_port;
  vapi_type_ip4_address ext_addr;
  u16 ext_port; 
} vapi_payload_det44_close_session_in;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_det44_close_session_in payload;
} vapi_msg_det44_close_session_in;

static inline void vapi_msg_det44_close_session_in_payload_hton(vapi_payload_det44_close_session_in *payload)
{
  payload->in_port = htobe16(payload->in_port);
  payload->ext_port = htobe16(payload->ext_port);
}

static inline void vapi_msg_det44_close_session_in_payload_ntoh(vapi_payload_det44_close_session_in *payload)
{
  payload->in_port = be16toh(payload->in_port);
  payload->ext_port = be16toh(payload->ext_port);
}

static inline void vapi_msg_det44_close_session_in_hton(vapi_msg_det44_close_session_in *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_close_session_in'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_det44_close_session_in_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_close_session_in_ntoh(vapi_msg_det44_close_session_in *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_close_session_in'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_det44_close_session_in_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_close_session_in_msg_size(vapi_msg_det44_close_session_in *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_close_session_in_msg_size(vapi_msg_det44_close_session_in *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_close_session_in) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_close_session_in' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_close_session_in));
      return -1;
    }
  if (vapi_calc_det44_close_session_in_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_close_session_in' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_close_session_in_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_det44_close_session_in* vapi_alloc_det44_close_session_in(struct vapi_ctx_s *ctx)
{
  vapi_msg_det44_close_session_in *msg = NULL;
  const size_t size = sizeof(vapi_msg_det44_close_session_in);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_det44_close_session_in*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_det44_close_session_in);

  return msg;
}

static inline vapi_error_e vapi_det44_close_session_in(struct vapi_ctx_s *ctx,
  vapi_msg_det44_close_session_in *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_det44_close_session_in_reply *reply),
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
  vapi_msg_det44_close_session_in_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_det44_close_session_in_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_det44_close_session_in_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_det44_close_session_in()
{
  static const char name[] = "det44_close_session_in";
  static const char name_with_crc[] = "det44_close_session_in_3c68e073";
  static vapi_message_desc_t __vapi_metadata_det44_close_session_in = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_det44_close_session_in, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_close_session_in_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_close_session_in_hton,
    (generic_swap_fn_t)vapi_msg_det44_close_session_in_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_close_session_in = vapi_register_msg(&__vapi_metadata_det44_close_session_in);
  VAPI_DBG("Assigned msg id %d to det44_close_session_in", vapi_msg_id_det44_close_session_in);
}
#endif

#ifndef defined_vapi_msg_det44_session_details
#define defined_vapi_msg_det44_session_details
typedef struct __attribute__ ((__packed__)) {
  u16 in_port;
  vapi_type_ip4_address ext_addr;
  u16 ext_port;
  u16 out_port;
  u8 state;
  u32 expire; 
} vapi_payload_det44_session_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_det44_session_details payload;
} vapi_msg_det44_session_details;

static inline void vapi_msg_det44_session_details_payload_hton(vapi_payload_det44_session_details *payload)
{
  payload->in_port = htobe16(payload->in_port);
  payload->ext_port = htobe16(payload->ext_port);
  payload->out_port = htobe16(payload->out_port);
  payload->expire = htobe32(payload->expire);
}

static inline void vapi_msg_det44_session_details_payload_ntoh(vapi_payload_det44_session_details *payload)
{
  payload->in_port = be16toh(payload->in_port);
  payload->ext_port = be16toh(payload->ext_port);
  payload->out_port = be16toh(payload->out_port);
  payload->expire = be32toh(payload->expire);
}

static inline void vapi_msg_det44_session_details_hton(vapi_msg_det44_session_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_session_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_det44_session_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_session_details_ntoh(vapi_msg_det44_session_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_session_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_det44_session_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_session_details_msg_size(vapi_msg_det44_session_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_session_details_msg_size(vapi_msg_det44_session_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_session_details) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_session_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_session_details));
      return -1;
    }
  if (vapi_calc_det44_session_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_session_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_session_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_det44_session_details()
{
  static const char name[] = "det44_session_details";
  static const char name_with_crc[] = "det44_session_details_27f3c171";
  static vapi_message_desc_t __vapi_metadata_det44_session_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_det44_session_details, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_session_details_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_session_details_hton,
    (generic_swap_fn_t)vapi_msg_det44_session_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_session_details = vapi_register_msg(&__vapi_metadata_det44_session_details);
  VAPI_DBG("Assigned msg id %d to det44_session_details", vapi_msg_id_det44_session_details);
}

static inline void vapi_set_vapi_msg_det44_session_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_det44_session_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_det44_session_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_det44_session_dump
#define defined_vapi_msg_det44_session_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address user_addr; 
} vapi_payload_det44_session_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_det44_session_dump payload;
} vapi_msg_det44_session_dump;

static inline void vapi_msg_det44_session_dump_payload_hton(vapi_payload_det44_session_dump *payload)
{

}

static inline void vapi_msg_det44_session_dump_payload_ntoh(vapi_payload_det44_session_dump *payload)
{

}

static inline void vapi_msg_det44_session_dump_hton(vapi_msg_det44_session_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_session_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_det44_session_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_session_dump_ntoh(vapi_msg_det44_session_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_session_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_det44_session_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_session_dump_msg_size(vapi_msg_det44_session_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_session_dump_msg_size(vapi_msg_det44_session_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_session_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_session_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_session_dump));
      return -1;
    }
  if (vapi_calc_det44_session_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_session_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_session_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_det44_session_dump* vapi_alloc_det44_session_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_det44_session_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_det44_session_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_det44_session_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_det44_session_dump);

  return msg;
}

static inline vapi_error_e vapi_det44_session_dump(struct vapi_ctx_s *ctx,
  vapi_msg_det44_session_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_det44_session_details *reply),
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
  vapi_msg_det44_session_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_det44_session_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_det44_session_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_det44_session_dump()
{
  static const char name[] = "det44_session_dump";
  static const char name_with_crc[] = "det44_session_dump_e45a3af7";
  static vapi_message_desc_t __vapi_metadata_det44_session_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_det44_session_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_session_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_session_dump_hton,
    (generic_swap_fn_t)vapi_msg_det44_session_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_session_dump = vapi_register_msg(&__vapi_metadata_det44_session_dump);
  VAPI_DBG("Assigned msg id %d to det44_session_dump", vapi_msg_id_det44_session_dump);
}
#endif

#ifndef defined_vapi_msg_det44_set_timeouts_reply
#define defined_vapi_msg_det44_set_timeouts_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_det44_set_timeouts_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_det44_set_timeouts_reply payload;
} vapi_msg_det44_set_timeouts_reply;

static inline void vapi_msg_det44_set_timeouts_reply_payload_hton(vapi_payload_det44_set_timeouts_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_det44_set_timeouts_reply_payload_ntoh(vapi_payload_det44_set_timeouts_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_det44_set_timeouts_reply_hton(vapi_msg_det44_set_timeouts_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_set_timeouts_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_det44_set_timeouts_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_set_timeouts_reply_ntoh(vapi_msg_det44_set_timeouts_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_set_timeouts_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_det44_set_timeouts_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_set_timeouts_reply_msg_size(vapi_msg_det44_set_timeouts_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_set_timeouts_reply_msg_size(vapi_msg_det44_set_timeouts_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_set_timeouts_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_set_timeouts_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_set_timeouts_reply));
      return -1;
    }
  if (vapi_calc_det44_set_timeouts_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_set_timeouts_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_set_timeouts_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_det44_set_timeouts_reply()
{
  static const char name[] = "det44_set_timeouts_reply";
  static const char name_with_crc[] = "det44_set_timeouts_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_det44_set_timeouts_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_det44_set_timeouts_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_set_timeouts_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_set_timeouts_reply_hton,
    (generic_swap_fn_t)vapi_msg_det44_set_timeouts_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_set_timeouts_reply = vapi_register_msg(&__vapi_metadata_det44_set_timeouts_reply);
  VAPI_DBG("Assigned msg id %d to det44_set_timeouts_reply", vapi_msg_id_det44_set_timeouts_reply);
}

static inline void vapi_set_vapi_msg_det44_set_timeouts_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_det44_set_timeouts_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_det44_set_timeouts_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_det44_set_timeouts
#define defined_vapi_msg_det44_set_timeouts
typedef struct __attribute__ ((__packed__)) {
  u32 udp;
  u32 tcp_established;
  u32 tcp_transitory;
  u32 icmp; 
} vapi_payload_det44_set_timeouts;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_det44_set_timeouts payload;
} vapi_msg_det44_set_timeouts;

static inline void vapi_msg_det44_set_timeouts_payload_hton(vapi_payload_det44_set_timeouts *payload)
{
  payload->udp = htobe32(payload->udp);
  payload->tcp_established = htobe32(payload->tcp_established);
  payload->tcp_transitory = htobe32(payload->tcp_transitory);
  payload->icmp = htobe32(payload->icmp);
}

static inline void vapi_msg_det44_set_timeouts_payload_ntoh(vapi_payload_det44_set_timeouts *payload)
{
  payload->udp = be32toh(payload->udp);
  payload->tcp_established = be32toh(payload->tcp_established);
  payload->tcp_transitory = be32toh(payload->tcp_transitory);
  payload->icmp = be32toh(payload->icmp);
}

static inline void vapi_msg_det44_set_timeouts_hton(vapi_msg_det44_set_timeouts *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_set_timeouts'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_det44_set_timeouts_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_set_timeouts_ntoh(vapi_msg_det44_set_timeouts *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_set_timeouts'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_det44_set_timeouts_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_set_timeouts_msg_size(vapi_msg_det44_set_timeouts *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_set_timeouts_msg_size(vapi_msg_det44_set_timeouts *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_set_timeouts) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_set_timeouts' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_set_timeouts));
      return -1;
    }
  if (vapi_calc_det44_set_timeouts_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_set_timeouts' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_set_timeouts_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_det44_set_timeouts* vapi_alloc_det44_set_timeouts(struct vapi_ctx_s *ctx)
{
  vapi_msg_det44_set_timeouts *msg = NULL;
  const size_t size = sizeof(vapi_msg_det44_set_timeouts);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_det44_set_timeouts*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_det44_set_timeouts);

  return msg;
}

static inline vapi_error_e vapi_det44_set_timeouts(struct vapi_ctx_s *ctx,
  vapi_msg_det44_set_timeouts *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_det44_set_timeouts_reply *reply),
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
  vapi_msg_det44_set_timeouts_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_det44_set_timeouts_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_det44_set_timeouts_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_det44_set_timeouts()
{
  static const char name[] = "det44_set_timeouts";
  static const char name_with_crc[] = "det44_set_timeouts_d4746b16";
  static vapi_message_desc_t __vapi_metadata_det44_set_timeouts = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_det44_set_timeouts, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_set_timeouts_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_set_timeouts_hton,
    (generic_swap_fn_t)vapi_msg_det44_set_timeouts_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_set_timeouts = vapi_register_msg(&__vapi_metadata_det44_set_timeouts);
  VAPI_DBG("Assigned msg id %d to det44_set_timeouts", vapi_msg_id_det44_set_timeouts);
}
#endif

#ifndef defined_vapi_msg_det44_get_timeouts_reply
#define defined_vapi_msg_det44_get_timeouts_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 udp;
  u32 tcp_established;
  u32 tcp_transitory;
  u32 icmp; 
} vapi_payload_det44_get_timeouts_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_det44_get_timeouts_reply payload;
} vapi_msg_det44_get_timeouts_reply;

static inline void vapi_msg_det44_get_timeouts_reply_payload_hton(vapi_payload_det44_get_timeouts_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->udp = htobe32(payload->udp);
  payload->tcp_established = htobe32(payload->tcp_established);
  payload->tcp_transitory = htobe32(payload->tcp_transitory);
  payload->icmp = htobe32(payload->icmp);
}

static inline void vapi_msg_det44_get_timeouts_reply_payload_ntoh(vapi_payload_det44_get_timeouts_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->udp = be32toh(payload->udp);
  payload->tcp_established = be32toh(payload->tcp_established);
  payload->tcp_transitory = be32toh(payload->tcp_transitory);
  payload->icmp = be32toh(payload->icmp);
}

static inline void vapi_msg_det44_get_timeouts_reply_hton(vapi_msg_det44_get_timeouts_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_get_timeouts_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_det44_get_timeouts_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_det44_get_timeouts_reply_ntoh(vapi_msg_det44_get_timeouts_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_get_timeouts_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_det44_get_timeouts_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_det44_get_timeouts_reply_msg_size(vapi_msg_det44_get_timeouts_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_get_timeouts_reply_msg_size(vapi_msg_det44_get_timeouts_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_get_timeouts_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_get_timeouts_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_get_timeouts_reply));
      return -1;
    }
  if (vapi_calc_det44_get_timeouts_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_get_timeouts_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_get_timeouts_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_det44_get_timeouts_reply()
{
  static const char name[] = "det44_get_timeouts_reply";
  static const char name_with_crc[] = "det44_get_timeouts_reply_3c4df4e1";
  static vapi_message_desc_t __vapi_metadata_det44_get_timeouts_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_det44_get_timeouts_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_det44_get_timeouts_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_get_timeouts_reply_hton,
    (generic_swap_fn_t)vapi_msg_det44_get_timeouts_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_get_timeouts_reply = vapi_register_msg(&__vapi_metadata_det44_get_timeouts_reply);
  VAPI_DBG("Assigned msg id %d to det44_get_timeouts_reply", vapi_msg_id_det44_get_timeouts_reply);
}

static inline void vapi_set_vapi_msg_det44_get_timeouts_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_det44_get_timeouts_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_det44_get_timeouts_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_det44_get_timeouts
#define defined_vapi_msg_det44_get_timeouts
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_det44_get_timeouts;

static inline void vapi_msg_det44_get_timeouts_hton(vapi_msg_det44_get_timeouts *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_get_timeouts'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_det44_get_timeouts_ntoh(vapi_msg_det44_get_timeouts *msg)
{
  VAPI_DBG("Swapping `vapi_msg_det44_get_timeouts'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_det44_get_timeouts_msg_size(vapi_msg_det44_get_timeouts *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_det44_get_timeouts_msg_size(vapi_msg_det44_get_timeouts *msg, uword buf_size)
{
  if (sizeof(vapi_msg_det44_get_timeouts) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_get_timeouts' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_det44_get_timeouts));
      return -1;
    }
  if (vapi_calc_det44_get_timeouts_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'det44_get_timeouts' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_det44_get_timeouts_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_det44_get_timeouts* vapi_alloc_det44_get_timeouts(struct vapi_ctx_s *ctx)
{
  vapi_msg_det44_get_timeouts *msg = NULL;
  const size_t size = sizeof(vapi_msg_det44_get_timeouts);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_det44_get_timeouts*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_det44_get_timeouts);

  return msg;
}

static inline vapi_error_e vapi_det44_get_timeouts(struct vapi_ctx_s *ctx,
  vapi_msg_det44_get_timeouts *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_det44_get_timeouts_reply *reply),
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
  vapi_msg_det44_get_timeouts_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_det44_get_timeouts_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_det44_get_timeouts_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_det44_get_timeouts()
{
  static const char name[] = "det44_get_timeouts";
  static const char name_with_crc[] = "det44_get_timeouts_51077d14";
  static vapi_message_desc_t __vapi_metadata_det44_get_timeouts = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_det44_get_timeouts_msg_size,
    (generic_swap_fn_t)vapi_msg_det44_get_timeouts_hton,
    (generic_swap_fn_t)vapi_msg_det44_get_timeouts_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_det44_get_timeouts = vapi_register_msg(&__vapi_metadata_det44_get_timeouts);
  VAPI_DBG("Assigned msg id %d to det44_get_timeouts", vapi_msg_id_det44_get_timeouts);
}
#endif

#ifndef defined_vapi_msg_nat_det_add_del_map_reply
#define defined_vapi_msg_nat_det_add_del_map_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat_det_add_del_map_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat_det_add_del_map_reply payload;
} vapi_msg_nat_det_add_del_map_reply;

static inline void vapi_msg_nat_det_add_del_map_reply_payload_hton(vapi_payload_nat_det_add_del_map_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat_det_add_del_map_reply_payload_ntoh(vapi_payload_nat_det_add_del_map_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat_det_add_del_map_reply_hton(vapi_msg_nat_det_add_del_map_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_add_del_map_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat_det_add_del_map_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat_det_add_del_map_reply_ntoh(vapi_msg_nat_det_add_del_map_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_add_del_map_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat_det_add_del_map_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat_det_add_del_map_reply_msg_size(vapi_msg_nat_det_add_del_map_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat_det_add_del_map_reply_msg_size(vapi_msg_nat_det_add_del_map_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat_det_add_del_map_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_add_del_map_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat_det_add_del_map_reply));
      return -1;
    }
  if (vapi_calc_nat_det_add_del_map_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_add_del_map_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat_det_add_del_map_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat_det_add_del_map_reply()
{
  static const char name[] = "nat_det_add_del_map_reply";
  static const char name_with_crc[] = "nat_det_add_del_map_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat_det_add_del_map_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat_det_add_del_map_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat_det_add_del_map_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat_det_add_del_map_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat_det_add_del_map_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat_det_add_del_map_reply = vapi_register_msg(&__vapi_metadata_nat_det_add_del_map_reply);
  VAPI_DBG("Assigned msg id %d to nat_det_add_del_map_reply", vapi_msg_id_nat_det_add_del_map_reply);
}

static inline void vapi_set_vapi_msg_nat_det_add_del_map_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat_det_add_del_map_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat_det_add_del_map_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat_det_add_del_map
#define defined_vapi_msg_nat_det_add_del_map
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_ip4_address in_addr;
  u8 in_plen;
  vapi_type_ip4_address out_addr;
  u8 out_plen; 
} vapi_payload_nat_det_add_del_map;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat_det_add_del_map payload;
} vapi_msg_nat_det_add_del_map;

static inline void vapi_msg_nat_det_add_del_map_payload_hton(vapi_payload_nat_det_add_del_map *payload)
{

}

static inline void vapi_msg_nat_det_add_del_map_payload_ntoh(vapi_payload_nat_det_add_del_map *payload)
{

}

static inline void vapi_msg_nat_det_add_del_map_hton(vapi_msg_nat_det_add_del_map *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_add_del_map'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat_det_add_del_map_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat_det_add_del_map_ntoh(vapi_msg_nat_det_add_del_map *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_add_del_map'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat_det_add_del_map_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat_det_add_del_map_msg_size(vapi_msg_nat_det_add_del_map *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat_det_add_del_map_msg_size(vapi_msg_nat_det_add_del_map *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat_det_add_del_map) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_add_del_map' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat_det_add_del_map));
      return -1;
    }
  if (vapi_calc_nat_det_add_del_map_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_add_del_map' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat_det_add_del_map_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat_det_add_del_map* vapi_alloc_nat_det_add_del_map(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat_det_add_del_map *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat_det_add_del_map);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat_det_add_del_map*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat_det_add_del_map);

  return msg;
}

static inline vapi_error_e vapi_nat_det_add_del_map(struct vapi_ctx_s *ctx,
  vapi_msg_nat_det_add_del_map *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat_det_add_del_map_reply *reply),
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
  vapi_msg_nat_det_add_del_map_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat_det_add_del_map_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_nat_det_add_del_map_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat_det_add_del_map()
{
  static const char name[] = "nat_det_add_del_map";
  static const char name_with_crc[] = "nat_det_add_del_map_1150a190";
  static vapi_message_desc_t __vapi_metadata_nat_det_add_del_map = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat_det_add_del_map, payload),
    (verify_msg_size_fn_t)vapi_verify_nat_det_add_del_map_msg_size,
    (generic_swap_fn_t)vapi_msg_nat_det_add_del_map_hton,
    (generic_swap_fn_t)vapi_msg_nat_det_add_del_map_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat_det_add_del_map = vapi_register_msg(&__vapi_metadata_nat_det_add_del_map);
  VAPI_DBG("Assigned msg id %d to nat_det_add_del_map", vapi_msg_id_nat_det_add_del_map);
}
#endif

#ifndef defined_vapi_msg_nat_det_forward_reply
#define defined_vapi_msg_nat_det_forward_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u16 out_port_lo;
  u16 out_port_hi;
  vapi_type_ip4_address out_addr; 
} vapi_payload_nat_det_forward_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat_det_forward_reply payload;
} vapi_msg_nat_det_forward_reply;

static inline void vapi_msg_nat_det_forward_reply_payload_hton(vapi_payload_nat_det_forward_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->out_port_lo = htobe16(payload->out_port_lo);
  payload->out_port_hi = htobe16(payload->out_port_hi);
}

static inline void vapi_msg_nat_det_forward_reply_payload_ntoh(vapi_payload_nat_det_forward_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->out_port_lo = be16toh(payload->out_port_lo);
  payload->out_port_hi = be16toh(payload->out_port_hi);
}

static inline void vapi_msg_nat_det_forward_reply_hton(vapi_msg_nat_det_forward_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_forward_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat_det_forward_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat_det_forward_reply_ntoh(vapi_msg_nat_det_forward_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_forward_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat_det_forward_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat_det_forward_reply_msg_size(vapi_msg_nat_det_forward_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat_det_forward_reply_msg_size(vapi_msg_nat_det_forward_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat_det_forward_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_forward_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat_det_forward_reply));
      return -1;
    }
  if (vapi_calc_nat_det_forward_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_forward_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat_det_forward_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat_det_forward_reply()
{
  static const char name[] = "nat_det_forward_reply";
  static const char name_with_crc[] = "nat_det_forward_reply_a8ccbdc0";
  static vapi_message_desc_t __vapi_metadata_nat_det_forward_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat_det_forward_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat_det_forward_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat_det_forward_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat_det_forward_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat_det_forward_reply = vapi_register_msg(&__vapi_metadata_nat_det_forward_reply);
  VAPI_DBG("Assigned msg id %d to nat_det_forward_reply", vapi_msg_id_nat_det_forward_reply);
}

static inline void vapi_set_vapi_msg_nat_det_forward_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat_det_forward_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat_det_forward_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat_det_forward
#define defined_vapi_msg_nat_det_forward
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address in_addr; 
} vapi_payload_nat_det_forward;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat_det_forward payload;
} vapi_msg_nat_det_forward;

static inline void vapi_msg_nat_det_forward_payload_hton(vapi_payload_nat_det_forward *payload)
{

}

static inline void vapi_msg_nat_det_forward_payload_ntoh(vapi_payload_nat_det_forward *payload)
{

}

static inline void vapi_msg_nat_det_forward_hton(vapi_msg_nat_det_forward *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_forward'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat_det_forward_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat_det_forward_ntoh(vapi_msg_nat_det_forward *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_forward'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat_det_forward_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat_det_forward_msg_size(vapi_msg_nat_det_forward *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat_det_forward_msg_size(vapi_msg_nat_det_forward *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat_det_forward) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_forward' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat_det_forward));
      return -1;
    }
  if (vapi_calc_nat_det_forward_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_forward' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat_det_forward_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat_det_forward* vapi_alloc_nat_det_forward(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat_det_forward *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat_det_forward);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat_det_forward*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat_det_forward);

  return msg;
}

static inline vapi_error_e vapi_nat_det_forward(struct vapi_ctx_s *ctx,
  vapi_msg_nat_det_forward *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat_det_forward_reply *reply),
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
  vapi_msg_nat_det_forward_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat_det_forward_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_nat_det_forward_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat_det_forward()
{
  static const char name[] = "nat_det_forward";
  static const char name_with_crc[] = "nat_det_forward_7f8a89cd";
  static vapi_message_desc_t __vapi_metadata_nat_det_forward = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat_det_forward, payload),
    (verify_msg_size_fn_t)vapi_verify_nat_det_forward_msg_size,
    (generic_swap_fn_t)vapi_msg_nat_det_forward_hton,
    (generic_swap_fn_t)vapi_msg_nat_det_forward_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat_det_forward = vapi_register_msg(&__vapi_metadata_nat_det_forward);
  VAPI_DBG("Assigned msg id %d to nat_det_forward", vapi_msg_id_nat_det_forward);
}
#endif

#ifndef defined_vapi_msg_nat_det_reverse_reply
#define defined_vapi_msg_nat_det_reverse_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_ip4_address in_addr; 
} vapi_payload_nat_det_reverse_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat_det_reverse_reply payload;
} vapi_msg_nat_det_reverse_reply;

static inline void vapi_msg_nat_det_reverse_reply_payload_hton(vapi_payload_nat_det_reverse_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat_det_reverse_reply_payload_ntoh(vapi_payload_nat_det_reverse_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat_det_reverse_reply_hton(vapi_msg_nat_det_reverse_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_reverse_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat_det_reverse_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat_det_reverse_reply_ntoh(vapi_msg_nat_det_reverse_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_reverse_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat_det_reverse_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat_det_reverse_reply_msg_size(vapi_msg_nat_det_reverse_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat_det_reverse_reply_msg_size(vapi_msg_nat_det_reverse_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat_det_reverse_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_reverse_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat_det_reverse_reply));
      return -1;
    }
  if (vapi_calc_nat_det_reverse_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_reverse_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat_det_reverse_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat_det_reverse_reply()
{
  static const char name[] = "nat_det_reverse_reply";
  static const char name_with_crc[] = "nat_det_reverse_reply_34066d48";
  static vapi_message_desc_t __vapi_metadata_nat_det_reverse_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat_det_reverse_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat_det_reverse_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat_det_reverse_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat_det_reverse_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat_det_reverse_reply = vapi_register_msg(&__vapi_metadata_nat_det_reverse_reply);
  VAPI_DBG("Assigned msg id %d to nat_det_reverse_reply", vapi_msg_id_nat_det_reverse_reply);
}

static inline void vapi_set_vapi_msg_nat_det_reverse_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat_det_reverse_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat_det_reverse_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat_det_reverse
#define defined_vapi_msg_nat_det_reverse
typedef struct __attribute__ ((__packed__)) {
  u16 out_port;
  vapi_type_ip4_address out_addr; 
} vapi_payload_nat_det_reverse;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat_det_reverse payload;
} vapi_msg_nat_det_reverse;

static inline void vapi_msg_nat_det_reverse_payload_hton(vapi_payload_nat_det_reverse *payload)
{
  payload->out_port = htobe16(payload->out_port);
}

static inline void vapi_msg_nat_det_reverse_payload_ntoh(vapi_payload_nat_det_reverse *payload)
{
  payload->out_port = be16toh(payload->out_port);
}

static inline void vapi_msg_nat_det_reverse_hton(vapi_msg_nat_det_reverse *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_reverse'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat_det_reverse_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat_det_reverse_ntoh(vapi_msg_nat_det_reverse *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_reverse'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat_det_reverse_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat_det_reverse_msg_size(vapi_msg_nat_det_reverse *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat_det_reverse_msg_size(vapi_msg_nat_det_reverse *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat_det_reverse) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_reverse' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat_det_reverse));
      return -1;
    }
  if (vapi_calc_nat_det_reverse_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_reverse' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat_det_reverse_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat_det_reverse* vapi_alloc_nat_det_reverse(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat_det_reverse *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat_det_reverse);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat_det_reverse*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat_det_reverse);

  return msg;
}

static inline vapi_error_e vapi_nat_det_reverse(struct vapi_ctx_s *ctx,
  vapi_msg_nat_det_reverse *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat_det_reverse_reply *reply),
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
  vapi_msg_nat_det_reverse_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat_det_reverse_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_nat_det_reverse_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat_det_reverse()
{
  static const char name[] = "nat_det_reverse";
  static const char name_with_crc[] = "nat_det_reverse_a7573fe1";
  static vapi_message_desc_t __vapi_metadata_nat_det_reverse = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat_det_reverse, payload),
    (verify_msg_size_fn_t)vapi_verify_nat_det_reverse_msg_size,
    (generic_swap_fn_t)vapi_msg_nat_det_reverse_hton,
    (generic_swap_fn_t)vapi_msg_nat_det_reverse_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat_det_reverse = vapi_register_msg(&__vapi_metadata_nat_det_reverse);
  VAPI_DBG("Assigned msg id %d to nat_det_reverse", vapi_msg_id_nat_det_reverse);
}
#endif

#ifndef defined_vapi_msg_nat_det_map_details
#define defined_vapi_msg_nat_det_map_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address in_addr;
  u8 in_plen;
  vapi_type_ip4_address out_addr;
  u8 out_plen;
  u32 sharing_ratio;
  u16 ports_per_host;
  u32 ses_num; 
} vapi_payload_nat_det_map_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat_det_map_details payload;
} vapi_msg_nat_det_map_details;

static inline void vapi_msg_nat_det_map_details_payload_hton(vapi_payload_nat_det_map_details *payload)
{
  payload->sharing_ratio = htobe32(payload->sharing_ratio);
  payload->ports_per_host = htobe16(payload->ports_per_host);
  payload->ses_num = htobe32(payload->ses_num);
}

static inline void vapi_msg_nat_det_map_details_payload_ntoh(vapi_payload_nat_det_map_details *payload)
{
  payload->sharing_ratio = be32toh(payload->sharing_ratio);
  payload->ports_per_host = be16toh(payload->ports_per_host);
  payload->ses_num = be32toh(payload->ses_num);
}

static inline void vapi_msg_nat_det_map_details_hton(vapi_msg_nat_det_map_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_map_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat_det_map_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat_det_map_details_ntoh(vapi_msg_nat_det_map_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_map_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat_det_map_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat_det_map_details_msg_size(vapi_msg_nat_det_map_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat_det_map_details_msg_size(vapi_msg_nat_det_map_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat_det_map_details) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_map_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat_det_map_details));
      return -1;
    }
  if (vapi_calc_nat_det_map_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_map_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat_det_map_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat_det_map_details()
{
  static const char name[] = "nat_det_map_details";
  static const char name_with_crc[] = "nat_det_map_details_ad91dc83";
  static vapi_message_desc_t __vapi_metadata_nat_det_map_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat_det_map_details, payload),
    (verify_msg_size_fn_t)vapi_verify_nat_det_map_details_msg_size,
    (generic_swap_fn_t)vapi_msg_nat_det_map_details_hton,
    (generic_swap_fn_t)vapi_msg_nat_det_map_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat_det_map_details = vapi_register_msg(&__vapi_metadata_nat_det_map_details);
  VAPI_DBG("Assigned msg id %d to nat_det_map_details", vapi_msg_id_nat_det_map_details);
}

static inline void vapi_set_vapi_msg_nat_det_map_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat_det_map_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat_det_map_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat_det_map_dump
#define defined_vapi_msg_nat_det_map_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_nat_det_map_dump;

static inline void vapi_msg_nat_det_map_dump_hton(vapi_msg_nat_det_map_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_map_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_nat_det_map_dump_ntoh(vapi_msg_nat_det_map_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_map_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_nat_det_map_dump_msg_size(vapi_msg_nat_det_map_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat_det_map_dump_msg_size(vapi_msg_nat_det_map_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat_det_map_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_map_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat_det_map_dump));
      return -1;
    }
  if (vapi_calc_nat_det_map_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_map_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat_det_map_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat_det_map_dump* vapi_alloc_nat_det_map_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat_det_map_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat_det_map_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat_det_map_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat_det_map_dump);

  return msg;
}

static inline vapi_error_e vapi_nat_det_map_dump(struct vapi_ctx_s *ctx,
  vapi_msg_nat_det_map_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat_det_map_details *reply),
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
  vapi_msg_nat_det_map_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat_det_map_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_nat_det_map_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat_det_map_dump()
{
  static const char name[] = "nat_det_map_dump";
  static const char name_with_crc[] = "nat_det_map_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_nat_det_map_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_nat_det_map_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_nat_det_map_dump_hton,
    (generic_swap_fn_t)vapi_msg_nat_det_map_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat_det_map_dump = vapi_register_msg(&__vapi_metadata_nat_det_map_dump);
  VAPI_DBG("Assigned msg id %d to nat_det_map_dump", vapi_msg_id_nat_det_map_dump);
}
#endif

#ifndef defined_vapi_msg_nat_det_close_session_out_reply
#define defined_vapi_msg_nat_det_close_session_out_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat_det_close_session_out_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat_det_close_session_out_reply payload;
} vapi_msg_nat_det_close_session_out_reply;

static inline void vapi_msg_nat_det_close_session_out_reply_payload_hton(vapi_payload_nat_det_close_session_out_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat_det_close_session_out_reply_payload_ntoh(vapi_payload_nat_det_close_session_out_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat_det_close_session_out_reply_hton(vapi_msg_nat_det_close_session_out_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_close_session_out_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat_det_close_session_out_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat_det_close_session_out_reply_ntoh(vapi_msg_nat_det_close_session_out_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_close_session_out_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat_det_close_session_out_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat_det_close_session_out_reply_msg_size(vapi_msg_nat_det_close_session_out_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat_det_close_session_out_reply_msg_size(vapi_msg_nat_det_close_session_out_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat_det_close_session_out_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_close_session_out_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat_det_close_session_out_reply));
      return -1;
    }
  if (vapi_calc_nat_det_close_session_out_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_close_session_out_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat_det_close_session_out_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat_det_close_session_out_reply()
{
  static const char name[] = "nat_det_close_session_out_reply";
  static const char name_with_crc[] = "nat_det_close_session_out_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat_det_close_session_out_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat_det_close_session_out_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat_det_close_session_out_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat_det_close_session_out_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat_det_close_session_out_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat_det_close_session_out_reply = vapi_register_msg(&__vapi_metadata_nat_det_close_session_out_reply);
  VAPI_DBG("Assigned msg id %d to nat_det_close_session_out_reply", vapi_msg_id_nat_det_close_session_out_reply);
}

static inline void vapi_set_vapi_msg_nat_det_close_session_out_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat_det_close_session_out_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat_det_close_session_out_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat_det_close_session_out
#define defined_vapi_msg_nat_det_close_session_out
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address out_addr;
  u16 out_port;
  vapi_type_ip4_address ext_addr;
  u16 ext_port; 
} vapi_payload_nat_det_close_session_out;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat_det_close_session_out payload;
} vapi_msg_nat_det_close_session_out;

static inline void vapi_msg_nat_det_close_session_out_payload_hton(vapi_payload_nat_det_close_session_out *payload)
{
  payload->out_port = htobe16(payload->out_port);
  payload->ext_port = htobe16(payload->ext_port);
}

static inline void vapi_msg_nat_det_close_session_out_payload_ntoh(vapi_payload_nat_det_close_session_out *payload)
{
  payload->out_port = be16toh(payload->out_port);
  payload->ext_port = be16toh(payload->ext_port);
}

static inline void vapi_msg_nat_det_close_session_out_hton(vapi_msg_nat_det_close_session_out *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_close_session_out'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat_det_close_session_out_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat_det_close_session_out_ntoh(vapi_msg_nat_det_close_session_out *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_close_session_out'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat_det_close_session_out_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat_det_close_session_out_msg_size(vapi_msg_nat_det_close_session_out *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat_det_close_session_out_msg_size(vapi_msg_nat_det_close_session_out *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat_det_close_session_out) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_close_session_out' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat_det_close_session_out));
      return -1;
    }
  if (vapi_calc_nat_det_close_session_out_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_close_session_out' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat_det_close_session_out_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat_det_close_session_out* vapi_alloc_nat_det_close_session_out(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat_det_close_session_out *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat_det_close_session_out);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat_det_close_session_out*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat_det_close_session_out);

  return msg;
}

static inline vapi_error_e vapi_nat_det_close_session_out(struct vapi_ctx_s *ctx,
  vapi_msg_nat_det_close_session_out *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat_det_close_session_out_reply *reply),
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
  vapi_msg_nat_det_close_session_out_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat_det_close_session_out_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_nat_det_close_session_out_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat_det_close_session_out()
{
  static const char name[] = "nat_det_close_session_out";
  static const char name_with_crc[] = "nat_det_close_session_out_f6b259d1";
  static vapi_message_desc_t __vapi_metadata_nat_det_close_session_out = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat_det_close_session_out, payload),
    (verify_msg_size_fn_t)vapi_verify_nat_det_close_session_out_msg_size,
    (generic_swap_fn_t)vapi_msg_nat_det_close_session_out_hton,
    (generic_swap_fn_t)vapi_msg_nat_det_close_session_out_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat_det_close_session_out = vapi_register_msg(&__vapi_metadata_nat_det_close_session_out);
  VAPI_DBG("Assigned msg id %d to nat_det_close_session_out", vapi_msg_id_nat_det_close_session_out);
}
#endif

#ifndef defined_vapi_msg_nat_det_close_session_in_reply
#define defined_vapi_msg_nat_det_close_session_in_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nat_det_close_session_in_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat_det_close_session_in_reply payload;
} vapi_msg_nat_det_close_session_in_reply;

static inline void vapi_msg_nat_det_close_session_in_reply_payload_hton(vapi_payload_nat_det_close_session_in_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nat_det_close_session_in_reply_payload_ntoh(vapi_payload_nat_det_close_session_in_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nat_det_close_session_in_reply_hton(vapi_msg_nat_det_close_session_in_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_close_session_in_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat_det_close_session_in_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat_det_close_session_in_reply_ntoh(vapi_msg_nat_det_close_session_in_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_close_session_in_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat_det_close_session_in_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat_det_close_session_in_reply_msg_size(vapi_msg_nat_det_close_session_in_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat_det_close_session_in_reply_msg_size(vapi_msg_nat_det_close_session_in_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat_det_close_session_in_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_close_session_in_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat_det_close_session_in_reply));
      return -1;
    }
  if (vapi_calc_nat_det_close_session_in_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_close_session_in_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat_det_close_session_in_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat_det_close_session_in_reply()
{
  static const char name[] = "nat_det_close_session_in_reply";
  static const char name_with_crc[] = "nat_det_close_session_in_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nat_det_close_session_in_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat_det_close_session_in_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nat_det_close_session_in_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nat_det_close_session_in_reply_hton,
    (generic_swap_fn_t)vapi_msg_nat_det_close_session_in_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat_det_close_session_in_reply = vapi_register_msg(&__vapi_metadata_nat_det_close_session_in_reply);
  VAPI_DBG("Assigned msg id %d to nat_det_close_session_in_reply", vapi_msg_id_nat_det_close_session_in_reply);
}

static inline void vapi_set_vapi_msg_nat_det_close_session_in_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat_det_close_session_in_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat_det_close_session_in_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat_det_close_session_in
#define defined_vapi_msg_nat_det_close_session_in
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address in_addr;
  u16 in_port;
  vapi_type_ip4_address ext_addr;
  u16 ext_port; 
} vapi_payload_nat_det_close_session_in;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat_det_close_session_in payload;
} vapi_msg_nat_det_close_session_in;

static inline void vapi_msg_nat_det_close_session_in_payload_hton(vapi_payload_nat_det_close_session_in *payload)
{
  payload->in_port = htobe16(payload->in_port);
  payload->ext_port = htobe16(payload->ext_port);
}

static inline void vapi_msg_nat_det_close_session_in_payload_ntoh(vapi_payload_nat_det_close_session_in *payload)
{
  payload->in_port = be16toh(payload->in_port);
  payload->ext_port = be16toh(payload->ext_port);
}

static inline void vapi_msg_nat_det_close_session_in_hton(vapi_msg_nat_det_close_session_in *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_close_session_in'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat_det_close_session_in_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat_det_close_session_in_ntoh(vapi_msg_nat_det_close_session_in *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_close_session_in'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat_det_close_session_in_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat_det_close_session_in_msg_size(vapi_msg_nat_det_close_session_in *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat_det_close_session_in_msg_size(vapi_msg_nat_det_close_session_in *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat_det_close_session_in) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_close_session_in' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat_det_close_session_in));
      return -1;
    }
  if (vapi_calc_nat_det_close_session_in_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_close_session_in' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat_det_close_session_in_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat_det_close_session_in* vapi_alloc_nat_det_close_session_in(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat_det_close_session_in *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat_det_close_session_in);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat_det_close_session_in*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat_det_close_session_in);

  return msg;
}

static inline vapi_error_e vapi_nat_det_close_session_in(struct vapi_ctx_s *ctx,
  vapi_msg_nat_det_close_session_in *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat_det_close_session_in_reply *reply),
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
  vapi_msg_nat_det_close_session_in_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat_det_close_session_in_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_nat_det_close_session_in_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat_det_close_session_in()
{
  static const char name[] = "nat_det_close_session_in";
  static const char name_with_crc[] = "nat_det_close_session_in_3c68e073";
  static vapi_message_desc_t __vapi_metadata_nat_det_close_session_in = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat_det_close_session_in, payload),
    (verify_msg_size_fn_t)vapi_verify_nat_det_close_session_in_msg_size,
    (generic_swap_fn_t)vapi_msg_nat_det_close_session_in_hton,
    (generic_swap_fn_t)vapi_msg_nat_det_close_session_in_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat_det_close_session_in = vapi_register_msg(&__vapi_metadata_nat_det_close_session_in);
  VAPI_DBG("Assigned msg id %d to nat_det_close_session_in", vapi_msg_id_nat_det_close_session_in);
}
#endif

#ifndef defined_vapi_msg_nat_det_session_details
#define defined_vapi_msg_nat_det_session_details
typedef struct __attribute__ ((__packed__)) {
  u16 in_port;
  vapi_type_ip4_address ext_addr;
  u16 ext_port;
  u16 out_port;
  u8 state;
  u32 expire; 
} vapi_payload_nat_det_session_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nat_det_session_details payload;
} vapi_msg_nat_det_session_details;

static inline void vapi_msg_nat_det_session_details_payload_hton(vapi_payload_nat_det_session_details *payload)
{
  payload->in_port = htobe16(payload->in_port);
  payload->ext_port = htobe16(payload->ext_port);
  payload->out_port = htobe16(payload->out_port);
  payload->expire = htobe32(payload->expire);
}

static inline void vapi_msg_nat_det_session_details_payload_ntoh(vapi_payload_nat_det_session_details *payload)
{
  payload->in_port = be16toh(payload->in_port);
  payload->ext_port = be16toh(payload->ext_port);
  payload->out_port = be16toh(payload->out_port);
  payload->expire = be32toh(payload->expire);
}

static inline void vapi_msg_nat_det_session_details_hton(vapi_msg_nat_det_session_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_session_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nat_det_session_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat_det_session_details_ntoh(vapi_msg_nat_det_session_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_session_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nat_det_session_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat_det_session_details_msg_size(vapi_msg_nat_det_session_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat_det_session_details_msg_size(vapi_msg_nat_det_session_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat_det_session_details) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_session_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat_det_session_details));
      return -1;
    }
  if (vapi_calc_nat_det_session_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_session_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat_det_session_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nat_det_session_details()
{
  static const char name[] = "nat_det_session_details";
  static const char name_with_crc[] = "nat_det_session_details_27f3c171";
  static vapi_message_desc_t __vapi_metadata_nat_det_session_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nat_det_session_details, payload),
    (verify_msg_size_fn_t)vapi_verify_nat_det_session_details_msg_size,
    (generic_swap_fn_t)vapi_msg_nat_det_session_details_hton,
    (generic_swap_fn_t)vapi_msg_nat_det_session_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat_det_session_details = vapi_register_msg(&__vapi_metadata_nat_det_session_details);
  VAPI_DBG("Assigned msg id %d to nat_det_session_details", vapi_msg_id_nat_det_session_details);
}

static inline void vapi_set_vapi_msg_nat_det_session_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nat_det_session_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nat_det_session_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nat_det_session_dump
#define defined_vapi_msg_nat_det_session_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address user_addr; 
} vapi_payload_nat_det_session_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nat_det_session_dump payload;
} vapi_msg_nat_det_session_dump;

static inline void vapi_msg_nat_det_session_dump_payload_hton(vapi_payload_nat_det_session_dump *payload)
{

}

static inline void vapi_msg_nat_det_session_dump_payload_ntoh(vapi_payload_nat_det_session_dump *payload)
{

}

static inline void vapi_msg_nat_det_session_dump_hton(vapi_msg_nat_det_session_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_session_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nat_det_session_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_nat_det_session_dump_ntoh(vapi_msg_nat_det_session_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nat_det_session_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nat_det_session_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nat_det_session_dump_msg_size(vapi_msg_nat_det_session_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nat_det_session_dump_msg_size(vapi_msg_nat_det_session_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nat_det_session_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_session_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nat_det_session_dump));
      return -1;
    }
  if (vapi_calc_nat_det_session_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nat_det_session_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nat_det_session_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nat_det_session_dump* vapi_alloc_nat_det_session_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_nat_det_session_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_nat_det_session_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nat_det_session_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nat_det_session_dump);

  return msg;
}

static inline vapi_error_e vapi_nat_det_session_dump(struct vapi_ctx_s *ctx,
  vapi_msg_nat_det_session_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nat_det_session_details *reply),
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
  vapi_msg_nat_det_session_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nat_det_session_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_nat_det_session_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nat_det_session_dump()
{
  static const char name[] = "nat_det_session_dump";
  static const char name_with_crc[] = "nat_det_session_dump_e45a3af7";
  static vapi_message_desc_t __vapi_metadata_nat_det_session_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nat_det_session_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_nat_det_session_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_nat_det_session_dump_hton,
    (generic_swap_fn_t)vapi_msg_nat_det_session_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nat_det_session_dump = vapi_register_msg(&__vapi_metadata_nat_det_session_dump);
  VAPI_DBG("Assigned msg id %d to nat_det_session_dump", vapi_msg_id_nat_det_session_dump);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
