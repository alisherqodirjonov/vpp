#ifndef __included_ip6_nd_api_json
#define __included_ip6_nd_api_json

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

extern vapi_msg_id_t vapi_msg_id_sw_interface_ip6nd_ra_config;
extern vapi_msg_id_t vapi_msg_id_sw_interface_ip6nd_ra_config_reply;
extern vapi_msg_id_t vapi_msg_id_sw_interface_ip6nd_ra_prefix;
extern vapi_msg_id_t vapi_msg_id_sw_interface_ip6nd_ra_prefix_reply;
extern vapi_msg_id_t vapi_msg_id_sw_interface_ip6nd_ra_dump;
extern vapi_msg_id_t vapi_msg_id_sw_interface_ip6nd_ra_details;
extern vapi_msg_id_t vapi_msg_id_ip6nd_proxy_enable_disable;
extern vapi_msg_id_t vapi_msg_id_ip6nd_proxy_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_ip6nd_proxy_add_del;
extern vapi_msg_id_t vapi_msg_id_ip6nd_proxy_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_ip6nd_proxy_details;
extern vapi_msg_id_t vapi_msg_id_ip6nd_proxy_dump;
extern vapi_msg_id_t vapi_msg_id_ip6nd_send_router_solicitation;
extern vapi_msg_id_t vapi_msg_id_ip6nd_send_router_solicitation_reply;
extern vapi_msg_id_t vapi_msg_id_want_ip6_ra_events;
extern vapi_msg_id_t vapi_msg_id_want_ip6_ra_events_reply;
extern vapi_msg_id_t vapi_msg_id_ip6_ra_event;

#define DEFINE_VAPI_MSG_IDS_IP6_ND_API_JSON\
  vapi_msg_id_t vapi_msg_id_sw_interface_ip6nd_ra_config;\
  vapi_msg_id_t vapi_msg_id_sw_interface_ip6nd_ra_config_reply;\
  vapi_msg_id_t vapi_msg_id_sw_interface_ip6nd_ra_prefix;\
  vapi_msg_id_t vapi_msg_id_sw_interface_ip6nd_ra_prefix_reply;\
  vapi_msg_id_t vapi_msg_id_sw_interface_ip6nd_ra_dump;\
  vapi_msg_id_t vapi_msg_id_sw_interface_ip6nd_ra_details;\
  vapi_msg_id_t vapi_msg_id_ip6nd_proxy_enable_disable;\
  vapi_msg_id_t vapi_msg_id_ip6nd_proxy_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_ip6nd_proxy_add_del;\
  vapi_msg_id_t vapi_msg_id_ip6nd_proxy_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_ip6nd_proxy_details;\
  vapi_msg_id_t vapi_msg_id_ip6nd_proxy_dump;\
  vapi_msg_id_t vapi_msg_id_ip6nd_send_router_solicitation;\
  vapi_msg_id_t vapi_msg_id_ip6nd_send_router_solicitation_reply;\
  vapi_msg_id_t vapi_msg_id_want_ip6_ra_events;\
  vapi_msg_id_t vapi_msg_id_want_ip6_ra_events_reply;\
  vapi_msg_id_t vapi_msg_id_ip6_ra_event;


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

#ifndef defined_vapi_type_ip6nd_ra_prefix
#define defined_vapi_type_ip6nd_ra_prefix
typedef struct __attribute__((__packed__)) {
  vapi_type_prefix prefix;
  bool onlink_flag;
  bool autonomous_flag;
  u32 val_lifetime;
  u32 pref_lifetime;
  f64 valid_lifetime_expires;
  f64 pref_lifetime_expires;
  bool decrement_lifetime_flag;
  bool no_advertise;
} vapi_type_ip6nd_ra_prefix;

static inline void vapi_type_ip6nd_ra_prefix_hton(vapi_type_ip6nd_ra_prefix *msg)
{
  msg->val_lifetime = htobe32(msg->val_lifetime);
  msg->pref_lifetime = htobe32(msg->pref_lifetime);
}

static inline void vapi_type_ip6nd_ra_prefix_ntoh(vapi_type_ip6nd_ra_prefix *msg)
{
  msg->val_lifetime = be32toh(msg->val_lifetime);
  msg->pref_lifetime = be32toh(msg->pref_lifetime);
}
#endif

#ifndef defined_vapi_type_ip6_ra_prefix_info
#define defined_vapi_type_ip6_ra_prefix_info
typedef struct __attribute__((__packed__)) {
  vapi_type_prefix prefix;
  u8 flags;
  u32 valid_time;
  u32 preferred_time;
} vapi_type_ip6_ra_prefix_info;

static inline void vapi_type_ip6_ra_prefix_info_hton(vapi_type_ip6_ra_prefix_info *msg)
{
  msg->valid_time = htobe32(msg->valid_time);
  msg->preferred_time = htobe32(msg->preferred_time);
}

static inline void vapi_type_ip6_ra_prefix_info_ntoh(vapi_type_ip6_ra_prefix_info *msg)
{
  msg->valid_time = be32toh(msg->valid_time);
  msg->preferred_time = be32toh(msg->preferred_time);
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

#ifndef defined_vapi_msg_sw_interface_ip6nd_ra_config_reply
#define defined_vapi_msg_sw_interface_ip6nd_ra_config_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_sw_interface_ip6nd_ra_config_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sw_interface_ip6nd_ra_config_reply payload;
} vapi_msg_sw_interface_ip6nd_ra_config_reply;

static inline void vapi_msg_sw_interface_ip6nd_ra_config_reply_payload_hton(vapi_payload_sw_interface_ip6nd_ra_config_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_sw_interface_ip6nd_ra_config_reply_payload_ntoh(vapi_payload_sw_interface_ip6nd_ra_config_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_sw_interface_ip6nd_ra_config_reply_hton(vapi_msg_sw_interface_ip6nd_ra_config_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6nd_ra_config_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sw_interface_ip6nd_ra_config_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_ip6nd_ra_config_reply_ntoh(vapi_msg_sw_interface_ip6nd_ra_config_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6nd_ra_config_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sw_interface_ip6nd_ra_config_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_ip6nd_ra_config_reply_msg_size(vapi_msg_sw_interface_ip6nd_ra_config_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_ip6nd_ra_config_reply_msg_size(vapi_msg_sw_interface_ip6nd_ra_config_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_ip6nd_ra_config_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6nd_ra_config_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_ip6nd_ra_config_reply));
      return -1;
    }
  if (vapi_calc_sw_interface_ip6nd_ra_config_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6nd_ra_config_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_ip6nd_ra_config_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sw_interface_ip6nd_ra_config_reply()
{
  static const char name[] = "sw_interface_ip6nd_ra_config_reply";
  static const char name_with_crc[] = "sw_interface_ip6nd_ra_config_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_sw_interface_ip6nd_ra_config_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sw_interface_ip6nd_ra_config_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_ip6nd_ra_config_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6nd_ra_config_reply_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6nd_ra_config_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_ip6nd_ra_config_reply = vapi_register_msg(&__vapi_metadata_sw_interface_ip6nd_ra_config_reply);
  VAPI_DBG("Assigned msg id %d to sw_interface_ip6nd_ra_config_reply", vapi_msg_id_sw_interface_ip6nd_ra_config_reply);
}

static inline void vapi_set_vapi_msg_sw_interface_ip6nd_ra_config_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sw_interface_ip6nd_ra_config_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sw_interface_ip6nd_ra_config_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sw_interface_ip6nd_ra_config
#define defined_vapi_msg_sw_interface_ip6nd_ra_config
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u8 suppress;
  u8 managed;
  u8 other;
  u8 ll_option;
  u8 send_unicast;
  u8 cease;
  bool is_no;
  u8 default_router;
  u32 max_interval;
  u32 min_interval;
  u32 lifetime;
  u32 initial_count;
  u32 initial_interval; 
} vapi_payload_sw_interface_ip6nd_ra_config;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sw_interface_ip6nd_ra_config payload;
} vapi_msg_sw_interface_ip6nd_ra_config;

static inline void vapi_msg_sw_interface_ip6nd_ra_config_payload_hton(vapi_payload_sw_interface_ip6nd_ra_config *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->max_interval = htobe32(payload->max_interval);
  payload->min_interval = htobe32(payload->min_interval);
  payload->lifetime = htobe32(payload->lifetime);
  payload->initial_count = htobe32(payload->initial_count);
  payload->initial_interval = htobe32(payload->initial_interval);
}

static inline void vapi_msg_sw_interface_ip6nd_ra_config_payload_ntoh(vapi_payload_sw_interface_ip6nd_ra_config *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->max_interval = be32toh(payload->max_interval);
  payload->min_interval = be32toh(payload->min_interval);
  payload->lifetime = be32toh(payload->lifetime);
  payload->initial_count = be32toh(payload->initial_count);
  payload->initial_interval = be32toh(payload->initial_interval);
}

static inline void vapi_msg_sw_interface_ip6nd_ra_config_hton(vapi_msg_sw_interface_ip6nd_ra_config *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6nd_ra_config'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sw_interface_ip6nd_ra_config_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_ip6nd_ra_config_ntoh(vapi_msg_sw_interface_ip6nd_ra_config *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6nd_ra_config'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sw_interface_ip6nd_ra_config_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_ip6nd_ra_config_msg_size(vapi_msg_sw_interface_ip6nd_ra_config *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_ip6nd_ra_config_msg_size(vapi_msg_sw_interface_ip6nd_ra_config *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_ip6nd_ra_config) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6nd_ra_config' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_ip6nd_ra_config));
      return -1;
    }
  if (vapi_calc_sw_interface_ip6nd_ra_config_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6nd_ra_config' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_ip6nd_ra_config_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sw_interface_ip6nd_ra_config* vapi_alloc_sw_interface_ip6nd_ra_config(struct vapi_ctx_s *ctx)
{
  vapi_msg_sw_interface_ip6nd_ra_config *msg = NULL;
  const size_t size = sizeof(vapi_msg_sw_interface_ip6nd_ra_config);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sw_interface_ip6nd_ra_config*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sw_interface_ip6nd_ra_config);

  return msg;
}

static inline vapi_error_e vapi_sw_interface_ip6nd_ra_config(struct vapi_ctx_s *ctx,
  vapi_msg_sw_interface_ip6nd_ra_config *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sw_interface_ip6nd_ra_config_reply *reply),
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
  vapi_msg_sw_interface_ip6nd_ra_config_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sw_interface_ip6nd_ra_config_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sw_interface_ip6nd_ra_config_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sw_interface_ip6nd_ra_config()
{
  static const char name[] = "sw_interface_ip6nd_ra_config";
  static const char name_with_crc[] = "sw_interface_ip6nd_ra_config_3eb00b1c";
  static vapi_message_desc_t __vapi_metadata_sw_interface_ip6nd_ra_config = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sw_interface_ip6nd_ra_config, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_ip6nd_ra_config_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6nd_ra_config_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6nd_ra_config_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_ip6nd_ra_config = vapi_register_msg(&__vapi_metadata_sw_interface_ip6nd_ra_config);
  VAPI_DBG("Assigned msg id %d to sw_interface_ip6nd_ra_config", vapi_msg_id_sw_interface_ip6nd_ra_config);
}
#endif

#ifndef defined_vapi_msg_sw_interface_ip6nd_ra_prefix_reply
#define defined_vapi_msg_sw_interface_ip6nd_ra_prefix_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_sw_interface_ip6nd_ra_prefix_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sw_interface_ip6nd_ra_prefix_reply payload;
} vapi_msg_sw_interface_ip6nd_ra_prefix_reply;

static inline void vapi_msg_sw_interface_ip6nd_ra_prefix_reply_payload_hton(vapi_payload_sw_interface_ip6nd_ra_prefix_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_sw_interface_ip6nd_ra_prefix_reply_payload_ntoh(vapi_payload_sw_interface_ip6nd_ra_prefix_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_sw_interface_ip6nd_ra_prefix_reply_hton(vapi_msg_sw_interface_ip6nd_ra_prefix_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6nd_ra_prefix_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sw_interface_ip6nd_ra_prefix_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_ip6nd_ra_prefix_reply_ntoh(vapi_msg_sw_interface_ip6nd_ra_prefix_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6nd_ra_prefix_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sw_interface_ip6nd_ra_prefix_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_ip6nd_ra_prefix_reply_msg_size(vapi_msg_sw_interface_ip6nd_ra_prefix_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_ip6nd_ra_prefix_reply_msg_size(vapi_msg_sw_interface_ip6nd_ra_prefix_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_ip6nd_ra_prefix_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6nd_ra_prefix_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_ip6nd_ra_prefix_reply));
      return -1;
    }
  if (vapi_calc_sw_interface_ip6nd_ra_prefix_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6nd_ra_prefix_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_ip6nd_ra_prefix_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sw_interface_ip6nd_ra_prefix_reply()
{
  static const char name[] = "sw_interface_ip6nd_ra_prefix_reply";
  static const char name_with_crc[] = "sw_interface_ip6nd_ra_prefix_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_sw_interface_ip6nd_ra_prefix_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sw_interface_ip6nd_ra_prefix_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_ip6nd_ra_prefix_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6nd_ra_prefix_reply_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6nd_ra_prefix_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_ip6nd_ra_prefix_reply = vapi_register_msg(&__vapi_metadata_sw_interface_ip6nd_ra_prefix_reply);
  VAPI_DBG("Assigned msg id %d to sw_interface_ip6nd_ra_prefix_reply", vapi_msg_id_sw_interface_ip6nd_ra_prefix_reply);
}

static inline void vapi_set_vapi_msg_sw_interface_ip6nd_ra_prefix_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sw_interface_ip6nd_ra_prefix_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sw_interface_ip6nd_ra_prefix_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sw_interface_ip6nd_ra_prefix
#define defined_vapi_msg_sw_interface_ip6nd_ra_prefix
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_type_prefix prefix;
  bool use_default;
  bool no_advertise;
  bool off_link;
  bool no_autoconfig;
  bool no_onlink;
  bool is_no;
  u32 val_lifetime;
  u32 pref_lifetime; 
} vapi_payload_sw_interface_ip6nd_ra_prefix;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sw_interface_ip6nd_ra_prefix payload;
} vapi_msg_sw_interface_ip6nd_ra_prefix;

static inline void vapi_msg_sw_interface_ip6nd_ra_prefix_payload_hton(vapi_payload_sw_interface_ip6nd_ra_prefix *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->val_lifetime = htobe32(payload->val_lifetime);
  payload->pref_lifetime = htobe32(payload->pref_lifetime);
}

static inline void vapi_msg_sw_interface_ip6nd_ra_prefix_payload_ntoh(vapi_payload_sw_interface_ip6nd_ra_prefix *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->val_lifetime = be32toh(payload->val_lifetime);
  payload->pref_lifetime = be32toh(payload->pref_lifetime);
}

static inline void vapi_msg_sw_interface_ip6nd_ra_prefix_hton(vapi_msg_sw_interface_ip6nd_ra_prefix *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6nd_ra_prefix'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sw_interface_ip6nd_ra_prefix_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_ip6nd_ra_prefix_ntoh(vapi_msg_sw_interface_ip6nd_ra_prefix *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6nd_ra_prefix'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sw_interface_ip6nd_ra_prefix_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_ip6nd_ra_prefix_msg_size(vapi_msg_sw_interface_ip6nd_ra_prefix *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_ip6nd_ra_prefix_msg_size(vapi_msg_sw_interface_ip6nd_ra_prefix *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_ip6nd_ra_prefix) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6nd_ra_prefix' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_ip6nd_ra_prefix));
      return -1;
    }
  if (vapi_calc_sw_interface_ip6nd_ra_prefix_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6nd_ra_prefix' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_ip6nd_ra_prefix_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sw_interface_ip6nd_ra_prefix* vapi_alloc_sw_interface_ip6nd_ra_prefix(struct vapi_ctx_s *ctx)
{
  vapi_msg_sw_interface_ip6nd_ra_prefix *msg = NULL;
  const size_t size = sizeof(vapi_msg_sw_interface_ip6nd_ra_prefix);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sw_interface_ip6nd_ra_prefix*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sw_interface_ip6nd_ra_prefix);

  return msg;
}

static inline vapi_error_e vapi_sw_interface_ip6nd_ra_prefix(struct vapi_ctx_s *ctx,
  vapi_msg_sw_interface_ip6nd_ra_prefix *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sw_interface_ip6nd_ra_prefix_reply *reply),
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
  vapi_msg_sw_interface_ip6nd_ra_prefix_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sw_interface_ip6nd_ra_prefix_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sw_interface_ip6nd_ra_prefix_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sw_interface_ip6nd_ra_prefix()
{
  static const char name[] = "sw_interface_ip6nd_ra_prefix";
  static const char name_with_crc[] = "sw_interface_ip6nd_ra_prefix_82cc1b28";
  static vapi_message_desc_t __vapi_metadata_sw_interface_ip6nd_ra_prefix = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sw_interface_ip6nd_ra_prefix, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_ip6nd_ra_prefix_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6nd_ra_prefix_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6nd_ra_prefix_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_ip6nd_ra_prefix = vapi_register_msg(&__vapi_metadata_sw_interface_ip6nd_ra_prefix);
  VAPI_DBG("Assigned msg id %d to sw_interface_ip6nd_ra_prefix", vapi_msg_id_sw_interface_ip6nd_ra_prefix);
}
#endif

#ifndef defined_vapi_msg_sw_interface_ip6nd_ra_details
#define defined_vapi_msg_sw_interface_ip6nd_ra_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u8 cur_hop_limit;
  bool adv_managed_flag;
  bool adv_other_flag;
  u16 adv_router_lifetime;
  u32 adv_neighbor_reachable_time;
  u32 adv_retransmit_interval;
  u32 adv_link_mtu;
  bool send_radv;
  bool cease_radv;
  bool send_unicast;
  bool adv_link_layer_address;
  f64 max_radv_interval;
  f64 min_radv_interval;
  f64 last_radv_time;
  f64 last_multicast_time;
  f64 next_multicast_time;
  u32 initial_adverts_count;
  f64 initial_adverts_interval;
  bool initial_adverts_sent;
  u32 n_advertisements_sent;
  u32 n_solicitations_rcvd;
  u32 n_solicitations_dropped;
  u32 n_prefixes;
  vapi_type_ip6nd_ra_prefix prefixes[0]; 
} vapi_payload_sw_interface_ip6nd_ra_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sw_interface_ip6nd_ra_details payload;
} vapi_msg_sw_interface_ip6nd_ra_details;

static inline void vapi_msg_sw_interface_ip6nd_ra_details_payload_hton(vapi_payload_sw_interface_ip6nd_ra_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->adv_router_lifetime = htobe16(payload->adv_router_lifetime);
  payload->adv_neighbor_reachable_time = htobe32(payload->adv_neighbor_reachable_time);
  payload->adv_retransmit_interval = htobe32(payload->adv_retransmit_interval);
  payload->adv_link_mtu = htobe32(payload->adv_link_mtu);
  payload->initial_adverts_count = htobe32(payload->initial_adverts_count);
  payload->n_advertisements_sent = htobe32(payload->n_advertisements_sent);
  payload->n_solicitations_rcvd = htobe32(payload->n_solicitations_rcvd);
  payload->n_solicitations_dropped = htobe32(payload->n_solicitations_dropped);
  payload->n_prefixes = htobe32(payload->n_prefixes);
  do { unsigned i; for (i = 0; i < be32toh(payload->n_prefixes); ++i) { vapi_type_ip6nd_ra_prefix_hton(&payload->prefixes[i]); } } while(0);
}

static inline void vapi_msg_sw_interface_ip6nd_ra_details_payload_ntoh(vapi_payload_sw_interface_ip6nd_ra_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->adv_router_lifetime = be16toh(payload->adv_router_lifetime);
  payload->adv_neighbor_reachable_time = be32toh(payload->adv_neighbor_reachable_time);
  payload->adv_retransmit_interval = be32toh(payload->adv_retransmit_interval);
  payload->adv_link_mtu = be32toh(payload->adv_link_mtu);
  payload->initial_adverts_count = be32toh(payload->initial_adverts_count);
  payload->n_advertisements_sent = be32toh(payload->n_advertisements_sent);
  payload->n_solicitations_rcvd = be32toh(payload->n_solicitations_rcvd);
  payload->n_solicitations_dropped = be32toh(payload->n_solicitations_dropped);
  payload->n_prefixes = be32toh(payload->n_prefixes);
  do { unsigned i; for (i = 0; i < payload->n_prefixes; ++i) { vapi_type_ip6nd_ra_prefix_ntoh(&payload->prefixes[i]); } } while(0);
}

static inline void vapi_msg_sw_interface_ip6nd_ra_details_hton(vapi_msg_sw_interface_ip6nd_ra_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6nd_ra_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sw_interface_ip6nd_ra_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_ip6nd_ra_details_ntoh(vapi_msg_sw_interface_ip6nd_ra_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6nd_ra_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sw_interface_ip6nd_ra_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_ip6nd_ra_details_msg_size(vapi_msg_sw_interface_ip6nd_ra_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.prefixes[0]) * msg->payload.n_prefixes;
}

static inline int vapi_verify_sw_interface_ip6nd_ra_details_msg_size(vapi_msg_sw_interface_ip6nd_ra_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_ip6nd_ra_details) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6nd_ra_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_ip6nd_ra_details));
      return -1;
    }
  if (vapi_calc_sw_interface_ip6nd_ra_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6nd_ra_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_ip6nd_ra_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sw_interface_ip6nd_ra_details()
{
  static const char name[] = "sw_interface_ip6nd_ra_details";
  static const char name_with_crc[] = "sw_interface_ip6nd_ra_details_d3198de5";
  static vapi_message_desc_t __vapi_metadata_sw_interface_ip6nd_ra_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sw_interface_ip6nd_ra_details, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_ip6nd_ra_details_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6nd_ra_details_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6nd_ra_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_ip6nd_ra_details = vapi_register_msg(&__vapi_metadata_sw_interface_ip6nd_ra_details);
  VAPI_DBG("Assigned msg id %d to sw_interface_ip6nd_ra_details", vapi_msg_id_sw_interface_ip6nd_ra_details);
}

static inline void vapi_set_vapi_msg_sw_interface_ip6nd_ra_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sw_interface_ip6nd_ra_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sw_interface_ip6nd_ra_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sw_interface_ip6nd_ra_dump
#define defined_vapi_msg_sw_interface_ip6nd_ra_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_sw_interface_ip6nd_ra_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sw_interface_ip6nd_ra_dump payload;
} vapi_msg_sw_interface_ip6nd_ra_dump;

static inline void vapi_msg_sw_interface_ip6nd_ra_dump_payload_hton(vapi_payload_sw_interface_ip6nd_ra_dump *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_sw_interface_ip6nd_ra_dump_payload_ntoh(vapi_payload_sw_interface_ip6nd_ra_dump *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_sw_interface_ip6nd_ra_dump_hton(vapi_msg_sw_interface_ip6nd_ra_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6nd_ra_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sw_interface_ip6nd_ra_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_ip6nd_ra_dump_ntoh(vapi_msg_sw_interface_ip6nd_ra_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_ip6nd_ra_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sw_interface_ip6nd_ra_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_ip6nd_ra_dump_msg_size(vapi_msg_sw_interface_ip6nd_ra_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_ip6nd_ra_dump_msg_size(vapi_msg_sw_interface_ip6nd_ra_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_ip6nd_ra_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6nd_ra_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_ip6nd_ra_dump));
      return -1;
    }
  if (vapi_calc_sw_interface_ip6nd_ra_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_ip6nd_ra_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_ip6nd_ra_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sw_interface_ip6nd_ra_dump* vapi_alloc_sw_interface_ip6nd_ra_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_sw_interface_ip6nd_ra_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_sw_interface_ip6nd_ra_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sw_interface_ip6nd_ra_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sw_interface_ip6nd_ra_dump);

  return msg;
}

static inline vapi_error_e vapi_sw_interface_ip6nd_ra_dump(struct vapi_ctx_s *ctx,
  vapi_msg_sw_interface_ip6nd_ra_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sw_interface_ip6nd_ra_details *reply),
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
  vapi_msg_sw_interface_ip6nd_ra_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sw_interface_ip6nd_ra_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_sw_interface_ip6nd_ra_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sw_interface_ip6nd_ra_dump()
{
  static const char name[] = "sw_interface_ip6nd_ra_dump";
  static const char name_with_crc[] = "sw_interface_ip6nd_ra_dump_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_sw_interface_ip6nd_ra_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sw_interface_ip6nd_ra_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_ip6nd_ra_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6nd_ra_dump_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_ip6nd_ra_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_ip6nd_ra_dump = vapi_register_msg(&__vapi_metadata_sw_interface_ip6nd_ra_dump);
  VAPI_DBG("Assigned msg id %d to sw_interface_ip6nd_ra_dump", vapi_msg_id_sw_interface_ip6nd_ra_dump);
}
#endif

#ifndef defined_vapi_msg_ip6nd_proxy_enable_disable_reply
#define defined_vapi_msg_ip6nd_proxy_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip6nd_proxy_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip6nd_proxy_enable_disable_reply payload;
} vapi_msg_ip6nd_proxy_enable_disable_reply;

static inline void vapi_msg_ip6nd_proxy_enable_disable_reply_payload_hton(vapi_payload_ip6nd_proxy_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip6nd_proxy_enable_disable_reply_payload_ntoh(vapi_payload_ip6nd_proxy_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip6nd_proxy_enable_disable_reply_hton(vapi_msg_ip6nd_proxy_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip6nd_proxy_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip6nd_proxy_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip6nd_proxy_enable_disable_reply_ntoh(vapi_msg_ip6nd_proxy_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip6nd_proxy_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip6nd_proxy_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip6nd_proxy_enable_disable_reply_msg_size(vapi_msg_ip6nd_proxy_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip6nd_proxy_enable_disable_reply_msg_size(vapi_msg_ip6nd_proxy_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip6nd_proxy_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip6nd_proxy_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip6nd_proxy_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_ip6nd_proxy_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip6nd_proxy_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip6nd_proxy_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip6nd_proxy_enable_disable_reply()
{
  static const char name[] = "ip6nd_proxy_enable_disable_reply";
  static const char name_with_crc[] = "ip6nd_proxy_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip6nd_proxy_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip6nd_proxy_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip6nd_proxy_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip6nd_proxy_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip6nd_proxy_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip6nd_proxy_enable_disable_reply = vapi_register_msg(&__vapi_metadata_ip6nd_proxy_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to ip6nd_proxy_enable_disable_reply", vapi_msg_id_ip6nd_proxy_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_ip6nd_proxy_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip6nd_proxy_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip6nd_proxy_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip6nd_proxy_enable_disable
#define defined_vapi_msg_ip6nd_proxy_enable_disable
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  bool is_enable; 
} vapi_payload_ip6nd_proxy_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip6nd_proxy_enable_disable payload;
} vapi_msg_ip6nd_proxy_enable_disable;

static inline void vapi_msg_ip6nd_proxy_enable_disable_payload_hton(vapi_payload_ip6nd_proxy_enable_disable *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ip6nd_proxy_enable_disable_payload_ntoh(vapi_payload_ip6nd_proxy_enable_disable *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ip6nd_proxy_enable_disable_hton(vapi_msg_ip6nd_proxy_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip6nd_proxy_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip6nd_proxy_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip6nd_proxy_enable_disable_ntoh(vapi_msg_ip6nd_proxy_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip6nd_proxy_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip6nd_proxy_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip6nd_proxy_enable_disable_msg_size(vapi_msg_ip6nd_proxy_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip6nd_proxy_enable_disable_msg_size(vapi_msg_ip6nd_proxy_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip6nd_proxy_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'ip6nd_proxy_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip6nd_proxy_enable_disable));
      return -1;
    }
  if (vapi_calc_ip6nd_proxy_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip6nd_proxy_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip6nd_proxy_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip6nd_proxy_enable_disable* vapi_alloc_ip6nd_proxy_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip6nd_proxy_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip6nd_proxy_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip6nd_proxy_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip6nd_proxy_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_ip6nd_proxy_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_ip6nd_proxy_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip6nd_proxy_enable_disable_reply *reply),
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
  vapi_msg_ip6nd_proxy_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip6nd_proxy_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ip6nd_proxy_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip6nd_proxy_enable_disable()
{
  static const char name[] = "ip6nd_proxy_enable_disable";
  static const char name_with_crc[] = "ip6nd_proxy_enable_disable_7daa1e3a";
  static vapi_message_desc_t __vapi_metadata_ip6nd_proxy_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip6nd_proxy_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_ip6nd_proxy_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_ip6nd_proxy_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_ip6nd_proxy_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip6nd_proxy_enable_disable = vapi_register_msg(&__vapi_metadata_ip6nd_proxy_enable_disable);
  VAPI_DBG("Assigned msg id %d to ip6nd_proxy_enable_disable", vapi_msg_id_ip6nd_proxy_enable_disable);
}
#endif

#ifndef defined_vapi_msg_ip6nd_proxy_add_del_reply
#define defined_vapi_msg_ip6nd_proxy_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip6nd_proxy_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip6nd_proxy_add_del_reply payload;
} vapi_msg_ip6nd_proxy_add_del_reply;

static inline void vapi_msg_ip6nd_proxy_add_del_reply_payload_hton(vapi_payload_ip6nd_proxy_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip6nd_proxy_add_del_reply_payload_ntoh(vapi_payload_ip6nd_proxy_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip6nd_proxy_add_del_reply_hton(vapi_msg_ip6nd_proxy_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip6nd_proxy_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip6nd_proxy_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip6nd_proxy_add_del_reply_ntoh(vapi_msg_ip6nd_proxy_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip6nd_proxy_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip6nd_proxy_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip6nd_proxy_add_del_reply_msg_size(vapi_msg_ip6nd_proxy_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip6nd_proxy_add_del_reply_msg_size(vapi_msg_ip6nd_proxy_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip6nd_proxy_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip6nd_proxy_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip6nd_proxy_add_del_reply));
      return -1;
    }
  if (vapi_calc_ip6nd_proxy_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip6nd_proxy_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip6nd_proxy_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip6nd_proxy_add_del_reply()
{
  static const char name[] = "ip6nd_proxy_add_del_reply";
  static const char name_with_crc[] = "ip6nd_proxy_add_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip6nd_proxy_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip6nd_proxy_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip6nd_proxy_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip6nd_proxy_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip6nd_proxy_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip6nd_proxy_add_del_reply = vapi_register_msg(&__vapi_metadata_ip6nd_proxy_add_del_reply);
  VAPI_DBG("Assigned msg id %d to ip6nd_proxy_add_del_reply", vapi_msg_id_ip6nd_proxy_add_del_reply);
}

static inline void vapi_set_vapi_msg_ip6nd_proxy_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip6nd_proxy_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip6nd_proxy_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip6nd_proxy_add_del
#define defined_vapi_msg_ip6nd_proxy_add_del
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  bool is_add;
  vapi_type_ip6_address ip; 
} vapi_payload_ip6nd_proxy_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip6nd_proxy_add_del payload;
} vapi_msg_ip6nd_proxy_add_del;

static inline void vapi_msg_ip6nd_proxy_add_del_payload_hton(vapi_payload_ip6nd_proxy_add_del *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ip6nd_proxy_add_del_payload_ntoh(vapi_payload_ip6nd_proxy_add_del *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ip6nd_proxy_add_del_hton(vapi_msg_ip6nd_proxy_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip6nd_proxy_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip6nd_proxy_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip6nd_proxy_add_del_ntoh(vapi_msg_ip6nd_proxy_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip6nd_proxy_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip6nd_proxy_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip6nd_proxy_add_del_msg_size(vapi_msg_ip6nd_proxy_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip6nd_proxy_add_del_msg_size(vapi_msg_ip6nd_proxy_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip6nd_proxy_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'ip6nd_proxy_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip6nd_proxy_add_del));
      return -1;
    }
  if (vapi_calc_ip6nd_proxy_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip6nd_proxy_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip6nd_proxy_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip6nd_proxy_add_del* vapi_alloc_ip6nd_proxy_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip6nd_proxy_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip6nd_proxy_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip6nd_proxy_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip6nd_proxy_add_del);

  return msg;
}

static inline vapi_error_e vapi_ip6nd_proxy_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_ip6nd_proxy_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip6nd_proxy_add_del_reply *reply),
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
  vapi_msg_ip6nd_proxy_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip6nd_proxy_add_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ip6nd_proxy_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip6nd_proxy_add_del()
{
  static const char name[] = "ip6nd_proxy_add_del";
  static const char name_with_crc[] = "ip6nd_proxy_add_del_c2e4a686";
  static vapi_message_desc_t __vapi_metadata_ip6nd_proxy_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip6nd_proxy_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_ip6nd_proxy_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_ip6nd_proxy_add_del_hton,
    (generic_swap_fn_t)vapi_msg_ip6nd_proxy_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip6nd_proxy_add_del = vapi_register_msg(&__vapi_metadata_ip6nd_proxy_add_del);
  VAPI_DBG("Assigned msg id %d to ip6nd_proxy_add_del", vapi_msg_id_ip6nd_proxy_add_del);
}
#endif

#ifndef defined_vapi_msg_ip6nd_proxy_details
#define defined_vapi_msg_ip6nd_proxy_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_type_ip6_address ip; 
} vapi_payload_ip6nd_proxy_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip6nd_proxy_details payload;
} vapi_msg_ip6nd_proxy_details;

static inline void vapi_msg_ip6nd_proxy_details_payload_hton(vapi_payload_ip6nd_proxy_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ip6nd_proxy_details_payload_ntoh(vapi_payload_ip6nd_proxy_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ip6nd_proxy_details_hton(vapi_msg_ip6nd_proxy_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip6nd_proxy_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip6nd_proxy_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip6nd_proxy_details_ntoh(vapi_msg_ip6nd_proxy_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip6nd_proxy_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip6nd_proxy_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip6nd_proxy_details_msg_size(vapi_msg_ip6nd_proxy_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip6nd_proxy_details_msg_size(vapi_msg_ip6nd_proxy_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip6nd_proxy_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ip6nd_proxy_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip6nd_proxy_details));
      return -1;
    }
  if (vapi_calc_ip6nd_proxy_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip6nd_proxy_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip6nd_proxy_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip6nd_proxy_details()
{
  static const char name[] = "ip6nd_proxy_details";
  static const char name_with_crc[] = "ip6nd_proxy_details_30b9ff4a";
  static vapi_message_desc_t __vapi_metadata_ip6nd_proxy_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip6nd_proxy_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ip6nd_proxy_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ip6nd_proxy_details_hton,
    (generic_swap_fn_t)vapi_msg_ip6nd_proxy_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip6nd_proxy_details = vapi_register_msg(&__vapi_metadata_ip6nd_proxy_details);
  VAPI_DBG("Assigned msg id %d to ip6nd_proxy_details", vapi_msg_id_ip6nd_proxy_details);
}

static inline void vapi_set_vapi_msg_ip6nd_proxy_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip6nd_proxy_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip6nd_proxy_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip6nd_proxy_dump
#define defined_vapi_msg_ip6nd_proxy_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ip6nd_proxy_dump;

static inline void vapi_msg_ip6nd_proxy_dump_hton(vapi_msg_ip6nd_proxy_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip6nd_proxy_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ip6nd_proxy_dump_ntoh(vapi_msg_ip6nd_proxy_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip6nd_proxy_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ip6nd_proxy_dump_msg_size(vapi_msg_ip6nd_proxy_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip6nd_proxy_dump_msg_size(vapi_msg_ip6nd_proxy_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip6nd_proxy_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ip6nd_proxy_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip6nd_proxy_dump));
      return -1;
    }
  if (vapi_calc_ip6nd_proxy_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip6nd_proxy_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip6nd_proxy_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip6nd_proxy_dump* vapi_alloc_ip6nd_proxy_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip6nd_proxy_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip6nd_proxy_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip6nd_proxy_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip6nd_proxy_dump);

  return msg;
}

static inline vapi_error_e vapi_ip6nd_proxy_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ip6nd_proxy_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip6nd_proxy_details *reply),
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
  vapi_msg_ip6nd_proxy_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip6nd_proxy_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_ip6nd_proxy_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip6nd_proxy_dump()
{
  static const char name[] = "ip6nd_proxy_dump";
  static const char name_with_crc[] = "ip6nd_proxy_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_ip6nd_proxy_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ip6nd_proxy_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ip6nd_proxy_dump_hton,
    (generic_swap_fn_t)vapi_msg_ip6nd_proxy_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip6nd_proxy_dump = vapi_register_msg(&__vapi_metadata_ip6nd_proxy_dump);
  VAPI_DBG("Assigned msg id %d to ip6nd_proxy_dump", vapi_msg_id_ip6nd_proxy_dump);
}
#endif

#ifndef defined_vapi_msg_ip6nd_send_router_solicitation_reply
#define defined_vapi_msg_ip6nd_send_router_solicitation_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip6nd_send_router_solicitation_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip6nd_send_router_solicitation_reply payload;
} vapi_msg_ip6nd_send_router_solicitation_reply;

static inline void vapi_msg_ip6nd_send_router_solicitation_reply_payload_hton(vapi_payload_ip6nd_send_router_solicitation_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip6nd_send_router_solicitation_reply_payload_ntoh(vapi_payload_ip6nd_send_router_solicitation_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip6nd_send_router_solicitation_reply_hton(vapi_msg_ip6nd_send_router_solicitation_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip6nd_send_router_solicitation_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip6nd_send_router_solicitation_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip6nd_send_router_solicitation_reply_ntoh(vapi_msg_ip6nd_send_router_solicitation_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip6nd_send_router_solicitation_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip6nd_send_router_solicitation_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip6nd_send_router_solicitation_reply_msg_size(vapi_msg_ip6nd_send_router_solicitation_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip6nd_send_router_solicitation_reply_msg_size(vapi_msg_ip6nd_send_router_solicitation_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip6nd_send_router_solicitation_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip6nd_send_router_solicitation_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip6nd_send_router_solicitation_reply));
      return -1;
    }
  if (vapi_calc_ip6nd_send_router_solicitation_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip6nd_send_router_solicitation_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip6nd_send_router_solicitation_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip6nd_send_router_solicitation_reply()
{
  static const char name[] = "ip6nd_send_router_solicitation_reply";
  static const char name_with_crc[] = "ip6nd_send_router_solicitation_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip6nd_send_router_solicitation_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip6nd_send_router_solicitation_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip6nd_send_router_solicitation_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip6nd_send_router_solicitation_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip6nd_send_router_solicitation_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip6nd_send_router_solicitation_reply = vapi_register_msg(&__vapi_metadata_ip6nd_send_router_solicitation_reply);
  VAPI_DBG("Assigned msg id %d to ip6nd_send_router_solicitation_reply", vapi_msg_id_ip6nd_send_router_solicitation_reply);
}

static inline void vapi_set_vapi_msg_ip6nd_send_router_solicitation_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip6nd_send_router_solicitation_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip6nd_send_router_solicitation_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip6nd_send_router_solicitation
#define defined_vapi_msg_ip6nd_send_router_solicitation
typedef struct __attribute__ ((__packed__)) {
  u32 irt;
  u32 mrt;
  u32 mrc;
  u32 mrd;
  vapi_type_interface_index sw_if_index;
  bool stop; 
} vapi_payload_ip6nd_send_router_solicitation;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip6nd_send_router_solicitation payload;
} vapi_msg_ip6nd_send_router_solicitation;

static inline void vapi_msg_ip6nd_send_router_solicitation_payload_hton(vapi_payload_ip6nd_send_router_solicitation *payload)
{
  payload->irt = htobe32(payload->irt);
  payload->mrt = htobe32(payload->mrt);
  payload->mrc = htobe32(payload->mrc);
  payload->mrd = htobe32(payload->mrd);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ip6nd_send_router_solicitation_payload_ntoh(vapi_payload_ip6nd_send_router_solicitation *payload)
{
  payload->irt = be32toh(payload->irt);
  payload->mrt = be32toh(payload->mrt);
  payload->mrc = be32toh(payload->mrc);
  payload->mrd = be32toh(payload->mrd);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ip6nd_send_router_solicitation_hton(vapi_msg_ip6nd_send_router_solicitation *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip6nd_send_router_solicitation'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip6nd_send_router_solicitation_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip6nd_send_router_solicitation_ntoh(vapi_msg_ip6nd_send_router_solicitation *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip6nd_send_router_solicitation'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip6nd_send_router_solicitation_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip6nd_send_router_solicitation_msg_size(vapi_msg_ip6nd_send_router_solicitation *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip6nd_send_router_solicitation_msg_size(vapi_msg_ip6nd_send_router_solicitation *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip6nd_send_router_solicitation) > buf_size)
    {
      VAPI_ERR("Truncated 'ip6nd_send_router_solicitation' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip6nd_send_router_solicitation));
      return -1;
    }
  if (vapi_calc_ip6nd_send_router_solicitation_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip6nd_send_router_solicitation' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip6nd_send_router_solicitation_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip6nd_send_router_solicitation* vapi_alloc_ip6nd_send_router_solicitation(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip6nd_send_router_solicitation *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip6nd_send_router_solicitation);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip6nd_send_router_solicitation*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip6nd_send_router_solicitation);

  return msg;
}

static inline vapi_error_e vapi_ip6nd_send_router_solicitation(struct vapi_ctx_s *ctx,
  vapi_msg_ip6nd_send_router_solicitation *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip6nd_send_router_solicitation_reply *reply),
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
  vapi_msg_ip6nd_send_router_solicitation_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip6nd_send_router_solicitation_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ip6nd_send_router_solicitation_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip6nd_send_router_solicitation()
{
  static const char name[] = "ip6nd_send_router_solicitation";
  static const char name_with_crc[] = "ip6nd_send_router_solicitation_e5de609c";
  static vapi_message_desc_t __vapi_metadata_ip6nd_send_router_solicitation = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip6nd_send_router_solicitation, payload),
    (verify_msg_size_fn_t)vapi_verify_ip6nd_send_router_solicitation_msg_size,
    (generic_swap_fn_t)vapi_msg_ip6nd_send_router_solicitation_hton,
    (generic_swap_fn_t)vapi_msg_ip6nd_send_router_solicitation_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip6nd_send_router_solicitation = vapi_register_msg(&__vapi_metadata_ip6nd_send_router_solicitation);
  VAPI_DBG("Assigned msg id %d to ip6nd_send_router_solicitation", vapi_msg_id_ip6nd_send_router_solicitation);
}
#endif

#ifndef defined_vapi_msg_want_ip6_ra_events_reply
#define defined_vapi_msg_want_ip6_ra_events_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_want_ip6_ra_events_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_want_ip6_ra_events_reply payload;
} vapi_msg_want_ip6_ra_events_reply;

static inline void vapi_msg_want_ip6_ra_events_reply_payload_hton(vapi_payload_want_ip6_ra_events_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_want_ip6_ra_events_reply_payload_ntoh(vapi_payload_want_ip6_ra_events_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_want_ip6_ra_events_reply_hton(vapi_msg_want_ip6_ra_events_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_ip6_ra_events_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_want_ip6_ra_events_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_want_ip6_ra_events_reply_ntoh(vapi_msg_want_ip6_ra_events_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_ip6_ra_events_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_want_ip6_ra_events_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_want_ip6_ra_events_reply_msg_size(vapi_msg_want_ip6_ra_events_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_want_ip6_ra_events_reply_msg_size(vapi_msg_want_ip6_ra_events_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_want_ip6_ra_events_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'want_ip6_ra_events_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_want_ip6_ra_events_reply));
      return -1;
    }
  if (vapi_calc_want_ip6_ra_events_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'want_ip6_ra_events_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_want_ip6_ra_events_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_want_ip6_ra_events_reply()
{
  static const char name[] = "want_ip6_ra_events_reply";
  static const char name_with_crc[] = "want_ip6_ra_events_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_want_ip6_ra_events_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_want_ip6_ra_events_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_want_ip6_ra_events_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_want_ip6_ra_events_reply_hton,
    (generic_swap_fn_t)vapi_msg_want_ip6_ra_events_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_want_ip6_ra_events_reply = vapi_register_msg(&__vapi_metadata_want_ip6_ra_events_reply);
  VAPI_DBG("Assigned msg id %d to want_ip6_ra_events_reply", vapi_msg_id_want_ip6_ra_events_reply);
}

static inline void vapi_set_vapi_msg_want_ip6_ra_events_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_want_ip6_ra_events_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_want_ip6_ra_events_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_want_ip6_ra_events
#define defined_vapi_msg_want_ip6_ra_events
typedef struct __attribute__ ((__packed__)) {
  bool enable;
  u32 pid; 
} vapi_payload_want_ip6_ra_events;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_want_ip6_ra_events payload;
} vapi_msg_want_ip6_ra_events;

static inline void vapi_msg_want_ip6_ra_events_payload_hton(vapi_payload_want_ip6_ra_events *payload)
{
  payload->pid = htobe32(payload->pid);
}

static inline void vapi_msg_want_ip6_ra_events_payload_ntoh(vapi_payload_want_ip6_ra_events *payload)
{
  payload->pid = be32toh(payload->pid);
}

static inline void vapi_msg_want_ip6_ra_events_hton(vapi_msg_want_ip6_ra_events *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_ip6_ra_events'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_want_ip6_ra_events_payload_hton(&msg->payload);
}

static inline void vapi_msg_want_ip6_ra_events_ntoh(vapi_msg_want_ip6_ra_events *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_ip6_ra_events'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_want_ip6_ra_events_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_want_ip6_ra_events_msg_size(vapi_msg_want_ip6_ra_events *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_want_ip6_ra_events_msg_size(vapi_msg_want_ip6_ra_events *msg, uword buf_size)
{
  if (sizeof(vapi_msg_want_ip6_ra_events) > buf_size)
    {
      VAPI_ERR("Truncated 'want_ip6_ra_events' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_want_ip6_ra_events));
      return -1;
    }
  if (vapi_calc_want_ip6_ra_events_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'want_ip6_ra_events' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_want_ip6_ra_events_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_want_ip6_ra_events* vapi_alloc_want_ip6_ra_events(struct vapi_ctx_s *ctx)
{
  vapi_msg_want_ip6_ra_events *msg = NULL;
  const size_t size = sizeof(vapi_msg_want_ip6_ra_events);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_want_ip6_ra_events*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_want_ip6_ra_events);

  return msg;
}

static inline vapi_error_e vapi_want_ip6_ra_events(struct vapi_ctx_s *ctx,
  vapi_msg_want_ip6_ra_events *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_want_ip6_ra_events_reply *reply),
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
  vapi_msg_want_ip6_ra_events_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_want_ip6_ra_events_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_want_ip6_ra_events_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_want_ip6_ra_events()
{
  static const char name[] = "want_ip6_ra_events";
  static const char name_with_crc[] = "want_ip6_ra_events_3ec6d6c2";
  static vapi_message_desc_t __vapi_metadata_want_ip6_ra_events = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_want_ip6_ra_events, payload),
    (verify_msg_size_fn_t)vapi_verify_want_ip6_ra_events_msg_size,
    (generic_swap_fn_t)vapi_msg_want_ip6_ra_events_hton,
    (generic_swap_fn_t)vapi_msg_want_ip6_ra_events_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_want_ip6_ra_events = vapi_register_msg(&__vapi_metadata_want_ip6_ra_events);
  VAPI_DBG("Assigned msg id %d to want_ip6_ra_events", vapi_msg_id_want_ip6_ra_events);
}
#endif

#ifndef defined_vapi_msg_ip6_ra_event
#define defined_vapi_msg_ip6_ra_event
typedef struct __attribute__ ((__packed__)) {
  u16 _vl_msg_id;
  u32 client_index;
  u32 pid;
  vapi_type_interface_index sw_if_index;
  vapi_type_ip6_address router_addr;
  u8 current_hop_limit;
  u8 flags;
  u16 router_lifetime_in_sec;
  u32 neighbor_reachable_time_in_msec;
  u32 time_in_msec_between_retransmitted_neighbor_solicitations;
  u32 n_prefixes;
  vapi_type_ip6_ra_prefix_info prefixes[0]; 
} vapi_payload_ip6_ra_event;

typedef struct __attribute__ ((__packed__)) {

  vapi_payload_ip6_ra_event payload;
} vapi_msg_ip6_ra_event;

static inline void vapi_msg_ip6_ra_event_payload_hton(vapi_payload_ip6_ra_event *payload)
{
  payload->_vl_msg_id = htobe16(payload->_vl_msg_id);
  payload->client_index = htobe32(payload->client_index);
  payload->pid = htobe32(payload->pid);
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->router_lifetime_in_sec = htobe16(payload->router_lifetime_in_sec);
  payload->neighbor_reachable_time_in_msec = htobe32(payload->neighbor_reachable_time_in_msec);
  payload->time_in_msec_between_retransmitted_neighbor_solicitations = htobe32(payload->time_in_msec_between_retransmitted_neighbor_solicitations);
  payload->n_prefixes = htobe32(payload->n_prefixes);
  do { unsigned i; for (i = 0; i < be32toh(payload->n_prefixes); ++i) { vapi_type_ip6_ra_prefix_info_hton(&payload->prefixes[i]); } } while(0);
}

static inline void vapi_msg_ip6_ra_event_payload_ntoh(vapi_payload_ip6_ra_event *payload)
{
  payload->_vl_msg_id = be16toh(payload->_vl_msg_id);
  payload->client_index = be32toh(payload->client_index);
  payload->pid = be32toh(payload->pid);
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->router_lifetime_in_sec = be16toh(payload->router_lifetime_in_sec);
  payload->neighbor_reachable_time_in_msec = be32toh(payload->neighbor_reachable_time_in_msec);
  payload->time_in_msec_between_retransmitted_neighbor_solicitations = be32toh(payload->time_in_msec_between_retransmitted_neighbor_solicitations);
  payload->n_prefixes = be32toh(payload->n_prefixes);
  do { unsigned i; for (i = 0; i < payload->n_prefixes; ++i) { vapi_type_ip6_ra_prefix_info_ntoh(&payload->prefixes[i]); } } while(0);
}

static inline void vapi_msg_ip6_ra_event_hton(vapi_msg_ip6_ra_event *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip6_ra_event'@%p to big endian", msg);

  vapi_msg_ip6_ra_event_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip6_ra_event_ntoh(vapi_msg_ip6_ra_event *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip6_ra_event'@%p to host byte order", msg);

  vapi_msg_ip6_ra_event_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip6_ra_event_msg_size(vapi_msg_ip6_ra_event *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.prefixes[0]) * msg->payload.n_prefixes;
}

static inline int vapi_verify_ip6_ra_event_msg_size(vapi_msg_ip6_ra_event *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip6_ra_event) > buf_size)
    {
      VAPI_ERR("Truncated 'ip6_ra_event' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip6_ra_event));
      return -1;
    }
  if (vapi_calc_ip6_ra_event_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip6_ra_event' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip6_ra_event_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip6_ra_event()
{
  static const char name[] = "ip6_ra_event";
  static const char name_with_crc[] = "ip6_ra_event_0364c1c5";
  static vapi_message_desc_t __vapi_metadata_ip6_ra_event = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    false,
    0,
    offsetof(vapi_msg_ip6_ra_event, payload),
    (verify_msg_size_fn_t)vapi_verify_ip6_ra_event_msg_size,
    (generic_swap_fn_t)vapi_msg_ip6_ra_event_hton,
    (generic_swap_fn_t)vapi_msg_ip6_ra_event_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip6_ra_event = vapi_register_msg(&__vapi_metadata_ip6_ra_event);
  VAPI_DBG("Assigned msg id %d to ip6_ra_event", vapi_msg_id_ip6_ra_event);
}

static inline void vapi_set_vapi_msg_ip6_ra_event_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip6_ra_event *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip6_ra_event, (vapi_event_cb)callback, callback_ctx);
};
#endif


#ifdef __cplusplus
}
#endif

#endif
