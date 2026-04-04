#ifndef __included_wireguard_api_json
#define __included_wireguard_api_json

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

extern vapi_msg_id_t vapi_msg_id_wireguard_interface_create;
extern vapi_msg_id_t vapi_msg_id_wireguard_interface_create_reply;
extern vapi_msg_id_t vapi_msg_id_wireguard_interface_delete;
extern vapi_msg_id_t vapi_msg_id_wireguard_interface_delete_reply;
extern vapi_msg_id_t vapi_msg_id_wireguard_interface_dump;
extern vapi_msg_id_t vapi_msg_id_wireguard_interface_details;
extern vapi_msg_id_t vapi_msg_id_want_wireguard_peer_events;
extern vapi_msg_id_t vapi_msg_id_want_wireguard_peer_events_reply;
extern vapi_msg_id_t vapi_msg_id_wireguard_peer_event;
extern vapi_msg_id_t vapi_msg_id_wireguard_peer_add;
extern vapi_msg_id_t vapi_msg_id_wireguard_peer_add_reply;
extern vapi_msg_id_t vapi_msg_id_wireguard_peer_remove;
extern vapi_msg_id_t vapi_msg_id_wireguard_peer_remove_reply;
extern vapi_msg_id_t vapi_msg_id_wireguard_peers_dump;
extern vapi_msg_id_t vapi_msg_id_wireguard_peers_details;
extern vapi_msg_id_t vapi_msg_id_wg_set_async_mode;
extern vapi_msg_id_t vapi_msg_id_wg_set_async_mode_reply;

#define DEFINE_VAPI_MSG_IDS_WIREGUARD_API_JSON\
  vapi_msg_id_t vapi_msg_id_wireguard_interface_create;\
  vapi_msg_id_t vapi_msg_id_wireguard_interface_create_reply;\
  vapi_msg_id_t vapi_msg_id_wireguard_interface_delete;\
  vapi_msg_id_t vapi_msg_id_wireguard_interface_delete_reply;\
  vapi_msg_id_t vapi_msg_id_wireguard_interface_dump;\
  vapi_msg_id_t vapi_msg_id_wireguard_interface_details;\
  vapi_msg_id_t vapi_msg_id_want_wireguard_peer_events;\
  vapi_msg_id_t vapi_msg_id_want_wireguard_peer_events_reply;\
  vapi_msg_id_t vapi_msg_id_wireguard_peer_event;\
  vapi_msg_id_t vapi_msg_id_wireguard_peer_add;\
  vapi_msg_id_t vapi_msg_id_wireguard_peer_add_reply;\
  vapi_msg_id_t vapi_msg_id_wireguard_peer_remove;\
  vapi_msg_id_t vapi_msg_id_wireguard_peer_remove_reply;\
  vapi_msg_id_t vapi_msg_id_wireguard_peers_dump;\
  vapi_msg_id_t vapi_msg_id_wireguard_peers_details;\
  vapi_msg_id_t vapi_msg_id_wg_set_async_mode;\
  vapi_msg_id_t vapi_msg_id_wg_set_async_mode_reply;


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

#ifndef defined_vapi_enum_wireguard_peer_flags
#define defined_vapi_enum_wireguard_peer_flags
typedef enum {
  WIREGUARD_PEER_STATUS_DEAD = 1,
  WIREGUARD_PEER_ESTABLISHED = 2,
} __attribute__((packed)) vapi_enum_wireguard_peer_flags;

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

#ifndef defined_vapi_type_wireguard_interface
#define defined_vapi_type_wireguard_interface
typedef struct __attribute__((__packed__)) {
  u32 user_instance;
  vapi_type_interface_index sw_if_index;
  u8 private_key[32];
  u8 public_key[32];
  u16 port;
  vapi_type_address src_ip;
} vapi_type_wireguard_interface;

static inline void vapi_type_wireguard_interface_hton(vapi_type_wireguard_interface *msg)
{
  msg->user_instance = htobe32(msg->user_instance);
  msg->sw_if_index = htobe32(msg->sw_if_index);
  msg->port = htobe16(msg->port);
}

static inline void vapi_type_wireguard_interface_ntoh(vapi_type_wireguard_interface *msg)
{
  msg->user_instance = be32toh(msg->user_instance);
  msg->sw_if_index = be32toh(msg->sw_if_index);
  msg->port = be16toh(msg->port);
}
#endif

#ifndef defined_vapi_type_wireguard_peer
#define defined_vapi_type_wireguard_peer
typedef struct __attribute__((__packed__)) {
  u32 peer_index;
  u8 public_key[32];
  u16 port;
  u16 persistent_keepalive;
  u32 table_id;
  vapi_type_address endpoint;
  vapi_type_interface_index sw_if_index;
  vapi_enum_wireguard_peer_flags flags;
  u8 n_allowed_ips;
  vapi_type_prefix allowed_ips[0];
} vapi_type_wireguard_peer;

static inline void vapi_type_wireguard_peer_hton(vapi_type_wireguard_peer *msg)
{
  msg->peer_index = htobe32(msg->peer_index);
  msg->port = htobe16(msg->port);
  msg->persistent_keepalive = htobe16(msg->persistent_keepalive);
  msg->table_id = htobe32(msg->table_id);
  msg->sw_if_index = htobe32(msg->sw_if_index);
}

static inline void vapi_type_wireguard_peer_ntoh(vapi_type_wireguard_peer *msg)
{
  msg->peer_index = be32toh(msg->peer_index);
  msg->port = be16toh(msg->port);
  msg->persistent_keepalive = be16toh(msg->persistent_keepalive);
  msg->table_id = be32toh(msg->table_id);
  msg->sw_if_index = be32toh(msg->sw_if_index);
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

#ifndef defined_vapi_msg_wireguard_interface_create_reply
#define defined_vapi_msg_wireguard_interface_create_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_wireguard_interface_create_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_wireguard_interface_create_reply payload;
} vapi_msg_wireguard_interface_create_reply;

static inline void vapi_msg_wireguard_interface_create_reply_payload_hton(vapi_payload_wireguard_interface_create_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_wireguard_interface_create_reply_payload_ntoh(vapi_payload_wireguard_interface_create_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_wireguard_interface_create_reply_hton(vapi_msg_wireguard_interface_create_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_interface_create_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_wireguard_interface_create_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_wireguard_interface_create_reply_ntoh(vapi_msg_wireguard_interface_create_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_interface_create_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_wireguard_interface_create_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_wireguard_interface_create_reply_msg_size(vapi_msg_wireguard_interface_create_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_wireguard_interface_create_reply_msg_size(vapi_msg_wireguard_interface_create_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_wireguard_interface_create_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_interface_create_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_wireguard_interface_create_reply));
      return -1;
    }
  if (vapi_calc_wireguard_interface_create_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_interface_create_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_wireguard_interface_create_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_wireguard_interface_create_reply()
{
  static const char name[] = "wireguard_interface_create_reply";
  static const char name_with_crc[] = "wireguard_interface_create_reply_5383d31f";
  static vapi_message_desc_t __vapi_metadata_wireguard_interface_create_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_wireguard_interface_create_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_wireguard_interface_create_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_wireguard_interface_create_reply_hton,
    (generic_swap_fn_t)vapi_msg_wireguard_interface_create_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_wireguard_interface_create_reply = vapi_register_msg(&__vapi_metadata_wireguard_interface_create_reply);
  VAPI_DBG("Assigned msg id %d to wireguard_interface_create_reply", vapi_msg_id_wireguard_interface_create_reply);
}

static inline void vapi_set_vapi_msg_wireguard_interface_create_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_wireguard_interface_create_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_wireguard_interface_create_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_wireguard_interface_create
#define defined_vapi_msg_wireguard_interface_create
typedef struct __attribute__ ((__packed__)) {
  vapi_type_wireguard_interface interface;
  bool generate_key; 
} vapi_payload_wireguard_interface_create;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_wireguard_interface_create payload;
} vapi_msg_wireguard_interface_create;

static inline void vapi_msg_wireguard_interface_create_payload_hton(vapi_payload_wireguard_interface_create *payload)
{
  vapi_type_wireguard_interface_hton(&payload->interface);
}

static inline void vapi_msg_wireguard_interface_create_payload_ntoh(vapi_payload_wireguard_interface_create *payload)
{
  vapi_type_wireguard_interface_ntoh(&payload->interface);
}

static inline void vapi_msg_wireguard_interface_create_hton(vapi_msg_wireguard_interface_create *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_interface_create'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_wireguard_interface_create_payload_hton(&msg->payload);
}

static inline void vapi_msg_wireguard_interface_create_ntoh(vapi_msg_wireguard_interface_create *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_interface_create'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_wireguard_interface_create_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_wireguard_interface_create_msg_size(vapi_msg_wireguard_interface_create *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_wireguard_interface_create_msg_size(vapi_msg_wireguard_interface_create *msg, uword buf_size)
{
  if (sizeof(vapi_msg_wireguard_interface_create) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_interface_create' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_wireguard_interface_create));
      return -1;
    }
  if (vapi_calc_wireguard_interface_create_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_interface_create' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_wireguard_interface_create_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_wireguard_interface_create* vapi_alloc_wireguard_interface_create(struct vapi_ctx_s *ctx)
{
  vapi_msg_wireguard_interface_create *msg = NULL;
  const size_t size = sizeof(vapi_msg_wireguard_interface_create);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_wireguard_interface_create*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_wireguard_interface_create);

  return msg;
}

static inline vapi_error_e vapi_wireguard_interface_create(struct vapi_ctx_s *ctx,
  vapi_msg_wireguard_interface_create *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_wireguard_interface_create_reply *reply),
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
  vapi_msg_wireguard_interface_create_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_wireguard_interface_create_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_wireguard_interface_create_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_wireguard_interface_create()
{
  static const char name[] = "wireguard_interface_create";
  static const char name_with_crc[] = "wireguard_interface_create_a530137e";
  static vapi_message_desc_t __vapi_metadata_wireguard_interface_create = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_wireguard_interface_create, payload),
    (verify_msg_size_fn_t)vapi_verify_wireguard_interface_create_msg_size,
    (generic_swap_fn_t)vapi_msg_wireguard_interface_create_hton,
    (generic_swap_fn_t)vapi_msg_wireguard_interface_create_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_wireguard_interface_create = vapi_register_msg(&__vapi_metadata_wireguard_interface_create);
  VAPI_DBG("Assigned msg id %d to wireguard_interface_create", vapi_msg_id_wireguard_interface_create);
}
#endif

#ifndef defined_vapi_msg_wireguard_interface_delete_reply
#define defined_vapi_msg_wireguard_interface_delete_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_wireguard_interface_delete_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_wireguard_interface_delete_reply payload;
} vapi_msg_wireguard_interface_delete_reply;

static inline void vapi_msg_wireguard_interface_delete_reply_payload_hton(vapi_payload_wireguard_interface_delete_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_wireguard_interface_delete_reply_payload_ntoh(vapi_payload_wireguard_interface_delete_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_wireguard_interface_delete_reply_hton(vapi_msg_wireguard_interface_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_interface_delete_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_wireguard_interface_delete_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_wireguard_interface_delete_reply_ntoh(vapi_msg_wireguard_interface_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_interface_delete_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_wireguard_interface_delete_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_wireguard_interface_delete_reply_msg_size(vapi_msg_wireguard_interface_delete_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_wireguard_interface_delete_reply_msg_size(vapi_msg_wireguard_interface_delete_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_wireguard_interface_delete_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_interface_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_wireguard_interface_delete_reply));
      return -1;
    }
  if (vapi_calc_wireguard_interface_delete_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_interface_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_wireguard_interface_delete_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_wireguard_interface_delete_reply()
{
  static const char name[] = "wireguard_interface_delete_reply";
  static const char name_with_crc[] = "wireguard_interface_delete_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_wireguard_interface_delete_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_wireguard_interface_delete_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_wireguard_interface_delete_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_wireguard_interface_delete_reply_hton,
    (generic_swap_fn_t)vapi_msg_wireguard_interface_delete_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_wireguard_interface_delete_reply = vapi_register_msg(&__vapi_metadata_wireguard_interface_delete_reply);
  VAPI_DBG("Assigned msg id %d to wireguard_interface_delete_reply", vapi_msg_id_wireguard_interface_delete_reply);
}

static inline void vapi_set_vapi_msg_wireguard_interface_delete_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_wireguard_interface_delete_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_wireguard_interface_delete_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_wireguard_interface_delete
#define defined_vapi_msg_wireguard_interface_delete
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_wireguard_interface_delete;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_wireguard_interface_delete payload;
} vapi_msg_wireguard_interface_delete;

static inline void vapi_msg_wireguard_interface_delete_payload_hton(vapi_payload_wireguard_interface_delete *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_wireguard_interface_delete_payload_ntoh(vapi_payload_wireguard_interface_delete *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_wireguard_interface_delete_hton(vapi_msg_wireguard_interface_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_interface_delete'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_wireguard_interface_delete_payload_hton(&msg->payload);
}

static inline void vapi_msg_wireguard_interface_delete_ntoh(vapi_msg_wireguard_interface_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_interface_delete'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_wireguard_interface_delete_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_wireguard_interface_delete_msg_size(vapi_msg_wireguard_interface_delete *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_wireguard_interface_delete_msg_size(vapi_msg_wireguard_interface_delete *msg, uword buf_size)
{
  if (sizeof(vapi_msg_wireguard_interface_delete) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_interface_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_wireguard_interface_delete));
      return -1;
    }
  if (vapi_calc_wireguard_interface_delete_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_interface_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_wireguard_interface_delete_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_wireguard_interface_delete* vapi_alloc_wireguard_interface_delete(struct vapi_ctx_s *ctx)
{
  vapi_msg_wireguard_interface_delete *msg = NULL;
  const size_t size = sizeof(vapi_msg_wireguard_interface_delete);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_wireguard_interface_delete*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_wireguard_interface_delete);

  return msg;
}

static inline vapi_error_e vapi_wireguard_interface_delete(struct vapi_ctx_s *ctx,
  vapi_msg_wireguard_interface_delete *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_wireguard_interface_delete_reply *reply),
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
  vapi_msg_wireguard_interface_delete_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_wireguard_interface_delete_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_wireguard_interface_delete_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_wireguard_interface_delete()
{
  static const char name[] = "wireguard_interface_delete";
  static const char name_with_crc[] = "wireguard_interface_delete_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_wireguard_interface_delete = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_wireguard_interface_delete, payload),
    (verify_msg_size_fn_t)vapi_verify_wireguard_interface_delete_msg_size,
    (generic_swap_fn_t)vapi_msg_wireguard_interface_delete_hton,
    (generic_swap_fn_t)vapi_msg_wireguard_interface_delete_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_wireguard_interface_delete = vapi_register_msg(&__vapi_metadata_wireguard_interface_delete);
  VAPI_DBG("Assigned msg id %d to wireguard_interface_delete", vapi_msg_id_wireguard_interface_delete);
}
#endif

#ifndef defined_vapi_msg_wireguard_interface_details
#define defined_vapi_msg_wireguard_interface_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_wireguard_interface interface; 
} vapi_payload_wireguard_interface_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_wireguard_interface_details payload;
} vapi_msg_wireguard_interface_details;

static inline void vapi_msg_wireguard_interface_details_payload_hton(vapi_payload_wireguard_interface_details *payload)
{
  vapi_type_wireguard_interface_hton(&payload->interface);
}

static inline void vapi_msg_wireguard_interface_details_payload_ntoh(vapi_payload_wireguard_interface_details *payload)
{
  vapi_type_wireguard_interface_ntoh(&payload->interface);
}

static inline void vapi_msg_wireguard_interface_details_hton(vapi_msg_wireguard_interface_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_interface_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_wireguard_interface_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_wireguard_interface_details_ntoh(vapi_msg_wireguard_interface_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_interface_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_wireguard_interface_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_wireguard_interface_details_msg_size(vapi_msg_wireguard_interface_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_wireguard_interface_details_msg_size(vapi_msg_wireguard_interface_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_wireguard_interface_details) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_interface_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_wireguard_interface_details));
      return -1;
    }
  if (vapi_calc_wireguard_interface_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_interface_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_wireguard_interface_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_wireguard_interface_details()
{
  static const char name[] = "wireguard_interface_details";
  static const char name_with_crc[] = "wireguard_interface_details_0dd4865d";
  static vapi_message_desc_t __vapi_metadata_wireguard_interface_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_wireguard_interface_details, payload),
    (verify_msg_size_fn_t)vapi_verify_wireguard_interface_details_msg_size,
    (generic_swap_fn_t)vapi_msg_wireguard_interface_details_hton,
    (generic_swap_fn_t)vapi_msg_wireguard_interface_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_wireguard_interface_details = vapi_register_msg(&__vapi_metadata_wireguard_interface_details);
  VAPI_DBG("Assigned msg id %d to wireguard_interface_details", vapi_msg_id_wireguard_interface_details);
}

static inline void vapi_set_vapi_msg_wireguard_interface_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_wireguard_interface_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_wireguard_interface_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_wireguard_interface_dump
#define defined_vapi_msg_wireguard_interface_dump
typedef struct __attribute__ ((__packed__)) {
  bool show_private_key;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_wireguard_interface_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_wireguard_interface_dump payload;
} vapi_msg_wireguard_interface_dump;

static inline void vapi_msg_wireguard_interface_dump_payload_hton(vapi_payload_wireguard_interface_dump *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_wireguard_interface_dump_payload_ntoh(vapi_payload_wireguard_interface_dump *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_wireguard_interface_dump_hton(vapi_msg_wireguard_interface_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_interface_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_wireguard_interface_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_wireguard_interface_dump_ntoh(vapi_msg_wireguard_interface_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_interface_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_wireguard_interface_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_wireguard_interface_dump_msg_size(vapi_msg_wireguard_interface_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_wireguard_interface_dump_msg_size(vapi_msg_wireguard_interface_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_wireguard_interface_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_interface_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_wireguard_interface_dump));
      return -1;
    }
  if (vapi_calc_wireguard_interface_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_interface_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_wireguard_interface_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_wireguard_interface_dump* vapi_alloc_wireguard_interface_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_wireguard_interface_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_wireguard_interface_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_wireguard_interface_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_wireguard_interface_dump);

  return msg;
}

static inline vapi_error_e vapi_wireguard_interface_dump(struct vapi_ctx_s *ctx,
  vapi_msg_wireguard_interface_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_wireguard_interface_details *reply),
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
  vapi_msg_wireguard_interface_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_wireguard_interface_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_wireguard_interface_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_wireguard_interface_dump()
{
  static const char name[] = "wireguard_interface_dump";
  static const char name_with_crc[] = "wireguard_interface_dump_2c954158";
  static vapi_message_desc_t __vapi_metadata_wireguard_interface_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_wireguard_interface_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_wireguard_interface_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_wireguard_interface_dump_hton,
    (generic_swap_fn_t)vapi_msg_wireguard_interface_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_wireguard_interface_dump = vapi_register_msg(&__vapi_metadata_wireguard_interface_dump);
  VAPI_DBG("Assigned msg id %d to wireguard_interface_dump", vapi_msg_id_wireguard_interface_dump);
}
#endif

#ifndef defined_vapi_msg_want_wireguard_peer_events_reply
#define defined_vapi_msg_want_wireguard_peer_events_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_want_wireguard_peer_events_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_want_wireguard_peer_events_reply payload;
} vapi_msg_want_wireguard_peer_events_reply;

static inline void vapi_msg_want_wireguard_peer_events_reply_payload_hton(vapi_payload_want_wireguard_peer_events_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_want_wireguard_peer_events_reply_payload_ntoh(vapi_payload_want_wireguard_peer_events_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_want_wireguard_peer_events_reply_hton(vapi_msg_want_wireguard_peer_events_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_wireguard_peer_events_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_want_wireguard_peer_events_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_want_wireguard_peer_events_reply_ntoh(vapi_msg_want_wireguard_peer_events_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_wireguard_peer_events_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_want_wireguard_peer_events_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_want_wireguard_peer_events_reply_msg_size(vapi_msg_want_wireguard_peer_events_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_want_wireguard_peer_events_reply_msg_size(vapi_msg_want_wireguard_peer_events_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_want_wireguard_peer_events_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'want_wireguard_peer_events_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_want_wireguard_peer_events_reply));
      return -1;
    }
  if (vapi_calc_want_wireguard_peer_events_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'want_wireguard_peer_events_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_want_wireguard_peer_events_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_want_wireguard_peer_events_reply()
{
  static const char name[] = "want_wireguard_peer_events_reply";
  static const char name_with_crc[] = "want_wireguard_peer_events_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_want_wireguard_peer_events_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_want_wireguard_peer_events_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_want_wireguard_peer_events_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_want_wireguard_peer_events_reply_hton,
    (generic_swap_fn_t)vapi_msg_want_wireguard_peer_events_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_want_wireguard_peer_events_reply = vapi_register_msg(&__vapi_metadata_want_wireguard_peer_events_reply);
  VAPI_DBG("Assigned msg id %d to want_wireguard_peer_events_reply", vapi_msg_id_want_wireguard_peer_events_reply);
}

static inline void vapi_set_vapi_msg_want_wireguard_peer_events_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_want_wireguard_peer_events_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_want_wireguard_peer_events_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_want_wireguard_peer_events
#define defined_vapi_msg_want_wireguard_peer_events
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u32 peer_index;
  u32 enable_disable;
  u32 pid; 
} vapi_payload_want_wireguard_peer_events;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_want_wireguard_peer_events payload;
} vapi_msg_want_wireguard_peer_events;

static inline void vapi_msg_want_wireguard_peer_events_payload_hton(vapi_payload_want_wireguard_peer_events *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->peer_index = htobe32(payload->peer_index);
  payload->enable_disable = htobe32(payload->enable_disable);
  payload->pid = htobe32(payload->pid);
}

static inline void vapi_msg_want_wireguard_peer_events_payload_ntoh(vapi_payload_want_wireguard_peer_events *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->peer_index = be32toh(payload->peer_index);
  payload->enable_disable = be32toh(payload->enable_disable);
  payload->pid = be32toh(payload->pid);
}

static inline void vapi_msg_want_wireguard_peer_events_hton(vapi_msg_want_wireguard_peer_events *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_wireguard_peer_events'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_want_wireguard_peer_events_payload_hton(&msg->payload);
}

static inline void vapi_msg_want_wireguard_peer_events_ntoh(vapi_msg_want_wireguard_peer_events *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_wireguard_peer_events'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_want_wireguard_peer_events_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_want_wireguard_peer_events_msg_size(vapi_msg_want_wireguard_peer_events *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_want_wireguard_peer_events_msg_size(vapi_msg_want_wireguard_peer_events *msg, uword buf_size)
{
  if (sizeof(vapi_msg_want_wireguard_peer_events) > buf_size)
    {
      VAPI_ERR("Truncated 'want_wireguard_peer_events' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_want_wireguard_peer_events));
      return -1;
    }
  if (vapi_calc_want_wireguard_peer_events_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'want_wireguard_peer_events' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_want_wireguard_peer_events_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_want_wireguard_peer_events* vapi_alloc_want_wireguard_peer_events(struct vapi_ctx_s *ctx)
{
  vapi_msg_want_wireguard_peer_events *msg = NULL;
  const size_t size = sizeof(vapi_msg_want_wireguard_peer_events);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_want_wireguard_peer_events*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_want_wireguard_peer_events);

  return msg;
}

static inline vapi_error_e vapi_want_wireguard_peer_events(struct vapi_ctx_s *ctx,
  vapi_msg_want_wireguard_peer_events *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_want_wireguard_peer_events_reply *reply),
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
  vapi_msg_want_wireguard_peer_events_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_want_wireguard_peer_events_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_want_wireguard_peer_events_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_want_wireguard_peer_events()
{
  static const char name[] = "want_wireguard_peer_events";
  static const char name_with_crc[] = "want_wireguard_peer_events_3bc666c8";
  static vapi_message_desc_t __vapi_metadata_want_wireguard_peer_events = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_want_wireguard_peer_events, payload),
    (verify_msg_size_fn_t)vapi_verify_want_wireguard_peer_events_msg_size,
    (generic_swap_fn_t)vapi_msg_want_wireguard_peer_events_hton,
    (generic_swap_fn_t)vapi_msg_want_wireguard_peer_events_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_want_wireguard_peer_events = vapi_register_msg(&__vapi_metadata_want_wireguard_peer_events);
  VAPI_DBG("Assigned msg id %d to want_wireguard_peer_events", vapi_msg_id_want_wireguard_peer_events);
}
#endif

#ifndef defined_vapi_msg_wireguard_peer_event
#define defined_vapi_msg_wireguard_peer_event
typedef struct __attribute__ ((__packed__)) {
  u16 _vl_msg_id;
  u32 client_index;
  u32 pid;
  u32 peer_index;
  vapi_enum_wireguard_peer_flags flags; 
} vapi_payload_wireguard_peer_event;

typedef struct __attribute__ ((__packed__)) {

  vapi_payload_wireguard_peer_event payload;
} vapi_msg_wireguard_peer_event;

static inline void vapi_msg_wireguard_peer_event_payload_hton(vapi_payload_wireguard_peer_event *payload)
{
  payload->_vl_msg_id = htobe16(payload->_vl_msg_id);
  payload->client_index = htobe32(payload->client_index);
  payload->pid = htobe32(payload->pid);
  payload->peer_index = htobe32(payload->peer_index);
}

static inline void vapi_msg_wireguard_peer_event_payload_ntoh(vapi_payload_wireguard_peer_event *payload)
{
  payload->_vl_msg_id = be16toh(payload->_vl_msg_id);
  payload->client_index = be32toh(payload->client_index);
  payload->pid = be32toh(payload->pid);
  payload->peer_index = be32toh(payload->peer_index);
}

static inline void vapi_msg_wireguard_peer_event_hton(vapi_msg_wireguard_peer_event *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_peer_event'@%p to big endian", msg);

  vapi_msg_wireguard_peer_event_payload_hton(&msg->payload);
}

static inline void vapi_msg_wireguard_peer_event_ntoh(vapi_msg_wireguard_peer_event *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_peer_event'@%p to host byte order", msg);

  vapi_msg_wireguard_peer_event_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_wireguard_peer_event_msg_size(vapi_msg_wireguard_peer_event *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_wireguard_peer_event_msg_size(vapi_msg_wireguard_peer_event *msg, uword buf_size)
{
  if (sizeof(vapi_msg_wireguard_peer_event) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_peer_event' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_wireguard_peer_event));
      return -1;
    }
  if (vapi_calc_wireguard_peer_event_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_peer_event' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_wireguard_peer_event_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_wireguard_peer_event()
{
  static const char name[] = "wireguard_peer_event";
  static const char name_with_crc[] = "wireguard_peer_event_4e1b5d67";
  static vapi_message_desc_t __vapi_metadata_wireguard_peer_event = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    false,
    0,
    offsetof(vapi_msg_wireguard_peer_event, payload),
    (verify_msg_size_fn_t)vapi_verify_wireguard_peer_event_msg_size,
    (generic_swap_fn_t)vapi_msg_wireguard_peer_event_hton,
    (generic_swap_fn_t)vapi_msg_wireguard_peer_event_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_wireguard_peer_event = vapi_register_msg(&__vapi_metadata_wireguard_peer_event);
  VAPI_DBG("Assigned msg id %d to wireguard_peer_event", vapi_msg_id_wireguard_peer_event);
}

static inline void vapi_set_vapi_msg_wireguard_peer_event_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_wireguard_peer_event *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_wireguard_peer_event, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_wireguard_peer_add_reply
#define defined_vapi_msg_wireguard_peer_add_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 peer_index; 
} vapi_payload_wireguard_peer_add_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_wireguard_peer_add_reply payload;
} vapi_msg_wireguard_peer_add_reply;

static inline void vapi_msg_wireguard_peer_add_reply_payload_hton(vapi_payload_wireguard_peer_add_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->peer_index = htobe32(payload->peer_index);
}

static inline void vapi_msg_wireguard_peer_add_reply_payload_ntoh(vapi_payload_wireguard_peer_add_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->peer_index = be32toh(payload->peer_index);
}

static inline void vapi_msg_wireguard_peer_add_reply_hton(vapi_msg_wireguard_peer_add_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_peer_add_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_wireguard_peer_add_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_wireguard_peer_add_reply_ntoh(vapi_msg_wireguard_peer_add_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_peer_add_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_wireguard_peer_add_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_wireguard_peer_add_reply_msg_size(vapi_msg_wireguard_peer_add_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_wireguard_peer_add_reply_msg_size(vapi_msg_wireguard_peer_add_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_wireguard_peer_add_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_peer_add_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_wireguard_peer_add_reply));
      return -1;
    }
  if (vapi_calc_wireguard_peer_add_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_peer_add_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_wireguard_peer_add_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_wireguard_peer_add_reply()
{
  static const char name[] = "wireguard_peer_add_reply";
  static const char name_with_crc[] = "wireguard_peer_add_reply_084a0cd3";
  static vapi_message_desc_t __vapi_metadata_wireguard_peer_add_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_wireguard_peer_add_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_wireguard_peer_add_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_wireguard_peer_add_reply_hton,
    (generic_swap_fn_t)vapi_msg_wireguard_peer_add_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_wireguard_peer_add_reply = vapi_register_msg(&__vapi_metadata_wireguard_peer_add_reply);
  VAPI_DBG("Assigned msg id %d to wireguard_peer_add_reply", vapi_msg_id_wireguard_peer_add_reply);
}

static inline void vapi_set_vapi_msg_wireguard_peer_add_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_wireguard_peer_add_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_wireguard_peer_add_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_wireguard_peer_add
#define defined_vapi_msg_wireguard_peer_add
typedef struct __attribute__ ((__packed__)) {
  vapi_type_wireguard_peer peer; 
} vapi_payload_wireguard_peer_add;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_wireguard_peer_add payload;
} vapi_msg_wireguard_peer_add;

static inline void vapi_msg_wireguard_peer_add_payload_hton(vapi_payload_wireguard_peer_add *payload)
{
  vapi_type_wireguard_peer_hton(&payload->peer);
}

static inline void vapi_msg_wireguard_peer_add_payload_ntoh(vapi_payload_wireguard_peer_add *payload)
{
  vapi_type_wireguard_peer_ntoh(&payload->peer);
}

static inline void vapi_msg_wireguard_peer_add_hton(vapi_msg_wireguard_peer_add *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_peer_add'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_wireguard_peer_add_payload_hton(&msg->payload);
}

static inline void vapi_msg_wireguard_peer_add_ntoh(vapi_msg_wireguard_peer_add *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_peer_add'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_wireguard_peer_add_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_wireguard_peer_add_msg_size(vapi_msg_wireguard_peer_add *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.peer.allowed_ips[0]) * msg->payload.peer.n_allowed_ips;
}

static inline int vapi_verify_wireguard_peer_add_msg_size(vapi_msg_wireguard_peer_add *msg, uword buf_size)
{
  if (sizeof(vapi_msg_wireguard_peer_add) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_peer_add' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_wireguard_peer_add));
      return -1;
    }
  if (vapi_calc_wireguard_peer_add_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_peer_add' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_wireguard_peer_add_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_wireguard_peer_add* vapi_alloc_wireguard_peer_add(struct vapi_ctx_s *ctx, size_t peer_allowed_ips_array_size)
{
  vapi_msg_wireguard_peer_add *msg = NULL;
  const size_t size = sizeof(vapi_msg_wireguard_peer_add) + sizeof(msg->payload.peer.allowed_ips[0]) * peer_allowed_ips_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_wireguard_peer_add*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_wireguard_peer_add);
  msg->payload.peer.n_allowed_ips = peer_allowed_ips_array_size;

  return msg;
}

static inline vapi_error_e vapi_wireguard_peer_add(struct vapi_ctx_s *ctx,
  vapi_msg_wireguard_peer_add *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_wireguard_peer_add_reply *reply),
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
  vapi_msg_wireguard_peer_add_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_wireguard_peer_add_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_wireguard_peer_add_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_wireguard_peer_add()
{
  static const char name[] = "wireguard_peer_add";
  static const char name_with_crc[] = "wireguard_peer_add_9b8aad61";
  static vapi_message_desc_t __vapi_metadata_wireguard_peer_add = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_wireguard_peer_add, payload),
    (verify_msg_size_fn_t)vapi_verify_wireguard_peer_add_msg_size,
    (generic_swap_fn_t)vapi_msg_wireguard_peer_add_hton,
    (generic_swap_fn_t)vapi_msg_wireguard_peer_add_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_wireguard_peer_add = vapi_register_msg(&__vapi_metadata_wireguard_peer_add);
  VAPI_DBG("Assigned msg id %d to wireguard_peer_add", vapi_msg_id_wireguard_peer_add);
}
#endif

#ifndef defined_vapi_msg_wireguard_peer_remove_reply
#define defined_vapi_msg_wireguard_peer_remove_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_wireguard_peer_remove_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_wireguard_peer_remove_reply payload;
} vapi_msg_wireguard_peer_remove_reply;

static inline void vapi_msg_wireguard_peer_remove_reply_payload_hton(vapi_payload_wireguard_peer_remove_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_wireguard_peer_remove_reply_payload_ntoh(vapi_payload_wireguard_peer_remove_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_wireguard_peer_remove_reply_hton(vapi_msg_wireguard_peer_remove_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_peer_remove_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_wireguard_peer_remove_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_wireguard_peer_remove_reply_ntoh(vapi_msg_wireguard_peer_remove_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_peer_remove_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_wireguard_peer_remove_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_wireguard_peer_remove_reply_msg_size(vapi_msg_wireguard_peer_remove_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_wireguard_peer_remove_reply_msg_size(vapi_msg_wireguard_peer_remove_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_wireguard_peer_remove_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_peer_remove_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_wireguard_peer_remove_reply));
      return -1;
    }
  if (vapi_calc_wireguard_peer_remove_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_peer_remove_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_wireguard_peer_remove_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_wireguard_peer_remove_reply()
{
  static const char name[] = "wireguard_peer_remove_reply";
  static const char name_with_crc[] = "wireguard_peer_remove_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_wireguard_peer_remove_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_wireguard_peer_remove_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_wireguard_peer_remove_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_wireguard_peer_remove_reply_hton,
    (generic_swap_fn_t)vapi_msg_wireguard_peer_remove_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_wireguard_peer_remove_reply = vapi_register_msg(&__vapi_metadata_wireguard_peer_remove_reply);
  VAPI_DBG("Assigned msg id %d to wireguard_peer_remove_reply", vapi_msg_id_wireguard_peer_remove_reply);
}

static inline void vapi_set_vapi_msg_wireguard_peer_remove_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_wireguard_peer_remove_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_wireguard_peer_remove_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_wireguard_peer_remove
#define defined_vapi_msg_wireguard_peer_remove
typedef struct __attribute__ ((__packed__)) {
  u32 peer_index; 
} vapi_payload_wireguard_peer_remove;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_wireguard_peer_remove payload;
} vapi_msg_wireguard_peer_remove;

static inline void vapi_msg_wireguard_peer_remove_payload_hton(vapi_payload_wireguard_peer_remove *payload)
{
  payload->peer_index = htobe32(payload->peer_index);
}

static inline void vapi_msg_wireguard_peer_remove_payload_ntoh(vapi_payload_wireguard_peer_remove *payload)
{
  payload->peer_index = be32toh(payload->peer_index);
}

static inline void vapi_msg_wireguard_peer_remove_hton(vapi_msg_wireguard_peer_remove *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_peer_remove'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_wireguard_peer_remove_payload_hton(&msg->payload);
}

static inline void vapi_msg_wireguard_peer_remove_ntoh(vapi_msg_wireguard_peer_remove *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_peer_remove'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_wireguard_peer_remove_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_wireguard_peer_remove_msg_size(vapi_msg_wireguard_peer_remove *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_wireguard_peer_remove_msg_size(vapi_msg_wireguard_peer_remove *msg, uword buf_size)
{
  if (sizeof(vapi_msg_wireguard_peer_remove) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_peer_remove' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_wireguard_peer_remove));
      return -1;
    }
  if (vapi_calc_wireguard_peer_remove_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_peer_remove' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_wireguard_peer_remove_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_wireguard_peer_remove* vapi_alloc_wireguard_peer_remove(struct vapi_ctx_s *ctx)
{
  vapi_msg_wireguard_peer_remove *msg = NULL;
  const size_t size = sizeof(vapi_msg_wireguard_peer_remove);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_wireguard_peer_remove*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_wireguard_peer_remove);

  return msg;
}

static inline vapi_error_e vapi_wireguard_peer_remove(struct vapi_ctx_s *ctx,
  vapi_msg_wireguard_peer_remove *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_wireguard_peer_remove_reply *reply),
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
  vapi_msg_wireguard_peer_remove_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_wireguard_peer_remove_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_wireguard_peer_remove_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_wireguard_peer_remove()
{
  static const char name[] = "wireguard_peer_remove";
  static const char name_with_crc[] = "wireguard_peer_remove_3b74607a";
  static vapi_message_desc_t __vapi_metadata_wireguard_peer_remove = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_wireguard_peer_remove, payload),
    (verify_msg_size_fn_t)vapi_verify_wireguard_peer_remove_msg_size,
    (generic_swap_fn_t)vapi_msg_wireguard_peer_remove_hton,
    (generic_swap_fn_t)vapi_msg_wireguard_peer_remove_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_wireguard_peer_remove = vapi_register_msg(&__vapi_metadata_wireguard_peer_remove);
  VAPI_DBG("Assigned msg id %d to wireguard_peer_remove", vapi_msg_id_wireguard_peer_remove);
}
#endif

#ifndef defined_vapi_msg_wireguard_peers_details
#define defined_vapi_msg_wireguard_peers_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_wireguard_peer peer; 
} vapi_payload_wireguard_peers_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_wireguard_peers_details payload;
} vapi_msg_wireguard_peers_details;

static inline void vapi_msg_wireguard_peers_details_payload_hton(vapi_payload_wireguard_peers_details *payload)
{
  vapi_type_wireguard_peer_hton(&payload->peer);
}

static inline void vapi_msg_wireguard_peers_details_payload_ntoh(vapi_payload_wireguard_peers_details *payload)
{
  vapi_type_wireguard_peer_ntoh(&payload->peer);
}

static inline void vapi_msg_wireguard_peers_details_hton(vapi_msg_wireguard_peers_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_peers_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_wireguard_peers_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_wireguard_peers_details_ntoh(vapi_msg_wireguard_peers_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_peers_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_wireguard_peers_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_wireguard_peers_details_msg_size(vapi_msg_wireguard_peers_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.peer.allowed_ips[0]) * msg->payload.peer.n_allowed_ips;
}

static inline int vapi_verify_wireguard_peers_details_msg_size(vapi_msg_wireguard_peers_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_wireguard_peers_details) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_peers_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_wireguard_peers_details));
      return -1;
    }
  if (vapi_calc_wireguard_peers_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_peers_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_wireguard_peers_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_wireguard_peers_details()
{
  static const char name[] = "wireguard_peers_details";
  static const char name_with_crc[] = "wireguard_peers_details_6a9f6bc3";
  static vapi_message_desc_t __vapi_metadata_wireguard_peers_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_wireguard_peers_details, payload),
    (verify_msg_size_fn_t)vapi_verify_wireguard_peers_details_msg_size,
    (generic_swap_fn_t)vapi_msg_wireguard_peers_details_hton,
    (generic_swap_fn_t)vapi_msg_wireguard_peers_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_wireguard_peers_details = vapi_register_msg(&__vapi_metadata_wireguard_peers_details);
  VAPI_DBG("Assigned msg id %d to wireguard_peers_details", vapi_msg_id_wireguard_peers_details);
}

static inline void vapi_set_vapi_msg_wireguard_peers_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_wireguard_peers_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_wireguard_peers_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_wireguard_peers_dump
#define defined_vapi_msg_wireguard_peers_dump
typedef struct __attribute__ ((__packed__)) {
  u32 peer_index; 
} vapi_payload_wireguard_peers_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_wireguard_peers_dump payload;
} vapi_msg_wireguard_peers_dump;

static inline void vapi_msg_wireguard_peers_dump_payload_hton(vapi_payload_wireguard_peers_dump *payload)
{
  payload->peer_index = htobe32(payload->peer_index);
}

static inline void vapi_msg_wireguard_peers_dump_payload_ntoh(vapi_payload_wireguard_peers_dump *payload)
{
  payload->peer_index = be32toh(payload->peer_index);
}

static inline void vapi_msg_wireguard_peers_dump_hton(vapi_msg_wireguard_peers_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_peers_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_wireguard_peers_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_wireguard_peers_dump_ntoh(vapi_msg_wireguard_peers_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wireguard_peers_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_wireguard_peers_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_wireguard_peers_dump_msg_size(vapi_msg_wireguard_peers_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_wireguard_peers_dump_msg_size(vapi_msg_wireguard_peers_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_wireguard_peers_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_peers_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_wireguard_peers_dump));
      return -1;
    }
  if (vapi_calc_wireguard_peers_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'wireguard_peers_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_wireguard_peers_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_wireguard_peers_dump* vapi_alloc_wireguard_peers_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_wireguard_peers_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_wireguard_peers_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_wireguard_peers_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_wireguard_peers_dump);

  return msg;
}

static inline vapi_error_e vapi_wireguard_peers_dump(struct vapi_ctx_s *ctx,
  vapi_msg_wireguard_peers_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_wireguard_peers_details *reply),
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
  vapi_msg_wireguard_peers_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_wireguard_peers_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_wireguard_peers_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_wireguard_peers_dump()
{
  static const char name[] = "wireguard_peers_dump";
  static const char name_with_crc[] = "wireguard_peers_dump_3b74607a";
  static vapi_message_desc_t __vapi_metadata_wireguard_peers_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_wireguard_peers_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_wireguard_peers_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_wireguard_peers_dump_hton,
    (generic_swap_fn_t)vapi_msg_wireguard_peers_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_wireguard_peers_dump = vapi_register_msg(&__vapi_metadata_wireguard_peers_dump);
  VAPI_DBG("Assigned msg id %d to wireguard_peers_dump", vapi_msg_id_wireguard_peers_dump);
}
#endif

#ifndef defined_vapi_msg_wg_set_async_mode_reply
#define defined_vapi_msg_wg_set_async_mode_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_wg_set_async_mode_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_wg_set_async_mode_reply payload;
} vapi_msg_wg_set_async_mode_reply;

static inline void vapi_msg_wg_set_async_mode_reply_payload_hton(vapi_payload_wg_set_async_mode_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_wg_set_async_mode_reply_payload_ntoh(vapi_payload_wg_set_async_mode_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_wg_set_async_mode_reply_hton(vapi_msg_wg_set_async_mode_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wg_set_async_mode_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_wg_set_async_mode_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_wg_set_async_mode_reply_ntoh(vapi_msg_wg_set_async_mode_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wg_set_async_mode_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_wg_set_async_mode_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_wg_set_async_mode_reply_msg_size(vapi_msg_wg_set_async_mode_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_wg_set_async_mode_reply_msg_size(vapi_msg_wg_set_async_mode_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_wg_set_async_mode_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'wg_set_async_mode_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_wg_set_async_mode_reply));
      return -1;
    }
  if (vapi_calc_wg_set_async_mode_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'wg_set_async_mode_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_wg_set_async_mode_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_wg_set_async_mode_reply()
{
  static const char name[] = "wg_set_async_mode_reply";
  static const char name_with_crc[] = "wg_set_async_mode_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_wg_set_async_mode_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_wg_set_async_mode_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_wg_set_async_mode_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_wg_set_async_mode_reply_hton,
    (generic_swap_fn_t)vapi_msg_wg_set_async_mode_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_wg_set_async_mode_reply = vapi_register_msg(&__vapi_metadata_wg_set_async_mode_reply);
  VAPI_DBG("Assigned msg id %d to wg_set_async_mode_reply", vapi_msg_id_wg_set_async_mode_reply);
}

static inline void vapi_set_vapi_msg_wg_set_async_mode_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_wg_set_async_mode_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_wg_set_async_mode_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_wg_set_async_mode
#define defined_vapi_msg_wg_set_async_mode
typedef struct __attribute__ ((__packed__)) {
  bool async_enable; 
} vapi_payload_wg_set_async_mode;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_wg_set_async_mode payload;
} vapi_msg_wg_set_async_mode;

static inline void vapi_msg_wg_set_async_mode_payload_hton(vapi_payload_wg_set_async_mode *payload)
{

}

static inline void vapi_msg_wg_set_async_mode_payload_ntoh(vapi_payload_wg_set_async_mode *payload)
{

}

static inline void vapi_msg_wg_set_async_mode_hton(vapi_msg_wg_set_async_mode *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wg_set_async_mode'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_wg_set_async_mode_payload_hton(&msg->payload);
}

static inline void vapi_msg_wg_set_async_mode_ntoh(vapi_msg_wg_set_async_mode *msg)
{
  VAPI_DBG("Swapping `vapi_msg_wg_set_async_mode'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_wg_set_async_mode_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_wg_set_async_mode_msg_size(vapi_msg_wg_set_async_mode *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_wg_set_async_mode_msg_size(vapi_msg_wg_set_async_mode *msg, uword buf_size)
{
  if (sizeof(vapi_msg_wg_set_async_mode) > buf_size)
    {
      VAPI_ERR("Truncated 'wg_set_async_mode' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_wg_set_async_mode));
      return -1;
    }
  if (vapi_calc_wg_set_async_mode_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'wg_set_async_mode' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_wg_set_async_mode_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_wg_set_async_mode* vapi_alloc_wg_set_async_mode(struct vapi_ctx_s *ctx)
{
  vapi_msg_wg_set_async_mode *msg = NULL;
  const size_t size = sizeof(vapi_msg_wg_set_async_mode);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_wg_set_async_mode*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_wg_set_async_mode);

  return msg;
}

static inline vapi_error_e vapi_wg_set_async_mode(struct vapi_ctx_s *ctx,
  vapi_msg_wg_set_async_mode *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_wg_set_async_mode_reply *reply),
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
  vapi_msg_wg_set_async_mode_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_wg_set_async_mode_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_wg_set_async_mode_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_wg_set_async_mode()
{
  static const char name[] = "wg_set_async_mode";
  static const char name_with_crc[] = "wg_set_async_mode_a6465f7c";
  static vapi_message_desc_t __vapi_metadata_wg_set_async_mode = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_wg_set_async_mode, payload),
    (verify_msg_size_fn_t)vapi_verify_wg_set_async_mode_msg_size,
    (generic_swap_fn_t)vapi_msg_wg_set_async_mode_hton,
    (generic_swap_fn_t)vapi_msg_wg_set_async_mode_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_wg_set_async_mode = vapi_register_msg(&__vapi_metadata_wg_set_async_mode);
  VAPI_DBG("Assigned msg id %d to wg_set_async_mode", vapi_msg_id_wg_set_async_mode);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
