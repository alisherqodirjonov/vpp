#ifndef __included_pnat_api_json
#define __included_pnat_api_json

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

extern vapi_msg_id_t vapi_msg_id_pnat_binding_add;
extern vapi_msg_id_t vapi_msg_id_pnat_binding_add_reply;
extern vapi_msg_id_t vapi_msg_id_pnat_binding_add_v2;
extern vapi_msg_id_t vapi_msg_id_pnat_binding_add_v2_reply;
extern vapi_msg_id_t vapi_msg_id_pnat_binding_del;
extern vapi_msg_id_t vapi_msg_id_pnat_binding_del_reply;
extern vapi_msg_id_t vapi_msg_id_pnat_binding_attach;
extern vapi_msg_id_t vapi_msg_id_pnat_binding_attach_reply;
extern vapi_msg_id_t vapi_msg_id_pnat_binding_detach;
extern vapi_msg_id_t vapi_msg_id_pnat_binding_detach_reply;
extern vapi_msg_id_t vapi_msg_id_pnat_bindings_get;
extern vapi_msg_id_t vapi_msg_id_pnat_bindings_get_reply;
extern vapi_msg_id_t vapi_msg_id_pnat_bindings_details;
extern vapi_msg_id_t vapi_msg_id_pnat_interfaces_get;
extern vapi_msg_id_t vapi_msg_id_pnat_interfaces_get_reply;
extern vapi_msg_id_t vapi_msg_id_pnat_interfaces_details;
extern vapi_msg_id_t vapi_msg_id_pnat_flow_lookup;
extern vapi_msg_id_t vapi_msg_id_pnat_flow_lookup_reply;

#define DEFINE_VAPI_MSG_IDS_PNAT_API_JSON\
  vapi_msg_id_t vapi_msg_id_pnat_binding_add;\
  vapi_msg_id_t vapi_msg_id_pnat_binding_add_reply;\
  vapi_msg_id_t vapi_msg_id_pnat_binding_add_v2;\
  vapi_msg_id_t vapi_msg_id_pnat_binding_add_v2_reply;\
  vapi_msg_id_t vapi_msg_id_pnat_binding_del;\
  vapi_msg_id_t vapi_msg_id_pnat_binding_del_reply;\
  vapi_msg_id_t vapi_msg_id_pnat_binding_attach;\
  vapi_msg_id_t vapi_msg_id_pnat_binding_attach_reply;\
  vapi_msg_id_t vapi_msg_id_pnat_binding_detach;\
  vapi_msg_id_t vapi_msg_id_pnat_binding_detach_reply;\
  vapi_msg_id_t vapi_msg_id_pnat_bindings_get;\
  vapi_msg_id_t vapi_msg_id_pnat_bindings_get_reply;\
  vapi_msg_id_t vapi_msg_id_pnat_bindings_details;\
  vapi_msg_id_t vapi_msg_id_pnat_interfaces_get;\
  vapi_msg_id_t vapi_msg_id_pnat_interfaces_get_reply;\
  vapi_msg_id_t vapi_msg_id_pnat_interfaces_details;\
  vapi_msg_id_t vapi_msg_id_pnat_flow_lookup;\
  vapi_msg_id_t vapi_msg_id_pnat_flow_lookup_reply;


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

#ifndef defined_vapi_enum_pnat_mask
#define defined_vapi_enum_pnat_mask
typedef enum {
  PNAT_SA = 1,
  PNAT_DA = 2,
  PNAT_SPORT = 4,
  PNAT_DPORT = 8,
  PNAT_COPY_BYTE = 16,
  PNAT_CLEAR_BYTE = 32,
  PNAT_PROTO = 64,
}  vapi_enum_pnat_mask;

#endif

#ifndef defined_vapi_enum_pnat_attachment_point
#define defined_vapi_enum_pnat_attachment_point
typedef enum {
  PNAT_IP4_INPUT = 0,
  PNAT_IP4_OUTPUT = 1,
  PNAT_ATTACHMENT_POINT_MAX = 2,
}  vapi_enum_pnat_attachment_point;

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

#ifndef defined_vapi_type_pnat_match_tuple
#define defined_vapi_type_pnat_match_tuple
typedef struct __attribute__((__packed__)) {
  vapi_type_ip4_address src;
  vapi_type_ip4_address dst;
  vapi_enum_ip_proto proto;
  u16 sport;
  u16 dport;
  vapi_enum_pnat_mask mask;
} vapi_type_pnat_match_tuple;

static inline void vapi_type_pnat_match_tuple_hton(vapi_type_pnat_match_tuple *msg)
{
  msg->sport = htobe16(msg->sport);
  msg->dport = htobe16(msg->dport);
  msg->mask = (vapi_enum_pnat_mask)htobe32(msg->mask);
}

static inline void vapi_type_pnat_match_tuple_ntoh(vapi_type_pnat_match_tuple *msg)
{
  msg->sport = be16toh(msg->sport);
  msg->dport = be16toh(msg->dport);
  msg->mask = (vapi_enum_pnat_mask)be32toh(msg->mask);
}
#endif

#ifndef defined_vapi_type_pnat_rewrite_tuple
#define defined_vapi_type_pnat_rewrite_tuple
typedef struct __attribute__((__packed__)) {
  vapi_type_ip4_address src;
  vapi_type_ip4_address dst;
  u16 sport;
  u16 dport;
  vapi_enum_pnat_mask mask;
  u8 from_offset;
  u8 to_offset;
  u8 clear_offset;
} vapi_type_pnat_rewrite_tuple;

static inline void vapi_type_pnat_rewrite_tuple_hton(vapi_type_pnat_rewrite_tuple *msg)
{
  msg->sport = htobe16(msg->sport);
  msg->dport = htobe16(msg->dport);
  msg->mask = (vapi_enum_pnat_mask)htobe32(msg->mask);
}

static inline void vapi_type_pnat_rewrite_tuple_ntoh(vapi_type_pnat_rewrite_tuple *msg)
{
  msg->sport = be16toh(msg->sport);
  msg->dport = be16toh(msg->dport);
  msg->mask = (vapi_enum_pnat_mask)be32toh(msg->mask);
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

#ifndef defined_vapi_msg_pnat_binding_add_reply
#define defined_vapi_msg_pnat_binding_add_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 binding_index; 
} vapi_payload_pnat_binding_add_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_pnat_binding_add_reply payload;
} vapi_msg_pnat_binding_add_reply;

static inline void vapi_msg_pnat_binding_add_reply_payload_hton(vapi_payload_pnat_binding_add_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->binding_index = htobe32(payload->binding_index);
}

static inline void vapi_msg_pnat_binding_add_reply_payload_ntoh(vapi_payload_pnat_binding_add_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->binding_index = be32toh(payload->binding_index);
}

static inline void vapi_msg_pnat_binding_add_reply_hton(vapi_msg_pnat_binding_add_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_binding_add_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_pnat_binding_add_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_pnat_binding_add_reply_ntoh(vapi_msg_pnat_binding_add_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_binding_add_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_pnat_binding_add_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pnat_binding_add_reply_msg_size(vapi_msg_pnat_binding_add_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pnat_binding_add_reply_msg_size(vapi_msg_pnat_binding_add_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pnat_binding_add_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_binding_add_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pnat_binding_add_reply));
      return -1;
    }
  if (vapi_calc_pnat_binding_add_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_binding_add_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pnat_binding_add_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_pnat_binding_add_reply()
{
  static const char name[] = "pnat_binding_add_reply";
  static const char name_with_crc[] = "pnat_binding_add_reply_4cd980a7";
  static vapi_message_desc_t __vapi_metadata_pnat_binding_add_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_pnat_binding_add_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_pnat_binding_add_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_pnat_binding_add_reply_hton,
    (generic_swap_fn_t)vapi_msg_pnat_binding_add_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pnat_binding_add_reply = vapi_register_msg(&__vapi_metadata_pnat_binding_add_reply);
  VAPI_DBG("Assigned msg id %d to pnat_binding_add_reply", vapi_msg_id_pnat_binding_add_reply);
}

static inline void vapi_set_vapi_msg_pnat_binding_add_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_pnat_binding_add_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_pnat_binding_add_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_pnat_binding_add
#define defined_vapi_msg_pnat_binding_add
typedef struct __attribute__ ((__packed__)) {
  vapi_type_pnat_match_tuple match;
  vapi_type_pnat_rewrite_tuple rewrite; 
} vapi_payload_pnat_binding_add;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_pnat_binding_add payload;
} vapi_msg_pnat_binding_add;

static inline void vapi_msg_pnat_binding_add_payload_hton(vapi_payload_pnat_binding_add *payload)
{
  vapi_type_pnat_match_tuple_hton(&payload->match);
  vapi_type_pnat_rewrite_tuple_hton(&payload->rewrite);
}

static inline void vapi_msg_pnat_binding_add_payload_ntoh(vapi_payload_pnat_binding_add *payload)
{
  vapi_type_pnat_match_tuple_ntoh(&payload->match);
  vapi_type_pnat_rewrite_tuple_ntoh(&payload->rewrite);
}

static inline void vapi_msg_pnat_binding_add_hton(vapi_msg_pnat_binding_add *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_binding_add'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_pnat_binding_add_payload_hton(&msg->payload);
}

static inline void vapi_msg_pnat_binding_add_ntoh(vapi_msg_pnat_binding_add *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_binding_add'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_pnat_binding_add_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pnat_binding_add_msg_size(vapi_msg_pnat_binding_add *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pnat_binding_add_msg_size(vapi_msg_pnat_binding_add *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pnat_binding_add) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_binding_add' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pnat_binding_add));
      return -1;
    }
  if (vapi_calc_pnat_binding_add_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_binding_add' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pnat_binding_add_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_pnat_binding_add* vapi_alloc_pnat_binding_add(struct vapi_ctx_s *ctx)
{
  vapi_msg_pnat_binding_add *msg = NULL;
  const size_t size = sizeof(vapi_msg_pnat_binding_add);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_pnat_binding_add*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_pnat_binding_add);

  return msg;
}

static inline vapi_error_e vapi_pnat_binding_add(struct vapi_ctx_s *ctx,
  vapi_msg_pnat_binding_add *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_pnat_binding_add_reply *reply),
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
  vapi_msg_pnat_binding_add_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_pnat_binding_add_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_pnat_binding_add_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_pnat_binding_add()
{
  static const char name[] = "pnat_binding_add";
  static const char name_with_crc[] = "pnat_binding_add_946ee0b7";
  static vapi_message_desc_t __vapi_metadata_pnat_binding_add = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_pnat_binding_add, payload),
    (verify_msg_size_fn_t)vapi_verify_pnat_binding_add_msg_size,
    (generic_swap_fn_t)vapi_msg_pnat_binding_add_hton,
    (generic_swap_fn_t)vapi_msg_pnat_binding_add_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pnat_binding_add = vapi_register_msg(&__vapi_metadata_pnat_binding_add);
  VAPI_DBG("Assigned msg id %d to pnat_binding_add", vapi_msg_id_pnat_binding_add);
}
#endif

#ifndef defined_vapi_msg_pnat_binding_add_v2_reply
#define defined_vapi_msg_pnat_binding_add_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 binding_index; 
} vapi_payload_pnat_binding_add_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_pnat_binding_add_v2_reply payload;
} vapi_msg_pnat_binding_add_v2_reply;

static inline void vapi_msg_pnat_binding_add_v2_reply_payload_hton(vapi_payload_pnat_binding_add_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->binding_index = htobe32(payload->binding_index);
}

static inline void vapi_msg_pnat_binding_add_v2_reply_payload_ntoh(vapi_payload_pnat_binding_add_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->binding_index = be32toh(payload->binding_index);
}

static inline void vapi_msg_pnat_binding_add_v2_reply_hton(vapi_msg_pnat_binding_add_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_binding_add_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_pnat_binding_add_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_pnat_binding_add_v2_reply_ntoh(vapi_msg_pnat_binding_add_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_binding_add_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_pnat_binding_add_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pnat_binding_add_v2_reply_msg_size(vapi_msg_pnat_binding_add_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pnat_binding_add_v2_reply_msg_size(vapi_msg_pnat_binding_add_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pnat_binding_add_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_binding_add_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pnat_binding_add_v2_reply));
      return -1;
    }
  if (vapi_calc_pnat_binding_add_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_binding_add_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pnat_binding_add_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_pnat_binding_add_v2_reply()
{
  static const char name[] = "pnat_binding_add_v2_reply";
  static const char name_with_crc[] = "pnat_binding_add_v2_reply_4cd980a7";
  static vapi_message_desc_t __vapi_metadata_pnat_binding_add_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_pnat_binding_add_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_pnat_binding_add_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_pnat_binding_add_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_pnat_binding_add_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pnat_binding_add_v2_reply = vapi_register_msg(&__vapi_metadata_pnat_binding_add_v2_reply);
  VAPI_DBG("Assigned msg id %d to pnat_binding_add_v2_reply", vapi_msg_id_pnat_binding_add_v2_reply);
}

static inline void vapi_set_vapi_msg_pnat_binding_add_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_pnat_binding_add_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_pnat_binding_add_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_pnat_binding_add_v2
#define defined_vapi_msg_pnat_binding_add_v2
typedef struct __attribute__ ((__packed__)) {
  vapi_type_pnat_match_tuple match;
  vapi_type_pnat_rewrite_tuple rewrite; 
} vapi_payload_pnat_binding_add_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_pnat_binding_add_v2 payload;
} vapi_msg_pnat_binding_add_v2;

static inline void vapi_msg_pnat_binding_add_v2_payload_hton(vapi_payload_pnat_binding_add_v2 *payload)
{
  vapi_type_pnat_match_tuple_hton(&payload->match);
  vapi_type_pnat_rewrite_tuple_hton(&payload->rewrite);
}

static inline void vapi_msg_pnat_binding_add_v2_payload_ntoh(vapi_payload_pnat_binding_add_v2 *payload)
{
  vapi_type_pnat_match_tuple_ntoh(&payload->match);
  vapi_type_pnat_rewrite_tuple_ntoh(&payload->rewrite);
}

static inline void vapi_msg_pnat_binding_add_v2_hton(vapi_msg_pnat_binding_add_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_binding_add_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_pnat_binding_add_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_pnat_binding_add_v2_ntoh(vapi_msg_pnat_binding_add_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_binding_add_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_pnat_binding_add_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pnat_binding_add_v2_msg_size(vapi_msg_pnat_binding_add_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pnat_binding_add_v2_msg_size(vapi_msg_pnat_binding_add_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pnat_binding_add_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_binding_add_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pnat_binding_add_v2));
      return -1;
    }
  if (vapi_calc_pnat_binding_add_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_binding_add_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pnat_binding_add_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_pnat_binding_add_v2* vapi_alloc_pnat_binding_add_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_pnat_binding_add_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_pnat_binding_add_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_pnat_binding_add_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_pnat_binding_add_v2);

  return msg;
}

static inline vapi_error_e vapi_pnat_binding_add_v2(struct vapi_ctx_s *ctx,
  vapi_msg_pnat_binding_add_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_pnat_binding_add_v2_reply *reply),
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
  vapi_msg_pnat_binding_add_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_pnat_binding_add_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_pnat_binding_add_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_pnat_binding_add_v2()
{
  static const char name[] = "pnat_binding_add_v2";
  static const char name_with_crc[] = "pnat_binding_add_v2_946ee0b7";
  static vapi_message_desc_t __vapi_metadata_pnat_binding_add_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_pnat_binding_add_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_pnat_binding_add_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_pnat_binding_add_v2_hton,
    (generic_swap_fn_t)vapi_msg_pnat_binding_add_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pnat_binding_add_v2 = vapi_register_msg(&__vapi_metadata_pnat_binding_add_v2);
  VAPI_DBG("Assigned msg id %d to pnat_binding_add_v2", vapi_msg_id_pnat_binding_add_v2);
}
#endif

#ifndef defined_vapi_msg_pnat_binding_del_reply
#define defined_vapi_msg_pnat_binding_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_pnat_binding_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_pnat_binding_del_reply payload;
} vapi_msg_pnat_binding_del_reply;

static inline void vapi_msg_pnat_binding_del_reply_payload_hton(vapi_payload_pnat_binding_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_pnat_binding_del_reply_payload_ntoh(vapi_payload_pnat_binding_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_pnat_binding_del_reply_hton(vapi_msg_pnat_binding_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_binding_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_pnat_binding_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_pnat_binding_del_reply_ntoh(vapi_msg_pnat_binding_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_binding_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_pnat_binding_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pnat_binding_del_reply_msg_size(vapi_msg_pnat_binding_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pnat_binding_del_reply_msg_size(vapi_msg_pnat_binding_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pnat_binding_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_binding_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pnat_binding_del_reply));
      return -1;
    }
  if (vapi_calc_pnat_binding_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_binding_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pnat_binding_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_pnat_binding_del_reply()
{
  static const char name[] = "pnat_binding_del_reply";
  static const char name_with_crc[] = "pnat_binding_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_pnat_binding_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_pnat_binding_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_pnat_binding_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_pnat_binding_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_pnat_binding_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pnat_binding_del_reply = vapi_register_msg(&__vapi_metadata_pnat_binding_del_reply);
  VAPI_DBG("Assigned msg id %d to pnat_binding_del_reply", vapi_msg_id_pnat_binding_del_reply);
}

static inline void vapi_set_vapi_msg_pnat_binding_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_pnat_binding_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_pnat_binding_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_pnat_binding_del
#define defined_vapi_msg_pnat_binding_del
typedef struct __attribute__ ((__packed__)) {
  u32 binding_index; 
} vapi_payload_pnat_binding_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_pnat_binding_del payload;
} vapi_msg_pnat_binding_del;

static inline void vapi_msg_pnat_binding_del_payload_hton(vapi_payload_pnat_binding_del *payload)
{
  payload->binding_index = htobe32(payload->binding_index);
}

static inline void vapi_msg_pnat_binding_del_payload_ntoh(vapi_payload_pnat_binding_del *payload)
{
  payload->binding_index = be32toh(payload->binding_index);
}

static inline void vapi_msg_pnat_binding_del_hton(vapi_msg_pnat_binding_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_binding_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_pnat_binding_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_pnat_binding_del_ntoh(vapi_msg_pnat_binding_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_binding_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_pnat_binding_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pnat_binding_del_msg_size(vapi_msg_pnat_binding_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pnat_binding_del_msg_size(vapi_msg_pnat_binding_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pnat_binding_del) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_binding_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pnat_binding_del));
      return -1;
    }
  if (vapi_calc_pnat_binding_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_binding_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pnat_binding_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_pnat_binding_del* vapi_alloc_pnat_binding_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_pnat_binding_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_pnat_binding_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_pnat_binding_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_pnat_binding_del);

  return msg;
}

static inline vapi_error_e vapi_pnat_binding_del(struct vapi_ctx_s *ctx,
  vapi_msg_pnat_binding_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_pnat_binding_del_reply *reply),
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
  vapi_msg_pnat_binding_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_pnat_binding_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_pnat_binding_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_pnat_binding_del()
{
  static const char name[] = "pnat_binding_del";
  static const char name_with_crc[] = "pnat_binding_del_9259df7b";
  static vapi_message_desc_t __vapi_metadata_pnat_binding_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_pnat_binding_del, payload),
    (verify_msg_size_fn_t)vapi_verify_pnat_binding_del_msg_size,
    (generic_swap_fn_t)vapi_msg_pnat_binding_del_hton,
    (generic_swap_fn_t)vapi_msg_pnat_binding_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pnat_binding_del = vapi_register_msg(&__vapi_metadata_pnat_binding_del);
  VAPI_DBG("Assigned msg id %d to pnat_binding_del", vapi_msg_id_pnat_binding_del);
}
#endif

#ifndef defined_vapi_msg_pnat_binding_attach_reply
#define defined_vapi_msg_pnat_binding_attach_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_pnat_binding_attach_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_pnat_binding_attach_reply payload;
} vapi_msg_pnat_binding_attach_reply;

static inline void vapi_msg_pnat_binding_attach_reply_payload_hton(vapi_payload_pnat_binding_attach_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_pnat_binding_attach_reply_payload_ntoh(vapi_payload_pnat_binding_attach_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_pnat_binding_attach_reply_hton(vapi_msg_pnat_binding_attach_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_binding_attach_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_pnat_binding_attach_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_pnat_binding_attach_reply_ntoh(vapi_msg_pnat_binding_attach_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_binding_attach_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_pnat_binding_attach_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pnat_binding_attach_reply_msg_size(vapi_msg_pnat_binding_attach_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pnat_binding_attach_reply_msg_size(vapi_msg_pnat_binding_attach_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pnat_binding_attach_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_binding_attach_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pnat_binding_attach_reply));
      return -1;
    }
  if (vapi_calc_pnat_binding_attach_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_binding_attach_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pnat_binding_attach_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_pnat_binding_attach_reply()
{
  static const char name[] = "pnat_binding_attach_reply";
  static const char name_with_crc[] = "pnat_binding_attach_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_pnat_binding_attach_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_pnat_binding_attach_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_pnat_binding_attach_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_pnat_binding_attach_reply_hton,
    (generic_swap_fn_t)vapi_msg_pnat_binding_attach_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pnat_binding_attach_reply = vapi_register_msg(&__vapi_metadata_pnat_binding_attach_reply);
  VAPI_DBG("Assigned msg id %d to pnat_binding_attach_reply", vapi_msg_id_pnat_binding_attach_reply);
}

static inline void vapi_set_vapi_msg_pnat_binding_attach_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_pnat_binding_attach_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_pnat_binding_attach_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_pnat_binding_attach
#define defined_vapi_msg_pnat_binding_attach
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_enum_pnat_attachment_point attachment;
  u32 binding_index; 
} vapi_payload_pnat_binding_attach;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_pnat_binding_attach payload;
} vapi_msg_pnat_binding_attach;

static inline void vapi_msg_pnat_binding_attach_payload_hton(vapi_payload_pnat_binding_attach *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->attachment = (vapi_enum_pnat_attachment_point)htobe32(payload->attachment);
  payload->binding_index = htobe32(payload->binding_index);
}

static inline void vapi_msg_pnat_binding_attach_payload_ntoh(vapi_payload_pnat_binding_attach *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->attachment = (vapi_enum_pnat_attachment_point)be32toh(payload->attachment);
  payload->binding_index = be32toh(payload->binding_index);
}

static inline void vapi_msg_pnat_binding_attach_hton(vapi_msg_pnat_binding_attach *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_binding_attach'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_pnat_binding_attach_payload_hton(&msg->payload);
}

static inline void vapi_msg_pnat_binding_attach_ntoh(vapi_msg_pnat_binding_attach *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_binding_attach'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_pnat_binding_attach_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pnat_binding_attach_msg_size(vapi_msg_pnat_binding_attach *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pnat_binding_attach_msg_size(vapi_msg_pnat_binding_attach *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pnat_binding_attach) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_binding_attach' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pnat_binding_attach));
      return -1;
    }
  if (vapi_calc_pnat_binding_attach_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_binding_attach' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pnat_binding_attach_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_pnat_binding_attach* vapi_alloc_pnat_binding_attach(struct vapi_ctx_s *ctx)
{
  vapi_msg_pnat_binding_attach *msg = NULL;
  const size_t size = sizeof(vapi_msg_pnat_binding_attach);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_pnat_binding_attach*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_pnat_binding_attach);

  return msg;
}

static inline vapi_error_e vapi_pnat_binding_attach(struct vapi_ctx_s *ctx,
  vapi_msg_pnat_binding_attach *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_pnat_binding_attach_reply *reply),
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
  vapi_msg_pnat_binding_attach_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_pnat_binding_attach_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_pnat_binding_attach_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_pnat_binding_attach()
{
  static const char name[] = "pnat_binding_attach";
  static const char name_with_crc[] = "pnat_binding_attach_6e074232";
  static vapi_message_desc_t __vapi_metadata_pnat_binding_attach = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_pnat_binding_attach, payload),
    (verify_msg_size_fn_t)vapi_verify_pnat_binding_attach_msg_size,
    (generic_swap_fn_t)vapi_msg_pnat_binding_attach_hton,
    (generic_swap_fn_t)vapi_msg_pnat_binding_attach_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pnat_binding_attach = vapi_register_msg(&__vapi_metadata_pnat_binding_attach);
  VAPI_DBG("Assigned msg id %d to pnat_binding_attach", vapi_msg_id_pnat_binding_attach);
}
#endif

#ifndef defined_vapi_msg_pnat_binding_detach_reply
#define defined_vapi_msg_pnat_binding_detach_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_pnat_binding_detach_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_pnat_binding_detach_reply payload;
} vapi_msg_pnat_binding_detach_reply;

static inline void vapi_msg_pnat_binding_detach_reply_payload_hton(vapi_payload_pnat_binding_detach_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_pnat_binding_detach_reply_payload_ntoh(vapi_payload_pnat_binding_detach_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_pnat_binding_detach_reply_hton(vapi_msg_pnat_binding_detach_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_binding_detach_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_pnat_binding_detach_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_pnat_binding_detach_reply_ntoh(vapi_msg_pnat_binding_detach_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_binding_detach_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_pnat_binding_detach_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pnat_binding_detach_reply_msg_size(vapi_msg_pnat_binding_detach_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pnat_binding_detach_reply_msg_size(vapi_msg_pnat_binding_detach_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pnat_binding_detach_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_binding_detach_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pnat_binding_detach_reply));
      return -1;
    }
  if (vapi_calc_pnat_binding_detach_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_binding_detach_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pnat_binding_detach_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_pnat_binding_detach_reply()
{
  static const char name[] = "pnat_binding_detach_reply";
  static const char name_with_crc[] = "pnat_binding_detach_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_pnat_binding_detach_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_pnat_binding_detach_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_pnat_binding_detach_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_pnat_binding_detach_reply_hton,
    (generic_swap_fn_t)vapi_msg_pnat_binding_detach_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pnat_binding_detach_reply = vapi_register_msg(&__vapi_metadata_pnat_binding_detach_reply);
  VAPI_DBG("Assigned msg id %d to pnat_binding_detach_reply", vapi_msg_id_pnat_binding_detach_reply);
}

static inline void vapi_set_vapi_msg_pnat_binding_detach_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_pnat_binding_detach_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_pnat_binding_detach_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_pnat_binding_detach
#define defined_vapi_msg_pnat_binding_detach
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_enum_pnat_attachment_point attachment;
  u32 binding_index; 
} vapi_payload_pnat_binding_detach;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_pnat_binding_detach payload;
} vapi_msg_pnat_binding_detach;

static inline void vapi_msg_pnat_binding_detach_payload_hton(vapi_payload_pnat_binding_detach *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->attachment = (vapi_enum_pnat_attachment_point)htobe32(payload->attachment);
  payload->binding_index = htobe32(payload->binding_index);
}

static inline void vapi_msg_pnat_binding_detach_payload_ntoh(vapi_payload_pnat_binding_detach *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->attachment = (vapi_enum_pnat_attachment_point)be32toh(payload->attachment);
  payload->binding_index = be32toh(payload->binding_index);
}

static inline void vapi_msg_pnat_binding_detach_hton(vapi_msg_pnat_binding_detach *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_binding_detach'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_pnat_binding_detach_payload_hton(&msg->payload);
}

static inline void vapi_msg_pnat_binding_detach_ntoh(vapi_msg_pnat_binding_detach *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_binding_detach'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_pnat_binding_detach_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pnat_binding_detach_msg_size(vapi_msg_pnat_binding_detach *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pnat_binding_detach_msg_size(vapi_msg_pnat_binding_detach *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pnat_binding_detach) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_binding_detach' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pnat_binding_detach));
      return -1;
    }
  if (vapi_calc_pnat_binding_detach_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_binding_detach' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pnat_binding_detach_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_pnat_binding_detach* vapi_alloc_pnat_binding_detach(struct vapi_ctx_s *ctx)
{
  vapi_msg_pnat_binding_detach *msg = NULL;
  const size_t size = sizeof(vapi_msg_pnat_binding_detach);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_pnat_binding_detach*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_pnat_binding_detach);

  return msg;
}

static inline vapi_error_e vapi_pnat_binding_detach(struct vapi_ctx_s *ctx,
  vapi_msg_pnat_binding_detach *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_pnat_binding_detach_reply *reply),
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
  vapi_msg_pnat_binding_detach_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_pnat_binding_detach_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_pnat_binding_detach_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_pnat_binding_detach()
{
  static const char name[] = "pnat_binding_detach";
  static const char name_with_crc[] = "pnat_binding_detach_6e074232";
  static vapi_message_desc_t __vapi_metadata_pnat_binding_detach = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_pnat_binding_detach, payload),
    (verify_msg_size_fn_t)vapi_verify_pnat_binding_detach_msg_size,
    (generic_swap_fn_t)vapi_msg_pnat_binding_detach_hton,
    (generic_swap_fn_t)vapi_msg_pnat_binding_detach_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pnat_binding_detach = vapi_register_msg(&__vapi_metadata_pnat_binding_detach);
  VAPI_DBG("Assigned msg id %d to pnat_binding_detach", vapi_msg_id_pnat_binding_detach);
}
#endif

#ifndef defined_vapi_msg_pnat_bindings_get_reply
#define defined_vapi_msg_pnat_bindings_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 cursor; 
} vapi_payload_pnat_bindings_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_pnat_bindings_get_reply payload;
} vapi_msg_pnat_bindings_get_reply;

static inline void vapi_msg_pnat_bindings_get_reply_payload_hton(vapi_payload_pnat_bindings_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_pnat_bindings_get_reply_payload_ntoh(vapi_payload_pnat_bindings_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_pnat_bindings_get_reply_hton(vapi_msg_pnat_bindings_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_bindings_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_pnat_bindings_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_pnat_bindings_get_reply_ntoh(vapi_msg_pnat_bindings_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_bindings_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_pnat_bindings_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pnat_bindings_get_reply_msg_size(vapi_msg_pnat_bindings_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pnat_bindings_get_reply_msg_size(vapi_msg_pnat_bindings_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pnat_bindings_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_bindings_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pnat_bindings_get_reply));
      return -1;
    }
  if (vapi_calc_pnat_bindings_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_bindings_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pnat_bindings_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_pnat_bindings_get_reply()
{
  static const char name[] = "pnat_bindings_get_reply";
  static const char name_with_crc[] = "pnat_bindings_get_reply_53b48f5d";
  static vapi_message_desc_t __vapi_metadata_pnat_bindings_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_pnat_bindings_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_pnat_bindings_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_pnat_bindings_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_pnat_bindings_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pnat_bindings_get_reply = vapi_register_msg(&__vapi_metadata_pnat_bindings_get_reply);
  VAPI_DBG("Assigned msg id %d to pnat_bindings_get_reply", vapi_msg_id_pnat_bindings_get_reply);
}

static inline void vapi_set_vapi_msg_pnat_bindings_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_pnat_bindings_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_pnat_bindings_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_pnat_bindings_details
#define defined_vapi_msg_pnat_bindings_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_pnat_match_tuple match;
  vapi_type_pnat_rewrite_tuple rewrite; 
} vapi_payload_pnat_bindings_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_pnat_bindings_details payload;
} vapi_msg_pnat_bindings_details;

static inline void vapi_msg_pnat_bindings_details_payload_hton(vapi_payload_pnat_bindings_details *payload)
{
  vapi_type_pnat_match_tuple_hton(&payload->match);
  vapi_type_pnat_rewrite_tuple_hton(&payload->rewrite);
}

static inline void vapi_msg_pnat_bindings_details_payload_ntoh(vapi_payload_pnat_bindings_details *payload)
{
  vapi_type_pnat_match_tuple_ntoh(&payload->match);
  vapi_type_pnat_rewrite_tuple_ntoh(&payload->rewrite);
}

static inline void vapi_msg_pnat_bindings_details_hton(vapi_msg_pnat_bindings_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_bindings_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_pnat_bindings_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_pnat_bindings_details_ntoh(vapi_msg_pnat_bindings_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_bindings_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_pnat_bindings_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pnat_bindings_details_msg_size(vapi_msg_pnat_bindings_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pnat_bindings_details_msg_size(vapi_msg_pnat_bindings_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pnat_bindings_details) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_bindings_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pnat_bindings_details));
      return -1;
    }
  if (vapi_calc_pnat_bindings_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_bindings_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pnat_bindings_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_pnat_bindings_details()
{
  static const char name[] = "pnat_bindings_details";
  static const char name_with_crc[] = "pnat_bindings_details_08fb2815";
  static vapi_message_desc_t __vapi_metadata_pnat_bindings_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_pnat_bindings_details, payload),
    (verify_msg_size_fn_t)vapi_verify_pnat_bindings_details_msg_size,
    (generic_swap_fn_t)vapi_msg_pnat_bindings_details_hton,
    (generic_swap_fn_t)vapi_msg_pnat_bindings_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pnat_bindings_details = vapi_register_msg(&__vapi_metadata_pnat_bindings_details);
  VAPI_DBG("Assigned msg id %d to pnat_bindings_details", vapi_msg_id_pnat_bindings_details);
}
#endif

#ifndef defined_vapi_msg_pnat_bindings_get
#define defined_vapi_msg_pnat_bindings_get
typedef struct __attribute__ ((__packed__)) {
  u32 cursor; 
} vapi_payload_pnat_bindings_get;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_pnat_bindings_get payload;
} vapi_msg_pnat_bindings_get;

static inline void vapi_msg_pnat_bindings_get_payload_hton(vapi_payload_pnat_bindings_get *payload)
{
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_pnat_bindings_get_payload_ntoh(vapi_payload_pnat_bindings_get *payload)
{
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_pnat_bindings_get_hton(vapi_msg_pnat_bindings_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_bindings_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_pnat_bindings_get_payload_hton(&msg->payload);
}

static inline void vapi_msg_pnat_bindings_get_ntoh(vapi_msg_pnat_bindings_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_bindings_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_pnat_bindings_get_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pnat_bindings_get_msg_size(vapi_msg_pnat_bindings_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pnat_bindings_get_msg_size(vapi_msg_pnat_bindings_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pnat_bindings_get) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_bindings_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pnat_bindings_get));
      return -1;
    }
  if (vapi_calc_pnat_bindings_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_bindings_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pnat_bindings_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_pnat_bindings_get* vapi_alloc_pnat_bindings_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_pnat_bindings_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_pnat_bindings_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_pnat_bindings_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_pnat_bindings_get);

  return msg;
}

static inline vapi_error_e vapi_pnat_bindings_get(struct vapi_ctx_s *ctx,
  vapi_msg_pnat_bindings_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_pnat_bindings_get_reply *reply),
  void *reply_callback_ctx,
  vapi_error_e (*details_callback)(struct vapi_ctx_s *ctx,
                                   void *callback_ctx,
                                   vapi_error_e rv,
                                   bool is_last,
                                   vapi_payload_pnat_bindings_details *details),
  void *details_callback_ctx)
{
  if (!msg || !reply_callback || !details_callback) {
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
  vapi_msg_pnat_bindings_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_pnat_bindings_details, VAPI_REQUEST_STREAM, 
                       (vapi_cb_t)details_callback, details_callback_ctx);
    vapi_store_request(ctx, req_context, vapi_msg_id_pnat_bindings_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_pnat_bindings_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_pnat_bindings_get()
{
  static const char name[] = "pnat_bindings_get";
  static const char name_with_crc[] = "pnat_bindings_get_f75ba505";
  static vapi_message_desc_t __vapi_metadata_pnat_bindings_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_pnat_bindings_get, payload),
    (verify_msg_size_fn_t)vapi_verify_pnat_bindings_get_msg_size,
    (generic_swap_fn_t)vapi_msg_pnat_bindings_get_hton,
    (generic_swap_fn_t)vapi_msg_pnat_bindings_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pnat_bindings_get = vapi_register_msg(&__vapi_metadata_pnat_bindings_get);
  VAPI_DBG("Assigned msg id %d to pnat_bindings_get", vapi_msg_id_pnat_bindings_get);
}
#endif

#ifndef defined_vapi_msg_pnat_interfaces_get_reply
#define defined_vapi_msg_pnat_interfaces_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 cursor; 
} vapi_payload_pnat_interfaces_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_pnat_interfaces_get_reply payload;
} vapi_msg_pnat_interfaces_get_reply;

static inline void vapi_msg_pnat_interfaces_get_reply_payload_hton(vapi_payload_pnat_interfaces_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_pnat_interfaces_get_reply_payload_ntoh(vapi_payload_pnat_interfaces_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_pnat_interfaces_get_reply_hton(vapi_msg_pnat_interfaces_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_interfaces_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_pnat_interfaces_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_pnat_interfaces_get_reply_ntoh(vapi_msg_pnat_interfaces_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_interfaces_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_pnat_interfaces_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pnat_interfaces_get_reply_msg_size(vapi_msg_pnat_interfaces_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pnat_interfaces_get_reply_msg_size(vapi_msg_pnat_interfaces_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pnat_interfaces_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_interfaces_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pnat_interfaces_get_reply));
      return -1;
    }
  if (vapi_calc_pnat_interfaces_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_interfaces_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pnat_interfaces_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_pnat_interfaces_get_reply()
{
  static const char name[] = "pnat_interfaces_get_reply";
  static const char name_with_crc[] = "pnat_interfaces_get_reply_53b48f5d";
  static vapi_message_desc_t __vapi_metadata_pnat_interfaces_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_pnat_interfaces_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_pnat_interfaces_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_pnat_interfaces_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_pnat_interfaces_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pnat_interfaces_get_reply = vapi_register_msg(&__vapi_metadata_pnat_interfaces_get_reply);
  VAPI_DBG("Assigned msg id %d to pnat_interfaces_get_reply", vapi_msg_id_pnat_interfaces_get_reply);
}

static inline void vapi_set_vapi_msg_pnat_interfaces_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_pnat_interfaces_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_pnat_interfaces_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_pnat_interfaces_details
#define defined_vapi_msg_pnat_interfaces_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  bool enabled[2];
  vapi_enum_pnat_mask lookup_mask[2]; 
} vapi_payload_pnat_interfaces_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_pnat_interfaces_details payload;
} vapi_msg_pnat_interfaces_details;

static inline void vapi_msg_pnat_interfaces_details_payload_hton(vapi_payload_pnat_interfaces_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  do { unsigned i; for (i = 0; i < 2; ++i) { payload->lookup_mask[i] = (vapi_enum_pnat_mask)htobe32(payload->lookup_mask[i]); } } while(0);
}

static inline void vapi_msg_pnat_interfaces_details_payload_ntoh(vapi_payload_pnat_interfaces_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  do { unsigned i; for (i = 0; i < 2; ++i) { payload->lookup_mask[i] = (vapi_enum_pnat_mask)be32toh(payload->lookup_mask[i]); } } while(0);
}

static inline void vapi_msg_pnat_interfaces_details_hton(vapi_msg_pnat_interfaces_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_interfaces_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_pnat_interfaces_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_pnat_interfaces_details_ntoh(vapi_msg_pnat_interfaces_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_interfaces_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_pnat_interfaces_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pnat_interfaces_details_msg_size(vapi_msg_pnat_interfaces_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pnat_interfaces_details_msg_size(vapi_msg_pnat_interfaces_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pnat_interfaces_details) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_interfaces_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pnat_interfaces_details));
      return -1;
    }
  if (vapi_calc_pnat_interfaces_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_interfaces_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pnat_interfaces_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_pnat_interfaces_details()
{
  static const char name[] = "pnat_interfaces_details";
  static const char name_with_crc[] = "pnat_interfaces_details_4cb09493";
  static vapi_message_desc_t __vapi_metadata_pnat_interfaces_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_pnat_interfaces_details, payload),
    (verify_msg_size_fn_t)vapi_verify_pnat_interfaces_details_msg_size,
    (generic_swap_fn_t)vapi_msg_pnat_interfaces_details_hton,
    (generic_swap_fn_t)vapi_msg_pnat_interfaces_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pnat_interfaces_details = vapi_register_msg(&__vapi_metadata_pnat_interfaces_details);
  VAPI_DBG("Assigned msg id %d to pnat_interfaces_details", vapi_msg_id_pnat_interfaces_details);
}
#endif

#ifndef defined_vapi_msg_pnat_interfaces_get
#define defined_vapi_msg_pnat_interfaces_get
typedef struct __attribute__ ((__packed__)) {
  u32 cursor; 
} vapi_payload_pnat_interfaces_get;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_pnat_interfaces_get payload;
} vapi_msg_pnat_interfaces_get;

static inline void vapi_msg_pnat_interfaces_get_payload_hton(vapi_payload_pnat_interfaces_get *payload)
{
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_pnat_interfaces_get_payload_ntoh(vapi_payload_pnat_interfaces_get *payload)
{
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_pnat_interfaces_get_hton(vapi_msg_pnat_interfaces_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_interfaces_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_pnat_interfaces_get_payload_hton(&msg->payload);
}

static inline void vapi_msg_pnat_interfaces_get_ntoh(vapi_msg_pnat_interfaces_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_interfaces_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_pnat_interfaces_get_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pnat_interfaces_get_msg_size(vapi_msg_pnat_interfaces_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pnat_interfaces_get_msg_size(vapi_msg_pnat_interfaces_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pnat_interfaces_get) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_interfaces_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pnat_interfaces_get));
      return -1;
    }
  if (vapi_calc_pnat_interfaces_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_interfaces_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pnat_interfaces_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_pnat_interfaces_get* vapi_alloc_pnat_interfaces_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_pnat_interfaces_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_pnat_interfaces_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_pnat_interfaces_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_pnat_interfaces_get);

  return msg;
}

static inline vapi_error_e vapi_pnat_interfaces_get(struct vapi_ctx_s *ctx,
  vapi_msg_pnat_interfaces_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_pnat_interfaces_get_reply *reply),
  void *reply_callback_ctx,
  vapi_error_e (*details_callback)(struct vapi_ctx_s *ctx,
                                   void *callback_ctx,
                                   vapi_error_e rv,
                                   bool is_last,
                                   vapi_payload_pnat_interfaces_details *details),
  void *details_callback_ctx)
{
  if (!msg || !reply_callback || !details_callback) {
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
  vapi_msg_pnat_interfaces_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_pnat_interfaces_details, VAPI_REQUEST_STREAM, 
                       (vapi_cb_t)details_callback, details_callback_ctx);
    vapi_store_request(ctx, req_context, vapi_msg_id_pnat_interfaces_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_pnat_interfaces_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_pnat_interfaces_get()
{
  static const char name[] = "pnat_interfaces_get";
  static const char name_with_crc[] = "pnat_interfaces_get_f75ba505";
  static vapi_message_desc_t __vapi_metadata_pnat_interfaces_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_pnat_interfaces_get, payload),
    (verify_msg_size_fn_t)vapi_verify_pnat_interfaces_get_msg_size,
    (generic_swap_fn_t)vapi_msg_pnat_interfaces_get_hton,
    (generic_swap_fn_t)vapi_msg_pnat_interfaces_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pnat_interfaces_get = vapi_register_msg(&__vapi_metadata_pnat_interfaces_get);
  VAPI_DBG("Assigned msg id %d to pnat_interfaces_get", vapi_msg_id_pnat_interfaces_get);
}
#endif

#ifndef defined_vapi_msg_pnat_flow_lookup_reply
#define defined_vapi_msg_pnat_flow_lookup_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 binding_index; 
} vapi_payload_pnat_flow_lookup_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_pnat_flow_lookup_reply payload;
} vapi_msg_pnat_flow_lookup_reply;

static inline void vapi_msg_pnat_flow_lookup_reply_payload_hton(vapi_payload_pnat_flow_lookup_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->binding_index = htobe32(payload->binding_index);
}

static inline void vapi_msg_pnat_flow_lookup_reply_payload_ntoh(vapi_payload_pnat_flow_lookup_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->binding_index = be32toh(payload->binding_index);
}

static inline void vapi_msg_pnat_flow_lookup_reply_hton(vapi_msg_pnat_flow_lookup_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_flow_lookup_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_pnat_flow_lookup_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_pnat_flow_lookup_reply_ntoh(vapi_msg_pnat_flow_lookup_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_flow_lookup_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_pnat_flow_lookup_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pnat_flow_lookup_reply_msg_size(vapi_msg_pnat_flow_lookup_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pnat_flow_lookup_reply_msg_size(vapi_msg_pnat_flow_lookup_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pnat_flow_lookup_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_flow_lookup_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pnat_flow_lookup_reply));
      return -1;
    }
  if (vapi_calc_pnat_flow_lookup_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_flow_lookup_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pnat_flow_lookup_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_pnat_flow_lookup_reply()
{
  static const char name[] = "pnat_flow_lookup_reply";
  static const char name_with_crc[] = "pnat_flow_lookup_reply_4cd980a7";
  static vapi_message_desc_t __vapi_metadata_pnat_flow_lookup_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_pnat_flow_lookup_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_pnat_flow_lookup_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_pnat_flow_lookup_reply_hton,
    (generic_swap_fn_t)vapi_msg_pnat_flow_lookup_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pnat_flow_lookup_reply = vapi_register_msg(&__vapi_metadata_pnat_flow_lookup_reply);
  VAPI_DBG("Assigned msg id %d to pnat_flow_lookup_reply", vapi_msg_id_pnat_flow_lookup_reply);
}

static inline void vapi_set_vapi_msg_pnat_flow_lookup_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_pnat_flow_lookup_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_pnat_flow_lookup_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_pnat_flow_lookup
#define defined_vapi_msg_pnat_flow_lookup
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_enum_pnat_attachment_point attachment;
  vapi_type_pnat_match_tuple match; 
} vapi_payload_pnat_flow_lookup;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_pnat_flow_lookup payload;
} vapi_msg_pnat_flow_lookup;

static inline void vapi_msg_pnat_flow_lookup_payload_hton(vapi_payload_pnat_flow_lookup *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->attachment = (vapi_enum_pnat_attachment_point)htobe32(payload->attachment);
  vapi_type_pnat_match_tuple_hton(&payload->match);
}

static inline void vapi_msg_pnat_flow_lookup_payload_ntoh(vapi_payload_pnat_flow_lookup *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->attachment = (vapi_enum_pnat_attachment_point)be32toh(payload->attachment);
  vapi_type_pnat_match_tuple_ntoh(&payload->match);
}

static inline void vapi_msg_pnat_flow_lookup_hton(vapi_msg_pnat_flow_lookup *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_flow_lookup'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_pnat_flow_lookup_payload_hton(&msg->payload);
}

static inline void vapi_msg_pnat_flow_lookup_ntoh(vapi_msg_pnat_flow_lookup *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pnat_flow_lookup'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_pnat_flow_lookup_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pnat_flow_lookup_msg_size(vapi_msg_pnat_flow_lookup *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pnat_flow_lookup_msg_size(vapi_msg_pnat_flow_lookup *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pnat_flow_lookup) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_flow_lookup' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pnat_flow_lookup));
      return -1;
    }
  if (vapi_calc_pnat_flow_lookup_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pnat_flow_lookup' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pnat_flow_lookup_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_pnat_flow_lookup* vapi_alloc_pnat_flow_lookup(struct vapi_ctx_s *ctx)
{
  vapi_msg_pnat_flow_lookup *msg = NULL;
  const size_t size = sizeof(vapi_msg_pnat_flow_lookup);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_pnat_flow_lookup*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_pnat_flow_lookup);

  return msg;
}

static inline vapi_error_e vapi_pnat_flow_lookup(struct vapi_ctx_s *ctx,
  vapi_msg_pnat_flow_lookup *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_pnat_flow_lookup_reply *reply),
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
  vapi_msg_pnat_flow_lookup_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_pnat_flow_lookup_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_pnat_flow_lookup_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_pnat_flow_lookup()
{
  static const char name[] = "pnat_flow_lookup";
  static const char name_with_crc[] = "pnat_flow_lookup_1ef8747c";
  static vapi_message_desc_t __vapi_metadata_pnat_flow_lookup = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_pnat_flow_lookup, payload),
    (verify_msg_size_fn_t)vapi_verify_pnat_flow_lookup_msg_size,
    (generic_swap_fn_t)vapi_msg_pnat_flow_lookup_hton,
    (generic_swap_fn_t)vapi_msg_pnat_flow_lookup_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pnat_flow_lookup = vapi_register_msg(&__vapi_metadata_pnat_flow_lookup);
  VAPI_DBG("Assigned msg id %d to pnat_flow_lookup", vapi_msg_id_pnat_flow_lookup);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
