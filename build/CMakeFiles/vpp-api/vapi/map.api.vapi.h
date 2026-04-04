#ifndef __included_map_api_json
#define __included_map_api_json

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

extern vapi_msg_id_t vapi_msg_id_map_add_domain;
extern vapi_msg_id_t vapi_msg_id_map_add_domain_reply;
extern vapi_msg_id_t vapi_msg_id_map_del_domain;
extern vapi_msg_id_t vapi_msg_id_map_del_domain_reply;
extern vapi_msg_id_t vapi_msg_id_map_add_del_rule;
extern vapi_msg_id_t vapi_msg_id_map_add_del_rule_reply;
extern vapi_msg_id_t vapi_msg_id_map_domains_get;
extern vapi_msg_id_t vapi_msg_id_map_domains_get_reply;
extern vapi_msg_id_t vapi_msg_id_map_domain_dump;
extern vapi_msg_id_t vapi_msg_id_map_domain_details;
extern vapi_msg_id_t vapi_msg_id_map_rule_dump;
extern vapi_msg_id_t vapi_msg_id_map_rule_details;
extern vapi_msg_id_t vapi_msg_id_map_if_enable_disable;
extern vapi_msg_id_t vapi_msg_id_map_if_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_map_summary_stats;
extern vapi_msg_id_t vapi_msg_id_map_summary_stats_reply;
extern vapi_msg_id_t vapi_msg_id_map_param_set_fragmentation;
extern vapi_msg_id_t vapi_msg_id_map_param_set_fragmentation_reply;
extern vapi_msg_id_t vapi_msg_id_map_param_set_icmp;
extern vapi_msg_id_t vapi_msg_id_map_param_set_icmp_reply;
extern vapi_msg_id_t vapi_msg_id_map_param_set_icmp6;
extern vapi_msg_id_t vapi_msg_id_map_param_set_icmp6_reply;
extern vapi_msg_id_t vapi_msg_id_map_param_add_del_pre_resolve;
extern vapi_msg_id_t vapi_msg_id_map_param_add_del_pre_resolve_reply;
extern vapi_msg_id_t vapi_msg_id_map_param_set_security_check;
extern vapi_msg_id_t vapi_msg_id_map_param_set_security_check_reply;
extern vapi_msg_id_t vapi_msg_id_map_param_set_traffic_class;
extern vapi_msg_id_t vapi_msg_id_map_param_set_traffic_class_reply;
extern vapi_msg_id_t vapi_msg_id_map_param_set_tcp;
extern vapi_msg_id_t vapi_msg_id_map_param_set_tcp_reply;
extern vapi_msg_id_t vapi_msg_id_map_param_get;
extern vapi_msg_id_t vapi_msg_id_map_param_get_reply;

#define DEFINE_VAPI_MSG_IDS_MAP_API_JSON\
  vapi_msg_id_t vapi_msg_id_map_add_domain;\
  vapi_msg_id_t vapi_msg_id_map_add_domain_reply;\
  vapi_msg_id_t vapi_msg_id_map_del_domain;\
  vapi_msg_id_t vapi_msg_id_map_del_domain_reply;\
  vapi_msg_id_t vapi_msg_id_map_add_del_rule;\
  vapi_msg_id_t vapi_msg_id_map_add_del_rule_reply;\
  vapi_msg_id_t vapi_msg_id_map_domains_get;\
  vapi_msg_id_t vapi_msg_id_map_domains_get_reply;\
  vapi_msg_id_t vapi_msg_id_map_domain_dump;\
  vapi_msg_id_t vapi_msg_id_map_domain_details;\
  vapi_msg_id_t vapi_msg_id_map_rule_dump;\
  vapi_msg_id_t vapi_msg_id_map_rule_details;\
  vapi_msg_id_t vapi_msg_id_map_if_enable_disable;\
  vapi_msg_id_t vapi_msg_id_map_if_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_map_summary_stats;\
  vapi_msg_id_t vapi_msg_id_map_summary_stats_reply;\
  vapi_msg_id_t vapi_msg_id_map_param_set_fragmentation;\
  vapi_msg_id_t vapi_msg_id_map_param_set_fragmentation_reply;\
  vapi_msg_id_t vapi_msg_id_map_param_set_icmp;\
  vapi_msg_id_t vapi_msg_id_map_param_set_icmp_reply;\
  vapi_msg_id_t vapi_msg_id_map_param_set_icmp6;\
  vapi_msg_id_t vapi_msg_id_map_param_set_icmp6_reply;\
  vapi_msg_id_t vapi_msg_id_map_param_add_del_pre_resolve;\
  vapi_msg_id_t vapi_msg_id_map_param_add_del_pre_resolve_reply;\
  vapi_msg_id_t vapi_msg_id_map_param_set_security_check;\
  vapi_msg_id_t vapi_msg_id_map_param_set_security_check_reply;\
  vapi_msg_id_t vapi_msg_id_map_param_set_traffic_class;\
  vapi_msg_id_t vapi_msg_id_map_param_set_traffic_class_reply;\
  vapi_msg_id_t vapi_msg_id_map_param_set_tcp;\
  vapi_msg_id_t vapi_msg_id_map_param_set_tcp_reply;\
  vapi_msg_id_t vapi_msg_id_map_param_get;\
  vapi_msg_id_t vapi_msg_id_map_param_get_reply;


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

#ifndef defined_vapi_msg_map_add_domain_reply
#define defined_vapi_msg_map_add_domain_reply
typedef struct __attribute__ ((__packed__)) {
  u32 index;
  i32 retval; 
} vapi_payload_map_add_domain_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_map_add_domain_reply payload;
} vapi_msg_map_add_domain_reply;

static inline void vapi_msg_map_add_domain_reply_payload_hton(vapi_payload_map_add_domain_reply *payload)
{
  payload->index = htobe32(payload->index);
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_map_add_domain_reply_payload_ntoh(vapi_payload_map_add_domain_reply *payload)
{
  payload->index = be32toh(payload->index);
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_map_add_domain_reply_hton(vapi_msg_map_add_domain_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_add_domain_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_map_add_domain_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_add_domain_reply_ntoh(vapi_msg_map_add_domain_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_add_domain_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_map_add_domain_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_add_domain_reply_msg_size(vapi_msg_map_add_domain_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_add_domain_reply_msg_size(vapi_msg_map_add_domain_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_add_domain_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'map_add_domain_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_add_domain_reply));
      return -1;
    }
  if (vapi_calc_map_add_domain_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_add_domain_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_add_domain_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_map_add_domain_reply()
{
  static const char name[] = "map_add_domain_reply";
  static const char name_with_crc[] = "map_add_domain_reply_3e6d4e2c";
  static vapi_message_desc_t __vapi_metadata_map_add_domain_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_map_add_domain_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_map_add_domain_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_map_add_domain_reply_hton,
    (generic_swap_fn_t)vapi_msg_map_add_domain_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_add_domain_reply = vapi_register_msg(&__vapi_metadata_map_add_domain_reply);
  VAPI_DBG("Assigned msg id %d to map_add_domain_reply", vapi_msg_id_map_add_domain_reply);
}

static inline void vapi_set_vapi_msg_map_add_domain_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_map_add_domain_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_map_add_domain_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_map_add_domain
#define defined_vapi_msg_map_add_domain
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip6_prefix ip6_prefix;
  vapi_type_ip4_prefix ip4_prefix;
  vapi_type_ip6_prefix ip6_src;
  u8 ea_bits_len;
  u8 psid_offset;
  u8 psid_length;
  u16 mtu;
  u8 tag[64]; 
} vapi_payload_map_add_domain;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_map_add_domain payload;
} vapi_msg_map_add_domain;

static inline void vapi_msg_map_add_domain_payload_hton(vapi_payload_map_add_domain *payload)
{
  payload->mtu = htobe16(payload->mtu);
}

static inline void vapi_msg_map_add_domain_payload_ntoh(vapi_payload_map_add_domain *payload)
{
  payload->mtu = be16toh(payload->mtu);
}

static inline void vapi_msg_map_add_domain_hton(vapi_msg_map_add_domain *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_add_domain'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_map_add_domain_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_add_domain_ntoh(vapi_msg_map_add_domain *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_add_domain'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_map_add_domain_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_add_domain_msg_size(vapi_msg_map_add_domain *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_add_domain_msg_size(vapi_msg_map_add_domain *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_add_domain) > buf_size)
    {
      VAPI_ERR("Truncated 'map_add_domain' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_add_domain));
      return -1;
    }
  if (vapi_calc_map_add_domain_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_add_domain' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_add_domain_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_map_add_domain* vapi_alloc_map_add_domain(struct vapi_ctx_s *ctx)
{
  vapi_msg_map_add_domain *msg = NULL;
  const size_t size = sizeof(vapi_msg_map_add_domain);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_map_add_domain*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_map_add_domain);

  return msg;
}

static inline vapi_error_e vapi_map_add_domain(struct vapi_ctx_s *ctx,
  vapi_msg_map_add_domain *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_map_add_domain_reply *reply),
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
  vapi_msg_map_add_domain_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_map_add_domain_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_map_add_domain_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_map_add_domain()
{
  static const char name[] = "map_add_domain";
  static const char name_with_crc[] = "map_add_domain_249f195c";
  static vapi_message_desc_t __vapi_metadata_map_add_domain = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_map_add_domain, payload),
    (verify_msg_size_fn_t)vapi_verify_map_add_domain_msg_size,
    (generic_swap_fn_t)vapi_msg_map_add_domain_hton,
    (generic_swap_fn_t)vapi_msg_map_add_domain_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_add_domain = vapi_register_msg(&__vapi_metadata_map_add_domain);
  VAPI_DBG("Assigned msg id %d to map_add_domain", vapi_msg_id_map_add_domain);
}
#endif

#ifndef defined_vapi_msg_map_del_domain_reply
#define defined_vapi_msg_map_del_domain_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_map_del_domain_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_map_del_domain_reply payload;
} vapi_msg_map_del_domain_reply;

static inline void vapi_msg_map_del_domain_reply_payload_hton(vapi_payload_map_del_domain_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_map_del_domain_reply_payload_ntoh(vapi_payload_map_del_domain_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_map_del_domain_reply_hton(vapi_msg_map_del_domain_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_del_domain_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_map_del_domain_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_del_domain_reply_ntoh(vapi_msg_map_del_domain_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_del_domain_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_map_del_domain_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_del_domain_reply_msg_size(vapi_msg_map_del_domain_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_del_domain_reply_msg_size(vapi_msg_map_del_domain_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_del_domain_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'map_del_domain_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_del_domain_reply));
      return -1;
    }
  if (vapi_calc_map_del_domain_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_del_domain_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_del_domain_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_map_del_domain_reply()
{
  static const char name[] = "map_del_domain_reply";
  static const char name_with_crc[] = "map_del_domain_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_map_del_domain_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_map_del_domain_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_map_del_domain_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_map_del_domain_reply_hton,
    (generic_swap_fn_t)vapi_msg_map_del_domain_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_del_domain_reply = vapi_register_msg(&__vapi_metadata_map_del_domain_reply);
  VAPI_DBG("Assigned msg id %d to map_del_domain_reply", vapi_msg_id_map_del_domain_reply);
}

static inline void vapi_set_vapi_msg_map_del_domain_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_map_del_domain_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_map_del_domain_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_map_del_domain
#define defined_vapi_msg_map_del_domain
typedef struct __attribute__ ((__packed__)) {
  u32 index; 
} vapi_payload_map_del_domain;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_map_del_domain payload;
} vapi_msg_map_del_domain;

static inline void vapi_msg_map_del_domain_payload_hton(vapi_payload_map_del_domain *payload)
{
  payload->index = htobe32(payload->index);
}

static inline void vapi_msg_map_del_domain_payload_ntoh(vapi_payload_map_del_domain *payload)
{
  payload->index = be32toh(payload->index);
}

static inline void vapi_msg_map_del_domain_hton(vapi_msg_map_del_domain *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_del_domain'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_map_del_domain_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_del_domain_ntoh(vapi_msg_map_del_domain *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_del_domain'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_map_del_domain_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_del_domain_msg_size(vapi_msg_map_del_domain *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_del_domain_msg_size(vapi_msg_map_del_domain *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_del_domain) > buf_size)
    {
      VAPI_ERR("Truncated 'map_del_domain' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_del_domain));
      return -1;
    }
  if (vapi_calc_map_del_domain_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_del_domain' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_del_domain_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_map_del_domain* vapi_alloc_map_del_domain(struct vapi_ctx_s *ctx)
{
  vapi_msg_map_del_domain *msg = NULL;
  const size_t size = sizeof(vapi_msg_map_del_domain);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_map_del_domain*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_map_del_domain);

  return msg;
}

static inline vapi_error_e vapi_map_del_domain(struct vapi_ctx_s *ctx,
  vapi_msg_map_del_domain *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_map_del_domain_reply *reply),
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
  vapi_msg_map_del_domain_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_map_del_domain_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_map_del_domain_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_map_del_domain()
{
  static const char name[] = "map_del_domain";
  static const char name_with_crc[] = "map_del_domain_8ac76db6";
  static vapi_message_desc_t __vapi_metadata_map_del_domain = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_map_del_domain, payload),
    (verify_msg_size_fn_t)vapi_verify_map_del_domain_msg_size,
    (generic_swap_fn_t)vapi_msg_map_del_domain_hton,
    (generic_swap_fn_t)vapi_msg_map_del_domain_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_del_domain = vapi_register_msg(&__vapi_metadata_map_del_domain);
  VAPI_DBG("Assigned msg id %d to map_del_domain", vapi_msg_id_map_del_domain);
}
#endif

#ifndef defined_vapi_msg_map_add_del_rule_reply
#define defined_vapi_msg_map_add_del_rule_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_map_add_del_rule_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_map_add_del_rule_reply payload;
} vapi_msg_map_add_del_rule_reply;

static inline void vapi_msg_map_add_del_rule_reply_payload_hton(vapi_payload_map_add_del_rule_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_map_add_del_rule_reply_payload_ntoh(vapi_payload_map_add_del_rule_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_map_add_del_rule_reply_hton(vapi_msg_map_add_del_rule_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_add_del_rule_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_map_add_del_rule_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_add_del_rule_reply_ntoh(vapi_msg_map_add_del_rule_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_add_del_rule_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_map_add_del_rule_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_add_del_rule_reply_msg_size(vapi_msg_map_add_del_rule_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_add_del_rule_reply_msg_size(vapi_msg_map_add_del_rule_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_add_del_rule_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'map_add_del_rule_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_add_del_rule_reply));
      return -1;
    }
  if (vapi_calc_map_add_del_rule_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_add_del_rule_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_add_del_rule_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_map_add_del_rule_reply()
{
  static const char name[] = "map_add_del_rule_reply";
  static const char name_with_crc[] = "map_add_del_rule_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_map_add_del_rule_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_map_add_del_rule_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_map_add_del_rule_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_map_add_del_rule_reply_hton,
    (generic_swap_fn_t)vapi_msg_map_add_del_rule_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_add_del_rule_reply = vapi_register_msg(&__vapi_metadata_map_add_del_rule_reply);
  VAPI_DBG("Assigned msg id %d to map_add_del_rule_reply", vapi_msg_id_map_add_del_rule_reply);
}

static inline void vapi_set_vapi_msg_map_add_del_rule_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_map_add_del_rule_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_map_add_del_rule_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_map_add_del_rule
#define defined_vapi_msg_map_add_del_rule
typedef struct __attribute__ ((__packed__)) {
  u32 index;
  bool is_add;
  vapi_type_ip6_address ip6_dst;
  u16 psid; 
} vapi_payload_map_add_del_rule;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_map_add_del_rule payload;
} vapi_msg_map_add_del_rule;

static inline void vapi_msg_map_add_del_rule_payload_hton(vapi_payload_map_add_del_rule *payload)
{
  payload->index = htobe32(payload->index);
  payload->psid = htobe16(payload->psid);
}

static inline void vapi_msg_map_add_del_rule_payload_ntoh(vapi_payload_map_add_del_rule *payload)
{
  payload->index = be32toh(payload->index);
  payload->psid = be16toh(payload->psid);
}

static inline void vapi_msg_map_add_del_rule_hton(vapi_msg_map_add_del_rule *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_add_del_rule'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_map_add_del_rule_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_add_del_rule_ntoh(vapi_msg_map_add_del_rule *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_add_del_rule'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_map_add_del_rule_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_add_del_rule_msg_size(vapi_msg_map_add_del_rule *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_add_del_rule_msg_size(vapi_msg_map_add_del_rule *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_add_del_rule) > buf_size)
    {
      VAPI_ERR("Truncated 'map_add_del_rule' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_add_del_rule));
      return -1;
    }
  if (vapi_calc_map_add_del_rule_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_add_del_rule' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_add_del_rule_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_map_add_del_rule* vapi_alloc_map_add_del_rule(struct vapi_ctx_s *ctx)
{
  vapi_msg_map_add_del_rule *msg = NULL;
  const size_t size = sizeof(vapi_msg_map_add_del_rule);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_map_add_del_rule*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_map_add_del_rule);

  return msg;
}

static inline vapi_error_e vapi_map_add_del_rule(struct vapi_ctx_s *ctx,
  vapi_msg_map_add_del_rule *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_map_add_del_rule_reply *reply),
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
  vapi_msg_map_add_del_rule_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_map_add_del_rule_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_map_add_del_rule_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_map_add_del_rule()
{
  static const char name[] = "map_add_del_rule";
  static const char name_with_crc[] = "map_add_del_rule_c65b32f7";
  static vapi_message_desc_t __vapi_metadata_map_add_del_rule = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_map_add_del_rule, payload),
    (verify_msg_size_fn_t)vapi_verify_map_add_del_rule_msg_size,
    (generic_swap_fn_t)vapi_msg_map_add_del_rule_hton,
    (generic_swap_fn_t)vapi_msg_map_add_del_rule_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_add_del_rule = vapi_register_msg(&__vapi_metadata_map_add_del_rule);
  VAPI_DBG("Assigned msg id %d to map_add_del_rule", vapi_msg_id_map_add_del_rule);
}
#endif

#ifndef defined_vapi_msg_map_domains_get_reply
#define defined_vapi_msg_map_domains_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 cursor; 
} vapi_payload_map_domains_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_map_domains_get_reply payload;
} vapi_msg_map_domains_get_reply;

static inline void vapi_msg_map_domains_get_reply_payload_hton(vapi_payload_map_domains_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_map_domains_get_reply_payload_ntoh(vapi_payload_map_domains_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_map_domains_get_reply_hton(vapi_msg_map_domains_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_domains_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_map_domains_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_domains_get_reply_ntoh(vapi_msg_map_domains_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_domains_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_map_domains_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_domains_get_reply_msg_size(vapi_msg_map_domains_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_domains_get_reply_msg_size(vapi_msg_map_domains_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_domains_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'map_domains_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_domains_get_reply));
      return -1;
    }
  if (vapi_calc_map_domains_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_domains_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_domains_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_map_domains_get_reply()
{
  static const char name[] = "map_domains_get_reply";
  static const char name_with_crc[] = "map_domains_get_reply_53b48f5d";
  static vapi_message_desc_t __vapi_metadata_map_domains_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_map_domains_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_map_domains_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_map_domains_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_map_domains_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_domains_get_reply = vapi_register_msg(&__vapi_metadata_map_domains_get_reply);
  VAPI_DBG("Assigned msg id %d to map_domains_get_reply", vapi_msg_id_map_domains_get_reply);
}

static inline void vapi_set_vapi_msg_map_domains_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_map_domains_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_map_domains_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_map_domain_details
#define defined_vapi_msg_map_domain_details
typedef struct __attribute__ ((__packed__)) {
  u32 domain_index;
  vapi_type_ip6_prefix ip6_prefix;
  vapi_type_ip4_prefix ip4_prefix;
  vapi_type_ip6_prefix ip6_src;
  u8 ea_bits_len;
  u8 psid_offset;
  u8 psid_length;
  u8 flags;
  u16 mtu;
  u8 tag[64]; 
} vapi_payload_map_domain_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_map_domain_details payload;
} vapi_msg_map_domain_details;

static inline void vapi_msg_map_domain_details_payload_hton(vapi_payload_map_domain_details *payload)
{
  payload->domain_index = htobe32(payload->domain_index);
  payload->mtu = htobe16(payload->mtu);
}

static inline void vapi_msg_map_domain_details_payload_ntoh(vapi_payload_map_domain_details *payload)
{
  payload->domain_index = be32toh(payload->domain_index);
  payload->mtu = be16toh(payload->mtu);
}

static inline void vapi_msg_map_domain_details_hton(vapi_msg_map_domain_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_domain_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_map_domain_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_domain_details_ntoh(vapi_msg_map_domain_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_domain_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_map_domain_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_domain_details_msg_size(vapi_msg_map_domain_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_domain_details_msg_size(vapi_msg_map_domain_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_domain_details) > buf_size)
    {
      VAPI_ERR("Truncated 'map_domain_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_domain_details));
      return -1;
    }
  if (vapi_calc_map_domain_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_domain_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_domain_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_map_domain_details()
{
  static const char name[] = "map_domain_details";
  static const char name_with_crc[] = "map_domain_details_796edb50";
  static vapi_message_desc_t __vapi_metadata_map_domain_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_map_domain_details, payload),
    (verify_msg_size_fn_t)vapi_verify_map_domain_details_msg_size,
    (generic_swap_fn_t)vapi_msg_map_domain_details_hton,
    (generic_swap_fn_t)vapi_msg_map_domain_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_domain_details = vapi_register_msg(&__vapi_metadata_map_domain_details);
  VAPI_DBG("Assigned msg id %d to map_domain_details", vapi_msg_id_map_domain_details);
}
#endif

#ifndef defined_vapi_msg_map_domains_get
#define defined_vapi_msg_map_domains_get
typedef struct __attribute__ ((__packed__)) {
  u32 cursor; 
} vapi_payload_map_domains_get;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_map_domains_get payload;
} vapi_msg_map_domains_get;

static inline void vapi_msg_map_domains_get_payload_hton(vapi_payload_map_domains_get *payload)
{
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_map_domains_get_payload_ntoh(vapi_payload_map_domains_get *payload)
{
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_map_domains_get_hton(vapi_msg_map_domains_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_domains_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_map_domains_get_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_domains_get_ntoh(vapi_msg_map_domains_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_domains_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_map_domains_get_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_domains_get_msg_size(vapi_msg_map_domains_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_domains_get_msg_size(vapi_msg_map_domains_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_domains_get) > buf_size)
    {
      VAPI_ERR("Truncated 'map_domains_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_domains_get));
      return -1;
    }
  if (vapi_calc_map_domains_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_domains_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_domains_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_map_domains_get* vapi_alloc_map_domains_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_map_domains_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_map_domains_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_map_domains_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_map_domains_get);

  return msg;
}

static inline vapi_error_e vapi_map_domains_get(struct vapi_ctx_s *ctx,
  vapi_msg_map_domains_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_map_domains_get_reply *reply),
  void *reply_callback_ctx,
  vapi_error_e (*details_callback)(struct vapi_ctx_s *ctx,
                                   void *callback_ctx,
                                   vapi_error_e rv,
                                   bool is_last,
                                   vapi_payload_map_domain_details *details),
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
  vapi_msg_map_domains_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_map_domain_details, VAPI_REQUEST_STREAM, 
                       (vapi_cb_t)details_callback, details_callback_ctx);
    vapi_store_request(ctx, req_context, vapi_msg_id_map_domains_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_map_domains_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_map_domains_get()
{
  static const char name[] = "map_domains_get";
  static const char name_with_crc[] = "map_domains_get_f75ba505";
  static vapi_message_desc_t __vapi_metadata_map_domains_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_map_domains_get, payload),
    (verify_msg_size_fn_t)vapi_verify_map_domains_get_msg_size,
    (generic_swap_fn_t)vapi_msg_map_domains_get_hton,
    (generic_swap_fn_t)vapi_msg_map_domains_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_domains_get = vapi_register_msg(&__vapi_metadata_map_domains_get);
  VAPI_DBG("Assigned msg id %d to map_domains_get", vapi_msg_id_map_domains_get);
}
#endif

#ifndef defined_vapi_msg_map_domain_dump
#define defined_vapi_msg_map_domain_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_map_domain_dump;

static inline void vapi_msg_map_domain_dump_hton(vapi_msg_map_domain_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_domain_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_map_domain_dump_ntoh(vapi_msg_map_domain_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_domain_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_map_domain_dump_msg_size(vapi_msg_map_domain_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_domain_dump_msg_size(vapi_msg_map_domain_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_domain_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'map_domain_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_domain_dump));
      return -1;
    }
  if (vapi_calc_map_domain_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_domain_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_domain_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_map_domain_dump* vapi_alloc_map_domain_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_map_domain_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_map_domain_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_map_domain_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_map_domain_dump);

  return msg;
}

static inline vapi_error_e vapi_map_domain_dump(struct vapi_ctx_s *ctx,
  vapi_msg_map_domain_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_map_domain_details *reply),
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
  vapi_msg_map_domain_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_map_domain_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_map_domain_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_map_domain_dump()
{
  static const char name[] = "map_domain_dump";
  static const char name_with_crc[] = "map_domain_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_map_domain_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_map_domain_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_map_domain_dump_hton,
    (generic_swap_fn_t)vapi_msg_map_domain_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_domain_dump = vapi_register_msg(&__vapi_metadata_map_domain_dump);
  VAPI_DBG("Assigned msg id %d to map_domain_dump", vapi_msg_id_map_domain_dump);
}
#endif

#ifndef defined_vapi_msg_map_rule_details
#define defined_vapi_msg_map_rule_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip6_address ip6_dst;
  u16 psid; 
} vapi_payload_map_rule_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_map_rule_details payload;
} vapi_msg_map_rule_details;

static inline void vapi_msg_map_rule_details_payload_hton(vapi_payload_map_rule_details *payload)
{
  payload->psid = htobe16(payload->psid);
}

static inline void vapi_msg_map_rule_details_payload_ntoh(vapi_payload_map_rule_details *payload)
{
  payload->psid = be16toh(payload->psid);
}

static inline void vapi_msg_map_rule_details_hton(vapi_msg_map_rule_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_rule_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_map_rule_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_rule_details_ntoh(vapi_msg_map_rule_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_rule_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_map_rule_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_rule_details_msg_size(vapi_msg_map_rule_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_rule_details_msg_size(vapi_msg_map_rule_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_rule_details) > buf_size)
    {
      VAPI_ERR("Truncated 'map_rule_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_rule_details));
      return -1;
    }
  if (vapi_calc_map_rule_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_rule_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_rule_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_map_rule_details()
{
  static const char name[] = "map_rule_details";
  static const char name_with_crc[] = "map_rule_details_c7cbeea5";
  static vapi_message_desc_t __vapi_metadata_map_rule_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_map_rule_details, payload),
    (verify_msg_size_fn_t)vapi_verify_map_rule_details_msg_size,
    (generic_swap_fn_t)vapi_msg_map_rule_details_hton,
    (generic_swap_fn_t)vapi_msg_map_rule_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_rule_details = vapi_register_msg(&__vapi_metadata_map_rule_details);
  VAPI_DBG("Assigned msg id %d to map_rule_details", vapi_msg_id_map_rule_details);
}

static inline void vapi_set_vapi_msg_map_rule_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_map_rule_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_map_rule_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_map_rule_dump
#define defined_vapi_msg_map_rule_dump
typedef struct __attribute__ ((__packed__)) {
  u32 domain_index; 
} vapi_payload_map_rule_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_map_rule_dump payload;
} vapi_msg_map_rule_dump;

static inline void vapi_msg_map_rule_dump_payload_hton(vapi_payload_map_rule_dump *payload)
{
  payload->domain_index = htobe32(payload->domain_index);
}

static inline void vapi_msg_map_rule_dump_payload_ntoh(vapi_payload_map_rule_dump *payload)
{
  payload->domain_index = be32toh(payload->domain_index);
}

static inline void vapi_msg_map_rule_dump_hton(vapi_msg_map_rule_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_rule_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_map_rule_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_rule_dump_ntoh(vapi_msg_map_rule_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_rule_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_map_rule_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_rule_dump_msg_size(vapi_msg_map_rule_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_rule_dump_msg_size(vapi_msg_map_rule_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_rule_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'map_rule_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_rule_dump));
      return -1;
    }
  if (vapi_calc_map_rule_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_rule_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_rule_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_map_rule_dump* vapi_alloc_map_rule_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_map_rule_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_map_rule_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_map_rule_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_map_rule_dump);

  return msg;
}

static inline vapi_error_e vapi_map_rule_dump(struct vapi_ctx_s *ctx,
  vapi_msg_map_rule_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_map_rule_details *reply),
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
  vapi_msg_map_rule_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_map_rule_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_map_rule_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_map_rule_dump()
{
  static const char name[] = "map_rule_dump";
  static const char name_with_crc[] = "map_rule_dump_e43e6ff6";
  static vapi_message_desc_t __vapi_metadata_map_rule_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_map_rule_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_map_rule_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_map_rule_dump_hton,
    (generic_swap_fn_t)vapi_msg_map_rule_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_rule_dump = vapi_register_msg(&__vapi_metadata_map_rule_dump);
  VAPI_DBG("Assigned msg id %d to map_rule_dump", vapi_msg_id_map_rule_dump);
}
#endif

#ifndef defined_vapi_msg_map_if_enable_disable_reply
#define defined_vapi_msg_map_if_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_map_if_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_map_if_enable_disable_reply payload;
} vapi_msg_map_if_enable_disable_reply;

static inline void vapi_msg_map_if_enable_disable_reply_payload_hton(vapi_payload_map_if_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_map_if_enable_disable_reply_payload_ntoh(vapi_payload_map_if_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_map_if_enable_disable_reply_hton(vapi_msg_map_if_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_if_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_map_if_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_if_enable_disable_reply_ntoh(vapi_msg_map_if_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_if_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_map_if_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_if_enable_disable_reply_msg_size(vapi_msg_map_if_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_if_enable_disable_reply_msg_size(vapi_msg_map_if_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_if_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'map_if_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_if_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_map_if_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_if_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_if_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_map_if_enable_disable_reply()
{
  static const char name[] = "map_if_enable_disable_reply";
  static const char name_with_crc[] = "map_if_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_map_if_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_map_if_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_map_if_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_map_if_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_map_if_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_if_enable_disable_reply = vapi_register_msg(&__vapi_metadata_map_if_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to map_if_enable_disable_reply", vapi_msg_id_map_if_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_map_if_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_map_if_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_map_if_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_map_if_enable_disable
#define defined_vapi_msg_map_if_enable_disable
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  bool is_enable;
  bool is_translation; 
} vapi_payload_map_if_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_map_if_enable_disable payload;
} vapi_msg_map_if_enable_disable;

static inline void vapi_msg_map_if_enable_disable_payload_hton(vapi_payload_map_if_enable_disable *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_map_if_enable_disable_payload_ntoh(vapi_payload_map_if_enable_disable *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_map_if_enable_disable_hton(vapi_msg_map_if_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_if_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_map_if_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_if_enable_disable_ntoh(vapi_msg_map_if_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_if_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_map_if_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_if_enable_disable_msg_size(vapi_msg_map_if_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_if_enable_disable_msg_size(vapi_msg_map_if_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_if_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'map_if_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_if_enable_disable));
      return -1;
    }
  if (vapi_calc_map_if_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_if_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_if_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_map_if_enable_disable* vapi_alloc_map_if_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_map_if_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_map_if_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_map_if_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_map_if_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_map_if_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_map_if_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_map_if_enable_disable_reply *reply),
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
  vapi_msg_map_if_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_map_if_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_map_if_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_map_if_enable_disable()
{
  static const char name[] = "map_if_enable_disable";
  static const char name_with_crc[] = "map_if_enable_disable_59bb32f4";
  static vapi_message_desc_t __vapi_metadata_map_if_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_map_if_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_map_if_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_map_if_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_map_if_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_if_enable_disable = vapi_register_msg(&__vapi_metadata_map_if_enable_disable);
  VAPI_DBG("Assigned msg id %d to map_if_enable_disable", vapi_msg_id_map_if_enable_disable);
}
#endif

#ifndef defined_vapi_msg_map_summary_stats_reply
#define defined_vapi_msg_map_summary_stats_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u64 total_bindings;
  u64 total_pkts[2];
  u64 total_bytes[2];
  u64 total_ip4_fragments;
  u64 total_security_check[2]; 
} vapi_payload_map_summary_stats_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_map_summary_stats_reply payload;
} vapi_msg_map_summary_stats_reply;

static inline void vapi_msg_map_summary_stats_reply_payload_hton(vapi_payload_map_summary_stats_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->total_bindings = htobe64(payload->total_bindings);
  do { unsigned i; for (i = 0; i < 2; ++i) { payload->total_pkts[i] = htobe64(payload->total_pkts[i]); } } while(0);
  do { unsigned i; for (i = 0; i < 2; ++i) { payload->total_bytes[i] = htobe64(payload->total_bytes[i]); } } while(0);
  payload->total_ip4_fragments = htobe64(payload->total_ip4_fragments);
  do { unsigned i; for (i = 0; i < 2; ++i) { payload->total_security_check[i] = htobe64(payload->total_security_check[i]); } } while(0);
}

static inline void vapi_msg_map_summary_stats_reply_payload_ntoh(vapi_payload_map_summary_stats_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->total_bindings = be64toh(payload->total_bindings);
  do { unsigned i; for (i = 0; i < 2; ++i) { payload->total_pkts[i] = be64toh(payload->total_pkts[i]); } } while(0);
  do { unsigned i; for (i = 0; i < 2; ++i) { payload->total_bytes[i] = be64toh(payload->total_bytes[i]); } } while(0);
  payload->total_ip4_fragments = be64toh(payload->total_ip4_fragments);
  do { unsigned i; for (i = 0; i < 2; ++i) { payload->total_security_check[i] = be64toh(payload->total_security_check[i]); } } while(0);
}

static inline void vapi_msg_map_summary_stats_reply_hton(vapi_msg_map_summary_stats_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_summary_stats_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_map_summary_stats_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_summary_stats_reply_ntoh(vapi_msg_map_summary_stats_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_summary_stats_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_map_summary_stats_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_summary_stats_reply_msg_size(vapi_msg_map_summary_stats_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_summary_stats_reply_msg_size(vapi_msg_map_summary_stats_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_summary_stats_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'map_summary_stats_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_summary_stats_reply));
      return -1;
    }
  if (vapi_calc_map_summary_stats_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_summary_stats_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_summary_stats_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_map_summary_stats_reply()
{
  static const char name[] = "map_summary_stats_reply";
  static const char name_with_crc[] = "map_summary_stats_reply_0e4ace0e";
  static vapi_message_desc_t __vapi_metadata_map_summary_stats_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_map_summary_stats_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_map_summary_stats_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_map_summary_stats_reply_hton,
    (generic_swap_fn_t)vapi_msg_map_summary_stats_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_summary_stats_reply = vapi_register_msg(&__vapi_metadata_map_summary_stats_reply);
  VAPI_DBG("Assigned msg id %d to map_summary_stats_reply", vapi_msg_id_map_summary_stats_reply);
}

static inline void vapi_set_vapi_msg_map_summary_stats_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_map_summary_stats_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_map_summary_stats_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_map_summary_stats
#define defined_vapi_msg_map_summary_stats
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_map_summary_stats;

static inline void vapi_msg_map_summary_stats_hton(vapi_msg_map_summary_stats *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_summary_stats'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_map_summary_stats_ntoh(vapi_msg_map_summary_stats *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_summary_stats'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_map_summary_stats_msg_size(vapi_msg_map_summary_stats *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_summary_stats_msg_size(vapi_msg_map_summary_stats *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_summary_stats) > buf_size)
    {
      VAPI_ERR("Truncated 'map_summary_stats' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_summary_stats));
      return -1;
    }
  if (vapi_calc_map_summary_stats_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_summary_stats' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_summary_stats_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_map_summary_stats* vapi_alloc_map_summary_stats(struct vapi_ctx_s *ctx)
{
  vapi_msg_map_summary_stats *msg = NULL;
  const size_t size = sizeof(vapi_msg_map_summary_stats);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_map_summary_stats*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_map_summary_stats);

  return msg;
}

static inline vapi_error_e vapi_map_summary_stats(struct vapi_ctx_s *ctx,
  vapi_msg_map_summary_stats *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_map_summary_stats_reply *reply),
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
  vapi_msg_map_summary_stats_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_map_summary_stats_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_map_summary_stats_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_map_summary_stats()
{
  static const char name[] = "map_summary_stats";
  static const char name_with_crc[] = "map_summary_stats_51077d14";
  static vapi_message_desc_t __vapi_metadata_map_summary_stats = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_map_summary_stats_msg_size,
    (generic_swap_fn_t)vapi_msg_map_summary_stats_hton,
    (generic_swap_fn_t)vapi_msg_map_summary_stats_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_summary_stats = vapi_register_msg(&__vapi_metadata_map_summary_stats);
  VAPI_DBG("Assigned msg id %d to map_summary_stats", vapi_msg_id_map_summary_stats);
}
#endif

#ifndef defined_vapi_msg_map_param_set_fragmentation_reply
#define defined_vapi_msg_map_param_set_fragmentation_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_map_param_set_fragmentation_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_map_param_set_fragmentation_reply payload;
} vapi_msg_map_param_set_fragmentation_reply;

static inline void vapi_msg_map_param_set_fragmentation_reply_payload_hton(vapi_payload_map_param_set_fragmentation_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_map_param_set_fragmentation_reply_payload_ntoh(vapi_payload_map_param_set_fragmentation_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_map_param_set_fragmentation_reply_hton(vapi_msg_map_param_set_fragmentation_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_fragmentation_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_map_param_set_fragmentation_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_param_set_fragmentation_reply_ntoh(vapi_msg_map_param_set_fragmentation_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_fragmentation_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_map_param_set_fragmentation_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_param_set_fragmentation_reply_msg_size(vapi_msg_map_param_set_fragmentation_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_param_set_fragmentation_reply_msg_size(vapi_msg_map_param_set_fragmentation_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_param_set_fragmentation_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_fragmentation_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_param_set_fragmentation_reply));
      return -1;
    }
  if (vapi_calc_map_param_set_fragmentation_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_fragmentation_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_param_set_fragmentation_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_map_param_set_fragmentation_reply()
{
  static const char name[] = "map_param_set_fragmentation_reply";
  static const char name_with_crc[] = "map_param_set_fragmentation_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_map_param_set_fragmentation_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_map_param_set_fragmentation_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_map_param_set_fragmentation_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_map_param_set_fragmentation_reply_hton,
    (generic_swap_fn_t)vapi_msg_map_param_set_fragmentation_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_param_set_fragmentation_reply = vapi_register_msg(&__vapi_metadata_map_param_set_fragmentation_reply);
  VAPI_DBG("Assigned msg id %d to map_param_set_fragmentation_reply", vapi_msg_id_map_param_set_fragmentation_reply);
}

static inline void vapi_set_vapi_msg_map_param_set_fragmentation_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_map_param_set_fragmentation_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_map_param_set_fragmentation_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_map_param_set_fragmentation
#define defined_vapi_msg_map_param_set_fragmentation
typedef struct __attribute__ ((__packed__)) {
  bool inner;
  bool ignore_df; 
} vapi_payload_map_param_set_fragmentation;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_map_param_set_fragmentation payload;
} vapi_msg_map_param_set_fragmentation;

static inline void vapi_msg_map_param_set_fragmentation_payload_hton(vapi_payload_map_param_set_fragmentation *payload)
{

}

static inline void vapi_msg_map_param_set_fragmentation_payload_ntoh(vapi_payload_map_param_set_fragmentation *payload)
{

}

static inline void vapi_msg_map_param_set_fragmentation_hton(vapi_msg_map_param_set_fragmentation *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_fragmentation'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_map_param_set_fragmentation_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_param_set_fragmentation_ntoh(vapi_msg_map_param_set_fragmentation *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_fragmentation'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_map_param_set_fragmentation_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_param_set_fragmentation_msg_size(vapi_msg_map_param_set_fragmentation *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_param_set_fragmentation_msg_size(vapi_msg_map_param_set_fragmentation *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_param_set_fragmentation) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_fragmentation' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_param_set_fragmentation));
      return -1;
    }
  if (vapi_calc_map_param_set_fragmentation_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_fragmentation' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_param_set_fragmentation_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_map_param_set_fragmentation* vapi_alloc_map_param_set_fragmentation(struct vapi_ctx_s *ctx)
{
  vapi_msg_map_param_set_fragmentation *msg = NULL;
  const size_t size = sizeof(vapi_msg_map_param_set_fragmentation);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_map_param_set_fragmentation*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_map_param_set_fragmentation);

  return msg;
}

static inline vapi_error_e vapi_map_param_set_fragmentation(struct vapi_ctx_s *ctx,
  vapi_msg_map_param_set_fragmentation *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_map_param_set_fragmentation_reply *reply),
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
  vapi_msg_map_param_set_fragmentation_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_map_param_set_fragmentation_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_map_param_set_fragmentation_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_map_param_set_fragmentation()
{
  static const char name[] = "map_param_set_fragmentation";
  static const char name_with_crc[] = "map_param_set_fragmentation_9ff54d90";
  static vapi_message_desc_t __vapi_metadata_map_param_set_fragmentation = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_map_param_set_fragmentation, payload),
    (verify_msg_size_fn_t)vapi_verify_map_param_set_fragmentation_msg_size,
    (generic_swap_fn_t)vapi_msg_map_param_set_fragmentation_hton,
    (generic_swap_fn_t)vapi_msg_map_param_set_fragmentation_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_param_set_fragmentation = vapi_register_msg(&__vapi_metadata_map_param_set_fragmentation);
  VAPI_DBG("Assigned msg id %d to map_param_set_fragmentation", vapi_msg_id_map_param_set_fragmentation);
}
#endif

#ifndef defined_vapi_msg_map_param_set_icmp_reply
#define defined_vapi_msg_map_param_set_icmp_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_map_param_set_icmp_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_map_param_set_icmp_reply payload;
} vapi_msg_map_param_set_icmp_reply;

static inline void vapi_msg_map_param_set_icmp_reply_payload_hton(vapi_payload_map_param_set_icmp_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_map_param_set_icmp_reply_payload_ntoh(vapi_payload_map_param_set_icmp_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_map_param_set_icmp_reply_hton(vapi_msg_map_param_set_icmp_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_icmp_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_map_param_set_icmp_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_param_set_icmp_reply_ntoh(vapi_msg_map_param_set_icmp_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_icmp_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_map_param_set_icmp_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_param_set_icmp_reply_msg_size(vapi_msg_map_param_set_icmp_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_param_set_icmp_reply_msg_size(vapi_msg_map_param_set_icmp_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_param_set_icmp_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_icmp_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_param_set_icmp_reply));
      return -1;
    }
  if (vapi_calc_map_param_set_icmp_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_icmp_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_param_set_icmp_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_map_param_set_icmp_reply()
{
  static const char name[] = "map_param_set_icmp_reply";
  static const char name_with_crc[] = "map_param_set_icmp_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_map_param_set_icmp_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_map_param_set_icmp_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_map_param_set_icmp_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_map_param_set_icmp_reply_hton,
    (generic_swap_fn_t)vapi_msg_map_param_set_icmp_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_param_set_icmp_reply = vapi_register_msg(&__vapi_metadata_map_param_set_icmp_reply);
  VAPI_DBG("Assigned msg id %d to map_param_set_icmp_reply", vapi_msg_id_map_param_set_icmp_reply);
}

static inline void vapi_set_vapi_msg_map_param_set_icmp_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_map_param_set_icmp_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_map_param_set_icmp_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_map_param_set_icmp
#define defined_vapi_msg_map_param_set_icmp
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address ip4_err_relay_src; 
} vapi_payload_map_param_set_icmp;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_map_param_set_icmp payload;
} vapi_msg_map_param_set_icmp;

static inline void vapi_msg_map_param_set_icmp_payload_hton(vapi_payload_map_param_set_icmp *payload)
{

}

static inline void vapi_msg_map_param_set_icmp_payload_ntoh(vapi_payload_map_param_set_icmp *payload)
{

}

static inline void vapi_msg_map_param_set_icmp_hton(vapi_msg_map_param_set_icmp *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_icmp'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_map_param_set_icmp_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_param_set_icmp_ntoh(vapi_msg_map_param_set_icmp *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_icmp'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_map_param_set_icmp_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_param_set_icmp_msg_size(vapi_msg_map_param_set_icmp *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_param_set_icmp_msg_size(vapi_msg_map_param_set_icmp *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_param_set_icmp) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_icmp' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_param_set_icmp));
      return -1;
    }
  if (vapi_calc_map_param_set_icmp_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_icmp' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_param_set_icmp_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_map_param_set_icmp* vapi_alloc_map_param_set_icmp(struct vapi_ctx_s *ctx)
{
  vapi_msg_map_param_set_icmp *msg = NULL;
  const size_t size = sizeof(vapi_msg_map_param_set_icmp);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_map_param_set_icmp*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_map_param_set_icmp);

  return msg;
}

static inline vapi_error_e vapi_map_param_set_icmp(struct vapi_ctx_s *ctx,
  vapi_msg_map_param_set_icmp *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_map_param_set_icmp_reply *reply),
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
  vapi_msg_map_param_set_icmp_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_map_param_set_icmp_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_map_param_set_icmp_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_map_param_set_icmp()
{
  static const char name[] = "map_param_set_icmp";
  static const char name_with_crc[] = "map_param_set_icmp_58210cbf";
  static vapi_message_desc_t __vapi_metadata_map_param_set_icmp = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_map_param_set_icmp, payload),
    (verify_msg_size_fn_t)vapi_verify_map_param_set_icmp_msg_size,
    (generic_swap_fn_t)vapi_msg_map_param_set_icmp_hton,
    (generic_swap_fn_t)vapi_msg_map_param_set_icmp_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_param_set_icmp = vapi_register_msg(&__vapi_metadata_map_param_set_icmp);
  VAPI_DBG("Assigned msg id %d to map_param_set_icmp", vapi_msg_id_map_param_set_icmp);
}
#endif

#ifndef defined_vapi_msg_map_param_set_icmp6_reply
#define defined_vapi_msg_map_param_set_icmp6_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_map_param_set_icmp6_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_map_param_set_icmp6_reply payload;
} vapi_msg_map_param_set_icmp6_reply;

static inline void vapi_msg_map_param_set_icmp6_reply_payload_hton(vapi_payload_map_param_set_icmp6_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_map_param_set_icmp6_reply_payload_ntoh(vapi_payload_map_param_set_icmp6_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_map_param_set_icmp6_reply_hton(vapi_msg_map_param_set_icmp6_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_icmp6_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_map_param_set_icmp6_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_param_set_icmp6_reply_ntoh(vapi_msg_map_param_set_icmp6_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_icmp6_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_map_param_set_icmp6_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_param_set_icmp6_reply_msg_size(vapi_msg_map_param_set_icmp6_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_param_set_icmp6_reply_msg_size(vapi_msg_map_param_set_icmp6_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_param_set_icmp6_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_icmp6_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_param_set_icmp6_reply));
      return -1;
    }
  if (vapi_calc_map_param_set_icmp6_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_icmp6_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_param_set_icmp6_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_map_param_set_icmp6_reply()
{
  static const char name[] = "map_param_set_icmp6_reply";
  static const char name_with_crc[] = "map_param_set_icmp6_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_map_param_set_icmp6_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_map_param_set_icmp6_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_map_param_set_icmp6_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_map_param_set_icmp6_reply_hton,
    (generic_swap_fn_t)vapi_msg_map_param_set_icmp6_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_param_set_icmp6_reply = vapi_register_msg(&__vapi_metadata_map_param_set_icmp6_reply);
  VAPI_DBG("Assigned msg id %d to map_param_set_icmp6_reply", vapi_msg_id_map_param_set_icmp6_reply);
}

static inline void vapi_set_vapi_msg_map_param_set_icmp6_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_map_param_set_icmp6_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_map_param_set_icmp6_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_map_param_set_icmp6
#define defined_vapi_msg_map_param_set_icmp6
typedef struct __attribute__ ((__packed__)) {
  bool enable_unreachable; 
} vapi_payload_map_param_set_icmp6;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_map_param_set_icmp6 payload;
} vapi_msg_map_param_set_icmp6;

static inline void vapi_msg_map_param_set_icmp6_payload_hton(vapi_payload_map_param_set_icmp6 *payload)
{

}

static inline void vapi_msg_map_param_set_icmp6_payload_ntoh(vapi_payload_map_param_set_icmp6 *payload)
{

}

static inline void vapi_msg_map_param_set_icmp6_hton(vapi_msg_map_param_set_icmp6 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_icmp6'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_map_param_set_icmp6_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_param_set_icmp6_ntoh(vapi_msg_map_param_set_icmp6 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_icmp6'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_map_param_set_icmp6_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_param_set_icmp6_msg_size(vapi_msg_map_param_set_icmp6 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_param_set_icmp6_msg_size(vapi_msg_map_param_set_icmp6 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_param_set_icmp6) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_icmp6' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_param_set_icmp6));
      return -1;
    }
  if (vapi_calc_map_param_set_icmp6_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_icmp6' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_param_set_icmp6_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_map_param_set_icmp6* vapi_alloc_map_param_set_icmp6(struct vapi_ctx_s *ctx)
{
  vapi_msg_map_param_set_icmp6 *msg = NULL;
  const size_t size = sizeof(vapi_msg_map_param_set_icmp6);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_map_param_set_icmp6*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_map_param_set_icmp6);

  return msg;
}

static inline vapi_error_e vapi_map_param_set_icmp6(struct vapi_ctx_s *ctx,
  vapi_msg_map_param_set_icmp6 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_map_param_set_icmp6_reply *reply),
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
  vapi_msg_map_param_set_icmp6_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_map_param_set_icmp6_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_map_param_set_icmp6_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_map_param_set_icmp6()
{
  static const char name[] = "map_param_set_icmp6";
  static const char name_with_crc[] = "map_param_set_icmp6_5d01f8c1";
  static vapi_message_desc_t __vapi_metadata_map_param_set_icmp6 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_map_param_set_icmp6, payload),
    (verify_msg_size_fn_t)vapi_verify_map_param_set_icmp6_msg_size,
    (generic_swap_fn_t)vapi_msg_map_param_set_icmp6_hton,
    (generic_swap_fn_t)vapi_msg_map_param_set_icmp6_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_param_set_icmp6 = vapi_register_msg(&__vapi_metadata_map_param_set_icmp6);
  VAPI_DBG("Assigned msg id %d to map_param_set_icmp6", vapi_msg_id_map_param_set_icmp6);
}
#endif

#ifndef defined_vapi_msg_map_param_add_del_pre_resolve_reply
#define defined_vapi_msg_map_param_add_del_pre_resolve_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_map_param_add_del_pre_resolve_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_map_param_add_del_pre_resolve_reply payload;
} vapi_msg_map_param_add_del_pre_resolve_reply;

static inline void vapi_msg_map_param_add_del_pre_resolve_reply_payload_hton(vapi_payload_map_param_add_del_pre_resolve_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_map_param_add_del_pre_resolve_reply_payload_ntoh(vapi_payload_map_param_add_del_pre_resolve_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_map_param_add_del_pre_resolve_reply_hton(vapi_msg_map_param_add_del_pre_resolve_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_add_del_pre_resolve_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_map_param_add_del_pre_resolve_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_param_add_del_pre_resolve_reply_ntoh(vapi_msg_map_param_add_del_pre_resolve_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_add_del_pre_resolve_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_map_param_add_del_pre_resolve_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_param_add_del_pre_resolve_reply_msg_size(vapi_msg_map_param_add_del_pre_resolve_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_param_add_del_pre_resolve_reply_msg_size(vapi_msg_map_param_add_del_pre_resolve_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_param_add_del_pre_resolve_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_add_del_pre_resolve_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_param_add_del_pre_resolve_reply));
      return -1;
    }
  if (vapi_calc_map_param_add_del_pre_resolve_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_add_del_pre_resolve_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_param_add_del_pre_resolve_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_map_param_add_del_pre_resolve_reply()
{
  static const char name[] = "map_param_add_del_pre_resolve_reply";
  static const char name_with_crc[] = "map_param_add_del_pre_resolve_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_map_param_add_del_pre_resolve_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_map_param_add_del_pre_resolve_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_map_param_add_del_pre_resolve_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_map_param_add_del_pre_resolve_reply_hton,
    (generic_swap_fn_t)vapi_msg_map_param_add_del_pre_resolve_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_param_add_del_pre_resolve_reply = vapi_register_msg(&__vapi_metadata_map_param_add_del_pre_resolve_reply);
  VAPI_DBG("Assigned msg id %d to map_param_add_del_pre_resolve_reply", vapi_msg_id_map_param_add_del_pre_resolve_reply);
}

static inline void vapi_set_vapi_msg_map_param_add_del_pre_resolve_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_map_param_add_del_pre_resolve_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_map_param_add_del_pre_resolve_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_map_param_add_del_pre_resolve
#define defined_vapi_msg_map_param_add_del_pre_resolve
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_ip4_address ip4_nh_address;
  vapi_type_ip6_address ip6_nh_address; 
} vapi_payload_map_param_add_del_pre_resolve;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_map_param_add_del_pre_resolve payload;
} vapi_msg_map_param_add_del_pre_resolve;

static inline void vapi_msg_map_param_add_del_pre_resolve_payload_hton(vapi_payload_map_param_add_del_pre_resolve *payload)
{

}

static inline void vapi_msg_map_param_add_del_pre_resolve_payload_ntoh(vapi_payload_map_param_add_del_pre_resolve *payload)
{

}

static inline void vapi_msg_map_param_add_del_pre_resolve_hton(vapi_msg_map_param_add_del_pre_resolve *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_add_del_pre_resolve'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_map_param_add_del_pre_resolve_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_param_add_del_pre_resolve_ntoh(vapi_msg_map_param_add_del_pre_resolve *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_add_del_pre_resolve'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_map_param_add_del_pre_resolve_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_param_add_del_pre_resolve_msg_size(vapi_msg_map_param_add_del_pre_resolve *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_param_add_del_pre_resolve_msg_size(vapi_msg_map_param_add_del_pre_resolve *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_param_add_del_pre_resolve) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_add_del_pre_resolve' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_param_add_del_pre_resolve));
      return -1;
    }
  if (vapi_calc_map_param_add_del_pre_resolve_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_add_del_pre_resolve' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_param_add_del_pre_resolve_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_map_param_add_del_pre_resolve* vapi_alloc_map_param_add_del_pre_resolve(struct vapi_ctx_s *ctx)
{
  vapi_msg_map_param_add_del_pre_resolve *msg = NULL;
  const size_t size = sizeof(vapi_msg_map_param_add_del_pre_resolve);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_map_param_add_del_pre_resolve*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_map_param_add_del_pre_resolve);

  return msg;
}

static inline vapi_error_e vapi_map_param_add_del_pre_resolve(struct vapi_ctx_s *ctx,
  vapi_msg_map_param_add_del_pre_resolve *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_map_param_add_del_pre_resolve_reply *reply),
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
  vapi_msg_map_param_add_del_pre_resolve_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_map_param_add_del_pre_resolve_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_map_param_add_del_pre_resolve_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_map_param_add_del_pre_resolve()
{
  static const char name[] = "map_param_add_del_pre_resolve";
  static const char name_with_crc[] = "map_param_add_del_pre_resolve_dae5af03";
  static vapi_message_desc_t __vapi_metadata_map_param_add_del_pre_resolve = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_map_param_add_del_pre_resolve, payload),
    (verify_msg_size_fn_t)vapi_verify_map_param_add_del_pre_resolve_msg_size,
    (generic_swap_fn_t)vapi_msg_map_param_add_del_pre_resolve_hton,
    (generic_swap_fn_t)vapi_msg_map_param_add_del_pre_resolve_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_param_add_del_pre_resolve = vapi_register_msg(&__vapi_metadata_map_param_add_del_pre_resolve);
  VAPI_DBG("Assigned msg id %d to map_param_add_del_pre_resolve", vapi_msg_id_map_param_add_del_pre_resolve);
}
#endif

#ifndef defined_vapi_msg_map_param_set_security_check_reply
#define defined_vapi_msg_map_param_set_security_check_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_map_param_set_security_check_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_map_param_set_security_check_reply payload;
} vapi_msg_map_param_set_security_check_reply;

static inline void vapi_msg_map_param_set_security_check_reply_payload_hton(vapi_payload_map_param_set_security_check_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_map_param_set_security_check_reply_payload_ntoh(vapi_payload_map_param_set_security_check_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_map_param_set_security_check_reply_hton(vapi_msg_map_param_set_security_check_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_security_check_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_map_param_set_security_check_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_param_set_security_check_reply_ntoh(vapi_msg_map_param_set_security_check_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_security_check_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_map_param_set_security_check_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_param_set_security_check_reply_msg_size(vapi_msg_map_param_set_security_check_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_param_set_security_check_reply_msg_size(vapi_msg_map_param_set_security_check_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_param_set_security_check_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_security_check_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_param_set_security_check_reply));
      return -1;
    }
  if (vapi_calc_map_param_set_security_check_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_security_check_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_param_set_security_check_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_map_param_set_security_check_reply()
{
  static const char name[] = "map_param_set_security_check_reply";
  static const char name_with_crc[] = "map_param_set_security_check_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_map_param_set_security_check_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_map_param_set_security_check_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_map_param_set_security_check_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_map_param_set_security_check_reply_hton,
    (generic_swap_fn_t)vapi_msg_map_param_set_security_check_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_param_set_security_check_reply = vapi_register_msg(&__vapi_metadata_map_param_set_security_check_reply);
  VAPI_DBG("Assigned msg id %d to map_param_set_security_check_reply", vapi_msg_id_map_param_set_security_check_reply);
}

static inline void vapi_set_vapi_msg_map_param_set_security_check_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_map_param_set_security_check_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_map_param_set_security_check_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_map_param_set_security_check
#define defined_vapi_msg_map_param_set_security_check
typedef struct __attribute__ ((__packed__)) {
  bool enable;
  bool fragments; 
} vapi_payload_map_param_set_security_check;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_map_param_set_security_check payload;
} vapi_msg_map_param_set_security_check;

static inline void vapi_msg_map_param_set_security_check_payload_hton(vapi_payload_map_param_set_security_check *payload)
{

}

static inline void vapi_msg_map_param_set_security_check_payload_ntoh(vapi_payload_map_param_set_security_check *payload)
{

}

static inline void vapi_msg_map_param_set_security_check_hton(vapi_msg_map_param_set_security_check *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_security_check'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_map_param_set_security_check_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_param_set_security_check_ntoh(vapi_msg_map_param_set_security_check *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_security_check'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_map_param_set_security_check_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_param_set_security_check_msg_size(vapi_msg_map_param_set_security_check *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_param_set_security_check_msg_size(vapi_msg_map_param_set_security_check *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_param_set_security_check) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_security_check' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_param_set_security_check));
      return -1;
    }
  if (vapi_calc_map_param_set_security_check_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_security_check' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_param_set_security_check_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_map_param_set_security_check* vapi_alloc_map_param_set_security_check(struct vapi_ctx_s *ctx)
{
  vapi_msg_map_param_set_security_check *msg = NULL;
  const size_t size = sizeof(vapi_msg_map_param_set_security_check);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_map_param_set_security_check*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_map_param_set_security_check);

  return msg;
}

static inline vapi_error_e vapi_map_param_set_security_check(struct vapi_ctx_s *ctx,
  vapi_msg_map_param_set_security_check *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_map_param_set_security_check_reply *reply),
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
  vapi_msg_map_param_set_security_check_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_map_param_set_security_check_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_map_param_set_security_check_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_map_param_set_security_check()
{
  static const char name[] = "map_param_set_security_check";
  static const char name_with_crc[] = "map_param_set_security_check_6abe9836";
  static vapi_message_desc_t __vapi_metadata_map_param_set_security_check = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_map_param_set_security_check, payload),
    (verify_msg_size_fn_t)vapi_verify_map_param_set_security_check_msg_size,
    (generic_swap_fn_t)vapi_msg_map_param_set_security_check_hton,
    (generic_swap_fn_t)vapi_msg_map_param_set_security_check_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_param_set_security_check = vapi_register_msg(&__vapi_metadata_map_param_set_security_check);
  VAPI_DBG("Assigned msg id %d to map_param_set_security_check", vapi_msg_id_map_param_set_security_check);
}
#endif

#ifndef defined_vapi_msg_map_param_set_traffic_class_reply
#define defined_vapi_msg_map_param_set_traffic_class_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_map_param_set_traffic_class_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_map_param_set_traffic_class_reply payload;
} vapi_msg_map_param_set_traffic_class_reply;

static inline void vapi_msg_map_param_set_traffic_class_reply_payload_hton(vapi_payload_map_param_set_traffic_class_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_map_param_set_traffic_class_reply_payload_ntoh(vapi_payload_map_param_set_traffic_class_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_map_param_set_traffic_class_reply_hton(vapi_msg_map_param_set_traffic_class_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_traffic_class_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_map_param_set_traffic_class_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_param_set_traffic_class_reply_ntoh(vapi_msg_map_param_set_traffic_class_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_traffic_class_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_map_param_set_traffic_class_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_param_set_traffic_class_reply_msg_size(vapi_msg_map_param_set_traffic_class_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_param_set_traffic_class_reply_msg_size(vapi_msg_map_param_set_traffic_class_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_param_set_traffic_class_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_traffic_class_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_param_set_traffic_class_reply));
      return -1;
    }
  if (vapi_calc_map_param_set_traffic_class_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_traffic_class_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_param_set_traffic_class_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_map_param_set_traffic_class_reply()
{
  static const char name[] = "map_param_set_traffic_class_reply";
  static const char name_with_crc[] = "map_param_set_traffic_class_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_map_param_set_traffic_class_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_map_param_set_traffic_class_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_map_param_set_traffic_class_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_map_param_set_traffic_class_reply_hton,
    (generic_swap_fn_t)vapi_msg_map_param_set_traffic_class_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_param_set_traffic_class_reply = vapi_register_msg(&__vapi_metadata_map_param_set_traffic_class_reply);
  VAPI_DBG("Assigned msg id %d to map_param_set_traffic_class_reply", vapi_msg_id_map_param_set_traffic_class_reply);
}

static inline void vapi_set_vapi_msg_map_param_set_traffic_class_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_map_param_set_traffic_class_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_map_param_set_traffic_class_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_map_param_set_traffic_class
#define defined_vapi_msg_map_param_set_traffic_class
typedef struct __attribute__ ((__packed__)) {
  bool copy;
  u8 tc_class; 
} vapi_payload_map_param_set_traffic_class;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_map_param_set_traffic_class payload;
} vapi_msg_map_param_set_traffic_class;

static inline void vapi_msg_map_param_set_traffic_class_payload_hton(vapi_payload_map_param_set_traffic_class *payload)
{

}

static inline void vapi_msg_map_param_set_traffic_class_payload_ntoh(vapi_payload_map_param_set_traffic_class *payload)
{

}

static inline void vapi_msg_map_param_set_traffic_class_hton(vapi_msg_map_param_set_traffic_class *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_traffic_class'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_map_param_set_traffic_class_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_param_set_traffic_class_ntoh(vapi_msg_map_param_set_traffic_class *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_traffic_class'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_map_param_set_traffic_class_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_param_set_traffic_class_msg_size(vapi_msg_map_param_set_traffic_class *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_param_set_traffic_class_msg_size(vapi_msg_map_param_set_traffic_class *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_param_set_traffic_class) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_traffic_class' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_param_set_traffic_class));
      return -1;
    }
  if (vapi_calc_map_param_set_traffic_class_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_traffic_class' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_param_set_traffic_class_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_map_param_set_traffic_class* vapi_alloc_map_param_set_traffic_class(struct vapi_ctx_s *ctx)
{
  vapi_msg_map_param_set_traffic_class *msg = NULL;
  const size_t size = sizeof(vapi_msg_map_param_set_traffic_class);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_map_param_set_traffic_class*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_map_param_set_traffic_class);

  return msg;
}

static inline vapi_error_e vapi_map_param_set_traffic_class(struct vapi_ctx_s *ctx,
  vapi_msg_map_param_set_traffic_class *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_map_param_set_traffic_class_reply *reply),
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
  vapi_msg_map_param_set_traffic_class_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_map_param_set_traffic_class_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_map_param_set_traffic_class_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_map_param_set_traffic_class()
{
  static const char name[] = "map_param_set_traffic_class";
  static const char name_with_crc[] = "map_param_set_traffic_class_9cac455c";
  static vapi_message_desc_t __vapi_metadata_map_param_set_traffic_class = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_map_param_set_traffic_class, payload),
    (verify_msg_size_fn_t)vapi_verify_map_param_set_traffic_class_msg_size,
    (generic_swap_fn_t)vapi_msg_map_param_set_traffic_class_hton,
    (generic_swap_fn_t)vapi_msg_map_param_set_traffic_class_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_param_set_traffic_class = vapi_register_msg(&__vapi_metadata_map_param_set_traffic_class);
  VAPI_DBG("Assigned msg id %d to map_param_set_traffic_class", vapi_msg_id_map_param_set_traffic_class);
}
#endif

#ifndef defined_vapi_msg_map_param_set_tcp_reply
#define defined_vapi_msg_map_param_set_tcp_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_map_param_set_tcp_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_map_param_set_tcp_reply payload;
} vapi_msg_map_param_set_tcp_reply;

static inline void vapi_msg_map_param_set_tcp_reply_payload_hton(vapi_payload_map_param_set_tcp_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_map_param_set_tcp_reply_payload_ntoh(vapi_payload_map_param_set_tcp_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_map_param_set_tcp_reply_hton(vapi_msg_map_param_set_tcp_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_tcp_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_map_param_set_tcp_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_param_set_tcp_reply_ntoh(vapi_msg_map_param_set_tcp_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_tcp_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_map_param_set_tcp_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_param_set_tcp_reply_msg_size(vapi_msg_map_param_set_tcp_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_param_set_tcp_reply_msg_size(vapi_msg_map_param_set_tcp_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_param_set_tcp_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_tcp_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_param_set_tcp_reply));
      return -1;
    }
  if (vapi_calc_map_param_set_tcp_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_tcp_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_param_set_tcp_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_map_param_set_tcp_reply()
{
  static const char name[] = "map_param_set_tcp_reply";
  static const char name_with_crc[] = "map_param_set_tcp_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_map_param_set_tcp_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_map_param_set_tcp_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_map_param_set_tcp_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_map_param_set_tcp_reply_hton,
    (generic_swap_fn_t)vapi_msg_map_param_set_tcp_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_param_set_tcp_reply = vapi_register_msg(&__vapi_metadata_map_param_set_tcp_reply);
  VAPI_DBG("Assigned msg id %d to map_param_set_tcp_reply", vapi_msg_id_map_param_set_tcp_reply);
}

static inline void vapi_set_vapi_msg_map_param_set_tcp_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_map_param_set_tcp_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_map_param_set_tcp_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_map_param_set_tcp
#define defined_vapi_msg_map_param_set_tcp
typedef struct __attribute__ ((__packed__)) {
  u16 tcp_mss; 
} vapi_payload_map_param_set_tcp;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_map_param_set_tcp payload;
} vapi_msg_map_param_set_tcp;

static inline void vapi_msg_map_param_set_tcp_payload_hton(vapi_payload_map_param_set_tcp *payload)
{
  payload->tcp_mss = htobe16(payload->tcp_mss);
}

static inline void vapi_msg_map_param_set_tcp_payload_ntoh(vapi_payload_map_param_set_tcp *payload)
{
  payload->tcp_mss = be16toh(payload->tcp_mss);
}

static inline void vapi_msg_map_param_set_tcp_hton(vapi_msg_map_param_set_tcp *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_tcp'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_map_param_set_tcp_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_param_set_tcp_ntoh(vapi_msg_map_param_set_tcp *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_set_tcp'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_map_param_set_tcp_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_param_set_tcp_msg_size(vapi_msg_map_param_set_tcp *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_param_set_tcp_msg_size(vapi_msg_map_param_set_tcp *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_param_set_tcp) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_tcp' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_param_set_tcp));
      return -1;
    }
  if (vapi_calc_map_param_set_tcp_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_set_tcp' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_param_set_tcp_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_map_param_set_tcp* vapi_alloc_map_param_set_tcp(struct vapi_ctx_s *ctx)
{
  vapi_msg_map_param_set_tcp *msg = NULL;
  const size_t size = sizeof(vapi_msg_map_param_set_tcp);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_map_param_set_tcp*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_map_param_set_tcp);

  return msg;
}

static inline vapi_error_e vapi_map_param_set_tcp(struct vapi_ctx_s *ctx,
  vapi_msg_map_param_set_tcp *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_map_param_set_tcp_reply *reply),
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
  vapi_msg_map_param_set_tcp_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_map_param_set_tcp_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_map_param_set_tcp_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_map_param_set_tcp()
{
  static const char name[] = "map_param_set_tcp";
  static const char name_with_crc[] = "map_param_set_tcp_87a825d9";
  static vapi_message_desc_t __vapi_metadata_map_param_set_tcp = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_map_param_set_tcp, payload),
    (verify_msg_size_fn_t)vapi_verify_map_param_set_tcp_msg_size,
    (generic_swap_fn_t)vapi_msg_map_param_set_tcp_hton,
    (generic_swap_fn_t)vapi_msg_map_param_set_tcp_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_param_set_tcp = vapi_register_msg(&__vapi_metadata_map_param_set_tcp);
  VAPI_DBG("Assigned msg id %d to map_param_set_tcp", vapi_msg_id_map_param_set_tcp);
}
#endif

#ifndef defined_vapi_msg_map_param_get_reply
#define defined_vapi_msg_map_param_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u8 frag_inner;
  u8 frag_ignore_df;
  vapi_type_ip4_address icmp_ip4_err_relay_src;
  bool icmp6_enable_unreachable;
  vapi_type_ip4_address ip4_nh_address;
  vapi_type_ip6_address ip6_nh_address;
  u16 ip4_lifetime_ms;
  u16 ip4_pool_size;
  u32 ip4_buffers;
  f64 ip4_ht_ratio;
  bool sec_check_enable;
  bool sec_check_fragments;
  bool tc_copy;
  u8 tc_class; 
} vapi_payload_map_param_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_map_param_get_reply payload;
} vapi_msg_map_param_get_reply;

static inline void vapi_msg_map_param_get_reply_payload_hton(vapi_payload_map_param_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->ip4_lifetime_ms = htobe16(payload->ip4_lifetime_ms);
  payload->ip4_pool_size = htobe16(payload->ip4_pool_size);
  payload->ip4_buffers = htobe32(payload->ip4_buffers);
}

static inline void vapi_msg_map_param_get_reply_payload_ntoh(vapi_payload_map_param_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->ip4_lifetime_ms = be16toh(payload->ip4_lifetime_ms);
  payload->ip4_pool_size = be16toh(payload->ip4_pool_size);
  payload->ip4_buffers = be32toh(payload->ip4_buffers);
}

static inline void vapi_msg_map_param_get_reply_hton(vapi_msg_map_param_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_map_param_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_map_param_get_reply_ntoh(vapi_msg_map_param_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_map_param_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_map_param_get_reply_msg_size(vapi_msg_map_param_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_param_get_reply_msg_size(vapi_msg_map_param_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_param_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_param_get_reply));
      return -1;
    }
  if (vapi_calc_map_param_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_param_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_map_param_get_reply()
{
  static const char name[] = "map_param_get_reply";
  static const char name_with_crc[] = "map_param_get_reply_26272c90";
  static vapi_message_desc_t __vapi_metadata_map_param_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_map_param_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_map_param_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_map_param_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_map_param_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_param_get_reply = vapi_register_msg(&__vapi_metadata_map_param_get_reply);
  VAPI_DBG("Assigned msg id %d to map_param_get_reply", vapi_msg_id_map_param_get_reply);
}

static inline void vapi_set_vapi_msg_map_param_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_map_param_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_map_param_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_map_param_get
#define defined_vapi_msg_map_param_get
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_map_param_get;

static inline void vapi_msg_map_param_get_hton(vapi_msg_map_param_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_map_param_get_ntoh(vapi_msg_map_param_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_map_param_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_map_param_get_msg_size(vapi_msg_map_param_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_map_param_get_msg_size(vapi_msg_map_param_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_map_param_get) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_map_param_get));
      return -1;
    }
  if (vapi_calc_map_param_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'map_param_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_map_param_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_map_param_get* vapi_alloc_map_param_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_map_param_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_map_param_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_map_param_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_map_param_get);

  return msg;
}

static inline vapi_error_e vapi_map_param_get(struct vapi_ctx_s *ctx,
  vapi_msg_map_param_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_map_param_get_reply *reply),
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
  vapi_msg_map_param_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_map_param_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_map_param_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_map_param_get()
{
  static const char name[] = "map_param_get";
  static const char name_with_crc[] = "map_param_get_51077d14";
  static vapi_message_desc_t __vapi_metadata_map_param_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_map_param_get_msg_size,
    (generic_swap_fn_t)vapi_msg_map_param_get_hton,
    (generic_swap_fn_t)vapi_msg_map_param_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_map_param_get = vapi_register_msg(&__vapi_metadata_map_param_get);
  VAPI_DBG("Assigned msg id %d to map_param_get", vapi_msg_id_map_param_get);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
