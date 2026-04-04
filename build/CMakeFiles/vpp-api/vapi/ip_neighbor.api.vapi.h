#ifndef __included_ip_neighbor_api_json
#define __included_ip_neighbor_api_json

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

extern vapi_msg_id_t vapi_msg_id_ip_neighbor_add_del;
extern vapi_msg_id_t vapi_msg_id_ip_neighbor_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_ip_neighbor_dump;
extern vapi_msg_id_t vapi_msg_id_ip_neighbor_details;
extern vapi_msg_id_t vapi_msg_id_ip_neighbor_config;
extern vapi_msg_id_t vapi_msg_id_ip_neighbor_config_reply;
extern vapi_msg_id_t vapi_msg_id_ip_neighbor_config_get;
extern vapi_msg_id_t vapi_msg_id_ip_neighbor_config_get_reply;
extern vapi_msg_id_t vapi_msg_id_ip_neighbor_replace_begin;
extern vapi_msg_id_t vapi_msg_id_ip_neighbor_replace_begin_reply;
extern vapi_msg_id_t vapi_msg_id_ip_neighbor_replace_end;
extern vapi_msg_id_t vapi_msg_id_ip_neighbor_replace_end_reply;
extern vapi_msg_id_t vapi_msg_id_ip_neighbor_flush;
extern vapi_msg_id_t vapi_msg_id_ip_neighbor_flush_reply;
extern vapi_msg_id_t vapi_msg_id_want_ip_neighbor_events;
extern vapi_msg_id_t vapi_msg_id_want_ip_neighbor_events_reply;
extern vapi_msg_id_t vapi_msg_id_ip_neighbor_event;
extern vapi_msg_id_t vapi_msg_id_want_ip_neighbor_events_v2;
extern vapi_msg_id_t vapi_msg_id_want_ip_neighbor_events_v2_reply;
extern vapi_msg_id_t vapi_msg_id_ip_neighbor_event_v2;

#define DEFINE_VAPI_MSG_IDS_IP_NEIGHBOR_API_JSON\
  vapi_msg_id_t vapi_msg_id_ip_neighbor_add_del;\
  vapi_msg_id_t vapi_msg_id_ip_neighbor_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_ip_neighbor_dump;\
  vapi_msg_id_t vapi_msg_id_ip_neighbor_details;\
  vapi_msg_id_t vapi_msg_id_ip_neighbor_config;\
  vapi_msg_id_t vapi_msg_id_ip_neighbor_config_reply;\
  vapi_msg_id_t vapi_msg_id_ip_neighbor_config_get;\
  vapi_msg_id_t vapi_msg_id_ip_neighbor_config_get_reply;\
  vapi_msg_id_t vapi_msg_id_ip_neighbor_replace_begin;\
  vapi_msg_id_t vapi_msg_id_ip_neighbor_replace_begin_reply;\
  vapi_msg_id_t vapi_msg_id_ip_neighbor_replace_end;\
  vapi_msg_id_t vapi_msg_id_ip_neighbor_replace_end_reply;\
  vapi_msg_id_t vapi_msg_id_ip_neighbor_flush;\
  vapi_msg_id_t vapi_msg_id_ip_neighbor_flush_reply;\
  vapi_msg_id_t vapi_msg_id_want_ip_neighbor_events;\
  vapi_msg_id_t vapi_msg_id_want_ip_neighbor_events_reply;\
  vapi_msg_id_t vapi_msg_id_ip_neighbor_event;\
  vapi_msg_id_t vapi_msg_id_want_ip_neighbor_events_v2;\
  vapi_msg_id_t vapi_msg_id_want_ip_neighbor_events_v2_reply;\
  vapi_msg_id_t vapi_msg_id_ip_neighbor_event_v2;


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

#ifndef defined_vapi_enum_ip_neighbor_flags
#define defined_vapi_enum_ip_neighbor_flags
typedef enum {
  IP_API_NEIGHBOR_FLAG_NONE = 0,
  IP_API_NEIGHBOR_FLAG_STATIC = 1,
  IP_API_NEIGHBOR_FLAG_NO_FIB_ENTRY = 2,
} __attribute__((packed)) vapi_enum_ip_neighbor_flags;

#endif

#ifndef defined_vapi_enum_ip_neighbor_event_flags
#define defined_vapi_enum_ip_neighbor_event_flags
typedef enum {
  IP_NEIGHBOR_API_EVENT_FLAG_ADDED = 1,
  IP_NEIGHBOR_API_EVENT_FLAG_REMOVED = 2,
}  vapi_enum_ip_neighbor_event_flags;

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

#ifndef defined_vapi_type_ip_neighbor
#define defined_vapi_type_ip_neighbor
typedef struct __attribute__((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_enum_ip_neighbor_flags flags;
  vapi_type_mac_address mac_address;
  vapi_type_address ip_address;
} vapi_type_ip_neighbor;

static inline void vapi_type_ip_neighbor_hton(vapi_type_ip_neighbor *msg)
{
  msg->sw_if_index = htobe32(msg->sw_if_index);
}

static inline void vapi_type_ip_neighbor_ntoh(vapi_type_ip_neighbor *msg)
{
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

#ifndef defined_vapi_msg_ip_neighbor_add_del_reply
#define defined_vapi_msg_ip_neighbor_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 stats_index; 
} vapi_payload_ip_neighbor_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_neighbor_add_del_reply payload;
} vapi_msg_ip_neighbor_add_del_reply;

static inline void vapi_msg_ip_neighbor_add_del_reply_payload_hton(vapi_payload_ip_neighbor_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->stats_index = htobe32(payload->stats_index);
}

static inline void vapi_msg_ip_neighbor_add_del_reply_payload_ntoh(vapi_payload_ip_neighbor_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->stats_index = be32toh(payload->stats_index);
}

static inline void vapi_msg_ip_neighbor_add_del_reply_hton(vapi_msg_ip_neighbor_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_neighbor_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_neighbor_add_del_reply_ntoh(vapi_msg_ip_neighbor_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_neighbor_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_neighbor_add_del_reply_msg_size(vapi_msg_ip_neighbor_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_neighbor_add_del_reply_msg_size(vapi_msg_ip_neighbor_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_neighbor_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_neighbor_add_del_reply));
      return -1;
    }
  if (vapi_calc_ip_neighbor_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_neighbor_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_neighbor_add_del_reply()
{
  static const char name[] = "ip_neighbor_add_del_reply";
  static const char name_with_crc[] = "ip_neighbor_add_del_reply_1992deab";
  static vapi_message_desc_t __vapi_metadata_ip_neighbor_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_neighbor_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_neighbor_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_neighbor_add_del_reply = vapi_register_msg(&__vapi_metadata_ip_neighbor_add_del_reply);
  VAPI_DBG("Assigned msg id %d to ip_neighbor_add_del_reply", vapi_msg_id_ip_neighbor_add_del_reply);
}

static inline void vapi_set_vapi_msg_ip_neighbor_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_neighbor_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_neighbor_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_neighbor_add_del
#define defined_vapi_msg_ip_neighbor_add_del
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_ip_neighbor neighbor; 
} vapi_payload_ip_neighbor_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_neighbor_add_del payload;
} vapi_msg_ip_neighbor_add_del;

static inline void vapi_msg_ip_neighbor_add_del_payload_hton(vapi_payload_ip_neighbor_add_del *payload)
{
  vapi_type_ip_neighbor_hton(&payload->neighbor);
}

static inline void vapi_msg_ip_neighbor_add_del_payload_ntoh(vapi_payload_ip_neighbor_add_del *payload)
{
  vapi_type_ip_neighbor_ntoh(&payload->neighbor);
}

static inline void vapi_msg_ip_neighbor_add_del_hton(vapi_msg_ip_neighbor_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_neighbor_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_neighbor_add_del_ntoh(vapi_msg_ip_neighbor_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_neighbor_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_neighbor_add_del_msg_size(vapi_msg_ip_neighbor_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_neighbor_add_del_msg_size(vapi_msg_ip_neighbor_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_neighbor_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_neighbor_add_del));
      return -1;
    }
  if (vapi_calc_ip_neighbor_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_neighbor_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_neighbor_add_del* vapi_alloc_ip_neighbor_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_neighbor_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_neighbor_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_neighbor_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_neighbor_add_del);

  return msg;
}

static inline vapi_error_e vapi_ip_neighbor_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_ip_neighbor_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_neighbor_add_del_reply *reply),
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
  vapi_msg_ip_neighbor_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_neighbor_add_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ip_neighbor_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_neighbor_add_del()
{
  static const char name[] = "ip_neighbor_add_del";
  static const char name_with_crc[] = "ip_neighbor_add_del_0607c257";
  static vapi_message_desc_t __vapi_metadata_ip_neighbor_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_neighbor_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_neighbor_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_add_del_hton,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_neighbor_add_del = vapi_register_msg(&__vapi_metadata_ip_neighbor_add_del);
  VAPI_DBG("Assigned msg id %d to ip_neighbor_add_del", vapi_msg_id_ip_neighbor_add_del);
}
#endif

#ifndef defined_vapi_msg_ip_neighbor_details
#define defined_vapi_msg_ip_neighbor_details
typedef struct __attribute__ ((__packed__)) {
  f64 age;
  vapi_type_ip_neighbor neighbor; 
} vapi_payload_ip_neighbor_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_neighbor_details payload;
} vapi_msg_ip_neighbor_details;

static inline void vapi_msg_ip_neighbor_details_payload_hton(vapi_payload_ip_neighbor_details *payload)
{
  vapi_type_ip_neighbor_hton(&payload->neighbor);
}

static inline void vapi_msg_ip_neighbor_details_payload_ntoh(vapi_payload_ip_neighbor_details *payload)
{
  vapi_type_ip_neighbor_ntoh(&payload->neighbor);
}

static inline void vapi_msg_ip_neighbor_details_hton(vapi_msg_ip_neighbor_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_neighbor_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_neighbor_details_ntoh(vapi_msg_ip_neighbor_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_neighbor_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_neighbor_details_msg_size(vapi_msg_ip_neighbor_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_neighbor_details_msg_size(vapi_msg_ip_neighbor_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_neighbor_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_neighbor_details));
      return -1;
    }
  if (vapi_calc_ip_neighbor_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_neighbor_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_neighbor_details()
{
  static const char name[] = "ip_neighbor_details";
  static const char name_with_crc[] = "ip_neighbor_details_e29d79f0";
  static vapi_message_desc_t __vapi_metadata_ip_neighbor_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_neighbor_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_neighbor_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_details_hton,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_neighbor_details = vapi_register_msg(&__vapi_metadata_ip_neighbor_details);
  VAPI_DBG("Assigned msg id %d to ip_neighbor_details", vapi_msg_id_ip_neighbor_details);
}

static inline void vapi_set_vapi_msg_ip_neighbor_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_neighbor_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_neighbor_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_neighbor_dump
#define defined_vapi_msg_ip_neighbor_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_enum_address_family af; 
} vapi_payload_ip_neighbor_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_neighbor_dump payload;
} vapi_msg_ip_neighbor_dump;

static inline void vapi_msg_ip_neighbor_dump_payload_hton(vapi_payload_ip_neighbor_dump *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ip_neighbor_dump_payload_ntoh(vapi_payload_ip_neighbor_dump *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ip_neighbor_dump_hton(vapi_msg_ip_neighbor_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_neighbor_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_neighbor_dump_ntoh(vapi_msg_ip_neighbor_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_neighbor_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_neighbor_dump_msg_size(vapi_msg_ip_neighbor_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_neighbor_dump_msg_size(vapi_msg_ip_neighbor_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_neighbor_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_neighbor_dump));
      return -1;
    }
  if (vapi_calc_ip_neighbor_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_neighbor_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_neighbor_dump* vapi_alloc_ip_neighbor_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_neighbor_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_neighbor_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_neighbor_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_neighbor_dump);

  return msg;
}

static inline vapi_error_e vapi_ip_neighbor_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ip_neighbor_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_neighbor_details *reply),
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
  vapi_msg_ip_neighbor_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_neighbor_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_ip_neighbor_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_neighbor_dump()
{
  static const char name[] = "ip_neighbor_dump";
  static const char name_with_crc[] = "ip_neighbor_dump_d817a484";
  static vapi_message_desc_t __vapi_metadata_ip_neighbor_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_neighbor_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_neighbor_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_dump_hton,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_neighbor_dump = vapi_register_msg(&__vapi_metadata_ip_neighbor_dump);
  VAPI_DBG("Assigned msg id %d to ip_neighbor_dump", vapi_msg_id_ip_neighbor_dump);
}
#endif

#ifndef defined_vapi_msg_ip_neighbor_config_reply
#define defined_vapi_msg_ip_neighbor_config_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip_neighbor_config_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_neighbor_config_reply payload;
} vapi_msg_ip_neighbor_config_reply;

static inline void vapi_msg_ip_neighbor_config_reply_payload_hton(vapi_payload_ip_neighbor_config_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_neighbor_config_reply_payload_ntoh(vapi_payload_ip_neighbor_config_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_neighbor_config_reply_hton(vapi_msg_ip_neighbor_config_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_config_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_neighbor_config_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_neighbor_config_reply_ntoh(vapi_msg_ip_neighbor_config_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_config_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_neighbor_config_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_neighbor_config_reply_msg_size(vapi_msg_ip_neighbor_config_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_neighbor_config_reply_msg_size(vapi_msg_ip_neighbor_config_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_neighbor_config_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_config_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_neighbor_config_reply));
      return -1;
    }
  if (vapi_calc_ip_neighbor_config_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_config_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_neighbor_config_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_neighbor_config_reply()
{
  static const char name[] = "ip_neighbor_config_reply";
  static const char name_with_crc[] = "ip_neighbor_config_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip_neighbor_config_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_neighbor_config_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_neighbor_config_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_config_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_config_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_neighbor_config_reply = vapi_register_msg(&__vapi_metadata_ip_neighbor_config_reply);
  VAPI_DBG("Assigned msg id %d to ip_neighbor_config_reply", vapi_msg_id_ip_neighbor_config_reply);
}

static inline void vapi_set_vapi_msg_ip_neighbor_config_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_neighbor_config_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_neighbor_config_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_neighbor_config
#define defined_vapi_msg_ip_neighbor_config
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_address_family af;
  u32 max_number;
  u32 max_age;
  bool recycle; 
} vapi_payload_ip_neighbor_config;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_neighbor_config payload;
} vapi_msg_ip_neighbor_config;

static inline void vapi_msg_ip_neighbor_config_payload_hton(vapi_payload_ip_neighbor_config *payload)
{
  payload->max_number = htobe32(payload->max_number);
  payload->max_age = htobe32(payload->max_age);
}

static inline void vapi_msg_ip_neighbor_config_payload_ntoh(vapi_payload_ip_neighbor_config *payload)
{
  payload->max_number = be32toh(payload->max_number);
  payload->max_age = be32toh(payload->max_age);
}

static inline void vapi_msg_ip_neighbor_config_hton(vapi_msg_ip_neighbor_config *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_config'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_neighbor_config_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_neighbor_config_ntoh(vapi_msg_ip_neighbor_config *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_config'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_neighbor_config_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_neighbor_config_msg_size(vapi_msg_ip_neighbor_config *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_neighbor_config_msg_size(vapi_msg_ip_neighbor_config *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_neighbor_config) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_config' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_neighbor_config));
      return -1;
    }
  if (vapi_calc_ip_neighbor_config_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_config' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_neighbor_config_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_neighbor_config* vapi_alloc_ip_neighbor_config(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_neighbor_config *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_neighbor_config);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_neighbor_config*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_neighbor_config);

  return msg;
}

static inline vapi_error_e vapi_ip_neighbor_config(struct vapi_ctx_s *ctx,
  vapi_msg_ip_neighbor_config *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_neighbor_config_reply *reply),
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
  vapi_msg_ip_neighbor_config_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_neighbor_config_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ip_neighbor_config_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_neighbor_config()
{
  static const char name[] = "ip_neighbor_config";
  static const char name_with_crc[] = "ip_neighbor_config_f4a5cf44";
  static vapi_message_desc_t __vapi_metadata_ip_neighbor_config = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_neighbor_config, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_neighbor_config_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_config_hton,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_config_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_neighbor_config = vapi_register_msg(&__vapi_metadata_ip_neighbor_config);
  VAPI_DBG("Assigned msg id %d to ip_neighbor_config", vapi_msg_id_ip_neighbor_config);
}
#endif

#ifndef defined_vapi_msg_ip_neighbor_config_get_reply
#define defined_vapi_msg_ip_neighbor_config_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_enum_address_family af;
  u32 max_number;
  u32 max_age;
  bool recycle; 
} vapi_payload_ip_neighbor_config_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_neighbor_config_get_reply payload;
} vapi_msg_ip_neighbor_config_get_reply;

static inline void vapi_msg_ip_neighbor_config_get_reply_payload_hton(vapi_payload_ip_neighbor_config_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->max_number = htobe32(payload->max_number);
  payload->max_age = htobe32(payload->max_age);
}

static inline void vapi_msg_ip_neighbor_config_get_reply_payload_ntoh(vapi_payload_ip_neighbor_config_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->max_number = be32toh(payload->max_number);
  payload->max_age = be32toh(payload->max_age);
}

static inline void vapi_msg_ip_neighbor_config_get_reply_hton(vapi_msg_ip_neighbor_config_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_config_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_neighbor_config_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_neighbor_config_get_reply_ntoh(vapi_msg_ip_neighbor_config_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_config_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_neighbor_config_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_neighbor_config_get_reply_msg_size(vapi_msg_ip_neighbor_config_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_neighbor_config_get_reply_msg_size(vapi_msg_ip_neighbor_config_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_neighbor_config_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_config_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_neighbor_config_get_reply));
      return -1;
    }
  if (vapi_calc_ip_neighbor_config_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_config_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_neighbor_config_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_neighbor_config_get_reply()
{
  static const char name[] = "ip_neighbor_config_get_reply";
  static const char name_with_crc[] = "ip_neighbor_config_get_reply_798e6fdd";
  static vapi_message_desc_t __vapi_metadata_ip_neighbor_config_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_neighbor_config_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_neighbor_config_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_config_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_config_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_neighbor_config_get_reply = vapi_register_msg(&__vapi_metadata_ip_neighbor_config_get_reply);
  VAPI_DBG("Assigned msg id %d to ip_neighbor_config_get_reply", vapi_msg_id_ip_neighbor_config_get_reply);
}

static inline void vapi_set_vapi_msg_ip_neighbor_config_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_neighbor_config_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_neighbor_config_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_neighbor_config_get
#define defined_vapi_msg_ip_neighbor_config_get
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_address_family af; 
} vapi_payload_ip_neighbor_config_get;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_neighbor_config_get payload;
} vapi_msg_ip_neighbor_config_get;

static inline void vapi_msg_ip_neighbor_config_get_payload_hton(vapi_payload_ip_neighbor_config_get *payload)
{

}

static inline void vapi_msg_ip_neighbor_config_get_payload_ntoh(vapi_payload_ip_neighbor_config_get *payload)
{

}

static inline void vapi_msg_ip_neighbor_config_get_hton(vapi_msg_ip_neighbor_config_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_config_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_neighbor_config_get_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_neighbor_config_get_ntoh(vapi_msg_ip_neighbor_config_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_config_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_neighbor_config_get_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_neighbor_config_get_msg_size(vapi_msg_ip_neighbor_config_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_neighbor_config_get_msg_size(vapi_msg_ip_neighbor_config_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_neighbor_config_get) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_config_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_neighbor_config_get));
      return -1;
    }
  if (vapi_calc_ip_neighbor_config_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_config_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_neighbor_config_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_neighbor_config_get* vapi_alloc_ip_neighbor_config_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_neighbor_config_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_neighbor_config_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_neighbor_config_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_neighbor_config_get);

  return msg;
}

static inline vapi_error_e vapi_ip_neighbor_config_get(struct vapi_ctx_s *ctx,
  vapi_msg_ip_neighbor_config_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_neighbor_config_get_reply *reply),
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
  vapi_msg_ip_neighbor_config_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_neighbor_config_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ip_neighbor_config_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_neighbor_config_get()
{
  static const char name[] = "ip_neighbor_config_get";
  static const char name_with_crc[] = "ip_neighbor_config_get_a5db7bf7";
  static vapi_message_desc_t __vapi_metadata_ip_neighbor_config_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_neighbor_config_get, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_neighbor_config_get_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_config_get_hton,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_config_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_neighbor_config_get = vapi_register_msg(&__vapi_metadata_ip_neighbor_config_get);
  VAPI_DBG("Assigned msg id %d to ip_neighbor_config_get", vapi_msg_id_ip_neighbor_config_get);
}
#endif

#ifndef defined_vapi_msg_ip_neighbor_replace_begin_reply
#define defined_vapi_msg_ip_neighbor_replace_begin_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip_neighbor_replace_begin_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_neighbor_replace_begin_reply payload;
} vapi_msg_ip_neighbor_replace_begin_reply;

static inline void vapi_msg_ip_neighbor_replace_begin_reply_payload_hton(vapi_payload_ip_neighbor_replace_begin_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_neighbor_replace_begin_reply_payload_ntoh(vapi_payload_ip_neighbor_replace_begin_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_neighbor_replace_begin_reply_hton(vapi_msg_ip_neighbor_replace_begin_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_replace_begin_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_neighbor_replace_begin_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_neighbor_replace_begin_reply_ntoh(vapi_msg_ip_neighbor_replace_begin_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_replace_begin_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_neighbor_replace_begin_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_neighbor_replace_begin_reply_msg_size(vapi_msg_ip_neighbor_replace_begin_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_neighbor_replace_begin_reply_msg_size(vapi_msg_ip_neighbor_replace_begin_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_neighbor_replace_begin_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_replace_begin_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_neighbor_replace_begin_reply));
      return -1;
    }
  if (vapi_calc_ip_neighbor_replace_begin_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_replace_begin_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_neighbor_replace_begin_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_neighbor_replace_begin_reply()
{
  static const char name[] = "ip_neighbor_replace_begin_reply";
  static const char name_with_crc[] = "ip_neighbor_replace_begin_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip_neighbor_replace_begin_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_neighbor_replace_begin_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_neighbor_replace_begin_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_replace_begin_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_replace_begin_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_neighbor_replace_begin_reply = vapi_register_msg(&__vapi_metadata_ip_neighbor_replace_begin_reply);
  VAPI_DBG("Assigned msg id %d to ip_neighbor_replace_begin_reply", vapi_msg_id_ip_neighbor_replace_begin_reply);
}

static inline void vapi_set_vapi_msg_ip_neighbor_replace_begin_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_neighbor_replace_begin_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_neighbor_replace_begin_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_neighbor_replace_begin
#define defined_vapi_msg_ip_neighbor_replace_begin
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ip_neighbor_replace_begin;

static inline void vapi_msg_ip_neighbor_replace_begin_hton(vapi_msg_ip_neighbor_replace_begin *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_replace_begin'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ip_neighbor_replace_begin_ntoh(vapi_msg_ip_neighbor_replace_begin *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_replace_begin'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ip_neighbor_replace_begin_msg_size(vapi_msg_ip_neighbor_replace_begin *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_neighbor_replace_begin_msg_size(vapi_msg_ip_neighbor_replace_begin *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_neighbor_replace_begin) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_replace_begin' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_neighbor_replace_begin));
      return -1;
    }
  if (vapi_calc_ip_neighbor_replace_begin_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_replace_begin' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_neighbor_replace_begin_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_neighbor_replace_begin* vapi_alloc_ip_neighbor_replace_begin(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_neighbor_replace_begin *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_neighbor_replace_begin);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_neighbor_replace_begin*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_neighbor_replace_begin);

  return msg;
}

static inline vapi_error_e vapi_ip_neighbor_replace_begin(struct vapi_ctx_s *ctx,
  vapi_msg_ip_neighbor_replace_begin *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_neighbor_replace_begin_reply *reply),
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
  vapi_msg_ip_neighbor_replace_begin_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_neighbor_replace_begin_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ip_neighbor_replace_begin_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_neighbor_replace_begin()
{
  static const char name[] = "ip_neighbor_replace_begin";
  static const char name_with_crc[] = "ip_neighbor_replace_begin_51077d14";
  static vapi_message_desc_t __vapi_metadata_ip_neighbor_replace_begin = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ip_neighbor_replace_begin_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_replace_begin_hton,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_replace_begin_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_neighbor_replace_begin = vapi_register_msg(&__vapi_metadata_ip_neighbor_replace_begin);
  VAPI_DBG("Assigned msg id %d to ip_neighbor_replace_begin", vapi_msg_id_ip_neighbor_replace_begin);
}
#endif

#ifndef defined_vapi_msg_ip_neighbor_replace_end_reply
#define defined_vapi_msg_ip_neighbor_replace_end_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip_neighbor_replace_end_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_neighbor_replace_end_reply payload;
} vapi_msg_ip_neighbor_replace_end_reply;

static inline void vapi_msg_ip_neighbor_replace_end_reply_payload_hton(vapi_payload_ip_neighbor_replace_end_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_neighbor_replace_end_reply_payload_ntoh(vapi_payload_ip_neighbor_replace_end_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_neighbor_replace_end_reply_hton(vapi_msg_ip_neighbor_replace_end_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_replace_end_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_neighbor_replace_end_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_neighbor_replace_end_reply_ntoh(vapi_msg_ip_neighbor_replace_end_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_replace_end_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_neighbor_replace_end_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_neighbor_replace_end_reply_msg_size(vapi_msg_ip_neighbor_replace_end_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_neighbor_replace_end_reply_msg_size(vapi_msg_ip_neighbor_replace_end_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_neighbor_replace_end_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_replace_end_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_neighbor_replace_end_reply));
      return -1;
    }
  if (vapi_calc_ip_neighbor_replace_end_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_replace_end_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_neighbor_replace_end_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_neighbor_replace_end_reply()
{
  static const char name[] = "ip_neighbor_replace_end_reply";
  static const char name_with_crc[] = "ip_neighbor_replace_end_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip_neighbor_replace_end_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_neighbor_replace_end_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_neighbor_replace_end_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_replace_end_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_replace_end_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_neighbor_replace_end_reply = vapi_register_msg(&__vapi_metadata_ip_neighbor_replace_end_reply);
  VAPI_DBG("Assigned msg id %d to ip_neighbor_replace_end_reply", vapi_msg_id_ip_neighbor_replace_end_reply);
}

static inline void vapi_set_vapi_msg_ip_neighbor_replace_end_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_neighbor_replace_end_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_neighbor_replace_end_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_neighbor_replace_end
#define defined_vapi_msg_ip_neighbor_replace_end
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ip_neighbor_replace_end;

static inline void vapi_msg_ip_neighbor_replace_end_hton(vapi_msg_ip_neighbor_replace_end *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_replace_end'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ip_neighbor_replace_end_ntoh(vapi_msg_ip_neighbor_replace_end *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_replace_end'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ip_neighbor_replace_end_msg_size(vapi_msg_ip_neighbor_replace_end *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_neighbor_replace_end_msg_size(vapi_msg_ip_neighbor_replace_end *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_neighbor_replace_end) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_replace_end' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_neighbor_replace_end));
      return -1;
    }
  if (vapi_calc_ip_neighbor_replace_end_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_replace_end' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_neighbor_replace_end_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_neighbor_replace_end* vapi_alloc_ip_neighbor_replace_end(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_neighbor_replace_end *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_neighbor_replace_end);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_neighbor_replace_end*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_neighbor_replace_end);

  return msg;
}

static inline vapi_error_e vapi_ip_neighbor_replace_end(struct vapi_ctx_s *ctx,
  vapi_msg_ip_neighbor_replace_end *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_neighbor_replace_end_reply *reply),
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
  vapi_msg_ip_neighbor_replace_end_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_neighbor_replace_end_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ip_neighbor_replace_end_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_neighbor_replace_end()
{
  static const char name[] = "ip_neighbor_replace_end";
  static const char name_with_crc[] = "ip_neighbor_replace_end_51077d14";
  static vapi_message_desc_t __vapi_metadata_ip_neighbor_replace_end = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ip_neighbor_replace_end_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_replace_end_hton,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_replace_end_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_neighbor_replace_end = vapi_register_msg(&__vapi_metadata_ip_neighbor_replace_end);
  VAPI_DBG("Assigned msg id %d to ip_neighbor_replace_end", vapi_msg_id_ip_neighbor_replace_end);
}
#endif

#ifndef defined_vapi_msg_ip_neighbor_flush_reply
#define defined_vapi_msg_ip_neighbor_flush_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ip_neighbor_flush_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ip_neighbor_flush_reply payload;
} vapi_msg_ip_neighbor_flush_reply;

static inline void vapi_msg_ip_neighbor_flush_reply_payload_hton(vapi_payload_ip_neighbor_flush_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ip_neighbor_flush_reply_payload_ntoh(vapi_payload_ip_neighbor_flush_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ip_neighbor_flush_reply_hton(vapi_msg_ip_neighbor_flush_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_flush_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ip_neighbor_flush_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_neighbor_flush_reply_ntoh(vapi_msg_ip_neighbor_flush_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_flush_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ip_neighbor_flush_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_neighbor_flush_reply_msg_size(vapi_msg_ip_neighbor_flush_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_neighbor_flush_reply_msg_size(vapi_msg_ip_neighbor_flush_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_neighbor_flush_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_flush_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_neighbor_flush_reply));
      return -1;
    }
  if (vapi_calc_ip_neighbor_flush_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_flush_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_neighbor_flush_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_neighbor_flush_reply()
{
  static const char name[] = "ip_neighbor_flush_reply";
  static const char name_with_crc[] = "ip_neighbor_flush_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ip_neighbor_flush_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ip_neighbor_flush_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_neighbor_flush_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_flush_reply_hton,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_flush_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_neighbor_flush_reply = vapi_register_msg(&__vapi_metadata_ip_neighbor_flush_reply);
  VAPI_DBG("Assigned msg id %d to ip_neighbor_flush_reply", vapi_msg_id_ip_neighbor_flush_reply);
}

static inline void vapi_set_vapi_msg_ip_neighbor_flush_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_neighbor_flush_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_neighbor_flush_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ip_neighbor_flush
#define defined_vapi_msg_ip_neighbor_flush
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_address_family af;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_ip_neighbor_flush;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ip_neighbor_flush payload;
} vapi_msg_ip_neighbor_flush;

static inline void vapi_msg_ip_neighbor_flush_payload_hton(vapi_payload_ip_neighbor_flush *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ip_neighbor_flush_payload_ntoh(vapi_payload_ip_neighbor_flush *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ip_neighbor_flush_hton(vapi_msg_ip_neighbor_flush *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_flush'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ip_neighbor_flush_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_neighbor_flush_ntoh(vapi_msg_ip_neighbor_flush *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_flush'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ip_neighbor_flush_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_neighbor_flush_msg_size(vapi_msg_ip_neighbor_flush *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_neighbor_flush_msg_size(vapi_msg_ip_neighbor_flush *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_neighbor_flush) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_flush' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_neighbor_flush));
      return -1;
    }
  if (vapi_calc_ip_neighbor_flush_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_flush' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_neighbor_flush_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ip_neighbor_flush* vapi_alloc_ip_neighbor_flush(struct vapi_ctx_s *ctx)
{
  vapi_msg_ip_neighbor_flush *msg = NULL;
  const size_t size = sizeof(vapi_msg_ip_neighbor_flush);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ip_neighbor_flush*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ip_neighbor_flush);

  return msg;
}

static inline vapi_error_e vapi_ip_neighbor_flush(struct vapi_ctx_s *ctx,
  vapi_msg_ip_neighbor_flush *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ip_neighbor_flush_reply *reply),
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
  vapi_msg_ip_neighbor_flush_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ip_neighbor_flush_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ip_neighbor_flush_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ip_neighbor_flush()
{
  static const char name[] = "ip_neighbor_flush";
  static const char name_with_crc[] = "ip_neighbor_flush_16aa35d2";
  static vapi_message_desc_t __vapi_metadata_ip_neighbor_flush = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ip_neighbor_flush, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_neighbor_flush_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_flush_hton,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_flush_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_neighbor_flush = vapi_register_msg(&__vapi_metadata_ip_neighbor_flush);
  VAPI_DBG("Assigned msg id %d to ip_neighbor_flush", vapi_msg_id_ip_neighbor_flush);
}
#endif

#ifndef defined_vapi_msg_want_ip_neighbor_events_reply
#define defined_vapi_msg_want_ip_neighbor_events_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_want_ip_neighbor_events_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_want_ip_neighbor_events_reply payload;
} vapi_msg_want_ip_neighbor_events_reply;

static inline void vapi_msg_want_ip_neighbor_events_reply_payload_hton(vapi_payload_want_ip_neighbor_events_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_want_ip_neighbor_events_reply_payload_ntoh(vapi_payload_want_ip_neighbor_events_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_want_ip_neighbor_events_reply_hton(vapi_msg_want_ip_neighbor_events_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_ip_neighbor_events_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_want_ip_neighbor_events_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_want_ip_neighbor_events_reply_ntoh(vapi_msg_want_ip_neighbor_events_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_ip_neighbor_events_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_want_ip_neighbor_events_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_want_ip_neighbor_events_reply_msg_size(vapi_msg_want_ip_neighbor_events_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_want_ip_neighbor_events_reply_msg_size(vapi_msg_want_ip_neighbor_events_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_want_ip_neighbor_events_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'want_ip_neighbor_events_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_want_ip_neighbor_events_reply));
      return -1;
    }
  if (vapi_calc_want_ip_neighbor_events_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'want_ip_neighbor_events_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_want_ip_neighbor_events_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_want_ip_neighbor_events_reply()
{
  static const char name[] = "want_ip_neighbor_events_reply";
  static const char name_with_crc[] = "want_ip_neighbor_events_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_want_ip_neighbor_events_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_want_ip_neighbor_events_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_want_ip_neighbor_events_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_want_ip_neighbor_events_reply_hton,
    (generic_swap_fn_t)vapi_msg_want_ip_neighbor_events_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_want_ip_neighbor_events_reply = vapi_register_msg(&__vapi_metadata_want_ip_neighbor_events_reply);
  VAPI_DBG("Assigned msg id %d to want_ip_neighbor_events_reply", vapi_msg_id_want_ip_neighbor_events_reply);
}

static inline void vapi_set_vapi_msg_want_ip_neighbor_events_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_want_ip_neighbor_events_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_want_ip_neighbor_events_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_want_ip_neighbor_events
#define defined_vapi_msg_want_ip_neighbor_events
typedef struct __attribute__ ((__packed__)) {
  bool enable;
  u32 pid;
  vapi_type_address ip;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_want_ip_neighbor_events;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_want_ip_neighbor_events payload;
} vapi_msg_want_ip_neighbor_events;

static inline void vapi_msg_want_ip_neighbor_events_payload_hton(vapi_payload_want_ip_neighbor_events *payload)
{
  payload->pid = htobe32(payload->pid);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_want_ip_neighbor_events_payload_ntoh(vapi_payload_want_ip_neighbor_events *payload)
{
  payload->pid = be32toh(payload->pid);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_want_ip_neighbor_events_hton(vapi_msg_want_ip_neighbor_events *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_ip_neighbor_events'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_want_ip_neighbor_events_payload_hton(&msg->payload);
}

static inline void vapi_msg_want_ip_neighbor_events_ntoh(vapi_msg_want_ip_neighbor_events *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_ip_neighbor_events'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_want_ip_neighbor_events_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_want_ip_neighbor_events_msg_size(vapi_msg_want_ip_neighbor_events *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_want_ip_neighbor_events_msg_size(vapi_msg_want_ip_neighbor_events *msg, uword buf_size)
{
  if (sizeof(vapi_msg_want_ip_neighbor_events) > buf_size)
    {
      VAPI_ERR("Truncated 'want_ip_neighbor_events' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_want_ip_neighbor_events));
      return -1;
    }
  if (vapi_calc_want_ip_neighbor_events_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'want_ip_neighbor_events' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_want_ip_neighbor_events_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_want_ip_neighbor_events* vapi_alloc_want_ip_neighbor_events(struct vapi_ctx_s *ctx)
{
  vapi_msg_want_ip_neighbor_events *msg = NULL;
  const size_t size = sizeof(vapi_msg_want_ip_neighbor_events);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_want_ip_neighbor_events*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_want_ip_neighbor_events);

  return msg;
}

static inline vapi_error_e vapi_want_ip_neighbor_events(struct vapi_ctx_s *ctx,
  vapi_msg_want_ip_neighbor_events *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_want_ip_neighbor_events_reply *reply),
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
  vapi_msg_want_ip_neighbor_events_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_want_ip_neighbor_events_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_want_ip_neighbor_events_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_want_ip_neighbor_events()
{
  static const char name[] = "want_ip_neighbor_events";
  static const char name_with_crc[] = "want_ip_neighbor_events_73e70a86";
  static vapi_message_desc_t __vapi_metadata_want_ip_neighbor_events = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_want_ip_neighbor_events, payload),
    (verify_msg_size_fn_t)vapi_verify_want_ip_neighbor_events_msg_size,
    (generic_swap_fn_t)vapi_msg_want_ip_neighbor_events_hton,
    (generic_swap_fn_t)vapi_msg_want_ip_neighbor_events_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_want_ip_neighbor_events = vapi_register_msg(&__vapi_metadata_want_ip_neighbor_events);
  VAPI_DBG("Assigned msg id %d to want_ip_neighbor_events", vapi_msg_id_want_ip_neighbor_events);
}
#endif

#ifndef defined_vapi_msg_ip_neighbor_event
#define defined_vapi_msg_ip_neighbor_event
typedef struct __attribute__ ((__packed__)) {
  u16 _vl_msg_id;
  u32 client_index;
  u32 pid;
  vapi_type_ip_neighbor neighbor; 
} vapi_payload_ip_neighbor_event;

typedef struct __attribute__ ((__packed__)) {

  vapi_payload_ip_neighbor_event payload;
} vapi_msg_ip_neighbor_event;

static inline void vapi_msg_ip_neighbor_event_payload_hton(vapi_payload_ip_neighbor_event *payload)
{
  payload->_vl_msg_id = htobe16(payload->_vl_msg_id);
  payload->client_index = htobe32(payload->client_index);
  payload->pid = htobe32(payload->pid);
  vapi_type_ip_neighbor_hton(&payload->neighbor);
}

static inline void vapi_msg_ip_neighbor_event_payload_ntoh(vapi_payload_ip_neighbor_event *payload)
{
  payload->_vl_msg_id = be16toh(payload->_vl_msg_id);
  payload->client_index = be32toh(payload->client_index);
  payload->pid = be32toh(payload->pid);
  vapi_type_ip_neighbor_ntoh(&payload->neighbor);
}

static inline void vapi_msg_ip_neighbor_event_hton(vapi_msg_ip_neighbor_event *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_event'@%p to big endian", msg);

  vapi_msg_ip_neighbor_event_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_neighbor_event_ntoh(vapi_msg_ip_neighbor_event *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_event'@%p to host byte order", msg);

  vapi_msg_ip_neighbor_event_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_neighbor_event_msg_size(vapi_msg_ip_neighbor_event *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_neighbor_event_msg_size(vapi_msg_ip_neighbor_event *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_neighbor_event) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_event' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_neighbor_event));
      return -1;
    }
  if (vapi_calc_ip_neighbor_event_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_event' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_neighbor_event_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_neighbor_event()
{
  static const char name[] = "ip_neighbor_event";
  static const char name_with_crc[] = "ip_neighbor_event_bdb092b2";
  static vapi_message_desc_t __vapi_metadata_ip_neighbor_event = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    false,
    0,
    offsetof(vapi_msg_ip_neighbor_event, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_neighbor_event_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_event_hton,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_event_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_neighbor_event = vapi_register_msg(&__vapi_metadata_ip_neighbor_event);
  VAPI_DBG("Assigned msg id %d to ip_neighbor_event", vapi_msg_id_ip_neighbor_event);
}

static inline void vapi_set_vapi_msg_ip_neighbor_event_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_neighbor_event *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_neighbor_event, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_want_ip_neighbor_events_v2_reply
#define defined_vapi_msg_want_ip_neighbor_events_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_want_ip_neighbor_events_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_want_ip_neighbor_events_v2_reply payload;
} vapi_msg_want_ip_neighbor_events_v2_reply;

static inline void vapi_msg_want_ip_neighbor_events_v2_reply_payload_hton(vapi_payload_want_ip_neighbor_events_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_want_ip_neighbor_events_v2_reply_payload_ntoh(vapi_payload_want_ip_neighbor_events_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_want_ip_neighbor_events_v2_reply_hton(vapi_msg_want_ip_neighbor_events_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_ip_neighbor_events_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_want_ip_neighbor_events_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_want_ip_neighbor_events_v2_reply_ntoh(vapi_msg_want_ip_neighbor_events_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_ip_neighbor_events_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_want_ip_neighbor_events_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_want_ip_neighbor_events_v2_reply_msg_size(vapi_msg_want_ip_neighbor_events_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_want_ip_neighbor_events_v2_reply_msg_size(vapi_msg_want_ip_neighbor_events_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_want_ip_neighbor_events_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'want_ip_neighbor_events_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_want_ip_neighbor_events_v2_reply));
      return -1;
    }
  if (vapi_calc_want_ip_neighbor_events_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'want_ip_neighbor_events_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_want_ip_neighbor_events_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_want_ip_neighbor_events_v2_reply()
{
  static const char name[] = "want_ip_neighbor_events_v2_reply";
  static const char name_with_crc[] = "want_ip_neighbor_events_v2_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_want_ip_neighbor_events_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_want_ip_neighbor_events_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_want_ip_neighbor_events_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_want_ip_neighbor_events_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_want_ip_neighbor_events_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_want_ip_neighbor_events_v2_reply = vapi_register_msg(&__vapi_metadata_want_ip_neighbor_events_v2_reply);
  VAPI_DBG("Assigned msg id %d to want_ip_neighbor_events_v2_reply", vapi_msg_id_want_ip_neighbor_events_v2_reply);
}

static inline void vapi_set_vapi_msg_want_ip_neighbor_events_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_want_ip_neighbor_events_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_want_ip_neighbor_events_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_want_ip_neighbor_events_v2
#define defined_vapi_msg_want_ip_neighbor_events_v2
typedef struct __attribute__ ((__packed__)) {
  bool enable;
  u32 pid;
  vapi_type_address ip;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_want_ip_neighbor_events_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_want_ip_neighbor_events_v2 payload;
} vapi_msg_want_ip_neighbor_events_v2;

static inline void vapi_msg_want_ip_neighbor_events_v2_payload_hton(vapi_payload_want_ip_neighbor_events_v2 *payload)
{
  payload->pid = htobe32(payload->pid);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_want_ip_neighbor_events_v2_payload_ntoh(vapi_payload_want_ip_neighbor_events_v2 *payload)
{
  payload->pid = be32toh(payload->pid);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_want_ip_neighbor_events_v2_hton(vapi_msg_want_ip_neighbor_events_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_ip_neighbor_events_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_want_ip_neighbor_events_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_want_ip_neighbor_events_v2_ntoh(vapi_msg_want_ip_neighbor_events_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_ip_neighbor_events_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_want_ip_neighbor_events_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_want_ip_neighbor_events_v2_msg_size(vapi_msg_want_ip_neighbor_events_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_want_ip_neighbor_events_v2_msg_size(vapi_msg_want_ip_neighbor_events_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_want_ip_neighbor_events_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'want_ip_neighbor_events_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_want_ip_neighbor_events_v2));
      return -1;
    }
  if (vapi_calc_want_ip_neighbor_events_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'want_ip_neighbor_events_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_want_ip_neighbor_events_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_want_ip_neighbor_events_v2* vapi_alloc_want_ip_neighbor_events_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_want_ip_neighbor_events_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_want_ip_neighbor_events_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_want_ip_neighbor_events_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_want_ip_neighbor_events_v2);

  return msg;
}

static inline vapi_error_e vapi_want_ip_neighbor_events_v2(struct vapi_ctx_s *ctx,
  vapi_msg_want_ip_neighbor_events_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_want_ip_neighbor_events_v2_reply *reply),
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
  vapi_msg_want_ip_neighbor_events_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_want_ip_neighbor_events_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_want_ip_neighbor_events_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_want_ip_neighbor_events_v2()
{
  static const char name[] = "want_ip_neighbor_events_v2";
  static const char name_with_crc[] = "want_ip_neighbor_events_v2_73e70a86";
  static vapi_message_desc_t __vapi_metadata_want_ip_neighbor_events_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_want_ip_neighbor_events_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_want_ip_neighbor_events_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_want_ip_neighbor_events_v2_hton,
    (generic_swap_fn_t)vapi_msg_want_ip_neighbor_events_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_want_ip_neighbor_events_v2 = vapi_register_msg(&__vapi_metadata_want_ip_neighbor_events_v2);
  VAPI_DBG("Assigned msg id %d to want_ip_neighbor_events_v2", vapi_msg_id_want_ip_neighbor_events_v2);
}
#endif

#ifndef defined_vapi_msg_ip_neighbor_event_v2
#define defined_vapi_msg_ip_neighbor_event_v2
typedef struct __attribute__ ((__packed__)) {
  u16 _vl_msg_id;
  u32 client_index;
  u32 pid;
  vapi_enum_ip_neighbor_event_flags flags;
  vapi_type_ip_neighbor neighbor; 
} vapi_payload_ip_neighbor_event_v2;

typedef struct __attribute__ ((__packed__)) {

  vapi_payload_ip_neighbor_event_v2 payload;
} vapi_msg_ip_neighbor_event_v2;

static inline void vapi_msg_ip_neighbor_event_v2_payload_hton(vapi_payload_ip_neighbor_event_v2 *payload)
{
  payload->_vl_msg_id = htobe16(payload->_vl_msg_id);
  payload->client_index = htobe32(payload->client_index);
  payload->pid = htobe32(payload->pid);
  payload->flags = (vapi_enum_ip_neighbor_event_flags)htobe32(payload->flags);
  vapi_type_ip_neighbor_hton(&payload->neighbor);
}

static inline void vapi_msg_ip_neighbor_event_v2_payload_ntoh(vapi_payload_ip_neighbor_event_v2 *payload)
{
  payload->_vl_msg_id = be16toh(payload->_vl_msg_id);
  payload->client_index = be32toh(payload->client_index);
  payload->pid = be32toh(payload->pid);
  payload->flags = (vapi_enum_ip_neighbor_event_flags)be32toh(payload->flags);
  vapi_type_ip_neighbor_ntoh(&payload->neighbor);
}

static inline void vapi_msg_ip_neighbor_event_v2_hton(vapi_msg_ip_neighbor_event_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_event_v2'@%p to big endian", msg);

  vapi_msg_ip_neighbor_event_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_ip_neighbor_event_v2_ntoh(vapi_msg_ip_neighbor_event_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ip_neighbor_event_v2'@%p to host byte order", msg);

  vapi_msg_ip_neighbor_event_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ip_neighbor_event_v2_msg_size(vapi_msg_ip_neighbor_event_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ip_neighbor_event_v2_msg_size(vapi_msg_ip_neighbor_event_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ip_neighbor_event_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_event_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ip_neighbor_event_v2));
      return -1;
    }
  if (vapi_calc_ip_neighbor_event_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ip_neighbor_event_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ip_neighbor_event_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ip_neighbor_event_v2()
{
  static const char name[] = "ip_neighbor_event_v2";
  static const char name_with_crc[] = "ip_neighbor_event_v2_c1d53dc0";
  static vapi_message_desc_t __vapi_metadata_ip_neighbor_event_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    false,
    0,
    offsetof(vapi_msg_ip_neighbor_event_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_ip_neighbor_event_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_event_v2_hton,
    (generic_swap_fn_t)vapi_msg_ip_neighbor_event_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ip_neighbor_event_v2 = vapi_register_msg(&__vapi_metadata_ip_neighbor_event_v2);
  VAPI_DBG("Assigned msg id %d to ip_neighbor_event_v2", vapi_msg_id_ip_neighbor_event_v2);
}

static inline void vapi_set_vapi_msg_ip_neighbor_event_v2_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ip_neighbor_event_v2 *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ip_neighbor_event_v2, (vapi_event_cb)callback, callback_ctx);
};
#endif


#ifdef __cplusplus
}
#endif

#endif
