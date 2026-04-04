#ifndef __included_snort_api_json
#define __included_snort_api_json

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

extern vapi_msg_id_t vapi_msg_id_snort_instance_create;
extern vapi_msg_id_t vapi_msg_id_snort_instance_create_reply;
extern vapi_msg_id_t vapi_msg_id_snort_instance_delete;
extern vapi_msg_id_t vapi_msg_id_snort_instance_delete_reply;
extern vapi_msg_id_t vapi_msg_id_snort_client_disconnect;
extern vapi_msg_id_t vapi_msg_id_snort_client_disconnect_reply;
extern vapi_msg_id_t vapi_msg_id_snort_instance_disconnect;
extern vapi_msg_id_t vapi_msg_id_snort_instance_disconnect_reply;
extern vapi_msg_id_t vapi_msg_id_snort_interface_attach;
extern vapi_msg_id_t vapi_msg_id_snort_interface_attach_reply;
extern vapi_msg_id_t vapi_msg_id_snort_interface_detach;
extern vapi_msg_id_t vapi_msg_id_snort_interface_detach_reply;
extern vapi_msg_id_t vapi_msg_id_snort_input_mode_get;
extern vapi_msg_id_t vapi_msg_id_snort_input_mode_get_reply;
extern vapi_msg_id_t vapi_msg_id_snort_input_mode_set;
extern vapi_msg_id_t vapi_msg_id_snort_input_mode_set_reply;
extern vapi_msg_id_t vapi_msg_id_snort_instance_get;
extern vapi_msg_id_t vapi_msg_id_snort_instance_get_reply;
extern vapi_msg_id_t vapi_msg_id_snort_instance_details;
extern vapi_msg_id_t vapi_msg_id_snort_interface_get;
extern vapi_msg_id_t vapi_msg_id_snort_interface_get_reply;
extern vapi_msg_id_t vapi_msg_id_snort_interface_details;
extern vapi_msg_id_t vapi_msg_id_snort_client_get;
extern vapi_msg_id_t vapi_msg_id_snort_client_get_reply;
extern vapi_msg_id_t vapi_msg_id_snort_client_details;

#define DEFINE_VAPI_MSG_IDS_SNORT_API_JSON\
  vapi_msg_id_t vapi_msg_id_snort_instance_create;\
  vapi_msg_id_t vapi_msg_id_snort_instance_create_reply;\
  vapi_msg_id_t vapi_msg_id_snort_instance_delete;\
  vapi_msg_id_t vapi_msg_id_snort_instance_delete_reply;\
  vapi_msg_id_t vapi_msg_id_snort_client_disconnect;\
  vapi_msg_id_t vapi_msg_id_snort_client_disconnect_reply;\
  vapi_msg_id_t vapi_msg_id_snort_instance_disconnect;\
  vapi_msg_id_t vapi_msg_id_snort_instance_disconnect_reply;\
  vapi_msg_id_t vapi_msg_id_snort_interface_attach;\
  vapi_msg_id_t vapi_msg_id_snort_interface_attach_reply;\
  vapi_msg_id_t vapi_msg_id_snort_interface_detach;\
  vapi_msg_id_t vapi_msg_id_snort_interface_detach_reply;\
  vapi_msg_id_t vapi_msg_id_snort_input_mode_get;\
  vapi_msg_id_t vapi_msg_id_snort_input_mode_get_reply;\
  vapi_msg_id_t vapi_msg_id_snort_input_mode_set;\
  vapi_msg_id_t vapi_msg_id_snort_input_mode_set_reply;\
  vapi_msg_id_t vapi_msg_id_snort_instance_get;\
  vapi_msg_id_t vapi_msg_id_snort_instance_get_reply;\
  vapi_msg_id_t vapi_msg_id_snort_instance_details;\
  vapi_msg_id_t vapi_msg_id_snort_interface_get;\
  vapi_msg_id_t vapi_msg_id_snort_interface_get_reply;\
  vapi_msg_id_t vapi_msg_id_snort_interface_details;\
  vapi_msg_id_t vapi_msg_id_snort_client_get;\
  vapi_msg_id_t vapi_msg_id_snort_client_get_reply;\
  vapi_msg_id_t vapi_msg_id_snort_client_details;


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

#ifndef defined_vapi_msg_snort_instance_create_reply
#define defined_vapi_msg_snort_instance_create_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 instance_index; 
} vapi_payload_snort_instance_create_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_snort_instance_create_reply payload;
} vapi_msg_snort_instance_create_reply;

static inline void vapi_msg_snort_instance_create_reply_payload_hton(vapi_payload_snort_instance_create_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->instance_index = htobe32(payload->instance_index);
}

static inline void vapi_msg_snort_instance_create_reply_payload_ntoh(vapi_payload_snort_instance_create_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->instance_index = be32toh(payload->instance_index);
}

static inline void vapi_msg_snort_instance_create_reply_hton(vapi_msg_snort_instance_create_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_instance_create_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_snort_instance_create_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_instance_create_reply_ntoh(vapi_msg_snort_instance_create_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_instance_create_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_snort_instance_create_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_instance_create_reply_msg_size(vapi_msg_snort_instance_create_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_instance_create_reply_msg_size(vapi_msg_snort_instance_create_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_instance_create_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_instance_create_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_instance_create_reply));
      return -1;
    }
  if (vapi_calc_snort_instance_create_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_instance_create_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_instance_create_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_snort_instance_create_reply()
{
  static const char name[] = "snort_instance_create_reply";
  static const char name_with_crc[] = "snort_instance_create_reply_e63a3fba";
  static vapi_message_desc_t __vapi_metadata_snort_instance_create_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_snort_instance_create_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_instance_create_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_instance_create_reply_hton,
    (generic_swap_fn_t)vapi_msg_snort_instance_create_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_instance_create_reply = vapi_register_msg(&__vapi_metadata_snort_instance_create_reply);
  VAPI_DBG("Assigned msg id %d to snort_instance_create_reply", vapi_msg_id_snort_instance_create_reply);
}

static inline void vapi_set_vapi_msg_snort_instance_create_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_snort_instance_create_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_snort_instance_create_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_snort_instance_create
#define defined_vapi_msg_snort_instance_create
typedef struct __attribute__ ((__packed__)) {
  u32 queue_size;
  u8 drop_on_disconnect;
  vl_api_string_t name; 
} vapi_payload_snort_instance_create;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_snort_instance_create payload;
} vapi_msg_snort_instance_create;

static inline void vapi_msg_snort_instance_create_payload_hton(vapi_payload_snort_instance_create *payload)
{
  payload->queue_size = htobe32(payload->queue_size);
  vl_api_string_t_hton(&payload->name);
}

static inline void vapi_msg_snort_instance_create_payload_ntoh(vapi_payload_snort_instance_create *payload)
{
  payload->queue_size = be32toh(payload->queue_size);
  vl_api_string_t_ntoh(&payload->name);
}

static inline void vapi_msg_snort_instance_create_hton(vapi_msg_snort_instance_create *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_instance_create'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_snort_instance_create_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_instance_create_ntoh(vapi_msg_snort_instance_create *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_instance_create'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_snort_instance_create_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_instance_create_msg_size(vapi_msg_snort_instance_create *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.name.buf[0]) * msg->payload.name.length;
}

static inline int vapi_verify_snort_instance_create_msg_size(vapi_msg_snort_instance_create *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_instance_create) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_instance_create' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_instance_create));
      return -1;
    }
  if (vapi_calc_snort_instance_create_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_instance_create' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_instance_create_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_snort_instance_create* vapi_alloc_snort_instance_create(struct vapi_ctx_s *ctx, size_t name_buf_array_size)
{
  vapi_msg_snort_instance_create *msg = NULL;
  const size_t size = sizeof(vapi_msg_snort_instance_create) + sizeof(msg->payload.name.buf[0]) * name_buf_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_snort_instance_create*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_snort_instance_create);
  msg->payload.name.length = name_buf_array_size;

  return msg;
}

static inline vapi_error_e vapi_snort_instance_create(struct vapi_ctx_s *ctx,
  vapi_msg_snort_instance_create *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_snort_instance_create_reply *reply),
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
  vapi_msg_snort_instance_create_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_snort_instance_create_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_snort_instance_create_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_snort_instance_create()
{
  static const char name[] = "snort_instance_create";
  static const char name_with_crc[] = "snort_instance_create_248cc390";
  static vapi_message_desc_t __vapi_metadata_snort_instance_create = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_snort_instance_create, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_instance_create_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_instance_create_hton,
    (generic_swap_fn_t)vapi_msg_snort_instance_create_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_instance_create = vapi_register_msg(&__vapi_metadata_snort_instance_create);
  VAPI_DBG("Assigned msg id %d to snort_instance_create", vapi_msg_id_snort_instance_create);
}
#endif

#ifndef defined_vapi_msg_snort_instance_delete_reply
#define defined_vapi_msg_snort_instance_delete_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_snort_instance_delete_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_snort_instance_delete_reply payload;
} vapi_msg_snort_instance_delete_reply;

static inline void vapi_msg_snort_instance_delete_reply_payload_hton(vapi_payload_snort_instance_delete_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_snort_instance_delete_reply_payload_ntoh(vapi_payload_snort_instance_delete_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_snort_instance_delete_reply_hton(vapi_msg_snort_instance_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_instance_delete_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_snort_instance_delete_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_instance_delete_reply_ntoh(vapi_msg_snort_instance_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_instance_delete_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_snort_instance_delete_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_instance_delete_reply_msg_size(vapi_msg_snort_instance_delete_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_instance_delete_reply_msg_size(vapi_msg_snort_instance_delete_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_instance_delete_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_instance_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_instance_delete_reply));
      return -1;
    }
  if (vapi_calc_snort_instance_delete_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_instance_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_instance_delete_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_snort_instance_delete_reply()
{
  static const char name[] = "snort_instance_delete_reply";
  static const char name_with_crc[] = "snort_instance_delete_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_snort_instance_delete_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_snort_instance_delete_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_instance_delete_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_instance_delete_reply_hton,
    (generic_swap_fn_t)vapi_msg_snort_instance_delete_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_instance_delete_reply = vapi_register_msg(&__vapi_metadata_snort_instance_delete_reply);
  VAPI_DBG("Assigned msg id %d to snort_instance_delete_reply", vapi_msg_id_snort_instance_delete_reply);
}

static inline void vapi_set_vapi_msg_snort_instance_delete_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_snort_instance_delete_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_snort_instance_delete_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_snort_instance_delete
#define defined_vapi_msg_snort_instance_delete
typedef struct __attribute__ ((__packed__)) {
  u32 instance_index; 
} vapi_payload_snort_instance_delete;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_snort_instance_delete payload;
} vapi_msg_snort_instance_delete;

static inline void vapi_msg_snort_instance_delete_payload_hton(vapi_payload_snort_instance_delete *payload)
{
  payload->instance_index = htobe32(payload->instance_index);
}

static inline void vapi_msg_snort_instance_delete_payload_ntoh(vapi_payload_snort_instance_delete *payload)
{
  payload->instance_index = be32toh(payload->instance_index);
}

static inline void vapi_msg_snort_instance_delete_hton(vapi_msg_snort_instance_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_instance_delete'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_snort_instance_delete_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_instance_delete_ntoh(vapi_msg_snort_instance_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_instance_delete'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_snort_instance_delete_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_instance_delete_msg_size(vapi_msg_snort_instance_delete *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_instance_delete_msg_size(vapi_msg_snort_instance_delete *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_instance_delete) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_instance_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_instance_delete));
      return -1;
    }
  if (vapi_calc_snort_instance_delete_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_instance_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_instance_delete_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_snort_instance_delete* vapi_alloc_snort_instance_delete(struct vapi_ctx_s *ctx)
{
  vapi_msg_snort_instance_delete *msg = NULL;
  const size_t size = sizeof(vapi_msg_snort_instance_delete);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_snort_instance_delete*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_snort_instance_delete);

  return msg;
}

static inline vapi_error_e vapi_snort_instance_delete(struct vapi_ctx_s *ctx,
  vapi_msg_snort_instance_delete *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_snort_instance_delete_reply *reply),
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
  vapi_msg_snort_instance_delete_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_snort_instance_delete_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_snort_instance_delete_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_snort_instance_delete()
{
  static const char name[] = "snort_instance_delete";
  static const char name_with_crc[] = "snort_instance_delete_6981211a";
  static vapi_message_desc_t __vapi_metadata_snort_instance_delete = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_snort_instance_delete, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_instance_delete_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_instance_delete_hton,
    (generic_swap_fn_t)vapi_msg_snort_instance_delete_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_instance_delete = vapi_register_msg(&__vapi_metadata_snort_instance_delete);
  VAPI_DBG("Assigned msg id %d to snort_instance_delete", vapi_msg_id_snort_instance_delete);
}
#endif

#ifndef defined_vapi_msg_snort_client_disconnect_reply
#define defined_vapi_msg_snort_client_disconnect_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_snort_client_disconnect_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_snort_client_disconnect_reply payload;
} vapi_msg_snort_client_disconnect_reply;

static inline void vapi_msg_snort_client_disconnect_reply_payload_hton(vapi_payload_snort_client_disconnect_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_snort_client_disconnect_reply_payload_ntoh(vapi_payload_snort_client_disconnect_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_snort_client_disconnect_reply_hton(vapi_msg_snort_client_disconnect_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_client_disconnect_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_snort_client_disconnect_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_client_disconnect_reply_ntoh(vapi_msg_snort_client_disconnect_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_client_disconnect_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_snort_client_disconnect_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_client_disconnect_reply_msg_size(vapi_msg_snort_client_disconnect_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_client_disconnect_reply_msg_size(vapi_msg_snort_client_disconnect_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_client_disconnect_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_client_disconnect_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_client_disconnect_reply));
      return -1;
    }
  if (vapi_calc_snort_client_disconnect_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_client_disconnect_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_client_disconnect_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_snort_client_disconnect_reply()
{
  static const char name[] = "snort_client_disconnect_reply";
  static const char name_with_crc[] = "snort_client_disconnect_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_snort_client_disconnect_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_snort_client_disconnect_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_client_disconnect_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_client_disconnect_reply_hton,
    (generic_swap_fn_t)vapi_msg_snort_client_disconnect_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_client_disconnect_reply = vapi_register_msg(&__vapi_metadata_snort_client_disconnect_reply);
  VAPI_DBG("Assigned msg id %d to snort_client_disconnect_reply", vapi_msg_id_snort_client_disconnect_reply);
}

static inline void vapi_set_vapi_msg_snort_client_disconnect_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_snort_client_disconnect_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_snort_client_disconnect_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_snort_client_disconnect
#define defined_vapi_msg_snort_client_disconnect
typedef struct __attribute__ ((__packed__)) {
  u32 snort_client_index; 
} vapi_payload_snort_client_disconnect;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_snort_client_disconnect payload;
} vapi_msg_snort_client_disconnect;

static inline void vapi_msg_snort_client_disconnect_payload_hton(vapi_payload_snort_client_disconnect *payload)
{
  payload->snort_client_index = htobe32(payload->snort_client_index);
}

static inline void vapi_msg_snort_client_disconnect_payload_ntoh(vapi_payload_snort_client_disconnect *payload)
{
  payload->snort_client_index = be32toh(payload->snort_client_index);
}

static inline void vapi_msg_snort_client_disconnect_hton(vapi_msg_snort_client_disconnect *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_client_disconnect'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_snort_client_disconnect_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_client_disconnect_ntoh(vapi_msg_snort_client_disconnect *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_client_disconnect'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_snort_client_disconnect_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_client_disconnect_msg_size(vapi_msg_snort_client_disconnect *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_client_disconnect_msg_size(vapi_msg_snort_client_disconnect *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_client_disconnect) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_client_disconnect' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_client_disconnect));
      return -1;
    }
  if (vapi_calc_snort_client_disconnect_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_client_disconnect' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_client_disconnect_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_snort_client_disconnect* vapi_alloc_snort_client_disconnect(struct vapi_ctx_s *ctx)
{
  vapi_msg_snort_client_disconnect *msg = NULL;
  const size_t size = sizeof(vapi_msg_snort_client_disconnect);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_snort_client_disconnect*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_snort_client_disconnect);

  return msg;
}

static inline vapi_error_e vapi_snort_client_disconnect(struct vapi_ctx_s *ctx,
  vapi_msg_snort_client_disconnect *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_snort_client_disconnect_reply *reply),
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
  vapi_msg_snort_client_disconnect_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_snort_client_disconnect_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_snort_client_disconnect_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_snort_client_disconnect()
{
  static const char name[] = "snort_client_disconnect";
  static const char name_with_crc[] = "snort_client_disconnect_30a221a6";
  static vapi_message_desc_t __vapi_metadata_snort_client_disconnect = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_snort_client_disconnect, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_client_disconnect_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_client_disconnect_hton,
    (generic_swap_fn_t)vapi_msg_snort_client_disconnect_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_client_disconnect = vapi_register_msg(&__vapi_metadata_snort_client_disconnect);
  VAPI_DBG("Assigned msg id %d to snort_client_disconnect", vapi_msg_id_snort_client_disconnect);
}
#endif

#ifndef defined_vapi_msg_snort_instance_disconnect_reply
#define defined_vapi_msg_snort_instance_disconnect_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_snort_instance_disconnect_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_snort_instance_disconnect_reply payload;
} vapi_msg_snort_instance_disconnect_reply;

static inline void vapi_msg_snort_instance_disconnect_reply_payload_hton(vapi_payload_snort_instance_disconnect_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_snort_instance_disconnect_reply_payload_ntoh(vapi_payload_snort_instance_disconnect_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_snort_instance_disconnect_reply_hton(vapi_msg_snort_instance_disconnect_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_instance_disconnect_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_snort_instance_disconnect_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_instance_disconnect_reply_ntoh(vapi_msg_snort_instance_disconnect_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_instance_disconnect_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_snort_instance_disconnect_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_instance_disconnect_reply_msg_size(vapi_msg_snort_instance_disconnect_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_instance_disconnect_reply_msg_size(vapi_msg_snort_instance_disconnect_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_instance_disconnect_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_instance_disconnect_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_instance_disconnect_reply));
      return -1;
    }
  if (vapi_calc_snort_instance_disconnect_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_instance_disconnect_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_instance_disconnect_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_snort_instance_disconnect_reply()
{
  static const char name[] = "snort_instance_disconnect_reply";
  static const char name_with_crc[] = "snort_instance_disconnect_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_snort_instance_disconnect_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_snort_instance_disconnect_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_instance_disconnect_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_instance_disconnect_reply_hton,
    (generic_swap_fn_t)vapi_msg_snort_instance_disconnect_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_instance_disconnect_reply = vapi_register_msg(&__vapi_metadata_snort_instance_disconnect_reply);
  VAPI_DBG("Assigned msg id %d to snort_instance_disconnect_reply", vapi_msg_id_snort_instance_disconnect_reply);
}

static inline void vapi_set_vapi_msg_snort_instance_disconnect_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_snort_instance_disconnect_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_snort_instance_disconnect_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_snort_instance_disconnect
#define defined_vapi_msg_snort_instance_disconnect
typedef struct __attribute__ ((__packed__)) {
  u32 instance_index; 
} vapi_payload_snort_instance_disconnect;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_snort_instance_disconnect payload;
} vapi_msg_snort_instance_disconnect;

static inline void vapi_msg_snort_instance_disconnect_payload_hton(vapi_payload_snort_instance_disconnect *payload)
{
  payload->instance_index = htobe32(payload->instance_index);
}

static inline void vapi_msg_snort_instance_disconnect_payload_ntoh(vapi_payload_snort_instance_disconnect *payload)
{
  payload->instance_index = be32toh(payload->instance_index);
}

static inline void vapi_msg_snort_instance_disconnect_hton(vapi_msg_snort_instance_disconnect *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_instance_disconnect'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_snort_instance_disconnect_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_instance_disconnect_ntoh(vapi_msg_snort_instance_disconnect *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_instance_disconnect'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_snort_instance_disconnect_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_instance_disconnect_msg_size(vapi_msg_snort_instance_disconnect *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_instance_disconnect_msg_size(vapi_msg_snort_instance_disconnect *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_instance_disconnect) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_instance_disconnect' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_instance_disconnect));
      return -1;
    }
  if (vapi_calc_snort_instance_disconnect_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_instance_disconnect' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_instance_disconnect_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_snort_instance_disconnect* vapi_alloc_snort_instance_disconnect(struct vapi_ctx_s *ctx)
{
  vapi_msg_snort_instance_disconnect *msg = NULL;
  const size_t size = sizeof(vapi_msg_snort_instance_disconnect);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_snort_instance_disconnect*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_snort_instance_disconnect);

  return msg;
}

static inline vapi_error_e vapi_snort_instance_disconnect(struct vapi_ctx_s *ctx,
  vapi_msg_snort_instance_disconnect *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_snort_instance_disconnect_reply *reply),
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
  vapi_msg_snort_instance_disconnect_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_snort_instance_disconnect_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_snort_instance_disconnect_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_snort_instance_disconnect()
{
  static const char name[] = "snort_instance_disconnect";
  static const char name_with_crc[] = "snort_instance_disconnect_6981211a";
  static vapi_message_desc_t __vapi_metadata_snort_instance_disconnect = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_snort_instance_disconnect, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_instance_disconnect_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_instance_disconnect_hton,
    (generic_swap_fn_t)vapi_msg_snort_instance_disconnect_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_instance_disconnect = vapi_register_msg(&__vapi_metadata_snort_instance_disconnect);
  VAPI_DBG("Assigned msg id %d to snort_instance_disconnect", vapi_msg_id_snort_instance_disconnect);
}
#endif

#ifndef defined_vapi_msg_snort_interface_attach_reply
#define defined_vapi_msg_snort_interface_attach_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_snort_interface_attach_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_snort_interface_attach_reply payload;
} vapi_msg_snort_interface_attach_reply;

static inline void vapi_msg_snort_interface_attach_reply_payload_hton(vapi_payload_snort_interface_attach_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_snort_interface_attach_reply_payload_ntoh(vapi_payload_snort_interface_attach_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_snort_interface_attach_reply_hton(vapi_msg_snort_interface_attach_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_interface_attach_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_snort_interface_attach_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_interface_attach_reply_ntoh(vapi_msg_snort_interface_attach_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_interface_attach_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_snort_interface_attach_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_interface_attach_reply_msg_size(vapi_msg_snort_interface_attach_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_interface_attach_reply_msg_size(vapi_msg_snort_interface_attach_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_interface_attach_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_interface_attach_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_interface_attach_reply));
      return -1;
    }
  if (vapi_calc_snort_interface_attach_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_interface_attach_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_interface_attach_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_snort_interface_attach_reply()
{
  static const char name[] = "snort_interface_attach_reply";
  static const char name_with_crc[] = "snort_interface_attach_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_snort_interface_attach_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_snort_interface_attach_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_interface_attach_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_interface_attach_reply_hton,
    (generic_swap_fn_t)vapi_msg_snort_interface_attach_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_interface_attach_reply = vapi_register_msg(&__vapi_metadata_snort_interface_attach_reply);
  VAPI_DBG("Assigned msg id %d to snort_interface_attach_reply", vapi_msg_id_snort_interface_attach_reply);
}

static inline void vapi_set_vapi_msg_snort_interface_attach_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_snort_interface_attach_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_snort_interface_attach_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_snort_interface_attach
#define defined_vapi_msg_snort_interface_attach
typedef struct __attribute__ ((__packed__)) {
  u32 instance_index;
  u32 sw_if_index;
  u8 snort_dir; 
} vapi_payload_snort_interface_attach;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_snort_interface_attach payload;
} vapi_msg_snort_interface_attach;

static inline void vapi_msg_snort_interface_attach_payload_hton(vapi_payload_snort_interface_attach *payload)
{
  payload->instance_index = htobe32(payload->instance_index);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_snort_interface_attach_payload_ntoh(vapi_payload_snort_interface_attach *payload)
{
  payload->instance_index = be32toh(payload->instance_index);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_snort_interface_attach_hton(vapi_msg_snort_interface_attach *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_interface_attach'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_snort_interface_attach_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_interface_attach_ntoh(vapi_msg_snort_interface_attach *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_interface_attach'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_snort_interface_attach_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_interface_attach_msg_size(vapi_msg_snort_interface_attach *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_interface_attach_msg_size(vapi_msg_snort_interface_attach *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_interface_attach) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_interface_attach' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_interface_attach));
      return -1;
    }
  if (vapi_calc_snort_interface_attach_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_interface_attach' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_interface_attach_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_snort_interface_attach* vapi_alloc_snort_interface_attach(struct vapi_ctx_s *ctx)
{
  vapi_msg_snort_interface_attach *msg = NULL;
  const size_t size = sizeof(vapi_msg_snort_interface_attach);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_snort_interface_attach*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_snort_interface_attach);

  return msg;
}

static inline vapi_error_e vapi_snort_interface_attach(struct vapi_ctx_s *ctx,
  vapi_msg_snort_interface_attach *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_snort_interface_attach_reply *reply),
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
  vapi_msg_snort_interface_attach_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_snort_interface_attach_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_snort_interface_attach_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_snort_interface_attach()
{
  static const char name[] = "snort_interface_attach";
  static const char name_with_crc[] = "snort_interface_attach_79ceda89";
  static vapi_message_desc_t __vapi_metadata_snort_interface_attach = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_snort_interface_attach, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_interface_attach_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_interface_attach_hton,
    (generic_swap_fn_t)vapi_msg_snort_interface_attach_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_interface_attach = vapi_register_msg(&__vapi_metadata_snort_interface_attach);
  VAPI_DBG("Assigned msg id %d to snort_interface_attach", vapi_msg_id_snort_interface_attach);
}
#endif

#ifndef defined_vapi_msg_snort_interface_detach_reply
#define defined_vapi_msg_snort_interface_detach_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_snort_interface_detach_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_snort_interface_detach_reply payload;
} vapi_msg_snort_interface_detach_reply;

static inline void vapi_msg_snort_interface_detach_reply_payload_hton(vapi_payload_snort_interface_detach_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_snort_interface_detach_reply_payload_ntoh(vapi_payload_snort_interface_detach_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_snort_interface_detach_reply_hton(vapi_msg_snort_interface_detach_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_interface_detach_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_snort_interface_detach_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_interface_detach_reply_ntoh(vapi_msg_snort_interface_detach_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_interface_detach_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_snort_interface_detach_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_interface_detach_reply_msg_size(vapi_msg_snort_interface_detach_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_interface_detach_reply_msg_size(vapi_msg_snort_interface_detach_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_interface_detach_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_interface_detach_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_interface_detach_reply));
      return -1;
    }
  if (vapi_calc_snort_interface_detach_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_interface_detach_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_interface_detach_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_snort_interface_detach_reply()
{
  static const char name[] = "snort_interface_detach_reply";
  static const char name_with_crc[] = "snort_interface_detach_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_snort_interface_detach_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_snort_interface_detach_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_interface_detach_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_interface_detach_reply_hton,
    (generic_swap_fn_t)vapi_msg_snort_interface_detach_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_interface_detach_reply = vapi_register_msg(&__vapi_metadata_snort_interface_detach_reply);
  VAPI_DBG("Assigned msg id %d to snort_interface_detach_reply", vapi_msg_id_snort_interface_detach_reply);
}

static inline void vapi_set_vapi_msg_snort_interface_detach_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_snort_interface_detach_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_snort_interface_detach_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_snort_interface_detach
#define defined_vapi_msg_snort_interface_detach
typedef struct __attribute__ ((__packed__)) {
  u32 sw_if_index; 
} vapi_payload_snort_interface_detach;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_snort_interface_detach payload;
} vapi_msg_snort_interface_detach;

static inline void vapi_msg_snort_interface_detach_payload_hton(vapi_payload_snort_interface_detach *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_snort_interface_detach_payload_ntoh(vapi_payload_snort_interface_detach *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_snort_interface_detach_hton(vapi_msg_snort_interface_detach *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_interface_detach'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_snort_interface_detach_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_interface_detach_ntoh(vapi_msg_snort_interface_detach *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_interface_detach'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_snort_interface_detach_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_interface_detach_msg_size(vapi_msg_snort_interface_detach *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_interface_detach_msg_size(vapi_msg_snort_interface_detach *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_interface_detach) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_interface_detach' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_interface_detach));
      return -1;
    }
  if (vapi_calc_snort_interface_detach_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_interface_detach' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_interface_detach_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_snort_interface_detach* vapi_alloc_snort_interface_detach(struct vapi_ctx_s *ctx)
{
  vapi_msg_snort_interface_detach *msg = NULL;
  const size_t size = sizeof(vapi_msg_snort_interface_detach);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_snort_interface_detach*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_snort_interface_detach);

  return msg;
}

static inline vapi_error_e vapi_snort_interface_detach(struct vapi_ctx_s *ctx,
  vapi_msg_snort_interface_detach *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_snort_interface_detach_reply *reply),
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
  vapi_msg_snort_interface_detach_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_snort_interface_detach_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_snort_interface_detach_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_snort_interface_detach()
{
  static const char name[] = "snort_interface_detach";
  static const char name_with_crc[] = "snort_interface_detach_529cb13f";
  static vapi_message_desc_t __vapi_metadata_snort_interface_detach = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_snort_interface_detach, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_interface_detach_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_interface_detach_hton,
    (generic_swap_fn_t)vapi_msg_snort_interface_detach_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_interface_detach = vapi_register_msg(&__vapi_metadata_snort_interface_detach);
  VAPI_DBG("Assigned msg id %d to snort_interface_detach", vapi_msg_id_snort_interface_detach);
}
#endif

#ifndef defined_vapi_msg_snort_input_mode_get_reply
#define defined_vapi_msg_snort_input_mode_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 snort_mode; 
} vapi_payload_snort_input_mode_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_snort_input_mode_get_reply payload;
} vapi_msg_snort_input_mode_get_reply;

static inline void vapi_msg_snort_input_mode_get_reply_payload_hton(vapi_payload_snort_input_mode_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->snort_mode = htobe32(payload->snort_mode);
}

static inline void vapi_msg_snort_input_mode_get_reply_payload_ntoh(vapi_payload_snort_input_mode_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->snort_mode = be32toh(payload->snort_mode);
}

static inline void vapi_msg_snort_input_mode_get_reply_hton(vapi_msg_snort_input_mode_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_input_mode_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_snort_input_mode_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_input_mode_get_reply_ntoh(vapi_msg_snort_input_mode_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_input_mode_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_snort_input_mode_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_input_mode_get_reply_msg_size(vapi_msg_snort_input_mode_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_input_mode_get_reply_msg_size(vapi_msg_snort_input_mode_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_input_mode_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_input_mode_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_input_mode_get_reply));
      return -1;
    }
  if (vapi_calc_snort_input_mode_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_input_mode_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_input_mode_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_snort_input_mode_get_reply()
{
  static const char name[] = "snort_input_mode_get_reply";
  static const char name_with_crc[] = "snort_input_mode_get_reply_a18796bf";
  static vapi_message_desc_t __vapi_metadata_snort_input_mode_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_snort_input_mode_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_input_mode_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_input_mode_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_snort_input_mode_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_input_mode_get_reply = vapi_register_msg(&__vapi_metadata_snort_input_mode_get_reply);
  VAPI_DBG("Assigned msg id %d to snort_input_mode_get_reply", vapi_msg_id_snort_input_mode_get_reply);
}

static inline void vapi_set_vapi_msg_snort_input_mode_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_snort_input_mode_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_snort_input_mode_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_snort_input_mode_get
#define defined_vapi_msg_snort_input_mode_get
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_snort_input_mode_get;

static inline void vapi_msg_snort_input_mode_get_hton(vapi_msg_snort_input_mode_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_input_mode_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_snort_input_mode_get_ntoh(vapi_msg_snort_input_mode_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_input_mode_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_snort_input_mode_get_msg_size(vapi_msg_snort_input_mode_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_input_mode_get_msg_size(vapi_msg_snort_input_mode_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_input_mode_get) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_input_mode_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_input_mode_get));
      return -1;
    }
  if (vapi_calc_snort_input_mode_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_input_mode_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_input_mode_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_snort_input_mode_get* vapi_alloc_snort_input_mode_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_snort_input_mode_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_snort_input_mode_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_snort_input_mode_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_snort_input_mode_get);

  return msg;
}

static inline vapi_error_e vapi_snort_input_mode_get(struct vapi_ctx_s *ctx,
  vapi_msg_snort_input_mode_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_snort_input_mode_get_reply *reply),
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
  vapi_msg_snort_input_mode_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_snort_input_mode_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_snort_input_mode_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_snort_input_mode_get()
{
  static const char name[] = "snort_input_mode_get";
  static const char name_with_crc[] = "snort_input_mode_get_51077d14";
  static vapi_message_desc_t __vapi_metadata_snort_input_mode_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_snort_input_mode_get_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_input_mode_get_hton,
    (generic_swap_fn_t)vapi_msg_snort_input_mode_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_input_mode_get = vapi_register_msg(&__vapi_metadata_snort_input_mode_get);
  VAPI_DBG("Assigned msg id %d to snort_input_mode_get", vapi_msg_id_snort_input_mode_get);
}
#endif

#ifndef defined_vapi_msg_snort_input_mode_set_reply
#define defined_vapi_msg_snort_input_mode_set_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_snort_input_mode_set_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_snort_input_mode_set_reply payload;
} vapi_msg_snort_input_mode_set_reply;

static inline void vapi_msg_snort_input_mode_set_reply_payload_hton(vapi_payload_snort_input_mode_set_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_snort_input_mode_set_reply_payload_ntoh(vapi_payload_snort_input_mode_set_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_snort_input_mode_set_reply_hton(vapi_msg_snort_input_mode_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_input_mode_set_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_snort_input_mode_set_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_input_mode_set_reply_ntoh(vapi_msg_snort_input_mode_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_input_mode_set_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_snort_input_mode_set_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_input_mode_set_reply_msg_size(vapi_msg_snort_input_mode_set_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_input_mode_set_reply_msg_size(vapi_msg_snort_input_mode_set_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_input_mode_set_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_input_mode_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_input_mode_set_reply));
      return -1;
    }
  if (vapi_calc_snort_input_mode_set_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_input_mode_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_input_mode_set_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_snort_input_mode_set_reply()
{
  static const char name[] = "snort_input_mode_set_reply";
  static const char name_with_crc[] = "snort_input_mode_set_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_snort_input_mode_set_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_snort_input_mode_set_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_input_mode_set_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_input_mode_set_reply_hton,
    (generic_swap_fn_t)vapi_msg_snort_input_mode_set_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_input_mode_set_reply = vapi_register_msg(&__vapi_metadata_snort_input_mode_set_reply);
  VAPI_DBG("Assigned msg id %d to snort_input_mode_set_reply", vapi_msg_id_snort_input_mode_set_reply);
}

static inline void vapi_set_vapi_msg_snort_input_mode_set_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_snort_input_mode_set_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_snort_input_mode_set_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_snort_input_mode_set
#define defined_vapi_msg_snort_input_mode_set
typedef struct __attribute__ ((__packed__)) {
  u8 input_mode; 
} vapi_payload_snort_input_mode_set;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_snort_input_mode_set payload;
} vapi_msg_snort_input_mode_set;

static inline void vapi_msg_snort_input_mode_set_payload_hton(vapi_payload_snort_input_mode_set *payload)
{

}

static inline void vapi_msg_snort_input_mode_set_payload_ntoh(vapi_payload_snort_input_mode_set *payload)
{

}

static inline void vapi_msg_snort_input_mode_set_hton(vapi_msg_snort_input_mode_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_input_mode_set'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_snort_input_mode_set_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_input_mode_set_ntoh(vapi_msg_snort_input_mode_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_input_mode_set'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_snort_input_mode_set_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_input_mode_set_msg_size(vapi_msg_snort_input_mode_set *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_input_mode_set_msg_size(vapi_msg_snort_input_mode_set *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_input_mode_set) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_input_mode_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_input_mode_set));
      return -1;
    }
  if (vapi_calc_snort_input_mode_set_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_input_mode_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_input_mode_set_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_snort_input_mode_set* vapi_alloc_snort_input_mode_set(struct vapi_ctx_s *ctx)
{
  vapi_msg_snort_input_mode_set *msg = NULL;
  const size_t size = sizeof(vapi_msg_snort_input_mode_set);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_snort_input_mode_set*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_snort_input_mode_set);

  return msg;
}

static inline vapi_error_e vapi_snort_input_mode_set(struct vapi_ctx_s *ctx,
  vapi_msg_snort_input_mode_set *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_snort_input_mode_set_reply *reply),
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
  vapi_msg_snort_input_mode_set_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_snort_input_mode_set_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_snort_input_mode_set_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_snort_input_mode_set()
{
  static const char name[] = "snort_input_mode_set";
  static const char name_with_crc[] = "snort_input_mode_set_d595d008";
  static vapi_message_desc_t __vapi_metadata_snort_input_mode_set = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_snort_input_mode_set, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_input_mode_set_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_input_mode_set_hton,
    (generic_swap_fn_t)vapi_msg_snort_input_mode_set_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_input_mode_set = vapi_register_msg(&__vapi_metadata_snort_input_mode_set);
  VAPI_DBG("Assigned msg id %d to snort_input_mode_set", vapi_msg_id_snort_input_mode_set);
}
#endif

#ifndef defined_vapi_msg_snort_instance_get_reply
#define defined_vapi_msg_snort_instance_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 cursor; 
} vapi_payload_snort_instance_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_snort_instance_get_reply payload;
} vapi_msg_snort_instance_get_reply;

static inline void vapi_msg_snort_instance_get_reply_payload_hton(vapi_payload_snort_instance_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_snort_instance_get_reply_payload_ntoh(vapi_payload_snort_instance_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_snort_instance_get_reply_hton(vapi_msg_snort_instance_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_instance_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_snort_instance_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_instance_get_reply_ntoh(vapi_msg_snort_instance_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_instance_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_snort_instance_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_instance_get_reply_msg_size(vapi_msg_snort_instance_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_instance_get_reply_msg_size(vapi_msg_snort_instance_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_instance_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_instance_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_instance_get_reply));
      return -1;
    }
  if (vapi_calc_snort_instance_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_instance_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_instance_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_snort_instance_get_reply()
{
  static const char name[] = "snort_instance_get_reply";
  static const char name_with_crc[] = "snort_instance_get_reply_53b48f5d";
  static vapi_message_desc_t __vapi_metadata_snort_instance_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_snort_instance_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_instance_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_instance_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_snort_instance_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_instance_get_reply = vapi_register_msg(&__vapi_metadata_snort_instance_get_reply);
  VAPI_DBG("Assigned msg id %d to snort_instance_get_reply", vapi_msg_id_snort_instance_get_reply);
}

static inline void vapi_set_vapi_msg_snort_instance_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_snort_instance_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_snort_instance_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_snort_instance_details
#define defined_vapi_msg_snort_instance_details
typedef struct __attribute__ ((__packed__)) {
  u32 instance_index;
  u32 shm_size;
  u32 shm_fd;
  u8 drop_on_disconnect;
  u32 snort_client_index;
  vl_api_string_t name; 
} vapi_payload_snort_instance_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_snort_instance_details payload;
} vapi_msg_snort_instance_details;

static inline void vapi_msg_snort_instance_details_payload_hton(vapi_payload_snort_instance_details *payload)
{
  payload->instance_index = htobe32(payload->instance_index);
  payload->shm_size = htobe32(payload->shm_size);
  payload->shm_fd = htobe32(payload->shm_fd);
  payload->snort_client_index = htobe32(payload->snort_client_index);
  vl_api_string_t_hton(&payload->name);
}

static inline void vapi_msg_snort_instance_details_payload_ntoh(vapi_payload_snort_instance_details *payload)
{
  payload->instance_index = be32toh(payload->instance_index);
  payload->shm_size = be32toh(payload->shm_size);
  payload->shm_fd = be32toh(payload->shm_fd);
  payload->snort_client_index = be32toh(payload->snort_client_index);
  vl_api_string_t_ntoh(&payload->name);
}

static inline void vapi_msg_snort_instance_details_hton(vapi_msg_snort_instance_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_instance_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_snort_instance_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_instance_details_ntoh(vapi_msg_snort_instance_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_instance_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_snort_instance_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_instance_details_msg_size(vapi_msg_snort_instance_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.name.buf[0]) * msg->payload.name.length;
}

static inline int vapi_verify_snort_instance_details_msg_size(vapi_msg_snort_instance_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_instance_details) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_instance_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_instance_details));
      return -1;
    }
  if (vapi_calc_snort_instance_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_instance_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_instance_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_snort_instance_details()
{
  static const char name[] = "snort_instance_details";
  static const char name_with_crc[] = "snort_instance_details_abb60d49";
  static vapi_message_desc_t __vapi_metadata_snort_instance_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_snort_instance_details, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_instance_details_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_instance_details_hton,
    (generic_swap_fn_t)vapi_msg_snort_instance_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_instance_details = vapi_register_msg(&__vapi_metadata_snort_instance_details);
  VAPI_DBG("Assigned msg id %d to snort_instance_details", vapi_msg_id_snort_instance_details);
}
#endif

#ifndef defined_vapi_msg_snort_instance_get
#define defined_vapi_msg_snort_instance_get
typedef struct __attribute__ ((__packed__)) {
  u32 cursor;
  u32 instance_index; 
} vapi_payload_snort_instance_get;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_snort_instance_get payload;
} vapi_msg_snort_instance_get;

static inline void vapi_msg_snort_instance_get_payload_hton(vapi_payload_snort_instance_get *payload)
{
  payload->cursor = htobe32(payload->cursor);
  payload->instance_index = htobe32(payload->instance_index);
}

static inline void vapi_msg_snort_instance_get_payload_ntoh(vapi_payload_snort_instance_get *payload)
{
  payload->cursor = be32toh(payload->cursor);
  payload->instance_index = be32toh(payload->instance_index);
}

static inline void vapi_msg_snort_instance_get_hton(vapi_msg_snort_instance_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_instance_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_snort_instance_get_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_instance_get_ntoh(vapi_msg_snort_instance_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_instance_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_snort_instance_get_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_instance_get_msg_size(vapi_msg_snort_instance_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_instance_get_msg_size(vapi_msg_snort_instance_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_instance_get) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_instance_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_instance_get));
      return -1;
    }
  if (vapi_calc_snort_instance_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_instance_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_instance_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_snort_instance_get* vapi_alloc_snort_instance_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_snort_instance_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_snort_instance_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_snort_instance_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_snort_instance_get);

  return msg;
}

static inline vapi_error_e vapi_snort_instance_get(struct vapi_ctx_s *ctx,
  vapi_msg_snort_instance_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_snort_instance_get_reply *reply),
  void *reply_callback_ctx,
  vapi_error_e (*details_callback)(struct vapi_ctx_s *ctx,
                                   void *callback_ctx,
                                   vapi_error_e rv,
                                   bool is_last,
                                   vapi_payload_snort_instance_details *details),
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
  vapi_msg_snort_instance_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_snort_instance_details, VAPI_REQUEST_STREAM, 
                       (vapi_cb_t)details_callback, details_callback_ctx);
    vapi_store_request(ctx, req_context, vapi_msg_id_snort_instance_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_snort_instance_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_snort_instance_get()
{
  static const char name[] = "snort_instance_get";
  static const char name_with_crc[] = "snort_instance_get_07c37475";
  static vapi_message_desc_t __vapi_metadata_snort_instance_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_snort_instance_get, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_instance_get_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_instance_get_hton,
    (generic_swap_fn_t)vapi_msg_snort_instance_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_instance_get = vapi_register_msg(&__vapi_metadata_snort_instance_get);
  VAPI_DBG("Assigned msg id %d to snort_instance_get", vapi_msg_id_snort_instance_get);
}
#endif

#ifndef defined_vapi_msg_snort_interface_get_reply
#define defined_vapi_msg_snort_interface_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 cursor; 
} vapi_payload_snort_interface_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_snort_interface_get_reply payload;
} vapi_msg_snort_interface_get_reply;

static inline void vapi_msg_snort_interface_get_reply_payload_hton(vapi_payload_snort_interface_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_snort_interface_get_reply_payload_ntoh(vapi_payload_snort_interface_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_snort_interface_get_reply_hton(vapi_msg_snort_interface_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_interface_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_snort_interface_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_interface_get_reply_ntoh(vapi_msg_snort_interface_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_interface_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_snort_interface_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_interface_get_reply_msg_size(vapi_msg_snort_interface_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_interface_get_reply_msg_size(vapi_msg_snort_interface_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_interface_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_interface_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_interface_get_reply));
      return -1;
    }
  if (vapi_calc_snort_interface_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_interface_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_interface_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_snort_interface_get_reply()
{
  static const char name[] = "snort_interface_get_reply";
  static const char name_with_crc[] = "snort_interface_get_reply_53b48f5d";
  static vapi_message_desc_t __vapi_metadata_snort_interface_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_snort_interface_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_interface_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_interface_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_snort_interface_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_interface_get_reply = vapi_register_msg(&__vapi_metadata_snort_interface_get_reply);
  VAPI_DBG("Assigned msg id %d to snort_interface_get_reply", vapi_msg_id_snort_interface_get_reply);
}

static inline void vapi_set_vapi_msg_snort_interface_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_snort_interface_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_snort_interface_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_snort_interface_details
#define defined_vapi_msg_snort_interface_details
typedef struct __attribute__ ((__packed__)) {
  u32 sw_if_index;
  u32 instance_index; 
} vapi_payload_snort_interface_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_snort_interface_details payload;
} vapi_msg_snort_interface_details;

static inline void vapi_msg_snort_interface_details_payload_hton(vapi_payload_snort_interface_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->instance_index = htobe32(payload->instance_index);
}

static inline void vapi_msg_snort_interface_details_payload_ntoh(vapi_payload_snort_interface_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->instance_index = be32toh(payload->instance_index);
}

static inline void vapi_msg_snort_interface_details_hton(vapi_msg_snort_interface_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_interface_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_snort_interface_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_interface_details_ntoh(vapi_msg_snort_interface_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_interface_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_snort_interface_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_interface_details_msg_size(vapi_msg_snort_interface_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_interface_details_msg_size(vapi_msg_snort_interface_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_interface_details) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_interface_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_interface_details));
      return -1;
    }
  if (vapi_calc_snort_interface_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_interface_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_interface_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_snort_interface_details()
{
  static const char name[] = "snort_interface_details";
  static const char name_with_crc[] = "snort_interface_details_52c75990";
  static vapi_message_desc_t __vapi_metadata_snort_interface_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_snort_interface_details, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_interface_details_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_interface_details_hton,
    (generic_swap_fn_t)vapi_msg_snort_interface_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_interface_details = vapi_register_msg(&__vapi_metadata_snort_interface_details);
  VAPI_DBG("Assigned msg id %d to snort_interface_details", vapi_msg_id_snort_interface_details);
}
#endif

#ifndef defined_vapi_msg_snort_interface_get
#define defined_vapi_msg_snort_interface_get
typedef struct __attribute__ ((__packed__)) {
  u32 cursor;
  u32 sw_if_index; 
} vapi_payload_snort_interface_get;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_snort_interface_get payload;
} vapi_msg_snort_interface_get;

static inline void vapi_msg_snort_interface_get_payload_hton(vapi_payload_snort_interface_get *payload)
{
  payload->cursor = htobe32(payload->cursor);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_snort_interface_get_payload_ntoh(vapi_payload_snort_interface_get *payload)
{
  payload->cursor = be32toh(payload->cursor);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_snort_interface_get_hton(vapi_msg_snort_interface_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_interface_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_snort_interface_get_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_interface_get_ntoh(vapi_msg_snort_interface_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_interface_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_snort_interface_get_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_interface_get_msg_size(vapi_msg_snort_interface_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_interface_get_msg_size(vapi_msg_snort_interface_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_interface_get) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_interface_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_interface_get));
      return -1;
    }
  if (vapi_calc_snort_interface_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_interface_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_interface_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_snort_interface_get* vapi_alloc_snort_interface_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_snort_interface_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_snort_interface_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_snort_interface_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_snort_interface_get);

  return msg;
}

static inline vapi_error_e vapi_snort_interface_get(struct vapi_ctx_s *ctx,
  vapi_msg_snort_interface_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_snort_interface_get_reply *reply),
  void *reply_callback_ctx,
  vapi_error_e (*details_callback)(struct vapi_ctx_s *ctx,
                                   void *callback_ctx,
                                   vapi_error_e rv,
                                   bool is_last,
                                   vapi_payload_snort_interface_details *details),
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
  vapi_msg_snort_interface_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_snort_interface_details, VAPI_REQUEST_STREAM, 
                       (vapi_cb_t)details_callback, details_callback_ctx);
    vapi_store_request(ctx, req_context, vapi_msg_id_snort_interface_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_snort_interface_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_snort_interface_get()
{
  static const char name[] = "snort_interface_get";
  static const char name_with_crc[] = "snort_interface_get_765a2424";
  static vapi_message_desc_t __vapi_metadata_snort_interface_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_snort_interface_get, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_interface_get_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_interface_get_hton,
    (generic_swap_fn_t)vapi_msg_snort_interface_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_interface_get = vapi_register_msg(&__vapi_metadata_snort_interface_get);
  VAPI_DBG("Assigned msg id %d to snort_interface_get", vapi_msg_id_snort_interface_get);
}
#endif

#ifndef defined_vapi_msg_snort_client_get_reply
#define defined_vapi_msg_snort_client_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 cursor; 
} vapi_payload_snort_client_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_snort_client_get_reply payload;
} vapi_msg_snort_client_get_reply;

static inline void vapi_msg_snort_client_get_reply_payload_hton(vapi_payload_snort_client_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_snort_client_get_reply_payload_ntoh(vapi_payload_snort_client_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_snort_client_get_reply_hton(vapi_msg_snort_client_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_client_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_snort_client_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_client_get_reply_ntoh(vapi_msg_snort_client_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_client_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_snort_client_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_client_get_reply_msg_size(vapi_msg_snort_client_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_client_get_reply_msg_size(vapi_msg_snort_client_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_client_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_client_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_client_get_reply));
      return -1;
    }
  if (vapi_calc_snort_client_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_client_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_client_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_snort_client_get_reply()
{
  static const char name[] = "snort_client_get_reply";
  static const char name_with_crc[] = "snort_client_get_reply_53b48f5d";
  static vapi_message_desc_t __vapi_metadata_snort_client_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_snort_client_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_client_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_client_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_snort_client_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_client_get_reply = vapi_register_msg(&__vapi_metadata_snort_client_get_reply);
  VAPI_DBG("Assigned msg id %d to snort_client_get_reply", vapi_msg_id_snort_client_get_reply);
}

static inline void vapi_set_vapi_msg_snort_client_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_snort_client_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_snort_client_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_snort_client_details
#define defined_vapi_msg_snort_client_details
typedef struct __attribute__ ((__packed__)) {
  u32 client_index;
  u32 instance_index; 
} vapi_payload_snort_client_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_snort_client_details payload;
} vapi_msg_snort_client_details;

static inline void vapi_msg_snort_client_details_payload_hton(vapi_payload_snort_client_details *payload)
{
  payload->client_index = htobe32(payload->client_index);
  payload->instance_index = htobe32(payload->instance_index);
}

static inline void vapi_msg_snort_client_details_payload_ntoh(vapi_payload_snort_client_details *payload)
{
  payload->client_index = be32toh(payload->client_index);
  payload->instance_index = be32toh(payload->instance_index);
}

static inline void vapi_msg_snort_client_details_hton(vapi_msg_snort_client_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_client_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_snort_client_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_client_details_ntoh(vapi_msg_snort_client_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_client_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_snort_client_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_client_details_msg_size(vapi_msg_snort_client_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_client_details_msg_size(vapi_msg_snort_client_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_client_details) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_client_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_client_details));
      return -1;
    }
  if (vapi_calc_snort_client_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_client_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_client_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_snort_client_details()
{
  static const char name[] = "snort_client_details";
  static const char name_with_crc[] = "snort_client_details_7e29e6f5";
  static vapi_message_desc_t __vapi_metadata_snort_client_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_snort_client_details, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_client_details_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_client_details_hton,
    (generic_swap_fn_t)vapi_msg_snort_client_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_client_details = vapi_register_msg(&__vapi_metadata_snort_client_details);
  VAPI_DBG("Assigned msg id %d to snort_client_details", vapi_msg_id_snort_client_details);
}
#endif

#ifndef defined_vapi_msg_snort_client_get
#define defined_vapi_msg_snort_client_get
typedef struct __attribute__ ((__packed__)) {
  u32 cursor;
  u32 snort_client_index; 
} vapi_payload_snort_client_get;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_snort_client_get payload;
} vapi_msg_snort_client_get;

static inline void vapi_msg_snort_client_get_payload_hton(vapi_payload_snort_client_get *payload)
{
  payload->cursor = htobe32(payload->cursor);
  payload->snort_client_index = htobe32(payload->snort_client_index);
}

static inline void vapi_msg_snort_client_get_payload_ntoh(vapi_payload_snort_client_get *payload)
{
  payload->cursor = be32toh(payload->cursor);
  payload->snort_client_index = be32toh(payload->snort_client_index);
}

static inline void vapi_msg_snort_client_get_hton(vapi_msg_snort_client_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_client_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_snort_client_get_payload_hton(&msg->payload);
}

static inline void vapi_msg_snort_client_get_ntoh(vapi_msg_snort_client_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_snort_client_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_snort_client_get_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_snort_client_get_msg_size(vapi_msg_snort_client_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_snort_client_get_msg_size(vapi_msg_snort_client_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_snort_client_get) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_client_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_snort_client_get));
      return -1;
    }
  if (vapi_calc_snort_client_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'snort_client_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_snort_client_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_snort_client_get* vapi_alloc_snort_client_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_snort_client_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_snort_client_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_snort_client_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_snort_client_get);

  return msg;
}

static inline vapi_error_e vapi_snort_client_get(struct vapi_ctx_s *ctx,
  vapi_msg_snort_client_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_snort_client_get_reply *reply),
  void *reply_callback_ctx,
  vapi_error_e (*details_callback)(struct vapi_ctx_s *ctx,
                                   void *callback_ctx,
                                   vapi_error_e rv,
                                   bool is_last,
                                   vapi_payload_snort_client_details *details),
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
  vapi_msg_snort_client_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_snort_client_details, VAPI_REQUEST_STREAM, 
                       (vapi_cb_t)details_callback, details_callback_ctx);
    vapi_store_request(ctx, req_context, vapi_msg_id_snort_client_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_snort_client_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_snort_client_get()
{
  static const char name[] = "snort_client_get";
  static const char name_with_crc[] = "snort_client_get_51d54b70";
  static vapi_message_desc_t __vapi_metadata_snort_client_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_snort_client_get, payload),
    (verify_msg_size_fn_t)vapi_verify_snort_client_get_msg_size,
    (generic_swap_fn_t)vapi_msg_snort_client_get_hton,
    (generic_swap_fn_t)vapi_msg_snort_client_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_snort_client_get = vapi_register_msg(&__vapi_metadata_snort_client_get);
  VAPI_DBG("Assigned msg id %d to snort_client_get", vapi_msg_id_snort_client_get);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
