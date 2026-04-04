#ifndef __included_punt_api_json
#define __included_punt_api_json

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

extern vapi_msg_id_t vapi_msg_id_set_punt;
extern vapi_msg_id_t vapi_msg_id_set_punt_reply;
extern vapi_msg_id_t vapi_msg_id_punt_socket_register;
extern vapi_msg_id_t vapi_msg_id_punt_socket_register_reply;
extern vapi_msg_id_t vapi_msg_id_punt_socket_dump;
extern vapi_msg_id_t vapi_msg_id_punt_socket_details;
extern vapi_msg_id_t vapi_msg_id_punt_socket_deregister;
extern vapi_msg_id_t vapi_msg_id_punt_socket_deregister_reply;

#define DEFINE_VAPI_MSG_IDS_PUNT_API_JSON\
  vapi_msg_id_t vapi_msg_id_set_punt;\
  vapi_msg_id_t vapi_msg_id_set_punt_reply;\
  vapi_msg_id_t vapi_msg_id_punt_socket_register;\
  vapi_msg_id_t vapi_msg_id_punt_socket_register_reply;\
  vapi_msg_id_t vapi_msg_id_punt_socket_dump;\
  vapi_msg_id_t vapi_msg_id_punt_socket_details;\
  vapi_msg_id_t vapi_msg_id_punt_socket_deregister;\
  vapi_msg_id_t vapi_msg_id_punt_socket_deregister_reply;


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

#ifndef defined_vapi_enum_punt_type
#define defined_vapi_enum_punt_type
typedef enum {
  PUNT_API_TYPE_L4 = 0,
  PUNT_API_TYPE_IP_PROTO = 1,
  PUNT_API_TYPE_EXCEPTION = 2,
}  vapi_enum_punt_type;

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

#ifndef defined_vapi_type_punt_exception
#define defined_vapi_type_punt_exception
typedef struct __attribute__((__packed__)) {
  u32 id;
} vapi_type_punt_exception;

static inline void vapi_type_punt_exception_hton(vapi_type_punt_exception *msg)
{
  msg->id = htobe32(msg->id);
}

static inline void vapi_type_punt_exception_ntoh(vapi_type_punt_exception *msg)
{
  msg->id = be32toh(msg->id);
}
#endif

#ifndef defined_vapi_type_punt_l4
#define defined_vapi_type_punt_l4
typedef struct __attribute__((__packed__)) {
  vapi_enum_address_family af;
  vapi_enum_ip_proto protocol;
  u16 port;
} vapi_type_punt_l4;

static inline void vapi_type_punt_l4_hton(vapi_type_punt_l4 *msg)
{
  msg->port = htobe16(msg->port);
}

static inline void vapi_type_punt_l4_ntoh(vapi_type_punt_l4 *msg)
{
  msg->port = be16toh(msg->port);
}
#endif

#ifndef defined_vapi_type_punt_ip_proto
#define defined_vapi_type_punt_ip_proto
typedef struct __attribute__((__packed__)) {
  vapi_enum_address_family af;
  vapi_enum_ip_proto protocol;
} vapi_type_punt_ip_proto;

static inline void vapi_type_punt_ip_proto_hton(vapi_type_punt_ip_proto *msg)
{

}

static inline void vapi_type_punt_ip_proto_ntoh(vapi_type_punt_ip_proto *msg)
{

}
#endif

#ifndef defined_vapi_union_punt_union
#define defined_vapi_union_punt_union
typedef union {
  vapi_type_punt_exception exception;
  vapi_type_punt_l4 l4;
  vapi_type_punt_ip_proto ip_proto;
} vapi_union_punt_union;

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

#ifndef defined_vapi_type_punt
#define defined_vapi_type_punt
typedef struct __attribute__((__packed__)) {
  vapi_enum_punt_type type;
  vapi_union_punt_union punt;
} vapi_type_punt;

static inline void vapi_type_punt_hton(vapi_type_punt *msg)
{
  msg->type = (vapi_enum_punt_type)htobe32(msg->type);
}

static inline void vapi_type_punt_ntoh(vapi_type_punt *msg)
{
  msg->type = (vapi_enum_punt_type)be32toh(msg->type);
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

#ifndef defined_vapi_msg_set_punt_reply
#define defined_vapi_msg_set_punt_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_set_punt_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_set_punt_reply payload;
} vapi_msg_set_punt_reply;

static inline void vapi_msg_set_punt_reply_payload_hton(vapi_payload_set_punt_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_set_punt_reply_payload_ntoh(vapi_payload_set_punt_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_set_punt_reply_hton(vapi_msg_set_punt_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_punt_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_set_punt_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_set_punt_reply_ntoh(vapi_msg_set_punt_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_punt_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_set_punt_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_set_punt_reply_msg_size(vapi_msg_set_punt_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_set_punt_reply_msg_size(vapi_msg_set_punt_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_set_punt_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'set_punt_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_set_punt_reply));
      return -1;
    }
  if (vapi_calc_set_punt_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'set_punt_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_set_punt_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_set_punt_reply()
{
  static const char name[] = "set_punt_reply";
  static const char name_with_crc[] = "set_punt_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_set_punt_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_set_punt_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_set_punt_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_set_punt_reply_hton,
    (generic_swap_fn_t)vapi_msg_set_punt_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_set_punt_reply = vapi_register_msg(&__vapi_metadata_set_punt_reply);
  VAPI_DBG("Assigned msg id %d to set_punt_reply", vapi_msg_id_set_punt_reply);
}

static inline void vapi_set_vapi_msg_set_punt_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_set_punt_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_set_punt_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_set_punt
#define defined_vapi_msg_set_punt
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_punt punt; 
} vapi_payload_set_punt;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_set_punt payload;
} vapi_msg_set_punt;

static inline void vapi_msg_set_punt_payload_hton(vapi_payload_set_punt *payload)
{
  vapi_type_punt_hton(&payload->punt);
}

static inline void vapi_msg_set_punt_payload_ntoh(vapi_payload_set_punt *payload)
{
  vapi_type_punt_ntoh(&payload->punt);
}

static inline void vapi_msg_set_punt_hton(vapi_msg_set_punt *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_punt'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_set_punt_payload_hton(&msg->payload);
}

static inline void vapi_msg_set_punt_ntoh(vapi_msg_set_punt *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_punt'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_set_punt_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_set_punt_msg_size(vapi_msg_set_punt *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_set_punt_msg_size(vapi_msg_set_punt *msg, uword buf_size)
{
  if (sizeof(vapi_msg_set_punt) > buf_size)
    {
      VAPI_ERR("Truncated 'set_punt' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_set_punt));
      return -1;
    }
  if (vapi_calc_set_punt_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'set_punt' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_set_punt_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_set_punt* vapi_alloc_set_punt(struct vapi_ctx_s *ctx)
{
  vapi_msg_set_punt *msg = NULL;
  const size_t size = sizeof(vapi_msg_set_punt);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_set_punt*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_set_punt);

  return msg;
}

static inline vapi_error_e vapi_set_punt(struct vapi_ctx_s *ctx,
  vapi_msg_set_punt *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_set_punt_reply *reply),
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
  vapi_msg_set_punt_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_set_punt_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_set_punt_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_set_punt()
{
  static const char name[] = "set_punt";
  static const char name_with_crc[] = "set_punt_47d0e347";
  static vapi_message_desc_t __vapi_metadata_set_punt = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_set_punt, payload),
    (verify_msg_size_fn_t)vapi_verify_set_punt_msg_size,
    (generic_swap_fn_t)vapi_msg_set_punt_hton,
    (generic_swap_fn_t)vapi_msg_set_punt_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_set_punt = vapi_register_msg(&__vapi_metadata_set_punt);
  VAPI_DBG("Assigned msg id %d to set_punt", vapi_msg_id_set_punt);
}
#endif

#ifndef defined_vapi_msg_punt_socket_register_reply
#define defined_vapi_msg_punt_socket_register_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u8 pathname[108]; 
} vapi_payload_punt_socket_register_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_punt_socket_register_reply payload;
} vapi_msg_punt_socket_register_reply;

static inline void vapi_msg_punt_socket_register_reply_payload_hton(vapi_payload_punt_socket_register_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_punt_socket_register_reply_payload_ntoh(vapi_payload_punt_socket_register_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_punt_socket_register_reply_hton(vapi_msg_punt_socket_register_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_punt_socket_register_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_punt_socket_register_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_punt_socket_register_reply_ntoh(vapi_msg_punt_socket_register_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_punt_socket_register_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_punt_socket_register_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_punt_socket_register_reply_msg_size(vapi_msg_punt_socket_register_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_punt_socket_register_reply_msg_size(vapi_msg_punt_socket_register_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_punt_socket_register_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'punt_socket_register_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_punt_socket_register_reply));
      return -1;
    }
  if (vapi_calc_punt_socket_register_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'punt_socket_register_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_punt_socket_register_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_punt_socket_register_reply()
{
  static const char name[] = "punt_socket_register_reply";
  static const char name_with_crc[] = "punt_socket_register_reply_bd30ae90";
  static vapi_message_desc_t __vapi_metadata_punt_socket_register_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_punt_socket_register_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_punt_socket_register_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_punt_socket_register_reply_hton,
    (generic_swap_fn_t)vapi_msg_punt_socket_register_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_punt_socket_register_reply = vapi_register_msg(&__vapi_metadata_punt_socket_register_reply);
  VAPI_DBG("Assigned msg id %d to punt_socket_register_reply", vapi_msg_id_punt_socket_register_reply);
}

static inline void vapi_set_vapi_msg_punt_socket_register_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_punt_socket_register_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_punt_socket_register_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_punt_socket_register
#define defined_vapi_msg_punt_socket_register
typedef struct __attribute__ ((__packed__)) {
  u32 header_version;
  vapi_type_punt punt;
  u8 pathname[108]; 
} vapi_payload_punt_socket_register;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_punt_socket_register payload;
} vapi_msg_punt_socket_register;

static inline void vapi_msg_punt_socket_register_payload_hton(vapi_payload_punt_socket_register *payload)
{
  payload->header_version = htobe32(payload->header_version);
  vapi_type_punt_hton(&payload->punt);
}

static inline void vapi_msg_punt_socket_register_payload_ntoh(vapi_payload_punt_socket_register *payload)
{
  payload->header_version = be32toh(payload->header_version);
  vapi_type_punt_ntoh(&payload->punt);
}

static inline void vapi_msg_punt_socket_register_hton(vapi_msg_punt_socket_register *msg)
{
  VAPI_DBG("Swapping `vapi_msg_punt_socket_register'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_punt_socket_register_payload_hton(&msg->payload);
}

static inline void vapi_msg_punt_socket_register_ntoh(vapi_msg_punt_socket_register *msg)
{
  VAPI_DBG("Swapping `vapi_msg_punt_socket_register'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_punt_socket_register_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_punt_socket_register_msg_size(vapi_msg_punt_socket_register *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_punt_socket_register_msg_size(vapi_msg_punt_socket_register *msg, uword buf_size)
{
  if (sizeof(vapi_msg_punt_socket_register) > buf_size)
    {
      VAPI_ERR("Truncated 'punt_socket_register' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_punt_socket_register));
      return -1;
    }
  if (vapi_calc_punt_socket_register_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'punt_socket_register' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_punt_socket_register_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_punt_socket_register* vapi_alloc_punt_socket_register(struct vapi_ctx_s *ctx)
{
  vapi_msg_punt_socket_register *msg = NULL;
  const size_t size = sizeof(vapi_msg_punt_socket_register);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_punt_socket_register*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_punt_socket_register);

  return msg;
}

static inline vapi_error_e vapi_punt_socket_register(struct vapi_ctx_s *ctx,
  vapi_msg_punt_socket_register *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_punt_socket_register_reply *reply),
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
  vapi_msg_punt_socket_register_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_punt_socket_register_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_punt_socket_register_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_punt_socket_register()
{
  static const char name[] = "punt_socket_register";
  static const char name_with_crc[] = "punt_socket_register_7875badb";
  static vapi_message_desc_t __vapi_metadata_punt_socket_register = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_punt_socket_register, payload),
    (verify_msg_size_fn_t)vapi_verify_punt_socket_register_msg_size,
    (generic_swap_fn_t)vapi_msg_punt_socket_register_hton,
    (generic_swap_fn_t)vapi_msg_punt_socket_register_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_punt_socket_register = vapi_register_msg(&__vapi_metadata_punt_socket_register);
  VAPI_DBG("Assigned msg id %d to punt_socket_register", vapi_msg_id_punt_socket_register);
}
#endif

#ifndef defined_vapi_msg_punt_socket_details
#define defined_vapi_msg_punt_socket_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_punt punt;
  u8 pathname[108]; 
} vapi_payload_punt_socket_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_punt_socket_details payload;
} vapi_msg_punt_socket_details;

static inline void vapi_msg_punt_socket_details_payload_hton(vapi_payload_punt_socket_details *payload)
{
  vapi_type_punt_hton(&payload->punt);
}

static inline void vapi_msg_punt_socket_details_payload_ntoh(vapi_payload_punt_socket_details *payload)
{
  vapi_type_punt_ntoh(&payload->punt);
}

static inline void vapi_msg_punt_socket_details_hton(vapi_msg_punt_socket_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_punt_socket_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_punt_socket_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_punt_socket_details_ntoh(vapi_msg_punt_socket_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_punt_socket_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_punt_socket_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_punt_socket_details_msg_size(vapi_msg_punt_socket_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_punt_socket_details_msg_size(vapi_msg_punt_socket_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_punt_socket_details) > buf_size)
    {
      VAPI_ERR("Truncated 'punt_socket_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_punt_socket_details));
      return -1;
    }
  if (vapi_calc_punt_socket_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'punt_socket_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_punt_socket_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_punt_socket_details()
{
  static const char name[] = "punt_socket_details";
  static const char name_with_crc[] = "punt_socket_details_330466e4";
  static vapi_message_desc_t __vapi_metadata_punt_socket_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_punt_socket_details, payload),
    (verify_msg_size_fn_t)vapi_verify_punt_socket_details_msg_size,
    (generic_swap_fn_t)vapi_msg_punt_socket_details_hton,
    (generic_swap_fn_t)vapi_msg_punt_socket_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_punt_socket_details = vapi_register_msg(&__vapi_metadata_punt_socket_details);
  VAPI_DBG("Assigned msg id %d to punt_socket_details", vapi_msg_id_punt_socket_details);
}

static inline void vapi_set_vapi_msg_punt_socket_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_punt_socket_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_punt_socket_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_punt_socket_dump
#define defined_vapi_msg_punt_socket_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_punt_type type; 
} vapi_payload_punt_socket_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_punt_socket_dump payload;
} vapi_msg_punt_socket_dump;

static inline void vapi_msg_punt_socket_dump_payload_hton(vapi_payload_punt_socket_dump *payload)
{
  payload->type = (vapi_enum_punt_type)htobe32(payload->type);
}

static inline void vapi_msg_punt_socket_dump_payload_ntoh(vapi_payload_punt_socket_dump *payload)
{
  payload->type = (vapi_enum_punt_type)be32toh(payload->type);
}

static inline void vapi_msg_punt_socket_dump_hton(vapi_msg_punt_socket_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_punt_socket_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_punt_socket_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_punt_socket_dump_ntoh(vapi_msg_punt_socket_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_punt_socket_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_punt_socket_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_punt_socket_dump_msg_size(vapi_msg_punt_socket_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_punt_socket_dump_msg_size(vapi_msg_punt_socket_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_punt_socket_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'punt_socket_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_punt_socket_dump));
      return -1;
    }
  if (vapi_calc_punt_socket_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'punt_socket_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_punt_socket_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_punt_socket_dump* vapi_alloc_punt_socket_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_punt_socket_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_punt_socket_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_punt_socket_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_punt_socket_dump);

  return msg;
}

static inline vapi_error_e vapi_punt_socket_dump(struct vapi_ctx_s *ctx,
  vapi_msg_punt_socket_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_punt_socket_details *reply),
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
  vapi_msg_punt_socket_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_punt_socket_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_punt_socket_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_punt_socket_dump()
{
  static const char name[] = "punt_socket_dump";
  static const char name_with_crc[] = "punt_socket_dump_916fb004";
  static vapi_message_desc_t __vapi_metadata_punt_socket_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_punt_socket_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_punt_socket_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_punt_socket_dump_hton,
    (generic_swap_fn_t)vapi_msg_punt_socket_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_punt_socket_dump = vapi_register_msg(&__vapi_metadata_punt_socket_dump);
  VAPI_DBG("Assigned msg id %d to punt_socket_dump", vapi_msg_id_punt_socket_dump);
}
#endif

#ifndef defined_vapi_msg_punt_socket_deregister_reply
#define defined_vapi_msg_punt_socket_deregister_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_punt_socket_deregister_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_punt_socket_deregister_reply payload;
} vapi_msg_punt_socket_deregister_reply;

static inline void vapi_msg_punt_socket_deregister_reply_payload_hton(vapi_payload_punt_socket_deregister_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_punt_socket_deregister_reply_payload_ntoh(vapi_payload_punt_socket_deregister_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_punt_socket_deregister_reply_hton(vapi_msg_punt_socket_deregister_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_punt_socket_deregister_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_punt_socket_deregister_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_punt_socket_deregister_reply_ntoh(vapi_msg_punt_socket_deregister_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_punt_socket_deregister_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_punt_socket_deregister_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_punt_socket_deregister_reply_msg_size(vapi_msg_punt_socket_deregister_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_punt_socket_deregister_reply_msg_size(vapi_msg_punt_socket_deregister_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_punt_socket_deregister_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'punt_socket_deregister_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_punt_socket_deregister_reply));
      return -1;
    }
  if (vapi_calc_punt_socket_deregister_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'punt_socket_deregister_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_punt_socket_deregister_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_punt_socket_deregister_reply()
{
  static const char name[] = "punt_socket_deregister_reply";
  static const char name_with_crc[] = "punt_socket_deregister_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_punt_socket_deregister_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_punt_socket_deregister_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_punt_socket_deregister_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_punt_socket_deregister_reply_hton,
    (generic_swap_fn_t)vapi_msg_punt_socket_deregister_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_punt_socket_deregister_reply = vapi_register_msg(&__vapi_metadata_punt_socket_deregister_reply);
  VAPI_DBG("Assigned msg id %d to punt_socket_deregister_reply", vapi_msg_id_punt_socket_deregister_reply);
}

static inline void vapi_set_vapi_msg_punt_socket_deregister_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_punt_socket_deregister_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_punt_socket_deregister_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_punt_socket_deregister
#define defined_vapi_msg_punt_socket_deregister
typedef struct __attribute__ ((__packed__)) {
  vapi_type_punt punt; 
} vapi_payload_punt_socket_deregister;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_punt_socket_deregister payload;
} vapi_msg_punt_socket_deregister;

static inline void vapi_msg_punt_socket_deregister_payload_hton(vapi_payload_punt_socket_deregister *payload)
{
  vapi_type_punt_hton(&payload->punt);
}

static inline void vapi_msg_punt_socket_deregister_payload_ntoh(vapi_payload_punt_socket_deregister *payload)
{
  vapi_type_punt_ntoh(&payload->punt);
}

static inline void vapi_msg_punt_socket_deregister_hton(vapi_msg_punt_socket_deregister *msg)
{
  VAPI_DBG("Swapping `vapi_msg_punt_socket_deregister'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_punt_socket_deregister_payload_hton(&msg->payload);
}

static inline void vapi_msg_punt_socket_deregister_ntoh(vapi_msg_punt_socket_deregister *msg)
{
  VAPI_DBG("Swapping `vapi_msg_punt_socket_deregister'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_punt_socket_deregister_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_punt_socket_deregister_msg_size(vapi_msg_punt_socket_deregister *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_punt_socket_deregister_msg_size(vapi_msg_punt_socket_deregister *msg, uword buf_size)
{
  if (sizeof(vapi_msg_punt_socket_deregister) > buf_size)
    {
      VAPI_ERR("Truncated 'punt_socket_deregister' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_punt_socket_deregister));
      return -1;
    }
  if (vapi_calc_punt_socket_deregister_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'punt_socket_deregister' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_punt_socket_deregister_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_punt_socket_deregister* vapi_alloc_punt_socket_deregister(struct vapi_ctx_s *ctx)
{
  vapi_msg_punt_socket_deregister *msg = NULL;
  const size_t size = sizeof(vapi_msg_punt_socket_deregister);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_punt_socket_deregister*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_punt_socket_deregister);

  return msg;
}

static inline vapi_error_e vapi_punt_socket_deregister(struct vapi_ctx_s *ctx,
  vapi_msg_punt_socket_deregister *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_punt_socket_deregister_reply *reply),
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
  vapi_msg_punt_socket_deregister_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_punt_socket_deregister_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_punt_socket_deregister_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_punt_socket_deregister()
{
  static const char name[] = "punt_socket_deregister";
  static const char name_with_crc[] = "punt_socket_deregister_75afa766";
  static vapi_message_desc_t __vapi_metadata_punt_socket_deregister = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_punt_socket_deregister, payload),
    (verify_msg_size_fn_t)vapi_verify_punt_socket_deregister_msg_size,
    (generic_swap_fn_t)vapi_msg_punt_socket_deregister_hton,
    (generic_swap_fn_t)vapi_msg_punt_socket_deregister_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_punt_socket_deregister = vapi_register_msg(&__vapi_metadata_punt_socket_deregister);
  VAPI_DBG("Assigned msg id %d to punt_socket_deregister", vapi_msg_id_punt_socket_deregister);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
