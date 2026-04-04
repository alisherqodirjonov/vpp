#ifndef __included_lcp_api_json
#define __included_lcp_api_json

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

extern vapi_msg_id_t vapi_msg_id_lcp_default_ns_set;
extern vapi_msg_id_t vapi_msg_id_lcp_default_ns_set_reply;
extern vapi_msg_id_t vapi_msg_id_lcp_default_ns_get;
extern vapi_msg_id_t vapi_msg_id_lcp_default_ns_get_reply;
extern vapi_msg_id_t vapi_msg_id_lcp_itf_pair_add_del;
extern vapi_msg_id_t vapi_msg_id_lcp_itf_pair_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_lcp_itf_pair_add_del_v2;
extern vapi_msg_id_t vapi_msg_id_lcp_itf_pair_add_del_v2_reply;
extern vapi_msg_id_t vapi_msg_id_lcp_itf_pair_add_del_v3;
extern vapi_msg_id_t vapi_msg_id_lcp_itf_pair_add_del_v3_reply;
extern vapi_msg_id_t vapi_msg_id_lcp_itf_pair_get;
extern vapi_msg_id_t vapi_msg_id_lcp_itf_pair_get_reply;
extern vapi_msg_id_t vapi_msg_id_lcp_itf_pair_get_v2;
extern vapi_msg_id_t vapi_msg_id_lcp_itf_pair_get_v2_reply;
extern vapi_msg_id_t vapi_msg_id_lcp_itf_pair_details;
extern vapi_msg_id_t vapi_msg_id_lcp_ethertype_enable;
extern vapi_msg_id_t vapi_msg_id_lcp_ethertype_enable_reply;
extern vapi_msg_id_t vapi_msg_id_lcp_ethertype_get;
extern vapi_msg_id_t vapi_msg_id_lcp_ethertype_get_reply;
extern vapi_msg_id_t vapi_msg_id_lcp_itf_pair_replace_begin;
extern vapi_msg_id_t vapi_msg_id_lcp_itf_pair_replace_begin_reply;
extern vapi_msg_id_t vapi_msg_id_lcp_itf_pair_replace_end;
extern vapi_msg_id_t vapi_msg_id_lcp_itf_pair_replace_end_reply;

#define DEFINE_VAPI_MSG_IDS_LCP_API_JSON\
  vapi_msg_id_t vapi_msg_id_lcp_default_ns_set;\
  vapi_msg_id_t vapi_msg_id_lcp_default_ns_set_reply;\
  vapi_msg_id_t vapi_msg_id_lcp_default_ns_get;\
  vapi_msg_id_t vapi_msg_id_lcp_default_ns_get_reply;\
  vapi_msg_id_t vapi_msg_id_lcp_itf_pair_add_del;\
  vapi_msg_id_t vapi_msg_id_lcp_itf_pair_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_lcp_itf_pair_add_del_v2;\
  vapi_msg_id_t vapi_msg_id_lcp_itf_pair_add_del_v2_reply;\
  vapi_msg_id_t vapi_msg_id_lcp_itf_pair_add_del_v3;\
  vapi_msg_id_t vapi_msg_id_lcp_itf_pair_add_del_v3_reply;\
  vapi_msg_id_t vapi_msg_id_lcp_itf_pair_get;\
  vapi_msg_id_t vapi_msg_id_lcp_itf_pair_get_reply;\
  vapi_msg_id_t vapi_msg_id_lcp_itf_pair_get_v2;\
  vapi_msg_id_t vapi_msg_id_lcp_itf_pair_get_v2_reply;\
  vapi_msg_id_t vapi_msg_id_lcp_itf_pair_details;\
  vapi_msg_id_t vapi_msg_id_lcp_ethertype_enable;\
  vapi_msg_id_t vapi_msg_id_lcp_ethertype_enable_reply;\
  vapi_msg_id_t vapi_msg_id_lcp_ethertype_get;\
  vapi_msg_id_t vapi_msg_id_lcp_ethertype_get_reply;\
  vapi_msg_id_t vapi_msg_id_lcp_itf_pair_replace_begin;\
  vapi_msg_id_t vapi_msg_id_lcp_itf_pair_replace_begin_reply;\
  vapi_msg_id_t vapi_msg_id_lcp_itf_pair_replace_end;\
  vapi_msg_id_t vapi_msg_id_lcp_itf_pair_replace_end_reply;


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

#ifndef defined_vapi_enum_lcp_itf_host_type
#define defined_vapi_enum_lcp_itf_host_type
typedef enum {
  LCP_API_ITF_HOST_TAP = 0,
  LCP_API_ITF_HOST_TUN = 1,
} __attribute__((packed)) vapi_enum_lcp_itf_host_type;

#endif

#ifndef defined_vapi_type_interface_index
#define defined_vapi_type_interface_index
typedef u32 vapi_type_interface_index;

#endif

#ifndef defined_vapi_msg_lcp_default_ns_set_reply
#define defined_vapi_msg_lcp_default_ns_set_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lcp_default_ns_set_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lcp_default_ns_set_reply payload;
} vapi_msg_lcp_default_ns_set_reply;

static inline void vapi_msg_lcp_default_ns_set_reply_payload_hton(vapi_payload_lcp_default_ns_set_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lcp_default_ns_set_reply_payload_ntoh(vapi_payload_lcp_default_ns_set_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lcp_default_ns_set_reply_hton(vapi_msg_lcp_default_ns_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_default_ns_set_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lcp_default_ns_set_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lcp_default_ns_set_reply_ntoh(vapi_msg_lcp_default_ns_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_default_ns_set_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lcp_default_ns_set_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lcp_default_ns_set_reply_msg_size(vapi_msg_lcp_default_ns_set_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_default_ns_set_reply_msg_size(vapi_msg_lcp_default_ns_set_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_default_ns_set_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_default_ns_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_default_ns_set_reply));
      return -1;
    }
  if (vapi_calc_lcp_default_ns_set_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_default_ns_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_default_ns_set_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lcp_default_ns_set_reply()
{
  static const char name[] = "lcp_default_ns_set_reply";
  static const char name_with_crc[] = "lcp_default_ns_set_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lcp_default_ns_set_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lcp_default_ns_set_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lcp_default_ns_set_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_default_ns_set_reply_hton,
    (generic_swap_fn_t)vapi_msg_lcp_default_ns_set_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_default_ns_set_reply = vapi_register_msg(&__vapi_metadata_lcp_default_ns_set_reply);
  VAPI_DBG("Assigned msg id %d to lcp_default_ns_set_reply", vapi_msg_id_lcp_default_ns_set_reply);
}

static inline void vapi_set_vapi_msg_lcp_default_ns_set_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lcp_default_ns_set_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lcp_default_ns_set_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lcp_default_ns_set
#define defined_vapi_msg_lcp_default_ns_set
typedef struct __attribute__ ((__packed__)) {
  u8 netns[32]; 
} vapi_payload_lcp_default_ns_set;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lcp_default_ns_set payload;
} vapi_msg_lcp_default_ns_set;

static inline void vapi_msg_lcp_default_ns_set_payload_hton(vapi_payload_lcp_default_ns_set *payload)
{

}

static inline void vapi_msg_lcp_default_ns_set_payload_ntoh(vapi_payload_lcp_default_ns_set *payload)
{

}

static inline void vapi_msg_lcp_default_ns_set_hton(vapi_msg_lcp_default_ns_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_default_ns_set'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lcp_default_ns_set_payload_hton(&msg->payload);
}

static inline void vapi_msg_lcp_default_ns_set_ntoh(vapi_msg_lcp_default_ns_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_default_ns_set'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lcp_default_ns_set_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lcp_default_ns_set_msg_size(vapi_msg_lcp_default_ns_set *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_default_ns_set_msg_size(vapi_msg_lcp_default_ns_set *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_default_ns_set) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_default_ns_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_default_ns_set));
      return -1;
    }
  if (vapi_calc_lcp_default_ns_set_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_default_ns_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_default_ns_set_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lcp_default_ns_set* vapi_alloc_lcp_default_ns_set(struct vapi_ctx_s *ctx)
{
  vapi_msg_lcp_default_ns_set *msg = NULL;
  const size_t size = sizeof(vapi_msg_lcp_default_ns_set);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lcp_default_ns_set*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lcp_default_ns_set);

  return msg;
}

static inline vapi_error_e vapi_lcp_default_ns_set(struct vapi_ctx_s *ctx,
  vapi_msg_lcp_default_ns_set *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lcp_default_ns_set_reply *reply),
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
  vapi_msg_lcp_default_ns_set_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lcp_default_ns_set_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lcp_default_ns_set_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lcp_default_ns_set()
{
  static const char name[] = "lcp_default_ns_set";
  static const char name_with_crc[] = "lcp_default_ns_set_69749409";
  static vapi_message_desc_t __vapi_metadata_lcp_default_ns_set = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lcp_default_ns_set, payload),
    (verify_msg_size_fn_t)vapi_verify_lcp_default_ns_set_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_default_ns_set_hton,
    (generic_swap_fn_t)vapi_msg_lcp_default_ns_set_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_default_ns_set = vapi_register_msg(&__vapi_metadata_lcp_default_ns_set);
  VAPI_DBG("Assigned msg id %d to lcp_default_ns_set", vapi_msg_id_lcp_default_ns_set);
}
#endif

#ifndef defined_vapi_msg_lcp_default_ns_get_reply
#define defined_vapi_msg_lcp_default_ns_get_reply
typedef struct __attribute__ ((__packed__)) {
  u8 netns[32]; 
} vapi_payload_lcp_default_ns_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lcp_default_ns_get_reply payload;
} vapi_msg_lcp_default_ns_get_reply;

static inline void vapi_msg_lcp_default_ns_get_reply_payload_hton(vapi_payload_lcp_default_ns_get_reply *payload)
{

}

static inline void vapi_msg_lcp_default_ns_get_reply_payload_ntoh(vapi_payload_lcp_default_ns_get_reply *payload)
{

}

static inline void vapi_msg_lcp_default_ns_get_reply_hton(vapi_msg_lcp_default_ns_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_default_ns_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lcp_default_ns_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lcp_default_ns_get_reply_ntoh(vapi_msg_lcp_default_ns_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_default_ns_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lcp_default_ns_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lcp_default_ns_get_reply_msg_size(vapi_msg_lcp_default_ns_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_default_ns_get_reply_msg_size(vapi_msg_lcp_default_ns_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_default_ns_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_default_ns_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_default_ns_get_reply));
      return -1;
    }
  if (vapi_calc_lcp_default_ns_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_default_ns_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_default_ns_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lcp_default_ns_get_reply()
{
  static const char name[] = "lcp_default_ns_get_reply";
  static const char name_with_crc[] = "lcp_default_ns_get_reply_5102feee";
  static vapi_message_desc_t __vapi_metadata_lcp_default_ns_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lcp_default_ns_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lcp_default_ns_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_default_ns_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_lcp_default_ns_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_default_ns_get_reply = vapi_register_msg(&__vapi_metadata_lcp_default_ns_get_reply);
  VAPI_DBG("Assigned msg id %d to lcp_default_ns_get_reply", vapi_msg_id_lcp_default_ns_get_reply);
}

static inline void vapi_set_vapi_msg_lcp_default_ns_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lcp_default_ns_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lcp_default_ns_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lcp_default_ns_get
#define defined_vapi_msg_lcp_default_ns_get
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_lcp_default_ns_get;

static inline void vapi_msg_lcp_default_ns_get_hton(vapi_msg_lcp_default_ns_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_default_ns_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_lcp_default_ns_get_ntoh(vapi_msg_lcp_default_ns_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_default_ns_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_lcp_default_ns_get_msg_size(vapi_msg_lcp_default_ns_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_default_ns_get_msg_size(vapi_msg_lcp_default_ns_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_default_ns_get) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_default_ns_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_default_ns_get));
      return -1;
    }
  if (vapi_calc_lcp_default_ns_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_default_ns_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_default_ns_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lcp_default_ns_get* vapi_alloc_lcp_default_ns_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_lcp_default_ns_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_lcp_default_ns_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lcp_default_ns_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lcp_default_ns_get);

  return msg;
}

static inline vapi_error_e vapi_lcp_default_ns_get(struct vapi_ctx_s *ctx,
  vapi_msg_lcp_default_ns_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lcp_default_ns_get_reply *reply),
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
  vapi_msg_lcp_default_ns_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lcp_default_ns_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lcp_default_ns_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lcp_default_ns_get()
{
  static const char name[] = "lcp_default_ns_get";
  static const char name_with_crc[] = "lcp_default_ns_get_51077d14";
  static vapi_message_desc_t __vapi_metadata_lcp_default_ns_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_lcp_default_ns_get_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_default_ns_get_hton,
    (generic_swap_fn_t)vapi_msg_lcp_default_ns_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_default_ns_get = vapi_register_msg(&__vapi_metadata_lcp_default_ns_get);
  VAPI_DBG("Assigned msg id %d to lcp_default_ns_get", vapi_msg_id_lcp_default_ns_get);
}
#endif

#ifndef defined_vapi_msg_lcp_itf_pair_add_del_reply
#define defined_vapi_msg_lcp_itf_pair_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lcp_itf_pair_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lcp_itf_pair_add_del_reply payload;
} vapi_msg_lcp_itf_pair_add_del_reply;

static inline void vapi_msg_lcp_itf_pair_add_del_reply_payload_hton(vapi_payload_lcp_itf_pair_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lcp_itf_pair_add_del_reply_payload_ntoh(vapi_payload_lcp_itf_pair_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lcp_itf_pair_add_del_reply_hton(vapi_msg_lcp_itf_pair_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lcp_itf_pair_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lcp_itf_pair_add_del_reply_ntoh(vapi_msg_lcp_itf_pair_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lcp_itf_pair_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lcp_itf_pair_add_del_reply_msg_size(vapi_msg_lcp_itf_pair_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_itf_pair_add_del_reply_msg_size(vapi_msg_lcp_itf_pair_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_itf_pair_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_itf_pair_add_del_reply));
      return -1;
    }
  if (vapi_calc_lcp_itf_pair_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_itf_pair_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lcp_itf_pair_add_del_reply()
{
  static const char name[] = "lcp_itf_pair_add_del_reply";
  static const char name_with_crc[] = "lcp_itf_pair_add_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lcp_itf_pair_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lcp_itf_pair_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lcp_itf_pair_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_itf_pair_add_del_reply = vapi_register_msg(&__vapi_metadata_lcp_itf_pair_add_del_reply);
  VAPI_DBG("Assigned msg id %d to lcp_itf_pair_add_del_reply", vapi_msg_id_lcp_itf_pair_add_del_reply);
}

static inline void vapi_set_vapi_msg_lcp_itf_pair_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lcp_itf_pair_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lcp_itf_pair_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lcp_itf_pair_add_del
#define defined_vapi_msg_lcp_itf_pair_add_del
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_interface_index sw_if_index;
  u8 host_if_name[16];
  vapi_enum_lcp_itf_host_type host_if_type;
  u8 netns[32]; 
} vapi_payload_lcp_itf_pair_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lcp_itf_pair_add_del payload;
} vapi_msg_lcp_itf_pair_add_del;

static inline void vapi_msg_lcp_itf_pair_add_del_payload_hton(vapi_payload_lcp_itf_pair_add_del *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_lcp_itf_pair_add_del_payload_ntoh(vapi_payload_lcp_itf_pair_add_del *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_lcp_itf_pair_add_del_hton(vapi_msg_lcp_itf_pair_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lcp_itf_pair_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_lcp_itf_pair_add_del_ntoh(vapi_msg_lcp_itf_pair_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lcp_itf_pair_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lcp_itf_pair_add_del_msg_size(vapi_msg_lcp_itf_pair_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_itf_pair_add_del_msg_size(vapi_msg_lcp_itf_pair_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_itf_pair_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_itf_pair_add_del));
      return -1;
    }
  if (vapi_calc_lcp_itf_pair_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_itf_pair_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lcp_itf_pair_add_del* vapi_alloc_lcp_itf_pair_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_lcp_itf_pair_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_lcp_itf_pair_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lcp_itf_pair_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lcp_itf_pair_add_del);

  return msg;
}

static inline vapi_error_e vapi_lcp_itf_pair_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_lcp_itf_pair_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lcp_itf_pair_add_del_reply *reply),
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
  vapi_msg_lcp_itf_pair_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lcp_itf_pair_add_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lcp_itf_pair_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lcp_itf_pair_add_del()
{
  static const char name[] = "lcp_itf_pair_add_del";
  static const char name_with_crc[] = "lcp_itf_pair_add_del_40482b80";
  static vapi_message_desc_t __vapi_metadata_lcp_itf_pair_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lcp_itf_pair_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_lcp_itf_pair_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_add_del_hton,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_itf_pair_add_del = vapi_register_msg(&__vapi_metadata_lcp_itf_pair_add_del);
  VAPI_DBG("Assigned msg id %d to lcp_itf_pair_add_del", vapi_msg_id_lcp_itf_pair_add_del);
}
#endif

#ifndef defined_vapi_msg_lcp_itf_pair_add_del_v2_reply
#define defined_vapi_msg_lcp_itf_pair_add_del_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_interface_index host_sw_if_index; 
} vapi_payload_lcp_itf_pair_add_del_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lcp_itf_pair_add_del_v2_reply payload;
} vapi_msg_lcp_itf_pair_add_del_v2_reply;

static inline void vapi_msg_lcp_itf_pair_add_del_v2_reply_payload_hton(vapi_payload_lcp_itf_pair_add_del_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->host_sw_if_index = htobe32(payload->host_sw_if_index);
}

static inline void vapi_msg_lcp_itf_pair_add_del_v2_reply_payload_ntoh(vapi_payload_lcp_itf_pair_add_del_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->host_sw_if_index = be32toh(payload->host_sw_if_index);
}

static inline void vapi_msg_lcp_itf_pair_add_del_v2_reply_hton(vapi_msg_lcp_itf_pair_add_del_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_add_del_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lcp_itf_pair_add_del_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lcp_itf_pair_add_del_v2_reply_ntoh(vapi_msg_lcp_itf_pair_add_del_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_add_del_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lcp_itf_pair_add_del_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lcp_itf_pair_add_del_v2_reply_msg_size(vapi_msg_lcp_itf_pair_add_del_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_itf_pair_add_del_v2_reply_msg_size(vapi_msg_lcp_itf_pair_add_del_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_itf_pair_add_del_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_add_del_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_itf_pair_add_del_v2_reply));
      return -1;
    }
  if (vapi_calc_lcp_itf_pair_add_del_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_add_del_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_itf_pair_add_del_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lcp_itf_pair_add_del_v2_reply()
{
  static const char name[] = "lcp_itf_pair_add_del_v2_reply";
  static const char name_with_crc[] = "lcp_itf_pair_add_del_v2_reply_39452f52";
  static vapi_message_desc_t __vapi_metadata_lcp_itf_pair_add_del_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lcp_itf_pair_add_del_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lcp_itf_pair_add_del_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_add_del_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_add_del_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_itf_pair_add_del_v2_reply = vapi_register_msg(&__vapi_metadata_lcp_itf_pair_add_del_v2_reply);
  VAPI_DBG("Assigned msg id %d to lcp_itf_pair_add_del_v2_reply", vapi_msg_id_lcp_itf_pair_add_del_v2_reply);
}

static inline void vapi_set_vapi_msg_lcp_itf_pair_add_del_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lcp_itf_pair_add_del_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lcp_itf_pair_add_del_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lcp_itf_pair_add_del_v2
#define defined_vapi_msg_lcp_itf_pair_add_del_v2
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_interface_index sw_if_index;
  u8 host_if_name[16];
  vapi_enum_lcp_itf_host_type host_if_type;
  u8 netns[32]; 
} vapi_payload_lcp_itf_pair_add_del_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lcp_itf_pair_add_del_v2 payload;
} vapi_msg_lcp_itf_pair_add_del_v2;

static inline void vapi_msg_lcp_itf_pair_add_del_v2_payload_hton(vapi_payload_lcp_itf_pair_add_del_v2 *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_lcp_itf_pair_add_del_v2_payload_ntoh(vapi_payload_lcp_itf_pair_add_del_v2 *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_lcp_itf_pair_add_del_v2_hton(vapi_msg_lcp_itf_pair_add_del_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_add_del_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lcp_itf_pair_add_del_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_lcp_itf_pair_add_del_v2_ntoh(vapi_msg_lcp_itf_pair_add_del_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_add_del_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lcp_itf_pair_add_del_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lcp_itf_pair_add_del_v2_msg_size(vapi_msg_lcp_itf_pair_add_del_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_itf_pair_add_del_v2_msg_size(vapi_msg_lcp_itf_pair_add_del_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_itf_pair_add_del_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_add_del_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_itf_pair_add_del_v2));
      return -1;
    }
  if (vapi_calc_lcp_itf_pair_add_del_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_add_del_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_itf_pair_add_del_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lcp_itf_pair_add_del_v2* vapi_alloc_lcp_itf_pair_add_del_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_lcp_itf_pair_add_del_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_lcp_itf_pair_add_del_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lcp_itf_pair_add_del_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lcp_itf_pair_add_del_v2);

  return msg;
}

static inline vapi_error_e vapi_lcp_itf_pair_add_del_v2(struct vapi_ctx_s *ctx,
  vapi_msg_lcp_itf_pair_add_del_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lcp_itf_pair_add_del_v2_reply *reply),
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
  vapi_msg_lcp_itf_pair_add_del_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lcp_itf_pair_add_del_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lcp_itf_pair_add_del_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lcp_itf_pair_add_del_v2()
{
  static const char name[] = "lcp_itf_pair_add_del_v2";
  static const char name_with_crc[] = "lcp_itf_pair_add_del_v2_40482b80";
  static vapi_message_desc_t __vapi_metadata_lcp_itf_pair_add_del_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lcp_itf_pair_add_del_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_lcp_itf_pair_add_del_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_add_del_v2_hton,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_add_del_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_itf_pair_add_del_v2 = vapi_register_msg(&__vapi_metadata_lcp_itf_pair_add_del_v2);
  VAPI_DBG("Assigned msg id %d to lcp_itf_pair_add_del_v2", vapi_msg_id_lcp_itf_pair_add_del_v2);
}
#endif

#ifndef defined_vapi_msg_lcp_itf_pair_add_del_v3_reply
#define defined_vapi_msg_lcp_itf_pair_add_del_v3_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 vif_index;
  vapi_type_interface_index host_sw_if_index; 
} vapi_payload_lcp_itf_pair_add_del_v3_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lcp_itf_pair_add_del_v3_reply payload;
} vapi_msg_lcp_itf_pair_add_del_v3_reply;

static inline void vapi_msg_lcp_itf_pair_add_del_v3_reply_payload_hton(vapi_payload_lcp_itf_pair_add_del_v3_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->vif_index = htobe32(payload->vif_index);
  payload->host_sw_if_index = htobe32(payload->host_sw_if_index);
}

static inline void vapi_msg_lcp_itf_pair_add_del_v3_reply_payload_ntoh(vapi_payload_lcp_itf_pair_add_del_v3_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->vif_index = be32toh(payload->vif_index);
  payload->host_sw_if_index = be32toh(payload->host_sw_if_index);
}

static inline void vapi_msg_lcp_itf_pair_add_del_v3_reply_hton(vapi_msg_lcp_itf_pair_add_del_v3_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_add_del_v3_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lcp_itf_pair_add_del_v3_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lcp_itf_pair_add_del_v3_reply_ntoh(vapi_msg_lcp_itf_pair_add_del_v3_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_add_del_v3_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lcp_itf_pair_add_del_v3_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lcp_itf_pair_add_del_v3_reply_msg_size(vapi_msg_lcp_itf_pair_add_del_v3_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_itf_pair_add_del_v3_reply_msg_size(vapi_msg_lcp_itf_pair_add_del_v3_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_itf_pair_add_del_v3_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_add_del_v3_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_itf_pair_add_del_v3_reply));
      return -1;
    }
  if (vapi_calc_lcp_itf_pair_add_del_v3_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_add_del_v3_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_itf_pair_add_del_v3_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lcp_itf_pair_add_del_v3_reply()
{
  static const char name[] = "lcp_itf_pair_add_del_v3_reply";
  static const char name_with_crc[] = "lcp_itf_pair_add_del_v3_reply_c2502663";
  static vapi_message_desc_t __vapi_metadata_lcp_itf_pair_add_del_v3_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lcp_itf_pair_add_del_v3_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lcp_itf_pair_add_del_v3_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_add_del_v3_reply_hton,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_add_del_v3_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_itf_pair_add_del_v3_reply = vapi_register_msg(&__vapi_metadata_lcp_itf_pair_add_del_v3_reply);
  VAPI_DBG("Assigned msg id %d to lcp_itf_pair_add_del_v3_reply", vapi_msg_id_lcp_itf_pair_add_del_v3_reply);
}

static inline void vapi_set_vapi_msg_lcp_itf_pair_add_del_v3_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lcp_itf_pair_add_del_v3_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lcp_itf_pair_add_del_v3_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lcp_itf_pair_add_del_v3
#define defined_vapi_msg_lcp_itf_pair_add_del_v3
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_interface_index sw_if_index;
  u8 host_if_name[16];
  vapi_enum_lcp_itf_host_type host_if_type;
  u8 netns[32]; 
} vapi_payload_lcp_itf_pair_add_del_v3;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lcp_itf_pair_add_del_v3 payload;
} vapi_msg_lcp_itf_pair_add_del_v3;

static inline void vapi_msg_lcp_itf_pair_add_del_v3_payload_hton(vapi_payload_lcp_itf_pair_add_del_v3 *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_lcp_itf_pair_add_del_v3_payload_ntoh(vapi_payload_lcp_itf_pair_add_del_v3 *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_lcp_itf_pair_add_del_v3_hton(vapi_msg_lcp_itf_pair_add_del_v3 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_add_del_v3'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lcp_itf_pair_add_del_v3_payload_hton(&msg->payload);
}

static inline void vapi_msg_lcp_itf_pair_add_del_v3_ntoh(vapi_msg_lcp_itf_pair_add_del_v3 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_add_del_v3'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lcp_itf_pair_add_del_v3_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lcp_itf_pair_add_del_v3_msg_size(vapi_msg_lcp_itf_pair_add_del_v3 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_itf_pair_add_del_v3_msg_size(vapi_msg_lcp_itf_pair_add_del_v3 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_itf_pair_add_del_v3) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_add_del_v3' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_itf_pair_add_del_v3));
      return -1;
    }
  if (vapi_calc_lcp_itf_pair_add_del_v3_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_add_del_v3' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_itf_pair_add_del_v3_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lcp_itf_pair_add_del_v3* vapi_alloc_lcp_itf_pair_add_del_v3(struct vapi_ctx_s *ctx)
{
  vapi_msg_lcp_itf_pair_add_del_v3 *msg = NULL;
  const size_t size = sizeof(vapi_msg_lcp_itf_pair_add_del_v3);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lcp_itf_pair_add_del_v3*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lcp_itf_pair_add_del_v3);

  return msg;
}

static inline vapi_error_e vapi_lcp_itf_pair_add_del_v3(struct vapi_ctx_s *ctx,
  vapi_msg_lcp_itf_pair_add_del_v3 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lcp_itf_pair_add_del_v3_reply *reply),
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
  vapi_msg_lcp_itf_pair_add_del_v3_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lcp_itf_pair_add_del_v3_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lcp_itf_pair_add_del_v3_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lcp_itf_pair_add_del_v3()
{
  static const char name[] = "lcp_itf_pair_add_del_v3";
  static const char name_with_crc[] = "lcp_itf_pair_add_del_v3_40482b80";
  static vapi_message_desc_t __vapi_metadata_lcp_itf_pair_add_del_v3 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lcp_itf_pair_add_del_v3, payload),
    (verify_msg_size_fn_t)vapi_verify_lcp_itf_pair_add_del_v3_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_add_del_v3_hton,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_add_del_v3_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_itf_pair_add_del_v3 = vapi_register_msg(&__vapi_metadata_lcp_itf_pair_add_del_v3);
  VAPI_DBG("Assigned msg id %d to lcp_itf_pair_add_del_v3", vapi_msg_id_lcp_itf_pair_add_del_v3);
}
#endif

#ifndef defined_vapi_msg_lcp_itf_pair_get_reply
#define defined_vapi_msg_lcp_itf_pair_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 cursor; 
} vapi_payload_lcp_itf_pair_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lcp_itf_pair_get_reply payload;
} vapi_msg_lcp_itf_pair_get_reply;

static inline void vapi_msg_lcp_itf_pair_get_reply_payload_hton(vapi_payload_lcp_itf_pair_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_lcp_itf_pair_get_reply_payload_ntoh(vapi_payload_lcp_itf_pair_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_lcp_itf_pair_get_reply_hton(vapi_msg_lcp_itf_pair_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lcp_itf_pair_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lcp_itf_pair_get_reply_ntoh(vapi_msg_lcp_itf_pair_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lcp_itf_pair_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lcp_itf_pair_get_reply_msg_size(vapi_msg_lcp_itf_pair_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_itf_pair_get_reply_msg_size(vapi_msg_lcp_itf_pair_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_itf_pair_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_itf_pair_get_reply));
      return -1;
    }
  if (vapi_calc_lcp_itf_pair_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_itf_pair_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lcp_itf_pair_get_reply()
{
  static const char name[] = "lcp_itf_pair_get_reply";
  static const char name_with_crc[] = "lcp_itf_pair_get_reply_53b48f5d";
  static vapi_message_desc_t __vapi_metadata_lcp_itf_pair_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lcp_itf_pair_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lcp_itf_pair_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_itf_pair_get_reply = vapi_register_msg(&__vapi_metadata_lcp_itf_pair_get_reply);
  VAPI_DBG("Assigned msg id %d to lcp_itf_pair_get_reply", vapi_msg_id_lcp_itf_pair_get_reply);
}

static inline void vapi_set_vapi_msg_lcp_itf_pair_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lcp_itf_pair_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lcp_itf_pair_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lcp_itf_pair_details
#define defined_vapi_msg_lcp_itf_pair_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index phy_sw_if_index;
  vapi_type_interface_index host_sw_if_index;
  u32 vif_index;
  u8 host_if_name[16];
  vapi_enum_lcp_itf_host_type host_if_type;
  u8 netns[32]; 
} vapi_payload_lcp_itf_pair_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lcp_itf_pair_details payload;
} vapi_msg_lcp_itf_pair_details;

static inline void vapi_msg_lcp_itf_pair_details_payload_hton(vapi_payload_lcp_itf_pair_details *payload)
{
  payload->phy_sw_if_index = htobe32(payload->phy_sw_if_index);
  payload->host_sw_if_index = htobe32(payload->host_sw_if_index);
  payload->vif_index = htobe32(payload->vif_index);
}

static inline void vapi_msg_lcp_itf_pair_details_payload_ntoh(vapi_payload_lcp_itf_pair_details *payload)
{
  payload->phy_sw_if_index = be32toh(payload->phy_sw_if_index);
  payload->host_sw_if_index = be32toh(payload->host_sw_if_index);
  payload->vif_index = be32toh(payload->vif_index);
}

static inline void vapi_msg_lcp_itf_pair_details_hton(vapi_msg_lcp_itf_pair_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lcp_itf_pair_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_lcp_itf_pair_details_ntoh(vapi_msg_lcp_itf_pair_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lcp_itf_pair_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lcp_itf_pair_details_msg_size(vapi_msg_lcp_itf_pair_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_itf_pair_details_msg_size(vapi_msg_lcp_itf_pair_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_itf_pair_details) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_itf_pair_details));
      return -1;
    }
  if (vapi_calc_lcp_itf_pair_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_itf_pair_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lcp_itf_pair_details()
{
  static const char name[] = "lcp_itf_pair_details";
  static const char name_with_crc[] = "lcp_itf_pair_details_8b5481af";
  static vapi_message_desc_t __vapi_metadata_lcp_itf_pair_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lcp_itf_pair_details, payload),
    (verify_msg_size_fn_t)vapi_verify_lcp_itf_pair_details_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_details_hton,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_itf_pair_details = vapi_register_msg(&__vapi_metadata_lcp_itf_pair_details);
  VAPI_DBG("Assigned msg id %d to lcp_itf_pair_details", vapi_msg_id_lcp_itf_pair_details);
}
#endif

#ifndef defined_vapi_msg_lcp_itf_pair_get
#define defined_vapi_msg_lcp_itf_pair_get
typedef struct __attribute__ ((__packed__)) {
  u32 cursor; 
} vapi_payload_lcp_itf_pair_get;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lcp_itf_pair_get payload;
} vapi_msg_lcp_itf_pair_get;

static inline void vapi_msg_lcp_itf_pair_get_payload_hton(vapi_payload_lcp_itf_pair_get *payload)
{
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_lcp_itf_pair_get_payload_ntoh(vapi_payload_lcp_itf_pair_get *payload)
{
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_lcp_itf_pair_get_hton(vapi_msg_lcp_itf_pair_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lcp_itf_pair_get_payload_hton(&msg->payload);
}

static inline void vapi_msg_lcp_itf_pair_get_ntoh(vapi_msg_lcp_itf_pair_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lcp_itf_pair_get_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lcp_itf_pair_get_msg_size(vapi_msg_lcp_itf_pair_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_itf_pair_get_msg_size(vapi_msg_lcp_itf_pair_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_itf_pair_get) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_itf_pair_get));
      return -1;
    }
  if (vapi_calc_lcp_itf_pair_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_itf_pair_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lcp_itf_pair_get* vapi_alloc_lcp_itf_pair_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_lcp_itf_pair_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_lcp_itf_pair_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lcp_itf_pair_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lcp_itf_pair_get);

  return msg;
}

static inline vapi_error_e vapi_lcp_itf_pair_get(struct vapi_ctx_s *ctx,
  vapi_msg_lcp_itf_pair_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lcp_itf_pair_get_reply *reply),
  void *reply_callback_ctx,
  vapi_error_e (*details_callback)(struct vapi_ctx_s *ctx,
                                   void *callback_ctx,
                                   vapi_error_e rv,
                                   bool is_last,
                                   vapi_payload_lcp_itf_pair_details *details),
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
  vapi_msg_lcp_itf_pair_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lcp_itf_pair_details, VAPI_REQUEST_STREAM, 
                       (vapi_cb_t)details_callback, details_callback_ctx);
    vapi_store_request(ctx, req_context, vapi_msg_id_lcp_itf_pair_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lcp_itf_pair_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lcp_itf_pair_get()
{
  static const char name[] = "lcp_itf_pair_get";
  static const char name_with_crc[] = "lcp_itf_pair_get_f75ba505";
  static vapi_message_desc_t __vapi_metadata_lcp_itf_pair_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lcp_itf_pair_get, payload),
    (verify_msg_size_fn_t)vapi_verify_lcp_itf_pair_get_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_get_hton,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_itf_pair_get = vapi_register_msg(&__vapi_metadata_lcp_itf_pair_get);
  VAPI_DBG("Assigned msg id %d to lcp_itf_pair_get", vapi_msg_id_lcp_itf_pair_get);
}
#endif

#ifndef defined_vapi_msg_lcp_itf_pair_get_v2_reply
#define defined_vapi_msg_lcp_itf_pair_get_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 cursor; 
} vapi_payload_lcp_itf_pair_get_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lcp_itf_pair_get_v2_reply payload;
} vapi_msg_lcp_itf_pair_get_v2_reply;

static inline void vapi_msg_lcp_itf_pair_get_v2_reply_payload_hton(vapi_payload_lcp_itf_pair_get_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_lcp_itf_pair_get_v2_reply_payload_ntoh(vapi_payload_lcp_itf_pair_get_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_lcp_itf_pair_get_v2_reply_hton(vapi_msg_lcp_itf_pair_get_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_get_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lcp_itf_pair_get_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lcp_itf_pair_get_v2_reply_ntoh(vapi_msg_lcp_itf_pair_get_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_get_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lcp_itf_pair_get_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lcp_itf_pair_get_v2_reply_msg_size(vapi_msg_lcp_itf_pair_get_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_itf_pair_get_v2_reply_msg_size(vapi_msg_lcp_itf_pair_get_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_itf_pair_get_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_get_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_itf_pair_get_v2_reply));
      return -1;
    }
  if (vapi_calc_lcp_itf_pair_get_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_get_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_itf_pair_get_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lcp_itf_pair_get_v2_reply()
{
  static const char name[] = "lcp_itf_pair_get_v2_reply";
  static const char name_with_crc[] = "lcp_itf_pair_get_v2_reply_53b48f5d";
  static vapi_message_desc_t __vapi_metadata_lcp_itf_pair_get_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lcp_itf_pair_get_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lcp_itf_pair_get_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_get_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_get_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_itf_pair_get_v2_reply = vapi_register_msg(&__vapi_metadata_lcp_itf_pair_get_v2_reply);
  VAPI_DBG("Assigned msg id %d to lcp_itf_pair_get_v2_reply", vapi_msg_id_lcp_itf_pair_get_v2_reply);
}

static inline void vapi_set_vapi_msg_lcp_itf_pair_get_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lcp_itf_pair_get_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lcp_itf_pair_get_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lcp_itf_pair_get_v2
#define defined_vapi_msg_lcp_itf_pair_get_v2
typedef struct __attribute__ ((__packed__)) {
  u32 cursor;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_lcp_itf_pair_get_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lcp_itf_pair_get_v2 payload;
} vapi_msg_lcp_itf_pair_get_v2;

static inline void vapi_msg_lcp_itf_pair_get_v2_payload_hton(vapi_payload_lcp_itf_pair_get_v2 *payload)
{
  payload->cursor = htobe32(payload->cursor);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_lcp_itf_pair_get_v2_payload_ntoh(vapi_payload_lcp_itf_pair_get_v2 *payload)
{
  payload->cursor = be32toh(payload->cursor);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_lcp_itf_pair_get_v2_hton(vapi_msg_lcp_itf_pair_get_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_get_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lcp_itf_pair_get_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_lcp_itf_pair_get_v2_ntoh(vapi_msg_lcp_itf_pair_get_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_get_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lcp_itf_pair_get_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lcp_itf_pair_get_v2_msg_size(vapi_msg_lcp_itf_pair_get_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_itf_pair_get_v2_msg_size(vapi_msg_lcp_itf_pair_get_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_itf_pair_get_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_get_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_itf_pair_get_v2));
      return -1;
    }
  if (vapi_calc_lcp_itf_pair_get_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_get_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_itf_pair_get_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lcp_itf_pair_get_v2* vapi_alloc_lcp_itf_pair_get_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_lcp_itf_pair_get_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_lcp_itf_pair_get_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lcp_itf_pair_get_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lcp_itf_pair_get_v2);

  return msg;
}

static inline vapi_error_e vapi_lcp_itf_pair_get_v2(struct vapi_ctx_s *ctx,
  vapi_msg_lcp_itf_pair_get_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lcp_itf_pair_get_v2_reply *reply),
  void *reply_callback_ctx,
  vapi_error_e (*details_callback)(struct vapi_ctx_s *ctx,
                                   void *callback_ctx,
                                   vapi_error_e rv,
                                   bool is_last,
                                   vapi_payload_lcp_itf_pair_details *details),
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
  vapi_msg_lcp_itf_pair_get_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lcp_itf_pair_details, VAPI_REQUEST_STREAM, 
                       (vapi_cb_t)details_callback, details_callback_ctx);
    vapi_store_request(ctx, req_context, vapi_msg_id_lcp_itf_pair_get_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lcp_itf_pair_get_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lcp_itf_pair_get_v2()
{
  static const char name[] = "lcp_itf_pair_get_v2";
  static const char name_with_crc[] = "lcp_itf_pair_get_v2_47250981";
  static vapi_message_desc_t __vapi_metadata_lcp_itf_pair_get_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lcp_itf_pair_get_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_lcp_itf_pair_get_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_get_v2_hton,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_get_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_itf_pair_get_v2 = vapi_register_msg(&__vapi_metadata_lcp_itf_pair_get_v2);
  VAPI_DBG("Assigned msg id %d to lcp_itf_pair_get_v2", vapi_msg_id_lcp_itf_pair_get_v2);
}
#endif

#ifndef defined_vapi_msg_lcp_ethertype_enable_reply
#define defined_vapi_msg_lcp_ethertype_enable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lcp_ethertype_enable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lcp_ethertype_enable_reply payload;
} vapi_msg_lcp_ethertype_enable_reply;

static inline void vapi_msg_lcp_ethertype_enable_reply_payload_hton(vapi_payload_lcp_ethertype_enable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lcp_ethertype_enable_reply_payload_ntoh(vapi_payload_lcp_ethertype_enable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lcp_ethertype_enable_reply_hton(vapi_msg_lcp_ethertype_enable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_ethertype_enable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lcp_ethertype_enable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lcp_ethertype_enable_reply_ntoh(vapi_msg_lcp_ethertype_enable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_ethertype_enable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lcp_ethertype_enable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lcp_ethertype_enable_reply_msg_size(vapi_msg_lcp_ethertype_enable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_ethertype_enable_reply_msg_size(vapi_msg_lcp_ethertype_enable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_ethertype_enable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_ethertype_enable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_ethertype_enable_reply));
      return -1;
    }
  if (vapi_calc_lcp_ethertype_enable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_ethertype_enable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_ethertype_enable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lcp_ethertype_enable_reply()
{
  static const char name[] = "lcp_ethertype_enable_reply";
  static const char name_with_crc[] = "lcp_ethertype_enable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lcp_ethertype_enable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lcp_ethertype_enable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lcp_ethertype_enable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_ethertype_enable_reply_hton,
    (generic_swap_fn_t)vapi_msg_lcp_ethertype_enable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_ethertype_enable_reply = vapi_register_msg(&__vapi_metadata_lcp_ethertype_enable_reply);
  VAPI_DBG("Assigned msg id %d to lcp_ethertype_enable_reply", vapi_msg_id_lcp_ethertype_enable_reply);
}

static inline void vapi_set_vapi_msg_lcp_ethertype_enable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lcp_ethertype_enable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lcp_ethertype_enable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lcp_ethertype_enable
#define defined_vapi_msg_lcp_ethertype_enable
typedef struct __attribute__ ((__packed__)) {
  u16 ethertype; 
} vapi_payload_lcp_ethertype_enable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lcp_ethertype_enable payload;
} vapi_msg_lcp_ethertype_enable;

static inline void vapi_msg_lcp_ethertype_enable_payload_hton(vapi_payload_lcp_ethertype_enable *payload)
{
  payload->ethertype = htobe16(payload->ethertype);
}

static inline void vapi_msg_lcp_ethertype_enable_payload_ntoh(vapi_payload_lcp_ethertype_enable *payload)
{
  payload->ethertype = be16toh(payload->ethertype);
}

static inline void vapi_msg_lcp_ethertype_enable_hton(vapi_msg_lcp_ethertype_enable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_ethertype_enable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lcp_ethertype_enable_payload_hton(&msg->payload);
}

static inline void vapi_msg_lcp_ethertype_enable_ntoh(vapi_msg_lcp_ethertype_enable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_ethertype_enable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lcp_ethertype_enable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lcp_ethertype_enable_msg_size(vapi_msg_lcp_ethertype_enable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_ethertype_enable_msg_size(vapi_msg_lcp_ethertype_enable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_ethertype_enable) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_ethertype_enable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_ethertype_enable));
      return -1;
    }
  if (vapi_calc_lcp_ethertype_enable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_ethertype_enable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_ethertype_enable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lcp_ethertype_enable* vapi_alloc_lcp_ethertype_enable(struct vapi_ctx_s *ctx)
{
  vapi_msg_lcp_ethertype_enable *msg = NULL;
  const size_t size = sizeof(vapi_msg_lcp_ethertype_enable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lcp_ethertype_enable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lcp_ethertype_enable);

  return msg;
}

static inline vapi_error_e vapi_lcp_ethertype_enable(struct vapi_ctx_s *ctx,
  vapi_msg_lcp_ethertype_enable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lcp_ethertype_enable_reply *reply),
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
  vapi_msg_lcp_ethertype_enable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lcp_ethertype_enable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lcp_ethertype_enable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lcp_ethertype_enable()
{
  static const char name[] = "lcp_ethertype_enable";
  static const char name_with_crc[] = "lcp_ethertype_enable_f893dae1";
  static vapi_message_desc_t __vapi_metadata_lcp_ethertype_enable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lcp_ethertype_enable, payload),
    (verify_msg_size_fn_t)vapi_verify_lcp_ethertype_enable_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_ethertype_enable_hton,
    (generic_swap_fn_t)vapi_msg_lcp_ethertype_enable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_ethertype_enable = vapi_register_msg(&__vapi_metadata_lcp_ethertype_enable);
  VAPI_DBG("Assigned msg id %d to lcp_ethertype_enable", vapi_msg_id_lcp_ethertype_enable);
}
#endif

#ifndef defined_vapi_msg_lcp_ethertype_get_reply
#define defined_vapi_msg_lcp_ethertype_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u16 count;
  u16 ethertypes[0]; 
} vapi_payload_lcp_ethertype_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lcp_ethertype_get_reply payload;
} vapi_msg_lcp_ethertype_get_reply;

static inline void vapi_msg_lcp_ethertype_get_reply_payload_hton(vapi_payload_lcp_ethertype_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->count = htobe16(payload->count);
  do { unsigned i; for (i = 0; i < be16toh(payload->count); ++i) { payload->ethertypes[i] = htobe16(payload->ethertypes[i]); } } while(0);
}

static inline void vapi_msg_lcp_ethertype_get_reply_payload_ntoh(vapi_payload_lcp_ethertype_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->count = be16toh(payload->count);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { payload->ethertypes[i] = be16toh(payload->ethertypes[i]); } } while(0);
}

static inline void vapi_msg_lcp_ethertype_get_reply_hton(vapi_msg_lcp_ethertype_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_ethertype_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lcp_ethertype_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lcp_ethertype_get_reply_ntoh(vapi_msg_lcp_ethertype_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_ethertype_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lcp_ethertype_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lcp_ethertype_get_reply_msg_size(vapi_msg_lcp_ethertype_get_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.ethertypes[0]) * msg->payload.count;
}

static inline int vapi_verify_lcp_ethertype_get_reply_msg_size(vapi_msg_lcp_ethertype_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_ethertype_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_ethertype_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_ethertype_get_reply));
      return -1;
    }
  if (vapi_calc_lcp_ethertype_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_ethertype_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_ethertype_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lcp_ethertype_get_reply()
{
  static const char name[] = "lcp_ethertype_get_reply";
  static const char name_with_crc[] = "lcp_ethertype_get_reply_db48c31e";
  static vapi_message_desc_t __vapi_metadata_lcp_ethertype_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lcp_ethertype_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lcp_ethertype_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_ethertype_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_lcp_ethertype_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_ethertype_get_reply = vapi_register_msg(&__vapi_metadata_lcp_ethertype_get_reply);
  VAPI_DBG("Assigned msg id %d to lcp_ethertype_get_reply", vapi_msg_id_lcp_ethertype_get_reply);
}

static inline void vapi_set_vapi_msg_lcp_ethertype_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lcp_ethertype_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lcp_ethertype_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lcp_ethertype_get
#define defined_vapi_msg_lcp_ethertype_get
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_lcp_ethertype_get;

static inline void vapi_msg_lcp_ethertype_get_hton(vapi_msg_lcp_ethertype_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_ethertype_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_lcp_ethertype_get_ntoh(vapi_msg_lcp_ethertype_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_ethertype_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_lcp_ethertype_get_msg_size(vapi_msg_lcp_ethertype_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_ethertype_get_msg_size(vapi_msg_lcp_ethertype_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_ethertype_get) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_ethertype_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_ethertype_get));
      return -1;
    }
  if (vapi_calc_lcp_ethertype_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_ethertype_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_ethertype_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lcp_ethertype_get* vapi_alloc_lcp_ethertype_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_lcp_ethertype_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_lcp_ethertype_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lcp_ethertype_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lcp_ethertype_get);

  return msg;
}

static inline vapi_error_e vapi_lcp_ethertype_get(struct vapi_ctx_s *ctx,
  vapi_msg_lcp_ethertype_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lcp_ethertype_get_reply *reply),
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
  vapi_msg_lcp_ethertype_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lcp_ethertype_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lcp_ethertype_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lcp_ethertype_get()
{
  static const char name[] = "lcp_ethertype_get";
  static const char name_with_crc[] = "lcp_ethertype_get_51077d14";
  static vapi_message_desc_t __vapi_metadata_lcp_ethertype_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_lcp_ethertype_get_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_ethertype_get_hton,
    (generic_swap_fn_t)vapi_msg_lcp_ethertype_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_ethertype_get = vapi_register_msg(&__vapi_metadata_lcp_ethertype_get);
  VAPI_DBG("Assigned msg id %d to lcp_ethertype_get", vapi_msg_id_lcp_ethertype_get);
}
#endif

#ifndef defined_vapi_msg_lcp_itf_pair_replace_begin_reply
#define defined_vapi_msg_lcp_itf_pair_replace_begin_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lcp_itf_pair_replace_begin_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lcp_itf_pair_replace_begin_reply payload;
} vapi_msg_lcp_itf_pair_replace_begin_reply;

static inline void vapi_msg_lcp_itf_pair_replace_begin_reply_payload_hton(vapi_payload_lcp_itf_pair_replace_begin_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lcp_itf_pair_replace_begin_reply_payload_ntoh(vapi_payload_lcp_itf_pair_replace_begin_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lcp_itf_pair_replace_begin_reply_hton(vapi_msg_lcp_itf_pair_replace_begin_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_replace_begin_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lcp_itf_pair_replace_begin_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lcp_itf_pair_replace_begin_reply_ntoh(vapi_msg_lcp_itf_pair_replace_begin_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_replace_begin_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lcp_itf_pair_replace_begin_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lcp_itf_pair_replace_begin_reply_msg_size(vapi_msg_lcp_itf_pair_replace_begin_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_itf_pair_replace_begin_reply_msg_size(vapi_msg_lcp_itf_pair_replace_begin_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_itf_pair_replace_begin_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_replace_begin_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_itf_pair_replace_begin_reply));
      return -1;
    }
  if (vapi_calc_lcp_itf_pair_replace_begin_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_replace_begin_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_itf_pair_replace_begin_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lcp_itf_pair_replace_begin_reply()
{
  static const char name[] = "lcp_itf_pair_replace_begin_reply";
  static const char name_with_crc[] = "lcp_itf_pair_replace_begin_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lcp_itf_pair_replace_begin_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lcp_itf_pair_replace_begin_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lcp_itf_pair_replace_begin_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_replace_begin_reply_hton,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_replace_begin_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_itf_pair_replace_begin_reply = vapi_register_msg(&__vapi_metadata_lcp_itf_pair_replace_begin_reply);
  VAPI_DBG("Assigned msg id %d to lcp_itf_pair_replace_begin_reply", vapi_msg_id_lcp_itf_pair_replace_begin_reply);
}

static inline void vapi_set_vapi_msg_lcp_itf_pair_replace_begin_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lcp_itf_pair_replace_begin_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lcp_itf_pair_replace_begin_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lcp_itf_pair_replace_begin
#define defined_vapi_msg_lcp_itf_pair_replace_begin
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_lcp_itf_pair_replace_begin;

static inline void vapi_msg_lcp_itf_pair_replace_begin_hton(vapi_msg_lcp_itf_pair_replace_begin *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_replace_begin'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_lcp_itf_pair_replace_begin_ntoh(vapi_msg_lcp_itf_pair_replace_begin *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_replace_begin'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_lcp_itf_pair_replace_begin_msg_size(vapi_msg_lcp_itf_pair_replace_begin *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_itf_pair_replace_begin_msg_size(vapi_msg_lcp_itf_pair_replace_begin *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_itf_pair_replace_begin) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_replace_begin' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_itf_pair_replace_begin));
      return -1;
    }
  if (vapi_calc_lcp_itf_pair_replace_begin_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_replace_begin' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_itf_pair_replace_begin_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lcp_itf_pair_replace_begin* vapi_alloc_lcp_itf_pair_replace_begin(struct vapi_ctx_s *ctx)
{
  vapi_msg_lcp_itf_pair_replace_begin *msg = NULL;
  const size_t size = sizeof(vapi_msg_lcp_itf_pair_replace_begin);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lcp_itf_pair_replace_begin*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lcp_itf_pair_replace_begin);

  return msg;
}

static inline vapi_error_e vapi_lcp_itf_pair_replace_begin(struct vapi_ctx_s *ctx,
  vapi_msg_lcp_itf_pair_replace_begin *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lcp_itf_pair_replace_begin_reply *reply),
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
  vapi_msg_lcp_itf_pair_replace_begin_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lcp_itf_pair_replace_begin_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lcp_itf_pair_replace_begin_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lcp_itf_pair_replace_begin()
{
  static const char name[] = "lcp_itf_pair_replace_begin";
  static const char name_with_crc[] = "lcp_itf_pair_replace_begin_51077d14";
  static vapi_message_desc_t __vapi_metadata_lcp_itf_pair_replace_begin = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_lcp_itf_pair_replace_begin_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_replace_begin_hton,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_replace_begin_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_itf_pair_replace_begin = vapi_register_msg(&__vapi_metadata_lcp_itf_pair_replace_begin);
  VAPI_DBG("Assigned msg id %d to lcp_itf_pair_replace_begin", vapi_msg_id_lcp_itf_pair_replace_begin);
}
#endif

#ifndef defined_vapi_msg_lcp_itf_pair_replace_end_reply
#define defined_vapi_msg_lcp_itf_pair_replace_end_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lcp_itf_pair_replace_end_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lcp_itf_pair_replace_end_reply payload;
} vapi_msg_lcp_itf_pair_replace_end_reply;

static inline void vapi_msg_lcp_itf_pair_replace_end_reply_payload_hton(vapi_payload_lcp_itf_pair_replace_end_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lcp_itf_pair_replace_end_reply_payload_ntoh(vapi_payload_lcp_itf_pair_replace_end_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lcp_itf_pair_replace_end_reply_hton(vapi_msg_lcp_itf_pair_replace_end_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_replace_end_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lcp_itf_pair_replace_end_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lcp_itf_pair_replace_end_reply_ntoh(vapi_msg_lcp_itf_pair_replace_end_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_replace_end_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lcp_itf_pair_replace_end_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lcp_itf_pair_replace_end_reply_msg_size(vapi_msg_lcp_itf_pair_replace_end_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_itf_pair_replace_end_reply_msg_size(vapi_msg_lcp_itf_pair_replace_end_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_itf_pair_replace_end_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_replace_end_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_itf_pair_replace_end_reply));
      return -1;
    }
  if (vapi_calc_lcp_itf_pair_replace_end_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_replace_end_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_itf_pair_replace_end_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lcp_itf_pair_replace_end_reply()
{
  static const char name[] = "lcp_itf_pair_replace_end_reply";
  static const char name_with_crc[] = "lcp_itf_pair_replace_end_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lcp_itf_pair_replace_end_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lcp_itf_pair_replace_end_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lcp_itf_pair_replace_end_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_replace_end_reply_hton,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_replace_end_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_itf_pair_replace_end_reply = vapi_register_msg(&__vapi_metadata_lcp_itf_pair_replace_end_reply);
  VAPI_DBG("Assigned msg id %d to lcp_itf_pair_replace_end_reply", vapi_msg_id_lcp_itf_pair_replace_end_reply);
}

static inline void vapi_set_vapi_msg_lcp_itf_pair_replace_end_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lcp_itf_pair_replace_end_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lcp_itf_pair_replace_end_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lcp_itf_pair_replace_end
#define defined_vapi_msg_lcp_itf_pair_replace_end
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_lcp_itf_pair_replace_end;

static inline void vapi_msg_lcp_itf_pair_replace_end_hton(vapi_msg_lcp_itf_pair_replace_end *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_replace_end'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_lcp_itf_pair_replace_end_ntoh(vapi_msg_lcp_itf_pair_replace_end *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lcp_itf_pair_replace_end'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_lcp_itf_pair_replace_end_msg_size(vapi_msg_lcp_itf_pair_replace_end *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lcp_itf_pair_replace_end_msg_size(vapi_msg_lcp_itf_pair_replace_end *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lcp_itf_pair_replace_end) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_replace_end' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lcp_itf_pair_replace_end));
      return -1;
    }
  if (vapi_calc_lcp_itf_pair_replace_end_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lcp_itf_pair_replace_end' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lcp_itf_pair_replace_end_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lcp_itf_pair_replace_end* vapi_alloc_lcp_itf_pair_replace_end(struct vapi_ctx_s *ctx)
{
  vapi_msg_lcp_itf_pair_replace_end *msg = NULL;
  const size_t size = sizeof(vapi_msg_lcp_itf_pair_replace_end);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lcp_itf_pair_replace_end*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lcp_itf_pair_replace_end);

  return msg;
}

static inline vapi_error_e vapi_lcp_itf_pair_replace_end(struct vapi_ctx_s *ctx,
  vapi_msg_lcp_itf_pair_replace_end *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lcp_itf_pair_replace_end_reply *reply),
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
  vapi_msg_lcp_itf_pair_replace_end_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lcp_itf_pair_replace_end_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lcp_itf_pair_replace_end_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lcp_itf_pair_replace_end()
{
  static const char name[] = "lcp_itf_pair_replace_end";
  static const char name_with_crc[] = "lcp_itf_pair_replace_end_51077d14";
  static vapi_message_desc_t __vapi_metadata_lcp_itf_pair_replace_end = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_lcp_itf_pair_replace_end_msg_size,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_replace_end_hton,
    (generic_swap_fn_t)vapi_msg_lcp_itf_pair_replace_end_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lcp_itf_pair_replace_end = vapi_register_msg(&__vapi_metadata_lcp_itf_pair_replace_end);
  VAPI_DBG("Assigned msg id %d to lcp_itf_pair_replace_end", vapi_msg_id_lcp_itf_pair_replace_end);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
