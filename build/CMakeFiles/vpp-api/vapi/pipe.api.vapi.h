#ifndef __included_pipe_api_json
#define __included_pipe_api_json

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

extern vapi_msg_id_t vapi_msg_id_pipe_create;
extern vapi_msg_id_t vapi_msg_id_pipe_create_reply;
extern vapi_msg_id_t vapi_msg_id_pipe_delete;
extern vapi_msg_id_t vapi_msg_id_pipe_delete_reply;
extern vapi_msg_id_t vapi_msg_id_pipe_dump;
extern vapi_msg_id_t vapi_msg_id_pipe_details;

#define DEFINE_VAPI_MSG_IDS_PIPE_API_JSON\
  vapi_msg_id_t vapi_msg_id_pipe_create;\
  vapi_msg_id_t vapi_msg_id_pipe_create_reply;\
  vapi_msg_id_t vapi_msg_id_pipe_delete;\
  vapi_msg_id_t vapi_msg_id_pipe_delete_reply;\
  vapi_msg_id_t vapi_msg_id_pipe_dump;\
  vapi_msg_id_t vapi_msg_id_pipe_details;


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

#ifndef defined_vapi_type_interface_index
#define defined_vapi_type_interface_index
typedef u32 vapi_type_interface_index;

#endif

#ifndef defined_vapi_msg_pipe_create_reply
#define defined_vapi_msg_pipe_create_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_interface_index sw_if_index;
  vapi_type_interface_index pipe_sw_if_index[2]; 
} vapi_payload_pipe_create_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_pipe_create_reply payload;
} vapi_msg_pipe_create_reply;

static inline void vapi_msg_pipe_create_reply_payload_hton(vapi_payload_pipe_create_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->sw_if_index = htobe32(payload->sw_if_index);
  do { unsigned i; for (i = 0; i < 2; ++i) { payload->pipe_sw_if_index[i] = htobe32(payload->pipe_sw_if_index[i]); } } while(0);
}

static inline void vapi_msg_pipe_create_reply_payload_ntoh(vapi_payload_pipe_create_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->sw_if_index = be32toh(payload->sw_if_index);
  do { unsigned i; for (i = 0; i < 2; ++i) { payload->pipe_sw_if_index[i] = be32toh(payload->pipe_sw_if_index[i]); } } while(0);
}

static inline void vapi_msg_pipe_create_reply_hton(vapi_msg_pipe_create_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pipe_create_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_pipe_create_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_pipe_create_reply_ntoh(vapi_msg_pipe_create_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pipe_create_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_pipe_create_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pipe_create_reply_msg_size(vapi_msg_pipe_create_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pipe_create_reply_msg_size(vapi_msg_pipe_create_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pipe_create_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'pipe_create_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pipe_create_reply));
      return -1;
    }
  if (vapi_calc_pipe_create_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pipe_create_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pipe_create_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_pipe_create_reply()
{
  static const char name[] = "pipe_create_reply";
  static const char name_with_crc[] = "pipe_create_reply_b7ce310c";
  static vapi_message_desc_t __vapi_metadata_pipe_create_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_pipe_create_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_pipe_create_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_pipe_create_reply_hton,
    (generic_swap_fn_t)vapi_msg_pipe_create_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pipe_create_reply = vapi_register_msg(&__vapi_metadata_pipe_create_reply);
  VAPI_DBG("Assigned msg id %d to pipe_create_reply", vapi_msg_id_pipe_create_reply);
}

static inline void vapi_set_vapi_msg_pipe_create_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_pipe_create_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_pipe_create_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_pipe_create
#define defined_vapi_msg_pipe_create
typedef struct __attribute__ ((__packed__)) {
  bool is_specified;
  u32 user_instance; 
} vapi_payload_pipe_create;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_pipe_create payload;
} vapi_msg_pipe_create;

static inline void vapi_msg_pipe_create_payload_hton(vapi_payload_pipe_create *payload)
{
  payload->user_instance = htobe32(payload->user_instance);
}

static inline void vapi_msg_pipe_create_payload_ntoh(vapi_payload_pipe_create *payload)
{
  payload->user_instance = be32toh(payload->user_instance);
}

static inline void vapi_msg_pipe_create_hton(vapi_msg_pipe_create *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pipe_create'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_pipe_create_payload_hton(&msg->payload);
}

static inline void vapi_msg_pipe_create_ntoh(vapi_msg_pipe_create *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pipe_create'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_pipe_create_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pipe_create_msg_size(vapi_msg_pipe_create *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pipe_create_msg_size(vapi_msg_pipe_create *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pipe_create) > buf_size)
    {
      VAPI_ERR("Truncated 'pipe_create' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pipe_create));
      return -1;
    }
  if (vapi_calc_pipe_create_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pipe_create' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pipe_create_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_pipe_create* vapi_alloc_pipe_create(struct vapi_ctx_s *ctx)
{
  vapi_msg_pipe_create *msg = NULL;
  const size_t size = sizeof(vapi_msg_pipe_create);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_pipe_create*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_pipe_create);

  return msg;
}

static inline vapi_error_e vapi_pipe_create(struct vapi_ctx_s *ctx,
  vapi_msg_pipe_create *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_pipe_create_reply *reply),
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
  vapi_msg_pipe_create_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_pipe_create_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_pipe_create_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_pipe_create()
{
  static const char name[] = "pipe_create";
  static const char name_with_crc[] = "pipe_create_bb263bd3";
  static vapi_message_desc_t __vapi_metadata_pipe_create = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_pipe_create, payload),
    (verify_msg_size_fn_t)vapi_verify_pipe_create_msg_size,
    (generic_swap_fn_t)vapi_msg_pipe_create_hton,
    (generic_swap_fn_t)vapi_msg_pipe_create_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pipe_create = vapi_register_msg(&__vapi_metadata_pipe_create);
  VAPI_DBG("Assigned msg id %d to pipe_create", vapi_msg_id_pipe_create);
}
#endif

#ifndef defined_vapi_msg_pipe_delete_reply
#define defined_vapi_msg_pipe_delete_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_pipe_delete_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_pipe_delete_reply payload;
} vapi_msg_pipe_delete_reply;

static inline void vapi_msg_pipe_delete_reply_payload_hton(vapi_payload_pipe_delete_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_pipe_delete_reply_payload_ntoh(vapi_payload_pipe_delete_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_pipe_delete_reply_hton(vapi_msg_pipe_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pipe_delete_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_pipe_delete_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_pipe_delete_reply_ntoh(vapi_msg_pipe_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pipe_delete_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_pipe_delete_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pipe_delete_reply_msg_size(vapi_msg_pipe_delete_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pipe_delete_reply_msg_size(vapi_msg_pipe_delete_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pipe_delete_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'pipe_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pipe_delete_reply));
      return -1;
    }
  if (vapi_calc_pipe_delete_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pipe_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pipe_delete_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_pipe_delete_reply()
{
  static const char name[] = "pipe_delete_reply";
  static const char name_with_crc[] = "pipe_delete_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_pipe_delete_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_pipe_delete_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_pipe_delete_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_pipe_delete_reply_hton,
    (generic_swap_fn_t)vapi_msg_pipe_delete_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pipe_delete_reply = vapi_register_msg(&__vapi_metadata_pipe_delete_reply);
  VAPI_DBG("Assigned msg id %d to pipe_delete_reply", vapi_msg_id_pipe_delete_reply);
}

static inline void vapi_set_vapi_msg_pipe_delete_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_pipe_delete_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_pipe_delete_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_pipe_delete
#define defined_vapi_msg_pipe_delete
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_pipe_delete;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_pipe_delete payload;
} vapi_msg_pipe_delete;

static inline void vapi_msg_pipe_delete_payload_hton(vapi_payload_pipe_delete *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_pipe_delete_payload_ntoh(vapi_payload_pipe_delete *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_pipe_delete_hton(vapi_msg_pipe_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pipe_delete'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_pipe_delete_payload_hton(&msg->payload);
}

static inline void vapi_msg_pipe_delete_ntoh(vapi_msg_pipe_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pipe_delete'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_pipe_delete_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pipe_delete_msg_size(vapi_msg_pipe_delete *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pipe_delete_msg_size(vapi_msg_pipe_delete *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pipe_delete) > buf_size)
    {
      VAPI_ERR("Truncated 'pipe_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pipe_delete));
      return -1;
    }
  if (vapi_calc_pipe_delete_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pipe_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pipe_delete_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_pipe_delete* vapi_alloc_pipe_delete(struct vapi_ctx_s *ctx)
{
  vapi_msg_pipe_delete *msg = NULL;
  const size_t size = sizeof(vapi_msg_pipe_delete);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_pipe_delete*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_pipe_delete);

  return msg;
}

static inline vapi_error_e vapi_pipe_delete(struct vapi_ctx_s *ctx,
  vapi_msg_pipe_delete *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_pipe_delete_reply *reply),
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
  vapi_msg_pipe_delete_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_pipe_delete_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_pipe_delete_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_pipe_delete()
{
  static const char name[] = "pipe_delete";
  static const char name_with_crc[] = "pipe_delete_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_pipe_delete = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_pipe_delete, payload),
    (verify_msg_size_fn_t)vapi_verify_pipe_delete_msg_size,
    (generic_swap_fn_t)vapi_msg_pipe_delete_hton,
    (generic_swap_fn_t)vapi_msg_pipe_delete_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pipe_delete = vapi_register_msg(&__vapi_metadata_pipe_delete);
  VAPI_DBG("Assigned msg id %d to pipe_delete", vapi_msg_id_pipe_delete);
}
#endif

#ifndef defined_vapi_msg_pipe_details
#define defined_vapi_msg_pipe_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_type_interface_index pipe_sw_if_index[2];
  u32 instance; 
} vapi_payload_pipe_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_pipe_details payload;
} vapi_msg_pipe_details;

static inline void vapi_msg_pipe_details_payload_hton(vapi_payload_pipe_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  do { unsigned i; for (i = 0; i < 2; ++i) { payload->pipe_sw_if_index[i] = htobe32(payload->pipe_sw_if_index[i]); } } while(0);
  payload->instance = htobe32(payload->instance);
}

static inline void vapi_msg_pipe_details_payload_ntoh(vapi_payload_pipe_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  do { unsigned i; for (i = 0; i < 2; ++i) { payload->pipe_sw_if_index[i] = be32toh(payload->pipe_sw_if_index[i]); } } while(0);
  payload->instance = be32toh(payload->instance);
}

static inline void vapi_msg_pipe_details_hton(vapi_msg_pipe_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pipe_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_pipe_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_pipe_details_ntoh(vapi_msg_pipe_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pipe_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_pipe_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pipe_details_msg_size(vapi_msg_pipe_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pipe_details_msg_size(vapi_msg_pipe_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pipe_details) > buf_size)
    {
      VAPI_ERR("Truncated 'pipe_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pipe_details));
      return -1;
    }
  if (vapi_calc_pipe_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pipe_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pipe_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_pipe_details()
{
  static const char name[] = "pipe_details";
  static const char name_with_crc[] = "pipe_details_c52b799d";
  static vapi_message_desc_t __vapi_metadata_pipe_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_pipe_details, payload),
    (verify_msg_size_fn_t)vapi_verify_pipe_details_msg_size,
    (generic_swap_fn_t)vapi_msg_pipe_details_hton,
    (generic_swap_fn_t)vapi_msg_pipe_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pipe_details = vapi_register_msg(&__vapi_metadata_pipe_details);
  VAPI_DBG("Assigned msg id %d to pipe_details", vapi_msg_id_pipe_details);
}

static inline void vapi_set_vapi_msg_pipe_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_pipe_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_pipe_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_pipe_dump
#define defined_vapi_msg_pipe_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_pipe_dump;

static inline void vapi_msg_pipe_dump_hton(vapi_msg_pipe_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pipe_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_pipe_dump_ntoh(vapi_msg_pipe_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pipe_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_pipe_dump_msg_size(vapi_msg_pipe_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pipe_dump_msg_size(vapi_msg_pipe_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pipe_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'pipe_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pipe_dump));
      return -1;
    }
  if (vapi_calc_pipe_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pipe_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pipe_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_pipe_dump* vapi_alloc_pipe_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_pipe_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_pipe_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_pipe_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_pipe_dump);

  return msg;
}

static inline vapi_error_e vapi_pipe_dump(struct vapi_ctx_s *ctx,
  vapi_msg_pipe_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_pipe_details *reply),
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
  vapi_msg_pipe_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_pipe_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_pipe_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_pipe_dump()
{
  static const char name[] = "pipe_dump";
  static const char name_with_crc[] = "pipe_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_pipe_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_pipe_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_pipe_dump_hton,
    (generic_swap_fn_t)vapi_msg_pipe_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pipe_dump = vapi_register_msg(&__vapi_metadata_pipe_dump);
  VAPI_DBG("Assigned msg id %d to pipe_dump", vapi_msg_id_pipe_dump);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
