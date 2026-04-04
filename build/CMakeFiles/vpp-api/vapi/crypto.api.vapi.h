#ifndef __included_crypto_api_json
#define __included_crypto_api_json

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

extern vapi_msg_id_t vapi_msg_id_crypto_set_async_dispatch;
extern vapi_msg_id_t vapi_msg_id_crypto_set_async_dispatch_reply;
extern vapi_msg_id_t vapi_msg_id_crypto_set_async_dispatch_v2;
extern vapi_msg_id_t vapi_msg_id_crypto_set_async_dispatch_v2_reply;
extern vapi_msg_id_t vapi_msg_id_crypto_set_handler;
extern vapi_msg_id_t vapi_msg_id_crypto_set_handler_reply;

#define DEFINE_VAPI_MSG_IDS_CRYPTO_API_JSON\
  vapi_msg_id_t vapi_msg_id_crypto_set_async_dispatch;\
  vapi_msg_id_t vapi_msg_id_crypto_set_async_dispatch_reply;\
  vapi_msg_id_t vapi_msg_id_crypto_set_async_dispatch_v2;\
  vapi_msg_id_t vapi_msg_id_crypto_set_async_dispatch_v2_reply;\
  vapi_msg_id_t vapi_msg_id_crypto_set_handler;\
  vapi_msg_id_t vapi_msg_id_crypto_set_handler_reply;


#ifndef defined_vapi_enum_crypto_dispatch_mode
#define defined_vapi_enum_crypto_dispatch_mode
typedef enum {
  CRYPTO_ASYNC_DISPATCH_POLLING = 0,
  CRYPTO_ASYNC_DISPATCH_INTERRUPT = 1,
} __attribute__((packed)) vapi_enum_crypto_dispatch_mode;

#endif

#ifndef defined_vapi_enum_crypto_op_class_type
#define defined_vapi_enum_crypto_op_class_type
typedef enum {
  CRYPTO_API_OP_SIMPLE = 0,
  CRYPTO_API_OP_CHAINED = 1,
  CRYPTO_API_OP_BOTH = 2,
} __attribute__((packed)) vapi_enum_crypto_op_class_type;

#endif

#ifndef defined_vapi_msg_crypto_set_async_dispatch_reply
#define defined_vapi_msg_crypto_set_async_dispatch_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_crypto_set_async_dispatch_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_crypto_set_async_dispatch_reply payload;
} vapi_msg_crypto_set_async_dispatch_reply;

static inline void vapi_msg_crypto_set_async_dispatch_reply_payload_hton(vapi_payload_crypto_set_async_dispatch_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_crypto_set_async_dispatch_reply_payload_ntoh(vapi_payload_crypto_set_async_dispatch_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_crypto_set_async_dispatch_reply_hton(vapi_msg_crypto_set_async_dispatch_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_crypto_set_async_dispatch_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_crypto_set_async_dispatch_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_crypto_set_async_dispatch_reply_ntoh(vapi_msg_crypto_set_async_dispatch_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_crypto_set_async_dispatch_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_crypto_set_async_dispatch_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_crypto_set_async_dispatch_reply_msg_size(vapi_msg_crypto_set_async_dispatch_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_crypto_set_async_dispatch_reply_msg_size(vapi_msg_crypto_set_async_dispatch_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_crypto_set_async_dispatch_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'crypto_set_async_dispatch_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_crypto_set_async_dispatch_reply));
      return -1;
    }
  if (vapi_calc_crypto_set_async_dispatch_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'crypto_set_async_dispatch_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_crypto_set_async_dispatch_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_crypto_set_async_dispatch_reply()
{
  static const char name[] = "crypto_set_async_dispatch_reply";
  static const char name_with_crc[] = "crypto_set_async_dispatch_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_crypto_set_async_dispatch_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_crypto_set_async_dispatch_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_crypto_set_async_dispatch_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_crypto_set_async_dispatch_reply_hton,
    (generic_swap_fn_t)vapi_msg_crypto_set_async_dispatch_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_crypto_set_async_dispatch_reply = vapi_register_msg(&__vapi_metadata_crypto_set_async_dispatch_reply);
  VAPI_DBG("Assigned msg id %d to crypto_set_async_dispatch_reply", vapi_msg_id_crypto_set_async_dispatch_reply);
}

static inline void vapi_set_vapi_msg_crypto_set_async_dispatch_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_crypto_set_async_dispatch_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_crypto_set_async_dispatch_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_crypto_set_async_dispatch
#define defined_vapi_msg_crypto_set_async_dispatch
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_crypto_dispatch_mode mode; 
} vapi_payload_crypto_set_async_dispatch;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_crypto_set_async_dispatch payload;
} vapi_msg_crypto_set_async_dispatch;

static inline void vapi_msg_crypto_set_async_dispatch_payload_hton(vapi_payload_crypto_set_async_dispatch *payload)
{

}

static inline void vapi_msg_crypto_set_async_dispatch_payload_ntoh(vapi_payload_crypto_set_async_dispatch *payload)
{

}

static inline void vapi_msg_crypto_set_async_dispatch_hton(vapi_msg_crypto_set_async_dispatch *msg)
{
  VAPI_DBG("Swapping `vapi_msg_crypto_set_async_dispatch'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_crypto_set_async_dispatch_payload_hton(&msg->payload);
}

static inline void vapi_msg_crypto_set_async_dispatch_ntoh(vapi_msg_crypto_set_async_dispatch *msg)
{
  VAPI_DBG("Swapping `vapi_msg_crypto_set_async_dispatch'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_crypto_set_async_dispatch_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_crypto_set_async_dispatch_msg_size(vapi_msg_crypto_set_async_dispatch *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_crypto_set_async_dispatch_msg_size(vapi_msg_crypto_set_async_dispatch *msg, uword buf_size)
{
  if (sizeof(vapi_msg_crypto_set_async_dispatch) > buf_size)
    {
      VAPI_ERR("Truncated 'crypto_set_async_dispatch' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_crypto_set_async_dispatch));
      return -1;
    }
  if (vapi_calc_crypto_set_async_dispatch_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'crypto_set_async_dispatch' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_crypto_set_async_dispatch_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_crypto_set_async_dispatch* vapi_alloc_crypto_set_async_dispatch(struct vapi_ctx_s *ctx)
{
  vapi_msg_crypto_set_async_dispatch *msg = NULL;
  const size_t size = sizeof(vapi_msg_crypto_set_async_dispatch);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_crypto_set_async_dispatch*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_crypto_set_async_dispatch);

  return msg;
}

static inline vapi_error_e vapi_crypto_set_async_dispatch(struct vapi_ctx_s *ctx,
  vapi_msg_crypto_set_async_dispatch *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_crypto_set_async_dispatch_reply *reply),
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
  vapi_msg_crypto_set_async_dispatch_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_crypto_set_async_dispatch_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_crypto_set_async_dispatch_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_crypto_set_async_dispatch()
{
  static const char name[] = "crypto_set_async_dispatch";
  static const char name_with_crc[] = "crypto_set_async_dispatch_5ca4adc0";
  static vapi_message_desc_t __vapi_metadata_crypto_set_async_dispatch = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_crypto_set_async_dispatch, payload),
    (verify_msg_size_fn_t)vapi_verify_crypto_set_async_dispatch_msg_size,
    (generic_swap_fn_t)vapi_msg_crypto_set_async_dispatch_hton,
    (generic_swap_fn_t)vapi_msg_crypto_set_async_dispatch_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_crypto_set_async_dispatch = vapi_register_msg(&__vapi_metadata_crypto_set_async_dispatch);
  VAPI_DBG("Assigned msg id %d to crypto_set_async_dispatch", vapi_msg_id_crypto_set_async_dispatch);
}
#endif

#ifndef defined_vapi_msg_crypto_set_async_dispatch_v2_reply
#define defined_vapi_msg_crypto_set_async_dispatch_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_crypto_set_async_dispatch_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_crypto_set_async_dispatch_v2_reply payload;
} vapi_msg_crypto_set_async_dispatch_v2_reply;

static inline void vapi_msg_crypto_set_async_dispatch_v2_reply_payload_hton(vapi_payload_crypto_set_async_dispatch_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_crypto_set_async_dispatch_v2_reply_payload_ntoh(vapi_payload_crypto_set_async_dispatch_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_crypto_set_async_dispatch_v2_reply_hton(vapi_msg_crypto_set_async_dispatch_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_crypto_set_async_dispatch_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_crypto_set_async_dispatch_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_crypto_set_async_dispatch_v2_reply_ntoh(vapi_msg_crypto_set_async_dispatch_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_crypto_set_async_dispatch_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_crypto_set_async_dispatch_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_crypto_set_async_dispatch_v2_reply_msg_size(vapi_msg_crypto_set_async_dispatch_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_crypto_set_async_dispatch_v2_reply_msg_size(vapi_msg_crypto_set_async_dispatch_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_crypto_set_async_dispatch_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'crypto_set_async_dispatch_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_crypto_set_async_dispatch_v2_reply));
      return -1;
    }
  if (vapi_calc_crypto_set_async_dispatch_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'crypto_set_async_dispatch_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_crypto_set_async_dispatch_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_crypto_set_async_dispatch_v2_reply()
{
  static const char name[] = "crypto_set_async_dispatch_v2_reply";
  static const char name_with_crc[] = "crypto_set_async_dispatch_v2_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_crypto_set_async_dispatch_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_crypto_set_async_dispatch_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_crypto_set_async_dispatch_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_crypto_set_async_dispatch_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_crypto_set_async_dispatch_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_crypto_set_async_dispatch_v2_reply = vapi_register_msg(&__vapi_metadata_crypto_set_async_dispatch_v2_reply);
  VAPI_DBG("Assigned msg id %d to crypto_set_async_dispatch_v2_reply", vapi_msg_id_crypto_set_async_dispatch_v2_reply);
}

static inline void vapi_set_vapi_msg_crypto_set_async_dispatch_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_crypto_set_async_dispatch_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_crypto_set_async_dispatch_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_crypto_set_async_dispatch_v2
#define defined_vapi_msg_crypto_set_async_dispatch_v2
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_crypto_dispatch_mode mode;
  bool adaptive; 
} vapi_payload_crypto_set_async_dispatch_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_crypto_set_async_dispatch_v2 payload;
} vapi_msg_crypto_set_async_dispatch_v2;

static inline void vapi_msg_crypto_set_async_dispatch_v2_payload_hton(vapi_payload_crypto_set_async_dispatch_v2 *payload)
{

}

static inline void vapi_msg_crypto_set_async_dispatch_v2_payload_ntoh(vapi_payload_crypto_set_async_dispatch_v2 *payload)
{

}

static inline void vapi_msg_crypto_set_async_dispatch_v2_hton(vapi_msg_crypto_set_async_dispatch_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_crypto_set_async_dispatch_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_crypto_set_async_dispatch_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_crypto_set_async_dispatch_v2_ntoh(vapi_msg_crypto_set_async_dispatch_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_crypto_set_async_dispatch_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_crypto_set_async_dispatch_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_crypto_set_async_dispatch_v2_msg_size(vapi_msg_crypto_set_async_dispatch_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_crypto_set_async_dispatch_v2_msg_size(vapi_msg_crypto_set_async_dispatch_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_crypto_set_async_dispatch_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'crypto_set_async_dispatch_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_crypto_set_async_dispatch_v2));
      return -1;
    }
  if (vapi_calc_crypto_set_async_dispatch_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'crypto_set_async_dispatch_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_crypto_set_async_dispatch_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_crypto_set_async_dispatch_v2* vapi_alloc_crypto_set_async_dispatch_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_crypto_set_async_dispatch_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_crypto_set_async_dispatch_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_crypto_set_async_dispatch_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_crypto_set_async_dispatch_v2);

  return msg;
}

static inline vapi_error_e vapi_crypto_set_async_dispatch_v2(struct vapi_ctx_s *ctx,
  vapi_msg_crypto_set_async_dispatch_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_crypto_set_async_dispatch_v2_reply *reply),
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
  vapi_msg_crypto_set_async_dispatch_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_crypto_set_async_dispatch_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_crypto_set_async_dispatch_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_crypto_set_async_dispatch_v2()
{
  static const char name[] = "crypto_set_async_dispatch_v2";
  static const char name_with_crc[] = "crypto_set_async_dispatch_v2_667d2d54";
  static vapi_message_desc_t __vapi_metadata_crypto_set_async_dispatch_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_crypto_set_async_dispatch_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_crypto_set_async_dispatch_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_crypto_set_async_dispatch_v2_hton,
    (generic_swap_fn_t)vapi_msg_crypto_set_async_dispatch_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_crypto_set_async_dispatch_v2 = vapi_register_msg(&__vapi_metadata_crypto_set_async_dispatch_v2);
  VAPI_DBG("Assigned msg id %d to crypto_set_async_dispatch_v2", vapi_msg_id_crypto_set_async_dispatch_v2);
}
#endif

#ifndef defined_vapi_msg_crypto_set_handler_reply
#define defined_vapi_msg_crypto_set_handler_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_crypto_set_handler_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_crypto_set_handler_reply payload;
} vapi_msg_crypto_set_handler_reply;

static inline void vapi_msg_crypto_set_handler_reply_payload_hton(vapi_payload_crypto_set_handler_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_crypto_set_handler_reply_payload_ntoh(vapi_payload_crypto_set_handler_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_crypto_set_handler_reply_hton(vapi_msg_crypto_set_handler_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_crypto_set_handler_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_crypto_set_handler_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_crypto_set_handler_reply_ntoh(vapi_msg_crypto_set_handler_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_crypto_set_handler_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_crypto_set_handler_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_crypto_set_handler_reply_msg_size(vapi_msg_crypto_set_handler_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_crypto_set_handler_reply_msg_size(vapi_msg_crypto_set_handler_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_crypto_set_handler_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'crypto_set_handler_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_crypto_set_handler_reply));
      return -1;
    }
  if (vapi_calc_crypto_set_handler_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'crypto_set_handler_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_crypto_set_handler_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_crypto_set_handler_reply()
{
  static const char name[] = "crypto_set_handler_reply";
  static const char name_with_crc[] = "crypto_set_handler_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_crypto_set_handler_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_crypto_set_handler_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_crypto_set_handler_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_crypto_set_handler_reply_hton,
    (generic_swap_fn_t)vapi_msg_crypto_set_handler_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_crypto_set_handler_reply = vapi_register_msg(&__vapi_metadata_crypto_set_handler_reply);
  VAPI_DBG("Assigned msg id %d to crypto_set_handler_reply", vapi_msg_id_crypto_set_handler_reply);
}

static inline void vapi_set_vapi_msg_crypto_set_handler_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_crypto_set_handler_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_crypto_set_handler_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_crypto_set_handler
#define defined_vapi_msg_crypto_set_handler
typedef struct __attribute__ ((__packed__)) {
  u8 alg_name[32];
  u8 engine[16];
  vapi_enum_crypto_op_class_type oct;
  u8 is_async; 
} vapi_payload_crypto_set_handler;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_crypto_set_handler payload;
} vapi_msg_crypto_set_handler;

static inline void vapi_msg_crypto_set_handler_payload_hton(vapi_payload_crypto_set_handler *payload)
{

}

static inline void vapi_msg_crypto_set_handler_payload_ntoh(vapi_payload_crypto_set_handler *payload)
{

}

static inline void vapi_msg_crypto_set_handler_hton(vapi_msg_crypto_set_handler *msg)
{
  VAPI_DBG("Swapping `vapi_msg_crypto_set_handler'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_crypto_set_handler_payload_hton(&msg->payload);
}

static inline void vapi_msg_crypto_set_handler_ntoh(vapi_msg_crypto_set_handler *msg)
{
  VAPI_DBG("Swapping `vapi_msg_crypto_set_handler'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_crypto_set_handler_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_crypto_set_handler_msg_size(vapi_msg_crypto_set_handler *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_crypto_set_handler_msg_size(vapi_msg_crypto_set_handler *msg, uword buf_size)
{
  if (sizeof(vapi_msg_crypto_set_handler) > buf_size)
    {
      VAPI_ERR("Truncated 'crypto_set_handler' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_crypto_set_handler));
      return -1;
    }
  if (vapi_calc_crypto_set_handler_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'crypto_set_handler' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_crypto_set_handler_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_crypto_set_handler* vapi_alloc_crypto_set_handler(struct vapi_ctx_s *ctx)
{
  vapi_msg_crypto_set_handler *msg = NULL;
  const size_t size = sizeof(vapi_msg_crypto_set_handler);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_crypto_set_handler*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_crypto_set_handler);

  return msg;
}

static inline vapi_error_e vapi_crypto_set_handler(struct vapi_ctx_s *ctx,
  vapi_msg_crypto_set_handler *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_crypto_set_handler_reply *reply),
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
  vapi_msg_crypto_set_handler_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_crypto_set_handler_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_crypto_set_handler_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_crypto_set_handler()
{
  static const char name[] = "crypto_set_handler";
  static const char name_with_crc[] = "crypto_set_handler_ce9ad00d";
  static vapi_message_desc_t __vapi_metadata_crypto_set_handler = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_crypto_set_handler, payload),
    (verify_msg_size_fn_t)vapi_verify_crypto_set_handler_msg_size,
    (generic_swap_fn_t)vapi_msg_crypto_set_handler_hton,
    (generic_swap_fn_t)vapi_msg_crypto_set_handler_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_crypto_set_handler = vapi_register_msg(&__vapi_metadata_crypto_set_handler);
  VAPI_DBG("Assigned msg id %d to crypto_set_handler", vapi_msg_id_crypto_set_handler);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
