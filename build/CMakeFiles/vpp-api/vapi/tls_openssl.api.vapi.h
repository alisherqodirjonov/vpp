#ifndef __included_tls_openssl_api_json
#define __included_tls_openssl_api_json

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

extern vapi_msg_id_t vapi_msg_id_tls_openssl_set_engine;
extern vapi_msg_id_t vapi_msg_id_tls_openssl_set_engine_reply;

#define DEFINE_VAPI_MSG_IDS_TLS_OPENSSL_API_JSON\
  vapi_msg_id_t vapi_msg_id_tls_openssl_set_engine;\
  vapi_msg_id_t vapi_msg_id_tls_openssl_set_engine_reply;


#ifndef defined_vapi_msg_tls_openssl_set_engine_reply
#define defined_vapi_msg_tls_openssl_set_engine_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_tls_openssl_set_engine_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_tls_openssl_set_engine_reply payload;
} vapi_msg_tls_openssl_set_engine_reply;

static inline void vapi_msg_tls_openssl_set_engine_reply_payload_hton(vapi_payload_tls_openssl_set_engine_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_tls_openssl_set_engine_reply_payload_ntoh(vapi_payload_tls_openssl_set_engine_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_tls_openssl_set_engine_reply_hton(vapi_msg_tls_openssl_set_engine_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_tls_openssl_set_engine_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_tls_openssl_set_engine_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_tls_openssl_set_engine_reply_ntoh(vapi_msg_tls_openssl_set_engine_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_tls_openssl_set_engine_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_tls_openssl_set_engine_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_tls_openssl_set_engine_reply_msg_size(vapi_msg_tls_openssl_set_engine_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_tls_openssl_set_engine_reply_msg_size(vapi_msg_tls_openssl_set_engine_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_tls_openssl_set_engine_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'tls_openssl_set_engine_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_tls_openssl_set_engine_reply));
      return -1;
    }
  if (vapi_calc_tls_openssl_set_engine_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'tls_openssl_set_engine_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_tls_openssl_set_engine_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_tls_openssl_set_engine_reply()
{
  static const char name[] = "tls_openssl_set_engine_reply";
  static const char name_with_crc[] = "tls_openssl_set_engine_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_tls_openssl_set_engine_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_tls_openssl_set_engine_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_tls_openssl_set_engine_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_tls_openssl_set_engine_reply_hton,
    (generic_swap_fn_t)vapi_msg_tls_openssl_set_engine_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_tls_openssl_set_engine_reply = vapi_register_msg(&__vapi_metadata_tls_openssl_set_engine_reply);
  VAPI_DBG("Assigned msg id %d to tls_openssl_set_engine_reply", vapi_msg_id_tls_openssl_set_engine_reply);
}

static inline void vapi_set_vapi_msg_tls_openssl_set_engine_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_tls_openssl_set_engine_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_tls_openssl_set_engine_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_tls_openssl_set_engine
#define defined_vapi_msg_tls_openssl_set_engine
typedef struct __attribute__ ((__packed__)) {
  u32 async_enable;
  u8 engine[64];
  u8 algorithm[64];
  u8 ciphers[64]; 
} vapi_payload_tls_openssl_set_engine;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_tls_openssl_set_engine payload;
} vapi_msg_tls_openssl_set_engine;

static inline void vapi_msg_tls_openssl_set_engine_payload_hton(vapi_payload_tls_openssl_set_engine *payload)
{
  payload->async_enable = htobe32(payload->async_enable);
}

static inline void vapi_msg_tls_openssl_set_engine_payload_ntoh(vapi_payload_tls_openssl_set_engine *payload)
{
  payload->async_enable = be32toh(payload->async_enable);
}

static inline void vapi_msg_tls_openssl_set_engine_hton(vapi_msg_tls_openssl_set_engine *msg)
{
  VAPI_DBG("Swapping `vapi_msg_tls_openssl_set_engine'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_tls_openssl_set_engine_payload_hton(&msg->payload);
}

static inline void vapi_msg_tls_openssl_set_engine_ntoh(vapi_msg_tls_openssl_set_engine *msg)
{
  VAPI_DBG("Swapping `vapi_msg_tls_openssl_set_engine'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_tls_openssl_set_engine_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_tls_openssl_set_engine_msg_size(vapi_msg_tls_openssl_set_engine *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_tls_openssl_set_engine_msg_size(vapi_msg_tls_openssl_set_engine *msg, uword buf_size)
{
  if (sizeof(vapi_msg_tls_openssl_set_engine) > buf_size)
    {
      VAPI_ERR("Truncated 'tls_openssl_set_engine' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_tls_openssl_set_engine));
      return -1;
    }
  if (vapi_calc_tls_openssl_set_engine_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'tls_openssl_set_engine' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_tls_openssl_set_engine_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_tls_openssl_set_engine* vapi_alloc_tls_openssl_set_engine(struct vapi_ctx_s *ctx)
{
  vapi_msg_tls_openssl_set_engine *msg = NULL;
  const size_t size = sizeof(vapi_msg_tls_openssl_set_engine);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_tls_openssl_set_engine*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_tls_openssl_set_engine);

  return msg;
}

static inline vapi_error_e vapi_tls_openssl_set_engine(struct vapi_ctx_s *ctx,
  vapi_msg_tls_openssl_set_engine *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_tls_openssl_set_engine_reply *reply),
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
  vapi_msg_tls_openssl_set_engine_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_tls_openssl_set_engine_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_tls_openssl_set_engine_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_tls_openssl_set_engine()
{
  static const char name[] = "tls_openssl_set_engine";
  static const char name_with_crc[] = "tls_openssl_set_engine_e34d95c1";
  static vapi_message_desc_t __vapi_metadata_tls_openssl_set_engine = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_tls_openssl_set_engine, payload),
    (verify_msg_size_fn_t)vapi_verify_tls_openssl_set_engine_msg_size,
    (generic_swap_fn_t)vapi_msg_tls_openssl_set_engine_hton,
    (generic_swap_fn_t)vapi_msg_tls_openssl_set_engine_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_tls_openssl_set_engine = vapi_register_msg(&__vapi_metadata_tls_openssl_set_engine);
  VAPI_DBG("Assigned msg id %d to tls_openssl_set_engine", vapi_msg_id_tls_openssl_set_engine);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
