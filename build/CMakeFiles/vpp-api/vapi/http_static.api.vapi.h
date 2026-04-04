#ifndef __included_http_static_api_json
#define __included_http_static_api_json

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

extern vapi_msg_id_t vapi_msg_id_http_static_enable_v4;
extern vapi_msg_id_t vapi_msg_id_http_static_enable_v4_reply;
extern vapi_msg_id_t vapi_msg_id_http_static_enable_v5;
extern vapi_msg_id_t vapi_msg_id_http_static_enable_v5_reply;

#define DEFINE_VAPI_MSG_IDS_HTTP_STATIC_API_JSON\
  vapi_msg_id_t vapi_msg_id_http_static_enable_v4;\
  vapi_msg_id_t vapi_msg_id_http_static_enable_v4_reply;\
  vapi_msg_id_t vapi_msg_id_http_static_enable_v5;\
  vapi_msg_id_t vapi_msg_id_http_static_enable_v5_reply;


#ifndef defined_vapi_msg_http_static_enable_v4_reply
#define defined_vapi_msg_http_static_enable_v4_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_http_static_enable_v4_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_http_static_enable_v4_reply payload;
} vapi_msg_http_static_enable_v4_reply;

static inline void vapi_msg_http_static_enable_v4_reply_payload_hton(vapi_payload_http_static_enable_v4_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_http_static_enable_v4_reply_payload_ntoh(vapi_payload_http_static_enable_v4_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_http_static_enable_v4_reply_hton(vapi_msg_http_static_enable_v4_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_http_static_enable_v4_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_http_static_enable_v4_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_http_static_enable_v4_reply_ntoh(vapi_msg_http_static_enable_v4_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_http_static_enable_v4_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_http_static_enable_v4_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_http_static_enable_v4_reply_msg_size(vapi_msg_http_static_enable_v4_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_http_static_enable_v4_reply_msg_size(vapi_msg_http_static_enable_v4_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_http_static_enable_v4_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'http_static_enable_v4_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_http_static_enable_v4_reply));
      return -1;
    }
  if (vapi_calc_http_static_enable_v4_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'http_static_enable_v4_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_http_static_enable_v4_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_http_static_enable_v4_reply()
{
  static const char name[] = "http_static_enable_v4_reply";
  static const char name_with_crc[] = "http_static_enable_v4_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_http_static_enable_v4_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_http_static_enable_v4_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_http_static_enable_v4_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_http_static_enable_v4_reply_hton,
    (generic_swap_fn_t)vapi_msg_http_static_enable_v4_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_http_static_enable_v4_reply = vapi_register_msg(&__vapi_metadata_http_static_enable_v4_reply);
  VAPI_DBG("Assigned msg id %d to http_static_enable_v4_reply", vapi_msg_id_http_static_enable_v4_reply);
}

static inline void vapi_set_vapi_msg_http_static_enable_v4_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_http_static_enable_v4_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_http_static_enable_v4_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_http_static_enable_v4
#define defined_vapi_msg_http_static_enable_v4
typedef struct __attribute__ ((__packed__)) {
  u32 fifo_size;
  u32 cache_size_limit;
  u32 max_age;
  u32 keepalive_timeout;
  u64 max_body_size;
  u32 prealloc_fifos;
  u32 private_segment_size;
  u8 www_root[256];
  u8 uri[256]; 
} vapi_payload_http_static_enable_v4;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_http_static_enable_v4 payload;
} vapi_msg_http_static_enable_v4;

static inline void vapi_msg_http_static_enable_v4_payload_hton(vapi_payload_http_static_enable_v4 *payload)
{
  payload->fifo_size = htobe32(payload->fifo_size);
  payload->cache_size_limit = htobe32(payload->cache_size_limit);
  payload->max_age = htobe32(payload->max_age);
  payload->keepalive_timeout = htobe32(payload->keepalive_timeout);
  payload->max_body_size = htobe64(payload->max_body_size);
  payload->prealloc_fifos = htobe32(payload->prealloc_fifos);
  payload->private_segment_size = htobe32(payload->private_segment_size);
}

static inline void vapi_msg_http_static_enable_v4_payload_ntoh(vapi_payload_http_static_enable_v4 *payload)
{
  payload->fifo_size = be32toh(payload->fifo_size);
  payload->cache_size_limit = be32toh(payload->cache_size_limit);
  payload->max_age = be32toh(payload->max_age);
  payload->keepalive_timeout = be32toh(payload->keepalive_timeout);
  payload->max_body_size = be64toh(payload->max_body_size);
  payload->prealloc_fifos = be32toh(payload->prealloc_fifos);
  payload->private_segment_size = be32toh(payload->private_segment_size);
}

static inline void vapi_msg_http_static_enable_v4_hton(vapi_msg_http_static_enable_v4 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_http_static_enable_v4'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_http_static_enable_v4_payload_hton(&msg->payload);
}

static inline void vapi_msg_http_static_enable_v4_ntoh(vapi_msg_http_static_enable_v4 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_http_static_enable_v4'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_http_static_enable_v4_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_http_static_enable_v4_msg_size(vapi_msg_http_static_enable_v4 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_http_static_enable_v4_msg_size(vapi_msg_http_static_enable_v4 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_http_static_enable_v4) > buf_size)
    {
      VAPI_ERR("Truncated 'http_static_enable_v4' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_http_static_enable_v4));
      return -1;
    }
  if (vapi_calc_http_static_enable_v4_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'http_static_enable_v4' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_http_static_enable_v4_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_http_static_enable_v4* vapi_alloc_http_static_enable_v4(struct vapi_ctx_s *ctx)
{
  vapi_msg_http_static_enable_v4 *msg = NULL;
  const size_t size = sizeof(vapi_msg_http_static_enable_v4);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_http_static_enable_v4*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_http_static_enable_v4);

  return msg;
}

static inline vapi_error_e vapi_http_static_enable_v4(struct vapi_ctx_s *ctx,
  vapi_msg_http_static_enable_v4 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_http_static_enable_v4_reply *reply),
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
  vapi_msg_http_static_enable_v4_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_http_static_enable_v4_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_http_static_enable_v4_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_http_static_enable_v4()
{
  static const char name[] = "http_static_enable_v4";
  static const char name_with_crc[] = "http_static_enable_v4_37540bfc";
  static vapi_message_desc_t __vapi_metadata_http_static_enable_v4 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_http_static_enable_v4, payload),
    (verify_msg_size_fn_t)vapi_verify_http_static_enable_v4_msg_size,
    (generic_swap_fn_t)vapi_msg_http_static_enable_v4_hton,
    (generic_swap_fn_t)vapi_msg_http_static_enable_v4_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_http_static_enable_v4 = vapi_register_msg(&__vapi_metadata_http_static_enable_v4);
  VAPI_DBG("Assigned msg id %d to http_static_enable_v4", vapi_msg_id_http_static_enable_v4);
}
#endif

#ifndef defined_vapi_msg_http_static_enable_v5_reply
#define defined_vapi_msg_http_static_enable_v5_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_http_static_enable_v5_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_http_static_enable_v5_reply payload;
} vapi_msg_http_static_enable_v5_reply;

static inline void vapi_msg_http_static_enable_v5_reply_payload_hton(vapi_payload_http_static_enable_v5_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_http_static_enable_v5_reply_payload_ntoh(vapi_payload_http_static_enable_v5_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_http_static_enable_v5_reply_hton(vapi_msg_http_static_enable_v5_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_http_static_enable_v5_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_http_static_enable_v5_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_http_static_enable_v5_reply_ntoh(vapi_msg_http_static_enable_v5_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_http_static_enable_v5_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_http_static_enable_v5_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_http_static_enable_v5_reply_msg_size(vapi_msg_http_static_enable_v5_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_http_static_enable_v5_reply_msg_size(vapi_msg_http_static_enable_v5_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_http_static_enable_v5_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'http_static_enable_v5_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_http_static_enable_v5_reply));
      return -1;
    }
  if (vapi_calc_http_static_enable_v5_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'http_static_enable_v5_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_http_static_enable_v5_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_http_static_enable_v5_reply()
{
  static const char name[] = "http_static_enable_v5_reply";
  static const char name_with_crc[] = "http_static_enable_v5_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_http_static_enable_v5_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_http_static_enable_v5_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_http_static_enable_v5_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_http_static_enable_v5_reply_hton,
    (generic_swap_fn_t)vapi_msg_http_static_enable_v5_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_http_static_enable_v5_reply = vapi_register_msg(&__vapi_metadata_http_static_enable_v5_reply);
  VAPI_DBG("Assigned msg id %d to http_static_enable_v5_reply", vapi_msg_id_http_static_enable_v5_reply);
}

static inline void vapi_set_vapi_msg_http_static_enable_v5_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_http_static_enable_v5_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_http_static_enable_v5_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_http_static_enable_v5
#define defined_vapi_msg_http_static_enable_v5
typedef struct __attribute__ ((__packed__)) {
  u32 fifo_size;
  u32 cache_size_limit;
  u32 max_age;
  u32 keepalive_timeout;
  u64 max_body_size;
  u32 rx_buff_thresh;
  u32 prealloc_fifos;
  u32 private_segment_size;
  u8 www_root[256];
  u8 uri[256]; 
} vapi_payload_http_static_enable_v5;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_http_static_enable_v5 payload;
} vapi_msg_http_static_enable_v5;

static inline void vapi_msg_http_static_enable_v5_payload_hton(vapi_payload_http_static_enable_v5 *payload)
{
  payload->fifo_size = htobe32(payload->fifo_size);
  payload->cache_size_limit = htobe32(payload->cache_size_limit);
  payload->max_age = htobe32(payload->max_age);
  payload->keepalive_timeout = htobe32(payload->keepalive_timeout);
  payload->max_body_size = htobe64(payload->max_body_size);
  payload->rx_buff_thresh = htobe32(payload->rx_buff_thresh);
  payload->prealloc_fifos = htobe32(payload->prealloc_fifos);
  payload->private_segment_size = htobe32(payload->private_segment_size);
}

static inline void vapi_msg_http_static_enable_v5_payload_ntoh(vapi_payload_http_static_enable_v5 *payload)
{
  payload->fifo_size = be32toh(payload->fifo_size);
  payload->cache_size_limit = be32toh(payload->cache_size_limit);
  payload->max_age = be32toh(payload->max_age);
  payload->keepalive_timeout = be32toh(payload->keepalive_timeout);
  payload->max_body_size = be64toh(payload->max_body_size);
  payload->rx_buff_thresh = be32toh(payload->rx_buff_thresh);
  payload->prealloc_fifos = be32toh(payload->prealloc_fifos);
  payload->private_segment_size = be32toh(payload->private_segment_size);
}

static inline void vapi_msg_http_static_enable_v5_hton(vapi_msg_http_static_enable_v5 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_http_static_enable_v5'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_http_static_enable_v5_payload_hton(&msg->payload);
}

static inline void vapi_msg_http_static_enable_v5_ntoh(vapi_msg_http_static_enable_v5 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_http_static_enable_v5'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_http_static_enable_v5_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_http_static_enable_v5_msg_size(vapi_msg_http_static_enable_v5 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_http_static_enable_v5_msg_size(vapi_msg_http_static_enable_v5 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_http_static_enable_v5) > buf_size)
    {
      VAPI_ERR("Truncated 'http_static_enable_v5' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_http_static_enable_v5));
      return -1;
    }
  if (vapi_calc_http_static_enable_v5_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'http_static_enable_v5' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_http_static_enable_v5_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_http_static_enable_v5* vapi_alloc_http_static_enable_v5(struct vapi_ctx_s *ctx)
{
  vapi_msg_http_static_enable_v5 *msg = NULL;
  const size_t size = sizeof(vapi_msg_http_static_enable_v5);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_http_static_enable_v5*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_http_static_enable_v5);

  return msg;
}

static inline vapi_error_e vapi_http_static_enable_v5(struct vapi_ctx_s *ctx,
  vapi_msg_http_static_enable_v5 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_http_static_enable_v5_reply *reply),
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
  vapi_msg_http_static_enable_v5_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_http_static_enable_v5_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_http_static_enable_v5_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_http_static_enable_v5()
{
  static const char name[] = "http_static_enable_v5";
  static const char name_with_crc[] = "http_static_enable_v5_8bf84069";
  static vapi_message_desc_t __vapi_metadata_http_static_enable_v5 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_http_static_enable_v5, payload),
    (verify_msg_size_fn_t)vapi_verify_http_static_enable_v5_msg_size,
    (generic_swap_fn_t)vapi_msg_http_static_enable_v5_hton,
    (generic_swap_fn_t)vapi_msg_http_static_enable_v5_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_http_static_enable_v5 = vapi_register_msg(&__vapi_metadata_http_static_enable_v5);
  VAPI_DBG("Assigned msg id %d to http_static_enable_v5", vapi_msg_id_http_static_enable_v5);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
