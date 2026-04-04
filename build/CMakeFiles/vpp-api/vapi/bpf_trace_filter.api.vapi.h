#ifndef __included_bpf_trace_filter_api_json
#define __included_bpf_trace_filter_api_json

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

extern vapi_msg_id_t vapi_msg_id_bpf_trace_filter_set;
extern vapi_msg_id_t vapi_msg_id_bpf_trace_filter_set_reply;
extern vapi_msg_id_t vapi_msg_id_bpf_trace_filter_set_v2;
extern vapi_msg_id_t vapi_msg_id_bpf_trace_filter_set_v2_reply;

#define DEFINE_VAPI_MSG_IDS_BPF_TRACE_FILTER_API_JSON\
  vapi_msg_id_t vapi_msg_id_bpf_trace_filter_set;\
  vapi_msg_id_t vapi_msg_id_bpf_trace_filter_set_reply;\
  vapi_msg_id_t vapi_msg_id_bpf_trace_filter_set_v2;\
  vapi_msg_id_t vapi_msg_id_bpf_trace_filter_set_v2_reply;


#ifndef defined_vapi_msg_bpf_trace_filter_set_reply
#define defined_vapi_msg_bpf_trace_filter_set_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bpf_trace_filter_set_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bpf_trace_filter_set_reply payload;
} vapi_msg_bpf_trace_filter_set_reply;

static inline void vapi_msg_bpf_trace_filter_set_reply_payload_hton(vapi_payload_bpf_trace_filter_set_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bpf_trace_filter_set_reply_payload_ntoh(vapi_payload_bpf_trace_filter_set_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bpf_trace_filter_set_reply_hton(vapi_msg_bpf_trace_filter_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bpf_trace_filter_set_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bpf_trace_filter_set_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bpf_trace_filter_set_reply_ntoh(vapi_msg_bpf_trace_filter_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bpf_trace_filter_set_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bpf_trace_filter_set_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bpf_trace_filter_set_reply_msg_size(vapi_msg_bpf_trace_filter_set_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bpf_trace_filter_set_reply_msg_size(vapi_msg_bpf_trace_filter_set_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bpf_trace_filter_set_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bpf_trace_filter_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bpf_trace_filter_set_reply));
      return -1;
    }
  if (vapi_calc_bpf_trace_filter_set_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bpf_trace_filter_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bpf_trace_filter_set_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bpf_trace_filter_set_reply()
{
  static const char name[] = "bpf_trace_filter_set_reply";
  static const char name_with_crc[] = "bpf_trace_filter_set_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bpf_trace_filter_set_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bpf_trace_filter_set_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bpf_trace_filter_set_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bpf_trace_filter_set_reply_hton,
    (generic_swap_fn_t)vapi_msg_bpf_trace_filter_set_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bpf_trace_filter_set_reply = vapi_register_msg(&__vapi_metadata_bpf_trace_filter_set_reply);
  VAPI_DBG("Assigned msg id %d to bpf_trace_filter_set_reply", vapi_msg_id_bpf_trace_filter_set_reply);
}

static inline void vapi_set_vapi_msg_bpf_trace_filter_set_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bpf_trace_filter_set_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bpf_trace_filter_set_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bpf_trace_filter_set
#define defined_vapi_msg_bpf_trace_filter_set
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vl_api_string_t filter; 
} vapi_payload_bpf_trace_filter_set;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bpf_trace_filter_set payload;
} vapi_msg_bpf_trace_filter_set;

static inline void vapi_msg_bpf_trace_filter_set_payload_hton(vapi_payload_bpf_trace_filter_set *payload)
{
  vl_api_string_t_hton(&payload->filter);
}

static inline void vapi_msg_bpf_trace_filter_set_payload_ntoh(vapi_payload_bpf_trace_filter_set *payload)
{
  vl_api_string_t_ntoh(&payload->filter);
}

static inline void vapi_msg_bpf_trace_filter_set_hton(vapi_msg_bpf_trace_filter_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bpf_trace_filter_set'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bpf_trace_filter_set_payload_hton(&msg->payload);
}

static inline void vapi_msg_bpf_trace_filter_set_ntoh(vapi_msg_bpf_trace_filter_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bpf_trace_filter_set'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bpf_trace_filter_set_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bpf_trace_filter_set_msg_size(vapi_msg_bpf_trace_filter_set *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.filter.buf[0]) * msg->payload.filter.length;
}

static inline int vapi_verify_bpf_trace_filter_set_msg_size(vapi_msg_bpf_trace_filter_set *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bpf_trace_filter_set) > buf_size)
    {
      VAPI_ERR("Truncated 'bpf_trace_filter_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bpf_trace_filter_set));
      return -1;
    }
  if (vapi_calc_bpf_trace_filter_set_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bpf_trace_filter_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bpf_trace_filter_set_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bpf_trace_filter_set* vapi_alloc_bpf_trace_filter_set(struct vapi_ctx_s *ctx, size_t filter_buf_array_size)
{
  vapi_msg_bpf_trace_filter_set *msg = NULL;
  const size_t size = sizeof(vapi_msg_bpf_trace_filter_set) + sizeof(msg->payload.filter.buf[0]) * filter_buf_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bpf_trace_filter_set*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bpf_trace_filter_set);
  msg->payload.filter.length = filter_buf_array_size;

  return msg;
}

static inline vapi_error_e vapi_bpf_trace_filter_set(struct vapi_ctx_s *ctx,
  vapi_msg_bpf_trace_filter_set *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bpf_trace_filter_set_reply *reply),
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
  vapi_msg_bpf_trace_filter_set_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bpf_trace_filter_set_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bpf_trace_filter_set_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bpf_trace_filter_set()
{
  static const char name[] = "bpf_trace_filter_set";
  static const char name_with_crc[] = "bpf_trace_filter_set_3171346e";
  static vapi_message_desc_t __vapi_metadata_bpf_trace_filter_set = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bpf_trace_filter_set, payload),
    (verify_msg_size_fn_t)vapi_verify_bpf_trace_filter_set_msg_size,
    (generic_swap_fn_t)vapi_msg_bpf_trace_filter_set_hton,
    (generic_swap_fn_t)vapi_msg_bpf_trace_filter_set_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bpf_trace_filter_set = vapi_register_msg(&__vapi_metadata_bpf_trace_filter_set);
  VAPI_DBG("Assigned msg id %d to bpf_trace_filter_set", vapi_msg_id_bpf_trace_filter_set);
}
#endif

#ifndef defined_vapi_msg_bpf_trace_filter_set_v2_reply
#define defined_vapi_msg_bpf_trace_filter_set_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bpf_trace_filter_set_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bpf_trace_filter_set_v2_reply payload;
} vapi_msg_bpf_trace_filter_set_v2_reply;

static inline void vapi_msg_bpf_trace_filter_set_v2_reply_payload_hton(vapi_payload_bpf_trace_filter_set_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bpf_trace_filter_set_v2_reply_payload_ntoh(vapi_payload_bpf_trace_filter_set_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bpf_trace_filter_set_v2_reply_hton(vapi_msg_bpf_trace_filter_set_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bpf_trace_filter_set_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bpf_trace_filter_set_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bpf_trace_filter_set_v2_reply_ntoh(vapi_msg_bpf_trace_filter_set_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bpf_trace_filter_set_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bpf_trace_filter_set_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bpf_trace_filter_set_v2_reply_msg_size(vapi_msg_bpf_trace_filter_set_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bpf_trace_filter_set_v2_reply_msg_size(vapi_msg_bpf_trace_filter_set_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bpf_trace_filter_set_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bpf_trace_filter_set_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bpf_trace_filter_set_v2_reply));
      return -1;
    }
  if (vapi_calc_bpf_trace_filter_set_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bpf_trace_filter_set_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bpf_trace_filter_set_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bpf_trace_filter_set_v2_reply()
{
  static const char name[] = "bpf_trace_filter_set_v2_reply";
  static const char name_with_crc[] = "bpf_trace_filter_set_v2_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bpf_trace_filter_set_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bpf_trace_filter_set_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bpf_trace_filter_set_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bpf_trace_filter_set_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_bpf_trace_filter_set_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bpf_trace_filter_set_v2_reply = vapi_register_msg(&__vapi_metadata_bpf_trace_filter_set_v2_reply);
  VAPI_DBG("Assigned msg id %d to bpf_trace_filter_set_v2_reply", vapi_msg_id_bpf_trace_filter_set_v2_reply);
}

static inline void vapi_set_vapi_msg_bpf_trace_filter_set_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bpf_trace_filter_set_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bpf_trace_filter_set_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bpf_trace_filter_set_v2
#define defined_vapi_msg_bpf_trace_filter_set_v2
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  bool optimize;
  vl_api_string_t filter; 
} vapi_payload_bpf_trace_filter_set_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bpf_trace_filter_set_v2 payload;
} vapi_msg_bpf_trace_filter_set_v2;

static inline void vapi_msg_bpf_trace_filter_set_v2_payload_hton(vapi_payload_bpf_trace_filter_set_v2 *payload)
{
  vl_api_string_t_hton(&payload->filter);
}

static inline void vapi_msg_bpf_trace_filter_set_v2_payload_ntoh(vapi_payload_bpf_trace_filter_set_v2 *payload)
{
  vl_api_string_t_ntoh(&payload->filter);
}

static inline void vapi_msg_bpf_trace_filter_set_v2_hton(vapi_msg_bpf_trace_filter_set_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bpf_trace_filter_set_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bpf_trace_filter_set_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_bpf_trace_filter_set_v2_ntoh(vapi_msg_bpf_trace_filter_set_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bpf_trace_filter_set_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bpf_trace_filter_set_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bpf_trace_filter_set_v2_msg_size(vapi_msg_bpf_trace_filter_set_v2 *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.filter.buf[0]) * msg->payload.filter.length;
}

static inline int vapi_verify_bpf_trace_filter_set_v2_msg_size(vapi_msg_bpf_trace_filter_set_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bpf_trace_filter_set_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'bpf_trace_filter_set_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bpf_trace_filter_set_v2));
      return -1;
    }
  if (vapi_calc_bpf_trace_filter_set_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bpf_trace_filter_set_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bpf_trace_filter_set_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bpf_trace_filter_set_v2* vapi_alloc_bpf_trace_filter_set_v2(struct vapi_ctx_s *ctx, size_t filter_buf_array_size)
{
  vapi_msg_bpf_trace_filter_set_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_bpf_trace_filter_set_v2) + sizeof(msg->payload.filter.buf[0]) * filter_buf_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bpf_trace_filter_set_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bpf_trace_filter_set_v2);
  msg->payload.filter.length = filter_buf_array_size;

  return msg;
}

static inline vapi_error_e vapi_bpf_trace_filter_set_v2(struct vapi_ctx_s *ctx,
  vapi_msg_bpf_trace_filter_set_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bpf_trace_filter_set_v2_reply *reply),
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
  vapi_msg_bpf_trace_filter_set_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bpf_trace_filter_set_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bpf_trace_filter_set_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bpf_trace_filter_set_v2()
{
  static const char name[] = "bpf_trace_filter_set_v2";
  static const char name_with_crc[] = "bpf_trace_filter_set_v2_5615acbf";
  static vapi_message_desc_t __vapi_metadata_bpf_trace_filter_set_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bpf_trace_filter_set_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_bpf_trace_filter_set_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_bpf_trace_filter_set_v2_hton,
    (generic_swap_fn_t)vapi_msg_bpf_trace_filter_set_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bpf_trace_filter_set_v2 = vapi_register_msg(&__vapi_metadata_bpf_trace_filter_set_v2);
  VAPI_DBG("Assigned msg id %d to bpf_trace_filter_set_v2", vapi_msg_id_bpf_trace_filter_set_v2);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
