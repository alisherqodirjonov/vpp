#ifndef __included_fake_api_json
#define __included_fake_api_json

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

extern vapi_msg_id_t vapi_msg_id_test_fake_msg;
extern vapi_msg_id_t vapi_msg_id_test_fake_msg_reply;
extern vapi_msg_id_t vapi_msg_id_test_fake_dump;
extern vapi_msg_id_t vapi_msg_id_test_fake_details;

#define DEFINE_VAPI_MSG_IDS_FAKE_API_JSON\
  vapi_msg_id_t vapi_msg_id_test_fake_msg;\
  vapi_msg_id_t vapi_msg_id_test_fake_msg_reply;\
  vapi_msg_id_t vapi_msg_id_test_fake_dump;\
  vapi_msg_id_t vapi_msg_id_test_fake_details;


#ifndef defined_vapi_msg_test_fake_msg_reply
#define defined_vapi_msg_test_fake_msg_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_test_fake_msg_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_test_fake_msg_reply payload;
} vapi_msg_test_fake_msg_reply;

static inline void vapi_msg_test_fake_msg_reply_payload_hton(vapi_payload_test_fake_msg_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_test_fake_msg_reply_payload_ntoh(vapi_payload_test_fake_msg_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_test_fake_msg_reply_hton(vapi_msg_test_fake_msg_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_test_fake_msg_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_test_fake_msg_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_test_fake_msg_reply_ntoh(vapi_msg_test_fake_msg_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_test_fake_msg_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_test_fake_msg_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_test_fake_msg_reply_msg_size(vapi_msg_test_fake_msg_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_test_fake_msg_reply_msg_size(vapi_msg_test_fake_msg_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_test_fake_msg_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'test_fake_msg_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_test_fake_msg_reply));
      return -1;
    }
  if (vapi_calc_test_fake_msg_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'test_fake_msg_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_test_fake_msg_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_test_fake_msg_reply()
{
  static const char name[] = "test_fake_msg_reply";
  static const char name_with_crc[] = "test_fake_msg_reply_cafebafe";
  static vapi_message_desc_t __vapi_metadata_test_fake_msg_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_test_fake_msg_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_test_fake_msg_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_test_fake_msg_reply_hton,
    (generic_swap_fn_t)vapi_msg_test_fake_msg_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_test_fake_msg_reply = vapi_register_msg(&__vapi_metadata_test_fake_msg_reply);
  VAPI_DBG("Assigned msg id %d to test_fake_msg_reply", vapi_msg_id_test_fake_msg_reply);
}

static inline void vapi_set_vapi_msg_test_fake_msg_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_test_fake_msg_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_test_fake_msg_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_test_fake_msg
#define defined_vapi_msg_test_fake_msg
typedef struct __attribute__ ((__packed__)) {
  u8 dummy[256]; 
} vapi_payload_test_fake_msg;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_test_fake_msg payload;
} vapi_msg_test_fake_msg;

static inline void vapi_msg_test_fake_msg_payload_hton(vapi_payload_test_fake_msg *payload)
{

}

static inline void vapi_msg_test_fake_msg_payload_ntoh(vapi_payload_test_fake_msg *payload)
{

}

static inline void vapi_msg_test_fake_msg_hton(vapi_msg_test_fake_msg *msg)
{
  VAPI_DBG("Swapping `vapi_msg_test_fake_msg'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_test_fake_msg_payload_hton(&msg->payload);
}

static inline void vapi_msg_test_fake_msg_ntoh(vapi_msg_test_fake_msg *msg)
{
  VAPI_DBG("Swapping `vapi_msg_test_fake_msg'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_test_fake_msg_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_test_fake_msg_msg_size(vapi_msg_test_fake_msg *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_test_fake_msg_msg_size(vapi_msg_test_fake_msg *msg, uword buf_size)
{
  if (sizeof(vapi_msg_test_fake_msg) > buf_size)
    {
      VAPI_ERR("Truncated 'test_fake_msg' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_test_fake_msg));
      return -1;
    }
  if (vapi_calc_test_fake_msg_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'test_fake_msg' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_test_fake_msg_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_test_fake_msg* vapi_alloc_test_fake_msg(struct vapi_ctx_s *ctx)
{
  vapi_msg_test_fake_msg *msg = NULL;
  const size_t size = sizeof(vapi_msg_test_fake_msg);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_test_fake_msg*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_test_fake_msg);

  return msg;
}

static inline vapi_error_e vapi_test_fake_msg(struct vapi_ctx_s *ctx,
  vapi_msg_test_fake_msg *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_test_fake_msg_reply *reply),
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
  vapi_msg_test_fake_msg_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_test_fake_msg_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_test_fake_msg_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_test_fake_msg()
{
  static const char name[] = "test_fake_msg";
  static const char name_with_crc[] = "test_fake_msg_cafebafe";
  static vapi_message_desc_t __vapi_metadata_test_fake_msg = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_test_fake_msg, payload),
    (verify_msg_size_fn_t)vapi_verify_test_fake_msg_msg_size,
    (generic_swap_fn_t)vapi_msg_test_fake_msg_hton,
    (generic_swap_fn_t)vapi_msg_test_fake_msg_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_test_fake_msg = vapi_register_msg(&__vapi_metadata_test_fake_msg);
  VAPI_DBG("Assigned msg id %d to test_fake_msg", vapi_msg_id_test_fake_msg);
}
#endif

#ifndef defined_vapi_msg_test_fake_details
#define defined_vapi_msg_test_fake_details
typedef struct __attribute__ ((__packed__)) {
  u32 dummy; 
} vapi_payload_test_fake_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_test_fake_details payload;
} vapi_msg_test_fake_details;

static inline void vapi_msg_test_fake_details_payload_hton(vapi_payload_test_fake_details *payload)
{
  payload->dummy = htobe32(payload->dummy);
}

static inline void vapi_msg_test_fake_details_payload_ntoh(vapi_payload_test_fake_details *payload)
{
  payload->dummy = be32toh(payload->dummy);
}

static inline void vapi_msg_test_fake_details_hton(vapi_msg_test_fake_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_test_fake_details'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_test_fake_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_test_fake_details_ntoh(vapi_msg_test_fake_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_test_fake_details'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_test_fake_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_test_fake_details_msg_size(vapi_msg_test_fake_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_test_fake_details_msg_size(vapi_msg_test_fake_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_test_fake_details) > buf_size)
    {
      VAPI_ERR("Truncated 'test_fake_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_test_fake_details));
      return -1;
    }
  if (vapi_calc_test_fake_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'test_fake_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_test_fake_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_test_fake_details()
{
  static const char name[] = "test_fake_details";
  static const char name_with_crc[] = "test_fake_details_cafebafe";
  static vapi_message_desc_t __vapi_metadata_test_fake_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_test_fake_details, payload),
    (verify_msg_size_fn_t)vapi_verify_test_fake_details_msg_size,
    (generic_swap_fn_t)vapi_msg_test_fake_details_hton,
    (generic_swap_fn_t)vapi_msg_test_fake_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_test_fake_details = vapi_register_msg(&__vapi_metadata_test_fake_details);
  VAPI_DBG("Assigned msg id %d to test_fake_details", vapi_msg_id_test_fake_details);
}

static inline void vapi_set_vapi_msg_test_fake_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_test_fake_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_test_fake_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_test_fake_dump
#define defined_vapi_msg_test_fake_dump
typedef struct __attribute__ ((__packed__)) {
  u32 dummy; 
} vapi_payload_test_fake_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_test_fake_dump payload;
} vapi_msg_test_fake_dump;

static inline void vapi_msg_test_fake_dump_payload_hton(vapi_payload_test_fake_dump *payload)
{
  payload->dummy = htobe32(payload->dummy);
}

static inline void vapi_msg_test_fake_dump_payload_ntoh(vapi_payload_test_fake_dump *payload)
{
  payload->dummy = be32toh(payload->dummy);
}

static inline void vapi_msg_test_fake_dump_hton(vapi_msg_test_fake_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_test_fake_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_test_fake_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_test_fake_dump_ntoh(vapi_msg_test_fake_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_test_fake_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_test_fake_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_test_fake_dump_msg_size(vapi_msg_test_fake_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_test_fake_dump_msg_size(vapi_msg_test_fake_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_test_fake_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'test_fake_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_test_fake_dump));
      return -1;
    }
  if (vapi_calc_test_fake_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'test_fake_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_test_fake_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_test_fake_dump* vapi_alloc_test_fake_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_test_fake_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_test_fake_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_test_fake_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_test_fake_dump);

  return msg;
}

static inline vapi_error_e vapi_test_fake_dump(struct vapi_ctx_s *ctx,
  vapi_msg_test_fake_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_test_fake_details *reply),
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
  vapi_msg_test_fake_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_test_fake_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_test_fake_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_test_fake_dump()
{
  static const char name[] = "test_fake_dump";
  static const char name_with_crc[] = "test_fake_dump_cafebafe";
  static vapi_message_desc_t __vapi_metadata_test_fake_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_test_fake_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_test_fake_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_test_fake_dump_hton,
    (generic_swap_fn_t)vapi_msg_test_fake_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_test_fake_dump = vapi_register_msg(&__vapi_metadata_test_fake_dump);
  VAPI_DBG("Assigned msg id %d to test_fake_dump", vapi_msg_id_test_fake_dump);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
