#ifndef __included_tracedump_api_json
#define __included_tracedump_api_json

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

extern vapi_msg_id_t vapi_msg_id_trace_set_filters;
extern vapi_msg_id_t vapi_msg_id_trace_set_filters_reply;
extern vapi_msg_id_t vapi_msg_id_trace_capture_packets;
extern vapi_msg_id_t vapi_msg_id_trace_capture_packets_reply;
extern vapi_msg_id_t vapi_msg_id_trace_clear_capture;
extern vapi_msg_id_t vapi_msg_id_trace_clear_capture_reply;
extern vapi_msg_id_t vapi_msg_id_trace_dump;
extern vapi_msg_id_t vapi_msg_id_trace_dump_reply;
extern vapi_msg_id_t vapi_msg_id_trace_details;
extern vapi_msg_id_t vapi_msg_id_trace_clear_cache;
extern vapi_msg_id_t vapi_msg_id_trace_clear_cache_reply;
extern vapi_msg_id_t vapi_msg_id_trace_v2_dump;
extern vapi_msg_id_t vapi_msg_id_trace_v2_details;
extern vapi_msg_id_t vapi_msg_id_trace_set_filter_function;
extern vapi_msg_id_t vapi_msg_id_trace_set_filter_function_reply;
extern vapi_msg_id_t vapi_msg_id_trace_filter_function_dump;
extern vapi_msg_id_t vapi_msg_id_trace_filter_function_details;

#define DEFINE_VAPI_MSG_IDS_TRACEDUMP_API_JSON\
  vapi_msg_id_t vapi_msg_id_trace_set_filters;\
  vapi_msg_id_t vapi_msg_id_trace_set_filters_reply;\
  vapi_msg_id_t vapi_msg_id_trace_capture_packets;\
  vapi_msg_id_t vapi_msg_id_trace_capture_packets_reply;\
  vapi_msg_id_t vapi_msg_id_trace_clear_capture;\
  vapi_msg_id_t vapi_msg_id_trace_clear_capture_reply;\
  vapi_msg_id_t vapi_msg_id_trace_dump;\
  vapi_msg_id_t vapi_msg_id_trace_dump_reply;\
  vapi_msg_id_t vapi_msg_id_trace_details;\
  vapi_msg_id_t vapi_msg_id_trace_clear_cache;\
  vapi_msg_id_t vapi_msg_id_trace_clear_cache_reply;\
  vapi_msg_id_t vapi_msg_id_trace_v2_dump;\
  vapi_msg_id_t vapi_msg_id_trace_v2_details;\
  vapi_msg_id_t vapi_msg_id_trace_set_filter_function;\
  vapi_msg_id_t vapi_msg_id_trace_set_filter_function_reply;\
  vapi_msg_id_t vapi_msg_id_trace_filter_function_dump;\
  vapi_msg_id_t vapi_msg_id_trace_filter_function_details;


#ifndef defined_vapi_enum_trace_filter_flag
#define defined_vapi_enum_trace_filter_flag
typedef enum {
  TRACE_FF_NONE = 0,
  TRACE_FF_INCLUDE_NODE = 1,
  TRACE_FF_EXCLUDE_NODE = 2,
  TRACE_FF_INCLUDE_CLASSIFIER = 3,
  TRACE_FF_EXCLUDE_CLASSIFIER = 4,
}  vapi_enum_trace_filter_flag;

#endif

#ifndef defined_vapi_msg_trace_set_filters_reply
#define defined_vapi_msg_trace_set_filters_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_trace_set_filters_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_trace_set_filters_reply payload;
} vapi_msg_trace_set_filters_reply;

static inline void vapi_msg_trace_set_filters_reply_payload_hton(vapi_payload_trace_set_filters_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_trace_set_filters_reply_payload_ntoh(vapi_payload_trace_set_filters_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_trace_set_filters_reply_hton(vapi_msg_trace_set_filters_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_set_filters_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_trace_set_filters_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_trace_set_filters_reply_ntoh(vapi_msg_trace_set_filters_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_set_filters_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_trace_set_filters_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_trace_set_filters_reply_msg_size(vapi_msg_trace_set_filters_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_trace_set_filters_reply_msg_size(vapi_msg_trace_set_filters_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_trace_set_filters_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_set_filters_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_trace_set_filters_reply));
      return -1;
    }
  if (vapi_calc_trace_set_filters_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_set_filters_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_trace_set_filters_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_trace_set_filters_reply()
{
  static const char name[] = "trace_set_filters_reply";
  static const char name_with_crc[] = "trace_set_filters_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_trace_set_filters_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_trace_set_filters_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_trace_set_filters_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_trace_set_filters_reply_hton,
    (generic_swap_fn_t)vapi_msg_trace_set_filters_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_trace_set_filters_reply = vapi_register_msg(&__vapi_metadata_trace_set_filters_reply);
  VAPI_DBG("Assigned msg id %d to trace_set_filters_reply", vapi_msg_id_trace_set_filters_reply);
}

static inline void vapi_set_vapi_msg_trace_set_filters_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_trace_set_filters_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_trace_set_filters_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_trace_set_filters
#define defined_vapi_msg_trace_set_filters
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_trace_filter_flag flag;
  u32 count;
  u32 node_index;
  u32 classifier_table_index; 
} vapi_payload_trace_set_filters;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_trace_set_filters payload;
} vapi_msg_trace_set_filters;

static inline void vapi_msg_trace_set_filters_payload_hton(vapi_payload_trace_set_filters *payload)
{
  payload->flag = (vapi_enum_trace_filter_flag)htobe32(payload->flag);
  payload->count = htobe32(payload->count);
  payload->node_index = htobe32(payload->node_index);
  payload->classifier_table_index = htobe32(payload->classifier_table_index);
}

static inline void vapi_msg_trace_set_filters_payload_ntoh(vapi_payload_trace_set_filters *payload)
{
  payload->flag = (vapi_enum_trace_filter_flag)be32toh(payload->flag);
  payload->count = be32toh(payload->count);
  payload->node_index = be32toh(payload->node_index);
  payload->classifier_table_index = be32toh(payload->classifier_table_index);
}

static inline void vapi_msg_trace_set_filters_hton(vapi_msg_trace_set_filters *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_set_filters'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_trace_set_filters_payload_hton(&msg->payload);
}

static inline void vapi_msg_trace_set_filters_ntoh(vapi_msg_trace_set_filters *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_set_filters'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_trace_set_filters_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_trace_set_filters_msg_size(vapi_msg_trace_set_filters *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_trace_set_filters_msg_size(vapi_msg_trace_set_filters *msg, uword buf_size)
{
  if (sizeof(vapi_msg_trace_set_filters) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_set_filters' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_trace_set_filters));
      return -1;
    }
  if (vapi_calc_trace_set_filters_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_set_filters' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_trace_set_filters_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_trace_set_filters* vapi_alloc_trace_set_filters(struct vapi_ctx_s *ctx)
{
  vapi_msg_trace_set_filters *msg = NULL;
  const size_t size = sizeof(vapi_msg_trace_set_filters);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_trace_set_filters*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_trace_set_filters);

  return msg;
}

static inline vapi_error_e vapi_trace_set_filters(struct vapi_ctx_s *ctx,
  vapi_msg_trace_set_filters *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_trace_set_filters_reply *reply),
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
  vapi_msg_trace_set_filters_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_trace_set_filters_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_trace_set_filters_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_trace_set_filters()
{
  static const char name[] = "trace_set_filters";
  static const char name_with_crc[] = "trace_set_filters_f522b44a";
  static vapi_message_desc_t __vapi_metadata_trace_set_filters = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_trace_set_filters, payload),
    (verify_msg_size_fn_t)vapi_verify_trace_set_filters_msg_size,
    (generic_swap_fn_t)vapi_msg_trace_set_filters_hton,
    (generic_swap_fn_t)vapi_msg_trace_set_filters_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_trace_set_filters = vapi_register_msg(&__vapi_metadata_trace_set_filters);
  VAPI_DBG("Assigned msg id %d to trace_set_filters", vapi_msg_id_trace_set_filters);
}
#endif

#ifndef defined_vapi_msg_trace_capture_packets_reply
#define defined_vapi_msg_trace_capture_packets_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_trace_capture_packets_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_trace_capture_packets_reply payload;
} vapi_msg_trace_capture_packets_reply;

static inline void vapi_msg_trace_capture_packets_reply_payload_hton(vapi_payload_trace_capture_packets_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_trace_capture_packets_reply_payload_ntoh(vapi_payload_trace_capture_packets_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_trace_capture_packets_reply_hton(vapi_msg_trace_capture_packets_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_capture_packets_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_trace_capture_packets_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_trace_capture_packets_reply_ntoh(vapi_msg_trace_capture_packets_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_capture_packets_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_trace_capture_packets_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_trace_capture_packets_reply_msg_size(vapi_msg_trace_capture_packets_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_trace_capture_packets_reply_msg_size(vapi_msg_trace_capture_packets_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_trace_capture_packets_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_capture_packets_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_trace_capture_packets_reply));
      return -1;
    }
  if (vapi_calc_trace_capture_packets_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_capture_packets_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_trace_capture_packets_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_trace_capture_packets_reply()
{
  static const char name[] = "trace_capture_packets_reply";
  static const char name_with_crc[] = "trace_capture_packets_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_trace_capture_packets_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_trace_capture_packets_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_trace_capture_packets_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_trace_capture_packets_reply_hton,
    (generic_swap_fn_t)vapi_msg_trace_capture_packets_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_trace_capture_packets_reply = vapi_register_msg(&__vapi_metadata_trace_capture_packets_reply);
  VAPI_DBG("Assigned msg id %d to trace_capture_packets_reply", vapi_msg_id_trace_capture_packets_reply);
}

static inline void vapi_set_vapi_msg_trace_capture_packets_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_trace_capture_packets_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_trace_capture_packets_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_trace_capture_packets
#define defined_vapi_msg_trace_capture_packets
typedef struct __attribute__ ((__packed__)) {
  u32 node_index;
  u32 max_packets;
  bool use_filter;
  bool verbose;
  bool pre_capture_clear; 
} vapi_payload_trace_capture_packets;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_trace_capture_packets payload;
} vapi_msg_trace_capture_packets;

static inline void vapi_msg_trace_capture_packets_payload_hton(vapi_payload_trace_capture_packets *payload)
{
  payload->node_index = htobe32(payload->node_index);
  payload->max_packets = htobe32(payload->max_packets);
}

static inline void vapi_msg_trace_capture_packets_payload_ntoh(vapi_payload_trace_capture_packets *payload)
{
  payload->node_index = be32toh(payload->node_index);
  payload->max_packets = be32toh(payload->max_packets);
}

static inline void vapi_msg_trace_capture_packets_hton(vapi_msg_trace_capture_packets *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_capture_packets'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_trace_capture_packets_payload_hton(&msg->payload);
}

static inline void vapi_msg_trace_capture_packets_ntoh(vapi_msg_trace_capture_packets *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_capture_packets'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_trace_capture_packets_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_trace_capture_packets_msg_size(vapi_msg_trace_capture_packets *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_trace_capture_packets_msg_size(vapi_msg_trace_capture_packets *msg, uword buf_size)
{
  if (sizeof(vapi_msg_trace_capture_packets) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_capture_packets' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_trace_capture_packets));
      return -1;
    }
  if (vapi_calc_trace_capture_packets_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_capture_packets' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_trace_capture_packets_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_trace_capture_packets* vapi_alloc_trace_capture_packets(struct vapi_ctx_s *ctx)
{
  vapi_msg_trace_capture_packets *msg = NULL;
  const size_t size = sizeof(vapi_msg_trace_capture_packets);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_trace_capture_packets*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_trace_capture_packets);

  return msg;
}

static inline vapi_error_e vapi_trace_capture_packets(struct vapi_ctx_s *ctx,
  vapi_msg_trace_capture_packets *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_trace_capture_packets_reply *reply),
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
  vapi_msg_trace_capture_packets_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_trace_capture_packets_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_trace_capture_packets_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_trace_capture_packets()
{
  static const char name[] = "trace_capture_packets";
  static const char name_with_crc[] = "trace_capture_packets_9e791a9b";
  static vapi_message_desc_t __vapi_metadata_trace_capture_packets = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_trace_capture_packets, payload),
    (verify_msg_size_fn_t)vapi_verify_trace_capture_packets_msg_size,
    (generic_swap_fn_t)vapi_msg_trace_capture_packets_hton,
    (generic_swap_fn_t)vapi_msg_trace_capture_packets_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_trace_capture_packets = vapi_register_msg(&__vapi_metadata_trace_capture_packets);
  VAPI_DBG("Assigned msg id %d to trace_capture_packets", vapi_msg_id_trace_capture_packets);
}
#endif

#ifndef defined_vapi_msg_trace_clear_capture_reply
#define defined_vapi_msg_trace_clear_capture_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_trace_clear_capture_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_trace_clear_capture_reply payload;
} vapi_msg_trace_clear_capture_reply;

static inline void vapi_msg_trace_clear_capture_reply_payload_hton(vapi_payload_trace_clear_capture_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_trace_clear_capture_reply_payload_ntoh(vapi_payload_trace_clear_capture_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_trace_clear_capture_reply_hton(vapi_msg_trace_clear_capture_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_clear_capture_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_trace_clear_capture_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_trace_clear_capture_reply_ntoh(vapi_msg_trace_clear_capture_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_clear_capture_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_trace_clear_capture_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_trace_clear_capture_reply_msg_size(vapi_msg_trace_clear_capture_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_trace_clear_capture_reply_msg_size(vapi_msg_trace_clear_capture_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_trace_clear_capture_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_clear_capture_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_trace_clear_capture_reply));
      return -1;
    }
  if (vapi_calc_trace_clear_capture_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_clear_capture_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_trace_clear_capture_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_trace_clear_capture_reply()
{
  static const char name[] = "trace_clear_capture_reply";
  static const char name_with_crc[] = "trace_clear_capture_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_trace_clear_capture_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_trace_clear_capture_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_trace_clear_capture_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_trace_clear_capture_reply_hton,
    (generic_swap_fn_t)vapi_msg_trace_clear_capture_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_trace_clear_capture_reply = vapi_register_msg(&__vapi_metadata_trace_clear_capture_reply);
  VAPI_DBG("Assigned msg id %d to trace_clear_capture_reply", vapi_msg_id_trace_clear_capture_reply);
}

static inline void vapi_set_vapi_msg_trace_clear_capture_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_trace_clear_capture_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_trace_clear_capture_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_trace_clear_capture
#define defined_vapi_msg_trace_clear_capture
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_trace_clear_capture;

static inline void vapi_msg_trace_clear_capture_hton(vapi_msg_trace_clear_capture *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_clear_capture'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_trace_clear_capture_ntoh(vapi_msg_trace_clear_capture *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_clear_capture'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_trace_clear_capture_msg_size(vapi_msg_trace_clear_capture *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_trace_clear_capture_msg_size(vapi_msg_trace_clear_capture *msg, uword buf_size)
{
  if (sizeof(vapi_msg_trace_clear_capture) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_clear_capture' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_trace_clear_capture));
      return -1;
    }
  if (vapi_calc_trace_clear_capture_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_clear_capture' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_trace_clear_capture_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_trace_clear_capture* vapi_alloc_trace_clear_capture(struct vapi_ctx_s *ctx)
{
  vapi_msg_trace_clear_capture *msg = NULL;
  const size_t size = sizeof(vapi_msg_trace_clear_capture);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_trace_clear_capture*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_trace_clear_capture);

  return msg;
}

static inline vapi_error_e vapi_trace_clear_capture(struct vapi_ctx_s *ctx,
  vapi_msg_trace_clear_capture *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_trace_clear_capture_reply *reply),
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
  vapi_msg_trace_clear_capture_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_trace_clear_capture_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_trace_clear_capture_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_trace_clear_capture()
{
  static const char name[] = "trace_clear_capture";
  static const char name_with_crc[] = "trace_clear_capture_51077d14";
  static vapi_message_desc_t __vapi_metadata_trace_clear_capture = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_trace_clear_capture_msg_size,
    (generic_swap_fn_t)vapi_msg_trace_clear_capture_hton,
    (generic_swap_fn_t)vapi_msg_trace_clear_capture_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_trace_clear_capture = vapi_register_msg(&__vapi_metadata_trace_clear_capture);
  VAPI_DBG("Assigned msg id %d to trace_clear_capture", vapi_msg_id_trace_clear_capture);
}
#endif

#ifndef defined_vapi_msg_trace_dump_reply
#define defined_vapi_msg_trace_dump_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 last_thread_id;
  u32 last_position;
  u8 more_this_thread;
  u8 more_threads;
  u8 flush_only;
  u8 done; 
} vapi_payload_trace_dump_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_trace_dump_reply payload;
} vapi_msg_trace_dump_reply;

static inline void vapi_msg_trace_dump_reply_payload_hton(vapi_payload_trace_dump_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->last_thread_id = htobe32(payload->last_thread_id);
  payload->last_position = htobe32(payload->last_position);
}

static inline void vapi_msg_trace_dump_reply_payload_ntoh(vapi_payload_trace_dump_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->last_thread_id = be32toh(payload->last_thread_id);
  payload->last_position = be32toh(payload->last_position);
}

static inline void vapi_msg_trace_dump_reply_hton(vapi_msg_trace_dump_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_dump_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_trace_dump_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_trace_dump_reply_ntoh(vapi_msg_trace_dump_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_dump_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_trace_dump_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_trace_dump_reply_msg_size(vapi_msg_trace_dump_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_trace_dump_reply_msg_size(vapi_msg_trace_dump_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_trace_dump_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_dump_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_trace_dump_reply));
      return -1;
    }
  if (vapi_calc_trace_dump_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_dump_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_trace_dump_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_trace_dump_reply()
{
  static const char name[] = "trace_dump_reply";
  static const char name_with_crc[] = "trace_dump_reply_e0e87f9d";
  static vapi_message_desc_t __vapi_metadata_trace_dump_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_trace_dump_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_trace_dump_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_trace_dump_reply_hton,
    (generic_swap_fn_t)vapi_msg_trace_dump_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_trace_dump_reply = vapi_register_msg(&__vapi_metadata_trace_dump_reply);
  VAPI_DBG("Assigned msg id %d to trace_dump_reply", vapi_msg_id_trace_dump_reply);
}

static inline void vapi_set_vapi_msg_trace_dump_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_trace_dump_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_trace_dump_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_trace_details
#define defined_vapi_msg_trace_details
typedef struct __attribute__ ((__packed__)) {
  u32 thread_id;
  u32 position;
  u8 more_this_thread;
  u8 more_threads;
  u8 done;
  u32 packet_number;
  vl_api_string_t trace_data; 
} vapi_payload_trace_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_trace_details payload;
} vapi_msg_trace_details;

static inline void vapi_msg_trace_details_payload_hton(vapi_payload_trace_details *payload)
{
  payload->thread_id = htobe32(payload->thread_id);
  payload->position = htobe32(payload->position);
  payload->packet_number = htobe32(payload->packet_number);
  vl_api_string_t_hton(&payload->trace_data);
}

static inline void vapi_msg_trace_details_payload_ntoh(vapi_payload_trace_details *payload)
{
  payload->thread_id = be32toh(payload->thread_id);
  payload->position = be32toh(payload->position);
  payload->packet_number = be32toh(payload->packet_number);
  vl_api_string_t_ntoh(&payload->trace_data);
}

static inline void vapi_msg_trace_details_hton(vapi_msg_trace_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_details'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_trace_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_trace_details_ntoh(vapi_msg_trace_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_details'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_trace_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_trace_details_msg_size(vapi_msg_trace_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.trace_data.buf[0]) * msg->payload.trace_data.length;
}

static inline int vapi_verify_trace_details_msg_size(vapi_msg_trace_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_trace_details) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_trace_details));
      return -1;
    }
  if (vapi_calc_trace_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_trace_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_trace_details()
{
  static const char name[] = "trace_details";
  static const char name_with_crc[] = "trace_details_1553e9eb";
  static vapi_message_desc_t __vapi_metadata_trace_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_trace_details, payload),
    (verify_msg_size_fn_t)vapi_verify_trace_details_msg_size,
    (generic_swap_fn_t)vapi_msg_trace_details_hton,
    (generic_swap_fn_t)vapi_msg_trace_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_trace_details = vapi_register_msg(&__vapi_metadata_trace_details);
  VAPI_DBG("Assigned msg id %d to trace_details", vapi_msg_id_trace_details);
}
#endif

#ifndef defined_vapi_msg_trace_dump
#define defined_vapi_msg_trace_dump
typedef struct __attribute__ ((__packed__)) {
  u8 clear_cache;
  u32 thread_id;
  u32 position;
  u32 max_records; 
} vapi_payload_trace_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_trace_dump payload;
} vapi_msg_trace_dump;

static inline void vapi_msg_trace_dump_payload_hton(vapi_payload_trace_dump *payload)
{
  payload->thread_id = htobe32(payload->thread_id);
  payload->position = htobe32(payload->position);
  payload->max_records = htobe32(payload->max_records);
}

static inline void vapi_msg_trace_dump_payload_ntoh(vapi_payload_trace_dump *payload)
{
  payload->thread_id = be32toh(payload->thread_id);
  payload->position = be32toh(payload->position);
  payload->max_records = be32toh(payload->max_records);
}

static inline void vapi_msg_trace_dump_hton(vapi_msg_trace_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_trace_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_trace_dump_ntoh(vapi_msg_trace_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_trace_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_trace_dump_msg_size(vapi_msg_trace_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_trace_dump_msg_size(vapi_msg_trace_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_trace_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_trace_dump));
      return -1;
    }
  if (vapi_calc_trace_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_trace_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_trace_dump* vapi_alloc_trace_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_trace_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_trace_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_trace_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_trace_dump);

  return msg;
}

static inline vapi_error_e vapi_trace_dump(struct vapi_ctx_s *ctx,
  vapi_msg_trace_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_trace_dump_reply *reply),
  void *reply_callback_ctx,
  vapi_error_e (*details_callback)(struct vapi_ctx_s *ctx,
                                   void *callback_ctx,
                                   vapi_error_e rv,
                                   bool is_last,
                                   vapi_payload_trace_details *details),
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
  vapi_msg_trace_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_trace_details, VAPI_REQUEST_STREAM, 
                       (vapi_cb_t)details_callback, details_callback_ctx);
    vapi_store_request(ctx, req_context, vapi_msg_id_trace_dump_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_trace_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_trace_dump()
{
  static const char name[] = "trace_dump";
  static const char name_with_crc[] = "trace_dump_c7d6681f";
  static vapi_message_desc_t __vapi_metadata_trace_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_trace_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_trace_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_trace_dump_hton,
    (generic_swap_fn_t)vapi_msg_trace_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_trace_dump = vapi_register_msg(&__vapi_metadata_trace_dump);
  VAPI_DBG("Assigned msg id %d to trace_dump", vapi_msg_id_trace_dump);
}
#endif

#ifndef defined_vapi_msg_trace_clear_cache_reply
#define defined_vapi_msg_trace_clear_cache_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_trace_clear_cache_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_trace_clear_cache_reply payload;
} vapi_msg_trace_clear_cache_reply;

static inline void vapi_msg_trace_clear_cache_reply_payload_hton(vapi_payload_trace_clear_cache_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_trace_clear_cache_reply_payload_ntoh(vapi_payload_trace_clear_cache_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_trace_clear_cache_reply_hton(vapi_msg_trace_clear_cache_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_clear_cache_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_trace_clear_cache_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_trace_clear_cache_reply_ntoh(vapi_msg_trace_clear_cache_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_clear_cache_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_trace_clear_cache_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_trace_clear_cache_reply_msg_size(vapi_msg_trace_clear_cache_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_trace_clear_cache_reply_msg_size(vapi_msg_trace_clear_cache_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_trace_clear_cache_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_clear_cache_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_trace_clear_cache_reply));
      return -1;
    }
  if (vapi_calc_trace_clear_cache_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_clear_cache_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_trace_clear_cache_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_trace_clear_cache_reply()
{
  static const char name[] = "trace_clear_cache_reply";
  static const char name_with_crc[] = "trace_clear_cache_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_trace_clear_cache_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_trace_clear_cache_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_trace_clear_cache_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_trace_clear_cache_reply_hton,
    (generic_swap_fn_t)vapi_msg_trace_clear_cache_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_trace_clear_cache_reply = vapi_register_msg(&__vapi_metadata_trace_clear_cache_reply);
  VAPI_DBG("Assigned msg id %d to trace_clear_cache_reply", vapi_msg_id_trace_clear_cache_reply);
}

static inline void vapi_set_vapi_msg_trace_clear_cache_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_trace_clear_cache_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_trace_clear_cache_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_trace_clear_cache
#define defined_vapi_msg_trace_clear_cache
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_trace_clear_cache;

static inline void vapi_msg_trace_clear_cache_hton(vapi_msg_trace_clear_cache *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_clear_cache'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_trace_clear_cache_ntoh(vapi_msg_trace_clear_cache *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_clear_cache'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_trace_clear_cache_msg_size(vapi_msg_trace_clear_cache *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_trace_clear_cache_msg_size(vapi_msg_trace_clear_cache *msg, uword buf_size)
{
  if (sizeof(vapi_msg_trace_clear_cache) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_clear_cache' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_trace_clear_cache));
      return -1;
    }
  if (vapi_calc_trace_clear_cache_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_clear_cache' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_trace_clear_cache_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_trace_clear_cache* vapi_alloc_trace_clear_cache(struct vapi_ctx_s *ctx)
{
  vapi_msg_trace_clear_cache *msg = NULL;
  const size_t size = sizeof(vapi_msg_trace_clear_cache);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_trace_clear_cache*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_trace_clear_cache);

  return msg;
}

static inline vapi_error_e vapi_trace_clear_cache(struct vapi_ctx_s *ctx,
  vapi_msg_trace_clear_cache *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_trace_clear_cache_reply *reply),
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
  vapi_msg_trace_clear_cache_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_trace_clear_cache_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_trace_clear_cache_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_trace_clear_cache()
{
  static const char name[] = "trace_clear_cache";
  static const char name_with_crc[] = "trace_clear_cache_51077d14";
  static vapi_message_desc_t __vapi_metadata_trace_clear_cache = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_trace_clear_cache_msg_size,
    (generic_swap_fn_t)vapi_msg_trace_clear_cache_hton,
    (generic_swap_fn_t)vapi_msg_trace_clear_cache_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_trace_clear_cache = vapi_register_msg(&__vapi_metadata_trace_clear_cache);
  VAPI_DBG("Assigned msg id %d to trace_clear_cache", vapi_msg_id_trace_clear_cache);
}
#endif

#ifndef defined_vapi_msg_trace_v2_details
#define defined_vapi_msg_trace_v2_details
typedef struct __attribute__ ((__packed__)) {
  u32 thread_id;
  u32 position;
  bool more;
  vl_api_string_t trace_data; 
} vapi_payload_trace_v2_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_trace_v2_details payload;
} vapi_msg_trace_v2_details;

static inline void vapi_msg_trace_v2_details_payload_hton(vapi_payload_trace_v2_details *payload)
{
  payload->thread_id = htobe32(payload->thread_id);
  payload->position = htobe32(payload->position);
  vl_api_string_t_hton(&payload->trace_data);
}

static inline void vapi_msg_trace_v2_details_payload_ntoh(vapi_payload_trace_v2_details *payload)
{
  payload->thread_id = be32toh(payload->thread_id);
  payload->position = be32toh(payload->position);
  vl_api_string_t_ntoh(&payload->trace_data);
}

static inline void vapi_msg_trace_v2_details_hton(vapi_msg_trace_v2_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_v2_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_trace_v2_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_trace_v2_details_ntoh(vapi_msg_trace_v2_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_v2_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_trace_v2_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_trace_v2_details_msg_size(vapi_msg_trace_v2_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.trace_data.buf[0]) * msg->payload.trace_data.length;
}

static inline int vapi_verify_trace_v2_details_msg_size(vapi_msg_trace_v2_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_trace_v2_details) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_v2_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_trace_v2_details));
      return -1;
    }
  if (vapi_calc_trace_v2_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_v2_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_trace_v2_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_trace_v2_details()
{
  static const char name[] = "trace_v2_details";
  static const char name_with_crc[] = "trace_v2_details_91f87d52";
  static vapi_message_desc_t __vapi_metadata_trace_v2_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_trace_v2_details, payload),
    (verify_msg_size_fn_t)vapi_verify_trace_v2_details_msg_size,
    (generic_swap_fn_t)vapi_msg_trace_v2_details_hton,
    (generic_swap_fn_t)vapi_msg_trace_v2_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_trace_v2_details = vapi_register_msg(&__vapi_metadata_trace_v2_details);
  VAPI_DBG("Assigned msg id %d to trace_v2_details", vapi_msg_id_trace_v2_details);
}

static inline void vapi_set_vapi_msg_trace_v2_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_trace_v2_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_trace_v2_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_trace_v2_dump
#define defined_vapi_msg_trace_v2_dump
typedef struct __attribute__ ((__packed__)) {
  u32 thread_id;
  u32 position;
  u32 max;
  bool clear_cache; 
} vapi_payload_trace_v2_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_trace_v2_dump payload;
} vapi_msg_trace_v2_dump;

static inline void vapi_msg_trace_v2_dump_payload_hton(vapi_payload_trace_v2_dump *payload)
{
  payload->thread_id = htobe32(payload->thread_id);
  payload->position = htobe32(payload->position);
  payload->max = htobe32(payload->max);
}

static inline void vapi_msg_trace_v2_dump_payload_ntoh(vapi_payload_trace_v2_dump *payload)
{
  payload->thread_id = be32toh(payload->thread_id);
  payload->position = be32toh(payload->position);
  payload->max = be32toh(payload->max);
}

static inline void vapi_msg_trace_v2_dump_hton(vapi_msg_trace_v2_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_v2_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_trace_v2_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_trace_v2_dump_ntoh(vapi_msg_trace_v2_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_v2_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_trace_v2_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_trace_v2_dump_msg_size(vapi_msg_trace_v2_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_trace_v2_dump_msg_size(vapi_msg_trace_v2_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_trace_v2_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_v2_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_trace_v2_dump));
      return -1;
    }
  if (vapi_calc_trace_v2_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_v2_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_trace_v2_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_trace_v2_dump* vapi_alloc_trace_v2_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_trace_v2_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_trace_v2_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_trace_v2_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_trace_v2_dump);

  return msg;
}

static inline vapi_error_e vapi_trace_v2_dump(struct vapi_ctx_s *ctx,
  vapi_msg_trace_v2_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_trace_v2_details *reply),
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
  vapi_msg_trace_v2_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_trace_v2_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_trace_v2_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_trace_v2_dump()
{
  static const char name[] = "trace_v2_dump";
  static const char name_with_crc[] = "trace_v2_dump_83f88d8e";
  static vapi_message_desc_t __vapi_metadata_trace_v2_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_trace_v2_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_trace_v2_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_trace_v2_dump_hton,
    (generic_swap_fn_t)vapi_msg_trace_v2_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_trace_v2_dump = vapi_register_msg(&__vapi_metadata_trace_v2_dump);
  VAPI_DBG("Assigned msg id %d to trace_v2_dump", vapi_msg_id_trace_v2_dump);
}
#endif

#ifndef defined_vapi_msg_trace_set_filter_function_reply
#define defined_vapi_msg_trace_set_filter_function_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_trace_set_filter_function_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_trace_set_filter_function_reply payload;
} vapi_msg_trace_set_filter_function_reply;

static inline void vapi_msg_trace_set_filter_function_reply_payload_hton(vapi_payload_trace_set_filter_function_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_trace_set_filter_function_reply_payload_ntoh(vapi_payload_trace_set_filter_function_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_trace_set_filter_function_reply_hton(vapi_msg_trace_set_filter_function_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_set_filter_function_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_trace_set_filter_function_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_trace_set_filter_function_reply_ntoh(vapi_msg_trace_set_filter_function_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_set_filter_function_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_trace_set_filter_function_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_trace_set_filter_function_reply_msg_size(vapi_msg_trace_set_filter_function_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_trace_set_filter_function_reply_msg_size(vapi_msg_trace_set_filter_function_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_trace_set_filter_function_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_set_filter_function_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_trace_set_filter_function_reply));
      return -1;
    }
  if (vapi_calc_trace_set_filter_function_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_set_filter_function_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_trace_set_filter_function_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_trace_set_filter_function_reply()
{
  static const char name[] = "trace_set_filter_function_reply";
  static const char name_with_crc[] = "trace_set_filter_function_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_trace_set_filter_function_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_trace_set_filter_function_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_trace_set_filter_function_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_trace_set_filter_function_reply_hton,
    (generic_swap_fn_t)vapi_msg_trace_set_filter_function_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_trace_set_filter_function_reply = vapi_register_msg(&__vapi_metadata_trace_set_filter_function_reply);
  VAPI_DBG("Assigned msg id %d to trace_set_filter_function_reply", vapi_msg_id_trace_set_filter_function_reply);
}

static inline void vapi_set_vapi_msg_trace_set_filter_function_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_trace_set_filter_function_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_trace_set_filter_function_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_trace_set_filter_function
#define defined_vapi_msg_trace_set_filter_function
typedef struct __attribute__ ((__packed__)) {
  vl_api_string_t filter_function_name; 
} vapi_payload_trace_set_filter_function;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_trace_set_filter_function payload;
} vapi_msg_trace_set_filter_function;

static inline void vapi_msg_trace_set_filter_function_payload_hton(vapi_payload_trace_set_filter_function *payload)
{
  vl_api_string_t_hton(&payload->filter_function_name);
}

static inline void vapi_msg_trace_set_filter_function_payload_ntoh(vapi_payload_trace_set_filter_function *payload)
{
  vl_api_string_t_ntoh(&payload->filter_function_name);
}

static inline void vapi_msg_trace_set_filter_function_hton(vapi_msg_trace_set_filter_function *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_set_filter_function'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_trace_set_filter_function_payload_hton(&msg->payload);
}

static inline void vapi_msg_trace_set_filter_function_ntoh(vapi_msg_trace_set_filter_function *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_set_filter_function'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_trace_set_filter_function_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_trace_set_filter_function_msg_size(vapi_msg_trace_set_filter_function *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.filter_function_name.buf[0]) * msg->payload.filter_function_name.length;
}

static inline int vapi_verify_trace_set_filter_function_msg_size(vapi_msg_trace_set_filter_function *msg, uword buf_size)
{
  if (sizeof(vapi_msg_trace_set_filter_function) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_set_filter_function' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_trace_set_filter_function));
      return -1;
    }
  if (vapi_calc_trace_set_filter_function_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_set_filter_function' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_trace_set_filter_function_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_trace_set_filter_function* vapi_alloc_trace_set_filter_function(struct vapi_ctx_s *ctx, size_t filter_function_name_buf_array_size)
{
  vapi_msg_trace_set_filter_function *msg = NULL;
  const size_t size = sizeof(vapi_msg_trace_set_filter_function) + sizeof(msg->payload.filter_function_name.buf[0]) * filter_function_name_buf_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_trace_set_filter_function*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_trace_set_filter_function);
  msg->payload.filter_function_name.length = filter_function_name_buf_array_size;

  return msg;
}

static inline vapi_error_e vapi_trace_set_filter_function(struct vapi_ctx_s *ctx,
  vapi_msg_trace_set_filter_function *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_trace_set_filter_function_reply *reply),
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
  vapi_msg_trace_set_filter_function_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_trace_set_filter_function_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_trace_set_filter_function_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_trace_set_filter_function()
{
  static const char name[] = "trace_set_filter_function";
  static const char name_with_crc[] = "trace_set_filter_function_616abb92";
  static vapi_message_desc_t __vapi_metadata_trace_set_filter_function = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_trace_set_filter_function, payload),
    (verify_msg_size_fn_t)vapi_verify_trace_set_filter_function_msg_size,
    (generic_swap_fn_t)vapi_msg_trace_set_filter_function_hton,
    (generic_swap_fn_t)vapi_msg_trace_set_filter_function_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_trace_set_filter_function = vapi_register_msg(&__vapi_metadata_trace_set_filter_function);
  VAPI_DBG("Assigned msg id %d to trace_set_filter_function", vapi_msg_id_trace_set_filter_function);
}
#endif

#ifndef defined_vapi_msg_trace_filter_function_details
#define defined_vapi_msg_trace_filter_function_details
typedef struct __attribute__ ((__packed__)) {
  bool selected;
  vl_api_string_t name; 
} vapi_payload_trace_filter_function_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_trace_filter_function_details payload;
} vapi_msg_trace_filter_function_details;

static inline void vapi_msg_trace_filter_function_details_payload_hton(vapi_payload_trace_filter_function_details *payload)
{
  vl_api_string_t_hton(&payload->name);
}

static inline void vapi_msg_trace_filter_function_details_payload_ntoh(vapi_payload_trace_filter_function_details *payload)
{
  vl_api_string_t_ntoh(&payload->name);
}

static inline void vapi_msg_trace_filter_function_details_hton(vapi_msg_trace_filter_function_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_filter_function_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_trace_filter_function_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_trace_filter_function_details_ntoh(vapi_msg_trace_filter_function_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_filter_function_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_trace_filter_function_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_trace_filter_function_details_msg_size(vapi_msg_trace_filter_function_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.name.buf[0]) * msg->payload.name.length;
}

static inline int vapi_verify_trace_filter_function_details_msg_size(vapi_msg_trace_filter_function_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_trace_filter_function_details) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_filter_function_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_trace_filter_function_details));
      return -1;
    }
  if (vapi_calc_trace_filter_function_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_filter_function_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_trace_filter_function_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_trace_filter_function_details()
{
  static const char name[] = "trace_filter_function_details";
  static const char name_with_crc[] = "trace_filter_function_details_28821359";
  static vapi_message_desc_t __vapi_metadata_trace_filter_function_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_trace_filter_function_details, payload),
    (verify_msg_size_fn_t)vapi_verify_trace_filter_function_details_msg_size,
    (generic_swap_fn_t)vapi_msg_trace_filter_function_details_hton,
    (generic_swap_fn_t)vapi_msg_trace_filter_function_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_trace_filter_function_details = vapi_register_msg(&__vapi_metadata_trace_filter_function_details);
  VAPI_DBG("Assigned msg id %d to trace_filter_function_details", vapi_msg_id_trace_filter_function_details);
}

static inline void vapi_set_vapi_msg_trace_filter_function_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_trace_filter_function_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_trace_filter_function_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_trace_filter_function_dump
#define defined_vapi_msg_trace_filter_function_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_trace_filter_function_dump;

static inline void vapi_msg_trace_filter_function_dump_hton(vapi_msg_trace_filter_function_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_filter_function_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_trace_filter_function_dump_ntoh(vapi_msg_trace_filter_function_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_trace_filter_function_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_trace_filter_function_dump_msg_size(vapi_msg_trace_filter_function_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_trace_filter_function_dump_msg_size(vapi_msg_trace_filter_function_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_trace_filter_function_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_filter_function_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_trace_filter_function_dump));
      return -1;
    }
  if (vapi_calc_trace_filter_function_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'trace_filter_function_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_trace_filter_function_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_trace_filter_function_dump* vapi_alloc_trace_filter_function_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_trace_filter_function_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_trace_filter_function_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_trace_filter_function_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_trace_filter_function_dump);

  return msg;
}

static inline vapi_error_e vapi_trace_filter_function_dump(struct vapi_ctx_s *ctx,
  vapi_msg_trace_filter_function_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_trace_filter_function_details *reply),
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
  vapi_msg_trace_filter_function_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_trace_filter_function_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_trace_filter_function_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_trace_filter_function_dump()
{
  static const char name[] = "trace_filter_function_dump";
  static const char name_with_crc[] = "trace_filter_function_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_trace_filter_function_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_trace_filter_function_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_trace_filter_function_dump_hton,
    (generic_swap_fn_t)vapi_msg_trace_filter_function_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_trace_filter_function_dump = vapi_register_msg(&__vapi_metadata_trace_filter_function_dump);
  VAPI_DBG("Assigned msg id %d to trace_filter_function_dump", vapi_msg_id_trace_filter_function_dump);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
