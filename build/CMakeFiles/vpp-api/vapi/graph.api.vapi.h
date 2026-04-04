#ifndef __included_graph_api_json
#define __included_graph_api_json

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

extern vapi_msg_id_t vapi_msg_id_graph_node_get;
extern vapi_msg_id_t vapi_msg_id_graph_node_get_reply;
extern vapi_msg_id_t vapi_msg_id_graph_node_details;

#define DEFINE_VAPI_MSG_IDS_GRAPH_API_JSON\
  vapi_msg_id_t vapi_msg_id_graph_node_get;\
  vapi_msg_id_t vapi_msg_id_graph_node_get_reply;\
  vapi_msg_id_t vapi_msg_id_graph_node_details;


#ifndef defined_vapi_enum_node_flag
#define defined_vapi_enum_node_flag
typedef enum {
  NODE_FLAG_FRAME_NO_FREE_AFTER_DISPATCH = 1,
  NODE_FLAG_IS_OUTPUT = 2,
  NODE_FLAG_IS_DROP = 4,
  NODE_FLAG_IS_PUNT = 8,
  NODE_FLAG_IS_HANDOFF = 16,
  NODE_FLAG_TRACE = 32,
  NODE_FLAG_SWITCH_FROM_INTERRUPT_TO_POLLING_MODE = 64,
  NODE_FLAG_SWITCH_FROM_POLLING_TO_INTERRUPT_MODE = 128,
  NODE_FLAG_TRACE_SUPPORTED = 256,
}  vapi_enum_node_flag;

#endif

#ifndef defined_vapi_msg_graph_node_get_reply
#define defined_vapi_msg_graph_node_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 cursor; 
} vapi_payload_graph_node_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_graph_node_get_reply payload;
} vapi_msg_graph_node_get_reply;

static inline void vapi_msg_graph_node_get_reply_payload_hton(vapi_payload_graph_node_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_graph_node_get_reply_payload_ntoh(vapi_payload_graph_node_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_graph_node_get_reply_hton(vapi_msg_graph_node_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_graph_node_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_graph_node_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_graph_node_get_reply_ntoh(vapi_msg_graph_node_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_graph_node_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_graph_node_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_graph_node_get_reply_msg_size(vapi_msg_graph_node_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_graph_node_get_reply_msg_size(vapi_msg_graph_node_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_graph_node_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'graph_node_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_graph_node_get_reply));
      return -1;
    }
  if (vapi_calc_graph_node_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'graph_node_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_graph_node_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_graph_node_get_reply()
{
  static const char name[] = "graph_node_get_reply";
  static const char name_with_crc[] = "graph_node_get_reply_53b48f5d";
  static vapi_message_desc_t __vapi_metadata_graph_node_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_graph_node_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_graph_node_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_graph_node_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_graph_node_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_graph_node_get_reply = vapi_register_msg(&__vapi_metadata_graph_node_get_reply);
  VAPI_DBG("Assigned msg id %d to graph_node_get_reply", vapi_msg_id_graph_node_get_reply);
}

static inline void vapi_set_vapi_msg_graph_node_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_graph_node_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_graph_node_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_graph_node_details
#define defined_vapi_msg_graph_node_details
typedef struct __attribute__ ((__packed__)) {
  u32 index;
  u8 name[64];
  vapi_enum_node_flag flags;
  u32 n_arcs;
  u32 arcs_out[0]; 
} vapi_payload_graph_node_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_graph_node_details payload;
} vapi_msg_graph_node_details;

static inline void vapi_msg_graph_node_details_payload_hton(vapi_payload_graph_node_details *payload)
{
  payload->index = htobe32(payload->index);
  payload->flags = (vapi_enum_node_flag)htobe32(payload->flags);
  payload->n_arcs = htobe32(payload->n_arcs);
  do { unsigned i; for (i = 0; i < be32toh(payload->n_arcs); ++i) { payload->arcs_out[i] = htobe32(payload->arcs_out[i]); } } while(0);
}

static inline void vapi_msg_graph_node_details_payload_ntoh(vapi_payload_graph_node_details *payload)
{
  payload->index = be32toh(payload->index);
  payload->flags = (vapi_enum_node_flag)be32toh(payload->flags);
  payload->n_arcs = be32toh(payload->n_arcs);
  do { unsigned i; for (i = 0; i < payload->n_arcs; ++i) { payload->arcs_out[i] = be32toh(payload->arcs_out[i]); } } while(0);
}

static inline void vapi_msg_graph_node_details_hton(vapi_msg_graph_node_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_graph_node_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_graph_node_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_graph_node_details_ntoh(vapi_msg_graph_node_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_graph_node_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_graph_node_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_graph_node_details_msg_size(vapi_msg_graph_node_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.arcs_out[0]) * msg->payload.n_arcs;
}

static inline int vapi_verify_graph_node_details_msg_size(vapi_msg_graph_node_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_graph_node_details) > buf_size)
    {
      VAPI_ERR("Truncated 'graph_node_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_graph_node_details));
      return -1;
    }
  if (vapi_calc_graph_node_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'graph_node_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_graph_node_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_graph_node_details()
{
  static const char name[] = "graph_node_details";
  static const char name_with_crc[] = "graph_node_details_ac762018";
  static vapi_message_desc_t __vapi_metadata_graph_node_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_graph_node_details, payload),
    (verify_msg_size_fn_t)vapi_verify_graph_node_details_msg_size,
    (generic_swap_fn_t)vapi_msg_graph_node_details_hton,
    (generic_swap_fn_t)vapi_msg_graph_node_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_graph_node_details = vapi_register_msg(&__vapi_metadata_graph_node_details);
  VAPI_DBG("Assigned msg id %d to graph_node_details", vapi_msg_id_graph_node_details);
}
#endif

#ifndef defined_vapi_msg_graph_node_get
#define defined_vapi_msg_graph_node_get
typedef struct __attribute__ ((__packed__)) {
  u32 cursor;
  u32 index;
  u8 name[64];
  vapi_enum_node_flag flags;
  bool want_arcs; 
} vapi_payload_graph_node_get;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_graph_node_get payload;
} vapi_msg_graph_node_get;

static inline void vapi_msg_graph_node_get_payload_hton(vapi_payload_graph_node_get *payload)
{
  payload->cursor = htobe32(payload->cursor);
  payload->index = htobe32(payload->index);
  payload->flags = (vapi_enum_node_flag)htobe32(payload->flags);
}

static inline void vapi_msg_graph_node_get_payload_ntoh(vapi_payload_graph_node_get *payload)
{
  payload->cursor = be32toh(payload->cursor);
  payload->index = be32toh(payload->index);
  payload->flags = (vapi_enum_node_flag)be32toh(payload->flags);
}

static inline void vapi_msg_graph_node_get_hton(vapi_msg_graph_node_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_graph_node_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_graph_node_get_payload_hton(&msg->payload);
}

static inline void vapi_msg_graph_node_get_ntoh(vapi_msg_graph_node_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_graph_node_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_graph_node_get_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_graph_node_get_msg_size(vapi_msg_graph_node_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_graph_node_get_msg_size(vapi_msg_graph_node_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_graph_node_get) > buf_size)
    {
      VAPI_ERR("Truncated 'graph_node_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_graph_node_get));
      return -1;
    }
  if (vapi_calc_graph_node_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'graph_node_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_graph_node_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_graph_node_get* vapi_alloc_graph_node_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_graph_node_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_graph_node_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_graph_node_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_graph_node_get);

  return msg;
}

static inline vapi_error_e vapi_graph_node_get(struct vapi_ctx_s *ctx,
  vapi_msg_graph_node_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_graph_node_get_reply *reply),
  void *reply_callback_ctx,
  vapi_error_e (*details_callback)(struct vapi_ctx_s *ctx,
                                   void *callback_ctx,
                                   vapi_error_e rv,
                                   bool is_last,
                                   vapi_payload_graph_node_details *details),
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
  vapi_msg_graph_node_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_graph_node_details, VAPI_REQUEST_STREAM, 
                       (vapi_cb_t)details_callback, details_callback_ctx);
    vapi_store_request(ctx, req_context, vapi_msg_id_graph_node_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_graph_node_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_graph_node_get()
{
  static const char name[] = "graph_node_get";
  static const char name_with_crc[] = "graph_node_get_39c8792e";
  static vapi_message_desc_t __vapi_metadata_graph_node_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_graph_node_get, payload),
    (verify_msg_size_fn_t)vapi_verify_graph_node_get_msg_size,
    (generic_swap_fn_t)vapi_msg_graph_node_get_hton,
    (generic_swap_fn_t)vapi_msg_graph_node_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_graph_node_get = vapi_register_msg(&__vapi_metadata_graph_node_get);
  VAPI_DBG("Assigned msg id %d to graph_node_get", vapi_msg_id_graph_node_get);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
