#ifndef __included_memclnt_api_json
#define __included_memclnt_api_json

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

static inline vapi_error_e vapi_send_with_control_ping (vapi_ctx_t ctx, void * msg, u32 context);

extern vapi_msg_id_t vapi_msg_id_memclnt_create;
extern vapi_msg_id_t vapi_msg_id_memclnt_create_reply;
extern vapi_msg_id_t vapi_msg_id_memclnt_delete_reply;
extern vapi_msg_id_t vapi_msg_id_rpc_call;
extern vapi_msg_id_t vapi_msg_id_rpc_call_reply;
extern vapi_msg_id_t vapi_msg_id_get_first_msg_id;
extern vapi_msg_id_t vapi_msg_id_get_first_msg_id_reply;
extern vapi_msg_id_t vapi_msg_id_api_versions;
extern vapi_msg_id_t vapi_msg_id_api_versions_reply;
extern vapi_msg_id_t vapi_msg_id_sockclnt_create;
extern vapi_msg_id_t vapi_msg_id_sockclnt_create_reply;
extern vapi_msg_id_t vapi_msg_id_sockclnt_delete;
extern vapi_msg_id_t vapi_msg_id_sockclnt_delete_reply;
extern vapi_msg_id_t vapi_msg_id_sock_init_shm;
extern vapi_msg_id_t vapi_msg_id_sock_init_shm_reply;
extern vapi_msg_id_t vapi_msg_id_memclnt_keepalive;
extern vapi_msg_id_t vapi_msg_id_memclnt_keepalive_reply;
extern vapi_msg_id_t vapi_msg_id_control_ping;
extern vapi_msg_id_t vapi_msg_id_control_ping_reply;
extern vapi_msg_id_t vapi_msg_id_memclnt_create_v2;
extern vapi_msg_id_t vapi_msg_id_memclnt_create_v2_reply;
extern vapi_msg_id_t vapi_msg_id_get_api_json;
extern vapi_msg_id_t vapi_msg_id_get_api_json_reply;

#define DEFINE_VAPI_MSG_IDS_MEMCLNT_API_JSON\
  vapi_msg_id_t vapi_msg_id_memclnt_create;\
  vapi_msg_id_t vapi_msg_id_memclnt_create_reply;\
  vapi_msg_id_t vapi_msg_id_memclnt_delete_reply;\
  vapi_msg_id_t vapi_msg_id_rpc_call;\
  vapi_msg_id_t vapi_msg_id_rpc_call_reply;\
  vapi_msg_id_t vapi_msg_id_get_first_msg_id;\
  vapi_msg_id_t vapi_msg_id_get_first_msg_id_reply;\
  vapi_msg_id_t vapi_msg_id_api_versions;\
  vapi_msg_id_t vapi_msg_id_api_versions_reply;\
  vapi_msg_id_t vapi_msg_id_sockclnt_create;\
  vapi_msg_id_t vapi_msg_id_sockclnt_create_reply;\
  vapi_msg_id_t vapi_msg_id_sockclnt_delete;\
  vapi_msg_id_t vapi_msg_id_sockclnt_delete_reply;\
  vapi_msg_id_t vapi_msg_id_sock_init_shm;\
  vapi_msg_id_t vapi_msg_id_sock_init_shm_reply;\
  vapi_msg_id_t vapi_msg_id_memclnt_keepalive;\
  vapi_msg_id_t vapi_msg_id_memclnt_keepalive_reply;\
  vapi_msg_id_t vapi_msg_id_control_ping;\
  vapi_msg_id_t vapi_msg_id_control_ping_reply;\
  vapi_msg_id_t vapi_msg_id_memclnt_create_v2;\
  vapi_msg_id_t vapi_msg_id_memclnt_create_v2_reply;\
  vapi_msg_id_t vapi_msg_id_get_api_json;\
  vapi_msg_id_t vapi_msg_id_get_api_json_reply;


#ifndef defined_vapi_type_module_version
#define defined_vapi_type_module_version
typedef struct __attribute__((__packed__)) {
  u32 major;
  u32 minor;
  u32 patch;
  u8 name[64];
} vapi_type_module_version;

static inline void vapi_type_module_version_hton(vapi_type_module_version *msg)
{
  msg->major = htobe32(msg->major);
  msg->minor = htobe32(msg->minor);
  msg->patch = htobe32(msg->patch);
}

static inline void vapi_type_module_version_ntoh(vapi_type_module_version *msg)
{
  msg->major = be32toh(msg->major);
  msg->minor = be32toh(msg->minor);
  msg->patch = be32toh(msg->patch);
}
#endif

#ifndef defined_vapi_type_message_table_entry
#define defined_vapi_type_message_table_entry
typedef struct __attribute__((__packed__)) {
  u16 index;
  u8 name[64];
} vapi_type_message_table_entry;

static inline void vapi_type_message_table_entry_hton(vapi_type_message_table_entry *msg)
{
  msg->index = htobe16(msg->index);
}

static inline void vapi_type_message_table_entry_ntoh(vapi_type_message_table_entry *msg)
{
  msg->index = be16toh(msg->index);
}
#endif

#ifndef defined_vapi_msg_memclnt_create_reply
#define defined_vapi_msg_memclnt_create_reply
typedef struct __attribute__ ((__packed__)) {
  i32 response;
  u64 handle;
  u32 index;
  u64 message_table; 
} vapi_payload_memclnt_create_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_memclnt_create_reply payload;
} vapi_msg_memclnt_create_reply;

static inline void vapi_msg_memclnt_create_reply_payload_hton(vapi_payload_memclnt_create_reply *payload)
{
  payload->response = htobe32(payload->response);
  payload->handle = htobe64(payload->handle);
  payload->index = htobe32(payload->index);
  payload->message_table = htobe64(payload->message_table);
}

static inline void vapi_msg_memclnt_create_reply_payload_ntoh(vapi_payload_memclnt_create_reply *payload)
{
  payload->response = be32toh(payload->response);
  payload->handle = be64toh(payload->handle);
  payload->index = be32toh(payload->index);
  payload->message_table = be64toh(payload->message_table);
}

static inline void vapi_msg_memclnt_create_reply_hton(vapi_msg_memclnt_create_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_memclnt_create_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_memclnt_create_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_memclnt_create_reply_ntoh(vapi_msg_memclnt_create_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_memclnt_create_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_memclnt_create_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_memclnt_create_reply_msg_size(vapi_msg_memclnt_create_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_memclnt_create_reply_msg_size(vapi_msg_memclnt_create_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_memclnt_create_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'memclnt_create_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_memclnt_create_reply));
      return -1;
    }
  if (vapi_calc_memclnt_create_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'memclnt_create_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_memclnt_create_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_memclnt_create_reply()
{
  static const char name[] = "memclnt_create_reply";
  static const char name_with_crc[] = "memclnt_create_reply_42ec4560";
  static vapi_message_desc_t __vapi_metadata_memclnt_create_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_memclnt_create_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_memclnt_create_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_memclnt_create_reply_hton,
    (generic_swap_fn_t)vapi_msg_memclnt_create_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_memclnt_create_reply = vapi_register_msg(&__vapi_metadata_memclnt_create_reply);
  VAPI_DBG("Assigned msg id %d to memclnt_create_reply", vapi_msg_id_memclnt_create_reply);
}

static inline void vapi_set_vapi_msg_memclnt_create_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_memclnt_create_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_memclnt_create_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_memclnt_create
#define defined_vapi_msg_memclnt_create
typedef struct __attribute__ ((__packed__)) {
  i32 ctx_quota;
  u64 input_queue;
  u8 name[64];
  u32 api_versions[8]; 
} vapi_payload_memclnt_create;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_memclnt_create payload;
} vapi_msg_memclnt_create;

static inline void vapi_msg_memclnt_create_payload_hton(vapi_payload_memclnt_create *payload)
{
  payload->ctx_quota = htobe32(payload->ctx_quota);
  payload->input_queue = htobe64(payload->input_queue);
  do { unsigned i; for (i = 0; i < 8; ++i) { payload->api_versions[i] = htobe32(payload->api_versions[i]); } } while(0);
}

static inline void vapi_msg_memclnt_create_payload_ntoh(vapi_payload_memclnt_create *payload)
{
  payload->ctx_quota = be32toh(payload->ctx_quota);
  payload->input_queue = be64toh(payload->input_queue);
  do { unsigned i; for (i = 0; i < 8; ++i) { payload->api_versions[i] = be32toh(payload->api_versions[i]); } } while(0);
}

static inline void vapi_msg_memclnt_create_hton(vapi_msg_memclnt_create *msg)
{
  VAPI_DBG("Swapping `vapi_msg_memclnt_create'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_memclnt_create_payload_hton(&msg->payload);
}

static inline void vapi_msg_memclnt_create_ntoh(vapi_msg_memclnt_create *msg)
{
  VAPI_DBG("Swapping `vapi_msg_memclnt_create'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_memclnt_create_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_memclnt_create_msg_size(vapi_msg_memclnt_create *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_memclnt_create_msg_size(vapi_msg_memclnt_create *msg, uword buf_size)
{
  if (sizeof(vapi_msg_memclnt_create) > buf_size)
    {
      VAPI_ERR("Truncated 'memclnt_create' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_memclnt_create));
      return -1;
    }
  if (vapi_calc_memclnt_create_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'memclnt_create' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_memclnt_create_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_memclnt_create* vapi_alloc_memclnt_create(struct vapi_ctx_s *ctx)
{
  vapi_msg_memclnt_create *msg = NULL;
  const size_t size = sizeof(vapi_msg_memclnt_create);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_memclnt_create*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_memclnt_create);

  return msg;
}

static inline vapi_error_e vapi_memclnt_create(struct vapi_ctx_s *ctx,
  vapi_msg_memclnt_create *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_memclnt_create_reply *reply),
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
  vapi_msg_memclnt_create_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_memclnt_create_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_memclnt_create_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_memclnt_create()
{
  static const char name[] = "memclnt_create";
  static const char name_with_crc[] = "memclnt_create_9c5e1c2f";
  static vapi_message_desc_t __vapi_metadata_memclnt_create = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_memclnt_create, payload),
    (verify_msg_size_fn_t)vapi_verify_memclnt_create_msg_size,
    (generic_swap_fn_t)vapi_msg_memclnt_create_hton,
    (generic_swap_fn_t)vapi_msg_memclnt_create_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_memclnt_create = vapi_register_msg(&__vapi_metadata_memclnt_create);
  VAPI_DBG("Assigned msg id %d to memclnt_create", vapi_msg_id_memclnt_create);
}
#endif

#ifndef defined_vapi_msg_memclnt_delete_reply
#define defined_vapi_msg_memclnt_delete_reply
typedef struct __attribute__ ((__packed__)) {
  u16 _vl_msg_id;
  i32 response;
  u64 handle; 
} vapi_payload_memclnt_delete_reply;

typedef struct __attribute__ ((__packed__)) {

  vapi_payload_memclnt_delete_reply payload;
} vapi_msg_memclnt_delete_reply;

static inline void vapi_msg_memclnt_delete_reply_payload_hton(vapi_payload_memclnt_delete_reply *payload)
{
  payload->_vl_msg_id = htobe16(payload->_vl_msg_id);
  payload->response = htobe32(payload->response);
  payload->handle = htobe64(payload->handle);
}

static inline void vapi_msg_memclnt_delete_reply_payload_ntoh(vapi_payload_memclnt_delete_reply *payload)
{
  payload->_vl_msg_id = be16toh(payload->_vl_msg_id);
  payload->response = be32toh(payload->response);
  payload->handle = be64toh(payload->handle);
}

static inline void vapi_msg_memclnt_delete_reply_hton(vapi_msg_memclnt_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_memclnt_delete_reply'@%p to big endian", msg);

  vapi_msg_memclnt_delete_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_memclnt_delete_reply_ntoh(vapi_msg_memclnt_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_memclnt_delete_reply'@%p to host byte order", msg);

  vapi_msg_memclnt_delete_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_memclnt_delete_reply_msg_size(vapi_msg_memclnt_delete_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_memclnt_delete_reply_msg_size(vapi_msg_memclnt_delete_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_memclnt_delete_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'memclnt_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_memclnt_delete_reply));
      return -1;
    }
  if (vapi_calc_memclnt_delete_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'memclnt_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_memclnt_delete_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_memclnt_delete_reply()
{
  static const char name[] = "memclnt_delete_reply";
  static const char name_with_crc[] = "memclnt_delete_reply_3d3b6312";
  static vapi_message_desc_t __vapi_metadata_memclnt_delete_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    false,
    0,
    offsetof(vapi_msg_memclnt_delete_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_memclnt_delete_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_memclnt_delete_reply_hton,
    (generic_swap_fn_t)vapi_msg_memclnt_delete_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_memclnt_delete_reply = vapi_register_msg(&__vapi_metadata_memclnt_delete_reply);
  VAPI_DBG("Assigned msg id %d to memclnt_delete_reply", vapi_msg_id_memclnt_delete_reply);
}

static inline void vapi_set_vapi_msg_memclnt_delete_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_memclnt_delete_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_memclnt_delete_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_rpc_call_reply
#define defined_vapi_msg_rpc_call_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_rpc_call_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_rpc_call_reply payload;
} vapi_msg_rpc_call_reply;

static inline void vapi_msg_rpc_call_reply_payload_hton(vapi_payload_rpc_call_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_rpc_call_reply_payload_ntoh(vapi_payload_rpc_call_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_rpc_call_reply_hton(vapi_msg_rpc_call_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_rpc_call_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_rpc_call_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_rpc_call_reply_ntoh(vapi_msg_rpc_call_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_rpc_call_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_rpc_call_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_rpc_call_reply_msg_size(vapi_msg_rpc_call_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_rpc_call_reply_msg_size(vapi_msg_rpc_call_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_rpc_call_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'rpc_call_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_rpc_call_reply));
      return -1;
    }
  if (vapi_calc_rpc_call_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'rpc_call_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_rpc_call_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_rpc_call_reply()
{
  static const char name[] = "rpc_call_reply";
  static const char name_with_crc[] = "rpc_call_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_rpc_call_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_rpc_call_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_rpc_call_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_rpc_call_reply_hton,
    (generic_swap_fn_t)vapi_msg_rpc_call_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_rpc_call_reply = vapi_register_msg(&__vapi_metadata_rpc_call_reply);
  VAPI_DBG("Assigned msg id %d to rpc_call_reply", vapi_msg_id_rpc_call_reply);
}

static inline void vapi_set_vapi_msg_rpc_call_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_rpc_call_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_rpc_call_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_rpc_call
#define defined_vapi_msg_rpc_call
typedef struct __attribute__ ((__packed__)) {
  u64 function;
  u8 multicast;
  u8 need_barrier_sync;
  u8 send_reply;
  u32 data_len;
  u8 data[0]; 
} vapi_payload_rpc_call;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_rpc_call payload;
} vapi_msg_rpc_call;

static inline void vapi_msg_rpc_call_payload_hton(vapi_payload_rpc_call *payload)
{
  payload->function = htobe64(payload->function);
  payload->data_len = htobe32(payload->data_len);
}

static inline void vapi_msg_rpc_call_payload_ntoh(vapi_payload_rpc_call *payload)
{
  payload->function = be64toh(payload->function);
  payload->data_len = be32toh(payload->data_len);
}

static inline void vapi_msg_rpc_call_hton(vapi_msg_rpc_call *msg)
{
  VAPI_DBG("Swapping `vapi_msg_rpc_call'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_rpc_call_payload_hton(&msg->payload);
}

static inline void vapi_msg_rpc_call_ntoh(vapi_msg_rpc_call *msg)
{
  VAPI_DBG("Swapping `vapi_msg_rpc_call'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_rpc_call_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_rpc_call_msg_size(vapi_msg_rpc_call *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.data[0]) * msg->payload.data_len;
}

static inline int vapi_verify_rpc_call_msg_size(vapi_msg_rpc_call *msg, uword buf_size)
{
  if (sizeof(vapi_msg_rpc_call) > buf_size)
    {
      VAPI_ERR("Truncated 'rpc_call' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_rpc_call));
      return -1;
    }
  if (vapi_calc_rpc_call_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'rpc_call' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_rpc_call_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_rpc_call* vapi_alloc_rpc_call(struct vapi_ctx_s *ctx, size_t _data_array_size)
{
  vapi_msg_rpc_call *msg = NULL;
  const size_t size = sizeof(vapi_msg_rpc_call) + sizeof(msg->payload.data[0]) * _data_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_rpc_call*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_rpc_call);
  msg->payload.data_len = _data_array_size;

  return msg;
}

static inline vapi_error_e vapi_rpc_call(struct vapi_ctx_s *ctx,
  vapi_msg_rpc_call *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_rpc_call_reply *reply),
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
  vapi_msg_rpc_call_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_rpc_call_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_rpc_call_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_rpc_call()
{
  static const char name[] = "rpc_call";
  static const char name_with_crc[] = "rpc_call_7e8a2c95";
  static vapi_message_desc_t __vapi_metadata_rpc_call = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_rpc_call, payload),
    (verify_msg_size_fn_t)vapi_verify_rpc_call_msg_size,
    (generic_swap_fn_t)vapi_msg_rpc_call_hton,
    (generic_swap_fn_t)vapi_msg_rpc_call_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_rpc_call = vapi_register_msg(&__vapi_metadata_rpc_call);
  VAPI_DBG("Assigned msg id %d to rpc_call", vapi_msg_id_rpc_call);
}
#endif

#ifndef defined_vapi_msg_get_first_msg_id_reply
#define defined_vapi_msg_get_first_msg_id_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u16 first_msg_id; 
} vapi_payload_get_first_msg_id_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_get_first_msg_id_reply payload;
} vapi_msg_get_first_msg_id_reply;

static inline void vapi_msg_get_first_msg_id_reply_payload_hton(vapi_payload_get_first_msg_id_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->first_msg_id = htobe16(payload->first_msg_id);
}

static inline void vapi_msg_get_first_msg_id_reply_payload_ntoh(vapi_payload_get_first_msg_id_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->first_msg_id = be16toh(payload->first_msg_id);
}

static inline void vapi_msg_get_first_msg_id_reply_hton(vapi_msg_get_first_msg_id_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_first_msg_id_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_get_first_msg_id_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_get_first_msg_id_reply_ntoh(vapi_msg_get_first_msg_id_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_first_msg_id_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_get_first_msg_id_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_get_first_msg_id_reply_msg_size(vapi_msg_get_first_msg_id_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_get_first_msg_id_reply_msg_size(vapi_msg_get_first_msg_id_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_get_first_msg_id_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'get_first_msg_id_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_get_first_msg_id_reply));
      return -1;
    }
  if (vapi_calc_get_first_msg_id_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'get_first_msg_id_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_get_first_msg_id_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_get_first_msg_id_reply()
{
  static const char name[] = "get_first_msg_id_reply";
  static const char name_with_crc[] = "get_first_msg_id_reply_7d337472";
  static vapi_message_desc_t __vapi_metadata_get_first_msg_id_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_get_first_msg_id_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_get_first_msg_id_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_get_first_msg_id_reply_hton,
    (generic_swap_fn_t)vapi_msg_get_first_msg_id_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_get_first_msg_id_reply = vapi_register_msg(&__vapi_metadata_get_first_msg_id_reply);
  VAPI_DBG("Assigned msg id %d to get_first_msg_id_reply", vapi_msg_id_get_first_msg_id_reply);
}

static inline void vapi_set_vapi_msg_get_first_msg_id_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_get_first_msg_id_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_get_first_msg_id_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_get_first_msg_id
#define defined_vapi_msg_get_first_msg_id
typedef struct __attribute__ ((__packed__)) {
  u8 name[64]; 
} vapi_payload_get_first_msg_id;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_get_first_msg_id payload;
} vapi_msg_get_first_msg_id;

static inline void vapi_msg_get_first_msg_id_payload_hton(vapi_payload_get_first_msg_id *payload)
{

}

static inline void vapi_msg_get_first_msg_id_payload_ntoh(vapi_payload_get_first_msg_id *payload)
{

}

static inline void vapi_msg_get_first_msg_id_hton(vapi_msg_get_first_msg_id *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_first_msg_id'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_get_first_msg_id_payload_hton(&msg->payload);
}

static inline void vapi_msg_get_first_msg_id_ntoh(vapi_msg_get_first_msg_id *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_first_msg_id'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_get_first_msg_id_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_get_first_msg_id_msg_size(vapi_msg_get_first_msg_id *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_get_first_msg_id_msg_size(vapi_msg_get_first_msg_id *msg, uword buf_size)
{
  if (sizeof(vapi_msg_get_first_msg_id) > buf_size)
    {
      VAPI_ERR("Truncated 'get_first_msg_id' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_get_first_msg_id));
      return -1;
    }
  if (vapi_calc_get_first_msg_id_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'get_first_msg_id' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_get_first_msg_id_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_get_first_msg_id* vapi_alloc_get_first_msg_id(struct vapi_ctx_s *ctx)
{
  vapi_msg_get_first_msg_id *msg = NULL;
  const size_t size = sizeof(vapi_msg_get_first_msg_id);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_get_first_msg_id*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_get_first_msg_id);

  return msg;
}

static inline vapi_error_e vapi_get_first_msg_id(struct vapi_ctx_s *ctx,
  vapi_msg_get_first_msg_id *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_get_first_msg_id_reply *reply),
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
  vapi_msg_get_first_msg_id_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_get_first_msg_id_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_get_first_msg_id_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_get_first_msg_id()
{
  static const char name[] = "get_first_msg_id";
  static const char name_with_crc[] = "get_first_msg_id_ebf79a66";
  static vapi_message_desc_t __vapi_metadata_get_first_msg_id = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_get_first_msg_id, payload),
    (verify_msg_size_fn_t)vapi_verify_get_first_msg_id_msg_size,
    (generic_swap_fn_t)vapi_msg_get_first_msg_id_hton,
    (generic_swap_fn_t)vapi_msg_get_first_msg_id_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_get_first_msg_id = vapi_register_msg(&__vapi_metadata_get_first_msg_id);
  VAPI_DBG("Assigned msg id %d to get_first_msg_id", vapi_msg_id_get_first_msg_id);
}
#endif

#ifndef defined_vapi_msg_api_versions_reply
#define defined_vapi_msg_api_versions_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 count;
  vapi_type_module_version api_versions[0]; 
} vapi_payload_api_versions_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_api_versions_reply payload;
} vapi_msg_api_versions_reply;

static inline void vapi_msg_api_versions_reply_payload_hton(vapi_payload_api_versions_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->count = htobe32(payload->count);
  do { unsigned i; for (i = 0; i < be32toh(payload->count); ++i) { vapi_type_module_version_hton(&payload->api_versions[i]); } } while(0);
}

static inline void vapi_msg_api_versions_reply_payload_ntoh(vapi_payload_api_versions_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->count = be32toh(payload->count);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { vapi_type_module_version_ntoh(&payload->api_versions[i]); } } while(0);
}

static inline void vapi_msg_api_versions_reply_hton(vapi_msg_api_versions_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_api_versions_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_api_versions_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_api_versions_reply_ntoh(vapi_msg_api_versions_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_api_versions_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_api_versions_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_api_versions_reply_msg_size(vapi_msg_api_versions_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.api_versions[0]) * msg->payload.count;
}

static inline int vapi_verify_api_versions_reply_msg_size(vapi_msg_api_versions_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_api_versions_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'api_versions_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_api_versions_reply));
      return -1;
    }
  if (vapi_calc_api_versions_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'api_versions_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_api_versions_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_api_versions_reply()
{
  static const char name[] = "api_versions_reply";
  static const char name_with_crc[] = "api_versions_reply_5f0d99d6";
  static vapi_message_desc_t __vapi_metadata_api_versions_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_api_versions_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_api_versions_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_api_versions_reply_hton,
    (generic_swap_fn_t)vapi_msg_api_versions_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_api_versions_reply = vapi_register_msg(&__vapi_metadata_api_versions_reply);
  VAPI_DBG("Assigned msg id %d to api_versions_reply", vapi_msg_id_api_versions_reply);
}

static inline void vapi_set_vapi_msg_api_versions_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_api_versions_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_api_versions_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_api_versions
#define defined_vapi_msg_api_versions
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_api_versions;

static inline void vapi_msg_api_versions_hton(vapi_msg_api_versions *msg)
{
  VAPI_DBG("Swapping `vapi_msg_api_versions'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_api_versions_ntoh(vapi_msg_api_versions *msg)
{
  VAPI_DBG("Swapping `vapi_msg_api_versions'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_api_versions_msg_size(vapi_msg_api_versions *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_api_versions_msg_size(vapi_msg_api_versions *msg, uword buf_size)
{
  if (sizeof(vapi_msg_api_versions) > buf_size)
    {
      VAPI_ERR("Truncated 'api_versions' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_api_versions));
      return -1;
    }
  if (vapi_calc_api_versions_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'api_versions' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_api_versions_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_api_versions* vapi_alloc_api_versions(struct vapi_ctx_s *ctx)
{
  vapi_msg_api_versions *msg = NULL;
  const size_t size = sizeof(vapi_msg_api_versions);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_api_versions*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_api_versions);

  return msg;
}

static inline vapi_error_e vapi_api_versions(struct vapi_ctx_s *ctx,
  vapi_msg_api_versions *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_api_versions_reply *reply),
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
  vapi_msg_api_versions_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_api_versions_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_api_versions_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_api_versions()
{
  static const char name[] = "api_versions";
  static const char name_with_crc[] = "api_versions_51077d14";
  static vapi_message_desc_t __vapi_metadata_api_versions = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_api_versions_msg_size,
    (generic_swap_fn_t)vapi_msg_api_versions_hton,
    (generic_swap_fn_t)vapi_msg_api_versions_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_api_versions = vapi_register_msg(&__vapi_metadata_api_versions);
  VAPI_DBG("Assigned msg id %d to api_versions", vapi_msg_id_api_versions);
}
#endif

#ifndef defined_vapi_msg_sockclnt_create_reply
#define defined_vapi_msg_sockclnt_create_reply
typedef struct __attribute__ ((__packed__)) {
  i32 response;
  u32 index;
  u16 count;
  vapi_type_message_table_entry message_table[0]; 
} vapi_payload_sockclnt_create_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sockclnt_create_reply payload;
} vapi_msg_sockclnt_create_reply;

static inline void vapi_msg_sockclnt_create_reply_payload_hton(vapi_payload_sockclnt_create_reply *payload)
{
  payload->response = htobe32(payload->response);
  payload->index = htobe32(payload->index);
  payload->count = htobe16(payload->count);
  do { unsigned i; for (i = 0; i < be16toh(payload->count); ++i) { vapi_type_message_table_entry_hton(&payload->message_table[i]); } } while(0);
}

static inline void vapi_msg_sockclnt_create_reply_payload_ntoh(vapi_payload_sockclnt_create_reply *payload)
{
  payload->response = be32toh(payload->response);
  payload->index = be32toh(payload->index);
  payload->count = be16toh(payload->count);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { vapi_type_message_table_entry_ntoh(&payload->message_table[i]); } } while(0);
}

static inline void vapi_msg_sockclnt_create_reply_hton(vapi_msg_sockclnt_create_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sockclnt_create_reply'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sockclnt_create_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sockclnt_create_reply_ntoh(vapi_msg_sockclnt_create_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sockclnt_create_reply'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sockclnt_create_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sockclnt_create_reply_msg_size(vapi_msg_sockclnt_create_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.message_table[0]) * msg->payload.count;
}

static inline int vapi_verify_sockclnt_create_reply_msg_size(vapi_msg_sockclnt_create_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sockclnt_create_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sockclnt_create_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sockclnt_create_reply));
      return -1;
    }
  if (vapi_calc_sockclnt_create_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sockclnt_create_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sockclnt_create_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sockclnt_create_reply()
{
  static const char name[] = "sockclnt_create_reply";
  static const char name_with_crc[] = "sockclnt_create_reply_35166268";
  static vapi_message_desc_t __vapi_metadata_sockclnt_create_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sockclnt_create_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sockclnt_create_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sockclnt_create_reply_hton,
    (generic_swap_fn_t)vapi_msg_sockclnt_create_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sockclnt_create_reply = vapi_register_msg(&__vapi_metadata_sockclnt_create_reply);
  VAPI_DBG("Assigned msg id %d to sockclnt_create_reply", vapi_msg_id_sockclnt_create_reply);
}

static inline void vapi_set_vapi_msg_sockclnt_create_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sockclnt_create_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sockclnt_create_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sockclnt_create
#define defined_vapi_msg_sockclnt_create
typedef struct __attribute__ ((__packed__)) {
  u8 name[64]; 
} vapi_payload_sockclnt_create;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sockclnt_create payload;
} vapi_msg_sockclnt_create;

static inline void vapi_msg_sockclnt_create_payload_hton(vapi_payload_sockclnt_create *payload)
{

}

static inline void vapi_msg_sockclnt_create_payload_ntoh(vapi_payload_sockclnt_create *payload)
{

}

static inline void vapi_msg_sockclnt_create_hton(vapi_msg_sockclnt_create *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sockclnt_create'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sockclnt_create_payload_hton(&msg->payload);
}

static inline void vapi_msg_sockclnt_create_ntoh(vapi_msg_sockclnt_create *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sockclnt_create'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sockclnt_create_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sockclnt_create_msg_size(vapi_msg_sockclnt_create *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sockclnt_create_msg_size(vapi_msg_sockclnt_create *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sockclnt_create) > buf_size)
    {
      VAPI_ERR("Truncated 'sockclnt_create' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sockclnt_create));
      return -1;
    }
  if (vapi_calc_sockclnt_create_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sockclnt_create' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sockclnt_create_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sockclnt_create* vapi_alloc_sockclnt_create(struct vapi_ctx_s *ctx)
{
  vapi_msg_sockclnt_create *msg = NULL;
  const size_t size = sizeof(vapi_msg_sockclnt_create);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sockclnt_create*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sockclnt_create);

  return msg;
}

static inline vapi_error_e vapi_sockclnt_create(struct vapi_ctx_s *ctx,
  vapi_msg_sockclnt_create *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sockclnt_create_reply *reply),
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
  vapi_msg_sockclnt_create_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sockclnt_create_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sockclnt_create_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sockclnt_create()
{
  static const char name[] = "sockclnt_create";
  static const char name_with_crc[] = "sockclnt_create_455fb9c4";
  static vapi_message_desc_t __vapi_metadata_sockclnt_create = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sockclnt_create, payload),
    (verify_msg_size_fn_t)vapi_verify_sockclnt_create_msg_size,
    (generic_swap_fn_t)vapi_msg_sockclnt_create_hton,
    (generic_swap_fn_t)vapi_msg_sockclnt_create_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sockclnt_create = vapi_register_msg(&__vapi_metadata_sockclnt_create);
  VAPI_DBG("Assigned msg id %d to sockclnt_create", vapi_msg_id_sockclnt_create);
}
#endif

#ifndef defined_vapi_msg_sockclnt_delete_reply
#define defined_vapi_msg_sockclnt_delete_reply
typedef struct __attribute__ ((__packed__)) {
  i32 response; 
} vapi_payload_sockclnt_delete_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sockclnt_delete_reply payload;
} vapi_msg_sockclnt_delete_reply;

static inline void vapi_msg_sockclnt_delete_reply_payload_hton(vapi_payload_sockclnt_delete_reply *payload)
{
  payload->response = htobe32(payload->response);
}

static inline void vapi_msg_sockclnt_delete_reply_payload_ntoh(vapi_payload_sockclnt_delete_reply *payload)
{
  payload->response = be32toh(payload->response);
}

static inline void vapi_msg_sockclnt_delete_reply_hton(vapi_msg_sockclnt_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sockclnt_delete_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sockclnt_delete_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sockclnt_delete_reply_ntoh(vapi_msg_sockclnt_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sockclnt_delete_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sockclnt_delete_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sockclnt_delete_reply_msg_size(vapi_msg_sockclnt_delete_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sockclnt_delete_reply_msg_size(vapi_msg_sockclnt_delete_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sockclnt_delete_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sockclnt_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sockclnt_delete_reply));
      return -1;
    }
  if (vapi_calc_sockclnt_delete_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sockclnt_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sockclnt_delete_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sockclnt_delete_reply()
{
  static const char name[] = "sockclnt_delete_reply";
  static const char name_with_crc[] = "sockclnt_delete_reply_8f38b1ee";
  static vapi_message_desc_t __vapi_metadata_sockclnt_delete_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sockclnt_delete_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sockclnt_delete_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sockclnt_delete_reply_hton,
    (generic_swap_fn_t)vapi_msg_sockclnt_delete_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sockclnt_delete_reply = vapi_register_msg(&__vapi_metadata_sockclnt_delete_reply);
  VAPI_DBG("Assigned msg id %d to sockclnt_delete_reply", vapi_msg_id_sockclnt_delete_reply);
}

static inline void vapi_set_vapi_msg_sockclnt_delete_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sockclnt_delete_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sockclnt_delete_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sockclnt_delete
#define defined_vapi_msg_sockclnt_delete
typedef struct __attribute__ ((__packed__)) {
  u32 index; 
} vapi_payload_sockclnt_delete;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sockclnt_delete payload;
} vapi_msg_sockclnt_delete;

static inline void vapi_msg_sockclnt_delete_payload_hton(vapi_payload_sockclnt_delete *payload)
{
  payload->index = htobe32(payload->index);
}

static inline void vapi_msg_sockclnt_delete_payload_ntoh(vapi_payload_sockclnt_delete *payload)
{
  payload->index = be32toh(payload->index);
}

static inline void vapi_msg_sockclnt_delete_hton(vapi_msg_sockclnt_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sockclnt_delete'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sockclnt_delete_payload_hton(&msg->payload);
}

static inline void vapi_msg_sockclnt_delete_ntoh(vapi_msg_sockclnt_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sockclnt_delete'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sockclnt_delete_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sockclnt_delete_msg_size(vapi_msg_sockclnt_delete *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sockclnt_delete_msg_size(vapi_msg_sockclnt_delete *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sockclnt_delete) > buf_size)
    {
      VAPI_ERR("Truncated 'sockclnt_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sockclnt_delete));
      return -1;
    }
  if (vapi_calc_sockclnt_delete_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sockclnt_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sockclnt_delete_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sockclnt_delete* vapi_alloc_sockclnt_delete(struct vapi_ctx_s *ctx)
{
  vapi_msg_sockclnt_delete *msg = NULL;
  const size_t size = sizeof(vapi_msg_sockclnt_delete);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sockclnt_delete*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sockclnt_delete);

  return msg;
}

static inline vapi_error_e vapi_sockclnt_delete(struct vapi_ctx_s *ctx,
  vapi_msg_sockclnt_delete *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sockclnt_delete_reply *reply),
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
  vapi_msg_sockclnt_delete_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sockclnt_delete_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sockclnt_delete_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sockclnt_delete()
{
  static const char name[] = "sockclnt_delete";
  static const char name_with_crc[] = "sockclnt_delete_8ac76db6";
  static vapi_message_desc_t __vapi_metadata_sockclnt_delete = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sockclnt_delete, payload),
    (verify_msg_size_fn_t)vapi_verify_sockclnt_delete_msg_size,
    (generic_swap_fn_t)vapi_msg_sockclnt_delete_hton,
    (generic_swap_fn_t)vapi_msg_sockclnt_delete_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sockclnt_delete = vapi_register_msg(&__vapi_metadata_sockclnt_delete);
  VAPI_DBG("Assigned msg id %d to sockclnt_delete", vapi_msg_id_sockclnt_delete);
}
#endif

#ifndef defined_vapi_msg_sock_init_shm_reply
#define defined_vapi_msg_sock_init_shm_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_sock_init_shm_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sock_init_shm_reply payload;
} vapi_msg_sock_init_shm_reply;

static inline void vapi_msg_sock_init_shm_reply_payload_hton(vapi_payload_sock_init_shm_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_sock_init_shm_reply_payload_ntoh(vapi_payload_sock_init_shm_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_sock_init_shm_reply_hton(vapi_msg_sock_init_shm_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sock_init_shm_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sock_init_shm_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sock_init_shm_reply_ntoh(vapi_msg_sock_init_shm_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sock_init_shm_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sock_init_shm_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sock_init_shm_reply_msg_size(vapi_msg_sock_init_shm_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sock_init_shm_reply_msg_size(vapi_msg_sock_init_shm_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sock_init_shm_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sock_init_shm_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sock_init_shm_reply));
      return -1;
    }
  if (vapi_calc_sock_init_shm_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sock_init_shm_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sock_init_shm_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sock_init_shm_reply()
{
  static const char name[] = "sock_init_shm_reply";
  static const char name_with_crc[] = "sock_init_shm_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_sock_init_shm_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sock_init_shm_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sock_init_shm_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sock_init_shm_reply_hton,
    (generic_swap_fn_t)vapi_msg_sock_init_shm_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sock_init_shm_reply = vapi_register_msg(&__vapi_metadata_sock_init_shm_reply);
  VAPI_DBG("Assigned msg id %d to sock_init_shm_reply", vapi_msg_id_sock_init_shm_reply);
}

static inline void vapi_set_vapi_msg_sock_init_shm_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sock_init_shm_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sock_init_shm_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sock_init_shm
#define defined_vapi_msg_sock_init_shm
typedef struct __attribute__ ((__packed__)) {
  u32 requested_size;
  u8 nitems;
  u64 configs[0]; 
} vapi_payload_sock_init_shm;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sock_init_shm payload;
} vapi_msg_sock_init_shm;

static inline void vapi_msg_sock_init_shm_payload_hton(vapi_payload_sock_init_shm *payload)
{
  payload->requested_size = htobe32(payload->requested_size);
  do { unsigned i; for (i = 0; i < payload->nitems; ++i) { payload->configs[i] = htobe64(payload->configs[i]); } } while(0);
}

static inline void vapi_msg_sock_init_shm_payload_ntoh(vapi_payload_sock_init_shm *payload)
{
  payload->requested_size = be32toh(payload->requested_size);
  do { unsigned i; for (i = 0; i < payload->nitems; ++i) { payload->configs[i] = be64toh(payload->configs[i]); } } while(0);
}

static inline void vapi_msg_sock_init_shm_hton(vapi_msg_sock_init_shm *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sock_init_shm'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sock_init_shm_payload_hton(&msg->payload);
}

static inline void vapi_msg_sock_init_shm_ntoh(vapi_msg_sock_init_shm *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sock_init_shm'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sock_init_shm_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sock_init_shm_msg_size(vapi_msg_sock_init_shm *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.configs[0]) * msg->payload.nitems;
}

static inline int vapi_verify_sock_init_shm_msg_size(vapi_msg_sock_init_shm *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sock_init_shm) > buf_size)
    {
      VAPI_ERR("Truncated 'sock_init_shm' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sock_init_shm));
      return -1;
    }
  if (vapi_calc_sock_init_shm_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sock_init_shm' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sock_init_shm_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sock_init_shm* vapi_alloc_sock_init_shm(struct vapi_ctx_s *ctx, size_t _configs_array_size)
{
  vapi_msg_sock_init_shm *msg = NULL;
  const size_t size = sizeof(vapi_msg_sock_init_shm) + sizeof(msg->payload.configs[0]) * _configs_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sock_init_shm*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sock_init_shm);
  msg->payload.nitems = _configs_array_size;

  return msg;
}

static inline vapi_error_e vapi_sock_init_shm(struct vapi_ctx_s *ctx,
  vapi_msg_sock_init_shm *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sock_init_shm_reply *reply),
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
  vapi_msg_sock_init_shm_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sock_init_shm_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sock_init_shm_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sock_init_shm()
{
  static const char name[] = "sock_init_shm";
  static const char name_with_crc[] = "sock_init_shm_51646d92";
  static vapi_message_desc_t __vapi_metadata_sock_init_shm = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sock_init_shm, payload),
    (verify_msg_size_fn_t)vapi_verify_sock_init_shm_msg_size,
    (generic_swap_fn_t)vapi_msg_sock_init_shm_hton,
    (generic_swap_fn_t)vapi_msg_sock_init_shm_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sock_init_shm = vapi_register_msg(&__vapi_metadata_sock_init_shm);
  VAPI_DBG("Assigned msg id %d to sock_init_shm", vapi_msg_id_sock_init_shm);
}
#endif

#ifndef defined_vapi_msg_memclnt_keepalive_reply
#define defined_vapi_msg_memclnt_keepalive_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_memclnt_keepalive_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_memclnt_keepalive_reply payload;
} vapi_msg_memclnt_keepalive_reply;

static inline void vapi_msg_memclnt_keepalive_reply_payload_hton(vapi_payload_memclnt_keepalive_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_memclnt_keepalive_reply_payload_ntoh(vapi_payload_memclnt_keepalive_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_memclnt_keepalive_reply_hton(vapi_msg_memclnt_keepalive_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_memclnt_keepalive_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_memclnt_keepalive_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_memclnt_keepalive_reply_ntoh(vapi_msg_memclnt_keepalive_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_memclnt_keepalive_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_memclnt_keepalive_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_memclnt_keepalive_reply_msg_size(vapi_msg_memclnt_keepalive_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_memclnt_keepalive_reply_msg_size(vapi_msg_memclnt_keepalive_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_memclnt_keepalive_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'memclnt_keepalive_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_memclnt_keepalive_reply));
      return -1;
    }
  if (vapi_calc_memclnt_keepalive_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'memclnt_keepalive_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_memclnt_keepalive_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_memclnt_keepalive_reply()
{
  static const char name[] = "memclnt_keepalive_reply";
  static const char name_with_crc[] = "memclnt_keepalive_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_memclnt_keepalive_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_memclnt_keepalive_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_memclnt_keepalive_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_memclnt_keepalive_reply_hton,
    (generic_swap_fn_t)vapi_msg_memclnt_keepalive_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_memclnt_keepalive_reply = vapi_register_msg(&__vapi_metadata_memclnt_keepalive_reply);
  VAPI_DBG("Assigned msg id %d to memclnt_keepalive_reply", vapi_msg_id_memclnt_keepalive_reply);
}

static inline void vapi_set_vapi_msg_memclnt_keepalive_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_memclnt_keepalive_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_memclnt_keepalive_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_memclnt_keepalive
#define defined_vapi_msg_memclnt_keepalive
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_memclnt_keepalive;

static inline void vapi_msg_memclnt_keepalive_hton(vapi_msg_memclnt_keepalive *msg)
{
  VAPI_DBG("Swapping `vapi_msg_memclnt_keepalive'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_memclnt_keepalive_ntoh(vapi_msg_memclnt_keepalive *msg)
{
  VAPI_DBG("Swapping `vapi_msg_memclnt_keepalive'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_memclnt_keepalive_msg_size(vapi_msg_memclnt_keepalive *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_memclnt_keepalive_msg_size(vapi_msg_memclnt_keepalive *msg, uword buf_size)
{
  if (sizeof(vapi_msg_memclnt_keepalive) > buf_size)
    {
      VAPI_ERR("Truncated 'memclnt_keepalive' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_memclnt_keepalive));
      return -1;
    }
  if (vapi_calc_memclnt_keepalive_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'memclnt_keepalive' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_memclnt_keepalive_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_memclnt_keepalive* vapi_alloc_memclnt_keepalive(struct vapi_ctx_s *ctx)
{
  vapi_msg_memclnt_keepalive *msg = NULL;
  const size_t size = sizeof(vapi_msg_memclnt_keepalive);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_memclnt_keepalive*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_memclnt_keepalive);

  return msg;
}

static inline vapi_error_e vapi_memclnt_keepalive(struct vapi_ctx_s *ctx,
  vapi_msg_memclnt_keepalive *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_memclnt_keepalive_reply *reply),
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
  vapi_msg_memclnt_keepalive_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_memclnt_keepalive_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_memclnt_keepalive_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_memclnt_keepalive()
{
  static const char name[] = "memclnt_keepalive";
  static const char name_with_crc[] = "memclnt_keepalive_51077d14";
  static vapi_message_desc_t __vapi_metadata_memclnt_keepalive = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_memclnt_keepalive_msg_size,
    (generic_swap_fn_t)vapi_msg_memclnt_keepalive_hton,
    (generic_swap_fn_t)vapi_msg_memclnt_keepalive_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_memclnt_keepalive = vapi_register_msg(&__vapi_metadata_memclnt_keepalive);
  VAPI_DBG("Assigned msg id %d to memclnt_keepalive", vapi_msg_id_memclnt_keepalive);
}
#endif

#ifndef defined_vapi_msg_control_ping_reply
#define defined_vapi_msg_control_ping_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 client_index;
  u32 vpe_pid; 
} vapi_payload_control_ping_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_control_ping_reply payload;
} vapi_msg_control_ping_reply;

static inline void vapi_msg_control_ping_reply_payload_hton(vapi_payload_control_ping_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->client_index = htobe32(payload->client_index);
  payload->vpe_pid = htobe32(payload->vpe_pid);
}

static inline void vapi_msg_control_ping_reply_payload_ntoh(vapi_payload_control_ping_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->client_index = be32toh(payload->client_index);
  payload->vpe_pid = be32toh(payload->vpe_pid);
}

static inline void vapi_msg_control_ping_reply_hton(vapi_msg_control_ping_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_control_ping_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_control_ping_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_control_ping_reply_ntoh(vapi_msg_control_ping_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_control_ping_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_control_ping_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_control_ping_reply_msg_size(vapi_msg_control_ping_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_control_ping_reply_msg_size(vapi_msg_control_ping_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_control_ping_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'control_ping_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_control_ping_reply));
      return -1;
    }
  if (vapi_calc_control_ping_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'control_ping_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_control_ping_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_control_ping_reply()
{
  static const char name[] = "control_ping_reply";
  static const char name_with_crc[] = "control_ping_reply_f6b0b8ca";
  static vapi_message_desc_t __vapi_metadata_control_ping_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_control_ping_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_control_ping_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_control_ping_reply_hton,
    (generic_swap_fn_t)vapi_msg_control_ping_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_control_ping_reply = vapi_register_msg(&__vapi_metadata_control_ping_reply);
  VAPI_DBG("Assigned msg id %d to control_ping_reply", vapi_msg_id_control_ping_reply);
}

static inline void vapi_set_vapi_msg_control_ping_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_control_ping_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_control_ping_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_control_ping
#define defined_vapi_msg_control_ping
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_control_ping;

static inline void vapi_msg_control_ping_hton(vapi_msg_control_ping *msg)
{
  VAPI_DBG("Swapping `vapi_msg_control_ping'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_control_ping_ntoh(vapi_msg_control_ping *msg)
{
  VAPI_DBG("Swapping `vapi_msg_control_ping'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_control_ping_msg_size(vapi_msg_control_ping *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_control_ping_msg_size(vapi_msg_control_ping *msg, uword buf_size)
{
  if (sizeof(vapi_msg_control_ping) > buf_size)
    {
      VAPI_ERR("Truncated 'control_ping' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_control_ping));
      return -1;
    }
  if (vapi_calc_control_ping_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'control_ping' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_control_ping_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_control_ping* vapi_alloc_control_ping(struct vapi_ctx_s *ctx)
{
  vapi_msg_control_ping *msg = NULL;
  const size_t size = sizeof(vapi_msg_control_ping);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_control_ping*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_control_ping);

  return msg;
}

static inline vapi_error_e vapi_control_ping(struct vapi_ctx_s *ctx,
  vapi_msg_control_ping *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_control_ping_reply *reply),
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
  vapi_msg_control_ping_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_control_ping_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_control_ping_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_control_ping()
{
  static const char name[] = "control_ping";
  static const char name_with_crc[] = "control_ping_51077d14";
  static vapi_message_desc_t __vapi_metadata_control_ping = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_control_ping_msg_size,
    (generic_swap_fn_t)vapi_msg_control_ping_hton,
    (generic_swap_fn_t)vapi_msg_control_ping_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_control_ping = vapi_register_msg(&__vapi_metadata_control_ping);
  VAPI_DBG("Assigned msg id %d to control_ping", vapi_msg_id_control_ping);
}
#endif

#ifndef defined_vapi_msg_memclnt_create_v2_reply
#define defined_vapi_msg_memclnt_create_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 response;
  u64 handle;
  u32 index;
  u64 message_table; 
} vapi_payload_memclnt_create_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_memclnt_create_v2_reply payload;
} vapi_msg_memclnt_create_v2_reply;

static inline void vapi_msg_memclnt_create_v2_reply_payload_hton(vapi_payload_memclnt_create_v2_reply *payload)
{
  payload->response = htobe32(payload->response);
  payload->handle = htobe64(payload->handle);
  payload->index = htobe32(payload->index);
  payload->message_table = htobe64(payload->message_table);
}

static inline void vapi_msg_memclnt_create_v2_reply_payload_ntoh(vapi_payload_memclnt_create_v2_reply *payload)
{
  payload->response = be32toh(payload->response);
  payload->handle = be64toh(payload->handle);
  payload->index = be32toh(payload->index);
  payload->message_table = be64toh(payload->message_table);
}

static inline void vapi_msg_memclnt_create_v2_reply_hton(vapi_msg_memclnt_create_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_memclnt_create_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_memclnt_create_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_memclnt_create_v2_reply_ntoh(vapi_msg_memclnt_create_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_memclnt_create_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_memclnt_create_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_memclnt_create_v2_reply_msg_size(vapi_msg_memclnt_create_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_memclnt_create_v2_reply_msg_size(vapi_msg_memclnt_create_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_memclnt_create_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'memclnt_create_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_memclnt_create_v2_reply));
      return -1;
    }
  if (vapi_calc_memclnt_create_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'memclnt_create_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_memclnt_create_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_memclnt_create_v2_reply()
{
  static const char name[] = "memclnt_create_v2_reply";
  static const char name_with_crc[] = "memclnt_create_v2_reply_42ec4560";
  static vapi_message_desc_t __vapi_metadata_memclnt_create_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_memclnt_create_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_memclnt_create_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_memclnt_create_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_memclnt_create_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_memclnt_create_v2_reply = vapi_register_msg(&__vapi_metadata_memclnt_create_v2_reply);
  VAPI_DBG("Assigned msg id %d to memclnt_create_v2_reply", vapi_msg_id_memclnt_create_v2_reply);
}

static inline void vapi_set_vapi_msg_memclnt_create_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_memclnt_create_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_memclnt_create_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_memclnt_create_v2
#define defined_vapi_msg_memclnt_create_v2
typedef struct __attribute__ ((__packed__)) {
  i32 ctx_quota;
  u64 input_queue;
  u8 name[64];
  u32 api_versions[8];
  bool keepalive; 
} vapi_payload_memclnt_create_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_memclnt_create_v2 payload;
} vapi_msg_memclnt_create_v2;

static inline void vapi_msg_memclnt_create_v2_payload_hton(vapi_payload_memclnt_create_v2 *payload)
{
  payload->ctx_quota = htobe32(payload->ctx_quota);
  payload->input_queue = htobe64(payload->input_queue);
  do { unsigned i; for (i = 0; i < 8; ++i) { payload->api_versions[i] = htobe32(payload->api_versions[i]); } } while(0);
}

static inline void vapi_msg_memclnt_create_v2_payload_ntoh(vapi_payload_memclnt_create_v2 *payload)
{
  payload->ctx_quota = be32toh(payload->ctx_quota);
  payload->input_queue = be64toh(payload->input_queue);
  do { unsigned i; for (i = 0; i < 8; ++i) { payload->api_versions[i] = be32toh(payload->api_versions[i]); } } while(0);
}

static inline void vapi_msg_memclnt_create_v2_hton(vapi_msg_memclnt_create_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_memclnt_create_v2'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_memclnt_create_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_memclnt_create_v2_ntoh(vapi_msg_memclnt_create_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_memclnt_create_v2'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_memclnt_create_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_memclnt_create_v2_msg_size(vapi_msg_memclnt_create_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_memclnt_create_v2_msg_size(vapi_msg_memclnt_create_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_memclnt_create_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'memclnt_create_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_memclnt_create_v2));
      return -1;
    }
  if (vapi_calc_memclnt_create_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'memclnt_create_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_memclnt_create_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_memclnt_create_v2* vapi_alloc_memclnt_create_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_memclnt_create_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_memclnt_create_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_memclnt_create_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_memclnt_create_v2);

  return msg;
}

static inline vapi_error_e vapi_memclnt_create_v2(struct vapi_ctx_s *ctx,
  vapi_msg_memclnt_create_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_memclnt_create_v2_reply *reply),
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
  vapi_msg_memclnt_create_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_memclnt_create_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_memclnt_create_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_memclnt_create_v2()
{
  static const char name[] = "memclnt_create_v2";
  static const char name_with_crc[] = "memclnt_create_v2_c4bd4882";
  static vapi_message_desc_t __vapi_metadata_memclnt_create_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_memclnt_create_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_memclnt_create_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_memclnt_create_v2_hton,
    (generic_swap_fn_t)vapi_msg_memclnt_create_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_memclnt_create_v2 = vapi_register_msg(&__vapi_metadata_memclnt_create_v2);
  VAPI_DBG("Assigned msg id %d to memclnt_create_v2", vapi_msg_id_memclnt_create_v2);
}
#endif

#ifndef defined_vapi_msg_get_api_json_reply
#define defined_vapi_msg_get_api_json_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vl_api_string_t json; 
} vapi_payload_get_api_json_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_get_api_json_reply payload;
} vapi_msg_get_api_json_reply;

static inline void vapi_msg_get_api_json_reply_payload_hton(vapi_payload_get_api_json_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  vl_api_string_t_hton(&payload->json);
}

static inline void vapi_msg_get_api_json_reply_payload_ntoh(vapi_payload_get_api_json_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  vl_api_string_t_ntoh(&payload->json);
}

static inline void vapi_msg_get_api_json_reply_hton(vapi_msg_get_api_json_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_api_json_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_get_api_json_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_get_api_json_reply_ntoh(vapi_msg_get_api_json_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_api_json_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_get_api_json_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_get_api_json_reply_msg_size(vapi_msg_get_api_json_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.json.buf[0]) * msg->payload.json.length;
}

static inline int vapi_verify_get_api_json_reply_msg_size(vapi_msg_get_api_json_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_get_api_json_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'get_api_json_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_get_api_json_reply));
      return -1;
    }
  if (vapi_calc_get_api_json_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'get_api_json_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_get_api_json_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_get_api_json_reply()
{
  static const char name[] = "get_api_json_reply";
  static const char name_with_crc[] = "get_api_json_reply_ea715b59";
  static vapi_message_desc_t __vapi_metadata_get_api_json_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_get_api_json_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_get_api_json_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_get_api_json_reply_hton,
    (generic_swap_fn_t)vapi_msg_get_api_json_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_get_api_json_reply = vapi_register_msg(&__vapi_metadata_get_api_json_reply);
  VAPI_DBG("Assigned msg id %d to get_api_json_reply", vapi_msg_id_get_api_json_reply);
}

static inline void vapi_set_vapi_msg_get_api_json_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_get_api_json_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_get_api_json_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_get_api_json
#define defined_vapi_msg_get_api_json
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_get_api_json;

static inline void vapi_msg_get_api_json_hton(vapi_msg_get_api_json *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_api_json'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_get_api_json_ntoh(vapi_msg_get_api_json *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_api_json'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_get_api_json_msg_size(vapi_msg_get_api_json *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_get_api_json_msg_size(vapi_msg_get_api_json *msg, uword buf_size)
{
  if (sizeof(vapi_msg_get_api_json) > buf_size)
    {
      VAPI_ERR("Truncated 'get_api_json' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_get_api_json));
      return -1;
    }
  if (vapi_calc_get_api_json_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'get_api_json' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_get_api_json_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_get_api_json* vapi_alloc_get_api_json(struct vapi_ctx_s *ctx)
{
  vapi_msg_get_api_json *msg = NULL;
  const size_t size = sizeof(vapi_msg_get_api_json);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_get_api_json*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_get_api_json);

  return msg;
}

static inline vapi_error_e vapi_get_api_json(struct vapi_ctx_s *ctx,
  vapi_msg_get_api_json *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_get_api_json_reply *reply),
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
  vapi_msg_get_api_json_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_get_api_json_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_get_api_json_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_get_api_json()
{
  static const char name[] = "get_api_json";
  static const char name_with_crc[] = "get_api_json_51077d14";
  static vapi_message_desc_t __vapi_metadata_get_api_json = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_get_api_json_msg_size,
    (generic_swap_fn_t)vapi_msg_get_api_json_hton,
    (generic_swap_fn_t)vapi_msg_get_api_json_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_get_api_json = vapi_register_msg(&__vapi_metadata_get_api_json);
  VAPI_DBG("Assigned msg id %d to get_api_json", vapi_msg_id_get_api_json);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
