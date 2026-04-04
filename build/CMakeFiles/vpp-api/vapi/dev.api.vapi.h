#ifndef __included_dev_api_json
#define __included_dev_api_json

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

extern vapi_msg_id_t vapi_msg_id_dev_attach;
extern vapi_msg_id_t vapi_msg_id_dev_attach_reply;
extern vapi_msg_id_t vapi_msg_id_dev_detach;
extern vapi_msg_id_t vapi_msg_id_dev_detach_reply;
extern vapi_msg_id_t vapi_msg_id_dev_create_port_if;
extern vapi_msg_id_t vapi_msg_id_dev_create_port_if_reply;
extern vapi_msg_id_t vapi_msg_id_dev_remove_port_if;
extern vapi_msg_id_t vapi_msg_id_dev_remove_port_if_reply;

#define DEFINE_VAPI_MSG_IDS_DEV_API_JSON\
  vapi_msg_id_t vapi_msg_id_dev_attach;\
  vapi_msg_id_t vapi_msg_id_dev_attach_reply;\
  vapi_msg_id_t vapi_msg_id_dev_detach;\
  vapi_msg_id_t vapi_msg_id_dev_detach_reply;\
  vapi_msg_id_t vapi_msg_id_dev_create_port_if;\
  vapi_msg_id_t vapi_msg_id_dev_create_port_if_reply;\
  vapi_msg_id_t vapi_msg_id_dev_remove_port_if;\
  vapi_msg_id_t vapi_msg_id_dev_remove_port_if_reply;


#ifndef defined_vapi_enum_dev_flags
#define defined_vapi_enum_dev_flags
typedef enum {
  VL_API_DEV_FLAG_NO_STATS = 1,
}  vapi_enum_dev_flags;

#endif

#ifndef defined_vapi_enum_dev_port_flags
#define defined_vapi_enum_dev_port_flags
typedef enum {
  VL_API_DEV_PORT_FLAG_INTERRUPT_MODE = 1,
  VL_API_DEV_PORT_FLAG_CONSISTENT_QP = 2,
}  vapi_enum_dev_port_flags;

#endif

#ifndef defined_vapi_msg_dev_attach_reply
#define defined_vapi_msg_dev_attach_reply
typedef struct __attribute__ ((__packed__)) {
  u32 dev_index;
  i32 retval;
  vl_api_string_t error_string; 
} vapi_payload_dev_attach_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_dev_attach_reply payload;
} vapi_msg_dev_attach_reply;

static inline void vapi_msg_dev_attach_reply_payload_hton(vapi_payload_dev_attach_reply *payload)
{
  payload->dev_index = htobe32(payload->dev_index);
  payload->retval = htobe32(payload->retval);
  vl_api_string_t_hton(&payload->error_string);
}

static inline void vapi_msg_dev_attach_reply_payload_ntoh(vapi_payload_dev_attach_reply *payload)
{
  payload->dev_index = be32toh(payload->dev_index);
  payload->retval = be32toh(payload->retval);
  vl_api_string_t_ntoh(&payload->error_string);
}

static inline void vapi_msg_dev_attach_reply_hton(vapi_msg_dev_attach_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dev_attach_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_dev_attach_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_dev_attach_reply_ntoh(vapi_msg_dev_attach_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dev_attach_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_dev_attach_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dev_attach_reply_msg_size(vapi_msg_dev_attach_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.error_string.buf[0]) * msg->payload.error_string.length;
}

static inline int vapi_verify_dev_attach_reply_msg_size(vapi_msg_dev_attach_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dev_attach_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'dev_attach_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dev_attach_reply));
      return -1;
    }
  if (vapi_calc_dev_attach_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dev_attach_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dev_attach_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dev_attach_reply()
{
  static const char name[] = "dev_attach_reply";
  static const char name_with_crc[] = "dev_attach_reply_6082b181";
  static vapi_message_desc_t __vapi_metadata_dev_attach_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_dev_attach_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_dev_attach_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_dev_attach_reply_hton,
    (generic_swap_fn_t)vapi_msg_dev_attach_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dev_attach_reply = vapi_register_msg(&__vapi_metadata_dev_attach_reply);
  VAPI_DBG("Assigned msg id %d to dev_attach_reply", vapi_msg_id_dev_attach_reply);
}

static inline void vapi_set_vapi_msg_dev_attach_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dev_attach_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dev_attach_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dev_attach
#define defined_vapi_msg_dev_attach
typedef struct __attribute__ ((__packed__)) {
  u8 device_id[48];
  u8 driver_name[16];
  vapi_enum_dev_flags flags;
  vl_api_string_t args; 
} vapi_payload_dev_attach;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_dev_attach payload;
} vapi_msg_dev_attach;

static inline void vapi_msg_dev_attach_payload_hton(vapi_payload_dev_attach *payload)
{
  payload->flags = (vapi_enum_dev_flags)htobe32(payload->flags);
  vl_api_string_t_hton(&payload->args);
}

static inline void vapi_msg_dev_attach_payload_ntoh(vapi_payload_dev_attach *payload)
{
  payload->flags = (vapi_enum_dev_flags)be32toh(payload->flags);
  vl_api_string_t_ntoh(&payload->args);
}

static inline void vapi_msg_dev_attach_hton(vapi_msg_dev_attach *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dev_attach'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_dev_attach_payload_hton(&msg->payload);
}

static inline void vapi_msg_dev_attach_ntoh(vapi_msg_dev_attach *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dev_attach'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_dev_attach_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dev_attach_msg_size(vapi_msg_dev_attach *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.args.buf[0]) * msg->payload.args.length;
}

static inline int vapi_verify_dev_attach_msg_size(vapi_msg_dev_attach *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dev_attach) > buf_size)
    {
      VAPI_ERR("Truncated 'dev_attach' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dev_attach));
      return -1;
    }
  if (vapi_calc_dev_attach_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dev_attach' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dev_attach_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_dev_attach* vapi_alloc_dev_attach(struct vapi_ctx_s *ctx, size_t args_buf_array_size)
{
  vapi_msg_dev_attach *msg = NULL;
  const size_t size = sizeof(vapi_msg_dev_attach) + sizeof(msg->payload.args.buf[0]) * args_buf_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_dev_attach*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_dev_attach);
  msg->payload.args.length = args_buf_array_size;

  return msg;
}

static inline vapi_error_e vapi_dev_attach(struct vapi_ctx_s *ctx,
  vapi_msg_dev_attach *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_dev_attach_reply *reply),
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
  vapi_msg_dev_attach_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_dev_attach_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_dev_attach_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_dev_attach()
{
  static const char name[] = "dev_attach";
  static const char name_with_crc[] = "dev_attach_44b725fc";
  static vapi_message_desc_t __vapi_metadata_dev_attach = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_dev_attach, payload),
    (verify_msg_size_fn_t)vapi_verify_dev_attach_msg_size,
    (generic_swap_fn_t)vapi_msg_dev_attach_hton,
    (generic_swap_fn_t)vapi_msg_dev_attach_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dev_attach = vapi_register_msg(&__vapi_metadata_dev_attach);
  VAPI_DBG("Assigned msg id %d to dev_attach", vapi_msg_id_dev_attach);
}
#endif

#ifndef defined_vapi_msg_dev_detach_reply
#define defined_vapi_msg_dev_detach_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vl_api_string_t error_string; 
} vapi_payload_dev_detach_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_dev_detach_reply payload;
} vapi_msg_dev_detach_reply;

static inline void vapi_msg_dev_detach_reply_payload_hton(vapi_payload_dev_detach_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  vl_api_string_t_hton(&payload->error_string);
}

static inline void vapi_msg_dev_detach_reply_payload_ntoh(vapi_payload_dev_detach_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  vl_api_string_t_ntoh(&payload->error_string);
}

static inline void vapi_msg_dev_detach_reply_hton(vapi_msg_dev_detach_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dev_detach_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_dev_detach_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_dev_detach_reply_ntoh(vapi_msg_dev_detach_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dev_detach_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_dev_detach_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dev_detach_reply_msg_size(vapi_msg_dev_detach_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.error_string.buf[0]) * msg->payload.error_string.length;
}

static inline int vapi_verify_dev_detach_reply_msg_size(vapi_msg_dev_detach_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dev_detach_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'dev_detach_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dev_detach_reply));
      return -1;
    }
  if (vapi_calc_dev_detach_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dev_detach_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dev_detach_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dev_detach_reply()
{
  static const char name[] = "dev_detach_reply";
  static const char name_with_crc[] = "dev_detach_reply_c8d74455";
  static vapi_message_desc_t __vapi_metadata_dev_detach_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_dev_detach_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_dev_detach_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_dev_detach_reply_hton,
    (generic_swap_fn_t)vapi_msg_dev_detach_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dev_detach_reply = vapi_register_msg(&__vapi_metadata_dev_detach_reply);
  VAPI_DBG("Assigned msg id %d to dev_detach_reply", vapi_msg_id_dev_detach_reply);
}

static inline void vapi_set_vapi_msg_dev_detach_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dev_detach_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dev_detach_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dev_detach
#define defined_vapi_msg_dev_detach
typedef struct __attribute__ ((__packed__)) {
  u32 dev_index; 
} vapi_payload_dev_detach;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_dev_detach payload;
} vapi_msg_dev_detach;

static inline void vapi_msg_dev_detach_payload_hton(vapi_payload_dev_detach *payload)
{
  payload->dev_index = htobe32(payload->dev_index);
}

static inline void vapi_msg_dev_detach_payload_ntoh(vapi_payload_dev_detach *payload)
{
  payload->dev_index = be32toh(payload->dev_index);
}

static inline void vapi_msg_dev_detach_hton(vapi_msg_dev_detach *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dev_detach'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_dev_detach_payload_hton(&msg->payload);
}

static inline void vapi_msg_dev_detach_ntoh(vapi_msg_dev_detach *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dev_detach'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_dev_detach_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dev_detach_msg_size(vapi_msg_dev_detach *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dev_detach_msg_size(vapi_msg_dev_detach *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dev_detach) > buf_size)
    {
      VAPI_ERR("Truncated 'dev_detach' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dev_detach));
      return -1;
    }
  if (vapi_calc_dev_detach_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dev_detach' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dev_detach_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_dev_detach* vapi_alloc_dev_detach(struct vapi_ctx_s *ctx)
{
  vapi_msg_dev_detach *msg = NULL;
  const size_t size = sizeof(vapi_msg_dev_detach);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_dev_detach*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_dev_detach);

  return msg;
}

static inline vapi_error_e vapi_dev_detach(struct vapi_ctx_s *ctx,
  vapi_msg_dev_detach *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_dev_detach_reply *reply),
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
  vapi_msg_dev_detach_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_dev_detach_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_dev_detach_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_dev_detach()
{
  static const char name[] = "dev_detach";
  static const char name_with_crc[] = "dev_detach_afae52d6";
  static vapi_message_desc_t __vapi_metadata_dev_detach = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_dev_detach, payload),
    (verify_msg_size_fn_t)vapi_verify_dev_detach_msg_size,
    (generic_swap_fn_t)vapi_msg_dev_detach_hton,
    (generic_swap_fn_t)vapi_msg_dev_detach_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dev_detach = vapi_register_msg(&__vapi_metadata_dev_detach);
  VAPI_DBG("Assigned msg id %d to dev_detach", vapi_msg_id_dev_detach);
}
#endif

#ifndef defined_vapi_msg_dev_create_port_if_reply
#define defined_vapi_msg_dev_create_port_if_reply
typedef struct __attribute__ ((__packed__)) {
  u32 sw_if_index;
  i32 retval;
  vl_api_string_t error_string; 
} vapi_payload_dev_create_port_if_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_dev_create_port_if_reply payload;
} vapi_msg_dev_create_port_if_reply;

static inline void vapi_msg_dev_create_port_if_reply_payload_hton(vapi_payload_dev_create_port_if_reply *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->retval = htobe32(payload->retval);
  vl_api_string_t_hton(&payload->error_string);
}

static inline void vapi_msg_dev_create_port_if_reply_payload_ntoh(vapi_payload_dev_create_port_if_reply *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->retval = be32toh(payload->retval);
  vl_api_string_t_ntoh(&payload->error_string);
}

static inline void vapi_msg_dev_create_port_if_reply_hton(vapi_msg_dev_create_port_if_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dev_create_port_if_reply'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_dev_create_port_if_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_dev_create_port_if_reply_ntoh(vapi_msg_dev_create_port_if_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dev_create_port_if_reply'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_dev_create_port_if_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dev_create_port_if_reply_msg_size(vapi_msg_dev_create_port_if_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.error_string.buf[0]) * msg->payload.error_string.length;
}

static inline int vapi_verify_dev_create_port_if_reply_msg_size(vapi_msg_dev_create_port_if_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dev_create_port_if_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'dev_create_port_if_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dev_create_port_if_reply));
      return -1;
    }
  if (vapi_calc_dev_create_port_if_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dev_create_port_if_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dev_create_port_if_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dev_create_port_if_reply()
{
  static const char name[] = "dev_create_port_if_reply";
  static const char name_with_crc[] = "dev_create_port_if_reply_243c2374";
  static vapi_message_desc_t __vapi_metadata_dev_create_port_if_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_dev_create_port_if_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_dev_create_port_if_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_dev_create_port_if_reply_hton,
    (generic_swap_fn_t)vapi_msg_dev_create_port_if_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dev_create_port_if_reply = vapi_register_msg(&__vapi_metadata_dev_create_port_if_reply);
  VAPI_DBG("Assigned msg id %d to dev_create_port_if_reply", vapi_msg_id_dev_create_port_if_reply);
}

static inline void vapi_set_vapi_msg_dev_create_port_if_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dev_create_port_if_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dev_create_port_if_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dev_create_port_if
#define defined_vapi_msg_dev_create_port_if
typedef struct __attribute__ ((__packed__)) {
  u32 dev_index;
  u8 intf_name[32];
  u16 num_rx_queues;
  u16 num_tx_queues;
  u16 rx_queue_size;
  u16 tx_queue_size;
  u16 port_id;
  vapi_enum_dev_port_flags flags;
  vl_api_string_t args; 
} vapi_payload_dev_create_port_if;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_dev_create_port_if payload;
} vapi_msg_dev_create_port_if;

static inline void vapi_msg_dev_create_port_if_payload_hton(vapi_payload_dev_create_port_if *payload)
{
  payload->dev_index = htobe32(payload->dev_index);
  payload->num_rx_queues = htobe16(payload->num_rx_queues);
  payload->num_tx_queues = htobe16(payload->num_tx_queues);
  payload->rx_queue_size = htobe16(payload->rx_queue_size);
  payload->tx_queue_size = htobe16(payload->tx_queue_size);
  payload->port_id = htobe16(payload->port_id);
  payload->flags = (vapi_enum_dev_port_flags)htobe32(payload->flags);
  vl_api_string_t_hton(&payload->args);
}

static inline void vapi_msg_dev_create_port_if_payload_ntoh(vapi_payload_dev_create_port_if *payload)
{
  payload->dev_index = be32toh(payload->dev_index);
  payload->num_rx_queues = be16toh(payload->num_rx_queues);
  payload->num_tx_queues = be16toh(payload->num_tx_queues);
  payload->rx_queue_size = be16toh(payload->rx_queue_size);
  payload->tx_queue_size = be16toh(payload->tx_queue_size);
  payload->port_id = be16toh(payload->port_id);
  payload->flags = (vapi_enum_dev_port_flags)be32toh(payload->flags);
  vl_api_string_t_ntoh(&payload->args);
}

static inline void vapi_msg_dev_create_port_if_hton(vapi_msg_dev_create_port_if *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dev_create_port_if'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_dev_create_port_if_payload_hton(&msg->payload);
}

static inline void vapi_msg_dev_create_port_if_ntoh(vapi_msg_dev_create_port_if *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dev_create_port_if'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_dev_create_port_if_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dev_create_port_if_msg_size(vapi_msg_dev_create_port_if *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.args.buf[0]) * msg->payload.args.length;
}

static inline int vapi_verify_dev_create_port_if_msg_size(vapi_msg_dev_create_port_if *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dev_create_port_if) > buf_size)
    {
      VAPI_ERR("Truncated 'dev_create_port_if' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dev_create_port_if));
      return -1;
    }
  if (vapi_calc_dev_create_port_if_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dev_create_port_if' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dev_create_port_if_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_dev_create_port_if* vapi_alloc_dev_create_port_if(struct vapi_ctx_s *ctx, size_t args_buf_array_size)
{
  vapi_msg_dev_create_port_if *msg = NULL;
  const size_t size = sizeof(vapi_msg_dev_create_port_if) + sizeof(msg->payload.args.buf[0]) * args_buf_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_dev_create_port_if*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_dev_create_port_if);
  msg->payload.args.length = args_buf_array_size;

  return msg;
}

static inline vapi_error_e vapi_dev_create_port_if(struct vapi_ctx_s *ctx,
  vapi_msg_dev_create_port_if *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_dev_create_port_if_reply *reply),
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
  vapi_msg_dev_create_port_if_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_dev_create_port_if_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_dev_create_port_if_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_dev_create_port_if()
{
  static const char name[] = "dev_create_port_if";
  static const char name_with_crc[] = "dev_create_port_if_dbdf06f3";
  static vapi_message_desc_t __vapi_metadata_dev_create_port_if = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_dev_create_port_if, payload),
    (verify_msg_size_fn_t)vapi_verify_dev_create_port_if_msg_size,
    (generic_swap_fn_t)vapi_msg_dev_create_port_if_hton,
    (generic_swap_fn_t)vapi_msg_dev_create_port_if_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dev_create_port_if = vapi_register_msg(&__vapi_metadata_dev_create_port_if);
  VAPI_DBG("Assigned msg id %d to dev_create_port_if", vapi_msg_id_dev_create_port_if);
}
#endif

#ifndef defined_vapi_msg_dev_remove_port_if_reply
#define defined_vapi_msg_dev_remove_port_if_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vl_api_string_t error_string; 
} vapi_payload_dev_remove_port_if_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_dev_remove_port_if_reply payload;
} vapi_msg_dev_remove_port_if_reply;

static inline void vapi_msg_dev_remove_port_if_reply_payload_hton(vapi_payload_dev_remove_port_if_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  vl_api_string_t_hton(&payload->error_string);
}

static inline void vapi_msg_dev_remove_port_if_reply_payload_ntoh(vapi_payload_dev_remove_port_if_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  vl_api_string_t_ntoh(&payload->error_string);
}

static inline void vapi_msg_dev_remove_port_if_reply_hton(vapi_msg_dev_remove_port_if_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dev_remove_port_if_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_dev_remove_port_if_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_dev_remove_port_if_reply_ntoh(vapi_msg_dev_remove_port_if_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dev_remove_port_if_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_dev_remove_port_if_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dev_remove_port_if_reply_msg_size(vapi_msg_dev_remove_port_if_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.error_string.buf[0]) * msg->payload.error_string.length;
}

static inline int vapi_verify_dev_remove_port_if_reply_msg_size(vapi_msg_dev_remove_port_if_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dev_remove_port_if_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'dev_remove_port_if_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dev_remove_port_if_reply));
      return -1;
    }
  if (vapi_calc_dev_remove_port_if_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dev_remove_port_if_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dev_remove_port_if_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dev_remove_port_if_reply()
{
  static const char name[] = "dev_remove_port_if_reply";
  static const char name_with_crc[] = "dev_remove_port_if_reply_c8d74455";
  static vapi_message_desc_t __vapi_metadata_dev_remove_port_if_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_dev_remove_port_if_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_dev_remove_port_if_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_dev_remove_port_if_reply_hton,
    (generic_swap_fn_t)vapi_msg_dev_remove_port_if_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dev_remove_port_if_reply = vapi_register_msg(&__vapi_metadata_dev_remove_port_if_reply);
  VAPI_DBG("Assigned msg id %d to dev_remove_port_if_reply", vapi_msg_id_dev_remove_port_if_reply);
}

static inline void vapi_set_vapi_msg_dev_remove_port_if_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dev_remove_port_if_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dev_remove_port_if_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dev_remove_port_if
#define defined_vapi_msg_dev_remove_port_if
typedef struct __attribute__ ((__packed__)) {
  u32 sw_if_index; 
} vapi_payload_dev_remove_port_if;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_dev_remove_port_if payload;
} vapi_msg_dev_remove_port_if;

static inline void vapi_msg_dev_remove_port_if_payload_hton(vapi_payload_dev_remove_port_if *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_dev_remove_port_if_payload_ntoh(vapi_payload_dev_remove_port_if *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_dev_remove_port_if_hton(vapi_msg_dev_remove_port_if *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dev_remove_port_if'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_dev_remove_port_if_payload_hton(&msg->payload);
}

static inline void vapi_msg_dev_remove_port_if_ntoh(vapi_msg_dev_remove_port_if *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dev_remove_port_if'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_dev_remove_port_if_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dev_remove_port_if_msg_size(vapi_msg_dev_remove_port_if *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dev_remove_port_if_msg_size(vapi_msg_dev_remove_port_if *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dev_remove_port_if) > buf_size)
    {
      VAPI_ERR("Truncated 'dev_remove_port_if' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dev_remove_port_if));
      return -1;
    }
  if (vapi_calc_dev_remove_port_if_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dev_remove_port_if' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dev_remove_port_if_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_dev_remove_port_if* vapi_alloc_dev_remove_port_if(struct vapi_ctx_s *ctx)
{
  vapi_msg_dev_remove_port_if *msg = NULL;
  const size_t size = sizeof(vapi_msg_dev_remove_port_if);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_dev_remove_port_if*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_dev_remove_port_if);

  return msg;
}

static inline vapi_error_e vapi_dev_remove_port_if(struct vapi_ctx_s *ctx,
  vapi_msg_dev_remove_port_if *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_dev_remove_port_if_reply *reply),
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
  vapi_msg_dev_remove_port_if_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_dev_remove_port_if_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_dev_remove_port_if_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_dev_remove_port_if()
{
  static const char name[] = "dev_remove_port_if";
  static const char name_with_crc[] = "dev_remove_port_if_529cb13f";
  static vapi_message_desc_t __vapi_metadata_dev_remove_port_if = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_dev_remove_port_if, payload),
    (verify_msg_size_fn_t)vapi_verify_dev_remove_port_if_msg_size,
    (generic_swap_fn_t)vapi_msg_dev_remove_port_if_hton,
    (generic_swap_fn_t)vapi_msg_dev_remove_port_if_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dev_remove_port_if = vapi_register_msg(&__vapi_metadata_dev_remove_port_if);
  VAPI_DBG("Assigned msg id %d to dev_remove_port_if", vapi_msg_id_dev_remove_port_if);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
