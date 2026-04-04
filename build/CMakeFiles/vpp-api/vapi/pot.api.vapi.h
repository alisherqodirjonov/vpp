#ifndef __included_pot_api_json
#define __included_pot_api_json

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

extern vapi_msg_id_t vapi_msg_id_pot_profile_add;
extern vapi_msg_id_t vapi_msg_id_pot_profile_add_reply;
extern vapi_msg_id_t vapi_msg_id_pot_profile_activate;
extern vapi_msg_id_t vapi_msg_id_pot_profile_activate_reply;
extern vapi_msg_id_t vapi_msg_id_pot_profile_del;
extern vapi_msg_id_t vapi_msg_id_pot_profile_del_reply;
extern vapi_msg_id_t vapi_msg_id_pot_profile_show_config_dump;
extern vapi_msg_id_t vapi_msg_id_pot_profile_show_config_details;

#define DEFINE_VAPI_MSG_IDS_POT_API_JSON\
  vapi_msg_id_t vapi_msg_id_pot_profile_add;\
  vapi_msg_id_t vapi_msg_id_pot_profile_add_reply;\
  vapi_msg_id_t vapi_msg_id_pot_profile_activate;\
  vapi_msg_id_t vapi_msg_id_pot_profile_activate_reply;\
  vapi_msg_id_t vapi_msg_id_pot_profile_del;\
  vapi_msg_id_t vapi_msg_id_pot_profile_del_reply;\
  vapi_msg_id_t vapi_msg_id_pot_profile_show_config_dump;\
  vapi_msg_id_t vapi_msg_id_pot_profile_show_config_details;


#ifndef defined_vapi_msg_pot_profile_add_reply
#define defined_vapi_msg_pot_profile_add_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_pot_profile_add_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_pot_profile_add_reply payload;
} vapi_msg_pot_profile_add_reply;

static inline void vapi_msg_pot_profile_add_reply_payload_hton(vapi_payload_pot_profile_add_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_pot_profile_add_reply_payload_ntoh(vapi_payload_pot_profile_add_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_pot_profile_add_reply_hton(vapi_msg_pot_profile_add_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pot_profile_add_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_pot_profile_add_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_pot_profile_add_reply_ntoh(vapi_msg_pot_profile_add_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pot_profile_add_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_pot_profile_add_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pot_profile_add_reply_msg_size(vapi_msg_pot_profile_add_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pot_profile_add_reply_msg_size(vapi_msg_pot_profile_add_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pot_profile_add_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'pot_profile_add_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pot_profile_add_reply));
      return -1;
    }
  if (vapi_calc_pot_profile_add_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pot_profile_add_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pot_profile_add_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_pot_profile_add_reply()
{
  static const char name[] = "pot_profile_add_reply";
  static const char name_with_crc[] = "pot_profile_add_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_pot_profile_add_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_pot_profile_add_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_pot_profile_add_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_pot_profile_add_reply_hton,
    (generic_swap_fn_t)vapi_msg_pot_profile_add_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pot_profile_add_reply = vapi_register_msg(&__vapi_metadata_pot_profile_add_reply);
  VAPI_DBG("Assigned msg id %d to pot_profile_add_reply", vapi_msg_id_pot_profile_add_reply);
}

static inline void vapi_set_vapi_msg_pot_profile_add_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_pot_profile_add_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_pot_profile_add_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_pot_profile_add
#define defined_vapi_msg_pot_profile_add
typedef struct __attribute__ ((__packed__)) {
  u8 id;
  u8 validator;
  u64 secret_key;
  u64 secret_share;
  u64 prime;
  u8 max_bits;
  u64 lpc;
  u64 polynomial_public;
  vl_api_string_t list_name; 
} vapi_payload_pot_profile_add;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_pot_profile_add payload;
} vapi_msg_pot_profile_add;

static inline void vapi_msg_pot_profile_add_payload_hton(vapi_payload_pot_profile_add *payload)
{
  payload->secret_key = htobe64(payload->secret_key);
  payload->secret_share = htobe64(payload->secret_share);
  payload->prime = htobe64(payload->prime);
  payload->lpc = htobe64(payload->lpc);
  payload->polynomial_public = htobe64(payload->polynomial_public);
  vl_api_string_t_hton(&payload->list_name);
}

static inline void vapi_msg_pot_profile_add_payload_ntoh(vapi_payload_pot_profile_add *payload)
{
  payload->secret_key = be64toh(payload->secret_key);
  payload->secret_share = be64toh(payload->secret_share);
  payload->prime = be64toh(payload->prime);
  payload->lpc = be64toh(payload->lpc);
  payload->polynomial_public = be64toh(payload->polynomial_public);
  vl_api_string_t_ntoh(&payload->list_name);
}

static inline void vapi_msg_pot_profile_add_hton(vapi_msg_pot_profile_add *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pot_profile_add'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_pot_profile_add_payload_hton(&msg->payload);
}

static inline void vapi_msg_pot_profile_add_ntoh(vapi_msg_pot_profile_add *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pot_profile_add'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_pot_profile_add_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pot_profile_add_msg_size(vapi_msg_pot_profile_add *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.list_name.buf[0]) * msg->payload.list_name.length;
}

static inline int vapi_verify_pot_profile_add_msg_size(vapi_msg_pot_profile_add *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pot_profile_add) > buf_size)
    {
      VAPI_ERR("Truncated 'pot_profile_add' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pot_profile_add));
      return -1;
    }
  if (vapi_calc_pot_profile_add_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pot_profile_add' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pot_profile_add_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_pot_profile_add* vapi_alloc_pot_profile_add(struct vapi_ctx_s *ctx, size_t list_name_buf_array_size)
{
  vapi_msg_pot_profile_add *msg = NULL;
  const size_t size = sizeof(vapi_msg_pot_profile_add) + sizeof(msg->payload.list_name.buf[0]) * list_name_buf_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_pot_profile_add*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_pot_profile_add);
  msg->payload.list_name.length = list_name_buf_array_size;

  return msg;
}

static inline vapi_error_e vapi_pot_profile_add(struct vapi_ctx_s *ctx,
  vapi_msg_pot_profile_add *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_pot_profile_add_reply *reply),
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
  vapi_msg_pot_profile_add_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_pot_profile_add_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_pot_profile_add_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_pot_profile_add()
{
  static const char name[] = "pot_profile_add";
  static const char name_with_crc[] = "pot_profile_add_ad5da3a3";
  static vapi_message_desc_t __vapi_metadata_pot_profile_add = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_pot_profile_add, payload),
    (verify_msg_size_fn_t)vapi_verify_pot_profile_add_msg_size,
    (generic_swap_fn_t)vapi_msg_pot_profile_add_hton,
    (generic_swap_fn_t)vapi_msg_pot_profile_add_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pot_profile_add = vapi_register_msg(&__vapi_metadata_pot_profile_add);
  VAPI_DBG("Assigned msg id %d to pot_profile_add", vapi_msg_id_pot_profile_add);
}
#endif

#ifndef defined_vapi_msg_pot_profile_activate_reply
#define defined_vapi_msg_pot_profile_activate_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_pot_profile_activate_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_pot_profile_activate_reply payload;
} vapi_msg_pot_profile_activate_reply;

static inline void vapi_msg_pot_profile_activate_reply_payload_hton(vapi_payload_pot_profile_activate_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_pot_profile_activate_reply_payload_ntoh(vapi_payload_pot_profile_activate_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_pot_profile_activate_reply_hton(vapi_msg_pot_profile_activate_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pot_profile_activate_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_pot_profile_activate_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_pot_profile_activate_reply_ntoh(vapi_msg_pot_profile_activate_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pot_profile_activate_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_pot_profile_activate_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pot_profile_activate_reply_msg_size(vapi_msg_pot_profile_activate_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pot_profile_activate_reply_msg_size(vapi_msg_pot_profile_activate_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pot_profile_activate_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'pot_profile_activate_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pot_profile_activate_reply));
      return -1;
    }
  if (vapi_calc_pot_profile_activate_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pot_profile_activate_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pot_profile_activate_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_pot_profile_activate_reply()
{
  static const char name[] = "pot_profile_activate_reply";
  static const char name_with_crc[] = "pot_profile_activate_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_pot_profile_activate_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_pot_profile_activate_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_pot_profile_activate_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_pot_profile_activate_reply_hton,
    (generic_swap_fn_t)vapi_msg_pot_profile_activate_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pot_profile_activate_reply = vapi_register_msg(&__vapi_metadata_pot_profile_activate_reply);
  VAPI_DBG("Assigned msg id %d to pot_profile_activate_reply", vapi_msg_id_pot_profile_activate_reply);
}

static inline void vapi_set_vapi_msg_pot_profile_activate_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_pot_profile_activate_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_pot_profile_activate_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_pot_profile_activate
#define defined_vapi_msg_pot_profile_activate
typedef struct __attribute__ ((__packed__)) {
  u8 id;
  vl_api_string_t list_name; 
} vapi_payload_pot_profile_activate;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_pot_profile_activate payload;
} vapi_msg_pot_profile_activate;

static inline void vapi_msg_pot_profile_activate_payload_hton(vapi_payload_pot_profile_activate *payload)
{
  vl_api_string_t_hton(&payload->list_name);
}

static inline void vapi_msg_pot_profile_activate_payload_ntoh(vapi_payload_pot_profile_activate *payload)
{
  vl_api_string_t_ntoh(&payload->list_name);
}

static inline void vapi_msg_pot_profile_activate_hton(vapi_msg_pot_profile_activate *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pot_profile_activate'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_pot_profile_activate_payload_hton(&msg->payload);
}

static inline void vapi_msg_pot_profile_activate_ntoh(vapi_msg_pot_profile_activate *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pot_profile_activate'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_pot_profile_activate_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pot_profile_activate_msg_size(vapi_msg_pot_profile_activate *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.list_name.buf[0]) * msg->payload.list_name.length;
}

static inline int vapi_verify_pot_profile_activate_msg_size(vapi_msg_pot_profile_activate *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pot_profile_activate) > buf_size)
    {
      VAPI_ERR("Truncated 'pot_profile_activate' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pot_profile_activate));
      return -1;
    }
  if (vapi_calc_pot_profile_activate_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pot_profile_activate' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pot_profile_activate_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_pot_profile_activate* vapi_alloc_pot_profile_activate(struct vapi_ctx_s *ctx, size_t list_name_buf_array_size)
{
  vapi_msg_pot_profile_activate *msg = NULL;
  const size_t size = sizeof(vapi_msg_pot_profile_activate) + sizeof(msg->payload.list_name.buf[0]) * list_name_buf_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_pot_profile_activate*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_pot_profile_activate);
  msg->payload.list_name.length = list_name_buf_array_size;

  return msg;
}

static inline vapi_error_e vapi_pot_profile_activate(struct vapi_ctx_s *ctx,
  vapi_msg_pot_profile_activate *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_pot_profile_activate_reply *reply),
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
  vapi_msg_pot_profile_activate_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_pot_profile_activate_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_pot_profile_activate_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_pot_profile_activate()
{
  static const char name[] = "pot_profile_activate";
  static const char name_with_crc[] = "pot_profile_activate_0770af98";
  static vapi_message_desc_t __vapi_metadata_pot_profile_activate = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_pot_profile_activate, payload),
    (verify_msg_size_fn_t)vapi_verify_pot_profile_activate_msg_size,
    (generic_swap_fn_t)vapi_msg_pot_profile_activate_hton,
    (generic_swap_fn_t)vapi_msg_pot_profile_activate_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pot_profile_activate = vapi_register_msg(&__vapi_metadata_pot_profile_activate);
  VAPI_DBG("Assigned msg id %d to pot_profile_activate", vapi_msg_id_pot_profile_activate);
}
#endif

#ifndef defined_vapi_msg_pot_profile_del_reply
#define defined_vapi_msg_pot_profile_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_pot_profile_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_pot_profile_del_reply payload;
} vapi_msg_pot_profile_del_reply;

static inline void vapi_msg_pot_profile_del_reply_payload_hton(vapi_payload_pot_profile_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_pot_profile_del_reply_payload_ntoh(vapi_payload_pot_profile_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_pot_profile_del_reply_hton(vapi_msg_pot_profile_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pot_profile_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_pot_profile_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_pot_profile_del_reply_ntoh(vapi_msg_pot_profile_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pot_profile_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_pot_profile_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pot_profile_del_reply_msg_size(vapi_msg_pot_profile_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pot_profile_del_reply_msg_size(vapi_msg_pot_profile_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pot_profile_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'pot_profile_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pot_profile_del_reply));
      return -1;
    }
  if (vapi_calc_pot_profile_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pot_profile_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pot_profile_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_pot_profile_del_reply()
{
  static const char name[] = "pot_profile_del_reply";
  static const char name_with_crc[] = "pot_profile_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_pot_profile_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_pot_profile_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_pot_profile_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_pot_profile_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_pot_profile_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pot_profile_del_reply = vapi_register_msg(&__vapi_metadata_pot_profile_del_reply);
  VAPI_DBG("Assigned msg id %d to pot_profile_del_reply", vapi_msg_id_pot_profile_del_reply);
}

static inline void vapi_set_vapi_msg_pot_profile_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_pot_profile_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_pot_profile_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_pot_profile_del
#define defined_vapi_msg_pot_profile_del
typedef struct __attribute__ ((__packed__)) {
  vl_api_string_t list_name; 
} vapi_payload_pot_profile_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_pot_profile_del payload;
} vapi_msg_pot_profile_del;

static inline void vapi_msg_pot_profile_del_payload_hton(vapi_payload_pot_profile_del *payload)
{
  vl_api_string_t_hton(&payload->list_name);
}

static inline void vapi_msg_pot_profile_del_payload_ntoh(vapi_payload_pot_profile_del *payload)
{
  vl_api_string_t_ntoh(&payload->list_name);
}

static inline void vapi_msg_pot_profile_del_hton(vapi_msg_pot_profile_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pot_profile_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_pot_profile_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_pot_profile_del_ntoh(vapi_msg_pot_profile_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pot_profile_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_pot_profile_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pot_profile_del_msg_size(vapi_msg_pot_profile_del *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.list_name.buf[0]) * msg->payload.list_name.length;
}

static inline int vapi_verify_pot_profile_del_msg_size(vapi_msg_pot_profile_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pot_profile_del) > buf_size)
    {
      VAPI_ERR("Truncated 'pot_profile_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pot_profile_del));
      return -1;
    }
  if (vapi_calc_pot_profile_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pot_profile_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pot_profile_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_pot_profile_del* vapi_alloc_pot_profile_del(struct vapi_ctx_s *ctx, size_t list_name_buf_array_size)
{
  vapi_msg_pot_profile_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_pot_profile_del) + sizeof(msg->payload.list_name.buf[0]) * list_name_buf_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_pot_profile_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_pot_profile_del);
  msg->payload.list_name.length = list_name_buf_array_size;

  return msg;
}

static inline vapi_error_e vapi_pot_profile_del(struct vapi_ctx_s *ctx,
  vapi_msg_pot_profile_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_pot_profile_del_reply *reply),
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
  vapi_msg_pot_profile_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_pot_profile_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_pot_profile_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_pot_profile_del()
{
  static const char name[] = "pot_profile_del";
  static const char name_with_crc[] = "pot_profile_del_cd63f53b";
  static vapi_message_desc_t __vapi_metadata_pot_profile_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_pot_profile_del, payload),
    (verify_msg_size_fn_t)vapi_verify_pot_profile_del_msg_size,
    (generic_swap_fn_t)vapi_msg_pot_profile_del_hton,
    (generic_swap_fn_t)vapi_msg_pot_profile_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pot_profile_del = vapi_register_msg(&__vapi_metadata_pot_profile_del);
  VAPI_DBG("Assigned msg id %d to pot_profile_del", vapi_msg_id_pot_profile_del);
}
#endif

#ifndef defined_vapi_msg_pot_profile_show_config_details
#define defined_vapi_msg_pot_profile_show_config_details
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u8 id;
  u8 validator;
  u64 secret_key;
  u64 secret_share;
  u64 prime;
  u64 bit_mask;
  u64 lpc;
  u64 polynomial_public; 
} vapi_payload_pot_profile_show_config_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_pot_profile_show_config_details payload;
} vapi_msg_pot_profile_show_config_details;

static inline void vapi_msg_pot_profile_show_config_details_payload_hton(vapi_payload_pot_profile_show_config_details *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->secret_key = htobe64(payload->secret_key);
  payload->secret_share = htobe64(payload->secret_share);
  payload->prime = htobe64(payload->prime);
  payload->bit_mask = htobe64(payload->bit_mask);
  payload->lpc = htobe64(payload->lpc);
  payload->polynomial_public = htobe64(payload->polynomial_public);
}

static inline void vapi_msg_pot_profile_show_config_details_payload_ntoh(vapi_payload_pot_profile_show_config_details *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->secret_key = be64toh(payload->secret_key);
  payload->secret_share = be64toh(payload->secret_share);
  payload->prime = be64toh(payload->prime);
  payload->bit_mask = be64toh(payload->bit_mask);
  payload->lpc = be64toh(payload->lpc);
  payload->polynomial_public = be64toh(payload->polynomial_public);
}

static inline void vapi_msg_pot_profile_show_config_details_hton(vapi_msg_pot_profile_show_config_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pot_profile_show_config_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_pot_profile_show_config_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_pot_profile_show_config_details_ntoh(vapi_msg_pot_profile_show_config_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pot_profile_show_config_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_pot_profile_show_config_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pot_profile_show_config_details_msg_size(vapi_msg_pot_profile_show_config_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pot_profile_show_config_details_msg_size(vapi_msg_pot_profile_show_config_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pot_profile_show_config_details) > buf_size)
    {
      VAPI_ERR("Truncated 'pot_profile_show_config_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pot_profile_show_config_details));
      return -1;
    }
  if (vapi_calc_pot_profile_show_config_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pot_profile_show_config_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pot_profile_show_config_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_pot_profile_show_config_details()
{
  static const char name[] = "pot_profile_show_config_details";
  static const char name_with_crc[] = "pot_profile_show_config_details_b7ce0618";
  static vapi_message_desc_t __vapi_metadata_pot_profile_show_config_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_pot_profile_show_config_details, payload),
    (verify_msg_size_fn_t)vapi_verify_pot_profile_show_config_details_msg_size,
    (generic_swap_fn_t)vapi_msg_pot_profile_show_config_details_hton,
    (generic_swap_fn_t)vapi_msg_pot_profile_show_config_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pot_profile_show_config_details = vapi_register_msg(&__vapi_metadata_pot_profile_show_config_details);
  VAPI_DBG("Assigned msg id %d to pot_profile_show_config_details", vapi_msg_id_pot_profile_show_config_details);
}

static inline void vapi_set_vapi_msg_pot_profile_show_config_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_pot_profile_show_config_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_pot_profile_show_config_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_pot_profile_show_config_dump
#define defined_vapi_msg_pot_profile_show_config_dump
typedef struct __attribute__ ((__packed__)) {
  u8 id; 
} vapi_payload_pot_profile_show_config_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_pot_profile_show_config_dump payload;
} vapi_msg_pot_profile_show_config_dump;

static inline void vapi_msg_pot_profile_show_config_dump_payload_hton(vapi_payload_pot_profile_show_config_dump *payload)
{

}

static inline void vapi_msg_pot_profile_show_config_dump_payload_ntoh(vapi_payload_pot_profile_show_config_dump *payload)
{

}

static inline void vapi_msg_pot_profile_show_config_dump_hton(vapi_msg_pot_profile_show_config_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pot_profile_show_config_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_pot_profile_show_config_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_pot_profile_show_config_dump_ntoh(vapi_msg_pot_profile_show_config_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_pot_profile_show_config_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_pot_profile_show_config_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_pot_profile_show_config_dump_msg_size(vapi_msg_pot_profile_show_config_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_pot_profile_show_config_dump_msg_size(vapi_msg_pot_profile_show_config_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_pot_profile_show_config_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'pot_profile_show_config_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_pot_profile_show_config_dump));
      return -1;
    }
  if (vapi_calc_pot_profile_show_config_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'pot_profile_show_config_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_pot_profile_show_config_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_pot_profile_show_config_dump* vapi_alloc_pot_profile_show_config_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_pot_profile_show_config_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_pot_profile_show_config_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_pot_profile_show_config_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_pot_profile_show_config_dump);

  return msg;
}

static inline vapi_error_e vapi_pot_profile_show_config_dump(struct vapi_ctx_s *ctx,
  vapi_msg_pot_profile_show_config_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_pot_profile_show_config_details *reply),
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
  vapi_msg_pot_profile_show_config_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_pot_profile_show_config_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_pot_profile_show_config_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_pot_profile_show_config_dump()
{
  static const char name[] = "pot_profile_show_config_dump";
  static const char name_with_crc[] = "pot_profile_show_config_dump_005b7d59";
  static vapi_message_desc_t __vapi_metadata_pot_profile_show_config_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_pot_profile_show_config_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_pot_profile_show_config_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_pot_profile_show_config_dump_hton,
    (generic_swap_fn_t)vapi_msg_pot_profile_show_config_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_pot_profile_show_config_dump = vapi_register_msg(&__vapi_metadata_pot_profile_show_config_dump);
  VAPI_DBG("Assigned msg id %d to pot_profile_show_config_dump", vapi_msg_id_pot_profile_show_config_dump);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
