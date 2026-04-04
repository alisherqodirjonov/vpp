#ifndef __included_dns_api_json
#define __included_dns_api_json

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

extern vapi_msg_id_t vapi_msg_id_dns_enable_disable;
extern vapi_msg_id_t vapi_msg_id_dns_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_dns_name_server_add_del;
extern vapi_msg_id_t vapi_msg_id_dns_name_server_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_dns_resolve_name;
extern vapi_msg_id_t vapi_msg_id_dns_resolve_name_reply;
extern vapi_msg_id_t vapi_msg_id_dns_resolve_ip;
extern vapi_msg_id_t vapi_msg_id_dns_resolve_ip_reply;

#define DEFINE_VAPI_MSG_IDS_DNS_API_JSON\
  vapi_msg_id_t vapi_msg_id_dns_enable_disable;\
  vapi_msg_id_t vapi_msg_id_dns_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_dns_name_server_add_del;\
  vapi_msg_id_t vapi_msg_id_dns_name_server_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_dns_resolve_name;\
  vapi_msg_id_t vapi_msg_id_dns_resolve_name_reply;\
  vapi_msg_id_t vapi_msg_id_dns_resolve_ip;\
  vapi_msg_id_t vapi_msg_id_dns_resolve_ip_reply;


#ifndef defined_vapi_msg_dns_enable_disable_reply
#define defined_vapi_msg_dns_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_dns_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_dns_enable_disable_reply payload;
} vapi_msg_dns_enable_disable_reply;

static inline void vapi_msg_dns_enable_disable_reply_payload_hton(vapi_payload_dns_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_dns_enable_disable_reply_payload_ntoh(vapi_payload_dns_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_dns_enable_disable_reply_hton(vapi_msg_dns_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dns_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_dns_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_dns_enable_disable_reply_ntoh(vapi_msg_dns_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dns_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_dns_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dns_enable_disable_reply_msg_size(vapi_msg_dns_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dns_enable_disable_reply_msg_size(vapi_msg_dns_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dns_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'dns_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dns_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_dns_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dns_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dns_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dns_enable_disable_reply()
{
  static const char name[] = "dns_enable_disable_reply";
  static const char name_with_crc[] = "dns_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_dns_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_dns_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_dns_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_dns_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_dns_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dns_enable_disable_reply = vapi_register_msg(&__vapi_metadata_dns_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to dns_enable_disable_reply", vapi_msg_id_dns_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_dns_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dns_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dns_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dns_enable_disable
#define defined_vapi_msg_dns_enable_disable
typedef struct __attribute__ ((__packed__)) {
  u8 enable; 
} vapi_payload_dns_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_dns_enable_disable payload;
} vapi_msg_dns_enable_disable;

static inline void vapi_msg_dns_enable_disable_payload_hton(vapi_payload_dns_enable_disable *payload)
{

}

static inline void vapi_msg_dns_enable_disable_payload_ntoh(vapi_payload_dns_enable_disable *payload)
{

}

static inline void vapi_msg_dns_enable_disable_hton(vapi_msg_dns_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dns_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_dns_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_dns_enable_disable_ntoh(vapi_msg_dns_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dns_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_dns_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dns_enable_disable_msg_size(vapi_msg_dns_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dns_enable_disable_msg_size(vapi_msg_dns_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dns_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'dns_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dns_enable_disable));
      return -1;
    }
  if (vapi_calc_dns_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dns_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dns_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_dns_enable_disable* vapi_alloc_dns_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_dns_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_dns_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_dns_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_dns_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_dns_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_dns_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_dns_enable_disable_reply *reply),
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
  vapi_msg_dns_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_dns_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_dns_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_dns_enable_disable()
{
  static const char name[] = "dns_enable_disable";
  static const char name_with_crc[] = "dns_enable_disable_8050327d";
  static vapi_message_desc_t __vapi_metadata_dns_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_dns_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_dns_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_dns_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_dns_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dns_enable_disable = vapi_register_msg(&__vapi_metadata_dns_enable_disable);
  VAPI_DBG("Assigned msg id %d to dns_enable_disable", vapi_msg_id_dns_enable_disable);
}
#endif

#ifndef defined_vapi_msg_dns_name_server_add_del_reply
#define defined_vapi_msg_dns_name_server_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_dns_name_server_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_dns_name_server_add_del_reply payload;
} vapi_msg_dns_name_server_add_del_reply;

static inline void vapi_msg_dns_name_server_add_del_reply_payload_hton(vapi_payload_dns_name_server_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_dns_name_server_add_del_reply_payload_ntoh(vapi_payload_dns_name_server_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_dns_name_server_add_del_reply_hton(vapi_msg_dns_name_server_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dns_name_server_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_dns_name_server_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_dns_name_server_add_del_reply_ntoh(vapi_msg_dns_name_server_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dns_name_server_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_dns_name_server_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dns_name_server_add_del_reply_msg_size(vapi_msg_dns_name_server_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dns_name_server_add_del_reply_msg_size(vapi_msg_dns_name_server_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dns_name_server_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'dns_name_server_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dns_name_server_add_del_reply));
      return -1;
    }
  if (vapi_calc_dns_name_server_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dns_name_server_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dns_name_server_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dns_name_server_add_del_reply()
{
  static const char name[] = "dns_name_server_add_del_reply";
  static const char name_with_crc[] = "dns_name_server_add_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_dns_name_server_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_dns_name_server_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_dns_name_server_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_dns_name_server_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_dns_name_server_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dns_name_server_add_del_reply = vapi_register_msg(&__vapi_metadata_dns_name_server_add_del_reply);
  VAPI_DBG("Assigned msg id %d to dns_name_server_add_del_reply", vapi_msg_id_dns_name_server_add_del_reply);
}

static inline void vapi_set_vapi_msg_dns_name_server_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dns_name_server_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dns_name_server_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dns_name_server_add_del
#define defined_vapi_msg_dns_name_server_add_del
typedef struct __attribute__ ((__packed__)) {
  u8 is_ip6;
  u8 is_add;
  u8 server_address[16]; 
} vapi_payload_dns_name_server_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_dns_name_server_add_del payload;
} vapi_msg_dns_name_server_add_del;

static inline void vapi_msg_dns_name_server_add_del_payload_hton(vapi_payload_dns_name_server_add_del *payload)
{

}

static inline void vapi_msg_dns_name_server_add_del_payload_ntoh(vapi_payload_dns_name_server_add_del *payload)
{

}

static inline void vapi_msg_dns_name_server_add_del_hton(vapi_msg_dns_name_server_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dns_name_server_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_dns_name_server_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_dns_name_server_add_del_ntoh(vapi_msg_dns_name_server_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dns_name_server_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_dns_name_server_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dns_name_server_add_del_msg_size(vapi_msg_dns_name_server_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dns_name_server_add_del_msg_size(vapi_msg_dns_name_server_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dns_name_server_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'dns_name_server_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dns_name_server_add_del));
      return -1;
    }
  if (vapi_calc_dns_name_server_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dns_name_server_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dns_name_server_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_dns_name_server_add_del* vapi_alloc_dns_name_server_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_dns_name_server_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_dns_name_server_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_dns_name_server_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_dns_name_server_add_del);

  return msg;
}

static inline vapi_error_e vapi_dns_name_server_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_dns_name_server_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_dns_name_server_add_del_reply *reply),
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
  vapi_msg_dns_name_server_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_dns_name_server_add_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_dns_name_server_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_dns_name_server_add_del()
{
  static const char name[] = "dns_name_server_add_del";
  static const char name_with_crc[] = "dns_name_server_add_del_3bb05d8c";
  static vapi_message_desc_t __vapi_metadata_dns_name_server_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_dns_name_server_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_dns_name_server_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_dns_name_server_add_del_hton,
    (generic_swap_fn_t)vapi_msg_dns_name_server_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dns_name_server_add_del = vapi_register_msg(&__vapi_metadata_dns_name_server_add_del);
  VAPI_DBG("Assigned msg id %d to dns_name_server_add_del", vapi_msg_id_dns_name_server_add_del);
}
#endif

#ifndef defined_vapi_msg_dns_resolve_name_reply
#define defined_vapi_msg_dns_resolve_name_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u8 ip4_set;
  u8 ip6_set;
  u8 ip4_address[4];
  u8 ip6_address[16]; 
} vapi_payload_dns_resolve_name_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_dns_resolve_name_reply payload;
} vapi_msg_dns_resolve_name_reply;

static inline void vapi_msg_dns_resolve_name_reply_payload_hton(vapi_payload_dns_resolve_name_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_dns_resolve_name_reply_payload_ntoh(vapi_payload_dns_resolve_name_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_dns_resolve_name_reply_hton(vapi_msg_dns_resolve_name_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dns_resolve_name_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_dns_resolve_name_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_dns_resolve_name_reply_ntoh(vapi_msg_dns_resolve_name_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dns_resolve_name_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_dns_resolve_name_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dns_resolve_name_reply_msg_size(vapi_msg_dns_resolve_name_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dns_resolve_name_reply_msg_size(vapi_msg_dns_resolve_name_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dns_resolve_name_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'dns_resolve_name_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dns_resolve_name_reply));
      return -1;
    }
  if (vapi_calc_dns_resolve_name_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dns_resolve_name_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dns_resolve_name_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dns_resolve_name_reply()
{
  static const char name[] = "dns_resolve_name_reply";
  static const char name_with_crc[] = "dns_resolve_name_reply_c2d758c3";
  static vapi_message_desc_t __vapi_metadata_dns_resolve_name_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_dns_resolve_name_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_dns_resolve_name_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_dns_resolve_name_reply_hton,
    (generic_swap_fn_t)vapi_msg_dns_resolve_name_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dns_resolve_name_reply = vapi_register_msg(&__vapi_metadata_dns_resolve_name_reply);
  VAPI_DBG("Assigned msg id %d to dns_resolve_name_reply", vapi_msg_id_dns_resolve_name_reply);
}

static inline void vapi_set_vapi_msg_dns_resolve_name_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dns_resolve_name_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dns_resolve_name_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dns_resolve_name
#define defined_vapi_msg_dns_resolve_name
typedef struct __attribute__ ((__packed__)) {
  u8 name[256]; 
} vapi_payload_dns_resolve_name;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_dns_resolve_name payload;
} vapi_msg_dns_resolve_name;

static inline void vapi_msg_dns_resolve_name_payload_hton(vapi_payload_dns_resolve_name *payload)
{

}

static inline void vapi_msg_dns_resolve_name_payload_ntoh(vapi_payload_dns_resolve_name *payload)
{

}

static inline void vapi_msg_dns_resolve_name_hton(vapi_msg_dns_resolve_name *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dns_resolve_name'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_dns_resolve_name_payload_hton(&msg->payload);
}

static inline void vapi_msg_dns_resolve_name_ntoh(vapi_msg_dns_resolve_name *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dns_resolve_name'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_dns_resolve_name_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dns_resolve_name_msg_size(vapi_msg_dns_resolve_name *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dns_resolve_name_msg_size(vapi_msg_dns_resolve_name *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dns_resolve_name) > buf_size)
    {
      VAPI_ERR("Truncated 'dns_resolve_name' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dns_resolve_name));
      return -1;
    }
  if (vapi_calc_dns_resolve_name_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dns_resolve_name' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dns_resolve_name_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_dns_resolve_name* vapi_alloc_dns_resolve_name(struct vapi_ctx_s *ctx)
{
  vapi_msg_dns_resolve_name *msg = NULL;
  const size_t size = sizeof(vapi_msg_dns_resolve_name);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_dns_resolve_name*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_dns_resolve_name);

  return msg;
}

static inline vapi_error_e vapi_dns_resolve_name(struct vapi_ctx_s *ctx,
  vapi_msg_dns_resolve_name *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_dns_resolve_name_reply *reply),
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
  vapi_msg_dns_resolve_name_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_dns_resolve_name_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_dns_resolve_name_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_dns_resolve_name()
{
  static const char name[] = "dns_resolve_name";
  static const char name_with_crc[] = "dns_resolve_name_c6566676";
  static vapi_message_desc_t __vapi_metadata_dns_resolve_name = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_dns_resolve_name, payload),
    (verify_msg_size_fn_t)vapi_verify_dns_resolve_name_msg_size,
    (generic_swap_fn_t)vapi_msg_dns_resolve_name_hton,
    (generic_swap_fn_t)vapi_msg_dns_resolve_name_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dns_resolve_name = vapi_register_msg(&__vapi_metadata_dns_resolve_name);
  VAPI_DBG("Assigned msg id %d to dns_resolve_name", vapi_msg_id_dns_resolve_name);
}
#endif

#ifndef defined_vapi_msg_dns_resolve_ip_reply
#define defined_vapi_msg_dns_resolve_ip_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u8 name[256]; 
} vapi_payload_dns_resolve_ip_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_dns_resolve_ip_reply payload;
} vapi_msg_dns_resolve_ip_reply;

static inline void vapi_msg_dns_resolve_ip_reply_payload_hton(vapi_payload_dns_resolve_ip_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_dns_resolve_ip_reply_payload_ntoh(vapi_payload_dns_resolve_ip_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_dns_resolve_ip_reply_hton(vapi_msg_dns_resolve_ip_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dns_resolve_ip_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_dns_resolve_ip_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_dns_resolve_ip_reply_ntoh(vapi_msg_dns_resolve_ip_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dns_resolve_ip_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_dns_resolve_ip_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dns_resolve_ip_reply_msg_size(vapi_msg_dns_resolve_ip_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dns_resolve_ip_reply_msg_size(vapi_msg_dns_resolve_ip_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dns_resolve_ip_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'dns_resolve_ip_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dns_resolve_ip_reply));
      return -1;
    }
  if (vapi_calc_dns_resolve_ip_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dns_resolve_ip_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dns_resolve_ip_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_dns_resolve_ip_reply()
{
  static const char name[] = "dns_resolve_ip_reply";
  static const char name_with_crc[] = "dns_resolve_ip_reply_49ed78d6";
  static vapi_message_desc_t __vapi_metadata_dns_resolve_ip_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_dns_resolve_ip_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_dns_resolve_ip_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_dns_resolve_ip_reply_hton,
    (generic_swap_fn_t)vapi_msg_dns_resolve_ip_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dns_resolve_ip_reply = vapi_register_msg(&__vapi_metadata_dns_resolve_ip_reply);
  VAPI_DBG("Assigned msg id %d to dns_resolve_ip_reply", vapi_msg_id_dns_resolve_ip_reply);
}

static inline void vapi_set_vapi_msg_dns_resolve_ip_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_dns_resolve_ip_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_dns_resolve_ip_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_dns_resolve_ip
#define defined_vapi_msg_dns_resolve_ip
typedef struct __attribute__ ((__packed__)) {
  u8 is_ip6;
  u8 address[16]; 
} vapi_payload_dns_resolve_ip;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_dns_resolve_ip payload;
} vapi_msg_dns_resolve_ip;

static inline void vapi_msg_dns_resolve_ip_payload_hton(vapi_payload_dns_resolve_ip *payload)
{

}

static inline void vapi_msg_dns_resolve_ip_payload_ntoh(vapi_payload_dns_resolve_ip *payload)
{

}

static inline void vapi_msg_dns_resolve_ip_hton(vapi_msg_dns_resolve_ip *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dns_resolve_ip'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_dns_resolve_ip_payload_hton(&msg->payload);
}

static inline void vapi_msg_dns_resolve_ip_ntoh(vapi_msg_dns_resolve_ip *msg)
{
  VAPI_DBG("Swapping `vapi_msg_dns_resolve_ip'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_dns_resolve_ip_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_dns_resolve_ip_msg_size(vapi_msg_dns_resolve_ip *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_dns_resolve_ip_msg_size(vapi_msg_dns_resolve_ip *msg, uword buf_size)
{
  if (sizeof(vapi_msg_dns_resolve_ip) > buf_size)
    {
      VAPI_ERR("Truncated 'dns_resolve_ip' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_dns_resolve_ip));
      return -1;
    }
  if (vapi_calc_dns_resolve_ip_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'dns_resolve_ip' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_dns_resolve_ip_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_dns_resolve_ip* vapi_alloc_dns_resolve_ip(struct vapi_ctx_s *ctx)
{
  vapi_msg_dns_resolve_ip *msg = NULL;
  const size_t size = sizeof(vapi_msg_dns_resolve_ip);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_dns_resolve_ip*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_dns_resolve_ip);

  return msg;
}

static inline vapi_error_e vapi_dns_resolve_ip(struct vapi_ctx_s *ctx,
  vapi_msg_dns_resolve_ip *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_dns_resolve_ip_reply *reply),
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
  vapi_msg_dns_resolve_ip_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_dns_resolve_ip_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_dns_resolve_ip_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_dns_resolve_ip()
{
  static const char name[] = "dns_resolve_ip";
  static const char name_with_crc[] = "dns_resolve_ip_ae96a1a3";
  static vapi_message_desc_t __vapi_metadata_dns_resolve_ip = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_dns_resolve_ip, payload),
    (verify_msg_size_fn_t)vapi_verify_dns_resolve_ip_msg_size,
    (generic_swap_fn_t)vapi_msg_dns_resolve_ip_hton,
    (generic_swap_fn_t)vapi_msg_dns_resolve_ip_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_dns_resolve_ip = vapi_register_msg(&__vapi_metadata_dns_resolve_ip);
  VAPI_DBG("Assigned msg id %d to dns_resolve_ip", vapi_msg_id_dns_resolve_ip);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
