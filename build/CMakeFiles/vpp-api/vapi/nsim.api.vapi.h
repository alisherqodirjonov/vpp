#ifndef __included_nsim_api_json
#define __included_nsim_api_json

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

extern vapi_msg_id_t vapi_msg_id_nsim_cross_connect_enable_disable;
extern vapi_msg_id_t vapi_msg_id_nsim_cross_connect_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_nsim_output_feature_enable_disable;
extern vapi_msg_id_t vapi_msg_id_nsim_output_feature_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_nsim_configure;
extern vapi_msg_id_t vapi_msg_id_nsim_configure_reply;
extern vapi_msg_id_t vapi_msg_id_nsim_configure2;
extern vapi_msg_id_t vapi_msg_id_nsim_configure2_reply;

#define DEFINE_VAPI_MSG_IDS_NSIM_API_JSON\
  vapi_msg_id_t vapi_msg_id_nsim_cross_connect_enable_disable;\
  vapi_msg_id_t vapi_msg_id_nsim_cross_connect_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_nsim_output_feature_enable_disable;\
  vapi_msg_id_t vapi_msg_id_nsim_output_feature_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_nsim_configure;\
  vapi_msg_id_t vapi_msg_id_nsim_configure_reply;\
  vapi_msg_id_t vapi_msg_id_nsim_configure2;\
  vapi_msg_id_t vapi_msg_id_nsim_configure2_reply;


#ifndef defined_vapi_enum_if_status_flags
#define defined_vapi_enum_if_status_flags
typedef enum {
  IF_STATUS_API_FLAG_ADMIN_UP = 1,
  IF_STATUS_API_FLAG_LINK_UP = 2,
}  vapi_enum_if_status_flags;

#endif

#ifndef defined_vapi_enum_mtu_proto
#define defined_vapi_enum_mtu_proto
typedef enum {
  MTU_PROTO_API_L3 = 0,
  MTU_PROTO_API_IP4 = 1,
  MTU_PROTO_API_IP6 = 2,
  MTU_PROTO_API_MPLS = 3,
}  vapi_enum_mtu_proto;

#endif

#ifndef defined_vapi_enum_link_duplex
#define defined_vapi_enum_link_duplex
typedef enum {
  LINK_DUPLEX_API_UNKNOWN = 0,
  LINK_DUPLEX_API_HALF = 1,
  LINK_DUPLEX_API_FULL = 2,
}  vapi_enum_link_duplex;

#endif

#ifndef defined_vapi_enum_sub_if_flags
#define defined_vapi_enum_sub_if_flags
typedef enum {
  SUB_IF_API_FLAG_NO_TAGS = 1,
  SUB_IF_API_FLAG_ONE_TAG = 2,
  SUB_IF_API_FLAG_TWO_TAGS = 4,
  SUB_IF_API_FLAG_DOT1AD = 8,
  SUB_IF_API_FLAG_EXACT_MATCH = 16,
  SUB_IF_API_FLAG_DEFAULT = 32,
  SUB_IF_API_FLAG_OUTER_VLAN_ID_ANY = 64,
  SUB_IF_API_FLAG_INNER_VLAN_ID_ANY = 128,
  SUB_IF_API_FLAG_MASK_VNET = 254,
  SUB_IF_API_FLAG_DOT1AH = 256,
}  vapi_enum_sub_if_flags;

#endif

#ifndef defined_vapi_enum_rx_mode
#define defined_vapi_enum_rx_mode
typedef enum {
  RX_MODE_API_UNKNOWN = 0,
  RX_MODE_API_POLLING = 1,
  RX_MODE_API_INTERRUPT = 2,
  RX_MODE_API_ADAPTIVE = 3,
  RX_MODE_API_DEFAULT = 4,
}  vapi_enum_rx_mode;

#endif

#ifndef defined_vapi_enum_if_type
#define defined_vapi_enum_if_type
typedef enum {
  IF_API_TYPE_HARDWARE = 0,
  IF_API_TYPE_SUB = 1,
  IF_API_TYPE_P2P = 2,
  IF_API_TYPE_PIPE = 3,
}  vapi_enum_if_type;

#endif

#ifndef defined_vapi_enum_direction
#define defined_vapi_enum_direction
typedef enum {
  RX = 0,
  TX = 1,
} __attribute__((packed)) vapi_enum_direction;

#endif

#ifndef defined_vapi_type_interface_index
#define defined_vapi_type_interface_index
typedef u32 vapi_type_interface_index;

#endif

#ifndef defined_vapi_msg_nsim_cross_connect_enable_disable_reply
#define defined_vapi_msg_nsim_cross_connect_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nsim_cross_connect_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nsim_cross_connect_enable_disable_reply payload;
} vapi_msg_nsim_cross_connect_enable_disable_reply;

static inline void vapi_msg_nsim_cross_connect_enable_disable_reply_payload_hton(vapi_payload_nsim_cross_connect_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nsim_cross_connect_enable_disable_reply_payload_ntoh(vapi_payload_nsim_cross_connect_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nsim_cross_connect_enable_disable_reply_hton(vapi_msg_nsim_cross_connect_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsim_cross_connect_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nsim_cross_connect_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nsim_cross_connect_enable_disable_reply_ntoh(vapi_msg_nsim_cross_connect_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsim_cross_connect_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nsim_cross_connect_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nsim_cross_connect_enable_disable_reply_msg_size(vapi_msg_nsim_cross_connect_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nsim_cross_connect_enable_disable_reply_msg_size(vapi_msg_nsim_cross_connect_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nsim_cross_connect_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nsim_cross_connect_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nsim_cross_connect_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_nsim_cross_connect_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nsim_cross_connect_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nsim_cross_connect_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nsim_cross_connect_enable_disable_reply()
{
  static const char name[] = "nsim_cross_connect_enable_disable_reply";
  static const char name_with_crc[] = "nsim_cross_connect_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nsim_cross_connect_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nsim_cross_connect_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nsim_cross_connect_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nsim_cross_connect_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_nsim_cross_connect_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nsim_cross_connect_enable_disable_reply = vapi_register_msg(&__vapi_metadata_nsim_cross_connect_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to nsim_cross_connect_enable_disable_reply", vapi_msg_id_nsim_cross_connect_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_nsim_cross_connect_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nsim_cross_connect_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nsim_cross_connect_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nsim_cross_connect_enable_disable
#define defined_vapi_msg_nsim_cross_connect_enable_disable
typedef struct __attribute__ ((__packed__)) {
  bool enable_disable;
  vapi_type_interface_index sw_if_index0;
  vapi_type_interface_index sw_if_index1; 
} vapi_payload_nsim_cross_connect_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nsim_cross_connect_enable_disable payload;
} vapi_msg_nsim_cross_connect_enable_disable;

static inline void vapi_msg_nsim_cross_connect_enable_disable_payload_hton(vapi_payload_nsim_cross_connect_enable_disable *payload)
{
  payload->sw_if_index0 = htobe32(payload->sw_if_index0);
  payload->sw_if_index1 = htobe32(payload->sw_if_index1);
}

static inline void vapi_msg_nsim_cross_connect_enable_disable_payload_ntoh(vapi_payload_nsim_cross_connect_enable_disable *payload)
{
  payload->sw_if_index0 = be32toh(payload->sw_if_index0);
  payload->sw_if_index1 = be32toh(payload->sw_if_index1);
}

static inline void vapi_msg_nsim_cross_connect_enable_disable_hton(vapi_msg_nsim_cross_connect_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsim_cross_connect_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nsim_cross_connect_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_nsim_cross_connect_enable_disable_ntoh(vapi_msg_nsim_cross_connect_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsim_cross_connect_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nsim_cross_connect_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nsim_cross_connect_enable_disable_msg_size(vapi_msg_nsim_cross_connect_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nsim_cross_connect_enable_disable_msg_size(vapi_msg_nsim_cross_connect_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nsim_cross_connect_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'nsim_cross_connect_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nsim_cross_connect_enable_disable));
      return -1;
    }
  if (vapi_calc_nsim_cross_connect_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nsim_cross_connect_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nsim_cross_connect_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nsim_cross_connect_enable_disable* vapi_alloc_nsim_cross_connect_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_nsim_cross_connect_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_nsim_cross_connect_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nsim_cross_connect_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nsim_cross_connect_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_nsim_cross_connect_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_nsim_cross_connect_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nsim_cross_connect_enable_disable_reply *reply),
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
  vapi_msg_nsim_cross_connect_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nsim_cross_connect_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_nsim_cross_connect_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nsim_cross_connect_enable_disable()
{
  static const char name[] = "nsim_cross_connect_enable_disable";
  static const char name_with_crc[] = "nsim_cross_connect_enable_disable_9c3ead86";
  static vapi_message_desc_t __vapi_metadata_nsim_cross_connect_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nsim_cross_connect_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_nsim_cross_connect_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_nsim_cross_connect_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_nsim_cross_connect_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nsim_cross_connect_enable_disable = vapi_register_msg(&__vapi_metadata_nsim_cross_connect_enable_disable);
  VAPI_DBG("Assigned msg id %d to nsim_cross_connect_enable_disable", vapi_msg_id_nsim_cross_connect_enable_disable);
}
#endif

#ifndef defined_vapi_msg_nsim_output_feature_enable_disable_reply
#define defined_vapi_msg_nsim_output_feature_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nsim_output_feature_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nsim_output_feature_enable_disable_reply payload;
} vapi_msg_nsim_output_feature_enable_disable_reply;

static inline void vapi_msg_nsim_output_feature_enable_disable_reply_payload_hton(vapi_payload_nsim_output_feature_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nsim_output_feature_enable_disable_reply_payload_ntoh(vapi_payload_nsim_output_feature_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nsim_output_feature_enable_disable_reply_hton(vapi_msg_nsim_output_feature_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsim_output_feature_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nsim_output_feature_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nsim_output_feature_enable_disable_reply_ntoh(vapi_msg_nsim_output_feature_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsim_output_feature_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nsim_output_feature_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nsim_output_feature_enable_disable_reply_msg_size(vapi_msg_nsim_output_feature_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nsim_output_feature_enable_disable_reply_msg_size(vapi_msg_nsim_output_feature_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nsim_output_feature_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nsim_output_feature_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nsim_output_feature_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_nsim_output_feature_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nsim_output_feature_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nsim_output_feature_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nsim_output_feature_enable_disable_reply()
{
  static const char name[] = "nsim_output_feature_enable_disable_reply";
  static const char name_with_crc[] = "nsim_output_feature_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nsim_output_feature_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nsim_output_feature_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nsim_output_feature_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nsim_output_feature_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_nsim_output_feature_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nsim_output_feature_enable_disable_reply = vapi_register_msg(&__vapi_metadata_nsim_output_feature_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to nsim_output_feature_enable_disable_reply", vapi_msg_id_nsim_output_feature_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_nsim_output_feature_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nsim_output_feature_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nsim_output_feature_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nsim_output_feature_enable_disable
#define defined_vapi_msg_nsim_output_feature_enable_disable
typedef struct __attribute__ ((__packed__)) {
  bool enable_disable;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_nsim_output_feature_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nsim_output_feature_enable_disable payload;
} vapi_msg_nsim_output_feature_enable_disable;

static inline void vapi_msg_nsim_output_feature_enable_disable_payload_hton(vapi_payload_nsim_output_feature_enable_disable *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_nsim_output_feature_enable_disable_payload_ntoh(vapi_payload_nsim_output_feature_enable_disable *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_nsim_output_feature_enable_disable_hton(vapi_msg_nsim_output_feature_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsim_output_feature_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nsim_output_feature_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_nsim_output_feature_enable_disable_ntoh(vapi_msg_nsim_output_feature_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsim_output_feature_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nsim_output_feature_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nsim_output_feature_enable_disable_msg_size(vapi_msg_nsim_output_feature_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nsim_output_feature_enable_disable_msg_size(vapi_msg_nsim_output_feature_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nsim_output_feature_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'nsim_output_feature_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nsim_output_feature_enable_disable));
      return -1;
    }
  if (vapi_calc_nsim_output_feature_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nsim_output_feature_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nsim_output_feature_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nsim_output_feature_enable_disable* vapi_alloc_nsim_output_feature_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_nsim_output_feature_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_nsim_output_feature_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nsim_output_feature_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nsim_output_feature_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_nsim_output_feature_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_nsim_output_feature_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nsim_output_feature_enable_disable_reply *reply),
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
  vapi_msg_nsim_output_feature_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nsim_output_feature_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_nsim_output_feature_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nsim_output_feature_enable_disable()
{
  static const char name[] = "nsim_output_feature_enable_disable";
  static const char name_with_crc[] = "nsim_output_feature_enable_disable_3865946c";
  static vapi_message_desc_t __vapi_metadata_nsim_output_feature_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nsim_output_feature_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_nsim_output_feature_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_nsim_output_feature_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_nsim_output_feature_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nsim_output_feature_enable_disable = vapi_register_msg(&__vapi_metadata_nsim_output_feature_enable_disable);
  VAPI_DBG("Assigned msg id %d to nsim_output_feature_enable_disable", vapi_msg_id_nsim_output_feature_enable_disable);
}
#endif

#ifndef defined_vapi_msg_nsim_configure_reply
#define defined_vapi_msg_nsim_configure_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nsim_configure_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nsim_configure_reply payload;
} vapi_msg_nsim_configure_reply;

static inline void vapi_msg_nsim_configure_reply_payload_hton(vapi_payload_nsim_configure_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nsim_configure_reply_payload_ntoh(vapi_payload_nsim_configure_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nsim_configure_reply_hton(vapi_msg_nsim_configure_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsim_configure_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nsim_configure_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nsim_configure_reply_ntoh(vapi_msg_nsim_configure_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsim_configure_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nsim_configure_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nsim_configure_reply_msg_size(vapi_msg_nsim_configure_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nsim_configure_reply_msg_size(vapi_msg_nsim_configure_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nsim_configure_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nsim_configure_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nsim_configure_reply));
      return -1;
    }
  if (vapi_calc_nsim_configure_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nsim_configure_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nsim_configure_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nsim_configure_reply()
{
  static const char name[] = "nsim_configure_reply";
  static const char name_with_crc[] = "nsim_configure_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nsim_configure_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nsim_configure_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nsim_configure_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nsim_configure_reply_hton,
    (generic_swap_fn_t)vapi_msg_nsim_configure_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nsim_configure_reply = vapi_register_msg(&__vapi_metadata_nsim_configure_reply);
  VAPI_DBG("Assigned msg id %d to nsim_configure_reply", vapi_msg_id_nsim_configure_reply);
}

static inline void vapi_set_vapi_msg_nsim_configure_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nsim_configure_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nsim_configure_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nsim_configure
#define defined_vapi_msg_nsim_configure
typedef struct __attribute__ ((__packed__)) {
  u32 delay_in_usec;
  u32 average_packet_size;
  u64 bandwidth_in_bits_per_second;
  u32 packets_per_drop; 
} vapi_payload_nsim_configure;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nsim_configure payload;
} vapi_msg_nsim_configure;

static inline void vapi_msg_nsim_configure_payload_hton(vapi_payload_nsim_configure *payload)
{
  payload->delay_in_usec = htobe32(payload->delay_in_usec);
  payload->average_packet_size = htobe32(payload->average_packet_size);
  payload->bandwidth_in_bits_per_second = htobe64(payload->bandwidth_in_bits_per_second);
  payload->packets_per_drop = htobe32(payload->packets_per_drop);
}

static inline void vapi_msg_nsim_configure_payload_ntoh(vapi_payload_nsim_configure *payload)
{
  payload->delay_in_usec = be32toh(payload->delay_in_usec);
  payload->average_packet_size = be32toh(payload->average_packet_size);
  payload->bandwidth_in_bits_per_second = be64toh(payload->bandwidth_in_bits_per_second);
  payload->packets_per_drop = be32toh(payload->packets_per_drop);
}

static inline void vapi_msg_nsim_configure_hton(vapi_msg_nsim_configure *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsim_configure'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nsim_configure_payload_hton(&msg->payload);
}

static inline void vapi_msg_nsim_configure_ntoh(vapi_msg_nsim_configure *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsim_configure'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nsim_configure_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nsim_configure_msg_size(vapi_msg_nsim_configure *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nsim_configure_msg_size(vapi_msg_nsim_configure *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nsim_configure) > buf_size)
    {
      VAPI_ERR("Truncated 'nsim_configure' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nsim_configure));
      return -1;
    }
  if (vapi_calc_nsim_configure_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nsim_configure' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nsim_configure_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nsim_configure* vapi_alloc_nsim_configure(struct vapi_ctx_s *ctx)
{
  vapi_msg_nsim_configure *msg = NULL;
  const size_t size = sizeof(vapi_msg_nsim_configure);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nsim_configure*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nsim_configure);

  return msg;
}

static inline vapi_error_e vapi_nsim_configure(struct vapi_ctx_s *ctx,
  vapi_msg_nsim_configure *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nsim_configure_reply *reply),
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
  vapi_msg_nsim_configure_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nsim_configure_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_nsim_configure_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nsim_configure()
{
  static const char name[] = "nsim_configure";
  static const char name_with_crc[] = "nsim_configure_16ed400f";
  static vapi_message_desc_t __vapi_metadata_nsim_configure = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nsim_configure, payload),
    (verify_msg_size_fn_t)vapi_verify_nsim_configure_msg_size,
    (generic_swap_fn_t)vapi_msg_nsim_configure_hton,
    (generic_swap_fn_t)vapi_msg_nsim_configure_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nsim_configure = vapi_register_msg(&__vapi_metadata_nsim_configure);
  VAPI_DBG("Assigned msg id %d to nsim_configure", vapi_msg_id_nsim_configure);
}
#endif

#ifndef defined_vapi_msg_nsim_configure2_reply
#define defined_vapi_msg_nsim_configure2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_nsim_configure2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nsim_configure2_reply payload;
} vapi_msg_nsim_configure2_reply;

static inline void vapi_msg_nsim_configure2_reply_payload_hton(vapi_payload_nsim_configure2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_nsim_configure2_reply_payload_ntoh(vapi_payload_nsim_configure2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_nsim_configure2_reply_hton(vapi_msg_nsim_configure2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsim_configure2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nsim_configure2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nsim_configure2_reply_ntoh(vapi_msg_nsim_configure2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsim_configure2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nsim_configure2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nsim_configure2_reply_msg_size(vapi_msg_nsim_configure2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nsim_configure2_reply_msg_size(vapi_msg_nsim_configure2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nsim_configure2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nsim_configure2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nsim_configure2_reply));
      return -1;
    }
  if (vapi_calc_nsim_configure2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nsim_configure2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nsim_configure2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nsim_configure2_reply()
{
  static const char name[] = "nsim_configure2_reply";
  static const char name_with_crc[] = "nsim_configure2_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_nsim_configure2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nsim_configure2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nsim_configure2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nsim_configure2_reply_hton,
    (generic_swap_fn_t)vapi_msg_nsim_configure2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nsim_configure2_reply = vapi_register_msg(&__vapi_metadata_nsim_configure2_reply);
  VAPI_DBG("Assigned msg id %d to nsim_configure2_reply", vapi_msg_id_nsim_configure2_reply);
}

static inline void vapi_set_vapi_msg_nsim_configure2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nsim_configure2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nsim_configure2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nsim_configure2
#define defined_vapi_msg_nsim_configure2
typedef struct __attribute__ ((__packed__)) {
  u32 delay_in_usec;
  u32 average_packet_size;
  u64 bandwidth_in_bits_per_second;
  u32 packets_per_drop;
  u32 packets_per_reorder; 
} vapi_payload_nsim_configure2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nsim_configure2 payload;
} vapi_msg_nsim_configure2;

static inline void vapi_msg_nsim_configure2_payload_hton(vapi_payload_nsim_configure2 *payload)
{
  payload->delay_in_usec = htobe32(payload->delay_in_usec);
  payload->average_packet_size = htobe32(payload->average_packet_size);
  payload->bandwidth_in_bits_per_second = htobe64(payload->bandwidth_in_bits_per_second);
  payload->packets_per_drop = htobe32(payload->packets_per_drop);
  payload->packets_per_reorder = htobe32(payload->packets_per_reorder);
}

static inline void vapi_msg_nsim_configure2_payload_ntoh(vapi_payload_nsim_configure2 *payload)
{
  payload->delay_in_usec = be32toh(payload->delay_in_usec);
  payload->average_packet_size = be32toh(payload->average_packet_size);
  payload->bandwidth_in_bits_per_second = be64toh(payload->bandwidth_in_bits_per_second);
  payload->packets_per_drop = be32toh(payload->packets_per_drop);
  payload->packets_per_reorder = be32toh(payload->packets_per_reorder);
}

static inline void vapi_msg_nsim_configure2_hton(vapi_msg_nsim_configure2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsim_configure2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nsim_configure2_payload_hton(&msg->payload);
}

static inline void vapi_msg_nsim_configure2_ntoh(vapi_msg_nsim_configure2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsim_configure2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nsim_configure2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nsim_configure2_msg_size(vapi_msg_nsim_configure2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nsim_configure2_msg_size(vapi_msg_nsim_configure2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nsim_configure2) > buf_size)
    {
      VAPI_ERR("Truncated 'nsim_configure2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nsim_configure2));
      return -1;
    }
  if (vapi_calc_nsim_configure2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nsim_configure2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nsim_configure2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nsim_configure2* vapi_alloc_nsim_configure2(struct vapi_ctx_s *ctx)
{
  vapi_msg_nsim_configure2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_nsim_configure2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nsim_configure2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nsim_configure2);

  return msg;
}

static inline vapi_error_e vapi_nsim_configure2(struct vapi_ctx_s *ctx,
  vapi_msg_nsim_configure2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nsim_configure2_reply *reply),
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
  vapi_msg_nsim_configure2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nsim_configure2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_nsim_configure2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nsim_configure2()
{
  static const char name[] = "nsim_configure2";
  static const char name_with_crc[] = "nsim_configure2_64de8ed3";
  static vapi_message_desc_t __vapi_metadata_nsim_configure2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nsim_configure2, payload),
    (verify_msg_size_fn_t)vapi_verify_nsim_configure2_msg_size,
    (generic_swap_fn_t)vapi_msg_nsim_configure2_hton,
    (generic_swap_fn_t)vapi_msg_nsim_configure2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nsim_configure2 = vapi_register_msg(&__vapi_metadata_nsim_configure2);
  VAPI_DBG("Assigned msg id %d to nsim_configure2", vapi_msg_id_nsim_configure2);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
