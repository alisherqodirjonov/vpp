#ifndef __included_sflow_api_json
#define __included_sflow_api_json

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

extern vapi_msg_id_t vapi_msg_id_sflow_enable_disable;
extern vapi_msg_id_t vapi_msg_id_sflow_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_sflow_sampling_rate_get;
extern vapi_msg_id_t vapi_msg_id_sflow_sampling_rate_get_reply;
extern vapi_msg_id_t vapi_msg_id_sflow_sampling_rate_set;
extern vapi_msg_id_t vapi_msg_id_sflow_sampling_rate_set_reply;
extern vapi_msg_id_t vapi_msg_id_sflow_polling_interval_set;
extern vapi_msg_id_t vapi_msg_id_sflow_polling_interval_set_reply;
extern vapi_msg_id_t vapi_msg_id_sflow_polling_interval_get;
extern vapi_msg_id_t vapi_msg_id_sflow_polling_interval_get_reply;
extern vapi_msg_id_t vapi_msg_id_sflow_header_bytes_set;
extern vapi_msg_id_t vapi_msg_id_sflow_header_bytes_set_reply;
extern vapi_msg_id_t vapi_msg_id_sflow_header_bytes_get;
extern vapi_msg_id_t vapi_msg_id_sflow_header_bytes_get_reply;
extern vapi_msg_id_t vapi_msg_id_sflow_direction_set;
extern vapi_msg_id_t vapi_msg_id_sflow_direction_set_reply;
extern vapi_msg_id_t vapi_msg_id_sflow_direction_get;
extern vapi_msg_id_t vapi_msg_id_sflow_direction_get_reply;
extern vapi_msg_id_t vapi_msg_id_sflow_drop_monitoring_set;
extern vapi_msg_id_t vapi_msg_id_sflow_drop_monitoring_set_reply;
extern vapi_msg_id_t vapi_msg_id_sflow_drop_monitoring_get;
extern vapi_msg_id_t vapi_msg_id_sflow_drop_monitoring_get_reply;
extern vapi_msg_id_t vapi_msg_id_sflow_interface_dump;
extern vapi_msg_id_t vapi_msg_id_sflow_interface_details;

#define DEFINE_VAPI_MSG_IDS_SFLOW_API_JSON\
  vapi_msg_id_t vapi_msg_id_sflow_enable_disable;\
  vapi_msg_id_t vapi_msg_id_sflow_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_sflow_sampling_rate_get;\
  vapi_msg_id_t vapi_msg_id_sflow_sampling_rate_get_reply;\
  vapi_msg_id_t vapi_msg_id_sflow_sampling_rate_set;\
  vapi_msg_id_t vapi_msg_id_sflow_sampling_rate_set_reply;\
  vapi_msg_id_t vapi_msg_id_sflow_polling_interval_set;\
  vapi_msg_id_t vapi_msg_id_sflow_polling_interval_set_reply;\
  vapi_msg_id_t vapi_msg_id_sflow_polling_interval_get;\
  vapi_msg_id_t vapi_msg_id_sflow_polling_interval_get_reply;\
  vapi_msg_id_t vapi_msg_id_sflow_header_bytes_set;\
  vapi_msg_id_t vapi_msg_id_sflow_header_bytes_set_reply;\
  vapi_msg_id_t vapi_msg_id_sflow_header_bytes_get;\
  vapi_msg_id_t vapi_msg_id_sflow_header_bytes_get_reply;\
  vapi_msg_id_t vapi_msg_id_sflow_direction_set;\
  vapi_msg_id_t vapi_msg_id_sflow_direction_set_reply;\
  vapi_msg_id_t vapi_msg_id_sflow_direction_get;\
  vapi_msg_id_t vapi_msg_id_sflow_direction_get_reply;\
  vapi_msg_id_t vapi_msg_id_sflow_drop_monitoring_set;\
  vapi_msg_id_t vapi_msg_id_sflow_drop_monitoring_set_reply;\
  vapi_msg_id_t vapi_msg_id_sflow_drop_monitoring_get;\
  vapi_msg_id_t vapi_msg_id_sflow_drop_monitoring_get_reply;\
  vapi_msg_id_t vapi_msg_id_sflow_interface_dump;\
  vapi_msg_id_t vapi_msg_id_sflow_interface_details;


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

#ifndef defined_vapi_msg_sflow_enable_disable_reply
#define defined_vapi_msg_sflow_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_sflow_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sflow_enable_disable_reply payload;
} vapi_msg_sflow_enable_disable_reply;

static inline void vapi_msg_sflow_enable_disable_reply_payload_hton(vapi_payload_sflow_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_sflow_enable_disable_reply_payload_ntoh(vapi_payload_sflow_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_sflow_enable_disable_reply_hton(vapi_msg_sflow_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sflow_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sflow_enable_disable_reply_ntoh(vapi_msg_sflow_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sflow_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sflow_enable_disable_reply_msg_size(vapi_msg_sflow_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_enable_disable_reply_msg_size(vapi_msg_sflow_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_sflow_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sflow_enable_disable_reply()
{
  static const char name[] = "sflow_enable_disable_reply";
  static const char name_with_crc[] = "sflow_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_sflow_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sflow_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sflow_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_sflow_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_enable_disable_reply = vapi_register_msg(&__vapi_metadata_sflow_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to sflow_enable_disable_reply", vapi_msg_id_sflow_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_sflow_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sflow_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sflow_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sflow_enable_disable
#define defined_vapi_msg_sflow_enable_disable
typedef struct __attribute__ ((__packed__)) {
  bool enable_disable;
  vapi_type_interface_index hw_if_index; 
} vapi_payload_sflow_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sflow_enable_disable payload;
} vapi_msg_sflow_enable_disable;

static inline void vapi_msg_sflow_enable_disable_payload_hton(vapi_payload_sflow_enable_disable *payload)
{
  payload->hw_if_index = htobe32(payload->hw_if_index);
}

static inline void vapi_msg_sflow_enable_disable_payload_ntoh(vapi_payload_sflow_enable_disable *payload)
{
  payload->hw_if_index = be32toh(payload->hw_if_index);
}

static inline void vapi_msg_sflow_enable_disable_hton(vapi_msg_sflow_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sflow_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_sflow_enable_disable_ntoh(vapi_msg_sflow_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sflow_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sflow_enable_disable_msg_size(vapi_msg_sflow_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_enable_disable_msg_size(vapi_msg_sflow_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_enable_disable));
      return -1;
    }
  if (vapi_calc_sflow_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sflow_enable_disable* vapi_alloc_sflow_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_sflow_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_sflow_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sflow_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sflow_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_sflow_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_sflow_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sflow_enable_disable_reply *reply),
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
  vapi_msg_sflow_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sflow_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sflow_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sflow_enable_disable()
{
  static const char name[] = "sflow_enable_disable";
  static const char name_with_crc[] = "sflow_enable_disable_8499814f";
  static vapi_message_desc_t __vapi_metadata_sflow_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sflow_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_sflow_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_sflow_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_enable_disable = vapi_register_msg(&__vapi_metadata_sflow_enable_disable);
  VAPI_DBG("Assigned msg id %d to sflow_enable_disable", vapi_msg_id_sflow_enable_disable);
}
#endif

#ifndef defined_vapi_msg_sflow_sampling_rate_get_reply
#define defined_vapi_msg_sflow_sampling_rate_get_reply
typedef struct __attribute__ ((__packed__)) {
  u32 sampling_N; 
} vapi_payload_sflow_sampling_rate_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sflow_sampling_rate_get_reply payload;
} vapi_msg_sflow_sampling_rate_get_reply;

static inline void vapi_msg_sflow_sampling_rate_get_reply_payload_hton(vapi_payload_sflow_sampling_rate_get_reply *payload)
{
  payload->sampling_N = htobe32(payload->sampling_N);
}

static inline void vapi_msg_sflow_sampling_rate_get_reply_payload_ntoh(vapi_payload_sflow_sampling_rate_get_reply *payload)
{
  payload->sampling_N = be32toh(payload->sampling_N);
}

static inline void vapi_msg_sflow_sampling_rate_get_reply_hton(vapi_msg_sflow_sampling_rate_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_sampling_rate_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sflow_sampling_rate_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sflow_sampling_rate_get_reply_ntoh(vapi_msg_sflow_sampling_rate_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_sampling_rate_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sflow_sampling_rate_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sflow_sampling_rate_get_reply_msg_size(vapi_msg_sflow_sampling_rate_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_sampling_rate_get_reply_msg_size(vapi_msg_sflow_sampling_rate_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_sampling_rate_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_sampling_rate_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_sampling_rate_get_reply));
      return -1;
    }
  if (vapi_calc_sflow_sampling_rate_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_sampling_rate_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_sampling_rate_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sflow_sampling_rate_get_reply()
{
  static const char name[] = "sflow_sampling_rate_get_reply";
  static const char name_with_crc[] = "sflow_sampling_rate_get_reply_9c8c8236";
  static vapi_message_desc_t __vapi_metadata_sflow_sampling_rate_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sflow_sampling_rate_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sflow_sampling_rate_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_sampling_rate_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_sflow_sampling_rate_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_sampling_rate_get_reply = vapi_register_msg(&__vapi_metadata_sflow_sampling_rate_get_reply);
  VAPI_DBG("Assigned msg id %d to sflow_sampling_rate_get_reply", vapi_msg_id_sflow_sampling_rate_get_reply);
}

static inline void vapi_set_vapi_msg_sflow_sampling_rate_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sflow_sampling_rate_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sflow_sampling_rate_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sflow_sampling_rate_get
#define defined_vapi_msg_sflow_sampling_rate_get
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_sflow_sampling_rate_get;

static inline void vapi_msg_sflow_sampling_rate_get_hton(vapi_msg_sflow_sampling_rate_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_sampling_rate_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_sflow_sampling_rate_get_ntoh(vapi_msg_sflow_sampling_rate_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_sampling_rate_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_sflow_sampling_rate_get_msg_size(vapi_msg_sflow_sampling_rate_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_sampling_rate_get_msg_size(vapi_msg_sflow_sampling_rate_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_sampling_rate_get) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_sampling_rate_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_sampling_rate_get));
      return -1;
    }
  if (vapi_calc_sflow_sampling_rate_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_sampling_rate_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_sampling_rate_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sflow_sampling_rate_get* vapi_alloc_sflow_sampling_rate_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_sflow_sampling_rate_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_sflow_sampling_rate_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sflow_sampling_rate_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sflow_sampling_rate_get);

  return msg;
}

static inline vapi_error_e vapi_sflow_sampling_rate_get(struct vapi_ctx_s *ctx,
  vapi_msg_sflow_sampling_rate_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sflow_sampling_rate_get_reply *reply),
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
  vapi_msg_sflow_sampling_rate_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sflow_sampling_rate_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sflow_sampling_rate_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sflow_sampling_rate_get()
{
  static const char name[] = "sflow_sampling_rate_get";
  static const char name_with_crc[] = "sflow_sampling_rate_get_51077d14";
  static vapi_message_desc_t __vapi_metadata_sflow_sampling_rate_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_sflow_sampling_rate_get_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_sampling_rate_get_hton,
    (generic_swap_fn_t)vapi_msg_sflow_sampling_rate_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_sampling_rate_get = vapi_register_msg(&__vapi_metadata_sflow_sampling_rate_get);
  VAPI_DBG("Assigned msg id %d to sflow_sampling_rate_get", vapi_msg_id_sflow_sampling_rate_get);
}
#endif

#ifndef defined_vapi_msg_sflow_sampling_rate_set_reply
#define defined_vapi_msg_sflow_sampling_rate_set_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_sflow_sampling_rate_set_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sflow_sampling_rate_set_reply payload;
} vapi_msg_sflow_sampling_rate_set_reply;

static inline void vapi_msg_sflow_sampling_rate_set_reply_payload_hton(vapi_payload_sflow_sampling_rate_set_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_sflow_sampling_rate_set_reply_payload_ntoh(vapi_payload_sflow_sampling_rate_set_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_sflow_sampling_rate_set_reply_hton(vapi_msg_sflow_sampling_rate_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_sampling_rate_set_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sflow_sampling_rate_set_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sflow_sampling_rate_set_reply_ntoh(vapi_msg_sflow_sampling_rate_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_sampling_rate_set_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sflow_sampling_rate_set_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sflow_sampling_rate_set_reply_msg_size(vapi_msg_sflow_sampling_rate_set_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_sampling_rate_set_reply_msg_size(vapi_msg_sflow_sampling_rate_set_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_sampling_rate_set_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_sampling_rate_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_sampling_rate_set_reply));
      return -1;
    }
  if (vapi_calc_sflow_sampling_rate_set_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_sampling_rate_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_sampling_rate_set_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sflow_sampling_rate_set_reply()
{
  static const char name[] = "sflow_sampling_rate_set_reply";
  static const char name_with_crc[] = "sflow_sampling_rate_set_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_sflow_sampling_rate_set_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sflow_sampling_rate_set_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sflow_sampling_rate_set_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_sampling_rate_set_reply_hton,
    (generic_swap_fn_t)vapi_msg_sflow_sampling_rate_set_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_sampling_rate_set_reply = vapi_register_msg(&__vapi_metadata_sflow_sampling_rate_set_reply);
  VAPI_DBG("Assigned msg id %d to sflow_sampling_rate_set_reply", vapi_msg_id_sflow_sampling_rate_set_reply);
}

static inline void vapi_set_vapi_msg_sflow_sampling_rate_set_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sflow_sampling_rate_set_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sflow_sampling_rate_set_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sflow_sampling_rate_set
#define defined_vapi_msg_sflow_sampling_rate_set
typedef struct __attribute__ ((__packed__)) {
  u32 sampling_N; 
} vapi_payload_sflow_sampling_rate_set;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sflow_sampling_rate_set payload;
} vapi_msg_sflow_sampling_rate_set;

static inline void vapi_msg_sflow_sampling_rate_set_payload_hton(vapi_payload_sflow_sampling_rate_set *payload)
{
  payload->sampling_N = htobe32(payload->sampling_N);
}

static inline void vapi_msg_sflow_sampling_rate_set_payload_ntoh(vapi_payload_sflow_sampling_rate_set *payload)
{
  payload->sampling_N = be32toh(payload->sampling_N);
}

static inline void vapi_msg_sflow_sampling_rate_set_hton(vapi_msg_sflow_sampling_rate_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_sampling_rate_set'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sflow_sampling_rate_set_payload_hton(&msg->payload);
}

static inline void vapi_msg_sflow_sampling_rate_set_ntoh(vapi_msg_sflow_sampling_rate_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_sampling_rate_set'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sflow_sampling_rate_set_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sflow_sampling_rate_set_msg_size(vapi_msg_sflow_sampling_rate_set *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_sampling_rate_set_msg_size(vapi_msg_sflow_sampling_rate_set *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_sampling_rate_set) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_sampling_rate_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_sampling_rate_set));
      return -1;
    }
  if (vapi_calc_sflow_sampling_rate_set_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_sampling_rate_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_sampling_rate_set_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sflow_sampling_rate_set* vapi_alloc_sflow_sampling_rate_set(struct vapi_ctx_s *ctx)
{
  vapi_msg_sflow_sampling_rate_set *msg = NULL;
  const size_t size = sizeof(vapi_msg_sflow_sampling_rate_set);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sflow_sampling_rate_set*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sflow_sampling_rate_set);

  return msg;
}

static inline vapi_error_e vapi_sflow_sampling_rate_set(struct vapi_ctx_s *ctx,
  vapi_msg_sflow_sampling_rate_set *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sflow_sampling_rate_set_reply *reply),
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
  vapi_msg_sflow_sampling_rate_set_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sflow_sampling_rate_set_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sflow_sampling_rate_set_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sflow_sampling_rate_set()
{
  static const char name[] = "sflow_sampling_rate_set";
  static const char name_with_crc[] = "sflow_sampling_rate_set_94778f50";
  static vapi_message_desc_t __vapi_metadata_sflow_sampling_rate_set = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sflow_sampling_rate_set, payload),
    (verify_msg_size_fn_t)vapi_verify_sflow_sampling_rate_set_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_sampling_rate_set_hton,
    (generic_swap_fn_t)vapi_msg_sflow_sampling_rate_set_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_sampling_rate_set = vapi_register_msg(&__vapi_metadata_sflow_sampling_rate_set);
  VAPI_DBG("Assigned msg id %d to sflow_sampling_rate_set", vapi_msg_id_sflow_sampling_rate_set);
}
#endif

#ifndef defined_vapi_msg_sflow_polling_interval_set_reply
#define defined_vapi_msg_sflow_polling_interval_set_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_sflow_polling_interval_set_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sflow_polling_interval_set_reply payload;
} vapi_msg_sflow_polling_interval_set_reply;

static inline void vapi_msg_sflow_polling_interval_set_reply_payload_hton(vapi_payload_sflow_polling_interval_set_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_sflow_polling_interval_set_reply_payload_ntoh(vapi_payload_sflow_polling_interval_set_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_sflow_polling_interval_set_reply_hton(vapi_msg_sflow_polling_interval_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_polling_interval_set_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sflow_polling_interval_set_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sflow_polling_interval_set_reply_ntoh(vapi_msg_sflow_polling_interval_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_polling_interval_set_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sflow_polling_interval_set_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sflow_polling_interval_set_reply_msg_size(vapi_msg_sflow_polling_interval_set_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_polling_interval_set_reply_msg_size(vapi_msg_sflow_polling_interval_set_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_polling_interval_set_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_polling_interval_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_polling_interval_set_reply));
      return -1;
    }
  if (vapi_calc_sflow_polling_interval_set_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_polling_interval_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_polling_interval_set_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sflow_polling_interval_set_reply()
{
  static const char name[] = "sflow_polling_interval_set_reply";
  static const char name_with_crc[] = "sflow_polling_interval_set_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_sflow_polling_interval_set_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sflow_polling_interval_set_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sflow_polling_interval_set_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_polling_interval_set_reply_hton,
    (generic_swap_fn_t)vapi_msg_sflow_polling_interval_set_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_polling_interval_set_reply = vapi_register_msg(&__vapi_metadata_sflow_polling_interval_set_reply);
  VAPI_DBG("Assigned msg id %d to sflow_polling_interval_set_reply", vapi_msg_id_sflow_polling_interval_set_reply);
}

static inline void vapi_set_vapi_msg_sflow_polling_interval_set_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sflow_polling_interval_set_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sflow_polling_interval_set_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sflow_polling_interval_set
#define defined_vapi_msg_sflow_polling_interval_set
typedef struct __attribute__ ((__packed__)) {
  u32 polling_S; 
} vapi_payload_sflow_polling_interval_set;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sflow_polling_interval_set payload;
} vapi_msg_sflow_polling_interval_set;

static inline void vapi_msg_sflow_polling_interval_set_payload_hton(vapi_payload_sflow_polling_interval_set *payload)
{
  payload->polling_S = htobe32(payload->polling_S);
}

static inline void vapi_msg_sflow_polling_interval_set_payload_ntoh(vapi_payload_sflow_polling_interval_set *payload)
{
  payload->polling_S = be32toh(payload->polling_S);
}

static inline void vapi_msg_sflow_polling_interval_set_hton(vapi_msg_sflow_polling_interval_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_polling_interval_set'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sflow_polling_interval_set_payload_hton(&msg->payload);
}

static inline void vapi_msg_sflow_polling_interval_set_ntoh(vapi_msg_sflow_polling_interval_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_polling_interval_set'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sflow_polling_interval_set_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sflow_polling_interval_set_msg_size(vapi_msg_sflow_polling_interval_set *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_polling_interval_set_msg_size(vapi_msg_sflow_polling_interval_set *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_polling_interval_set) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_polling_interval_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_polling_interval_set));
      return -1;
    }
  if (vapi_calc_sflow_polling_interval_set_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_polling_interval_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_polling_interval_set_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sflow_polling_interval_set* vapi_alloc_sflow_polling_interval_set(struct vapi_ctx_s *ctx)
{
  vapi_msg_sflow_polling_interval_set *msg = NULL;
  const size_t size = sizeof(vapi_msg_sflow_polling_interval_set);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sflow_polling_interval_set*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sflow_polling_interval_set);

  return msg;
}

static inline vapi_error_e vapi_sflow_polling_interval_set(struct vapi_ctx_s *ctx,
  vapi_msg_sflow_polling_interval_set *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sflow_polling_interval_set_reply *reply),
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
  vapi_msg_sflow_polling_interval_set_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sflow_polling_interval_set_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sflow_polling_interval_set_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sflow_polling_interval_set()
{
  static const char name[] = "sflow_polling_interval_set";
  static const char name_with_crc[] = "sflow_polling_interval_set_7f19cb51";
  static vapi_message_desc_t __vapi_metadata_sflow_polling_interval_set = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sflow_polling_interval_set, payload),
    (verify_msg_size_fn_t)vapi_verify_sflow_polling_interval_set_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_polling_interval_set_hton,
    (generic_swap_fn_t)vapi_msg_sflow_polling_interval_set_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_polling_interval_set = vapi_register_msg(&__vapi_metadata_sflow_polling_interval_set);
  VAPI_DBG("Assigned msg id %d to sflow_polling_interval_set", vapi_msg_id_sflow_polling_interval_set);
}
#endif

#ifndef defined_vapi_msg_sflow_polling_interval_get_reply
#define defined_vapi_msg_sflow_polling_interval_get_reply
typedef struct __attribute__ ((__packed__)) {
  u32 polling_S; 
} vapi_payload_sflow_polling_interval_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sflow_polling_interval_get_reply payload;
} vapi_msg_sflow_polling_interval_get_reply;

static inline void vapi_msg_sflow_polling_interval_get_reply_payload_hton(vapi_payload_sflow_polling_interval_get_reply *payload)
{
  payload->polling_S = htobe32(payload->polling_S);
}

static inline void vapi_msg_sflow_polling_interval_get_reply_payload_ntoh(vapi_payload_sflow_polling_interval_get_reply *payload)
{
  payload->polling_S = be32toh(payload->polling_S);
}

static inline void vapi_msg_sflow_polling_interval_get_reply_hton(vapi_msg_sflow_polling_interval_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_polling_interval_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sflow_polling_interval_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sflow_polling_interval_get_reply_ntoh(vapi_msg_sflow_polling_interval_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_polling_interval_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sflow_polling_interval_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sflow_polling_interval_get_reply_msg_size(vapi_msg_sflow_polling_interval_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_polling_interval_get_reply_msg_size(vapi_msg_sflow_polling_interval_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_polling_interval_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_polling_interval_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_polling_interval_get_reply));
      return -1;
    }
  if (vapi_calc_sflow_polling_interval_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_polling_interval_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_polling_interval_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sflow_polling_interval_get_reply()
{
  static const char name[] = "sflow_polling_interval_get_reply";
  static const char name_with_crc[] = "sflow_polling_interval_get_reply_e929801c";
  static vapi_message_desc_t __vapi_metadata_sflow_polling_interval_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sflow_polling_interval_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sflow_polling_interval_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_polling_interval_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_sflow_polling_interval_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_polling_interval_get_reply = vapi_register_msg(&__vapi_metadata_sflow_polling_interval_get_reply);
  VAPI_DBG("Assigned msg id %d to sflow_polling_interval_get_reply", vapi_msg_id_sflow_polling_interval_get_reply);
}

static inline void vapi_set_vapi_msg_sflow_polling_interval_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sflow_polling_interval_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sflow_polling_interval_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sflow_polling_interval_get
#define defined_vapi_msg_sflow_polling_interval_get
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_sflow_polling_interval_get;

static inline void vapi_msg_sflow_polling_interval_get_hton(vapi_msg_sflow_polling_interval_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_polling_interval_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_sflow_polling_interval_get_ntoh(vapi_msg_sflow_polling_interval_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_polling_interval_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_sflow_polling_interval_get_msg_size(vapi_msg_sflow_polling_interval_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_polling_interval_get_msg_size(vapi_msg_sflow_polling_interval_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_polling_interval_get) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_polling_interval_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_polling_interval_get));
      return -1;
    }
  if (vapi_calc_sflow_polling_interval_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_polling_interval_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_polling_interval_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sflow_polling_interval_get* vapi_alloc_sflow_polling_interval_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_sflow_polling_interval_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_sflow_polling_interval_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sflow_polling_interval_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sflow_polling_interval_get);

  return msg;
}

static inline vapi_error_e vapi_sflow_polling_interval_get(struct vapi_ctx_s *ctx,
  vapi_msg_sflow_polling_interval_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sflow_polling_interval_get_reply *reply),
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
  vapi_msg_sflow_polling_interval_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sflow_polling_interval_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sflow_polling_interval_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sflow_polling_interval_get()
{
  static const char name[] = "sflow_polling_interval_get";
  static const char name_with_crc[] = "sflow_polling_interval_get_51077d14";
  static vapi_message_desc_t __vapi_metadata_sflow_polling_interval_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_sflow_polling_interval_get_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_polling_interval_get_hton,
    (generic_swap_fn_t)vapi_msg_sflow_polling_interval_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_polling_interval_get = vapi_register_msg(&__vapi_metadata_sflow_polling_interval_get);
  VAPI_DBG("Assigned msg id %d to sflow_polling_interval_get", vapi_msg_id_sflow_polling_interval_get);
}
#endif

#ifndef defined_vapi_msg_sflow_header_bytes_set_reply
#define defined_vapi_msg_sflow_header_bytes_set_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_sflow_header_bytes_set_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sflow_header_bytes_set_reply payload;
} vapi_msg_sflow_header_bytes_set_reply;

static inline void vapi_msg_sflow_header_bytes_set_reply_payload_hton(vapi_payload_sflow_header_bytes_set_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_sflow_header_bytes_set_reply_payload_ntoh(vapi_payload_sflow_header_bytes_set_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_sflow_header_bytes_set_reply_hton(vapi_msg_sflow_header_bytes_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_header_bytes_set_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sflow_header_bytes_set_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sflow_header_bytes_set_reply_ntoh(vapi_msg_sflow_header_bytes_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_header_bytes_set_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sflow_header_bytes_set_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sflow_header_bytes_set_reply_msg_size(vapi_msg_sflow_header_bytes_set_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_header_bytes_set_reply_msg_size(vapi_msg_sflow_header_bytes_set_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_header_bytes_set_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_header_bytes_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_header_bytes_set_reply));
      return -1;
    }
  if (vapi_calc_sflow_header_bytes_set_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_header_bytes_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_header_bytes_set_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sflow_header_bytes_set_reply()
{
  static const char name[] = "sflow_header_bytes_set_reply";
  static const char name_with_crc[] = "sflow_header_bytes_set_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_sflow_header_bytes_set_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sflow_header_bytes_set_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sflow_header_bytes_set_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_header_bytes_set_reply_hton,
    (generic_swap_fn_t)vapi_msg_sflow_header_bytes_set_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_header_bytes_set_reply = vapi_register_msg(&__vapi_metadata_sflow_header_bytes_set_reply);
  VAPI_DBG("Assigned msg id %d to sflow_header_bytes_set_reply", vapi_msg_id_sflow_header_bytes_set_reply);
}

static inline void vapi_set_vapi_msg_sflow_header_bytes_set_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sflow_header_bytes_set_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sflow_header_bytes_set_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sflow_header_bytes_set
#define defined_vapi_msg_sflow_header_bytes_set
typedef struct __attribute__ ((__packed__)) {
  u32 header_B; 
} vapi_payload_sflow_header_bytes_set;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sflow_header_bytes_set payload;
} vapi_msg_sflow_header_bytes_set;

static inline void vapi_msg_sflow_header_bytes_set_payload_hton(vapi_payload_sflow_header_bytes_set *payload)
{
  payload->header_B = htobe32(payload->header_B);
}

static inline void vapi_msg_sflow_header_bytes_set_payload_ntoh(vapi_payload_sflow_header_bytes_set *payload)
{
  payload->header_B = be32toh(payload->header_B);
}

static inline void vapi_msg_sflow_header_bytes_set_hton(vapi_msg_sflow_header_bytes_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_header_bytes_set'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sflow_header_bytes_set_payload_hton(&msg->payload);
}

static inline void vapi_msg_sflow_header_bytes_set_ntoh(vapi_msg_sflow_header_bytes_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_header_bytes_set'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sflow_header_bytes_set_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sflow_header_bytes_set_msg_size(vapi_msg_sflow_header_bytes_set *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_header_bytes_set_msg_size(vapi_msg_sflow_header_bytes_set *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_header_bytes_set) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_header_bytes_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_header_bytes_set));
      return -1;
    }
  if (vapi_calc_sflow_header_bytes_set_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_header_bytes_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_header_bytes_set_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sflow_header_bytes_set* vapi_alloc_sflow_header_bytes_set(struct vapi_ctx_s *ctx)
{
  vapi_msg_sflow_header_bytes_set *msg = NULL;
  const size_t size = sizeof(vapi_msg_sflow_header_bytes_set);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sflow_header_bytes_set*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sflow_header_bytes_set);

  return msg;
}

static inline vapi_error_e vapi_sflow_header_bytes_set(struct vapi_ctx_s *ctx,
  vapi_msg_sflow_header_bytes_set *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sflow_header_bytes_set_reply *reply),
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
  vapi_msg_sflow_header_bytes_set_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sflow_header_bytes_set_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sflow_header_bytes_set_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sflow_header_bytes_set()
{
  static const char name[] = "sflow_header_bytes_set";
  static const char name_with_crc[] = "sflow_header_bytes_set_5baf56f3";
  static vapi_message_desc_t __vapi_metadata_sflow_header_bytes_set = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sflow_header_bytes_set, payload),
    (verify_msg_size_fn_t)vapi_verify_sflow_header_bytes_set_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_header_bytes_set_hton,
    (generic_swap_fn_t)vapi_msg_sflow_header_bytes_set_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_header_bytes_set = vapi_register_msg(&__vapi_metadata_sflow_header_bytes_set);
  VAPI_DBG("Assigned msg id %d to sflow_header_bytes_set", vapi_msg_id_sflow_header_bytes_set);
}
#endif

#ifndef defined_vapi_msg_sflow_header_bytes_get_reply
#define defined_vapi_msg_sflow_header_bytes_get_reply
typedef struct __attribute__ ((__packed__)) {
  u32 header_B; 
} vapi_payload_sflow_header_bytes_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sflow_header_bytes_get_reply payload;
} vapi_msg_sflow_header_bytes_get_reply;

static inline void vapi_msg_sflow_header_bytes_get_reply_payload_hton(vapi_payload_sflow_header_bytes_get_reply *payload)
{
  payload->header_B = htobe32(payload->header_B);
}

static inline void vapi_msg_sflow_header_bytes_get_reply_payload_ntoh(vapi_payload_sflow_header_bytes_get_reply *payload)
{
  payload->header_B = be32toh(payload->header_B);
}

static inline void vapi_msg_sflow_header_bytes_get_reply_hton(vapi_msg_sflow_header_bytes_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_header_bytes_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sflow_header_bytes_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sflow_header_bytes_get_reply_ntoh(vapi_msg_sflow_header_bytes_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_header_bytes_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sflow_header_bytes_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sflow_header_bytes_get_reply_msg_size(vapi_msg_sflow_header_bytes_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_header_bytes_get_reply_msg_size(vapi_msg_sflow_header_bytes_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_header_bytes_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_header_bytes_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_header_bytes_get_reply));
      return -1;
    }
  if (vapi_calc_sflow_header_bytes_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_header_bytes_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_header_bytes_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sflow_header_bytes_get_reply()
{
  static const char name[] = "sflow_header_bytes_get_reply";
  static const char name_with_crc[] = "sflow_header_bytes_get_reply_624c95b9";
  static vapi_message_desc_t __vapi_metadata_sflow_header_bytes_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sflow_header_bytes_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sflow_header_bytes_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_header_bytes_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_sflow_header_bytes_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_header_bytes_get_reply = vapi_register_msg(&__vapi_metadata_sflow_header_bytes_get_reply);
  VAPI_DBG("Assigned msg id %d to sflow_header_bytes_get_reply", vapi_msg_id_sflow_header_bytes_get_reply);
}

static inline void vapi_set_vapi_msg_sflow_header_bytes_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sflow_header_bytes_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sflow_header_bytes_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sflow_header_bytes_get
#define defined_vapi_msg_sflow_header_bytes_get
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_sflow_header_bytes_get;

static inline void vapi_msg_sflow_header_bytes_get_hton(vapi_msg_sflow_header_bytes_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_header_bytes_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_sflow_header_bytes_get_ntoh(vapi_msg_sflow_header_bytes_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_header_bytes_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_sflow_header_bytes_get_msg_size(vapi_msg_sflow_header_bytes_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_header_bytes_get_msg_size(vapi_msg_sflow_header_bytes_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_header_bytes_get) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_header_bytes_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_header_bytes_get));
      return -1;
    }
  if (vapi_calc_sflow_header_bytes_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_header_bytes_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_header_bytes_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sflow_header_bytes_get* vapi_alloc_sflow_header_bytes_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_sflow_header_bytes_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_sflow_header_bytes_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sflow_header_bytes_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sflow_header_bytes_get);

  return msg;
}

static inline vapi_error_e vapi_sflow_header_bytes_get(struct vapi_ctx_s *ctx,
  vapi_msg_sflow_header_bytes_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sflow_header_bytes_get_reply *reply),
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
  vapi_msg_sflow_header_bytes_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sflow_header_bytes_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sflow_header_bytes_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sflow_header_bytes_get()
{
  static const char name[] = "sflow_header_bytes_get";
  static const char name_with_crc[] = "sflow_header_bytes_get_51077d14";
  static vapi_message_desc_t __vapi_metadata_sflow_header_bytes_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_sflow_header_bytes_get_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_header_bytes_get_hton,
    (generic_swap_fn_t)vapi_msg_sflow_header_bytes_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_header_bytes_get = vapi_register_msg(&__vapi_metadata_sflow_header_bytes_get);
  VAPI_DBG("Assigned msg id %d to sflow_header_bytes_get", vapi_msg_id_sflow_header_bytes_get);
}
#endif

#ifndef defined_vapi_msg_sflow_direction_set_reply
#define defined_vapi_msg_sflow_direction_set_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_sflow_direction_set_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sflow_direction_set_reply payload;
} vapi_msg_sflow_direction_set_reply;

static inline void vapi_msg_sflow_direction_set_reply_payload_hton(vapi_payload_sflow_direction_set_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_sflow_direction_set_reply_payload_ntoh(vapi_payload_sflow_direction_set_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_sflow_direction_set_reply_hton(vapi_msg_sflow_direction_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_direction_set_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sflow_direction_set_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sflow_direction_set_reply_ntoh(vapi_msg_sflow_direction_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_direction_set_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sflow_direction_set_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sflow_direction_set_reply_msg_size(vapi_msg_sflow_direction_set_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_direction_set_reply_msg_size(vapi_msg_sflow_direction_set_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_direction_set_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_direction_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_direction_set_reply));
      return -1;
    }
  if (vapi_calc_sflow_direction_set_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_direction_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_direction_set_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sflow_direction_set_reply()
{
  static const char name[] = "sflow_direction_set_reply";
  static const char name_with_crc[] = "sflow_direction_set_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_sflow_direction_set_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sflow_direction_set_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sflow_direction_set_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_direction_set_reply_hton,
    (generic_swap_fn_t)vapi_msg_sflow_direction_set_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_direction_set_reply = vapi_register_msg(&__vapi_metadata_sflow_direction_set_reply);
  VAPI_DBG("Assigned msg id %d to sflow_direction_set_reply", vapi_msg_id_sflow_direction_set_reply);
}

static inline void vapi_set_vapi_msg_sflow_direction_set_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sflow_direction_set_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sflow_direction_set_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sflow_direction_set
#define defined_vapi_msg_sflow_direction_set
typedef struct __attribute__ ((__packed__)) {
  u32 sampling_D; 
} vapi_payload_sflow_direction_set;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sflow_direction_set payload;
} vapi_msg_sflow_direction_set;

static inline void vapi_msg_sflow_direction_set_payload_hton(vapi_payload_sflow_direction_set *payload)
{
  payload->sampling_D = htobe32(payload->sampling_D);
}

static inline void vapi_msg_sflow_direction_set_payload_ntoh(vapi_payload_sflow_direction_set *payload)
{
  payload->sampling_D = be32toh(payload->sampling_D);
}

static inline void vapi_msg_sflow_direction_set_hton(vapi_msg_sflow_direction_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_direction_set'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sflow_direction_set_payload_hton(&msg->payload);
}

static inline void vapi_msg_sflow_direction_set_ntoh(vapi_msg_sflow_direction_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_direction_set'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sflow_direction_set_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sflow_direction_set_msg_size(vapi_msg_sflow_direction_set *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_direction_set_msg_size(vapi_msg_sflow_direction_set *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_direction_set) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_direction_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_direction_set));
      return -1;
    }
  if (vapi_calc_sflow_direction_set_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_direction_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_direction_set_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sflow_direction_set* vapi_alloc_sflow_direction_set(struct vapi_ctx_s *ctx)
{
  vapi_msg_sflow_direction_set *msg = NULL;
  const size_t size = sizeof(vapi_msg_sflow_direction_set);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sflow_direction_set*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sflow_direction_set);

  return msg;
}

static inline vapi_error_e vapi_sflow_direction_set(struct vapi_ctx_s *ctx,
  vapi_msg_sflow_direction_set *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sflow_direction_set_reply *reply),
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
  vapi_msg_sflow_direction_set_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sflow_direction_set_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sflow_direction_set_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sflow_direction_set()
{
  static const char name[] = "sflow_direction_set";
  static const char name_with_crc[] = "sflow_direction_set_fbca6f34";
  static vapi_message_desc_t __vapi_metadata_sflow_direction_set = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sflow_direction_set, payload),
    (verify_msg_size_fn_t)vapi_verify_sflow_direction_set_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_direction_set_hton,
    (generic_swap_fn_t)vapi_msg_sflow_direction_set_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_direction_set = vapi_register_msg(&__vapi_metadata_sflow_direction_set);
  VAPI_DBG("Assigned msg id %d to sflow_direction_set", vapi_msg_id_sflow_direction_set);
}
#endif

#ifndef defined_vapi_msg_sflow_direction_get_reply
#define defined_vapi_msg_sflow_direction_get_reply
typedef struct __attribute__ ((__packed__)) {
  u32 sampling_D; 
} vapi_payload_sflow_direction_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sflow_direction_get_reply payload;
} vapi_msg_sflow_direction_get_reply;

static inline void vapi_msg_sflow_direction_get_reply_payload_hton(vapi_payload_sflow_direction_get_reply *payload)
{
  payload->sampling_D = htobe32(payload->sampling_D);
}

static inline void vapi_msg_sflow_direction_get_reply_payload_ntoh(vapi_payload_sflow_direction_get_reply *payload)
{
  payload->sampling_D = be32toh(payload->sampling_D);
}

static inline void vapi_msg_sflow_direction_get_reply_hton(vapi_msg_sflow_direction_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_direction_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sflow_direction_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sflow_direction_get_reply_ntoh(vapi_msg_sflow_direction_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_direction_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sflow_direction_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sflow_direction_get_reply_msg_size(vapi_msg_sflow_direction_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_direction_get_reply_msg_size(vapi_msg_sflow_direction_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_direction_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_direction_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_direction_get_reply));
      return -1;
    }
  if (vapi_calc_sflow_direction_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_direction_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_direction_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sflow_direction_get_reply()
{
  static const char name[] = "sflow_direction_get_reply";
  static const char name_with_crc[] = "sflow_direction_get_reply_f3316252";
  static vapi_message_desc_t __vapi_metadata_sflow_direction_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sflow_direction_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sflow_direction_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_direction_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_sflow_direction_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_direction_get_reply = vapi_register_msg(&__vapi_metadata_sflow_direction_get_reply);
  VAPI_DBG("Assigned msg id %d to sflow_direction_get_reply", vapi_msg_id_sflow_direction_get_reply);
}

static inline void vapi_set_vapi_msg_sflow_direction_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sflow_direction_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sflow_direction_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sflow_direction_get
#define defined_vapi_msg_sflow_direction_get
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_sflow_direction_get;

static inline void vapi_msg_sflow_direction_get_hton(vapi_msg_sflow_direction_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_direction_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_sflow_direction_get_ntoh(vapi_msg_sflow_direction_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_direction_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_sflow_direction_get_msg_size(vapi_msg_sflow_direction_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_direction_get_msg_size(vapi_msg_sflow_direction_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_direction_get) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_direction_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_direction_get));
      return -1;
    }
  if (vapi_calc_sflow_direction_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_direction_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_direction_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sflow_direction_get* vapi_alloc_sflow_direction_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_sflow_direction_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_sflow_direction_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sflow_direction_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sflow_direction_get);

  return msg;
}

static inline vapi_error_e vapi_sflow_direction_get(struct vapi_ctx_s *ctx,
  vapi_msg_sflow_direction_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sflow_direction_get_reply *reply),
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
  vapi_msg_sflow_direction_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sflow_direction_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sflow_direction_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sflow_direction_get()
{
  static const char name[] = "sflow_direction_get";
  static const char name_with_crc[] = "sflow_direction_get_51077d14";
  static vapi_message_desc_t __vapi_metadata_sflow_direction_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_sflow_direction_get_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_direction_get_hton,
    (generic_swap_fn_t)vapi_msg_sflow_direction_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_direction_get = vapi_register_msg(&__vapi_metadata_sflow_direction_get);
  VAPI_DBG("Assigned msg id %d to sflow_direction_get", vapi_msg_id_sflow_direction_get);
}
#endif

#ifndef defined_vapi_msg_sflow_drop_monitoring_set_reply
#define defined_vapi_msg_sflow_drop_monitoring_set_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_sflow_drop_monitoring_set_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sflow_drop_monitoring_set_reply payload;
} vapi_msg_sflow_drop_monitoring_set_reply;

static inline void vapi_msg_sflow_drop_monitoring_set_reply_payload_hton(vapi_payload_sflow_drop_monitoring_set_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_sflow_drop_monitoring_set_reply_payload_ntoh(vapi_payload_sflow_drop_monitoring_set_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_sflow_drop_monitoring_set_reply_hton(vapi_msg_sflow_drop_monitoring_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_drop_monitoring_set_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sflow_drop_monitoring_set_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sflow_drop_monitoring_set_reply_ntoh(vapi_msg_sflow_drop_monitoring_set_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_drop_monitoring_set_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sflow_drop_monitoring_set_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sflow_drop_monitoring_set_reply_msg_size(vapi_msg_sflow_drop_monitoring_set_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_drop_monitoring_set_reply_msg_size(vapi_msg_sflow_drop_monitoring_set_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_drop_monitoring_set_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_drop_monitoring_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_drop_monitoring_set_reply));
      return -1;
    }
  if (vapi_calc_sflow_drop_monitoring_set_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_drop_monitoring_set_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_drop_monitoring_set_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sflow_drop_monitoring_set_reply()
{
  static const char name[] = "sflow_drop_monitoring_set_reply";
  static const char name_with_crc[] = "sflow_drop_monitoring_set_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_sflow_drop_monitoring_set_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sflow_drop_monitoring_set_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sflow_drop_monitoring_set_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_drop_monitoring_set_reply_hton,
    (generic_swap_fn_t)vapi_msg_sflow_drop_monitoring_set_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_drop_monitoring_set_reply = vapi_register_msg(&__vapi_metadata_sflow_drop_monitoring_set_reply);
  VAPI_DBG("Assigned msg id %d to sflow_drop_monitoring_set_reply", vapi_msg_id_sflow_drop_monitoring_set_reply);
}

static inline void vapi_set_vapi_msg_sflow_drop_monitoring_set_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sflow_drop_monitoring_set_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sflow_drop_monitoring_set_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sflow_drop_monitoring_set
#define defined_vapi_msg_sflow_drop_monitoring_set
typedef struct __attribute__ ((__packed__)) {
  u32 drop_M; 
} vapi_payload_sflow_drop_monitoring_set;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sflow_drop_monitoring_set payload;
} vapi_msg_sflow_drop_monitoring_set;

static inline void vapi_msg_sflow_drop_monitoring_set_payload_hton(vapi_payload_sflow_drop_monitoring_set *payload)
{
  payload->drop_M = htobe32(payload->drop_M);
}

static inline void vapi_msg_sflow_drop_monitoring_set_payload_ntoh(vapi_payload_sflow_drop_monitoring_set *payload)
{
  payload->drop_M = be32toh(payload->drop_M);
}

static inline void vapi_msg_sflow_drop_monitoring_set_hton(vapi_msg_sflow_drop_monitoring_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_drop_monitoring_set'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sflow_drop_monitoring_set_payload_hton(&msg->payload);
}

static inline void vapi_msg_sflow_drop_monitoring_set_ntoh(vapi_msg_sflow_drop_monitoring_set *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_drop_monitoring_set'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sflow_drop_monitoring_set_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sflow_drop_monitoring_set_msg_size(vapi_msg_sflow_drop_monitoring_set *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_drop_monitoring_set_msg_size(vapi_msg_sflow_drop_monitoring_set *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_drop_monitoring_set) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_drop_monitoring_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_drop_monitoring_set));
      return -1;
    }
  if (vapi_calc_sflow_drop_monitoring_set_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_drop_monitoring_set' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_drop_monitoring_set_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sflow_drop_monitoring_set* vapi_alloc_sflow_drop_monitoring_set(struct vapi_ctx_s *ctx)
{
  vapi_msg_sflow_drop_monitoring_set *msg = NULL;
  const size_t size = sizeof(vapi_msg_sflow_drop_monitoring_set);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sflow_drop_monitoring_set*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sflow_drop_monitoring_set);

  return msg;
}

static inline vapi_error_e vapi_sflow_drop_monitoring_set(struct vapi_ctx_s *ctx,
  vapi_msg_sflow_drop_monitoring_set *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sflow_drop_monitoring_set_reply *reply),
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
  vapi_msg_sflow_drop_monitoring_set_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sflow_drop_monitoring_set_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sflow_drop_monitoring_set_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sflow_drop_monitoring_set()
{
  static const char name[] = "sflow_drop_monitoring_set";
  static const char name_with_crc[] = "sflow_drop_monitoring_set_100b1e04";
  static vapi_message_desc_t __vapi_metadata_sflow_drop_monitoring_set = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sflow_drop_monitoring_set, payload),
    (verify_msg_size_fn_t)vapi_verify_sflow_drop_monitoring_set_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_drop_monitoring_set_hton,
    (generic_swap_fn_t)vapi_msg_sflow_drop_monitoring_set_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_drop_monitoring_set = vapi_register_msg(&__vapi_metadata_sflow_drop_monitoring_set);
  VAPI_DBG("Assigned msg id %d to sflow_drop_monitoring_set", vapi_msg_id_sflow_drop_monitoring_set);
}
#endif

#ifndef defined_vapi_msg_sflow_drop_monitoring_get_reply
#define defined_vapi_msg_sflow_drop_monitoring_get_reply
typedef struct __attribute__ ((__packed__)) {
  u32 drop_M; 
} vapi_payload_sflow_drop_monitoring_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sflow_drop_monitoring_get_reply payload;
} vapi_msg_sflow_drop_monitoring_get_reply;

static inline void vapi_msg_sflow_drop_monitoring_get_reply_payload_hton(vapi_payload_sflow_drop_monitoring_get_reply *payload)
{
  payload->drop_M = htobe32(payload->drop_M);
}

static inline void vapi_msg_sflow_drop_monitoring_get_reply_payload_ntoh(vapi_payload_sflow_drop_monitoring_get_reply *payload)
{
  payload->drop_M = be32toh(payload->drop_M);
}

static inline void vapi_msg_sflow_drop_monitoring_get_reply_hton(vapi_msg_sflow_drop_monitoring_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_drop_monitoring_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sflow_drop_monitoring_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sflow_drop_monitoring_get_reply_ntoh(vapi_msg_sflow_drop_monitoring_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_drop_monitoring_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sflow_drop_monitoring_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sflow_drop_monitoring_get_reply_msg_size(vapi_msg_sflow_drop_monitoring_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_drop_monitoring_get_reply_msg_size(vapi_msg_sflow_drop_monitoring_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_drop_monitoring_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_drop_monitoring_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_drop_monitoring_get_reply));
      return -1;
    }
  if (vapi_calc_sflow_drop_monitoring_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_drop_monitoring_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_drop_monitoring_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sflow_drop_monitoring_get_reply()
{
  static const char name[] = "sflow_drop_monitoring_get_reply";
  static const char name_with_crc[] = "sflow_drop_monitoring_get_reply_b56ae30e";
  static vapi_message_desc_t __vapi_metadata_sflow_drop_monitoring_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sflow_drop_monitoring_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sflow_drop_monitoring_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_drop_monitoring_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_sflow_drop_monitoring_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_drop_monitoring_get_reply = vapi_register_msg(&__vapi_metadata_sflow_drop_monitoring_get_reply);
  VAPI_DBG("Assigned msg id %d to sflow_drop_monitoring_get_reply", vapi_msg_id_sflow_drop_monitoring_get_reply);
}

static inline void vapi_set_vapi_msg_sflow_drop_monitoring_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sflow_drop_monitoring_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sflow_drop_monitoring_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sflow_drop_monitoring_get
#define defined_vapi_msg_sflow_drop_monitoring_get
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_sflow_drop_monitoring_get;

static inline void vapi_msg_sflow_drop_monitoring_get_hton(vapi_msg_sflow_drop_monitoring_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_drop_monitoring_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_sflow_drop_monitoring_get_ntoh(vapi_msg_sflow_drop_monitoring_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_drop_monitoring_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_sflow_drop_monitoring_get_msg_size(vapi_msg_sflow_drop_monitoring_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_drop_monitoring_get_msg_size(vapi_msg_sflow_drop_monitoring_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_drop_monitoring_get) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_drop_monitoring_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_drop_monitoring_get));
      return -1;
    }
  if (vapi_calc_sflow_drop_monitoring_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_drop_monitoring_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_drop_monitoring_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sflow_drop_monitoring_get* vapi_alloc_sflow_drop_monitoring_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_sflow_drop_monitoring_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_sflow_drop_monitoring_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sflow_drop_monitoring_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sflow_drop_monitoring_get);

  return msg;
}

static inline vapi_error_e vapi_sflow_drop_monitoring_get(struct vapi_ctx_s *ctx,
  vapi_msg_sflow_drop_monitoring_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sflow_drop_monitoring_get_reply *reply),
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
  vapi_msg_sflow_drop_monitoring_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sflow_drop_monitoring_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sflow_drop_monitoring_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sflow_drop_monitoring_get()
{
  static const char name[] = "sflow_drop_monitoring_get";
  static const char name_with_crc[] = "sflow_drop_monitoring_get_51077d14";
  static vapi_message_desc_t __vapi_metadata_sflow_drop_monitoring_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_sflow_drop_monitoring_get_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_drop_monitoring_get_hton,
    (generic_swap_fn_t)vapi_msg_sflow_drop_monitoring_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_drop_monitoring_get = vapi_register_msg(&__vapi_metadata_sflow_drop_monitoring_get);
  VAPI_DBG("Assigned msg id %d to sflow_drop_monitoring_get", vapi_msg_id_sflow_drop_monitoring_get);
}
#endif

#ifndef defined_vapi_msg_sflow_interface_details
#define defined_vapi_msg_sflow_interface_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index hw_if_index; 
} vapi_payload_sflow_interface_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sflow_interface_details payload;
} vapi_msg_sflow_interface_details;

static inline void vapi_msg_sflow_interface_details_payload_hton(vapi_payload_sflow_interface_details *payload)
{
  payload->hw_if_index = htobe32(payload->hw_if_index);
}

static inline void vapi_msg_sflow_interface_details_payload_ntoh(vapi_payload_sflow_interface_details *payload)
{
  payload->hw_if_index = be32toh(payload->hw_if_index);
}

static inline void vapi_msg_sflow_interface_details_hton(vapi_msg_sflow_interface_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_interface_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sflow_interface_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_sflow_interface_details_ntoh(vapi_msg_sflow_interface_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_interface_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sflow_interface_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sflow_interface_details_msg_size(vapi_msg_sflow_interface_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_interface_details_msg_size(vapi_msg_sflow_interface_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_interface_details) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_interface_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_interface_details));
      return -1;
    }
  if (vapi_calc_sflow_interface_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_interface_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_interface_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sflow_interface_details()
{
  static const char name[] = "sflow_interface_details";
  static const char name_with_crc[] = "sflow_interface_details_b7b9143f";
  static vapi_message_desc_t __vapi_metadata_sflow_interface_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sflow_interface_details, payload),
    (verify_msg_size_fn_t)vapi_verify_sflow_interface_details_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_interface_details_hton,
    (generic_swap_fn_t)vapi_msg_sflow_interface_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_interface_details = vapi_register_msg(&__vapi_metadata_sflow_interface_details);
  VAPI_DBG("Assigned msg id %d to sflow_interface_details", vapi_msg_id_sflow_interface_details);
}

static inline void vapi_set_vapi_msg_sflow_interface_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sflow_interface_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sflow_interface_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sflow_interface_dump
#define defined_vapi_msg_sflow_interface_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index hw_if_index; 
} vapi_payload_sflow_interface_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sflow_interface_dump payload;
} vapi_msg_sflow_interface_dump;

static inline void vapi_msg_sflow_interface_dump_payload_hton(vapi_payload_sflow_interface_dump *payload)
{
  payload->hw_if_index = htobe32(payload->hw_if_index);
}

static inline void vapi_msg_sflow_interface_dump_payload_ntoh(vapi_payload_sflow_interface_dump *payload)
{
  payload->hw_if_index = be32toh(payload->hw_if_index);
}

static inline void vapi_msg_sflow_interface_dump_hton(vapi_msg_sflow_interface_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_interface_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sflow_interface_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_sflow_interface_dump_ntoh(vapi_msg_sflow_interface_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sflow_interface_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sflow_interface_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sflow_interface_dump_msg_size(vapi_msg_sflow_interface_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sflow_interface_dump_msg_size(vapi_msg_sflow_interface_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sflow_interface_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_interface_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sflow_interface_dump));
      return -1;
    }
  if (vapi_calc_sflow_interface_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sflow_interface_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sflow_interface_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sflow_interface_dump* vapi_alloc_sflow_interface_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_sflow_interface_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_sflow_interface_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sflow_interface_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sflow_interface_dump);

  return msg;
}

static inline vapi_error_e vapi_sflow_interface_dump(struct vapi_ctx_s *ctx,
  vapi_msg_sflow_interface_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sflow_interface_details *reply),
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
  vapi_msg_sflow_interface_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sflow_interface_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_sflow_interface_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sflow_interface_dump()
{
  static const char name[] = "sflow_interface_dump";
  static const char name_with_crc[] = "sflow_interface_dump_451a727d";
  static vapi_message_desc_t __vapi_metadata_sflow_interface_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sflow_interface_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_sflow_interface_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_sflow_interface_dump_hton,
    (generic_swap_fn_t)vapi_msg_sflow_interface_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sflow_interface_dump = vapi_register_msg(&__vapi_metadata_sflow_interface_dump);
  VAPI_DBG("Assigned msg id %d to sflow_interface_dump", vapi_msg_id_sflow_interface_dump);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
