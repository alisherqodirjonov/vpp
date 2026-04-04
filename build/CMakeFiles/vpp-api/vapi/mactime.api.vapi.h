#ifndef __included_mactime_api_json
#define __included_mactime_api_json

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

extern vapi_msg_id_t vapi_msg_id_mactime_enable_disable;
extern vapi_msg_id_t vapi_msg_id_mactime_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_mactime_add_del_range;
extern vapi_msg_id_t vapi_msg_id_mactime_add_del_range_reply;
extern vapi_msg_id_t vapi_msg_id_mactime_dump;
extern vapi_msg_id_t vapi_msg_id_mactime_details;

#define DEFINE_VAPI_MSG_IDS_MACTIME_API_JSON\
  vapi_msg_id_t vapi_msg_id_mactime_enable_disable;\
  vapi_msg_id_t vapi_msg_id_mactime_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_mactime_add_del_range;\
  vapi_msg_id_t vapi_msg_id_mactime_add_del_range_reply;\
  vapi_msg_id_t vapi_msg_id_mactime_dump;\
  vapi_msg_id_t vapi_msg_id_mactime_details;


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

#ifndef defined_vapi_type_time_range
#define defined_vapi_type_time_range
typedef struct __attribute__((__packed__)) {
  f64 start;
  f64 end;
} vapi_type_time_range;

static inline void vapi_type_time_range_hton(vapi_type_time_range *msg)
{

}

static inline void vapi_type_time_range_ntoh(vapi_type_time_range *msg)
{

}
#endif

#ifndef defined_vapi_type_mactime_time_range
#define defined_vapi_type_mactime_time_range
typedef struct __attribute__((__packed__)) {
  f64 start;
  f64 end;
} vapi_type_mactime_time_range;

static inline void vapi_type_mactime_time_range_hton(vapi_type_mactime_time_range *msg)
{

}

static inline void vapi_type_mactime_time_range_ntoh(vapi_type_mactime_time_range *msg)
{

}
#endif

#ifndef defined_vapi_type_mac_address
#define defined_vapi_type_mac_address
typedef u8 vapi_type_mac_address[6];

#endif

#ifndef defined_vapi_type_interface_index
#define defined_vapi_type_interface_index
typedef u32 vapi_type_interface_index;

#endif

#ifndef defined_vapi_msg_mactime_enable_disable_reply
#define defined_vapi_msg_mactime_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_mactime_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_mactime_enable_disable_reply payload;
} vapi_msg_mactime_enable_disable_reply;

static inline void vapi_msg_mactime_enable_disable_reply_payload_hton(vapi_payload_mactime_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_mactime_enable_disable_reply_payload_ntoh(vapi_payload_mactime_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_mactime_enable_disable_reply_hton(vapi_msg_mactime_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mactime_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_mactime_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_mactime_enable_disable_reply_ntoh(vapi_msg_mactime_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mactime_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_mactime_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_mactime_enable_disable_reply_msg_size(vapi_msg_mactime_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_mactime_enable_disable_reply_msg_size(vapi_msg_mactime_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_mactime_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'mactime_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_mactime_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_mactime_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'mactime_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_mactime_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_mactime_enable_disable_reply()
{
  static const char name[] = "mactime_enable_disable_reply";
  static const char name_with_crc[] = "mactime_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_mactime_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_mactime_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_mactime_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_mactime_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_mactime_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_mactime_enable_disable_reply = vapi_register_msg(&__vapi_metadata_mactime_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to mactime_enable_disable_reply", vapi_msg_id_mactime_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_mactime_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_mactime_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_mactime_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_mactime_enable_disable
#define defined_vapi_msg_mactime_enable_disable
typedef struct __attribute__ ((__packed__)) {
  bool enable_disable;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_mactime_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_mactime_enable_disable payload;
} vapi_msg_mactime_enable_disable;

static inline void vapi_msg_mactime_enable_disable_payload_hton(vapi_payload_mactime_enable_disable *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_mactime_enable_disable_payload_ntoh(vapi_payload_mactime_enable_disable *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_mactime_enable_disable_hton(vapi_msg_mactime_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mactime_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_mactime_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_mactime_enable_disable_ntoh(vapi_msg_mactime_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mactime_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_mactime_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_mactime_enable_disable_msg_size(vapi_msg_mactime_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_mactime_enable_disable_msg_size(vapi_msg_mactime_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_mactime_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'mactime_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_mactime_enable_disable));
      return -1;
    }
  if (vapi_calc_mactime_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'mactime_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_mactime_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_mactime_enable_disable* vapi_alloc_mactime_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_mactime_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_mactime_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_mactime_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_mactime_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_mactime_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_mactime_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_mactime_enable_disable_reply *reply),
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
  vapi_msg_mactime_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_mactime_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_mactime_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_mactime_enable_disable()
{
  static const char name[] = "mactime_enable_disable";
  static const char name_with_crc[] = "mactime_enable_disable_3865946c";
  static vapi_message_desc_t __vapi_metadata_mactime_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_mactime_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_mactime_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_mactime_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_mactime_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_mactime_enable_disable = vapi_register_msg(&__vapi_metadata_mactime_enable_disable);
  VAPI_DBG("Assigned msg id %d to mactime_enable_disable", vapi_msg_id_mactime_enable_disable);
}
#endif

#ifndef defined_vapi_msg_mactime_add_del_range_reply
#define defined_vapi_msg_mactime_add_del_range_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_mactime_add_del_range_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_mactime_add_del_range_reply payload;
} vapi_msg_mactime_add_del_range_reply;

static inline void vapi_msg_mactime_add_del_range_reply_payload_hton(vapi_payload_mactime_add_del_range_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_mactime_add_del_range_reply_payload_ntoh(vapi_payload_mactime_add_del_range_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_mactime_add_del_range_reply_hton(vapi_msg_mactime_add_del_range_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mactime_add_del_range_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_mactime_add_del_range_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_mactime_add_del_range_reply_ntoh(vapi_msg_mactime_add_del_range_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mactime_add_del_range_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_mactime_add_del_range_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_mactime_add_del_range_reply_msg_size(vapi_msg_mactime_add_del_range_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_mactime_add_del_range_reply_msg_size(vapi_msg_mactime_add_del_range_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_mactime_add_del_range_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'mactime_add_del_range_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_mactime_add_del_range_reply));
      return -1;
    }
  if (vapi_calc_mactime_add_del_range_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'mactime_add_del_range_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_mactime_add_del_range_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_mactime_add_del_range_reply()
{
  static const char name[] = "mactime_add_del_range_reply";
  static const char name_with_crc[] = "mactime_add_del_range_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_mactime_add_del_range_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_mactime_add_del_range_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_mactime_add_del_range_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_mactime_add_del_range_reply_hton,
    (generic_swap_fn_t)vapi_msg_mactime_add_del_range_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_mactime_add_del_range_reply = vapi_register_msg(&__vapi_metadata_mactime_add_del_range_reply);
  VAPI_DBG("Assigned msg id %d to mactime_add_del_range_reply", vapi_msg_id_mactime_add_del_range_reply);
}

static inline void vapi_set_vapi_msg_mactime_add_del_range_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_mactime_add_del_range_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_mactime_add_del_range_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_mactime_add_del_range
#define defined_vapi_msg_mactime_add_del_range
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  bool drop;
  bool allow;
  u8 allow_quota;
  bool no_udp_10001;
  u64 data_quota;
  vapi_type_mac_address mac_address;
  u8 device_name[64];
  u32 count;
  vapi_type_time_range ranges[0]; 
} vapi_payload_mactime_add_del_range;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_mactime_add_del_range payload;
} vapi_msg_mactime_add_del_range;

static inline void vapi_msg_mactime_add_del_range_payload_hton(vapi_payload_mactime_add_del_range *payload)
{
  payload->data_quota = htobe64(payload->data_quota);
  payload->count = htobe32(payload->count);
}

static inline void vapi_msg_mactime_add_del_range_payload_ntoh(vapi_payload_mactime_add_del_range *payload)
{
  payload->data_quota = be64toh(payload->data_quota);
  payload->count = be32toh(payload->count);
}

static inline void vapi_msg_mactime_add_del_range_hton(vapi_msg_mactime_add_del_range *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mactime_add_del_range'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_mactime_add_del_range_payload_hton(&msg->payload);
}

static inline void vapi_msg_mactime_add_del_range_ntoh(vapi_msg_mactime_add_del_range *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mactime_add_del_range'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_mactime_add_del_range_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_mactime_add_del_range_msg_size(vapi_msg_mactime_add_del_range *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.ranges[0]) * msg->payload.count;
}

static inline int vapi_verify_mactime_add_del_range_msg_size(vapi_msg_mactime_add_del_range *msg, uword buf_size)
{
  if (sizeof(vapi_msg_mactime_add_del_range) > buf_size)
    {
      VAPI_ERR("Truncated 'mactime_add_del_range' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_mactime_add_del_range));
      return -1;
    }
  if (vapi_calc_mactime_add_del_range_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'mactime_add_del_range' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_mactime_add_del_range_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_mactime_add_del_range* vapi_alloc_mactime_add_del_range(struct vapi_ctx_s *ctx, size_t _ranges_array_size)
{
  vapi_msg_mactime_add_del_range *msg = NULL;
  const size_t size = sizeof(vapi_msg_mactime_add_del_range) + sizeof(msg->payload.ranges[0]) * _ranges_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_mactime_add_del_range*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_mactime_add_del_range);
  msg->payload.count = _ranges_array_size;

  return msg;
}

static inline vapi_error_e vapi_mactime_add_del_range(struct vapi_ctx_s *ctx,
  vapi_msg_mactime_add_del_range *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_mactime_add_del_range_reply *reply),
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
  vapi_msg_mactime_add_del_range_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_mactime_add_del_range_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_mactime_add_del_range_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_mactime_add_del_range()
{
  static const char name[] = "mactime_add_del_range";
  static const char name_with_crc[] = "mactime_add_del_range_cb56e877";
  static vapi_message_desc_t __vapi_metadata_mactime_add_del_range = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_mactime_add_del_range, payload),
    (verify_msg_size_fn_t)vapi_verify_mactime_add_del_range_msg_size,
    (generic_swap_fn_t)vapi_msg_mactime_add_del_range_hton,
    (generic_swap_fn_t)vapi_msg_mactime_add_del_range_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_mactime_add_del_range = vapi_register_msg(&__vapi_metadata_mactime_add_del_range);
  VAPI_DBG("Assigned msg id %d to mactime_add_del_range", vapi_msg_id_mactime_add_del_range);
}
#endif

#ifndef defined_vapi_msg_mactime_details
#define defined_vapi_msg_mactime_details
typedef struct __attribute__ ((__packed__)) {
  u32 pool_index;
  vapi_type_mac_address mac_address;
  u64 data_quota;
  u64 data_used_in_range;
  u32 flags;
  u8 device_name[64];
  u32 nranges;
  vapi_type_mactime_time_range ranges[0]; 
} vapi_payload_mactime_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_mactime_details payload;
} vapi_msg_mactime_details;

static inline void vapi_msg_mactime_details_payload_hton(vapi_payload_mactime_details *payload)
{
  payload->pool_index = htobe32(payload->pool_index);
  payload->data_quota = htobe64(payload->data_quota);
  payload->data_used_in_range = htobe64(payload->data_used_in_range);
  payload->flags = htobe32(payload->flags);
  payload->nranges = htobe32(payload->nranges);
}

static inline void vapi_msg_mactime_details_payload_ntoh(vapi_payload_mactime_details *payload)
{
  payload->pool_index = be32toh(payload->pool_index);
  payload->data_quota = be64toh(payload->data_quota);
  payload->data_used_in_range = be64toh(payload->data_used_in_range);
  payload->flags = be32toh(payload->flags);
  payload->nranges = be32toh(payload->nranges);
}

static inline void vapi_msg_mactime_details_hton(vapi_msg_mactime_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mactime_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_mactime_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_mactime_details_ntoh(vapi_msg_mactime_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mactime_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_mactime_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_mactime_details_msg_size(vapi_msg_mactime_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.ranges[0]) * msg->payload.nranges;
}

static inline int vapi_verify_mactime_details_msg_size(vapi_msg_mactime_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_mactime_details) > buf_size)
    {
      VAPI_ERR("Truncated 'mactime_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_mactime_details));
      return -1;
    }
  if (vapi_calc_mactime_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'mactime_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_mactime_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_mactime_details()
{
  static const char name[] = "mactime_details";
  static const char name_with_crc[] = "mactime_details_da25b13a";
  static vapi_message_desc_t __vapi_metadata_mactime_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_mactime_details, payload),
    (verify_msg_size_fn_t)vapi_verify_mactime_details_msg_size,
    (generic_swap_fn_t)vapi_msg_mactime_details_hton,
    (generic_swap_fn_t)vapi_msg_mactime_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_mactime_details = vapi_register_msg(&__vapi_metadata_mactime_details);
  VAPI_DBG("Assigned msg id %d to mactime_details", vapi_msg_id_mactime_details);
}

static inline void vapi_set_vapi_msg_mactime_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_mactime_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_mactime_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_mactime_dump
#define defined_vapi_msg_mactime_dump
typedef struct __attribute__ ((__packed__)) {
  u32 my_table_epoch; 
} vapi_payload_mactime_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_mactime_dump payload;
} vapi_msg_mactime_dump;

static inline void vapi_msg_mactime_dump_payload_hton(vapi_payload_mactime_dump *payload)
{
  payload->my_table_epoch = htobe32(payload->my_table_epoch);
}

static inline void vapi_msg_mactime_dump_payload_ntoh(vapi_payload_mactime_dump *payload)
{
  payload->my_table_epoch = be32toh(payload->my_table_epoch);
}

static inline void vapi_msg_mactime_dump_hton(vapi_msg_mactime_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mactime_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_mactime_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_mactime_dump_ntoh(vapi_msg_mactime_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mactime_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_mactime_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_mactime_dump_msg_size(vapi_msg_mactime_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_mactime_dump_msg_size(vapi_msg_mactime_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_mactime_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'mactime_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_mactime_dump));
      return -1;
    }
  if (vapi_calc_mactime_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'mactime_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_mactime_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_mactime_dump* vapi_alloc_mactime_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_mactime_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_mactime_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_mactime_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_mactime_dump);

  return msg;
}

static inline vapi_error_e vapi_mactime_dump(struct vapi_ctx_s *ctx,
  vapi_msg_mactime_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_mactime_details *reply),
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
  vapi_msg_mactime_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_mactime_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_mactime_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_mactime_dump()
{
  static const char name[] = "mactime_dump";
  static const char name_with_crc[] = "mactime_dump_8f454e23";
  static vapi_message_desc_t __vapi_metadata_mactime_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_mactime_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_mactime_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_mactime_dump_hton,
    (generic_swap_fn_t)vapi_msg_mactime_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_mactime_dump = vapi_register_msg(&__vapi_metadata_mactime_dump);
  VAPI_DBG("Assigned msg id %d to mactime_dump", vapi_msg_id_mactime_dump);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
