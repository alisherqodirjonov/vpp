#ifndef __included_mss_clamp_api_json
#define __included_mss_clamp_api_json

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

extern vapi_msg_id_t vapi_msg_id_mss_clamp_enable_disable;
extern vapi_msg_id_t vapi_msg_id_mss_clamp_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_mss_clamp_get;
extern vapi_msg_id_t vapi_msg_id_mss_clamp_get_reply;
extern vapi_msg_id_t vapi_msg_id_mss_clamp_details;

#define DEFINE_VAPI_MSG_IDS_MSS_CLAMP_API_JSON\
  vapi_msg_id_t vapi_msg_id_mss_clamp_enable_disable;\
  vapi_msg_id_t vapi_msg_id_mss_clamp_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_mss_clamp_get;\
  vapi_msg_id_t vapi_msg_id_mss_clamp_get_reply;\
  vapi_msg_id_t vapi_msg_id_mss_clamp_details;


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

#ifndef defined_vapi_enum_mss_clamp_dir
#define defined_vapi_enum_mss_clamp_dir
typedef enum {
  MSS_CLAMP_DIR_NONE = 0,
  MSS_CLAMP_DIR_RX = 1,
  MSS_CLAMP_DIR_TX = 2,
} __attribute__((packed)) vapi_enum_mss_clamp_dir;

#endif

#ifndef defined_vapi_type_interface_index
#define defined_vapi_type_interface_index
typedef u32 vapi_type_interface_index;

#endif

#ifndef defined_vapi_msg_mss_clamp_enable_disable_reply
#define defined_vapi_msg_mss_clamp_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_mss_clamp_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_mss_clamp_enable_disable_reply payload;
} vapi_msg_mss_clamp_enable_disable_reply;

static inline void vapi_msg_mss_clamp_enable_disable_reply_payload_hton(vapi_payload_mss_clamp_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_mss_clamp_enable_disable_reply_payload_ntoh(vapi_payload_mss_clamp_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_mss_clamp_enable_disable_reply_hton(vapi_msg_mss_clamp_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mss_clamp_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_mss_clamp_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_mss_clamp_enable_disable_reply_ntoh(vapi_msg_mss_clamp_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mss_clamp_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_mss_clamp_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_mss_clamp_enable_disable_reply_msg_size(vapi_msg_mss_clamp_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_mss_clamp_enable_disable_reply_msg_size(vapi_msg_mss_clamp_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_mss_clamp_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'mss_clamp_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_mss_clamp_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_mss_clamp_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'mss_clamp_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_mss_clamp_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_mss_clamp_enable_disable_reply()
{
  static const char name[] = "mss_clamp_enable_disable_reply";
  static const char name_with_crc[] = "mss_clamp_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_mss_clamp_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_mss_clamp_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_mss_clamp_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_mss_clamp_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_mss_clamp_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_mss_clamp_enable_disable_reply = vapi_register_msg(&__vapi_metadata_mss_clamp_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to mss_clamp_enable_disable_reply", vapi_msg_id_mss_clamp_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_mss_clamp_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_mss_clamp_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_mss_clamp_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_mss_clamp_enable_disable
#define defined_vapi_msg_mss_clamp_enable_disable
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u16 ipv4_mss;
  u16 ipv6_mss;
  vapi_enum_mss_clamp_dir ipv4_direction;
  vapi_enum_mss_clamp_dir ipv6_direction; 
} vapi_payload_mss_clamp_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_mss_clamp_enable_disable payload;
} vapi_msg_mss_clamp_enable_disable;

static inline void vapi_msg_mss_clamp_enable_disable_payload_hton(vapi_payload_mss_clamp_enable_disable *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->ipv4_mss = htobe16(payload->ipv4_mss);
  payload->ipv6_mss = htobe16(payload->ipv6_mss);
}

static inline void vapi_msg_mss_clamp_enable_disable_payload_ntoh(vapi_payload_mss_clamp_enable_disable *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->ipv4_mss = be16toh(payload->ipv4_mss);
  payload->ipv6_mss = be16toh(payload->ipv6_mss);
}

static inline void vapi_msg_mss_clamp_enable_disable_hton(vapi_msg_mss_clamp_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mss_clamp_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_mss_clamp_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_mss_clamp_enable_disable_ntoh(vapi_msg_mss_clamp_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mss_clamp_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_mss_clamp_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_mss_clamp_enable_disable_msg_size(vapi_msg_mss_clamp_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_mss_clamp_enable_disable_msg_size(vapi_msg_mss_clamp_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_mss_clamp_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'mss_clamp_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_mss_clamp_enable_disable));
      return -1;
    }
  if (vapi_calc_mss_clamp_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'mss_clamp_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_mss_clamp_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_mss_clamp_enable_disable* vapi_alloc_mss_clamp_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_mss_clamp_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_mss_clamp_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_mss_clamp_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_mss_clamp_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_mss_clamp_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_mss_clamp_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_mss_clamp_enable_disable_reply *reply),
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
  vapi_msg_mss_clamp_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_mss_clamp_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_mss_clamp_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_mss_clamp_enable_disable()
{
  static const char name[] = "mss_clamp_enable_disable";
  static const char name_with_crc[] = "mss_clamp_enable_disable_d31b44e3";
  static vapi_message_desc_t __vapi_metadata_mss_clamp_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_mss_clamp_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_mss_clamp_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_mss_clamp_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_mss_clamp_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_mss_clamp_enable_disable = vapi_register_msg(&__vapi_metadata_mss_clamp_enable_disable);
  VAPI_DBG("Assigned msg id %d to mss_clamp_enable_disable", vapi_msg_id_mss_clamp_enable_disable);
}
#endif

#ifndef defined_vapi_msg_mss_clamp_get_reply
#define defined_vapi_msg_mss_clamp_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 cursor; 
} vapi_payload_mss_clamp_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_mss_clamp_get_reply payload;
} vapi_msg_mss_clamp_get_reply;

static inline void vapi_msg_mss_clamp_get_reply_payload_hton(vapi_payload_mss_clamp_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_mss_clamp_get_reply_payload_ntoh(vapi_payload_mss_clamp_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_mss_clamp_get_reply_hton(vapi_msg_mss_clamp_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mss_clamp_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_mss_clamp_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_mss_clamp_get_reply_ntoh(vapi_msg_mss_clamp_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mss_clamp_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_mss_clamp_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_mss_clamp_get_reply_msg_size(vapi_msg_mss_clamp_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_mss_clamp_get_reply_msg_size(vapi_msg_mss_clamp_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_mss_clamp_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'mss_clamp_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_mss_clamp_get_reply));
      return -1;
    }
  if (vapi_calc_mss_clamp_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'mss_clamp_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_mss_clamp_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_mss_clamp_get_reply()
{
  static const char name[] = "mss_clamp_get_reply";
  static const char name_with_crc[] = "mss_clamp_get_reply_53b48f5d";
  static vapi_message_desc_t __vapi_metadata_mss_clamp_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_mss_clamp_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_mss_clamp_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_mss_clamp_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_mss_clamp_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_mss_clamp_get_reply = vapi_register_msg(&__vapi_metadata_mss_clamp_get_reply);
  VAPI_DBG("Assigned msg id %d to mss_clamp_get_reply", vapi_msg_id_mss_clamp_get_reply);
}

static inline void vapi_set_vapi_msg_mss_clamp_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_mss_clamp_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_mss_clamp_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_mss_clamp_details
#define defined_vapi_msg_mss_clamp_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u16 ipv4_mss;
  u16 ipv6_mss;
  vapi_enum_mss_clamp_dir ipv4_direction;
  vapi_enum_mss_clamp_dir ipv6_direction; 
} vapi_payload_mss_clamp_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_mss_clamp_details payload;
} vapi_msg_mss_clamp_details;

static inline void vapi_msg_mss_clamp_details_payload_hton(vapi_payload_mss_clamp_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->ipv4_mss = htobe16(payload->ipv4_mss);
  payload->ipv6_mss = htobe16(payload->ipv6_mss);
}

static inline void vapi_msg_mss_clamp_details_payload_ntoh(vapi_payload_mss_clamp_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->ipv4_mss = be16toh(payload->ipv4_mss);
  payload->ipv6_mss = be16toh(payload->ipv6_mss);
}

static inline void vapi_msg_mss_clamp_details_hton(vapi_msg_mss_clamp_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mss_clamp_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_mss_clamp_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_mss_clamp_details_ntoh(vapi_msg_mss_clamp_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mss_clamp_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_mss_clamp_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_mss_clamp_details_msg_size(vapi_msg_mss_clamp_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_mss_clamp_details_msg_size(vapi_msg_mss_clamp_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_mss_clamp_details) > buf_size)
    {
      VAPI_ERR("Truncated 'mss_clamp_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_mss_clamp_details));
      return -1;
    }
  if (vapi_calc_mss_clamp_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'mss_clamp_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_mss_clamp_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_mss_clamp_details()
{
  static const char name[] = "mss_clamp_details";
  static const char name_with_crc[] = "mss_clamp_details_d3a4de61";
  static vapi_message_desc_t __vapi_metadata_mss_clamp_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_mss_clamp_details, payload),
    (verify_msg_size_fn_t)vapi_verify_mss_clamp_details_msg_size,
    (generic_swap_fn_t)vapi_msg_mss_clamp_details_hton,
    (generic_swap_fn_t)vapi_msg_mss_clamp_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_mss_clamp_details = vapi_register_msg(&__vapi_metadata_mss_clamp_details);
  VAPI_DBG("Assigned msg id %d to mss_clamp_details", vapi_msg_id_mss_clamp_details);
}
#endif

#ifndef defined_vapi_msg_mss_clamp_get
#define defined_vapi_msg_mss_clamp_get
typedef struct __attribute__ ((__packed__)) {
  u32 cursor;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_mss_clamp_get;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_mss_clamp_get payload;
} vapi_msg_mss_clamp_get;

static inline void vapi_msg_mss_clamp_get_payload_hton(vapi_payload_mss_clamp_get *payload)
{
  payload->cursor = htobe32(payload->cursor);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_mss_clamp_get_payload_ntoh(vapi_payload_mss_clamp_get *payload)
{
  payload->cursor = be32toh(payload->cursor);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_mss_clamp_get_hton(vapi_msg_mss_clamp_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mss_clamp_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_mss_clamp_get_payload_hton(&msg->payload);
}

static inline void vapi_msg_mss_clamp_get_ntoh(vapi_msg_mss_clamp_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_mss_clamp_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_mss_clamp_get_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_mss_clamp_get_msg_size(vapi_msg_mss_clamp_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_mss_clamp_get_msg_size(vapi_msg_mss_clamp_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_mss_clamp_get) > buf_size)
    {
      VAPI_ERR("Truncated 'mss_clamp_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_mss_clamp_get));
      return -1;
    }
  if (vapi_calc_mss_clamp_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'mss_clamp_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_mss_clamp_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_mss_clamp_get* vapi_alloc_mss_clamp_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_mss_clamp_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_mss_clamp_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_mss_clamp_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_mss_clamp_get);

  return msg;
}

static inline vapi_error_e vapi_mss_clamp_get(struct vapi_ctx_s *ctx,
  vapi_msg_mss_clamp_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_mss_clamp_get_reply *reply),
  void *reply_callback_ctx,
  vapi_error_e (*details_callback)(struct vapi_ctx_s *ctx,
                                   void *callback_ctx,
                                   vapi_error_e rv,
                                   bool is_last,
                                   vapi_payload_mss_clamp_details *details),
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
  vapi_msg_mss_clamp_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_mss_clamp_details, VAPI_REQUEST_STREAM, 
                       (vapi_cb_t)details_callback, details_callback_ctx);
    vapi_store_request(ctx, req_context, vapi_msg_id_mss_clamp_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_mss_clamp_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_mss_clamp_get()
{
  static const char name[] = "mss_clamp_get";
  static const char name_with_crc[] = "mss_clamp_get_47250981";
  static vapi_message_desc_t __vapi_metadata_mss_clamp_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_mss_clamp_get, payload),
    (verify_msg_size_fn_t)vapi_verify_mss_clamp_get_msg_size,
    (generic_swap_fn_t)vapi_msg_mss_clamp_get_hton,
    (generic_swap_fn_t)vapi_msg_mss_clamp_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_mss_clamp_get = vapi_register_msg(&__vapi_metadata_mss_clamp_get);
  VAPI_DBG("Assigned msg id %d to mss_clamp_get", vapi_msg_id_mss_clamp_get);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
