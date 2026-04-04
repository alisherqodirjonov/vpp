#ifndef __included_policer_api_json
#define __included_policer_api_json

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

extern vapi_msg_id_t vapi_msg_id_policer_bind;
extern vapi_msg_id_t vapi_msg_id_policer_bind_reply;
extern vapi_msg_id_t vapi_msg_id_policer_bind_v2;
extern vapi_msg_id_t vapi_msg_id_policer_bind_v2_reply;
extern vapi_msg_id_t vapi_msg_id_policer_input;
extern vapi_msg_id_t vapi_msg_id_policer_input_reply;
extern vapi_msg_id_t vapi_msg_id_policer_input_v2;
extern vapi_msg_id_t vapi_msg_id_policer_input_v2_reply;
extern vapi_msg_id_t vapi_msg_id_policer_output;
extern vapi_msg_id_t vapi_msg_id_policer_output_reply;
extern vapi_msg_id_t vapi_msg_id_policer_output_v2;
extern vapi_msg_id_t vapi_msg_id_policer_output_v2_reply;
extern vapi_msg_id_t vapi_msg_id_policer_add_del;
extern vapi_msg_id_t vapi_msg_id_policer_add;
extern vapi_msg_id_t vapi_msg_id_policer_del;
extern vapi_msg_id_t vapi_msg_id_policer_del_reply;
extern vapi_msg_id_t vapi_msg_id_policer_update;
extern vapi_msg_id_t vapi_msg_id_policer_update_reply;
extern vapi_msg_id_t vapi_msg_id_policer_reset;
extern vapi_msg_id_t vapi_msg_id_policer_reset_reply;
extern vapi_msg_id_t vapi_msg_id_policer_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_policer_add_reply;
extern vapi_msg_id_t vapi_msg_id_policer_dump;
extern vapi_msg_id_t vapi_msg_id_policer_dump_v2;
extern vapi_msg_id_t vapi_msg_id_policer_details;

#define DEFINE_VAPI_MSG_IDS_POLICER_API_JSON\
  vapi_msg_id_t vapi_msg_id_policer_bind;\
  vapi_msg_id_t vapi_msg_id_policer_bind_reply;\
  vapi_msg_id_t vapi_msg_id_policer_bind_v2;\
  vapi_msg_id_t vapi_msg_id_policer_bind_v2_reply;\
  vapi_msg_id_t vapi_msg_id_policer_input;\
  vapi_msg_id_t vapi_msg_id_policer_input_reply;\
  vapi_msg_id_t vapi_msg_id_policer_input_v2;\
  vapi_msg_id_t vapi_msg_id_policer_input_v2_reply;\
  vapi_msg_id_t vapi_msg_id_policer_output;\
  vapi_msg_id_t vapi_msg_id_policer_output_reply;\
  vapi_msg_id_t vapi_msg_id_policer_output_v2;\
  vapi_msg_id_t vapi_msg_id_policer_output_v2_reply;\
  vapi_msg_id_t vapi_msg_id_policer_add_del;\
  vapi_msg_id_t vapi_msg_id_policer_add;\
  vapi_msg_id_t vapi_msg_id_policer_del;\
  vapi_msg_id_t vapi_msg_id_policer_del_reply;\
  vapi_msg_id_t vapi_msg_id_policer_update;\
  vapi_msg_id_t vapi_msg_id_policer_update_reply;\
  vapi_msg_id_t vapi_msg_id_policer_reset;\
  vapi_msg_id_t vapi_msg_id_policer_reset_reply;\
  vapi_msg_id_t vapi_msg_id_policer_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_policer_add_reply;\
  vapi_msg_id_t vapi_msg_id_policer_dump;\
  vapi_msg_id_t vapi_msg_id_policer_dump_v2;\
  vapi_msg_id_t vapi_msg_id_policer_details;


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

#ifndef defined_vapi_enum_sse2_qos_rate_type
#define defined_vapi_enum_sse2_qos_rate_type
typedef enum {
  SSE2_QOS_RATE_API_KBPS = 0,
  SSE2_QOS_RATE_API_PPS = 1,
  SSE2_QOS_RATE_API_INVALID = 2,
} __attribute__((packed)) vapi_enum_sse2_qos_rate_type;

#endif

#ifndef defined_vapi_enum_sse2_qos_round_type
#define defined_vapi_enum_sse2_qos_round_type
typedef enum {
  SSE2_QOS_ROUND_API_TO_CLOSEST = 0,
  SSE2_QOS_ROUND_API_TO_UP = 1,
  SSE2_QOS_ROUND_API_TO_DOWN = 2,
  SSE2_QOS_ROUND_API_INVALID = 3,
} __attribute__((packed)) vapi_enum_sse2_qos_round_type;

#endif

#ifndef defined_vapi_enum_sse2_qos_policer_type
#define defined_vapi_enum_sse2_qos_policer_type
typedef enum {
  SSE2_QOS_POLICER_TYPE_API_1R2C = 0,
  SSE2_QOS_POLICER_TYPE_API_1R3C_RFC_2697 = 1,
  SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_2698 = 2,
  SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_4115 = 3,
  SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_MEF5CF1 = 4,
  SSE2_QOS_POLICER_TYPE_API_MAX = 5,
} __attribute__((packed)) vapi_enum_sse2_qos_policer_type;

#endif

#ifndef defined_vapi_enum_sse2_qos_action_type
#define defined_vapi_enum_sse2_qos_action_type
typedef enum {
  SSE2_QOS_ACTION_API_DROP = 0,
  SSE2_QOS_ACTION_API_TRANSMIT = 1,
  SSE2_QOS_ACTION_API_MARK_AND_TRANSMIT = 2,
} __attribute__((packed)) vapi_enum_sse2_qos_action_type;

#endif

#ifndef defined_vapi_type_sse2_qos_action
#define defined_vapi_type_sse2_qos_action
typedef struct __attribute__((__packed__)) {
  vapi_enum_sse2_qos_action_type type;
  u8 dscp;
} vapi_type_sse2_qos_action;

static inline void vapi_type_sse2_qos_action_hton(vapi_type_sse2_qos_action *msg)
{

}

static inline void vapi_type_sse2_qos_action_ntoh(vapi_type_sse2_qos_action *msg)
{

}
#endif

#ifndef defined_vapi_type_policer_config
#define defined_vapi_type_policer_config
typedef struct __attribute__((__packed__)) {
  u32 cir;
  u32 eir;
  u64 cb;
  u64 eb;
  vapi_enum_sse2_qos_rate_type rate_type;
  vapi_enum_sse2_qos_round_type round_type;
  vapi_enum_sse2_qos_policer_type type;
  bool color_aware;
  vapi_type_sse2_qos_action conform_action;
  vapi_type_sse2_qos_action exceed_action;
  vapi_type_sse2_qos_action violate_action;
} vapi_type_policer_config;

static inline void vapi_type_policer_config_hton(vapi_type_policer_config *msg)
{
  msg->cir = htobe32(msg->cir);
  msg->eir = htobe32(msg->eir);
  msg->cb = htobe64(msg->cb);
  msg->eb = htobe64(msg->eb);
}

static inline void vapi_type_policer_config_ntoh(vapi_type_policer_config *msg)
{
  msg->cir = be32toh(msg->cir);
  msg->eir = be32toh(msg->eir);
  msg->cb = be64toh(msg->cb);
  msg->eb = be64toh(msg->eb);
}
#endif

#ifndef defined_vapi_type_interface_index
#define defined_vapi_type_interface_index
typedef u32 vapi_type_interface_index;

#endif

#ifndef defined_vapi_msg_policer_bind_reply
#define defined_vapi_msg_policer_bind_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_policer_bind_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_policer_bind_reply payload;
} vapi_msg_policer_bind_reply;

static inline void vapi_msg_policer_bind_reply_payload_hton(vapi_payload_policer_bind_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_policer_bind_reply_payload_ntoh(vapi_payload_policer_bind_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_policer_bind_reply_hton(vapi_msg_policer_bind_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_bind_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_policer_bind_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_bind_reply_ntoh(vapi_msg_policer_bind_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_bind_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_policer_bind_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_bind_reply_msg_size(vapi_msg_policer_bind_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_bind_reply_msg_size(vapi_msg_policer_bind_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_bind_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_bind_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_bind_reply));
      return -1;
    }
  if (vapi_calc_policer_bind_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_bind_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_bind_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_policer_bind_reply()
{
  static const char name[] = "policer_bind_reply";
  static const char name_with_crc[] = "policer_bind_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_policer_bind_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_policer_bind_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_bind_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_bind_reply_hton,
    (generic_swap_fn_t)vapi_msg_policer_bind_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_bind_reply = vapi_register_msg(&__vapi_metadata_policer_bind_reply);
  VAPI_DBG("Assigned msg id %d to policer_bind_reply", vapi_msg_id_policer_bind_reply);
}

static inline void vapi_set_vapi_msg_policer_bind_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_policer_bind_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_policer_bind_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_policer_bind
#define defined_vapi_msg_policer_bind
typedef struct __attribute__ ((__packed__)) {
  u8 name[64];
  u32 worker_index;
  bool bind_enable; 
} vapi_payload_policer_bind;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_policer_bind payload;
} vapi_msg_policer_bind;

static inline void vapi_msg_policer_bind_payload_hton(vapi_payload_policer_bind *payload)
{
  payload->worker_index = htobe32(payload->worker_index);
}

static inline void vapi_msg_policer_bind_payload_ntoh(vapi_payload_policer_bind *payload)
{
  payload->worker_index = be32toh(payload->worker_index);
}

static inline void vapi_msg_policer_bind_hton(vapi_msg_policer_bind *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_bind'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_policer_bind_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_bind_ntoh(vapi_msg_policer_bind *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_bind'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_policer_bind_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_bind_msg_size(vapi_msg_policer_bind *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_bind_msg_size(vapi_msg_policer_bind *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_bind) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_bind' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_bind));
      return -1;
    }
  if (vapi_calc_policer_bind_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_bind' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_bind_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_policer_bind* vapi_alloc_policer_bind(struct vapi_ctx_s *ctx)
{
  vapi_msg_policer_bind *msg = NULL;
  const size_t size = sizeof(vapi_msg_policer_bind);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_policer_bind*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_policer_bind);

  return msg;
}

static inline vapi_error_e vapi_policer_bind(struct vapi_ctx_s *ctx,
  vapi_msg_policer_bind *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_policer_bind_reply *reply),
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
  vapi_msg_policer_bind_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_policer_bind_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_policer_bind_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_policer_bind()
{
  static const char name[] = "policer_bind";
  static const char name_with_crc[] = "policer_bind_dcf516f9";
  static vapi_message_desc_t __vapi_metadata_policer_bind = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_policer_bind, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_bind_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_bind_hton,
    (generic_swap_fn_t)vapi_msg_policer_bind_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_bind = vapi_register_msg(&__vapi_metadata_policer_bind);
  VAPI_DBG("Assigned msg id %d to policer_bind", vapi_msg_id_policer_bind);
}
#endif

#ifndef defined_vapi_msg_policer_bind_v2_reply
#define defined_vapi_msg_policer_bind_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_policer_bind_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_policer_bind_v2_reply payload;
} vapi_msg_policer_bind_v2_reply;

static inline void vapi_msg_policer_bind_v2_reply_payload_hton(vapi_payload_policer_bind_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_policer_bind_v2_reply_payload_ntoh(vapi_payload_policer_bind_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_policer_bind_v2_reply_hton(vapi_msg_policer_bind_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_bind_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_policer_bind_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_bind_v2_reply_ntoh(vapi_msg_policer_bind_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_bind_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_policer_bind_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_bind_v2_reply_msg_size(vapi_msg_policer_bind_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_bind_v2_reply_msg_size(vapi_msg_policer_bind_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_bind_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_bind_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_bind_v2_reply));
      return -1;
    }
  if (vapi_calc_policer_bind_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_bind_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_bind_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_policer_bind_v2_reply()
{
  static const char name[] = "policer_bind_v2_reply";
  static const char name_with_crc[] = "policer_bind_v2_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_policer_bind_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_policer_bind_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_bind_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_bind_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_policer_bind_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_bind_v2_reply = vapi_register_msg(&__vapi_metadata_policer_bind_v2_reply);
  VAPI_DBG("Assigned msg id %d to policer_bind_v2_reply", vapi_msg_id_policer_bind_v2_reply);
}

static inline void vapi_set_vapi_msg_policer_bind_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_policer_bind_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_policer_bind_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_policer_bind_v2
#define defined_vapi_msg_policer_bind_v2
typedef struct __attribute__ ((__packed__)) {
  u32 policer_index;
  u32 worker_index;
  bool bind_enable; 
} vapi_payload_policer_bind_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_policer_bind_v2 payload;
} vapi_msg_policer_bind_v2;

static inline void vapi_msg_policer_bind_v2_payload_hton(vapi_payload_policer_bind_v2 *payload)
{
  payload->policer_index = htobe32(payload->policer_index);
  payload->worker_index = htobe32(payload->worker_index);
}

static inline void vapi_msg_policer_bind_v2_payload_ntoh(vapi_payload_policer_bind_v2 *payload)
{
  payload->policer_index = be32toh(payload->policer_index);
  payload->worker_index = be32toh(payload->worker_index);
}

static inline void vapi_msg_policer_bind_v2_hton(vapi_msg_policer_bind_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_bind_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_policer_bind_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_bind_v2_ntoh(vapi_msg_policer_bind_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_bind_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_policer_bind_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_bind_v2_msg_size(vapi_msg_policer_bind_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_bind_v2_msg_size(vapi_msg_policer_bind_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_bind_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_bind_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_bind_v2));
      return -1;
    }
  if (vapi_calc_policer_bind_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_bind_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_bind_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_policer_bind_v2* vapi_alloc_policer_bind_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_policer_bind_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_policer_bind_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_policer_bind_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_policer_bind_v2);

  return msg;
}

static inline vapi_error_e vapi_policer_bind_v2(struct vapi_ctx_s *ctx,
  vapi_msg_policer_bind_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_policer_bind_v2_reply *reply),
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
  vapi_msg_policer_bind_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_policer_bind_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_policer_bind_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_policer_bind_v2()
{
  static const char name[] = "policer_bind_v2";
  static const char name_with_crc[] = "policer_bind_v2_f87bd3c0";
  static vapi_message_desc_t __vapi_metadata_policer_bind_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_policer_bind_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_bind_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_bind_v2_hton,
    (generic_swap_fn_t)vapi_msg_policer_bind_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_bind_v2 = vapi_register_msg(&__vapi_metadata_policer_bind_v2);
  VAPI_DBG("Assigned msg id %d to policer_bind_v2", vapi_msg_id_policer_bind_v2);
}
#endif

#ifndef defined_vapi_msg_policer_input_reply
#define defined_vapi_msg_policer_input_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_policer_input_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_policer_input_reply payload;
} vapi_msg_policer_input_reply;

static inline void vapi_msg_policer_input_reply_payload_hton(vapi_payload_policer_input_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_policer_input_reply_payload_ntoh(vapi_payload_policer_input_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_policer_input_reply_hton(vapi_msg_policer_input_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_input_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_policer_input_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_input_reply_ntoh(vapi_msg_policer_input_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_input_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_policer_input_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_input_reply_msg_size(vapi_msg_policer_input_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_input_reply_msg_size(vapi_msg_policer_input_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_input_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_input_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_input_reply));
      return -1;
    }
  if (vapi_calc_policer_input_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_input_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_input_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_policer_input_reply()
{
  static const char name[] = "policer_input_reply";
  static const char name_with_crc[] = "policer_input_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_policer_input_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_policer_input_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_input_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_input_reply_hton,
    (generic_swap_fn_t)vapi_msg_policer_input_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_input_reply = vapi_register_msg(&__vapi_metadata_policer_input_reply);
  VAPI_DBG("Assigned msg id %d to policer_input_reply", vapi_msg_id_policer_input_reply);
}

static inline void vapi_set_vapi_msg_policer_input_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_policer_input_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_policer_input_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_policer_input
#define defined_vapi_msg_policer_input
typedef struct __attribute__ ((__packed__)) {
  u8 name[64];
  vapi_type_interface_index sw_if_index;
  bool apply; 
} vapi_payload_policer_input;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_policer_input payload;
} vapi_msg_policer_input;

static inline void vapi_msg_policer_input_payload_hton(vapi_payload_policer_input *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_policer_input_payload_ntoh(vapi_payload_policer_input *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_policer_input_hton(vapi_msg_policer_input *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_input'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_policer_input_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_input_ntoh(vapi_msg_policer_input *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_input'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_policer_input_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_input_msg_size(vapi_msg_policer_input *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_input_msg_size(vapi_msg_policer_input *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_input) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_input' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_input));
      return -1;
    }
  if (vapi_calc_policer_input_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_input' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_input_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_policer_input* vapi_alloc_policer_input(struct vapi_ctx_s *ctx)
{
  vapi_msg_policer_input *msg = NULL;
  const size_t size = sizeof(vapi_msg_policer_input);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_policer_input*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_policer_input);

  return msg;
}

static inline vapi_error_e vapi_policer_input(struct vapi_ctx_s *ctx,
  vapi_msg_policer_input *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_policer_input_reply *reply),
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
  vapi_msg_policer_input_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_policer_input_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_policer_input_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_policer_input()
{
  static const char name[] = "policer_input";
  static const char name_with_crc[] = "policer_input_233f0ef5";
  static vapi_message_desc_t __vapi_metadata_policer_input = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_policer_input, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_input_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_input_hton,
    (generic_swap_fn_t)vapi_msg_policer_input_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_input = vapi_register_msg(&__vapi_metadata_policer_input);
  VAPI_DBG("Assigned msg id %d to policer_input", vapi_msg_id_policer_input);
}
#endif

#ifndef defined_vapi_msg_policer_input_v2_reply
#define defined_vapi_msg_policer_input_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_policer_input_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_policer_input_v2_reply payload;
} vapi_msg_policer_input_v2_reply;

static inline void vapi_msg_policer_input_v2_reply_payload_hton(vapi_payload_policer_input_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_policer_input_v2_reply_payload_ntoh(vapi_payload_policer_input_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_policer_input_v2_reply_hton(vapi_msg_policer_input_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_input_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_policer_input_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_input_v2_reply_ntoh(vapi_msg_policer_input_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_input_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_policer_input_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_input_v2_reply_msg_size(vapi_msg_policer_input_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_input_v2_reply_msg_size(vapi_msg_policer_input_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_input_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_input_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_input_v2_reply));
      return -1;
    }
  if (vapi_calc_policer_input_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_input_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_input_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_policer_input_v2_reply()
{
  static const char name[] = "policer_input_v2_reply";
  static const char name_with_crc[] = "policer_input_v2_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_policer_input_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_policer_input_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_input_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_input_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_policer_input_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_input_v2_reply = vapi_register_msg(&__vapi_metadata_policer_input_v2_reply);
  VAPI_DBG("Assigned msg id %d to policer_input_v2_reply", vapi_msg_id_policer_input_v2_reply);
}

static inline void vapi_set_vapi_msg_policer_input_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_policer_input_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_policer_input_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_policer_input_v2
#define defined_vapi_msg_policer_input_v2
typedef struct __attribute__ ((__packed__)) {
  u32 policer_index;
  vapi_type_interface_index sw_if_index;
  bool apply; 
} vapi_payload_policer_input_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_policer_input_v2 payload;
} vapi_msg_policer_input_v2;

static inline void vapi_msg_policer_input_v2_payload_hton(vapi_payload_policer_input_v2 *payload)
{
  payload->policer_index = htobe32(payload->policer_index);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_policer_input_v2_payload_ntoh(vapi_payload_policer_input_v2 *payload)
{
  payload->policer_index = be32toh(payload->policer_index);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_policer_input_v2_hton(vapi_msg_policer_input_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_input_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_policer_input_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_input_v2_ntoh(vapi_msg_policer_input_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_input_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_policer_input_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_input_v2_msg_size(vapi_msg_policer_input_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_input_v2_msg_size(vapi_msg_policer_input_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_input_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_input_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_input_v2));
      return -1;
    }
  if (vapi_calc_policer_input_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_input_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_input_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_policer_input_v2* vapi_alloc_policer_input_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_policer_input_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_policer_input_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_policer_input_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_policer_input_v2);

  return msg;
}

static inline vapi_error_e vapi_policer_input_v2(struct vapi_ctx_s *ctx,
  vapi_msg_policer_input_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_policer_input_v2_reply *reply),
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
  vapi_msg_policer_input_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_policer_input_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_policer_input_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_policer_input_v2()
{
  static const char name[] = "policer_input_v2";
  static const char name_with_crc[] = "policer_input_v2_8388eb84";
  static vapi_message_desc_t __vapi_metadata_policer_input_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_policer_input_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_input_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_input_v2_hton,
    (generic_swap_fn_t)vapi_msg_policer_input_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_input_v2 = vapi_register_msg(&__vapi_metadata_policer_input_v2);
  VAPI_DBG("Assigned msg id %d to policer_input_v2", vapi_msg_id_policer_input_v2);
}
#endif

#ifndef defined_vapi_msg_policer_output_reply
#define defined_vapi_msg_policer_output_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_policer_output_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_policer_output_reply payload;
} vapi_msg_policer_output_reply;

static inline void vapi_msg_policer_output_reply_payload_hton(vapi_payload_policer_output_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_policer_output_reply_payload_ntoh(vapi_payload_policer_output_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_policer_output_reply_hton(vapi_msg_policer_output_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_output_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_policer_output_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_output_reply_ntoh(vapi_msg_policer_output_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_output_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_policer_output_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_output_reply_msg_size(vapi_msg_policer_output_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_output_reply_msg_size(vapi_msg_policer_output_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_output_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_output_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_output_reply));
      return -1;
    }
  if (vapi_calc_policer_output_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_output_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_output_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_policer_output_reply()
{
  static const char name[] = "policer_output_reply";
  static const char name_with_crc[] = "policer_output_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_policer_output_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_policer_output_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_output_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_output_reply_hton,
    (generic_swap_fn_t)vapi_msg_policer_output_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_output_reply = vapi_register_msg(&__vapi_metadata_policer_output_reply);
  VAPI_DBG("Assigned msg id %d to policer_output_reply", vapi_msg_id_policer_output_reply);
}

static inline void vapi_set_vapi_msg_policer_output_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_policer_output_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_policer_output_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_policer_output
#define defined_vapi_msg_policer_output
typedef struct __attribute__ ((__packed__)) {
  u8 name[64];
  vapi_type_interface_index sw_if_index;
  bool apply; 
} vapi_payload_policer_output;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_policer_output payload;
} vapi_msg_policer_output;

static inline void vapi_msg_policer_output_payload_hton(vapi_payload_policer_output *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_policer_output_payload_ntoh(vapi_payload_policer_output *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_policer_output_hton(vapi_msg_policer_output *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_output'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_policer_output_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_output_ntoh(vapi_msg_policer_output *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_output'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_policer_output_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_output_msg_size(vapi_msg_policer_output *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_output_msg_size(vapi_msg_policer_output *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_output) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_output' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_output));
      return -1;
    }
  if (vapi_calc_policer_output_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_output' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_output_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_policer_output* vapi_alloc_policer_output(struct vapi_ctx_s *ctx)
{
  vapi_msg_policer_output *msg = NULL;
  const size_t size = sizeof(vapi_msg_policer_output);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_policer_output*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_policer_output);

  return msg;
}

static inline vapi_error_e vapi_policer_output(struct vapi_ctx_s *ctx,
  vapi_msg_policer_output *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_policer_output_reply *reply),
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
  vapi_msg_policer_output_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_policer_output_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_policer_output_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_policer_output()
{
  static const char name[] = "policer_output";
  static const char name_with_crc[] = "policer_output_233f0ef5";
  static vapi_message_desc_t __vapi_metadata_policer_output = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_policer_output, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_output_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_output_hton,
    (generic_swap_fn_t)vapi_msg_policer_output_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_output = vapi_register_msg(&__vapi_metadata_policer_output);
  VAPI_DBG("Assigned msg id %d to policer_output", vapi_msg_id_policer_output);
}
#endif

#ifndef defined_vapi_msg_policer_output_v2_reply
#define defined_vapi_msg_policer_output_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_policer_output_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_policer_output_v2_reply payload;
} vapi_msg_policer_output_v2_reply;

static inline void vapi_msg_policer_output_v2_reply_payload_hton(vapi_payload_policer_output_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_policer_output_v2_reply_payload_ntoh(vapi_payload_policer_output_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_policer_output_v2_reply_hton(vapi_msg_policer_output_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_output_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_policer_output_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_output_v2_reply_ntoh(vapi_msg_policer_output_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_output_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_policer_output_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_output_v2_reply_msg_size(vapi_msg_policer_output_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_output_v2_reply_msg_size(vapi_msg_policer_output_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_output_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_output_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_output_v2_reply));
      return -1;
    }
  if (vapi_calc_policer_output_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_output_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_output_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_policer_output_v2_reply()
{
  static const char name[] = "policer_output_v2_reply";
  static const char name_with_crc[] = "policer_output_v2_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_policer_output_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_policer_output_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_output_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_output_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_policer_output_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_output_v2_reply = vapi_register_msg(&__vapi_metadata_policer_output_v2_reply);
  VAPI_DBG("Assigned msg id %d to policer_output_v2_reply", vapi_msg_id_policer_output_v2_reply);
}

static inline void vapi_set_vapi_msg_policer_output_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_policer_output_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_policer_output_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_policer_output_v2
#define defined_vapi_msg_policer_output_v2
typedef struct __attribute__ ((__packed__)) {
  u32 policer_index;
  vapi_type_interface_index sw_if_index;
  bool apply; 
} vapi_payload_policer_output_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_policer_output_v2 payload;
} vapi_msg_policer_output_v2;

static inline void vapi_msg_policer_output_v2_payload_hton(vapi_payload_policer_output_v2 *payload)
{
  payload->policer_index = htobe32(payload->policer_index);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_policer_output_v2_payload_ntoh(vapi_payload_policer_output_v2 *payload)
{
  payload->policer_index = be32toh(payload->policer_index);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_policer_output_v2_hton(vapi_msg_policer_output_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_output_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_policer_output_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_output_v2_ntoh(vapi_msg_policer_output_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_output_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_policer_output_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_output_v2_msg_size(vapi_msg_policer_output_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_output_v2_msg_size(vapi_msg_policer_output_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_output_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_output_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_output_v2));
      return -1;
    }
  if (vapi_calc_policer_output_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_output_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_output_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_policer_output_v2* vapi_alloc_policer_output_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_policer_output_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_policer_output_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_policer_output_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_policer_output_v2);

  return msg;
}

static inline vapi_error_e vapi_policer_output_v2(struct vapi_ctx_s *ctx,
  vapi_msg_policer_output_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_policer_output_v2_reply *reply),
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
  vapi_msg_policer_output_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_policer_output_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_policer_output_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_policer_output_v2()
{
  static const char name[] = "policer_output_v2";
  static const char name_with_crc[] = "policer_output_v2_8388eb84";
  static vapi_message_desc_t __vapi_metadata_policer_output_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_policer_output_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_output_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_output_v2_hton,
    (generic_swap_fn_t)vapi_msg_policer_output_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_output_v2 = vapi_register_msg(&__vapi_metadata_policer_output_v2);
  VAPI_DBG("Assigned msg id %d to policer_output_v2", vapi_msg_id_policer_output_v2);
}
#endif

#ifndef defined_vapi_msg_policer_add_del_reply
#define defined_vapi_msg_policer_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 policer_index; 
} vapi_payload_policer_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_policer_add_del_reply payload;
} vapi_msg_policer_add_del_reply;

static inline void vapi_msg_policer_add_del_reply_payload_hton(vapi_payload_policer_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->policer_index = htobe32(payload->policer_index);
}

static inline void vapi_msg_policer_add_del_reply_payload_ntoh(vapi_payload_policer_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->policer_index = be32toh(payload->policer_index);
}

static inline void vapi_msg_policer_add_del_reply_hton(vapi_msg_policer_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_policer_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_add_del_reply_ntoh(vapi_msg_policer_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_policer_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_add_del_reply_msg_size(vapi_msg_policer_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_add_del_reply_msg_size(vapi_msg_policer_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_add_del_reply));
      return -1;
    }
  if (vapi_calc_policer_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_policer_add_del_reply()
{
  static const char name[] = "policer_add_del_reply";
  static const char name_with_crc[] = "policer_add_del_reply_a177cef2";
  static vapi_message_desc_t __vapi_metadata_policer_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_policer_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_policer_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_add_del_reply = vapi_register_msg(&__vapi_metadata_policer_add_del_reply);
  VAPI_DBG("Assigned msg id %d to policer_add_del_reply", vapi_msg_id_policer_add_del_reply);
}

static inline void vapi_set_vapi_msg_policer_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_policer_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_policer_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_policer_add_del
#define defined_vapi_msg_policer_add_del
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  u8 name[64];
  u32 cir;
  u32 eir;
  u64 cb;
  u64 eb;
  vapi_enum_sse2_qos_rate_type rate_type;
  vapi_enum_sse2_qos_round_type round_type;
  vapi_enum_sse2_qos_policer_type type;
  bool color_aware;
  vapi_type_sse2_qos_action conform_action;
  vapi_type_sse2_qos_action exceed_action;
  vapi_type_sse2_qos_action violate_action; 
} vapi_payload_policer_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_policer_add_del payload;
} vapi_msg_policer_add_del;

static inline void vapi_msg_policer_add_del_payload_hton(vapi_payload_policer_add_del *payload)
{
  payload->cir = htobe32(payload->cir);
  payload->eir = htobe32(payload->eir);
  payload->cb = htobe64(payload->cb);
  payload->eb = htobe64(payload->eb);
}

static inline void vapi_msg_policer_add_del_payload_ntoh(vapi_payload_policer_add_del *payload)
{
  payload->cir = be32toh(payload->cir);
  payload->eir = be32toh(payload->eir);
  payload->cb = be64toh(payload->cb);
  payload->eb = be64toh(payload->eb);
}

static inline void vapi_msg_policer_add_del_hton(vapi_msg_policer_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_policer_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_add_del_ntoh(vapi_msg_policer_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_policer_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_add_del_msg_size(vapi_msg_policer_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_add_del_msg_size(vapi_msg_policer_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_add_del));
      return -1;
    }
  if (vapi_calc_policer_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_policer_add_del* vapi_alloc_policer_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_policer_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_policer_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_policer_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_policer_add_del);

  return msg;
}

static inline vapi_error_e vapi_policer_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_policer_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_policer_add_del_reply *reply),
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
  vapi_msg_policer_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_policer_add_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_policer_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_policer_add_del()
{
  static const char name[] = "policer_add_del";
  static const char name_with_crc[] = "policer_add_del_2b31dd38";
  static vapi_message_desc_t __vapi_metadata_policer_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_policer_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_add_del_hton,
    (generic_swap_fn_t)vapi_msg_policer_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_add_del = vapi_register_msg(&__vapi_metadata_policer_add_del);
  VAPI_DBG("Assigned msg id %d to policer_add_del", vapi_msg_id_policer_add_del);
}
#endif

#ifndef defined_vapi_msg_policer_add_reply
#define defined_vapi_msg_policer_add_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 policer_index; 
} vapi_payload_policer_add_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_policer_add_reply payload;
} vapi_msg_policer_add_reply;

static inline void vapi_msg_policer_add_reply_payload_hton(vapi_payload_policer_add_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->policer_index = htobe32(payload->policer_index);
}

static inline void vapi_msg_policer_add_reply_payload_ntoh(vapi_payload_policer_add_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->policer_index = be32toh(payload->policer_index);
}

static inline void vapi_msg_policer_add_reply_hton(vapi_msg_policer_add_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_add_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_policer_add_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_add_reply_ntoh(vapi_msg_policer_add_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_add_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_policer_add_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_add_reply_msg_size(vapi_msg_policer_add_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_add_reply_msg_size(vapi_msg_policer_add_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_add_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_add_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_add_reply));
      return -1;
    }
  if (vapi_calc_policer_add_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_add_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_add_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_policer_add_reply()
{
  static const char name[] = "policer_add_reply";
  static const char name_with_crc[] = "policer_add_reply_a177cef2";
  static vapi_message_desc_t __vapi_metadata_policer_add_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_policer_add_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_add_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_add_reply_hton,
    (generic_swap_fn_t)vapi_msg_policer_add_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_add_reply = vapi_register_msg(&__vapi_metadata_policer_add_reply);
  VAPI_DBG("Assigned msg id %d to policer_add_reply", vapi_msg_id_policer_add_reply);
}

static inline void vapi_set_vapi_msg_policer_add_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_policer_add_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_policer_add_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_policer_add
#define defined_vapi_msg_policer_add
typedef struct __attribute__ ((__packed__)) {
  u8 name[64];
  vapi_type_policer_config infos; 
} vapi_payload_policer_add;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_policer_add payload;
} vapi_msg_policer_add;

static inline void vapi_msg_policer_add_payload_hton(vapi_payload_policer_add *payload)
{
  vapi_type_policer_config_hton(&payload->infos);
}

static inline void vapi_msg_policer_add_payload_ntoh(vapi_payload_policer_add *payload)
{
  vapi_type_policer_config_ntoh(&payload->infos);
}

static inline void vapi_msg_policer_add_hton(vapi_msg_policer_add *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_add'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_policer_add_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_add_ntoh(vapi_msg_policer_add *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_add'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_policer_add_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_add_msg_size(vapi_msg_policer_add *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_add_msg_size(vapi_msg_policer_add *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_add) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_add' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_add));
      return -1;
    }
  if (vapi_calc_policer_add_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_add' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_add_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_policer_add* vapi_alloc_policer_add(struct vapi_ctx_s *ctx)
{
  vapi_msg_policer_add *msg = NULL;
  const size_t size = sizeof(vapi_msg_policer_add);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_policer_add*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_policer_add);

  return msg;
}

static inline vapi_error_e vapi_policer_add(struct vapi_ctx_s *ctx,
  vapi_msg_policer_add *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_policer_add_reply *reply),
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
  vapi_msg_policer_add_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_policer_add_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_policer_add_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_policer_add()
{
  static const char name[] = "policer_add";
  static const char name_with_crc[] = "policer_add_4d949e35";
  static vapi_message_desc_t __vapi_metadata_policer_add = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_policer_add, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_add_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_add_hton,
    (generic_swap_fn_t)vapi_msg_policer_add_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_add = vapi_register_msg(&__vapi_metadata_policer_add);
  VAPI_DBG("Assigned msg id %d to policer_add", vapi_msg_id_policer_add);
}
#endif

#ifndef defined_vapi_msg_policer_del_reply
#define defined_vapi_msg_policer_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_policer_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_policer_del_reply payload;
} vapi_msg_policer_del_reply;

static inline void vapi_msg_policer_del_reply_payload_hton(vapi_payload_policer_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_policer_del_reply_payload_ntoh(vapi_payload_policer_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_policer_del_reply_hton(vapi_msg_policer_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_policer_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_del_reply_ntoh(vapi_msg_policer_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_policer_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_del_reply_msg_size(vapi_msg_policer_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_del_reply_msg_size(vapi_msg_policer_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_del_reply));
      return -1;
    }
  if (vapi_calc_policer_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_policer_del_reply()
{
  static const char name[] = "policer_del_reply";
  static const char name_with_crc[] = "policer_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_policer_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_policer_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_policer_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_del_reply = vapi_register_msg(&__vapi_metadata_policer_del_reply);
  VAPI_DBG("Assigned msg id %d to policer_del_reply", vapi_msg_id_policer_del_reply);
}

static inline void vapi_set_vapi_msg_policer_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_policer_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_policer_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_policer_del
#define defined_vapi_msg_policer_del
typedef struct __attribute__ ((__packed__)) {
  u32 policer_index; 
} vapi_payload_policer_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_policer_del payload;
} vapi_msg_policer_del;

static inline void vapi_msg_policer_del_payload_hton(vapi_payload_policer_del *payload)
{
  payload->policer_index = htobe32(payload->policer_index);
}

static inline void vapi_msg_policer_del_payload_ntoh(vapi_payload_policer_del *payload)
{
  payload->policer_index = be32toh(payload->policer_index);
}

static inline void vapi_msg_policer_del_hton(vapi_msg_policer_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_policer_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_del_ntoh(vapi_msg_policer_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_policer_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_del_msg_size(vapi_msg_policer_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_del_msg_size(vapi_msg_policer_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_del) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_del));
      return -1;
    }
  if (vapi_calc_policer_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_policer_del* vapi_alloc_policer_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_policer_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_policer_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_policer_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_policer_del);

  return msg;
}

static inline vapi_error_e vapi_policer_del(struct vapi_ctx_s *ctx,
  vapi_msg_policer_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_policer_del_reply *reply),
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
  vapi_msg_policer_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_policer_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_policer_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_policer_del()
{
  static const char name[] = "policer_del";
  static const char name_with_crc[] = "policer_del_7ff7912e";
  static vapi_message_desc_t __vapi_metadata_policer_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_policer_del, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_del_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_del_hton,
    (generic_swap_fn_t)vapi_msg_policer_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_del = vapi_register_msg(&__vapi_metadata_policer_del);
  VAPI_DBG("Assigned msg id %d to policer_del", vapi_msg_id_policer_del);
}
#endif

#ifndef defined_vapi_msg_policer_update_reply
#define defined_vapi_msg_policer_update_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_policer_update_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_policer_update_reply payload;
} vapi_msg_policer_update_reply;

static inline void vapi_msg_policer_update_reply_payload_hton(vapi_payload_policer_update_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_policer_update_reply_payload_ntoh(vapi_payload_policer_update_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_policer_update_reply_hton(vapi_msg_policer_update_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_update_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_policer_update_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_update_reply_ntoh(vapi_msg_policer_update_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_update_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_policer_update_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_update_reply_msg_size(vapi_msg_policer_update_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_update_reply_msg_size(vapi_msg_policer_update_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_update_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_update_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_update_reply));
      return -1;
    }
  if (vapi_calc_policer_update_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_update_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_update_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_policer_update_reply()
{
  static const char name[] = "policer_update_reply";
  static const char name_with_crc[] = "policer_update_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_policer_update_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_policer_update_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_update_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_update_reply_hton,
    (generic_swap_fn_t)vapi_msg_policer_update_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_update_reply = vapi_register_msg(&__vapi_metadata_policer_update_reply);
  VAPI_DBG("Assigned msg id %d to policer_update_reply", vapi_msg_id_policer_update_reply);
}

static inline void vapi_set_vapi_msg_policer_update_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_policer_update_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_policer_update_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_policer_update
#define defined_vapi_msg_policer_update
typedef struct __attribute__ ((__packed__)) {
  u32 policer_index;
  vapi_type_policer_config infos; 
} vapi_payload_policer_update;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_policer_update payload;
} vapi_msg_policer_update;

static inline void vapi_msg_policer_update_payload_hton(vapi_payload_policer_update *payload)
{
  payload->policer_index = htobe32(payload->policer_index);
  vapi_type_policer_config_hton(&payload->infos);
}

static inline void vapi_msg_policer_update_payload_ntoh(vapi_payload_policer_update *payload)
{
  payload->policer_index = be32toh(payload->policer_index);
  vapi_type_policer_config_ntoh(&payload->infos);
}

static inline void vapi_msg_policer_update_hton(vapi_msg_policer_update *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_update'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_policer_update_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_update_ntoh(vapi_msg_policer_update *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_update'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_policer_update_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_update_msg_size(vapi_msg_policer_update *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_update_msg_size(vapi_msg_policer_update *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_update) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_update' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_update));
      return -1;
    }
  if (vapi_calc_policer_update_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_update' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_update_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_policer_update* vapi_alloc_policer_update(struct vapi_ctx_s *ctx)
{
  vapi_msg_policer_update *msg = NULL;
  const size_t size = sizeof(vapi_msg_policer_update);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_policer_update*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_policer_update);

  return msg;
}

static inline vapi_error_e vapi_policer_update(struct vapi_ctx_s *ctx,
  vapi_msg_policer_update *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_policer_update_reply *reply),
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
  vapi_msg_policer_update_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_policer_update_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_policer_update_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_policer_update()
{
  static const char name[] = "policer_update";
  static const char name_with_crc[] = "policer_update_fd039ef0";
  static vapi_message_desc_t __vapi_metadata_policer_update = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_policer_update, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_update_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_update_hton,
    (generic_swap_fn_t)vapi_msg_policer_update_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_update = vapi_register_msg(&__vapi_metadata_policer_update);
  VAPI_DBG("Assigned msg id %d to policer_update", vapi_msg_id_policer_update);
}
#endif

#ifndef defined_vapi_msg_policer_reset_reply
#define defined_vapi_msg_policer_reset_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_policer_reset_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_policer_reset_reply payload;
} vapi_msg_policer_reset_reply;

static inline void vapi_msg_policer_reset_reply_payload_hton(vapi_payload_policer_reset_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_policer_reset_reply_payload_ntoh(vapi_payload_policer_reset_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_policer_reset_reply_hton(vapi_msg_policer_reset_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_reset_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_policer_reset_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_reset_reply_ntoh(vapi_msg_policer_reset_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_reset_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_policer_reset_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_reset_reply_msg_size(vapi_msg_policer_reset_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_reset_reply_msg_size(vapi_msg_policer_reset_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_reset_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_reset_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_reset_reply));
      return -1;
    }
  if (vapi_calc_policer_reset_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_reset_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_reset_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_policer_reset_reply()
{
  static const char name[] = "policer_reset_reply";
  static const char name_with_crc[] = "policer_reset_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_policer_reset_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_policer_reset_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_reset_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_reset_reply_hton,
    (generic_swap_fn_t)vapi_msg_policer_reset_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_reset_reply = vapi_register_msg(&__vapi_metadata_policer_reset_reply);
  VAPI_DBG("Assigned msg id %d to policer_reset_reply", vapi_msg_id_policer_reset_reply);
}

static inline void vapi_set_vapi_msg_policer_reset_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_policer_reset_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_policer_reset_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_policer_reset
#define defined_vapi_msg_policer_reset
typedef struct __attribute__ ((__packed__)) {
  u32 policer_index; 
} vapi_payload_policer_reset;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_policer_reset payload;
} vapi_msg_policer_reset;

static inline void vapi_msg_policer_reset_payload_hton(vapi_payload_policer_reset *payload)
{
  payload->policer_index = htobe32(payload->policer_index);
}

static inline void vapi_msg_policer_reset_payload_ntoh(vapi_payload_policer_reset *payload)
{
  payload->policer_index = be32toh(payload->policer_index);
}

static inline void vapi_msg_policer_reset_hton(vapi_msg_policer_reset *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_reset'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_policer_reset_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_reset_ntoh(vapi_msg_policer_reset *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_reset'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_policer_reset_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_reset_msg_size(vapi_msg_policer_reset *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_reset_msg_size(vapi_msg_policer_reset *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_reset) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_reset' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_reset));
      return -1;
    }
  if (vapi_calc_policer_reset_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_reset' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_reset_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_policer_reset* vapi_alloc_policer_reset(struct vapi_ctx_s *ctx)
{
  vapi_msg_policer_reset *msg = NULL;
  const size_t size = sizeof(vapi_msg_policer_reset);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_policer_reset*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_policer_reset);

  return msg;
}

static inline vapi_error_e vapi_policer_reset(struct vapi_ctx_s *ctx,
  vapi_msg_policer_reset *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_policer_reset_reply *reply),
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
  vapi_msg_policer_reset_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_policer_reset_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_policer_reset_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_policer_reset()
{
  static const char name[] = "policer_reset";
  static const char name_with_crc[] = "policer_reset_7ff7912e";
  static vapi_message_desc_t __vapi_metadata_policer_reset = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_policer_reset, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_reset_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_reset_hton,
    (generic_swap_fn_t)vapi_msg_policer_reset_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_reset = vapi_register_msg(&__vapi_metadata_policer_reset);
  VAPI_DBG("Assigned msg id %d to policer_reset", vapi_msg_id_policer_reset);
}
#endif

#ifndef defined_vapi_msg_policer_details
#define defined_vapi_msg_policer_details
typedef struct __attribute__ ((__packed__)) {
  u8 name[64];
  u32 cir;
  u32 eir;
  u64 cb;
  u64 eb;
  vapi_enum_sse2_qos_rate_type rate_type;
  vapi_enum_sse2_qos_round_type round_type;
  vapi_enum_sse2_qos_policer_type type;
  vapi_type_sse2_qos_action conform_action;
  vapi_type_sse2_qos_action exceed_action;
  vapi_type_sse2_qos_action violate_action;
  bool single_rate;
  bool color_aware;
  u32 scale;
  u32 cir_tokens_per_period;
  u32 pir_tokens_per_period;
  u32 current_limit;
  u32 current_bucket;
  u32 extended_limit;
  u32 extended_bucket;
  u64 last_update_time; 
} vapi_payload_policer_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_policer_details payload;
} vapi_msg_policer_details;

static inline void vapi_msg_policer_details_payload_hton(vapi_payload_policer_details *payload)
{
  payload->cir = htobe32(payload->cir);
  payload->eir = htobe32(payload->eir);
  payload->cb = htobe64(payload->cb);
  payload->eb = htobe64(payload->eb);
  payload->scale = htobe32(payload->scale);
  payload->cir_tokens_per_period = htobe32(payload->cir_tokens_per_period);
  payload->pir_tokens_per_period = htobe32(payload->pir_tokens_per_period);
  payload->current_limit = htobe32(payload->current_limit);
  payload->current_bucket = htobe32(payload->current_bucket);
  payload->extended_limit = htobe32(payload->extended_limit);
  payload->extended_bucket = htobe32(payload->extended_bucket);
  payload->last_update_time = htobe64(payload->last_update_time);
}

static inline void vapi_msg_policer_details_payload_ntoh(vapi_payload_policer_details *payload)
{
  payload->cir = be32toh(payload->cir);
  payload->eir = be32toh(payload->eir);
  payload->cb = be64toh(payload->cb);
  payload->eb = be64toh(payload->eb);
  payload->scale = be32toh(payload->scale);
  payload->cir_tokens_per_period = be32toh(payload->cir_tokens_per_period);
  payload->pir_tokens_per_period = be32toh(payload->pir_tokens_per_period);
  payload->current_limit = be32toh(payload->current_limit);
  payload->current_bucket = be32toh(payload->current_bucket);
  payload->extended_limit = be32toh(payload->extended_limit);
  payload->extended_bucket = be32toh(payload->extended_bucket);
  payload->last_update_time = be64toh(payload->last_update_time);
}

static inline void vapi_msg_policer_details_hton(vapi_msg_policer_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_policer_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_details_ntoh(vapi_msg_policer_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_policer_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_details_msg_size(vapi_msg_policer_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_details_msg_size(vapi_msg_policer_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_details) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_details));
      return -1;
    }
  if (vapi_calc_policer_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_policer_details()
{
  static const char name[] = "policer_details";
  static const char name_with_crc[] = "policer_details_72d0e248";
  static vapi_message_desc_t __vapi_metadata_policer_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_policer_details, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_details_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_details_hton,
    (generic_swap_fn_t)vapi_msg_policer_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_details = vapi_register_msg(&__vapi_metadata_policer_details);
  VAPI_DBG("Assigned msg id %d to policer_details", vapi_msg_id_policer_details);
}

static inline void vapi_set_vapi_msg_policer_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_policer_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_policer_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_policer_dump
#define defined_vapi_msg_policer_dump
typedef struct __attribute__ ((__packed__)) {
  bool match_name_valid;
  u8 match_name[64]; 
} vapi_payload_policer_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_policer_dump payload;
} vapi_msg_policer_dump;

static inline void vapi_msg_policer_dump_payload_hton(vapi_payload_policer_dump *payload)
{

}

static inline void vapi_msg_policer_dump_payload_ntoh(vapi_payload_policer_dump *payload)
{

}

static inline void vapi_msg_policer_dump_hton(vapi_msg_policer_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_policer_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_dump_ntoh(vapi_msg_policer_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_policer_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_dump_msg_size(vapi_msg_policer_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_dump_msg_size(vapi_msg_policer_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_dump));
      return -1;
    }
  if (vapi_calc_policer_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_policer_dump* vapi_alloc_policer_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_policer_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_policer_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_policer_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_policer_dump);

  return msg;
}

static inline vapi_error_e vapi_policer_dump(struct vapi_ctx_s *ctx,
  vapi_msg_policer_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_policer_details *reply),
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
  vapi_msg_policer_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_policer_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_policer_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_policer_dump()
{
  static const char name[] = "policer_dump";
  static const char name_with_crc[] = "policer_dump_35f1ae0f";
  static vapi_message_desc_t __vapi_metadata_policer_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_policer_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_dump_hton,
    (generic_swap_fn_t)vapi_msg_policer_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_dump = vapi_register_msg(&__vapi_metadata_policer_dump);
  VAPI_DBG("Assigned msg id %d to policer_dump", vapi_msg_id_policer_dump);
}
#endif

#ifndef defined_vapi_msg_policer_dump_v2
#define defined_vapi_msg_policer_dump_v2
typedef struct __attribute__ ((__packed__)) {
  u32 policer_index; 
} vapi_payload_policer_dump_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_policer_dump_v2 payload;
} vapi_msg_policer_dump_v2;

static inline void vapi_msg_policer_dump_v2_payload_hton(vapi_payload_policer_dump_v2 *payload)
{
  payload->policer_index = htobe32(payload->policer_index);
}

static inline void vapi_msg_policer_dump_v2_payload_ntoh(vapi_payload_policer_dump_v2 *payload)
{
  payload->policer_index = be32toh(payload->policer_index);
}

static inline void vapi_msg_policer_dump_v2_hton(vapi_msg_policer_dump_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_dump_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_policer_dump_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_dump_v2_ntoh(vapi_msg_policer_dump_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_dump_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_policer_dump_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_dump_v2_msg_size(vapi_msg_policer_dump_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_dump_v2_msg_size(vapi_msg_policer_dump_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_dump_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_dump_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_dump_v2));
      return -1;
    }
  if (vapi_calc_policer_dump_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_dump_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_dump_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_policer_dump_v2* vapi_alloc_policer_dump_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_policer_dump_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_policer_dump_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_policer_dump_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_policer_dump_v2);

  return msg;
}

static inline vapi_error_e vapi_policer_dump_v2(struct vapi_ctx_s *ctx,
  vapi_msg_policer_dump_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_policer_details *reply),
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
  vapi_msg_policer_dump_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_policer_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_policer_dump_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_policer_dump_v2()
{
  static const char name[] = "policer_dump_v2";
  static const char name_with_crc[] = "policer_dump_v2_7ff7912e";
  static vapi_message_desc_t __vapi_metadata_policer_dump_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_policer_dump_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_dump_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_dump_v2_hton,
    (generic_swap_fn_t)vapi_msg_policer_dump_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_dump_v2 = vapi_register_msg(&__vapi_metadata_policer_dump_v2);
  VAPI_DBG("Assigned msg id %d to policer_dump_v2", vapi_msg_id_policer_dump_v2);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
