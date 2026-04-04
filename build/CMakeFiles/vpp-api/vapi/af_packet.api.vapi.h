#ifndef __included_af_packet_api_json
#define __included_af_packet_api_json

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

extern vapi_msg_id_t vapi_msg_id_af_packet_create;
extern vapi_msg_id_t vapi_msg_id_af_packet_create_reply;
extern vapi_msg_id_t vapi_msg_id_af_packet_create_v2;
extern vapi_msg_id_t vapi_msg_id_af_packet_create_v2_reply;
extern vapi_msg_id_t vapi_msg_id_af_packet_create_v3;
extern vapi_msg_id_t vapi_msg_id_af_packet_create_v3_reply;
extern vapi_msg_id_t vapi_msg_id_af_packet_delete;
extern vapi_msg_id_t vapi_msg_id_af_packet_delete_reply;
extern vapi_msg_id_t vapi_msg_id_af_packet_set_l4_cksum_offload;
extern vapi_msg_id_t vapi_msg_id_af_packet_set_l4_cksum_offload_reply;
extern vapi_msg_id_t vapi_msg_id_af_packet_dump;
extern vapi_msg_id_t vapi_msg_id_af_packet_details;

#define DEFINE_VAPI_MSG_IDS_AF_PACKET_API_JSON\
  vapi_msg_id_t vapi_msg_id_af_packet_create;\
  vapi_msg_id_t vapi_msg_id_af_packet_create_reply;\
  vapi_msg_id_t vapi_msg_id_af_packet_create_v2;\
  vapi_msg_id_t vapi_msg_id_af_packet_create_v2_reply;\
  vapi_msg_id_t vapi_msg_id_af_packet_create_v3;\
  vapi_msg_id_t vapi_msg_id_af_packet_create_v3_reply;\
  vapi_msg_id_t vapi_msg_id_af_packet_delete;\
  vapi_msg_id_t vapi_msg_id_af_packet_delete_reply;\
  vapi_msg_id_t vapi_msg_id_af_packet_set_l4_cksum_offload;\
  vapi_msg_id_t vapi_msg_id_af_packet_set_l4_cksum_offload_reply;\
  vapi_msg_id_t vapi_msg_id_af_packet_dump;\
  vapi_msg_id_t vapi_msg_id_af_packet_details;


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

#ifndef defined_vapi_enum_af_packet_mode
#define defined_vapi_enum_af_packet_mode
typedef enum {
  AF_PACKET_API_MODE_ETHERNET = 1,
  AF_PACKET_API_MODE_IP = 2,
}  vapi_enum_af_packet_mode;

#endif

#ifndef defined_vapi_enum_af_packet_flags
#define defined_vapi_enum_af_packet_flags
typedef enum {
  AF_PACKET_API_FLAG_QDISC_BYPASS = 1,
  AF_PACKET_API_FLAG_CKSUM_GSO = 2,
  AF_PACKET_API_FLAG_VERSION_2 = 8,
}  vapi_enum_af_packet_flags;

#endif

#ifndef defined_vapi_type_interface_index
#define defined_vapi_type_interface_index
typedef u32 vapi_type_interface_index;

#endif

#ifndef defined_vapi_type_mac_address
#define defined_vapi_type_mac_address
typedef u8 vapi_type_mac_address[6];

#endif

#ifndef defined_vapi_msg_af_packet_create_reply
#define defined_vapi_msg_af_packet_create_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_af_packet_create_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_af_packet_create_reply payload;
} vapi_msg_af_packet_create_reply;

static inline void vapi_msg_af_packet_create_reply_payload_hton(vapi_payload_af_packet_create_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_af_packet_create_reply_payload_ntoh(vapi_payload_af_packet_create_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_af_packet_create_reply_hton(vapi_msg_af_packet_create_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_create_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_af_packet_create_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_af_packet_create_reply_ntoh(vapi_msg_af_packet_create_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_create_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_af_packet_create_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_af_packet_create_reply_msg_size(vapi_msg_af_packet_create_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_af_packet_create_reply_msg_size(vapi_msg_af_packet_create_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_af_packet_create_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_create_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_af_packet_create_reply));
      return -1;
    }
  if (vapi_calc_af_packet_create_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_create_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_af_packet_create_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_af_packet_create_reply()
{
  static const char name[] = "af_packet_create_reply";
  static const char name_with_crc[] = "af_packet_create_reply_5383d31f";
  static vapi_message_desc_t __vapi_metadata_af_packet_create_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_af_packet_create_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_af_packet_create_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_af_packet_create_reply_hton,
    (generic_swap_fn_t)vapi_msg_af_packet_create_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_af_packet_create_reply = vapi_register_msg(&__vapi_metadata_af_packet_create_reply);
  VAPI_DBG("Assigned msg id %d to af_packet_create_reply", vapi_msg_id_af_packet_create_reply);
}

static inline void vapi_set_vapi_msg_af_packet_create_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_af_packet_create_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_af_packet_create_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_af_packet_create
#define defined_vapi_msg_af_packet_create
typedef struct __attribute__ ((__packed__)) {
  vapi_type_mac_address hw_addr;
  bool use_random_hw_addr;
  u8 host_if_name[64]; 
} vapi_payload_af_packet_create;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_af_packet_create payload;
} vapi_msg_af_packet_create;

static inline void vapi_msg_af_packet_create_payload_hton(vapi_payload_af_packet_create *payload)
{

}

static inline void vapi_msg_af_packet_create_payload_ntoh(vapi_payload_af_packet_create *payload)
{

}

static inline void vapi_msg_af_packet_create_hton(vapi_msg_af_packet_create *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_create'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_af_packet_create_payload_hton(&msg->payload);
}

static inline void vapi_msg_af_packet_create_ntoh(vapi_msg_af_packet_create *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_create'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_af_packet_create_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_af_packet_create_msg_size(vapi_msg_af_packet_create *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_af_packet_create_msg_size(vapi_msg_af_packet_create *msg, uword buf_size)
{
  if (sizeof(vapi_msg_af_packet_create) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_create' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_af_packet_create));
      return -1;
    }
  if (vapi_calc_af_packet_create_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_create' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_af_packet_create_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_af_packet_create* vapi_alloc_af_packet_create(struct vapi_ctx_s *ctx)
{
  vapi_msg_af_packet_create *msg = NULL;
  const size_t size = sizeof(vapi_msg_af_packet_create);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_af_packet_create*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_af_packet_create);

  return msg;
}

static inline vapi_error_e vapi_af_packet_create(struct vapi_ctx_s *ctx,
  vapi_msg_af_packet_create *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_af_packet_create_reply *reply),
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
  vapi_msg_af_packet_create_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_af_packet_create_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_af_packet_create_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_af_packet_create()
{
  static const char name[] = "af_packet_create";
  static const char name_with_crc[] = "af_packet_create_a190415f";
  static vapi_message_desc_t __vapi_metadata_af_packet_create = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_af_packet_create, payload),
    (verify_msg_size_fn_t)vapi_verify_af_packet_create_msg_size,
    (generic_swap_fn_t)vapi_msg_af_packet_create_hton,
    (generic_swap_fn_t)vapi_msg_af_packet_create_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_af_packet_create = vapi_register_msg(&__vapi_metadata_af_packet_create);
  VAPI_DBG("Assigned msg id %d to af_packet_create", vapi_msg_id_af_packet_create);
}
#endif

#ifndef defined_vapi_msg_af_packet_create_v2_reply
#define defined_vapi_msg_af_packet_create_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_af_packet_create_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_af_packet_create_v2_reply payload;
} vapi_msg_af_packet_create_v2_reply;

static inline void vapi_msg_af_packet_create_v2_reply_payload_hton(vapi_payload_af_packet_create_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_af_packet_create_v2_reply_payload_ntoh(vapi_payload_af_packet_create_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_af_packet_create_v2_reply_hton(vapi_msg_af_packet_create_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_create_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_af_packet_create_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_af_packet_create_v2_reply_ntoh(vapi_msg_af_packet_create_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_create_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_af_packet_create_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_af_packet_create_v2_reply_msg_size(vapi_msg_af_packet_create_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_af_packet_create_v2_reply_msg_size(vapi_msg_af_packet_create_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_af_packet_create_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_create_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_af_packet_create_v2_reply));
      return -1;
    }
  if (vapi_calc_af_packet_create_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_create_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_af_packet_create_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_af_packet_create_v2_reply()
{
  static const char name[] = "af_packet_create_v2_reply";
  static const char name_with_crc[] = "af_packet_create_v2_reply_5383d31f";
  static vapi_message_desc_t __vapi_metadata_af_packet_create_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_af_packet_create_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_af_packet_create_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_af_packet_create_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_af_packet_create_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_af_packet_create_v2_reply = vapi_register_msg(&__vapi_metadata_af_packet_create_v2_reply);
  VAPI_DBG("Assigned msg id %d to af_packet_create_v2_reply", vapi_msg_id_af_packet_create_v2_reply);
}

static inline void vapi_set_vapi_msg_af_packet_create_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_af_packet_create_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_af_packet_create_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_af_packet_create_v2
#define defined_vapi_msg_af_packet_create_v2
typedef struct __attribute__ ((__packed__)) {
  vapi_type_mac_address hw_addr;
  bool use_random_hw_addr;
  u8 host_if_name[64];
  u32 rx_frame_size;
  u32 tx_frame_size;
  u32 rx_frames_per_block;
  u32 tx_frames_per_block;
  u32 flags;
  u16 num_rx_queues; 
} vapi_payload_af_packet_create_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_af_packet_create_v2 payload;
} vapi_msg_af_packet_create_v2;

static inline void vapi_msg_af_packet_create_v2_payload_hton(vapi_payload_af_packet_create_v2 *payload)
{
  payload->rx_frame_size = htobe32(payload->rx_frame_size);
  payload->tx_frame_size = htobe32(payload->tx_frame_size);
  payload->rx_frames_per_block = htobe32(payload->rx_frames_per_block);
  payload->tx_frames_per_block = htobe32(payload->tx_frames_per_block);
  payload->flags = htobe32(payload->flags);
  payload->num_rx_queues = htobe16(payload->num_rx_queues);
}

static inline void vapi_msg_af_packet_create_v2_payload_ntoh(vapi_payload_af_packet_create_v2 *payload)
{
  payload->rx_frame_size = be32toh(payload->rx_frame_size);
  payload->tx_frame_size = be32toh(payload->tx_frame_size);
  payload->rx_frames_per_block = be32toh(payload->rx_frames_per_block);
  payload->tx_frames_per_block = be32toh(payload->tx_frames_per_block);
  payload->flags = be32toh(payload->flags);
  payload->num_rx_queues = be16toh(payload->num_rx_queues);
}

static inline void vapi_msg_af_packet_create_v2_hton(vapi_msg_af_packet_create_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_create_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_af_packet_create_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_af_packet_create_v2_ntoh(vapi_msg_af_packet_create_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_create_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_af_packet_create_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_af_packet_create_v2_msg_size(vapi_msg_af_packet_create_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_af_packet_create_v2_msg_size(vapi_msg_af_packet_create_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_af_packet_create_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_create_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_af_packet_create_v2));
      return -1;
    }
  if (vapi_calc_af_packet_create_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_create_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_af_packet_create_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_af_packet_create_v2* vapi_alloc_af_packet_create_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_af_packet_create_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_af_packet_create_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_af_packet_create_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_af_packet_create_v2);

  return msg;
}

static inline vapi_error_e vapi_af_packet_create_v2(struct vapi_ctx_s *ctx,
  vapi_msg_af_packet_create_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_af_packet_create_v2_reply *reply),
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
  vapi_msg_af_packet_create_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_af_packet_create_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_af_packet_create_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_af_packet_create_v2()
{
  static const char name[] = "af_packet_create_v2";
  static const char name_with_crc[] = "af_packet_create_v2_4aff0436";
  static vapi_message_desc_t __vapi_metadata_af_packet_create_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_af_packet_create_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_af_packet_create_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_af_packet_create_v2_hton,
    (generic_swap_fn_t)vapi_msg_af_packet_create_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_af_packet_create_v2 = vapi_register_msg(&__vapi_metadata_af_packet_create_v2);
  VAPI_DBG("Assigned msg id %d to af_packet_create_v2", vapi_msg_id_af_packet_create_v2);
}
#endif

#ifndef defined_vapi_msg_af_packet_create_v3_reply
#define defined_vapi_msg_af_packet_create_v3_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_af_packet_create_v3_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_af_packet_create_v3_reply payload;
} vapi_msg_af_packet_create_v3_reply;

static inline void vapi_msg_af_packet_create_v3_reply_payload_hton(vapi_payload_af_packet_create_v3_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_af_packet_create_v3_reply_payload_ntoh(vapi_payload_af_packet_create_v3_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_af_packet_create_v3_reply_hton(vapi_msg_af_packet_create_v3_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_create_v3_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_af_packet_create_v3_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_af_packet_create_v3_reply_ntoh(vapi_msg_af_packet_create_v3_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_create_v3_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_af_packet_create_v3_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_af_packet_create_v3_reply_msg_size(vapi_msg_af_packet_create_v3_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_af_packet_create_v3_reply_msg_size(vapi_msg_af_packet_create_v3_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_af_packet_create_v3_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_create_v3_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_af_packet_create_v3_reply));
      return -1;
    }
  if (vapi_calc_af_packet_create_v3_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_create_v3_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_af_packet_create_v3_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_af_packet_create_v3_reply()
{
  static const char name[] = "af_packet_create_v3_reply";
  static const char name_with_crc[] = "af_packet_create_v3_reply_5383d31f";
  static vapi_message_desc_t __vapi_metadata_af_packet_create_v3_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_af_packet_create_v3_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_af_packet_create_v3_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_af_packet_create_v3_reply_hton,
    (generic_swap_fn_t)vapi_msg_af_packet_create_v3_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_af_packet_create_v3_reply = vapi_register_msg(&__vapi_metadata_af_packet_create_v3_reply);
  VAPI_DBG("Assigned msg id %d to af_packet_create_v3_reply", vapi_msg_id_af_packet_create_v3_reply);
}

static inline void vapi_set_vapi_msg_af_packet_create_v3_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_af_packet_create_v3_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_af_packet_create_v3_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_af_packet_create_v3
#define defined_vapi_msg_af_packet_create_v3
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_af_packet_mode mode;
  vapi_type_mac_address hw_addr;
  bool use_random_hw_addr;
  u8 host_if_name[64];
  u32 rx_frame_size;
  u32 tx_frame_size;
  u32 rx_frames_per_block;
  u32 tx_frames_per_block;
  vapi_enum_af_packet_flags flags;
  u16 num_rx_queues;
  u16 num_tx_queues; 
} vapi_payload_af_packet_create_v3;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_af_packet_create_v3 payload;
} vapi_msg_af_packet_create_v3;

static inline void vapi_msg_af_packet_create_v3_payload_hton(vapi_payload_af_packet_create_v3 *payload)
{
  payload->mode = (vapi_enum_af_packet_mode)htobe32(payload->mode);
  payload->rx_frame_size = htobe32(payload->rx_frame_size);
  payload->tx_frame_size = htobe32(payload->tx_frame_size);
  payload->rx_frames_per_block = htobe32(payload->rx_frames_per_block);
  payload->tx_frames_per_block = htobe32(payload->tx_frames_per_block);
  payload->flags = (vapi_enum_af_packet_flags)htobe32(payload->flags);
  payload->num_rx_queues = htobe16(payload->num_rx_queues);
  payload->num_tx_queues = htobe16(payload->num_tx_queues);
}

static inline void vapi_msg_af_packet_create_v3_payload_ntoh(vapi_payload_af_packet_create_v3 *payload)
{
  payload->mode = (vapi_enum_af_packet_mode)be32toh(payload->mode);
  payload->rx_frame_size = be32toh(payload->rx_frame_size);
  payload->tx_frame_size = be32toh(payload->tx_frame_size);
  payload->rx_frames_per_block = be32toh(payload->rx_frames_per_block);
  payload->tx_frames_per_block = be32toh(payload->tx_frames_per_block);
  payload->flags = (vapi_enum_af_packet_flags)be32toh(payload->flags);
  payload->num_rx_queues = be16toh(payload->num_rx_queues);
  payload->num_tx_queues = be16toh(payload->num_tx_queues);
}

static inline void vapi_msg_af_packet_create_v3_hton(vapi_msg_af_packet_create_v3 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_create_v3'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_af_packet_create_v3_payload_hton(&msg->payload);
}

static inline void vapi_msg_af_packet_create_v3_ntoh(vapi_msg_af_packet_create_v3 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_create_v3'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_af_packet_create_v3_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_af_packet_create_v3_msg_size(vapi_msg_af_packet_create_v3 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_af_packet_create_v3_msg_size(vapi_msg_af_packet_create_v3 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_af_packet_create_v3) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_create_v3' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_af_packet_create_v3));
      return -1;
    }
  if (vapi_calc_af_packet_create_v3_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_create_v3' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_af_packet_create_v3_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_af_packet_create_v3* vapi_alloc_af_packet_create_v3(struct vapi_ctx_s *ctx)
{
  vapi_msg_af_packet_create_v3 *msg = NULL;
  const size_t size = sizeof(vapi_msg_af_packet_create_v3);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_af_packet_create_v3*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_af_packet_create_v3);

  return msg;
}

static inline vapi_error_e vapi_af_packet_create_v3(struct vapi_ctx_s *ctx,
  vapi_msg_af_packet_create_v3 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_af_packet_create_v3_reply *reply),
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
  vapi_msg_af_packet_create_v3_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_af_packet_create_v3_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_af_packet_create_v3_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_af_packet_create_v3()
{
  static const char name[] = "af_packet_create_v3";
  static const char name_with_crc[] = "af_packet_create_v3_b3a809d4";
  static vapi_message_desc_t __vapi_metadata_af_packet_create_v3 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_af_packet_create_v3, payload),
    (verify_msg_size_fn_t)vapi_verify_af_packet_create_v3_msg_size,
    (generic_swap_fn_t)vapi_msg_af_packet_create_v3_hton,
    (generic_swap_fn_t)vapi_msg_af_packet_create_v3_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_af_packet_create_v3 = vapi_register_msg(&__vapi_metadata_af_packet_create_v3);
  VAPI_DBG("Assigned msg id %d to af_packet_create_v3", vapi_msg_id_af_packet_create_v3);
}
#endif

#ifndef defined_vapi_msg_af_packet_delete_reply
#define defined_vapi_msg_af_packet_delete_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_af_packet_delete_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_af_packet_delete_reply payload;
} vapi_msg_af_packet_delete_reply;

static inline void vapi_msg_af_packet_delete_reply_payload_hton(vapi_payload_af_packet_delete_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_af_packet_delete_reply_payload_ntoh(vapi_payload_af_packet_delete_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_af_packet_delete_reply_hton(vapi_msg_af_packet_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_delete_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_af_packet_delete_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_af_packet_delete_reply_ntoh(vapi_msg_af_packet_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_delete_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_af_packet_delete_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_af_packet_delete_reply_msg_size(vapi_msg_af_packet_delete_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_af_packet_delete_reply_msg_size(vapi_msg_af_packet_delete_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_af_packet_delete_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_af_packet_delete_reply));
      return -1;
    }
  if (vapi_calc_af_packet_delete_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_af_packet_delete_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_af_packet_delete_reply()
{
  static const char name[] = "af_packet_delete_reply";
  static const char name_with_crc[] = "af_packet_delete_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_af_packet_delete_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_af_packet_delete_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_af_packet_delete_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_af_packet_delete_reply_hton,
    (generic_swap_fn_t)vapi_msg_af_packet_delete_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_af_packet_delete_reply = vapi_register_msg(&__vapi_metadata_af_packet_delete_reply);
  VAPI_DBG("Assigned msg id %d to af_packet_delete_reply", vapi_msg_id_af_packet_delete_reply);
}

static inline void vapi_set_vapi_msg_af_packet_delete_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_af_packet_delete_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_af_packet_delete_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_af_packet_delete
#define defined_vapi_msg_af_packet_delete
typedef struct __attribute__ ((__packed__)) {
  u8 host_if_name[64]; 
} vapi_payload_af_packet_delete;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_af_packet_delete payload;
} vapi_msg_af_packet_delete;

static inline void vapi_msg_af_packet_delete_payload_hton(vapi_payload_af_packet_delete *payload)
{

}

static inline void vapi_msg_af_packet_delete_payload_ntoh(vapi_payload_af_packet_delete *payload)
{

}

static inline void vapi_msg_af_packet_delete_hton(vapi_msg_af_packet_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_delete'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_af_packet_delete_payload_hton(&msg->payload);
}

static inline void vapi_msg_af_packet_delete_ntoh(vapi_msg_af_packet_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_delete'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_af_packet_delete_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_af_packet_delete_msg_size(vapi_msg_af_packet_delete *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_af_packet_delete_msg_size(vapi_msg_af_packet_delete *msg, uword buf_size)
{
  if (sizeof(vapi_msg_af_packet_delete) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_af_packet_delete));
      return -1;
    }
  if (vapi_calc_af_packet_delete_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_af_packet_delete_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_af_packet_delete* vapi_alloc_af_packet_delete(struct vapi_ctx_s *ctx)
{
  vapi_msg_af_packet_delete *msg = NULL;
  const size_t size = sizeof(vapi_msg_af_packet_delete);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_af_packet_delete*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_af_packet_delete);

  return msg;
}

static inline vapi_error_e vapi_af_packet_delete(struct vapi_ctx_s *ctx,
  vapi_msg_af_packet_delete *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_af_packet_delete_reply *reply),
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
  vapi_msg_af_packet_delete_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_af_packet_delete_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_af_packet_delete_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_af_packet_delete()
{
  static const char name[] = "af_packet_delete";
  static const char name_with_crc[] = "af_packet_delete_863fa648";
  static vapi_message_desc_t __vapi_metadata_af_packet_delete = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_af_packet_delete, payload),
    (verify_msg_size_fn_t)vapi_verify_af_packet_delete_msg_size,
    (generic_swap_fn_t)vapi_msg_af_packet_delete_hton,
    (generic_swap_fn_t)vapi_msg_af_packet_delete_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_af_packet_delete = vapi_register_msg(&__vapi_metadata_af_packet_delete);
  VAPI_DBG("Assigned msg id %d to af_packet_delete", vapi_msg_id_af_packet_delete);
}
#endif

#ifndef defined_vapi_msg_af_packet_set_l4_cksum_offload_reply
#define defined_vapi_msg_af_packet_set_l4_cksum_offload_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_af_packet_set_l4_cksum_offload_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_af_packet_set_l4_cksum_offload_reply payload;
} vapi_msg_af_packet_set_l4_cksum_offload_reply;

static inline void vapi_msg_af_packet_set_l4_cksum_offload_reply_payload_hton(vapi_payload_af_packet_set_l4_cksum_offload_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_af_packet_set_l4_cksum_offload_reply_payload_ntoh(vapi_payload_af_packet_set_l4_cksum_offload_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_af_packet_set_l4_cksum_offload_reply_hton(vapi_msg_af_packet_set_l4_cksum_offload_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_set_l4_cksum_offload_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_af_packet_set_l4_cksum_offload_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_af_packet_set_l4_cksum_offload_reply_ntoh(vapi_msg_af_packet_set_l4_cksum_offload_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_set_l4_cksum_offload_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_af_packet_set_l4_cksum_offload_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_af_packet_set_l4_cksum_offload_reply_msg_size(vapi_msg_af_packet_set_l4_cksum_offload_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_af_packet_set_l4_cksum_offload_reply_msg_size(vapi_msg_af_packet_set_l4_cksum_offload_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_af_packet_set_l4_cksum_offload_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_set_l4_cksum_offload_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_af_packet_set_l4_cksum_offload_reply));
      return -1;
    }
  if (vapi_calc_af_packet_set_l4_cksum_offload_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_set_l4_cksum_offload_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_af_packet_set_l4_cksum_offload_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_af_packet_set_l4_cksum_offload_reply()
{
  static const char name[] = "af_packet_set_l4_cksum_offload_reply";
  static const char name_with_crc[] = "af_packet_set_l4_cksum_offload_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_af_packet_set_l4_cksum_offload_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_af_packet_set_l4_cksum_offload_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_af_packet_set_l4_cksum_offload_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_af_packet_set_l4_cksum_offload_reply_hton,
    (generic_swap_fn_t)vapi_msg_af_packet_set_l4_cksum_offload_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_af_packet_set_l4_cksum_offload_reply = vapi_register_msg(&__vapi_metadata_af_packet_set_l4_cksum_offload_reply);
  VAPI_DBG("Assigned msg id %d to af_packet_set_l4_cksum_offload_reply", vapi_msg_id_af_packet_set_l4_cksum_offload_reply);
}

static inline void vapi_set_vapi_msg_af_packet_set_l4_cksum_offload_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_af_packet_set_l4_cksum_offload_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_af_packet_set_l4_cksum_offload_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_af_packet_set_l4_cksum_offload
#define defined_vapi_msg_af_packet_set_l4_cksum_offload
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  bool set; 
} vapi_payload_af_packet_set_l4_cksum_offload;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_af_packet_set_l4_cksum_offload payload;
} vapi_msg_af_packet_set_l4_cksum_offload;

static inline void vapi_msg_af_packet_set_l4_cksum_offload_payload_hton(vapi_payload_af_packet_set_l4_cksum_offload *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_af_packet_set_l4_cksum_offload_payload_ntoh(vapi_payload_af_packet_set_l4_cksum_offload *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_af_packet_set_l4_cksum_offload_hton(vapi_msg_af_packet_set_l4_cksum_offload *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_set_l4_cksum_offload'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_af_packet_set_l4_cksum_offload_payload_hton(&msg->payload);
}

static inline void vapi_msg_af_packet_set_l4_cksum_offload_ntoh(vapi_msg_af_packet_set_l4_cksum_offload *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_set_l4_cksum_offload'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_af_packet_set_l4_cksum_offload_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_af_packet_set_l4_cksum_offload_msg_size(vapi_msg_af_packet_set_l4_cksum_offload *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_af_packet_set_l4_cksum_offload_msg_size(vapi_msg_af_packet_set_l4_cksum_offload *msg, uword buf_size)
{
  if (sizeof(vapi_msg_af_packet_set_l4_cksum_offload) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_set_l4_cksum_offload' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_af_packet_set_l4_cksum_offload));
      return -1;
    }
  if (vapi_calc_af_packet_set_l4_cksum_offload_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_set_l4_cksum_offload' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_af_packet_set_l4_cksum_offload_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_af_packet_set_l4_cksum_offload* vapi_alloc_af_packet_set_l4_cksum_offload(struct vapi_ctx_s *ctx)
{
  vapi_msg_af_packet_set_l4_cksum_offload *msg = NULL;
  const size_t size = sizeof(vapi_msg_af_packet_set_l4_cksum_offload);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_af_packet_set_l4_cksum_offload*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_af_packet_set_l4_cksum_offload);

  return msg;
}

static inline vapi_error_e vapi_af_packet_set_l4_cksum_offload(struct vapi_ctx_s *ctx,
  vapi_msg_af_packet_set_l4_cksum_offload *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_af_packet_set_l4_cksum_offload_reply *reply),
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
  vapi_msg_af_packet_set_l4_cksum_offload_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_af_packet_set_l4_cksum_offload_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_af_packet_set_l4_cksum_offload_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_af_packet_set_l4_cksum_offload()
{
  static const char name[] = "af_packet_set_l4_cksum_offload";
  static const char name_with_crc[] = "af_packet_set_l4_cksum_offload_319cd5c8";
  static vapi_message_desc_t __vapi_metadata_af_packet_set_l4_cksum_offload = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_af_packet_set_l4_cksum_offload, payload),
    (verify_msg_size_fn_t)vapi_verify_af_packet_set_l4_cksum_offload_msg_size,
    (generic_swap_fn_t)vapi_msg_af_packet_set_l4_cksum_offload_hton,
    (generic_swap_fn_t)vapi_msg_af_packet_set_l4_cksum_offload_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_af_packet_set_l4_cksum_offload = vapi_register_msg(&__vapi_metadata_af_packet_set_l4_cksum_offload);
  VAPI_DBG("Assigned msg id %d to af_packet_set_l4_cksum_offload", vapi_msg_id_af_packet_set_l4_cksum_offload);
}
#endif

#ifndef defined_vapi_msg_af_packet_details
#define defined_vapi_msg_af_packet_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u8 host_if_name[64]; 
} vapi_payload_af_packet_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_af_packet_details payload;
} vapi_msg_af_packet_details;

static inline void vapi_msg_af_packet_details_payload_hton(vapi_payload_af_packet_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_af_packet_details_payload_ntoh(vapi_payload_af_packet_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_af_packet_details_hton(vapi_msg_af_packet_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_af_packet_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_af_packet_details_ntoh(vapi_msg_af_packet_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_af_packet_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_af_packet_details_msg_size(vapi_msg_af_packet_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_af_packet_details_msg_size(vapi_msg_af_packet_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_af_packet_details) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_af_packet_details));
      return -1;
    }
  if (vapi_calc_af_packet_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_af_packet_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_af_packet_details()
{
  static const char name[] = "af_packet_details";
  static const char name_with_crc[] = "af_packet_details_58c7c042";
  static vapi_message_desc_t __vapi_metadata_af_packet_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_af_packet_details, payload),
    (verify_msg_size_fn_t)vapi_verify_af_packet_details_msg_size,
    (generic_swap_fn_t)vapi_msg_af_packet_details_hton,
    (generic_swap_fn_t)vapi_msg_af_packet_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_af_packet_details = vapi_register_msg(&__vapi_metadata_af_packet_details);
  VAPI_DBG("Assigned msg id %d to af_packet_details", vapi_msg_id_af_packet_details);
}

static inline void vapi_set_vapi_msg_af_packet_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_af_packet_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_af_packet_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_af_packet_dump
#define defined_vapi_msg_af_packet_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_af_packet_dump;

static inline void vapi_msg_af_packet_dump_hton(vapi_msg_af_packet_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_af_packet_dump_ntoh(vapi_msg_af_packet_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_af_packet_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_af_packet_dump_msg_size(vapi_msg_af_packet_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_af_packet_dump_msg_size(vapi_msg_af_packet_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_af_packet_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_af_packet_dump));
      return -1;
    }
  if (vapi_calc_af_packet_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'af_packet_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_af_packet_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_af_packet_dump* vapi_alloc_af_packet_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_af_packet_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_af_packet_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_af_packet_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_af_packet_dump);

  return msg;
}

static inline vapi_error_e vapi_af_packet_dump(struct vapi_ctx_s *ctx,
  vapi_msg_af_packet_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_af_packet_details *reply),
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
  vapi_msg_af_packet_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_af_packet_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_af_packet_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_af_packet_dump()
{
  static const char name[] = "af_packet_dump";
  static const char name_with_crc[] = "af_packet_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_af_packet_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_af_packet_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_af_packet_dump_hton,
    (generic_swap_fn_t)vapi_msg_af_packet_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_af_packet_dump = vapi_register_msg(&__vapi_metadata_af_packet_dump);
  VAPI_DBG("Assigned msg id %d to af_packet_dump", vapi_msg_id_af_packet_dump);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
