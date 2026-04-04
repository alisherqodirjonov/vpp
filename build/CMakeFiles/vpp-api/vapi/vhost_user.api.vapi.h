#ifndef __included_vhost_user_api_json
#define __included_vhost_user_api_json

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

extern vapi_msg_id_t vapi_msg_id_create_vhost_user_if;
extern vapi_msg_id_t vapi_msg_id_create_vhost_user_if_reply;
extern vapi_msg_id_t vapi_msg_id_modify_vhost_user_if;
extern vapi_msg_id_t vapi_msg_id_modify_vhost_user_if_reply;
extern vapi_msg_id_t vapi_msg_id_create_vhost_user_if_v2;
extern vapi_msg_id_t vapi_msg_id_create_vhost_user_if_v2_reply;
extern vapi_msg_id_t vapi_msg_id_modify_vhost_user_if_v2;
extern vapi_msg_id_t vapi_msg_id_modify_vhost_user_if_v2_reply;
extern vapi_msg_id_t vapi_msg_id_delete_vhost_user_if;
extern vapi_msg_id_t vapi_msg_id_delete_vhost_user_if_reply;
extern vapi_msg_id_t vapi_msg_id_sw_interface_vhost_user_details;
extern vapi_msg_id_t vapi_msg_id_sw_interface_vhost_user_dump;

#define DEFINE_VAPI_MSG_IDS_VHOST_USER_API_JSON\
  vapi_msg_id_t vapi_msg_id_create_vhost_user_if;\
  vapi_msg_id_t vapi_msg_id_create_vhost_user_if_reply;\
  vapi_msg_id_t vapi_msg_id_modify_vhost_user_if;\
  vapi_msg_id_t vapi_msg_id_modify_vhost_user_if_reply;\
  vapi_msg_id_t vapi_msg_id_create_vhost_user_if_v2;\
  vapi_msg_id_t vapi_msg_id_create_vhost_user_if_v2_reply;\
  vapi_msg_id_t vapi_msg_id_modify_vhost_user_if_v2;\
  vapi_msg_id_t vapi_msg_id_modify_vhost_user_if_v2_reply;\
  vapi_msg_id_t vapi_msg_id_delete_vhost_user_if;\
  vapi_msg_id_t vapi_msg_id_delete_vhost_user_if_reply;\
  vapi_msg_id_t vapi_msg_id_sw_interface_vhost_user_details;\
  vapi_msg_id_t vapi_msg_id_sw_interface_vhost_user_dump;


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

#ifndef defined_vapi_enum_virtio_net_features_first_32
#define defined_vapi_enum_virtio_net_features_first_32
typedef enum {
  VIRTIO_NET_F_API_CSUM = 1,
  VIRTIO_NET_F_API_GUEST_CSUM = 2,
  VIRTIO_NET_F_API_GUEST_TSO4 = 128,
  VIRTIO_NET_F_API_GUEST_TSO6 = 256,
  VIRTIO_NET_F_API_GUEST_UFO = 1024,
  VIRTIO_NET_F_API_HOST_TSO4 = 2048,
  VIRTIO_NET_F_API_HOST_TSO6 = 4096,
  VIRTIO_NET_F_API_HOST_UFO = 16384,
  VIRTIO_NET_F_API_MRG_RXBUF = 32768,
  VIRTIO_NET_F_API_CTRL_VQ = 131072,
  VIRTIO_NET_F_API_GUEST_ANNOUNCE = 2097152,
  VIRTIO_NET_F_API_MQ = 4194304,
  VHOST_F_API_LOG_ALL = 67108864,
  VIRTIO_F_API_ANY_LAYOUT = 134217728,
  VIRTIO_F_API_INDIRECT_DESC = 268435456,
  VHOST_USER_F_API_PROTOCOL_FEATURES = 1073741824,
}  vapi_enum_virtio_net_features_first_32;

#endif

#ifndef defined_vapi_enum_virtio_net_features_last_32
#define defined_vapi_enum_virtio_net_features_last_32
typedef enum {
  VIRTIO_F_API_VERSION_1 = 1,
}  vapi_enum_virtio_net_features_last_32;

#endif

#ifndef defined_vapi_type_interface_index
#define defined_vapi_type_interface_index
typedef u32 vapi_type_interface_index;

#endif

#ifndef defined_vapi_type_mac_address
#define defined_vapi_type_mac_address
typedef u8 vapi_type_mac_address[6];

#endif

#ifndef defined_vapi_msg_create_vhost_user_if_reply
#define defined_vapi_msg_create_vhost_user_if_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_create_vhost_user_if_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_create_vhost_user_if_reply payload;
} vapi_msg_create_vhost_user_if_reply;

static inline void vapi_msg_create_vhost_user_if_reply_payload_hton(vapi_payload_create_vhost_user_if_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_create_vhost_user_if_reply_payload_ntoh(vapi_payload_create_vhost_user_if_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_create_vhost_user_if_reply_hton(vapi_msg_create_vhost_user_if_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_create_vhost_user_if_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_create_vhost_user_if_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_create_vhost_user_if_reply_ntoh(vapi_msg_create_vhost_user_if_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_create_vhost_user_if_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_create_vhost_user_if_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_create_vhost_user_if_reply_msg_size(vapi_msg_create_vhost_user_if_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_create_vhost_user_if_reply_msg_size(vapi_msg_create_vhost_user_if_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_create_vhost_user_if_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'create_vhost_user_if_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_create_vhost_user_if_reply));
      return -1;
    }
  if (vapi_calc_create_vhost_user_if_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'create_vhost_user_if_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_create_vhost_user_if_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_create_vhost_user_if_reply()
{
  static const char name[] = "create_vhost_user_if_reply";
  static const char name_with_crc[] = "create_vhost_user_if_reply_5383d31f";
  static vapi_message_desc_t __vapi_metadata_create_vhost_user_if_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_create_vhost_user_if_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_create_vhost_user_if_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_create_vhost_user_if_reply_hton,
    (generic_swap_fn_t)vapi_msg_create_vhost_user_if_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_create_vhost_user_if_reply = vapi_register_msg(&__vapi_metadata_create_vhost_user_if_reply);
  VAPI_DBG("Assigned msg id %d to create_vhost_user_if_reply", vapi_msg_id_create_vhost_user_if_reply);
}

static inline void vapi_set_vapi_msg_create_vhost_user_if_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_create_vhost_user_if_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_create_vhost_user_if_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_create_vhost_user_if
#define defined_vapi_msg_create_vhost_user_if
typedef struct __attribute__ ((__packed__)) {
  bool is_server;
  u8 sock_filename[256];
  bool renumber;
  bool disable_mrg_rxbuf;
  bool disable_indirect_desc;
  bool enable_gso;
  bool enable_packed;
  u32 custom_dev_instance;
  bool use_custom_mac;
  vapi_type_mac_address mac_address;
  u8 tag[64]; 
} vapi_payload_create_vhost_user_if;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_create_vhost_user_if payload;
} vapi_msg_create_vhost_user_if;

static inline void vapi_msg_create_vhost_user_if_payload_hton(vapi_payload_create_vhost_user_if *payload)
{
  payload->custom_dev_instance = htobe32(payload->custom_dev_instance);
}

static inline void vapi_msg_create_vhost_user_if_payload_ntoh(vapi_payload_create_vhost_user_if *payload)
{
  payload->custom_dev_instance = be32toh(payload->custom_dev_instance);
}

static inline void vapi_msg_create_vhost_user_if_hton(vapi_msg_create_vhost_user_if *msg)
{
  VAPI_DBG("Swapping `vapi_msg_create_vhost_user_if'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_create_vhost_user_if_payload_hton(&msg->payload);
}

static inline void vapi_msg_create_vhost_user_if_ntoh(vapi_msg_create_vhost_user_if *msg)
{
  VAPI_DBG("Swapping `vapi_msg_create_vhost_user_if'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_create_vhost_user_if_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_create_vhost_user_if_msg_size(vapi_msg_create_vhost_user_if *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_create_vhost_user_if_msg_size(vapi_msg_create_vhost_user_if *msg, uword buf_size)
{
  if (sizeof(vapi_msg_create_vhost_user_if) > buf_size)
    {
      VAPI_ERR("Truncated 'create_vhost_user_if' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_create_vhost_user_if));
      return -1;
    }
  if (vapi_calc_create_vhost_user_if_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'create_vhost_user_if' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_create_vhost_user_if_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_create_vhost_user_if* vapi_alloc_create_vhost_user_if(struct vapi_ctx_s *ctx)
{
  vapi_msg_create_vhost_user_if *msg = NULL;
  const size_t size = sizeof(vapi_msg_create_vhost_user_if);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_create_vhost_user_if*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_create_vhost_user_if);

  return msg;
}

static inline vapi_error_e vapi_create_vhost_user_if(struct vapi_ctx_s *ctx,
  vapi_msg_create_vhost_user_if *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_create_vhost_user_if_reply *reply),
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
  vapi_msg_create_vhost_user_if_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_create_vhost_user_if_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_create_vhost_user_if_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_create_vhost_user_if()
{
  static const char name[] = "create_vhost_user_if";
  static const char name_with_crc[] = "create_vhost_user_if_c785c6fc";
  static vapi_message_desc_t __vapi_metadata_create_vhost_user_if = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_create_vhost_user_if, payload),
    (verify_msg_size_fn_t)vapi_verify_create_vhost_user_if_msg_size,
    (generic_swap_fn_t)vapi_msg_create_vhost_user_if_hton,
    (generic_swap_fn_t)vapi_msg_create_vhost_user_if_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_create_vhost_user_if = vapi_register_msg(&__vapi_metadata_create_vhost_user_if);
  VAPI_DBG("Assigned msg id %d to create_vhost_user_if", vapi_msg_id_create_vhost_user_if);
}
#endif

#ifndef defined_vapi_msg_modify_vhost_user_if_reply
#define defined_vapi_msg_modify_vhost_user_if_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_modify_vhost_user_if_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_modify_vhost_user_if_reply payload;
} vapi_msg_modify_vhost_user_if_reply;

static inline void vapi_msg_modify_vhost_user_if_reply_payload_hton(vapi_payload_modify_vhost_user_if_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_modify_vhost_user_if_reply_payload_ntoh(vapi_payload_modify_vhost_user_if_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_modify_vhost_user_if_reply_hton(vapi_msg_modify_vhost_user_if_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_modify_vhost_user_if_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_modify_vhost_user_if_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_modify_vhost_user_if_reply_ntoh(vapi_msg_modify_vhost_user_if_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_modify_vhost_user_if_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_modify_vhost_user_if_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_modify_vhost_user_if_reply_msg_size(vapi_msg_modify_vhost_user_if_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_modify_vhost_user_if_reply_msg_size(vapi_msg_modify_vhost_user_if_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_modify_vhost_user_if_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'modify_vhost_user_if_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_modify_vhost_user_if_reply));
      return -1;
    }
  if (vapi_calc_modify_vhost_user_if_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'modify_vhost_user_if_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_modify_vhost_user_if_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_modify_vhost_user_if_reply()
{
  static const char name[] = "modify_vhost_user_if_reply";
  static const char name_with_crc[] = "modify_vhost_user_if_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_modify_vhost_user_if_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_modify_vhost_user_if_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_modify_vhost_user_if_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_modify_vhost_user_if_reply_hton,
    (generic_swap_fn_t)vapi_msg_modify_vhost_user_if_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_modify_vhost_user_if_reply = vapi_register_msg(&__vapi_metadata_modify_vhost_user_if_reply);
  VAPI_DBG("Assigned msg id %d to modify_vhost_user_if_reply", vapi_msg_id_modify_vhost_user_if_reply);
}

static inline void vapi_set_vapi_msg_modify_vhost_user_if_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_modify_vhost_user_if_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_modify_vhost_user_if_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_modify_vhost_user_if
#define defined_vapi_msg_modify_vhost_user_if
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  bool is_server;
  u8 sock_filename[256];
  bool renumber;
  bool enable_gso;
  bool enable_packed;
  u32 custom_dev_instance; 
} vapi_payload_modify_vhost_user_if;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_modify_vhost_user_if payload;
} vapi_msg_modify_vhost_user_if;

static inline void vapi_msg_modify_vhost_user_if_payload_hton(vapi_payload_modify_vhost_user_if *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->custom_dev_instance = htobe32(payload->custom_dev_instance);
}

static inline void vapi_msg_modify_vhost_user_if_payload_ntoh(vapi_payload_modify_vhost_user_if *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->custom_dev_instance = be32toh(payload->custom_dev_instance);
}

static inline void vapi_msg_modify_vhost_user_if_hton(vapi_msg_modify_vhost_user_if *msg)
{
  VAPI_DBG("Swapping `vapi_msg_modify_vhost_user_if'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_modify_vhost_user_if_payload_hton(&msg->payload);
}

static inline void vapi_msg_modify_vhost_user_if_ntoh(vapi_msg_modify_vhost_user_if *msg)
{
  VAPI_DBG("Swapping `vapi_msg_modify_vhost_user_if'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_modify_vhost_user_if_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_modify_vhost_user_if_msg_size(vapi_msg_modify_vhost_user_if *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_modify_vhost_user_if_msg_size(vapi_msg_modify_vhost_user_if *msg, uword buf_size)
{
  if (sizeof(vapi_msg_modify_vhost_user_if) > buf_size)
    {
      VAPI_ERR("Truncated 'modify_vhost_user_if' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_modify_vhost_user_if));
      return -1;
    }
  if (vapi_calc_modify_vhost_user_if_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'modify_vhost_user_if' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_modify_vhost_user_if_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_modify_vhost_user_if* vapi_alloc_modify_vhost_user_if(struct vapi_ctx_s *ctx)
{
  vapi_msg_modify_vhost_user_if *msg = NULL;
  const size_t size = sizeof(vapi_msg_modify_vhost_user_if);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_modify_vhost_user_if*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_modify_vhost_user_if);

  return msg;
}

static inline vapi_error_e vapi_modify_vhost_user_if(struct vapi_ctx_s *ctx,
  vapi_msg_modify_vhost_user_if *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_modify_vhost_user_if_reply *reply),
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
  vapi_msg_modify_vhost_user_if_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_modify_vhost_user_if_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_modify_vhost_user_if_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_modify_vhost_user_if()
{
  static const char name[] = "modify_vhost_user_if";
  static const char name_with_crc[] = "modify_vhost_user_if_0e71d40b";
  static vapi_message_desc_t __vapi_metadata_modify_vhost_user_if = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_modify_vhost_user_if, payload),
    (verify_msg_size_fn_t)vapi_verify_modify_vhost_user_if_msg_size,
    (generic_swap_fn_t)vapi_msg_modify_vhost_user_if_hton,
    (generic_swap_fn_t)vapi_msg_modify_vhost_user_if_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_modify_vhost_user_if = vapi_register_msg(&__vapi_metadata_modify_vhost_user_if);
  VAPI_DBG("Assigned msg id %d to modify_vhost_user_if", vapi_msg_id_modify_vhost_user_if);
}
#endif

#ifndef defined_vapi_msg_create_vhost_user_if_v2_reply
#define defined_vapi_msg_create_vhost_user_if_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_create_vhost_user_if_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_create_vhost_user_if_v2_reply payload;
} vapi_msg_create_vhost_user_if_v2_reply;

static inline void vapi_msg_create_vhost_user_if_v2_reply_payload_hton(vapi_payload_create_vhost_user_if_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_create_vhost_user_if_v2_reply_payload_ntoh(vapi_payload_create_vhost_user_if_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_create_vhost_user_if_v2_reply_hton(vapi_msg_create_vhost_user_if_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_create_vhost_user_if_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_create_vhost_user_if_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_create_vhost_user_if_v2_reply_ntoh(vapi_msg_create_vhost_user_if_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_create_vhost_user_if_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_create_vhost_user_if_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_create_vhost_user_if_v2_reply_msg_size(vapi_msg_create_vhost_user_if_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_create_vhost_user_if_v2_reply_msg_size(vapi_msg_create_vhost_user_if_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_create_vhost_user_if_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'create_vhost_user_if_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_create_vhost_user_if_v2_reply));
      return -1;
    }
  if (vapi_calc_create_vhost_user_if_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'create_vhost_user_if_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_create_vhost_user_if_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_create_vhost_user_if_v2_reply()
{
  static const char name[] = "create_vhost_user_if_v2_reply";
  static const char name_with_crc[] = "create_vhost_user_if_v2_reply_5383d31f";
  static vapi_message_desc_t __vapi_metadata_create_vhost_user_if_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_create_vhost_user_if_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_create_vhost_user_if_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_create_vhost_user_if_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_create_vhost_user_if_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_create_vhost_user_if_v2_reply = vapi_register_msg(&__vapi_metadata_create_vhost_user_if_v2_reply);
  VAPI_DBG("Assigned msg id %d to create_vhost_user_if_v2_reply", vapi_msg_id_create_vhost_user_if_v2_reply);
}

static inline void vapi_set_vapi_msg_create_vhost_user_if_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_create_vhost_user_if_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_create_vhost_user_if_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_create_vhost_user_if_v2
#define defined_vapi_msg_create_vhost_user_if_v2
typedef struct __attribute__ ((__packed__)) {
  bool is_server;
  u8 sock_filename[256];
  bool renumber;
  bool disable_mrg_rxbuf;
  bool disable_indirect_desc;
  bool enable_gso;
  bool enable_packed;
  bool enable_event_idx;
  u32 custom_dev_instance;
  bool use_custom_mac;
  vapi_type_mac_address mac_address;
  u8 tag[64]; 
} vapi_payload_create_vhost_user_if_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_create_vhost_user_if_v2 payload;
} vapi_msg_create_vhost_user_if_v2;

static inline void vapi_msg_create_vhost_user_if_v2_payload_hton(vapi_payload_create_vhost_user_if_v2 *payload)
{
  payload->custom_dev_instance = htobe32(payload->custom_dev_instance);
}

static inline void vapi_msg_create_vhost_user_if_v2_payload_ntoh(vapi_payload_create_vhost_user_if_v2 *payload)
{
  payload->custom_dev_instance = be32toh(payload->custom_dev_instance);
}

static inline void vapi_msg_create_vhost_user_if_v2_hton(vapi_msg_create_vhost_user_if_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_create_vhost_user_if_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_create_vhost_user_if_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_create_vhost_user_if_v2_ntoh(vapi_msg_create_vhost_user_if_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_create_vhost_user_if_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_create_vhost_user_if_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_create_vhost_user_if_v2_msg_size(vapi_msg_create_vhost_user_if_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_create_vhost_user_if_v2_msg_size(vapi_msg_create_vhost_user_if_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_create_vhost_user_if_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'create_vhost_user_if_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_create_vhost_user_if_v2));
      return -1;
    }
  if (vapi_calc_create_vhost_user_if_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'create_vhost_user_if_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_create_vhost_user_if_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_create_vhost_user_if_v2* vapi_alloc_create_vhost_user_if_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_create_vhost_user_if_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_create_vhost_user_if_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_create_vhost_user_if_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_create_vhost_user_if_v2);

  return msg;
}

static inline vapi_error_e vapi_create_vhost_user_if_v2(struct vapi_ctx_s *ctx,
  vapi_msg_create_vhost_user_if_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_create_vhost_user_if_v2_reply *reply),
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
  vapi_msg_create_vhost_user_if_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_create_vhost_user_if_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_create_vhost_user_if_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_create_vhost_user_if_v2()
{
  static const char name[] = "create_vhost_user_if_v2";
  static const char name_with_crc[] = "create_vhost_user_if_v2_dba1cc1d";
  static vapi_message_desc_t __vapi_metadata_create_vhost_user_if_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_create_vhost_user_if_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_create_vhost_user_if_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_create_vhost_user_if_v2_hton,
    (generic_swap_fn_t)vapi_msg_create_vhost_user_if_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_create_vhost_user_if_v2 = vapi_register_msg(&__vapi_metadata_create_vhost_user_if_v2);
  VAPI_DBG("Assigned msg id %d to create_vhost_user_if_v2", vapi_msg_id_create_vhost_user_if_v2);
}
#endif

#ifndef defined_vapi_msg_modify_vhost_user_if_v2_reply
#define defined_vapi_msg_modify_vhost_user_if_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_modify_vhost_user_if_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_modify_vhost_user_if_v2_reply payload;
} vapi_msg_modify_vhost_user_if_v2_reply;

static inline void vapi_msg_modify_vhost_user_if_v2_reply_payload_hton(vapi_payload_modify_vhost_user_if_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_modify_vhost_user_if_v2_reply_payload_ntoh(vapi_payload_modify_vhost_user_if_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_modify_vhost_user_if_v2_reply_hton(vapi_msg_modify_vhost_user_if_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_modify_vhost_user_if_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_modify_vhost_user_if_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_modify_vhost_user_if_v2_reply_ntoh(vapi_msg_modify_vhost_user_if_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_modify_vhost_user_if_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_modify_vhost_user_if_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_modify_vhost_user_if_v2_reply_msg_size(vapi_msg_modify_vhost_user_if_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_modify_vhost_user_if_v2_reply_msg_size(vapi_msg_modify_vhost_user_if_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_modify_vhost_user_if_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'modify_vhost_user_if_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_modify_vhost_user_if_v2_reply));
      return -1;
    }
  if (vapi_calc_modify_vhost_user_if_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'modify_vhost_user_if_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_modify_vhost_user_if_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_modify_vhost_user_if_v2_reply()
{
  static const char name[] = "modify_vhost_user_if_v2_reply";
  static const char name_with_crc[] = "modify_vhost_user_if_v2_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_modify_vhost_user_if_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_modify_vhost_user_if_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_modify_vhost_user_if_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_modify_vhost_user_if_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_modify_vhost_user_if_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_modify_vhost_user_if_v2_reply = vapi_register_msg(&__vapi_metadata_modify_vhost_user_if_v2_reply);
  VAPI_DBG("Assigned msg id %d to modify_vhost_user_if_v2_reply", vapi_msg_id_modify_vhost_user_if_v2_reply);
}

static inline void vapi_set_vapi_msg_modify_vhost_user_if_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_modify_vhost_user_if_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_modify_vhost_user_if_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_modify_vhost_user_if_v2
#define defined_vapi_msg_modify_vhost_user_if_v2
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  bool is_server;
  u8 sock_filename[256];
  bool renumber;
  bool enable_gso;
  bool enable_packed;
  bool enable_event_idx;
  u32 custom_dev_instance; 
} vapi_payload_modify_vhost_user_if_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_modify_vhost_user_if_v2 payload;
} vapi_msg_modify_vhost_user_if_v2;

static inline void vapi_msg_modify_vhost_user_if_v2_payload_hton(vapi_payload_modify_vhost_user_if_v2 *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->custom_dev_instance = htobe32(payload->custom_dev_instance);
}

static inline void vapi_msg_modify_vhost_user_if_v2_payload_ntoh(vapi_payload_modify_vhost_user_if_v2 *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->custom_dev_instance = be32toh(payload->custom_dev_instance);
}

static inline void vapi_msg_modify_vhost_user_if_v2_hton(vapi_msg_modify_vhost_user_if_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_modify_vhost_user_if_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_modify_vhost_user_if_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_modify_vhost_user_if_v2_ntoh(vapi_msg_modify_vhost_user_if_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_modify_vhost_user_if_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_modify_vhost_user_if_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_modify_vhost_user_if_v2_msg_size(vapi_msg_modify_vhost_user_if_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_modify_vhost_user_if_v2_msg_size(vapi_msg_modify_vhost_user_if_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_modify_vhost_user_if_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'modify_vhost_user_if_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_modify_vhost_user_if_v2));
      return -1;
    }
  if (vapi_calc_modify_vhost_user_if_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'modify_vhost_user_if_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_modify_vhost_user_if_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_modify_vhost_user_if_v2* vapi_alloc_modify_vhost_user_if_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_modify_vhost_user_if_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_modify_vhost_user_if_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_modify_vhost_user_if_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_modify_vhost_user_if_v2);

  return msg;
}

static inline vapi_error_e vapi_modify_vhost_user_if_v2(struct vapi_ctx_s *ctx,
  vapi_msg_modify_vhost_user_if_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_modify_vhost_user_if_v2_reply *reply),
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
  vapi_msg_modify_vhost_user_if_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_modify_vhost_user_if_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_modify_vhost_user_if_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_modify_vhost_user_if_v2()
{
  static const char name[] = "modify_vhost_user_if_v2";
  static const char name_with_crc[] = "modify_vhost_user_if_v2_b2483771";
  static vapi_message_desc_t __vapi_metadata_modify_vhost_user_if_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_modify_vhost_user_if_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_modify_vhost_user_if_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_modify_vhost_user_if_v2_hton,
    (generic_swap_fn_t)vapi_msg_modify_vhost_user_if_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_modify_vhost_user_if_v2 = vapi_register_msg(&__vapi_metadata_modify_vhost_user_if_v2);
  VAPI_DBG("Assigned msg id %d to modify_vhost_user_if_v2", vapi_msg_id_modify_vhost_user_if_v2);
}
#endif

#ifndef defined_vapi_msg_delete_vhost_user_if_reply
#define defined_vapi_msg_delete_vhost_user_if_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_delete_vhost_user_if_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_delete_vhost_user_if_reply payload;
} vapi_msg_delete_vhost_user_if_reply;

static inline void vapi_msg_delete_vhost_user_if_reply_payload_hton(vapi_payload_delete_vhost_user_if_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_delete_vhost_user_if_reply_payload_ntoh(vapi_payload_delete_vhost_user_if_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_delete_vhost_user_if_reply_hton(vapi_msg_delete_vhost_user_if_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_delete_vhost_user_if_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_delete_vhost_user_if_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_delete_vhost_user_if_reply_ntoh(vapi_msg_delete_vhost_user_if_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_delete_vhost_user_if_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_delete_vhost_user_if_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_delete_vhost_user_if_reply_msg_size(vapi_msg_delete_vhost_user_if_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_delete_vhost_user_if_reply_msg_size(vapi_msg_delete_vhost_user_if_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_delete_vhost_user_if_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'delete_vhost_user_if_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_delete_vhost_user_if_reply));
      return -1;
    }
  if (vapi_calc_delete_vhost_user_if_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'delete_vhost_user_if_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_delete_vhost_user_if_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_delete_vhost_user_if_reply()
{
  static const char name[] = "delete_vhost_user_if_reply";
  static const char name_with_crc[] = "delete_vhost_user_if_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_delete_vhost_user_if_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_delete_vhost_user_if_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_delete_vhost_user_if_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_delete_vhost_user_if_reply_hton,
    (generic_swap_fn_t)vapi_msg_delete_vhost_user_if_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_delete_vhost_user_if_reply = vapi_register_msg(&__vapi_metadata_delete_vhost_user_if_reply);
  VAPI_DBG("Assigned msg id %d to delete_vhost_user_if_reply", vapi_msg_id_delete_vhost_user_if_reply);
}

static inline void vapi_set_vapi_msg_delete_vhost_user_if_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_delete_vhost_user_if_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_delete_vhost_user_if_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_delete_vhost_user_if
#define defined_vapi_msg_delete_vhost_user_if
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_delete_vhost_user_if;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_delete_vhost_user_if payload;
} vapi_msg_delete_vhost_user_if;

static inline void vapi_msg_delete_vhost_user_if_payload_hton(vapi_payload_delete_vhost_user_if *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_delete_vhost_user_if_payload_ntoh(vapi_payload_delete_vhost_user_if *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_delete_vhost_user_if_hton(vapi_msg_delete_vhost_user_if *msg)
{
  VAPI_DBG("Swapping `vapi_msg_delete_vhost_user_if'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_delete_vhost_user_if_payload_hton(&msg->payload);
}

static inline void vapi_msg_delete_vhost_user_if_ntoh(vapi_msg_delete_vhost_user_if *msg)
{
  VAPI_DBG("Swapping `vapi_msg_delete_vhost_user_if'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_delete_vhost_user_if_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_delete_vhost_user_if_msg_size(vapi_msg_delete_vhost_user_if *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_delete_vhost_user_if_msg_size(vapi_msg_delete_vhost_user_if *msg, uword buf_size)
{
  if (sizeof(vapi_msg_delete_vhost_user_if) > buf_size)
    {
      VAPI_ERR("Truncated 'delete_vhost_user_if' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_delete_vhost_user_if));
      return -1;
    }
  if (vapi_calc_delete_vhost_user_if_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'delete_vhost_user_if' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_delete_vhost_user_if_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_delete_vhost_user_if* vapi_alloc_delete_vhost_user_if(struct vapi_ctx_s *ctx)
{
  vapi_msg_delete_vhost_user_if *msg = NULL;
  const size_t size = sizeof(vapi_msg_delete_vhost_user_if);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_delete_vhost_user_if*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_delete_vhost_user_if);

  return msg;
}

static inline vapi_error_e vapi_delete_vhost_user_if(struct vapi_ctx_s *ctx,
  vapi_msg_delete_vhost_user_if *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_delete_vhost_user_if_reply *reply),
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
  vapi_msg_delete_vhost_user_if_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_delete_vhost_user_if_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_delete_vhost_user_if_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_delete_vhost_user_if()
{
  static const char name[] = "delete_vhost_user_if";
  static const char name_with_crc[] = "delete_vhost_user_if_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_delete_vhost_user_if = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_delete_vhost_user_if, payload),
    (verify_msg_size_fn_t)vapi_verify_delete_vhost_user_if_msg_size,
    (generic_swap_fn_t)vapi_msg_delete_vhost_user_if_hton,
    (generic_swap_fn_t)vapi_msg_delete_vhost_user_if_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_delete_vhost_user_if = vapi_register_msg(&__vapi_metadata_delete_vhost_user_if);
  VAPI_DBG("Assigned msg id %d to delete_vhost_user_if", vapi_msg_id_delete_vhost_user_if);
}
#endif

#ifndef defined_vapi_msg_sw_interface_vhost_user_details
#define defined_vapi_msg_sw_interface_vhost_user_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u8 interface_name[64];
  u32 virtio_net_hdr_sz;
  vapi_enum_virtio_net_features_first_32 features_first_32;
  vapi_enum_virtio_net_features_last_32 features_last_32;
  bool is_server;
  u8 sock_filename[256];
  u32 num_regions;
  i32 sock_errno; 
} vapi_payload_sw_interface_vhost_user_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sw_interface_vhost_user_details payload;
} vapi_msg_sw_interface_vhost_user_details;

static inline void vapi_msg_sw_interface_vhost_user_details_payload_hton(vapi_payload_sw_interface_vhost_user_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->virtio_net_hdr_sz = htobe32(payload->virtio_net_hdr_sz);
  payload->features_first_32 = (vapi_enum_virtio_net_features_first_32)htobe32(payload->features_first_32);
  payload->features_last_32 = (vapi_enum_virtio_net_features_last_32)htobe32(payload->features_last_32);
  payload->num_regions = htobe32(payload->num_regions);
  payload->sock_errno = htobe32(payload->sock_errno);
}

static inline void vapi_msg_sw_interface_vhost_user_details_payload_ntoh(vapi_payload_sw_interface_vhost_user_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->virtio_net_hdr_sz = be32toh(payload->virtio_net_hdr_sz);
  payload->features_first_32 = (vapi_enum_virtio_net_features_first_32)be32toh(payload->features_first_32);
  payload->features_last_32 = (vapi_enum_virtio_net_features_last_32)be32toh(payload->features_last_32);
  payload->num_regions = be32toh(payload->num_regions);
  payload->sock_errno = be32toh(payload->sock_errno);
}

static inline void vapi_msg_sw_interface_vhost_user_details_hton(vapi_msg_sw_interface_vhost_user_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_vhost_user_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sw_interface_vhost_user_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_vhost_user_details_ntoh(vapi_msg_sw_interface_vhost_user_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_vhost_user_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sw_interface_vhost_user_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_vhost_user_details_msg_size(vapi_msg_sw_interface_vhost_user_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_vhost_user_details_msg_size(vapi_msg_sw_interface_vhost_user_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_vhost_user_details) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_vhost_user_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_vhost_user_details));
      return -1;
    }
  if (vapi_calc_sw_interface_vhost_user_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_vhost_user_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_vhost_user_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sw_interface_vhost_user_details()
{
  static const char name[] = "sw_interface_vhost_user_details";
  static const char name_with_crc[] = "sw_interface_vhost_user_details_0cee1e53";
  static vapi_message_desc_t __vapi_metadata_sw_interface_vhost_user_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sw_interface_vhost_user_details, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_vhost_user_details_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_vhost_user_details_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_vhost_user_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_vhost_user_details = vapi_register_msg(&__vapi_metadata_sw_interface_vhost_user_details);
  VAPI_DBG("Assigned msg id %d to sw_interface_vhost_user_details", vapi_msg_id_sw_interface_vhost_user_details);
}

static inline void vapi_set_vapi_msg_sw_interface_vhost_user_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sw_interface_vhost_user_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sw_interface_vhost_user_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sw_interface_vhost_user_dump
#define defined_vapi_msg_sw_interface_vhost_user_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_sw_interface_vhost_user_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sw_interface_vhost_user_dump payload;
} vapi_msg_sw_interface_vhost_user_dump;

static inline void vapi_msg_sw_interface_vhost_user_dump_payload_hton(vapi_payload_sw_interface_vhost_user_dump *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_sw_interface_vhost_user_dump_payload_ntoh(vapi_payload_sw_interface_vhost_user_dump *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_sw_interface_vhost_user_dump_hton(vapi_msg_sw_interface_vhost_user_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_vhost_user_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sw_interface_vhost_user_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_vhost_user_dump_ntoh(vapi_msg_sw_interface_vhost_user_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_vhost_user_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sw_interface_vhost_user_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_vhost_user_dump_msg_size(vapi_msg_sw_interface_vhost_user_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_vhost_user_dump_msg_size(vapi_msg_sw_interface_vhost_user_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_vhost_user_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_vhost_user_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_vhost_user_dump));
      return -1;
    }
  if (vapi_calc_sw_interface_vhost_user_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_vhost_user_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_vhost_user_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sw_interface_vhost_user_dump* vapi_alloc_sw_interface_vhost_user_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_sw_interface_vhost_user_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_sw_interface_vhost_user_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sw_interface_vhost_user_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sw_interface_vhost_user_dump);

  return msg;
}

static inline vapi_error_e vapi_sw_interface_vhost_user_dump(struct vapi_ctx_s *ctx,
  vapi_msg_sw_interface_vhost_user_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sw_interface_vhost_user_details *reply),
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
  vapi_msg_sw_interface_vhost_user_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sw_interface_vhost_user_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_sw_interface_vhost_user_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sw_interface_vhost_user_dump()
{
  static const char name[] = "sw_interface_vhost_user_dump";
  static const char name_with_crc[] = "sw_interface_vhost_user_dump_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_sw_interface_vhost_user_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sw_interface_vhost_user_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_vhost_user_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_vhost_user_dump_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_vhost_user_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_vhost_user_dump = vapi_register_msg(&__vapi_metadata_sw_interface_vhost_user_dump);
  VAPI_DBG("Assigned msg id %d to sw_interface_vhost_user_dump", vapi_msg_id_sw_interface_vhost_user_dump);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
