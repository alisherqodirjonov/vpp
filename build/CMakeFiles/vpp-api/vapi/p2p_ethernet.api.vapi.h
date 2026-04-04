#ifndef __included_p2p_ethernet_api_json
#define __included_p2p_ethernet_api_json

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

extern vapi_msg_id_t vapi_msg_id_p2p_ethernet_add;
extern vapi_msg_id_t vapi_msg_id_p2p_ethernet_add_reply;
extern vapi_msg_id_t vapi_msg_id_p2p_ethernet_del;
extern vapi_msg_id_t vapi_msg_id_p2p_ethernet_del_reply;

#define DEFINE_VAPI_MSG_IDS_P2P_ETHERNET_API_JSON\
  vapi_msg_id_t vapi_msg_id_p2p_ethernet_add;\
  vapi_msg_id_t vapi_msg_id_p2p_ethernet_add_reply;\
  vapi_msg_id_t vapi_msg_id_p2p_ethernet_del;\
  vapi_msg_id_t vapi_msg_id_p2p_ethernet_del_reply;


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

#ifndef defined_vapi_type_mac_address
#define defined_vapi_type_mac_address
typedef u8 vapi_type_mac_address[6];

#endif

#ifndef defined_vapi_msg_p2p_ethernet_add_reply
#define defined_vapi_msg_p2p_ethernet_add_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_p2p_ethernet_add_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_p2p_ethernet_add_reply payload;
} vapi_msg_p2p_ethernet_add_reply;

static inline void vapi_msg_p2p_ethernet_add_reply_payload_hton(vapi_payload_p2p_ethernet_add_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_p2p_ethernet_add_reply_payload_ntoh(vapi_payload_p2p_ethernet_add_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_p2p_ethernet_add_reply_hton(vapi_msg_p2p_ethernet_add_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_p2p_ethernet_add_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_p2p_ethernet_add_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_p2p_ethernet_add_reply_ntoh(vapi_msg_p2p_ethernet_add_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_p2p_ethernet_add_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_p2p_ethernet_add_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_p2p_ethernet_add_reply_msg_size(vapi_msg_p2p_ethernet_add_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_p2p_ethernet_add_reply_msg_size(vapi_msg_p2p_ethernet_add_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_p2p_ethernet_add_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'p2p_ethernet_add_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_p2p_ethernet_add_reply));
      return -1;
    }
  if (vapi_calc_p2p_ethernet_add_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'p2p_ethernet_add_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_p2p_ethernet_add_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_p2p_ethernet_add_reply()
{
  static const char name[] = "p2p_ethernet_add_reply";
  static const char name_with_crc[] = "p2p_ethernet_add_reply_5383d31f";
  static vapi_message_desc_t __vapi_metadata_p2p_ethernet_add_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_p2p_ethernet_add_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_p2p_ethernet_add_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_p2p_ethernet_add_reply_hton,
    (generic_swap_fn_t)vapi_msg_p2p_ethernet_add_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_p2p_ethernet_add_reply = vapi_register_msg(&__vapi_metadata_p2p_ethernet_add_reply);
  VAPI_DBG("Assigned msg id %d to p2p_ethernet_add_reply", vapi_msg_id_p2p_ethernet_add_reply);
}

static inline void vapi_set_vapi_msg_p2p_ethernet_add_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_p2p_ethernet_add_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_p2p_ethernet_add_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_p2p_ethernet_add
#define defined_vapi_msg_p2p_ethernet_add
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index parent_if_index;
  u32 subif_id;
  vapi_type_mac_address remote_mac; 
} vapi_payload_p2p_ethernet_add;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_p2p_ethernet_add payload;
} vapi_msg_p2p_ethernet_add;

static inline void vapi_msg_p2p_ethernet_add_payload_hton(vapi_payload_p2p_ethernet_add *payload)
{
  payload->parent_if_index = htobe32(payload->parent_if_index);
  payload->subif_id = htobe32(payload->subif_id);
}

static inline void vapi_msg_p2p_ethernet_add_payload_ntoh(vapi_payload_p2p_ethernet_add *payload)
{
  payload->parent_if_index = be32toh(payload->parent_if_index);
  payload->subif_id = be32toh(payload->subif_id);
}

static inline void vapi_msg_p2p_ethernet_add_hton(vapi_msg_p2p_ethernet_add *msg)
{
  VAPI_DBG("Swapping `vapi_msg_p2p_ethernet_add'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_p2p_ethernet_add_payload_hton(&msg->payload);
}

static inline void vapi_msg_p2p_ethernet_add_ntoh(vapi_msg_p2p_ethernet_add *msg)
{
  VAPI_DBG("Swapping `vapi_msg_p2p_ethernet_add'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_p2p_ethernet_add_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_p2p_ethernet_add_msg_size(vapi_msg_p2p_ethernet_add *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_p2p_ethernet_add_msg_size(vapi_msg_p2p_ethernet_add *msg, uword buf_size)
{
  if (sizeof(vapi_msg_p2p_ethernet_add) > buf_size)
    {
      VAPI_ERR("Truncated 'p2p_ethernet_add' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_p2p_ethernet_add));
      return -1;
    }
  if (vapi_calc_p2p_ethernet_add_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'p2p_ethernet_add' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_p2p_ethernet_add_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_p2p_ethernet_add* vapi_alloc_p2p_ethernet_add(struct vapi_ctx_s *ctx)
{
  vapi_msg_p2p_ethernet_add *msg = NULL;
  const size_t size = sizeof(vapi_msg_p2p_ethernet_add);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_p2p_ethernet_add*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_p2p_ethernet_add);

  return msg;
}

static inline vapi_error_e vapi_p2p_ethernet_add(struct vapi_ctx_s *ctx,
  vapi_msg_p2p_ethernet_add *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_p2p_ethernet_add_reply *reply),
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
  vapi_msg_p2p_ethernet_add_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_p2p_ethernet_add_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_p2p_ethernet_add_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_p2p_ethernet_add()
{
  static const char name[] = "p2p_ethernet_add";
  static const char name_with_crc[] = "p2p_ethernet_add_36a1a6dc";
  static vapi_message_desc_t __vapi_metadata_p2p_ethernet_add = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_p2p_ethernet_add, payload),
    (verify_msg_size_fn_t)vapi_verify_p2p_ethernet_add_msg_size,
    (generic_swap_fn_t)vapi_msg_p2p_ethernet_add_hton,
    (generic_swap_fn_t)vapi_msg_p2p_ethernet_add_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_p2p_ethernet_add = vapi_register_msg(&__vapi_metadata_p2p_ethernet_add);
  VAPI_DBG("Assigned msg id %d to p2p_ethernet_add", vapi_msg_id_p2p_ethernet_add);
}
#endif

#ifndef defined_vapi_msg_p2p_ethernet_del_reply
#define defined_vapi_msg_p2p_ethernet_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_p2p_ethernet_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_p2p_ethernet_del_reply payload;
} vapi_msg_p2p_ethernet_del_reply;

static inline void vapi_msg_p2p_ethernet_del_reply_payload_hton(vapi_payload_p2p_ethernet_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_p2p_ethernet_del_reply_payload_ntoh(vapi_payload_p2p_ethernet_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_p2p_ethernet_del_reply_hton(vapi_msg_p2p_ethernet_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_p2p_ethernet_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_p2p_ethernet_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_p2p_ethernet_del_reply_ntoh(vapi_msg_p2p_ethernet_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_p2p_ethernet_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_p2p_ethernet_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_p2p_ethernet_del_reply_msg_size(vapi_msg_p2p_ethernet_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_p2p_ethernet_del_reply_msg_size(vapi_msg_p2p_ethernet_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_p2p_ethernet_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'p2p_ethernet_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_p2p_ethernet_del_reply));
      return -1;
    }
  if (vapi_calc_p2p_ethernet_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'p2p_ethernet_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_p2p_ethernet_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_p2p_ethernet_del_reply()
{
  static const char name[] = "p2p_ethernet_del_reply";
  static const char name_with_crc[] = "p2p_ethernet_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_p2p_ethernet_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_p2p_ethernet_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_p2p_ethernet_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_p2p_ethernet_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_p2p_ethernet_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_p2p_ethernet_del_reply = vapi_register_msg(&__vapi_metadata_p2p_ethernet_del_reply);
  VAPI_DBG("Assigned msg id %d to p2p_ethernet_del_reply", vapi_msg_id_p2p_ethernet_del_reply);
}

static inline void vapi_set_vapi_msg_p2p_ethernet_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_p2p_ethernet_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_p2p_ethernet_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_p2p_ethernet_del
#define defined_vapi_msg_p2p_ethernet_del
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index parent_if_index;
  vapi_type_mac_address remote_mac; 
} vapi_payload_p2p_ethernet_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_p2p_ethernet_del payload;
} vapi_msg_p2p_ethernet_del;

static inline void vapi_msg_p2p_ethernet_del_payload_hton(vapi_payload_p2p_ethernet_del *payload)
{
  payload->parent_if_index = htobe32(payload->parent_if_index);
}

static inline void vapi_msg_p2p_ethernet_del_payload_ntoh(vapi_payload_p2p_ethernet_del *payload)
{
  payload->parent_if_index = be32toh(payload->parent_if_index);
}

static inline void vapi_msg_p2p_ethernet_del_hton(vapi_msg_p2p_ethernet_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_p2p_ethernet_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_p2p_ethernet_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_p2p_ethernet_del_ntoh(vapi_msg_p2p_ethernet_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_p2p_ethernet_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_p2p_ethernet_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_p2p_ethernet_del_msg_size(vapi_msg_p2p_ethernet_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_p2p_ethernet_del_msg_size(vapi_msg_p2p_ethernet_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_p2p_ethernet_del) > buf_size)
    {
      VAPI_ERR("Truncated 'p2p_ethernet_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_p2p_ethernet_del));
      return -1;
    }
  if (vapi_calc_p2p_ethernet_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'p2p_ethernet_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_p2p_ethernet_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_p2p_ethernet_del* vapi_alloc_p2p_ethernet_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_p2p_ethernet_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_p2p_ethernet_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_p2p_ethernet_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_p2p_ethernet_del);

  return msg;
}

static inline vapi_error_e vapi_p2p_ethernet_del(struct vapi_ctx_s *ctx,
  vapi_msg_p2p_ethernet_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_p2p_ethernet_del_reply *reply),
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
  vapi_msg_p2p_ethernet_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_p2p_ethernet_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_p2p_ethernet_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_p2p_ethernet_del()
{
  static const char name[] = "p2p_ethernet_del";
  static const char name_with_crc[] = "p2p_ethernet_del_62f81c8c";
  static vapi_message_desc_t __vapi_metadata_p2p_ethernet_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_p2p_ethernet_del, payload),
    (verify_msg_size_fn_t)vapi_verify_p2p_ethernet_del_msg_size,
    (generic_swap_fn_t)vapi_msg_p2p_ethernet_del_hton,
    (generic_swap_fn_t)vapi_msg_p2p_ethernet_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_p2p_ethernet_del = vapi_register_msg(&__vapi_metadata_p2p_ethernet_del);
  VAPI_DBG("Assigned msg id %d to p2p_ethernet_del", vapi_msg_id_p2p_ethernet_del);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
