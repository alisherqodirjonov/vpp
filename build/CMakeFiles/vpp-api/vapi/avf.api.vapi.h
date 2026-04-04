#ifndef __included_avf_api_json
#define __included_avf_api_json

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

extern vapi_msg_id_t vapi_msg_id_avf_create;
extern vapi_msg_id_t vapi_msg_id_avf_create_reply;
extern vapi_msg_id_t vapi_msg_id_avf_delete;
extern vapi_msg_id_t vapi_msg_id_avf_delete_reply;

#define DEFINE_VAPI_MSG_IDS_AVF_API_JSON\
  vapi_msg_id_t vapi_msg_id_avf_create;\
  vapi_msg_id_t vapi_msg_id_avf_create_reply;\
  vapi_msg_id_t vapi_msg_id_avf_delete;\
  vapi_msg_id_t vapi_msg_id_avf_delete_reply;


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

#ifndef defined_vapi_msg_avf_create_reply
#define defined_vapi_msg_avf_create_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_avf_create_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_avf_create_reply payload;
} vapi_msg_avf_create_reply;

static inline void vapi_msg_avf_create_reply_payload_hton(vapi_payload_avf_create_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_avf_create_reply_payload_ntoh(vapi_payload_avf_create_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_avf_create_reply_hton(vapi_msg_avf_create_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_avf_create_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_avf_create_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_avf_create_reply_ntoh(vapi_msg_avf_create_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_avf_create_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_avf_create_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_avf_create_reply_msg_size(vapi_msg_avf_create_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_avf_create_reply_msg_size(vapi_msg_avf_create_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_avf_create_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'avf_create_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_avf_create_reply));
      return -1;
    }
  if (vapi_calc_avf_create_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'avf_create_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_avf_create_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_avf_create_reply()
{
  static const char name[] = "avf_create_reply";
  static const char name_with_crc[] = "avf_create_reply_5383d31f";
  static vapi_message_desc_t __vapi_metadata_avf_create_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_avf_create_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_avf_create_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_avf_create_reply_hton,
    (generic_swap_fn_t)vapi_msg_avf_create_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_avf_create_reply = vapi_register_msg(&__vapi_metadata_avf_create_reply);
  VAPI_DBG("Assigned msg id %d to avf_create_reply", vapi_msg_id_avf_create_reply);
}

static inline void vapi_set_vapi_msg_avf_create_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_avf_create_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_avf_create_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_avf_create
#define defined_vapi_msg_avf_create
typedef struct __attribute__ ((__packed__)) {
  u32 pci_addr;
  i32 enable_elog;
  u16 rxq_num;
  u16 rxq_size;
  u16 txq_size; 
} vapi_payload_avf_create;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_avf_create payload;
} vapi_msg_avf_create;

static inline void vapi_msg_avf_create_payload_hton(vapi_payload_avf_create *payload)
{
  payload->pci_addr = htobe32(payload->pci_addr);
  payload->enable_elog = htobe32(payload->enable_elog);
  payload->rxq_num = htobe16(payload->rxq_num);
  payload->rxq_size = htobe16(payload->rxq_size);
  payload->txq_size = htobe16(payload->txq_size);
}

static inline void vapi_msg_avf_create_payload_ntoh(vapi_payload_avf_create *payload)
{
  payload->pci_addr = be32toh(payload->pci_addr);
  payload->enable_elog = be32toh(payload->enable_elog);
  payload->rxq_num = be16toh(payload->rxq_num);
  payload->rxq_size = be16toh(payload->rxq_size);
  payload->txq_size = be16toh(payload->txq_size);
}

static inline void vapi_msg_avf_create_hton(vapi_msg_avf_create *msg)
{
  VAPI_DBG("Swapping `vapi_msg_avf_create'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_avf_create_payload_hton(&msg->payload);
}

static inline void vapi_msg_avf_create_ntoh(vapi_msg_avf_create *msg)
{
  VAPI_DBG("Swapping `vapi_msg_avf_create'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_avf_create_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_avf_create_msg_size(vapi_msg_avf_create *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_avf_create_msg_size(vapi_msg_avf_create *msg, uword buf_size)
{
  if (sizeof(vapi_msg_avf_create) > buf_size)
    {
      VAPI_ERR("Truncated 'avf_create' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_avf_create));
      return -1;
    }
  if (vapi_calc_avf_create_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'avf_create' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_avf_create_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_avf_create* vapi_alloc_avf_create(struct vapi_ctx_s *ctx)
{
  vapi_msg_avf_create *msg = NULL;
  const size_t size = sizeof(vapi_msg_avf_create);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_avf_create*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_avf_create);

  return msg;
}

static inline vapi_error_e vapi_avf_create(struct vapi_ctx_s *ctx,
  vapi_msg_avf_create *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_avf_create_reply *reply),
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
  vapi_msg_avf_create_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_avf_create_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_avf_create_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_avf_create()
{
  static const char name[] = "avf_create";
  static const char name_with_crc[] = "avf_create_daab8ae2";
  static vapi_message_desc_t __vapi_metadata_avf_create = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_avf_create, payload),
    (verify_msg_size_fn_t)vapi_verify_avf_create_msg_size,
    (generic_swap_fn_t)vapi_msg_avf_create_hton,
    (generic_swap_fn_t)vapi_msg_avf_create_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_avf_create = vapi_register_msg(&__vapi_metadata_avf_create);
  VAPI_DBG("Assigned msg id %d to avf_create", vapi_msg_id_avf_create);
}
#endif

#ifndef defined_vapi_msg_avf_delete_reply
#define defined_vapi_msg_avf_delete_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_avf_delete_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_avf_delete_reply payload;
} vapi_msg_avf_delete_reply;

static inline void vapi_msg_avf_delete_reply_payload_hton(vapi_payload_avf_delete_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_avf_delete_reply_payload_ntoh(vapi_payload_avf_delete_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_avf_delete_reply_hton(vapi_msg_avf_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_avf_delete_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_avf_delete_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_avf_delete_reply_ntoh(vapi_msg_avf_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_avf_delete_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_avf_delete_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_avf_delete_reply_msg_size(vapi_msg_avf_delete_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_avf_delete_reply_msg_size(vapi_msg_avf_delete_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_avf_delete_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'avf_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_avf_delete_reply));
      return -1;
    }
  if (vapi_calc_avf_delete_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'avf_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_avf_delete_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_avf_delete_reply()
{
  static const char name[] = "avf_delete_reply";
  static const char name_with_crc[] = "avf_delete_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_avf_delete_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_avf_delete_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_avf_delete_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_avf_delete_reply_hton,
    (generic_swap_fn_t)vapi_msg_avf_delete_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_avf_delete_reply = vapi_register_msg(&__vapi_metadata_avf_delete_reply);
  VAPI_DBG("Assigned msg id %d to avf_delete_reply", vapi_msg_id_avf_delete_reply);
}

static inline void vapi_set_vapi_msg_avf_delete_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_avf_delete_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_avf_delete_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_avf_delete
#define defined_vapi_msg_avf_delete
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_avf_delete;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_avf_delete payload;
} vapi_msg_avf_delete;

static inline void vapi_msg_avf_delete_payload_hton(vapi_payload_avf_delete *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_avf_delete_payload_ntoh(vapi_payload_avf_delete *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_avf_delete_hton(vapi_msg_avf_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_avf_delete'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_avf_delete_payload_hton(&msg->payload);
}

static inline void vapi_msg_avf_delete_ntoh(vapi_msg_avf_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_avf_delete'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_avf_delete_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_avf_delete_msg_size(vapi_msg_avf_delete *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_avf_delete_msg_size(vapi_msg_avf_delete *msg, uword buf_size)
{
  if (sizeof(vapi_msg_avf_delete) > buf_size)
    {
      VAPI_ERR("Truncated 'avf_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_avf_delete));
      return -1;
    }
  if (vapi_calc_avf_delete_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'avf_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_avf_delete_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_avf_delete* vapi_alloc_avf_delete(struct vapi_ctx_s *ctx)
{
  vapi_msg_avf_delete *msg = NULL;
  const size_t size = sizeof(vapi_msg_avf_delete);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_avf_delete*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_avf_delete);

  return msg;
}

static inline vapi_error_e vapi_avf_delete(struct vapi_ctx_s *ctx,
  vapi_msg_avf_delete *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_avf_delete_reply *reply),
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
  vapi_msg_avf_delete_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_avf_delete_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_avf_delete_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_avf_delete()
{
  static const char name[] = "avf_delete";
  static const char name_with_crc[] = "avf_delete_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_avf_delete = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_avf_delete, payload),
    (verify_msg_size_fn_t)vapi_verify_avf_delete_msg_size,
    (generic_swap_fn_t)vapi_msg_avf_delete_hton,
    (generic_swap_fn_t)vapi_msg_avf_delete_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_avf_delete = vapi_register_msg(&__vapi_metadata_avf_delete);
  VAPI_DBG("Assigned msg id %d to avf_delete", vapi_msg_id_avf_delete);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
