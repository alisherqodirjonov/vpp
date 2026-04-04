#ifndef __included_vmxnet3_api_json
#define __included_vmxnet3_api_json

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

extern vapi_msg_id_t vapi_msg_id_vmxnet3_create;
extern vapi_msg_id_t vapi_msg_id_vmxnet3_create_reply;
extern vapi_msg_id_t vapi_msg_id_vmxnet3_delete;
extern vapi_msg_id_t vapi_msg_id_vmxnet3_delete_reply;
extern vapi_msg_id_t vapi_msg_id_vmxnet3_details;
extern vapi_msg_id_t vapi_msg_id_vmxnet3_dump;
extern vapi_msg_id_t vapi_msg_id_sw_vmxnet3_interface_dump;
extern vapi_msg_id_t vapi_msg_id_sw_vmxnet3_interface_details;

#define DEFINE_VAPI_MSG_IDS_VMXNET3_API_JSON\
  vapi_msg_id_t vapi_msg_id_vmxnet3_create;\
  vapi_msg_id_t vapi_msg_id_vmxnet3_create_reply;\
  vapi_msg_id_t vapi_msg_id_vmxnet3_delete;\
  vapi_msg_id_t vapi_msg_id_vmxnet3_delete_reply;\
  vapi_msg_id_t vapi_msg_id_vmxnet3_details;\
  vapi_msg_id_t vapi_msg_id_vmxnet3_dump;\
  vapi_msg_id_t vapi_msg_id_sw_vmxnet3_interface_dump;\
  vapi_msg_id_t vapi_msg_id_sw_vmxnet3_interface_details;


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

#ifndef defined_vapi_type_vmxnet3_tx_list
#define defined_vapi_type_vmxnet3_tx_list
typedef struct __attribute__((__packed__)) {
  u16 tx_qsize;
  u16 tx_next;
  u16 tx_produce;
  u16 tx_consume;
} vapi_type_vmxnet3_tx_list;

static inline void vapi_type_vmxnet3_tx_list_hton(vapi_type_vmxnet3_tx_list *msg)
{
  msg->tx_qsize = htobe16(msg->tx_qsize);
  msg->tx_next = htobe16(msg->tx_next);
  msg->tx_produce = htobe16(msg->tx_produce);
  msg->tx_consume = htobe16(msg->tx_consume);
}

static inline void vapi_type_vmxnet3_tx_list_ntoh(vapi_type_vmxnet3_tx_list *msg)
{
  msg->tx_qsize = be16toh(msg->tx_qsize);
  msg->tx_next = be16toh(msg->tx_next);
  msg->tx_produce = be16toh(msg->tx_produce);
  msg->tx_consume = be16toh(msg->tx_consume);
}
#endif

#ifndef defined_vapi_type_vmxnet3_rx_list
#define defined_vapi_type_vmxnet3_rx_list
typedef struct __attribute__((__packed__)) {
  u16 rx_qsize;
  u16 rx_fill[2];
  u16 rx_next;
  u16 rx_produce[2];
  u16 rx_consume[2];
} vapi_type_vmxnet3_rx_list;

static inline void vapi_type_vmxnet3_rx_list_hton(vapi_type_vmxnet3_rx_list *msg)
{
  msg->rx_qsize = htobe16(msg->rx_qsize);
  do { unsigned i; for (i = 0; i < 2; ++i) { msg->rx_fill[i] = htobe16(msg->rx_fill[i]); } } while(0);
  msg->rx_next = htobe16(msg->rx_next);
  do { unsigned i; for (i = 0; i < 2; ++i) { msg->rx_produce[i] = htobe16(msg->rx_produce[i]); } } while(0);
  do { unsigned i; for (i = 0; i < 2; ++i) { msg->rx_consume[i] = htobe16(msg->rx_consume[i]); } } while(0);
}

static inline void vapi_type_vmxnet3_rx_list_ntoh(vapi_type_vmxnet3_rx_list *msg)
{
  msg->rx_qsize = be16toh(msg->rx_qsize);
  do { unsigned i; for (i = 0; i < 2; ++i) { msg->rx_fill[i] = be16toh(msg->rx_fill[i]); } } while(0);
  msg->rx_next = be16toh(msg->rx_next);
  do { unsigned i; for (i = 0; i < 2; ++i) { msg->rx_produce[i] = be16toh(msg->rx_produce[i]); } } while(0);
  do { unsigned i; for (i = 0; i < 2; ++i) { msg->rx_consume[i] = be16toh(msg->rx_consume[i]); } } while(0);
}
#endif

#ifndef defined_vapi_type_interface_index
#define defined_vapi_type_interface_index
typedef u32 vapi_type_interface_index;

#endif

#ifndef defined_vapi_type_mac_address
#define defined_vapi_type_mac_address
typedef u8 vapi_type_mac_address[6];

#endif

#ifndef defined_vapi_msg_vmxnet3_create_reply
#define defined_vapi_msg_vmxnet3_create_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_vmxnet3_create_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_vmxnet3_create_reply payload;
} vapi_msg_vmxnet3_create_reply;

static inline void vapi_msg_vmxnet3_create_reply_payload_hton(vapi_payload_vmxnet3_create_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_vmxnet3_create_reply_payload_ntoh(vapi_payload_vmxnet3_create_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_vmxnet3_create_reply_hton(vapi_msg_vmxnet3_create_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_vmxnet3_create_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_vmxnet3_create_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_vmxnet3_create_reply_ntoh(vapi_msg_vmxnet3_create_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_vmxnet3_create_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_vmxnet3_create_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_vmxnet3_create_reply_msg_size(vapi_msg_vmxnet3_create_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_vmxnet3_create_reply_msg_size(vapi_msg_vmxnet3_create_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_vmxnet3_create_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'vmxnet3_create_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_vmxnet3_create_reply));
      return -1;
    }
  if (vapi_calc_vmxnet3_create_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'vmxnet3_create_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_vmxnet3_create_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_vmxnet3_create_reply()
{
  static const char name[] = "vmxnet3_create_reply";
  static const char name_with_crc[] = "vmxnet3_create_reply_5383d31f";
  static vapi_message_desc_t __vapi_metadata_vmxnet3_create_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_vmxnet3_create_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_vmxnet3_create_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_vmxnet3_create_reply_hton,
    (generic_swap_fn_t)vapi_msg_vmxnet3_create_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_vmxnet3_create_reply = vapi_register_msg(&__vapi_metadata_vmxnet3_create_reply);
  VAPI_DBG("Assigned msg id %d to vmxnet3_create_reply", vapi_msg_id_vmxnet3_create_reply);
}

static inline void vapi_set_vapi_msg_vmxnet3_create_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_vmxnet3_create_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_vmxnet3_create_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_vmxnet3_create
#define defined_vapi_msg_vmxnet3_create
typedef struct __attribute__ ((__packed__)) {
  u32 pci_addr;
  i32 enable_elog;
  u16 rxq_size;
  u16 rxq_num;
  u16 txq_size;
  u16 txq_num;
  u8 bind;
  bool enable_gso; 
} vapi_payload_vmxnet3_create;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_vmxnet3_create payload;
} vapi_msg_vmxnet3_create;

static inline void vapi_msg_vmxnet3_create_payload_hton(vapi_payload_vmxnet3_create *payload)
{
  payload->pci_addr = htobe32(payload->pci_addr);
  payload->enable_elog = htobe32(payload->enable_elog);
  payload->rxq_size = htobe16(payload->rxq_size);
  payload->rxq_num = htobe16(payload->rxq_num);
  payload->txq_size = htobe16(payload->txq_size);
  payload->txq_num = htobe16(payload->txq_num);
}

static inline void vapi_msg_vmxnet3_create_payload_ntoh(vapi_payload_vmxnet3_create *payload)
{
  payload->pci_addr = be32toh(payload->pci_addr);
  payload->enable_elog = be32toh(payload->enable_elog);
  payload->rxq_size = be16toh(payload->rxq_size);
  payload->rxq_num = be16toh(payload->rxq_num);
  payload->txq_size = be16toh(payload->txq_size);
  payload->txq_num = be16toh(payload->txq_num);
}

static inline void vapi_msg_vmxnet3_create_hton(vapi_msg_vmxnet3_create *msg)
{
  VAPI_DBG("Swapping `vapi_msg_vmxnet3_create'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_vmxnet3_create_payload_hton(&msg->payload);
}

static inline void vapi_msg_vmxnet3_create_ntoh(vapi_msg_vmxnet3_create *msg)
{
  VAPI_DBG("Swapping `vapi_msg_vmxnet3_create'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_vmxnet3_create_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_vmxnet3_create_msg_size(vapi_msg_vmxnet3_create *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_vmxnet3_create_msg_size(vapi_msg_vmxnet3_create *msg, uword buf_size)
{
  if (sizeof(vapi_msg_vmxnet3_create) > buf_size)
    {
      VAPI_ERR("Truncated 'vmxnet3_create' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_vmxnet3_create));
      return -1;
    }
  if (vapi_calc_vmxnet3_create_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'vmxnet3_create' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_vmxnet3_create_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_vmxnet3_create* vapi_alloc_vmxnet3_create(struct vapi_ctx_s *ctx)
{
  vapi_msg_vmxnet3_create *msg = NULL;
  const size_t size = sizeof(vapi_msg_vmxnet3_create);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_vmxnet3_create*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_vmxnet3_create);

  return msg;
}

static inline vapi_error_e vapi_vmxnet3_create(struct vapi_ctx_s *ctx,
  vapi_msg_vmxnet3_create *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_vmxnet3_create_reply *reply),
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
  vapi_msg_vmxnet3_create_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_vmxnet3_create_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_vmxnet3_create_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_vmxnet3_create()
{
  static const char name[] = "vmxnet3_create";
  static const char name_with_crc[] = "vmxnet3_create_71a07314";
  static vapi_message_desc_t __vapi_metadata_vmxnet3_create = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_vmxnet3_create, payload),
    (verify_msg_size_fn_t)vapi_verify_vmxnet3_create_msg_size,
    (generic_swap_fn_t)vapi_msg_vmxnet3_create_hton,
    (generic_swap_fn_t)vapi_msg_vmxnet3_create_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_vmxnet3_create = vapi_register_msg(&__vapi_metadata_vmxnet3_create);
  VAPI_DBG("Assigned msg id %d to vmxnet3_create", vapi_msg_id_vmxnet3_create);
}
#endif

#ifndef defined_vapi_msg_vmxnet3_delete_reply
#define defined_vapi_msg_vmxnet3_delete_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_vmxnet3_delete_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_vmxnet3_delete_reply payload;
} vapi_msg_vmxnet3_delete_reply;

static inline void vapi_msg_vmxnet3_delete_reply_payload_hton(vapi_payload_vmxnet3_delete_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_vmxnet3_delete_reply_payload_ntoh(vapi_payload_vmxnet3_delete_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_vmxnet3_delete_reply_hton(vapi_msg_vmxnet3_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_vmxnet3_delete_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_vmxnet3_delete_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_vmxnet3_delete_reply_ntoh(vapi_msg_vmxnet3_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_vmxnet3_delete_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_vmxnet3_delete_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_vmxnet3_delete_reply_msg_size(vapi_msg_vmxnet3_delete_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_vmxnet3_delete_reply_msg_size(vapi_msg_vmxnet3_delete_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_vmxnet3_delete_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'vmxnet3_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_vmxnet3_delete_reply));
      return -1;
    }
  if (vapi_calc_vmxnet3_delete_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'vmxnet3_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_vmxnet3_delete_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_vmxnet3_delete_reply()
{
  static const char name[] = "vmxnet3_delete_reply";
  static const char name_with_crc[] = "vmxnet3_delete_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_vmxnet3_delete_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_vmxnet3_delete_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_vmxnet3_delete_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_vmxnet3_delete_reply_hton,
    (generic_swap_fn_t)vapi_msg_vmxnet3_delete_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_vmxnet3_delete_reply = vapi_register_msg(&__vapi_metadata_vmxnet3_delete_reply);
  VAPI_DBG("Assigned msg id %d to vmxnet3_delete_reply", vapi_msg_id_vmxnet3_delete_reply);
}

static inline void vapi_set_vapi_msg_vmxnet3_delete_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_vmxnet3_delete_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_vmxnet3_delete_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_vmxnet3_delete
#define defined_vapi_msg_vmxnet3_delete
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_vmxnet3_delete;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_vmxnet3_delete payload;
} vapi_msg_vmxnet3_delete;

static inline void vapi_msg_vmxnet3_delete_payload_hton(vapi_payload_vmxnet3_delete *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_vmxnet3_delete_payload_ntoh(vapi_payload_vmxnet3_delete *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_vmxnet3_delete_hton(vapi_msg_vmxnet3_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_vmxnet3_delete'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_vmxnet3_delete_payload_hton(&msg->payload);
}

static inline void vapi_msg_vmxnet3_delete_ntoh(vapi_msg_vmxnet3_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_vmxnet3_delete'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_vmxnet3_delete_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_vmxnet3_delete_msg_size(vapi_msg_vmxnet3_delete *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_vmxnet3_delete_msg_size(vapi_msg_vmxnet3_delete *msg, uword buf_size)
{
  if (sizeof(vapi_msg_vmxnet3_delete) > buf_size)
    {
      VAPI_ERR("Truncated 'vmxnet3_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_vmxnet3_delete));
      return -1;
    }
  if (vapi_calc_vmxnet3_delete_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'vmxnet3_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_vmxnet3_delete_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_vmxnet3_delete* vapi_alloc_vmxnet3_delete(struct vapi_ctx_s *ctx)
{
  vapi_msg_vmxnet3_delete *msg = NULL;
  const size_t size = sizeof(vapi_msg_vmxnet3_delete);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_vmxnet3_delete*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_vmxnet3_delete);

  return msg;
}

static inline vapi_error_e vapi_vmxnet3_delete(struct vapi_ctx_s *ctx,
  vapi_msg_vmxnet3_delete *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_vmxnet3_delete_reply *reply),
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
  vapi_msg_vmxnet3_delete_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_vmxnet3_delete_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_vmxnet3_delete_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_vmxnet3_delete()
{
  static const char name[] = "vmxnet3_delete";
  static const char name_with_crc[] = "vmxnet3_delete_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_vmxnet3_delete = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_vmxnet3_delete, payload),
    (verify_msg_size_fn_t)vapi_verify_vmxnet3_delete_msg_size,
    (generic_swap_fn_t)vapi_msg_vmxnet3_delete_hton,
    (generic_swap_fn_t)vapi_msg_vmxnet3_delete_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_vmxnet3_delete = vapi_register_msg(&__vapi_metadata_vmxnet3_delete);
  VAPI_DBG("Assigned msg id %d to vmxnet3_delete", vapi_msg_id_vmxnet3_delete);
}
#endif

#ifndef defined_vapi_msg_vmxnet3_details
#define defined_vapi_msg_vmxnet3_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u8 if_name[64];
  vapi_type_mac_address hw_addr;
  u32 pci_addr;
  u8 version;
  bool admin_up_down;
  u8 rx_count;
  vapi_type_vmxnet3_rx_list rx_list[16];
  u8 tx_count;
  vapi_type_vmxnet3_tx_list tx_list[8]; 
} vapi_payload_vmxnet3_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_vmxnet3_details payload;
} vapi_msg_vmxnet3_details;

static inline void vapi_msg_vmxnet3_details_payload_hton(vapi_payload_vmxnet3_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->pci_addr = htobe32(payload->pci_addr);
  do { unsigned i; for (i = 0; i < 16; ++i) { vapi_type_vmxnet3_rx_list_hton(&payload->rx_list[i]); } } while(0);
  do { unsigned i; for (i = 0; i < 8; ++i) { vapi_type_vmxnet3_tx_list_hton(&payload->tx_list[i]); } } while(0);
}

static inline void vapi_msg_vmxnet3_details_payload_ntoh(vapi_payload_vmxnet3_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->pci_addr = be32toh(payload->pci_addr);
  do { unsigned i; for (i = 0; i < 16; ++i) { vapi_type_vmxnet3_rx_list_ntoh(&payload->rx_list[i]); } } while(0);
  do { unsigned i; for (i = 0; i < 8; ++i) { vapi_type_vmxnet3_tx_list_ntoh(&payload->tx_list[i]); } } while(0);
}

static inline void vapi_msg_vmxnet3_details_hton(vapi_msg_vmxnet3_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_vmxnet3_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_vmxnet3_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_vmxnet3_details_ntoh(vapi_msg_vmxnet3_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_vmxnet3_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_vmxnet3_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_vmxnet3_details_msg_size(vapi_msg_vmxnet3_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_vmxnet3_details_msg_size(vapi_msg_vmxnet3_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_vmxnet3_details) > buf_size)
    {
      VAPI_ERR("Truncated 'vmxnet3_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_vmxnet3_details));
      return -1;
    }
  if (vapi_calc_vmxnet3_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'vmxnet3_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_vmxnet3_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_vmxnet3_details()
{
  static const char name[] = "vmxnet3_details";
  static const char name_with_crc[] = "vmxnet3_details_6a1a5498";
  static vapi_message_desc_t __vapi_metadata_vmxnet3_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_vmxnet3_details, payload),
    (verify_msg_size_fn_t)vapi_verify_vmxnet3_details_msg_size,
    (generic_swap_fn_t)vapi_msg_vmxnet3_details_hton,
    (generic_swap_fn_t)vapi_msg_vmxnet3_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_vmxnet3_details = vapi_register_msg(&__vapi_metadata_vmxnet3_details);
  VAPI_DBG("Assigned msg id %d to vmxnet3_details", vapi_msg_id_vmxnet3_details);
}

static inline void vapi_set_vapi_msg_vmxnet3_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_vmxnet3_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_vmxnet3_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_vmxnet3_dump
#define defined_vapi_msg_vmxnet3_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_vmxnet3_dump;

static inline void vapi_msg_vmxnet3_dump_hton(vapi_msg_vmxnet3_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_vmxnet3_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_vmxnet3_dump_ntoh(vapi_msg_vmxnet3_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_vmxnet3_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_vmxnet3_dump_msg_size(vapi_msg_vmxnet3_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_vmxnet3_dump_msg_size(vapi_msg_vmxnet3_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_vmxnet3_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'vmxnet3_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_vmxnet3_dump));
      return -1;
    }
  if (vapi_calc_vmxnet3_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'vmxnet3_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_vmxnet3_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_vmxnet3_dump* vapi_alloc_vmxnet3_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_vmxnet3_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_vmxnet3_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_vmxnet3_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_vmxnet3_dump);

  return msg;
}

static inline vapi_error_e vapi_vmxnet3_dump(struct vapi_ctx_s *ctx,
  vapi_msg_vmxnet3_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_vmxnet3_details *reply),
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
  vapi_msg_vmxnet3_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_vmxnet3_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_vmxnet3_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_vmxnet3_dump()
{
  static const char name[] = "vmxnet3_dump";
  static const char name_with_crc[] = "vmxnet3_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_vmxnet3_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_vmxnet3_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_vmxnet3_dump_hton,
    (generic_swap_fn_t)vapi_msg_vmxnet3_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_vmxnet3_dump = vapi_register_msg(&__vapi_metadata_vmxnet3_dump);
  VAPI_DBG("Assigned msg id %d to vmxnet3_dump", vapi_msg_id_vmxnet3_dump);
}
#endif

#ifndef defined_vapi_msg_sw_vmxnet3_interface_details
#define defined_vapi_msg_sw_vmxnet3_interface_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u8 if_name[64];
  vapi_type_mac_address hw_addr;
  u32 pci_addr;
  u8 version;
  bool admin_up_down;
  u8 rx_count;
  vapi_type_vmxnet3_rx_list rx_list[16];
  u8 tx_count;
  vapi_type_vmxnet3_tx_list tx_list[8]; 
} vapi_payload_sw_vmxnet3_interface_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sw_vmxnet3_interface_details payload;
} vapi_msg_sw_vmxnet3_interface_details;

static inline void vapi_msg_sw_vmxnet3_interface_details_payload_hton(vapi_payload_sw_vmxnet3_interface_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->pci_addr = htobe32(payload->pci_addr);
  do { unsigned i; for (i = 0; i < 16; ++i) { vapi_type_vmxnet3_rx_list_hton(&payload->rx_list[i]); } } while(0);
  do { unsigned i; for (i = 0; i < 8; ++i) { vapi_type_vmxnet3_tx_list_hton(&payload->tx_list[i]); } } while(0);
}

static inline void vapi_msg_sw_vmxnet3_interface_details_payload_ntoh(vapi_payload_sw_vmxnet3_interface_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->pci_addr = be32toh(payload->pci_addr);
  do { unsigned i; for (i = 0; i < 16; ++i) { vapi_type_vmxnet3_rx_list_ntoh(&payload->rx_list[i]); } } while(0);
  do { unsigned i; for (i = 0; i < 8; ++i) { vapi_type_vmxnet3_tx_list_ntoh(&payload->tx_list[i]); } } while(0);
}

static inline void vapi_msg_sw_vmxnet3_interface_details_hton(vapi_msg_sw_vmxnet3_interface_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_vmxnet3_interface_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sw_vmxnet3_interface_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_vmxnet3_interface_details_ntoh(vapi_msg_sw_vmxnet3_interface_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_vmxnet3_interface_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sw_vmxnet3_interface_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_vmxnet3_interface_details_msg_size(vapi_msg_sw_vmxnet3_interface_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_vmxnet3_interface_details_msg_size(vapi_msg_sw_vmxnet3_interface_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_vmxnet3_interface_details) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_vmxnet3_interface_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_vmxnet3_interface_details));
      return -1;
    }
  if (vapi_calc_sw_vmxnet3_interface_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_vmxnet3_interface_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_vmxnet3_interface_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sw_vmxnet3_interface_details()
{
  static const char name[] = "sw_vmxnet3_interface_details";
  static const char name_with_crc[] = "sw_vmxnet3_interface_details_6a1a5498";
  static vapi_message_desc_t __vapi_metadata_sw_vmxnet3_interface_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sw_vmxnet3_interface_details, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_vmxnet3_interface_details_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_vmxnet3_interface_details_hton,
    (generic_swap_fn_t)vapi_msg_sw_vmxnet3_interface_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_vmxnet3_interface_details = vapi_register_msg(&__vapi_metadata_sw_vmxnet3_interface_details);
  VAPI_DBG("Assigned msg id %d to sw_vmxnet3_interface_details", vapi_msg_id_sw_vmxnet3_interface_details);
}

static inline void vapi_set_vapi_msg_sw_vmxnet3_interface_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sw_vmxnet3_interface_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sw_vmxnet3_interface_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sw_vmxnet3_interface_dump
#define defined_vapi_msg_sw_vmxnet3_interface_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_sw_vmxnet3_interface_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sw_vmxnet3_interface_dump payload;
} vapi_msg_sw_vmxnet3_interface_dump;

static inline void vapi_msg_sw_vmxnet3_interface_dump_payload_hton(vapi_payload_sw_vmxnet3_interface_dump *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_sw_vmxnet3_interface_dump_payload_ntoh(vapi_payload_sw_vmxnet3_interface_dump *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_sw_vmxnet3_interface_dump_hton(vapi_msg_sw_vmxnet3_interface_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_vmxnet3_interface_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sw_vmxnet3_interface_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_vmxnet3_interface_dump_ntoh(vapi_msg_sw_vmxnet3_interface_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_vmxnet3_interface_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sw_vmxnet3_interface_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_vmxnet3_interface_dump_msg_size(vapi_msg_sw_vmxnet3_interface_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_vmxnet3_interface_dump_msg_size(vapi_msg_sw_vmxnet3_interface_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_vmxnet3_interface_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_vmxnet3_interface_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_vmxnet3_interface_dump));
      return -1;
    }
  if (vapi_calc_sw_vmxnet3_interface_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_vmxnet3_interface_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_vmxnet3_interface_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sw_vmxnet3_interface_dump* vapi_alloc_sw_vmxnet3_interface_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_sw_vmxnet3_interface_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_sw_vmxnet3_interface_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sw_vmxnet3_interface_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sw_vmxnet3_interface_dump);

  return msg;
}

static inline vapi_error_e vapi_sw_vmxnet3_interface_dump(struct vapi_ctx_s *ctx,
  vapi_msg_sw_vmxnet3_interface_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sw_vmxnet3_interface_details *reply),
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
  vapi_msg_sw_vmxnet3_interface_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sw_vmxnet3_interface_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_sw_vmxnet3_interface_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sw_vmxnet3_interface_dump()
{
  static const char name[] = "sw_vmxnet3_interface_dump";
  static const char name_with_crc[] = "sw_vmxnet3_interface_dump_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_sw_vmxnet3_interface_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sw_vmxnet3_interface_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_vmxnet3_interface_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_vmxnet3_interface_dump_hton,
    (generic_swap_fn_t)vapi_msg_sw_vmxnet3_interface_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_vmxnet3_interface_dump = vapi_register_msg(&__vapi_metadata_sw_vmxnet3_interface_dump);
  VAPI_DBG("Assigned msg id %d to sw_vmxnet3_interface_dump", vapi_msg_id_sw_vmxnet3_interface_dump);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
