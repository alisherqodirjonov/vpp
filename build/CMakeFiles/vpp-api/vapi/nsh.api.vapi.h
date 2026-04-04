#ifndef __included_nsh_api_json
#define __included_nsh_api_json

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

extern vapi_msg_id_t vapi_msg_id_nsh_add_del_entry;
extern vapi_msg_id_t vapi_msg_id_nsh_add_del_entry_reply;
extern vapi_msg_id_t vapi_msg_id_nsh_entry_dump;
extern vapi_msg_id_t vapi_msg_id_nsh_entry_details;
extern vapi_msg_id_t vapi_msg_id_nsh_add_del_map;
extern vapi_msg_id_t vapi_msg_id_nsh_add_del_map_reply;
extern vapi_msg_id_t vapi_msg_id_nsh_map_dump;
extern vapi_msg_id_t vapi_msg_id_nsh_map_details;

#define DEFINE_VAPI_MSG_IDS_NSH_API_JSON\
  vapi_msg_id_t vapi_msg_id_nsh_add_del_entry;\
  vapi_msg_id_t vapi_msg_id_nsh_add_del_entry_reply;\
  vapi_msg_id_t vapi_msg_id_nsh_entry_dump;\
  vapi_msg_id_t vapi_msg_id_nsh_entry_details;\
  vapi_msg_id_t vapi_msg_id_nsh_add_del_map;\
  vapi_msg_id_t vapi_msg_id_nsh_add_del_map_reply;\
  vapi_msg_id_t vapi_msg_id_nsh_map_dump;\
  vapi_msg_id_t vapi_msg_id_nsh_map_details;


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

#ifndef defined_vapi_msg_nsh_add_del_entry_reply
#define defined_vapi_msg_nsh_add_del_entry_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 entry_index; 
} vapi_payload_nsh_add_del_entry_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nsh_add_del_entry_reply payload;
} vapi_msg_nsh_add_del_entry_reply;

static inline void vapi_msg_nsh_add_del_entry_reply_payload_hton(vapi_payload_nsh_add_del_entry_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->entry_index = htobe32(payload->entry_index);
}

static inline void vapi_msg_nsh_add_del_entry_reply_payload_ntoh(vapi_payload_nsh_add_del_entry_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->entry_index = be32toh(payload->entry_index);
}

static inline void vapi_msg_nsh_add_del_entry_reply_hton(vapi_msg_nsh_add_del_entry_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsh_add_del_entry_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nsh_add_del_entry_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nsh_add_del_entry_reply_ntoh(vapi_msg_nsh_add_del_entry_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsh_add_del_entry_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nsh_add_del_entry_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nsh_add_del_entry_reply_msg_size(vapi_msg_nsh_add_del_entry_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nsh_add_del_entry_reply_msg_size(vapi_msg_nsh_add_del_entry_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nsh_add_del_entry_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nsh_add_del_entry_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nsh_add_del_entry_reply));
      return -1;
    }
  if (vapi_calc_nsh_add_del_entry_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nsh_add_del_entry_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nsh_add_del_entry_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nsh_add_del_entry_reply()
{
  static const char name[] = "nsh_add_del_entry_reply";
  static const char name_with_crc[] = "nsh_add_del_entry_reply_6296a9eb";
  static vapi_message_desc_t __vapi_metadata_nsh_add_del_entry_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nsh_add_del_entry_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nsh_add_del_entry_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nsh_add_del_entry_reply_hton,
    (generic_swap_fn_t)vapi_msg_nsh_add_del_entry_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nsh_add_del_entry_reply = vapi_register_msg(&__vapi_metadata_nsh_add_del_entry_reply);
  VAPI_DBG("Assigned msg id %d to nsh_add_del_entry_reply", vapi_msg_id_nsh_add_del_entry_reply);
}

static inline void vapi_set_vapi_msg_nsh_add_del_entry_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nsh_add_del_entry_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nsh_add_del_entry_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nsh_add_del_entry
#define defined_vapi_msg_nsh_add_del_entry
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  u32 nsp_nsi;
  u8 md_type;
  u8 ver_o_c;
  u8 ttl;
  u8 length;
  u8 next_protocol;
  u32 c1;
  u32 c2;
  u32 c3;
  u32 c4;
  u8 tlv_length;
  u8 tlv[248]; 
} vapi_payload_nsh_add_del_entry;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nsh_add_del_entry payload;
} vapi_msg_nsh_add_del_entry;

static inline void vapi_msg_nsh_add_del_entry_payload_hton(vapi_payload_nsh_add_del_entry *payload)
{
  payload->nsp_nsi = htobe32(payload->nsp_nsi);
  payload->c1 = htobe32(payload->c1);
  payload->c2 = htobe32(payload->c2);
  payload->c3 = htobe32(payload->c3);
  payload->c4 = htobe32(payload->c4);
}

static inline void vapi_msg_nsh_add_del_entry_payload_ntoh(vapi_payload_nsh_add_del_entry *payload)
{
  payload->nsp_nsi = be32toh(payload->nsp_nsi);
  payload->c1 = be32toh(payload->c1);
  payload->c2 = be32toh(payload->c2);
  payload->c3 = be32toh(payload->c3);
  payload->c4 = be32toh(payload->c4);
}

static inline void vapi_msg_nsh_add_del_entry_hton(vapi_msg_nsh_add_del_entry *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsh_add_del_entry'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nsh_add_del_entry_payload_hton(&msg->payload);
}

static inline void vapi_msg_nsh_add_del_entry_ntoh(vapi_msg_nsh_add_del_entry *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsh_add_del_entry'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nsh_add_del_entry_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nsh_add_del_entry_msg_size(vapi_msg_nsh_add_del_entry *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nsh_add_del_entry_msg_size(vapi_msg_nsh_add_del_entry *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nsh_add_del_entry) > buf_size)
    {
      VAPI_ERR("Truncated 'nsh_add_del_entry' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nsh_add_del_entry));
      return -1;
    }
  if (vapi_calc_nsh_add_del_entry_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nsh_add_del_entry' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nsh_add_del_entry_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nsh_add_del_entry* vapi_alloc_nsh_add_del_entry(struct vapi_ctx_s *ctx)
{
  vapi_msg_nsh_add_del_entry *msg = NULL;
  const size_t size = sizeof(vapi_msg_nsh_add_del_entry);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nsh_add_del_entry*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nsh_add_del_entry);

  return msg;
}

static inline vapi_error_e vapi_nsh_add_del_entry(struct vapi_ctx_s *ctx,
  vapi_msg_nsh_add_del_entry *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nsh_add_del_entry_reply *reply),
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
  vapi_msg_nsh_add_del_entry_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nsh_add_del_entry_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_nsh_add_del_entry_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nsh_add_del_entry()
{
  static const char name[] = "nsh_add_del_entry";
  static const char name_with_crc[] = "nsh_add_del_entry_7dea480b";
  static vapi_message_desc_t __vapi_metadata_nsh_add_del_entry = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nsh_add_del_entry, payload),
    (verify_msg_size_fn_t)vapi_verify_nsh_add_del_entry_msg_size,
    (generic_swap_fn_t)vapi_msg_nsh_add_del_entry_hton,
    (generic_swap_fn_t)vapi_msg_nsh_add_del_entry_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nsh_add_del_entry = vapi_register_msg(&__vapi_metadata_nsh_add_del_entry);
  VAPI_DBG("Assigned msg id %d to nsh_add_del_entry", vapi_msg_id_nsh_add_del_entry);
}
#endif

#ifndef defined_vapi_msg_nsh_entry_details
#define defined_vapi_msg_nsh_entry_details
typedef struct __attribute__ ((__packed__)) {
  u32 entry_index;
  u32 nsp_nsi;
  u8 md_type;
  u8 ver_o_c;
  u8 ttl;
  u8 length;
  u8 next_protocol;
  u32 c1;
  u32 c2;
  u32 c3;
  u32 c4;
  u8 tlv_length;
  u8 tlv[248]; 
} vapi_payload_nsh_entry_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nsh_entry_details payload;
} vapi_msg_nsh_entry_details;

static inline void vapi_msg_nsh_entry_details_payload_hton(vapi_payload_nsh_entry_details *payload)
{
  payload->entry_index = htobe32(payload->entry_index);
  payload->nsp_nsi = htobe32(payload->nsp_nsi);
  payload->c1 = htobe32(payload->c1);
  payload->c2 = htobe32(payload->c2);
  payload->c3 = htobe32(payload->c3);
  payload->c4 = htobe32(payload->c4);
}

static inline void vapi_msg_nsh_entry_details_payload_ntoh(vapi_payload_nsh_entry_details *payload)
{
  payload->entry_index = be32toh(payload->entry_index);
  payload->nsp_nsi = be32toh(payload->nsp_nsi);
  payload->c1 = be32toh(payload->c1);
  payload->c2 = be32toh(payload->c2);
  payload->c3 = be32toh(payload->c3);
  payload->c4 = be32toh(payload->c4);
}

static inline void vapi_msg_nsh_entry_details_hton(vapi_msg_nsh_entry_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsh_entry_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nsh_entry_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_nsh_entry_details_ntoh(vapi_msg_nsh_entry_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsh_entry_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nsh_entry_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nsh_entry_details_msg_size(vapi_msg_nsh_entry_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nsh_entry_details_msg_size(vapi_msg_nsh_entry_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nsh_entry_details) > buf_size)
    {
      VAPI_ERR("Truncated 'nsh_entry_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nsh_entry_details));
      return -1;
    }
  if (vapi_calc_nsh_entry_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nsh_entry_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nsh_entry_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nsh_entry_details()
{
  static const char name[] = "nsh_entry_details";
  static const char name_with_crc[] = "nsh_entry_details_046fb556";
  static vapi_message_desc_t __vapi_metadata_nsh_entry_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nsh_entry_details, payload),
    (verify_msg_size_fn_t)vapi_verify_nsh_entry_details_msg_size,
    (generic_swap_fn_t)vapi_msg_nsh_entry_details_hton,
    (generic_swap_fn_t)vapi_msg_nsh_entry_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nsh_entry_details = vapi_register_msg(&__vapi_metadata_nsh_entry_details);
  VAPI_DBG("Assigned msg id %d to nsh_entry_details", vapi_msg_id_nsh_entry_details);
}

static inline void vapi_set_vapi_msg_nsh_entry_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nsh_entry_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nsh_entry_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nsh_entry_dump
#define defined_vapi_msg_nsh_entry_dump
typedef struct __attribute__ ((__packed__)) {
  u32 entry_index; 
} vapi_payload_nsh_entry_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nsh_entry_dump payload;
} vapi_msg_nsh_entry_dump;

static inline void vapi_msg_nsh_entry_dump_payload_hton(vapi_payload_nsh_entry_dump *payload)
{
  payload->entry_index = htobe32(payload->entry_index);
}

static inline void vapi_msg_nsh_entry_dump_payload_ntoh(vapi_payload_nsh_entry_dump *payload)
{
  payload->entry_index = be32toh(payload->entry_index);
}

static inline void vapi_msg_nsh_entry_dump_hton(vapi_msg_nsh_entry_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsh_entry_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nsh_entry_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_nsh_entry_dump_ntoh(vapi_msg_nsh_entry_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsh_entry_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nsh_entry_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nsh_entry_dump_msg_size(vapi_msg_nsh_entry_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nsh_entry_dump_msg_size(vapi_msg_nsh_entry_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nsh_entry_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'nsh_entry_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nsh_entry_dump));
      return -1;
    }
  if (vapi_calc_nsh_entry_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nsh_entry_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nsh_entry_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nsh_entry_dump* vapi_alloc_nsh_entry_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_nsh_entry_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_nsh_entry_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nsh_entry_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nsh_entry_dump);

  return msg;
}

static inline vapi_error_e vapi_nsh_entry_dump(struct vapi_ctx_s *ctx,
  vapi_msg_nsh_entry_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nsh_entry_details *reply),
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
  vapi_msg_nsh_entry_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nsh_entry_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_nsh_entry_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nsh_entry_dump()
{
  static const char name[] = "nsh_entry_dump";
  static const char name_with_crc[] = "nsh_entry_dump_cdaf8ccb";
  static vapi_message_desc_t __vapi_metadata_nsh_entry_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nsh_entry_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_nsh_entry_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_nsh_entry_dump_hton,
    (generic_swap_fn_t)vapi_msg_nsh_entry_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nsh_entry_dump = vapi_register_msg(&__vapi_metadata_nsh_entry_dump);
  VAPI_DBG("Assigned msg id %d to nsh_entry_dump", vapi_msg_id_nsh_entry_dump);
}
#endif

#ifndef defined_vapi_msg_nsh_add_del_map_reply
#define defined_vapi_msg_nsh_add_del_map_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 map_index; 
} vapi_payload_nsh_add_del_map_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nsh_add_del_map_reply payload;
} vapi_msg_nsh_add_del_map_reply;

static inline void vapi_msg_nsh_add_del_map_reply_payload_hton(vapi_payload_nsh_add_del_map_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->map_index = htobe32(payload->map_index);
}

static inline void vapi_msg_nsh_add_del_map_reply_payload_ntoh(vapi_payload_nsh_add_del_map_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->map_index = be32toh(payload->map_index);
}

static inline void vapi_msg_nsh_add_del_map_reply_hton(vapi_msg_nsh_add_del_map_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsh_add_del_map_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nsh_add_del_map_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_nsh_add_del_map_reply_ntoh(vapi_msg_nsh_add_del_map_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsh_add_del_map_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nsh_add_del_map_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nsh_add_del_map_reply_msg_size(vapi_msg_nsh_add_del_map_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nsh_add_del_map_reply_msg_size(vapi_msg_nsh_add_del_map_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nsh_add_del_map_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'nsh_add_del_map_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nsh_add_del_map_reply));
      return -1;
    }
  if (vapi_calc_nsh_add_del_map_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nsh_add_del_map_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nsh_add_del_map_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nsh_add_del_map_reply()
{
  static const char name[] = "nsh_add_del_map_reply";
  static const char name_with_crc[] = "nsh_add_del_map_reply_b2b127ef";
  static vapi_message_desc_t __vapi_metadata_nsh_add_del_map_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nsh_add_del_map_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_nsh_add_del_map_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_nsh_add_del_map_reply_hton,
    (generic_swap_fn_t)vapi_msg_nsh_add_del_map_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nsh_add_del_map_reply = vapi_register_msg(&__vapi_metadata_nsh_add_del_map_reply);
  VAPI_DBG("Assigned msg id %d to nsh_add_del_map_reply", vapi_msg_id_nsh_add_del_map_reply);
}

static inline void vapi_set_vapi_msg_nsh_add_del_map_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nsh_add_del_map_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nsh_add_del_map_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nsh_add_del_map
#define defined_vapi_msg_nsh_add_del_map
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  u32 nsp_nsi;
  u32 mapped_nsp_nsi;
  u32 nsh_action;
  vapi_type_interface_index sw_if_index;
  vapi_type_interface_index rx_sw_if_index;
  u32 next_node; 
} vapi_payload_nsh_add_del_map;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nsh_add_del_map payload;
} vapi_msg_nsh_add_del_map;

static inline void vapi_msg_nsh_add_del_map_payload_hton(vapi_payload_nsh_add_del_map *payload)
{
  payload->nsp_nsi = htobe32(payload->nsp_nsi);
  payload->mapped_nsp_nsi = htobe32(payload->mapped_nsp_nsi);
  payload->nsh_action = htobe32(payload->nsh_action);
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->rx_sw_if_index = htobe32(payload->rx_sw_if_index);
  payload->next_node = htobe32(payload->next_node);
}

static inline void vapi_msg_nsh_add_del_map_payload_ntoh(vapi_payload_nsh_add_del_map *payload)
{
  payload->nsp_nsi = be32toh(payload->nsp_nsi);
  payload->mapped_nsp_nsi = be32toh(payload->mapped_nsp_nsi);
  payload->nsh_action = be32toh(payload->nsh_action);
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->rx_sw_if_index = be32toh(payload->rx_sw_if_index);
  payload->next_node = be32toh(payload->next_node);
}

static inline void vapi_msg_nsh_add_del_map_hton(vapi_msg_nsh_add_del_map *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsh_add_del_map'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nsh_add_del_map_payload_hton(&msg->payload);
}

static inline void vapi_msg_nsh_add_del_map_ntoh(vapi_msg_nsh_add_del_map *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsh_add_del_map'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nsh_add_del_map_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nsh_add_del_map_msg_size(vapi_msg_nsh_add_del_map *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nsh_add_del_map_msg_size(vapi_msg_nsh_add_del_map *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nsh_add_del_map) > buf_size)
    {
      VAPI_ERR("Truncated 'nsh_add_del_map' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nsh_add_del_map));
      return -1;
    }
  if (vapi_calc_nsh_add_del_map_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nsh_add_del_map' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nsh_add_del_map_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nsh_add_del_map* vapi_alloc_nsh_add_del_map(struct vapi_ctx_s *ctx)
{
  vapi_msg_nsh_add_del_map *msg = NULL;
  const size_t size = sizeof(vapi_msg_nsh_add_del_map);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nsh_add_del_map*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nsh_add_del_map);

  return msg;
}

static inline vapi_error_e vapi_nsh_add_del_map(struct vapi_ctx_s *ctx,
  vapi_msg_nsh_add_del_map *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nsh_add_del_map_reply *reply),
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
  vapi_msg_nsh_add_del_map_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nsh_add_del_map_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_nsh_add_del_map_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nsh_add_del_map()
{
  static const char name[] = "nsh_add_del_map";
  static const char name_with_crc[] = "nsh_add_del_map_0a0f42b0";
  static vapi_message_desc_t __vapi_metadata_nsh_add_del_map = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nsh_add_del_map, payload),
    (verify_msg_size_fn_t)vapi_verify_nsh_add_del_map_msg_size,
    (generic_swap_fn_t)vapi_msg_nsh_add_del_map_hton,
    (generic_swap_fn_t)vapi_msg_nsh_add_del_map_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nsh_add_del_map = vapi_register_msg(&__vapi_metadata_nsh_add_del_map);
  VAPI_DBG("Assigned msg id %d to nsh_add_del_map", vapi_msg_id_nsh_add_del_map);
}
#endif

#ifndef defined_vapi_msg_nsh_map_details
#define defined_vapi_msg_nsh_map_details
typedef struct __attribute__ ((__packed__)) {
  u32 map_index;
  u32 nsp_nsi;
  u32 mapped_nsp_nsi;
  u32 nsh_action;
  vapi_type_interface_index sw_if_index;
  vapi_type_interface_index rx_sw_if_index;
  u32 next_node; 
} vapi_payload_nsh_map_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_nsh_map_details payload;
} vapi_msg_nsh_map_details;

static inline void vapi_msg_nsh_map_details_payload_hton(vapi_payload_nsh_map_details *payload)
{
  payload->map_index = htobe32(payload->map_index);
  payload->nsp_nsi = htobe32(payload->nsp_nsi);
  payload->mapped_nsp_nsi = htobe32(payload->mapped_nsp_nsi);
  payload->nsh_action = htobe32(payload->nsh_action);
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->rx_sw_if_index = htobe32(payload->rx_sw_if_index);
  payload->next_node = htobe32(payload->next_node);
}

static inline void vapi_msg_nsh_map_details_payload_ntoh(vapi_payload_nsh_map_details *payload)
{
  payload->map_index = be32toh(payload->map_index);
  payload->nsp_nsi = be32toh(payload->nsp_nsi);
  payload->mapped_nsp_nsi = be32toh(payload->mapped_nsp_nsi);
  payload->nsh_action = be32toh(payload->nsh_action);
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->rx_sw_if_index = be32toh(payload->rx_sw_if_index);
  payload->next_node = be32toh(payload->next_node);
}

static inline void vapi_msg_nsh_map_details_hton(vapi_msg_nsh_map_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsh_map_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_nsh_map_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_nsh_map_details_ntoh(vapi_msg_nsh_map_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsh_map_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_nsh_map_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nsh_map_details_msg_size(vapi_msg_nsh_map_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nsh_map_details_msg_size(vapi_msg_nsh_map_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nsh_map_details) > buf_size)
    {
      VAPI_ERR("Truncated 'nsh_map_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nsh_map_details));
      return -1;
    }
  if (vapi_calc_nsh_map_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nsh_map_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nsh_map_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_nsh_map_details()
{
  static const char name[] = "nsh_map_details";
  static const char name_with_crc[] = "nsh_map_details_2fefcf49";
  static vapi_message_desc_t __vapi_metadata_nsh_map_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_nsh_map_details, payload),
    (verify_msg_size_fn_t)vapi_verify_nsh_map_details_msg_size,
    (generic_swap_fn_t)vapi_msg_nsh_map_details_hton,
    (generic_swap_fn_t)vapi_msg_nsh_map_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nsh_map_details = vapi_register_msg(&__vapi_metadata_nsh_map_details);
  VAPI_DBG("Assigned msg id %d to nsh_map_details", vapi_msg_id_nsh_map_details);
}

static inline void vapi_set_vapi_msg_nsh_map_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_nsh_map_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_nsh_map_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_nsh_map_dump
#define defined_vapi_msg_nsh_map_dump
typedef struct __attribute__ ((__packed__)) {
  u32 map_index; 
} vapi_payload_nsh_map_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_nsh_map_dump payload;
} vapi_msg_nsh_map_dump;

static inline void vapi_msg_nsh_map_dump_payload_hton(vapi_payload_nsh_map_dump *payload)
{
  payload->map_index = htobe32(payload->map_index);
}

static inline void vapi_msg_nsh_map_dump_payload_ntoh(vapi_payload_nsh_map_dump *payload)
{
  payload->map_index = be32toh(payload->map_index);
}

static inline void vapi_msg_nsh_map_dump_hton(vapi_msg_nsh_map_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsh_map_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_nsh_map_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_nsh_map_dump_ntoh(vapi_msg_nsh_map_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_nsh_map_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_nsh_map_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_nsh_map_dump_msg_size(vapi_msg_nsh_map_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_nsh_map_dump_msg_size(vapi_msg_nsh_map_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_nsh_map_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'nsh_map_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_nsh_map_dump));
      return -1;
    }
  if (vapi_calc_nsh_map_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'nsh_map_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_nsh_map_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_nsh_map_dump* vapi_alloc_nsh_map_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_nsh_map_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_nsh_map_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_nsh_map_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_nsh_map_dump);

  return msg;
}

static inline vapi_error_e vapi_nsh_map_dump(struct vapi_ctx_s *ctx,
  vapi_msg_nsh_map_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_nsh_map_details *reply),
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
  vapi_msg_nsh_map_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_nsh_map_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_nsh_map_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_nsh_map_dump()
{
  static const char name[] = "nsh_map_dump";
  static const char name_with_crc[] = "nsh_map_dump_8fc06b82";
  static vapi_message_desc_t __vapi_metadata_nsh_map_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_nsh_map_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_nsh_map_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_nsh_map_dump_hton,
    (generic_swap_fn_t)vapi_msg_nsh_map_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_nsh_map_dump = vapi_register_msg(&__vapi_metadata_nsh_map_dump);
  VAPI_DBG("Assigned msg id %d to nsh_map_dump", vapi_msg_id_nsh_map_dump);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
