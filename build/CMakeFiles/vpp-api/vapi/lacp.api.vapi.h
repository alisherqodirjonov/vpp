#ifndef __included_lacp_api_json
#define __included_lacp_api_json

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

extern vapi_msg_id_t vapi_msg_id_sw_interface_lacp_dump;
extern vapi_msg_id_t vapi_msg_id_sw_interface_lacp_details;

#define DEFINE_VAPI_MSG_IDS_LACP_API_JSON\
  vapi_msg_id_t vapi_msg_id_sw_interface_lacp_dump;\
  vapi_msg_id_t vapi_msg_id_sw_interface_lacp_details;


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

#ifndef defined_vapi_type_mac_address
#define defined_vapi_type_mac_address
typedef u8 vapi_type_mac_address[6];

#endif

#ifndef defined_vapi_type_interface_index
#define defined_vapi_type_interface_index
typedef u32 vapi_type_interface_index;

#endif

#ifndef defined_vapi_msg_sw_interface_lacp_details
#define defined_vapi_msg_sw_interface_lacp_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u8 interface_name[64];
  u32 rx_state;
  u32 tx_state;
  u32 mux_state;
  u32 ptx_state;
  u8 bond_interface_name[64];
  u16 actor_system_priority;
  vapi_type_mac_address actor_system;
  u16 actor_key;
  u16 actor_port_priority;
  u16 actor_port_number;
  u8 actor_state;
  u16 partner_system_priority;
  vapi_type_mac_address partner_system;
  u16 partner_key;
  u16 partner_port_priority;
  u16 partner_port_number;
  u8 partner_state; 
} vapi_payload_sw_interface_lacp_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sw_interface_lacp_details payload;
} vapi_msg_sw_interface_lacp_details;

static inline void vapi_msg_sw_interface_lacp_details_payload_hton(vapi_payload_sw_interface_lacp_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->rx_state = htobe32(payload->rx_state);
  payload->tx_state = htobe32(payload->tx_state);
  payload->mux_state = htobe32(payload->mux_state);
  payload->ptx_state = htobe32(payload->ptx_state);
  payload->actor_system_priority = htobe16(payload->actor_system_priority);
  payload->actor_key = htobe16(payload->actor_key);
  payload->actor_port_priority = htobe16(payload->actor_port_priority);
  payload->actor_port_number = htobe16(payload->actor_port_number);
  payload->partner_system_priority = htobe16(payload->partner_system_priority);
  payload->partner_key = htobe16(payload->partner_key);
  payload->partner_port_priority = htobe16(payload->partner_port_priority);
  payload->partner_port_number = htobe16(payload->partner_port_number);
}

static inline void vapi_msg_sw_interface_lacp_details_payload_ntoh(vapi_payload_sw_interface_lacp_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->rx_state = be32toh(payload->rx_state);
  payload->tx_state = be32toh(payload->tx_state);
  payload->mux_state = be32toh(payload->mux_state);
  payload->ptx_state = be32toh(payload->ptx_state);
  payload->actor_system_priority = be16toh(payload->actor_system_priority);
  payload->actor_key = be16toh(payload->actor_key);
  payload->actor_port_priority = be16toh(payload->actor_port_priority);
  payload->actor_port_number = be16toh(payload->actor_port_number);
  payload->partner_system_priority = be16toh(payload->partner_system_priority);
  payload->partner_key = be16toh(payload->partner_key);
  payload->partner_port_priority = be16toh(payload->partner_port_priority);
  payload->partner_port_number = be16toh(payload->partner_port_number);
}

static inline void vapi_msg_sw_interface_lacp_details_hton(vapi_msg_sw_interface_lacp_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_lacp_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sw_interface_lacp_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_lacp_details_ntoh(vapi_msg_sw_interface_lacp_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_lacp_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sw_interface_lacp_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_lacp_details_msg_size(vapi_msg_sw_interface_lacp_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_lacp_details_msg_size(vapi_msg_sw_interface_lacp_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_lacp_details) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_lacp_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_lacp_details));
      return -1;
    }
  if (vapi_calc_sw_interface_lacp_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_lacp_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_lacp_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sw_interface_lacp_details()
{
  static const char name[] = "sw_interface_lacp_details";
  static const char name_with_crc[] = "sw_interface_lacp_details_d9a83d2f";
  static vapi_message_desc_t __vapi_metadata_sw_interface_lacp_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sw_interface_lacp_details, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_lacp_details_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_lacp_details_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_lacp_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_lacp_details = vapi_register_msg(&__vapi_metadata_sw_interface_lacp_details);
  VAPI_DBG("Assigned msg id %d to sw_interface_lacp_details", vapi_msg_id_sw_interface_lacp_details);
}

static inline void vapi_set_vapi_msg_sw_interface_lacp_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sw_interface_lacp_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sw_interface_lacp_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sw_interface_lacp_dump
#define defined_vapi_msg_sw_interface_lacp_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_sw_interface_lacp_dump;

static inline void vapi_msg_sw_interface_lacp_dump_hton(vapi_msg_sw_interface_lacp_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_lacp_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_sw_interface_lacp_dump_ntoh(vapi_msg_sw_interface_lacp_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_lacp_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_sw_interface_lacp_dump_msg_size(vapi_msg_sw_interface_lacp_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_lacp_dump_msg_size(vapi_msg_sw_interface_lacp_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_lacp_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_lacp_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_lacp_dump));
      return -1;
    }
  if (vapi_calc_sw_interface_lacp_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_lacp_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_lacp_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sw_interface_lacp_dump* vapi_alloc_sw_interface_lacp_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_sw_interface_lacp_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_sw_interface_lacp_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sw_interface_lacp_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sw_interface_lacp_dump);

  return msg;
}

static inline vapi_error_e vapi_sw_interface_lacp_dump(struct vapi_ctx_s *ctx,
  vapi_msg_sw_interface_lacp_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sw_interface_lacp_details *reply),
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
  vapi_msg_sw_interface_lacp_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sw_interface_lacp_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_sw_interface_lacp_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sw_interface_lacp_dump()
{
  static const char name[] = "sw_interface_lacp_dump";
  static const char name_with_crc[] = "sw_interface_lacp_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_sw_interface_lacp_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_sw_interface_lacp_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_lacp_dump_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_lacp_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_lacp_dump = vapi_register_msg(&__vapi_metadata_sw_interface_lacp_dump);
  VAPI_DBG("Assigned msg id %d to sw_interface_lacp_dump", vapi_msg_id_sw_interface_lacp_dump);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
