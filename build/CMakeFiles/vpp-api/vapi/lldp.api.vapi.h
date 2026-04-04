#ifndef __included_lldp_api_json
#define __included_lldp_api_json

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

extern vapi_msg_id_t vapi_msg_id_lldp_config;
extern vapi_msg_id_t vapi_msg_id_lldp_config_reply;
extern vapi_msg_id_t vapi_msg_id_sw_interface_set_lldp;
extern vapi_msg_id_t vapi_msg_id_sw_interface_set_lldp_reply;
extern vapi_msg_id_t vapi_msg_id_lldp_dump;
extern vapi_msg_id_t vapi_msg_id_lldp_dump_reply;
extern vapi_msg_id_t vapi_msg_id_lldp_details;

#define DEFINE_VAPI_MSG_IDS_LLDP_API_JSON\
  vapi_msg_id_t vapi_msg_id_lldp_config;\
  vapi_msg_id_t vapi_msg_id_lldp_config_reply;\
  vapi_msg_id_t vapi_msg_id_sw_interface_set_lldp;\
  vapi_msg_id_t vapi_msg_id_sw_interface_set_lldp_reply;\
  vapi_msg_id_t vapi_msg_id_lldp_dump;\
  vapi_msg_id_t vapi_msg_id_lldp_dump_reply;\
  vapi_msg_id_t vapi_msg_id_lldp_details;


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

#ifndef defined_vapi_enum_address_family
#define defined_vapi_enum_address_family
typedef enum {
  ADDRESS_IP4 = 0,
  ADDRESS_IP6 = 1,
} __attribute__((packed)) vapi_enum_address_family;

#endif

#ifndef defined_vapi_enum_ip_feature_location
#define defined_vapi_enum_ip_feature_location
typedef enum {
  IP_API_FEATURE_INPUT = 0,
  IP_API_FEATURE_OUTPUT = 1,
  IP_API_FEATURE_LOCAL = 2,
  IP_API_FEATURE_PUNT = 3,
  IP_API_FEATURE_DROP = 4,
} __attribute__((packed)) vapi_enum_ip_feature_location;

#endif

#ifndef defined_vapi_enum_ip_ecn
#define defined_vapi_enum_ip_ecn
typedef enum {
  IP_API_ECN_NONE = 0,
  IP_API_ECN_ECT0 = 1,
  IP_API_ECN_ECT1 = 2,
  IP_API_ECN_CE = 3,
} __attribute__((packed)) vapi_enum_ip_ecn;

#endif

#ifndef defined_vapi_enum_ip_dscp
#define defined_vapi_enum_ip_dscp
typedef enum {
  IP_API_DSCP_CS0 = 0,
  IP_API_DSCP_CS1 = 8,
  IP_API_DSCP_AF11 = 10,
  IP_API_DSCP_AF12 = 12,
  IP_API_DSCP_AF13 = 14,
  IP_API_DSCP_CS2 = 16,
  IP_API_DSCP_AF21 = 18,
  IP_API_DSCP_AF22 = 20,
  IP_API_DSCP_AF23 = 22,
  IP_API_DSCP_CS3 = 24,
  IP_API_DSCP_AF31 = 26,
  IP_API_DSCP_AF32 = 28,
  IP_API_DSCP_AF33 = 30,
  IP_API_DSCP_CS4 = 32,
  IP_API_DSCP_AF41 = 34,
  IP_API_DSCP_AF42 = 36,
  IP_API_DSCP_AF43 = 38,
  IP_API_DSCP_CS5 = 40,
  IP_API_DSCP_EF = 46,
  IP_API_DSCP_CS6 = 48,
  IP_API_DSCP_CS7 = 50,
} __attribute__((packed)) vapi_enum_ip_dscp;

#endif

#ifndef defined_vapi_enum_ip_proto
#define defined_vapi_enum_ip_proto
typedef enum {
  IP_API_PROTO_HOPOPT = 0,
  IP_API_PROTO_ICMP = 1,
  IP_API_PROTO_IGMP = 2,
  IP_API_PROTO_TCP = 6,
  IP_API_PROTO_UDP = 17,
  IP_API_PROTO_GRE = 47,
  IP_API_PROTO_ESP = 50,
  IP_API_PROTO_AH = 51,
  IP_API_PROTO_ICMP6 = 58,
  IP_API_PROTO_EIGRP = 88,
  IP_API_PROTO_OSPF = 89,
  IP_API_PROTO_SCTP = 132,
  IP_API_PROTO_RESERVED = 255,
} __attribute__((packed)) vapi_enum_ip_proto;

#endif

#ifndef defined_vapi_enum_port_id_subtype
#define defined_vapi_enum_port_id_subtype
typedef enum {
  PORT_ID_SUBTYPE_RESERVED = 0,
  PORT_ID_SUBTYPE_INTF_ALIAS = 1,
  PORT_ID_SUBTYPE_PORT_COMP = 2,
  PORT_ID_SUBTYPE_MAC_ADDR = 3,
  PORT_ID_SUBTYPE_NET_ADDR = 4,
  PORT_ID_SUBTYPE_INTF_NAME = 5,
  PORT_ID_SUBTYPE_AGENT_CIRCUIT_ID = 6,
  PORT_ID_SUBTYPE_LOCAL = 7,
}  vapi_enum_port_id_subtype;

#endif

#ifndef defined_vapi_enum_chassis_id_subtype
#define defined_vapi_enum_chassis_id_subtype
typedef enum {
  CHASSIS_ID_SUBTYPE_RESERVED = 0,
  CHASSIS_ID_SUBTYPE_CHASSIS_COMP = 1,
  CHASSIS_ID_SUBTYPE_INTF_ALIAS = 2,
  CHASSIS_ID_SUBTYPE_PORT_COMP = 3,
  CHASSIS_ID_SUBTYPE_MAC_ADDR = 4,
  CHASSIS_ID_SUBTYPE_NET_ADDR = 5,
  CHASSIS_ID_SUBTYPE_INTF_NAME = 6,
  CHASSIS_ID_SUBTYPE_LOCAL = 7,
}  vapi_enum_chassis_id_subtype;

#endif

#ifndef defined_vapi_type_ip4_address
#define defined_vapi_type_ip4_address
typedef u8 vapi_type_ip4_address[4];

#endif

#ifndef defined_vapi_type_ip6_address
#define defined_vapi_type_ip6_address
typedef u8 vapi_type_ip6_address[16];

#endif

#ifndef defined_vapi_union_address_union
#define defined_vapi_union_address_union
typedef union {
  vapi_type_ip4_address ip4;
  vapi_type_ip6_address ip6;
} vapi_union_address_union;

#endif

#ifndef defined_vapi_type_prefix_matcher
#define defined_vapi_type_prefix_matcher
typedef struct __attribute__((__packed__)) {
  u8 le;
  u8 ge;
} vapi_type_prefix_matcher;

static inline void vapi_type_prefix_matcher_hton(vapi_type_prefix_matcher *msg)
{

}

static inline void vapi_type_prefix_matcher_ntoh(vapi_type_prefix_matcher *msg)
{

}
#endif

#ifndef defined_vapi_type_address
#define defined_vapi_type_address
typedef struct __attribute__((__packed__)) {
  vapi_enum_address_family af;
  vapi_union_address_union un;
} vapi_type_address;

static inline void vapi_type_address_hton(vapi_type_address *msg)
{

}

static inline void vapi_type_address_ntoh(vapi_type_address *msg)
{

}
#endif

#ifndef defined_vapi_type_prefix
#define defined_vapi_type_prefix
typedef struct __attribute__((__packed__)) {
  vapi_type_address address;
  u8 len;
} vapi_type_prefix;

static inline void vapi_type_prefix_hton(vapi_type_prefix *msg)
{

}

static inline void vapi_type_prefix_ntoh(vapi_type_prefix *msg)
{

}
#endif

#ifndef defined_vapi_type_ip4_address_and_mask
#define defined_vapi_type_ip4_address_and_mask
typedef struct __attribute__((__packed__)) {
  vapi_type_ip4_address addr;
  vapi_type_ip4_address mask;
} vapi_type_ip4_address_and_mask;

static inline void vapi_type_ip4_address_and_mask_hton(vapi_type_ip4_address_and_mask *msg)
{

}

static inline void vapi_type_ip4_address_and_mask_ntoh(vapi_type_ip4_address_and_mask *msg)
{

}
#endif

#ifndef defined_vapi_type_ip6_address_and_mask
#define defined_vapi_type_ip6_address_and_mask
typedef struct __attribute__((__packed__)) {
  vapi_type_ip6_address addr;
  vapi_type_ip6_address mask;
} vapi_type_ip6_address_and_mask;

static inline void vapi_type_ip6_address_and_mask_hton(vapi_type_ip6_address_and_mask *msg)
{

}

static inline void vapi_type_ip6_address_and_mask_ntoh(vapi_type_ip6_address_and_mask *msg)
{

}
#endif

#ifndef defined_vapi_type_mprefix
#define defined_vapi_type_mprefix
typedef struct __attribute__((__packed__)) {
  vapi_enum_address_family af;
  u16 grp_address_length;
  vapi_union_address_union grp_address;
  vapi_union_address_union src_address;
} vapi_type_mprefix;

static inline void vapi_type_mprefix_hton(vapi_type_mprefix *msg)
{
  msg->grp_address_length = htobe16(msg->grp_address_length);
}

static inline void vapi_type_mprefix_ntoh(vapi_type_mprefix *msg)
{
  msg->grp_address_length = be16toh(msg->grp_address_length);
}
#endif

#ifndef defined_vapi_type_ip6_prefix
#define defined_vapi_type_ip6_prefix
typedef struct __attribute__((__packed__)) {
  vapi_type_ip6_address address;
  u8 len;
} vapi_type_ip6_prefix;

static inline void vapi_type_ip6_prefix_hton(vapi_type_ip6_prefix *msg)
{

}

static inline void vapi_type_ip6_prefix_ntoh(vapi_type_ip6_prefix *msg)
{

}
#endif

#ifndef defined_vapi_type_ip4_prefix
#define defined_vapi_type_ip4_prefix
typedef struct __attribute__((__packed__)) {
  vapi_type_ip4_address address;
  u8 len;
} vapi_type_ip4_prefix;

static inline void vapi_type_ip4_prefix_hton(vapi_type_ip4_prefix *msg)
{

}

static inline void vapi_type_ip4_prefix_ntoh(vapi_type_ip4_prefix *msg)
{

}
#endif

#ifndef defined_vapi_type_interface_index
#define defined_vapi_type_interface_index
typedef u32 vapi_type_interface_index;

#endif

#ifndef defined_vapi_type_address_with_prefix
#define defined_vapi_type_address_with_prefix
typedef vapi_type_prefix vapi_type_address_with_prefix;

#endif

#ifndef defined_vapi_type_ip4_address_with_prefix
#define defined_vapi_type_ip4_address_with_prefix
typedef vapi_type_ip4_prefix vapi_type_ip4_address_with_prefix;

#endif

#ifndef defined_vapi_type_ip6_address_with_prefix
#define defined_vapi_type_ip6_address_with_prefix
typedef vapi_type_ip6_prefix vapi_type_ip6_address_with_prefix;

#endif

#ifndef defined_vapi_msg_lldp_config_reply
#define defined_vapi_msg_lldp_config_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lldp_config_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lldp_config_reply payload;
} vapi_msg_lldp_config_reply;

static inline void vapi_msg_lldp_config_reply_payload_hton(vapi_payload_lldp_config_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lldp_config_reply_payload_ntoh(vapi_payload_lldp_config_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lldp_config_reply_hton(vapi_msg_lldp_config_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lldp_config_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lldp_config_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lldp_config_reply_ntoh(vapi_msg_lldp_config_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lldp_config_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lldp_config_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lldp_config_reply_msg_size(vapi_msg_lldp_config_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lldp_config_reply_msg_size(vapi_msg_lldp_config_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lldp_config_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lldp_config_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lldp_config_reply));
      return -1;
    }
  if (vapi_calc_lldp_config_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lldp_config_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lldp_config_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lldp_config_reply()
{
  static const char name[] = "lldp_config_reply";
  static const char name_with_crc[] = "lldp_config_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lldp_config_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lldp_config_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lldp_config_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lldp_config_reply_hton,
    (generic_swap_fn_t)vapi_msg_lldp_config_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lldp_config_reply = vapi_register_msg(&__vapi_metadata_lldp_config_reply);
  VAPI_DBG("Assigned msg id %d to lldp_config_reply", vapi_msg_id_lldp_config_reply);
}

static inline void vapi_set_vapi_msg_lldp_config_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lldp_config_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lldp_config_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lldp_config
#define defined_vapi_msg_lldp_config
typedef struct __attribute__ ((__packed__)) {
  u32 tx_hold;
  u32 tx_interval;
  vl_api_string_t system_name; 
} vapi_payload_lldp_config;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lldp_config payload;
} vapi_msg_lldp_config;

static inline void vapi_msg_lldp_config_payload_hton(vapi_payload_lldp_config *payload)
{
  payload->tx_hold = htobe32(payload->tx_hold);
  payload->tx_interval = htobe32(payload->tx_interval);
  vl_api_string_t_hton(&payload->system_name);
}

static inline void vapi_msg_lldp_config_payload_ntoh(vapi_payload_lldp_config *payload)
{
  payload->tx_hold = be32toh(payload->tx_hold);
  payload->tx_interval = be32toh(payload->tx_interval);
  vl_api_string_t_ntoh(&payload->system_name);
}

static inline void vapi_msg_lldp_config_hton(vapi_msg_lldp_config *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lldp_config'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lldp_config_payload_hton(&msg->payload);
}

static inline void vapi_msg_lldp_config_ntoh(vapi_msg_lldp_config *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lldp_config'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lldp_config_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lldp_config_msg_size(vapi_msg_lldp_config *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.system_name.buf[0]) * msg->payload.system_name.length;
}

static inline int vapi_verify_lldp_config_msg_size(vapi_msg_lldp_config *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lldp_config) > buf_size)
    {
      VAPI_ERR("Truncated 'lldp_config' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lldp_config));
      return -1;
    }
  if (vapi_calc_lldp_config_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lldp_config' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lldp_config_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lldp_config* vapi_alloc_lldp_config(struct vapi_ctx_s *ctx, size_t system_name_buf_array_size)
{
  vapi_msg_lldp_config *msg = NULL;
  const size_t size = sizeof(vapi_msg_lldp_config) + sizeof(msg->payload.system_name.buf[0]) * system_name_buf_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lldp_config*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lldp_config);
  msg->payload.system_name.length = system_name_buf_array_size;

  return msg;
}

static inline vapi_error_e vapi_lldp_config(struct vapi_ctx_s *ctx,
  vapi_msg_lldp_config *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lldp_config_reply *reply),
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
  vapi_msg_lldp_config_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lldp_config_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lldp_config_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lldp_config()
{
  static const char name[] = "lldp_config";
  static const char name_with_crc[] = "lldp_config_c14445df";
  static vapi_message_desc_t __vapi_metadata_lldp_config = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lldp_config, payload),
    (verify_msg_size_fn_t)vapi_verify_lldp_config_msg_size,
    (generic_swap_fn_t)vapi_msg_lldp_config_hton,
    (generic_swap_fn_t)vapi_msg_lldp_config_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lldp_config = vapi_register_msg(&__vapi_metadata_lldp_config);
  VAPI_DBG("Assigned msg id %d to lldp_config", vapi_msg_id_lldp_config);
}
#endif

#ifndef defined_vapi_msg_sw_interface_set_lldp_reply
#define defined_vapi_msg_sw_interface_set_lldp_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_sw_interface_set_lldp_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sw_interface_set_lldp_reply payload;
} vapi_msg_sw_interface_set_lldp_reply;

static inline void vapi_msg_sw_interface_set_lldp_reply_payload_hton(vapi_payload_sw_interface_set_lldp_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_sw_interface_set_lldp_reply_payload_ntoh(vapi_payload_sw_interface_set_lldp_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_sw_interface_set_lldp_reply_hton(vapi_msg_sw_interface_set_lldp_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_set_lldp_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sw_interface_set_lldp_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_set_lldp_reply_ntoh(vapi_msg_sw_interface_set_lldp_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_set_lldp_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sw_interface_set_lldp_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_set_lldp_reply_msg_size(vapi_msg_sw_interface_set_lldp_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_set_lldp_reply_msg_size(vapi_msg_sw_interface_set_lldp_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_set_lldp_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_set_lldp_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_set_lldp_reply));
      return -1;
    }
  if (vapi_calc_sw_interface_set_lldp_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_set_lldp_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_set_lldp_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sw_interface_set_lldp_reply()
{
  static const char name[] = "sw_interface_set_lldp_reply";
  static const char name_with_crc[] = "sw_interface_set_lldp_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_sw_interface_set_lldp_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sw_interface_set_lldp_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_set_lldp_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_set_lldp_reply_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_set_lldp_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_set_lldp_reply = vapi_register_msg(&__vapi_metadata_sw_interface_set_lldp_reply);
  VAPI_DBG("Assigned msg id %d to sw_interface_set_lldp_reply", vapi_msg_id_sw_interface_set_lldp_reply);
}

static inline void vapi_set_vapi_msg_sw_interface_set_lldp_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sw_interface_set_lldp_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sw_interface_set_lldp_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sw_interface_set_lldp
#define defined_vapi_msg_sw_interface_set_lldp
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_type_ip4_address mgmt_ip4;
  vapi_type_ip6_address mgmt_ip6;
  u8 mgmt_oid[128];
  bool enable;
  vl_api_string_t port_desc; 
} vapi_payload_sw_interface_set_lldp;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sw_interface_set_lldp payload;
} vapi_msg_sw_interface_set_lldp;

static inline void vapi_msg_sw_interface_set_lldp_payload_hton(vapi_payload_sw_interface_set_lldp *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  vl_api_string_t_hton(&payload->port_desc);
}

static inline void vapi_msg_sw_interface_set_lldp_payload_ntoh(vapi_payload_sw_interface_set_lldp *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  vl_api_string_t_ntoh(&payload->port_desc);
}

static inline void vapi_msg_sw_interface_set_lldp_hton(vapi_msg_sw_interface_set_lldp *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_set_lldp'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sw_interface_set_lldp_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_set_lldp_ntoh(vapi_msg_sw_interface_set_lldp *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_set_lldp'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sw_interface_set_lldp_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_set_lldp_msg_size(vapi_msg_sw_interface_set_lldp *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.port_desc.buf[0]) * msg->payload.port_desc.length;
}

static inline int vapi_verify_sw_interface_set_lldp_msg_size(vapi_msg_sw_interface_set_lldp *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_set_lldp) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_set_lldp' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_set_lldp));
      return -1;
    }
  if (vapi_calc_sw_interface_set_lldp_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_set_lldp' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_set_lldp_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sw_interface_set_lldp* vapi_alloc_sw_interface_set_lldp(struct vapi_ctx_s *ctx, size_t port_desc_buf_array_size)
{
  vapi_msg_sw_interface_set_lldp *msg = NULL;
  const size_t size = sizeof(vapi_msg_sw_interface_set_lldp) + sizeof(msg->payload.port_desc.buf[0]) * port_desc_buf_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sw_interface_set_lldp*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sw_interface_set_lldp);
  msg->payload.port_desc.length = port_desc_buf_array_size;

  return msg;
}

static inline vapi_error_e vapi_sw_interface_set_lldp(struct vapi_ctx_s *ctx,
  vapi_msg_sw_interface_set_lldp *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sw_interface_set_lldp_reply *reply),
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
  vapi_msg_sw_interface_set_lldp_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sw_interface_set_lldp_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sw_interface_set_lldp_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sw_interface_set_lldp()
{
  static const char name[] = "sw_interface_set_lldp";
  static const char name_with_crc[] = "sw_interface_set_lldp_57afbcd4";
  static vapi_message_desc_t __vapi_metadata_sw_interface_set_lldp = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sw_interface_set_lldp, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_set_lldp_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_set_lldp_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_set_lldp_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_set_lldp = vapi_register_msg(&__vapi_metadata_sw_interface_set_lldp);
  VAPI_DBG("Assigned msg id %d to sw_interface_set_lldp", vapi_msg_id_sw_interface_set_lldp);
}
#endif

#ifndef defined_vapi_msg_lldp_dump_reply
#define defined_vapi_msg_lldp_dump_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 cursor; 
} vapi_payload_lldp_dump_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lldp_dump_reply payload;
} vapi_msg_lldp_dump_reply;

static inline void vapi_msg_lldp_dump_reply_payload_hton(vapi_payload_lldp_dump_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_lldp_dump_reply_payload_ntoh(vapi_payload_lldp_dump_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_lldp_dump_reply_hton(vapi_msg_lldp_dump_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lldp_dump_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lldp_dump_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lldp_dump_reply_ntoh(vapi_msg_lldp_dump_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lldp_dump_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lldp_dump_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lldp_dump_reply_msg_size(vapi_msg_lldp_dump_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lldp_dump_reply_msg_size(vapi_msg_lldp_dump_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lldp_dump_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lldp_dump_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lldp_dump_reply));
      return -1;
    }
  if (vapi_calc_lldp_dump_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lldp_dump_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lldp_dump_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lldp_dump_reply()
{
  static const char name[] = "lldp_dump_reply";
  static const char name_with_crc[] = "lldp_dump_reply_53b48f5d";
  static vapi_message_desc_t __vapi_metadata_lldp_dump_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lldp_dump_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lldp_dump_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lldp_dump_reply_hton,
    (generic_swap_fn_t)vapi_msg_lldp_dump_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lldp_dump_reply = vapi_register_msg(&__vapi_metadata_lldp_dump_reply);
  VAPI_DBG("Assigned msg id %d to lldp_dump_reply", vapi_msg_id_lldp_dump_reply);
}

static inline void vapi_set_vapi_msg_lldp_dump_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lldp_dump_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lldp_dump_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lldp_details
#define defined_vapi_msg_lldp_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  f64 last_heard;
  f64 last_sent;
  u8 chassis_id[64];
  u8 chassis_id_len;
  u8 port_id[64];
  u8 port_id_len;
  u16 ttl;
  vapi_enum_port_id_subtype port_id_subtype;
  vapi_enum_chassis_id_subtype chassis_id_subtype; 
} vapi_payload_lldp_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lldp_details payload;
} vapi_msg_lldp_details;

static inline void vapi_msg_lldp_details_payload_hton(vapi_payload_lldp_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->ttl = htobe16(payload->ttl);
  payload->port_id_subtype = (vapi_enum_port_id_subtype)htobe32(payload->port_id_subtype);
  payload->chassis_id_subtype = (vapi_enum_chassis_id_subtype)htobe32(payload->chassis_id_subtype);
}

static inline void vapi_msg_lldp_details_payload_ntoh(vapi_payload_lldp_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->ttl = be16toh(payload->ttl);
  payload->port_id_subtype = (vapi_enum_port_id_subtype)be32toh(payload->port_id_subtype);
  payload->chassis_id_subtype = (vapi_enum_chassis_id_subtype)be32toh(payload->chassis_id_subtype);
}

static inline void vapi_msg_lldp_details_hton(vapi_msg_lldp_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lldp_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lldp_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_lldp_details_ntoh(vapi_msg_lldp_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lldp_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lldp_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lldp_details_msg_size(vapi_msg_lldp_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lldp_details_msg_size(vapi_msg_lldp_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lldp_details) > buf_size)
    {
      VAPI_ERR("Truncated 'lldp_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lldp_details));
      return -1;
    }
  if (vapi_calc_lldp_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lldp_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lldp_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lldp_details()
{
  static const char name[] = "lldp_details";
  static const char name_with_crc[] = "lldp_details_c2d226cd";
  static vapi_message_desc_t __vapi_metadata_lldp_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lldp_details, payload),
    (verify_msg_size_fn_t)vapi_verify_lldp_details_msg_size,
    (generic_swap_fn_t)vapi_msg_lldp_details_hton,
    (generic_swap_fn_t)vapi_msg_lldp_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lldp_details = vapi_register_msg(&__vapi_metadata_lldp_details);
  VAPI_DBG("Assigned msg id %d to lldp_details", vapi_msg_id_lldp_details);
}
#endif

#ifndef defined_vapi_msg_lldp_dump
#define defined_vapi_msg_lldp_dump
typedef struct __attribute__ ((__packed__)) {
  u32 cursor; 
} vapi_payload_lldp_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lldp_dump payload;
} vapi_msg_lldp_dump;

static inline void vapi_msg_lldp_dump_payload_hton(vapi_payload_lldp_dump *payload)
{
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_lldp_dump_payload_ntoh(vapi_payload_lldp_dump *payload)
{
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_lldp_dump_hton(vapi_msg_lldp_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lldp_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lldp_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_lldp_dump_ntoh(vapi_msg_lldp_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lldp_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lldp_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lldp_dump_msg_size(vapi_msg_lldp_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lldp_dump_msg_size(vapi_msg_lldp_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lldp_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'lldp_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lldp_dump));
      return -1;
    }
  if (vapi_calc_lldp_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lldp_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lldp_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lldp_dump* vapi_alloc_lldp_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_lldp_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_lldp_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lldp_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lldp_dump);

  return msg;
}

static inline vapi_error_e vapi_lldp_dump(struct vapi_ctx_s *ctx,
  vapi_msg_lldp_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lldp_dump_reply *reply),
  void *reply_callback_ctx,
  vapi_error_e (*details_callback)(struct vapi_ctx_s *ctx,
                                   void *callback_ctx,
                                   vapi_error_e rv,
                                   bool is_last,
                                   vapi_payload_lldp_details *details),
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
  vapi_msg_lldp_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lldp_details, VAPI_REQUEST_STREAM, 
                       (vapi_cb_t)details_callback, details_callback_ctx);
    vapi_store_request(ctx, req_context, vapi_msg_id_lldp_dump_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lldp_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lldp_dump()
{
  static const char name[] = "lldp_dump";
  static const char name_with_crc[] = "lldp_dump_f75ba505";
  static vapi_message_desc_t __vapi_metadata_lldp_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lldp_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_lldp_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_lldp_dump_hton,
    (generic_swap_fn_t)vapi_msg_lldp_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lldp_dump = vapi_register_msg(&__vapi_metadata_lldp_dump);
  VAPI_DBG("Assigned msg id %d to lldp_dump", vapi_msg_id_lldp_dump);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
