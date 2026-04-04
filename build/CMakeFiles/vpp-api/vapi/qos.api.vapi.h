#ifndef __included_qos_api_json
#define __included_qos_api_json

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

extern vapi_msg_id_t vapi_msg_id_qos_store_enable_disable;
extern vapi_msg_id_t vapi_msg_id_qos_store_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_qos_store_dump;
extern vapi_msg_id_t vapi_msg_id_qos_store_details;
extern vapi_msg_id_t vapi_msg_id_qos_record_enable_disable;
extern vapi_msg_id_t vapi_msg_id_qos_record_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_qos_record_dump;
extern vapi_msg_id_t vapi_msg_id_qos_record_details;
extern vapi_msg_id_t vapi_msg_id_qos_egress_map_update;
extern vapi_msg_id_t vapi_msg_id_qos_egress_map_update_reply;
extern vapi_msg_id_t vapi_msg_id_qos_egress_map_delete;
extern vapi_msg_id_t vapi_msg_id_qos_egress_map_delete_reply;
extern vapi_msg_id_t vapi_msg_id_qos_egress_map_dump;
extern vapi_msg_id_t vapi_msg_id_qos_egress_map_details;
extern vapi_msg_id_t vapi_msg_id_qos_mark_enable_disable;
extern vapi_msg_id_t vapi_msg_id_qos_mark_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_qos_mark_dump;
extern vapi_msg_id_t vapi_msg_id_qos_mark_details;

#define DEFINE_VAPI_MSG_IDS_QOS_API_JSON\
  vapi_msg_id_t vapi_msg_id_qos_store_enable_disable;\
  vapi_msg_id_t vapi_msg_id_qos_store_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_qos_store_dump;\
  vapi_msg_id_t vapi_msg_id_qos_store_details;\
  vapi_msg_id_t vapi_msg_id_qos_record_enable_disable;\
  vapi_msg_id_t vapi_msg_id_qos_record_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_qos_record_dump;\
  vapi_msg_id_t vapi_msg_id_qos_record_details;\
  vapi_msg_id_t vapi_msg_id_qos_egress_map_update;\
  vapi_msg_id_t vapi_msg_id_qos_egress_map_update_reply;\
  vapi_msg_id_t vapi_msg_id_qos_egress_map_delete;\
  vapi_msg_id_t vapi_msg_id_qos_egress_map_delete_reply;\
  vapi_msg_id_t vapi_msg_id_qos_egress_map_dump;\
  vapi_msg_id_t vapi_msg_id_qos_egress_map_details;\
  vapi_msg_id_t vapi_msg_id_qos_mark_enable_disable;\
  vapi_msg_id_t vapi_msg_id_qos_mark_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_qos_mark_dump;\
  vapi_msg_id_t vapi_msg_id_qos_mark_details;


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

#ifndef defined_vapi_enum_qos_source
#define defined_vapi_enum_qos_source
typedef enum {
  QOS_API_SOURCE_EXT = 0,
  QOS_API_SOURCE_VLAN = 1,
  QOS_API_SOURCE_MPLS = 2,
  QOS_API_SOURCE_IP = 3,
} __attribute__((packed)) vapi_enum_qos_source;

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

#ifndef defined_vapi_type_qos_egress_map_row
#define defined_vapi_type_qos_egress_map_row
typedef struct __attribute__((__packed__)) {
  u8 outputs[256];
} vapi_type_qos_egress_map_row;

static inline void vapi_type_qos_egress_map_row_hton(vapi_type_qos_egress_map_row *msg)
{

}

static inline void vapi_type_qos_egress_map_row_ntoh(vapi_type_qos_egress_map_row *msg)
{

}
#endif

#ifndef defined_vapi_type_qos_egress_map
#define defined_vapi_type_qos_egress_map
typedef struct __attribute__((__packed__)) {
  u32 id;
  vapi_type_qos_egress_map_row rows[4];
} vapi_type_qos_egress_map;

static inline void vapi_type_qos_egress_map_hton(vapi_type_qos_egress_map *msg)
{
  msg->id = htobe32(msg->id);
}

static inline void vapi_type_qos_egress_map_ntoh(vapi_type_qos_egress_map *msg)
{
  msg->id = be32toh(msg->id);
}
#endif

#ifndef defined_vapi_type_qos_mark
#define defined_vapi_type_qos_mark
typedef struct __attribute__((__packed__)) {
  u32 sw_if_index;
  u32 map_id;
  vapi_enum_qos_source output_source;
} vapi_type_qos_mark;

static inline void vapi_type_qos_mark_hton(vapi_type_qos_mark *msg)
{
  msg->sw_if_index = htobe32(msg->sw_if_index);
  msg->map_id = htobe32(msg->map_id);
}

static inline void vapi_type_qos_mark_ntoh(vapi_type_qos_mark *msg)
{
  msg->sw_if_index = be32toh(msg->sw_if_index);
  msg->map_id = be32toh(msg->map_id);
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

#ifndef defined_vapi_type_qos_store
#define defined_vapi_type_qos_store
typedef struct __attribute__((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_enum_qos_source input_source;
  u8 value;
} vapi_type_qos_store;

static inline void vapi_type_qos_store_hton(vapi_type_qos_store *msg)
{
  msg->sw_if_index = htobe32(msg->sw_if_index);
}

static inline void vapi_type_qos_store_ntoh(vapi_type_qos_store *msg)
{
  msg->sw_if_index = be32toh(msg->sw_if_index);
}
#endif

#ifndef defined_vapi_type_qos_record
#define defined_vapi_type_qos_record
typedef struct __attribute__((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_enum_qos_source input_source;
} vapi_type_qos_record;

static inline void vapi_type_qos_record_hton(vapi_type_qos_record *msg)
{
  msg->sw_if_index = htobe32(msg->sw_if_index);
}

static inline void vapi_type_qos_record_ntoh(vapi_type_qos_record *msg)
{
  msg->sw_if_index = be32toh(msg->sw_if_index);
}
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

#ifndef defined_vapi_msg_qos_store_enable_disable_reply
#define defined_vapi_msg_qos_store_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_qos_store_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_qos_store_enable_disable_reply payload;
} vapi_msg_qos_store_enable_disable_reply;

static inline void vapi_msg_qos_store_enable_disable_reply_payload_hton(vapi_payload_qos_store_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_qos_store_enable_disable_reply_payload_ntoh(vapi_payload_qos_store_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_qos_store_enable_disable_reply_hton(vapi_msg_qos_store_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_store_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_qos_store_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_qos_store_enable_disable_reply_ntoh(vapi_msg_qos_store_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_store_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_qos_store_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_qos_store_enable_disable_reply_msg_size(vapi_msg_qos_store_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_qos_store_enable_disable_reply_msg_size(vapi_msg_qos_store_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_qos_store_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_store_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_qos_store_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_qos_store_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_store_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_qos_store_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_qos_store_enable_disable_reply()
{
  static const char name[] = "qos_store_enable_disable_reply";
  static const char name_with_crc[] = "qos_store_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_qos_store_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_qos_store_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_qos_store_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_qos_store_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_qos_store_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_qos_store_enable_disable_reply = vapi_register_msg(&__vapi_metadata_qos_store_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to qos_store_enable_disable_reply", vapi_msg_id_qos_store_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_qos_store_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_qos_store_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_qos_store_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_qos_store_enable_disable
#define defined_vapi_msg_qos_store_enable_disable
typedef struct __attribute__ ((__packed__)) {
  bool enable;
  vapi_type_qos_store store; 
} vapi_payload_qos_store_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_qos_store_enable_disable payload;
} vapi_msg_qos_store_enable_disable;

static inline void vapi_msg_qos_store_enable_disable_payload_hton(vapi_payload_qos_store_enable_disable *payload)
{
  vapi_type_qos_store_hton(&payload->store);
}

static inline void vapi_msg_qos_store_enable_disable_payload_ntoh(vapi_payload_qos_store_enable_disable *payload)
{
  vapi_type_qos_store_ntoh(&payload->store);
}

static inline void vapi_msg_qos_store_enable_disable_hton(vapi_msg_qos_store_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_store_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_qos_store_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_qos_store_enable_disable_ntoh(vapi_msg_qos_store_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_store_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_qos_store_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_qos_store_enable_disable_msg_size(vapi_msg_qos_store_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_qos_store_enable_disable_msg_size(vapi_msg_qos_store_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_qos_store_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_store_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_qos_store_enable_disable));
      return -1;
    }
  if (vapi_calc_qos_store_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_store_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_qos_store_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_qos_store_enable_disable* vapi_alloc_qos_store_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_qos_store_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_qos_store_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_qos_store_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_qos_store_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_qos_store_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_qos_store_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_qos_store_enable_disable_reply *reply),
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
  vapi_msg_qos_store_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_qos_store_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_qos_store_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_qos_store_enable_disable()
{
  static const char name[] = "qos_store_enable_disable";
  static const char name_with_crc[] = "qos_store_enable_disable_f3abcc8b";
  static vapi_message_desc_t __vapi_metadata_qos_store_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_qos_store_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_qos_store_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_qos_store_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_qos_store_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_qos_store_enable_disable = vapi_register_msg(&__vapi_metadata_qos_store_enable_disable);
  VAPI_DBG("Assigned msg id %d to qos_store_enable_disable", vapi_msg_id_qos_store_enable_disable);
}
#endif

#ifndef defined_vapi_msg_qos_store_details
#define defined_vapi_msg_qos_store_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_qos_store store; 
} vapi_payload_qos_store_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_qos_store_details payload;
} vapi_msg_qos_store_details;

static inline void vapi_msg_qos_store_details_payload_hton(vapi_payload_qos_store_details *payload)
{
  vapi_type_qos_store_hton(&payload->store);
}

static inline void vapi_msg_qos_store_details_payload_ntoh(vapi_payload_qos_store_details *payload)
{
  vapi_type_qos_store_ntoh(&payload->store);
}

static inline void vapi_msg_qos_store_details_hton(vapi_msg_qos_store_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_store_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_qos_store_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_qos_store_details_ntoh(vapi_msg_qos_store_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_store_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_qos_store_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_qos_store_details_msg_size(vapi_msg_qos_store_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_qos_store_details_msg_size(vapi_msg_qos_store_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_qos_store_details) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_store_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_qos_store_details));
      return -1;
    }
  if (vapi_calc_qos_store_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_store_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_qos_store_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_qos_store_details()
{
  static const char name[] = "qos_store_details";
  static const char name_with_crc[] = "qos_store_details_3ee0aad7";
  static vapi_message_desc_t __vapi_metadata_qos_store_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_qos_store_details, payload),
    (verify_msg_size_fn_t)vapi_verify_qos_store_details_msg_size,
    (generic_swap_fn_t)vapi_msg_qos_store_details_hton,
    (generic_swap_fn_t)vapi_msg_qos_store_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_qos_store_details = vapi_register_msg(&__vapi_metadata_qos_store_details);
  VAPI_DBG("Assigned msg id %d to qos_store_details", vapi_msg_id_qos_store_details);
}

static inline void vapi_set_vapi_msg_qos_store_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_qos_store_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_qos_store_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_qos_store_dump
#define defined_vapi_msg_qos_store_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_qos_store_dump;

static inline void vapi_msg_qos_store_dump_hton(vapi_msg_qos_store_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_store_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_qos_store_dump_ntoh(vapi_msg_qos_store_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_store_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_qos_store_dump_msg_size(vapi_msg_qos_store_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_qos_store_dump_msg_size(vapi_msg_qos_store_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_qos_store_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_store_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_qos_store_dump));
      return -1;
    }
  if (vapi_calc_qos_store_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_store_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_qos_store_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_qos_store_dump* vapi_alloc_qos_store_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_qos_store_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_qos_store_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_qos_store_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_qos_store_dump);

  return msg;
}

static inline vapi_error_e vapi_qos_store_dump(struct vapi_ctx_s *ctx,
  vapi_msg_qos_store_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_qos_store_details *reply),
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
  vapi_msg_qos_store_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_qos_store_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_qos_store_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_qos_store_dump()
{
  static const char name[] = "qos_store_dump";
  static const char name_with_crc[] = "qos_store_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_qos_store_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_qos_store_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_qos_store_dump_hton,
    (generic_swap_fn_t)vapi_msg_qos_store_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_qos_store_dump = vapi_register_msg(&__vapi_metadata_qos_store_dump);
  VAPI_DBG("Assigned msg id %d to qos_store_dump", vapi_msg_id_qos_store_dump);
}
#endif

#ifndef defined_vapi_msg_qos_record_enable_disable_reply
#define defined_vapi_msg_qos_record_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_qos_record_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_qos_record_enable_disable_reply payload;
} vapi_msg_qos_record_enable_disable_reply;

static inline void vapi_msg_qos_record_enable_disable_reply_payload_hton(vapi_payload_qos_record_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_qos_record_enable_disable_reply_payload_ntoh(vapi_payload_qos_record_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_qos_record_enable_disable_reply_hton(vapi_msg_qos_record_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_record_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_qos_record_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_qos_record_enable_disable_reply_ntoh(vapi_msg_qos_record_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_record_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_qos_record_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_qos_record_enable_disable_reply_msg_size(vapi_msg_qos_record_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_qos_record_enable_disable_reply_msg_size(vapi_msg_qos_record_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_qos_record_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_record_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_qos_record_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_qos_record_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_record_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_qos_record_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_qos_record_enable_disable_reply()
{
  static const char name[] = "qos_record_enable_disable_reply";
  static const char name_with_crc[] = "qos_record_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_qos_record_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_qos_record_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_qos_record_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_qos_record_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_qos_record_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_qos_record_enable_disable_reply = vapi_register_msg(&__vapi_metadata_qos_record_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to qos_record_enable_disable_reply", vapi_msg_id_qos_record_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_qos_record_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_qos_record_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_qos_record_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_qos_record_enable_disable
#define defined_vapi_msg_qos_record_enable_disable
typedef struct __attribute__ ((__packed__)) {
  bool enable;
  vapi_type_qos_record record; 
} vapi_payload_qos_record_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_qos_record_enable_disable payload;
} vapi_msg_qos_record_enable_disable;

static inline void vapi_msg_qos_record_enable_disable_payload_hton(vapi_payload_qos_record_enable_disable *payload)
{
  vapi_type_qos_record_hton(&payload->record);
}

static inline void vapi_msg_qos_record_enable_disable_payload_ntoh(vapi_payload_qos_record_enable_disable *payload)
{
  vapi_type_qos_record_ntoh(&payload->record);
}

static inline void vapi_msg_qos_record_enable_disable_hton(vapi_msg_qos_record_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_record_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_qos_record_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_qos_record_enable_disable_ntoh(vapi_msg_qos_record_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_record_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_qos_record_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_qos_record_enable_disable_msg_size(vapi_msg_qos_record_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_qos_record_enable_disable_msg_size(vapi_msg_qos_record_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_qos_record_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_record_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_qos_record_enable_disable));
      return -1;
    }
  if (vapi_calc_qos_record_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_record_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_qos_record_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_qos_record_enable_disable* vapi_alloc_qos_record_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_qos_record_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_qos_record_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_qos_record_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_qos_record_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_qos_record_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_qos_record_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_qos_record_enable_disable_reply *reply),
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
  vapi_msg_qos_record_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_qos_record_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_qos_record_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_qos_record_enable_disable()
{
  static const char name[] = "qos_record_enable_disable";
  static const char name_with_crc[] = "qos_record_enable_disable_2f1a4a38";
  static vapi_message_desc_t __vapi_metadata_qos_record_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_qos_record_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_qos_record_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_qos_record_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_qos_record_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_qos_record_enable_disable = vapi_register_msg(&__vapi_metadata_qos_record_enable_disable);
  VAPI_DBG("Assigned msg id %d to qos_record_enable_disable", vapi_msg_id_qos_record_enable_disable);
}
#endif

#ifndef defined_vapi_msg_qos_record_details
#define defined_vapi_msg_qos_record_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_qos_record record; 
} vapi_payload_qos_record_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_qos_record_details payload;
} vapi_msg_qos_record_details;

static inline void vapi_msg_qos_record_details_payload_hton(vapi_payload_qos_record_details *payload)
{
  vapi_type_qos_record_hton(&payload->record);
}

static inline void vapi_msg_qos_record_details_payload_ntoh(vapi_payload_qos_record_details *payload)
{
  vapi_type_qos_record_ntoh(&payload->record);
}

static inline void vapi_msg_qos_record_details_hton(vapi_msg_qos_record_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_record_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_qos_record_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_qos_record_details_ntoh(vapi_msg_qos_record_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_record_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_qos_record_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_qos_record_details_msg_size(vapi_msg_qos_record_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_qos_record_details_msg_size(vapi_msg_qos_record_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_qos_record_details) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_record_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_qos_record_details));
      return -1;
    }
  if (vapi_calc_qos_record_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_record_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_qos_record_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_qos_record_details()
{
  static const char name[] = "qos_record_details";
  static const char name_with_crc[] = "qos_record_details_a425d4d3";
  static vapi_message_desc_t __vapi_metadata_qos_record_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_qos_record_details, payload),
    (verify_msg_size_fn_t)vapi_verify_qos_record_details_msg_size,
    (generic_swap_fn_t)vapi_msg_qos_record_details_hton,
    (generic_swap_fn_t)vapi_msg_qos_record_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_qos_record_details = vapi_register_msg(&__vapi_metadata_qos_record_details);
  VAPI_DBG("Assigned msg id %d to qos_record_details", vapi_msg_id_qos_record_details);
}

static inline void vapi_set_vapi_msg_qos_record_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_qos_record_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_qos_record_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_qos_record_dump
#define defined_vapi_msg_qos_record_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_qos_record_dump;

static inline void vapi_msg_qos_record_dump_hton(vapi_msg_qos_record_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_record_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_qos_record_dump_ntoh(vapi_msg_qos_record_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_record_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_qos_record_dump_msg_size(vapi_msg_qos_record_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_qos_record_dump_msg_size(vapi_msg_qos_record_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_qos_record_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_record_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_qos_record_dump));
      return -1;
    }
  if (vapi_calc_qos_record_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_record_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_qos_record_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_qos_record_dump* vapi_alloc_qos_record_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_qos_record_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_qos_record_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_qos_record_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_qos_record_dump);

  return msg;
}

static inline vapi_error_e vapi_qos_record_dump(struct vapi_ctx_s *ctx,
  vapi_msg_qos_record_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_qos_record_details *reply),
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
  vapi_msg_qos_record_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_qos_record_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_qos_record_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_qos_record_dump()
{
  static const char name[] = "qos_record_dump";
  static const char name_with_crc[] = "qos_record_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_qos_record_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_qos_record_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_qos_record_dump_hton,
    (generic_swap_fn_t)vapi_msg_qos_record_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_qos_record_dump = vapi_register_msg(&__vapi_metadata_qos_record_dump);
  VAPI_DBG("Assigned msg id %d to qos_record_dump", vapi_msg_id_qos_record_dump);
}
#endif

#ifndef defined_vapi_msg_qos_egress_map_update_reply
#define defined_vapi_msg_qos_egress_map_update_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_qos_egress_map_update_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_qos_egress_map_update_reply payload;
} vapi_msg_qos_egress_map_update_reply;

static inline void vapi_msg_qos_egress_map_update_reply_payload_hton(vapi_payload_qos_egress_map_update_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_qos_egress_map_update_reply_payload_ntoh(vapi_payload_qos_egress_map_update_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_qos_egress_map_update_reply_hton(vapi_msg_qos_egress_map_update_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_egress_map_update_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_qos_egress_map_update_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_qos_egress_map_update_reply_ntoh(vapi_msg_qos_egress_map_update_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_egress_map_update_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_qos_egress_map_update_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_qos_egress_map_update_reply_msg_size(vapi_msg_qos_egress_map_update_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_qos_egress_map_update_reply_msg_size(vapi_msg_qos_egress_map_update_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_qos_egress_map_update_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_egress_map_update_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_qos_egress_map_update_reply));
      return -1;
    }
  if (vapi_calc_qos_egress_map_update_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_egress_map_update_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_qos_egress_map_update_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_qos_egress_map_update_reply()
{
  static const char name[] = "qos_egress_map_update_reply";
  static const char name_with_crc[] = "qos_egress_map_update_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_qos_egress_map_update_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_qos_egress_map_update_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_qos_egress_map_update_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_qos_egress_map_update_reply_hton,
    (generic_swap_fn_t)vapi_msg_qos_egress_map_update_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_qos_egress_map_update_reply = vapi_register_msg(&__vapi_metadata_qos_egress_map_update_reply);
  VAPI_DBG("Assigned msg id %d to qos_egress_map_update_reply", vapi_msg_id_qos_egress_map_update_reply);
}

static inline void vapi_set_vapi_msg_qos_egress_map_update_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_qos_egress_map_update_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_qos_egress_map_update_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_qos_egress_map_update
#define defined_vapi_msg_qos_egress_map_update
typedef struct __attribute__ ((__packed__)) {
  vapi_type_qos_egress_map map; 
} vapi_payload_qos_egress_map_update;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_qos_egress_map_update payload;
} vapi_msg_qos_egress_map_update;

static inline void vapi_msg_qos_egress_map_update_payload_hton(vapi_payload_qos_egress_map_update *payload)
{
  vapi_type_qos_egress_map_hton(&payload->map);
}

static inline void vapi_msg_qos_egress_map_update_payload_ntoh(vapi_payload_qos_egress_map_update *payload)
{
  vapi_type_qos_egress_map_ntoh(&payload->map);
}

static inline void vapi_msg_qos_egress_map_update_hton(vapi_msg_qos_egress_map_update *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_egress_map_update'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_qos_egress_map_update_payload_hton(&msg->payload);
}

static inline void vapi_msg_qos_egress_map_update_ntoh(vapi_msg_qos_egress_map_update *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_egress_map_update'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_qos_egress_map_update_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_qos_egress_map_update_msg_size(vapi_msg_qos_egress_map_update *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_qos_egress_map_update_msg_size(vapi_msg_qos_egress_map_update *msg, uword buf_size)
{
  if (sizeof(vapi_msg_qos_egress_map_update) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_egress_map_update' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_qos_egress_map_update));
      return -1;
    }
  if (vapi_calc_qos_egress_map_update_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_egress_map_update' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_qos_egress_map_update_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_qos_egress_map_update* vapi_alloc_qos_egress_map_update(struct vapi_ctx_s *ctx)
{
  vapi_msg_qos_egress_map_update *msg = NULL;
  const size_t size = sizeof(vapi_msg_qos_egress_map_update);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_qos_egress_map_update*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_qos_egress_map_update);

  return msg;
}

static inline vapi_error_e vapi_qos_egress_map_update(struct vapi_ctx_s *ctx,
  vapi_msg_qos_egress_map_update *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_qos_egress_map_update_reply *reply),
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
  vapi_msg_qos_egress_map_update_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_qos_egress_map_update_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_qos_egress_map_update_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_qos_egress_map_update()
{
  static const char name[] = "qos_egress_map_update";
  static const char name_with_crc[] = "qos_egress_map_update_6d1c065f";
  static vapi_message_desc_t __vapi_metadata_qos_egress_map_update = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_qos_egress_map_update, payload),
    (verify_msg_size_fn_t)vapi_verify_qos_egress_map_update_msg_size,
    (generic_swap_fn_t)vapi_msg_qos_egress_map_update_hton,
    (generic_swap_fn_t)vapi_msg_qos_egress_map_update_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_qos_egress_map_update = vapi_register_msg(&__vapi_metadata_qos_egress_map_update);
  VAPI_DBG("Assigned msg id %d to qos_egress_map_update", vapi_msg_id_qos_egress_map_update);
}
#endif

#ifndef defined_vapi_msg_qos_egress_map_delete_reply
#define defined_vapi_msg_qos_egress_map_delete_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_qos_egress_map_delete_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_qos_egress_map_delete_reply payload;
} vapi_msg_qos_egress_map_delete_reply;

static inline void vapi_msg_qos_egress_map_delete_reply_payload_hton(vapi_payload_qos_egress_map_delete_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_qos_egress_map_delete_reply_payload_ntoh(vapi_payload_qos_egress_map_delete_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_qos_egress_map_delete_reply_hton(vapi_msg_qos_egress_map_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_egress_map_delete_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_qos_egress_map_delete_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_qos_egress_map_delete_reply_ntoh(vapi_msg_qos_egress_map_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_egress_map_delete_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_qos_egress_map_delete_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_qos_egress_map_delete_reply_msg_size(vapi_msg_qos_egress_map_delete_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_qos_egress_map_delete_reply_msg_size(vapi_msg_qos_egress_map_delete_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_qos_egress_map_delete_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_egress_map_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_qos_egress_map_delete_reply));
      return -1;
    }
  if (vapi_calc_qos_egress_map_delete_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_egress_map_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_qos_egress_map_delete_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_qos_egress_map_delete_reply()
{
  static const char name[] = "qos_egress_map_delete_reply";
  static const char name_with_crc[] = "qos_egress_map_delete_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_qos_egress_map_delete_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_qos_egress_map_delete_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_qos_egress_map_delete_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_qos_egress_map_delete_reply_hton,
    (generic_swap_fn_t)vapi_msg_qos_egress_map_delete_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_qos_egress_map_delete_reply = vapi_register_msg(&__vapi_metadata_qos_egress_map_delete_reply);
  VAPI_DBG("Assigned msg id %d to qos_egress_map_delete_reply", vapi_msg_id_qos_egress_map_delete_reply);
}

static inline void vapi_set_vapi_msg_qos_egress_map_delete_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_qos_egress_map_delete_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_qos_egress_map_delete_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_qos_egress_map_delete
#define defined_vapi_msg_qos_egress_map_delete
typedef struct __attribute__ ((__packed__)) {
  u32 id; 
} vapi_payload_qos_egress_map_delete;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_qos_egress_map_delete payload;
} vapi_msg_qos_egress_map_delete;

static inline void vapi_msg_qos_egress_map_delete_payload_hton(vapi_payload_qos_egress_map_delete *payload)
{
  payload->id = htobe32(payload->id);
}

static inline void vapi_msg_qos_egress_map_delete_payload_ntoh(vapi_payload_qos_egress_map_delete *payload)
{
  payload->id = be32toh(payload->id);
}

static inline void vapi_msg_qos_egress_map_delete_hton(vapi_msg_qos_egress_map_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_egress_map_delete'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_qos_egress_map_delete_payload_hton(&msg->payload);
}

static inline void vapi_msg_qos_egress_map_delete_ntoh(vapi_msg_qos_egress_map_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_egress_map_delete'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_qos_egress_map_delete_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_qos_egress_map_delete_msg_size(vapi_msg_qos_egress_map_delete *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_qos_egress_map_delete_msg_size(vapi_msg_qos_egress_map_delete *msg, uword buf_size)
{
  if (sizeof(vapi_msg_qos_egress_map_delete) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_egress_map_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_qos_egress_map_delete));
      return -1;
    }
  if (vapi_calc_qos_egress_map_delete_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_egress_map_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_qos_egress_map_delete_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_qos_egress_map_delete* vapi_alloc_qos_egress_map_delete(struct vapi_ctx_s *ctx)
{
  vapi_msg_qos_egress_map_delete *msg = NULL;
  const size_t size = sizeof(vapi_msg_qos_egress_map_delete);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_qos_egress_map_delete*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_qos_egress_map_delete);

  return msg;
}

static inline vapi_error_e vapi_qos_egress_map_delete(struct vapi_ctx_s *ctx,
  vapi_msg_qos_egress_map_delete *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_qos_egress_map_delete_reply *reply),
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
  vapi_msg_qos_egress_map_delete_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_qos_egress_map_delete_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_qos_egress_map_delete_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_qos_egress_map_delete()
{
  static const char name[] = "qos_egress_map_delete";
  static const char name_with_crc[] = "qos_egress_map_delete_3a91bde5";
  static vapi_message_desc_t __vapi_metadata_qos_egress_map_delete = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_qos_egress_map_delete, payload),
    (verify_msg_size_fn_t)vapi_verify_qos_egress_map_delete_msg_size,
    (generic_swap_fn_t)vapi_msg_qos_egress_map_delete_hton,
    (generic_swap_fn_t)vapi_msg_qos_egress_map_delete_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_qos_egress_map_delete = vapi_register_msg(&__vapi_metadata_qos_egress_map_delete);
  VAPI_DBG("Assigned msg id %d to qos_egress_map_delete", vapi_msg_id_qos_egress_map_delete);
}
#endif

#ifndef defined_vapi_msg_qos_egress_map_details
#define defined_vapi_msg_qos_egress_map_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_qos_egress_map map; 
} vapi_payload_qos_egress_map_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_qos_egress_map_details payload;
} vapi_msg_qos_egress_map_details;

static inline void vapi_msg_qos_egress_map_details_payload_hton(vapi_payload_qos_egress_map_details *payload)
{
  vapi_type_qos_egress_map_hton(&payload->map);
}

static inline void vapi_msg_qos_egress_map_details_payload_ntoh(vapi_payload_qos_egress_map_details *payload)
{
  vapi_type_qos_egress_map_ntoh(&payload->map);
}

static inline void vapi_msg_qos_egress_map_details_hton(vapi_msg_qos_egress_map_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_egress_map_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_qos_egress_map_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_qos_egress_map_details_ntoh(vapi_msg_qos_egress_map_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_egress_map_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_qos_egress_map_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_qos_egress_map_details_msg_size(vapi_msg_qos_egress_map_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_qos_egress_map_details_msg_size(vapi_msg_qos_egress_map_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_qos_egress_map_details) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_egress_map_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_qos_egress_map_details));
      return -1;
    }
  if (vapi_calc_qos_egress_map_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_egress_map_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_qos_egress_map_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_qos_egress_map_details()
{
  static const char name[] = "qos_egress_map_details";
  static const char name_with_crc[] = "qos_egress_map_details_46c5653c";
  static vapi_message_desc_t __vapi_metadata_qos_egress_map_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_qos_egress_map_details, payload),
    (verify_msg_size_fn_t)vapi_verify_qos_egress_map_details_msg_size,
    (generic_swap_fn_t)vapi_msg_qos_egress_map_details_hton,
    (generic_swap_fn_t)vapi_msg_qos_egress_map_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_qos_egress_map_details = vapi_register_msg(&__vapi_metadata_qos_egress_map_details);
  VAPI_DBG("Assigned msg id %d to qos_egress_map_details", vapi_msg_id_qos_egress_map_details);
}

static inline void vapi_set_vapi_msg_qos_egress_map_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_qos_egress_map_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_qos_egress_map_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_qos_egress_map_dump
#define defined_vapi_msg_qos_egress_map_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_qos_egress_map_dump;

static inline void vapi_msg_qos_egress_map_dump_hton(vapi_msg_qos_egress_map_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_egress_map_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_qos_egress_map_dump_ntoh(vapi_msg_qos_egress_map_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_egress_map_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_qos_egress_map_dump_msg_size(vapi_msg_qos_egress_map_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_qos_egress_map_dump_msg_size(vapi_msg_qos_egress_map_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_qos_egress_map_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_egress_map_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_qos_egress_map_dump));
      return -1;
    }
  if (vapi_calc_qos_egress_map_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_egress_map_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_qos_egress_map_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_qos_egress_map_dump* vapi_alloc_qos_egress_map_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_qos_egress_map_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_qos_egress_map_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_qos_egress_map_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_qos_egress_map_dump);

  return msg;
}

static inline vapi_error_e vapi_qos_egress_map_dump(struct vapi_ctx_s *ctx,
  vapi_msg_qos_egress_map_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_qos_egress_map_details *reply),
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
  vapi_msg_qos_egress_map_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_qos_egress_map_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_qos_egress_map_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_qos_egress_map_dump()
{
  static const char name[] = "qos_egress_map_dump";
  static const char name_with_crc[] = "qos_egress_map_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_qos_egress_map_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_qos_egress_map_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_qos_egress_map_dump_hton,
    (generic_swap_fn_t)vapi_msg_qos_egress_map_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_qos_egress_map_dump = vapi_register_msg(&__vapi_metadata_qos_egress_map_dump);
  VAPI_DBG("Assigned msg id %d to qos_egress_map_dump", vapi_msg_id_qos_egress_map_dump);
}
#endif

#ifndef defined_vapi_msg_qos_mark_enable_disable_reply
#define defined_vapi_msg_qos_mark_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_qos_mark_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_qos_mark_enable_disable_reply payload;
} vapi_msg_qos_mark_enable_disable_reply;

static inline void vapi_msg_qos_mark_enable_disable_reply_payload_hton(vapi_payload_qos_mark_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_qos_mark_enable_disable_reply_payload_ntoh(vapi_payload_qos_mark_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_qos_mark_enable_disable_reply_hton(vapi_msg_qos_mark_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_mark_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_qos_mark_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_qos_mark_enable_disable_reply_ntoh(vapi_msg_qos_mark_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_mark_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_qos_mark_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_qos_mark_enable_disable_reply_msg_size(vapi_msg_qos_mark_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_qos_mark_enable_disable_reply_msg_size(vapi_msg_qos_mark_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_qos_mark_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_mark_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_qos_mark_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_qos_mark_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_mark_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_qos_mark_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_qos_mark_enable_disable_reply()
{
  static const char name[] = "qos_mark_enable_disable_reply";
  static const char name_with_crc[] = "qos_mark_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_qos_mark_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_qos_mark_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_qos_mark_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_qos_mark_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_qos_mark_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_qos_mark_enable_disable_reply = vapi_register_msg(&__vapi_metadata_qos_mark_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to qos_mark_enable_disable_reply", vapi_msg_id_qos_mark_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_qos_mark_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_qos_mark_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_qos_mark_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_qos_mark_enable_disable
#define defined_vapi_msg_qos_mark_enable_disable
typedef struct __attribute__ ((__packed__)) {
  bool enable;
  vapi_type_qos_mark mark; 
} vapi_payload_qos_mark_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_qos_mark_enable_disable payload;
} vapi_msg_qos_mark_enable_disable;

static inline void vapi_msg_qos_mark_enable_disable_payload_hton(vapi_payload_qos_mark_enable_disable *payload)
{
  vapi_type_qos_mark_hton(&payload->mark);
}

static inline void vapi_msg_qos_mark_enable_disable_payload_ntoh(vapi_payload_qos_mark_enable_disable *payload)
{
  vapi_type_qos_mark_ntoh(&payload->mark);
}

static inline void vapi_msg_qos_mark_enable_disable_hton(vapi_msg_qos_mark_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_mark_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_qos_mark_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_qos_mark_enable_disable_ntoh(vapi_msg_qos_mark_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_mark_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_qos_mark_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_qos_mark_enable_disable_msg_size(vapi_msg_qos_mark_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_qos_mark_enable_disable_msg_size(vapi_msg_qos_mark_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_qos_mark_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_mark_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_qos_mark_enable_disable));
      return -1;
    }
  if (vapi_calc_qos_mark_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_mark_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_qos_mark_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_qos_mark_enable_disable* vapi_alloc_qos_mark_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_qos_mark_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_qos_mark_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_qos_mark_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_qos_mark_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_qos_mark_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_qos_mark_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_qos_mark_enable_disable_reply *reply),
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
  vapi_msg_qos_mark_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_qos_mark_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_qos_mark_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_qos_mark_enable_disable()
{
  static const char name[] = "qos_mark_enable_disable";
  static const char name_with_crc[] = "qos_mark_enable_disable_1a010f74";
  static vapi_message_desc_t __vapi_metadata_qos_mark_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_qos_mark_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_qos_mark_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_qos_mark_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_qos_mark_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_qos_mark_enable_disable = vapi_register_msg(&__vapi_metadata_qos_mark_enable_disable);
  VAPI_DBG("Assigned msg id %d to qos_mark_enable_disable", vapi_msg_id_qos_mark_enable_disable);
}
#endif

#ifndef defined_vapi_msg_qos_mark_details
#define defined_vapi_msg_qos_mark_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_qos_mark mark; 
} vapi_payload_qos_mark_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_qos_mark_details payload;
} vapi_msg_qos_mark_details;

static inline void vapi_msg_qos_mark_details_payload_hton(vapi_payload_qos_mark_details *payload)
{
  vapi_type_qos_mark_hton(&payload->mark);
}

static inline void vapi_msg_qos_mark_details_payload_ntoh(vapi_payload_qos_mark_details *payload)
{
  vapi_type_qos_mark_ntoh(&payload->mark);
}

static inline void vapi_msg_qos_mark_details_hton(vapi_msg_qos_mark_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_mark_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_qos_mark_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_qos_mark_details_ntoh(vapi_msg_qos_mark_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_mark_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_qos_mark_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_qos_mark_details_msg_size(vapi_msg_qos_mark_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_qos_mark_details_msg_size(vapi_msg_qos_mark_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_qos_mark_details) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_mark_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_qos_mark_details));
      return -1;
    }
  if (vapi_calc_qos_mark_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_mark_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_qos_mark_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_qos_mark_details()
{
  static const char name[] = "qos_mark_details";
  static const char name_with_crc[] = "qos_mark_details_89fe81a9";
  static vapi_message_desc_t __vapi_metadata_qos_mark_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_qos_mark_details, payload),
    (verify_msg_size_fn_t)vapi_verify_qos_mark_details_msg_size,
    (generic_swap_fn_t)vapi_msg_qos_mark_details_hton,
    (generic_swap_fn_t)vapi_msg_qos_mark_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_qos_mark_details = vapi_register_msg(&__vapi_metadata_qos_mark_details);
  VAPI_DBG("Assigned msg id %d to qos_mark_details", vapi_msg_id_qos_mark_details);
}

static inline void vapi_set_vapi_msg_qos_mark_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_qos_mark_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_qos_mark_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_qos_mark_dump
#define defined_vapi_msg_qos_mark_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_qos_mark_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_qos_mark_dump payload;
} vapi_msg_qos_mark_dump;

static inline void vapi_msg_qos_mark_dump_payload_hton(vapi_payload_qos_mark_dump *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_qos_mark_dump_payload_ntoh(vapi_payload_qos_mark_dump *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_qos_mark_dump_hton(vapi_msg_qos_mark_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_mark_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_qos_mark_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_qos_mark_dump_ntoh(vapi_msg_qos_mark_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_qos_mark_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_qos_mark_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_qos_mark_dump_msg_size(vapi_msg_qos_mark_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_qos_mark_dump_msg_size(vapi_msg_qos_mark_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_qos_mark_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_mark_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_qos_mark_dump));
      return -1;
    }
  if (vapi_calc_qos_mark_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'qos_mark_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_qos_mark_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_qos_mark_dump* vapi_alloc_qos_mark_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_qos_mark_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_qos_mark_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_qos_mark_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_qos_mark_dump);

  return msg;
}

static inline vapi_error_e vapi_qos_mark_dump(struct vapi_ctx_s *ctx,
  vapi_msg_qos_mark_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_qos_mark_details *reply),
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
  vapi_msg_qos_mark_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_qos_mark_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_qos_mark_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_qos_mark_dump()
{
  static const char name[] = "qos_mark_dump";
  static const char name_with_crc[] = "qos_mark_dump_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_qos_mark_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_qos_mark_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_qos_mark_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_qos_mark_dump_hton,
    (generic_swap_fn_t)vapi_msg_qos_mark_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_qos_mark_dump = vapi_register_msg(&__vapi_metadata_qos_mark_dump);
  VAPI_DBG("Assigned msg id %d to qos_mark_dump", vapi_msg_id_qos_mark_dump);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
