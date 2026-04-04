#ifndef __included_bfd_api_json
#define __included_bfd_api_json

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

extern vapi_msg_id_t vapi_msg_id_bfd_udp_set_echo_source;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_set_echo_source_reply;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_del_echo_source;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_del_echo_source_reply;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_get_echo_source;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_get_echo_source_reply;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_add;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_add_reply;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_upd;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_upd_reply;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_mod;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_mod_reply;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_del;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_del_reply;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_session_dump;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_session_details;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_session_set_flags;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_session_set_flags_reply;
extern vapi_msg_id_t vapi_msg_id_want_bfd_events;
extern vapi_msg_id_t vapi_msg_id_want_bfd_events_reply;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_session_event;
extern vapi_msg_id_t vapi_msg_id_bfd_auth_set_key;
extern vapi_msg_id_t vapi_msg_id_bfd_auth_set_key_reply;
extern vapi_msg_id_t vapi_msg_id_bfd_auth_del_key;
extern vapi_msg_id_t vapi_msg_id_bfd_auth_del_key_reply;
extern vapi_msg_id_t vapi_msg_id_bfd_auth_keys_dump;
extern vapi_msg_id_t vapi_msg_id_bfd_auth_keys_details;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_auth_activate;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_auth_activate_reply;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_auth_deactivate;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_auth_deactivate_reply;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_enable_multihop;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_enable_multihop_reply;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_set_tos;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_set_tos_reply;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_get_tos;
extern vapi_msg_id_t vapi_msg_id_bfd_udp_get_tos_reply;

#define DEFINE_VAPI_MSG_IDS_BFD_API_JSON\
  vapi_msg_id_t vapi_msg_id_bfd_udp_set_echo_source;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_set_echo_source_reply;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_del_echo_source;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_del_echo_source_reply;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_get_echo_source;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_get_echo_source_reply;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_add;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_add_reply;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_upd;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_upd_reply;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_mod;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_mod_reply;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_del;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_del_reply;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_session_dump;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_session_details;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_session_set_flags;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_session_set_flags_reply;\
  vapi_msg_id_t vapi_msg_id_want_bfd_events;\
  vapi_msg_id_t vapi_msg_id_want_bfd_events_reply;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_session_event;\
  vapi_msg_id_t vapi_msg_id_bfd_auth_set_key;\
  vapi_msg_id_t vapi_msg_id_bfd_auth_set_key_reply;\
  vapi_msg_id_t vapi_msg_id_bfd_auth_del_key;\
  vapi_msg_id_t vapi_msg_id_bfd_auth_del_key_reply;\
  vapi_msg_id_t vapi_msg_id_bfd_auth_keys_dump;\
  vapi_msg_id_t vapi_msg_id_bfd_auth_keys_details;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_auth_activate;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_auth_activate_reply;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_auth_deactivate;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_auth_deactivate_reply;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_enable_multihop;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_enable_multihop_reply;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_set_tos;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_set_tos_reply;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_get_tos;\
  vapi_msg_id_t vapi_msg_id_bfd_udp_get_tos_reply;


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

#ifndef defined_vapi_enum_bfd_state
#define defined_vapi_enum_bfd_state
typedef enum {
  BFD_STATE_API_ADMIN_DOWN = 0,
  BFD_STATE_API_DOWN = 1,
  BFD_STATE_API_INIT = 2,
  BFD_STATE_API_UP = 3,
}  vapi_enum_bfd_state;

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

#ifndef defined_vapi_msg_bfd_udp_set_echo_source_reply
#define defined_vapi_msg_bfd_udp_set_echo_source_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bfd_udp_set_echo_source_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bfd_udp_set_echo_source_reply payload;
} vapi_msg_bfd_udp_set_echo_source_reply;

static inline void vapi_msg_bfd_udp_set_echo_source_reply_payload_hton(vapi_payload_bfd_udp_set_echo_source_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bfd_udp_set_echo_source_reply_payload_ntoh(vapi_payload_bfd_udp_set_echo_source_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bfd_udp_set_echo_source_reply_hton(vapi_msg_bfd_udp_set_echo_source_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_set_echo_source_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bfd_udp_set_echo_source_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_set_echo_source_reply_ntoh(vapi_msg_bfd_udp_set_echo_source_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_set_echo_source_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_set_echo_source_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_set_echo_source_reply_msg_size(vapi_msg_bfd_udp_set_echo_source_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_set_echo_source_reply_msg_size(vapi_msg_bfd_udp_set_echo_source_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_set_echo_source_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_set_echo_source_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_set_echo_source_reply));
      return -1;
    }
  if (vapi_calc_bfd_udp_set_echo_source_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_set_echo_source_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_set_echo_source_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bfd_udp_set_echo_source_reply()
{
  static const char name[] = "bfd_udp_set_echo_source_reply";
  static const char name_with_crc[] = "bfd_udp_set_echo_source_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_set_echo_source_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bfd_udp_set_echo_source_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_set_echo_source_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_set_echo_source_reply_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_set_echo_source_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_set_echo_source_reply = vapi_register_msg(&__vapi_metadata_bfd_udp_set_echo_source_reply);
  VAPI_DBG("Assigned msg id %d to bfd_udp_set_echo_source_reply", vapi_msg_id_bfd_udp_set_echo_source_reply);
}

static inline void vapi_set_vapi_msg_bfd_udp_set_echo_source_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bfd_udp_set_echo_source_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bfd_udp_set_echo_source_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bfd_udp_set_echo_source
#define defined_vapi_msg_bfd_udp_set_echo_source
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_bfd_udp_set_echo_source;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bfd_udp_set_echo_source payload;
} vapi_msg_bfd_udp_set_echo_source;

static inline void vapi_msg_bfd_udp_set_echo_source_payload_hton(vapi_payload_bfd_udp_set_echo_source *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_bfd_udp_set_echo_source_payload_ntoh(vapi_payload_bfd_udp_set_echo_source *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_bfd_udp_set_echo_source_hton(vapi_msg_bfd_udp_set_echo_source *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_set_echo_source'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bfd_udp_set_echo_source_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_set_echo_source_ntoh(vapi_msg_bfd_udp_set_echo_source *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_set_echo_source'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_set_echo_source_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_set_echo_source_msg_size(vapi_msg_bfd_udp_set_echo_source *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_set_echo_source_msg_size(vapi_msg_bfd_udp_set_echo_source *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_set_echo_source) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_set_echo_source' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_set_echo_source));
      return -1;
    }
  if (vapi_calc_bfd_udp_set_echo_source_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_set_echo_source' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_set_echo_source_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bfd_udp_set_echo_source* vapi_alloc_bfd_udp_set_echo_source(struct vapi_ctx_s *ctx)
{
  vapi_msg_bfd_udp_set_echo_source *msg = NULL;
  const size_t size = sizeof(vapi_msg_bfd_udp_set_echo_source);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bfd_udp_set_echo_source*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bfd_udp_set_echo_source);

  return msg;
}

static inline vapi_error_e vapi_bfd_udp_set_echo_source(struct vapi_ctx_s *ctx,
  vapi_msg_bfd_udp_set_echo_source *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bfd_udp_set_echo_source_reply *reply),
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
  vapi_msg_bfd_udp_set_echo_source_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bfd_udp_set_echo_source_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bfd_udp_set_echo_source_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bfd_udp_set_echo_source()
{
  static const char name[] = "bfd_udp_set_echo_source";
  static const char name_with_crc[] = "bfd_udp_set_echo_source_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_set_echo_source = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bfd_udp_set_echo_source, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_set_echo_source_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_set_echo_source_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_set_echo_source_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_set_echo_source = vapi_register_msg(&__vapi_metadata_bfd_udp_set_echo_source);
  VAPI_DBG("Assigned msg id %d to bfd_udp_set_echo_source", vapi_msg_id_bfd_udp_set_echo_source);
}
#endif

#ifndef defined_vapi_msg_bfd_udp_del_echo_source_reply
#define defined_vapi_msg_bfd_udp_del_echo_source_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bfd_udp_del_echo_source_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bfd_udp_del_echo_source_reply payload;
} vapi_msg_bfd_udp_del_echo_source_reply;

static inline void vapi_msg_bfd_udp_del_echo_source_reply_payload_hton(vapi_payload_bfd_udp_del_echo_source_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bfd_udp_del_echo_source_reply_payload_ntoh(vapi_payload_bfd_udp_del_echo_source_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bfd_udp_del_echo_source_reply_hton(vapi_msg_bfd_udp_del_echo_source_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_del_echo_source_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bfd_udp_del_echo_source_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_del_echo_source_reply_ntoh(vapi_msg_bfd_udp_del_echo_source_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_del_echo_source_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_del_echo_source_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_del_echo_source_reply_msg_size(vapi_msg_bfd_udp_del_echo_source_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_del_echo_source_reply_msg_size(vapi_msg_bfd_udp_del_echo_source_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_del_echo_source_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_del_echo_source_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_del_echo_source_reply));
      return -1;
    }
  if (vapi_calc_bfd_udp_del_echo_source_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_del_echo_source_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_del_echo_source_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bfd_udp_del_echo_source_reply()
{
  static const char name[] = "bfd_udp_del_echo_source_reply";
  static const char name_with_crc[] = "bfd_udp_del_echo_source_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_del_echo_source_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bfd_udp_del_echo_source_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_del_echo_source_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_del_echo_source_reply_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_del_echo_source_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_del_echo_source_reply = vapi_register_msg(&__vapi_metadata_bfd_udp_del_echo_source_reply);
  VAPI_DBG("Assigned msg id %d to bfd_udp_del_echo_source_reply", vapi_msg_id_bfd_udp_del_echo_source_reply);
}

static inline void vapi_set_vapi_msg_bfd_udp_del_echo_source_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bfd_udp_del_echo_source_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bfd_udp_del_echo_source_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bfd_udp_del_echo_source
#define defined_vapi_msg_bfd_udp_del_echo_source
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_bfd_udp_del_echo_source;

static inline void vapi_msg_bfd_udp_del_echo_source_hton(vapi_msg_bfd_udp_del_echo_source *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_del_echo_source'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_bfd_udp_del_echo_source_ntoh(vapi_msg_bfd_udp_del_echo_source *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_del_echo_source'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_bfd_udp_del_echo_source_msg_size(vapi_msg_bfd_udp_del_echo_source *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_del_echo_source_msg_size(vapi_msg_bfd_udp_del_echo_source *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_del_echo_source) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_del_echo_source' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_del_echo_source));
      return -1;
    }
  if (vapi_calc_bfd_udp_del_echo_source_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_del_echo_source' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_del_echo_source_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bfd_udp_del_echo_source* vapi_alloc_bfd_udp_del_echo_source(struct vapi_ctx_s *ctx)
{
  vapi_msg_bfd_udp_del_echo_source *msg = NULL;
  const size_t size = sizeof(vapi_msg_bfd_udp_del_echo_source);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bfd_udp_del_echo_source*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bfd_udp_del_echo_source);

  return msg;
}

static inline vapi_error_e vapi_bfd_udp_del_echo_source(struct vapi_ctx_s *ctx,
  vapi_msg_bfd_udp_del_echo_source *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bfd_udp_del_echo_source_reply *reply),
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
  vapi_msg_bfd_udp_del_echo_source_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bfd_udp_del_echo_source_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bfd_udp_del_echo_source_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bfd_udp_del_echo_source()
{
  static const char name[] = "bfd_udp_del_echo_source";
  static const char name_with_crc[] = "bfd_udp_del_echo_source_51077d14";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_del_echo_source = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_del_echo_source_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_del_echo_source_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_del_echo_source_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_del_echo_source = vapi_register_msg(&__vapi_metadata_bfd_udp_del_echo_source);
  VAPI_DBG("Assigned msg id %d to bfd_udp_del_echo_source", vapi_msg_id_bfd_udp_del_echo_source);
}
#endif

#ifndef defined_vapi_msg_bfd_udp_get_echo_source_reply
#define defined_vapi_msg_bfd_udp_get_echo_source_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_interface_index sw_if_index;
  bool is_set;
  bool have_usable_ip4;
  vapi_type_ip4_address ip4_addr;
  bool have_usable_ip6;
  vapi_type_ip6_address ip6_addr; 
} vapi_payload_bfd_udp_get_echo_source_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bfd_udp_get_echo_source_reply payload;
} vapi_msg_bfd_udp_get_echo_source_reply;

static inline void vapi_msg_bfd_udp_get_echo_source_reply_payload_hton(vapi_payload_bfd_udp_get_echo_source_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_bfd_udp_get_echo_source_reply_payload_ntoh(vapi_payload_bfd_udp_get_echo_source_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_bfd_udp_get_echo_source_reply_hton(vapi_msg_bfd_udp_get_echo_source_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_get_echo_source_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bfd_udp_get_echo_source_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_get_echo_source_reply_ntoh(vapi_msg_bfd_udp_get_echo_source_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_get_echo_source_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_get_echo_source_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_get_echo_source_reply_msg_size(vapi_msg_bfd_udp_get_echo_source_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_get_echo_source_reply_msg_size(vapi_msg_bfd_udp_get_echo_source_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_get_echo_source_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_get_echo_source_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_get_echo_source_reply));
      return -1;
    }
  if (vapi_calc_bfd_udp_get_echo_source_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_get_echo_source_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_get_echo_source_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bfd_udp_get_echo_source_reply()
{
  static const char name[] = "bfd_udp_get_echo_source_reply";
  static const char name_with_crc[] = "bfd_udp_get_echo_source_reply_e3d736a1";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_get_echo_source_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bfd_udp_get_echo_source_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_get_echo_source_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_get_echo_source_reply_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_get_echo_source_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_get_echo_source_reply = vapi_register_msg(&__vapi_metadata_bfd_udp_get_echo_source_reply);
  VAPI_DBG("Assigned msg id %d to bfd_udp_get_echo_source_reply", vapi_msg_id_bfd_udp_get_echo_source_reply);
}

static inline void vapi_set_vapi_msg_bfd_udp_get_echo_source_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bfd_udp_get_echo_source_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bfd_udp_get_echo_source_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bfd_udp_get_echo_source
#define defined_vapi_msg_bfd_udp_get_echo_source
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_bfd_udp_get_echo_source;

static inline void vapi_msg_bfd_udp_get_echo_source_hton(vapi_msg_bfd_udp_get_echo_source *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_get_echo_source'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_bfd_udp_get_echo_source_ntoh(vapi_msg_bfd_udp_get_echo_source *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_get_echo_source'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_bfd_udp_get_echo_source_msg_size(vapi_msg_bfd_udp_get_echo_source *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_get_echo_source_msg_size(vapi_msg_bfd_udp_get_echo_source *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_get_echo_source) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_get_echo_source' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_get_echo_source));
      return -1;
    }
  if (vapi_calc_bfd_udp_get_echo_source_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_get_echo_source' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_get_echo_source_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bfd_udp_get_echo_source* vapi_alloc_bfd_udp_get_echo_source(struct vapi_ctx_s *ctx)
{
  vapi_msg_bfd_udp_get_echo_source *msg = NULL;
  const size_t size = sizeof(vapi_msg_bfd_udp_get_echo_source);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bfd_udp_get_echo_source*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bfd_udp_get_echo_source);

  return msg;
}

static inline vapi_error_e vapi_bfd_udp_get_echo_source(struct vapi_ctx_s *ctx,
  vapi_msg_bfd_udp_get_echo_source *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bfd_udp_get_echo_source_reply *reply),
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
  vapi_msg_bfd_udp_get_echo_source_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bfd_udp_get_echo_source_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bfd_udp_get_echo_source_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bfd_udp_get_echo_source()
{
  static const char name[] = "bfd_udp_get_echo_source";
  static const char name_with_crc[] = "bfd_udp_get_echo_source_51077d14";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_get_echo_source = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_get_echo_source_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_get_echo_source_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_get_echo_source_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_get_echo_source = vapi_register_msg(&__vapi_metadata_bfd_udp_get_echo_source);
  VAPI_DBG("Assigned msg id %d to bfd_udp_get_echo_source", vapi_msg_id_bfd_udp_get_echo_source);
}
#endif

#ifndef defined_vapi_msg_bfd_udp_add_reply
#define defined_vapi_msg_bfd_udp_add_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bfd_udp_add_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bfd_udp_add_reply payload;
} vapi_msg_bfd_udp_add_reply;

static inline void vapi_msg_bfd_udp_add_reply_payload_hton(vapi_payload_bfd_udp_add_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bfd_udp_add_reply_payload_ntoh(vapi_payload_bfd_udp_add_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bfd_udp_add_reply_hton(vapi_msg_bfd_udp_add_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_add_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bfd_udp_add_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_add_reply_ntoh(vapi_msg_bfd_udp_add_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_add_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_add_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_add_reply_msg_size(vapi_msg_bfd_udp_add_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_add_reply_msg_size(vapi_msg_bfd_udp_add_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_add_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_add_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_add_reply));
      return -1;
    }
  if (vapi_calc_bfd_udp_add_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_add_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_add_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bfd_udp_add_reply()
{
  static const char name[] = "bfd_udp_add_reply";
  static const char name_with_crc[] = "bfd_udp_add_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_add_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bfd_udp_add_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_add_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_add_reply_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_add_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_add_reply = vapi_register_msg(&__vapi_metadata_bfd_udp_add_reply);
  VAPI_DBG("Assigned msg id %d to bfd_udp_add_reply", vapi_msg_id_bfd_udp_add_reply);
}

static inline void vapi_set_vapi_msg_bfd_udp_add_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bfd_udp_add_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bfd_udp_add_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bfd_udp_add
#define defined_vapi_msg_bfd_udp_add
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u32 desired_min_tx;
  u32 required_min_rx;
  vapi_type_address local_addr;
  vapi_type_address peer_addr;
  u8 detect_mult;
  bool is_authenticated;
  u8 bfd_key_id;
  u32 conf_key_id; 
} vapi_payload_bfd_udp_add;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bfd_udp_add payload;
} vapi_msg_bfd_udp_add;

static inline void vapi_msg_bfd_udp_add_payload_hton(vapi_payload_bfd_udp_add *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->desired_min_tx = htobe32(payload->desired_min_tx);
  payload->required_min_rx = htobe32(payload->required_min_rx);
  payload->conf_key_id = htobe32(payload->conf_key_id);
}

static inline void vapi_msg_bfd_udp_add_payload_ntoh(vapi_payload_bfd_udp_add *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->desired_min_tx = be32toh(payload->desired_min_tx);
  payload->required_min_rx = be32toh(payload->required_min_rx);
  payload->conf_key_id = be32toh(payload->conf_key_id);
}

static inline void vapi_msg_bfd_udp_add_hton(vapi_msg_bfd_udp_add *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_add'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bfd_udp_add_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_add_ntoh(vapi_msg_bfd_udp_add *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_add'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_add_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_add_msg_size(vapi_msg_bfd_udp_add *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_add_msg_size(vapi_msg_bfd_udp_add *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_add) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_add' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_add));
      return -1;
    }
  if (vapi_calc_bfd_udp_add_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_add' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_add_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bfd_udp_add* vapi_alloc_bfd_udp_add(struct vapi_ctx_s *ctx)
{
  vapi_msg_bfd_udp_add *msg = NULL;
  const size_t size = sizeof(vapi_msg_bfd_udp_add);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bfd_udp_add*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bfd_udp_add);

  return msg;
}

static inline vapi_error_e vapi_bfd_udp_add(struct vapi_ctx_s *ctx,
  vapi_msg_bfd_udp_add *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bfd_udp_add_reply *reply),
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
  vapi_msg_bfd_udp_add_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bfd_udp_add_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bfd_udp_add_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bfd_udp_add()
{
  static const char name[] = "bfd_udp_add";
  static const char name_with_crc[] = "bfd_udp_add_939cd26a";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_add = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bfd_udp_add, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_add_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_add_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_add_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_add = vapi_register_msg(&__vapi_metadata_bfd_udp_add);
  VAPI_DBG("Assigned msg id %d to bfd_udp_add", vapi_msg_id_bfd_udp_add);
}
#endif

#ifndef defined_vapi_msg_bfd_udp_upd_reply
#define defined_vapi_msg_bfd_udp_upd_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 stats_index; 
} vapi_payload_bfd_udp_upd_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bfd_udp_upd_reply payload;
} vapi_msg_bfd_udp_upd_reply;

static inline void vapi_msg_bfd_udp_upd_reply_payload_hton(vapi_payload_bfd_udp_upd_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->stats_index = htobe32(payload->stats_index);
}

static inline void vapi_msg_bfd_udp_upd_reply_payload_ntoh(vapi_payload_bfd_udp_upd_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->stats_index = be32toh(payload->stats_index);
}

static inline void vapi_msg_bfd_udp_upd_reply_hton(vapi_msg_bfd_udp_upd_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_upd_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bfd_udp_upd_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_upd_reply_ntoh(vapi_msg_bfd_udp_upd_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_upd_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_upd_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_upd_reply_msg_size(vapi_msg_bfd_udp_upd_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_upd_reply_msg_size(vapi_msg_bfd_udp_upd_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_upd_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_upd_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_upd_reply));
      return -1;
    }
  if (vapi_calc_bfd_udp_upd_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_upd_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_upd_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bfd_udp_upd_reply()
{
  static const char name[] = "bfd_udp_upd_reply";
  static const char name_with_crc[] = "bfd_udp_upd_reply_1992deab";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_upd_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bfd_udp_upd_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_upd_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_upd_reply_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_upd_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_upd_reply = vapi_register_msg(&__vapi_metadata_bfd_udp_upd_reply);
  VAPI_DBG("Assigned msg id %d to bfd_udp_upd_reply", vapi_msg_id_bfd_udp_upd_reply);
}

static inline void vapi_set_vapi_msg_bfd_udp_upd_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bfd_udp_upd_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bfd_udp_upd_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bfd_udp_upd
#define defined_vapi_msg_bfd_udp_upd
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u32 desired_min_tx;
  u32 required_min_rx;
  vapi_type_address local_addr;
  vapi_type_address peer_addr;
  u8 detect_mult;
  bool is_authenticated;
  u8 bfd_key_id;
  u32 conf_key_id; 
} vapi_payload_bfd_udp_upd;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bfd_udp_upd payload;
} vapi_msg_bfd_udp_upd;

static inline void vapi_msg_bfd_udp_upd_payload_hton(vapi_payload_bfd_udp_upd *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->desired_min_tx = htobe32(payload->desired_min_tx);
  payload->required_min_rx = htobe32(payload->required_min_rx);
  payload->conf_key_id = htobe32(payload->conf_key_id);
}

static inline void vapi_msg_bfd_udp_upd_payload_ntoh(vapi_payload_bfd_udp_upd *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->desired_min_tx = be32toh(payload->desired_min_tx);
  payload->required_min_rx = be32toh(payload->required_min_rx);
  payload->conf_key_id = be32toh(payload->conf_key_id);
}

static inline void vapi_msg_bfd_udp_upd_hton(vapi_msg_bfd_udp_upd *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_upd'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bfd_udp_upd_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_upd_ntoh(vapi_msg_bfd_udp_upd *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_upd'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_upd_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_upd_msg_size(vapi_msg_bfd_udp_upd *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_upd_msg_size(vapi_msg_bfd_udp_upd *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_upd) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_upd' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_upd));
      return -1;
    }
  if (vapi_calc_bfd_udp_upd_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_upd' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_upd_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bfd_udp_upd* vapi_alloc_bfd_udp_upd(struct vapi_ctx_s *ctx)
{
  vapi_msg_bfd_udp_upd *msg = NULL;
  const size_t size = sizeof(vapi_msg_bfd_udp_upd);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bfd_udp_upd*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bfd_udp_upd);

  return msg;
}

static inline vapi_error_e vapi_bfd_udp_upd(struct vapi_ctx_s *ctx,
  vapi_msg_bfd_udp_upd *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bfd_udp_upd_reply *reply),
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
  vapi_msg_bfd_udp_upd_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bfd_udp_upd_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bfd_udp_upd_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bfd_udp_upd()
{
  static const char name[] = "bfd_udp_upd";
  static const char name_with_crc[] = "bfd_udp_upd_939cd26a";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_upd = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bfd_udp_upd, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_upd_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_upd_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_upd_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_upd = vapi_register_msg(&__vapi_metadata_bfd_udp_upd);
  VAPI_DBG("Assigned msg id %d to bfd_udp_upd", vapi_msg_id_bfd_udp_upd);
}
#endif

#ifndef defined_vapi_msg_bfd_udp_mod_reply
#define defined_vapi_msg_bfd_udp_mod_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bfd_udp_mod_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bfd_udp_mod_reply payload;
} vapi_msg_bfd_udp_mod_reply;

static inline void vapi_msg_bfd_udp_mod_reply_payload_hton(vapi_payload_bfd_udp_mod_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bfd_udp_mod_reply_payload_ntoh(vapi_payload_bfd_udp_mod_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bfd_udp_mod_reply_hton(vapi_msg_bfd_udp_mod_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_mod_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bfd_udp_mod_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_mod_reply_ntoh(vapi_msg_bfd_udp_mod_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_mod_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_mod_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_mod_reply_msg_size(vapi_msg_bfd_udp_mod_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_mod_reply_msg_size(vapi_msg_bfd_udp_mod_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_mod_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_mod_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_mod_reply));
      return -1;
    }
  if (vapi_calc_bfd_udp_mod_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_mod_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_mod_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bfd_udp_mod_reply()
{
  static const char name[] = "bfd_udp_mod_reply";
  static const char name_with_crc[] = "bfd_udp_mod_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_mod_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bfd_udp_mod_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_mod_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_mod_reply_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_mod_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_mod_reply = vapi_register_msg(&__vapi_metadata_bfd_udp_mod_reply);
  VAPI_DBG("Assigned msg id %d to bfd_udp_mod_reply", vapi_msg_id_bfd_udp_mod_reply);
}

static inline void vapi_set_vapi_msg_bfd_udp_mod_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bfd_udp_mod_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bfd_udp_mod_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bfd_udp_mod
#define defined_vapi_msg_bfd_udp_mod
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u32 desired_min_tx;
  u32 required_min_rx;
  vapi_type_address local_addr;
  vapi_type_address peer_addr;
  u8 detect_mult; 
} vapi_payload_bfd_udp_mod;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bfd_udp_mod payload;
} vapi_msg_bfd_udp_mod;

static inline void vapi_msg_bfd_udp_mod_payload_hton(vapi_payload_bfd_udp_mod *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->desired_min_tx = htobe32(payload->desired_min_tx);
  payload->required_min_rx = htobe32(payload->required_min_rx);
}

static inline void vapi_msg_bfd_udp_mod_payload_ntoh(vapi_payload_bfd_udp_mod *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->desired_min_tx = be32toh(payload->desired_min_tx);
  payload->required_min_rx = be32toh(payload->required_min_rx);
}

static inline void vapi_msg_bfd_udp_mod_hton(vapi_msg_bfd_udp_mod *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_mod'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bfd_udp_mod_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_mod_ntoh(vapi_msg_bfd_udp_mod *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_mod'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_mod_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_mod_msg_size(vapi_msg_bfd_udp_mod *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_mod_msg_size(vapi_msg_bfd_udp_mod *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_mod) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_mod' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_mod));
      return -1;
    }
  if (vapi_calc_bfd_udp_mod_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_mod' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_mod_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bfd_udp_mod* vapi_alloc_bfd_udp_mod(struct vapi_ctx_s *ctx)
{
  vapi_msg_bfd_udp_mod *msg = NULL;
  const size_t size = sizeof(vapi_msg_bfd_udp_mod);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bfd_udp_mod*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bfd_udp_mod);

  return msg;
}

static inline vapi_error_e vapi_bfd_udp_mod(struct vapi_ctx_s *ctx,
  vapi_msg_bfd_udp_mod *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bfd_udp_mod_reply *reply),
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
  vapi_msg_bfd_udp_mod_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bfd_udp_mod_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bfd_udp_mod_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bfd_udp_mod()
{
  static const char name[] = "bfd_udp_mod";
  static const char name_with_crc[] = "bfd_udp_mod_913df085";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_mod = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bfd_udp_mod, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_mod_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_mod_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_mod_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_mod = vapi_register_msg(&__vapi_metadata_bfd_udp_mod);
  VAPI_DBG("Assigned msg id %d to bfd_udp_mod", vapi_msg_id_bfd_udp_mod);
}
#endif

#ifndef defined_vapi_msg_bfd_udp_del_reply
#define defined_vapi_msg_bfd_udp_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bfd_udp_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bfd_udp_del_reply payload;
} vapi_msg_bfd_udp_del_reply;

static inline void vapi_msg_bfd_udp_del_reply_payload_hton(vapi_payload_bfd_udp_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bfd_udp_del_reply_payload_ntoh(vapi_payload_bfd_udp_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bfd_udp_del_reply_hton(vapi_msg_bfd_udp_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bfd_udp_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_del_reply_ntoh(vapi_msg_bfd_udp_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_del_reply_msg_size(vapi_msg_bfd_udp_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_del_reply_msg_size(vapi_msg_bfd_udp_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_del_reply));
      return -1;
    }
  if (vapi_calc_bfd_udp_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bfd_udp_del_reply()
{
  static const char name[] = "bfd_udp_del_reply";
  static const char name_with_crc[] = "bfd_udp_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bfd_udp_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_del_reply = vapi_register_msg(&__vapi_metadata_bfd_udp_del_reply);
  VAPI_DBG("Assigned msg id %d to bfd_udp_del_reply", vapi_msg_id_bfd_udp_del_reply);
}

static inline void vapi_set_vapi_msg_bfd_udp_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bfd_udp_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bfd_udp_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bfd_udp_del
#define defined_vapi_msg_bfd_udp_del
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_type_address local_addr;
  vapi_type_address peer_addr; 
} vapi_payload_bfd_udp_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bfd_udp_del payload;
} vapi_msg_bfd_udp_del;

static inline void vapi_msg_bfd_udp_del_payload_hton(vapi_payload_bfd_udp_del *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_bfd_udp_del_payload_ntoh(vapi_payload_bfd_udp_del *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_bfd_udp_del_hton(vapi_msg_bfd_udp_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bfd_udp_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_del_ntoh(vapi_msg_bfd_udp_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_del_msg_size(vapi_msg_bfd_udp_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_del_msg_size(vapi_msg_bfd_udp_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_del) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_del));
      return -1;
    }
  if (vapi_calc_bfd_udp_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bfd_udp_del* vapi_alloc_bfd_udp_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_bfd_udp_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_bfd_udp_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bfd_udp_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bfd_udp_del);

  return msg;
}

static inline vapi_error_e vapi_bfd_udp_del(struct vapi_ctx_s *ctx,
  vapi_msg_bfd_udp_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bfd_udp_del_reply *reply),
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
  vapi_msg_bfd_udp_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bfd_udp_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bfd_udp_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bfd_udp_del()
{
  static const char name[] = "bfd_udp_del";
  static const char name_with_crc[] = "bfd_udp_del_dcb13a89";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bfd_udp_del, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_del_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_del_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_del = vapi_register_msg(&__vapi_metadata_bfd_udp_del);
  VAPI_DBG("Assigned msg id %d to bfd_udp_del", vapi_msg_id_bfd_udp_del);
}
#endif

#ifndef defined_vapi_msg_bfd_udp_session_details
#define defined_vapi_msg_bfd_udp_session_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_type_address local_addr;
  vapi_type_address peer_addr;
  vapi_enum_bfd_state state;
  bool is_authenticated;
  u8 bfd_key_id;
  u32 conf_key_id;
  u32 required_min_rx;
  u32 desired_min_tx;
  u8 detect_mult; 
} vapi_payload_bfd_udp_session_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bfd_udp_session_details payload;
} vapi_msg_bfd_udp_session_details;

static inline void vapi_msg_bfd_udp_session_details_payload_hton(vapi_payload_bfd_udp_session_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->state = (vapi_enum_bfd_state)htobe32(payload->state);
  payload->conf_key_id = htobe32(payload->conf_key_id);
  payload->required_min_rx = htobe32(payload->required_min_rx);
  payload->desired_min_tx = htobe32(payload->desired_min_tx);
}

static inline void vapi_msg_bfd_udp_session_details_payload_ntoh(vapi_payload_bfd_udp_session_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->state = (vapi_enum_bfd_state)be32toh(payload->state);
  payload->conf_key_id = be32toh(payload->conf_key_id);
  payload->required_min_rx = be32toh(payload->required_min_rx);
  payload->desired_min_tx = be32toh(payload->desired_min_tx);
}

static inline void vapi_msg_bfd_udp_session_details_hton(vapi_msg_bfd_udp_session_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_session_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bfd_udp_session_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_session_details_ntoh(vapi_msg_bfd_udp_session_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_session_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_session_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_session_details_msg_size(vapi_msg_bfd_udp_session_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_session_details_msg_size(vapi_msg_bfd_udp_session_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_session_details) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_session_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_session_details));
      return -1;
    }
  if (vapi_calc_bfd_udp_session_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_session_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_session_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bfd_udp_session_details()
{
  static const char name[] = "bfd_udp_session_details";
  static const char name_with_crc[] = "bfd_udp_session_details_09fb2f2d";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_session_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bfd_udp_session_details, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_session_details_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_session_details_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_session_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_session_details = vapi_register_msg(&__vapi_metadata_bfd_udp_session_details);
  VAPI_DBG("Assigned msg id %d to bfd_udp_session_details", vapi_msg_id_bfd_udp_session_details);
}

static inline void vapi_set_vapi_msg_bfd_udp_session_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bfd_udp_session_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bfd_udp_session_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bfd_udp_session_dump
#define defined_vapi_msg_bfd_udp_session_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_bfd_udp_session_dump;

static inline void vapi_msg_bfd_udp_session_dump_hton(vapi_msg_bfd_udp_session_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_session_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_bfd_udp_session_dump_ntoh(vapi_msg_bfd_udp_session_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_session_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_bfd_udp_session_dump_msg_size(vapi_msg_bfd_udp_session_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_session_dump_msg_size(vapi_msg_bfd_udp_session_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_session_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_session_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_session_dump));
      return -1;
    }
  if (vapi_calc_bfd_udp_session_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_session_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_session_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bfd_udp_session_dump* vapi_alloc_bfd_udp_session_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_bfd_udp_session_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_bfd_udp_session_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bfd_udp_session_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bfd_udp_session_dump);

  return msg;
}

static inline vapi_error_e vapi_bfd_udp_session_dump(struct vapi_ctx_s *ctx,
  vapi_msg_bfd_udp_session_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bfd_udp_session_details *reply),
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
  vapi_msg_bfd_udp_session_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bfd_udp_session_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_bfd_udp_session_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bfd_udp_session_dump()
{
  static const char name[] = "bfd_udp_session_dump";
  static const char name_with_crc[] = "bfd_udp_session_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_session_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_session_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_session_dump_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_session_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_session_dump = vapi_register_msg(&__vapi_metadata_bfd_udp_session_dump);
  VAPI_DBG("Assigned msg id %d to bfd_udp_session_dump", vapi_msg_id_bfd_udp_session_dump);
}
#endif

#ifndef defined_vapi_msg_bfd_udp_session_set_flags_reply
#define defined_vapi_msg_bfd_udp_session_set_flags_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bfd_udp_session_set_flags_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bfd_udp_session_set_flags_reply payload;
} vapi_msg_bfd_udp_session_set_flags_reply;

static inline void vapi_msg_bfd_udp_session_set_flags_reply_payload_hton(vapi_payload_bfd_udp_session_set_flags_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bfd_udp_session_set_flags_reply_payload_ntoh(vapi_payload_bfd_udp_session_set_flags_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bfd_udp_session_set_flags_reply_hton(vapi_msg_bfd_udp_session_set_flags_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_session_set_flags_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bfd_udp_session_set_flags_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_session_set_flags_reply_ntoh(vapi_msg_bfd_udp_session_set_flags_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_session_set_flags_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_session_set_flags_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_session_set_flags_reply_msg_size(vapi_msg_bfd_udp_session_set_flags_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_session_set_flags_reply_msg_size(vapi_msg_bfd_udp_session_set_flags_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_session_set_flags_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_session_set_flags_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_session_set_flags_reply));
      return -1;
    }
  if (vapi_calc_bfd_udp_session_set_flags_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_session_set_flags_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_session_set_flags_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bfd_udp_session_set_flags_reply()
{
  static const char name[] = "bfd_udp_session_set_flags_reply";
  static const char name_with_crc[] = "bfd_udp_session_set_flags_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_session_set_flags_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bfd_udp_session_set_flags_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_session_set_flags_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_session_set_flags_reply_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_session_set_flags_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_session_set_flags_reply = vapi_register_msg(&__vapi_metadata_bfd_udp_session_set_flags_reply);
  VAPI_DBG("Assigned msg id %d to bfd_udp_session_set_flags_reply", vapi_msg_id_bfd_udp_session_set_flags_reply);
}

static inline void vapi_set_vapi_msg_bfd_udp_session_set_flags_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bfd_udp_session_set_flags_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bfd_udp_session_set_flags_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bfd_udp_session_set_flags
#define defined_vapi_msg_bfd_udp_session_set_flags
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_type_address local_addr;
  vapi_type_address peer_addr;
  vapi_enum_if_status_flags flags; 
} vapi_payload_bfd_udp_session_set_flags;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bfd_udp_session_set_flags payload;
} vapi_msg_bfd_udp_session_set_flags;

static inline void vapi_msg_bfd_udp_session_set_flags_payload_hton(vapi_payload_bfd_udp_session_set_flags *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->flags = (vapi_enum_if_status_flags)htobe32(payload->flags);
}

static inline void vapi_msg_bfd_udp_session_set_flags_payload_ntoh(vapi_payload_bfd_udp_session_set_flags *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->flags = (vapi_enum_if_status_flags)be32toh(payload->flags);
}

static inline void vapi_msg_bfd_udp_session_set_flags_hton(vapi_msg_bfd_udp_session_set_flags *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_session_set_flags'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bfd_udp_session_set_flags_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_session_set_flags_ntoh(vapi_msg_bfd_udp_session_set_flags *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_session_set_flags'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_session_set_flags_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_session_set_flags_msg_size(vapi_msg_bfd_udp_session_set_flags *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_session_set_flags_msg_size(vapi_msg_bfd_udp_session_set_flags *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_session_set_flags) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_session_set_flags' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_session_set_flags));
      return -1;
    }
  if (vapi_calc_bfd_udp_session_set_flags_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_session_set_flags' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_session_set_flags_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bfd_udp_session_set_flags* vapi_alloc_bfd_udp_session_set_flags(struct vapi_ctx_s *ctx)
{
  vapi_msg_bfd_udp_session_set_flags *msg = NULL;
  const size_t size = sizeof(vapi_msg_bfd_udp_session_set_flags);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bfd_udp_session_set_flags*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bfd_udp_session_set_flags);

  return msg;
}

static inline vapi_error_e vapi_bfd_udp_session_set_flags(struct vapi_ctx_s *ctx,
  vapi_msg_bfd_udp_session_set_flags *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bfd_udp_session_set_flags_reply *reply),
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
  vapi_msg_bfd_udp_session_set_flags_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bfd_udp_session_set_flags_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bfd_udp_session_set_flags_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bfd_udp_session_set_flags()
{
  static const char name[] = "bfd_udp_session_set_flags";
  static const char name_with_crc[] = "bfd_udp_session_set_flags_04b4bdfd";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_session_set_flags = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bfd_udp_session_set_flags, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_session_set_flags_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_session_set_flags_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_session_set_flags_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_session_set_flags = vapi_register_msg(&__vapi_metadata_bfd_udp_session_set_flags);
  VAPI_DBG("Assigned msg id %d to bfd_udp_session_set_flags", vapi_msg_id_bfd_udp_session_set_flags);
}
#endif

#ifndef defined_vapi_msg_want_bfd_events_reply
#define defined_vapi_msg_want_bfd_events_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_want_bfd_events_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_want_bfd_events_reply payload;
} vapi_msg_want_bfd_events_reply;

static inline void vapi_msg_want_bfd_events_reply_payload_hton(vapi_payload_want_bfd_events_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_want_bfd_events_reply_payload_ntoh(vapi_payload_want_bfd_events_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_want_bfd_events_reply_hton(vapi_msg_want_bfd_events_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_bfd_events_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_want_bfd_events_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_want_bfd_events_reply_ntoh(vapi_msg_want_bfd_events_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_bfd_events_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_want_bfd_events_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_want_bfd_events_reply_msg_size(vapi_msg_want_bfd_events_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_want_bfd_events_reply_msg_size(vapi_msg_want_bfd_events_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_want_bfd_events_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'want_bfd_events_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_want_bfd_events_reply));
      return -1;
    }
  if (vapi_calc_want_bfd_events_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'want_bfd_events_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_want_bfd_events_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_want_bfd_events_reply()
{
  static const char name[] = "want_bfd_events_reply";
  static const char name_with_crc[] = "want_bfd_events_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_want_bfd_events_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_want_bfd_events_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_want_bfd_events_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_want_bfd_events_reply_hton,
    (generic_swap_fn_t)vapi_msg_want_bfd_events_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_want_bfd_events_reply = vapi_register_msg(&__vapi_metadata_want_bfd_events_reply);
  VAPI_DBG("Assigned msg id %d to want_bfd_events_reply", vapi_msg_id_want_bfd_events_reply);
}

static inline void vapi_set_vapi_msg_want_bfd_events_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_want_bfd_events_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_want_bfd_events_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_want_bfd_events
#define defined_vapi_msg_want_bfd_events
typedef struct __attribute__ ((__packed__)) {
  bool enable_disable;
  u32 pid; 
} vapi_payload_want_bfd_events;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_want_bfd_events payload;
} vapi_msg_want_bfd_events;

static inline void vapi_msg_want_bfd_events_payload_hton(vapi_payload_want_bfd_events *payload)
{
  payload->pid = htobe32(payload->pid);
}

static inline void vapi_msg_want_bfd_events_payload_ntoh(vapi_payload_want_bfd_events *payload)
{
  payload->pid = be32toh(payload->pid);
}

static inline void vapi_msg_want_bfd_events_hton(vapi_msg_want_bfd_events *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_bfd_events'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_want_bfd_events_payload_hton(&msg->payload);
}

static inline void vapi_msg_want_bfd_events_ntoh(vapi_msg_want_bfd_events *msg)
{
  VAPI_DBG("Swapping `vapi_msg_want_bfd_events'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_want_bfd_events_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_want_bfd_events_msg_size(vapi_msg_want_bfd_events *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_want_bfd_events_msg_size(vapi_msg_want_bfd_events *msg, uword buf_size)
{
  if (sizeof(vapi_msg_want_bfd_events) > buf_size)
    {
      VAPI_ERR("Truncated 'want_bfd_events' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_want_bfd_events));
      return -1;
    }
  if (vapi_calc_want_bfd_events_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'want_bfd_events' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_want_bfd_events_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_want_bfd_events* vapi_alloc_want_bfd_events(struct vapi_ctx_s *ctx)
{
  vapi_msg_want_bfd_events *msg = NULL;
  const size_t size = sizeof(vapi_msg_want_bfd_events);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_want_bfd_events*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_want_bfd_events);

  return msg;
}

static inline vapi_error_e vapi_want_bfd_events(struct vapi_ctx_s *ctx,
  vapi_msg_want_bfd_events *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_want_bfd_events_reply *reply),
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
  vapi_msg_want_bfd_events_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_want_bfd_events_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_want_bfd_events_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_want_bfd_events()
{
  static const char name[] = "want_bfd_events";
  static const char name_with_crc[] = "want_bfd_events_c5e2af94";
  static vapi_message_desc_t __vapi_metadata_want_bfd_events = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_want_bfd_events, payload),
    (verify_msg_size_fn_t)vapi_verify_want_bfd_events_msg_size,
    (generic_swap_fn_t)vapi_msg_want_bfd_events_hton,
    (generic_swap_fn_t)vapi_msg_want_bfd_events_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_want_bfd_events = vapi_register_msg(&__vapi_metadata_want_bfd_events);
  VAPI_DBG("Assigned msg id %d to want_bfd_events", vapi_msg_id_want_bfd_events);
}
#endif

#ifndef defined_vapi_msg_bfd_udp_session_event
#define defined_vapi_msg_bfd_udp_session_event
typedef struct __attribute__ ((__packed__)) {
  u16 _vl_msg_id;
  u32 client_index;
  u32 pid;
  vapi_type_interface_index sw_if_index;
  vapi_type_address local_addr;
  vapi_type_address peer_addr;
  vapi_enum_bfd_state state;
  bool is_authenticated;
  u8 bfd_key_id;
  u32 conf_key_id;
  u32 required_min_rx;
  u32 desired_min_tx;
  u8 detect_mult; 
} vapi_payload_bfd_udp_session_event;

typedef struct __attribute__ ((__packed__)) {

  vapi_payload_bfd_udp_session_event payload;
} vapi_msg_bfd_udp_session_event;

static inline void vapi_msg_bfd_udp_session_event_payload_hton(vapi_payload_bfd_udp_session_event *payload)
{
  payload->_vl_msg_id = htobe16(payload->_vl_msg_id);
  payload->client_index = htobe32(payload->client_index);
  payload->pid = htobe32(payload->pid);
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->state = (vapi_enum_bfd_state)htobe32(payload->state);
  payload->conf_key_id = htobe32(payload->conf_key_id);
  payload->required_min_rx = htobe32(payload->required_min_rx);
  payload->desired_min_tx = htobe32(payload->desired_min_tx);
}

static inline void vapi_msg_bfd_udp_session_event_payload_ntoh(vapi_payload_bfd_udp_session_event *payload)
{
  payload->_vl_msg_id = be16toh(payload->_vl_msg_id);
  payload->client_index = be32toh(payload->client_index);
  payload->pid = be32toh(payload->pid);
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->state = (vapi_enum_bfd_state)be32toh(payload->state);
  payload->conf_key_id = be32toh(payload->conf_key_id);
  payload->required_min_rx = be32toh(payload->required_min_rx);
  payload->desired_min_tx = be32toh(payload->desired_min_tx);
}

static inline void vapi_msg_bfd_udp_session_event_hton(vapi_msg_bfd_udp_session_event *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_session_event'@%p to big endian", msg);

  vapi_msg_bfd_udp_session_event_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_session_event_ntoh(vapi_msg_bfd_udp_session_event *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_session_event'@%p to host byte order", msg);

  vapi_msg_bfd_udp_session_event_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_session_event_msg_size(vapi_msg_bfd_udp_session_event *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_session_event_msg_size(vapi_msg_bfd_udp_session_event *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_session_event) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_session_event' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_session_event));
      return -1;
    }
  if (vapi_calc_bfd_udp_session_event_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_session_event' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_session_event_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bfd_udp_session_event()
{
  static const char name[] = "bfd_udp_session_event";
  static const char name_with_crc[] = "bfd_udp_session_event_8eaaf062";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_session_event = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    false,
    0,
    offsetof(vapi_msg_bfd_udp_session_event, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_session_event_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_session_event_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_session_event_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_session_event = vapi_register_msg(&__vapi_metadata_bfd_udp_session_event);
  VAPI_DBG("Assigned msg id %d to bfd_udp_session_event", vapi_msg_id_bfd_udp_session_event);
}

static inline void vapi_set_vapi_msg_bfd_udp_session_event_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bfd_udp_session_event *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bfd_udp_session_event, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bfd_auth_set_key_reply
#define defined_vapi_msg_bfd_auth_set_key_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bfd_auth_set_key_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bfd_auth_set_key_reply payload;
} vapi_msg_bfd_auth_set_key_reply;

static inline void vapi_msg_bfd_auth_set_key_reply_payload_hton(vapi_payload_bfd_auth_set_key_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bfd_auth_set_key_reply_payload_ntoh(vapi_payload_bfd_auth_set_key_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bfd_auth_set_key_reply_hton(vapi_msg_bfd_auth_set_key_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_auth_set_key_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bfd_auth_set_key_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_auth_set_key_reply_ntoh(vapi_msg_bfd_auth_set_key_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_auth_set_key_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bfd_auth_set_key_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_auth_set_key_reply_msg_size(vapi_msg_bfd_auth_set_key_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_auth_set_key_reply_msg_size(vapi_msg_bfd_auth_set_key_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_auth_set_key_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_auth_set_key_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_auth_set_key_reply));
      return -1;
    }
  if (vapi_calc_bfd_auth_set_key_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_auth_set_key_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_auth_set_key_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bfd_auth_set_key_reply()
{
  static const char name[] = "bfd_auth_set_key_reply";
  static const char name_with_crc[] = "bfd_auth_set_key_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bfd_auth_set_key_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bfd_auth_set_key_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_auth_set_key_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_auth_set_key_reply_hton,
    (generic_swap_fn_t)vapi_msg_bfd_auth_set_key_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_auth_set_key_reply = vapi_register_msg(&__vapi_metadata_bfd_auth_set_key_reply);
  VAPI_DBG("Assigned msg id %d to bfd_auth_set_key_reply", vapi_msg_id_bfd_auth_set_key_reply);
}

static inline void vapi_set_vapi_msg_bfd_auth_set_key_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bfd_auth_set_key_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bfd_auth_set_key_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bfd_auth_set_key
#define defined_vapi_msg_bfd_auth_set_key
typedef struct __attribute__ ((__packed__)) {
  u32 conf_key_id;
  u8 key_len;
  u8 auth_type;
  u8 key[20]; 
} vapi_payload_bfd_auth_set_key;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bfd_auth_set_key payload;
} vapi_msg_bfd_auth_set_key;

static inline void vapi_msg_bfd_auth_set_key_payload_hton(vapi_payload_bfd_auth_set_key *payload)
{
  payload->conf_key_id = htobe32(payload->conf_key_id);
}

static inline void vapi_msg_bfd_auth_set_key_payload_ntoh(vapi_payload_bfd_auth_set_key *payload)
{
  payload->conf_key_id = be32toh(payload->conf_key_id);
}

static inline void vapi_msg_bfd_auth_set_key_hton(vapi_msg_bfd_auth_set_key *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_auth_set_key'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bfd_auth_set_key_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_auth_set_key_ntoh(vapi_msg_bfd_auth_set_key *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_auth_set_key'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bfd_auth_set_key_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_auth_set_key_msg_size(vapi_msg_bfd_auth_set_key *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_auth_set_key_msg_size(vapi_msg_bfd_auth_set_key *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_auth_set_key) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_auth_set_key' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_auth_set_key));
      return -1;
    }
  if (vapi_calc_bfd_auth_set_key_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_auth_set_key' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_auth_set_key_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bfd_auth_set_key* vapi_alloc_bfd_auth_set_key(struct vapi_ctx_s *ctx)
{
  vapi_msg_bfd_auth_set_key *msg = NULL;
  const size_t size = sizeof(vapi_msg_bfd_auth_set_key);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bfd_auth_set_key*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bfd_auth_set_key);

  return msg;
}

static inline vapi_error_e vapi_bfd_auth_set_key(struct vapi_ctx_s *ctx,
  vapi_msg_bfd_auth_set_key *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bfd_auth_set_key_reply *reply),
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
  vapi_msg_bfd_auth_set_key_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bfd_auth_set_key_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bfd_auth_set_key_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bfd_auth_set_key()
{
  static const char name[] = "bfd_auth_set_key";
  static const char name_with_crc[] = "bfd_auth_set_key_690b8877";
  static vapi_message_desc_t __vapi_metadata_bfd_auth_set_key = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bfd_auth_set_key, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_auth_set_key_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_auth_set_key_hton,
    (generic_swap_fn_t)vapi_msg_bfd_auth_set_key_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_auth_set_key = vapi_register_msg(&__vapi_metadata_bfd_auth_set_key);
  VAPI_DBG("Assigned msg id %d to bfd_auth_set_key", vapi_msg_id_bfd_auth_set_key);
}
#endif

#ifndef defined_vapi_msg_bfd_auth_del_key_reply
#define defined_vapi_msg_bfd_auth_del_key_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bfd_auth_del_key_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bfd_auth_del_key_reply payload;
} vapi_msg_bfd_auth_del_key_reply;

static inline void vapi_msg_bfd_auth_del_key_reply_payload_hton(vapi_payload_bfd_auth_del_key_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bfd_auth_del_key_reply_payload_ntoh(vapi_payload_bfd_auth_del_key_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bfd_auth_del_key_reply_hton(vapi_msg_bfd_auth_del_key_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_auth_del_key_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bfd_auth_del_key_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_auth_del_key_reply_ntoh(vapi_msg_bfd_auth_del_key_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_auth_del_key_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bfd_auth_del_key_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_auth_del_key_reply_msg_size(vapi_msg_bfd_auth_del_key_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_auth_del_key_reply_msg_size(vapi_msg_bfd_auth_del_key_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_auth_del_key_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_auth_del_key_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_auth_del_key_reply));
      return -1;
    }
  if (vapi_calc_bfd_auth_del_key_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_auth_del_key_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_auth_del_key_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bfd_auth_del_key_reply()
{
  static const char name[] = "bfd_auth_del_key_reply";
  static const char name_with_crc[] = "bfd_auth_del_key_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bfd_auth_del_key_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bfd_auth_del_key_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_auth_del_key_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_auth_del_key_reply_hton,
    (generic_swap_fn_t)vapi_msg_bfd_auth_del_key_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_auth_del_key_reply = vapi_register_msg(&__vapi_metadata_bfd_auth_del_key_reply);
  VAPI_DBG("Assigned msg id %d to bfd_auth_del_key_reply", vapi_msg_id_bfd_auth_del_key_reply);
}

static inline void vapi_set_vapi_msg_bfd_auth_del_key_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bfd_auth_del_key_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bfd_auth_del_key_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bfd_auth_del_key
#define defined_vapi_msg_bfd_auth_del_key
typedef struct __attribute__ ((__packed__)) {
  u32 conf_key_id; 
} vapi_payload_bfd_auth_del_key;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bfd_auth_del_key payload;
} vapi_msg_bfd_auth_del_key;

static inline void vapi_msg_bfd_auth_del_key_payload_hton(vapi_payload_bfd_auth_del_key *payload)
{
  payload->conf_key_id = htobe32(payload->conf_key_id);
}

static inline void vapi_msg_bfd_auth_del_key_payload_ntoh(vapi_payload_bfd_auth_del_key *payload)
{
  payload->conf_key_id = be32toh(payload->conf_key_id);
}

static inline void vapi_msg_bfd_auth_del_key_hton(vapi_msg_bfd_auth_del_key *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_auth_del_key'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bfd_auth_del_key_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_auth_del_key_ntoh(vapi_msg_bfd_auth_del_key *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_auth_del_key'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bfd_auth_del_key_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_auth_del_key_msg_size(vapi_msg_bfd_auth_del_key *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_auth_del_key_msg_size(vapi_msg_bfd_auth_del_key *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_auth_del_key) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_auth_del_key' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_auth_del_key));
      return -1;
    }
  if (vapi_calc_bfd_auth_del_key_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_auth_del_key' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_auth_del_key_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bfd_auth_del_key* vapi_alloc_bfd_auth_del_key(struct vapi_ctx_s *ctx)
{
  vapi_msg_bfd_auth_del_key *msg = NULL;
  const size_t size = sizeof(vapi_msg_bfd_auth_del_key);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bfd_auth_del_key*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bfd_auth_del_key);

  return msg;
}

static inline vapi_error_e vapi_bfd_auth_del_key(struct vapi_ctx_s *ctx,
  vapi_msg_bfd_auth_del_key *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bfd_auth_del_key_reply *reply),
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
  vapi_msg_bfd_auth_del_key_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bfd_auth_del_key_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bfd_auth_del_key_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bfd_auth_del_key()
{
  static const char name[] = "bfd_auth_del_key";
  static const char name_with_crc[] = "bfd_auth_del_key_65310b22";
  static vapi_message_desc_t __vapi_metadata_bfd_auth_del_key = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bfd_auth_del_key, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_auth_del_key_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_auth_del_key_hton,
    (generic_swap_fn_t)vapi_msg_bfd_auth_del_key_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_auth_del_key = vapi_register_msg(&__vapi_metadata_bfd_auth_del_key);
  VAPI_DBG("Assigned msg id %d to bfd_auth_del_key", vapi_msg_id_bfd_auth_del_key);
}
#endif

#ifndef defined_vapi_msg_bfd_auth_keys_details
#define defined_vapi_msg_bfd_auth_keys_details
typedef struct __attribute__ ((__packed__)) {
  u32 conf_key_id;
  u32 use_count;
  u8 auth_type; 
} vapi_payload_bfd_auth_keys_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bfd_auth_keys_details payload;
} vapi_msg_bfd_auth_keys_details;

static inline void vapi_msg_bfd_auth_keys_details_payload_hton(vapi_payload_bfd_auth_keys_details *payload)
{
  payload->conf_key_id = htobe32(payload->conf_key_id);
  payload->use_count = htobe32(payload->use_count);
}

static inline void vapi_msg_bfd_auth_keys_details_payload_ntoh(vapi_payload_bfd_auth_keys_details *payload)
{
  payload->conf_key_id = be32toh(payload->conf_key_id);
  payload->use_count = be32toh(payload->use_count);
}

static inline void vapi_msg_bfd_auth_keys_details_hton(vapi_msg_bfd_auth_keys_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_auth_keys_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bfd_auth_keys_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_auth_keys_details_ntoh(vapi_msg_bfd_auth_keys_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_auth_keys_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bfd_auth_keys_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_auth_keys_details_msg_size(vapi_msg_bfd_auth_keys_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_auth_keys_details_msg_size(vapi_msg_bfd_auth_keys_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_auth_keys_details) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_auth_keys_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_auth_keys_details));
      return -1;
    }
  if (vapi_calc_bfd_auth_keys_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_auth_keys_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_auth_keys_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bfd_auth_keys_details()
{
  static const char name[] = "bfd_auth_keys_details";
  static const char name_with_crc[] = "bfd_auth_keys_details_84130e9f";
  static vapi_message_desc_t __vapi_metadata_bfd_auth_keys_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bfd_auth_keys_details, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_auth_keys_details_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_auth_keys_details_hton,
    (generic_swap_fn_t)vapi_msg_bfd_auth_keys_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_auth_keys_details = vapi_register_msg(&__vapi_metadata_bfd_auth_keys_details);
  VAPI_DBG("Assigned msg id %d to bfd_auth_keys_details", vapi_msg_id_bfd_auth_keys_details);
}

static inline void vapi_set_vapi_msg_bfd_auth_keys_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bfd_auth_keys_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bfd_auth_keys_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bfd_auth_keys_dump
#define defined_vapi_msg_bfd_auth_keys_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_bfd_auth_keys_dump;

static inline void vapi_msg_bfd_auth_keys_dump_hton(vapi_msg_bfd_auth_keys_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_auth_keys_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_bfd_auth_keys_dump_ntoh(vapi_msg_bfd_auth_keys_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_auth_keys_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_bfd_auth_keys_dump_msg_size(vapi_msg_bfd_auth_keys_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_auth_keys_dump_msg_size(vapi_msg_bfd_auth_keys_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_auth_keys_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_auth_keys_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_auth_keys_dump));
      return -1;
    }
  if (vapi_calc_bfd_auth_keys_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_auth_keys_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_auth_keys_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bfd_auth_keys_dump* vapi_alloc_bfd_auth_keys_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_bfd_auth_keys_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_bfd_auth_keys_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bfd_auth_keys_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bfd_auth_keys_dump);

  return msg;
}

static inline vapi_error_e vapi_bfd_auth_keys_dump(struct vapi_ctx_s *ctx,
  vapi_msg_bfd_auth_keys_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bfd_auth_keys_details *reply),
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
  vapi_msg_bfd_auth_keys_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bfd_auth_keys_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_bfd_auth_keys_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bfd_auth_keys_dump()
{
  static const char name[] = "bfd_auth_keys_dump";
  static const char name_with_crc[] = "bfd_auth_keys_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_bfd_auth_keys_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_bfd_auth_keys_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_auth_keys_dump_hton,
    (generic_swap_fn_t)vapi_msg_bfd_auth_keys_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_auth_keys_dump = vapi_register_msg(&__vapi_metadata_bfd_auth_keys_dump);
  VAPI_DBG("Assigned msg id %d to bfd_auth_keys_dump", vapi_msg_id_bfd_auth_keys_dump);
}
#endif

#ifndef defined_vapi_msg_bfd_udp_auth_activate_reply
#define defined_vapi_msg_bfd_udp_auth_activate_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bfd_udp_auth_activate_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bfd_udp_auth_activate_reply payload;
} vapi_msg_bfd_udp_auth_activate_reply;

static inline void vapi_msg_bfd_udp_auth_activate_reply_payload_hton(vapi_payload_bfd_udp_auth_activate_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bfd_udp_auth_activate_reply_payload_ntoh(vapi_payload_bfd_udp_auth_activate_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bfd_udp_auth_activate_reply_hton(vapi_msg_bfd_udp_auth_activate_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_auth_activate_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bfd_udp_auth_activate_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_auth_activate_reply_ntoh(vapi_msg_bfd_udp_auth_activate_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_auth_activate_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_auth_activate_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_auth_activate_reply_msg_size(vapi_msg_bfd_udp_auth_activate_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_auth_activate_reply_msg_size(vapi_msg_bfd_udp_auth_activate_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_auth_activate_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_auth_activate_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_auth_activate_reply));
      return -1;
    }
  if (vapi_calc_bfd_udp_auth_activate_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_auth_activate_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_auth_activate_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bfd_udp_auth_activate_reply()
{
  static const char name[] = "bfd_udp_auth_activate_reply";
  static const char name_with_crc[] = "bfd_udp_auth_activate_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_auth_activate_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bfd_udp_auth_activate_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_auth_activate_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_auth_activate_reply_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_auth_activate_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_auth_activate_reply = vapi_register_msg(&__vapi_metadata_bfd_udp_auth_activate_reply);
  VAPI_DBG("Assigned msg id %d to bfd_udp_auth_activate_reply", vapi_msg_id_bfd_udp_auth_activate_reply);
}

static inline void vapi_set_vapi_msg_bfd_udp_auth_activate_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bfd_udp_auth_activate_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bfd_udp_auth_activate_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bfd_udp_auth_activate
#define defined_vapi_msg_bfd_udp_auth_activate
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_type_address local_addr;
  vapi_type_address peer_addr;
  bool is_delayed;
  u8 bfd_key_id;
  u32 conf_key_id; 
} vapi_payload_bfd_udp_auth_activate;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bfd_udp_auth_activate payload;
} vapi_msg_bfd_udp_auth_activate;

static inline void vapi_msg_bfd_udp_auth_activate_payload_hton(vapi_payload_bfd_udp_auth_activate *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->conf_key_id = htobe32(payload->conf_key_id);
}

static inline void vapi_msg_bfd_udp_auth_activate_payload_ntoh(vapi_payload_bfd_udp_auth_activate *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->conf_key_id = be32toh(payload->conf_key_id);
}

static inline void vapi_msg_bfd_udp_auth_activate_hton(vapi_msg_bfd_udp_auth_activate *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_auth_activate'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bfd_udp_auth_activate_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_auth_activate_ntoh(vapi_msg_bfd_udp_auth_activate *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_auth_activate'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_auth_activate_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_auth_activate_msg_size(vapi_msg_bfd_udp_auth_activate *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_auth_activate_msg_size(vapi_msg_bfd_udp_auth_activate *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_auth_activate) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_auth_activate' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_auth_activate));
      return -1;
    }
  if (vapi_calc_bfd_udp_auth_activate_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_auth_activate' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_auth_activate_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bfd_udp_auth_activate* vapi_alloc_bfd_udp_auth_activate(struct vapi_ctx_s *ctx)
{
  vapi_msg_bfd_udp_auth_activate *msg = NULL;
  const size_t size = sizeof(vapi_msg_bfd_udp_auth_activate);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bfd_udp_auth_activate*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bfd_udp_auth_activate);

  return msg;
}

static inline vapi_error_e vapi_bfd_udp_auth_activate(struct vapi_ctx_s *ctx,
  vapi_msg_bfd_udp_auth_activate *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bfd_udp_auth_activate_reply *reply),
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
  vapi_msg_bfd_udp_auth_activate_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bfd_udp_auth_activate_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bfd_udp_auth_activate_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bfd_udp_auth_activate()
{
  static const char name[] = "bfd_udp_auth_activate";
  static const char name_with_crc[] = "bfd_udp_auth_activate_21fd1bdb";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_auth_activate = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bfd_udp_auth_activate, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_auth_activate_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_auth_activate_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_auth_activate_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_auth_activate = vapi_register_msg(&__vapi_metadata_bfd_udp_auth_activate);
  VAPI_DBG("Assigned msg id %d to bfd_udp_auth_activate", vapi_msg_id_bfd_udp_auth_activate);
}
#endif

#ifndef defined_vapi_msg_bfd_udp_auth_deactivate_reply
#define defined_vapi_msg_bfd_udp_auth_deactivate_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bfd_udp_auth_deactivate_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bfd_udp_auth_deactivate_reply payload;
} vapi_msg_bfd_udp_auth_deactivate_reply;

static inline void vapi_msg_bfd_udp_auth_deactivate_reply_payload_hton(vapi_payload_bfd_udp_auth_deactivate_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bfd_udp_auth_deactivate_reply_payload_ntoh(vapi_payload_bfd_udp_auth_deactivate_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bfd_udp_auth_deactivate_reply_hton(vapi_msg_bfd_udp_auth_deactivate_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_auth_deactivate_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bfd_udp_auth_deactivate_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_auth_deactivate_reply_ntoh(vapi_msg_bfd_udp_auth_deactivate_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_auth_deactivate_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_auth_deactivate_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_auth_deactivate_reply_msg_size(vapi_msg_bfd_udp_auth_deactivate_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_auth_deactivate_reply_msg_size(vapi_msg_bfd_udp_auth_deactivate_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_auth_deactivate_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_auth_deactivate_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_auth_deactivate_reply));
      return -1;
    }
  if (vapi_calc_bfd_udp_auth_deactivate_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_auth_deactivate_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_auth_deactivate_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bfd_udp_auth_deactivate_reply()
{
  static const char name[] = "bfd_udp_auth_deactivate_reply";
  static const char name_with_crc[] = "bfd_udp_auth_deactivate_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_auth_deactivate_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bfd_udp_auth_deactivate_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_auth_deactivate_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_auth_deactivate_reply_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_auth_deactivate_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_auth_deactivate_reply = vapi_register_msg(&__vapi_metadata_bfd_udp_auth_deactivate_reply);
  VAPI_DBG("Assigned msg id %d to bfd_udp_auth_deactivate_reply", vapi_msg_id_bfd_udp_auth_deactivate_reply);
}

static inline void vapi_set_vapi_msg_bfd_udp_auth_deactivate_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bfd_udp_auth_deactivate_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bfd_udp_auth_deactivate_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bfd_udp_auth_deactivate
#define defined_vapi_msg_bfd_udp_auth_deactivate
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_type_address local_addr;
  vapi_type_address peer_addr;
  bool is_delayed; 
} vapi_payload_bfd_udp_auth_deactivate;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bfd_udp_auth_deactivate payload;
} vapi_msg_bfd_udp_auth_deactivate;

static inline void vapi_msg_bfd_udp_auth_deactivate_payload_hton(vapi_payload_bfd_udp_auth_deactivate *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_bfd_udp_auth_deactivate_payload_ntoh(vapi_payload_bfd_udp_auth_deactivate *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_bfd_udp_auth_deactivate_hton(vapi_msg_bfd_udp_auth_deactivate *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_auth_deactivate'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bfd_udp_auth_deactivate_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_auth_deactivate_ntoh(vapi_msg_bfd_udp_auth_deactivate *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_auth_deactivate'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_auth_deactivate_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_auth_deactivate_msg_size(vapi_msg_bfd_udp_auth_deactivate *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_auth_deactivate_msg_size(vapi_msg_bfd_udp_auth_deactivate *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_auth_deactivate) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_auth_deactivate' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_auth_deactivate));
      return -1;
    }
  if (vapi_calc_bfd_udp_auth_deactivate_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_auth_deactivate' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_auth_deactivate_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bfd_udp_auth_deactivate* vapi_alloc_bfd_udp_auth_deactivate(struct vapi_ctx_s *ctx)
{
  vapi_msg_bfd_udp_auth_deactivate *msg = NULL;
  const size_t size = sizeof(vapi_msg_bfd_udp_auth_deactivate);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bfd_udp_auth_deactivate*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bfd_udp_auth_deactivate);

  return msg;
}

static inline vapi_error_e vapi_bfd_udp_auth_deactivate(struct vapi_ctx_s *ctx,
  vapi_msg_bfd_udp_auth_deactivate *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bfd_udp_auth_deactivate_reply *reply),
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
  vapi_msg_bfd_udp_auth_deactivate_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bfd_udp_auth_deactivate_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bfd_udp_auth_deactivate_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bfd_udp_auth_deactivate()
{
  static const char name[] = "bfd_udp_auth_deactivate";
  static const char name_with_crc[] = "bfd_udp_auth_deactivate_9a05e2e0";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_auth_deactivate = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bfd_udp_auth_deactivate, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_auth_deactivate_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_auth_deactivate_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_auth_deactivate_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_auth_deactivate = vapi_register_msg(&__vapi_metadata_bfd_udp_auth_deactivate);
  VAPI_DBG("Assigned msg id %d to bfd_udp_auth_deactivate", vapi_msg_id_bfd_udp_auth_deactivate);
}
#endif

#ifndef defined_vapi_msg_bfd_udp_enable_multihop_reply
#define defined_vapi_msg_bfd_udp_enable_multihop_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bfd_udp_enable_multihop_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bfd_udp_enable_multihop_reply payload;
} vapi_msg_bfd_udp_enable_multihop_reply;

static inline void vapi_msg_bfd_udp_enable_multihop_reply_payload_hton(vapi_payload_bfd_udp_enable_multihop_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bfd_udp_enable_multihop_reply_payload_ntoh(vapi_payload_bfd_udp_enable_multihop_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bfd_udp_enable_multihop_reply_hton(vapi_msg_bfd_udp_enable_multihop_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_enable_multihop_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bfd_udp_enable_multihop_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_enable_multihop_reply_ntoh(vapi_msg_bfd_udp_enable_multihop_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_enable_multihop_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_enable_multihop_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_enable_multihop_reply_msg_size(vapi_msg_bfd_udp_enable_multihop_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_enable_multihop_reply_msg_size(vapi_msg_bfd_udp_enable_multihop_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_enable_multihop_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_enable_multihop_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_enable_multihop_reply));
      return -1;
    }
  if (vapi_calc_bfd_udp_enable_multihop_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_enable_multihop_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_enable_multihop_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bfd_udp_enable_multihop_reply()
{
  static const char name[] = "bfd_udp_enable_multihop_reply";
  static const char name_with_crc[] = "bfd_udp_enable_multihop_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_enable_multihop_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bfd_udp_enable_multihop_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_enable_multihop_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_enable_multihop_reply_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_enable_multihop_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_enable_multihop_reply = vapi_register_msg(&__vapi_metadata_bfd_udp_enable_multihop_reply);
  VAPI_DBG("Assigned msg id %d to bfd_udp_enable_multihop_reply", vapi_msg_id_bfd_udp_enable_multihop_reply);
}

static inline void vapi_set_vapi_msg_bfd_udp_enable_multihop_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bfd_udp_enable_multihop_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bfd_udp_enable_multihop_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bfd_udp_enable_multihop
#define defined_vapi_msg_bfd_udp_enable_multihop
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_bfd_udp_enable_multihop;

static inline void vapi_msg_bfd_udp_enable_multihop_hton(vapi_msg_bfd_udp_enable_multihop *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_enable_multihop'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_bfd_udp_enable_multihop_ntoh(vapi_msg_bfd_udp_enable_multihop *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_enable_multihop'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_bfd_udp_enable_multihop_msg_size(vapi_msg_bfd_udp_enable_multihop *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_enable_multihop_msg_size(vapi_msg_bfd_udp_enable_multihop *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_enable_multihop) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_enable_multihop' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_enable_multihop));
      return -1;
    }
  if (vapi_calc_bfd_udp_enable_multihop_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_enable_multihop' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_enable_multihop_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bfd_udp_enable_multihop* vapi_alloc_bfd_udp_enable_multihop(struct vapi_ctx_s *ctx)
{
  vapi_msg_bfd_udp_enable_multihop *msg = NULL;
  const size_t size = sizeof(vapi_msg_bfd_udp_enable_multihop);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bfd_udp_enable_multihop*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bfd_udp_enable_multihop);

  return msg;
}

static inline vapi_error_e vapi_bfd_udp_enable_multihop(struct vapi_ctx_s *ctx,
  vapi_msg_bfd_udp_enable_multihop *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bfd_udp_enable_multihop_reply *reply),
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
  vapi_msg_bfd_udp_enable_multihop_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bfd_udp_enable_multihop_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bfd_udp_enable_multihop_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bfd_udp_enable_multihop()
{
  static const char name[] = "bfd_udp_enable_multihop";
  static const char name_with_crc[] = "bfd_udp_enable_multihop_51077d14";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_enable_multihop = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_enable_multihop_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_enable_multihop_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_enable_multihop_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_enable_multihop = vapi_register_msg(&__vapi_metadata_bfd_udp_enable_multihop);
  VAPI_DBG("Assigned msg id %d to bfd_udp_enable_multihop", vapi_msg_id_bfd_udp_enable_multihop);
}
#endif

#ifndef defined_vapi_msg_bfd_udp_set_tos_reply
#define defined_vapi_msg_bfd_udp_set_tos_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_bfd_udp_set_tos_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bfd_udp_set_tos_reply payload;
} vapi_msg_bfd_udp_set_tos_reply;

static inline void vapi_msg_bfd_udp_set_tos_reply_payload_hton(vapi_payload_bfd_udp_set_tos_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bfd_udp_set_tos_reply_payload_ntoh(vapi_payload_bfd_udp_set_tos_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bfd_udp_set_tos_reply_hton(vapi_msg_bfd_udp_set_tos_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_set_tos_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bfd_udp_set_tos_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_set_tos_reply_ntoh(vapi_msg_bfd_udp_set_tos_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_set_tos_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_set_tos_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_set_tos_reply_msg_size(vapi_msg_bfd_udp_set_tos_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_set_tos_reply_msg_size(vapi_msg_bfd_udp_set_tos_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_set_tos_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_set_tos_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_set_tos_reply));
      return -1;
    }
  if (vapi_calc_bfd_udp_set_tos_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_set_tos_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_set_tos_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bfd_udp_set_tos_reply()
{
  static const char name[] = "bfd_udp_set_tos_reply";
  static const char name_with_crc[] = "bfd_udp_set_tos_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_set_tos_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bfd_udp_set_tos_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_set_tos_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_set_tos_reply_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_set_tos_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_set_tos_reply = vapi_register_msg(&__vapi_metadata_bfd_udp_set_tos_reply);
  VAPI_DBG("Assigned msg id %d to bfd_udp_set_tos_reply", vapi_msg_id_bfd_udp_set_tos_reply);
}

static inline void vapi_set_vapi_msg_bfd_udp_set_tos_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bfd_udp_set_tos_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bfd_udp_set_tos_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bfd_udp_set_tos
#define defined_vapi_msg_bfd_udp_set_tos
typedef struct __attribute__ ((__packed__)) {
  u8 tos; 
} vapi_payload_bfd_udp_set_tos;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_bfd_udp_set_tos payload;
} vapi_msg_bfd_udp_set_tos;

static inline void vapi_msg_bfd_udp_set_tos_payload_hton(vapi_payload_bfd_udp_set_tos *payload)
{

}

static inline void vapi_msg_bfd_udp_set_tos_payload_ntoh(vapi_payload_bfd_udp_set_tos *payload)
{

}

static inline void vapi_msg_bfd_udp_set_tos_hton(vapi_msg_bfd_udp_set_tos *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_set_tos'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_bfd_udp_set_tos_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_set_tos_ntoh(vapi_msg_bfd_udp_set_tos *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_set_tos'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_set_tos_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_set_tos_msg_size(vapi_msg_bfd_udp_set_tos *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_set_tos_msg_size(vapi_msg_bfd_udp_set_tos *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_set_tos) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_set_tos' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_set_tos));
      return -1;
    }
  if (vapi_calc_bfd_udp_set_tos_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_set_tos' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_set_tos_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bfd_udp_set_tos* vapi_alloc_bfd_udp_set_tos(struct vapi_ctx_s *ctx)
{
  vapi_msg_bfd_udp_set_tos *msg = NULL;
  const size_t size = sizeof(vapi_msg_bfd_udp_set_tos);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bfd_udp_set_tos*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bfd_udp_set_tos);

  return msg;
}

static inline vapi_error_e vapi_bfd_udp_set_tos(struct vapi_ctx_s *ctx,
  vapi_msg_bfd_udp_set_tos *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bfd_udp_set_tos_reply *reply),
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
  vapi_msg_bfd_udp_set_tos_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bfd_udp_set_tos_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bfd_udp_set_tos_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bfd_udp_set_tos()
{
  static const char name[] = "bfd_udp_set_tos";
  static const char name_with_crc[] = "bfd_udp_set_tos_00fe25ce";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_set_tos = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_bfd_udp_set_tos, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_set_tos_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_set_tos_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_set_tos_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_set_tos = vapi_register_msg(&__vapi_metadata_bfd_udp_set_tos);
  VAPI_DBG("Assigned msg id %d to bfd_udp_set_tos", vapi_msg_id_bfd_udp_set_tos);
}
#endif

#ifndef defined_vapi_msg_bfd_udp_get_tos_reply
#define defined_vapi_msg_bfd_udp_get_tos_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u8 tos; 
} vapi_payload_bfd_udp_get_tos_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_bfd_udp_get_tos_reply payload;
} vapi_msg_bfd_udp_get_tos_reply;

static inline void vapi_msg_bfd_udp_get_tos_reply_payload_hton(vapi_payload_bfd_udp_get_tos_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_bfd_udp_get_tos_reply_payload_ntoh(vapi_payload_bfd_udp_get_tos_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_bfd_udp_get_tos_reply_hton(vapi_msg_bfd_udp_get_tos_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_get_tos_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_bfd_udp_get_tos_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_bfd_udp_get_tos_reply_ntoh(vapi_msg_bfd_udp_get_tos_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_get_tos_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_bfd_udp_get_tos_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_bfd_udp_get_tos_reply_msg_size(vapi_msg_bfd_udp_get_tos_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_get_tos_reply_msg_size(vapi_msg_bfd_udp_get_tos_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_get_tos_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_get_tos_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_get_tos_reply));
      return -1;
    }
  if (vapi_calc_bfd_udp_get_tos_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_get_tos_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_get_tos_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_bfd_udp_get_tos_reply()
{
  static const char name[] = "bfd_udp_get_tos_reply";
  static const char name_with_crc[] = "bfd_udp_get_tos_reply_d8931abf";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_get_tos_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_bfd_udp_get_tos_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_get_tos_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_get_tos_reply_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_get_tos_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_get_tos_reply = vapi_register_msg(&__vapi_metadata_bfd_udp_get_tos_reply);
  VAPI_DBG("Assigned msg id %d to bfd_udp_get_tos_reply", vapi_msg_id_bfd_udp_get_tos_reply);
}

static inline void vapi_set_vapi_msg_bfd_udp_get_tos_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_bfd_udp_get_tos_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_bfd_udp_get_tos_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_bfd_udp_get_tos
#define defined_vapi_msg_bfd_udp_get_tos
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_bfd_udp_get_tos;

static inline void vapi_msg_bfd_udp_get_tos_hton(vapi_msg_bfd_udp_get_tos *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_get_tos'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_bfd_udp_get_tos_ntoh(vapi_msg_bfd_udp_get_tos *msg)
{
  VAPI_DBG("Swapping `vapi_msg_bfd_udp_get_tos'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_bfd_udp_get_tos_msg_size(vapi_msg_bfd_udp_get_tos *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_bfd_udp_get_tos_msg_size(vapi_msg_bfd_udp_get_tos *msg, uword buf_size)
{
  if (sizeof(vapi_msg_bfd_udp_get_tos) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_get_tos' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_bfd_udp_get_tos));
      return -1;
    }
  if (vapi_calc_bfd_udp_get_tos_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'bfd_udp_get_tos' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_bfd_udp_get_tos_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_bfd_udp_get_tos* vapi_alloc_bfd_udp_get_tos(struct vapi_ctx_s *ctx)
{
  vapi_msg_bfd_udp_get_tos *msg = NULL;
  const size_t size = sizeof(vapi_msg_bfd_udp_get_tos);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_bfd_udp_get_tos*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_bfd_udp_get_tos);

  return msg;
}

static inline vapi_error_e vapi_bfd_udp_get_tos(struct vapi_ctx_s *ctx,
  vapi_msg_bfd_udp_get_tos *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_bfd_udp_get_tos_reply *reply),
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
  vapi_msg_bfd_udp_get_tos_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_bfd_udp_get_tos_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_bfd_udp_get_tos_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_bfd_udp_get_tos()
{
  static const char name[] = "bfd_udp_get_tos";
  static const char name_with_crc[] = "bfd_udp_get_tos_51077d14";
  static vapi_message_desc_t __vapi_metadata_bfd_udp_get_tos = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_bfd_udp_get_tos_msg_size,
    (generic_swap_fn_t)vapi_msg_bfd_udp_get_tos_hton,
    (generic_swap_fn_t)vapi_msg_bfd_udp_get_tos_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_bfd_udp_get_tos = vapi_register_msg(&__vapi_metadata_bfd_udp_get_tos);
  VAPI_DBG("Assigned msg id %d to bfd_udp_get_tos", vapi_msg_id_bfd_udp_get_tos);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
