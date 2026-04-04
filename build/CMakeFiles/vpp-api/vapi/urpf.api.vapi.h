#ifndef __included_urpf_api_json
#define __included_urpf_api_json

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

extern vapi_msg_id_t vapi_msg_id_urpf_update;
extern vapi_msg_id_t vapi_msg_id_urpf_update_reply;
extern vapi_msg_id_t vapi_msg_id_urpf_update_v2;
extern vapi_msg_id_t vapi_msg_id_urpf_update_v2_reply;
extern vapi_msg_id_t vapi_msg_id_urpf_interface_dump;
extern vapi_msg_id_t vapi_msg_id_urpf_interface_details;

#define DEFINE_VAPI_MSG_IDS_URPF_API_JSON\
  vapi_msg_id_t vapi_msg_id_urpf_update;\
  vapi_msg_id_t vapi_msg_id_urpf_update_reply;\
  vapi_msg_id_t vapi_msg_id_urpf_update_v2;\
  vapi_msg_id_t vapi_msg_id_urpf_update_v2_reply;\
  vapi_msg_id_t vapi_msg_id_urpf_interface_dump;\
  vapi_msg_id_t vapi_msg_id_urpf_interface_details;


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

#ifndef defined_vapi_enum_fib_path_nh_proto
#define defined_vapi_enum_fib_path_nh_proto
typedef enum {
  FIB_API_PATH_NH_PROTO_IP4 = 0,
  FIB_API_PATH_NH_PROTO_IP6 = 1,
  FIB_API_PATH_NH_PROTO_MPLS = 2,
  FIB_API_PATH_NH_PROTO_ETHERNET = 3,
  FIB_API_PATH_NH_PROTO_BIER = 4,
}  vapi_enum_fib_path_nh_proto;

#endif

#ifndef defined_vapi_enum_fib_path_flags
#define defined_vapi_enum_fib_path_flags
typedef enum {
  FIB_API_PATH_FLAG_NONE = 0,
  FIB_API_PATH_FLAG_RESOLVE_VIA_ATTACHED = 1,
  FIB_API_PATH_FLAG_RESOLVE_VIA_HOST = 2,
  FIB_API_PATH_FLAG_POP_PW_CW = 4,
}  vapi_enum_fib_path_flags;

#endif

#ifndef defined_vapi_enum_fib_path_type
#define defined_vapi_enum_fib_path_type
typedef enum {
  FIB_API_PATH_TYPE_NORMAL = 0,
  FIB_API_PATH_TYPE_LOCAL = 1,
  FIB_API_PATH_TYPE_DROP = 2,
  FIB_API_PATH_TYPE_UDP_ENCAP = 3,
  FIB_API_PATH_TYPE_BIER_IMP = 4,
  FIB_API_PATH_TYPE_ICMP_UNREACH = 5,
  FIB_API_PATH_TYPE_ICMP_PROHIBIT = 6,
  FIB_API_PATH_TYPE_SOURCE_LOOKUP = 7,
  FIB_API_PATH_TYPE_DVR = 8,
  FIB_API_PATH_TYPE_INTERFACE_RX = 9,
  FIB_API_PATH_TYPE_CLASSIFY = 10,
}  vapi_enum_fib_path_type;

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

#ifndef defined_vapi_enum_urpf_mode
#define defined_vapi_enum_urpf_mode
typedef enum {
  URPF_API_MODE_OFF = 0,
  URPF_API_MODE_LOOSE = 1,
  URPF_API_MODE_STRICT = 2,
} __attribute__((packed)) vapi_enum_urpf_mode;

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

#ifndef defined_vapi_type_fib_mpls_label
#define defined_vapi_type_fib_mpls_label
typedef struct __attribute__((__packed__)) {
  u8 is_uniform;
  u32 label;
  u8 ttl;
  u8 exp;
} vapi_type_fib_mpls_label;

static inline void vapi_type_fib_mpls_label_hton(vapi_type_fib_mpls_label *msg)
{
  msg->label = htobe32(msg->label);
}

static inline void vapi_type_fib_mpls_label_ntoh(vapi_type_fib_mpls_label *msg)
{
  msg->label = be32toh(msg->label);
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

#ifndef defined_vapi_type_fib_path_nh
#define defined_vapi_type_fib_path_nh
typedef struct __attribute__((__packed__)) {
  vapi_union_address_union address;
  u32 via_label;
  u32 obj_id;
  u32 classify_table_index;
} vapi_type_fib_path_nh;

static inline void vapi_type_fib_path_nh_hton(vapi_type_fib_path_nh *msg)
{
  msg->via_label = htobe32(msg->via_label);
  msg->obj_id = htobe32(msg->obj_id);
  msg->classify_table_index = htobe32(msg->classify_table_index);
}

static inline void vapi_type_fib_path_nh_ntoh(vapi_type_fib_path_nh *msg)
{
  msg->via_label = be32toh(msg->via_label);
  msg->obj_id = be32toh(msg->obj_id);
  msg->classify_table_index = be32toh(msg->classify_table_index);
}
#endif

#ifndef defined_vapi_type_fib_path
#define defined_vapi_type_fib_path
typedef struct __attribute__((__packed__)) {
  u32 sw_if_index;
  u32 table_id;
  u32 rpf_id;
  u8 weight;
  u8 preference;
  vapi_enum_fib_path_type type;
  vapi_enum_fib_path_flags flags;
  vapi_enum_fib_path_nh_proto proto;
  vapi_type_fib_path_nh nh;
  u8 n_labels;
  vapi_type_fib_mpls_label label_stack[16];
} vapi_type_fib_path;

static inline void vapi_type_fib_path_hton(vapi_type_fib_path *msg)
{
  msg->sw_if_index = htobe32(msg->sw_if_index);
  msg->table_id = htobe32(msg->table_id);
  msg->rpf_id = htobe32(msg->rpf_id);
  msg->type = (vapi_enum_fib_path_type)htobe32(msg->type);
  msg->flags = (vapi_enum_fib_path_flags)htobe32(msg->flags);
  msg->proto = (vapi_enum_fib_path_nh_proto)htobe32(msg->proto);
  vapi_type_fib_path_nh_hton(&msg->nh);
  do { unsigned i; for (i = 0; i < 16; ++i) { vapi_type_fib_mpls_label_hton(&msg->label_stack[i]); } } while(0);
}

static inline void vapi_type_fib_path_ntoh(vapi_type_fib_path *msg)
{
  msg->sw_if_index = be32toh(msg->sw_if_index);
  msg->table_id = be32toh(msg->table_id);
  msg->rpf_id = be32toh(msg->rpf_id);
  msg->type = (vapi_enum_fib_path_type)be32toh(msg->type);
  msg->flags = (vapi_enum_fib_path_flags)be32toh(msg->flags);
  msg->proto = (vapi_enum_fib_path_nh_proto)be32toh(msg->proto);
  vapi_type_fib_path_nh_ntoh(&msg->nh);
  do { unsigned i; for (i = 0; i < 16; ++i) { vapi_type_fib_mpls_label_ntoh(&msg->label_stack[i]); } } while(0);
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

#ifndef defined_vapi_msg_urpf_update_reply
#define defined_vapi_msg_urpf_update_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_urpf_update_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_urpf_update_reply payload;
} vapi_msg_urpf_update_reply;

static inline void vapi_msg_urpf_update_reply_payload_hton(vapi_payload_urpf_update_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_urpf_update_reply_payload_ntoh(vapi_payload_urpf_update_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_urpf_update_reply_hton(vapi_msg_urpf_update_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_urpf_update_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_urpf_update_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_urpf_update_reply_ntoh(vapi_msg_urpf_update_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_urpf_update_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_urpf_update_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_urpf_update_reply_msg_size(vapi_msg_urpf_update_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_urpf_update_reply_msg_size(vapi_msg_urpf_update_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_urpf_update_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'urpf_update_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_urpf_update_reply));
      return -1;
    }
  if (vapi_calc_urpf_update_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'urpf_update_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_urpf_update_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_urpf_update_reply()
{
  static const char name[] = "urpf_update_reply";
  static const char name_with_crc[] = "urpf_update_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_urpf_update_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_urpf_update_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_urpf_update_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_urpf_update_reply_hton,
    (generic_swap_fn_t)vapi_msg_urpf_update_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_urpf_update_reply = vapi_register_msg(&__vapi_metadata_urpf_update_reply);
  VAPI_DBG("Assigned msg id %d to urpf_update_reply", vapi_msg_id_urpf_update_reply);
}

static inline void vapi_set_vapi_msg_urpf_update_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_urpf_update_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_urpf_update_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_urpf_update
#define defined_vapi_msg_urpf_update
typedef struct __attribute__ ((__packed__)) {
  bool is_input;
  vapi_enum_urpf_mode mode;
  vapi_enum_address_family af;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_urpf_update;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_urpf_update payload;
} vapi_msg_urpf_update;

static inline void vapi_msg_urpf_update_payload_hton(vapi_payload_urpf_update *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_urpf_update_payload_ntoh(vapi_payload_urpf_update *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_urpf_update_hton(vapi_msg_urpf_update *msg)
{
  VAPI_DBG("Swapping `vapi_msg_urpf_update'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_urpf_update_payload_hton(&msg->payload);
}

static inline void vapi_msg_urpf_update_ntoh(vapi_msg_urpf_update *msg)
{
  VAPI_DBG("Swapping `vapi_msg_urpf_update'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_urpf_update_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_urpf_update_msg_size(vapi_msg_urpf_update *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_urpf_update_msg_size(vapi_msg_urpf_update *msg, uword buf_size)
{
  if (sizeof(vapi_msg_urpf_update) > buf_size)
    {
      VAPI_ERR("Truncated 'urpf_update' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_urpf_update));
      return -1;
    }
  if (vapi_calc_urpf_update_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'urpf_update' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_urpf_update_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_urpf_update* vapi_alloc_urpf_update(struct vapi_ctx_s *ctx)
{
  vapi_msg_urpf_update *msg = NULL;
  const size_t size = sizeof(vapi_msg_urpf_update);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_urpf_update*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_urpf_update);

  return msg;
}

static inline vapi_error_e vapi_urpf_update(struct vapi_ctx_s *ctx,
  vapi_msg_urpf_update *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_urpf_update_reply *reply),
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
  vapi_msg_urpf_update_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_urpf_update_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_urpf_update_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_urpf_update()
{
  static const char name[] = "urpf_update";
  static const char name_with_crc[] = "urpf_update_cc274cd1";
  static vapi_message_desc_t __vapi_metadata_urpf_update = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_urpf_update, payload),
    (verify_msg_size_fn_t)vapi_verify_urpf_update_msg_size,
    (generic_swap_fn_t)vapi_msg_urpf_update_hton,
    (generic_swap_fn_t)vapi_msg_urpf_update_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_urpf_update = vapi_register_msg(&__vapi_metadata_urpf_update);
  VAPI_DBG("Assigned msg id %d to urpf_update", vapi_msg_id_urpf_update);
}
#endif

#ifndef defined_vapi_msg_urpf_update_v2_reply
#define defined_vapi_msg_urpf_update_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_urpf_update_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_urpf_update_v2_reply payload;
} vapi_msg_urpf_update_v2_reply;

static inline void vapi_msg_urpf_update_v2_reply_payload_hton(vapi_payload_urpf_update_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_urpf_update_v2_reply_payload_ntoh(vapi_payload_urpf_update_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_urpf_update_v2_reply_hton(vapi_msg_urpf_update_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_urpf_update_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_urpf_update_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_urpf_update_v2_reply_ntoh(vapi_msg_urpf_update_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_urpf_update_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_urpf_update_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_urpf_update_v2_reply_msg_size(vapi_msg_urpf_update_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_urpf_update_v2_reply_msg_size(vapi_msg_urpf_update_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_urpf_update_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'urpf_update_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_urpf_update_v2_reply));
      return -1;
    }
  if (vapi_calc_urpf_update_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'urpf_update_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_urpf_update_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_urpf_update_v2_reply()
{
  static const char name[] = "urpf_update_v2_reply";
  static const char name_with_crc[] = "urpf_update_v2_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_urpf_update_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_urpf_update_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_urpf_update_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_urpf_update_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_urpf_update_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_urpf_update_v2_reply = vapi_register_msg(&__vapi_metadata_urpf_update_v2_reply);
  VAPI_DBG("Assigned msg id %d to urpf_update_v2_reply", vapi_msg_id_urpf_update_v2_reply);
}

static inline void vapi_set_vapi_msg_urpf_update_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_urpf_update_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_urpf_update_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_urpf_update_v2
#define defined_vapi_msg_urpf_update_v2
typedef struct __attribute__ ((__packed__)) {
  bool is_input;
  vapi_enum_urpf_mode mode;
  vapi_enum_address_family af;
  vapi_type_interface_index sw_if_index;
  u32 table_id; 
} vapi_payload_urpf_update_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_urpf_update_v2 payload;
} vapi_msg_urpf_update_v2;

static inline void vapi_msg_urpf_update_v2_payload_hton(vapi_payload_urpf_update_v2 *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->table_id = htobe32(payload->table_id);
}

static inline void vapi_msg_urpf_update_v2_payload_ntoh(vapi_payload_urpf_update_v2 *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->table_id = be32toh(payload->table_id);
}

static inline void vapi_msg_urpf_update_v2_hton(vapi_msg_urpf_update_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_urpf_update_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_urpf_update_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_urpf_update_v2_ntoh(vapi_msg_urpf_update_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_urpf_update_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_urpf_update_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_urpf_update_v2_msg_size(vapi_msg_urpf_update_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_urpf_update_v2_msg_size(vapi_msg_urpf_update_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_urpf_update_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'urpf_update_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_urpf_update_v2));
      return -1;
    }
  if (vapi_calc_urpf_update_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'urpf_update_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_urpf_update_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_urpf_update_v2* vapi_alloc_urpf_update_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_urpf_update_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_urpf_update_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_urpf_update_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_urpf_update_v2);

  return msg;
}

static inline vapi_error_e vapi_urpf_update_v2(struct vapi_ctx_s *ctx,
  vapi_msg_urpf_update_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_urpf_update_v2_reply *reply),
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
  vapi_msg_urpf_update_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_urpf_update_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_urpf_update_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_urpf_update_v2()
{
  static const char name[] = "urpf_update_v2";
  static const char name_with_crc[] = "urpf_update_v2_b873d028";
  static vapi_message_desc_t __vapi_metadata_urpf_update_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_urpf_update_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_urpf_update_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_urpf_update_v2_hton,
    (generic_swap_fn_t)vapi_msg_urpf_update_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_urpf_update_v2 = vapi_register_msg(&__vapi_metadata_urpf_update_v2);
  VAPI_DBG("Assigned msg id %d to urpf_update_v2", vapi_msg_id_urpf_update_v2);
}
#endif

#ifndef defined_vapi_msg_urpf_interface_details
#define defined_vapi_msg_urpf_interface_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  bool is_input;
  vapi_enum_urpf_mode mode;
  vapi_enum_address_family af;
  u32 table_id; 
} vapi_payload_urpf_interface_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_urpf_interface_details payload;
} vapi_msg_urpf_interface_details;

static inline void vapi_msg_urpf_interface_details_payload_hton(vapi_payload_urpf_interface_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->table_id = htobe32(payload->table_id);
}

static inline void vapi_msg_urpf_interface_details_payload_ntoh(vapi_payload_urpf_interface_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->table_id = be32toh(payload->table_id);
}

static inline void vapi_msg_urpf_interface_details_hton(vapi_msg_urpf_interface_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_urpf_interface_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_urpf_interface_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_urpf_interface_details_ntoh(vapi_msg_urpf_interface_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_urpf_interface_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_urpf_interface_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_urpf_interface_details_msg_size(vapi_msg_urpf_interface_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_urpf_interface_details_msg_size(vapi_msg_urpf_interface_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_urpf_interface_details) > buf_size)
    {
      VAPI_ERR("Truncated 'urpf_interface_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_urpf_interface_details));
      return -1;
    }
  if (vapi_calc_urpf_interface_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'urpf_interface_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_urpf_interface_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_urpf_interface_details()
{
  static const char name[] = "urpf_interface_details";
  static const char name_with_crc[] = "urpf_interface_details_f94b5374";
  static vapi_message_desc_t __vapi_metadata_urpf_interface_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_urpf_interface_details, payload),
    (verify_msg_size_fn_t)vapi_verify_urpf_interface_details_msg_size,
    (generic_swap_fn_t)vapi_msg_urpf_interface_details_hton,
    (generic_swap_fn_t)vapi_msg_urpf_interface_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_urpf_interface_details = vapi_register_msg(&__vapi_metadata_urpf_interface_details);
  VAPI_DBG("Assigned msg id %d to urpf_interface_details", vapi_msg_id_urpf_interface_details);
}

static inline void vapi_set_vapi_msg_urpf_interface_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_urpf_interface_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_urpf_interface_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_urpf_interface_dump
#define defined_vapi_msg_urpf_interface_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_urpf_interface_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_urpf_interface_dump payload;
} vapi_msg_urpf_interface_dump;

static inline void vapi_msg_urpf_interface_dump_payload_hton(vapi_payload_urpf_interface_dump *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_urpf_interface_dump_payload_ntoh(vapi_payload_urpf_interface_dump *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_urpf_interface_dump_hton(vapi_msg_urpf_interface_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_urpf_interface_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_urpf_interface_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_urpf_interface_dump_ntoh(vapi_msg_urpf_interface_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_urpf_interface_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_urpf_interface_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_urpf_interface_dump_msg_size(vapi_msg_urpf_interface_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_urpf_interface_dump_msg_size(vapi_msg_urpf_interface_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_urpf_interface_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'urpf_interface_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_urpf_interface_dump));
      return -1;
    }
  if (vapi_calc_urpf_interface_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'urpf_interface_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_urpf_interface_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_urpf_interface_dump* vapi_alloc_urpf_interface_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_urpf_interface_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_urpf_interface_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_urpf_interface_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_urpf_interface_dump);

  return msg;
}

static inline vapi_error_e vapi_urpf_interface_dump(struct vapi_ctx_s *ctx,
  vapi_msg_urpf_interface_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_urpf_interface_details *reply),
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
  vapi_msg_urpf_interface_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_urpf_interface_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_urpf_interface_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_urpf_interface_dump()
{
  static const char name[] = "urpf_interface_dump";
  static const char name_with_crc[] = "urpf_interface_dump_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_urpf_interface_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_urpf_interface_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_urpf_interface_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_urpf_interface_dump_hton,
    (generic_swap_fn_t)vapi_msg_urpf_interface_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_urpf_interface_dump = vapi_register_msg(&__vapi_metadata_urpf_interface_dump);
  VAPI_DBG("Assigned msg id %d to urpf_interface_dump", vapi_msg_id_urpf_interface_dump);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
