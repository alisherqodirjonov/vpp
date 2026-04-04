#ifndef __included_gtpu_api_json
#define __included_gtpu_api_json

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

extern vapi_msg_id_t vapi_msg_id_gtpu_add_del_tunnel;
extern vapi_msg_id_t vapi_msg_id_gtpu_add_del_tunnel_reply;
extern vapi_msg_id_t vapi_msg_id_gtpu_add_del_tunnel_v2;
extern vapi_msg_id_t vapi_msg_id_gtpu_add_del_tunnel_v2_reply;
extern vapi_msg_id_t vapi_msg_id_gtpu_tunnel_update_tteid;
extern vapi_msg_id_t vapi_msg_id_gtpu_tunnel_update_tteid_reply;
extern vapi_msg_id_t vapi_msg_id_gtpu_tunnel_dump;
extern vapi_msg_id_t vapi_msg_id_gtpu_tunnel_details;
extern vapi_msg_id_t vapi_msg_id_gtpu_tunnel_v2_dump;
extern vapi_msg_id_t vapi_msg_id_gtpu_tunnel_v2_details;
extern vapi_msg_id_t vapi_msg_id_sw_interface_set_gtpu_bypass;
extern vapi_msg_id_t vapi_msg_id_sw_interface_set_gtpu_bypass_reply;
extern vapi_msg_id_t vapi_msg_id_gtpu_offload_rx;
extern vapi_msg_id_t vapi_msg_id_gtpu_offload_rx_reply;
extern vapi_msg_id_t vapi_msg_id_gtpu_add_del_forward;
extern vapi_msg_id_t vapi_msg_id_gtpu_add_del_forward_reply;
extern vapi_msg_id_t vapi_msg_id_gtpu_get_transfer_counts;
extern vapi_msg_id_t vapi_msg_id_gtpu_get_transfer_counts_reply;

#define DEFINE_VAPI_MSG_IDS_GTPU_API_JSON\
  vapi_msg_id_t vapi_msg_id_gtpu_add_del_tunnel;\
  vapi_msg_id_t vapi_msg_id_gtpu_add_del_tunnel_reply;\
  vapi_msg_id_t vapi_msg_id_gtpu_add_del_tunnel_v2;\
  vapi_msg_id_t vapi_msg_id_gtpu_add_del_tunnel_v2_reply;\
  vapi_msg_id_t vapi_msg_id_gtpu_tunnel_update_tteid;\
  vapi_msg_id_t vapi_msg_id_gtpu_tunnel_update_tteid_reply;\
  vapi_msg_id_t vapi_msg_id_gtpu_tunnel_dump;\
  vapi_msg_id_t vapi_msg_id_gtpu_tunnel_details;\
  vapi_msg_id_t vapi_msg_id_gtpu_tunnel_v2_dump;\
  vapi_msg_id_t vapi_msg_id_gtpu_tunnel_v2_details;\
  vapi_msg_id_t vapi_msg_id_sw_interface_set_gtpu_bypass;\
  vapi_msg_id_t vapi_msg_id_sw_interface_set_gtpu_bypass_reply;\
  vapi_msg_id_t vapi_msg_id_gtpu_offload_rx;\
  vapi_msg_id_t vapi_msg_id_gtpu_offload_rx_reply;\
  vapi_msg_id_t vapi_msg_id_gtpu_add_del_forward;\
  vapi_msg_id_t vapi_msg_id_gtpu_add_del_forward_reply;\
  vapi_msg_id_t vapi_msg_id_gtpu_get_transfer_counts;\
  vapi_msg_id_t vapi_msg_id_gtpu_get_transfer_counts_reply;


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

#ifndef defined_vapi_enum_gtpu_forwarding_type
#define defined_vapi_enum_gtpu_forwarding_type
typedef enum {
  GTPU_API_FORWARDING_NONE = 0,
  GTPU_API_FORWARDING_BAD_HEADER = 1,
  GTPU_API_FORWARDING_UNKNOWN_TEID = 2,
  GTPU_API_FORWARDING_UNKNOWN_TYPE = 4,
}  vapi_enum_gtpu_forwarding_type;

#endif

#ifndef defined_vapi_enum_gtpu_decap_next_type
#define defined_vapi_enum_gtpu_decap_next_type
typedef enum {
  GTPU_API_DECAP_NEXT_DROP = 0,
  GTPU_API_DECAP_NEXT_L2 = 1,
  GTPU_API_DECAP_NEXT_IP4 = 2,
  GTPU_API_DECAP_NEXT_IP6 = 3,
}  vapi_enum_gtpu_decap_next_type;

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

#ifndef defined_vapi_type_sw_if_counters
#define defined_vapi_type_sw_if_counters
typedef struct __attribute__((__packed__)) {
  u64 packets_rx;
  u64 packets_tx;
  u64 bytes_rx;
  u64 bytes_tx;
} vapi_type_sw_if_counters;

static inline void vapi_type_sw_if_counters_hton(vapi_type_sw_if_counters *msg)
{
  msg->packets_rx = htobe64(msg->packets_rx);
  msg->packets_tx = htobe64(msg->packets_tx);
  msg->bytes_rx = htobe64(msg->bytes_rx);
  msg->bytes_tx = htobe64(msg->bytes_tx);
}

static inline void vapi_type_sw_if_counters_ntoh(vapi_type_sw_if_counters *msg)
{
  msg->packets_rx = be64toh(msg->packets_rx);
  msg->packets_tx = be64toh(msg->packets_tx);
  msg->bytes_rx = be64toh(msg->bytes_rx);
  msg->bytes_tx = be64toh(msg->bytes_tx);
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

#ifndef defined_vapi_type_tunnel_metrics
#define defined_vapi_type_tunnel_metrics
typedef struct __attribute__((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u32 reserved;
  vapi_type_sw_if_counters counters;
} vapi_type_tunnel_metrics;

static inline void vapi_type_tunnel_metrics_hton(vapi_type_tunnel_metrics *msg)
{
  msg->sw_if_index = htobe32(msg->sw_if_index);
  msg->reserved = htobe32(msg->reserved);
  vapi_type_sw_if_counters_hton(&msg->counters);
}

static inline void vapi_type_tunnel_metrics_ntoh(vapi_type_tunnel_metrics *msg)
{
  msg->sw_if_index = be32toh(msg->sw_if_index);
  msg->reserved = be32toh(msg->reserved);
  vapi_type_sw_if_counters_ntoh(&msg->counters);
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

#ifndef defined_vapi_msg_gtpu_add_del_tunnel_reply
#define defined_vapi_msg_gtpu_add_del_tunnel_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_gtpu_add_del_tunnel_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_gtpu_add_del_tunnel_reply payload;
} vapi_msg_gtpu_add_del_tunnel_reply;

static inline void vapi_msg_gtpu_add_del_tunnel_reply_payload_hton(vapi_payload_gtpu_add_del_tunnel_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_gtpu_add_del_tunnel_reply_payload_ntoh(vapi_payload_gtpu_add_del_tunnel_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_gtpu_add_del_tunnel_reply_hton(vapi_msg_gtpu_add_del_tunnel_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_add_del_tunnel_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_gtpu_add_del_tunnel_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_gtpu_add_del_tunnel_reply_ntoh(vapi_msg_gtpu_add_del_tunnel_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_add_del_tunnel_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_gtpu_add_del_tunnel_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gtpu_add_del_tunnel_reply_msg_size(vapi_msg_gtpu_add_del_tunnel_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gtpu_add_del_tunnel_reply_msg_size(vapi_msg_gtpu_add_del_tunnel_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gtpu_add_del_tunnel_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_add_del_tunnel_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gtpu_add_del_tunnel_reply));
      return -1;
    }
  if (vapi_calc_gtpu_add_del_tunnel_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_add_del_tunnel_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gtpu_add_del_tunnel_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_gtpu_add_del_tunnel_reply()
{
  static const char name[] = "gtpu_add_del_tunnel_reply";
  static const char name_with_crc[] = "gtpu_add_del_tunnel_reply_5383d31f";
  static vapi_message_desc_t __vapi_metadata_gtpu_add_del_tunnel_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_gtpu_add_del_tunnel_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_gtpu_add_del_tunnel_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_gtpu_add_del_tunnel_reply_hton,
    (generic_swap_fn_t)vapi_msg_gtpu_add_del_tunnel_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gtpu_add_del_tunnel_reply = vapi_register_msg(&__vapi_metadata_gtpu_add_del_tunnel_reply);
  VAPI_DBG("Assigned msg id %d to gtpu_add_del_tunnel_reply", vapi_msg_id_gtpu_add_del_tunnel_reply);
}

static inline void vapi_set_vapi_msg_gtpu_add_del_tunnel_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_gtpu_add_del_tunnel_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_gtpu_add_del_tunnel_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_gtpu_add_del_tunnel
#define defined_vapi_msg_gtpu_add_del_tunnel
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_address src_address;
  vapi_type_address dst_address;
  vapi_type_interface_index mcast_sw_if_index;
  u32 encap_vrf_id;
  u32 decap_next_index;
  u32 teid;
  u32 tteid; 
} vapi_payload_gtpu_add_del_tunnel;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_gtpu_add_del_tunnel payload;
} vapi_msg_gtpu_add_del_tunnel;

static inline void vapi_msg_gtpu_add_del_tunnel_payload_hton(vapi_payload_gtpu_add_del_tunnel *payload)
{
  payload->mcast_sw_if_index = htobe32(payload->mcast_sw_if_index);
  payload->encap_vrf_id = htobe32(payload->encap_vrf_id);
  payload->decap_next_index = htobe32(payload->decap_next_index);
  payload->teid = htobe32(payload->teid);
  payload->tteid = htobe32(payload->tteid);
}

static inline void vapi_msg_gtpu_add_del_tunnel_payload_ntoh(vapi_payload_gtpu_add_del_tunnel *payload)
{
  payload->mcast_sw_if_index = be32toh(payload->mcast_sw_if_index);
  payload->encap_vrf_id = be32toh(payload->encap_vrf_id);
  payload->decap_next_index = be32toh(payload->decap_next_index);
  payload->teid = be32toh(payload->teid);
  payload->tteid = be32toh(payload->tteid);
}

static inline void vapi_msg_gtpu_add_del_tunnel_hton(vapi_msg_gtpu_add_del_tunnel *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_add_del_tunnel'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_gtpu_add_del_tunnel_payload_hton(&msg->payload);
}

static inline void vapi_msg_gtpu_add_del_tunnel_ntoh(vapi_msg_gtpu_add_del_tunnel *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_add_del_tunnel'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_gtpu_add_del_tunnel_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gtpu_add_del_tunnel_msg_size(vapi_msg_gtpu_add_del_tunnel *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gtpu_add_del_tunnel_msg_size(vapi_msg_gtpu_add_del_tunnel *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gtpu_add_del_tunnel) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_add_del_tunnel' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gtpu_add_del_tunnel));
      return -1;
    }
  if (vapi_calc_gtpu_add_del_tunnel_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_add_del_tunnel' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gtpu_add_del_tunnel_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_gtpu_add_del_tunnel* vapi_alloc_gtpu_add_del_tunnel(struct vapi_ctx_s *ctx)
{
  vapi_msg_gtpu_add_del_tunnel *msg = NULL;
  const size_t size = sizeof(vapi_msg_gtpu_add_del_tunnel);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_gtpu_add_del_tunnel*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_gtpu_add_del_tunnel);

  return msg;
}

static inline vapi_error_e vapi_gtpu_add_del_tunnel(struct vapi_ctx_s *ctx,
  vapi_msg_gtpu_add_del_tunnel *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_gtpu_add_del_tunnel_reply *reply),
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
  vapi_msg_gtpu_add_del_tunnel_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_gtpu_add_del_tunnel_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_gtpu_add_del_tunnel_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_gtpu_add_del_tunnel()
{
  static const char name[] = "gtpu_add_del_tunnel";
  static const char name_with_crc[] = "gtpu_add_del_tunnel_ca983a2b";
  static vapi_message_desc_t __vapi_metadata_gtpu_add_del_tunnel = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_gtpu_add_del_tunnel, payload),
    (verify_msg_size_fn_t)vapi_verify_gtpu_add_del_tunnel_msg_size,
    (generic_swap_fn_t)vapi_msg_gtpu_add_del_tunnel_hton,
    (generic_swap_fn_t)vapi_msg_gtpu_add_del_tunnel_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gtpu_add_del_tunnel = vapi_register_msg(&__vapi_metadata_gtpu_add_del_tunnel);
  VAPI_DBG("Assigned msg id %d to gtpu_add_del_tunnel", vapi_msg_id_gtpu_add_del_tunnel);
}
#endif

#ifndef defined_vapi_msg_gtpu_add_del_tunnel_v2_reply
#define defined_vapi_msg_gtpu_add_del_tunnel_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_interface_index sw_if_index;
  vapi_type_sw_if_counters counters; 
} vapi_payload_gtpu_add_del_tunnel_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_gtpu_add_del_tunnel_v2_reply payload;
} vapi_msg_gtpu_add_del_tunnel_v2_reply;

static inline void vapi_msg_gtpu_add_del_tunnel_v2_reply_payload_hton(vapi_payload_gtpu_add_del_tunnel_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->sw_if_index = htobe32(payload->sw_if_index);
  vapi_type_sw_if_counters_hton(&payload->counters);
}

static inline void vapi_msg_gtpu_add_del_tunnel_v2_reply_payload_ntoh(vapi_payload_gtpu_add_del_tunnel_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->sw_if_index = be32toh(payload->sw_if_index);
  vapi_type_sw_if_counters_ntoh(&payload->counters);
}

static inline void vapi_msg_gtpu_add_del_tunnel_v2_reply_hton(vapi_msg_gtpu_add_del_tunnel_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_add_del_tunnel_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_gtpu_add_del_tunnel_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_gtpu_add_del_tunnel_v2_reply_ntoh(vapi_msg_gtpu_add_del_tunnel_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_add_del_tunnel_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_gtpu_add_del_tunnel_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gtpu_add_del_tunnel_v2_reply_msg_size(vapi_msg_gtpu_add_del_tunnel_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gtpu_add_del_tunnel_v2_reply_msg_size(vapi_msg_gtpu_add_del_tunnel_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gtpu_add_del_tunnel_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_add_del_tunnel_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gtpu_add_del_tunnel_v2_reply));
      return -1;
    }
  if (vapi_calc_gtpu_add_del_tunnel_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_add_del_tunnel_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gtpu_add_del_tunnel_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_gtpu_add_del_tunnel_v2_reply()
{
  static const char name[] = "gtpu_add_del_tunnel_v2_reply";
  static const char name_with_crc[] = "gtpu_add_del_tunnel_v2_reply_62b41304";
  static vapi_message_desc_t __vapi_metadata_gtpu_add_del_tunnel_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_gtpu_add_del_tunnel_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_gtpu_add_del_tunnel_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_gtpu_add_del_tunnel_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_gtpu_add_del_tunnel_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gtpu_add_del_tunnel_v2_reply = vapi_register_msg(&__vapi_metadata_gtpu_add_del_tunnel_v2_reply);
  VAPI_DBG("Assigned msg id %d to gtpu_add_del_tunnel_v2_reply", vapi_msg_id_gtpu_add_del_tunnel_v2_reply);
}

static inline void vapi_set_vapi_msg_gtpu_add_del_tunnel_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_gtpu_add_del_tunnel_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_gtpu_add_del_tunnel_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_gtpu_add_del_tunnel_v2
#define defined_vapi_msg_gtpu_add_del_tunnel_v2
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_address src_address;
  vapi_type_address dst_address;
  vapi_type_interface_index mcast_sw_if_index;
  u32 encap_vrf_id;
  vapi_enum_gtpu_decap_next_type decap_next_index;
  u32 teid;
  u32 tteid;
  bool pdu_extension;
  u8 qfi; 
} vapi_payload_gtpu_add_del_tunnel_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_gtpu_add_del_tunnel_v2 payload;
} vapi_msg_gtpu_add_del_tunnel_v2;

static inline void vapi_msg_gtpu_add_del_tunnel_v2_payload_hton(vapi_payload_gtpu_add_del_tunnel_v2 *payload)
{
  payload->mcast_sw_if_index = htobe32(payload->mcast_sw_if_index);
  payload->encap_vrf_id = htobe32(payload->encap_vrf_id);
  payload->decap_next_index = (vapi_enum_gtpu_decap_next_type)htobe32(payload->decap_next_index);
  payload->teid = htobe32(payload->teid);
  payload->tteid = htobe32(payload->tteid);
}

static inline void vapi_msg_gtpu_add_del_tunnel_v2_payload_ntoh(vapi_payload_gtpu_add_del_tunnel_v2 *payload)
{
  payload->mcast_sw_if_index = be32toh(payload->mcast_sw_if_index);
  payload->encap_vrf_id = be32toh(payload->encap_vrf_id);
  payload->decap_next_index = (vapi_enum_gtpu_decap_next_type)be32toh(payload->decap_next_index);
  payload->teid = be32toh(payload->teid);
  payload->tteid = be32toh(payload->tteid);
}

static inline void vapi_msg_gtpu_add_del_tunnel_v2_hton(vapi_msg_gtpu_add_del_tunnel_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_add_del_tunnel_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_gtpu_add_del_tunnel_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_gtpu_add_del_tunnel_v2_ntoh(vapi_msg_gtpu_add_del_tunnel_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_add_del_tunnel_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_gtpu_add_del_tunnel_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gtpu_add_del_tunnel_v2_msg_size(vapi_msg_gtpu_add_del_tunnel_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gtpu_add_del_tunnel_v2_msg_size(vapi_msg_gtpu_add_del_tunnel_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gtpu_add_del_tunnel_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_add_del_tunnel_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gtpu_add_del_tunnel_v2));
      return -1;
    }
  if (vapi_calc_gtpu_add_del_tunnel_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_add_del_tunnel_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gtpu_add_del_tunnel_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_gtpu_add_del_tunnel_v2* vapi_alloc_gtpu_add_del_tunnel_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_gtpu_add_del_tunnel_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_gtpu_add_del_tunnel_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_gtpu_add_del_tunnel_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_gtpu_add_del_tunnel_v2);

  return msg;
}

static inline vapi_error_e vapi_gtpu_add_del_tunnel_v2(struct vapi_ctx_s *ctx,
  vapi_msg_gtpu_add_del_tunnel_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_gtpu_add_del_tunnel_v2_reply *reply),
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
  vapi_msg_gtpu_add_del_tunnel_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_gtpu_add_del_tunnel_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_gtpu_add_del_tunnel_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_gtpu_add_del_tunnel_v2()
{
  static const char name[] = "gtpu_add_del_tunnel_v2";
  static const char name_with_crc[] = "gtpu_add_del_tunnel_v2_a0c30713";
  static vapi_message_desc_t __vapi_metadata_gtpu_add_del_tunnel_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_gtpu_add_del_tunnel_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_gtpu_add_del_tunnel_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_gtpu_add_del_tunnel_v2_hton,
    (generic_swap_fn_t)vapi_msg_gtpu_add_del_tunnel_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gtpu_add_del_tunnel_v2 = vapi_register_msg(&__vapi_metadata_gtpu_add_del_tunnel_v2);
  VAPI_DBG("Assigned msg id %d to gtpu_add_del_tunnel_v2", vapi_msg_id_gtpu_add_del_tunnel_v2);
}
#endif

#ifndef defined_vapi_msg_gtpu_tunnel_update_tteid_reply
#define defined_vapi_msg_gtpu_tunnel_update_tteid_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_gtpu_tunnel_update_tteid_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_gtpu_tunnel_update_tteid_reply payload;
} vapi_msg_gtpu_tunnel_update_tteid_reply;

static inline void vapi_msg_gtpu_tunnel_update_tteid_reply_payload_hton(vapi_payload_gtpu_tunnel_update_tteid_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_gtpu_tunnel_update_tteid_reply_payload_ntoh(vapi_payload_gtpu_tunnel_update_tteid_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_gtpu_tunnel_update_tteid_reply_hton(vapi_msg_gtpu_tunnel_update_tteid_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_tunnel_update_tteid_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_gtpu_tunnel_update_tteid_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_gtpu_tunnel_update_tteid_reply_ntoh(vapi_msg_gtpu_tunnel_update_tteid_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_tunnel_update_tteid_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_gtpu_tunnel_update_tteid_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gtpu_tunnel_update_tteid_reply_msg_size(vapi_msg_gtpu_tunnel_update_tteid_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gtpu_tunnel_update_tteid_reply_msg_size(vapi_msg_gtpu_tunnel_update_tteid_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gtpu_tunnel_update_tteid_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_tunnel_update_tteid_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gtpu_tunnel_update_tteid_reply));
      return -1;
    }
  if (vapi_calc_gtpu_tunnel_update_tteid_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_tunnel_update_tteid_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gtpu_tunnel_update_tteid_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_gtpu_tunnel_update_tteid_reply()
{
  static const char name[] = "gtpu_tunnel_update_tteid_reply";
  static const char name_with_crc[] = "gtpu_tunnel_update_tteid_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_gtpu_tunnel_update_tteid_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_gtpu_tunnel_update_tteid_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_gtpu_tunnel_update_tteid_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_gtpu_tunnel_update_tteid_reply_hton,
    (generic_swap_fn_t)vapi_msg_gtpu_tunnel_update_tteid_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gtpu_tunnel_update_tteid_reply = vapi_register_msg(&__vapi_metadata_gtpu_tunnel_update_tteid_reply);
  VAPI_DBG("Assigned msg id %d to gtpu_tunnel_update_tteid_reply", vapi_msg_id_gtpu_tunnel_update_tteid_reply);
}

static inline void vapi_set_vapi_msg_gtpu_tunnel_update_tteid_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_gtpu_tunnel_update_tteid_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_gtpu_tunnel_update_tteid_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_gtpu_tunnel_update_tteid
#define defined_vapi_msg_gtpu_tunnel_update_tteid
typedef struct __attribute__ ((__packed__)) {
  vapi_type_address dst_address;
  u32 encap_vrf_id;
  u32 teid;
  u32 tteid; 
} vapi_payload_gtpu_tunnel_update_tteid;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_gtpu_tunnel_update_tteid payload;
} vapi_msg_gtpu_tunnel_update_tteid;

static inline void vapi_msg_gtpu_tunnel_update_tteid_payload_hton(vapi_payload_gtpu_tunnel_update_tteid *payload)
{
  payload->encap_vrf_id = htobe32(payload->encap_vrf_id);
  payload->teid = htobe32(payload->teid);
  payload->tteid = htobe32(payload->tteid);
}

static inline void vapi_msg_gtpu_tunnel_update_tteid_payload_ntoh(vapi_payload_gtpu_tunnel_update_tteid *payload)
{
  payload->encap_vrf_id = be32toh(payload->encap_vrf_id);
  payload->teid = be32toh(payload->teid);
  payload->tteid = be32toh(payload->tteid);
}

static inline void vapi_msg_gtpu_tunnel_update_tteid_hton(vapi_msg_gtpu_tunnel_update_tteid *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_tunnel_update_tteid'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_gtpu_tunnel_update_tteid_payload_hton(&msg->payload);
}

static inline void vapi_msg_gtpu_tunnel_update_tteid_ntoh(vapi_msg_gtpu_tunnel_update_tteid *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_tunnel_update_tteid'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_gtpu_tunnel_update_tteid_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gtpu_tunnel_update_tteid_msg_size(vapi_msg_gtpu_tunnel_update_tteid *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gtpu_tunnel_update_tteid_msg_size(vapi_msg_gtpu_tunnel_update_tteid *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gtpu_tunnel_update_tteid) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_tunnel_update_tteid' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gtpu_tunnel_update_tteid));
      return -1;
    }
  if (vapi_calc_gtpu_tunnel_update_tteid_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_tunnel_update_tteid' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gtpu_tunnel_update_tteid_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_gtpu_tunnel_update_tteid* vapi_alloc_gtpu_tunnel_update_tteid(struct vapi_ctx_s *ctx)
{
  vapi_msg_gtpu_tunnel_update_tteid *msg = NULL;
  const size_t size = sizeof(vapi_msg_gtpu_tunnel_update_tteid);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_gtpu_tunnel_update_tteid*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_gtpu_tunnel_update_tteid);

  return msg;
}

static inline vapi_error_e vapi_gtpu_tunnel_update_tteid(struct vapi_ctx_s *ctx,
  vapi_msg_gtpu_tunnel_update_tteid *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_gtpu_tunnel_update_tteid_reply *reply),
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
  vapi_msg_gtpu_tunnel_update_tteid_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_gtpu_tunnel_update_tteid_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_gtpu_tunnel_update_tteid_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_gtpu_tunnel_update_tteid()
{
  static const char name[] = "gtpu_tunnel_update_tteid";
  static const char name_with_crc[] = "gtpu_tunnel_update_tteid_79f33816";
  static vapi_message_desc_t __vapi_metadata_gtpu_tunnel_update_tteid = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_gtpu_tunnel_update_tteid, payload),
    (verify_msg_size_fn_t)vapi_verify_gtpu_tunnel_update_tteid_msg_size,
    (generic_swap_fn_t)vapi_msg_gtpu_tunnel_update_tteid_hton,
    (generic_swap_fn_t)vapi_msg_gtpu_tunnel_update_tteid_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gtpu_tunnel_update_tteid = vapi_register_msg(&__vapi_metadata_gtpu_tunnel_update_tteid);
  VAPI_DBG("Assigned msg id %d to gtpu_tunnel_update_tteid", vapi_msg_id_gtpu_tunnel_update_tteid);
}
#endif

#ifndef defined_vapi_msg_gtpu_tunnel_details
#define defined_vapi_msg_gtpu_tunnel_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_type_address src_address;
  vapi_type_address dst_address;
  vapi_type_interface_index mcast_sw_if_index;
  u32 encap_vrf_id;
  u32 decap_next_index;
  u32 teid;
  u32 tteid; 
} vapi_payload_gtpu_tunnel_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_gtpu_tunnel_details payload;
} vapi_msg_gtpu_tunnel_details;

static inline void vapi_msg_gtpu_tunnel_details_payload_hton(vapi_payload_gtpu_tunnel_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->mcast_sw_if_index = htobe32(payload->mcast_sw_if_index);
  payload->encap_vrf_id = htobe32(payload->encap_vrf_id);
  payload->decap_next_index = htobe32(payload->decap_next_index);
  payload->teid = htobe32(payload->teid);
  payload->tteid = htobe32(payload->tteid);
}

static inline void vapi_msg_gtpu_tunnel_details_payload_ntoh(vapi_payload_gtpu_tunnel_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->mcast_sw_if_index = be32toh(payload->mcast_sw_if_index);
  payload->encap_vrf_id = be32toh(payload->encap_vrf_id);
  payload->decap_next_index = be32toh(payload->decap_next_index);
  payload->teid = be32toh(payload->teid);
  payload->tteid = be32toh(payload->tteid);
}

static inline void vapi_msg_gtpu_tunnel_details_hton(vapi_msg_gtpu_tunnel_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_tunnel_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_gtpu_tunnel_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_gtpu_tunnel_details_ntoh(vapi_msg_gtpu_tunnel_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_tunnel_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_gtpu_tunnel_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gtpu_tunnel_details_msg_size(vapi_msg_gtpu_tunnel_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gtpu_tunnel_details_msg_size(vapi_msg_gtpu_tunnel_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gtpu_tunnel_details) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_tunnel_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gtpu_tunnel_details));
      return -1;
    }
  if (vapi_calc_gtpu_tunnel_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_tunnel_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gtpu_tunnel_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_gtpu_tunnel_details()
{
  static const char name[] = "gtpu_tunnel_details";
  static const char name_with_crc[] = "gtpu_tunnel_details_27f434ae";
  static vapi_message_desc_t __vapi_metadata_gtpu_tunnel_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_gtpu_tunnel_details, payload),
    (verify_msg_size_fn_t)vapi_verify_gtpu_tunnel_details_msg_size,
    (generic_swap_fn_t)vapi_msg_gtpu_tunnel_details_hton,
    (generic_swap_fn_t)vapi_msg_gtpu_tunnel_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gtpu_tunnel_details = vapi_register_msg(&__vapi_metadata_gtpu_tunnel_details);
  VAPI_DBG("Assigned msg id %d to gtpu_tunnel_details", vapi_msg_id_gtpu_tunnel_details);
}

static inline void vapi_set_vapi_msg_gtpu_tunnel_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_gtpu_tunnel_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_gtpu_tunnel_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_gtpu_tunnel_dump
#define defined_vapi_msg_gtpu_tunnel_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_gtpu_tunnel_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_gtpu_tunnel_dump payload;
} vapi_msg_gtpu_tunnel_dump;

static inline void vapi_msg_gtpu_tunnel_dump_payload_hton(vapi_payload_gtpu_tunnel_dump *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_gtpu_tunnel_dump_payload_ntoh(vapi_payload_gtpu_tunnel_dump *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_gtpu_tunnel_dump_hton(vapi_msg_gtpu_tunnel_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_tunnel_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_gtpu_tunnel_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_gtpu_tunnel_dump_ntoh(vapi_msg_gtpu_tunnel_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_tunnel_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_gtpu_tunnel_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gtpu_tunnel_dump_msg_size(vapi_msg_gtpu_tunnel_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gtpu_tunnel_dump_msg_size(vapi_msg_gtpu_tunnel_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gtpu_tunnel_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_tunnel_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gtpu_tunnel_dump));
      return -1;
    }
  if (vapi_calc_gtpu_tunnel_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_tunnel_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gtpu_tunnel_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_gtpu_tunnel_dump* vapi_alloc_gtpu_tunnel_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_gtpu_tunnel_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_gtpu_tunnel_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_gtpu_tunnel_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_gtpu_tunnel_dump);

  return msg;
}

static inline vapi_error_e vapi_gtpu_tunnel_dump(struct vapi_ctx_s *ctx,
  vapi_msg_gtpu_tunnel_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_gtpu_tunnel_details *reply),
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
  vapi_msg_gtpu_tunnel_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_gtpu_tunnel_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_gtpu_tunnel_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_gtpu_tunnel_dump()
{
  static const char name[] = "gtpu_tunnel_dump";
  static const char name_with_crc[] = "gtpu_tunnel_dump_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_gtpu_tunnel_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_gtpu_tunnel_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_gtpu_tunnel_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_gtpu_tunnel_dump_hton,
    (generic_swap_fn_t)vapi_msg_gtpu_tunnel_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gtpu_tunnel_dump = vapi_register_msg(&__vapi_metadata_gtpu_tunnel_dump);
  VAPI_DBG("Assigned msg id %d to gtpu_tunnel_dump", vapi_msg_id_gtpu_tunnel_dump);
}
#endif

#ifndef defined_vapi_msg_gtpu_tunnel_v2_details
#define defined_vapi_msg_gtpu_tunnel_v2_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_type_address src_address;
  vapi_type_address dst_address;
  vapi_type_interface_index mcast_sw_if_index;
  u32 encap_vrf_id;
  vapi_enum_gtpu_decap_next_type decap_next_index;
  u32 teid;
  u32 tteid;
  bool pdu_extension;
  u8 qfi;
  bool is_forwarding;
  vapi_enum_gtpu_forwarding_type forwarding_type;
  vapi_type_sw_if_counters counters; 
} vapi_payload_gtpu_tunnel_v2_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_gtpu_tunnel_v2_details payload;
} vapi_msg_gtpu_tunnel_v2_details;

static inline void vapi_msg_gtpu_tunnel_v2_details_payload_hton(vapi_payload_gtpu_tunnel_v2_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->mcast_sw_if_index = htobe32(payload->mcast_sw_if_index);
  payload->encap_vrf_id = htobe32(payload->encap_vrf_id);
  payload->decap_next_index = (vapi_enum_gtpu_decap_next_type)htobe32(payload->decap_next_index);
  payload->teid = htobe32(payload->teid);
  payload->tteid = htobe32(payload->tteid);
  payload->forwarding_type = (vapi_enum_gtpu_forwarding_type)htobe32(payload->forwarding_type);
  vapi_type_sw_if_counters_hton(&payload->counters);
}

static inline void vapi_msg_gtpu_tunnel_v2_details_payload_ntoh(vapi_payload_gtpu_tunnel_v2_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->mcast_sw_if_index = be32toh(payload->mcast_sw_if_index);
  payload->encap_vrf_id = be32toh(payload->encap_vrf_id);
  payload->decap_next_index = (vapi_enum_gtpu_decap_next_type)be32toh(payload->decap_next_index);
  payload->teid = be32toh(payload->teid);
  payload->tteid = be32toh(payload->tteid);
  payload->forwarding_type = (vapi_enum_gtpu_forwarding_type)be32toh(payload->forwarding_type);
  vapi_type_sw_if_counters_ntoh(&payload->counters);
}

static inline void vapi_msg_gtpu_tunnel_v2_details_hton(vapi_msg_gtpu_tunnel_v2_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_tunnel_v2_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_gtpu_tunnel_v2_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_gtpu_tunnel_v2_details_ntoh(vapi_msg_gtpu_tunnel_v2_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_tunnel_v2_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_gtpu_tunnel_v2_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gtpu_tunnel_v2_details_msg_size(vapi_msg_gtpu_tunnel_v2_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gtpu_tunnel_v2_details_msg_size(vapi_msg_gtpu_tunnel_v2_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gtpu_tunnel_v2_details) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_tunnel_v2_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gtpu_tunnel_v2_details));
      return -1;
    }
  if (vapi_calc_gtpu_tunnel_v2_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_tunnel_v2_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gtpu_tunnel_v2_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_gtpu_tunnel_v2_details()
{
  static const char name[] = "gtpu_tunnel_v2_details";
  static const char name_with_crc[] = "gtpu_tunnel_v2_details_8bf4ba92";
  static vapi_message_desc_t __vapi_metadata_gtpu_tunnel_v2_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_gtpu_tunnel_v2_details, payload),
    (verify_msg_size_fn_t)vapi_verify_gtpu_tunnel_v2_details_msg_size,
    (generic_swap_fn_t)vapi_msg_gtpu_tunnel_v2_details_hton,
    (generic_swap_fn_t)vapi_msg_gtpu_tunnel_v2_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gtpu_tunnel_v2_details = vapi_register_msg(&__vapi_metadata_gtpu_tunnel_v2_details);
  VAPI_DBG("Assigned msg id %d to gtpu_tunnel_v2_details", vapi_msg_id_gtpu_tunnel_v2_details);
}

static inline void vapi_set_vapi_msg_gtpu_tunnel_v2_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_gtpu_tunnel_v2_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_gtpu_tunnel_v2_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_gtpu_tunnel_v2_dump
#define defined_vapi_msg_gtpu_tunnel_v2_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_gtpu_tunnel_v2_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_gtpu_tunnel_v2_dump payload;
} vapi_msg_gtpu_tunnel_v2_dump;

static inline void vapi_msg_gtpu_tunnel_v2_dump_payload_hton(vapi_payload_gtpu_tunnel_v2_dump *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_gtpu_tunnel_v2_dump_payload_ntoh(vapi_payload_gtpu_tunnel_v2_dump *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_gtpu_tunnel_v2_dump_hton(vapi_msg_gtpu_tunnel_v2_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_tunnel_v2_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_gtpu_tunnel_v2_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_gtpu_tunnel_v2_dump_ntoh(vapi_msg_gtpu_tunnel_v2_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_tunnel_v2_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_gtpu_tunnel_v2_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gtpu_tunnel_v2_dump_msg_size(vapi_msg_gtpu_tunnel_v2_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gtpu_tunnel_v2_dump_msg_size(vapi_msg_gtpu_tunnel_v2_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gtpu_tunnel_v2_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_tunnel_v2_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gtpu_tunnel_v2_dump));
      return -1;
    }
  if (vapi_calc_gtpu_tunnel_v2_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_tunnel_v2_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gtpu_tunnel_v2_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_gtpu_tunnel_v2_dump* vapi_alloc_gtpu_tunnel_v2_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_gtpu_tunnel_v2_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_gtpu_tunnel_v2_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_gtpu_tunnel_v2_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_gtpu_tunnel_v2_dump);

  return msg;
}

static inline vapi_error_e vapi_gtpu_tunnel_v2_dump(struct vapi_ctx_s *ctx,
  vapi_msg_gtpu_tunnel_v2_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_gtpu_tunnel_v2_details *reply),
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
  vapi_msg_gtpu_tunnel_v2_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_gtpu_tunnel_v2_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_gtpu_tunnel_v2_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_gtpu_tunnel_v2_dump()
{
  static const char name[] = "gtpu_tunnel_v2_dump";
  static const char name_with_crc[] = "gtpu_tunnel_v2_dump_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_gtpu_tunnel_v2_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_gtpu_tunnel_v2_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_gtpu_tunnel_v2_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_gtpu_tunnel_v2_dump_hton,
    (generic_swap_fn_t)vapi_msg_gtpu_tunnel_v2_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gtpu_tunnel_v2_dump = vapi_register_msg(&__vapi_metadata_gtpu_tunnel_v2_dump);
  VAPI_DBG("Assigned msg id %d to gtpu_tunnel_v2_dump", vapi_msg_id_gtpu_tunnel_v2_dump);
}
#endif

#ifndef defined_vapi_msg_sw_interface_set_gtpu_bypass_reply
#define defined_vapi_msg_sw_interface_set_gtpu_bypass_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_sw_interface_set_gtpu_bypass_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_sw_interface_set_gtpu_bypass_reply payload;
} vapi_msg_sw_interface_set_gtpu_bypass_reply;

static inline void vapi_msg_sw_interface_set_gtpu_bypass_reply_payload_hton(vapi_payload_sw_interface_set_gtpu_bypass_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_sw_interface_set_gtpu_bypass_reply_payload_ntoh(vapi_payload_sw_interface_set_gtpu_bypass_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_sw_interface_set_gtpu_bypass_reply_hton(vapi_msg_sw_interface_set_gtpu_bypass_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_set_gtpu_bypass_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_sw_interface_set_gtpu_bypass_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_set_gtpu_bypass_reply_ntoh(vapi_msg_sw_interface_set_gtpu_bypass_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_set_gtpu_bypass_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_sw_interface_set_gtpu_bypass_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_set_gtpu_bypass_reply_msg_size(vapi_msg_sw_interface_set_gtpu_bypass_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_set_gtpu_bypass_reply_msg_size(vapi_msg_sw_interface_set_gtpu_bypass_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_set_gtpu_bypass_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_set_gtpu_bypass_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_set_gtpu_bypass_reply));
      return -1;
    }
  if (vapi_calc_sw_interface_set_gtpu_bypass_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_set_gtpu_bypass_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_set_gtpu_bypass_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_sw_interface_set_gtpu_bypass_reply()
{
  static const char name[] = "sw_interface_set_gtpu_bypass_reply";
  static const char name_with_crc[] = "sw_interface_set_gtpu_bypass_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_sw_interface_set_gtpu_bypass_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_sw_interface_set_gtpu_bypass_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_set_gtpu_bypass_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_set_gtpu_bypass_reply_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_set_gtpu_bypass_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_set_gtpu_bypass_reply = vapi_register_msg(&__vapi_metadata_sw_interface_set_gtpu_bypass_reply);
  VAPI_DBG("Assigned msg id %d to sw_interface_set_gtpu_bypass_reply", vapi_msg_id_sw_interface_set_gtpu_bypass_reply);
}

static inline void vapi_set_vapi_msg_sw_interface_set_gtpu_bypass_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_sw_interface_set_gtpu_bypass_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_sw_interface_set_gtpu_bypass_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_sw_interface_set_gtpu_bypass
#define defined_vapi_msg_sw_interface_set_gtpu_bypass
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  bool is_ipv6;
  bool enable; 
} vapi_payload_sw_interface_set_gtpu_bypass;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_sw_interface_set_gtpu_bypass payload;
} vapi_msg_sw_interface_set_gtpu_bypass;

static inline void vapi_msg_sw_interface_set_gtpu_bypass_payload_hton(vapi_payload_sw_interface_set_gtpu_bypass *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_sw_interface_set_gtpu_bypass_payload_ntoh(vapi_payload_sw_interface_set_gtpu_bypass *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_sw_interface_set_gtpu_bypass_hton(vapi_msg_sw_interface_set_gtpu_bypass *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_set_gtpu_bypass'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_sw_interface_set_gtpu_bypass_payload_hton(&msg->payload);
}

static inline void vapi_msg_sw_interface_set_gtpu_bypass_ntoh(vapi_msg_sw_interface_set_gtpu_bypass *msg)
{
  VAPI_DBG("Swapping `vapi_msg_sw_interface_set_gtpu_bypass'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_sw_interface_set_gtpu_bypass_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_sw_interface_set_gtpu_bypass_msg_size(vapi_msg_sw_interface_set_gtpu_bypass *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_sw_interface_set_gtpu_bypass_msg_size(vapi_msg_sw_interface_set_gtpu_bypass *msg, uword buf_size)
{
  if (sizeof(vapi_msg_sw_interface_set_gtpu_bypass) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_set_gtpu_bypass' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_sw_interface_set_gtpu_bypass));
      return -1;
    }
  if (vapi_calc_sw_interface_set_gtpu_bypass_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'sw_interface_set_gtpu_bypass' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_sw_interface_set_gtpu_bypass_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_sw_interface_set_gtpu_bypass* vapi_alloc_sw_interface_set_gtpu_bypass(struct vapi_ctx_s *ctx)
{
  vapi_msg_sw_interface_set_gtpu_bypass *msg = NULL;
  const size_t size = sizeof(vapi_msg_sw_interface_set_gtpu_bypass);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_sw_interface_set_gtpu_bypass*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_sw_interface_set_gtpu_bypass);

  return msg;
}

static inline vapi_error_e vapi_sw_interface_set_gtpu_bypass(struct vapi_ctx_s *ctx,
  vapi_msg_sw_interface_set_gtpu_bypass *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sw_interface_set_gtpu_bypass_reply *reply),
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
  vapi_msg_sw_interface_set_gtpu_bypass_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_sw_interface_set_gtpu_bypass_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_sw_interface_set_gtpu_bypass_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_sw_interface_set_gtpu_bypass()
{
  static const char name[] = "sw_interface_set_gtpu_bypass";
  static const char name_with_crc[] = "sw_interface_set_gtpu_bypass_65247409";
  static vapi_message_desc_t __vapi_metadata_sw_interface_set_gtpu_bypass = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_sw_interface_set_gtpu_bypass, payload),
    (verify_msg_size_fn_t)vapi_verify_sw_interface_set_gtpu_bypass_msg_size,
    (generic_swap_fn_t)vapi_msg_sw_interface_set_gtpu_bypass_hton,
    (generic_swap_fn_t)vapi_msg_sw_interface_set_gtpu_bypass_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_sw_interface_set_gtpu_bypass = vapi_register_msg(&__vapi_metadata_sw_interface_set_gtpu_bypass);
  VAPI_DBG("Assigned msg id %d to sw_interface_set_gtpu_bypass", vapi_msg_id_sw_interface_set_gtpu_bypass);
}
#endif

#ifndef defined_vapi_msg_gtpu_offload_rx_reply
#define defined_vapi_msg_gtpu_offload_rx_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_gtpu_offload_rx_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_gtpu_offload_rx_reply payload;
} vapi_msg_gtpu_offload_rx_reply;

static inline void vapi_msg_gtpu_offload_rx_reply_payload_hton(vapi_payload_gtpu_offload_rx_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_gtpu_offload_rx_reply_payload_ntoh(vapi_payload_gtpu_offload_rx_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_gtpu_offload_rx_reply_hton(vapi_msg_gtpu_offload_rx_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_offload_rx_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_gtpu_offload_rx_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_gtpu_offload_rx_reply_ntoh(vapi_msg_gtpu_offload_rx_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_offload_rx_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_gtpu_offload_rx_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gtpu_offload_rx_reply_msg_size(vapi_msg_gtpu_offload_rx_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gtpu_offload_rx_reply_msg_size(vapi_msg_gtpu_offload_rx_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gtpu_offload_rx_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_offload_rx_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gtpu_offload_rx_reply));
      return -1;
    }
  if (vapi_calc_gtpu_offload_rx_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_offload_rx_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gtpu_offload_rx_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_gtpu_offload_rx_reply()
{
  static const char name[] = "gtpu_offload_rx_reply";
  static const char name_with_crc[] = "gtpu_offload_rx_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_gtpu_offload_rx_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_gtpu_offload_rx_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_gtpu_offload_rx_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_gtpu_offload_rx_reply_hton,
    (generic_swap_fn_t)vapi_msg_gtpu_offload_rx_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gtpu_offload_rx_reply = vapi_register_msg(&__vapi_metadata_gtpu_offload_rx_reply);
  VAPI_DBG("Assigned msg id %d to gtpu_offload_rx_reply", vapi_msg_id_gtpu_offload_rx_reply);
}

static inline void vapi_set_vapi_msg_gtpu_offload_rx_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_gtpu_offload_rx_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_gtpu_offload_rx_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_gtpu_offload_rx
#define defined_vapi_msg_gtpu_offload_rx
typedef struct __attribute__ ((__packed__)) {
  u32 hw_if_index;
  u32 sw_if_index;
  u8 enable; 
} vapi_payload_gtpu_offload_rx;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_gtpu_offload_rx payload;
} vapi_msg_gtpu_offload_rx;

static inline void vapi_msg_gtpu_offload_rx_payload_hton(vapi_payload_gtpu_offload_rx *payload)
{
  payload->hw_if_index = htobe32(payload->hw_if_index);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_gtpu_offload_rx_payload_ntoh(vapi_payload_gtpu_offload_rx *payload)
{
  payload->hw_if_index = be32toh(payload->hw_if_index);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_gtpu_offload_rx_hton(vapi_msg_gtpu_offload_rx *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_offload_rx'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_gtpu_offload_rx_payload_hton(&msg->payload);
}

static inline void vapi_msg_gtpu_offload_rx_ntoh(vapi_msg_gtpu_offload_rx *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_offload_rx'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_gtpu_offload_rx_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gtpu_offload_rx_msg_size(vapi_msg_gtpu_offload_rx *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gtpu_offload_rx_msg_size(vapi_msg_gtpu_offload_rx *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gtpu_offload_rx) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_offload_rx' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gtpu_offload_rx));
      return -1;
    }
  if (vapi_calc_gtpu_offload_rx_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_offload_rx' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gtpu_offload_rx_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_gtpu_offload_rx* vapi_alloc_gtpu_offload_rx(struct vapi_ctx_s *ctx)
{
  vapi_msg_gtpu_offload_rx *msg = NULL;
  const size_t size = sizeof(vapi_msg_gtpu_offload_rx);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_gtpu_offload_rx*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_gtpu_offload_rx);

  return msg;
}

static inline vapi_error_e vapi_gtpu_offload_rx(struct vapi_ctx_s *ctx,
  vapi_msg_gtpu_offload_rx *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_gtpu_offload_rx_reply *reply),
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
  vapi_msg_gtpu_offload_rx_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_gtpu_offload_rx_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_gtpu_offload_rx_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_gtpu_offload_rx()
{
  static const char name[] = "gtpu_offload_rx";
  static const char name_with_crc[] = "gtpu_offload_rx_f0b08786";
  static vapi_message_desc_t __vapi_metadata_gtpu_offload_rx = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_gtpu_offload_rx, payload),
    (verify_msg_size_fn_t)vapi_verify_gtpu_offload_rx_msg_size,
    (generic_swap_fn_t)vapi_msg_gtpu_offload_rx_hton,
    (generic_swap_fn_t)vapi_msg_gtpu_offload_rx_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gtpu_offload_rx = vapi_register_msg(&__vapi_metadata_gtpu_offload_rx);
  VAPI_DBG("Assigned msg id %d to gtpu_offload_rx", vapi_msg_id_gtpu_offload_rx);
}
#endif

#ifndef defined_vapi_msg_gtpu_add_del_forward_reply
#define defined_vapi_msg_gtpu_add_del_forward_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_gtpu_add_del_forward_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_gtpu_add_del_forward_reply payload;
} vapi_msg_gtpu_add_del_forward_reply;

static inline void vapi_msg_gtpu_add_del_forward_reply_payload_hton(vapi_payload_gtpu_add_del_forward_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_gtpu_add_del_forward_reply_payload_ntoh(vapi_payload_gtpu_add_del_forward_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_gtpu_add_del_forward_reply_hton(vapi_msg_gtpu_add_del_forward_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_add_del_forward_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_gtpu_add_del_forward_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_gtpu_add_del_forward_reply_ntoh(vapi_msg_gtpu_add_del_forward_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_add_del_forward_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_gtpu_add_del_forward_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gtpu_add_del_forward_reply_msg_size(vapi_msg_gtpu_add_del_forward_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gtpu_add_del_forward_reply_msg_size(vapi_msg_gtpu_add_del_forward_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gtpu_add_del_forward_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_add_del_forward_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gtpu_add_del_forward_reply));
      return -1;
    }
  if (vapi_calc_gtpu_add_del_forward_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_add_del_forward_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gtpu_add_del_forward_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_gtpu_add_del_forward_reply()
{
  static const char name[] = "gtpu_add_del_forward_reply";
  static const char name_with_crc[] = "gtpu_add_del_forward_reply_5383d31f";
  static vapi_message_desc_t __vapi_metadata_gtpu_add_del_forward_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_gtpu_add_del_forward_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_gtpu_add_del_forward_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_gtpu_add_del_forward_reply_hton,
    (generic_swap_fn_t)vapi_msg_gtpu_add_del_forward_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gtpu_add_del_forward_reply = vapi_register_msg(&__vapi_metadata_gtpu_add_del_forward_reply);
  VAPI_DBG("Assigned msg id %d to gtpu_add_del_forward_reply", vapi_msg_id_gtpu_add_del_forward_reply);
}

static inline void vapi_set_vapi_msg_gtpu_add_del_forward_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_gtpu_add_del_forward_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_gtpu_add_del_forward_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_gtpu_add_del_forward
#define defined_vapi_msg_gtpu_add_del_forward
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_address dst_address;
  vapi_enum_gtpu_forwarding_type forwarding_type;
  u32 encap_vrf_id;
  vapi_enum_gtpu_decap_next_type decap_next_index; 
} vapi_payload_gtpu_add_del_forward;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_gtpu_add_del_forward payload;
} vapi_msg_gtpu_add_del_forward;

static inline void vapi_msg_gtpu_add_del_forward_payload_hton(vapi_payload_gtpu_add_del_forward *payload)
{
  payload->forwarding_type = (vapi_enum_gtpu_forwarding_type)htobe32(payload->forwarding_type);
  payload->encap_vrf_id = htobe32(payload->encap_vrf_id);
  payload->decap_next_index = (vapi_enum_gtpu_decap_next_type)htobe32(payload->decap_next_index);
}

static inline void vapi_msg_gtpu_add_del_forward_payload_ntoh(vapi_payload_gtpu_add_del_forward *payload)
{
  payload->forwarding_type = (vapi_enum_gtpu_forwarding_type)be32toh(payload->forwarding_type);
  payload->encap_vrf_id = be32toh(payload->encap_vrf_id);
  payload->decap_next_index = (vapi_enum_gtpu_decap_next_type)be32toh(payload->decap_next_index);
}

static inline void vapi_msg_gtpu_add_del_forward_hton(vapi_msg_gtpu_add_del_forward *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_add_del_forward'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_gtpu_add_del_forward_payload_hton(&msg->payload);
}

static inline void vapi_msg_gtpu_add_del_forward_ntoh(vapi_msg_gtpu_add_del_forward *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_add_del_forward'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_gtpu_add_del_forward_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gtpu_add_del_forward_msg_size(vapi_msg_gtpu_add_del_forward *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gtpu_add_del_forward_msg_size(vapi_msg_gtpu_add_del_forward *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gtpu_add_del_forward) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_add_del_forward' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gtpu_add_del_forward));
      return -1;
    }
  if (vapi_calc_gtpu_add_del_forward_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_add_del_forward' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gtpu_add_del_forward_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_gtpu_add_del_forward* vapi_alloc_gtpu_add_del_forward(struct vapi_ctx_s *ctx)
{
  vapi_msg_gtpu_add_del_forward *msg = NULL;
  const size_t size = sizeof(vapi_msg_gtpu_add_del_forward);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_gtpu_add_del_forward*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_gtpu_add_del_forward);

  return msg;
}

static inline vapi_error_e vapi_gtpu_add_del_forward(struct vapi_ctx_s *ctx,
  vapi_msg_gtpu_add_del_forward *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_gtpu_add_del_forward_reply *reply),
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
  vapi_msg_gtpu_add_del_forward_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_gtpu_add_del_forward_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_gtpu_add_del_forward_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_gtpu_add_del_forward()
{
  static const char name[] = "gtpu_add_del_forward";
  static const char name_with_crc[] = "gtpu_add_del_forward_c6ccce13";
  static vapi_message_desc_t __vapi_metadata_gtpu_add_del_forward = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_gtpu_add_del_forward, payload),
    (verify_msg_size_fn_t)vapi_verify_gtpu_add_del_forward_msg_size,
    (generic_swap_fn_t)vapi_msg_gtpu_add_del_forward_hton,
    (generic_swap_fn_t)vapi_msg_gtpu_add_del_forward_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gtpu_add_del_forward = vapi_register_msg(&__vapi_metadata_gtpu_add_del_forward);
  VAPI_DBG("Assigned msg id %d to gtpu_add_del_forward", vapi_msg_id_gtpu_add_del_forward);
}
#endif

#ifndef defined_vapi_msg_gtpu_get_transfer_counts_reply
#define defined_vapi_msg_gtpu_get_transfer_counts_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 count;
  vapi_type_tunnel_metrics tunnels[0]; 
} vapi_payload_gtpu_get_transfer_counts_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_gtpu_get_transfer_counts_reply payload;
} vapi_msg_gtpu_get_transfer_counts_reply;

static inline void vapi_msg_gtpu_get_transfer_counts_reply_payload_hton(vapi_payload_gtpu_get_transfer_counts_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->count = htobe32(payload->count);
  do { unsigned i; for (i = 0; i < be32toh(payload->count); ++i) { vapi_type_tunnel_metrics_hton(&payload->tunnels[i]); } } while(0);
}

static inline void vapi_msg_gtpu_get_transfer_counts_reply_payload_ntoh(vapi_payload_gtpu_get_transfer_counts_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->count = be32toh(payload->count);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { vapi_type_tunnel_metrics_ntoh(&payload->tunnels[i]); } } while(0);
}

static inline void vapi_msg_gtpu_get_transfer_counts_reply_hton(vapi_msg_gtpu_get_transfer_counts_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_get_transfer_counts_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_gtpu_get_transfer_counts_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_gtpu_get_transfer_counts_reply_ntoh(vapi_msg_gtpu_get_transfer_counts_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_get_transfer_counts_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_gtpu_get_transfer_counts_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gtpu_get_transfer_counts_reply_msg_size(vapi_msg_gtpu_get_transfer_counts_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.tunnels[0]) * msg->payload.count;
}

static inline int vapi_verify_gtpu_get_transfer_counts_reply_msg_size(vapi_msg_gtpu_get_transfer_counts_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gtpu_get_transfer_counts_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_get_transfer_counts_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gtpu_get_transfer_counts_reply));
      return -1;
    }
  if (vapi_calc_gtpu_get_transfer_counts_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_get_transfer_counts_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gtpu_get_transfer_counts_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_gtpu_get_transfer_counts_reply()
{
  static const char name[] = "gtpu_get_transfer_counts_reply";
  static const char name_with_crc[] = "gtpu_get_transfer_counts_reply_e35f04bc";
  static vapi_message_desc_t __vapi_metadata_gtpu_get_transfer_counts_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_gtpu_get_transfer_counts_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_gtpu_get_transfer_counts_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_gtpu_get_transfer_counts_reply_hton,
    (generic_swap_fn_t)vapi_msg_gtpu_get_transfer_counts_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gtpu_get_transfer_counts_reply = vapi_register_msg(&__vapi_metadata_gtpu_get_transfer_counts_reply);
  VAPI_DBG("Assigned msg id %d to gtpu_get_transfer_counts_reply", vapi_msg_id_gtpu_get_transfer_counts_reply);
}

static inline void vapi_set_vapi_msg_gtpu_get_transfer_counts_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_gtpu_get_transfer_counts_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_gtpu_get_transfer_counts_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_gtpu_get_transfer_counts
#define defined_vapi_msg_gtpu_get_transfer_counts
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index_start;
  u32 capacity; 
} vapi_payload_gtpu_get_transfer_counts;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_gtpu_get_transfer_counts payload;
} vapi_msg_gtpu_get_transfer_counts;

static inline void vapi_msg_gtpu_get_transfer_counts_payload_hton(vapi_payload_gtpu_get_transfer_counts *payload)
{
  payload->sw_if_index_start = htobe32(payload->sw_if_index_start);
  payload->capacity = htobe32(payload->capacity);
}

static inline void vapi_msg_gtpu_get_transfer_counts_payload_ntoh(vapi_payload_gtpu_get_transfer_counts *payload)
{
  payload->sw_if_index_start = be32toh(payload->sw_if_index_start);
  payload->capacity = be32toh(payload->capacity);
}

static inline void vapi_msg_gtpu_get_transfer_counts_hton(vapi_msg_gtpu_get_transfer_counts *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_get_transfer_counts'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_gtpu_get_transfer_counts_payload_hton(&msg->payload);
}

static inline void vapi_msg_gtpu_get_transfer_counts_ntoh(vapi_msg_gtpu_get_transfer_counts *msg)
{
  VAPI_DBG("Swapping `vapi_msg_gtpu_get_transfer_counts'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_gtpu_get_transfer_counts_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_gtpu_get_transfer_counts_msg_size(vapi_msg_gtpu_get_transfer_counts *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_gtpu_get_transfer_counts_msg_size(vapi_msg_gtpu_get_transfer_counts *msg, uword buf_size)
{
  if (sizeof(vapi_msg_gtpu_get_transfer_counts) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_get_transfer_counts' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_gtpu_get_transfer_counts));
      return -1;
    }
  if (vapi_calc_gtpu_get_transfer_counts_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'gtpu_get_transfer_counts' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_gtpu_get_transfer_counts_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_gtpu_get_transfer_counts* vapi_alloc_gtpu_get_transfer_counts(struct vapi_ctx_s *ctx)
{
  vapi_msg_gtpu_get_transfer_counts *msg = NULL;
  const size_t size = sizeof(vapi_msg_gtpu_get_transfer_counts);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_gtpu_get_transfer_counts*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_gtpu_get_transfer_counts);

  return msg;
}

static inline vapi_error_e vapi_gtpu_get_transfer_counts(struct vapi_ctx_s *ctx,
  vapi_msg_gtpu_get_transfer_counts *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_gtpu_get_transfer_counts_reply *reply),
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
  vapi_msg_gtpu_get_transfer_counts_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_gtpu_get_transfer_counts_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_gtpu_get_transfer_counts_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_gtpu_get_transfer_counts()
{
  static const char name[] = "gtpu_get_transfer_counts";
  static const char name_with_crc[] = "gtpu_get_transfer_counts_61410788";
  static vapi_message_desc_t __vapi_metadata_gtpu_get_transfer_counts = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_gtpu_get_transfer_counts, payload),
    (verify_msg_size_fn_t)vapi_verify_gtpu_get_transfer_counts_msg_size,
    (generic_swap_fn_t)vapi_msg_gtpu_get_transfer_counts_hton,
    (generic_swap_fn_t)vapi_msg_gtpu_get_transfer_counts_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_gtpu_get_transfer_counts = vapi_register_msg(&__vapi_metadata_gtpu_get_transfer_counts);
  VAPI_DBG("Assigned msg id %d to gtpu_get_transfer_counts", vapi_msg_id_gtpu_get_transfer_counts);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
