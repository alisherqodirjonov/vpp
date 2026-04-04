#ifndef __included_lb_api_json
#define __included_lb_api_json

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

extern vapi_msg_id_t vapi_msg_id_lb_conf;
extern vapi_msg_id_t vapi_msg_id_lb_conf_reply;
extern vapi_msg_id_t vapi_msg_id_lb_add_del_vip;
extern vapi_msg_id_t vapi_msg_id_lb_add_del_vip_reply;
extern vapi_msg_id_t vapi_msg_id_lb_add_del_vip_v2;
extern vapi_msg_id_t vapi_msg_id_lb_add_del_vip_v2_reply;
extern vapi_msg_id_t vapi_msg_id_lb_add_del_as;
extern vapi_msg_id_t vapi_msg_id_lb_add_del_as_reply;
extern vapi_msg_id_t vapi_msg_id_lb_flush_vip;
extern vapi_msg_id_t vapi_msg_id_lb_flush_vip_reply;
extern vapi_msg_id_t vapi_msg_id_lb_vip_dump;
extern vapi_msg_id_t vapi_msg_id_lb_vip_details;
extern vapi_msg_id_t vapi_msg_id_lb_as_dump;
extern vapi_msg_id_t vapi_msg_id_lb_as_details;
extern vapi_msg_id_t vapi_msg_id_lb_add_del_intf_nat4;
extern vapi_msg_id_t vapi_msg_id_lb_add_del_intf_nat4_reply;
extern vapi_msg_id_t vapi_msg_id_lb_add_del_intf_nat6;
extern vapi_msg_id_t vapi_msg_id_lb_add_del_intf_nat6_reply;

#define DEFINE_VAPI_MSG_IDS_LB_API_JSON\
  vapi_msg_id_t vapi_msg_id_lb_conf;\
  vapi_msg_id_t vapi_msg_id_lb_conf_reply;\
  vapi_msg_id_t vapi_msg_id_lb_add_del_vip;\
  vapi_msg_id_t vapi_msg_id_lb_add_del_vip_reply;\
  vapi_msg_id_t vapi_msg_id_lb_add_del_vip_v2;\
  vapi_msg_id_t vapi_msg_id_lb_add_del_vip_v2_reply;\
  vapi_msg_id_t vapi_msg_id_lb_add_del_as;\
  vapi_msg_id_t vapi_msg_id_lb_add_del_as_reply;\
  vapi_msg_id_t vapi_msg_id_lb_flush_vip;\
  vapi_msg_id_t vapi_msg_id_lb_flush_vip_reply;\
  vapi_msg_id_t vapi_msg_id_lb_vip_dump;\
  vapi_msg_id_t vapi_msg_id_lb_vip_details;\
  vapi_msg_id_t vapi_msg_id_lb_as_dump;\
  vapi_msg_id_t vapi_msg_id_lb_as_details;\
  vapi_msg_id_t vapi_msg_id_lb_add_del_intf_nat4;\
  vapi_msg_id_t vapi_msg_id_lb_add_del_intf_nat4_reply;\
  vapi_msg_id_t vapi_msg_id_lb_add_del_intf_nat6;\
  vapi_msg_id_t vapi_msg_id_lb_add_del_intf_nat6_reply;


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

#ifndef defined_vapi_enum_lb_srv_type
#define defined_vapi_enum_lb_srv_type
typedef enum {
  LB_API_SRV_TYPE_CLUSTERIP = 0,
  LB_API_SRV_TYPE_NODEPORT = 1,
  LB_API_SRV_N_TYPES = 2,
}  vapi_enum_lb_srv_type;

#endif

#ifndef defined_vapi_enum_lb_encap_type
#define defined_vapi_enum_lb_encap_type
typedef enum {
  LB_API_ENCAP_TYPE_GRE4 = 0,
  LB_API_ENCAP_TYPE_GRE6 = 1,
  LB_API_ENCAP_TYPE_L3DSR = 2,
  LB_API_ENCAP_TYPE_NAT4 = 3,
  LB_API_ENCAP_TYPE_NAT6 = 4,
  LB_API_ENCAP_N_TYPES = 5,
}  vapi_enum_lb_encap_type;

#endif

#ifndef defined_vapi_enum_lb_lkp_type_t
#define defined_vapi_enum_lb_lkp_type_t
typedef enum {
  LB_API_LKP_SAME_IP_PORT = 0,
  LB_API_LKP_DIFF_IP_PORT = 1,
  LB_API_LKP_ALL_PORT_IP = 2,
  LB_API_LKP_N_TYPES = 3,
}  vapi_enum_lb_lkp_type_t;

#endif

#ifndef defined_vapi_enum_lb_vip_type
#define defined_vapi_enum_lb_vip_type
typedef enum {
  LB_API_VIP_TYPE_IP6_GRE6 = 0,
  LB_API_VIP_TYPE_IP6_GRE4 = 1,
  LB_API_VIP_TYPE_IP4_GRE6 = 2,
  LB_API_VIP_TYPE_IP4_GRE4 = 3,
  LB_API_VIP_TYPE_IP4_L3DSR = 4,
  LB_API_VIP_TYPE_IP4_NAT4 = 5,
  LB_API_VIP_TYPE_IP6_NAT6 = 6,
  LB_API_VIP_N_TYPES = 7,
}  vapi_enum_lb_vip_type;

#endif

#ifndef defined_vapi_enum_lb_nat_protocol
#define defined_vapi_enum_lb_nat_protocol
typedef enum {
  LB_API_NAT_PROTOCOL_UDP = 6,
  LB_API_NAT_PROTOCOL_TCP = 23,
  LB_API_NAT_PROTOCOL_ANY = 4294967295,
}  vapi_enum_lb_nat_protocol;

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

#ifndef defined_vapi_type_address_with_prefix
#define defined_vapi_type_address_with_prefix
typedef vapi_type_prefix vapi_type_address_with_prefix;

#endif

#ifndef defined_vapi_type_lb_vip
#define defined_vapi_type_lb_vip
typedef struct __attribute__((__packed__)) {
  vapi_type_address_with_prefix pfx;
  vapi_enum_ip_proto protocol;
  u16 port;
} vapi_type_lb_vip;

static inline void vapi_type_lb_vip_hton(vapi_type_lb_vip *msg)
{
  msg->port = htobe16(msg->port);
}

static inline void vapi_type_lb_vip_ntoh(vapi_type_lb_vip *msg)
{
  msg->port = be16toh(msg->port);
}
#endif

#ifndef defined_vapi_type_interface_index
#define defined_vapi_type_interface_index
typedef u32 vapi_type_interface_index;

#endif

#ifndef defined_vapi_type_ip4_address_with_prefix
#define defined_vapi_type_ip4_address_with_prefix
typedef vapi_type_ip4_prefix vapi_type_ip4_address_with_prefix;

#endif

#ifndef defined_vapi_type_ip6_address_with_prefix
#define defined_vapi_type_ip6_address_with_prefix
typedef vapi_type_ip6_prefix vapi_type_ip6_address_with_prefix;

#endif

#ifndef defined_vapi_msg_lb_conf_reply
#define defined_vapi_msg_lb_conf_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lb_conf_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lb_conf_reply payload;
} vapi_msg_lb_conf_reply;

static inline void vapi_msg_lb_conf_reply_payload_hton(vapi_payload_lb_conf_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lb_conf_reply_payload_ntoh(vapi_payload_lb_conf_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lb_conf_reply_hton(vapi_msg_lb_conf_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_conf_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lb_conf_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lb_conf_reply_ntoh(vapi_msg_lb_conf_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_conf_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lb_conf_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lb_conf_reply_msg_size(vapi_msg_lb_conf_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lb_conf_reply_msg_size(vapi_msg_lb_conf_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lb_conf_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_conf_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lb_conf_reply));
      return -1;
    }
  if (vapi_calc_lb_conf_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_conf_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lb_conf_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lb_conf_reply()
{
  static const char name[] = "lb_conf_reply";
  static const char name_with_crc[] = "lb_conf_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lb_conf_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lb_conf_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lb_conf_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lb_conf_reply_hton,
    (generic_swap_fn_t)vapi_msg_lb_conf_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lb_conf_reply = vapi_register_msg(&__vapi_metadata_lb_conf_reply);
  VAPI_DBG("Assigned msg id %d to lb_conf_reply", vapi_msg_id_lb_conf_reply);
}

static inline void vapi_set_vapi_msg_lb_conf_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lb_conf_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lb_conf_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lb_conf
#define defined_vapi_msg_lb_conf
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ip4_address ip4_src_address;
  vapi_type_ip6_address ip6_src_address;
  u32 sticky_buckets_per_core;
  u32 flow_timeout; 
} vapi_payload_lb_conf;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lb_conf payload;
} vapi_msg_lb_conf;

static inline void vapi_msg_lb_conf_payload_hton(vapi_payload_lb_conf *payload)
{
  payload->sticky_buckets_per_core = htobe32(payload->sticky_buckets_per_core);
  payload->flow_timeout = htobe32(payload->flow_timeout);
}

static inline void vapi_msg_lb_conf_payload_ntoh(vapi_payload_lb_conf *payload)
{
  payload->sticky_buckets_per_core = be32toh(payload->sticky_buckets_per_core);
  payload->flow_timeout = be32toh(payload->flow_timeout);
}

static inline void vapi_msg_lb_conf_hton(vapi_msg_lb_conf *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_conf'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lb_conf_payload_hton(&msg->payload);
}

static inline void vapi_msg_lb_conf_ntoh(vapi_msg_lb_conf *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_conf'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lb_conf_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lb_conf_msg_size(vapi_msg_lb_conf *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lb_conf_msg_size(vapi_msg_lb_conf *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lb_conf) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_conf' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lb_conf));
      return -1;
    }
  if (vapi_calc_lb_conf_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_conf' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lb_conf_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lb_conf* vapi_alloc_lb_conf(struct vapi_ctx_s *ctx)
{
  vapi_msg_lb_conf *msg = NULL;
  const size_t size = sizeof(vapi_msg_lb_conf);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lb_conf*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lb_conf);

  return msg;
}

static inline vapi_error_e vapi_lb_conf(struct vapi_ctx_s *ctx,
  vapi_msg_lb_conf *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lb_conf_reply *reply),
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
  vapi_msg_lb_conf_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lb_conf_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lb_conf_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lb_conf()
{
  static const char name[] = "lb_conf";
  static const char name_with_crc[] = "lb_conf_56cd3261";
  static vapi_message_desc_t __vapi_metadata_lb_conf = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lb_conf, payload),
    (verify_msg_size_fn_t)vapi_verify_lb_conf_msg_size,
    (generic_swap_fn_t)vapi_msg_lb_conf_hton,
    (generic_swap_fn_t)vapi_msg_lb_conf_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lb_conf = vapi_register_msg(&__vapi_metadata_lb_conf);
  VAPI_DBG("Assigned msg id %d to lb_conf", vapi_msg_id_lb_conf);
}
#endif

#ifndef defined_vapi_msg_lb_add_del_vip_reply
#define defined_vapi_msg_lb_add_del_vip_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lb_add_del_vip_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lb_add_del_vip_reply payload;
} vapi_msg_lb_add_del_vip_reply;

static inline void vapi_msg_lb_add_del_vip_reply_payload_hton(vapi_payload_lb_add_del_vip_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lb_add_del_vip_reply_payload_ntoh(vapi_payload_lb_add_del_vip_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lb_add_del_vip_reply_hton(vapi_msg_lb_add_del_vip_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_add_del_vip_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lb_add_del_vip_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lb_add_del_vip_reply_ntoh(vapi_msg_lb_add_del_vip_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_add_del_vip_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lb_add_del_vip_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lb_add_del_vip_reply_msg_size(vapi_msg_lb_add_del_vip_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lb_add_del_vip_reply_msg_size(vapi_msg_lb_add_del_vip_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lb_add_del_vip_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_add_del_vip_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lb_add_del_vip_reply));
      return -1;
    }
  if (vapi_calc_lb_add_del_vip_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_add_del_vip_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lb_add_del_vip_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lb_add_del_vip_reply()
{
  static const char name[] = "lb_add_del_vip_reply";
  static const char name_with_crc[] = "lb_add_del_vip_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lb_add_del_vip_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lb_add_del_vip_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lb_add_del_vip_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lb_add_del_vip_reply_hton,
    (generic_swap_fn_t)vapi_msg_lb_add_del_vip_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lb_add_del_vip_reply = vapi_register_msg(&__vapi_metadata_lb_add_del_vip_reply);
  VAPI_DBG("Assigned msg id %d to lb_add_del_vip_reply", vapi_msg_id_lb_add_del_vip_reply);
}

static inline void vapi_set_vapi_msg_lb_add_del_vip_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lb_add_del_vip_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lb_add_del_vip_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lb_add_del_vip
#define defined_vapi_msg_lb_add_del_vip
typedef struct __attribute__ ((__packed__)) {
  vapi_type_address_with_prefix pfx;
  u8 protocol;
  u16 port;
  vapi_enum_lb_encap_type encap;
  u8 dscp;
  vapi_enum_lb_srv_type type;
  u16 target_port;
  u16 node_port;
  u32 new_flows_table_length;
  bool is_del; 
} vapi_payload_lb_add_del_vip;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lb_add_del_vip payload;
} vapi_msg_lb_add_del_vip;

static inline void vapi_msg_lb_add_del_vip_payload_hton(vapi_payload_lb_add_del_vip *payload)
{
  payload->port = htobe16(payload->port);
  payload->encap = (vapi_enum_lb_encap_type)htobe32(payload->encap);
  payload->type = (vapi_enum_lb_srv_type)htobe32(payload->type);
  payload->target_port = htobe16(payload->target_port);
  payload->node_port = htobe16(payload->node_port);
  payload->new_flows_table_length = htobe32(payload->new_flows_table_length);
}

static inline void vapi_msg_lb_add_del_vip_payload_ntoh(vapi_payload_lb_add_del_vip *payload)
{
  payload->port = be16toh(payload->port);
  payload->encap = (vapi_enum_lb_encap_type)be32toh(payload->encap);
  payload->type = (vapi_enum_lb_srv_type)be32toh(payload->type);
  payload->target_port = be16toh(payload->target_port);
  payload->node_port = be16toh(payload->node_port);
  payload->new_flows_table_length = be32toh(payload->new_flows_table_length);
}

static inline void vapi_msg_lb_add_del_vip_hton(vapi_msg_lb_add_del_vip *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_add_del_vip'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lb_add_del_vip_payload_hton(&msg->payload);
}

static inline void vapi_msg_lb_add_del_vip_ntoh(vapi_msg_lb_add_del_vip *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_add_del_vip'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lb_add_del_vip_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lb_add_del_vip_msg_size(vapi_msg_lb_add_del_vip *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lb_add_del_vip_msg_size(vapi_msg_lb_add_del_vip *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lb_add_del_vip) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_add_del_vip' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lb_add_del_vip));
      return -1;
    }
  if (vapi_calc_lb_add_del_vip_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_add_del_vip' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lb_add_del_vip_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lb_add_del_vip* vapi_alloc_lb_add_del_vip(struct vapi_ctx_s *ctx)
{
  vapi_msg_lb_add_del_vip *msg = NULL;
  const size_t size = sizeof(vapi_msg_lb_add_del_vip);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lb_add_del_vip*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lb_add_del_vip);

  return msg;
}

static inline vapi_error_e vapi_lb_add_del_vip(struct vapi_ctx_s *ctx,
  vapi_msg_lb_add_del_vip *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lb_add_del_vip_reply *reply),
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
  vapi_msg_lb_add_del_vip_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lb_add_del_vip_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lb_add_del_vip_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lb_add_del_vip()
{
  static const char name[] = "lb_add_del_vip";
  static const char name_with_crc[] = "lb_add_del_vip_6fa569c7";
  static vapi_message_desc_t __vapi_metadata_lb_add_del_vip = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lb_add_del_vip, payload),
    (verify_msg_size_fn_t)vapi_verify_lb_add_del_vip_msg_size,
    (generic_swap_fn_t)vapi_msg_lb_add_del_vip_hton,
    (generic_swap_fn_t)vapi_msg_lb_add_del_vip_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lb_add_del_vip = vapi_register_msg(&__vapi_metadata_lb_add_del_vip);
  VAPI_DBG("Assigned msg id %d to lb_add_del_vip", vapi_msg_id_lb_add_del_vip);
}
#endif

#ifndef defined_vapi_msg_lb_add_del_vip_v2_reply
#define defined_vapi_msg_lb_add_del_vip_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lb_add_del_vip_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lb_add_del_vip_v2_reply payload;
} vapi_msg_lb_add_del_vip_v2_reply;

static inline void vapi_msg_lb_add_del_vip_v2_reply_payload_hton(vapi_payload_lb_add_del_vip_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lb_add_del_vip_v2_reply_payload_ntoh(vapi_payload_lb_add_del_vip_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lb_add_del_vip_v2_reply_hton(vapi_msg_lb_add_del_vip_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_add_del_vip_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lb_add_del_vip_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lb_add_del_vip_v2_reply_ntoh(vapi_msg_lb_add_del_vip_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_add_del_vip_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lb_add_del_vip_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lb_add_del_vip_v2_reply_msg_size(vapi_msg_lb_add_del_vip_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lb_add_del_vip_v2_reply_msg_size(vapi_msg_lb_add_del_vip_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lb_add_del_vip_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_add_del_vip_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lb_add_del_vip_v2_reply));
      return -1;
    }
  if (vapi_calc_lb_add_del_vip_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_add_del_vip_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lb_add_del_vip_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lb_add_del_vip_v2_reply()
{
  static const char name[] = "lb_add_del_vip_v2_reply";
  static const char name_with_crc[] = "lb_add_del_vip_v2_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lb_add_del_vip_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lb_add_del_vip_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lb_add_del_vip_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lb_add_del_vip_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_lb_add_del_vip_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lb_add_del_vip_v2_reply = vapi_register_msg(&__vapi_metadata_lb_add_del_vip_v2_reply);
  VAPI_DBG("Assigned msg id %d to lb_add_del_vip_v2_reply", vapi_msg_id_lb_add_del_vip_v2_reply);
}

static inline void vapi_set_vapi_msg_lb_add_del_vip_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lb_add_del_vip_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lb_add_del_vip_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lb_add_del_vip_v2
#define defined_vapi_msg_lb_add_del_vip_v2
typedef struct __attribute__ ((__packed__)) {
  vapi_type_address_with_prefix pfx;
  u8 protocol;
  u16 port;
  vapi_enum_lb_encap_type encap;
  u8 dscp;
  vapi_enum_lb_srv_type type;
  u16 target_port;
  u16 node_port;
  u32 new_flows_table_length;
  bool src_ip_sticky;
  bool is_del; 
} vapi_payload_lb_add_del_vip_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lb_add_del_vip_v2 payload;
} vapi_msg_lb_add_del_vip_v2;

static inline void vapi_msg_lb_add_del_vip_v2_payload_hton(vapi_payload_lb_add_del_vip_v2 *payload)
{
  payload->port = htobe16(payload->port);
  payload->encap = (vapi_enum_lb_encap_type)htobe32(payload->encap);
  payload->type = (vapi_enum_lb_srv_type)htobe32(payload->type);
  payload->target_port = htobe16(payload->target_port);
  payload->node_port = htobe16(payload->node_port);
  payload->new_flows_table_length = htobe32(payload->new_flows_table_length);
}

static inline void vapi_msg_lb_add_del_vip_v2_payload_ntoh(vapi_payload_lb_add_del_vip_v2 *payload)
{
  payload->port = be16toh(payload->port);
  payload->encap = (vapi_enum_lb_encap_type)be32toh(payload->encap);
  payload->type = (vapi_enum_lb_srv_type)be32toh(payload->type);
  payload->target_port = be16toh(payload->target_port);
  payload->node_port = be16toh(payload->node_port);
  payload->new_flows_table_length = be32toh(payload->new_flows_table_length);
}

static inline void vapi_msg_lb_add_del_vip_v2_hton(vapi_msg_lb_add_del_vip_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_add_del_vip_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lb_add_del_vip_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_lb_add_del_vip_v2_ntoh(vapi_msg_lb_add_del_vip_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_add_del_vip_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lb_add_del_vip_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lb_add_del_vip_v2_msg_size(vapi_msg_lb_add_del_vip_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lb_add_del_vip_v2_msg_size(vapi_msg_lb_add_del_vip_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lb_add_del_vip_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_add_del_vip_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lb_add_del_vip_v2));
      return -1;
    }
  if (vapi_calc_lb_add_del_vip_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_add_del_vip_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lb_add_del_vip_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lb_add_del_vip_v2* vapi_alloc_lb_add_del_vip_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_lb_add_del_vip_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_lb_add_del_vip_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lb_add_del_vip_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lb_add_del_vip_v2);

  return msg;
}

static inline vapi_error_e vapi_lb_add_del_vip_v2(struct vapi_ctx_s *ctx,
  vapi_msg_lb_add_del_vip_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lb_add_del_vip_v2_reply *reply),
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
  vapi_msg_lb_add_del_vip_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lb_add_del_vip_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lb_add_del_vip_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lb_add_del_vip_v2()
{
  static const char name[] = "lb_add_del_vip_v2";
  static const char name_with_crc[] = "lb_add_del_vip_v2_7c520e0f";
  static vapi_message_desc_t __vapi_metadata_lb_add_del_vip_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lb_add_del_vip_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_lb_add_del_vip_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_lb_add_del_vip_v2_hton,
    (generic_swap_fn_t)vapi_msg_lb_add_del_vip_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lb_add_del_vip_v2 = vapi_register_msg(&__vapi_metadata_lb_add_del_vip_v2);
  VAPI_DBG("Assigned msg id %d to lb_add_del_vip_v2", vapi_msg_id_lb_add_del_vip_v2);
}
#endif

#ifndef defined_vapi_msg_lb_add_del_as_reply
#define defined_vapi_msg_lb_add_del_as_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lb_add_del_as_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lb_add_del_as_reply payload;
} vapi_msg_lb_add_del_as_reply;

static inline void vapi_msg_lb_add_del_as_reply_payload_hton(vapi_payload_lb_add_del_as_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lb_add_del_as_reply_payload_ntoh(vapi_payload_lb_add_del_as_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lb_add_del_as_reply_hton(vapi_msg_lb_add_del_as_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_add_del_as_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lb_add_del_as_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lb_add_del_as_reply_ntoh(vapi_msg_lb_add_del_as_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_add_del_as_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lb_add_del_as_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lb_add_del_as_reply_msg_size(vapi_msg_lb_add_del_as_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lb_add_del_as_reply_msg_size(vapi_msg_lb_add_del_as_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lb_add_del_as_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_add_del_as_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lb_add_del_as_reply));
      return -1;
    }
  if (vapi_calc_lb_add_del_as_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_add_del_as_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lb_add_del_as_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lb_add_del_as_reply()
{
  static const char name[] = "lb_add_del_as_reply";
  static const char name_with_crc[] = "lb_add_del_as_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lb_add_del_as_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lb_add_del_as_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lb_add_del_as_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lb_add_del_as_reply_hton,
    (generic_swap_fn_t)vapi_msg_lb_add_del_as_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lb_add_del_as_reply = vapi_register_msg(&__vapi_metadata_lb_add_del_as_reply);
  VAPI_DBG("Assigned msg id %d to lb_add_del_as_reply", vapi_msg_id_lb_add_del_as_reply);
}

static inline void vapi_set_vapi_msg_lb_add_del_as_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lb_add_del_as_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lb_add_del_as_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lb_add_del_as
#define defined_vapi_msg_lb_add_del_as
typedef struct __attribute__ ((__packed__)) {
  vapi_type_address_with_prefix pfx;
  u8 protocol;
  u16 port;
  vapi_type_address as_address;
  bool is_del;
  bool is_flush; 
} vapi_payload_lb_add_del_as;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lb_add_del_as payload;
} vapi_msg_lb_add_del_as;

static inline void vapi_msg_lb_add_del_as_payload_hton(vapi_payload_lb_add_del_as *payload)
{
  payload->port = htobe16(payload->port);
}

static inline void vapi_msg_lb_add_del_as_payload_ntoh(vapi_payload_lb_add_del_as *payload)
{
  payload->port = be16toh(payload->port);
}

static inline void vapi_msg_lb_add_del_as_hton(vapi_msg_lb_add_del_as *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_add_del_as'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lb_add_del_as_payload_hton(&msg->payload);
}

static inline void vapi_msg_lb_add_del_as_ntoh(vapi_msg_lb_add_del_as *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_add_del_as'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lb_add_del_as_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lb_add_del_as_msg_size(vapi_msg_lb_add_del_as *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lb_add_del_as_msg_size(vapi_msg_lb_add_del_as *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lb_add_del_as) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_add_del_as' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lb_add_del_as));
      return -1;
    }
  if (vapi_calc_lb_add_del_as_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_add_del_as' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lb_add_del_as_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lb_add_del_as* vapi_alloc_lb_add_del_as(struct vapi_ctx_s *ctx)
{
  vapi_msg_lb_add_del_as *msg = NULL;
  const size_t size = sizeof(vapi_msg_lb_add_del_as);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lb_add_del_as*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lb_add_del_as);

  return msg;
}

static inline vapi_error_e vapi_lb_add_del_as(struct vapi_ctx_s *ctx,
  vapi_msg_lb_add_del_as *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lb_add_del_as_reply *reply),
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
  vapi_msg_lb_add_del_as_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lb_add_del_as_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lb_add_del_as_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lb_add_del_as()
{
  static const char name[] = "lb_add_del_as";
  static const char name_with_crc[] = "lb_add_del_as_35d72500";
  static vapi_message_desc_t __vapi_metadata_lb_add_del_as = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lb_add_del_as, payload),
    (verify_msg_size_fn_t)vapi_verify_lb_add_del_as_msg_size,
    (generic_swap_fn_t)vapi_msg_lb_add_del_as_hton,
    (generic_swap_fn_t)vapi_msg_lb_add_del_as_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lb_add_del_as = vapi_register_msg(&__vapi_metadata_lb_add_del_as);
  VAPI_DBG("Assigned msg id %d to lb_add_del_as", vapi_msg_id_lb_add_del_as);
}
#endif

#ifndef defined_vapi_msg_lb_flush_vip_reply
#define defined_vapi_msg_lb_flush_vip_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lb_flush_vip_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lb_flush_vip_reply payload;
} vapi_msg_lb_flush_vip_reply;

static inline void vapi_msg_lb_flush_vip_reply_payload_hton(vapi_payload_lb_flush_vip_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lb_flush_vip_reply_payload_ntoh(vapi_payload_lb_flush_vip_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lb_flush_vip_reply_hton(vapi_msg_lb_flush_vip_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_flush_vip_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lb_flush_vip_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lb_flush_vip_reply_ntoh(vapi_msg_lb_flush_vip_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_flush_vip_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lb_flush_vip_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lb_flush_vip_reply_msg_size(vapi_msg_lb_flush_vip_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lb_flush_vip_reply_msg_size(vapi_msg_lb_flush_vip_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lb_flush_vip_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_flush_vip_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lb_flush_vip_reply));
      return -1;
    }
  if (vapi_calc_lb_flush_vip_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_flush_vip_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lb_flush_vip_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lb_flush_vip_reply()
{
  static const char name[] = "lb_flush_vip_reply";
  static const char name_with_crc[] = "lb_flush_vip_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lb_flush_vip_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lb_flush_vip_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lb_flush_vip_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lb_flush_vip_reply_hton,
    (generic_swap_fn_t)vapi_msg_lb_flush_vip_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lb_flush_vip_reply = vapi_register_msg(&__vapi_metadata_lb_flush_vip_reply);
  VAPI_DBG("Assigned msg id %d to lb_flush_vip_reply", vapi_msg_id_lb_flush_vip_reply);
}

static inline void vapi_set_vapi_msg_lb_flush_vip_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lb_flush_vip_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lb_flush_vip_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lb_flush_vip
#define defined_vapi_msg_lb_flush_vip
typedef struct __attribute__ ((__packed__)) {
  vapi_type_address_with_prefix pfx;
  u8 protocol;
  u16 port; 
} vapi_payload_lb_flush_vip;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lb_flush_vip payload;
} vapi_msg_lb_flush_vip;

static inline void vapi_msg_lb_flush_vip_payload_hton(vapi_payload_lb_flush_vip *payload)
{
  payload->port = htobe16(payload->port);
}

static inline void vapi_msg_lb_flush_vip_payload_ntoh(vapi_payload_lb_flush_vip *payload)
{
  payload->port = be16toh(payload->port);
}

static inline void vapi_msg_lb_flush_vip_hton(vapi_msg_lb_flush_vip *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_flush_vip'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lb_flush_vip_payload_hton(&msg->payload);
}

static inline void vapi_msg_lb_flush_vip_ntoh(vapi_msg_lb_flush_vip *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_flush_vip'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lb_flush_vip_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lb_flush_vip_msg_size(vapi_msg_lb_flush_vip *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lb_flush_vip_msg_size(vapi_msg_lb_flush_vip *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lb_flush_vip) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_flush_vip' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lb_flush_vip));
      return -1;
    }
  if (vapi_calc_lb_flush_vip_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_flush_vip' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lb_flush_vip_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lb_flush_vip* vapi_alloc_lb_flush_vip(struct vapi_ctx_s *ctx)
{
  vapi_msg_lb_flush_vip *msg = NULL;
  const size_t size = sizeof(vapi_msg_lb_flush_vip);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lb_flush_vip*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lb_flush_vip);

  return msg;
}

static inline vapi_error_e vapi_lb_flush_vip(struct vapi_ctx_s *ctx,
  vapi_msg_lb_flush_vip *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lb_flush_vip_reply *reply),
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
  vapi_msg_lb_flush_vip_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lb_flush_vip_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lb_flush_vip_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lb_flush_vip()
{
  static const char name[] = "lb_flush_vip";
  static const char name_with_crc[] = "lb_flush_vip_1063f819";
  static vapi_message_desc_t __vapi_metadata_lb_flush_vip = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lb_flush_vip, payload),
    (verify_msg_size_fn_t)vapi_verify_lb_flush_vip_msg_size,
    (generic_swap_fn_t)vapi_msg_lb_flush_vip_hton,
    (generic_swap_fn_t)vapi_msg_lb_flush_vip_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lb_flush_vip = vapi_register_msg(&__vapi_metadata_lb_flush_vip);
  VAPI_DBG("Assigned msg id %d to lb_flush_vip", vapi_msg_id_lb_flush_vip);
}
#endif

#ifndef defined_vapi_msg_lb_vip_details
#define defined_vapi_msg_lb_vip_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_lb_vip vip;
  vapi_enum_lb_encap_type encap;
  vapi_enum_ip_dscp dscp;
  vapi_enum_lb_srv_type srv_type;
  u16 target_port;
  u16 flow_table_length; 
} vapi_payload_lb_vip_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lb_vip_details payload;
} vapi_msg_lb_vip_details;

static inline void vapi_msg_lb_vip_details_payload_hton(vapi_payload_lb_vip_details *payload)
{
  vapi_type_lb_vip_hton(&payload->vip);
  payload->encap = (vapi_enum_lb_encap_type)htobe32(payload->encap);
  payload->srv_type = (vapi_enum_lb_srv_type)htobe32(payload->srv_type);
  payload->target_port = htobe16(payload->target_port);
  payload->flow_table_length = htobe16(payload->flow_table_length);
}

static inline void vapi_msg_lb_vip_details_payload_ntoh(vapi_payload_lb_vip_details *payload)
{
  vapi_type_lb_vip_ntoh(&payload->vip);
  payload->encap = (vapi_enum_lb_encap_type)be32toh(payload->encap);
  payload->srv_type = (vapi_enum_lb_srv_type)be32toh(payload->srv_type);
  payload->target_port = be16toh(payload->target_port);
  payload->flow_table_length = be16toh(payload->flow_table_length);
}

static inline void vapi_msg_lb_vip_details_hton(vapi_msg_lb_vip_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_vip_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lb_vip_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_lb_vip_details_ntoh(vapi_msg_lb_vip_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_vip_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lb_vip_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lb_vip_details_msg_size(vapi_msg_lb_vip_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lb_vip_details_msg_size(vapi_msg_lb_vip_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lb_vip_details) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_vip_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lb_vip_details));
      return -1;
    }
  if (vapi_calc_lb_vip_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_vip_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lb_vip_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lb_vip_details()
{
  static const char name[] = "lb_vip_details";
  static const char name_with_crc[] = "lb_vip_details_1329ec9b";
  static vapi_message_desc_t __vapi_metadata_lb_vip_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lb_vip_details, payload),
    (verify_msg_size_fn_t)vapi_verify_lb_vip_details_msg_size,
    (generic_swap_fn_t)vapi_msg_lb_vip_details_hton,
    (generic_swap_fn_t)vapi_msg_lb_vip_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lb_vip_details = vapi_register_msg(&__vapi_metadata_lb_vip_details);
  VAPI_DBG("Assigned msg id %d to lb_vip_details", vapi_msg_id_lb_vip_details);
}

static inline void vapi_set_vapi_msg_lb_vip_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lb_vip_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lb_vip_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lb_vip_dump
#define defined_vapi_msg_lb_vip_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_address_with_prefix pfx;
  vapi_type_prefix_matcher pfx_matcher;
  u8 protocol;
  u16 port; 
} vapi_payload_lb_vip_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lb_vip_dump payload;
} vapi_msg_lb_vip_dump;

static inline void vapi_msg_lb_vip_dump_payload_hton(vapi_payload_lb_vip_dump *payload)
{
  payload->port = htobe16(payload->port);
}

static inline void vapi_msg_lb_vip_dump_payload_ntoh(vapi_payload_lb_vip_dump *payload)
{
  payload->port = be16toh(payload->port);
}

static inline void vapi_msg_lb_vip_dump_hton(vapi_msg_lb_vip_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_vip_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lb_vip_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_lb_vip_dump_ntoh(vapi_msg_lb_vip_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_vip_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lb_vip_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lb_vip_dump_msg_size(vapi_msg_lb_vip_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lb_vip_dump_msg_size(vapi_msg_lb_vip_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lb_vip_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_vip_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lb_vip_dump));
      return -1;
    }
  if (vapi_calc_lb_vip_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_vip_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lb_vip_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lb_vip_dump* vapi_alloc_lb_vip_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_lb_vip_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_lb_vip_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lb_vip_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lb_vip_dump);

  return msg;
}

static inline vapi_error_e vapi_lb_vip_dump(struct vapi_ctx_s *ctx,
  vapi_msg_lb_vip_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lb_vip_details *reply),
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
  vapi_msg_lb_vip_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lb_vip_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_lb_vip_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lb_vip_dump()
{
  static const char name[] = "lb_vip_dump";
  static const char name_with_crc[] = "lb_vip_dump_56110cb7";
  static vapi_message_desc_t __vapi_metadata_lb_vip_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lb_vip_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_lb_vip_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_lb_vip_dump_hton,
    (generic_swap_fn_t)vapi_msg_lb_vip_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lb_vip_dump = vapi_register_msg(&__vapi_metadata_lb_vip_dump);
  VAPI_DBG("Assigned msg id %d to lb_vip_dump", vapi_msg_id_lb_vip_dump);
}
#endif

#ifndef defined_vapi_msg_lb_as_details
#define defined_vapi_msg_lb_as_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_lb_vip vip;
  vapi_type_address app_srv;
  u8 flags;
  u32 in_use_since; 
} vapi_payload_lb_as_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lb_as_details payload;
} vapi_msg_lb_as_details;

static inline void vapi_msg_lb_as_details_payload_hton(vapi_payload_lb_as_details *payload)
{
  vapi_type_lb_vip_hton(&payload->vip);
  payload->in_use_since = htobe32(payload->in_use_since);
}

static inline void vapi_msg_lb_as_details_payload_ntoh(vapi_payload_lb_as_details *payload)
{
  vapi_type_lb_vip_ntoh(&payload->vip);
  payload->in_use_since = be32toh(payload->in_use_since);
}

static inline void vapi_msg_lb_as_details_hton(vapi_msg_lb_as_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_as_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lb_as_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_lb_as_details_ntoh(vapi_msg_lb_as_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_as_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lb_as_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lb_as_details_msg_size(vapi_msg_lb_as_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lb_as_details_msg_size(vapi_msg_lb_as_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lb_as_details) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_as_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lb_as_details));
      return -1;
    }
  if (vapi_calc_lb_as_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_as_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lb_as_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lb_as_details()
{
  static const char name[] = "lb_as_details";
  static const char name_with_crc[] = "lb_as_details_8d24c29e";
  static vapi_message_desc_t __vapi_metadata_lb_as_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lb_as_details, payload),
    (verify_msg_size_fn_t)vapi_verify_lb_as_details_msg_size,
    (generic_swap_fn_t)vapi_msg_lb_as_details_hton,
    (generic_swap_fn_t)vapi_msg_lb_as_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lb_as_details = vapi_register_msg(&__vapi_metadata_lb_as_details);
  VAPI_DBG("Assigned msg id %d to lb_as_details", vapi_msg_id_lb_as_details);
}

static inline void vapi_set_vapi_msg_lb_as_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lb_as_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lb_as_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lb_as_dump
#define defined_vapi_msg_lb_as_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_address_with_prefix pfx;
  u8 protocol;
  u16 port; 
} vapi_payload_lb_as_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lb_as_dump payload;
} vapi_msg_lb_as_dump;

static inline void vapi_msg_lb_as_dump_payload_hton(vapi_payload_lb_as_dump *payload)
{
  payload->port = htobe16(payload->port);
}

static inline void vapi_msg_lb_as_dump_payload_ntoh(vapi_payload_lb_as_dump *payload)
{
  payload->port = be16toh(payload->port);
}

static inline void vapi_msg_lb_as_dump_hton(vapi_msg_lb_as_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_as_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lb_as_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_lb_as_dump_ntoh(vapi_msg_lb_as_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_as_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lb_as_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lb_as_dump_msg_size(vapi_msg_lb_as_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lb_as_dump_msg_size(vapi_msg_lb_as_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lb_as_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_as_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lb_as_dump));
      return -1;
    }
  if (vapi_calc_lb_as_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_as_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lb_as_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lb_as_dump* vapi_alloc_lb_as_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_lb_as_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_lb_as_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lb_as_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lb_as_dump);

  return msg;
}

static inline vapi_error_e vapi_lb_as_dump(struct vapi_ctx_s *ctx,
  vapi_msg_lb_as_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lb_as_details *reply),
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
  vapi_msg_lb_as_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lb_as_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_lb_as_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lb_as_dump()
{
  static const char name[] = "lb_as_dump";
  static const char name_with_crc[] = "lb_as_dump_1063f819";
  static vapi_message_desc_t __vapi_metadata_lb_as_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lb_as_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_lb_as_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_lb_as_dump_hton,
    (generic_swap_fn_t)vapi_msg_lb_as_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lb_as_dump = vapi_register_msg(&__vapi_metadata_lb_as_dump);
  VAPI_DBG("Assigned msg id %d to lb_as_dump", vapi_msg_id_lb_as_dump);
}
#endif

#ifndef defined_vapi_msg_lb_add_del_intf_nat4_reply
#define defined_vapi_msg_lb_add_del_intf_nat4_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lb_add_del_intf_nat4_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lb_add_del_intf_nat4_reply payload;
} vapi_msg_lb_add_del_intf_nat4_reply;

static inline void vapi_msg_lb_add_del_intf_nat4_reply_payload_hton(vapi_payload_lb_add_del_intf_nat4_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lb_add_del_intf_nat4_reply_payload_ntoh(vapi_payload_lb_add_del_intf_nat4_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lb_add_del_intf_nat4_reply_hton(vapi_msg_lb_add_del_intf_nat4_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_add_del_intf_nat4_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lb_add_del_intf_nat4_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lb_add_del_intf_nat4_reply_ntoh(vapi_msg_lb_add_del_intf_nat4_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_add_del_intf_nat4_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lb_add_del_intf_nat4_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lb_add_del_intf_nat4_reply_msg_size(vapi_msg_lb_add_del_intf_nat4_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lb_add_del_intf_nat4_reply_msg_size(vapi_msg_lb_add_del_intf_nat4_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lb_add_del_intf_nat4_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_add_del_intf_nat4_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lb_add_del_intf_nat4_reply));
      return -1;
    }
  if (vapi_calc_lb_add_del_intf_nat4_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_add_del_intf_nat4_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lb_add_del_intf_nat4_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lb_add_del_intf_nat4_reply()
{
  static const char name[] = "lb_add_del_intf_nat4_reply";
  static const char name_with_crc[] = "lb_add_del_intf_nat4_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lb_add_del_intf_nat4_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lb_add_del_intf_nat4_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lb_add_del_intf_nat4_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lb_add_del_intf_nat4_reply_hton,
    (generic_swap_fn_t)vapi_msg_lb_add_del_intf_nat4_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lb_add_del_intf_nat4_reply = vapi_register_msg(&__vapi_metadata_lb_add_del_intf_nat4_reply);
  VAPI_DBG("Assigned msg id %d to lb_add_del_intf_nat4_reply", vapi_msg_id_lb_add_del_intf_nat4_reply);
}

static inline void vapi_set_vapi_msg_lb_add_del_intf_nat4_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lb_add_del_intf_nat4_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lb_add_del_intf_nat4_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lb_add_del_intf_nat4
#define defined_vapi_msg_lb_add_del_intf_nat4
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_lb_add_del_intf_nat4;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lb_add_del_intf_nat4 payload;
} vapi_msg_lb_add_del_intf_nat4;

static inline void vapi_msg_lb_add_del_intf_nat4_payload_hton(vapi_payload_lb_add_del_intf_nat4 *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_lb_add_del_intf_nat4_payload_ntoh(vapi_payload_lb_add_del_intf_nat4 *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_lb_add_del_intf_nat4_hton(vapi_msg_lb_add_del_intf_nat4 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_add_del_intf_nat4'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lb_add_del_intf_nat4_payload_hton(&msg->payload);
}

static inline void vapi_msg_lb_add_del_intf_nat4_ntoh(vapi_msg_lb_add_del_intf_nat4 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_add_del_intf_nat4'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lb_add_del_intf_nat4_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lb_add_del_intf_nat4_msg_size(vapi_msg_lb_add_del_intf_nat4 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lb_add_del_intf_nat4_msg_size(vapi_msg_lb_add_del_intf_nat4 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lb_add_del_intf_nat4) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_add_del_intf_nat4' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lb_add_del_intf_nat4));
      return -1;
    }
  if (vapi_calc_lb_add_del_intf_nat4_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_add_del_intf_nat4' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lb_add_del_intf_nat4_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lb_add_del_intf_nat4* vapi_alloc_lb_add_del_intf_nat4(struct vapi_ctx_s *ctx)
{
  vapi_msg_lb_add_del_intf_nat4 *msg = NULL;
  const size_t size = sizeof(vapi_msg_lb_add_del_intf_nat4);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lb_add_del_intf_nat4*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lb_add_del_intf_nat4);

  return msg;
}

static inline vapi_error_e vapi_lb_add_del_intf_nat4(struct vapi_ctx_s *ctx,
  vapi_msg_lb_add_del_intf_nat4 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lb_add_del_intf_nat4_reply *reply),
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
  vapi_msg_lb_add_del_intf_nat4_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lb_add_del_intf_nat4_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lb_add_del_intf_nat4_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lb_add_del_intf_nat4()
{
  static const char name[] = "lb_add_del_intf_nat4";
  static const char name_with_crc[] = "lb_add_del_intf_nat4_47d6e753";
  static vapi_message_desc_t __vapi_metadata_lb_add_del_intf_nat4 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lb_add_del_intf_nat4, payload),
    (verify_msg_size_fn_t)vapi_verify_lb_add_del_intf_nat4_msg_size,
    (generic_swap_fn_t)vapi_msg_lb_add_del_intf_nat4_hton,
    (generic_swap_fn_t)vapi_msg_lb_add_del_intf_nat4_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lb_add_del_intf_nat4 = vapi_register_msg(&__vapi_metadata_lb_add_del_intf_nat4);
  VAPI_DBG("Assigned msg id %d to lb_add_del_intf_nat4", vapi_msg_id_lb_add_del_intf_nat4);
}
#endif

#ifndef defined_vapi_msg_lb_add_del_intf_nat6_reply
#define defined_vapi_msg_lb_add_del_intf_nat6_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_lb_add_del_intf_nat6_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_lb_add_del_intf_nat6_reply payload;
} vapi_msg_lb_add_del_intf_nat6_reply;

static inline void vapi_msg_lb_add_del_intf_nat6_reply_payload_hton(vapi_payload_lb_add_del_intf_nat6_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_lb_add_del_intf_nat6_reply_payload_ntoh(vapi_payload_lb_add_del_intf_nat6_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_lb_add_del_intf_nat6_reply_hton(vapi_msg_lb_add_del_intf_nat6_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_add_del_intf_nat6_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_lb_add_del_intf_nat6_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_lb_add_del_intf_nat6_reply_ntoh(vapi_msg_lb_add_del_intf_nat6_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_add_del_intf_nat6_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_lb_add_del_intf_nat6_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lb_add_del_intf_nat6_reply_msg_size(vapi_msg_lb_add_del_intf_nat6_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lb_add_del_intf_nat6_reply_msg_size(vapi_msg_lb_add_del_intf_nat6_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lb_add_del_intf_nat6_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_add_del_intf_nat6_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lb_add_del_intf_nat6_reply));
      return -1;
    }
  if (vapi_calc_lb_add_del_intf_nat6_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_add_del_intf_nat6_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lb_add_del_intf_nat6_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_lb_add_del_intf_nat6_reply()
{
  static const char name[] = "lb_add_del_intf_nat6_reply";
  static const char name_with_crc[] = "lb_add_del_intf_nat6_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_lb_add_del_intf_nat6_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_lb_add_del_intf_nat6_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_lb_add_del_intf_nat6_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_lb_add_del_intf_nat6_reply_hton,
    (generic_swap_fn_t)vapi_msg_lb_add_del_intf_nat6_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lb_add_del_intf_nat6_reply = vapi_register_msg(&__vapi_metadata_lb_add_del_intf_nat6_reply);
  VAPI_DBG("Assigned msg id %d to lb_add_del_intf_nat6_reply", vapi_msg_id_lb_add_del_intf_nat6_reply);
}

static inline void vapi_set_vapi_msg_lb_add_del_intf_nat6_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_lb_add_del_intf_nat6_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_lb_add_del_intf_nat6_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_lb_add_del_intf_nat6
#define defined_vapi_msg_lb_add_del_intf_nat6
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_lb_add_del_intf_nat6;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_lb_add_del_intf_nat6 payload;
} vapi_msg_lb_add_del_intf_nat6;

static inline void vapi_msg_lb_add_del_intf_nat6_payload_hton(vapi_payload_lb_add_del_intf_nat6 *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_lb_add_del_intf_nat6_payload_ntoh(vapi_payload_lb_add_del_intf_nat6 *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_lb_add_del_intf_nat6_hton(vapi_msg_lb_add_del_intf_nat6 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_add_del_intf_nat6'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_lb_add_del_intf_nat6_payload_hton(&msg->payload);
}

static inline void vapi_msg_lb_add_del_intf_nat6_ntoh(vapi_msg_lb_add_del_intf_nat6 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_lb_add_del_intf_nat6'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_lb_add_del_intf_nat6_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_lb_add_del_intf_nat6_msg_size(vapi_msg_lb_add_del_intf_nat6 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_lb_add_del_intf_nat6_msg_size(vapi_msg_lb_add_del_intf_nat6 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_lb_add_del_intf_nat6) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_add_del_intf_nat6' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_lb_add_del_intf_nat6));
      return -1;
    }
  if (vapi_calc_lb_add_del_intf_nat6_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'lb_add_del_intf_nat6' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_lb_add_del_intf_nat6_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_lb_add_del_intf_nat6* vapi_alloc_lb_add_del_intf_nat6(struct vapi_ctx_s *ctx)
{
  vapi_msg_lb_add_del_intf_nat6 *msg = NULL;
  const size_t size = sizeof(vapi_msg_lb_add_del_intf_nat6);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_lb_add_del_intf_nat6*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_lb_add_del_intf_nat6);

  return msg;
}

static inline vapi_error_e vapi_lb_add_del_intf_nat6(struct vapi_ctx_s *ctx,
  vapi_msg_lb_add_del_intf_nat6 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_lb_add_del_intf_nat6_reply *reply),
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
  vapi_msg_lb_add_del_intf_nat6_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_lb_add_del_intf_nat6_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_lb_add_del_intf_nat6_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_lb_add_del_intf_nat6()
{
  static const char name[] = "lb_add_del_intf_nat6";
  static const char name_with_crc[] = "lb_add_del_intf_nat6_47d6e753";
  static vapi_message_desc_t __vapi_metadata_lb_add_del_intf_nat6 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_lb_add_del_intf_nat6, payload),
    (verify_msg_size_fn_t)vapi_verify_lb_add_del_intf_nat6_msg_size,
    (generic_swap_fn_t)vapi_msg_lb_add_del_intf_nat6_hton,
    (generic_swap_fn_t)vapi_msg_lb_add_del_intf_nat6_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_lb_add_del_intf_nat6 = vapi_register_msg(&__vapi_metadata_lb_add_del_intf_nat6);
  VAPI_DBG("Assigned msg id %d to lb_add_del_intf_nat6", vapi_msg_id_lb_add_del_intf_nat6);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
