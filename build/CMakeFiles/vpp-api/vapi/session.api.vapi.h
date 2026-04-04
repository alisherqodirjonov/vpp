#ifndef __included_session_api_json
#define __included_session_api_json

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

extern vapi_msg_id_t vapi_msg_id_app_attach;
extern vapi_msg_id_t vapi_msg_id_app_attach_reply;
extern vapi_msg_id_t vapi_msg_id_application_detach;
extern vapi_msg_id_t vapi_msg_id_application_detach_reply;
extern vapi_msg_id_t vapi_msg_id_app_add_cert_key_pair;
extern vapi_msg_id_t vapi_msg_id_app_add_cert_key_pair_reply;
extern vapi_msg_id_t vapi_msg_id_app_del_cert_key_pair;
extern vapi_msg_id_t vapi_msg_id_app_del_cert_key_pair_reply;
extern vapi_msg_id_t vapi_msg_id_app_worker_add_del;
extern vapi_msg_id_t vapi_msg_id_app_worker_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_session_enable_disable;
extern vapi_msg_id_t vapi_msg_id_session_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_session_enable_disable_v2;
extern vapi_msg_id_t vapi_msg_id_session_enable_disable_v2_reply;
extern vapi_msg_id_t vapi_msg_id_session_sapi_enable_disable;
extern vapi_msg_id_t vapi_msg_id_session_sapi_enable_disable_reply;
extern vapi_msg_id_t vapi_msg_id_app_namespace_add_del;
extern vapi_msg_id_t vapi_msg_id_app_namespace_add_del_v4;
extern vapi_msg_id_t vapi_msg_id_app_namespace_add_del_v4_reply;
extern vapi_msg_id_t vapi_msg_id_app_namespace_add_del_v2;
extern vapi_msg_id_t vapi_msg_id_app_namespace_add_del_v3;
extern vapi_msg_id_t vapi_msg_id_app_namespace_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_app_namespace_add_del_v2_reply;
extern vapi_msg_id_t vapi_msg_id_app_namespace_add_del_v3_reply;
extern vapi_msg_id_t vapi_msg_id_session_rule_add_del;
extern vapi_msg_id_t vapi_msg_id_session_rule_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_session_rules_dump;
extern vapi_msg_id_t vapi_msg_id_session_rules_details;
extern vapi_msg_id_t vapi_msg_id_session_rules_v2_dump;
extern vapi_msg_id_t vapi_msg_id_session_rules_v2_details;
extern vapi_msg_id_t vapi_msg_id_session_sdl_add_del;
extern vapi_msg_id_t vapi_msg_id_session_sdl_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_session_sdl_add_del_v2;
extern vapi_msg_id_t vapi_msg_id_session_sdl_add_del_v2_reply;
extern vapi_msg_id_t vapi_msg_id_session_sdl_dump;
extern vapi_msg_id_t vapi_msg_id_session_sdl_details;
extern vapi_msg_id_t vapi_msg_id_session_sdl_v2_dump;
extern vapi_msg_id_t vapi_msg_id_session_sdl_v2_details;
extern vapi_msg_id_t vapi_msg_id_session_sdl_v3_dump;
extern vapi_msg_id_t vapi_msg_id_session_sdl_v3_details;

#define DEFINE_VAPI_MSG_IDS_SESSION_API_JSON\
  vapi_msg_id_t vapi_msg_id_app_attach;\
  vapi_msg_id_t vapi_msg_id_app_attach_reply;\
  vapi_msg_id_t vapi_msg_id_application_detach;\
  vapi_msg_id_t vapi_msg_id_application_detach_reply;\
  vapi_msg_id_t vapi_msg_id_app_add_cert_key_pair;\
  vapi_msg_id_t vapi_msg_id_app_add_cert_key_pair_reply;\
  vapi_msg_id_t vapi_msg_id_app_del_cert_key_pair;\
  vapi_msg_id_t vapi_msg_id_app_del_cert_key_pair_reply;\
  vapi_msg_id_t vapi_msg_id_app_worker_add_del;\
  vapi_msg_id_t vapi_msg_id_app_worker_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_session_enable_disable;\
  vapi_msg_id_t vapi_msg_id_session_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_session_enable_disable_v2;\
  vapi_msg_id_t vapi_msg_id_session_enable_disable_v2_reply;\
  vapi_msg_id_t vapi_msg_id_session_sapi_enable_disable;\
  vapi_msg_id_t vapi_msg_id_session_sapi_enable_disable_reply;\
  vapi_msg_id_t vapi_msg_id_app_namespace_add_del;\
  vapi_msg_id_t vapi_msg_id_app_namespace_add_del_v4;\
  vapi_msg_id_t vapi_msg_id_app_namespace_add_del_v4_reply;\
  vapi_msg_id_t vapi_msg_id_app_namespace_add_del_v2;\
  vapi_msg_id_t vapi_msg_id_app_namespace_add_del_v3;\
  vapi_msg_id_t vapi_msg_id_app_namespace_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_app_namespace_add_del_v2_reply;\
  vapi_msg_id_t vapi_msg_id_app_namespace_add_del_v3_reply;\
  vapi_msg_id_t vapi_msg_id_session_rule_add_del;\
  vapi_msg_id_t vapi_msg_id_session_rule_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_session_rules_dump;\
  vapi_msg_id_t vapi_msg_id_session_rules_details;\
  vapi_msg_id_t vapi_msg_id_session_rules_v2_dump;\
  vapi_msg_id_t vapi_msg_id_session_rules_v2_details;\
  vapi_msg_id_t vapi_msg_id_session_sdl_add_del;\
  vapi_msg_id_t vapi_msg_id_session_sdl_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_session_sdl_add_del_v2;\
  vapi_msg_id_t vapi_msg_id_session_sdl_add_del_v2_reply;\
  vapi_msg_id_t vapi_msg_id_session_sdl_dump;\
  vapi_msg_id_t vapi_msg_id_session_sdl_details;\
  vapi_msg_id_t vapi_msg_id_session_sdl_v2_dump;\
  vapi_msg_id_t vapi_msg_id_session_sdl_v2_details;\
  vapi_msg_id_t vapi_msg_id_session_sdl_v3_dump;\
  vapi_msg_id_t vapi_msg_id_session_sdl_v3_details;


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

#ifndef defined_vapi_enum_transport_proto
#define defined_vapi_enum_transport_proto
typedef enum {
  TRANSPORT_PROTO_API_TCP = 0,
  TRANSPORT_PROTO_API_UDP = 1,
  TRANSPORT_PROTO_API_NONE = 2,
  TRANSPORT_PROTO_API_TLS = 3,
  TRANSPORT_PROTO_API_QUIC = 4,
} __attribute__((packed)) vapi_enum_transport_proto;

#endif

#ifndef defined_vapi_enum_rt_backend_engine
#define defined_vapi_enum_rt_backend_engine
typedef enum {
  RT_BACKEND_ENGINE_API_DISABLE = 0,
  RT_BACKEND_ENGINE_API_RULE_TABLE = 1,
  RT_BACKEND_ENGINE_API_NONE = 2,
  RT_BACKEND_ENGINE_API_SDL = 3,
} __attribute__((packed)) vapi_enum_rt_backend_engine;

#endif

#ifndef defined_vapi_enum_session_rule_scope
#define defined_vapi_enum_session_rule_scope
typedef enum {
  SESSION_RULE_SCOPE_API_GLOBAL = 0,
  SESSION_RULE_SCOPE_API_LOCAL = 1,
  SESSION_RULE_SCOPE_API_BOTH = 2,
}  vapi_enum_session_rule_scope;

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

#ifndef defined_vapi_type_sdl_rule
#define defined_vapi_type_sdl_rule
typedef struct __attribute__((__packed__)) {
  vapi_type_prefix lcl;
  u32 action_index;
  u8 tag[64];
} vapi_type_sdl_rule;

static inline void vapi_type_sdl_rule_hton(vapi_type_sdl_rule *msg)
{
  msg->action_index = htobe32(msg->action_index);
}

static inline void vapi_type_sdl_rule_ntoh(vapi_type_sdl_rule *msg)
{
  msg->action_index = be32toh(msg->action_index);
}
#endif

#ifndef defined_vapi_type_sdl_rule_v2
#define defined_vapi_type_sdl_rule_v2
typedef struct __attribute__((__packed__)) {
  vapi_type_prefix rmt;
  u32 action_index;
  u8 tag[64];
} vapi_type_sdl_rule_v2;

static inline void vapi_type_sdl_rule_v2_hton(vapi_type_sdl_rule_v2 *msg)
{
  msg->action_index = htobe32(msg->action_index);
}

static inline void vapi_type_sdl_rule_v2_ntoh(vapi_type_sdl_rule_v2 *msg)
{
  msg->action_index = be32toh(msg->action_index);
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

#ifndef defined_vapi_msg_app_attach_reply
#define defined_vapi_msg_app_attach_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u64 app_mq;
  u64 vpp_ctrl_mq;
  u8 vpp_ctrl_mq_thread;
  u32 app_index;
  u8 n_fds;
  u8 fd_flags;
  u32 segment_size;
  u64 segment_handle;
  vl_api_string_t segment_name; 
} vapi_payload_app_attach_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_app_attach_reply payload;
} vapi_msg_app_attach_reply;

static inline void vapi_msg_app_attach_reply_payload_hton(vapi_payload_app_attach_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->app_mq = htobe64(payload->app_mq);
  payload->vpp_ctrl_mq = htobe64(payload->vpp_ctrl_mq);
  payload->app_index = htobe32(payload->app_index);
  payload->segment_size = htobe32(payload->segment_size);
  payload->segment_handle = htobe64(payload->segment_handle);
  vl_api_string_t_hton(&payload->segment_name);
}

static inline void vapi_msg_app_attach_reply_payload_ntoh(vapi_payload_app_attach_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->app_mq = be64toh(payload->app_mq);
  payload->vpp_ctrl_mq = be64toh(payload->vpp_ctrl_mq);
  payload->app_index = be32toh(payload->app_index);
  payload->segment_size = be32toh(payload->segment_size);
  payload->segment_handle = be64toh(payload->segment_handle);
  vl_api_string_t_ntoh(&payload->segment_name);
}

static inline void vapi_msg_app_attach_reply_hton(vapi_msg_app_attach_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_attach_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_app_attach_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_app_attach_reply_ntoh(vapi_msg_app_attach_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_attach_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_app_attach_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_app_attach_reply_msg_size(vapi_msg_app_attach_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.segment_name.buf[0]) * msg->payload.segment_name.length;
}

static inline int vapi_verify_app_attach_reply_msg_size(vapi_msg_app_attach_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_app_attach_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'app_attach_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_app_attach_reply));
      return -1;
    }
  if (vapi_calc_app_attach_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'app_attach_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_app_attach_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_app_attach_reply()
{
  static const char name[] = "app_attach_reply";
  static const char name_with_crc[] = "app_attach_reply_5c89c3b0";
  static vapi_message_desc_t __vapi_metadata_app_attach_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_app_attach_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_app_attach_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_app_attach_reply_hton,
    (generic_swap_fn_t)vapi_msg_app_attach_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_app_attach_reply = vapi_register_msg(&__vapi_metadata_app_attach_reply);
  VAPI_DBG("Assigned msg id %d to app_attach_reply", vapi_msg_id_app_attach_reply);
}

static inline void vapi_set_vapi_msg_app_attach_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_app_attach_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_app_attach_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_app_attach
#define defined_vapi_msg_app_attach
typedef struct __attribute__ ((__packed__)) {
  u64 options[18];
  vl_api_string_t namespace_id; 
} vapi_payload_app_attach;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_app_attach payload;
} vapi_msg_app_attach;

static inline void vapi_msg_app_attach_payload_hton(vapi_payload_app_attach *payload)
{
  do { unsigned i; for (i = 0; i < 18; ++i) { payload->options[i] = htobe64(payload->options[i]); } } while(0);
  vl_api_string_t_hton(&payload->namespace_id);
}

static inline void vapi_msg_app_attach_payload_ntoh(vapi_payload_app_attach *payload)
{
  do { unsigned i; for (i = 0; i < 18; ++i) { payload->options[i] = be64toh(payload->options[i]); } } while(0);
  vl_api_string_t_ntoh(&payload->namespace_id);
}

static inline void vapi_msg_app_attach_hton(vapi_msg_app_attach *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_attach'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_app_attach_payload_hton(&msg->payload);
}

static inline void vapi_msg_app_attach_ntoh(vapi_msg_app_attach *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_attach'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_app_attach_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_app_attach_msg_size(vapi_msg_app_attach *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.namespace_id.buf[0]) * msg->payload.namespace_id.length;
}

static inline int vapi_verify_app_attach_msg_size(vapi_msg_app_attach *msg, uword buf_size)
{
  if (sizeof(vapi_msg_app_attach) > buf_size)
    {
      VAPI_ERR("Truncated 'app_attach' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_app_attach));
      return -1;
    }
  if (vapi_calc_app_attach_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'app_attach' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_app_attach_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_app_attach* vapi_alloc_app_attach(struct vapi_ctx_s *ctx, size_t namespace_id_buf_array_size)
{
  vapi_msg_app_attach *msg = NULL;
  const size_t size = sizeof(vapi_msg_app_attach) + sizeof(msg->payload.namespace_id.buf[0]) * namespace_id_buf_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_app_attach*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_app_attach);
  msg->payload.namespace_id.length = namespace_id_buf_array_size;

  return msg;
}

static inline vapi_error_e vapi_app_attach(struct vapi_ctx_s *ctx,
  vapi_msg_app_attach *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_app_attach_reply *reply),
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
  vapi_msg_app_attach_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_app_attach_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_app_attach_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_app_attach()
{
  static const char name[] = "app_attach";
  static const char name_with_crc[] = "app_attach_5f4a260d";
  static vapi_message_desc_t __vapi_metadata_app_attach = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_app_attach, payload),
    (verify_msg_size_fn_t)vapi_verify_app_attach_msg_size,
    (generic_swap_fn_t)vapi_msg_app_attach_hton,
    (generic_swap_fn_t)vapi_msg_app_attach_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_app_attach = vapi_register_msg(&__vapi_metadata_app_attach);
  VAPI_DBG("Assigned msg id %d to app_attach", vapi_msg_id_app_attach);
}
#endif

#ifndef defined_vapi_msg_application_detach_reply
#define defined_vapi_msg_application_detach_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_application_detach_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_application_detach_reply payload;
} vapi_msg_application_detach_reply;

static inline void vapi_msg_application_detach_reply_payload_hton(vapi_payload_application_detach_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_application_detach_reply_payload_ntoh(vapi_payload_application_detach_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_application_detach_reply_hton(vapi_msg_application_detach_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_application_detach_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_application_detach_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_application_detach_reply_ntoh(vapi_msg_application_detach_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_application_detach_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_application_detach_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_application_detach_reply_msg_size(vapi_msg_application_detach_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_application_detach_reply_msg_size(vapi_msg_application_detach_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_application_detach_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'application_detach_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_application_detach_reply));
      return -1;
    }
  if (vapi_calc_application_detach_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'application_detach_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_application_detach_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_application_detach_reply()
{
  static const char name[] = "application_detach_reply";
  static const char name_with_crc[] = "application_detach_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_application_detach_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_application_detach_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_application_detach_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_application_detach_reply_hton,
    (generic_swap_fn_t)vapi_msg_application_detach_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_application_detach_reply = vapi_register_msg(&__vapi_metadata_application_detach_reply);
  VAPI_DBG("Assigned msg id %d to application_detach_reply", vapi_msg_id_application_detach_reply);
}

static inline void vapi_set_vapi_msg_application_detach_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_application_detach_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_application_detach_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_application_detach
#define defined_vapi_msg_application_detach
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_application_detach;

static inline void vapi_msg_application_detach_hton(vapi_msg_application_detach *msg)
{
  VAPI_DBG("Swapping `vapi_msg_application_detach'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_application_detach_ntoh(vapi_msg_application_detach *msg)
{
  VAPI_DBG("Swapping `vapi_msg_application_detach'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_application_detach_msg_size(vapi_msg_application_detach *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_application_detach_msg_size(vapi_msg_application_detach *msg, uword buf_size)
{
  if (sizeof(vapi_msg_application_detach) > buf_size)
    {
      VAPI_ERR("Truncated 'application_detach' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_application_detach));
      return -1;
    }
  if (vapi_calc_application_detach_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'application_detach' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_application_detach_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_application_detach* vapi_alloc_application_detach(struct vapi_ctx_s *ctx)
{
  vapi_msg_application_detach *msg = NULL;
  const size_t size = sizeof(vapi_msg_application_detach);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_application_detach*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_application_detach);

  return msg;
}

static inline vapi_error_e vapi_application_detach(struct vapi_ctx_s *ctx,
  vapi_msg_application_detach *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_application_detach_reply *reply),
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
  vapi_msg_application_detach_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_application_detach_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_application_detach_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_application_detach()
{
  static const char name[] = "application_detach";
  static const char name_with_crc[] = "application_detach_51077d14";
  static vapi_message_desc_t __vapi_metadata_application_detach = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_application_detach_msg_size,
    (generic_swap_fn_t)vapi_msg_application_detach_hton,
    (generic_swap_fn_t)vapi_msg_application_detach_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_application_detach = vapi_register_msg(&__vapi_metadata_application_detach);
  VAPI_DBG("Assigned msg id %d to application_detach", vapi_msg_id_application_detach);
}
#endif

#ifndef defined_vapi_msg_app_add_cert_key_pair_reply
#define defined_vapi_msg_app_add_cert_key_pair_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 index; 
} vapi_payload_app_add_cert_key_pair_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_app_add_cert_key_pair_reply payload;
} vapi_msg_app_add_cert_key_pair_reply;

static inline void vapi_msg_app_add_cert_key_pair_reply_payload_hton(vapi_payload_app_add_cert_key_pair_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->index = htobe32(payload->index);
}

static inline void vapi_msg_app_add_cert_key_pair_reply_payload_ntoh(vapi_payload_app_add_cert_key_pair_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->index = be32toh(payload->index);
}

static inline void vapi_msg_app_add_cert_key_pair_reply_hton(vapi_msg_app_add_cert_key_pair_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_add_cert_key_pair_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_app_add_cert_key_pair_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_app_add_cert_key_pair_reply_ntoh(vapi_msg_app_add_cert_key_pair_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_add_cert_key_pair_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_app_add_cert_key_pair_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_app_add_cert_key_pair_reply_msg_size(vapi_msg_app_add_cert_key_pair_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_app_add_cert_key_pair_reply_msg_size(vapi_msg_app_add_cert_key_pair_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_app_add_cert_key_pair_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'app_add_cert_key_pair_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_app_add_cert_key_pair_reply));
      return -1;
    }
  if (vapi_calc_app_add_cert_key_pair_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'app_add_cert_key_pair_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_app_add_cert_key_pair_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_app_add_cert_key_pair_reply()
{
  static const char name[] = "app_add_cert_key_pair_reply";
  static const char name_with_crc[] = "app_add_cert_key_pair_reply_b42958d0";
  static vapi_message_desc_t __vapi_metadata_app_add_cert_key_pair_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_app_add_cert_key_pair_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_app_add_cert_key_pair_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_app_add_cert_key_pair_reply_hton,
    (generic_swap_fn_t)vapi_msg_app_add_cert_key_pair_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_app_add_cert_key_pair_reply = vapi_register_msg(&__vapi_metadata_app_add_cert_key_pair_reply);
  VAPI_DBG("Assigned msg id %d to app_add_cert_key_pair_reply", vapi_msg_id_app_add_cert_key_pair_reply);
}

static inline void vapi_set_vapi_msg_app_add_cert_key_pair_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_app_add_cert_key_pair_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_app_add_cert_key_pair_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_app_add_cert_key_pair
#define defined_vapi_msg_app_add_cert_key_pair
typedef struct __attribute__ ((__packed__)) {
  u16 cert_len;
  u16 certkey_len;
  u8 certkey[0]; 
} vapi_payload_app_add_cert_key_pair;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_app_add_cert_key_pair payload;
} vapi_msg_app_add_cert_key_pair;

static inline void vapi_msg_app_add_cert_key_pair_payload_hton(vapi_payload_app_add_cert_key_pair *payload)
{
  payload->cert_len = htobe16(payload->cert_len);
  payload->certkey_len = htobe16(payload->certkey_len);
}

static inline void vapi_msg_app_add_cert_key_pair_payload_ntoh(vapi_payload_app_add_cert_key_pair *payload)
{
  payload->cert_len = be16toh(payload->cert_len);
  payload->certkey_len = be16toh(payload->certkey_len);
}

static inline void vapi_msg_app_add_cert_key_pair_hton(vapi_msg_app_add_cert_key_pair *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_add_cert_key_pair'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_app_add_cert_key_pair_payload_hton(&msg->payload);
}

static inline void vapi_msg_app_add_cert_key_pair_ntoh(vapi_msg_app_add_cert_key_pair *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_add_cert_key_pair'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_app_add_cert_key_pair_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_app_add_cert_key_pair_msg_size(vapi_msg_app_add_cert_key_pair *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.certkey[0]) * msg->payload.certkey_len;
}

static inline int vapi_verify_app_add_cert_key_pair_msg_size(vapi_msg_app_add_cert_key_pair *msg, uword buf_size)
{
  if (sizeof(vapi_msg_app_add_cert_key_pair) > buf_size)
    {
      VAPI_ERR("Truncated 'app_add_cert_key_pair' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_app_add_cert_key_pair));
      return -1;
    }
  if (vapi_calc_app_add_cert_key_pair_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'app_add_cert_key_pair' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_app_add_cert_key_pair_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_app_add_cert_key_pair* vapi_alloc_app_add_cert_key_pair(struct vapi_ctx_s *ctx, size_t _certkey_array_size)
{
  vapi_msg_app_add_cert_key_pair *msg = NULL;
  const size_t size = sizeof(vapi_msg_app_add_cert_key_pair) + sizeof(msg->payload.certkey[0]) * _certkey_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_app_add_cert_key_pair*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_app_add_cert_key_pair);
  msg->payload.certkey_len = _certkey_array_size;

  return msg;
}

static inline vapi_error_e vapi_app_add_cert_key_pair(struct vapi_ctx_s *ctx,
  vapi_msg_app_add_cert_key_pair *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_app_add_cert_key_pair_reply *reply),
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
  vapi_msg_app_add_cert_key_pair_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_app_add_cert_key_pair_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_app_add_cert_key_pair_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_app_add_cert_key_pair()
{
  static const char name[] = "app_add_cert_key_pair";
  static const char name_with_crc[] = "app_add_cert_key_pair_02eb8016";
  static vapi_message_desc_t __vapi_metadata_app_add_cert_key_pair = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_app_add_cert_key_pair, payload),
    (verify_msg_size_fn_t)vapi_verify_app_add_cert_key_pair_msg_size,
    (generic_swap_fn_t)vapi_msg_app_add_cert_key_pair_hton,
    (generic_swap_fn_t)vapi_msg_app_add_cert_key_pair_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_app_add_cert_key_pair = vapi_register_msg(&__vapi_metadata_app_add_cert_key_pair);
  VAPI_DBG("Assigned msg id %d to app_add_cert_key_pair", vapi_msg_id_app_add_cert_key_pair);
}
#endif

#ifndef defined_vapi_msg_app_del_cert_key_pair_reply
#define defined_vapi_msg_app_del_cert_key_pair_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_app_del_cert_key_pair_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_app_del_cert_key_pair_reply payload;
} vapi_msg_app_del_cert_key_pair_reply;

static inline void vapi_msg_app_del_cert_key_pair_reply_payload_hton(vapi_payload_app_del_cert_key_pair_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_app_del_cert_key_pair_reply_payload_ntoh(vapi_payload_app_del_cert_key_pair_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_app_del_cert_key_pair_reply_hton(vapi_msg_app_del_cert_key_pair_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_del_cert_key_pair_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_app_del_cert_key_pair_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_app_del_cert_key_pair_reply_ntoh(vapi_msg_app_del_cert_key_pair_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_del_cert_key_pair_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_app_del_cert_key_pair_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_app_del_cert_key_pair_reply_msg_size(vapi_msg_app_del_cert_key_pair_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_app_del_cert_key_pair_reply_msg_size(vapi_msg_app_del_cert_key_pair_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_app_del_cert_key_pair_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'app_del_cert_key_pair_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_app_del_cert_key_pair_reply));
      return -1;
    }
  if (vapi_calc_app_del_cert_key_pair_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'app_del_cert_key_pair_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_app_del_cert_key_pair_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_app_del_cert_key_pair_reply()
{
  static const char name[] = "app_del_cert_key_pair_reply";
  static const char name_with_crc[] = "app_del_cert_key_pair_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_app_del_cert_key_pair_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_app_del_cert_key_pair_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_app_del_cert_key_pair_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_app_del_cert_key_pair_reply_hton,
    (generic_swap_fn_t)vapi_msg_app_del_cert_key_pair_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_app_del_cert_key_pair_reply = vapi_register_msg(&__vapi_metadata_app_del_cert_key_pair_reply);
  VAPI_DBG("Assigned msg id %d to app_del_cert_key_pair_reply", vapi_msg_id_app_del_cert_key_pair_reply);
}

static inline void vapi_set_vapi_msg_app_del_cert_key_pair_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_app_del_cert_key_pair_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_app_del_cert_key_pair_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_app_del_cert_key_pair
#define defined_vapi_msg_app_del_cert_key_pair
typedef struct __attribute__ ((__packed__)) {
  u32 index; 
} vapi_payload_app_del_cert_key_pair;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_app_del_cert_key_pair payload;
} vapi_msg_app_del_cert_key_pair;

static inline void vapi_msg_app_del_cert_key_pair_payload_hton(vapi_payload_app_del_cert_key_pair *payload)
{
  payload->index = htobe32(payload->index);
}

static inline void vapi_msg_app_del_cert_key_pair_payload_ntoh(vapi_payload_app_del_cert_key_pair *payload)
{
  payload->index = be32toh(payload->index);
}

static inline void vapi_msg_app_del_cert_key_pair_hton(vapi_msg_app_del_cert_key_pair *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_del_cert_key_pair'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_app_del_cert_key_pair_payload_hton(&msg->payload);
}

static inline void vapi_msg_app_del_cert_key_pair_ntoh(vapi_msg_app_del_cert_key_pair *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_del_cert_key_pair'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_app_del_cert_key_pair_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_app_del_cert_key_pair_msg_size(vapi_msg_app_del_cert_key_pair *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_app_del_cert_key_pair_msg_size(vapi_msg_app_del_cert_key_pair *msg, uword buf_size)
{
  if (sizeof(vapi_msg_app_del_cert_key_pair) > buf_size)
    {
      VAPI_ERR("Truncated 'app_del_cert_key_pair' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_app_del_cert_key_pair));
      return -1;
    }
  if (vapi_calc_app_del_cert_key_pair_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'app_del_cert_key_pair' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_app_del_cert_key_pair_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_app_del_cert_key_pair* vapi_alloc_app_del_cert_key_pair(struct vapi_ctx_s *ctx)
{
  vapi_msg_app_del_cert_key_pair *msg = NULL;
  const size_t size = sizeof(vapi_msg_app_del_cert_key_pair);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_app_del_cert_key_pair*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_app_del_cert_key_pair);

  return msg;
}

static inline vapi_error_e vapi_app_del_cert_key_pair(struct vapi_ctx_s *ctx,
  vapi_msg_app_del_cert_key_pair *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_app_del_cert_key_pair_reply *reply),
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
  vapi_msg_app_del_cert_key_pair_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_app_del_cert_key_pair_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_app_del_cert_key_pair_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_app_del_cert_key_pair()
{
  static const char name[] = "app_del_cert_key_pair";
  static const char name_with_crc[] = "app_del_cert_key_pair_8ac76db6";
  static vapi_message_desc_t __vapi_metadata_app_del_cert_key_pair = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_app_del_cert_key_pair, payload),
    (verify_msg_size_fn_t)vapi_verify_app_del_cert_key_pair_msg_size,
    (generic_swap_fn_t)vapi_msg_app_del_cert_key_pair_hton,
    (generic_swap_fn_t)vapi_msg_app_del_cert_key_pair_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_app_del_cert_key_pair = vapi_register_msg(&__vapi_metadata_app_del_cert_key_pair);
  VAPI_DBG("Assigned msg id %d to app_del_cert_key_pair", vapi_msg_id_app_del_cert_key_pair);
}
#endif

#ifndef defined_vapi_msg_app_worker_add_del_reply
#define defined_vapi_msg_app_worker_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 wrk_index;
  u64 app_event_queue_address;
  u8 n_fds;
  u8 fd_flags;
  u64 segment_handle;
  bool is_add;
  vl_api_string_t segment_name; 
} vapi_payload_app_worker_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_app_worker_add_del_reply payload;
} vapi_msg_app_worker_add_del_reply;

static inline void vapi_msg_app_worker_add_del_reply_payload_hton(vapi_payload_app_worker_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->wrk_index = htobe32(payload->wrk_index);
  payload->app_event_queue_address = htobe64(payload->app_event_queue_address);
  payload->segment_handle = htobe64(payload->segment_handle);
  vl_api_string_t_hton(&payload->segment_name);
}

static inline void vapi_msg_app_worker_add_del_reply_payload_ntoh(vapi_payload_app_worker_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->wrk_index = be32toh(payload->wrk_index);
  payload->app_event_queue_address = be64toh(payload->app_event_queue_address);
  payload->segment_handle = be64toh(payload->segment_handle);
  vl_api_string_t_ntoh(&payload->segment_name);
}

static inline void vapi_msg_app_worker_add_del_reply_hton(vapi_msg_app_worker_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_worker_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_app_worker_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_app_worker_add_del_reply_ntoh(vapi_msg_app_worker_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_worker_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_app_worker_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_app_worker_add_del_reply_msg_size(vapi_msg_app_worker_add_del_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.segment_name.buf[0]) * msg->payload.segment_name.length;
}

static inline int vapi_verify_app_worker_add_del_reply_msg_size(vapi_msg_app_worker_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_app_worker_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'app_worker_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_app_worker_add_del_reply));
      return -1;
    }
  if (vapi_calc_app_worker_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'app_worker_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_app_worker_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_app_worker_add_del_reply()
{
  static const char name[] = "app_worker_add_del_reply";
  static const char name_with_crc[] = "app_worker_add_del_reply_5735ffe7";
  static vapi_message_desc_t __vapi_metadata_app_worker_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_app_worker_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_app_worker_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_app_worker_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_app_worker_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_app_worker_add_del_reply = vapi_register_msg(&__vapi_metadata_app_worker_add_del_reply);
  VAPI_DBG("Assigned msg id %d to app_worker_add_del_reply", vapi_msg_id_app_worker_add_del_reply);
}

static inline void vapi_set_vapi_msg_app_worker_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_app_worker_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_app_worker_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_app_worker_add_del
#define defined_vapi_msg_app_worker_add_del
typedef struct __attribute__ ((__packed__)) {
  u32 app_index;
  u32 wrk_index;
  bool is_add; 
} vapi_payload_app_worker_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_app_worker_add_del payload;
} vapi_msg_app_worker_add_del;

static inline void vapi_msg_app_worker_add_del_payload_hton(vapi_payload_app_worker_add_del *payload)
{
  payload->app_index = htobe32(payload->app_index);
  payload->wrk_index = htobe32(payload->wrk_index);
}

static inline void vapi_msg_app_worker_add_del_payload_ntoh(vapi_payload_app_worker_add_del *payload)
{
  payload->app_index = be32toh(payload->app_index);
  payload->wrk_index = be32toh(payload->wrk_index);
}

static inline void vapi_msg_app_worker_add_del_hton(vapi_msg_app_worker_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_worker_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_app_worker_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_app_worker_add_del_ntoh(vapi_msg_app_worker_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_worker_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_app_worker_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_app_worker_add_del_msg_size(vapi_msg_app_worker_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_app_worker_add_del_msg_size(vapi_msg_app_worker_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_app_worker_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'app_worker_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_app_worker_add_del));
      return -1;
    }
  if (vapi_calc_app_worker_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'app_worker_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_app_worker_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_app_worker_add_del* vapi_alloc_app_worker_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_app_worker_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_app_worker_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_app_worker_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_app_worker_add_del);

  return msg;
}

static inline vapi_error_e vapi_app_worker_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_app_worker_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_app_worker_add_del_reply *reply),
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
  vapi_msg_app_worker_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_app_worker_add_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_app_worker_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_app_worker_add_del()
{
  static const char name[] = "app_worker_add_del";
  static const char name_with_crc[] = "app_worker_add_del_753253dc";
  static vapi_message_desc_t __vapi_metadata_app_worker_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_app_worker_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_app_worker_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_app_worker_add_del_hton,
    (generic_swap_fn_t)vapi_msg_app_worker_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_app_worker_add_del = vapi_register_msg(&__vapi_metadata_app_worker_add_del);
  VAPI_DBG("Assigned msg id %d to app_worker_add_del", vapi_msg_id_app_worker_add_del);
}
#endif

#ifndef defined_vapi_msg_session_enable_disable_reply
#define defined_vapi_msg_session_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_session_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_session_enable_disable_reply payload;
} vapi_msg_session_enable_disable_reply;

static inline void vapi_msg_session_enable_disable_reply_payload_hton(vapi_payload_session_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_session_enable_disable_reply_payload_ntoh(vapi_payload_session_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_session_enable_disable_reply_hton(vapi_msg_session_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_session_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_session_enable_disable_reply_ntoh(vapi_msg_session_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_session_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_session_enable_disable_reply_msg_size(vapi_msg_session_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_session_enable_disable_reply_msg_size(vapi_msg_session_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'session_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_session_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_session_enable_disable_reply()
{
  static const char name[] = "session_enable_disable_reply";
  static const char name_with_crc[] = "session_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_session_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_session_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_session_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_session_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_session_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_enable_disable_reply = vapi_register_msg(&__vapi_metadata_session_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to session_enable_disable_reply", vapi_msg_id_session_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_session_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_session_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_session_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_session_enable_disable
#define defined_vapi_msg_session_enable_disable
typedef struct __attribute__ ((__packed__)) {
  bool is_enable; 
} vapi_payload_session_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_session_enable_disable payload;
} vapi_msg_session_enable_disable;

static inline void vapi_msg_session_enable_disable_payload_hton(vapi_payload_session_enable_disable *payload)
{

}

static inline void vapi_msg_session_enable_disable_payload_ntoh(vapi_payload_session_enable_disable *payload)
{

}

static inline void vapi_msg_session_enable_disable_hton(vapi_msg_session_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_session_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_session_enable_disable_ntoh(vapi_msg_session_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_session_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_session_enable_disable_msg_size(vapi_msg_session_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_session_enable_disable_msg_size(vapi_msg_session_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'session_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_enable_disable));
      return -1;
    }
  if (vapi_calc_session_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_session_enable_disable* vapi_alloc_session_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_session_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_session_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_session_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_session_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_session_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_session_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_session_enable_disable_reply *reply),
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
  vapi_msg_session_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_session_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_session_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_session_enable_disable()
{
  static const char name[] = "session_enable_disable";
  static const char name_with_crc[] = "session_enable_disable_c264d7bf";
  static vapi_message_desc_t __vapi_metadata_session_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_session_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_session_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_session_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_session_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_enable_disable = vapi_register_msg(&__vapi_metadata_session_enable_disable);
  VAPI_DBG("Assigned msg id %d to session_enable_disable", vapi_msg_id_session_enable_disable);
}
#endif

#ifndef defined_vapi_msg_session_enable_disable_v2_reply
#define defined_vapi_msg_session_enable_disable_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_session_enable_disable_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_session_enable_disable_v2_reply payload;
} vapi_msg_session_enable_disable_v2_reply;

static inline void vapi_msg_session_enable_disable_v2_reply_payload_hton(vapi_payload_session_enable_disable_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_session_enable_disable_v2_reply_payload_ntoh(vapi_payload_session_enable_disable_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_session_enable_disable_v2_reply_hton(vapi_msg_session_enable_disable_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_enable_disable_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_session_enable_disable_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_session_enable_disable_v2_reply_ntoh(vapi_msg_session_enable_disable_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_enable_disable_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_session_enable_disable_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_session_enable_disable_v2_reply_msg_size(vapi_msg_session_enable_disable_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_session_enable_disable_v2_reply_msg_size(vapi_msg_session_enable_disable_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_enable_disable_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'session_enable_disable_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_enable_disable_v2_reply));
      return -1;
    }
  if (vapi_calc_session_enable_disable_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_enable_disable_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_enable_disable_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_session_enable_disable_v2_reply()
{
  static const char name[] = "session_enable_disable_v2_reply";
  static const char name_with_crc[] = "session_enable_disable_v2_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_session_enable_disable_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_session_enable_disable_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_session_enable_disable_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_session_enable_disable_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_session_enable_disable_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_enable_disable_v2_reply = vapi_register_msg(&__vapi_metadata_session_enable_disable_v2_reply);
  VAPI_DBG("Assigned msg id %d to session_enable_disable_v2_reply", vapi_msg_id_session_enable_disable_v2_reply);
}

static inline void vapi_set_vapi_msg_session_enable_disable_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_session_enable_disable_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_session_enable_disable_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_session_enable_disable_v2
#define defined_vapi_msg_session_enable_disable_v2
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_rt_backend_engine rt_engine_type; 
} vapi_payload_session_enable_disable_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_session_enable_disable_v2 payload;
} vapi_msg_session_enable_disable_v2;

static inline void vapi_msg_session_enable_disable_v2_payload_hton(vapi_payload_session_enable_disable_v2 *payload)
{

}

static inline void vapi_msg_session_enable_disable_v2_payload_ntoh(vapi_payload_session_enable_disable_v2 *payload)
{

}

static inline void vapi_msg_session_enable_disable_v2_hton(vapi_msg_session_enable_disable_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_enable_disable_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_session_enable_disable_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_session_enable_disable_v2_ntoh(vapi_msg_session_enable_disable_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_enable_disable_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_session_enable_disable_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_session_enable_disable_v2_msg_size(vapi_msg_session_enable_disable_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_session_enable_disable_v2_msg_size(vapi_msg_session_enable_disable_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_enable_disable_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'session_enable_disable_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_enable_disable_v2));
      return -1;
    }
  if (vapi_calc_session_enable_disable_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_enable_disable_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_enable_disable_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_session_enable_disable_v2* vapi_alloc_session_enable_disable_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_session_enable_disable_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_session_enable_disable_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_session_enable_disable_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_session_enable_disable_v2);

  return msg;
}

static inline vapi_error_e vapi_session_enable_disable_v2(struct vapi_ctx_s *ctx,
  vapi_msg_session_enable_disable_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_session_enable_disable_v2_reply *reply),
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
  vapi_msg_session_enable_disable_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_session_enable_disable_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_session_enable_disable_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_session_enable_disable_v2()
{
  static const char name[] = "session_enable_disable_v2";
  static const char name_with_crc[] = "session_enable_disable_v2_f09fbf32";
  static vapi_message_desc_t __vapi_metadata_session_enable_disable_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_session_enable_disable_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_session_enable_disable_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_session_enable_disable_v2_hton,
    (generic_swap_fn_t)vapi_msg_session_enable_disable_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_enable_disable_v2 = vapi_register_msg(&__vapi_metadata_session_enable_disable_v2);
  VAPI_DBG("Assigned msg id %d to session_enable_disable_v2", vapi_msg_id_session_enable_disable_v2);
}
#endif

#ifndef defined_vapi_msg_session_sapi_enable_disable_reply
#define defined_vapi_msg_session_sapi_enable_disable_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_session_sapi_enable_disable_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_session_sapi_enable_disable_reply payload;
} vapi_msg_session_sapi_enable_disable_reply;

static inline void vapi_msg_session_sapi_enable_disable_reply_payload_hton(vapi_payload_session_sapi_enable_disable_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_session_sapi_enable_disable_reply_payload_ntoh(vapi_payload_session_sapi_enable_disable_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_session_sapi_enable_disable_reply_hton(vapi_msg_session_sapi_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sapi_enable_disable_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_session_sapi_enable_disable_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_session_sapi_enable_disable_reply_ntoh(vapi_msg_session_sapi_enable_disable_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sapi_enable_disable_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_session_sapi_enable_disable_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_session_sapi_enable_disable_reply_msg_size(vapi_msg_session_sapi_enable_disable_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_session_sapi_enable_disable_reply_msg_size(vapi_msg_session_sapi_enable_disable_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_sapi_enable_disable_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sapi_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_sapi_enable_disable_reply));
      return -1;
    }
  if (vapi_calc_session_sapi_enable_disable_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sapi_enable_disable_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_sapi_enable_disable_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_session_sapi_enable_disable_reply()
{
  static const char name[] = "session_sapi_enable_disable_reply";
  static const char name_with_crc[] = "session_sapi_enable_disable_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_session_sapi_enable_disable_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_session_sapi_enable_disable_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_session_sapi_enable_disable_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_session_sapi_enable_disable_reply_hton,
    (generic_swap_fn_t)vapi_msg_session_sapi_enable_disable_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_sapi_enable_disable_reply = vapi_register_msg(&__vapi_metadata_session_sapi_enable_disable_reply);
  VAPI_DBG("Assigned msg id %d to session_sapi_enable_disable_reply", vapi_msg_id_session_sapi_enable_disable_reply);
}

static inline void vapi_set_vapi_msg_session_sapi_enable_disable_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_session_sapi_enable_disable_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_session_sapi_enable_disable_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_session_sapi_enable_disable
#define defined_vapi_msg_session_sapi_enable_disable
typedef struct __attribute__ ((__packed__)) {
  bool is_enable; 
} vapi_payload_session_sapi_enable_disable;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_session_sapi_enable_disable payload;
} vapi_msg_session_sapi_enable_disable;

static inline void vapi_msg_session_sapi_enable_disable_payload_hton(vapi_payload_session_sapi_enable_disable *payload)
{

}

static inline void vapi_msg_session_sapi_enable_disable_payload_ntoh(vapi_payload_session_sapi_enable_disable *payload)
{

}

static inline void vapi_msg_session_sapi_enable_disable_hton(vapi_msg_session_sapi_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sapi_enable_disable'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_session_sapi_enable_disable_payload_hton(&msg->payload);
}

static inline void vapi_msg_session_sapi_enable_disable_ntoh(vapi_msg_session_sapi_enable_disable *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sapi_enable_disable'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_session_sapi_enable_disable_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_session_sapi_enable_disable_msg_size(vapi_msg_session_sapi_enable_disable *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_session_sapi_enable_disable_msg_size(vapi_msg_session_sapi_enable_disable *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_sapi_enable_disable) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sapi_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_sapi_enable_disable));
      return -1;
    }
  if (vapi_calc_session_sapi_enable_disable_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sapi_enable_disable' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_sapi_enable_disable_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_session_sapi_enable_disable* vapi_alloc_session_sapi_enable_disable(struct vapi_ctx_s *ctx)
{
  vapi_msg_session_sapi_enable_disable *msg = NULL;
  const size_t size = sizeof(vapi_msg_session_sapi_enable_disable);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_session_sapi_enable_disable*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_session_sapi_enable_disable);

  return msg;
}

static inline vapi_error_e vapi_session_sapi_enable_disable(struct vapi_ctx_s *ctx,
  vapi_msg_session_sapi_enable_disable *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_session_sapi_enable_disable_reply *reply),
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
  vapi_msg_session_sapi_enable_disable_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_session_sapi_enable_disable_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_session_sapi_enable_disable_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_session_sapi_enable_disable()
{
  static const char name[] = "session_sapi_enable_disable";
  static const char name_with_crc[] = "session_sapi_enable_disable_c264d7bf";
  static vapi_message_desc_t __vapi_metadata_session_sapi_enable_disable = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_session_sapi_enable_disable, payload),
    (verify_msg_size_fn_t)vapi_verify_session_sapi_enable_disable_msg_size,
    (generic_swap_fn_t)vapi_msg_session_sapi_enable_disable_hton,
    (generic_swap_fn_t)vapi_msg_session_sapi_enable_disable_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_sapi_enable_disable = vapi_register_msg(&__vapi_metadata_session_sapi_enable_disable);
  VAPI_DBG("Assigned msg id %d to session_sapi_enable_disable", vapi_msg_id_session_sapi_enable_disable);
}
#endif

#ifndef defined_vapi_msg_app_namespace_add_del_reply
#define defined_vapi_msg_app_namespace_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 appns_index; 
} vapi_payload_app_namespace_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_app_namespace_add_del_reply payload;
} vapi_msg_app_namespace_add_del_reply;

static inline void vapi_msg_app_namespace_add_del_reply_payload_hton(vapi_payload_app_namespace_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->appns_index = htobe32(payload->appns_index);
}

static inline void vapi_msg_app_namespace_add_del_reply_payload_ntoh(vapi_payload_app_namespace_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->appns_index = be32toh(payload->appns_index);
}

static inline void vapi_msg_app_namespace_add_del_reply_hton(vapi_msg_app_namespace_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_namespace_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_app_namespace_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_app_namespace_add_del_reply_ntoh(vapi_msg_app_namespace_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_namespace_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_app_namespace_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_app_namespace_add_del_reply_msg_size(vapi_msg_app_namespace_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_app_namespace_add_del_reply_msg_size(vapi_msg_app_namespace_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_app_namespace_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'app_namespace_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_app_namespace_add_del_reply));
      return -1;
    }
  if (vapi_calc_app_namespace_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'app_namespace_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_app_namespace_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_app_namespace_add_del_reply()
{
  static const char name[] = "app_namespace_add_del_reply";
  static const char name_with_crc[] = "app_namespace_add_del_reply_85137120";
  static vapi_message_desc_t __vapi_metadata_app_namespace_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_app_namespace_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_app_namespace_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_app_namespace_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_app_namespace_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_app_namespace_add_del_reply = vapi_register_msg(&__vapi_metadata_app_namespace_add_del_reply);
  VAPI_DBG("Assigned msg id %d to app_namespace_add_del_reply", vapi_msg_id_app_namespace_add_del_reply);
}

static inline void vapi_set_vapi_msg_app_namespace_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_app_namespace_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_app_namespace_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_app_namespace_add_del
#define defined_vapi_msg_app_namespace_add_del
typedef struct __attribute__ ((__packed__)) {
  u64 secret;
  vapi_type_interface_index sw_if_index;
  u32 ip4_fib_id;
  u32 ip6_fib_id;
  vl_api_string_t namespace_id; 
} vapi_payload_app_namespace_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_app_namespace_add_del payload;
} vapi_msg_app_namespace_add_del;

static inline void vapi_msg_app_namespace_add_del_payload_hton(vapi_payload_app_namespace_add_del *payload)
{
  payload->secret = htobe64(payload->secret);
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->ip4_fib_id = htobe32(payload->ip4_fib_id);
  payload->ip6_fib_id = htobe32(payload->ip6_fib_id);
  vl_api_string_t_hton(&payload->namespace_id);
}

static inline void vapi_msg_app_namespace_add_del_payload_ntoh(vapi_payload_app_namespace_add_del *payload)
{
  payload->secret = be64toh(payload->secret);
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->ip4_fib_id = be32toh(payload->ip4_fib_id);
  payload->ip6_fib_id = be32toh(payload->ip6_fib_id);
  vl_api_string_t_ntoh(&payload->namespace_id);
}

static inline void vapi_msg_app_namespace_add_del_hton(vapi_msg_app_namespace_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_namespace_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_app_namespace_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_app_namespace_add_del_ntoh(vapi_msg_app_namespace_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_namespace_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_app_namespace_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_app_namespace_add_del_msg_size(vapi_msg_app_namespace_add_del *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.namespace_id.buf[0]) * msg->payload.namespace_id.length;
}

static inline int vapi_verify_app_namespace_add_del_msg_size(vapi_msg_app_namespace_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_app_namespace_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'app_namespace_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_app_namespace_add_del));
      return -1;
    }
  if (vapi_calc_app_namespace_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'app_namespace_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_app_namespace_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_app_namespace_add_del* vapi_alloc_app_namespace_add_del(struct vapi_ctx_s *ctx, size_t namespace_id_buf_array_size)
{
  vapi_msg_app_namespace_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_app_namespace_add_del) + sizeof(msg->payload.namespace_id.buf[0]) * namespace_id_buf_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_app_namespace_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_app_namespace_add_del);
  msg->payload.namespace_id.length = namespace_id_buf_array_size;

  return msg;
}

static inline vapi_error_e vapi_app_namespace_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_app_namespace_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_app_namespace_add_del_reply *reply),
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
  vapi_msg_app_namespace_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_app_namespace_add_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_app_namespace_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_app_namespace_add_del()
{
  static const char name[] = "app_namespace_add_del";
  static const char name_with_crc[] = "app_namespace_add_del_6306aecb";
  static vapi_message_desc_t __vapi_metadata_app_namespace_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_app_namespace_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_app_namespace_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_app_namespace_add_del_hton,
    (generic_swap_fn_t)vapi_msg_app_namespace_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_app_namespace_add_del = vapi_register_msg(&__vapi_metadata_app_namespace_add_del);
  VAPI_DBG("Assigned msg id %d to app_namespace_add_del", vapi_msg_id_app_namespace_add_del);
}
#endif

#ifndef defined_vapi_msg_app_namespace_add_del_v4_reply
#define defined_vapi_msg_app_namespace_add_del_v4_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 appns_index; 
} vapi_payload_app_namespace_add_del_v4_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_app_namespace_add_del_v4_reply payload;
} vapi_msg_app_namespace_add_del_v4_reply;

static inline void vapi_msg_app_namespace_add_del_v4_reply_payload_hton(vapi_payload_app_namespace_add_del_v4_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->appns_index = htobe32(payload->appns_index);
}

static inline void vapi_msg_app_namespace_add_del_v4_reply_payload_ntoh(vapi_payload_app_namespace_add_del_v4_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->appns_index = be32toh(payload->appns_index);
}

static inline void vapi_msg_app_namespace_add_del_v4_reply_hton(vapi_msg_app_namespace_add_del_v4_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_namespace_add_del_v4_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_app_namespace_add_del_v4_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_app_namespace_add_del_v4_reply_ntoh(vapi_msg_app_namespace_add_del_v4_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_namespace_add_del_v4_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_app_namespace_add_del_v4_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_app_namespace_add_del_v4_reply_msg_size(vapi_msg_app_namespace_add_del_v4_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_app_namespace_add_del_v4_reply_msg_size(vapi_msg_app_namespace_add_del_v4_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_app_namespace_add_del_v4_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'app_namespace_add_del_v4_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_app_namespace_add_del_v4_reply));
      return -1;
    }
  if (vapi_calc_app_namespace_add_del_v4_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'app_namespace_add_del_v4_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_app_namespace_add_del_v4_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_app_namespace_add_del_v4_reply()
{
  static const char name[] = "app_namespace_add_del_v4_reply";
  static const char name_with_crc[] = "app_namespace_add_del_v4_reply_85137120";
  static vapi_message_desc_t __vapi_metadata_app_namespace_add_del_v4_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_app_namespace_add_del_v4_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_app_namespace_add_del_v4_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_app_namespace_add_del_v4_reply_hton,
    (generic_swap_fn_t)vapi_msg_app_namespace_add_del_v4_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_app_namespace_add_del_v4_reply = vapi_register_msg(&__vapi_metadata_app_namespace_add_del_v4_reply);
  VAPI_DBG("Assigned msg id %d to app_namespace_add_del_v4_reply", vapi_msg_id_app_namespace_add_del_v4_reply);
}

static inline void vapi_set_vapi_msg_app_namespace_add_del_v4_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_app_namespace_add_del_v4_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_app_namespace_add_del_v4_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_app_namespace_add_del_v4
#define defined_vapi_msg_app_namespace_add_del_v4
typedef struct __attribute__ ((__packed__)) {
  u64 secret;
  bool is_add;
  vapi_type_interface_index sw_if_index;
  u32 ip4_fib_id;
  u32 ip6_fib_id;
  u8 namespace_id[64];
  vl_api_string_t sock_name; 
} vapi_payload_app_namespace_add_del_v4;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_app_namespace_add_del_v4 payload;
} vapi_msg_app_namespace_add_del_v4;

static inline void vapi_msg_app_namespace_add_del_v4_payload_hton(vapi_payload_app_namespace_add_del_v4 *payload)
{
  payload->secret = htobe64(payload->secret);
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->ip4_fib_id = htobe32(payload->ip4_fib_id);
  payload->ip6_fib_id = htobe32(payload->ip6_fib_id);
  vl_api_string_t_hton(&payload->sock_name);
}

static inline void vapi_msg_app_namespace_add_del_v4_payload_ntoh(vapi_payload_app_namespace_add_del_v4 *payload)
{
  payload->secret = be64toh(payload->secret);
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->ip4_fib_id = be32toh(payload->ip4_fib_id);
  payload->ip6_fib_id = be32toh(payload->ip6_fib_id);
  vl_api_string_t_ntoh(&payload->sock_name);
}

static inline void vapi_msg_app_namespace_add_del_v4_hton(vapi_msg_app_namespace_add_del_v4 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_namespace_add_del_v4'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_app_namespace_add_del_v4_payload_hton(&msg->payload);
}

static inline void vapi_msg_app_namespace_add_del_v4_ntoh(vapi_msg_app_namespace_add_del_v4 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_namespace_add_del_v4'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_app_namespace_add_del_v4_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_app_namespace_add_del_v4_msg_size(vapi_msg_app_namespace_add_del_v4 *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.sock_name.buf[0]) * msg->payload.sock_name.length;
}

static inline int vapi_verify_app_namespace_add_del_v4_msg_size(vapi_msg_app_namespace_add_del_v4 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_app_namespace_add_del_v4) > buf_size)
    {
      VAPI_ERR("Truncated 'app_namespace_add_del_v4' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_app_namespace_add_del_v4));
      return -1;
    }
  if (vapi_calc_app_namespace_add_del_v4_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'app_namespace_add_del_v4' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_app_namespace_add_del_v4_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_app_namespace_add_del_v4* vapi_alloc_app_namespace_add_del_v4(struct vapi_ctx_s *ctx, size_t sock_name_buf_array_size)
{
  vapi_msg_app_namespace_add_del_v4 *msg = NULL;
  const size_t size = sizeof(vapi_msg_app_namespace_add_del_v4) + sizeof(msg->payload.sock_name.buf[0]) * sock_name_buf_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_app_namespace_add_del_v4*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_app_namespace_add_del_v4);
  msg->payload.sock_name.length = sock_name_buf_array_size;

  return msg;
}

static inline vapi_error_e vapi_app_namespace_add_del_v4(struct vapi_ctx_s *ctx,
  vapi_msg_app_namespace_add_del_v4 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_app_namespace_add_del_v4_reply *reply),
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
  vapi_msg_app_namespace_add_del_v4_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_app_namespace_add_del_v4_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_app_namespace_add_del_v4_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_app_namespace_add_del_v4()
{
  static const char name[] = "app_namespace_add_del_v4";
  static const char name_with_crc[] = "app_namespace_add_del_v4_42c1d824";
  static vapi_message_desc_t __vapi_metadata_app_namespace_add_del_v4 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_app_namespace_add_del_v4, payload),
    (verify_msg_size_fn_t)vapi_verify_app_namespace_add_del_v4_msg_size,
    (generic_swap_fn_t)vapi_msg_app_namespace_add_del_v4_hton,
    (generic_swap_fn_t)vapi_msg_app_namespace_add_del_v4_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_app_namespace_add_del_v4 = vapi_register_msg(&__vapi_metadata_app_namespace_add_del_v4);
  VAPI_DBG("Assigned msg id %d to app_namespace_add_del_v4", vapi_msg_id_app_namespace_add_del_v4);
}
#endif

#ifndef defined_vapi_msg_app_namespace_add_del_v2_reply
#define defined_vapi_msg_app_namespace_add_del_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 appns_index; 
} vapi_payload_app_namespace_add_del_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_app_namespace_add_del_v2_reply payload;
} vapi_msg_app_namespace_add_del_v2_reply;

static inline void vapi_msg_app_namespace_add_del_v2_reply_payload_hton(vapi_payload_app_namespace_add_del_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->appns_index = htobe32(payload->appns_index);
}

static inline void vapi_msg_app_namespace_add_del_v2_reply_payload_ntoh(vapi_payload_app_namespace_add_del_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->appns_index = be32toh(payload->appns_index);
}

static inline void vapi_msg_app_namespace_add_del_v2_reply_hton(vapi_msg_app_namespace_add_del_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_namespace_add_del_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_app_namespace_add_del_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_app_namespace_add_del_v2_reply_ntoh(vapi_msg_app_namespace_add_del_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_namespace_add_del_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_app_namespace_add_del_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_app_namespace_add_del_v2_reply_msg_size(vapi_msg_app_namespace_add_del_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_app_namespace_add_del_v2_reply_msg_size(vapi_msg_app_namespace_add_del_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_app_namespace_add_del_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'app_namespace_add_del_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_app_namespace_add_del_v2_reply));
      return -1;
    }
  if (vapi_calc_app_namespace_add_del_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'app_namespace_add_del_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_app_namespace_add_del_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_app_namespace_add_del_v2_reply()
{
  static const char name[] = "app_namespace_add_del_v2_reply";
  static const char name_with_crc[] = "app_namespace_add_del_v2_reply_85137120";
  static vapi_message_desc_t __vapi_metadata_app_namespace_add_del_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_app_namespace_add_del_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_app_namespace_add_del_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_app_namespace_add_del_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_app_namespace_add_del_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_app_namespace_add_del_v2_reply = vapi_register_msg(&__vapi_metadata_app_namespace_add_del_v2_reply);
  VAPI_DBG("Assigned msg id %d to app_namespace_add_del_v2_reply", vapi_msg_id_app_namespace_add_del_v2_reply);
}

static inline void vapi_set_vapi_msg_app_namespace_add_del_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_app_namespace_add_del_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_app_namespace_add_del_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_app_namespace_add_del_v2
#define defined_vapi_msg_app_namespace_add_del_v2
typedef struct __attribute__ ((__packed__)) {
  u64 secret;
  vapi_type_interface_index sw_if_index;
  u32 ip4_fib_id;
  u32 ip6_fib_id;
  u8 namespace_id[64];
  u8 netns[64]; 
} vapi_payload_app_namespace_add_del_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_app_namespace_add_del_v2 payload;
} vapi_msg_app_namespace_add_del_v2;

static inline void vapi_msg_app_namespace_add_del_v2_payload_hton(vapi_payload_app_namespace_add_del_v2 *payload)
{
  payload->secret = htobe64(payload->secret);
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->ip4_fib_id = htobe32(payload->ip4_fib_id);
  payload->ip6_fib_id = htobe32(payload->ip6_fib_id);
}

static inline void vapi_msg_app_namespace_add_del_v2_payload_ntoh(vapi_payload_app_namespace_add_del_v2 *payload)
{
  payload->secret = be64toh(payload->secret);
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->ip4_fib_id = be32toh(payload->ip4_fib_id);
  payload->ip6_fib_id = be32toh(payload->ip6_fib_id);
}

static inline void vapi_msg_app_namespace_add_del_v2_hton(vapi_msg_app_namespace_add_del_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_namespace_add_del_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_app_namespace_add_del_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_app_namespace_add_del_v2_ntoh(vapi_msg_app_namespace_add_del_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_namespace_add_del_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_app_namespace_add_del_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_app_namespace_add_del_v2_msg_size(vapi_msg_app_namespace_add_del_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_app_namespace_add_del_v2_msg_size(vapi_msg_app_namespace_add_del_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_app_namespace_add_del_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'app_namespace_add_del_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_app_namespace_add_del_v2));
      return -1;
    }
  if (vapi_calc_app_namespace_add_del_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'app_namespace_add_del_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_app_namespace_add_del_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_app_namespace_add_del_v2* vapi_alloc_app_namespace_add_del_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_app_namespace_add_del_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_app_namespace_add_del_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_app_namespace_add_del_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_app_namespace_add_del_v2);

  return msg;
}

static inline vapi_error_e vapi_app_namespace_add_del_v2(struct vapi_ctx_s *ctx,
  vapi_msg_app_namespace_add_del_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_app_namespace_add_del_v2_reply *reply),
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
  vapi_msg_app_namespace_add_del_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_app_namespace_add_del_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_app_namespace_add_del_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_app_namespace_add_del_v2()
{
  static const char name[] = "app_namespace_add_del_v2";
  static const char name_with_crc[] = "app_namespace_add_del_v2_ee0755cf";
  static vapi_message_desc_t __vapi_metadata_app_namespace_add_del_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_app_namespace_add_del_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_app_namespace_add_del_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_app_namespace_add_del_v2_hton,
    (generic_swap_fn_t)vapi_msg_app_namespace_add_del_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_app_namespace_add_del_v2 = vapi_register_msg(&__vapi_metadata_app_namespace_add_del_v2);
  VAPI_DBG("Assigned msg id %d to app_namespace_add_del_v2", vapi_msg_id_app_namespace_add_del_v2);
}
#endif

#ifndef defined_vapi_msg_app_namespace_add_del_v3_reply
#define defined_vapi_msg_app_namespace_add_del_v3_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 appns_index; 
} vapi_payload_app_namespace_add_del_v3_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_app_namespace_add_del_v3_reply payload;
} vapi_msg_app_namespace_add_del_v3_reply;

static inline void vapi_msg_app_namespace_add_del_v3_reply_payload_hton(vapi_payload_app_namespace_add_del_v3_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->appns_index = htobe32(payload->appns_index);
}

static inline void vapi_msg_app_namespace_add_del_v3_reply_payload_ntoh(vapi_payload_app_namespace_add_del_v3_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->appns_index = be32toh(payload->appns_index);
}

static inline void vapi_msg_app_namespace_add_del_v3_reply_hton(vapi_msg_app_namespace_add_del_v3_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_namespace_add_del_v3_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_app_namespace_add_del_v3_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_app_namespace_add_del_v3_reply_ntoh(vapi_msg_app_namespace_add_del_v3_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_namespace_add_del_v3_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_app_namespace_add_del_v3_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_app_namespace_add_del_v3_reply_msg_size(vapi_msg_app_namespace_add_del_v3_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_app_namespace_add_del_v3_reply_msg_size(vapi_msg_app_namespace_add_del_v3_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_app_namespace_add_del_v3_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'app_namespace_add_del_v3_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_app_namespace_add_del_v3_reply));
      return -1;
    }
  if (vapi_calc_app_namespace_add_del_v3_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'app_namespace_add_del_v3_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_app_namespace_add_del_v3_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_app_namespace_add_del_v3_reply()
{
  static const char name[] = "app_namespace_add_del_v3_reply";
  static const char name_with_crc[] = "app_namespace_add_del_v3_reply_85137120";
  static vapi_message_desc_t __vapi_metadata_app_namespace_add_del_v3_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_app_namespace_add_del_v3_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_app_namespace_add_del_v3_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_app_namespace_add_del_v3_reply_hton,
    (generic_swap_fn_t)vapi_msg_app_namespace_add_del_v3_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_app_namespace_add_del_v3_reply = vapi_register_msg(&__vapi_metadata_app_namespace_add_del_v3_reply);
  VAPI_DBG("Assigned msg id %d to app_namespace_add_del_v3_reply", vapi_msg_id_app_namespace_add_del_v3_reply);
}

static inline void vapi_set_vapi_msg_app_namespace_add_del_v3_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_app_namespace_add_del_v3_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_app_namespace_add_del_v3_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_app_namespace_add_del_v3
#define defined_vapi_msg_app_namespace_add_del_v3
typedef struct __attribute__ ((__packed__)) {
  u64 secret;
  bool is_add;
  vapi_type_interface_index sw_if_index;
  u32 ip4_fib_id;
  u32 ip6_fib_id;
  u8 namespace_id[64];
  u8 netns[64];
  vl_api_string_t sock_name; 
} vapi_payload_app_namespace_add_del_v3;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_app_namespace_add_del_v3 payload;
} vapi_msg_app_namespace_add_del_v3;

static inline void vapi_msg_app_namespace_add_del_v3_payload_hton(vapi_payload_app_namespace_add_del_v3 *payload)
{
  payload->secret = htobe64(payload->secret);
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->ip4_fib_id = htobe32(payload->ip4_fib_id);
  payload->ip6_fib_id = htobe32(payload->ip6_fib_id);
  vl_api_string_t_hton(&payload->sock_name);
}

static inline void vapi_msg_app_namespace_add_del_v3_payload_ntoh(vapi_payload_app_namespace_add_del_v3 *payload)
{
  payload->secret = be64toh(payload->secret);
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->ip4_fib_id = be32toh(payload->ip4_fib_id);
  payload->ip6_fib_id = be32toh(payload->ip6_fib_id);
  vl_api_string_t_ntoh(&payload->sock_name);
}

static inline void vapi_msg_app_namespace_add_del_v3_hton(vapi_msg_app_namespace_add_del_v3 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_namespace_add_del_v3'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_app_namespace_add_del_v3_payload_hton(&msg->payload);
}

static inline void vapi_msg_app_namespace_add_del_v3_ntoh(vapi_msg_app_namespace_add_del_v3 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_app_namespace_add_del_v3'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_app_namespace_add_del_v3_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_app_namespace_add_del_v3_msg_size(vapi_msg_app_namespace_add_del_v3 *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.sock_name.buf[0]) * msg->payload.sock_name.length;
}

static inline int vapi_verify_app_namespace_add_del_v3_msg_size(vapi_msg_app_namespace_add_del_v3 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_app_namespace_add_del_v3) > buf_size)
    {
      VAPI_ERR("Truncated 'app_namespace_add_del_v3' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_app_namespace_add_del_v3));
      return -1;
    }
  if (vapi_calc_app_namespace_add_del_v3_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'app_namespace_add_del_v3' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_app_namespace_add_del_v3_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_app_namespace_add_del_v3* vapi_alloc_app_namespace_add_del_v3(struct vapi_ctx_s *ctx, size_t sock_name_buf_array_size)
{
  vapi_msg_app_namespace_add_del_v3 *msg = NULL;
  const size_t size = sizeof(vapi_msg_app_namespace_add_del_v3) + sizeof(msg->payload.sock_name.buf[0]) * sock_name_buf_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_app_namespace_add_del_v3*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_app_namespace_add_del_v3);
  msg->payload.sock_name.length = sock_name_buf_array_size;

  return msg;
}

static inline vapi_error_e vapi_app_namespace_add_del_v3(struct vapi_ctx_s *ctx,
  vapi_msg_app_namespace_add_del_v3 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_app_namespace_add_del_v3_reply *reply),
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
  vapi_msg_app_namespace_add_del_v3_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_app_namespace_add_del_v3_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_app_namespace_add_del_v3_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_app_namespace_add_del_v3()
{
  static const char name[] = "app_namespace_add_del_v3";
  static const char name_with_crc[] = "app_namespace_add_del_v3_8a7e40a1";
  static vapi_message_desc_t __vapi_metadata_app_namespace_add_del_v3 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_app_namespace_add_del_v3, payload),
    (verify_msg_size_fn_t)vapi_verify_app_namespace_add_del_v3_msg_size,
    (generic_swap_fn_t)vapi_msg_app_namespace_add_del_v3_hton,
    (generic_swap_fn_t)vapi_msg_app_namespace_add_del_v3_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_app_namespace_add_del_v3 = vapi_register_msg(&__vapi_metadata_app_namespace_add_del_v3);
  VAPI_DBG("Assigned msg id %d to app_namespace_add_del_v3", vapi_msg_id_app_namespace_add_del_v3);
}
#endif

#ifndef defined_vapi_msg_session_rule_add_del_reply
#define defined_vapi_msg_session_rule_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_session_rule_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_session_rule_add_del_reply payload;
} vapi_msg_session_rule_add_del_reply;

static inline void vapi_msg_session_rule_add_del_reply_payload_hton(vapi_payload_session_rule_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_session_rule_add_del_reply_payload_ntoh(vapi_payload_session_rule_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_session_rule_add_del_reply_hton(vapi_msg_session_rule_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_rule_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_session_rule_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_session_rule_add_del_reply_ntoh(vapi_msg_session_rule_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_rule_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_session_rule_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_session_rule_add_del_reply_msg_size(vapi_msg_session_rule_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_session_rule_add_del_reply_msg_size(vapi_msg_session_rule_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_rule_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'session_rule_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_rule_add_del_reply));
      return -1;
    }
  if (vapi_calc_session_rule_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_rule_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_rule_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_session_rule_add_del_reply()
{
  static const char name[] = "session_rule_add_del_reply";
  static const char name_with_crc[] = "session_rule_add_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_session_rule_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_session_rule_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_session_rule_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_session_rule_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_session_rule_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_rule_add_del_reply = vapi_register_msg(&__vapi_metadata_session_rule_add_del_reply);
  VAPI_DBG("Assigned msg id %d to session_rule_add_del_reply", vapi_msg_id_session_rule_add_del_reply);
}

static inline void vapi_set_vapi_msg_session_rule_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_session_rule_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_session_rule_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_session_rule_add_del
#define defined_vapi_msg_session_rule_add_del
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_transport_proto transport_proto;
  vapi_type_prefix lcl;
  vapi_type_prefix rmt;
  u16 lcl_port;
  u16 rmt_port;
  u32 action_index;
  bool is_add;
  u32 appns_index;
  vapi_enum_session_rule_scope scope;
  u8 tag[64]; 
} vapi_payload_session_rule_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_session_rule_add_del payload;
} vapi_msg_session_rule_add_del;

static inline void vapi_msg_session_rule_add_del_payload_hton(vapi_payload_session_rule_add_del *payload)
{
  payload->lcl_port = htobe16(payload->lcl_port);
  payload->rmt_port = htobe16(payload->rmt_port);
  payload->action_index = htobe32(payload->action_index);
  payload->appns_index = htobe32(payload->appns_index);
  payload->scope = (vapi_enum_session_rule_scope)htobe32(payload->scope);
}

static inline void vapi_msg_session_rule_add_del_payload_ntoh(vapi_payload_session_rule_add_del *payload)
{
  payload->lcl_port = be16toh(payload->lcl_port);
  payload->rmt_port = be16toh(payload->rmt_port);
  payload->action_index = be32toh(payload->action_index);
  payload->appns_index = be32toh(payload->appns_index);
  payload->scope = (vapi_enum_session_rule_scope)be32toh(payload->scope);
}

static inline void vapi_msg_session_rule_add_del_hton(vapi_msg_session_rule_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_rule_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_session_rule_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_session_rule_add_del_ntoh(vapi_msg_session_rule_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_rule_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_session_rule_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_session_rule_add_del_msg_size(vapi_msg_session_rule_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_session_rule_add_del_msg_size(vapi_msg_session_rule_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_rule_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'session_rule_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_rule_add_del));
      return -1;
    }
  if (vapi_calc_session_rule_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_rule_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_rule_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_session_rule_add_del* vapi_alloc_session_rule_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_session_rule_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_session_rule_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_session_rule_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_session_rule_add_del);

  return msg;
}

static inline vapi_error_e vapi_session_rule_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_session_rule_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_session_rule_add_del_reply *reply),
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
  vapi_msg_session_rule_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_session_rule_add_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_session_rule_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_session_rule_add_del()
{
  static const char name[] = "session_rule_add_del";
  static const char name_with_crc[] = "session_rule_add_del_82a90af5";
  static vapi_message_desc_t __vapi_metadata_session_rule_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_session_rule_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_session_rule_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_session_rule_add_del_hton,
    (generic_swap_fn_t)vapi_msg_session_rule_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_rule_add_del = vapi_register_msg(&__vapi_metadata_session_rule_add_del);
  VAPI_DBG("Assigned msg id %d to session_rule_add_del", vapi_msg_id_session_rule_add_del);
}
#endif

#ifndef defined_vapi_msg_session_rules_details
#define defined_vapi_msg_session_rules_details
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_transport_proto transport_proto;
  vapi_type_prefix lcl;
  vapi_type_prefix rmt;
  u16 lcl_port;
  u16 rmt_port;
  u32 action_index;
  u32 appns_index;
  vapi_enum_session_rule_scope scope;
  u8 tag[64]; 
} vapi_payload_session_rules_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_session_rules_details payload;
} vapi_msg_session_rules_details;

static inline void vapi_msg_session_rules_details_payload_hton(vapi_payload_session_rules_details *payload)
{
  payload->lcl_port = htobe16(payload->lcl_port);
  payload->rmt_port = htobe16(payload->rmt_port);
  payload->action_index = htobe32(payload->action_index);
  payload->appns_index = htobe32(payload->appns_index);
  payload->scope = (vapi_enum_session_rule_scope)htobe32(payload->scope);
}

static inline void vapi_msg_session_rules_details_payload_ntoh(vapi_payload_session_rules_details *payload)
{
  payload->lcl_port = be16toh(payload->lcl_port);
  payload->rmt_port = be16toh(payload->rmt_port);
  payload->action_index = be32toh(payload->action_index);
  payload->appns_index = be32toh(payload->appns_index);
  payload->scope = (vapi_enum_session_rule_scope)be32toh(payload->scope);
}

static inline void vapi_msg_session_rules_details_hton(vapi_msg_session_rules_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_rules_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_session_rules_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_session_rules_details_ntoh(vapi_msg_session_rules_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_rules_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_session_rules_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_session_rules_details_msg_size(vapi_msg_session_rules_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_session_rules_details_msg_size(vapi_msg_session_rules_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_rules_details) > buf_size)
    {
      VAPI_ERR("Truncated 'session_rules_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_rules_details));
      return -1;
    }
  if (vapi_calc_session_rules_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_rules_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_rules_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_session_rules_details()
{
  static const char name[] = "session_rules_details";
  static const char name_with_crc[] = "session_rules_details_4ef746e7";
  static vapi_message_desc_t __vapi_metadata_session_rules_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_session_rules_details, payload),
    (verify_msg_size_fn_t)vapi_verify_session_rules_details_msg_size,
    (generic_swap_fn_t)vapi_msg_session_rules_details_hton,
    (generic_swap_fn_t)vapi_msg_session_rules_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_rules_details = vapi_register_msg(&__vapi_metadata_session_rules_details);
  VAPI_DBG("Assigned msg id %d to session_rules_details", vapi_msg_id_session_rules_details);
}

static inline void vapi_set_vapi_msg_session_rules_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_session_rules_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_session_rules_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_session_rules_dump
#define defined_vapi_msg_session_rules_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_session_rules_dump;

static inline void vapi_msg_session_rules_dump_hton(vapi_msg_session_rules_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_rules_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_session_rules_dump_ntoh(vapi_msg_session_rules_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_rules_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_session_rules_dump_msg_size(vapi_msg_session_rules_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_session_rules_dump_msg_size(vapi_msg_session_rules_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_rules_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'session_rules_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_rules_dump));
      return -1;
    }
  if (vapi_calc_session_rules_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_rules_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_rules_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_session_rules_dump* vapi_alloc_session_rules_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_session_rules_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_session_rules_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_session_rules_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_session_rules_dump);

  return msg;
}

static inline vapi_error_e vapi_session_rules_dump(struct vapi_ctx_s *ctx,
  vapi_msg_session_rules_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_session_rules_details *reply),
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
  vapi_msg_session_rules_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_session_rules_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_session_rules_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_session_rules_dump()
{
  static const char name[] = "session_rules_dump";
  static const char name_with_crc[] = "session_rules_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_session_rules_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_session_rules_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_session_rules_dump_hton,
    (generic_swap_fn_t)vapi_msg_session_rules_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_rules_dump = vapi_register_msg(&__vapi_metadata_session_rules_dump);
  VAPI_DBG("Assigned msg id %d to session_rules_dump", vapi_msg_id_session_rules_dump);
}
#endif

#ifndef defined_vapi_msg_session_rules_v2_details
#define defined_vapi_msg_session_rules_v2_details
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_transport_proto transport_proto;
  vapi_type_prefix lcl;
  vapi_type_prefix rmt;
  u16 lcl_port;
  u16 rmt_port;
  u32 action_index;
  vapi_enum_session_rule_scope scope;
  u8 tag[64];
  u32 count;
  u32 appns_index[0]; 
} vapi_payload_session_rules_v2_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_session_rules_v2_details payload;
} vapi_msg_session_rules_v2_details;

static inline void vapi_msg_session_rules_v2_details_payload_hton(vapi_payload_session_rules_v2_details *payload)
{
  payload->lcl_port = htobe16(payload->lcl_port);
  payload->rmt_port = htobe16(payload->rmt_port);
  payload->action_index = htobe32(payload->action_index);
  payload->scope = (vapi_enum_session_rule_scope)htobe32(payload->scope);
  payload->count = htobe32(payload->count);
  do { unsigned i; for (i = 0; i < be32toh(payload->count); ++i) { payload->appns_index[i] = htobe32(payload->appns_index[i]); } } while(0);
}

static inline void vapi_msg_session_rules_v2_details_payload_ntoh(vapi_payload_session_rules_v2_details *payload)
{
  payload->lcl_port = be16toh(payload->lcl_port);
  payload->rmt_port = be16toh(payload->rmt_port);
  payload->action_index = be32toh(payload->action_index);
  payload->scope = (vapi_enum_session_rule_scope)be32toh(payload->scope);
  payload->count = be32toh(payload->count);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { payload->appns_index[i] = be32toh(payload->appns_index[i]); } } while(0);
}

static inline void vapi_msg_session_rules_v2_details_hton(vapi_msg_session_rules_v2_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_rules_v2_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_session_rules_v2_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_session_rules_v2_details_ntoh(vapi_msg_session_rules_v2_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_rules_v2_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_session_rules_v2_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_session_rules_v2_details_msg_size(vapi_msg_session_rules_v2_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.appns_index[0]) * msg->payload.count;
}

static inline int vapi_verify_session_rules_v2_details_msg_size(vapi_msg_session_rules_v2_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_rules_v2_details) > buf_size)
    {
      VAPI_ERR("Truncated 'session_rules_v2_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_rules_v2_details));
      return -1;
    }
  if (vapi_calc_session_rules_v2_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_rules_v2_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_rules_v2_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_session_rules_v2_details()
{
  static const char name[] = "session_rules_v2_details";
  static const char name_with_crc[] = "session_rules_v2_details_f91993dc";
  static vapi_message_desc_t __vapi_metadata_session_rules_v2_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_session_rules_v2_details, payload),
    (verify_msg_size_fn_t)vapi_verify_session_rules_v2_details_msg_size,
    (generic_swap_fn_t)vapi_msg_session_rules_v2_details_hton,
    (generic_swap_fn_t)vapi_msg_session_rules_v2_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_rules_v2_details = vapi_register_msg(&__vapi_metadata_session_rules_v2_details);
  VAPI_DBG("Assigned msg id %d to session_rules_v2_details", vapi_msg_id_session_rules_v2_details);
}

static inline void vapi_set_vapi_msg_session_rules_v2_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_session_rules_v2_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_session_rules_v2_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_session_rules_v2_dump
#define defined_vapi_msg_session_rules_v2_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_session_rules_v2_dump;

static inline void vapi_msg_session_rules_v2_dump_hton(vapi_msg_session_rules_v2_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_rules_v2_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_session_rules_v2_dump_ntoh(vapi_msg_session_rules_v2_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_rules_v2_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_session_rules_v2_dump_msg_size(vapi_msg_session_rules_v2_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_session_rules_v2_dump_msg_size(vapi_msg_session_rules_v2_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_rules_v2_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'session_rules_v2_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_rules_v2_dump));
      return -1;
    }
  if (vapi_calc_session_rules_v2_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_rules_v2_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_rules_v2_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_session_rules_v2_dump* vapi_alloc_session_rules_v2_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_session_rules_v2_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_session_rules_v2_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_session_rules_v2_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_session_rules_v2_dump);

  return msg;
}

static inline vapi_error_e vapi_session_rules_v2_dump(struct vapi_ctx_s *ctx,
  vapi_msg_session_rules_v2_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_session_rules_v2_details *reply),
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
  vapi_msg_session_rules_v2_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_session_rules_v2_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_session_rules_v2_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_session_rules_v2_dump()
{
  static const char name[] = "session_rules_v2_dump";
  static const char name_with_crc[] = "session_rules_v2_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_session_rules_v2_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_session_rules_v2_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_session_rules_v2_dump_hton,
    (generic_swap_fn_t)vapi_msg_session_rules_v2_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_rules_v2_dump = vapi_register_msg(&__vapi_metadata_session_rules_v2_dump);
  VAPI_DBG("Assigned msg id %d to session_rules_v2_dump", vapi_msg_id_session_rules_v2_dump);
}
#endif

#ifndef defined_vapi_msg_session_sdl_add_del_reply
#define defined_vapi_msg_session_sdl_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_session_sdl_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_session_sdl_add_del_reply payload;
} vapi_msg_session_sdl_add_del_reply;

static inline void vapi_msg_session_sdl_add_del_reply_payload_hton(vapi_payload_session_sdl_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_session_sdl_add_del_reply_payload_ntoh(vapi_payload_session_sdl_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_session_sdl_add_del_reply_hton(vapi_msg_session_sdl_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sdl_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_session_sdl_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_session_sdl_add_del_reply_ntoh(vapi_msg_session_sdl_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sdl_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_session_sdl_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_session_sdl_add_del_reply_msg_size(vapi_msg_session_sdl_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_session_sdl_add_del_reply_msg_size(vapi_msg_session_sdl_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_sdl_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sdl_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_sdl_add_del_reply));
      return -1;
    }
  if (vapi_calc_session_sdl_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sdl_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_sdl_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_session_sdl_add_del_reply()
{
  static const char name[] = "session_sdl_add_del_reply";
  static const char name_with_crc[] = "session_sdl_add_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_session_sdl_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_session_sdl_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_session_sdl_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_session_sdl_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_session_sdl_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_sdl_add_del_reply = vapi_register_msg(&__vapi_metadata_session_sdl_add_del_reply);
  VAPI_DBG("Assigned msg id %d to session_sdl_add_del_reply", vapi_msg_id_session_sdl_add_del_reply);
}

static inline void vapi_set_vapi_msg_session_sdl_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_session_sdl_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_session_sdl_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_session_sdl_add_del
#define defined_vapi_msg_session_sdl_add_del
typedef struct __attribute__ ((__packed__)) {
  u32 appns_index;
  bool is_add;
  u32 count;
  vapi_type_sdl_rule r[0]; 
} vapi_payload_session_sdl_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_session_sdl_add_del payload;
} vapi_msg_session_sdl_add_del;

static inline void vapi_msg_session_sdl_add_del_payload_hton(vapi_payload_session_sdl_add_del *payload)
{
  payload->appns_index = htobe32(payload->appns_index);
  payload->count = htobe32(payload->count);
  do { unsigned i; for (i = 0; i < be32toh(payload->count); ++i) { vapi_type_sdl_rule_hton(&payload->r[i]); } } while(0);
}

static inline void vapi_msg_session_sdl_add_del_payload_ntoh(vapi_payload_session_sdl_add_del *payload)
{
  payload->appns_index = be32toh(payload->appns_index);
  payload->count = be32toh(payload->count);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { vapi_type_sdl_rule_ntoh(&payload->r[i]); } } while(0);
}

static inline void vapi_msg_session_sdl_add_del_hton(vapi_msg_session_sdl_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sdl_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_session_sdl_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_session_sdl_add_del_ntoh(vapi_msg_session_sdl_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sdl_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_session_sdl_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_session_sdl_add_del_msg_size(vapi_msg_session_sdl_add_del *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.r[0]) * msg->payload.count;
}

static inline int vapi_verify_session_sdl_add_del_msg_size(vapi_msg_session_sdl_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_sdl_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sdl_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_sdl_add_del));
      return -1;
    }
  if (vapi_calc_session_sdl_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sdl_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_sdl_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_session_sdl_add_del* vapi_alloc_session_sdl_add_del(struct vapi_ctx_s *ctx, size_t _r_array_size)
{
  vapi_msg_session_sdl_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_session_sdl_add_del) + sizeof(msg->payload.r[0]) * _r_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_session_sdl_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_session_sdl_add_del);
  msg->payload.count = _r_array_size;

  return msg;
}

static inline vapi_error_e vapi_session_sdl_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_session_sdl_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_session_sdl_add_del_reply *reply),
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
  vapi_msg_session_sdl_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_session_sdl_add_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_session_sdl_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_session_sdl_add_del()
{
  static const char name[] = "session_sdl_add_del";
  static const char name_with_crc[] = "session_sdl_add_del_faeb89fc";
  static vapi_message_desc_t __vapi_metadata_session_sdl_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_session_sdl_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_session_sdl_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_session_sdl_add_del_hton,
    (generic_swap_fn_t)vapi_msg_session_sdl_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_sdl_add_del = vapi_register_msg(&__vapi_metadata_session_sdl_add_del);
  VAPI_DBG("Assigned msg id %d to session_sdl_add_del", vapi_msg_id_session_sdl_add_del);
}
#endif

#ifndef defined_vapi_msg_session_sdl_add_del_v2_reply
#define defined_vapi_msg_session_sdl_add_del_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_session_sdl_add_del_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_session_sdl_add_del_v2_reply payload;
} vapi_msg_session_sdl_add_del_v2_reply;

static inline void vapi_msg_session_sdl_add_del_v2_reply_payload_hton(vapi_payload_session_sdl_add_del_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_session_sdl_add_del_v2_reply_payload_ntoh(vapi_payload_session_sdl_add_del_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_session_sdl_add_del_v2_reply_hton(vapi_msg_session_sdl_add_del_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sdl_add_del_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_session_sdl_add_del_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_session_sdl_add_del_v2_reply_ntoh(vapi_msg_session_sdl_add_del_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sdl_add_del_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_session_sdl_add_del_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_session_sdl_add_del_v2_reply_msg_size(vapi_msg_session_sdl_add_del_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_session_sdl_add_del_v2_reply_msg_size(vapi_msg_session_sdl_add_del_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_sdl_add_del_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sdl_add_del_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_sdl_add_del_v2_reply));
      return -1;
    }
  if (vapi_calc_session_sdl_add_del_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sdl_add_del_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_sdl_add_del_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_session_sdl_add_del_v2_reply()
{
  static const char name[] = "session_sdl_add_del_v2_reply";
  static const char name_with_crc[] = "session_sdl_add_del_v2_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_session_sdl_add_del_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_session_sdl_add_del_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_session_sdl_add_del_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_session_sdl_add_del_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_session_sdl_add_del_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_sdl_add_del_v2_reply = vapi_register_msg(&__vapi_metadata_session_sdl_add_del_v2_reply);
  VAPI_DBG("Assigned msg id %d to session_sdl_add_del_v2_reply", vapi_msg_id_session_sdl_add_del_v2_reply);
}

static inline void vapi_set_vapi_msg_session_sdl_add_del_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_session_sdl_add_del_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_session_sdl_add_del_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_session_sdl_add_del_v2
#define defined_vapi_msg_session_sdl_add_del_v2
typedef struct __attribute__ ((__packed__)) {
  u32 appns_index;
  bool is_add;
  u32 count;
  vapi_type_sdl_rule_v2 r[0]; 
} vapi_payload_session_sdl_add_del_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_session_sdl_add_del_v2 payload;
} vapi_msg_session_sdl_add_del_v2;

static inline void vapi_msg_session_sdl_add_del_v2_payload_hton(vapi_payload_session_sdl_add_del_v2 *payload)
{
  payload->appns_index = htobe32(payload->appns_index);
  payload->count = htobe32(payload->count);
  do { unsigned i; for (i = 0; i < be32toh(payload->count); ++i) { vapi_type_sdl_rule_v2_hton(&payload->r[i]); } } while(0);
}

static inline void vapi_msg_session_sdl_add_del_v2_payload_ntoh(vapi_payload_session_sdl_add_del_v2 *payload)
{
  payload->appns_index = be32toh(payload->appns_index);
  payload->count = be32toh(payload->count);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { vapi_type_sdl_rule_v2_ntoh(&payload->r[i]); } } while(0);
}

static inline void vapi_msg_session_sdl_add_del_v2_hton(vapi_msg_session_sdl_add_del_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sdl_add_del_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_session_sdl_add_del_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_session_sdl_add_del_v2_ntoh(vapi_msg_session_sdl_add_del_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sdl_add_del_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_session_sdl_add_del_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_session_sdl_add_del_v2_msg_size(vapi_msg_session_sdl_add_del_v2 *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.r[0]) * msg->payload.count;
}

static inline int vapi_verify_session_sdl_add_del_v2_msg_size(vapi_msg_session_sdl_add_del_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_sdl_add_del_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sdl_add_del_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_sdl_add_del_v2));
      return -1;
    }
  if (vapi_calc_session_sdl_add_del_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sdl_add_del_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_sdl_add_del_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_session_sdl_add_del_v2* vapi_alloc_session_sdl_add_del_v2(struct vapi_ctx_s *ctx, size_t _r_array_size)
{
  vapi_msg_session_sdl_add_del_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_session_sdl_add_del_v2) + sizeof(msg->payload.r[0]) * _r_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_session_sdl_add_del_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_session_sdl_add_del_v2);
  msg->payload.count = _r_array_size;

  return msg;
}

static inline vapi_error_e vapi_session_sdl_add_del_v2(struct vapi_ctx_s *ctx,
  vapi_msg_session_sdl_add_del_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_session_sdl_add_del_v2_reply *reply),
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
  vapi_msg_session_sdl_add_del_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_session_sdl_add_del_v2_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_session_sdl_add_del_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_session_sdl_add_del_v2()
{
  static const char name[] = "session_sdl_add_del_v2";
  static const char name_with_crc[] = "session_sdl_add_del_v2_7f89d3fa";
  static vapi_message_desc_t __vapi_metadata_session_sdl_add_del_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_session_sdl_add_del_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_session_sdl_add_del_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_session_sdl_add_del_v2_hton,
    (generic_swap_fn_t)vapi_msg_session_sdl_add_del_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_sdl_add_del_v2 = vapi_register_msg(&__vapi_metadata_session_sdl_add_del_v2);
  VAPI_DBG("Assigned msg id %d to session_sdl_add_del_v2", vapi_msg_id_session_sdl_add_del_v2);
}
#endif

#ifndef defined_vapi_msg_session_sdl_details
#define defined_vapi_msg_session_sdl_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_prefix lcl;
  u32 action_index;
  u32 appns_index;
  u8 tag[64]; 
} vapi_payload_session_sdl_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_session_sdl_details payload;
} vapi_msg_session_sdl_details;

static inline void vapi_msg_session_sdl_details_payload_hton(vapi_payload_session_sdl_details *payload)
{
  payload->action_index = htobe32(payload->action_index);
  payload->appns_index = htobe32(payload->appns_index);
}

static inline void vapi_msg_session_sdl_details_payload_ntoh(vapi_payload_session_sdl_details *payload)
{
  payload->action_index = be32toh(payload->action_index);
  payload->appns_index = be32toh(payload->appns_index);
}

static inline void vapi_msg_session_sdl_details_hton(vapi_msg_session_sdl_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sdl_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_session_sdl_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_session_sdl_details_ntoh(vapi_msg_session_sdl_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sdl_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_session_sdl_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_session_sdl_details_msg_size(vapi_msg_session_sdl_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_session_sdl_details_msg_size(vapi_msg_session_sdl_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_sdl_details) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sdl_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_sdl_details));
      return -1;
    }
  if (vapi_calc_session_sdl_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sdl_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_sdl_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_session_sdl_details()
{
  static const char name[] = "session_sdl_details";
  static const char name_with_crc[] = "session_sdl_details_9a8ef5d0";
  static vapi_message_desc_t __vapi_metadata_session_sdl_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_session_sdl_details, payload),
    (verify_msg_size_fn_t)vapi_verify_session_sdl_details_msg_size,
    (generic_swap_fn_t)vapi_msg_session_sdl_details_hton,
    (generic_swap_fn_t)vapi_msg_session_sdl_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_sdl_details = vapi_register_msg(&__vapi_metadata_session_sdl_details);
  VAPI_DBG("Assigned msg id %d to session_sdl_details", vapi_msg_id_session_sdl_details);
}

static inline void vapi_set_vapi_msg_session_sdl_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_session_sdl_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_session_sdl_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_session_sdl_dump
#define defined_vapi_msg_session_sdl_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_session_sdl_dump;

static inline void vapi_msg_session_sdl_dump_hton(vapi_msg_session_sdl_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sdl_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_session_sdl_dump_ntoh(vapi_msg_session_sdl_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sdl_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_session_sdl_dump_msg_size(vapi_msg_session_sdl_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_session_sdl_dump_msg_size(vapi_msg_session_sdl_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_sdl_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sdl_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_sdl_dump));
      return -1;
    }
  if (vapi_calc_session_sdl_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sdl_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_sdl_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_session_sdl_dump* vapi_alloc_session_sdl_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_session_sdl_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_session_sdl_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_session_sdl_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_session_sdl_dump);

  return msg;
}

static inline vapi_error_e vapi_session_sdl_dump(struct vapi_ctx_s *ctx,
  vapi_msg_session_sdl_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_session_sdl_details *reply),
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
  vapi_msg_session_sdl_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_session_sdl_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_session_sdl_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_session_sdl_dump()
{
  static const char name[] = "session_sdl_dump";
  static const char name_with_crc[] = "session_sdl_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_session_sdl_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_session_sdl_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_session_sdl_dump_hton,
    (generic_swap_fn_t)vapi_msg_session_sdl_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_sdl_dump = vapi_register_msg(&__vapi_metadata_session_sdl_dump);
  VAPI_DBG("Assigned msg id %d to session_sdl_dump", vapi_msg_id_session_sdl_dump);
}
#endif

#ifndef defined_vapi_msg_session_sdl_v2_details
#define defined_vapi_msg_session_sdl_v2_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_prefix rmt;
  u32 action_index;
  u32 appns_index;
  u8 tag[64]; 
} vapi_payload_session_sdl_v2_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_session_sdl_v2_details payload;
} vapi_msg_session_sdl_v2_details;

static inline void vapi_msg_session_sdl_v2_details_payload_hton(vapi_payload_session_sdl_v2_details *payload)
{
  payload->action_index = htobe32(payload->action_index);
  payload->appns_index = htobe32(payload->appns_index);
}

static inline void vapi_msg_session_sdl_v2_details_payload_ntoh(vapi_payload_session_sdl_v2_details *payload)
{
  payload->action_index = be32toh(payload->action_index);
  payload->appns_index = be32toh(payload->appns_index);
}

static inline void vapi_msg_session_sdl_v2_details_hton(vapi_msg_session_sdl_v2_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sdl_v2_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_session_sdl_v2_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_session_sdl_v2_details_ntoh(vapi_msg_session_sdl_v2_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sdl_v2_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_session_sdl_v2_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_session_sdl_v2_details_msg_size(vapi_msg_session_sdl_v2_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_session_sdl_v2_details_msg_size(vapi_msg_session_sdl_v2_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_sdl_v2_details) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sdl_v2_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_sdl_v2_details));
      return -1;
    }
  if (vapi_calc_session_sdl_v2_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sdl_v2_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_sdl_v2_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_session_sdl_v2_details()
{
  static const char name[] = "session_sdl_v2_details";
  static const char name_with_crc[] = "session_sdl_v2_details_0a057683";
  static vapi_message_desc_t __vapi_metadata_session_sdl_v2_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_session_sdl_v2_details, payload),
    (verify_msg_size_fn_t)vapi_verify_session_sdl_v2_details_msg_size,
    (generic_swap_fn_t)vapi_msg_session_sdl_v2_details_hton,
    (generic_swap_fn_t)vapi_msg_session_sdl_v2_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_sdl_v2_details = vapi_register_msg(&__vapi_metadata_session_sdl_v2_details);
  VAPI_DBG("Assigned msg id %d to session_sdl_v2_details", vapi_msg_id_session_sdl_v2_details);
}

static inline void vapi_set_vapi_msg_session_sdl_v2_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_session_sdl_v2_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_session_sdl_v2_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_session_sdl_v2_dump
#define defined_vapi_msg_session_sdl_v2_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_session_sdl_v2_dump;

static inline void vapi_msg_session_sdl_v2_dump_hton(vapi_msg_session_sdl_v2_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sdl_v2_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_session_sdl_v2_dump_ntoh(vapi_msg_session_sdl_v2_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sdl_v2_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_session_sdl_v2_dump_msg_size(vapi_msg_session_sdl_v2_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_session_sdl_v2_dump_msg_size(vapi_msg_session_sdl_v2_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_sdl_v2_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sdl_v2_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_sdl_v2_dump));
      return -1;
    }
  if (vapi_calc_session_sdl_v2_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sdl_v2_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_sdl_v2_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_session_sdl_v2_dump* vapi_alloc_session_sdl_v2_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_session_sdl_v2_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_session_sdl_v2_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_session_sdl_v2_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_session_sdl_v2_dump);

  return msg;
}

static inline vapi_error_e vapi_session_sdl_v2_dump(struct vapi_ctx_s *ctx,
  vapi_msg_session_sdl_v2_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_session_sdl_v2_details *reply),
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
  vapi_msg_session_sdl_v2_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_session_sdl_v2_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_session_sdl_v2_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_session_sdl_v2_dump()
{
  static const char name[] = "session_sdl_v2_dump";
  static const char name_with_crc[] = "session_sdl_v2_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_session_sdl_v2_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_session_sdl_v2_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_session_sdl_v2_dump_hton,
    (generic_swap_fn_t)vapi_msg_session_sdl_v2_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_sdl_v2_dump = vapi_register_msg(&__vapi_metadata_session_sdl_v2_dump);
  VAPI_DBG("Assigned msg id %d to session_sdl_v2_dump", vapi_msg_id_session_sdl_v2_dump);
}
#endif

#ifndef defined_vapi_msg_session_sdl_v3_details
#define defined_vapi_msg_session_sdl_v3_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_prefix rmt;
  u32 action_index;
  u8 tag[64];
  u32 count;
  u32 appns_index[0]; 
} vapi_payload_session_sdl_v3_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_session_sdl_v3_details payload;
} vapi_msg_session_sdl_v3_details;

static inline void vapi_msg_session_sdl_v3_details_payload_hton(vapi_payload_session_sdl_v3_details *payload)
{
  payload->action_index = htobe32(payload->action_index);
  payload->count = htobe32(payload->count);
  do { unsigned i; for (i = 0; i < be32toh(payload->count); ++i) { payload->appns_index[i] = htobe32(payload->appns_index[i]); } } while(0);
}

static inline void vapi_msg_session_sdl_v3_details_payload_ntoh(vapi_payload_session_sdl_v3_details *payload)
{
  payload->action_index = be32toh(payload->action_index);
  payload->count = be32toh(payload->count);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { payload->appns_index[i] = be32toh(payload->appns_index[i]); } } while(0);
}

static inline void vapi_msg_session_sdl_v3_details_hton(vapi_msg_session_sdl_v3_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sdl_v3_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_session_sdl_v3_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_session_sdl_v3_details_ntoh(vapi_msg_session_sdl_v3_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sdl_v3_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_session_sdl_v3_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_session_sdl_v3_details_msg_size(vapi_msg_session_sdl_v3_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.appns_index[0]) * msg->payload.count;
}

static inline int vapi_verify_session_sdl_v3_details_msg_size(vapi_msg_session_sdl_v3_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_sdl_v3_details) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sdl_v3_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_sdl_v3_details));
      return -1;
    }
  if (vapi_calc_session_sdl_v3_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sdl_v3_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_sdl_v3_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_session_sdl_v3_details()
{
  static const char name[] = "session_sdl_v3_details";
  static const char name_with_crc[] = "session_sdl_v3_details_829e367f";
  static vapi_message_desc_t __vapi_metadata_session_sdl_v3_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_session_sdl_v3_details, payload),
    (verify_msg_size_fn_t)vapi_verify_session_sdl_v3_details_msg_size,
    (generic_swap_fn_t)vapi_msg_session_sdl_v3_details_hton,
    (generic_swap_fn_t)vapi_msg_session_sdl_v3_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_sdl_v3_details = vapi_register_msg(&__vapi_metadata_session_sdl_v3_details);
  VAPI_DBG("Assigned msg id %d to session_sdl_v3_details", vapi_msg_id_session_sdl_v3_details);
}

static inline void vapi_set_vapi_msg_session_sdl_v3_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_session_sdl_v3_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_session_sdl_v3_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_session_sdl_v3_dump
#define defined_vapi_msg_session_sdl_v3_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_session_sdl_v3_dump;

static inline void vapi_msg_session_sdl_v3_dump_hton(vapi_msg_session_sdl_v3_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sdl_v3_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_session_sdl_v3_dump_ntoh(vapi_msg_session_sdl_v3_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_session_sdl_v3_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_session_sdl_v3_dump_msg_size(vapi_msg_session_sdl_v3_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_session_sdl_v3_dump_msg_size(vapi_msg_session_sdl_v3_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_session_sdl_v3_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sdl_v3_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_session_sdl_v3_dump));
      return -1;
    }
  if (vapi_calc_session_sdl_v3_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'session_sdl_v3_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_session_sdl_v3_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_session_sdl_v3_dump* vapi_alloc_session_sdl_v3_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_session_sdl_v3_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_session_sdl_v3_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_session_sdl_v3_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_session_sdl_v3_dump);

  return msg;
}

static inline vapi_error_e vapi_session_sdl_v3_dump(struct vapi_ctx_s *ctx,
  vapi_msg_session_sdl_v3_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_session_sdl_v3_details *reply),
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
  vapi_msg_session_sdl_v3_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_session_sdl_v3_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_session_sdl_v3_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_session_sdl_v3_dump()
{
  static const char name[] = "session_sdl_v3_dump";
  static const char name_with_crc[] = "session_sdl_v3_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_session_sdl_v3_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_session_sdl_v3_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_session_sdl_v3_dump_hton,
    (generic_swap_fn_t)vapi_msg_session_sdl_v3_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_session_sdl_v3_dump = vapi_register_msg(&__vapi_metadata_session_sdl_v3_dump);
  VAPI_DBG("Assigned msg id %d to session_sdl_v3_dump", vapi_msg_id_session_sdl_v3_dump);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
