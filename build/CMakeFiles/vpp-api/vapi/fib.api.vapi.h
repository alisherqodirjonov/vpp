#ifndef __included_fib_api_json
#define __included_fib_api_json

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

extern vapi_msg_id_t vapi_msg_id_fib_source_add;
extern vapi_msg_id_t vapi_msg_id_fib_source_add_reply;
extern vapi_msg_id_t vapi_msg_id_fib_source_dump;
extern vapi_msg_id_t vapi_msg_id_fib_source_details;

#define DEFINE_VAPI_MSG_IDS_FIB_API_JSON\
  vapi_msg_id_t vapi_msg_id_fib_source_add;\
  vapi_msg_id_t vapi_msg_id_fib_source_add_reply;\
  vapi_msg_id_t vapi_msg_id_fib_source_dump;\
  vapi_msg_id_t vapi_msg_id_fib_source_details;


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

#ifndef defined_vapi_type_fib_source
#define defined_vapi_type_fib_source
typedef struct __attribute__((__packed__)) {
  u8 priority;
  u8 id;
  u8 name[64];
} vapi_type_fib_source;

static inline void vapi_type_fib_source_hton(vapi_type_fib_source *msg)
{

}

static inline void vapi_type_fib_source_ntoh(vapi_type_fib_source *msg)
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

#ifndef defined_vapi_msg_fib_source_add_reply
#define defined_vapi_msg_fib_source_add_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u8 id; 
} vapi_payload_fib_source_add_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_fib_source_add_reply payload;
} vapi_msg_fib_source_add_reply;

static inline void vapi_msg_fib_source_add_reply_payload_hton(vapi_payload_fib_source_add_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_fib_source_add_reply_payload_ntoh(vapi_payload_fib_source_add_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_fib_source_add_reply_hton(vapi_msg_fib_source_add_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_fib_source_add_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_fib_source_add_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_fib_source_add_reply_ntoh(vapi_msg_fib_source_add_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_fib_source_add_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_fib_source_add_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_fib_source_add_reply_msg_size(vapi_msg_fib_source_add_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_fib_source_add_reply_msg_size(vapi_msg_fib_source_add_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_fib_source_add_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'fib_source_add_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_fib_source_add_reply));
      return -1;
    }
  if (vapi_calc_fib_source_add_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'fib_source_add_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_fib_source_add_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_fib_source_add_reply()
{
  static const char name[] = "fib_source_add_reply";
  static const char name_with_crc[] = "fib_source_add_reply_604fd6f1";
  static vapi_message_desc_t __vapi_metadata_fib_source_add_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_fib_source_add_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_fib_source_add_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_fib_source_add_reply_hton,
    (generic_swap_fn_t)vapi_msg_fib_source_add_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_fib_source_add_reply = vapi_register_msg(&__vapi_metadata_fib_source_add_reply);
  VAPI_DBG("Assigned msg id %d to fib_source_add_reply", vapi_msg_id_fib_source_add_reply);
}

static inline void vapi_set_vapi_msg_fib_source_add_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_fib_source_add_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_fib_source_add_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_fib_source_add
#define defined_vapi_msg_fib_source_add
typedef struct __attribute__ ((__packed__)) {
  vapi_type_fib_source src; 
} vapi_payload_fib_source_add;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_fib_source_add payload;
} vapi_msg_fib_source_add;

static inline void vapi_msg_fib_source_add_payload_hton(vapi_payload_fib_source_add *payload)
{

}

static inline void vapi_msg_fib_source_add_payload_ntoh(vapi_payload_fib_source_add *payload)
{

}

static inline void vapi_msg_fib_source_add_hton(vapi_msg_fib_source_add *msg)
{
  VAPI_DBG("Swapping `vapi_msg_fib_source_add'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_fib_source_add_payload_hton(&msg->payload);
}

static inline void vapi_msg_fib_source_add_ntoh(vapi_msg_fib_source_add *msg)
{
  VAPI_DBG("Swapping `vapi_msg_fib_source_add'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_fib_source_add_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_fib_source_add_msg_size(vapi_msg_fib_source_add *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_fib_source_add_msg_size(vapi_msg_fib_source_add *msg, uword buf_size)
{
  if (sizeof(vapi_msg_fib_source_add) > buf_size)
    {
      VAPI_ERR("Truncated 'fib_source_add' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_fib_source_add));
      return -1;
    }
  if (vapi_calc_fib_source_add_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'fib_source_add' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_fib_source_add_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_fib_source_add* vapi_alloc_fib_source_add(struct vapi_ctx_s *ctx)
{
  vapi_msg_fib_source_add *msg = NULL;
  const size_t size = sizeof(vapi_msg_fib_source_add);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_fib_source_add*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_fib_source_add);

  return msg;
}

static inline vapi_error_e vapi_fib_source_add(struct vapi_ctx_s *ctx,
  vapi_msg_fib_source_add *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_fib_source_add_reply *reply),
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
  vapi_msg_fib_source_add_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_fib_source_add_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_fib_source_add_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_fib_source_add()
{
  static const char name[] = "fib_source_add";
  static const char name_with_crc[] = "fib_source_add_b3ac2aec";
  static vapi_message_desc_t __vapi_metadata_fib_source_add = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_fib_source_add, payload),
    (verify_msg_size_fn_t)vapi_verify_fib_source_add_msg_size,
    (generic_swap_fn_t)vapi_msg_fib_source_add_hton,
    (generic_swap_fn_t)vapi_msg_fib_source_add_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_fib_source_add = vapi_register_msg(&__vapi_metadata_fib_source_add);
  VAPI_DBG("Assigned msg id %d to fib_source_add", vapi_msg_id_fib_source_add);
}
#endif

#ifndef defined_vapi_msg_fib_source_details
#define defined_vapi_msg_fib_source_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_fib_source src; 
} vapi_payload_fib_source_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_fib_source_details payload;
} vapi_msg_fib_source_details;

static inline void vapi_msg_fib_source_details_payload_hton(vapi_payload_fib_source_details *payload)
{

}

static inline void vapi_msg_fib_source_details_payload_ntoh(vapi_payload_fib_source_details *payload)
{

}

static inline void vapi_msg_fib_source_details_hton(vapi_msg_fib_source_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_fib_source_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_fib_source_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_fib_source_details_ntoh(vapi_msg_fib_source_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_fib_source_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_fib_source_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_fib_source_details_msg_size(vapi_msg_fib_source_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_fib_source_details_msg_size(vapi_msg_fib_source_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_fib_source_details) > buf_size)
    {
      VAPI_ERR("Truncated 'fib_source_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_fib_source_details));
      return -1;
    }
  if (vapi_calc_fib_source_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'fib_source_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_fib_source_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_fib_source_details()
{
  static const char name[] = "fib_source_details";
  static const char name_with_crc[] = "fib_source_details_8668acdb";
  static vapi_message_desc_t __vapi_metadata_fib_source_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_fib_source_details, payload),
    (verify_msg_size_fn_t)vapi_verify_fib_source_details_msg_size,
    (generic_swap_fn_t)vapi_msg_fib_source_details_hton,
    (generic_swap_fn_t)vapi_msg_fib_source_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_fib_source_details = vapi_register_msg(&__vapi_metadata_fib_source_details);
  VAPI_DBG("Assigned msg id %d to fib_source_details", vapi_msg_id_fib_source_details);
}

static inline void vapi_set_vapi_msg_fib_source_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_fib_source_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_fib_source_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_fib_source_dump
#define defined_vapi_msg_fib_source_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_fib_source_dump;

static inline void vapi_msg_fib_source_dump_hton(vapi_msg_fib_source_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_fib_source_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_fib_source_dump_ntoh(vapi_msg_fib_source_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_fib_source_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_fib_source_dump_msg_size(vapi_msg_fib_source_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_fib_source_dump_msg_size(vapi_msg_fib_source_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_fib_source_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'fib_source_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_fib_source_dump));
      return -1;
    }
  if (vapi_calc_fib_source_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'fib_source_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_fib_source_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_fib_source_dump* vapi_alloc_fib_source_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_fib_source_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_fib_source_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_fib_source_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_fib_source_dump);

  return msg;
}

static inline vapi_error_e vapi_fib_source_dump(struct vapi_ctx_s *ctx,
  vapi_msg_fib_source_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_fib_source_details *reply),
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
  vapi_msg_fib_source_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_fib_source_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_fib_source_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_fib_source_dump()
{
  static const char name[] = "fib_source_dump";
  static const char name_with_crc[] = "fib_source_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_fib_source_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_fib_source_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_fib_source_dump_hton,
    (generic_swap_fn_t)vapi_msg_fib_source_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_fib_source_dump = vapi_register_msg(&__vapi_metadata_fib_source_dump);
  VAPI_DBG("Assigned msg id %d to fib_source_dump", vapi_msg_id_fib_source_dump);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
