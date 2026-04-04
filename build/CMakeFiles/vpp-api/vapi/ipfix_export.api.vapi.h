#ifndef __included_ipfix_export_api_json
#define __included_ipfix_export_api_json

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

extern vapi_msg_id_t vapi_msg_id_set_ipfix_exporter;
extern vapi_msg_id_t vapi_msg_id_set_ipfix_exporter_reply;
extern vapi_msg_id_t vapi_msg_id_ipfix_exporter_dump;
extern vapi_msg_id_t vapi_msg_id_ipfix_exporter_details;
extern vapi_msg_id_t vapi_msg_id_ipfix_exporter_create_delete;
extern vapi_msg_id_t vapi_msg_id_ipfix_exporter_create_delete_reply;
extern vapi_msg_id_t vapi_msg_id_ipfix_all_exporter_get;
extern vapi_msg_id_t vapi_msg_id_ipfix_all_exporter_get_reply;
extern vapi_msg_id_t vapi_msg_id_ipfix_all_exporter_details;
extern vapi_msg_id_t vapi_msg_id_set_ipfix_classify_stream;
extern vapi_msg_id_t vapi_msg_id_set_ipfix_classify_stream_reply;
extern vapi_msg_id_t vapi_msg_id_ipfix_classify_stream_dump;
extern vapi_msg_id_t vapi_msg_id_ipfix_classify_stream_details;
extern vapi_msg_id_t vapi_msg_id_ipfix_classify_table_add_del;
extern vapi_msg_id_t vapi_msg_id_ipfix_classify_table_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_ipfix_classify_table_dump;
extern vapi_msg_id_t vapi_msg_id_ipfix_classify_table_details;
extern vapi_msg_id_t vapi_msg_id_ipfix_flush;
extern vapi_msg_id_t vapi_msg_id_ipfix_flush_reply;

#define DEFINE_VAPI_MSG_IDS_IPFIX_EXPORT_API_JSON\
  vapi_msg_id_t vapi_msg_id_set_ipfix_exporter;\
  vapi_msg_id_t vapi_msg_id_set_ipfix_exporter_reply;\
  vapi_msg_id_t vapi_msg_id_ipfix_exporter_dump;\
  vapi_msg_id_t vapi_msg_id_ipfix_exporter_details;\
  vapi_msg_id_t vapi_msg_id_ipfix_exporter_create_delete;\
  vapi_msg_id_t vapi_msg_id_ipfix_exporter_create_delete_reply;\
  vapi_msg_id_t vapi_msg_id_ipfix_all_exporter_get;\
  vapi_msg_id_t vapi_msg_id_ipfix_all_exporter_get_reply;\
  vapi_msg_id_t vapi_msg_id_ipfix_all_exporter_details;\
  vapi_msg_id_t vapi_msg_id_set_ipfix_classify_stream;\
  vapi_msg_id_t vapi_msg_id_set_ipfix_classify_stream_reply;\
  vapi_msg_id_t vapi_msg_id_ipfix_classify_stream_dump;\
  vapi_msg_id_t vapi_msg_id_ipfix_classify_stream_details;\
  vapi_msg_id_t vapi_msg_id_ipfix_classify_table_add_del;\
  vapi_msg_id_t vapi_msg_id_ipfix_classify_table_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_ipfix_classify_table_dump;\
  vapi_msg_id_t vapi_msg_id_ipfix_classify_table_details;\
  vapi_msg_id_t vapi_msg_id_ipfix_flush;\
  vapi_msg_id_t vapi_msg_id_ipfix_flush_reply;


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

#ifndef defined_vapi_type_ip4_address_with_prefix
#define defined_vapi_type_ip4_address_with_prefix
typedef vapi_type_ip4_prefix vapi_type_ip4_address_with_prefix;

#endif

#ifndef defined_vapi_type_ip6_address_with_prefix
#define defined_vapi_type_ip6_address_with_prefix
typedef vapi_type_ip6_prefix vapi_type_ip6_address_with_prefix;

#endif

#ifndef defined_vapi_msg_set_ipfix_exporter_reply
#define defined_vapi_msg_set_ipfix_exporter_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_set_ipfix_exporter_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_set_ipfix_exporter_reply payload;
} vapi_msg_set_ipfix_exporter_reply;

static inline void vapi_msg_set_ipfix_exporter_reply_payload_hton(vapi_payload_set_ipfix_exporter_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_set_ipfix_exporter_reply_payload_ntoh(vapi_payload_set_ipfix_exporter_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_set_ipfix_exporter_reply_hton(vapi_msg_set_ipfix_exporter_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ipfix_exporter_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_set_ipfix_exporter_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_set_ipfix_exporter_reply_ntoh(vapi_msg_set_ipfix_exporter_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ipfix_exporter_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_set_ipfix_exporter_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_set_ipfix_exporter_reply_msg_size(vapi_msg_set_ipfix_exporter_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_set_ipfix_exporter_reply_msg_size(vapi_msg_set_ipfix_exporter_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_set_ipfix_exporter_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ipfix_exporter_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_set_ipfix_exporter_reply));
      return -1;
    }
  if (vapi_calc_set_ipfix_exporter_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ipfix_exporter_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_set_ipfix_exporter_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_set_ipfix_exporter_reply()
{
  static const char name[] = "set_ipfix_exporter_reply";
  static const char name_with_crc[] = "set_ipfix_exporter_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_set_ipfix_exporter_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_set_ipfix_exporter_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_set_ipfix_exporter_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_set_ipfix_exporter_reply_hton,
    (generic_swap_fn_t)vapi_msg_set_ipfix_exporter_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_set_ipfix_exporter_reply = vapi_register_msg(&__vapi_metadata_set_ipfix_exporter_reply);
  VAPI_DBG("Assigned msg id %d to set_ipfix_exporter_reply", vapi_msg_id_set_ipfix_exporter_reply);
}

static inline void vapi_set_vapi_msg_set_ipfix_exporter_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_set_ipfix_exporter_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_set_ipfix_exporter_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_set_ipfix_exporter
#define defined_vapi_msg_set_ipfix_exporter
typedef struct __attribute__ ((__packed__)) {
  vapi_type_address collector_address;
  u16 collector_port;
  vapi_type_address src_address;
  u32 vrf_id;
  u32 path_mtu;
  u32 template_interval;
  bool udp_checksum; 
} vapi_payload_set_ipfix_exporter;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_set_ipfix_exporter payload;
} vapi_msg_set_ipfix_exporter;

static inline void vapi_msg_set_ipfix_exporter_payload_hton(vapi_payload_set_ipfix_exporter *payload)
{
  payload->collector_port = htobe16(payload->collector_port);
  payload->vrf_id = htobe32(payload->vrf_id);
  payload->path_mtu = htobe32(payload->path_mtu);
  payload->template_interval = htobe32(payload->template_interval);
}

static inline void vapi_msg_set_ipfix_exporter_payload_ntoh(vapi_payload_set_ipfix_exporter *payload)
{
  payload->collector_port = be16toh(payload->collector_port);
  payload->vrf_id = be32toh(payload->vrf_id);
  payload->path_mtu = be32toh(payload->path_mtu);
  payload->template_interval = be32toh(payload->template_interval);
}

static inline void vapi_msg_set_ipfix_exporter_hton(vapi_msg_set_ipfix_exporter *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ipfix_exporter'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_set_ipfix_exporter_payload_hton(&msg->payload);
}

static inline void vapi_msg_set_ipfix_exporter_ntoh(vapi_msg_set_ipfix_exporter *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ipfix_exporter'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_set_ipfix_exporter_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_set_ipfix_exporter_msg_size(vapi_msg_set_ipfix_exporter *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_set_ipfix_exporter_msg_size(vapi_msg_set_ipfix_exporter *msg, uword buf_size)
{
  if (sizeof(vapi_msg_set_ipfix_exporter) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ipfix_exporter' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_set_ipfix_exporter));
      return -1;
    }
  if (vapi_calc_set_ipfix_exporter_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ipfix_exporter' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_set_ipfix_exporter_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_set_ipfix_exporter* vapi_alloc_set_ipfix_exporter(struct vapi_ctx_s *ctx)
{
  vapi_msg_set_ipfix_exporter *msg = NULL;
  const size_t size = sizeof(vapi_msg_set_ipfix_exporter);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_set_ipfix_exporter*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_set_ipfix_exporter);

  return msg;
}

static inline vapi_error_e vapi_set_ipfix_exporter(struct vapi_ctx_s *ctx,
  vapi_msg_set_ipfix_exporter *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_set_ipfix_exporter_reply *reply),
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
  vapi_msg_set_ipfix_exporter_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_set_ipfix_exporter_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_set_ipfix_exporter_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_set_ipfix_exporter()
{
  static const char name[] = "set_ipfix_exporter";
  static const char name_with_crc[] = "set_ipfix_exporter_5530c8a0";
  static vapi_message_desc_t __vapi_metadata_set_ipfix_exporter = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_set_ipfix_exporter, payload),
    (verify_msg_size_fn_t)vapi_verify_set_ipfix_exporter_msg_size,
    (generic_swap_fn_t)vapi_msg_set_ipfix_exporter_hton,
    (generic_swap_fn_t)vapi_msg_set_ipfix_exporter_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_set_ipfix_exporter = vapi_register_msg(&__vapi_metadata_set_ipfix_exporter);
  VAPI_DBG("Assigned msg id %d to set_ipfix_exporter", vapi_msg_id_set_ipfix_exporter);
}
#endif

#ifndef defined_vapi_msg_ipfix_exporter_details
#define defined_vapi_msg_ipfix_exporter_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_address collector_address;
  u16 collector_port;
  vapi_type_address src_address;
  u32 vrf_id;
  u32 path_mtu;
  u32 template_interval;
  bool udp_checksum; 
} vapi_payload_ipfix_exporter_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipfix_exporter_details payload;
} vapi_msg_ipfix_exporter_details;

static inline void vapi_msg_ipfix_exporter_details_payload_hton(vapi_payload_ipfix_exporter_details *payload)
{
  payload->collector_port = htobe16(payload->collector_port);
  payload->vrf_id = htobe32(payload->vrf_id);
  payload->path_mtu = htobe32(payload->path_mtu);
  payload->template_interval = htobe32(payload->template_interval);
}

static inline void vapi_msg_ipfix_exporter_details_payload_ntoh(vapi_payload_ipfix_exporter_details *payload)
{
  payload->collector_port = be16toh(payload->collector_port);
  payload->vrf_id = be32toh(payload->vrf_id);
  payload->path_mtu = be32toh(payload->path_mtu);
  payload->template_interval = be32toh(payload->template_interval);
}

static inline void vapi_msg_ipfix_exporter_details_hton(vapi_msg_ipfix_exporter_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_exporter_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipfix_exporter_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipfix_exporter_details_ntoh(vapi_msg_ipfix_exporter_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_exporter_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipfix_exporter_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipfix_exporter_details_msg_size(vapi_msg_ipfix_exporter_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipfix_exporter_details_msg_size(vapi_msg_ipfix_exporter_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipfix_exporter_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_exporter_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipfix_exporter_details));
      return -1;
    }
  if (vapi_calc_ipfix_exporter_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_exporter_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipfix_exporter_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipfix_exporter_details()
{
  static const char name[] = "ipfix_exporter_details";
  static const char name_with_crc[] = "ipfix_exporter_details_0dedbfe4";
  static vapi_message_desc_t __vapi_metadata_ipfix_exporter_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipfix_exporter_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ipfix_exporter_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ipfix_exporter_details_hton,
    (generic_swap_fn_t)vapi_msg_ipfix_exporter_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipfix_exporter_details = vapi_register_msg(&__vapi_metadata_ipfix_exporter_details);
  VAPI_DBG("Assigned msg id %d to ipfix_exporter_details", vapi_msg_id_ipfix_exporter_details);
}

static inline void vapi_set_vapi_msg_ipfix_exporter_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipfix_exporter_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipfix_exporter_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipfix_exporter_dump
#define defined_vapi_msg_ipfix_exporter_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ipfix_exporter_dump;

static inline void vapi_msg_ipfix_exporter_dump_hton(vapi_msg_ipfix_exporter_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_exporter_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ipfix_exporter_dump_ntoh(vapi_msg_ipfix_exporter_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_exporter_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ipfix_exporter_dump_msg_size(vapi_msg_ipfix_exporter_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipfix_exporter_dump_msg_size(vapi_msg_ipfix_exporter_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipfix_exporter_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_exporter_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipfix_exporter_dump));
      return -1;
    }
  if (vapi_calc_ipfix_exporter_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_exporter_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipfix_exporter_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipfix_exporter_dump* vapi_alloc_ipfix_exporter_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipfix_exporter_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipfix_exporter_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipfix_exporter_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipfix_exporter_dump);

  return msg;
}

static inline vapi_error_e vapi_ipfix_exporter_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ipfix_exporter_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipfix_exporter_details *reply),
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
  vapi_msg_ipfix_exporter_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipfix_exporter_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_ipfix_exporter_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipfix_exporter_dump()
{
  static const char name[] = "ipfix_exporter_dump";
  static const char name_with_crc[] = "ipfix_exporter_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_ipfix_exporter_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ipfix_exporter_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ipfix_exporter_dump_hton,
    (generic_swap_fn_t)vapi_msg_ipfix_exporter_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipfix_exporter_dump = vapi_register_msg(&__vapi_metadata_ipfix_exporter_dump);
  VAPI_DBG("Assigned msg id %d to ipfix_exporter_dump", vapi_msg_id_ipfix_exporter_dump);
}
#endif

#ifndef defined_vapi_msg_ipfix_exporter_create_delete_reply
#define defined_vapi_msg_ipfix_exporter_create_delete_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 stat_index; 
} vapi_payload_ipfix_exporter_create_delete_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipfix_exporter_create_delete_reply payload;
} vapi_msg_ipfix_exporter_create_delete_reply;

static inline void vapi_msg_ipfix_exporter_create_delete_reply_payload_hton(vapi_payload_ipfix_exporter_create_delete_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->stat_index = htobe32(payload->stat_index);
}

static inline void vapi_msg_ipfix_exporter_create_delete_reply_payload_ntoh(vapi_payload_ipfix_exporter_create_delete_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->stat_index = be32toh(payload->stat_index);
}

static inline void vapi_msg_ipfix_exporter_create_delete_reply_hton(vapi_msg_ipfix_exporter_create_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_exporter_create_delete_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipfix_exporter_create_delete_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipfix_exporter_create_delete_reply_ntoh(vapi_msg_ipfix_exporter_create_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_exporter_create_delete_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipfix_exporter_create_delete_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipfix_exporter_create_delete_reply_msg_size(vapi_msg_ipfix_exporter_create_delete_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipfix_exporter_create_delete_reply_msg_size(vapi_msg_ipfix_exporter_create_delete_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipfix_exporter_create_delete_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_exporter_create_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipfix_exporter_create_delete_reply));
      return -1;
    }
  if (vapi_calc_ipfix_exporter_create_delete_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_exporter_create_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipfix_exporter_create_delete_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipfix_exporter_create_delete_reply()
{
  static const char name[] = "ipfix_exporter_create_delete_reply";
  static const char name_with_crc[] = "ipfix_exporter_create_delete_reply_9ffac24b";
  static vapi_message_desc_t __vapi_metadata_ipfix_exporter_create_delete_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipfix_exporter_create_delete_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipfix_exporter_create_delete_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipfix_exporter_create_delete_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipfix_exporter_create_delete_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipfix_exporter_create_delete_reply = vapi_register_msg(&__vapi_metadata_ipfix_exporter_create_delete_reply);
  VAPI_DBG("Assigned msg id %d to ipfix_exporter_create_delete_reply", vapi_msg_id_ipfix_exporter_create_delete_reply);
}

static inline void vapi_set_vapi_msg_ipfix_exporter_create_delete_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipfix_exporter_create_delete_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipfix_exporter_create_delete_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipfix_exporter_create_delete
#define defined_vapi_msg_ipfix_exporter_create_delete
typedef struct __attribute__ ((__packed__)) {
  bool is_create;
  vapi_type_address collector_address;
  u16 collector_port;
  vapi_type_address src_address;
  u32 vrf_id;
  u32 path_mtu;
  u32 template_interval;
  bool udp_checksum; 
} vapi_payload_ipfix_exporter_create_delete;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipfix_exporter_create_delete payload;
} vapi_msg_ipfix_exporter_create_delete;

static inline void vapi_msg_ipfix_exporter_create_delete_payload_hton(vapi_payload_ipfix_exporter_create_delete *payload)
{
  payload->collector_port = htobe16(payload->collector_port);
  payload->vrf_id = htobe32(payload->vrf_id);
  payload->path_mtu = htobe32(payload->path_mtu);
  payload->template_interval = htobe32(payload->template_interval);
}

static inline void vapi_msg_ipfix_exporter_create_delete_payload_ntoh(vapi_payload_ipfix_exporter_create_delete *payload)
{
  payload->collector_port = be16toh(payload->collector_port);
  payload->vrf_id = be32toh(payload->vrf_id);
  payload->path_mtu = be32toh(payload->path_mtu);
  payload->template_interval = be32toh(payload->template_interval);
}

static inline void vapi_msg_ipfix_exporter_create_delete_hton(vapi_msg_ipfix_exporter_create_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_exporter_create_delete'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipfix_exporter_create_delete_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipfix_exporter_create_delete_ntoh(vapi_msg_ipfix_exporter_create_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_exporter_create_delete'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipfix_exporter_create_delete_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipfix_exporter_create_delete_msg_size(vapi_msg_ipfix_exporter_create_delete *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipfix_exporter_create_delete_msg_size(vapi_msg_ipfix_exporter_create_delete *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipfix_exporter_create_delete) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_exporter_create_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipfix_exporter_create_delete));
      return -1;
    }
  if (vapi_calc_ipfix_exporter_create_delete_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_exporter_create_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipfix_exporter_create_delete_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipfix_exporter_create_delete* vapi_alloc_ipfix_exporter_create_delete(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipfix_exporter_create_delete *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipfix_exporter_create_delete);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipfix_exporter_create_delete*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipfix_exporter_create_delete);

  return msg;
}

static inline vapi_error_e vapi_ipfix_exporter_create_delete(struct vapi_ctx_s *ctx,
  vapi_msg_ipfix_exporter_create_delete *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipfix_exporter_create_delete_reply *reply),
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
  vapi_msg_ipfix_exporter_create_delete_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipfix_exporter_create_delete_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ipfix_exporter_create_delete_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipfix_exporter_create_delete()
{
  static const char name[] = "ipfix_exporter_create_delete";
  static const char name_with_crc[] = "ipfix_exporter_create_delete_0753a768";
  static vapi_message_desc_t __vapi_metadata_ipfix_exporter_create_delete = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipfix_exporter_create_delete, payload),
    (verify_msg_size_fn_t)vapi_verify_ipfix_exporter_create_delete_msg_size,
    (generic_swap_fn_t)vapi_msg_ipfix_exporter_create_delete_hton,
    (generic_swap_fn_t)vapi_msg_ipfix_exporter_create_delete_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipfix_exporter_create_delete = vapi_register_msg(&__vapi_metadata_ipfix_exporter_create_delete);
  VAPI_DBG("Assigned msg id %d to ipfix_exporter_create_delete", vapi_msg_id_ipfix_exporter_create_delete);
}
#endif

#ifndef defined_vapi_msg_ipfix_all_exporter_get_reply
#define defined_vapi_msg_ipfix_all_exporter_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 cursor; 
} vapi_payload_ipfix_all_exporter_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipfix_all_exporter_get_reply payload;
} vapi_msg_ipfix_all_exporter_get_reply;

static inline void vapi_msg_ipfix_all_exporter_get_reply_payload_hton(vapi_payload_ipfix_all_exporter_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_ipfix_all_exporter_get_reply_payload_ntoh(vapi_payload_ipfix_all_exporter_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_ipfix_all_exporter_get_reply_hton(vapi_msg_ipfix_all_exporter_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_all_exporter_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipfix_all_exporter_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipfix_all_exporter_get_reply_ntoh(vapi_msg_ipfix_all_exporter_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_all_exporter_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipfix_all_exporter_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipfix_all_exporter_get_reply_msg_size(vapi_msg_ipfix_all_exporter_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipfix_all_exporter_get_reply_msg_size(vapi_msg_ipfix_all_exporter_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipfix_all_exporter_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_all_exporter_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipfix_all_exporter_get_reply));
      return -1;
    }
  if (vapi_calc_ipfix_all_exporter_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_all_exporter_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipfix_all_exporter_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipfix_all_exporter_get_reply()
{
  static const char name[] = "ipfix_all_exporter_get_reply";
  static const char name_with_crc[] = "ipfix_all_exporter_get_reply_53b48f5d";
  static vapi_message_desc_t __vapi_metadata_ipfix_all_exporter_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipfix_all_exporter_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipfix_all_exporter_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipfix_all_exporter_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipfix_all_exporter_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipfix_all_exporter_get_reply = vapi_register_msg(&__vapi_metadata_ipfix_all_exporter_get_reply);
  VAPI_DBG("Assigned msg id %d to ipfix_all_exporter_get_reply", vapi_msg_id_ipfix_all_exporter_get_reply);
}

static inline void vapi_set_vapi_msg_ipfix_all_exporter_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipfix_all_exporter_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipfix_all_exporter_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipfix_all_exporter_details
#define defined_vapi_msg_ipfix_all_exporter_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_address collector_address;
  u16 collector_port;
  vapi_type_address src_address;
  u32 vrf_id;
  u32 path_mtu;
  u32 template_interval;
  bool udp_checksum; 
} vapi_payload_ipfix_all_exporter_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipfix_all_exporter_details payload;
} vapi_msg_ipfix_all_exporter_details;

static inline void vapi_msg_ipfix_all_exporter_details_payload_hton(vapi_payload_ipfix_all_exporter_details *payload)
{
  payload->collector_port = htobe16(payload->collector_port);
  payload->vrf_id = htobe32(payload->vrf_id);
  payload->path_mtu = htobe32(payload->path_mtu);
  payload->template_interval = htobe32(payload->template_interval);
}

static inline void vapi_msg_ipfix_all_exporter_details_payload_ntoh(vapi_payload_ipfix_all_exporter_details *payload)
{
  payload->collector_port = be16toh(payload->collector_port);
  payload->vrf_id = be32toh(payload->vrf_id);
  payload->path_mtu = be32toh(payload->path_mtu);
  payload->template_interval = be32toh(payload->template_interval);
}

static inline void vapi_msg_ipfix_all_exporter_details_hton(vapi_msg_ipfix_all_exporter_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_all_exporter_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipfix_all_exporter_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipfix_all_exporter_details_ntoh(vapi_msg_ipfix_all_exporter_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_all_exporter_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipfix_all_exporter_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipfix_all_exporter_details_msg_size(vapi_msg_ipfix_all_exporter_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipfix_all_exporter_details_msg_size(vapi_msg_ipfix_all_exporter_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipfix_all_exporter_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_all_exporter_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipfix_all_exporter_details));
      return -1;
    }
  if (vapi_calc_ipfix_all_exporter_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_all_exporter_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipfix_all_exporter_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipfix_all_exporter_details()
{
  static const char name[] = "ipfix_all_exporter_details";
  static const char name_with_crc[] = "ipfix_all_exporter_details_0dedbfe4";
  static vapi_message_desc_t __vapi_metadata_ipfix_all_exporter_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipfix_all_exporter_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ipfix_all_exporter_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ipfix_all_exporter_details_hton,
    (generic_swap_fn_t)vapi_msg_ipfix_all_exporter_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipfix_all_exporter_details = vapi_register_msg(&__vapi_metadata_ipfix_all_exporter_details);
  VAPI_DBG("Assigned msg id %d to ipfix_all_exporter_details", vapi_msg_id_ipfix_all_exporter_details);
}
#endif

#ifndef defined_vapi_msg_ipfix_all_exporter_get
#define defined_vapi_msg_ipfix_all_exporter_get
typedef struct __attribute__ ((__packed__)) {
  u32 cursor; 
} vapi_payload_ipfix_all_exporter_get;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipfix_all_exporter_get payload;
} vapi_msg_ipfix_all_exporter_get;

static inline void vapi_msg_ipfix_all_exporter_get_payload_hton(vapi_payload_ipfix_all_exporter_get *payload)
{
  payload->cursor = htobe32(payload->cursor);
}

static inline void vapi_msg_ipfix_all_exporter_get_payload_ntoh(vapi_payload_ipfix_all_exporter_get *payload)
{
  payload->cursor = be32toh(payload->cursor);
}

static inline void vapi_msg_ipfix_all_exporter_get_hton(vapi_msg_ipfix_all_exporter_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_all_exporter_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipfix_all_exporter_get_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipfix_all_exporter_get_ntoh(vapi_msg_ipfix_all_exporter_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_all_exporter_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipfix_all_exporter_get_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipfix_all_exporter_get_msg_size(vapi_msg_ipfix_all_exporter_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipfix_all_exporter_get_msg_size(vapi_msg_ipfix_all_exporter_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipfix_all_exporter_get) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_all_exporter_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipfix_all_exporter_get));
      return -1;
    }
  if (vapi_calc_ipfix_all_exporter_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_all_exporter_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipfix_all_exporter_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipfix_all_exporter_get* vapi_alloc_ipfix_all_exporter_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipfix_all_exporter_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipfix_all_exporter_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipfix_all_exporter_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipfix_all_exporter_get);

  return msg;
}

static inline vapi_error_e vapi_ipfix_all_exporter_get(struct vapi_ctx_s *ctx,
  vapi_msg_ipfix_all_exporter_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipfix_all_exporter_get_reply *reply),
  void *reply_callback_ctx,
  vapi_error_e (*details_callback)(struct vapi_ctx_s *ctx,
                                   void *callback_ctx,
                                   vapi_error_e rv,
                                   bool is_last,
                                   vapi_payload_ipfix_all_exporter_details *details),
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
  vapi_msg_ipfix_all_exporter_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipfix_all_exporter_details, VAPI_REQUEST_STREAM, 
                       (vapi_cb_t)details_callback, details_callback_ctx);
    vapi_store_request(ctx, req_context, vapi_msg_id_ipfix_all_exporter_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ipfix_all_exporter_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipfix_all_exporter_get()
{
  static const char name[] = "ipfix_all_exporter_get";
  static const char name_with_crc[] = "ipfix_all_exporter_get_f75ba505";
  static vapi_message_desc_t __vapi_metadata_ipfix_all_exporter_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipfix_all_exporter_get, payload),
    (verify_msg_size_fn_t)vapi_verify_ipfix_all_exporter_get_msg_size,
    (generic_swap_fn_t)vapi_msg_ipfix_all_exporter_get_hton,
    (generic_swap_fn_t)vapi_msg_ipfix_all_exporter_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipfix_all_exporter_get = vapi_register_msg(&__vapi_metadata_ipfix_all_exporter_get);
  VAPI_DBG("Assigned msg id %d to ipfix_all_exporter_get", vapi_msg_id_ipfix_all_exporter_get);
}
#endif

#ifndef defined_vapi_msg_set_ipfix_classify_stream_reply
#define defined_vapi_msg_set_ipfix_classify_stream_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_set_ipfix_classify_stream_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_set_ipfix_classify_stream_reply payload;
} vapi_msg_set_ipfix_classify_stream_reply;

static inline void vapi_msg_set_ipfix_classify_stream_reply_payload_hton(vapi_payload_set_ipfix_classify_stream_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_set_ipfix_classify_stream_reply_payload_ntoh(vapi_payload_set_ipfix_classify_stream_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_set_ipfix_classify_stream_reply_hton(vapi_msg_set_ipfix_classify_stream_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ipfix_classify_stream_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_set_ipfix_classify_stream_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_set_ipfix_classify_stream_reply_ntoh(vapi_msg_set_ipfix_classify_stream_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ipfix_classify_stream_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_set_ipfix_classify_stream_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_set_ipfix_classify_stream_reply_msg_size(vapi_msg_set_ipfix_classify_stream_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_set_ipfix_classify_stream_reply_msg_size(vapi_msg_set_ipfix_classify_stream_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_set_ipfix_classify_stream_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ipfix_classify_stream_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_set_ipfix_classify_stream_reply));
      return -1;
    }
  if (vapi_calc_set_ipfix_classify_stream_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ipfix_classify_stream_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_set_ipfix_classify_stream_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_set_ipfix_classify_stream_reply()
{
  static const char name[] = "set_ipfix_classify_stream_reply";
  static const char name_with_crc[] = "set_ipfix_classify_stream_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_set_ipfix_classify_stream_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_set_ipfix_classify_stream_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_set_ipfix_classify_stream_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_set_ipfix_classify_stream_reply_hton,
    (generic_swap_fn_t)vapi_msg_set_ipfix_classify_stream_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_set_ipfix_classify_stream_reply = vapi_register_msg(&__vapi_metadata_set_ipfix_classify_stream_reply);
  VAPI_DBG("Assigned msg id %d to set_ipfix_classify_stream_reply", vapi_msg_id_set_ipfix_classify_stream_reply);
}

static inline void vapi_set_vapi_msg_set_ipfix_classify_stream_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_set_ipfix_classify_stream_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_set_ipfix_classify_stream_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_set_ipfix_classify_stream
#define defined_vapi_msg_set_ipfix_classify_stream
typedef struct __attribute__ ((__packed__)) {
  u32 domain_id;
  u16 src_port; 
} vapi_payload_set_ipfix_classify_stream;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_set_ipfix_classify_stream payload;
} vapi_msg_set_ipfix_classify_stream;

static inline void vapi_msg_set_ipfix_classify_stream_payload_hton(vapi_payload_set_ipfix_classify_stream *payload)
{
  payload->domain_id = htobe32(payload->domain_id);
  payload->src_port = htobe16(payload->src_port);
}

static inline void vapi_msg_set_ipfix_classify_stream_payload_ntoh(vapi_payload_set_ipfix_classify_stream *payload)
{
  payload->domain_id = be32toh(payload->domain_id);
  payload->src_port = be16toh(payload->src_port);
}

static inline void vapi_msg_set_ipfix_classify_stream_hton(vapi_msg_set_ipfix_classify_stream *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ipfix_classify_stream'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_set_ipfix_classify_stream_payload_hton(&msg->payload);
}

static inline void vapi_msg_set_ipfix_classify_stream_ntoh(vapi_msg_set_ipfix_classify_stream *msg)
{
  VAPI_DBG("Swapping `vapi_msg_set_ipfix_classify_stream'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_set_ipfix_classify_stream_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_set_ipfix_classify_stream_msg_size(vapi_msg_set_ipfix_classify_stream *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_set_ipfix_classify_stream_msg_size(vapi_msg_set_ipfix_classify_stream *msg, uword buf_size)
{
  if (sizeof(vapi_msg_set_ipfix_classify_stream) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ipfix_classify_stream' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_set_ipfix_classify_stream));
      return -1;
    }
  if (vapi_calc_set_ipfix_classify_stream_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'set_ipfix_classify_stream' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_set_ipfix_classify_stream_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_set_ipfix_classify_stream* vapi_alloc_set_ipfix_classify_stream(struct vapi_ctx_s *ctx)
{
  vapi_msg_set_ipfix_classify_stream *msg = NULL;
  const size_t size = sizeof(vapi_msg_set_ipfix_classify_stream);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_set_ipfix_classify_stream*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_set_ipfix_classify_stream);

  return msg;
}

static inline vapi_error_e vapi_set_ipfix_classify_stream(struct vapi_ctx_s *ctx,
  vapi_msg_set_ipfix_classify_stream *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_set_ipfix_classify_stream_reply *reply),
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
  vapi_msg_set_ipfix_classify_stream_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_set_ipfix_classify_stream_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_set_ipfix_classify_stream_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_set_ipfix_classify_stream()
{
  static const char name[] = "set_ipfix_classify_stream";
  static const char name_with_crc[] = "set_ipfix_classify_stream_c9cbe053";
  static vapi_message_desc_t __vapi_metadata_set_ipfix_classify_stream = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_set_ipfix_classify_stream, payload),
    (verify_msg_size_fn_t)vapi_verify_set_ipfix_classify_stream_msg_size,
    (generic_swap_fn_t)vapi_msg_set_ipfix_classify_stream_hton,
    (generic_swap_fn_t)vapi_msg_set_ipfix_classify_stream_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_set_ipfix_classify_stream = vapi_register_msg(&__vapi_metadata_set_ipfix_classify_stream);
  VAPI_DBG("Assigned msg id %d to set_ipfix_classify_stream", vapi_msg_id_set_ipfix_classify_stream);
}
#endif

#ifndef defined_vapi_msg_ipfix_classify_stream_details
#define defined_vapi_msg_ipfix_classify_stream_details
typedef struct __attribute__ ((__packed__)) {
  u32 domain_id;
  u16 src_port; 
} vapi_payload_ipfix_classify_stream_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipfix_classify_stream_details payload;
} vapi_msg_ipfix_classify_stream_details;

static inline void vapi_msg_ipfix_classify_stream_details_payload_hton(vapi_payload_ipfix_classify_stream_details *payload)
{
  payload->domain_id = htobe32(payload->domain_id);
  payload->src_port = htobe16(payload->src_port);
}

static inline void vapi_msg_ipfix_classify_stream_details_payload_ntoh(vapi_payload_ipfix_classify_stream_details *payload)
{
  payload->domain_id = be32toh(payload->domain_id);
  payload->src_port = be16toh(payload->src_port);
}

static inline void vapi_msg_ipfix_classify_stream_details_hton(vapi_msg_ipfix_classify_stream_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_classify_stream_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipfix_classify_stream_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipfix_classify_stream_details_ntoh(vapi_msg_ipfix_classify_stream_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_classify_stream_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipfix_classify_stream_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipfix_classify_stream_details_msg_size(vapi_msg_ipfix_classify_stream_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipfix_classify_stream_details_msg_size(vapi_msg_ipfix_classify_stream_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipfix_classify_stream_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_classify_stream_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipfix_classify_stream_details));
      return -1;
    }
  if (vapi_calc_ipfix_classify_stream_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_classify_stream_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipfix_classify_stream_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipfix_classify_stream_details()
{
  static const char name[] = "ipfix_classify_stream_details";
  static const char name_with_crc[] = "ipfix_classify_stream_details_2903539d";
  static vapi_message_desc_t __vapi_metadata_ipfix_classify_stream_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipfix_classify_stream_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ipfix_classify_stream_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ipfix_classify_stream_details_hton,
    (generic_swap_fn_t)vapi_msg_ipfix_classify_stream_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipfix_classify_stream_details = vapi_register_msg(&__vapi_metadata_ipfix_classify_stream_details);
  VAPI_DBG("Assigned msg id %d to ipfix_classify_stream_details", vapi_msg_id_ipfix_classify_stream_details);
}

static inline void vapi_set_vapi_msg_ipfix_classify_stream_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipfix_classify_stream_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipfix_classify_stream_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipfix_classify_stream_dump
#define defined_vapi_msg_ipfix_classify_stream_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ipfix_classify_stream_dump;

static inline void vapi_msg_ipfix_classify_stream_dump_hton(vapi_msg_ipfix_classify_stream_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_classify_stream_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ipfix_classify_stream_dump_ntoh(vapi_msg_ipfix_classify_stream_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_classify_stream_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ipfix_classify_stream_dump_msg_size(vapi_msg_ipfix_classify_stream_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipfix_classify_stream_dump_msg_size(vapi_msg_ipfix_classify_stream_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipfix_classify_stream_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_classify_stream_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipfix_classify_stream_dump));
      return -1;
    }
  if (vapi_calc_ipfix_classify_stream_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_classify_stream_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipfix_classify_stream_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipfix_classify_stream_dump* vapi_alloc_ipfix_classify_stream_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipfix_classify_stream_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipfix_classify_stream_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipfix_classify_stream_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipfix_classify_stream_dump);

  return msg;
}

static inline vapi_error_e vapi_ipfix_classify_stream_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ipfix_classify_stream_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipfix_classify_stream_details *reply),
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
  vapi_msg_ipfix_classify_stream_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipfix_classify_stream_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_ipfix_classify_stream_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipfix_classify_stream_dump()
{
  static const char name[] = "ipfix_classify_stream_dump";
  static const char name_with_crc[] = "ipfix_classify_stream_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_ipfix_classify_stream_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ipfix_classify_stream_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ipfix_classify_stream_dump_hton,
    (generic_swap_fn_t)vapi_msg_ipfix_classify_stream_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipfix_classify_stream_dump = vapi_register_msg(&__vapi_metadata_ipfix_classify_stream_dump);
  VAPI_DBG("Assigned msg id %d to ipfix_classify_stream_dump", vapi_msg_id_ipfix_classify_stream_dump);
}
#endif

#ifndef defined_vapi_msg_ipfix_classify_table_add_del_reply
#define defined_vapi_msg_ipfix_classify_table_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ipfix_classify_table_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipfix_classify_table_add_del_reply payload;
} vapi_msg_ipfix_classify_table_add_del_reply;

static inline void vapi_msg_ipfix_classify_table_add_del_reply_payload_hton(vapi_payload_ipfix_classify_table_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ipfix_classify_table_add_del_reply_payload_ntoh(vapi_payload_ipfix_classify_table_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ipfix_classify_table_add_del_reply_hton(vapi_msg_ipfix_classify_table_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_classify_table_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipfix_classify_table_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipfix_classify_table_add_del_reply_ntoh(vapi_msg_ipfix_classify_table_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_classify_table_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipfix_classify_table_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipfix_classify_table_add_del_reply_msg_size(vapi_msg_ipfix_classify_table_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipfix_classify_table_add_del_reply_msg_size(vapi_msg_ipfix_classify_table_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipfix_classify_table_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_classify_table_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipfix_classify_table_add_del_reply));
      return -1;
    }
  if (vapi_calc_ipfix_classify_table_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_classify_table_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipfix_classify_table_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipfix_classify_table_add_del_reply()
{
  static const char name[] = "ipfix_classify_table_add_del_reply";
  static const char name_with_crc[] = "ipfix_classify_table_add_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ipfix_classify_table_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipfix_classify_table_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipfix_classify_table_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipfix_classify_table_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipfix_classify_table_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipfix_classify_table_add_del_reply = vapi_register_msg(&__vapi_metadata_ipfix_classify_table_add_del_reply);
  VAPI_DBG("Assigned msg id %d to ipfix_classify_table_add_del_reply", vapi_msg_id_ipfix_classify_table_add_del_reply);
}

static inline void vapi_set_vapi_msg_ipfix_classify_table_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipfix_classify_table_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipfix_classify_table_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipfix_classify_table_add_del
#define defined_vapi_msg_ipfix_classify_table_add_del
typedef struct __attribute__ ((__packed__)) {
  u32 table_id;
  vapi_enum_address_family ip_version;
  vapi_enum_ip_proto transport_protocol;
  bool is_add; 
} vapi_payload_ipfix_classify_table_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipfix_classify_table_add_del payload;
} vapi_msg_ipfix_classify_table_add_del;

static inline void vapi_msg_ipfix_classify_table_add_del_payload_hton(vapi_payload_ipfix_classify_table_add_del *payload)
{
  payload->table_id = htobe32(payload->table_id);
}

static inline void vapi_msg_ipfix_classify_table_add_del_payload_ntoh(vapi_payload_ipfix_classify_table_add_del *payload)
{
  payload->table_id = be32toh(payload->table_id);
}

static inline void vapi_msg_ipfix_classify_table_add_del_hton(vapi_msg_ipfix_classify_table_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_classify_table_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipfix_classify_table_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipfix_classify_table_add_del_ntoh(vapi_msg_ipfix_classify_table_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_classify_table_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipfix_classify_table_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipfix_classify_table_add_del_msg_size(vapi_msg_ipfix_classify_table_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipfix_classify_table_add_del_msg_size(vapi_msg_ipfix_classify_table_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipfix_classify_table_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_classify_table_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipfix_classify_table_add_del));
      return -1;
    }
  if (vapi_calc_ipfix_classify_table_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_classify_table_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipfix_classify_table_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipfix_classify_table_add_del* vapi_alloc_ipfix_classify_table_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipfix_classify_table_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipfix_classify_table_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipfix_classify_table_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipfix_classify_table_add_del);

  return msg;
}

static inline vapi_error_e vapi_ipfix_classify_table_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_ipfix_classify_table_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipfix_classify_table_add_del_reply *reply),
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
  vapi_msg_ipfix_classify_table_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipfix_classify_table_add_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ipfix_classify_table_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipfix_classify_table_add_del()
{
  static const char name[] = "ipfix_classify_table_add_del";
  static const char name_with_crc[] = "ipfix_classify_table_add_del_3e449bb9";
  static vapi_message_desc_t __vapi_metadata_ipfix_classify_table_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipfix_classify_table_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_ipfix_classify_table_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_ipfix_classify_table_add_del_hton,
    (generic_swap_fn_t)vapi_msg_ipfix_classify_table_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipfix_classify_table_add_del = vapi_register_msg(&__vapi_metadata_ipfix_classify_table_add_del);
  VAPI_DBG("Assigned msg id %d to ipfix_classify_table_add_del", vapi_msg_id_ipfix_classify_table_add_del);
}
#endif

#ifndef defined_vapi_msg_ipfix_classify_table_details
#define defined_vapi_msg_ipfix_classify_table_details
typedef struct __attribute__ ((__packed__)) {
  u32 table_id;
  vapi_enum_address_family ip_version;
  vapi_enum_ip_proto transport_protocol; 
} vapi_payload_ipfix_classify_table_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipfix_classify_table_details payload;
} vapi_msg_ipfix_classify_table_details;

static inline void vapi_msg_ipfix_classify_table_details_payload_hton(vapi_payload_ipfix_classify_table_details *payload)
{
  payload->table_id = htobe32(payload->table_id);
}

static inline void vapi_msg_ipfix_classify_table_details_payload_ntoh(vapi_payload_ipfix_classify_table_details *payload)
{
  payload->table_id = be32toh(payload->table_id);
}

static inline void vapi_msg_ipfix_classify_table_details_hton(vapi_msg_ipfix_classify_table_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_classify_table_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipfix_classify_table_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipfix_classify_table_details_ntoh(vapi_msg_ipfix_classify_table_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_classify_table_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipfix_classify_table_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipfix_classify_table_details_msg_size(vapi_msg_ipfix_classify_table_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipfix_classify_table_details_msg_size(vapi_msg_ipfix_classify_table_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipfix_classify_table_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_classify_table_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipfix_classify_table_details));
      return -1;
    }
  if (vapi_calc_ipfix_classify_table_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_classify_table_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipfix_classify_table_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipfix_classify_table_details()
{
  static const char name[] = "ipfix_classify_table_details";
  static const char name_with_crc[] = "ipfix_classify_table_details_1af8c28c";
  static vapi_message_desc_t __vapi_metadata_ipfix_classify_table_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipfix_classify_table_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ipfix_classify_table_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ipfix_classify_table_details_hton,
    (generic_swap_fn_t)vapi_msg_ipfix_classify_table_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipfix_classify_table_details = vapi_register_msg(&__vapi_metadata_ipfix_classify_table_details);
  VAPI_DBG("Assigned msg id %d to ipfix_classify_table_details", vapi_msg_id_ipfix_classify_table_details);
}

static inline void vapi_set_vapi_msg_ipfix_classify_table_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipfix_classify_table_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipfix_classify_table_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipfix_classify_table_dump
#define defined_vapi_msg_ipfix_classify_table_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ipfix_classify_table_dump;

static inline void vapi_msg_ipfix_classify_table_dump_hton(vapi_msg_ipfix_classify_table_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_classify_table_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ipfix_classify_table_dump_ntoh(vapi_msg_ipfix_classify_table_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_classify_table_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ipfix_classify_table_dump_msg_size(vapi_msg_ipfix_classify_table_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipfix_classify_table_dump_msg_size(vapi_msg_ipfix_classify_table_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipfix_classify_table_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_classify_table_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipfix_classify_table_dump));
      return -1;
    }
  if (vapi_calc_ipfix_classify_table_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_classify_table_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipfix_classify_table_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipfix_classify_table_dump* vapi_alloc_ipfix_classify_table_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipfix_classify_table_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipfix_classify_table_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipfix_classify_table_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipfix_classify_table_dump);

  return msg;
}

static inline vapi_error_e vapi_ipfix_classify_table_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ipfix_classify_table_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipfix_classify_table_details *reply),
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
  vapi_msg_ipfix_classify_table_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipfix_classify_table_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_ipfix_classify_table_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipfix_classify_table_dump()
{
  static const char name[] = "ipfix_classify_table_dump";
  static const char name_with_crc[] = "ipfix_classify_table_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_ipfix_classify_table_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ipfix_classify_table_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ipfix_classify_table_dump_hton,
    (generic_swap_fn_t)vapi_msg_ipfix_classify_table_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipfix_classify_table_dump = vapi_register_msg(&__vapi_metadata_ipfix_classify_table_dump);
  VAPI_DBG("Assigned msg id %d to ipfix_classify_table_dump", vapi_msg_id_ipfix_classify_table_dump);
}
#endif

#ifndef defined_vapi_msg_ipfix_flush_reply
#define defined_vapi_msg_ipfix_flush_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ipfix_flush_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipfix_flush_reply payload;
} vapi_msg_ipfix_flush_reply;

static inline void vapi_msg_ipfix_flush_reply_payload_hton(vapi_payload_ipfix_flush_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ipfix_flush_reply_payload_ntoh(vapi_payload_ipfix_flush_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ipfix_flush_reply_hton(vapi_msg_ipfix_flush_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_flush_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipfix_flush_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipfix_flush_reply_ntoh(vapi_msg_ipfix_flush_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_flush_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipfix_flush_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipfix_flush_reply_msg_size(vapi_msg_ipfix_flush_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipfix_flush_reply_msg_size(vapi_msg_ipfix_flush_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipfix_flush_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_flush_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipfix_flush_reply));
      return -1;
    }
  if (vapi_calc_ipfix_flush_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_flush_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipfix_flush_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipfix_flush_reply()
{
  static const char name[] = "ipfix_flush_reply";
  static const char name_with_crc[] = "ipfix_flush_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ipfix_flush_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipfix_flush_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipfix_flush_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipfix_flush_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipfix_flush_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipfix_flush_reply = vapi_register_msg(&__vapi_metadata_ipfix_flush_reply);
  VAPI_DBG("Assigned msg id %d to ipfix_flush_reply", vapi_msg_id_ipfix_flush_reply);
}

static inline void vapi_set_vapi_msg_ipfix_flush_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipfix_flush_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipfix_flush_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipfix_flush
#define defined_vapi_msg_ipfix_flush
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ipfix_flush;

static inline void vapi_msg_ipfix_flush_hton(vapi_msg_ipfix_flush *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_flush'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ipfix_flush_ntoh(vapi_msg_ipfix_flush *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipfix_flush'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ipfix_flush_msg_size(vapi_msg_ipfix_flush *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipfix_flush_msg_size(vapi_msg_ipfix_flush *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipfix_flush) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_flush' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipfix_flush));
      return -1;
    }
  if (vapi_calc_ipfix_flush_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipfix_flush' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipfix_flush_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipfix_flush* vapi_alloc_ipfix_flush(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipfix_flush *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipfix_flush);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipfix_flush*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipfix_flush);

  return msg;
}

static inline vapi_error_e vapi_ipfix_flush(struct vapi_ctx_s *ctx,
  vapi_msg_ipfix_flush *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipfix_flush_reply *reply),
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
  vapi_msg_ipfix_flush_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipfix_flush_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_ipfix_flush_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipfix_flush()
{
  static const char name[] = "ipfix_flush";
  static const char name_with_crc[] = "ipfix_flush_51077d14";
  static vapi_message_desc_t __vapi_metadata_ipfix_flush = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ipfix_flush_msg_size,
    (generic_swap_fn_t)vapi_msg_ipfix_flush_hton,
    (generic_swap_fn_t)vapi_msg_ipfix_flush_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipfix_flush = vapi_register_msg(&__vapi_metadata_ipfix_flush);
  VAPI_DBG("Assigned msg id %d to ipfix_flush", vapi_msg_id_ipfix_flush);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
